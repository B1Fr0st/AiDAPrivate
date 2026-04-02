

#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "standalone_license.hpp"
#include "../helpers/globals.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <sstream>
#include <cstdio>
#include <cstring>

using json = nlohmann::json;


standalone_ai_client_t::standalone_ai_client_t(const settings_sa_t& settings)
    : _settings(settings)
{
}

standalone_ai_client_t::~standalone_ai_client_t()
{
    cancel();
    std::lock_guard<std::mutex> lk(_worker_mtx);
    if (_worker.joinable())
        _worker.join();
}


bool standalone_ai_client_t::is_available() const
{
    const auto& model = _settings.get_active_model();
    const auto kind = _settings.get_active_profile_kind();
    if (kind == "local")
        return !_settings.get_active_base_url().empty() && !model.empty();
    if (kind == "gemini" || kind == "anthropic" || kind == "openrouter")
        return !_settings.get_active_api_key().empty() && !model.empty();
    return !_settings.get_active_base_url().empty() && !model.empty();
}


void standalone_ai_client_t::chat_async(
    const std::string& user_message,
    const std::vector<std::pair<std::string, std::string>>& history,
    ai_callback_t on_complete,
    ai_stream_chunk_t on_chunk)
{
    if (!is_available()) {
        if (on_complete)
            on_complete("Error: AI client not configured. Set your API key in Settings.");
        return;
    }


    if (!standalone_license::is_valid()) {
        if (on_complete)
            on_complete("Error: Service unavailable. Please restart the application.");
        return;
    }

    std::lock_guard<std::mutex> lk(_worker_mtx);
    if (_worker.joinable())
        _worker.join();

    _cancelled = false;
    _task_done = false;

    auto prompt = build_chat_prompt(user_message, history);


    _worker = std::thread([this, prompt, on_complete, on_chunk]() {
        std::string result;
        try {


            ai_stream_chunk_t threadsafe_chunk = nullptr;
            if (on_chunk) {
                threadsafe_chunk = [this, on_chunk](const std::string& chunk) {
                    std::lock_guard<std::mutex> ck(_chunk_mtx);
                    _chunks.push_back({on_chunk, chunk});
                };
            }

            result = do_generate(prompt, _settings.temperature, threadsafe_chunk, nullptr);
        } catch (const std::exception& e) {
            result = std::string("Error: ") + e.what();
        } catch (...) {
            result = "Error: Unknown exception in AI worker thread.";
        }

        _task_done = true;

        std::lock_guard<std::mutex> rl(_result_mtx);
        _results.push_back({on_complete, std::move(result)});
    });
}


std::string standalone_ai_client_t::chat_blocking(
    const std::string& user_message,
    const std::vector<std::pair<std::string, std::string>>& history,
    ai_stream_chunk_t on_chunk,
    ai_stop_predicate_t stop_check)
{
    if (!is_available())
        return "Error: AI client not configured.";

    auto prompt = build_chat_prompt(user_message, history);
    return do_generate(prompt, _settings.temperature, on_chunk, stop_check);
}


bool standalone_ai_client_t::poll()
{
    bool dispatched = false;


    {
        std::lock_guard<std::mutex> ck(_chunk_mtx);
        for (auto& [cb, text] : _chunks) {
            if (cb) cb(text);
            dispatched = true;
        }
        _chunks.clear();
    }


    {
        std::lock_guard<std::mutex> rl(_result_mtx);
        for (auto& [cb, text] : _results) {
            if (cb) cb(text);
            dispatched = true;
        }
        _results.clear();
    }

    return dispatched;
}


void standalone_ai_client_t::cancel()
{
    _cancelled = true;
    std::lock_guard<std::mutex> lk(_http_mtx);
    if (_http) _http->stop();
}


std::shared_ptr<httplib::Client> standalone_ai_client_t::get_or_create_client(
    const std::string& host)
{
    std::lock_guard<std::mutex> lk(_http_mtx);
    if (!_http || _last_host != host) {
        _http = std::make_shared<httplib::Client>(host.c_str());
        _last_host = host;

        _http->set_connection_timeout(5);
        _http->set_read_timeout(300);
        _http->set_write_timeout(10);
        _http->set_tcp_nodelay(true);
        _http->set_keep_alive(true);
        _http->set_decompress(true);
        _http->set_follow_location(true);
        _http->enable_server_certificate_verification(false);
    }
    return _http;
}

void standalone_ai_client_t::reset_client()
{
    std::lock_guard<std::mutex> lk(_http_mtx);
    _http.reset();
    _last_host.clear();
}


std::string standalone_ai_client_t::do_generate(
    const std::string& prompt,
    double temperature,
    ai_stream_chunk_t on_chunk,
    ai_stop_predicate_t stop_check)
{
    const auto provider = _settings.get_active_profile_kind();
    if (provider == "gemini")      return generate_gemini(prompt, temperature, on_chunk, stop_check);
    if (provider == "openai_compatible") return generate_openai(prompt, temperature, on_chunk, stop_check);
    if (provider == "anthropic")   return generate_anthropic(prompt, temperature, on_chunk, stop_check);
    if (provider == "openrouter")  return generate_openrouter(prompt, temperature, on_chunk, stop_check);
    if (provider == "local")       return generate_local(prompt, temperature, on_chunk, stop_check);
    return "Error: Unknown provider kind: " + provider;
}


std::string standalone_ai_client_t::simple_post(
    const std::string& host,
    const std::string& path,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    std::function<std::string(const json&)> response_parser)
{
    constexpr int MAX_RETRIES = 3;
    constexpr int BASE_DELAY_MS = 2000;

    for (int attempt = 0; attempt <= MAX_RETRIES; ++attempt) {
        try {
            auto client = get_or_create_client(host);

            httplib::Headers h;
            for (auto& [k, v] : headers) h.emplace(k, v);

            auto res = client->Post(path.c_str(), h, body, "application/json");

            if (_cancelled) return "Error: Operation cancelled.";

            if (!res) {
                reset_client();
                auto err = res.error();
                if (err == httplib::Error::Canceled)
                    return "Error: Operation cancelled.";
                if (attempt < MAX_RETRIES) {
                    int delay = (std::min)(BASE_DELAY_MS * (1 << attempt), 30000);
                    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
                    continue;
                }
                return "Error: HTTP request failed: " + httplib::to_string(err);
            }

            if ((res->status == 429 || res->status == 503) && attempt < MAX_RETRIES) {
                int delay = (std::min)(BASE_DELAY_MS * (1 << attempt), 30000);
                reset_client();
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
                continue;
            }

            if (res->status != 200)
                return "Error: API returned status " + std::to_string(res->status) +
                       ": " + res->body.substr(0, 600);

            auto j = json::parse(res->body, nullptr, false);
            if (j.is_discarded())
                return "Error: API returned invalid JSON.";

            return response_parser(j);
        } catch (const std::exception& e) {
            reset_client();
            if (attempt < MAX_RETRIES) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                    (std::min)(BASE_DELAY_MS * (1 << attempt), 30000)));
                continue;
            }
            return std::string("Error: ") + e.what();
        }
    }
    return "Error: All retries exhausted.";
}


std::string standalone_ai_client_t::streaming_post(
    const std::string& host,
    const std::string& path,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    std::function<std::string(const std::string& sse_data)> chunk_parser,
    ai_stream_chunk_t on_chunk,
    ai_stop_predicate_t stop_check)
{
    auto client = get_or_create_client(host);

    httplib::Headers h;
    for (auto& [k, v] : headers) h.emplace(k, v);

    std::string accumulated;
    std::string sse_buffer;

    httplib::Request req;
    req.method = "POST";
    req.path = path;
    req.headers = h;
    req.headers.emplace("Content-Type", "application/json");
    req.body = body;
    req.content_receiver = [&](const char* data, size_t len, uint64_t, uint64_t) -> bool {
            if (_cancelled) return false;

            sse_buffer.append(data, len);


            size_t pos = 0;
            while (pos < sse_buffer.size()) {
                auto nl = sse_buffer.find('\n', pos);
                if (nl == std::string::npos) break;

                std::string line = sse_buffer.substr(pos, nl - pos);
                pos = nl + 1;


                if (!line.empty() && line.back() == '\r')
                    line.pop_back();

                if (line == "data: [DONE]" || line == "data:[DONE]")
                    continue;

                if (line.substr(0, 6) == "data: " || line.substr(0, 5) == "data:") {
                    std::string payload = line.substr(0, 5) == "data:" ?
                        line.substr(5) : line.substr(6);
                    if (payload.empty()) continue;

                    std::string chunk_text = chunk_parser(payload);
                    if (!chunk_text.empty()) {
                        accumulated += chunk_text;
                        if (on_chunk) on_chunk(chunk_text);
                        if (stop_check && stop_check(accumulated))
                            return false;
                    }
                }
            }
            sse_buffer.erase(0, pos);
            return true;
        };

    auto res = client->send(req);

    if (_cancelled) return "Error: Operation cancelled.";
    if (!res) return "Error: Streaming request failed: " + httplib::to_string(res.error());
    if (res->status != 200)
        return "Error: API returned status " + std::to_string(res->status);

    return accumulated;
}


std::string standalone_ai_client_t::generate_gemini(
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check)
{
    std::string base_url = _settings.get_active_base_url();
    std::string model = _settings.get_active_model();
    std::string api_key = _settings.get_active_api_key();

    json body = {
        {"contents", json::array({
            {{"role", "user"}, {"parts", json::array({{{"text", prompt}}})} }
        })},
        {"generationConfig", {
            {"temperature", temperature},
            {"maxOutputTokens", 16384}
        }}
    };

    if (on_chunk) {
        std::string path = "/v1beta/models/" + model + ":streamGenerateContent?alt=sse&key=" + api_key;
        return streaming_post(base_url, path, {}, body.dump(),
            [](const std::string& sse_data) -> std::string {
                auto j = json::parse(sse_data, nullptr, false);
                if (j.is_discarded()) return "";
                try {
                    return j["candidates"][0]["content"]["parts"][0]["text"].get<std::string>();
                } catch (...) { return ""; }
            }, on_chunk, stop_check);
    }

    std::string path = "/v1beta/models/" + model + ":generateContent?key=" + api_key;
    return simple_post(base_url, path, {}, body.dump(),
        [](const json& j) -> std::string {
            return j["candidates"][0]["content"]["parts"][0]["text"].get<std::string>();
        });
}


std::string standalone_ai_client_t::generate_openai(
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check)
{
    std::string base_url = _settings.get_active_base_url();
    std::string model = _settings.get_active_model();

    json body = {
        {"model", model},
        {"messages", json::array({
            {{"role", "system"}, {"content", "You are AiDA, an advanced reverse engineering assistant. Be precise and technical."}},
            {{"role", "user"}, {"content", prompt}}
        })},
        {"temperature", temperature},
        {"max_tokens", 16384},
        {"stream", on_chunk != nullptr}
    };

    std::map<std::string, std::string> headers = _settings.get_active_headers();
    if (!_settings.get_active_api_key().empty())
        headers["Authorization"] = "Bearer " + _settings.get_active_api_key();
    headers["Content-Type"] = "application/json";

    if (on_chunk) {
        return streaming_post(base_url, "/v1/chat/completions", headers, body.dump(),
            [](const std::string& sse_data) -> std::string {
                auto j = json::parse(sse_data, nullptr, false);
                if (j.is_discarded()) return "";
                try {
                    auto& choices = j["choices"];
                    if (choices.empty()) return "";
                    auto& delta = choices[0]["delta"];
                    if (delta.contains("content"))
                        return delta["content"].get<std::string>();
                } catch (...) {}
                return "";
            }, on_chunk, stop_check);
    }

    return simple_post(base_url, "/v1/chat/completions", headers, body.dump(),
        [](const json& j) -> std::string {
            return j["choices"][0]["message"]["content"].get<std::string>();
        });
}


std::string standalone_ai_client_t::generate_anthropic(
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check)
{
    std::string base_url = _settings.get_active_base_url();
    std::string model = _settings.get_active_model();

    std::string clean_model = model;
    for (const char* suffix : {" (Max Effort)", " (High Effort)", " (Medium Effort)",
                               " (Low Effort)", " (Standard)"}) {
        auto pos = clean_model.find(suffix);
        if (pos != std::string::npos) { clean_model.erase(pos); break; }
    }


    json system_block = {
        {"type", "text"},
        {"text", "You are AiDA, an advanced reverse engineering assistant. Be precise and technical."}
    };
    if (_settings.prompt_caching) {
        system_block["cache_control"] = {{"type", "ephemeral"}};
    }

    json body = {
        {"model", clean_model},
        {"max_tokens", 16384},
        {"messages", json::array({
            {{"role", "user"}, {"content", prompt}}
        })},
        {"system", json::array({system_block})},
        {"stream", on_chunk != nullptr}
    };


    if (_settings.thinking_enabled) {
        json thinking_cfg = {
            {"type", "enabled"},
            {"budget_tokens", (std::max)(_settings.thinking_budget, 1024)}
        };
        body["thinking"] = thinking_cfg;

    } else if (clean_model.find("thought") == std::string::npos) {
        body["temperature"] = temperature;
    }

    std::map<std::string, std::string> headers = _settings.get_active_headers();
    headers["x-api-key"] = _settings.get_active_api_key();
    headers["anthropic-version"] = "2023-06-01";
    headers["Content-Type"] = "application/json";


    std::string beta_features;
    auto add_beta = [&](const char* feature) {
        if (!beta_features.empty()) beta_features += ",";
        beta_features += feature;
    };


    add_beta("context-1m-2025-08-07");


    if (_settings.thinking_enabled)
        add_beta("interleaved-thinking-2025-05-14");


    if (_settings.prompt_caching)
        add_beta("prompt-caching-scope-2026-01-05");


    if (_settings.web_search_enabled)
        add_beta("web-search-2025-03-05");


    if (_settings.task_budget_tokens > 0)
        add_beta("task-budgets-2026-03-13");


    if (_settings.effort_level >= 0 && _settings.effort_level <= 3) {
        add_beta("effort-2025-11-24");
        static const char* effort_names[] = {"low", "medium", "high", "max"};
        body["effort"] = {{"level", effort_names[_settings.effort_level]}};
    }


    add_beta("advanced-tool-use-2025-11-20");


    add_beta("token-efficient-tools-2026-03-28");


    add_beta("structured-outputs-2025-12-15");

    if (!beta_features.empty())
        headers["anthropic-beta"] = beta_features;


    if (_settings.task_budget_tokens > 0) {
        body["task_budget"] = {{"total", _settings.task_budget_tokens}};
    }

    if (on_chunk) {

        std::string thinking_text;
        int64_t in_tokens = 0, out_tokens = 0, cache_read = 0, cache_write = 0;

        auto result = streaming_post(base_url, "/v1/messages", headers, body.dump(),
            [&](const std::string& sse_data) -> std::string {
                auto j = json::parse(sse_data, nullptr, false);
                if (j.is_discarded()) return "";
                try {
                    std::string type = j.value("type", "");


                    if (type == "message_start" && j.contains("message")) {
                        auto& usage = j["message"]["usage"];
                        if (usage.is_object()) {
                            in_tokens = usage.value("input_tokens", (int64_t)0);
                            cache_read = usage.value("cache_read_input_tokens", (int64_t)0);
                            cache_write = usage.value("cache_creation_input_tokens", (int64_t)0);
                        }
                    }
                    if (type == "message_delta" && j.contains("usage")) {
                        out_tokens = j["usage"].value("output_tokens", (int64_t)0);
                    }

                    if (type == "content_block_delta") {
                        auto& delta = j["delta"];
                        std::string delta_type = delta.value("type", "");
                        if (delta_type == "text_delta")
                            return delta["text"].get<std::string>();
                        if (delta_type == "thinking_delta") {
                            thinking_text += delta["thinking"].get<std::string>();

                            return "\x01THINK:" + delta["thinking"].get<std::string>();
                        }
                    }
                } catch (...) {}
                return "";
            }, on_chunk, stop_check);


        cost_tracking::session_input_tokens += in_tokens;
        cost_tracking::session_output_tokens += out_tokens;
        cost_tracking::session_cache_read += cache_read;
        cost_tracking::session_cache_write += cache_write;
        cost_tracking::session_request_count++;
        cost_tracking::session_cost_usd += cost_tracking::estimate_cost(
            clean_model, in_tokens, out_tokens, cache_read, cache_write);

        return result;
    }


    return simple_post(base_url, "/v1/messages", headers, body.dump(),
        [&](const json& j) -> std::string {
            std::string text;
            std::string thinking;

            for (auto& block : j["content"]) {
                std::string btype = block.value("type", "");
                if (btype == "text")
                    text += block["text"].get<std::string>();
                else if (btype == "thinking")
                    thinking += block["thinking"].get<std::string>();
            }


            if (j.contains("usage") && j["usage"].is_object()) {
                auto& usage = j["usage"];
                int64_t in_t = usage.value("input_tokens", (int64_t)0);
                int64_t out_t = usage.value("output_tokens", (int64_t)0);
                int64_t cr = usage.value("cache_read_input_tokens", (int64_t)0);
                int64_t cw = usage.value("cache_creation_input_tokens", (int64_t)0);
                cost_tracking::session_input_tokens += in_t;
                cost_tracking::session_output_tokens += out_t;
                cost_tracking::session_cache_read += cr;
                cost_tracking::session_cache_write += cw;
                cost_tracking::session_request_count++;
                cost_tracking::session_cost_usd += cost_tracking::estimate_cost(
                    clean_model, in_t, out_t, cr, cw);
            }


            if (!thinking.empty())
                return "\x01THINK:" + thinking + "\x01ENDTHINK\n" + text;
            return text;
        });
}


std::string standalone_ai_client_t::generate_openrouter(
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check)
{
    std::string model = _settings.get_active_model();
    std::string base_url = _settings.get_active_base_url();

    json body = {
        {"model", model},
        {"messages", json::array({
            {{"role", "user"}, {"content", prompt}}
        })},
        {"temperature", temperature},
        {"stream", on_chunk != nullptr}
    };

    std::map<std::string, std::string> headers = _settings.get_active_headers();
    headers["Authorization"] = "Bearer " + _settings.get_active_api_key();
    headers["X-Title"] = "AiDA Standalone";
    headers["Content-Type"] = "application/json";

    if (on_chunk) {
        return streaming_post(base_url, "/api/v1/chat/completions",
            headers, body.dump(),
            [](const std::string& sse_data) -> std::string {
                auto j = json::parse(sse_data, nullptr, false);
                if (j.is_discarded()) return "";
                try {
                    auto& choices = j["choices"];
                    if (!choices.empty() && choices[0].contains("delta"))
                        return choices[0]["delta"].value("content", "");
                } catch (...) {}
                return "";
            }, on_chunk, stop_check);
    }

    return simple_post(base_url, "/api/v1/chat/completions",
        headers, body.dump(),
        [](const json& j) -> std::string {
            return j["choices"][0]["message"]["content"].get<std::string>();
        });
}


std::string standalone_ai_client_t::generate_local(
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check)
{
    std::string base_url = _settings.get_active_base_url();
    if (base_url.empty()) return "Error: Local LLM base URL not configured.";

    std::string model = _settings.get_active_model();
    if (model.empty()) model = "llama3:latest";

    json body = {
        {"model", model},
        {"messages", json::array({
            {{"role", "user"}, {"content", prompt}}
        })},
        {"temperature", temperature},
        {"stream", on_chunk != nullptr}
    };

    std::map<std::string, std::string> headers = _settings.get_active_headers();
    headers["Content-Type"] = "application/json";
    if (!_settings.get_active_api_key().empty())
        headers["Authorization"] = "Bearer " + _settings.get_active_api_key();

    if (on_chunk) {
        return streaming_post(base_url, "/v1/chat/completions", headers, body.dump(),
            [](const std::string& sse_data) -> std::string {
                auto j = json::parse(sse_data, nullptr, false);
                if (j.is_discarded()) return "";
                try {
                    auto& choices = j["choices"];
                    if (!choices.empty() && choices[0].contains("delta"))
                        return choices[0]["delta"].value("content", "");
                } catch (...) {}
                return "";
            }, on_chunk, stop_check);
    }

    return simple_post(base_url, "/v1/chat/completions", headers, body.dump(),
        [](const json& j) -> std::string {
            return j["choices"][0]["message"]["content"].get<std::string>();
        });
}


std::string standalone_ai_client_t::build_chat_prompt(
    const std::string& user_message,
    const std::vector<std::pair<std::string, std::string>>& history)
{
    if (history.empty())
        return user_message;

    std::string prompt;
    prompt.reserve(4096);
    prompt += "Previous conversation:\n";
    for (auto& [role, content] : history) {
        prompt += role + ": " + content + "\n";
    }
    prompt += "\nCurrent message:\n" + user_message;
    return prompt;
}
