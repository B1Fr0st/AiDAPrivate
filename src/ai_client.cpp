#include "aida_pro.hpp"
#include "agentic.hpp"
#include "agent_tools.hpp"
#include "ida_utils.hpp"
#include "chat_widget.hpp"
#include "chat_widget_ui.hpp"
using json = nlohmann::json;

static std::string trim_copy(const std::string& value)
{
    qstring qv = value.c_str();
    qv.trim2();
    return qv.c_str();
}

static std::string format_api_status_error(int status, const std::string& raw_body)
{
    std::string detail;
    if (!raw_body.empty())
    {
        json parsed = json::parse(raw_body, nullptr, false);
        if (!parsed.is_discarded() && parsed.contains("error"))
        {
            const auto& err = parsed["error"];
            if (err.is_object())
            {
                detail = json_str(err, "message");
                if (detail.empty())
                    detail = json_dump_safe(err);
            }
            else
            {
                detail = json_dump_safe(err);
            }
        }

        if (detail.empty())
            detail = trim_copy(raw_body);
    }

    if (detail.size() > 600)
        detail = detail.substr(0, 600) + "...";

    if (detail.empty())
        return "Error: API returned status " + std::to_string(status);

    return "Error: API returned status " + std::to_string(status) + ": " + detail;
}

static int idaapi timer_cb(void* ud);

struct AIClient::ai_request_t : public exec_request_t
{
    std::string result;
    bool was_cancelled;
    AIClient::callback_t callback;
    qtimer_t timer;
    qstring request_type;
    std::weak_ptr<void> client_validity_token;

    ai_request_t(
        AIClient::callback_t cb,
        qtimer_t t,
        qstring req_type,
        std::shared_ptr<void> validity_token)
        : was_cancelled(false),
        callback(std::move(cb)),
        timer(t),
        request_type(std::move(req_type)),
        client_validity_token(validity_token) {}

    ~ai_request_t() override = default;

    ssize_t idaapi execute() override
    {
        std::shared_ptr<void> client_validity_sp = client_validity_token.lock();
        if (!client_validity_sp)
        {
            delete this;
            return 0;
        }

        try
        {
            if (timer != nullptr)
            {
                unregister_timer(timer);
                timer = nullptr;
            }

            if (was_cancelled)
            {
                msg(OBFSTR_C("AiDA: Request for %s was cancelled.\n"), request_type.c_str());
            }
            else if (callback)
            {
                callback(result);
            }
        }
        catch (const std::exception& e)
        {
            warning(OBFSTR_C("AI Assistant: Exception caught during AI request callback execution: %s"), e.what());
        }
        catch (...)
        {
            warning(OBFSTR_C("AI Assistant: Unknown exception caught during AI request callback execution."));
        }

        delete this;
        return 0;
    }
};

struct status_update_request_t : public exec_request_t
{
    agentic::status_update_t status;

    explicit status_update_request_t(const agentic::status_update_t& s) : status(s) {}

    ssize_t idaapi execute() override
    {
        AiDAChatPanel* panel = chat_widget::get_panel();
        if (panel != nullptr)
        {
            switch (status.type)
            {
                case agentic::status_type_t::calling_ai:
                {
                    panel->updateThinkingStatus(
                        QString::fromStdString(status.message),
                        QStringList(),
                        QString());
                    break;
                }
                case agentic::status_type_t::thinking:
                {
                    QStringList pending;
                    for (const auto& t : status.pending_tools)
                        pending.append(QString::fromStdString(t));
                    panel->updateThinkingStatus(
                        QString::fromStdString(status.reasoning),
                        pending,
                        QString());
                    break;
                }
                case agentic::status_type_t::executing_tool:
                {
                    QStringList pending;
                    for (const auto& t : status.pending_tools)
                        pending.append(QString::fromStdString(t));
                    panel->updateThinkingStatus(
                        QString(),
                        pending,
                        QString::fromStdString(status.tool_name));
                    break;
                }
                case agentic::status_type_t::tool_complete:
                {
                    panel->addToolResult(
                        QString::fromStdString(status.tool_name),
                        status.tool_success,
                        QString::fromStdString(status.message));
                    break;
                }
                default:
                    break;
            }
        }
        delete this;
        return 0;
    }
};

struct stream_chunk_request_t : public exec_request_t
{
    std::string chunk;

    explicit stream_chunk_request_t(const std::string& c) : chunk(c) {}

    ssize_t idaapi execute() override
    {
        AiDAChatPanel* panel = chat_widget::get_panel();
        if (panel != nullptr)
            panel->appendStreamChunk(QString::fromStdString(chunk));
        delete this;
        return 0;
    }
};

static int idaapi timer_cb(void* ud)
{
    auto* client = static_cast<AIClient*>(ud);

    if (client->_task_done.load())
    {
        return -1;
    }

    if (!client->_is_request_active.load())
    {
        client->_is_request_active = true;
        msg(OBFSTR_C("AiDA: Request for %s is in progress, please wait...\n"), client->_current_request_type.c_str());
    }
    else
    {
        int elapsed = client->_elapsed_secs.load();
        msg(OBFSTR_C("AiDA: Request for %s is in progress... elapsed time: %d second%s.\n"),
            client->_current_request_type.c_str(),
            elapsed,
            elapsed == 1 ? "" : "s");
    }

    client->_elapsed_secs++;
    return 1000;
}

AIClient::AIClient(const settings_t& settings)
    : _settings(settings), _validity_token(std::make_shared<char>()) {}

AIClient::~AIClient()
{
    _validity_token.reset();
    cancel_current_request();
    if (_worker_thread.joinable())
    {
        _worker_thread.join();
    }
}

void AIClient::cancel_current_request()
{
    _cancelled = true;
    std::shared_ptr<httplib::Client> client_to_stop;
    {
        std::lock_guard<std::mutex> lock(_http_client_mutex);
        client_to_stop = _http_client;
    }

    if (client_to_stop)
    {
        client_to_stop->stop();
    }
}

void AIClient::_generate(const std::string& prompt_text, callback_t callback, double temperature, const qstring& request_type)
{
    if (!is_available())
    {
        if (callback)
            callback("Error: AI client is not configured. Please set your API key in Settings.");
        return;
    }

    std::lock_guard<std::mutex> lock(_worker_thread_mutex);
    if (_worker_thread.joinable())
    {
        _worker_thread.join();
    }

    _cancelled = false;
    _task_done = false;
    _is_request_active = false;
    _current_request_type = request_type;
    _elapsed_secs = 0;

    qtimer_t timer = register_timer(1000, timer_cb, this);

    auto req = new ai_request_t(callback, timer, request_type, _validity_token);

    auto worker_func = [this, prompt_text, temperature, req, validity_token = this->_validity_token]() {
        std::string result;
        try
        {
            result = this->_blocking_generate(prompt_text, temperature);
        }
        catch (const std::exception& e)
        {
            result = "Error: Exception in worker thread: ";
            result += e.what();
            warning(OBFSTR_C("AiDA: %s"), result.c_str());
        }
        catch (...)
        {
            result = "Error: Unknown exception in worker thread.";
            warning(OBFSTR_C("AiDA: %s"), result.c_str());
        }

        _task_done = true;

        req->was_cancelled = _cancelled.load();
        if (!req->was_cancelled)
        {
            req->result = std::move(result);
        }

        execute_sync(*req, MFF_NOWAIT);
    };

    try
    {
        _worker_thread = std::thread(worker_func);
    }
    catch (const std::exception& e)
    {
        _task_done = true;
        unregister_timer(timer);
        delete req;
        if (callback)
            callback("Error: Failed to start worker thread: " + std::string(e.what()));
    }
}

std::shared_ptr<httplib::Client> AIClient::_get_or_create_client(
    const std::string& host,
    const httplib::Headers& headers)
{
    std::lock_guard<std::mutex> lock(_http_client_mutex);
    if (!_http_client || _last_http_host != host)
    {
        _http_client = std::make_shared<httplib::Client>(host.c_str());
        _last_http_host = host;

        _http_client->set_connection_timeout(3);
        _http_client->set_read_timeout(300);
        _http_client->set_write_timeout(10);
        _http_client->set_tcp_nodelay(true);
        _http_client->set_keep_alive(true);
        _http_client->set_decompress(true);
        _http_client->set_compress(true);
        _http_client->set_follow_location(true);
    }
    _http_client->set_default_headers(headers);
    return _http_client;
}

void AIClient::_reset_http_client()
{
    std::lock_guard<std::mutex> lock(_http_client_mutex);
    _http_client.reset();
    _last_http_host.clear();
}

std::string AIClient::_http_post_request(
    const std::string& host,
    const std::string& path,
    const httplib::Headers& headers,
    const std::string& body,
    std::function<std::string(const json&)> response_parser)
{
    std::shared_ptr<httplib::Client> current_client;
    try
    {
        current_client = _get_or_create_client(host, headers);

        auto res = current_client->Post(
            path.c_str(),
            body.c_str(),
            body.length(),
            "application/json",
            [this](uint64_t, uint64_t) {
                return !_cancelled.load();
            });

        if (_cancelled)
            return "Error: Operation cancelled.";

        if (!res)
        {
            auto err = res.error();
            _reset_http_client();
            if (err == httplib::Error::Canceled) {
                return "Error: Operation cancelled.";
            }
            return "Error: HTTP request failed: " + httplib::to_string(err);
        }
        if (res->status != 200)
        {
            qstring error_details = "No details in response body.";
            if (!res->body.empty())
            {
                try
                {
                    error_details = json_dump_safe(json::parse(res->body), 2).c_str();
                }
                catch (const std::exception&)
                {
                    error_details = res->body.c_str();
                }
            }
            msg(OBFSTR_C("AiDA: API Error. Host: %s, Status: %d\nResponse body: %s\n"), host.c_str(), res->status, error_details.c_str());
            return format_api_status_error(res->status, res->body);
        }
        json jres = json::parse(res->body, nullptr, false);
        if (jres.is_discarded())
        {
            msg(OBFSTR_C("AiDA: Failed to parse JSON response from %s.\nRaw body (first 512 chars): %.512s\n"),
                host.c_str(), res->body.c_str());
            return "Error: API returned invalid JSON response.";
        }
        try
        {
            return response_parser(jres);
        }
        catch (const std::exception& e)
        {
            msg(OBFSTR_C("AiDA: Failed to process API response from %s: %s\n"), host.c_str(), e.what());
            return std::string("Error: Failed to process API response. Details: ") + e.what();
        }
    }
    catch (const std::exception& e)
    {
        _reset_http_client();
        warning(OBFSTR_C("AI Assistant: API call to %s failed: %s\n"), host.c_str(), e.what());
        return std::string("Error: API call failed. Details: ") + e.what();
    }
}

std::string AIClient::_blocking_generate(const std::string& prompt_text, double temperature)
{
    if (!is_available())
        return "Error: AI client is not initialized. Check API key.";

    auto payload = _get_api_payload(sanitize_utf8(prompt_text), temperature);
    auto headers = _get_api_headers();
    auto host = _get_api_host();
    auto path = _get_api_path(_model_name);
    auto parser = [this](const json& jres) { return _parse_api_response(jres); };

    return _http_post_request(host, path, headers, json_dump_fast(payload), parser);
}

std::string AIClient::blocking_generate(const std::string& prompt_text, double temperature)
{
    return _blocking_generate(prompt_text, temperature);
}

std::string AIClient::streaming_blocking_generate(const std::string& prompt_text, double temperature, stream_callback_t on_chunk)
{
    qstring provider = ida_utils::qstring_tolower(_settings.api_provider.c_str());
    if (provider == "openai")
    {
        std::string non_stream = _blocking_generate(prompt_text, temperature);
        if (on_chunk && non_stream.rfind("Error:", 0) != 0)
            on_chunk(non_stream);
        return non_stream;
    }

    if (on_chunk)
    {
        std::string streamed = _streaming_blocking_generate(prompt_text, temperature, on_chunk);
        if (streamed.rfind("Error: API returned status ", 0) == 0)
        {
            msg(OBFSTR_C("AiDA: Streaming request failed; retrying once with non-streaming generation.\n"));
            std::string retried = _blocking_generate(prompt_text, temperature);
            if (retried.rfind("Error:", 0) != 0)
                return retried;
        }
        return streamed;
    }
    return _blocking_generate(prompt_text, temperature);
}

nlohmann::json AIClient::_get_streaming_payload(const std::string& prompt_text, double temperature) const
{
    auto payload = _get_api_payload(prompt_text, temperature);
    payload["stream"] = true;
    return payload;
}

std::string AIClient::_get_streaming_api_path(const std::string& model_name) const
{
    return _get_api_path(model_name);
}

std::string AIClient::_parse_sse_chunk(const std::string& data_line) const
{
    if (data_line == "[DONE]")
        return "";
    json j = json::parse(data_line, nullptr, false);
    if (j.is_discarded())
        return "";
    return _extract_sse_content(j);
}

std::string AIClient::_extract_sse_content(const nlohmann::json& j) const
{
    if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty())
    {
        auto delta = j["choices"][0].value("delta", json::object());
        return json_str(delta, "content");
    }
    return "";
}

std::string AIClient::_streaming_blocking_generate(const std::string& prompt_text, double temperature, stream_callback_t on_chunk)
{
    if (!is_available())
        return "Error: AI client is not initialized. Check API key.";

    auto payload = _get_streaming_payload(sanitize_utf8(prompt_text), temperature);
    auto headers = _get_api_headers();
    auto host = _get_api_host();
    auto path = _get_streaming_api_path(_model_name);

    return _streaming_http_post_request(host, path, headers, json_dump_fast(payload), on_chunk);
}

std::string AIClient::_streaming_http_post_request(
    const std::string& host,
    const std::string& path,
    const httplib::Headers& headers,
    const std::string& body,
    stream_callback_t on_chunk)
{
    std::shared_ptr<httplib::Client> current_client;
    try
    {
        current_client = _get_or_create_client(host, headers);

        std::string accumulated_text;
        accumulated_text.reserve(65536);
        std::string sse_buffer;
        sse_buffer.reserve(32768);
        std::string error_body;
        size_t sse_buf_start = 0;
        bool stream_error = false;
        bool stream_truncated = false;

        httplib::Request req;
        req.method = "POST";
        req.path = path;
        req.headers = headers;
        req.body = body;
        req.set_header("Content-Type", "application/json");
        req.set_header("Accept", "text/event-stream");

        req.content_receiver = [&](const char* data, size_t data_length, uint64_t, uint64_t) -> bool {
            try
            {
            if (_cancelled.load())
                return false;

            if (stream_error)
            {
                error_body.append(data, data_length);
                return true;
            }

            sse_buffer.append(data, data_length);

            size_t pos = sse_buf_start;
            while (pos < sse_buffer.size())
            {
                size_t line_end = sse_buffer.find('\n', pos);
                if (line_end == std::string::npos)
                    break;

                const char* line_ptr = sse_buffer.data() + pos;
                size_t line_len = line_end - pos;
                pos = line_end + 1;

                if (line_len > 0 && line_ptr[line_len - 1] == '\r')
                    --line_len;

                if (line_len == 0)
                    continue;

                if (line_len > 6 && std::memcmp(line_ptr, "data: ", 6) == 0)
                {
                    const char* payload_ptr = line_ptr + 6;
                    size_t payload_len = line_len - 6;

                    if (payload_len == 6 && std::memcmp(payload_ptr, "[DONE]", 6) == 0)
                        continue;

                    json chunk_json = json::parse(
                        payload_ptr, payload_ptr + payload_len, nullptr, false);
                    if (chunk_json.is_discarded())
                        continue;

                    // openai
                    if (chunk_json.contains("choices") && chunk_json["choices"].is_array() && !chunk_json["choices"].empty())
                    {
                        std::string fr = json_str(chunk_json["choices"][0], "finish_reason");
                        if (fr == "length" || fr == "LENGTH")
                            stream_truncated = true;
                    }
                    // gemini
                    if (chunk_json.contains("candidates") && chunk_json["candidates"].is_array() && !chunk_json["candidates"].empty())
                    {
                        std::string fr = json_str(chunk_json["candidates"][0], "finishReason");
                        if (fr == "MAX_TOKENS" || fr == "LENGTH")
                            stream_truncated = true;
                    }
                    // anthropic
                    if (json_str(chunk_json, "type") == "message_delta")
                    {
                        auto delta = chunk_json.value("delta", json::object());
                        std::string sr = json_str(delta, "stop_reason");
                        if (sr == "max_tokens")
                            stream_truncated = true;
                    }

                    std::string chunk_text = _extract_sse_content(chunk_json);

                    if (!chunk_text.empty())
                    {
                        accumulated_text += chunk_text;
                        try
                        {
                            if (on_chunk)
                                on_chunk(chunk_text);
                        }
                        catch (const std::exception&) {}


                    }
                }
            }

            sse_buf_start = pos;

            if (sse_buf_start > 32768)
            {
                sse_buffer.erase(0, sse_buf_start);
                sse_buf_start = 0;
            }

            }
            catch (const std::exception& e) {
                msg(OBFSTR_C("AiDA: SSE processing error: %s\n"), e.what());
            }
            return true;
        };

        req.response_handler = [&](const httplib::Response& resp) -> bool {
            if (resp.status != 200)
            {
                stream_error = true;
                return true;
            }
            return true;
        };

        auto res = current_client->send(req);

        if (_cancelled.load())
            return "Error: Operation cancelled.";

        if (!res)
        {
            auto err = res.error();
            _reset_http_client();
            if (err == httplib::Error::Canceled)
                return "Error: Operation cancelled.";
            return "Error: HTTP request failed: " + httplib::to_string(err);
        }

        if (res->status != 200)
        {
            qstring error_details = "No details in response body.";
            std::string resp_body;
            if (!error_body.empty())
                resp_body = error_body;
            else if (!accumulated_text.empty())
                resp_body = accumulated_text;
            else
                resp_body = res->body;
            if (!resp_body.empty())
            {
                try
                {
                    error_details = json_dump_safe(json::parse(resp_body), 2).c_str();
                }
                catch (const std::exception&)
                {
                    error_details = resp_body.c_str();
                }
            }
            msg(OBFSTR_C("AiDA: Streaming API Error. Host: %s, Status: %d\nResponse body: %s\n"),
                host.c_str(), res->status, error_details.c_str());
            return format_api_status_error(res->status, resp_body);
        }

        if (accumulated_text.empty() && !res->body.empty())
        {
            json jres = json::parse(res->body, nullptr, false);
            if (!jres.is_discarded())
            {
                try
                {
                    return _parse_api_response(jres);
                }
                catch (const std::exception& e)
                {
                    msg(OBFSTR_C("AiDA: Failed to process streaming fallback response: %s\n"), e.what());
                }
            }
            else
            {
                return res->body;
            }
        }

        if (accumulated_text.empty() && !sse_buffer.empty())
        {
            json jres = json::parse(sse_buffer, nullptr, false);
            if (!jres.is_discarded())
            {
                try
                {
                    return _parse_api_response(jres);
                }
                catch (const std::exception& e)
                {
                    msg(OBFSTR_C("AiDA: Failed to process streaming SSE buffer fallback: %s\n"), e.what());
                }
            }
        }

        if (stream_truncated && !accumulated_text.empty())
        {
            accumulated_text += "\n\n[RESPONSE_TRUNCATED]";
        }

        return accumulated_text;
    }
    catch (const std::exception& e)
    {
        _reset_http_client();
        warning(OBFSTR_C("AI Assistant: Streaming API call to %s failed: %s\n"), host.c_str(), e.what());
        return std::string("Error: API call failed. Details: ") + e.what();
    }
}

void AIClient::analyze_function(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_full_cached_context(ea, g_settings);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        callback(json_str(context, "message", "Failed to get context for analysis."));
        return;
    }

    std::string prompt = ida_utils::format_prompt(ANALYZE_FUNCTION_PROMPT, context);

    _generate(prompt, callback, _settings.temperature, "function analysis");
}

void AIClient::generate_struct(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_full_cached_context(ea, g_settings);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        callback(json_str(context, "message", "Failed to get context for struct generation."));
        return;
    }

    std::string prompt = ida_utils::format_prompt(GENERATE_STRUCT_PROMPT, context);
    _generate(prompt, callback, 0.0, "struct generation");
}

void AIClient::generate_hook(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_full_cached_context(ea, g_settings);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        callback(json_str(context, "message", "Failed to get context for hook generation."));
        return;
    }
    qstring q_func_name;
    get_func_name(&q_func_name, ea);
    std::string func_name = q_func_name.c_str();
    
    std::string clean_func_name;
    clean_func_name.reserve(func_name.size());
    for (char c : func_name)
        clean_func_name.push_back((qisalnum(c) || c == '_') ? c : '_');
    
    context["func_name"] = clean_func_name;

    std::string prompt = ida_utils::format_prompt(GENERATE_HOOK_PROMPT, context);
    _generate(prompt, callback, 0.0, "hook generation");
}

void AIClient::generate_comments(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_full_cached_context(ea, g_settings);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        callback(json_str(context, "message", "Failed to get context for comment generation."));
        return;
    }

    std::string prompt = ida_utils::format_prompt(GENERATE_COMMENTS_PROMPT, context);
    _generate(prompt, callback, 0.0, "comment generation");
}

void AIClient::custom_query(ea_t ea, const std::string& question, callback_t callback)
{
    json context = ida_utils::get_full_cached_context(ea, g_settings);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        callback(json_str(context, "message", "Failed to get context for query."));
        return;
    }

    context["user_question"] = question;
    std::string prompt = ida_utils::format_prompt(ASK_AI_PROMPT, context);
    _generate(prompt, callback, _settings.temperature, "AI query");
}

void AIClient::locate_global_pointer(ea_t ea, const std::string& target_name, addr_callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea, false, 16000);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        callback(BADADDR);
        return;
    }
    context["target_name"] = target_name;
    std::string prompt = ida_utils::format_prompt(LOCATE_GLOBAL_POINTER_PROMPT, context);

    auto on_result = [callback, target_name](const std::string& result) {
        if (!result.empty() && result.find("Error:") == std::string::npos && result.find("None") == std::string::npos)
        {
            try
            {
                std::string clean_result = result;
                clean_result.erase(std::remove(clean_result.begin(), clean_result.end(), '`'), clean_result.end());
                clean_result.erase(0, clean_result.find_first_not_of(" \t\n\r"));
                clean_result.erase(clean_result.find_last_not_of(" \t\n\r") + 1);
                ea_t addr = std::stoull(clean_result, nullptr, 16);
                callback(addr);
            }
            catch (const std::exception&)
            {
                msg(OBFSTR_C("AI Assistant: AI returned a non-address value for %s: %s\n"), target_name.c_str(), result.c_str());
                callback(BADADDR);
            }
        }
        else
        {
            callback(BADADDR);
        }
    };
    _generate(prompt, on_result, 0.0, "global pointer location");
}

void AIClient::rename_all(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_full_cached_context(ea, g_settings);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        callback(json_str(context, "message", "Failed to get context for renaming."));
        return;
    }

    std::string prompt = ida_utils::format_prompt(RENAME_ALL_PROMPT, context);
    _generate(prompt, callback, 0.0, "renaming");
}

void AIClient::chat_message(ea_t ea, const std::string& message,
                            const std::vector<std::pair<std::string, std::string>>& history,
                            callback_t callback)
{
    json context;

    func_t* pfn = get_func(ea);
    if (pfn != nullptr)
    {
        context = ida_utils::get_full_cached_context(ea, g_settings);
        if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
        {
            context = json{{"ok", true}};
        }
    }
    else
    {
        context["ok"] = true;
        context["code"] = "// No function selected.";
        context["language"] = "N/A";
        context["func_ea_hex"] = "N/A";
        context["func_prototype"] = "// N/A";
        context["xrefs_to"] = "// N/A";
        context["xrefs_from"] = "// N/A";
        context["local_vars"] = "// N/A";
        context["string_xrefs"] = "// N/A";
        context["struct_context"] = "// N/A";
        context["decompiler_warnings"] = "// N/A";
        context["binary_metadata"] = ida_utils::get_binary_metadata();
        context["imports_context"] = "// N/A";
        context["type_context"] = "// N/A";
    }

    std::string history_str;
    for (const auto& [role, content] : history)
    {
        history_str += "**" + role + ":** " + content + "\n\n";
    }

    context["user_question"] = message;
    context["chat_history"] = history_str;

    std::string prompt = ida_utils::format_prompt(CHAT_PROMPT, context);
    _generate(prompt, callback, _settings.temperature, "chat");
}

void AIClient::fix_analysis(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_full_cached_context(ea, g_settings);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        callback(json_str(context, "message", "Failed to get context for analysis correction."));
        return;
    }

    std::string prompt = ida_utils::format_prompt(FIX_ANALYSIS_PROMPT, context);
    _generate(prompt, callback, 0.0, "analysis correction");
}

void AIClient::agentic_query(ea_t ea, const std::string& question, callback_t callback)
{
    if (!is_available())
    {
        if (callback)
            callback("Error: AI client is not configured. Please set your API key in Settings.");
        return;
    }

    std::ostringstream ctx_ss;
    
    json context = ida_utils::get_full_cached_context(ea, g_settings);
    if (context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>())
    {
        ctx_ss << "**Binary Metadata:**\n" << json_str(context, "binary_metadata", "N/A") << "\n\n";
        ctx_ss << "**Function Prototype:**\n```cpp\n" << json_str(context, "func_prototype", "N/A") << "\n```\n\n";
        ctx_ss << "**Decompiled Code (at " << json_str(context, "func_ea_hex", "?") << "):**\n```cpp\n"
               << json_str(context, "code", "// No code") << "\n```\n\n";
        ctx_ss << "**Local Variables:**\n```\n" << json_str(context, "local_vars", "N/A") << "\n```\n\n";
        ctx_ss << "**String References:**\n" << json_str(context, "string_xrefs", "N/A") << "\n\n";
        ctx_ss << "**Imports Used:**\n" << json_str(context, "imports_context", "N/A") << "\n\n";
        ctx_ss << "**Types Referenced:**\n" << json_str(context, "type_context", "N/A") << "\n\n";
        ctx_ss << "**Callers:**\n" << json_str(context, "xrefs_to", "N/A") << "\n\n";
        ctx_ss << "**Callees:**\n" << json_str(context, "xrefs_from", "N/A") << "\n\n";
        ctx_ss << "**Struct Usage:**\n" << json_str(context, "struct_context", "N/A") << "\n\n";
    }
    else
    {
        ctx_ss << "**Binary Metadata:**\n" << ida_utils::get_binary_metadata() << "\n\n";
        ctx_ss << "No function selected at the current address.\n";
    }
    
    std::string agentic_prompt = agentic::build_agentic_prompt(question, ctx_ss.str());
    
    std::lock_guard<std::mutex> lock(_worker_thread_mutex);
    if (_worker_thread.joinable())
        _worker_thread.join();
    
    _cancelled = false;
    _task_done = false;
    _is_request_active = false;
    _current_request_type = "agentic query";
    _elapsed_secs = 0;
    
    qtimer_t timer = register_timer(1000, timer_cb, this);
    auto req = new ai_request_t(callback, timer, "agentic query", _validity_token);
    
    auto worker_func = [this, agentic_prompt, req, validity_token = this->_validity_token]() {
        std::string result;
        try
        {
            agentic::config_t config;
            config.max_iterations = 25;
            config.temperature = _settings.temperature;
            config.verbose_logging = true;
            config.max_context_tokens = g_settings.get_active_context_window();
            
            auto on_status = [](const agentic::status_update_t& status) {
                auto* sreq = new status_update_request_t(status);
                execute_sync(*sreq, MFF_NOWAIT);
            };

            auto on_stream = [](const std::string& chunk) {
                auto* creq = new stream_chunk_request_t(chunk);
                execute_sync(*creq, MFF_NOWAIT);
            };
            
            auto agentic_result = agentic::run(
                this, agentic_prompt, config, &_cancelled,
                [](int iter, const std::string& status) {
                    msg(OBFSTR_C("AiDA Agent: [%d] %s\n"), iter, status.c_str());
                },
                on_status,
                on_stream);
            
            if (agentic_result.was_cancelled)
            {
                req->was_cancelled = true;
            }
            else
            {
                std::ostringstream response_ss;
                
                if (!agentic_result.iterations.empty())
                {
                    response_ss << "**Agent Actions Taken (" << agentic_result.total_iterations << " iteration(s)):**\n";
                    for (const auto& iter : agentic_result.iterations)
                    {
                        for (const auto& tr : iter.tool_results)
                        {
                            response_ss << "- `" << tr.tool_name << "`: "
                                        << (tr.success ? "✓" : "✗") << " " << tr.message << "\n";
                        }
                    }
                    response_ss << "\n---\n\n";
                }
                
                response_ss << agentic_result.final_response;
                result = response_ss.str();
            }
        }
        catch (const std::exception& e)
        {
            result = "Error: Agentic engine exception: ";
            result += e.what();
        }
        
        _task_done = true;
        req->was_cancelled = _cancelled.load();
        if (!req->was_cancelled)
            req->result = std::move(result);
        execute_sync(*req, MFF_NOWAIT);
    };
    
    try
    {
        _worker_thread = std::thread(worker_func);
    }
    catch (const std::exception& e)
    {
        _task_done = true;
        unregister_timer(timer);
        delete req;
        if (callback)
            callback("Error: Failed to start worker thread: " + std::string(e.what()));
    }
}

void AIClient::agentic_chat(ea_t ea, const std::string& message,
                            const std::vector<std::pair<std::string, std::string>>& history,
                            callback_t callback)
{
    if (!is_available())
    {
        if (callback)
            callback("Error: AI client is not configured. Please set your API key in Settings.");
        return;
    }

    std::ostringstream ctx_ss;
    
    func_t* pfn = get_func(ea);
    if (pfn != nullptr)
    {
        json context = ida_utils::get_full_cached_context(ea, g_settings);
        if (context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>())
        {
            ctx_ss << "**Binary Metadata:**\n" << json_str(context, "binary_metadata", "N/A") << "\n\n";
            ctx_ss << "**Function Prototype:**\n```cpp\n" << json_str(context, "func_prototype", "N/A") << "\n```\n\n";
            ctx_ss << "**Decompiled Code (at " << json_str(context, "func_ea_hex", "?") << "):**\n```cpp\n"
                   << json_str(context, "code", "// No code") << "\n```\n\n";
            ctx_ss << "**Local Variables:**\n```\n" << json_str(context, "local_vars", "N/A") << "\n```\n\n";
            ctx_ss << "**String References:**\n" << json_str(context, "string_xrefs", "N/A") << "\n\n";
            ctx_ss << "**Imports Used:**\n" << json_str(context, "imports_context", "N/A") << "\n\n";
            ctx_ss << "**Types Referenced:**\n" << json_str(context, "type_context", "N/A") << "\n\n";
            ctx_ss << "**Callers:**\n" << json_str(context, "xrefs_to", "N/A") << "\n\n";
            ctx_ss << "**Callees:**\n" << json_str(context, "xrefs_from", "N/A") << "\n\n";
            ctx_ss << "**Struct Usage:**\n" << json_str(context, "struct_context", "N/A") << "\n\n";
        }
    }
    else
    {
        ctx_ss << "**Binary Metadata:**\n" << ida_utils::get_binary_metadata() << "\n\n";
        ctx_ss << "No function selected.\n";
    }
    
    std::string history_str;
    size_t max_history_tokens = static_cast<size_t>(g_settings.get_active_context_window()) / 6;
    size_t history_token_count = 0;

    for (int i = static_cast<int>(history.size()) - 1; i >= 0; --i)
    {
        std::string entry = "**" + history[i].first + ":** " + history[i].second + "\n\n";
        size_t entry_tokens = agentic::estimate_tokens(entry);
        if (history_token_count + entry_tokens > max_history_tokens && !history_str.empty())
        {
            history_str = "[Earlier messages omitted for context management]\n\n" + history_str;
            break;
        }
        history_token_count += entry_tokens;
        history_str = entry + history_str;
    }
    
    std::string agentic_prompt = agentic::build_agentic_prompt(message, ctx_ss.str(), history_str);
    
    std::lock_guard<std::mutex> lock(_worker_thread_mutex);
    if (_worker_thread.joinable())
        _worker_thread.join();
    
    _cancelled = false;
    _task_done = false;
    _is_request_active = false;
    _current_request_type = "agentic chat";
    _elapsed_secs = 0;
    
    qtimer_t timer = register_timer(1000, timer_cb, this);
    auto req = new ai_request_t(callback, timer, "agentic chat", _validity_token);
    
    auto worker_func = [this, agentic_prompt, req, validity_token = this->_validity_token]() {
        std::string result;
        try
        {
            agentic::config_t config;
            config.max_iterations = 25;
            config.temperature = _settings.temperature;
            config.verbose_logging = true;
            config.max_context_tokens = g_settings.get_active_context_window();
            
            auto on_status = [](const agentic::status_update_t& status) {
                auto* sreq = new status_update_request_t(status);
                execute_sync(*sreq, MFF_NOWAIT);
            };

            auto on_stream = [](const std::string& chunk) {
                auto* creq = new stream_chunk_request_t(chunk);
                execute_sync(*creq, MFF_NOWAIT);
            };
            
            auto agentic_result = agentic::run(
                this, agentic_prompt, config, &_cancelled,
                [](int iter, const std::string& status) {
                    msg(OBFSTR_C("AiDA Agent: [%d] %s\n"), iter, status.c_str());
                },
                on_status,
                on_stream);
            
            if (agentic_result.was_cancelled)
            {
                req->was_cancelled = true;
            }
            else
            {
                std::ostringstream response_ss;
                
                if (!agentic_result.iterations.empty())
                {
                    response_ss << "**Agent Actions (" << agentic_result.total_iterations << " iteration(s)):**\n";
                    for (const auto& iter : agentic_result.iterations)
                    {
                        for (const auto& tr : iter.tool_results)
                        {
                            response_ss << "- `" << tr.tool_name << "`: "
                                        << (tr.success ? "✓" : "✗") << " " << tr.message << "\n";
                        }
                    }
                    response_ss << "\n---\n\n";
                }
                
                response_ss << agentic_result.final_response;
                result = response_ss.str();
            }
        }
        catch (const std::exception& e)
        {
            result = "Error: Agentic engine exception: ";
            result += e.what();
        }
        
        _task_done = true;
        req->was_cancelled = _cancelled.load();
        if (!req->was_cancelled)
            req->result = std::move(result);
        execute_sync(*req, MFF_NOWAIT);
    };
    
    try
    {
        _worker_thread = std::thread(worker_func);
    }
    catch (const std::exception& e)
    {
        _task_done = true;
        unregister_timer(timer);
        delete req;
        if (callback)
            callback("Error: Failed to start worker thread: " + std::string(e.what()));
    }
}

GeminiClient::GeminiClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.gemini_model_name;
}

bool GeminiClient::is_available() const
{
    return !_settings.gemini_api_key.empty();
}


std::string GeminiClient::_get_api_host() const
{
    if (!_settings.gemini_base_url.empty())
        return _settings.gemini_base_url;
    return "https://generativelanguage.googleapis.com";
}

std::string GeminiClient::_get_api_path(const std::string& model_name) const { return "/v1beta/models/" + model_name + ":generateContent?key=" + _settings.gemini_api_key; }
httplib::Headers GeminiClient::_get_api_headers() const { return {}; }
json GeminiClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    std::string system_prompt = BASE_PROMPT;
    if (!g_settings.active_prompt_name.empty())
    {
        auto it = g_settings.custom_prompts.find(g_settings.active_prompt_name);
        if (it != g_settings.custom_prompts.end())
            system_prompt = it->second;
    }

    std::string full_prompt = system_prompt + "\n\n" + prompt_text;

    return {
        {"contents", {{{"role", "user"}, {"parts", {{{"text", full_prompt}}}}}}},
        {"generationConfig", {{"temperature", temperature}, {"maxOutputTokens", 16384}}}
    };
}

std::string GeminiClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = "Gemini API Error: ";
        if (jres["error"].is_object() && jres["error"].contains("message") && jres["error"]["message"].is_string())
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += json_dump_safe(jres, 2);
        }
        msg(OBFSTR_C("AiDA: %s\n"), error_msg.c_str());
        return "Error: " + error_msg;
    }

    const auto candidates = jres.value("candidates", json::array());
    if (candidates.empty() || !candidates[0].is_object())
    {
        if (jres.contains("promptFeedback") && jres["promptFeedback"].contains("blockReason") && jres["promptFeedback"]["blockReason"].is_string()) {
            std::string reason = jres["promptFeedback"]["blockReason"].get<std::string>();
            msg(OBFSTR_C("AiDA: Gemini API blocked the prompt. Reason: %s\n"), reason.c_str());
            return "Error: Prompt was blocked by API for reason: " + reason;
        }
        msg(OBFSTR_C("AiDA: Invalid Gemini API response: 'candidates' array is missing or empty.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'candidates' array from API.";
    }

    const auto& first_candidate = candidates[0];
    std::string finish_reason = json_str(first_candidate, "finishReason", "UNKNOWN");

    if (finish_reason != "STOP")
    {
        if (finish_reason == "MAX_TOKENS" || finish_reason == "LENGTH")
        {
            msg(OBFSTR_C("AiDA: Gemini API response truncated (finishReason: %s). Extracting partial content.\n"), finish_reason.c_str());
            const auto trunc_content = first_candidate.value("content", json::object());
            if (trunc_content.is_object())
            {
                const auto trunc_parts = trunc_content.value("parts", json::array());
                if (!trunc_parts.empty() && trunc_parts[0].is_object())
                {
                    std::string partial = json_str(trunc_parts[0], "text");
                    if (!partial.empty())
                        return partial + "\n\n[RESPONSE_TRUNCATED]";
                }
            }
            return "Error: API response truncated and no content could be extracted.";
        }
        msg(OBFSTR_C("AiDA: Gemini API returned a non-STOP finish reason: %s\n"), finish_reason.c_str());
        return "Error: API request finished unexpectedly. Reason: " + finish_reason;
    }

    const auto content = first_candidate.value("content", json::object());
    if (!content.is_object())
    {
        msg(OBFSTR_C("AiDA: Invalid Gemini API response: 'content' object is missing or invalid.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'content' object from API.";
    }

    const auto parts = content.value("parts", json::array());
    if (parts.empty() || !parts[0].is_object())
    {
        msg(OBFSTR_C("AiDA: Invalid Gemini API response: 'parts' array is missing, empty, or invalid.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'parts' array from API.";
    }

    return json_str(parts[0], "text", "Error: 'text' field not found in API response.");
}

nlohmann::json GeminiClient::_get_streaming_payload(const std::string& prompt_text, double temperature) const
{
    return _get_api_payload(prompt_text, temperature);
}

std::string GeminiClient::_get_streaming_api_path(const std::string& model_name) const
{
    return "/v1beta/models/" + model_name + ":streamGenerateContent?alt=sse&key=" + _settings.gemini_api_key;
}

std::string GeminiClient::_parse_sse_chunk(const std::string& data_line) const
{
    json j = json::parse(data_line, nullptr, false);
    if (j.is_discarded())
        return "";
    return _extract_sse_content(j);
}

std::string GeminiClient::_extract_sse_content(const nlohmann::json& j) const
{
    if (j.contains("candidates") && j["candidates"].is_array() && !j["candidates"].empty())
    {
        auto& candidate = j["candidates"][0];
        auto content = candidate.value("content", json::object());
        if (content.is_object())
        {
            auto parts = content.value("parts", json::array());
            if (!parts.empty() && parts[0].is_object())
                return json_str(parts[0], "text");
        }
    }
    return "";
}

OpenAIClient::OpenAIClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.openai_model_name;
}

bool OpenAIClient::is_available() const
{
    return !_settings.openai_api_key.empty();
}

std::string OpenAIClient::_get_api_host() const
{
    if (!_settings.openai_base_url.empty())
        return _settings.openai_base_url;
    return "https://api.openai.com";
}

std::string OpenAIClient::_get_api_path(const std::string&) const { return "/v1/chat/completions"; }
httplib::Headers OpenAIClient::_get_api_headers() const
{
    return {
        {"Authorization", "Bearer " + _settings.openai_api_key},
        {"Content-Type", "application/json"}
    };
}
json OpenAIClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    std::string model = trim_copy(_model_name);
    if (model.empty())
    {
        qstring provider = ida_utils::qstring_tolower(_settings.api_provider.c_str());
        if (provider == "openrouter")
            model = trim_copy(_settings.openrouter_model_name);
        else
            model = trim_copy(_settings.openai_model_name);
    }
    if (model.empty())
        model = "gpt-5";

    std::string system_prompt = BASE_PROMPT;
    if (!g_settings.active_prompt_name.empty())
    {
        auto it = g_settings.custom_prompts.find(g_settings.active_prompt_name);
        if (it != g_settings.custom_prompts.end())
            system_prompt = it->second;
    }

    std::string model_id = model;
    bool is_reasoning = false;
    std::string reasoning_effort;

    if (model == "gpt-5.1 Instant")
    {
        model_id = "gpt-5.1";
        is_reasoning = true;
        reasoning_effort = "none";
    }
    else if (model == "gpt-5.1 Thinking")
    {
        model_id = "gpt-5.1";
        is_reasoning = true;
        reasoning_effort = "high";
    }
    else if (model == "gpt-5" || model == "gpt-5-mini" || model == "gpt-5-nano")
    {
        is_reasoning = true;
        reasoning_effort = "minimal";
    }
    else if (model.find("o1") == 0 || model.find("o3") == 0 || model.find("o4") == 0)
    {
        is_reasoning = true;
    }

    json payload = {
        {"model", model_id},
        {"messages", {
            {{"role", "system"}, {"content", system_prompt}},
            {{"role", "user"}, {"content", prompt_text}}
        }},
        {"max_completion_tokens", 16384}
    };

    if (is_reasoning)
    {
        if (!reasoning_effort.empty())
            payload["reasoning_effort"] = reasoning_effort;
    }
    else
    {
        payload["temperature"] = temperature;
    }

    return payload;
}

std::string OpenAIClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = "OpenAI API Error: ";
        if (jres["error"].is_object() && jres["error"].contains("message") && jres["error"]["message"].is_string())
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += json_dump_safe(jres, 2);
        }
        msg(OBFSTR_C("AiDA: %s\n"), error_msg.c_str());
        return "Error: " + error_msg;
    }

    const auto choices = jres.value("choices", json::array());
    if (choices.empty() || !choices[0].is_object())
    {
        if (jres.contains("promptFeedback") && jres["promptFeedback"].contains("blockReason") && jres["promptFeedback"]["blockReason"].is_string()) {
            std::string reason = jres["promptFeedback"]["blockReason"].get<std::string>();
            msg(OBFSTR_C("AiDA: OpenAI API blocked the prompt. Reason: %s\n"), reason.c_str());
            return "Error: Prompt was blocked by API for reason: " + reason;
        }
        msg(OBFSTR_C("AiDA: Invalid OpenAI API response: 'choices' array is missing or empty.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'choices' array from API.";
    }

    const auto& first_choice = choices[0];
    std::string finish_reason = json_str(first_choice, "finish_reason", "UNKNOWN");

    if (finish_reason != "stop" && finish_reason != "STOP")
    {
        if (finish_reason == "length" || finish_reason == "LENGTH")
        {
            msg(OBFSTR_C("AiDA: OpenAI API response truncated (finish_reason: length). Extracting partial content.\n"));
            const auto partial_msg = first_choice.value("message", json::object());
            if (partial_msg.is_object())
            {
                std::string partial = json_str(partial_msg, "content");
                if (!partial.empty())
                    return partial + "\n\n[RESPONSE_TRUNCATED]";
            }
            return "Error: API response truncated and no content could be extracted.";
        }
        msg(OBFSTR_C("AiDA: OpenAI API returned a non-STOP finish reason: %s\n"), finish_reason.c_str());
        return "Error: API request finished unexpectedly. Reason: " + finish_reason;
    }

    const auto message = first_choice.value("message", json::object());
    if (!message.is_object())
    {
        msg(OBFSTR_C("AiDA: Invalid OpenAI API response: 'message' object is missing or invalid.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'message' object from API.";
    }

    return json_str(message, "content", "Error: 'content' field not found in API response.");
}

nlohmann::json OpenAIClient::_get_streaming_payload(const std::string& prompt_text, double temperature) const
{
    auto payload = _get_api_payload(prompt_text, temperature);
    payload["stream"] = true;
    return payload;
}

std::string OpenAIClient::_parse_sse_chunk(const std::string& data_line) const
{
    if (data_line == "[DONE]")
        return "";
    json j = json::parse(data_line, nullptr, false);
    if (j.is_discarded())
        return "";
    return _extract_sse_content(j);
}

std::string OpenAIClient::_extract_sse_content(const nlohmann::json& j) const
{
    if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty())
    {
        auto& choice = j["choices"][0];
        auto delta = choice.value("delta", json::object());
        return json_str(delta, "content");
    }
    return "";
}

OpenRouterClient::OpenRouterClient(const settings_t& settings) : OpenAIClient(settings)
{
    _model_name = _settings.openrouter_model_name;
}

bool OpenRouterClient::is_available() const
{
    return !_settings.openrouter_api_key.empty();
}

std::string OpenRouterClient::_get_api_host() const { return "https://openrouter.ai"; }
std::string OpenRouterClient::_get_api_path(const std::string&) const { return "/api/v1/chat/completions"; }
httplib::Headers OpenRouterClient::_get_api_headers() const
{
    std::string auth = _settings.openrouter_api_key;
    if (auth.find("Bearer ") != 0) {
        auth = "Bearer " + auth;
    }
    return {
        {"Authorization", auth},
        {"Content-Type", "application/json"}
    };
}

AnthropicClient::AnthropicClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.anthropic_model_name;
}

bool AnthropicClient::is_available() const
{
    return !_settings.anthropic_api_key.empty();
}

std::string AnthropicClient::_get_api_host() const
{
    if (!_settings.anthropic_base_url.empty())
        return _settings.anthropic_base_url;
    return "https://api.anthropic.com";
}

std::string AnthropicClient::_get_api_path(const std::string&) const { return "/v1/messages"; }
httplib::Headers AnthropicClient::_get_api_headers() const
{
    httplib::Headers headers = {
        {"x-api-key", _settings.anthropic_api_key},
        {"anthropic-version", "2023-06-01"},
        {"Content-Type", "application/json"}
    };

    if (_model_name.find("claude-opus-4-5") != std::string::npos)
    {
        headers.emplace("anthropic-beta", "effort-2025-11-24");
    }
    else if (_model_name.find("claude-3-7-sonnet") != std::string::npos)
    {
        headers.emplace("anthropic-beta", "output-128k-2025-02-19");
    }

    return headers;
}
json AnthropicClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    std::string model_id = _model_name;
    std::string effort = "";
    bool use_thinking = false;

    if (model_id == "claude-opus-4-5 (High Effort)")
    {
        model_id = "claude-opus-4-5";
        effort = "high";
    }
    else if (model_id == "claude-opus-4-5 (Medium Effort)")
    {
        model_id = "claude-opus-4-5";
        effort = "medium";
    }
    else if (model_id == "claude-opus-4-5 (Low Effort)")
    {
        model_id = "claude-opus-4-5";
        effort = "low";
    }
    else if (model_id == "claude-3-7-sonnet-thought")
    {
        model_id = "claude-3-7-sonnet";
        use_thinking = true;
    }

    std::string system_prompt = BASE_PROMPT;
    if (!g_settings.active_prompt_name.empty())
    {
        auto it = g_settings.custom_prompts.find(g_settings.active_prompt_name);
        if (it != g_settings.custom_prompts.end())
            system_prompt = it->second;
    }

    json payload = {
        {"model", model_id},
        {"system", system_prompt},
        {"messages", {{{"role", "user"}, {"content", prompt_text}}}},
        {"max_tokens", 16384}
    };

    if (!effort.empty())
    {
        payload["output_config"] = { {"effort", effort} };
    }
    else if (use_thinking)
    {
        payload["thinking"] = { {"type", "enabled"}, {"budget_tokens", 10000} };
        payload["max_tokens"] = 16384;
    }
    else
    {
        payload["temperature"] = temperature;
    }

    return payload;
}

std::string AnthropicClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = "Anthropic API Error: ";
        if (jres["error"].is_object() && jres["error"].contains("message") && jres["error"]["message"].is_string())
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += json_dump_safe(jres, 2);
        }
        msg(OBFSTR_C("AiDA: %s\n"), error_msg.c_str());
        return "Error: " + error_msg;
    }

    const auto content = jres.value("content", json::array());
    if (content.empty())
    {
        if (jres.contains("promptFeedback") && jres["promptFeedback"].contains("blockReason") && jres["promptFeedback"]["blockReason"].is_string()) {
            std::string reason = jres["promptFeedback"]["blockReason"].get<std::string>();
            msg(OBFSTR_C("AiDA: Anthropic API blocked the prompt. Reason: %s\n"), reason.c_str());
            return "Error: Prompt was blocked by API for reason: " + reason;
        }
        msg(OBFSTR_C("AiDA: Invalid Anthropic API response: 'content' array is missing or empty.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'content' array from API.";
    }

    std::string stop_reason = json_str(jres, "stop_reason", "UNKNOWN");
    if (stop_reason != "end_turn" && stop_reason != "max_tokens"
        && stop_reason != "tool_use" && stop_reason != "stop_sequence")
    {
        msg(OBFSTR_C("AiDA: Anthropic API returned a non-success stop reason: %s\n"), stop_reason.c_str());
        return "Error: API request finished unexpectedly. Reason: " + stop_reason;
    }

    bool anthropic_truncated = (stop_reason == "max_tokens");

    std::string result_text;
    for (const auto& block : content)
    {
        if (block.is_object() && json_str(block, "type") == "text")
        {
            result_text += json_str(block, "text");
        }
    }

    if (result_text.empty())
    {
        msg(OBFSTR_C("AiDA: No text content found in Anthropic API response.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: No text content found in API response.";
    }

    if (anthropic_truncated)
    {
        msg(OBFSTR_C("AiDA: Anthropic API response truncated (stop_reason: max_tokens).\n"));
        result_text += "\n\n[RESPONSE_TRUNCATED]";
    }

    return result_text;
}

nlohmann::json AnthropicClient::_get_streaming_payload(const std::string& prompt_text, double temperature) const
{
    auto payload = _get_api_payload(prompt_text, temperature);
    payload["stream"] = true;
    return payload;
}

std::string AnthropicClient::_parse_sse_chunk(const std::string& data_line) const
{
    json j = json::parse(data_line, nullptr, false);
    if (j.is_discarded())
        return "";
    return _extract_sse_content(j);
}

std::string AnthropicClient::_extract_sse_content(const nlohmann::json& j) const
{
    std::string event_type = json_str(j, "type");
    if (event_type == "content_block_delta")
    {
        auto delta = j.value("delta", json::object());
        if (json_str(delta, "type") == "text_delta")
            return json_str(delta, "text");
    }
    return "";
}

CopilotClient::CopilotClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.copilot_model_name;
}

bool CopilotClient::is_available() const
{
    return !_settings.copilot_proxy_address.empty();
}

std::string CopilotClient::_get_api_host() const { return _settings.copilot_proxy_address; }
std::string CopilotClient::_get_api_path(const std::string&) const { return "/v1/chat/completions"; }
httplib::Headers CopilotClient::_get_api_headers() const { return {{"Content-Type", "application/json"}}; }
json CopilotClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    std::string system_prompt = BASE_PROMPT;
    if (!g_settings.active_prompt_name.empty())
    {
        auto it = g_settings.custom_prompts.find(g_settings.active_prompt_name);
        if (it != g_settings.custom_prompts.end())
            system_prompt = it->second;
    }

    return {
        {"model", _model_name},
        {"messages", {
            {{"role", "system"}, {"content", system_prompt}},
            {{"role", "user"}, {"content", prompt_text}}
        }},
        {"temperature", temperature},
        {"max_tokens", 16384}
    };
}
std::string CopilotClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = "Copilot API Error: ";
        if (jres["error"].is_object() && jres["error"].contains("message") && jres["error"]["message"].is_string())
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += json_dump_safe(jres, 2);
        }
        msg(OBFSTR_C("AiDA: %s\n"), error_msg.c_str());
        return "Error: " + error_msg;
    }

    const auto choices = jres.value("choices", json::array());
    if (choices.empty() || !choices[0].is_object())
    {
        if (jres.contains("promptFeedback") && jres["promptFeedback"].contains("blockReason") && jres["promptFeedback"]["blockReason"].is_string()) {
            std::string reason = jres["promptFeedback"]["blockReason"].get<std::string>();
            msg(OBFSTR_C("AiDA: Copilot API blocked the prompt. Reason: %s\n"), reason.c_str());
            return "Error: Prompt was blocked by API for reason: " + reason;
        }
        msg(OBFSTR_C("AiDA: Invalid Copilot API response: 'choices' array is missing or empty.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'choices' array from API.";
    }

    const auto& first_choice = choices[0];
    std::string finish_reason = json_str(first_choice, "finish_reason", "UNKNOWN");

    if (finish_reason != "stop" && finish_reason != "STOP")
    {
        if (finish_reason == "length" || finish_reason == "LENGTH")
        {
            msg(OBFSTR_C("AiDA: Copilot API response truncated (finish_reason: length). Extracting partial content.\n"));
            const auto partial_msg = first_choice.value("message", json::object());
            if (partial_msg.is_object())
            {
                std::string partial = json_str(partial_msg, "content");
                if (!partial.empty())
                    return partial + "\n\n[RESPONSE_TRUNCATED]";
            }
            return "Error: API response truncated and no content could be extracted.";
        }
        msg(OBFSTR_C("AiDA: Copilot API returned a non-STOP finish reason: %s\n"), finish_reason.c_str());
        return "Error: API request finished unexpectedly. Reason: " + finish_reason;
    }

    const auto message = first_choice.value("message", json::object());
    if (!message.is_object())
    {
        msg(OBFSTR_C("AiDA: Invalid Copilot API response: 'message' object is missing or invalid.\nResponse body: %s\n"), json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'message' object from API.";
    }

    return json_str(message, "content", "Error: 'content' field not found in API response.");
}

nlohmann::json CopilotClient::_get_streaming_payload(const std::string& prompt_text, double temperature) const
{
    auto payload = _get_api_payload(prompt_text, temperature);
    payload["stream"] = true;
    return payload;
}

std::string CopilotClient::_parse_sse_chunk(const std::string& data_line) const
{
    if (data_line == "[DONE]")
        return "";
    json j = json::parse(data_line, nullptr, false);
    if (j.is_discarded())
        return "";
    return _extract_sse_content(j);
}

std::string CopilotClient::_extract_sse_content(const nlohmann::json& j) const
{
    if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty())
    {
        auto& choice = j["choices"][0];
        auto delta = choice.value("delta", json::object());
        return json_str(delta, "content");
    }
    return "";
}

LocalLLMClient::LocalLLMClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.local_llm_model_name;
}

bool LocalLLMClient::is_available() const
{
    return !_settings.local_llm_base_url.empty() && !_settings.local_llm_model_name.empty();
}

std::string LocalLLMClient::_get_api_host() const
{
    return _settings.local_llm_base_url;
}

std::string LocalLLMClient::_get_api_path(const std::string&) const
{
    return "/v1/chat/completions";
}

httplib::Headers LocalLLMClient::_get_api_headers() const
{
    httplib::Headers headers = {{"Content-Type", "application/json"}};
    if (!_settings.local_llm_api_key.empty())
    {
        headers.emplace("Authorization", "Bearer " + _settings.local_llm_api_key);
    }
    return headers;
}

json LocalLLMClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    std::string system_prompt = BASE_PROMPT;
    if (!g_settings.active_prompt_name.empty())
    {
        auto it = g_settings.custom_prompts.find(g_settings.active_prompt_name);
        if (it != g_settings.custom_prompts.end())
            system_prompt = it->second;
    }

    return {
        {"model", _model_name},
        {"messages", {
            {{"role", "system"}, {"content", system_prompt}},
            {{"role", "user"}, {"content", prompt_text}}
        }},
        {"temperature", temperature},
        {"max_tokens", 16384}
    };
}

std::string LocalLLMClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = "Local LLM API Error: ";
        if (jres["error"].is_object() && jres["error"].contains("message") && jres["error"]["message"].is_string())
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += json_dump_safe(jres, 2);
        }
        msg(OBFSTR_C("AiDA: %s\n"), error_msg.c_str());
        return "Error: " + error_msg;
    }

    const auto choices = jres.value("choices", json::array());
    if (choices.empty() || !choices[0].is_object())
    {
        if (jres.contains("message") && jres["message"].is_object())
        {
            std::string content = json_str(jres["message"], "content");
            if (!content.empty())
                return content;
        }
        msg(OBFSTR_C("AiDA: Invalid Local LLM API response: 'choices' array is missing or empty.\nResponse body: %s\n"),
            json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'choices' array from local LLM.";
    }

    const auto& first_choice = choices[0];
    std::string finish_reason = json_str(first_choice, "finish_reason", "");

    if (!finish_reason.empty() && finish_reason != "stop" && finish_reason != "STOP")
    {
        if (finish_reason == "length" || finish_reason == "LENGTH")
        {
            msg(OBFSTR_C("AiDA: Local LLM response truncated (finish_reason: length). Extracting partial content.\n"));
            const auto partial_msg = first_choice.value("message", json::object());
            if (partial_msg.is_object())
            {
                std::string partial = json_str(partial_msg, "content");
                if (!partial.empty())
                    return partial + "\n\n[RESPONSE_TRUNCATED]";
            }
            return "Error: API response truncated and no content could be extracted.";
        }
    }

    const auto message = first_choice.value("message", json::object());
    if (!message.is_object())
    {
        msg(OBFSTR_C("AiDA: Invalid Local LLM API response: 'message' object is missing or invalid.\nResponse body: %s\n"),
            json_dump_safe(jres, 2).c_str());
        return "Error: Received invalid 'message' object from local LLM.";
    }

    return json_str(message, "content", "Error: 'content' field not found in local LLM response.");
}

nlohmann::json LocalLLMClient::_get_streaming_payload(const std::string& prompt_text, double temperature) const
{
    auto payload = _get_api_payload(prompt_text, temperature);
    payload["stream"] = true;
    return payload;
}

std::string LocalLLMClient::_parse_sse_chunk(const std::string& data_line) const
{
    if (data_line == "[DONE]")
        return "";
    json j = json::parse(data_line, nullptr, false);
    if (j.is_discarded())
        return "";
    return _extract_sse_content(j);
}

std::string LocalLLMClient::_extract_sse_content(const nlohmann::json& j) const
{
    if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty())
    {
        auto& choice = j["choices"][0];
        auto delta = choice.value("delta", json::object());
        return json_str(delta, "content");
    }
    return "";
}

std::unique_ptr<AIClient> get_ai_client(const settings_t& settings)
{
    if (!license_manager_t::instance().is_valid())
        return nullptr;

    qstring provider = ida_utils::qstring_tolower(settings.api_provider.c_str());

    msg(OBFSTR_C("Initializing AI provider: %s\n"), provider.c_str());

    if (provider == "gemini")
    {
        return std::make_unique<GeminiClient>(settings);
    }
    else if (provider == "openai")
    {
        return std::make_unique<OpenAIClient>(settings);
    }
    else if (provider == "openrouter")
    {
        return std::make_unique<OpenRouterClient>(settings);
    }
    else if (provider == "anthropic")
    {
        return std::make_unique<AnthropicClient>(settings);
    }
    else if (provider == "copilot")
    {
        return std::make_unique<CopilotClient>(settings);
    }
    else if (provider == "local llm")
    {
        return std::make_unique<LocalLLMClient>(settings);
    }
    else
    {
        warning(OBFSTR_C("Unknown AI provider '%s' in settings. No AI features will be available."), provider.c_str());
        return nullptr;
    }
}