

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "standalone_license.hpp"
#include "standalone_context.hpp"
#include "standalone_chat.hpp"
#include "mcp_standalone.hpp"
#include "provider_transforms.hpp"
#include "../auth/auth_store.hpp"
#include "../auth/auth_claude_code.hpp"
#include "../auth/auth_codex.hpp"
#include "../auth/auth_copilot.hpp"
#include "../auth/auth_http.hpp"
#include "../mcp/mcp_client.hpp"
#include "../session/session_store.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <limits>
#include <set>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <utility>
#include <vector>

using json = nlohmann::json;

extern mcp_client::manager_t s_mcp_client_mgr;

struct standalone_ai_client_t::runtime_operation_t
{
    enum class terminal_t : uint8_t
    {
        running,
        completed,
        cancelled,
        timed_out
    };

    uint64_t generation = 0;
    std::chrono::steady_clock::time_point deadline;
    std::atomic<terminal_t> terminal{terminal_t::running};
    mutable std::mutex wait_mutex;
    std::condition_variable wait_cv;

    bool request_cancel() noexcept
    {
        terminal_t expected = terminal_t::running;
        const bool changed = terminal.compare_exchange_strong(
            expected, terminal_t::cancelled,
            std::memory_order_acq_rel, std::memory_order_acquire);
        if (changed)
            wait_cv.notify_all();
        return changed;
    }

    bool request_timeout() noexcept
    {
        terminal_t expected = terminal_t::running;
        const bool changed = terminal.compare_exchange_strong(
            expected, terminal_t::timed_out,
            std::memory_order_acq_rel, std::memory_order_acquire);
        if (changed)
            wait_cv.notify_all();
        return changed;
    }

    bool stop_requested() noexcept
    {
        terminal_t state = terminal.load(std::memory_order_acquire);
        if (state != terminal_t::running)
            return true;
        if (std::chrono::steady_clock::now() < deadline)
            return false;
        terminal_t expected = terminal_t::running;
        if (terminal.compare_exchange_strong(
                expected, terminal_t::timed_out,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
            wait_cv.notify_all();
        }
        return true;
    }

    bool claim_completed() noexcept
    {
        terminal_t expected = terminal_t::running;
        const bool changed = terminal.compare_exchange_strong(
            expected, terminal_t::completed,
            std::memory_order_acq_rel, std::memory_order_acquire);
        if (changed)
            wait_cv.notify_all();
        return changed;
    }

    terminal_t state() const noexcept
    {
        return terminal.load(std::memory_order_acquire);
    }

    int remaining_seconds() noexcept
    {
        if (stop_requested())
            return 0;
        const auto remaining = deadline - std::chrono::steady_clock::now();
        const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
        return static_cast<int>((std::max<int64_t>)(1, (millis + 999) / 1000));
    }

    bool wait_for_stop(std::chrono::milliseconds delay) noexcept
    {
        if (stop_requested())
            return true;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        const auto bounded = (std::min)(delay, remaining);
        std::unique_lock<std::mutex> lock(wait_mutex);
        wait_cv.wait_for(lock, bounded, [this]() noexcept {
            return terminal.load(std::memory_order_acquire) != terminal_t::running;
        });
        return stop_requested();
    }
};

struct standalone_ai_client_t::runtime_control_t
{
    static constexpr size_t max_active_operations = 8;

    std::mutex mutex;
    std::condition_variable quiescent_cv;
    std::map<uint64_t, std::shared_ptr<runtime_operation_t>> active;
    uint64_t next_generation = 1;
    bool generation_exhausted = false;
    bool shutdown = false;

    std::shared_ptr<runtime_operation_t> acquire(
        std::chrono::steady_clock::time_point deadline,
        std::string& error) noexcept
    {
        try {
            std::lock_guard<std::mutex> lock(mutex);
            if (shutdown) {
                error = "Error: AI client is shutting down.";
                return nullptr;
            }
            if (generation_exhausted) {
                error = "Error: AI request generation space exhausted.";
                return nullptr;
            }
            if (active.size() >= max_active_operations) {
                error = "Error: Too many concurrent AI requests.";
                return nullptr;
            }

            const uint64_t generation = next_generation;
            if (next_generation == (std::numeric_limits<uint64_t>::max)())
                generation_exhausted = true;
            else
                ++next_generation;

            auto operation = std::make_shared<runtime_operation_t>();
            operation->generation = generation;
            operation->deadline = deadline;
            active.emplace(generation, operation);
            return operation;
        } catch (...) {
            error = "Error: Unable to allocate AI request state.";
            return nullptr;
        }
    }

    void release(uint64_t generation) noexcept
    {
        std::lock_guard<std::mutex> lock(mutex);
        active.erase(generation);
        if (active.empty())
            quiescent_cv.notify_all();
    }

    void cancel_active() noexcept
    {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& entry : active)
            entry.second->request_cancel();
    }

    void shutdown_and_wait(std::chrono::milliseconds timeout) noexcept
    {
        std::unique_lock<std::mutex> lock(mutex);
        shutdown = true;
        for (const auto& entry : active)
            entry.second->request_cancel();
        quiescent_cv.wait_for(lock, timeout, [this]() noexcept {
            return active.empty();
        });
    }

    bool busy() const noexcept
    {
        auto& self = const_cast<runtime_control_t&>(*this);
        std::lock_guard<std::mutex> lock(self.mutex);
        return !self.active.empty();
    }
};

struct standalone_ai_client_t::async_state_t
{
    struct pending_result_t
    {
        ai_callback_t callback;
        std::string text;
    };

    struct pending_chunk_t
    {
        ai_stream_chunk_t callback;
        std::string text;
    };

    std::mutex mutex;
    std::deque<pending_result_t> results;
    std::deque<pending_chunk_t> chunks;
    std::atomic<bool> accepting{true};
};

struct standalone_ai_client_t::usage_record_t
{
    std::string model;
    int64_t input_tokens = 0;
    int64_t output_tokens = 0;
    int64_t cache_read = 0;
    int64_t cache_write = 0;
    int64_t thinking_tokens = 0;
};

namespace {

constexpr int64_t k_oauth_refresh_safety_margin_sec = 30;
#if defined(AIDA_C03_STANDALONE_AI_CANCEL_FIXTURE)
constexpr int k_ai_chat_stream_timeout_sec = 5;
constexpr int k_ai_chat_post_timeout_sec = 2;
constexpr int k_ai_retry_base_delay_ms = 20;
#else
constexpr int k_ai_chat_stream_timeout_sec = 300;
constexpr int k_ai_chat_post_timeout_sec = 60;
constexpr int k_ai_retry_base_delay_ms = 2000;
#endif
constexpr const char* k_ai_user_agent = "AiDAStandalone/1.0";

nlohmann::json compact_tool_parameters()
{
    return nlohmann::json{
        {"type", "object"},
        {"properties", nlohmann::json::object()}
    };
}

const char* oauth_store_key_for_profile_kind(const std::string& kind)
{
    if (kind == "anthropic")      return "anthropic";
    if (kind == "openai_codex")   return "openai";
    if (kind == "openai_native")  return "openai";
    if (kind == "github-copilot" || kind == "copilot") return "github-copilot";
    return "";
}

bool refresh_oauth_if_needed(
    const std::string& store_key,
    const aida::auth::http::cancel_cb_t& cancelled,
    int timeout_sec,
    std::string& error)
{
    if ((cancelled && cancelled()) || timeout_sec <= 0) {
        error = "Operation cancelled or timed out before OAuth refresh.";
        return false;
    }
    if (store_key.empty())
        return true;

    aida::auth::auth_info_t info;
    if (!aida::auth::store::get(store_key, info))
        return true;
    if (info.kind != aida::auth::auth_kind_t::oauth)
        return true;

    // If expires_unix is not set but the access token is present, assume it's valid.
    // If expires_unix is not set and the access token is empty, force a refresh.
    if (info.expires_unix <= 0) {
        if (!info.access.empty())
            return true;
        // Access token is empty with no expiry info -- force refresh below.
    } else {
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (info.expires_unix > now + k_oauth_refresh_safety_margin_sec)
            return true;
    }

    bool ok = false;
    if (store_key == "anthropic") {
        ok = aida::auth::claude_code::refresh_token(cancelled, timeout_sec);
        if (!ok)
            error = std::string("Anthropic OAuth refresh failed: ") + aida::auth::claude_code::last_error();
    } else if (store_key == "openai") {
        ok = aida::auth::codex::refresh_token(cancelled, timeout_sec);
        if (!ok)
            error = std::string("Codex OAuth refresh failed: ") + aida::auth::codex::last_error();
    } else if (store_key == "github-copilot") {
        ok = aida::auth::copilot::refresh_token(cancelled, timeout_sec);
        if (!ok)
            error = std::string("Copilot token refresh failed: ") + aida::auth::copilot::last_error();
    } else {
        return true;
    }
    if (ok && cancelled && cancelled()) {
        error = "Operation cancelled during OAuth refresh.";
        return false;
    }
    return ok;
}

bool refresh_active_provider_oauth(
    const std::string& profile_kind,
    const aida::auth::http::cancel_cb_t& cancelled,
    int timeout_sec,
    std::string& error)
{
    return refresh_oauth_if_needed(
        oauth_store_key_for_profile_kind(profile_kind), cancelled, timeout_sec, error);
}

aida::provider::transforms::request_context_t build_request_context(const nlohmann::json* request_body)
{
    aida::provider::transforms::request_context_t ctx;
    ctx.session_id = chat_active_session();
    if (!ctx.session_id.empty()) {
        aida::session::session_info_t info;
        if (aida::session::get(ctx.session_id, info))
            ctx.has_parent_session = !info.parent_id.empty();
    }
    ctx.is_compaction_continued = false;
    ctx.request_body = request_body;
    return ctx;
}

void apply_oauth_headers(std::map<std::string, std::string>& headers,
                         const std::string& provider_id,
                         const std::string& store_key,
                         const std::string& model_id,
                         const aida::provider::transforms::request_context_t& ctx)
{
    if (store_key.empty()) return;
    aida::auth::auth_info_t info;
    if (!aida::auth::store::get(store_key, info)) return;
    if (info.kind == aida::auth::auth_kind_t::none) return;

    auto computed = aida::provider::transforms::compute_headers(provider_id, model_id, info, ctx);
    for (auto& [k, v] : computed)
        headers[k] = v;
}

class ai_operation_lease_t
{
public:
    ai_operation_lease_t(
        std::shared_ptr<standalone_ai_client_t::runtime_control_t> control,
        std::shared_ptr<standalone_ai_client_t::runtime_operation_t> operation) noexcept
        : _control(std::move(control)), _operation(std::move(operation))
    {
    }

    ~ai_operation_lease_t()
    {
        if (_operation) {
            _operation->request_cancel();
            if (_control)
                _control->release(_operation->generation);
        }
    }

    ai_operation_lease_t(const ai_operation_lease_t&) = delete;
    ai_operation_lease_t& operator=(const ai_operation_lease_t&) = delete;

    const std::shared_ptr<standalone_ai_client_t::runtime_operation_t>& operation() const noexcept
    {
        return _operation;
    }

private:
    std::shared_ptr<standalone_ai_client_t::runtime_control_t> _control;
    std::shared_ptr<standalone_ai_client_t::runtime_operation_t> _operation;
};

std::string operation_stop_error(
    const std::shared_ptr<standalone_ai_client_t::runtime_operation_t>& operation)
{
    if (!operation)
        return "Error: AI request state unavailable.";
    operation->stop_requested();
    switch (operation->state()) {
    case standalone_ai_client_t::runtime_operation_t::terminal_t::cancelled:
        return "Error: Operation cancelled.";
    case standalone_ai_client_t::runtime_operation_t::terminal_t::timed_out:
        return "Error: Operation timed out.";
    default:
        return {};
    }
}

aida::auth::http::cancel_cb_t operation_cancel_callback(
    const std::shared_ptr<standalone_ai_client_t::runtime_operation_t>& operation)
{
    return [operation]() noexcept {
        return !operation || operation->stop_requested();
    };
}

bool has_non_whitespace(const std::string& value)
{
    return std::any_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) == 0;
    });
}

bool is_error_result(const std::string& value)
{
    return value.rfind("Error:", 0) == 0;
}

void commit_usage(const standalone_ai_client_t::usage_record_t& usage)
{
    cost_tracking::accumulate(
        usage.model,
        usage.input_tokens,
        usage.output_tokens,
        usage.cache_read,
        usage.cache_write,
        usage.thinking_tokens);
}

}


standalone_ai_client_t::standalone_ai_client_t(const settings_sa_t& settings)
    : _settings_source(&settings),
      _control(std::make_shared<runtime_control_t>()),
      _async(std::make_shared<async_state_t>())
{
}

standalone_ai_client_t::~standalone_ai_client_t() noexcept
{
    if (_async)
        _async->accepting.store(false, std::memory_order_release);
    if (_control)
        _control->shutdown_and_wait(std::chrono::seconds(5));
}

standalone_ai_client_t::cancellation_handle_t::cancellation_handle_t(
    std::weak_ptr<runtime_control_t> control) noexcept
    : _control(std::move(control))
{
}

void standalone_ai_client_t::cancellation_handle_t::cancel() const noexcept
{
    if (auto control = _control.lock())
        control->cancel_active();
}

bool standalone_ai_client_t::cancellation_handle_t::valid() const noexcept
{
    return !_control.expired();
}

bool standalone_ai_client_t::is_available() const
{
    if (!_settings_source)
        return false;
    try {
        return is_available(_settings_source->ai_runtime_snapshot());
    } catch (...) {
        return false;
    }
}

bool standalone_ai_client_t::is_available(const settings_sa_t& settings)
{
    const auto model = settings.get_active_model();
    if (model.empty())
        return false;

    const auto kind = settings.get_active_profile_kind();
    if (kind == "local" || kind == "ollama" || kind == "lmstudio" || kind == "litellm")
        return !settings.resolve_active_base_url().empty();

    // For providers that require an API key, check resolve_active_api_key first.
    if (kind == "gemini" || kind == "google" || kind == "anthropic" || kind == "openrouter"
        || kind == "deepseek" || kind == "mistral" || kind == "xai" || kind == "fireworks"
        || kind == "sambanova" || kind == "moonshot" || kind == "minimax" || kind == "qwen_code"
        || kind == "baseten" || kind == "zai") {
        if (!settings.resolve_active_api_key().empty())
            return true;
    }

    // For OAuth-based providers (Copilot, Anthropic OAuth, OpenAI Codex OAuth),
    // check the auth store for a valid access token or API key.
    const std::string store_key = oauth_store_key_for_profile_kind(kind);
    if (!store_key.empty()) {
        aida::auth::auth_info_t info;
        if (aida::auth::store::get(store_key, info)) {
            if (info.kind == aida::auth::auth_kind_t::oauth && !info.access.empty())
                return true;
            if (info.kind == aida::auth::auth_kind_t::api && !info.api_key.empty())
                return true;
            if (info.kind == aida::auth::auth_kind_t::wellknown && !info.wellknown_token.empty())
                return true;
        }
    }

    // Also check the auth store using the raw selected_provider_id (e.g. "google" from catalog).
    const std::string raw_pid = settings.selected_provider_id();
    if (!raw_pid.empty() && raw_pid != store_key) {
        aida::auth::auth_info_t info;
        if (aida::auth::store::get(raw_pid, info)) {
            if (info.kind == aida::auth::auth_kind_t::oauth && !info.access.empty())
                return true;
            if (info.kind == aida::auth::auth_kind_t::api && !info.api_key.empty())
                return true;
            if (info.kind == aida::auth::auth_kind_t::wellknown && !info.wellknown_token.empty())
                return true;
        }
    }

    // Fallback: if there's a base URL configured, allow it (for custom/unknown providers).
    return !settings.resolve_active_base_url().empty();
}


std::string standalone_ai_client_t::resolve_api_key_logged(
    const settings_sa_t& settings,
    const char* context)
{
    bool from_store = false;
    std::string key = settings.resolve_active_api_key(from_store);
    diag::log_tagged_fmt("ai",
        "resolve_api_key context=%.40s provider=%.40s source=%s present=%d",
        context ? context : "",
        settings.selected_provider_id().c_str(),
        from_store ? "auth-store" : "profile",
        key.empty() ? 0 : 1);
    return key;
}


void standalone_ai_client_t::chat_async(
    const std::string& user_message,
    const std::vector<std::pair<std::string, std::string>>& history,
    ai_callback_t on_complete,
    ai_stream_chunk_t on_chunk)
{
    settings_sa_t settings;
    try {
        settings = _settings_source->ai_runtime_snapshot();
    } catch (...) {
        if (on_complete)
            on_complete("Error: Unable to snapshot AI settings.");
        return;
    }

    if (!is_available(settings)) {
        if (on_complete)
            on_complete("Error: AI client not configured. Set your API key in Settings.");
        return;
    }


#if !defined(AIDA_C03_STANDALONE_AI_CANCEL_FIXTURE)
    if (!standalone_license::is_valid()) {
        if (on_complete)
            on_complete("Error: Service unavailable. Please restart the application.");
        return;
    }
#endif

#if !defined(AIDA_C03_STANDALONE_AI_CANCEL_FIXTURE)
    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_ai_chat_async);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_ai_chat_async, gt) < 0.5) {
            if (on_complete)
                on_complete(standalone_license::decode_status_string(
                    standalone_license::str_internal_error));
            return;
        }
    }
#endif

    auto prompt = build_chat_prompt(user_message, history);
    std::string acquire_error;
    auto operation = _control->acquire(
        std::chrono::steady_clock::now() + std::chrono::seconds(k_ai_chat_stream_timeout_sec),
        acquire_error);
    if (!operation) {
        if (on_complete)
            on_complete(acquire_error);
        return;
    }
    auto lease = std::make_shared<ai_operation_lease_t>(_control, operation);
    const auto async = _async;

    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "ai_client";
    sub.label = "ai_client.chat_async";
    sub.thread_class = "bounded_task";
    sub.domain = aida::infra::executor::domain_t::external_tool;
    sub.priority = 3;
    sub.body = [lease, operation, settings = std::move(settings), prompt, on_complete, on_chunk, async]() mutable {
        std::string result;
        usage_record_t usage;
        try {
            ai_stream_chunk_t threadsafe_chunk = nullptr;
            if (on_chunk) {
                threadsafe_chunk = [operation, async, on_chunk](const std::string& chunk) {
                    if (!async->accepting.load(std::memory_order_acquire) || operation->stop_requested())
                        return;
                    std::lock_guard<std::mutex> lock(async->mutex);
                    if (async->accepting.load(std::memory_order_acquire) && !operation->stop_requested())
                        async->chunks.push_back({on_chunk, chunk});
                };
            }

            result = do_generate(
                operation, settings, prompt, settings.temperature,
                threadsafe_chunk, nullptr, usage);
        } catch (const std::exception& e) {
            result = std::string("Error: ") + e.what();
        } catch (...) {
            result = "Error: Unknown exception in AI worker thread.";
        }

        const bool completed = operation->claim_completed();
        if (completed && !is_error_result(result))
            commit_usage(usage);
        if (!completed) {
            const auto terminal_error = operation_stop_error(operation);
            result = terminal_error.empty() ? "Error: AI request did not complete." : terminal_error;
        }
        if (async->accepting.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(async->mutex);
            if (async->accepting.load(std::memory_order_acquire))
                async->results.push_back({on_complete, std::move(result)});
        }
    };
    std::lock_guard<std::mutex> submit_lock(_async_submit_mutex);
    if (!aida::infra::executor::submit(std::move(sub)).submitted) {
        operation->claim_completed();
        if (async->accepting.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(async->mutex);
            if (async->accepting.load(std::memory_order_acquire))
                async->results.push_back({on_complete, "Error: Service unavailable. Please restart the application."});
        }
    }
}


std::string standalone_ai_client_t::chat_blocking(
    const std::string& user_message,
    const std::vector<std::pair<std::string, std::string>>& history,
    ai_stream_chunk_t on_chunk,
    ai_stop_predicate_t stop_check)
{
    settings_sa_t settings;
    try {
        settings = _settings_source->ai_runtime_snapshot();
    } catch (...) {
        return "Error: Unable to snapshot AI settings.";
    }

    if (!is_available(settings))
        return "Error: AI client not configured.";


#if !defined(AIDA_C03_STANDALONE_AI_CANCEL_FIXTURE)
    if (standalone_license::inline_proof_check_b() == 0) {

        std::this_thread::sleep_for(std::chrono::milliseconds(800 + (GetTickCount64() % 400)));
        return "Error: Internal model routing failure. Please retry.";
    }
#endif

#if !defined(AIDA_C03_STANDALONE_AI_CANCEL_FIXTURE)
    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_ai_stream_cb);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_ai_stream_cb, gt) < 0.5) {
            return standalone_license::decode_status_string(
                standalone_license::str_model_routing);
        }
    }
#endif

    std::string acquire_error;
    auto operation = _control->acquire(
        std::chrono::steady_clock::now() + std::chrono::seconds(k_ai_chat_stream_timeout_sec),
        acquire_error);
    if (!operation)
        return acquire_error;
    ai_operation_lease_t lease(_control, operation);

    usage_record_t usage;
    std::string result;
    try {
        result = do_generate(
            operation, settings, build_chat_prompt(user_message, history),
            settings.temperature, on_chunk, stop_check, usage);
    } catch (const std::exception& e) {
        result = std::string("Error: ") + e.what();
    } catch (...) {
        result = "Error: Unknown exception in AI request.";
    }
    if (!operation->claim_completed()) {
        const auto terminal_error = operation_stop_error(operation);
        return terminal_error.empty() ? "Error: AI request did not complete." : terminal_error;
    }
    if (!is_error_result(result))
        commit_usage(usage);
    return result;
}


bool standalone_ai_client_t::poll()
{
    bool dispatched = false;

    std::deque<async_state_t::pending_chunk_t> chunks;
    std::deque<async_state_t::pending_result_t> results;
    {
        std::lock_guard<std::mutex> lock(_async->mutex);
        chunks.swap(_async->chunks);
        results.swap(_async->results);
    }

    for (auto& pending : chunks) {
        if (!pending.callback)
            continue;
        try {
            pending.callback(pending.text);
        } catch (...) {
            diag::log_tagged("ai", "stream callback failed");
        }
        dispatched = true;
    }

    for (auto& pending : results) {
        if (!pending.callback)
            continue;
        try {
            pending.callback(pending.text);
        } catch (...) {
            diag::log_tagged("ai", "completion callback failed");
        }
        dispatched = true;
    }

    return dispatched;
}


void standalone_ai_client_t::cancel() noexcept
{
    if (_control)
        _control->cancel_active();
}

standalone_ai_client_t::cancellation_handle_t
standalone_ai_client_t::cancellation_handle() const noexcept
{
    return cancellation_handle_t(_control);
}

bool standalone_ai_client_t::is_busy() const noexcept
{
    return _control && _control->busy();
}


namespace {

std::string join_host_path(const std::string& host, const std::string& path)
{
    std::string h = host;
    while (!h.empty() && h.back() == '/')
        h.pop_back();
    if (path.empty())
        return h;
    if (path[0] != '/')
        return h + "/" + path;
    return h + path;
}

aida::auth::http::header_list_t headers_map_to_list(
    const std::map<std::string, std::string>& headers,
    bool inject_user_agent)
{
    aida::auth::http::header_list_t out;
    out.reserve(headers.size() + 2);
    bool seen_ua = false;
    for (const auto& kv : headers) {
        if (kv.first.empty())
            continue;
        std::string lk = kv.first;
        std::transform(lk.begin(), lk.end(), lk.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lk == "user-agent")
            seen_ua = true;
        out.emplace_back(kv.first, kv.second);
    }
    if (inject_user_agent && !seen_ua)
        out.emplace_back("User-Agent", k_ai_user_agent);
    return out;
}

std::string sanitize_transport_error(const std::string& provider,
    const std::string& host, const std::string& detail)
{
    std::string msg = "Network transport failed for " + provider;
    if (!host.empty())
        msg += " (" + host + ")";
    if (!detail.empty())
        msg += ": " + detail;
    msg += ". Verify your internet connection, proxy, firewall, and API endpoint.";
    return msg;
}

}


std::string standalone_ai_client_t::do_generate(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const std::string& prompt,
    double temperature,
    ai_stream_chunk_t on_chunk,
    ai_stop_predicate_t stop_check,
    usage_record_t& usage)
{
    if (const auto error = operation_stop_error(operation); !error.empty())
        return error;
#if !defined(AIDA_C03_STANDALONE_AI_CANCEL_FIXTURE)
    if (!standalone_license::inline_proof_check_c()) {
        return "Error: API endpoint unreachable. Check your network connection.";
    }
#endif

    const auto provider = settings.get_active_profile_kind();
    diag::log_tagged_fmt("chat",
        "do_generate_dispatch provider=%.40s",
        provider.c_str());
    if (provider == "gemini" || provider == "google" || provider == "vertex")
        return generate_gemini(operation, settings, prompt, temperature, on_chunk, stop_check, usage);
    if (provider == "anthropic")
        return generate_anthropic(operation, settings, prompt, temperature, on_chunk, stop_check, usage);
    if (provider == "openrouter")
        return generate_openrouter(operation, settings, prompt, temperature, on_chunk, stop_check, usage);

    return generate_openai(operation, settings, prompt, temperature, on_chunk, stop_check, usage);
}


std::string standalone_ai_client_t::simple_post(
    const std::shared_ptr<runtime_operation_t>& operation,
    const std::string& host,
    const std::string& path,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    std::function<std::string(const json&)> response_parser)
{
    constexpr int MAX_RETRIES = 3;

    const std::string url = join_host_path(host, path);
    auto hdrs = headers_map_to_list(headers, true);
    const auto cancel_cb = operation_cancel_callback(operation);
    const auto request_deadline = (std::min)(
        operation->deadline,
        std::chrono::steady_clock::now() + std::chrono::seconds(k_ai_chat_post_timeout_sec));

    for (int attempt = 0; attempt <= MAX_RETRIES; ++attempt) {
        if (const auto error = operation_stop_error(operation); !error.empty())
            return error;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            request_deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) {
            operation->request_timeout();
            return "Error: Operation timed out.";
        }
        const int timeout_sec = static_cast<int>((std::max<int64_t>)(
            1, (remaining.count() + 999) / 1000));

        aida::auth::http::response_t res = aida::auth::http::post(
            url, hdrs, body, std::string("application/json"),
            timeout_sec, cancel_cb);

        if (const auto error = operation_stop_error(operation); !error.empty())
            return error;
        if (res.cancelled) {
            operation->request_cancel();
            return "Error: Operation cancelled.";
        }

        if (!res.ok && res.status == 0) {
            if (attempt < MAX_RETRIES) {
                int delay = (std::min)(k_ai_retry_base_delay_ms * (1 << attempt), 30000);
                const auto retry_remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    request_deadline - std::chrono::steady_clock::now());
                if (retry_remaining.count() <= 0) {
                    operation->request_timeout();
                    return "Error: Operation timed out.";
                }
                if (operation->wait_for_stop((std::min)(
                        std::chrono::milliseconds(delay), retry_remaining)))
                    return operation_stop_error(operation);
                continue;
            }
            return std::string("Error: ")
                + sanitize_transport_error("API", host, res.error);
        }

        if ((res.status == 429 || res.status == 503) && attempt < MAX_RETRIES) {
            int delay = (std::min)(k_ai_retry_base_delay_ms * (1 << attempt), 30000);
            const auto retry_remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                request_deadline - std::chrono::steady_clock::now());
            if (retry_remaining.count() <= 0) {
                operation->request_timeout();
                return "Error: Operation timed out.";
            }
            if (operation->wait_for_stop((std::min)(
                    std::chrono::milliseconds(delay), retry_remaining)))
                return operation_stop_error(operation);
            continue;
        }

        if (res.status < 200 || res.status >= 300)
            return "Error: API returned status " + std::to_string(res.status) +
                   ": " + res.body.substr(0, 600);

        if (!res.ok || !res.complete || res.truncated) {
            const std::string detail = res.error.empty()
                ? "response body was incomplete"
                : res.error;
            return "Error: API response incomplete: " + detail;
        }

        auto j = json::parse(res.body, nullptr, false);
        if (j.is_discarded())
            return "Error: API returned invalid JSON.";

        return response_parser(j);
    }
    return "Error: All retries exhausted.";
}


std::string standalone_ai_client_t::streaming_post(
    const std::shared_ptr<runtime_operation_t>& operation,
    const std::string& host,
    const std::string& path,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    std::function<std::string(const std::string& sse_data)> chunk_parser,
    ai_stream_chunk_t on_chunk,
    ai_stop_predicate_t stop_check)
{
    const std::string url = join_host_path(host, path);
    auto hdrs = headers_map_to_list(headers, true);

    std::string accumulated;
    std::string sse_buffer;
    bool callback_failed = false;
    bool caller_stopped = false;
    const auto cancel_cb = operation_cancel_callback(operation);

    const int transport_timeout_sec = operation->remaining_seconds();
    if (transport_timeout_sec <= 0)
        return operation_stop_error(operation);

    auto chunk_cb = [&](const char* data, size_t len) -> bool {
        if (operation->stop_requested())
            return false;

        try {
            sse_buffer.append(data, len);

            size_t pos = 0;
            while (pos < sse_buffer.size()) {
                auto nl = sse_buffer.find('\n', pos);
                if (nl == std::string::npos)
                    break;

                std::string line = sse_buffer.substr(pos, nl - pos);
                pos = nl + 1;

                if (!line.empty() && line.back() == '\r')
                    line.pop_back();

                if (line == "data: [DONE]" || line == "data:[DONE]")
                    continue;

                if (line.size() >= 5 && line.substr(0, 5) == "data:") {
                    std::string payload = (line.size() > 6 && line[5] == ' ')
                        ? line.substr(6) : line.substr(5);
                    if (payload.empty())
                        continue;

                    std::string chunk_text = chunk_parser(payload);
                    if (!chunk_text.empty()) {
                        accumulated += chunk_text;
                        if (on_chunk)
                            on_chunk(chunk_text);
                        if (stop_check && stop_check(accumulated)) {
                            caller_stopped = true;
                            operation->request_cancel();
                            return false;
                        }
                    }
                }
            }
            sse_buffer.erase(0, pos);
            return true;
        } catch (...) {
            callback_failed = true;
            operation->request_cancel();
            return false;
        }
    };

    aida::auth::http::stream_result_t res = aida::auth::http::stream(
        "POST", url, hdrs, body, std::string("application/json"),
        transport_timeout_sec, chunk_cb, cancel_cb);

    if (callback_failed)
        return "Error: AI stream callback failed.";
    if (caller_stopped)
        return "Error: Operation cancelled by caller.";
    if (const auto error = operation_stop_error(operation); !error.empty())
        return error;
    if (res.cancelled) {
        operation->request_cancel();
        return "Error: Operation cancelled.";
    }

    if (!res.ok && res.status == 0) {
        return std::string("Error: ")
            + sanitize_transport_error("API stream", host, res.error);
    }
    if (res.status < 200 || res.status >= 300) {
        std::string err_detail;
        if (!sse_buffer.empty()) {
            auto ej = json::parse(sse_buffer, nullptr, false);
            if (!ej.is_discarded()) {
                if (ej.is_array() && !ej.empty()) ej = ej[0];
                if (ej.contains("error") && ej["error"].is_object())
                    err_detail = ej["error"].value("message", sse_buffer.substr(0, 400));
                else
                    err_detail = sse_buffer.substr(0, 400);
            } else {
                err_detail = sse_buffer.substr(0, 400);
            }
        }
        if (err_detail.empty() && !res.error.empty())
            err_detail = res.error.substr(0, 400);
        return "Error: API returned status " + std::to_string(res.status)
             + (err_detail.empty() ? "" : ": " + err_detail);
    }

    if (!res.ok || !res.complete || res.truncated) {
        const std::string detail = res.error.empty()
            ? "stream ended before a complete response"
            : res.error;
        return "Error: API stream incomplete: " + detail;
    }
    if (has_non_whitespace(sse_buffer))
        return "Error: API stream ended with an incomplete SSE frame.";

    return accumulated;
}


std::string standalone_ai_client_t::generate_gemini(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check,
    usage_record_t& usage)
{
    std::string base_url = settings.resolve_active_base_url();
    std::string model = clean_model_name(settings.get_active_model());
    std::string api_key = resolve_api_key_logged(settings, "gemini");
    usage.model = model;


    bool is_thinking_model = (model.find("2.5") != std::string::npos ||
                              model.find("thinking") != std::string::npos);

    json gen_config = {
        {"temperature", temperature},
        {"maxOutputTokens", 16384}
    };

    json body = {
        {"contents", json::array({
            {{"role", "user"}, {"parts", json::array({{{"text", prompt}}})} }
        })},
        {"generationConfig", gen_config}
    };


    if (is_thinking_model && settings.enable_reasoning) {
        body["generationConfig"]["thinkingConfig"] = {
            {"thinkingBudget", (std::max)(settings.reasoning_budget, 1024)}
        };
    }

    if (on_chunk) {
        std::string thinking_text;
        int64_t in_tokens = 0, out_tokens = 0;

        std::string path = "/v1beta/models/" + model + ":streamGenerateContent?alt=sse&key=" + api_key;
        auto result = streaming_post(operation, base_url, path, {}, body.dump(),
            [&](const std::string& sse_data) -> std::string {
                auto j = json::parse(sse_data, nullptr, false);
                if (j.is_discarded()) return "";
                try {

                    if (j.contains("usageMetadata") && j["usageMetadata"].is_object()) {
                        auto& u = j["usageMetadata"];
                        in_tokens = u.value("promptTokenCount", (int64_t)0);
                        out_tokens = u.value("candidatesTokenCount", (int64_t)0);
                    }

                    auto& parts = j["candidates"][0]["content"]["parts"];
                    std::string accumulated_text;
                    for (auto& part : parts) {
                        if (part.contains("thought") && part["thought"].get<bool>()) {

                            std::string thought = part.value("text", "");
                            if (!thought.empty()) {
                                thinking_text += thought;
                                accumulated_text += "\x01THINK:" + thought;
                            }
                        } else if (part.contains("text")) {
                            accumulated_text += part["text"].get<std::string>();
                        }
                    }
                    return accumulated_text;
                } catch (...) { return ""; }
            }, on_chunk, stop_check);


        usage.input_tokens = in_tokens;
        usage.output_tokens = out_tokens;

        return result;
    }

    std::string path = "/v1beta/models/" + model + ":generateContent?key=" + api_key;
    return simple_post(operation, base_url, path, {}, body.dump(),
        [&usage](const json& j) -> std::string {
            if (j.contains("usageMetadata") && j["usageMetadata"].is_object()) {
                const auto& metrics = j["usageMetadata"];
                usage.input_tokens = metrics.value("promptTokenCount", int64_t{0});
                usage.output_tokens = metrics.value("candidatesTokenCount", int64_t{0});
            }
            return j["candidates"][0]["content"]["parts"][0]["text"].get<std::string>();
        });
}


std::string standalone_ai_client_t::generate_openai(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check,
    usage_record_t& usage)
{
    std::string base_url = settings.resolve_active_base_url();
    std::string model = settings.get_active_model();
    usage.model = model;


    bool is_o_series = (model.find("o1") != std::string::npos ||
                        model.find("o3") != std::string::npos ||
                        model.find("o4") != std::string::npos);

    json body = {
        {"model", model},
        {"messages", json::array({
            {{"role", "system"}, {"content", "You are AiDA, an advanced reverse engineering assistant. Be precise and technical."}},
            {{"role", "user"}, {"content", prompt}}
        })},
        {"stream", on_chunk != nullptr}
    };

    if (is_o_series) {

        body["max_completion_tokens"] = 16384;
        if (settings.enable_reasoning && !settings.reasoning_effort.empty()) {
            body["reasoning_effort"] = settings.reasoning_effort;
        }
    } else {
        body["temperature"] = temperature;
        body["max_tokens"] = 16384;
    }

    const std::string oai_kind = settings.get_active_profile_kind();
    const std::string oai_store_key = oauth_store_key_for_profile_kind(oai_kind);
    std::string oauth_error;
    if (!refresh_oauth_if_needed(
            oai_store_key, operation_cancel_callback(operation),
            operation->remaining_seconds(), oauth_error)) {
        if (const auto error = operation_stop_error(operation); !error.empty())
            return error;
        return std::string("Error: ") + oauth_error;
    }

    const bool oai_is_copilot = (oai_store_key == "github-copilot");
    std::string oai_path = "/v1/chat/completions";

    std::map<std::string, std::string> headers = settings.get_active_headers();
    {
        const std::string resolved_key = resolve_api_key_logged(settings, "openai");
        if (!resolved_key.empty())
            headers["Authorization"] = "Bearer " + resolved_key;
    }
    headers["Content-Type"] = "application/json";

    if (!oai_store_key.empty()) {
        std::string provider_id;
        if (oai_is_copilot)
            provider_id = settings.selected_provider_id();
        else if (oai_kind == "openai_codex")
            provider_id = "openai-codex";
        else
            provider_id = "openai";

        apply_oauth_headers(headers, provider_id, oai_store_key, model,
                            build_request_context(&body));
        if (headers.count("authorization") > 0)
            headers.erase("Authorization");

        if (oai_is_copilot) {
            aida::auth::auth_info_t oai_info;
            const bool have_oai_info = aida::auth::store::get(oai_store_key, oai_info);
            std::string resolved = aida::provider::transforms::resolve_endpoint(provider_id, model, oai_info);
            const auto responses_pos = resolved.rfind("/responses");
            if (responses_pos != std::string::npos && responses_pos == resolved.size() - 10)
                resolved.replace(responses_pos, std::string::npos, "/chat/completions");
            if (!resolved.empty())
                base_url = resolved;
            oai_path.clear();
            diag::log_tagged_fmt("ai",
                "copilot endpoint=%.160s responses_api=%d info=%d",
                base_url.c_str(),
                aida::provider::transforms::copilot_uses_responses_api(model) ? 1 : 0,
                have_oai_info ? 1 : 0);
        }
    }

    if (on_chunk) {
        std::string thinking_text;
        int64_t in_tokens = 0, out_tokens = 0, cache_read = 0, cache_write = 0;

        auto result = streaming_post(operation, base_url, oai_path, headers, body.dump(),
            [&](const std::string& sse_data) -> std::string {
                auto j = json::parse(sse_data, nullptr, false);
                if (j.is_discarded()) return "";
                try {

                    if (j.contains("usage") && j["usage"].is_object()) {
                        auto& u = j["usage"];
                        in_tokens = u.value("prompt_tokens", (int64_t)0);
                        out_tokens = u.value("completion_tokens", (int64_t)0);

                        if (u.contains("prompt_tokens_details") && u["prompt_tokens_details"].is_object()) {
                            cache_read = u["prompt_tokens_details"].value("cached_tokens", (int64_t)0);
                        }
                        if (u.contains("completion_tokens_details") && u["completion_tokens_details"].is_object())
                            usage.thinking_tokens = u["completion_tokens_details"].value("reasoning_tokens", int64_t{0});
                    }

                    auto& choices = j["choices"];
                    if (choices.empty()) return "";
                    auto& delta = choices[0]["delta"];


                    if (delta.contains("reasoning") && !delta["reasoning"].is_null()) {
                        std::string reasoning = delta["reasoning"].get<std::string>();
                        if (!reasoning.empty()) {
                            thinking_text += reasoning;
                            return "\x01THINK:" + reasoning;
                        }
                    }

                    if (delta.contains("content") && !delta["content"].is_null())
                        return delta["content"].get<std::string>();
                } catch (...) {}
                return "";
            }, on_chunk, stop_check);


        usage.input_tokens = in_tokens;
        usage.output_tokens = out_tokens;
        usage.cache_read = cache_read;

        return result;
    }

    return simple_post(operation, base_url, oai_path, headers, body.dump(),
        [&usage](const json& j) -> std::string {
            if (j.contains("usage") && j["usage"].is_object()) {
                const auto& metrics = j["usage"];
                usage.input_tokens = metrics.value("prompt_tokens", int64_t{0});
                usage.output_tokens = metrics.value("completion_tokens", int64_t{0});
                if (metrics.contains("prompt_tokens_details") && metrics["prompt_tokens_details"].is_object())
                    usage.cache_read = metrics["prompt_tokens_details"].value("cached_tokens", int64_t{0});
                if (metrics.contains("completion_tokens_details") && metrics["completion_tokens_details"].is_object())
                    usage.thinking_tokens = metrics["completion_tokens_details"].value("reasoning_tokens", int64_t{0});
            }
            return j["choices"][0]["message"]["content"].get<std::string>();
        });
}


std::string standalone_ai_client_t::generate_anthropic(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check,
    usage_record_t& usage)
{

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_ai_generate);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_ai_generate, gt) < 0.5) {
            return standalone_license::decode_status_string(
                standalone_license::str_model_routing);
        }
    }

    std::string base_url = settings.resolve_active_base_url();
    std::string model = settings.get_active_model();

    std::string clean_model = model;
    for (const char* suffix : {" (Max Effort)", " (High Effort)", " (Medium Effort)",
                               " (Low Effort)", " (Standard)"}) {
        auto pos = clean_model.find(suffix);
        if (pos != std::string::npos) { clean_model.erase(pos); break; }
    }
    usage.model = clean_model;


    json system_block = {
        {"type", "text"},
        {"text", "You are AiDA, an advanced reverse engineering assistant. Be precise and technical."}
    };
    if (settings.prompt_caching) {
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


    if (settings.enable_reasoning) {
        json thinking_cfg = {
            {"type", "enabled"},
            {"budget_tokens", (std::max)(settings.reasoning_budget, 1024)}
        };
        body["thinking"] = thinking_cfg;

    } else if (clean_model.find("thought") == std::string::npos) {
        body["temperature"] = temperature;
    }

    std::string oauth_error;
    if (!refresh_active_provider_oauth(
            "anthropic", operation_cancel_callback(operation),
            operation->remaining_seconds(), oauth_error)) {
        if (const auto error = operation_stop_error(operation); !error.empty())
            return error;
        return std::string("Error: ") + oauth_error;
    }

    std::map<std::string, std::string> headers = settings.get_active_headers();
    const std::string anthropic_api_key = resolve_api_key_logged(settings, "anthropic");
    if (!anthropic_api_key.empty())
        headers["x-api-key"] = anthropic_api_key;
    headers["anthropic-version"] = "2023-06-01";
    headers["Content-Type"] = "application/json";

    apply_oauth_headers(headers, "anthropic", "anthropic", clean_model,
                        build_request_context(&body));
    if (headers.count("authorization") > 0 || headers.count("Authorization") > 0)
        headers.erase("x-api-key");

    if (on_chunk) {

        std::string thinking_text;
        int64_t in_tokens = 0, out_tokens = 0, cache_read = 0, cache_write = 0;

        auto result = streaming_post(operation, base_url, "/v1/messages", headers, body.dump(),
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


        usage.input_tokens = in_tokens;
        usage.output_tokens = out_tokens;
        usage.cache_read = cache_read;
        usage.cache_write = cache_write;

        return result;
    }


    return simple_post(operation, base_url, "/v1/messages", headers, body.dump(),
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
                const auto& metrics = j["usage"];
                usage.input_tokens = metrics.value("input_tokens", int64_t{0});
                usage.output_tokens = metrics.value("output_tokens", int64_t{0});
                usage.cache_read = metrics.value("cache_read_input_tokens", int64_t{0});
                usage.cache_write = metrics.value("cache_creation_input_tokens", int64_t{0});
            }


            if (!thinking.empty())
                return "\x01THINK:" + thinking + "\x01ENDTHINK\n" + text;
            return text;
        });
}


std::string standalone_ai_client_t::generate_openrouter(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const std::string& prompt, double temperature,
    ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check,
    usage_record_t& usage)
{
    std::string model = settings.get_active_model();
    std::string base_url = settings.resolve_active_base_url();
    usage.model = model;

    json body = {
        {"model", model},
        {"messages", json::array({
            {{"role", "user"}, {"content", prompt}}
        })},
        {"temperature", temperature},
        {"stream", on_chunk != nullptr}
    };

    std::map<std::string, std::string> headers = settings.get_active_headers();
    headers["Authorization"] = "Bearer " + resolve_api_key_logged(settings, "openrouter");
    headers["X-Title"] = "AiDA Standalone";
    headers["Content-Type"] = "application/json";

    if (on_chunk) {


        int64_t in_tokens = 0, out_tokens = 0;

        auto result = streaming_post(operation, base_url, "/api/v1/chat/completions",
            headers, body.dump(),
            [&](const std::string& sse_data) -> std::string {
                auto j = json::parse(sse_data, nullptr, false);
                if (j.is_discarded()) return "";
                try {

                    if (j.contains("usage") && j["usage"].is_object()) {
                        auto& u = j["usage"];
                        in_tokens = u.value("prompt_tokens", (int64_t)0);
                        out_tokens = u.value("completion_tokens", (int64_t)0);
                    }

                    auto& choices = j["choices"];
                    if (choices.empty()) return "";
                    if (!choices[0].contains("delta")) return "";
                    auto& delta = choices[0]["delta"];


                    if (delta.contains("reasoning_content") && delta["reasoning_content"].is_string()) {
                        std::string th = delta["reasoning_content"].get<std::string>();
                        if (!th.empty())
                            return "\x01THINK:" + th;
                    }


                    if (delta.contains("reasoning") && !delta["reasoning"].is_null()) {
                        std::string reasoning = delta["reasoning"].get<std::string>();
                        if (!reasoning.empty())
                            return "\x01THINK:" + reasoning;
                    }


                    if (delta.contains("content") && !delta["content"].is_null())
                        return delta["content"].get<std::string>();
                } catch (...) {}
                return "";
            }, on_chunk, stop_check);


        usage.input_tokens = in_tokens;
        usage.output_tokens = out_tokens;

        return result;
    }

    return simple_post(operation, base_url, "/api/v1/chat/completions",
        headers, body.dump(),
        [&usage](const json& j) -> std::string {
            if (j.contains("usage") && j["usage"].is_object()) {
                const auto& metrics = j["usage"];
                usage.input_tokens = metrics.value("prompt_tokens", int64_t{0});
                usage.output_tokens = metrics.value("completion_tokens", int64_t{0});
            }

            auto& msg = j["choices"][0]["message"];
            std::string text = msg.value("content", "");
            if (text.empty() && msg.contains("reasoning_content") && msg["reasoning_content"].is_string())
                text = msg["reasoning_content"].get<std::string>();
            return text;
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


nlohmann::json standalone_ai_client_t::build_anthropic_tools(
    const std::vector<mcp_standalone::tool_def_t>& tools)
{
    using json = nlohmann::json;
    json arr = json::array();


    arr.push_back({
        {"name", "get_tool_descriptions"},
        {"description", "Returns the full description and parameter schema for one or more tools. "
                        "Call this FIRST when you need to use a tool and are unsure of its parameters."},
        {"input_schema", {
            {"type", "object"},
            {"properties", {
                {"names", {
                    {"type", "array"},
                    {"items", {{"type", "string"}}},
                    {"description", "Array of tool names to look up (e.g. [\"read_memory\", \"disassemble_file\"])"}
                }}
            }},
            {"required", json::array({"names"})}
        }}
    });


    std::set<std::string> emitted;
    emitted.insert("get_tool_descriptions");
    for (auto& t : tools) {
        if (!emitted.insert(t.name).second) continue;
        arr.push_back({
            {"name", t.name},
            {"description", ""},
            {"input_schema", compact_tool_parameters()}
        });
    }

    json mcp_tools = s_mcp_client_mgr.mcp_tool_list_json();
    for (auto& m : mcp_tools) {
        std::string qualified = m.value("name", std::string());
        if (qualified.empty()) continue;
        std::string prefixed = std::string("mcp::") + qualified;
        if (!emitted.insert(prefixed).second) continue;
        arr.push_back({
            {"name", prefixed},
            {"description", ""},
            {"input_schema", compact_tool_parameters()}
        });
    }
    return arr;
}

nlohmann::json standalone_ai_client_t::build_full_tools(
    const std::vector<mcp_standalone::tool_def_t>& tools)
{
    using json = nlohmann::json;
    json arr = json::array();
    for (auto& t : tools) {
        json props = json::object();
        json req   = json::array();
        for (auto& p : t.params) {
            json prop = {{"type", p.type}, {"description", p.description}};
            props[p.name] = prop;
            if (p.required) req.push_back(p.name);
        }
        json schema = {
            {"type", "object"},
            {"properties", props}
        };
        if (!req.empty()) schema["required"] = req;

        json tool_obj = {
            {"name", t.name},
            {"description", t.description},
            {"input_schema", schema}
        };
        arr.push_back(std::move(tool_obj));
    }
    return arr;
}


nlohmann::json standalone_ai_client_t::make_tool_result_block(
    const std::string& tool_use_id,
    const std::string& content,
    bool is_error)
{
    using json = nlohmann::json;
    json block = {
        {"type", "tool_result"},
        {"tool_use_id", tool_use_id},
        {"content", content}
    };
    if (is_error) block["is_error"] = true;
    return block;
}


nlohmann::json standalone_ai_client_t::make_openai_tool_result(
    const std::string& tool_call_id,
    const std::string& content)
{
    return {
        {"role", "tool"},
        {"tool_call_id", tool_call_id},
        {"content", content}
    };
}


nlohmann::json standalone_ai_client_t::make_gemini_tool_result(
    const std::string& function_name,
    const nlohmann::json& result_data)
{
    return {
        {"role", "user"},
        {"parts", json::array({
            {{"functionResponse", {
                {"name", function_name},
                {"response", result_data}
            }}}
        })}
    };
}


std::string standalone_ai_client_t::clean_model_name(const std::string& model)
{
    std::string clean = model;
    for (const char* suffix : {" (Max Effort)", " (High Effort)", " (Medium Effort)",
                               " (Low Effort)", " (Standard)"}) {
        auto pos = clean.find(suffix);
        if (pos != std::string::npos) { clean.erase(pos); break; }
    }
    return clean;
}


nlohmann::json standalone_ai_client_t::build_openai_tools(
    const std::vector<mcp_standalone::tool_def_t>& tools)
{
    json arr = json::array();
    std::set<std::string> seen_names;

    {
        json params = {
            {"type", "object"},
            {"properties", {
                {"names", {
                    {"type", "array"},
                    {"items", {{"type", "string"}}},
                    {"description", "Array of tool names to look up"}
                }}
            }},
            {"required", json::array({"names"})},
            {"additionalProperties", false}
        };
        arr.push_back({
            {"type", "function"},
            {"function", {
                {"name", "get_tool_descriptions"},
                {"description", "Returns the full description and parameter schema for one or more tools. "
                                "Call this FIRST when you need to use a tool and are unsure of its parameters."},
                {"parameters", params},
                {"strict", true}
            }}
        });
        seen_names.insert("get_tool_descriptions");
    }

    for (auto& t : tools) {
        if (t.name == "get_tool_descriptions") continue;
        if (!seen_names.insert(t.name).second) continue;
        arr.push_back({
            {"type", "function"},
            {"function", {
                {"name", t.name},
                {"description", ""},
                {"parameters", compact_tool_parameters()}
            }}
        });
    }

    json oai_mcp_tools = s_mcp_client_mgr.mcp_tool_list_json();
    for (auto& m : oai_mcp_tools) {
        std::string qualified = m.value("name", std::string());
        if (qualified.empty()) continue;
        std::string prefixed = std::string("mcp::") + qualified;
        if (!seen_names.insert(prefixed).second) continue;
        arr.push_back({
            {"type", "function"},
            {"function", {
                {"name", prefixed},
                {"description", ""},
                {"parameters", compact_tool_parameters()}
            }}
        });
    }
    return arr;
}


nlohmann::json standalone_ai_client_t::build_gemini_tools(
    const std::vector<mcp_standalone::tool_def_t>& tools)
{
    json decls = json::array();
    std::set<std::string> seen_names;

    {
        json params = {
            {"type", "object"},
            {"properties", {
                {"names", {
                    {"type", "array"},
                    {"items", {{"type", "string"}}},
                    {"description", "Array of tool names to look up"}
                }}
            }},
            {"required", json::array({"names"})}
        };
        decls.push_back({
            {"name", "get_tool_descriptions"},
            {"description", "Returns the full description and parameter schema for one or more tools."},


            {"parametersJsonSchema", params}
        });
        seen_names.insert("get_tool_descriptions");
    }

    for (auto& t : tools) {
        if (t.name == "get_tool_descriptions") continue;
        if (!seen_names.insert(t.name).second) continue;
        decls.push_back({
            {"name", t.name},
            {"description", ""},
            {"parametersJsonSchema", compact_tool_parameters()}
        });
    }

    json gem_mcp_tools = s_mcp_client_mgr.mcp_tool_list_json();
    for (auto& m : gem_mcp_tools) {
        std::string qualified = m.value("name", std::string());
        if (qualified.empty()) continue;
        std::string prefixed = std::string("mcp::") + qualified;
        if (!seen_names.insert(prefixed).second) continue;
        decls.push_back({
            {"name", prefixed},
            {"description", ""},
            {"parametersJsonSchema", compact_tool_parameters()}
        });
    }
    return json::array({{{"functionDeclarations", decls}}});
}


nlohmann::json standalone_ai_client_t::convert_messages_for_openai(
    const nlohmann::json& anthropic_messages,
    const std::string& system_prompt)
{
    json messages = json::array();


    if (!system_prompt.empty()) {
        messages.push_back({{"role", "system"}, {"content", system_prompt}});
    }

    for (auto& msg : anthropic_messages) {
        if (!msg.is_object()) continue;
        std::string role = msg.value("role", "user");

        if (!msg.contains("content")) continue;
        const auto& content_ref = msg["content"];

        if (content_ref.is_string()) {
            messages.push_back({{"role", role}, {"content", content_ref.get<std::string>()}});
            continue;
        }

        if (!content_ref.is_array()) continue;


        if (role == "assistant") {
            std::string text_content;
            json tool_calls = json::array();
            int tc_idx = 0;

            for (auto& block : content_ref) {
                std::string btype = block.value("type", "");
                if (btype == "text") {
                    text_content += block.value("text", "");
                } else if (btype == "tool_use") {
                    json tc = {
                        {"id", block.value("id", "tc_" + std::to_string(tc_idx))},
                        {"type", "function"},
                        {"function", {
                            {"name", block.value("name", "")},
                            {"arguments", block.value("input", json::object()).dump()}
                        }}
                    };
                    tool_calls.push_back(std::move(tc));
                    ++tc_idx;
                }
            }

            json oai_msg = {{"role", "assistant"}};
            if (!text_content.empty())
                oai_msg["content"] = text_content;
            else
                oai_msg["content"] = nullptr;

            if (!tool_calls.empty())
                oai_msg["tool_calls"] = tool_calls;

            messages.push_back(std::move(oai_msg));
        }
        else if (role == "user") {

            bool has_tool_results = false;
            for (auto& block : content_ref) {
                if (block.value("type", "") == "tool_result") {
                    has_tool_results = true;
                    break;
                }
            }

            if (has_tool_results) {
                for (auto& block : content_ref) {
                    if (block.value("type", "") == "tool_result") {
                        messages.push_back(make_openai_tool_result(
                            block.value("tool_use_id", ""),
                            block.value("content", "")));
                    }
                }
            } else {
                std::string text_content;
                for (auto& block : content_ref) {
                    if (block.value("type", "") == "text")
                        text_content += block.value("text", "");
                }
                if (!text_content.empty())
                    messages.push_back({{"role", "user"}, {"content", text_content}});
            }
        }
    }
    return messages;
}


nlohmann::json standalone_ai_client_t::convert_messages_for_gemini(
    const nlohmann::json& anthropic_messages)
{
    json contents = json::array();

    for (auto& msg : anthropic_messages) {
        if (!msg.is_object()) continue;
        std::string role = msg.value("role", "user");
        std::string gemini_role = (role == "assistant") ? "model" : "user";

        if (!msg.contains("content")) continue;
        const auto& content_ref = msg["content"];

        if (content_ref.is_string()) {
            contents.push_back({
                {"role", gemini_role},
                {"parts", json::array({{{"text", content_ref.get<std::string>()}}})}
            });
            continue;
        }

        if (!content_ref.is_array()) continue;

        json parts = json::array();
        bool has_tool_results = false;

        for (auto& block : content_ref) {
            std::string btype = block.value("type", "");

            if (btype == "text") {
                std::string t = block.value("text", "");
                if (!t.empty())
                    parts.push_back({{"text", t}});
            }
            else if (btype == "tool_use") {
                parts.push_back({
                    {"functionCall", {
                        {"name", block.value("name", "")},
                        {"args", block.value("input", json::object())}
                    }}
                });
            }
            else if (btype == "tool_result") {
                has_tool_results = true;
                json response_data;
                std::string content_str = block.value("content", "");
                if (!content_str.empty()) {
                    response_data = {{"result", content_str}};
                } else {
                    response_data = {{"result", "OK"}};
                }
                if (block.value("is_error", false))
                    response_data["error"] = true;

                parts.push_back({
                    {"functionResponse", {
                        {"name", block.value("tool_use_id", "unknown")},
                        {"response", response_data}
                    }}
                });
            }
        }

        if (!parts.empty()) {
            contents.push_back({
                {"role", has_tool_results ? "user" : gemini_role},
                {"parts", parts}
            });
        }
    }
    return contents;
}


nlohmann::json standalone_ai_client_t::merge_consecutive_roles(
    const nlohmann::json& messages)
{
    if (messages.empty()) return messages;

    json merged = json::array();
    for (auto& msg : messages) {
        if (!merged.empty() &&
            merged.back().value("role", "") == msg.value("role", "")) {

            std::string prev = merged.back().value("content", "");
            std::string curr = msg.value("content", "");
            merged.back()["content"] = prev + "\n\n" + curr;
        } else {
            merged.push_back(msg);
        }
    }
    return merged;
}


ai_generation_result_t standalone_ai_client_t::generate_with_tools(
    const nlohmann::json& messages,
    const std::string& system_prompt,
    const std::vector<mcp_standalone::tool_def_t>& tools,
    ai_stream_chunk_t on_chunk)
{
    ai_generation_result_t result;
    settings_sa_t settings;
    try {
        settings = _settings_source->ai_runtime_snapshot();
    } catch (...) {
        result.is_error = true;
        result.text = "Error: Unable to snapshot AI settings.";
        return result;
    }

    {
        const uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_ai_generate);
        const double v = standalone_license::verify_gate_token(
            standalone_license::gate_ai_generate, gt);
        standalone_license::fold_integrity_token(gt);
        if (v < 0.5) {
            diag::log_tagged_fmt("chat",
                "generate_with_tools_gate_blocked gt=0x%016llX v=%.3f",
                static_cast<unsigned long long>(gt), v);
            result.is_error = true;
            result.text = "Error: License gate blocked native tool use.";
            return result;
        }
    }

    std::string acquire_error;
    auto operation = _control->acquire(
        std::chrono::steady_clock::now() + std::chrono::seconds(k_ai_chat_stream_timeout_sec),
        acquire_error);
    if (!operation) {
        result.is_error = true;
        result.text = acquire_error;
        return result;
    }
    ai_operation_lease_t lease(_control, operation);
    usage_record_t usage;

    const auto provider = settings.get_active_profile_kind();
    const auto raw_provider = settings.selected_provider_id();
    diag::log_tagged_fmt("chat",
        "generate_with_tools_enter provider=%.40s raw=%.40s tools=%zu msgs=%zu",
        provider.c_str(), raw_provider.c_str(),
        tools.size(), messages.is_array() ? messages.size() : 0);


    try {
        if (provider == "anthropic") {
            diag::log_tagged_fmt("chat", "generate_with_tools_path=anthropic");
            result = generate_with_tools_anthropic(
                operation, settings, messages, system_prompt, tools, on_chunk, usage);
        } else if (provider == "gemini" || provider == "google" || provider == "vertex") {
            diag::log_tagged_fmt("chat", "generate_with_tools_path=gemini");
            result = generate_with_tools_gemini(
                operation, settings, messages, system_prompt, tools, on_chunk, usage);
        } else if (provider == "openai_native" || provider == "openai_codex") {
            diag::log_tagged_fmt("chat", "generate_with_tools_path=openai_native");
            result = generate_with_tools_openai(
                operation, settings, messages, system_prompt, tools, on_chunk, usage);
        } else {
            diag::log_tagged_fmt("chat", "generate_with_tools_path=generic_openai provider=%.40s",
                provider.c_str());
            result = generate_with_tools_generic_openai(
                operation, settings, messages, system_prompt, tools, on_chunk, usage);
        }
    } catch (const std::exception& e) {
        result.is_error = true;
        result.text = std::string("Error: ") + e.what();
    } catch (...) {
        result.is_error = true;
        result.text = "Error: Unknown exception in AI tool request.";
    }

    if (!operation->claim_completed()) {
        result.is_error = true;
        const auto terminal_error = operation_stop_error(operation);
        result.text = terminal_error.empty() ? "Error: AI request did not complete." : terminal_error;
        result.tool_calls.clear();
        return result;
    }
    if (!result.is_error)
        commit_usage(usage);
    return result;
}


ai_generation_result_t standalone_ai_client_t::generate_with_tools_anthropic(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const nlohmann::json& messages,
    const std::string& system_prompt,
    const std::vector<mcp_standalone::tool_def_t>& tools,
    ai_stream_chunk_t on_chunk,
    usage_record_t& usage)
{
    using json = nlohmann::json;
    ai_generation_result_t result;


    {
        const uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_ai_generate);
        const double v = standalone_license::verify_gate_token(
            standalone_license::gate_ai_generate, gt);
        standalone_license::fold_integrity_token(gt);
        if (v < 0.5) {
            diag::log_tagged_fmt("chat",
                "anthropic_gate_blocked gt=0x%016llX v=%.3f",
                static_cast<unsigned long long>(gt), v);
            result.is_error = true;
            result.text = "Error: License gate blocked native tool use.";
            return result;
        }
    }

    std::string base_url = settings.resolve_active_base_url();
    std::string model    = settings.get_active_model();
    diag::log_tagged_fmt("chat",
        "anthropic_enter base=%.80s model=%.80s tools=%zu",
        base_url.c_str(), model.c_str(), tools.size());


    std::string clean_model = model;
    for (const char* suffix : {" (Max Effort)", " (High Effort)", " (Medium Effort)",
                               " (Low Effort)", " (Standard)"}) {
        auto pos = clean_model.find(suffix);
        if (pos != std::string::npos) { clean_model.erase(pos); break; }
    }
    usage.model = clean_model;


    json system_block = {
        {"type", "text"},
        {"text", system_prompt}
    };
    if (settings.prompt_caching)
        system_block["cache_control"] = {{"type", "ephemeral"}};


    json body = {
        {"model", clean_model},
        {"max_tokens", 16384},
        {"messages", messages},
        {"system", json::array({system_block})},
        {"stream", true}
    };


    if (!tools.empty())
        body["tools"] = build_anthropic_tools(tools);


    if (settings.enable_reasoning) {
        body["thinking"] = {
            {"type", "enabled"},
            {"budget_tokens", (std::max)(settings.reasoning_budget, 1024)}
        };
    } else if (clean_model.find("thought") == std::string::npos) {
        body["temperature"] = 0.0;
    }


    std::string oauth_error;
    if (!refresh_active_provider_oauth(
            "anthropic", operation_cancel_callback(operation),
            operation->remaining_seconds(), oauth_error)) {
        result.is_error = true;
        const auto stop_error = operation_stop_error(operation);
        result.text = stop_error.empty() ? std::string("Error: ") + oauth_error : stop_error;
        return result;
    }

    std::map<std::string, std::string> headers = settings.get_active_headers();
    const std::string anthropic_api_key = resolve_api_key_logged(settings, "anthropic_tools");
    if (!anthropic_api_key.empty())
        headers["x-api-key"] = anthropic_api_key;
    headers["anthropic-version"]  = "2023-06-01";
    headers["Content-Type"]       = "application/json";

    apply_oauth_headers(headers, "anthropic", "anthropic", clean_model,
                        build_request_context(&body));
    if (headers.count("authorization") > 0 || headers.count("Authorization") > 0)
        headers.erase("x-api-key");


    headers["Content-Type"] = "application/json";
    const std::string url = join_host_path(base_url, "/v1/messages");
    auto hdrs_list = headers_map_to_list(headers, true);

    struct block_state_t {
        int    index = -1;
        std::string type;
        std::string id;
        std::string name;
        std::string json_accum;
    };
    std::map<int, block_state_t> blocks;

    std::string sse_buffer;
    bool callback_failed = false;
    const std::string request_body = body.dump();
    const auto cancel_cb = operation_cancel_callback(operation);

    auto chunk_cb = [&](const char* data, size_t len) -> bool {
        if (operation->stop_requested())
            return false;
        try {
            sse_buffer.append(data, len);

        size_t pos = 0;
        while (pos < sse_buffer.size()) {
            auto nl = sse_buffer.find('\n', pos);
            if (nl == std::string::npos) break;
            std::string line = sse_buffer.substr(pos, nl - pos);
            pos = nl + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();

            if (line == "data: [DONE]" || line == "data:[DONE]") continue;

            std::string payload;
            if (line.size() > 6 && line.substr(0, 6) == "data: ")
                payload = line.substr(6);
            else if (line.size() > 5 && line.substr(0, 5) == "data:")
                payload = line.substr(5);
            else
                continue;

            if (payload.empty()) continue;
            auto j = json::parse(payload, nullptr, false);
            if (j.is_discarded()) continue;

            std::string event_type = j.value("type", "");


            if (event_type == "message_start" && j.contains("message")) {
                auto& u = j["message"]["usage"];
                if (u.is_object()) {
                    result.input_tokens = u.value("input_tokens", (int64_t)0);
                    result.cache_read   = u.value("cache_read_input_tokens", (int64_t)0);
                    result.cache_write  = u.value("cache_creation_input_tokens", (int64_t)0);
                }
            }


            if (event_type == "content_block_start" && j.contains("content_block")) {
                int idx = j.value("index", -1);
                auto& cb = j["content_block"];
                block_state_t bs;
                bs.index = idx;
                bs.type  = cb.value("type", "");
                if (bs.type == "tool_use") {
                    bs.id   = cb.value("id", "");
                    bs.name = cb.value("name", "");
                }
                blocks[idx] = std::move(bs);
            }


            if (event_type == "content_block_delta" && j.contains("delta")) {
                int idx = j.value("index", -1);
                auto& delta = j["delta"];
                std::string delta_type = delta.value("type", "");

                if (delta_type == "text_delta") {
                    std::string txt = delta.value("text", "");
                    result.text += txt;
                    if (on_chunk) on_chunk(txt);
                }
                else if (delta_type == "thinking_delta") {
                    std::string th = delta.value("thinking", "");
                    result.thinking += th;
                    if (on_chunk) {
                        on_chunk("\x01THINK:" + th);
                        result.thinking_streamed = true;
                    }
                }
                else if (delta_type == "input_json_delta") {
                    auto it = blocks.find(idx);
                    if (it != blocks.end())
                        it->second.json_accum += delta.value("partial_json", "");
                }
            }


            if (event_type == "content_block_stop") {
                int idx = j.value("index", -1);
                auto it = blocks.find(idx);
                if (it != blocks.end() && it->second.type == "tool_use") {
                    ai_tool_call_t tc;
                    tc.id   = it->second.id;
                    tc.name = it->second.name;
                    tc.arguments = json::parse(it->second.json_accum, nullptr, false);
                    if (tc.arguments.is_discarded())
                        tc.arguments = json::object();
                    result.tool_calls.push_back(std::move(tc));
                }
            }


            if (event_type == "message_delta") {
                if (j.contains("delta"))
                    result.stop_reason = j["delta"].value("stop_reason", "");
                if (j.contains("usage"))
                    result.output_tokens = j["usage"].value("output_tokens", (int64_t)0);
            }
        }
            sse_buffer.erase(0, pos);
            return true;
        } catch (...) {
            callback_failed = true;
            operation->request_cancel();
            return false;
        }
    };

    const int anthropic_timeout_sec = operation->remaining_seconds();
    if (anthropic_timeout_sec <= 0) {
        result.is_error = true;
        result.text = operation_stop_error(operation);
        return result;
    }
    aida::auth::http::stream_result_t res = aida::auth::http::stream(
        "POST", url, hdrs_list, request_body, std::string("application/json"),
        anthropic_timeout_sec, chunk_cb, cancel_cb);

    if (callback_failed) {
        result.is_error = true;
        result.text = "Error: Anthropic stream callback failed.";
        result.tool_calls.clear();
        return result;
    }
    if (const auto stop_error = operation_stop_error(operation); !stop_error.empty()) {
        result.is_error = true;
        result.text = stop_error;
        result.tool_calls.clear();
        return result;
    }
    if (res.cancelled) {
        operation->request_cancel();
        result.is_error = true;
        result.text = "Error: Operation cancelled.";
        result.tool_calls.clear();
        return result;
    }
    if (!res.ok && res.status == 0) {
        result.is_error = true;
        result.text = std::string("Error: ")
            + sanitize_transport_error("Anthropic", base_url, res.error);
        return result;
    }
    if (res.status < 200 || res.status >= 300) {
        result.is_error = true;
        std::string err_body;
        if (!sse_buffer.empty()) {
            auto ej = json::parse(sse_buffer, nullptr, false);
            if (!ej.is_discarded() && ej.contains("error") && ej["error"].is_object())
                err_body = ej["error"].value("message", sse_buffer.substr(0, 800));
            else
                err_body = sse_buffer.substr(0, 800);
        }
        if (err_body.empty() && !res.error.empty())
            err_body = res.error.substr(0, 800);
        result.text = "Error: API returned status " + std::to_string(res.status)
                    + (err_body.empty() ? std::string() : (": " + err_body));
        return result;
    }

    if (!res.ok || !res.complete || res.truncated || has_non_whitespace(sse_buffer)) {
        result.is_error = true;
        result.text = has_non_whitespace(sse_buffer)
            ? "Error: Anthropic stream ended with an incomplete SSE frame."
            : "Error: Anthropic stream response was incomplete.";
        result.tool_calls.clear();
        return result;
    }

    usage.input_tokens = result.input_tokens;
    usage.output_tokens = result.output_tokens;
    usage.cache_read = result.cache_read;
    usage.cache_write = result.cache_write;

    return result;
}


ai_generation_result_t standalone_ai_client_t::generate_with_tools_openai(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const nlohmann::json& messages,
    const std::string& system_prompt,
    const std::vector<mcp_standalone::tool_def_t>& tools,
    ai_stream_chunk_t on_chunk,
    usage_record_t& usage)
{
    using json = nlohmann::json;
    ai_generation_result_t result;

    std::string base_url = settings.resolve_active_base_url();
    std::string model    = clean_model_name(settings.get_active_model());
    usage.model = model;

    json oai_messages = convert_messages_for_openai(messages, system_prompt);
    json oai_tools    = build_openai_tools(tools);

    json body = {
        {"model", model},
        {"messages", oai_messages},
        {"stream", true},
        {"stream_options", {{"include_usage", true}}}
    };

    if (!oai_tools.empty()) {
        body["tools"] = oai_tools;
        body["tool_choice"] = "auto";
    }


    bool is_o_series = (model.find("o1") != std::string::npos ||
                        model.find("o3") != std::string::npos ||
                        model.find("o4") != std::string::npos);
    if (is_o_series) {
        body.erase("stream");
        body.erase("stream_options");
        if (settings.enable_reasoning) {
            std::string effort = settings.reasoning_effort;
            if (effort.empty() || effort == "xhigh") effort = "high";
            if (effort == "minimal") effort = "low";
            body["reasoning"] = {{"effort", effort}};
        }
    } else {
        body["temperature"] = 0.0;
    }

    const std::string oai_kind = settings.get_active_profile_kind();
    const std::string oai_store_key = oauth_store_key_for_profile_kind(oai_kind);
    std::string oauth_error;
    if (!refresh_oauth_if_needed(
            oai_store_key, operation_cancel_callback(operation),
            operation->remaining_seconds(), oauth_error)) {
        result.is_error = true;
        const auto stop_error = operation_stop_error(operation);
        result.text = stop_error.empty() ? std::string("Error: ") + oauth_error : stop_error;
        return result;
    }

    std::map<std::string, std::string> openai_headers = settings.get_active_headers();
    openai_headers["Content-Type"] = "application/json";
    openai_headers["Authorization"] = "Bearer " + resolve_api_key_logged(settings, "openai_tools");

    if (!oai_store_key.empty()) {
        const std::string provider_id = (oai_kind == "openai_codex") ? std::string("openai-codex") : std::string("openai");
        apply_oauth_headers(openai_headers, provider_id, oai_store_key, model,
                            build_request_context(&body));
        if (openai_headers.count("authorization") > 0)
            openai_headers.erase("Authorization");
    }

    const std::string openai_url = join_host_path(base_url, "/v1/chat/completions");
    auto openai_hdr_list = headers_map_to_list(openai_headers, true);


    struct oai_tc_state_t {
        std::string id;
        std::string name;
        std::string arguments_accum;
    };
    std::map<int, oai_tc_state_t> tc_map;

    std::string sse_buffer;
    bool callback_failed = false;
    bool is_streaming = body.contains("stream") && body["stream"].get<bool>();
    const std::string openai_body = body.dump();
    const auto cancel_cb = operation_cancel_callback(operation);

    if (is_streaming) {
        auto chunk_cb = [&](const char* data, size_t len) -> bool {
            if (operation->stop_requested())
                return false;
            try {
                sse_buffer.append(data, len);

            size_t pos = 0;
            while (pos < sse_buffer.size()) {
                auto nl = sse_buffer.find('\n', pos);
                if (nl == std::string::npos) break;
                std::string line = sse_buffer.substr(pos, nl - pos);
                pos = nl + 1;
                if (!line.empty() && line.back() == '\r') line.pop_back();

                if (line == "data: [DONE]" || line == "data:[DONE]") continue;

                std::string payload;
                if (line.size() > 6 && line.substr(0, 6) == "data: ")
                    payload = line.substr(6);
                else if (line.size() > 5 && line.substr(0, 5) == "data:")
                    payload = line.substr(5);
                else continue;

                if (payload.empty()) continue;
                auto j = json::parse(payload, nullptr, false);
                if (j.is_discarded()) continue;


                if (j.contains("usage") && j["usage"].is_object()) {
                    auto& u = j["usage"];
                    result.input_tokens  = u.value("prompt_tokens", (int64_t)0);
                    result.output_tokens = u.value("completion_tokens", (int64_t)0);
                    if (u.contains("prompt_tokens_details") && u["prompt_tokens_details"].is_object())
                        result.cache_read = u["prompt_tokens_details"].value("cached_tokens", (int64_t)0);
                }

                if (!j.contains("choices") || j["choices"].empty()) continue;
                auto& choice = j["choices"][0];
                auto& delta = choice["delta"];

                if (delta.contains("content") && delta["content"].is_string()) {
                    std::string txt = delta["content"].get<std::string>();
                    result.text += txt;
                    if (on_chunk) on_chunk(txt);
                }


                if (delta.contains("reasoning_content") && delta["reasoning_content"].is_string()) {
                    std::string th = delta["reasoning_content"].get<std::string>();
                    result.thinking += th;
                    if (on_chunk) {
                        on_chunk("\x01THINK:" + th);
                        result.thinking_streamed = true;
                    }
                }


                if (delta.contains("reasoning") && !delta["reasoning"].is_null()) {
                    std::string th = delta["reasoning"].get<std::string>();
                    if (!th.empty()) {
                        result.thinking += th;
                        if (on_chunk) {
                            on_chunk("\x01THINK:" + th);
                            result.thinking_streamed = true;
                        }
                    }
                }

                if (delta.contains("tool_calls") && delta["tool_calls"].is_array()) {
                    for (auto& tc_delta : delta["tool_calls"]) {
                        int idx = tc_delta.value("index", 0);
                        if (tc_delta.contains("id"))
                            tc_map[idx].id = tc_delta["id"].get<std::string>();
                        if (tc_delta.contains("function")) {
                            auto& fn = tc_delta["function"];
                            if (fn.contains("name"))
                                tc_map[idx].name = fn["name"].get<std::string>();
                            if (fn.contains("arguments"))
                                tc_map[idx].arguments_accum += fn["arguments"].get<std::string>();
                        }
                    }
                }

                if (choice.contains("finish_reason") && choice["finish_reason"].is_string())
                    result.stop_reason = choice["finish_reason"].get<std::string>();
            }
                sse_buffer.erase(0, pos);
                return true;
            } catch (...) {
                callback_failed = true;
                operation->request_cancel();
                return false;
            }
        };

        const int openai_timeout_sec = operation->remaining_seconds();
        if (openai_timeout_sec <= 0) {
            result.is_error = true;
            result.text = operation_stop_error(operation);
            return result;
        }
        aida::auth::http::stream_result_t res = aida::auth::http::stream(
            "POST", openai_url, openai_hdr_list, openai_body,
            std::string("application/json"),
            openai_timeout_sec, chunk_cb, cancel_cb);

        if (callback_failed) {
            result.is_error = true;
            result.text = "Error: OpenAI stream callback failed.";
            result.tool_calls.clear();
            return result;
        }
        if (const auto stop_error = operation_stop_error(operation); !stop_error.empty()) {
            result.is_error = true;
            result.text = stop_error;
            result.tool_calls.clear();
            return result;
        }
        if (res.cancelled) {
            operation->request_cancel();
            result.is_error = true;
            result.text = "Error: Operation cancelled.";
            result.tool_calls.clear();
            return result;
        }
        if (!res.ok && res.status == 0) {
            result.is_error = true;
            result.text = std::string("Error: ")
                + sanitize_transport_error("OpenAI", base_url, res.error);
            return result;
        }
        if (res.status < 200 || res.status >= 300) {
            result.is_error = true;

            std::string err_body;
            if (!sse_buffer.empty()) {
                auto ej = json::parse(sse_buffer, nullptr, false);
                if (!ej.is_discarded() && ej.contains("error") && ej["error"].is_object())
                    err_body = ej["error"].value("message", sse_buffer.substr(0, 600));
                else
                    err_body = sse_buffer.substr(0, 600);
            }
            if (err_body.empty() && !res.error.empty())
                err_body = res.error.substr(0, 600);
            result.text = "Error: API returned status " + std::to_string(res.status)
                        + (err_body.empty() ? std::string() : (": " + err_body));
            return result;
        }
        if (!res.ok || !res.complete || res.truncated || has_non_whitespace(sse_buffer)) {
            result.is_error = true;
            result.text = has_non_whitespace(sse_buffer)
                ? "Error: OpenAI stream ended with an incomplete SSE frame."
                : "Error: OpenAI stream response was incomplete.";
            result.tool_calls.clear();
            return result;
        }
    } else {

        const int openai_timeout_sec = (std::min)(
            k_ai_chat_post_timeout_sec, operation->remaining_seconds());
        if (openai_timeout_sec <= 0) {
            result.is_error = true;
            result.text = operation_stop_error(operation);
            return result;
        }
        aida::auth::http::response_t res = aida::auth::http::post(
            openai_url, openai_hdr_list, openai_body,
            std::string("application/json"),
            openai_timeout_sec,
            cancel_cb);
        if (const auto stop_error = operation_stop_error(operation); !stop_error.empty()) {
            result.is_error = true;
            result.text = stop_error;
            return result;
        }
        if (res.cancelled) {
            operation->request_cancel();
            result.is_error = true;
            result.text = "Error: Operation cancelled.";
            return result;
        }
        if (!res.ok && res.status == 0) {
            result.is_error = true;
            result.text = std::string("Error: ")
                + sanitize_transport_error("OpenAI", base_url, res.error);
            return result;
        }
        if (res.status < 200 || res.status >= 300) {
            result.is_error = true;
            result.text = "Error: API returned status " + std::to_string(res.status) + ": " + res.body.substr(0, 800);
            return result;
        }
        if (!res.ok || !res.complete || res.truncated) {
            result.is_error = true;
            result.text = "Error: OpenAI response was incomplete.";
            return result;
        }

        auto resp = json::parse(res.body, nullptr, false);
        if (resp.is_discarded()) { result.is_error = true; result.text = "Error: Failed to parse response."; return result; }

        if (resp.contains("usage") && resp["usage"].is_object()) {
            auto& u = resp["usage"];
            result.input_tokens  = u.value("prompt_tokens", (int64_t)0);
            result.output_tokens = u.value("completion_tokens", (int64_t)0);
        }

        if (resp.contains("choices") && !resp["choices"].empty()) {
            auto& msg = resp["choices"][0]["message"];
            result.text = msg.value("content", "");
            result.stop_reason = resp["choices"][0].value("finish_reason", "");

            if (msg.contains("reasoning_content") && msg["reasoning_content"].is_string()) {
                result.thinking = msg["reasoning_content"].get<std::string>();
            }

            if (msg.contains("tool_calls") && msg["tool_calls"].is_array()) {
                for (auto& tc : msg["tool_calls"]) {
                    if (tc.value("type", "") != "function") continue;
                    auto& fn = tc["function"];
                    int idx = static_cast<int>(tc_map.size());
                    tc_map[idx].id   = tc.value("id", "tc_" + std::to_string(idx));
                    tc_map[idx].name = fn.value("name", "");
                    tc_map[idx].arguments_accum = fn.value("arguments", "{}");
                }
            }

            if (on_chunk && !result.text.empty()) on_chunk(result.text);
        }
    }


    for (auto& [idx, tcs] : tc_map) {
        ai_tool_call_t tc;
        tc.id   = tcs.id;
        tc.name = tcs.name;
        tc.arguments = json::parse(tcs.arguments_accum, nullptr, false);
        if (tc.arguments.is_discarded()) tc.arguments = json::object();
        result.tool_calls.push_back(std::move(tc));
    }


    usage.input_tokens = result.input_tokens;
    usage.output_tokens = result.output_tokens;
    usage.cache_read = result.cache_read;

    return result;
}


ai_generation_result_t standalone_ai_client_t::generate_with_tools_gemini(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const nlohmann::json& messages,
    const std::string& system_prompt,
    const std::vector<mcp_standalone::tool_def_t>& tools,
    ai_stream_chunk_t on_chunk,
    usage_record_t& usage)
{
    using json = nlohmann::json;
    ai_generation_result_t result;

    std::string base_url = settings.resolve_active_base_url();
    std::string model    = clean_model_name(settings.get_active_model());
    std::string api_key  = resolve_api_key_logged(settings, "gemini_tools");
    usage.model = model;


    json contents  = convert_messages_for_gemini(messages);
    json gem_tools = build_gemini_tools(tools);

    json body = {
        {"contents", contents}
    };

    if (!system_prompt.empty()) {
        body["systemInstruction"] = {
            {"parts", json::array({{{"text", system_prompt}}})}
        };
    }

    if (!gem_tools.empty()) {
        body["tools"] = gem_tools;


        body["toolConfig"] = {
            {"functionCallingConfig", {
                {"mode", "AUTO"}
            }}
        };
    }


    json gen_config = {{"maxOutputTokens", 16384}};


    bool is_thinking_model = (model.find("2.5") != std::string::npos ||
                              model.find("thinking") != std::string::npos ||
                              model.find("3.1") != std::string::npos ||
                              model.find("3-pro") != std::string::npos ||
                              model.find("3-flash") != std::string::npos);

    if (is_thinking_model && settings.enable_reasoning) {
        gen_config["thinkingConfig"] = {
            {"thinkingBudget", (std::max)(settings.reasoning_budget, 1024)}
        };
    }

    if (!is_thinking_model || !settings.enable_reasoning) {
        gen_config["temperature"] = 0.0;
    }

    body["generationConfig"] = gen_config;


    const std::string gemini_path = "/v1beta/models/" + model + ":streamGenerateContent?alt=sse&key=" + api_key;
    const std::string gemini_url = join_host_path(base_url, gemini_path);

    std::map<std::string, std::string> gemini_headers = settings.get_active_headers();
    gemini_headers["Content-Type"] = "application/json";
    auto gemini_hdr_list = headers_map_to_list(gemini_headers, true);

    std::string sse_buffer;
    std::string raw_response;
    bool callback_failed = false;
    const std::string gemini_body = body.dump();

    diag::log_tagged_fmt("chat",
        "gemini_request host=%.120s model=%.80s body=%zu key_present=%d",
        base_url.c_str(), model.c_str(), gemini_body.size(),
        api_key.empty() ? 0 : 1);

    output_log::push(bottom_tab_t::output, "[ai] Gemini POST model=" + model
        + " tools=" + std::to_string(gem_tools.empty() ? 0 : gem_tools[0].value("functionDeclarations", json::array()).size())
        + " body=" + std::to_string(gemini_body.size()) + "B");
    const auto cancel_cb = operation_cancel_callback(operation);

    auto chunk_cb = [&](const char* data, size_t len) -> bool {
        if (operation->stop_requested())
            return false;
        try {
            sse_buffer.append(data, len);
            if (raw_response.size() < 65536) {
                const size_t available = 65536 - raw_response.size();
                raw_response.append(data, (std::min)(len, available));
            }

        size_t pos = 0;
        while (pos < sse_buffer.size()) {
            auto nl = sse_buffer.find('\n', pos);
            if (nl == std::string::npos) break;
            std::string line = sse_buffer.substr(pos, nl - pos);
            pos = nl + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();

            std::string payload;
            if (line.size() > 6 && line.substr(0, 6) == "data: ")
                payload = line.substr(6);
            else if (line.size() > 5 && line.substr(0, 5) == "data:")
                payload = line.substr(5);
            else continue;

            if (payload.empty()) continue;
            auto j = json::parse(payload, nullptr, false);
            if (j.is_discarded()) continue;


            if (j.contains("usageMetadata") && j["usageMetadata"].is_object()) {
                auto& u = j["usageMetadata"];
                result.input_tokens  = u.value("promptTokenCount", (int64_t)0);
                result.output_tokens = u.value("candidatesTokenCount", (int64_t)0);
                if (u.contains("cachedContentTokenCount"))
                    result.cache_read = u.value("cachedContentTokenCount", (int64_t)0);
            }

            if (!j.contains("candidates") || j["candidates"].empty()) continue;
            auto& cand = j["candidates"][0];

            if (cand.contains("finishReason") && cand["finishReason"].is_string())
                result.stop_reason = cand["finishReason"].get<std::string>();

            if (!cand.contains("content") || !cand["content"].contains("parts")) continue;

            for (auto& part : cand["content"]["parts"]) {


                if (part.contains("thought") && part["thought"].is_boolean() &&
                    part["thought"].get<bool>()) {
                    std::string th = part.value("text", "");
                    if (!th.empty()) {
                        result.thinking += th;
                        if (on_chunk) {
                            on_chunk("\x01THINK:" + th);
                            result.thinking_streamed = true;
                        }
                    }
                }
                else if (part.contains("text") && part["text"].is_string()) {
                    std::string txt = part["text"].get<std::string>();
                    result.text += txt;
                    if (on_chunk) on_chunk(txt);
                }
                else if (part.contains("functionCall")) {
                    auto& fc = part["functionCall"];
                    ai_tool_call_t tc;
                    tc.name = fc.value("name", "");
                    tc.id   = "gemini_tc_" + std::to_string(result.tool_calls.size());
                    tc.arguments = fc.value("args", json::object());
                    result.tool_calls.push_back(std::move(tc));
                }
            }
        }
            sse_buffer.erase(0, pos);
            return true;
        } catch (...) {
            callback_failed = true;
            operation->request_cancel();
            return false;
        }
    };

    const int gemini_timeout_sec = operation->remaining_seconds();
    if (gemini_timeout_sec <= 0) {
        result.is_error = true;
        result.text = operation_stop_error(operation);
        return result;
    }
    aida::auth::http::stream_result_t res = aida::auth::http::stream(
        "POST", gemini_url, gemini_hdr_list, gemini_body,
        std::string("application/json"),
        gemini_timeout_sec, chunk_cb, cancel_cb);

    diag::log_tagged_fmt("chat",
        "gemini_response status=%d ok=%d cancelled=%d err_len=%zu raw_len=%zu",
        res.status, res.ok ? 1 : 0, res.cancelled ? 1 : 0,
        res.error.size(), raw_response.size());

    if (callback_failed) {
        result.is_error = true;
        result.text = "Error: Gemini stream callback failed.";
        result.tool_calls.clear();
        return result;
    }
    if (const auto stop_error = operation_stop_error(operation); !stop_error.empty()) {
        result.is_error = true;
        result.text = stop_error;
        result.tool_calls.clear();
        return result;
    }
    if (res.cancelled) {
        operation->request_cancel();
        result.is_error = true;
        result.text = "Error: Operation cancelled.";
        result.tool_calls.clear();
        return result;
    }

    if (!res.ok && res.status == 0) {
        result.is_error = true;
        result.text = std::string("Error: ")
            + sanitize_transport_error("Gemini", base_url, res.error)
            + "\nCheck your internet connection and API key.";
        output_log::push(bottom_tab_t::output, "[ai] Gemini transport error: "
            + res.error + " host=" + base_url);
        return result;
    }
    if (res.status < 200 || res.status >= 300) {
        result.is_error = true;
        std::string raw_err;
        if (!raw_response.empty())
            raw_err = raw_response;
        else if (!res.error.empty())
            raw_err = res.error;

        std::string err_body;
        if (!raw_err.empty()) {
            auto ej = json::parse(raw_err, nullptr, false);
            if (!ej.is_discarded()) {
                if (ej.is_array() && !ej.empty()) ej = ej[0];
                if (ej.contains("error") && ej["error"].is_object())
                    err_body = ej["error"].value("message", raw_err.substr(0, 600));
                else
                    err_body = raw_err.substr(0, 600);
            } else {
                err_body = raw_err.substr(0, 600);
            }
        }
        result.text = "Error: API returned status " + std::to_string(res.status)
                    + (err_body.empty() ? std::string() : (": " + err_body));
        output_log::push(bottom_tab_t::output, "[ai] Gemini error " + std::to_string(res.status)
            + ": " + (err_body.empty() ? "(no error body)" : err_body));
        return result;
    }

    if (!res.ok || !res.complete || res.truncated || has_non_whitespace(sse_buffer)) {
        result.is_error = true;
        result.text = has_non_whitespace(sse_buffer)
            ? "Error: Gemini stream ended with an incomplete SSE frame."
            : "Error: Gemini stream response was incomplete.";
        result.tool_calls.clear();
        return result;
    }

    usage.input_tokens = result.input_tokens;
    usage.output_tokens = result.output_tokens;
    usage.cache_read = result.cache_read;

    return result;
}


ai_generation_result_t standalone_ai_client_t::generate_with_tools_generic_openai(
    const std::shared_ptr<runtime_operation_t>& operation,
    const settings_sa_t& settings,
    const nlohmann::json& messages,
    const std::string& system_prompt,
    const std::vector<mcp_standalone::tool_def_t>& tools,
    ai_stream_chunk_t on_chunk,
    usage_record_t& usage)
{
    using json = nlohmann::json;
    ai_generation_result_t result;

    std::string base_url = settings.resolve_active_base_url();
    std::string model    = clean_model_name(settings.get_active_model());
    std::string api_key  = resolve_api_key_logged(settings, "generic_openai");
    std::string provider = settings.get_active_profile_kind();
    usage.model = model;

    json oai_messages = convert_messages_for_openai(messages, system_prompt);
    json oai_tools    = build_openai_tools(tools);

    json body = {
        {"model", model},
        {"messages", oai_messages},
        {"stream", true}
    };

    if (!oai_tools.empty()) {
        body["tools"] = oai_tools;
        body["tool_choice"] = "auto";
    }

    const bool generic_is_copilot =
        (oauth_store_key_for_profile_kind(provider) == "github-copilot");
    const bool copilot_reasoning_model =
        generic_is_copilot && aida::provider::transforms::copilot_uses_responses_api(model);

    if (copilot_reasoning_model) {
        if (settings.enable_reasoning && !settings.reasoning_effort.empty()) {
            std::string effort = settings.reasoning_effort;
            if (effort == "xhigh") effort = "high";
            if (effort == "minimal") effort = "low";
            body["reasoning_effort"] = effort;
        }
    } else {
        body["temperature"] = 0.0;
    }


    if (provider == "deepseek" || provider == "deepseek_r1") {
        body["stream_options"] = {{"include_usage", true}};
    }
    else if (provider == "openrouter") {
        body["stream_options"] = {{"include_usage", true}};
    }
    else if (provider == "mistral" || provider == "codestral") {
        body["stream_options"] = {{"include_usage", true}};
    }
    else if (provider == "xai") {
        body["stream_options"] = {{"include_usage", true}};
    }
    else {
        body["stream_options"] = {{"include_usage", true}};
    }


    const std::string generic_store_key = oauth_store_key_for_profile_kind(provider);
    std::string oauth_error;
    if (!refresh_oauth_if_needed(
            generic_store_key, operation_cancel_callback(operation),
            operation->remaining_seconds(), oauth_error)) {
        result.is_error = true;
        const auto stop_error = operation_stop_error(operation);
        result.text = stop_error.empty() ? std::string("Error: ") + oauth_error : stop_error;
        return result;
    }

    std::map<std::string, std::string> generic_headers = settings.get_active_headers();
    generic_headers["Content-Type"] = "application/json";
    if (provider == "openrouter") {
        generic_headers["Authorization"] = "Bearer " + api_key;
        generic_headers["HTTP-Referer"] = "https://aida.dev";
        generic_headers["X-Title"] = "AiDA";
    } else if (!api_key.empty()) {
        generic_headers["Authorization"] = "Bearer " + api_key;
    }

    if (!generic_store_key.empty()) {
        // Use the actual provider_id for proper header computation,
        // matching generate_openai's Copilot handling.
        std::string oauth_provider_id;
        if (generic_is_copilot)
            oauth_provider_id = settings.selected_provider_id();
        else if (provider == "openai_codex")
            oauth_provider_id = "openai-codex";
        else if (!generic_store_key.empty())
            oauth_provider_id = generic_store_key;
        else
            oauth_provider_id = provider;

        apply_oauth_headers(generic_headers, oauth_provider_id, generic_store_key, model,
                            build_request_context(&body));
        // If the OAuth layer set a lowercase "authorization" header, remove the
        // uppercase "Authorization" to avoid duplicate/conflicting headers.
        if (generic_headers.count("authorization") > 0)
            generic_headers.erase("Authorization");
        // If the OAuth layer set an uppercase "Authorization" and we had an empty
        // API key, verify we actually have a token. Otherwise the request will fail
        // silently with an empty bearer.
        if (api_key.empty() && generic_headers.count("Authorization") > 0) {
            const std::string& auth_val = generic_headers["Authorization"];
            if (auth_val == "Bearer " || auth_val == "Bearer") {
                // OAuth token was not applied - the auth store may be empty or stale.
                // Try refreshing the token one more time.
                if (!generic_store_key.empty()) {
                    diag::log_tagged_fmt("ai",
                        "generic_openai_empty_oauth_token store_key=%.40s provider=%.40s, forcing refresh",
                        generic_store_key.c_str(), oauth_provider_id.c_str());
                    std::string retry_error;
                    if (!refresh_oauth_if_needed(
                            generic_store_key, operation_cancel_callback(operation),
                            operation->remaining_seconds(), retry_error)) {
                        result.is_error = true;
                        const auto stop_error = operation_stop_error(operation);
                        result.text = stop_error.empty()
                            ? std::string("Error: ") + retry_error
                            : stop_error;
                        return result;
                    }
                    apply_oauth_headers(generic_headers, oauth_provider_id, generic_store_key, model,
                                        build_request_context(&body));
                    if (generic_headers.count("authorization") > 0)
                        generic_headers.erase("Authorization");
                }
            }
        }
    }


    struct oai_tc_state_t {
        std::string id;
        std::string name;
        std::string arguments_accum;
    };
    std::map<int, oai_tc_state_t> tc_map;

    std::string sse_buffer;
    std::string chat_path = "/v1/chat/completions";


    if (provider == "openrouter")
        chat_path = "/api/v1/chat/completions";
    else if (provider == "mistral" || provider == "codestral")
        chat_path = "/v1/chat/completions";
    else if (provider == "ollama")
        chat_path = "/api/chat";

    std::string generic_url = join_host_path(base_url, chat_path);

    if (generic_store_key == "github-copilot") {
        aida::auth::auth_info_t copilot_info;
        const std::string endpoint_provider = settings.selected_provider_id();
        const bool have_info = aida::auth::store::get(generic_store_key, copilot_info);
        const bool uses_responses = aida::provider::transforms::copilot_uses_responses_api(model);
        std::string resolved = aida::provider::transforms::resolve_endpoint(endpoint_provider, model, copilot_info);

        const auto responses_pos = resolved.rfind("/responses");
        if (responses_pos != std::string::npos && responses_pos == resolved.size() - 10)
            resolved.replace(responses_pos, std::string::npos, "/chat/completions");

        if (!resolved.empty())
            generic_url = resolved;

        diag::log_tagged_fmt("ai",
            "copilot endpoint=%.160s responses_api=%d info=%d",
            generic_url.c_str(), uses_responses ? 1 : 0, have_info ? 1 : 0);
    }

    // Pre-flight check: for OAuth providers, ensure we have valid credentials
    // before making the HTTP request. This catches cases where the token
    // exchange failed or the auth store is empty, preventing silent failures
    // that appear as infinite "thinking" to the user.
    if (generic_is_copilot) {
        bool has_auth = false;
        if (generic_headers.count("Authorization") > 0) {
            const std::string& val = generic_headers["Authorization"];
            has_auth = (val.size() > 7);  // "Bearer " + at least one char
        }
        if (!has_auth && generic_headers.count("authorization") > 0) {
            const std::string& val = generic_headers["authorization"];
            has_auth = (val.size() > 7);
        }
        if (!has_auth) {
            result.is_error = true;
            result.text = "Error: GitHub Copilot authentication token is missing or expired. "
                          "Please sign out and sign in again in Settings > Accounts.";
            diag::log_tagged("ai", "copilot_preflight_no_auth_token");
            return result;
        }
    }

    auto generic_hdr_list = headers_map_to_list(generic_headers, true);
    const std::string generic_body = body.dump();
    bool callback_failed = false;
    const auto cancel_cb = operation_cancel_callback(operation);

    auto chunk_cb = [&](const char* data, size_t len) -> bool {
        if (operation->stop_requested())
            return false;
        try {
            sse_buffer.append(data, len);

        size_t pos = 0;
        while (pos < sse_buffer.size()) {
            auto nl = sse_buffer.find('\n', pos);
            if (nl == std::string::npos) break;
            std::string line = sse_buffer.substr(pos, nl - pos);
            pos = nl + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();

            if (line == "data: [DONE]" || line == "data:[DONE]") continue;

            std::string payload;
            if (line.size() > 6 && line.substr(0, 6) == "data: ")
                payload = line.substr(6);
            else if (line.size() > 5 && line.substr(0, 5) == "data:")
                payload = line.substr(5);
            else continue;

            if (payload.empty()) continue;
            auto j = json::parse(payload, nullptr, false);
            if (j.is_discarded()) continue;


            if (j.contains("error") && j["error"].is_object()) {
                std::string err_msg = j["error"].value("message", "Unknown API error");
                int err_code = j["error"].value("code", 0);
                result.is_error = true;
                result.text = "Error: " + err_msg;
                if (err_code != 0)
                    result.text += " (code " + std::to_string(err_code) + ")";
                return false;
            }

            if (j.contains("usage") && j["usage"].is_object()) {
                auto& u = j["usage"];
                result.input_tokens  = u.value("prompt_tokens", (int64_t)0);
                result.output_tokens = u.value("completion_tokens", (int64_t)0);
            }

            if (!j.contains("choices") || j["choices"].empty()) continue;
            auto& choice = j["choices"][0];
            auto& delta  = choice["delta"];

            if (delta.contains("content") && delta["content"].is_string()) {
                std::string txt = delta["content"].get<std::string>();
                result.text += txt;
                if (on_chunk) on_chunk(txt);
            }


            if (delta.contains("reasoning_content") && delta["reasoning_content"].is_string()) {
                std::string th = delta["reasoning_content"].get<std::string>();
                result.thinking += th;
                if (on_chunk) {
                    on_chunk("\x01THINK:" + th);
                    result.thinking_streamed = true;
                }
            }


            if (delta.contains("reasoning") && !delta["reasoning"].is_null()) {
                std::string th = delta["reasoning"].get<std::string>();
                if (!th.empty()) {
                    result.thinking += th;
                    if (on_chunk) {
                        on_chunk("\x01THINK:" + th);
                        result.thinking_streamed = true;
                    }
                }
            }

            if (delta.contains("tool_calls") && delta["tool_calls"].is_array()) {
                for (auto& tc_delta : delta["tool_calls"]) {
                    int idx = tc_delta.value("index", 0);
                    if (tc_delta.contains("id"))
                        tc_map[idx].id = tc_delta["id"].get<std::string>();
                    if (tc_delta.contains("function")) {
                        auto& fn = tc_delta["function"];
                        if (fn.contains("name"))
                            tc_map[idx].name = fn["name"].get<std::string>();
                        if (fn.contains("arguments"))
                            tc_map[idx].arguments_accum += fn["arguments"].get<std::string>();
                    }
                }
            }

            if (choice.contains("finish_reason") && choice["finish_reason"].is_string())
                result.stop_reason = choice["finish_reason"].get<std::string>();
        }
            sse_buffer.erase(0, pos);
            return true;
        } catch (...) {
            callback_failed = true;
            operation->request_cancel();
            return false;
        }
    };

    const int generic_timeout_sec = operation->remaining_seconds();
    if (generic_timeout_sec <= 0) {
        result.is_error = true;
        result.text = operation_stop_error(operation);
        return result;
    }
    aida::auth::http::stream_result_t res = aida::auth::http::stream(
        "POST", generic_url, generic_hdr_list, generic_body,
        std::string("application/json"),
        generic_timeout_sec, chunk_cb, cancel_cb);

    if (callback_failed) {
        result.is_error = true;
        result.text = "Error: Provider stream callback failed.";
        result.tool_calls.clear();
        return result;
    }
    if (result.is_error)
        return result;
    if (const auto stop_error = operation_stop_error(operation); !stop_error.empty()) {
        result.is_error = true;
        result.text = stop_error;
        result.tool_calls.clear();
        return result;
    }
    if (res.cancelled) {
        operation->request_cancel();
        result.is_error = true;
        result.text = "Error: Operation cancelled.";
        result.tool_calls.clear();
        return result;
    }
    if (!res.ok && res.status == 0) {
        result.is_error = true;
        result.text = std::string("Error: ")
            + sanitize_transport_error(provider, base_url, res.error);
        return result;
    }

    if (!res.ok || !res.complete || res.truncated || has_non_whitespace(sse_buffer)) {
        result.is_error = true;
        result.text = has_non_whitespace(sse_buffer)
            ? "Error: Provider stream ended with an incomplete SSE frame."
            : "Error: Provider stream response was incomplete.";
        result.tool_calls.clear();
        return result;
    }
    if (res.status < 200 || res.status >= 300) {
        result.is_error = true;

        std::string err_body;
        if (!sse_buffer.empty()) {
            auto ej = json::parse(sse_buffer, nullptr, false);
            if (!ej.is_discarded() && ej.contains("error") && ej["error"].is_object())
                err_body = ej["error"].value("message", sse_buffer.substr(0, 600));
            else
                err_body = sse_buffer.substr(0, 600);
        }
        if (err_body.empty() && !res.error.empty())
            err_body = res.error.substr(0, 600);
        result.text = "Error: API returned status " + std::to_string(res.status)
                    + (err_body.empty() ? std::string() : (": " + err_body));
        return result;
    }


    for (auto& [idx, tcs] : tc_map) {
        ai_tool_call_t tc;
        tc.id   = tcs.id;
        tc.name = tcs.name;
        tc.arguments = json::parse(tcs.arguments_accum, nullptr, false);
        if (tc.arguments.is_discarded()) tc.arguments = json::object();
        result.tool_calls.push_back(std::move(tc));
    }


    usage.input_tokens = result.input_tokens;
    usage.output_tokens = result.output_tokens;

    return result;
}
