#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#pragma comment(lib, "bcrypt.lib")
#include <shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#include "mcp_standalone.hpp"
#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "../anti-tamper/mcp_posture.hpp"
#include "arc/arc.h"
#include "zydis_disasm.hpp"
#include "sandbox.hpp"
#include "../infra/critical_work_queue.hpp"
#include "../session/analysis_session.hpp"
#include "../../helpers/diag_log.hpp"
#include <httplib.h>
#include <sstream>
#include <fstream>
#include <random>
#include <set>
#include <queue>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <memory>
#include <thread>

namespace mcp_standalone
{
namespace
{
    std::atomic<bool> g_ide_lifecycle_ready{false};
    constexpr size_t kMcpHttpMaxQueuedRequests = 256;
    constexpr int kMcpMaxConcurrentStreams = 8;
    constexpr DWORD kSseSessionMaxAgeMs = 60u * 60u * 1000u;
    std::atomic<std::uint64_t> g_http_request_seq{0};
    std::atomic<int> g_active_http_requests{0};
    std::atomic<std::uint64_t> g_stream_seq{0};
    std::atomic<int> g_active_streams{0};
    std::atomic<size_t> g_cached_external_tool_count{0};
    std::atomic<bool> g_cached_health_ready{false};
    thread_local std::uint64_t tls_http_request_id = 0;
    thread_local std::uint64_t tls_http_request_start_tick = 0;

    static std::uint64_t mcp_now_ms()
    {
        return static_cast<std::uint64_t>(GetTickCount64());
    }

    static void log_work_queue_stats(const char* context)
    {
        const auto st = critical_work_queue::stats();
        diag::log_tagged_fmt("mcp_srv",
            "%s critical_queue alive=%d shutting_down=%d pool_size=%d workers=%zu pending=%zu active=%u post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu",
            context ? context : "critical_queue",
            st.alive ? 1 : 0,
            st.shutting_down ? 1 : 0,
            st.pool_size,
            st.workers,
            st.pending,
            static_cast<unsigned>(st.active),
            static_cast<unsigned long long>(st.post_attempts),
            static_cast<unsigned long long>(st.posted),
            static_cast<unsigned long long>(st.rejected),
            static_cast<unsigned long long>(st.started),
            static_cast<unsigned long long>(st.finished));
    }

    class work_queue_task_queue final : public httplib::TaskQueue
    {
    public:
        explicit work_queue_task_queue(std::size_t max_queued_requests)
            : _max_queued_requests(max_queued_requests)
            , _state(std::make_shared<state_t>())
        {
            log_work_queue_stats("http_task_queue create");
        }

        bool enqueue(std::function<void()> fn) override
        {
            auto state = _state;
            if (!fn || state->shutdown.load(std::memory_order_acquire))
                return false;

            std::size_t observed = state->pending.load(std::memory_order_acquire);
            for (;;) {
                if (_max_queued_requests > 0 && observed >= _max_queued_requests) {
                    diag::log_tagged_fmt("mcp_srv", "http_task_queue enqueue rejected pending=%zu max=%zu",
                        observed, _max_queued_requests);
                    return false;
                }
                if (state->pending.compare_exchange_weak(
                    observed,
                    observed + 1,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                    break;
                }
            }

            const std::uint64_t queued_at = mcp_now_ms();
            bool posted = critical_work_queue::post([state, queued_at, task = std::move(fn)]() mutable {
                const std::uint64_t entered_at = mcp_now_ms();
                const std::uint64_t delay = entered_at >= queued_at ? (entered_at - queued_at) : 0;
                if (delay > 100) {
                    diag::log_tagged_fmt("mcp_srv", "http_task_queue dispatch delay_ms=%llu pending=%zu tid=%lu",
                        static_cast<unsigned long long>(delay),
                        state->pending.load(std::memory_order_acquire),
                        static_cast<unsigned long>(GetCurrentThreadId()));
                }
                try {
                    task();
                } catch (const std::exception& ex) {
                    diag::log_tagged_fmt("mcp_srv", "http_task_queue task exception err='%s'", ex.what());
                } catch (...) {
                    diag::log_tagged("mcp_srv", "http_task_queue task exception err='<unknown>'");
                }
                const std::size_t left = state->pending.fetch_sub(1, std::memory_order_acq_rel) - 1;
                if (state->shutdown.load(std::memory_order_acquire) && left == 0) {
                    std::lock_guard<std::mutex> lk(state->mtx);
                    state->cv.notify_all();
                }
            });
            if (!posted) {
                state->pending.fetch_sub(1, std::memory_order_acq_rel);
                diag::log_tagged_fmt("mcp_srv", "http_task_queue critical_queue post failed pending=%zu",
                    state->pending.load(std::memory_order_acquire));
                log_work_queue_stats("http_task_queue post_failed");
                return false;
            }
            return true;
        }

        void shutdown() override
        {
            auto state = _state;
            state->shutdown.store(true, std::memory_order_release);
            std::unique_lock<std::mutex> lk(state->mtx);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (state->pending.load(std::memory_order_acquire) != 0) {
                if (state->cv.wait_until(lk, deadline, [state]() {
                    return state->pending.load(std::memory_order_acquire) == 0;
                })) {
                    break;
                }
                diag::log_tagged_fmt("mcp_srv", "http_task_queue shutdown timeout pending=%zu",
                    state->pending.load(std::memory_order_acquire));
                break;
            }
            log_work_queue_stats("http_task_queue shutdown");
        }

    private:
        struct state_t {
            std::atomic<bool> shutdown{false};
            std::atomic<std::size_t> pending{0};
            std::mutex mtx;
            std::condition_variable cv;
        };

        const std::size_t _max_queued_requests;
        std::shared_ptr<state_t> _state;
    };

    static std::string remote_endpoint(const httplib::Request& req)
    {
        std::string endpoint = req.remote_addr.empty() ? "<unknown>" : req.remote_addr;
        endpoint += ":";
        endpoint += std::to_string(req.remote_port);
        return endpoint;
    }

    static bool request_connection_closed(const httplib::Request& req)
    {
        try {
            return req.is_connection_closed ? req.is_connection_closed() : false;
        } catch (...) {
            return false;
        }
    }

    static bool connection_closed_now(const std::function<bool()>& fn)
    {
        try {
            return fn ? fn() : false;
        } catch (...) {
            return false;
        }
    }

    struct mcp_stream_state_t
    {
        std::uint64_t id = 0;
        const char* route = "";
        std::string remote;
        std::uint64_t opened_tick = 0;
        std::atomic<bool> released{false};
        std::atomic<bool> done_called{false};
    };

    static std::shared_ptr<mcp_stream_state_t> acquire_stream_slot(const char* route, const httplib::Request& req, httplib::Response& res)
    {
        int cur = g_active_streams.load(std::memory_order_acquire);
        while (cur < kMcpMaxConcurrentStreams) {
            if (g_active_streams.compare_exchange_weak(cur, cur + 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
                auto state = std::make_shared<mcp_stream_state_t>();
                state->id = g_stream_seq.fetch_add(1, std::memory_order_acq_rel) + 1;
                state->route = route ? route : "<unknown>";
                state->remote = remote_endpoint(req);
                state->opened_tick = mcp_now_ms();
                diag::log_tagged_fmt("mcp_srv",
                    "stream_open id=%llu route=%s remote=%s pid=%lu tid=%lu active_streams=%d active_requests=%d",
                    static_cast<unsigned long long>(state->id),
                    state->route,
                    state->remote.c_str(),
                    static_cast<unsigned long>(GetCurrentProcessId()),
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    cur + 1,
                    g_active_http_requests.load(std::memory_order_acquire));
                return state;
            }
        }

        diag::log_tagged_fmt("mcp_srv",
            "stream_reject route=%s remote=%s pid=%lu tid=%lu active_streams=%d max_streams=%d active_requests=%d",
            route ? route : "<unknown>",
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            cur,
            kMcpMaxConcurrentStreams,
            g_active_http_requests.load(std::memory_order_acquire));
        res.status = 503;
        res.set_header("Retry-After", "2");
        res.set_content("{\"error\":\"mcp stream capacity exhausted\"}", "application/json");
        return {};
    }

    static void release_stream_slot(const std::shared_ptr<mcp_stream_state_t>& state, bool success, const char* reason)
    {
        if (!state)
            return;
        if (state->released.exchange(true, std::memory_order_acq_rel))
            return;
        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t elapsed = now >= state->opened_tick ? now - state->opened_tick : 0;
        int active_after = g_active_streams.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (active_after < 0) {
            g_active_streams.store(0, std::memory_order_release);
            active_after = 0;
        }
        diag::log_tagged_fmt("mcp_srv",
            "stream_close id=%llu route=%s remote=%s success=%d reason=%s elapsed_ms=%llu pid=%lu tid=%lu active_streams=%d active_requests=%d",
            static_cast<unsigned long long>(state->id),
            state->route ? state->route : "<unknown>",
            state->remote.c_str(),
            success ? 1 : 0,
            reason ? reason : "",
            static_cast<unsigned long long>(elapsed),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active_after,
            g_active_http_requests.load(std::memory_order_acquire));
    }

    static void finish_stream_cleanly(mcp_stream_state_t* state, httplib::DataSink& sink, const char* reason)
    {
        if (!state || state->done_called.exchange(true, std::memory_order_acq_rel))
            return;
        diag::log_tagged_fmt("mcp_srv",
            "stream_done id=%llu route=%s reason=%s remote=%s pid=%lu tid=%lu",
            static_cast<unsigned long long>(state->id),
            state->route ? state->route : "<unknown>",
            reason ? reason : "",
            state->remote.c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (sink.done)
            sink.done();
    }

    static void finish_stream_cleanly(const std::shared_ptr<mcp_stream_state_t>& state, httplib::DataSink& sink, const char* reason)
    {
        finish_stream_cleanly(state.get(), sink, reason);
    }
}

static std::string json_dump_safe(const json& j, int indent = -1)
{
    try { return j.dump(indent); }
    catch (...) { return "{}"; }
}

[[noreturn]] static void mcp_auth_fastfail(const char* where)
{
    std::string missing_exports;
    const bool exports_ok = standalone_license::is_arc_loaded()
        && standalone_license::validate_arc_required_exports(missing_exports);
    diag::log_tagged_fmt("mcp_srv",
        "auth_fastfail where=%s ide=%d valid=%d arc=%d loading=%d exports=%d missing='%.160s'",
        where ? where : "<null>",
        g_ide_lifecycle_ready.load(std::memory_order_acquire) ? 1 : 0,
        standalone_license::is_valid() ? 1 : 0,
        standalone_license::is_arc_loaded() ? 1 : 0,
        standalone_license::is_arc_download_in_progress() ? 1 : 0,
        exports_ok ? 1 : 0,
        missing_exports.c_str());
    __fastfail(0xA1DA4D43u);
}

static bool mcp_runtime_authorized()
{
    if (!g_ide_lifecycle_ready.load(std::memory_order_acquire))
        return false;
    if (!anti_tamper::mcp_posture::is_current_posture_trusted())
        return false;
    if (!standalone_license::is_valid() || !standalone_license::is_arc_loaded())
        return false;
    std::string missing_exports;
    return standalone_license::validate_arc_required_exports(missing_exports);
}

static void require_mcp_runtime_authorized(const char* where)
{
    if (!mcp_runtime_authorized())
        mcp_auth_fastfail(where);
}

void set_ide_lifecycle_ready(bool ready) noexcept
{
    g_ide_lifecycle_ready.store(ready, std::memory_order_release);
}

bool lifecycle_authorized(std::string* reason)
{
    if (!g_ide_lifecycle_ready.load(std::memory_order_acquire)) {
        if (reason) *reason = "ide_not_ready";
        return false;
    }
    if (!standalone_license::is_valid()) {
        if (reason) *reason = "license_invalid";
        return false;
    }
    if (!standalone_license::is_arc_loaded()) {
        if (reason)
            *reason = standalone_license::is_arc_download_in_progress() ? "arc_loading" : "arc_not_loaded";
        return false;
    }
    std::string missing_exports;
    if (!standalone_license::validate_arc_required_exports(missing_exports)) {
        if (reason) *reason = missing_exports.empty() ? "arc_exports_missing" : ("arc_exports_missing:" + missing_exports);
        return false;
    }
    if (reason) *reason = "authorized";
    return true;
}

static std::string generate_session_id()
{

    unsigned char rnd[16] = {};
    NTSTATUS st = BCryptGenRandom(nullptr, rnd, sizeof(rnd),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {

        auto t = std::chrono::steady_clock::now().time_since_epoch().count();
        for (size_t i = 0; i < sizeof(rnd); ++i)
            rnd[i] = static_cast<unsigned char>((t >> (i * 8)) ^ i);
    }
    char buf[48];
    snprintf(buf, sizeof(buf),
             "sa-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7],
             rnd[8], rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14], rnd[15]);
    return buf;
}

static std::string read_env_var(const char* name)
{
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || !value)
        return {};
    std::string result(value);
    free(value);
    return result;
}

static std::string sanitize_utf8(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size(); )
    {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            result += static_cast<char>(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size()) {
            result += input[i]; result += input[i+1]; i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size()) {
            result += input[i]; result += input[i+1]; result += input[i+2]; i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size()) {
            result += input[i]; result += input[i+1]; result += input[i+2]; result += input[i+3]; i += 4;
        } else {
            result += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return result;
}

static std::string snake_to_title(const std::string& name)
{
    std::string result;
    bool cap = true;
    for (char c : name) {
        if (c == '_') {
            result += ' ';
            cap = true;
        } else {
            result += cap ? static_cast<char>(toupper(c)) : c;
            cap = false;
        }
    }
    return result;
}

static std::string lower_ascii(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

static bool json_bool_param(const json& params, const char* name)
{
    if (!params.is_object() || !params.contains(name))
        return false;
    const auto& value = params[name];
    if (value.is_boolean())
        return value.get<bool>();
    if (value.is_string()) {
        const std::string v = lower_ascii(value.get<std::string>());
        return v == "1" || v == "true" || v == "yes" || v == "full";
    }
    return false;
}

static bool wants_full_tool_list(const json& params)
{
    if (!params.is_object())
        return false;
    if (json_bool_param(params, "full") ||
        json_bool_param(params, "includeDescriptions") ||
        json_bool_param(params, "include_descriptions") ||
        json_bool_param(params, "includeSchema") ||
        json_bool_param(params, "include_schema")) {
        return true;
    }
    if (params.contains("detail") && params["detail"].is_string()) {
        const std::string detail = lower_ascii(params["detail"].get<std::string>());
        return detail == "full" || detail == "description" ||
               detail == "descriptions" || detail == "schema" ||
               detail == "schemas";
    }
    return false;
}

static std::string format_sse_event(const std::string& event_type, const std::string& data)
{
    std::string result;
    if (!event_type.empty())
        result += "event: " + event_type + "\n";
    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line))
        result += "data: " + line + "\n";
    result += "\n";
    return result;
}

struct sse_session_t
{
    std::string id;
    std::mutex  mtx;
    std::queue<std::string> events;
    std::atomic<bool> closed{false};
    std::uint64_t opened_tick = mcp_now_ms();
    std::atomic<std::uint64_t> last_activity_tick{0};

    void push_event(const std::string& event)
    {
        last_activity_tick.store(mcp_now_ms(), std::memory_order_release);
        std::lock_guard<std::mutex> lk(mtx);
        events.push(event);
    }

    bool wait_event(std::string& out, int timeout_ms)
    {
        const DWORD start_tick = GetTickCount();
        const DWORD timeout = static_cast<DWORD>(timeout_ms < 0 ? 0 : timeout_ms);
        for (;;)
        {
            {
                std::lock_guard<std::mutex> lk(mtx);
                if (closed.load(std::memory_order_acquire))
                    return false;
                if (!events.empty()) {
                    out = std::move(events.front());
                    events.pop();
                    last_activity_tick.store(mcp_now_ms(), std::memory_order_release);
                    return true;
                }
            }
            const DWORD elapsed = GetTickCount() - start_tick;
            if (elapsed >= timeout)
                return false;
            const DWORD remaining = timeout - elapsed;
            Sleep(remaining < 50u ? remaining : 50u);
        }
    }

    void close() { closed.store(true, std::memory_order_release); }
};

static bool sse_provider_step_impl(
    sse_session_t* session,
    httplib::DataSink* sink,
    size_t offset,
    std::atomic<bool>* stop_requested,
    mcp_stream_state_t* stream_state,
    const std::function<bool()>& connection_closed)
{
    if (offset == 0) {
        std::string evt = format_sse_event("endpoint",
            "/message?sessionId=" + session->id);
        if (!sink->write(evt.c_str(), evt.size())) {
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=endpoint",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            return false;
        }
    }
    if (connection_closed_now(connection_closed)) {
        session->close();
        finish_stream_cleanly(stream_state, *sink, "connection_closed");
        return true;
    }
    std::string event;
    if (session->wait_event(event, 2000)) {
        if (!sink->write(event.c_str(), event.size())) {
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=event",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            return false;
        }
    } else if (session->closed.load(std::memory_order_acquire)) {
        finish_stream_cleanly(stream_state, *sink, "session_closed");
        return true;
    } else if (stop_requested && stop_requested->load(std::memory_order_acquire)) {
        session->close();
        finish_stream_cleanly(stream_state, *sink, "server_stop");
        return true;
    } else {
        const char ka[] = ": keepalive\n\n";
        if (sink->is_writable && !sink->is_writable()) {
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=writable",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            return false;
        }
        if (!sink->write(ka, sizeof(ka) - 1u)) {
            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=keepalive",
                stream_state ? static_cast<unsigned long long>(stream_state->id) : 0ULL,
                stream_state && stream_state->route ? stream_state->route : "<unknown>");
            session->close();
            return false;
        }
    }
    return !session->closed.load(std::memory_order_acquire);
}

__declspec(noinline) static DWORD seh_sse_provider_step(
    sse_session_t* session,
    httplib::DataSink* sink,
    size_t offset,
    std::atomic<bool>* stop_requested,
    mcp_stream_state_t* stream_state,
    const std::function<bool()>& connection_closed,
    bool* out_continue)
{
    *out_continue = false;
    __try {
        *out_continue = sse_provider_step_impl(session, sink, offset, stop_requested, stream_state, connection_closed);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

namespace
{
    std::mutex                                                       g_in_flight_mutex;
    std::map<std::string, std::shared_ptr<std::atomic<bool>>>        g_in_flight_cancels;
    thread_local std::atomic<bool>*                                  tls_current_cancel_token = nullptr;

    std::string cancel_key_for_id(const json& id)
    {
        if (id.is_null())              return std::string{"\1null"};
        if (id.is_string())            return std::string{"s:"} + id.get<std::string>();
        if (id.is_number_integer())    return std::string{"i:"} + std::to_string(id.get<long long>());
        if (id.is_number_unsigned())   return std::string{"u:"} + std::to_string(id.get<unsigned long long>());
        if (id.is_number_float())      return std::string{"f:"} + std::to_string(id.get<double>());
        return std::string{"j:"} + id.dump();
    }

    std::shared_ptr<std::atomic<bool>> register_in_flight_call(const json& id)
    {
        auto token = std::make_shared<std::atomic<bool>>(false);
        std::lock_guard<std::mutex> lk(g_in_flight_mutex);
        g_in_flight_cancels[cancel_key_for_id(id)] = token;
        return token;
    }

    void unregister_in_flight_call(const json& id)
    {
        std::lock_guard<std::mutex> lk(g_in_flight_mutex);
        g_in_flight_cancels.erase(cancel_key_for_id(id));
    }

    bool signal_in_flight_cancel(const json& id)
    {
        std::shared_ptr<std::atomic<bool>> token;
        {
            std::lock_guard<std::mutex> lk(g_in_flight_mutex);
            auto it = g_in_flight_cancels.find(cancel_key_for_id(id));
            if (it == g_in_flight_cancels.end()) return false;
            token = it->second;
        }
        if (token) token->store(true, std::memory_order_release);
        return true;
    }

    struct cancel_scope_t
    {
        json                              id;
        std::shared_ptr<std::atomic<bool>> token;
        std::atomic<bool>*                previous = nullptr;

        cancel_scope_t(const json& request_id)
            : id(request_id)
        {
            token = register_in_flight_call(id);
            previous = tls_current_cancel_token;
            tls_current_cancel_token = token.get();
        }

        cancel_scope_t(const cancel_scope_t&) = delete;
        cancel_scope_t& operator=(const cancel_scope_t&) = delete;

        ~cancel_scope_t()
        {
            tls_current_cancel_token = previous;
            unregister_in_flight_call(id);
        }
    };
}

std::atomic<bool>* current_cancel_token() noexcept
{
    return tls_current_cancel_token;
}

bool current_call_cancelled() noexcept
{
    std::atomic<bool>* tok = tls_current_cancel_token;
    return tok && tok->load(std::memory_order_acquire);
}

server_t::server_t()  = default;
server_t::~server_t() { stop(); }

static bool is_camoufox_reverse_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "browser_lifecycle", "browser_navigation", "browser_interaction", "browser_inspect", "browser_state",
        "browser_network", "browser_hooks", "browser_instrumentation",
        "get_console_logs", "scripts", "search_code", "compare_env",
        "verify_signer_offline", "analyze_cookie_sources"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_camoufox_browser_tool_name(const std::string& name)
{
    return is_camoufox_reverse_tool_name(name);
}

static bool is_standalone_internal_only_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "apply_diff", "apply_patch", "codebase_search", "read_command_output",
        "search_workspace", "run_command", "cancel_command", "list_commands"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_standalone_ide_chat_only_tool_name(const std::string& name)
{
    static const char* const names[] = {
        "switch_agent", "plan_enter", "plan_exit", "list_agents", "ask_followup_question",
        "attempt_completion", "update_todo_list", "save_checkpoint", "restore_checkpoint",
        "list_checkpoints", "checkpoint_list", "skill", "run_slash_command", "get_context",
        "workflow_status", "task"
    };
    for (const char* n : names)
    {
        if (name == n)
            return true;
    }
    return false;
}

static bool is_external_mcp_tool(const tool_def_t& tool)
{
    return tool.visibility == tool_visibility_t::external_visible &&
           !is_standalone_ide_chat_only_tool_name(tool.name) &&
           !is_standalone_internal_only_tool_name(tool.name);
}

bool server_t::register_tool(tool_def_t tool)
{
    if (is_standalone_ide_chat_only_tool_name(tool.name))
        tool.visibility = tool_visibility_t::ide_chat_only;
    else if (is_standalone_internal_only_tool_name(tool.name))
        tool.visibility = tool_visibility_t::internal_only;

    bool already_has_binary_id = false;
    for (const auto& p : tool.params) {
        if (p.name == "binary_id") { already_has_binary_id = true; break; }
    }
    bool is_targetless_tool = tool.name.rfind("sessions_", 0) == 0 ||
                              tool.name == "get_tool_descriptions" ||
                              is_camoufox_browser_tool_name(tool.name);
    if (!already_has_binary_id && !is_targetless_tool) {
        tool.params.push_back(tool_param_t{
            "binary_id",
            "string",
            "Optional session id to target (returned by `sessions_manage` action=list). When omitted the active session is used.",
            false
        });
    }
    std::lock_guard<std::mutex> lk(_tools_mtx);
    auto dup = std::find_if(_tools.begin(), _tools.end(), [&](const tool_def_t& existing) {
        return existing.name == tool.name;
    });
    if (dup != _tools.end()) {
        if (tool.name == "decompile_function" &&
            dup->visibility == tool_visibility_t::external_visible &&
            tool.visibility == tool_visibility_t::external_visible) {
            diag::log_tagged_fmt("mcp_srv",
                "register_tool updated name='%s' visibility=%d",
                tool.name.c_str(), static_cast<int>(tool.visibility));
            *dup = std::move(tool);
            return true;
        }
        diag::log_tagged_fmt("mcp_srv",
            "register_tool duplicate skipped name='%s' existing_visibility=%d new_visibility=%d",
            tool.name.c_str(), static_cast<int>(dup->visibility), static_cast<int>(tool.visibility));
        return false;
    }
    _tools.push_back(std::move(tool));
    return true;
}

json server_t::make_result(const json& id, const json& result)
{
    json r;
    r["jsonrpc"] = "2.0";
    r["id"]      = id;
    r["result"]  = result;
    return r;
}

json server_t::make_error(const json& id, int code, const std::string& msg)
{
    json r;
    r["jsonrpc"]          = "2.0";
    r["id"]               = id;
    r["error"]["code"]    = code;
    r["error"]["message"] = msg;
    return r;
}

json server_t::tool_schema(const tool_def_t& tool, bool compact) const
{
    if (compact && tool.name != "get_tool_descriptions") {
        return json{
            {"name", tool.name},
            {"description", tool.description},
            {"inputSchema", json{{"type", "object"}}}
        };
    }

    json input_schema;
    input_schema["type"] = "object";
    json properties = json::object();
    json required_arr = json::array();

    for (const auto& p : tool.params) {
        json desc;
        desc["type"]        = p.type;
        desc["description"] = p.description;
        properties[p.name] = desc;
        if (p.required) required_arr.push_back(p.name);
    }

    input_schema["properties"] = properties;
    if (!required_arr.empty()) input_schema["required"] = required_arr;

    json annotations;
    annotations["title"]           = snake_to_title(tool.name);
    annotations["readOnlyHint"]    = tool.read_only;
    annotations["destructiveHint"] = (!tool.read_only);
    annotations["idempotentHint"]  = tool.read_only;
    annotations["openWorldHint"]   = (tool.name == "sandbox_execute");

    json t;
    t["name"]        = tool.name;
    t["description"] = tool.description;
    t["inputSchema"] = input_schema;
    t["annotations"] = annotations;
    return t;
}

tool_result_t server_t::describe_tools(const json& params)
{
    std::vector<std::string> names;
    if (params.is_object()) {
        if (params.contains("names") && params["names"].is_array()) {
            for (const auto& n : params["names"]) {
                if (n.is_string())
                    names.push_back(n.get<std::string>());
            }
        } else if (params.contains("names") && params["names"].is_string()) {
            names.push_back(params["names"].get<std::string>());
        }
        if (params.contains("name") && params["name"].is_string())
            names.push_back(params["name"].get<std::string>());
    }

    std::string prefix;
    std::string query;
    bool include_schema = true;
    int limit = 40;
    if (params.is_object()) {
        if (params.contains("prefix") && params["prefix"].is_string())
            prefix = params["prefix"].get<std::string>();
        if (params.contains("query") && params["query"].is_string())
            query = params["query"].get<std::string>();
        if (params.contains("include_schema") && params["include_schema"].is_boolean())
            include_schema = params["include_schema"].get<bool>();
        if (params.contains("limit") && params["limit"].is_number_integer())
            limit = params["limit"].get<int>();
    }
    limit = (std::max)(1, (std::min)(limit, 100));

    std::vector<tool_def_t> matches;
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        if (!names.empty()) {
            for (const auto& wanted : names) {
                for (const auto& tool : _tools) {
                    if (!is_external_mcp_tool(tool))
                        continue;
                    if (tool.name == wanted) {
                        auto dup = std::find_if(matches.begin(), matches.end(),
                            [&](const tool_def_t& existing) { return existing.name == tool.name; });
                        if (dup == matches.end())
                            matches.push_back(tool);
                        break;
                    }
                }
            }
        } else if (!prefix.empty() || !query.empty()) {
            const std::string prefix_l = lower_ascii(prefix);
            const std::string query_l = lower_ascii(query);
            for (const auto& tool : _tools) {
                if (!is_external_mcp_tool(tool))
                    continue;
                const std::string name_l = lower_ascii(tool.name);
                const std::string desc_l = lower_ascii(tool.description);
                bool ok = true;
                if (!prefix_l.empty())
                    ok = name_l.rfind(prefix_l, 0) == 0;
                if (ok && !query_l.empty())
                    ok = name_l.find(query_l) != std::string::npos ||
                         desc_l.find(query_l) != std::string::npos;
                if (ok)
                    matches.push_back(tool);
            }
        }
    }

    if (names.empty() && prefix.empty() && query.empty())
        return tool_result_t::ok("Pass `names`, `name`, `prefix`, or `query` to retrieve full tool descriptions.");

    if (matches.empty())
        return tool_result_t::ok("No matching tools found.");

    const size_t shown = (std::min)(matches.size(), static_cast<size_t>(limit));
    std::string result;
    result.reserve(shown * 256);
    if (matches.size() > shown) {
        result += "Showing " + std::to_string(shown) + " of " +
                  std::to_string(matches.size()) +
                  " matching tools. Refine with `name`, `names`, `prefix`, or `query`.\n\n";
    }
    for (size_t i = 0; i < shown; ++i) {
        const auto& tool = matches[i];
        result += "### " + tool.name + "\n";
        if (!tool.description.empty())
            result += tool.description + "\n";
        result += std::string("Read-only: ") + (tool.read_only ? "true" : "false") + "\n";
        if (include_schema) {
            if (tool.params.empty()) {
                result += "Parameters: none\n";
            } else {
                result += "Parameters:\n";
                for (const auto& p : tool.params) {
                    result += "- `" + p.name + "` (" + p.type;
                    if (p.required)
                        result += ", required";
                    result += ")";
                    if (!p.description.empty())
                        result += ": " + p.description;
                    result += "\n";
                }
            }
        }
        result += "\n";
    }
    return tool_result_t::ok(result);
}

json server_t::handle_initialize(const json& id, const json&)
{
    diag::log_tagged_fmt("mcp_srv", "handle_initialize entry");
    json capabilities;
    capabilities["tools"]     = {{"listChanged", true}};
    capabilities["resources"] = {{"listChanged", true}};
    capabilities["prompts"]   = {{"listChanged", true}};
    capabilities["logging"]   = json::object();

    json server_info;
    server_info["name"]    = SERVER_NAME;
    server_info["version"] = SERVER_VERSION;

    static const char* instructions =
        "AiDAStandalone MCP is self-describing. Do not expect external markdown files such as TOOLS.md; shipped users normally receive only AiDAStandalone.exe and AiDA.dll. Learn the available surface from this initialize response, `tools/list`, and targeted `get_tool_descriptions` calls.\n\n"
        "You are connected to AiDAStandalone, a reverse-engineering assistant "
        "for standalone static binary sessions, live process/runtime inspection, "
        "kernel-backed debugger/memory workflows, Windows Sandbox sample execution, "
        "and browser/network reversing through bundled Camoufox MCP tools.\n\n"
        "## Capabilities\n"
        "- Open and analyze PE/ELF/Mach-O/SYS files as standalone static sessions\n"
        "- Read live process memory from an attached process\n"
        "- Disassemble x64 code at live addresses or from files\n"
        "- Attach to or detach from running processes when runtime access is required\n"
        "- Execute untrusted binaries in Windows Sandbox when explicitly requested\n"
        "- Convert integers, endian bytes, ASCII, signed/unsigned views, IEEE-754 values, alignment, VA, RVA, module-relative, and PE file-offset references\n"
        "- Use bundled Camoufox reverse-engineering browser tools through grouped actions exposed as `browser_lifecycle`, `browser_navigation`, `browser_interaction`, `browser_inspect`, `browser_state`, `browser_network`, `browser_hooks`, and `browser_instrumentation`\n\n"
        "## First-use workflow\n"
        "- Use `get_tool_descriptions` with `names`, `prefix`, or `query` for only the tools you plan to call; do not spam broad discovery calls\n"
        "- For standalone static binaries, use `sessions_manage` action `open_file`, then `analysis_query` action `binary_map_overview` or `disasm_get_section_info`, `disasm_list_functions`, and targeted disassembly/decompilation tools\n"
        "- For live runtime work, use `sessions_manage` action `attach_pid` for session attachment, then memory/disassembly tools.\n"
        "- When a VM bridge is active, pass `target: \"guest\"` or `target: \"host\"` explicitly whenever host/VM memory matters\n"
        "- Custom QEMU, VirtualBox, VMware, and Windows Sandbox workflows use the normal AiDA MCP tools such as `list_processes`, `sessions_manage` action `attach_pid`, `read_memory`, `query_memory`, `dbg_get_modules_detail`, and `disassemble_zydis`\n"
        "- For custom VM workflows, keep AiDAStandalone.exe on the host and run only the sample plus MCP client or guest agent in the VM through an authenticated host bridge or tunnel that terminates at AiDA's localhost MCP endpoint\n"
        "- Cache session IDs, binary IDs, module bases, function bounds, xrefs, scan state, and decompiler output; avoid duplicate calls with identical parameters\n"
        "- Prefer batch or paginated tools over repeated one-off calls; set limits before large scans\n\n"
        "## Address and conversion rules\n"
        "- Prefer hex strings such as `0x140001000`\n"
        "- Live/debugger addresses are process VAs; stable references should include module+RVA when module context is known\n"
        "- Static file tools may return image base, section RVA, and raw file-offset context; carry that context forward\n"
        "- Use `convert_number` for all number, byte, signedness, float, VA/RVA, module-base, and PE file-offset conversions; never hand-convert offsets or byte values\n\n"
        "## Safety and mutation rules\n"
        "- `read_only=true` tools inspect state; `read_only=false` tools may mutate process memory, debugger state, files, browser state, proxy state, sandbox state, or analysis/session state\n"
        "- Only call mutating tools when the user asked for that action and the target is clear\n"
        "- Runtime, debugger, sandbox, browser interception, and filesystem tools are local trust-boundary tools even though the server binds to localhost\n\n"
        "## Browser/runtime shortcuts\n"
        "- For browser tasks, call `browser_lifecycle` with `action=launch` first when no Camoufox session is running, then call `browser_navigation` with `action=navigate` and a fully-qualified URL\n"
        "- Do not call session/driver attach or list helpers before browser-only work unless the user asks for diagnostics or runtime access\n"
        "- For runtime inspection, open or verify the process target with `sessions_manage` (`action=list` or `action=attach_pid`) and then use `query_memory`, `read_memory`, or `disassemble_zydis` as needed\n"
        "- Use `list_processes` if you need PID and process context before `sessions_manage` attachment\n"
        "- Use `disassemble_zydis` for live memory; `disassemble_file` for PE files\n"
        "- Use `sandbox_execute` for running untrusted binaries safely when the user requests execution\n";

    json result;
    result["protocolVersion"] = PROTOCOL_VERSION;
    result["capabilities"]    = capabilities;
    result["serverInfo"]      = server_info;
    result["instructions"]    = instructions;
    return make_result(id, result);
}

json server_t::handle_ping(const json& id, const json&)
{
    return make_result(id, json::object());
}

json server_t::handle_tools_list(const json& id, const json& params)
{
    json tools_arr = json::array();
    const bool compact = !wants_full_tool_list(params);
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        for (const auto& t : _tools) {
            if (!is_external_mcp_tool(t)) continue;
            tools_arr.push_back(tool_schema(t, compact));
        }
    }
    diag::log_tagged_fmt("mcp_srv", "handle_tools_list compact=%d count=%zu",
        compact ? 1 : 0, tools_arr.size());
    json result;
    result["tools"] = tools_arr;
    result["_meta"] = {
        {"aidaToolListMode", compact ? "compact" : "full"},
        {"aidaToolDetailTool", "get_tool_descriptions"}
    };
    return make_result(id, result);
}

json server_t::handle_tools_call(const json& id, const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    const std::string early_name = params["name"].get<std::string>();
    diag::log_tagged_fmt("mcp_srv", "handle_tools_call tool='%s'", early_name.c_str());

    require_mcp_runtime_authorized("tools_call");

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_mcp_tool_exec);
        if (!standalone_license::verify_tool_runtime(
                standalone_license::gate_mcp_tool_exec, gt, early_name)) {
            std::string error_text = standalone_license::decode_status_string(
                standalone_license::str_session_revoked);
            if (standalone_license::is_valid() && !standalone_license::is_arc_loaded()) {
                error_text = standalone_license::is_arc_download_in_progress()
                    ? "AiDA protected runtime is still loading. Try the tool again after activation finishes."
                    : "AiDA protected runtime is not loaded. Open AiDAStandalone.exe, activate the license, and wait for ARC initialization to complete.";
                const std::string last = standalone_license::last_error();
                if (!last.empty())
                    error_text += " Last license status: " + last;
            }
            return make_error(id, -32000, error_text);
        }
    }

    std::string tool_name = early_name;
    json arguments = params.contains("arguments") && params["arguments"].is_object()
                   ? params["arguments"] : json::object();

    if (is_standalone_ide_chat_only_tool_name(tool_name) || is_standalone_internal_only_tool_name(tool_name))
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);

    const tool_def_t* found = nullptr;
    std::function<tool_result_t(const json&)> handler_copy;
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        for (const auto& t : _tools) {
            if (t.name == tool_name) {
                if (!is_external_mcp_tool(t)) {
                    return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
                }
                found = &t;
                handler_copy = t.handler;
                break;
            }
        }
    }

    if (!found)
    {
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call unknown_tool='%s'", tool_name.c_str());
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
    }

    diag::log_tagged_fmt("mcp_srv", "handle_tools_call dispatching tool='%s'", tool_name.c_str());
    cancel_scope_t scope(id);

    tool_result_t tr;
    try {
        tr = handler_copy(arguments);
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call exception tool='%s' what='%s'",
            tool_name.c_str(), e.what());
        tr = tool_result_t::error(std::string("Tool threw exception: ") + e.what());
    } catch (...) {
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call unknown_exception tool='%s'", tool_name.c_str());
        tr = tool_result_t::error("Tool threw unknown exception");
    }
    diag::log_tagged_fmt("mcp_srv", "handle_tools_call result tool='%s' success=%d",
        tool_name.c_str(), (int)tr.success);

    if (scope.token && scope.token->load(std::memory_order_acquire)) {
        json cancel_result;
        cancel_result["content"] = json::array({
            json{{"type", "text"}, {"text", "Tool call cancelled by client request."}}
        });
        cancel_result["isError"] = true;
        return make_result(id, cancel_result);
    }

    json content = json::array();
    if (!tr.text.empty()) {
        content.push_back({{"type", "text"}, {"text", sanitize_utf8(tr.text)}});
    }
    if (!tr.data.is_null() && !tr.data.empty()) {
        content.push_back({{"type", "text"}, {"text", sanitize_utf8(json_dump_safe(tr.data, 2))}});
    }
    if (content.empty()) {
        content.push_back({{"type", "text"}, {"text", tr.success
            ? "Tool executed successfully (no output)."
            : "Tool execution failed (no details)."}});
    }

    json result;
    result["content"] = content;
    if (!tr.success) result["isError"] = true;
    return make_result(id, result);
}

json server_t::handle_resources_list(const json& id, const json&)
{
    json resources = json::array();

    resources.push_back({
        {"uri",         "standalone://driver-status"},
        {"name",        "Driver Status"},
        {"description", "Current driver and process attachment state"},
        {"mimeType",    "application/json"}
    });

    resources.push_back({
        {"uri",         "standalone://loaded-file"},
        {"name",        "Loaded File Info"},
        {"description", "Information about the currently loaded PE file"},
        {"mimeType",    "application/json"}
    });

    json result;
    result["resources"] = resources;
    return make_result(id, result);
}

json server_t::handle_resources_read(const json& id, const json& params)
{
    if (!params.contains("uri") || !params["uri"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'uri'");

    std::string uri = params["uri"].get<std::string>();
    json text_content;

    if (uri == "standalone://driver-status") {
        json status;
        status["ready"]       = driver_bridge::is_loaded();
        status["attached_pid"]= driver_bridge::attached_pid();
        status["status"]      = driver_bridge::status();
        text_content = status;
    }
    else if (uri == "standalone://loaded-file") {
        text_content = json{{"info", "Use disassemble_file tool to load and inspect PE files."}};
    }
    else {
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown resource URI: " + uri);
    }

    json contents = json::array();
    contents.push_back({
        {"uri",      uri},
        {"mimeType", "application/json"},
        {"text",     json_dump_safe(text_content, 2)}
    });

    json result;
    result["contents"] = contents;
    return make_result(id, result);
}

json server_t::handle_prompts_list(const json& id, const json&)
{
    json prompts = json::array();

    prompts.push_back({
        {"name",        "analyze_memory"},
        {"description", "Read and analyze memory at an address in the attached process"},
        {"arguments",   json::array({
            {{"name", "address"}, {"description", "Hex address to analyze"}, {"required", true}},
            {{"name", "size"},    {"description", "Number of bytes to read (default 256)"}, {"required", false}}
        })}
    });

    prompts.push_back({
        {"name",        "disassemble_region"},
        {"description", "Disassemble code at an address in the attached process"},
        {"arguments",   json::array({
            {{"name", "address"}, {"description", "Hex address to disassemble"}, {"required", true}},
            {{"name", "count"},   {"description", "Max instructions (default 50)"}, {"required", false}}
        })}
    });

    prompts.push_back({
        {"name",        "sandbox_analysis"},
        {"description", "Run a binary in Windows Sandbox and analyze its output"},
        {"arguments",   json::array({
            {{"name", "path"}, {"description", "Path to the executable to analyze"}, {"required", true}}
        })}
    });

    json result;
    result["prompts"] = prompts;
    return make_result(id, result);
}

json server_t::handle_prompts_get(const json& id, const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string name = params["name"].get<std::string>();
    json arguments = params.value("arguments", json::object());

    json messages = json::array();

    if (name == "analyze_memory") {
        std::string addr = arguments.value("address", "");
        if (addr.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        std::string prompt =
            "Read and analyze the memory at address " + addr + " in the attached process.\n"
            "Use the read_memory tool to fetch the bytes, then:\n"
            "1. Show a hex dump of the data\n"
            "2. Identify any strings or recognizable patterns\n"
            "3. Disassemble if the region appears to contain code\n"
            "4. Note any pointers or interesting values\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else if (name == "disassemble_region") {
        std::string addr = arguments.value("address", "");
        if (addr.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        std::string prompt =
            "Disassemble the code at address " + addr + " in the attached process.\n"
            "Use the disassemble_zydis tool, then:\n"
            "1. Identify the function's purpose\n"
            "2. Analyze control flow (branches, loops, calls)\n"
            "3. Note any system calls, API calls, or string references\n"
            "4. Look for security-relevant patterns\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else if (name == "sandbox_analysis") {
        std::string path = arguments.value("path", "");
        if (path.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'path'");

        std::string prompt =
            "Execute the binary at '" + path + "' in Windows Sandbox.\n"
            "Use the sandbox_execute tool, then:\n"
            "1. Examine the stdout/stderr output\n"
            "2. Check if the process timed out or was killed\n"
            "3. Note the peak memory usage\n"
            "4. Investigate any suspicious behavior indicators\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else {
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown prompt: " + name);
    }

    json result;
    result["description"] = name;
    result["messages"]    = messages;
    return make_result(id, result);
}

json server_t::route_request(const json& msg)
{
    require_mcp_runtime_authorized("route_request");

    if (!msg.is_object())
        return make_error(nullptr, JSONRPC_INVALID_REQUEST, "Request must be a JSON object");

    std::string method = msg.value("method", "");
    diag::log_tagged_fmt("mcp_srv", "route_request method='%s'", method.c_str());
    if (method.empty())
        return make_error(msg.value("id", json(nullptr)), JSONRPC_INVALID_REQUEST, "Missing 'method' field");

    json id     = msg.contains("id") ? msg["id"] : json(nullptr);
    json params = msg.value("params", json::object());
    bool is_notification = !msg.contains("id");

    if (method == "initialize")               return handle_initialize(id, params);
    if (method == "notifications/initialized") return json();
    if (method == "ping")                     return handle_ping(id, params);
    if (method == "tools/list")               return handle_tools_list(id, params);
    if (method == "tools/call")               return handle_tools_call(id, params);
    if (method == "resources/list")           return handle_resources_list(id, params);
    if (method == "resources/read")           return handle_resources_read(id, params);
    if (method == "prompts/list")             return handle_prompts_list(id, params);
    if (method == "prompts/get")              return handle_prompts_get(id, params);
    if (method == "notifications/cancelled") {
        if (params.is_object() && params.contains("requestId"))
            signal_in_flight_cancel(params["requestId"]);
        return json();
    }
    if (method == "logging/setLevel")
        return json();
    if (is_notification)                      return json();

    return make_error(id, JSONRPC_METHOD_NOT_FOUND, "Unknown method: " + method);
}

std::string handle_body(server_t* self, const std::string& body)
{
    json parsed;
    try { parsed = json::parse(body); }
    catch (const json::parse_error& e) {
        return json_dump_safe(self->make_error(nullptr, JSONRPC_PARSE_ERROR,
            std::string("JSON parse error: ") + e.what()));
    }

    if (parsed.is_array()) {
        if (parsed.empty())
            return json_dump_safe(self->make_error(nullptr, JSONRPC_INVALID_REQUEST, "Empty batch"));
        json responses = json::array();
        for (const auto& item : parsed) {
            json response = self->route_request(item);
            if (!response.is_null()) responses.push_back(response);
        }
        if (responses.empty()) return "";
        return json_dump_safe(responses);
    }

    json response = self->route_request(parsed);
    if (response.is_null()) return "";
    return json_dump_safe(response);
}

bool server_t::start(int port)
{
    diag::log_tagged_fmt("mcp_srv", "start entry port=%d", port);
    if (!mcp_runtime_authorized())
    {
        std::string missing_exports;
        const bool exports_ok = standalone_license::is_arc_loaded()
            && standalone_license::validate_arc_required_exports(missing_exports);
        diag::log_tagged_fmt("mcp_srv",
            "start_blocked_unauthorized ide=%d valid=%d arc=%d loading=%d exports=%d missing='%.160s'",
            g_ide_lifecycle_ready.load(std::memory_order_acquire) ? 1 : 0,
            standalone_license::is_valid() ? 1 : 0,
            standalone_license::is_arc_loaded() ? 1 : 0,
            standalone_license::is_arc_download_in_progress() ? 1 : 0,
            exports_ok ? 1 : 0,
            missing_exports.c_str());
        return false;
    }
    if (_running.load())
    {
        diag::log_tagged_fmt("mcp_srv", "start already running port=%d", port);
        return true;
    }

    _stop_requested = false;
    _port = 0;

    if (!_server_done.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("mcp_srv", "start rejected server worker already starting port=%d", port);
        log_work_queue_stats("start rejected");
        return false;
    }

    _server_done.store(false, std::memory_order_release);
    log_work_queue_stats("start before post");
    const bool posted = critical_work_queue::post([this, port]() {
        const DWORD tid = GetCurrentThreadId();
        _server_worker_tid.store(static_cast<std::uint32_t>(tid), std::memory_order_release);
        diag::log_tagged_fmt("mcp_srv", "server_worker starting port=%d tid=%lu", port, static_cast<unsigned long>(tid));
        log_work_queue_stats("server_worker entry");
        try {
            server_thread_func(port);
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("mcp_srv", "server_worker exception port=%d err='%s'", port, ex.what());
            _running.store(false, std::memory_order_release);
        } catch (...) {
            diag::log_tagged_fmt("mcp_srv", "server_worker exception port=%d err='<unknown>'", port);
            _running.store(false, std::memory_order_release);
        }
        diag::log_tagged_fmt("mcp_srv", "server_worker exited port=%d tid=%lu", port, static_cast<unsigned long>(GetCurrentThreadId()));
        _server_worker_tid.store(0, std::memory_order_release);
        _server_done.store(true, std::memory_order_release);
    });
    if (!posted) {
        diag::log_tagged("mcp_srv", "start critical_queue post failed");
        log_work_queue_stats("start post_failed");
        _server_done.store(true, std::memory_order_release);
        return false;
    }
    diag::log_tagged_fmt("mcp_srv", "start critical_queue post ok port=%d", port);

    for (int i = 0; i < 500 && !_running.load() && !_server_done.load(std::memory_order_acquire) && !_stop_requested.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    diag::log_tagged_fmt("mcp_srv", "start result running=%d port=%d",
        (int)_running.load(), _port);
    return _running.load();
}

void server_t::stop()
{
    diag::log_tagged_fmt("mcp_srv", "stop entry running=%d", (int)_running.load());
    const bool on_server_worker = _server_worker_tid.load(std::memory_order_acquire) == static_cast<std::uint32_t>(GetCurrentThreadId());
    if (!_running.load() && _server_done.load(std::memory_order_acquire))
    {
        diag::log_tagged_fmt("mcp_srv", "stop already stopped");
        return;
    }
    _stop_requested = true;
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        if (_active_server)
            static_cast<httplib::Server*>(_active_server)->stop();
    }
    if (!on_server_worker) {
        const std::uint64_t wait_start = mcp_now_ms();
        while (!_server_done.load(std::memory_order_acquire)) {
            const std::uint64_t elapsed = mcp_now_ms() - wait_start;
            if (elapsed > 10000) {
                diag::log_tagged_fmt("mcp_srv", "stop wait timeout elapsed_ms=%llu worker_tid=%u running=%d",
                    static_cast<unsigned long long>(elapsed),
                    static_cast<unsigned>(_server_worker_tid.load(std::memory_order_acquire)),
                    _running.load(std::memory_order_acquire) ? 1 : 0);
                log_work_queue_stats("stop wait timeout");
                break;
            }
            if (elapsed == 1000 || elapsed == 3000 || elapsed == 5000)
                log_work_queue_stats("stop waiting");
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    diag::log_tagged_fmt("mcp_srv", "stop done");
}

void server_t::server_thread_func(int port)
{
    diag::log_tagged_fmt("mcp_srv", "server_thread_func entry port=%d", port);
    g_cached_health_ready.store(false, std::memory_order_release);
    g_cached_external_tool_count.store(0, std::memory_order_release);
    httplib::Server svr;
    svr.new_task_queue = [] {
        return new work_queue_task_queue(kMcpHttpMaxQueuedRequests);
    };
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func critical_queue_http_dispatch max_queue=%zu",
        kMcpHttpMaxQueuedRequests);
    svr.set_keep_alive_max_count(8);
    svr.set_keep_alive_timeout(2);
    svr.set_read_timeout(5, 0);
    svr.set_write_timeout(10, 0);
    svr.set_idle_interval(0, 100000);
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func http_limits keep_alive_max=8 keep_alive_timeout_sec=2 read_timeout_sec=5 write_timeout_sec=10 idle_interval_us=100000 max_streams=%d",
        kMcpMaxConcurrentStreams);
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = &svr;
    }

    std::string session_id = generate_session_id();
    diag::log_tagged_fmt("mcp_srv", "server_thread_func session_id='%s'", session_id.c_str());

    svr.set_default_headers({
        {"Access-Control-Allow-Origin",  "*"},
        {"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, MCP-Protocol-Version, Accept, Authorization, Last-Event-ID"},
        {"Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version"}
    });

    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response&) {
        tls_http_request_id = g_http_request_seq.fetch_add(1, std::memory_order_acq_rel) + 1;
        tls_http_request_start_tick = mcp_now_ms();
        const int active = g_active_http_requests.fetch_add(1, std::memory_order_acq_rel) + 1;
        diag::log_tagged_fmt("mcp_srv",
            "request_entry id=%llu method=%s path=%s matched=%s remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d body_len=%zu conn_closed=%d",
            static_cast<unsigned long long>(tls_http_request_id),
            req.method.c_str(),
            req.path.c_str(),
            req.matched_route.c_str(),
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active,
            g_active_streams.load(std::memory_order_acquire),
            req.body.size(),
            request_connection_closed(req) ? 1 : 0);
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        const std::uint64_t now = mcp_now_ms();
        const std::uint64_t elapsed = (tls_http_request_start_tick != 0 && now >= tls_http_request_start_tick) ? (now - tls_http_request_start_tick) : 0;
        int active_after = g_active_http_requests.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (active_after < 0) {
            g_active_http_requests.store(0, std::memory_order_release);
            active_after = 0;
        }
        diag::log_tagged_fmt("mcp_srv",
            "request_exit id=%llu method=%s path=%s matched=%s status=%d elapsed_ms=%llu remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d body_len=%zu conn_closed=%d",
            static_cast<unsigned long long>(tls_http_request_id),
            req.method.c_str(),
            req.path.c_str(),
            req.matched_route.c_str(),
            res.status,
            static_cast<unsigned long long>(elapsed),
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            active_after,
            g_active_streams.load(std::memory_order_acquire),
            req.body.size(),
            request_connection_closed(req) ? 1 : 0);
        tls_http_request_id = 0;
        tls_http_request_start_tick = 0;
    });

    svr.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
        diag::log_tagged_fmt("mcp_srv",
            "OPTIONS path=%s acrm=%s acrh=%s",
            req.path.c_str(),
            req.get_header_value("Access-Control-Request-Method").c_str(),
            req.get_header_value("Access-Control-Request-Headers").c_str());
        res.status = 204;
    });

    svr.Post("/mcp", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_post_mcp");
        diag::log_tagged_fmt("mcp_srv",
            "POST /mcp body_len=%zu accept=%s content_type=%s protocol=%s session=%s",
            req.body.size(),
            req.get_header_value("Accept").c_str(),
            req.get_header_value("Content-Type").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            req.get_header_value("Mcp-Session-Id").c_str());
        std::string response_body = handle_body(this, req.body);
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        if (response_body.empty())
            res.status = 202;
        else
            res.set_content(response_body, "application/json");
    });

    svr.Get("/mcp", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_get_mcp");
        diag::log_tagged_fmt("mcp_srv",
            "GET /mcp accept=%s protocol=%s session=%s",
            req.get_header_value("Accept").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            req.get_header_value("Mcp-Session-Id").c_str());
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        std::string accept = req.get_header_value("Accept");
        bool wants_sse = accept.find("text/event-stream") != std::string::npos;

        if (wants_sse) {
            auto stream_state = acquire_stream_slot("GET /mcp", req, res);
            if (!stream_state)
                return;
            auto connection_closed = req.is_connection_closed;
            res.set_header("Cache-Control", "no-cache");
            res.set_chunked_content_provider(
                "text/event-stream",
                [this, stream_state, connection_closed](size_t offset, httplib::DataSink& sink) -> bool {
                    if (connection_closed_now(connection_closed)) {
                        finish_stream_cleanly(stream_state, sink, "connection_closed");
                        return true;
                    }
                    if (offset == 0) {
                        const char connected[] = ": connected\n\n";
                        if (!sink.write(connected, sizeof(connected) - 1u)) {
                            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=connected",
                                static_cast<unsigned long long>(stream_state->id),
                                stream_state->route ? stream_state->route : "<unknown>");
                            return false;
                        }
                    }
                    const char ka[] = ": keepalive\n\n";
                    for (int i = 0; i < 6; ++i) {
                        for (int slice = 0; slice < 50; ++slice) {
                            if (_stop_requested.load(std::memory_order_acquire)) {
                                finish_stream_cleanly(stream_state, sink, "server_stop");
                                return true;
                            }
                            if (connection_closed_now(connection_closed)) {
                                finish_stream_cleanly(stream_state, sink, "connection_closed");
                                return true;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                        if (_stop_requested.load(std::memory_order_acquire)) {
                            finish_stream_cleanly(stream_state, sink, "server_stop");
                            return true;
                        }
                        if (connection_closed_now(connection_closed)) {
                            finish_stream_cleanly(stream_state, sink, "connection_closed");
                            return true;
                        }
                        if (sink.is_writable && !sink.is_writable()) {
                            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=writable",
                                static_cast<unsigned long long>(stream_state->id),
                                stream_state->route ? stream_state->route : "<unknown>");
                            return false;
                        }
                        if (!sink.write(ka, sizeof(ka) - 1u)) {
                            diag::log_tagged_fmt("mcp_srv", "stream_write_fail id=%llu route=%s phase=keepalive",
                                static_cast<unsigned long long>(stream_state->id),
                                stream_state->route ? stream_state->route : "<unknown>");
                            return false;
                        }
                    }
                    return true;
                },
                [stream_state](bool success) {
                    release_stream_slot(stream_state, success, success ? "provider_complete" : "provider_failed");
                });
        } else {
            res.set_content("event: endpoint\ndata: /mcp\n\n", "text/event-stream");
        }
    });

    svr.Delete("/mcp", [&session_id](const httplib::Request&, httplib::Response& res) {
        require_mcp_runtime_authorized("http_delete_mcp");
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.Get("/health", [this](const httplib::Request& req, httplib::Response& res) {
        const std::uint64_t t0 = mcp_now_ms();
        diag::log_tagged_fmt("mcp_srv",
            "health_entry remote=%s pid=%lu tid=%lu active_requests=%d active_streams=%d",
            remote_endpoint(req).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            g_active_http_requests.load(std::memory_order_acquire),
            g_active_streams.load(std::memory_order_acquire));
        json health;
        std::string missing_exports;
        const bool exports_ok = standalone_license::is_arc_loaded()
            && standalone_license::validate_arc_required_exports(missing_exports);
        const bool runtime_ok = g_ide_lifecycle_ready.load(std::memory_order_acquire)
            && standalone_license::is_valid()
            && standalone_license::is_arc_loaded()
            && exports_ok;
        health["status"]      = "ok";
        health["server"]      = SERVER_NAME;
        health["version"]     = SERVER_VERSION;
        health["pid"]         = static_cast<std::uint32_t>(GetCurrentProcessId());
        health["port"]        = _port;
        health["authenticated"] = runtime_ok;
        health["validated"] = standalone_license::is_valid();
        health["arc_loaded"] = standalone_license::is_arc_loaded();
        health["lifecycle_ready"] = g_ide_lifecycle_ready.load(std::memory_order_acquire);
        health["exports_verified"] = exports_ok;
        health["tools_count"] = g_cached_external_tool_count.load(std::memory_order_acquire);
        health["cache_ready"] = g_cached_health_ready.load(std::memory_order_acquire);
        health["active_requests"] = g_active_http_requests.load(std::memory_order_acquire);
        health["active_streams"] = g_active_streams.load(std::memory_order_acquire);
        health["stream_limit"] = kMcpMaxConcurrentStreams;
        res.status = 200;
        res.set_content(json_dump_safe(health), "application/json");
        const std::uint64_t elapsed = mcp_now_ms() - t0;
        diag::log_tagged_fmt("mcp_srv",
            "health_exit status=%d elapsed_ms=%llu remote=%s active_requests=%d active_streams=%d",
            res.status,
            static_cast<unsigned long long>(elapsed),
            remote_endpoint(req).c_str(),
            g_active_http_requests.load(std::memory_order_acquire),
            g_active_streams.load(std::memory_order_acquire));
    });

    svr.Get("/", [this](const httplib::Request&, httplib::Response& res) {
        json health;
        health["status"] = "ok";
        health["server"] = SERVER_NAME;
        health["mcp"] = "/mcp";
        health["sse"] = "/sse";
        health["health"] = "/health";
        size_t external_tools = 0;
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools)
              if (is_external_mcp_tool(t)) ++external_tools; }
        health["tools_count"] = external_tools;
        res.set_content(json_dump_safe(health), "application/json");
    });

    svr.Get("/api/tools", [this](const httplib::Request&, httplib::Response& res) {
        require_mcp_runtime_authorized("api_tools_list");
        json tools_arr = json::array();
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools) {
              if (!is_external_mcp_tool(t)) continue;
              tools_arr.push_back(tool_schema(t, false));
          } }
        res.set_content(json_dump_safe(tools_arr, 2), "application/json");
    });

    svr.Post("/api/tools/call", [this](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("api_tools_call");
        diag::log_tagged_fmt("mcp_srv", "POST /api/tools/call body_len=%zu", req.body.size());
        json body;
        try { body = json::parse(req.body); }
        catch (const json::parse_error& e) {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", e.what()}}), "application/json");
            return;
        }

        std::string tool_name = body.value("name", "");
        json arguments = body.value("arguments", json::object());

        if (tool_name.empty()) {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing 'name' field"}}), "application/json");
            return;
        }

        const tool_def_t* found = nullptr;
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools) {
              if (t.name == tool_name) {
                  if (!is_external_mcp_tool(t)) {
                      res.status = 404;
                      res.set_content(json_dump_safe({{"error", "Unknown tool: " + tool_name}}), "application/json");
                      return;
                  }
                  found = &t;
                  break;
              }
          } }

        if (!found) {
            res.status = 404;
            res.set_content(json_dump_safe({{"error", "Unknown tool: " + tool_name}}), "application/json");
            return;
        }

        tool_result_t tr;
        try { tr = found->handler(arguments); }
        catch (const std::exception& e) { tr = tool_result_t::error(e.what()); }

        json resp;
        resp["success"] = tr.success;
        resp["output"]  = sanitize_utf8(tr.text);
        if (!tr.data.is_null() && !tr.data.empty()) resp["data"] = tr.data;
        res.set_content(json_dump_safe(resp, 2), "application/json");
    });

    std::map<std::string, std::shared_ptr<sse_session_t>> sse_sessions;
    std::mutex sse_mtx;

    auto cleanup_sse_sessions = [&sse_sessions, &sse_mtx](const char* reason) {
        const std::uint64_t now = mcp_now_ms();
        size_t removed = 0;
        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            for (auto it = sse_sessions.begin(); it != sse_sessions.end(); ) {
                const auto& session = it->second;
                const bool aged = session && now >= session->opened_tick && (now - session->opened_tick) > kSseSessionMaxAgeMs;
                if (!session || session->closed.load(std::memory_order_acquire) || aged) {
                    if (session)
                        session->close();
                    it = sse_sessions.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
        }
        if (removed != 0) {
            diag::log_tagged_fmt("mcp_srv",
                "sse_session_cleanup reason=%s removed=%zu active_streams=%d active_requests=%d",
                reason ? reason : "",
                removed,
                g_active_streams.load(std::memory_order_acquire),
                g_active_http_requests.load(std::memory_order_acquire));
        }
    };

    svr.Get("/sse", [this, &sse_sessions, &sse_mtx, &cleanup_sse_sessions](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_get_sse");
        cleanup_sse_sessions("before_open");
        auto session = std::make_shared<sse_session_t>();
        session->id = generate_session_id();
        auto stream_state = acquire_stream_slot("GET /sse", req, res);
        if (!stream_state)
            return;
        auto connection_closed = req.is_connection_closed;
        size_t session_count = 0;
        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            sse_sessions[session->id] = session;
            session_count = sse_sessions.size();
        }
        diag::log_tagged_fmt("mcp_srv",
            "sse_session_open session=%s stream_id=%llu remote=%s sessions=%zu",
            session->id.c_str(),
            static_cast<unsigned long long>(stream_state->id),
            stream_state->remote.c_str(),
            session_count);

        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");

        std::atomic<bool>* stop_ptr = &_stop_requested;
        res.set_chunked_content_provider(
            "text/event-stream",
            [session, stop_ptr, stream_state, connection_closed](size_t offset, httplib::DataSink& sink) -> bool {
                bool cont = false;
                DWORD seh = seh_sse_provider_step(session.get(), &sink, offset, stop_ptr, stream_state.get(), connection_closed, &cont);
                if (seh != 0) {
                    diag::log_tagged_fmt("mcp_srv",
                        "stream_provider_seh id=%llu route=%s code=0x%08lX",
                        static_cast<unsigned long long>(stream_state->id),
                        stream_state->route ? stream_state->route : "<unknown>",
                        static_cast<unsigned long>(seh));
                    session->close();
                    return false;
                }
                return cont;
            },
            [session, &sse_sessions, &sse_mtx, stream_state](bool success) {
                session->close();
                size_t remaining = 0;
                {
                    std::lock_guard<std::mutex> lk(sse_mtx);
                    sse_sessions.erase(session->id);
                    remaining = sse_sessions.size();
                }
                diag::log_tagged_fmt("mcp_srv",
                    "sse_session_close session=%s stream_id=%llu success=%d remaining=%zu",
                    session->id.c_str(),
                    static_cast<unsigned long long>(stream_state->id),
                    success ? 1 : 0,
                    remaining);
                release_stream_slot(stream_state, success, success ? "provider_complete" : "provider_failed");
            });
    });

    svr.Post("/message", [this, &sse_sessions, &sse_mtx, &cleanup_sse_sessions](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_post_message");
        cleanup_sse_sessions("before_message");
        std::string sid = req.get_param_value("sessionId");
        if (sid.empty()) {
            res.status = 400;
            res.set_content(json_dump_safe(make_error(nullptr,
                JSONRPC_INVALID_REQUEST, "Missing sessionId query parameter")), "application/json");
            return;
        }

        std::shared_ptr<sse_session_t> session;
        { std::lock_guard<std::mutex> lk(sse_mtx);
          auto it = sse_sessions.find(sid);
          if (it == sse_sessions.end() || !it->second || it->second->closed.load(std::memory_order_acquire)) {
              if (it != sse_sessions.end())
                  sse_sessions.erase(it);
              res.status = 404;
              res.set_content(json_dump_safe(make_error(nullptr,
                  JSONRPC_INVALID_REQUEST, "Unknown or expired session: " + sid)), "application/json");
              return;
          }
          session = it->second;
        }

        std::string response_body = handle_body(this, req.body);
        if (!response_body.empty()) {
            std::string event = format_sse_event("message", response_body);
            session->push_event(event);
        }
        res.status = 202;
        res.set_content("Accepted", "text/plain");
    });

    svr.Post("/sse", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        require_mcp_runtime_authorized("http_post_sse");
        diag::log_tagged_fmt("mcp_srv",
            "POST /sse body_len=%zu accept=%s protocol=%s session=%s",
            req.body.size(),
            req.get_header_value("Accept").c_str(),
            req.get_header_value("MCP-Protocol-Version").c_str(),
            req.get_header_value("Mcp-Session-Id").c_str());
        std::string response_body = handle_body(this, req.body);
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        if (response_body.empty()) res.status = 202;
        else res.set_content(response_body, "application/json");
    });

    svr.Delete("/sse", [&session_id](const httplib::Request&, httplib::Response& res) {
        require_mcp_runtime_authorized("http_delete_sse");
        res.set_header("Mcp-Session-Id", session_id);
        res.set_header("MCP-Protocol-Version", PROTOCOL_VERSION);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.set_socket_options([](socket_t sock) {
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&yes), sizeof(yes));
    });

    int bound_port = 0;
    if (port > 0 && svr.bind_to_port("127.0.0.1", port))
        bound_port = port;
    if (bound_port <= 0)
        bound_port = svr.bind_to_any_port("127.0.0.1");

    if (bound_port <= 0) {
        diag::log_tagged_fmt("mcp_srv", "server_thread_func bind fail port=%d", port);
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = nullptr;
        _stop_requested = true;
        return;
    }

    _port = bound_port;
    _running = true;
    size_t external_tools = 0;
    { std::lock_guard<std::mutex> lk(_tools_mtx);
      for (const auto& t : _tools)
          if (is_external_mcp_tool(t)) ++external_tools; }
    g_cached_external_tool_count.store(external_tools, std::memory_order_release);
    g_cached_health_ready.store(true, std::memory_order_release);
    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func listening bound_port=%d endpoints=/mcp,/sse,/health external_tools=%zu",
        bound_port, external_tools);

    diag::log_tagged_fmt("mcp_srv",
        "server_thread_func listen_after_bind_enter port=%d pid=%lu tid=%lu",
        bound_port,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    svr.listen_after_bind();

    diag::log_tagged_fmt("mcp_srv", "server_thread_func listen_after_bind returned port=%d", bound_port);
    g_cached_health_ready.store(false, std::memory_order_release);
    _running = false;
    { std::lock_guard<std::mutex> lk(_server_mtx); _active_server = nullptr; }
}

static std::string get_home_dir()
{
    std::string env_home = read_env_var("USERPROFILE");
    if (!env_home.empty())
        return env_home;
    char buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, buf)))
        return buf;
    return "";
}

static std::string get_appdata_dir()
{
    std::string env_appdata = read_env_var("APPDATA");
    if (!env_appdata.empty())
        return env_appdata;
    char buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, buf)))
        return buf;
    return "";
}

static std::string expand_path(const char* tmpl)
{
    if (!tmpl || !*tmpl) return "";
    std::string path(tmpl);

    if (path.size() >= 1 && path[0] == '~') {
        std::string home = get_home_dir();
        if (home.empty()) return "";
        if (path.size() >= 2 && (path[1] == '/' || path[1] == '\\'))
            path = home + path.substr(1);
        else if (path.size() == 1)
            path = home;
    }

    size_t pos = path.find("%APPDATA%");
    if (pos != std::string::npos) {
        std::string appdata = get_appdata_dir();
        if (appdata.empty()) return "";
        path.replace(pos, 9, appdata);
    }

    for (auto& c : path) if (c == '/') c = '\\';
    return path;
}

static bool ensure_dir(const std::string& dir)
{
    if (dir.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return std::filesystem::is_directory(dir, ec);
}

static bool ensure_parent_dir(const std::string& path)
{
    auto p = std::filesystem::path(path).parent_path();
    if (p.empty()) return true;
    return ensure_dir(p.string());
}

static bool read_file_to_string(const std::string& path, std::string& out)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

static bool write_string_to_file(const std::string& path, const std::string& content)
{
    if (!ensure_parent_dir(path)) return false;
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs << content;
    return ofs.good();
}

static std::string strip_jsonc(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    bool in_string = false, in_line = false, in_block = false;

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (in_line)  { if (c == '\n') { in_line = false; result += '\n'; } continue; }
        if (in_block) { if (c == '*' && i+1 < input.size() && input[i+1] == '/') { in_block = false; ++i; } continue; }
        if (in_string) { result += c; if (c == '\\' && i+1 < input.size()) result += input[++i]; else if (c == '"') in_string = false; continue; }
        if (c == '"') { in_string = true; result += c; continue; }
        if (c == '/' && i+1 < input.size()) {
            if (input[i+1] == '/') { in_line = true; ++i; continue; }
            if (input[i+1] == '*') { in_block = true; ++i; continue; }
        }
        if (c == ',') {
            size_t j = i+1;
            while (j < input.size() && (input[j]==' '||input[j]=='\t'||input[j]=='\n'||input[j]=='\r')) ++j;
            if (j < input.size() && (input[j] == '}' || input[j] == ']')) continue;
        }
        result += c;
    }
    return result;
}

static bool parse_json_file(const std::string& path, json& out, bool allow_jsonc)
{
    std::string raw;
    if (!read_file_to_string(path, raw)) return false;
    try { out = json::parse(raw); return true; }
    catch (const json::parse_error&) {
        if (!allow_jsonc) return false;
    }
    try { out = json::parse(strip_jsonc(raw)); return true; }
    catch (const json::parse_error&) { return false; }
}

static bool write_json_file(const std::string& path, const json& data)
{
    return write_string_to_file(path, json_dump_safe(data, 2) + "\n");
}

static const char* MCP_NAME = "aida-standalone-mcp";

struct client_cfg_t {
    const char* name;
    enum { URL, SERVERURL, OPENCODE, VSCODE, VSCODE_JSON, CLINE, ZED, CODEX, CLAUDE_CODE } format;
    const char* win_path;
};

static const client_cfg_t g_clients[] = {
    { "Cline",           client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" },
    { "Roo Code",        client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" },
    { "Kilo Code",       client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json" },
    { "Claude",          client_cfg_t::URL,          "%APPDATA%/Claude/claude_desktop_config.json" },
    { "Cursor",          client_cfg_t::URL,          "~/.cursor/mcp.json" },
    { "Windsurf",        client_cfg_t::URL,          "~/.codeium/windsurf/mcp_config.json" },
    { "Claude Code",     client_cfg_t::CLAUDE_CODE,  "~/.claude.json" },
    { "LM Studio",       client_cfg_t::URL,          "~/.lmstudio/mcp.json" },
    { "Codex",           client_cfg_t::CODEX,        "~/.codex/config.toml" },
    { "Zed",             client_cfg_t::ZED,          "%APPDATA%/Zed/settings.json" },
    { "Gemini CLI",      client_cfg_t::URL,          "~/.gemini/settings.json" },
    { "Qwen Coder",      client_cfg_t::URL,          "~/.qwen/settings.json" },
    { "Copilot CLI",     client_cfg_t::URL,          "~/.copilot/mcp-config.json" },
    { "Crush",           client_cfg_t::URL,          "~/crush.json" },
    { "Augment Code",    client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "Qodo Gen",        client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "Antigravity IDE", client_cfg_t::SERVERURL,    "~/.gemini/antigravity/mcp_config.json" },
    { "Warp",            client_cfg_t::URL,          "~/.warp/mcp_config.json" },
    { "Amazon Q",        client_cfg_t::URL,          "~/.aws/amazonq/mcp_config.json" },
    { "Opencode",        client_cfg_t::OPENCODE,     "~/.config/opencode/opencode.json" },
    { "Kiro",            client_cfg_t::URL,          "~/.kiro/settings/mcp.json" },
    { "Kiro Legacy",     client_cfg_t::URL,          "~/.kiro/mcp_config.json" },
    { "Trae",            client_cfg_t::URL,          "~/.trae/mcp_config.json" },
    { "VS Code",         client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "VS Code Insiders",client_cfg_t::VSCODE,       "%APPDATA%/Code - Insiders/User/settings.json" },
    { "VS Code (mcp.json)", client_cfg_t::VSCODE_JSON, "%APPDATA%/Code/User/mcp.json" },
    { "VS Code Insiders (mcp.json)", client_cfg_t::VSCODE_JSON, "%APPDATA%/Code - Insiders/User/mcp.json" },
};

static bool is_managed_key(const std::string& key)
{
    return key == MCP_NAME ||
           key == "AiDA-Pro-MCP" ||
           key == "aida-pro-mcp" ||
           key == "aida-standalone-mcp" ||
           key == "camoufox-reverse-mcp" ||
           key == "camoufox_reverse_mcp" ||
           key == "camoufox-reverse";
}

static void erase_managed_keys(json& root)
{
    if (!root.is_object())
        return;
    std::vector<std::string> keys;
    for (auto it = root.begin(); it != root.end(); ++it) {
        if (is_managed_key(it.key()))
            keys.push_back(it.key());
    }
    for (const auto& key : keys)
        root.erase(key);
}

static bool write_mcpservers(const std::string& path, const std::string& url, const char* key)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    config["mcpServers"][MCP_NAME] = json::object();
    config["mcpServers"][MCP_NAME]["type"] = "http";
    config["mcpServers"][MCP_NAME][key] = url;
    return write_json_file(path, config);
}

static bool write_opencode(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcp") || !config["mcp"].is_object())
        config["mcp"] = json::object();
    erase_managed_keys(config["mcp"]);
    config["mcp"][MCP_NAME] = {{"type", "remote"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_vscode(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcp") || !config["mcp"].is_object()) config["mcp"] = json::object();
    if (!config["mcp"].contains("servers") || !config["mcp"]["servers"].is_object())
        config["mcp"]["servers"] = json::object();
    erase_managed_keys(config["mcp"]["servers"]);
    config["mcp"]["servers"][MCP_NAME] = {{"type", "http"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_vscode_json(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("servers") || !config["servers"].is_object())
        config["servers"] = json::object();
    erase_managed_keys(config["servers"]);
    config["servers"][MCP_NAME] = {{"type", "http"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_cline(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    json entry;
    entry["type"] = "http";
    entry["url"] = url;
    config["mcpServers"][MCP_NAME] = entry;
    return write_json_file(path, config);
}

static bool write_zed(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("context_servers") || !config["context_servers"].is_object())
        config["context_servers"] = json::object();
    erase_managed_keys(config["context_servers"]);
    config["context_servers"][MCP_NAME] = {{"settings", {{"url", url}}}};
    return write_json_file(path, config);
}

static bool write_codex(const std::string& path, const std::string& url)
{
    std::string content;
    if (std::filesystem::exists(path)) read_file_to_string(path, content);
    auto strip_section = [](std::string& doc, const std::string& marker) {
        size_t pos = doc.find(marker);
        while (pos != std::string::npos) {
            size_t end = doc.find("\n[", pos + marker.size());
            if (end == std::string::npos) end = doc.size(); else end += 1;
            doc.erase(pos, end - pos);
            pos = doc.find(marker);
        }
    };
    strip_section(content, "[mcp_servers.aida-standalone-mcp]");
    strip_section(content, "[mcp_servers.aida-pro-mcp]");
    strip_section(content, "[mcp_servers.AiDA-Pro-MCP]");
    strip_section(content, "[mcp_servers.camoufox-reverse-mcp]");
    strip_section(content, "[mcp_servers.camoufox_reverse_mcp]");
    strip_section(content, "[mcp_servers.camoufox-reverse]");
    strip_section(content, std::string("[mcp_servers.") + MCP_NAME + "]");
    if (!content.empty() && content.back() != '\n') {
        content += "\n";
    }
    content += "\n[mcp_servers." + std::string(MCP_NAME) + "]\nurl = \"" + url + "\"\n";
    return write_string_to_file(path, content);
}

static bool write_claude_code(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    erase_managed_keys(config["mcpServers"]);
    config["mcpServers"][MCP_NAME] = {{"type", "http"}, {"url", url}};
    return write_json_file(path, config);
}

void server_t::write_client_configs() const
{
    if (!mcp_runtime_authorized())
    {
        std::string missing_exports;
        const bool exports_ok = standalone_license::is_arc_loaded()
            && standalone_license::validate_arc_required_exports(missing_exports);
        diag::log_tagged_fmt("mcp_config",
            "write_client_configs_blocked_unauthorized ide=%d valid=%d arc=%d exports=%d missing='%.160s'",
            g_ide_lifecycle_ready.load(std::memory_order_acquire) ? 1 : 0,
            standalone_license::is_valid() ? 1 : 0,
            standalone_license::is_arc_loaded() ? 1 : 0,
            exports_ok ? 1 : 0,
            missing_exports.c_str());
        return;
    }
    if (!_running.load()) {
        diag::log_tagged("mcp_config", "write_client_configs_skipped_not_running");
        return;
    }

    std::string port_str = std::to_string(_port);
    std::string http_url = "http://127.0.0.1:" + port_str + "/mcp";
    std::string sse_url = "http://127.0.0.1:" + port_str + "/sse";
    diag::log_tagged_fmt("mcp_config", "write_client_configs_start url='%s' sse='%s'", http_url.c_str(), sse_url.c_str());

    std::set<std::string> written;
    int ok = 0, skip = 0, fail = 0;

    for (const auto& def : g_clients) {
        try {
            std::string path = expand_path(def.win_path);
            if (path.empty()) {
                diag::log_tagged_fmt("mcp_config", "client_skip_empty name='%s'", def.name);
                ++skip;
                continue;
            }
            if (written.count(path)) {
                diag::log_tagged_fmt("mcp_config", "client_skip_duplicate name='%s' path='%s'", def.name, path.c_str());
                continue;
            }

            if (path.find("globalStorage") != std::string::npos) {
                auto parent = std::filesystem::path(path).parent_path();
                std::error_code ec;
                if (!std::filesystem::is_directory(parent, ec)) {
                    diag::log_tagged_fmt("mcp_config", "client_optional_storage_absent name='%s' path='%s'", def.name, path.c_str());
                    ++skip;
                    continue;
                }
            }

            diag::log_tagged_fmt("mcp_config", "client_write_start name='%s' path='%s'", def.name, path.c_str());
            bool success = false;
            switch (def.format) {
            case client_cfg_t::URL:          success = write_mcpservers(path, http_url, "url"); break;
            case client_cfg_t::SERVERURL:    success = write_mcpservers(path, http_url, "serverUrl"); break;
            case client_cfg_t::OPENCODE:     success = write_opencode(path, http_url); break;
            case client_cfg_t::VSCODE:       success = write_vscode(path, http_url); break;
            case client_cfg_t::VSCODE_JSON:  success = write_vscode_json(path, http_url); break;
            case client_cfg_t::CLINE:        success = write_cline(path, http_url); break;
            case client_cfg_t::ZED:          success = write_zed(path, http_url); break;
            case client_cfg_t::CODEX:        success = write_codex(path, http_url); break;
            case client_cfg_t::CLAUDE_CODE:  success = write_claude_code(path, http_url); break;
            }

            if (success) {
                diag::log_tagged_fmt("mcp_config", "client_write_ok name='%s' path='%s'", def.name, path.c_str());
                written.insert(path);
                ++ok;
            }
            else {
                diag::log_tagged_fmt("mcp_config", "client_write_fail name='%s' path='%s'", def.name, path.c_str());
                ++fail;
            }
        } catch (const std::exception& e) {
            diag::log_tagged_fmt("mcp_config", "client_write_exception name='%s' what='%.180s'", def.name, e.what());
            ++fail;
        } catch (...) {
            diag::log_tagged_fmt("mcp_config", "client_write_exception name='%s' what='<unknown>'", def.name);
            ++fail;
        }
    }
    diag::log_tagged_fmt("mcp_config", "write_client_configs_done ok=%d skip=%d fail=%d", ok, skip, fail);
}


target_scope_t::target_scope_t(target_scope_t&& other) noexcept
    : ok(other.ok),
      swapped(other.swapped),
      resolved(other.resolved),
      prev_active_idx(other.prev_active_idx),
      target_idx(other.target_idx),
      resolved_id(std::move(other.resolved_id)),
      err(std::move(other.err))
{
    other.ok = false;
    other.swapped = false;
    other.resolved = false;
    other.prev_active_idx = static_cast<size_t>(-1);
    other.target_idx = static_cast<size_t>(-1);
}

target_scope_t& target_scope_t::operator=(target_scope_t&& other) noexcept
{
    if (this != &other) {
        ok = other.ok;
        swapped = other.swapped;
        resolved = other.resolved;
        prev_active_idx = other.prev_active_idx;
        target_idx = other.target_idx;
        resolved_id = std::move(other.resolved_id);
        err = std::move(other.err);
        other.ok = false;
        other.swapped = false;
        other.resolved = false;
        other.prev_active_idx = static_cast<size_t>(-1);
        other.target_idx = static_cast<size_t>(-1);
    }
    return *this;
}

target_scope_t::~target_scope_t()
{
    if (!ok) return;
    if (!swapped) return;
    if (prev_active_idx == static_cast<size_t>(-1)) return;
    if (prev_active_idx >= analysis_session::session_count()) return;
    (void)analysis_session::switch_session(prev_active_idx);
    diag::log_tagged_fmt("mcp_standalone",
        "target_scope_restore restored_idx=%llu",
        static_cast<unsigned long long>(prev_active_idx));
}

target_scope_t resolve_target(const json& args, std::string* out_err)
{
    target_scope_t scope;
    scope.ok = true;
    scope.resolved = false;

    if (args.is_null() || !args.is_object()) {
        return scope;
    }

    std::string binary_id;
    if (args.contains("binary_id") && args["binary_id"].is_string()) {
        binary_id = args["binary_id"].get<std::string>();
    } else if (args.contains("session_id") && args["session_id"].is_string()) {
        binary_id = args["session_id"].get<std::string>();
    }

    std::string file_path;
    if (binary_id.empty() && args.contains("file_path") && args["file_path"].is_string()) {
        file_path = args["file_path"].get<std::string>();
    }

    uint32_t target_pid = 0;
    if (binary_id.empty() && file_path.empty()) {
        for (const char* key : {"target_pid", "process_id", "pid"}) {
            if (!args.contains(key)) continue;
            const auto& v = args[key];
            if (v.is_number_unsigned()) {
                target_pid = static_cast<uint32_t>(v.get<uint64_t>());
            } else if (v.is_number_integer()) {
                int64_t s = v.get<int64_t>();
                if (s > 0) target_pid = static_cast<uint32_t>(s);
            } else if (v.is_string()) {
                std::string s = v.get<std::string>();
                if (!s.empty()) {
                    try { target_pid = static_cast<uint32_t>(std::stoul(s, nullptr, 0)); }
                    catch (...) { target_pid = 0; }
                }
            }
            if (target_pid != 0) break;
        }
    }

    size_t resolved_idx = static_cast<size_t>(-1);
    if (!binary_id.empty()) {
        size_t idx = 0;
        if (analysis_session::find_session_by_id(binary_id, &idx)) {
            resolved_idx = idx;
        } else {
            scope.ok = false;
            scope.err = "binary_id '" + binary_id + "' not found in active sessions";
            if (out_err) *out_err = scope.err;
            diag::log_tagged_fmt("mcp_standalone",
                "resolve_target binary_id='%s' not_found", binary_id.c_str());
            return scope;
        }
    } else if (!file_path.empty()) {
        size_t idx = 0;
        if (analysis_session::find_session_by_path(file_path, &idx)) {
            resolved_idx = idx;
        } else {
            scope.ok = false;
            scope.err = "file_path '" + file_path + "' not found in active sessions";
            if (out_err) *out_err = scope.err;
            return scope;
        }
    } else if (target_pid != 0) {
        size_t idx = 0;
        if (analysis_session::find_session_by_pid(target_pid, &idx)) {
            resolved_idx = idx;
        }
    }

    if (resolved_idx == static_cast<size_t>(-1)) {
        return scope;
    }

    size_t cur = analysis_session::active_session_idx();
    scope.prev_active_idx = cur;
    scope.target_idx = resolved_idx;
    scope.resolved = true;

    auto sum = analysis_session::summarize_session_at(resolved_idx);
    scope.resolved_id = sum.id;

    if (cur == resolved_idx) {
        diag::log_tagged_fmt("mcp_standalone",
            "resolve_target id='%s' idx=%llu already_active",
            scope.resolved_id.c_str(),
            static_cast<unsigned long long>(resolved_idx));
        return scope;
    }

    if (!analysis_session::switch_session(resolved_idx)) {
        scope.ok = false;
        scope.err = std::string("switch_session failed: ") + analysis_session::last_error();
        if (out_err) *out_err = scope.err;
        diag::log_tagged_fmt("mcp_standalone",
            "resolve_target switch_failed target_idx=%llu err='%s'",
            static_cast<unsigned long long>(resolved_idx), scope.err.c_str());
        return scope;
    }

    scope.swapped = true;
    diag::log_tagged_fmt("mcp_standalone",
        "resolve_target id='%s' resolved_idx=%llu swapped=1 prev_idx=%llu",
        scope.resolved_id.c_str(),
        static_cast<unsigned long long>(resolved_idx),
        static_cast<unsigned long long>(cur));
    return scope;
}


}
