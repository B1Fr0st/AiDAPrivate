#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "thread_intel.hpp"
#include "obfuscation.hpp"
#include "helpers/diag_log.hpp"

#include <cstdint>
#include <string>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace thread_intel_tools {
namespace {

std::uint32_t process_id_from_params(const json& params)
{
    if (params.contains("process_id") && params["process_id"].is_number()) {
        const auto v = params["process_id"].get<std::int64_t>();
        if (v > 0 && v <= 0xffffffffLL)
            return static_cast<std::uint32_t>(v);
    }
    if (params.contains("pid") && params["pid"].is_number()) {
        const auto v = params["pid"].get<std::int64_t>();
        if (v > 0 && v <= 0xffffffffLL)
            return static_cast<std::uint32_t>(v);
    }
    return 0;
}

tool_result_t handle_thread_classify(const json& raw_params)
{
    const ULONGLONG classify_handler_t0 = GetTickCount64();
    const DWORD classify_caller_pid = GetCurrentProcessId();
    const DWORD classify_caller_tid = GetCurrentThreadId();
    const json params = compat_action_payload(raw_params);
    thread_intel::classify_options_t options;
    options.process_id = process_id_from_params(params);
    double sample_sec = params.value("sample_sec", 2.0);
    if (sample_sec < 0.1)
        sample_sec = 0.1;
    if (sample_sec > 5.0)
        sample_sec = 5.0;
    options.sample_ms = static_cast<std::uint32_t>(sample_sec * 1000.0);
    options.interval_ms = params.value("interval_ms", 100u);
    options.max_threads = params.value("max_threads", 128u);

    diag::log_tagged_fmt("thread_intel",
        "thread_classify_phase phase=handler_enter pid=%u caller_pid=%lu caller_tid=%lu sample_ms=%u interval_ms=%u max_threads=%u elapsed_ms=0",
        options.process_id,
        static_cast<unsigned long>(classify_caller_pid),
        static_cast<unsigned long>(classify_caller_tid),
        options.sample_ms,
        options.interval_ms,
        options.max_threads);

    json result;
    std::string error;
    const ULONGLONG classify_call_t0 = GetTickCount64();
    SetLastError(0);
    const bool classify_ok = thread_intel::classify_threads(options, result, error);
    const DWORD classify_gle = classify_ok ? 0 : GetLastError();
    const ULONGLONG classify_call_elapsed_ms = GetTickCount64() - classify_call_t0;
    diag::log_tagged_fmt("thread_intel",
        "thread_classify_phase phase=handler_exit pid=%u caller_pid=%lu caller_tid=%lu ok=%d gle=%lu classify_elapsed_ms=%llu total_elapsed_ms=%llu error=%s",
        options.process_id,
        static_cast<unsigned long>(classify_caller_pid),
        static_cast<unsigned long>(classify_caller_tid),
        classify_ok ? 1 : 0,
        static_cast<unsigned long>(classify_gle),
        static_cast<unsigned long long>(classify_call_elapsed_ms),
        static_cast<unsigned long long>(GetTickCount64() - classify_handler_t0),
        error.empty() ? "<empty>" : error.c_str());
    if (!classify_ok)
        return tool_result_t::error(error.empty() ? OBFSTR("thread classification failed") : error);
    if (options.process_id)
        result["process_id_hex"] = sa_format_address(options.process_id);
    return tool_result_t::ok(OBFSTR("Thread roles classified with heuristic evidence."), result);
}

tool_result_t handle_thread_watch_rip(const json& raw_params)
{
    const ULONGLONG handler_started_ms = GetTickCount64();
    const json params = compat_action_payload(raw_params);
    if (!params.contains("tid") || !params["tid"].is_number())
        return tool_result_t::error(OBFSTR("'tid' is required."));

    thread_intel::watch_options_t options;
    const auto tid_value = params["tid"].get<std::int64_t>();
    if (tid_value <= 0 || tid_value > 0xffffffffLL)
        return tool_result_t::error(OBFSTR("Invalid tid."));
    options.tid = static_cast<std::uint32_t>(tid_value);
    options.process_id = process_id_from_params(params);
    options.samples = params.value("samples", 50u);
    options.interval_ms = params.value("interval_ms", 20u);

    diag::log_tagged_fmt("thread_intel",
        "watch_rip_phase phase=handler_enter tid=%u pid=%u samples=%u interval_ms=%u caller_pid=%lu caller_tid=%lu elapsed_ms=0",
        options.tid,
        options.process_id,
        options.samples,
        options.interval_ms,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    json result;
    std::string error;
    const ULONGLONG watch_started_ms = GetTickCount64();
    SetLastError(0);
    const bool watch_ok = thread_intel::watch_rip(options, result, error);
    const DWORD watch_gle = watch_ok ? 0 : GetLastError();
    const ULONGLONG watch_elapsed_ms = GetTickCount64() - watch_started_ms;
    diag::log_tagged_fmt("thread_intel",
        "watch_rip_phase phase=handler_exit tid=%u pid=%u samples=%u interval_ms=%u ok=%d gle=%lu caller_pid=%lu caller_tid=%lu watch_elapsed_ms=%llu total_elapsed_ms=%llu error=%s",
        options.tid,
        options.process_id,
        options.samples,
        options.interval_ms,
        watch_ok ? 1 : 0,
        static_cast<unsigned long>(watch_gle),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(watch_elapsed_ms),
        static_cast<unsigned long long>(GetTickCount64() - handler_started_ms),
        error.empty() ? "<empty>" : error.c_str());
    if (!watch_ok)
        return tool_result_t::error(error.empty() ? OBFSTR("thread RIP watch failed") : error);
    result["tid_hex"] = sa_format_address(options.tid);
    return tool_result_t::ok(OBFSTR("Thread RIP hot-path profile sampled."), result);
}

}

void register_thread_intel_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged("thread_intel", "register_thread_intel_tools entry");

    register_compat(srv, {
        OBFSTR("thread_classify"), OBFSTR("thread_intel"),
        OBFSTR("Heuristically classify target threads as render, network, audio, physics, main/logic, wait, or worker using bounded RIP samples, modules, priority, state, and CPU-time deltas."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Target process ID. Defaults to attached process."), false},
         {OBFSTR("sample_sec"), OBFSTR("number"), OBFSTR("Sampling duration in seconds, default 2, max 5."), false},
         {OBFSTR("interval_ms"), OBFSTR("number"), OBFSTR("Sampling interval, default 100, max 500."), false},
         {OBFSTR("max_threads"), OBFSTR("number"), OBFSTR("Thread cap, default 128, max 256."), false}},
        handle_thread_classify, false});

    register_compat(srv, {
        OBFSTR("thread_watch_rip"), OBFSTR("thread_intel"),
        OBFSTR("Repeatedly sample a thread RIP and return hot VA buckets with module/function hints and hit ratios."),
        {{OBFSTR("tid"), OBFSTR("number"), OBFSTR("Thread ID to sample."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Target process ID. Defaults to attached process; TID ownership is verified before sampling."), false},
         {OBFSTR("samples"), OBFSTR("number"), OBFSTR("Sample count, default 50, max 500."), false},
         {OBFSTR("interval_ms"), OBFSTR("number"), OBFSTR("Interval between samples, default 20, max 1000."), false}},
        handle_thread_watch_rip, false});
}

}
