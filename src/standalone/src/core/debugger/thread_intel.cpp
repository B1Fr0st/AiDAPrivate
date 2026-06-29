#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "thread_intel.hpp"

#include "../analysis/symbol_store.hpp"
#include "../helpers/diag_log.hpp"
#include "standalone_driver.hpp"
#include "../mcp/mcp_standalone.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

namespace thread_intel {
namespace {

struct rip_sample_t {
    std::uint64_t rip = 0;
    std::string module;
    std::string function_name;
    std::string source;
    std::uint64_t module_offset = 0;
};

struct thread_sample_state_t {
    driver_bridge::thread_info_t info{};
    std::vector<rip_sample_t> samples;
    std::uint64_t cpu_start_100ns = 0;
    std::uint64_t cpu_end_100ns = 0;
    std::uint64_t cycle_start = 0;
    std::uint64_t cycle_end = 0;
    bool cpu_start_available = false;
    bool cpu_end_available = false;
    bool cycle_start_available = false;
    bool cycle_end_available = false;
};

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string fmt_addr(std::uint64_t va)
{
    std::ostringstream os;
    os << "0x" << std::uppercase << std::hex << va;
    return os.str();
}

std::uint64_t filetime_to_100ns(const FILETIME& ft)
{
    return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | static_cast<std::uint64_t>(ft.dwLowDateTime);
}

struct thread_timing_sample_t {
    std::uint64_t cpu_100ns = 0;
    std::uint64_t cycles = 0;
    bool cpu_available = false;
    bool cycles_available = false;
};

thread_timing_sample_t query_thread_timing(std::uint32_t tid)
{
    thread_timing_sample_t sample;
    HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!thread)
        return sample;

    FILETIME create_time{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    if (GetThreadTimes(thread, &create_time, &exit_time, &kernel_time, &user_time)) {
        sample.cpu_100ns = filetime_to_100ns(kernel_time) + filetime_to_100ns(user_time);
        sample.cpu_available = true;
    }

    ULONG64 cycles = 0;
    if (QueryThreadCycleTime(thread, &cycles)) {
        sample.cycles = static_cast<std::uint64_t>(cycles);
        sample.cycles_available = true;
    }

    CloseHandle(thread);
    return sample;
}

std::string state_name(std::uint32_t state)
{
    switch (state) {
    case 0: return "Initialized";
    case 1: return "Ready";
    case 2: return "Running";
    case 3: return "Standby";
    case 4: return "Terminated";
    case 5: return "Waiting";
    case 6: return "Transition";
    default: return "Unknown";
    }
}

bool ensure_process_context(std::uint32_t requested_pid, std::uint32_t& resolved_pid, std::string& error)
{
    resolved_pid = requested_pid ? requested_pid : driver_bridge::attached_pid();
    if (resolved_pid == 0) {
        error = "process_id is required when no process is attached";
        return false;
    }
    if (!driver_bridge::using_kernel_driver()) {
        error = "driver bridge is not connected";
        return false;
    }
    if (driver_bridge::attached_pid() == resolved_pid)
        return true;
    bool already_attached = false;
    for (std::uint32_t pid : driver_bridge::attached_pids()) {
        if (pid == resolved_pid) {
            already_attached = true;
            break;
        }
    }
    if (already_attached) {
        if (!driver_bridge::set_active_pid(resolved_pid)) {
            error = driver_bridge::last_error().empty() ? "failed to set active process" : driver_bridge::last_error();
            return false;
        }
        return true;
    }
    if (driver_bridge::attached_pid() == 0) {
        if (!driver_bridge::attach(resolved_pid)) {
            error = driver_bridge::last_error().empty() ? "failed to attach process" : driver_bridge::last_error();
            return false;
        }
        return true;
    }
    if (!driver_bridge::attach_additional(resolved_pid)) {
        error = driver_bridge::last_error().empty() ? "failed to attach additional process" : driver_bridge::last_error();
        return false;
    }
    if (!driver_bridge::set_active_pid(resolved_pid)) {
        error = driver_bridge::last_error().empty() ? "failed to activate process" : driver_bridge::last_error();
        return false;
    }
    return true;
}

rip_sample_t describe_rip(std::uint64_t rip, const std::vector<driver_bridge::module_info_t>& modules, const char* source)
{
    rip_sample_t sample;
    sample.rip = rip;
    sample.source = source ? source : "context";
    for (const auto& module : modules) {
        const std::uint64_t end = module.base + module.size;
        if (rip >= module.base && rip < end) {
            sample.module = module.name;
            sample.module_offset = rip - module.base;
            break;
        }
    }
    std::string exact = symbol_store::resolve_symbol_exact(rip);
    if (exact.empty())
        exact = symbol_store::resolve_symbol(rip);
    if (!exact.empty())
        sample.function_name = std::move(exact);
    return sample;
}

bool sample_thread_rip(std::uint32_t tid,
                       const std::vector<driver_bridge::module_info_t>& modules,
                       rip_sample_t& out)
{
    driver_bridge::thread_context_t ctx{};
    const bool same_thread = GetCurrentProcessId() == driver_bridge::attached_pid() && tid == GetCurrentThreadId();
    if (!same_thread) {
        std::uint32_t prev = 0;
        const bool suspended = driver_bridge::suspend_thread(tid, &prev);
        bool ok = false;
        if (suspended) {
            ok = driver_bridge::get_thread_context(tid, ctx);
            driver_bridge::resume_thread(tid, nullptr);
        }
        if (!ok)
            return false;
    } else {
        return false;
    }
    out = describe_rip(ctx.rip, modules, "suspended_context");
    return out.rip != 0;
}

double module_role_score(const std::string& module, const char* const* names, std::size_t count)
{
    const std::string lower = lower_copy(module);
    for (std::size_t i = 0; i < count; ++i)
        if (lower.find(names[i]) != std::string::npos)
            return 1.0;
    return 0.0;
}

double text_role_score(const std::string& text, const char* const* names, std::size_t count)
{
    const std::string lower = lower_copy(text);
    double score = 0.0;
    for (std::size_t i = 0; i < count; ++i)
        if (lower.find(names[i]) != std::string::npos)
            score = (std::max)(score, 1.0);
    return score;
}

std::string module_hint(const rip_sample_t& sample)
{
    if (!sample.function_name.empty())
        return sample.function_name;
    if (sample.module.empty())
        return "unknown";
    return sample.module + "+" + fmt_addr(sample.module_offset);
}

nlohmann::json classify_one(const thread_sample_state_t& t,
                            std::uint32_t lowest_tid,
                            double cpu_percent,
                            std::uint32_t sample_count)
{
    static const char* render_mods[] = {"d3d", "dxgi", "vulkan", "nvwgf", "amdvlk", "atidxx", "render"};
    static const char* network_mods[] = {"ws2_32", "mswsock", "winhttp", "wininet", "schannel", "secur32", "libssl", "nss3"};
    static const char* audio_mods[] = {"xaudio", "dsound", "audioses", "mmdevapi", "openal", "fmod", "wwise"};
    static const char* physics_mods[] = {"physx", "havok", "bullet", "chaos", "physics"};
    static const char* wait_mods[] = {"ntdll", "kernelbase", "kernel32"};
    static const char* render_funcs[] = {"present", "swapchain", "render", "draw", "paint", "frame", "d3d", "dxgi", "vulkan", "opengl", "imgui"};
    static const char* network_funcs[] = {"recv", "send", "select", "poll", "socket", "connect", "accept", "http", "tls", "ssl", "websocket", "network"};
    static const char* audio_funcs[] = {"audio", "sound", "voice", "mix", "xaudio", "dsound", "fmod", "wwise", "openal"};
    static const char* physics_funcs[] = {"physics", "simulate", "collision", "rigid", "constraint", "havok", "physx", "bullet", "chaos"};
    static const char* main_funcs[] = {"winmain", "main", "wndproc", "dispatchmessage", "peekmessage", "getmessage", "tick", "update", "logic", "game"};
    static const char* wait_funcs[] = {"waitforsingleobject", "waitformultipleobjects", "ntwait", "sleep", "condition", "futex", "delayexecution"};

    double render = 0.0;
    double network = 0.0;
    double audio = 0.0;
    double physics = 0.0;
    double main_logic = 0.0;
    double idle = 0.0;
    std::map<std::string, std::uint32_t> module_counts;
    std::map<std::string, std::uint32_t> function_counts;
    std::map<std::string, std::uint32_t> source_counts;
    nlohmann::json evidence = nlohmann::json::array();

    for (const auto& sample : t.samples) {
        if (!sample.module.empty())
            ++module_counts[sample.module];
        if (!sample.function_name.empty())
            ++function_counts[sample.function_name];
        if (!sample.source.empty())
            ++source_counts[sample.source];
        render += module_role_score(sample.module, render_mods, sizeof(render_mods) / sizeof(render_mods[0]));
        network += module_role_score(sample.module, network_mods, sizeof(network_mods) / sizeof(network_mods[0]));
        audio += module_role_score(sample.module, audio_mods, sizeof(audio_mods) / sizeof(audio_mods[0]));
        physics += module_role_score(sample.module, physics_mods, sizeof(physics_mods) / sizeof(physics_mods[0]));
        idle += module_role_score(sample.module, wait_mods, sizeof(wait_mods) / sizeof(wait_mods[0]));
        const std::string text = sample.module + " " + sample.function_name;
        render += text_role_score(text, render_funcs, sizeof(render_funcs) / sizeof(render_funcs[0])) * 1.35;
        network += text_role_score(text, network_funcs, sizeof(network_funcs) / sizeof(network_funcs[0])) * 1.35;
        audio += text_role_score(text, audio_funcs, sizeof(audio_funcs) / sizeof(audio_funcs[0])) * 1.35;
        physics += text_role_score(text, physics_funcs, sizeof(physics_funcs) / sizeof(physics_funcs[0])) * 1.35;
        main_logic += text_role_score(text, main_funcs, sizeof(main_funcs) / sizeof(main_funcs[0])) * 1.2;
        idle += text_role_score(text, wait_funcs, sizeof(wait_funcs) / sizeof(wait_funcs[0])) * 1.2;
    }

    const double denom = t.samples.empty() ? 1.0 : static_cast<double>(t.samples.size());
    render /= denom;
    network /= denom;
    audio /= denom;
    physics /= denom;
    main_logic /= denom;
    idle /= denom;

    const std::uint64_t cycle_delta = t.cycle_end > t.cycle_start ? t.cycle_end - t.cycle_start : 0;
    const bool cpu_time_available = t.cpu_start_available && t.cpu_end_available;
    const bool cycle_available = t.cycle_start_available && t.cycle_end_available;
    const bool cycle_active = !cpu_time_available && cycle_available && cycle_delta >= 1000000ull;

    if (cpu_percent >= 8.0) {
        render += 0.12;
        evidence.push_back("sustained_cpu_percent=" + std::to_string(cpu_percent));
    }
    if (cycle_active) {
        main_logic += 0.08;
        evidence.push_back("thread_cycle_delta=" + std::to_string(cycle_delta));
    }
    if (t.info.priority >= 10) {
        render += 0.05;
        evidence.push_back("elevated_priority=" + std::to_string(t.info.priority));
    }
    if (t.info.tid == lowest_tid) {
        evidence.push_back("lowest_tid_candidate");
    }
    if (state_name(t.info.state) == "Waiting" && idle > 0.6)
        evidence.push_back("mostly_waiting_in_system_wait_modules");

    std::string role = "worker_or_unknown";
    double confidence = 0.24;
    auto choose = [&](const std::string& candidate, double score, const std::string& reason) {
        if (score > confidence) {
            role = candidate;
            confidence = score;
            evidence.push_back(reason);
        }
    };

    choose("render", (std::min)(0.9, render), "render_api_or_rip_hints");
    choose("network", (std::min)(0.9, network), "network_api_or_rip_hints");
    choose("audio", (std::min)(0.86, audio), "audio_api_or_rip_hints");
    choose("physics", (std::min)(0.86, physics), "physics_api_or_rip_hints");
    choose("main_or_logic", (std::min)(0.84, main_logic), "main_or_logic_rip_hints");
    if (idle > confidence && idle > 0.55) {
        role = "idle_or_wait";
        confidence = (std::min)(0.78, idle);
        evidence.push_back("wait_function_or_module_rip_samples");
    }
    if (t.info.tid == lowest_tid && confidence < 0.58) {
        role = "main_or_logic";
        confidence = 0.52 + (cpu_percent >= 3.0 ? 0.08 : 0.0);
    }
    if (role == "worker_or_unknown" && (cpu_percent >= 5.0 || cycle_active)) {
        role = "active_worker_or_logic";
        confidence = 0.46;
    }

    nlohmann::json modules = nlohmann::json::array();
    for (const auto& [name, count] : module_counts) {
        nlohmann::json m;
        m["module"] = name;
        m["hits"] = count;
        modules.push_back(std::move(m));
    }
    std::sort(modules.begin(), modules.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
        return a.value("hits", 0u) > b.value("hits", 0u);
    });
    while (modules.size() > 8)
        modules.erase(modules.size() - 1);

    nlohmann::json functions = nlohmann::json::array();
    for (const auto& [name, count] : function_counts) {
        nlohmann::json f;
        f["function"] = name;
        f["hits"] = count;
        functions.push_back(std::move(f));
    }
    std::sort(functions.begin(), functions.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
        return a.value("hits", 0u) > b.value("hits", 0u);
    });
    while (functions.size() > 8)
        functions.erase(functions.size() - 1);

    nlohmann::json sources = nlohmann::json::array();
    for (const auto& [name, count] : source_counts) {
        nlohmann::json s;
        s["source"] = name;
        s["hits"] = count;
        sources.push_back(std::move(s));
    }
    std::sort(sources.begin(), sources.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
        return a.value("hits", 0u) > b.value("hits", 0u);
    });

    nlohmann::json out;
    out["tid"] = t.info.tid;
    out["role"] = role;
    out["confidence"] = (std::min)(0.95, confidence);
    out["priority"] = t.info.priority;
    out["state"] = state_name(t.info.state);
    out["cpu_percent"] = cpu_percent;
    out["cpu_start_100ns"] = t.cpu_start_100ns;
    out["cpu_end_100ns"] = t.cpu_end_100ns;
    out["cpu_delta_100ns"] = t.cpu_end_100ns > t.cpu_start_100ns ? t.cpu_end_100ns - t.cpu_start_100ns : 0;
    out["cpu_measurement_available"] = cpu_time_available;
    out["cycle_start"] = t.cycle_start;
    out["cycle_end"] = t.cycle_end;
    out["cycle_delta"] = cycle_delta;
    out["cycle_measurement_available"] = cycle_available;
    out["sample_count"] = sample_count;
    out["observed_sample_count"] = t.samples.size();
    out["hot_modules"] = std::move(modules);
    out["hot_functions"] = std::move(functions);
    out["sample_sources"] = std::move(sources);
    out["role_scores"] = {
        {"render", render},
        {"network", network},
        {"audio", audio},
        {"physics", physics},
        {"main_or_logic", main_logic},
        {"idle_or_wait", idle}
    };
    out["evidence"] = std::move(evidence);
    if (!t.samples.empty()) {
        const auto& last = t.samples.back();
        out["last_rip"] = fmt_addr(last.rip);
        out["last_module_hint"] = module_hint(last);
        out["last_function_name"] = last.function_name;
        out["last_sample_source"] = last.source;
    } else if (t.info.rip) {
        out["last_rip"] = fmt_addr(t.info.rip);
    }
    return out;
}

}

bool classify_threads(const classify_options_t& input,
                      nlohmann::json& out,
                      std::string& error)
{
    out = nlohmann::json::object();
    error.clear();
    std::uint32_t pid = 0;
    if (!ensure_process_context(input.process_id, pid, error))
        return false;

    classify_options_t options = input;
    if (options.sample_ms == 0)
        options.sample_ms = 2000;
    if (options.sample_ms > 5000)
        options.sample_ms = 5000;
    if (options.interval_ms == 0)
        options.interval_ms = 100;
    if (options.interval_ms > 500)
        options.interval_ms = 500;
    if (options.max_threads == 0)
        options.max_threads = 128;
    if (options.max_threads > 256)
        options.max_threads = 256;

    auto threads = driver_bridge::enumerate_threads_for(pid);
    if (threads.size() > options.max_threads)
        threads.resize(options.max_threads);
    auto modules = driver_bridge::enumerate_modules_for(pid);

    std::uint32_t lowest_tid = 0xffffffffu;
    std::vector<thread_sample_state_t> states;
    states.reserve(threads.size());
    for (const auto& th : threads) {
        thread_sample_state_t st;
        st.info = th;
        const thread_timing_sample_t timing = query_thread_timing(th.tid);
        st.cpu_start_100ns = timing.cpu_100ns;
        st.cycle_start = timing.cycles;
        st.cpu_start_available = timing.cpu_available;
        st.cycle_start_available = timing.cycles_available;
        if (th.rip != 0)
            st.samples.push_back(describe_rip(th.rip, modules, "enumerated_thread"));
        if (th.tid < lowest_tid)
            lowest_tid = th.tid;
        states.push_back(std::move(st));
    }

    const std::uint32_t sample_count = (std::max)(1u, options.sample_ms / options.interval_ms);
    const auto sample_started = std::chrono::steady_clock::now();
    std::uint32_t context_sample_attempts = 0;
    std::uint32_t context_sample_successes = 0;
    for (std::uint32_t i = 0; i < sample_count; ++i) {
        for (auto& st : states) {
            if (mcp_standalone::current_call_cancelled())
                goto sampling_done;
            rip_sample_t sample;
            ++context_sample_attempts;
            if (sample_thread_rip(st.info.tid, modules, sample)) {
                st.samples.push_back(std::move(sample));
                ++context_sample_successes;
            }
        }
        if (i + 1 < sample_count) {
            if (mcp_standalone::current_call_cancelled())
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(options.interval_ms));
        }
    }
    sampling_done:

    const auto sample_elapsed_ms_raw = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - sample_started).count());
    const std::uint64_t sample_elapsed_ms = (std::max<std::uint64_t>)(1, sample_elapsed_ms_raw);

    if (mcp_standalone::current_call_cancelled()) {
        error = "cancelled";
        return false;
    }

    for (auto& st : states) {
        const thread_timing_sample_t timing = query_thread_timing(st.info.tid);
        st.cpu_end_100ns = timing.cpu_100ns;
        st.cycle_end = timing.cycles;
        st.cpu_end_available = timing.cpu_available;
        st.cycle_end_available = timing.cycles_available;
    }

    nlohmann::json arr = nlohmann::json::array();
    std::uint32_t sampled_threads = 0;
    std::uint32_t cpu_time_threads = 0;
    std::uint32_t cycle_time_threads = 0;
    std::uint32_t kernel_only_threads = 0;
    for (const auto& st : states) {
        const bool cpu_time_available = st.cpu_start_available && st.cpu_end_available;
        const bool cycle_time_available = st.cycle_start_available && st.cycle_end_available;
        const std::uint64_t cpu_delta = st.cpu_end_100ns > st.cpu_start_100ns ? st.cpu_end_100ns - st.cpu_start_100ns : 0;
        const double cpu_percent = cpu_time_available ? (static_cast<double>(cpu_delta) / (static_cast<double>(sample_elapsed_ms) * 10000.0)) * 100.0 : 0.0;
        nlohmann::json row = classify_one(st, lowest_tid, cpu_percent, sample_count);
        if (!st.samples.empty())
            ++sampled_threads;
        if (cpu_time_available)
            ++cpu_time_threads;
        if (cycle_time_available)
            ++cycle_time_threads;
        if (!cpu_time_available && !cycle_time_available)
            ++kernel_only_threads;
        row["cpu_percent_available"] = cpu_time_available;
        row["cpu_percent_source"] = cpu_time_available ? "GetThreadTimes" : "kernel_context_only";
        row["kernel_only_capture"] = !cpu_time_available && !cycle_time_available;
        row["timing_enrichment"] = {
            {"cpu_time_status", cpu_time_available ? "captured" : "not_collected"},
            {"cpu_time_source", "GetThreadTimes"},
            {"thread_cycle_status", cycle_time_available ? "captured" : "not_collected"},
            {"thread_cycle_source", "QueryThreadCycleTime"},
            {"optional_user_mode_timing", true}
        };
        row["kernel_evidence"] = {
            {"thread_enumerated_by_driver", true},
            {"initial_rip_from_driver", st.info.rip != 0},
            {"context_sample_count", st.samples.size()},
            {"authoritative", true}
        };
        arr.push_back(std::move(row));
    }

    std::sort(arr.begin(), arr.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
        const double ca = a.value("confidence", 0.0);
        const double cb = b.value("confidence", 0.0);
        if (ca == cb)
            return a.value("cpu_percent", 0.0) > b.value("cpu_percent", 0.0);
        return ca > cb;
    });

    std::map<std::string, std::uint32_t> role_counts;
    std::uint32_t confidence_ge_070 = 0;
    std::uint32_t confidence_ge_050 = 0;
    for (const auto& row : arr) {
        ++role_counts[row.value("role", std::string("worker_or_unknown"))];
        const double confidence = row.value("confidence", 0.0);
        if (confidence >= 0.70)
            ++confidence_ge_070;
        if (confidence >= 0.50)
            ++confidence_ge_050;
    }
    std::ostringstream role_summary;
    bool first_role = true;
    for (const auto& [role, count] : role_counts) {
        if (!first_role)
            role_summary << ",";
        first_role = false;
        role_summary << role << "=" << count;
    }

    out["process_id"] = pid;
    out["sample_ms"] = options.sample_ms;
    out["sample_elapsed_ms"] = sample_elapsed_ms;
    out["interval_ms"] = options.interval_ms;
    out["thread_count"] = threads.size();
    out["kernel_evidence"] = {
        {"authority", "kernel_driver_thread_enumeration_and_context"},
        {"thread_count", threads.size()},
        {"module_count", modules.size()},
        {"context_sample_attempts", context_sample_attempts},
        {"context_sample_successes", context_sample_successes},
        {"context_sample_misses", context_sample_attempts >= context_sample_successes ? context_sample_attempts - context_sample_successes : 0},
        {"sampled_threads", sampled_threads}
    };
    out["timing_enrichment"] = {
        {"optional", true},
        {"cpu_time_source", "GetThreadTimes"},
        {"cycle_time_source", "QueryThreadCycleTime"},
        {"cpu_time_threads", cpu_time_threads},
        {"cycle_time_threads", cycle_time_threads},
        {"kernel_only_threads", kernel_only_threads}
    };
    out["classification_summary"] = {
        {"role_histogram", role_counts},
        {"confidence_ge_070", confidence_ge_070},
        {"confidence_ge_050", confidence_ge_050}
    };
    out["threads"] = std::move(arr);
    out["limitations"] = nlohmann::json::array({
        "roles are heuristic and based on kernel-driver thread enumeration, bounded RIP samples, module names, thread state, priority, and optional timing enrichment",
        "user-mode OpenThread/GetThreadTimes/QueryThreadCycleTime timing is enrichment only and kernel driver evidence remains authoritative",
        "threads blocked in waits may hide their eventual application callback role",
        "render and network confidence improves when sampling catches API module frames"
    });
    diag::log_tagged_fmt("thread_intel",
        "thread_classify_summary pid=%u enumerated=%zu modules=%zu sampled_threads=%u context_attempts=%u context_successes=%u context_misses=%u cpu_time_threads=%u cycle_time_threads=%u kernel_only_threads=%u confidence_ge_070=%u confidence_ge_050=%u roles=%s",
        pid,
        threads.size(),
        modules.size(),
        sampled_threads,
        context_sample_attempts,
        context_sample_successes,
        context_sample_attempts >= context_sample_successes ? context_sample_attempts - context_sample_successes : 0,
        cpu_time_threads,
        cycle_time_threads,
        kernel_only_threads,
        confidence_ge_070,
        confidence_ge_050,
        role_summary.str().c_str());
    return true;
}

bool watch_rip(const watch_options_t& input,
               nlohmann::json& out,
               std::string& error)
{
    out = nlohmann::json::object();
    error.clear();
    if (input.tid == 0) {
        error = "tid is required";
        return false;
    }

    std::uint32_t pid = 0;
    if (!ensure_process_context(input.process_id, pid, error))
        return false;

    watch_options_t options = input;
    if (options.samples == 0)
        options.samples = 50;
    if (options.samples > 500)
        options.samples = 500;
    if (options.interval_ms == 0)
        options.interval_ms = 20;
    if (options.interval_ms > 1000)
        options.interval_ms = 1000;

    auto threads = driver_bridge::enumerate_threads_for(pid);
    auto owner = std::find_if(threads.begin(), threads.end(), [&](const driver_bridge::thread_info_t& th) {
        return th.tid == options.tid;
    });
    if (owner == threads.end()) {
        error = "tid does not belong to resolved process";
        return false;
    }
    if (owner->owner_pid != 0 && owner->owner_pid != pid) {
        error = "tid owner does not match resolved process";
        return false;
    }

    auto modules = driver_bridge::enumerate_modules_for(pid);
    if (mcp_standalone::current_call_cancelled()) {
        error = "cancelled";
        return false;
    }
    std::map<std::uint64_t, std::uint32_t> hits;
    std::map<std::uint64_t, rip_sample_t> descriptions;
    std::uint32_t failed_samples = 0;

    for (std::uint32_t i = 0; i < options.samples; ++i) {
        if (mcp_standalone::current_call_cancelled())
            break;
        rip_sample_t sample;
        if (sample_thread_rip(options.tid, modules, sample)) {
            ++hits[sample.rip];
            descriptions[sample.rip] = std::move(sample);
        } else {
            ++failed_samples;
        }
        if (i + 1 < options.samples)
            std::this_thread::sleep_for(std::chrono::milliseconds(options.interval_ms));
    }

    std::vector<std::pair<std::uint64_t, std::uint32_t>> sorted(hits.begin(), hits.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        if (a.second == b.second)
            return a.first < b.first;
        return a.second > b.second;
    });

    nlohmann::json arr = nlohmann::json::array();
    for (const auto& [rip, count] : sorted) {
        if (arr.size() >= 64)
            break;
        const auto& d = descriptions[rip];
        nlohmann::json row;
        row["va"] = fmt_addr(rip);
        row["hit_count"] = count;
        row["hit_ratio"] = options.samples ? static_cast<double>(count) / static_cast<double>(options.samples) : 0.0;
        row["module"] = d.module;
        row["module_offset"] = fmt_addr(d.module_offset);
        row["function_name_hint"] = module_hint(d);
        row["evidence"] = nlohmann::json::array({"sampled_thread_rip"});
        arr.push_back(std::move(row));
    }

    out["process_id"] = pid;
    out["thread_owner_pid"] = owner->owner_pid ? owner->owner_pid : pid;
    out["tid"] = options.tid;
    out["samples_requested"] = options.samples;
    out["failed_samples"] = failed_samples;
    out["interval_ms"] = options.interval_ms;
    out["hot_paths"] = std::move(arr);
    out["unique_rips"] = hits.size();
    out["confidence"] = hits.empty() ? 0.0 : (std::min)(0.82, 0.4 + 0.04 * static_cast<double>((std::min)(hits.size(), std::size_t(6))));
    return true;
}

}
