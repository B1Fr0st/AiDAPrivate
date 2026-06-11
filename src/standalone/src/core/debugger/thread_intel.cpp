#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "thread_intel.hpp"

#include "standalone_driver.hpp"

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
    std::uint64_t module_offset = 0;
};

struct thread_sample_state_t {
    driver_bridge::thread_info_t info{};
    std::vector<rip_sample_t> samples;
    std::uint64_t cpu_start_100ns = 0;
    std::uint64_t cpu_end_100ns = 0;
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

std::uint64_t filetime_to_u64(const FILETIME& ft)
{
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

std::uint64_t query_thread_cpu_time(std::uint32_t tid)
{
    HANDLE h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!h)
        return 0;
    FILETIME create_time{}, exit_time{}, kernel_time{}, user_time{};
    std::uint64_t total = 0;
    if (GetThreadTimes(h, &create_time, &exit_time, &kernel_time, &user_time))
        total = filetime_to_u64(kernel_time) + filetime_to_u64(user_time);
    CloseHandle(h);
    return total;
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

rip_sample_t describe_rip(std::uint64_t rip, const std::vector<driver_bridge::module_info_t>& modules)
{
    rip_sample_t sample;
    sample.rip = rip;
    for (const auto& module : modules) {
        const std::uint64_t end = module.base + module.size;
        if (rip >= module.base && rip < end) {
            sample.module = module.name;
            sample.module_offset = rip - module.base;
            break;
        }
    }
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
    out = describe_rip(ctx.rip, modules);
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

std::string module_hint(const rip_sample_t& sample)
{
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

    double render = 0.0;
    double network = 0.0;
    double audio = 0.0;
    double physics = 0.0;
    double idle = 0.0;
    std::map<std::string, std::uint32_t> module_counts;
    nlohmann::json evidence = nlohmann::json::array();

    for (const auto& sample : t.samples) {
        if (!sample.module.empty())
            ++module_counts[sample.module];
        render += module_role_score(sample.module, render_mods, sizeof(render_mods) / sizeof(render_mods[0]));
        network += module_role_score(sample.module, network_mods, sizeof(network_mods) / sizeof(network_mods[0]));
        audio += module_role_score(sample.module, audio_mods, sizeof(audio_mods) / sizeof(audio_mods[0]));
        physics += module_role_score(sample.module, physics_mods, sizeof(physics_mods) / sizeof(physics_mods[0]));
        idle += module_role_score(sample.module, wait_mods, sizeof(wait_mods) / sizeof(wait_mods[0]));
    }

    const double denom = t.samples.empty() ? 1.0 : static_cast<double>(t.samples.size());
    render /= denom;
    network /= denom;
    audio /= denom;
    physics /= denom;
    idle /= denom;

    if (cpu_percent >= 8.0) {
        render += 0.12;
        evidence.push_back("sustained_cpu_percent=" + std::to_string(cpu_percent));
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

    choose("render", (std::min)(0.9, render), "render_module_rip_samples");
    choose("network", (std::min)(0.9, network), "network_module_rip_samples");
    choose("audio", (std::min)(0.86, audio), "audio_module_rip_samples");
    choose("physics", (std::min)(0.86, physics), "physics_module_rip_samples");
    if (idle > confidence && idle > 0.55) {
        role = "idle_or_wait";
        confidence = (std::min)(0.78, idle);
    }
    if (t.info.tid == lowest_tid && confidence < 0.58) {
        role = "main_or_logic";
        confidence = 0.52 + (cpu_percent >= 3.0 ? 0.08 : 0.0);
    }
    if (role == "worker_or_unknown" && cpu_percent >= 5.0) {
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

    nlohmann::json out;
    out["tid"] = t.info.tid;
    out["role"] = role;
    out["confidence"] = (std::min)(0.95, confidence);
    out["priority"] = t.info.priority;
    out["state"] = state_name(t.info.state);
    out["cpu_percent"] = cpu_percent;
    out["sample_count"] = sample_count;
    out["observed_sample_count"] = t.samples.size();
    out["hot_modules"] = std::move(modules);
    out["evidence"] = std::move(evidence);
    if (!t.samples.empty()) {
        const auto& last = t.samples.back();
        out["last_rip"] = fmt_addr(last.rip);
        out["last_module_hint"] = module_hint(last);
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
        st.cpu_start_100ns = query_thread_cpu_time(th.tid);
        if (th.tid < lowest_tid)
            lowest_tid = th.tid;
        states.push_back(std::move(st));
    }

    const std::uint32_t sample_count = (std::max)(1u, options.sample_ms / options.interval_ms);
    for (std::uint32_t i = 0; i < sample_count; ++i) {
        for (auto& st : states) {
            rip_sample_t sample;
            if (sample_thread_rip(st.info.tid, modules, sample))
                st.samples.push_back(std::move(sample));
        }
        if (i + 1 < sample_count)
            std::this_thread::sleep_for(std::chrono::milliseconds(options.interval_ms));
    }

    for (auto& st : states)
        st.cpu_end_100ns = query_thread_cpu_time(st.info.tid);

    nlohmann::json arr = nlohmann::json::array();
    for (const auto& st : states) {
        const std::uint64_t delta = st.cpu_end_100ns > st.cpu_start_100ns ? st.cpu_end_100ns - st.cpu_start_100ns : 0;
        const double cpu_percent = options.sample_ms ? (static_cast<double>(delta) / (static_cast<double>(options.sample_ms) * 10000.0)) * 100.0 : 0.0;
        arr.push_back(classify_one(st, lowest_tid, cpu_percent, sample_count));
    }

    std::sort(arr.begin(), arr.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
        const double ca = a.value("confidence", 0.0);
        const double cb = b.value("confidence", 0.0);
        if (ca == cb)
            return a.value("cpu_percent", 0.0) > b.value("cpu_percent", 0.0);
        return ca > cb;
    });

    out["process_id"] = pid;
    out["sample_ms"] = options.sample_ms;
    out["interval_ms"] = options.interval_ms;
    out["thread_count"] = threads.size();
    out["threads"] = std::move(arr);
    out["limitations"] = nlohmann::json::array({
        "roles are heuristic and based on bounded RIP samples, module names, thread state, priority, and CPU time deltas",
        "threads blocked in waits may hide their eventual application callback role",
        "render and network confidence improves when sampling catches API module frames"
    });
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
    std::map<std::uint64_t, std::uint32_t> hits;
    std::map<std::uint64_t, rip_sample_t> descriptions;
    std::uint32_t failed_samples = 0;

    for (std::uint32_t i = 0; i < options.samples; ++i) {
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
