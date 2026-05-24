

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "debugger_engine.hpp"
#include "comm.h"
#include "obfuscation.hpp"
#include "pro.h"
#include "../runtime/standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "xref_engine.hpp"
#include "cfg_view.hpp"
#include "seh_view.hpp"
#include "module_view.hpp"
#include "pe_parser.hpp"
#include "code_patcher.hpp"
#include "stealth_engine.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace debugger_tools
{


static bool is_process_alive(std::uint32_t pid)
{
    if (pid == 0)
        return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return false;
    DWORD exit_code = 0;
    const bool ok = GetExitCodeProcess(h, &exit_code) != FALSE;
    CloseHandle(h);
    return ok && exit_code == STILL_ACTIVE;
}

static std::optional<tool_result_t> ensure_attached(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "ensure_attached: entry");
    if (!device->is_connected()) {
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: driver not connected");
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    }

    std::uint32_t requested_pid = 0;
    for (const char* key : {"target_pid", "process_id", "pid"})
    {
        if (!params.contains(key))
            continue;
        const auto& v = params[key];
        if (v.is_number_unsigned())
            requested_pid = static_cast<std::uint32_t>(v.get<std::uint64_t>());
        else if (v.is_number_integer())
            requested_pid = static_cast<std::uint32_t>(v.get<std::int64_t>());
        else if (v.is_string())
        {
            auto addr = sa_parse_address(v.get<std::string>());
            if (addr) requested_pid = static_cast<std::uint32_t>(*addr);
        }
        if (requested_pid != 0)
            break;
    }

    const std::uint32_t current_pid = driver_bridge::attached_pid();
    if (requested_pid != 0 && requested_pid != current_pid)
    {
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: switching active pid from %u to %u", current_pid, requested_pid);
        if (!is_process_alive(requested_pid)) {
            diag::log_tagged_fmt("dbg_tools", "ensure_attached: target_pid %u not alive", requested_pid);
            return tool_result_t::error(OBFSTR("target_pid ") + std::to_string(requested_pid) + OBFSTR(" is not alive."));
        }

        const auto attached = driver_bridge::attached_pids();
        bool in_map = false;
        for (auto p : attached) { if (p == requested_pid) { in_map = true; break; } }
        if (!in_map)
        {
            diag::log_tagged_fmt("dbg_tools", "ensure_attached: calling attach_additional for pid %u", requested_pid);
            if (!driver_bridge::attach_additional(requested_pid))
            {
                diag::log_tagged_fmt("dbg_tools", "ensure_attached: attach_additional failed for pid %u", requested_pid);
                return tool_result_t::error(
                    OBFSTR("attach_additional failed for target_pid ") + std::to_string(requested_pid) +
                    OBFSTR(": ") + driver_bridge::last_error());
            }
        }

        if (!driver_bridge::set_active_pid(requested_pid)) {
            diag::log_tagged_fmt("dbg_tools", "ensure_attached: set_active_pid failed for pid %u", requested_pid);
            return tool_result_t::error(
                OBFSTR("set_active_pid failed for target_pid ") + std::to_string(requested_pid) +
                OBFSTR(": ") + driver_bridge::last_error());
        }

        if (device->get_dtb() == 0)
        {
            device->solve_dtb();
            if (device->get_dtb() == 0) {
                diag::log_tagged_fmt("dbg_tools", "ensure_attached: DTB solve failed for pid %u", requested_pid);
                return tool_result_t::error(
                    OBFSTR("Failed to solve DTB for target_pid ") +
                    std::to_string(requested_pid) + OBFSTR("."));
            }
        }
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: switched to pid %u ok", requested_pid);
    }

    if (driver_bridge::attached_pid() == 0) {
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: not attached");
        return tool_result_t::error(OBFSTR("Not attached. Call driver_attach first or pass target_pid."));
    }

    if (!is_process_alive(driver_bridge::attached_pid()))
    {
        const std::uint32_t dead_pid = driver_bridge::attached_pid();
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: attached pid %u is dead", dead_pid);
        device->clear_process_context();
        return tool_result_t::error(
            OBFSTR("Attached process PID ") + std::to_string(dead_pid) +
            OBFSTR(" is no longer alive. Call driver_attach again."));
    }

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0) {
            diag::log_tagged_fmt("dbg_tools", "ensure_attached: DTB solve failed for attached pid");
            return tool_result_t::error(OBFSTR("Failed to solve DTB for the attached process."));
        }
    }
    diag::log_tagged_fmt("dbg_tools", "ensure_attached: ok pid=%u", driver_bridge::attached_pid());
    return std::nullopt;
}

static std::optional<std::uint32_t> parse_tid(const json& params)
{
    if (!params.contains("tid")) {
        diag::log_tagged_fmt("dbg_tools", "parse_tid: no tid param");
        return std::nullopt;
    }
    const auto& v = params["tid"];
    std::uint32_t tid = 0;
    if (v.is_number_unsigned())
        tid = static_cast<std::uint32_t>(v.get<std::uint64_t>());
    else if (v.is_number_integer())
        tid = static_cast<std::uint32_t>(v.get<std::int64_t>());
    else if (v.is_string())
    {
        auto addr = sa_parse_address(v.get<std::string>());
        if (addr) tid = static_cast<std::uint32_t>(*addr);
    }
    if (tid != 0)
        diag::log_tagged_fmt("dbg_tools", "parse_tid: resolved tid=%u", tid);
    else
        diag::log_tagged_fmt("dbg_tools", "parse_tid: failed to parse tid");
    return (tid != 0) ? std::optional<std::uint32_t>{tid} : std::nullopt;
}

static int int_param_clamped(const json& params, const char* key, int fallback, int lo, int hi)
{
    int value = fallback;
    if (params.contains(key)) {
        const auto& v = params[key];
        if (v.is_number_unsigned()) {
            auto raw = v.get<std::uint64_t>();
            value = raw > static_cast<std::uint64_t>(hi) ? hi : static_cast<int>(raw);
        } else if (v.is_number_integer()) {
            auto raw = v.get<std::int64_t>();
            if (raw < static_cast<std::int64_t>(lo))
                value = lo;
            else if (raw > static_cast<std::int64_t>(hi))
                value = hi;
            else
                value = static_cast<int>(raw);
        }
        else if (v.is_string()) {
            auto parsed = sa_parse_address(v.get<std::string>());
            if (parsed)
                value = static_cast<int>(*parsed);
        }
    }
    return std::clamp(value, lo, hi);
}

static bool deadline_expired(const std::chrono::steady_clock::time_point& deadline)
{
    return std::chrono::steady_clock::now() >= deadline || mcp_standalone::current_call_cancelled();
}


static tool_result_t dbg_set_breakpoint(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_set_breakpoint: entry");
    if (auto err = ensure_attached(params))
        return *err;

    if (!params.contains("address") || !params["address"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_set_breakpoint: missing address param");
        return tool_result_t::error(OBFSTR("'address' (hex string) is required."));
    }

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0) {
        diag::log_tagged_fmt("dbg_tools", "dbg_set_breakpoint: invalid address");
        return tool_result_t::error(OBFSTR("Invalid address."));
    }
    const std::uint64_t addr = *addr_opt;

    diag::log_tagged_fmt("dbg_tools", "dbg_set_breakpoint: adding SW BP at 0x%llX", (unsigned long long)addr);
    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software);
    if (idx < 0) {
        const auto& err_msg = debugger_engine::last_error();
        diag::log_tagged_fmt("dbg_tools", "dbg_set_breakpoint: add_breakpoint failed at 0x%llX: %s", (unsigned long long)addr, err_msg.c_str());
        std::string detail = err_msg.empty() ? std::string() : (OBFSTR(": ") + err_msg);
        return tool_result_t::error(
            OBFSTR("Failed to add breakpoint at ") + sa_format_address(addr) + detail);
    }

    std::uint8_t original = 0;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
        if (idx < static_cast<int>(debugger_engine::g_state.breakpoints.size()))
            original = debugger_engine::g_state.breakpoints[idx].original_byte;
    }

    diag::log_tagged_fmt("dbg_tools", "dbg_set_breakpoint: SW BP set at 0x%llX idx=%d original_byte=0x%02X", (unsigned long long)addr, idx, original);
    json result;
    result["address"]       = sa_format_address(addr);
    result["original_byte"] = sa_format_address(static_cast<uint64_t>(original));
    result["index"]         = idx;
    return tool_result_t::ok(
        OBFSTR("Software breakpoint set at ") + sa_format_address(addr), result);
}

static tool_result_t dbg_remove_breakpoint(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_remove_breakpoint: entry");
    if (auto err = ensure_attached(params))
        return *err;

    if (!params.contains("address") || !params["address"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_remove_breakpoint: missing address param");
        return tool_result_t::error(OBFSTR("'address' (hex string) is required."));
    }

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0) {
        diag::log_tagged_fmt("dbg_tools", "dbg_remove_breakpoint: invalid address");
        return tool_result_t::error(OBFSTR("Invalid address."));
    }
    const std::uint64_t addr = *addr_opt;

    int target_idx = -1;
    std::uint8_t original = 0;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
        for (size_t i = 0; i < debugger_engine::g_state.breakpoints.size(); ++i) {
            auto& bp = debugger_engine::g_state.breakpoints[i];
            if (bp.address == addr && bp.type == debugger_engine::bp_type_t::software) {
                target_idx = static_cast<int>(i);
                original = bp.original_byte;
                break;
            }
        }
    }

    if (target_idx < 0) {
        diag::log_tagged_fmt("dbg_tools", "dbg_remove_breakpoint: no BP at 0x%llX", (unsigned long long)addr);
        return tool_result_t::error(
            OBFSTR("No active breakpoint found at ") + sa_format_address(addr));
    }

    diag::log_tagged_fmt("dbg_tools", "dbg_remove_breakpoint: removing BP at 0x%llX idx=%d", (unsigned long long)addr, target_idx);
    if (!debugger_engine::remove_breakpoint(target_idx)) {
        const auto& err_msg = debugger_engine::last_error();
        diag::log_tagged_fmt("dbg_tools", "dbg_remove_breakpoint: remove_breakpoint failed: %s", err_msg.c_str());
        std::string detail = err_msg.empty() ? std::string() : (OBFSTR(": ") + err_msg);
        return tool_result_t::error(
            OBFSTR("Failed to remove breakpoint at ") + sa_format_address(addr) + detail);
    }

    diag::log_tagged_fmt("dbg_tools", "dbg_remove_breakpoint: BP removed at 0x%llX restored_byte=0x%02X", (unsigned long long)addr, original);
    json result;
    result["address"]       = sa_format_address(addr);
    result["restored_byte"] = sa_format_address(static_cast<uint64_t>(original));
    return tool_result_t::ok(
        OBFSTR("Breakpoint removed at ") + sa_format_address(addr), result);
}

static tool_result_t dbg_list_breakpoints(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_list_breakpoints: entry");
    (void)params;

    std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);

    json arr = json::array();
    int active_count = 0;
    for (std::size_t i = 0; i < debugger_engine::g_state.breakpoints.size(); ++i)
    {
        const auto& bp = debugger_engine::g_state.breakpoints[i];
        if (bp.state == debugger_engine::bp_state_t::disabled)
            continue;
        json entry;
        entry["index"]         = static_cast<int>(i);
        entry["address"]       = sa_format_address(bp.address);
        entry["original_byte"] = sa_format_address(static_cast<uint64_t>(bp.original_byte));
        entry["type"]          = static_cast<int>(bp.type);
        entry["state"]         = static_cast<int>(bp.state);
        entry["hit_count"]     = bp.hit_count;
        if (!bp.name.empty()) entry["name"] = bp.name;
        if (!bp.condition.empty()) entry["condition"] = bp.condition;
        arr.push_back(entry);
        ++active_count;
    }

    diag::log_tagged_fmt("dbg_tools", "dbg_list_breakpoints: found %d active breakpoints", active_count);
    json result;
    result["active_count"] = active_count;
    result["breakpoints"]  = arr;
    return tool_result_t::ok(
        std::to_string(active_count) + OBFSTR(" active breakpoint(s)"), result);
}


static tool_result_t dbg_get_callstack(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_get_callstack: entry");
    if (auto err = ensure_attached(params))
        return *err;

    auto tid_opt = parse_tid(params);
    if (!tid_opt) {
        diag::log_tagged_fmt("dbg_tools", "dbg_get_callstack: missing tid param");
        return tool_result_t::error(
            OBFSTR("'tid' (thread ID) is required."));
    }
    const std::uint32_t tid = *tid_opt;

    int max_depth = 64;
    if (params.contains("max_depth") && params["max_depth"].is_number())
        max_depth = std::clamp(params["max_depth"].get<int>(), 1, 256);

    diag::log_tagged_fmt("dbg_tools", "dbg_get_callstack: tid=%u max_depth=%d", tid, max_depth);

    std::uint32_t prev_count = 0;
    const bool did_suspend = device->suspend_thread(tid, &prev_count);
    diag::log_tagged_fmt("dbg_tools", "dbg_get_callstack: suspend_thread did_suspend=%d", (int)did_suspend);

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
    {
        diag::log_tagged_fmt("dbg_tools", "dbg_get_callstack: get_thread_context failed for tid=%u", tid);
        if (did_suspend) device->resume_thread(tid);
        return tool_result_t::error(
            OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));
    }
    diag::log_tagged_fmt("dbg_tools", "dbg_get_callstack: thread context RIP=0x%llX RSP=0x%llX RBP=0x%llX", (unsigned long long)ctx.rip, (unsigned long long)ctx.rsp, (unsigned long long)ctx.rbp);

    json frames = json::array();


    {
        json f;
        f["depth"]   = 0;
        f["rip"]     = sa_format_address(static_cast<uint64_t>(ctx.rip));
        f["rsp"]     = sa_format_address(static_cast<uint64_t>(ctx.rsp));
        f["rbp"]     = sa_format_address(static_cast<uint64_t>(ctx.rbp));


        uint8_t code[16] = {};
        if (device->read_raw(ctx.rip, code, sizeof(code)) >= 1)
        {
            AsmInstr ins = zydis_decode_one(code, 16, ctx.rip);
            f["instruction"] = std::string(ins.mnem) + " " + std::string(ins.ops);
        }
        frames.push_back(f);
    }


    std::uint64_t rbp = ctx.rbp;
    std::uint64_t rsp = ctx.rsp;


    const bool rbp_looks_valid =
        rbp > 0x10000 && rbp < 0x7FFFFFFFFFFF0000ULL &&
        rbp > rsp && (rbp - rsp) < 0x100000;

    if (rbp_looks_valid)
    {

        for (int depth = 1; depth < max_depth; ++depth)
        {

            if (rbp == 0 || rbp < 0x10000 || rbp > 0x7FFFFFFFFFFF0000ULL)
                break;


            std::uint64_t saved_rbp = 0;
            std::uint64_t ret_addr  = 0;
            if (device->read_raw(rbp, &saved_rbp, 8) < 8)
                break;
            if (device->read_raw(rbp + 8, &ret_addr, 8) < 8)
                break;


            if (ret_addr == 0 || ret_addr < 0x10000)
                break;

            json f;
            f["depth"]      = depth;
            f["rip"]        = sa_format_address(ret_addr);
            f["rbp"]        = sa_format_address(saved_rbp);
            f["frame_addr"] = sa_format_address(rbp);


            uint8_t code[16] = {};
            if (device->read_raw(ret_addr, code, sizeof(code)) >= 1)
            {
                AsmInstr ins = zydis_decode_one(code, 16, ret_addr);
                f["instruction"] = std::string(ins.mnem) + " " + std::string(ins.ops);
            }

            frames.push_back(f);


            if (saved_rbp == rbp || saved_rbp <= rbp)
                break;
            rbp = saved_rbp;
        }
    }
    else
    {


        constexpr std::size_t SCAN_SIZE = 0x800;
        std::vector<std::uint8_t> stack_data(SCAN_SIZE);
        std::size_t read = device->read_raw(rsp, stack_data.data(), SCAN_SIZE);
        int depth = 1;

        for (std::size_t off = 0; off + 8 <= read && depth < max_depth; off += 8)
        {
            std::uint64_t candidate = 0;
            std::memcpy(&candidate, stack_data.data() + off, 8);


            if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF0000ULL)
                continue;


            voyager::device_t::memory_region_info region{};
            if (!device->query_memory(candidate, region))
                continue;
            if (region.state != 0x1000)
                continue;
            if (!(region.protect & 0xF0))
                continue;


            uint8_t code[16] = {};
            if (device->read_raw(candidate, code, sizeof(code)) < 1)
                continue;
            AsmInstr ins = zydis_decode_one(code, 16, candidate);

            if (ins.len <= 0)
                continue;

            json f;
            f["depth"]        = depth;
            f["rip"]          = sa_format_address(candidate);
            f["stack_offset"] = sa_format_address(rsp + off);
            f["instruction"]  = std::string(ins.mnem) + " " + std::string(ins.ops);
            f["method"]       = "stack_scan";
            frames.push_back(f);
            ++depth;
        }
    }


    if (did_suspend)
        device->resume_thread(tid);

    diag::log_tagged_fmt("dbg_tools", "dbg_get_callstack: tid=%u method=%s frames=%zu", tid, rbp_looks_valid ? "rbp_chain" : "stack_scan", frames.size());
    json result;
    result["tid"]         = tid;
    result["frame_count"] = static_cast<int>(frames.size());
    result["method"]      = rbp_looks_valid ? "rbp_chain" : "stack_scan";
    result["frames"]      = frames;
    return tool_result_t::ok(
        OBFSTR("Call stack for TID ") + std::to_string(tid) +
        OBFSTR(": ") + std::to_string(frames.size()) + OBFSTR(" frame(s)"),
        result);
}


struct memory_snapshot_region
{
    std::uint64_t             address = 0;
    std::vector<std::uint8_t> data;
};

struct execution_snapshot
{
    std::string                          name;
    std::uint32_t                        tid = 0;
    voyager::device_t::thread_context    ctx{};
    std::vector<memory_snapshot_region>  memory;
    std::chrono::steady_clock::time_point timestamp;
};

static std::mutex                                   s_snap_mutex;
static std::map<std::string, execution_snapshot>    s_snapshots;

static tool_result_t dbg_snapshot_state(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: entry");
    if (auto err = ensure_attached(params))
        return *err;

    auto tid_opt = parse_tid(params);
    if (!tid_opt) {
        diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: missing tid param");
        return tool_result_t::error(OBFSTR("'tid' (thread ID) is required."));
    }
    const std::uint32_t tid = *tid_opt;

    std::string snap_name = "default";
    if (params.contains("name") && params["name"].is_string())
        snap_name = params["name"].get<std::string>();
    if (snap_name.empty()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: empty snapshot name");
        return tool_result_t::error(OBFSTR("Snapshot name cannot be empty."));
    }
    diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: capturing snapshot '%s' tid=%u", snap_name.c_str(), tid);


    std::uint32_t prev_count = 0;
    const bool did_suspend = device->suspend_thread(tid, &prev_count);

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
    {
        if (did_suspend) device->resume_thread(tid);
        return tool_result_t::error(
            OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));
    }

    execution_snapshot snap;
    snap.name      = snap_name;
    snap.tid       = tid;
    snap.ctx       = ctx;
    snap.timestamp = std::chrono::steady_clock::now();


    if (params.contains("memory_regions") && params["memory_regions"].is_array())
    {
        for (const auto& region : params["memory_regions"])
        {
            if (!region.contains("address") || !region["address"].is_string())
                continue;
            auto addr = sa_parse_address(region["address"].get<std::string>());
            if (!addr || *addr == 0)
                continue;

            std::size_t size = 256;
            if (region.contains("size") && region["size"].is_number())
                size = static_cast<std::size_t>(
                    std::clamp(region["size"].get<int>(), 1, 65536));

            memory_snapshot_region mem;
            mem.address = *addr;
            mem.data.resize(size);
            std::size_t read = device->read_raw(*addr, mem.data.data(), size);
            mem.data.resize(read);
            snap.memory.push_back(std::move(mem));
        }
    }

    if (did_suspend)
        device->resume_thread(tid);


    json result;
    result["name"]           = snap_name;
    result["tid"]            = tid;
    result["rip"]            = sa_format_address(static_cast<uint64_t>(ctx.rip));
    result["rsp"]            = sa_format_address(static_cast<uint64_t>(ctx.rsp));
    result["memory_regions"] = static_cast<int>(snap.memory.size());


    {
        std::lock_guard<std::mutex> lock(s_snap_mutex);
        s_snapshots[snap_name] = std::move(snap);
    }

    diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: snapshot '%s' captured tid=%u RIP=0x%llX memory_regions=%zu", snap_name.c_str(), tid, (unsigned long long)ctx.rip, snap.memory.size());
    return tool_result_t::ok(
        OBFSTR("Snapshot '") + snap_name + OBFSTR("' captured"), result);
}

static tool_result_t dbg_compare_snapshots(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: entry");
    if (!params.contains("snapshot_a") || !params["snapshot_a"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: missing snapshot_a");
        return tool_result_t::error(OBFSTR("'snapshot_a' name is required."));
    }
    if (!params.contains("snapshot_b") || !params["snapshot_b"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: missing snapshot_b");
        return tool_result_t::error(OBFSTR("'snapshot_b' name is required."));
    }

    const std::string name_a = params["snapshot_a"].get<std::string>();
    const std::string name_b = params["snapshot_b"].get<std::string>();
    diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: comparing '%s' vs '%s'", name_a.c_str(), name_b.c_str());

    std::lock_guard<std::mutex> lock(s_snap_mutex);

    auto it_a = s_snapshots.find(name_a);
    auto it_b = s_snapshots.find(name_b);
    if (it_a == s_snapshots.end()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: snapshot '%s' not found", name_a.c_str());
        return tool_result_t::error(OBFSTR("Snapshot '") + name_a + OBFSTR("' not found."));
    }
    if (it_b == s_snapshots.end()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: snapshot '%s' not found", name_b.c_str());
        return tool_result_t::error(OBFSTR("Snapshot '") + name_b + OBFSTR("' not found."));
    }

    const auto& a = it_a->second;
    const auto& b = it_b->second;


    json reg_diffs = json::array();
    auto cmp_reg = [&](const char* name, std::uint64_t va, std::uint64_t vb) {
        if (va != vb)
        {
            json d;
            d["register"] = name;
            d["before"]   = sa_format_address(va);
            d["after"]    = sa_format_address(vb);
            reg_diffs.push_back(d);
        }
    };

    cmp_reg("rax", a.ctx.rax, b.ctx.rax);
    cmp_reg("rbx", a.ctx.rbx, b.ctx.rbx);
    cmp_reg("rcx", a.ctx.rcx, b.ctx.rcx);
    cmp_reg("rdx", a.ctx.rdx, b.ctx.rdx);
    cmp_reg("rsi", a.ctx.rsi, b.ctx.rsi);
    cmp_reg("rdi", a.ctx.rdi, b.ctx.rdi);
    cmp_reg("rbp", a.ctx.rbp, b.ctx.rbp);
    cmp_reg("rsp", a.ctx.rsp, b.ctx.rsp);
    cmp_reg("r8",  a.ctx.r8,  b.ctx.r8);
    cmp_reg("r9",  a.ctx.r9,  b.ctx.r9);
    cmp_reg("r10", a.ctx.r10, b.ctx.r10);
    cmp_reg("r11", a.ctx.r11, b.ctx.r11);
    cmp_reg("r12", a.ctx.r12, b.ctx.r12);
    cmp_reg("r13", a.ctx.r13, b.ctx.r13);
    cmp_reg("r14", a.ctx.r14, b.ctx.r14);
    cmp_reg("r15", a.ctx.r15, b.ctx.r15);
    cmp_reg("rip", a.ctx.rip, b.ctx.rip);
    cmp_reg("rflags", a.ctx.rflags, b.ctx.rflags);
    cmp_reg("dr0", a.ctx.dr0, b.ctx.dr0);
    cmp_reg("dr1", a.ctx.dr1, b.ctx.dr1);
    cmp_reg("dr2", a.ctx.dr2, b.ctx.dr2);
    cmp_reg("dr3", a.ctx.dr3, b.ctx.dr3);
    cmp_reg("dr6", a.ctx.dr6, b.ctx.dr6);
    cmp_reg("dr7", a.ctx.dr7, b.ctx.dr7);


    json mem_diffs = json::array();
    for (const auto& mem_a : a.memory)
    {
        for (const auto& mem_b : b.memory)
        {
            if (mem_a.address != mem_b.address)
                continue;

            const std::size_t cmp_len =
                (std::min)(mem_a.data.size(), mem_b.data.size());
            json byte_diffs = json::array();

            for (std::size_t i = 0; i < cmp_len; ++i)
            {
                if (mem_a.data[i] != mem_b.data[i])
                {
                    json bd;
                    bd["offset"] = static_cast<int>(i);
                    bd["address"] = sa_format_address(mem_a.address + i);
                    bd["before"]  = sa_format_address(
                        static_cast<uint64_t>(mem_a.data[i]));
                    bd["after"]   = sa_format_address(
                        static_cast<uint64_t>(mem_b.data[i]));
                    byte_diffs.push_back(bd);
                    if (byte_diffs.size() >= 256)
                        break;
                }
            }

            if (!byte_diffs.empty())
            {
                json rd;
                rd["address"]    = sa_format_address(mem_a.address);
                rd["diff_count"] = static_cast<int>(byte_diffs.size());
                rd["diffs"]      = byte_diffs;
                if (mem_a.data.size() != mem_b.data.size())
                {
                    rd["size_a"] = static_cast<int>(mem_a.data.size());
                    rd["size_b"] = static_cast<int>(mem_b.data.size());
                }
                mem_diffs.push_back(rd);
            }
            break;
        }
    }

    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        b.timestamp - a.timestamp).count();

    json result;
    result["snapshot_a"]       = name_a;
    result["snapshot_b"]       = name_b;
    result["tid_a"]            = a.tid;
    result["tid_b"]            = b.tid;
    result["elapsed_ms"]       = static_cast<int>(elapsed_ms);
    result["register_changes"] = static_cast<int>(reg_diffs.size());
    result["register_diffs"]   = reg_diffs;
    result["memory_changes"]   = static_cast<int>(mem_diffs.size());
    result["memory_diffs"]     = mem_diffs;

    diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: '%s' vs '%s' => %zu reg diffs, %zu mem diffs, elapsed_ms=%lld", name_a.c_str(), name_b.c_str(), reg_diffs.size(), mem_diffs.size(), (long long)elapsed_ms);
    return tool_result_t::ok(
        OBFSTR("Diff: ") + std::to_string(reg_diffs.size()) +
        OBFSTR(" register(s), ") + std::to_string(mem_diffs.size()) +
        OBFSTR(" memory region(s) changed"),
        result);
}


static tool_result_t dbg_detect_vm_handler(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: entry");
    if (auto err = ensure_attached(params))
        return *err;

    if (!params.contains("address") || !params["address"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: missing address param");
        return tool_result_t::error(OBFSTR("'address' (hex string) is required."));
    }

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0) {
        diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: invalid address");
        return tool_result_t::error(OBFSTR("Invalid address."));
    }
    const std::uint64_t addr = *addr_opt;

    int scan_size = 512;
    if (params.contains("size") && params["size"].is_number())
        scan_size = std::clamp(params["size"].get<int>(), 64, 16384);
    diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: analyzing 0x%llX size=%d", (unsigned long long)addr, scan_size);


    std::vector<uint8_t> code(static_cast<std::size_t>(scan_size));
    std::size_t read = device->read_raw(addr, code.data(), code.size());
    if (read < 16) {
        diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: only %zu bytes read at 0x%llX", read, (unsigned long long)addr);
        return tool_result_t::error(
            OBFSTR("Insufficient bytes read at ") + sa_format_address(addr));
    }
    diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: read %zu bytes", read);
    code.resize(read);

    zydis_detail::ensure_init();


    json indicators = json::array();
    int indirect_jumps      = 0;
    int scaled_jumps        = 0;
    int memory_reads        = 0;
    int dispatch_candidates = 0;
    std::uint64_t likely_dispatch_addr = 0;

    std::size_t offset = 0;
    std::uint64_t va = addr;
    int instr_count = 0;

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset + 1 <= code.size() && instr_count < 2000)
    {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &zydis_detail::decoder(),
                code.data() + offset,
                code.size() - offset,
                &instr, operands)))
        {
            offset++;
            va++;
            continue;
        }

        ++instr_count;


        if (instr.mnemonic == ZYDIS_MNEMONIC_JMP)
        {
            for (int i = 0; i < static_cast<int>(instr.operand_count_visible); ++i)
            {
                const auto& op = operands[i];
                if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    ++indirect_jumps;
                    json ind;
                    ind["type"]    = "indirect_jmp_reg";
                    ind["address"] = sa_format_address(va);
                    char buf[128] = {};
                    ZydisFormatterFormatInstruction(
                        &zydis_detail::formatter(), &instr, operands,
                        instr.operand_count_visible, buf, sizeof(buf),
                        va, ZYAN_NULL);
                    ind["instruction"] = buf;
                    indicators.push_back(ind);
                    if (likely_dispatch_addr == 0)
                        likely_dispatch_addr = va;
                }
                else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (op.mem.scale > 1)
                    {
                        ++scaled_jumps;
                        json ind;
                        ind["type"]    = "scaled_table_jmp";
                        ind["address"] = sa_format_address(va);
                        ind["scale"]   = op.mem.scale;
                        char buf[128] = {};
                        ZydisFormatterFormatInstruction(
                            &zydis_detail::formatter(), &instr, operands,
                            instr.operand_count_visible, buf, sizeof(buf),
                            va, ZYAN_NULL);
                        ind["instruction"] = buf;
                        indicators.push_back(ind);
                        ++dispatch_candidates;
                        if (likely_dispatch_addr == 0)
                            likely_dispatch_addr = va;
                    }
                    else
                    {
                        ++indirect_jumps;
                        json ind;
                        ind["type"]    = "indirect_jmp_mem";
                        ind["address"] = sa_format_address(va);
                        char buf[128] = {};
                        ZydisFormatterFormatInstruction(
                            &zydis_detail::formatter(), &instr, operands,
                            instr.operand_count_visible, buf, sizeof(buf),
                            va, ZYAN_NULL);
                        ind["instruction"] = buf;
                        indicators.push_back(ind);
                    }
                }
            }
        }


        if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX ||
            instr.mnemonic == ZYDIS_MNEMONIC_MOVSX)
        {
            for (int i = 0; i < static_cast<int>(instr.operand_count_visible); ++i)
            {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    ++memory_reads;
                    break;
                }
            }
        }

        offset += instr.length;
        va     += instr.length;
    }


    double score = 0.0;
    if (indirect_jumps > 0)  score += 20.0;
    if (scaled_jumps > 0)    score += 40.0;
    if (memory_reads > 3)    score += 15.0;
    if (dispatch_candidates > 0) score += 25.0;
    score = (std::min)(score, 100.0);

    std::string verdict;
    if (score >= 60.0)      verdict = "HIGH — likely VM dispatcher";
    else if (score >= 30.0) verdict = "MEDIUM — possible VM handler region";
    else                    verdict = "LOW — unlikely VM code";

    json result;
    result["address"]              = sa_format_address(addr);
    result["bytes_analyzed"]       = static_cast<int>(read);
    result["instructions_decoded"] = instr_count;
    result["indirect_jumps"]       = indirect_jumps;
    result["scaled_table_jumps"]   = scaled_jumps;
    result["memory_reads"]         = memory_reads;
    result["dispatch_candidates"]  = dispatch_candidates;
    result["vm_score"]             = static_cast<int>(score);
    result["verdict"]              = verdict;
    result["indicators"]           = indicators;
    if (likely_dispatch_addr != 0)
        result["likely_dispatch"] = sa_format_address(likely_dispatch_addr);

    diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: addr=0x%llX score=%d verdict=%s indirect_jmps=%d scaled_jmps=%d", (unsigned long long)addr, (int)score, verdict.c_str(), indirect_jumps, scaled_jumps);
    return tool_result_t::ok(
        OBFSTR("VM analysis at ") + sa_format_address(addr) +
        OBFSTR(": ") + verdict, result);
}

static tool_result_t dbg_map_vm_handlers(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: entry");
    if (auto err = ensure_attached(params))
        return *err;

    if (!params.contains("table_address") || !params["table_address"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: missing table_address param");
        return tool_result_t::error(
            OBFSTR("'table_address' (hex string of handler table base) is required."));
    }

    auto table_addr_opt = sa_parse_address(
        params["table_address"].get<std::string>());
    if (!table_addr_opt || *table_addr_opt == 0) {
        diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: invalid table_address");
        return tool_result_t::error(OBFSTR("Invalid table_address."));
    }
    const std::uint64_t table_base = *table_addr_opt;

    int entry_count = 256;
    if (params.contains("count") && params["count"].is_number())
        entry_count = std::clamp(params["count"].get<int>(), 1, 4096);
    diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: table=0x%llX count=%d", (unsigned long long)table_base, entry_count);

    int entry_size = 8;
    if (params.contains("entry_size") && params["entry_size"].is_number())
        entry_size = std::clamp(params["entry_size"].get<int>(), 1, 8);

    int preview_instructions = 5;
    if (params.contains("preview_instructions") && params["preview_instructions"].is_number())
        preview_instructions = std::clamp(
            params["preview_instructions"].get<int>(), 0, 32);


    bool relative = false;
    if (params.contains("relative") && params["relative"].is_boolean())
        relative = params["relative"].get<bool>();

    std::uint64_t image_base = 0;
    if (relative)
    {
        if (params.contains("image_base") && params["image_base"].is_string())
        {
            auto ib = sa_parse_address(params["image_base"].get<std::string>());
            if (ib) image_base = *ib;
        }
        if (image_base == 0)
            image_base = device->get_base_address();
    }

    zydis_detail::ensure_init();


    const std::size_t table_byte_size =
        static_cast<std::size_t>(entry_count) * static_cast<std::size_t>(entry_size);
    std::vector<uint8_t> table_data(table_byte_size);
    std::size_t table_read = device->read_raw(
        table_base, table_data.data(), table_byte_size);
    if (table_read < static_cast<std::size_t>(entry_size)) {
        diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: failed to read table at 0x%llX read=%zu", (unsigned long long)table_base, table_read);
        return tool_result_t::error(
            OBFSTR("Failed to read handler table at ") +
            sa_format_address(table_base));
    }
    diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: read %zu bytes from table", table_read);

    const int actual_entries =
        static_cast<int>(table_read) / entry_size;

    json handlers = json::array();
    int valid_count = 0;
    int null_count  = 0;

    for (int i = 0; i < actual_entries; ++i)
    {
        std::uint64_t raw_value = 0;
        std::memcpy(&raw_value,
                     table_data.data() + static_cast<std::size_t>(i) * static_cast<std::size_t>(entry_size),
                     static_cast<std::size_t>(entry_size));


        if (entry_size == 4)
            raw_value = static_cast<std::uint64_t>(
                static_cast<std::int32_t>(raw_value & 0xFFFFFFFF));


        std::uint64_t handler_addr = raw_value;
        if (relative)
            handler_addr = image_base + raw_value;

        if (handler_addr == 0 || handler_addr < 0x10000)
        {
            ++null_count;
            continue;
        }

        json entry;
        entry["index"]        = i;
        entry["table_offset"] = sa_format_address(
            table_base + static_cast<uint64_t>(i) * static_cast<uint64_t>(entry_size));
        entry["raw_value"]    = sa_format_address(raw_value);
        entry["handler_addr"] = sa_format_address(handler_addr);


        if (preview_instructions > 0)
        {
            const int preview_bytes = preview_instructions * 15;
            std::vector<uint8_t> code(static_cast<std::size_t>(preview_bytes));
            std::size_t code_read = device->read_raw(
                handler_addr, code.data(), code.size());

            if (code_read >= 1)
            {
                json disasm_arr = json::array();
                std::size_t off = 0;
                std::uint64_t pc = handler_addr;
                int decoded = 0;

                while (off < code_read && decoded < preview_instructions)
                {
                    AsmInstr ins = zydis_decode_one(
                        code.data() + off,
                        static_cast<int>(code_read - off),
                        pc);

                    json dj;
                    dj["address"]     = sa_format_address(pc);
                    dj["instruction"] = std::string(ins.mnem) + " " + std::string(ins.ops);
                    dj["size"]        = ins.len;
                    disasm_arr.push_back(dj);

                    off += static_cast<std::size_t>(ins.len);
                    pc  += static_cast<uint64_t>(ins.len);
                    ++decoded;
                }
                entry["disassembly"] = disasm_arr;
            }
        }

        handlers.push_back(entry);
        ++valid_count;
    }

    json result;
    result["table_address"]  = sa_format_address(table_base);
    result["entry_size"]     = entry_size;
    result["entries_read"]   = actual_entries;
    result["valid_handlers"] = valid_count;
    result["null_entries"]   = null_count;
    result["relative"]       = relative;
    if (relative)
        result["image_base"] = sa_format_address(image_base);
    result["handlers"]       = handlers;

    diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: table=0x%llX valid=%d null=%d", (unsigned long long)table_base, valid_count, null_count);
    return tool_result_t::ok(
        OBFSTR("Mapped ") + std::to_string(valid_count) +
        OBFSTR(" handlers from table at ") + sa_format_address(table_base),
        result);
}


void register_debugger_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged_fmt("dbg_tools", "register_debugger_tools: registering all debugger MCP tools");

    register_compat(srv, {
        OBFSTR("dbg_set_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Set a software breakpoint (INT3 / 0xCC) at an address in the attached process. "
               "The original byte is saved and can be restored with dbg_remove_breakpoint. "
               "Uses kernel driver writes to bypass all memory protection and anti-tamper. "
               "Note: INT3 breakpoints cause an unhandled exception in the target unless "
               "a vectored exception handler is installed — use driver_set_hw_breakpoint for "
               "transparent breakpoints that don't modify code bytes."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address (hex)"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_set_breakpoint, false});

    register_compat(srv, {
        OBFSTR("dbg_remove_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Remove a software breakpoint by restoring the original byte at the address. "
               "Only works for breakpoints set via dbg_set_breakpoint (original byte must be tracked)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Breakpoint address to remove (hex)"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_remove_breakpoint, false});

    register_compat(srv, {
        OBFSTR("dbg_list_breakpoints"), OBFSTR("debugger"),
        OBFSTR("List all active software breakpoints (INT3 patches) managed by this session. "
               "Shows address and the original byte that will be restored on removal."),
        {},
        dbg_list_breakpoints, true});


    register_compat(srv, {
        OBFSTR("dbg_get_callstack"), OBFSTR("debugger"),
        OBFSTR("Unwind the call stack of a thread in the attached process. "
               "Suspends the thread, reads its register context, and walks the RBP frame "
               "pointer chain through memory. Falls back to RSP scanning if RBP is invalid "
               "(e.g. leaf functions compiled with -fomit-frame-pointer). Each frame includes "
               "the return address and a Zydis disassembly of the instruction at that address."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("max_depth"), OBFSTR("number"), OBFSTR("Maximum stack frames to unwind (default 64, max 256)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_get_callstack, true});


    register_compat(srv, {
        OBFSTR("dbg_snapshot_state"), OBFSTR("debugger"),
        OBFSTR("Capture the full execution state (all registers + optional memory regions) of a "
               "thread into a named snapshot. Snapshots can be compared with dbg_compare_snapshots "
               "to see exactly which registers and bytes changed between two points in execution."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Snapshot name (default 'default'). Use descriptive names like 'before_call', 'after_decrypt'."), false},
         {OBFSTR("memory_regions"), OBFSTR("array"),
          OBFSTR("Optional array of {address, size} objects specifying memory regions to capture."), false, {},
          json::object({{"type", "object"},
                        {"properties", json::object({
                            {"address", json::object({{"type", "string"}})},
                            {"size", json::object({{"type", "number"}})}
                        })}
          })},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_snapshot_state, false});

    register_compat(srv, {
        OBFSTR("dbg_compare_snapshots"), OBFSTR("debugger"),
        OBFSTR("Compare two previously captured execution snapshots. Shows all register "
               "differences and byte-level memory diffs. Useful for tracing exactly what a "
               "function call modified, detecting encryption/decryption state changes, or "
               "verifying that a code patch had the expected effect."),
        {{OBFSTR("snapshot_a"), OBFSTR("string"), OBFSTR("Name of the 'before' snapshot"), true},
         {OBFSTR("snapshot_b"), OBFSTR("string"), OBFSTR("Name of the 'after' snapshot"), true}},
        dbg_compare_snapshots, true});


    register_compat(srv, {
        OBFSTR("dbg_detect_vm_handler"), OBFSTR("debugger"),
        OBFSTR("Analyze code at an address to detect virtual machine (VM) obfuscation patterns. "
               "Reads code bytes from the target process and uses Zydis disassembly to identify "
               "VM dispatcher indicators: indirect jumps through registers, scaled table dispatches "
               "(jmp [reg*8+table]), opcode fetch patterns (movzx/movsx from memory), and other "
               "common VM handler idioms. Returns a confidence score and detailed indicators."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to analyze (hex)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes to analyze (default 512, max 16384)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_detect_vm_handler, true});

    register_compat(srv, {
        OBFSTR("dbg_map_vm_handlers"), OBFSTR("debugger"),
        OBFSTR("Read a VM handler dispatch table from target memory and disassemble each handler entry. "
               "Reads an array of handler pointers (or relative offsets) from a table address, resolves "
               "each to a handler address, and provides a Zydis disassembly preview of each handler. "
               "Use dbg_detect_vm_handler first to locate the dispatch table, then use this tool to "
               "map all handler entries."),
        {{OBFSTR("table_address"), OBFSTR("string"), OBFSTR("Base address of the handler table (hex)"), true},
         {OBFSTR("count"), OBFSTR("number"), OBFSTR("Number of entries to read (default 256, max 4096)"), false},
         {OBFSTR("entry_size"), OBFSTR("number"), OBFSTR("Size of each table entry in bytes: 4 or 8 (default 8)"), false},
         {OBFSTR("relative"), OBFSTR("boolean"), OBFSTR("If true, entries are relative offsets from image_base (default false = absolute pointers)"), false},
         {OBFSTR("image_base"), OBFSTR("string"), OBFSTR("Base address for resolving relative offsets (default: attached process image base)"), false},
         {OBFSTR("preview_instructions"), OBFSTR("number"), OBFSTR("Instructions to disassemble per handler (default 5, max 32)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_map_vm_handlers, true});


    register_compat(srv, {
        OBFSTR("dbg_run"), OBFSTR("debugger"),
        OBFSTR("Resume execution of the attached process (set debugger state to running)."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_run: entry");
            if (auto err = ensure_attached(params)) return *err;
            bool ok = debugger_engine::run_target();
            diag::log_tagged_fmt("dbg_tools", "dbg_run: run_target returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("run_target failed.") : debugger_engine::last_error());
            return tool_result_t::ok(OBFSTR("Execution resumed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_pause"), OBFSTR("debugger"),
        OBFSTR("Pause (break) the attached process."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_pause: entry");
            if (auto err = ensure_attached(params)) return *err;
            bool ok = debugger_engine::pause_target();
            diag::log_tagged_fmt("dbg_tools", "dbg_pause: pause_target returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("pause_target failed.") : debugger_engine::last_error());
            return tool_result_t::ok(OBFSTR("Execution paused."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_step_into"), OBFSTR("debugger"),
        OBFSTR("Single-step into the next instruction (follows calls)."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_step_into: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            diag::log_tagged_fmt("dbg_tools", "dbg_step_into: tid=%u", *tid);
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_into();
            diag::log_tagged_fmt("dbg_tools", "dbg_step_into: step_into returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("step_into failed.") : debugger_engine::last_error());
            return tool_result_t::ok(OBFSTR("Step into executed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_step_over"), OBFSTR("debugger"),
        OBFSTR("Step over the next instruction (does not follow calls)."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_step_over: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            diag::log_tagged_fmt("dbg_tools", "dbg_step_over: tid=%u", *tid);
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_over();
            diag::log_tagged_fmt("dbg_tools", "dbg_step_over: step_over returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("step_over failed.") : debugger_engine::last_error());
            return tool_result_t::ok(OBFSTR("Step over executed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_step_out"), OBFSTR("debugger"),
        OBFSTR("Step out of the current function (run until return)."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_step_out: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            diag::log_tagged_fmt("dbg_tools", "dbg_step_out: tid=%u", *tid);
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_out();
            diag::log_tagged_fmt("dbg_tools", "dbg_step_out: step_out returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("step_out failed.") : debugger_engine::last_error());
            return tool_result_t::ok(OBFSTR("Step out executed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_run_to_address"), OBFSTR("debugger"),
        OBFSTR("Run until execution reaches a specific address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address (hex)"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_run_to_address: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            diag::log_tagged_fmt("dbg_tools", "dbg_run_to_address: running to 0x%llX", (unsigned long long)*addr);
            bool wait = false;
            if (params.contains("wait_for_completion") && params["wait_for_completion"].is_boolean())
                wait = params["wait_for_completion"].get<bool>();
            else if (params.contains("wait") && params["wait"].is_boolean())
                wait = params["wait"].get<bool>();
            uint32_t timeout_ms = static_cast<uint32_t>(int_param_clamped(params, "timeout_ms", 30000, 1, 300000));
            bool ok = debugger_engine::run_to_address(*addr, wait, timeout_ms);
            diag::log_tagged_fmt("dbg_tools", "dbg_run_to_address: run_to_address returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("run_to_address failed.") : debugger_engine::last_error());
            return tool_result_t::ok(OBFSTR("Running to ") + sa_format_address(*addr));
        }, false});

    srv.register_tool({
        "debugger_get_attached",
        "Report whether a process is currently attached, its PID, name, image base and image size.",
        {},
        true,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_attached: entry");
            json result;
            result["driver_connected"] = device->is_connected();
            uint32_t pid = device->is_connected() ? device->get_process_id() : 0u;
            result["is_attached"] = (pid != 0);
            result["pid"] = pid;
            if (pid != 0) {
                uint64_t base = device->find_image();
                result["name"] = driver_bridge::attached_process_name();
                result["base_address"] = sa_format_address(base);
                diag::log_tagged_fmt("dbg_tools", "debugger_get_attached: pid=%u name=%s base=0x%llX", pid, driver_bridge::attached_process_name().c_str(), (unsigned long long)base);
                auto mods = driver_bridge::enumerate_modules();
                uint64_t image_size = 0;
                for (const auto& m : mods) {
                    if (m.base == base) { image_size = m.size; break; }
                }
                if (image_size == 0 && !mods.empty()) image_size = mods.front().size;
                result["image_size"] = image_size;
            }
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_registers",
        "Snapshot the cached register set for the active debugger thread (RAX..R15, RIP, RFLAGS, segment regs, DR0..DR7).",
        {},
        true,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_registers: entry");
            auto regs = debugger_engine::get_registers();
            diag::log_tagged_fmt("dbg_tools", "debugger_get_registers: RIP=0x%llX RAX=0x%llX RSP=0x%llX", (unsigned long long)regs.rip, (unsigned long long)regs.rax, (unsigned long long)regs.rsp);
            json result;
            result["rax"] = sa_format_address(regs.rax);
            result["rbx"] = sa_format_address(regs.rbx);
            result["rcx"] = sa_format_address(regs.rcx);
            result["rdx"] = sa_format_address(regs.rdx);
            result["rsi"] = sa_format_address(regs.rsi);
            result["rdi"] = sa_format_address(regs.rdi);
            result["rbp"] = sa_format_address(regs.rbp);
            result["rsp"] = sa_format_address(regs.rsp);
            result["r8"]  = sa_format_address(regs.r8);
            result["r9"]  = sa_format_address(regs.r9);
            result["r10"] = sa_format_address(regs.r10);
            result["r11"] = sa_format_address(regs.r11);
            result["r12"] = sa_format_address(regs.r12);
            result["r13"] = sa_format_address(regs.r13);
            result["r14"] = sa_format_address(regs.r14);
            result["r15"] = sa_format_address(regs.r15);
            result["rip"] = sa_format_address(regs.rip);
            result["rflags"] = sa_format_address(regs.rflags);
            result["flags_decoded"] = debugger_engine::format_flags(regs.rflags);
            result["dr0"] = sa_format_address(regs.dr0);
            result["dr1"] = sa_format_address(regs.dr1);
            result["dr2"] = sa_format_address(regs.dr2);
            result["dr3"] = sa_format_address(regs.dr3);
            result["dr6"] = sa_format_address(regs.dr6);
            result["dr7"] = sa_format_address(regs.dr7);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_breakpoints",
        "List every breakpoint tracked by the debugger engine, including disabled and one-shot entries.",
        {},
        true,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_breakpoints: entry");
            std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
            json arr = json::array();
            for (size_t i = 0; i < debugger_engine::g_state.breakpoints.size(); ++i) {
                const auto& bp = debugger_engine::g_state.breakpoints[i];
                json e;
                e["index"]   = static_cast<int>(i);
                e["address"] = sa_format_address(bp.address);
                e["type"]    = static_cast<int>(bp.type);
                e["state"]   = static_cast<int>(bp.state);
                e["size"]    = bp.size;
                e["hit_count"] = bp.hit_count;
                e["byte_written"] = bp.byte_written;
                e["original_byte"] = static_cast<unsigned>(bp.original_byte);
                if (!bp.name.empty())      e["name"]      = bp.name;
                if (!bp.condition.empty()) e["condition"] = bp.condition;
                if (!bp.log_text.empty())  e["log_text"]  = bp.log_text;
                arr.push_back(std::move(e));
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_get_breakpoints: returning %zu breakpoints", arr.size());
            json result;
            result["count"]       = arr.size();
            result["breakpoints"] = std::move(arr);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_memory_map",
        "Snapshot the virtual memory map of the attached process (alias of dbg_get_memory_map).",
        {},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_memory_map: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto regions = debugger_engine::get_memory_map();
            diag::log_tagged_fmt("dbg_tools", "debugger_get_memory_map: got %zu regions", regions.size());
            json arr = json::array();
            for (const auto& r : regions) {
                json o;
                o["base"]    = sa_format_address(r.base);
                o["size"]    = r.size;
                o["protect"] = debugger_engine::format_protect(r.protect);
                o["state"]   = r.state;
                o["type"]    = r.type;
                if (!r.module_name.empty()) o["module"] = r.module_name;
                arr.push_back(std::move(o));
            }
            json result;
            result["count"]   = arr.size();
            result["regions"] = std::move(arr);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_callstack",
        "Return the cached call stack of the active debugger thread (each frame: address, return_addr, module, function_name, module_offset).",
        {{"tid", "string", "Optional thread ID. Defaults to the active debugger thread.", false},
         {"max_depth", "number", "Maximum stack frames to unwind (default 64, max 256)", false},
         {"target_pid", "number", "Optional PID override. Switches the active attach context for this call.", false}},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack: entry");
            if (auto err = ensure_attached(params))
                return *err;

            json call_params = params.is_object() ? params : json::object();
            if (!parse_tid(call_params)) {
                std::uint32_t tid = debugger_engine::g_state.active_tid;
                if (tid == 0) {
                    const std::uint32_t pid = driver_bridge::attached_pid();
                    for (const auto& th : driver_bridge::enumerate_threads()) {
                        if (th.owner_pid == pid && th.tid != 0) {
                            tid = th.tid;
                            break;
                        }
                    }
                }
                if (tid == 0) {
                    diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack: no live thread");
                    return tool_result_t::error(OBFSTR("No live target thread available."));
                }
                call_params["tid"] = std::to_string(tid);
            }

            auto result = dbg_get_callstack(call_params);
            diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack: delegated success=%d", result.success ? 1 : 0);
            return result;
        }
    });

    srv.register_tool({
        "debugger_get_threads",
        "Enumerate the threads of the attached process via the kernel driver.",
        {},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_threads: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto threads = driver_bridge::enumerate_threads();
            diag::log_tagged_fmt("dbg_tools", "debugger_get_threads: got %zu threads", threads.size());
            json arr = json::array();
            for (const auto& t : threads) {
                json o;
                o["tid"]      = t.tid;
                o["owner_pid"] = t.owner_pid;
                o["priority"] = t.priority;
                o["state"]    = t.state;
                o["rip"]      = sa_format_address(t.rip);
                arr.push_back(std::move(o));
            }
            json result;
            result["count"]   = arr.size();
            result["threads"] = std::move(arr);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_handles",
        "Enumerate kernel handles owned by the attached process via the debugger engine's handle table.",
        {},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_handles: entry");
            if (auto err = ensure_attached(params)) return *err;
            debugger_engine::enumerate_handles();
            std::lock_guard<std::mutex> lk(debugger_engine::g_state.handle_mutex);
            json arr = json::array();
            for (const auto& h : debugger_engine::g_state.handles) {
                json o;
                o["handle"]     = sa_format_address(h.handle);
                o["type_index"] = h.type_index;
                if (!h.type_name.empty()) o["type"] = h.type_name;
                if (!h.name.empty())      o["name"] = h.name;
                o["access"]     = sa_format_address(static_cast<uint64_t>(h.access));
                arr.push_back(std::move(o));
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_get_handles: returning %zu handles", arr.size());
            json result;
            result["count"]   = arr.size();
            result["handles"] = std::move(arr);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_modules",
        "List loaded modules (DLLs / EXEs) of the attached process: name, base address, size, and full path.",
        {},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_modules: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto modules = driver_bridge::enumerate_modules();
            diag::log_tagged_fmt("dbg_tools", "debugger_get_modules: got %zu modules", modules.size());
            json arr = json::array();
            for (const auto& m : modules) {
                json o;
                o["name"] = m.name;
                o["path"] = m.path;
                o["base"] = sa_format_address(m.base);
                o["size"] = m.size;
                arr.push_back(std::move(o));
            }
            json result;
            result["count"]   = arr.size();
            result["modules"] = std::move(arr);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_seh_chain",
        "Refresh and return the SEH exception handler chain for the active thread of the attached process.",
        {},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_seh_chain: entry");
            if (auto err = ensure_attached(params)) return *err;
            diag::log_tagged_fmt("dbg_tools", "debugger_get_seh_chain: calling seh_view::refresh");
            seh_view::refresh();
            for (int i = 0; i < 100; ++i) {
                if (!seh_view::g_ui.refreshing.load()) break;
                Sleep(20);
            }
            std::lock_guard<std::mutex> lk(seh_view::g_ui.mutex);
            json arr = json::array();
            for (const auto& e : seh_view::g_ui.entries) {
                json o;
                o["index"]         = e.index;
                o["frame_addr"]    = sa_format_address(e.frame_addr);
                o["handler_addr"]  = sa_format_address(e.handler_addr);
                o["filter_addr"]   = sa_format_address(e.filter_addr);
                if (!e.module_name.empty())  o["module"]       = e.module_name;
                if (!e.handler_name.empty()) o["handler_name"] = e.handler_name;
                arr.push_back(std::move(o));
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_get_seh_chain: returning %zu SEH entries", arr.size());
            json result;
            result["count"]   = arr.size();
            result["entries"] = std::move(arr);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_patches",
        "List active byte-patches tracked by the code patcher (address, description, original/patched bytes, active flag, timestamp).",
        {},
        true,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_patches: entry");
            std::lock_guard<std::mutex> lk(code_patcher::g_state.mtx);
            json arr = json::array();
            for (size_t i = 0; i < code_patcher::g_state.patches.size(); ++i) {
                const auto& p = code_patcher::g_state.patches[i];
                json o;
                o["index"]          = static_cast<int>(i);
                o["address"]        = sa_format_address(p.address);
                o["description"]    = p.description;
                o["active"]         = p.active;
                o["timestamp"]      = p.timestamp;
                o["original_bytes"] = code_patcher::format_bytes(p.original_bytes);
                o["patched_bytes"]  = code_patcher::format_bytes(p.patched_bytes);
                o["size"]           = p.patched_bytes.size();
                arr.push_back(std::move(o));
            }
            json result;
            result["count"]   = arr.size();
            result["patches"] = std::move(arr);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_set_breakpoint",
        "Install a breakpoint via the debugger engine. type=exec (software int3), read/write (hardware DR breakpoint), size=1/2/4/8.",
        {{"address", "string", "Breakpoint address (hex)", true},
         {"type",    "string", "exec (software), read, write, access (default exec)", false},
         {"size",    "number", "Breakpoint size 1/2/4/8 (default 1)", false},
         {"name",    "string", "Optional label", false},
         {"condition", "string", "Optional condition expression", false}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_set_breakpoint: entry");
            if (!device->is_connected())
                return tool_result_t::error("Driver not connected. Call driver_load first.");
            uint64_t addr = 0;
            if (params.contains("address") && params["address"].is_string()) {
                auto p = sa_parse_address(params["address"].get<std::string>());
                if (!p) return tool_result_t::error("Invalid address.");
                addr = *p;
            } else {
                return tool_result_t::error("'address' is required.");
            }
            std::string type_str = "exec";
            if (params.contains("type") && params["type"].is_string())
                type_str = params["type"].get<std::string>();
            debugger_engine::bp_type_t bp_type = debugger_engine::bp_type_t::software;
            if (type_str == "exec" || type_str == "software")          bp_type = debugger_engine::bp_type_t::software;
            else if (type_str == "hw_exec" || type_str == "hardware") bp_type = debugger_engine::bp_type_t::hardware_execute;
            else if (type_str == "read")   bp_type = debugger_engine::bp_type_t::hardware_read;
            else if (type_str == "write")  bp_type = debugger_engine::bp_type_t::hardware_write;
            else if (type_str == "access") bp_type = debugger_engine::bp_type_t::memory_access;
            else return tool_result_t::error("Unknown 'type': use exec, read, write, access, or hw_exec.");
            int size = 1;
            if (params.contains("size") && params["size"].is_number_integer())
                size = params["size"].get<int>();
            std::string name;
            if (params.contains("name") && params["name"].is_string())
                name = params["name"].get<std::string>();
            std::string cond;
            if (params.contains("condition") && params["condition"].is_string())
                cond = params["condition"].get<std::string>();
            diag::log_tagged_fmt("dbg_tools", "debugger_set_breakpoint: addr=0x%llX type=%s size=%d", (unsigned long long)addr, type_str.c_str(), size);
            int idx = debugger_engine::add_breakpoint(addr, bp_type, name, cond, size);
            if (idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "debugger_set_breakpoint: add_breakpoint failed: %s", debugger_engine::last_error().c_str());
                return tool_result_t::error("debugger_engine::add_breakpoint failed: " +
                                            debugger_engine::last_error());
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_set_breakpoint: BP set at 0x%llX idx=%d", (unsigned long long)addr, idx);
            json result;
            result["index"]   = idx;
            result["address"] = sa_format_address(addr);
            result["type"]    = type_str;
            result["size"]    = size;
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_remove_breakpoint",
        "Remove a breakpoint tracked by the debugger engine by index OR by address.",
        {{"index",   "number", "Breakpoint index from debugger_get_breakpoints", false},
         {"address", "string", "Breakpoint address (hex). Used when index is absent.", false}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_remove_breakpoint: entry");
            int idx = -1;
            if (params.contains("index") && params["index"].is_number_integer()) {
                idx = params["index"].get<int>();
            } else if (params.contains("address") && params["address"].is_string()) {
                auto p = sa_parse_address(params["address"].get<std::string>());
                if (!p) return tool_result_t::error("Invalid address.");
                std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
                for (size_t i = 0; i < debugger_engine::g_state.breakpoints.size(); ++i) {
                    if (debugger_engine::g_state.breakpoints[i].address == *p) {
                        idx = static_cast<int>(i);
                        break;
                    }
                }
                if (idx < 0) return tool_result_t::error("No breakpoint exists at that address.");
            } else {
                return tool_result_t::error("Provide 'index' or 'address'.");
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_remove_breakpoint: removing idx=%d", idx);
            if (!debugger_engine::remove_breakpoint(idx)) {
                diag::log_tagged_fmt("dbg_tools", "debugger_remove_breakpoint: remove failed: %s", debugger_engine::last_error().c_str());
                return tool_result_t::error("debugger_engine::remove_breakpoint failed: " +
                                            debugger_engine::last_error());
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_remove_breakpoint: removed idx=%d", idx);
            json result;
            result["index"]  = idx;
            result["status"] = "removed";
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_step_over",
        "Step over the next instruction for an explicit thread.",
        {{"tid", "string", "Thread ID", true}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_step_over: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_over();
            diag::log_tagged_fmt("dbg_tools", "debugger_step_over: step_over returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("step_over failed.") : debugger_engine::last_error());
            json result;
            result["status"] = "stepped";
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_step_into",
        "Single-step into the next instruction for an explicit thread.",
        {{"tid", "string", "Thread ID", true}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_step_into: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_into();
            diag::log_tagged_fmt("dbg_tools", "debugger_step_into: step_into returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("step_into failed.") : debugger_engine::last_error());
            json result;
            result["status"] = "stepped";
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_step_out",
        "Run until the current function returns for an explicit thread.",
        {{"tid", "string", "Thread ID", true}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_step_out: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_out();
            diag::log_tagged_fmt("dbg_tools", "debugger_step_out: step_out returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("step_out failed.") : debugger_engine::last_error());
            json result;
            result["status"] = "stepped";
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_continue",
        "Resume the attached process (alias of dbg_run).",
        {},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_continue: entry");
            if (auto err = ensure_attached(params)) return *err;
            bool ok = debugger_engine::run_target();
            diag::log_tagged_fmt("dbg_tools", "debugger_continue: run_target returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("run_target failed.") : debugger_engine::last_error());
            json result;
            result["status"] = "running";
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_pause",
        "Pause / break the attached process (alias of dbg_pause).",
        {},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_pause: entry");
            if (auto err = ensure_attached(params)) return *err;
            bool ok = debugger_engine::pause_target();
            diag::log_tagged_fmt("dbg_tools", "debugger_pause: pause_target returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? OBFSTR("pause_target failed.") : debugger_engine::last_error());
            json result;
            result["status"] = "paused";
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_read_memory",
        "Read up to 65536 bytes from the attached process via driver_bridge::read_memory.",
        {{"address", "string", "Source address (hex)", true},
         {"size",    "number", "Bytes to read (default 256, max 65536)", false}},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_read_memory: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error("'address' is required.");
            auto a = sa_parse_address(params["address"].get<std::string>());
            if (!a) return tool_result_t::error("Invalid address.");
            size_t size = 256;
            if (params.contains("size") && params["size"].is_number_unsigned()) {
                size_t v = params["size"].get<size_t>();
                if (v == 0) return tool_result_t::error("'size' must be > 0.");
                if (v > 65536) v = 65536;
                size = v;
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_read_memory: addr=0x%llX size=%zu", (unsigned long long)*a, size);
            std::vector<uint8_t> bytes;
            if (!driver_bridge::read_memory(*a, size, bytes)) {
                diag::log_tagged_fmt("dbg_tools", "debugger_read_memory: read_memory failed at 0x%llX", (unsigned long long)*a);
                return tool_result_t::error("driver_bridge::read_memory failed.");
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_read_memory: read %zu bytes from 0x%llX", bytes.size(), (unsigned long long)*a);
            std::string hex;
            hex.reserve(bytes.size() * 3);
            char buf[4];
            for (size_t i = 0; i < bytes.size(); ++i) {
                if (i > 0) hex.push_back(' ');
                std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(bytes[i]));
                hex.append(buf, 2);
            }
            json result;
            result["address"] = sa_format_address(*a);
            result["size"]    = bytes.size();
            result["bytes"]   = hex;
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_write_memory",
        "Write hex-encoded bytes to the attached process via driver_bridge::write_memory (capped at 65536 bytes).",
        {{"address",   "string", "Destination address (hex)", true},
         {"hex_bytes", "string", "Hex byte sequence (whitespace/comma separated, e.g. 'CC 90 90')", true}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_write_memory: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error("'address' is required.");
            if (!params.contains("hex_bytes") || !params["hex_bytes"].is_string())
                return tool_result_t::error("'hex_bytes' is required.");
            auto a = sa_parse_address(params["address"].get<std::string>());
            if (!a) return tool_result_t::error("Invalid address.");
            std::string hex = params["hex_bytes"].get<std::string>();
            std::vector<uint8_t> bytes;
            std::string cur;
            auto flush = [&](const std::string& tok) -> bool {
                if (tok.empty()) return true;
                if (tok.size() != 2) return false;
                auto nib = [](char c, int& out) {
                    if (c >= '0' && c <= '9') { out = c - '0'; return true; }
                    if (c >= 'a' && c <= 'f') { out = 10 + (c - 'a'); return true; }
                    if (c >= 'A' && c <= 'F') { out = 10 + (c - 'A'); return true; }
                    return false;
                };
                int hi = 0, lo = 0;
                if (!nib(tok[0], hi) || !nib(tok[1], lo)) return false;
                bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
                return true;
            };
            for (char c : hex) {
                if (c == ' ' || c == '\t' || c == ',' || c == '\r' || c == '\n') {
                    if (!flush(cur)) return tool_result_t::error("Invalid hex token in 'hex_bytes'.");
                    cur.clear();
                    continue;
                }
                cur.push_back(c);
                if (cur.size() == 2) {
                    if (!flush(cur)) return tool_result_t::error("Invalid hex byte.");
                    cur.clear();
                }
            }
            if (!cur.empty() && !flush(cur))
                return tool_result_t::error("Invalid trailing hex token.");
            if (bytes.empty())
                return tool_result_t::error("Decoded byte sequence is empty.");
            if (bytes.size() > 65536)
                return tool_result_t::error("Write exceeds 64 KiB cap.");
            diag::log_tagged_fmt("dbg_tools", "debugger_write_memory: addr=0x%llX bytes=%zu", (unsigned long long)*a, bytes.size());
            if (!driver_bridge::write_memory(*a, bytes)) {
                diag::log_tagged_fmt("dbg_tools", "debugger_write_memory: write_memory failed at 0x%llX", (unsigned long long)*a);
                return tool_result_t::error("driver_bridge::write_memory failed.");
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_write_memory: wrote %zu bytes to 0x%llX", bytes.size(), (unsigned long long)*a);
            json result;
            result["address"] = sa_format_address(*a);
            result["bytes_written"] = bytes.size();
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_protect_memory",
        "Change protection on a memory region via driver_bridge::protect_memory. new_protect uses Win32 PAGE_* constants (0x01..0x80).",
        {{"address",     "string", "Region address (hex)", true},
         {"size",        "number", "Region size in bytes", true},
         {"new_protect", "number", "PAGE_* constant (e.g. 0x40 for PAGE_EXECUTE_READWRITE)", true}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_protect_memory: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error("'address' is required.");
            auto a = sa_parse_address(params["address"].get<std::string>());
            if (!a) return tool_result_t::error("Invalid address.");
            if (!params.contains("size") || !params["size"].is_number_unsigned())
                return tool_result_t::error("'size' is required.");
            if (!params.contains("new_protect") || !params["new_protect"].is_number_integer())
                return tool_result_t::error("'new_protect' is required (PAGE_* constant).");
            uint64_t size = params["size"].get<uint64_t>();
            uint32_t new_prot = static_cast<uint32_t>(params["new_protect"].get<int>());
            diag::log_tagged_fmt("dbg_tools", "debugger_protect_memory: addr=0x%llX size=%llu new_prot=0x%X", (unsigned long long)*a, (unsigned long long)size, new_prot);
            uint32_t old_prot = 0;
            if (!driver_bridge::protect_memory(*a, size, new_prot, &old_prot)) {
                diag::log_tagged_fmt("dbg_tools", "debugger_protect_memory: protect_memory failed at 0x%llX", (unsigned long long)*a);
                return tool_result_t::error("driver_bridge::protect_memory failed.");
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_protect_memory: old_prot=0x%X new_prot=0x%X", old_prot, new_prot);
            json result;
            result["address"]      = sa_format_address(*a);
            result["size"]         = size;
            result["new_protect"]  = debugger_engine::format_protect(new_prot);
            result["old_protect"]  = debugger_engine::format_protect(old_prot);
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_attach_to_process",
        "Attach the kernel driver to a target process by PID or by process name (alias of driver_attach for the debugger domain).",
        {{"pid",  "number", "Target PID (preferred when known)", false},
         {"name", "string", "Process name (e.g. 'notepad.exe')", false}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_attach_to_process: entry");
            if (!device->is_connected()) {
                diag::log_tagged_fmt("dbg_tools", "debugger_attach_to_process: connecting to driver");
                if (!device->connect())
                    return tool_result_t::error("Cannot connect to kernel driver.");
            }
            uint32_t pid = 0;
            if (params.contains("pid") && params["pid"].is_number_unsigned()) {
                pid = params["pid"].get<uint32_t>();
            } else if (params.contains("name") && params["name"].is_string()) {
                std::string n = params["name"].get<std::string>();
                pid = device->find_process(n.c_str());
                if (pid == 0) {
                    diag::log_tagged_fmt("dbg_tools", "debugger_attach_to_process: process not found: %s", n.c_str());
                    return tool_result_t::error("Process not found: " + n);
                }
            } else {
                return tool_result_t::error("Provide 'pid' or 'name'.");
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_attach_to_process: attaching to pid=%u", pid);
            if (!driver_bridge::attach(pid)) {
                diag::log_tagged_fmt("dbg_tools", "debugger_attach_to_process: attach failed for pid=%u: %s", pid, driver_bridge::last_error().c_str());
                return tool_result_t::error("driver_bridge::attach failed: " +
                                            driver_bridge::last_error());
            }
            uint64_t base = device->find_image();
            device->solve_dtb();
            diag::log_tagged_fmt("dbg_tools", "debugger_attach_to_process: attached pid=%u base=0x%llX", pid, (unsigned long long)base);
            json result;
            result["pid"]          = pid;
            result["base_address"] = sa_format_address(base);
            result["name"]         = driver_bridge::attached_process_name();
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_detach",
        "Detach the kernel driver from the current target process.",
        {},
        false,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_detach: entry");
            driver_bridge::detach();
            diag::log_tagged_fmt("dbg_tools", "debugger_detach: detached");
            return tool_result_t::ok("Detached.");
        }
    });

    register_compat(srv, {
        OBFSTR("dbg_get_registers"), OBFSTR("debugger"),
        OBFSTR("Read all general-purpose registers, RIP, RFLAGS, segment and debug registers "
               "of a thread in the attached process."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID (default: first thread)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_registers: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (tid) debugger_engine::g_state.active_tid = *tid;
            auto regs = debugger_engine::get_registers();
            diag::log_tagged_fmt("dbg_tools", "dbg_get_registers: RIP=0x%llX RAX=0x%llX", (unsigned long long)regs.rip, (unsigned long long)regs.rax);

            json r;
            r["rax"] = sa_format_address(regs.rax);
            r["rbx"] = sa_format_address(regs.rbx);
            r["rcx"] = sa_format_address(regs.rcx);
            r["rdx"] = sa_format_address(regs.rdx);
            r["rsi"] = sa_format_address(regs.rsi);
            r["rdi"] = sa_format_address(regs.rdi);
            r["rbp"] = sa_format_address(regs.rbp);
            r["rsp"] = sa_format_address(regs.rsp);
            r["r8"]  = sa_format_address(regs.r8);
            r["r9"]  = sa_format_address(regs.r9);
            r["r10"] = sa_format_address(regs.r10);
            r["r11"] = sa_format_address(regs.r11);
            r["r12"] = sa_format_address(regs.r12);
            r["r13"] = sa_format_address(regs.r13);
            r["r14"] = sa_format_address(regs.r14);
            r["r15"] = sa_format_address(regs.r15);
            r["rip"] = sa_format_address(regs.rip);
            r["rflags"] = sa_format_address(regs.rflags);
            r["flags_decoded"] = debugger_engine::format_flags(regs.rflags);
            return tool_result_t::ok(OBFSTR("Registers read."), r);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_set_register"), OBFSTR("debugger"),
        OBFSTR("Set a single register value in a thread of the attached process."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("register"), OBFSTR("string"), OBFSTR("Register name (e.g. rax, rip, r8)"), true},
         {OBFSTR("value"), OBFSTR("string"), OBFSTR("New value (hex)"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_set_register: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            if (!params.contains("register") || !params.contains("value"))
                return tool_result_t::error(OBFSTR("'register' and 'value' required."));
            auto val = sa_parse_address(params["value"].get<std::string>());
            if (!val) return tool_result_t::error(OBFSTR("Invalid value."));
            const std::string reg_name = params["register"].get<std::string>();
            diag::log_tagged_fmt("dbg_tools", "dbg_set_register: tid=%u reg=%s val=0x%llX", *tid, reg_name.c_str(), (unsigned long long)*val);
            debugger_engine::g_state.active_tid = *tid;
            debugger_engine::set_register(reg_name, *val);
            diag::log_tagged_fmt("dbg_tools", "dbg_set_register: set_register done");
            return tool_result_t::ok(OBFSTR("Register set."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_memory_map"), OBFSTR("debugger"),
        OBFSTR("Get the full virtual memory map of the attached process, including base address, "
               "size, protection flags, and module name for each region."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_memory_map: entry");
            if (auto err = ensure_attached(params)) return *err;
            auto regions = debugger_engine::get_memory_map();
            diag::log_tagged_fmt("dbg_tools", "dbg_get_memory_map: got %zu regions", regions.size());
            json arr = json::array();
            for (const auto& r : regions) {
                json rj;
                rj["base"] = sa_format_address(r.base);
                rj["size"] = r.size;
                rj["protect"] = debugger_engine::format_protect(r.protect);
                if (!r.module_name.empty()) rj["module"] = r.module_name;
                arr.push_back(rj);
            }
            json result;
            result["count"] = arr.size();
            result["regions"] = arr;
            return tool_result_t::ok(
                OBFSTR("Memory map: ") + std::to_string(arr.size()) + OBFSTR(" regions."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_add_watch"), OBFSTR("debugger"),
        OBFSTR("Add a watch expression. Supports register names (rax, rsp, etc.) and hex addresses."),
        {{OBFSTR("expression"), OBFSTR("string"), OBFSTR("Watch expression"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_add_watch: entry");
            if (!params.contains("expression") || !params["expression"].is_string())
                return tool_result_t::error(OBFSTR("'expression' is required."));
            const std::string expr = params["expression"].get<std::string>();
            diag::log_tagged_fmt("dbg_tools", "dbg_add_watch: expr=%s", expr.c_str());
            debugger_engine::add_watch(expr);
            debugger_engine::refresh_watches();
            diag::log_tagged_fmt("dbg_tools", "dbg_add_watch: watch added and refreshed");
            return tool_result_t::ok(OBFSTR("Watch added."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_remove_watch"), OBFSTR("debugger"),
        OBFSTR("Remove a watch by index."),
        {{OBFSTR("index"), OBFSTR("number"), OBFSTR("Watch index"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_watch: entry");
            if (!params.contains("index") || !params["index"].is_number())
                return tool_result_t::error(OBFSTR("'index' required."));
            int idx = params["index"].get<int>();
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_watch: removing watch idx=%d", idx);
            debugger_engine::remove_watch(idx);
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_watch: removed");
            return tool_result_t::ok(OBFSTR("Watch removed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_watches"), OBFSTR("debugger"),
        OBFSTR("Get all watch expressions and their current values."),
        {},
        [](const json& ) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_watches: entry");
            debugger_engine::refresh_watches();
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.watch_mutex);
            json arr = json::array();
            for (size_t i = 0; i < st.watches.size(); ++i) {
                json wj;
                wj["index"] = i;
                wj["expression"] = st.watches[i].expression;
                wj["value"] = st.watches[i].value;
                wj["valid"] = st.watches[i].valid;
                wj["error"] = st.watches[i].error;
                arr.push_back(wj);
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_get_watches: returning %zu watches", arr.size());
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" watches."), arr);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_start_trace"), OBFSTR("debugger"),
        OBFSTR("Start instruction tracing on the attached process. Each step records address, "
               "disassembly, and register state."),
        {{OBFSTR("max_records"), OBFSTR("number"), OBFSTR("Maximum trace records to keep (default 50000)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_start_trace: entry");
            if (auto err = ensure_attached(params)) return *err;
            int max_records = params.value("max_records", 50000);
            diag::log_tagged_fmt("dbg_tools", "dbg_start_trace: max_records=%d", max_records);
            debugger_engine::start_trace(max_records);
            diag::log_tagged_fmt("dbg_tools", "dbg_start_trace: trace started");
            return tool_result_t::ok(OBFSTR("Trace started."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_stop_trace"), OBFSTR("debugger"),
        OBFSTR("Stop instruction tracing."),
        {},
        [](const json& ) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_stop_trace: entry");
            debugger_engine::stop_trace();
            diag::log_tagged_fmt("dbg_tools", "dbg_stop_trace: trace stopped");
            return tool_result_t::ok(OBFSTR("Trace stopped."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_trace"), OBFSTR("debugger"),
        OBFSTR("Get recorded trace entries. Returns instruction addresses, disassembly, and register diffs."),
        {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start index (default 0)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max entries to return (default 200)"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_trace: entry");
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.trace_mutex);
            int offset = params.value("offset", 0);
            int limit = params.value("limit", 200);
            if (limit > 1000) limit = 1000;
            json arr = json::array();
            for (int i = offset; i < static_cast<int>(st.trace_log.size()) && i < offset + limit; ++i) {
                auto& tr = st.trace_log[static_cast<size_t>(i)];
                json tj;
                tj["index"] = tr.index;
                tj["address"] = sa_format_address(tr.address);
                tj["disasm"] = tr.disasm_text;
                arr.push_back(tj);
            }
            json result;
            result["total"] = st.trace_log.size();
            result["returned"] = arr.size();
            result["entries"] = arr;
            diag::log_tagged_fmt("dbg_tools", "dbg_get_trace: total=%zu returned=%zu", st.trace_log.size(), arr.size());
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" trace entries."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_set_comment"), OBFSTR("debugger"),
        OBFSTR("Set a comment annotation at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true},
         {OBFSTR("text"), OBFSTR("string"), OBFSTR("Comment text"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_set_comment: entry");
            if (!params.contains("address") || !params.contains("text"))
                return tool_result_t::error(OBFSTR("'address' and 'text' required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            const std::string text = params["text"].get<std::string>();
            diag::log_tagged_fmt("dbg_tools", "dbg_set_comment: addr=0x%llX text=%s", (unsigned long long)*addr, text.c_str());
            debugger_engine::set_comment(*addr, text);
            return tool_result_t::ok(OBFSTR("Comment set at ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_set_label"), OBFSTR("debugger"),
        OBFSTR("Set a label (name) at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true},
         {OBFSTR("text"), OBFSTR("string"), OBFSTR("Label text"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_set_label: entry");
            if (!params.contains("address") || !params.contains("text"))
                return tool_result_t::error(OBFSTR("'address' and 'text' required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            const std::string text = params["text"].get<std::string>();
            diag::log_tagged_fmt("dbg_tools", "dbg_set_label: addr=0x%llX text=%s", (unsigned long long)*addr, text.c_str());
            debugger_engine::set_label(*addr, text);
            return tool_result_t::ok(OBFSTR("Label set at ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_toggle_bookmark"), OBFSTR("debugger"),
        OBFSTR("Toggle a bookmark at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_bookmark: entry");
            if (!params.contains("address"))
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_bookmark: addr=0x%llX", (unsigned long long)*addr);
            debugger_engine::toggle_bookmark(*addr);
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_bookmark: toggled");
            return tool_result_t::ok(OBFSTR("Bookmark toggled at ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_find_strings"), OBFSTR("debugger"),
        OBFSTR("Find ASCII strings in the memory of the attached process. Results include address, "
               "string value, and containing module."),
        {{OBFSTR("min_length"), OBFSTR("number"), OBFSTR("Minimum string length (default 4)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_find_strings: entry");
            if (auto err = ensure_attached(params)) return *err;
            int min_len = params.value("min_length", 4);
            diag::log_tagged_fmt("dbg_tools", "dbg_find_strings: min_length=%d", min_len);
            debugger_engine::find_strings(min_len);
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.strings_mutex);
            json arr = json::array();
            int count = 0;
            for (const auto& s : st.strings) {
                if (count++ >= 500) break;
                json sj;
                sj["address"] = sa_format_address(s.address);
                sj["value"] = s.value;
                if (!s.module_name.empty()) sj["module"] = s.module_name;
                arr.push_back(sj);
            }
            json result;
            result["total"] = st.strings.size();
            result["returned"] = arr.size();
            result["strings"] = arr;
            diag::log_tagged_fmt("dbg_tools", "dbg_find_strings: total=%zu returned=%d", st.strings.size(), count < 500 ? count : 500);
            return tool_result_t::ok(
                std::to_string(st.strings.size()) + OBFSTR(" strings found."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_enumerate_handles"), OBFSTR("debugger"),
        OBFSTR("Enumerate open handles in the attached process (requires NtQuerySystemInformation)."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_enumerate_handles: entry");
            if (auto err = ensure_attached(params)) return *err;
            diag::log_tagged_fmt("dbg_tools", "dbg_enumerate_handles: calling enumerate_handles");
            debugger_engine::enumerate_handles();
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.handle_mutex);
            json arr = json::array();
            for (const auto& h : st.handles) {
                json hj;
                hj["handle"] = h.handle;
                hj["type"] = h.type_name;
                hj["name"] = h.name;
                arr.push_back(hj);
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_enumerate_handles: returning %zu handles", arr.size());
            json result;
            result["count"] = arr.size();
            result["handles"] = arr;
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" handles."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_add_hw_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Set a hardware breakpoint using debug registers (DR0-DR3). "
               "Does not modify code bytes, so it is transparent to anti-tamper. "
               "Limited to 4 active hardware breakpoints."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true},
         {OBFSTR("type"), OBFSTR("string"), OBFSTR("Type: 'execute', 'write', 'read' (default 'execute')"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Watch granularity in bytes: 1, 2, 4, or 8 (default 1; ignored for 'execute')"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_add_hw_breakpoint: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            std::string type_str = params.value("type", "execute");
            debugger_engine::bp_type_t bpt = debugger_engine::bp_type_t::hardware_execute;
            if (type_str == "write") bpt = debugger_engine::bp_type_t::hardware_write;
            else if (type_str == "read") bpt = debugger_engine::bp_type_t::hardware_read;
            int size = 1;
            if (params.contains("size") && params["size"].is_number())
                size = params["size"].get<int>();
            if (size != 1 && size != 2 && size != 4 && size != 8)
                return tool_result_t::error(OBFSTR("'size' must be 1, 2, 4, or 8."));
            diag::log_tagged_fmt("dbg_tools", "dbg_add_hw_breakpoint: addr=0x%llX type=%s size=%d", (unsigned long long)*addr, type_str.c_str(), size);
            int idx = debugger_engine::add_breakpoint(*addr, bpt, "", "", size);
            if (idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "dbg_add_hw_breakpoint: add_breakpoint failed: %s", debugger_engine::last_error().c_str());
                return tool_result_t::error(debugger_engine::last_error());
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_add_hw_breakpoint: HW BP set at 0x%llX idx=%d", (unsigned long long)*addr, idx);
            return tool_result_t::ok(OBFSTR("Hardware breakpoint set at ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_toggle_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Toggle a breakpoint on or off by its index in the breakpoint list."),
        {{OBFSTR("index"), OBFSTR("number"), OBFSTR("Breakpoint index"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_breakpoint: entry");
            if (!params.contains("index") || !params["index"].is_number())
                return tool_result_t::error(OBFSTR("'index' is required."));
            int idx = params["index"].get<int>();
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_breakpoint: toggling idx=%d", idx);
            if (!debugger_engine::toggle_breakpoint(idx)) {
                diag::log_tagged_fmt("dbg_tools", "dbg_toggle_breakpoint: toggle failed for idx=%d", idx);
                return tool_result_t::error(OBFSTR("Failed to toggle breakpoint at index ") + std::to_string(idx));
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_breakpoint: toggled idx=%d", idx);
            return tool_result_t::ok(OBFSTR("Breakpoint toggled."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_clear_all_breakpoints"), OBFSTR("debugger"),
        OBFSTR("Remove all breakpoints (software and hardware)."),
        {},
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_clear_all_breakpoints: entry");
            debugger_engine::clear_all_breakpoints();
            diag::log_tagged_fmt("dbg_tools", "dbg_clear_all_breakpoints: all breakpoints cleared");
            return tool_result_t::ok(OBFSTR("All breakpoints cleared."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_comment"), OBFSTR("debugger"),
        OBFSTR("Get the comment annotation at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_comment: entry");
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            std::string text = debugger_engine::get_comment(*addr);
            diag::log_tagged_fmt("dbg_tools", "dbg_get_comment: addr=0x%llX comment=%s", (unsigned long long)*addr, text.c_str());
            json result;
            result["address"] = sa_format_address(*addr);
            result["comment"] = text;
            return tool_result_t::ok(text.empty() ? OBFSTR("No comment at this address.") : text, result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_label"), OBFSTR("debugger"),
        OBFSTR("Get the label (name) at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_label: entry");
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            std::string text = debugger_engine::get_label(*addr);
            diag::log_tagged_fmt("dbg_tools", "dbg_get_label: addr=0x%llX label=%s", (unsigned long long)*addr, text.c_str());
            json result;
            result["address"] = sa_format_address(*addr);
            result["label"] = text;
            return tool_result_t::ok(text.empty() ? OBFSTR("No label at this address.") : text, result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_bookmarks"), OBFSTR("debugger"),
        OBFSTR("Get all bookmarked addresses."),
        {},
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_bookmarks: entry");
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.anno_mutex);
            json arr = json::array();
            for (auto addr : st.bookmarks)
                arr.push_back(sa_format_address(addr));
            json result;
            result["count"] = arr.size();
            result["bookmarks"] = arr;
            diag::log_tagged_fmt("dbg_tools", "dbg_get_bookmarks: returning %zu bookmarks", arr.size());
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" bookmark(s)."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_xrefs_to"), OBFSTR("debugger"),
        OBFSTR("Get cross-references to a target address. Scans for CALL, JMP, Jcc, LEA and data refs that point to the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address (hex)"), true},
         {OBFSTR("max_results"), OBFSTR("number"), OBFSTR("Maximum results to return (default 100)"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_xrefs_to: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            int max_results = params.value("max_results", 100);
            if (max_results <= 0) max_results = 100;
            if (max_results > 10000) max_results = 10000;
            diag::log_tagged_fmt("dbg_tools", "dbg_get_xrefs_to: addr=0x%llX max_results=%d", (unsigned long long)*addr, max_results);
            auto modules = driver_bridge::enumerate_modules();
            uint64_t search_start = 0;
            uint64_t search_size = 0;
            for (const auto& m : modules) {
                if (*addr >= m.base && *addr < m.base + m.size) {
                    search_start = m.base;
                    search_size = m.size;
                    break;
                }
            }
            if (search_size == 0) {
                search_start = (*addr > 0x10000) ? *addr - 0x10000 : 0;
                search_size = 0x20000;
            }
            xref_engine::find_xrefs_to(*addr, search_start, search_size);
            for (int i = 0; i < 300; ++i) {
                if (!xref_engine::g_state.scanning.load()) break;
                Sleep(10);
            }
            if (xref_engine::g_state.scanning.load()) {
                diag::log_tagged_fmt("dbg_tools", "dbg_get_xrefs_to: scan timeout, cancelling");
                xref_engine::cancel_scan();
            }
            std::lock_guard<std::mutex> lk(xref_engine::g_state.mutex);
            json arr = json::array();
            size_t n = std::min(static_cast<size_t>(max_results), xref_engine::g_state.results.size());
            for (size_t i = 0; i < n; ++i) {
                const auto& x = xref_engine::g_state.results[i];
                json xj;
                xj["from"] = sa_format_address(x.from_addr);
                xj["to"] = sa_format_address(x.to_addr);
                xj["type"] = xref_engine::xref_type_name(x.type);
                xj["disasm"] = x.disasm_text;
                if (!x.module_name.empty()) xj["module"] = x.module_name;
                arr.push_back(std::move(xj));
            }
            json result;
            result["count"] = arr.size();
            result["total"] = xref_engine::g_state.results.size();
            result["xrefs"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_get_xrefs_to: found %zu xrefs to 0x%llX", xref_engine::g_state.results.size(), (unsigned long long)*addr);
            return tool_result_t::ok(
                std::to_string(result["count"].get<size_t>()) + OBFSTR(" xref(s) to ") + sa_format_address(*addr), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_xrefs_from"), OBFSTR("debugger"),
        OBFSTR("Get cross-references from a source address. Follows instructions and collects all outgoing CALL, JMP, Jcc, LEA and data refs."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Source address (hex)"), true},
         {OBFSTR("max_results"), OBFSTR("number"), OBFSTR("Maximum instructions to scan (default 200)"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_xrefs_from: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            int max_insns = params.value("max_results", 200);
            if (max_insns <= 0) max_insns = 200;
            if (max_insns > 10000) max_insns = 10000;
            std::vector<xref_engine::xref_t> xrefs;
            xref_engine::find_xrefs_from(*addr, static_cast<size_t>(max_insns), xrefs);
            json arr = json::array();
            for (const auto& x : xrefs) {
                json xj;
                xj["from"] = sa_format_address(x.from_addr);
                xj["to"] = sa_format_address(x.to_addr);
                xj["type"] = xref_engine::xref_type_name(x.type);
                xj["disasm"] = x.disasm_text;
                if (!x.module_name.empty()) xj["module"] = x.module_name;
                arr.push_back(std::move(xj));
            }
            json result;
            result["count"] = arr.size();
            result["xrefs"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_get_xrefs_from: found %zu xrefs from 0x%llX", xrefs.size(), (unsigned long long)*addr);
            return tool_result_t::ok(
                std::to_string(result["count"].get<size_t>()) + OBFSTR(" xref(s) from ") + sa_format_address(*addr), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_scan_xrefs"), OBFSTR("debugger"),
        OBFSTR("Scan a memory range for cross-references that target a specific address."),
        {{OBFSTR("target_address"), OBFSTR("string"), OBFSTR("Address to find references to (hex)"), true},
         {OBFSTR("start_address"), OBFSTR("string"), OBFSTR("Start of scan range (hex)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Size of range in bytes (default 0x10000)"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_scan_xrefs: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("target_address") || !params["target_address"].is_string())
                return tool_result_t::error(OBFSTR("'target_address' is required."));
            if (!params.contains("start_address") || !params["start_address"].is_string())
                return tool_result_t::error(OBFSTR("'start_address' is required."));
            auto target = sa_parse_address(params["target_address"].get<std::string>());
            if (!target) return tool_result_t::error(OBFSTR("Invalid target_address."));
            auto start = sa_parse_address(params["start_address"].get<std::string>());
            if (!start) return tool_result_t::error(OBFSTR("Invalid start_address."));
            uint64_t size = params.value("size", 0x10000);
            if (size == 0) size = 0x10000;
            if (size > 0x1000000) size = 0x1000000;
            xref_engine::find_xrefs_to(*target, *start, size);
            for (int i = 0; i < 300; ++i) {
                if (!xref_engine::g_state.scanning.load()) break;
                Sleep(10);
            }
            if (xref_engine::g_state.scanning.load()) {
                diag::log_tagged_fmt("dbg_tools", "dbg_scan_xrefs: scan timeout, cancelling");
                xref_engine::cancel_scan();
            }
            std::lock_guard<std::mutex> lk(xref_engine::g_state.mutex);
            json result;
            result["total_found"] = xref_engine::g_state.results.size();
            result["target"] = sa_format_address(*target);
            result["range_start"] = sa_format_address(*start);
            result["range_size"] = size;
            diag::log_tagged_fmt("dbg_tools", "dbg_scan_xrefs: target=0x%llX start=0x%llX size=0x%llX results=%zu", (unsigned long long)*target, (unsigned long long)*start, (unsigned long long)size, xref_engine::g_state.results.size());
            return tool_result_t::ok(
                OBFSTR("Scan complete. ") + std::to_string(xref_engine::g_state.results.size()) + OBFSTR(" xref(s) found."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_build_cfg"), OBFSTR("debugger"),
        OBFSTR("Build a control flow graph starting from an address. Disassembles and splits into basic blocks with edges."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Entry address to build CFG from (hex)"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_build_cfg: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            diag::log_tagged_fmt("dbg_tools", "dbg_build_cfg: building CFG from 0x%llX", (unsigned long long)*addr);
            cfg_view::build_cfg(*addr);
            for (int i = 0; i < 300; ++i) {
                if (!cfg_view::g_state.building.load()) break;
                Sleep(10);
            }
            std::lock_guard<std::mutex> lk(cfg_view::g_state.mutex);
            json result;
            result["entry"] = sa_format_address(*addr);
            result["blocks"] = cfg_view::g_state.blocks.size();
            result["built"] = cfg_view::g_state.built;
            diag::log_tagged_fmt("dbg_tools", "dbg_build_cfg: CFG built for 0x%llX with %zu blocks", (unsigned long long)*addr, cfg_view::g_state.blocks.size());
            return tool_result_t::ok(
                OBFSTR("CFG built: ") + std::to_string(cfg_view::g_state.blocks.size()) + OBFSTR(" blocks."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_cfg"), OBFSTR("debugger"),
        OBFSTR("Get the current control flow graph state, including all basic blocks, instructions, and edges."),
        {},
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_cfg: entry");
            std::lock_guard<std::mutex> lk(cfg_view::g_state.mutex);
            if (!cfg_view::g_state.built) {
                diag::log_tagged_fmt("dbg_tools", "dbg_get_cfg: no CFG built yet");
                return tool_result_t::error(OBFSTR("No CFG built. Call dbg_build_cfg first."));
            }
            json blocks_arr = json::array();
            for (size_t bi = 0; bi < cfg_view::g_state.blocks.size(); ++bi) {
                const auto& blk = cfg_view::g_state.blocks[bi];
                json bj;
                bj["index"] = bi;
                bj["start"] = sa_format_address(blk.start_addr);
                bj["end"] = sa_format_address(blk.end_addr);
                bj["is_entry"] = blk.is_entry;
                json insns = json::array();
                for (const auto& ins : blk.instructions) {
                    json ij;
                    ij["addr"] = sa_format_address(ins.addr);
                    ij["text"] = ins.text;
                    insns.push_back(std::move(ij));
                }
                bj["instructions"] = std::move(insns);
                bj["successors"] = blk.successors;
                blocks_arr.push_back(std::move(bj));
            }
            json result;
            result["entry"] = sa_format_address(cfg_view::g_state.entry_addr);
            result["block_count"] = cfg_view::g_state.blocks.size();
            result["blocks"] = std::move(blocks_arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_get_cfg: returning %zu blocks entry=0x%llX", cfg_view::g_state.blocks.size(), (unsigned long long)cfg_view::g_state.entry_addr);
            return tool_result_t::ok(
                OBFSTR("CFG: ") + std::to_string(cfg_view::g_state.blocks.size()) + OBFSTR(" blocks."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_seh_chain"), OBFSTR("debugger"),
        OBFSTR("Get the SEH (Structured Exception Handler) chain of the attached process."),
        {},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_seh_chain: entry");
            if (auto err = ensure_attached(params)) return *err;
            diag::log_tagged_fmt("dbg_tools", "dbg_get_seh_chain: calling seh_view::refresh");
            seh_view::refresh();
            Sleep(500);
            std::lock_guard<std::mutex> lk(seh_view::g_ui.mutex);
            json arr = json::array();
            for (const auto& e : seh_view::g_ui.entries) {
                json ej;
                ej["index"] = e.index;
                ej["handler_addr"] = sa_format_address(e.handler_addr);
                ej["filter_addr"] = sa_format_address(e.filter_addr);
                ej["frame_addr"] = sa_format_address(e.frame_addr);
                if (!e.module_name.empty()) ej["module"] = e.module_name;
                if (!e.handler_name.empty()) ej["handler_name"] = e.handler_name;
                arr.push_back(std::move(ej));
            }
            json result;
            result["count"] = arr.size();
            result["entries"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_get_seh_chain: returning %zu SEH handlers", arr.size());
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" SEH handler(s)."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_modules_detail"), OBFSTR("debugger"),
        OBFSTR("Get detailed module information with PE analysis including exports and imports."),
        {{OBFSTR("module_name"), OBFSTR("string"), OBFSTR("Optional module name filter"), false},
         {OBFSTR("max_modules"), OBFSTR("number"), OBFSTR("Maximum modules to inspect deeply"), false},
         {OBFSTR("max_exports"), OBFSTR("number"), OBFSTR("Maximum exports per module"), false},
         {OBFSTR("max_imports"), OBFSTR("number"), OBFSTR("Maximum imports per module"), false},
         {OBFSTR("timeout_ms"), OBFSTR("number"), OBFSTR("Maximum elapsed time before returning partial results"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_modules_detail: entry");
            if (auto err = ensure_attached(params)) return *err;
            diag::log_tagged_fmt("dbg_tools", "dbg_get_modules_detail: calling module_view::refresh");
            module_view::refresh();
            const int timeout_ms = int_param_clamped(params, "timeout_ms", 5000, 500, 60000);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            while (module_view::g_ui.loading.load(std::memory_order_acquire) && !deadline_expired(deadline))
                Sleep(25);
            std::string filter;
            if (params.contains("module_name") && params["module_name"].is_string())
                filter = params["module_name"].get<std::string>();
            const int default_modules = filter.empty() ? 8 : 1;
            const int max_modules = int_param_clamped(params, "max_modules", default_modules, 1, 256);
            const int max_exports = int_param_clamped(params, "max_exports", 50, 0, 1000);
            const int max_imports = int_param_clamped(params, "max_imports", 50, 0, 1000);
            std::vector<driver_bridge::module_info_t> mods;
            {
                std::lock_guard<std::mutex> lk(module_view::g_ui.modules_mutex);
                mods = module_view::g_ui.modules;
            }
            json arr = json::array();
            bool truncated = false;
            bool timed_out = false;
            for (const auto& m : mods) {
                if (arr.size() >= static_cast<size_t>(max_modules)) {
                    truncated = true;
                    break;
                }
                if (deadline_expired(deadline)) {
                    timed_out = true;
                    truncated = true;
                    break;
                }
                if (!filter.empty()) {
                    std::string lower_name = m.name;
                    std::string lower_filter = filter;
                    for (auto& c : lower_name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    for (auto& c : lower_filter) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (lower_name.find(lower_filter) == std::string::npos)
                        continue;
                }
                json mj;
                mj["name"] = m.name;
                mj["base"] = sa_format_address(m.base);
                mj["size"] = m.size;
                pe_parser::pe_info_t pe;
                if (pe_parser::parse(m.base, pe, false)) {
                    mj["entry_point"] = sa_format_address(pe.entry_point);
                    mj["is_64bit"] = pe.is_64bit;
                    json sections = json::array();
                    for (const auto& s : pe.sections) {
                        json sj;
                        sj["name"] = s.name;
                        sj["virtual_address"] = s.virtual_address;
                        sj["virtual_size"] = s.virtual_size;
                        sj["characteristics"] = pe_parser::format_characteristics(s.characteristics);
                        sections.push_back(std::move(sj));
                    }
                    mj["sections"] = std::move(sections);
                    std::vector<pe_parser::export_entry_t> exports;
                    bool exports_truncated = false;
                    pe_parser::parse_exports(m.base, pe, exports, static_cast<size_t>(max_exports), &deadline, &exports_truncated);
                    if (exports_truncated) truncated = true;
                    mj["export_count"] = exports.size();
                    mj["exports_truncated"] = exports_truncated;
                    json exp_arr = json::array();
                    size_t exp_limit = std::min<size_t>(exports.size(), static_cast<size_t>(max_exports));
                    for (size_t ei = 0; ei < exp_limit; ++ei) {
                        json ej;
                        ej["ordinal"] = exports[ei].ordinal;
                        ej["name"] = exports[ei].name;
                        ej["address"] = sa_format_address(exports[ei].address);
                        if (exports[ei].is_forwarded) ej["forward"] = exports[ei].forward_name;
                        exp_arr.push_back(std::move(ej));
                    }
                    mj["exports"] = std::move(exp_arr);
                    std::vector<pe_parser::import_entry_t> imports;
                    bool imports_truncated = false;
                    pe_parser::parse_imports(m.base, pe, imports, static_cast<size_t>(max_imports), &deadline, &imports_truncated);
                    if (imports_truncated) truncated = true;
                    if (deadline_expired(deadline)) timed_out = true;
                    mj["import_count"] = imports.size();
                    mj["imports_truncated"] = imports_truncated;
                    json imp_arr = json::array();
                    size_t imp_limit = std::min<size_t>(imports.size(), static_cast<size_t>(max_imports));
                    for (size_t ii = 0; ii < imp_limit; ++ii) {
                        json ij;
                        ij["module"] = imports[ii].module_name;
                        ij["function"] = imports[ii].function_name;
                        ij["iat_address"] = sa_format_address(imports[ii].iat_address);
                        imp_arr.push_back(std::move(ij));
                    }
                    mj["imports"] = std::move(imp_arr);
                }
                arr.push_back(std::move(mj));
            }
            json result;
            result["count"] = arr.size();
            result["truncated"] = truncated;
            result["timed_out"] = timed_out;
            result["max_modules"] = max_modules;
            result["max_exports"] = max_exports;
            result["max_imports"] = max_imports;
            result["timeout_ms"] = timeout_ms;
            result["modules"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_get_modules_detail: returning %zu modules truncated=%d timed_out=%d",
                arr.size(), truncated ? 1 : 0, timed_out ? 1 : 0);
            return tool_result_t::ok(
                std::to_string(result["count"].get<size_t>()) + OBFSTR(" module(s)."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_add_patch"), OBFSTR("debugger"),
        OBFSTR("Apply a code patch at an address. Overwrites bytes and saves original for reverting."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to patch (hex)"), true},
         {OBFSTR("bytes"), OBFSTR("string"), OBFSTR("Hex bytes to write (e.g. '90 90 90')"), true},
         {OBFSTR("label"), OBFSTR("string"), OBFSTR("Optional description for this patch"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            if (!params.contains("bytes") || !params["bytes"].is_string())
                return tool_result_t::error(OBFSTR("'bytes' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            auto patched = code_patcher::parse_bytes(params["bytes"].get<std::string>());
            if (patched.empty()) {
                diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: invalid hex bytes");
                return tool_result_t::error(OBFSTR("Invalid hex bytes."));
            }
            std::string label;
            if (params.contains("label") && params["label"].is_string())
                label = params["label"].get<std::string>();
            diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: addr=0x%llX size=%zu label=%s", (unsigned long long)*addr, patched.size(), label.c_str());
            int idx = code_patcher::create_patch(*addr, patched, label);
            if (idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: create_patch failed");
                return tool_result_t::error(OBFSTR("Failed to create patch."));
            }
            if (!code_patcher::apply_patch(idx)) {
                diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: apply_patch failed for idx=%d", idx);
                return tool_result_t::error(OBFSTR("Patch created but failed to apply."));
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: patch applied at 0x%llX idx=%d", (unsigned long long)*addr, idx);
            json result;
            result["index"] = idx;
            result["address"] = sa_format_address(*addr);
            result["size"] = patched.size();
            result["bytes"] = code_patcher::format_bytes(patched);
            return tool_result_t::ok(
                OBFSTR("Patch applied at ") + sa_format_address(*addr) + OBFSTR(" (") + std::to_string(patched.size()) + OBFSTR(" bytes)."), result);
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_remove_patch"), OBFSTR("debugger"),
        OBFSTR("Remove a code patch by index. Reverts original bytes before removing."),
        {{OBFSTR("index"), OBFSTR("number"), OBFSTR("Patch index to remove"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: entry");
            if (!params.contains("index") || !params["index"].is_number())
                return tool_result_t::error(OBFSTR("'index' is required."));
            int idx = params["index"].get<int>();
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: reverting and removing idx=%d", idx);
            if (!code_patcher::revert_patch(idx)) {
                diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: revert_patch failed for idx=%d", idx);
                return tool_result_t::error(OBFSTR("Failed to revert patch."));
            }
            if (!code_patcher::remove_patch(idx)) {
                diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: remove_patch failed for idx=%d", idx);
                return tool_result_t::error(OBFSTR("Failed to remove patch."));
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: patch removed idx=%d", idx);
            return tool_result_t::ok(OBFSTR("Patch removed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_list_patches"), OBFSTR("debugger"),
        OBFSTR("List all code patches with their status, addresses, and byte values."),
        {},
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_list_patches: entry");
            std::lock_guard<std::mutex> lk(code_patcher::g_state.mtx);
            json arr = json::array();
            for (size_t i = 0; i < code_patcher::g_state.patches.size(); ++i) {
                const auto& p = code_patcher::g_state.patches[i];
                json pj;
                pj["index"] = i;
                pj["address"] = sa_format_address(p.address);
                pj["original_bytes"] = code_patcher::format_bytes(p.original_bytes);
                pj["patched_bytes"] = code_patcher::format_bytes(p.patched_bytes);
                pj["description"] = p.description;
                pj["active"] = p.active;
                arr.push_back(std::move(pj));
            }
            json result;
            result["count"] = arr.size();
            result["patches"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_list_patches: returning %zu patches", arr.size());
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" patch(es)."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_nop_fill"), OBFSTR("debugger"),
        OBFSTR("NOP-fill a range of bytes at the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to start NOP fill (hex)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Number of bytes to NOP"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_nop_fill: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            if (!params.contains("size") || !params["size"].is_number())
                return tool_result_t::error(OBFSTR("'size' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            int size = params["size"].get<int>();
            if (size <= 0 || size > 4096)
                return tool_result_t::error(OBFSTR("Size must be between 1 and 4096."));
            diag::log_tagged_fmt("dbg_tools", "dbg_nop_fill: addr=0x%llX size=%d", (unsigned long long)*addr, size);
            if (!code_patcher::nop_region(*addr, static_cast<size_t>(size), OBFSTR("NOP fill"))) {
                diag::log_tagged_fmt("dbg_tools", "dbg_nop_fill: nop_region failed at 0x%llX", (unsigned long long)*addr);
                return tool_result_t::error(OBFSTR("Failed to NOP-fill region."));
            }
            int idx = static_cast<int>(code_patcher::count()) - 1;
            if (!code_patcher::apply_patch(idx))
                return tool_result_t::error(OBFSTR("NOP patch created but failed to apply."));
            json result;
            result["address"] = sa_format_address(*addr);
            result["size"] = size;
            diag::log_tagged_fmt("dbg_tools", "dbg_nop_fill: NOP-filled %d bytes at 0x%llX", size, (unsigned long long)*addr);
            return tool_result_t::ok(
                OBFSTR("NOP-filled ") + std::to_string(size) + OBFSTR(" bytes at ") + sa_format_address(*addr), result);
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_find_code_caves"), OBFSTR("debugger"),
        OBFSTR("Find regions of unused bytes (code caves) near a given address. Searches for consecutive 0x00 or 0xCC bytes."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Module base or search start address (hex)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Size of region to scan (default 0x1000)"), false},
         {OBFSTR("min_cave_size"), OBFSTR("number"), OBFSTR("Minimum cave size in bytes (default 16)"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_find_code_caves: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            uint32_t size = static_cast<uint32_t>(params.value("size", 0x1000));
            if (size == 0) size = 0x1000;
            size_t min_size = static_cast<size_t>(params.value("min_cave_size", 16));
            if (min_size == 0) min_size = 16;
            diag::log_tagged_fmt("dbg_tools", "dbg_find_code_caves: addr=0x%llX size=0x%X min_size=%zu", (unsigned long long)*addr, size, min_size);
            auto caves = code_patcher::find_code_caves(*addr, size, min_size);
            json arr = json::array();
            for (const auto& c : caves) {
                json cj;
                cj["address"] = sa_format_address(c.address);
                cj["size"] = c.size;
                if (!c.module_name.empty()) cj["module"] = c.module_name;
                arr.push_back(std::move(cj));
            }
            json result;
            result["count"] = arr.size();
            result["caves"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_find_code_caves: found %zu caves", caves.size());
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" code cave(s) found."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_conditional_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Set a breakpoint with a condition expression. The breakpoint will only trigger when the condition is met."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address for breakpoint (hex)"), true},
         {OBFSTR("condition"), OBFSTR("string"), OBFSTR("Condition expression (e.g. 'rax == 0x1234')"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_conditional_breakpoint: entry");
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            if (!params.contains("condition") || !params["condition"].is_string())
                return tool_result_t::error(OBFSTR("'condition' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            std::string cond = params["condition"].get<std::string>();
            diag::log_tagged_fmt("dbg_tools", "dbg_conditional_breakpoint: addr=0x%llX cond=%s", (unsigned long long)*addr, cond.c_str());
            int bp_idx = debugger_engine::add_breakpoint(*addr, debugger_engine::bp_type_t::software, "", cond);
            if (bp_idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "dbg_conditional_breakpoint: add_breakpoint failed: %s", debugger_engine::last_error().c_str());
                return tool_result_t::error(OBFSTR("Failed to add breakpoint."));
            }
            json result;
            result["index"] = bp_idx;
            result["address"] = sa_format_address(*addr);
            result["condition"] = cond;
            diag::log_tagged_fmt("dbg_tools", "dbg_conditional_breakpoint: BP set at 0x%llX idx=%d cond=%s", (unsigned long long)*addr, bp_idx, cond.c_str());
            return tool_result_t::ok(
                OBFSTR("Conditional breakpoint set at ") + sa_format_address(*addr) + OBFSTR(" [condition: ") + cond + OBFSTR("]"), result);
        }, false});

	srv.register_tool({
		"enable_stealth",
		"Enable anti-anti-debug stealth mode for the attached process. Spoofs PEB debug flags, hooks RDTSC to return fake timestamps, and patches known anti-debug checks.",
		{
			{"process_id", "integer", "PID to enable stealth on (uses attached if omitted)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			diag::log_tagged_fmt("dbg_tools", "enable_stealth: entry");
			if (auto err = ensure_attached(params)) return *err;

			uint32_t pid = device->get_process_id();
			if (pid == 0) {
				diag::log_tagged_fmt("dbg_tools", "enable_stealth: not attached to any process");
				return tool_result_t::error("Not attached to a process.");
			}

			if (stealth_engine::is_active()) {
				diag::log_tagged_fmt("dbg_tools", "enable_stealth: already active");
				return tool_result_t::error("Stealth mode is already active.");
			}

			diag::log_tagged_fmt("dbg_tools", "enable_stealth: enabling for pid=%u", pid);
			bool ok = stealth_engine::enable_stealth(pid);
			if (!ok) {
				diag::log_tagged_fmt("dbg_tools", "enable_stealth: enable_stealth failed for pid=%u", pid);
				return tool_result_t::error("Failed to enable stealth mode.");
			}

			auto status = stealth_engine::get_session_info();
			diag::log_tagged_fmt("dbg_tools", "enable_stealth: active pid=%u peb_spoofed=%d hooks=%zu", pid, (int)status.peb_spoofed, status.hooks.size());
			json result;
			result["status"] = "active";
			result["pid"] = pid;
			result["peb_spoofed"] = status.peb_spoofed;
			result["rdtsc_hooks"] = static_cast<int>(status.hooks.size());
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"disable_stealth",
		"Disable anti-anti-debug stealth mode and restore all patches and hooks.",
		{},
		true,
		[](const json&) -> tool_result_t {
			diag::log_tagged_fmt("dbg_tools", "disable_stealth: entry");
			if (!stealth_engine::is_active()) {
				diag::log_tagged_fmt("dbg_tools", "disable_stealth: stealth not active");
				return tool_result_t::error("Stealth mode is not active.");
			}

			diag::log_tagged_fmt("dbg_tools", "disable_stealth: disabling stealth");
			stealth_engine::disable_stealth();

			diag::log_tagged_fmt("dbg_tools", "disable_stealth: stealth disabled");
			json result;
			result["status"] = "disabled";
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"stealth_status",
		"Get current stealth engine status including active hooks and PEB spoofing state.",
		{},
		true,
		[](const json&) -> tool_result_t {
			diag::log_tagged_fmt("dbg_tools", "stealth_status: entry");
			json result;
			result["active"] = stealth_engine::is_active();
			diag::log_tagged_fmt("dbg_tools", "stealth_status: active=%d", (int)stealth_engine::is_active());

			if (stealth_engine::is_active()) {
				auto status = stealth_engine::get_session_info();
				result["pid"] = status.pid;
				result["peb_spoofed"] = status.peb_spoofed;
				result["rdtsc_hooks"] = static_cast<int>(status.hooks.size());

				json hooks_arr = json::array();
				for (auto& h : status.hooks) {
					json hobj;
					char abuf[32];
					std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(h.target_addr));
					hobj["address"] = abuf;
					char tbuf[32];
					std::snprintf(tbuf, sizeof(tbuf), "0x%llX", static_cast<unsigned long long>(h.trampoline_addr));
					hobj["trampoline"] = tbuf;
					hobj["active"] = h.active;
					hooks_arr.push_back(hobj);
				}
				result["hooks"] = hooks_arr;
			}

			return tool_result_t::ok(result);
		}
	});
}

}
