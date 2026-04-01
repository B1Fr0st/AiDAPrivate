// debugger_tools_standalone.cpp — High-level debugger analysis tools for AiDA Standalone.
// Provides managed software breakpoints, call stack unwinding, execution state
// snapshots, and VM handler analysis using the kernel driver bridge + Zydis.
//
// These tools complement the low-level driver_tools (which provide raw register
// access, HW breakpoints, memory R/W, thread control) with higher-level
// debugger workflows that the old DLL debugger_tools namespace provided via
// IDA's debugging APIs.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "comm.h"
#include "obfuscation.hpp"
#include "pro.h"
#include "zydis_disasm.hpp"

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

// ---------------------------------------------------------------------------
// Helpers — lightweight versions of driver_tools helpers, scoped to this TU.
// ---------------------------------------------------------------------------

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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    std::uint32_t requested_pid = 0;
    for (const char* key : {"process_id", "pid"})
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
        break;
    }

    const std::uint32_t current_pid = device->get_process_id();
    if (requested_pid != 0 && requested_pid != current_pid)
    {
        if (!is_process_alive(requested_pid))
            return tool_result_t::error(OBFSTR("process_id ") + std::to_string(requested_pid) + OBFSTR(" is not alive."));
        device->clear_process_context();
        device->set_process_id(requested_pid);
        (void)device->find_image();
        device->solve_dtb();
        if (device->get_dtb() == 0)
        {
            device->clear_process_context();
            return tool_result_t::error(
                OBFSTR("Failed to solve DTB for process_id ") +
                std::to_string(requested_pid) + OBFSTR(". Reattach by name with driver_attach."));
        }
    }

    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_attach first or pass process_id."));

    if (!is_process_alive(device->get_process_id()))
    {
        const std::uint32_t dead_pid = device->get_process_id();
        device->clear_process_context();
        return tool_result_t::error(
            OBFSTR("Attached process PID ") + std::to_string(dead_pid) +
            OBFSTR(" is no longer alive. Call driver_attach again."));
    }

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve DTB for the attached process."));
    }
    return std::nullopt;
}

static std::optional<std::uint32_t> parse_tid(const json& params)
{
    if (!params.contains("tid"))
        return std::nullopt;
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
    return (tid != 0) ? std::optional<std::uint32_t>{tid} : std::nullopt;
}

// ---------------------------------------------------------------------------
// Software breakpoint management — INT3 (0xCC) patches with original byte
// tracking.  Uses the kernel driver for memory R/W so all writes bypass
// page protection and anti-tamper checks.
// ---------------------------------------------------------------------------

struct sw_breakpoint
{
    std::uint64_t address       = 0;
    std::uint8_t  original_byte = 0;
    bool          enabled       = false;
};

static std::mutex             s_bp_mutex;
static std::vector<sw_breakpoint> s_breakpoints;

static tool_result_t dbg_set_breakpoint(const json& params)
{
    if (auto err = ensure_attached(params))
        return *err;

    if (!params.contains("address") || !params["address"].is_string())
        return tool_result_t::error(OBFSTR("'address' (hex string) is required."));

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid address."));
    const std::uint64_t addr = *addr_opt;

    std::lock_guard<std::mutex> lock(s_bp_mutex);

    // Check if breakpoint already exists at this address.
    for (const auto& bp : s_breakpoints)
    {
        if (bp.address == addr && bp.enabled)
            return tool_result_t::error(
                OBFSTR("Breakpoint already set at ") + sa_format_address(addr));
    }

    // Read original byte.
    std::uint8_t original = device->read<std::uint8_t>(addr);

    // Already an INT3?
    if (original == 0xCC)
        return tool_result_t::error(
            OBFSTR("Byte at ") + sa_format_address(addr) +
            OBFSTR(" is already 0xCC (INT3). Possible existing breakpoint."));

    // Write INT3.
    device->write<std::uint8_t>(addr, 0xCC);

    // Verify write.
    std::uint8_t verify = device->read<std::uint8_t>(addr);
    if (verify != 0xCC)
        return tool_result_t::error(
            OBFSTR("Failed to write INT3 at ") + sa_format_address(addr) +
            OBFSTR(". Read-back: 0x") +
            sa_format_address(static_cast<uint64_t>(verify)));

    // Track the breakpoint.
    sw_breakpoint bp;
    bp.address       = addr;
    bp.original_byte = original;
    bp.enabled       = true;
    s_breakpoints.push_back(bp);

    json result;
    result["address"]       = sa_format_address(addr);
    result["original_byte"] = sa_format_address(static_cast<uint64_t>(original));
    result["index"]         = static_cast<int>(s_breakpoints.size()) - 1;
    return tool_result_t::ok(
        OBFSTR("Software breakpoint set at ") + sa_format_address(addr), result);
}

static tool_result_t dbg_remove_breakpoint(const json& params)
{
    if (auto err = ensure_attached(params))
        return *err;

    if (!params.contains("address") || !params["address"].is_string())
        return tool_result_t::error(OBFSTR("'address' (hex string) is required."));

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid address."));
    const std::uint64_t addr = *addr_opt;

    std::lock_guard<std::mutex> lock(s_bp_mutex);

    for (auto it = s_breakpoints.begin(); it != s_breakpoints.end(); ++it)
    {
        if (it->address == addr && it->enabled)
        {
            // Restore original byte.
            device->write<std::uint8_t>(addr, it->original_byte);

            std::uint8_t verify = device->read<std::uint8_t>(addr);
            if (verify != it->original_byte)
                return tool_result_t::error(
                    OBFSTR("Failed to restore original byte at ") +
                    sa_format_address(addr));

            json result;
            result["address"]       = sa_format_address(addr);
            result["restored_byte"] = sa_format_address(
                static_cast<uint64_t>(it->original_byte));

            it->enabled = false;
            return tool_result_t::ok(
                OBFSTR("Breakpoint removed at ") + sa_format_address(addr), result);
        }
    }

    return tool_result_t::error(
        OBFSTR("No active breakpoint found at ") + sa_format_address(addr));
}

static tool_result_t dbg_list_breakpoints(const json& params)
{
    (void)params;

    std::lock_guard<std::mutex> lock(s_bp_mutex);

    json arr = json::array();
    int active_count = 0;
    for (std::size_t i = 0; i < s_breakpoints.size(); ++i)
    {
        const auto& bp = s_breakpoints[i];
        if (!bp.enabled)
            continue;
        json entry;
        entry["index"]         = static_cast<int>(i);
        entry["address"]       = sa_format_address(bp.address);
        entry["original_byte"] = sa_format_address(static_cast<uint64_t>(bp.original_byte));
        arr.push_back(entry);
        ++active_count;
    }

    json result;
    result["active_count"] = active_count;
    result["breakpoints"]  = arr;
    return tool_result_t::ok(
        std::to_string(active_count) + OBFSTR(" active software breakpoint(s)"), result);
}

// ---------------------------------------------------------------------------
// Call stack unwinding — reads the RBP chain from a target thread's register
// state, following frame pointers through the target's memory.  Each frame
// also captures the return address and attempts a Zydis disassembly of the
// first instruction at the return address for context.
// ---------------------------------------------------------------------------

static tool_result_t dbg_get_callstack(const json& params)
{
    if (auto err = ensure_attached(params))
        return *err;

    auto tid_opt = parse_tid(params);
    if (!tid_opt)
        return tool_result_t::error(
            OBFSTR("'tid' (thread ID) is required."));
    const std::uint32_t tid = *tid_opt;

    int max_depth = 64;
    if (params.contains("max_depth") && params["max_depth"].is_number())
        max_depth = std::clamp(params["max_depth"].get<int>(), 1, 256);

    // Suspend the thread so the stack doesn't change under us.
    std::uint32_t prev_count = 0;
    const bool did_suspend = device->suspend_thread(tid, &prev_count);

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
    {
        if (did_suspend) device->resume_thread(tid);
        return tool_result_t::error(
            OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));
    }

    json frames = json::array();

    // Frame 0: current RIP.
    {
        json f;
        f["depth"]   = 0;
        f["rip"]     = sa_format_address(static_cast<uint64_t>(ctx.rip));
        f["rsp"]     = sa_format_address(static_cast<uint64_t>(ctx.rsp));
        f["rbp"]     = sa_format_address(static_cast<uint64_t>(ctx.rbp));

        // Disassemble instruction at RIP for context.
        uint8_t code[16] = {};
        if (device->read_raw(ctx.rip, code, sizeof(code)) >= 1)
        {
            AsmInstr ins = zydis_decode_one(code, 16, ctx.rip);
            f["instruction"] = std::string(ins.mnem) + " " + std::string(ins.ops);
        }
        frames.push_back(f);
    }

    // Walk the RBP chain.  Frame layout: [RBP] = saved_rbp, [RBP+8] = return_addr.
    std::uint64_t rbp = ctx.rbp;
    std::uint64_t rsp = ctx.rsp;

    // Heuristic: if RBP looks invalid (e.g. leaf function with no frame pointer),
    // fall back to scanning RSP for return addresses.
    const bool rbp_looks_valid =
        rbp > 0x10000 && rbp < 0x7FFFFFFFFFFF0000ULL &&
        rbp > rsp && (rbp - rsp) < 0x100000;  // within 1MB of RSP

    if (rbp_looks_valid)
    {
        // Standard RBP chain walk.
        for (int depth = 1; depth < max_depth; ++depth)
        {
            // Validate RBP range.
            if (rbp == 0 || rbp < 0x10000 || rbp > 0x7FFFFFFFFFFF0000ULL)
                break;

            // Read saved RBP and return address.
            std::uint64_t saved_rbp = 0;
            std::uint64_t ret_addr  = 0;
            if (device->read_raw(rbp, &saved_rbp, 8) < 8)
                break;
            if (device->read_raw(rbp + 8, &ret_addr, 8) < 8)
                break;

            // Validate return address.
            if (ret_addr == 0 || ret_addr < 0x10000)
                break;

            json f;
            f["depth"]      = depth;
            f["rip"]        = sa_format_address(ret_addr);
            f["rbp"]        = sa_format_address(saved_rbp);
            f["frame_addr"] = sa_format_address(rbp);

            // Disassemble at return address.
            uint8_t code[16] = {};
            if (device->read_raw(ret_addr, code, sizeof(code)) >= 1)
            {
                AsmInstr ins = zydis_decode_one(code, 16, ret_addr);
                f["instruction"] = std::string(ins.mnem) + " " + std::string(ins.ops);
            }

            frames.push_back(f);

            // Detect loops.
            if (saved_rbp == rbp || saved_rbp <= rbp)
                break;
            rbp = saved_rbp;
        }
    }
    else
    {
        // Fallback: scan the stack for return addresses.
        // Read a chunk of the stack and look for values that point to executable memory.
        constexpr std::size_t SCAN_SIZE = 0x800;  // 2KB
        std::vector<std::uint8_t> stack_data(SCAN_SIZE);
        std::size_t read = device->read_raw(rsp, stack_data.data(), SCAN_SIZE);
        int depth = 1;

        for (std::size_t off = 0; off + 8 <= read && depth < max_depth; off += 8)
        {
            std::uint64_t candidate = 0;
            std::memcpy(&candidate, stack_data.data() + off, 8);

            // Basic heuristic: user-mode code address.
            if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF0000ULL)
                continue;

            // Check if the memory at candidate is executable (committed + execute).
            voyager::device_t::memory_region_info region{};
            if (!device->query_memory(candidate, region))
                continue;
            if (region.state != 0x1000)  // MEM_COMMIT
                continue;
            if (!(region.protect & 0xF0))  // No execute bit
                continue;

            // Read instruction at candidate to verify it's valid code.
            uint8_t code[16] = {};
            if (device->read_raw(candidate, code, sizeof(code)) < 1)
                continue;
            AsmInstr ins = zydis_decode_one(code, 16, candidate);
            // Skip clearly invalid entries.
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

    // Resume the thread.
    if (did_suspend)
        device->resume_thread(tid);

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

// ---------------------------------------------------------------------------
// Execution state snapshots — capture the full register state + configurable
// memory ranges of a thread into a named snapshot.  Two snapshots can then
// be compared ("diffed") to see exactly what changed.
// ---------------------------------------------------------------------------

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
    if (auto err = ensure_attached(params))
        return *err;

    auto tid_opt = parse_tid(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("'tid' (thread ID) is required."));
    const std::uint32_t tid = *tid_opt;

    std::string snap_name = "default";
    if (params.contains("name") && params["name"].is_string())
        snap_name = params["name"].get<std::string>();
    if (snap_name.empty())
        return tool_result_t::error(OBFSTR("Snapshot name cannot be empty."));

    // Suspend to get a consistent view.
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

    // Optional: capture memory regions.
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

    // Build result.
    json result;
    result["name"]           = snap_name;
    result["tid"]            = tid;
    result["rip"]            = sa_format_address(static_cast<uint64_t>(ctx.rip));
    result["rsp"]            = sa_format_address(static_cast<uint64_t>(ctx.rsp));
    result["memory_regions"] = static_cast<int>(snap.memory.size());

    // Store.
    {
        std::lock_guard<std::mutex> lock(s_snap_mutex);
        s_snapshots[snap_name] = std::move(snap);
    }

    return tool_result_t::ok(
        OBFSTR("Snapshot '") + snap_name + OBFSTR("' captured"), result);
}

static tool_result_t dbg_compare_snapshots(const json& params)
{
    if (!params.contains("snapshot_a") || !params["snapshot_a"].is_string())
        return tool_result_t::error(OBFSTR("'snapshot_a' name is required."));
    if (!params.contains("snapshot_b") || !params["snapshot_b"].is_string())
        return tool_result_t::error(OBFSTR("'snapshot_b' name is required."));

    const std::string name_a = params["snapshot_a"].get<std::string>();
    const std::string name_b = params["snapshot_b"].get<std::string>();

    std::lock_guard<std::mutex> lock(s_snap_mutex);

    auto it_a = s_snapshots.find(name_a);
    auto it_b = s_snapshots.find(name_b);
    if (it_a == s_snapshots.end())
        return tool_result_t::error(OBFSTR("Snapshot '") + name_a + OBFSTR("' not found."));
    if (it_b == s_snapshots.end())
        return tool_result_t::error(OBFSTR("Snapshot '") + name_b + OBFSTR("' not found."));

    const auto& a = it_a->second;
    const auto& b = it_b->second;

    // Compare registers.
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

    // Compare memory regions (only regions at matching addresses).
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
                        break;  // Cap diff output.
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

    return tool_result_t::ok(
        OBFSTR("Diff: ") + std::to_string(reg_diffs.size()) +
        OBFSTR(" register(s), ") + std::to_string(mem_diffs.size()) +
        OBFSTR(" memory region(s) changed"),
        result);
}

// ---------------------------------------------------------------------------
// VM handler detection — Zydis-based analysis of obfuscated code to detect
// virtual machine dispatcher patterns and map handler tables.  Reads code
// from the target process via driver and disassembles locally.
// ---------------------------------------------------------------------------

static tool_result_t dbg_detect_vm_handler(const json& params)
{
    if (auto err = ensure_attached(params))
        return *err;

    if (!params.contains("address") || !params["address"].is_string())
        return tool_result_t::error(OBFSTR("'address' (hex string) is required."));

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid address."));
    const std::uint64_t addr = *addr_opt;

    int scan_size = 512;
    if (params.contains("size") && params["size"].is_number())
        scan_size = std::clamp(params["size"].get<int>(), 64, 16384);

    // Read code bytes from target process.
    std::vector<uint8_t> code(static_cast<std::size_t>(scan_size));
    std::size_t read = device->read_raw(addr, code.data(), code.size());
    if (read < 16)
        return tool_result_t::error(
            OBFSTR("Insufficient bytes read at ") + sa_format_address(addr));
    code.resize(read);

    zydis_detail::ensure_init();

    // VM dispatcher pattern detection heuristics:
    // 1. Indirect jump through register or memory (jmp [reg+disp])
    // 2. Switch-like table dispatch (jmp [rax*8+table])
    // 3. Opcode fetch + handler lookup loops
    // 4. Register use as bytecode pointer (repeated [reg] reads + inc/add)

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

        // Detect indirect jumps (jmp reg, jmp [reg], jmp [reg+disp], jmp [reg*scale+disp]).
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

        // Detect movzx/movsx patterns (bytecode fetch).
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

    // Score the likelihood of this being a VM dispatcher.
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

    return tool_result_t::ok(
        OBFSTR("VM analysis at ") + sa_format_address(addr) +
        OBFSTR(": ") + verdict, result);
}

static tool_result_t dbg_map_vm_handlers(const json& params)
{
    if (auto err = ensure_attached(params))
        return *err;

    if (!params.contains("table_address") || !params["table_address"].is_string())
        return tool_result_t::error(
            OBFSTR("'table_address' (hex string of handler table base) is required."));

    auto table_addr_opt = sa_parse_address(
        params["table_address"].get<std::string>());
    if (!table_addr_opt || *table_addr_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid table_address."));
    const std::uint64_t table_base = *table_addr_opt;

    int entry_count = 256;
    if (params.contains("count") && params["count"].is_number())
        entry_count = std::clamp(params["count"].get<int>(), 1, 4096);

    int entry_size = 8;
    if (params.contains("entry_size") && params["entry_size"].is_number())
        entry_size = std::clamp(params["entry_size"].get<int>(), 1, 8);

    int preview_instructions = 5;
    if (params.contains("preview_instructions") && params["preview_instructions"].is_number())
        preview_instructions = std::clamp(
            params["preview_instructions"].get<int>(), 0, 32);

    // Check if handler addresses are relative or absolute.
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

    // Read the table.
    const std::size_t table_byte_size =
        static_cast<std::size_t>(entry_count) * static_cast<std::size_t>(entry_size);
    std::vector<uint8_t> table_data(table_byte_size);
    std::size_t table_read = device->read_raw(
        table_base, table_data.data(), table_byte_size);
    if (table_read < static_cast<std::size_t>(entry_size))
        return tool_result_t::error(
            OBFSTR("Failed to read handler table at ") +
            sa_format_address(table_base));

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

        // Sign-extend if 4-byte entries.
        if (entry_size == 4)
            raw_value = static_cast<std::uint64_t>(
                static_cast<std::int32_t>(raw_value & 0xFFFFFFFF));

        // Compute handler address.
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

        // Preview-disassemble the handler.
        if (preview_instructions > 0)
        {
            const int preview_bytes = preview_instructions * 15;  // max x86 insn = 15
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

    return tool_result_t::ok(
        OBFSTR("Mapped ") + std::to_string(valid_count) +
        OBFSTR(" handlers from table at ") + sa_format_address(table_base),
        result);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void register_debugger_tools(mcp_standalone::server_t& srv)
{
    // --- Software breakpoints ---

    register_compat(srv, {
        OBFSTR("dbg_set_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Set a software breakpoint (INT3 / 0xCC) at an address in the attached process. "
               "The original byte is saved and can be restored with dbg_remove_breakpoint. "
               "Uses kernel driver writes to bypass all memory protection and anti-tamper. "
               "Note: INT3 breakpoints cause an unhandled exception in the target unless "
               "a vectored exception handler is installed — use driver_set_hw_breakpoint for "
               "transparent breakpoints that don't modify code bytes."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address (hex)"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        dbg_set_breakpoint, false});

    register_compat(srv, {
        OBFSTR("dbg_remove_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Remove a software breakpoint by restoring the original byte at the address. "
               "Only works for breakpoints set via dbg_set_breakpoint (original byte must be tracked)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Breakpoint address to remove (hex)"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        dbg_remove_breakpoint, false});

    register_compat(srv, {
        OBFSTR("dbg_list_breakpoints"), OBFSTR("debugger"),
        OBFSTR("List all active software breakpoints (INT3 patches) managed by this session. "
               "Shows address and the original byte that will be restored on removal."),
        {},
        dbg_list_breakpoints, true});

    // --- Call stack ---

    register_compat(srv, {
        OBFSTR("dbg_get_callstack"), OBFSTR("debugger"),
        OBFSTR("Unwind the call stack of a thread in the attached process. "
               "Suspends the thread, reads its register context, and walks the RBP frame "
               "pointer chain through memory. Falls back to RSP scanning if RBP is invalid "
               "(e.g. leaf functions compiled with -fomit-frame-pointer). Each frame includes "
               "the return address and a Zydis disassembly of the instruction at that address."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("max_depth"), OBFSTR("number"), OBFSTR("Maximum stack frames to unwind (default 64, max 256)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        dbg_get_callstack, true});

    // --- Execution state snapshots ---

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
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
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

    // --- VM handler analysis ---

    register_compat(srv, {
        OBFSTR("dbg_detect_vm_handler"), OBFSTR("debugger"),
        OBFSTR("Analyze code at an address to detect virtual machine (VM) obfuscation patterns. "
               "Reads code bytes from the target process and uses Zydis disassembly to identify "
               "VM dispatcher indicators: indirect jumps through registers, scaled table dispatches "
               "(jmp [reg*8+table]), opcode fetch patterns (movzx/movsx from memory), and other "
               "common VM handler idioms. Returns a confidence score and detailed indicators."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to analyze (hex)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes to analyze (default 512, max 16384)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
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
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        dbg_map_vm_handlers, true});
}

} // namespace debugger_tools
