

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "debugger_engine.hpp"
#include "comm.h"
#include "obfuscation.hpp"
#include "pro.h"
#include "zydis_disasm.hpp"
#include "xref_engine.hpp"
#include "cfg_view.hpp"
#include "seh_view.hpp"
#include "module_view.hpp"
#include "pe_parser.hpp"
#include "code_patcher.hpp"
#include "stealth_engine.hpp"

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

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software);
    if (idx < 0) {
        const auto& err_msg = debugger_engine::last_error();
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

    json result;
    result["address"]       = sa_format_address(addr);
    result["original_byte"] = sa_format_address(static_cast<uint64_t>(original));
    result["index"]         = idx;
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

    if (target_idx < 0)
        return tool_result_t::error(
            OBFSTR("No active breakpoint found at ") + sa_format_address(addr));

    if (!debugger_engine::remove_breakpoint(target_idx)) {
        const auto& err_msg = debugger_engine::last_error();
        std::string detail = err_msg.empty() ? std::string() : (OBFSTR(": ") + err_msg);
        return tool_result_t::error(
            OBFSTR("Failed to remove breakpoint at ") + sa_format_address(addr) + detail);
    }

    json result;
    result["address"]       = sa_format_address(addr);
    result["restored_byte"] = sa_format_address(static_cast<uint64_t>(original));
    return tool_result_t::ok(
        OBFSTR("Breakpoint removed at ") + sa_format_address(addr), result);
}

static tool_result_t dbg_list_breakpoints(const json& params)
{
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

    json result;
    result["active_count"] = active_count;
    result["breakpoints"]  = arr;
    return tool_result_t::ok(
        std::to_string(active_count) + OBFSTR(" active breakpoint(s)"), result);
}


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

    return tool_result_t::ok(
        OBFSTR("Diff: ") + std::to_string(reg_diffs.size()) +
        OBFSTR(" register(s), ") + std::to_string(mem_diffs.size()) +
        OBFSTR(" memory region(s) changed"),
        result);
}


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


    std::vector<uint8_t> code(static_cast<std::size_t>(scan_size));
    std::size_t read = device->read_raw(addr, code.data(), code.size());
    if (read < 16)
        return tool_result_t::error(
            OBFSTR("Insufficient bytes read at ") + sa_format_address(addr));
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

    return tool_result_t::ok(
        OBFSTR("Mapped ") + std::to_string(valid_count) +
        OBFSTR(" handlers from table at ") + sa_format_address(table_base),
        result);
}


void register_debugger_tools(mcp_standalone::server_t& srv)
{


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


    register_compat(srv, {
        OBFSTR("dbg_run"), OBFSTR("debugger"),
        OBFSTR("Resume execution of the attached process (set debugger state to running)."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            debugger_engine::run_target();
            return tool_result_t::ok(OBFSTR("Execution resumed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_pause"), OBFSTR("debugger"),
        OBFSTR("Pause (break) the attached process."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            debugger_engine::pause_target();
            return tool_result_t::ok(OBFSTR("Execution paused."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_step_into"), OBFSTR("debugger"),
        OBFSTR("Single-step into the next instruction (follows calls)."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            debugger_engine::step_into();
            return tool_result_t::ok(OBFSTR("Step into executed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_step_over"), OBFSTR("debugger"),
        OBFSTR("Step over the next instruction (does not follow calls)."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            debugger_engine::step_over();
            return tool_result_t::ok(OBFSTR("Step over executed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_step_out"), OBFSTR("debugger"),
        OBFSTR("Step out of the current function (run until return)."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            debugger_engine::step_out();
            return tool_result_t::ok(OBFSTR("Step out executed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_run_to_address"), OBFSTR("debugger"),
        OBFSTR("Run until execution reaches a specific address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address (hex)"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            debugger_engine::run_to_address(*addr);
            return tool_result_t::ok(OBFSTR("Running to ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_registers"), OBFSTR("debugger"),
        OBFSTR("Read all general-purpose registers, RIP, RFLAGS, segment and debug registers "
               "of a thread in the attached process."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID (default: first thread)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (tid) debugger_engine::g_state.active_tid = *tid;
            auto regs = debugger_engine::get_registers();

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
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(OBFSTR("'tid' is required."));
            if (!params.contains("register") || !params.contains("value"))
                return tool_result_t::error(OBFSTR("'register' and 'value' required."));
            auto val = sa_parse_address(params["value"].get<std::string>());
            if (!val) return tool_result_t::error(OBFSTR("Invalid value."));
            debugger_engine::g_state.active_tid = *tid;
            debugger_engine::set_register(params["register"].get<std::string>(), *val);
            return tool_result_t::ok(OBFSTR("Register set."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_memory_map"), OBFSTR("debugger"),
        OBFSTR("Get the full virtual memory map of the attached process, including base address, "
               "size, protection flags, and module name for each region."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            auto regions = debugger_engine::get_memory_map();
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
            if (!params.contains("expression") || !params["expression"].is_string())
                return tool_result_t::error(OBFSTR("'expression' is required."));
            debugger_engine::add_watch(params["expression"].get<std::string>());
            debugger_engine::refresh_watches();
            return tool_result_t::ok(OBFSTR("Watch added."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_remove_watch"), OBFSTR("debugger"),
        OBFSTR("Remove a watch by index."),
        {{OBFSTR("index"), OBFSTR("number"), OBFSTR("Watch index"), true}},
        [](const json& params) -> tool_result_t {
            if (!params.contains("index") || !params["index"].is_number())
                return tool_result_t::error(OBFSTR("'index' required."));
            debugger_engine::remove_watch(params["index"].get<int>());
            return tool_result_t::ok(OBFSTR("Watch removed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_watches"), OBFSTR("debugger"),
        OBFSTR("Get all watch expressions and their current values."),
        {},
        [](const json& ) -> tool_result_t {
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
                arr.push_back(wj);
            }
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" watches."), arr);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_start_trace"), OBFSTR("debugger"),
        OBFSTR("Start instruction tracing on the attached process. Each step records address, "
               "disassembly, and register state."),
        {{OBFSTR("max_records"), OBFSTR("number"), OBFSTR("Maximum trace records to keep (default 50000)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            int max_records = params.value("max_records", 50000);
            debugger_engine::start_trace(max_records);
            return tool_result_t::ok(OBFSTR("Trace started."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_stop_trace"), OBFSTR("debugger"),
        OBFSTR("Stop instruction tracing."),
        {},
        [](const json& ) -> tool_result_t {
            debugger_engine::stop_trace();
            return tool_result_t::ok(OBFSTR("Trace stopped."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_trace"), OBFSTR("debugger"),
        OBFSTR("Get recorded trace entries. Returns instruction addresses, disassembly, and register diffs."),
        {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start index (default 0)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max entries to return (default 200)"), false}},
        [](const json& params) -> tool_result_t {
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
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" trace entries."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_set_comment"), OBFSTR("debugger"),
        OBFSTR("Set a comment annotation at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true},
         {OBFSTR("text"), OBFSTR("string"), OBFSTR("Comment text"), true}},
        [](const json& params) -> tool_result_t {
            if (!params.contains("address") || !params.contains("text"))
                return tool_result_t::error(OBFSTR("'address' and 'text' required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            debugger_engine::set_comment(*addr, params["text"].get<std::string>());
            return tool_result_t::ok(OBFSTR("Comment set at ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_set_label"), OBFSTR("debugger"),
        OBFSTR("Set a label (name) at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true},
         {OBFSTR("text"), OBFSTR("string"), OBFSTR("Label text"), true}},
        [](const json& params) -> tool_result_t {
            if (!params.contains("address") || !params.contains("text"))
                return tool_result_t::error(OBFSTR("'address' and 'text' required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            debugger_engine::set_label(*addr, params["text"].get<std::string>());
            return tool_result_t::ok(OBFSTR("Label set at ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_toggle_bookmark"), OBFSTR("debugger"),
        OBFSTR("Toggle a bookmark at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true}},
        [](const json& params) -> tool_result_t {
            if (!params.contains("address"))
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            debugger_engine::toggle_bookmark(*addr);
            return tool_result_t::ok(OBFSTR("Bookmark toggled at ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_find_strings"), OBFSTR("debugger"),
        OBFSTR("Find ASCII strings in the memory of the attached process. Results include address, "
               "string value, and containing module."),
        {{OBFSTR("min_length"), OBFSTR("number"), OBFSTR("Minimum string length (default 4)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            int min_len = params.value("min_length", 4);
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
            return tool_result_t::ok(
                std::to_string(st.strings.size()) + OBFSTR(" strings found."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_enumerate_handles"), OBFSTR("debugger"),
        OBFSTR("Enumerate open handles in the attached process (requires NtQuerySystemInformation)."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
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
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            std::string type_str = params.value("type", "execute");
            debugger_engine::bp_type_t bpt = debugger_engine::bp_type_t::hardware_execute;
            if (type_str == "write") bpt = debugger_engine::bp_type_t::hardware_write;
            else if (type_str == "read") bpt = debugger_engine::bp_type_t::hardware_read;
            debugger_engine::add_breakpoint(*addr, bpt);
            return tool_result_t::ok(OBFSTR("Hardware breakpoint set at ") + sa_format_address(*addr));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_toggle_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Toggle a breakpoint on or off by its index in the breakpoint list."),
        {{OBFSTR("index"), OBFSTR("number"), OBFSTR("Breakpoint index"), true}},
        [](const json& params) -> tool_result_t {
            if (!params.contains("index") || !params["index"].is_number())
                return tool_result_t::error(OBFSTR("'index' is required."));
            int idx = params["index"].get<int>();
            if (!debugger_engine::toggle_breakpoint(idx))
                return tool_result_t::error(OBFSTR("Failed to toggle breakpoint at index ") + std::to_string(idx));
            return tool_result_t::ok(OBFSTR("Breakpoint toggled."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_clear_all_breakpoints"), OBFSTR("debugger"),
        OBFSTR("Remove all breakpoints (software and hardware)."),
        {},
        [](const json&) -> tool_result_t {
            debugger_engine::clear_all_breakpoints();
            return tool_result_t::ok(OBFSTR("All breakpoints cleared."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_get_comment"), OBFSTR("debugger"),
        OBFSTR("Get the comment annotation at an address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (hex)"), true}},
        [](const json& params) -> tool_result_t {
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            std::string text = debugger_engine::get_comment(*addr);
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
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            std::string text = debugger_engine::get_label(*addr);
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
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.anno_mutex);
            json arr = json::array();
            for (auto addr : st.bookmarks)
                arr.push_back(sa_format_address(addr));
            json result;
            result["count"] = arr.size();
            result["bookmarks"] = arr;
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" bookmark(s)."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_xrefs_to"), OBFSTR("debugger"),
        OBFSTR("Get cross-references to a target address. Scans for CALL, JMP, Jcc, LEA and data refs that point to the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address (hex)"), true},
         {OBFSTR("max_results"), OBFSTR("number"), OBFSTR("Maximum results to return (default 100)"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            int max_results = params.value("max_results", 100);
            if (max_results <= 0) max_results = 100;
            if (max_results > 10000) max_results = 10000;
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
            return tool_result_t::ok(
                std::to_string(result["count"].get<size_t>()) + OBFSTR(" xref(s) to ") + sa_format_address(*addr), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_xrefs_from"), OBFSTR("debugger"),
        OBFSTR("Get cross-references from a source address. Follows instructions and collects all outgoing CALL, JMP, Jcc, LEA and data refs."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Source address (hex)"), true},
         {OBFSTR("max_results"), OBFSTR("number"), OBFSTR("Maximum instructions to scan (default 200)"), false}},
        [](const json& params) -> tool_result_t {
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
            std::lock_guard<std::mutex> lk(xref_engine::g_state.mutex);
            json result;
            result["total_found"] = xref_engine::g_state.results.size();
            result["target"] = sa_format_address(*target);
            result["range_start"] = sa_format_address(*start);
            result["range_size"] = size;
            return tool_result_t::ok(
                OBFSTR("Scan complete. ") + std::to_string(xref_engine::g_state.results.size()) + OBFSTR(" xref(s) found."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_build_cfg"), OBFSTR("debugger"),
        OBFSTR("Build a control flow graph starting from an address. Disassembles and splits into basic blocks with edges."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Entry address to build CFG from (hex)"), true}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
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
            return tool_result_t::ok(
                OBFSTR("CFG built: ") + std::to_string(cfg_view::g_state.blocks.size()) + OBFSTR(" blocks."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_cfg"), OBFSTR("debugger"),
        OBFSTR("Get the current control flow graph state, including all basic blocks, instructions, and edges."),
        {},
        [](const json&) -> tool_result_t {
            std::lock_guard<std::mutex> lk(cfg_view::g_state.mutex);
            if (!cfg_view::g_state.built)
                return tool_result_t::error(OBFSTR("No CFG built. Call dbg_build_cfg first."));
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
            return tool_result_t::ok(
                OBFSTR("CFG: ") + std::to_string(cfg_view::g_state.blocks.size()) + OBFSTR(" blocks."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_seh_chain"), OBFSTR("debugger"),
        OBFSTR("Get the SEH (Structured Exception Handler) chain of the attached process."),
        {},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
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
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" SEH handler(s)."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_get_modules_detail"), OBFSTR("debugger"),
        OBFSTR("Get detailed module information with PE analysis including exports and imports."),
        {{OBFSTR("module_name"), OBFSTR("string"), OBFSTR("Optional module name filter"), false}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            module_view::refresh();
            Sleep(300);
            std::string filter;
            if (params.contains("module_name") && params["module_name"].is_string())
                filter = params["module_name"].get<std::string>();
            std::vector<driver_bridge::module_info_t> mods;
            {
                std::lock_guard<std::mutex> lk(module_view::g_ui.modules_mutex);
                mods = module_view::g_ui.modules;
            }
            json arr = json::array();
            for (const auto& m : mods) {
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
                if (pe_parser::parse(m.base, pe)) {
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
                    pe_parser::parse_exports(m.base, pe, exports);
                    mj["export_count"] = exports.size();
                    json exp_arr = json::array();
                    size_t exp_limit = std::min<size_t>(exports.size(), 50);
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
                    pe_parser::parse_imports(m.base, pe, imports);
                    mj["import_count"] = imports.size();
                    json imp_arr = json::array();
                    size_t imp_limit = std::min<size_t>(imports.size(), 50);
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
            result["modules"] = std::move(arr);
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
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            if (!params.contains("bytes") || !params["bytes"].is_string())
                return tool_result_t::error(OBFSTR("'bytes' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            auto patched = code_patcher::parse_bytes(params["bytes"].get<std::string>());
            if (patched.empty())
                return tool_result_t::error(OBFSTR("Invalid hex bytes."));
            std::string label;
            if (params.contains("label") && params["label"].is_string())
                label = params["label"].get<std::string>();
            int idx = code_patcher::create_patch(*addr, patched, label);
            if (idx < 0)
                return tool_result_t::error(OBFSTR("Failed to create patch."));
            if (!code_patcher::apply_patch(idx))
                return tool_result_t::error(OBFSTR("Patch created but failed to apply."));
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
            if (!params.contains("index") || !params["index"].is_number())
                return tool_result_t::error(OBFSTR("'index' is required."));
            int idx = params["index"].get<int>();
            if (!code_patcher::revert_patch(idx))
                return tool_result_t::error(OBFSTR("Failed to revert patch."));
            if (!code_patcher::remove_patch(idx))
                return tool_result_t::error(OBFSTR("Failed to remove patch."));
            return tool_result_t::ok(OBFSTR("Patch removed."));
        }, false});

    register_compat(srv, {
        OBFSTR("dbg_list_patches"), OBFSTR("debugger"),
        OBFSTR("List all code patches with their status, addresses, and byte values."),
        {},
        [](const json&) -> tool_result_t {
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
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" patch(es)."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_nop_fill"), OBFSTR("debugger"),
        OBFSTR("NOP-fill a range of bytes at the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to start NOP fill (hex)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Number of bytes to NOP"), true}},
        [](const json& params) -> tool_result_t {
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
            if (!code_patcher::nop_region(*addr, static_cast<size_t>(size), OBFSTR("NOP fill")))
                return tool_result_t::error(OBFSTR("Failed to NOP-fill region."));
            int idx = static_cast<int>(code_patcher::count()) - 1;
            if (!code_patcher::apply_patch(idx))
                return tool_result_t::error(OBFSTR("NOP patch created but failed to apply."));
            json result;
            result["address"] = sa_format_address(*addr);
            result["size"] = size;
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
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            uint32_t size = static_cast<uint32_t>(params.value("size", 0x1000));
            if (size == 0) size = 0x1000;
            size_t min_size = static_cast<size_t>(params.value("min_cave_size", 16));
            if (min_size == 0) min_size = 16;
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
            return tool_result_t::ok(
                std::to_string(arr.size()) + OBFSTR(" code cave(s) found."), result);
        }, true});

    register_compat(srv, {
        OBFSTR("dbg_conditional_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Set a breakpoint with a condition expression. The breakpoint will only trigger when the condition is met."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address for breakpoint (hex)"), true},
         {OBFSTR("condition"), OBFSTR("string"), OBFSTR("Condition expression (e.g. 'rax == 0x1234')"), true}},
        [](const json& params) -> tool_result_t {
            if (auto err = ensure_attached(params)) return *err;
            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(OBFSTR("'address' is required."));
            if (!params.contains("condition") || !params["condition"].is_string())
                return tool_result_t::error(OBFSTR("'condition' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(OBFSTR("Invalid address."));
            std::string cond = params["condition"].get<std::string>();
            int bp_idx = debugger_engine::add_breakpoint(*addr, debugger_engine::bp_type_t::software, "", cond);
            if (bp_idx < 0)
                return tool_result_t::error(OBFSTR("Failed to add breakpoint."));
            json result;
            result["index"] = bp_idx;
            result["address"] = sa_format_address(*addr);
            result["condition"] = cond;
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
			if (auto err = ensure_attached(params)) return *err;

			uint32_t pid = device->get_process_id();
			if (pid == 0)
				return tool_result_t::error("Not attached to a process.");

			if (stealth_engine::is_active())
				return tool_result_t::error("Stealth mode is already active.");

			bool ok = stealth_engine::enable_stealth(pid);
			if (!ok)
				return tool_result_t::error("Failed to enable stealth mode.");

			auto status = stealth_engine::get_session_info();
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
			if (!stealth_engine::is_active())
				return tool_result_t::error("Stealth mode is not active.");

			stealth_engine::disable_stealth();

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
			json result;
			result["active"] = stealth_engine::is_active();

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
