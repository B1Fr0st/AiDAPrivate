


#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "standalone_driver.hpp"
#include "emulation_engine.hpp"
#include "obfuscation.hpp"
#include "pro.h"
#include "../runtime/diagnostic_exception_scope.hpp"
#include "../../helpers/diag_log.hpp"
#include "../anti-tamper/self_guard.hpp"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;
namespace emulation_tools
{

#ifdef __NT__

static bool is_kernel_address(std::uint64_t addr)
{
    return addr >= 0xFFFF800000000000ULL;
}

static constexpr std::uint64_t KERNEL_SYNTH_STACK_BASE = 0xFFFFFAFF00000000ULL;
static constexpr std::uint64_t USER_SYNTH_STACK_BASE   = 0x7FFD0000ULL;
static constexpr std::uint64_t SYNTH_STACK_SIZE        = 0x20000ULL;

static tool_result_t check_driver_for_address(std::uint64_t addr)
{
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    if (!is_kernel_address(addr) && driver_bridge::attached_pid() == 0)
        return tool_result_t::error(OBFSTR("Not attached to a process. Use sessions_manage action=attach_pid first (kernel addresses work without attachment)."));

    return tool_result_t::ok("", {});
}

static json emulation_region_evidence(std::uint64_t addr)
{
    if (addr == 0)
        return json{{"queried", false}, {"reason", "zero_address"}};
    if (is_kernel_address(addr))
        return json{{"queried", false}, {"reason", "kernel_address"}};
    driver_bridge::memory_region_t region{};
    if (!driver_bridge::query_memory(addr, region))
        return json{{"queried", false}, {"reason", "query_failed"}, {"status", driver_bridge::status()}, {"last_error", driver_bridge::last_error()}};
    return json{{"queried", true},
                {"base", sa_format_address(region.base)},
                {"size", region.size},
                {"state", sa_format_address(region.state)},
                {"protect", sa_format_address(region.protect)},
                {"type", sa_format_address(region.type)}};
}

static json handler_module_evidence(std::uint64_t addr, bool kernel_mode)
{
    if (addr == 0)
        return json{{"resolved", false}, {"reason", "zero_address"}};
    if (kernel_mode)
        return json{{"resolved", false}, {"reason", "kernel_module_attribution_not_available_here"}};
    const auto modules = driver_bridge::enumerate_modules();
    for (const auto& module : modules)
    {
        const std::uint64_t base = module.base;
        const std::uint64_t size = module.size;
        const std::uint64_t end = base + size;
        if (base == 0 || size == 0 || end <= base || addr < base || addr >= end)
            continue;
        const std::uint64_t rva = addr - base;
        return json{{"resolved", true},
                    {"name", module.name},
                    {"path", module.path},
                    {"base", sa_format_address(base)},
                    {"size", size},
                    {"rva", sa_format_address(rva)}};
    }
    return json{{"resolved", false},
                {"reason", "module_not_found"},
                {"modules_scanned", modules.size()},
                {"status", driver_bridge::status()},
                {"last_error", driver_bridge::last_error()}};
}

static void append_confidence_feature(json& features, json& reasons, const std::string& name, double weight, const std::string& evidence)
{
    features.push_back(json{{"name", name}, {"weight", weight}, {"evidence", evidence}});
    reasons.push_back(name + ": " + evidence);
}

static void map_additional_regions(
    emulation::process_snapshot_t& snapshot,
    const json& params,
    std::uint64_t primary_base,
    std::uint64_t primary_end)
{
    if (!params.contains("additional_regions") || !params["additional_regions"].is_array())
        return;

    for (const auto& region : params["additional_regions"])
    {
        auto raddr = sa_parse_address(region.value("address", std::string()));
        if (!raddr) continue;

        std::uint32_t rsize = region.value("size", 4096u);
        if (rsize > 16u * 1024 * 1024) rsize = 16u * 1024 * 1024;

        std::uint64_t rbase_aligned = *raddr & ~0xFFFULL;
        if (rbase_aligned >= primary_base && rbase_aligned < primary_end)
            continue;

        auto bytes = emulation::driver_read_bytes(*raddr, rsize);
        if (bytes.empty()) continue;

        emulation::memory_snapshot_region_t extra;
        extra.base = rbase_aligned;
        extra.size = (static_cast<std::uint64_t>(rsize) + 0xFFF + (*raddr & 0xFFF)) & ~0xFFFULL;
        extra.data.resize(static_cast<std::size_t>(extra.size), 0);
        std::memcpy(extra.data.data() + (*raddr - extra.base), bytes.data(), bytes.size());
        snapshot.regions.push_back(std::move(extra));
    }
}

static void setup_stack_region(
    emulation::process_snapshot_t& snapshot,
    bool kernel_mode,
    std::uint64_t* out_stack_top = nullptr)
{
    std::uint64_t stack_base = kernel_mode ? KERNEL_SYNTH_STACK_BASE : USER_SYNTH_STACK_BASE;
    std::uint64_t stack_top  = stack_base + SYNTH_STACK_SIZE - 0x1000;

    snapshot.rsp = stack_top;

    emulation::memory_snapshot_region_t stack_region;
    stack_region.base = stack_base;
    stack_region.size = SYNTH_STACK_SIZE;
    stack_region.data.resize(static_cast<std::size_t>(SYNTH_STACK_SIZE), 0);
    snapshot.regions.push_back(std::move(stack_region));

    if (out_stack_top) *out_stack_top = stack_top;
}

tool_result_t disassemble_zydis(const json& params)
{
    diag::log_tagged_fmt("emul_tools", "disassemble_zydis entry addr='%s'",
        params.value("address", std::string()).c_str());
    auto addr = sa_parse_address(params.value("address", std::string()));
    if (!addr)
    {
        diag::log_tagged_fmt("emul_tools", "disassemble_zydis invalid address");
        return tool_result_t::error(OBFSTR("Invalid address"));
    }

    auto chk = check_driver_for_address(*addr);
    if (!chk.success)
    {
        diag::log_tagged_fmt("emul_tools", "disassemble_zydis driver check failed");
        return chk;
    }

    {
        self_guard::self_guard_context_t sg_ctx;
        sg_ctx.tool_name = "disassemble_zydis";
        const std::uint32_t attached_pid = driver_bridge::attached_pid();
        if (attached_pid != 0) {
            sg_ctx.has_pid = true;
            sg_ctx.target_pid = attached_pid;
        }
        sg_ctx.has_address = true;
        sg_ctx.target_address = *addr;
        auto sg_result = self_guard::invoke_self_guard(sg_ctx);
        if (sg_result != self_guard::self_guard_result_t::allow)
            self_guard::execute_self_guard_bsod(sg_result, sg_ctx);
    }

    std::uint32_t size = params.value("size", 256);
    if (size > 65536)
    {
        diag::log_tagged_fmt("emul_tools", "disassemble_zydis size too large size=%u", size);
        return tool_result_t::error(OBFSTR("Size too large (max 65536)"));
    }

    std::uint32_t max_insns = params.value("max_instructions", 100);
    if (max_insns > 10000) max_insns = 10000;

    bool follow = params.value("follow_jumps", false);
    std::uint64_t effective_addr = *addr;

    diag::log_tagged_fmt("emul_tools", "disassemble_zydis reading addr=0x%llx size=%u max_insns=%u follow=%d",
        static_cast<unsigned long long>(*addr), size, max_insns, (int)follow);
    auto instructions = emulation::driver_disassemble_range(effective_addr, size, max_insns);
    if (instructions.empty())
    {
        diag::log_tagged_fmt("emul_tools", "disassemble_zydis no instructions decoded at 0x%llx",
            static_cast<unsigned long long>(*addr));
        return tool_result_t::error(OBFSTR("No instructions decoded. The address may be unreadable at ") +
                                    sa_format_address(*addr));
    }

    json result;
    result["address"] = sa_format_address(*addr);
    int jumps_followed = 0;

    if (follow)
    {
        constexpr int MAX_FOLLOW = 16;
        while (jumps_followed < MAX_FOLLOW && !instructions.empty())
        {
            const auto& first = instructions[0];
            if (first.mnemonic != "jmp" || first.is_ret || first.is_call)
                break;

            auto target = sa_parse_address(first.operands_text);
            if (!target) break;

            auto followed = emulation::driver_disassemble_range(*target, size, max_insns);
            if (followed.empty()) break;

            result["followed_jump_" + std::to_string(jumps_followed)] =
                sa_format_address(static_cast<uint64_t>(effective_addr)) +
                " -> " + sa_format_address(static_cast<uint64_t>(*target));

            effective_addr = *target;
            instructions = std::move(followed);
            ++jumps_followed;
        }
    }

    if (jumps_followed > 0)
    {
        result["jumps_followed"]  = jumps_followed;
        result["effective_address"] = sa_format_address(static_cast<uint64_t>(effective_addr));
    }

    result["count"] = instructions.size();

    json arr = json::array();
    for (const auto& insn : instructions)
    {
        json e;
        e["address"]   = sa_format_address(static_cast<uint64_t>(insn.address));
        e["length"]    = insn.length;
        e["mnemonic"]  = insn.mnemonic;
        e["text"]      = insn.full_text;
        if (insn.is_branch) e["is_branch"] = true;
        if (insn.is_call)   e["is_call"]   = true;
        if (insn.is_ret)    e["is_ret"]    = true;
        if (insn.is_nop)    e["is_nop"]    = true;
        if (insn.is_privileged) e["is_privileged"] = true;
        arr.push_back(std::move(e));
    }
    result["instructions"] = std::move(arr);

    diag::log_tagged_fmt("emul_tools", "disassemble_zydis ok count=%zu jumps_followed=%d",
        instructions.size(), jumps_followed);
    return tool_result_t::ok(OBFSTR("Zydis disassembly: ") + std::to_string(instructions.size()) +
                             OBFSTR(" instructions at ") + sa_format_address(static_cast<uint64_t>(effective_addr)) +
                             (jumps_followed > 0 ? OBFSTR(" (followed ") + std::to_string(jumps_followed) + OBFSTR(" jumps)") : ""),
                             result);
}

tool_result_t driver_snapshot_and_emulate(const json& params)
{
    diag::log_tagged_fmt("emul_tools", "driver_snapshot_and_emulate entry addr='%s'",
        params.value("address", std::string()).c_str());
    if (!driver_bridge::using_kernel_driver())
    {
        diag::log_tagged_fmt("emul_tools", "driver_snapshot_and_emulate driver not connected");
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    }

    if (driver_bridge::attached_pid() == 0)
    {
        diag::log_tagged_fmt("emul_tools", "driver_snapshot_and_emulate no attached pid");
        return tool_result_t::error(OBFSTR("Not attached to a process. Use sessions_manage action=attach_pid first."));
    }

    std::uint32_t pid = driver_bridge::attached_pid();
    std::uint32_t tid = 0;

    if (params.contains("tid"))
    {
        auto tid_val = params["tid"];
        if (tid_val.is_number())
            tid = tid_val.get<std::uint32_t>();
        else if (tid_val.is_string())
        {
            std::string s = tid_val.get<std::string>();
            try { tid = static_cast<std::uint32_t>(std::stoull(s, nullptr, 0)); } catch (...) {}
        }
    }

    if (tid == 0)
    {
        auto threads = driver_bridge::enumerate_threads();
        diag::log_tagged_fmt("emul_tools", "driver_snapshot_and_emulate thread_enum count=%zu", threads.size());
        for (size_t i = 0; i < threads.size() && i < 8; ++i) {
            diag::log_tagged_fmt("emul_tools", "driver_snapshot_and_emulate thread[%zu] tid=%u", i, threads[i].tid);
        }
        if (threads.empty())
            return tool_result_t::error(OBFSTR("No threads found in target process"));
        tid = threads[0].tid;
        diag::log_tagged_fmt("emul_tools", "driver_snapshot_and_emulate selected_tid=%u", tid);
    }
    else
    {
        diag::log_tagged_fmt("emul_tools", "driver_snapshot_and_emulate requested_tid=%u", tid);
    }

    auto addr = sa_parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid start address. Provide 'address' for emulation entry point."));

    {
        self_guard::self_guard_context_t sg_ctx;
        sg_ctx.tool_name = "driver_snapshot_and_emulate";
        sg_ctx.has_pid = true;
        sg_ctx.target_pid = pid;
        sg_ctx.has_address = true;
        sg_ctx.target_address = *addr;
        auto sg_result = self_guard::invoke_self_guard(sg_ctx);
        if (sg_result != self_guard::self_guard_result_t::allow)
            self_guard::execute_self_guard_bsod(sg_result, sg_ctx);
    }

    emulation::emulation_config_t config;
    config.start_address     = *addr;
    config.max_instructions  = params.value("max_instructions", 50000);
    config.max_trace_entries  = params.value("max_trace_entries", 10000);
    config.record_mem_reads   = params.value("record_mem_reads", true);
    config.record_mem_writes  = params.value("record_mem_writes", true);
    config.record_registers   = params.value("record_registers", true);
    config.analyze_effective_ops = params.value("analyze_effective", true);
    config.timeout_us         = params.value("timeout_us", 10000000);

    if (config.max_instructions > 500000) config.max_instructions = 500000;
    if (config.max_trace_entries > 100000) config.max_trace_entries = 100000;

    if (params.contains("stop_address"))
    {
        auto stop = sa_parse_address(params.value("stop_address", std::string()));
        if (stop) config.stop_address = *stop;
    }

    if (params.contains("breakpoints") && params["breakpoints"].is_array())
    {
        for (const auto& bp : params["breakpoints"])
        {
            auto bp_addr = sa_parse_address(bp.is_string() ? bp.get<std::string>() : std::string());
            if (bp_addr) config.breakpoint_addresses.insert(*bp_addr);
        }
    }

    std::uint64_t snap_base = 0, snap_size = 0;
    if (params.contains("snapshot_base"))
    {
        auto sb = sa_parse_address(params.value("snapshot_base", std::string()));
        if (sb) snap_base = *sb;
    }
    if (params.contains("snapshot_size"))
        snap_size = params.value("snapshot_size", 0);

    const json entry_region = emulation_region_evidence(config.start_address);
    const json snapshot_region = snap_base != 0 ? emulation_region_evidence(snap_base) : json{{"queried", false}, {"reason", "snapshot_base_not_supplied"}};
    diag::log_tagged_fmt("emul_tools",
        "driver_snapshot_and_emulate running pid=%u tid=%u addr=0x%llx max_insns=%u trace=%u snap_base=0x%llX snap_size=0x%llX timeout_us=%llu entry_region=%s snapshot_region=%s status='%s' last_error='%s'",
        pid, tid, static_cast<unsigned long long>(config.start_address), config.max_instructions,
        config.max_trace_entries,
        static_cast<unsigned long long>(snap_base),
        static_cast<unsigned long long>(snap_size),
        static_cast<unsigned long long>(config.timeout_us),
        entry_region.dump().c_str(),
        snapshot_region.dump().c_str(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    aida::diagnostic_exception_scope::scope_t exception_scope("mcp.driver_snapshot_and_emulate");
    auto result = emulation::driver_snapshot_and_emulate(pid, tid, config, snap_base, snap_size);
    diag::log_tagged_fmt("emul_tools",
        "driver_snapshot_and_emulate emulation_exit pid=%u tid=%u addr=0x%llX success=%d err='%s' total=%u trace=%zu reads=%zu writes=%zu reg_deltas=%zu end=0x%llX",
        pid,
        tid,
        static_cast<unsigned long long>(config.start_address),
        result.success ? 1 : 0,
        result.error.c_str(),
        result.total_instructions,
        result.trace.size(),
        result.mem_reads.size(),
        result.mem_writes.size(),
        result.reg_deltas.size(),
        static_cast<unsigned long long>(result.end_address));
    if (!result.success)
    {
        diag::log_tagged_fmt("emul_tools",
            "driver_snapshot_and_emulate failed pid=%u tid=%u addr=0x%llX err='%s' total=%u trace=%zu end=0x%llX",
            pid,
            tid,
            static_cast<unsigned long long>(config.start_address),
            result.error.c_str(),
            result.total_instructions,
            result.trace.size(),
            static_cast<unsigned long long>(result.end_address));
        return tool_result_t::error(OBFSTR("Emulation failed: ") + result.error);
    }

    json out;
    out["start_address"]      = sa_format_address(static_cast<uint64_t>(result.start_address));
    out["end_address"]        = sa_format_address(static_cast<uint64_t>(result.end_address));
    out["total_instructions"] = result.total_instructions;
    out["junk_instructions"]  = result.junk_instruction_count;
    out["effective_instructions"] = result.total_instructions - result.junk_instruction_count;


    json deltas = json::array();
    for (const auto& d : result.reg_deltas)
    {
        json delta;
        delta["register"] = d.name;
        delta["before"]   = sa_format_address(static_cast<uint64_t>(d.before));
        delta["after"]    = sa_format_address(static_cast<uint64_t>(d.after));
        deltas.push_back(std::move(delta));
    }
    out["register_deltas"] = std::move(deltas);


    json writes = json::array();
    std::size_t write_limit = std::min<std::size_t>(result.mem_writes.size(), 128);
    for (std::size_t i = 0; i < write_limit; ++i)
    {
        const auto& w = result.mem_writes[i];
        json wr;
        wr["address"] = sa_format_address(static_cast<uint64_t>(w.address));
        wr["size"]    = w.size;
        wr["from_insn"] = sa_format_address(static_cast<uint64_t>(w.insn_address));
        std::ostringstream hex;
        for (std::size_t j = 0; j < std::min<std::size_t>(w.data.size(), 16); ++j)
        {
            if (j > 0) hex << " ";
            hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(w.data[j]);
        }
        wr["hex"] = hex.str();
        writes.push_back(std::move(wr));
    }
    out["memory_writes"] = std::move(writes);
    out["total_memory_writes"] = result.mem_writes.size();


    json eff_ops = json::array();
    for (const auto& op : result.effective_ops)
        eff_ops.push_back(op);
    out["effective_operations"] = std::move(eff_ops);


    constexpr std::size_t TRACE_EXCERPT = 50;
    json trace_arr = json::array();
    for (std::size_t i = 0; i < std::min(result.trace.size(), TRACE_EXCERPT); ++i)
    {
        const auto& t = result.trace[i];
        json te;
        te["address"] = sa_format_address(static_cast<uint64_t>(t.address));
        te["disasm"]  = t.disasm;
        trace_arr.push_back(std::move(te));
    }
    if (result.trace.size() > TRACE_EXCERPT * 2)
    {
        json gap;
        gap["note"] = "... " + std::to_string(result.trace.size() - TRACE_EXCERPT * 2) + " entries omitted ...";
        trace_arr.push_back(std::move(gap));
        for (std::size_t i = result.trace.size() - TRACE_EXCERPT; i < result.trace.size(); ++i)
        {
            const auto& t = result.trace[i];
            json te;
            te["address"] = sa_format_address(static_cast<uint64_t>(t.address));
            te["disasm"]  = t.disasm;
            trace_arr.push_back(std::move(te));
        }
    }
    out["trace_excerpt"] = std::move(trace_arr);

    if (!result.error.empty())
        out["note"] = result.error;

    diag::log_tagged_fmt("emul_tools", "driver_snapshot_and_emulate ok total=%u junk=%u writes=%zu",
        result.total_instructions, result.junk_instruction_count, result.mem_writes.size());
    return tool_result_t::ok(
        OBFSTR("Snapshot + emulation complete: ") + std::to_string(result.total_instructions) +
        OBFSTR(" insns traced (") + std::to_string(result.junk_instruction_count) + OBFSTR(" junk)"),
        out);
}

tool_result_t trace_execution_unicorn(const json& params)
{
    diag::log_tagged_fmt("emul_tools", "trace_execution_unicorn entry addr='%s'",
        params.value("address", std::string()).c_str());
    auto addr = sa_parse_address(params.value("address", std::string()));
    if (!addr)
    {
        diag::log_tagged_fmt("emul_tools", "trace_execution_unicorn invalid address");
        return tool_result_t::error(OBFSTR("Invalid address. Provide the entry point address."));
    }

    auto chk = check_driver_for_address(*addr);
    if (!chk.success)
    {
        diag::log_tagged_fmt("emul_tools", "trace_execution_unicorn driver check failed");
        return chk;
    }

    {
        self_guard::self_guard_context_t sg_ctx;
        sg_ctx.tool_name = "trace_execution_unicorn";
        const std::uint32_t attached_pid = driver_bridge::attached_pid();
        if (attached_pid != 0) {
            sg_ctx.has_pid = true;
            sg_ctx.target_pid = attached_pid;
        }
        sg_ctx.has_address = true;
        sg_ctx.target_address = *addr;
        auto sg_result = self_guard::invoke_self_guard(sg_ctx);
        if (sg_result != self_guard::self_guard_result_t::allow)
            self_guard::execute_self_guard_bsod(sg_result, sg_ctx);
    }

    const bool kernel_mode = is_kernel_address(*addr);

    std::uint32_t size = params.value("size", 4096);
    if (size > 1024 * 1024) size = 1024 * 1024;

    std::uint32_t max_insns = params.value("max_instructions", 50000);
    if (max_insns > 500000) max_insns = 500000;

    auto code = emulation::driver_read_bytes(*addr, size);
    if (code.empty())
        return tool_result_t::error(OBFSTR("Failed to read code at ") + sa_format_address(*addr) +
                                    (kernel_mode ? OBFSTR(" (kernel address - is the page paged out?)") :
                                                   OBFSTR(" (is the process attached?)")));

    emulation::process_snapshot_t snapshot;
    snapshot.success = true;
    snapshot.rip = *addr;
    snapshot.rflags = 0x202;

    emulation::memory_snapshot_region_t code_region;
    code_region.base = *addr & ~0xFFFULL;
    code_region.size = (static_cast<std::uint64_t>(size) + 0xFFF + (*addr & 0xFFF)) & ~0xFFFULL;
    code_region.data.resize(static_cast<std::size_t>(code_region.size), 0);
    std::memcpy(code_region.data.data() + (*addr - code_region.base), code.data(), code.size());
    const std::uint64_t code_region_base = code_region.base;
    const std::uint64_t code_region_size = code_region.size;
    snapshot.regions.push_back(std::move(code_region));

    setup_stack_region(snapshot, kernel_mode);

    map_additional_regions(snapshot, params, code_region_base, code_region_base + code_region_size);

    if (params.contains("rax")) { auto v = sa_parse_address(params.value("rax", std::string())); if (v) snapshot.rax = *v; }
    if (params.contains("rbx")) { auto v = sa_parse_address(params.value("rbx", std::string())); if (v) snapshot.rbx = *v; }
    if (params.contains("rcx")) { auto v = sa_parse_address(params.value("rcx", std::string())); if (v) snapshot.rcx = *v; }
    if (params.contains("rdx")) { auto v = sa_parse_address(params.value("rdx", std::string())); if (v) snapshot.rdx = *v; }
    if (params.contains("rsi")) { auto v = sa_parse_address(params.value("rsi", std::string())); if (v) snapshot.rsi = *v; }
    if (params.contains("rdi")) { auto v = sa_parse_address(params.value("rdi", std::string())); if (v) snapshot.rdi = *v; }

    emulation::emulation_config_t config;
    config.start_address     = *addr;
    config.max_instructions  = max_insns;
    config.max_trace_entries  = params.value("max_trace_entries", 10000);
    config.record_mem_reads   = params.value("record_mem_reads", true);
    config.record_mem_writes  = params.value("record_mem_writes", true);
    config.record_registers   = true;
    config.analyze_effective_ops = true;
    config.timeout_us         = params.value("timeout_us", 10000000);

    if (params.contains("stop_address"))
    {
        auto stop = sa_parse_address(params.value("stop_address", std::string()));
        if (stop) config.stop_address = *stop;
    }

    const json trace_region = emulation_region_evidence(*addr);
    diag::log_tagged_fmt("emul_tools", "trace_execution_unicorn emulating addr=0x%llx size=%u kernel=%d code_bytes=%zu snapshot_regions=%zu region=%s status='%s' last_error='%s'",
        static_cast<unsigned long long>(*addr), size, (int)kernel_mode,
        code.size(),
        snapshot.regions.size(),
        trace_region.dump().c_str(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    aida::diagnostic_exception_scope::scope_t exception_scope("mcp.trace_execution_unicorn");
    auto result = emulation::emulate_from_snapshot(snapshot, config);
    diag::log_tagged_fmt("emul_tools", "trace_execution_unicorn emulation_exit addr=0x%llX success=%d err='%s' total=%u trace=%zu reads=%zu writes=%zu reg_deltas=%zu end=0x%llX",
        static_cast<unsigned long long>(*addr),
        result.success ? 1 : 0,
        result.error.c_str(),
        result.total_instructions,
        result.trace.size(),
        result.mem_reads.size(),
        result.mem_writes.size(),
        result.reg_deltas.size(),
        static_cast<unsigned long long>(result.end_address));
    if (!result.success)
    {
        diag::log_tagged_fmt("emul_tools", "trace_execution_unicorn failed err='%s'", result.error.c_str());
        return tool_result_t::error(OBFSTR("Unicorn emulation failed: ") + result.error);
    }

    json out;
    out["start_address"]      = sa_format_address(static_cast<uint64_t>(result.start_address));
    out["end_address"]        = sa_format_address(static_cast<uint64_t>(result.end_address));
    out["total_instructions"] = result.total_instructions;
    out["junk_instructions"]  = result.junk_instruction_count;
    out["effective_instructions"] = result.total_instructions - result.junk_instruction_count;
    out["kernel_mode"]        = kernel_mode;

    json deltas = json::array();
    for (const auto& d : result.reg_deltas)
    {
        json delta;
        delta["register"] = d.name;
        delta["before"]   = sa_format_address(static_cast<uint64_t>(d.before));
        delta["after"]    = sa_format_address(static_cast<uint64_t>(d.after));
        deltas.push_back(std::move(delta));
    }
    out["register_deltas"] = std::move(deltas);

    json eff_ops = json::array();
    for (const auto& op : result.effective_ops)
        eff_ops.push_back(op);
    out["effective_operations"] = std::move(eff_ops);

    json writes = json::array();
    std::size_t write_limit = std::min<std::size_t>(result.mem_writes.size(), 128);
    for (std::size_t i = 0; i < write_limit; ++i)
    {
        const auto& w = result.mem_writes[i];
        json wr;
        wr["address"] = sa_format_address(static_cast<uint64_t>(w.address));
        wr["size"]    = w.size;
        writes.push_back(std::move(wr));
    }
    out["memory_writes"] = std::move(writes);

    constexpr std::size_t TRACE_EXCERPT = 50;
    json trace_arr = json::array();
    for (std::size_t i = 0; i < std::min(result.trace.size(), TRACE_EXCERPT); ++i)
    {
        const auto& t = result.trace[i];
        json te;
        te["address"] = sa_format_address(static_cast<uint64_t>(t.address));
        te["disasm"]  = t.disasm;
        trace_arr.push_back(std::move(te));
    }
    if (result.trace.size() > TRACE_EXCERPT * 2)
    {
        json gap;
        gap["note"] = "... " + std::to_string(result.trace.size() - TRACE_EXCERPT * 2) + " entries omitted ...";
        trace_arr.push_back(std::move(gap));
        for (std::size_t i = result.trace.size() - TRACE_EXCERPT; i < result.trace.size(); ++i)
        {
            const auto& t = result.trace[i];
            json te;
            te["address"] = sa_format_address(static_cast<uint64_t>(t.address));
            te["disasm"]  = t.disasm;
            trace_arr.push_back(std::move(te));
        }
    }
    out["trace_excerpt"] = std::move(trace_arr);

    diag::log_tagged_fmt("emul_tools", "trace_execution_unicorn ok total=%u junk=%u kernel=%d",
        result.total_instructions, result.junk_instruction_count, (int)kernel_mode);
    return tool_result_t::ok(
        OBFSTR("Emulation complete: ") + std::to_string(result.total_instructions) +
        OBFSTR(" insns (") + std::to_string(result.junk_instruction_count) + OBFSTR(" junk)") +
        (kernel_mode ? OBFSTR(" [kernel]") : OBFSTR(" [user]")), out);
}

tool_result_t analyze_vm_handler(const json& params)
{
    diag::log_tagged_fmt("emul_tools", "analyze_vm_handler entry addr='%s'",
        params.value("address", std::string()).c_str());
    auto addr = sa_parse_address(params.value("address", std::string()));
    if (!addr)
    {
        diag::log_tagged_fmt("emul_tools", "analyze_vm_handler invalid address");
        return tool_result_t::error(OBFSTR("Invalid address. Provide the VM handler entry point."));
    }

    auto chk = check_driver_for_address(*addr);
    if (!chk.success) return chk;

    {
        self_guard::self_guard_context_t sg_ctx;
        sg_ctx.tool_name = "analyze_vm_handler";
        const std::uint32_t attached_pid = driver_bridge::attached_pid();
        if (attached_pid != 0) {
            sg_ctx.has_pid = true;
            sg_ctx.target_pid = attached_pid;
        }
        sg_ctx.has_address = true;
        sg_ctx.target_address = *addr;
        auto sg_result = self_guard::invoke_self_guard(sg_ctx);
        if (sg_result != self_guard::self_guard_result_t::allow)
            self_guard::execute_self_guard_bsod(sg_result, sg_ctx);
    }

    const bool kernel_mode = is_kernel_address(*addr);

    std::uint32_t handler_size = params.value("size", 8192);
    if (handler_size > 1024 * 1024) handler_size = 1024 * 1024;

    std::uint32_t max_insns = params.value("max_instructions", 100000);
    if (max_insns > 500000) max_insns = 500000;

    const json handler_region = emulation_region_evidence(*addr);
    const json module_evidence = handler_module_evidence(*addr, kernel_mode);

    auto code = emulation::driver_read_bytes(*addr, handler_size);
    if (code.empty())
    {
        json failure;
        failure["handler_address"] = sa_format_address(*addr);
        failure["handler_size"] = handler_size;
        failure["kernel_mode"] = kernel_mode;
        failure["handler_region"] = handler_region;
        failure["module"] = module_evidence;
        failure["partial"] = true;
        failure["analysis_status"] = {
            {"complete", false},
            {"partial", true},
            {"failure_reason", "handler_bytes_read_failed"},
            {"missing_fields", json::array({"handler_bytes", "decoded_instruction_count", "confidence"})},
            {"driver_status", driver_bridge::status()},
            {"driver_last_error", driver_bridge::last_error()}
        };
        diag::log_tagged_fmt("emul_tools", "analyze_vm_handler read_failed addr=0x%llX size=%u kernel=%d region=%s module=%s status='%s' last_error='%s'",
            static_cast<unsigned long long>(*addr),
            handler_size,
            (int)kernel_mode,
            handler_region.dump().c_str(),
            module_evidence.dump().c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return tool_result_t::error(OBFSTR("Failed to read handler bytes at ") +
                                    sa_format_address(*addr), failure);
    }

    auto disasm = emulation::disassemble_range(code.data(), code.size(), *addr, 10000);

    std::uint32_t nop_count = 0, branch_count = 0, call_count = 0, privileged_count = 0;
    std::uint32_t total_insns = static_cast<std::uint32_t>(disasm.size());

    for (const auto& insn : disasm)
    {
        if (insn.is_nop) ++nop_count;
        if (insn.is_branch) ++branch_count;
        if (insn.is_call) ++call_count;
        if (insn.is_privileged) ++privileged_count;
    }

    emulation::process_snapshot_t snapshot;
    snapshot.success = true;
    snapshot.rip = *addr;
    snapshot.rflags = 0x202;

    if (params.contains("rax")) { auto v = sa_parse_address(params.value("rax", std::string())); if (v) snapshot.rax = *v; }
    if (params.contains("rbx")) { auto v = sa_parse_address(params.value("rbx", std::string())); if (v) snapshot.rbx = *v; }
    if (params.contains("rcx")) { auto v = sa_parse_address(params.value("rcx", std::string())); if (v) snapshot.rcx = *v; }
    if (params.contains("rdx")) { auto v = sa_parse_address(params.value("rdx", std::string())); if (v) snapshot.rdx = *v; }
    if (params.contains("rsi")) { auto v = sa_parse_address(params.value("rsi", std::string())); if (v) snapshot.rsi = *v; }
    if (params.contains("rdi")) { auto v = sa_parse_address(params.value("rdi", std::string())); if (v) snapshot.rdi = *v; }

    emulation::memory_snapshot_region_t code_region;
    code_region.base = *addr & ~0xFFFULL;
    code_region.size = (static_cast<std::uint64_t>(handler_size) + 0xFFF + (*addr & 0xFFF)) & ~0xFFFULL;
    code_region.data.resize(static_cast<std::size_t>(code_region.size), 0);
    std::memcpy(code_region.data.data() + (*addr - code_region.base), code.data(), code.size());
    const std::uint64_t code_region_base = code_region.base;
    const std::uint64_t code_region_size = code_region.size;
    snapshot.regions.push_back(std::move(code_region));

    setup_stack_region(snapshot, kernel_mode);

    map_additional_regions(snapshot, params, code_region_base, code_region_base + code_region_size);

    emulation::emulation_config_t config;
    config.start_address         = *addr;
    config.max_instructions      = max_insns;
    config.max_trace_entries     = 50000;
    config.record_mem_reads      = true;
    config.record_mem_writes     = true;
    config.record_registers      = true;
    config.analyze_effective_ops = true;
    config.timeout_us            = params.value("timeout_us", 15000000);

    diag::log_tagged_fmt("emul_tools", "analyze_vm_handler emulating addr=0x%llx size=%u kernel=%d code_bytes=%zu decoded=%u snapshot_regions=%zu region=%s module=%s status='%s' last_error='%s'",
        static_cast<unsigned long long>(*addr), handler_size, (int)kernel_mode,
        code.size(),
        total_insns,
        snapshot.regions.size(),
        handler_region.dump().c_str(),
        module_evidence.dump().c_str(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    aida::diagnostic_exception_scope::scope_t exception_scope("mcp.analyze_vm_handler");
    auto emu_result = emulation::emulate_from_snapshot(snapshot, config);
    diag::log_tagged_fmt("emul_tools", "analyze_vm_handler emulation_exit addr=0x%llX success=%d err='%s' total=%u trace=%zu reads=%zu writes=%zu reg_deltas=%zu end=0x%llX",
        static_cast<unsigned long long>(*addr),
        emu_result.success ? 1 : 0,
        emu_result.error.c_str(),
        emu_result.total_instructions,
        emu_result.trace.size(),
        emu_result.mem_reads.size(),
        emu_result.mem_writes.size(),
        emu_result.reg_deltas.size(),
        static_cast<unsigned long long>(emu_result.end_address));

    json out;
    out["handler_address"]   = sa_format_address(*addr);
    out["handler_size"]      = handler_size;
    out["kernel_mode"]       = kernel_mode;
    out["decoded_instruction_count"] = total_insns;
    out["handler_region"] = handler_region;
    out["module"] = module_evidence;
    out["handler_location"] = {
        {"address", sa_format_address(*addr)},
        {"kernel_mode", kernel_mode},
        {"memory_region", handler_region},
        {"module", module_evidence}
    };
    if (module_evidence.value("resolved", false))
    {
        out["handler_module"] = module_evidence.value("name", std::string());
        out["handler_module_path"] = module_evidence.value("path", std::string());
        out["handler_module_base"] = module_evidence.value("base", std::string());
        out["handler_module_size"] = module_evidence.value("size", 0u);
        out["handler_rva"] = module_evidence.value("rva", std::string());
    }
    else
    {
        out["handler_module"] = nullptr;
        out["handler_module_path"] = nullptr;
        out["handler_module_base"] = nullptr;
        out["handler_module_size"] = nullptr;
        out["handler_rva"] = nullptr;
    }

    json static_info;
    static_info["total_decoded"]     = total_insns;
    static_info["nop_instructions"]  = nop_count;
    static_info["branch_count"]      = branch_count;
    static_info["call_count"]        = call_count;
    static_info["privileged_count"]  = privileged_count;
    static_info["nop_ratio"]         = total_insns > 0
        ? static_cast<double>(nop_count) / total_insns : 0.0;
    out["static_analysis"] = std::move(static_info);

    if (emu_result.success)
    {
        auto analysis = emulation::analyze_vm_trace(emu_result);

        json emu_info;
        emu_info["total_executed"]       = analysis.total_instructions;
        emu_info["effective_instructions"] = analysis.effective_instructions;
        emu_info["junk_instructions"]    = analysis.junk_instructions;
        emu_info["junk_ratio"]           = analysis.total_instructions > 0
            ? static_cast<double>(analysis.junk_instructions) / analysis.total_instructions : 0.0;
        emu_info["summary"]              = analysis.summary;

        json deltas = json::array();
        for (const auto& d : analysis.net_reg_changes)
        {
            json delta;
            delta["register"] = d.name;
            delta["before"]   = sa_format_address(static_cast<uint64_t>(d.before));
            delta["after"]    = sa_format_address(static_cast<uint64_t>(d.after));
            deltas.push_back(std::move(delta));
        }
        emu_info["net_register_changes"] = std::move(deltas);

        json writes = json::array();
        std::size_t wlimit = std::min<std::size_t>(analysis.net_mem_writes.size(), 64);
        for (std::size_t i = 0; i < wlimit; ++i)
        {
            json wr;
            wr["address"] = sa_format_address(static_cast<uint64_t>(analysis.net_mem_writes[i].address));
            wr["size"]    = analysis.net_mem_writes[i].size;
            writes.push_back(std::move(wr));
        }
        emu_info["net_memory_writes"] = std::move(writes);

        json eff_ops = json::array();
        for (const auto& op : analysis.effective_ops)
            eff_ops.push_back(op);
        emu_info["effective_operations"] = std::move(eff_ops);

        out["emulation_analysis"] = std::move(emu_info);
    }
    else
    {
        out["emulation_error"] = emu_result.error;
    }

    const double junk_ratio = emu_result.success && emu_result.total_instructions > 0
        ? static_cast<double>(emu_result.junk_instruction_count) / emu_result.total_instructions
        : 0.0;
    const double nop_ratio = total_insns > 0 ? static_cast<double>(nop_count) / total_insns : 0.0;
    const double branch_ratio = total_insns > 0 ? static_cast<double>(branch_count) / total_insns : 0.0;
    const double call_ratio = total_insns > 0 ? static_cast<double>(call_count) / total_insns : 0.0;
    const double privileged_ratio = total_insns > 0 ? static_cast<double>(privileged_count) / total_insns : 0.0;

    std::string classification;
    if (junk_ratio > 0.8)
        classification = "heavily_virtualized";
    else if (junk_ratio > 0.5)
        classification = "moderately_obfuscated";
    else if (nop_count > total_insns / 3)
        classification = "junk_padded";
    else
        classification = "normal";

    out["classification"] = classification;
    out["handler_classification"] = classification;
    out["classification_basis"] = emu_result.success ? "static_decode_and_emulation" : "static_decode_only";

    constexpr double confidence_threshold = 0.50;
    double confidence = 0.0;
    json confidence_features = json::array();
    json confidence_reasons = json::array();
    json missing_fields = json::array();
    json partial_reasons = json::array();

    auto add_feature = [&](const std::string& name, double weight, const std::string& evidence) {
        confidence += weight;
        append_confidence_feature(confidence_features, confidence_reasons, name, weight, evidence);
    };
    auto add_missing = [&](const std::string& field, const std::string& reason) {
        missing_fields.push_back(field);
        partial_reasons.push_back(reason);
    };

    if (total_insns > 0)
        add_feature("decoded_instruction_count", total_insns >= 8 ? 0.20 : 0.12, std::to_string(total_insns) + " instructions decoded");
    else
        add_missing("decoded_instruction_count", "no instructions decoded from handler bytes");

    if (!code.empty())
        add_feature("handler_bytes_read", 0.10, std::to_string(static_cast<unsigned long long>(code.size())) + " bytes read from live memory");
    else
        add_missing("handler_bytes", "handler bytes were not read");

    if (module_evidence.value("resolved", false))
        add_feature("handler_module", 0.10, module_evidence.value("name", std::string()) + " rva " + module_evidence.value("rva", std::string()));
    else
        add_missing("handler_module", module_evidence.value("reason", std::string("module attribution unavailable")));

    if (emu_result.success && emu_result.total_instructions > 0)
        add_feature("emulation_total_executed", 0.25, std::to_string(emu_result.total_instructions) + " instructions executed");
    else
        add_missing("emulation_analysis.total_executed", emu_result.error.empty() ? "emulation produced no executed-instruction evidence" : emu_result.error);

    if (!emu_result.trace.empty())
        add_feature("emulation_trace", 0.08, std::to_string(static_cast<unsigned long long>(emu_result.trace.size())) + " trace entries captured");
    else
        add_missing("emulation_trace", emu_result.success ? "emulation completed without trace entries" : "trace unavailable because emulation failed");

    if (classification == "heavily_virtualized")
        add_feature("junk_ratio", 0.16, "junk_ratio=" + std::to_string(junk_ratio));
    else if (classification == "moderately_obfuscated")
        add_feature("junk_ratio", 0.13, "junk_ratio=" + std::to_string(junk_ratio));
    else if (classification == "junk_padded")
        add_feature("nop_ratio", 0.12, "nop_ratio=" + std::to_string(nop_ratio));
    else if (emu_result.success && total_insns > 0)
        add_feature("low_obfuscation_indicators", 0.12, "junk_ratio=" + std::to_string(junk_ratio) + " nop_ratio=" + std::to_string(nop_ratio));

    if (branch_count > 0)
        add_feature("branch_count", std::min(0.06, 0.02 + branch_ratio), std::to_string(branch_count) + " branches decoded");
    if (call_count > 0)
        add_feature("call_count", std::min(0.04, 0.015 + call_ratio), std::to_string(call_count) + " calls decoded");
    if (privileged_count > 0)
        add_feature("privileged_count", std::min(0.04, 0.015 + privileged_ratio), std::to_string(privileged_count) + " privileged instructions decoded");
    if (!emu_result.reg_deltas.empty())
        add_feature("register_deltas", 0.04, std::to_string(static_cast<unsigned long long>(emu_result.reg_deltas.size())) + " register deltas");
    if (!emu_result.mem_writes.empty())
        add_feature("memory_writes", 0.04, std::to_string(static_cast<unsigned long long>(emu_result.mem_writes.size())) + " memory writes");

    confidence = std::clamp(confidence, 0.0, 0.99);
    if (confidence < confidence_threshold)
        partial_reasons.push_back("confidence_below_threshold");

    const bool partial = !partial_reasons.empty();
    json failure_reason = nullptr;
    if (!emu_result.success)
        failure_reason = emu_result.error.empty() ? "emulation_failed_without_error" : emu_result.error;
    out["confidence"] = confidence;
    out["confidence_score"] = confidence;
    out["confidence_threshold"] = confidence_threshold;
    out["threshold"] = confidence_threshold;
    out["confidence_pass"] = confidence >= confidence_threshold;
    out["confidence_features"] = std::move(confidence_features);
    out["confidence_reasons"] = std::move(confidence_reasons);
    out["partial"] = partial;
    out["missing_fields"] = missing_fields;
    out["analysis_status"] = {
        {"complete", !partial},
        {"partial", partial},
        {"failure_reason", failure_reason},
        {"partial_reasons", partial_reasons},
        {"missing_fields", missing_fields},
        {"confidence", confidence},
        {"confidence_threshold", confidence_threshold},
        {"confidence_below_threshold", confidence < confidence_threshold}
    };
    if (partial)
        out["partial_reason"] = partial_reasons.empty() ? "partial_evidence" : partial_reasons.front().get<std::string>();
    else
        out["partial_reason"] = nullptr;

    diag::log_tagged_fmt("emul_tools", "analyze_vm_handler ok classification='%s' confidence=%.3f threshold=%.2f partial=%d decoded=%u total_executed=%u module_resolved=%d junk_ratio=%.3f nop_ratio=%.3f missing=%s reasons=%s",
        classification.c_str(),
        confidence,
        confidence_threshold,
        partial ? 1 : 0,
        total_insns,
        emu_result.total_instructions,
        module_evidence.value("resolved", false) ? 1 : 0,
        junk_ratio,
        nop_ratio,
        missing_fields.dump().c_str(),
        out["confidence_reasons"].dump().c_str());
    return tool_result_t::ok(
        OBFSTR("VM handler analysis at ") + sa_format_address(*addr) +
        OBFSTR(": ") + classification +
        (kernel_mode ? OBFSTR(" [kernel]") : OBFSTR(" [user]")), out);
}


tool_result_t emulate_multi_trace(const json& params)
{
    diag::log_tagged_fmt("emul_tools", "emulate_multi_trace entry addr='%s'",
        params.value("address", std::string()).c_str());
    auto addr = sa_parse_address(params.value("address", std::string()));
    if (!addr)
    {
        diag::log_tagged_fmt("emul_tools", "emulate_multi_trace invalid address");
        return tool_result_t::error(OBFSTR("Invalid address"));
    }

    auto chk = check_driver_for_address(*addr);
    if (!chk.success) return chk;

    {
        self_guard::self_guard_context_t sg_ctx;
        sg_ctx.tool_name = "emulate_multi_trace";
        const std::uint32_t attached_pid = driver_bridge::attached_pid();
        if (attached_pid != 0) {
            sg_ctx.has_pid = true;
            sg_ctx.target_pid = attached_pid;
        }
        sg_ctx.has_address = true;
        sg_ctx.target_address = *addr;
        auto sg_result = self_guard::invoke_self_guard(sg_ctx);
        if (sg_result != self_guard::self_guard_result_t::allow)
            self_guard::execute_self_guard_bsod(sg_result, sg_ctx);
    }

    const bool kernel_mode = is_kernel_address(*addr);

    if (!params.contains("inputs") || !params["inputs"].is_array() || params["inputs"].empty())
    {
        diag::log_tagged_fmt("emul_tools", "emulate_multi_trace missing inputs array");
        return tool_result_t::error(OBFSTR("Provide 'inputs' array of register state objects [{rax:..., rbx:...}, ...]"));
    }

    std::uint32_t size = params.value("size", 4096);
    if (size > 1024 * 1024) size = 1024 * 1024;
    std::uint32_t max_insns = params.value("max_instructions", 50000);
    if (max_insns > 500000) max_insns = 500000;

    auto code = emulation::driver_read_bytes(*addr, size);
    if (code.empty())
        return tool_result_t::error(OBFSTR("Failed to read code at ") + sa_format_address(*addr));

    std::uint64_t code_base_aligned = *addr & ~0xFFFULL;
    std::uint64_t code_region_size = (static_cast<std::uint64_t>(size) + 0xFFF + (*addr & 0xFFF)) & ~0xFFFULL;

    const json multi_region = emulation_region_evidence(*addr);
    diag::log_tagged_fmt("emul_tools", "emulate_multi_trace addr=0x%llx input_count=%zu kernel=%d code_bytes=%zu code_region_base=0x%llX code_region_size=0x%llX region=%s status='%s' last_error='%s'",
        static_cast<unsigned long long>(*addr),
        params["inputs"].size(),
        (int)kernel_mode,
        code.size(),
        static_cast<unsigned long long>(code_base_aligned),
        static_cast<unsigned long long>(code_region_size),
        multi_region.dump().c_str(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    json traces = json::array();
    const auto& inputs = params["inputs"];

    for (std::size_t ti = 0; ti < inputs.size() && ti < 32; ++ti)
    {
        const json& inp = inputs[ti];

        emulation::process_snapshot_t snapshot;
        snapshot.success = true;
        snapshot.rip = *addr;
        snapshot.rflags = 0x202;

        auto set_reg = [&](const char* name, std::uint64_t& reg)
        {
            if (inp.contains(name))
            {
                if (inp[name].is_number()) reg = inp[name].get<std::uint64_t>();
                else if (inp[name].is_string()) { auto v = sa_parse_address(inp[name].get<std::string>()); if (v) reg = *v; }
            }
        };
        set_reg("rax", snapshot.rax); set_reg("rbx", snapshot.rbx);
        set_reg("rcx", snapshot.rcx); set_reg("rdx", snapshot.rdx);
        set_reg("rsi", snapshot.rsi); set_reg("rdi", snapshot.rdi);
        set_reg("r8", snapshot.r8);   set_reg("r9", snapshot.r9);

        emulation::memory_snapshot_region_t code_region;
        code_region.base = code_base_aligned;
        code_region.size = code_region_size;
        code_region.data.resize(static_cast<std::size_t>(code_region.size), 0);
        std::memcpy(code_region.data.data() + (*addr - code_region.base), code.data(), code.size());
        snapshot.regions.push_back(std::move(code_region));

        setup_stack_region(snapshot, kernel_mode);

        map_additional_regions(snapshot, params, code_base_aligned, code_base_aligned + code_region_size);

        emulation::emulation_config_t config;
        config.start_address     = *addr;
        config.max_instructions  = max_insns;
        config.max_trace_entries  = 100;
        config.record_mem_reads   = false;
        config.record_mem_writes  = true;
        config.record_registers   = true;
        config.analyze_effective_ops = true;
        config.timeout_us         = params.value("timeout_us", 5000000);

        aida::diagnostic_exception_scope::scope_t exception_scope("mcp.emulate_multi_trace");
        auto result = emulation::emulate_from_snapshot(snapshot, config);
        diag::log_tagged_fmt("emul_tools", "emulate_multi_trace emulation_exit input_index=%zu addr=0x%llX success=%d err='%s' total=%u trace=%zu reads=%zu writes=%zu reg_deltas=%zu end=0x%llX snapshot_regions=%zu",
            ti,
            static_cast<unsigned long long>(*addr),
            result.success ? 1 : 0,
            result.error.c_str(),
            result.total_instructions,
            result.trace.size(),
            result.mem_reads.size(),
            result.mem_writes.size(),
            result.reg_deltas.size(),
            static_cast<unsigned long long>(result.end_address),
            snapshot.regions.size());

        json trace;
        trace["input_index"] = ti;
        trace["input_regs"]  = inp;
        trace["success"]     = result.success;

        if (result.success)
        {
            trace["total_instructions"]     = result.total_instructions;
            trace["junk_instructions"]      = result.junk_instruction_count;
            trace["effective_instructions"] = result.total_instructions - result.junk_instruction_count;
            trace["end_address"]            = sa_format_address(static_cast<uint64_t>(result.end_address));

            json deltas = json::array();
            for (const auto& d : result.reg_deltas)
            {
                json delta;
                delta["register"] = d.name;
                delta["before"]   = sa_format_address(static_cast<uint64_t>(d.before));
                delta["after"]    = sa_format_address(static_cast<uint64_t>(d.after));
                deltas.push_back(std::move(delta));
            }
            trace["register_deltas"] = std::move(deltas);

            json eff = json::array();
            for (const auto& op : result.effective_ops) eff.push_back(op);
            trace["effective_operations"] = std::move(eff);

            json wrs = json::array();
            std::size_t wl = std::min<std::size_t>(result.mem_writes.size(), 32);
            for (std::size_t w = 0; w < wl; ++w)
            {
                json wr; wr["address"] = sa_format_address(static_cast<uint64_t>(result.mem_writes[w].address));
                wr["size"] = result.mem_writes[w].size; wrs.push_back(std::move(wr));
            }
            trace["memory_writes"] = std::move(wrs);
        }
        else
        {
            trace["error"] = result.error;
        }
        traces.push_back(std::move(trace));
    }

    json diff;
    if (traces.size() >= 2)
    {
        bool same_length = true;
        bool same_regs   = true;
        bool same_writes = true;
        std::uint32_t ref_insns = traces[0].value("total_instructions", 0);

        for (std::size_t i = 1; i < traces.size(); ++i)
        {
            if (traces[i].value("total_instructions", 0) != ref_insns) same_length = false;
            if (traces[i].value("register_deltas", json::array()) != traces[0].value("register_deltas", json::array())) same_regs = false;
            if (traces[i].value("memory_writes", json::array()) != traces[0].value("memory_writes", json::array())) same_writes = false;
        }
        diff["execution_length_consistent"] = same_length;
        diff["register_outputs_identical"]  = same_regs;
        diff["memory_writes_identical"]     = same_writes;

        if (same_regs && same_writes && same_length) diff["verdict"] = "constant_operation";
        else if (!same_regs && !same_writes) diff["verdict"] = "input_dependent_behavior";
        else if (!same_regs && same_writes)  diff["verdict"] = "register_transform_only";
        else                                 diff["verdict"] = "memory_behavior_varies";
    }

    json out;
    out["address"]      = sa_format_address(*addr);
    out["trace_count"]  = traces.size();
    out["kernel_mode"]  = kernel_mode;
    out["traces"]       = std::move(traces);
    if (!diff.empty()) out["differential_analysis"] = std::move(diff);

    diag::log_tagged_fmt("emul_tools", "emulate_multi_trace ok trace_count=%zu",
        out["trace_count"].get<std::size_t>());
    return tool_result_t::ok(OBFSTR("Multi-trace: ") + std::to_string(out["trace_count"].get<std::size_t>()) +
                             OBFSTR(" traces at ") + sa_format_address(*addr) +
                             (kernel_mode ? OBFSTR(" [kernel]") : OBFSTR(" [user]")), out);
}


#else

tool_result_t disassemble_zydis(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t driver_snapshot_and_emulate(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t trace_execution_unicorn(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t analyze_vm_handler(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t emulate_multi_trace(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

#endif

void register_emulation_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged_fmt("emul_tools", "register_emulation_tools registering 5 tools");
        register_compat(srv, {
        OBFSTR("disassemble_zydis"), OBFSTR("emulation"),
        OBFSTR("Disassemble raw bytes from LIVE MEMORY using the Zydis engine via the kernel driver. "
               "Reads memory directly - completely independent of the IDA database. "
               "Works on both user-mode process addresses (attach with sessions_manage action=attach_pid) and "
               "kernel-mode addresses through the driver bridge. "
               "Produces rich instruction metadata: branch/call/ret/nop/privileged "
               "classification, precise mnemonic parsing, and accurate instruction lengths. "
               "Use follow_jumps=true to automatically follow unconditional JMP trampolines (up to 16 hops) "
               "to reach the real code - essential for VM-protected binaries where every function "
               "is a jmp-trampoline into a packed section."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to disassemble (user-mode or kernel-mode)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Number of bytes to read and disassemble (default 256, max 65536)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Maximum instructions to decode (default 100, max 10000)"), false},
         {OBFSTR("follow_jumps"), OBFSTR("boolean"), OBFSTR("Follow unconditional JMP trampolines to reach actual code (default false)"), false}},
        disassemble_zydis, true});

    register_compat(srv, {
        OBFSTR("driver_snapshot_and_emulate"), OBFSTR("emulation"),
        OBFSTR("Capture a live process snapshot via the kernel driver and emulate code offline in Unicorn. "
               "The driver silently reads physical memory pages and thread context without triggering "
               "any anti-debug or anti-tamper mechanisms. The captured state is loaded into Unicorn "
               "for offline x86-64 emulation with full instruction tracing. "
               "Produces: register deltas (before/after), memory writes, effective vs junk instruction "
               "classification, and an execution trace. "
               "Use this to analyze VM handlers, unpacking stubs, and obfuscated code in protected "
               "processes where the debugger would be detected. "
               "Requires an attached process through sessions_manage action=attach_pid."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Emulation start address (entry point of VM handler or code to trace)"), true},
         {OBFSTR("tid"), OBFSTR("number"), OBFSTR("Target thread ID (auto-selects first thread if omitted)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Maximum instructions to emulate (default 50000)"), false},
         {OBFSTR("max_trace_entries"), OBFSTR("number"), OBFSTR("Maximum trace log entries (default 10000)"), false},
         {OBFSTR("stop_address"), OBFSTR("string"), OBFSTR("Address to stop emulation at (optional)"), false},
         {OBFSTR("breakpoints"), OBFSTR("array"), OBFSTR("Array of addresses to break at during emulation"), false,
          {}, {{"type", "string"}}},
         {OBFSTR("snapshot_base"), OBFSTR("string"), OBFSTR("Override snapshot region base address (auto if omitted)"), false},
         {OBFSTR("snapshot_size"), OBFSTR("number"), OBFSTR("Override snapshot region size in bytes (auto if omitted)"), false},
         {OBFSTR("record_mem_reads"), OBFSTR("boolean"), OBFSTR("Log all memory reads (default true)"), false},
         {OBFSTR("record_mem_writes"), OBFSTR("boolean"), OBFSTR("Log all memory writes (default true)"), false},
         {OBFSTR("analyze_effective"), OBFSTR("boolean"), OBFSTR("Classify junk vs effective instructions (default true)"), false},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Emulation timeout in microseconds (default 10000000 = 10s)"), false}},
        driver_snapshot_and_emulate, false});

    register_compat(srv, {
        OBFSTR("trace_execution_unicorn"), OBFSTR("emulation"),
        OBFSTR("Read raw code bytes from LIVE MEMORY via the kernel driver and emulate them "
               "offline in a Unicorn x86-64 engine with a synthetic stack. Completely independent of "
               "the IDA database. Works on both user-mode addresses attached through sessions_manage action=attach_pid and "
               "kernel-mode addresses through the driver bridge. "
               "Produces register deltas, memory writes, effective vs junk instruction classification, "
               "and an execution trace. "
               "Use additional_regions to map extra memory sections into the emulator (e.g. .be0 packed "
               "section alongside .text for cross-section jumps). "
               "You can set initial register values (rax, rbx, ...) to simulate specific VM opcodes."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to emulate from (user-mode or kernel-mode)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes of code to read (default 4096, max 1MB)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Maximum instructions to emulate (default 50000)"), false},
         {OBFSTR("max_trace_entries"), OBFSTR("number"), OBFSTR("Maximum trace log entries (default 10000)"), false},
         {OBFSTR("stop_address"), OBFSTR("string"), OBFSTR("Address to stop emulation at (optional)"), false},
         {OBFSTR("additional_regions"), OBFSTR("array"), OBFSTR("Extra memory regions to map: [{address,size},...] for cross-section code"), false,
          {}, {{"type", "object"}}},
         {OBFSTR("rax"), OBFSTR("string"), OBFSTR("Initial RAX value (hex)"), false},
         {OBFSTR("rbx"), OBFSTR("string"), OBFSTR("Initial RBX value (hex)"), false},
         {OBFSTR("rcx"), OBFSTR("string"), OBFSTR("Initial RCX value (hex)"), false},
         {OBFSTR("rdx"), OBFSTR("string"), OBFSTR("Initial RDX value (hex)"), false},
         {OBFSTR("rsi"), OBFSTR("string"), OBFSTR("Initial RSI value (hex)"), false},
         {OBFSTR("rdi"), OBFSTR("string"), OBFSTR("Initial RDI value (hex)"), false},
         {OBFSTR("record_mem_reads"), OBFSTR("boolean"), OBFSTR("Log memory reads (default true)"), false},
         {OBFSTR("record_mem_writes"), OBFSTR("boolean"), OBFSTR("Log memory writes (default true)"), false},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Emulation timeout in microseconds (default 10s)"), false}},
        trace_execution_unicorn, true});

    register_compat(srv, {
        OBFSTR("analyze_vm_handler"), OBFSTR("emulation"),
        OBFSTR("Combined disassembly + emulation analysis of a VM handler or obfuscated code block "
               "via the kernel driver. Works on user-mode addresses attached through sessions_manage action=attach_pid and "
               "kernel-mode addresses through the driver bridge. "
               "Step 1: Read raw bytes from live memory and disassemble with Zydis. "
               "Step 2: Emulate the same bytes offline in Unicorn to separate junk from effective operations. "
               "Produces: static instruction counts (nop/branch/call/privileged ratios), "
               "emulation results (register deltas, memory writes, effective ops), "
               "handler VA/RVA/module attribution, classification, confidence score, confidence features, threshold, "
               "and structured partial evidence when required proof is missing. "
               "Use additional_regions to map extra sections for cross-section jumps."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("VM handler entry point address (user-mode or kernel-mode)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Handler size in bytes to read (default 8192)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Max instructions for emulation (default 100000)"), false},
         {OBFSTR("additional_regions"), OBFSTR("array"), OBFSTR("Extra memory regions to map: [{address,size},...] for cross-section code"), false,
          {}, {{"type", "object"}}},
         {OBFSTR("rax"), OBFSTR("string"), OBFSTR("Initial RAX for emulation (hex)"), false},
         {OBFSTR("rbx"), OBFSTR("string"), OBFSTR("Initial RBX for emulation (hex)"), false},
         {OBFSTR("rcx"), OBFSTR("string"), OBFSTR("Initial RCX for emulation (hex)"), false},
         {OBFSTR("rdx"), OBFSTR("string"), OBFSTR("Initial RDX for emulation (hex)"), false},
         {OBFSTR("rsi"), OBFSTR("string"), OBFSTR("Initial RSI for emulation (hex)"), false},
         {OBFSTR("rdi"), OBFSTR("string"), OBFSTR("Initial RDI for emulation (hex)"), false},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Emulation timeout in microseconds (default 15s)"), false}},
        analyze_vm_handler, true});

    register_compat(srv, {
        OBFSTR("emulate_multi_trace"), OBFSTR("emulation"),
        OBFSTR("Read code from LIVE MEMORY via the kernel driver and run multiple Unicorn emulation "
               "traces with different register inputs for differential analysis. "
               "Works on user-mode addresses attached through sessions_manage action=attach_pid and kernel-mode addresses through the driver bridge. "
               "Compare execution paths, register outputs, and memory writes across traces. "
               "Classifies behavior: constant_operation, register_transform_only, input_dependent_behavior, "
               "memory_behavior_varies. Use additional_regions for cross-section jumps."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Code address to emulate (user-mode or kernel-mode)"), true},
         {OBFSTR("inputs"), OBFSTR("array"), OBFSTR("Array of register state objects, e.g. [{rax:\"0x10\",rbx:\"0x20\"}, {rax:\"0x30\",rbx:\"0x40\"}]"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Code size in bytes to read (default: 4096)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Max instructions per trace (default: 50000)"), false},
         {OBFSTR("additional_regions"), OBFSTR("array"), OBFSTR("Extra memory regions to map: [{address,size},...] for cross-section code"), false,
          {}, {{"type", "object"}}},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Timeout per trace in microseconds (default: 5s)"), false}},
        emulate_multi_trace, true});

}

}
