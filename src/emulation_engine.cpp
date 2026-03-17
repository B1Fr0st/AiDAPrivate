#ifdef __NT__

#include "emulation_engine.hpp"
#include "../driver/comm.h"

#pragma warning(push)
#pragma warning(disable: 4005)
#pragma warning(disable: 4267)
#include <pro.h>
#include <kernwin.hpp>
#pragma warning(pop)

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <cstring>

extern std::unique_ptr<voyager::device_t> device;

namespace emulation {


static ZydisDecoder     g_decoder;
static ZydisFormatter   g_formatter;
static bool             g_zydis_initialized = false;
static std::once_flag   g_zydis_init_flag;

static void ensure_zydis_init()
{
    std::call_once(g_zydis_init_flag, []() {
        ZydisDecoderInit(&g_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisFormatterInit(&g_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        ZydisFormatterSetProperty(&g_formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_FALSE);
        ZydisFormatterSetProperty(&g_formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_FALSE);
        g_zydis_initialized = true;
    });
}

decoded_insn_t disassemble_one(
    const std::uint8_t* data,
    std::size_t         data_size,
    std::uint64_t       runtime_address)
{
    ensure_zydis_init();

    decoded_insn_t result;
    result.address = runtime_address;

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &g_decoder, data, data_size, &instruction, operands)))
    {
        result.length   = 1;
        result.mnemonic = "db";
        result.full_text = "db ??";
        return result;
    }

    result.length   = instruction.length;
    result.category = instruction.meta.category;

    const char* mnemonic_str = ZydisMnemonicGetString(instruction.mnemonic);
    result.mnemonic = mnemonic_str ? mnemonic_str : "???";

    char full_buf[256] = {};
    ZydisFormatterFormatInstruction(&g_formatter, &instruction, operands,
                                    instruction.operand_count_visible,
                                    full_buf, sizeof(full_buf),
                                    runtime_address, ZYAN_NULL);
    result.full_text = full_buf;


    const char* space = std::strchr(full_buf, ' ');
    result.operands_text = space ? (space + 1) : "";


    switch (instruction.meta.category)
    {
    case ZYDIS_CATEGORY_CALL:
        result.is_call = true;
        break;
    case ZYDIS_CATEGORY_RET:
        result.is_ret = true;
        break;
    case ZYDIS_CATEGORY_COND_BR:
    case ZYDIS_CATEGORY_UNCOND_BR:
        result.is_branch = true;
        break;
    case ZYDIS_CATEGORY_NOP:
        result.is_nop = true;
        break;
    default:
        break;
    }

    if (instruction.meta.category == ZYDIS_CATEGORY_SYSTEM ||
        instruction.meta.category == ZYDIS_CATEGORY_INTERRUPT)
        result.is_privileged = true;

    return result;
}

std::vector<decoded_insn_t> disassemble_range(
    const std::uint8_t* data,
    std::size_t         data_size,
    std::uint64_t       runtime_address,
    std::uint32_t       max_instructions)
{
    ensure_zydis_init();

    std::vector<decoded_insn_t> results;
    results.reserve(std::min<std::uint32_t>(max_instructions, 4096u));

    std::size_t offset = 0;
    std::uint32_t count = 0;

    while (offset < data_size && count < max_instructions)
    {
        auto insn = disassemble_one(
            data + offset,
            data_size - offset,
            runtime_address + offset);

        offset += insn.length;
        ++count;
        results.push_back(std::move(insn));
    }

    return results;
}

std::vector<std::uint8_t> driver_read_bytes(
    std::uint64_t  address,
    std::size_t    size)
{
    if (!device || !device->is_connected())
        return {};

    const bool kernel_addr = address >= 0xFFFF800000000000ULL;

    if (!kernel_addr && device->get_process_id() == 0)
        return {};

    if (size == 0 || size > 64ULL * 1024 * 1024)
        return {};

    std::vector<std::uint8_t> buffer(size, 0);
    constexpr std::size_t CHUNK_SIZE = 65536;
    for (std::size_t offset = 0; offset < size; offset += CHUNK_SIZE)
    {
        std::size_t chunk = std::min(CHUNK_SIZE, size - offset);
        if (kernel_addr)
            device->read_kernel_raw(address + offset, buffer.data() + offset, chunk);
        else
            device->read_raw(address + offset, buffer.data() + offset, chunk);
    }
    return buffer;
}

std::vector<decoded_insn_t> driver_disassemble_range(
    std::uint64_t  address,
    std::uint32_t  size,
    std::uint32_t  max_instructions)
{
    auto bytes = driver_read_bytes(address, size);
    if (bytes.empty())
        return {};

    return disassemble_range(bytes.data(), bytes.size(), address, max_instructions);
}


process_snapshot_t driver_snapshot(
    std::uint32_t pid,
    std::uint32_t tid,
    std::uint64_t region_base,
    std::uint64_t region_size)
{
    process_snapshot_t snap;
    snap.pid = pid;
    snap.tid = tid;

    if (!device || !device->is_connected())
    {
        snap.error = "Driver not connected";
        return snap;
    }


    std::uint32_t prev_count = 0;
    bool did_suspend = device->suspend_thread(tid, &prev_count);


    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
    {
        if (did_suspend)
            device->resume_thread(tid);
        snap.error = "Failed to read thread context for TID " + std::to_string(tid);
        return snap;
    }

    snap.rax = ctx.rax; snap.rbx = ctx.rbx; snap.rcx = ctx.rcx; snap.rdx = ctx.rdx;
    snap.rsi = ctx.rsi; snap.rdi = ctx.rdi; snap.rbp = ctx.rbp; snap.rsp = ctx.rsp;
    snap.r8  = ctx.r8;  snap.r9  = ctx.r9;  snap.r10 = ctx.r10; snap.r11 = ctx.r11;
    snap.r12 = ctx.r12; snap.r13 = ctx.r13; snap.r14 = ctx.r14; snap.r15 = ctx.r15;
    snap.rip = ctx.rip;  snap.rflags = ctx.rflags;


    std::vector<voyager::detail::region_entry> regions;
    if (region_base != 0 && region_size != 0)
    {

        regions = device->enumerate_memory_regions(region_base, region_base + region_size, false);
    }
    else
    {

        struct snapshot_range { std::uint64_t base; std::uint64_t size; };
        std::vector<snapshot_range> ranges_to_capture;


        constexpr std::uint64_t RIP_WINDOW = 0x200000;
        std::uint64_t rip_start = (ctx.rip > RIP_WINDOW) ? (ctx.rip - RIP_WINDOW) : 0x10000;
        ranges_to_capture.push_back({rip_start, RIP_WINDOW * 2});


        constexpr std::uint64_t RSP_WINDOW = 0x100000;
        std::uint64_t rsp_start = (ctx.rsp > RSP_WINDOW) ? (ctx.rsp - RSP_WINDOW) : 0x10000;
        ranges_to_capture.push_back({rsp_start, RSP_WINDOW * 2});


        auto all_regions = device->enumerate_memory_regions(0x10000, 0x7FFFFFFFFFFF, false);
        for (const auto& r : all_regions)
        {

            if (r.state == 0x1000 && r.type == 0x1000000)
            {
                regions.push_back(r);
                continue;
            }


            if (r.state == 0x1000)
            {
                for (const auto& range : ranges_to_capture)
                {
                    std::uint64_t range_end = range.base + range.size;
                    std::uint64_t reg_end = r.base + r.size;
                    if (r.base < range_end && reg_end > range.base)
                    {
                        regions.push_back(r);
                        break;
                    }
                }
            }
        }
    }


    constexpr std::uint64_t MAX_SNAPSHOT_BYTES = 256ULL * 1024 * 1024;
    std::uint64_t total_bytes = 0;

    for (const auto& r : regions)
    {
        if (total_bytes + r.size > MAX_SNAPSHOT_BYTES)
            break;

        memory_snapshot_region_t region;
        region.base    = r.base;
        region.size    = r.size;
        region.protect = r.protect;
        region.data.resize(static_cast<std::size_t>(r.size), 0);


        constexpr std::size_t CHUNK_SIZE = 65536;
        for (std::uint64_t offset = 0; offset < r.size; offset += CHUNK_SIZE)
        {
            std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uint64_t>(CHUNK_SIZE, r.size - offset));
            device->read_raw(r.base + offset, region.data.data() + offset, chunk);
        }

        total_bytes += r.size;
        snap.regions.push_back(std::move(region));
    }

    snap.total_snapshot_bytes = total_bytes;


    if (did_suspend)
        device->resume_thread(tid);

    snap.success = true;
    return snap;
}


struct uc_trace_ctx_t {
    uc_engine*                  uc          = nullptr;
    const emulation_config_t*   config      = nullptr;
    std::vector<trace_entry_t>* trace       = nullptr;
    std::vector<mem_write_t>*   mem_writes  = nullptr;
    std::vector<mem_read_t>*    mem_reads   = nullptr;
    std::uint32_t               insn_count  = 0;
    std::uint64_t               current_rip = 0;
    bool                        hit_ret     = false;
    bool                        hit_bp      = false;
    const std::uint8_t*         mapped_code = nullptr;
    std::size_t                 mapped_code_size = 0;
    std::uint64_t               mapped_code_base = 0;
};

static void uc_read_regs(uc_engine* uc, trace_entry_t& entry)
{
    uc_reg_read(uc, UC_X86_REG_RAX, &entry.rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &entry.rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &entry.rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &entry.rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &entry.rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &entry.rdi);
    uc_reg_read(uc, UC_X86_REG_RBP, &entry.rbp);
    uc_reg_read(uc, UC_X86_REG_RSP, &entry.rsp);
    uc_reg_read(uc, UC_X86_REG_R8,  &entry.r8);
    uc_reg_read(uc, UC_X86_REG_R9,  &entry.r9);
    uc_reg_read(uc, UC_X86_REG_R10, &entry.r10);
    uc_reg_read(uc, UC_X86_REG_R11, &entry.r11);
    uc_reg_read(uc, UC_X86_REG_R12, &entry.r12);
    uc_reg_read(uc, UC_X86_REG_R13, &entry.r13);
    uc_reg_read(uc, UC_X86_REG_R14, &entry.r14);
    uc_reg_read(uc, UC_X86_REG_R15, &entry.r15);
    uc_reg_read(uc, UC_X86_REG_RIP, &entry.rip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &entry.rflags);
}

static void hook_code_cb(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    auto* ctx = static_cast<uc_trace_ctx_t*>(user_data);
    ctx->current_rip = address;
    ctx->insn_count++;


    if (ctx->insn_count > ctx->config->max_instructions)
    {
        uc_emu_stop(uc);
        return;
    }


    if (!ctx->config->breakpoint_addresses.empty() &&
        ctx->config->breakpoint_addresses.count(address))
    {
        ctx->hit_bp = true;
        uc_emu_stop(uc);
        return;
    }


    if (ctx->config->stop_address != 0 && address == ctx->config->stop_address)
    {
        uc_emu_stop(uc);
        return;
    }


    if (ctx->trace && ctx->trace->size() < ctx->config->max_trace_entries)
    {
        trace_entry_t entry;
        entry.address   = address;
        entry.insn_size = size;


        if (ctx->mapped_code && address >= ctx->mapped_code_base)
        {
            std::uint64_t off = address - ctx->mapped_code_base;
            if (off + size <= ctx->mapped_code_size)
            {
                auto decoded = disassemble_one(
                    ctx->mapped_code + off,
                    ctx->mapped_code_size - static_cast<std::size_t>(off),
                    address);
                entry.disasm = decoded.full_text;

                if (decoded.is_ret)
                    ctx->hit_ret = true;
            }
        }

        if (ctx->config->record_registers)
            uc_read_regs(uc, entry);

        ctx->trace->push_back(std::move(entry));
    }


    if (ctx->hit_ret)
        uc_emu_stop(uc);
}

static void hook_mem_write_cb(uc_engine* , uc_mem_type ,
                              uint64_t address, int size,
                              int64_t value, void* user_data)
{
    auto* ctx = static_cast<uc_trace_ctx_t*>(user_data);
    if (!ctx->config->record_mem_writes || !ctx->mem_writes)
        return;

    mem_write_t w;
    w.address      = address;
    w.size         = static_cast<std::uint64_t>(size);
    w.insn_address = ctx->current_rip;
    w.data.resize(size);
    std::memcpy(w.data.data(), &value, std::min<int>(size, 8));
    ctx->mem_writes->push_back(std::move(w));
}

static bool hook_mem_invalid_cb(uc_engine* uc, uc_mem_type type,
                                uint64_t address, int size,
                                int64_t , void* )
{

    if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_FETCH_UNMAPPED)
    {
        std::uint64_t aligned = address & ~0xFFFULL;
        std::vector<std::uint8_t> zeros(0x2000, 0);
        uc_mem_map(uc, aligned, 0x2000, UC_PROT_ALL);
        uc_mem_write(uc, aligned, zeros.data(), zeros.size());
        return true;
    }

    if (type == UC_MEM_WRITE_UNMAPPED)
    {
        std::uint64_t aligned = address & ~0xFFFULL;
        uc_mem_map(uc, aligned, 0x2000, UC_PROT_ALL);
        return true;
    }

    (void)size;
    return false;
}

static void hook_mem_read_cb(uc_engine* , uc_mem_type ,
                             uint64_t address, int size,
                             int64_t , void* user_data)
{
    auto* ctx = static_cast<uc_trace_ctx_t*>(user_data);
    if (!ctx->config->record_mem_reads || !ctx->mem_reads)
        return;

    mem_read_t r;
    r.address      = address;
    r.size         = static_cast<std::uint64_t>(size);
    r.insn_address = ctx->current_rip;
    ctx->mem_reads->push_back(std::move(r));
}

emulation_result_t emulate_from_snapshot(
    const process_snapshot_t& snapshot,
    const emulation_config_t& config)
{
    emulation_result_t result;
    result.start_address = config.start_address != 0 ? config.start_address : snapshot.rip;

    if (snapshot.regions.empty())
    {
        result.error = "Snapshot has no memory regions";
        return result;
    }


    uc_engine* uc = nullptr;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK)
    {
        result.error = std::string("Unicorn init failed: ") + uc_strerror(err);
        return result;
    }


    struct uc_guard_t {
        uc_engine* engine;
        ~uc_guard_t() { if (engine) uc_close(engine); }
    } uc_guard{uc};


    struct merged_region_t {
        std::uint64_t base;
        std::uint64_t size;
    };
    std::vector<merged_region_t> to_map;

    for (const auto& region : snapshot.regions)
    {

        std::uint64_t aligned_base = region.base & ~0xFFFULL;
        std::uint64_t aligned_end  = (region.base + region.size + 0xFFF) & ~0xFFFULL;
        std::uint64_t aligned_size = aligned_end - aligned_base;


        bool merged = false;
        for (auto& m : to_map)
        {
            std::uint64_t m_end = m.base + m.size;
            if (aligned_base < m_end && aligned_end > m.base)
            {

                std::uint64_t new_base = std::min(m.base, aligned_base);
                std::uint64_t new_end  = std::max(m_end, aligned_end);
                m.base = new_base;
                m.size = new_end - new_base;
                merged = true;
                break;
            }
        }
        if (!merged)
            to_map.push_back({aligned_base, aligned_size});
    }


    for (const auto& m : to_map)
    {
        err = uc_mem_map(uc, m.base, static_cast<size_t>(m.size), UC_PROT_ALL);
        if (err != UC_ERR_OK)
        {
            result.error = std::string("uc_mem_map failed at 0x") +
                (std::ostringstream() << std::hex << m.base).str() + ": " + uc_strerror(err);
            return result;
        }
    }


    const std::uint8_t* code_at_rip = nullptr;
    std::size_t          code_at_rip_size = 0;
    std::uint64_t        code_at_rip_base = 0;

    for (const auto& region : snapshot.regions)
    {
        if (!region.data.empty())
        {
            uc_mem_write(uc, region.base, region.data.data(), region.data.size());
        }


        std::uint64_t start = result.start_address;
        if (start >= region.base && start < region.base + region.size)
        {
            code_at_rip      = region.data.data();
            code_at_rip_size = region.data.size();
            code_at_rip_base = region.base;
        }
    }


    uc_reg_write(uc, UC_X86_REG_RAX, &snapshot.rax);
    uc_reg_write(uc, UC_X86_REG_RBX, &snapshot.rbx);
    uc_reg_write(uc, UC_X86_REG_RCX, &snapshot.rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &snapshot.rdx);
    uc_reg_write(uc, UC_X86_REG_RSI, &snapshot.rsi);
    uc_reg_write(uc, UC_X86_REG_RDI, &snapshot.rdi);
    uc_reg_write(uc, UC_X86_REG_RBP, &snapshot.rbp);
    uc_reg_write(uc, UC_X86_REG_RSP, &snapshot.rsp);
    uc_reg_write(uc, UC_X86_REG_R8,  &snapshot.r8);
    uc_reg_write(uc, UC_X86_REG_R9,  &snapshot.r9);
    uc_reg_write(uc, UC_X86_REG_R10, &snapshot.r10);
    uc_reg_write(uc, UC_X86_REG_R11, &snapshot.r11);
    uc_reg_write(uc, UC_X86_REG_R12, &snapshot.r12);
    uc_reg_write(uc, UC_X86_REG_R13, &snapshot.r13);
    uc_reg_write(uc, UC_X86_REG_R14, &snapshot.r14);
    uc_reg_write(uc, UC_X86_REG_R15, &snapshot.r15);
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &snapshot.rflags);


    std::uint64_t start_rip = result.start_address;


    uc_trace_ctx_t trace_ctx;
    trace_ctx.uc               = uc;
    trace_ctx.config           = &config;
    trace_ctx.mapped_code      = code_at_rip;
    trace_ctx.mapped_code_size = code_at_rip_size;
    trace_ctx.mapped_code_base = code_at_rip_base;

    std::vector<trace_entry_t> trace_log;
    std::vector<mem_write_t>   write_log;
    std::vector<mem_read_t>    read_log;
    trace_log.reserve(std::min<std::uint32_t>(config.max_trace_entries, 16384u));

    trace_ctx.trace      = &trace_log;
    trace_ctx.mem_writes = &write_log;
    trace_ctx.mem_reads  = &read_log;


    trace_entry_t initial_regs;
    initial_regs.rax = snapshot.rax; initial_regs.rbx = snapshot.rbx;
    initial_regs.rcx = snapshot.rcx; initial_regs.rdx = snapshot.rdx;
    initial_regs.rsi = snapshot.rsi; initial_regs.rdi = snapshot.rdi;
    initial_regs.rbp = snapshot.rbp; initial_regs.rsp = snapshot.rsp;
    initial_regs.r8  = snapshot.r8;  initial_regs.r9  = snapshot.r9;
    initial_regs.r10 = snapshot.r10; initial_regs.r11 = snapshot.r11;
    initial_regs.r12 = snapshot.r12; initial_regs.r13 = snapshot.r13;
    initial_regs.r14 = snapshot.r14; initial_regs.r15 = snapshot.r15;
    initial_regs.rip = snapshot.rip; initial_regs.rflags = snapshot.rflags;


    uc_hook h_code, h_mem_write, h_mem_read, h_mem_invalid;

    uc_hook_add(uc, &h_code, UC_HOOK_CODE,
                reinterpret_cast<void*>(&hook_code_cb), &trace_ctx, 1, 0);

    if (config.record_mem_writes)
    {
        uc_hook_add(uc, &h_mem_write, UC_HOOK_MEM_WRITE,
                    reinterpret_cast<void*>(&hook_mem_write_cb), &trace_ctx, 1, 0);
    }

    if (config.record_mem_reads)
    {
        uc_hook_add(uc, &h_mem_read, UC_HOOK_MEM_READ,
                    reinterpret_cast<void*>(&hook_mem_read_cb), &trace_ctx, 1, 0);
    }


    uc_hook_add(uc, &h_mem_invalid,
                UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                reinterpret_cast<void*>(&hook_mem_invalid_cb), &trace_ctx, 1, 0);


    err = uc_emu_start(uc, start_rip, config.stop_address ? config.stop_address : 0xFFFFFFFFFFFFFFFFULL,
                       config.timeout_us, config.max_instructions);


    std::uint64_t final_rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &final_rip);

    result.end_address        = final_rip;
    result.total_instructions = trace_ctx.insn_count;
    result.trace              = std::move(trace_log);
    result.mem_writes         = std::move(write_log);
    result.mem_reads          = std::move(read_log);


    trace_entry_t final_regs;
    uc_read_regs(uc, final_regs);

    auto add_delta = [&](const char* name, std::uint64_t before, std::uint64_t after) {
        if (before != after)
            result.reg_deltas.push_back({name, before, after});
    };

    add_delta("RAX", initial_regs.rax, final_regs.rax);
    add_delta("RBX", initial_regs.rbx, final_regs.rbx);
    add_delta("RCX", initial_regs.rcx, final_regs.rcx);
    add_delta("RDX", initial_regs.rdx, final_regs.rdx);
    add_delta("RSI", initial_regs.rsi, final_regs.rsi);
    add_delta("RDI", initial_regs.rdi, final_regs.rdi);
    add_delta("RBP", initial_regs.rbp, final_regs.rbp);
    add_delta("RSP", initial_regs.rsp, final_regs.rsp);
    add_delta("R8",  initial_regs.r8,  final_regs.r8);
    add_delta("R9",  initial_regs.r9,  final_regs.r9);
    add_delta("R10", initial_regs.r10, final_regs.r10);
    add_delta("R11", initial_regs.r11, final_regs.r11);
    add_delta("R12", initial_regs.r12, final_regs.r12);
    add_delta("R13", initial_regs.r13, final_regs.r13);
    add_delta("R14", initial_regs.r14, final_regs.r14);
    add_delta("R15", initial_regs.r15, final_regs.r15);
    add_delta("RFLAGS", initial_regs.rflags, final_regs.rflags);


    if (config.analyze_effective_ops)
    {
        auto analysis = analyze_vm_trace(result);
        result.effective_ops          = std::move(analysis.effective_ops);
        result.junk_instruction_count = analysis.junk_instructions;
    }

    if (err != UC_ERR_OK && !trace_ctx.hit_ret && !trace_ctx.hit_bp &&
        trace_ctx.insn_count < config.max_instructions)
    {
        result.error = std::string("Emulation stopped: ") + uc_strerror(err);
    }

    result.success = true;
    return result;
}

emulation_result_t driver_snapshot_and_emulate(
    std::uint32_t pid,
    std::uint32_t tid,
    const emulation_config_t& config,
    std::uint64_t snapshot_base,
    std::uint64_t snapshot_size)
{
    auto snapshot = driver_snapshot(pid, tid, snapshot_base, snapshot_size);
    if (!snapshot.success)
    {
        emulation_result_t fail;
        fail.error = "Snapshot failed: " + snapshot.error;
        return fail;
    }

    return emulate_from_snapshot(snapshot, config);
}


vm_analysis_result_t analyze_vm_trace(const emulation_result_t& result)
{
    vm_analysis_result_t analysis;
    analysis.total_instructions = result.total_instructions;

    if (result.trace.empty())
    {
        analysis.summary = "Empty trace";
        return analysis;
    }


    std::unordered_set<std::string> globally_changed_regs;
    for (const auto& d : result.reg_deltas)
        globally_changed_regs.insert(d.name);


    std::unordered_set<std::uint64_t> net_write_addresses;
    for (const auto& w : result.mem_writes)
        net_write_addresses.insert(w.address);


    ensure_zydis_init();

    std::uint32_t junk_count = 0;
    std::uint32_t effective_count = 0;


    auto is_junk_pattern = [](const std::string& disasm) -> bool {
        if (disasm.empty()) return false;


        if (disasm.find("nop") == 0) return true;


        if (disasm == "xchg eax, eax") return true;


        if (disasm.find("lea") == 0 && disasm.find("+0x0]") != std::string::npos)
            return true;


        if (disasm.find("mov") == 0)
        {
            auto comma = disasm.find(',');
            if (comma != std::string::npos)
            {
                std::string dest = disasm.substr(4, comma - 4);
                std::string src  = disasm.substr(comma + 2);

                while (!dest.empty() && dest.back() == ' ') dest.pop_back();
                while (!src.empty() && src.front() == ' ') src.erase(src.begin());
                if (dest == src) return true;
            }
        }

        return false;
    };

    for (const auto& entry : result.trace)
    {
        if (is_junk_pattern(entry.disasm))
        {
            ++junk_count;
        }
        else
        {
            ++effective_count;


            if (analysis.effective_ops.size() < 256)
            {
                std::ostringstream ss;
                ss << "0x" << std::hex << entry.address << ": " << entry.disasm;
                analysis.effective_ops.push_back(ss.str());
            }
        }
    }

    analysis.junk_instructions      = junk_count;
    analysis.effective_instructions = effective_count;
    analysis.net_reg_changes        = result.reg_deltas;
    analysis.net_mem_writes         = result.mem_writes;


    std::ostringstream summary;
    summary << "Traced " << analysis.total_instructions << " instructions: "
            << analysis.effective_instructions << " effective, "
            << analysis.junk_instructions << " junk ("
            << (analysis.total_instructions > 0
                ? static_cast<int>(100.0 * analysis.junk_instructions / analysis.total_instructions)
                : 0)
            << "% noise). ";

    if (!result.reg_deltas.empty())
    {
        summary << "Net register changes: ";
        for (std::size_t i = 0; i < result.reg_deltas.size(); ++i)
        {
            if (i > 0) summary << ", ";
            summary << result.reg_deltas[i].name
                    << " (0x" << std::hex << result.reg_deltas[i].before
                    << " -> 0x" << result.reg_deltas[i].after << ")";
        }
        summary << ". ";
    }

    if (!result.mem_writes.empty())
    {
        summary << std::dec << result.mem_writes.size() << " memory write(s) to "
                << net_write_addresses.size() << " unique address(es).";
    }

    analysis.summary = summary.str();
    return analysis;
}

}

#endif
