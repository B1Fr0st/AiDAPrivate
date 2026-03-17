#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <functional>

#ifdef __NT__

namespace emulation {


struct decoded_insn_t {
    std::uint64_t address     = 0;
    std::uint32_t length      = 0;
    std::string   mnemonic;
    std::string   operands_text;
    std::string   full_text;
    std::uint16_t category    = 0;
    bool          is_branch   = false;
    bool          is_call     = false;
    bool          is_ret      = false;
    bool          is_nop      = false;
    bool          is_privileged = false;
};


struct trace_entry_t {
    std::uint64_t address     = 0;
    std::uint32_t insn_size   = 0;
    std::string   disasm;


    std::uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    std::uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
    std::uint64_t r8  = 0, r9  = 0, r10 = 0, r11 = 0;
    std::uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    std::uint64_t rip = 0, rflags = 0;
};


struct mem_write_t {
    std::uint64_t address = 0;
    std::uint64_t size    = 0;
    std::vector<std::uint8_t> data;
    std::uint64_t insn_address = 0;
};


struct mem_read_t {
    std::uint64_t address = 0;
    std::uint64_t size    = 0;
    std::uint64_t insn_address = 0;
};


struct reg_delta_t {
    std::string   name;
    std::uint64_t before = 0;
    std::uint64_t after  = 0;
};


struct emulation_result_t {
    bool          success = false;
    std::string   error;

    std::uint64_t start_address = 0;
    std::uint64_t end_address   = 0;
    std::uint32_t total_instructions = 0;

    std::vector<trace_entry_t> trace;
    std::vector<mem_write_t>   mem_writes;
    std::vector<mem_read_t>    mem_reads;
    std::vector<reg_delta_t>   reg_deltas;


    std::vector<std::string>   effective_ops;
    std::uint32_t              junk_instruction_count = 0;
};


struct memory_snapshot_region_t {
    std::uint64_t             base = 0;
    std::uint64_t             size = 0;
    std::uint32_t             protect = 0;
    std::vector<std::uint8_t> data;
};


struct process_snapshot_t {
    bool success = false;
    std::string error;

    std::uint32_t pid = 0;
    std::uint32_t tid = 0;


    std::uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    std::uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
    std::uint64_t r8  = 0, r9  = 0, r10 = 0, r11 = 0;
    std::uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    std::uint64_t rip = 0, rflags = 0;

    std::vector<memory_snapshot_region_t> regions;
    std::uint64_t total_snapshot_bytes = 0;
};


struct emulation_config_t {
    std::uint64_t start_address    = 0;
    std::uint64_t stop_address     = 0;
    std::uint32_t max_instructions = 50000;
    std::uint32_t max_trace_entries = 10000;
    bool          record_mem_reads  = true;
    bool          record_mem_writes = true;
    bool          record_registers  = true;
    bool          analyze_effective_ops = true;
    std::uint64_t timeout_us       = 10000000;
    std::set<std::uint64_t> breakpoint_addresses;
};


decoded_insn_t disassemble_one(
    const std::uint8_t* data,
    std::size_t         data_size,
    std::uint64_t       runtime_address);


std::vector<decoded_insn_t> disassemble_range(
    const std::uint8_t* data,
    std::size_t         data_size,
    std::uint64_t       runtime_address,
    std::uint32_t       max_instructions = 1000);


std::vector<std::uint8_t> driver_read_bytes(
    std::uint64_t       address,
    std::size_t         size);


std::vector<decoded_insn_t> driver_disassemble_range(
    std::uint64_t       address,
    std::uint32_t       size,
    std::uint32_t       max_instructions = 1000);


process_snapshot_t driver_snapshot(
    std::uint32_t pid,
    std::uint32_t tid,
    std::uint64_t region_base = 0,
    std::uint64_t region_size = 0);


emulation_result_t emulate_from_snapshot(
    const process_snapshot_t& snapshot,
    const emulation_config_t& config);


emulation_result_t driver_snapshot_and_emulate(
    std::uint32_t pid,
    std::uint32_t tid,
    const emulation_config_t& config,
    std::uint64_t snapshot_base = 0,
    std::uint64_t snapshot_size = 0);


struct vm_analysis_result_t {
    std::uint32_t total_instructions = 0;
    std::uint32_t junk_instructions  = 0;
    std::uint32_t effective_instructions = 0;
    std::vector<std::string>   effective_ops;
    std::vector<reg_delta_t>   net_reg_changes;
    std::vector<mem_write_t>   net_mem_writes;
    std::string                summary;
};

vm_analysis_result_t analyze_vm_trace(const emulation_result_t& result);

}

#endif
