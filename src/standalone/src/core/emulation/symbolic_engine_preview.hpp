#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace symbolic_engine {

struct traced_instruction_t {
	uint64_t address = 0;
	uint32_t size = 0;
	std::string disasm;
	std::string symbolic_state;
	bool is_tainted = false;
	bool is_junk = false;
	bool is_opaque_predicate = false;
	bool is_branch = false;
	bool branch_taken = false;
	uint64_t branch_target = 0;
	std::vector<std::string> read_regs;
	std::vector<std::string> written_regs;
};

struct opaque_predicate_t {
	uint64_t address = 0;
	std::string disasm;
	bool always_taken = false;
	std::string condition_ast;
	std::string simplified_ast;
};

struct constant_fold_t {
	uint64_t address = 0;
	std::string register_name;
	uint64_t concrete_value = 0;
	std::string original_ast;
};

struct symbolic_result_t {
	bool success = false;
	std::string error;
	std::vector<traced_instruction_t> trace;
	std::vector<opaque_predicate_t> opaque_predicates;
	std::vector<constant_fold_t> constants_resolved;
	uint32_t total_instructions = 0;
	uint32_t tainted_count = 0;
	uint32_t junk_count = 0;
	uint32_t opaque_count = 0;
	uint32_t constants_count = 0;
};

struct slice_result_t {
	bool success = false;
	std::string error;
	std::vector<traced_instruction_t> effective_instructions;
	uint32_t total_instructions = 0;
	uint32_t effective_count = 0;
	uint32_t removed_count = 0;
};

struct solve_result_t {
	bool success = false;
	std::string error;
	bool satisfiable = false;
	std::unordered_map<std::string, uint64_t> variable_values;
	uint32_t solving_time_ms = 0;
};

struct taint_result_t {
	bool success = false;
	std::string error;
	std::vector<traced_instruction_t> tainted_instructions;
	uint32_t total_processed = 0;
	uint32_t tainted_count = 0;
	std::unordered_set<std::string> tainted_registers;
	std::vector<uint64_t> tainted_memory_addresses;
};

inline std::vector<traced_instruction_t> preview_trace(uint64_t base)
{
	if (base == 0) base = 0x140001000;
	return {
		{base, 3, "mov rax, qword ptr [rcx]", "rax = SymVar_0", true, false, false, false, false, 0, {"rcx"}, {"rax"}},
		{base + 3, 4, "xor edx, edx", "rdx = 0x0", false, false, false, false, false, 0, {}, {"rdx"}},
		{base + 7, 4, "test rax, rax", "ZF = (SymVar_0 == 0)", true, false, true, false, false, 0, {"rax"}, {"rflags"}},
		{base + 11, 2, "je 0x140001021", "branch (SymVar_0 == 0)", true, false, true, true, false, base + 0x21, {"rflags"}, {}},
		{base + 13, 4, "add rax, 0x20", "rax = (SymVar_0 + 0x20)", true, false, false, false, false, 0, {"rax"}, {"rax"}},
		{base + 17, 3, "mov qword ptr [rsp+0x30], rax", "mem_0 = (SymVar_0 + 0x20)", true, false, false, false, false, 0, {"rsp", "rax"}, {}},
		{base + 20, 1, "ret", "return", false, false, false, false, false, 0, {"rsp"}, {"rip"}}
	};
}

inline symbolic_result_t execute_symbolic(uint64_t start_addr, uint64_t, uint32_t,
	const std::vector<std::string>&, const std::vector<std::pair<uint64_t, uint32_t>>&)
{
	symbolic_result_t result;
	result.success = true;
	result.trace = preview_trace(start_addr);
	result.opaque_predicates.push_back({result.trace[2].address, result.trace[2].disasm, false,
		"(= ((_ extract 63 0) SymVar_0) #x0000000000000000)", "SymVar_0 == 0"});
	result.constants_resolved.push_back({result.trace[1].address, "rdx", 0, "(bvxor rdx rdx)"});
	result.total_instructions = static_cast<uint32_t>(result.trace.size());
	result.tainted_count = 5;
	result.opaque_count = 1;
	result.constants_count = 1;
	return result;
}

inline slice_result_t slice_to_register(uint64_t start_addr, uint64_t, uint32_t,
	const std::string&)
{
	slice_result_t result;
	result.success = true;
	auto trace = preview_trace(start_addr);
	result.total_instructions = static_cast<uint32_t>(trace.size());
	result.effective_instructions = {trace[0], trace[2], trace[4], trace[5]};
	result.effective_count = static_cast<uint32_t>(result.effective_instructions.size());
	result.removed_count = result.total_instructions - result.effective_count;
	return result;
}

inline solve_result_t solve_for_path(uint64_t, uint64_t, uint32_t,
	const std::vector<std::string>& symbolic_regs)
{
	solve_result_t result;
	result.success = true;
	result.satisfiable = true;
	result.solving_time_ms = 7;
	if (symbolic_regs.empty()) result.variable_values.emplace("input", 0x41414141);
	for (std::size_t i = 0; i < symbolic_regs.size(); ++i)
		result.variable_values.emplace(symbolic_regs[i], 0x41414141 + i * 0x101);
	return result;
}

inline taint_result_t taint_trace(uint64_t start_addr, uint64_t, uint32_t,
	const std::vector<std::string>& taint_regs,
	const std::vector<std::pair<uint64_t, uint32_t>>& taint_mem_ranges)
{
	taint_result_t result;
	result.success = true;
	result.tainted_instructions = preview_trace(start_addr);
	result.total_processed = 11;
	result.tainted_count = static_cast<uint32_t>(result.tainted_instructions.size());
	for (const auto& reg : taint_regs) result.tainted_registers.insert(reg);
	result.tainted_registers.insert("rax");
	result.tainted_registers.insert("rflags");
	for (const auto& range : taint_mem_ranges) result.tainted_memory_addresses.push_back(range.first);
	if (result.tainted_memory_addresses.empty()) result.tainted_memory_addresses.push_back(0x7FF6A0123000);
	return result;
}

inline bool is_opaque_predicate(uint64_t branch_addr, uint32_t)
{
	return (branch_addr & 0xFu) == 3u || (branch_addr & 0xFu) == 7u;
}

inline std::string get_register_expression(uint64_t, uint32_t,
	const std::string& target_reg, const std::vector<std::string>&)
{
	return "(bvadd " + target_reg + " #x0000000000000020)";
}

struct state_t {
	std::mutex mutex;
	std::atomic<bool> processing{false};
	symbolic_result_t last_result = execute_symbolic(0x140001000, 0, 10000, {}, {});
	slice_result_t last_slice = slice_to_register(0x140001000, 0, 10000, "rax");
	solve_result_t last_solve = solve_for_path(0x140001000, 0x140001021, 10000, {"rax", "rcx"});
	taint_result_t last_taint = taint_trace(0x140001000, 0, 10000, {"rcx"}, {{0x7FF6A0123000, 64}});
	std::atomic<uint32_t> progress_current{7};
	std::atomic<uint32_t> progress_total{7};
};

inline state_t g_state;

}
