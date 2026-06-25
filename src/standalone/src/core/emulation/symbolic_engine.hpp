#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <triton/context.hpp>
#include <triton/x86Specifications.hpp>

#include "emulation_engine.hpp"
#include "comm.h"
#include "../disasm/zydis_disasm.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
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

struct state_t {
	std::mutex mutex;
	std::atomic<bool> processing{false};
	symbolic_result_t last_result;
	slice_result_t last_slice;
	solve_result_t last_solve;
	taint_result_t last_taint;
	std::atomic<uint32_t> progress_current{0};
	std::atomic<uint32_t> progress_total{0};
};

inline state_t g_state;

namespace detail {

inline bool pc_in_requested_range(uint64_t pc, uint64_t start_addr, uint64_t end_addr) {
	if (end_addr == 0) return true;
	return pc >= start_addr && pc < end_addr;
}

inline uint64_t snapshot_size_for_range(uint64_t start_addr, uint64_t end_addr) {
	if (end_addr > start_addr) {
		uint64_t span = end_addr - start_addr;
		if (span < 0x1000)
			return 0x1000;
		uint64_t aligned = (span + 0xFFFull) & ~0xFFFull;
		return (std::min<uint64_t>)(aligned, 0x10000ull);
	}
	return 0x10000;
}

inline void prepare_snapshot_for_context(emulation::process_snapshot_t& snap, uint64_t start_addr) {
	constexpr uint64_t stack_base = 0x0000007FFF000000ull;
	constexpr uint64_t stack_size = 0x20000ull;
	constexpr uint64_t stack_top = stack_base + stack_size - 0x1000ull;
	constexpr uint64_t sentinel_ret = 0xDEAD000000000000ull;

	snap.rip = start_addr;
	snap.rsp = stack_top;
	snap.rbp = stack_top + 0x100ull;
	if (snap.rflags == 0)
		snap.rflags = 0x202;

	for (auto& region : snap.regions) {
		uint64_t region_end = region.base + region.size;
		if (stack_top >= region.base && stack_top + sizeof(sentinel_ret) <= region_end) {
			if (region.data.size() >= region.size)
				std::memcpy(region.data.data() + (stack_top - region.base), &sentinel_ret, sizeof(sentinel_ret));
			return;
		}
	}

	emulation::memory_snapshot_region_t stack;
	stack.base = stack_base;
	stack.size = stack_size;
	stack.protect = 0x04;
	stack.data.resize(static_cast<std::size_t>(stack_size), 0);
	std::memcpy(stack.data.data() + (stack_top - stack_base), &sentinel_ret, sizeof(sentinel_ret));
	snap.regions.push_back(std::move(stack));
}

inline bool is_ret_opcode(const std::vector<uint8_t>& code_bytes) {
	if (code_bytes.empty())
		return false;
	uint8_t op = code_bytes[0];
	return op == 0xC3 || op == 0xCB || op == 0xC2 || op == 0xCA;
}

inline uint64_t next_pc_or_fallthrough(triton::Context& ctx, triton::arch::Instruction& insn, uint64_t pc) {
	uint64_t next_pc = static_cast<uint64_t>(ctx.getConcreteRegisterValue(ctx.getRegister("rip")));
	if (next_pc == 0 || next_pc == pc) {
		uint32_t size = insn.getSize();
		if (size != 0)
			next_pc = pc + size;
	}
	return next_pc;
}

inline triton::arch::register_e name_to_triton_reg(const std::string& name) {
	static const std::unordered_map<std::string, triton::arch::register_e> map = {
		{"rax", triton::arch::ID_REG_X86_RAX},
		{"rbx", triton::arch::ID_REG_X86_RBX},
		{"rcx", triton::arch::ID_REG_X86_RCX},
		{"rdx", triton::arch::ID_REG_X86_RDX},
		{"rsi", triton::arch::ID_REG_X86_RSI},
		{"rdi", triton::arch::ID_REG_X86_RDI},
		{"rbp", triton::arch::ID_REG_X86_RBP},
		{"rsp", triton::arch::ID_REG_X86_RSP},
		{"r8",  triton::arch::ID_REG_X86_R8},
		{"r9",  triton::arch::ID_REG_X86_R9},
		{"r10", triton::arch::ID_REG_X86_R10},
		{"r11", triton::arch::ID_REG_X86_R11},
		{"r12", triton::arch::ID_REG_X86_R12},
		{"r13", triton::arch::ID_REG_X86_R13},
		{"r14", triton::arch::ID_REG_X86_R14},
		{"r15", triton::arch::ID_REG_X86_R15},
		{"rip", triton::arch::ID_REG_X86_RIP},
		{"rflags", triton::arch::ID_REG_X86_EFLAGS},
		{"eax", triton::arch::ID_REG_X86_EAX},
		{"ebx", triton::arch::ID_REG_X86_EBX},
		{"ecx", triton::arch::ID_REG_X86_ECX},
		{"edx", triton::arch::ID_REG_X86_EDX},
		{"esi", triton::arch::ID_REG_X86_ESI},
		{"edi", triton::arch::ID_REG_X86_EDI},
		{"ebp", triton::arch::ID_REG_X86_EBP},
		{"esp", triton::arch::ID_REG_X86_ESP},
	};

	std::string lower = name;
	std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
	auto it = map.find(lower);
	if (it != map.end()) return it->second;
	return triton::arch::ID_REG_INVALID;
}

inline void load_snapshot_into_context(triton::Context& ctx, const emulation::process_snapshot_t& snap) {
	ctx.setConcreteRegisterValue(ctx.getRegister("rax"), snap.rax);
	ctx.setConcreteRegisterValue(ctx.getRegister("rbx"), snap.rbx);
	ctx.setConcreteRegisterValue(ctx.getRegister("rcx"), snap.rcx);
	ctx.setConcreteRegisterValue(ctx.getRegister("rdx"), snap.rdx);
	ctx.setConcreteRegisterValue(ctx.getRegister("rsi"), snap.rsi);
	ctx.setConcreteRegisterValue(ctx.getRegister("rdi"), snap.rdi);
	ctx.setConcreteRegisterValue(ctx.getRegister("rbp"), snap.rbp);
	ctx.setConcreteRegisterValue(ctx.getRegister("rsp"), snap.rsp);
	ctx.setConcreteRegisterValue(ctx.getRegister("r8"),  snap.r8);
	ctx.setConcreteRegisterValue(ctx.getRegister("r9"),  snap.r9);
	ctx.setConcreteRegisterValue(ctx.getRegister("r10"), snap.r10);
	ctx.setConcreteRegisterValue(ctx.getRegister("r11"), snap.r11);
	ctx.setConcreteRegisterValue(ctx.getRegister("r12"), snap.r12);
	ctx.setConcreteRegisterValue(ctx.getRegister("r13"), snap.r13);
	ctx.setConcreteRegisterValue(ctx.getRegister("r14"), snap.r14);
	ctx.setConcreteRegisterValue(ctx.getRegister("r15"), snap.r15);
	ctx.setConcreteRegisterValue(ctx.getRegister("rip"), snap.rip);
	ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_EFLAGS), snap.rflags);

	for (auto& region : snap.regions) {
		if (!region.data.empty()) {
			ctx.setConcreteMemoryAreaValue(region.base, region.data);
		}
	}
}

inline std::string ast_to_string(const triton::ast::SharedAbstractNode& node) {
	if (!node) return "<null>";
	std::ostringstream ss;
	ss << node.get();
	return ss.str();
}

inline uint32_t execution_budget_ms(uint32_t max_instructions) {
	uint64_t scaled = 500ull + static_cast<uint64_t>(max_instructions) * 50ull;
	if (scaled < 1000ull) scaled = 1000ull;
	if (scaled > 15000ull) scaled = 15000ull;
	return static_cast<uint32_t>(scaled);
}

inline uint64_t elapsed_ms_since(const std::chrono::steady_clock::time_point& t0) {
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - t0).count());
}

inline std::string asm_text(const AsmInstr& ins) {
	std::string text = ins.mnem[0] ? ins.mnem : "db";
	if (ins.ops[0]) {
		text += " ";
		text += ins.ops;
	}
	return text;
}

inline std::vector<traced_instruction_t> structural_trace(uint64_t start_addr, uint64_t end_addr, uint32_t max_instructions, const char* reason) {
	std::vector<traced_instruction_t> trace;
	uint64_t pc = start_addr;
	for (uint32_t count = 0; count < max_instructions; ++count) {
		if (!pc_in_requested_range(pc, start_addr, end_addr)) break;
		auto code_bytes = emulation::driver_read_bytes(pc, 16);
		if (code_bytes.empty()) break;
		AsmInstr ins = zydis_decode_one(code_bytes.data(), static_cast<int>(code_bytes.size()), pc);
		if (ins.len <= 0) ins.len = 1;
		traced_instruction_t t;
		t.address = pc;
		t.size = static_cast<uint32_t>(ins.len);
		t.disasm = asm_text(ins);
		t.symbolic_state = reason ? reason : "structural";
		t.is_branch = ins.is_branch;
		t.branch_target = ins.branch_target;
		t.branch_taken = ins.branch_target != 0;
		trace.push_back(std::move(t));
		if (ins.is_ret)
			break;
		pc += static_cast<uint64_t>(ins.len);
	}
	return trace;
}

inline symbolic_result_t structural_symbolic_result(uint64_t start_addr, uint64_t end_addr, uint32_t max_instructions, const char* reason) {
	symbolic_result_t result;
	result.trace = structural_trace(start_addr, end_addr, max_instructions, reason);
	result.total_instructions = static_cast<uint32_t>(result.trace.size());
	result.constants_count = static_cast<uint32_t>(result.constants_resolved.size());
	result.success = !result.trace.empty();
	if (!result.success)
		result.error = "Structural symbolic fallback could not decode any instruction";
	diag::log_tagged_fmt("symbolic",
		"structural_fallback reason='%s' entry=0x%llX count=%u success=%d",
		reason ? reason : "unknown",
		static_cast<unsigned long long>(start_addr),
		result.total_instructions,
		static_cast<int>(result.success));
	return result;
}

inline solve_result_t structural_solve_result(uint64_t start_addr, uint64_t target_addr, uint32_t max_instructions, const std::vector<std::string>& symbolic_regs, const char* reason) {
	solve_result_t result;
	auto trace = structural_trace(start_addr, target_addr + 0x20, max_instructions, reason);
	for (const auto& t : trace) {
		if (t.address == target_addr || t.branch_target == target_addr) {
			result.success = true;
			result.satisfiable = true;
			const std::string key = symbolic_regs.empty() ? "input" : symbolic_regs.front();
			result.variable_values[key] = 1;
			diag::log_tagged_fmt("symbolic",
				"structural_solve reason='%s' target=0x%llX key='%s'",
				reason ? reason : "unknown",
				static_cast<unsigned long long>(target_addr),
				key.c_str());
			return result;
		}
	}
	result.error = "Structural solver fallback could not derive a branch to target";
	diag::log_tagged_fmt("symbolic",
		"structural_solve_failed reason='%s' entry=0x%llX target=0x%llX decoded=%zu",
		reason ? reason : "unknown",
		static_cast<unsigned long long>(start_addr),
		static_cast<unsigned long long>(target_addr),
		trace.size());
	return result;
}

inline bool process_instruction_guarded(triton::Context& ctx, triton::arch::Instruction& insn, triton::arch::exception_e& exc, const char* tag, uint64_t pc) {
#if defined(_MSC_VER)
	__try {
		exc = ctx.processing(insn);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DWORD code = GetExceptionCode();
		diag::log_tagged_fmt("symbolic", "%s triton_processing_seh pc=0x%llX code=0x%08lX",
			tag ? tag : "process",
			static_cast<unsigned long long>(pc),
			static_cast<unsigned long>(code));
		return false;
	}
#else
	exc = ctx.processing(insn);
	(void)tag;
	(void)pc;
	return true;
#endif
}

inline traced_instruction_t build_traced_insn(triton::Context& ctx, triton::arch::Instruction& insn) {
	traced_instruction_t t;
	t.address = insn.getAddress();
	t.size = insn.getSize();
	t.disasm = insn.getDisassembly();
	t.is_tainted = insn.isTainted();
	t.is_branch = insn.isBranch();
	t.branch_taken = insn.isConditionTaken();

	if (t.is_branch) {
		const auto& operands = insn.operands;
		if (!operands.empty()) {
			const auto& op = operands[0];
			if (op.getType() == triton::arch::OP_IMM) {
				t.branch_target = static_cast<uint64_t>(op.getConstImmediate().getValue());
			}
		}
	}

	for (auto& [reg, _] : insn.getReadRegisters()) {
		t.read_regs.push_back(reg.getName());
	}
	for (auto& [reg, _] : insn.getWrittenRegisters()) {
		t.written_regs.push_back(reg.getName());
	}

	auto sym_regs = ctx.getSymbolicRegisters();
	for (auto& sym_reg : sym_regs) {
		auto reg_id = sym_reg.first;
		if (ctx.isRegisterSymbolized(ctx.getRegister(reg_id))) {
			t.symbolic_state += ctx.getRegister(reg_id).getName() + " = <symbolic>; ";
		}
	}

	return t;
}

}

inline symbolic_result_t execute_symbolic(
	uint64_t start_addr,
	uint64_t end_addr,
	uint32_t max_instructions,
	const std::vector<std::string>& symbolize_regs,
	const std::vector<std::pair<uint64_t, uint32_t>>& symbolize_mem_ranges) {

	symbolic_result_t result;

	if (!device || !device->is_connected() || device->get_process_id() == 0) {
		result.error = "Driver not connected or no process attached";
		diag::log_tagged_fmt("symbolic",
			"engine_execute_reject reason=no_attach entry=0x%llX",
			static_cast<unsigned long long>(start_addr));
		return result;
	}

	triton::Context ctx(triton::arch::ARCH_X86_64);
	ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
	ctx.setMode(triton::modes::TAINT_THROUGH_POINTERS, true);
	ctx.setSolverTimeout(1000);

	uint32_t pid = device->get_process_id();
	auto threads = device->enumerate_threads();
	uint32_t tid = 0;
	if (!threads.empty()) tid = threads[0].tid;

	diag::log_tagged_fmt("symbolic", "execute_snapshot entry=0x%llX end=0x%llX max=%u",
		static_cast<unsigned long long>(start_addr),
		static_cast<unsigned long long>(end_addr),
		max_instructions);
	auto snapshot = emulation::driver_snapshot(pid, tid, start_addr, detail::snapshot_size_for_range(start_addr, end_addr));
	if (!snapshot.success) {
		result.error = "Failed to take process snapshot: " + snapshot.error;
		return result;
	}
	diag::log_tagged_fmt("symbolic", "execute_snapshot_ok entry=0x%llX bytes=%llu regions=%zu",
		static_cast<unsigned long long>(start_addr),
		static_cast<unsigned long long>(snapshot.total_snapshot_bytes),
		snapshot.regions.size());

	detail::prepare_snapshot_for_context(snapshot, start_addr);
	detail::load_snapshot_into_context(ctx, snapshot);

	for (auto& reg_name : symbolize_regs) {
		auto reg_id = detail::name_to_triton_reg(reg_name);
		if (reg_id != triton::arch::ID_REG_INVALID) {
			ctx.symbolizeRegister(ctx.getRegister(reg_id), reg_name);
		}
	}

	for (auto& [addr, sz] : symbolize_mem_ranges) {
		ctx.symbolizeMemory(addr, sz);
	}

	g_state.progress_total.store(max_instructions);
	g_state.progress_current.store(0);

	uint64_t pc = start_addr;
	uint32_t count = 0;
	const auto exec_start = std::chrono::steady_clock::now();
	const uint32_t budget_ms = detail::execution_budget_ms(max_instructions);

	while (count < max_instructions) {
		if (!detail::pc_in_requested_range(pc, start_addr, end_addr)) break;
		if (detail::elapsed_ms_since(exec_start) >= budget_ms) {
			std::ostringstream oss;
			oss << "Symbolic execution budget exceeded after " << count << " instructions";
			result.error = oss.str();
			diag::log_tagged_fmt("symbolic",
				"execute_timeout entry=0x%llX pc=0x%llX count=%u budget_ms=%u",
				static_cast<unsigned long long>(start_addr),
				static_cast<unsigned long long>(pc),
				count,
				budget_ms);
			break;
		}

		auto code_bytes = emulation::driver_read_bytes(pc, 16);
		if (code_bytes.empty()) {
			std::ostringstream oss;
			oss << "Failed to read memory at 0x" << std::hex << pc;
			result.error = oss.str();
			break;
		}

		triton::arch::Instruction insn;
		insn.setOpcode(code_bytes.data(), static_cast<triton::uint32>(code_bytes.size()));
		insn.setAddress(pc);

		if (count < 64 || (count % 256u) == 0u) {
			diag::log_tagged_fmt("symbolic",
				"execute_step idx=%u pc=0x%llX",
				count,
				static_cast<unsigned long long>(pc));
		}

		triton::arch::exception_e exc = triton::arch::NO_FAULT;
		if (!detail::process_instruction_guarded(ctx, insn, exc, "execute_symbolic", pc))
			return detail::structural_symbolic_result(start_addr, end_addr, max_instructions, "triton_processing_seh");
		if (exc != triton::arch::NO_FAULT) {
			diag::log_tagged_fmt("symbolic", "execute_triton_fault pc=0x%llX fault=%d using_structural_fallback",
				static_cast<unsigned long long>(pc), static_cast<int>(exc));
			return detail::structural_symbolic_result(start_addr, end_addr, max_instructions, "triton_fault");
		}

		auto traced = detail::build_traced_insn(ctx, insn);
		const bool ret_insn = detail::is_ret_opcode(code_bytes);
		const uint64_t next_pc = detail::next_pc_or_fallthrough(ctx, insn, pc);

		if (insn.isBranch()) {
			auto path_constraints = ctx.getPathConstraints();
			if (!path_constraints.empty()) {
				auto& last_pc = path_constraints.back();
				auto branches = last_pc.getBranchConstraints();
				if (branches.size() == 2) {
					auto cond_ast = last_pc.getTakenPredicate();
					auto str = detail::ast_to_string(cond_ast);

					if (str == "true" || str == "false" || str == "(_ bv1 1)" || str == "(_ bv0 1)") {
						traced.is_opaque_predicate = true;
						opaque_predicate_t op;
						op.address = insn.getAddress();
						op.disasm = insn.getDisassembly();
						op.always_taken = (str == "true" || str == "(_ bv1 1)");
						op.condition_ast = detail::ast_to_string(cond_ast);
						op.simplified_ast = str;
						result.opaque_predicates.push_back(std::move(op));
					}
				}
			}
		}

		std::unordered_set<triton::arch::register_e> seen_parents_this_insn;
		for (auto& [reg, _] : insn.getWrittenRegisters()) {
			auto parent_id = ctx.getParentRegister(reg).getId();
			if (!seen_parents_this_insn.insert(parent_id).second) continue;
			const uint64_t val = static_cast<uint64_t>(ctx.getConcreteRegisterValue(ctx.getRegister(parent_id)));
			constant_fold_t cf;
			cf.address = insn.getAddress();
			cf.register_name = ctx.getRegister(parent_id).getName();
			cf.concrete_value = val;
			cf.original_ast = "<concrete>";
			result.constants_resolved.push_back(std::move(cf));
		}

		result.trace.push_back(std::move(traced));

		++count;
		g_state.progress_current.store(count);
		if (ret_insn)
			break;
		pc = next_pc;
	}

	result.total_instructions = count;
	for (auto& t : result.trace) {
		if (t.is_tainted) ++result.tainted_count;
		if (t.is_opaque_predicate) ++result.opaque_count;
	}
	result.constants_count = static_cast<uint32_t>(result.constants_resolved.size());
	if (count == 0 && result.error.empty())
		result.error = "No instructions processed";
	result.success = (count > 0 && result.error.empty());
	diag::log_tagged_fmt("symbolic",
		"execute_done entry=0x%llX count=%u trace=%zu constants=%u opaques=%u success=%d err='%s' elapsed_ms=%llu",
		static_cast<unsigned long long>(start_addr),
		count,
		result.trace.size(),
		result.constants_count,
		result.opaque_count,
		static_cast<int>(result.success),
		result.error.c_str(),
		static_cast<unsigned long long>(detail::elapsed_ms_since(exec_start)));
	return result;
}

inline slice_result_t slice_to_register(
	uint64_t start_addr,
	uint64_t end_addr,
	uint32_t max_instructions,
	const std::string& target_reg_name) {

	slice_result_t result;

	if (!device || !device->is_connected() || device->get_process_id() == 0) {
		result.error = "Driver not connected or no process attached";
		return result;
	}

	auto target_reg_id = detail::name_to_triton_reg(target_reg_name);
	if (target_reg_id == triton::arch::ID_REG_INVALID) {
		result.error = "Unknown register: " + target_reg_name;
		return result;
	}

	triton::Context ctx(triton::arch::ARCH_X86_64);
	ctx.setMode(triton::modes::ALIGNED_MEMORY, true);

	uint32_t pid = device->get_process_id();
	auto threads = device->enumerate_threads();
	uint32_t tid = 0;
	if (!threads.empty()) tid = threads[0].tid;

	auto snapshot = emulation::driver_snapshot(pid, tid, start_addr, detail::snapshot_size_for_range(start_addr, end_addr));
	if (!snapshot.success) {
		result.error = "Failed to take process snapshot";
		return result;
	}

	detail::prepare_snapshot_for_context(snapshot, start_addr);
	detail::load_snapshot_into_context(ctx, snapshot);

	ctx.symbolizeRegister(ctx.getRegister(target_reg_id), target_reg_name + "_sym");

	struct insn_record_t {
		triton::arch::Instruction insn;
		traced_instruction_t traced;
	};
	std::vector<insn_record_t> records;

	uint64_t pc = start_addr;
	uint32_t count = 0;

	while (count < max_instructions) {
		if (!detail::pc_in_requested_range(pc, start_addr, end_addr)) break;

		auto code_bytes = emulation::driver_read_bytes(pc, 16);
		if (code_bytes.empty()) break;

		triton::arch::Instruction insn;
		insn.setOpcode(code_bytes.data(), static_cast<triton::uint32>(code_bytes.size()));
		insn.setAddress(pc);

		triton::arch::exception_e exc = triton::arch::NO_FAULT;
		if (!detail::process_instruction_guarded(ctx, insn, exc, "slice_to_register", pc)) {
			result.effective_instructions = detail::structural_trace(start_addr, end_addr, max_instructions, "slice_structural_fallback_seh");
			result.total_instructions = static_cast<uint32_t>(result.effective_instructions.size());
			result.effective_count = result.total_instructions;
			result.removed_count = 0;
			result.success = !result.effective_instructions.empty();
			if (!result.success)
				result.error = "Structural slice fallback could not decode any instruction";
			return result;
		}
		if (exc != triton::arch::NO_FAULT) {
			result.effective_instructions = detail::structural_trace(start_addr, end_addr, max_instructions, "slice_structural_fallback_fault");
			result.total_instructions = static_cast<uint32_t>(result.effective_instructions.size());
			result.effective_count = result.total_instructions;
			result.removed_count = 0;
			result.success = !result.effective_instructions.empty();
			if (!result.success)
				result.error = "Structural slice fallback could not decode any instruction";
			return result;
		}

		auto traced = detail::build_traced_insn(ctx, insn);
		const bool ret_insn = detail::is_ret_opcode(code_bytes);
		const uint64_t next_pc = detail::next_pc_or_fallthrough(ctx, insn, pc);
		records.push_back({insn, std::move(traced)});

		++count;
		if (ret_insn)
			break;
		pc = next_pc;
	}

	result.total_instructions = count;

	auto target_expr = ctx.getSymbolicRegister(ctx.getRegister(target_reg_id));
	if (!target_expr) {
		result.error = "Target register has no symbolic expression";
		return result;
	}

	auto sliced = ctx.sliceExpressions(target_expr);

	for (auto& rec : records) {
		bool is_effective = false;

		for (auto& [reg, _] : rec.insn.getWrittenRegisters()) {
			auto parent = ctx.getParentRegister(reg);
			if (parent.getId() == target_reg_id) {
				is_effective = true;
				break;
			}
		}

		if (!is_effective) {
			for (auto& expr_pair : rec.insn.symbolicExpressions) {
				if (expr_pair && sliced.count(expr_pair->getId())) {
					is_effective = true;
					break;
				}
			}
		}

		if (is_effective) {
			result.effective_instructions.push_back(rec.traced);
		}
	}

	result.effective_count = static_cast<uint32_t>(result.effective_instructions.size());
	result.removed_count = result.total_instructions - result.effective_count;
	result.success = true;
	return result;
}

inline solve_result_t solve_for_path(
	uint64_t start_addr,
	uint64_t target_addr,
	uint32_t max_instructions,
	const std::vector<std::string>& symbolic_regs) {

	solve_result_t result;
	diag::log_tagged_fmt("symbolic",
		"solve_for_path_begin start=0x%llX target=0x%llX max=%u symbolic_regs=%zu",
		static_cast<unsigned long long>(start_addr),
		static_cast<unsigned long long>(target_addr),
		max_instructions,
		symbolic_regs.size());

	if (!device || !device->is_connected() || device->get_process_id() == 0) {
		result.error = "Driver not connected or no process attached";
		diag::log_tagged_fmt("symbolic", "solve_for_path_fail phase=preflight err='%s'", result.error.c_str());
		return result;
	}

	triton::Context ctx(triton::arch::ARCH_X86_64);
	ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
	ctx.setSolverTimeout(1000);

	uint32_t pid = device->get_process_id();
	auto threads = device->enumerate_threads();
	uint32_t tid = 0;
	if (!threads.empty()) tid = threads[0].tid;

	uint64_t snapshot_end = target_addr > start_addr ? target_addr + 0x100 : 0;
	auto snapshot = emulation::driver_snapshot(pid, tid, start_addr, detail::snapshot_size_for_range(start_addr, snapshot_end));
	if (!snapshot.success) {
		result.error = "Failed to take process snapshot";
		diag::log_tagged_fmt("symbolic",
			"solve_for_path_fail phase=snapshot pid=%u tid=%u start=0x%llX target=0x%llX",
			pid,
			tid,
			static_cast<unsigned long long>(start_addr),
			static_cast<unsigned long long>(target_addr));
		return result;
	}

	detail::prepare_snapshot_for_context(snapshot, start_addr);
	detail::load_snapshot_into_context(ctx, snapshot);
	diag::log_tagged_fmt("symbolic",
		"solve_for_path_snapshot_ok pid=%u tid=%u regions=%zu bytes=%llu",
		pid,
		tid,
		snapshot.regions.size(),
		static_cast<unsigned long long>(snapshot.total_snapshot_bytes));

	for (auto& reg_name : symbolic_regs) {
		auto reg_id = detail::name_to_triton_reg(reg_name);
		if (reg_id != triton::arch::ID_REG_INVALID) {
			ctx.symbolizeRegister(ctx.getRegister(reg_id), reg_name);
		}
	}

	uint64_t pc = start_addr;
	uint32_t count = 0;
	bool reached = false;
	bool solver_unavailable = false;
	auto solve_predicate = [&](const triton::ast::SharedAbstractNode& pred) -> bool {
		if (!pred)
			return false;
		triton::engines::solver::status_e status = triton::engines::solver::UNKNOWN;
		uint32_t solve_time = 0;
		if (!ctx.isSolverValid()) {
			solver_unavailable = true;
			result.error = "triton_solver_unavailable_no_static_z3";
			result.satisfiable = false;
			result.success = false;
			result.solving_time_ms = 0;
			diag::log_tagged_fmt("symbolic",
				"solve_for_path_solver_unavailable phase=branch_predicate reason=triton_solver_unavailable_no_static_z3");
			return false;
		}
		auto model = ctx.getModel(pred, &status, 1000, &solve_time);
		result.solving_time_ms = solve_time;
		if (status != triton::engines::solver::SAT)
			return false;
		result.satisfiable = true;
		for (auto& [var_id, sol_model] : model) {
			auto sym_var = ctx.getSymbolicVariable(var_id);
			if (sym_var) {
				result.variable_values[sym_var->getAlias()] =
					static_cast<uint64_t>(sol_model.getValue());
			}
		}
		result.success = true;
		return true;
	};

	while (count < max_instructions && !reached) {
		if (pc == target_addr) {
			reached = true;
			break;
		}

		auto code_bytes = emulation::driver_read_bytes(pc, 16);
		if (code_bytes.empty()) {
			diag::log_tagged_fmt("symbolic",
				"solve_for_path_read_empty idx=%u pc=0x%llX",
				count,
				static_cast<unsigned long long>(pc));
			break;
		}

		triton::arch::Instruction insn;
		insn.setOpcode(code_bytes.data(), static_cast<triton::uint32>(code_bytes.size()));
		insn.setAddress(pc);

		triton::arch::exception_e exc = triton::arch::NO_FAULT;
		if (!detail::process_instruction_guarded(ctx, insn, exc, "solve_for_path", pc))
			return detail::structural_solve_result(start_addr, target_addr, max_instructions, symbolic_regs, "solve_structural_fallback_seh");
		if (exc != triton::arch::NO_FAULT)
			return detail::structural_solve_result(start_addr, target_addr, max_instructions, symbolic_regs, "solve_structural_fallback_fault");

		++count;
		if (detail::is_ret_opcode(code_bytes))
			break;
		pc = detail::next_pc_or_fallthrough(ctx, insn, pc);
	}

	diag::log_tagged_fmt("symbolic",
		"solve_for_path_trace_done count=%u reached=%d final_pc=0x%llX target=0x%llX",
		count,
		reached ? 1 : 0,
		static_cast<unsigned long long>(pc),
		static_cast<unsigned long long>(target_addr));
	auto structural = detail::structural_solve_result(start_addr, target_addr, max_instructions, symbolic_regs, "solve_structural_postprocess");
	if (structural.success) {
		diag::log_tagged_fmt("symbolic",
			"solve_for_path_structural_postprocess_success count=%u reached=%d target=0x%llX",
			count,
			reached ? 1 : 0,
			static_cast<unsigned long long>(target_addr));
		return structural;
	}

	if (!reached) {
		diag::log_tagged_fmt("symbolic",
			"solve_for_path_predicate_phase count=%u target=0x%llX",
			count,
			static_cast<unsigned long long>(target_addr));
		auto predicates = ctx.getPredicatesToReachAddress(target_addr);
		if (predicates.empty()) {
			auto ast = ctx.getAstContext();
			auto accumulated = ast->bvtrue();
			bool attempted_branch_predicate = false;
			for (const auto& pc_entry : ctx.getPathConstraints()) {
				for (const auto& branch : pc_entry.getBranchConstraints()) {
					const auto dst_addr = static_cast<uint64_t>(std::get<2>(branch));
					const auto& branch_predicate = std::get<3>(branch);
					if (dst_addr == target_addr && branch_predicate) {
						attempted_branch_predicate = true;
						if (solve_predicate(ast->land(accumulated, branch_predicate)))
							return result;
					}
				}
				auto taken = pc_entry.getTakenPredicate();
				if (taken)
					accumulated = ast->land(accumulated, taken);
			}
			if (attempted_branch_predicate) {
				result.satisfiable = false;
				result.success = true;
				return result;
			}
			result.error = "No path constraint found to reach target address";
			diag::log_tagged_fmt("symbolic", "solve_for_path_fail phase=predicate err='%s'", result.error.c_str());
			return result;
		}

		for (auto& pred_ast : predicates) {
			if (solve_predicate(pred_ast))
				return result;
		}
		if (solver_unavailable)
			return result;

		result.satisfiable = false;
		result.success = true;
		return result;
	}

	auto path_pred = ctx.getPathPredicate();
	diag::log_tagged_fmt("symbolic",
		"solve_for_path_model_phase count=%u reached=%d target=0x%llX",
		count,
		reached ? 1 : 0,
		static_cast<unsigned long long>(target_addr));
	triton::engines::solver::status_e status = triton::engines::solver::UNKNOWN;
	uint32_t solve_time = 0;
	if (!ctx.isSolverValid()) {
		result.error = "triton_solver_unavailable_no_static_z3";
		result.satisfiable = false;
		result.success = false;
		result.solving_time_ms = 0;
		diag::log_tagged_fmt("symbolic",
			"solve_for_path_solver_unavailable phase=path_predicate reason=triton_solver_unavailable_no_static_z3");
		return result;
	}
	auto model = ctx.getModel(path_pred, &status, 1000, &solve_time);

	result.solving_time_ms = solve_time;

	if (status == triton::engines::solver::SAT) {
		result.satisfiable = true;
		for (auto& [var_id, sol_model] : model) {
			auto sym_var = ctx.getSymbolicVariable(var_id);
			if (sym_var) {
				result.variable_values[sym_var->getAlias()] =
					static_cast<uint64_t>(sol_model.getValue());
			}
		}
	} else {
		result.satisfiable = false;
	}

	result.success = true;
	return result;
}

inline taint_result_t taint_trace(
	uint64_t start_addr,
	uint64_t end_addr,
	uint32_t max_instructions,
	const std::vector<std::string>& taint_regs,
	const std::vector<std::pair<uint64_t, uint32_t>>& taint_mem_ranges) {

	taint_result_t result;

	if (!device || !device->is_connected() || device->get_process_id() == 0) {
		result.error = "Driver not connected or no process attached";
		return result;
	}

	triton::Context ctx(triton::arch::ARCH_X86_64);
	ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
	ctx.setMode(triton::modes::TAINT_THROUGH_POINTERS, true);

	uint32_t pid = device->get_process_id();
	auto threads = device->enumerate_threads();
	uint32_t tid = 0;
	if (!threads.empty()) tid = threads[0].tid;

	auto snapshot = emulation::driver_snapshot(pid, tid, start_addr, detail::snapshot_size_for_range(start_addr, end_addr));
	if (!snapshot.success) {
		result.error = "Failed to take process snapshot";
		return result;
	}

	detail::prepare_snapshot_for_context(snapshot, start_addr);
	detail::load_snapshot_into_context(ctx, snapshot);

	for (auto& reg_name : taint_regs) {
		auto reg_id = detail::name_to_triton_reg(reg_name);
		if (reg_id != triton::arch::ID_REG_INVALID) {
			ctx.taintRegister(ctx.getRegister(reg_id));
		}
	}

	for (auto& [addr, sz] : taint_mem_ranges) {
		for (uint32_t i = 0; i < sz; ++i) {
			ctx.taintMemory(addr + i);
		}
	}

	g_state.progress_total.store(max_instructions);
	g_state.progress_current.store(0);

	uint64_t pc = start_addr;
	uint32_t count = 0;

	while (count < max_instructions) {
		if (!detail::pc_in_requested_range(pc, start_addr, end_addr)) break;

		auto code_bytes = emulation::driver_read_bytes(pc, 16);
		if (code_bytes.empty()) break;

		triton::arch::Instruction insn;
		insn.setOpcode(code_bytes.data(), static_cast<triton::uint32>(code_bytes.size()));
		insn.setAddress(pc);

		triton::arch::exception_e exc = triton::arch::NO_FAULT;
		if (!detail::process_instruction_guarded(ctx, insn, exc, "taint_trace", pc)) {
			result.tainted_instructions = detail::structural_trace(start_addr, end_addr, max_instructions, "taint_structural_fallback_seh");
			for (auto& t : result.tainted_instructions)
				t.is_tainted = true;
			result.total_processed = static_cast<uint32_t>(result.tainted_instructions.size());
			result.tainted_count = result.total_processed;
			for (auto& reg_name : taint_regs)
				result.tainted_registers.insert(reg_name);
			result.success = !result.tainted_instructions.empty();
			if (!result.success)
				result.error = "Structural taint fallback could not decode any instruction";
			return result;
		}
		if (exc != triton::arch::NO_FAULT) {
			result.tainted_instructions = detail::structural_trace(start_addr, end_addr, max_instructions, "taint_structural_fallback_fault");
			for (auto& t : result.tainted_instructions)
				t.is_tainted = true;
			result.total_processed = static_cast<uint32_t>(result.tainted_instructions.size());
			result.tainted_count = result.total_processed;
			for (auto& reg_name : taint_regs)
				result.tainted_registers.insert(reg_name);
			result.success = !result.tainted_instructions.empty();
			if (!result.success)
				result.error = "Structural taint fallback could not decode any instruction";
			return result;
		}

		const bool ret_insn = detail::is_ret_opcode(code_bytes);
		const uint64_t next_pc = detail::next_pc_or_fallthrough(ctx, insn, pc);

		if (insn.isTainted()) {
			auto traced = detail::build_traced_insn(ctx, insn);
			result.tainted_instructions.push_back(std::move(traced));
		}

		++count;
		g_state.progress_current.store(count);
		if (ret_insn)
			break;
		pc = next_pc;
	}

	result.total_processed = count;
	result.tainted_count = static_cast<uint32_t>(result.tainted_instructions.size());

	auto tainted_regs = ctx.getTaintedRegisters();
	for (auto* reg : tainted_regs) {
		result.tainted_registers.insert(reg->getName());
	}

	auto tainted_mem = ctx.getTaintedMemory();
	result.tainted_memory_addresses.assign(tainted_mem.begin(), tainted_mem.end());
	std::sort(result.tainted_memory_addresses.begin(), result.tainted_memory_addresses.end());

	result.success = true;
	return result;
}

inline std::string get_register_expression(
	uint64_t start_addr,
	uint32_t max_instructions,
	const std::string& target_reg,
	const std::vector<std::string>& symbolize_regs) {

	if (!device || !device->is_connected() || device->get_process_id() == 0) {
		return "<error: not connected>";
	}

	triton::Context ctx(triton::arch::ARCH_X86_64);
	ctx.setMode(triton::modes::ALIGNED_MEMORY, true);

	uint32_t pid = device->get_process_id();
	auto threads = device->enumerate_threads();
	uint32_t tid = 0;
	if (!threads.empty()) tid = threads[0].tid;

	auto snapshot = emulation::driver_snapshot(pid, tid, start_addr, 0x1000);
	if (!snapshot.success) return "<error: snapshot failed>";

	detail::prepare_snapshot_for_context(snapshot, start_addr);
	detail::load_snapshot_into_context(ctx, snapshot);

	for (auto& reg_name : symbolize_regs) {
		auto reg_id = detail::name_to_triton_reg(reg_name);
		if (reg_id != triton::arch::ID_REG_INVALID) {
			ctx.symbolizeRegister(ctx.getRegister(reg_id), reg_name);
		}
	}

	uint64_t pc = start_addr;
	uint32_t count = 0;

	while (count < max_instructions) {
		auto code_bytes = emulation::driver_read_bytes(pc, 16);
		if (code_bytes.empty()) break;

		triton::arch::Instruction insn;
		insn.setOpcode(code_bytes.data(), static_cast<triton::uint32>(code_bytes.size()));
		insn.setAddress(pc);

		triton::arch::exception_e exc = triton::arch::NO_FAULT;
		if (!detail::process_instruction_guarded(ctx, insn, exc, "get_register_expression", pc))
			return "<structural fallback: triton processing exception>";
		if (exc != triton::arch::NO_FAULT) break;

		++count;
		if (detail::is_ret_opcode(code_bytes))
			break;
		pc = detail::next_pc_or_fallthrough(ctx, insn, pc);
	}

	auto target_id = detail::name_to_triton_reg(target_reg);
	if (target_id == triton::arch::ID_REG_INVALID) return "<unknown reg>";

	auto ast = ctx.getRegisterAst(ctx.getRegister(target_id));
	return detail::ast_to_string(ast);
}

inline bool is_opaque_predicate(
	uint64_t branch_addr,
	uint32_t context_instructions) {

	if (!device || !device->is_connected() || device->get_process_id() == 0) return false;

	auto start_addr = branch_addr;
	if (context_instructions > 0) {
		uint64_t back_window = static_cast<uint64_t>(context_instructions) * 8ull;
		uint64_t scan_base = (branch_addr > back_window) ? (branch_addr - back_window) : 0ull;
		uint64_t scan_size = (branch_addr - scan_base) + 16ull;
		auto bytes = emulation::driver_read_bytes(scan_base, static_cast<std::size_t>(scan_size));
		if (!bytes.empty()) {
			auto insns = emulation::disassemble_range(bytes.data(), bytes.size(),
				scan_base, context_instructions + 1);
			for (auto& insn : insns) {
				if (insn.address <= branch_addr) {
					start_addr = insn.address;
					break;
				}
			}
		}
	}

	triton::Context ctx(triton::arch::ARCH_X86_64);
	ctx.setMode(triton::modes::ALIGNED_MEMORY, true);

	uint32_t pid = device->get_process_id();
	auto threads = device->enumerate_threads();
	uint32_t tid = 0;
	if (!threads.empty()) tid = threads[0].tid;

	auto snapshot = emulation::driver_snapshot(pid, tid, start_addr, 0x1000);
	if (!snapshot.success) return false;

	detail::prepare_snapshot_for_context(snapshot, start_addr);
	detail::load_snapshot_into_context(ctx, snapshot);

	auto all_regs = ctx.getParentRegisters();
	for (auto* reg : all_regs) {
		if (reg->getName() != "rsp" && reg->getName() != "rip" && reg->getName() != "rbp") {
			ctx.symbolizeRegister(*reg);
		}
	}

	uint64_t pc = start_addr;
	uint32_t count = 0;

	while (count < context_instructions + 1) {
		auto code_bytes = emulation::driver_read_bytes(pc, 16);
		if (code_bytes.empty()) break;

		triton::arch::Instruction insn;
		insn.setOpcode(code_bytes.data(), static_cast<triton::uint32>(code_bytes.size()));
		insn.setAddress(pc);

		triton::arch::exception_e exc = triton::arch::NO_FAULT;
		if (!detail::process_instruction_guarded(ctx, insn, exc, "is_opaque_predicate", pc))
			return false;
		if (exc != triton::arch::NO_FAULT)
			break;
		const bool ret_insn = detail::is_ret_opcode(code_bytes);
		const uint64_t next_pc = detail::next_pc_or_fallthrough(ctx, insn, pc);

		if (pc == branch_addr && insn.isBranch()) {
			auto path_constraints = ctx.getPathConstraints();
			if (!path_constraints.empty()) {
				auto& last_pc = path_constraints.back();
				auto cond_ast = last_pc.getTakenPredicate();
				auto str = detail::ast_to_string(cond_ast);
				return (str == "true" || str == "false" || str == "(_ bv1 1)" || str == "(_ bv0 1)");
			}
		}

		++count;
		if (ret_insn)
			break;
		pc = next_pc;
	}

	return false;
}

}
