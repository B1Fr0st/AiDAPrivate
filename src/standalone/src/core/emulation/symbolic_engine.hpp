#pragma once

#include <triton/context.hpp>
#include <triton/x86Specifications.hpp>

#include "emulation_engine.hpp"
#include "comm.h"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <string>
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
	for (auto& [reg_id, expr] : sym_regs) {
		if (ctx.isRegisterSymbolized(ctx.getRegister(reg_id))) {
			auto ast = ctx.getRegisterAst(ctx.getRegister(reg_id));
			auto simplified = ctx.simplify(ast, true);
			t.symbolic_state += ctx.getRegister(reg_id).getName() + " = " + ast_to_string(simplified) + "; ";
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
	ctx.setSolverTimeout(5000);

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

	while (count < max_instructions) {
		if (!detail::pc_in_requested_range(pc, start_addr, end_addr)) break;

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

		auto exc = ctx.processing(insn);
		if (exc != triton::arch::NO_FAULT) {
			std::ostringstream oss;
			oss << "Triton fault at 0x" << std::hex << pc << " (code=" << std::dec << static_cast<int>(exc) << ")";
			result.error = oss.str();
			break;
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
					auto simplified = ctx.simplify(cond_ast, true);
					auto str = detail::ast_to_string(simplified);

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
			auto ast = ctx.getRegisterAst(ctx.getRegister(parent_id));
			if (!ast) continue;
			auto simplified = ctx.simplify(ast, true);
			if (simplified && simplified->getType() == triton::ast::BV_NODE) {
				uint64_t val = static_cast<uint64_t>(simplified->evaluate());
				constant_fold_t cf;
				cf.address = insn.getAddress();
				cf.register_name = ctx.getRegister(parent_id).getName();
				cf.concrete_value = val;
				cf.original_ast = detail::ast_to_string(ast);
				result.constants_resolved.push_back(std::move(cf));
			}
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
	result.success = true;
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

		auto exc = ctx.processing(insn);
		if (exc != triton::arch::NO_FAULT) break;

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

	if (!device || !device->is_connected() || device->get_process_id() == 0) {
		result.error = "Driver not connected or no process attached";
		return result;
	}

	triton::Context ctx(triton::arch::ARCH_X86_64);
	ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
	ctx.setSolverTimeout(10000);

	uint32_t pid = device->get_process_id();
	auto threads = device->enumerate_threads();
	uint32_t tid = 0;
	if (!threads.empty()) tid = threads[0].tid;

	uint64_t snapshot_end = target_addr > start_addr ? target_addr + 0x100 : 0;
	auto snapshot = emulation::driver_snapshot(pid, tid, start_addr, detail::snapshot_size_for_range(start_addr, snapshot_end));
	if (!snapshot.success) {
		result.error = "Failed to take process snapshot";
		return result;
	}

	detail::load_snapshot_into_context(ctx, snapshot);

	for (auto& reg_name : symbolic_regs) {
		auto reg_id = detail::name_to_triton_reg(reg_name);
		if (reg_id != triton::arch::ID_REG_INVALID) {
			ctx.symbolizeRegister(ctx.getRegister(reg_id), reg_name);
		}
	}

	uint64_t pc = start_addr;
	uint32_t count = 0;
	bool reached = false;

	while (count < max_instructions && !reached) {
		if (pc == target_addr) {
			reached = true;
			break;
		}

		auto code_bytes = emulation::driver_read_bytes(pc, 16);
		if (code_bytes.empty()) break;

		triton::arch::Instruction insn;
		insn.setOpcode(code_bytes.data(), static_cast<triton::uint32>(code_bytes.size()));
		insn.setAddress(pc);

		auto exc = ctx.processing(insn);
		if (exc != triton::arch::NO_FAULT) break;

		++count;
		if (detail::is_ret_opcode(code_bytes))
			break;
		pc = detail::next_pc_or_fallthrough(ctx, insn, pc);
	}

	if (!reached) {
		auto predicates = ctx.getPredicatesToReachAddress(target_addr);
		if (predicates.empty()) {
			result.error = "No path constraint found to reach target address";
			return result;
		}

		for (auto& pred_ast : predicates) {
			triton::engines::solver::status_e status;
			uint32_t solve_time = 0;
			auto model = ctx.getModel(pred_ast, &status, 10000, &solve_time);

			if (status == triton::engines::solver::SAT) {
				result.satisfiable = true;
				result.solving_time_ms = solve_time;

				for (auto& [var_id, sol_model] : model) {
					auto sym_var = ctx.getSymbolicVariable(var_id);
					if (sym_var) {
						result.variable_values[sym_var->getAlias()] =
							static_cast<uint64_t>(sol_model.getValue());
					}
				}

				result.success = true;
				return result;
			}
		}

		result.satisfiable = false;
		result.success = true;
		return result;
	}

	auto path_pred = ctx.getPathPredicate();
	triton::engines::solver::status_e status;
	uint32_t solve_time = 0;
	auto model = ctx.getModel(path_pred, &status, 10000, &solve_time);

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

		auto exc = ctx.processing(insn);
		if (exc != triton::arch::NO_FAULT) break;

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

		auto exc = ctx.processing(insn);
		if (exc != triton::arch::NO_FAULT) break;

		++count;
		if (detail::is_ret_opcode(code_bytes))
			break;
		pc = detail::next_pc_or_fallthrough(ctx, insn, pc);
	}

	auto target_id = detail::name_to_triton_reg(target_reg);
	if (target_id == triton::arch::ID_REG_INVALID) return "<unknown reg>";

	auto ast = ctx.getRegisterAst(ctx.getRegister(target_id));
	auto simplified = ctx.simplify(ast, true);
	return detail::ast_to_string(simplified);
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

		auto exc = ctx.processing(insn);
		if (exc != triton::arch::NO_FAULT)
			break;
		const bool ret_insn = detail::is_ret_opcode(code_bytes);
		const uint64_t next_pc = detail::next_pc_or_fallthrough(ctx, insn, pc);

		if (pc == branch_addr && insn.isBranch()) {
			auto path_constraints = ctx.getPathConstraints();
			if (!path_constraints.empty()) {
				auto& last_pc = path_constraints.back();
				auto cond_ast = last_pc.getTakenPredicate();
				auto simplified = ctx.simplify(cond_ast, true);
				auto str = detail::ast_to_string(simplified);
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
