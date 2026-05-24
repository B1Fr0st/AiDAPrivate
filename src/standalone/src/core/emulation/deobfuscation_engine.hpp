#pragma once

#include "symbolic_engine.hpp"
#include "cfg_view.hpp"
#include "zydis_disasm.hpp"
#include "emulation_engine.hpp"
#include "comm.h"

#include <triton/context.hpp>
#include <triton/x86Specifications.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace deobfuscation_engine {

struct clean_instruction_t {
	uint64_t address = 0;
	uint32_t size = 0;
	std::string disasm;
	bool was_junk = false;
	bool was_opaque = false;
	bool was_constant_folded = false;
	std::string original_expression;
	std::string simplified_expression;
};

struct state_variable_t {
	uint64_t dispatcher_addr = 0;
	std::string register_name;
	std::vector<uint64_t> concrete_values;
	std::unordered_map<uint64_t, uint64_t> state_to_target;
};

struct cfg_edge_t {
	int from_block = -1;
	int to_block = -1;
	bool is_fake = false;
	std::string label;
};

struct clean_block_t {
	uint64_t start_addr = 0;
	uint64_t end_addr = 0;
	std::vector<clean_instruction_t> instructions;
	std::vector<int> successors;
	bool is_entry = false;
	bool is_dispatcher = false;
};

struct deobfuscated_result_t {
	bool success = false;
	std::string error;

	std::vector<clean_instruction_t> clean_instructions;
	std::vector<clean_block_t> clean_blocks;
	std::vector<cfg_edge_t> clean_edges;

	uint32_t total_original = 0;
	uint32_t total_clean = 0;
	uint32_t removed_junk = 0;
	uint32_t opaque_predicates_found = 0;
	uint32_t constants_resolved = 0;
	uint32_t dispatcher_states_resolved = 0;
	float junk_ratio = 0.0f;

	std::vector<symbolic_engine::opaque_predicate_t> opaques;
	std::vector<symbolic_engine::constant_fold_t> constants;
	std::vector<state_variable_t> state_vars;
};

struct state_t {
	std::mutex mutex;
	std::atomic<bool> processing{false};
	deobfuscated_result_t last_result;
	std::atomic<uint32_t> progress_current{0};
	std::atomic<uint32_t> progress_total{0};
};

inline state_t g_state;

namespace detail {

struct block_range_t {
	uint64_t start = 0;
	uint64_t end = 0;
	std::vector<emulation::decoded_insn_t> insns;
	std::vector<int> successor_indices;
	bool is_entry = false;
};

inline std::vector<block_range_t> recover_cfg_blocks(uint64_t entry_addr, uint32_t max_blocks = 256) {
	std::vector<block_range_t> blocks;
	std::unordered_map<uint64_t, int> addr_to_idx;
	std::set<uint64_t> work_queue;
	std::unordered_set<uint64_t> visited;

	work_queue.insert(entry_addr);

	while (!work_queue.empty() && blocks.size() < max_blocks) {
		auto it = work_queue.begin();
		uint64_t block_start = *it;
		work_queue.erase(it);

		if (visited.count(block_start)) continue;
		visited.insert(block_start);

		auto code = emulation::driver_read_bytes(block_start, 0x200);
		if (code.empty()) continue;

		auto insns = emulation::disassemble_range(code.data(), code.size(), block_start, 128);
		if (insns.empty()) continue;

		block_range_t block;
		block.start = block_start;
		block.is_entry = (block_start == entry_addr);

		for (size_t i = 0; i < insns.size(); ++i) {
			auto& insn = insns[i];
			block.insns.push_back(insn);
			block.end = insn.address + insn.length;

			bool is_ret = (insn.mnemonic.find("ret") != std::string::npos);
			bool is_jmp = (insn.mnemonic == "jmp");
			bool is_jcc = (insn.mnemonic.size() >= 2 && insn.mnemonic[0] == 'j' && insn.mnemonic != "jmp");
			bool is_call = (insn.mnemonic == "call");

			if (is_ret) break;

			if (is_jmp) {
				uint64_t target = 0;
				if (!insn.operands_text.empty() && insn.operands_text[0] == '0') {
					target = std::strtoull(insn.operands_text.c_str(), nullptr, 16);
				}
				if (target != 0) work_queue.insert(target);
				break;
			}

			if (is_jcc) {
				uint64_t target = 0;
				if (!insn.operands_text.empty() && insn.operands_text[0] == '0') {
					target = std::strtoull(insn.operands_text.c_str(), nullptr, 16);
				}
				uint64_t fallthrough = insn.address + insn.length;
				if (target != 0) work_queue.insert(target);
				work_queue.insert(fallthrough);
				break;
			}

			if (is_call) continue;
		}

		int idx = static_cast<int>(blocks.size());
		addr_to_idx[block_start] = idx;
		blocks.push_back(std::move(block));
	}

	for (auto& block : blocks) {
		if (block.insns.empty()) continue;
		auto& last = block.insns.back();
		bool is_jmp = (last.mnemonic == "jmp");
		bool is_jcc = (last.mnemonic.size() >= 2 && last.mnemonic[0] == 'j' && last.mnemonic != "jmp");
		bool is_ret = (last.mnemonic.find("ret") != std::string::npos);

		if (is_jmp) {
			uint64_t target = 0;
			if (!last.operands_text.empty() && last.operands_text[0] == '0')
				target = std::strtoull(last.operands_text.c_str(), nullptr, 16);
			if (target != 0) {
				auto it2 = addr_to_idx.find(target);
				if (it2 != addr_to_idx.end()) block.successor_indices.push_back(it2->second);
			}
		} else if (is_jcc) {
			uint64_t target = 0;
			if (!last.operands_text.empty() && last.operands_text[0] == '0')
				target = std::strtoull(last.operands_text.c_str(), nullptr, 16);
			uint64_t fallthrough = last.address + last.length;
			if (target != 0) {
				auto it2 = addr_to_idx.find(target);
				if (it2 != addr_to_idx.end()) block.successor_indices.push_back(it2->second);
			}
			auto it3 = addr_to_idx.find(fallthrough);
			if (it3 != addr_to_idx.end()) block.successor_indices.push_back(it3->second);
		} else if (!is_ret) {
			uint64_t fallthrough = last.address + last.length;
			auto it2 = addr_to_idx.find(fallthrough);
			if (it2 != addr_to_idx.end()) block.successor_indices.push_back(it2->second);
		}
	}

	return blocks;
}

inline bool detect_state_machine(triton::Context& ctx, const std::vector<block_range_t>& blocks,
								 state_variable_t& out_state_var) {
	(void)ctx;
	std::unordered_map<std::string, uint32_t> cmp_reg_frequency;

	for (auto& block : blocks) {
		for (auto& insn : block.insns) {
			if (insn.mnemonic == "cmp" || insn.mnemonic == "test") {
				std::string ops = insn.operands_text;
				size_t comma = ops.find(',');
				if (comma != std::string::npos) {
					std::string reg_part = ops.substr(0, comma);
					while (!reg_part.empty() && reg_part.front() == ' ') reg_part.erase(reg_part.begin());
					while (!reg_part.empty() && reg_part.back() == ' ') reg_part.pop_back();
					cmp_reg_frequency[reg_part]++;
				}
			}
		}
	}

	if (cmp_reg_frequency.empty()) return false;

	std::string best_reg;
	uint32_t max_freq = 0;
	for (auto& [reg, freq] : cmp_reg_frequency) {
		if (freq > max_freq) {
			max_freq = freq;
			best_reg = reg;
		}
	}

	if (max_freq < 3) return false;

	out_state_var.register_name = best_reg;

	for (auto& block : blocks) {
		for (auto& insn : block.insns) {
			if (insn.mnemonic == "cmp" && insn.operands_text.find(best_reg) != std::string::npos) {
				size_t comma = insn.operands_text.find(',');
				if (comma != std::string::npos) {
					std::string val_str = insn.operands_text.substr(comma + 1);
					while (!val_str.empty() && val_str.front() == ' ') val_str.erase(val_str.begin());
					uint64_t val = std::strtoull(val_str.c_str(), nullptr, 0);
					if (val != 0) {
						out_state_var.concrete_values.push_back(val);
					}
				}
			}
		}
	}

	return true;
}

inline void resolve_state_targets(triton::Context& ctx_template,
								  state_variable_t& state_var,
								  const std::vector<block_range_t>& blocks,
								  uint64_t dispatcher_addr) {
	state_var.dispatcher_addr = dispatcher_addr;

	auto reg_id = symbolic_engine::detail::name_to_triton_reg(state_var.register_name);
	if (reg_id == triton::arch::ID_REG_INVALID) return;

	for (auto state_val : state_var.concrete_values) {
		triton::Context ctx(triton::arch::ARCH_X86_64);
		ctx.setMode(triton::modes::ALIGNED_MEMORY, true);

		auto& reg = ctx.getRegister(reg_id);
		ctx.setConcreteRegisterValue(reg, state_val);

		uint64_t pc = dispatcher_addr;
		uint32_t steps = 0;
		uint64_t last_non_dispatcher = 0;

		while (steps < 50) {
			auto code = emulation::driver_read_bytes(pc, 16);
			if (code.empty()) break;

			triton::arch::Instruction insn;
			insn.setOpcode(code.data(), static_cast<triton::uint32>(code.size()));
			insn.setAddress(pc);

			auto exc = ctx.processing(insn);
			if (exc != triton::arch::NO_FAULT) break;

			pc = static_cast<uint64_t>(ctx.getConcreteRegisterValue(ctx.getRegister("rip")));

			bool in_dispatcher = false;
			for (auto& block : blocks) {
				if (pc >= block.start && pc < block.end) {
					bool has_many_succs = (block.successor_indices.size() > 2);
					if (has_many_succs) in_dispatcher = true;
					break;
				}
			}

			if (!in_dispatcher && pc != dispatcher_addr) {
				last_non_dispatcher = pc;
				break;
			}

			++steps;
		}

		if (last_non_dispatcher != 0) {
			state_var.state_to_target[state_val] = last_non_dispatcher;
		}
	}
}

inline std::vector<clean_instruction_t> strip_junk_from_block(
	triton::Context& ctx,
	const block_range_t& block,
	const std::unordered_set<triton::arch::register_e>& live_out_regs) {

	std::vector<std::pair<triton::arch::Instruction, clean_instruction_t>> processed;

	for (auto& raw_insn : block.insns) {
		auto code = emulation::driver_read_bytes(raw_insn.address, raw_insn.length);
		if (code.empty()) continue;

		triton::arch::Instruction insn;
		insn.setOpcode(code.data(), static_cast<triton::uint32>(code.size()));
		insn.setAddress(raw_insn.address);

		ctx.processing(insn);

		clean_instruction_t ci;
		ci.address = raw_insn.address;
		ci.size = raw_insn.length;
		ci.disasm = raw_insn.mnemonic + " " + raw_insn.operands_text;
		processed.push_back({insn, ci});
	}

	std::unordered_set<triton::arch::register_e> live = live_out_regs;
	std::unordered_set<uint64_t> live_mem;

	for (auto it = processed.rbegin(); it != processed.rend(); ++it) {
		auto& [insn, ci] = *it;

		if (insn.isBranch() || insn.isControlFlow()) continue;

		bool needed = false;
		for (auto& [reg, _] : insn.getWrittenRegisters()) {
			if (live.count(ctx.getParentRegister(reg).getId())) {
				needed = true;
				break;
			}
		}

		if (!needed) {
			for (auto& [mem, _] : insn.getStoreAccess()) {
				uint64_t addr = static_cast<uint64_t>(mem.getAddress());
				for (uint64_t i = 0; i < mem.getSize(); ++i) {
					if (live_mem.count(addr + i)) {
						needed = true;
						break;
					}
				}
				if (needed) break;
			}
		}

		if (!needed) {
			ci.was_junk = true;
		} else {
			std::unordered_set<triton::arch::register_e> read_parents;
			for (auto& [reg, _] : insn.getReadRegisters()) {
				read_parents.insert(ctx.getParentRegister(reg).getId());
			}
			for (auto& [reg, _] : insn.getWrittenRegisters()) {
				auto parent_id = ctx.getParentRegister(reg).getId();
				if (!read_parents.count(parent_id)) {
					auto it_live = live.find(parent_id);
					if (it_live != live.end()) live.erase(it_live);
				}
			}
			for (auto& parent_id : read_parents) {
				live.insert(parent_id);
			}
			std::unordered_set<uint64_t> read_mem_addrs;
			for (auto& [mem, _] : insn.getLoadAccess()) {
				uint64_t addr = static_cast<uint64_t>(mem.getAddress());
				for (uint64_t i = 0; i < mem.getSize(); ++i) {
					read_mem_addrs.insert(addr + i);
				}
			}
			for (auto& [mem, _] : insn.getStoreAccess()) {
				uint64_t addr = static_cast<uint64_t>(mem.getAddress());
				for (uint64_t i = 0; i < mem.getSize(); ++i) {
					if (!read_mem_addrs.count(addr + i)) {
						auto it_lm = live_mem.find(addr + i);
						if (it_lm != live_mem.end()) live_mem.erase(it_lm);
					}
				}
			}
			for (auto addr : read_mem_addrs) {
				live_mem.insert(addr);
			}
		}
	}

	std::vector<clean_instruction_t> result;
	for (auto& [insn, ci] : processed) {
		result.push_back(std::move(ci));
	}
	return result;
}

}

inline deobfuscated_result_t deobfuscate_function(uint64_t entry_addr, uint32_t max_instructions = 50000) {
	deobfuscated_result_t result;

	if (!device || !device->is_connected() || device->get_process_id() == 0) {
		result.error = "Driver not connected or no process attached";
		diag::log_tagged_fmt("deobf",
			"engine_reject reason=no_attach entry=0x%llX",
			static_cast<unsigned long long>(entry_addr));
		return result;
	}

	g_state.progress_current.store(0);
	g_state.progress_total.store(5);

	auto blocks = detail::recover_cfg_blocks(entry_addr);
	if (blocks.empty()) {
		result.error = "Failed to recover CFG blocks";
		diag::log_tagged_fmt("deobf",
			"engine_reject reason=cfg_recovery_failed entry=0x%llX",
			static_cast<unsigned long long>(entry_addr));
		return result;
	}

	diag::log_tagged_fmt("deobf",
		"engine_cfg_recovered entry=0x%llX blocks=%zu",
		static_cast<unsigned long long>(entry_addr), blocks.size());

	g_state.progress_current.store(1);

	triton::Context ctx(triton::arch::ARCH_X86_64);
	ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
	ctx.setMode(triton::modes::TAINT_THROUGH_POINTERS, true);
	ctx.setSolverTimeout(5000);

	uint32_t pid = device->get_process_id();
	auto threads = device->enumerate_threads();
	uint32_t tid = 0;
	if (!threads.empty()) tid = threads[0].tid;

	auto snapshot = emulation::driver_snapshot(pid, tid, entry_addr, 0x1000);
	if (!snapshot.success) {
		result.error = "Failed to take process snapshot";
		return result;
	}

	symbolic_engine::detail::load_snapshot_into_context(ctx, snapshot);

	g_state.progress_current.store(2);

	state_variable_t state_var;
	bool is_state_machine = detail::detect_state_machine(ctx, blocks, state_var);

	if (is_state_machine) {
		detail::resolve_state_targets(ctx, state_var, blocks, entry_addr);
		result.state_vars.push_back(state_var);
		result.dispatcher_states_resolved = static_cast<uint32_t>(state_var.state_to_target.size());
	}

	g_state.progress_current.store(3);

	std::unordered_set<triton::arch::register_e> live_out = {
		triton::arch::ID_REG_X86_RAX,
		triton::arch::ID_REG_X86_RCX,
		triton::arch::ID_REG_X86_RDX,
		triton::arch::ID_REG_X86_R8,
		triton::arch::ID_REG_X86_R9,
		triton::arch::ID_REG_X86_RSP,
		triton::arch::ID_REG_X86_RBP,
	};

	for (size_t bi = 0; bi < blocks.size(); ++bi) {
		auto& block = blocks[bi];

		triton::Context block_ctx(triton::arch::ARCH_X86_64);
		block_ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
		symbolic_engine::detail::load_snapshot_into_context(block_ctx, snapshot);

		auto clean_insns = detail::strip_junk_from_block(block_ctx, block, live_out);

		clean_block_t cblock;
		cblock.start_addr = block.start;
		cblock.end_addr = block.end;
		cblock.is_entry = block.is_entry;
		cblock.successors = block.successor_indices;

		for (auto& ci : clean_insns) {
			if (!ci.was_junk) {
				cblock.instructions.push_back(ci);
				result.clean_instructions.push_back(ci);
			} else {
				++result.removed_junk;
			}
			++result.total_original;
		}

		result.clean_blocks.push_back(std::move(cblock));
	}

	g_state.progress_current.store(4);

	uint64_t symbolic_end = 0;
	for (const auto& block : blocks) {
		if (block.end > symbolic_end)
			symbolic_end = block.end;
	}
	auto sym_result = symbolic_engine::execute_symbolic(entry_addr, symbolic_end, max_instructions, {}, {});
	if (sym_result.success) {
		result.opaques = sym_result.opaque_predicates;
		result.constants = sym_result.constants_resolved;
		result.opaque_predicates_found = sym_result.opaque_count;
		result.constants_resolved = sym_result.constants_count;
	}

	std::unordered_set<uint64_t> opaque_addr_set;
	for (auto& op : result.opaques) opaque_addr_set.insert(op.address);
	std::unordered_set<uint64_t> const_addr_set;
	for (auto& cf : result.constants) const_addr_set.insert(cf.address);

	auto annotate_ci = [&](clean_instruction_t& ci) {
		if (opaque_addr_set.count(ci.address)) ci.was_opaque = true;
		if (const_addr_set.count(ci.address)) ci.was_constant_folded = true;
	};
	for (auto& blk : result.clean_blocks) {
		for (auto& ci : blk.instructions) annotate_ci(ci);
	}
	for (auto& ci : result.clean_instructions) annotate_ci(ci);

	for (size_t bi = 0; bi < result.clean_blocks.size(); ++bi) {
		for (auto succ_idx : result.clean_blocks[bi].successors) {
			cfg_edge_t edge;
			edge.from_block = static_cast<int>(bi);
			edge.to_block = succ_idx;

			for (auto& op : result.opaques) {
				if (!result.clean_blocks[bi].instructions.empty()) {
					auto& last = result.clean_blocks[bi].instructions.back();
					if (last.address == op.address) {
						edge.is_fake = true;
						edge.label = "opaque";
						break;
					}
				}
			}
			result.clean_edges.push_back(edge);
		}
	}

	result.total_clean = static_cast<uint32_t>(result.clean_instructions.size());
	if (result.total_original > 0) {
		result.junk_ratio = static_cast<float>(result.removed_junk) / static_cast<float>(result.total_original);
	}

	g_state.progress_current.store(5);
	result.success = true;
	return result;
}

inline deobfuscated_result_t strip_junk_code(
	uint64_t start_addr,
	uint64_t end_addr,
	const std::vector<std::string>& target_regs,
	uint32_t max_instructions = 512) {

	deobfuscated_result_t result;

	uint32_t work_budget = max_instructions ? max_instructions : 1u;
	if (end_addr > start_addr) {
		const uint64_t span = end_addr - start_addr;
		if (span < work_budget)
			work_budget = static_cast<uint32_t>((std::max<uint64_t>)(1, span));
	}

	auto slice = symbolic_engine::slice_to_register(start_addr, end_addr, work_budget,
		target_regs.empty() ? "rax" : target_regs[0]);

	if (!slice.success) {
		result.error = slice.error;
		return result;
	}

	for (auto& insn : slice.effective_instructions) {
		clean_instruction_t ci;
		ci.address = insn.address;
		ci.size = insn.size;
		ci.disasm = insn.disasm;
		ci.was_junk = false;
		result.clean_instructions.push_back(std::move(ci));
	}

	result.total_original = slice.total_instructions;
	result.total_clean = slice.effective_count;
	result.removed_junk = slice.removed_count;
	if (result.total_original > 0) {
		result.junk_ratio = static_cast<float>(result.removed_junk) / static_cast<float>(result.total_original);
	}

	result.success = true;
	return result;
}

inline std::vector<symbolic_engine::constant_fold_t> resolve_constants(
	uint64_t start_addr,
	uint64_t end_addr,
	uint32_t max_instructions) {

	auto sym = symbolic_engine::execute_symbolic(start_addr, end_addr, max_instructions, {}, {});
	return sym.constants_resolved;
}

inline std::string export_clean_asm(const deobfuscated_result_t& result) {
	std::string out;
	for (auto& ci : result.clean_instructions) {
		if (ci.was_junk) continue;
		char buf[32];
		std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(ci.address));
		out += buf;
		out += "  ";
		out += ci.disasm;
		out += "\n";
	}
	return out;
}

inline std::string export_statistics(const deobfuscated_result_t& result) {
	std::string out;
	out += "Deobfuscation Statistics\n";
	out += "========================\n";
	char buf[256];
	std::snprintf(buf, sizeof(buf), "Total original instructions: %u\n", result.total_original);
	out += buf;
	std::snprintf(buf, sizeof(buf), "Clean instructions:          %u\n", result.total_clean);
	out += buf;
	std::snprintf(buf, sizeof(buf), "Removed junk:                %u (%.1f%%)\n",
		result.removed_junk, result.junk_ratio * 100.0f);
	out += buf;
	std::snprintf(buf, sizeof(buf), "Opaque predicates found:     %u\n", result.opaque_predicates_found);
	out += buf;
	std::snprintf(buf, sizeof(buf), "Constants resolved:          %u\n", result.constants_resolved);
	out += buf;
	std::snprintf(buf, sizeof(buf), "Dispatcher states resolved:  %u\n", result.dispatcher_states_resolved);
	out += buf;
	return out;
}

}
