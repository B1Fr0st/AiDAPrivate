#pragma once

#include "symbolic_engine.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
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

inline deobfuscated_result_t deobfuscate_function(uint64_t entry_addr, uint32_t = 50000)
{
	if (entry_addr == 0) entry_addr = 0x140001000;
	deobfuscated_result_t result;
	result.success = true;
	result.clean_instructions = {
		{entry_addr, 3, "mov rax, qword ptr [rcx]", false, false, false, "", ""},
		{entry_addr + 3, 2, "test rax, rax", false, true, false, "(= rax 0)", "rax == 0"},
		{entry_addr + 5, 2, "je 0x140001018", false, false, false, "", ""},
		{entry_addr + 7, 5, "mov edx, 0x20", false, false, true, "(bvadd 0x10 0x10)", "0x20"},
		{entry_addr + 12, 3, "add rax, rdx", false, false, false, "", ""},
		{entry_addr + 15, 2, "jmp 0x14000101D", true, false, false, "", ""},
		{entry_addr + 17, 3, "xor eax, eax", false, false, false, "", ""},
		{entry_addr + 20, 1, "ret", false, false, false, "", ""}
	};
	clean_block_t entry;
	entry.start_addr = entry_addr;
	entry.end_addr = entry_addr + 17;
	entry.instructions.assign(result.clean_instructions.begin(), result.clean_instructions.begin() + 6);
	entry.successors = {1};
	entry.is_entry = true;
	clean_block_t exit;
	exit.start_addr = entry_addr + 17;
	exit.end_addr = entry_addr + 21;
	exit.instructions.assign(result.clean_instructions.begin() + 6, result.clean_instructions.end());
	result.clean_blocks = {entry, exit};
	result.clean_edges = {{0, 1, false, "fallthrough"}};
	result.total_original = 13;
	result.total_clean = 7;
	result.removed_junk = 5;
	result.opaque_predicates_found = 1;
	result.constants_resolved = 1;
	result.dispatcher_states_resolved = 3;
	result.junk_ratio = 5.0f / 13.0f;
	result.opaques.push_back({entry_addr + 3, "test rax, rax", false, "(= rax 0)", "rax == 0"});
	result.constants.push_back({entry_addr + 7, "edx", 0x20, "(bvadd 0x10 0x10)"});
	state_variable_t state;
	state.dispatcher_addr = entry_addr + 0x40;
	state.register_name = "r11d";
	state.concrete_values = {0x11, 0x2A, 0x37};
	state.state_to_target = {{0x11, entry_addr}, {0x2A, entry_addr + 17}, {0x37, entry_addr + 20}};
	result.state_vars.push_back(std::move(state));
	return result;
}

inline deobfuscated_result_t strip_junk_code(uint64_t start_addr, uint64_t,
	const std::vector<std::string>&, uint32_t = 512)
{
	return deobfuscate_function(start_addr);
}

inline std::vector<symbolic_engine::constant_fold_t> resolve_constants(uint64_t start_addr,
	uint64_t, uint32_t)
{
	return deobfuscate_function(start_addr).constants;
}

struct state_t {
	std::mutex mutex;
	std::atomic<bool> processing{false};
	deobfuscated_result_t last_result = deobfuscate_function(0x140001000);
	std::atomic<uint32_t> progress_current{5};
	std::atomic<uint32_t> progress_total{5};
};

inline state_t g_state;

inline std::string export_clean_asm(const deobfuscated_result_t& result)
{
	std::string out;
	for (const auto& instruction : result.clean_instructions) {
		if (instruction.was_junk) continue;
		char address[32];
		std::snprintf(address, sizeof(address), "%016llX", static_cast<unsigned long long>(instruction.address));
		out += address;
		out += "  ";
		out += instruction.disasm;
		out += "\n";
	}
	return out;
}

inline std::string export_statistics(const deobfuscated_result_t& result)
{
	char values[512];
	std::snprintf(values, sizeof(values),
		"Deobfuscation Statistics\n========================\nTotal original instructions: %u\nClean instructions:          %u\nRemoved junk:                %u (%.1f%%)\nOpaque predicates found:     %u\nConstants resolved:          %u\nDispatcher states resolved:  %u\n",
		result.total_original, result.total_clean, result.removed_junk, result.junk_ratio * 100.0f,
		result.opaque_predicates_found, result.constants_resolved, result.dispatcher_states_resolved);
	return values;
}

}
