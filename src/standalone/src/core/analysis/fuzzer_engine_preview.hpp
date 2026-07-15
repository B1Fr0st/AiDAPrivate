#pragma once

#include "../../preview/re_hubs_preview_adapter.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace fuzzer_engine {

enum class mutation_strategy_t : int { bit_flip, byte_flip, arithmetic, interesting_values, havoc, splice, COUNT };
enum class crash_type_t : int { none, access_violation, invalid_instruction, division_by_zero, stack_overflow, timeout, assertion };
enum class exploit_score_t : int { unknown, low, medium, high, critical };

struct mutation_t {
	mutation_strategy_t strategy = mutation_strategy_t::bit_flip;
	size_t offset = 0;
	size_t size = 0;
	std::vector<uint8_t> original;
	std::vector<uint8_t> mutated;
};

struct crash_info_t {
	crash_type_t type = crash_type_t::none;
	exploit_score_t score = exploit_score_t::unknown;
	uint64_t fault_address = 0;
	uint64_t instruction_address = 0;
	uint64_t crash_hash = 0;
	std::string description;
	std::string crashing_instruction;
	std::vector<uint8_t> input;
	mutation_t mutation;
	uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
	uint64_t rsp = 0, rbp = 0, rsi = 0, rdi = 0;
	uint64_t rip = 0;
	uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
	uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
	std::string ai_analysis;
	std::vector<uint8_t> minimized_input;
	bool is_minimized = false;
};

struct coverage_info_t {
	uint8_t bitmap[65536] = {};
	uint32_t edge_count = 0;
	uint32_t total_edges_discovered = 0;
	uint64_t prev_block = 0;
};

struct corpus_entry_t {
	std::vector<uint8_t> data;
	uint32_t edge_hits = 0;
	uint32_t new_coverage = 0;
	std::string source;
	float energy = 1.f;
	uint64_t exec_us = 0;
};

struct fuzz_config_t {
	uint64_t target_address = 0x140001000;
	uint64_t end_address = 0x140001180;
	uint32_t max_instructions = 100000;
	uint32_t timeout_ms = 5000;
	uint32_t max_iterations = 10000;
	int input_size = 256;
	int mutation_count = 4;
	bool strategies[static_cast<int>(mutation_strategy_t::COUNT)] = {true, true, true, true, true, false};
	uint32_t pid = 4242;
	uint32_t tid = 7331;
	uint64_t input_address = 0x7FF6A0123000;
};

struct fuzz_stats_t {
	uint64_t total_executions = 0;
	uint64_t total_crashes = 0;
	uint64_t total_unique_crashes = 0;
	uint64_t new_coverage_finds = 0;
	uint64_t executions_per_second = 0;
	double elapsed_seconds = 0.0;
	uint32_t corpus_size = 0;
	uint32_t edge_coverage = 0;
	std::vector<uint64_t> exec_rate_history;
};

inline crash_info_t preview_crash(crash_type_t type, exploit_score_t score, uint64_t rip,
	mutation_strategy_t strategy, const char* detail)
{
	crash_info_t crash;
	crash.type = type;
	crash.score = score;
	crash.fault_address = type == crash_type_t::access_violation ? 0x4141414141414141 : rip;
	crash.instruction_address = rip;
	crash.rip = rip;
	crash.rsp = 0x0000007FFDEFF4C0;
	crash.rbp = 0x0000007FFDEFF550;
	crash.rax = 0x4141414141414141;
	crash.rcx = 0x7FF6A0123000;
	crash.description = detail;
	crash.crashing_instruction = "mov qword ptr [rax], rcx";
	crash.input = {0x41, 0x41, 0x41, 0x41, 0x00, 0xFF, 0x7F, 0x10};
	crash.mutation.strategy = strategy;
	crash.mutation.offset = 4;
	crash.mutation.size = 4;
	crash.mutation.original = {0x10, 0x00, 0x00, 0x00};
	crash.mutation.mutated = {0xFF, 0xFF, 0xFF, 0x7F};
	crash.crash_hash = rip ^ (static_cast<uint64_t>(type) << 56);
	return crash;
}

struct state_t {
	fuzz_config_t config;
	fuzz_stats_t stats;
	coverage_info_t coverage;
	std::vector<corpus_entry_t> corpus;
	std::vector<crash_info_t> crashes;
	std::vector<crash_info_t> unique_crashes;
	std::set<uint64_t> crash_hashes;
	std::string setup_error;
	std::mutex mutex;
	std::atomic<bool> running{false};
	std::atomic<bool> cancel{false};
	std::atomic<bool> minimizing{false};
	std::atomic<bool> analyzing_crash{false};
	std::atomic<bool> worker_active{false};
	std::atomic<bool> setup_complete{true};
	std::atomic<bool> setup_success{true};
	bool active = true;
	char addr_input[32] = "140001000";
	char end_addr_input[32] = "140001180";
	char input_addr[32] = "7FF6A0123000";
	char input_size_str[16] = "256";
	char max_iter_str[16] = "10000";

	state_t()
	{
		stats.total_executions = 184732;
		stats.total_crashes = 7;
		stats.total_unique_crashes = 3;
		stats.new_coverage_finds = 214;
		stats.executions_per_second = 12840;
		stats.elapsed_seconds = 14.38;
		stats.corpus_size = 41;
		stats.edge_coverage = 2376;
		stats.exec_rate_history = {8200, 9400, 11200, 10800, 12100, 12640, 12840};
		coverage.edge_count = stats.edge_coverage;
		coverage.total_edges_discovered = stats.edge_coverage;
		unique_crashes = {
			preview_crash(crash_type_t::access_violation, exploit_score_t::critical, 0x1400010F4,
				mutation_strategy_t::havoc, "Write access violation with attacker-controlled destination"),
			preview_crash(crash_type_t::invalid_instruction, exploit_score_t::medium, 0x140001132,
				mutation_strategy_t::bit_flip, "Execution reached an invalid opcode after parser state corruption"),
			preview_crash(crash_type_t::division_by_zero, exploit_score_t::low, 0x140001086,
				mutation_strategy_t::arithmetic, "Arithmetic mutation produced a zero divisor")
		};
		crashes = unique_crashes;
		for (const auto& crash : unique_crashes) crash_hashes.insert(crash.crash_hash);
		corpus.push_back({{0x41, 0x49, 0x44, 0x41}, 821, 17, "seed", 1.4f, 76});
	}
};

inline state_t g_state;

inline const char* strategy_name(mutation_strategy_t strategy)
{
	switch (strategy) {
	case mutation_strategy_t::bit_flip: return "Bit Flip";
	case mutation_strategy_t::byte_flip: return "Byte Flip";
	case mutation_strategy_t::arithmetic: return "Arithmetic";
	case mutation_strategy_t::interesting_values: return "Interesting";
	case mutation_strategy_t::havoc: return "Havoc";
	case mutation_strategy_t::splice: return "Splice";
	default: return "Unknown";
	}
}

inline const char* crash_type_name(crash_type_t type)
{
	switch (type) {
	case crash_type_t::access_violation: return "Access Violation";
	case crash_type_t::invalid_instruction: return "Invalid Instruction";
	case crash_type_t::division_by_zero: return "Division by Zero";
	case crash_type_t::stack_overflow: return "Stack Overflow";
	case crash_type_t::timeout: return "Timeout";
	case crash_type_t::assertion: return "Assertion";
	default: return "None";
	}
}

inline const char* exploit_score_name(exploit_score_t score)
{
	switch (score) {
	case exploit_score_t::critical: return "CRITICAL";
	case exploit_score_t::high: return "HIGH";
	case exploit_score_t::medium: return "MEDIUM";
	case exploit_score_t::low: return "LOW";
	default: return "UNKNOWN";
	}
}

inline bool start_fuzzing()
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.running.store(false);
	g_state.active = true;
	g_state.setup_complete.store(true);
	g_state.setup_success.store(true);
	g_state.stats.total_executions += 25000;
	g_state.stats.executions_per_second = 13120;
	g_state.stats.exec_rate_history.push_back(g_state.stats.executions_per_second);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::analysis, 3, "fuzzer.run", "deterministic corpus pass complete");
	return true;
}

inline void stop_fuzzing()
{
	g_state.cancel.store(true);
	g_state.running.store(false);
	g_state.worker_active.store(false);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::analysis, 3, "fuzzer.stop");
}

inline bool wait_until_idle(uint32_t)
{
	return !g_state.running.load() && !g_state.worker_active.load() &&
		!g_state.minimizing.load() && !g_state.analyzing_crash.load();
}

inline bool reset_state()
{
	if (g_state.running.load() || g_state.minimizing.load() || g_state.analyzing_crash.load()) return false;
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.stats = {};
	g_state.coverage = {};
	g_state.corpus.clear();
	g_state.crashes.clear();
	g_state.unique_crashes.clear();
	g_state.crash_hashes.clear();
	g_state.active = false;
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::analysis, 3, "fuzzer.reset");
	return true;
}

inline void ai_analyze_crash(int crash_index)
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	if (crash_index < 0 || crash_index >= static_cast<int>(g_state.unique_crashes.size())) return;
	g_state.unique_crashes[static_cast<std::size_t>(crash_index)].ai_analysis =
		"Controlled pointer propagation reaches the faulting write. Reproduce with page-heap and inspect the parser length field before triage.";
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::analysis, 3, "fuzzer.analyze");
}

inline void minimize_crash(int crash_index)
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	if (crash_index < 0 || crash_index >= static_cast<int>(g_state.unique_crashes.size())) return;
	auto& crash = g_state.unique_crashes[static_cast<std::size_t>(crash_index)];
	crash.minimized_input = {0x41, 0x41, 0xFF, 0x7F};
	crash.is_minimized = true;
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::analysis, 3, "fuzzer.minimize");
}

inline void export_crashes()
{
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::analysis, 3, "fuzzer.export", "3 crash records prepared");
}

inline void import_crashes()
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	if (g_state.unique_crashes.empty()) {
		g_state.unique_crashes = {
			preview_crash(crash_type_t::access_violation, exploit_score_t::critical, 0x1400010F4,
				mutation_strategy_t::havoc, "Write access violation with attacker-controlled destination"),
			preview_crash(crash_type_t::invalid_instruction, exploit_score_t::medium, 0x140001132,
				mutation_strategy_t::bit_flip, "Execution reached an invalid opcode after parser state corruption"),
			preview_crash(crash_type_t::division_by_zero, exploit_score_t::low, 0x140001086,
				mutation_strategy_t::arithmetic, "Arithmetic mutation produced a zero divisor")
		};
		g_state.crashes = g_state.unique_crashes;
		g_state.stats.total_crashes = 7;
		g_state.stats.total_unique_crashes = 3;
		for (const auto& crash : g_state.unique_crashes) g_state.crash_hashes.insert(crash.crash_hash);
		g_state.active = true;
	}
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::analysis, 3, "fuzzer.import", "fixture crash corpus restored");
}

}
