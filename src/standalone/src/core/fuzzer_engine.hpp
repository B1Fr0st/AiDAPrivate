#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#ifdef __NT__
#include "../../../emulation_engine.hpp"
#endif

namespace fuzzer_engine {

enum class mutation_strategy_t : int {
	bit_flip = 0,
	byte_flip,
	arithmetic,
	interesting_values,
	havoc,
	splice,
	COUNT
};

enum class crash_type_t : int {
	none = 0,
	access_violation,
	invalid_instruction,
	division_by_zero,
	stack_overflow,
	timeout,
	assertion,
};

struct mutation_t {
	mutation_strategy_t strategy;
	size_t              offset = 0;
	size_t              size = 0;
	std::vector<uint8_t> original;
	std::vector<uint8_t> mutated;
};

struct crash_info_t {
	crash_type_t type = crash_type_t::none;
	uint64_t     fault_address = 0;
	uint64_t     instruction_address = 0;
	std::string  description;
	std::vector<uint8_t> input;
	mutation_t   mutation;
	uint64_t     rax = 0, rbx = 0, rcx = 0, rdx = 0;
	uint64_t     rsp = 0, rbp = 0, rsi = 0, rdi = 0;
	uint64_t     rip = 0;
};

struct coverage_info_t {
	uint8_t  bitmap[65536] = {};
	uint32_t edge_count = 0;
	uint32_t total_edges_discovered = 0;
	uint64_t prev_block = 0;
};

struct corpus_entry_t {
	std::vector<uint8_t>   data;
	uint32_t               edge_hits = 0;
	uint32_t               new_coverage = 0;
	std::string            source;
};

struct fuzz_config_t {
	uint64_t  target_address = 0;
	uint64_t  end_address = 0;
	uint32_t  max_instructions = 100000;
	uint32_t  timeout_ms = 5000;
	uint32_t  max_iterations = 100000;
	int       input_size = 256;
	int       mutation_count = 4;
	bool      strategies[static_cast<int>(mutation_strategy_t::COUNT)] = {true, true, true, true, true, false};
	uint32_t  pid = 0;
	uint32_t  tid = 0;
	uint64_t  input_address = 0;
};

struct fuzz_stats_t {
	uint64_t total_executions = 0;
	uint64_t total_crashes = 0;
	uint64_t total_unique_crashes = 0;
	uint64_t new_coverage_finds = 0;
	uint64_t executions_per_second = 0;
	double   elapsed_seconds = 0.0;
	uint32_t corpus_size = 0;
	uint32_t edge_coverage = 0;
	std::vector<uint64_t> exec_rate_history;
};

struct state_t {
	fuzz_config_t  config;
	fuzz_stats_t   stats;
	coverage_info_t coverage;

	std::vector<corpus_entry_t> corpus;
	std::vector<crash_info_t>   crashes;
	std::vector<crash_info_t>   unique_crashes;

	std::mutex      mutex;
	std::atomic<bool> running{false};
	std::atomic<bool> cancel{false};
	bool            active = false;

	char addr_input[32] = {};
	char end_addr_input[32] = {};
	char input_addr[32] = {};
	char input_size_str[16] = "256";
	char max_iter_str[16] = "10000";
};

inline state_t g_state;

namespace detail {

static constexpr int32_t interesting_8[]  = {0, 1, -1, 16, 32, 64, 100, 127, -128};
static constexpr int32_t interesting_16[] = {0, 1, -1, 128, 255, 256, 512, 1000, 1024, 4096, 32767, -32768, 65535};
static constexpr int32_t interesting_32[] = {0, 1, -1, 256, 65535, 65536, 100000, 0x7FFFFFFF, -2147483647 - 1};

inline void mutate_havoc(std::vector<uint8_t>& data, std::mt19937& rng, mutation_t& mut);

inline void mutate_bit_flip(std::vector<uint8_t>& data, std::mt19937& rng, mutation_t& mut)
{
	if (data.empty()) return;
	std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 1);
	std::uniform_int_distribution<int> bit_dist(0, 7);
	size_t pos = pos_dist(rng);
	int bit = bit_dist(rng);

	mut.strategy = mutation_strategy_t::bit_flip;
	mut.offset = pos;
	mut.size = 1;
	mut.original = {data[pos]};

	data[pos] ^= (1u << bit);

	mut.mutated = {data[pos]};
}

inline void mutate_byte_flip(std::vector<uint8_t>& data, std::mt19937& rng, mutation_t& mut)
{
	if (data.empty()) return;
	std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 1);
	size_t pos = pos_dist(rng);

	mut.strategy = mutation_strategy_t::byte_flip;
	mut.offset = pos;
	mut.size = 1;
	mut.original = {data[pos]};

	data[pos] ^= 0xFF;

	mut.mutated = {data[pos]};
}

inline void mutate_arithmetic(std::vector<uint8_t>& data, std::mt19937& rng, mutation_t& mut)
{
	if (data.empty()) return;
	std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 1);
	std::uniform_int_distribution<int> delta_dist(-35, 35);
	size_t pos = pos_dist(rng);

	mut.strategy = mutation_strategy_t::arithmetic;
	mut.offset = pos;
	mut.size = 1;
	mut.original = {data[pos]};

	int delta = delta_dist(rng);
	if (delta == 0) delta = 1;
	data[pos] = static_cast<uint8_t>(data[pos] + delta);

	mut.mutated = {data[pos]};
}

inline void mutate_interesting(std::vector<uint8_t>& data, std::mt19937& rng, mutation_t& mut)
{
	if (data.empty()) return;
	std::uniform_int_distribution<int> width_dist(0, 2);
	int width = width_dist(rng);

	mut.strategy = mutation_strategy_t::interesting_values;

	if (width == 0 && data.size() >= 1) {
		std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 1);
		std::uniform_int_distribution<int> val_dist(0, static_cast<int>(std::size(interesting_8)) - 1);
		size_t pos = pos_dist(rng);
		mut.offset = pos;
		mut.size = 1;
		mut.original = {data[pos]};
		data[pos] = static_cast<uint8_t>(interesting_8[val_dist(rng)]);
		mut.mutated = {data[pos]};
	} else if (width == 1 && data.size() >= 2) {
		std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 2);
		std::uniform_int_distribution<int> val_dist(0, static_cast<int>(std::size(interesting_16)) - 1);
		size_t pos = pos_dist(rng);
		mut.offset = pos;
		mut.size = 2;
		mut.original.assign(data.begin() + pos, data.begin() + pos + 2);
		int16_t val = static_cast<int16_t>(interesting_16[val_dist(rng)]);
		std::memcpy(data.data() + pos, &val, 2);
		mut.mutated.assign(data.begin() + pos, data.begin() + pos + 2);
	} else if (data.size() >= 4) {
		std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 4);
		std::uniform_int_distribution<int> val_dist(0, static_cast<int>(std::size(interesting_32)) - 1);
		size_t pos = pos_dist(rng);
		mut.offset = pos;
		mut.size = 4;
		mut.original.assign(data.begin() + pos, data.begin() + pos + 4);
		int32_t val = interesting_32[val_dist(rng)];
		std::memcpy(data.data() + pos, &val, 4);
		mut.mutated.assign(data.begin() + pos, data.begin() + pos + 4);
	}
}

inline void mutate_splice(std::vector<uint8_t>& data, std::mt19937& rng, mutation_t& mut)
{
	mut.strategy = mutation_strategy_t::splice;

	auto& corpus = g_state.corpus;
	if (corpus.size() < 2 || data.empty()) {
		mutate_havoc(data, rng, mut);
		mut.strategy = mutation_strategy_t::splice;
		return;
	}

	std::uniform_int_distribution<size_t> corpus_dist(0, corpus.size() - 1);
	size_t donor_idx = corpus_dist(rng);
	auto& donor = corpus[donor_idx].data;
	if (donor.empty()) {
		mutate_havoc(data, rng, mut);
		mut.strategy = mutation_strategy_t::splice;
		return;
	}

	size_t min_len = (std::min)(data.size(), donor.size());
	std::uniform_int_distribution<size_t> split_dist(1, min_len > 1 ? min_len - 1 : 1);
	size_t split_point = split_dist(rng);

	mut.offset = split_point;
	mut.size = data.size() - split_point;
	mut.original.assign(data.begin() + static_cast<ptrdiff_t>(split_point), data.end());

	for (size_t i = split_point; i < data.size() && i < donor.size(); ++i) {
		data[i] = donor[i];
	}

	mut.mutated.assign(data.begin() + static_cast<ptrdiff_t>(split_point), data.end());

	std::uniform_int_distribution<int> extra_dist(0, 1);
	if (extra_dist(rng) == 1) {
		mutation_t extra;
		mutate_bit_flip(data, rng, extra);
	}
}

inline void mutate_havoc(std::vector<uint8_t>& data, std::mt19937& rng, mutation_t& mut)
{
	std::uniform_int_distribution<int> op_dist(0, 5);
	int op = op_dist(rng);

	switch (op) {
	case 0: mutate_bit_flip(data, rng, mut); mut.strategy = mutation_strategy_t::havoc; break;
	case 1: mutate_byte_flip(data, rng, mut); mut.strategy = mutation_strategy_t::havoc; break;
	case 2: mutate_arithmetic(data, rng, mut); mut.strategy = mutation_strategy_t::havoc; break;
	case 3: mutate_interesting(data, rng, mut); mut.strategy = mutation_strategy_t::havoc; break;
	case 4: {
		if (data.size() >= 4) {
			std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 4);
			size_t pos = pos_dist(rng);
			std::uniform_int_distribution<size_t> src_dist(0, data.size() - 4);
			size_t src = src_dist(rng);
			mut.strategy = mutation_strategy_t::havoc;
			mut.offset = pos;
			mut.size = 4;
			mut.original.assign(data.begin() + pos, data.begin() + pos + 4);
			std::memcpy(data.data() + pos, data.data() + src, 4);
			mut.mutated.assign(data.begin() + pos, data.begin() + pos + 4);
		}
		break;
	}
	case 5: {
		if (data.size() > 1) {
			std::uniform_int_distribution<size_t> pos_dist(0, data.size() - 1);
			size_t pos = pos_dist(rng);
			std::uniform_int_distribution<uint8_t> val_dist(0, 255);
			mut.strategy = mutation_strategy_t::havoc;
			mut.offset = pos;
			mut.size = 1;
			mut.original = {data[pos]};
			data[pos] = val_dist(rng);
			mut.mutated = {data[pos]};
		}
		break;
	}
	}
}

inline mutation_t apply_mutation(std::vector<uint8_t>& data, std::mt19937& rng,
                                  const bool strategies[static_cast<int>(mutation_strategy_t::COUNT)])
{
	std::vector<int> enabled;
	for (int i = 0; i < static_cast<int>(mutation_strategy_t::COUNT); ++i) {
		if (strategies[i]) enabled.push_back(i);
	}
	if (enabled.empty()) enabled.push_back(0);

	std::uniform_int_distribution<size_t> strat_dist(0, enabled.size() - 1);
	int chosen = enabled[strat_dist(rng)];

	mutation_t mut;
	switch (static_cast<mutation_strategy_t>(chosen)) {
	case mutation_strategy_t::bit_flip:          mutate_bit_flip(data, rng, mut); break;
	case mutation_strategy_t::byte_flip:         mutate_byte_flip(data, rng, mut); break;
	case mutation_strategy_t::arithmetic:        mutate_arithmetic(data, rng, mut); break;
	case mutation_strategy_t::interesting_values: mutate_interesting(data, rng, mut); break;
	case mutation_strategy_t::havoc:             mutate_havoc(data, rng, mut); break;
	case mutation_strategy_t::splice:            mutate_splice(data, rng, mut); break;
	default: break;
	}
	return mut;
}

inline bool has_new_coverage(coverage_info_t& cov, const uint8_t* trace_bitmap)
{
	bool found_new = false;
	for (int i = 0; i < 65536; ++i) {
		if (trace_bitmap[i] && !cov.bitmap[i]) {
			cov.bitmap[i] = trace_bitmap[i];
			found_new = true;
		}
	}
	if (found_new) {
		cov.total_edges_discovered = 0;
		for (int i = 0; i < 65536; ++i) {
			if (cov.bitmap[i]) ++cov.total_edges_discovered;
		}
	}
	return found_new;
}

}

inline const char* strategy_name(mutation_strategy_t s)
{
	switch (s) {
	case mutation_strategy_t::bit_flip:           return "Bit Flip";
	case mutation_strategy_t::byte_flip:          return "Byte Flip";
	case mutation_strategy_t::arithmetic:         return "Arithmetic";
	case mutation_strategy_t::interesting_values: return "Interesting";
	case mutation_strategy_t::havoc:              return "Havoc";
	case mutation_strategy_t::splice:             return "Splice";
	default: return "Unknown";
	}
}

inline const char* crash_type_name(crash_type_t t)
{
	switch (t) {
	case crash_type_t::access_violation:   return "Access Violation";
	case crash_type_t::invalid_instruction: return "Invalid Instruction";
	case crash_type_t::division_by_zero:   return "Division by Zero";
	case crash_type_t::stack_overflow:     return "Stack Overflow";
	case crash_type_t::timeout:            return "Timeout";
	case crash_type_t::assertion:          return "Assertion";
	default: return "None";
	}
}

inline void start_fuzzing()
{
#ifdef __NT__
	if (g_state.running.load()) return;
	g_state.running.store(true);
	g_state.cancel.store(false);

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.stats = {};
		g_state.crashes.clear();
		g_state.unique_crashes.clear();
		std::memset(g_state.coverage.bitmap, 0, sizeof(g_state.coverage.bitmap));
		g_state.coverage.edge_count = 0;
		g_state.coverage.total_edges_discovered = 0;
		g_state.active = true;
	}

	std::thread([]() {
		auto& cfg = g_state.config;
		auto& stats = g_state.stats;

		std::mt19937 rng(static_cast<uint32_t>(
			std::chrono::high_resolution_clock::now().time_since_epoch().count()));

		std::vector<uint8_t> seed_input(static_cast<size_t>(cfg.input_size), 0);
		if (cfg.input_address != 0) {
			driver_bridge::read_memory(cfg.input_address, seed_input.size(), seed_input);
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			corpus_entry_t seed;
			seed.data = seed_input;
			seed.source = "seed";
			g_state.corpus.push_back(std::move(seed));
		}

		emulation::process_snapshot_t snapshot;
		if (cfg.pid != 0 && cfg.tid != 0) {
			snapshot = emulation::driver_snapshot(cfg.pid, cfg.tid);
		}

		auto start_time = std::chrono::high_resolution_clock::now();
		auto last_rate_update = start_time;
		uint64_t last_rate_execs = 0;

		for (uint64_t iter = 0; iter < cfg.max_iterations && !g_state.cancel.load(); ++iter) {

			std::vector<uint8_t> input;
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				if (g_state.corpus.empty()) break;
				std::uniform_int_distribution<size_t> corpus_dist(0, g_state.corpus.size() - 1);
				input = g_state.corpus[corpus_dist(rng)].data;
			}

			mutation_t last_mutation;
			for (int m = 0; m < cfg.mutation_count; ++m) {
				last_mutation = detail::apply_mutation(input, rng, cfg.strategies);
			}

			emulation::emulation_config_t emu_cfg;
			emu_cfg.start_address = cfg.target_address;
			emu_cfg.stop_address = cfg.end_address;
			emu_cfg.max_instructions = cfg.max_instructions;
			emu_cfg.timeout_us = static_cast<uint64_t>(cfg.timeout_ms) * 1000;
			emu_cfg.record_mem_reads = false;
			emu_cfg.record_mem_writes = false;
			emu_cfg.record_registers = true;
			emu_cfg.analyze_effective_ops = false;
			emu_cfg.max_trace_entries = 10000;

			auto custom_snapshot = snapshot;
			if (cfg.input_address != 0) {
				for (auto& region : custom_snapshot.regions) {
					if (cfg.input_address >= region.base &&
					    cfg.input_address + input.size() <= region.base + region.data.size()) {
						size_t offset = static_cast<size_t>(cfg.input_address - region.base);
						std::memcpy(region.data.data() + offset, input.data(),
						            std::min(input.size(), region.data.size() - offset));
						break;
					}
				}
			}

			auto result = emulation::emulate_from_snapshot(custom_snapshot, emu_cfg);

			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				++stats.total_executions;
			}

			if (!result.success && !result.error.empty()) {
				crash_info_t crash;
				crash.input = input;
				crash.mutation = last_mutation;

				std::string err = result.error;
				if (err.find("access") != std::string::npos || err.find("memory") != std::string::npos) {
					crash.type = crash_type_t::access_violation;
				} else if (err.find("invalid") != std::string::npos) {
					crash.type = crash_type_t::invalid_instruction;
				} else if (err.find("timeout") != std::string::npos || err.find("limit") != std::string::npos) {
					crash.type = crash_type_t::timeout;
				} else {
					crash.type = crash_type_t::access_violation;
				}
				crash.description = err;
				crash.instruction_address = result.end_address;
				crash.rip = result.end_address;

				for (auto& delta : result.reg_deltas) {
					if (delta.name == "rax") crash.rax = delta.after;
					else if (delta.name == "rbx") crash.rbx = delta.after;
					else if (delta.name == "rcx") crash.rcx = delta.after;
					else if (delta.name == "rdx") crash.rdx = delta.after;
					else if (delta.name == "rsp") crash.rsp = delta.after;
					else if (delta.name == "rbp") crash.rbp = delta.after;
					else if (delta.name == "rsi") crash.rsi = delta.after;
					else if (delta.name == "rdi") crash.rdi = delta.after;
					else if (delta.name == "rip") crash.rip = delta.after;
				}

				std::lock_guard<std::mutex> lk(g_state.mutex);
				stats.total_crashes++;
				g_state.crashes.push_back(crash);

				bool is_unique = true;
				for (auto& uc : g_state.unique_crashes) {
					if (uc.instruction_address == crash.instruction_address &&
					    uc.type == crash.type) {
						is_unique = false;
						break;
					}
				}
				if (is_unique) {
					stats.total_unique_crashes++;
					g_state.unique_crashes.push_back(crash);
				}
			}

			uint8_t trace_bitmap[65536] = {};
			if (!result.trace.empty()) {
				uint64_t prev = 0;
				for (auto& t : result.trace) {
					uint64_t cur = t.address;
					uint32_t edge = static_cast<uint32_t>((prev >> 1) ^ cur);
					trace_bitmap[edge & 0xFFFF]++;
					prev = cur;
				}
			}

			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				if (detail::has_new_coverage(g_state.coverage, trace_bitmap)) {
					stats.new_coverage_finds++;
					corpus_entry_t entry;
					entry.data = input;
					entry.new_coverage = 1;
					entry.source = strategy_name(last_mutation.strategy);
					g_state.corpus.push_back(std::move(entry));
					stats.corpus_size = static_cast<uint32_t>(g_state.corpus.size());
				}
				stats.edge_coverage = g_state.coverage.total_edges_discovered;
			}

			auto now = std::chrono::high_resolution_clock::now();
			auto rate_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rate_update).count();
			if (rate_elapsed >= 1000) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				uint64_t execs_since = stats.total_executions - last_rate_execs;
				stats.executions_per_second = (execs_since * 1000) / static_cast<uint64_t>(rate_elapsed);
				stats.exec_rate_history.push_back(stats.executions_per_second);
				if (stats.exec_rate_history.size() > 120) {
					stats.exec_rate_history.erase(stats.exec_rate_history.begin());
				}
				last_rate_execs = stats.total_executions;
				last_rate_update = now;
				stats.elapsed_seconds = std::chrono::duration<double>(now - start_time).count();
			}
		}

		{
			auto now = std::chrono::high_resolution_clock::now();
			std::lock_guard<std::mutex> lk(g_state.mutex);
			stats.elapsed_seconds = std::chrono::duration<double>(now - start_time).count();
		}

		g_state.running.store(false);
	}).detach();
#endif
}

inline void stop_fuzzing()
{
	g_state.cancel.store(true);
}

}
