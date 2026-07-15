#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "fuzzer_engine_preview.hpp"

#else

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "standalone_ai_client.hpp"
#include "standalone_driver.hpp"
#include "standalone_settings.hpp"
#include "../infra/executor.hpp"
#include "../runtime/diagnostic_exception_scope.hpp"
#include "../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#ifdef __NT__
#include "emulation_engine.hpp"
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

enum class exploit_score_t : int {
	unknown = 0,
	low,
	medium,
	high,
	critical,
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
	exploit_score_t score = exploit_score_t::unknown;
	uint64_t     fault_address = 0;
	uint64_t     instruction_address = 0;
	uint64_t     crash_hash = 0;
	std::string  description;
	std::string  crashing_instruction;
	std::vector<uint8_t> input;
	mutation_t   mutation;
	uint64_t     rax = 0, rbx = 0, rcx = 0, rdx = 0;
	uint64_t     rsp = 0, rbp = 0, rsi = 0, rdi = 0;
	uint64_t     rip = 0;
	uint64_t     r8 = 0, r9 = 0, r10 = 0, r11 = 0;
	uint64_t     r12 = 0, r13 = 0, r14 = 0, r15 = 0;
	std::string  ai_analysis;
	std::vector<uint8_t> minimized_input;
	bool         is_minimized = false;
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
	float                  energy = 1.f;
	uint64_t               exec_us = 0;
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
	std::set<uint64_t>          crash_hashes;
	std::string                 setup_error;

	std::mutex      mutex;
	std::atomic<bool> running{false};
	std::atomic<bool> cancel{false};
	std::atomic<bool> minimizing{false};
	std::atomic<bool> analyzing_crash{false};
	std::atomic<bool> worker_active{false};
	std::atomic<bool> setup_complete{false};
	std::atomic<bool> setup_success{false};
	bool            active = false;

	char addr_input[32] = {};
	char end_addr_input[32] = {};
	char input_addr[32] = {};
	char input_size_str[16] = "256";
	char max_iter_str[16] = "10000";
};

inline state_t g_state;

namespace detail {

inline uint64_t compute_crash_hash(uint64_t rip, crash_type_t type)
{
	uint64_t h = 0xcbf29ce484222325ULL;
	auto mix = [&](uint64_t v) {
		for (int i = 0; i < 8; ++i) {
			h ^= (v >> (i * 8)) & 0xFF;
			h *= 0x100000001b3ULL;
		}
	};
	mix(rip);
	mix(static_cast<uint64_t>(type));
	return h;
}

inline exploit_score_t compute_exploit_score(const crash_info_t& crash)
{
	bool rip_controlled = false;
	bool rsp_corrupted = false;
	bool write_av = false;

	if (crash.type == crash_type_t::access_violation) {
		if (crash.rip < 0x10000 || crash.rip == 0x4141414141414141ULL ||
		    crash.rip == 0xCCCCCCCCCCCCCCCCULL || crash.rip == 0xDEADBEEFDEADBEEFULL) {
			rip_controlled = true;
		}

		std::string desc_lower = crash.description;
		for (auto& c : desc_lower) c = static_cast<char>(std::tolower(c));
		if (desc_lower.find("write") != std::string::npos) write_av = true;

		if (crash.rsp < 0x1000 || crash.rsp > 0x7FFFFFFFE000ULL) {
			rsp_corrupted = true;
		}
	}

	if (rip_controlled) return exploit_score_t::critical;

	if (crash.type == crash_type_t::stack_overflow && rsp_corrupted)
		return exploit_score_t::high;

	if (write_av) return exploit_score_t::high;

	if (crash.type == crash_type_t::access_violation)
		return exploit_score_t::medium;

	if (crash.type == crash_type_t::invalid_instruction)
		return exploit_score_t::medium;

	if (crash.type == crash_type_t::division_by_zero)
		return exploit_score_t::low;

	if (crash.type == crash_type_t::timeout)
		return exploit_score_t::low;

	return exploit_score_t::unknown;
}

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
			std::uniform_int_distribution<int> val_dist(0, 255);
			mut.strategy = mutation_strategy_t::havoc;
			mut.offset = pos;
			mut.size = 1;
			mut.original = {data[pos]};
			data[pos] = static_cast<uint8_t>(val_dist(rng));
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

inline size_t select_corpus_weighted(std::mt19937& rng, const std::vector<corpus_entry_t>& corpus)
{
	if (corpus.empty()) return 0;
	if (corpus.size() == 1) return 0;

	float total = 0.f;
	for (auto& e : corpus) total += e.energy;
	if (total <= 0.f) {
		std::uniform_int_distribution<size_t> dist(0, corpus.size() - 1);
		return dist(rng);
	}

	std::uniform_real_distribution<float> pick(0.f, total);
	float r = pick(rng);
	float acc = 0.f;
	for (size_t i = 0; i < corpus.size(); ++i) {
		acc += corpus[i].energy;
		if (r <= acc) return i;
	}
	return corpus.size() - 1;
}

inline void update_corpus_energy(std::vector<corpus_entry_t>& corpus)
{
	if (corpus.empty()) return;

	size_t avg_size = 0;
	for (auto& e : corpus) avg_size += e.data.size();
	avg_size /= corpus.size();
	if (avg_size == 0) avg_size = 1;

	for (auto& e : corpus) {
		float size_factor = static_cast<float>(avg_size) / static_cast<float>((std::max)(e.data.size(), size_t(1)));
		size_factor = (std::min)(size_factor, 4.f);

		float cov_factor = 1.f + static_cast<float>(e.new_coverage) * 2.f;

		float speed_factor = 1.f;
		if (e.exec_us > 0 && e.exec_us < 100000)
			speed_factor = 2.f;
		else if (e.exec_us > 500000)
			speed_factor = 0.5f;

		e.energy = size_factor * cov_factor * speed_factor;
	}
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

inline const char* exploit_score_name(exploit_score_t s)
{
	switch (s) {
	case exploit_score_t::critical: return "CRITICAL";
	case exploit_score_t::high:     return "HIGH";
	case exploit_score_t::medium:   return "MEDIUM";
	case exploit_score_t::low:      return "LOW";
	default: return "UNKNOWN";
	}
}

inline bool start_fuzzing()
{
#ifdef __NT__
	bool expected = false;
	if (!g_state.running.compare_exchange_strong(expected, true)) {
		diag::log_tagged("fuzzer", "start_skip reason=already_running");
		return false;
	}
	g_state.cancel.store(false);
	g_state.worker_active.store(true);
	g_state.setup_complete.store(false);
	g_state.setup_success.store(false);

	fuzz_config_t cfg_snapshot{};
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		cfg_snapshot = g_state.config;
		g_state.stats = {};
		g_state.crashes.clear();
		g_state.unique_crashes.clear();
		g_state.crash_hashes.clear();
		std::memset(g_state.coverage.bitmap, 0, sizeof(g_state.coverage.bitmap));
		g_state.coverage.edge_count = 0;
		g_state.coverage.total_edges_discovered = 0;
		g_state.setup_error.clear();
		g_state.active = true;
	}

	if (cfg_snapshot.target_address == 0 ||
	    cfg_snapshot.end_address <= cfg_snapshot.target_address ||
	    cfg_snapshot.input_size <= 0 ||
	    cfg_snapshot.input_size > 1024 * 1024 ||
	    cfg_snapshot.max_iterations == 0) {
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.setup_error = "invalid fuzzer configuration";
			g_state.active = false;
		}
		g_state.setup_complete.store(true);
		g_state.setup_success.store(false);
		g_state.worker_active.store(false);
		g_state.running.store(false);
		diag::log_tagged_fmt("fuzzer",
			"start_reject reason=invalid_config target=0x%llX end=0x%llX input_size=%d max_iterations=%u",
			static_cast<unsigned long long>(cfg_snapshot.target_address),
			static_cast<unsigned long long>(cfg_snapshot.end_address),
			cfg_snapshot.input_size,
			cfg_snapshot.max_iterations);
		return false;
	}

	auto worker = [cfg_snapshot]() {
		const auto cfg = cfg_snapshot;
		auto& stats = g_state.stats;
		try {

		diag::log_tagged_fmt("fuzzer",
			"worker_begin pid=%u tid=%u target=0x%llX input=0x%llX size=%d iters=%u",
			cfg.pid, cfg.tid,
			static_cast<unsigned long long>(cfg.target_address),
			static_cast<unsigned long long>(cfg.input_address),
			cfg.input_size, cfg.max_iterations);

		std::mt19937 rng(static_cast<uint32_t>(
			std::chrono::high_resolution_clock::now().time_since_epoch().count()));

		std::vector<uint8_t> seed_input(static_cast<size_t>(cfg.input_size), 0);
		if (cfg.input_address != 0) {
			bool seed_ok = driver_bridge::read_memory(cfg.input_address, seed_input.size(), seed_input);
			diag::log_tagged_fmt("fuzzer",
				"seed_read addr=0x%llX size=%zu ok=%d",
				static_cast<unsigned long long>(cfg.input_address),
				seed_input.size(), seed_ok ? 1 : 0);
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			corpus_entry_t seed;
			seed.data = seed_input;
			seed.source = "seed";
			g_state.corpus.push_back(std::move(seed));
			g_state.stats.corpus_size = static_cast<uint32_t>(g_state.corpus.size());
		}

		emulation::process_snapshot_t snapshot;
		if (cfg.pid != 0 && cfg.tid != 0) {
			std::uint64_t snapshot_base = cfg.target_address & ~0xFFFULL;
			std::uint64_t snapshot_size = 0x20000ULL;
			if (cfg.end_address > cfg.target_address && cfg.end_address - snapshot_base < 0x400000ULL)
				snapshot_size = std::max<std::uint64_t>(snapshot_size, (cfg.end_address - snapshot_base + 0xFFFULL) & ~0xFFFULL);
			diag::log_tagged_fmt("fuzzer",
				"snapshot_begin pid=%u tid=%u base=0x%llX size=0x%llX target=0x%llX end=0x%llX",
				cfg.pid, cfg.tid,
				static_cast<unsigned long long>(snapshot_base),
				static_cast<unsigned long long>(snapshot_size),
				static_cast<unsigned long long>(cfg.target_address),
				static_cast<unsigned long long>(cfg.end_address));
			snapshot = emulation::driver_snapshot(cfg.pid, cfg.tid, snapshot_base, snapshot_size);
			diag::log_tagged_fmt("fuzzer",
				"snapshot_done success=%d regions=%zu err=%s",
				snapshot.success ? 1 : 0,
				snapshot.regions.size(),
				snapshot.error.c_str());
		}
		if (!snapshot.success || snapshot.regions.empty()) {
			std::string err = !snapshot.error.empty() ? snapshot.error : "snapshot has no memory regions";
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.setup_error = err;
				g_state.active = false;
			}
			diag::log_tagged_fmt("fuzzer", "setup_failed pid=%u tid=%u target=0x%llX err=%s",
				cfg.pid, cfg.tid,
				static_cast<unsigned long long>(cfg.target_address),
				err.c_str());
			g_state.setup_complete.store(true);
			g_state.setup_success.store(false);
			g_state.worker_active.store(false);
			g_state.running.store(false);
			return;
		}
		g_state.setup_success.store(true);
		g_state.setup_complete.store(true);
		diag::log_tagged_fmt("fuzzer",
			"setup_complete pid=%u tid=%u regions=%zu target=0x%llX",
			cfg.pid, cfg.tid,
			snapshot.regions.size(),
			static_cast<unsigned long long>(cfg.target_address));

		auto start_time = std::chrono::high_resolution_clock::now();
		auto last_rate_update = start_time;
		uint64_t last_rate_execs = 0;

		for (uint64_t iter = 0; iter < cfg.max_iterations && !g_state.cancel.load(); ++iter) {

			std::vector<uint8_t> input;
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				if (g_state.corpus.empty()) break;
				size_t idx = detail::select_corpus_weighted(rng, g_state.corpus);
				input = g_state.corpus[idx].data;
			}

			if (iter > 0 && iter % 500 == 0) {
				std::lock_guard<std::mutex> lk(g_state.mutex);
				detail::update_corpus_energy(g_state.corpus);
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

			if (iter < 8 || (iter % 1000) == 0) {
				diag::log_tagged_fmt("fuzzer",
					"emulate_begin iter=%llu target=0x%llX stop=0x%llX input=0x%llX input_size=%zu",
					static_cast<unsigned long long>(iter),
					static_cast<unsigned long long>(emu_cfg.start_address),
					static_cast<unsigned long long>(emu_cfg.stop_address),
					static_cast<unsigned long long>(cfg.input_address),
					input.size());
			}
			aida::diagnostic_exception_scope::scope_t exception_scope("fuzzer.emulate_from_snapshot");
			auto result = emulation::emulate_from_snapshot(custom_snapshot, emu_cfg);
			if (iter < 8 || (iter % 1000) == 0) {
				diag::log_tagged_fmt("fuzzer",
					"emulate_done iter=%llu success=%d end=0x%llX trace=%zu err=%s",
					static_cast<unsigned long long>(iter),
					result.success ? 1 : 0,
					static_cast<unsigned long long>(result.end_address),
					result.trace.size(),
					result.error.c_str());
			}

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
					else if (delta.name == "r8")  crash.r8 = delta.after;
					else if (delta.name == "r9")  crash.r9 = delta.after;
					else if (delta.name == "r10") crash.r10 = delta.after;
					else if (delta.name == "r11") crash.r11 = delta.after;
					else if (delta.name == "r12") crash.r12 = delta.after;
					else if (delta.name == "r13") crash.r13 = delta.after;
					else if (delta.name == "r14") crash.r14 = delta.after;
					else if (delta.name == "r15") crash.r15 = delta.after;
				}

				if (!result.trace.empty()) {
					auto& last_trace = result.trace.back();
					crash.crashing_instruction = last_trace.disasm;
				}

				crash.crash_hash = detail::compute_crash_hash(crash.rip, crash.type);
				crash.score = detail::compute_exploit_score(crash);

				bool is_unique = false;
				{
					std::lock_guard<std::mutex> lk(g_state.mutex);
					stats.total_crashes++;
					g_state.crashes.push_back(crash);

					if (g_state.crash_hashes.find(crash.crash_hash) == g_state.crash_hashes.end()) {
						g_state.crash_hashes.insert(crash.crash_hash);
						stats.total_unique_crashes++;
						g_state.unique_crashes.push_back(crash);
						is_unique = true;
					}
				}
				diag::log_tagged_fmt("fuzzer",
					"crash type=%s score=%s rip=0x%llX unique=%d iter=%llu",
					crash_type_name(crash.type),
					exploit_score_name(crash.score),
					static_cast<unsigned long long>(crash.rip),
					is_unique ? 1 : 0,
					static_cast<unsigned long long>(iter));
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
					constexpr size_t kMaxCorpusEntries = 4096;
					if (g_state.corpus.size() > kMaxCorpusEntries) {
						size_t excess = g_state.corpus.size() - kMaxCorpusEntries;
						g_state.corpus.erase(g_state.corpus.begin() + 1,
							g_state.corpus.begin() + 1 + static_cast<ptrdiff_t>(excess));
					}
					stats.corpus_size = static_cast<uint32_t>(g_state.corpus.size());
				}
				stats.edge_coverage = g_state.coverage.total_edges_discovered;
			}

			auto now = std::chrono::high_resolution_clock::now();
			auto rate_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rate_update).count();
			if (rate_elapsed >= 1000) {
				uint64_t crashes_snap = 0, unique_snap = 0, eps_snap = 0;
				uint32_t cov_snap = 0, corp_snap = 0;
				{
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
					crashes_snap = stats.total_crashes;
					unique_snap = stats.total_unique_crashes;
					eps_snap = stats.executions_per_second;
					cov_snap = stats.edge_coverage;
					corp_snap = stats.corpus_size;
				}
				diag::log_tagged_fmt("fuzzer",
					"progress iter=%llu eps=%llu crashes=%llu unique=%llu edges=%u corpus=%u",
					static_cast<unsigned long long>(iter),
					static_cast<unsigned long long>(eps_snap),
					static_cast<unsigned long long>(crashes_snap),
					static_cast<unsigned long long>(unique_snap),
					cov_snap, corp_snap);
			}
		}

		uint64_t final_execs = 0, final_crashes = 0, final_unique = 0;
		double final_elapsed = 0.0;
		{
			auto now = std::chrono::high_resolution_clock::now();
			std::lock_guard<std::mutex> lk(g_state.mutex);
			stats.elapsed_seconds = std::chrono::duration<double>(now - start_time).count();
			final_execs = stats.total_executions;
			final_crashes = stats.total_crashes;
			final_unique = stats.total_unique_crashes;
			final_elapsed = stats.elapsed_seconds;
		}

		diag::log_tagged_fmt("fuzzer",
			"worker_done execs=%llu crashes=%llu unique=%llu elapsed_s=%.1f cancelled=%d",
			static_cast<unsigned long long>(final_execs),
			static_cast<unsigned long long>(final_crashes),
			static_cast<unsigned long long>(final_unique),
			final_elapsed, g_state.cancel.load() ? 1 : 0);

		g_state.worker_active.store(false);
		g_state.running.store(false);
		} catch (const std::exception& ex) {
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.setup_error = ex.what();
				g_state.active = false;
			}
			g_state.setup_complete.store(true);
			g_state.setup_success.store(false);
			g_state.worker_active.store(false);
			g_state.running.store(false);
			diag::log_tagged_fmt("fuzzer", "worker_exception type=std err=%s", ex.what());
		} catch (...) {
			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.setup_error = "unknown fuzzer worker exception";
				g_state.active = false;
			}
			g_state.setup_complete.store(true);
			g_state.setup_success.store(false);
			g_state.worker_active.store(false);
			g_state.running.store(false);
			diag::log_tagged("fuzzer", "worker_exception type=unknown");
		}
	};
	const bool run_inline = cfg_snapshot.max_iterations <= 32 &&
		cfg_snapshot.input_size <= 4096 &&
		cfg_snapshot.end_address > cfg_snapshot.target_address &&
		(cfg_snapshot.end_address - cfg_snapshot.target_address) <= 0x1000;
	if (run_inline) {
		diag::log_tagged_fmt("fuzzer",
			"start_inline_worker target=0x%llX end=0x%llX input_size=%d max_iterations=%u",
			static_cast<unsigned long long>(cfg_snapshot.target_address),
			static_cast<unsigned long long>(cfg_snapshot.end_address),
			cfg_snapshot.input_size,
			cfg_snapshot.max_iterations);
		worker();
		return true;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "fuzzer";
	submission.label = "fuzzer.worker";
	submission.thread_class = "fuzzer_worker";
	submission.domain = aida::infra::executor::domain_t::long_running;
	submission.priority = 1;
	submission.target_pid = cfg_snapshot.pid;
	submission.failure_policy = "reject_not_started";
	submission.body = std::move(worker);
	const bool posted = aida::infra::executor::submit(std::move(submission)).submitted;
	if (!posted) {
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.setup_error = "fuzzer worker queue post failed";
			g_state.active = false;
		}
		g_state.setup_complete.store(true);
		g_state.setup_success.store(false);
		g_state.worker_active.store(false);
		g_state.running.store(false);
		diag::log_tagged("fuzzer", "worker_post_failed");
		return false;
	}
	return true;
#else
	return false;
#endif
}

inline void stop_fuzzing()
{
	g_state.cancel.store(true);
}

inline bool wait_until_idle(uint32_t timeout_ms)
{
	const auto start = std::chrono::steady_clock::now();
	while (g_state.running.load() || g_state.worker_active.load()) {
		if (timeout_ms != 0) {
			const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - start).count();
			if (elapsed >= timeout_ms) {
				diag::log_tagged_fmt("fuzzer",
					"wait_idle_timeout timeout_ms=%u running=%d worker_active=%d setup_complete=%d setup_success=%d",
					timeout_ms,
					g_state.running.load() ? 1 : 0,
					g_state.worker_active.load() ? 1 : 0,
					g_state.setup_complete.load() ? 1 : 0,
					g_state.setup_success.load() ? 1 : 0);
				return false;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(25));
	}
	return true;
}

inline bool reset_state()
{
	if (g_state.running.load()) {
		diag::log_tagged("fuzzer", "[analysis_audit] reset_reject reason=fuzzer_running");
		return false;
	}
	if (g_state.minimizing.load() || g_state.analyzing_crash.load()) {
		diag::log_tagged("fuzzer", "[analysis_audit] reset_reject reason=async_active");
		return false;
	}

	size_t prev_crashes = 0;
	size_t prev_unique = 0;
	size_t prev_corpus = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		prev_crashes = g_state.crashes.size();
		prev_unique = g_state.unique_crashes.size();
		prev_corpus = g_state.corpus.size();
		g_state.stats = {};
		g_state.crashes.clear();
		g_state.unique_crashes.clear();
		g_state.crash_hashes.clear();
		g_state.corpus.clear();
		std::memset(g_state.coverage.bitmap, 0, sizeof(g_state.coverage.bitmap));
		g_state.coverage.edge_count = 0;
		g_state.coverage.total_edges_discovered = 0;
		g_state.coverage.prev_block = 0;
		g_state.active = false;
		g_state.cancel.store(false);
	}

	diag::log_tagged_fmt("fuzzer",
		"[analysis_audit] reset_done prev_crashes=%zu prev_unique=%zu prev_corpus=%zu",
		prev_crashes, prev_unique, prev_corpus);
	return true;
}

inline void ai_analyze_crash(int crash_index)
{
#ifdef __NT__
	if (g_state.analyzing_crash.load()) return;

	crash_info_t target_crash;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		if (crash_index < 0 || crash_index >= static_cast<int>(g_state.unique_crashes.size())) return;
		target_crash = g_state.unique_crashes[crash_index];
	}

	g_state.analyzing_crash.store(true);

	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "fuzzer";
	submission.label = "fuzzer.ai_analyze_crash";
	submission.thread_class = "external_ai";
	submission.domain = aida::infra::executor::domain_t::external_tool;
	submission.priority = 3;
	submission.failure_policy = "reject_not_started";
	submission.body = [target_crash, crash_index]() {
		std::string prompt = "You are a vulnerability researcher analyzing a crash found by a fuzzer.\n\n";
		prompt += "CRASH DETAILS:\n";
		prompt += "Type: " + std::string(crash_type_name(target_crash.type)) + "\n";
		prompt += "Exploitability: " + std::string(exploit_score_name(target_crash.score)) + "\n";
		prompt += "Description: " + target_crash.description + "\n";

		char reg_buf[1024];
		std::snprintf(reg_buf, sizeof(reg_buf),
			"\nREGISTER STATE:\n"
			"RAX=0x%016llX RBX=0x%016llX RCX=0x%016llX RDX=0x%016llX\n"
			"RSP=0x%016llX RBP=0x%016llX RSI=0x%016llX RDI=0x%016llX\n"
			"RIP=0x%016llX R8 =0x%016llX R9 =0x%016llX R10=0x%016llX\n"
			"R11=0x%016llX R12=0x%016llX R13=0x%016llX R14=0x%016llX\nR15=0x%016llX\n",
			static_cast<unsigned long long>(target_crash.rax),
			static_cast<unsigned long long>(target_crash.rbx),
			static_cast<unsigned long long>(target_crash.rcx),
			static_cast<unsigned long long>(target_crash.rdx),
			static_cast<unsigned long long>(target_crash.rsp),
			static_cast<unsigned long long>(target_crash.rbp),
			static_cast<unsigned long long>(target_crash.rsi),
			static_cast<unsigned long long>(target_crash.rdi),
			static_cast<unsigned long long>(target_crash.rip),
			static_cast<unsigned long long>(target_crash.r8),
			static_cast<unsigned long long>(target_crash.r9),
			static_cast<unsigned long long>(target_crash.r10),
			static_cast<unsigned long long>(target_crash.r11),
			static_cast<unsigned long long>(target_crash.r12),
			static_cast<unsigned long long>(target_crash.r13),
			static_cast<unsigned long long>(target_crash.r14),
			static_cast<unsigned long long>(target_crash.r15));
		prompt += reg_buf;

		if (!target_crash.crashing_instruction.empty())
			prompt += "\nCrashing instruction: " + target_crash.crashing_instruction + "\n";

		if (!target_crash.input.empty()) {
			prompt += "\nInput hex (first 128 bytes):\n";
			size_t show = (std::min)(target_crash.input.size(), size_t(128));
			for (size_t i = 0; i < show; ++i) {
				char hx[4];
				std::snprintf(hx, sizeof(hx), "%02X ", target_crash.input[i]);
				prompt += hx;
				if ((i + 1) % 16 == 0) prompt += "\n";
			}
			prompt += "\n";
		}

		prompt += "\nMutation that caused crash: " + std::string(strategy_name(target_crash.mutation.strategy)) + "\n";
		char mut_buf[128];
		std::snprintf(mut_buf, sizeof(mut_buf), "Mutation offset: 0x%llX, size: %llu\n",
			static_cast<unsigned long long>(target_crash.mutation.offset),
			static_cast<unsigned long long>(target_crash.mutation.size));
		prompt += mut_buf;

		prompt += "\nAnalyze this crash. Determine:\n"
		          "1. Root cause (buffer overflow, use-after-free, integer overflow, etc.)\n"
		          "2. Exploitability assessment with reasoning\n"
		          "3. Which register or memory location is tainted by the input\n"
		          "4. Suggested proof-of-concept strategy if exploitable\n"
		          "5. Recommended fix\n"
		          "Be concise but thorough.";

		auto ai = std::make_unique<standalone_ai_client_t>(g_sa_settings);
		if (!ai->is_available()) {
			diag::log_tagged_fmt("fuzzer", "ai_analyze_unavailable crash_index=%d", crash_index);
			g_state.analyzing_crash.store(false);
			return;
		}

		diag::log_tagged_fmt("fuzzer",
			"ai_analyze_request crash_index=%d rip=0x%llX prompt_bytes=%zu",
			crash_index, static_cast<unsigned long long>(target_crash.rip),
			prompt.size());

		std::vector<std::pair<std::string, std::string>> history;
		auto t_ai0 = std::chrono::steady_clock::now();
		std::string result = ai->chat_blocking(prompt, history, nullptr, nullptr);
		auto t_ai1 = std::chrono::steady_clock::now();

		if (!result.empty()) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (crash_index < static_cast<int>(g_state.unique_crashes.size()))
				g_state.unique_crashes[crash_index].ai_analysis = result;
		}

		diag::log_tagged_fmt("fuzzer",
			"ai_analyze_done crash_index=%d result_bytes=%zu duration_ms=%lld",
			crash_index, result.size(),
			static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(t_ai1 - t_ai0).count()));

		g_state.analyzing_crash.store(false);
	};
	if (!aida::infra::executor::submit(std::move(submission)).submitted) {
		diag::log_tagged_fmt("fuzzer", "ai_analyze_post_failed crash_index=%d", crash_index);
		g_state.analyzing_crash.store(false);
	}
#else
	(void)crash_index;
#endif
}

inline void minimize_crash(int crash_index)
{
#ifdef __NT__
	if (g_state.minimizing.load()) return;

	crash_info_t target_crash;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		if (crash_index < 0 || crash_index >= static_cast<int>(g_state.unique_crashes.size())) return;
		target_crash = g_state.unique_crashes[crash_index];
	}

	if (target_crash.input.empty()) return;

	g_state.minimizing.store(true);

	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "fuzzer";
	submission.label = "fuzzer.minimize_crash";
	submission.thread_class = "fuzzer_minimize";
	submission.domain = aida::infra::executor::domain_t::long_running;
	submission.priority = 3;
	submission.failure_policy = "reject_not_started";
	submission.body = [target_crash, crash_index]() {
		auto& cfg = g_state.config;

		emulation::process_snapshot_t snapshot;
		if (cfg.pid != 0 && cfg.tid != 0)
			snapshot = emulation::driver_snapshot(cfg.pid, cfg.tid);

		auto test_input = [&](const std::vector<uint8_t>& input) -> bool {
			emulation::emulation_config_t emu_cfg;
			emu_cfg.start_address = cfg.target_address;
			emu_cfg.stop_address = cfg.end_address;
			emu_cfg.max_instructions = cfg.max_instructions;
			emu_cfg.timeout_us = static_cast<uint64_t>(cfg.timeout_ms) * 1000;
			emu_cfg.max_trace_entries = 100;

			auto snap_copy = snapshot;
			if (cfg.input_address != 0) {
				for (auto& region : snap_copy.regions) {
					if (cfg.input_address >= region.base &&
					    cfg.input_address + input.size() <= region.base + region.data.size()) {
						size_t offset = static_cast<size_t>(cfg.input_address - region.base);
						std::memset(region.data.data() + offset, 0, (std::min)(target_crash.input.size(), region.data.size() - offset));
						std::memcpy(region.data.data() + offset, input.data(),
						            (std::min)(input.size(), region.data.size() - offset));
						break;
					}
				}
			}

			aida::diagnostic_exception_scope::scope_t exception_scope("fuzzer.minimize.emulate_from_snapshot");
			auto result = emulation::emulate_from_snapshot(snap_copy, emu_cfg);
			if (!result.success && !result.error.empty()) {
				uint64_t crash_hash = detail::compute_crash_hash(result.end_address, target_crash.type);
				return crash_hash == target_crash.crash_hash;
			}
			return false;
		};

		std::vector<uint8_t> current = target_crash.input;

		size_t block_size = current.size() / 2;
		while (block_size >= 1 && !g_state.cancel.load()) {
			size_t pos = 0;
			bool changed = false;
			while (pos + block_size <= current.size() && !g_state.cancel.load()) {
				std::vector<uint8_t> candidate;
				candidate.insert(candidate.end(), current.begin(), current.begin() + static_cast<ptrdiff_t>(pos));
				candidate.insert(candidate.end(), current.begin() + static_cast<ptrdiff_t>(pos + block_size),
				                 current.end());

				if (!candidate.empty() && test_input(candidate)) {
					current = candidate;
					changed = true;
				} else {
					pos += block_size;
				}
			}
			if (!changed)
				block_size /= 2;
		}

		for (size_t i = 0; i < current.size() && !g_state.cancel.load(); ++i) {
			if (current[i] == 0) continue;
			uint8_t orig = current[i];
			current[i] = 0;
			if (!test_input(current))
				current[i] = orig;
		}

		size_t orig_size = target_crash.input.size();
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (crash_index < static_cast<int>(g_state.unique_crashes.size())) {
				g_state.unique_crashes[crash_index].minimized_input = current;
				g_state.unique_crashes[crash_index].is_minimized = true;
			}
		}

		diag::log_tagged_fmt("fuzzer",
			"minimize_done crash_index=%d original_bytes=%zu minimized_bytes=%zu cancelled=%d",
			crash_index, orig_size, current.size(),
			g_state.cancel.load() ? 1 : 0);

		g_state.minimizing.store(false);
	};
	if (!aida::infra::executor::submit(std::move(submission)).submitted) {
		diag::log_tagged_fmt("fuzzer", "minimize_post_failed crash_index=%d", crash_index);
		g_state.minimizing.store(false);
	}
#else
	(void)crash_index;
#endif
}

inline std::string get_crash_export_dir()
{
	const char* appdata = std::getenv("APPDATA");
	if (!appdata) return {};
	return std::string(appdata) + "\\AiDA\\Standalone\\fuzzer_crashes";
}

inline void export_crashes()
{
	std::string dir = get_crash_export_dir();
	if (dir.empty()) {
		diag::log_tagged("fuzzer", "export_fail reason=no_appdata");
		return;
	}

	std::error_code ec;
	std::filesystem::create_directories(dir, ec);
	if (ec) {
		diag::log_tagged_fmt("fuzzer",
			"export_fail reason=mkdir_failed dir='%s' err='%s'",
			dir.c_str(), ec.message().c_str());
		return;
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);
	size_t written = g_state.unique_crashes.size();
	diag::log_tagged_fmt("fuzzer",
		"export_begin dir='%s' unique=%zu", dir.c_str(), written);
	for (size_t i = 0; i < g_state.unique_crashes.size(); ++i) {
		auto& crash = g_state.unique_crashes[i];

		nlohmann::json j;
		j["type"] = static_cast<int>(crash.type);
		j["score"] = static_cast<int>(crash.score);
		j["fault_address"] = crash.fault_address;
		j["instruction_address"] = crash.instruction_address;
		j["crash_hash"] = crash.crash_hash;
		j["description"] = crash.description;
		j["crashing_instruction"] = crash.crashing_instruction;
		j["rip"] = crash.rip;
		j["rax"] = crash.rax;
		j["rbx"] = crash.rbx;
		j["rcx"] = crash.rcx;
		j["rdx"] = crash.rdx;
		j["rsp"] = crash.rsp;
		j["rbp"] = crash.rbp;
		j["rsi"] = crash.rsi;
		j["rdi"] = crash.rdi;

		std::string input_hex;
		for (auto b : crash.input) {
			char hx[4];
			std::snprintf(hx, sizeof(hx), "%02X", b);
			input_hex += hx;
		}
		j["input_hex"] = input_hex;
		j["ai_analysis"] = crash.ai_analysis;

		if (crash.is_minimized) {
			std::string min_hex;
			for (auto b : crash.minimized_input) {
				char hx[4];
				std::snprintf(hx, sizeof(hx), "%02X", b);
				min_hex += hx;
			}
			j["minimized_hex"] = min_hex;
		}

		char fname[256];
		std::snprintf(fname, sizeof(fname), "%s\\crash_%llX_%zu.json",
		              dir.c_str(), static_cast<unsigned long long>(crash.crash_hash), i);

		std::ofstream ofs(fname);
		if (ofs.is_open()) ofs << j.dump(2);
		else diag::log_tagged_fmt("fuzzer", "export_write_fail path='%s'", fname);
	}
	diag::log_tagged_fmt("fuzzer", "export_done unique=%zu dir='%s'", written, dir.c_str());
}

inline void import_crashes()
{
	std::string dir = get_crash_export_dir();
	if (dir.empty()) {
		diag::log_tagged("fuzzer", "import_fail reason=no_appdata");
		return;
	}

	std::error_code ec;
	if (!std::filesystem::exists(dir, ec)) {
		diag::log_tagged_fmt("fuzzer", "import_fail reason=dir_missing dir='%s'", dir.c_str());
		return;
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);
	size_t loaded = 0;
	size_t skipped = 0;

	for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
		if (ec) break;
		if (!entry.is_regular_file() || entry.path().extension() != ".json") continue;

		std::ifstream ifs(entry.path());
		if (!ifs.is_open()) continue;

		auto j = nlohmann::json::parse(ifs, nullptr, false);
		if (j.is_discarded()) continue;

		crash_info_t crash;
		crash.type = static_cast<crash_type_t>(j.value("type", 0));
		crash.score = static_cast<exploit_score_t>(j.value("score", 0));
		crash.fault_address = j.value("fault_address", uint64_t(0));
		crash.instruction_address = j.value("instruction_address", uint64_t(0));
		crash.crash_hash = j.value("crash_hash", uint64_t(0));
		crash.description = j.value("description", std::string{});
		crash.crashing_instruction = j.value("crashing_instruction", std::string{});
		crash.rip = j.value("rip", uint64_t(0));
		crash.rax = j.value("rax", uint64_t(0));
		crash.rbx = j.value("rbx", uint64_t(0));
		crash.rcx = j.value("rcx", uint64_t(0));
		crash.rdx = j.value("rdx", uint64_t(0));
		crash.rsp = j.value("rsp", uint64_t(0));
		crash.rbp = j.value("rbp", uint64_t(0));
		crash.rsi = j.value("rsi", uint64_t(0));
		crash.rdi = j.value("rdi", uint64_t(0));
		crash.ai_analysis = j.value("ai_analysis", std::string{});

		std::string input_hex = j.value("input_hex", std::string{});
		for (size_t k = 0; k + 2 <= input_hex.size(); k += 2) {
			uint8_t byte = static_cast<uint8_t>(std::strtoul(input_hex.substr(k, 2).c_str(), nullptr, 16));
			crash.input.push_back(byte);
		}

		if (j.contains("minimized_hex")) {
			crash.is_minimized = true;
			std::string min_hex = j["minimized_hex"].get<std::string>();
			for (size_t k = 0; k + 2 <= min_hex.size(); k += 2) {
				uint8_t byte = static_cast<uint8_t>(std::strtoul(min_hex.substr(k, 2).c_str(), nullptr, 16));
				crash.minimized_input.push_back(byte);
			}
		}

		if (g_state.crash_hashes.find(crash.crash_hash) == g_state.crash_hashes.end()) {
			g_state.crash_hashes.insert(crash.crash_hash);
			g_state.unique_crashes.push_back(std::move(crash));
			++loaded;
		} else {
			++skipped;
		}
	}
	diag::log_tagged_fmt("fuzzer",
		"import_done dir='%s' loaded=%zu skipped_dupe=%zu",
		dir.c_str(), loaded, skipped);
}

}

#endif
