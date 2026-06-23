#pragma once

#include <atomic>
#include "work_queue.hpp"
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "page_guard_engine.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "../infra/critical_work_queue.hpp"
#include "../../helpers/diag_log.hpp"

namespace integrity_hunter {

inline constexpr uint32_t k_integrity_hunter_max_records_per_drain = 0;

struct integrity_node_t {
	uint64_t reader_rip = 0;
	uint64_t hash_compare_addr = 0;
	uint64_t loop_start = 0;
	uint64_t loop_end = 0;
	uint64_t patch_addr = 0;
	int      read_count = 0;
	float    reads_per_second = 0.f;
	std::string module_name;
	std::string disasm_text;
	bool     neutralized = false;
	std::vector<uint8_t> original_bytes;
	std::vector<uint64_t> callstack;
};

struct capture_event_t {
	uint64_t rip = 0;
	uint64_t fault_addr = 0;
	uint64_t timestamp = 0;
	uint32_t access_type = 0;
};

struct state_t {
	std::vector<integrity_node_t> nodes;
	std::vector<capture_event_t> event_log;
	std::mutex mutex;
	std::atomic<bool> hunting{false};
	std::atomic<bool> cancel{false};
	std::atomic<bool> worker_active{false};
	std::atomic<bool> install_complete{false};
	std::atomic<bool> install_success{false};
	std::atomic<uint64_t> total_reads{0};
	std::atomic<uint64_t> generation{0};
	std::atomic<uint64_t> install_generation{0};
	std::atomic<uint32_t> pg_session_id{0};
	std::atomic<uint32_t> target_pid{0};
	uint64_t target_address = 0;
	uint64_t target_size = 0;
	char address_input[32] = {};
	char size_input[16] = "4096";
	std::string status_text;
};

inline state_t g_state;

struct idle_result_t {
	bool idle = false;
	uint64_t generation = 0;
	uint64_t install_generation = 0;
	uint32_t session_id = 0;
	uint32_t target_pid = 0;
	bool hunting = false;
	bool worker_active = false;
	bool install_complete = false;
	bool install_success = false;
	size_t nodes = 0;
	size_t events = 0;
	uint64_t total_reads = 0;
	int64_t elapsed_ms = 0;
	std::string status_text;
};

inline bool install_complete_for_generation(uint64_t generation)
{
	return g_state.install_generation.load(std::memory_order_acquire) == generation &&
	       g_state.install_complete.load(std::memory_order_acquire);
}

inline bool install_success_for_generation(uint64_t generation)
{
	return g_state.install_generation.load(std::memory_order_acquire) == generation &&
	       g_state.install_complete.load(std::memory_order_acquire) &&
	       g_state.install_success.load(std::memory_order_acquire);
}

inline idle_result_t snapshot_idle_state(int64_t elapsed_ms = 0)
{
	idle_result_t result;
	result.generation = g_state.generation.load(std::memory_order_acquire);
	result.install_generation = g_state.install_generation.load(std::memory_order_acquire);
	result.session_id = g_state.pg_session_id.load(std::memory_order_acquire);
	result.target_pid = g_state.target_pid.load(std::memory_order_acquire);
	result.hunting = g_state.hunting.load(std::memory_order_acquire);
	result.worker_active = g_state.worker_active.load(std::memory_order_acquire);
	result.install_complete = g_state.install_complete.load(std::memory_order_acquire);
	result.install_success = g_state.install_success.load(std::memory_order_acquire);
	result.total_reads = g_state.total_reads.load(std::memory_order_acquire);
	result.idle = !result.hunting && !result.worker_active;
	result.elapsed_ms = elapsed_ms;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		result.nodes = g_state.nodes.size();
		result.events = g_state.event_log.size();
		result.status_text = g_state.status_text;
	}
	return result;
}

namespace detail {

struct rip_stats_t {
	uint64_t rip = 0;
	int      count = 0;
	uint64_t first_seen = 0;
	uint64_t last_seen = 0;
	std::string disasm;
	std::string module;
};

inline std::string find_module_for_addr(uint64_t addr)
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (addr >= m.base && addr < m.base + m.size) {
			char buf[256];
			std::snprintf(buf, sizeof(buf), "%s+0x%llX",
			              m.name.c_str(),
			              static_cast<unsigned long long>(addr - m.base));
			return buf;
		}
	}
	return {};
}

inline uint64_t find_compare_near_rip(uint64_t rip)
{
	std::vector<uint8_t> code;
	driver_bridge::read_memory(rip, 64, code);
	if (code.empty()) return 0;

	uint64_t scan_addr = rip;
	int pos = 0;
	int count = 0;

	while (pos < static_cast<int>(code.size()) - 1 && count < 20) {
		int avail = static_cast<int>(code.size()) - pos;
		if (avail < 1) break;

		AsmInstr ins = zydis_decode_one(code.data() + pos, avail, scan_addr);
		if (ins.len == 0) break;

		std::string mnem(ins.mnem);
		for (auto& c : mnem) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

		if (mnem == "cmp" || mnem == "test") {
			return scan_addr;
		}

		pos += ins.len;
		scan_addr += static_cast<uint64_t>(ins.len);
		++count;
	}

	return 0;
}

inline void find_loop_bounds(uint64_t rip, uint64_t& loop_start, uint64_t& loop_end)
{
	loop_start = rip;
	loop_end = rip;

	std::vector<uint8_t> code;
	uint64_t scan_base = (rip > 0x80) ? rip - 0x80 : 0;
	driver_bridge::read_memory(scan_base, 0x100, code);
	if (code.empty()) return;

	uint64_t addr = scan_base;
	int pos = 0;
	int count = 0;

	while (pos < static_cast<int>(code.size()) - 1 && count < 100) {
		int avail = static_cast<int>(code.size()) - pos;
		if (avail < 1) break;

		AsmInstr ins = zydis_decode_one(code.data() + pos, avail, addr);
		if (ins.len == 0) { ++pos; ++addr; continue; }

		if (ins.is_ret || ins.is_call) {
			if (addr < rip) loop_start = addr + static_cast<uint64_t>(ins.len);
			if (addr > rip && loop_end == rip) loop_end = addr;
		}

		std::string mnem(ins.mnem);
		for (auto& c : mnem) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
		bool is_jcc = (mnem.size() >= 2 && mnem[0] == 'j' && mnem != "jmp");
		if (is_jcc && addr > rip) {
			int64_t rel = 0;
			bool decoded = false;
			if (ins.len == 2) {
				int8_t rel8 = 0;
				std::memcpy(&rel8, code.data() + pos + 1, 1);
				rel = static_cast<int64_t>(rel8);
				decoded = true;
			} else if (ins.len == 6) {
				int32_t rel32 = 0;
				std::memcpy(&rel32, code.data() + pos + 2, 4);
				rel = static_cast<int64_t>(rel32);
				decoded = true;
			}
			if (decoded) {
				uint64_t next_rip = addr + static_cast<uint64_t>(ins.len);
				uint64_t target = next_rip + static_cast<uint64_t>(rel);
				if (target < rip) {
					loop_start = target;
					loop_end = next_rip;
					return;
				}
			}
		}

		pos += ins.len;
		addr += static_cast<uint64_t>(ins.len);
		++count;
	}
}

inline std::vector<uint64_t> walk_callstack(uint64_t rbp, int max_depth)
{
	std::vector<uint64_t> stack;
	uint64_t current_rbp = rbp;

	for (int i = 0; i < max_depth && current_rbp != 0; ++i) {
		std::vector<uint8_t> frame;
		driver_bridge::read_memory(current_rbp, 16, frame);
		if (frame.size() < 16) break;

		uint64_t saved_rbp = 0;
		uint64_t ret_addr = 0;
		std::memcpy(&saved_rbp, frame.data(), 8);
		std::memcpy(&ret_addr, frame.data() + 8, 8);

		if (ret_addr == 0) break;

		uint64_t top16 = ret_addr >> 48;
		if (top16 != 0x0000 && top16 != 0x7FFF) break;

		stack.push_back(ret_addr);

		if (saved_rbp != 0 && saved_rbp <= current_rbp) break;

		current_rbp = saved_rbp;
	}

	return stack;
}

struct capture_batch_stats_t {
	size_t captures = 0;
	size_t processed = 0;
	size_t filtered_range = 0;
	size_t skipped_writes = 0;
	size_t accepted_reads = 0;
	size_t node_count = 0;
	size_t event_count = 0;
};

inline capture_batch_stats_t process_capture_batch(std::vector<page_guard_engine::pg_capture_t>& captures,
	uint64_t target_address,
	uint64_t target_size,
	std::map<uint64_t, rip_stats_t>& rip_stats,
	uint64_t& total,
	const std::chrono::steady_clock::time_point& start_time,
	uint64_t generation,
	uint32_t pg_session,
	const char* stage,
	bool cancel_seen)
{
	capture_batch_stats_t stats;
	stats.captures = captures.size();
	const uint64_t target_end = target_address + target_size;

	for (auto& cap : captures) {
		++stats.processed;
		if (cap.fault_addr < target_address || cap.fault_addr >= target_end) {
			++stats.filtered_range;
			continue;
		}

		if (cap.access_type == 1) {
			++stats.skipped_writes;
			continue;
		}

		++stats.accepted_reads;
		++total;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.event_log.size() < 10000) {
				capture_event_t evt;
				evt.rip = cap.rip;
				evt.fault_addr = cap.fault_addr;
				evt.timestamp = cap.timestamp;
				evt.access_type = cap.access_type;
				g_state.event_log.push_back(evt);
			}
		}

		auto it = rip_stats.find(cap.rip);
		if (it == rip_stats.end()) {
			rip_stats_t rip_stat;
			rip_stat.rip = cap.rip;
			rip_stat.count = 1;
			rip_stat.first_seen = cap.timestamp;
			rip_stat.last_seen = cap.timestamp;

			std::vector<uint8_t> code;
			driver_bridge::read_memory(cap.rip, 16, code);
			if (!code.empty()) {
				AsmInstr ins = zydis_decode_one(code.data(), static_cast<int>(code.size()), cap.rip);
				char dbuf[192];
				std::snprintf(dbuf, sizeof(dbuf), "%s %s", ins.mnem, ins.ops);
				rip_stat.disasm = dbuf;
			}

			rip_stat.module = find_module_for_addr(cap.rip);
			rip_stats[cap.rip] = rip_stat;
		} else {
			it->second.count++;
			it->second.last_seen = cap.timestamp;
		}
	}

	g_state.total_reads.store(total);

	const auto now = std::chrono::steady_clock::now();
	const auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.nodes.clear();

		for (auto& [rip, rip_stat] : rip_stats) {
			if (rip_stat.count < 2) continue;

			integrity_node_t node;
			node.reader_rip = rip;
			node.read_count = rip_stat.count;
			node.disasm_text = rip_stat.disasm;
			node.module_name = rip_stat.module;

			if (elapsed_s > 0) {
				node.reads_per_second = static_cast<float>(rip_stat.count) /
				    static_cast<float>(elapsed_s);
			}

			node.hash_compare_addr = find_compare_near_rip(rip);
			find_loop_bounds(rip, node.loop_start, node.loop_end);

			g_state.nodes.push_back(node);
		}

		std::sort(g_state.nodes.begin(), g_state.nodes.end(),
		          [](const integrity_node_t& a, const integrity_node_t& b) {
			          return a.read_count > b.read_count;
		          });

		g_state.status_text = "Monitoring: " + std::to_string(total) + " reads, " +
		    std::to_string(g_state.nodes.size()) + " unique readers";
		stats.node_count = g_state.nodes.size();
		stats.event_count = g_state.event_log.size();
	}

	diag::log_tagged_fmt("integrity_hunter",
		"capture_batch stage=%s gen=%llu session=%u captures=%zu processed=%zu filtered_range=%zu skipped_writes=%zu accepted_reads=%zu total_reads=%llu nodes=%zu events=%zu cancel=%d",
		stage ? stage : "",
		static_cast<unsigned long long>(generation),
		pg_session,
		stats.captures,
		stats.processed,
		stats.filtered_range,
		stats.skipped_writes,
		stats.accepted_reads,
		static_cast<unsigned long long>(total),
		stats.node_count,
		stats.event_count,
		cancel_seen ? 1 : 0);

	return stats;
}

}

inline bool start_hunt(uint64_t target_address, uint64_t target_size)
{
	bool expected = false;
	if (!g_state.hunting.compare_exchange_strong(expected, true)) {
		diag::log_tagged("integrity_hunter", "start_skip reason=already_hunting");
		return false;
	}

	if (target_address == 0 || target_size == 0 ||
	    target_size > (std::numeric_limits<uint64_t>::max() - target_address)) {
		diag::log_tagged_fmt("integrity_hunter",
			"start_reject reason=invalid_range target=0x%llX size=0x%llX",
			static_cast<unsigned long long>(target_address),
			static_cast<unsigned long long>(target_size));
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.status_text = "Invalid integrity hunter target range";
		g_state.hunting.store(false);
		return false;
	}

	uint32_t pid = driver_bridge::attached_pid();
	if (pid == 0) {
		diag::log_tagged("integrity_hunter", "start_reject reason=no_attached_pid");
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.status_text = "Attach to a process first";
		g_state.hunting.store(false);
		return false;
	}

	g_state.cancel.store(false);
	g_state.worker_active.store(true);
	g_state.install_complete.store(false);
	g_state.install_success.store(false);
	g_state.total_reads.store(0);
	g_state.target_address = target_address;
	g_state.target_size = target_size;
	g_state.target_pid.store(pid);
	const uint64_t generation = g_state.generation.fetch_add(1, std::memory_order_acq_rel) + 1;
	g_state.install_generation.store(generation, std::memory_order_release);

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.nodes.clear();
		g_state.event_log.clear();
		g_state.pg_session_id.store(0);
		g_state.status_text = "Installing page guard...";
	}

	diag::log_tagged_fmt("integrity_hunter",
		"start_hunt pid=%u target=0x%llX size=0x%llX gen=%llu",
		pid, static_cast<unsigned long long>(target_address),
		static_cast<unsigned long long>(target_size),
		static_cast<unsigned long long>(generation));

	auto worker = [target_address, target_size, pid, generation]() {
		uint64_t page_base = target_address & ~0xFFFULL;
		uint64_t page_end = (target_address + target_size + 0xFFF) & ~0xFFFULL;
		uint64_t region_size = page_end - page_base;

		if (g_state.cancel.load()) {
			diag::log_tagged_fmt("integrity_hunter",
				"worker_cancelled_before_install gen=%llu target=0x%llX",
				static_cast<unsigned long long>(generation),
				static_cast<unsigned long long>(target_address));
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.status_text = "Cancelled before installing page guard";
			g_state.install_success.store(false);
			g_state.install_generation.store(generation, std::memory_order_release);
			g_state.install_complete.store(true);
			g_state.worker_active.store(false);
			g_state.hunting.store(false);
			return;
		}

		uint32_t pg_session = page_guard_engine::g_pg_engine.install(
			pid,
			page_base,
			region_size,
			false,
			k_integrity_hunter_max_records_per_drain,
			false);
		if (pg_session == 0) {
			diag::log_tagged_fmt("integrity_hunter",
				"page_guard_install_fail gen=%llu target=0x%llX page_base=0x%llX size=0x%llX cancelled=%d",
				static_cast<unsigned long long>(generation),
				static_cast<unsigned long long>(target_address),
				static_cast<unsigned long long>(page_base),
				static_cast<unsigned long long>(region_size),
				g_state.cancel.load() ? 1 : 0);
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.status_text = "Failed to install page guard";
			g_state.install_success.store(false);
			g_state.install_generation.store(generation, std::memory_order_release);
			g_state.install_complete.store(true);
			g_state.worker_active.store(false);
			g_state.hunting.store(false);
			return;
		}

		diag::log_tagged_fmt("integrity_hunter",
			"page_guard_installed gen=%llu session=%u page_base=0x%llX size=0x%llX payloads=0 max_drain=%u auto_poll=0",
			static_cast<unsigned long long>(generation), pg_session, static_cast<unsigned long long>(page_base),
			static_cast<unsigned long long>(region_size),
			k_integrity_hunter_max_records_per_drain);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.pg_session_id.store(pg_session);
			g_state.status_text = "Monitoring for integrity checkers...";
		}
		g_state.install_success.store(true);
		g_state.install_generation.store(generation, std::memory_order_release);
		g_state.install_complete.store(true);

		std::map<uint64_t, detail::rip_stats_t> rip_stats;
		uint64_t total = 0;
		auto start_time = std::chrono::steady_clock::now();

		while (true) {
			std::this_thread::sleep_for(std::chrono::milliseconds(50));

			const bool capture_hunting_before = g_state.hunting.load(std::memory_order_acquire);
			const bool capture_worker_before = g_state.worker_active.load(std::memory_order_acquire);
			const bool capture_cancel_before = g_state.cancel.load(std::memory_order_acquire);
			const uint64_t capture_total_before = total;
			const auto capture_t0 = std::chrono::steady_clock::now();
			diag::log_tagged_fmt("integrity_hunter",
				"get_captures_begin gen=%llu session=%u hunting=%d worker_active=%d cancel=%d total_before=%llu",
				static_cast<unsigned long long>(generation),
				pg_session,
				capture_hunting_before ? 1 : 0,
				capture_worker_before ? 1 : 0,
				capture_cancel_before ? 1 : 0,
				static_cast<unsigned long long>(capture_total_before));
			auto captures = page_guard_engine::g_pg_engine.get_captures(pg_session);
			const auto capture_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - capture_t0).count();
			diag::log_tagged_fmt("integrity_hunter",
				"get_captures_done gen=%llu session=%u captures=%zu elapsed_ms=%lld hunting=%d worker_active=%d cancel=%d total_before=%llu",
				static_cast<unsigned long long>(generation),
				pg_session,
				captures.size(),
				static_cast<long long>(capture_elapsed),
				g_state.hunting.load(std::memory_order_acquire) ? 1 : 0,
				g_state.worker_active.load(std::memory_order_acquire) ? 1 : 0,
				g_state.cancel.load(std::memory_order_acquire) ? 1 : 0,
				static_cast<unsigned long long>(capture_total_before));
			const bool cancel_seen = g_state.cancel.load(std::memory_order_acquire);
			if (cancel_seen) {
				diag::log_tagged_fmt("integrity_hunter",
					"worker_cancel_seen gen=%llu session=%u pending_captures=%zu total_before=%llu",
					static_cast<unsigned long long>(generation),
					pg_session,
					captures.size(),
					static_cast<unsigned long long>(total));
			}

			const auto batch_stats = detail::process_capture_batch(captures,
				target_address,
				target_size,
				rip_stats,
				total,
				start_time,
				generation,
				pg_session,
				"poll",
				cancel_seen);
			if (cancel_seen) {
				diag::log_tagged_fmt("integrity_hunter",
					"worker_cancel_drain_done gen=%llu session=%u processed=%zu filtered_range=%zu skipped_writes=%zu accepted_reads=%zu total_after=%llu nodes=%zu events=%zu",
					static_cast<unsigned long long>(generation),
					pg_session,
					batch_stats.processed,
					batch_stats.filtered_range,
					batch_stats.skipped_writes,
					batch_stats.accepted_reads,
					static_cast<unsigned long long>(total),
					batch_stats.node_count,
					batch_stats.event_count);
				break;
			}
		}

		const auto final_drain_t0 = std::chrono::steady_clock::now();
		auto final_captures = page_guard_engine::g_pg_engine.get_captures(pg_session);
		const auto final_drain_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - final_drain_t0).count();
		const bool final_cancel_seen = g_state.cancel.load(std::memory_order_acquire);
		const auto final_stats = detail::process_capture_batch(final_captures,
			target_address,
			target_size,
			rip_stats,
			total,
			start_time,
			generation,
			pg_session,
			"final_pre_uninstall",
			final_cancel_seen);
		diag::log_tagged_fmt("integrity_hunter",
			"final_drain_done gen=%llu session=%u captures=%zu processed=%zu filtered_range=%zu skipped_writes=%zu accepted_reads=%zu total_after=%llu nodes=%zu events=%zu elapsed_ms=%lld cancel=%d",
			static_cast<unsigned long long>(generation),
			pg_session,
			final_stats.captures,
			final_stats.processed,
			final_stats.filtered_range,
			final_stats.skipped_writes,
			final_stats.accepted_reads,
			static_cast<unsigned long long>(total),
			final_stats.node_count,
			final_stats.event_count,
			static_cast<long long>(final_drain_elapsed),
			final_cancel_seen ? 1 : 0);

		size_t nodes_before_uninstall = 0;
		size_t events_before_uninstall = 0;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			nodes_before_uninstall = g_state.nodes.size();
			events_before_uninstall = g_state.event_log.size();
		}
		const auto uninstall_t0 = std::chrono::steady_clock::now();
		diag::log_tagged_fmt("integrity_hunter",
			"uninstall_begin gen=%llu session=%u hunting=%d worker_active=%d cancel=%d install_complete=%d install_success=%d nodes=%zu events=%zu total_reads=%llu",
			static_cast<unsigned long long>(generation),
			pg_session,
			g_state.hunting.load(std::memory_order_acquire) ? 1 : 0,
			g_state.worker_active.load(std::memory_order_acquire) ? 1 : 0,
			g_state.cancel.load(std::memory_order_acquire) ? 1 : 0,
			g_state.install_complete.load(std::memory_order_acquire) ? 1 : 0,
			g_state.install_success.load(std::memory_order_acquire) ? 1 : 0,
			nodes_before_uninstall,
			events_before_uninstall,
			static_cast<unsigned long long>(g_state.total_reads.load(std::memory_order_acquire)));
		const bool uninstall_ok = page_guard_engine::g_pg_engine.uninstall(pg_session);
		const auto uninstall_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - uninstall_t0).count();
		diag::log_tagged_fmt("integrity_hunter",
			"uninstall_done gen=%llu session=%u ok=%d elapsed_ms=%lld hunting=%d worker_active=%d cancel=%d install_complete=%d install_success=%d",
			static_cast<unsigned long long>(generation),
			pg_session,
			uninstall_ok ? 1 : 0,
			static_cast<long long>(uninstall_elapsed),
			g_state.hunting.load(std::memory_order_acquire) ? 1 : 0,
			g_state.worker_active.load(std::memory_order_acquire) ? 1 : 0,
			g_state.cancel.load(std::memory_order_acquire) ? 1 : 0,
			g_state.install_complete.load(std::memory_order_acquire) ? 1 : 0,
			g_state.install_success.load(std::memory_order_acquire) ? 1 : 0);

		size_t final_nodes = 0;
		uint64_t final_reads = g_state.total_reads.load();
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.pg_session_id.store(0);
			final_nodes = g_state.nodes.size();
			g_state.status_text = "Stopped. Found " + std::to_string(final_nodes) + " integrity checkers.";
		}

		diag::log_tagged_fmt("integrity_hunter",
			"hunt_done gen=%llu nodes=%zu total_reads=%llu uninstall_ok=%d",
			static_cast<unsigned long long>(generation),
			final_nodes, static_cast<unsigned long long>(final_reads),
			uninstall_ok ? 1 : 0);

		g_state.worker_active.store(false);
		g_state.hunting.store(false);
		diag::log_tagged_fmt("integrity_hunter",
			"worker_state_cleared gen=%llu session=%u hunting=%d worker_active=%d cancel=%d install_complete=%d install_success=%d uninstall_ok=%d",
			static_cast<unsigned long long>(generation),
			pg_session,
			g_state.hunting.load(std::memory_order_acquire) ? 1 : 0,
			g_state.worker_active.load(std::memory_order_acquire) ? 1 : 0,
			g_state.cancel.load(std::memory_order_acquire) ? 1 : 0,
			g_state.install_complete.load(std::memory_order_acquire) ? 1 : 0,
			g_state.install_success.load(std::memory_order_acquire) ? 1 : 0,
			uninstall_ok ? 1 : 0);
	};
	const bool run_install_inline = target_size <= 4096;
	if (run_install_inline) {
		diag::log_tagged_fmt("integrity_hunter",
			"start_queue_worker target=0x%llX size=0x%llX gen=%llu",
			static_cast<unsigned long long>(target_address),
			static_cast<unsigned long long>(target_size),
			static_cast<unsigned long long>(generation));
		if (critical_work_queue::post(worker) || work_queue::post(worker))
			return true;
		const auto cq = critical_work_queue::stats();
		const auto wq = work_queue::stats();
		diag::log_tagged_fmt("integrity_hunter",
			"start_reject reason=worker_post_failed gen=%llu cq_alive=%d cq_shutdown=%d cq_pending=%llu cq_active=%u cq_rejected=%llu wq_alive=%d wq_shutdown=%d wq_pending=%llu wq_active=%u wq_rejected=%llu",
			static_cast<unsigned long long>(generation),
			cq.alive ? 1 : 0,
			cq.shutting_down ? 1 : 0,
			static_cast<unsigned long long>(cq.pending),
			cq.active,
			static_cast<unsigned long long>(cq.rejected),
			wq.alive ? 1 : 0,
			wq.shutting_down ? 1 : 0,
			static_cast<unsigned long long>(wq.pending),
			wq.active,
			static_cast<unsigned long long>(wq.rejected));
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.status_text = "Failed to queue integrity hunter worker";
		g_state.worker_active.store(false);
		g_state.install_success.store(false);
		g_state.install_generation.store(generation, std::memory_order_release);
		g_state.install_complete.store(true);
		g_state.hunting.store(false);
		return false;
	}
	const bool posted = critical_work_queue::post(worker) || work_queue::post(std::move(worker));
	if (!posted) {
		diag::log_tagged_fmt("integrity_hunter",
			"start_reject reason=worker_post_failed gen=%llu",
			static_cast<unsigned long long>(generation));
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.status_text = "Failed to queue integrity hunter worker";
		g_state.worker_active.store(false);
		g_state.install_success.store(false);
		g_state.install_generation.store(generation, std::memory_order_release);
		g_state.install_complete.store(true);
		g_state.hunting.store(false);
		return false;
	}
	return true;
}

inline void stop_hunt()
{
	size_t nodes = 0;
	size_t events = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		nodes = g_state.nodes.size();
		events = g_state.event_log.size();
	}
	diag::log_tagged_fmt("integrity_hunter",
		"stop_hunt_requested hunting=%d worker_active=%d install_complete=%d install_success=%d session=%u nodes=%zu events=%zu total_reads=%llu",
		g_state.hunting.load(std::memory_order_acquire) ? 1 : 0,
		g_state.worker_active.load(std::memory_order_acquire) ? 1 : 0,
		g_state.install_complete.load(std::memory_order_acquire) ? 1 : 0,
		g_state.install_success.load(std::memory_order_acquire) ? 1 : 0,
		g_state.pg_session_id.load(std::memory_order_acquire),
		nodes,
		events,
		static_cast<unsigned long long>(g_state.total_reads.load(std::memory_order_acquire)));
	g_state.cancel.store(true);
}

inline idle_result_t wait_until_idle_result(uint32_t timeout_ms)
{
	const auto start = std::chrono::steady_clock::now();
	while (g_state.hunting.load() || g_state.worker_active.load()) {
		if (timeout_ms != 0) {
			const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - start).count();
			if (elapsed >= timeout_ms) {
				diag::log_tagged_fmt("integrity_hunter",
					"wait_idle_timeout timeout_ms=%u elapsed_ms=%lld hunting=%d worker_active=%d install_complete=%d install_success=%d session=%u",
					timeout_ms,
					static_cast<long long>(elapsed),
					g_state.hunting.load() ? 1 : 0,
					g_state.worker_active.load() ? 1 : 0,
					g_state.install_complete.load() ? 1 : 0,
					g_state.install_success.load() ? 1 : 0,
					g_state.pg_session_id.load());
				return snapshot_idle_state(static_cast<int64_t>(elapsed));
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(25));
	}
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - start).count();
	auto result = snapshot_idle_state(static_cast<int64_t>(elapsed));
	diag::log_tagged_fmt("integrity_hunter",
		"wait_idle_success timeout_ms=%u elapsed_ms=%lld hunting=%d worker_active=%d install_complete=%d install_success=%d session=%u nodes=%zu events=%zu total_reads=%llu",
		timeout_ms,
		static_cast<long long>(elapsed),
		result.hunting ? 1 : 0,
		result.worker_active ? 1 : 0,
		result.install_complete ? 1 : 0,
		result.install_success ? 1 : 0,
		result.session_id,
		result.nodes,
		result.events,
		static_cast<unsigned long long>(result.total_reads));
	return result;
}

inline bool wait_until_idle(uint32_t timeout_ms)
{
	return wait_until_idle_result(timeout_ms).idle;
}

inline bool neutralize(int node_index)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	if (node_index < 0 || node_index >= static_cast<int>(g_state.nodes.size())) {
		diag::log_tagged_fmt("integrity_hunter",
			"neutralize_reject reason=bad_index index=%d size=%zu",
			node_index, g_state.nodes.size());
		return false;
	}

	auto& node = g_state.nodes[static_cast<size_t>(node_index)];
	if (node.neutralized) {
		diag::log_tagged_fmt("integrity_hunter",
			"neutralize_skip reason=already_neutralized index=%d", node_index);
		return true;
	}

	uint64_t patch_addr = node.hash_compare_addr;
	if (patch_addr == 0) patch_addr = node.reader_rip;

	std::vector<uint8_t> code;
	driver_bridge::read_memory(patch_addr, 32, code);
	if (code.empty()) {
		diag::log_tagged_fmt("integrity_hunter",
			"neutralize_fail reason=read_failed addr=0x%llX",
			static_cast<unsigned long long>(patch_addr));
		return false;
	}

	uint64_t scan_addr = patch_addr;
	int pos = 0;
	int count = 0;

	while (pos < static_cast<int>(code.size()) - 1 && count < 15) {
		int avail = static_cast<int>(code.size()) - pos;
		if (avail < 1) break;

		AsmInstr ins = zydis_decode_one(code.data() + pos, avail, scan_addr);
		if (ins.len == 0) break;

		std::string mnem(ins.mnem);
		for (auto& c : mnem) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

		bool is_jcc = (mnem.size() >= 2 && mnem[0] == 'j' && mnem != "jmp");
		if (is_jcc) {
			node.original_bytes.assign(code.data() + pos, code.data() + pos + ins.len);
			node.patch_addr = scan_addr;

			if (ins.len < 2 || ins.len > 6) {
				diag::log_tagged_fmt("integrity_hunter",
					"neutralize_fail reason=bad_jcc_len addr=0x%llX len=%d",
					static_cast<unsigned long long>(scan_addr), ins.len);
				return false;
			}

			std::vector<uint8_t> patch(static_cast<size_t>(ins.len), 0x90);
			if (!driver_bridge::write_memory(scan_addr, patch)) {
				diag::log_tagged_fmt("integrity_hunter",
					"neutralize_fail reason=write_failed addr=0x%llX len=%d",
					static_cast<unsigned long long>(scan_addr), ins.len);
				return false;
			}

			node.neutralized = true;
			diag::log_tagged_fmt("integrity_hunter",
				"integrity_hunter_hit kind=patched_jcc index=%d addr=0x%llX rip=0x%llX len=%d module='%s'",
				node_index,
				static_cast<unsigned long long>(scan_addr),
				static_cast<unsigned long long>(node.reader_rip),
				ins.len, node.module_name.c_str());
			return true;
		}

		pos += ins.len;
		scan_addr += static_cast<uint64_t>(ins.len);
		++count;
	}

	diag::log_tagged_fmt("integrity_hunter",
		"neutralize_fail reason=no_jcc_found index=%d start=0x%llX",
		node_index, static_cast<unsigned long long>(patch_addr));
	return false;
}

inline bool restore(int node_index)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	if (node_index < 0 || node_index >= static_cast<int>(g_state.nodes.size()))
		return false;

	auto& node = g_state.nodes[static_cast<size_t>(node_index)];
	if (!node.neutralized || node.original_bytes.empty() || node.patch_addr == 0)
		return false;

	std::vector<uint8_t> current;
	driver_bridge::read_memory(node.patch_addr, node.original_bytes.size(), current);
	if (current.size() != node.original_bytes.size())
		return false;

	if (!driver_bridge::write_memory(node.patch_addr, node.original_bytes))
		return false;

	node.neutralized = false;
	node.original_bytes.clear();
	node.patch_addr = 0;
	return true;
}

}
