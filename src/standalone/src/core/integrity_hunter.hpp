#pragma once

#include <atomic>
#include "work_queue.hpp"
#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "page_guard_engine.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"

namespace integrity_hunter {

struct integrity_node_t {
	uint64_t reader_rip = 0;
	uint64_t hash_compare_addr = 0;
	uint64_t loop_start = 0;
	uint64_t loop_end = 0;
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
	std::atomic<uint64_t> total_reads{0};
	uint32_t pg_session_id = 0;
	uint64_t target_address = 0;
	uint64_t target_size = 0;
	char address_input[32] = {};
	char size_input[16] = "4096";
	std::string status_text;
};

inline state_t g_state;

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
			if (ins.len >= 2) {
				int8_t rel8 = 0;
				std::memcpy(&rel8, code.data() + pos + 1, 1);
				uint64_t target = addr + static_cast<uint64_t>(ins.len) + static_cast<uint64_t>(rel8);
				if (target < rip) {
					loop_start = target;
					loop_end = addr + static_cast<uint64_t>(ins.len);
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
		current_rbp = saved_rbp;

		if (saved_rbp <= current_rbp && saved_rbp != 0) break;
	}

	return stack;
}

}

inline void start_hunt(uint64_t target_address, uint64_t target_size)
{
	if (g_state.hunting.load()) return;

	uint32_t pid = driver_bridge::attached_pid();
	if (pid == 0) return;

	g_state.hunting.store(true);
	g_state.cancel.store(false);
	g_state.total_reads.store(0);
	g_state.target_address = target_address;
	g_state.target_size = target_size;

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.nodes.clear();
		g_state.event_log.clear();
		g_state.status_text = "Installing page guard...";
	}

	work_queue::post([target_address, target_size, pid]() {
		uint64_t page_base = target_address & ~0xFFFULL;
		uint64_t page_end = (target_address + target_size + 0xFFF) & ~0xFFFULL;
		uint64_t region_size = page_end - page_base;

		uint32_t pg_session = page_guard_engine::g_pg_engine.install(pid, page_base, region_size);
		if (pg_session == 0) {
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.status_text = "Failed to install page guard";
			g_state.hunting.store(false);
			return;
		}

		g_state.pg_session_id = pg_session;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.status_text = "Monitoring for integrity checkers...";
		}

		std::map<uint64_t, detail::rip_stats_t> rip_stats;
		uint64_t total = 0;
		auto start_time = std::chrono::steady_clock::now();

		while (!g_state.cancel.load()) {
			std::this_thread::sleep_for(std::chrono::milliseconds(50));

			auto captures = page_guard_engine::g_pg_engine.get_captures(pg_session);

			for (auto& cap : captures) {
				if (cap.fault_addr < target_address ||
				    cap.fault_addr >= target_address + target_size)
					continue;

				if (cap.access_type == 1) continue;

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
					detail::rip_stats_t stats;
					stats.rip = cap.rip;
					stats.count = 1;
					stats.first_seen = cap.timestamp;
					stats.last_seen = cap.timestamp;

					std::vector<uint8_t> code;
					driver_bridge::read_memory(cap.rip, 16, code);
					if (!code.empty()) {
						AsmInstr ins = zydis_decode_one(code.data(),
						    static_cast<int>(code.size()), cap.rip);
						char dbuf[192];
						std::snprintf(dbuf, sizeof(dbuf), "%s %s", ins.mnem, ins.ops);
						stats.disasm = dbuf;
					}

					stats.module = detail::find_module_for_addr(cap.rip);
					rip_stats[cap.rip] = stats;
				} else {
					it->second.count++;
					it->second.last_seen = cap.timestamp;
				}
			}

			g_state.total_reads.store(total);

			auto now = std::chrono::steady_clock::now();
			auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

			{
				std::lock_guard<std::mutex> lk(g_state.mutex);
				g_state.nodes.clear();

				for (auto& [rip, stats] : rip_stats) {
					if (stats.count < 2) continue;

					integrity_node_t node;
					node.reader_rip = rip;
					node.read_count = stats.count;
					node.disasm_text = stats.disasm;
					node.module_name = stats.module;

					if (elapsed_s > 0) {
						node.reads_per_second = static_cast<float>(stats.count) /
						    static_cast<float>(elapsed_s);
					}

					node.hash_compare_addr = detail::find_compare_near_rip(rip);
					detail::find_loop_bounds(rip, node.loop_start, node.loop_end);

					g_state.nodes.push_back(node);
				}

				std::sort(g_state.nodes.begin(), g_state.nodes.end(),
				          [](const integrity_node_t& a, const integrity_node_t& b) {
					          return a.read_count > b.read_count;
				          });

				g_state.status_text = "Monitoring: " + std::to_string(total) + " reads, " +
				    std::to_string(g_state.nodes.size()) + " unique readers";
			}
		}

		page_guard_engine::g_pg_engine.uninstall(pg_session);
		g_state.pg_session_id = 0;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.status_text = "Stopped. Found " + std::to_string(g_state.nodes.size()) + " integrity checkers.";
		}

		g_state.hunting.store(false);
	});
}

inline void stop_hunt()
{
	g_state.cancel.store(true);
}

inline bool neutralize(int node_index)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	if (node_index < 0 || node_index >= static_cast<int>(g_state.nodes.size()))
		return false;

	auto& node = g_state.nodes[static_cast<size_t>(node_index)];
	if (node.neutralized) return true;

	uint64_t patch_addr = node.hash_compare_addr;
	if (patch_addr == 0) patch_addr = node.reader_rip;

	std::vector<uint8_t> code;
	driver_bridge::read_memory(patch_addr, 32, code);
	if (code.empty()) return false;

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

			if (ins.len == 2) {
				std::vector<uint8_t> nops(2, 0x90);
				driver_bridge::write_memory(scan_addr, nops);
			} else if (ins.len == 6) {
				std::vector<uint8_t> patch = {0xE9, 0x00, 0x00, 0x00, 0x00, 0x90};
				int32_t rel = 0;
				std::memcpy(&rel, code.data() + pos + 2, 4);
				std::memcpy(patch.data() + 1, &rel, 4);
				driver_bridge::write_memory(scan_addr, patch);
			} else {
				std::vector<uint8_t> nops(static_cast<size_t>(ins.len), 0x90);
				driver_bridge::write_memory(scan_addr, nops);
			}

			node.neutralized = true;
			return true;
		}

		pos += ins.len;
		scan_addr += static_cast<uint64_t>(ins.len);
		++count;
	}

	return false;
}

inline bool restore(int node_index)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);

	if (node_index < 0 || node_index >= static_cast<int>(g_state.nodes.size()))
		return false;

	auto& node = g_state.nodes[static_cast<size_t>(node_index)];
	if (!node.neutralized || node.original_bytes.empty()) return false;

	uint64_t patch_addr = node.hash_compare_addr;
	if (patch_addr == 0) patch_addr = node.reader_rip;

	std::vector<uint8_t> code;
	driver_bridge::read_memory(patch_addr, 32, code);
	if (code.empty()) return false;

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

		bool is_nop = (mnem == "nop");
		bool is_jmp = (mnem == "jmp");

		if ((is_nop || is_jmp) && ins.len == static_cast<int>(node.original_bytes.size())) {
			driver_bridge::write_memory(scan_addr, node.original_bytes);
			node.neutralized = false;
			node.original_bytes.clear();
			return true;
		}

		pos += ins.len;
		scan_addr += static_cast<uint64_t>(ins.len);
		++count;
	}

	return false;
}

}
