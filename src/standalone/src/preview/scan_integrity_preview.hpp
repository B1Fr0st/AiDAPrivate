#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "scan_preview_runtime.hpp"

namespace integrity_hunter {

inline constexpr std::uint32_t k_integrity_hunter_max_records_per_drain = 0;

struct integrity_node_t {
	std::uint64_t reader_rip = 0;
	std::uint64_t hash_compare_addr = 0;
	std::uint64_t loop_start = 0;
	std::uint64_t loop_end = 0;
	std::uint64_t patch_addr = 0;
	int read_count = 0;
	float reads_per_second = 0.f;
	std::string module_name;
	std::string disasm_text;
	bool neutralized = false;
	std::vector<std::uint8_t> original_bytes;
	std::vector<std::uint64_t> callstack;
};

struct capture_event_t {
	std::uint64_t rip = 0;
	std::uint64_t fault_addr = 0;
	std::uint64_t timestamp = 0;
	std::uint32_t access_type = 0;
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
	std::atomic<std::uint64_t> total_reads{0};
	std::atomic<std::uint64_t> generation{0};
	std::atomic<std::uint64_t> install_generation{0};
	std::atomic<std::uint64_t> stop_request_tick_ms{0};
	std::atomic<std::uint64_t> worker_cancel_tick_ms{0};
	std::atomic<std::uint64_t> uninstall_begin_tick_ms{0};
	std::atomic<std::uint64_t> uninstall_end_tick_ms{0};
	std::atomic<std::uint64_t> worker_exit_tick_ms{0};
	std::atomic<std::uint64_t> last_uninstall_elapsed_ms{0};
	std::atomic<std::uint32_t> pg_session_id{0};
	std::atomic<std::uint32_t> target_pid{0};
	std::uint64_t target_address = 0;
	std::uint64_t target_size = 0;
	char address_input[32] = "00007FF7A4C12000";
	char size_input[16] = "4096";
	std::string status_text = "Ready to capture integrity readers";
};

inline state_t g_state;

inline bool start_hunt(std::uint64_t address, std::uint64_t size)
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.target_address = address;
	g_state.target_size = size;
	g_state.nodes = {
		{address + 0x16A, address + 0x178, address + 0x148, address + 0x186,
			address + 0x178, 1842, 122.8f, "sample.exe", "cmp rax, rdx", false,
			{0x48, 0x3B, 0xC2}, {address + 0x16A, address + 0xA20, address + 0xF50}},
		{address + 0x4B0, address + 0x4D2, address + 0x498, address + 0x4E8,
			address + 0x4D2, 716, 47.7f, "sample.exe", "test eax, eax", false,
			{0x85, 0xC0}, {address + 0x4B0, address + 0x1120}},
		{address + 0x8C0, address + 0x8E6, address + 0x8A0, address + 0x910,
			address + 0x8E6, 298, 19.9f, "ntdll.dll", "jne short integrity_fail", false,
			{0x75, 0x18}, {address + 0x8C0}}
	};
	g_state.event_log = {
		{address + 0x16A, address + 0x20, 1710000001, 0},
		{address + 0x4B0, address + 0x118, 1710000016, 0},
		{address + 0x8C0, address + 0x2D0, 1710000032, 0}
	};
	g_state.total_reads.store(2856);
	g_state.target_pid.store(6420);
	g_state.install_complete.store(true);
	g_state.install_success.store(true);
	g_state.hunting.store(true);
	g_state.status_text = "Capturing integrity readers from 3 hot paths";
	aida::preview::scan::record("integrity.start", std::to_string(address));
	return true;
}

inline void stop_hunt()
{
	g_state.hunting.store(false);
	g_state.worker_active.store(false);
	g_state.status_text = "Capture stopped; results remain available";
	aida::preview::scan::record("integrity.stop", std::to_string(g_state.nodes.size()));
}

inline bool neutralize(int index)
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	if (index < 0 || index >= static_cast<int>(g_state.nodes.size())) return false;
	g_state.nodes[static_cast<std::size_t>(index)].neutralized = true;
	aida::preview::scan::record("integrity.neutralize", std::to_string(index));
	return true;
}

inline bool restore(int index)
{
	std::lock_guard<std::mutex> lock(g_state.mutex);
	if (index < 0 || index >= static_cast<int>(g_state.nodes.size())) return false;
	g_state.nodes[static_cast<std::size_t>(index)].neutralized = false;
	aida::preview::scan::record("integrity.restore", std::to_string(index));
	return true;
}

}
