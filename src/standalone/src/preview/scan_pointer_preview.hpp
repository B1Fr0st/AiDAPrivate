#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "scan_preview_runtime.hpp"

namespace pointer_scanner {

struct pointer_data_t {
	std::uint64_t address = 0;
	bool is_static = false;
	int module_index = -1;
	std::uint64_t module_offset = 0;
};

struct pointer_chain_t {
	int module_index = -1;
	std::string module_name;
	std::uint64_t base_offset = 0;
	std::vector<std::int64_t> offsets;
	int depth = 0;
	bool is_static = false;
	bool validated = false;
};

struct scan_config_t {
	std::uint64_t target_address = 0;
	int max_depth = 4;
	std::int64_t max_offset = 4096;
	std::int64_t struct_size = 4096;
	bool negative_offsets = false;
	bool only_static_bases = true;
};

struct map_diagnostics_t {
	std::uint32_t pid = 0;
	std::size_t module_count = 0;
	std::size_t raw_region_count = 0;
	std::size_t scanned_region_count = 0;
	std::uint64_t scanned_bytes = 0;
	std::size_t candidate_pointer_count = 0;
	std::size_t map_key_count = 0;
	std::size_t map_entry_count = 0;
	std::uint64_t duration_ms = 0;
	bool cancelled = false;
	std::string source;
};

struct scan_diagnostics_t {
	std::uint32_t pid = 0;
	std::uint64_t target_address = 0;
	int max_depth = 0;
	std::int64_t max_offset = 0;
	std::int64_t struct_size = 0;
	bool negative_offsets = false;
	bool only_static_bases = false;
	std::size_t map_key_count = 0;
	std::size_t map_entry_count = 0;
	std::size_t chain_count = 0;
	std::uint64_t duration_ms = 0;
	bool cancelled = false;
};

struct module_info_t {
	std::uint64_t base = 0;
	std::uint64_t size = 0;
	std::string name;
	std::string path;
};

struct state_t {
	std::map<std::uint64_t, std::vector<pointer_data_t>> reverse_map;
	std::mutex map_mutex;
	std::atomic<bool> map_building{false};
	std::atomic<float> map_progress{0.f};
	std::atomic<bool> map_cancel{false};
	std::size_t map_entry_count = 0;
	std::vector<pointer_chain_t> results;
	std::mutex results_mutex;
	std::atomic<bool> scanning{false};
	std::atomic<float> scan_progress{0.f};
	std::atomic<bool> scan_cancel{false};
	std::atomic<bool> validating{false};
	std::atomic<float> validate_progress{0.f};
	scan_config_t config;
	std::vector<module_info_t> cached_modules;
	map_diagnostics_t last_map_diagnostics;
	scan_diagnostics_t last_scan_diagnostics;
	int selected_result = -1;
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	char addr_buf[20] = "7FF7A4C4F2A0";
};

inline state_t g_state;

inline void build_reverse_map()
{
	std::lock_guard<std::mutex> lock(g_state.map_mutex);
	g_state.map_building.store(true);
	g_state.cached_modules = {
		{0x00007FF7A4C00000, 0x1A0000, "sample.exe", "C:/Samples/sample.exe"},
		{0x00007FFDA1700000, 0x1F0000, "KERNEL32.DLL", "C:/Windows/System32/KERNEL32.DLL"}
	};
	g_state.reverse_map = {
		{0x000001D42A900F40, {{0x00007FF7A4C8D1B8, true, 0, 0x8D1B8}}},
		{0x000001D42A9012A0, {{0x000001D42A900F58, false, -1, 0}}},
		{0x00007FF7A4C4F2A0, {{0x000001D42A9012C8, false, -1, 0}}}
	};
	g_state.map_entry_count = 3;
	g_state.last_map_diagnostics = {6420, 2, 146, 118, 0x2F40000, 98624, 3, 3, 84, false, "Studio fixture"};
	g_state.map_progress.store(1.f);
	g_state.map_building.store(false);
	aida::preview::scan::record("pointer.map", "3 reverse links");
}

inline void start_scan()
{
	if (g_state.reverse_map.empty()) build_reverse_map();
	g_state.scanning.store(true);
	std::lock_guard<std::mutex> lock(g_state.results_mutex);
	const std::uint64_t target = g_state.config.target_address ? g_state.config.target_address : 0x00007FF7A4C4F2A0;
	g_state.config.target_address = target;
	g_state.results = {
		{0, "sample.exe", 0x8D1B8, {0x18, 0x40, 0x28}, 3, true, true},
		{0, "sample.exe", 0x9A3F0, {0x30, 0x10, 0x68, 0x20}, 4, true, true},
		{-1, "heap", 0x000001D42A8F7010, {0x88, 0x20}, 2, false, false}
	};
	g_state.last_scan_diagnostics = {6420, target, g_state.config.max_depth, g_state.config.max_offset,
		g_state.config.struct_size, g_state.config.negative_offsets, g_state.config.only_static_bases,
		g_state.reverse_map.size(), g_state.map_entry_count, g_state.results.size(), 16, false};
	g_state.scan_progress.store(1.f);
	g_state.scanning.store(false);
	aida::preview::scan::record("pointer.scan", std::to_string(target));
}

inline bool validate_chain(const pointer_chain_t& chain)
{
	return !chain.offsets.empty();
}

inline void validate_all_results()
{
	g_state.validating.store(true);
	std::lock_guard<std::mutex> lock(g_state.results_mutex);
	for (auto& chain : g_state.results) chain.validated = validate_chain(chain);
	g_state.validate_progress.store(1.f);
	g_state.validating.store(false);
	aida::preview::scan::record("pointer.validate", std::to_string(g_state.results.size()));
}

inline std::string chain_to_string(const pointer_chain_t& chain)
{
	std::ostringstream output;
	output << (chain.module_name.empty() ? "address" : chain.module_name) << "+0x" << std::hex << chain.base_offset;
	for (std::int64_t offset : chain.offsets)
		output << (offset >= 0 ? " -> +0x" : " -> -0x") << std::hex << (offset >= 0 ? offset : -offset);
	return output.str();
}

inline std::string export_chain_cpp(const pointer_chain_t& chain)
{
	return "resolve_pointer_chain(\"" + chain.module_name + "\", 0x" + [] (std::uint64_t value) {
		char buffer[24]{};
		std::snprintf(buffer, sizeof(buffer), "%llX", static_cast<unsigned long long>(value));
		return std::string(buffer);
	}(chain.base_offset) + ")";
}

inline std::string export_results_json()
{
	return "{\"chains\":" + std::to_string(g_state.results.size()) + "}";
}

inline void cancel_all()
{
	g_state.map_cancel.store(true);
	g_state.scan_cancel.store(true);
	g_state.map_building.store(false);
	g_state.scanning.store(false);
	g_state.validating.store(false);
	aida::preview::scan::record("pointer.cancel", {});
}

inline void clear_results()
{
	std::lock_guard<std::mutex> lock(g_state.results_mutex);
	g_state.results.clear();
	g_state.selected_result = -1;
	aida::preview::scan::record("pointer.clear_results", {});
}

inline void clear_map()
{
	std::lock_guard<std::mutex> lock(g_state.map_mutex);
	g_state.reverse_map.clear();
	g_state.map_entry_count = 0;
	aida::preview::scan::record("pointer.clear_map", {});
}

}
