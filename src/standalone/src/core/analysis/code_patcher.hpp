#pragma once

#include "standalone_driver.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

namespace code_patcher {

struct patch_entry_t {
	uint64_t             address = 0;
	std::vector<uint8_t> original_bytes;
	std::vector<uint8_t> patched_bytes;
	std::string          description;
	bool                 active = false;
	int64_t              timestamp = 0;
};

struct code_cave_t {
	uint64_t    address = 0;
	uint64_t    size = 0;
	std::string module_name;
};

struct state_t {
	std::vector<patch_entry_t> patches;
	std::mutex                 mtx;
};

inline state_t g_state;

inline int64_t current_timestamp() {
	return std::chrono::duration_cast<std::chrono::seconds>(
		std::chrono::system_clock::now().time_since_epoch()).count();
}

inline std::string format_bytes(const std::vector<uint8_t>& bytes) {
	std::string out;
	out.reserve(bytes.size() * 3);
	for (size_t i = 0; i < bytes.size(); ++i) {
		if (i > 0) out += ' ';
		char hex[4];
		std::snprintf(hex, sizeof(hex), "%02X", bytes[i]);
		out += hex;
	}
	return out;
}

inline std::vector<uint8_t> parse_bytes(const std::string& hex_str) {
	std::vector<uint8_t> out;
	size_t i = 0;
	while (i < hex_str.size()) {
		while (i < hex_str.size() && (hex_str[i] == ' ' || hex_str[i] == '\t'))
			++i;
		if (i >= hex_str.size()) break;
		if (i + 1 >= hex_str.size()) break;
		char hi = hex_str[i];
		char lo = hex_str[i + 1];
		auto hex_val = [](char c) -> int {
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return 10 + c - 'a';
			if (c >= 'A' && c <= 'F') return 10 + c - 'A';
			return -1;
		};
		int h = hex_val(hi);
		int l = hex_val(lo);
		if (h < 0 || l < 0) break;
		out.push_back(static_cast<uint8_t>((h << 4) | l));
		i += 2;
	}
	return out;
}

inline size_t count() {
	std::lock_guard<std::mutex> lk(g_state.mtx);
	return g_state.patches.size();
}

inline size_t active_count() {
	std::lock_guard<std::mutex> lk(g_state.mtx);
	size_t n = 0;
	for (const auto& p : g_state.patches)
		if (p.active) ++n;
	return n;
}

inline bool resolve_patch_index(int index, std::vector<patch_entry_t>::size_type size,
								std::vector<patch_entry_t>::size_type& resolved) {
	if (index < 0)
		return false;
	resolved = static_cast<std::vector<patch_entry_t>::size_type>(index);
	return resolved < size;
}

inline int create_patch(uint64_t address, const std::vector<uint8_t>& new_bytes,
						const std::string& description) {
	if (!driver_bridge::is_loaded()) return -1;
	if (new_bytes.empty()) return -1;

	std::vector<uint8_t> orig;
	if (!driver_bridge::read_memory(address, new_bytes.size(), orig))
		return -1;

	patch_entry_t entry;
	entry.address = address;
	entry.original_bytes = std::move(orig);
	entry.patched_bytes = new_bytes;
	entry.description = description;
	entry.active = false;
	entry.timestamp = current_timestamp();

	std::lock_guard<std::mutex> lk(g_state.mtx);
	if (g_state.patches.size() >= static_cast<std::vector<patch_entry_t>::size_type>(
			(std::numeric_limits<int>::max)()))
		return -1;
	const auto index = g_state.patches.size();
	g_state.patches.push_back(std::move(entry));
	return static_cast<int>(index);
}

inline bool apply_patch(int index) {
	if (!driver_bridge::is_loaded()) return false;
	std::lock_guard<std::mutex> lk(g_state.mtx);
	std::vector<patch_entry_t>::size_type resolved = 0;
	if (!resolve_patch_index(index, g_state.patches.size(), resolved))
		return false;
	auto& p = g_state.patches[resolved];
	if (p.active) return true;
	if (!driver_bridge::write_memory(p.address, p.patched_bytes))
		return false;
	p.active = true;
	return true;
}

inline bool revert_patch(int index) {
	if (!driver_bridge::is_loaded()) return false;
	std::lock_guard<std::mutex> lk(g_state.mtx);
	std::vector<patch_entry_t>::size_type resolved = 0;
	if (!resolve_patch_index(index, g_state.patches.size(), resolved))
		return false;
	auto& p = g_state.patches[resolved];
	if (!p.active) return true;
	if (!driver_bridge::write_memory(p.address, p.original_bytes))
		return false;
	p.active = false;
	return true;
}

inline bool toggle_patch(int index) {
	bool is_active = false;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		std::vector<patch_entry_t>::size_type resolved = 0;
		if (!resolve_patch_index(index, g_state.patches.size(), resolved))
			return false;
		is_active = g_state.patches[resolved].active;
	}
	if (is_active)
		return revert_patch(index);
	return apply_patch(index);
}

inline bool remove_patch(int index) {
	bool need_revert = false;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		std::vector<patch_entry_t>::size_type resolved = 0;
		if (!resolve_patch_index(index, g_state.patches.size(), resolved))
			return false;
		need_revert = g_state.patches[resolved].active;
	}
	if (need_revert)
		revert_patch(index);
	std::lock_guard<std::mutex> lk(g_state.mtx);
	std::vector<patch_entry_t>::size_type resolved = 0;
	if (!resolve_patch_index(index, g_state.patches.size(), resolved))
		return false;
	g_state.patches.erase(g_state.patches.begin() +
		static_cast<std::vector<patch_entry_t>::difference_type>(resolved));
	return true;
}

inline bool nop_region(uint64_t address, size_t size, const std::string& description) {
	std::vector<uint8_t> nops(size, 0x90);
	return create_patch(address, nops, description) >= 0;
}

inline std::vector<code_cave_t> find_code_caves(uint64_t module_base, uint32_t module_size,
												size_t min_cave_size) {
	std::vector<code_cave_t> caves;
	if (!driver_bridge::is_loaded()) return caves;
	if (module_size == 0 || min_cave_size == 0) return caves;

	std::string mod_name;
	auto mods = driver_bridge::enumerate_modules();
	for (const auto& m : mods) {
		if (m.base == module_base) {
			mod_name = m.name;
			break;
		}
	}

	static constexpr size_t CHUNK_SIZE = 0x10000;
	size_t remaining = module_size;
	uint64_t addr = module_base;

	uint64_t pending_run_start = 0;
	size_t   pending_run_len = 0;
	bool     pending_run_active = false;

	while (remaining > 0) {
		size_t read_size = std::min<size_t>(remaining, CHUNK_SIZE);
		std::vector<uint8_t> chunk;
		if (!driver_bridge::read_memory(addr, read_size, chunk)) {
			if (pending_run_active && pending_run_len >= min_cave_size) {
				code_cave_t cave;
				cave.address = pending_run_start;
				cave.size = pending_run_len;
				cave.module_name = mod_name;
				caves.push_back(std::move(cave));
			}
			pending_run_active = false;
			pending_run_len = 0;
			break;
		}
		if (chunk.empty()) {
			if (pending_run_active && pending_run_len >= min_cave_size) {
				code_cave_t cave;
				cave.address = pending_run_start;
				cave.size = pending_run_len;
				cave.module_name = mod_name;
				caves.push_back(std::move(cave));
			}
			pending_run_active = false;
			pending_run_len = 0;
			break;
		}

		for (size_t i = 0; i < chunk.size(); ++i) {
			bool is_filler = (chunk[i] == 0x00 || chunk[i] == 0xCC);
			if (is_filler) {
				if (!pending_run_active) {
					pending_run_start = addr + i;
					pending_run_len = 0;
					pending_run_active = true;
				}
				++pending_run_len;
			} else {
				if (pending_run_active && pending_run_len >= min_cave_size) {
					code_cave_t cave;
					cave.address = pending_run_start;
					cave.size = pending_run_len;
					cave.module_name = mod_name;
					caves.push_back(std::move(cave));
				}
				pending_run_active = false;
				pending_run_len = 0;
			}
		}

		addr += chunk.size();
		if (chunk.size() >= remaining)
			remaining = 0;
		else
			remaining -= chunk.size();
	}

	if (pending_run_active && pending_run_len >= min_cave_size) {
		code_cave_t cave;
		cave.address = pending_run_start;
		cave.size = pending_run_len;
		cave.module_name = mod_name;
		caves.push_back(std::move(cave));
	}

	return caves;
}

}
