#pragma once

#include "standalone_driver.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
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
	std::uint32_t        target_pid = 0;
};

struct code_cave_t {
	uint64_t    address = 0;
	uint64_t    size = 0;
	std::string module_name;
};

struct patch_snapshot_row_t {
	std::uint64_t address = 0;
	std::size_t patched_size = 0;
	std::string original;
	std::string patched;
	std::string description;
	bool active = false;
};

struct patch_snapshot_t {
	std::uint64_t generation = 1;
	std::size_t total_count = 0;
	std::vector<patch_snapshot_row_t> rows;
};

struct state_t {
	std::vector<patch_entry_t> patches;
	std::mutex                 mtx;
	std::atomic<std::uint64_t> generation{1};
	std::atomic<std::uint64_t> publication_failure_generation{0};
	std::shared_ptr<const patch_snapshot_t> publication =
		std::make_shared<const patch_snapshot_t>();
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

inline std::string format_bytes_preview(const std::vector<uint8_t>& bytes) {
	constexpr std::size_t k_max_characters = 22;
	std::string out;
	out.reserve(k_max_characters + 3);
	for (std::size_t i = 0; i < bytes.size(); ++i) {
		const std::size_t required = i == 0 ? 2U : 3U;
		if (out.size() + required > k_max_characters) {
			out.append("...");
			break;
		}
		if (i > 0) out.push_back(' ');
		char hex[4];
		std::snprintf(hex, sizeof(hex), "%02X", bytes[i]);
		out.append(hex);
	}
	return out;
}

inline void publish_snapshot_locked() noexcept {
	constexpr std::size_t k_max_rows = 4096;
	const std::uint64_t next_generation =
		g_state.generation.fetch_add(1, std::memory_order_acq_rel) + 1;
	try {
		auto next = std::make_shared<patch_snapshot_t>();
		next->generation = next_generation;
		next->total_count = g_state.patches.size();
		const std::size_t row_count = (std::min)(g_state.patches.size(), k_max_rows);
		next->rows.reserve(row_count);
		for (std::size_t i = 0; i < row_count; ++i) {
			const auto& patch = g_state.patches[i];
			patch_snapshot_row_t row;
			row.address = patch.address;
			row.patched_size = patch.patched_bytes.size();
			row.original = format_bytes_preview(patch.original_bytes);
			row.patched = format_bytes_preview(patch.patched_bytes);
			row.description = patch.description;
			row.active = patch.active;
			next->rows.push_back(std::move(row));
		}
		std::shared_ptr<const patch_snapshot_t> immutable = std::move(next);
		std::atomic_store_explicit(&g_state.publication, std::move(immutable),
			std::memory_order_release);
		g_state.publication_failure_generation.store(0, std::memory_order_release);
	} catch (...) {
		g_state.publication_failure_generation.store(next_generation,
			std::memory_order_release);
	}
}

inline std::shared_ptr<const patch_snapshot_t> published_snapshot() {
	return std::atomic_load_explicit(&g_state.publication, std::memory_order_acquire);
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline const bool g_preview_patch_publication_initialized = [] {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (g_state.patches.empty()) {
		g_state.patches = {
			{0x00007FF7A4C16A32, {0x75, 0x14}, {0x90, 0x90}, "Bypass conditional branch", true, 1720946700, 0},
			{0x00007FF7A4C1B420, {0x48, 0x85, 0xC0}, {0xB0, 0x01, 0x90}, "Force decrypt success", false, 1720946760, 0},
			{0x00007FF7A4C208F0, {0x74, 0x05}, {0xEB, 0x05}, "Follow unpacked path", true, 1720946820, 0}
		};
		publish_snapshot_locked();
	}
	return true;
}();
#endif

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

	const std::uint32_t target_pid = driver_bridge::attached_pid();
	if (target_pid == 0) return -1;
	std::vector<uint8_t> orig;
	if (!driver_bridge::read_memory(address, new_bytes.size(), orig) ||
		driver_bridge::attached_pid() != target_pid)
		return -1;

	patch_entry_t entry;
	entry.address = address;
	entry.original_bytes = std::move(orig);
	entry.patched_bytes = new_bytes;
	entry.description = description;
	entry.active = false;
	entry.timestamp = current_timestamp();
	entry.target_pid = target_pid;

	std::lock_guard<std::mutex> lk(g_state.mtx);
	if (g_state.patches.size() >= static_cast<std::vector<patch_entry_t>::size_type>(
			(std::numeric_limits<int>::max)()))
		return -1;
	const auto index = g_state.patches.size();
	g_state.patches.push_back(std::move(entry));
	publish_snapshot_locked();
	return static_cast<int>(index);
}

inline int create_patch_exact(uint64_t address,
							 const std::vector<uint8_t>& expected_before,
							 const std::vector<uint8_t>& new_bytes,
							 std::uint32_t expected_pid,
							 const std::string& description) {
	if (expected_pid == 0 || !driver_bridge::is_loaded() ||
		driver_bridge::attached_pid() != expected_pid || expected_before.empty() ||
		new_bytes.empty() || expected_before.size() != new_bytes.size()) return -1;
	std::vector<uint8_t> current;
	if (!driver_bridge::read_memory(address, expected_before.size(), current) ||
		driver_bridge::attached_pid() != expected_pid ||
		current != expected_before) return -1;
	patch_entry_t entry;
	entry.address = address;
	entry.original_bytes = std::move(current);
	entry.patched_bytes = new_bytes;
	entry.description = description;
	entry.active = false;
	entry.timestamp = current_timestamp();
	entry.target_pid = expected_pid;
	std::lock_guard<std::mutex> lk(g_state.mtx);
	if (g_state.patches.size() >= static_cast<std::vector<patch_entry_t>::size_type>(
			(std::numeric_limits<int>::max)())) return -1;
	const auto index = g_state.patches.size();
	g_state.patches.push_back(std::move(entry));
	publish_snapshot_locked();
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
	if (p.target_pid != 0 && driver_bridge::attached_pid() != p.target_pid) return false;
	std::vector<uint8_t> current;
	if (!driver_bridge::read_memory(p.address, p.original_bytes.size(), current) ||
		(p.target_pid != 0 && driver_bridge::attached_pid() != p.target_pid) ||
		current != p.original_bytes) return false;
	if (!driver_bridge::write_memory(p.address, p.patched_bytes))
		return false;
	p.active = true;
	publish_snapshot_locked();
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
	if (p.target_pid != 0 && driver_bridge::attached_pid() != p.target_pid) return false;
	std::vector<uint8_t> current;
	if (!driver_bridge::read_memory(p.address, p.patched_bytes.size(), current) ||
		(p.target_pid != 0 && driver_bridge::attached_pid() != p.target_pid) ||
		current != p.patched_bytes) return false;
	if (!driver_bridge::write_memory(p.address, p.original_bytes))
		return false;
	p.active = false;
	publish_snapshot_locked();
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
	std::lock_guard<std::mutex> lk(g_state.mtx);
	std::vector<patch_entry_t>::size_type resolved = 0;
	if (!resolve_patch_index(index, g_state.patches.size(), resolved))
		return false;
	const auto& patch = g_state.patches[resolved];
	if (patch.active && (!driver_bridge::is_loaded() ||
		(patch.target_pid != 0 && driver_bridge::attached_pid() != patch.target_pid) ||
		!driver_bridge::write_memory(patch.address, patch.original_bytes)))
		return false;
	g_state.patches.erase(g_state.patches.begin() +
		static_cast<std::vector<patch_entry_t>::difference_type>(resolved));
	publish_snapshot_locked();
	return true;
}

inline bool remove_patch_exact(int index, uint64_t expected_address,
							   const std::vector<uint8_t>& expected_bytes) {
	std::lock_guard<std::mutex> lk(g_state.mtx);
	std::vector<patch_entry_t>::size_type resolved = 0;
	if (!resolve_patch_index(index, g_state.patches.size(), resolved))
		return false;
	const auto& patch = g_state.patches[resolved];
	if (patch.address != expected_address || patch.patched_bytes != expected_bytes)
		return false;
	if (patch.active && (!driver_bridge::is_loaded() ||
		(patch.target_pid != 0 && driver_bridge::attached_pid() != patch.target_pid) ||
		!driver_bridge::write_memory(patch.address, patch.original_bytes)))
		return false;
	g_state.patches.erase(g_state.patches.begin() +
		static_cast<std::vector<patch_entry_t>::difference_type>(resolved));
	publish_snapshot_locked();
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
