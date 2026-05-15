#pragma once

#include <algorithm>
#include "work_queue.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <shlobj.h>
#include <commdlg.h>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"

extern DisasmState g_disasm;

namespace snapshot_diff {

struct memory_region_t {
	uint64_t             base = 0;
	uint64_t             size = 0;
	uint32_t             protect = 0;
	std::vector<uint8_t> data;
};

struct snapshot_t {
	uint64_t                   id = 0;
	std::string                name;
	uint32_t                   pid = 0;
	int64_t                    timestamp = 0;
	std::vector<memory_region_t> regions;
	uint64_t                   total_bytes = 0;
};

enum class change_type_t : int {
	unknown = 0,
	pointer_changed,
	float_changed,
	counter_incremented,
	counter_decremented,
	string_modified,
	zeroed_out,
	byte_flip,
};

struct changed_region_t {
	uint64_t             address = 0;
	uint32_t             size = 0;
	std::vector<uint8_t> old_data;
	std::vector<uint8_t> new_data;
	change_type_t        type = change_type_t::unknown;
	std::string          module_name;
};

struct diff_result_t {
	std::string                  snap_a_name;
	std::string                  snap_b_name;
	std::vector<changed_region_t> changes;
	uint64_t                     total_changed_bytes = 0;
	size_t                       changed_page_count = 0;
};

struct state_t {
	std::vector<snapshot_t>     snapshots;
	uint64_t                    snap_a_id = 0;
	uint64_t                    snap_b_id = 0;
	diff_result_t               diff;
	std::mutex                  mutex;
	std::atomic<bool>           capturing{false};
	std::atomic<bool>           comparing{false};
	std::atomic<bool>           loading{false};
	std::atomic<float>          progress{0.f};
	std::atomic<bool>           cancel{false};
	int                         snap_counter = 0;
	std::atomic<uint64_t>       next_snap_id{1};
	std::string                 last_error;

	int                         selected_change = -1;
	float                       scroll_y = 0.f;
	float                       target_scroll_y = 0.f;
	char                        filter_buf[128] = {};
	uint64_t                    filter_min_addr = 0;
	uint64_t                    filter_max_addr = 0;
	bool                        show_only_changes = true;

	int                         dragging_marker = -1;
	float                       compare_cursor_t = 0.f;
	bool                        compare_cursor_active = false;
	std::unordered_set<uint64_t> prev_change_keys;
	std::vector<float>           row_flash;
};

inline state_t g_state;

inline const std::string& last_error()
{
	return g_state.last_error;
}

namespace detail {

inline std::filesystem::path snapshot_dir()
{
	wchar_t* appdata = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
		auto p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"snapshots";
		CoTaskMemFree(appdata);
		return p;
	}
	return std::filesystem::current_path() / "snapshots";
}

inline change_type_t classify_change(const uint8_t* old_data, const uint8_t* new_data, uint32_t size)
{
	bool all_zero_new = true;
	for (uint32_t i = 0; i < size; ++i)
		if (new_data[i] != 0) { all_zero_new = false; break; }
	if (all_zero_new) return change_type_t::zeroed_out;

	if (size == 4) {
		float old_f, new_f;
		std::memcpy(&old_f, old_data, 4);
		std::memcpy(&new_f, new_data, 4);
		if (std::isfinite(old_f) && std::isfinite(new_f) &&
		    std::abs(old_f) < 1e12f && std::abs(new_f) < 1e12f)
			return change_type_t::float_changed;

		int32_t old_i, new_i;
		std::memcpy(&old_i, old_data, 4);
		std::memcpy(&new_i, new_data, 4);
		if (new_i == old_i + 1) return change_type_t::counter_incremented;
		if (new_i == old_i - 1) return change_type_t::counter_decremented;
	}

	if (size == 8) {
		uint64_t old_val, new_val;
		std::memcpy(&old_val, old_data, 8);
		std::memcpy(&new_val, new_data, 8);
		if (old_val > 0x10000 && new_val > 0x10000 &&
		    old_val < 0x00007FFFFFFFFFFF && new_val < 0x00007FFFFFFFFFFF)
			return change_type_t::pointer_changed;
	}

	if (size >= 4) {
		bool is_string = true;
		for (uint32_t i = 0; i < size; ++i) {
			if (old_data[i] == 0) break;
			if (old_data[i] < 0x20 || old_data[i] > 0x7E) { is_string = false; break; }
		}
		if (is_string) return change_type_t::string_modified;
	}

	if (size == 1) return change_type_t::byte_flip;

	return change_type_t::unknown;
}

inline const char* change_type_name(change_type_t t)
{
	switch (t) {
	case change_type_t::pointer_changed:     return "Pointer";
	case change_type_t::float_changed:       return "Float";
	case change_type_t::counter_incremented: return "Counter++";
	case change_type_t::counter_decremented: return "Counter--";
	case change_type_t::string_modified:     return "String";
	case change_type_t::zeroed_out:          return "Zeroed";
	case change_type_t::byte_flip:           return "Byte";
	default:                                 return "Unknown";
	}
}

inline aida::ui::components::pill_kind_t change_pill_kind(change_type_t t)
{
	switch (t) {
	case change_type_t::pointer_changed:     return aida::ui::components::pill_kind_t::warning;
	case change_type_t::float_changed:       return aida::ui::components::pill_kind_t::info;
	case change_type_t::counter_incremented: return aida::ui::components::pill_kind_t::success;
	case change_type_t::counter_decremented: return aida::ui::components::pill_kind_t::success;
	case change_type_t::string_modified:     return aida::ui::components::pill_kind_t::accent;
	case change_type_t::zeroed_out:          return aida::ui::components::pill_kind_t::error;
	case change_type_t::byte_flip:           return aida::ui::components::pill_kind_t::neutral;
	default:                                 return aida::ui::components::pill_kind_t::neutral;
	}
}

inline void save_snapshot(const snapshot_t& snap)
{
	auto dir = snapshot_dir();
	std::filesystem::create_directories(dir);

	char fname[128];
	snprintf(fname, sizeof(fname), "%s_%lld.bin", snap.name.c_str(), static_cast<long long>(snap.timestamp));
	auto path = dir / fname;

	std::ofstream ofs(path, std::ios::binary);
	if (!ofs.is_open()) return;

	uint32_t name_len = static_cast<uint32_t>(snap.name.size());
	ofs.write(reinterpret_cast<const char*>(&name_len), 4);
	ofs.write(snap.name.data(), name_len);
	ofs.write(reinterpret_cast<const char*>(&snap.pid), 4);
	ofs.write(reinterpret_cast<const char*>(&snap.timestamp), 8);
	uint32_t region_count = static_cast<uint32_t>(snap.regions.size());
	ofs.write(reinterpret_cast<const char*>(&region_count), 4);

	for (auto& r : snap.regions) {
		ofs.write(reinterpret_cast<const char*>(&r.base), 8);
		uint64_t rsize = r.data.size();
		ofs.write(reinterpret_cast<const char*>(&rsize), 8);
		ofs.write(reinterpret_cast<const char*>(&r.protect), 4);
		if (rsize > 0)
			ofs.write(reinterpret_cast<const char*>(r.data.data()), static_cast<std::streamsize>(rsize));
	}
}

inline bool load_snapshot(const std::string& path, snapshot_t& out)
{
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs.is_open()) {
		g_state.last_error = "load_snapshot: failed to open file";
		return false;
	}

	uint32_t name_len = 0;
	if (!ifs.read(reinterpret_cast<char*>(&name_len), 4)) {
		g_state.last_error = "load_snapshot: failed reading name length";
		return false;
	}
	if (name_len > 0x10000u) {
		g_state.last_error = "load_snapshot: implausible name length";
		return false;
	}

	std::string name;
	name.resize(name_len);
	if (name_len > 0) {
		if (!ifs.read(name.data(), static_cast<std::streamsize>(name_len))) {
			g_state.last_error = "load_snapshot: failed reading name";
			return false;
		}
	}

	uint32_t pid = 0;
	int64_t  ts = 0;
	uint32_t region_count = 0;
	if (!ifs.read(reinterpret_cast<char*>(&pid), 4) ||
	    !ifs.read(reinterpret_cast<char*>(&ts), 8) ||
	    !ifs.read(reinterpret_cast<char*>(&region_count), 4)) {
		g_state.last_error = "load_snapshot: failed reading header";
		return false;
	}

	if (region_count > 0x10000000u) {
		g_state.last_error = "load_snapshot: implausible region count";
		return false;
	}

	out = snapshot_t{};
	out.name = std::move(name);
	out.pid = pid;
	out.timestamp = ts;
	out.regions.reserve(region_count);

	for (uint32_t i = 0; i < region_count; ++i) {
		memory_region_t r;
		uint64_t rsize = 0;
		if (!ifs.read(reinterpret_cast<char*>(&r.base), 8) ||
		    !ifs.read(reinterpret_cast<char*>(&rsize), 8) ||
		    !ifs.read(reinterpret_cast<char*>(&r.protect), 4)) {
			g_state.last_error = "load_snapshot: failed reading region header";
			return false;
		}

		if (rsize > 0x10000000ULL) {
			g_state.last_error = "load_snapshot: implausible region size";
			return false;
		}

		r.size = rsize;
		if (rsize > 0) {
			r.data.resize(static_cast<size_t>(rsize));
			if (!ifs.read(reinterpret_cast<char*>(r.data.data()), static_cast<std::streamsize>(rsize))) {
				g_state.last_error = "load_snapshot: failed reading region data";
				return false;
			}
		}

		out.total_bytes += rsize;
		out.regions.push_back(std::move(r));
	}

	return true;
}

}

inline void take_snapshot(const std::string& name = "")
{
	if (g_state.capturing.load())
		return;

	g_state.capturing.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);

	std::string snap_name = name;
	if (snap_name.empty()) {
		++g_state.snap_counter;
		char buf[32];
		snprintf(buf, sizeof(buf), "Snap%d", g_state.snap_counter);
		snap_name = buf;
	}

	work_queue::post([snap_name]() {
		snapshot_t snap;
		snap.id = g_state.next_snap_id.fetch_add(1);
		snap.name = snap_name;
		snap.pid = driver_bridge::attached_pid();
		snap.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count();

		auto regions = driver_bridge::enumerate_memory_regions(4096);

		std::vector<driver_bridge::memory_region_t> readable;
		for (auto& r : regions) {
			if (r.state != 0x1000) continue;
			if (r.protect & 0x100) continue;
			uint32_t p = r.protect & 0xFF;
			if (p == 0x01 || p == 0x00) continue;
			if (r.size > 0x10000000) continue;
			readable.push_back(r);
		}

		uint64_t total = 0;
		for (auto& r : readable) total += r.size;
		if (total == 0) total = 1;
		uint64_t done = 0;

		for (auto& r : readable) {
			if (g_state.cancel.load()) break;

			memory_region_t sr;
			sr.base = r.base;
			sr.protect = r.protect;

			if (driver_bridge::read_memory(r.base, static_cast<size_t>(r.size), sr.data) && !sr.data.empty()) {
				sr.size = sr.data.size();
				snap.total_bytes += sr.data.size();
				snap.regions.push_back(std::move(sr));
			}

			done += r.size;
			g_state.progress.store(static_cast<float>(done) / static_cast<float>(total));
		}

		detail::save_snapshot(snap);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.snapshots.size() >= 10) {
				uint64_t evicted_id = g_state.snapshots.front().id;
				g_state.snapshots.erase(g_state.snapshots.begin());
				if (g_state.snap_a_id == evicted_id) g_state.snap_a_id = 0;
				if (g_state.snap_b_id == evicted_id) g_state.snap_b_id = 0;
			}
			g_state.snapshots.push_back(std::move(snap));
		}

		g_state.capturing.store(false);
	});
}

inline void load_from_disk(const std::string& path)
{
	if (g_state.loading.load() || g_state.capturing.load())
		return;

	g_state.loading.store(true);
	g_state.cancel.store(false);

	std::string fallback_name;
	{
		++g_state.snap_counter;
		char buf[32];
		snprintf(buf, sizeof(buf), "Snap%d", g_state.snap_counter);
		fallback_name = buf;
	}

	std::string path_copy = path;
	work_queue::post([path_copy, fallback_name]() {
		snapshot_t snap;
		if (!detail::load_snapshot(path_copy, snap)) {
			g_state.loading.store(false);
			return;
		}

		snap.id = g_state.next_snap_id.fetch_add(1);
		if (snap.name.empty()) {
			snap.name = fallback_name;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.snapshots.size() >= 10) {
				uint64_t evicted_id = g_state.snapshots.front().id;
				g_state.snapshots.erase(g_state.snapshots.begin());
				if (g_state.snap_a_id == evicted_id) g_state.snap_a_id = 0;
				if (g_state.snap_b_id == evicted_id) g_state.snap_b_id = 0;
			}
			g_state.snapshots.push_back(std::move(snap));
		}

		g_state.loading.store(false);
	});
}

inline void compare_snapshots(uint64_t id_a, uint64_t id_b)
{
	if (g_state.comparing.load())
		return;

	g_state.comparing.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
	g_state.compare_cursor_active = true;
	g_state.compare_cursor_t = 0.f;

	work_queue::post([id_a, id_b]() {
		diff_result_t result;

		snapshot_t snap_a, snap_b;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			const snapshot_t* p_a = nullptr;
			const snapshot_t* p_b = nullptr;
			for (auto& s : g_state.snapshots) {
				if (s.id == id_a) p_a = &s;
				if (s.id == id_b) p_b = &s;
			}
			if (p_a == nullptr || p_b == nullptr) {
				g_state.last_error = (p_a == nullptr && p_b == nullptr)
					? "compare_snapshots: both snapshots evicted"
					: (p_a == nullptr
						? "compare_snapshots: snapshot A evicted"
						: "compare_snapshots: snapshot B evicted");
				g_state.comparing.store(false);
				g_state.compare_cursor_active = false;
				return;
			}
			snap_a = *p_a;
			snap_b = *p_b;
		}

		result.snap_a_name = snap_a.name;
		result.snap_b_name = snap_b.name;

		std::unordered_map<uint64_t, size_t> b_map;
		for (size_t i = 0; i < snap_b.regions.size(); ++i)
			b_map[snap_b.regions[i].base] = i;

		auto modules = driver_bridge::enumerate_modules();

		uint64_t total = snap_a.regions.size();
		if (total == 0) total = 1;
		uint64_t done = 0;

		for (auto& ra : snap_a.regions) {
			if (g_state.cancel.load()) break;

			auto it = b_map.find(ra.base);
			if (it == b_map.end()) {
				++done;
				g_state.progress.store(static_cast<float>(done) / static_cast<float>(total));
				continue;
			}

			auto& rb = snap_b.regions[it->second];
			uint64_t cmp_size = (std::min)(ra.size, rb.size);
			uint64_t min_data = (std::min)(ra.data.size(), rb.data.size());
			if (min_data < cmp_size) cmp_size = min_data;

			uint64_t i = 0;
			while (i < cmp_size) {
				if ((i & 0xFFFFF) == 0 && g_state.cancel.load()) break;
				if (ra.data[i] == rb.data[i]) { ++i; continue; }

				uint64_t start = i;
				while (i < cmp_size && ra.data[i] != rb.data[i] && (i - start) < 64)
					++i;

				changed_region_t cr;
				cr.address = ra.base + start;
				cr.size = static_cast<uint32_t>(i - start);
				cr.old_data.assign(ra.data.begin() + start, ra.data.begin() + i);
				cr.new_data.assign(rb.data.begin() + start, rb.data.begin() + i);
				cr.type = detail::classify_change(cr.old_data.data(), cr.new_data.data(), cr.size);

				for (auto& m : modules) {
					if (cr.address >= m.base && cr.address < m.base + m.size) {
						cr.module_name = m.name;
						break;
					}
				}

				result.changes.push_back(std::move(cr));
				result.total_changed_bytes += cr.size;
			}

			++result.changed_page_count;
			++done;
			g_state.progress.store(static_cast<float>(done) / static_cast<float>(total));
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.diff = std::move(result);
			g_state.selected_change = -1;
			g_state.row_flash.clear();
		}

		g_state.comparing.store(false);
	});
}

inline void clear_snapshots()
{
	g_state.cancel.store(true);
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.snapshots.clear();
	g_state.diff = {};
	g_state.snap_a_id = 0;
	g_state.snap_b_id = 0;
	g_state.snap_counter = 0;
	g_state.prev_change_keys.clear();
	g_state.row_flash.clear();
	g_state.selected_change = -1;
}

namespace detail {

inline void render_timeline(ImDrawList* dl, float ox, float oy, float w, float h, float a)
{
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.panel_bg, a), 10.f);
	dl->AddRect(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.border_subtle, a), 10.f, 0, 1.f);

	int snap_count = 0;
	std::vector<uint64_t> snap_ids;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		snap_count = static_cast<int>(g_state.snapshots.size());
		snap_ids.reserve(static_cast<size_t>(snap_count));
		for (auto& s : g_state.snapshots) snap_ids.push_back(s.id);
	}

	float track_y = oy + h * 0.5f;
	float pad_x = 28.f;
	float track_x0 = ox + pad_x;
	float track_x1 = ox + w - pad_x;
	float track_w = track_x1 - track_x0;

	dl->AddLine(ImVec2(track_x0, track_y), ImVec2(track_x1, track_y),
		aida::ui::with_alpha(t.border_strong, a), 2.f);

	if (snap_count == 0) {
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(ox + w * 0.5f - 80.f, oy + h * 0.5f - 5.f),
			aida::ui::with_alpha(t.text_dim, a),
			"Capture snapshots to populate the timeline");
		return;
	}

	float seg = (snap_count > 1) ? track_w / static_cast<float>(snap_count - 1) : 0.f;

	int idx_a = -1;
	int idx_b = -1;
	for (int i = 0; i < snap_count; ++i) {
		if (g_state.snap_a_id != 0 && snap_ids[i] == g_state.snap_a_id) idx_a = i;
		if (g_state.snap_b_id != 0 && snap_ids[i] == g_state.snap_b_id) idx_b = i;
	}

	int hot_marker = -1;
	for (int i = 0; i < snap_count; ++i) {
		float mx = (snap_count > 1) ? (track_x0 + seg * i) : (track_x0 + track_w * 0.5f);
		float my = track_y;
		ImGui::PushID(i + 100000);
		ImGui::SetCursorScreenPos(ImVec2(mx - 12.f, my - 12.f));
		ImGui::InvisibleButton("##mk", ImVec2(24.f, 24.f));
		bool hov = ImGui::IsItemHovered();
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool clk_r = ImGui::IsItemClicked(ImGuiMouseButton_Right);
		ImGui::PopID();
		if (hov) hot_marker = i;
		uint64_t this_id = snap_ids[i];
		if (clk) {
			if (g_state.snap_a_id == this_id) g_state.snap_a_id = 0;
			else if (g_state.snap_b_id == this_id) g_state.snap_b_id = 0;
			else if (g_state.snap_a_id == 0) g_state.snap_a_id = this_id;
			else if (g_state.snap_b_id == 0) g_state.snap_b_id = this_id;
			else g_state.snap_b_id = this_id;
		}
		if (clk_r) {
			if (g_state.snap_a_id == this_id) g_state.snap_a_id = 0;
			if (g_state.snap_b_id == this_id) g_state.snap_b_id = 0;
		}
	}

	if (idx_a >= 0 && idx_a < snap_count && idx_b >= 0 && idx_b < snap_count) {
		float ax = (snap_count > 1) ? (track_x0 + seg * idx_a) : (track_x0 + track_w * 0.5f);
		float bx = (snap_count > 1) ? (track_x0 + seg * idx_b) : (track_x0 + track_w * 0.5f);
		if (ax > bx) std::swap(ax, bx);
		dl->AddRectFilledMultiColor(
			ImVec2(ax, track_y - 2.f), ImVec2(bx, track_y + 2.f),
			t.accent_grad_top, t.accent_grad_top,
			t.accent_grad_bot, t.accent_grad_bot);

		if (g_state.compare_cursor_active) {
			float dt = aida::ui::clock::dt();
			g_state.compare_cursor_t += dt * 1.4f;
			if (g_state.compare_cursor_t > 1.f) {
				g_state.compare_cursor_t = 0.f;
				if (!g_state.comparing.load()) g_state.compare_cursor_active = false;
			}
			float cx_pos = ax + (bx - ax) * g_state.compare_cursor_t;
			dl->AddCircleFilled(ImVec2(cx_pos, track_y), 5.f,
				aida::ui::with_alpha(t.accent_u32, a), 24);
			dl->AddCircle(ImVec2(cx_pos, track_y), 9.f,
				aida::ui::with_alpha(t.accent_u32, a * 0.4f), 24, 1.5f);
		}
	}

	for (int i = 0; i < snap_count; ++i) {
		float mx = (snap_count > 1) ? (track_x0 + seg * i) : (track_x0 + track_w * 0.5f);
		float my = track_y;
		bool is_a = (idx_a == i);
		bool is_b = (idx_b == i);
		bool is_hot = (hot_marker == i);

		ImU32 outer = aida::ui::with_alpha(t.panel_header, a);
		ImU32 inner = aida::ui::with_alpha(t.text_secondary, a);
		float r_outer = 7.f;
		if (is_a || is_b) {
			outer = aida::ui::with_alpha(t.accent_u32, a);
			inner = aida::ui::with_alpha(t.accent_grad_top, a);
			r_outer = 9.f;
		}
		if (is_hot) {
			r_outer += 2.f;
			dl->AddCircle(ImVec2(mx, my), r_outer + 4.f,
				aida::ui::with_alpha(t.accent_u32, a * 0.5f), 24, 1.5f);
		}

		dl->AddCircleFilled(ImVec2(mx, my), r_outer, outer, 24);
		dl->AddCircleFilled(ImVec2(mx, my), r_outer - 3.f, inner, 24);

		std::string nm;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (i < (int)g_state.snapshots.size())
				nm = g_state.snapshots[i].name;
		}
		ImVec2 ts = ImGui::CalcTextSize(nm.c_str());
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(mx - ts.x * 0.5f, my + 11.f),
			aida::ui::with_alpha(t.text_secondary, a), nm.c_str());

		if (is_a) {
			dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
				ImVec2(mx - 5.f, my - 22.f),
				aida::ui::with_alpha(t.accent_u32, a), "A");
		}
		if (is_b) {
			dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
				ImVec2(mx - 5.f, my - 22.f),
				aida::ui::with_alpha(t.accent_u32, a), "B");
		}
	}
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float, float, float)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float a = alpha;

	const auto& t = aida::ui::resolved();

	float x0 = wp.x + pos_x;
	float y0 = wp.y + pos_y;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + height),
		aida::ui::with_alpha(t.bg_base, a));

	float toolbar_h = 52.f;
	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + toolbar_h),
		aida::ui::with_alpha(t.panel_header, a));
	dl->AddLine(ImVec2(x0, y0 + toolbar_h), ImVec2(x0 + width, y0 + toolbar_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	float cx = x0 + 16.f;
	float cy = y0 + (toolbar_h - 32.f) * 0.5f;

	{
		ImFont* hdr_fn = aida::ui::fonts::body_em();
		float hdr_fs = hdr_fn ? hdr_fn->FontSize : 14.f;
		dl->AddText(hdr_fn, hdr_fs,
			ImVec2(cx, y0 + (toolbar_h - hdr_fs) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a), "Snapshot Diff");
		ImVec2 ts = ImGui::CalcTextSize("Snapshot Diff");
		cx += ts.x + 24.f;
	}

	const float btn_gap = 14.f;

	bool busy = g_state.capturing.load() || g_state.comparing.load() || g_state.loading.load();
	bool taking = g_state.capturing.load();
	bool comparing = g_state.comparing.load();
	bool loading = g_state.loading.load();

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		const char* lbl = taking ? "Capturing..." : "Take Snapshot";
		if (aida::ui::button(lbl, aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), busy, nullptr, taking)) {
			take_snapshot();
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}

	int snap_count = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		snap_count = static_cast<int>(g_state.snapshots.size());
	}

	bool can_compare = (!busy && snap_count >= 2 &&
		g_state.snap_a_id != 0 && g_state.snap_b_id != 0 &&
		g_state.snap_a_id != g_state.snap_b_id);

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		const char* lbl = comparing ? "Comparing..." : "Compare";
		if (aida::ui::button(lbl, aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), !can_compare, nullptr, comparing)) {
			compare_snapshots(g_state.snap_a_id, g_state.snap_b_id);
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Clear All", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), busy || snap_count == 0)) {
			clear_snapshots();
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		const char* lbl_load = loading ? "Loading..." : "Load";
		if (aida::ui::button(lbl_load, aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), busy, nullptr, loading)) {
			auto initial_dir = detail::snapshot_dir();
			std::error_code ec;
			std::filesystem::create_directories(initial_dir, ec);
			std::string initial_dir_str = initial_dir.string();
			work_queue::post([initial_dir_str]() {
				char path_buf[MAX_PATH] = {};
				OPENFILENAMEA ofn = {};
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = g_hwnd;
				ofn.lpstrFile = path_buf;
				ofn.nMaxFile = MAX_PATH;
				ofn.lpstrFilter = "Snapshot (*.bin)\0*.bin\0All files\0*.*\0\0";
				ofn.lpstrDefExt = "bin";
				ofn.lpstrInitialDir = initial_dir_str.c_str();
				ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
				if (GetOpenFileNameA(&ofn)) {
					load_from_disk(std::string(path_buf));
				}
			});
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}

	{
		float prog = g_state.progress.load();
		float bar_w = 180.f;
		float bar_x = x0 + width - bar_w - 16.f;
		float bar_y = y0 + (toolbar_h - 6.f) * 0.5f;
		if (busy) {
			aida::ui::render_progress_bar(ImVec2(bar_x, bar_y), bar_w, 6.f, prog, false, true);
		} else {
			char info[64];
			snprintf(info, sizeof(info), "%d snapshot%s", snap_count, snap_count == 1 ? "" : "s");
			ImVec2 ts = ImGui::CalcTextSize(info);
			dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
				ImVec2(x0 + width - ts.x - 16.f, y0 + (toolbar_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_secondary, a), info);
		}
	}

	float timeline_h = 64.f;
	detail::render_timeline(dl, x0 + 12.f, y0 + toolbar_h + 8.f,
		width - 24.f, timeline_h, a);

	float content_y = y0 + toolbar_h + 8.f + timeline_h + 8.f;
	float content_h = (y0 + height) - content_y;

	float detail_h = (g_state.selected_change >= 0) ? 180.f : 0.f;
	float table_h = content_h - detail_h;

	float col_addr_w = 130.f;
	float col_old_w = 170.f;
	float col_new_w = 170.f;
	float col_type_w = 100.f;
	float col_mod_w = width - col_addr_w - col_old_w - col_new_w - col_type_w - 36.f;
	if (col_mod_w < 60.f) col_mod_w = 60.f;

	float hdr_h = 26.f;
	dl->AddRectFilled(ImVec2(x0, content_y),
		ImVec2(x0 + width, content_y + hdr_h),
		aida::ui::with_alpha(t.panel_header, a * 0.85f));
	dl->AddLine(ImVec2(x0, content_y + hdr_h),
		ImVec2(x0 + width, content_y + hdr_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	const char* col_names[5] = { "Address", "Old Value", "New Value", "Type", "Module" };
	float col_widths[5] = { col_addr_w, col_old_w, col_new_w, col_type_w, col_mod_w };
	float hx = x0 + 12.f;
	for (int c = 0; c < 5; ++c) {
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(hx, content_y + (hdr_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), col_names[c]);
		hx += col_widths[c];
	}

	std::vector<changed_region_t> filtered;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		for (auto& c : g_state.diff.changes) {
			if (g_state.filter_min_addr != 0 && c.address < g_state.filter_min_addr) continue;
			if (g_state.filter_max_addr != 0 && c.address > g_state.filter_max_addr) continue;
			filtered.push_back(c);
		}
	}

	if (g_state.row_flash.size() < filtered.size())
		g_state.row_flash.resize(filtered.size(), 0.f);

	{
		std::unordered_set<uint64_t> current;
		current.reserve(filtered.size());
		for (auto& c : filtered) current.insert(c.address);
		bool changed = (current.size() != g_state.prev_change_keys.size());
		if (!changed) {
			for (auto k : current) {
				if (g_state.prev_change_keys.find(k) == g_state.prev_change_keys.end()) {
					changed = true; break;
				}
			}
		}
		if (changed) {
			for (size_t i = 0; i < filtered.size(); ++i) {
				if (g_state.prev_change_keys.find(filtered[i].address) == g_state.prev_change_keys.end()) {
					if (i < g_state.row_flash.size()) g_state.row_flash[i] = 1.f;
				}
			}
			g_state.prev_change_keys = std::move(current);
		}
	}

	for (auto& f : g_state.row_flash) {
		if (f > 0.f) {
			f -= aida::ui::clock::dt() * 1.66f;
			if (f < 0.f) f = 0.f;
		}
	}

	float body_y = content_y + hdr_h;
	float body_h = (table_h > hdr_h) ? (table_h - hdr_h) : 0.f;

	ImGui::SetCursorScreenPos(ImVec2(x0, body_y));
	ImGui::BeginChild("##snap_diff_table", ImVec2(width, body_h), false,
	                  ImGuiWindowFlags_NoBackground);

	static float diff_row_anim_time = 0.f;
	diff_row_anim_time += aida::ui::clock::dt();

	float row_height = 22.f;
	for (int i = 0; i < static_cast<int>(filtered.size()); ++i) {
		auto& c = filtered[i];
		ImVec2 rp = ImGui::GetCursorScreenPos();

		float entrance = ui_anim::render_row_entrance(i, diff_row_anim_time, 0.012f);
		bool hov = ImGui::IsMouseHoveringRect(rp, ImVec2(rp.x + width, rp.y + row_height), true);
		bool sel = (g_state.selected_change == i);

		if (sel) {
			dl->AddRectFilled(rp, ImVec2(rp.x + width, rp.y + row_height),
				aida::ui::with_alpha(t.selection, a * entrance));
			dl->AddRectFilled(rp, ImVec2(rp.x + 3.f, rp.y + row_height),
				aida::ui::with_alpha(t.accent_u32, a * entrance));
		} else if (hov) {
			dl->AddRectFilled(rp, ImVec2(rp.x + width, rp.y + row_height),
				aida::ui::with_alpha(t.hover_wash, a * entrance));
		} else if (i & 1) {
			dl->AddRectFilled(rp, ImVec2(rp.x + width, rp.y + row_height),
				aida::ui::with_alpha(IM_COL32(255, 255, 255, 4), a * entrance));
		}

		float flash = (i < (int)g_state.row_flash.size()) ? g_state.row_flash[i] : 0.f;
		if (flash > 0.f) {
			dl->AddRectFilled(rp, ImVec2(rp.x + width, rp.y + row_height),
				aida::ui::with_alpha(t.accent_glow, a * flash * 0.85f));
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			g_state.selected_change = i;

		char addr_str[24];
		snprintf(addr_str, sizeof(addr_str), "0x%llX", static_cast<unsigned long long>(c.address));
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(rp.x + 12.f, rp.y + (row_height - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, a * entrance), addr_str);

		float old_x = rp.x + 12.f + col_addr_w;
		std::string old_hex;
		for (uint32_t j = 0; j < c.size && j < 8; ++j) {
			char hb[4]; snprintf(hb, sizeof(hb), "%02X ", c.old_data[j]);
			old_hex += hb;
		}
		if (c.size > 8) old_hex += "...";
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(old_x, rp.y + (row_height - 12.f) * 0.5f),
			aida::ui::with_alpha(t.error, a * entrance), old_hex.c_str());

		float new_x = old_x + col_old_w;
		std::string new_hex;
		for (uint32_t j = 0; j < c.size && j < 8; ++j) {
			char hb[4]; snprintf(hb, sizeof(hb), "%02X ", c.new_data[j]);
			new_hex += hb;
		}
		if (c.size > 8) new_hex += "...";
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(new_x, rp.y + (row_height - 12.f) * 0.5f),
			aida::ui::with_alpha(t.success, a * entrance), new_hex.c_str());

		float type_x = new_x + col_new_w;
		ImGui::SetCursorScreenPos(ImVec2(type_x, rp.y + (row_height - 18.f) * 0.5f));
		ImGui::PushID(i + 8192);
		aida::ui::pill_kind(detail::change_type_name(c.type), detail::change_pill_kind(c.type),
			aida::ui::size_t_::sm, true);
		ImGui::PopID();

		float mod_x = type_x + col_type_w;
		if (!c.module_name.empty()) {
			dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
				ImVec2(mod_x, rp.y + (row_height - 11.f) * 0.5f),
				aida::ui::with_alpha(t.text_dim, a * entrance), c.module_name.c_str());
		}

		ImGui::SetCursorScreenPos(ImVec2(rp.x, rp.y + row_height));
	}

	if (filtered.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::memory;
		if (g_state.snapshots.empty()) {
			cfg.title = "No snapshots yet";
			cfg.body = "Capture two snapshots of the target process, then compare them to see what changed.";
		} else {
			cfg.title = "Pick A and B";
			cfg.body = "Click two markers on the timeline above and press Compare.";
		}
		aida::ui::empty_state::render(ImVec2(x0, body_y), ImVec2(width, body_h), cfg);
	}

	ImGui::EndChild();

	if (g_state.selected_change >= 0 && g_state.selected_change < static_cast<int>(filtered.size())) {
		auto& c = filtered[g_state.selected_change];
		float dy = y0 + height - detail_h;
		dl->AddLine(ImVec2(x0, dy), ImVec2(x0 + width, dy),
			aida::ui::with_alpha(t.border_subtle, a), 1.f);
		dl->AddRectFilled(ImVec2(x0, dy), ImVec2(x0 + width, y0 + height),
			aida::ui::with_alpha(t.panel_bg, a));

		dl->AddText(aida::ui::fonts::body_em(), 13.f,
			ImVec2(x0 + 16.f, dy + 10.f),
			aida::ui::with_alpha(t.text_primary, a), "Detail");

		char addr_info[80];
		snprintf(addr_info, sizeof(addr_info), "0x%llX  ·  %u bytes",
		         static_cast<unsigned long long>(c.address), c.size);
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(x0 + 70.f, dy + 11.f),
			aida::ui::with_alpha(t.text_secondary, a), addr_info);

		float hex_y = dy + 36.f;
		float byte_w = 26.f;
		float byte_h = 22.f;
		float row_pad_x = 16.f;

		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(x0 + row_pad_x, hex_y + (byte_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.error, a), "Old");
		float ohx = x0 + row_pad_x + 36.f;
		for (uint32_t j = 0; j < c.size && j < 32; ++j) {
			char hb[4]; snprintf(hb, sizeof(hb), "%02X", c.old_data[j]);
			bool diff = (j < c.new_data.size() && c.old_data[j] != c.new_data[j]);
			if (diff) {
				dl->AddRectFilled(ImVec2(ohx - 3.f, hex_y),
					ImVec2(ohx + byte_w - 3.f, hex_y + byte_h),
					aida::ui::with_alpha(t.error_soft, a), 4.f);
			}
			dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
				ImVec2(ohx, hex_y + (byte_h - 12.f) * 0.5f),
				aida::ui::with_alpha(diff ? t.error : t.text_dim, a), hb);
			ohx += byte_w;
		}

		hex_y += byte_h + 6.f;
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(x0 + row_pad_x, hex_y + (byte_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.success, a), "New");
		float nhx = x0 + row_pad_x + 36.f;
		for (uint32_t j = 0; j < c.size && j < 32; ++j) {
			char hb[4]; snprintf(hb, sizeof(hb), "%02X", c.new_data[j]);
			bool diff = (j < c.old_data.size() && c.old_data[j] != c.new_data[j]);
			if (diff) {
				dl->AddRectFilled(ImVec2(nhx - 3.f, hex_y),
					ImVec2(nhx + byte_w - 3.f, hex_y + byte_h),
					aida::ui::with_alpha(t.success_soft, a), 4.f);
			}
			dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
				ImVec2(nhx, hex_y + (byte_h - 12.f) * 0.5f),
				aida::ui::with_alpha(diff ? t.success : t.text_dim, a), hb);
			nhx += byte_w;
		}

		hex_y += byte_h + 8.f;
		if (c.size == 4) {
			float old_f, new_f;
			std::memcpy(&old_f, c.old_data.data(), 4);
			std::memcpy(&new_f, c.new_data.data(), 4);
			int32_t old_i, new_i;
			std::memcpy(&old_i, c.old_data.data(), 4);
			std::memcpy(&new_i, c.new_data.data(), 4);

			char val_info[160];
			snprintf(val_info, sizeof(val_info), "Int32: %d -> %d   Float: %.6f -> %.6f",
			         old_i, new_i, old_f, new_f);
			dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
				ImVec2(x0 + row_pad_x, hex_y),
				aida::ui::with_alpha(t.text_secondary, a), val_info);
		} else if (c.size == 8) {
			uint64_t old_v, new_v;
			std::memcpy(&old_v, c.old_data.data(), 8);
			std::memcpy(&new_v, c.new_data.data(), 8);
			char val_info[160];
			snprintf(val_info, sizeof(val_info), "UInt64: 0x%llX -> 0x%llX",
			         static_cast<unsigned long long>(old_v), static_cast<unsigned long long>(new_v));
			dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
				ImVec2(x0 + row_pad_x, hex_y),
				aida::ui::with_alpha(t.text_secondary, a), val_info);
		}
	}
}

}
