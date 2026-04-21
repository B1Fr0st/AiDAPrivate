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
#include <vector>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

extern DisasmState g_disasm;

namespace snapshot_diff {

struct memory_region_t {
	uint64_t             base = 0;
	uint64_t             size = 0;
	uint32_t             protect = 0;
	std::vector<uint8_t> data;
};

struct snapshot_t {
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
	int                         snap_a_idx = -1;
	int                         snap_b_idx = -1;
	diff_result_t               diff;
	std::mutex                  mutex;
	std::atomic<bool>           capturing{false};
	std::atomic<bool>           comparing{false};
	std::atomic<float>          progress{0.f};
	std::atomic<bool>           cancel{false};
	int                         snap_counter = 0;

	int                         selected_change = -1;
	float                       scroll_y = 0.f;
	float                       target_scroll_y = 0.f;
	char                        filter_buf[128] = {};
	uint64_t                    filter_min_addr = 0;
	uint64_t                    filter_max_addr = 0;
	bool                        show_only_changes = true;
};

inline state_t g_state;

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
		uint64_t rsize = r.size;
		ofs.write(reinterpret_cast<const char*>(&rsize), 8);
		ofs.write(reinterpret_cast<const char*>(&r.protect), 4);
		ofs.write(reinterpret_cast<const char*>(r.data.data()), rsize);
	}
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
		snap.name = snap_name;
		snap.pid = driver_bridge::attached_pid();
		snap.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count();

		auto regions = driver_bridge::enumerate_memory_regions(4096);

		std::vector<driver_bridge::memory_region_t> readable;
		for (auto& r : regions) {
			if (r.state != 0x1000) continue;
			uint32_t p = r.protect & 0xFF;
			if (p == 0x01 || p == 0x00) continue;
			if (r.size > 0x10000000) continue;
			readable.push_back(r);
		}

		uint64_t total = 0;
		for (auto& r : readable) total += r.size;
		uint64_t done = 0;

		for (auto& r : readable) {
			if (g_state.cancel.load()) break;

			memory_region_t sr;
			sr.base = r.base;
			sr.size = r.size;
			sr.protect = r.protect;

			if (driver_bridge::read_memory(r.base, static_cast<size_t>(r.size), sr.data)) {
				snap.total_bytes += sr.data.size();
				snap.regions.push_back(std::move(sr));
			}

			done += r.size;
			g_state.progress.store(static_cast<float>(done) / static_cast<float>(total));
		}

		detail::save_snapshot(snap);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (g_state.snapshots.size() >= 10)
				g_state.snapshots.erase(g_state.snapshots.begin());
			g_state.snapshots.push_back(std::move(snap));
		}

		g_state.capturing.store(false);
	});
}

inline void compare_snapshots(int idx_a, int idx_b)
{
	if (g_state.comparing.load())
		return;

	g_state.comparing.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);

	work_queue::post([idx_a, idx_b]() {
		diff_result_t result;

		snapshot_t snap_a, snap_b;
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			if (idx_a < 0 || idx_a >= static_cast<int>(g_state.snapshots.size()) ||
			    idx_b < 0 || idx_b >= static_cast<int>(g_state.snapshots.size())) {
				g_state.comparing.store(false);
				return;
			}
			snap_a = g_state.snapshots[idx_a];
			snap_b = g_state.snapshots[idx_b];
		}

		result.snap_a_name = snap_a.name;
		result.snap_b_name = snap_b.name;

		std::unordered_map<uint64_t, size_t> b_map;
		for (size_t i = 0; i < snap_b.regions.size(); ++i)
			b_map[snap_b.regions[i].base] = i;

		auto modules = driver_bridge::enumerate_modules();

		uint64_t total = snap_a.regions.size();
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
		}

		g_state.comparing.store(false);
	});
}

inline void clear_snapshots()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.snapshots.clear();
	g_state.diff = {};
	g_state.snap_a_idx = -1;
	g_state.snap_b_idx = -1;
	g_state.snap_counter = 0;
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float a = alpha;

	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 bg = _ta(_t.bg_base);
	ImU32 panel_bg = _ta(_t.panel_bg);
	ImU32 hdr_bg = _ta(_t.panel_header);
	ImU32 text_main = _ta(_t.text_primary);
	ImU32 text_dim = _ta(_t.text_dim);
	ImU32 text_sec = _ta(_t.text_secondary);
	ImU32 accent_col = IM_COL32(
		static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
		static_cast<int>(accent_b * 255), static_cast<int>(220 * a));
	ImU32 red_col = IM_COL32(255, 90, 90, static_cast<int>(200 * a));
	ImU32 green_col = IM_COL32(90, 255, 130, static_cast<int>(200 * a));
	ImU32 row_hover_col = _ta(_t.panel_header);
	ImU32 row_sel = IM_COL32(
		static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
		static_cast<int>(accent_b * 255), static_cast<int>(30 * a));
	ImU32 sep_col = _ta(ui_anim::lighten(_t.panel_bg, 12));

	float x0 = wp.x + pos_x;
	float y0 = wp.y + pos_y;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + height), bg);

	float toolbar_h = 36.f;
	ui_anim::render_toolbar(dl, x0, y0, width, toolbar_h, accent_r, accent_g, accent_b, a);
	dl->AddLine(ImVec2(x0, y0 + toolbar_h), ImVec2(x0 + width, y0 + toolbar_h), sep_col);

	ImGui::SetCursorPos(ImVec2(pos_x + 8.f, pos_y + 6.f));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::TextUnformatted("Memory Snapshot Diff");
	ImGui::PopStyleColor();

	ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, _ta(ui_anim::lighten(_t.panel_header, 14)));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));

	ImGui::SetCursorPos(ImVec2(pos_x + 200.f, pos_y + 5.f));
	bool busy = g_state.capturing.load() || g_state.comparing.load();
	if (!busy) {
		if (ImGui::Button("Take Snapshot##sd")) {
			take_snapshot();
		}
	} else {
		float prog = g_state.progress.load();
		float bar_w = 100.f;
		float bar_h = 8.f;
		ImVec2 bp = ImGui::GetCursorScreenPos();
		dl->AddRectFilled(ImVec2(bp.x, bp.y + 8.f), ImVec2(bp.x + bar_w, bp.y + 8.f + bar_h),
		                  _ta(_t.panel_header), 4.f);
		dl->AddRectFilled(ImVec2(bp.x, bp.y + 8.f), ImVec2(bp.x + bar_w * prog, bp.y + 8.f + bar_h),
		                  accent_col, 4.f);
		char pct[16];
		snprintf(pct, sizeof(pct), "%.0f%%", prog * 100.f);
		dl->AddText(ImVec2(bp.x + bar_w + 6.f, bp.y + 4.f), text_sec, pct);
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);

	int snap_count = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		snap_count = static_cast<int>(g_state.snapshots.size());
	}

	ImGui::SetCursorPos(ImVec2(pos_x + width * 0.35f, pos_y + 5.f));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_header));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));

	ImGui::PushItemWidth(100.f);
	if (ImGui::BeginCombo("##snap_a", g_state.snap_a_idx >= 0 && g_state.snap_a_idx < snap_count
	                       ? g_state.snapshots[g_state.snap_a_idx].name.c_str() : "Snap A")) {
		std::lock_guard<std::mutex> lk(g_state.mutex);
		for (int i = 0; i < snap_count; ++i) {
			bool sel = (g_state.snap_a_idx == i);
			if (ImGui::Selectable(g_state.snapshots[i].name.c_str(), sel))
				g_state.snap_a_idx = i;
		}
		ImGui::EndCombo();
	}
	ImGui::PopItemWidth();

	ImGui::SameLine();
	dl->AddText(ImGui::GetCursorScreenPos(), text_sec, "vs");
	ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 20.f);

	ImGui::SameLine();
	ImGui::PushItemWidth(100.f);
	if (ImGui::BeginCombo("##snap_b", g_state.snap_b_idx >= 0 && g_state.snap_b_idx < snap_count
	                       ? g_state.snapshots[g_state.snap_b_idx].name.c_str() : "Snap B")) {
		std::lock_guard<std::mutex> lk(g_state.mutex);
		for (int i = 0; i < snap_count; ++i) {
			bool sel = (g_state.snap_b_idx == i);
			if (ImGui::Selectable(g_state.snapshots[i].name.c_str(), sel))
				g_state.snap_b_idx = i;
		}
		ImGui::EndCombo();
	}
	ImGui::PopItemWidth();

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, _ta(ui_anim::lighten(_t.panel_header, 14)));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));

	if (!busy && snap_count >= 2 && g_state.snap_a_idx >= 0 && g_state.snap_b_idx >= 0 &&
	    g_state.snap_a_idx != g_state.snap_b_idx) {
		if (ImGui::Button("Compare##sd"))
			compare_snapshots(g_state.snap_a_idx, g_state.snap_b_idx);
	}

	ImGui::SameLine();
	if (!busy && snap_count > 0) {
		if (ImGui::Button("Clear All##sd"))
			clear_snapshots();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);

	float content_y = y0 + toolbar_h;
	float content_h = height - toolbar_h;

	float detail_h = (g_state.selected_change >= 0) ? 160.f : 0.f;
	float table_h = content_h - detail_h;

	float col_addr_w = 130.f;
	float col_old_w = 160.f;
	float col_new_w = 160.f;
	float col_type_w = 80.f;
	float col_mod_w = width - col_addr_w - col_old_w - col_new_w - col_type_w - 24.f;
	if (col_mod_w < 60.f) col_mod_w = 60.f;

	{
		ui_anim::table_col_t hdr_cols[] = {
			{"Address", col_addr_w}, {"Old Value", col_old_w}, {"New Value", col_new_w},
			{"Type", col_type_w}, {"Module", col_mod_w}
		};
		ui_anim::render_table_header(dl, x0, content_y, width, 24.f, hdr_cols, 5, accent_r, accent_g, accent_b, a);
	}

	ImGui::SetCursorPos(ImVec2(pos_x, pos_y + toolbar_h + 24.f));
	ImGui::BeginChild("##snap_diff_table", ImVec2(width, table_h - 24.f), false,
	                  ImGuiWindowFlags_NoBackground);

	std::vector<changed_region_t> filtered;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		for (auto& c : g_state.diff.changes) {
			if (g_state.filter_min_addr != 0 && c.address < g_state.filter_min_addr) continue;
			if (g_state.filter_max_addr != 0 && c.address > g_state.filter_max_addr) continue;
			filtered.push_back(c);
		}
	}

	static float diff_row_anim_time = 0.f;
	diff_row_anim_time += ImGui::GetIO().DeltaTime;

	float row_height = 20.f;
	for (int i = 0; i < static_cast<int>(filtered.size()); ++i) {
		auto& c = filtered[i];
		ImVec2 rp = ImGui::GetCursorScreenPos();

		float row_entrance = ui_anim::render_row_entrance(i, diff_row_anim_time, 0.012f);
		bool hov = ImGui::IsMouseHoveringRect(rp, ImVec2(rp.x + width, rp.y + row_height), true);
		bool sel = (g_state.selected_change == i);

		ui_anim::table_row_style_t rs{};
		rs.selected = sel;
		rs.hovered = hov;
		rs.index = i;
		rs.alpha = a;
		rs.entrance = row_entrance;
		rs.ar = accent_r; rs.ag = accent_g; rs.ab = accent_b;
		ui_anim::render_table_row(dl, rp.x, rp.y, width, row_height, rs);

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			g_state.selected_change = i;

		char addr_str[24];
		snprintf(addr_str, sizeof(addr_str), "0x%llX", static_cast<unsigned long long>(c.address));
		dl->AddText(ImVec2(rp.x + 4.f, rp.y + 2.f), accent_col, addr_str);

		float ox = rp.x + col_addr_w;
		std::string old_hex;
		for (uint32_t j = 0; j < c.size && j < 8; ++j) {
			char hb[4]; snprintf(hb, sizeof(hb), "%02X ", c.old_data[j]);
			old_hex += hb;
		}
		if (c.size > 8) old_hex += "...";
		dl->AddText(ImVec2(ox, rp.y + 2.f), red_col, old_hex.c_str());

		float nx = rp.x + col_addr_w + col_old_w;
		std::string new_hex;
		for (uint32_t j = 0; j < c.size && j < 8; ++j) {
			char hb[4]; snprintf(hb, sizeof(hb), "%02X ", c.new_data[j]);
			new_hex += hb;
		}
		if (c.size > 8) new_hex += "...";
		dl->AddText(ImVec2(nx, rp.y + 2.f), green_col, new_hex.c_str());

		const char* type_str = detail::change_type_name(c.type);
		ImU32 type_col = text_sec;
		if (c.type == change_type_t::pointer_changed) type_col = IM_COL32(255, 200, 100, static_cast<int>(220 * a));
		else if (c.type == change_type_t::float_changed) type_col = IM_COL32(100, 200, 255, static_cast<int>(220 * a));
		else if (c.type == change_type_t::counter_incremented || c.type == change_type_t::counter_decremented)
			type_col = IM_COL32(200, 255, 100, static_cast<int>(220 * a));
		{
			float tx = rp.x + col_addr_w + col_old_w + col_new_w + 4.f;
			ImVec2 tts = ImGui::CalcTextSize(type_str);
			float pw = tts.x + 10.f;
			float ph = tts.y + 2.f;
			float py = rp.y + (row_height - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(tx, py), ImVec2(tx + pw, py + ph),
				IM_COL32((type_col >> IM_COL32_R_SHIFT) & 0xFF,
				         (type_col >> IM_COL32_G_SHIFT) & 0xFF,
				         (type_col >> IM_COL32_B_SHIFT) & 0xFF,
				         static_cast<int>(40 * a)), ph * 0.5f);
			dl->AddText(ImVec2(tx + 5.f, py + 1.f), type_col, type_str);
		}

		dl->AddText(ImVec2(rp.x + col_addr_w + col_old_w + col_new_w + col_type_w + 4.f, rp.y + 2.f),
		            text_dim, c.module_name.c_str());

		ImGui::SetCursorScreenPos(ImVec2(rp.x, rp.y + row_height));
	}

	if (filtered.empty()) {
		const char* empty_msg = g_state.snapshots.empty()
			? "Take snapshots of the target process to compare memory states."
			: "Select two snapshots and click 'Compare' to view differences.";
		ui_anim::render_empty_state(dl, x0, content_y + 24.f, width, table_h - 24.f,
			empty_msg, accent_r, accent_g, accent_b, a, static_cast<float>(ImGui::GetTime()));
	}

	ImGui::EndChild();

	if (g_state.selected_change >= 0 && g_state.selected_change < static_cast<int>(filtered.size())) {
		auto& c = filtered[g_state.selected_change];
		float dy = y0 + height - detail_h;
		dl->AddLine(ImVec2(x0, dy), ImVec2(x0 + width, dy), sep_col);
		ui_anim::render_panel_card(dl, x0, dy, width, detail_h, accent_r, accent_g, accent_b, a, 0.f, true);

		dl->AddText(ImVec2(x0 + 8.f, dy + 6.f), text_sec, "Detail");

		char addr_info[64];
		snprintf(addr_info, sizeof(addr_info), "Address: 0x%llX  Size: %u bytes",
		         static_cast<unsigned long long>(c.address), c.size);
		dl->AddText(ImVec2(x0 + 8.f, dy + 24.f), text_main, addr_info);

		float hex_y = dy + 44.f;
		dl->AddText(ImVec2(x0 + 8.f, hex_y), red_col, "Old:");
		float ohx = x0 + 48.f;
		for (uint32_t j = 0; j < c.size && j < 32; ++j) {
			char hb[4]; snprintf(hb, sizeof(hb), "%02X", c.old_data[j]);
			bool diff = (j < c.new_data.size() && c.old_data[j] != c.new_data[j]);
			dl->AddText(ImVec2(ohx, hex_y), diff ? red_col : text_dim, hb);
			ohx += 22.f;
		}

		hex_y += 18.f;
		dl->AddText(ImVec2(x0 + 8.f, hex_y), green_col, "New:");
		float nhx = x0 + 48.f;
		for (uint32_t j = 0; j < c.size && j < 32; ++j) {
			char hb[4]; snprintf(hb, sizeof(hb), "%02X", c.new_data[j]);
			bool diff = (j < c.old_data.size() && c.old_data[j] != c.new_data[j]);
			dl->AddText(ImVec2(nhx, hex_y), diff ? green_col : text_dim, hb);
			nhx += 22.f;
		}

		if (c.size == 4) {
			float old_f, new_f;
			std::memcpy(&old_f, c.old_data.data(), 4);
			std::memcpy(&new_f, c.new_data.data(), 4);
			int32_t old_i, new_i;
			std::memcpy(&old_i, c.old_data.data(), 4);
			std::memcpy(&new_i, c.new_data.data(), 4);

			char val_info[128];
			snprintf(val_info, sizeof(val_info), "Int32: %d -> %d   Float: %.6f -> %.6f",
			         old_i, new_i, old_f, new_f);
			dl->AddText(ImVec2(x0 + 8.f, hex_y + 22.f), text_sec, val_info);
		} else if (c.size == 8) {
			uint64_t old_v, new_v;
			std::memcpy(&old_v, c.old_data.data(), 8);
			std::memcpy(&new_v, c.new_data.data(), 8);
			char val_info[128];
			snprintf(val_info, sizeof(val_info), "UInt64: 0x%llX -> 0x%llX",
			         static_cast<unsigned long long>(old_v), static_cast<unsigned long long>(new_v));
			dl->AddText(ImVec2(x0 + 8.f, hex_y + 22.f), text_sec, val_info);
		}
	}

	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		char info[64];
		snprintf(info, sizeof(info), "%d snapshots  |  %d changes",
		         static_cast<int>(g_state.snapshots.size()),
		         static_cast<int>(g_state.diff.changes.size()));
		ImVec2 it = ImGui::CalcTextSize(info);
		dl->AddText(ImVec2(x0 + width - it.x - 10.f, y0 + height - 18.f), text_dim, info);
	}
}

}
