#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "imgui/imgui.h"
#include "pointer_scanner.hpp"
#include "disasm_view.hpp"
#include "hex_view.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"

extern DisasmState g_disasm;

namespace pointer_scanner_view {

struct chain_anim_t {
	float reveal = 0.f;
	float step_flash[16] = {};
	int   hover_step = -1;
	uint64_t cached_addr[16] = {};
	bool     cached_valid[16] = {};
	float    cache_age = 0.f;
};

struct view_state_t {
	std::unordered_map<int, chain_anim_t> chain_anims;
	int   last_selected = -1;
	float anim_clock = 0.f;
};

inline view_state_t g_view;

namespace detail {

inline std::string format_offset(int64_t off) {
	char buf[32];
	if (off >= 0) snprintf(buf, sizeof(buf), "+0x%llX", static_cast<unsigned long long>(off));
	else          snprintf(buf, sizeof(buf), "-0x%llX", static_cast<unsigned long long>(-off));
	return buf;
}

inline uint64_t resolve_step_address(const pointer_scanner::pointer_chain_t& chain, int step) {
	auto& st = pointer_scanner::g_state;
	uint64_t base_addr = 0;
	if (chain.is_static && chain.module_index >= 0 &&
		chain.module_index < static_cast<int>(st.cached_modules.size())) {
		base_addr = st.cached_modules[chain.module_index].base + chain.base_offset;
	} else {
		base_addr = chain.base_offset;
	}
	if (step <= 0) return base_addr;
	uint64_t current = base_addr;
	for (int i = 0; i < step && i < static_cast<int>(chain.offsets.size()); ++i) {
		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory(current, 8, buf) || buf.size() < 8) return current;
		uint64_t ptr = 0;
		std::memcpy(&ptr, buf.data(), 8);
		current = ptr + chain.offsets[i];
	}
	return current;
}

inline void render_step_box(ImDrawList* dl, ImVec2 a, ImVec2 b, ImU32 fill, ImU32 border,
	const char* label, ImU32 text_col, float radius)
{
	dl->AddRectFilled(a, b, fill, radius);
	dl->AddRect(a, b, border, radius, 0, 1.f);
	ImVec2 ts = ImGui::CalcTextSize(label);
	dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
		ImVec2(a.x + (b.x - a.x - ts.x) * 0.5f, a.y + (b.y - a.y - 12.f) * 0.5f),
		text_col, label);
}

inline void render_arrow(ImDrawList* dl, ImVec2 from, ImVec2 to, ImU32 col, float reveal) {
	if (reveal <= 0.001f) return;
	ImVec2 cp1(from.x + (to.x - from.x) * 0.4f, from.y - 6.f);
	ImVec2 cp2(to.x   - (to.x - from.x) * 0.4f, to.y   + 6.f);

	int segments = 24;
	float clip_t = reveal;
	for (int i = 0; i < segments; ++i) {
		float t1 = (float)i / (float)segments;
		float t2 = (float)(i + 1) / (float)segments;
		if (t2 > clip_t) t2 = clip_t;
		if (t1 >= clip_t) break;
		auto bez = [&](float tt) {
			float u = 1.f - tt;
			float x = u*u*u*from.x + 3.f*u*u*tt*cp1.x + 3.f*u*tt*tt*cp2.x + tt*tt*tt*to.x;
			float y = u*u*u*from.y + 3.f*u*u*tt*cp1.y + 3.f*u*tt*tt*cp2.y + tt*tt*tt*to.y;
			return ImVec2(x, y);
		};
		dl->AddLine(bez(t1), bez(t2), col, 1.5f);
	}
	if (reveal >= 0.99f) {
		float head = 5.f;
		dl->AddTriangleFilled(
			ImVec2(to.x - head, to.y - head * 0.6f),
			ImVec2(to.x - head, to.y + head * 0.6f),
			to, col);
	}
	float t_sec = aida::ui::clock::seconds() * 0.8f;
	float ph = fmodf(t_sec, 1.f);
	if (ph <= reveal) {
		float u = 1.f - ph;
		float dx = u*u*u*from.x + 3.f*u*u*ph*cp1.x + 3.f*u*ph*ph*cp2.x + ph*ph*ph*to.x;
		float dy = u*u*u*from.y + 3.f*u*u*ph*cp1.y + 3.f*u*ph*ph*cp2.y + ph*ph*ph*to.y;
		dl->AddCircleFilled(ImVec2(dx, dy), 2.f, col, 12);
	}
}

inline void render_chain_diagram(ImDrawList* dl, float ox, float oy, float w, float h,
	int chain_idx, pointer_scanner::pointer_chain_t& chain, float a, chain_anim_t& anim)
{
	const auto& t = aida::ui::resolved();

	float pad = 14.f;
	float row_y = oy + h * 0.5f - 18.f;
	float box_h = 32.f;
	float gap_w = 56.f;

	int total_steps = 1 + static_cast<int>(chain.offsets.size());
	if (total_steps < 1) return;

	std::vector<float> box_w_arr;
	box_w_arr.reserve(total_steps * 2);

	float total_w = 0.f;
	{
		char base_lbl[96];
		if (chain.is_static && chain.module_index >= 0 &&
			chain.module_index < static_cast<int>(pointer_scanner::g_state.cached_modules.size())) {
			snprintf(base_lbl, sizeof(base_lbl), "%s+0x%llX",
				chain.module_name.c_str(), static_cast<unsigned long long>(chain.base_offset));
		} else {
			snprintf(base_lbl, sizeof(base_lbl), "0x%llX",
				static_cast<unsigned long long>(chain.base_offset));
		}
		ImVec2 ts = ImGui::CalcTextSize(base_lbl);
		float bw = ts.x + 22.f;
		box_w_arr.push_back(bw);
		total_w += bw;
	}

	for (size_t i = 0; i < chain.offsets.size(); ++i) {
		std::string off = format_offset(chain.offsets[i]);
		ImVec2 ts = ImGui::CalcTextSize(off.c_str());
		float bw = ts.x + 18.f;
		box_w_arr.push_back(bw);
		total_w += bw + gap_w;
	}

	float scale = 1.f;
	if (total_w + pad * 2.f > w) {
		scale = (w - pad * 2.f) / total_w;
		if (scale < 0.45f) scale = 0.45f;
		gap_w *= scale;
		for (auto& bw : box_w_arr) bw *= scale;
	}

	float cx = ox + pad;
	int hover_step = -1;

	float dt = aida::ui::clock::dt();
	anim.reveal = aida::motion::smooth_lerp(anim.reveal, 1.f, 14.f, dt);

	{
		float bw = box_w_arr[0];
		ImVec2 ba(cx, row_y);
		ImVec2 bb(cx + bw, row_y + box_h);
		float local_t = anim.reveal * 1.0f;
		float lift = (1.f - aida::motion::ease::out_cubic(local_t)) * 8.f;
		ba.y += lift; bb.y += lift;

		ImU32 fill = chain.is_static ? aida::ui::with_alpha(t.accent_dim, a * 0.55f * local_t)
		                              : aida::ui::with_alpha(t.panel_bg, a * local_t);
		ImU32 border = chain.is_static ? aida::ui::with_alpha(t.accent_u32, a * local_t)
		                                : aida::ui::with_alpha(t.border_subtle, a * local_t);

		ImGui::PushID(chain_idx * 100 + 0);
		ImGui::SetCursorScreenPos(ba);
		ImGui::InvisibleButton("##step0", ImVec2(bw, box_h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		if (hov) hover_step = 0;
		if (clk) {
			uint64_t addr = resolve_step_address(chain, 0);
			if (addr != 0) {
				hex_view::read_from_process(addr, 256);
				globals::ui::active_center_view = center_view_t::hex_view;
			}
		}
		ImGui::PopID();

		if (hov) {
			anim.step_flash[0] = 1.f;
		}
		float flash = anim.step_flash[0];
		if (flash > 0.f) {
			border = aida::ui::with_alpha(t.accent_u32, a * (0.6f + flash * 0.4f));
			fill = aida::ui::with_alpha(t.accent_glow, a * (0.6f * flash + (chain.is_static ? 0.55f : 0.f)));
		}

		char lbl[96];
		if (chain.is_static && chain.module_index >= 0 &&
			chain.module_index < static_cast<int>(pointer_scanner::g_state.cached_modules.size())) {
			snprintf(lbl, sizeof(lbl), "%s+0x%llX",
				chain.module_name.c_str(), static_cast<unsigned long long>(chain.base_offset));
		} else {
			snprintf(lbl, sizeof(lbl), "0x%llX", static_cast<unsigned long long>(chain.base_offset));
		}
		render_step_box(dl, ba, bb, fill, border, lbl,
			aida::ui::with_alpha(t.text_primary, a * local_t), 8.f);

		cx += bw;
	}

	for (size_t i = 0; i < chain.offsets.size(); ++i) {
		float reveal_offset = (float)(i + 1) * 0.16f;
		float local_t = (anim.reveal - reveal_offset) / (1.f - reveal_offset + 0.0001f);
		if (local_t < 0.f) local_t = 0.f;
		if (local_t > 1.f) local_t = 1.f;

		ImVec2 from(cx, row_y + box_h * 0.5f);
		ImVec2 to(cx + gap_w, row_y + box_h * 0.5f);
		render_arrow(dl, from, to,
			aida::ui::with_alpha(t.accent_u32, a * local_t), local_t);

		cx += gap_w;

		float bw = box_w_arr[i + 1];
		ImVec2 ba(cx, row_y);
		ImVec2 bb(cx + bw, row_y + box_h);
		float lift = (1.f - aida::motion::ease::out_cubic(local_t)) * 8.f;
		ba.y += lift; bb.y += lift;

		ImU32 fill = aida::ui::with_alpha(t.panel_bg, a * local_t);
		ImU32 border = aida::ui::with_alpha(t.border_subtle, a * local_t);

		int step_idx = static_cast<int>(i + 1);
		ImGui::PushID(chain_idx * 100 + step_idx);
		ImGui::SetCursorScreenPos(ba);
		ImGui::InvisibleButton("##stepn", ImVec2(bw, box_h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		if (hov) hover_step = step_idx;
		if (clk) {
			uint64_t addr = resolve_step_address(chain, step_idx);
			if (addr != 0) {
				hex_view::read_from_process(addr, 256);
				globals::ui::active_center_view = center_view_t::hex_view;
			}
		}
		ImGui::PopID();

		if (hov) anim.step_flash[step_idx & 15] = 1.f;
		float flash = anim.step_flash[step_idx & 15];
		if (flash > 0.f) {
			border = aida::ui::with_alpha(t.accent_u32, a * (0.6f + flash * 0.4f));
			fill = aida::ui::with_alpha(t.accent_glow, a * 0.4f * flash);
		}

		std::string off = format_offset(chain.offsets[i]);
		ImU32 dot_col = aida::ui::with_alpha(t.accent_u32, a * local_t);
		float dot_cx = ba.x + 8.f;
		float dot_cy = (ba.y + bb.y) * 0.5f;
		dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), 3.f, dot_col, 12);

		ImVec2 ts = ImGui::CalcTextSize(off.c_str());
		dl->AddRectFilled(ba, bb, fill, 8.f);
		dl->AddRect(ba, bb, border, 8.f, 0, 1.f);
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(dot_cx + 8.f, dot_cy - 6.f),
			aida::ui::with_alpha(t.text_primary, a * local_t), off.c_str());

		cx += bw;
	}

	for (auto& f : anim.step_flash) {
		if (f > 0.f) {
			f -= dt * 1.66f;
			if (f < 0.f) f = 0.f;
		}
	}

	anim.hover_step = hover_step;
	anim.cache_age += dt;
	if (anim.cache_age > 0.5f) {
		anim.cache_age = 0.f;
		for (int i = 0; i < 16; ++i) anim.cached_valid[i] = false;
	}
	if (hover_step >= 0) {
		int idx = hover_step & 15;
		if (!anim.cached_valid[idx]) {
			anim.cached_addr[idx] = resolve_step_address(chain, hover_step);
			anim.cached_valid[idx] = true;
		}
		uint64_t addr = anim.cached_addr[idx];
		char tip[96];
		snprintf(tip, sizeof(tip), "Resolved: 0x%llX", static_cast<unsigned long long>(addr));
		ImVec2 mp = ImGui::GetMousePos();
		ImVec2 ts = ImGui::CalcTextSize(tip);
		ImVec2 tp(mp.x + 16.f, mp.y - ts.y - 8.f);
		dl->AddRectFilled(ImVec2(tp.x - 6.f, tp.y - 4.f),
			ImVec2(tp.x + ts.x + 6.f, tp.y + ts.y + 4.f),
			aida::ui::with_alpha(t.bg_overlay, 0.95f), 6.f);
		dl->AddRect(ImVec2(tp.x - 6.f, tp.y - 4.f),
			ImVec2(tp.x + ts.x + 6.f, tp.y + ts.y + 4.f),
			aida::ui::with_alpha(t.border_subtle, 1.f), 6.f, 0, 1.f);
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize, tp,
			aida::ui::with_alpha(t.text_primary, 1.f), tip);
	}
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float, float, float)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float a = alpha;
	auto& st = pointer_scanner::g_state;
	auto& view = g_view;

	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();
	view.anim_clock += dt;

	float x0 = wp.x + pos_x;
	float y0 = wp.y + pos_y;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + height),
		aida::ui::with_alpha(t.bg_base, a));

	float toolbar_h = 56.f;
	float config_panel_w = 340.f;
	float row_h = 28.f;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + toolbar_h),
		aida::ui::with_alpha(t.panel_header, a));
	dl->AddLine(ImVec2(x0, y0 + toolbar_h), ImVec2(x0 + width, y0 + toolbar_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	{
		ImFont* hdr_fn = aida::ui::fonts::body_em();
		float hdr_fs = hdr_fn ? hdr_fn->FontSize : 16.f;
		dl->AddText(hdr_fn, hdr_fs,
			ImVec2(x0 + 16.f, y0 + (toolbar_h - hdr_fs) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a), "Pointer Chain Scanner");
	}

	{
		char status_buf[160];
		size_t entries;
		size_t res_count;
		{
			std::lock_guard<std::mutex> lk(st.map_mutex);
			entries = st.map_entry_count;
		}
		{
			std::lock_guard<std::mutex> lk(st.results_mutex);
			res_count = st.results.size();
		}
		snprintf(status_buf, sizeof(status_buf), "Map: %zu  ·  Chains: %zu", entries, res_count);
		ImFont* sf = aida::ui::fonts::body();
		float sfs = sf ? sf->FontSize : ImGui::GetFontSize();
		ImVec2 ts = ImGui::CalcTextSize(status_buf);
		dl->AddText(sf, sfs,
			ImVec2(x0 + width - ts.x - 16.f, y0 + (toolbar_h - sfs) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a), status_buf);
	}

	float cfg_x = x0;
	float cfg_y = y0 + toolbar_h;
	float cfg_h = height - toolbar_h;

	dl->AddRectFilled(ImVec2(cfg_x, cfg_y), ImVec2(cfg_x + config_panel_w, cfg_y + cfg_h),
		aida::ui::with_alpha(t.panel_bg, a));
	dl->AddLine(ImVec2(cfg_x + config_panel_w, cfg_y), ImVec2(cfg_x + config_panel_w, cfg_y + cfg_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	float cy = cfg_y + 18.f;
	float cx = cfg_x + 18.f;
	float field_w = config_panel_w - 36.f;

	{
		ImFont* hfn = aida::ui::fonts::body_em();
		float hfs = hfn ? hfn->FontSize : 14.f;
		dl->AddText(hfn, hfs,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_primary, a), "Configuration");
		cy += hfs + 12.f;
	}

	{
		ImFont* lblf = aida::ui::fonts::body();
		float lblfs = lblf ? lblf->FontSize : ImGui::GetFontSize();
		dl->AddText(lblf, lblfs,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_dim, a), "Target Address");
		cy += lblfs + 6.f;
	}

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	aida::ui::input_text("##ptr_addr", st.addr_buf, sizeof(st.addr_buf),
		"e.g. 7FF60012A440", false, ImVec2(field_w, 32.f));
	cy += 44.f;

	auto draw_label_and_value = [&](const char* lbl, int value) {
		ImFont* lblf = aida::ui::fonts::body();
		if (!lblf) lblf = ImGui::GetFont();
		ImFont* valf = aida::ui::fonts::body_em();
		if (!valf) valf = ImGui::GetFont();
		float lblfs = lblf->FontSize;
		float valfs = valf->FontSize;
		dl->AddText(lblf, lblfs,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_dim, a), lbl);
		char vbuf[32];
		std::snprintf(vbuf, sizeof(vbuf), "%d", value);
		ImVec2 vts = valf->CalcTextSizeA(valfs, FLT_MAX, 0.f, vbuf);
		float chip_pad_x = 8.f;
		float chip_w = vts.x + chip_pad_x * 2.f;
		float chip_h = valfs + 6.f;
		float chip_x = cx + field_w - chip_w;
		float chip_y = cy - 2.f;
		dl->AddRectFilled(ImVec2(chip_x, chip_y), ImVec2(chip_x + chip_w, chip_y + chip_h),
			aida::ui::with_alpha(t.panel_header, a * 0.9f), chip_h * 0.5f);
		dl->AddText(valf, valfs,
			ImVec2(chip_x + chip_pad_x, chip_y + 3.f),
			aida::ui::with_alpha(t.text_primary, a), vbuf);
		cy += lblfs + 6.f;
	};

	draw_label_and_value("Max Depth", st.config.max_depth);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushItemWidth(field_w);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, aida::ui::with_alpha(t.accent_hover, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::SliderInt("##ptr_depth", &st.config.max_depth, 1, 7, "");
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(4);
	ImGui::PopItemWidth();
	cy += 36.f;

	int max_off = static_cast<int>(st.config.max_offset);
	draw_label_and_value("Max Offset", max_off);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushItemWidth(field_w);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, aida::ui::with_alpha(t.accent_hover, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::SliderInt("##ptr_maxoff", &max_off, 64, 16384, "");
	st.config.max_offset = max_off;
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(4);
	ImGui::PopItemWidth();
	cy += 36.f;

	int struct_sz = static_cast<int>(st.config.struct_size);
	draw_label_and_value("Struct Size", struct_sz);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushItemWidth(field_w);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, aida::ui::with_alpha(t.accent_hover, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::SliderInt("##ptr_struct", &struct_sz, 64, 16384, "");
	st.config.struct_size = struct_sz;
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(4);
	ImGui::PopItemWidth();
	cy += 40.f;

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool n = st.config.negative_offsets;
		aida::ui::toggle_switch("Negative Offsets##neg", &n, aida::ui::size_t_::sm);
		st.config.negative_offsets = n;
		cy += 28.f;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool s = st.config.only_static_bases;
		aida::ui::toggle_switch("Static Bases Only##sb", &s, aida::ui::size_t_::sm);
		st.config.only_static_bases = s;
		cy += 34.f;
	}

	dl->AddLine(ImVec2(cx, cy), ImVec2(cx + field_w, cy),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);
	cy += 14.f;

	bool building = st.map_building.load();
	bool scanning = st.scanning.load();

	if (building) {
		float prog = st.map_progress.load();
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_dim, a), "Building reverse map...");
		aida::ui::render_progress_bar(ImVec2(cx, cy + 18.f), field_w, 6.f, prog, false, true);
		cy += 34.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
			pointer_scanner::cancel_all();
		}
		cy += 44.f;
	} else {
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Build Pointer Map", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
			pointer_scanner::build_reverse_map();
		}
		cy += 46.f;
	}

	if (scanning) {
		float prog = st.scan_progress.load();
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_dim, a), "Scanning chains...");
		aida::ui::render_progress_bar(ImVec2(cx, cy + 18.f), field_w, 6.f, prog, false, true);
		cy += 34.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
			st.scan_cancel.store(true);
		}
		cy += 44.f;
	} else {
		bool can_scan = !building && st.map_entry_count > 0;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Scan Chains", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f), !can_scan)) {
			st.config.target_address = strtoull(st.addr_buf, nullptr, 16);
			pointer_scanner::start_scan();
		}
		cy += 46.f;
	}

	dl->AddLine(ImVec2(cx, cy), ImVec2(cx + field_w, cy),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);
	cy += 14.f;

	bool validating = st.validating.load();
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (validating) {
		float prog = st.validate_progress.load();
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(cx, cy - 16.f), aida::ui::with_alpha(t.text_dim, a), "Validating chains...");
		aida::ui::render_progress_bar(ImVec2(cx, cy + 4.f), field_w, 6.f, prog, false, true);
	} else {
		if (aida::ui::button("Validate All", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f),
				scanning || building || validating)) {
			pointer_scanner::validate_all_results();
		}
	}
	cy += 44.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (aida::ui::button("Clear Results", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
		pointer_scanner::clear_results();
		view.chain_anims.clear();
	}
	cy += 44.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (aida::ui::button("Clear Map", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
		pointer_scanner::clear_map();
	}

	float table_x = cfg_x + config_panel_w + 1.f;
	float table_y = cfg_y;
	float table_w = width - config_panel_w - 1.f;

	float detail_h = 200.f;
	float list_h = cfg_h - detail_h;

	float col_depth_w = 60.f;
	float col_module_w = 160.f;
	float col_base_w = 130.f;
	float col_status_w = 70.f;
	float col_chain_w = table_w - col_depth_w - col_module_w - col_base_w - col_status_w - 32.f;
	if (col_chain_w < 100.f) col_chain_w = 100.f;

	float hdr_h = 28.f;
	dl->AddRectFilled(ImVec2(table_x, table_y),
		ImVec2(table_x + table_w, table_y + hdr_h),
		aida::ui::with_alpha(t.panel_header, a * 0.85f));
	dl->AddLine(ImVec2(table_x, table_y + hdr_h),
		ImVec2(table_x + table_w, table_y + hdr_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	const char* col_names[5] = { "Depth", "Module", "Base+Offset", "Chain", "Valid" };
	float col_widths[5] = { col_depth_w, col_module_w, col_base_w, col_chain_w, col_status_w };
	float hx = table_x + 16.f;
	for (int c = 0; c < 5; ++c) {
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(hx, table_y + (hdr_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), col_names[c]);
		hx += col_widths[c];
	}

	float body_y = table_y + hdr_h;
	float body_h = list_h - hdr_h;

	ImGui::SetCursorScreenPos(ImVec2(table_x, body_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
	ImGui::BeginChild("##ptr_results", ImVec2(table_w, body_h), false,
	                   ImGuiWindowFlags_NoScrollbar);

	std::lock_guard<std::mutex> lk(st.results_mutex);
	int total = static_cast<int>(st.results.size());
	int visible_count = static_cast<int>(body_h / row_h);

	float wheel = ImGui::GetIO().MouseWheel;
	ImVec2 mp = ImGui::GetMousePos();
	if (mp.x >= table_x && mp.x <= table_x + table_w && mp.y >= body_y && mp.y <= body_y + body_h) {
		st.target_scroll_y -= wheel * row_h * 3.f;
		if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
		float max_scroll = (total > visible_count) ? (total - visible_count) * row_h : 0.f;
		if (st.target_scroll_y > max_scroll) st.target_scroll_y = max_scroll;
	}
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 20.f, dt);

	int start_row = static_cast<int>(st.scroll_y / row_h);
	if (start_row < 0) start_row = 0;

	for (int i = start_row; i < total && i < start_row + visible_count + 2; ++i) {
		auto& chain = st.results[i];
		float ry = body_y + (i - start_row) * row_h - (st.scroll_y - start_row * row_h);
		if (ry + row_h < body_y || ry > body_y + body_h) continue;

		bool hovered = (mp.x >= table_x && mp.x <= table_x + table_w &&
		                mp.y >= ry && mp.y < ry + row_h);
		bool selected = (i == st.selected_result);

		float row_a = ui_anim::render_row_entrance(i - start_row, view.anim_clock, 0.012f);

		if (selected) {
			dl->AddRectFilled(ImVec2(table_x, ry), ImVec2(table_x + table_w, ry + row_h),
				aida::ui::with_alpha(t.selection, a * row_a));
			dl->AddRectFilled(ImVec2(table_x, ry), ImVec2(table_x + 3.f, ry + row_h),
				aida::ui::with_alpha(t.accent_u32, a * row_a));
		} else if (hovered) {
			dl->AddRectFilled(ImVec2(table_x, ry), ImVec2(table_x + table_w, ry + row_h),
				aida::ui::with_alpha(t.hover_wash, a * row_a));
		} else if (i & 1) {
			dl->AddRectFilled(ImVec2(table_x, ry), ImVec2(table_x + table_w, ry + row_h),
				aida::ui::with_alpha(IM_COL32(255, 255, 255, 4), a * row_a));
		}

		if (hovered && ImGui::IsMouseClicked(0))
			st.selected_result = i;

		float rx = table_x + 16.f;
		char buf[32];

		snprintf(buf, sizeof(buf), "%d", chain.depth);
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a * row_a), buf);
		rx += col_depth_w;

		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			chain.is_static ? aida::ui::with_alpha(t.accent_u32, a * row_a)
			                 : aida::ui::with_alpha(t.text_dim, a * row_a),
			chain.module_name.empty() ? "dynamic" : chain.module_name.c_str());
		rx += col_module_w;

		snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(chain.base_offset));
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, a * row_a), buf);
		rx += col_base_w;

		std::string chain_str;
		for (size_t j = 0; j < chain.offsets.size(); ++j) {
			if (j > 0) chain_str += " -> ";
			chain_str += detail::format_offset(chain.offsets[j]);
		}

		float avail = col_chain_w - 4.f;
		ImVec2 chain_sz = ImGui::CalcTextSize(chain_str.c_str());
		if (chain_sz.x > avail) {
			size_t trunc = chain_str.size();
			while (trunc > 3) {
				--trunc;
				std::string test = chain_str.substr(0, trunc) + "...";
				if (ImGui::CalcTextSize(test.c_str()).x <= avail) {
					chain_str = test;
					break;
				}
			}
		}
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(rx, ry + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a * row_a), chain_str.c_str());
		rx += col_chain_w;

		ImGui::SetCursorScreenPos(ImVec2(rx, ry + (row_h - 18.f) * 0.5f));
		ImGui::PushID(i + 32768);
		aida::ui::pill_kind(chain.validated ? "valid" : "?",
			chain.validated ? aida::ui::components::pill_kind_t::success
			                : aida::ui::components::pill_kind_t::neutral,
			aida::ui::size_t_::sm, true);
		ImGui::PopID();
	}

	ImGui::EndChild();
	ImGui::PopStyleColor();

	if (total == 0) {
		if (scanning || building) {
			float sk_y = body_y + 12.f;
			for (int s = 0; s < 6; ++s) {
				if (sk_y + 24.f > body_y + body_h) break;
				aida::ui::skeleton::render_block(dl,
					ImVec2(table_x + 16.f, sk_y),
					ImVec2(table_x + table_w - 24.f, sk_y + 22.f), 8.f, 1.4f);
				sk_y += 30.f;
			}
		} else {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::dots;
			if (st.map_entry_count == 0) {
				cfg.title = "Build the map first";
				cfg.body = "Click \"Build Pointer Map\" to enumerate every pointer in the target.";
			} else {
				cfg.title = "No chains yet";
				cfg.body = "Enter a target address and click \"Scan Chains\".";
			}
			aida::ui::empty_state::render(ImVec2(table_x, body_y), ImVec2(table_w, body_h), cfg);
		}
	}

	float det_x = table_x;
	float det_y = cfg_y + list_h;
	float det_w = table_w;

	dl->AddLine(ImVec2(det_x, det_y), ImVec2(det_x + det_w, det_y),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);
	dl->AddRectFilled(ImVec2(det_x, det_y + 1.f),
		ImVec2(det_x + det_w, det_y + detail_h),
		aida::ui::with_alpha(t.panel_bg, a));

	if (st.selected_result >= 0 && st.selected_result < total) {
		auto& chain = st.results[st.selected_result];
		auto& anim = view.chain_anims[st.selected_result];
		if (view.last_selected != st.selected_result) {
			anim.reveal = 0.f;
			view.last_selected = st.selected_result;
		}

		dl->AddText(aida::ui::fonts::body_em(), 13.f,
			ImVec2(det_x + 16.f, det_y + 12.f),
			aida::ui::with_alpha(t.text_primary, a), "Chain Detail");

		{
			float bx = det_x + det_w - 320.f;
			ImGui::SetCursorScreenPos(ImVec2(bx, det_y + 8.f));
			if (aida::ui::button("Copy Chain", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				std::string cs = pointer_scanner::chain_to_string(chain);
				ImGui::SetClipboardText(cs.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(bx + 100.f, det_y + 8.f));
			if (aida::ui::button("Copy C++", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				std::string cs = pointer_scanner::export_chain_cpp(chain);
				ImGui::SetClipboardText(cs.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(bx + 200.f, det_y + 8.f));
			if (aida::ui::button("Goto Base", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::sm)) {
				uint64_t addr = 0;
				if (chain.is_static && chain.module_index >= 0 &&
				    chain.module_index < static_cast<int>(st.cached_modules.size()))
					addr = st.cached_modules[chain.module_index].base + chain.base_offset;
				else
					addr = chain.base_offset;
				if (addr != 0) {
					g_disasm.goto_address = addr;
					g_disasm.has_new_goto = true;
					globals::ui::active_center_view = center_view_t::disassembly;
				}
			}
		}

		float info_y = det_y + 36.f;
		char info_buf[160];
		snprintf(info_buf, sizeof(info_buf), "Depth %d  ·  %s  ·  %s",
			chain.depth, chain.is_static ? "Static" : "Dynamic",
			chain.validated ? "Validated" : "Not validated");
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(det_x + 16.f, info_y),
			aida::ui::with_alpha(t.text_secondary, a), info_buf);

		float diag_y = det_y + 60.f;
		float diag_h = detail_h - 70.f;
		dl->AddRectFilled(ImVec2(det_x + 12.f, diag_y),
			ImVec2(det_x + det_w - 12.f, diag_y + diag_h),
			aida::ui::with_alpha(t.bg_overlay, a * 0.55f), 10.f);
		dl->AddRect(ImVec2(det_x + 12.f, diag_y),
			ImVec2(det_x + det_w - 12.f, diag_y + diag_h),
			aida::ui::with_alpha(t.border_subtle, a), 10.f, 0, 1.f);

		detail::render_chain_diagram(dl, det_x + 12.f, diag_y, det_w - 24.f, diag_h,
			st.selected_result, chain, a, anim);
	} else if (total > 0) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::flow;
		cfg.title = "Select a chain";
		cfg.body = "Click any row above to inspect its dereference path. Click any step to peek at the resolved memory.";
		aida::ui::empty_state::render(ImVec2(det_x, det_y), ImVec2(det_w, detail_h), cfg);
	}
}

}
