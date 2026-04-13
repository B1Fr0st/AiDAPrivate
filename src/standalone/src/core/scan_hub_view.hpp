#pragma once

#include "ui_anim.hpp"
#include "memory_scanner_view.hpp"
#include "crypto_scanner_view.hpp"
#include "aob_view.hpp"
#include "decrypt_oracle_view.hpp"
#include "pointer_scanner_view.hpp"
#include "snapshot_diff.hpp"
#include "xref_db_view.hpp"
#include "integrity_hunter_view.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <algorithm>
#include <cmath>

namespace scan_hub_view {

enum class sub_tab_t : int {
	value_scan = 0,
	crypto,
	aob,
	decrypt,
	pointers,
	snapshots,
	xrefs,
	integrity,
	COUNT
};

struct state_t {
	sub_tab_t active_tab = sub_tab_t::value_scan;
	sub_tab_t prev_tab   = sub_tab_t::value_scan;
	float tab_scroll_x        = 0.f;
	float tab_target_scroll_x = 0.f;
	float underline_x   = 0.f;
	float underline_w   = 0.f;
	float underline_vel = 0.f;
	float content_fade  = 1.f;
};

inline state_t g_state;

inline void set_sub_tab(sub_tab_t tab)
{
	if (g_state.active_tab != tab) {
		g_state.prev_tab = g_state.active_tab;
		g_state.content_fade = 0.f;
	}
	g_state.active_tab = tab;
}

static const char* tab_names[] = {
	"Value Scan", "Crypto", "AOB", "Decrypt",
	"Pointers", "Snapshots", "XRefs", "Integrity"
};

inline void render_tab_bar(state_t& state, float x, float y, float w, float alpha,
							float ar, float ag, float ab, float dt)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetWindowPos();

	float tab_h = 28.f;
	int count = static_cast<int>(sub_tab_t::COUNT);

	ui_anim::render_gradient_header(dl, origin.x + x, origin.y + y, w, tab_h, ar, ag, ab, alpha);

	float total_w = 0.f;
	float tab_widths[static_cast<int>(sub_tab_t::COUNT)];
	float tab_offsets[static_cast<int>(sub_tab_t::COUNT)];
	for (int i = 0; i < count; i++) {
		tab_widths[i] = ImGui::CalcTextSize(tab_names[i]).x + 20.f;
		tab_offsets[i] = total_w;
		total_w += tab_widths[i] + 2.f;
	}

	float clip_x0 = origin.x + x;
	float clip_x1 = origin.x + x + w;
	float clip_y0 = origin.y + y;
	float clip_y1 = origin.y + y + tab_h;

	if (ImGui::IsMouseHoveringRect(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			state.tab_target_scroll_x -= wheel * 60.f;
	}

	float max_scroll = std::max(0.f, total_w - w);
	state.tab_target_scroll_x = std::clamp(state.tab_target_scroll_x, 0.f, max_scroll);
	state.tab_scroll_x = ui_anim::smooth_lerp(state.tab_scroll_x, state.tab_target_scroll_x, 14.f, dt);

	int active_idx = static_cast<int>(state.active_tab);
	float active_left = tab_offsets[active_idx] - state.tab_scroll_x;
	float active_right = active_left + tab_widths[active_idx];
	if (active_left < 0.f)
		state.tab_target_scroll_x = tab_offsets[active_idx];
	else if (active_right > w)
		state.tab_target_scroll_x = tab_offsets[active_idx] + tab_widths[active_idx] - w;

	float target_ux = clip_x0 + tab_offsets[active_idx] - state.tab_scroll_x + 4.f;
	float target_uw = tab_widths[active_idx] - 8.f;
	if (state.underline_w < 0.1f) {
		state.underline_x = target_ux;
		state.underline_w = target_uw;
	}
	state.underline_x = ui_anim::spring_interp(state.underline_x, target_ux, state.underline_vel, 280.f, 22.f, dt);
	state.underline_w = ui_anim::smooth_lerp(state.underline_w, target_uw, 16.f, dt);

	ImGui::PushClipRect(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1), true);

	for (int i = 0; i < count; i++) {
		float bx0 = clip_x0 + tab_offsets[i] - state.tab_scroll_x;
		float bx1 = bx0 + tab_widths[i];
		float by0 = clip_y0;
		float by1 = clip_y0 + tab_h;
		bool is_active = (i == active_idx);

		ImVec2 mouse = ImGui::GetMousePos();
		bool hovered = (mouse.x >= bx0 && mouse.x < bx1 && mouse.y >= by0 && mouse.y < by1);
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (state.active_tab != static_cast<sub_tab_t>(i)) {
				state.prev_tab = state.active_tab;
				state.content_fade = 0.f;
			}
			state.active_tab = static_cast<sub_tab_t>(i);
		}

		float bg_alpha = is_active ? 0.15f : (hovered ? 0.08f : 0.f);
		if (bg_alpha > 0.01f)
			dl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1),
				IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
						 static_cast<int>(ab * 255), static_cast<int>(bg_alpha * alpha * 255)),
				4.f);

		ImVec2 ts = ImGui::CalcTextSize(tab_names[i]);
		float text_alpha = is_active ? 0.95f : (hovered ? 0.7f : 0.5f);
		dl->AddText(ImVec2(bx0 + (tab_widths[i] - ts.x) * 0.5f, by0 + (tab_h - ts.y) * 0.5f),
			IM_COL32(255, 255, 255, static_cast<int>(text_alpha * alpha * 255)),
			tab_names[i]);
	}

	float ux = state.underline_x;
	float uw = state.underline_w;
	float uy = clip_y1 - 2.f;
	ImU32 ul_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							 static_cast<int>(ab * 255), static_cast<int>(alpha * 255));
	dl->AddRectFilled(ImVec2(ux, uy), ImVec2(ux + uw, uy + 2.f), ul_col, 1.f);
	dl->AddRectFilled(ImVec2(ux - 3.f, uy - 1.f), ImVec2(ux + uw + 3.f, uy + 3.f),
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(alpha * 40)), 2.f);
	dl->AddRectFilled(ImVec2(ux - 6.f, uy - 2.f), ImVec2(ux + uw + 6.f, uy + 5.f),
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(alpha * 15)), 3.f);

	ImGui::PopClipRect();

	if (state.tab_scroll_x > 1.f) {
		dl->AddRectFilledMultiColor(
			ImVec2(clip_x0, clip_y0), ImVec2(clip_x0 + 30.f, clip_y1),
			IM_COL32(18, 20, 26, static_cast<int>(240 * alpha)),
			IM_COL32(18, 20, 26, 0),
			IM_COL32(18, 20, 26, 0),
			IM_COL32(18, 20, 26, static_cast<int>(240 * alpha)));
	}
	if (state.tab_scroll_x < max_scroll - 1.f) {
		dl->AddRectFilledMultiColor(
			ImVec2(clip_x1 - 30.f, clip_y0), ImVec2(clip_x1, clip_y1),
			IM_COL32(18, 20, 26, 0),
			IM_COL32(18, 20, 26, static_cast<int>(240 * alpha)),
			IM_COL32(18, 20, 26, static_cast<int>(240 * alpha)),
			IM_COL32(18, 20, 26, 0));
	}

	dl->AddLine(
		ImVec2(origin.x + x, origin.y + y + tab_h),
		ImVec2(origin.x + x + w, origin.y + y + tab_h),
		IM_COL32(80, 80, 100, static_cast<int>(0.3f * alpha * 255)));

	dl->AddRectFilledMultiColor(
		ImVec2(origin.x + x, origin.y + y + tab_h + 1.f),
		ImVec2(origin.x + x + w, origin.y + y + tab_h + 4.f),
		IM_COL32(0, 0, 0, static_cast<int>(30.f * alpha)),
		IM_COL32(0, 0, 0, static_cast<int>(30.f * alpha)),
		IM_COL32(0, 0, 0, 0),
		IM_COL32(0, 0, 0, 0));
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b)
{
	float dt = ImGui::GetIO().DeltaTime;
	g_state.content_fade = ui_anim::smooth_lerp(g_state.content_fade, 1.f, 12.f, dt);

	float tab_h = 28.f;
	render_tab_bar(g_state, pos_x, pos_y, width, alpha, accent_r, accent_g, accent_b, dt);

	float content_y = pos_y + tab_h + 4.f;
	float content_h = height - tab_h - 4.f;
	if (content_h < 1.f) return;

	float fa = alpha * g_state.content_fade;

	ImGui::SetCursorPos(ImVec2(pos_x, content_y));
	ImGui::BeginChild("##scan_hub_content", ImVec2(width, content_h), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	float cw = ImGui::GetWindowSize().x;
	float ch = ImGui::GetWindowSize().y;

	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, fa);

	switch (g_state.active_tab) {
		case sub_tab_t::value_scan:
			memory_scanner_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::crypto:
			crypto_scanner_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::aob:
			aob_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::decrypt:
			decrypt_oracle_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::pointers:
			pointer_scanner_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::snapshots:
			snapshot_diff::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::xrefs:
			xref_db_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::integrity:
			integrity_hunter_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		default:
			break;
	}

	ImGui::PopStyleVar();
	ImGui::EndChild();
}

}
