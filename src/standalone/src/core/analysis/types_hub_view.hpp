#pragma once

#include "ui_anim.hpp"
#include "struct_recon_view.hpp"
#include "struct_dissector_view.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <algorithm>
#include <cmath>

namespace types_hub_view {

enum class sub_tab_t : int {
	structs = 0,
	dissector,
	COUNT
};

struct state_t {
	sub_tab_t active_tab = sub_tab_t::structs;
	sub_tab_t prev_tab   = sub_tab_t::structs;
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
	"Structures", "Dissector"
};

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b)
{
	float dt = ImGui::GetIO().DeltaTime;
	g_state.content_fade = ui_anim::smooth_lerp(g_state.content_fade, 1.f, 12.f, dt);

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetWindowPos();

	int active_idx = static_cast<int>(g_state.active_tab);
	int prev_idx = static_cast<int>(g_state.prev_tab);
	ui_anim::render_hub_tab_bar(dl, origin, pos_x, pos_y, width,
		tab_names, static_cast<int>(sub_tab_t::COUNT), active_idx,
		g_state.tab_scroll_x, g_state.tab_target_scroll_x,
		g_state.underline_x, g_state.underline_w, g_state.underline_vel,
		g_state.content_fade, prev_idx,
		accent_r, accent_g, accent_b, alpha, dt);
	g_state.active_tab = static_cast<sub_tab_t>(active_idx);
	g_state.prev_tab = static_cast<sub_tab_t>(prev_idx);

	float tab_h = 28.f;
	float content_y = pos_y + tab_h + 4.f;
	float content_h = height - tab_h - 4.f;
	if (content_h < 1.f) return;

	float fa = alpha * g_state.content_fade;

	ImGui::SetCursorPos(ImVec2(pos_x, content_y));
	ImGui::BeginChild("##types_hub_content", ImVec2(width, content_h), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	float cw = ImGui::GetWindowSize().x;
	float ch = ImGui::GetWindowSize().y;

	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, fa);

	switch (g_state.active_tab) {
		case sub_tab_t::structs:
			struct_recon_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::dissector:
			struct_dissector_view::render(0.f, 0.f, cw, ch, fa, accent_r, accent_g, accent_b);
			break;
		default:
			break;
	}

	ImGui::PopStyleVar();
	ImGui::EndChild();
}

}
