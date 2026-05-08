#pragma once

#include "ui/hub_strip.hpp"
#include "ui/clock.hpp"
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
	aida::ui::hub_strip::state_t strip;
};

inline state_t g_state;

inline void set_sub_tab(sub_tab_t tab)
{
	int idx = static_cast<int>(tab);
	aida::ui::hub_strip::notify_select(g_state.strip, idx);
}

inline constexpr aida::ui::hub_strip::tab_t s_tabs[] = {
	{ "Structures", "reconstructed types" },
	{ "Dissector",  "live struct dissector" },
};

inline void render_active(int idx, float cw, float ch, float fa, float ar, float ag, float ab)
{
	switch (static_cast<sub_tab_t>(idx)) {
		case sub_tab_t::structs:
			struct_recon_view::render(0.f, 0.f, cw, ch, fa, ar, ag, ab);
			break;
		case sub_tab_t::dissector:
			struct_dissector_view::render(0.f, 0.f, cw, ch, fa, ar, ag, ab);
			break;
		default:
			break;
	}
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b)
{
	float dt = aida::ui::clock::dt();
	aida::ui::hub_strip::tick_swap(g_state.strip, dt);

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetWindowPos();

	const int count = static_cast<int>(sub_tab_t::COUNT);
	aida::ui::hub_strip::render_strip(dl, origin, pos_x, pos_y, width,
		s_tabs, count, g_state.strip, alpha);

	const float tab_h = 30.f;
	float content_y = pos_y + tab_h + 6.f;
	float content_h = height - tab_h - 6.f;
	if (content_h < 1.f) return;

	ImGui::SetCursorPos(ImVec2(pos_x, content_y));
	ImGui::BeginChild("##types_hub_content", ImVec2(width, content_h), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	float cw = ImGui::GetWindowSize().x;
	float ch = ImGui::GetWindowSize().y;

	int prev_idx = g_state.strip.prev;
	int new_idx  = g_state.strip.active;

	aida::ui::hub_strip::render_swap_content(g_state.strip, cw,
		[&]() { render_active(prev_idx, cw, ch, alpha, accent_r, accent_g, accent_b); },
		[&]() { render_active(new_idx,  cw, ch, alpha, accent_r, accent_g, accent_b); }
	);

	ImGui::EndChild();
}

}
