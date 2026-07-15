#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/re_hubs_preview_adapter.hpp"
#endif

#include "ui/hub_strip.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/no_target_overlay.hpp"
#include "ui/empty_state.hpp"
#include "symbolic_view.hpp"
#include "taint_view.hpp"
#include "deobfuscation_view.hpp"
#include "stealth_view.hpp"
#include "fuzzer_view.hpp"
#include "../session/analysis_session.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace analysis_hub_view {

enum class sub_tab_t : int {
	symbolic = 0,
	taint,
	deobfuscation,
	fuzzer,
	stealth,
	COUNT
};

struct state_t {
	aida::ui::hub_strip::state_t strip;
};

inline std::mutex& state_registry_mutex()
{
	static std::mutex value;
	return value;
}

inline std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
	aida::analysis::binary_id_hash_t>& state_registry()
{
	static std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
		aida::analysis::binary_id_hash_t> value;
	return value;
}

inline std::shared_ptr<state_t> state_for(const disasm_view::workspace_context_t& context)
{
	if (!context.workspace)
		return {};
	std::lock_guard<std::mutex> lock(state_registry_mutex());
	auto& values = state_registry();
	const auto id = context.workspace->identity().binary_id();
	auto found = values.find(id);
	if (found != values.end())
		return found->second;
	auto created = std::make_shared<state_t>();
	values.emplace(id, created);
	return created;
}

inline std::atomic<int>& default_active_tab()
{
	static std::atomic<int> value{static_cast<int>(sub_tab_t::symbolic)};
	return value;
}

inline void set_sub_tab(const disasm_view::workspace_context_t& context, sub_tab_t tab)
{
	const int idx = static_cast<int>(tab);
	if (idx < 0 || idx >= static_cast<int>(sub_tab_t::COUNT)) return;
	default_active_tab().store(idx, std::memory_order_release);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::re_hubs::select(aida::preview::re_hubs::domain_t::analysis, idx, nullptr);
#endif
	auto state = state_for(context);
	if (!state) return;
	aida::ui::hub_strip::notify_select(state->strip, idx);
}

inline void set_sub_tab(sub_tab_t tab)
{
	set_sub_tab(disasm_view::capture_selected_workspace(), tab);
}

inline sub_tab_t active_sub_tab(const disasm_view::workspace_context_t& context)
{
	auto state = state_for(context);
	return state ? static_cast<sub_tab_t>(state->strip.active) :
		static_cast<sub_tab_t>(default_active_tab().load(std::memory_order_acquire));
}

inline sub_tab_t active_sub_tab()
{
	return active_sub_tab(disasm_view::capture_selected_workspace());
}

inline constexpr aida::ui::hub_strip::tab_t s_tabs[] = {
	{ "Symbolic",      "symbolic execution",     "Sym" },
	{ "Taint",         "taint analysis",         "Tnt" },
	{ "Deobfuscation", "deobfuscation tools",    "Deo" },
	{ "Fuzzer",        "coverage fuzzing",       "Fuz" },
	{ "Protection",    "protection scan / stealth", "Prot" },
};

inline const char* sub_tab_label(sub_tab_t tab)
{
	int idx = static_cast<int>(tab);
	if (idx < 0 || idx >= static_cast<int>(sub_tab_t::COUNT))
		return "";
	return s_tabs[idx].label;
}

inline void render_active(int idx, float cw, float ch,
                          float fa, float ar, float ag, float ab,
                          const disasm_view::workspace_context_t& context)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (idx >= 0 && idx < static_cast<int>(sub_tab_t::COUNT))
		aida::preview::re_hubs::rendered(aida::preview::re_hubs::domain_t::analysis, idx, s_tabs[idx].label);
#endif
	switch (static_cast<sub_tab_t>(idx)) {
		case sub_tab_t::symbolic:
			symbolic_view::render(0.f, 0.f, cw, ch, fa, ar, ag, ab);
			break;
		case sub_tab_t::taint:
			taint_view::render(0.f, 0.f, cw, ch, fa, ar, ag, ab, context);
			break;
		case sub_tab_t::deobfuscation:
			deobfuscation_view::render(0.f, 0.f, cw, ch, fa, ar, ag, ab);
			break;
		case sub_tab_t::fuzzer:
			fuzzer_view::render(0.f, 0.f, cw, ch, fa, ar, ag, ab);
			break;
		case sub_tab_t::stealth:
			stealth_view::render(0.f, 0.f, cw, ch, fa, ar, ag, ab);
			break;
		default:
			break;
	}
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b,
				   const disasm_view::workspace_context_t& context)
{
	if (!context) {
		ImVec2 wp = ImGui::GetWindowPos();
		aida::ui::no_target_overlay::render(
			ImVec2(wp.x + pos_x, wp.y + pos_y),
			ImVec2(width, height),
			"No binary open",
			"Symbolic execution, taint, deobfuscation, fuzzing and stealth checks operate on an open binary. Open a file or attach to a process to start.",
			alpha, aida::ui::empty_state::glyph_t::cpu);
		return;
	}
	auto state = state_for(context);
	if (!state)
		return;

	float dt = aida::ui::clock::dt();
	aida::ui::hub_strip::tick_swap(state->strip, dt);

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetWindowPos();

	const int count = static_cast<int>(sub_tab_t::COUNT);
	aida::ui::hub_strip::render_strip(dl, origin, pos_x, pos_y, width,
		s_tabs, count, state->strip, alpha);
	default_active_tab().store(state->strip.active, std::memory_order_release);

	const float tab_h = 30.f;
	float content_y = pos_y + tab_h + 6.f;
	float content_h = height - tab_h - 6.f;
	if (content_h < 1.f) return;

	ImGui::SetCursorPos(ImVec2(pos_x, content_y));
	ImGui::BeginChild("##analysis_hub_content", ImVec2(width, content_h), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	float cw = ImGui::GetWindowSize().x;
	float ch = ImGui::GetWindowSize().y;

	int prev_idx = state->strip.prev;
	int new_idx  = state->strip.active;

	aida::ui::hub_strip::render_swap_content(state->strip, cw,
		[&]() { render_active(prev_idx, cw, ch, alpha, accent_r, accent_g, accent_b, context); },
		[&]() { render_active(new_idx,  cw, ch, alpha, accent_r, accent_g, accent_b, context); }
	);

	ImGui::EndChild();
}

inline void render(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b)
{
	render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b,
		disasm_view::capture_selected_workspace());
}

}
