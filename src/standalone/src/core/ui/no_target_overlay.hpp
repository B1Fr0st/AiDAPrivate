#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "components.hpp"
#include "empty_state.hpp"
#include "design_system.hpp"
#include "application_ui_runtime.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#else
#include "../../helpers/diag_log.hpp"
#endif
#include <string>

namespace aida::ui::no_target_overlay {

	enum class action_t {
		none,
		open_file,
		attach_process,
		run_target
	};

	inline action_t action_from_id(const std::string& id) {
		if (id == "open_file") return action_t::open_file;
		if (id == "attach_process") return action_t::attach_process;
		if (id == "run_target") return action_t::run_target;
		return action_t::none;
	}

	inline const char* state_id_for_glyph(aida::ui::empty_state::glyph_t glyph) {
		switch (glyph) {
		case aida::ui::empty_state::glyph_t::cpu: return "no_target.analysis";
		case aida::ui::empty_state::glyph_t::shield: return "no_target.debugger";
		case aida::ui::empty_state::glyph_t::search: return "no_target.scanner";
		case aida::ui::empty_state::glyph_t::network: return "no_target.network";
		case aida::ui::empty_state::glyph_t::memory: return "no_target.memory";
		default: return "no_target.binary";
		}
	}

	inline action_t render_actions(ImVec2 region_pos, ImVec2 region_size,
		const char* title_text, const char* subtitle_text, float alpha,
		aida::ui::empty_state::glyph_t glyph = aida::ui::empty_state::glyph_t::binary_file)
	{
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();

		dl->AddRectFilled(region_pos,
			ImVec2(region_pos.x + region_size.x, region_pos.y + region_size.y),
			aida::ui::with_alpha(t.bg_base, alpha * 0.95f));

		const auto open_action = aida::ui::application_ui::present_action("tools.load_binary");
		const auto attach_action = aida::ui::application_ui::present_action("tools.attach_process");
		const auto run_action = aida::ui::application_ui::present_action("debugger.launch");
		const aida::ui::design::action_t actions[] = {
			{"open_file", open_action.label.c_str(), "Open",
				open_action.enabled ? open_action.description.c_str() : open_action.disabled_reason.c_str(),
				open_action.shortcut.empty() ? nullptr : open_action.shortcut.c_str(),
				nullptr,
				aida::ui::components::button_kind_t::primary,
				open_action.enabled, true, open_action.visible},
			{"attach_process", attach_action.label.c_str(), "Attach",
				attach_action.enabled ? attach_action.description.c_str() : attach_action.disabled_reason.c_str(),
				attach_action.shortcut.empty() ? nullptr : attach_action.shortcut.c_str(), nullptr,
				aida::ui::components::button_kind_t::secondary,
				attach_action.enabled, false, attach_action.visible},
			{"run_target", run_action.label.c_str(), "Run",
				run_action.enabled ? run_action.description.c_str() : run_action.disabled_reason.c_str(),
				run_action.shortcut.empty() ? nullptr : run_action.shortcut.c_str(), nullptr,
				aida::ui::components::button_kind_t::secondary,
				run_action.enabled, false, run_action.visible}
		};
		aida::ui::design::state_presentation_t state;
		state.stable_id = state_id_for_glyph(glyph);
		state.state = aida::ui::design::view_state_t::empty;
		state.title = title_text;
		state.message = subtitle_text;
		state.hint = "Drag any .exe, .dll, or .sys into this window, then send evidence to the AI Assistant.";
		state.actions = actions;
		state.action_count = IM_ARRAYSIZE(actions);
		ImGui::SetCursorScreenPos(region_pos);
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * alpha);
		const aida::ui::design::action_result_t result =
			aida::ui::design::render_state(state, region_size);
		ImGui::PopStyleVar();
		return action_from_id(result.id ? result.id : "");
	}

	inline void dispatch_default_action(action_t action) {
		if (action == action_t::open_file) {
			diag::log_tagged_critical("file_dialog", "no_target_overlay.open_binary_clicked");
			static_cast<void>(aida::ui::application_ui::execute_action(
				"tools.load_binary", aida::ui::action_invocation_source_t::toolbar));
		}
		if (action == action_t::attach_process) {
			diag::log_tagged_critical("file_dialog", "no_target_overlay.attach_clicked");
			static_cast<void>(aida::ui::application_ui::execute_action(
				"tools.attach_process", aida::ui::action_invocation_source_t::toolbar));
		}
		if (action == action_t::run_target) {
			diag::log_tagged_critical("file_dialog", "no_target_overlay.run_clicked");
			static_cast<void>(aida::ui::application_ui::execute_action(
				"debugger.launch", aida::ui::action_invocation_source_t::toolbar));
		}
	}

	inline action_t render(ImVec2 region_pos, ImVec2 region_size,
		const char* title_text, const char* subtitle_text, float alpha,
		aida::ui::empty_state::glyph_t glyph = aida::ui::empty_state::glyph_t::binary_file,
		bool dispatch_default_actions = true)
	{
		action_t action = render_actions(region_pos, region_size, title_text, subtitle_text, alpha, glyph);
		if (dispatch_default_actions) dispatch_default_action(action);
		return action;
	}

}
