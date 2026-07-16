#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "components.hpp"
#include "empty_state.hpp"
#include "design_system.hpp"
#include "application_ui_runtime.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/workspace_preview_fixture.hpp"
#else
#include "../disasm/zydis_disasm.hpp"
#endif
#include "../../helpers/globals.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#endif
#include "../debugger/spawn_target_dialog.hpp"

#include <string>

extern HWND g_hwnd;

namespace analysis_session {
bool open_session(const std::string& path);
}

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

		const auto open_action = aida::ui::application_ui::present_action("file.open");
		const aida::ui::design::action_t actions[] = {
			{"open_file", "Open File...", "Open", "Open a binary for static analysis",
				open_action.shortcut.empty() ? nullptr : open_action.shortcut.c_str(),
				open_action.disabled_reason.empty() ? nullptr : open_action.disabled_reason.c_str(),
				aida::ui::components::button_kind_t::primary,
				open_action.enabled, true, open_action.visible},
			{"attach_process", "Attach...", "Attach", "Attach to a running process", nullptr, nullptr,
				aida::ui::components::button_kind_t::secondary, true, false, true},
			{"run_target", "Run...", "Run", "Launch a binary under AiDA", nullptr, nullptr,
				aida::ui::components::button_kind_t::secondary, true, false, true}
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
			diag::log_tagged_critical("file_dialog", "no_target_overlay.open_clicked invoking_open_file_dialog");
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::string fpath = aida::preview::workspace_preview_fixture().source_path;
#else
			std::string fpath = disasm::open_file_dialog(g_hwnd);
#endif
			if (!fpath.empty()) {
				diag::log_tagged_critical_fmt("file_dialog",
					"no_target_overlay.open ok path=%s", fpath.c_str());
				analysis_session::open_session(fpath);
			} else {
				diag::log_tagged_critical("file_dialog", "no_target_overlay.open cancelled_or_empty");
			}
		}
		if (action == action_t::attach_process) {
			diag::log_tagged_critical("file_dialog", "no_target_overlay.attach_clicked");
			globals::ui::process_attach_open = true;
		}
		if (action == action_t::run_target) {
			diag::log_tagged_critical("file_dialog", "no_target_overlay.run_clicked");
			spawn_target_dialog::request_open();
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
