#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "clock.hpp"
#include "fonts.hpp"
#include "metrics.hpp"
#include "components.hpp"
#include "empty_state.hpp"

#include "../disasm/zydis_disasm.hpp"
#include "../../helpers/globals.h"
#include "../../helpers/diag_log.hpp"
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

	inline aida::ui::empty_state::config_t make_config(const char* title_text,
		const char* subtitle_text, aida::ui::empty_state::glyph_t glyph) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = glyph;
		cfg.title = title_text ? title_text : "";
		cfg.body = subtitle_text ? subtitle_text : "";
		cfg.footer = "Tip: drag any .exe/.dll/.sys into this window, then ask the AI Assistant on the right.";
		cfg.max_width = 432.f;
		cfg.actions.push_back({
			"open_file",
			"Open File...",
			aida::ui::components::button_kind_t::primary,
			false,
			"Open a binary for static analysis"
		});
		cfg.actions.push_back({
			"attach_process",
			"Attach...",
			aida::ui::components::button_kind_t::secondary,
			false,
			"Attach to a running process"
		});
		cfg.actions.push_back({
			"run_target",
			"Run...",
			aida::ui::components::button_kind_t::secondary,
			false,
			"Launch a binary under AiDA"
		});
		return cfg;
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

		aida::ui::empty_state::config_t cfg = make_config(title_text, subtitle_text, glyph);
		aida::ui::empty_state::render_result_t result =
			aida::ui::empty_state::render_panel(region_pos, region_size, cfg, alpha);
		return action_from_id(result.action_id);
	}

	inline void dispatch_default_action(action_t action) {
		if (action == action_t::open_file) {
			diag::log_tagged_critical("file_dialog", "no_target_overlay.open_clicked invoking_open_file_dialog");
			std::string fpath = disasm::open_file_dialog(g_hwnd);
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
