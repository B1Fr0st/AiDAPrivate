#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "imgui/imgui.h"

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "provider_catalog.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "../ui/avatar.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/brand.hpp"
#include "../ui/clock.hpp"
#include "../ui/components.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"
#include "../ui/motion.hpp"
#include "../ui/theme.hpp"
#include "../ui/transition.hpp"
#include "../ui/responsive.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"

namespace aida {
namespace agent_manager {

	namespace detail {

		struct rule_buf_t
		{
			char permission_key[96] = {};
			char pattern[160] = {};
			int  action = 2;
		};

		struct chip_input_t
		{
			char buf[96] = {};
		};

		struct row_anim_t
		{
			aida::ui::hover_state_t hover;
			aida::ui::transition_t  entrance;
		};

		struct manager_state_t
		{
			std::mutex                          mtx;
			std::string                         err;
			std::string                         selected_name;
			bool                                initialized = false;

			char                                edit_name[96] = {};
			char                                edit_description[1024] = {};
			char                                edit_color[16] = {};
			char                                edit_system_prompt[16384] = {};
			char                                provider_buf[96] = {};
			char                                model_buf[160] = {};
			float                               temperature = 1.0f;
			float                               top_p = 1.0f;
			int                                 max_steps = 0;
			int                                 mode_index = 0;

			std::vector<rule_buf_t>             rules;
			std::vector<std::string>            tools_allowed;
			std::vector<std::string>            tools_denied;
			chip_input_t                        new_allowed;
			chip_input_t                        new_denied;
			rule_buf_t                          new_rule;
			nlohmann::json                      preserved_options = nlohmann::json::object();

			bool                                buffers_loaded_for_selected = false;
			bool                                dirty = false;

			char                                left_filter[96] = {};

			std::unordered_map<std::string, row_anim_t> row_anims;
			aida::ui::flash_t                   dirty_flash;
			bool                                last_dirty_state = false;

			bool                                section_perm_open = true;
			bool                                section_prompt_open = true;
			bool                                section_model_open = true;
			bool                                section_tools_open = true;
			aida::ui::transition_t              section_perm_anim;
			aida::ui::transition_t              section_prompt_anim;
			aida::ui::transition_t              section_model_anim;
			aida::ui::transition_t              section_tools_anim;

			aida::events::subscription_handle_t sub_changed;
		};

		inline manager_state_t& state()
		{
			static manager_state_t s;
			return s;
		}

		inline std::string action_name(int action)
		{
			switch (action) {
				case 0: return "allow";
				case 1: return "deny";
				default: return "ask";
			}
		}

		inline aida::agent::permission_rule_t::action_t action_from_int(int v)
		{
			switch (v) {
				case 0: return aida::agent::permission_rule_t::action_t::allow;
				case 1: return aida::agent::permission_rule_t::action_t::deny;
				default: return aida::agent::permission_rule_t::action_t::ask;
			}
		}

		inline int int_from_action(aida::agent::permission_rule_t::action_t a)
		{
			switch (a) {
				case aida::agent::permission_rule_t::action_t::allow: return 0;
				case aida::agent::permission_rule_t::action_t::deny:  return 1;
				default: return 2;
			}
		}

		inline int mode_from_enum(aida::agent::agent_info_t::mode_t m)
		{
			switch (m) {
				case aida::agent::agent_info_t::mode_t::primary:  return 0;
				case aida::agent::agent_info_t::mode_t::subagent: return 1;
				default: return 2;
			}
		}

		inline aida::agent::agent_info_t::mode_t mode_from_int(int v)
		{
			switch (v) {
				case 0: return aida::agent::agent_info_t::mode_t::primary;
				case 1: return aida::agent::agent_info_t::mode_t::subagent;
				default: return aida::agent::agent_info_t::mode_t::all;
			}
		}

		inline void copy_to_buf(char* dst, std::size_t cap, const std::string& src)
		{
			if (cap == 0) return;
			std::size_t copy = std::min(src.size(), cap - 1);
			std::memcpy(dst, src.data(), copy);
			dst[copy] = '\0';
		}

		inline void load_buffers_for_selected_locked()
		{
			auto& st = state();
			st.buffers_loaded_for_selected = false;
			st.dirty = false;
			st.rules.clear();
			st.tools_allowed.clear();
			st.tools_denied.clear();
			st.edit_name[0] = '\0';
			st.edit_description[0] = '\0';
			st.edit_color[0] = '\0';
			st.edit_system_prompt[0] = '\0';
			st.provider_buf[0] = '\0';
			st.model_buf[0] = '\0';
			st.temperature = 1.0f;
			st.top_p = 1.0f;
			st.max_steps = 0;
			st.mode_index = 0;
			st.new_allowed.buf[0] = '\0';
			st.new_denied.buf[0] = '\0';
			st.new_rule = rule_buf_t{};
			st.preserved_options = nlohmann::json::object();

			if (st.selected_name.empty()) return;
			const aida::agent::agent_info_t* info = aida::agent::get(st.selected_name);
			if (info == nullptr) return;
			st.preserved_options = info->options;

			copy_to_buf(st.edit_name, sizeof(st.edit_name), info->name);
			copy_to_buf(st.edit_description, sizeof(st.edit_description), info->description);
			copy_to_buf(st.edit_color, sizeof(st.edit_color), info->color);
			copy_to_buf(st.edit_system_prompt, sizeof(st.edit_system_prompt), info->system_prompt);
			st.temperature = static_cast<float>(info->temperature);
			st.top_p = static_cast<float>(info->top_p);
			st.max_steps = info->max_steps;
			st.mode_index = mode_from_enum(info->mode);

			if (info->model_override.has_value()) {
				copy_to_buf(st.provider_buf, sizeof(st.provider_buf), info->model_override->provider_id);
				copy_to_buf(st.model_buf, sizeof(st.model_buf), info->model_override->model_id);
			}

			for (const auto& r : info->permissions) {
				rule_buf_t rb;
				copy_to_buf(rb.permission_key, sizeof(rb.permission_key), r.permission_key);
				copy_to_buf(rb.pattern, sizeof(rb.pattern), r.pattern);
				rb.action = int_from_action(r.action);
				st.rules.push_back(rb);
			}
			for (const auto& t : info->tools_allowed) st.tools_allowed.push_back(t);
			for (const auto& t : info->tools_denied) st.tools_denied.push_back(t);

			st.buffers_loaded_for_selected = true;
		}

		inline aida::agent::agent_info_t build_info_from_buffers_locked(bool keep_native)
		{
			auto& st = state();
			aida::agent::agent_info_t info;
			info.name = std::string(st.edit_name);
			info.description = std::string(st.edit_description);
			info.color = std::string(st.edit_color);
			info.system_prompt = std::string(st.edit_system_prompt);
			info.temperature = st.temperature;
			info.top_p = st.top_p;
			info.max_steps = st.max_steps;
			info.mode = mode_from_int(st.mode_index);
			info.native = keep_native;
			info.hidden = false;
			if (std::strlen(st.provider_buf) > 0 || std::strlen(st.model_buf) > 0) {
				aida::agent::agent_model_override_t mo;
				mo.provider_id = std::string(st.provider_buf);
				mo.model_id = std::string(st.model_buf);
				info.model_override = mo;
			}
			for (const auto& rb : st.rules) {
				aida::agent::permission_rule_t r;
				r.permission_key = std::string(rb.permission_key);
				r.pattern = std::string(rb.pattern);
				r.action = action_from_int(rb.action);
				if (r.permission_key.empty()) continue;
				if (r.pattern.empty()) r.pattern = "*";
				info.permissions.push_back(r);
			}
			info.tools_allowed = st.tools_allowed;
			info.tools_denied = st.tools_denied;
			info.options = st.preserved_options;
			return info;
		}

		inline const char* mode_label(int mode_index)
		{
			switch (mode_index) {
				case 0: return "primary";
				case 1: return "subagent";
				default: return "all";
			}
		}

		inline void mark_dirty_locked()
		{
			auto& st = state();
			st.dirty = true;
		}

		inline bool render_section_header(const char* title, bool* open_state,
			aida::ui::transition_t& anim, ImU32 accent)
		{
			const auto& th = aida::ui::resolved();
			ImFont* font = aida::ui::fonts::body_strong();
			float fs = aida::ui::components::detail::ui_fs() * 0.98f;

			ImVec2 pos = ImGui::GetCursorScreenPos();
			float w = ImGui::GetContentRegionAvail().x;
			float h = (std::max)(32.f, fs + 16.f);

			ImGui::PushID(title);
			ImGui::InvisibleButton("##sec_hdr", ImVec2(w, h));
			bool clicked = ImGui::IsItemClicked();
			bool hovered = ImGui::IsItemHovered();
			ImGui::PopID();

			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 a = pos;
			ImVec2 b(pos.x + w, pos.y + h);
			ImU32 bg = hovered ? th.hover_wash : aida::ui::with_alpha(th.panel_header, 0.55f);
			dl->AddRectFilled(a, b, bg, 8.f);
			dl->AddLine(ImVec2(a.x, b.y - 1.f), ImVec2(b.x, b.y - 1.f),
				aida::ui::with_alpha(accent, 0.45f), 1.f);

			float ang = (*open_state ? 1.f : 0.f);
			float anim_p = anim.eased();
			float draw_ang = anim_p * 1.5707963f;
			(void)ang;

			float arrow_cx = a.x + 12.f;
			float arrow_cy = (a.y + b.y) * 0.5f;
			ImVec2 ar0(-3.f, -3.f), ar1(3.f, 0.f), ar2(-3.f, 3.f);
			float ca = cosf(draw_ang), sa = sinf(draw_ang);
			ImVec2 p0(arrow_cx + ar0.x * ca - ar0.y * sa, arrow_cy + ar0.x * sa + ar0.y * ca);
			ImVec2 p1(arrow_cx + ar1.x * ca - ar1.y * sa, arrow_cy + ar1.x * sa + ar1.y * ca);
			ImVec2 p2(arrow_cx + ar2.x * ca - ar2.y * sa, arrow_cy + ar2.x * sa + ar2.y * ca);
			dl->AddTriangleFilled(p0, p1, p2, th.text_secondary);

			dl->AddText(font, fs, ImVec2(a.x + 28.f, a.y + (h - fs) * 0.5f),
				th.text_primary, title);

			if (clicked) {
				*open_state = !*open_state;
				if (*open_state)
					anim.start(0.22f, aida::motion::ease::out_cubic);
				else
					anim.start_reverse(0.18f, aida::motion::ease::in_cubic);
			}
			anim.tick(aida::ui::clock::dt());
			(void)anim_p;
			return *open_state;
		}

	}

	inline void initialize()
	{
		auto& st = detail::state();
		std::lock_guard<std::mutex> lk(st.mtx);
		if (st.initialized) return;
		st.initialized = true;

		aida::agent::load_custom_from_disk();

		st.selected_name = aida::agent::active_agent_name();
		if (st.selected_name.empty()) st.selected_name = aida::agent::default_agent_name();
		detail::load_buffers_for_selected_locked();

		st.section_perm_anim.start(0.001f, aida::motion::ease::linear);
		st.section_prompt_anim.start(0.001f, aida::motion::ease::linear);
		st.section_model_anim.start(0.001f, aida::motion::ease::linear);
		st.section_tools_anim.start(0.001f, aida::motion::ease::linear);

		st.sub_changed = aida::events::subscribe(
			aida::events::event_agent_changed,
			std::function<void(const aida::events::agent_changed_t&)>(
				[](const aida::events::agent_changed_t&) {
				}));
	}

	inline void shutdown()
	{
		auto& st = detail::state();
		std::lock_guard<std::mutex> lk(st.mtx);
		if (st.sub_changed.valid()) {
			aida::events::unsubscribe(st.sub_changed);
			st.sub_changed = aida::events::subscription_handle_t{};
		}
		st.initialized = false;
	}

	inline const std::string& last_error()
	{
		return detail::state().err;
	}

	inline void render(float panel_w, float panel_h)
	{
		auto& st = detail::state();
		const auto& th = aida::ui::resolved();
		const float dt = aida::ui::clock::dt();

		float content_h = panel_h > 0.f ? panel_h : ImGui::GetContentRegionAvail().y;

		if (st.dirty != st.last_dirty_state) {
			if (st.dirty) st.dirty_flash.trigger();
			st.last_dirty_state = st.dirty;
		}
		float dirty_flash_v = st.dirty_flash.tick(dt, 1.5f);

		ImGui::PushID("aida_agent_manager_root");
		ImGui::BeginChild("##aida_agent_manager_root", ImVec2(panel_w, content_h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

		const float gm_gap = 12.f;
		const float gm_min_detail_w = 260.f;
		float left_w = std::clamp(panel_w * 0.24f, 190.f, 280.f);
		bool gm_stack_vertical = (panel_w - left_w - gm_gap) < gm_min_detail_w;
		if (gm_stack_vertical) {
			left_w = std::max(panel_w - 8.f, 180.f);
		}
		float right_w = gm_stack_vertical
			? std::max(panel_w - 8.f, 180.f)
			: std::max(gm_min_detail_w, panel_w - left_w - gm_gap);

		static bool s_gm_logged_stack = false;
		if (gm_stack_vertical && !s_gm_logged_stack) {
			s_gm_logged_stack = true;
			::diag::log_tagged_fmt("responsive",
				"agent_manager panel stacked panel_w=%.0f min_detail_w=%.0f",
				panel_w, gm_min_detail_w);
		} else if (!gm_stack_vertical && s_gm_logged_stack) {
			s_gm_logged_stack = false;
		}

		float gm_left_h = gm_stack_vertical
			? std::max(ImGui::GetContentRegionAvail().y * 0.42f, 160.f)
			: ImGui::GetContentRegionAvail().y;

		ImGui::BeginChild("##agent_manager_left",
			ImVec2(left_w, gm_left_h), false,
			ImGuiWindowFlags_None);

		{
			char filter_local[96];
			std::memcpy(filter_local, st.left_filter, sizeof(filter_local));
			if (aida::ui::input_text("##agent_filter", filter_local, sizeof(filter_local),
					"Filter agents...", false, ImVec2((std::max)(120.f, left_w - 14.f), 32.f))) {
				std::lock_guard<std::mutex> lk(st.mtx);
				std::memcpy(st.left_filter, filter_local, sizeof(st.left_filter));
			}
		}
		ImGui::Dummy(ImVec2(0.f, 4.f));

		std::string filter_lower;
		for (const char* p = st.left_filter; *p; ++p) {
			char c = *p;
			if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
			filter_lower.push_back(c);
		}

		const auto& all = aida::agent::list();
		ImDrawList* ldl = ImGui::GetWindowDrawList();

		size_t row_index = 0;
		for (const auto& a : all) {
			std::string name_lower;
			for (char c : a.name) {
				if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
				name_lower.push_back(c);
			}
			if (!filter_lower.empty() && name_lower.find(filter_lower) == std::string::npos)
				continue;

			detail::row_anim_t* ra = nullptr;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				ra = &st.row_anims[a.name];
			}

			const bool selected_now = (a.name == st.selected_name);
			const float row_h = 54.f;
			const float row_w = left_w - 12.f;

			ImVec2 row_pos = ImGui::GetCursorScreenPos();

			ImGui::PushID(a.name.c_str());
			ImGui::InvisibleButton("##row", ImVec2(row_w, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			ImGui::PopID();

			float hov_v = ra->hover.tick(hov, dt, aida::motion::spring::playful);
			float lift = hov_v * 2.f;
			ImVec2 ra2(row_pos.x, row_pos.y - lift);
			ImVec2 rb2(row_pos.x + row_w, row_pos.y + row_h - 6.f - lift);

			ImU32 bg_col = aida::ui::mix(
				aida::ui::with_alpha(th.panel_header, 0.5f),
				aida::ui::with_alpha(th.hover_wash, 1.f),
				hov_v * 0.7f);
			if (selected_now) {
				bg_col = aida::ui::mix(bg_col,
					aida::ui::with_alpha(th.selection, 0.85f), 0.6f);
			}
			ldl->AddRectFilled(ra2, rb2, bg_col, 10.f);
			if (selected_now) {
				ldl->AddRect(ra2, rb2, th.accent_u32, 10.f, 0, 1.5f);
			} else {
				ldl->AddRect(ra2, rb2,
					aida::ui::with_alpha(th.border_subtle, 0.6f + 0.4f * hov_v),
					10.f, 0, 1.f);
			}

			const float av_r = 12.f;
			ImVec2 av_c(ra2.x + 10.f + av_r, (ra2.y + rb2.y) * 0.5f);
			aida::ui::avatar::render(ldl, av_c, av_r, a.name,
				aida::ui::avatar::kind_t::gradient, true, 1.f,
				aida::ui::fonts::body_strong());

			ldl->AddText(aida::ui::fonts::body_strong(),
				aida::ui::components::detail::ui_fs() * 0.96f,
				ImVec2(av_c.x + av_r + 8.f, ra2.y + 6.f),
				th.text_primary, a.name.c_str());

			ImGui::SetCursorScreenPos(ImVec2(av_c.x + av_r + 8.f, ra2.y + 24.f));
			aida::ui::pill_kind(a.native ? "native" : "custom",
				a.native ? aida::ui::pill_kind_t::info : aida::ui::pill_kind_t::warning,
				aida::ui::size_t_::sm, false);

			if (a.hidden) {
				ImGui::SetCursorScreenPos(ImVec2(rb2.x - 84.f, ra2.y + 7.f));
				aida::ui::badge("hidden", aida::ui::with_alpha(th.text_dim, 0.85f), 4.f);
			}

			if (clicked) {
				if (st.dirty && a.name != st.selected_name) {
					toast_notification::push("Discarded unsaved changes",
						toast_notification::toast_type_t::warning, 3.5f);
				}
				st.selected_name = a.name;
				detail::load_buffers_for_selected_locked();
			}

			ImGui::SetCursorScreenPos(ImVec2(row_pos.x, row_pos.y + row_h));
			++row_index;
		}

		ImGui::EndChild();

		if (!gm_stack_vertical) ImGui::SameLine();

		ImGui::BeginChild("##agent_manager_right",
			ImVec2(right_w, ImGui::GetContentRegionAvail().y), false,
			ImGuiWindowFlags_HorizontalScrollbar);

		const aida::agent::agent_info_t* selected_info = aida::agent::get(st.selected_name);
		bool is_native = selected_info != nullptr && selected_info->native;
		bool empty_selection = selected_info == nullptr;

		if (empty_selection) {
			ImVec2 region_pos = ImGui::GetCursorScreenPos();
			ImVec2 region_size(right_w - 8.f, ImGui::GetContentRegionAvail().y);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::dots;
			cfg.title = "No agent selected";
			cfg.body = "Pick an agent on the left to inspect or edit its configuration.";
			cfg.max_width = right_w * 0.8f;
			aida::ui::empty_state::render(region_pos, region_size, cfg);
		} else {
			ImDrawList* dl = ImGui::GetWindowDrawList();

			ImVec2 hdr_pos = ImGui::GetCursorScreenPos();
			float hdr_w = ImGui::GetContentRegionAvail().x;
			float hdr_h = 60.f;

			ImVec2 ha(hdr_pos.x, hdr_pos.y);
			ImVec2 hb(hdr_pos.x + hdr_w, hdr_pos.y + hdr_h);
			dl->AddRectFilled(ha, hb,
				aida::ui::with_alpha(th.panel_header, 0.6f), 10.f);
			dl->AddRect(ha, hb, th.border_subtle, 10.f, 0, 1.f);

			const float av_r = 20.f;
			ImVec2 av_c(ha.x + 16.f + av_r, (ha.y + hb.y) * 0.5f);
			aida::ui::avatar::render(dl, av_c, av_r, st.selected_name,
				aida::ui::avatar::kind_t::gradient, true, 1.f,
				aida::ui::fonts::body_strong());

			dl->AddText(aida::ui::fonts::h2(),
				aida::ui::components::detail::ui_fs() * 1.28f,
				ImVec2(av_c.x + av_r + 14.f, ha.y + 9.f),
				th.text_primary, st.selected_name.c_str());

			ImGui::SetCursorScreenPos(ImVec2(av_c.x + av_r + 14.f, ha.y + 32.f));
			aida::ui::pill_kind(is_native ? "native" : "custom",
				is_native ? aida::ui::pill_kind_t::info : aida::ui::pill_kind_t::warning,
				aida::ui::size_t_::sm, false);
			ImGui::SameLine(0.f, 8.f);
			if (st.dirty) {
				float bounce = 1.f + 0.08f * sinf(aida::ui::clock::seconds() * 6.f) * dirty_flash_v;
				ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f * bounce, 4.f));
				aida::ui::pill_kind("Unsaved changes", aida::ui::pill_kind_t::warning,
					aida::ui::size_t_::sm, true);
				ImGui::PopStyleVar();
			} else {
				aida::ui::pill_kind("Up to date", aida::ui::pill_kind_t::success,
					aida::ui::size_t_::sm, false);
			}

			ImGui::SetCursorScreenPos(ImVec2(hdr_pos.x, hdr_pos.y + hdr_h + 12.f));

			if (is_native) {
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary),
					"Built-in agents are read-only. Click \"Duplicate as custom\" to override.");
				ImGui::Spacing();
			}

			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 6.f));

			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Name");
			ImGui::SetNextItemWidth(-FLT_MIN);
			if (ImGui::InputText("##agent_name", st.edit_name, sizeof(st.edit_name),
				is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
				detail::mark_dirty_locked();
			}

			ImGui::Spacing();
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Description");
			ImGui::SetNextItemWidth(-FLT_MIN);
			if (ImGui::InputTextMultiline("##agent_desc", st.edit_description,
				sizeof(st.edit_description), ImVec2(0, ImGui::GetFontSize() * 2.2f + 8.f),
				is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
				detail::mark_dirty_locked();
			}

			ImGui::Spacing();
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Color");
			ImGui::SetNextItemWidth(120.f);
			if (ImGui::InputText("##agent_color", st.edit_color, sizeof(st.edit_color),
				is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
				detail::mark_dirty_locked();
			}
			ImGui::SameLine(0.f, 8.f);
			ImVec4 preview = ImVec4(0.5f, 0.5f, 0.7f, 1.f);
			{
				const std::string hex(st.edit_color);
				auto from_hex = [](char c) -> int {
					if (c >= '0' && c <= '9') return c - '0';
					if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
					if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
					return -1;
				};
				if (hex.size() >= 7 && hex[0] == '#') {
					int r1 = from_hex(hex[1]);
					int r2 = from_hex(hex[2]);
					int g1 = from_hex(hex[3]);
					int g2 = from_hex(hex[4]);
					int b1 = from_hex(hex[5]);
					int b2 = from_hex(hex[6]);
					if (r1 >= 0 && r2 >= 0 && g1 >= 0 && g2 >= 0 && b1 >= 0 && b2 >= 0) {
						preview = ImVec4((r1 * 16 + r2) / 255.f, (g1 * 16 + g2) / 255.f, (b1 * 16 + b2) / 255.f, 1.f);
					}
				}
			}
			ImGui::ColorButton("##agent_color_preview", preview, ImGuiColorEditFlags_NoTooltip, ImVec2(40.f, 28.f));
			ImGui::SameLine(0.f, 8.f);
			if (!is_native) {
				float col[3] = { preview.x, preview.y, preview.z };
				ImGui::SetNextItemWidth(120.f);
				if (ImGui::ColorEdit3("##agent_color_picker", col,
					ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel)) {
					int r = static_cast<int>(col[0] * 255.f);
					int g = static_cast<int>(col[1] * 255.f);
					int b = static_cast<int>(col[2] * 255.f);
					std::snprintf(st.edit_color, sizeof(st.edit_color), "#%02X%02X%02X", r, g, b);
					detail::mark_dirty_locked();
				}
			}

			ImGui::Spacing();
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Mode");
			ImGui::SetNextItemWidth(180.f);
			const char* modes[] = { "primary", "subagent", "all" };
			if (is_native) {
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "%s", detail::mode_label(st.mode_index));
			} else {
				if (ImGui::Combo("##agent_mode", &st.mode_index, modes, IM_ARRAYSIZE(modes))) {
					detail::mark_dirty_locked();
				}
			}

			ImGui::Spacing();
			ImGui::Spacing();

			if (detail::render_section_header("System prompt", &st.section_prompt_open,
					st.section_prompt_anim, th.accent_u32)) {
				ImGui::SetNextItemWidth(-FLT_MIN);
				if (ImGui::InputTextMultiline("##agent_sys_prompt", st.edit_system_prompt,
					sizeof(st.edit_system_prompt),
					ImVec2(0, ImGui::GetFontSize() * 12.f + 8.f),
					is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_AllowTabInput)) {
					detail::mark_dirty_locked();
				}
			}

			ImGui::Spacing();

			if (detail::render_section_header("Model override", &st.section_model_open,
					st.section_model_anim, th.accent_u32)) {
				const auto& providers = aida::provider::catalog::list_providers();
				const float model_avail = (std::max)(160.f, ImGui::GetContentRegionAvail().x);
				const bool model_narrow = model_avail < 360.f;
				const bool model_medium = model_avail < 560.f;
				const float provider_w = model_narrow ? model_avail : (model_medium ? (model_avail - 8.f) * 0.5f : 180.f);
				const float model_w = model_narrow ? model_avail : (model_medium ? (model_avail - 8.f) * 0.5f : 220.f);

				ImGui::SetNextItemWidth(provider_w);
				std::string prov_label = std::strlen(st.provider_buf) > 0 ? std::string(st.provider_buf) : std::string("(default)");
				if (ImGui::BeginCombo("##agent_provider", prov_label.c_str())) {
					bool default_selected = std::strlen(st.provider_buf) == 0;
					if (ImGui::Selectable("(default)", default_selected)) {
						st.provider_buf[0] = '\0';
						st.model_buf[0] = '\0';
						detail::mark_dirty_locked();
					}
					for (const auto& p : providers) {
						bool selected = (std::string(st.provider_buf) == p.id);
						if (ImGui::Selectable(p.id.c_str(), selected)) {
							detail::copy_to_buf(st.provider_buf, sizeof(st.provider_buf), p.id);
							st.model_buf[0] = '\0';
							detail::mark_dirty_locked();
						}
					}
					ImGui::EndCombo();
				}

				if (!model_narrow)
					ImGui::SameLine(0.f, 8.f);
				ImGui::SetNextItemWidth(model_w);
				std::string model_label = std::strlen(st.model_buf) > 0 ? std::string(st.model_buf) : std::string("(default)");
				if (ImGui::BeginCombo("##agent_model", model_label.c_str())) {
					bool default_selected = std::strlen(st.model_buf) == 0;
					if (ImGui::Selectable("(default)", default_selected)) {
						st.model_buf[0] = '\0';
						detail::mark_dirty_locked();
					}
					const aida::provider::provider_info_t* prov = nullptr;
					if (std::strlen(st.provider_buf) > 0)
						prov = aida::provider::catalog::get_provider(std::string(st.provider_buf));
					if (prov != nullptr) {
						for (const auto& mid : prov->model_ids) {
							bool selected = (std::string(st.model_buf) == mid);
							if (ImGui::Selectable(mid.c_str(), selected)) {
								detail::copy_to_buf(st.model_buf, sizeof(st.model_buf), mid);
								detail::mark_dirty_locked();
							}
						}
					} else {
						ImGui::TextDisabled("(pick a provider first)");
					}
					ImGui::EndCombo();
				}

				ImGui::Spacing();
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Temperature");
				const float slider_w = model_narrow ? model_avail : (model_medium ? (model_avail - 8.f) * 0.5f : 220.f);
				ImGui::SetNextItemWidth(slider_w);
				if (ImGui::SliderFloat("##agent_temp", &st.temperature, 0.f, 2.f, "%.2f")) {
					detail::mark_dirty_locked();
				}
				if (!model_narrow)
					ImGui::SameLine(0.f, 12.f);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Top-p");
				if (!model_narrow && !model_medium)
					ImGui::SameLine();
				ImGui::SetNextItemWidth(model_narrow ? model_avail : (model_medium ? slider_w : 180.f));
				if (ImGui::SliderFloat("##agent_topp", &st.top_p, 0.f, 1.f, "%.2f")) {
					detail::mark_dirty_locked();
				}
				if (!model_medium)
					ImGui::SameLine(0.f, 12.f);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Max steps");
				if (!model_medium)
					ImGui::SameLine();
				ImGui::SetNextItemWidth(model_narrow ? model_avail : 120.f);
				if (ImGui::InputInt("##agent_max_steps", &st.max_steps, 1, 8,
					is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
					if (st.max_steps < 0) st.max_steps = 0;
					detail::mark_dirty_locked();
				}
			}

			ImGui::Spacing();

			if (detail::render_section_header("Permission rules", &st.section_perm_open,
					st.section_perm_anim, th.accent_u32)) {
				const float rules_avail = (std::max)(160.f, ImGui::GetContentRegionAvail().x);
				int remove_idx = -1;
				const char* actions[] = { "allow", "deny", "ask" };
				if (rules_avail >= 520.f) {
					if (ImGui::BeginTable("##agent_rules", 4,
						ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
						ImGui::TableSetupColumn("Permission Key", ImGuiTableColumnFlags_WidthStretch, 0.30f);
						ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch, 0.40f);
						ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 100.f);
						ImGui::TableSetupColumn("##rm", ImGuiTableColumnFlags_WidthFixed, 32.f);
						ImGui::TableHeadersRow();

						for (size_t i = 0; i < st.rules.size(); ++i) {
							ImGui::TableNextRow();
							ImGui::PushID(static_cast<int>(i));
							ImGui::TableSetColumnIndex(0);
							ImGui::SetNextItemWidth(-FLT_MIN);
							if (ImGui::InputText("##rk", st.rules[i].permission_key, sizeof(st.rules[i].permission_key),
								is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
								detail::mark_dirty_locked();
							}
							ImGui::TableSetColumnIndex(1);
							ImGui::SetNextItemWidth(-FLT_MIN);
							if (ImGui::InputText("##rp", st.rules[i].pattern, sizeof(st.rules[i].pattern),
								is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
								detail::mark_dirty_locked();
							}
							ImGui::TableSetColumnIndex(2);
							ImGui::SetNextItemWidth(-FLT_MIN);
							if (is_native) {
								ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "%s",
									actions[std::clamp(st.rules[i].action, 0, 2)]);
							} else {
								if (ImGui::Combo("##ra", &st.rules[i].action, actions, IM_ARRAYSIZE(actions))) {
									detail::mark_dirty_locked();
								}
							}
							ImGui::TableSetColumnIndex(3);
							if (!is_native) {
								if (aida::ui::button("X", aida::ui::button_kind_t::ghost,
										aida::ui::size_t_::sm, ImVec2(28.f, 28.f))) {
									remove_idx = static_cast<int>(i);
								}
							}
							ImGui::PopID();
						}
						ImGui::EndTable();
					}
				} else {
					for (size_t i = 0; i < st.rules.size(); ++i) {
						ImGui::PushID(static_cast<int>(i));
						ImGui::PushStyleColor(ImGuiCol_ChildBg,
							ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_header, 0.45f)));
						ImGui::BeginChild("##rule_card", ImVec2(0.f, is_native ? 108.f : 138.f), true,
							ImGuiWindowFlags_NoSavedSettings);
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Permission Key");
						ImGui::SetNextItemWidth(-FLT_MIN);
						if (ImGui::InputText("##rk_card", st.rules[i].permission_key, sizeof(st.rules[i].permission_key),
							is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
							detail::mark_dirty_locked();
						}
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Pattern");
						ImGui::SetNextItemWidth(-FLT_MIN);
						if (ImGui::InputText("##rp_card", st.rules[i].pattern, sizeof(st.rules[i].pattern),
							is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
							detail::mark_dirty_locked();
						}
						if (is_native) {
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "%s",
								actions[std::clamp(st.rules[i].action, 0, 2)]);
						} else {
							ImGui::SetNextItemWidth((std::min)(140.f, rules_avail));
							if (ImGui::Combo("##ra_card", &st.rules[i].action, actions, IM_ARRAYSIZE(actions)))
								detail::mark_dirty_locked();
							if (rules_avail >= 250.f)
								ImGui::SameLine(0.f, 8.f);
							if (aida::ui::button("Remove",
									aida::ui::button_kind_t::ghost,
									aida::ui::size_t_::sm,
									ImVec2((std::min)(96.f, rules_avail), 24.f))) {
								remove_idx = static_cast<int>(i);
							}
						}
						ImGui::EndChild();
						ImGui::PopStyleColor();
						ImGui::Dummy(ImVec2(0.f, 6.f));
						ImGui::PopID();
					}
				}
				if (remove_idx >= 0) {
					st.rules.erase(st.rules.begin() + remove_idx);
					detail::mark_dirty_locked();
				}
				if (!is_native) {
					const float add_avail = (std::max)(160.f, ImGui::GetContentRegionAvail().x);
					const bool add_stack = add_avail < 600.f;
					ImGui::SetNextItemWidth(add_stack ? add_avail : 180.f);
					ImGui::InputTextWithHint("##new_rk", "permission key",
						st.new_rule.permission_key, sizeof(st.new_rule.permission_key));
					if (!add_stack)
						ImGui::SameLine();
					ImGui::SetNextItemWidth(add_stack ? add_avail : 220.f);
					ImGui::InputTextWithHint("##new_rp", "pattern (eg. **/*.cpp)",
						st.new_rule.pattern, sizeof(st.new_rule.pattern));
					if (!add_stack)
						ImGui::SameLine();
					ImGui::SetNextItemWidth(add_stack ? (std::min)(140.f, add_avail) : 80.f);
					ImGui::Combo("##new_ra", &st.new_rule.action, actions, IM_ARRAYSIZE(actions));
					if (!add_stack)
						ImGui::SameLine();
					if (aida::ui::button("Add rule",
							aida::ui::button_kind_t::secondary,
							aida::ui::size_t_::sm,
							ImVec2(add_stack ? (std::min)(add_avail, 140.f) : 96.f, 24.f))) {
						if (std::strlen(st.new_rule.permission_key) > 0) {
							st.rules.push_back(st.new_rule);
							st.new_rule = detail::rule_buf_t{};
							detail::mark_dirty_locked();
						}
					}
				}
			}

			ImGui::Spacing();

			if (detail::render_section_header("Tools", &st.section_tools_open,
					st.section_tools_anim, th.accent_u32)) {
				auto chip_strip = [&](const char* label, std::vector<std::string>& chips,
					detail::chip_input_t& input, const char* hint, ImU32 chip_col) {
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "%s", label);
					int remove_idx = -1;
					float chip_x_start = ImGui::GetCursorScreenPos().x;
					float chip_avail = ImGui::GetContentRegionAvail().x;
					float chip_x = chip_x_start;
					float chip_y = ImGui::GetCursorScreenPos().y;

					for (size_t i = 0; i < chips.size(); ++i) {
						ImGui::PushID(static_cast<int>(i + 1000));
						ImFont* font = ImGui::GetFont();
						float fs = aida::ui::components::detail::sz_font(aida::ui::size_t_::sm);
						float text_w = font->CalcTextSizeA(fs, FLT_MAX, 0.f, chips[i].c_str()).x;
						float chip_w = text_w + 34.f;
						if (chip_x - chip_x_start + chip_w > chip_avail) {
							chip_x = chip_x_start;
							chip_y += 30.f;
						}
						ImGui::SetCursorScreenPos(ImVec2(chip_x, chip_y));
						bool removed = false;
						aida::ui::components::chip(chips[i].c_str(),
							aida::ui::with_alpha(chip_col, 0.95f),
							!is_native, &removed);
						if (removed && !is_native) remove_idx = static_cast<int>(i);
						chip_x += chip_w + 4.f;
						ImGui::PopID();
					}
					if (remove_idx >= 0) {
						chips.erase(chips.begin() + remove_idx);
						detail::mark_dirty_locked();
					}
					ImGui::SetCursorScreenPos(ImVec2(chip_x_start, chip_y + 28.f));
					if (!is_native) {
						const float input_avail = (std::max)(120.f, ImGui::GetContentRegionAvail().x);
						const bool chip_stack = input_avail < 320.f;
						ImGui::SetNextItemWidth(chip_stack ? input_avail : (std::min)(220.f, input_avail - 84.f));
						ImGui::InputTextWithHint(("##chip_in_" + std::string(label)).c_str(), hint,
							input.buf, sizeof(input.buf));
						if (!chip_stack)
							ImGui::SameLine();
						if (aida::ui::button(("Add##" + std::string(label)).c_str(),
								aida::ui::button_kind_t::secondary,
								aida::ui::size_t_::sm,
								ImVec2(chip_stack ? (std::min)(input_avail, 96.f) : 72.f, 24.f))) {
							if (std::strlen(input.buf) > 0) {
								chips.emplace_back(input.buf);
								input.buf[0] = '\0';
								detail::mark_dirty_locked();
							}
						}
					}
				};

				chip_strip("Tools allowed", st.tools_allowed, st.new_allowed, "tool name", th.success);
				ImGui::Dummy(ImVec2(0.f, 6.f));
				chip_strip("Tools denied", st.tools_denied, st.new_denied, "tool name", th.error);
			}

			ImGui::PopStyleVar(2);

			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();

			if (is_native) {
				const float footer_avail = (std::max)(160.f, ImGui::GetContentRegionAvail().x);
				if (aida::ui::button("Duplicate as custom",
						aida::ui::button_kind_t::primary,
						aida::ui::size_t_::md,
						ImVec2((std::min)(180.f, footer_avail), 32.f))) {
					aida::agent::agent_info_t copy = detail::build_info_from_buffers_locked(false);
					copy.name = st.selected_name + "-custom";
					copy.native = false;
					if (aida::agent::register_custom(copy)) {
						aida::agent::save_custom_to_disk();
						st.selected_name = copy.name;
						detail::load_buffers_for_selected_locked();
						toast_notification::push("Custom agent created: " + copy.name,
							toast_notification::toast_type_t::info, 3.5f);
					} else {
						toast_notification::push("Duplicate failed: " + aida::agent::last_error(),
							toast_notification::toast_type_t::error, 5.f);
					}
				}
			} else {
				const float footer_avail = (std::max)(160.f, ImGui::GetContentRegionAvail().x);
				const bool footer_stack = footer_avail < 290.f;
				const float footer_btn_w = footer_stack ? (std::min)(footer_avail, 140.f) : 86.f;
				if (aida::ui::button("Save",
						aida::ui::button_kind_t::primary,
						aida::ui::size_t_::md,
						ImVec2(footer_btn_w, 32.f))) {
					std::string trimmed_name(st.edit_name);
					if (trimmed_name.empty()) {
						toast_notification::push("Agent name cannot be empty",
							toast_notification::toast_type_t::error, 4.f);
					} else {
						aida::agent::agent_info_t info = detail::build_info_from_buffers_locked(false);
						bool need_unregister = (info.name != st.selected_name);
						if (aida::agent::register_custom(info)) {
							if (need_unregister && !st.selected_name.empty())
								aida::agent::unregister_custom(st.selected_name);
							aida::agent::save_custom_to_disk();
							st.selected_name = info.name;
							st.dirty = false;
							toast_notification::push("Saved agent: " + info.name,
								toast_notification::toast_type_t::info, 3.5f);
							detail::load_buffers_for_selected_locked();
						} else {
							toast_notification::push("Save failed: " + aida::agent::last_error(),
								toast_notification::toast_type_t::error, 5.f);
						}
					}
				}
				if (!footer_stack)
					ImGui::SameLine(0.f, 8.f);
				if (aida::ui::button("Reset",
						aida::ui::button_kind_t::secondary,
						aida::ui::size_t_::md,
						ImVec2(footer_btn_w, 32.f))) {
					detail::load_buffers_for_selected_locked();
					toast_notification::push("Reverted unsaved changes",
						toast_notification::toast_type_t::info, 2.5f);
				}
				if (!footer_stack)
					ImGui::SameLine(0.f, 8.f);
				if (aida::ui::button("Delete",
						aida::ui::button_kind_t::destructive,
						aida::ui::size_t_::md,
						ImVec2(footer_btn_w, 32.f))) {
					if (aida::agent::unregister_custom(st.selected_name)) {
						aida::agent::save_custom_to_disk();
						toast_notification::push("Deleted: " + st.selected_name,
							toast_notification::toast_type_t::info, 3.f);
						st.selected_name = aida::agent::default_agent_name();
						detail::load_buffers_for_selected_locked();
					} else {
						toast_notification::push("Delete failed: " + aida::agent::last_error(),
							toast_notification::toast_type_t::error, 5.f);
					}
				}
			}
		}

		ImGui::EndChild();

		ImGui::EndChild();
		ImGui::PopID();
		(void)dirty_flash_v;
	}

}
}
