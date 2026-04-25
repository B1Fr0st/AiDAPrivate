#pragma once

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "imgui/imgui.h"

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "provider_catalog.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

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

			bool                                buffers_loaded_for_selected = false;
			bool                                dirty = false;
			bool                                pending_save_status = false;
			std::string                         pending_save_text;

			char                                left_filter[96] = {};

			aida::events::subscription_handle_t sub_changed;
		};

		inline manager_state_t& state()
		{
			static manager_state_t s;
			return s;
		}

		inline void set_err_locked(const std::string& msg)
		{
			state().err = msg;
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

			if (st.selected_name.empty()) return;
			const aida::agent::agent_info_t* info = aida::agent::get(st.selected_name);
			if (info == nullptr) return;

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
			return info;
		}

		inline std::string available_providers_combo_label_locked()
		{
			std::string label;
			label = std::strlen(state().provider_buf) > 0 ? std::string(state().provider_buf) : std::string("(default)");
			return label;
		}

		inline std::string available_models_combo_label_locked()
		{
			std::string label = std::strlen(state().model_buf) > 0 ? std::string(state().model_buf) : std::string("(default)");
			return label;
		}

		inline ImU32 mode_color(int mode_index)
		{
			switch (mode_index) {
				case 0: return IM_COL32(70, 110, 170, 220);
				case 1: return IM_COL32(110, 170, 90, 220);
				default: return IM_COL32(150, 130, 90, 220);
			}
		}

		inline const char* mode_label(int mode_index)
		{
			switch (mode_index) {
				case 0: return "primary";
				case 1: return "subagent";
				default: return "all";
			}
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
		float content_h = panel_h > 0.f ? panel_h : ImGui::GetContentRegionAvail().y;

		ImGui::PushID("aida_agent_manager_root");
		ImGui::BeginChild("##aida_agent_manager_root", ImVec2(panel_w, content_h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

		float left_w = std::max(180.f, panel_w * 0.30f);
		float right_w = std::max(220.f, panel_w - left_w - 12.f);

		ImGui::BeginChild("##agent_manager_left",
			ImVec2(left_w, ImGui::GetContentRegionAvail().y), true,
			ImGuiWindowFlags_None);

		ImGui::PushItemWidth(-FLT_MIN);
		ImGui::InputTextWithHint("##agent_filter", "Filter...",
			st.left_filter, sizeof(st.left_filter));
		ImGui::PopItemWidth();
		ImGui::Separator();

		std::string filter_lower;
		for (const char* p = st.left_filter; *p; ++p) {
			char c = *p;
			if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
			filter_lower.push_back(c);
		}

		const auto& all = aida::agent::list();
		for (const auto& a : all) {
			std::string name_lower;
			for (char c : a.name) {
				if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
				name_lower.push_back(c);
			}
			if (!filter_lower.empty() && name_lower.find(filter_lower) == std::string::npos)
				continue;

			bool selected_now = (a.name == st.selected_name);
			ImGui::PushID(a.name.c_str());
			ImVec4 push_color = a.native
				? ImVec4(0.65f, 0.78f, 0.95f, 1.f)
				: ImVec4(0.95f, 0.83f, 0.65f, 1.f);
			ImGui::PushStyleColor(ImGuiCol_Text, push_color);
			std::string row = a.name;
			if (a.hidden) row += " (hidden)";
			if (ImGui::Selectable(row.c_str(), selected_now)) {
				if (st.dirty && a.name != st.selected_name) {
					toast_notification::push("Discarded unsaved changes",
						toast_notification::toast_type_t::warning, 3.5f);
				}
				st.selected_name = a.name;
				detail::load_buffers_for_selected_locked();
			}
			ImGui::PopStyleColor();
			ImGui::SameLine(left_w - 56.f);
			if (a.native) {
				ImGui::TextColored(ImVec4(0.55f, 0.7f, 0.95f, 0.9f), "native");
			} else {
				ImGui::TextColored(ImVec4(0.95f, 0.78f, 0.55f, 0.9f), "custom");
			}
			ImGui::PopID();
		}

		ImGui::EndChild();

		ImGui::SameLine();

		ImGui::BeginChild("##agent_manager_right",
			ImVec2(right_w, ImGui::GetContentRegionAvail().y), true,
			ImGuiWindowFlags_HorizontalScrollbar);

		const aida::agent::agent_info_t* selected_info = aida::agent::get(st.selected_name);
		bool is_native = selected_info != nullptr && selected_info->native;
		bool empty_selection = selected_info == nullptr;

		if (empty_selection) {
			ImGui::TextColored(ImVec4(0.65f, 0.66f, 0.78f, 1.f), "Select an agent to inspect or edit.");
		} else {
			float ar = globals::ui::accent.x;
			float ag = globals::ui::accent.y;
			float ab = globals::ui::accent.z;

			ImGui::TextColored(ImVec4(0.92f, 0.92f, 0.96f, 1.f), "%s", st.selected_name.c_str());
			ImGui::SameLine(0.f, 8.f);
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ui_anim::render_badge(dl,
				is_native ? "native" : "custom",
				cp.x, cp.y - 2.f,
				is_native
					? IM_COL32(40, 56, 80, 220)
					: IM_COL32(80, 56, 36, 220),
				is_native
					? IM_COL32(170, 200, 235, 230)
					: IM_COL32(235, 200, 150, 230));
			ImGui::Dummy(ImVec2(60.f, 0.f));

			ImGui::Spacing();

			if (is_native) {
				ImGui::TextColored(ImVec4(0.7f, 0.72f, 0.85f, 1.f),
					"Built-in agents are read-only. Click \"Duplicate as custom\" to override.");
			}

			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));

			ImGui::TextDisabled("Name");
			ImGui::SetNextItemWidth(-FLT_MIN);
			if (ImGui::InputText("##agent_name", st.edit_name, sizeof(st.edit_name),
				is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
				st.dirty = true;
			}

			ImGui::Spacing();
			ImGui::TextDisabled("Description");
			ImGui::SetNextItemWidth(-FLT_MIN);
			if (ImGui::InputTextMultiline("##agent_desc", st.edit_description,
				sizeof(st.edit_description), ImVec2(0, ImGui::GetFontSize() * 2.2f + 8.f),
				is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
				st.dirty = true;
			}

			ImGui::Spacing();
			ImGui::TextDisabled("Color");
			ImGui::SetNextItemWidth(120.f);
			if (ImGui::InputText("##agent_color", st.edit_color, sizeof(st.edit_color),
				is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
				st.dirty = true;
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
			ImGui::ColorButton("##agent_color_preview", preview, ImGuiColorEditFlags_NoTooltip, ImVec2(28.f, 22.f));
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
					st.dirty = true;
				}
			}

			ImGui::Spacing();
			ImGui::TextDisabled("Mode");
			ImGui::SetNextItemWidth(180.f);
			const char* modes[] = { "primary", "subagent", "all" };
			if (is_native) {
				ImGui::TextColored(ImVec4(0.78f, 0.8f, 0.9f, 1.f), "%s", detail::mode_label(st.mode_index));
			} else {
				if (ImGui::Combo("##agent_mode", &st.mode_index, modes, IM_ARRAYSIZE(modes))) {
					st.dirty = true;
				}
			}

			ImGui::Spacing();
			ImGui::TextDisabled("System prompt");
			ImGui::SetNextItemWidth(-FLT_MIN);
			ImGui::PushFont(ImGui::GetFont());
			if (ImGui::InputTextMultiline("##agent_sys_prompt", st.edit_system_prompt,
				sizeof(st.edit_system_prompt),
				ImVec2(0, ImGui::GetFontSize() * 12.f + 8.f),
				is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_AllowTabInput)) {
				st.dirty = true;
			}
			ImGui::PopFont();

			ImGui::Spacing();
			ImGui::TextDisabled("Model override");
			const auto& providers = aida::provider::catalog::list_providers();

			ImGui::SetNextItemWidth(180.f);
			std::string prov_label = std::strlen(st.provider_buf) > 0 ? std::string(st.provider_buf) : std::string("(default)");
			if (ImGui::BeginCombo("##agent_provider", prov_label.c_str())) {
				bool default_selected = std::strlen(st.provider_buf) == 0;
				if (ImGui::Selectable("(default)", default_selected)) {
					st.provider_buf[0] = '\0';
					st.model_buf[0] = '\0';
					st.dirty = true;
				}
				for (const auto& p : providers) {
					bool selected = (std::string(st.provider_buf) == p.id);
					if (ImGui::Selectable(p.id.c_str(), selected)) {
						detail::copy_to_buf(st.provider_buf, sizeof(st.provider_buf), p.id);
						st.model_buf[0] = '\0';
						st.dirty = true;
					}
				}
				ImGui::EndCombo();
			}

			ImGui::SameLine(0.f, 8.f);
			ImGui::SetNextItemWidth(220.f);
			std::string model_label = std::strlen(st.model_buf) > 0 ? std::string(st.model_buf) : std::string("(default)");
			if (ImGui::BeginCombo("##agent_model", model_label.c_str())) {
				bool default_selected = std::strlen(st.model_buf) == 0;
				if (ImGui::Selectable("(default)", default_selected)) {
					st.model_buf[0] = '\0';
					st.dirty = true;
				}
				const aida::provider::provider_info_t* prov = nullptr;
				if (std::strlen(st.provider_buf) > 0)
					prov = aida::provider::catalog::get_provider(std::string(st.provider_buf));
				if (prov != nullptr) {
					for (const auto& mid : prov->model_ids) {
						bool selected = (std::string(st.model_buf) == mid);
						if (ImGui::Selectable(mid.c_str(), selected)) {
							detail::copy_to_buf(st.model_buf, sizeof(st.model_buf), mid);
							st.dirty = true;
						}
					}
				} else {
					ImGui::TextDisabled("(pick a provider first)");
				}
				ImGui::EndCombo();
			}

			ImGui::Spacing();
			ImGui::TextDisabled("Temperature");
			ImGui::SetNextItemWidth(220.f);
			if (ImGui::SliderFloat("##agent_temp", &st.temperature, 0.f, 2.f, "%.2f")) {
				st.dirty = true;
			}
			ImGui::SameLine(0.f, 12.f);
			ImGui::TextDisabled("Top-p");
			ImGui::SameLine();
			ImGui::SetNextItemWidth(180.f);
			if (ImGui::SliderFloat("##agent_topp", &st.top_p, 0.f, 1.f, "%.2f")) {
				st.dirty = true;
			}
			ImGui::SameLine(0.f, 12.f);
			ImGui::TextDisabled("Max steps");
			ImGui::SameLine();
			ImGui::SetNextItemWidth(120.f);
			if (ImGui::InputInt("##agent_max_steps", &st.max_steps, 1, 8,
				is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
				if (st.max_steps < 0) st.max_steps = 0;
				st.dirty = true;
			}

			ImGui::Spacing();
			ImGui::TextDisabled("Permission rules");
			if (ImGui::BeginTable("##agent_rules", 4,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
				ImGui::TableSetupColumn("Permission Key", ImGuiTableColumnFlags_WidthStretch, 0.30f);
				ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch, 0.40f);
				ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 100.f);
				ImGui::TableSetupColumn("##rm", ImGuiTableColumnFlags_WidthFixed, 32.f);
				ImGui::TableHeadersRow();

				int remove_idx = -1;
				for (size_t i = 0; i < st.rules.size(); ++i) {
					ImGui::TableNextRow();
					ImGui::PushID(static_cast<int>(i));
					ImGui::TableSetColumnIndex(0);
					ImGui::SetNextItemWidth(-FLT_MIN);
					if (ImGui::InputText("##rk", st.rules[i].permission_key, sizeof(st.rules[i].permission_key),
						is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
						st.dirty = true;
					}
					ImGui::TableSetColumnIndex(1);
					ImGui::SetNextItemWidth(-FLT_MIN);
					if (ImGui::InputText("##rp", st.rules[i].pattern, sizeof(st.rules[i].pattern),
						is_native ? ImGuiInputTextFlags_ReadOnly : ImGuiInputTextFlags_None)) {
						st.dirty = true;
					}
					ImGui::TableSetColumnIndex(2);
					const char* actions[] = { "allow", "deny", "ask" };
					ImGui::SetNextItemWidth(-FLT_MIN);
					if (is_native) {
						ImGui::TextColored(ImVec4(0.8f, 0.82f, 0.9f, 1.f), "%s", actions[std::clamp(st.rules[i].action, 0, 2)]);
					} else {
						if (ImGui::Combo("##ra", &st.rules[i].action, actions, IM_ARRAYSIZE(actions))) {
							st.dirty = true;
						}
					}
					ImGui::TableSetColumnIndex(3);
					if (!is_native) {
						if (ImGui::Button("X")) remove_idx = static_cast<int>(i);
					}
					ImGui::PopID();
				}
				if (remove_idx >= 0) {
					st.rules.erase(st.rules.begin() + remove_idx);
					st.dirty = true;
				}
				ImGui::EndTable();
			}
			if (!is_native) {
				ImGui::SetNextItemWidth(180.f);
				ImGui::InputTextWithHint("##new_rk", "permission key", st.new_rule.permission_key, sizeof(st.new_rule.permission_key));
				ImGui::SameLine();
				ImGui::SetNextItemWidth(220.f);
				ImGui::InputTextWithHint("##new_rp", "pattern (eg. **/*.cpp)", st.new_rule.pattern, sizeof(st.new_rule.pattern));
				ImGui::SameLine();
				const char* actions[] = { "allow", "deny", "ask" };
				ImGui::SetNextItemWidth(80.f);
				ImGui::Combo("##new_ra", &st.new_rule.action, actions, IM_ARRAYSIZE(actions));
				ImGui::SameLine();
				if (ImGui::Button("Add rule")) {
					if (std::strlen(st.new_rule.permission_key) > 0) {
						st.rules.push_back(st.new_rule);
						st.new_rule = detail::rule_buf_t{};
						st.dirty = true;
					}
				}
			}

			auto chip_strip = [&](const char* label, std::vector<std::string>& chips,
				detail::chip_input_t& input, const char* hint) {
				ImGui::Spacing();
				ImGui::TextDisabled("%s", label);
				int remove_idx = -1;
				for (size_t i = 0; i < chips.size(); ++i) {
					ImGui::PushID(static_cast<int>(i + 1000));
					ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(46, 56, 78, 220));
					ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(80, 36, 36, 230));
					ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(70, 32, 32, 235));
					std::string lbl = chips[i] + "  X";
					if (ImGui::Button(lbl.c_str())) {
						if (!is_native) remove_idx = static_cast<int>(i);
					}
					ImGui::PopStyleColor(3);
					ImGui::SameLine();
					ImGui::PopID();
				}
				if (remove_idx >= 0) {
					chips.erase(chips.begin() + remove_idx);
					st.dirty = true;
				}
				ImGui::NewLine();
				if (!is_native) {
					ImGui::SetNextItemWidth(220.f);
					ImGui::InputTextWithHint(("##chip_in_" + std::string(label)).c_str(), hint,
						input.buf, sizeof(input.buf));
					ImGui::SameLine();
					if (ImGui::Button(("Add##" + std::string(label)).c_str())) {
						if (std::strlen(input.buf) > 0) {
							chips.emplace_back(input.buf);
							input.buf[0] = '\0';
							st.dirty = true;
						}
					}
				}
			};

			chip_strip("Tools allowed", st.tools_allowed, st.new_allowed, "tool name");
			chip_strip("Tools denied", st.tools_denied, st.new_denied, "tool name");

			ImGui::PopStyleVar(2);

			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();

			float btn_h = 30.f;
			if (is_native) {
				ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(50, 56, 78, 230));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(70, 80, 110, 240));
				ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(48, 54, 76, 245));
				if (ImGui::Button("Duplicate as custom", ImVec2(180.f, btn_h))) {
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
				ImGui::PopStyleColor(3);
			} else {
				ImGui::PushStyleColor(ImGuiCol_Button,
					ImVec4(ar * 0.42f, ag * 0.42f, ab * 0.42f, 0.85f));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
					ImVec4(ar * 0.62f, ag * 0.62f, ab * 0.62f, 0.95f));
				ImGui::PushStyleColor(ImGuiCol_ButtonActive,
					ImVec4(ar * 0.52f, ag * 0.52f, ab * 0.52f, 1.f));
				if (ImGui::Button("Save", ImVec2(86.f, btn_h))) {
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
				ImGui::PopStyleColor(3);

				ImGui::SameLine(0.f, 8.f);
				ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(54, 60, 80, 220));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(74, 82, 110, 235));
				ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(48, 54, 76, 245));
				if (ImGui::Button("Reset", ImVec2(86.f, btn_h))) {
					detail::load_buffers_for_selected_locked();
					toast_notification::push("Reverted unsaved changes",
						toast_notification::toast_type_t::info, 2.5f);
				}
				ImGui::PopStyleColor(3);

				ImGui::SameLine(0.f, 8.f);
				ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(96, 36, 36, 220));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(132, 50, 50, 235));
				ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(86, 32, 32, 245));
				if (ImGui::Button("Delete", ImVec2(86.f, btn_h))) {
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
				ImGui::PopStyleColor(3);
			}

			ImGui::SameLine(0.f, 16.f);
			if (st.dirty) {
				ImGui::TextColored(ImVec4(1.f, 0.78f, 0.4f, 1.f), "Unsaved changes");
			} else {
				ImGui::TextColored(ImVec4(0.55f, 0.78f, 0.55f, 0.9f), "Up to date");
			}
		}

		ImGui::EndChild();

		ImGui::EndChild();
		ImGui::PopID();
	}

}
}
