#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "imgui/imgui.h"

#include "agent_registry.hpp"
#include "event_bus.hpp"
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
#include "../helpers/globals.h"

namespace aida {
namespace agent_picker {

	namespace detail {

		struct row_anim_t
		{
			aida::ui::transition_t entrance;
			aida::ui::hover_state_t hover;
		};

		struct picker_state_t
		{
			std::mutex                          mtx;
			std::atomic<bool>                   open{ false };
			std::atomic<bool>                   manager_request{ false };
			float                               anim = 0.f;
			float                               anim_velocity = 0.f;
			char                                search_buf[160] = {};
			int                                 selected_index = 0;
			aida::events::subscription_handle_t sub_changed;
			std::string                         pending_inject_prefix;
			std::atomic<bool>                   has_pending_inject{ false };
			std::atomic<bool>                   prev_was_at_only{ false };
			bool                                initialized = false;
			std::unordered_map<std::string, row_anim_t> row_anims;
			std::string                         last_filter_signature;
		};

		inline picker_state_t& state()
		{
			static picker_state_t s;
			return s;
		}

		inline std::string lower_copy(const std::string& s)
		{
			std::string out;
			out.reserve(s.size());
			for (char c : s) {
				if (c >= 'A' && c <= 'Z') out.push_back(static_cast<char>(c + ('a' - 'A')));
				else out.push_back(c);
			}
			return out;
		}

		inline bool agent_matches_filter(const aida::agent::agent_info_t& info, const std::string& filter_lower)
		{
			if (filter_lower.empty()) return true;
			std::string name_lower = lower_copy(info.name);
			if (name_lower.find(filter_lower) != std::string::npos) return true;
			std::string desc_lower = lower_copy(info.description);
			if (desc_lower.find(filter_lower) != std::string::npos) return true;
			return false;
		}

		inline std::vector<const aida::agent::agent_info_t*> filtered_primary_agents(const std::string& filter_lower)
		{
			auto primary = aida::agent::primary_agents();
			std::vector<const aida::agent::agent_info_t*> out;
			out.reserve(primary.size());
			for (const auto* p : primary) {
				if (p == nullptr) continue;
				if (p->hidden) continue;
				if (agent_matches_filter(*p, filter_lower)) out.push_back(p);
			}
			return out;
		}

	}

	inline void initialize()
	{
		auto& st = detail::state();
		std::lock_guard<std::mutex> lk(st.mtx);
		if (st.initialized) return;
		st.initialized = true;
		st.anim = 0.f;
		st.anim_velocity = 0.f;
		st.selected_index = 0;
		st.search_buf[0] = '\0';
		st.open.store(false);
		st.manager_request.store(false);
		st.has_pending_inject.store(false);

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
		st.open.store(false);
		st.manager_request.store(false);
		st.has_pending_inject.store(false);
		st.row_anims.clear();
		st.initialized = false;
	}

	inline void open()
	{
		auto& st = detail::state();
		std::lock_guard<std::mutex> lk(st.mtx);
		st.anim = 0.f;
		st.anim_velocity = 0.f;
		st.selected_index = 0;
		st.search_buf[0] = '\0';
		st.row_anims.clear();
		st.last_filter_signature.clear();
		st.open.store(true);
	}

	inline void close()
	{
		auto& st = detail::state();
		std::lock_guard<std::mutex> lk(st.mtx);
		st.open.store(false);
	}

	inline bool is_open()
	{
		return detail::state().open.load();
	}

	inline bool consume_manager_request()
	{
		auto& st = detail::state();
		bool expected = true;
		return st.manager_request.compare_exchange_strong(expected, false);
	}

	inline bool consume_inject_prefix(std::string& out_prefix)
	{
		auto& st = detail::state();
		bool expected = true;
		if (!st.has_pending_inject.compare_exchange_strong(expected, false))
			return false;
		std::lock_guard<std::mutex> lk(st.mtx);
		out_prefix = st.pending_inject_prefix;
		st.pending_inject_prefix.clear();
		return !out_prefix.empty();
	}

	inline void apply_pending_inject_to_buffer(char* buf, std::size_t buf_size)
	{
		if (buf == nullptr || buf_size == 0) return;
		std::string prefix;
		if (!consume_inject_prefix(prefix)) return;

		std::size_t cur_len = std::strlen(buf);
		bool starts_with_at_only = (cur_len == 1 && buf[0] == '@');
		if (starts_with_at_only) {
			std::size_t copy = std::min(prefix.size(), buf_size - 1);
			std::memcpy(buf, prefix.data(), copy);
			buf[copy] = '\0';
			return;
		}
		if (cur_len > 0 && buf[0] == '@' && (cur_len == 1 || buf[1] == ' ' || buf[1] == '\n')) {
			std::string remainder(buf + 1);
			std::string combined = prefix + remainder;
			std::size_t copy = std::min(combined.size(), buf_size - 1);
			std::memcpy(buf, combined.data(), copy);
			buf[copy] = '\0';
			return;
		}
		std::string combined = prefix + std::string(buf);
		std::size_t copy = std::min(combined.size(), buf_size - 1);
		std::memcpy(buf, combined.data(), copy);
		buf[copy] = '\0';
	}

	inline void notify_chat_buffer_changed(const char* buf)
	{
		if (buf == nullptr) return;
		auto& st = detail::state();
		bool now_at_only = (buf[0] == '@' && buf[1] == '\0');
		bool was = st.prev_was_at_only.exchange(now_at_only);
		if (now_at_only && !was) {
			if (!st.open.load()) open();
		}
	}

	inline void render_if_open()
	{
		auto& st = detail::state();
		const float dt = aida::ui::clock::dt();
		const float target = st.open.load() ? 1.f : 0.f;
		float anim_v = 0.f;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			st.anim = aida::motion::spring_step(st.anim, target, st.anim_velocity,
				aida::motion::spring::balanced, dt);
			if (st.anim < 0.f) st.anim = 0.f;
			if (st.anim > 1.f) st.anim = 1.f;
			if (target > 0.5f && st.anim > 0.985f) st.anim = 1.f;
			if (target < 0.5f && st.anim < 0.015f) st.anim = 0.f;
			anim_v = st.anim;
		}
		if (anim_v <= 0.001f && target <= 0.f) return;

		const auto& th = aida::ui::resolved();
		ImVec2 display = ImGui::GetIO().DisplaySize;

		const float pw = 480.f;
		const float ph = 460.f;
		const float ease = aida::motion::ease::out_back(anim_v);
		const float scale = 0.92f + 0.08f * ease;
		const float sw = pw * scale;
		const float sh = ph * scale;
		const float px = display.x * 0.5f - sw * 0.5f;
		const float py = display.y * 0.5f - sh * 0.5f - 18.f * (1.f - ease);
		const float alpha = anim_v;

		const float content_x_local = 16.f;
		const float content_y_local = 52.f;
		const float content_w = sw - 32.f;

		ImGui::SetNextWindowPos(ImVec2(px, py), ImGuiCond_Always);
		ImGui::SetNextWindowSize(ImVec2(sw, sh), ImGuiCond_Always);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(0, 0, 0, 0));

		bool win_open = true;
		ImGuiWindowFlags picker_flags =
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings;
	#ifdef IMGUI_HAS_DOCK
		picker_flags |= ImGuiWindowFlags_NoDocking;
	#endif
		if (ImGui::Begin("##aida_agent_picker", &win_open, picker_flags)) {

			ImDrawList* wdl = ImGui::GetWindowDrawList();
			ImDrawList* bgdl = ImGui::GetBackgroundDrawList();
			bgdl->AddRectFilled(ImVec2(0, 0), display,
				IM_COL32(0, 0, 0, static_cast<int>(160.f * anim_v)));

			ImVec2 panel_a(px, py);
			ImVec2 panel_b(px + sw, py + sh);

			aida::ui::blur::layer_request_t br;
			br.pos = panel_a;
			br.size = ImVec2(sw, sh);
			br.radius = 16.f;
			br.strength = 0.85f;
			br.alpha = alpha;
			aida::ui::blur::schedule(br);

			aida::ui::blur::render_drop_shadow(wdl, panel_a, panel_b, 16.f, 6, 0.45f * alpha,
				ImVec2(0.f, 12.f));
			aida::ui::blur::render_glass_fill(wdl, panel_a, panel_b, 16.f, alpha);
			aida::ui::blur::render_glass_border(wdl, panel_a, panel_b, 16.f, alpha, 1.f);

			float pulse_v = aida::ui::clock::pulse(0.55f, 0.4f, 1.f) * alpha;
			ImU32 grad_top = aida::ui::with_alpha(th.accent_grad_top, alpha * (0.85f + 0.15f * pulse_v));
			ImU32 grad_bot = aida::ui::with_alpha(th.accent_grad_bot, alpha * (0.85f + 0.15f * pulse_v));
			wdl->AddRectFilledMultiColor(
				ImVec2(panel_a.x + 1.f, panel_a.y + 1.f),
				ImVec2(panel_b.x - 1.f, panel_a.y + 4.f),
				grad_top, grad_top, grad_bot, grad_bot);

			ImFont* f_h2 = aida::ui::fonts::h2();
			ImFont* f_caption = aida::ui::fonts::caption();
			ImFont* f_body = aida::ui::fonts::body();
			const float fs = aida::ui::components::detail::ui_fs();
			const float caption_fs = fs * 0.85f;

			wdl->AddText(f_h2, 17.f, ImVec2(panel_a.x + 18.f, panel_a.y + 16.f),
				aida::ui::with_alpha(th.text_primary, alpha), "Switch agent");

			const char* hint = "Esc to cancel  |  Click to switch";
			const float hint_fs = fs * 0.92f;
			ImVec2 hts = f_caption->CalcTextSizeA(hint_fs, FLT_MAX, 0.f, hint);
			wdl->AddText(f_caption, hint_fs,
				ImVec2(panel_b.x - hts.x - 24.f, panel_a.y + 20.f),
				aida::ui::with_alpha(th.text_dim, alpha), hint);

			float content_x = panel_a.x + content_x_local;
			float content_y = panel_a.y + content_y_local;

			ImGui::SetCursorScreenPos(ImVec2(content_x, content_y));
			char search_local[160];
			std::memcpy(search_local, st.search_buf, sizeof(search_local));
			if (st.open.load() && ImGui::IsWindowAppearing())
				ImGui::SetKeyboardFocusHere();
			if (aida::ui::input_text("##aida_agent_picker_search",
					search_local, sizeof(search_local),
					"Search agents...", false, ImVec2(content_w, 34.f))) {
				std::lock_guard<std::mutex> lk(st.mtx);
				std::memcpy(st.search_buf, search_local, sizeof(st.search_buf));
			}

			float list_y = content_y + 44.f;
			float list_h = sh - (52.f + 44.f + 48.f);

			ImGui::SetCursorScreenPos(ImVec2(content_x, list_y));
			ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
			ImGui::BeginChild("##aida_agent_picker_list", ImVec2(content_w, list_h), false,
				ImGuiWindowFlags_NoBackground);

			std::string filter_lower;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				filter_lower = detail::lower_copy(std::string(st.search_buf));
			}
			auto items = detail::filtered_primary_agents(filter_lower);

			std::string current_active = aida::agent::active_agent_name();

			std::string sig;
			sig.reserve(items.size() * 16 + filter_lower.size());
			sig.append(filter_lower);
			sig.push_back('|');
			for (const auto* p : items) sig.append(p->name).push_back(';');

			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (sig != st.last_filter_signature) {
					st.last_filter_signature = sig;
					for (size_t i = 0; i < items.size(); ++i) {
						auto& ra = st.row_anims[items[i]->name];
						ra.entrance.start(0.42f, aida::motion::ease::out_quint,
							0.030f * static_cast<float>(i));
					}
				}
			}

			ImDrawList* dl = ImGui::GetWindowDrawList();
			for (size_t i = 0; i < items.size(); ++i) {
				const auto* info = items[i];
				if (info == nullptr) continue;

				detail::row_anim_t* ra_ptr = nullptr;
				{
					std::lock_guard<std::mutex> lk(st.mtx);
					ra_ptr = &st.row_anims[info->name];
					ra_ptr->entrance.tick(dt);
				}

				const float entrance_p = ra_ptr->entrance.eased();
				const float entrance_y = (1.f - entrance_p) * 14.f;
				const float entrance_alpha = entrance_p;

				ImVec2 row_pos = ImGui::GetCursorScreenPos();
				row_pos.y += entrance_y;

				const float name_fs = fs * 1.10f;
				const float desc_fs = fs * 0.94f;
				const float avatar_radius = 18.f;
				const float text_x_rel = 14.f + avatar_radius * 2.f + 14.f;
				const float row_pad_r = 14.f;
				const float name_top = 9.f;
				const float name_h = name_fs;
				const float gap_name_desc = 6.f;
				const float desc_top = name_top + name_h + gap_name_desc;

				float wrap_w = content_w - text_x_rel - row_pad_r;
				if (wrap_w < 40.f) wrap_w = 40.f;

				std::string desc = info->description;
				ImVec2 desc_sz = aida::ui::fonts::caption()->CalcTextSizeA(desc_fs, FLT_MAX, wrap_w, desc.c_str());
				const float desc_block_h = desc_sz.y;
				const float row_inner_h = desc_top + desc_block_h + 10.f;
				const float row_h = (std::max)(60.f, row_inner_h);

				ImGui::PushID(static_cast<int>(i));
				ImGui::SetCursorScreenPos(ImVec2(row_pos.x, row_pos.y));
				ImGui::InvisibleButton("##agent_row", ImVec2(content_w, row_h - 6.f));
				bool hov = ImGui::IsItemHovered();
				bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);

				const float hov_v = ra_ptr->hover.tick(hov, dt, aida::motion::spring::playful);
				const float lift = hov_v * 2.f;
				ImVec2 row_a(row_pos.x, row_pos.y - lift);
				ImVec2 row_b(row_pos.x + content_w, row_pos.y + row_h - 8.f - lift);

				const bool is_active = (info->name == current_active);
				const float row_alpha = alpha * entrance_alpha;

				if (hov_v > 0.02f) {
					ImU32 sh_col = IM_COL32(0, 0, 0, static_cast<int>(70.f * row_alpha * hov_v));
					for (int s = 0; s < 4; ++s) {
						float spread = (float)(s + 1) * 1.4f * hov_v;
						dl->AddRectFilled(
							ImVec2(row_a.x - spread, row_a.y - spread + 4.f),
							ImVec2(row_b.x + spread, row_b.y + spread + 4.f),
							IM_COL32(0, 0, 0, static_cast<int>((static_cast<float>(4 - s) / 4.f) * 28.f * row_alpha * hov_v)),
							10.f + spread);
					}
					(void)sh_col;
				}

				ImU32 row_bg = aida::ui::mix(
					aida::ui::with_alpha(th.panel_header, row_alpha * 0.5f),
					aida::ui::with_alpha(th.hover_wash, row_alpha),
					hov_v);
				if (is_active) {
					row_bg = aida::ui::mix(row_bg,
						aida::ui::with_alpha(th.selection, row_alpha * 0.85f), 0.55f);
				}
				dl->AddRectFilled(row_a, row_b, row_bg, 10.f);

				if (is_active) {
					float ring_pulse = aida::ui::clock::pulse(0.8f, 0.5f, 1.f);
					ImU32 ring_col = aida::ui::with_alpha(th.accent_glow, row_alpha * ring_pulse);
					dl->AddRect(
						ImVec2(row_a.x - 1.f, row_a.y - 1.f),
						ImVec2(row_b.x + 1.f, row_b.y + 1.f),
						ring_col, 11.f, 0, 2.5f);
					dl->AddRect(row_a, row_b,
						aida::ui::with_alpha(th.accent_u32, row_alpha), 10.f, 0, 1.5f);
				} else {
					dl->AddRect(row_a, row_b,
						aida::ui::with_alpha(th.border_subtle, row_alpha * (0.6f + 0.4f * hov_v)),
						10.f, 0, 1.f);
				}

				const ImVec2 avatar_center(row_a.x + 14.f + avatar_radius, (row_a.y + row_b.y) * 0.5f);
				aida::ui::avatar::render(dl, avatar_center, avatar_radius,
					info->name, aida::ui::avatar::kind_t::gradient,
					true, row_alpha, aida::ui::fonts::body_strong());

				const float text_x = row_a.x + text_x_rel;
				dl->AddText(aida::ui::fonts::body_strong(), name_fs,
					ImVec2(text_x, row_a.y + name_top),
					aida::ui::with_alpha(th.text_primary, row_alpha),
					info->name.c_str());

				if (info->native) {
					ImFont* nf = aida::ui::fonts::body_strong();
					ImVec2 ns = nf->CalcTextSizeA(name_fs, FLT_MAX, 0.f, info->name.c_str());
					const char* badge_txt = "native";
					ImFont* bf = aida::ui::fonts::caption();
					const float badge_fs = fs * 0.78f;
					ImVec2 bts = bf->CalcTextSizeA(badge_fs, FLT_MAX, 0.f, badge_txt);
					const float pill_pad_x = 6.f;
					const float pill_h = badge_fs + 4.f;
					const float pill_w = bts.x + pill_pad_x * 2.f;
					float pill_x = text_x + ns.x + 8.f;
					const float pill_y = row_a.y + name_top + (name_h - pill_h) * 0.5f;
					if (pill_x + pill_w > row_b.x - 8.f) pill_x = row_b.x - 8.f - pill_w;
					ImVec2 pa(pill_x, pill_y);
					ImVec2 pb(pill_x + pill_w, pill_y + pill_h);
					ImU32 pill_top = aida::ui::with_alpha(th.info, row_alpha * 0.95f);
					ImU32 pill_bot = aida::ui::with_alpha(th.info, row_alpha * 0.70f);
					dl->AddRectFilled(pa, pb, aida::ui::mix(pill_top, pill_bot, 0.5f), pill_h * 0.5f);
					dl->AddText(bf, badge_fs,
						ImVec2(pa.x + pill_pad_x, pa.y + (pill_h - badge_fs) * 0.5f),
						aida::ui::with_alpha(IM_COL32(255, 255, 255, 240), row_alpha), badge_txt);
				}

				dl->AddText(aida::ui::fonts::caption(), desc_fs,
					ImVec2(text_x, row_a.y + desc_top),
					aida::ui::with_alpha(th.text_secondary, row_alpha * 0.95f),
					desc.c_str(), nullptr, wrap_w);

				if (clicked) {
					if (aida::agent::set_active_agent(info->name)) {
						aida::events::publish(aida::events::event_agent_changed,
							aida::events::agent_changed_t{ std::string{}, current_active, info->name });
						{
							std::lock_guard<std::mutex> lk(st.mtx);
							st.pending_inject_prefix = "@" + info->name + " ";
							st.has_pending_inject.store(true);
						}
						toast_notification::push("Agent: " + info->name,
							toast_notification::toast_type_t::info, 2.5f);
						close();
					}
				}

				ImGui::PopID();
				ImGui::SetCursorScreenPos(ImVec2(row_pos.x, row_pos.y - entrance_y + row_h - 2.f));
			}

			if (items.empty()) {
				ImVec2 region_pos = ImGui::GetCursorScreenPos();
				ImVec2 region_size(content_w, list_h - 40.f);
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::dots;
				cfg.title = "No matching agents";
				cfg.body = "Refine your search or open the agent manager to add a custom agent.";
				cfg.max_width = content_w * 0.9f;
				aida::ui::empty_state::render(region_pos, region_size, cfg);
			}

			ImGui::EndChild();
			ImGui::PopStyleColor();

			float footer_y = panel_b.y - 44.f;
			ImGui::SetCursorScreenPos(ImVec2(content_x, footer_y));
			if (aida::ui::button("Manage agents...",
					aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm,
					ImVec2(170.f, 30.f))) {
				st.manager_request.store(true);
				close();
			}

			std::string active_name = aida::agent::active_agent_name();
			std::string footer_active = "Active: " + (active_name.empty() ? std::string("none") : active_name);
			ImVec2 ats = aida::ui::fonts::caption()->CalcTextSizeA(caption_fs, FLT_MAX, 0.f, footer_active.c_str());
			wdl->AddText(aida::ui::fonts::caption(), caption_fs,
				ImVec2(panel_b.x - ats.x - 20.f, footer_y + 8.f),
				aida::ui::with_alpha(th.text_secondary, alpha),
				footer_active.c_str());
			(void)f_body;
		}
		ImGui::End();
		ImGui::PopStyleColor();
		ImGui::PopStyleVar(2);

		if (st.open.load()) {
			if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
				close();
		}
	}

}
}
