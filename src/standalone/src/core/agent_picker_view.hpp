#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "imgui/imgui.h"

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

namespace aida {
namespace agent_picker {

	namespace detail {

		struct picker_state_t
		{
			std::mutex                          mtx;
			std::atomic<bool>                   open{ false };
			std::atomic<bool>                   manager_request{ false };
			float                               anim = 0.f;
			char                                search_buf[160] = {};
			int                                 selected_index = 0;
			aida::events::subscription_handle_t sub_changed;
			std::string                         pending_inject_prefix;
			std::atomic<bool>                   has_pending_inject{ false };
			bool                                initialized = false;
		};

		inline picker_state_t& state()
		{
			static picker_state_t s;
			return s;
		}

		inline ImU32 hash_color_for(const std::string& text)
		{
			uint32_t h = 2166136261u;
			for (char c : text) {
				h ^= static_cast<uint8_t>(c);
				h *= 16777619u;
			}
			float hue = static_cast<float>(h % 360u) / 360.f;
			float r = 0.f, g = 0.f, b = 0.f;
			float sat = 0.55f;
			float val = 0.85f;
			float k_r = std::fmod(5.f + hue * 6.f, 6.f);
			float k_g = std::fmod(3.f + hue * 6.f, 6.f);
			float k_b = std::fmod(1.f + hue * 6.f, 6.f);
			r = val - val * sat * std::max(0.f, std::min(std::min(k_r, 4.f - k_r), 1.f));
			g = val - val * sat * std::max(0.f, std::min(std::min(k_g, 4.f - k_g), 1.f));
			b = val - val * sat * std::max(0.f, std::min(std::min(k_b, 4.f - k_b), 1.f));
			return IM_COL32(static_cast<int>(r * 255.f), static_cast<int>(g * 255.f), static_cast<int>(b * 255.f), 235);
		}

		inline ImU32 parse_hex_color(const std::string& hex, ImU32 fallback)
		{
			if (hex.size() < 7 || hex[0] != '#') return fallback;
			auto from_hex = [](char c) -> int {
				if (c >= '0' && c <= '9') return c - '0';
				if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
				if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
				return -1;
			};
			int r1 = from_hex(hex[1]);
			int r2 = from_hex(hex[2]);
			int g1 = from_hex(hex[3]);
			int g2 = from_hex(hex[4]);
			int b1 = from_hex(hex[5]);
			int b2 = from_hex(hex[6]);
			if (r1 < 0 || r2 < 0 || g1 < 0 || g2 < 0 || b1 < 0 || b2 < 0) return fallback;
			int r = r1 * 16 + r2;
			int g = g1 * 16 + g2;
			int b = b1 * 16 + b2;
			return IM_COL32(r, g, b, 235);
		}

		inline ImU32 color_for_agent(const aida::agent::agent_info_t& info)
		{
			if (!info.color.empty())
				return parse_hex_color(info.color, hash_color_for(info.name));
			return hash_color_for(info.name);
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

		inline void render_agent_avatar(ImDrawList* dl, float cx, float cy, float radius, ImU32 color, char glyph)
		{
			ImU32 ring = (color & 0x00FFFFFFu) | (static_cast<ImU32>(255) << 24);
			int rr = (color >> 0) & 0xFF;
			int gg = (color >> 8) & 0xFF;
			int bb = (color >> 16) & 0xFF;
			ImU32 ring_dark = IM_COL32(static_cast<int>(rr * 0.55f), static_cast<int>(gg * 0.55f), static_cast<int>(bb * 0.55f), 230);
			dl->AddCircleFilled(ImVec2(cx, cy), radius, color, 28);
			dl->AddCircle(ImVec2(cx, cy), radius, ring_dark, 28, 1.4f);
			char buf[2] = { glyph, 0 };
			ImVec2 ts = ImGui::CalcTextSize(buf);
			float lum = 0.299f * (rr / 255.f) + 0.587f * (gg / 255.f) + 0.114f * (bb / 255.f);
			ImU32 text_col = lum < 0.5f ? IM_COL32(245, 245, 250, 255) : IM_COL32(20, 20, 28, 255);
			dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f), text_col, buf);
		}

	}

	inline void initialize()
	{
		auto& st = detail::state();
		std::lock_guard<std::mutex> lk(st.mtx);
		if (st.initialized) return;
		st.initialized = true;
		st.anim = 0.f;
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
		st.initialized = false;
	}

	inline void open()
	{
		auto& st = detail::state();
		std::lock_guard<std::mutex> lk(st.mtx);
		st.anim = 0.f;
		st.selected_index = 0;
		st.search_buf[0] = '\0';
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
		if (buf[0] == '@' && buf[1] == '\0') {
			if (!is_open()) open();
		}
	}

	inline void render_if_open()
	{
		auto& st = detail::state();
		if (!st.open.load()) {
			std::lock_guard<std::mutex> lk(st.mtx);
			if (st.anim > 0.f)
				st.anim = std::max(0.f, st.anim - ImGui::GetIO().DeltaTime * 6.f);
			else
				return;
		}

		float dt = ImGui::GetIO().DeltaTime;
		ImDrawList* fdl = ImGui::GetForegroundDrawList();

		float target = st.open.load() ? 1.f : 0.f;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			st.anim += (target - st.anim) * std::min(10.f * dt, 1.f);
			if (target > 0.5f && st.anim > 0.985f) st.anim = 1.f;
			if (target < 0.5f && st.anim < 0.015f) st.anim = 0.f;
		}

		float anim_v = 0.f;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			anim_v = st.anim;
		}

		ImVec2 display = ImGui::GetIO().DisplaySize;
		fdl->AddRectFilled(ImVec2(0, 0), display, IM_COL32(0, 0, 0, static_cast<int>(150 * anim_v)));

		const float pw = 480.f;
		const float ph = 420.f;
		float scale = 0.94f + 0.06f * anim_v;
		float sw = pw * scale;
		float sh = ph * scale;
		float px = display.x * 0.5f - sw * 0.5f;
		float py = display.y * 0.5f - sh * 0.5f - 16.f * (1.f - anim_v);
		float alpha = anim_v;

		for (int s = 0; s < 4; ++s) {
			float off = 4.f + s * 3.f;
			fdl->AddRectFilled(
				ImVec2(px + off, py + off),
				ImVec2(px + sw + off, py + sh + off),
				IM_COL32(0, 0, 0, static_cast<int>(28 * alpha * (4 - s) / 4.f)), 12.f);
		}

		float ax = globals::ui::accent.x;
		float ay = globals::ui::accent.y;
		float az = globals::ui::accent.z;

		fdl->AddRectFilled(ImVec2(px, py), ImVec2(px + sw, py + sh),
			IM_COL32(28, 28, 38, static_cast<int>(245 * alpha)), 12.f);
		fdl->AddRect(ImVec2(px, py), ImVec2(px + sw, py + sh),
			IM_COL32(80, 80, 120, static_cast<int>(60 * alpha)), 12.f);
		fdl->AddRectFilled(ImVec2(px + 1.f, py + 1.f), ImVec2(px + sw - 1.f, py + 3.f),
			IM_COL32(static_cast<int>(ax * 255), static_cast<int>(ay * 255), static_cast<int>(az * 255),
				static_cast<int>(180 * alpha)), 2.f);

		std::string title = "Switch agent";
		ImVec2 tts = ImGui::CalcTextSize(title.c_str());
		fdl->AddText(ImVec2(px + 18.f, py + 14.f),
			IM_COL32(232, 232, 245, static_cast<int>(245 * alpha)), title.c_str());

		std::string hint = "Esc to cancel  -  Click to switch";
		ImVec2 hts = ImGui::CalcTextSize(hint.c_str());
		fdl->AddText(ImVec2(px + sw - hts.x - 18.f, py + 18.f),
			IM_COL32(150, 152, 168, static_cast<int>(180 * alpha)), hint.c_str());

		float content_x = px + 14.f;
		float content_y = py + 44.f;
		float content_w = sw - 28.f;

		ImGui::SetNextWindowPos(ImVec2(px, py), ImGuiCond_Always);
		ImGui::SetNextWindowSize(ImVec2(sw, sh), ImGuiCond_Always);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(0, 0, 0, 0));
		bool win_open = true;
		if (ImGui::Begin("##aida_agent_picker", &win_open,
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBringToFrontOnFocus)) {

			ImGui::SetCursorScreenPos(ImVec2(content_x, content_y));
			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 6.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(20, 22, 30, static_cast<int>(220 * alpha)));
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(228, 230, 248, static_cast<int>(250 * alpha)));

			ImGui::SetNextItemWidth(content_w);
			if (st.open.load() && ImGui::IsWindowAppearing())
				ImGui::SetKeyboardFocusHere();
			ImGui::InputTextWithHint("##aida_agent_picker_search", "Search agents...",
				st.search_buf, sizeof(st.search_buf));

			ImGui::PopStyleColor(2);
			ImGui::PopStyleVar(2);

			float list_y = content_y + 36.f;
			float list_h = sh - (44.f + 36.f + 44.f);

			ImGui::SetCursorScreenPos(ImVec2(content_x, list_y));
			ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
			ImGui::BeginChild("##aida_agent_picker_list", ImVec2(content_w, list_h), false,
				ImGuiWindowFlags_NoBackground);

			std::string filter_lower = detail::lower_copy(std::string(st.search_buf));
			auto items = detail::filtered_primary_agents(filter_lower);

			std::string current_active = aida::agent::active_agent_name();

			ImDrawList* dl = ImGui::GetWindowDrawList();
			for (size_t i = 0; i < items.size(); ++i) {
				const auto* info = items[i];
				if (info == nullptr) continue;

				ImVec2 row_pos = ImGui::GetCursorScreenPos();
				const float row_h = 56.f;

				ImGui::PushID(static_cast<int>(i));
				ImGui::InvisibleButton("##agent_row", ImVec2(content_w, row_h));
				bool hov = ImGui::IsItemHovered();
				bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGui::PopID();

				ImU32 row_bg = hov
					? IM_COL32(60, 64, 92, static_cast<int>(180 * alpha))
					: IM_COL32(255, 255, 255, static_cast<int>(8 * alpha));
				dl->AddRectFilled(row_pos, ImVec2(row_pos.x + content_w, row_pos.y + row_h - 4.f),
					row_bg, 8.f);

				bool is_active = (info->name == current_active);
				if (is_active) {
					dl->AddRect(row_pos, ImVec2(row_pos.x + content_w, row_pos.y + row_h - 4.f),
						IM_COL32(static_cast<int>(ax * 255 * 0.9f),
							static_cast<int>(ay * 255 * 0.9f),
							static_cast<int>(az * 255 * 0.9f),
							static_cast<int>(180 * alpha)), 8.f, 0, 1.5f);
				}

				ImU32 col = detail::color_for_agent(*info);
				char glyph = info->name.empty() ? '?' : static_cast<char>(std::toupper(static_cast<unsigned char>(info->name[0])));
				detail::render_agent_avatar(dl,
					row_pos.x + 16.f + 16.f, row_pos.y + (row_h - 4.f) * 0.5f,
					16.f, col, glyph);

				float text_x = row_pos.x + 16.f + 32.f + 12.f;
				dl->AddText(ImVec2(text_x, row_pos.y + 8.f),
					IM_COL32(232, 232, 245, static_cast<int>(245 * alpha)), info->name.c_str());

				if (info->native) {
					ImVec2 ns = ImGui::CalcTextSize(info->name.c_str());
					float bx = text_x + ns.x + 8.f;
					float by = row_pos.y + 9.f;
					ui_anim::render_badge(dl, "native", bx, by,
						IM_COL32(40, 56, 80, static_cast<int>(220 * alpha)),
						IM_COL32(170, 200, 235, static_cast<int>(230 * alpha)));
				}

				std::string desc = info->description;
				if (desc.size() > 96) {
					desc.resize(93);
					desc.append("...");
				}
				dl->AddText(ImVec2(text_x, row_pos.y + 26.f),
					IM_COL32(168, 170, 188, static_cast<int>(210 * alpha)),
					desc.c_str());

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

				ImGui::Dummy(ImVec2(content_w, 4.f));
			}

			if (items.empty()) {
				ImGui::Dummy(ImVec2(content_w, 32.f));
				ImVec2 cp = ImGui::GetCursorScreenPos();
				dl->AddText(ImVec2(cp.x + 12.f, cp.y),
					IM_COL32(150, 152, 168, static_cast<int>(220 * alpha)),
					"No matching agents.");
			}

			ImGui::EndChild();
			ImGui::PopStyleColor();

			float footer_y = py + sh - 38.f;
			ImGui::SetCursorScreenPos(ImVec2(content_x, footer_y));
			ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(50, 56, 78, static_cast<int>(220 * alpha)));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(70, 80, 110, static_cast<int>(235 * alpha)));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(48, 54, 76, static_cast<int>(240 * alpha)));
			if (ImGui::Button("Manage agents...", ImVec2(170.f, 28.f))) {
				st.manager_request.store(true);
				close();
			}
			ImGui::PopStyleColor(3);

			ImGui::SameLine(0.f, 8.f);
			std::string active_name = aida::agent::active_agent_name();
			std::string footer_active = "Active: " + (active_name.empty() ? std::string("none") : active_name);
			ImVec2 ats = ImGui::CalcTextSize(footer_active.c_str());
			ImGui::SetCursorScreenPos(ImVec2(content_x + content_w - ats.x - 6.f, footer_y + 6.f));
			ImGui::TextColored(ImVec4(0.66f, 0.67f, 0.78f, alpha), "%s", footer_active.c_str());
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
