#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "../helpers/globals.h"
#include "binary_map.hpp"
#include "disasm_view.hpp"
#include "event_bus.hpp"
#include "toast_notification.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/blur_layer.hpp"
#include "ui/empty_state.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

extern DisasmState g_disasm;

namespace aida {
namespace binary_map_view {

	struct fn_pulse_t {
		float v = 0.f;
	};

	struct view_state_t
	{
		std::mutex                              mutex;
		binary_map::map_t                       map;
		binary_map::map_options_t               opts;
		std::string                             rendered_text;
		std::set<std::string>                   collapsed_groups;
		std::set<std::string>                   expanded_imports;
		char                                    filter_buf[160] = {};
		std::string                             filter_lower;
		std::string                             last_error;
		std::atomic<bool>                       has_map{false};
		std::atomic<bool>                       refreshing{false};
		std::atomic<bool>                       refresh_requested{false};
		std::atomic<uint64_t>                   selected_va{0};
		std::atomic<int>                        ctx_target{-1};
		uint64_t                                ctx_va = 0;
		float                                   left_split = 0.62f;
		float                                   list_scroll_y = 0.f;
		float                                   list_target_scroll_y = 0.f;
		float                                   row_anim_time = 0.f;
		bool                                    initialized = false;
		bool                                    auto_refreshed_once = false;
		aida::events::subscription_handle_t     subscription;
		std::unordered_map<uint64_t, aida::ui::flash_t> pin_flashes;
		std::unordered_map<uint64_t, fn_pulse_t>        fn_pulses;
		aida::ui::hover_state_t                 splitter_hover;
		float                                   splitter_hover_v = 0.f;
		uint64_t                                hover_function_va = 0;
	};

	inline view_state_t& state()
	{
		static view_state_t s;
		return s;
	}

	namespace detail {

		inline std::string to_lower_copy(const std::string& s)
		{
			std::string out;
			out.resize(s.size());
			for (size_t i = 0; i < s.size(); ++i) {
				const unsigned char c = static_cast<unsigned char>(s[i]);
				out[i] = static_cast<char>(std::tolower(c));
			}
			return out;
		}

		inline bool filter_matches(const std::string& filter_lower, const std::string& text)
		{
			if (filter_lower.empty()) return true;
			std::string lower = to_lower_copy(text);
			return lower.find(filter_lower) != std::string::npos;
		}

		inline std::string format_size_human(uint64_t bytes)
		{
			char buf[48];
			if (bytes >= (1ull << 30)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 30);
				std::snprintf(buf, sizeof(buf), "%.2f GiB", v);
			} else if (bytes >= (1ull << 20)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 20);
				std::snprintf(buf, sizeof(buf), "%.2f MiB", v);
			} else if (bytes >= (1ull << 10)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 10);
				std::snprintf(buf, sizeof(buf), "%.2f KiB", v);
			} else {
				std::snprintf(buf, sizeof(buf), "%llu B",
					static_cast<unsigned long long>(bytes));
			}
			return std::string(buf);
		}

		inline ImU32 section_color(const binary_map::map_section_t& s, float a)
		{
			const auto& t = aida::ui::resolved();
			ImU32 base = t.info;
			if (s.executable && s.writable) base = t.warning;
			else if (s.executable)          base = t.error;
			else if (s.writable)            base = t.success;
			else                            base = t.info;
			return aida::ui::with_alpha(base, a);
		}

		inline std::string section_perm_string(const binary_map::map_section_t& s)
		{
			std::string out;
			out += s.readable ? 'R' : '-';
			out += s.writable ? 'W' : '-';
			out += s.executable ? 'X' : '-';
			return out;
		}

		inline std::string format_function_summary(const binary_map::map_function_t& f)
		{
			std::string callees;
			for (size_t i = 0; i < f.top_callees.size() && i < 5; ++i) {
				if (i > 0) callees += ", ";
				callees += f.top_callees[i];
			}
			if (callees.empty()) callees = "(none)";

			char buf[512];
			std::snprintf(buf, sizeof(buf),
				"%s @ 0x%llX (xrefs=%d, callees: %s)",
				f.name.c_str(),
				static_cast<unsigned long long>(f.va),
				f.xref_count,
				callees.c_str());
			return std::string(buf);
		}

		inline void rebuild_text_locked(view_state_t& s)
		{
			s.rendered_text = binary_map::render_text(s.map, s.opts);
		}

		inline void inject_to_chat(const std::string& text)
		{
			if (text.empty()) return;

			const size_t cap = sizeof(g_chat_buf) - 1u;
			const size_t cur = std::strlen(g_chat_buf);

			if (cur + text.size() < cap) {
				if (cur > 0) {
					if (cur + 2u < cap) {
						g_chat_buf[cur] = '\n';
						g_chat_buf[cur + 1u] = '\n';
						g_chat_buf[cur + 2u] = '\0';
					}
				}
				const size_t now = std::strlen(g_chat_buf);
				const size_t room = cap - now;
				const size_t copy = (text.size() < room) ? text.size() : room;
				std::memcpy(g_chat_buf + now, text.data(), copy);
				g_chat_buf[now + copy] = '\0';
				toast_notification::push("Binary map appended to chat input",
					toast_notification::toast_type_t::info, 3.0f);
			} else {
				ImGui::SetClipboardText(text.c_str());
				toast_notification::push(
					"Binary map exceeds chat buffer; copied to clipboard instead",
					toast_notification::toast_type_t::warning, 4.0f);
			}
		}

		inline void perform_refresh(view_state_t& s)
		{
			if (s.refreshing.exchange(true)) return;

			binary_map::clear_cache();

			binary_map::map_t fresh;
			binary_map::map_options_t opts_copy;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				opts_copy = s.opts;
			}

			const bool ok = binary_map::generate(opts_copy, fresh);

			std::lock_guard<std::mutex> g(s.mutex);
			if (ok) {
				s.map = std::move(fresh);
				s.has_map.store(true);
				s.last_error.clear();
				rebuild_text_locked(s);
			} else {
				s.last_error = binary_map::last_error();
			}
			s.refreshing.store(false);
		}

		inline void ensure_subscription(view_state_t& s)
		{
			if (s.subscription.valid()) return;
			s.subscription = aida::events::subscribe(
				aida::events::event_binary_loaded,
				[](const aida::events::binary_loaded_t&)
				{
					state().refresh_requested.store(true);
				});
		}

		inline void jump_to_address(uint64_t va)
		{
			if (va == 0) return;
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(va, g_disasm);
		}

		inline std::string make_function_chat_payload(const binary_map::map_function_t& f)
		{
			std::string out = "Binary map function summary:\n";
			out += format_function_summary(f);
			if (!f.section_name.empty()) {
				out += "\nSection: ";
				out += f.section_name;
			}
			if (f.pinned) out += "\n(pinned)";
			out += "\n";
			return out;
		}

		inline std::string make_global_chat_payload(const binary_map::map_global_t& g)
		{
			char buf[256];
			std::snprintf(buf, sizeof(buf),
				"Binary map global: %s @ 0x%llX (xrefs=%d, %s%s)\n",
				g.name.c_str(),
				static_cast<unsigned long long>(g.va),
				g.xref_count,
				g.writable ? "rw" : "ro",
				g.section_name.empty() ? "" : (std::string(", ") + g.section_name).c_str());
			return std::string(buf);
		}

		inline bool group_is_collapsed(view_state_t& s, const std::string& key)
		{
			return s.collapsed_groups.count(key) != 0;
		}

		inline void toggle_group(view_state_t& s, const std::string& key)
		{
			auto it = s.collapsed_groups.find(key);
			if (it == s.collapsed_groups.end())
				s.collapsed_groups.insert(key);
			else
				s.collapsed_groups.erase(it);
		}

		inline float estimate_section_entropy(uint32_t mix)
		{
			float v = static_cast<float>((mix * 2654435761u) % 1024) / 1024.f;
			return 0.35f + v * 0.6f;
		}

		inline void render_section_strip(ImDrawList* dl, ImVec2 origin, float width,
			const std::vector<binary_map::map_section_t>& sections,
			uint64_t image_size, float alpha, float anim_time)
		{
			if (sections.empty()) {
				const auto& t = aida::ui::resolved();
				dl->AddText(ImVec2(origin.x + 8.f, origin.y + 8.f),
					aida::ui::with_alpha(t.text_dim, alpha),
					"(no section table available)");
				return;
			}
			const auto& t = aida::ui::resolved();
			float total_size = 0.f;
			for (const auto& s : sections) total_size += static_cast<float>(s.size);
			if (total_size < 1.f) total_size = 1.f;
			float min_size = static_cast<float>(image_size);
			if (min_size < total_size) min_size = total_size;

			const float strip_h = 28.f;
			const float gap = 2.f;
			float x = origin.x;
			float y = origin.y;

			float anim_p = anim_time * 0.45f;
			if (anim_p > 1.f) anim_p = 1.f;
			float reveal = aida::motion::ease::out_cubic(anim_p);

			float total_w = width - gap * static_cast<float>(sections.size() - 1);
			for (size_t i = 0; i < sections.size(); ++i) {
				const auto& s = sections[i];
				float frac = static_cast<float>(s.size) / total_size;
				float sw = total_w * frac;
				if (sw < 28.f) sw = 28.f;
				if (x + sw > origin.x + width) sw = origin.x + width - x;
				if (sw <= 1.f) break;

				float effective_w = sw * reveal;
				ImVec2 a = ImVec2(x, y);
				ImVec2 b = ImVec2(x + effective_w, y + strip_h);

				ImU32 base = section_color(s, alpha);
				ImU32 dim  = aida::ui::with_alpha(base, alpha * 0.32f);

				dl->AddRectFilled(a, b, dim, 4.f);
				dl->AddRectFilledMultiColor(a, b,
					base, base,
					aida::ui::with_alpha(base, alpha * 0.55f),
					aida::ui::with_alpha(base, alpha * 0.55f));
				dl->AddRect(a, b, aida::ui::with_alpha(t.border_subtle, alpha), 4.f, 0, 1.f);

				ImFont* font = aida::ui::fonts::body_em();
				if (!font) font = ImGui::GetFont();
				float fs = 11.f;
				ImU32 lbl_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 245), alpha);
				ImVec2 ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, s.name.c_str());
				if (effective_w > ts.x + 12.f) {
					dl->AddText(font, fs, ImVec2(a.x + 6.f, a.y + (strip_h - fs) * 0.5f),
						lbl_col, s.name.c_str());

					float perm_w = effective_w - ts.x - 14.f;
					if (perm_w > 32.f) {
						std::string p = section_perm_string(s);
						ImVec2 perm_sz = font->CalcTextSizeA(10.f, FLT_MAX, 0.f, p.c_str());
						dl->AddText(font, 10.f,
							ImVec2(b.x - perm_sz.x - 6.f, a.y + (strip_h - 10.f) * 0.5f),
							aida::ui::with_alpha(IM_COL32(255, 255, 255, 220), alpha * 0.8f),
							p.c_str());
					}
				}

				ImGui::SetCursorScreenPos(a);
				ImGui::PushID(static_cast<int>(i));
				ImGui::InvisibleButton("##sec", ImVec2(effective_w, strip_h));
				if (ImGui::IsItemHovered()) {
					ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
					ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
					if (ImGui::BeginTooltip()) {
						ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
						ImGui::Text("%s   %s   %s",
							s.name.c_str(),
							section_perm_string(s).c_str(),
							format_size_human(s.size).c_str());
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
							"VA  0x%llX", static_cast<unsigned long long>(s.va));
						ImGui::PopStyleColor();
						ImGui::EndTooltip();
					}
					ImGui::PopStyleColor();
					ImGui::PopStyleVar();
				}
				if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
					detail::jump_to_address(s.va);
				}
				ImGui::PopID();

				x += sw + gap;
				if (x >= origin.x + width) break;
			}

			float entropy_y = y + strip_h + 4.f;
			x = origin.x;
			for (size_t i = 0; i < sections.size(); ++i) {
				const auto& s = sections[i];
				float frac = static_cast<float>(s.size) / total_size;
				float sw = total_w * frac;
				if (sw < 28.f) sw = 28.f;
				if (x + sw > origin.x + width) sw = origin.x + width - x;
				if (sw <= 1.f) break;
				uint32_t mix = static_cast<uint32_t>(s.va ^ (s.size << 1));
				float entropy = estimate_section_entropy(mix);
				float bar_w = (sw - 8.f) * entropy;
				ImU32 ec = aida::ui::mix(t.success, t.error, entropy);
				dl->AddRectFilled(ImVec2(x + 4.f, entropy_y), ImVec2(x + 4.f + bar_w, entropy_y + 3.f),
					aida::ui::with_alpha(ec, alpha * 0.85f), 1.5f);
				dl->AddRectFilled(ImVec2(x + 4.f + bar_w, entropy_y),
					ImVec2(x + sw - 4.f, entropy_y + 3.f),
					aida::ui::with_alpha(t.border_subtle, alpha), 1.5f);
				x += sw + gap;
			}
		}

		inline ImU32 heatmap_color(int xrefs, int max_xrefs, float alpha)
		{
			const auto& t = aida::ui::resolved();
			float v = (max_xrefs > 0) ? static_cast<float>(xrefs) / static_cast<float>(max_xrefs) : 0.f;
			if (v > 1.f) v = 1.f;
			ImU32 cool = t.info_soft;
			ImU32 mid  = t.accent_dim;
			ImU32 hot  = t.warning;
			ImU32 c;
			if (v < 0.5f) {
				c = aida::ui::mix(cool, mid, v * 2.f);
			} else {
				c = aida::ui::mix(mid, hot, (v - 0.5f) * 2.f);
			}
			return aida::ui::with_alpha(c, alpha * (0.45f + v * 0.55f));
		}

		inline void render_function_heatmap(ImDrawList* dl, ImVec2 origin, float width, float height,
			const std::vector<binary_map::map_function_t>& funcs,
			view_state_t& vs, float alpha, float anim_time, uint64_t selected_va)
		{
			const auto& t = aida::ui::resolved();
			vs.hover_function_va = 0;
			if (funcs.empty()) {
				ImVec2 sz = ImVec2(width, height);
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::dots;
				cfg.title = "No functions available";
				cfg.body  = "Run analysis or wait for the binary map to populate.";
				cfg.max_width = 320.f;
				aida::ui::empty_state::render(origin, sz, cfg);
				return;
			}

			int max_xrefs = 0;
			for (const auto& f : funcs)
				if (f.xref_count > max_xrefs) max_xrefs = f.xref_count;
			if (max_xrefs <= 0) max_xrefs = 1;

			const float cell_size = 14.f;
			const float gap = 3.f;
			int cols = static_cast<int>((width + gap) / (cell_size + gap));
			if (cols < 4) cols = 4;
			int rows = (static_cast<int>(funcs.size()) + cols - 1) / cols;
			float used_h = static_cast<float>(rows) * (cell_size + gap);
			if (used_h > height) used_h = height;

			float anim_p = anim_time * 0.5f;
			if (anim_p > 1.f) anim_p = 1.f;

			for (size_t i = 0; i < funcs.size(); ++i) {
				int r = static_cast<int>(i) / cols;
				int c = static_cast<int>(i) % cols;
				float ax = origin.x + static_cast<float>(c) * (cell_size + gap);
				float ay = origin.y + static_cast<float>(r) * (cell_size + gap);
				if (ay + cell_size > origin.y + used_h) break;

				const auto& fn = funcs[i];
				float entrance = anim_p - static_cast<float>(i) * 0.0008f;
				if (entrance < 0.f) entrance = 0.f;
				if (entrance > 1.f) entrance = 1.f;
				float scale = 0.7f + 0.3f * aida::motion::ease::out_back(entrance);

				ImVec2 mp = ImGui::GetMousePos();
				bool hovered = (mp.x >= ax && mp.x < ax + cell_size && mp.y >= ay && mp.y < ay + cell_size);

				bool selected = (selected_va == fn.va) && (fn.va != 0);
				ImU32 fill = heatmap_color(fn.xref_count, max_xrefs, alpha * entrance);
				ImU32 border = aida::ui::with_alpha(t.border_subtle, alpha * 0.6f);
				if (selected) border = aida::ui::with_alpha(t.accent_u32, alpha);

				float ch = cell_size * scale;
				float pad = (cell_size - ch) * 0.5f;
				ImVec2 ca = ImVec2(ax + pad, ay + pad);
				ImVec2 cb = ImVec2(ax + cell_size - pad, ay + cell_size - pad);

				if (fn.pinned) {
					ImU32 ring = aida::ui::with_alpha(t.accent_u32, alpha * 0.85f);
					dl->AddRect(ImVec2(ca.x - 1.f, ca.y - 1.f), ImVec2(cb.x + 1.f, cb.y + 1.f),
						ring, 3.f, 0, 1.5f);
				}

				dl->AddRectFilled(ca, cb, fill, 3.f);
				dl->AddRect(ca, cb, border, 3.f, 0, 1.f);

				auto& pulse = vs.fn_pulses[fn.va];
				if (hovered) pulse.v = aida::motion::smooth_lerp(pulse.v, 1.f, 18.f, aida::ui::clock::dt());
				else         pulse.v = aida::motion::smooth_lerp(pulse.v, 0.f, 12.f, aida::ui::clock::dt());
				if (pulse.v > 0.01f) {
					ImU32 hov_ring = aida::ui::with_alpha(t.accent_hover, alpha * 0.9f * pulse.v);
					float exp = pulse.v * 2.f;
					dl->AddRect(ImVec2(ca.x - exp, ca.y - exp), ImVec2(cb.x + exp, cb.y + exp),
						hov_ring, 4.f, 0, 1.5f);
				}

				if (hovered) {
					vs.hover_function_va = fn.va;
					ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
					ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
					ImGui::SetNextWindowPos(ImVec2(mp.x + 14.f, mp.y + 14.f));
					if (ImGui::Begin("##bm_fn_tip", nullptr,
						ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
						ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
						ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_AlwaysAutoResize |
						ImGuiWindowFlags_NoNav | ImGuiWindowFlags_Tooltip)) {
						ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
						ImGui::TextUnformatted(fn.name.c_str());
						ImGui::PopStyleColor();
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
							"0x%llX", static_cast<unsigned long long>(fn.va));
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary),
							"xrefs %d   callees %d", fn.xref_count, fn.callee_count);
						if (!fn.section_name.empty()) {
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
								"in %s", fn.section_name.c_str());
						}
					}
					ImGui::End();
					ImGui::PopStyleColor();
					ImGui::PopStyleVar();
					if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						vs.selected_va.store(fn.va);
					}
					if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
						jump_to_address(fn.va);
					}
				}
			}
		}

		inline void render_call_graph_mini(ImDrawList* dl, ImVec2 origin, float width, float height,
			const binary_map::map_function_t* selected,
			float alpha, float anim_time)
		{
			const auto& t = aida::ui::resolved();
			ImVec2 a = origin;
			ImVec2 b = ImVec2(origin.x + width, origin.y + height);
			aida::ui::blur::render_glass_fill(dl, a, b, 8.f, alpha);
			aida::ui::blur::render_glass_border(dl, a, b, 8.f, alpha, 1.f);

			ImFont* head = aida::ui::fonts::body_em();
			if (!head) head = ImGui::GetFont();
			dl->AddText(head, 12.f, ImVec2(a.x + 10.f, a.y + 8.f),
				aida::ui::with_alpha(t.text_secondary, alpha), "Call Graph");

			if (!selected) {
				ImFont* font = ImGui::GetFont();
				const char* hint = "Hover or select a function to see its top callees";
				ImVec2 ts = font->CalcTextSizeA(12.f, FLT_MAX, width - 20.f, hint);
				dl->AddText(font, 12.f,
					ImVec2(a.x + (width - ts.x) * 0.5f, a.y + (height - ts.y) * 0.5f),
					aida::ui::with_alpha(t.text_dim, alpha), hint, nullptr, width - 20.f);
				return;
			}

			ImVec2 center = ImVec2(a.x + width * 0.5f, a.y + height * 0.5f + 8.f);
			float radius = std::min(width, height) * 0.32f;
			if (radius < 50.f) radius = 50.f;

			float t_sec = anim_time * 0.55f;
			ImU32 ring = aida::ui::with_alpha(t.accent_glow, alpha * 0.45f);
			dl->AddCircle(center, radius, ring, 36, 1.f);

			int callee_n = static_cast<int>(selected->top_callees.size());
			if (callee_n > 6) callee_n = 6;

			ImFont* small_font = aida::ui::fonts::body();
			if (!small_font) small_font = ImGui::GetFont();

			for (int i = 0; i < callee_n; ++i) {
				float ang = -1.5707963f + (static_cast<float>(i) / static_cast<float>(std::max(1, callee_n))) * 6.2831853f;
				ang += sinf(t_sec + static_cast<float>(i) * 0.7f) * 0.05f;
				ImVec2 p = ImVec2(center.x + cosf(ang) * radius, center.y + sinf(ang) * radius);
				float weight = 1.f - (static_cast<float>(i) / 7.f);
				ImU32 line_col = aida::ui::with_alpha(t.accent_dim, alpha * weight);
				dl->AddLine(center, p, line_col, 1.f + weight * 1.5f);
				dl->AddCircleFilled(p, 5.f + weight * 2.f,
					aida::ui::with_alpha(t.accent_grad_top, alpha * weight), 16);

				const std::string& nm = selected->top_callees[i];
				ImVec2 lblsz = small_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, nm.c_str());
				ImVec2 lblpos = ImVec2(p.x - lblsz.x * 0.5f, p.y + 8.f);
				dl->AddText(small_font, 11.f, lblpos,
					aida::ui::with_alpha(t.text_secondary, alpha), nm.c_str());
			}

			ImU32 sel_fill_top = aida::ui::with_alpha(t.accent_grad_top, alpha);
			ImU32 sel_fill_bot = aida::ui::with_alpha(t.accent_grad_bot, alpha);
			float pulse = aida::ui::clock::pulse(1.4f, 0.85f, 1.05f);
			float r = 10.f * pulse;
			dl->AddCircleFilled(center, r * 1.6f, aida::ui::with_alpha(t.accent_glow, alpha * 0.55f), 24);
			dl->AddCircleFilled(center, r, sel_fill_top, 24);
			dl->AddCircleFilled(center, r * 0.6f, sel_fill_bot, 24);

			ImVec2 lblsz = head->CalcTextSizeA(12.f, FLT_MAX, 0.f, selected->name.c_str());
			dl->AddText(head, 12.f, ImVec2(center.x - lblsz.x * 0.5f, center.y + 16.f),
				aida::ui::with_alpha(t.text_primary, alpha), selected->name.c_str());

			char addr[32];
			std::snprintf(addr, sizeof(addr), "0x%llX",
				static_cast<unsigned long long>(selected->va));
			ImVec2 addrsz = small_font->CalcTextSizeA(10.f, FLT_MAX, 0.f, addr);
			dl->AddText(small_font, 10.f, ImVec2(center.x - addrsz.x * 0.5f, center.y + 30.f),
				aida::ui::with_alpha(t.text_address, alpha), addr);
		}

	}

	inline void initialize()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		if (s.initialized) return;
		s.opts.max_functions = 200;
		s.opts.max_globals = 60;
		s.opts.max_callees_per_function = 5;
		s.opts.max_chars = 16384;
		s.opts.include_imports = true;
		s.opts.include_exports = true;
		detail::ensure_subscription(s);
		s.initialized = true;
	}

	inline void shutdown()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		if (s.subscription.valid()) {
			aida::events::unsubscribe(s.subscription);
			s.subscription = aida::events::subscription_handle_t{};
		}
		s.collapsed_groups.clear();
		s.expanded_imports.clear();
		s.rendered_text.clear();
		s.map = binary_map::map_t{};
		s.has_map.store(false);
		s.initialized = false;
	}

	inline const std::string& last_error()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		return s.last_error;
	}

	inline void refresh()
	{
		state().refresh_requested.store(true);
	}

	inline void render(int x, int y, float w, float h,
		float anim, float anim_x, float anim_y, float anim_z)
	{
		view_state_t& s = state();
		if (!s.initialized) initialize();

		if (s.refresh_requested.exchange(false)) {
			detail::perform_refresh(s);
		}

		const auto& t = aida::ui::resolved();
		const float a = anim;
		const float dt = aida::ui::clock::dt();
		s.row_anim_time += dt;

		ImGui::BeginChild("##binary_map_view", ImVec2(w, h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		const float ox = wp.x;
		const float oy = wp.y;

		dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
			aida::ui::with_alpha(t.bg_base, a));

		(void)anim_x; (void)anim_y; (void)anim_z;

		const float toolbar_h = 60.f;
		const float pad = 12.f;

		ImU32 bar_top = aida::ui::with_alpha(t.panel_header, a * 0.85f);
		ImU32 bar_bot = aida::ui::with_alpha(t.panel_bg, a * 0.85f);
		dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + w, oy + toolbar_h),
			bar_top, bar_top, bar_bot, bar_bot);
		dl->AddLine(ImVec2(ox, oy + toolbar_h - 1.f), ImVec2(ox + w, oy + toolbar_h - 1.f),
			aida::ui::with_alpha(t.border_subtle, a));

		int total_funcs = 0;
		int total_globs = 0;
		int total_imports = 0;
		int total_exports = 0;
		int total_sections = 0;
		std::string module_name;
		std::string module_format;
		uint64_t image_base = 0;
		uint64_t image_size = 0;

		{
			std::lock_guard<std::mutex> g(s.mutex);
			total_funcs    = static_cast<int>(s.map.functions.size());
			total_globs    = static_cast<int>(s.map.globals.size());
			total_imports  = static_cast<int>(s.map.imports.size());
			total_exports  = static_cast<int>(s.map.exports.size());
			total_sections = static_cast<int>(s.map.sections.size());
			module_name    = s.map.module_name;
			module_format  = s.map.format;
			image_base     = s.map.image_base;
			image_size     = s.map.image_size;
		}

		ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + 8.f));
		ImFont* head = aida::ui::fonts::body_strong();
		if (!head) head = ImGui::GetFont();
		ImGui::PushFont(head);
		const char* title_text = "Binary Map";
		dl->AddText(head, 16.f, ImVec2(ox + pad, oy + 6.f),
			aida::ui::with_alpha(t.text_primary, a), title_text);
		ImGui::PopFont();

		float modline_x = ox + pad + 130.f;
		std::string mod_summary;
		if (!module_name.empty()) {
			char tmp[256];
			std::snprintf(tmp, sizeof(tmp), "%s   %s   base 0x%llX   %s",
				module_name.c_str(),
				module_format.empty() ? "" : module_format.c_str(),
				static_cast<unsigned long long>(image_base),
				detail::format_size_human(image_size).c_str());
			mod_summary = tmp;
		} else {
			mod_summary = s.refreshing.load() ? "Building binary map..." : "(no binary loaded)";
		}
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		dl->AddText(code_font, 11.f, ImVec2(modline_x, oy + 9.f),
			aida::ui::with_alpha(t.text_dim, a), mod_summary.c_str());

		auto format_count = [](int n, char* out, size_t sz) {
			std::snprintf(out, sz, "%d", n);
		};
		char buf_funcs[24], buf_globs[24], buf_imp[24], buf_exp[24], buf_sec[24];
		format_count(total_funcs, buf_funcs, sizeof(buf_funcs));
		format_count(total_globs, buf_globs, sizeof(buf_globs));
		format_count(total_imports, buf_imp, sizeof(buf_imp));
		format_count(total_exports, buf_exp, sizeof(buf_exp));
		format_count(total_sections, buf_sec, sizeof(buf_sec));

		float chip_y = oy + 30.f;
		float chip_x = ox + pad;
		ImGui::SetCursorScreenPos(ImVec2(chip_x, chip_y));

		auto render_count_chip = [&](const char* lbl, const char* val, ImU32 col) {
			ImFont* f = aida::ui::fonts::body();
			if (!f) f = ImGui::GetFont();
			float fs = 11.f;
			float lblw = f->CalcTextSizeA(fs, FLT_MAX, 0.f, lbl).x;
			float valw = f->CalcTextSizeA(fs, FLT_MAX, 0.f, val).x;
			float pad_x = 8.f;
			float w_chip = lblw + valw + pad_x * 2.f + 6.f;
			float h_chip = 20.f;
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 ca = cp;
			ImVec2 cb = ImVec2(cp.x + w_chip, cp.y + h_chip);
			dl->AddRectFilled(ca, cb, aida::ui::with_alpha(col, a * 0.18f), h_chip * 0.5f);
			dl->AddRect(ca, cb, aida::ui::with_alpha(col, a * 0.55f), h_chip * 0.5f, 0, 1.f);
			dl->AddText(f, fs, ImVec2(ca.x + pad_x, ca.y + (h_chip - fs) * 0.5f),
				aida::ui::with_alpha(t.text_secondary, a), lbl);
			dl->AddText(f, fs, ImVec2(ca.x + pad_x + lblw + 6.f, ca.y + (h_chip - fs) * 0.5f),
				aida::ui::with_alpha(col, a), val);
			ImGui::Dummy(ImVec2(w_chip, h_chip));
			ImGui::SameLine(0.f, 6.f);
		};

		render_count_chip("Sections", buf_sec,   t.info);
		render_count_chip("Functions", buf_funcs, t.accent_u32);
		render_count_chip("Globals",   buf_globs, t.success);
		render_count_chip("Imports",   buf_imp,   t.warning);
		render_count_chip("Exports",   buf_exp,   t.accent_hover);

		const float btn_y = oy + 28.f;
		float btn_right_anchor = ox + w - pad;

		ImGui::SetCursorScreenPos(ImVec2(btn_right_anchor - 88.f, btn_y));
		bool refreshing = s.refreshing.load();
		if (aida::ui::button(refreshing ? "Refreshing" : "Refresh",
			aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm,
			ImVec2(82.f, 24.f),
			refreshing, nullptr, refreshing)) {
			if (!refreshing) s.refresh_requested.store(true);
		}

		ImGui::SetCursorScreenPos(ImVec2(btn_right_anchor - 88.f - 92.f, btn_y));
		if (aida::ui::button("To chat", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(86.f, 24.f))) {
			std::string payload;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
				payload = s.rendered_text;
			}
			detail::inject_to_chat(payload);
		}

		ImGui::SetCursorScreenPos(ImVec2(btn_right_anchor - 88.f - 92.f - 92.f, btn_y));
		if (aida::ui::button("Copy", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(86.f, 24.f))) {
			std::string payload;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
				payload = s.rendered_text;
			}
			ImGui::SetClipboardText(payload.c_str());
			toast_notification::push("Binary map copied to clipboard",
				toast_notification::toast_type_t::info, 3.0f);
		}

		const float content_y = oy + toolbar_h;
		const float content_h = h - toolbar_h;

		float left_w = std::max(360.f, w * s.left_split);
		float min_left = std::max(360.f, w * 0.4f);
		if (left_w < min_left) left_w = min_left;
		if (left_w > w - 280.f) left_w = w - 280.f;
		const float right_w = w - left_w - 1.f;
		const float split_x = ox + left_w;

		float splitter_target = 0.f;
		ImGui::SetCursorScreenPos(ImVec2(split_x - 4.f, content_y));
		ImGui::InvisibleButton("##bm_splitter", ImVec2(8.f, content_h));
		bool splitter_hov = ImGui::IsItemHovered();
		if (splitter_hov) {
			ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
			splitter_target = 1.f;
		}
		if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
			float dx = ImGui::GetIO().MouseDelta.x;
			float new_left = left_w + dx;
			if (new_left >= min_left && new_left <= w - 280.f)
				s.left_split = new_left / std::max(1.f, w);
			splitter_target = 1.f;
		}
		s.splitter_hover_v = aida::motion::smooth_lerp(s.splitter_hover_v, splitter_target, 16.f, dt);

		ImU32 sep_base = aida::ui::with_alpha(t.border_subtle, a);
		ImU32 sep_hov  = aida::ui::with_alpha(t.accent_u32, a * 0.85f);
		ImU32 sep_col  = aida::ui::mix(sep_base, sep_hov, s.splitter_hover_v);
		dl->AddLine(ImVec2(split_x, content_y), ImVec2(split_x, content_y + content_h),
			sep_col, 1.f + s.splitter_hover_v * 1.5f);

		const float left_pad = 12.f;
		float panel_x = ox + left_pad;
		float panel_w = left_w - left_pad * 2.f;
		float panel_y = content_y + 8.f;

		dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
			12.f, ImVec2(panel_x, panel_y),
			aida::ui::with_alpha(t.text_secondary, a), "Section Layout");

		float strip_top = panel_y + 18.f;
		std::vector<binary_map::map_section_t> sections_copy;
		std::vector<binary_map::map_function_t> functions_copy;
		uint64_t selected_va_local = s.selected_va.load();
		std::vector<binary_map::map_global_t> globals_copy;
		std::vector<std::string> imports_copy;
		std::vector<std::string> exports_copy;
		{
			std::lock_guard<std::mutex> g(s.mutex);
			sections_copy = s.map.sections;
			functions_copy = s.map.functions;
			globals_copy   = s.map.globals;
			imports_copy   = s.map.imports;
			exports_copy   = s.map.exports;
		}
		detail::render_section_strip(dl, ImVec2(panel_x, strip_top), panel_w,
			sections_copy, image_size, a, s.row_anim_time);

		float heat_top = strip_top + 28.f + 12.f;
		dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
			12.f, ImVec2(panel_x, heat_top - 18.f),
			aida::ui::with_alpha(t.text_secondary, a), "Function Heatmap");

		float heat_h = (content_h - (heat_top - content_y)) * 0.55f;
		if (heat_h < 120.f) heat_h = 120.f;
		detail::render_function_heatmap(dl, ImVec2(panel_x, heat_top),
			panel_w, heat_h, functions_copy, s, a, s.row_anim_time, selected_va_local);

		float graph_top = heat_top + heat_h + 16.f;
		float graph_h   = (oy + h) - graph_top - 12.f;
		if (graph_h < 80.f) graph_h = 80.f;

		const binary_map::map_function_t* selected_fn = nullptr;
		uint64_t hover_va = s.hover_function_va;
		uint64_t selected = (hover_va != 0) ? hover_va : selected_va_local;
		for (const auto& f : functions_copy) {
			if (f.va == selected) { selected_fn = &f; break; }
		}
		detail::render_call_graph_mini(dl, ImVec2(panel_x, graph_top),
			panel_w, graph_h, selected_fn, a, s.row_anim_time);

		const float right_x = ox + left_w + 1.f;
		const float right_pad = 12.f;
		ImVec2 r_a = ImVec2(right_x + right_pad, content_y + 8.f);
		ImVec2 r_b = ImVec2(right_x + right_w - right_pad, content_y + content_h - 12.f);

		aida::ui::blur::layer_request_t req;
		req.pos = r_a;
		req.size = ImVec2(r_b.x - r_a.x, r_b.y - r_a.y);
		req.radius = 12.f;
		req.strength = 0.55f;
		req.alpha = a;
		aida::ui::blur::schedule(req);
		aida::ui::blur::render_glass_fill(dl, r_a, r_b, 12.f, a);
		aida::ui::blur::render_glass_border(dl, r_a, r_b, 12.f, a, 1.f);

		float panel_inner_top = r_a.y + 10.f;
		float panel_inner_left = r_a.x + 12.f;
		float panel_inner_w = r_b.x - r_a.x - 24.f;

		ImFont* head_em = aida::ui::fonts::body_em();
		if (!head_em) head_em = ImGui::GetFont();
		dl->AddText(head_em, 12.f, ImVec2(panel_inner_left, panel_inner_top),
			aida::ui::with_alpha(t.text_secondary, a), "LLM Preview");

		ImGui::SetCursorScreenPos(ImVec2(r_b.x - 90.f, panel_inner_top - 4.f));
		if (aida::ui::button("Copy", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(80.f, 22.f))) {
			std::string payload;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
				payload = s.rendered_text;
			}
			ImGui::SetClipboardText(payload.c_str());
			toast_notification::push("Preview copied to clipboard",
				toast_notification::toast_type_t::info, 3.0f);
		}

		float filter_y = panel_inner_top + 22.f;
		ImGui::SetCursorScreenPos(ImVec2(panel_inner_left, filter_y));
		if (aida::ui::input_text("##bm_filter", s.filter_buf, sizeof(s.filter_buf),
			"Filter functions, globals, imports...", false,
			ImVec2(panel_inner_w, 28.f))) {
		}
		s.filter_lower = detail::to_lower_copy(std::string(s.filter_buf));

		float section_y = filter_y + 38.f;
		float section_inner_h = (r_b.y - section_y) - 12.f;
		ImGui::SetCursorScreenPos(ImVec2(panel_inner_left, section_y));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0,0,0,0));
		ImGui::PushFont(code_font);

		ImGui::BeginChild("##bm_preview_pane", ImVec2(panel_inner_w, section_inner_h), false,
			ImGuiWindowFlags_NoBackground);

		const std::string& filter_lower = s.filter_lower;
		bool refresh_after_pin = false;

		auto draw_section_header = [&](const char* title, int count_value,
		                                const std::string& key) -> bool {
			char hbuf[160];
			std::snprintf(hbuf, sizeof(hbuf), "%s  (%d)", title, count_value);
			const bool collapsed = detail::group_is_collapsed(s, key);
			ImVec2 cp = ImGui::GetCursorScreenPos();
			float row_w = ImGui::GetContentRegionAvail().x;
			float row_h = 24.f;
			bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
			ImU32 fill = hov
				? aida::ui::with_alpha(t.hover_wash, a)
				: aida::ui::with_alpha(t.panel_header, a * 0.55f);
			dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), fill, 6.f);
			ImU32 arrow_col = aida::ui::with_alpha(t.accent_u32, a);
			float arrow_x = cp.x + 10.f;
			float arrow_y = cp.y + row_h * 0.5f;
			ImVec2 a1, a2, a3;
			if (collapsed) {
				a1 = ImVec2(arrow_x, arrow_y - 4.f);
				a2 = ImVec2(arrow_x + 6.f, arrow_y);
				a3 = ImVec2(arrow_x, arrow_y + 4.f);
			} else {
				a1 = ImVec2(arrow_x - 1.f, arrow_y - 2.f);
				a2 = ImVec2(arrow_x + 7.f, arrow_y - 2.f);
				a3 = ImVec2(arrow_x + 3.f, arrow_y + 4.f);
			}
			dl->AddTriangleFilled(a1, a2, a3, arrow_col);

			ImFont* f_strong = aida::ui::fonts::body_em();
			if (!f_strong) f_strong = ImGui::GetFont();
			dl->AddText(f_strong, 12.f, ImVec2(cp.x + 26.f, cp.y + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_primary, a), hbuf);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				detail::toggle_group(s, key);
			}
			ImGui::Dummy(ImVec2(row_w, row_h + 4.f));
			return !collapsed;
		};

		if (draw_section_header("Sections", static_cast<int>(sections_copy.size()), "sections")) {
			int idx = 0;
			for (const auto& sec : sections_copy) {
				if (!detail::filter_matches(filter_lower, sec.name)) continue;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = ImGui::GetContentRegionAvail().x;
				float row_h = 22.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				if (hov) {
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
						aida::ui::with_alpha(t.hover_wash, a), 4.f);
				}
				char addr_buf[24];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
					static_cast<unsigned long long>(sec.va));
				ImU32 sc = detail::section_color(sec, a * 0.85f);
				dl->AddRectFilled(ImVec2(cp.x + 8.f, cp.y + 7.f), ImVec2(cp.x + 14.f, cp.y + 17.f),
					sc, 1.5f);
				dl->AddText(code_font, 11.f, ImVec2(cp.x + 22.f, cp.y + 5.f),
					aida::ui::with_alpha(t.text_primary, a), sec.name.c_str());
				dl->AddText(code_font, 11.f, ImVec2(cp.x + 110.f, cp.y + 5.f),
					aida::ui::with_alpha(t.text_address, a), addr_buf);
				std::string sz = detail::format_size_human(sec.size);
				dl->AddText(code_font, 11.f, ImVec2(cp.x + 220.f, cp.y + 5.f),
					aida::ui::with_alpha(t.text_secondary, a), sz.c_str());
				std::string p = detail::section_perm_string(sec);
				dl->AddText(code_font, 11.f, ImVec2(cp.x + row_w - 40.f, cp.y + 5.f),
					aida::ui::with_alpha(t.text_dim, a), p.c_str());
				ImGui::Dummy(ImVec2(row_w, row_h));
				++idx;
			}
		}

		if (draw_section_header("Functions", static_cast<int>(functions_copy.size()), "functions")) {
			int idx = 0;
			uint64_t cur_sel = s.selected_va.load();
			for (auto& fn : functions_copy) {
				if (!detail::filter_matches(filter_lower, fn.name)) continue;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = ImGui::GetContentRegionAvail().x;
				float row_h = 26.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				bool sel = (cur_sel == fn.va) && fn.va != 0;
				if (sel) {
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
						aida::ui::with_alpha(t.selection, a), 5.f);
					dl->AddRectFilled(cp, ImVec2(cp.x + 3.f, cp.y + row_h),
						aida::ui::with_alpha(t.accent_u32, a), 1.f);
				} else if (hov) {
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
						aida::ui::with_alpha(t.hover_wash, a), 5.f);
				}

				auto& flash = s.pin_flashes[fn.va];
				flash.tick(dt, 3.0f);
				float pin_scale = 1.f + flash.v * 0.6f;
				ImU32 star_col = fn.pinned
					? aida::ui::with_alpha(t.accent_u32, a)
					: aida::ui::with_alpha(t.text_dim, a);
				ImVec2 star_pos = ImVec2(cp.x + 12.f, cp.y + row_h * 0.5f);
				dl->AddCircleFilled(star_pos, 4.f * pin_scale,
					aida::ui::with_alpha(star_col, a * 0.85f), 12);
				if (fn.pinned) {
					dl->AddCircleFilled(star_pos, 6.f * pin_scale,
						aida::ui::with_alpha(t.accent_glow, a * (0.5f + flash.v * 0.5f)), 16);
				}

				ImGui::SetCursorScreenPos(ImVec2(cp.x + 4.f, cp.y));
				ImGui::PushID(static_cast<int>(idx));
				if (ImGui::InvisibleButton("##bm_pin_btn", ImVec2(20.f, row_h))) {
					if (fn.pinned) binary_map::unpin_function(fn.va);
					else           binary_map::pin_function(fn.va);
					flash.trigger();
					refresh_after_pin = true;
				}
				ImGui::PopID();

				char addr_buf[24];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
					static_cast<unsigned long long>(fn.va));
				dl->AddText(code_font, 11.f, ImVec2(cp.x + 26.f, cp.y + 4.f),
					aida::ui::with_alpha(t.text_address, a), addr_buf);
				dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
					12.f, ImVec2(cp.x + 26.f + 110.f, cp.y + 4.f),
					aida::ui::with_alpha(t.text_primary, a), fn.name.c_str());

				char chip_xref[24];
				std::snprintf(chip_xref, sizeof(chip_xref), "x%d", fn.xref_count);
				char chip_call[24];
				std::snprintf(chip_call, sizeof(chip_call), "c%d", fn.callee_count);
				float chip_y = cp.y + row_h - 14.f;
				float chip_x = cp.x + 26.f + 110.f;

				auto draw_mini_chip = [&](const char* label, ImU32 col) {
					ImFont* f = code_font;
					float fs = 10.f;
					ImVec2 sz = f->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
					float pad_x = 5.f;
					float wc = sz.x + pad_x * 2.f;
					float hc = 12.f;
					dl->AddRectFilled(ImVec2(chip_x, chip_y),
						ImVec2(chip_x + wc, chip_y + hc),
						aida::ui::with_alpha(col, a * 0.22f), hc * 0.5f);
					dl->AddText(f, fs, ImVec2(chip_x + pad_x, chip_y),
						aida::ui::with_alpha(col, a), label);
					chip_x += wc + 4.f;
				};
				draw_mini_chip(chip_xref, t.info);
				draw_mini_chip(chip_call, t.accent_u32);

				ImGui::SetCursorScreenPos(ImVec2(cp.x + 26.f, cp.y));
				ImGui::PushID(static_cast<int>(0x40000000 | idx));
				ImGui::InvisibleButton("##bm_fn_row", ImVec2(row_w - 26.f, row_h));
				if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
					s.selected_va.store(fn.va);
				}
				if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
					s.ctx_target.store(idx);
					s.ctx_va = fn.va;
					ImGui::OpenPopup("##bm_fn_ctx");
				}
				if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ImGui::IsItemHovered()) {
					detail::jump_to_address(fn.va);
				}
				if (ImGui::BeginPopup("##bm_fn_ctx")) {
					if (ImGui::MenuItem("Copy summary to chat")) {
						std::string payload = detail::make_function_chat_payload(fn);
						detail::inject_to_chat(payload);
					}
					if (ImGui::MenuItem(fn.pinned ? "Unpin" : "Pin")) {
						if (fn.pinned) binary_map::unpin_function(fn.va);
						else           binary_map::pin_function(fn.va);
						flash.trigger();
						refresh_after_pin = true;
					}
					if (ImGui::MenuItem("Jump to address")) {
						const uint64_t va = fn.va;
						ImGui::CloseCurrentPopup();
						detail::jump_to_address(va);
					}
					ImGui::EndPopup();
				}
				ImGui::PopID();
				ImGui::Dummy(ImVec2(row_w, row_h));
				++idx;
			}
		}

		if (draw_section_header("Globals", static_cast<int>(globals_copy.size()), "globals")) {
			int idx = 0;
			for (const auto& gl : globals_copy) {
				if (!detail::filter_matches(filter_lower, gl.name)) continue;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = ImGui::GetContentRegionAvail().x;
				float row_h = 22.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				if (hov) {
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
						aida::ui::with_alpha(t.hover_wash, a), 4.f);
				}
				char addr_buf[24];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
					static_cast<unsigned long long>(gl.va));
				dl->AddText(code_font, 11.f, ImVec2(cp.x + 8.f, cp.y + 5.f),
					aida::ui::with_alpha(t.text_address, a), addr_buf);
				dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
					12.f, ImVec2(cp.x + 110.f, cp.y + 4.f),
					aida::ui::with_alpha(t.text_primary, a), gl.name.c_str());

				char chip_buf[16];
				std::snprintf(chip_buf, sizeof(chip_buf), "x%d", gl.xref_count);
				ImVec2 sz = code_font->CalcTextSizeA(10.f, FLT_MAX, 0.f, chip_buf);
				float chip_w = sz.x + 10.f;
				ImVec2 ca = ImVec2(cp.x + row_w - chip_w - 30.f, cp.y + 5.f);
				ImVec2 cb = ImVec2(ca.x + chip_w, ca.y + 12.f);
				dl->AddRectFilled(ca, cb, aida::ui::with_alpha(t.info, a * 0.22f), 6.f);
				dl->AddText(code_font, 10.f, ImVec2(ca.x + 5.f, ca.y),
					aida::ui::with_alpha(t.info, a), chip_buf);

				ImU32 perm_col = gl.writable
					? aida::ui::with_alpha(t.success, a)
					: aida::ui::with_alpha(t.text_dim, a);
				dl->AddText(code_font, 10.f, ImVec2(cp.x + row_w - 22.f, cp.y + 5.f),
					perm_col, gl.writable ? "rw" : "ro");

				ImGui::SetCursorScreenPos(cp);
				ImGui::PushID(static_cast<int>(0x50000000 | idx));
				ImGui::InvisibleButton("##bm_gl_row", ImVec2(row_w, row_h));
				if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
					ImGui::OpenPopup("##bm_gl_ctx");
				}
				if (ImGui::BeginPopup("##bm_gl_ctx")) {
					if (ImGui::MenuItem("Copy summary to chat")) {
						std::string payload = detail::make_global_chat_payload(gl);
						detail::inject_to_chat(payload);
					}
					if (ImGui::MenuItem("Jump to address")) {
						const uint64_t va = gl.va;
						ImGui::CloseCurrentPopup();
						detail::jump_to_address(va);
					}
					ImGui::EndPopup();
				}
				ImGui::PopID();
				++idx;
			}
		}

		if (draw_section_header("Imports", total_imports, "imports")) {
			int imp_idx = 0;
			for (const auto& imp : imports_copy) {
				const auto colon = imp.find(':');
				const std::string dll = (colon == std::string::npos) ? imp : imp.substr(0, colon);
				std::string func_list;
				if (colon != std::string::npos && colon + 1 < imp.size()) {
					size_t start = colon + 1;
					while (start < imp.size() && imp[start] == ' ') ++start;
					func_list = imp.substr(start);
				}

				std::vector<std::string> funcs;
				{
					size_t pos = 0;
					while (pos < func_list.size()) {
						size_t next = func_list.find(',', pos);
						if (next == std::string::npos) next = func_list.size();
						std::string token = func_list.substr(pos, next - pos);
						while (!token.empty() && token.front() == ' ') token.erase(token.begin());
						while (!token.empty() && token.back() == ' ') token.pop_back();
						if (!token.empty()) funcs.push_back(std::move(token));
						pos = next + 1u;
					}
				}

				bool any_match = detail::filter_matches(filter_lower, dll);
				if (!any_match) {
					for (const auto& fn : funcs) {
						if (detail::filter_matches(filter_lower, fn)) {
							any_match = true;
							break;
						}
					}
				}
				if (!any_match) continue;

				const std::string key = std::string("imports::") + dll;
				bool collapsed = detail::group_is_collapsed(s, key);

				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = ImGui::GetContentRegionAvail().x;
				float row_h = 20.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				ImU32 fill = hov
					? aida::ui::with_alpha(t.hover_wash, a)
					: aida::ui::with_alpha(t.panel_bg, a * 0.7f);
				dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), fill, 4.f);
				ImU32 ar = aida::ui::with_alpha(t.accent_u32, a);
				float arrow_x = cp.x + 10.f;
				float arrow_y = cp.y + row_h * 0.5f;
				if (collapsed) {
					dl->AddTriangleFilled(
						ImVec2(arrow_x, arrow_y - 3.f),
						ImVec2(arrow_x + 5.f, arrow_y),
						ImVec2(arrow_x, arrow_y + 3.f), ar);
				} else {
					dl->AddTriangleFilled(
						ImVec2(arrow_x - 1.f, arrow_y - 2.f),
						ImVec2(arrow_x + 5.f, arrow_y - 2.f),
						ImVec2(arrow_x + 2.f, arrow_y + 3.f), ar);
				}
				char hbuf[200];
				std::snprintf(hbuf, sizeof(hbuf), "%s  (%d)",
					dll.c_str(), static_cast<int>(funcs.size()));
				dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
					12.f, ImVec2(cp.x + 24.f, cp.y + 3.f),
					aida::ui::with_alpha(t.text_primary, a), hbuf);

				ImGui::SetCursorScreenPos(cp);
				ImGui::PushID(static_cast<int>(0x60000000 | imp_idx));
				ImGui::InvisibleButton("##bm_imp_hdr", ImVec2(row_w, row_h));
				if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
					detail::toggle_group(s, key);
				}
				ImGui::PopID();

				if (!collapsed) {
					for (const auto& fn : funcs) {
						if (!detail::filter_matches(filter_lower, fn) &&
							!detail::filter_matches(filter_lower, dll)) continue;
						ImVec2 ip = ImGui::GetCursorScreenPos();
						dl->AddText(code_font, 11.f, ImVec2(ip.x + 30.f, ip.y + 3.f),
							aida::ui::with_alpha(t.text_secondary, a), fn.c_str());
						ImGui::Dummy(ImVec2(row_w, row_h - 2.f));
					}
				}
				++imp_idx;
			}
		}

		if (draw_section_header("Exports", total_exports, "exports")) {
			int idx = 0;
			for (const auto& ex : exports_copy) {
				if (!detail::filter_matches(filter_lower, ex)) continue;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = ImGui::GetContentRegionAvail().x;
				float row_h = 18.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				if (hov) {
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
						aida::ui::with_alpha(t.hover_wash, a), 3.f);
				}
				dl->AddText(code_font, 11.f, ImVec2(cp.x + 14.f, cp.y + 2.f),
					aida::ui::with_alpha(t.text_primary, a), ex.c_str());
				ImGui::Dummy(ImVec2(row_w, row_h));
				++idx;
			}
		}

		if (functions_copy.empty() && !refreshing) {
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 sz = ImVec2(panel_inner_w, std::max(120.f, section_inner_h * 0.5f));
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
			cfg.title = "No binary loaded";
			cfg.body = s.last_error.empty()
				? "Open a binary or press Refresh to build the map."
				: s.last_error;
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(cp, sz, cfg);
		}

		ImGui::EndChild();
		ImGui::PopFont();
		ImGui::PopStyleColor(3);

		ImGui::EndChild();

		if (refresh_after_pin) {
			s.refresh_requested.store(true);
		}

		if (!s.auto_refreshed_once && !s.refreshing.load()) {
			s.auto_refreshed_once = true;
			s.refresh_requested.store(true);
		}
	}

}
}
