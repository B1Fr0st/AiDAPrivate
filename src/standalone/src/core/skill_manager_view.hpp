#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <windows.h>
#include <shellapi.h>

#include "imgui/imgui.h"

#include "agent_registry.hpp"
#include "chat_render.hpp"
#include "skills.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "work_queue.hpp"
#include "../helpers/globals.h"

namespace aida {
namespace skill_manager {


	enum class source_tab_t : int {
		built_in = 0,
		project  = 1,
		remote   = 2,
	};


	struct remote_fetch_result_t {
		std::string                                 url;
		bool                                        completed = false;
		bool                                        success   = false;
		std::string                                 error;
		::aida::skills::remote_index_t              index;
	};

	struct install_request_t {
		std::string url;
		std::string name;
		std::atomic<bool> completed{false};
		std::atomic<bool> success{false};
		std::string error;
	};


	inline std::mutex& state_mutex()
	{
		static std::mutex m;
		return m;
	}

	struct view_state_t {
		bool                                                       initialized = false;
		std::atomic<bool>                                          shutdown_flag{false};
		std::string                                                last_error;
		source_tab_t                                               active_tab = source_tab_t::built_in;
		std::string                                                selected_skill_name;
		char                                                       search_buf[256] = {};
		char                                                       add_url_buf[1024] = {};
		std::string                                                agent_filter;
		std::map<std::string, remote_fetch_result_t>               remote_cache;
		std::map<std::string, std::shared_ptr<install_request_t>>  install_pending;
		std::set<std::string>                                      pending_uninstall;
		bool                                                       preview_rendered = true;
		float                                                      list_split = 0.32f;
		float                                                      detail_split = 0.40f;
		int                                                        last_skill_count = 0;
		int64_t                                                    last_indexed_unix = 0;
		std::string                                                cached_skill_name;
		std::string                                                cached_skill_body;
		std::vector<std::string>                                   cached_skill_hints;
	};

	inline view_state_t& state()
	{
		static view_state_t s;
		return s;
	}


	inline const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		return state().last_error;
	}

	inline void set_error(const std::string& msg)
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		state().last_error = msg;
	}


	inline std::string lower_copy(const std::string& s)
	{
		std::string out = s;
		std::transform(out.begin(), out.end(), out.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return out;
	}

	inline std::string truncate_text(const std::string& s, size_t max_len)
	{
		if (s.size() <= max_len) return s;
		return s.substr(0, max_len) + "...";
	}

	inline source_tab_t classify_skill(const ::aida::skills::skill_metadata_t& m)
	{
		if (m.source == "remote") return source_tab_t::remote;
		if (m.source == "global") return source_tab_t::built_in;
		return source_tab_t::project;
	}

	inline const char* tab_label(source_tab_t t)
	{
		switch (t) {
			case source_tab_t::built_in: return "Built-in";
			case source_tab_t::project:  return "Project";
			case source_tab_t::remote:   return "Remote";
		}
		return "?";
	}

	inline std::string source_label(const ::aida::skills::skill_metadata_t& m)
	{
		if (m.source == "remote") return "remote";
		if (m.source == "global") return "built-in";
		return "project";
	}

	inline void open_path_in_shell(const std::string& path, bool select_in_explorer)
	{
		if (path.empty()) return;
		const int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
		if (wlen <= 0) return;
		std::wstring wpath(static_cast<size_t>(wlen), L'\0');
		MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wlen);
		if (!wpath.empty() && wpath.back() == L'\0') wpath.pop_back();
		if (select_in_explorer) {
			std::wstring args = L"/select,\"" + wpath + L"\"";
			ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
		} else {
			ShellExecuteW(nullptr, L"open", wpath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
		}
	}


	inline std::vector<::aida::skills::skill_metadata_t> snapshot_filtered_for_view(
		source_tab_t tab,
		const std::string& filter_lower,
		const std::string& agent_filter)
	{
		std::vector<::aida::skills::skill_metadata_t> base;
		if (!agent_filter.empty()) {
			const auto ptrs = ::aida::skills::available_for_agent(agent_filter);
			base.reserve(ptrs.size());
			for (const auto* p : ptrs) {
				if (p) base.push_back(*p);
			}
		} else {
			base = ::aida::skills::all();
		}

		std::vector<::aida::skills::skill_metadata_t> out;
		out.reserve(base.size());
		for (const auto& m : base) {
			if (classify_skill(m) != tab) continue;
			if (!filter_lower.empty()) {
				const std::string n = lower_copy(m.name);
				const std::string d = lower_copy(m.description);
				if (n.find(filter_lower) == std::string::npos &&
					d.find(filter_lower) == std::string::npos)
					continue;
			}
			out.push_back(m);
		}
		return out;
	}


	inline void render_chip(ImDrawList* dl, float x, float y, const std::string& text,
		ImU32 bg, ImU32 fg, float alpha)
	{
		ImVec2 ts = ImGui::CalcTextSize(text.c_str());
		const float pad_x = 6.f;
		const float pad_y = 2.f;
		const float w = ts.x + pad_x * 2.f;
		const float h = ts.y + pad_y * 2.f;
		ImU32 bg_a = (bg & 0x00FFFFFFu) | (static_cast<unsigned>(((bg >> 24) & 0xFFu) * alpha) << 24);
		ImU32 fg_a = (fg & 0x00FFFFFFu) | (static_cast<unsigned>(((fg >> 24) & 0xFFu) * alpha) << 24);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), bg_a, h * 0.5f);
		dl->AddText(ImVec2(x + pad_x, y + pad_y), fg_a, text.c_str());
	}

	inline float render_agent_chips_row(ImDrawList* dl, float x, float y, float max_w,
		const std::vector<std::string>& slugs, float alpha)
	{
		if (slugs.empty()) return 0.f;
		float cx = x;
		const float gap = 4.f;
		const ImU32 bg = IM_COL32(60, 70, 90, 200);
		const ImU32 fg = IM_COL32(190, 210, 240, 240);
		int shown = 0;
		for (const auto& s : slugs) {
			ImVec2 ts = ImGui::CalcTextSize(s.c_str());
			const float w = ts.x + 12.f;
			if (shown >= 3 || cx + w > x + max_w) {
				render_chip(dl, cx, y, "...", IM_COL32(60, 70, 90, 200),
					IM_COL32(190, 210, 240, 240), alpha);
				return ts.y + 4.f;
			}
			render_chip(dl, cx, y, s, bg, fg, alpha);
			cx += w + gap;
			++shown;
		}
		return ImGui::GetFontSize() + 4.f;
	}


	inline void start_remote_fetch(const std::string& url)
	{
		work_queue::post([url]() {
			::aida::skills::remote_index_t idx;
			std::string err;
			const bool ok = ::aida::skills::fetch_remote_index(url, idx, 10000);
			if (!ok) err = ::aida::skills::last_error();

			std::lock_guard<std::mutex> lk(state_mutex());
			auto& cache = state().remote_cache[url];
			cache.url       = url;
			cache.completed = true;
			cache.success   = ok;
			cache.error     = err;
			cache.index     = std::move(idx);
		});
	}

	inline void start_install(const std::string& url, const std::string& name)
	{
		auto rec = std::make_shared<install_request_t>();
		rec->url  = url;
		rec->name = name;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			state().install_pending[name] = rec;
		}
		work_queue::post([rec]() {
			const bool ok = ::aida::skills::install_remote_skill(rec->url, rec->name);
			if (!ok) rec->error = ::aida::skills::last_error();
			rec->success.store(ok);
			rec->completed.store(true);
		});
	}


	inline void ensure_selected_cached()
	{
		std::string sel;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			sel = state().selected_skill_name;
			if (sel.empty()) {
				state().cached_skill_name.clear();
				state().cached_skill_body.clear();
				state().cached_skill_hints.clear();
				return;
			}
			if (state().cached_skill_name == sel) return;
		}
		const auto resolved = ::aida::skills::resolve(sel);
		const auto hints = ::aida::skills::placeholder_hints_for(resolved.instructions);
		std::lock_guard<std::mutex> lk(state_mutex());
		state().cached_skill_name = sel;
		state().cached_skill_body = resolved.instructions;
		state().cached_skill_hints = hints;
	}

	inline void poll_pending_installs()
	{
		std::vector<std::shared_ptr<install_request_t>> done;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			auto& pending = state().install_pending;
			for (auto it = pending.begin(); it != pending.end(); ) {
				if (it->second->completed.load()) {
					done.push_back(it->second);
					it = pending.erase(it);
				} else {
					++it;
				}
			}
		}
		for (const auto& r : done) {
			if (r->success.load()) {
				toast_notification::push("Installed skill: " + r->name,
					toast_notification::toast_type_t::info, 4.0f);
				::aida::skills::reindex();
			} else {
				toast_notification::push("Install failed: " + truncate_text(r->error, 200),
					toast_notification::toast_type_t::error, 6.0f);
			}
		}
	}

	inline void poll_pending_remote_fetches()
	{
		std::vector<remote_fetch_result_t> snapshots;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			for (auto& kv : state().remote_cache) {
				if (kv.second.completed && !kv.second.error.empty()) {
					snapshots.push_back(kv.second);
					kv.second.error.clear();
				}
			}
		}
		for (const auto& s : snapshots) {
			toast_notification::push("Index fetch failed: " + truncate_text(s.error, 200),
				toast_notification::toast_type_t::error, 5.0f);
		}
	}


	inline void initialize()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		auto& s = state();
		if (s.initialized) return;
		s.initialized = true;
		s.active_tab = source_tab_t::built_in;
		s.selected_skill_name.clear();
		s.list_split = 0.32f;
		s.detail_split = 0.40f;
		s.last_indexed_unix = static_cast<int64_t>(std::time(nullptr));
	}

	inline void shutdown()
	{
		std::lock_guard<std::mutex> lk(state_mutex());
		auto& s = state();
		s.shutdown_flag.store(true);
		s.initialized = false;
		s.remote_cache.clear();
		s.install_pending.clear();
		s.pending_uninstall.clear();
	}


	inline void render_toolbar(float root_x, float root_y, float root_w, float toolbar_h,
		float ar, float ag, float ab, float alpha)
	{
		auto& st = state();
		const float pad = 10.f;
		const float search_w = std::max(220.f, (root_w - pad * 6.f) * 0.30f);
		ImGui::SetCursorScreenPos(ImVec2(root_x + pad, root_y + 4.f));
		ui_anim::render_filter_input_chip("##sm_search", st.search_buf, sizeof(st.search_buf),
			"Filter skills", search_w, ar, ag, ab, alpha);

		const float combo_x = root_x + pad * 2.f + search_w;
		const float combo_w = 200.f;
		ImGui::SetCursorScreenPos(ImVec2(combo_x, root_y + 4.f));
		ImGui::PushItemWidth(combo_w);

		std::string current_label = st.agent_filter.empty()
			? std::string("All agents") : st.agent_filter;
		if (ImGui::BeginCombo("##sm_agent_filter", current_label.c_str())) {
			if (ImGui::Selectable("All agents", st.agent_filter.empty())) {
				st.agent_filter.clear();
			}
			const auto agents = ::aida::agent::primary_agents();
			for (const auto* a : agents) {
				if (a == nullptr) continue;
				const bool sel = (st.agent_filter == a->name);
				if (ImGui::Selectable(a->name.c_str(), sel)) {
					st.agent_filter = a->name;
				}
			}
			ImGui::EndCombo();
		}
		ImGui::PopItemWidth();

		const float refresh_x = combo_x + combo_w + pad;
		const float refresh_w = 110.f;
		ImGui::SetCursorScreenPos(ImVec2(refresh_x, root_y + 4.f));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(ar * 0.32f, ag * 0.32f, ab * 0.32f, 0.6f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(ar * 0.55f, ag * 0.55f, ab * 0.55f, 0.8f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(ar * 0.7f, ag * 0.7f, ab * 0.7f, 1.f));
		if (ImGui::Button("Refresh##sm", ImVec2(refresh_w, 24.f))) {
			::aida::skills::reindex();
			std::lock_guard<std::mutex> lk(state_mutex());
			state().last_indexed_unix = static_cast<int64_t>(std::time(nullptr));
			toast_notification::push("Skills re-indexed",
				toast_notification::toast_type_t::info, 2.5f);
		}
		ImGui::PopStyleColor(3);

		const float url_w = 280.f;
		const float url_x = root_x + root_w - pad - url_w - 80.f;
		ImGui::SetCursorScreenPos(ImVec2(url_x, root_y + 4.f));
		ImGui::PushItemWidth(url_w);
		ImGui::InputTextWithHint("##sm_add_url", "https://host/index.json",
			st.add_url_buf, sizeof(st.add_url_buf));
		ImGui::PopItemWidth();

		const float add_x = root_x + root_w - pad - 70.f;
		ImGui::SetCursorScreenPos(ImVec2(add_x, root_y + 4.f));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(ar * 0.40f, ag * 0.40f, ab * 0.40f, 0.7f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(ar * 0.60f, ag * 0.60f, ab * 0.60f, 0.9f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(ar * 0.75f, ag * 0.75f, ab * 0.75f, 1.0f));
		if (ImGui::Button("Add URL##sm", ImVec2(70.f, 24.f))) {
			std::string url(st.add_url_buf);
			if (!url.empty()) {
				if (::aida::skills::add_remote_url(url)) {
					toast_notification::push("Remote URL added",
						toast_notification::toast_type_t::info, 3.0f);
					std::memset(st.add_url_buf, 0, sizeof(st.add_url_buf));
					st.active_tab = source_tab_t::remote;
					start_remote_fetch(url);
				} else {
					toast_notification::push("Add URL failed: " +
						truncate_text(::aida::skills::last_error(), 160),
						toast_notification::toast_type_t::error, 5.0f);
				}
			}
		}
		ImGui::PopStyleColor(3);
	}

	inline void render_tab_strip(float x, float y, float w,
		float ar, float ag, float ab, float alpha)
	{
		auto& st = state();
		ImGui::SetCursorScreenPos(ImVec2(x, y));
		const source_tab_t tabs[] = { source_tab_t::built_in, source_tab_t::project, source_tab_t::remote };
		const float btn_w = (w - 8.f) / 3.f;
		for (int i = 0; i < 3; ++i) {
			if (i > 0) ImGui::SameLine(0.f, 4.f);
			const bool active = (st.active_tab == tabs[i]);
			if (active) {
				ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(ar * 0.45f, ag * 0.45f, ab * 0.45f, 0.85f));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(ar * 0.60f, ag * 0.60f, ab * 0.60f, 0.95f));
				ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(ar * 0.75f, ag * 0.75f, ab * 0.75f, 1.0f));
			} else {
				ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.18f, 0.22f, 0.65f));
				ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.26f, 0.26f, 0.30f, 0.80f));
				ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.34f, 0.34f, 0.38f, 0.95f));
			}
			char id[40];
			std::snprintf(id, sizeof(id), "%s##sm_tab_%d", tab_label(tabs[i]), i);
			if (ImGui::Button(id, ImVec2(btn_w, 22.f))) {
				st.active_tab = tabs[i];
				st.selected_skill_name.clear();
			}
			ImGui::PopStyleColor(3);
		}
		(void)alpha;
	}

	inline void render_skill_row(ImDrawList* dl, float x, float y, float w, float h,
		const ::aida::skills::skill_metadata_t& m, bool selected, bool enabled,
		float ar, float ag, float ab, float alpha)
	{
		ImU32 row_bg;
		if (selected) {
			row_bg = IM_COL32(
				static_cast<int>(ar * 0.35f * 255.f),
				static_cast<int>(ag * 0.35f * 255.f),
				static_cast<int>(ab * 0.35f * 255.f),
				static_cast<int>(220 * alpha));
		} else {
			row_bg = IM_COL32(28, 28, 36, static_cast<int>(180 * alpha));
		}
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), row_bg, 4.f);
		dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h),
			IM_COL32(255, 255, 255, static_cast<int>(14 * alpha)), 4.f, 0, 0.5f);

		const float cb_size = 14.f;
		const float cb_x = x + 8.f;
		const float cb_y = y + (h - cb_size) * 0.5f;
		ImU32 cb_border = IM_COL32(160, 160, 180, static_cast<int>(220 * alpha));
		dl->AddRect(ImVec2(cb_x, cb_y), ImVec2(cb_x + cb_size, cb_y + cb_size), cb_border, 2.f, 0, 1.f);
		if (enabled) {
			ImU32 cb_fill = IM_COL32(
				static_cast<int>(ar * 255.f),
				static_cast<int>(ag * 255.f),
				static_cast<int>(ab * 255.f),
				static_cast<int>(230 * alpha));
			dl->AddRectFilled(ImVec2(cb_x + 2.f, cb_y + 2.f),
				ImVec2(cb_x + cb_size - 2.f, cb_y + cb_size - 2.f),
				cb_fill, 1.5f);
		}

		const float text_x = cb_x + cb_size + 8.f;
		ImU32 name_col = enabled
			? IM_COL32(232, 232, 248, static_cast<int>(245 * alpha))
			: IM_COL32(150, 150, 170, static_cast<int>(180 * alpha));
		dl->AddText(ImVec2(text_x, y + 6.f), name_col, m.name.c_str());

		ImU32 dim_col = IM_COL32(150, 155, 175, static_cast<int>(170 * alpha));
		const std::string path_short = truncate_text(m.file_path, 60);
		dl->AddText(ImVec2(text_x, y + 6.f + ImGui::GetFontSize() + 2.f), dim_col, path_short.c_str());

		const float chips_y = y + 6.f + (ImGui::GetFontSize() + 2.f) * 2.f;
		render_agent_chips_row(dl, text_x, chips_y, w - (text_x - x) - 8.f, m.agent_slugs, alpha);
	}

	inline void render_left_column(float x, float y, float w, float h,
		float ar, float ag, float ab, float alpha)
	{
		auto& st = state();
		ImGui::SetCursorScreenPos(ImVec2(x, y));
		render_tab_strip(x, y, w, ar, ag, ab, alpha);

		const float tab_h = 26.f;
		const float list_y = y + tab_h;
		const bool remote_tab = (st.active_tab == source_tab_t::remote);
		const float remote_panel_h = remote_tab ? 180.f : 0.f;
		const float list_h = h - tab_h - remote_panel_h - (remote_tab ? 6.f : 0.f);

		ImGui::SetCursorScreenPos(ImVec2(x, list_y));
		ImGui::BeginChild("##sm_list_scroll", ImVec2(w, list_h), false,
			ImGuiWindowFlags_NoBackground);

		const std::string filter_lower = lower_copy(std::string(st.search_buf));
		std::vector<::aida::skills::skill_metadata_t> filtered;
		std::string agent_snapshot;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			agent_snapshot = st.agent_filter;
		}
		filtered = snapshot_filtered_for_view(st.active_tab, filter_lower, agent_snapshot);

		std::set<std::string> disabled_snapshot;
		{
			const auto disabled_list = ::aida::skills::list_disabled();
			for (const auto& n : disabled_list) disabled_snapshot.insert(n);
		}

		auto* dl = ImGui::GetWindowDrawList();
		const float row_h = 64.f;
		const float row_gap = 6.f;
		const float row_w = w - 16.f;

		if (filtered.empty()) {
			const ImVec2 cs = ImGui::GetCursorScreenPos();
			ImU32 dim = IM_COL32(170, 175, 195, static_cast<int>(220 * alpha));
			dl->AddText(ImVec2(cs.x + 8.f, cs.y + 8.f), dim, "No skills in this category");
			ImGui::Dummy(ImVec2(row_w, 32.f));
		}

		for (const auto& m : filtered) {
			ImGui::Dummy(ImVec2(8.f, 0.f));
			ImGui::SameLine();
			const ImVec2 sp = ImGui::GetCursorScreenPos();
			const bool sel = (st.selected_skill_name == m.name);
			const bool en = (disabled_snapshot.count(m.name) == 0);
			render_skill_row(dl, sp.x, sp.y, row_w, row_h, m, sel, en, ar, ag, ab, alpha);

			ImGui::SetCursorScreenPos(sp);
			ImGui::PushID(m.name.c_str());
			ImGui::InvisibleButton("##sm_row", ImVec2(row_w, row_h));
			const bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			const bool right   = ImGui::IsItemClicked(ImGuiMouseButton_Right);

			const ImVec2 mp = ImGui::GetIO().MousePos;
			const bool in_cb = mp.x >= sp.x + 6.f && mp.x <= sp.x + 26.f &&
				mp.y >= sp.y + 6.f && mp.y <= sp.y + 26.f;
			if (clicked) {
				if (in_cb) {
					::aida::skills::set_enabled(m.name, !en);
				} else {
					st.selected_skill_name = m.name;
				}
			}
			if (right) ImGui::OpenPopup("##sm_row_ctx");

			if (ImGui::BeginPopup("##sm_row_ctx")) {
				if (ImGui::MenuItem("Open file")) open_path_in_shell(m.file_path, true);
				if (ImGui::MenuItem("Reload")) ::aida::skills::reindex();
				if (ImGui::MenuItem(en ? "Disable" : "Enable")) {
					::aida::skills::set_enabled(m.name, !en);
				}
				if (m.source == "remote") {
					if (ImGui::MenuItem("Delete")) {
						if (::aida::skills::uninstall_remote_skill(m.name)) {
							toast_notification::push("Uninstalled: " + m.name,
								toast_notification::toast_type_t::info, 3.0f);
							if (st.selected_skill_name == m.name)
								st.selected_skill_name.clear();
						} else {
							toast_notification::push("Uninstall failed: " +
								truncate_text(::aida::skills::last_error(), 180),
								toast_notification::toast_type_t::error, 5.0f);
						}
					}
				}
				ImGui::EndPopup();
			}
			ImGui::PopID();

			ImGui::SetCursorScreenPos(sp);
			ImGui::Dummy(ImVec2(row_w, row_h + row_gap));
		}

		ImGui::EndChild();

		if (remote_tab) {
			const float rp_y = list_y + list_h + 6.f;
			ImGui::SetCursorScreenPos(ImVec2(x, rp_y));
			ImGui::BeginChild("##sm_remote_panel", ImVec2(w, remote_panel_h), false,
				ImGuiWindowFlags_NoBackground);

			auto* dl2 = ImGui::GetWindowDrawList();
			const ImVec2 rp = ImGui::GetCursorScreenPos();
			ImU32 hdr = IM_COL32(220, 220, 240, static_cast<int>(220 * alpha));
			dl2->AddText(ImVec2(rp.x + 8.f, rp.y + 4.f), hdr, "Remote sources");

			ImGui::Dummy(ImVec2(0.f, 22.f));

			const auto urls = ::aida::skills::list_remote_urls();
			if (urls.empty()) {
				ImU32 dim = IM_COL32(160, 165, 185, static_cast<int>(200 * alpha));
				const ImVec2 cs = ImGui::GetCursorScreenPos();
				dl2->AddText(ImVec2(cs.x + 8.f, cs.y + 4.f), dim,
					"No remote URLs registered. Use the toolbar above to add one.");
				ImGui::Dummy(ImVec2(w, 26.f));
			}

			for (const auto& u : urls) {
				ImGui::PushID(u.c_str());
				const ImVec2 cs = ImGui::GetCursorScreenPos();
				const float row_w_inner = w - 16.f;
				dl2->AddRectFilled(ImVec2(cs.x + 4.f, cs.y), ImVec2(cs.x + row_w_inner, cs.y + 24.f),
					IM_COL32(28, 28, 36, static_cast<int>(170 * alpha)), 4.f);
				dl2->AddText(ImVec2(cs.x + 10.f, cs.y + 4.f),
					IM_COL32(220, 222, 240, static_cast<int>(230 * alpha)),
					truncate_text(u, 80).c_str());

				ImGui::SetCursorScreenPos(ImVec2(cs.x + row_w_inner - 140.f, cs.y));
				if (ImGui::SmallButton("Fetch")) start_remote_fetch(u);
				ImGui::SameLine(0.f, 4.f);
				if (ImGui::SmallButton("Remove")) {
					if (::aida::skills::remove_remote_url(u)) {
						toast_notification::push("Removed remote URL",
							toast_notification::toast_type_t::info, 3.0f);
					} else {
						toast_notification::push("Remove failed: " +
							truncate_text(::aida::skills::last_error(), 160),
							toast_notification::toast_type_t::error, 4.0f);
					}
				}

				ImGui::SetCursorScreenPos(ImVec2(cs.x, cs.y + 28.f));

				bool have_index = false;
				remote_fetch_result_t snap;
				{
					std::lock_guard<std::mutex> lk(state_mutex());
					auto it = state().remote_cache.find(u);
					if (it != state().remote_cache.end()) {
						snap = it->second;
						have_index = snap.completed && snap.success;
					}
				}
				if (have_index) {
					for (const auto& e : snap.index.entries) {
						ImGui::PushID(e.name.c_str());
						const ImVec2 ec = ImGui::GetCursorScreenPos();
						dl2->AddText(ImVec2(ec.x + 16.f, ec.y + 2.f),
							IM_COL32(210, 215, 235, static_cast<int>(220 * alpha)),
							e.name.c_str());
						ImGui::SetCursorScreenPos(ImVec2(ec.x + row_w_inner - 80.f, ec.y));
						std::shared_ptr<install_request_t> req;
						{
							std::lock_guard<std::mutex> lk(state_mutex());
							auto it2 = state().install_pending.find(e.name);
							if (it2 != state().install_pending.end()) req = it2->second;
						}
						if (req) {
							ImGui::TextUnformatted("Installing...");
						} else {
							if (ImGui::SmallButton("Install")) start_install(u, e.name);
						}
						ImGui::SetCursorScreenPos(ImVec2(ec.x, ec.y + 22.f));
						ImGui::PopID();
					}
				}
				ImGui::PopID();
				ImGui::Dummy(ImVec2(0.f, 6.f));
			}

			ImGui::EndChild();
		}
	}

	inline const ::aida::skills::skill_metadata_t* find_meta_in_list(
		const std::vector<::aida::skills::skill_metadata_t>& list, const std::string& name)
	{
		for (const auto& m : list) {
			if (m.name == name) return &m;
		}
		return nullptr;
	}

	inline void render_middle_column(float x, float y, float w, float h,
		const ::aida::skills::skill_metadata_t* meta,
		float ar, float ag, float ab, float alpha)
	{
		(void)ar; (void)ag; (void)ab;
		ImGui::SetCursorScreenPos(ImVec2(x, y));
		ImGui::BeginChild("##sm_detail_pane", ImVec2(w, h), false,
			ImGuiWindowFlags_NoBackground);
		auto* dl = ImGui::GetWindowDrawList();
		const ImVec2 cs = ImGui::GetCursorScreenPos();

		if (meta == nullptr) {
			ImU32 dim = IM_COL32(170, 175, 195, static_cast<int>(220 * alpha));
			dl->AddText(ImVec2(cs.x + 8.f, cs.y + 8.f), dim,
				"Select a skill from the list to view details.");
			ImGui::EndChild();
			return;
		}

		ImU32 fg = IM_COL32(232, 232, 248, static_cast<int>(245 * alpha));
		ImU32 dim = IM_COL32(170, 175, 195, static_cast<int>(220 * alpha));

		dl->AddText(ImVec2(cs.x + 8.f, cs.y + 4.f), fg, meta->name.c_str());
		const float line_h = ImGui::GetFontSize() + 4.f;
		dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
			ImVec2(cs.x + 8.f, cs.y + 4.f + line_h), dim,
			meta->description.c_str(), nullptr, w - 16.f);

		float cy = cs.y + 4.f + line_h * 3.f;
		std::string src = "Source: " + source_label(*meta);
		dl->AddText(ImVec2(cs.x + 8.f, cy), dim, src.c_str());
		cy += line_h;

		std::string fp = "Path: " + meta->file_path;
		dl->AddText(ImVec2(cs.x + 8.f, cy), dim, truncate_text(fp, 80).c_str());

		ImGui::SetCursorScreenPos(ImVec2(cs.x + 8.f, cy + line_h + 4.f));
		if (ImGui::SmallButton("Reveal in Explorer")) {
			open_path_in_shell(meta->file_path, true);
		}
		ImGui::SameLine(0.f, 6.f);
		if (ImGui::SmallButton("Open file")) {
			open_path_in_shell(meta->file_path, false);
		}
		ImGui::SameLine(0.f, 6.f);
		const bool en = ::aida::skills::is_enabled(meta->name);
		if (ImGui::SmallButton(en ? "Disable" : "Enable")) {
			::aida::skills::set_enabled(meta->name, !en);
		}

		ImGui::SetCursorScreenPos(ImVec2(cs.x + 8.f, cy + line_h * 2.5f + 4.f));
		dl->AddText(ImVec2(cs.x + 8.f, cy + line_h * 2.5f + 4.f), dim, "Agent slugs:");
		float chip_y = cy + line_h * 3.5f + 4.f;
		if (meta->agent_slugs.empty()) {
			dl->AddText(ImVec2(cs.x + 8.f, chip_y), dim, "(none, available to all primary agents)");
		} else {
			float chip_x = cs.x + 8.f;
			for (const auto& s : meta->agent_slugs) {
				render_chip(dl, chip_x, chip_y, s,
					IM_COL32(60, 70, 90, 200),
					IM_COL32(190, 210, 240, 240), alpha);
				ImVec2 ts = ImGui::CalcTextSize(s.c_str());
				chip_x += ts.x + 16.f;
				if (chip_x > cs.x + w - 60.f) {
					chip_x = cs.x + 8.f;
					chip_y += ImGui::GetFontSize() + 8.f;
				}
			}
		}

		const float ph_y = chip_y + ImGui::GetFontSize() + 14.f;
		dl->AddText(ImVec2(cs.x + 8.f, ph_y), dim, "Placeholder hints:");

		std::vector<std::string> hints;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			hints = state().cached_skill_hints;
		}
		float hx = cs.x + 8.f;
		float hy = ph_y + line_h;
		if (hints.empty()) {
			dl->AddText(ImVec2(hx, hy), dim, "(none)");
		} else {
			for (const auto& ph : hints) {
				render_chip(dl, hx, hy, ph,
					IM_COL32(40, 80, 60, 200),
					IM_COL32(180, 230, 200, 240), alpha);
				ImVec2 ts = ImGui::CalcTextSize(ph.c_str());
				hx += ts.x + 16.f;
				if (hx > cs.x + w - 60.f) {
					hx = cs.x + 8.f;
					hy += ImGui::GetFontSize() + 8.f;
				}
			}
		}

		ImGui::EndChild();
	}

	inline void render_right_column(float x, float y, float w, float h,
		const ::aida::skills::skill_metadata_t* meta,
		float ar, float ag, float ab, float alpha)
	{
		auto& st = state();
		ImGui::SetCursorScreenPos(ImVec2(x, y));
		ImGui::BeginChild("##sm_preview_pane", ImVec2(w, h), false,
			ImGuiWindowFlags_NoBackground);

		const ImVec2 cs = ImGui::GetCursorScreenPos();
		auto* dl = ImGui::GetWindowDrawList();
		ImU32 fg = IM_COL32(232, 232, 248, static_cast<int>(245 * alpha));
		dl->AddText(ImVec2(cs.x + 8.f, cs.y + 4.f), fg, "Preview");

		ImGui::SetCursorScreenPos(ImVec2(cs.x + w - 120.f, cs.y));
		ImGui::Checkbox("Render##sm_render_toggle", &st.preview_rendered);

		ImGui::SetCursorScreenPos(ImVec2(cs.x, cs.y + 26.f));
		ImGui::BeginChild("##sm_preview_scroll", ImVec2(w, h - 30.f), false,
			ImGuiWindowFlags_AlwaysVerticalScrollbar);

		if (meta == nullptr) {
			auto* dl2 = ImGui::GetWindowDrawList();
			const ImVec2 ic = ImGui::GetCursorScreenPos();
			ImU32 dim = IM_COL32(170, 175, 195, static_cast<int>(220 * alpha));
			dl2->AddText(ImVec2(ic.x + 8.f, ic.y + 8.f), dim,
				"Select a skill to preview its markdown.");
			ImGui::Dummy(ImVec2(w - 16.f, 32.f));
			ImGui::EndChild();
			ImGui::EndChild();
			return;
		}

		std::string body;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			body = state().cached_skill_body;
		}

		auto* idl = ImGui::GetWindowDrawList();
		const ImVec2 ic = ImGui::GetCursorScreenPos();
		const float wrap_w = w - 24.f;

		if (st.preview_rendered) {
			auto rr = chat_render::render_rich_message(idl,
				ImVec2(ic.x + 4.f, ic.y + 4.f), wrap_w, body,
				alpha, ar * 255.f, ag * 255.f, ab * 255.f, 0, ImGui::GetIO().DeltaTime, false);
			ImGui::Dummy(ImVec2(wrap_w, std::max(120.f, rr.height + 20.f)));
		} else {
			ImU32 mono_col = IM_COL32(220, 222, 240, static_cast<int>(235 * alpha));
			idl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
				ImVec2(ic.x + 4.f, ic.y + 4.f), mono_col,
				body.c_str(), nullptr, wrap_w);
			ImVec2 ts = ImGui::GetFont()->CalcTextSizeA(ImGui::GetFontSize(),
				FLT_MAX, wrap_w, body.c_str());
			ImGui::Dummy(ImVec2(wrap_w, std::max(120.f, ts.y + 20.f)));
		}

		ImGui::EndChild();
		ImGui::EndChild();
	}

	inline void render(float panel_w, float panel_h)
	{
		auto& st = state();
		if (!st.initialized) initialize();

		poll_pending_installs();
		poll_pending_remote_fetches();
		ensure_selected_cached();

		const float ar = globals::ui::accent.x;
		const float ag = globals::ui::accent.y;
		const float ab = globals::ui::accent.z;
		const float alpha = 1.0f;

		ImGui::BeginChild("##skill_manager_root", ImVec2(panel_w, panel_h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
			ImGuiWindowFlags_NoBackground);

		const ImVec2 wp = ImGui::GetWindowPos();
		const float root_x = wp.x;
		const float root_y = wp.y;
		const float root_w = panel_w;
		const float root_h = panel_h;

		const float toolbar_h = 32.f;
		const float pad = 8.f;
		render_toolbar(root_x, root_y, root_w, toolbar_h, ar, ag, ab, alpha);

		const float body_y = root_y + toolbar_h + 6.f;
		const float body_h = root_h - (toolbar_h + 8.f);

		const float left_w = std::max(260.f, root_w * st.list_split);
		const float right_w = std::max(280.f, root_w * st.detail_split);
		const float middle_w = std::max(220.f, root_w - left_w - right_w - pad * 2.f);

		render_left_column(root_x + pad, body_y, left_w, body_h, ar, ag, ab, alpha);

		std::vector<::aida::skills::skill_metadata_t> all_for_lookup = ::aida::skills::all();
		const ::aida::skills::skill_metadata_t* meta = nullptr;
		if (!st.selected_skill_name.empty()) {
			meta = find_meta_in_list(all_for_lookup, st.selected_skill_name);
		}

		const float middle_x = root_x + pad + left_w + pad;
		render_middle_column(middle_x, body_y, middle_w, body_h, meta, ar, ag, ab, alpha);

		const float right_x = middle_x + middle_w + pad;
		render_right_column(right_x, body_y, right_w, body_h, meta, ar, ag, ab, alpha);

		ImGui::EndChild();
	}


}
}
