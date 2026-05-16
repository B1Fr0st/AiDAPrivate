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
#include <unordered_map>
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

	struct row_anim_t
	{
		aida::ui::hover_state_t hover;
	};

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
		bool                                                       refreshing = false;
		std::unordered_map<std::string, row_anim_t>                row_anims;
		float                                                      tab_underline_x = 0.f;
		float                                                      tab_underline_w = 0.f;
		float                                                      tab_underline_target_x = 0.f;
		float                                                      tab_underline_target_w = 0.f;
		float                                                      tab_underline_vel_x = 0.f;
		float                                                      tab_underline_vel_w = 0.f;
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

	inline aida::ui::pill_kind_t source_pill_kind(const ::aida::skills::skill_metadata_t& m)
	{
		if (m.source == "remote") return aida::ui::pill_kind_t::accent;
		if (m.source == "global") return aida::ui::pill_kind_t::info;
		return aida::ui::pill_kind_t::success;
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
		s.row_anims.clear();
	}


	inline void render_toolbar(float root_x, float root_y, float root_w, float toolbar_h)
	{
		auto& st = state();
		const float pad = 10.f;
		const float search_w = std::max(220.f, (root_w - pad * 6.f) * 0.30f);
		ImGui::SetCursorScreenPos(ImVec2(root_x + pad, root_y + 2.f));
		char search_local[256];
		std::memcpy(search_local, st.search_buf, sizeof(search_local));
		if (aida::ui::input_text("##sm_search", search_local, sizeof(search_local),
				"Filter skills", false, ImVec2(search_w, 28.f))) {
			std::lock_guard<std::mutex> lk(state_mutex());
			std::memcpy(st.search_buf, search_local, sizeof(st.search_buf));
		}

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
		ImGui::SetCursorScreenPos(ImVec2(refresh_x, root_y + 2.f));
		bool refreshing_local = st.refreshing;
		if (aida::ui::button("Refresh##sm",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm,
				ImVec2(110.f, 28.f),
				false, nullptr, refreshing_local)) {
			st.refreshing = true;
			work_queue::post([]() {
				::aida::skills::reindex();
				{
					std::lock_guard<std::mutex> lk(state_mutex());
					state().last_indexed_unix = static_cast<int64_t>(std::time(nullptr));
					state().refreshing = false;
				}
				toast_notification::push("Skills re-indexed",
					toast_notification::toast_type_t::info, 2.5f);
			});
		}

		const float url_w = 280.f;
		const float url_x = root_x + root_w - pad - url_w - 80.f;
		ImGui::SetCursorScreenPos(ImVec2(url_x, root_y + 4.f));
		ImGui::PushItemWidth(url_w);
		ImGui::InputTextWithHint("##sm_add_url", "https://host/index.json",
			st.add_url_buf, sizeof(st.add_url_buf));
		ImGui::PopItemWidth();

		const float add_x = root_x + root_w - pad - 70.f;
		ImGui::SetCursorScreenPos(ImVec2(add_x, root_y + 2.f));
		if (aida::ui::button("Add URL##sm",
				aida::ui::button_kind_t::primary,
				aida::ui::size_t_::sm,
				ImVec2(70.f, 28.f))) {
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
	}

	inline void render_tab_strip(float x, float y, float w, float dt)
	{
		auto& st = state();
		const auto& th = aida::ui::resolved();
		const source_tab_t tabs[] = { source_tab_t::built_in, source_tab_t::project, source_tab_t::remote };
		const float btn_w = (w - 8.f) / 3.f;
		const float btn_h = 26.f;
		ImDrawList* dl = ImGui::GetWindowDrawList();

		ImVec2 strip_a(x, y);
		ImVec2 strip_b(x + w, y + btn_h);
		dl->AddRectFilled(strip_a, strip_b,
			aida::ui::with_alpha(th.panel_header, 0.45f), 8.f);

		float sel_x = x;
		float sel_w = btn_w;
		for (int i = 0; i < 3; ++i) {
			float bx = x + (btn_w + 4.f) * i;
			if (st.active_tab == tabs[i]) {
				sel_x = bx;
				sel_w = btn_w;
			}
		}
		st.tab_underline_target_x = sel_x;
		st.tab_underline_target_w = sel_w;

		if (st.tab_underline_w <= 0.001f) {
			st.tab_underline_x = sel_x;
			st.tab_underline_w = sel_w;
		} else {
			st.tab_underline_x = aida::motion::spring_step(st.tab_underline_x,
				st.tab_underline_target_x, st.tab_underline_vel_x,
				aida::motion::spring::balanced, dt);
			st.tab_underline_w = aida::motion::spring_step(st.tab_underline_w,
				st.tab_underline_target_w, st.tab_underline_vel_w,
				aida::motion::spring::balanced, dt);
		}

		ui_anim::render_tab_underline_glow(dl, st.tab_underline_x, st.tab_underline_w,
			y + btn_h - 3.f, 1.f);

		for (int i = 0; i < 3; ++i) {
			float bx = x + (btn_w + 4.f) * i;
			ImGui::SetCursorScreenPos(ImVec2(bx, y));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##tab_btn", ImVec2(btn_w, btn_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			ImGui::PopID();

			ImU32 text_col = (st.active_tab == tabs[i]) ? th.text_primary : th.text_secondary;
			if (hov) text_col = th.text_primary;
			ImFont* f = aida::ui::fonts::body_em();
			float fs = 14.f;
			ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0.f, tab_label(tabs[i]));
			dl->AddText(f, fs,
				ImVec2(bx + (btn_w - ts.x) * 0.5f, y + (btn_h - ts.y) * 0.5f),
				text_col, tab_label(tabs[i]));

			if (clicked) {
				st.active_tab = tabs[i];
				st.selected_skill_name.clear();
			}
		}
	}

	inline void render_skill_row(ImDrawList* dl, float x, float y, float w, float h,
		const ::aida::skills::skill_metadata_t& m, bool selected, bool enabled,
		float hov_v, float lift)
	{
		const auto& th = aida::ui::resolved();
		ImVec2 a(x, y - lift);
		ImVec2 b(x + w, y + h - lift);

		ImU32 row_bg;
		if (selected) {
			row_bg = aida::ui::with_alpha(th.selection, 0.85f);
		} else {
			row_bg = aida::ui::mix(
				aida::ui::with_alpha(th.panel_header, 0.5f),
				aida::ui::with_alpha(th.hover_wash, 1.f),
				hov_v * 0.65f);
		}
		dl->AddRectFilled(a, b, row_bg, 10.f);

		if (selected) {
			dl->AddRect(a, b, th.accent_u32, 10.f, 0, 1.5f);
		} else {
			dl->AddRect(a, b,
				aida::ui::with_alpha(th.border_subtle, 0.5f + 0.4f * hov_v),
				10.f, 0, 1.f);
		}

		if (hov_v > 0.05f) {
			float strength = 0.18f + hov_v * 0.22f;
			aida::ui::blur::render_drop_shadow(dl, a, b, 10.f, 4, strength,
				ImVec2(0.f, 3.f * hov_v));
		}

		const float av_r = 16.f;
		ImVec2 av_c(a.x + 14.f + av_r, (a.y + b.y) * 0.5f);
		aida::ui::avatar::render(dl, av_c, av_r, m.name,
			aida::ui::avatar::kind_t::gradient, true,
			enabled ? 1.f : 0.55f,
			aida::ui::fonts::body_strong());

		const float text_x = av_c.x + av_r + 12.f;
		ImU32 name_col = enabled
			? th.text_primary
			: aida::ui::with_alpha(th.text_dim, 0.85f);
		dl->AddText(aida::ui::fonts::body_strong(), 13.f,
			ImVec2(text_x, a.y + 8.f), name_col, m.name.c_str());

		std::string short_path = truncate_text(m.file_path, 60);
		dl->AddText(aida::ui::fonts::caption(), 13.f,
			ImVec2(text_x, a.y + 26.f),
			aida::ui::with_alpha(th.text_dim, 0.85f), short_path.c_str());

		if (m.source == "global") {
			ImGui::SetCursorScreenPos(ImVec2(text_x, a.y + 42.f));
			aida::ui::pill_kind("built-in", aida::ui::pill_kind_t::info,
				aida::ui::size_t_::sm, false);
		} else if (m.source == "remote") {
			ImGui::SetCursorScreenPos(ImVec2(text_x, a.y + 42.f));
			aida::ui::pill_kind("remote", aida::ui::pill_kind_t::accent,
				aida::ui::size_t_::sm, true);
		} else {
			ImGui::SetCursorScreenPos(ImVec2(text_x, a.y + 42.f));
			aida::ui::pill_kind("project", aida::ui::pill_kind_t::success,
				aida::ui::size_t_::sm, false);
		}

		float tog_x = b.x - 50.f;
		float tog_y = a.y + (h - 20.f) * 0.5f;
		ImGui::SetCursorScreenPos(ImVec2(tog_x, tog_y));
	}

	inline void render_left_column(float x, float y, float w, float h, float dt)
	{
		auto& st = state();
		const auto& th = aida::ui::resolved();
		ImGui::SetCursorScreenPos(ImVec2(x, y));
		render_tab_strip(x, y, w, dt);

		const float tab_h = 28.f;
		const float list_y = y + tab_h + 4.f;
		const bool remote_tab = (st.active_tab == source_tab_t::remote);
		const float remote_panel_h = remote_tab ? 180.f : 0.f;
		const float list_h = h - tab_h - 4.f - remote_panel_h - (remote_tab ? 6.f : 0.f);

		ImGui::SetCursorScreenPos(ImVec2(x, list_y));
		ImGui::BeginChild("##sm_list_scroll", ImVec2(w, list_h), false,
			ImGuiWindowFlags_NoBackground);

		const std::string filter_lower = lower_copy(std::string(st.search_buf));
		std::string agent_snapshot;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			agent_snapshot = st.agent_filter;
		}
		auto filtered = snapshot_filtered_for_view(st.active_tab, filter_lower, agent_snapshot);

		std::set<std::string> disabled_snapshot;
		{
			const auto disabled_list = ::aida::skills::list_disabled();
			for (const auto& n : disabled_list) disabled_snapshot.insert(n);
		}

		auto* dl = ImGui::GetWindowDrawList();
		const float row_h = 76.f;
		const float row_gap = 8.f;
		const float row_w = w - 16.f;

		if (filtered.empty()) {
			ImVec2 region_pos = ImGui::GetCursorScreenPos();
			ImVec2 region_size(row_w, list_h - 16.f);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::dots;
			cfg.title = "No skills here";
			cfg.body = "No skills matched in this category.";
			cfg.max_width = w * 0.85f;
			aida::ui::empty_state::render(region_pos, region_size, cfg);
		}

		for (const auto& m : filtered) {
			ImGui::Dummy(ImVec2(8.f, 0.f));
			ImGui::SameLine();
			const ImVec2 sp = ImGui::GetCursorScreenPos();
			const bool sel = (st.selected_skill_name == m.name);
			const bool en = (disabled_snapshot.count(m.name) == 0);

			row_anim_t* ra = nullptr;
			{
				std::lock_guard<std::mutex> lk(state_mutex());
				ra = &st.row_anims[m.name];
			}

			ImGui::PushID(m.name.c_str());
			ImGui::SetNextItemAllowOverlap();
			ImGui::InvisibleButton("##sm_row_btn", ImVec2(row_w, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool right   = ImGui::IsItemClicked(ImGuiMouseButton_Right);
			ImGui::PopID();

			float hov_v = ra->hover.tick(hov, dt, aida::motion::spring::playful);
			float lift = hov_v * 2.f;

			render_skill_row(dl, sp.x, sp.y, row_w, row_h, m, sel, en, hov_v, lift);

			float tog_x = sp.x + row_w - 50.f;
			float tog_y = sp.y + (row_h - 20.f) * 0.5f - lift;
			ImGui::SetCursorScreenPos(ImVec2(tog_x, tog_y));
			ImGui::PushID((std::string("tog_") + m.name).c_str());
			bool en_local = en;
			if (aida::ui::toggle_switch("##en", &en_local, aida::ui::size_t_::sm)) {
				::aida::skills::set_enabled(m.name, en_local);
			}
			ImGui::PopID();
			(void)th;

			const ImVec2 mp = ImGui::GetIO().MousePos;
			bool on_toggle = (mp.x >= tog_x - 4.f && mp.x <= tog_x + 38.f &&
				mp.y >= tog_y - 4.f && mp.y <= tog_y + 24.f);
			if (clicked && !on_toggle) {
				st.selected_skill_name = m.name;
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

			ImGui::SetCursorScreenPos(ImVec2(sp.x, sp.y + row_h + row_gap));
		}

		ImGui::EndChild();

		if (remote_tab) {
			const float rp_y = list_y + list_h + 6.f;
			ImGui::SetCursorScreenPos(ImVec2(x, rp_y));
			ImGui::BeginChild("##sm_remote_panel", ImVec2(w, remote_panel_h), false,
				ImGuiWindowFlags_NoBackground);

			ImDrawList* dl2 = ImGui::GetWindowDrawList();
			const ImVec2 rp = ImGui::GetCursorScreenPos();
			dl2->AddText(aida::ui::fonts::body_strong(), 13.f,
				ImVec2(rp.x + 8.f, rp.y + 4.f), th.text_primary, "Remote sources");

			ImGui::Dummy(ImVec2(0.f, 22.f));

			const auto urls = ::aida::skills::list_remote_urls();
			if (urls.empty()) {
				const ImVec2 cs = ImGui::GetCursorScreenPos();
				dl2->AddText(aida::ui::fonts::caption(), 14.f,
					ImVec2(cs.x + 8.f, cs.y + 4.f), th.text_dim,
					"No remote URLs registered. Use the toolbar above to add one.");
				ImGui::Dummy(ImVec2(w, 26.f));
			}

			for (const auto& u : urls) {
				ImGui::PushID(u.c_str());
				const ImVec2 cs = ImGui::GetCursorScreenPos();
				const float row_w_inner = w - 16.f;
				dl2->AddRectFilled(ImVec2(cs.x + 4.f, cs.y),
					ImVec2(cs.x + row_w_inner, cs.y + 24.f),
					aida::ui::with_alpha(th.panel_header, 0.7f), 6.f);
				dl2->AddText(aida::ui::fonts::caption(), 13.f,
					ImVec2(cs.x + 10.f, cs.y + 6.f),
					th.text_secondary, truncate_text(u, 80).c_str());

				ImGui::SetCursorScreenPos(ImVec2(cs.x + row_w_inner - 140.f, cs.y));
				if (aida::ui::button("Fetch",
						aida::ui::button_kind_t::secondary,
						aida::ui::size_t_::sm,
						ImVec2(60.f, 28.f))) {
					start_remote_fetch(u);
				}
				ImGui::SameLine(0.f, 4.f);
				if (aida::ui::button("Remove",
						aida::ui::button_kind_t::ghost,
						aida::ui::size_t_::sm,
						ImVec2(70.f, 28.f))) {
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
						dl2->AddText(aida::ui::fonts::caption(), 13.f,
							ImVec2(ec.x + 16.f, ec.y + 2.f),
							th.text_secondary, e.name.c_str());
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
							if (aida::ui::button("Install",
									aida::ui::button_kind_t::primary,
									aida::ui::size_t_::sm,
									ImVec2(74.f, 28.f))) {
								start_install(u, e.name);
							}
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
		const ::aida::skills::skill_metadata_t* meta, float alpha)
	{
		const auto& th = aida::ui::resolved();
		ImGui::SetCursorScreenPos(ImVec2(x, y));
		ImGui::BeginChild("##sm_detail_pane", ImVec2(w, h), false,
			ImGuiWindowFlags_NoBackground);
		auto* dl = ImGui::GetWindowDrawList();
		const ImVec2 cs = ImGui::GetCursorScreenPos();

		if (meta == nullptr) {
			ImVec2 region_pos = cs;
			ImVec2 region_size(w, h);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::dots;
			cfg.title = "Pick a skill";
			cfg.body = "Select a skill from the list to view its metadata, agent slugs and placeholder hints.";
			cfg.max_width = w * 0.8f;
			aida::ui::empty_state::render(region_pos, region_size, cfg);
			ImGui::EndChild();
			return;
		}

		const float av_r = 22.f;
		ImVec2 av_c(cs.x + 16.f + av_r, cs.y + 16.f + av_r);
		aida::ui::avatar::render(dl, av_c, av_r, meta->name,
			aida::ui::avatar::kind_t::gradient, true, alpha,
			aida::ui::fonts::body_strong());

		dl->AddText(aida::ui::fonts::h2(), 18.f,
			ImVec2(av_c.x + av_r + 14.f, cs.y + 12.f),
			th.text_primary, meta->name.c_str());

		ImGui::SetCursorScreenPos(ImVec2(av_c.x + av_r + 14.f, cs.y + 38.f));
		aida::ui::pill_kind(source_label(*meta).c_str(), source_pill_kind(*meta),
			aida::ui::size_t_::sm, true);

		const float content_y = cs.y + av_r * 2.f + 32.f;
		dl->AddText(aida::ui::fonts::body(), 13.f,
			ImVec2(cs.x + 12.f, content_y),
			th.text_secondary, meta->description.c_str(),
			nullptr, w - 24.f);

		float cy = content_y + 56.f;
		std::string fp = "Path: " + truncate_text(meta->file_path, 80);
		dl->AddText(aida::ui::fonts::caption(), 13.f,
			ImVec2(cs.x + 12.f, cy), th.text_dim, fp.c_str());

		ImGui::SetCursorScreenPos(ImVec2(cs.x + 12.f, cy + 22.f));
		if (aida::ui::button("Reveal",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm,
				ImVec2(96.f, 24.f))) {
			open_path_in_shell(meta->file_path, true);
		}
		ImGui::SameLine(0.f, 6.f);
		if (aida::ui::button("Open file",
				aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::sm,
				ImVec2(96.f, 24.f))) {
			open_path_in_shell(meta->file_path, false);
		}
		ImGui::SameLine(0.f, 6.f);
		const bool en = ::aida::skills::is_enabled(meta->name);
		if (aida::ui::button(en ? "Disable" : "Enable",
				en ? aida::ui::button_kind_t::ghost : aida::ui::button_kind_t::primary,
				aida::ui::size_t_::sm,
				ImVec2(96.f, 24.f))) {
			::aida::skills::set_enabled(meta->name, !en);
		}

		float chip_y = cy + 60.f;
		dl->AddText(aida::ui::fonts::body_em(), 14.f,
			ImVec2(cs.x + 12.f, chip_y), th.text_secondary, "Agent slugs:");
		chip_y += 22.f;
		if (meta->agent_slugs.empty()) {
			dl->AddText(aida::ui::fonts::caption(), 13.f,
				ImVec2(cs.x + 12.f, chip_y), th.text_dim,
				"(none, available to all primary agents)");
		} else {
			float cx = cs.x + 12.f;
			ImGui::SetCursorScreenPos(ImVec2(cx, chip_y));
			for (const auto& s : meta->agent_slugs) {
				ImU32 ch_col = aida::ui::brand::hash_color(s.c_str(), 0.6f);
				ImGui::SetCursorScreenPos(ImVec2(cx, chip_y));
				aida::ui::components::chip(s.c_str(), ch_col, false);
				ImVec2 ts = ImGui::CalcTextSize(s.c_str());
				cx += ts.x + 24.f;
				if (cx > cs.x + w - 60.f) {
					cx = cs.x + 12.f;
					chip_y += 24.f;
				}
			}
		}

		const float ph_y = chip_y + 36.f;
		dl->AddText(aida::ui::fonts::body_em(), 14.f,
			ImVec2(cs.x + 12.f, ph_y), th.text_secondary, "Placeholder hints:");

		std::vector<std::string> hints;
		{
			std::lock_guard<std::mutex> lk(state_mutex());
			hints = state().cached_skill_hints;
		}
		float hx = cs.x + 12.f;
		float hy = ph_y + 22.f;
		if (hints.empty()) {
			dl->AddText(aida::ui::fonts::caption(), 13.f,
				ImVec2(hx, hy), th.text_dim, "(none)");
		} else {
			for (const auto& ph : hints) {
				ImGui::SetCursorScreenPos(ImVec2(hx, hy));
				aida::ui::components::chip(ph.c_str(), th.success, false);
				ImVec2 ts = ImGui::CalcTextSize(ph.c_str());
				hx += ts.x + 24.f;
				if (hx > cs.x + w - 60.f) {
					hx = cs.x + 12.f;
					hy += 24.f;
				}
			}
		}

		ImGui::EndChild();
	}

	inline void render_right_column(float x, float y, float w, float h,
		const ::aida::skills::skill_metadata_t* meta, float alpha)
	{
		auto& st = state();
		const auto& th = aida::ui::resolved();
		ImGui::SetCursorScreenPos(ImVec2(x, y));
		ImGui::BeginChild("##sm_preview_pane", ImVec2(w, h), false,
			ImGuiWindowFlags_NoBackground);

		const ImVec2 cs = ImGui::GetCursorScreenPos();
		auto* dl = ImGui::GetWindowDrawList();
		dl->AddText(aida::ui::fonts::body_strong(), 13.f,
			ImVec2(cs.x + 8.f, cs.y + 4.f), th.text_primary, "Preview");

		ImGui::SetCursorScreenPos(ImVec2(cs.x + w - 110.f, cs.y));
		aida::ui::toggle_switch("Render##sm_render_toggle", &st.preview_rendered,
			aida::ui::size_t_::sm);

		ImGui::SetCursorScreenPos(ImVec2(cs.x, cs.y + 30.f));
		ImGui::BeginChild("##sm_preview_scroll", ImVec2(w, h - 34.f), false,
			ImGuiWindowFlags_AlwaysVerticalScrollbar);

		if (meta == nullptr) {
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

		float ar = globals::ui::accent.x;
		float ag = globals::ui::accent.y;
		float ab = globals::ui::accent.z;

		if (st.preview_rendered) {
			auto rr = chat_render::render_rich_message(idl,
				ImVec2(ic.x + 4.f, ic.y + 4.f), wrap_w, body,
				alpha, ar * 255.f, ag * 255.f, ab * 255.f, 0,
				ImGui::GetIO().DeltaTime, false);
			ImGui::Dummy(ImVec2(wrap_w, std::max(120.f, rr.height + 20.f)));
		} else {
			idl->AddText(aida::ui::fonts::code(), ImGui::GetFontSize(),
				ImVec2(ic.x + 4.f, ic.y + 4.f), th.text_primary,
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

		const float dt = aida::ui::clock::dt();
		const float alpha = 1.0f;

		ImGui::BeginChild("##skill_manager_root", ImVec2(panel_w, panel_h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
			ImGuiWindowFlags_NoBackground);

		const ImVec2 wp = ImGui::GetWindowPos();
		const float root_x = wp.x;
		const float root_y = wp.y;
		const float root_w = panel_w;
		const float root_h = panel_h;

		const float toolbar_h = 34.f;
		const float pad = 8.f;
		render_toolbar(root_x, root_y, root_w, toolbar_h);

		const float body_y = root_y + toolbar_h + 6.f;
		const float body_h = root_h - (toolbar_h + 8.f);

		const float left_w = std::max(280.f, root_w * st.list_split);
		const float right_w = std::max(300.f, root_w * st.detail_split);
		const float middle_w = std::max(220.f, root_w - left_w - right_w - pad * 2.f);

		render_left_column(root_x + pad, body_y, left_w, body_h, dt);

		std::vector<::aida::skills::skill_metadata_t> all_for_lookup = ::aida::skills::all();
		const ::aida::skills::skill_metadata_t* meta = nullptr;
		if (!st.selected_skill_name.empty()) {
			meta = find_meta_in_list(all_for_lookup, st.selected_skill_name);
		}

		const float middle_x = root_x + pad + left_w + pad;
		render_middle_column(middle_x, body_y, middle_w, body_h, meta, alpha);

		const float right_x = middle_x + middle_w + pad;
		render_right_column(right_x, body_y, right_w, body_h, meta, alpha);

		ImGui::EndChild();
	}


}
}
