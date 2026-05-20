#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "imgui/imgui.h"

#include "mcp_marketplace.hpp"
#include "../settings/standalone_settings.hpp"
#include "../ui/toast_notification.hpp"
#include "../ui/avatar.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/brand.hpp"
#include "../ui/clock.hpp"
#include "../ui/components.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"
#include "../ui/motion.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/theme.hpp"
#include "../ui/transition.hpp"


extern settings_sa_t g_sa_settings;


namespace aida::mcp_marketplace_view {


	// Categories removed -- search-only filtering (VSCode-style).


	struct card_anim_t
	{
		aida::ui::hover_state_t hover;
		aida::ui::transition_t  entrance;
	};


	struct view_state_t
	{
		std::mutex mtx;
		std::atomic<bool> open{false};
		std::atomic<bool> initialized{false};

		float open_anim = 0.f;
		float open_velocity = 0.f;

		char  search_buf[256] = {};
		std::vector<::mcp_marketplace::package_info_t> last_results;
		::mcp_marketplace::search_state_t last_search_state =
			::mcp_marketplace::search_state_t::idle;
		std::string last_search_error;

		std::string selected_pkg;
		bool detail_view_open = false;
		float detail_anim = 0.f;
		float detail_velocity = 0.f;

		std::unordered_map<std::string, card_anim_t> card_anims;
		std::deque<std::string> install_log;
		std::string installing_pkg;
		bool show_install_log = false;
		float install_log_anim = 0.f;

		double last_search_time = 0.0;
		std::string last_query_committed;
		bool first_search_done = false;
	};


	inline view_state_t& state()
	{
		static view_state_t s;
		return s;
	}


	inline void open()
	{
		auto& s = state();
		s.open.store(true);
		s.open_anim = 0.f;
		s.open_velocity = 0.f;
		if (!s.first_search_done) {
			s.first_search_done = true;
			::mcp_marketplace::search_async("server", ::mcp_marketplace::registry_t::npm);
		}
	}


	inline void close()
	{
		auto& s = state();
		s.open.store(false);
	}


	inline bool is_open()
	{
		return state().open.load();
	}


	inline void initialize()
	{
		auto& s = state();
		bool expected = false;
		if (!s.initialized.compare_exchange_strong(expected, true)) return;
	}


	inline void shutdown()
	{
		auto& s = state();
		s.initialized.store(false);
		s.open.store(false);
		s.card_anims.clear();
		s.install_log.clear();
	}


	inline std::string lower_copy(const std::string& s)
	{
		std::string out = s;
		std::transform(out.begin(), out.end(), out.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return out;
	}


	inline std::string truncate_text(const std::string& s, std::size_t max_len)
	{
		if (s.size() <= max_len) return s;
		return s.substr(0, max_len) + "...";
	}


	inline std::string format_count(int64_t v)
	{
		char buf[32];
		if (v >= 1000000) std::snprintf(buf, sizeof(buf), "%.1fM", v / 1000000.0);
		else if (v >= 1000) std::snprintf(buf, sizeof(buf), "%.1fK", v / 1000.0);
		else std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
		return std::string(buf);
	}


	inline bool is_pkg_installed(const std::string& name)
	{
		auto installed = ::mcp_marketplace::get_installed();
		for (const auto& s : installed)
			if (s.package_name == name) return true;
		return false;
	}


	// Category pills removed -- VSCode-style search-only filtering.


	inline void start_search()
	{
		auto& s = state();
		std::string q(s.search_buf);
		if (q.empty()) q = "server";
		s.last_query_committed = q;
		::mcp_marketplace::search_async(q, ::mcp_marketplace::registry_t::npm);
	}


	inline void render_hero_search(float ox, float oy, float w)
	{
		auto& s = state();
		const auto& th = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		(void)dl;

		ImGui::SetCursorScreenPos(ImVec2(ox, oy));
		char local[256];
		std::memcpy(local, s.search_buf, sizeof(local));
		bool changed = aida::ui::input_text("##mp_search", local, sizeof(local),
			"Search MCP servers...", false, ImVec2(w, 44.f));
		if (changed) {
			std::memcpy(s.search_buf, local, sizeof(s.search_buf));
		}
		bool committed = ImGui::IsItemDeactivatedAfterEdit() ||
			ImGui::IsKeyPressed(ImGuiKey_Enter, false);
		if (committed) start_search();

		ImGui::SetCursorScreenPos(ImVec2(ox + w + 12.f, oy + 6.f));
		bool searching = (s.last_search_state == ::mcp_marketplace::search_state_t::searching);
		if (aida::ui::button(searching ? "Searching" : "Search",
				aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md,
				ImVec2(120.f, 36.f),
				false, nullptr, searching)) {
			start_search();
		}

		(void)th;
	}


	inline void render_install_button(const ::mcp_marketplace::package_info_t& p, float bx, float by)
	{
		auto& s = state();
		bool installed = is_pkg_installed(p.name);
		bool installing = (s.installing_pkg == p.name) &&
			(::mcp_marketplace::get_install_state() == ::mcp_marketplace::install_state_t::installing);

		ImGui::SetCursorScreenPos(ImVec2(bx, by));
		if (installed) {
			aida::ui::button("Configured",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm,
				ImVec2(90.f, 26.f), true);
		} else {
			if (aida::ui::button(installing ? "Installing" : "Install",
					aida::ui::button_kind_t::primary,
					aida::ui::size_t_::sm,
					ImVec2(90.f, 26.f),
					false, nullptr, installing)) {
				if (!installing) {
					s.installing_pkg = p.name;
					s.show_install_log = true;
					s.install_log.clear();
					s.install_log.push_back("Installing " + p.name + "...");
					::mcp_marketplace::install_async(p);
				}
			}
		}
	}


	inline void render_card_glyph_ring(ImDrawList* dl, ImVec2 c, float radius,
		const std::string& seed, float alpha)
	{
		const auto& th = aida::ui::resolved();
		aida::ui::avatar::render(dl, c, radius, seed,
			aida::ui::avatar::kind_t::gradient, true, alpha,
			aida::ui::fonts::body_strong());
		(void)th;
	}


	// Featured cards removed -- all items render as list rows (VSCode-style).


	inline void render_list_row(float ox, float oy, float w,
		const ::mcp_marketplace::package_info_t& p, float dt)
	{
		auto& s = state();
		const auto& th = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();

		card_anim_t* ca = nullptr;
		{
			std::lock_guard<std::mutex> lk(s.mtx);
			ca = &s.card_anims[p.name];
		}

		// --- measure description height for dynamic row sizing ---
		const float icon_size = 36.f;
		const float row_pad_x = 14.f;
		const float row_pad_y = 10.f;
		const float text_x = ox + row_pad_x + icon_size + 12.f;
		const float btn_w = 90.f;
		const float right_margin = btn_w + 24.f;
		const float desc_wrap = w - (text_x - ox) - right_margin;

		const std::string& display = p.display_name.empty() ? p.name : p.display_name;
		const float name_h = 16.f;
		const float author_h = 14.f;

		// Compute wrapped description height.
		float desc_h = 0.f;
		if (!p.description.empty()) {
			ImFont* desc_font = aida::ui::fonts::body();
			ImVec2 desc_sz = desc_font->CalcTextSizeA(13.f, FLT_MAX, desc_wrap,
				p.description.c_str(), nullptr);
			desc_h = desc_sz.y;
		}

		const float row_h = row_pad_y * 2.f + name_h + 4.f + desc_h +
			(p.author.empty() ? 0.f : author_h + 2.f);
		const float min_h = icon_size + row_pad_y * 2.f;
		const float h = std::max(row_h, min_h);

		// --- hit test ---
		ImGui::PushID(p.name.c_str());
		ImGui::SetCursorScreenPos(ImVec2(ox, oy));
		ImGui::SetNextItemAllowOverlap();
		ImGui::InvisibleButton("##lr_hit", ImVec2(w, h));
		bool hov = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked();
		ImGui::PopID();

		float hov_v = ca->hover.tick(hov, dt, aida::motion::spring::balanced);

		ImVec2 a(ox, oy);
		ImVec2 b(ox + w, oy + h);

		// Hover highlight (subtle, no lift).
		if (hov_v > 0.01f) {
			ImU32 hov_fill = aida::ui::with_alpha(th.hover_wash, 0.55f * hov_v);
			dl->AddRectFilled(a, b, hov_fill, 6.f);
		}

		// Separator line at the bottom of each row.
		dl->AddLine(ImVec2(a.x + row_pad_x, b.y),
			ImVec2(b.x - row_pad_x, b.y),
			aida::ui::with_alpha(th.border_subtle, 0.35f), 1.f);

		// --- icon (avatar glyph, rounded-rect clipped) ---
		float icon_x = a.x + row_pad_x;
		float icon_cy = a.y + h * 0.5f;
		ImVec2 icon_tl(icon_x, icon_cy - icon_size * 0.5f);
		ImVec2 icon_br(icon_x + icon_size, icon_cy + icon_size * 0.5f);

		// Rounded-rect avatar background + initial.
		ImVec2 icon_c(icon_x + icon_size * 0.5f, icon_cy);
		aida::ui::avatar::render(dl, icon_c, icon_size * 0.5f, p.name,
			aida::ui::avatar::kind_t::gradient, false, 1.f,
			aida::ui::fonts::body_strong());

		// Round the corners by overlaying a rounded-rect clip border.
		dl->AddRect(icon_tl, icon_br,
			aida::ui::with_alpha(th.border_subtle, 0.5f), 8.f, 0, 1.f);

		// --- text block ---
		float ty = a.y + row_pad_y;

		// Package name (bold).
		dl->AddText(aida::ui::fonts::body_strong(), 14.f,
			ImVec2(text_x, ty), th.text_primary, display.c_str());

		// Author + downloads inline after name.
		{
			ImFont* name_font = aida::ui::fonts::body_strong();
			float name_w = name_font->CalcTextSizeA(14.f, FLT_MAX, 0.f, display.c_str()).x;
			float meta_x = text_x + name_w + 10.f;

			if (!p.author.empty()) {
				dl->AddText(aida::ui::fonts::caption(), 12.f,
					ImVec2(meta_x, ty + 2.f),
					aida::ui::with_alpha(th.text_dim, 0.85f),
					p.author.c_str());
				float author_w = aida::ui::fonts::caption()->CalcTextSizeA(
					12.f, FLT_MAX, 0.f, p.author.c_str()).x;
				meta_x += author_w + 10.f;
			}

			if (p.weekly_downloads > 0) {
				std::string dl_str = format_count(p.weekly_downloads) + " installs";
				dl->AddText(aida::ui::fonts::caption(), 12.f,
					ImVec2(meta_x, ty + 2.f),
					aida::ui::with_alpha(th.text_dim, 0.6f),
					dl_str.c_str());
			}
		}

		ty += name_h + 4.f;

		// Description (full text, wrapped).
		if (!p.description.empty()) {
			dl->AddText(aida::ui::fonts::body(), 13.f,
				ImVec2(text_x, ty),
				aida::ui::with_alpha(th.text_secondary, 0.9f),
				p.description.c_str(), nullptr, desc_wrap);
		}

		// --- install button (right-aligned, vertically centered) ---
		float btn_x = b.x - btn_w - row_pad_x;
		float btn_y = a.y + (h - 26.f) * 0.5f;
		render_install_button(p, btn_x, btn_y);

		// --- click to open detail ---
		if (clicked) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < btn_x - 4.f) {
				s.selected_pkg = p.name;
				s.detail_view_open = true;
			}
		}

		// Advance cursor past this row.
		ImGui::SetCursorScreenPos(ImVec2(ox, oy + h + 1.f));
		ImGui::Dummy(ImVec2(w, 0.f));
	}


	inline void render_detail_drawer(float ox, float oy, float w, float h,
		const ::mcp_marketplace::package_info_t& p)
	{
		auto& s = state();
		const auto& th = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();

		ImVec2 a(ox, oy);
		ImVec2 b(ox + w, oy + h);

		aida::ui::blur::layer_request_t br;
		br.pos = a;
		br.size = ImVec2(w, h);
		br.radius = 14.f;
		br.strength = 0.85f;
		br.alpha = 1.f;
		aida::ui::blur::schedule(br);

		aida::ui::blur::render_drop_shadow(dl, a, b, 14.f, 5, 0.40f, ImVec2(-3.f, 0.f));
		aida::ui::blur::render_glass_fill(dl, a, b, 14.f, 1.f);
		aida::ui::blur::render_glass_border(dl, a, b, 14.f, 1.f, 1.f);

		float pad = 18.f;
		ImVec2 av_c(a.x + pad + 28.f, a.y + pad + 28.f);
		render_card_glyph_ring(dl, av_c, 28.f, p.name, 1.f);

		dl->AddText(aida::ui::fonts::h2(), 18.f,
			ImVec2(a.x + pad + 70.f, a.y + pad),
			th.text_primary, (p.display_name.empty() ? p.name : p.display_name).c_str());
		dl->AddText(aida::ui::fonts::caption(), 13.f,
			ImVec2(a.x + pad + 70.f, a.y + pad + 22.f),
			aida::ui::with_alpha(th.text_dim, 1.f), p.name.c_str());

		ImGui::SetCursorScreenPos(ImVec2(b.x - pad - 32.f, a.y + pad - 4.f));
		if (aida::ui::button("X##close_det",
				aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::sm,
				ImVec2(32.f, 28.f))) {
			s.detail_view_open = false;
		}

		float content_y = a.y + pad + 80.f;
		float content_w = w - pad * 2.f;

		dl->AddText(aida::ui::fonts::body(), 14.f,
			ImVec2(a.x + pad, content_y), th.text_primary,
			p.description.c_str(), nullptr, content_w);

		float info_y = content_y + 100.f;
		ImGui::SetCursorScreenPos(ImVec2(a.x + pad, info_y));
		if (!p.version.empty()) {
			std::string vlbl = "v" + p.version;
			aida::ui::components::badge(vlbl.c_str(),
				aida::ui::with_alpha(th.info, 0.85f), 4.f);
			ImGui::SameLine(0.f, 8.f);
		}
		if (!p.author.empty()) {
			std::string albl = "by " + p.author;
			aida::ui::components::badge(albl.c_str(),
				aida::ui::with_alpha(th.text_secondary, 0.85f), 4.f);
			ImGui::SameLine(0.f, 8.f);
		}
		if (p.weekly_downloads > 0) {
			std::string dlbl = format_count(p.weekly_downloads) + "/wk";
			aida::ui::components::badge(dlbl.c_str(),
				aida::ui::with_alpha(th.success, 0.85f), 4.f);
		}

		if (!p.keywords_str.empty()) {
			float kw_y = info_y + 36.f;
			dl->AddText(aida::ui::fonts::body_em(), 14.f,
				ImVec2(a.x + pad, kw_y),
				aida::ui::with_alpha(th.text_secondary, 1.f), "Tags");
			float chip_x = a.x + pad;
			float chip_y = kw_y + 22.f;
			std::string keywords = p.keywords_str;
			std::string cur;
			for (char c : keywords) {
				if (c == ',') {
					if (!cur.empty()) {
						std::string trimmed = cur;
						while (!trimmed.empty() && trimmed.front() == ' ') trimmed.erase(trimmed.begin());
						while (!trimmed.empty() && trimmed.back() == ' ') trimmed.pop_back();
						if (!trimmed.empty()) {
							ImU32 ch_col = aida::ui::brand::hash_color(trimmed.c_str(), 0.6f);
							ImGui::SetCursorScreenPos(ImVec2(chip_x, chip_y));
							aida::ui::components::chip(trimmed.c_str(), ch_col, false);
							ImVec2 ts = ImGui::CalcTextSize(trimmed.c_str());
							chip_x += ts.x + 24.f;
							if (chip_x > b.x - pad - 80.f) {
								chip_x = a.x + pad;
								chip_y += 24.f;
							}
						}
					}
					cur.clear();
				} else cur.push_back(c);
			}
		}

		float btn_y = b.y - pad - 30.f;
		ImGui::SetCursorScreenPos(ImVec2(a.x + pad, btn_y));
		render_install_button(p, a.x + pad, btn_y);

		if (s.show_install_log && s.installing_pkg == p.name) {
			float log_y = btn_y - 140.f;
			float log_h = 130.f;
			ImVec2 lg_a(a.x + pad, log_y);
			ImVec2 lg_b(b.x - pad, log_y + log_h);
			dl->AddRectFilled(lg_a, lg_b,
				aida::ui::with_alpha(IM_COL32(0, 0, 0, 220), 1.f), 8.f);
			dl->AddRect(lg_a, lg_b, th.border_subtle, 8.f, 0, 1.f);
			std::deque<std::string> lines;
			{
				std::lock_guard<std::mutex> lk(s.mtx);
				lines = s.install_log;
			}
			float ly = lg_a.y + 6.f;
			for (const auto& ln : lines) {
				if (ly + 14.f > lg_b.y) break;
				dl->AddText(aida::ui::fonts::code(), 13.f, ImVec2(lg_a.x + 8.f, ly),
					aida::ui::with_alpha(aida::ui::resolved().success, 0.96f), ln.c_str());
				ly += 14.f;
			}

			if (::mcp_marketplace::get_install_state() ==
				::mcp_marketplace::install_state_t::installing) {
				float ring_x = lg_b.x - 28.f;
				float ring_y = lg_a.y + 14.f;
				aida::ui::brand::render_orbit_ring(dl, ImVec2(ring_x, ring_y), 9.f, 6,
					3.5f, th.accent_u32, 1.f);
			}
		}
	}


	inline void render_modal_if_open()
	{
		auto& s = state();
		const auto& th = aida::ui::resolved();
		const float dt = aida::ui::clock::dt();

		float target = s.open.load() ? 1.f : 0.f;
		s.open_anim = aida::motion::spring_step(s.open_anim, target, s.open_velocity,
			aida::motion::spring::balanced, dt);
		if (s.open_anim < 0.f) s.open_anim = 0.f;
		if (s.open_anim > 1.f) s.open_anim = 1.f;
		if (target > 0.5f && s.open_anim > 0.985f) s.open_anim = 1.f;
		if (target < 0.5f && s.open_anim < 0.015f) s.open_anim = 0.f;

		if (s.open_anim <= 0.001f && target <= 0.f) return;

		auto search_state_now = ::mcp_marketplace::get_search_state();
		if (search_state_now == ::mcp_marketplace::search_state_t::done &&
			s.last_search_state != ::mcp_marketplace::search_state_t::done) {
			s.last_results = ::mcp_marketplace::get_search_results();
		}
		if (search_state_now == ::mcp_marketplace::search_state_t::error_state) {
			std::string e = ::mcp_marketplace::get_search_error();
			if (!e.empty() && e != s.last_search_error) {
				s.last_search_error = e;
				toast_notification::push("Search error: " + truncate_text(e, 120),
					toast_notification::toast_type_t::error, 4.f);
			}
		}
		s.last_search_state = search_state_now;

		auto inst_state_now = ::mcp_marketplace::get_install_state();
		if (inst_state_now == ::mcp_marketplace::install_state_t::done &&
			!s.installing_pkg.empty()) {
			toast_notification::push("Installed: " + s.installing_pkg,
				toast_notification::toast_type_t::info, 3.5f);
			{
				std::lock_guard<std::mutex> lk(s.mtx);
				s.install_log.push_back("Done.");
			}
			s.installing_pkg.clear();
		} else if (inst_state_now == ::mcp_marketplace::install_state_t::error_state &&
			!s.installing_pkg.empty()) {
			std::string ie = ::mcp_marketplace::get_install_error();
			toast_notification::push("Install failed: " + truncate_text(ie, 120),
				toast_notification::toast_type_t::error, 5.f);
			{
				std::lock_guard<std::mutex> lk(s.mtx);
				s.install_log.push_back("Error: " + ie);
			}
			s.installing_pkg.clear();
		}

		ImVec2 display = ImGui::GetIO().DisplaySize;
		const float ease = aida::motion::ease::out_back(s.open_anim);
		const float pw = std::min(1080.f, display.x * 0.85f);
		const float ph = std::min(720.f, display.y * 0.85f);
		const float scale = 0.94f + 0.06f * ease;
		const float sw = pw * scale;
		const float sh = ph * scale;
		const float px = display.x * 0.5f - sw * 0.5f;
		const float py = display.y * 0.5f - sh * 0.5f - 24.f * (1.f - ease);
		const float alpha = s.open_anim;

		ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
		ImGui::SetNextWindowSize(display, ImGuiCond_Always);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(0, 0, 0, 0));
		if (ImGui::Begin("##mcp_market_blocker", nullptr,
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
			ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoScrollbar)) {
			ImGui::GetBackgroundDrawList()->AddRectFilled(ImVec2(0, 0), display,
				IM_COL32(0, 0, 0, static_cast<int>(140.f * alpha)));
			ImGui::InvisibleButton("##mcp_block", display);
			if (ImGui::IsItemClicked(ImGuiMouseButton_Left))
				close();
		}
		ImGui::End();
		ImGui::PopStyleColor();
		ImGui::PopStyleVar(2);

		ImGui::SetNextWindowPos(ImVec2(px, py), ImGuiCond_Always);
		ImGui::SetNextWindowSize(ImVec2(sw, sh), ImGuiCond_Always);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(0, 0, 0, 0));
		ImGui::SetNextWindowFocus();

		bool win_open = true;
		if (ImGui::Begin("##aida_mcp_marketplace", &win_open,
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking)) {

			ImDrawList* wdl = ImGui::GetWindowDrawList();

			ImVec2 panel_a(px, py);
			ImVec2 panel_b(px + sw, py + sh);

			aida::ui::blur::layer_request_t br;
			br.pos = panel_a;
			br.size = ImVec2(sw, sh);
			br.radius = 16.f;
			br.strength = 0.95f;
			br.alpha = alpha;
			aida::ui::blur::schedule(br);

			aida::ui::blur::render_drop_shadow(wdl, panel_a, panel_b, 16.f, 6, 0.45f * alpha,
				ImVec2(0.f, 12.f));
			aida::ui::blur::render_glass_fill(wdl, panel_a, panel_b, 16.f, alpha);
			aida::ui::blur::render_glass_border(wdl, panel_a, panel_b, 16.f, alpha, 1.f);

			ImU32 grad_top = aida::ui::with_alpha(th.accent_grad_top, alpha);
			ImU32 grad_bot = aida::ui::with_alpha(th.accent_grad_bot, alpha);
			wdl->AddRectFilledMultiColor(
				ImVec2(panel_a.x + 1.f, panel_a.y + 1.f),
				ImVec2(panel_b.x - 1.f, panel_a.y + 4.f),
				grad_top, grad_top, grad_bot, grad_bot);

			float pad = 22.f;
			wdl->AddText(aida::ui::fonts::display(), 24.f,
				ImVec2(panel_a.x + pad, panel_a.y + pad),
				aida::ui::with_alpha(th.text_primary, alpha), "MCP Marketplace");
			wdl->AddText(aida::ui::fonts::caption(), 14.f,
				ImVec2(panel_a.x + pad, panel_a.y + pad + 32.f),
				aida::ui::with_alpha(th.text_dim, alpha),
				"Discover and install Model Context Protocol servers from npm.");

			ImGui::SetCursorScreenPos(ImVec2(panel_b.x - pad - 36.f, panel_a.y + pad - 4.f));
			if (aida::ui::button("X##close_mp",
					aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::md,
					ImVec2(36.f, 32.f))) {
				close();
			}

			float search_y = panel_a.y + pad + 60.f;
			float search_w = sw - pad * 2.f - 132.f;
			render_hero_search(panel_a.x + pad, search_y, search_w);

			// Thin separator below search.
			float sep_y = search_y + 52.f;
			wdl->AddLine(ImVec2(panel_a.x + pad, sep_y),
				ImVec2(panel_b.x - pad, sep_y),
				aida::ui::with_alpha(th.border_subtle, 0.4f * alpha), 1.f);

			// Result count label.
			float count_y = sep_y + 6.f;
			if (!s.last_results.empty()) {
				char count_buf[64];
				std::snprintf(count_buf, sizeof(count_buf), "%d server%s",
					(int)s.last_results.size(),
					s.last_results.size() == 1 ? "" : "s");
				wdl->AddText(aida::ui::fonts::caption(), 12.f,
					ImVec2(panel_a.x + pad, count_y),
					aida::ui::with_alpha(th.text_dim, 0.7f * alpha),
					count_buf);
			}

			float content_y = count_y + 18.f;
			float content_h = panel_b.y - content_y - pad;
			float content_w = sw - pad * 2.f;

			ImGui::SetCursorScreenPos(ImVec2(panel_a.x + pad, content_y));
			ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
			ImGui::BeginChild("##mp_content", ImVec2(content_w, content_h), false,
				ImGuiWindowFlags_NoBackground);

			const auto& filtered = s.last_results;

			if (s.last_search_state == ::mcp_marketplace::search_state_t::searching &&
				s.last_results.empty()) {
				// Loading skeleton rows.
				ImVec2 sp = ImGui::GetCursorScreenPos();
				ImDrawList* sdl = ImGui::GetWindowDrawList();
				for (int i = 0; i < 6; ++i) {
					float row_h = 58.f;
					ImVec2 ka(sp.x, sp.y + i * (row_h + 1.f));
					ImVec2 kb(sp.x + content_w, ka.y + row_h);
					aida::ui::skeleton::render_card(sdl, ka, kb, 6.f, 1.5f);
				}
				ImGui::Dummy(ImVec2(content_w, 6 * 59.f));
			} else if (filtered.empty()) {
				ImVec2 region_pos = ImGui::GetCursorScreenPos();
				ImVec2 region_size(content_w, content_h);
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::dots;
				cfg.title = s.last_results.empty()
					? std::string("Search for MCP servers")
					: std::string("No matches");
				cfg.body = s.last_results.empty()
					? std::string("Type a query above to discover MCP servers from npm.")
					: std::string("No servers found for this query.");
				cfg.max_width = content_w * 0.7f;
				aida::ui::empty_state::render(region_pos, region_size, cfg);
			} else {
				// Clean list view -- one row per server.
				for (size_t i = 0; i < filtered.size(); ++i) {
					ImVec2 cp = ImGui::GetCursorScreenPos();
					render_list_row(cp.x, cp.y, content_w, filtered[i], dt);
				}
			}

			ImGui::EndChild();
			ImGui::PopStyleColor();

			if (s.detail_view_open && !s.selected_pkg.empty()) {
				const ::mcp_marketplace::package_info_t* pp = nullptr;
				for (const auto& p : s.last_results) {
					if (p.name == s.selected_pkg) { pp = &p; break; }
				}
				if (pp) {
					float dt_target = 1.f;
					s.detail_anim = aida::motion::spring_step(s.detail_anim, dt_target,
						s.detail_velocity, aida::motion::spring::balanced, dt);
					float drawer_w = std::min(420.f, sw * 0.42f);
					float drawer_x = panel_b.x - drawer_w * s.detail_anim;
					float drawer_y = panel_a.y;
					float drawer_h = sh;
					render_detail_drawer(drawer_x, drawer_y, drawer_w, drawer_h, *pp);
				} else {
					s.detail_view_open = false;
					s.selected_pkg.clear();
				}
			} else {
				s.detail_anim = aida::motion::spring_step(s.detail_anim, 0.f,
					s.detail_velocity, aida::motion::spring::balanced, dt);
			}
		}
		ImGui::End();
		ImGui::PopStyleColor();
		ImGui::PopStyleVar(2);

		if (s.open.load()) {
			if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
				if (s.detail_view_open) s.detail_view_open = false;
				else close();
			}
		}
	}


	inline void render(float panel_w, float panel_h)
	{
		(void)panel_w;
		(void)panel_h;
		render_modal_if_open();
	}


}
