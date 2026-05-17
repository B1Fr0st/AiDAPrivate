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


	enum class category_t : int
	{
		all = 0,
		database,
		web,
		ai,
		productivity,
		files,
		dev,
		other,
		count
	};


	inline const char* category_label(category_t c)
	{
		switch (c) {
		case category_t::all:           return "All";
		case category_t::database:      return "Database";
		case category_t::web:           return "Web";
		case category_t::ai:            return "AI";
		case category_t::productivity:  return "Productivity";
		case category_t::files:         return "Files";
		case category_t::dev:           return "Dev";
		case category_t::other:         return "Other";
		default: return "?";
		}
	}


	inline category_t classify_package(const ::mcp_marketplace::package_info_t& p)
	{
		std::string blob = p.name + " " + p.description + " " + p.keywords_str;
		std::transform(blob.begin(), blob.end(), blob.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		auto has = [&](const char* k) { return blob.find(k) != std::string::npos; };
		if (has("postgres") || has("mysql") || has("sqlite") || has("mongo") ||
			has("redis") || has("database") || has("sql ")) return category_t::database;
		if (has("http") || has("web") || has("browser") || has("fetch") ||
			has("scrape") || has("api ")) return category_t::web;
		if (has("openai") || has("claude") || has("anthropic") || has("gemini") ||
			has("llm") || has("embedding") || has("rag")) return category_t::ai;
		if (has("calendar") || has("email") || has("slack") || has("notion") ||
			has("trello") || has("jira") || has("ticket")) return category_t::productivity;
		if (has("filesystem") || has("file ") || has("path ") || has("directory") ||
			has("git ") || has("github")) return category_t::files;
		if (has("editor") || has("ide ") || has("debugger") || has("compile")) return category_t::dev;
		return category_t::other;
	}


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
		category_t active_category = category_t::all;
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


	inline void render_category_pills(float origin_x, float origin_y, float avail_w)
	{
		auto& s = state();
		const auto& th = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		(void)dl;

		float x = origin_x;
		float y = origin_y;
		const float gap = 8.f;
		const int n = static_cast<int>(category_t::count);
		for (int i = 0; i < n; ++i) {
			category_t c = static_cast<category_t>(i);
			const char* label = category_label(c);
			ImFont* font = aida::ui::fonts::body();
			float fs = 14.f;
			float text_w = font->CalcTextSizeA(fs, FLT_MAX, 0.f, label).x;
			float pill_w = text_w + 22.f;
			float pill_h = 24.f;
			if (x + pill_w > origin_x + avail_w) {
				x = origin_x;
				y += pill_h + gap;
			}
			ImGui::SetCursorScreenPos(ImVec2(x, y));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##cat", ImVec2(pill_w, pill_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			ImGui::PopID();

			ImVec2 a(x, y);
			ImVec2 b(x + pill_w, y + pill_h);
			bool active = (s.active_category == c);
			ImU32 fill = active
				? aida::ui::with_alpha(th.accent_u32, 0.95f)
				: hov
					? aida::ui::with_alpha(th.hover_wash, 1.f)
					: aida::ui::with_alpha(th.panel_header, 0.85f);
			ImU32 border = active
				? th.accent_u32
				: aida::ui::with_alpha(th.border_subtle, hov ? 1.f : 0.7f);
			ImU32 text_col = active ? IM_COL32(255, 255, 255, 245) : th.text_secondary;
			dl->AddRectFilled(a, b, fill, pill_h * 0.5f);
			dl->AddRect(a, b, border, pill_h * 0.5f, 0, 1.f);
			dl->AddText(font, fs, ImVec2(x + 11.f, y + (pill_h - fs) * 0.5f),
				text_col, label);

			if (clicked) s.active_category = c;
			x += pill_w + gap;
		}
	}


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
				ImVec2(120.f, 28.f), true);
		} else {
			if (aida::ui::button(installing ? "Installing" : "Install",
					aida::ui::button_kind_t::primary,
					aida::ui::size_t_::sm,
					ImVec2(120.f, 28.f),
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


	inline void render_featured_card(float ox, float oy, float w, float h,
		const ::mcp_marketplace::package_info_t& p, float dt)
	{
		auto& s = state();
		const auto& th = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();

		card_anim_t* ca = nullptr;
		{
			std::lock_guard<std::mutex> lk(s.mtx);
			ca = &s.card_anims[std::string("feat_") + p.name];
		}

		ImGui::PushID((std::string("feat_") + p.name).c_str());
		ImGui::SetCursorScreenPos(ImVec2(ox, oy));
		ImGui::InvisibleButton("##card", ImVec2(w, h));
		bool hov = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked();
		ImGui::PopID();

		float hov_v = ca->hover.tick(hov, dt, aida::motion::spring::playful);
		float lift = hov_v * 4.f;

		ImVec2 a(ox, oy - lift);
		ImVec2 b(ox + w, oy + h - lift);

		if (hov_v > 0.05f) {
			aida::ui::blur::render_drop_shadow(dl, a, b, 14.f, 5,
				0.32f * hov_v, ImVec2(0.f, 5.f * hov_v));
		}

		aida::ui::blur::layer_request_t br;
		br.pos = a;
		br.size = ImVec2(w, h);
		br.radius = 14.f;
		br.strength = 0.5f + 0.2f * hov_v;
		br.alpha = 1.f;
		aida::ui::blur::schedule(br);

		aida::ui::blur::render_glass_fill(dl, a, b, 14.f, 1.f);
		aida::ui::blur::render_glass_border(dl, a, b, 14.f, 1.f, 1.f);

		ImU32 grad_top = aida::ui::with_alpha(th.accent_grad_top, 0.18f * (0.4f + hov_v * 0.6f));
		ImU32 grad_bot = aida::ui::with_alpha(th.accent_grad_bot, 0.05f);
		ImU32 grad_flat = aida::ui::mix(grad_top, grad_bot, 0.5f);
		dl->AddRectFilled(a, b, grad_flat, 14.f);

		ImVec2 av_c(a.x + 22.f, a.y + 24.f);
		render_card_glyph_ring(dl, av_c, 16.f, p.name, 1.f);

		float text_x = a.x + 16.f;
		float text_y = a.y + 50.f;
		dl->AddText(aida::ui::fonts::body_strong(), 13.f,
			ImVec2(text_x, text_y), th.text_primary,
			truncate_text(p.display_name.empty() ? p.name : p.display_name, 24).c_str());
		dl->AddText(aida::ui::fonts::caption(), 13.f,
			ImVec2(text_x, text_y + 18.f),
			aida::ui::with_alpha(th.text_secondary, 0.95f),
			truncate_text(p.description, 64).c_str(),
			nullptr, w - 32.f);

		if (clicked) {
			s.selected_pkg = p.name;
			s.detail_view_open = true;
		}
	}


	inline void render_full_card(float ox, float oy, float w, float h,
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

		ImGui::PushID(p.name.c_str());
		ImGui::SetCursorScreenPos(ImVec2(ox, oy));
		ImGui::SetNextItemAllowOverlap();
		ImGui::InvisibleButton("##fc_hit", ImVec2(w, h));
		bool hov = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked();
		ImGui::PopID();

		float hov_v = ca->hover.tick(hov, dt, aida::motion::spring::playful);
		float lift = hov_v * 4.f;

		ImVec2 a(ox, oy - lift);
		ImVec2 b(ox + w, oy + h - lift);

		if (hov_v > 0.05f) {
			aida::ui::blur::render_drop_shadow(dl, a, b, 12.f, 5,
				0.30f * hov_v, ImVec2(0.f, 4.f * hov_v));
		}

		ImU32 fill = aida::ui::mix(
			aida::ui::with_alpha(th.panel_header, 0.85f),
			aida::ui::with_alpha(th.bg_elevated, 1.f),
			0.3f + hov_v * 0.3f);
		dl->AddRectFilled(a, b, fill, 12.f);
		dl->AddRect(a, b,
			aida::ui::with_alpha(th.border_subtle, 0.7f + 0.4f * hov_v), 12.f, 0, 1.f);

		const float av_r = 22.f;
		ImVec2 av_c(a.x + 18.f + av_r, (a.y + b.y) * 0.5f);
		render_card_glyph_ring(dl, av_c, av_r, p.name, 1.f);

		float text_x = av_c.x + av_r + 14.f;
		dl->AddText(aida::ui::fonts::body_strong(), 14.f,
			ImVec2(text_x, a.y + 12.f), th.text_primary,
			(p.display_name.empty() ? p.name : p.display_name).c_str());
		dl->AddText(aida::ui::fonts::caption(), 13.f,
			ImVec2(text_x, a.y + 32.f),
			aida::ui::with_alpha(th.text_dim, 0.9f), p.name.c_str());

		dl->AddText(aida::ui::fonts::body(), 14.f,
			ImVec2(text_x, a.y + 50.f),
			aida::ui::with_alpha(th.text_secondary, 0.95f),
			truncate_text(p.description, 120).c_str(),
			nullptr, w - (text_x - a.x) - 160.f);

		std::string dl_label = format_count(p.weekly_downloads) + "/wk";
		ImVec2 dl_pos(text_x, b.y - 26.f);
		ImGui::SetCursorScreenPos(dl_pos);
		aida::ui::components::badge(dl_label.c_str(),
			aida::ui::with_alpha(th.info, 0.85f), 4.f);

		if (!p.version.empty()) {
			ImGui::SameLine(0.f, 8.f);
			aida::ui::components::badge(p.version.c_str(),
				aida::ui::with_alpha(th.text_dim, 0.85f), 4.f);
		}

		float btn_x = b.x - 134.f;
		float btn_y = a.y + (h - 28.f) * 0.5f;
		render_install_button(p, btn_x, btn_y);

		if (clicked) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < btn_x - 4.f) {
				s.selected_pkg = p.name;
				s.detail_view_open = true;
			}
		}
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
			std::string albl = "by " + truncate_text(p.author, 18);
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

		ImGui::SetNextWindowPos(ImVec2(px, py), ImGuiCond_Always);
		ImGui::SetNextWindowSize(ImVec2(sw, sh), ImGuiCond_Always);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(0, 0, 0, 0));

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

			float cat_y = search_y + 60.f;
			render_category_pills(panel_a.x + pad, cat_y, sw - pad * 2.f);

			float content_y = cat_y + 50.f;
			float content_h = panel_b.y - content_y - pad;
			float content_w = sw - pad * 2.f;

			ImGui::SetCursorScreenPos(ImVec2(panel_a.x + pad, content_y));
			ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
			ImGui::BeginChild("##mp_content", ImVec2(content_w, content_h), false,
				ImGuiWindowFlags_NoBackground);

			std::vector<::mcp_marketplace::package_info_t> filtered;
			filtered.reserve(s.last_results.size());
			for (const auto& p : s.last_results) {
				if (s.active_category != category_t::all &&
					classify_package(p) != s.active_category) continue;
				filtered.push_back(p);
			}

			if (s.last_search_state == ::mcp_marketplace::search_state_t::searching &&
				s.last_results.empty()) {
				ImVec2 sp = ImGui::GetCursorScreenPos();
				ImDrawList* sdl = ImGui::GetWindowDrawList();
				for (int i = 0; i < 4; ++i) {
					float card_h = 96.f;
					ImVec2 ka(sp.x, sp.y + i * (card_h + 12.f));
					ImVec2 kb(sp.x + content_w - 16.f, ka.y + card_h);
					aida::ui::skeleton::render_card(sdl, ka, kb, 12.f, 1.5f);
				}
				ImGui::Dummy(ImVec2(content_w, 4 * 108.f));
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
					: std::string("No packages match the selected category.");
				cfg.max_width = content_w * 0.7f;
				aida::ui::empty_state::render(region_pos, region_size, cfg);
			} else {
				int featured_count = std::min((int)filtered.size(), 4);
				if (featured_count > 0) {
					ImVec2 fp = ImGui::GetCursorScreenPos();
					float fc_w = 220.f;
					float fc_h = 140.f;
					float fx = fp.x;
					for (int i = 0; i < featured_count; ++i) {
						render_featured_card(fx, fp.y, fc_w, fc_h, filtered[i], dt);
						fx += fc_w + 12.f;
						if (fx + fc_w > fp.x + content_w - 16.f) break;
					}
					ImGui::Dummy(ImVec2(content_w, fc_h + 16.f));
				}

				ImVec2 hdr_p = ImGui::GetCursorScreenPos();
				wdl->AddText(aida::ui::fonts::body_strong(), 13.f,
					hdr_p, aida::ui::with_alpha(th.text_primary, alpha),
					"All servers");
				ImGui::Dummy(ImVec2(content_w, 22.f));

				const float card_h = 88.f;
				const float card_gap = 10.f;
				for (size_t i = featured_count; i < filtered.size(); ++i) {
					ImVec2 cp = ImGui::GetCursorScreenPos();
					render_full_card(cp.x, cp.y, content_w - 16.f, card_h, filtered[i], dt);
					ImGui::Dummy(ImVec2(content_w, card_h + card_gap));
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
