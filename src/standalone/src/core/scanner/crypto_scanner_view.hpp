#pragma once

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "imgui.h"
#include "crypto_scanner.hpp"
#include "disasm_view.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"

extern DisasmState g_disasm;

namespace crypto_scanner_view {

struct state_t {
	float  scroll_y = 0.f;
	float  target_scroll_y = 0.f;
	bool   scrollbar_dragging = false;
	float  scrollbar_drag_offset = 0.f;
	int    category_filter = -1;
	char   search_filter[128] = {};
	int    sort_column = -1;
	bool   sort_ascending = true;
	int    ctx_hit_idx = -1;
	float  sort_arrow_anim = 0.f;
	int    last_sort_column = -1;
};

inline state_t g_state;

namespace detail {

inline ImU32 algo_color(crypto_scanner::crypto_category_t cat) {
	const auto& t = aida::ui::resolved();
	switch (cat) {
	case crypto_scanner::crypto_category_t::symmetric:    return t.info;
	case crypto_scanner::crypto_category_t::hash:         return t.success;
	case crypto_scanner::crypto_category_t::stream_cipher:return t.warning;
	case crypto_scanner::crypto_category_t::block_cipher: return t.accent_u32;
	case crypto_scanner::crypto_category_t::checksum:     return t.warning;
	case crypto_scanner::crypto_category_t::encoding:     return t.text_secondary;
	case crypto_scanner::crypto_category_t::asymmetric:   return t.error;
	default:                                              return t.text_secondary;
	}
}

inline aida::ui::components::pill_kind_t category_pill_kind(crypto_scanner::crypto_category_t cat) {
	switch (cat) {
	case crypto_scanner::crypto_category_t::symmetric:    return aida::ui::components::pill_kind_t::info;
	case crypto_scanner::crypto_category_t::hash:         return aida::ui::components::pill_kind_t::success;
	case crypto_scanner::crypto_category_t::stream_cipher:return aida::ui::components::pill_kind_t::warning;
	case crypto_scanner::crypto_category_t::block_cipher: return aida::ui::components::pill_kind_t::accent;
	case crypto_scanner::crypto_category_t::checksum:     return aida::ui::components::pill_kind_t::warning;
	case crypto_scanner::crypto_category_t::encoding:     return aida::ui::components::pill_kind_t::neutral;
	case crypto_scanner::crypto_category_t::asymmetric:   return aida::ui::components::pill_kind_t::error;
	default:                                              return aida::ui::components::pill_kind_t::neutral;
	}
}

enum class glyph_kind_t {
	aes_grid,
	sha_chain,
	rsa_keys,
	md_block,
	stream_flow,
	checksum_loop,
	encode_alpha,
	generic_hex
};

inline glyph_kind_t glyph_for(const std::string& algo, crypto_scanner::crypto_category_t cat) {
	std::string a;
	a.reserve(algo.size());
	for (char ch : algo) a.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
	if (a.find("aes") != std::string::npos)        return glyph_kind_t::aes_grid;
	if (a.find("sha") != std::string::npos)        return glyph_kind_t::sha_chain;
	if (a.find("rsa") != std::string::npos)        return glyph_kind_t::rsa_keys;
	if (a.find("ecc") != std::string::npos ||
	    a.find("ecdsa") != std::string::npos ||
	    a.find("dsa") != std::string::npos)        return glyph_kind_t::rsa_keys;
	if (a.find("md") != std::string::npos)         return glyph_kind_t::md_block;
	if (a.find("rc4") != std::string::npos ||
	    a.find("salsa") != std::string::npos ||
	    a.find("chacha") != std::string::npos)     return glyph_kind_t::stream_flow;
	if (a.find("crc") != std::string::npos)        return glyph_kind_t::checksum_loop;
	if (a.find("base") != std::string::npos)       return glyph_kind_t::encode_alpha;
	switch (cat) {
	case crypto_scanner::crypto_category_t::symmetric:
	case crypto_scanner::crypto_category_t::block_cipher: return glyph_kind_t::aes_grid;
	case crypto_scanner::crypto_category_t::hash:         return glyph_kind_t::sha_chain;
	case crypto_scanner::crypto_category_t::asymmetric:   return glyph_kind_t::rsa_keys;
	case crypto_scanner::crypto_category_t::stream_cipher:return glyph_kind_t::stream_flow;
	case crypto_scanner::crypto_category_t::checksum:     return glyph_kind_t::checksum_loop;
	case crypto_scanner::crypto_category_t::encoding:     return glyph_kind_t::encode_alpha;
	default: return glyph_kind_t::generic_hex;
	}
}

inline void glyph_aes(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float side = r * 1.6f;
	float cell = side / 4.f;
	ImVec2 a(c.x - side * 0.5f, c.y - side * 0.5f);
	float t = aida::ui::clock::seconds();
	for (int row = 0; row < 4; ++row) {
		for (int co = 0; co < 4; ++co) {
			float ph = sinf(t * 1.6f + (float)(row * 4 + co) * 0.4f) * 0.5f + 0.5f;
			ImU32 fill = aida::ui::with_alpha(col, 0.18f + ph * 0.30f);
			ImVec2 ca(a.x + cell * co + 1.f, a.y + cell * row + 1.f);
			ImVec2 cb(ca.x + cell - 2.f, ca.y + cell - 2.f);
			dl->AddRectFilled(ca, cb, fill, 1.5f);
		}
	}
	dl->AddRect(a, ImVec2(a.x + side, a.y + side),
		aida::ui::with_alpha(col, 0.7f), 2.f, 0, 1.f);
}

inline void glyph_sha(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float w = r * 1.8f;
	int n = 4;
	float gap = w / (float)(n + 1);
	float t = aida::ui::clock::seconds();
	for (int i = 0; i < n; ++i) {
		float lx = c.x - w * 0.5f + gap * (float)(i + 1);
		float ph = (float)i * 0.4f;
		float vy = sinf(t * 1.4f + ph) * 1.5f;
		dl->AddCircle(ImVec2(lx, c.y + vy), r * 0.32f,
			aida::ui::with_alpha(col, 0.85f), 18, 1.5f);
		if (i + 1 < n) {
			float lx2 = c.x - w * 0.5f + gap * (float)(i + 2);
			float vy2 = sinf(t * 1.4f + (float)(i + 1) * 0.4f) * 1.5f;
			dl->AddLine(
				ImVec2(lx + r * 0.32f, c.y + vy),
				ImVec2(lx2 - r * 0.32f, c.y + vy2),
				aida::ui::with_alpha(col, 0.6f), 1.5f);
		}
	}
}

inline void glyph_rsa(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float t = aida::ui::clock::seconds();
	float ang = sinf(t * 1.0f) * 0.12f;
	auto draw_key = [&](float ox, float angle_off) {
		float kr = r * 0.34f;
		ImVec2 head(c.x + ox, c.y - r * 0.18f);
		dl->AddCircle(head, kr, aida::ui::with_alpha(col, 0.85f), 20, 1.6f);
		float dx = sinf(angle_off) * 1.f;
		ImVec2 stem_a(head.x + dx, head.y + kr - 1.f);
		ImVec2 stem_b(head.x + dx, head.y + r * 1.05f);
		dl->AddLine(stem_a, stem_b, aida::ui::with_alpha(col, 0.85f), 1.5f);
		dl->AddLine(ImVec2(stem_b.x - 5.f, stem_b.y - 6.f), stem_b,
			aida::ui::with_alpha(col, 0.85f), 1.5f);
		dl->AddLine(ImVec2(stem_b.x + 5.f, stem_b.y - 12.f),
			ImVec2(stem_b.x, stem_b.y - 6.f),
			aida::ui::with_alpha(col, 0.85f), 1.5f);
	};
	draw_key(-r * 0.5f,  ang);
	draw_key( r * 0.5f, -ang);
}

inline void glyph_md(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float w = r * 1.4f;
	float h_each = (r * 1.6f) / 5.f;
	float t = aida::ui::clock::seconds();
	for (int i = 0; i < 5; ++i) {
		float y0 = c.y + r * 0.8f - h_each * (float)(i + 1);
		float y1 = y0 + h_each - 1.5f;
		float ph = sinf(t * 1.4f + (float)i * 0.55f) * 0.5f + 0.5f;
		ImU32 fill = aida::ui::with_alpha(col, 0.20f + ph * 0.45f);
		dl->AddRectFilled(ImVec2(c.x - w * 0.5f, y0),
			ImVec2(c.x + w * 0.5f, y1), fill, 2.f);
	}
}

inline void glyph_stream(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float t = aida::ui::clock::seconds();
	for (int i = 0; i < 3; ++i) {
		ImVec2 prev = ImVec2(c.x - r * 0.9f, c.y + (float)(i - 1) * r * 0.45f);
		for (int s = 1; s <= 16; ++s) {
			float fx = (float)s / 16.f;
			float wave = sinf(t * 2.f + fx * 7.5f + (float)i * 1.0f) * r * 0.18f;
			ImVec2 nx = ImVec2(c.x - r * 0.9f + fx * r * 1.8f,
			                   c.y + (float)(i - 1) * r * 0.45f + wave);
			dl->AddLine(prev, nx, aida::ui::with_alpha(col, 0.65f), 1.4f);
			prev = nx;
		}
	}
}

inline void glyph_checksum(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	float t = aida::ui::clock::seconds() * 1.6f;
	dl->AddCircle(c, r * 0.85f, aida::ui::with_alpha(col, 0.75f), 32, 1.5f);
	float arc_start = t;
	float arc_end = t + 1.4f;
	dl->PathArcTo(c, r * 0.85f, arc_start, arc_end, 24);
	dl->PathStroke(aida::ui::with_alpha(col, 1.f), 0, 2.f);
	float ax = c.x + cosf(arc_end) * r * 0.85f;
	float ay = c.y + sinf(arc_end) * r * 0.85f;
	dl->AddCircleFilled(ImVec2(ax, ay), 3.f, aida::ui::with_alpha(col, 1.f), 12);
}

inline void glyph_encode(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	const char* glyphs[3] = { "01", "AB", "+/" };
	float t = aida::ui::clock::seconds();
	int idx = ((int)floorf(t * 1.0f)) % 3;
	if (idx < 0) idx += 3;
	const char* lbl = glyphs[idx];
	dl->AddRectFilled(ImVec2(c.x - r * 0.7f, c.y - r * 0.5f),
		ImVec2(c.x + r * 0.7f, c.y + r * 0.5f),
		aida::ui::with_alpha(col, 0.18f), 4.f);
	dl->AddRect(ImVec2(c.x - r * 0.7f, c.y - r * 0.5f),
		ImVec2(c.x + r * 0.7f, c.y + r * 0.5f),
		aida::ui::with_alpha(col, 0.7f), 4.f, 0, 1.f);
	ImVec2 ts = ImGui::CalcTextSize(lbl);
	dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
		ImVec2(c.x - ts.x * 0.5f, c.y - ts.y * 0.5f),
		aida::ui::with_alpha(col, 1.f), lbl);
}

inline void glyph_hex(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
	dl->AddCircle(c, r * 0.7f, aida::ui::with_alpha(col, 0.7f), 24, 1.5f);
	dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
		ImVec2(c.x - 5.f, c.y - 5.f),
		aida::ui::with_alpha(col, 1.f), "??");
}

inline void render_glyph(ImDrawList* dl, ImVec2 center, float radius,
	const std::string& algo, crypto_scanner::crypto_category_t cat, ImU32 col)
{
	switch (glyph_for(algo, cat)) {
	case glyph_kind_t::aes_grid:      glyph_aes(dl, center, radius, col); break;
	case glyph_kind_t::sha_chain:     glyph_sha(dl, center, radius, col); break;
	case glyph_kind_t::rsa_keys:      glyph_rsa(dl, center, radius, col); break;
	case glyph_kind_t::md_block:      glyph_md(dl, center, radius, col); break;
	case glyph_kind_t::stream_flow:   glyph_stream(dl, center, radius, col); break;
	case glyph_kind_t::checksum_loop: glyph_checksum(dl, center, radius, col); break;
	case glyph_kind_t::encode_alpha:  glyph_encode(dl, center, radius, col); break;
	default:                          glyph_hex(dl, center, radius, col); break;
	}
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float, float, float)
{
	ImGui::BeginChild("##crypto_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = g_state;
	auto& cs = crypto_scanner::g_state;
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
		aida::ui::with_alpha(t.bg_base, alpha));

	float toolbar_h = 48.f;
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + toolbar_h),
		aida::ui::with_alpha(t.panel_header, alpha));
	dl->AddLine(ImVec2(ox, oy + toolbar_h), ImVec2(ox + width, oy + toolbar_h),
		aida::ui::with_alpha(t.border_subtle, alpha), 1.f);

	float cx = ox + 16.f;
	float cy = oy + (toolbar_h - 32.f) * 0.5f;

	dl->AddText(aida::ui::fonts::body_em(), 14.f,
		ImVec2(cx, oy + (toolbar_h - 14.f) * 0.5f),
		aida::ui::with_alpha(t.text_primary, alpha), "Crypto Scanner");
	cx += 140.f;

	bool scanning = cs.scanning.load();

	const float btn_gap = 14.f;
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		const char* lbl = scanning ? "Cancel" : "Scan Process";
		if (aida::ui::button(lbl,
				scanning ? aida::ui::button_kind_t::destructive : aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), false, nullptr, false)) {
			if (scanning) crypto_scanner::cancel();
			else          crypto_scanner::scan_process();
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool fl = !g_disasm.file.loaded;
		if (aida::ui::button("Scan File", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), scanning || fl)) {
			crypto_scanner::scan_file(g_disasm.file);
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Entropy", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), scanning)) {
			crypto_scanner::scan_entropy();
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("JSON", aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::md)) {
			char* appdata = nullptr;
			size_t len = 0;
			_dupenv_s(&appdata, &len, "APPDATA");
			if (appdata) {
				std::string path = std::string(appdata) + "\\AiDA\\Standalone\\crypto_export.json";
				free(appdata);
				crypto_scanner::export_results_json(path);
			}
		}
		cx = ImGui::GetItemRectMax().x + btn_gap;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("CSV", aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::md)) {
			char* appdata = nullptr;
			size_t len = 0;
			_dupenv_s(&appdata, &len, "APPDATA");
			if (appdata) {
				std::string path = std::string(appdata) + "\\AiDA\\Standalone\\crypto_export.csv";
				free(appdata);
				crypto_scanner::export_results_csv(path);
			}
		}
	}

	if (scanning) {
		float prog = cs.progress.load();
		float bar_w = 160.f;
		float bar_x = ox + width - bar_w - 16.f;
		float bar_y = oy + (toolbar_h - 6.f) * 0.5f;
		aida::ui::render_progress_bar(ImVec2(bar_x, bar_y), bar_w, 6.f, prog, false, true);
	}

	cy = oy + toolbar_h + 12.f;

	{
		ImGui::SetCursorScreenPos(ImVec2(ox + 16.f, cy));
		aida::ui::input_text("##crypto_filter", st.search_filter, sizeof(st.search_filter),
			"Filter algorithm, signature, module...", false, ImVec2(280.f, 32.f));

		const char* cats[] = {"All", "Symmetric", "Hash", "Stream Cipher", "Block Cipher", "Checksum", "Encoding", "Asymmetric"};
		ImGui::SetCursorScreenPos(ImVec2(ox + 16.f + 290.f, cy + 2.f));
		ImGui::PushItemWidth(160.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
		ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
		ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, alpha));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		int combo_sel = st.category_filter + 1;
		if (ImGui::Combo("##cat_combo", &combo_sel, cats, 8)) {
			st.category_filter = combo_sel - 1;
		}
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(4);
		ImGui::PopItemWidth();

		int total = 0, sym = 0, hash = 0, referenced = 0;
		{
			std::lock_guard<std::mutex> lk(cs.mutex);
			total = static_cast<int>(cs.results.size());
			for (auto& h : cs.results) {
				int cat = static_cast<int>(h.category);
				if (cat == 0 || cat == 3 || cat == 4) sym++;
				else if (cat == 1) hash++;
				if (!h.referencing_functions.empty()) referenced++;
			}
		}

		float pill_x = ox + 16.f + 290.f + 170.f + 20.f;
		float pill_y = cy + 6.f;
		auto chip = [&](const char* label, int n, aida::ui::components::pill_kind_t k) {
			char buf[48];
			snprintf(buf, sizeof(buf), "%s · %d", label, n);
			ImGui::SetCursorScreenPos(ImVec2(pill_x, pill_y));
			aida::ui::pill_kind(buf, k, aida::ui::size_t_::sm, true);
			pill_x = ImGui::GetItemRectMax().x + 12.f;
		};
		chip("hits", total, aida::ui::components::pill_kind_t::accent);
		chip("ciph", sym, aida::ui::components::pill_kind_t::info);
		chip("hash", hash, aida::ui::components::pill_kind_t::success);
		chip("refs", referenced, aida::ui::components::pill_kind_t::neutral);
	}

	cy += 44.f;

	std::vector<crypto_scanner::crypto_hit_t> filtered;
	{
		std::lock_guard<std::mutex> lk(cs.mutex);
		for (auto& hit : cs.results) {
			if (st.category_filter >= 0 && static_cast<int>(hit.category) != st.category_filter)
				continue;
			if (st.search_filter[0]) {
				std::string lower_name = hit.signature_name;
				std::string lower_algo = hit.algorithm;
				std::string lower_mod = hit.module_name;
				std::string lower_filter = st.search_filter;
				for (auto& c : lower_name) c = static_cast<char>(std::tolower(c));
				for (auto& c : lower_algo) c = static_cast<char>(std::tolower(c));
				for (auto& c : lower_mod) c = static_cast<char>(std::tolower(c));
				for (auto& c : lower_filter) c = static_cast<char>(std::tolower(c));
				if (lower_name.find(lower_filter) == std::string::npos &&
				    lower_algo.find(lower_filter) == std::string::npos &&
				    lower_mod.find(lower_filter) == std::string::npos)
					continue;
			}
			filtered.push_back(hit);
		}
	}

	if (st.sort_column >= 0) {
		std::sort(filtered.begin(), filtered.end(),
			[&](const crypto_scanner::crypto_hit_t& a, const crypto_scanner::crypto_hit_t& b) {
				int cmp = 0;
				switch (st.sort_column) {
				case 0: cmp = a.algorithm.compare(b.algorithm); break;
				case 1: cmp = a.signature_name.compare(b.signature_name); break;
				case 2: cmp = (a.address < b.address) ? -1 : (a.address > b.address ? 1 : 0); break;
				case 3: cmp = a.module_name.compare(b.module_name); break;
				default: break;
				}
				return st.sort_ascending ? (cmp < 0) : (cmp > 0);
			});
	}

	const float row_h = 30.f;
	const float table_top = cy;
	const float table_h = oy + height - cy - 8.f;
	const float col_widths[6] = { width * 0.18f, width * 0.18f, width * 0.14f, width * 0.22f, width * 0.14f, width * 0.12f };
	const char* col_names[6] = { "Algorithm", "Signature", "Address", "Module + Offset", "Category", "Refs" };

	float hdr_h = 28.f;
	dl->AddRectFilled(ImVec2(ox, cy),
		ImVec2(ox + width, cy + hdr_h),
		aida::ui::with_alpha(t.panel_header, alpha * 0.85f));
	dl->AddLine(ImVec2(ox, cy + hdr_h),
		ImVec2(ox + width, cy + hdr_h),
		aida::ui::with_alpha(t.border_subtle, alpha), 1.f);

	{
		float dt = aida::ui::clock::dt();
		if (st.last_sort_column != st.sort_column) {
			st.sort_arrow_anim = 0.f;
			st.last_sort_column = st.sort_column;
		}
		st.sort_arrow_anim = aida::motion::smooth_lerp(st.sort_arrow_anim, 1.f, 14.f, dt);
	}

	float hx = ox + 12.f;
	for (int c = 0; c < 6; ++c) {
		ImGui::PushID(c);
		ImGui::SetCursorScreenPos(ImVec2(hx, cy));
		ImGui::InvisibleButton("##hdr", ImVec2(col_widths[c] - 6.f, hdr_h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		if (clk && c < 4) {
			if (st.sort_column == c) st.sort_ascending = !st.sort_ascending;
			else { st.sort_column = c; st.sort_ascending = true; }
		}

		ImU32 lc = hov ? aida::ui::with_alpha(t.text_primary, alpha)
		               : aida::ui::with_alpha(t.text_dim, alpha);
		ImFont* hdr_fn = aida::ui::fonts::body();
		float hdr_fs = hdr_fn ? hdr_fn->FontSize : ImGui::GetFontSize();
		dl->AddText(hdr_fn, hdr_fs,
			ImVec2(hx + 4.f, cy + (hdr_h - hdr_fs) * 0.5f), lc, col_names[c]);
		ImVec2 ts = ImGui::CalcTextSize(col_names[c]);

		if (st.sort_column == c) {
			float aax = hx + 4.f + ts.x + 8.f;
			float aay = cy + hdr_h * 0.5f;
			float aw = 6.f;
			float pop = st.sort_arrow_anim * 3.f;
			if (st.sort_ascending) {
				dl->AddTriangleFilled(
					ImVec2(aax, aay - aw * 0.5f - pop),
					ImVec2(aax + aw, aay + aw * 0.5f - pop * 0.5f),
					ImVec2(aax - aw, aay + aw * 0.5f - pop * 0.5f),
					aida::ui::with_alpha(t.accent_u32, alpha));
			} else {
				dl->AddTriangleFilled(
					ImVec2(aax, aay + aw * 0.5f + pop),
					ImVec2(aax + aw, aay - aw * 0.5f + pop * 0.5f),
					ImVec2(aax - aw, aay - aw * 0.5f + pop * 0.5f),
					aida::ui::with_alpha(t.accent_u32, alpha));
			}
		}

		ImGui::PopID();
		hx += col_widths[c];
	}
	cy += hdr_h;

	float content_h = static_cast<float>(filtered.size()) * row_h;
	float visible_h = table_h - hdr_h - 36.f;

	float dt = aida::ui::clock::dt();
	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - visible_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, dt);

	ImGui::PushClipRect(ImVec2(ox, cy), ImVec2(ox + width - 14.f, cy + visible_h), true);

	int first_visible = static_cast<int>(st.scroll_y / row_h);
	int last_visible = first_visible + static_cast<int>(visible_h / row_h) + 2;
	if (first_visible < 0) first_visible = 0;
	if (last_visible > static_cast<int>(filtered.size())) last_visible = static_cast<int>(filtered.size());

	static float crypto_anim_time = 0.f;
	crypto_anim_time += dt;

	char addr_buf[32];
	char offset_buf[96];

	for (int i = first_visible; i < last_visible; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > cy + visible_h) continue;

		auto& hit = filtered[static_cast<size_t>(i)];
		ImVec2 row_min(ox, ry);
		ImVec2 row_max(ox + width - 14.f, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(row_min, row_max);
		float entrance = ui_anim::render_row_entrance(i - first_visible, crypto_anim_time, 0.012f);

		if (hovered) {
			dl->AddRectFilled(row_min, row_max,
				aida::ui::with_alpha(t.hover_wash, alpha * entrance));
		} else if (i & 1) {
			dl->AddRectFilled(row_min, row_max,
				aida::ui::with_alpha(IM_COL32(255, 255, 255, 4), alpha * entrance));
		}

		if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(hit.address, g_disasm);
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			st.ctx_hit_idx = i;
			ImGui::OpenPopup("##crypto_ctx");
		}

		float rx = ox + 12.f;
		ImU32 algo_col = aida::ui::with_alpha(detail::algo_color(hit.category), alpha * entrance);

		{
			float gr = 11.f;
			ImVec2 gctr(rx + gr + 2.f, ry + row_h * 0.5f);
			detail::render_glyph(dl, gctr, gr, hit.algorithm, hit.category, algo_col);
			dl->AddText(aida::ui::fonts::body_em(), 13.f,
				ImVec2(rx + 30.f, ry + (row_h - 13.f) * 0.5f),
				algo_col, hit.algorithm.c_str());
		}
		rx += col_widths[0];

		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, alpha * entrance), hit.signature_name.c_str());
		rx += col_widths[1];

		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(hit.address));
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, alpha * entrance), addr_buf);
		rx += col_widths[2];

		std::snprintf(offset_buf, sizeof(offset_buf), "%s+0x%llX",
		              hit.module_name.c_str(), static_cast<unsigned long long>(hit.module_offset));
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, alpha * entrance), offset_buf);
		rx += col_widths[3];

		ImGui::SetCursorScreenPos(ImVec2(rx, ry + (row_h - 18.f) * 0.5f));
		ImGui::PushID(i + 12345);
		aida::ui::pill_kind(crypto_scanner::category_name(hit.category),
			detail::category_pill_kind(hit.category),
			aida::ui::size_t_::sm, true);
		ImGui::PopID();
		rx += col_widths[4];

		if (!hit.referencing_functions.empty()) {
			char ref_buf[32];
			std::snprintf(ref_buf, sizeof(ref_buf), "%zu refs", hit.referencing_functions.size());
			dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
				ImVec2(rx, ry + (row_h - 11.f) * 0.5f),
				aida::ui::with_alpha(t.accent_u32, alpha * entrance), ref_buf);
		}
	}

	ImGui::PopClipRect();

	if (filtered.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::shield;
		cfg.title = "No crypto hits";
		cfg.body = scanning
			? "Scanning the target memory regions..."
			: "Run Scan Process or Scan File to detect cryptographic primitives.";
		aida::ui::empty_state::render(ImVec2(ox, cy), ImVec2(width, visible_h), cfg);
	} else if (scanning && filtered.size() < 4) {
		float sk_y = cy + static_cast<float>(filtered.size()) * row_h + 6.f;
		for (int s = 0; s < 5; ++s) {
			if (sk_y + 18.f > cy + visible_h) break;
			aida::ui::skeleton::render_block(dl,
				ImVec2(ox + 16.f, sk_y),
				ImVec2(ox + width - 28.f, sk_y + 16.f), 6.f, 1.4f);
			sk_y += 24.f;
		}
	}

	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 10.f);
	if (ImGui::BeginPopup("##crypto_ctx")) {
		if (st.ctx_hit_idx >= 0 && st.ctx_hit_idx < static_cast<int>(filtered.size())) {
			auto& ctx_hit = filtered[static_cast<size_t>(st.ctx_hit_idx)];

			if (ImGui::MenuItem("Go to Disassembly")) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(ctx_hit.address, g_disasm);
			}

			if (!ctx_hit.referencing_functions.empty()) {
				if (ImGui::BeginMenu("Show References")) {
					for (auto ref_addr : ctx_hit.referencing_functions) {
						char ref_label[64];
						std::snprintf(ref_label, sizeof(ref_label), "0x%llX", static_cast<unsigned long long>(ref_addr));
						auto lbl = crypto_scanner::get_function_label(ref_addr);
						std::string menu_text = ref_label;
						if (!lbl.empty()) menu_text += " (" + lbl + ")";
						if (ImGui::MenuItem(menu_text.c_str())) {
							globals::ui::active_center_view = center_view_t::disassembly;
							disasm_view::goto_address(ref_addr, g_disasm);
						}
					}
					ImGui::EndMenu();
				}
			}

			if (ImGui::MenuItem("Copy Address")) {
				char addr_copy[32];
				std::snprintf(addr_copy, sizeof(addr_copy), "0x%llX", static_cast<unsigned long long>(ctx_hit.address));
				ImGui::SetClipboardText(addr_copy);
			}
		}
		ImGui::EndPopup();
	}
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(3);

	{
		float footer_h = 26.f;
		float fy = oy + height - footer_h - 4.f;
		dl->AddRectFilled(ImVec2(ox + 8.f, fy), ImVec2(ox + width - 8.f, fy + footer_h),
			aida::ui::with_alpha(t.panel_bg, alpha * 0.6f), 6.f);
		char count_buf[160];
		std::lock_guard<std::mutex> lk(cs.mutex);
		size_t entropy_count = cs.entropy_map.size();
		if (entropy_count > 0) {
			std::snprintf(count_buf, sizeof(count_buf), "%zu results  ·  %zu entropy regions", filtered.size(), entropy_count);
		} else {
			std::snprintf(count_buf, sizeof(count_buf), "%zu results", filtered.size());
		}
		ImVec2 fts = ImGui::CalcTextSize(count_buf);
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(ox + width - fts.x - 18.f, fy + (footer_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha), count_buf);
	}

	if (content_h > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + width - 12.f, table_top + hdr_h,
		                                  8.f, visible_h, st.scroll_y, content_h, visible_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}
	ImGui::EndChild();
}

}
