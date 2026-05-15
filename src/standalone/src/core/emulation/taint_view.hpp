#pragma once

#include "symbolic_engine.hpp"
#include "work_queue.hpp"
#include "disasm_view.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "../ui/theme.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/brand.hpp"
#include "../ui/fonts.hpp"

extern DisasmState g_disasm;

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace taint_view {

struct taint_node_t {
	uint64_t address = 0;
	std::string disasm;
	std::vector<std::string> source_regs;
	std::vector<std::string> dest_regs;
	bool is_user_source = false;
	bool is_sink = false;
	bool is_propagation = false;
};

struct local_state_t {
	char addr_buf[64] = "0x";
	char end_addr_buf[64] = "";
	char taint_regs_buf[128] = "rcx";
	char taint_mem_buf[64] = "";
	int max_insns = 10000;
	int selected_row = -1;
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int view_mode = 0;
	aida::ui::transition_t mode_swap;
	int hovered_row = -1;
	std::unordered_map<int, aida::ui::flash_t> row_flashes;
	int scrub_position = 0;
	float scrub_anim_v = 0.f;
};

static local_state_t s_state;

namespace detail {

inline std::vector<std::string> parse_list(const char* buf) {
	std::vector<std::string> items;
	std::string s(buf);
	size_t pos = 0;
	while (pos < s.size()) {
		size_t comma = s.find(',', pos);
		if (comma == std::string::npos) comma = s.size();
		std::string item = s.substr(pos, comma - pos);
		while (!item.empty() && item.front() == ' ') item.erase(item.begin());
		while (!item.empty() && item.back() == ' ') item.pop_back();
		if (!item.empty()) items.push_back(item);
		pos = comma + 1;
	}
	return items;
}

inline std::string lower_copy(const std::string& s) {
	std::string out = s;
	std::transform(out.begin(), out.end(), out.begin(), ::tolower);
	return out;
}

inline void start_taint_trace(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);
	if (addr == 0) return;
	uint64_t end = st.end_addr_buf[0] ? std::strtoull(st.end_addr_buf, nullptr, 16) : 0;
	auto regs = parse_list(st.taint_regs_buf);

	std::vector<std::pair<uint64_t, uint32_t>> mem_ranges;
	if (st.taint_mem_buf[0]) {
		uint64_t mem_addr = std::strtoull(st.taint_mem_buf, nullptr, 16);
		if (mem_addr != 0) {
			mem_ranges.push_back({mem_addr, 64});
		}
	}

	if (symbolic_engine::g_state.processing.load()) return;
	symbolic_engine::g_state.processing.store(true);
	work_queue::post([addr, end, max_i = static_cast<uint32_t>(st.max_insns), regs, mem_ranges]() {
		symbolic_engine::taint_result_t result;
		try {
			result = symbolic_engine::taint_trace(addr, end, max_i, regs, mem_ranges);
		} catch (const std::exception& ex) {
			result.success = false;
			result.error = std::string("Taint trace aborted: ") + ex.what();
		} catch (...) {
			result.success = false;
			result.error = "Taint trace aborted by unknown exception";
		}
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_taint = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	});
}

inline std::vector<taint_node_t> build_taint_flow(const symbolic_engine::taint_result_t& res,
                                                   const std::vector<std::string>& source_regs) {
	std::vector<taint_node_t> nodes;
	std::unordered_set<std::string> source_set;
	for (auto& s : source_regs) source_set.insert(lower_copy(s));

	std::unordered_set<std::string> already_introduced;

	for (auto& insn : res.tainted_instructions) {
		taint_node_t node;
		node.address = insn.address;
		node.disasm = insn.disasm;
		node.source_regs = insn.read_regs;
		node.dest_regs = insn.written_regs;

		bool writes_a_user_source = false;
		bool first_introduction = false;
		for (auto& wr : insn.written_regs) {
			std::string lw = lower_copy(wr);
			if (source_set.count(lw)) {
				writes_a_user_source = true;
				if (!already_introduced.count(lw)) {
					first_introduction = true;
					already_introduced.insert(lw);
				}
			}
		}

		bool reads_from_tainted = false;
		for (auto& rd : insn.read_regs) {
			std::string lr = lower_copy(rd);
			if (source_set.count(lr) || already_introduced.count(lr)) {
				reads_from_tainted = true;
				break;
			}
		}

		if (first_introduction || (writes_a_user_source && reads_from_tainted == false)) {
			node.is_user_source = true;
		} else if (insn.written_regs.empty() && reads_from_tainted) {
			node.is_sink = true;
		} else {
			node.is_propagation = true;
		}

		for (auto& wr : insn.written_regs) {
			already_introduced.insert(lower_copy(wr));
		}

		nodes.push_back(std::move(node));
	}

	return nodes;
}

inline std::vector<int> downstream_of(const std::vector<taint_node_t>& nodes, int from_idx) {
	std::vector<int> hits;
	if (from_idx < 0 || from_idx >= static_cast<int>(nodes.size())) return hits;
	std::unordered_set<std::string> live;
	for (auto& wr : nodes[from_idx].dest_regs) live.insert(lower_copy(wr));
	if (live.empty()) {
		for (auto& rd : nodes[from_idx].source_regs) live.insert(lower_copy(rd));
	}

	for (int i = from_idx + 1; i < static_cast<int>(nodes.size()); ++i) {
		bool consumed = false;
		for (auto& rd : nodes[i].source_regs) {
			if (live.count(lower_copy(rd))) { consumed = true; break; }
		}
		if (consumed) {
			hits.push_back(i);
			for (auto& wr : nodes[i].dest_regs) live.insert(lower_copy(wr));
		} else if (!nodes[i].dest_regs.empty()) {
			for (auto& wr : nodes[i].dest_regs) {
				auto lw = lower_copy(wr);
				auto it = live.find(lw);
				if (it != live.end()) live.erase(it);
			}
			if (live.empty()) break;
		}
	}
	return hits;
}

inline ImU32 source_color(const aida::ui::theme_t& t)  { return t.info; }
inline ImU32 prop_color(const aida::ui::theme_t& t)    { return t.warning; }
inline ImU32 sink_color(const aida::ui::theme_t& t)    { return t.error; }

inline ImU32 type_color(const aida::ui::theme_t& t, const taint_node_t& n) {
	if (n.is_user_source) return source_color(t);
	if (n.is_sink) return sink_color(t);
	return prop_color(t);
}

inline const char* type_label(const taint_node_t& n) {
	if (n.is_user_source) return "SRC";
	if (n.is_sink) return "SINK";
	return "PROP";
}

inline std::string join_regs(const std::vector<std::string>& regs, size_t max_chars = 96) {
	std::string out;
	for (size_t i = 0; i < regs.size(); ++i) {
		if (i) out += ", ";
		out += regs[i];
		if (out.size() > max_chars) { out += "..."; break; }
	}
	return out;
}

inline void render_glass_panel(ImDrawList* dl, ImVec2 a, ImVec2 b, float radius,
                                float alpha, bool accent_border = false) {
	const auto& t = aida::ui::resolved();
	aida::ui::blur::render_drop_shadow(dl, a, b, radius, 4, 0.22f * alpha, ImVec2(0.f, 4.f));
	dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_bg, 0.92f * alpha), radius);
	dl->AddRectFilled(a, b, aida::ui::with_alpha(t.glass_tint, 0.55f * alpha), radius);
	ImU32 border_col = accent_border
		? aida::ui::with_alpha(t.accent_dim, 0.85f * alpha)
		: aida::ui::with_alpha(t.border_subtle, 1.f * alpha);
	dl->AddRect(a, b, border_col, radius, 0, 1.f);
}

inline void render_stat_chip(ImDrawList* dl, float x, float y, float w, float h,
                              const char* label, const char* value, ImU32 accent_token,
                              float alpha) {
	const auto& t = aida::ui::resolved();
	ImVec2 a(x, y);
	ImVec2 b(x + w, y + h);
	render_glass_panel(dl, a, b, 10.f, alpha);

	dl->AddRectFilled(ImVec2(a.x, a.y), ImVec2(a.x + 3.f, a.y + h),
		aida::ui::with_alpha(accent_token, 0.85f * alpha), 10.f);

	ImFont* lf = aida::ui::fonts::caption();
	ImFont* vf = aida::ui::fonts::body_strong();
	float lab_size = 11.f;
	float val_size = 18.f;
	dl->AddText(lf, lab_size, ImVec2(a.x + 12.f, a.y + 6.f),
		aida::ui::with_alpha(t.text_dim, alpha), label);
	dl->AddText(vf, val_size, ImVec2(a.x + 12.f, a.y + h - val_size - 4.f),
		aida::ui::with_alpha(t.text_primary, alpha), value);
}

inline ImVec2 cubic_bezier(ImVec2 p1, ImVec2 p2, ImVec2 p3, ImVec2 p4, float pt) {
	float u = 1.f - pt;
	float x = u*u*u*p1.x + 3.f*u*u*pt*p2.x + 3.f*u*pt*pt*p3.x + pt*pt*pt*p4.x;
	float y = u*u*u*p1.y + 3.f*u*u*pt*p2.y + 3.f*u*pt*pt*p3.y + pt*pt*pt*p4.y;
	return ImVec2(x, y);
}

inline void render_flow_edge(ImDrawList* dl, ImVec2 from, ImVec2 to, ImU32 col,
                              float alpha, float fan_offset = 0.f, bool reverse = false) {
	float dy = to.y - from.y;
	ImVec2 p1 = from;
	ImVec2 p2(from.x + fan_offset * 0.6f, from.y + dy * 0.32f);
	ImVec2 p3(to.x   - fan_offset * 0.6f, to.y   - dy * 0.32f);
	ImVec2 p4 = to;

	ImU32 glow = aida::ui::with_alpha(col, 0.18f * alpha);
	dl->AddBezierCubic(p1, p2, p3, p4, glow, 5.f);
	dl->AddBezierCubic(p1, p2, p3, p4, aida::ui::with_alpha(col, 0.85f * alpha), 1.6f);

	float seconds = aida::ui::clock::seconds();
	int dot_count = reverse ? 1 : 2;
	float speed = reverse ? 0.55f : 1.1f;
	for (int pi = 0; pi < dot_count; ++pi) {
		float pt = std::fmod(seconds * speed + static_cast<float>(pi) * 0.5f
			+ (fan_offset * 0.0021f), 1.f);
		if (reverse) pt = 1.f - pt;
		ImVec2 d = cubic_bezier(p1, p2, p3, p4, pt);
		float dot_a = std::sin(pt * 3.14159f);
		float head = reverse ? 1.5f : 2.4f;
		dl->AddCircleFilled(d, head, aida::ui::with_alpha(col, dot_a * alpha), 12);
		dl->AddCircleFilled(d, head + 2.f,
			aida::ui::with_alpha(col, dot_a * 0.25f * alpha), 12);
	}
}

inline void render_arrow_head(ImDrawList* dl, ImVec2 tip, ImU32 col, float alpha) {
	float arrow_sz = 5.f;
	dl->AddTriangleFilled(
		ImVec2(tip.x - arrow_sz, tip.y - arrow_sz - 1.f),
		ImVec2(tip.x + arrow_sz, tip.y - arrow_sz - 1.f),
		tip,
		aida::ui::with_alpha(col, alpha));
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)pos_x; (void)pos_y; (void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##taint_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float cx = wp.x;
	float cy = wp.y;

	float dt = aida::ui::clock::dt();
	const auto& t = aida::ui::resolved();

	const ImU32 src_col  = detail::source_color(t);
	const ImU32 prop_col = detail::prop_color(t);
	const ImU32 sink_col = detail::sink_color(t);

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height),
		aida::ui::with_alpha(t.bg_base, alpha));

	const float toolbar_h = 96.f;
	const float pad = 12.f;
	const float row_h = 22.f;

	ImVec2 toolbar_a(cx + 6.f, cy + 6.f);
	ImVec2 toolbar_b(cx + width - 6.f, cy + toolbar_h - 6.f);
	detail::render_glass_panel(dl, toolbar_a, toolbar_b, 12.f, alpha);

	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
	ImGui::PushStyleColor(ImGuiCol_Border,  aida::ui::with_alpha(t.border_subtle, alpha));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);

	float input_y = cy + 16.f;
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 8.f, input_y + 4.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_secondary, alpha));
	ImGui::TextUnformatted("Start");
	ImGui::PopStyleColor();

	ImGui::SameLine();
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 52.f, input_y));
	ImGui::SetNextItemWidth(120.f);
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
	ImGui::PushFont(aida::ui::fonts::code());
	ImGui::InputText("##taint_addr", st.addr_buf, sizeof(st.addr_buf));
	ImGui::PopFont();
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 184.f, input_y + 4.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_secondary, alpha));
	ImGui::TextUnformatted("End");
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 220.f, input_y));
	ImGui::SetNextItemWidth(120.f);
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
	ImGui::PushFont(aida::ui::fonts::code());
	ImGui::InputText("##taint_end", st.end_addr_buf, sizeof(st.end_addr_buf));
	ImGui::PopFont();
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 352.f, input_y + 4.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_secondary, alpha));
	ImGui::TextUnformatted("Taint");
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 398.f, input_y));
	ImGui::SetNextItemWidth(140.f);
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
	ImGui::PushFont(aida::ui::fonts::code());
	ImGui::InputText("##taint_regs", st.taint_regs_buf, sizeof(st.taint_regs_buf));
	ImGui::PopFont();
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 552.f, input_y + 4.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_secondary, alpha));
	ImGui::TextUnformatted("Mem");
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 590.f, input_y));
	ImGui::SetNextItemWidth(110.f);
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
	ImGui::PushFont(aida::ui::fonts::code());
	ImGui::InputText("##taint_mem", st.taint_mem_buf, sizeof(st.taint_mem_buf));
	ImGui::PopFont();
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 714.f, input_y + 4.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_secondary, alpha));
	ImGui::TextUnformatted("Max");
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 752.f, input_y + 2.f));
	ImGui::SetNextItemWidth(110.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, alpha));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::SliderInt("##taint_max", &st.max_insns, 100, 100000);
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(2);

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);

	float ctrl_y = cy + 54.f;
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 8.f, ctrl_y));

	bool busy = symbolic_engine::g_state.processing.load();

	if (aida::ui::components::button("Start Trace",
		busy ? aida::ui::components::button_kind_t::secondary
		     : aida::ui::components::button_kind_t::primary,
		aida::ui::components::size_t_::sm,
		ImVec2(118.f, 30.f), busy, nullptr, busy)) {
		if (!busy) detail::start_taint_trace(st);
	}

	const char* mode_labels[2] = { "Table", "Flow" };
	float mode_x = cx + pad + 8.f + 134.f;
	for (int i = 0; i < 2; ++i) {
		bool active = (st.view_mode == i);
		ImGui::SetCursorScreenPos(ImVec2(mode_x, ctrl_y));
		if (aida::ui::components::button(mode_labels[i],
			active ? aida::ui::components::button_kind_t::primary
			       : aida::ui::components::button_kind_t::ghost,
			aida::ui::components::size_t_::sm,
			ImVec2(86.f, 30.f))) {
			if (st.view_mode != i) {
				st.mode_swap.start(aida::motion::dur::md, aida::motion::ease::out_cubic);
				st.view_mode = i;
			}
		}
		mode_x += 96.f;
	}

	st.mode_swap.tick(dt);

	if (busy) {
		float pb_x = cx + pad + 8.f + 134.f + 96.f * 2.f + 24.f;
		float pb_y = ctrl_y + 9.f;
		uint32_t cur = symbolic_engine::g_state.progress_current.load();
		uint32_t tot = symbolic_engine::g_state.progress_total.load();
		float frac = (tot > 0) ? static_cast<float>(cur) / static_cast<float>(tot) : 0.f;
		aida::ui::components::render_progress_bar(ImVec2(pb_x, pb_y), 220.f, 12.f, frac,
			tot == 0, true);
	}

	float content_y = cy + toolbar_h + 6.f;
	float content_h = height - toolbar_h - 12.f;

	std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
	auto& res = symbolic_engine::g_state.last_taint;

	if (!res.success && !res.error.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::shield;
		cfg.title = "Taint trace failed";
		cfg.body  = res.error;
		aida::ui::empty_state::render(ImVec2(cx, content_y), ImVec2(width, content_h), cfg);
		ImGui::EndChild();
		return;
	}

	if (!res.success) {
		if (busy) {
			float skel_pad = 14.f;
			aida::ui::skeleton::render_table_rows(dl,
				ImVec2(cx + skel_pad, content_y + skel_pad),
				ImVec2(cx + width - skel_pad, content_y + content_h - skel_pad),
				5, 12, 24.f, 1.5f);
		} else {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::network;
			cfg.title = "No taint trace yet";
			cfg.body  = "Configure taint sources, then press Start Trace. Examples: registers like rcx, rdx, or memory like Mem 0x401000.";
			aida::ui::empty_state::render(ImVec2(cx, content_y), ImVec2(width, content_h), cfg);
		}
		ImGui::EndChild();
		return;
	}

	auto source_regs = detail::parse_list(st.taint_regs_buf);
	auto nodes = detail::build_taint_flow(res, source_regs);
	int total = static_cast<int>(nodes.size());

	float card_h = 56.f;
	float card_w = (width - pad * 2.f - 18.f) / 5.f;
	float card_y = content_y + 4.f;
	float card_x = cx + pad;

	uint32_t src_count = 0, prop_count = 0, sink_count = 0;
	for (auto& n : nodes) {
		if (n.is_user_source) ++src_count;
		else if (n.is_sink) ++sink_count;
		else ++prop_count;
	}

	char b1[16], b2[16], b3[16], b4[16], b5[16];
	std::snprintf(b1, sizeof(b1), "%u", res.total_processed);
	std::snprintf(b2, sizeof(b2), "%u", res.tainted_count);
	std::snprintf(b3, sizeof(b3), "%u", src_count);
	std::snprintf(b4, sizeof(b4), "%u", prop_count);
	std::snprintf(b5, sizeof(b5), "%u", sink_count);

	detail::render_stat_chip(dl, card_x, card_y, card_w, card_h, "Processed", b1, t.text_primary, alpha);
	card_x += card_w + 4.f;
	detail::render_stat_chip(dl, card_x, card_y, card_w, card_h, "Tainted", b2, t.accent_u32, alpha);
	card_x += card_w + 4.f;
	detail::render_stat_chip(dl, card_x, card_y, card_w, card_h, "Sources", b3, src_col, alpha);
	card_x += card_w + 4.f;
	detail::render_stat_chip(dl, card_x, card_y, card_w, card_h, "Propagation", b4, prop_col, alpha);
	card_x += card_w + 4.f;
	detail::render_stat_chip(dl, card_x, card_y, card_w, card_h, "Sinks", b5, sink_col, alpha);

	float scrub_y = card_y + card_h + 8.f;
	float scrub_h = 36.f;
	float scrub_x0 = cx + pad;
	float scrub_x1 = cx + width - pad;
	float scrub_w = scrub_x1 - scrub_x0;

	detail::render_glass_panel(dl, ImVec2(scrub_x0, scrub_y),
		ImVec2(scrub_x1, scrub_y + scrub_h), 10.f, alpha);

	ImGui::SetCursorScreenPos(ImVec2(scrub_x0, scrub_y));
	ImGui::InvisibleButton("##taint_scrub", ImVec2(scrub_w, scrub_h));
	bool scrub_hov = ImGui::IsItemHovered();
	bool scrub_act = ImGui::IsItemActive();

	if (total > 0) {
		float track_a_x = scrub_x0 + 14.f;
		float track_b_x = scrub_x1 - 14.f;
		float track_y = scrub_y + scrub_h * 0.5f;
		float track_w = track_b_x - track_a_x;

		dl->AddLine(ImVec2(track_a_x, track_y), ImVec2(track_b_x, track_y),
			aida::ui::with_alpha(t.border_strong, alpha), 2.f);

		for (int i = 0; i < total; ++i) {
			float fx = track_a_x + (static_cast<float>(i) / static_cast<float>(total - (total > 1 ? 1 : 0))) * track_w;
			ImU32 tick_col = detail::type_color(t, nodes[i]);
			float th = 5.f;
			dl->AddRectFilled(ImVec2(fx - 1.f, track_y - th * 0.5f),
				ImVec2(fx + 1.f, track_y + th * 0.5f),
				aida::ui::with_alpha(tick_col, 0.65f * alpha));
		}

		if (scrub_act) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			float rel = (mp.x - track_a_x) / track_w;
			if (rel < 0.f) rel = 0.f; if (rel > 1.f) rel = 1.f;
			st.scrub_position = static_cast<int>(rel * static_cast<float>((std::max)(1, total - 1)));
		}

		float scrub_target = (total > 1)
			? (static_cast<float>(st.scrub_position) / static_cast<float>(total - 1))
			: 0.f;
		st.scrub_anim_v = aida::motion::smooth_lerp(st.scrub_anim_v, scrub_target, 14.f, dt);

		float head_x = track_a_x + st.scrub_anim_v * track_w;
		dl->AddRectFilled(ImVec2(track_a_x, track_y - 1.f), ImVec2(head_x, track_y + 1.f),
			aida::ui::with_alpha(t.accent_u32, 0.95f * alpha));

		ImU32 head_glow = aida::ui::with_alpha(t.accent_glow, 0.6f * alpha);
		dl->AddCircleFilled(ImVec2(head_x, track_y), 9.f, head_glow, 24);
		dl->AddCircleFilled(ImVec2(head_x, track_y), 6.f, aida::ui::with_alpha(t.accent_u32, alpha), 16);
		dl->AddCircleFilled(ImVec2(head_x, track_y), 3.f,
			aida::ui::with_alpha(t.text_primary, 0.95f * alpha), 12);

		char scrub_lbl[64];
		std::snprintf(scrub_lbl, sizeof(scrub_lbl), "%d / %d", st.scrub_position + 1, total);
		ImVec2 lsz = ImGui::CalcTextSize(scrub_lbl);
		dl->AddText(aida::ui::fonts::caption(), 13.f,
			ImVec2(head_x - lsz.x * 0.5f, scrub_y + 4.f),
			aida::ui::with_alpha(t.text_dim, alpha), scrub_lbl);

		(void)scrub_hov;
	} else {
		ImVec2 lsz = ImGui::CalcTextSize("No tainted instructions");
		dl->AddText(ImVec2(scrub_x0 + (scrub_w - lsz.x) * 0.5f, scrub_y + (scrub_h - lsz.y) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha), "No tainted instructions");
	}

	float table_y = scrub_y + scrub_h + 8.f;
	float table_h = content_h - (table_y - content_y) - 4.f;
	if (table_h < 80.f) table_h = 80.f;

	ImGui::PushClipRect(ImVec2(cx, table_y), ImVec2(cx + width, table_y + table_h), true);

	auto draw_table_mode = [&]() {
		const aida::ui::theme_t& tt = aida::ui::resolved();
		const ImU32 row_even  = aida::ui::with_alpha(tt.panel_bg, 0.5f * alpha);
		const ImU32 row_odd   = aida::ui::with_alpha(tt.bg_elevated, 0.5f * alpha);
		const ImU32 row_hover = aida::ui::with_alpha(tt.hover_wash, alpha);
		const ImU32 sel_col   = aida::ui::with_alpha(tt.selection, alpha);

		float hdr_y = table_y;
		dl->AddRectFilled(ImVec2(cx + pad, hdr_y), ImVec2(cx + width - pad, hdr_y + row_h),
			aida::ui::with_alpha(tt.panel_header, 0.85f * alpha), 6.f);

		struct col_t { const char* label; float w; };
		col_t cols[] = {
			{ "Address",     130.f },
			{ "Instruction", 220.f },
			{ "Source Regs", 140.f },
			{ "Dest Regs",   140.f },
			{ "Type",         70.f }
		};
		float hx = cx + pad + 12.f;
		for (auto& c : cols) {
			dl->AddText(aida::ui::fonts::caption(), 13.f,
				ImVec2(hx, hdr_y + (row_h - 11.f) * 0.5f),
				aida::ui::with_alpha(tt.text_dim, alpha), c.label);
			hx += c.w;
		}

		float list_y = hdr_y + row_h + 2.f;
		float list_h = table_h - row_h - 4.f;
		int visible = static_cast<int>(list_h / row_h);

		ImGui::SetCursorScreenPos(ImVec2(cx, list_y));
		ImGui::InvisibleButton("##taint_scroll", ImVec2(width - 10.f, list_h));
		float max_scroll = (std::max)(0.f, static_cast<float>(total - visible) * row_h);
		if (ImGui::IsItemHovered())
			ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, max_scroll, row_h * 3.f);
		ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 15.f, dt);
		ui_anim::clamp_scroll(st.scroll_y, 0.f, max_scroll);
		ui_anim::clamp_scroll(st.target_scroll_y, 0.f, max_scroll);

		int start = static_cast<int>(st.scroll_y / row_h);
		if (start < 0) start = 0;

		std::unordered_set<int> downstream_set;
		if (st.hovered_row >= 0 && st.hovered_row < total) {
			auto hits = detail::downstream_of(nodes, st.hovered_row);
			for (int h : hits) downstream_set.insert(h);
		}

		int prev_hover = st.hovered_row;
		st.hovered_row = -1;

		static float row_acc = 0.f;
		row_acc += dt;

		for (int i = start; i < total && i < start + visible + 1; ++i) {
			auto& n = nodes[i];
			float ry = list_y + static_cast<float>(i - start) * row_h
				- (st.scroll_y - static_cast<float>(start) * row_h);
			if (ry + row_h < list_y || ry > list_y + list_h) continue;

			ImU32 rbg = (i % 2 == 0) ? row_even : row_odd;
			float row_t = ui_anim::render_row_entrance(i - start, row_acc, 0.012f);

			ImGui::SetCursorScreenPos(ImVec2(cx + pad, ry));
			ImGui::InvisibleButton(("##trow" + std::to_string(i)).c_str(),
				ImVec2(width - pad * 2.f, row_h));
			bool hovered = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);

			if (hovered) {
				st.hovered_row = i;
				rbg = row_hover;
			}
			if (clicked) st.selected_row = i;
			if (dbl) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(n.address, g_disasm);
			}

			auto& fl = st.row_flashes[i];
			float flash_v = fl.tick(dt, 2.6f);
			if (downstream_set.count(i)) flash_v = 1.f;

			if (i == st.selected_row) rbg = sel_col;

			dl->AddRectFilled(ImVec2(cx + pad, ry), ImVec2(cx + width - pad, ry + row_h),
				aida::ui::with_alpha(rbg, row_t), 6.f);

			if (i == st.selected_row) {
				dl->AddRectFilled(ImVec2(cx + pad, ry), ImVec2(cx + pad + 3.f, ry + row_h),
					aida::ui::with_alpha(tt.accent_u32, 0.85f * alpha * row_t), 6.f);
			}

			if (flash_v > 0.001f) {
				ImU32 fl_col = aida::ui::with_alpha(tt.accent_glow, flash_v * 0.55f * alpha);
				dl->AddRectFilled(ImVec2(cx + pad, ry), ImVec2(cx + width - pad, ry + row_h),
					fl_col, 6.f);
			}

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%llX",
				static_cast<unsigned long long>(n.address));

			float rx = cx + pad + 12.f;
			dl->AddText(aida::ui::fonts::code(), 13.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(tt.text_address, alpha * row_t), abuf);
			rx += cols[0].w;

			std::string disp = n.disasm;
			if (disp.size() > 36) disp = disp.substr(0, 33) + "...";
			dl->AddText(aida::ui::fonts::code(), 13.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(tt.text_primary, alpha * row_t), disp.c_str());
			rx += cols[1].w;

			std::string srcs = detail::join_regs(n.source_regs, 22);
			dl->AddText(aida::ui::fonts::code(), 13.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(tt.syn_type, alpha * row_t), srcs.c_str());
			rx += cols[2].w;

			std::string dsts = detail::join_regs(n.dest_regs, 22);
			dl->AddText(aida::ui::fonts::code(), 13.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(tt.syn_register, alpha * row_t), dsts.c_str());
			rx += cols[3].w;

			ImU32 tcol = detail::type_color(tt, n);
			ImGui::SetCursorScreenPos(ImVec2(rx, ry + 3.f));
			aida::ui::components::badge(detail::type_label(n),
				aida::ui::with_alpha(tcol, alpha * row_t), 4.f);
		}

		if (prev_hover != st.hovered_row && st.hovered_row >= 0) {
			auto hits = detail::downstream_of(nodes, st.hovered_row);
			for (int h : hits) st.row_flashes[h].trigger();
		}

		ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, list_y, 6.f, list_h,
			st.scroll_y, static_cast<float>(total) * row_h, list_h,
			alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	};

	auto draw_flow_mode = [&]() {
		const aida::ui::theme_t& tt = aida::ui::resolved();
		float node_w = (std::min)(360.f, width * 0.42f);
		float node_h = 30.f;
		float node_spacing = 18.f;
		float flow_x = cx + pad;
		float flow_y = table_y + 12.f;
		float flow_w = width - pad * 2.f;

		int max_vis = static_cast<int>((table_h - 24.f) / (node_h + node_spacing));
		if (max_vis < 1) max_vis = 1;

		int start = 0;
		float max_s = static_cast<float>((std::max)(0, total - max_vis)) * (node_h + node_spacing);

		ImGui::SetCursorScreenPos(ImVec2(cx, table_y));
		ImGui::InvisibleButton("##flow_scroll", ImVec2(width - 10.f, table_h));
		if (ImGui::IsItemHovered())
			ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, max_s, (node_h + node_spacing) * 3.f);
		ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 15.f, dt);
		ui_anim::clamp_scroll(st.scroll_y, 0.f, max_s);
		ui_anim::clamp_scroll(st.target_scroll_y, 0.f, max_s);

		if (total > max_vis) {
			start = static_cast<int>(st.scroll_y / (node_h + node_spacing));
			if (start < 0) start = 0;
			if (start > total - max_vis) start = total - max_vis;
		}

		std::unordered_set<int> hovered_downstream;
		if (st.hovered_row >= 0 && st.hovered_row < total) {
			auto hits = detail::downstream_of(nodes, st.hovered_row);
			for (int h : hits) hovered_downstream.insert(h);
		}

		st.hovered_row = -1;

		std::vector<ImVec2> centers(total, ImVec2(0.f, 0.f));
		std::vector<bool> visible_flag(total, false);

		for (int i = start; i < total && i < start + max_vis; ++i) {
			float ny = flow_y + static_cast<float>(i - start) * (node_h + node_spacing);
			float nx = flow_x + (flow_w - node_w) * 0.5f;
			centers[i] = ImVec2(nx + node_w * 0.5f, ny + node_h * 0.5f);
			visible_flag[i] = true;
		}

		auto find_consumer_indices = [&](int from_idx) -> std::vector<int> {
			std::vector<int> outs;
			if (nodes[from_idx].dest_regs.empty()) return outs;
			std::unordered_set<std::string> live;
			for (auto& wr : nodes[from_idx].dest_regs)
				live.insert(detail::lower_copy(wr));
			for (int j = from_idx + 1; j < total && j < from_idx + 8; ++j) {
				bool consumed = false;
				for (auto& rd : nodes[j].source_regs) {
					if (live.count(detail::lower_copy(rd))) { consumed = true; break; }
				}
				if (consumed) {
					outs.push_back(j);
					if (outs.size() >= 3) break;
				}
				bool overwrites = false;
				for (auto& wr : nodes[j].dest_regs) {
					if (live.count(detail::lower_copy(wr))) { overwrites = true; break; }
				}
				if (overwrites) break;
			}
			return outs;
		};

		for (int i = start; i < total && i < start + max_vis; ++i) {
			auto outs = find_consumer_indices(i);
			ImU32 ec = detail::type_color(tt, nodes[i]);
			ImVec2 from = ImVec2(centers[i].x, centers[i].y + node_h * 0.5f);
			int fan = static_cast<int>(outs.size());
			for (int oi = 0; oi < fan; ++oi) {
				int target_idx = outs[oi];
				if (target_idx >= total) continue;
				if (target_idx >= start + max_vis) continue;
				ImVec2 to;
				if (visible_flag[target_idx]) {
					to = ImVec2(centers[target_idx].x, centers[target_idx].y - node_h * 0.5f);
				} else {
					float ny = flow_y + static_cast<float>(target_idx - start) * (node_h + node_spacing);
					to = ImVec2(centers[i].x, ny);
				}
				float fan_off = (fan > 1)
					? (static_cast<float>(oi) - (static_cast<float>(fan - 1)) * 0.5f) * 60.f
					: 0.f;
				detail::render_flow_edge(dl, from, to, ec, alpha, fan_off, false);
				if (fan > 0 && hovered_downstream.count(target_idx)) {
					detail::render_flow_edge(dl, to, from, tt.accent_u32, alpha * 0.6f, fan_off, true);
				}
				detail::render_arrow_head(dl, to, ec, alpha);
			}
			if (outs.empty() && i + 1 < total && i + 1 < start + max_vis) {
				ImVec2 to = ImVec2(centers[i + 1].x, centers[i + 1].y - node_h * 0.5f);
				detail::render_flow_edge(dl, from, to,
					aida::ui::with_alpha(tt.text_dim, 0.6f * alpha), alpha, 0.f, false);
			}
		}

		static float entrance_acc = 0.f;
		entrance_acc += dt;

		for (int i = start; i < total && i < start + max_vis; ++i) {
			auto& n = nodes[i];
			float ny = flow_y + static_cast<float>(i - start) * (node_h + node_spacing);
			float nx = flow_x + (flow_w - node_w) * 0.5f;
			float row_t = ui_anim::render_row_entrance(i - start, entrance_acc, 0.012f);

			ImU32 col = detail::type_color(tt, n);

			ImGui::SetCursorScreenPos(ImVec2(nx, ny));
			ImGui::InvisibleButton(("##fnode" + std::to_string(i)).c_str(), ImVec2(node_w, node_h));
			bool hovered = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
			if (hovered) st.hovered_row = i;
			if (clicked) st.selected_row = i;
			if (dbl) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(n.address, g_disasm);
			}

			auto& fl = st.row_flashes[i];
			float flash_v = fl.tick(dt, 2.6f);
			if (hovered_downstream.count(i)) flash_v = 1.f;

			ImVec2 a(nx, ny);
			ImVec2 b(nx + node_w, ny + node_h);

			if (n.is_user_source || n.is_sink) {
				float pulse = aida::ui::clock::pulse(0.7f, 0.f, 1.f);
				ImU32 glow = aida::ui::with_alpha(col, 0.18f * alpha * (0.5f + 0.5f * pulse));
				dl->AddRectFilled(ImVec2(a.x - 4.f, a.y - 4.f),
					ImVec2(b.x + 4.f, b.y + 4.f), glow, 10.f);
			}

			detail::render_glass_panel(dl, a, b, 8.f, alpha * row_t);

			ImU32 border_col = aida::ui::with_alpha(col, hovered ? 0.95f * alpha : 0.8f * alpha);
			dl->AddRect(a, b, border_col, 8.f, 0, hovered ? 1.6f : 1.0f);

			if (flash_v > 0.001f) {
				dl->AddRect(ImVec2(a.x - 1.f, a.y - 1.f), ImVec2(b.x + 1.f, b.y + 1.f),
					aida::ui::with_alpha(tt.accent_u32, flash_v * alpha), 8.f, 0, 2.f);
			}

			ImGui::SetCursorScreenPos(ImVec2(a.x + 8.f, a.y + 6.f));
			aida::ui::components::badge(detail::type_label(n),
				aida::ui::with_alpha(col, alpha * row_t), 4.f);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%llX",
				static_cast<unsigned long long>(n.address));
			dl->AddText(aida::ui::fonts::code(), 13.f,
				ImVec2(a.x + 56.f, a.y + 6.f),
				aida::ui::with_alpha(tt.text_address, alpha * row_t), abuf);

			std::string disp = n.disasm;
			if (disp.size() > 28) disp = disp.substr(0, 25) + "...";
			dl->AddText(aida::ui::fonts::code(), 13.f,
				ImVec2(a.x + 56.f, a.y + 16.f),
				aida::ui::with_alpha(tt.text_primary, alpha * row_t), disp.c_str());

			std::string regs_text;
			if (!n.dest_regs.empty()) regs_text = detail::join_regs(n.dest_regs, 14);
			else regs_text = detail::join_regs(n.source_regs, 14);
			ImVec2 rsz = aida::ui::fonts::caption()->CalcTextSizeA(11.f, FLT_MAX, 0.f, regs_text.c_str());
			dl->AddText(aida::ui::fonts::caption(), 13.f,
				ImVec2(b.x - rsz.x - 10.f, a.y + (node_h - 11.f) * 0.5f),
				aida::ui::with_alpha(tt.text_dim, alpha * row_t), regs_text.c_str());
		}

		ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, table_y, 6.f, table_h,
			st.scroll_y, static_cast<float>(total) * (node_h + node_spacing), table_h,
			alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	};

	if (st.view_mode == 0) {
		draw_table_mode();
	} else {
		draw_flow_mode();
	}

	ImGui::PopClipRect();

	ImGui::EndChild();
}

}
