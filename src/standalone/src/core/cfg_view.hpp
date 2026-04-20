#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "imgui/imgui.h"
#include "cfg_layout.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "debugger_engine.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

namespace cfg_view {

struct instruction_line_t {
	uint64_t    addr = 0;
	std::string text;
};

struct basic_block_t {
	uint64_t                       start_addr = 0;
	uint64_t                       end_addr = 0;
	std::vector<instruction_line_t> instructions;
	std::vector<int>               successors;
	bool                           is_entry = false;
	bool                           has_breakpoint = false;
};

struct cfg_state_t {
	std::vector<basic_block_t> blocks;
	cfg_layout::graph_t        graph;
	uint64_t                   entry_addr = 0;
	bool                       built = false;
	uint64_t                   current_rip = 0;
	float                      pan_x = 0.f;
	float                      pan_y = 0.f;
	float                      target_pan_x = 0.f;
	float                      target_pan_y = 0.f;
	float                      zoom = 1.f;
	float                      target_zoom = 1.f;
	int                        selected_block = -1;
	std::mutex                 mutex;
	std::atomic<bool>          building{false};
	uint64_t                   navigate_to = 0;
};

inline cfg_state_t g_state;

inline void clear()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.blocks.clear();
	g_state.graph = {};
	g_state.entry_addr = 0;
	g_state.built = false;
	g_state.selected_block = -1;
	g_state.navigate_to = 0;
}

namespace detail {

inline int find_or_create_block(std::map<uint64_t, int>& addr_to_block,
								std::vector<basic_block_t>& blocks, uint64_t addr)
{
	auto it = addr_to_block.find(addr);
	if (it != addr_to_block.end())
		return it->second;
	int idx = static_cast<int>(blocks.size());
	blocks.emplace_back();
	blocks.back().start_addr = addr;
	addr_to_block[addr] = idx;
	return idx;
}

}

inline void build_cfg(uint64_t entry_address)
{
	if (g_state.building.load())
		return;

	g_state.building.store(true);

	std::thread([entry_address]() {
		const size_t max_bytes = 0x10000;
		const size_t max_insns = 4096;

		std::vector<uint8_t> mem;
		bool have_data = false;

		if (driver_bridge::attached_pid() != 0)
			have_data = driver_bridge::read_memory(entry_address, max_bytes, mem);

		if (!have_data || mem.empty()) {
			extern DisasmState g_disasm;
			have_data = static_analysis::read_bytes_from_pe(g_disasm.file, entry_address, max_bytes, mem);
		}

		if (mem.empty()) {
			g_state.building.store(false);
			return;
		}

		struct decoded_insn_t {
			AsmInstr    ins;
			uint64_t    branch_target = 0;
			bool        has_target = false;
		};

		std::vector<decoded_insn_t> all_insns;
		all_insns.reserve(max_insns);

		const uint8_t* data = mem.data();
		int sz = static_cast<int>(mem.size());
		int pos = 0;

		while (pos < sz && all_insns.size() < max_insns) {
			int avail = sz - pos;
			if (avail > 15) avail = 15;
			uint64_t va = entry_address + pos;
			AsmInstr ins = zydis_decode_one(data + pos, avail, va);

			decoded_insn_t d;
			d.ins = ins;

			if (ins.is_call || ins.is_branch) {
				if (ins.len == 5 && (data[pos] == 0xE8 || data[pos] == 0xE9)) {
					int32_t rel = 0;
					std::memcpy(&rel, data + pos + 1, 4);
					d.branch_target = va + ins.len + rel;
					d.has_target = true;
				} else if (ins.len == 2 && (data[pos] >= 0x70 && data[pos] <= 0x7F)) {
					int8_t rel = static_cast<int8_t>(data[pos + 1]);
					d.branch_target = va + ins.len + rel;
					d.has_target = true;
				} else if (ins.len == 6 && data[pos] == 0x0F && (data[pos+1] >= 0x80 && data[pos+1] <= 0x8F)) {
					int32_t rel = 0;
					std::memcpy(&rel, data + pos + 2, 4);
					d.branch_target = va + ins.len + rel;
					d.has_target = true;
				} else if (ins.len == 2 && data[pos] == 0xEB) {
					int8_t rel = static_cast<int8_t>(data[pos + 1]);
					d.branch_target = va + ins.len + rel;
					d.has_target = true;
				}
			}

			all_insns.push_back(d);

			if (ins.is_ret)
				break;

			pos += ins.len;
		}

		if (all_insns.empty()) {
			g_state.building.store(false);
			return;
		}

		std::map<uint64_t, bool> leaders;
		leaders[entry_address] = true;

		for (auto& d : all_insns) {
			if (d.has_target && !d.ins.is_call) {
				leaders[d.branch_target] = true;
				uint64_t fallthrough = d.ins.addr + d.ins.len;
				leaders[fallthrough] = true;
			}
			if (d.ins.is_ret) {
				uint64_t next = d.ins.addr + d.ins.len;
				leaders[next] = true;
			}
		}

		std::vector<basic_block_t> blocks;
		std::map<uint64_t, int> addr_to_block;

		int cur_block = -1;
		for (auto& d : all_insns) {
			if (leaders.count(d.ins.addr)) {
				cur_block = detail::find_or_create_block(addr_to_block, blocks, d.ins.addr);
				if (d.ins.addr == entry_address)
					blocks[cur_block].is_entry = true;
			}
			if (cur_block < 0)
				cur_block = detail::find_or_create_block(addr_to_block, blocks, d.ins.addr);

			instruction_line_t line;
			line.addr = d.ins.addr;
			char buf[192];
			snprintf(buf, sizeof(buf), "%s %s", d.ins.mnem, d.ins.ops);
			line.text = buf;
			blocks[cur_block].instructions.push_back(std::move(line));
			blocks[cur_block].end_addr = d.ins.addr + d.ins.len;

			if (d.ins.is_ret)
				continue;

			if (d.has_target && !d.ins.is_call) {
				auto it_target = addr_to_block.find(d.branch_target);
				if (it_target != addr_to_block.end())
					blocks[cur_block].successors.push_back(it_target->second);
				else {
					int tidx = detail::find_or_create_block(addr_to_block, blocks, d.branch_target);
					blocks[cur_block].successors.push_back(tidx);
				}

				bool is_unconditional = (std::strcmp(d.ins.mnem, "jmp") == 0 || std::strcmp(d.ins.mnem, "JMP") == 0);
				if (!is_unconditional) {
					uint64_t fall = d.ins.addr + d.ins.len;
					auto it_fall = addr_to_block.find(fall);
					if (it_fall != addr_to_block.end())
						blocks[cur_block].successors.push_back(it_fall->second);
					else {
						int fidx = detail::find_or_create_block(addr_to_block, blocks, fall);
						blocks[cur_block].successors.push_back(fidx);
					}
				}

				uint64_t next_addr = d.ins.addr + d.ins.len;
				if (leaders.count(next_addr)) {
					cur_block = -1;
				}
			}
		}

		{
			auto& bps = debugger_engine::g_state.breakpoints;
			std::lock_guard<std::mutex> bp_lk(debugger_engine::g_state.bp_mutex);
			for (auto& b : blocks) {
				for (auto& bp : bps) {
					if (bp.address >= b.start_addr && bp.address < b.end_addr) {
						b.has_breakpoint = true;
						break;
					}
				}
			}
		}

		float line_h = 14.f;
		float padding = 8.f;

		cfg_layout::graph_t graph;
		graph.nodes.reserve(blocks.size());
		for (int i = 0; i < static_cast<int>(blocks.size()); ++i) {
			cfg_layout::node_t n;
			n.id = i;
			n.width = 240.f;
			n.height = padding * 2.f + static_cast<float>(blocks[i].instructions.size()) * line_h;
			if (n.height < 30.f) n.height = 30.f;
			graph.nodes.push_back(n);
		}

		for (int i = 0; i < static_cast<int>(blocks.size()); ++i) {
			auto& succs = blocks[i].successors;
			for (int j = 0; j < static_cast<int>(succs.size()); ++j) {
				cfg_layout::edge_t e;
				e.from = i;
				e.to = succs[j];
				e.is_true_branch = (j == 0 && succs.size() > 1);
				graph.edges.push_back(e);
			}
		}

		cfg_layout::layout(graph, 60.f, 40.f);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.blocks = std::move(blocks);
			g_state.graph = std::move(graph);
			g_state.entry_addr = entry_address;
			g_state.built = true;
			g_state.selected_block = -1;
			g_state.pan_x = 0.f;
			g_state.pan_y = 0.f;
			g_state.target_pan_x = 0.f;
			g_state.target_pan_y = 0.f;
			g_state.zoom = 1.f;
			g_state.target_zoom = 1.f;
		}

		g_state.building.store(false);
	}).detach();
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 clip_min(pos_x, pos_y);
	ImVec2 clip_max(pos_x + width, pos_y + height);
	dl->PushClipRect(clip_min, clip_max, true);

	const auto& _t = themes::resolved;
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, alpha);
	};
	const ImU32 accent = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
								  static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	float dt = ImGui::GetIO().DeltaTime;

	dl->AddRectFilled(clip_min, clip_max, _ta(_t.bg_base));

	if (g_state.building.load()) {
		float cx = pos_x + width * 0.5f;
		float cy = pos_y + height * 0.5f;
		ui_anim::render_spinner(dl, cx, cy, 14.f, 2.5f, accent,
								static_cast<float>(ImGui::GetTime()));
		dl->AddText(ImVec2(cx - 40.f, cy + 22.f), _ta(_t.text_secondary), "Building CFG...");
		dl->PopClipRect();
		return;
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);

	if (!g_state.built || g_state.blocks.empty()) {
		ui_anim::render_empty_state(dl, pos_x, pos_y, width, height,
			"No CFG - select an address", accent_r, accent_g, accent_b, alpha,
			static_cast<float>(ImGui::GetTime()));
		dl->PopClipRect();
		return;
	}

	ImGuiIO& io = ImGui::GetIO();
	bool hovered = ImGui::IsMouseHoveringRect(clip_min, clip_max, false);

	if (hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.f)) {
		g_state.target_pan_x += io.MouseDelta.x / g_state.zoom;
		g_state.target_pan_y += io.MouseDelta.y / g_state.zoom;
	}

	if (hovered && io.MouseWheel != 0.f) {
		if (io.KeyCtrl) {
			float old_zoom = g_state.target_zoom;
			g_state.target_zoom *= (io.MouseWheel > 0) ? 1.1f : 0.9f;
			if (g_state.target_zoom < 0.1f) g_state.target_zoom = 0.1f;
			if (g_state.target_zoom > 5.f) g_state.target_zoom = 5.f;

			float mx = io.MousePos.x - pos_x - width * 0.5f;
			float my = io.MousePos.y - pos_y - height * 0.5f;
			float scale_change = g_state.target_zoom / old_zoom;
			g_state.target_pan_x -= mx * (1.f - 1.f / scale_change) / g_state.target_zoom;
			g_state.target_pan_y -= my * (1.f - 1.f / scale_change) / g_state.target_zoom;
		} else {
			g_state.target_pan_y += io.MouseWheel * 40.f / g_state.zoom;
		}
	}

	g_state.pan_x = ui_anim::smooth_lerp(g_state.pan_x, g_state.target_pan_x, 12.f, dt);
	g_state.pan_y = ui_anim::smooth_lerp(g_state.pan_y, g_state.target_pan_y, 12.f, dt);
	g_state.zoom = ui_anim::smooth_lerp(g_state.zoom, g_state.target_zoom, 12.f, dt);

	float center_x = pos_x + width * 0.5f;
	float center_y = pos_y + height * 0.5f;
	float z = g_state.zoom;

	auto world_to_screen = [&](float wx, float wy) -> ImVec2 {
		return ImVec2(center_x + (wx + g_state.pan_x) * z,
					  center_y + (wy + g_state.pan_y) * z);
	};

	auto& nodes = g_state.graph.nodes;
	auto& edges = g_state.graph.edges;
	auto& blocks = g_state.blocks;

	int ar = static_cast<int>(accent_r * 255);
	int ag = static_cast<int>(accent_g * 255);
	int ab = static_cast<int>(accent_b * 255);

	for (auto& e : edges) {
		int from_idx = -1, to_idx = -1;
		for (int i = 0; i < static_cast<int>(nodes.size()); ++i) {
			if (nodes[i].id == e.from) from_idx = i;
			if (nodes[i].id == e.to) to_idx = i;
		}
		if (from_idx < 0 || to_idx < 0) continue;

		auto& fn = nodes[from_idx];
		auto& tn = nodes[to_idx];

		ImVec2 p1 = world_to_screen(fn.x, fn.y + fn.height);
		ImVec2 p4 = world_to_screen(tn.x, tn.y);
		float mid_y = (p1.y + p4.y) * 0.5f;
		ImVec2 p2(p1.x, mid_y);
		ImVec2 p3(p4.x, mid_y);

		ImU32 edge_col;
		if (e.from < static_cast<int>(blocks.size()) && blocks[e.from].successors.size() > 1) {
			if (e.is_true_branch)
				edge_col = IM_COL32(80, 200, 80, static_cast<int>(alpha * 220));
			else
				edge_col = IM_COL32(220, 80, 80, static_cast<int>(alpha * 220));
		} else {
			edge_col = _ta(_t.text_dim);
		}

		dl->AddBezierCubic(p1, p2, p3, p4,
			IM_COL32((edge_col >> IM_COL32_R_SHIFT) & 0xFF, (edge_col >> IM_COL32_G_SHIFT) & 0xFF,
					 (edge_col >> IM_COL32_B_SHIFT) & 0xFF, static_cast<int>(40 * alpha)),
			4.f * z);
		dl->AddBezierCubic(p1, p2, p3, p4, edge_col, 1.5f * z);

		float arrow_sz = 5.f * z;
		ImVec2 dir(p4.x - p3.x, p4.y - p3.y);
		float dir_len = std::sqrt(dir.x * dir.x + dir.y * dir.y);
		if (dir_len > 0.001f) {
			dir.x /= dir_len;
			dir.y /= dir_len;
			ImVec2 perp(-dir.y, dir.x);
			ImVec2 a1(p4.x - dir.x * arrow_sz + perp.x * arrow_sz * 0.5f,
					   p4.y - dir.y * arrow_sz + perp.y * arrow_sz * 0.5f);
			ImVec2 a2(p4.x - dir.x * arrow_sz - perp.x * arrow_sz * 0.5f,
					   p4.y - dir.y * arrow_sz - perp.y * arrow_sz * 0.5f);
			dl->AddTriangleFilled(p4, a1, a2, edge_col);
		}
	}

	float line_h = 14.f * z;
	float padding = 8.f * z;

	for (int ni = 0; ni < static_cast<int>(nodes.size()); ++ni) {
		auto& n = nodes[ni];
		if (n.id < 0 || n.id >= static_cast<int>(blocks.size()))
			continue;

		auto& blk = blocks[n.id];

		float nw = n.width * z;
		float nh = n.height * z;
		ImVec2 tl = world_to_screen(n.x - n.width * 0.5f, n.y);
		ImVec2 br(tl.x + nw, tl.y + nh);

		if (br.x < pos_x || tl.x > pos_x + width || br.y < pos_y || tl.y > pos_y + height)
			continue;

		bool is_rip_block = false;
		if (g_state.current_rip >= blk.start_addr && g_state.current_rip < blk.end_addr)
			is_rip_block = true;

		ImU32 bg_col = _ta(_t.panel_bg);
		dl->AddRectFilled(ImVec2(tl.x + 3.f * z, tl.y + 3.f * z),
						  ImVec2(br.x + 3.f * z, br.y + 3.f * z),
						  IM_COL32(0, 0, 0, static_cast<int>(60 * alpha)), 4.f * z);
		dl->AddRectFilled(tl, br, bg_col, 4.f * z);

		if (is_rip_block) {
			ImU32 glow = IM_COL32(ar, ag, ab, static_cast<int>(60 * alpha));
			dl->AddRectFilled(tl, br, glow, 4.f * z);
			dl->AddRect(tl, br, IM_COL32(ar, ag, ab, static_cast<int>(200 * alpha)), 4.f * z, 0, 2.f * z);
		} else if (blk.is_entry) {
			ImU32 entry_glow = IM_COL32(ar, ag, ab, static_cast<int>(30 * alpha));
			dl->AddRectFilled(tl, br, entry_glow, 4.f * z);
			dl->AddRect(tl, br, IM_COL32(ar, ag, ab, static_cast<int>(140 * alpha)), 4.f * z, 0, 1.5f * z);
		} else if (n.id == g_state.selected_block) {
			dl->AddRect(tl, br, IM_COL32(ar, ag, ab, static_cast<int>(160 * alpha)), 4.f * z, 0, 1.5f * z);
		} else {
			dl->AddRect(tl, br, _ta(ui_anim::lighten(_t.panel_bg, 20)), 4.f * z, 0, 1.f * z);
		}

		if (blk.has_breakpoint) {
			dl->AddRectFilled(tl, ImVec2(tl.x + 3.f * z, br.y),
							  IM_COL32(220, 80, 80, static_cast<int>(alpha * 200)), 2.f * z);
		}

		if (blk.is_entry) {
			char entry_label[32];
			snprintf(entry_label, sizeof(entry_label), "entry: %llX",
					 static_cast<unsigned long long>(blk.start_addr));
			dl->AddText(ImVec2(tl.x + padding, tl.y - 14.f * z), accent, entry_label);
		}

		float text_y = tl.y + padding;
		for (auto& line : blk.instructions) {
			if (text_y + line_h > pos_y + height) break;
			if (text_y + line_h < pos_y) { text_y += line_h; continue; }

			char addr_buf[24];
			snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(line.addr));

			ImU32 addr_col = _ta(_t.text_secondary);
			ImU32 text_col = _ta(_t.text_primary);

			if (line.addr == g_state.current_rip) {
				dl->AddRectFilled(ImVec2(tl.x + 2.f * z, text_y),
								  ImVec2(br.x - 2.f * z, text_y + line_h),
								  IM_COL32(ar, ag, ab, static_cast<int>(35 * alpha)));
				text_col = _ta(_t.text_primary);
			}

			float font_scale = z < 0.5f ? 0.5f : (z > 2.f ? 2.f : z);
			ImGui::SetWindowFontScale(font_scale);

			dl->AddText(ImVec2(tl.x + padding, text_y), addr_col, addr_buf);
			dl->AddText(ImVec2(tl.x + padding + 80.f * z, text_y), text_col, line.text.c_str());

			ImGui::SetWindowFontScale(1.f);

			text_y += line_h;
		}

		if (hovered && ImGui::IsMouseHoveringRect(tl, br, false)) {
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				g_state.selected_block = n.id;
			if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
				g_state.navigate_to = blk.start_addr;
		}
	}

	{
		char zoom_buf[16];
		snprintf(zoom_buf, sizeof(zoom_buf), "%.0f%%", g_state.zoom * 100.f);
		ImVec2 zts = ImGui::CalcTextSize(zoom_buf);
		float zx = pos_x + width - zts.x - 16.f;
		float zy = pos_y + 8.f;
		dl->AddRectFilled(ImVec2(zx - 6.f, zy - 2.f), ImVec2(zx + zts.x + 6.f, zy + zts.y + 2.f),
			_ta(_t.panel_bg), 4.f);
		dl->AddText(ImVec2(zx, zy), _ta(_t.text_secondary), zoom_buf);
	}

	dl->PopClipRect();
}

}
