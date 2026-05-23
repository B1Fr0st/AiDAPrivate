#pragma once

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "cfg_layout.hpp"
#include "function_index.hpp"
#include "standalone_driver.hpp"
#include "symbol_classifier.hpp"
#include "disasm_theme.hpp"
#include "zydis_disasm.hpp"
#include "debugger_engine.hpp"
#include "disasm_view.hpp"
#include "ui_anim.hpp"
#include "work_queue.hpp"
#include "../analysis/pdb_events.hpp"
#include "../analysis/symbol_store.hpp"
#include "../anti-tamper/webhook.hpp"
#include "../infra/event_bus.hpp"
#include "../ui/theme.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/fonts.hpp"
#include "../helpers/globals.h"
#include "../../helpers/diag_log.hpp"

extern DisasmState g_disasm;

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

struct block_motion_t {
	float current_x = 0.f;
	float current_y = 0.f;
	float vel_x = 0.f;
	float vel_y = 0.f;
	float entrance = 0.f;
	float hover = 0.f;
	float hover_vel = 0.f;
	bool  initialized = false;
};

struct cfg_state_t {
	std::vector<basic_block_t> blocks;
	cfg_layout::graph_t        graph;
	uint64_t                   entry_addr = 0;
	bool                       built = false;
	uint64_t                   current_rip = 0;
	uint64_t                   last_cursor_addr = 0;
	float                      pan_x = 0.f;
	float                      pan_y = 0.f;
	float                      target_pan_x = 0.f;
	float                      target_pan_y = 0.f;
	float                      pan_vel_x = 0.f;
	float                      pan_vel_y = 0.f;
	float                      zoom = 1.f;
	float                      target_zoom = 1.f;
	float                      zoom_vel = 0.f;
	int                        selected_block = -1;
	float                      rebuild_anim = 1.f;
	bool                       fit_request = false;
	std::unordered_map<int, block_motion_t> block_motion;
	std::map<int, std::vector<function_index::injection_row_t>> entry_injections;
	bool                       minimap_dragging = false;
	int                        text_sel_block = -1;
	int                        text_sel_line_anchor = -1;
	int                        text_sel_line_extent = -1;
	bool                       text_sel_dragging = false;
	int                        text_ctx_block = -1;
	int                        text_ctx_line  = -1;
	int                        sel_log_frame = -1;
	std::mutex                 mutex;
	std::atomic<bool>          building{false};
};

inline cfg_state_t g_state;

inline void build_cfg(uint64_t entry_address);

namespace detail {

inline float estimate_text_width_for_cfg(const char* text, float font_size)
{
	if (!text || font_size <= 0.f)
		return 0.f;
	float width = 0.f;
	for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
		const unsigned char c = *p;
		if (c == '\t') {
			width += font_size * 2.0f;
		} else if (c == ' ') {
			width += font_size * 0.35f;
		} else if (std::strchr("ilI.,:;!|'", c)) {
			width += font_size * 0.34f;
		} else if (std::strchr("mwMW@#%&", c)) {
			width += font_size * 0.86f;
		} else {
			width += font_size * 0.58f;
		}
	}
	return width;
}

inline float estimate_text_width_for_cfg(const std::string& text, float font_size)
{
	return estimate_text_width_for_cfg(text.c_str(), font_size);
}

inline bool safe_decode_for_cfg(const uint8_t* code, int avail, uint64_t va, AsmInstr& out)
{
#if defined(_MSC_VER)
	__try {
		out = zydis_decode_one(code, avail, va);
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		std::snprintf(out.mnem, sizeof(out.mnem), "db");
		std::snprintf(out.ops, sizeof(out.ops), "0x%02X", (code && avail > 0) ? code[0] : 0);
		out.addr = va;
		out.len = 1;
		if (code && avail > 0)
			out.raw[0] = code[0];
		return false;
	}
#else
	out = zydis_decode_one(code, avail, va);
	return true;
#endif
}

inline std::atomic<bool>&                    pdb_subscription_armed_flag()
{
	static std::atomic<bool> armed{false};
	return armed;
}

inline aida::events::subscription_handle_t& pdb_subscription_slot()
{
	static aida::events::subscription_handle_t slot;
	return slot;
}

inline void rebuild_on_pdb_load(const aida::events::event_pdb_loaded& ev)
{
	if (!ev.success) return;
	uint64_t entry = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		if (!g_state.built) return;
		entry = g_state.entry_addr;
	}
	if (entry == 0) return;
	build_cfg(entry);
}

inline void ensure_pdb_subscription()
{
	auto& armed = pdb_subscription_armed_flag();
	if (armed.load(std::memory_order_acquire)) return;
	bool expected = false;
	if (!armed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
	pdb_subscription_slot() = aida::events::subscribe(
		aida::events::event_pdb_loaded_def,
		[](const aida::events::event_pdb_loaded& ev) {
			rebuild_on_pdb_load(ev);
		});
	if (!pdb_subscription_slot().valid()) {
		armed.store(false, std::memory_order_release);
	}
}

}

inline void clear()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.blocks.clear();
	g_state.graph = {};
	g_state.entry_addr = 0;
	g_state.built = false;
	g_state.selected_block = -1;
	g_state.block_motion.clear();
	g_state.entry_injections.clear();
	g_state.rebuild_anim = 1.f;
	g_state.text_sel_block = -1;
	g_state.text_sel_line_anchor = -1;
	g_state.text_sel_line_extent = -1;
	g_state.text_sel_dragging = false;
	g_state.text_ctx_block = -1;
	g_state.text_ctx_line = -1;
	g_state.sel_log_frame = -1;
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

inline ImVec2 bezier_point(ImVec2 p1, ImVec2 p2, ImVec2 p3, ImVec2 p4, float t)
{
	float u = 1.f - t;
	float w0 = u * u * u;
	float w1 = 3.f * u * u * t;
	float w2 = 3.f * u * t * t;
	float w3 = t * t * t;
	return ImVec2(w0 * p1.x + w1 * p2.x + w2 * p3.x + w3 * p4.x,
	              w0 * p1.y + w1 * p2.y + w2 * p3.y + w3 * p4.y);
}

inline void compute_world_bounds(const cfg_layout::graph_t& g, float& min_x, float& min_y,
                                 float& max_x, float& max_y)
{
	min_x = min_y = 1e9f;
	max_x = max_y = -1e9f;
	for (const auto& n : g.nodes) {
		float lx = n.x - n.width * 0.5f;
		float rx = n.x + n.width * 0.5f;
		float ty = n.y;
		float by = n.y + n.height;
		if (lx < min_x) min_x = lx;
		if (rx > max_x) max_x = rx;
		if (ty < min_y) min_y = ty;
		if (by > max_y) max_y = by;
	}
	if (min_x > max_x) { min_x = -100.f; max_x = 100.f; }
	if (min_y > max_y) { min_y = -100.f; max_y = 100.f; }
}

inline float render_colored_insn(ImDrawList* dl, float x, float y,
                                  const char* text, const aida::ui::theme_t& tk,
                                  float alpha, float clip_right,
                                  ImFont* font, float font_size)
{
	if (!text || !*text) return x;
	if (!font) font = ImGui::GetFont();

	ImU32 col_mnem  = aida::ui::with_alpha(tk.accent_u32,    alpha);
	ImU32 col_reg   = aida::ui::with_alpha(tk.info,          alpha);
	ImU32 col_imm   = aida::ui::with_alpha(tk.warning,       alpha);
	ImU32 col_mem   = aida::ui::with_alpha(tk.success,       alpha);
	ImU32 col_punct = aida::ui::with_alpha(tk.text_secondary, alpha);
	ImU32 col_def   = aida::ui::with_alpha(tk.text_primary,  alpha);

	const char* p = text;
	float cur_x = x;

	while (*p && static_cast<unsigned char>(*p) <= 0x20) ++p;
	const char* mnem_start = p;
	while (*p && static_cast<unsigned char>(*p) > 0x20) ++p;
	if (p > mnem_start) {
		if (cur_x < clip_right) {
			dl->AddText(font, font_size, ImVec2(cur_x, y), col_mnem, mnem_start, p);
		}
		ImVec2 ms = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, mnem_start, p);
		cur_x += ms.x;
	}

	while (*p) {
		if (cur_x >= clip_right) break;

		if (static_cast<unsigned char>(*p) <= 0x20) {
			const char* ws = p;
			while (*p && static_cast<unsigned char>(*p) <= 0x20) ++p;
			ImVec2 ss = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, ws, p);
			cur_x += ss.x;
			continue;
		}

		const char* tok = p;
		ImU32 col;

		if (*p == '[') {
			int depth = 0;
			while (*p) {
				if (*p == '[') ++depth;
				else if (*p == ']') {
					++p; --depth;
					if (depth <= 0) break;
					continue;
				}
				++p;
			}
			col = col_mem;
		} else if (*p == '0' && (*(p + 1) == 'x' || *(p + 1) == 'X')) {
			p += 2;
			while (*p && ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
				++p;
			col = col_imm;
		} else if (*p >= '0' && *p <= '9') {
			while (*p && *p >= '0' && *p <= '9') ++p;
			col = col_imm;
		} else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_') {
			while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
			              (*p >= '0' && *p <= '9') || *p == '_'))
				++p;
			col = col_reg;
		} else if (*p == ',' || *p == '+' || *p == '-' || *p == '*' || *p == ':' || *p == '.') {
			++p;
			col = col_punct;
		} else {
			++p;
			col = col_def;
		}

		dl->AddText(font, font_size, ImVec2(cur_x, y), col, tok, p);
		ImVec2 ts = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, tok, p);
		cur_x += ts.x;
	}

	return cur_x;
}

inline std::string resolve_branch_symbol_for_cfg(uint64_t target)
{
	if (target == 0) return std::string();
	std::string sym = symbol_store::resolve_symbol_exact(target);
	if (!sym.empty()) {
		auto bang = sym.find('!');
		if (bang != std::string::npos) sym = sym.substr(bang + 1);
		return sym;
	}
	sym = symbol_store::resolve_symbol(target);
	if (!sym.empty()) {
		auto bang = sym.find('!');
		if (bang != std::string::npos) sym = sym.substr(bang + 1);
		return sym;
	}
	return std::string();
}

inline ImU32 injection_color_for_kind(function_index::injection_t kind)
{
	switch (kind) {
		case function_index::injection_t::function_banner:
		case function_index::injection_t::endp_separator:
			return disasm_theme::banner();
		case function_index::injection_t::attributes_line:
		case function_index::injection_t::prototype_line:
			return disasm_theme::comment();
		case function_index::injection_t::var_decl:
			return disasm_theme::var_decl();
		case function_index::injection_t::label_line:
			return disasm_theme::loc_label();
		case function_index::injection_t::proc_header:
		case function_index::injection_t::proc_endp:
			return disasm_theme::sub_label();
		case function_index::injection_t::spacer_line:
		case function_index::injection_t::noreturn_separator:
		default:
			return disasm_theme::comment();
	}
}

inline std::string substitute_branch_operand(const std::string& ops, uint64_t target)
{
	if (target == 0) return ops;
	std::string sym = resolve_branch_symbol_for_cfg(target);
	if (sym.empty()) return ops;
	symbol_classifier::kind_t k = symbol_classifier::classify(target);
	if (k == symbol_classifier::kind_t::external_import) {
		if (sym.compare(0, 6, "__imp_") != 0)
			sym = "__imp_" + sym;
	}
	char hex_buf[32];
	std::snprintf(hex_buf, sizeof(hex_buf), "0x%llX", static_cast<unsigned long long>(target));
	size_t pos = ops.find(hex_buf);
	if (pos == std::string::npos) {
		std::snprintf(hex_buf, sizeof(hex_buf), "0x%llx", static_cast<unsigned long long>(target));
		pos = ops.find(hex_buf);
	}
	if (pos == std::string::npos) {
		std::snprintf(hex_buf, sizeof(hex_buf), "%llXh", static_cast<unsigned long long>(target));
		pos = ops.find(hex_buf);
	}
	if (pos == std::string::npos) return ops;
	std::string out = ops.substr(0, pos) + sym + ops.substr(pos + std::strlen(hex_buf));
	return out;
}

}

inline void fit_to_view(float view_width, float view_height)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (!g_state.built || g_state.graph.nodes.empty())
		return;

	float min_x, min_y, max_x, max_y;
	detail::compute_world_bounds(g_state.graph, min_x, min_y, max_x, max_y);
	float ww = max_x - min_x;
	float wh = max_y - min_y;
	if (ww < 1.f) ww = 1.f;
	if (wh < 1.f) wh = 1.f;

	const float pad = 60.f;
	float zx = (view_width - pad * 2.f) / ww;
	float zy = (view_height - pad * 2.f) / wh;
	float z = zx < zy ? zx : zy;
	if (z < 0.1f) z = 0.1f;
	if (z > 5.f) z = 5.f;

	float cx = (min_x + max_x) * 0.5f;
	float cy = (min_y + max_y) * 0.5f;

	g_state.target_zoom = z;
	g_state.target_pan_x = -cx;
	g_state.target_pan_y = -cy;
}

inline void center_on_address(uint64_t addr)
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (!g_state.built)
		return;
	for (int i = 0; i < static_cast<int>(g_state.blocks.size()); ++i) {
		auto& b = g_state.blocks[i];
		if (addr >= b.start_addr && addr < b.end_addr) {
			int node_idx = -1;
			for (int ni = 0; ni < static_cast<int>(g_state.graph.nodes.size()); ++ni) {
				if (g_state.graph.nodes[ni].id == i) { node_idx = ni; break; }
			}
			if (node_idx >= 0) {
				auto& n = g_state.graph.nodes[node_idx];
				g_state.target_pan_x = -n.x;
				g_state.target_pan_y = -(n.y + n.height * 0.5f);
				g_state.selected_block = i;
			}
			return;
		}
	}
}

inline void build_cfg(uint64_t entry_address)
{
	detail::ensure_pdb_subscription();

	if (g_state.building.load()) {
		diag::log_tagged_fmt("cfg", "build_cfg skipped already_building entry=0x%llX",
			static_cast<unsigned long long>(entry_address));
		return;
	}

	diag::log_tagged_fmt("cfg", "build_cfg START entry=0x%llX pid=%u",
		static_cast<unsigned long long>(entry_address), driver_bridge::attached_pid());

	g_state.building.store(true);
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.rebuild_anim = 0.f;
	}

	work_queue::post([entry_address]() {
		struct build_guard_t {
			~build_guard_t()
			{
				g_state.building.store(false);
			}
		} build_guard;

		auto t_start = std::chrono::steady_clock::now();
		const size_t max_bytes = 0x10000;
		const size_t max_insns = 4096;

		std::vector<uint8_t> mem;
		bool have_data = false;

		if (driver_bridge::attached_pid() != 0)
			have_data = driver_bridge::read_memory(entry_address, max_bytes, mem);

		if (!have_data || mem.empty()) {
			have_data = static_analysis::read_bytes_from_pe(g_disasm.file, entry_address, max_bytes, mem);
		}

		if (mem.empty()) {
			diag::log_tagged_fmt("cfg", "build_cfg FAILED no_memory_data entry=0x%llX have_data=%d",
				static_cast<unsigned long long>(entry_address), static_cast<int>(have_data));
			g_state.building.store(false);
			return;
		}
		diag::log_tagged_fmt("cfg", "build_cfg memory_read %zu bytes from 0x%llX",
			mem.size(), static_cast<unsigned long long>(entry_address));

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
			AsmInstr ins = {};
			if (!detail::safe_decode_for_cfg(data + pos, avail, va, ins)) {
				diag::log_tagged_fmt("cfg", "build_cfg decode_seh addr=0x%llX",
					static_cast<unsigned long long>(va));
			}
			if (ins.len <= 0) {
				ins.addr = va;
				ins.len = 1;
				std::snprintf(ins.mnem, sizeof(ins.mnem), "db");
				std::snprintf(ins.ops, sizeof(ins.ops), "0x%02X", data[pos]);
				ins.raw[0] = data[pos];
			}

			decoded_insn_t d;
			d.ins = ins;

			if ((ins.is_call || ins.is_branch) && ins.branch_target != 0) {
				d.branch_target = ins.branch_target;
				d.has_target = true;
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

		uint64_t decoded_lo = all_insns.front().ins.addr;
		uint64_t decoded_hi = all_insns.back().ins.addr + static_cast<uint64_t>(all_insns.back().ins.len);

		std::map<uint64_t, bool> leaders;
		leaders[entry_address] = true;

		for (auto& d : all_insns) {
			if (d.has_target && !d.ins.is_call) {
				if (d.branch_target >= decoded_lo && d.branch_target < decoded_hi)
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
			std::string ops_text = d.ins.ops;
			if ((d.ins.is_branch || d.ins.is_call) && d.ins.branch_target != 0) {
				ops_text = detail::substitute_branch_operand(ops_text, d.ins.branch_target);
			}
			line.text.reserve(std::strlen(d.ins.mnem) + 1 + ops_text.size());
			line.text.assign(d.ins.mnem);
			line.text.push_back(' ');
			line.text.append(ops_text);
			blocks[cur_block].instructions.push_back(std::move(line));
			blocks[cur_block].end_addr = d.ins.addr + d.ins.len;

			if (d.ins.is_ret)
				continue;

			if (d.has_target && !d.ins.is_call) {
				bool target_in_range = (d.branch_target >= decoded_lo && d.branch_target < decoded_hi);
				if (target_in_range) {
					auto it_target = addr_to_block.find(d.branch_target);
					if (it_target != addr_to_block.end())
						blocks[cur_block].successors.push_back(it_target->second);
					else {
						int tidx = detail::find_or_create_block(addr_to_block, blocks, d.branch_target);
						blocks[cur_block].successors.push_back(tidx);
					}
				}

				bool is_unconditional = (std::strcmp(d.ins.mnem, "jmp") == 0);
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

		const float code_base = 13.f;
		const float ui_base = 13.f;

		const float line_gap = 5.f;
		const float line_h = code_base + line_gap;
		const float padding = 14.f;
		const float header_h = ui_base + 12.f;
		const float addr_gap = 14.f;
		const float text_slack = 24.f;
		const float min_node_w = 380.f;
		const float max_node_w = 1200.f;

		std::map<int, std::vector<function_index::injection_row_t>> entry_injections;
		for (int bi = 0; bi < static_cast<int>(blocks.size()); ++bi) {
			if (!blocks[bi].is_entry) continue;
			std::vector<function_index::injection_row_t> rows =
				function_index::rows_before(blocks[bi].start_addr);
			if (!rows.empty()) {
				char log_buf[160];
				std::snprintf(log_buf, sizeof(log_buf),
					"[cfg] entry block=%d addr=0x%llX inj_rows=%zu",
					bi,
					static_cast<unsigned long long>(blocks[bi].start_addr),
					rows.size());
				anti_tamper::webhook::write_log("cfg_view", log_buf);
				entry_injections.emplace(bi, std::move(rows));
			}
		}

		cfg_layout::graph_t graph;
		graph.nodes.reserve(blocks.size());
		for (int i = 0; i < static_cast<int>(blocks.size()); ++i) {
			cfg_layout::node_t n;
			n.id = i;
			n.is_entry = blocks[i].is_entry;

			float addr_w = 0.f;
			float text_w = 0.f;
			for (auto& ln : blocks[i].instructions) {
				char ab[24];
				std::snprintf(ab, sizeof(ab), "%llX",
					static_cast<unsigned long long>(ln.addr));
				float aw = detail::estimate_text_width_for_cfg(ab, code_base);
				if (aw > addr_w) addr_w = aw;
				if (!ln.text.empty()) {
					float tw = detail::estimate_text_width_for_cfg(ln.text, code_base);
					if (tw > text_w) text_w = tw;
				}
			}

			size_t inj_lines = 0;
			auto it_inj = entry_injections.find(i);
			if (it_inj != entry_injections.end()) {
				inj_lines = it_inj->second.size();
				for (const auto& r : it_inj->second) {
					if (r.text.empty()) continue;
					float tw = detail::estimate_text_width_for_cfg(r.text, code_base);
					if (tw > text_w) text_w = tw;
				}
			}

			char header_buf[160];
			const char* kind = blocks[i].is_entry
				? "ENTRY"
				: (blocks[i].successors.empty() && !blocks[i].is_entry ? "EXIT" : "BLOCK");
			if (blocks[i].is_entry) {
				std::string fname = detail::resolve_branch_symbol_for_cfg(entry_address);
				if (fname.empty() && entry_address != blocks[i].start_addr)
					fname = detail::resolve_branch_symbol_for_cfg(blocks[i].start_addr);
				if (!fname.empty()) {
					size_t avail = sizeof(header_buf) - 12;
					std::string fn_short = fname.size() > avail
						? fname.substr(0, avail - 2) + ".." : fname;
					std::snprintf(header_buf, sizeof(header_buf), "%s  %s",
						kind, fn_short.c_str());
				} else {
					std::snprintf(header_buf, sizeof(header_buf), "%s  %llX",
						kind, static_cast<unsigned long long>(blocks[i].start_addr));
				}
			} else {
				std::snprintf(header_buf, sizeof(header_buf), "%s  %llX",
					kind, static_cast<unsigned long long>(blocks[i].start_addr));
			}
			float header_w = detail::estimate_text_width_for_cfg(header_buf, ui_base);

			n.addr_col_w = addr_w + addr_gap;

			float body_w = n.addr_col_w + text_w + padding * 2.f + text_slack;
			float head_w = header_w + padding * 2.f + 20.f;
			float w = body_w > head_w ? body_w : head_w;
			if (w < min_node_w) w = min_node_w;
			if (w > max_node_w) w = max_node_w;
			n.width = w;

			size_t total_lines = blocks[i].instructions.size() + inj_lines;
			n.height = header_h + padding * 2.f + static_cast<float>(total_lines) * line_h;
			float min_h = header_h + line_h + padding * 2.f;
			if (n.height < min_h) n.height = min_h;
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

		cfg_layout::layout(graph, 60.f, 60.f);

		const std::size_t block_count = blocks.size();
		const std::size_t node_count = graph.nodes.size();
		const std::size_t edge_count = graph.edges.size();

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.blocks = std::move(blocks);
			g_state.graph = std::move(graph);
			g_state.entry_injections = std::move(entry_injections);
			g_state.entry_addr = entry_address;
			g_state.built = true;
			g_state.selected_block = -1;
			g_state.target_pan_x = 0.f;
			g_state.target_pan_y = 0.f;
			g_state.pan_x = 0.f;
			g_state.pan_y = 0.f;
			g_state.target_zoom = 1.f;
			g_state.zoom = 1.f;
			g_state.block_motion.clear();
			g_state.rebuild_anim = 0.f;
			g_state.fit_request = true;
			g_state.text_sel_block = -1;
			g_state.text_sel_line_anchor = -1;
			g_state.text_sel_line_extent = -1;
			g_state.text_sel_dragging = false;
			g_state.text_ctx_block = -1;
			g_state.text_ctx_line = -1;
			g_state.sel_log_frame = -1;
		}

		auto t_end = std::chrono::steady_clock::now();
		uint64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
		diag::log_tagged_fmt("cfg", "build_cfg DONE entry=0x%llX blocks=%zu nodes=%zu edges=%zu duration_ms=%llu",
			static_cast<unsigned long long>(entry_address),
			block_count,
			node_count,
			edge_count,
			static_cast<unsigned long long>(dur_ms));
	});
}

inline bool handle_view_keys(float view_width, float view_height)
{
	if (g_state.fit_request && g_state.built && !g_state.graph.nodes.empty()) {
		g_state.fit_request = false;
		fit_to_view(view_width, view_height);
	}

	ImGuiIO& key_io = ImGui::GetIO();
	bool key_text_lock = key_io.WantTextInput
		|| ImGui::IsAnyItemActive();

	if (key_text_lock || key_io.KeyCtrl || key_io.KeyAlt)
		return false;

	if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
		if (g_state.text_sel_block >= 0
			|| g_state.text_sel_line_anchor >= 0
			|| g_state.text_sel_line_extent >= 0)
		{
			g_state.text_sel_block = -1;
			g_state.text_sel_line_anchor = -1;
			g_state.text_sel_line_extent = -1;
			g_state.text_sel_dragging = false;
			return true;
		}
		uint64_t back_addr = g_state.last_cursor_addr != 0
			? g_state.last_cursor_addr
			: g_state.entry_addr;
		globals::ui::active_center_view = center_view_t::disassembly;
		if (back_addr != 0)
			disasm_view::goto_address(back_addr, g_disasm);
		return true;
	}
	if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) {
		uint64_t back_addr = g_state.last_cursor_addr != 0
			? g_state.last_cursor_addr
			: g_state.entry_addr;
		globals::ui::active_center_view = center_view_t::disassembly;
		if (back_addr != 0)
			disasm_view::goto_address(back_addr, g_disasm);
		return true;
	}
	if (ImGui::IsKeyPressed(ImGuiKey_F, false)) {
		fit_to_view(view_width, view_height);
		return true;
	}
	if (ImGui::IsKeyPressed(ImGuiKey_G, false)) {
		if (g_state.last_cursor_addr != 0)
			center_on_address(g_state.last_cursor_addr);
		else if (g_state.entry_addr != 0)
			center_on_address(g_state.entry_addr);
		return true;
	}
	return false;
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 clip_min(pos_x, pos_y);
	ImVec2 clip_max(pos_x + width, pos_y + height);
	dl->PushClipRect(clip_min, clip_max, true);

	const auto& tk = aida::ui::resolved();
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return aida::ui::with_alpha(c, alpha);
	};
	float dt = aida::ui::clock::dt();

	dl->AddRectFilled(clip_min, clip_max, _ta(tk.bg_base));

	handle_view_keys(width, height);

	if (g_state.building.load()) {
		float panel_w = width * 0.55f;
		if (panel_w > 480.f) panel_w = 480.f;
		float panel_h = 180.f;
		float px = pos_x + (width - panel_w) * 0.5f;
		float py = pos_y + (height - panel_h) * 0.5f;
		ImVec2 a(px, py);
		ImVec2 b(px + panel_w, py + panel_h);
		aida::ui::blur::render_drop_shadow(dl, a, b, 14.f, 4, 0.30f * alpha);
		aida::ui::blur::render_glass_fill(dl, a, b, 14.f, alpha);
		aida::ui::blur::render_glass_border(dl, a, b, 14.f, alpha);

		float row_y = py + 22.f;
		ImFont* ft = aida::ui::fonts::body_em();
		dl->AddText(ft, 14.f, ImVec2(px + 22.f, row_y),
		            _ta(tk.text_primary), "Building CFG...");
		row_y += 26.f;
		aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, row_y), panel_w - 44.f, 12.f);
		row_y += 18.f;
		aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, row_y), (panel_w - 44.f) * 0.78f, 12.f);
		row_y += 18.f;
		aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, row_y), (panel_w - 44.f) * 0.62f, 12.f);

		float bar_y = py + panel_h - 26.f;
		aida::ui::components::render_progress_bar(ImVec2(px + 22.f, bar_y),
		                                          panel_w - 44.f, 4.f, 0.f, true, true);
		dl->PopClipRect();
		return;
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);

	if (!g_state.built || g_state.blocks.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::flow;
		cfg.title = "No CFG built";
		cfg.body  = "Place the cursor on an address in the disassembly view, then press Space to build a control-flow graph.";
		cfg.hints = { { "Space" }, { "Esc" } };
		aida::ui::empty_state::render(ImVec2(pos_x, pos_y), ImVec2(width, height), cfg);
		dl->PopClipRect();
		return;
	}

	g_state.rebuild_anim = aida::motion::smooth_lerp(g_state.rebuild_anim, 1.f, 4.f, dt);

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

	g_state.pan_x = aida::motion::spring_step(g_state.pan_x, g_state.target_pan_x,
	                                           g_state.pan_vel_x, aida::motion::spring::balanced, dt);
	g_state.pan_y = aida::motion::spring_step(g_state.pan_y, g_state.target_pan_y,
	                                           g_state.pan_vel_y, aida::motion::spring::balanced, dt);
	g_state.zoom = aida::motion::spring_step(g_state.zoom, g_state.target_zoom,
	                                          g_state.zoom_vel, aida::motion::spring::balanced, dt);

	float center_x = pos_x + width * 0.5f;
	float center_y = pos_y + height * 0.5f;
	float z = g_state.zoom;

	auto world_to_screen = [&](float wx, float wy) -> ImVec2 {
		return ImVec2(center_x + (wx + g_state.pan_x) * z,
					  center_y + (wy + g_state.pan_y) * z);
	};

	{
		const float grid_step = 40.f;
		float inv_z = z > 0.0001f ? 1.f / z : 1.f;
		float w_left   = -g_state.pan_x - (width  * 0.5f) * inv_z;
		float w_right  = -g_state.pan_x + (width  * 0.5f) * inv_z;
		float w_top    = -g_state.pan_y - (height * 0.5f) * inv_z;
		float w_bottom = -g_state.pan_y + (height * 0.5f) * inv_z;
		float span_x = w_right - w_left;
		float span_y = w_bottom - w_top;
		if (span_x > 0.f && span_y > 0.f) {
			float est_cols = span_x / grid_step;
			float est_rows = span_y / grid_step;
			if (est_cols * est_rows <= 4000.f) {
				float gx0 = std::floor(w_left  / grid_step) * grid_step;
				float gy0 = std::floor(w_top   / grid_step) * grid_step;
				float gx1 = std::ceil (w_right / grid_step) * grid_step;
				float gy1 = std::ceil (w_bottom / grid_step) * grid_step;
				ImU32 dot_col = aida::ui::with_alpha(tk.border_subtle, alpha * 0.6f);
				for (float gy = gy0; gy <= gy1; gy += grid_step) {
					for (float gx = gx0; gx <= gx1; gx += grid_step) {
						ImVec2 sp = world_to_screen(gx, gy);
						if (sp.x < pos_x - 2.f || sp.x > pos_x + width + 2.f) continue;
						if (sp.y < pos_y - 2.f || sp.y > pos_y + height + 2.f) continue;
						dl->AddCircleFilled(sp, 0.9f, dot_col, 6);
					}
				}
			}
		}
	}

	auto& nodes = g_state.graph.nodes;
	auto& edges = g_state.graph.edges;
	auto& blocks = g_state.blocks;

	for (auto& n : nodes) {
		auto& m = g_state.block_motion[n.id];
		if (!m.initialized) {
			m.current_x = n.x;
			m.current_y = n.y;
			m.initialized = true;
			m.entrance = 0.f;
		}
		m.current_x = aida::motion::spring_step(m.current_x, n.x, m.vel_x, aida::motion::spring::gentle, dt);
		m.current_y = aida::motion::spring_step(m.current_y, n.y, m.vel_y, aida::motion::spring::gentle, dt);
	}

	for (auto& e : edges) {
		int from_idx = -1, to_idx = -1;
		for (int i = 0; i < static_cast<int>(nodes.size()); ++i) {
			if (nodes[i].id == e.from) from_idx = i;
			if (nodes[i].id == e.to) to_idx = i;
		}
		if (from_idx < 0 || to_idx < 0) continue;

		auto& fn = nodes[from_idx];
		auto& tn = nodes[to_idx];
		auto& fm = g_state.block_motion[fn.id];
		auto& tm = g_state.block_motion[tn.id];

		float arrow_sz = std::max(5.f, 7.f * z);
		ImVec2 p1 = world_to_screen(fm.current_x, fm.current_y + fn.height);
		ImVec2 p_tip = world_to_screen(tm.current_x, tm.current_y);
		ImVec2 p4(p_tip.x, p_tip.y - arrow_sz);
		float mid_y = (p1.y + p4.y) * 0.5f;
		ImVec2 p2(p1.x, mid_y);
		ImVec2 p3(p4.x, mid_y);

		bool two_succ = (e.from < static_cast<int>(blocks.size()) && blocks[e.from].successors.size() > 1);
		ImU32 edge_col;
		if (two_succ) {
			edge_col = e.is_true_branch
				? aida::ui::with_alpha(tk.success, alpha)
				: aida::ui::with_alpha(tk.error,   alpha);
		} else {
			edge_col = aida::ui::with_alpha(aida::ui::lighten(tk.text_secondary, 10), alpha);
		}

		float halo_thick = std::max(3.5f, 5.5f * z);
		float line_thick = std::max(1.5f, 2.0f * z);
		ImU32 halo = aida::ui::with_alpha(edge_col, 0.18f);
		dl->AddBezierCubic(p1, p2, p3, p4, halo, halo_thick);
		dl->AddBezierCubic(p1, p2, p3, p4, edge_col, line_thick);

		ImVec2 dir(p_tip.x - p3.x, p_tip.y - p3.y);
		float dir_len = std::sqrt(dir.x * dir.x + dir.y * dir.y);
		if (dir_len > 0.001f) {
			dir.x /= dir_len;
			dir.y /= dir_len;
			ImVec2 perp(-dir.y, dir.x);
			ImVec2 a1(p_tip.x - dir.x * arrow_sz + perp.x * arrow_sz * 0.5f,
					   p_tip.y - dir.y * arrow_sz + perp.y * arrow_sz * 0.5f);
			ImVec2 a2(p_tip.x - dir.x * arrow_sz - perp.x * arrow_sz * 0.5f,
					   p_tip.y - dir.y * arrow_sz - perp.y * arrow_sz * 0.5f);
			dl->AddTriangleFilled(p_tip, a1, a2, edge_col);
		}

		if (two_succ) {
			const char* label = e.is_true_branch ? "T" : "F";
			ImVec2 lts = ImGui::CalcTextSize(label);
			float lx = (p1.x + p4.x) * 0.5f + 6.f;
			float ly = (p1.y + p4.y) * 0.5f - lts.y * 0.5f;
			float pad_x = 4.f;
			float pad_y = 1.f;
			ImVec2 box_a(lx - pad_x, ly - pad_y);
			ImVec2 box_b(lx + lts.x + pad_x, ly + lts.y + pad_y);
			dl->AddRectFilled(box_a, box_b,
				aida::ui::with_alpha(aida::ui::resolved().bg_base, 0.94f * alpha), 3.f);
			dl->AddRect(box_a, box_b, edge_col, 3.f, 0, 1.f);
			dl->AddText(ImVec2(lx, ly), edge_col, label);
		}
	}

	float card_font_scale = z;
	if (card_font_scale < 0.30f) card_font_scale = 0.30f;
	if (card_font_scale > 3.00f) card_font_scale = 3.00f;
	ImFont* header_font = aida::ui::fonts::body_em();
	if (!header_font) header_font = ImGui::GetFont();
	float header_base = header_font && header_font->FontSize > 0.f
		? header_font->FontSize : 13.f;
	const float header_strip_h = (header_base + 8.f) * card_font_scale;

	{
		ImFont* log_font = aida::ui::fonts::code();
		if (!log_font) log_font = ImGui::GetFont();
		float log_base = log_font->FontSize > 0.f ? log_font->FontSize : ImGui::GetFontSize();
		if (log_base <= 0.f) log_base = 13.f;
		float log_raw = log_base * z;
		float log_final = log_raw < 6.f ? 6.f : log_raw;
		bool  log_skip = log_raw < 6.f;
		static double s_last_log_time = -1e9;
		double now_log = ImGui::GetTime();
		if (now_log - s_last_log_time >= 2.0) {
			s_last_log_time = now_log;
			char log_msg[160];
			std::snprintf(log_msg, sizeof(log_msg),
				"node_render font=disasm_code base_size=%.2f zoom=%.3f final_size=%.2f skip_text=%d",
				log_base, z, log_final, log_skip ? 1 : 0);
			anti_tamper::webhook::write_log("cfg", log_msg);
		}
	}

	for (int ni = 0; ni < static_cast<int>(nodes.size()); ++ni) {
		auto& n = nodes[ni];
		if (n.id < 0 || n.id >= static_cast<int>(blocks.size()))
			continue;

		auto& blk = blocks[n.id];
		auto& mm = g_state.block_motion[n.id];

		float nw = n.width * z;
		float nh = n.height * z;
		ImVec2 base_tl = world_to_screen(mm.current_x - n.width * 0.5f, mm.current_y);
		ImVec2 base_br(base_tl.x + nw, base_tl.y + nh);

		bool block_hov = ImGui::IsMouseHoveringRect(base_tl, base_br, false) && hovered;
		mm.hover = aida::motion::spring_step(mm.hover, block_hov ? 1.f : 0.f, mm.hover_vel,
		                                      aida::motion::spring::snappy, dt);
		float lift = mm.hover * 2.f;

		ImVec2 tl(base_tl.x, base_tl.y - lift);
		ImVec2 br(base_br.x, base_br.y - lift);

		float entrance = mm.entrance;
		if (entrance < 1.f) {
			float fy = (1.f - entrance) * 8.f;
			tl.y += fy; br.y += fy;
		}
		float row_alpha = alpha * (entrance < 1.f ? entrance : 1.f);

		if (br.x < pos_x || tl.x > pos_x + width || br.y < pos_y || tl.y > pos_y + height)
			continue;

		bool is_rip_block = (g_state.current_rip >= blk.start_addr && g_state.current_rip < blk.end_addr);
		bool is_selected = (n.id == g_state.selected_block);
		bool is_exit = blk.successors.empty() && !blk.is_entry;

		char header_buf[160];
		const char* kind = blk.is_entry ? "ENTRY" : (is_exit ? "EXIT" : "BLOCK");
		if (blk.is_entry) {
			std::string fname = detail::resolve_branch_symbol_for_cfg(g_state.entry_addr);
			if (fname.empty() && g_state.entry_addr != blk.start_addr)
				fname = detail::resolve_branch_symbol_for_cfg(blk.start_addr);
			if (!fname.empty()) {
				size_t avail = sizeof(header_buf) - 12;
				std::string fn_short = fname.size() > avail
					? fname.substr(0, avail - 2) + ".." : fname;
				snprintf(header_buf, sizeof(header_buf), "%s  %s",
				         kind, fn_short.c_str());
			} else {
				snprintf(header_buf, sizeof(header_buf), "%s  %llX",
				         kind, static_cast<unsigned long long>(blk.start_addr));
			}
		} else {
			snprintf(header_buf, sizeof(header_buf), "%s  %llX",
			         kind, static_cast<unsigned long long>(blk.start_addr));
		}

		ui_anim::render_graph_node_card(dl, tl.x, tl.y, nw, nh,
		                                 header_buf, blk.is_entry, is_selected,
		                                 accent_r, accent_g, accent_b, row_alpha,
		                                 aida::ui::clock::seconds(), card_font_scale);

		if (is_exit) {
			dl->AddRect(tl, br,
			            aida::ui::with_alpha(tk.warning, row_alpha * 0.75f),
			            7.f, 0, 1.5f * z);
		}
		if (is_rip_block) {
			float pulse = aida::ui::clock::pulse(1.4f, 0.55f, 1.f);
			dl->AddRect(tl, br,
			            aida::ui::with_alpha(tk.accent_u32, row_alpha * pulse),
			            7.f, 0, 2.f * z);
		}

		if (mm.hover > 0.001f) {
			ImU32 wash = aida::ui::with_alpha(tk.hover_wash, row_alpha * mm.hover);
			dl->AddRectFilled(ImVec2(tl.x + 1.f, tl.y + header_strip_h + 1.f),
			                  ImVec2(br.x - 1.f, br.y - 1.f), wash, 6.f);
		}

		if (blk.has_breakpoint) {
			dl->AddRectFilled(ImVec2(tl.x, tl.y + header_strip_h),
			                  ImVec2(tl.x + 3.f * z, br.y),
			                  aida::ui::with_alpha(tk.error, row_alpha));
		}

		int hovered_line_idx = -1;
		float body_top_y = tl.y + header_strip_h;
		float body_bottom_y = br.y - 1.f;

		{
			ImVec2 body_clip_a(tl.x + 1.f, tl.y + header_strip_h);
			ImVec2 body_clip_b(br.x - 1.f, br.y - 1.f);
			dl->PushClipRect(body_clip_a, body_clip_b, true);

			ImFont* node_font = aida::ui::fonts::code();
			if (!node_font) node_font = ImGui::GetFont();
			float base_font_size = node_font->FontSize > 0.f
				? node_font->FontSize : ImGui::GetFontSize();
			if (base_font_size <= 0.f) base_font_size = 13.f;

			float raw_size = base_font_size * z;
			float node_font_size = raw_size;
			if (node_font_size < 7.5f) node_font_size = 7.5f;
			const float size_ratio = node_font_size / base_font_size;
			const bool  skip_text = raw_size < 3.f;

			const float scaled_line_h   = (base_font_size + 4.f) * size_ratio;
			const float scaled_padding  =  8.f * size_ratio;
			const float scaled_addr_col = n.addr_col_w * size_ratio;
			const float row_text_dy     = (scaled_line_h - node_font_size) * 0.5f;

			int sel_lo = -1, sel_hi = -1;
			if (g_state.text_sel_block == n.id
				&& g_state.text_sel_line_anchor >= 0
				&& g_state.text_sel_line_extent >= 0)
			{
				sel_lo = g_state.text_sel_line_anchor < g_state.text_sel_line_extent
					? g_state.text_sel_line_anchor : g_state.text_sel_line_extent;
				sel_hi = g_state.text_sel_line_anchor > g_state.text_sel_line_extent
					? g_state.text_sel_line_anchor : g_state.text_sel_line_extent;
			}

			const std::vector<function_index::injection_row_t>* injs = nullptr;
			if (blk.is_entry) {
				auto it_inj = g_state.entry_injections.find(n.id);
				if (it_inj != g_state.entry_injections.end() && !it_inj->second.empty())
					injs = &it_inj->second;
			}
			int inj_count = injs ? static_cast<int>(injs->size()) : 0;

			float inj_y = body_top_y;
			for (int ii = 0; ii < inj_count; ++ii) {
				if (inj_y + scaled_line_h > br.y - 2.f) break;
				const auto& r = (*injs)[ii];
				float inj_text_y = inj_y + row_text_dy;
				if (!(inj_y + scaled_line_h < pos_y || inj_y > pos_y + height)) {
					if (!skip_text && r.kind != function_index::injection_t::spacer_line && !r.text.empty()) {
						if (r.kind == function_index::injection_t::proc_header
							|| r.kind == function_index::injection_t::proc_endp)
						{
							ImU32 name_base = disasm_theme::sub_label();
							symbol_classifier::kind_t sk = symbol_classifier::classify(r.addr);
							if (sk != symbol_classifier::kind_t::unknown)
								name_base = disasm_theme::color_for_kind(static_cast<int>(sk));
							const std::string& t = r.text;
							size_t name_end = 0;
							while (name_end < t.size()
								&& t[name_end] != ' ' && t[name_end] != '\t') ++name_end;
							std::string name_part = t.substr(0, name_end);
							std::string tail_part = t.substr(name_end);
							ImU32 name_col = aida::ui::with_alpha(name_base, row_alpha);
							dl->AddText(node_font, node_font_size,
								ImVec2(tl.x + scaled_padding, inj_text_y),
								name_col, name_part.c_str());
							if (!tail_part.empty()) {
								float name_w = node_font->CalcTextSizeA(node_font_size, FLT_MAX, 0.f,
									name_part.c_str()).x;
								ImU32 tail_col = aida::ui::with_alpha(
									disasm_theme::keyword(), row_alpha);
								dl->AddText(node_font, node_font_size,
									ImVec2(tl.x + scaled_padding + name_w, inj_text_y),
									tail_col, tail_part.c_str());
							}
						} else {
							ImU32 inj_col_base = detail::injection_color_for_kind(r.kind);
							ImU32 inj_col = aida::ui::with_alpha(inj_col_base, row_alpha);
							dl->AddText(node_font, node_font_size,
								ImVec2(tl.x + scaled_padding, inj_text_y),
								inj_col, r.text.c_str());
						}
					}
				}
				inj_y += scaled_line_h;
			}

			float instr_top_y = body_top_y + static_cast<float>(inj_count) * scaled_line_h;

			for (int li = 0; li < static_cast<int>(blk.instructions.size()); ++li) {
				auto& line = blk.instructions[li];
				float line_y = instr_top_y + scaled_line_h * static_cast<float>(li);
				float line_bottom = line_y + scaled_line_h;
				if (line_bottom > br.y - 2.f) break;
				if (line_y > pos_y + height) break;
				if (line_bottom < pos_y) continue;

				ImVec2 line_a(tl.x + 2.f, line_y);
				ImVec2 line_b(br.x - 2.f, line_bottom);

				if (block_hov && io.MousePos.x >= line_a.x && io.MousePos.x <= line_b.x
					&& io.MousePos.y >= line_a.y && io.MousePos.y <= line_b.y)
				{
					hovered_line_idx = li;
				}

				bool line_selected = (sel_lo >= 0 && li >= sel_lo && li <= sel_hi);

				char addr_buf[24];
				snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(line.addr));

				ImU32 addr_col = aida::ui::with_alpha(tk.text_address, row_alpha * 0.85f);

				if (line.addr == g_state.current_rip) {
					dl->AddRectFilled(line_a, line_b,
									  aida::ui::with_alpha(tk.accent_glow, row_alpha));
				}

				if (line_selected) {
					dl->AddRectFilled(line_a, line_b,
									  aida::ui::with_alpha(tk.accent_u32, row_alpha * 0.32f));
					dl->AddLine(ImVec2(line_a.x, line_a.y),
								ImVec2(line_a.x, line_b.y),
								aida::ui::with_alpha(tk.accent_u32, row_alpha), 1.5f);
				}

				if (!skip_text) {
					float text_y = line_y + row_text_dy;
					dl->AddText(node_font, node_font_size,
						ImVec2(tl.x + scaled_padding, text_y), addr_col, addr_buf);
					detail::render_colored_insn(dl,
						tl.x + scaled_padding + scaled_addr_col, text_y,
						line.text.c_str(), tk, row_alpha, br.x - scaled_padding,
						node_font, node_font_size);
				}
			}

			dl->PopClipRect();
		}

		if (block_hov) {
			bool in_body = io.MousePos.y >= body_top_y && io.MousePos.y <= body_bottom_y;

			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				g_state.selected_block = n.id;
				g_state.last_cursor_addr = blk.start_addr;
				if (in_body && hovered_line_idx >= 0) {
					if (hovered_line_idx >= 0
						&& hovered_line_idx < static_cast<int>(blk.instructions.size()))
					{
						g_state.last_cursor_addr = blk.instructions[hovered_line_idx].addr;
					}
					g_state.text_sel_block = n.id;
					if (io.KeyShift && g_state.text_sel_block == n.id
						&& g_state.text_sel_line_anchor >= 0)
					{
						g_state.text_sel_line_extent = hovered_line_idx;
					} else {
						g_state.text_sel_line_anchor = hovered_line_idx;
						g_state.text_sel_line_extent = hovered_line_idx;
					}
					g_state.text_sel_dragging = true;
					int cur_frame = ImGui::GetFrameCount();
					if (g_state.sel_log_frame != cur_frame) {
						g_state.sel_log_frame = cur_frame;
						char log_buf[96];
						std::snprintf(log_buf, sizeof(log_buf),
							"[cfg] sel block=%d line=%d y=%.1f",
							n.id, hovered_line_idx, io.MousePos.y);
						anti_tamper::webhook::write_log("cfg_view", log_buf);
					}
				} else {
					g_state.text_sel_block = -1;
					g_state.text_sel_line_anchor = -1;
					g_state.text_sel_line_extent = -1;
					g_state.text_sel_dragging = false;
				}
			}
			if (g_state.text_sel_dragging && g_state.text_sel_block == n.id
				&& ImGui::IsMouseDown(ImGuiMouseButton_Left)
				&& hovered_line_idx >= 0)
			{
				g_state.text_sel_line_extent = hovered_line_idx;
			}
			if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
				uint64_t go_addr = blk.start_addr;
				if (in_body && hovered_line_idx >= 0
					&& hovered_line_idx < static_cast<int>(blk.instructions.size()))
				{
					go_addr = blk.instructions[hovered_line_idx].addr;
				}
				g_state.last_cursor_addr = go_addr;
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(go_addr, g_disasm);
			}
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)
				&& in_body && hovered_line_idx >= 0)
			{
				g_state.text_ctx_block = n.id;
				g_state.text_ctx_line  = hovered_line_idx;
				if (g_state.text_sel_block != n.id
					|| g_state.text_sel_line_anchor < 0
					|| hovered_line_idx < (g_state.text_sel_line_anchor < g_state.text_sel_line_extent
						? g_state.text_sel_line_anchor : g_state.text_sel_line_extent)
					|| hovered_line_idx > (g_state.text_sel_line_anchor > g_state.text_sel_line_extent
						? g_state.text_sel_line_anchor : g_state.text_sel_line_extent))
				{
					g_state.text_sel_block = n.id;
					g_state.text_sel_line_anchor = hovered_line_idx;
					g_state.text_sel_line_extent = hovered_line_idx;
				}
				ImGui::OpenPopup("##cfg_line_ctx");
			}
		}

		if (mm.entrance < 1.f) mm.entrance += dt * 3.5f;
		if (mm.entrance > 1.f) mm.entrance = 1.f;
	}

	if (g_state.text_sel_dragging && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
		g_state.text_sel_dragging = false;
	}

	auto build_sel_text = [&](bool include_address) -> std::string {
		if (g_state.text_sel_block < 0
			|| g_state.text_sel_line_anchor < 0
			|| g_state.text_sel_line_extent < 0)
			return std::string();
		if (g_state.text_sel_block >= static_cast<int>(g_state.blocks.size()))
			return std::string();
		const auto& sblk = g_state.blocks[g_state.text_sel_block];
		int lo = g_state.text_sel_line_anchor < g_state.text_sel_line_extent
			? g_state.text_sel_line_anchor : g_state.text_sel_line_extent;
		int hi = g_state.text_sel_line_anchor > g_state.text_sel_line_extent
			? g_state.text_sel_line_anchor : g_state.text_sel_line_extent;
		if (lo < 0) lo = 0;
		if (hi >= static_cast<int>(sblk.instructions.size()))
			hi = static_cast<int>(sblk.instructions.size()) - 1;
		std::string out;
		out.reserve(static_cast<size_t>(hi - lo + 1) * 64);
		char buf[256];
		for (int i = lo; i <= hi; ++i) {
			const auto& ln = sblk.instructions[i];
			if (include_address) {
				snprintf(buf, sizeof(buf), ".text:%016llX  %s\n",
					static_cast<unsigned long long>(ln.addr), ln.text.c_str());
			} else {
				snprintf(buf, sizeof(buf), "%s\n", ln.text.c_str());
			}
			out += buf;
		}
		if (!out.empty() && out.back() == '\n') out.pop_back();
		return out;
	};

	if (hovered && !io.WantTextInput && !io.WantCaptureKeyboard
		&& io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false))
	{
		std::string txt = build_sel_text(true);
		if (!txt.empty()) ImGui::SetClipboardText(txt.c_str());
	}
	if (hovered && !io.WantTextInput && !io.WantCaptureKeyboard
		&& io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false))
	{
		if (g_state.selected_block >= 0
			&& g_state.selected_block < static_cast<int>(g_state.blocks.size()))
		{
			const auto& sblk = g_state.blocks[g_state.selected_block];
			g_state.text_sel_block = g_state.selected_block;
			g_state.text_sel_line_anchor = 0;
			g_state.text_sel_line_extent = static_cast<int>(sblk.instructions.size()) - 1;
		}
	}

	if (ImGui::BeginPopup("##cfg_line_ctx")) {
		bool has_sel = (g_state.text_sel_block >= 0
			&& g_state.text_sel_line_anchor >= 0
			&& g_state.text_sel_line_extent >= 0
			&& g_state.text_sel_block < static_cast<int>(g_state.blocks.size()));
		uint64_t ctx_addr = 0;
		if (g_state.text_ctx_block >= 0
			&& g_state.text_ctx_block < static_cast<int>(g_state.blocks.size())
			&& g_state.text_ctx_line >= 0
			&& g_state.text_ctx_line < static_cast<int>(g_state.blocks[g_state.text_ctx_block].instructions.size()))
		{
			ctx_addr = g_state.blocks[g_state.text_ctx_block].instructions[g_state.text_ctx_line].addr;
		}
		if (ImGui::MenuItem("Copy text", "Ctrl+C", false, has_sel)) {
			std::string txt = build_sel_text(false);
			if (!txt.empty()) ImGui::SetClipboardText(txt.c_str());
		}
		if (ImGui::MenuItem("Copy text with address", nullptr, false, has_sel)) {
			std::string txt = build_sel_text(true);
			if (!txt.empty()) ImGui::SetClipboardText(txt.c_str());
		}
		if (ImGui::MenuItem("Copy address", nullptr, false, ctx_addr != 0)) {
			char addr_buf[32];
			snprintf(addr_buf, sizeof(addr_buf), "%llX",
				static_cast<unsigned long long>(ctx_addr));
			ImGui::SetClipboardText(addr_buf);
		}
		ImGui::Separator();
		if (ImGui::MenuItem("Go to in disassembly", "Dbl-Click", false, ctx_addr != 0)) {
			g_state.last_cursor_addr = ctx_addr;
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(ctx_addr, g_disasm);
		}
		ImGui::Separator();
		if (ImGui::MenuItem("Select all in block", "Ctrl+A", false,
			g_state.text_ctx_block >= 0
			&& g_state.text_ctx_block < static_cast<int>(g_state.blocks.size())))
		{
			const auto& sblk = g_state.blocks[g_state.text_ctx_block];
			g_state.text_sel_block = g_state.text_ctx_block;
			g_state.text_sel_line_anchor = 0;
			g_state.text_sel_line_extent = static_cast<int>(sblk.instructions.size()) - 1;
		}
		if (ImGui::MenuItem("Clear selection", "Esc", false, has_sel)) {
			g_state.text_sel_block = -1;
			g_state.text_sel_line_anchor = -1;
			g_state.text_sel_line_extent = -1;
		}
		ImGui::EndPopup();
	}

	{
		float zoom_w = 220.f;
		float zoom_h = 32.f;
		float zx = pos_x + 14.f;
		float zy = pos_y + height - zoom_h - 14.f;
		ImVec2 za(zx, zy);
		ImVec2 zb(zx + zoom_w, zy + zoom_h);
		aida::ui::blur::render_drop_shadow(dl, za, zb, zoom_h * 0.5f, 4, 0.30f * alpha);
		aida::ui::blur::render_glass_fill(dl, za, zb, zoom_h * 0.5f, alpha);
		aida::ui::blur::render_glass_border(dl, za, zb, zoom_h * 0.5f, alpha);

		float btn_sz = zoom_h - 6.f;
		float by = zy + 3.f;

		float minus_x = zx + 4.f;
		ImVec2 minus_a(minus_x, by);
		ImVec2 minus_b(minus_x + btn_sz, by + btn_sz);
		bool minus_hov = ImGui::IsMouseHoveringRect(minus_a, minus_b, false);
		if (minus_hov) {
			dl->AddRectFilled(minus_a, minus_b,
			                  aida::ui::with_alpha(tk.hover_wash, alpha), btn_sz * 0.5f);
		}
		ImVec2 mc((minus_a.x + minus_b.x) * 0.5f, (minus_a.y + minus_b.y) * 0.5f);
		dl->AddLine(ImVec2(mc.x - 6.f, mc.y), ImVec2(mc.x + 6.f, mc.y),
		            minus_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
		                      : aida::ui::with_alpha(tk.text_secondary, alpha), 2.f);

		float text_box_w = 56.f;
		float plus_x = minus_b.x + text_box_w;
		ImVec2 plus_a(plus_x, by);
		ImVec2 plus_b(plus_x + btn_sz, by + btn_sz);
		bool plus_hov = ImGui::IsMouseHoveringRect(plus_a, plus_b, false);
		if (plus_hov) {
			dl->AddRectFilled(plus_a, plus_b,
			                  aida::ui::with_alpha(tk.hover_wash, alpha), btn_sz * 0.5f);
		}
		ImVec2 pc((plus_a.x + plus_b.x) * 0.5f, (plus_a.y + plus_b.y) * 0.5f);
		dl->AddLine(ImVec2(pc.x - 6.f, pc.y), ImVec2(pc.x + 6.f, pc.y),
		            plus_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
		                     : aida::ui::with_alpha(tk.text_secondary, alpha), 2.f);
		dl->AddLine(ImVec2(pc.x, pc.y - 6.f), ImVec2(pc.x, pc.y + 6.f),
		            plus_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
		                     : aida::ui::with_alpha(tk.text_secondary, alpha), 2.f);

		char zoom_buf[16];
		snprintf(zoom_buf, sizeof(zoom_buf), "%.0f%%", g_state.zoom * 100.f);
		ImVec2 zts = ImGui::CalcTextSize(zoom_buf);
		float zoom_text_x = (minus_b.x + plus_a.x - zts.x) * 0.5f;
		float zoom_text_y = zy + (zoom_h - zts.y) * 0.5f;
		dl->AddText(ImVec2(zoom_text_x, zoom_text_y),
		            aida::ui::with_alpha(tk.text_primary, alpha), zoom_buf);

		float sep_x = plus_b.x + 6.f;
		dl->AddLine(ImVec2(sep_x, zy + 6.f),
		            ImVec2(sep_x, zy + zoom_h - 6.f),
		            aida::ui::with_alpha(tk.border_subtle, alpha), 1.f);

		float fit_x = sep_x + 6.f;
		ImVec2 fit_a(fit_x, by);
		ImVec2 fit_b(fit_x + btn_sz, by + btn_sz);
		bool fit_hov = ImGui::IsMouseHoveringRect(fit_a, fit_b, false);
		if (fit_hov) {
			dl->AddRectFilled(fit_a, fit_b,
			                  aida::ui::with_alpha(tk.hover_wash, alpha), btn_sz * 0.5f);
		}
		{
			ImU32 fit_col = fit_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
			                        : aida::ui::with_alpha(tk.text_secondary, alpha);
			float fcx = (fit_a.x + fit_b.x) * 0.5f;
			float fcy = (fit_a.y + fit_b.y) * 0.5f;
			float rw = 12.f * 0.5f;
			float rh = 8.f * 0.5f;
			float tick = 3.f;
			ImVec2 r_tl(fcx - rw, fcy - rh);
			ImVec2 r_tr(fcx + rw, fcy - rh);
			ImVec2 r_bl(fcx - rw, fcy + rh);
			ImVec2 r_br(fcx + rw, fcy + rh);
			dl->AddLine(r_tl, ImVec2(r_tl.x + tick, r_tl.y), fit_col, 1.6f);
			dl->AddLine(r_tl, ImVec2(r_tl.x, r_tl.y + tick), fit_col, 1.6f);
			dl->AddLine(r_tr, ImVec2(r_tr.x - tick, r_tr.y), fit_col, 1.6f);
			dl->AddLine(r_tr, ImVec2(r_tr.x, r_tr.y + tick), fit_col, 1.6f);
			dl->AddLine(r_bl, ImVec2(r_bl.x + tick, r_bl.y), fit_col, 1.6f);
			dl->AddLine(r_bl, ImVec2(r_bl.x, r_bl.y - tick), fit_col, 1.6f);
			dl->AddLine(r_br, ImVec2(r_br.x - tick, r_br.y), fit_col, 1.6f);
			dl->AddLine(r_br, ImVec2(r_br.x, r_br.y - tick), fit_col, 1.6f);
		}

		float home_x = fit_b.x + 4.f;
		ImVec2 home_a(home_x, by);
		ImVec2 home_b(home_x + btn_sz, by + btn_sz);
		bool home_hov = ImGui::IsMouseHoveringRect(home_a, home_b, false);
		if (home_hov) {
			dl->AddRectFilled(home_a, home_b,
			                  aida::ui::with_alpha(tk.hover_wash, alpha), btn_sz * 0.5f);
		}
		{
			ImU32 home_col = home_hov ? aida::ui::with_alpha(tk.accent_u32, alpha)
			                          : aida::ui::with_alpha(tk.text_secondary, alpha);
			float hcx = (home_a.x + home_b.x) * 0.5f;
			float hcy = (home_a.y + home_b.y) * 0.5f;
			float arm = 7.f;
			dl->AddLine(ImVec2(hcx - arm, hcy), ImVec2(hcx + arm, hcy), home_col, 1.4f);
			dl->AddLine(ImVec2(hcx, hcy - arm), ImVec2(hcx, hcy + arm), home_col, 1.4f);
			dl->AddCircle(ImVec2(hcx, hcy), 4.f, home_col, 16, 1.4f);
			dl->AddCircleFilled(ImVec2(hcx, hcy), 1.6f, home_col, 8);
		}

		if (minus_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_state.target_zoom *= 0.85f;
			if (g_state.target_zoom < 0.1f) g_state.target_zoom = 0.1f;
		}
		if (plus_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_state.target_zoom *= 1.18f;
			if (g_state.target_zoom > 5.f) g_state.target_zoom = 5.f;
		}
		if (fit_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_state.fit_request = true;
		}
		if (home_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (g_state.entry_addr != 0) {
				for (int i = 0; i < static_cast<int>(g_state.blocks.size()); ++i) {
					auto& b = g_state.blocks[i];
					if (g_state.entry_addr >= b.start_addr && g_state.entry_addr < b.end_addr) {
						int node_idx = -1;
						for (int ni = 0; ni < static_cast<int>(g_state.graph.nodes.size()); ++ni) {
							if (g_state.graph.nodes[ni].id == i) { node_idx = ni; break; }
						}
						if (node_idx >= 0) {
							auto& nd = g_state.graph.nodes[node_idx];
							g_state.target_pan_x = -nd.x;
							g_state.target_pan_y = -(nd.y + nd.height * 0.5f);
							g_state.selected_block = i;
						}
						break;
					}
				}
			}
		}
	}

	{
		float mw = 220.f;
		float mh = 140.f;
		float mx = pos_x + width - mw - 14.f;
		float my = pos_y + height - mh - 14.f;
		ImVec2 ma(mx, my);
		ImVec2 mb(mx + mw, my + mh);

		aida::ui::blur::render_drop_shadow(dl, ma, mb, 10.f, 4, 0.32f * alpha);
		aida::ui::blur::render_glass_fill(dl, ma, mb, 10.f, alpha);
		aida::ui::blur::render_glass_border(dl, ma, mb, 10.f, alpha);

		dl->PushClipRect(ma, mb, true);

		{
			const char* mm_label = "Overview";
			ImFont* cap = aida::ui::fonts::caption();
			float lbl_size = 10.f;
			dl->AddText(cap, lbl_size,
			            ImVec2(mx + 8.f, my + 4.f),
			            aida::ui::with_alpha(tk.text_dim, alpha),
			            mm_label);
		}

		float wmin_x, wmin_y, wmax_x, wmax_y;
		detail::compute_world_bounds(g_state.graph, wmin_x, wmin_y, wmax_x, wmax_y);
		float ww = wmax_x - wmin_x;
		float wh = wmax_y - wmin_y;
		if (ww < 1.f) ww = 1.f;
		if (wh < 1.f) wh = 1.f;

		float pad = 10.f;
		float top_pad = 18.f;
		float scale_x = (mw - pad * 2.f) / ww;
		float scale_y = (mh - top_pad - pad) / wh;
		float scale = scale_x < scale_y ? scale_x : scale_y;

		float ox = mx + pad + ((mw - pad * 2.f) - ww * scale) * 0.5f;
		float oy = my + top_pad + ((mh - top_pad - pad) - wh * scale) * 0.5f;

		auto wts = [&](float wx, float wy) -> ImVec2 {
			return ImVec2(ox + (wx - wmin_x) * scale,
			              oy + (wy - wmin_y) * scale);
		};

		for (int ni = 0; ni < static_cast<int>(g_state.graph.nodes.size()); ++ni) {
			auto& n = g_state.graph.nodes[ni];
			if (n.id < 0 || n.id >= static_cast<int>(g_state.blocks.size())) continue;
			auto& blk = g_state.blocks[n.id];

			ImVec2 t1 = wts(n.x - n.width * 0.5f, n.y);
			ImVec2 t2 = wts(n.x + n.width * 0.5f, n.y + n.height);

			ImU32 nc;
			if (g_state.current_rip >= blk.start_addr && g_state.current_rip < blk.end_addr)
				nc = aida::ui::with_alpha(tk.accent_u32, alpha);
			else if (blk.is_entry)
				nc = aida::ui::with_alpha(tk.accent_dim, alpha);
			else if (n.id == g_state.selected_block)
				nc = aida::ui::with_alpha(tk.accent_hover, alpha);
			else
				nc = aida::ui::with_alpha(tk.text_secondary, alpha * 0.6f);

			dl->AddRectFilled(t1, t2, nc, 1.5f);
		}

		float view_world_w = width / z;
		float view_world_h = height / z;
		float view_world_x = -g_state.pan_x - view_world_w * 0.5f;
		float view_world_y = -g_state.pan_y - view_world_h * 0.5f;

		ImVec2 v1 = wts(view_world_x, view_world_y);
		ImVec2 v2 = wts(view_world_x + view_world_w, view_world_y + view_world_h);
		dl->AddRect(v1, v2, aida::ui::with_alpha(tk.accent_u32, alpha), 2.f, 0, 1.5f);
		dl->AddRectFilled(v1, v2, aida::ui::with_alpha(tk.accent_glow, alpha * 0.7f), 2.f);

		{
			ImU32 br_col = aida::ui::with_alpha(tk.accent_hover, alpha);
			float bo = 2.f;
			float bl = 6.f;
			float bt = 1.5f;
			ImVec2 c_tl(v1.x - bo, v1.y - bo);
			ImVec2 c_tr(v2.x + bo, v1.y - bo);
			ImVec2 c_bl(v1.x - bo, v2.y + bo);
			ImVec2 c_br(v2.x + bo, v2.y + bo);
			dl->AddLine(c_tl, ImVec2(c_tl.x + bl, c_tl.y), br_col, bt);
			dl->AddLine(c_tl, ImVec2(c_tl.x, c_tl.y + bl), br_col, bt);
			dl->AddLine(c_tr, ImVec2(c_tr.x - bl, c_tr.y), br_col, bt);
			dl->AddLine(c_tr, ImVec2(c_tr.x, c_tr.y + bl), br_col, bt);
			dl->AddLine(c_bl, ImVec2(c_bl.x + bl, c_bl.y), br_col, bt);
			dl->AddLine(c_bl, ImVec2(c_bl.x, c_bl.y - bl), br_col, bt);
			dl->AddLine(c_br, ImVec2(c_br.x - bl, c_br.y), br_col, bt);
			dl->AddLine(c_br, ImVec2(c_br.x, c_br.y - bl), br_col, bt);
		}

		dl->PopClipRect();

		bool minimap_hov = ImGui::IsMouseHoveringRect(ma, mb, false);
		if (minimap_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			g_state.minimap_dragging = true;
		if (g_state.minimap_dragging) {
			if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
				ImVec2 mp = ImGui::GetMousePos();
				float wx = wmin_x + (mp.x - ox) / scale;
				float wy = wmin_y + (mp.y - oy) / scale;
				g_state.target_pan_x = -wx;
				g_state.target_pan_y = -wy;
			} else {
				g_state.minimap_dragging = false;
			}
		}
	}

	dl->PopClipRect();
}

}
