#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../helpers/globals.h"
#include "disasm_view.hpp"
#include "cfg_view.hpp"
#include "pe_parser.hpp"
#include "symbol_store.hpp"
#include "rename_store.hpp"
#include "work_queue.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/fonts.hpp"
#include "ui/ui_anim.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

extern DisasmState g_disasm;

namespace functions_panel {

	struct function_entry_t {
		uint64_t    address = 0;
		uint32_t    size = 0;
		std::string name;
		std::string section;
		uint32_t    calls_in = 0;
		uint32_t    calls_out = 0;
		bool        synthetic_name = true;
	};

	struct view_state_t {
		std::mutex                     mtx;
		std::vector<function_entry_t>  entries;
		std::atomic<bool>              ready{false};
		std::atomic<bool>              building{false};
		std::atomic<bool>              cancel{false};
		uint64_t                       cached_module_base = 0;
		uint32_t                       cached_module_size = 0;
		std::string                    cached_module_name;
		uint64_t                       cached_pid_token = 0;

		char                           filter_buf[160] = {};
		std::string                    last_filter_lower;
		std::vector<int>               filtered_indices;
		bool                           filter_dirty = true;

		int                            selected_row = -1;
		uint64_t                       selected_addr = 0;
		float                          row_anim_time = 0.f;
		int                            ctx_row = -1;
		uint64_t                       ctx_addr = 0;

		int                            sort_column = 0;
		bool                           sort_ascending = true;
		bool                           sort_dirty = false;
		std::vector<int>               sorted_indices;
	};

	inline view_state_t& state() {
		static view_state_t s;
		return s;
	}

	namespace detail {

		inline std::string to_lower_copy(const std::string& s) {
			std::string out;
			out.resize(s.size());
			for (size_t i = 0; i < s.size(); ++i) {
				out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
			}
			return out;
		}

		inline std::string section_name_for_rva(const pe_parser::pe_info_t& pe, uint32_t rva) {
			for (const auto& s : pe.sections) {
				if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) {
					return s.name;
				}
			}
			return std::string();
		}

		inline std::string make_synthetic_name(uint64_t addr) {
			char buf[32];
			std::snprintf(buf, sizeof(buf), "sub_%llX",
				static_cast<unsigned long long>(addr));
			return std::string(buf);
		}

		inline std::string strip_module_prefix(const std::string& s) {
			auto pos = s.find('!');
			if (pos == std::string::npos) return s;
			return s.substr(pos + 1);
		}

		inline std::string resolve_function_name(uint64_t va, uint64_t module_base,
			const std::unordered_map<uint64_t, std::string>& export_lookup,
			bool& out_synthetic)
		{
			out_synthetic = false;

			std::string rn = rename_store::get(va);
			if (!rn.empty()) {
				return rn;
			}

			std::string sym = symbol_store::resolve_symbol_exact(va);
			if (!sym.empty()) {
				return sym;
			}

			auto it = export_lookup.find(va);
			if (it != export_lookup.end() && !it->second.empty()) {
				return it->second;
			}

			std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
			for (auto& [mod_name, ms] : symbol_store::g_state.modules) {
				if (!ms.pdb.loaded) continue;
				if (va < ms.base || va >= ms.base + ms.size) continue;
				uint64_t rva = va - ms.base;
				auto rit = ms.pdb.symbol_by_rva.find(rva);
				if (rit != ms.pdb.symbol_by_rva.end()) {
					return ms.pdb.symbols[rit->second].name;
				}
			}

			(void)module_base;
			out_synthetic = true;
			return make_synthetic_name(va);
		}

		inline bool read_runtime_function_table(uint64_t module_base,
			const pe_parser::pe_info_t& pe,
			std::vector<uint64_t>& out_starts,
			std::vector<uint32_t>& out_sizes)
		{
			out_starts.clear();
			out_sizes.clear();

			uint16_t dos_magic = 0;
			if (!pe_parser::detail::read_mem(module_base, &dos_magic, 2)) return false;
			if (dos_magic != 0x5A4D) return false;

			uint32_t e_lfanew = 0;
			if (!pe_parser::detail::read_mem(module_base + 0x3C, &e_lfanew, 4)) return false;
			if (e_lfanew == 0 || e_lfanew > 0x1000) return false;

			uint64_t opt_addr = module_base + e_lfanew + 24;

			uint16_t opt_magic = 0;
			if (!pe_parser::detail::read_mem(opt_addr, &opt_magic, 2)) return false;
			if (opt_magic != 0x020B) return true;

			uint32_t exception_dir_rva = 0;
			uint32_t exception_dir_size = 0;
			if (!pe_parser::detail::read_mem(opt_addr + 144, &exception_dir_rva, 4)) return false;
			if (!pe_parser::detail::read_mem(opt_addr + 148, &exception_dir_size, 4)) return false;
			if (exception_dir_rva == 0 || exception_dir_size < 12) return true;

			const uint32_t entry_size = 12;
			uint32_t count = exception_dir_size / entry_size;
			if (count == 0 || count > 0x100000) return true;

			std::vector<uint8_t> table;
			if (!driver_bridge::read_memory(module_base + exception_dir_rva,
				static_cast<size_t>(count) * entry_size, table))
			{
				return false;
			}
			if (table.size() < static_cast<size_t>(count) * entry_size) {
				count = static_cast<uint32_t>(table.size() / entry_size);
			}

			out_starts.reserve(count);
			out_sizes.reserve(count);
			for (uint32_t i = 0; i < count; ++i) {
				uint32_t begin_rva = 0;
				uint32_t end_rva = 0;
				std::memcpy(&begin_rva, table.data() + i * entry_size + 0, 4);
				std::memcpy(&end_rva, table.data() + i * entry_size + 4, 4);
				if (begin_rva == 0 || end_rva <= begin_rva) continue;
				if (begin_rva >= pe.size_of_image) continue;
				out_starts.push_back(module_base + begin_rva);
				uint32_t fsz = end_rva - begin_rva;
				if (fsz > 0x4000000u) fsz = 0x4000000u;
				out_sizes.push_back(fsz);
			}

			(void)pe;
			return true;
		}

		inline const driver_bridge::module_info_t* select_target_module(
			const std::vector<driver_bridge::module_info_t>& modules,
			const std::string& process_name)
		{
			if (modules.empty()) return nullptr;

			if (!process_name.empty()) {
				for (const auto& m : modules) {
					if (_stricmp(m.name.c_str(), process_name.c_str()) == 0) {
						return &m;
					}
				}
			}

			const driver_bridge::module_info_t* best = &modules.front();
			for (const auto& m : modules) {
				if (m.base != 0 && (best->base == 0 || m.base < best->base)) {
					best = &m;
				}
			}
			return best;
		}

		inline void build_locked(view_state_t& s, uint64_t module_base, uint32_t module_size,
			const std::string& module_name)
		{
			pe_parser::pe_info_t pe;
			if (!pe_parser::parse(module_base, pe)) {
				std::lock_guard<std::mutex> lk(s.mtx);
				s.entries.clear();
				s.cached_module_base = module_base;
				s.cached_module_size = module_size;
				s.cached_module_name = module_name;
				s.filter_dirty = true;
				s.sort_dirty = true;
				return;
			}

			std::vector<uint64_t> rf_starts;
			std::vector<uint32_t> rf_sizes;
			read_runtime_function_table(module_base, pe, rf_starts, rf_sizes);

			std::unordered_map<uint64_t, uint32_t> size_lookup;
			size_lookup.reserve(rf_starts.size());
			for (size_t i = 0; i < rf_starts.size(); ++i) {
				auto it = size_lookup.find(rf_starts[i]);
				if (it == size_lookup.end()) {
					size_lookup.emplace(rf_starts[i], rf_sizes[i]);
				}
				else {
					if (rf_sizes[i] > it->second) it->second = rf_sizes[i];
				}
			}

			std::unordered_map<uint64_t, std::string> export_lookup;
			export_lookup.reserve(pe.exports.size());
			for (const auto& exp : pe.exports) {
				if (exp.is_forwarded || exp.address == 0 || exp.name.empty()) continue;
				if (export_lookup.find(exp.address) == export_lookup.end()) {
					export_lookup.emplace(exp.address, exp.name);
				}
			}

			std::vector<uint64_t> candidate_addrs;
			candidate_addrs.reserve(rf_starts.size() + pe.exports.size() + 64);

			for (uint64_t va : rf_starts) {
				candidate_addrs.push_back(va);
			}

			for (const auto& exp : pe.exports) {
				if (exp.is_forwarded || exp.address == 0) continue;
				if (exp.address < module_base) continue;
				if (exp.address >= module_base + module_size) continue;
				candidate_addrs.push_back(exp.address);
			}

			{
				std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
				auto it = symbol_store::g_state.modules.find(module_name);
				if (it != symbol_store::g_state.modules.end() && it->second.pdb.loaded) {
					for (const auto& sym : it->second.pdb.symbols) {
						if (!sym.is_function) continue;
						if (sym.rva == 0) continue;
						uint64_t va = it->second.base + sym.rva;
						if (va < module_base || va >= module_base + module_size) continue;
						candidate_addrs.push_back(va);
					}
				}
			}

			if (pe.entry_point >= module_base && pe.entry_point < module_base + module_size) {
				candidate_addrs.push_back(pe.entry_point);
			}

			std::sort(candidate_addrs.begin(), candidate_addrs.end());
			candidate_addrs.erase(
				std::unique(candidate_addrs.begin(), candidate_addrs.end()),
				candidate_addrs.end());

			std::vector<function_entry_t> built;
			built.reserve(candidate_addrs.size());

			for (uint64_t va : candidate_addrs) {
				if (s.cancel.load(std::memory_order_acquire)) return;

				function_entry_t fn;
				fn.address = va;

				auto sit = size_lookup.find(va);
				fn.size = (sit != size_lookup.end()) ? sit->second : 0;

				bool synthetic = true;
				fn.name = resolve_function_name(va, module_base, export_lookup, synthetic);
				fn.synthetic_name = synthetic;

				if (va >= module_base && va < module_base + module_size) {
					uint32_t rva = static_cast<uint32_t>(va - module_base);
					fn.section = section_name_for_rva(pe, rva);
				}

				built.push_back(std::move(fn));
			}

			std::sort(built.begin(), built.end(),
				[](const function_entry_t& a, const function_entry_t& b) {
					return a.address < b.address;
				});

			{
				std::lock_guard<std::mutex> lk(s.mtx);
				s.entries = std::move(built);
				s.cached_module_base = module_base;
				s.cached_module_size = module_size;
				s.cached_module_name = module_name;
				s.filter_dirty = true;
				s.sort_dirty = true;
				s.selected_row = -1;
				s.selected_addr = 0;
			}
		}

		inline void launch_build_if_needed(view_state_t& s) {
			if (s.building.load(std::memory_order_acquire)) return;
			if (!driver_bridge::is_loaded()) return;

			auto modules = driver_bridge::enumerate_modules();
			if (modules.empty()) return;

			const auto process_name = driver_bridge::attached_process_name();
			const auto* m = select_target_module(modules, process_name);
			if (m == nullptr || m->base == 0 || m->size == 0) return;

			uint64_t pid_token = static_cast<uint64_t>(driver_bridge::attached_pid())
				^ (static_cast<uint64_t>(m->size) << 32);

			bool need_build = false;
			{
				std::lock_guard<std::mutex> lk(s.mtx);
				if (!s.ready.load(std::memory_order_acquire) ||
					s.cached_module_base != m->base ||
					s.cached_module_size != m->size ||
					s.cached_pid_token != pid_token)
				{
					need_build = true;
					s.cached_pid_token = pid_token;
				}
			}
			if (!need_build) return;

			bool expected = false;
			if (!s.building.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
			{
				return;
			}
			s.cancel.store(false, std::memory_order_release);
			s.ready.store(false, std::memory_order_release);

			uint64_t base = m->base;
			uint32_t size = m->size;
			std::string name = m->name;

			work_queue::post([base, size, name]() {
				auto& s = state();
				build_locked(s, base, size, name);
				s.ready.store(true, std::memory_order_release);
				s.building.store(false, std::memory_order_release);
			});
		}

		inline void rebuild_filter(view_state_t& s) {
			std::string current = to_lower_copy(s.filter_buf);
			if (!s.filter_dirty && current == s.last_filter_lower) return;
			s.last_filter_lower = current;
			s.filter_dirty = false;
			s.sort_dirty = true;

			std::lock_guard<std::mutex> lk(s.mtx);
			s.filtered_indices.clear();
			s.filtered_indices.reserve(s.entries.size());

			if (current.empty()) {
				for (int i = 0; i < static_cast<int>(s.entries.size()); ++i) {
					s.filtered_indices.push_back(i);
				}
				return;
			}

			std::string addr_query = current;
			if (addr_query.size() > 2 && addr_query[0] == '0' && addr_query[1] == 'x') {
				addr_query = addr_query.substr(2);
			}

			char addr_buf[32];
			for (int i = 0; i < static_cast<int>(s.entries.size()); ++i) {
				const auto& e = s.entries[i];
				bool matched = false;

				std::snprintf(addr_buf, sizeof(addr_buf), "%llx",
					static_cast<unsigned long long>(e.address));
				if (std::strstr(addr_buf, addr_query.c_str()) != nullptr) {
					matched = true;
				}

				if (!matched) {
					std::string lname = to_lower_copy(e.name);
					if (lname.find(current) != std::string::npos) matched = true;
				}

				if (!matched && !e.section.empty()) {
					std::string lsec = to_lower_copy(e.section);
					if (lsec.find(current) != std::string::npos) matched = true;
				}

				if (matched) s.filtered_indices.push_back(i);
			}
		}

		inline void apply_sort(view_state_t& s) {
			if (!s.sort_dirty) return;
			s.sort_dirty = false;

			std::lock_guard<std::mutex> lk(s.mtx);
			s.sorted_indices = s.filtered_indices;

			const int col = s.sort_column;
			const bool asc = s.sort_ascending;
			const auto& entries = s.entries;

			auto cmp = [col, asc, &entries](int ia, int ib) {
				const auto& a = entries[static_cast<size_t>(ia)];
				const auto& b = entries[static_cast<size_t>(ib)];
				int c = 0;
				switch (col) {
					case 0:
						if (a.address < b.address) c = -1;
						else if (a.address > b.address) c = 1;
						break;
					case 1:
						c = _stricmp(a.name.c_str(), b.name.c_str());
						break;
					case 2:
						if (a.size < b.size) c = -1;
						else if (a.size > b.size) c = 1;
						break;
					case 3:
						c = _stricmp(a.section.c_str(), b.section.c_str());
						break;
					case 4: {
						uint64_t ax = static_cast<uint64_t>(a.calls_in)
							+ static_cast<uint64_t>(a.calls_out);
						uint64_t bx = static_cast<uint64_t>(b.calls_in)
							+ static_cast<uint64_t>(b.calls_out);
						if (ax < bx) c = -1;
						else if (ax > bx) c = 1;
						break;
					}
					default:
						if (a.address < b.address) c = -1;
						else if (a.address > b.address) c = 1;
						break;
				}
				if (c == 0) {
					if (a.address < b.address) c = -1;
					else if (a.address > b.address) c = 1;
				}
				return asc ? (c < 0) : (c > 0);
			};

			std::sort(s.sorted_indices.begin(), s.sorted_indices.end(), cmp);
		}

		inline void jump_to_disasm(uint64_t addr) {
			if (addr == 0) return;
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(addr, g_disasm);
		}

		inline void open_in_graph(uint64_t addr) {
			if (addr == 0) return;
			cfg_view::build_cfg(addr);
			globals::ui::active_center_view = center_view_t::graph_view;
		}

		inline void show_xrefs_to(uint64_t addr) {
			if (addr == 0) return;
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(addr, g_disasm);
			disasm_view::g_state.xref_popup_open = true;
			disasm_view::g_state.xref_popup_addr = addr;
			disasm_view::g_state.xref_popup_fade = 0.f;
			disasm_view::g_state.xref_popup_selected = -1;
			disasm_view::g_state.xref_popup_filter[0] = '\0';
			{
				std::lock_guard<std::mutex> lk(disasm_view::g_state.xref_mutex);
				disasm_view::g_state.xref_results.clear();
			}
			char addr_buf[32];
			std::snprintf(addr_buf, sizeof(addr_buf), "sub_%llX",
				static_cast<unsigned long long>(addr));
			std::string rn = rename_store::get(addr);
			if (!rn.empty()) {
				disasm_view::g_state.xref_popup_target_name = rn;
			} else {
				std::string sym = symbol_store::resolve_symbol_exact(addr);
				disasm_view::g_state.xref_popup_target_name = sym.empty()
					? std::string(addr_buf) : strip_module_prefix(sym);
			}
		}

		inline ImU32 alpha_u32(ImU32 c, float a) {
			return aida::ui::with_alpha(c, a);
		}

		inline void draw_loading_strip(ImDrawList* dl, ImVec2 a, ImVec2 b, ImU32 col) {
			float t = aida::ui::clock::seconds() * 1.2f;
			float phase = t - std::floor(t);
			float w = b.x - a.x;
			float bw = w * 0.30f;
			float bx = a.x + (w + bw) * phase - bw;
			ImVec2 ba = ImVec2(bx, a.y);
			ImVec2 bb = ImVec2(bx + bw, b.y);
			if (ba.x < a.x) ba.x = a.x;
			if (bb.x > b.x) bb.x = b.x;
			dl->PushClipRect(a, b, true);
			dl->AddRectFilledMultiColor(ba, bb,
				aida::ui::with_alpha(col, 0.f),
				aida::ui::with_alpha(col, 1.f),
				aida::ui::with_alpha(col, 1.f),
				aida::ui::with_alpha(col, 0.f));
			dl->PopClipRect();
		}

	}

	inline void render(float x, float y, float w, float h) {
		auto& s = state();
		const auto& th = aida::ui::resolved();
		const float dt = aida::ui::clock::dt();
		s.row_anim_time += dt;

		detail::launch_build_if_needed(s);

		ImGui::SetNextWindowPos(ImVec2(x, y));
		ImGui::SetNextWindowSize(ImVec2(w, h));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
		ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(th.bg_base));

		const ImGuiWindowFlags wflags =
			ImGuiWindowFlags_NoTitleBar |
			ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoScrollbar |
			ImGuiWindowFlags_NoScrollWithMouse |
			ImGuiWindowFlags_NoBringToFrontOnFocus;

		ImGui::Begin("##functions_panel_root", nullptr, wflags);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();

		const float header_h = 78.f;
		const float pad = 10.f;

		ImVec2 hdr_a = ImVec2(wp.x, wp.y);
		ImVec2 hdr_b = ImVec2(wp.x + w, wp.y + header_h);
		dl->AddRectFilledMultiColor(hdr_a, hdr_b,
			th.panel_header, th.panel_header, th.panel_bg, th.panel_bg);
		dl->AddLine(ImVec2(hdr_a.x, hdr_b.y - 0.5f),
			ImVec2(hdr_b.x, hdr_b.y - 0.5f), th.border_subtle, 1.f);

		ImFont* title_font = aida::ui::fonts::body_strong();
		if (!title_font) title_font = ImGui::GetFont();
		ImFont* body_font = aida::ui::fonts::body();
		if (!body_font) body_font = ImGui::GetFont();
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = body_font;
		ImFont* caption_font = aida::ui::fonts::caption();
		if (!caption_font) caption_font = body_font;

		dl->AddText(title_font, 16.f,
			ImVec2(wp.x + pad + 2.f, wp.y + 8.f),
			th.text_primary, "Functions");

		size_t total_count = 0;
		size_t shown_count = 0;
		bool ready = s.ready.load(std::memory_order_acquire);
		bool building = s.building.load(std::memory_order_acquire);
		std::string module_name_local;
		{
			std::lock_guard<std::mutex> lk(s.mtx);
			total_count = s.entries.size();
			module_name_local = s.cached_module_name;
		}

		ImGui::PushFont(body_font);

		const float input_y = 32.f;
		const float input_h = 30.f;
		const float input_w_max = w - pad * 2.f - 110.f;
		float input_w = input_w_max;
		if (input_w < 120.f) input_w = w - pad * 2.f;

		ImGui::SetCursorScreenPos(ImVec2(wp.x + pad, wp.y + input_y));
		bool filter_changed = aida::ui::input_text(
			"##fn_filter", s.filter_buf, sizeof(s.filter_buf),
			"Filter functions...", false,
			ImVec2(input_w, input_h));
		if (filter_changed) {
			s.filter_dirty = true;
		}

		if (input_w_max == input_w && input_w_max < w - pad * 2.f) {
			char count_buf[48];
			std::snprintf(count_buf, sizeof(count_buf), "%zu functions", total_count);
			ImFont* badge_font = caption_font;
			float bfs = 13.f;
			float bw = badge_font->CalcTextSizeA(bfs, FLT_MAX, 0.f, count_buf).x + 16.f;
			float bh = 22.f;
			ImVec2 ba = ImVec2(wp.x + w - pad - bw, wp.y + input_y + (input_h - bh) * 0.5f);
			ImVec2 bb = ImVec2(ba.x + bw, ba.y + bh);
			ImU32 badge_col = building
				? aida::ui::mix(th.panel_header, th.accent_u32, 0.35f)
				: aida::ui::with_alpha(th.accent_u32, 0.85f);
			dl->AddRectFilled(ba, bb, badge_col, 4.f);
			ImU32 text_on_badge = IM_COL32(255, 255, 255, 240);
			dl->AddText(badge_font, bfs,
				ImVec2(ba.x + 8.f, ba.y + (bh - bfs) * 0.5f),
				text_on_badge, count_buf);
		}

		if (!module_name_local.empty()) {
			char sub_buf[256];
			std::snprintf(sub_buf, sizeof(sub_buf), "Module: %s", module_name_local.c_str());
			dl->AddText(caption_font, 12.f,
				ImVec2(wp.x + pad + 2.f, wp.y + header_h - 18.f),
				th.text_dim, sub_buf);
		}

		if (building) {
			float bar_y = wp.y + header_h - 3.f;
			detail::draw_loading_strip(dl,
				ImVec2(wp.x, bar_y),
				ImVec2(wp.x + w, bar_y + 2.f),
				th.accent_u32);
		}

		ImGui::SetCursorScreenPos(ImVec2(wp.x + pad, wp.y + header_h + 4.f));

		const float content_h = h - header_h - 8.f;
		ImVec2 content_pos = ImVec2(wp.x + pad, wp.y + header_h + 4.f);
		ImVec2 content_size = ImVec2(w - pad * 2.f, content_h);

		if (!ready && building) {
			ImGui::BeginChild("##fn_loading", content_size, false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);
			ImVec2 cp = ImGui::GetCursorScreenPos();
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::cpu;
			cfg.title = "Building functions list...";
			cfg.body = "Walking exception directory and resolving symbols on a worker thread.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
			ImGui::EndChild();
			ImGui::PopFont();
			ImGui::End();
			ImGui::PopStyleColor();
			ImGui::PopStyleVar(2);
			return;
		}

		if (!ready && !building) {
			ImGui::BeginChild("##fn_empty_no_module", content_size, false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);
			ImVec2 cp = ImGui::GetCursorScreenPos();
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
			cfg.title = "No analyzed functions yet";
			cfg.body = "Open a module to populate.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
			ImGui::EndChild();
			ImGui::PopFont();
			ImGui::End();
			ImGui::PopStyleColor();
			ImGui::PopStyleVar(2);
			return;
		}

		detail::rebuild_filter(s);
		detail::apply_sort(s);

		{
			std::lock_guard<std::mutex> lk(s.mtx);
			shown_count = s.sorted_indices.size();
		}

		ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(8.f, 5.f));
		ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, th.panel_header);
		ImGui::PushStyleColor(ImGuiCol_TableBorderLight, th.border_subtle);
		ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, th.border_subtle);
		ImGui::PushStyleColor(ImGuiCol_TableRowBg, ImVec4(0.f, 0.f, 0.f, 0.f));
		ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt,
			ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_bg, 0.45f)));

		const ImGuiTableFlags tflags =
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_Reorderable |
			ImGuiTableFlags_Sortable |
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_BordersInnerV |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_NoSavedSettings |
			ImGuiTableFlags_SizingStretchProp;

		ImVec2 outer = ImVec2(content_size.x, content_size.y);
		ImGui::SetCursorScreenPos(content_pos);
		bool ctx_menu_request = false;

		if (ImGui::BeginTable("##fn_table", 5, tflags, outer)) {
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 132.f);
			ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.0f);
			ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 76.f);
			ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 88.f);
			ImGui::TableSetupColumn("Calls", ImGuiTableColumnFlags_WidthFixed, 72.f);

			ImGui::PushFont(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : body_font);
			ImGui::TableHeadersRow();
			ImGui::PopFont();

			if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs()) {
				if (sort_specs->SpecsDirty && sort_specs->SpecsCount > 0) {
					int col = sort_specs->Specs[0].ColumnIndex;
					bool asc = sort_specs->Specs[0].SortDirection == ImGuiSortDirection_Ascending;
					if (col != s.sort_column || asc != s.sort_ascending) {
						s.sort_column = col;
						s.sort_ascending = asc;
						s.sort_dirty = true;
						detail::apply_sort(s);
					}
					sort_specs->SpecsDirty = false;
				}
			}

			std::vector<int> row_view;
			{
				std::lock_guard<std::mutex> lk(s.mtx);
				row_view = s.sorted_indices;
			}

			ImGuiListClipper clipper;
			clipper.Begin(static_cast<int>(row_view.size()), 22.f);
			while (clipper.Step()) {
				for (int row_idx = clipper.DisplayStart; row_idx < clipper.DisplayEnd; ++row_idx) {
					int entry_idx = row_view[static_cast<size_t>(row_idx)];

					function_entry_t e;
					{
						std::lock_guard<std::mutex> lk(s.mtx);
						if (entry_idx < 0 || entry_idx >= static_cast<int>(s.entries.size())) {
							continue;
						}
						e = s.entries[static_cast<size_t>(entry_idx)];
					}

					ImGui::TableNextRow(0, 22.f);
					ImGui::TableSetColumnIndex(0);

					bool is_selected = (s.selected_addr != 0 && s.selected_addr == e.address);

					ImGui::PushID(row_idx);
					char sel_label[32];
					std::snprintf(sel_label, sizeof(sel_label), "##fn_sel_%d", row_idx);

					if (ImGui::Selectable(sel_label, is_selected,
						ImGuiSelectableFlags_SpanAllColumns |
						ImGuiSelectableFlags_AllowDoubleClick |
						ImGuiSelectableFlags_AllowItemOverlap,
						ImVec2(0.f, 20.f)))
					{
						s.selected_row = row_idx;
						s.selected_addr = e.address;
						if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
							detail::jump_to_disasm(e.address);
						}
					}

					if (ImGui::IsItemFocused() &&
						(ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
						 ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false)))
					{
						detail::jump_to_disasm(e.address);
					}

					if (is_selected && ImGui::IsKeyPressed(ImGuiKey_Space, false) &&
						!ImGui::IsAnyItemActive() &&
						!ImGui::GetIO().WantCaptureKeyboard)
					{
						detail::open_in_graph(e.address);
					}

					if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
						s.ctx_row = row_idx;
						s.ctx_addr = e.address;
						s.selected_row = row_idx;
						s.selected_addr = e.address;
						ctx_menu_request = true;
					}

					ImGui::PopID();

					ImGui::SameLine();
					ImGui::PushFont(code_font);
					char addr_str[32];
					std::snprintf(addr_str, sizeof(addr_str), "0x%llX",
						static_cast<unsigned long long>(e.address));
					ImGui::PushStyleColor(ImGuiCol_Text,
						ImGui::ColorConvertU32ToFloat4(th.text_address));
					ImGui::TextUnformatted(addr_str);
					ImGui::PopStyleColor();
					ImGui::PopFont();

					ImGui::TableSetColumnIndex(1);
					ImGui::PushFont(code_font);
					ImU32 name_col = e.synthetic_name ? th.text_dim : th.text_primary;
					ImGui::PushStyleColor(ImGuiCol_Text,
						ImGui::ColorConvertU32ToFloat4(name_col));
					ImGui::TextUnformatted(e.name.c_str());
					ImGui::PopStyleColor();
					ImGui::PopFont();
					if (ImGui::IsItemHovered()) {
						ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.f, 6.f));
						if (ImGui::BeginTooltip()) {
							ImGui::PushFont(code_font);
							ImGui::TextUnformatted(e.name.c_str());
							ImGui::PopFont();
							ImGui::EndTooltip();
						}
						ImGui::PopStyleVar();
					}

					ImGui::TableSetColumnIndex(2);
					ImGui::PushFont(code_font);
					if (e.size > 0) {
						char size_buf[24];
						if (e.size >= 1024) {
							std::snprintf(size_buf, sizeof(size_buf), "%u (%.1fK)",
								e.size, static_cast<double>(e.size) / 1024.0);
						}
						else {
							std::snprintf(size_buf, sizeof(size_buf), "%u", e.size);
						}
						ImGui::PushStyleColor(ImGuiCol_Text,
							ImGui::ColorConvertU32ToFloat4(th.text_secondary));
						ImGui::TextUnformatted(size_buf);
						ImGui::PopStyleColor();
					}
					else {
						ImGui::PushStyleColor(ImGuiCol_Text,
							ImGui::ColorConvertU32ToFloat4(th.text_dim));
						ImGui::TextUnformatted("-");
						ImGui::PopStyleColor();
					}
					ImGui::PopFont();

					ImGui::TableSetColumnIndex(3);
					if (e.section.empty()) {
						ImGui::PushStyleColor(ImGuiCol_Text,
							ImGui::ColorConvertU32ToFloat4(th.text_dim));
						ImGui::TextUnformatted("-");
						ImGui::PopStyleColor();
					}
					else {
						ImGui::PushFont(code_font);
						ImGui::PushStyleColor(ImGuiCol_Text,
							ImGui::ColorConvertU32ToFloat4(th.text_secondary));
						ImGui::TextUnformatted(e.section.c_str());
						ImGui::PopStyleColor();
						ImGui::PopFont();
					}

					ImGui::TableSetColumnIndex(4);
					ImGui::PushFont(code_font);
					char calls_buf[32];
					std::snprintf(calls_buf, sizeof(calls_buf), "%u/%u",
						e.calls_in, e.calls_out);
					ImGui::PushStyleColor(ImGuiCol_Text,
						ImGui::ColorConvertU32ToFloat4(th.text_dim));
					ImGui::TextUnformatted(calls_buf);
					ImGui::PopStyleColor();
					ImGui::PopFont();
				}
			}
			clipper.End();

			ImGui::EndTable();
		}

		ImGui::PopStyleColor(5);
		ImGui::PopStyleVar();

		if (ctx_menu_request) {
			ImGui::OpenPopup("##fn_ctx_menu");
		}

		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.f, 6.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.f, 4.f));
		ImGui::PushStyleColor(ImGuiCol_PopupBg, th.bg_overlay);
		ImGui::PushStyleColor(ImGuiCol_Border, th.border_subtle);
		if (ImGui::BeginPopup("##fn_ctx_menu")) {
			uint64_t target = s.ctx_addr;
			if (ImGui::MenuItem("Goto in disassembly")) {
				detail::jump_to_disasm(target);
			}
			if (ImGui::MenuItem("Show xrefs to", "X")) {
				detail::show_xrefs_to(target);
			}
			if (ImGui::MenuItem("Open in graph view", "Space")) {
				detail::open_in_graph(target);
			}
			ImGui::EndPopup();
		}
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar(3);

		if (ready && !building && total_count == 0) {
			ImVec2 cp = ImVec2(wp.x + pad, wp.y + header_h + 8.f);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
			cfg.title = "No analyzed functions yet";
			cfg.body = "Open a module to populate.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
		}
		else if (ready && shown_count == 0 && total_count > 0) {
			ImVec2 cp = ImVec2(wp.x + pad, wp.y + header_h + 8.f);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::search;
			cfg.title = "No matches";
			cfg.body = "No functions match the current filter.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
		}

		ImGui::PopFont();

		ImGui::End();
		ImGui::PopStyleColor();
		ImGui::PopStyleVar(2);
	}

}
