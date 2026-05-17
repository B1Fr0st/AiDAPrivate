#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "function_index.hpp"
#include "functions_panel.hpp"
#include "pe_parser.hpp"
#include "xref_engine.hpp"
#include "standalone_driver.hpp"
#include "work_queue.hpp"
#include "zydis_disasm.hpp"

namespace xref_index {

	enum class kind_t { code, data };
	enum class edge_t { jump, call_proc, offset_ref };

	struct annotation_t {
		kind_t      kind = kind_t::code;
		edge_t      edge = edge_t::jump;
		bool        up = false;
		uint64_t    source_addr = 0;
		std::string source_label;
	};

	namespace detail {

		enum class build_state_t : uint32_t {
			idle = 0,
			building = 1,
			built = 2,
			failed = 3
		};

		struct module_index_t {
			std::string                                             name;
			uint64_t                                                base = 0;
			uint32_t                                                size = 0;
			bool                                                    is_static_pe = false;
			std::string                                             static_pe_path;
			std::vector<pe_parser::section_info_t>                  sections;
			std::unordered_map<uint64_t, std::vector<annotation_t>> to_index;
			std::atomic<uint32_t>                                   state{static_cast<uint32_t>(build_state_t::idle)};
		};

		inline bool xref_static_pe_active() {
			if (driver_bridge::attached_pid() != 0) return false;
			if (!g_disasm.file.loaded) return false;
			if (g_disasm.file.path.empty()) return false;
			if (g_disasm.file.path.compare(0, 7, "live://") == 0) return false;
			if (g_disasm.file.image_base == 0) return false;
			return true;
		}

		inline bool fetch_static_pe_module(std::string& out_name, uint64_t& out_base,
			uint32_t& out_size, std::string& out_path)
		{
			if (!xref_static_pe_active()) return false;
			uint64_t img_sz = static_analysis::total_image_size(g_disasm.file);
			if (img_sz == 0) return false;
			if (img_sz > 0xFFFFFFFFull) img_sz = 0xFFFFFFFFull;
			out_base = g_disasm.file.image_base;
			out_size = static_cast<uint32_t>(img_sz);
			out_name = g_disasm.file.filename.empty()
				? g_disasm.file.path
				: g_disasm.file.filename;
			out_path = g_disasm.file.path;
			return true;
		}

		struct module_range_t {
			uint64_t                          start_va = 0;
			uint64_t                          end_va = 0;
			std::string                       name;
			std::shared_ptr<module_index_t>   index;
		};

		struct registry_t {
			std::shared_mutex                                                rw;
			std::unordered_map<std::string, std::shared_ptr<module_index_t>> modules;
			std::vector<module_range_t>                                      table;
			std::atomic<uint64_t>                                            generation{0};
			std::atomic<bool>                                                table_built{false};
			std::atomic<bool>                                                rebuild_in_flight{false};
		};

		inline std::unique_ptr<registry_t>& registry_holder() {
			static std::unique_ptr<registry_t> h = std::make_unique<registry_t>();
			return h;
		}

		inline registry_t& registry() {
			return *registry_holder();
		}

		inline edge_t classify_edge(xref_engine::xref_type_t t) {
			switch (t) {
				case xref_engine::xref_type_t::call:             return edge_t::call_proc;
				case xref_engine::xref_type_t::jump:             return edge_t::jump;
				case xref_engine::xref_type_t::conditional_jump: return edge_t::jump;
				case xref_engine::xref_type_t::lea:              return edge_t::offset_ref;
				case xref_engine::xref_type_t::data_ref:         return edge_t::offset_ref;
			}
			return edge_t::offset_ref;
		}

		inline kind_t classify_kind(xref_engine::xref_type_t t) {
			switch (t) {
				case xref_engine::xref_type_t::call:             return kind_t::code;
				case xref_engine::xref_type_t::jump:             return kind_t::code;
				case xref_engine::xref_type_t::conditional_jump: return kind_t::code;
				case xref_engine::xref_type_t::lea:              return kind_t::data;
				case xref_engine::xref_type_t::data_ref:         return kind_t::data;
			}
			return kind_t::data;
		}

		inline std::string section_name_for_addr(const std::vector<pe_parser::section_info_t>& sections,
			uint64_t module_base, uint64_t addr)
		{
			if (addr < module_base) return std::string();
			uint64_t rva64 = addr - module_base;
			if (rva64 > 0xFFFFFFFFull) return std::string();
			uint32_t rva = static_cast<uint32_t>(rva64);
			for (const auto& s : sections) {
				if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
					return s.name;
			}
			return std::string();
		}

		inline std::string make_function_offset_label(const std::string& name, uint64_t offset) {
			char buf[64];
			std::snprintf(buf, sizeof(buf), "%s+%llX",
				name.c_str(), static_cast<unsigned long long>(offset));
			return std::string(buf);
		}

		inline std::string make_segment_label(const std::string& seg_or_module, uint64_t addr) {
			char buf[96];
			std::snprintf(buf, sizeof(buf), "%s:%08llX",
				seg_or_module.c_str(), static_cast<unsigned long long>(addr));
			return std::string(buf);
		}

		inline bool find_enclosing_function(uint64_t addr,
			const std::vector<functions_panel::function_entry_t>& fns,
			functions_panel::function_entry_t& out)
		{
			if (fns.empty()) return false;
			auto it = std::upper_bound(fns.begin(), fns.end(), addr,
				[](uint64_t a, const functions_panel::function_entry_t& e) {
					return a < e.address;
				});
			if (it == fns.begin()) return false;
			--it;
			if (addr < it->address) return false;
			if (it->size != 0) {
				if (addr >= it->address + it->size) return false;
			} else {
				if (addr - it->address > 0x40000ull) return false;
			}
			out = *it;
			return true;
		}

		inline std::string resolve_source_label(uint64_t source_addr,
			const std::vector<functions_panel::function_entry_t>& fns,
			const std::vector<pe_parser::section_info_t>& sections,
			uint64_t module_base, const std::string& module_name)
		{
			functions_panel::function_entry_t fn;
			if (find_enclosing_function(source_addr, fns, fn)) {
				return make_function_offset_label(fn.name, source_addr - fn.address);
			}
			std::string seg = section_name_for_addr(sections, module_base, source_addr);
			if (seg.empty()) seg = module_name.empty() ? std::string("seg") : module_name;
			return make_segment_label(seg, source_addr);
		}

		inline bool sort_less(const annotation_t& a, const annotation_t& b) {
			if (a.up != b.up) return a.up && !b.up;
			if (a.source_addr != b.source_addr) return a.source_addr < b.source_addr;
			if (a.kind != b.kind) return static_cast<int>(a.kind) < static_cast<int>(b.kind);
			return static_cast<int>(a.edge) < static_cast<int>(b.edge);
		}

		inline std::vector<functions_panel::function_entry_t> snapshot_functions(uint64_t module_base, uint32_t module_size) {
			std::vector<functions_panel::function_entry_t> out;
			auto& fs = functions_panel::state();
			if (fs.ready.load(std::memory_order_acquire)) {
				std::lock_guard<std::mutex> lk(fs.mtx);
				out.reserve(fs.entries.size());
				for (const auto& e : fs.entries) {
					if (e.address >= module_base && e.address < module_base + module_size)
						out.push_back(e);
				}
			}
			if (out.empty()) {
				auto& fc = function_index::detail::cache();
				std::shared_lock<std::shared_mutex> lk(fc.mutex);
				out.reserve(fc.sorted_starts.size());
				for (uint64_t start : fc.sorted_starts) {
					if (start < module_base) continue;
					if (start >= module_base + module_size) continue;
					functions_panel::function_entry_t fe;
					fe.address = start;
					auto bit = fc.by_start.find(start);
					if (bit != fc.by_start.end()) {
						uint64_t end = bit->second.end;
						if (end > start && (end - start) <= 0xFFFFFFFFull) {
							fe.size = static_cast<uint32_t>(end - start);
						}
						fe.name = bit->second.display_name;
						fe.section = bit->second.section;
					}
					if (fe.name.empty()) {
						auto sit = fc.synthetic_names.find(start);
						if (sit != fc.synthetic_names.end() && !sit->second.empty()) {
							fe.name = sit->second;
						} else {
							fe.name = function_index::detail::make_synthetic_sub(start);
						}
					}
					out.push_back(std::move(fe));
				}
			}
			std::sort(out.begin(), out.end(),
				[](const functions_panel::function_entry_t& a, const functions_panel::function_entry_t& b) {
					return a.address < b.address;
				});
			return out;
		}

		inline bool build_static_pe_pe_info(const std::string& disk_path,
			functions_panel::detail::disk_pe_view_t& out_view,
			pe_parser::pe_info_t& out_pe)
		{
			if (disk_path.empty()) return false;
			if (!functions_panel::detail::disk_read_whole_file(disk_path, out_view.raw)) return false;
			if (!functions_panel::detail::disk_parse_pe(out_view)) return false;
			out_pe.image_base = out_view.image_base;
			out_pe.entry_point = (out_view.entry_rva != 0)
				? (out_view.image_base + out_view.entry_rva)
				: 0;
			out_pe.size_of_image = out_view.size_of_image;
			out_pe.is_64bit = out_view.is_pe32_plus;
			out_pe.export_dir_rva = out_view.export_dir_rva;
			out_pe.export_dir_size = out_view.export_dir_size;
			out_pe.sections.reserve(out_view.sections.size());
			for (const auto& s : out_view.sections) {
				pe_parser::section_info_t si;
				si.name = s.name;
				si.virtual_address = s.virtual_address;
				si.virtual_size = (s.virtual_size != 0) ? s.virtual_size : s.raw_size;
				si.raw_size = s.raw_size;
				si.characteristics = s.characteristics;
				out_pe.sections.push_back(std::move(si));
			}
			if (!out_view.raw.empty() && out_view.raw.size() >= sizeof(IMAGE_DOS_HEADER)) {
				const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(out_view.raw.data());
				uint32_t pe_off = static_cast<uint32_t>(dos->e_lfanew);
				if (out_view.is_pe32_plus
					&& pe_off + sizeof(IMAGE_NT_HEADERS64) <= out_view.raw.size())
				{
					const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
						out_view.raw.data() + pe_off);
					out_pe.subsystem = nt64->OptionalHeader.Subsystem;
					out_pe.characteristics = nt64->FileHeader.Characteristics;
				}
				else if (!out_view.is_pe32_plus
					&& pe_off + sizeof(IMAGE_NT_HEADERS32) <= out_view.raw.size())
				{
					const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
						out_view.raw.data() + pe_off);
					out_pe.subsystem = nt32->OptionalHeader.Subsystem;
					out_pe.characteristics = nt32->FileHeader.Characteristics;
				}
			}
			return true;
		}

		inline void scan_block_for_xrefs(
			const uint8_t* data, size_t length, uint64_t base_va,
			const std::vector<functions_panel::function_entry_t>& fns,
			const std::vector<pe_parser::section_info_t>& sections,
			uint64_t module_base, const std::string& module_name,
			std::unordered_map<uint64_t, std::vector<annotation_t>>& map)
		{
			if (!data || length == 0) return;
			int sz = static_cast<int>(length);
			int pos = 0;
			while (pos < sz) {
				int avail = sz - pos;
				if (avail > 15) avail = 15;

				uint64_t ins_addr = base_va + static_cast<uint64_t>(pos);
				AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);
				if (ins.len <= 0) {
					pos += 1;
					continue;
				}

				uint64_t target = 0;
				if (xref_engine::detail::extract_target(data + pos, ins.len, ins_addr, ins, target)) {
					xref_engine::xref_type_t t = xref_engine::detail::classify_instruction(ins);

					annotation_t ann;
					ann.kind = classify_kind(t);
					ann.edge = classify_edge(t);
					ann.up = (ins_addr < target);
					ann.source_addr = ins_addr;
					ann.source_label = resolve_source_label(ins_addr, fns, sections, module_base, module_name);

					map[target].push_back(std::move(ann));
				}

				pos += ins.len;
			}
		}

		inline bool section_is_code(uint32_t characteristics) {
			const uint32_t exec_mask = 0x20000000u;
			const uint32_t code_mask = 0x00000020u;
			return (characteristics & exec_mask) != 0
				|| (characteristics & code_mask) != 0;
		}

		inline bool section_is_data_readable(uint32_t characteristics) {
			const uint32_t exec_mask = 0x20000000u;
			const uint32_t read_mask = 0x40000000u;
			const uint32_t init_data_mask = 0x00000040u;
			const uint32_t uninit_data_mask = 0x00000080u;
			if (characteristics & exec_mask) return false;
			if (characteristics & uninit_data_mask) return false;
			if (characteristics & init_data_mask) return true;
			if (characteristics & read_mask) return true;
			return false;
		}

		inline void scan_data_section_for_pointers(
			const functions_panel::detail::disk_pe_view_t& v,
			const functions_panel::detail::disk_section_t& sec,
			uint64_t module_base, uint32_t module_size,
			const std::vector<functions_panel::function_entry_t>& fns,
			const std::vector<pe_parser::section_info_t>& sections,
			const std::string& module_name,
			std::unordered_map<uint64_t, std::vector<annotation_t>>& map)
		{
			if (sec.raw_size == 0 || sec.raw_offset == 0) return;
			if (static_cast<uint64_t>(sec.raw_offset) + sec.raw_size > v.raw.size()) return;
			const uint8_t* data = v.raw.data() + sec.raw_offset;
			uint64_t base_va = module_base + sec.virtual_address;
			uint32_t avail = sec.raw_size;
			if (avail > sec.virtual_size && sec.virtual_size > 0) avail = sec.virtual_size;

			std::vector<std::pair<uint64_t, uint64_t>> code_ranges;
			code_ranges.reserve(sections.size());
			for (const auto& s : sections) {
				if (!section_is_code(s.characteristics)) continue;
				uint64_t lo = module_base + s.virtual_address;
				uint64_t hi = lo + (s.virtual_size != 0 ? s.virtual_size : s.raw_size);
				if (hi > lo) code_ranges.emplace_back(lo, hi);
			}
			if (code_ranges.empty()) return;

			auto is_code_target = [&](uint64_t target) {
				for (const auto& r : code_ranges) {
					if (target >= r.first && target < r.second) return true;
				}
				return false;
			};

			if (v.is_pe32_plus) {
				for (uint32_t off = 0; off + 8 <= avail; off += 8) {
					uint64_t ptr = 0;
					std::memcpy(&ptr, data + off, 8);
					if (ptr < module_base) continue;
					if (ptr >= module_base + module_size) continue;
					if (!is_code_target(ptr)) continue;
					uint64_t src_va = base_va + off;
					annotation_t ann;
					ann.kind = kind_t::data;
					ann.edge = edge_t::offset_ref;
					ann.up = (src_va < ptr);
					ann.source_addr = src_va;
					ann.source_label = resolve_source_label(src_va, fns, sections, module_base, module_name);
					map[ptr].push_back(std::move(ann));
				}
			}
			else {
				for (uint32_t off = 0; off + 4 <= avail; off += 4) {
					uint32_t ptr32 = 0;
					std::memcpy(&ptr32, data + off, 4);
					uint64_t ptr = ptr32;
					if (ptr < module_base) continue;
					if (ptr >= module_base + module_size) continue;
					if (!is_code_target(ptr)) continue;
					uint64_t src_va = base_va + off;
					annotation_t ann;
					ann.kind = kind_t::data;
					ann.edge = edge_t::offset_ref;
					ann.up = (src_va < ptr);
					ann.source_addr = src_va;
					ann.source_label = resolve_source_label(src_va, fns, sections, module_base, module_name);
					map[ptr].push_back(std::move(ann));
				}
			}
		}

		inline void build_module_to_index_live(std::shared_ptr<module_index_t> mod) {
			pe_parser::pe_info_t pe;
			std::vector<pe_parser::section_info_t> sections;
			if (pe_parser::parse(mod->base, pe))
				sections = pe.sections;

			auto fns = snapshot_functions(mod->base, mod->size);

			std::unordered_map<uint64_t, std::vector<annotation_t>> map;
			map.reserve(4096);

			const size_t page_size = 4096;
			const uint64_t module_size = mod->size;

			for (uint64_t offset = 0; offset < module_size; offset += page_size) {
				if (driver_bridge::attached_pid() == 0) {
					mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
					return;
				}

				size_t chunk = page_size;
				if (offset + chunk > module_size)
					chunk = static_cast<size_t>(module_size - offset);

				std::vector<uint8_t> page_data;
				if (!driver_bridge::read_memory(mod->base + offset, chunk, page_data) || page_data.empty())
					continue;

				scan_block_for_xrefs(page_data.data(), page_data.size(),
					mod->base + offset, fns, sections, mod->base, mod->name, map);
			}

			for (auto& kv : map) {
				std::sort(kv.second.begin(), kv.second.end(), sort_less);
			}

			mod->sections = std::move(sections);
			mod->to_index = std::move(map);
			mod->state.store(static_cast<uint32_t>(build_state_t::built), std::memory_order_release);
		}

		inline void build_module_to_index_static(std::shared_ptr<module_index_t> mod) {
			std::string disk_path = mod->static_pe_path;
			if (disk_path.empty()) disk_path = g_disasm.file.path;

			functions_panel::detail::disk_pe_view_t view;
			pe_parser::pe_info_t pe;
			std::vector<pe_parser::section_info_t> sections;
			bool have_disk_pe = build_static_pe_pe_info(disk_path, view, pe);
			if (have_disk_pe) {
				sections = pe.sections;
			}
			else {
				sections.reserve(g_disasm.file.sections.size());
				for (const auto& s : g_disasm.file.sections) {
					if (s.va < mod->base) continue;
					uint64_t rva64 = s.va - mod->base;
					if (rva64 > 0xFFFFFFFFull) continue;
					pe_parser::section_info_t si;
					si.virtual_address = static_cast<uint32_t>(rva64);
					si.virtual_size = static_cast<uint32_t>(s.bytes.size());
					si.raw_size = static_cast<uint32_t>(s.bytes.size());
					si.characteristics = s.is_executable ? 0x60000020u : 0x40000040u;
					sections.push_back(std::move(si));
				}
			}

			auto fns = snapshot_functions(mod->base, mod->size);

			std::unordered_map<uint64_t, std::vector<annotation_t>> map;
			map.reserve(4096);

			for (const auto& s : g_disasm.file.sections) {
				if (!s.is_executable) continue;
				if (s.bytes.empty()) continue;
				if (!xref_static_pe_active()) {
					mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
					return;
				}
				scan_block_for_xrefs(s.bytes.data(), s.bytes.size(), s.va,
					fns, sections, mod->base, mod->name, map);
			}

			if (have_disk_pe) {
				for (const auto& sec : view.sections) {
					if (!xref_static_pe_active()) {
						mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
						return;
					}
					if (!section_is_data_readable(sec.characteristics)) continue;
					scan_data_section_for_pointers(view, sec, mod->base, mod->size,
						fns, sections, mod->name, map);
				}
			}

			for (auto& kv : map) {
				std::sort(kv.second.begin(), kv.second.end(), sort_less);
			}

			mod->sections = std::move(sections);
			mod->to_index = std::move(map);
			mod->state.store(static_cast<uint32_t>(build_state_t::built), std::memory_order_release);
		}

		inline void build_module_to_index(std::shared_ptr<module_index_t> mod) {
			if (!mod) return;

			if (mod->is_static_pe) {
				if (!xref_static_pe_active()) {
					mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
					return;
				}
				build_module_to_index_static(mod);
				return;
			}

			if (driver_bridge::attached_pid() == 0) {
				mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
				return;
			}

			build_module_to_index_live(mod);
		}

		inline std::shared_ptr<module_index_t> get_or_create_module_unlocked(registry_t& reg,
			const driver_bridge::module_info_t& m)
		{
			auto it = reg.modules.find(m.name);
			if (it != reg.modules.end()) {
				if (it->second->base == m.base && it->second->size == m.size)
					return it->second;
				reg.modules.erase(it);
			}
			auto mod = std::make_shared<module_index_t>();
			mod->name = m.name;
			mod->base = m.base;
			mod->size = m.size;
			reg.modules.emplace(m.name, mod);
			return mod;
		}

		inline std::shared_ptr<module_index_t> get_or_create_static_module_unlocked(registry_t& reg,
			const std::string& name, uint64_t base, uint32_t size, const std::string& disk_path)
		{
			auto it = reg.modules.find(name);
			if (it != reg.modules.end()) {
				if (it->second->base == base
					&& it->second->size == size
					&& it->second->is_static_pe
					&& it->second->static_pe_path == disk_path)
				{
					return it->second;
				}
				reg.modules.erase(it);
			}
			auto mod = std::make_shared<module_index_t>();
			mod->name = name;
			mod->base = base;
			mod->size = size;
			mod->is_static_pe = true;
			mod->static_pe_path = disk_path;
			reg.modules.emplace(name, mod);
			return mod;
		}

		inline void rebuild_module_table_unlocked(registry_t& reg) {
			reg.table.clear();
			if (driver_bridge::attached_pid() == 0) {
				std::string name;
				uint64_t base = 0;
				uint32_t size = 0;
				std::string disk_path;
				if (fetch_static_pe_module(name, base, size, disk_path)) {
					module_range_t r;
					r.start_va = base;
					r.end_va = base + size;
					r.name = name;
					r.index = get_or_create_static_module_unlocked(reg, name, base, size, disk_path);
					reg.table.push_back(std::move(r));
				}
				reg.table_built.store(true, std::memory_order_release);
				return;
			}
			auto mods = driver_bridge::enumerate_modules();
			reg.table.reserve(mods.size());
			for (const auto& m : mods) {
				if (m.base == 0 || m.size == 0) continue;
				module_range_t r;
				r.start_va = m.base;
				r.end_va = m.base + m.size;
				r.name = m.name;
				r.index = get_or_create_module_unlocked(reg, m);
				reg.table.push_back(std::move(r));
			}
			std::sort(reg.table.begin(), reg.table.end(),
				[](const module_range_t& a, const module_range_t& b) {
					return a.start_va < b.start_va;
				});
			reg.table_built.store(true, std::memory_order_release);
		}

		inline bool rebuild_module_table_offlock(registry_t& reg) {
			if (driver_bridge::attached_pid() == 0) {
				std::string name;
				uint64_t base = 0;
				uint32_t size = 0;
				std::string disk_path;
				bool have_static = fetch_static_pe_module(name, base, size, disk_path);

				std::vector<module_range_t> staged;
				std::shared_ptr<module_index_t> static_mod_new;
				bool need_replace = false;

				if (have_static) {
					std::shared_lock<std::shared_mutex> r_lk(reg.rw);
					auto it = reg.modules.find(name);
					if (it != reg.modules.end()
						&& it->second->base == base
						&& it->second->size == size
						&& it->second->is_static_pe
						&& it->second->static_pe_path == disk_path)
					{
						module_range_t r;
						r.start_va = base;
						r.end_va = base + size;
						r.name = name;
						r.index = it->second;
						staged.push_back(std::move(r));
					}
					else {
						auto mod = std::make_shared<module_index_t>();
						mod->name = name;
						mod->base = base;
						mod->size = size;
						mod->is_static_pe = true;
						mod->static_pe_path = disk_path;
						static_mod_new = mod;
						need_replace = true;
						module_range_t r;
						r.start_va = base;
						r.end_va = base + size;
						r.name = name;
						r.index = mod;
						staged.push_back(std::move(r));
					}
				}

				{
					std::scoped_lock<std::shared_mutex> w(reg.rw);
					if (need_replace && static_mod_new) {
						auto it = reg.modules.find(static_mod_new->name);
						if (it == reg.modules.end()) {
							reg.modules.emplace(static_mod_new->name, static_mod_new);
						}
						else if (!it->second->is_static_pe
							|| it->second->base != static_mod_new->base
							|| it->second->size != static_mod_new->size
							|| it->second->static_pe_path != static_mod_new->static_pe_path)
						{
							it->second = static_mod_new;
						}
					}
					reg.table.swap(staged);
					reg.table_built.store(true, std::memory_order_release);
				}
				return true;
			}

			auto mods = driver_bridge::enumerate_modules();

			std::vector<module_range_t> staged;
			staged.reserve(mods.size());
			std::vector<std::pair<std::string, std::shared_ptr<module_index_t>>> new_modules;
			new_modules.reserve(mods.size());

			{
				std::shared_lock<std::shared_mutex> r_lk(reg.rw);
				for (const auto& m : mods) {
					if (m.base == 0 || m.size == 0) continue;
					module_range_t r;
					r.start_va = m.base;
					r.end_va = m.base + m.size;
					r.name = m.name;

					auto it = reg.modules.find(m.name);
					if (it != reg.modules.end() && it->second->base == m.base && it->second->size == m.size) {
						r.index = it->second;
					} else {
						auto mod = std::make_shared<module_index_t>();
						mod->name = m.name;
						mod->base = m.base;
						mod->size = m.size;
						r.index = mod;
						new_modules.emplace_back(m.name, mod);
					}
					staged.push_back(std::move(r));
				}
			}

			std::sort(staged.begin(), staged.end(),
				[](const module_range_t& a, const module_range_t& b) {
					return a.start_va < b.start_va;
				});

			{
				std::scoped_lock<std::shared_mutex> w(reg.rw);
				for (auto& kv : new_modules) {
					auto it = reg.modules.find(kv.first);
					if (it == reg.modules.end()) {
						reg.modules.emplace(kv.first, kv.second);
					} else if (it->second->base != kv.second->base || it->second->size != kv.second->size) {
						it->second = kv.second;
					}
				}
				reg.table.swap(staged);
				reg.table_built.store(true, std::memory_order_release);
			}
			return true;
		}

		inline std::shared_ptr<module_index_t> lookup_cached_module(uint64_t addr) {
			auto& reg = registry();
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			if (!reg.table_built.load(std::memory_order_acquire)) return nullptr;
			if (reg.table.empty()) return nullptr;
			auto it = std::upper_bound(reg.table.begin(), reg.table.end(), addr,
				[](uint64_t a, const module_range_t& r) {
					return a < r.start_va;
				});
			if (it == reg.table.begin()) return nullptr;
			--it;
			if (addr < it->start_va || addr >= it->end_va) return nullptr;
			return it->index;
		}

		inline std::atomic<bool>& deep_static_xref_requested() {
			static std::atomic<bool> v{false};
			return v;
		}

		inline void schedule_build_locked(std::shared_ptr<module_index_t> mod) {
			if (!mod) return;
			if (mod->is_static_pe
				&& !deep_static_xref_requested().load(std::memory_order_acquire))
			{
				return;
			}
			uint32_t expected = static_cast<uint32_t>(build_state_t::idle);
			if (!mod->state.compare_exchange_strong(expected,
				static_cast<uint32_t>(build_state_t::building),
				std::memory_order_acq_rel))
				return;
			std::weak_ptr<module_index_t> weak = mod;
			work_queue::post([weak]() {
				auto strong = weak.lock();
				if (!strong) return;
				build_module_to_index(strong);
			});
		}

	}

	inline bool deep_static_xref_requested() {
		return detail::deep_static_xref_requested().load(std::memory_order_acquire);
	}

	inline void request_deep_static_xref() {
		detail::deep_static_xref_requested().store(true, std::memory_order_release);
		auto& reg = detail::registry();
		std::vector<std::shared_ptr<detail::module_index_t>> targets;
		{
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			for (const auto& r : reg.table) {
				if (!r.index) continue;
				if (!r.index->is_static_pe) continue;
				uint32_t s = r.index->state.load(std::memory_order_acquire);
				if (s != static_cast<uint32_t>(detail::build_state_t::idle)) continue;
				targets.push_back(r.index);
			}
		}
		for (auto& mod : targets) {
			detail::schedule_build_locked(mod);
		}
	}

	inline std::vector<annotation_t> query_to(uint64_t addr, size_t limit = 16) {
		std::vector<annotation_t> out;
		if (addr == 0 || limit == 0) return out;

		auto mod = detail::lookup_cached_module(addr);
		if (!mod) return out;

		uint32_t st = mod->state.load(std::memory_order_acquire);
		if (st != static_cast<uint32_t>(detail::build_state_t::built)) return out;

		auto it = mod->to_index.find(addr);
		if (it == mod->to_index.end()) return out;

		const auto& vec = it->second;
		if (vec.size() <= limit) {
			out = vec;
		} else {
			out.assign(vec.begin(), vec.begin() + static_cast<std::ptrdiff_t>(limit));
		}
		return out;
	}

	inline bool has_more(uint64_t addr, size_t limit) {
		if (addr == 0) return false;
		auto mod = detail::lookup_cached_module(addr);
		if (!mod) return false;
		if (mod->state.load(std::memory_order_acquire) !=
			static_cast<uint32_t>(detail::build_state_t::built)) return false;
		auto it = mod->to_index.find(addr);
		if (it == mod->to_index.end()) return false;
		return it->second.size() > limit;
	}

	inline void warm_range(uint64_t lo_addr, uint64_t hi_addr) {
		if (hi_addr <= lo_addr) return;

		auto& reg = detail::registry();

		if (!reg.table_built.load(std::memory_order_acquire)) {
			bool expected = false;
			if (reg.rebuild_in_flight.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
			{
				work_queue::post([&reg]() {
					detail::rebuild_module_table_offlock(reg);
					reg.rebuild_in_flight.store(false, std::memory_order_release);
				});
			}
			return;
		}

		std::vector<std::shared_ptr<detail::module_index_t>> targets;
		{
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			targets.reserve(reg.table.size());
			for (const auto& r : reg.table) {
				if (r.end_va <= lo_addr || r.start_va >= hi_addr) continue;
				if (!r.index) continue;
				uint32_t s = r.index->state.load(std::memory_order_acquire);
				if (s != static_cast<uint32_t>(detail::build_state_t::idle)) continue;
				targets.push_back(r.index);
			}
		}

		for (auto& mod : targets) {
			detail::schedule_build_locked(mod);
		}
	}

	inline void on_attach_changed() {
		auto& reg = detail::registry();
		{
			std::unique_lock<std::shared_mutex> lk(reg.rw);
			reg.table.clear();
			reg.modules.clear();
		}
		reg.table_built.store(false, std::memory_order_release);
		reg.rebuild_in_flight.store(false, std::memory_order_release);
		reg.generation.fetch_add(1, std::memory_order_acq_rel);
	}

	inline void on_file_loaded() {
		auto& reg = detail::registry();
		{
			std::unique_lock<std::shared_mutex> lk(reg.rw);
			reg.table.clear();
			reg.modules.clear();
		}
		reg.table_built.store(false, std::memory_order_release);
		reg.rebuild_in_flight.store(false, std::memory_order_release);
		reg.generation.fetch_add(1, std::memory_order_acq_rel);
		detail::deep_static_xref_requested().store(false, std::memory_order_release);

		if (detail::xref_static_pe_active()) {
			bool expected = false;
			if (reg.rebuild_in_flight.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
			{
				work_queue::post([&reg]() {
					detail::rebuild_module_table_offlock(reg);
					reg.rebuild_in_flight.store(false, std::memory_order_release);
				});
			}
		}
	}

	inline std::unique_ptr<detail::registry_t> detach_snapshot() {
		auto& h = detail::registry_holder();
		{
			std::unique_lock<std::shared_mutex> drain(h->rw);
			(void)drain;
		}
		std::unique_ptr<detail::registry_t> out = std::move(h);
		h = std::make_unique<detail::registry_t>();
		return out;
	}

	inline void attach_snapshot(std::unique_ptr<detail::registry_t> snap) {
		auto& h = detail::registry_holder();
		if (!snap) snap = std::make_unique<detail::registry_t>();
		{
			std::unique_lock<std::shared_mutex> drain(h->rw);
			(void)drain;
		}
		h = std::move(snap);
	}

}
