#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "function_index.hpp"
#include "functions_panel.hpp"
#include "pe_parser.hpp"
#include "xref_engine.hpp"
#include "standalone_driver.hpp"
#include "work_queue.hpp"
#include "zydis_disasm.hpp"
#include "../../helpers/diag_log.hpp"

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

	struct bounded_live_range_result_t {
		bool        ok = false;
		uint32_t    pid = 0;
		std::string module;
		uint64_t    module_base = 0;
		uint32_t    module_size = 0;
		uint64_t    requested_lo = 0;
		uint64_t    requested_hi = 0;
		uint64_t    clipped_lo = 0;
		uint64_t    clipped_hi = 0;
		size_t      pages_read = 0;
		size_t      pages_failed = 0;
		size_t      bytes_read = 0;
		size_t      targets_found = 0;
		size_t      xrefs_found = 0;
		uint64_t    proof_target = 0;
		uint64_t    proof_source = 0;
		std::string proof_label;
		uint32_t    state_before = 0;
		uint32_t    state_after = 0;
		bool        table_built_before = false;
		bool        table_built_after = false;
		bool        rebuild_in_flight_before = false;
		bool        rebuild_in_flight_after = false;
		uint64_t    elapsed_us = 0;
		std::string error;
	};

	namespace detail {

		inline unsigned long current_worker_tid()
		{
			return static_cast<unsigned long>(GetCurrentThreadId());
		}

		inline uint64_t elapsed_us_since(const std::chrono::steady_clock::time_point& started)
		{
			return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now() - started).count());
		}

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

		inline void build_module_to_index_live(std::shared_ptr<module_index_t> mod, uint64_t warm_lo = 0, uint64_t warm_hi = 0) {
			const auto started = std::chrono::steady_clock::now();
			const unsigned long worker_tid = current_worker_tid();
			const uint32_t start_pid = driver_bridge::attached_pid();
			pe_parser::pe_info_t pe;
			std::vector<pe_parser::section_info_t> sections;
			if (pe_parser::parse(mod->base, pe))
				sections = pe.sections;

			auto fns = snapshot_functions(mod->base, mod->size);

			std::unordered_map<uint64_t, std::vector<annotation_t>> map;
			map.reserve(4096);

			const size_t page_size = 4096;
			const uint64_t module_size = mod->size;
			size_t pages_read = 0;
			size_t pages_failed = 0;
			size_t bytes_read = 0;
			diag::log_tagged_critical_fmt("xref",
				"warm_range_worker_enter module=%s base=0x%llX size=0x%llX warm_lo=0x%llX warm_hi=0x%llX pid=%u tid=%lu sections=%zu elapsed_us=%llu",
				mod->name.c_str(),
				static_cast<unsigned long long>(mod->base),
				static_cast<unsigned long long>(module_size),
				static_cast<unsigned long long>(warm_lo),
				static_cast<unsigned long long>(warm_hi),
				start_pid,
				worker_tid,
				sections.size(),
				static_cast<unsigned long long>(elapsed_us_since(started)));

			for (uint64_t offset = 0; offset < module_size; offset += page_size) {
				if (driver_bridge::attached_pid() == 0) {
					mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
					diag::log_tagged_critical_fmt("xref",
						"warm_range_worker_exit module=%s reason=no_attached_pid warm_lo=0x%llX warm_hi=0x%llX page_cursor=0x%llX pages_read=%zu pages_failed=%zu bytes_read=%zu tid=%lu elapsed_us=%llu",
						mod->name.c_str(),
						static_cast<unsigned long long>(warm_lo),
						static_cast<unsigned long long>(warm_hi),
						static_cast<unsigned long long>(mod->base + offset),
						pages_read,
						pages_failed,
						bytes_read,
						worker_tid,
						static_cast<unsigned long long>(elapsed_us_since(started)));
					return;
				}

				size_t chunk = page_size;
				if (offset + chunk > module_size)
					chunk = static_cast<size_t>(module_size - offset);

				std::vector<uint8_t> page_data;
				const uint64_t cursor = mod->base + offset;
				const auto page_started = std::chrono::steady_clock::now();
				diag::log_tagged_critical_fmt("xref",
					"warm_range_worker_page_pre module=%s base=0x%llX warm_lo=0x%llX warm_hi=0x%llX cursor=0x%llX chunk=%zu pid=%u tid=%lu elapsed_us=%llu",
					mod->name.c_str(),
					static_cast<unsigned long long>(mod->base),
					static_cast<unsigned long long>(warm_lo),
					static_cast<unsigned long long>(warm_hi),
					static_cast<unsigned long long>(cursor),
					chunk,
					driver_bridge::attached_pid(),
					worker_tid,
					static_cast<unsigned long long>(elapsed_us_since(started)));
				const bool read_ok = driver_bridge::read_memory(cursor, chunk, page_data);
				if (!read_ok || page_data.empty()) {
					++pages_failed;
					diag::log_tagged_critical_fmt("xref",
						"warm_range_worker_page_post module=%s cursor=0x%llX chunk=%zu ok=%d bytes=%zu pages_read=%zu pages_failed=%zu pid=%u tid=%lu page_elapsed_us=%llu elapsed_us=%llu",
						mod->name.c_str(),
						static_cast<unsigned long long>(cursor),
						chunk,
						read_ok ? 1 : 0,
						page_data.size(),
						pages_read,
						pages_failed,
						driver_bridge::attached_pid(),
						worker_tid,
						static_cast<unsigned long long>(elapsed_us_since(page_started)),
						static_cast<unsigned long long>(elapsed_us_since(started)));
					continue;
				}
				++pages_read;
				bytes_read += page_data.size();

				scan_block_for_xrefs(page_data.data(), page_data.size(),
					cursor, fns, sections, mod->base, mod->name, map);
				diag::log_tagged_critical_fmt("xref",
					"warm_range_worker_page_post module=%s cursor=0x%llX chunk=%zu ok=1 bytes=%zu pages_read=%zu pages_failed=%zu pid=%u tid=%lu page_elapsed_us=%llu elapsed_us=%llu",
					mod->name.c_str(),
					static_cast<unsigned long long>(cursor),
					chunk,
					page_data.size(),
					pages_read,
					pages_failed,
					driver_bridge::attached_pid(),
					worker_tid,
					static_cast<unsigned long long>(elapsed_us_since(page_started)),
					static_cast<unsigned long long>(elapsed_us_since(started)));
			}

			for (auto& kv : map) {
				std::sort(kv.second.begin(), kv.second.end(), sort_less);
			}

			mod->sections = std::move(sections);
			mod->to_index = std::move(map);
			mod->state.store(static_cast<uint32_t>(build_state_t::built), std::memory_order_release);
			diag::log_tagged_critical_fmt("xref",
				"warm_range_worker_exit module=%s reason=built warm_lo=0x%llX warm_hi=0x%llX pages_read=%zu pages_failed=%zu bytes_read=%zu targets=%zu tid=%lu elapsed_us=%llu",
				mod->name.c_str(),
				static_cast<unsigned long long>(warm_lo),
				static_cast<unsigned long long>(warm_hi),
				pages_read,
				pages_failed,
				bytes_read,
				mod->to_index.size(),
				worker_tid,
				static_cast<unsigned long long>(elapsed_us_since(started)));
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

		inline void build_module_to_index(std::shared_ptr<module_index_t> mod, uint64_t warm_lo = 0, uint64_t warm_hi = 0) {
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

			build_module_to_index_live(mod, warm_lo, warm_hi);
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

		inline std::vector<std::shared_ptr<module_index_t>> built_modules_snapshot() {
			std::vector<std::shared_ptr<module_index_t>> out;
			auto& reg = registry();
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			if (!reg.table_built.load(std::memory_order_acquire)) return out;
			out.reserve(reg.table.size());
			for (const auto& r : reg.table) {
				if (!r.index) continue;
				if (r.index->state.load(std::memory_order_acquire) !=
					static_cast<uint32_t>(build_state_t::built))
					continue;
				if (std::find(out.begin(), out.end(), r.index) != out.end())
					continue;
				out.push_back(r.index);
			}
			return out;
		}

		inline std::atomic<bool>& deep_static_xref_requested() {
			static std::atomic<bool> v{false};
			return v;
		}

		inline void schedule_build_locked(std::shared_ptr<module_index_t> mod, uint64_t warm_lo = 0, uint64_t warm_hi = 0) {
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
			diag::log_tagged_critical_fmt("xref",
				"warm_range_schedule module=%s base=0x%llX size=0x%llX warm_lo=0x%llX warm_hi=0x%llX tid=%lu",
				mod->name.c_str(),
				static_cast<unsigned long long>(mod->base),
				static_cast<unsigned long long>(mod->size),
				static_cast<unsigned long long>(warm_lo),
				static_cast<unsigned long long>(warm_hi),
				current_worker_tid());
			work_queue::post([weak, warm_lo, warm_hi]() {
				auto strong = weak.lock();
				if (!strong) return;
				build_module_to_index(strong, warm_lo, warm_hi);
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

		auto modules = detail::built_modules_snapshot();
		for (const auto& mod : modules) {
			auto it = mod->to_index.find(addr);
			if (it == mod->to_index.end()) continue;
			out.insert(out.end(), it->second.begin(), it->second.end());
		}

		if (out.empty()) return out;

		std::sort(out.begin(), out.end(), detail::sort_less);
		out.erase(std::unique(out.begin(), out.end(),
			[](const annotation_t& a, const annotation_t& b) {
				return a.source_addr == b.source_addr
					&& a.kind == b.kind
					&& a.edge == b.edge;
			}), out.end());
		if (out.size() > limit) {
			out.resize(limit);
		}
		return out;
	}

	inline bool has_more(uint64_t addr, size_t limit) {
		if (addr == 0) return false;
		size_t count = 0;
		auto modules = detail::built_modules_snapshot();
		for (const auto& mod : modules) {
			auto it = mod->to_index.find(addr);
			if (it == mod->to_index.end()) continue;
			count += it->second.size();
			if (count > limit) return true;
		}
		return false;
	}

	inline void warm_range(uint64_t lo_addr, uint64_t hi_addr) {
		if (hi_addr <= lo_addr) return;

		auto& reg = detail::registry();
		const auto started = std::chrono::steady_clock::now();
		diag::log_tagged_critical_fmt("xref",
			"warm_range_enter lo=0x%llX hi=0x%llX pid=%u tid=%lu table_built=%d rebuild_in_flight=%d",
			static_cast<unsigned long long>(lo_addr),
			static_cast<unsigned long long>(hi_addr),
			driver_bridge::attached_pid(),
			detail::current_worker_tid(),
			reg.table_built.load(std::memory_order_acquire) ? 1 : 0,
			reg.rebuild_in_flight.load(std::memory_order_acquire) ? 1 : 0);

		if (!reg.table_built.load(std::memory_order_acquire)) {
			bool expected = false;
			if (reg.rebuild_in_flight.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
			{
				work_queue::post([&reg]() {
					const auto rebuild_started = std::chrono::steady_clock::now();
					diag::log_tagged_critical_fmt("xref",
						"warm_range_rebuild_worker_enter tid=%lu",
						detail::current_worker_tid());
					detail::rebuild_module_table_offlock(reg);
					reg.rebuild_in_flight.store(false, std::memory_order_release);
					diag::log_tagged_critical_fmt("xref",
						"warm_range_rebuild_worker_exit tid=%lu table_built=%d elapsed_us=%llu",
						detail::current_worker_tid(),
						reg.table_built.load(std::memory_order_acquire) ? 1 : 0,
						static_cast<unsigned long long>(detail::elapsed_us_since(rebuild_started)));
				});
				diag::log_tagged_critical_fmt("xref",
					"warm_range_exit lo=0x%llX hi=0x%llX reason=rebuild_queued tid=%lu elapsed_us=%llu",
					static_cast<unsigned long long>(lo_addr),
					static_cast<unsigned long long>(hi_addr),
					detail::current_worker_tid(),
					static_cast<unsigned long long>(detail::elapsed_us_since(started)));
			}
			else {
				diag::log_tagged_critical_fmt("xref",
					"warm_range_exit lo=0x%llX hi=0x%llX reason=rebuild_in_flight tid=%lu elapsed_us=%llu",
					static_cast<unsigned long long>(lo_addr),
					static_cast<unsigned long long>(hi_addr),
					detail::current_worker_tid(),
					static_cast<unsigned long long>(detail::elapsed_us_since(started)));
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
			detail::schedule_build_locked(mod, lo_addr, hi_addr);
		}
		diag::log_tagged_critical_fmt("xref",
			"warm_range_exit lo=0x%llX hi=0x%llX reason=scheduled targets=%zu tid=%lu elapsed_us=%llu",
			static_cast<unsigned long long>(lo_addr),
			static_cast<unsigned long long>(hi_addr),
			targets.size(),
			detail::current_worker_tid(),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
	}

	inline bounded_live_range_result_t build_bounded_live_range(uint64_t lo_addr, uint64_t hi_addr, uint32_t timeout_ms = 2000) {
		bounded_live_range_result_t result{};
		result.requested_lo = lo_addr;
		result.requested_hi = hi_addr;
		result.pid = driver_bridge::attached_pid();
		auto started = std::chrono::steady_clock::now();
		const bool deadline_enabled = timeout_ms != 0;
		const auto deadline = started + std::chrono::milliseconds(timeout_ms);
		auto deadline_expired = [&]() {
			return deadline_enabled && std::chrono::steady_clock::now() >= deadline;
		};
		auto deadline_remaining_ms = [&]() -> uint64_t {
			if (!deadline_enabled) return 0;
			const auto now = std::chrono::steady_clock::now();
			if (now >= deadline) return 0;
			return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
		};
		auto& reg = detail::registry();
		result.table_built_before = reg.table_built.load(std::memory_order_acquire);
		result.rebuild_in_flight_before = reg.rebuild_in_flight.load(std::memory_order_acquire);
		diag::log_tagged_critical_fmt("xref",
			"bounded_live_range_enter lo=0x%llX hi=0x%llX timeout_ms=%u pid=%u tid=%lu table_built=%d rebuild_in_flight=%d",
			static_cast<unsigned long long>(lo_addr),
			static_cast<unsigned long long>(hi_addr),
			timeout_ms,
			result.pid,
			detail::current_worker_tid(),
			result.table_built_before ? 1 : 0,
			result.rebuild_in_flight_before ? 1 : 0);

		std::shared_ptr<detail::module_index_t> mod;
		auto finish = [&](const char* error, bool ok) {
			result.ok = ok;
			if (error && error[0] != '\0')
				result.error = error;
			if (mod)
				result.state_after = mod->state.load(std::memory_order_acquire);
			result.table_built_after = reg.table_built.load(std::memory_order_acquire);
			result.rebuild_in_flight_after = reg.rebuild_in_flight.load(std::memory_order_acquire);
			result.elapsed_us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now() - started).count());
			diag::log_tagged_critical_fmt("xref",
				"bounded_live_range_exit ok=%d error=%s module=%s base=0x%llX clipped_lo=0x%llX clipped_hi=0x%llX pages_read=%zu pages_failed=%zu bytes_read=%zu targets=%zu xrefs=%zu pid=%u tid=%lu elapsed_us=%llu",
				ok ? 1 : 0,
				result.error.empty() ? "" : result.error.c_str(),
				result.module.empty() ? "" : result.module.c_str(),
				static_cast<unsigned long long>(result.module_base),
				static_cast<unsigned long long>(result.clipped_lo),
				static_cast<unsigned long long>(result.clipped_hi),
				result.pages_read,
				result.pages_failed,
				result.bytes_read,
				result.targets_found,
				result.xrefs_found,
				result.pid,
				detail::current_worker_tid(),
				static_cast<unsigned long long>(result.elapsed_us));
			return result;
		};

		if (hi_addr <= lo_addr)
			return finish("invalid_range", false);
		if (result.pid == 0)
			return finish("no_attached_pid", false);

		if (!reg.table_built.load(std::memory_order_acquire)) {
			diag::log_tagged_critical_fmt("xref",
				"bounded_live_range_module_ready_begin table_built=0 rebuild_in_flight=%d deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
				reg.rebuild_in_flight.load(std::memory_order_acquire) ? 1 : 0,
				static_cast<unsigned long long>(deadline_remaining_ms()),
				result.pid,
				detail::current_worker_tid(),
				static_cast<unsigned long long>(detail::elapsed_us_since(started)));
			bool expected = false;
			if (reg.rebuild_in_flight.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
				if (deadline_enabled) {
					reg.rebuild_in_flight.store(false, std::memory_order_release);
					return finish("deadline_before_module_table_rebuild", false);
				}
				const auto rebuild_started = std::chrono::steady_clock::now();
				detail::rebuild_module_table_offlock(reg);
				reg.rebuild_in_flight.store(false, std::memory_order_release);
				diag::log_tagged_critical_fmt("xref",
					"bounded_live_range_module_ready_rebuild_end table_built=%d elapsed_us=%llu total_elapsed_us=%llu",
					reg.table_built.load(std::memory_order_acquire) ? 1 : 0,
					static_cast<unsigned long long>(detail::elapsed_us_since(rebuild_started)),
					static_cast<unsigned long long>(detail::elapsed_us_since(started)));
			} else {
				const auto wait_limit = started + std::chrono::milliseconds(timeout_ms > 250 ? 250 : timeout_ms);
				while (!reg.table_built.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < wait_limit) {
					if (deadline_expired())
						return finish("deadline_waiting_module_table_rebuild", false);
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
				}
				if (!reg.table_built.load(std::memory_order_acquire)) {
					if (deadline_enabled)
						return finish("deadline_waiting_module_table_rebuild", false);
					detail::rebuild_module_table_offlock(reg);
				}
			}
			diag::log_tagged_critical_fmt("xref",
				"bounded_live_range_module_ready_end table_built=%d rebuild_in_flight=%d deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
				reg.table_built.load(std::memory_order_acquire) ? 1 : 0,
				reg.rebuild_in_flight.load(std::memory_order_acquire) ? 1 : 0,
				static_cast<unsigned long long>(deadline_remaining_ms()),
				result.pid,
				detail::current_worker_tid(),
				static_cast<unsigned long long>(detail::elapsed_us_since(started)));
		}

		if (!reg.table_built.load(std::memory_order_acquire))
			return finish("module_table_not_built", false);

		diag::log_tagged_critical_fmt("xref",
			"bounded_live_range_module_lookup_begin table_size_unknown=1 deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
			static_cast<unsigned long long>(deadline_remaining_ms()),
			result.pid,
			detail::current_worker_tid(),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
		bool lookup_lock_busy = false;
		for (;;) {
			std::shared_lock<std::shared_mutex> lk(reg.rw, std::try_to_lock);
			if (lk.owns_lock()) {
				const size_t table_size = reg.table.size();
				for (const auto& r : reg.table) {
					if (r.end_va <= lo_addr || r.start_va >= hi_addr) continue;
					if (!r.index) continue;
					mod = r.index;
					result.module = r.name;
					result.module_base = r.start_va;
					uint64_t size64 = r.end_va > r.start_va ? (r.end_va - r.start_va) : 0;
					if (size64 > 0xFFFFFFFFull)
						size64 = 0xFFFFFFFFull;
					result.module_size = static_cast<uint32_t>(size64);
					break;
				}
				diag::log_tagged_critical_fmt("xref",
					"bounded_live_range_module_lookup_end found=%d table_size=%zu lock_busy=%d deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
					mod ? 1 : 0,
					table_size,
					lookup_lock_busy ? 1 : 0,
					static_cast<unsigned long long>(deadline_remaining_ms()),
					result.pid,
					detail::current_worker_tid(),
					static_cast<unsigned long long>(detail::elapsed_us_since(started)));
				break;
			}
			lookup_lock_busy = true;
			if (deadline_expired())
				return finish("deadline_waiting_module_table_lookup_lock", false);
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}

		if (!mod)
			return finish("covering_module_not_found", false);

		result.state_before = mod->state.load(std::memory_order_acquire);
		if (result.module.empty())
			result.module = mod->name;
		if (result.module_base == 0)
			result.module_base = mod->base;
		if (result.module_size == 0)
			result.module_size = mod->size;

		const uint64_t module_end = result.module_base + result.module_size;
		result.clipped_lo = std::max(lo_addr, result.module_base);
		result.clipped_hi = std::min(hi_addr, module_end);
		if (result.clipped_hi <= result.clipped_lo)
			return finish("range_outside_module", false);

		if (deadline_expired())
			return finish("deadline_before_pe_parse", false);
		pe_parser::pe_info_t pe;
		std::vector<pe_parser::section_info_t> sections;
		const auto pe_started = std::chrono::steady_clock::now();
		diag::log_tagged_critical_fmt("xref",
			"bounded_live_range_pe_parse_begin module=%s base=0x%llX deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
			result.module.c_str(),
			static_cast<unsigned long long>(result.module_base),
			static_cast<unsigned long long>(deadline_remaining_ms()),
			result.pid,
			detail::current_worker_tid(),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
		if (pe_parser::parse(result.module_base, pe))
			sections = pe.sections;
		diag::log_tagged_critical_fmt("xref",
			"bounded_live_range_pe_parse_end module=%s ok=%d sections=%zu parse_elapsed_us=%llu deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
			result.module.c_str(),
			sections.empty() ? 0 : 1,
			sections.size(),
			static_cast<unsigned long long>(detail::elapsed_us_since(pe_started)),
			static_cast<unsigned long long>(deadline_remaining_ms()),
			result.pid,
			detail::current_worker_tid(),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
		if (deadline_expired())
			return finish("deadline_after_pe_parse", false);
		if (sections.empty())
			return finish("pe_sections_unavailable", false);
		diag::log_tagged_critical_fmt("xref",
			"bounded_live_range_module module=%s base=0x%llX size=0x%X clipped_lo=0x%llX clipped_hi=0x%llX sections=%zu pid=%u tid=%lu elapsed_us=%llu",
			result.module.c_str(),
			static_cast<unsigned long long>(result.module_base),
			result.module_size,
			static_cast<unsigned long long>(result.clipped_lo),
			static_cast<unsigned long long>(result.clipped_hi),
			sections.size(),
			result.pid,
			detail::current_worker_tid(),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));

		if (deadline_expired())
			return finish("deadline_before_function_snapshot", false);
		const auto function_snapshot_started = std::chrono::steady_clock::now();
		diag::log_tagged_critical_fmt("xref",
			"bounded_live_range_function_snapshot_begin module=%s base=0x%llX size=0x%X deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
			result.module.c_str(),
			static_cast<unsigned long long>(result.module_base),
			result.module_size,
			static_cast<unsigned long long>(deadline_remaining_ms()),
			result.pid,
			detail::current_worker_tid(),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
		std::vector<functions_panel::function_entry_t> fns;
		bool function_snapshot_lock_busy = false;
		{
			auto& fs = functions_panel::state();
			if (fs.ready.load(std::memory_order_acquire)) {
				std::unique_lock<std::mutex> lk(fs.mtx, std::try_to_lock);
				if (lk.owns_lock()) {
					fns.reserve(fs.entries.size());
					for (const auto& e : fs.entries) {
						if (e.address >= result.module_base && e.address < result.module_base + result.module_size)
							fns.push_back(e);
					}
				} else {
					function_snapshot_lock_busy = true;
				}
			}
		}
		if (fns.empty() && !deadline_expired()) {
			auto& fc = function_index::detail::cache();
			std::shared_lock<std::shared_mutex> lk(fc.mutex, std::try_to_lock);
			if (lk.owns_lock()) {
				fns.reserve(fc.sorted_starts.size());
				for (uint64_t start : fc.sorted_starts) {
					if (start < result.module_base) continue;
					if (start >= result.module_base + result.module_size) continue;
					functions_panel::function_entry_t fe;
					fe.address = start;
					auto bit = fc.by_start.find(start);
					if (bit != fc.by_start.end()) {
						uint64_t end = bit->second.end;
						if (end > start && (end - start) <= 0xFFFFFFFFull)
							fe.size = static_cast<uint32_t>(end - start);
						fe.name = bit->second.display_name;
						fe.section = bit->second.section;
					}
					if (fe.name.empty()) {
						auto sit = fc.synthetic_names.find(start);
						if (sit != fc.synthetic_names.end() && !sit->second.empty())
							fe.name = sit->second;
						else
							fe.name = function_index::detail::make_synthetic_sub(start);
					}
					fns.push_back(std::move(fe));
				}
			} else {
				function_snapshot_lock_busy = true;
			}
		}
		std::sort(fns.begin(), fns.end(),
			[](const functions_panel::function_entry_t& a, const functions_panel::function_entry_t& b) {
				return a.address < b.address;
			});
		diag::log_tagged_critical_fmt("xref",
			"bounded_live_range_function_snapshot_end module=%s count=%zu lock_busy=%d snapshot_elapsed_us=%llu deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
			result.module.c_str(),
			fns.size(),
			function_snapshot_lock_busy ? 1 : 0,
			static_cast<unsigned long long>(detail::elapsed_us_since(function_snapshot_started)),
			static_cast<unsigned long long>(deadline_remaining_ms()),
			result.pid,
			detail::current_worker_tid(),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
		if (deadline_expired())
			return finish("deadline_after_function_snapshot", false);
		if (function_snapshot_lock_busy && fns.empty())
			return finish("function_snapshot_lock_busy", false);
		std::unordered_map<uint64_t, std::vector<annotation_t>> map;
		map.reserve(1024);

		const size_t page_size = 4096;
		diag::log_tagged_critical_fmt("xref",
			"bounded_live_range_page_loop_ready module=%s sections=%zu functions=%zu deadline_remaining_ms=%llu pid=%u tid=%lu elapsed_us=%llu",
			result.module.c_str(),
			sections.size(),
			fns.size(),
			static_cast<unsigned long long>(deadline_remaining_ms()),
			result.pid,
			detail::current_worker_tid(),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
		for (const auto& s : sections) {
			if (!detail::section_is_code(s.characteristics))
				continue;
			const uint64_t section_start = result.module_base + s.virtual_address;
			const uint64_t section_size = s.virtual_size != 0 ? s.virtual_size : s.raw_size;
			const uint64_t section_end = section_start + section_size;
			uint64_t cursor = std::max(result.clipped_lo, section_start);
			const uint64_t end = std::min(result.clipped_hi, section_end);
			while (cursor < end) {
				if (deadline_expired())
					return finish("deadline_before_page_read", false);
				size_t chunk = page_size;
				if (cursor + chunk > end)
					chunk = static_cast<size_t>(end - cursor);
				std::vector<uint8_t> page_data;
				const auto page_started = std::chrono::steady_clock::now();
				diag::log_tagged_critical_fmt("xref",
					"bounded_live_range_page_pre module=%s base=0x%llX section=0x%llX cursor=0x%llX chunk=%zu pid=%u tid=%lu elapsed_us=%llu",
					result.module.c_str(),
					static_cast<unsigned long long>(result.module_base),
					static_cast<unsigned long long>(section_start),
					static_cast<unsigned long long>(cursor),
					chunk,
					result.pid,
					detail::current_worker_tid(),
					static_cast<unsigned long long>(detail::elapsed_us_since(started)));
				const bool read_ok = driver_bridge::read_memory_for(result.pid, cursor, chunk, page_data);
				const uint64_t page_elapsed_us = detail::elapsed_us_since(page_started);
				if (read_ok && !page_data.empty()) {
					++result.pages_read;
					result.bytes_read += page_data.size();
					diag::log_tagged_critical_fmt("xref",
						"bounded_live_range_page_post module=%s cursor=0x%llX chunk=%zu ok=1 bytes=%zu pages_read=%zu pages_failed=%zu pid=%u tid=%lu page_elapsed_us=%llu elapsed_us=%llu",
						result.module.c_str(),
						static_cast<unsigned long long>(cursor),
						chunk,
						page_data.size(),
						result.pages_read,
						result.pages_failed,
						result.pid,
						detail::current_worker_tid(),
						static_cast<unsigned long long>(page_elapsed_us),
						static_cast<unsigned long long>(detail::elapsed_us_since(started)));
					if (deadline_expired())
						return finish("deadline_after_page_read", false);
					detail::scan_block_for_xrefs(page_data.data(), page_data.size(), cursor, fns, sections, result.module_base, result.module, map);
					if (deadline_expired())
						return finish("deadline_after_page_scan", false);
				} else {
					++result.pages_failed;
					diag::log_tagged_critical_fmt("xref",
						"bounded_live_range_page_post module=%s cursor=0x%llX chunk=%zu ok=%d bytes=%zu pages_read=%zu pages_failed=%zu pid=%u tid=%lu page_elapsed_us=%llu elapsed_us=%llu",
						result.module.c_str(),
						static_cast<unsigned long long>(cursor),
						chunk,
						read_ok ? 1 : 0,
						page_data.size(),
						result.pages_read,
						result.pages_failed,
						result.pid,
						detail::current_worker_tid(),
						static_cast<unsigned long long>(page_elapsed_us),
						static_cast<unsigned long long>(detail::elapsed_us_since(started)));
					if (deadline_expired())
						return finish("deadline_after_page_read_failed", false);
				}
				cursor += chunk;
			}
		}

		for (auto& kv : map) {
			if (kv.first != 0)
				++result.targets_found;
			std::sort(kv.second.begin(), kv.second.end(), detail::sort_less);
			for (const auto& ann : kv.second) {
				if (kv.first == 0 || ann.source_addr == 0)
					continue;
				++result.xrefs_found;
				if (result.proof_target == 0) {
					result.proof_target = kv.first;
					result.proof_source = ann.source_addr;
					result.proof_label = ann.source_label;
				}
			}
		}

		if (result.pages_read == 0)
			return finish("range_read_empty", false);
		if (result.xrefs_found == 0 || result.proof_target == 0 || result.proof_source == 0)
			return finish("xref_proof_empty", false);
		return finish("", true);
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
