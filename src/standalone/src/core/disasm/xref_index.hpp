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
			std::vector<pe_parser::section_info_t>                  sections;
			std::unordered_map<uint64_t, std::vector<annotation_t>> to_index;
			std::atomic<uint32_t>                                   state{static_cast<uint32_t>(build_state_t::idle)};
		};

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

		inline registry_t& registry() {
			static registry_t r;
			return r;
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
			if (!fs.ready.load(std::memory_order_acquire)) return out;
			std::lock_guard<std::mutex> lk(fs.mtx);
			out.reserve(fs.entries.size());
			for (const auto& e : fs.entries) {
				if (e.address >= module_base && e.address < module_base + module_size)
					out.push_back(e);
			}
			std::sort(out.begin(), out.end(),
				[](const functions_panel::function_entry_t& a, const functions_panel::function_entry_t& b) {
					return a.address < b.address;
				});
			return out;
		}

		inline void build_module_to_index(std::shared_ptr<module_index_t> mod) {
			if (!mod) return;

			if (driver_bridge::attached_pid() == 0) {
				mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
				return;
			}

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

				const uint8_t* data = page_data.data();
				int sz = static_cast<int>(page_data.size());
				int pos = 0;

				while (pos < sz) {
					int avail = sz - pos;
					if (avail > 15) avail = 15;

					uint64_t ins_addr = mod->base + offset + static_cast<uint64_t>(pos);
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
						ann.source_label = resolve_source_label(ins_addr, fns, sections, mod->base, mod->name);

						map[target].push_back(std::move(ann));
					}

					pos += ins.len;
				}
			}

			for (auto& kv : map) {
				std::sort(kv.second.begin(), kv.second.end(), sort_less);
			}

			mod->sections = std::move(sections);
			mod->to_index = std::move(map);
			mod->state.store(static_cast<uint32_t>(build_state_t::built), std::memory_order_release);
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

		inline void rebuild_module_table_unlocked(registry_t& reg) {
			reg.table.clear();
			if (driver_bridge::attached_pid() == 0) {
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
				std::scoped_lock<std::shared_mutex> w(reg.rw);
				reg.table.clear();
				reg.table_built.store(true, std::memory_order_release);
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

		inline void schedule_build_locked(std::shared_ptr<module_index_t> mod) {
			if (!mod) return;
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

}
