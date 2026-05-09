#pragma once

#include <Zydis/Zydis.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "functions_panel.hpp"
#include "pe_parser.hpp"
#include "rename_store.hpp"
#include "standalone_driver.hpp"
#include "symbol_store.hpp"
#include "work_queue.hpp"
#include "zydis_disasm.hpp"

namespace function_index {

	enum class injection_t {
		function_banner,
		attributes_line,
		prototype_line,
		proc_header,
		var_decl,
		proc_endp,
		endp_separator,
		label_line,
		spacer_line
	};

	struct injection_row_t {
		injection_t kind;
		std::string text;
		uint64_t    addr = 0;
	};

	namespace detail {

		enum class func_state_t : uint32_t {
			idle = 0,
			building = 1,
			built = 2,
			failed = 3
		};

		enum class bounds_state_t : uint32_t {
			idle = 0,
			building = 1,
			ready = 2,
			failed = 3
		};

		struct var_slot_t {
			int64_t     offset = 0;
			uint32_t    size = 4;
			std::string name;
		};

		struct label_slot_t {
			uint64_t    addr = 0;
			bool        is_locret = false;
		};

		struct func_record_t {
			uint64_t                                  start = 0;
			uint64_t                                  end = 0;
			std::string                               section;
			std::string                               display_name;
			bool                                      bp_based = false;
			bool                                      sp_analysis_failed = false;
			std::vector<var_slot_t>                   vars;
			std::vector<label_slot_t>                 labels;
			std::unordered_set<uint64_t>              ret_addrs;
			uint64_t                                  last_insn_addr = 0;
			std::vector<injection_row_t>              before_first_insn;
			std::vector<injection_row_t>              after_last_insn;
			std::unordered_map<uint64_t, std::string> inline_labels;
		};

		struct func_status_t {
			std::atomic<uint32_t> state{static_cast<uint32_t>(func_state_t::idle)};
		};

		struct cache_t {
			std::shared_mutex                                              mutex;
			std::unordered_map<uint64_t, func_record_t>                    by_start;
			std::unordered_map<uint64_t, std::shared_ptr<func_status_t>>   status_by_start;
			std::unordered_map<uint64_t, uint64_t>                         addr_to_func_start;
			std::vector<uint64_t>                                          sorted_starts;
			std::unordered_map<uint64_t, std::string>                      synthetic_names;
			uint64_t                                                       cached_module_base = 0;
			uint32_t                                                       cached_module_size = 0;
			std::string                                                    cached_module_name;
			uint64_t                                                       cached_pid_token = 0;
			std::atomic<uint32_t>                                          bounds_state{static_cast<uint32_t>(bounds_state_t::idle)};
		};

		inline cache_t& cache() {
			static cache_t c;
			return c;
		}

		inline std::string format_hex_upper(uint64_t v) {
			char buf[32];
			std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
			return std::string(buf);
		}

		inline std::string format_signed_hex(int64_t v) {
			char buf[32];
			if (v < 0) {
				std::snprintf(buf, sizeof(buf), "-%llXh", static_cast<unsigned long long>(-v));
			}
			else {
				std::snprintf(buf, sizeof(buf), " %llXh", static_cast<unsigned long long>(v));
			}
			return std::string(buf);
		}

		inline std::string ptr_word_for_size(uint32_t sz) {
			switch (sz) {
				case 1: return "byte ptr";
				case 2: return "word ptr";
				case 4: return "dword ptr";
				case 8: return "qword ptr";
				case 16: return "xmmword ptr";
				case 32: return "ymmword ptr";
				case 64: return "zmmword ptr";
				default: return "dword ptr";
			}
		}

		inline std::string make_synthetic_sub(uint64_t addr) {
			char buf[40];
			std::snprintf(buf, sizeof(buf), "sub_%llX",
				static_cast<unsigned long long>(addr));
			return std::string(buf);
		}

		inline std::string strip_module_prefix(const std::string& s) {
			auto pos = s.find('!');
			if (pos == std::string::npos) return s;
			return s.substr(pos + 1);
		}

		inline std::string resolve_display_name(uint64_t addr) {
			std::string rn = rename_store::get(addr);
			if (!rn.empty()) return rn;
			std::string sym = symbol_store::resolve_symbol_exact(addr);
			if (!sym.empty()) return strip_module_prefix(sym);
			return make_synthetic_sub(addr);
		}

		inline std::string pad_right(const std::string& s, size_t width) {
			if (s.size() >= width) return s + " ";
			std::string out = s;
			out.append(width - s.size(), ' ');
			return out;
		}

		inline bool resolve_module_for_address(uint64_t addr, uint64_t& out_base,
			uint32_t& out_size, std::string& out_name)
		{
			if (!driver_bridge::is_loaded()) return false;
			auto modules = driver_bridge::enumerate_modules();
			if (modules.empty()) return false;

			for (const auto& m : modules) {
				if (m.base == 0 || m.size == 0) continue;
				if (addr >= m.base && addr < m.base + m.size) {
					out_base = m.base;
					out_size = m.size;
					out_name = m.name;
					return true;
				}
			}
			return false;
		}

		inline bool fetch_active_module(uint64_t& out_base, uint32_t& out_size,
			std::string& out_name)
		{
			if (!driver_bridge::is_loaded()) return false;
			auto modules = driver_bridge::enumerate_modules();
			if (modules.empty()) return false;

			const auto process_name = driver_bridge::attached_process_name();
			if (!process_name.empty()) {
				for (const auto& m : modules) {
					if (_stricmp(m.name.c_str(), process_name.c_str()) == 0) {
						if (m.base == 0 || m.size == 0) continue;
						out_base = m.base;
						out_size = m.size;
						out_name = m.name;
						return true;
					}
				}
			}

			const driver_bridge::module_info_t* best = nullptr;
			for (const auto& m : modules) {
				if (m.base == 0 || m.size == 0) continue;
				if (best == nullptr || m.base < best->base) {
					best = &m;
				}
			}
			if (best == nullptr) return false;
			out_base = best->base;
			out_size = best->size;
			out_name = best->name;
			return true;
		}

		inline std::string section_name_for_va(const pe_parser::pe_info_t& pe,
			uint64_t module_base, uint64_t va)
		{
			if (va < module_base) return std::string();
			uint32_t rva = static_cast<uint32_t>(va - module_base);
			for (const auto& s : pe.sections) {
				if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) {
					return s.name;
				}
			}
			return std::string();
		}

		inline void rebuild_bounds_index(uint64_t module_base, uint32_t module_size,
			const std::string& module_name)
		{
			pe_parser::pe_info_t pe;
			if (!pe_parser::parse(module_base, pe)) {
				cache_t& c = cache();
				std::unique_lock<std::shared_mutex> lk(c.mutex);
				c.by_start.clear();
				c.status_by_start.clear();
				c.addr_to_func_start.clear();
				c.sorted_starts.clear();
				c.synthetic_names.clear();
				c.cached_module_base = module_base;
				c.cached_module_size = module_size;
				c.cached_module_name = module_name;
				return;
			}

			std::vector<uint64_t> rf_starts;
			std::vector<uint32_t> rf_sizes;
			functions_panel::detail::read_runtime_function_table(module_base, pe,
				rf_starts, rf_sizes);

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

			std::vector<uint64_t> candidates;
			candidates.reserve(rf_starts.size() + pe.exports.size() + 64);
			for (uint64_t va : rf_starts) {
				if (va >= module_base && va < module_base + module_size) {
					candidates.push_back(va);
				}
			}
			for (const auto& exp : pe.exports) {
				if (exp.is_forwarded || exp.address == 0) continue;
				if (exp.address < module_base) continue;
				if (exp.address >= module_base + module_size) continue;
				candidates.push_back(exp.address);
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
						candidates.push_back(va);
					}
				}
			}

			if (pe.entry_point >= module_base && pe.entry_point < module_base + module_size) {
				candidates.push_back(pe.entry_point);
			}

			std::sort(candidates.begin(), candidates.end());
			candidates.erase(std::unique(candidates.begin(), candidates.end()),
				candidates.end());

			std::unordered_map<uint64_t, func_record_t>                  by_start;
			std::unordered_map<uint64_t, std::shared_ptr<func_status_t>> status_by_start;
			std::unordered_map<uint64_t, std::string>                    synthetic_names;
			std::vector<uint64_t>                                        sorted_starts;
			by_start.reserve(candidates.size());
			status_by_start.reserve(candidates.size());
			synthetic_names.reserve(candidates.size());
			sorted_starts.reserve(candidates.size());

			for (size_t i = 0; i < candidates.size(); ++i) {
				uint64_t start = candidates[i];
				uint64_t next = (i + 1 < candidates.size())
					? candidates[i + 1]
					: (module_base + module_size);

				uint32_t pdata_size = 0;
				auto sit = size_lookup.find(start);
				if (sit != size_lookup.end()) {
					pdata_size = sit->second;
				}

				uint64_t end = start + (pdata_size > 0 ? pdata_size : 1);
				if (end > next) end = next;
				if (end <= start) end = start + 1;
				if (end > module_base + module_size) end = module_base + module_size;

				func_record_t r;
				r.start = start;
				r.end = end;
				r.section = section_name_for_va(pe, module_base, start);
				r.display_name = resolve_display_name(start);
				r.last_insn_addr = start;
				synthetic_names.emplace(start, r.display_name);
				by_start.emplace(start, std::move(r));
				status_by_start.emplace(start, std::make_shared<func_status_t>());
				sorted_starts.push_back(start);
			}

			std::unordered_map<uint64_t, uint64_t> addr_to_func_start;
			addr_to_func_start.reserve(by_start.size());
			for (const auto& kv : by_start) {
				addr_to_func_start.emplace(kv.first, kv.first);
			}

			cache_t& c = cache();
			std::unique_lock<std::shared_mutex> lk(c.mutex);
			c.by_start = std::move(by_start);
			c.status_by_start = std::move(status_by_start);
			c.addr_to_func_start = std::move(addr_to_func_start);
			c.sorted_starts = std::move(sorted_starts);
			c.synthetic_names = std::move(synthetic_names);
			c.cached_module_base = module_base;
			c.cached_module_size = module_size;
			c.cached_module_name = module_name;
		}

		inline uint64_t lookup_function_start_for_addr(uint64_t addr) {
			cache_t& c = cache();
			std::shared_lock<std::shared_mutex> lk(c.mutex);
			if (c.sorted_starts.empty()) return 0;
			auto it = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), addr);
			if (it == c.sorted_starts.begin()) return 0;
			--it;
			uint64_t start = *it;
			auto rit = c.by_start.find(start);
			if (rit == c.by_start.end()) return 0;
			if (addr < rit->second.start || addr >= rit->second.end) return 0;
			return start;
		}

		inline uint32_t pdb_var_size_hint(const std::string& module_name,
			const std::string& sym_name)
		{
			std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
			auto it = symbol_store::g_state.modules.find(module_name);
			if (it == symbol_store::g_state.modules.end()) return 0;
			if (!it->second.pdb.loaded) return 0;
			auto nit = it->second.pdb.symbol_by_name.find(sym_name);
			if (nit == it->second.pdb.symbol_by_name.end()) return 0;
			const auto& sym = it->second.pdb.symbols[nit->second];
			return sym.size;
		}

		inline uint32_t operand_size_bytes(const ZydisDecodedOperand& op,
			const ZydisDecodedInstruction& ins)
		{
			if (op.size > 0) return op.size / 8u;
			return ins.operand_width / 8u;
		}

		inline void scan_function_body(func_record_t& r, const std::string& mod_name) {
			if (r.end <= r.start) return;
			size_t span = static_cast<size_t>(r.end - r.start);
			if (span > 0x100000) span = 0x100000;

			std::vector<uint8_t> bytes;
			if (!driver_bridge::read_memory(r.start, span, bytes)) return;
			if (bytes.empty()) return;

			zydis_detail::ensure_init();
			ZydisDecoder& dec = zydis_detail::decoder();

			std::unordered_map<int64_t, var_slot_t> var_map;
			std::unordered_set<uint64_t> branch_targets;
			std::unordered_set<uint64_t> ret_addrs;

			uint64_t last_insn_addr = r.start;

			size_t off = 0;
			while (off < bytes.size()) {
				size_t avail = bytes.size() - off;
				if (avail > 15) avail = 15;
				ZydisDecodedInstruction ins;
				ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
				if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, bytes.data() + off,
					avail, &ins, operands)))
				{
					off += 1;
					continue;
				}

				uint64_t va = r.start + off;
				last_insn_addr = va;

				if (ins.meta.category == ZYDIS_CATEGORY_RET) {
					ret_addrs.insert(va);
				}

				if (ins.mnemonic == ZYDIS_MNEMONIC_PUSH
					|| ins.mnemonic == ZYDIS_MNEMONIC_MOV
					|| ins.mnemonic == ZYDIS_MNEMONIC_LEA
					|| ins.mnemonic == ZYDIS_MNEMONIC_ADD
					|| ins.mnemonic == ZYDIS_MNEMONIC_SUB
					|| ins.mnemonic == ZYDIS_MNEMONIC_CMP
					|| ins.mnemonic == ZYDIS_MNEMONIC_TEST
					|| ins.mnemonic == ZYDIS_MNEMONIC_OR
					|| ins.mnemonic == ZYDIS_MNEMONIC_AND
					|| ins.mnemonic == ZYDIS_MNEMONIC_XOR
					|| ins.mnemonic == ZYDIS_MNEMONIC_INC
					|| ins.mnemonic == ZYDIS_MNEMONIC_DEC
					|| ins.mnemonic == ZYDIS_MNEMONIC_MOVZX
					|| ins.mnemonic == ZYDIS_MNEMONIC_MOVSX
					|| ins.mnemonic == ZYDIS_MNEMONIC_MOVSXD)
				{
					for (uint8_t i = 0; i < ins.operand_count_visible; ++i) {
						const auto& op = operands[i];
						if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
						if (op.mem.type != ZYDIS_MEMOP_TYPE_MEM
							&& op.mem.type != ZYDIS_MEMOP_TYPE_AGEN)
						{
							continue;
						}
						ZydisRegister base = op.mem.base;
						bool is_bp = (base == ZYDIS_REGISTER_RBP
							|| base == ZYDIS_REGISTER_EBP
							|| base == ZYDIS_REGISTER_BP);
						if (!is_bp) continue;
						if (op.mem.index != ZYDIS_REGISTER_NONE) continue;
						if (op.mem.disp.size == 0) continue;

						int64_t disp = op.mem.disp.value;
						uint32_t sz = operand_size_bytes(op, ins);
						if (sz == 0) sz = 4;

						auto vit = var_map.find(disp);
						if (vit == var_map.end()) {
							var_slot_t v;
							v.offset = disp;
							v.size = sz;
							var_map.emplace(disp, std::move(v));
						}
						else {
							if (sz > vit->second.size) vit->second.size = sz;
						}

						r.bp_based = true;
					}
				}

				if (ins.meta.category == ZYDIS_CATEGORY_COND_BR
					|| ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR
					|| ins.meta.category == ZYDIS_CATEGORY_CALL)
				{
					for (uint8_t i = 0; i < ins.operand_count_visible; ++i) {
						const auto& op = operands[i];
						if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
						if (!op.imm.is_relative) continue;
						uint64_t tgt = 0;
						if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, va, &tgt))) {
							if (tgt > r.start && tgt < r.end) {
								branch_targets.insert(tgt);
							}
						}
					}
				}

				off += ins.length;
			}

			r.ret_addrs = std::move(ret_addrs);
			r.last_insn_addr = last_insn_addr;

			std::vector<var_slot_t> vars;
			vars.reserve(var_map.size());
			for (auto& kv : var_map) {
				vars.push_back(std::move(kv.second));
			}
			std::sort(vars.begin(), vars.end(),
				[](const var_slot_t& a, const var_slot_t& b) {
					return a.offset < b.offset;
				});

			for (auto& v : vars) {
				if (v.offset < 0) {
					std::string nm = "var_" + format_hex_upper(static_cast<uint64_t>(-v.offset));
					if (!mod_name.empty()) {
						uint32_t hint = pdb_var_size_hint(mod_name, nm);
						if (hint > 0) v.size = hint;
					}
					v.name = std::move(nm);
				}
				else if (v.offset > 0) {
					std::string nm = "arg_" + format_hex_upper(static_cast<uint64_t>(v.offset));
					if (!mod_name.empty()) {
						uint32_t hint = pdb_var_size_hint(mod_name, nm);
						if (hint > 0) v.size = hint;
					}
					v.name = std::move(nm);
				}
				else {
					v.name = "saved_bp";
				}
			}
			r.vars = std::move(vars);

			std::vector<label_slot_t> labels;
			labels.reserve(branch_targets.size());
			for (uint64_t t : branch_targets) {
				if (t == r.start) continue;
				label_slot_t ls;
				ls.addr = t;
				ls.is_locret = (r.ret_addrs.find(t) != r.ret_addrs.end());
				labels.push_back(ls);
			}
			std::sort(labels.begin(), labels.end(),
				[](const label_slot_t& a, const label_slot_t& b) {
					return a.addr < b.addr;
				});
			r.labels = std::move(labels);

			r.inline_labels.clear();
			r.inline_labels.reserve(r.labels.size());
			for (const auto& ls : r.labels) {
				std::string nm = ls.is_locret
					? std::string("locret_") + format_hex_upper(ls.addr) + ":"
					: std::string("loc_") + format_hex_upper(ls.addr) + ":";
				r.inline_labels.emplace(ls.addr, std::move(nm));
			}
		}

		inline void build_before_after(func_record_t& r) {
			r.before_first_insn.clear();
			r.after_last_insn.clear();

			injection_row_t banner;
			banner.kind = injection_t::function_banner;
			banner.addr = r.start;
			banner.text =
				"; =============== S U B R O U T I N E =======================================";
			r.before_first_insn.push_back(std::move(banner));

			injection_row_t sp1;
			sp1.kind = injection_t::spacer_line;
			sp1.addr = r.start;
			r.before_first_insn.push_back(sp1);

			injection_row_t sp2 = sp1;
			r.before_first_insn.push_back(sp2);

			if (r.bp_based) {
				injection_row_t attr;
				attr.kind = injection_t::attributes_line;
				attr.addr = r.start;
				attr.text = "; Attributes: bp-based frame";
				r.before_first_insn.push_back(std::move(attr));

				injection_row_t sp_after_attr = sp1;
				r.before_first_insn.push_back(sp_after_attr);
			}

			injection_row_t header;
			header.kind = injection_t::proc_header;
			header.addr = r.start;
			std::string name_padded = pad_right(r.display_name, 16);
			header.text = name_padded + "proc near";
			r.before_first_insn.push_back(std::move(header));

			injection_row_t sp_after_header = sp1;
			r.before_first_insn.push_back(sp_after_header);

			if (!r.vars.empty()) {
				for (const auto& v : r.vars) {
					injection_row_t row;
					row.kind = injection_t::var_decl;
					row.addr = r.start;
					std::string n_padded = pad_right(v.name, 16);
					std::string ptr_word = ptr_word_for_size(v.size);
					std::string disp = format_signed_hex(v.offset);
					row.text = n_padded + "= " + ptr_word + " " + disp;
					r.before_first_insn.push_back(std::move(row));
				}
				injection_row_t sp_after_vars = sp1;
				r.before_first_insn.push_back(sp_after_vars);
			}

			injection_row_t endp;
			endp.kind = injection_t::proc_endp;
			endp.addr = r.end;
			std::string name_padded2 = pad_right(r.display_name, 16);
			if (r.sp_analysis_failed) {
				endp.text = name_padded2 + "endp ; sp-analysis failed";
			}
			else {
				endp.text = name_padded2 + "endp";
			}
			r.after_last_insn.push_back(std::move(endp));

			injection_row_t sp_after_endp;
			sp_after_endp.kind = injection_t::spacer_line;
			sp_after_endp.addr = r.end;
			r.after_last_insn.push_back(sp_after_endp);

			injection_row_t sep;
			sep.kind = injection_t::endp_separator;
			sep.addr = r.end;
			sep.text =
				"; ---------------------------------------------------------------------------";
			r.after_last_insn.push_back(std::move(sep));
		}

		inline void schedule_function_build(uint64_t func_start,
			std::shared_ptr<func_status_t> status,
			const std::string& mod_name)
		{
			if (!status) return;
			uint32_t expected = static_cast<uint32_t>(func_state_t::idle);
			if (!status->state.compare_exchange_strong(expected,
				static_cast<uint32_t>(func_state_t::building),
				std::memory_order_acq_rel))
			{
				return;
			}

			work_queue::post([func_start, status, mod_name]() {
				if (driver_bridge::attached_pid() == 0) {
					status->state.store(static_cast<uint32_t>(func_state_t::idle),
						std::memory_order_release);
					return;
				}

				cache_t& c = cache();
				func_record_t snapshot;
				{
					std::shared_lock<std::shared_mutex> lk(c.mutex);
					auto it = c.by_start.find(func_start);
					if (it == c.by_start.end()) {
						status->state.store(static_cast<uint32_t>(func_state_t::failed),
							std::memory_order_release);
						return;
					}
					snapshot.start = it->second.start;
					snapshot.end = it->second.end;
					snapshot.section = it->second.section;
					snapshot.display_name = it->second.display_name;
				}

				snapshot.last_insn_addr = snapshot.start;
				if (snapshot.display_name.empty()
					|| snapshot.display_name.rfind("sub_", 0) == 0)
				{
					snapshot.display_name = resolve_display_name(snapshot.start);
				}

				scan_function_body(snapshot, mod_name);
				build_before_after(snapshot);

				{
					std::unique_lock<std::shared_mutex> lk(c.mutex);
					auto it = c.by_start.find(func_start);
					if (it == c.by_start.end()) {
						status->state.store(static_cast<uint32_t>(func_state_t::failed),
							std::memory_order_release);
						return;
					}
					it->second.bp_based = snapshot.bp_based;
					it->second.sp_analysis_failed = snapshot.sp_analysis_failed;
					it->second.vars = std::move(snapshot.vars);
					it->second.labels = std::move(snapshot.labels);
					it->second.ret_addrs = std::move(snapshot.ret_addrs);
					it->second.last_insn_addr = snapshot.last_insn_addr;
					it->second.inline_labels = std::move(snapshot.inline_labels);
					it->second.before_first_insn = std::move(snapshot.before_first_insn);
					it->second.after_last_insn = std::move(snapshot.after_last_insn);
					it->second.display_name = snapshot.display_name;
					c.synthetic_names[func_start] = snapshot.display_name;
				}

				status->state.store(static_cast<uint32_t>(func_state_t::built),
					std::memory_order_release);
			});
		}

		inline void schedule_bounds_rebuild() {
			cache_t& c = cache();
			uint32_t cur = c.bounds_state.load(std::memory_order_acquire);
			if (cur == static_cast<uint32_t>(bounds_state_t::building)) return;

			uint32_t expected = cur;
			if (!c.bounds_state.compare_exchange_strong(expected,
				static_cast<uint32_t>(bounds_state_t::building),
				std::memory_order_acq_rel))
			{
				return;
			}

			work_queue::post([]() {
				cache_t& c2 = cache();
				if (driver_bridge::attached_pid() == 0) {
					c2.bounds_state.store(static_cast<uint32_t>(bounds_state_t::idle),
						std::memory_order_release);
					return;
				}

				uint64_t base = 0;
				uint32_t size = 0;
				std::string name;
				if (!fetch_active_module(base, size, name)) {
					c2.bounds_state.store(static_cast<uint32_t>(bounds_state_t::failed),
						std::memory_order_release);
					return;
				}

				uint64_t pid_token = static_cast<uint64_t>(driver_bridge::attached_pid())
					^ (static_cast<uint64_t>(size) << 32);

				bool same = false;
				{
					std::shared_lock<std::shared_mutex> lk(c2.mutex);
					same = (c2.cached_module_base == base
						&& c2.cached_module_size == size
						&& c2.cached_pid_token == pid_token
						&& !c2.sorted_starts.empty());
				}
				if (same) {
					c2.bounds_state.store(static_cast<uint32_t>(bounds_state_t::ready),
						std::memory_order_release);
					return;
				}

				rebuild_bounds_index(base, size, name);
				{
					std::unique_lock<std::shared_mutex> lk(c2.mutex);
					c2.cached_pid_token = pid_token;
				}
				c2.bounds_state.store(static_cast<uint32_t>(bounds_state_t::ready),
					std::memory_order_release);
			});
		}

		inline void reset_all() {
			cache_t& c = cache();
			std::unique_lock<std::shared_mutex> lk(c.mutex);
			c.by_start.clear();
			c.status_by_start.clear();
			c.addr_to_func_start.clear();
			c.sorted_starts.clear();
			c.synthetic_names.clear();
			c.cached_module_base = 0;
			c.cached_module_size = 0;
			c.cached_module_name.clear();
			c.cached_pid_token = 0;
			c.bounds_state.store(static_cast<uint32_t>(bounds_state_t::idle),
				std::memory_order_release);
		}

	}

	inline std::string synthetic_name(uint64_t addr) {
		std::string rn = rename_store::get(addr);
		if (!rn.empty()) return rn;

		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		auto it = c.synthetic_names.find(addr);
		if (it != c.synthetic_names.end() && !it->second.empty()) return it->second;
		return detail::make_synthetic_sub(addr);
	}

	inline void on_attach_changed() {
		detail::reset_all();
	}

	inline void warm_range(uint64_t lo_addr, uint64_t hi_addr) {
		if (lo_addr >= hi_addr) return;
		if (driver_bridge::attached_pid() == 0) return;

		detail::cache_t& c = detail::cache();
		uint32_t bs = c.bounds_state.load(std::memory_order_acquire);

		if (bs == static_cast<uint32_t>(detail::bounds_state_t::idle)
			|| bs == static_cast<uint32_t>(detail::bounds_state_t::failed))
		{
			detail::schedule_bounds_rebuild();
			return;
		}

		if (bs != static_cast<uint32_t>(detail::bounds_state_t::ready)) return;

		std::vector<std::pair<uint64_t, std::shared_ptr<detail::func_status_t>>> targets;
		std::string mod_name;
		{
			std::shared_lock<std::shared_mutex> lk(c.mutex);
			if (c.sorted_starts.empty()) return;
			mod_name = c.cached_module_name;
			auto lo_it = std::lower_bound(c.sorted_starts.begin(),
				c.sorted_starts.end(), lo_addr);
			if (lo_it != c.sorted_starts.begin()) {
				auto prev = lo_it;
				--prev;
				auto rit = c.by_start.find(*prev);
				if (rit != c.by_start.end() && rit->second.end > lo_addr) {
					auto sit = c.status_by_start.find(*prev);
					if (sit != c.status_by_start.end()) {
						targets.emplace_back(*prev, sit->second);
					}
				}
			}
			auto hi_it = std::upper_bound(c.sorted_starts.begin(),
				c.sorted_starts.end(), hi_addr);
			for (auto it = lo_it; it != hi_it; ++it) {
				auto sit = c.status_by_start.find(*it);
				if (sit != c.status_by_start.end()) {
					targets.emplace_back(*it, sit->second);
				}
			}
		}

		for (auto& kv : targets) {
			if (!kv.second) continue;
			uint32_t st = kv.second->state.load(std::memory_order_acquire);
			if (st != static_cast<uint32_t>(detail::func_state_t::idle)) continue;
			detail::schedule_function_build(kv.first, kv.second, mod_name);
		}
	}

	inline std::vector<injection_row_t> rows_before(uint64_t addr) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return {};
		auto sit = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), addr);
		if (sit == c.sorted_starts.begin()) return {};
		--sit;
		uint64_t func_start = *sit;
		if (addr != func_start) return {};
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return {};
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return {};
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return {};
		}
		return it->second.before_first_insn;
	}

	inline std::vector<injection_row_t> rows_after(uint64_t addr) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return {};
		auto sit = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), addr);
		if (sit == c.sorted_starts.begin()) return {};
		--sit;
		uint64_t func_start = *sit;
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return {};
		const auto& rec = it->second;
		if (addr < rec.start || addr >= rec.end) return {};
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return {};
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return {};
		}
		if (addr != rec.last_insn_addr) return {};
		return rec.after_last_insn;
	}

	inline std::string inline_label_at(uint64_t addr) {
		detail::cache_t& c = detail::cache();
		std::shared_lock<std::shared_mutex> lk(c.mutex);
		if (c.sorted_starts.empty()) return std::string();
		auto sit = std::upper_bound(c.sorted_starts.begin(), c.sorted_starts.end(), addr);
		if (sit == c.sorted_starts.begin()) return std::string();
		--sit;
		uint64_t func_start = *sit;
		if (addr == func_start) return std::string();
		auto it = c.by_start.find(func_start);
		if (it == c.by_start.end()) return std::string();
		const auto& rec = it->second;
		if (addr < rec.start || addr >= rec.end) return std::string();
		auto stit = c.status_by_start.find(func_start);
		if (stit == c.status_by_start.end() || !stit->second) return std::string();
		if (stit->second->state.load(std::memory_order_acquire)
			!= static_cast<uint32_t>(detail::func_state_t::built))
		{
			return std::string();
		}
		auto lit = rec.inline_labels.find(addr);
		if (lit == rec.inline_labels.end()) return std::string();
		return lit->second;
	}

}
