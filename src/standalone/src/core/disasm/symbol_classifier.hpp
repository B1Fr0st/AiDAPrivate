#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "event_bus.hpp"
#include "pe_parser.hpp"
#include "standalone_driver.hpp"
#include "symbol_store.hpp"
#include "work_queue.hpp"

namespace symbol_classifier {

	enum class kind_t {
		unknown          = 0,
		regular_function = 1,
		library_function = 2,
		lumina_function  = 3,
		external_import  = 4,
		instruction      = 5,
		data             = 6,
		string           = 7,
		label            = 8,
		register_op      = 9,
		immediate        = 10,
		comment          = 11
	};

	inline const char* kind_name(kind_t kind) {
		switch (kind) {
			case kind_t::regular_function: return "regular_function";
			case kind_t::library_function: return "library_function";
			case kind_t::lumina_function:  return "lumina_function";
			case kind_t::external_import:  return "external_import";
			case kind_t::instruction:      return "instruction";
			case kind_t::data:             return "data";
			case kind_t::string:           return "string";
			case kind_t::label:            return "label";
			case kind_t::register_op:      return "register_op";
			case kind_t::immediate:        return "immediate";
			case kind_t::comment:          return "comment";
			case kind_t::unknown:          return "unknown";
		}
		return "unknown";
	}

	namespace detail {

		enum class build_state_t : uint32_t {
			idle = 0,
			building = 1,
			built = 2,
			failed = 3
		};

		struct section_range_t {
			uint64_t start_va = 0;
			uint64_t end_va = 0;
			uint32_t characteristics = 0;
			bool     is_code = false;
			bool     is_data = false;
		};

		struct module_entry_t {
			std::string                            name;
			uint64_t                               base = 0;
			uint64_t                               size = 0;
			std::vector<section_range_t>           sections;
			std::unordered_map<uint64_t, kind_t>   address_kind;
			std::unordered_set<std::string>        external_names;
			std::atomic<uint32_t>                  state{static_cast<uint32_t>(build_state_t::idle)};
		};

		struct module_range_t {
			uint64_t                          start_va = 0;
			uint64_t                          end_va = 0;
			std::shared_ptr<module_entry_t>   entry;
		};

		struct registry_t {
			std::shared_mutex                                              rw;
			std::unordered_map<std::string, std::shared_ptr<module_entry_t>> modules;
			std::vector<module_range_t>                                    table;
			std::atomic<bool>                                              table_built{false};
			std::atomic<bool>                                              subscription_armed{false};
			aida::events::subscription_handle_t                            subscription;
			std::atomic<uint64_t>                                          generation{0};
		};

		inline registry_t& registry() {
			static registry_t r;
			return r;
		}

		inline bool ascii_eq_lower(char a, char b) {
			if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
			if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
			return a == b;
		}

		inline bool name_starts_with(std::string_view name, std::string_view prefix) {
			if (name.size() < prefix.size()) return false;
			for (size_t i = 0; i < prefix.size(); ++i) {
				if (!ascii_eq_lower(name[i], prefix[i])) return false;
			}
			return true;
		}

		inline bool name_contains_ci(std::string_view name, std::string_view needle) {
			if (needle.empty()) return true;
			if (name.size() < needle.size()) return false;
			const size_t limit = name.size() - needle.size();
			for (size_t i = 0; i <= limit; ++i) {
				bool match = true;
				for (size_t j = 0; j < needle.size(); ++j) {
					if (!ascii_eq_lower(name[i + j], needle[j])) {
						match = false;
						break;
					}
				}
				if (match) return true;
			}
			return false;
		}

		inline bool is_register_token(std::string_view name) {
			if (name.empty() || name.size() > 6) return false;
			static constexpr std::array<std::string_view, 89> kRegs = {
				"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
				"r8","r9","r10","r11","r12","r13","r14","r15",
				"eax","ebx","ecx","edx","esi","edi","ebp","esp",
				"r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
				"ax","bx","cx","dx","si","di","bp","sp",
				"r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
				"al","bl","cl","dl","ah","bh","ch","dh","sil","dil","bpl","spl",
				"r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
				"rip","eip","ip","cs","ds","es","fs","gs","ss",
				"st0","st1","st2","st3","st4","st5","st6","st7",
				"mxcsr","eflags","rflags","fpu"
			};
			for (auto r : kRegs) {
				if (name.size() != r.size()) continue;
				bool eq = true;
				for (size_t i = 0; i < r.size(); ++i) {
					if (!ascii_eq_lower(name[i], r[i])) { eq = false; break; }
				}
				if (eq) return true;
			}
			if (name.size() >= 3 && name.size() <= 6) {
				char c0 = name[0]; if (c0 >= 'A' && c0 <= 'Z') c0 = static_cast<char>(c0 - 'A' + 'a');
				char c1 = name[1]; if (c1 >= 'A' && c1 <= 'Z') c1 = static_cast<char>(c1 - 'A' + 'a');
				const bool dr   = (c0 == 'd' && c1 == 'r');
				const bool cr   = (c0 == 'c' && c1 == 'r');
				if ((dr || cr) && name.size() >= 3) {
					for (size_t i = 2; i < name.size(); ++i) {
						if (name[i] < '0' || name[i] > '9') return false;
					}
					return true;
				}
				if (name.size() >= 4) {
					char c2 = name[2]; if (c2 >= 'A' && c2 <= 'Z') c2 = static_cast<char>(c2 - 'A' + 'a');
					const bool xmm  = (c0 == 'x' && c1 == 'm' && c2 == 'm');
					const bool ymm  = (c0 == 'y' && c1 == 'm' && c2 == 'm');
					const bool zmm  = (c0 == 'z' && c1 == 'm' && c2 == 'm');
					if (xmm || ymm || zmm) {
						for (size_t i = 3; i < name.size(); ++i) {
							if (name[i] < '0' || name[i] > '9') return false;
						}
						return true;
					}
				}
			}
			return false;
		}

		inline bool is_library_name(std::string_view name) {
			if (name.empty()) return false;
			static constexpr std::array<std::string_view, 28> kLibPrefixes = {
				"__security_",
				"__scrt_",
				"__std_",
				"__msvcrt_",
				"__report_",
				"__acrt_",
				"__crt_",
				"__vcrt_",
				"_RTC_",
				"_CRT_",
				"_amsg_",
				"_alloca_probe",
				"__chkstk",
				"__C_specific_handler",
				"__GSHandlerCheck",
				"__CxxFrameHandler",
				"__except_handler",
				"_fltused",
				"__threadhandle",
				"__threadid",
				"__guard_",
				"_initterm",
				"_initterm_e",
				"mainCRTStartup",
				"WinMainCRTStartup",
				"DllMainCRTStartup",
				"_DllMainCRTStartup",
				"__dyn_tls_init"
			};
			for (auto p : kLibPrefixes) {
				if (name_starts_with(name, p)) return true;
			}
			return false;
		}

		inline bool is_os_module(std::string_view module_name) {
			if (module_name.empty()) return false;
			static constexpr std::array<std::string_view, 32> kOsDlls = {
				"kernel32.dll", "kernelbase.dll", "ntdll.dll",
				"msvcrt.dll", "msvcr120.dll", "msvcr110.dll", "msvcr100.dll",
				"ucrtbase.dll", "ucrtbased.dll",
				"vcruntime.dll", "vcruntime140.dll", "vcruntime140d.dll",
				"vcruntime140_1.dll", "vcruntime140_1d.dll",
				"advapi32.dll", "user32.dll", "gdi32.dll", "gdi32full.dll",
				"shell32.dll", "shcore.dll", "ole32.dll", "oleaut32.dll",
				"ws2_32.dll", "wsock32.dll", "shlwapi.dll", "shlwapi.lib",
				"crypt32.dll", "bcrypt.dll", "bcryptprimitives.dll",
				"rpcrt4.dll", "sechost.dll", "combase.dll"
			};
			for (auto d : kOsDlls) {
				if (module_name.size() != d.size()) {
					if (name_contains_ci(module_name, d)) return true;
					continue;
				}
				bool eq = true;
				for (size_t i = 0; i < d.size(); ++i) {
					if (!ascii_eq_lower(module_name[i], d[i])) { eq = false; break; }
				}
				if (eq) return true;
			}
			return name_starts_with(module_name, "api-ms-win-");
		}

		inline bool section_name_is_data(const std::string& name) {
			if (name.empty()) return false;
			if (name == ".rdata") return true;
			if (name == ".data") return true;
			if (name == ".bss")  return true;
			if (name == ".idata") return true;
			if (name == ".tls") return true;
			if (name == ".CRT") return true;
			if (name == ".rodata") return true;
			return false;
		}

		inline bool section_name_is_code(uint32_t characteristics) {
			return (characteristics & 0x20000000u) != 0u;
		}

		inline section_range_t make_section_range(uint64_t module_base, const pe_parser::section_info_t& s) {
			section_range_t r;
			r.start_va = module_base + static_cast<uint64_t>(s.virtual_address);
			r.end_va = r.start_va + static_cast<uint64_t>(s.virtual_size != 0 ? s.virtual_size : s.raw_size);
			r.characteristics = s.characteristics;
			r.is_code = section_name_is_code(s.characteristics);
			r.is_data = !r.is_code && (((s.characteristics & 0x40000000u) != 0u) || section_name_is_data(s.name));
			return r;
		}

		inline const section_range_t* find_section(const std::vector<section_range_t>& secs, uint64_t va) {
			for (const auto& s : secs) {
				if (va >= s.start_va && va < s.end_va) return &s;
			}
			return nullptr;
		}

		inline bool read_runtime_function_starts(uint64_t module_base, std::vector<uint32_t>& out_starts) {
			out_starts.clear();
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
			if (!pe_parser::detail::read_mem(opt_addr + 136, &exception_dir_rva, 4)) return false;
			if (!pe_parser::detail::read_mem(opt_addr + 140, &exception_dir_size, 4)) return false;
			if (exception_dir_rva == 0 || exception_dir_size < 12) return true;
			const uint32_t entry_size = 12;
			uint32_t count = exception_dir_size / entry_size;
			if (count == 0 || count > 0x100000) return true;
			std::vector<uint8_t> table;
			if (!driver_bridge::read_memory(module_base + exception_dir_rva,
				static_cast<size_t>(count) * entry_size, table)) return false;
			if (table.size() < static_cast<size_t>(count) * entry_size) {
				count = static_cast<uint32_t>(table.size() / entry_size);
			}
			out_starts.reserve(count);
			for (uint32_t i = 0; i < count; ++i) {
				uint32_t begin_rva = 0;
				uint32_t end_rva = 0;
				std::memcpy(&begin_rva, table.data() + i * entry_size + 0, 4);
				std::memcpy(&end_rva, table.data() + i * entry_size + 4, 4);
				if (begin_rva == 0 || end_rva <= begin_rva) continue;
				out_starts.push_back(begin_rva);
			}
			return true;
		}

		inline void scan_strings_in_blob(uint64_t base_va, const std::vector<uint8_t>& bytes,
			std::unordered_map<uint64_t, kind_t>& map)
		{
			const size_t n = bytes.size();
			if (n < 4) return;
			size_t i = 0;
			while (i < n) {
				size_t run_start = i;
				size_t printable = 0;
				while (i < n) {
					uint8_t b = bytes[i];
					bool ok = (b >= 0x20 && b < 0x7F) || b == '\t' || b == '\r' || b == '\n';
					if (!ok) break;
					++printable;
					++i;
				}
				if (printable >= 4 && i < n && bytes[i] == 0x00) {
					map[base_va + run_start] = kind_t::string;
				}
				while (i < n && bytes[i] == 0x00) ++i;
				if (printable < 4) {
					if (i == run_start) ++i;
				}
			}
			if (n >= 8) {
				size_t j = 0;
				while (j + 1 < n) {
					size_t run_start = j;
					size_t printable_w = 0;
					while (j + 1 < n) {
						uint8_t lo = bytes[j];
						uint8_t hi = bytes[j + 1];
						bool ok = (hi == 0) && ((lo >= 0x20 && lo < 0x7F) || lo == '\t' || lo == '\r' || lo == '\n');
						if (!ok) break;
						++printable_w;
						j += 2;
					}
					if (printable_w >= 4 && j + 1 < n && bytes[j] == 0 && bytes[j + 1] == 0) {
						uint64_t va = base_va + run_start;
						auto it = map.find(va);
						if (it == map.end()) map[va] = kind_t::string;
					}
					while (j + 1 < n && bytes[j] == 0 && bytes[j + 1] == 0) j += 2;
					if (printable_w < 4) {
						if (j == run_start) ++j;
					}
				}
			}
		}

		inline void apply_pdb_symbols(std::shared_ptr<module_entry_t>& mod) {
			std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
			auto it = symbol_store::g_state.modules.find(mod->name);
			if (it == symbol_store::g_state.modules.end()) return;
			const auto& ms = it->second;
			if (!ms.pdb.loaded) return;
			for (const auto& sym : ms.pdb.symbols) {
				if (!sym.is_function) continue;
				uint64_t va = mod->base + sym.rva;
				if (va < mod->base || va >= mod->base + mod->size) continue;
				kind_t k = is_library_name(sym.name) ? kind_t::library_function : kind_t::regular_function;
				auto eit = mod->address_kind.find(va);
				if (eit == mod->address_kind.end()) {
					mod->address_kind.emplace(va, k);
				} else if (eit->second == kind_t::regular_function && k == kind_t::library_function) {
					eit->second = kind_t::library_function;
				}
			}
		}

		inline void build_module_classification(std::shared_ptr<module_entry_t> mod) {
			if (!mod) return;
			if (driver_bridge::attached_pid() == 0) {
				mod->state.store(static_cast<uint32_t>(build_state_t::failed), std::memory_order_release);
				return;
			}
			pe_parser::pe_info_t pe;
			const bool pe_ok = pe_parser::parse(mod->base, pe);
			std::vector<section_range_t> sections;
			if (pe_ok) {
				sections.reserve(pe.sections.size());
				for (const auto& s : pe.sections) {
					sections.push_back(make_section_range(mod->base, s));
				}
			}

			std::unordered_map<uint64_t, kind_t> kinds;
			std::unordered_set<std::string>      external_names;
			kinds.reserve(8192);

			const bool host_module_is_os = is_os_module(mod->name);

			if (pe_ok) {
				for (const auto& imp : pe.imports) {
					if (imp.bound_address != 0) {
						kinds[imp.bound_address] = kind_t::external_import;
					}
					if (imp.iat_address != 0) {
						auto it = kinds.find(imp.iat_address);
						if (it == kinds.end()) kinds.emplace(imp.iat_address, kind_t::external_import);
					}
					if (!imp.function_name.empty()) {
						external_names.insert(imp.function_name);
						if (!imp.module_name.empty()) {
							std::string composite = imp.module_name;
							composite.push_back('!');
							composite.append(imp.function_name);
							external_names.insert(std::move(composite));
						}
					}
				}

				for (const auto& exp : pe.exports) {
					if (exp.address == 0) continue;
					kind_t k = (host_module_is_os || is_library_name(exp.name))
						? kind_t::library_function
						: kind_t::regular_function;
					auto it = kinds.find(exp.address);
					if (it == kinds.end()) {
						kinds.emplace(exp.address, k);
					} else if (it->second == kind_t::regular_function && k == kind_t::library_function) {
						it->second = kind_t::library_function;
					}
				}
			}

			std::vector<uint32_t> rfn_starts;
			read_runtime_function_starts(mod->base, rfn_starts);
			for (uint32_t rva : rfn_starts) {
				uint64_t va = mod->base + rva;
				if (va < mod->base || va >= mod->base + mod->size) continue;
				auto it = kinds.find(va);
				if (it == kinds.end()) {
					kinds.emplace(va, host_module_is_os ? kind_t::library_function : kind_t::regular_function);
				}
			}

			mod->sections = std::move(sections);
			mod->address_kind = std::move(kinds);
			mod->external_names = std::move(external_names);

			apply_pdb_symbols(mod);

			constexpr size_t kMaxStringScanBytes = 4u * 1024u * 1024u;
			for (const auto& sec : mod->sections) {
				if (!sec.is_data) continue;
				uint64_t span = sec.end_va > sec.start_va ? (sec.end_va - sec.start_va) : 0;
				if (span == 0) continue;
				size_t to_read = static_cast<size_t>(span < kMaxStringScanBytes ? span : kMaxStringScanBytes);
				std::vector<uint8_t> blob;
				if (!driver_bridge::read_memory(sec.start_va, to_read, blob) || blob.empty()) continue;
				scan_strings_in_blob(sec.start_va, blob, mod->address_kind);
			}

			mod->state.store(static_cast<uint32_t>(build_state_t::built), std::memory_order_release);
		}

		inline std::shared_ptr<module_entry_t> get_or_create_module_unlocked(registry_t& reg,
			const driver_bridge::module_info_t& m)
		{
			auto it = reg.modules.find(m.name);
			if (it != reg.modules.end()) {
				if (it->second->base == m.base && it->second->size == m.size)
					return it->second;
				reg.modules.erase(it);
			}
			auto mod = std::make_shared<module_entry_t>();
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
				r.entry = get_or_create_module_unlocked(reg, m);
				reg.table.push_back(std::move(r));
			}
			std::sort(reg.table.begin(), reg.table.end(),
				[](const module_range_t& a, const module_range_t& b) {
					return a.start_va < b.start_va;
				});
			reg.table_built.store(true, std::memory_order_release);
		}

		inline std::shared_ptr<module_entry_t> lookup_cached_module(uint64_t addr) {
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
			return it->entry;
		}

		inline void schedule_build_locked(std::shared_ptr<module_entry_t> mod) {
			if (!mod) return;
			uint32_t expected = static_cast<uint32_t>(build_state_t::idle);
			if (!mod->state.compare_exchange_strong(expected,
				static_cast<uint32_t>(build_state_t::building),
				std::memory_order_acq_rel))
				return;
			std::weak_ptr<module_entry_t> weak = mod;
			work_queue::post([weak]() {
				auto strong = weak.lock();
				if (!strong) return;
				build_module_classification(strong);
			});
		}

		inline void clear_caches() {
			auto& reg = registry();
			std::unique_lock<std::shared_mutex> lk(reg.rw);
			reg.table.clear();
			reg.modules.clear();
			reg.table_built.store(false, std::memory_order_release);
			reg.generation.fetch_add(1, std::memory_order_acq_rel);
		}

		inline void ensure_subscription() {
			auto& reg = registry();
			if (reg.subscription_armed.load(std::memory_order_acquire)) return;
			bool expected = false;
			if (!reg.subscription_armed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
			reg.subscription = aida::events::subscribe(
				aida::events::event_binary_loaded,
				[](const aida::events::binary_loaded_t&) {
					clear_caches();
				});
			if (!reg.subscription.valid()) {
				reg.subscription_armed.store(false, std::memory_order_release);
			}
		}

	}

	inline kind_t classify(uint64_t addr) {
		if (addr == 0) return kind_t::unknown;
		auto& reg = detail::registry();
		std::shared_lock<std::shared_mutex> lk(reg.rw);
		if (!reg.table_built.load(std::memory_order_acquire)) return kind_t::unknown;
		if (reg.table.empty()) return kind_t::unknown;
		auto it = std::upper_bound(reg.table.begin(), reg.table.end(), addr,
			[](uint64_t a, const detail::module_range_t& r) {
				return a < r.start_va;
			});
		if (it == reg.table.begin()) return kind_t::unknown;
		--it;
		if (addr < it->start_va || addr >= it->end_va) return kind_t::unknown;
		auto& entry = it->entry;
		if (!entry) return kind_t::unknown;
		uint32_t st = entry->state.load(std::memory_order_acquire);
		if (st != static_cast<uint32_t>(detail::build_state_t::built)) return kind_t::unknown;
		auto kit = entry->address_kind.find(addr);
		if (kit != entry->address_kind.end()) return kit->second;
		const detail::section_range_t* sec = detail::find_section(entry->sections, addr);
		if (sec) {
			if (sec->is_data) return kind_t::data;
			if (sec->is_code) return kind_t::unknown;
		}
		return kind_t::unknown;
	}

	inline kind_t classify_name(const std::string& name) {
		if (name.empty()) return kind_t::unknown;
		std::string_view nv(name);
		while (!nv.empty() && (nv.front() == ' ' || nv.front() == '\t')) nv.remove_prefix(1);
		while (!nv.empty() && (nv.back() == ' ' || nv.back() == '\t')) nv.remove_suffix(1);
		if (nv.empty()) return kind_t::unknown;

		if (detail::name_starts_with(nv, "sub_")) return kind_t::regular_function;
		if (detail::name_starts_with(nv, "locret_")) return kind_t::label;
		if (detail::name_starts_with(nv, "loc_")) return kind_t::label;
		if (detail::name_starts_with(nv, "j_")) return kind_t::label;
		if (detail::name_starts_with(nv, "nullsub_")) return kind_t::regular_function;
		if (detail::name_starts_with(nv, "off_")) return kind_t::data;
		if (detail::name_starts_with(nv, "dword_")) return kind_t::data;
		if (detail::name_starts_with(nv, "qword_")) return kind_t::data;
		if (detail::name_starts_with(nv, "word_")) return kind_t::data;
		if (detail::name_starts_with(nv, "byte_")) return kind_t::data;
		if (detail::name_starts_with(nv, "unk_")) return kind_t::data;
		if (detail::name_starts_with(nv, "asc_") || detail::name_starts_with(nv, "aS")) return kind_t::string;
		if (detail::name_starts_with(nv, "stru_")) return kind_t::data;

		if (detail::is_register_token(nv)) return kind_t::register_op;

		const auto bang = nv.find('!');
		if (bang != std::string_view::npos && bang > 0 && bang + 1 < nv.size()) {
			std::string_view module_part = nv.substr(0, bang);
			if (detail::is_os_module(module_part)) return kind_t::external_import;
		}

		auto& reg = detail::registry();
		{
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			std::string key(nv);
			for (const auto& kv : reg.modules) {
				if (!kv.second) continue;
				uint32_t st = kv.second->state.load(std::memory_order_acquire);
				if (st != static_cast<uint32_t>(detail::build_state_t::built)) continue;
				if (kv.second->external_names.find(key) != kv.second->external_names.end()) {
					return kind_t::external_import;
				}
			}
		}

		if (detail::is_library_name(nv)) return kind_t::library_function;

		return kind_t::unknown;
	}

	inline void warm_range(uint64_t lo_addr, uint64_t hi_addr) {
		if (hi_addr <= lo_addr) return;

		detail::ensure_subscription();

		auto& reg = detail::registry();

		if (!reg.table_built.load(std::memory_order_acquire)) {
			std::unique_lock<std::shared_mutex> lk(reg.rw);
			if (!reg.table_built.load(std::memory_order_acquire)) {
				detail::rebuild_module_table_unlocked(reg);
			}
		}

		std::vector<std::shared_ptr<detail::module_entry_t>> targets;
		{
			std::shared_lock<std::shared_mutex> lk(reg.rw);
			targets.reserve(reg.table.size());
			for (const auto& r : reg.table) {
				if (r.end_va <= lo_addr || r.start_va >= hi_addr) continue;
				if (!r.entry) continue;
				uint32_t s = r.entry->state.load(std::memory_order_acquire);
				if (s != static_cast<uint32_t>(detail::build_state_t::idle)) continue;
				targets.push_back(r.entry);
			}
		}

		for (auto& mod : targets) {
			detail::schedule_build_locked(mod);
		}
	}

	inline void on_attach_changed() {
		detail::clear_caches();
	}

}
