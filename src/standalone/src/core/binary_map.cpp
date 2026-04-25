#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "binary_map.hpp"

#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <ios>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "event_bus.hpp"
#include "pe_parser.hpp"
#include "standalone_driver.hpp"
#include "symbol_store.hpp"
#include "xref_db.hpp"
#include "xref_engine.hpp"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")

namespace aida {
namespace binary_map {

	namespace {

		std::mutex& state_mutex()
		{
			static std::mutex m;
			return m;
		}

		std::string& last_error_storage()
		{
			static std::string s;
			return s;
		}

		void set_last_error_unlocked(const std::string& msg)
		{
			last_error_storage() = msg;
		}

		void set_last_error(const std::string& msg)
		{
			std::lock_guard<std::mutex> guard(state_mutex());
			last_error_storage() = msg;
		}

		std::set<uint64_t>& pin_set()
		{
			static std::set<uint64_t> s;
			return s;
		}

		std::string& current_binary_hash()
		{
			static std::string s;
			return s;
		}

		struct cache_slot_t
		{
			std::string hash;
			map_t       map;
			bool        valid = false;
			int64_t     stored_unix = 0;
		};

		cache_slot_t& cache_slot()
		{
			static cache_slot_t s;
			return s;
		}

		aida::events::subscription_handle_t& invalidation_handle()
		{
			static aida::events::subscription_handle_t s;
			return s;
		}

		bool& subscription_armed()
		{
			static bool b = false;
			return b;
		}

		std::string sha256_hex(const void* data, size_t length)
		{
			HCRYPTPROV prov = 0;
			HCRYPTHASH hash = 0;
			unsigned char digest[32] = {};
			DWORD dlen = sizeof(digest);
			std::string out;

			if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES,
				CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
				return out;

			if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
				if (CryptHashData(hash,
					reinterpret_cast<const BYTE*>(data),
					static_cast<DWORD>(length), 0)) {
					if (CryptGetHashParam(hash, HP_HASHVAL, digest, &dlen, 0)) {
						static const char hexd[] = "0123456789abcdef";
						out.resize(static_cast<size_t>(dlen) * 2u);
						for (DWORD i = 0; i < dlen; ++i) {
							out[i * 2u] = hexd[(digest[i] >> 4) & 0xF];
							out[i * 2u + 1u] = hexd[digest[i] & 0xF];
						}
					}
				}
				CryptDestroyHash(hash);
			}
			CryptReleaseContext(prov, 0);
			return out;
		}

		std::string compute_binary_hash(const std::string& canonical_path)
		{
			if (canonical_path.empty())
				return std::string();
			std::string lower = canonical_path;
			for (auto& c : lower)
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			return sha256_hex(lower.data(), lower.size());
		}

		std::filesystem::path pin_directory()
		{
			wchar_t* appdata = nullptr;
			std::filesystem::path base;
			if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
				base = std::filesystem::path(appdata) / L"AiDA" / L"binary_map_pins";
				CoTaskMemFree(appdata);
			} else {
				base = std::filesystem::current_path() / "AiDA" / "binary_map_pins";
			}
			std::error_code ec;
			std::filesystem::create_directories(base, ec);
			return base;
		}

		std::filesystem::path pin_file_for_hash(const std::string& hash)
		{
			return pin_directory() / (hash + ".json");
		}

		void load_pins_for_hash(const std::string& hash)
		{
			pin_set().clear();
			if (hash.empty())
				return;

			auto path = pin_file_for_hash(hash);
			std::error_code ec;
			if (!std::filesystem::exists(path, ec))
				return;

			std::ifstream ifs(path);
			if (!ifs.is_open())
				return;

			try {
				nlohmann::json root = nlohmann::json::parse(ifs, nullptr, false);
				if (root.is_discarded())
					return;
				if (root.contains("pins") && root["pins"].is_array()) {
					for (const auto& v : root["pins"]) {
						if (v.is_number_unsigned() || v.is_number_integer()) {
							pin_set().insert(v.get<uint64_t>());
						} else if (v.is_string()) {
							const auto s = v.get<std::string>();
							if (s.size() > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
								char* endp = nullptr;
								const auto val = std::strtoull(s.c_str() + 2, &endp, 16);
								if (endp != nullptr && *endp == '\0')
									pin_set().insert(static_cast<uint64_t>(val));
							}
						}
					}
				}
			} catch (...) {
				return;
			}
		}

		void save_pins_for_hash(const std::string& hash)
		{
			if (hash.empty())
				return;

			auto path = pin_file_for_hash(hash);
			nlohmann::json root;
			nlohmann::json arr = nlohmann::json::array();
			for (const auto va : pin_set()) {
				char buf[32];
				std::snprintf(buf, sizeof(buf), "0x%llX",
					static_cast<unsigned long long>(va));
				arr.push_back(std::string(buf));
			}
			root["pins"] = std::move(arr);

			std::error_code ec;
			std::filesystem::create_directories(path.parent_path(), ec);
			std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
			if (!ofs.is_open())
				return;
			const std::string body = root.dump();
			ofs.write(body.data(), static_cast<std::streamsize>(body.size()));
		}

		void ensure_invalidation_subscription()
		{
			std::lock_guard<std::mutex> guard(state_mutex());
			if (subscription_armed())
				return;
			invalidation_handle() = aida::events::subscribe(
				aida::events::event_binary_loaded,
				[](const aida::events::binary_loaded_t& payload)
				{
					std::lock_guard<std::mutex> g(state_mutex());
					cache_slot().valid = false;
					cache_slot().hash.clear();
					cache_slot().map = map_t{};
					std::string canonical;
					try {
						canonical = std::filesystem::weakly_canonical(
							std::filesystem::path(payload.binary_path)).string();
					} catch (...) {
						canonical = payload.binary_path;
					}
					if (canonical.empty())
						canonical = payload.binary_path;
					const auto new_hash = compute_binary_hash(canonical);
					if (new_hash != current_binary_hash()) {
						current_binary_hash() = new_hash;
						pin_set().clear();
					}
					if (!new_hash.empty())
						load_pins_for_hash(new_hash);
				});
			subscription_armed() = invalidation_handle().valid();
		}

		bool is_section_executable(uint32_t characteristics)
		{
			return (characteristics & 0x20000000u) != 0u;
		}

		bool is_section_writable(uint32_t characteristics)
		{
			return (characteristics & 0x80000000u) != 0u;
		}

		bool is_section_readable(uint32_t characteristics)
		{
			return (characteristics & 0x40000000u) != 0u;
		}

		const driver_bridge::module_info_t* select_main_module(
			const std::vector<driver_bridge::module_info_t>& modules,
			const std::string& process_name)
		{
			if (modules.empty())
				return nullptr;

			if (!process_name.empty()) {
				for (const auto& m : modules) {
					if (_stricmp(m.name.c_str(), process_name.c_str()) == 0)
						return &m;
				}
			}

			const driver_bridge::module_info_t* best = &modules.front();
			for (const auto& m : modules) {
				if (m.base != 0 && (best->base == 0 || m.base < best->base))
					best = &m;
			}
			return best;
		}

		std::string section_name_for_va(const map_t& map, uint64_t va)
		{
			for (const auto& s : map.sections) {
				if (va >= s.va && va < s.va + s.size)
					return s.name;
			}
			return std::string();
		}

		std::string format_size_human(uint64_t bytes)
		{
			char buf[64];
			if (bytes >= (1ull << 30)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 30);
				std::snprintf(buf, sizeof(buf), "%.2f GB", v);
			} else if (bytes >= (1ull << 20)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 20);
				std::snprintf(buf, sizeof(buf), "%.2f MB", v);
			} else if (bytes >= (1ull << 10)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 10);
				std::snprintf(buf, sizeof(buf), "%.2f KB", v);
			} else {
				std::snprintf(buf, sizeof(buf), "%llu B",
					static_cast<unsigned long long>(bytes));
			}
			return buf;
		}

		std::string default_function_name(uint64_t va)
		{
			char buf[32];
			std::snprintf(buf, sizeof(buf), "sub_%llX",
				static_cast<unsigned long long>(va));
			return buf;
		}

		std::string default_global_name(uint64_t va)
		{
			char buf[32];
			std::snprintf(buf, sizeof(buf), "data_%llX",
				static_cast<unsigned long long>(va));
			return buf;
		}

		struct callee_summary_t
		{
			uint64_t target = 0;
			int      count = 0;
		};

		struct xref_snapshot_t
		{
			bool                                                              available = false;
			std::unordered_map<uint64_t, int>                                 to_count;
			std::unordered_map<uint64_t, std::vector<callee_summary_t>>       call_targets;
			std::unordered_map<uint64_t, std::vector<xref_engine::xref_type_t>> to_kinds;
		};

		void snapshot_xref_module(const std::string& module_name, xref_snapshot_t& out)
		{
			out = xref_snapshot_t{};
			std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
			auto it = xref_db::g_state.modules.find(module_name);
			if (it == xref_db::g_state.modules.end() || !it->second.built)
				return;

			const xref_db::module_index_t& mod = it->second;
			out.available = true;

			out.to_count.reserve(mod.to_index.size());
			out.to_kinds.reserve(mod.to_index.size());
			for (const auto& kv : mod.to_index) {
				out.to_count[kv.first] = static_cast<int>(kv.second.size());
				std::vector<xref_engine::xref_type_t> kinds;
				kinds.reserve(kv.second.size());
				for (const auto& e : kv.second)
					kinds.push_back(e.type);
				out.to_kinds[kv.first] = std::move(kinds);
			}

			out.call_targets.reserve(mod.from_index.size());
			for (const auto& kv : mod.from_index) {
				std::unordered_map<uint64_t, int> tally;
				for (const auto& e : kv.second) {
					if (e.type == xref_engine::xref_type_t::call)
						++tally[e.to_addr];
				}
				if (tally.empty())
					continue;
				std::vector<callee_summary_t> sums;
				sums.reserve(tally.size());
				for (const auto& tk : tally) {
					callee_summary_t cs;
					cs.target = tk.first;
					cs.count = tk.second;
					sums.push_back(cs);
				}
				std::sort(sums.begin(), sums.end(),
					[](const callee_summary_t& a, const callee_summary_t& b) {
						if (a.count != b.count) return a.count > b.count;
						return a.target < b.target;
					});
				out.call_targets[kv.first] = std::move(sums);
			}
		}

		bool collect_call_targets(const xref_snapshot_t& snap, uint64_t func_va,
			std::vector<callee_summary_t>& out, int& callee_count)
		{
			out.clear();
			callee_count = 0;
			auto it = snap.call_targets.find(func_va);
			if (it == snap.call_targets.end())
				return false;
			out = it->second;
			callee_count = static_cast<int>(out.size());
			return true;
		}

		std::string resolve_callee_name(uint64_t target,
			const std::unordered_map<uint64_t, std::string>& function_name_lookup,
			const std::unordered_map<uint64_t, std::string>& import_name_lookup,
			uint64_t image_base, uint64_t image_size)
		{
			auto fit = function_name_lookup.find(target);
			if (fit != function_name_lookup.end() && !fit->second.empty())
				return fit->second;

			auto iit = import_name_lookup.find(target);
			if (iit != import_name_lookup.end() && !iit->second.empty())
				return iit->second;

			std::string sym = symbol_store::resolve_symbol_exact(target);
			if (!sym.empty())
				return sym;

			std::string near_sym = symbol_store::resolve_symbol(target);
			if (!near_sym.empty())
				return near_sym;

			if (target >= image_base && target < image_base + image_size)
				return default_function_name(target);

			char buf[32];
			std::snprintf(buf, sizeof(buf), "%llX",
				static_cast<unsigned long long>(target));
			return buf;
		}

		struct pdb_symbol_snapshot_t
		{
			std::string name;
			uint64_t    rva = 0;
			bool        is_function = false;
		};

		void snapshot_pdb_symbols(const std::string& module_name,
			std::vector<pdb_symbol_snapshot_t>& out)
		{
			out.clear();
			std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
			auto it = symbol_store::g_state.modules.find(module_name);
			if (it == symbol_store::g_state.modules.end())
				return;
			if (!it->second.pdb.loaded)
				return;
			out.reserve(it->second.pdb.symbols.size());
			for (const auto& sym : it->second.pdb.symbols) {
				pdb_symbol_snapshot_t snap;
				snap.name = sym.name;
				snap.rva = sym.rva;
				snap.is_function = sym.is_function;
				out.push_back(std::move(snap));
			}
		}

		void enumerate_functions_from_pdb(const std::vector<pdb_symbol_snapshot_t>& syms,
			std::unordered_map<uint64_t, std::string>& out_lookup,
			std::vector<uint64_t>& out_function_vas,
			uint64_t module_base)
		{
			out_function_vas.clear();
			out_function_vas.reserve(syms.size());
			for (const auto& sym : syms) {
				if (!sym.is_function)
					continue;
				const uint64_t va = module_base + sym.rva;
				out_function_vas.push_back(va);
				if (out_lookup.find(va) == out_lookup.end())
					out_lookup[va] = sym.name;
			}
		}

		void enumerate_globals_from_pdb(const std::vector<pdb_symbol_snapshot_t>& syms,
			uint64_t module_base,
			std::vector<map_global_t>& out_globals,
			std::unordered_map<uint64_t, std::string>& out_lookup)
		{
			out_globals.clear();
			out_globals.reserve(syms.size());
			for (const auto& sym : syms) {
				if (sym.is_function)
					continue;
				if (sym.rva == 0)
					continue;
				map_global_t g;
				g.va = module_base + sym.rva;
				g.name = sym.name;
				out_globals.push_back(g);
				if (out_lookup.find(g.va) == out_lookup.end())
					out_lookup[g.va] = sym.name;
			}
		}

		bool detect_arch_format(const pe_parser::pe_info_t& pe, std::string& arch, std::string& format)
		{
			format = "PE";
			arch = pe.is_64bit ? "x64" : "x86";
			return true;
		}

		void seed_function_vas_from_xrefs(const xref_snapshot_t& snap,
			uint64_t image_base, uint64_t image_size,
			std::vector<uint64_t>& out_vas)
		{
			std::unordered_set<uint64_t> seeded(out_vas.begin(), out_vas.end());
			for (const auto& kv : snap.to_kinds) {
				const uint64_t target = kv.first;
				if (target < image_base || target >= image_base + image_size)
					continue;
				bool has_call = false;
				for (const auto kind : kv.second) {
					if (kind == xref_engine::xref_type_t::call) {
						has_call = true;
						break;
					}
				}
				if (!has_call)
					continue;
				if (seeded.insert(target).second)
					out_vas.push_back(target);
			}
		}

		int score_function(int xrefs, int callees, bool pinned)
		{
			int s = xrefs * 3 + callees;
			if (pinned)
				s += 1000;
			return s;
		}

		uint64_t now_unix_seconds()
		{
			using namespace std::chrono;
			return static_cast<uint64_t>(
				duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
		}

		bool generate_locked(const map_options_t& opts, map_t& out)
		{
			out = map_t{};

			if (!driver_bridge::is_loaded()) {
				set_last_error_unlocked("binary_map.generate: no driver/process attached");
				return false;
			}

			auto modules = driver_bridge::enumerate_modules();
			if (modules.empty()) {
				set_last_error_unlocked("binary_map.generate: no modules enumerated");
				return false;
			}

			const auto process_name = driver_bridge::attached_process_name();
			const auto* main_mod = select_main_module(modules, process_name);
			if (main_mod == nullptr) {
				set_last_error_unlocked("binary_map.generate: failed to select main module");
				return false;
			}

			pe_parser::pe_info_t pe;
			if (!pe_parser::parse(main_mod->base, pe)) {
				set_last_error_unlocked("binary_map.generate: PE parse failed");
				return false;
			}

			out.module_name = main_mod->name;
			out.module_path = main_mod->path;
			out.image_base = main_mod->base;
			out.image_size = (pe.size_of_image != 0)
				? static_cast<uint64_t>(pe.size_of_image)
				: static_cast<uint64_t>(main_mod->size);

			detect_arch_format(pe, out.architecture, out.format);

			out.sections.reserve(pe.sections.size());
			for (const auto& s : pe.sections) {
				map_section_t ms;
				ms.name = s.name;
				ms.va = main_mod->base + s.virtual_address;
				ms.size = s.virtual_size;
				ms.executable = is_section_executable(s.characteristics);
				ms.writable = is_section_writable(s.characteristics);
				ms.readable = is_section_readable(s.characteristics);
				out.sections.push_back(std::move(ms));
			}

			std::unordered_map<uint64_t, std::string> import_name_lookup;
			if (opts.include_imports) {
				out.imports.reserve(pe.imports.size());
				std::unordered_map<std::string, std::vector<std::string>> by_module;
				for (const auto& imp : pe.imports) {
					if (imp.iat_address != 0) {
						import_name_lookup[imp.iat_address] = imp.module_name + "!" + imp.function_name;
						if (imp.bound_address != 0)
							import_name_lookup[imp.bound_address] = imp.module_name + "!" + imp.function_name;
					}
					if (!imp.module_name.empty())
						by_module[imp.module_name].push_back(imp.function_name);
				}
				for (auto& kv : by_module) {
					std::sort(kv.second.begin(), kv.second.end());
					kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
					std::string line = kv.first + ": ";
					for (size_t i = 0; i < kv.second.size(); ++i) {
						if (i != 0) line += ", ";
						line += kv.second[i];
					}
					out.imports.push_back(std::move(line));
				}
				std::sort(out.imports.begin(), out.imports.end());
			}

			if (opts.include_exports) {
				out.exports.reserve(pe.exports.size());
				for (const auto& exp : pe.exports) {
					if (exp.is_forwarded || exp.name.empty())
						continue;
					out.exports.push_back(exp.name);
				}
				std::sort(out.exports.begin(), out.exports.end());
				out.exports.erase(std::unique(out.exports.begin(), out.exports.end()), out.exports.end());
			}

			std::vector<pdb_symbol_snapshot_t> pdb_syms;
			snapshot_pdb_symbols(main_mod->name, pdb_syms);

			std::unordered_map<uint64_t, std::string> function_name_lookup;
			std::vector<uint64_t> candidate_function_vas;
			enumerate_functions_from_pdb(pdb_syms, function_name_lookup,
				candidate_function_vas, main_mod->base);

			for (const auto& exp : pe.exports) {
				if (exp.is_forwarded || exp.address == 0)
					continue;
				if (function_name_lookup.find(exp.address) == function_name_lookup.end()) {
					if (!exp.name.empty())
						function_name_lookup[exp.address] = exp.name;
				}
				candidate_function_vas.push_back(exp.address);
			}

			xref_snapshot_t xref_snap;
			snapshot_xref_module(main_mod->name, xref_snap);

			std::vector<map_global_t> pdb_globals;
			std::unordered_map<uint64_t, std::string> data_name_lookup;
			enumerate_globals_from_pdb(pdb_syms, main_mod->base, pdb_globals, data_name_lookup);

			if (xref_snap.available) {
				seed_function_vas_from_xrefs(xref_snap, out.image_base, out.image_size,
					candidate_function_vas);
			}

			std::sort(candidate_function_vas.begin(), candidate_function_vas.end());
			candidate_function_vas.erase(
				std::unique(candidate_function_vas.begin(), candidate_function_vas.end()),
				candidate_function_vas.end());

			std::vector<uint64_t> pinned_snapshot(pin_set().begin(), pin_set().end());
			for (auto va : pinned_snapshot) {
				if (va >= out.image_base && va < out.image_base + out.image_size)
					candidate_function_vas.push_back(va);
			}
			std::sort(candidate_function_vas.begin(), candidate_function_vas.end());
			candidate_function_vas.erase(
				std::unique(candidate_function_vas.begin(), candidate_function_vas.end()),
				candidate_function_vas.end());

			std::vector<map_function_t> all_functions;
			all_functions.reserve(candidate_function_vas.size());

			const std::set<uint64_t>& pin_view = pin_set();

			for (const auto va : candidate_function_vas) {
				map_function_t fn;
				fn.va = va;
				auto nit = function_name_lookup.find(va);
				if (nit != function_name_lookup.end() && !nit->second.empty())
					fn.name = nit->second;
				else
					fn.name = default_function_name(va);

				auto xc = xref_snap.to_count.find(va);
				fn.xref_count = (xc != xref_snap.to_count.end()) ? xc->second : 0;

				std::vector<callee_summary_t> callees;
				int callee_total = 0;
				if (xref_snap.available)
					collect_call_targets(xref_snap, va, callees, callee_total);
				fn.callee_count = callee_total;

				const int max_top = opts.max_callees_per_function > 0
					? opts.max_callees_per_function : 5;
				const int take = (static_cast<int>(callees.size()) < max_top)
					? static_cast<int>(callees.size()) : max_top;
				fn.top_callees.reserve(take);
				for (int i = 0; i < take; ++i) {
					fn.top_callees.push_back(resolve_callee_name(
						callees[i].target,
						function_name_lookup,
						import_name_lookup,
						out.image_base,
						out.image_size));
				}

				fn.section_name = section_name_for_va(out, va);
				fn.pinned = pin_view.count(va) != 0;
				fn.score = score_function(fn.xref_count, fn.callee_count, fn.pinned);

				all_functions.push_back(std::move(fn));
			}

			std::sort(all_functions.begin(), all_functions.end(),
				[](const map_function_t& a, const map_function_t& b) {
					if (a.score != b.score) return a.score > b.score;
					if (a.xref_count != b.xref_count) return a.xref_count > b.xref_count;
					return a.va < b.va;
				});

			std::vector<map_function_t> selected;
			std::unordered_set<uint64_t> already;
			selected.reserve(static_cast<size_t>(opts.max_functions > 0 ? opts.max_functions : 50));

			for (const auto& fn : all_functions) {
				if (!fn.pinned) continue;
				if (already.insert(fn.va).second)
					selected.push_back(fn);
			}

			const int budget = opts.max_functions > 0 ? opts.max_functions : 50;
			for (const auto& fn : all_functions) {
				if (static_cast<int>(selected.size()) >= budget)
					break;
				if (already.insert(fn.va).second)
					selected.push_back(fn);
			}

			std::sort(selected.begin(), selected.end(),
				[](const map_function_t& a, const map_function_t& b) {
					if (a.score != b.score) return a.score > b.score;
					if (a.xref_count != b.xref_count) return a.xref_count > b.xref_count;
					return a.va < b.va;
				});

			out.functions = std::move(selected);

			std::vector<map_global_t> all_globals;
			all_globals.reserve(pdb_globals.size());
			for (auto& g : pdb_globals) {
				if (g.va < out.image_base || g.va >= out.image_base + out.image_size)
					continue;
				auto xc = xref_snap.to_count.find(g.va);
				g.xref_count = (xc != xref_snap.to_count.end()) ? xc->second : 0;
				if (g.xref_count <= 0)
					continue;
				g.section_name = section_name_for_va(out, g.va);
				for (const auto& sec : out.sections) {
					if (g.va >= sec.va && g.va < sec.va + sec.size) {
						g.writable = sec.writable;
						break;
					}
				}
				all_globals.push_back(std::move(g));
			}

			if (xref_snap.available) {
				for (const auto& kv : xref_snap.to_kinds) {
					const uint64_t target = kv.first;
					if (target < out.image_base || target >= out.image_base + out.image_size)
						continue;
					bool is_data = true;
					for (const auto kind : kv.second) {
						if (kind == xref_engine::xref_type_t::call ||
							kind == xref_engine::xref_type_t::jump ||
							kind == xref_engine::xref_type_t::conditional_jump) {
							is_data = false;
							break;
						}
					}
					if (!is_data)
						continue;

					bool in_writable_or_readonly = false;
					std::string sec_name;
					bool sec_writable = false;
					for (const auto& sec : out.sections) {
						if (target >= sec.va && target < sec.va + sec.size) {
							in_writable_or_readonly = !sec.executable;
							sec_name = sec.name;
							sec_writable = sec.writable;
							break;
						}
					}
					if (!in_writable_or_readonly)
						continue;

					auto already_has = std::find_if(all_globals.begin(), all_globals.end(),
						[&](const map_global_t& g) { return g.va == target; });
					if (already_has != all_globals.end())
						continue;

					map_global_t g;
					g.va = target;
					auto dit = data_name_lookup.find(target);
					g.name = (dit != data_name_lookup.end() && !dit->second.empty())
						? dit->second : default_global_name(target);
					g.xref_count = static_cast<int>(kv.second.size());
					g.section_name = sec_name;
					g.writable = sec_writable;
					all_globals.push_back(std::move(g));
				}
			}

			std::sort(all_globals.begin(), all_globals.end(),
				[](const map_global_t& a, const map_global_t& b) {
					if (a.xref_count != b.xref_count) return a.xref_count > b.xref_count;
					return a.va < b.va;
				});

			const int gbudget = opts.max_globals > 0 ? opts.max_globals : 30;
			if (static_cast<int>(all_globals.size()) > gbudget)
				all_globals.resize(static_cast<size_t>(gbudget));
			out.globals = std::move(all_globals);

			out.generated_unix = static_cast<int64_t>(now_unix_seconds());
			set_last_error_unlocked(std::string());
			return true;
		}

		std::string render_to_string(const map_t& map, const map_options_t& opts)
		{
			std::ostringstream oss;
			char hex[64];

			std::snprintf(hex, sizeof(hex), "0x%llX",
				static_cast<unsigned long long>(map.image_base));
			oss << "module " << (map.module_name.empty() ? std::string("<unnamed>") : map.module_name)
				<< " (" << (map.format.empty() ? std::string("PE") : map.format)
				<< " " << (map.architecture.empty() ? std::string("?") : map.architecture)
				<< ", base=" << hex
				<< ", size=" << format_size_human(map.image_size) << ")";
			oss << "\n\nsections:\n";

			for (const auto& s : map.sections) {
				const char* perm = s.executable
					? (s.writable ? "[exec rw]" : "[exec ro]")
					: (s.writable ? "[rw]" : "[ro]");
				char range[96];
				std::snprintf(range, sizeof(range), "0x%llX-0x%llX",
					static_cast<unsigned long long>(s.va),
					static_cast<unsigned long long>(s.va + s.size));
				oss << "  " << (s.name.empty() ? std::string("<unnamed>") : s.name)
					<< " " << perm
					<< " " << range
					<< " (" << format_size_human(s.size) << ")\n";
			}

			oss << "\nfunctions (top " << map.functions.size() << " by score):\n";
			for (const auto& fn : map.functions) {
				char addr[32];
				std::snprintf(addr, sizeof(addr), "0x%llX",
					static_cast<unsigned long long>(fn.va));
				oss << "  " << addr;
				if (!fn.name.empty() && fn.name != default_function_name(fn.va))
					oss << " \"" << fn.name << "\"";
				oss << " - " << fn.xref_count << " xrefs";
				if (fn.callee_count > 0) {
					oss << ", calls: ";
					for (size_t i = 0; i < fn.top_callees.size(); ++i) {
						if (i != 0) oss << ", ";
						oss << fn.top_callees[i];
					}
					if (fn.callee_count > static_cast<int>(fn.top_callees.size()))
						oss << ", ...";
				}
				if (fn.pinned)
					oss << " [pinned]";
				oss << "\n";
			}

			if (!map.globals.empty()) {
				oss << "\nglobals:\n";
				for (const auto& g : map.globals) {
					char addr[32];
					std::snprintf(addr, sizeof(addr), "0x%llX",
						static_cast<unsigned long long>(g.va));
					oss << "  " << g.name
						<< " (" << (g.writable ? "rw" : "ro")
						<< ") at " << addr
						<< " - " << g.xref_count << " xrefs\n";
				}
			}

			if (opts.include_imports && !map.imports.empty()) {
				oss << "\nimports:\n";
				for (const auto& line : map.imports)
					oss << "  " << line << "\n";
			}

			if (opts.include_exports && !map.exports.empty()) {
				oss << "\nexports:\n";
				for (size_t i = 0; i < map.exports.size(); ++i) {
					if (i != 0) oss << ", ";
					if (i % 8 == 0 && i != 0) oss << "\n  ";
					if (i == 0) oss << "  ";
					oss << map.exports[i];
				}
				oss << "\n";
			}

			return oss.str();
		}

		std::string render_text_locked(const map_t& map, const map_options_t& opts)
		{
			std::string result = render_to_string(map, opts);
			const size_t budget = (opts.max_chars == 0) ? 4096u : opts.max_chars;
			if (result.size() <= budget)
				return result;

			map_t trimmed = map;
			while (result.size() > budget && !trimmed.functions.empty()) {
				size_t drop_idx = trimmed.functions.size();
				for (size_t i = trimmed.functions.size(); i > 0; --i) {
					if (!trimmed.functions[i - 1].pinned) {
						drop_idx = i - 1;
						break;
					}
				}
				if (drop_idx >= trimmed.functions.size())
					break;
				trimmed.functions.erase(trimmed.functions.begin() + static_cast<std::ptrdiff_t>(drop_idx));
				result = render_to_string(trimmed, opts);
			}

			if (result.size() > budget) {
				if (budget >= 16)
					result.resize(budget - 16);
				result += "\n... [truncated]\n";
			}
			return result;
		}

	}

	bool generate(const map_options_t& opts, map_t& out)
	{
		ensure_invalidation_subscription();

		std::lock_guard<std::mutex> guard(state_mutex());

		std::string canonical_path;
		auto modules = driver_bridge::enumerate_modules();
		const auto process_name = driver_bridge::attached_process_name();
		const auto* main_mod = select_main_module(modules, process_name);
		if (main_mod != nullptr) {
			try {
				canonical_path = std::filesystem::weakly_canonical(
					std::filesystem::path(main_mod->path)).string();
			} catch (...) {
				canonical_path = main_mod->path;
			}
		}

		const std::string new_hash = compute_binary_hash(canonical_path);
		if (!new_hash.empty() && new_hash != current_binary_hash()) {
			current_binary_hash() = new_hash;
			pin_set().clear();
			load_pins_for_hash(new_hash);
			cache_slot().valid = false;
		}

		auto& slot = cache_slot();
		if (slot.valid && !slot.hash.empty() && slot.hash == new_hash) {
			out = slot.map;
			return true;
		}

		map_t fresh;
		if (!generate_locked(opts, fresh))
			return false;

		out = fresh;
		slot.hash = new_hash;
		slot.map = std::move(fresh);
		slot.valid = true;
		slot.stored_unix = static_cast<int64_t>(now_unix_seconds());
		return true;
	}

	std::string render_text(const map_t& map, const map_options_t& opts)
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		return render_text_locked(map, opts);
	}

	bool pin_function(uint64_t va)
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		const auto inserted = pin_set().insert(va).second;
		if (inserted) {
			save_pins_for_hash(current_binary_hash());
			cache_slot().valid = false;
		}
		return inserted;
	}

	bool unpin_function(uint64_t va)
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		const auto erased = pin_set().erase(va) != 0;
		if (erased) {
			save_pins_for_hash(current_binary_hash());
			cache_slot().valid = false;
		}
		return erased;
	}

	std::vector<uint64_t> pinned_functions()
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		return std::vector<uint64_t>(pin_set().begin(), pin_set().end());
	}

	bool clear_cache()
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		cache_slot().valid = false;
		cache_slot().hash.clear();
		cache_slot().map = map_t{};
		return true;
	}

	const std::string& last_error()
	{
		std::lock_guard<std::mutex> guard(state_mutex());
		return last_error_storage();
	}

	std::string auto_inject_text(size_t max_chars)
	{
		if (!driver_bridge::is_loaded())
			return std::string();

		auto modules = driver_bridge::enumerate_modules();
		if (modules.empty())
			return std::string();

		map_options_t opts;
		if (max_chars > 0)
			opts.max_chars = max_chars;
		else
			opts.max_chars = 4096;

		map_t m;
		if (!generate(opts, m))
			return std::string();

		std::string body = render_text(m, opts);
		if (body.empty())
			return std::string();

		const std::string header = "<binary_context>\n";
		const std::string footer = "\n</binary_context>";
		const size_t reserve = header.size() + footer.size();
		if (opts.max_chars > reserve && body.size() > opts.max_chars - reserve) {
			body.resize(opts.max_chars - reserve - 16);
			body += "\n... [truncated]";
		}
		return header + body + footer;
	}

}
}
