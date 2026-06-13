#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "binary_map.hpp"

#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
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

#include "../../helpers/diag_log.hpp"

#include "event_bus.hpp"
#include "pe_parser.hpp"
#include "standalone_driver.hpp"
#include "symbol_store.hpp"
#include "xref_db.hpp"
#include "xref_engine.hpp"
#include "zydis_disasm.hpp"
#include "function_index.hpp"

extern DisasmState g_disasm;

#pragma comment(lib, "bcrypt.lib")
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
			std::string out;
			BCRYPT_ALG_HANDLE alg = nullptr;
			BCRYPT_HASH_HANDLE hash = nullptr;
			unsigned char digest[32] = {};

			NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
			if (st < 0) {
				set_last_error_unlocked("binary_map.sha256_hex: BCryptOpenAlgorithmProvider failed");
				return out;
			}

			st = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
			if (st < 0) {
				BCryptCloseAlgorithmProvider(alg, 0);
				set_last_error_unlocked("binary_map.sha256_hex: BCryptCreateHash failed");
				return out;
			}

			st = BCryptHashData(hash,
				reinterpret_cast<PUCHAR>(const_cast<void*>(data)),
				static_cast<ULONG>(length), 0);
			if (st >= 0) {
				st = BCryptFinishHash(hash, digest, sizeof(digest), 0);
				if (st >= 0) {
					static const char hexd[] = "0123456789abcdef";
					out.resize(sizeof(digest) * 2u);
					for (size_t i = 0; i < sizeof(digest); ++i) {
						out[i * 2u] = hexd[(digest[i] >> 4) & 0xF];
						out[i * 2u + 1u] = hexd[digest[i] & 0xF];
					}
				} else {
					set_last_error_unlocked("binary_map.sha256_hex: BCryptFinishHash failed");
				}
			} else {
				set_last_error_unlocked("binary_map.sha256_hex: BCryptHashData failed");
			}

			BCryptDestroyHash(hash);
			BCryptCloseAlgorithmProvider(alg, 0);
			return out;
		}

		std::string compute_binary_hash(const std::string& canonical_path)
		{
			if (canonical_path.empty())
				return std::string();
			std::string lower = canonical_path;
			for (auto& c : lower)
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

			std::error_code mt_ec;
			const auto mtime = std::filesystem::last_write_time(
				std::filesystem::path(canonical_path), mt_ec);
			int64_t mtime_count = 0;
			if (!mt_ec)
				mtime_count = static_cast<int64_t>(mtime.time_since_epoch().count());

			std::string key;
			key.reserve(lower.size() + 24u);
			key.append(lower);
			key.push_back('|');
			char buf[32];
			std::snprintf(buf, sizeof(buf), "%lld",
				static_cast<long long>(mtime_count));
			key.append(buf);

			return sha256_hex(key.data(), key.size());
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

			nlohmann::json root = nlohmann::json::parse(ifs, nullptr, false);
			if (root.is_discarded())
				return;
			if (!root.contains("pins") || !root["pins"].is_array())
				return;

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

					std::error_code canon_ec;
					auto canonical = std::filesystem::weakly_canonical(
						std::filesystem::path(payload.binary_path), canon_ec).string();
					if (canon_ec || canonical.empty())
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

		float compute_shannon_entropy(const uint8_t* data, size_t length)
		{
			if (data == nullptr || length == 0)
				return 0.f;
			uint64_t freq[256] = {};
			for (size_t i = 0; i < length; ++i)
				++freq[data[i]];
			const double inv = 1.0 / static_cast<double>(length);
			double h = 0.0;
			for (int i = 0; i < 256; ++i) {
				if (freq[i] == 0) continue;
				const double p = static_cast<double>(freq[i]) * inv;
				h -= p * (std::log(p) / std::log(2.0));
			}
			if (h < 0.0) h = 0.0;
			if (h > 8.0) h = 8.0;
			return static_cast<float>(h / 8.0);
		}

		constexpr uint64_t kEntropyMaxSample = 256ull * 1024ull;
		constexpr uint64_t kEntropyMaxPerSection = 1024ull * 1024ull;

		void populate_section_entropy_static(std::vector<map_section_t>& sections)
		{
			for (auto& ms : sections) {
				if (ms.size == 0) {
					ms.entropy = 0.f;
					ms.sampled_bytes = 0;
					continue;
				}
				uint64_t to_read = ms.size;
				if (to_read > kEntropyMaxPerSection) to_read = kEntropyMaxPerSection;
				std::vector<uint8_t> blob;
				if (!static_analysis::read_bytes_from_pe(g_disasm.file, ms.va,
					static_cast<size_t>(to_read), blob) || blob.empty()) {
					ms.entropy = 0.f;
					ms.sampled_bytes = 0;
					diag::log_tagged_fmt("binary_map",
						"entropy_static SKIP name='%s' va=0x%llX size=%llu read_failed",
						ms.name.c_str(),
						static_cast<unsigned long long>(ms.va),
						static_cast<unsigned long long>(ms.size));
					continue;
				}
				size_t sample = blob.size();
				if (sample > kEntropyMaxSample) sample = static_cast<size_t>(kEntropyMaxSample);
				ms.entropy = compute_shannon_entropy(blob.data(), sample);
				ms.sampled_bytes = static_cast<uint64_t>(sample);
			}
		}

		void populate_section_entropy_live(std::vector<map_section_t>& sections)
		{
			for (auto& ms : sections) {
				if (ms.size == 0) {
					ms.entropy = 0.f;
					ms.sampled_bytes = 0;
					continue;
				}
				uint64_t to_read = ms.size;
				if (to_read > kEntropyMaxSample) to_read = kEntropyMaxSample;
				std::vector<uint8_t> blob;
				if (!driver_bridge::read_memory(ms.va, static_cast<size_t>(to_read), blob)
					|| blob.empty()) {
					ms.entropy = 0.f;
					ms.sampled_bytes = 0;
					diag::log_tagged_fmt("binary_map",
						"entropy_live SKIP name='%s' va=0x%llX size=%llu read_failed",
						ms.name.c_str(),
						static_cast<unsigned long long>(ms.va),
						static_cast<unsigned long long>(ms.size));
					continue;
				}
				ms.entropy = compute_shannon_entropy(blob.data(), blob.size());
				ms.sampled_bytes = static_cast<uint64_t>(blob.size());
			}
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

		void parse_static_exports(uint64_t module_base, pe_parser::pe_info_t& pe);
		void parse_static_imports(uint64_t module_base, pe_parser::pe_info_t& pe);

		bool read_static_mem(uint64_t addr, void* buf, size_t size)
		{
			std::vector<uint8_t> tmp;
			if (!static_analysis::read_bytes_from_pe(g_disasm.file, addr, size, tmp))
				return false;
			if (tmp.size() < size)
				return false;
			std::memcpy(buf, tmp.data(), size);
			return true;
		}

		bool read_static_string_at(uint64_t addr, size_t max_len, std::string& out)
		{
			out.clear();
			std::vector<uint8_t> blob;
			if (!static_analysis::read_bytes_from_pe(g_disasm.file, addr, max_len, blob))
				return false;
			for (size_t i = 0; i < blob.size(); ++i) {
				if (blob[i] == 0)
					return true;
				out.push_back(static_cast<char>(blob[i]));
			}
			return !out.empty();
		}

		bool parse_pe_static(uint64_t module_base, pe_parser::pe_info_t& out)
		{
			out = pe_parser::pe_info_t{};

			uint16_t dos_magic = 0;
			if (!read_static_mem(module_base, &dos_magic, 2)) return false;
			if (dos_magic != 0x5A4D) return false;

			uint32_t e_lfanew = 0;
			if (!read_static_mem(module_base + 0x3C, &e_lfanew, 4)) return false;
			if (e_lfanew > 0x1000) return false;

			uint64_t nt_addr = module_base + e_lfanew;
			uint32_t nt_sig = 0;
			if (!read_static_mem(nt_addr, &nt_sig, 4)) return false;
			if (nt_sig != 0x00004550) return false;

			uint8_t file_header[20];
			if (!read_static_mem(nt_addr + 4, file_header, 20)) return false;

			uint16_t num_sections = 0;
			std::memcpy(&num_sections, file_header + 2, 2);
			std::memcpy(&out.timestamp, file_header + 4, 4);
			uint16_t opt_header_size = 0;
			std::memcpy(&opt_header_size, file_header + 16, 2);
			std::memcpy(&out.characteristics, file_header + 18, 2);

			uint64_t opt_addr = nt_addr + 24;
			uint16_t opt_magic = 0;
			if (!read_static_mem(opt_addr, &opt_magic, 2)) return false;
			out.is_64bit = (opt_magic == 0x020B);

			uint8_t opt_buf[128];
			size_t to_read = (opt_header_size < 128) ? opt_header_size : 128;
			if (!read_static_mem(opt_addr, opt_buf, to_read)) return false;

			uint32_t ep_rva = 0;
			std::memcpy(&ep_rva, opt_buf + 16, 4);
			if (out.is_64bit) {
				std::memcpy(&out.image_base, opt_buf + 24, 8);
				std::memcpy(&out.size_of_image, opt_buf + 56, 4);
				if (to_read >= 70) std::memcpy(&out.subsystem, opt_buf + 68, 2);
				if (to_read >= 128) {
					std::memcpy(&out.export_dir_rva, opt_buf + 112, 4);
					std::memcpy(&out.export_dir_size, opt_buf + 116, 4);
					std::memcpy(&out.import_dir_rva, opt_buf + 120, 4);
					std::memcpy(&out.import_dir_size, opt_buf + 124, 4);
				}
			} else {
				uint32_t image_base_32 = 0;
				std::memcpy(&image_base_32, opt_buf + 28, 4);
				out.image_base = image_base_32;
				std::memcpy(&out.size_of_image, opt_buf + 56, 4);
				if (to_read >= 70) std::memcpy(&out.subsystem, opt_buf + 68, 2);
				if (to_read >= 104) {
					std::memcpy(&out.export_dir_rva, opt_buf + 96, 4);
					std::memcpy(&out.export_dir_size, opt_buf + 100, 4);
				}
				if (to_read >= 112) {
					std::memcpy(&out.import_dir_rva, opt_buf + 104, 4);
					std::memcpy(&out.import_dir_size, opt_buf + 108, 4);
				}
			}
			out.entry_point = module_base + ep_rva;

			uint64_t section_start = opt_addr + opt_header_size;
			if (num_sections > 96) num_sections = 96;
			for (uint16_t i = 0; i < num_sections; ++i) {
				uint8_t sec_buf[40];
				if (!read_static_mem(section_start + i * 40, sec_buf, 40)) break;
				pe_parser::section_info_t sec;
				char sec_name[9] = {};
				std::memcpy(sec_name, sec_buf, 8);
				sec_name[8] = 0;
				sec.name = sec_name;
				std::memcpy(&sec.virtual_size, sec_buf + 8, 4);
				std::memcpy(&sec.virtual_address, sec_buf + 12, 4);
				std::memcpy(&sec.raw_size, sec_buf + 16, 4);
				std::memcpy(&sec.characteristics, sec_buf + 36, 4);
				out.sections.push_back(std::move(sec));
			}

			parse_static_exports(module_base, out);
			parse_static_imports(module_base, out);
			return true;
		}

		void parse_static_exports(uint64_t module_base, pe_parser::pe_info_t& pe)
		{
			pe.exports.clear();
			if (pe.export_dir_rva == 0 || pe.export_dir_size == 0) return;

			uint64_t export_dir_addr = module_base + pe.export_dir_rva;
			uint8_t dir_buf[40];
			if (!read_static_mem(export_dir_addr, dir_buf, 40)) return;

			uint32_t num_functions = 0;
			uint32_t num_names = 0;
			uint32_t addr_table_rva = 0;
			uint32_t name_table_rva = 0;
			uint32_t ordinal_table_rva = 0;
			uint32_t ordinal_base = 0;
			std::memcpy(&ordinal_base, dir_buf + 16, 4);
			std::memcpy(&num_functions, dir_buf + 20, 4);
			std::memcpy(&num_names, dir_buf + 24, 4);
			std::memcpy(&addr_table_rva, dir_buf + 28, 4);
			std::memcpy(&name_table_rva, dir_buf + 32, 4);
			std::memcpy(&ordinal_table_rva, dir_buf + 36, 4);

			if (num_functions == 0 || num_functions > 0x10000) return;
			if (num_names > num_functions) num_names = num_functions;

			std::vector<uint32_t> addr_table(num_functions);
			if (!read_static_mem(module_base + addr_table_rva, addr_table.data(), num_functions * 4))
				return;

			std::vector<uint32_t> name_ptrs(num_names);
			std::vector<uint16_t> ordinals(num_names);
			if (num_names > 0) {
				if (!read_static_mem(module_base + name_table_rva, name_ptrs.data(), num_names * 4)) return;
				if (!read_static_mem(module_base + ordinal_table_rva, ordinals.data(), num_names * 2)) return;
			}

			std::vector<std::string> name_lookup(num_functions);
			for (uint32_t i = 0; i < num_names; ++i) {
				if (ordinals[i] < num_functions) {
					std::string fname;
					read_static_string_at(module_base + name_ptrs[i], 512, fname);
					name_lookup[ordinals[i]] = std::move(fname);
				}
			}

			uint32_t exp_start = pe.export_dir_rva;
			uint32_t exp_end = pe.export_dir_rva + pe.export_dir_size;

			pe.exports.reserve(num_functions);
			for (uint32_t i = 0; i < num_functions; ++i) {
				if (addr_table[i] == 0) continue;
				pe_parser::export_entry_t entry;
				entry.ordinal = static_cast<uint16_t>(ordinal_base + i);
				entry.rva = addr_table[i];
				entry.address = module_base + addr_table[i];
				entry.name = name_lookup[i];
				if (addr_table[i] >= exp_start && addr_table[i] < exp_end) {
					entry.is_forwarded = true;
					read_static_string_at(module_base + addr_table[i], 512, entry.forward_name);
				}
				pe.exports.push_back(std::move(entry));
			}
		}

		void parse_static_imports(uint64_t module_base, pe_parser::pe_info_t& pe)
		{
			pe.imports.clear();
			if (pe.import_dir_rva == 0 || pe.import_dir_size == 0) return;

			uint64_t import_dir_addr = module_base + pe.import_dir_rva;
			for (uint32_t desc_idx = 0; desc_idx < 4096; ++desc_idx) {
				uint8_t desc_buf[20];
				if (!read_static_mem(import_dir_addr + desc_idx * 20, desc_buf, 20)) break;

				uint32_t ilt_rva = 0;
				uint32_t name_rva = 0;
				uint32_t iat_rva = 0;
				std::memcpy(&ilt_rva, desc_buf + 0, 4);
				std::memcpy(&name_rva, desc_buf + 12, 4);
				std::memcpy(&iat_rva, desc_buf + 16, 4);
				if (ilt_rva == 0 && iat_rva == 0) break;

				std::string mod_name;
				if (name_rva != 0)
					read_static_string_at(module_base + name_rva, 256, mod_name);

				uint32_t lookup_rva = (ilt_rva != 0) ? ilt_rva : iat_rva;
				for (uint32_t thunk_idx = 0; thunk_idx < 0x10000; ++thunk_idx) {
					uint64_t thunk_addr = module_base + lookup_rva
						+ (pe.is_64bit ? thunk_idx * 8 : thunk_idx * 4);
					uint64_t thunk_val = 0;
					if (pe.is_64bit) {
						if (!read_static_mem(thunk_addr, &thunk_val, 8)) break;
					} else {
						uint32_t tmp32 = 0;
						if (!read_static_mem(thunk_addr, &tmp32, 4)) break;
						thunk_val = tmp32;
					}
					if (thunk_val == 0) break;

					pe_parser::import_entry_t entry;
					entry.module_name = mod_name;
					entry.iat_address = module_base + iat_rva
						+ (pe.is_64bit ? thunk_idx * 8 : thunk_idx * 4);
					uint64_t iat_val = 0;
					if (pe.is_64bit) read_static_mem(entry.iat_address, &iat_val, 8);
					else {
						uint32_t tmp32 = 0;
						read_static_mem(entry.iat_address, &tmp32, 4);
						iat_val = tmp32;
					}
					entry.bound_address = iat_val;

					bool is_ordinal = pe.is_64bit
						? (thunk_val & 0x8000000000000000ULL) != 0
						: (thunk_val & 0x80000000ULL) != 0;
					if (is_ordinal) {
						entry.ordinal = static_cast<uint16_t>(thunk_val & 0xFFFF);
						char ord_buf[32];
						snprintf(ord_buf, sizeof(ord_buf), "Ordinal#%u", entry.ordinal);
						entry.function_name = ord_buf;
					} else {
						uint32_t hint_name_rva = static_cast<uint32_t>(thunk_val & 0x7FFFFFFF);
						uint16_t hint = 0;
						read_static_mem(module_base + hint_name_rva, &hint, 2);
						entry.hint = hint;
						read_static_string_at(module_base + hint_name_rva + 2, 512,
							entry.function_name);
					}
					pe.imports.push_back(std::move(entry));
				}
			}
		}

		bool generate_static_locked(const map_options_t& opts, map_t& out)
		{
			out = map_t{};

			if (!function_index::detail::static_pe_active()) {
				set_last_error_unlocked("binary_map.generate_static: no static PE loaded");
				return false;
			}

			pe_parser::pe_info_t pe;
			const uint64_t image_base = g_disasm.file.image_base;
			if (!parse_pe_static(image_base, pe)) {
				set_last_error_unlocked("binary_map.generate_static: PE parse failed");
				return false;
			}

			out.module_name = g_disasm.file.filename.empty()
				? g_disasm.file.path : g_disasm.file.filename;
			out.module_path = g_disasm.file.path;
			out.image_base = image_base;
			out.image_size = (pe.size_of_image != 0)
				? static_cast<uint64_t>(pe.size_of_image)
				: static_analysis::total_image_size(g_disasm.file);

			detect_arch_format(pe, out.architecture, out.format);

			out.sections.reserve(pe.sections.size());
			for (const auto& s : pe.sections) {
				map_section_t ms;
				ms.name = s.name;
				ms.va = image_base + s.virtual_address;
				ms.size = s.virtual_size;
				ms.executable = is_section_executable(s.characteristics);
				ms.writable = is_section_writable(s.characteristics);
				ms.readable = is_section_readable(s.characteristics);
				out.sections.push_back(std::move(ms));
			}
			if (opts.include_entropy)
				populate_section_entropy_static(out.sections);
			else
				diag::log_tagged_fmt("binary_map", "entropy_static skipped sections=%zu", out.sections.size());

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
			snapshot_pdb_symbols(out.module_name, pdb_syms);

			std::unordered_map<uint64_t, std::string> function_name_lookup;
			std::vector<uint64_t> candidate_function_vas;
			enumerate_functions_from_pdb(pdb_syms, function_name_lookup,
				candidate_function_vas, image_base);

			for (const auto& exp : pe.exports) {
				if (exp.is_forwarded || exp.address == 0) continue;
				if (function_name_lookup.find(exp.address) == function_name_lookup.end()) {
					if (!exp.name.empty()) function_name_lookup[exp.address] = exp.name;
				}
				candidate_function_vas.push_back(exp.address);
			}

			xref_snapshot_t xref_snap;
			if (opts.include_xrefs)
				snapshot_xref_module(out.module_name, xref_snap);

			std::vector<map_global_t> pdb_globals;
			std::unordered_map<uint64_t, std::string> data_name_lookup;
			enumerate_globals_from_pdb(pdb_syms, image_base, pdb_globals, data_name_lookup);

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
				fn.name = (nit != function_name_lookup.end() && !nit->second.empty())
					? nit->second : default_function_name(va);

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
						callees[i].target, function_name_lookup,
						import_name_lookup, out.image_base, out.image_size));
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
				if (static_cast<int>(selected.size()) >= budget) break;
				if (already.insert(fn.va).second) selected.push_back(fn);
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
				if (g.va < out.image_base || g.va >= out.image_base + out.image_size) continue;
				auto xc = xref_snap.to_count.find(g.va);
				g.xref_count = (xc != xref_snap.to_count.end()) ? xc->second : 0;
				if (g.xref_count <= 0) continue;
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
					if (target < out.image_base || target >= out.image_base + out.image_size) continue;
					bool is_data = true;
					for (const auto kind : kv.second) {
						if (kind == xref_engine::xref_type_t::call ||
							kind == xref_engine::xref_type_t::jump ||
							kind == xref_engine::xref_type_t::conditional_jump) {
							is_data = false;
							break;
						}
					}
					if (!is_data) continue;
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
					if (!in_writable_or_readonly) continue;
					auto already_has = std::find_if(all_globals.begin(), all_globals.end(),
						[&](const map_global_t& g) { return g.va == target; });
					if (already_has != all_globals.end()) continue;
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

		bool generate_locked(const map_options_t& opts, map_t& out)
		{
			out = map_t{};

			if (!driver_bridge::is_loaded()) {
				if (function_index::detail::static_pe_active()) {
					return generate_static_locked(opts, out);
				}
				set_last_error_unlocked("binary_map.generate: no driver/process attached and no static PE loaded");
				return false;
			}

			auto modules = driver_bridge::enumerate_modules();
			if (modules.empty()) {
				if (function_index::detail::static_pe_active()) {
					return generate_static_locked(opts, out);
				}
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
			if (opts.include_entropy)
				populate_section_entropy_live(out.sections);
			else
				diag::log_tagged_fmt("binary_map", "entropy_live skipped sections=%zu", out.sections.size());

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
			if (opts.include_xrefs)
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
				char ent_buf[48];
				if (s.sampled_bytes > 0) {
					std::snprintf(ent_buf, sizeof(ent_buf), " H=%.2f",
						static_cast<double>(s.entropy) * 8.0);
				} else {
					ent_buf[0] = '\0';
				}
				oss << "  " << (s.name.empty() ? std::string("<unnamed>") : s.name)
					<< " " << perm
					<< " " << range
					<< " (" << format_size_human(s.size) << ")"
					<< ent_buf << "\n";
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

		const auto start_us = std::chrono::steady_clock::now();
		std::lock_guard<std::mutex> guard(state_mutex());

		std::string canonical_path;
		auto modules = driver_bridge::enumerate_modules();
		const auto process_name = driver_bridge::attached_process_name();
		const auto* main_mod = select_main_module(modules, process_name);
		if (main_mod != nullptr) {
			std::error_code canon_ec;
			canonical_path = std::filesystem::weakly_canonical(
				std::filesystem::path(main_mod->path), canon_ec).string();
			if (canon_ec || canonical_path.empty())
				canonical_path = main_mod->path;
		} else if (function_index::detail::static_pe_active()) {
			std::error_code canon_ec;
			canonical_path = std::filesystem::weakly_canonical(
				std::filesystem::path(g_disasm.file.path), canon_ec).string();
			if (canon_ec || canonical_path.empty())
				canonical_path = g_disasm.file.path;
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
			diag::log_tagged_fmt("binary_map",
				"generate cache_hit module='%s' funcs=%zu globals=%zu imports=%zu exports=%zu",
				slot.map.module_name.c_str(),
				slot.map.functions.size(),
				slot.map.globals.size(),
				slot.map.imports.size(),
				slot.map.exports.size());
			return true;
		}

		map_t fresh;
		if (!generate_locked(opts, fresh)) {
			diag::log_tagged_fmt("binary_map",
				"generate FAILED canonical='%s' err='%s'",
				canonical_path.c_str(), last_error_storage().c_str());
			return false;
		}

		const auto end_us = std::chrono::steady_clock::now();
		const auto dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			end_us - start_us).count();
		diag::log_tagged_fmt("binary_map",
			"generate ok module='%s' base=0x%llX size=%llu sections=%zu funcs=%zu globals=%zu imports=%zu exports=%zu entropy=%d duration_ms=%lld",
			fresh.module_name.c_str(),
			static_cast<unsigned long long>(fresh.image_base),
			static_cast<unsigned long long>(fresh.image_size),
			fresh.sections.size(), fresh.functions.size(),
			fresh.globals.size(), fresh.imports.size(),
			fresh.exports.size(),
			opts.include_entropy ? 1 : 0,
			static_cast<long long>(dur_ms));
		{
			size_t sampled_count = 0;
			uint64_t total_sampled_bytes = 0;
			for (const auto& s : fresh.sections) {
				if (s.sampled_bytes > 0) ++sampled_count;
				total_sampled_bytes += s.sampled_bytes;
				diag::log_tagged_fmt("binary_map",
					"[binmap_audit] section name='%s' va=0x%llX size=%llu sampled=%llu entropy01=%.3f H_bits=%.2f exec=%d write=%d",
					s.name.c_str(),
					static_cast<unsigned long long>(s.va),
					static_cast<unsigned long long>(s.size),
					static_cast<unsigned long long>(s.sampled_bytes),
					static_cast<double>(s.entropy),
					static_cast<double>(s.entropy) * 8.0,
					s.executable ? 1 : 0,
					s.writable ? 1 : 0);
			}
			diag::log_tagged_fmt("binary_map",
				"[binmap_audit] entropy_summary module='%s' sections=%zu sampled=%zu total_sampled_bytes=%llu",
				fresh.module_name.c_str(),
				fresh.sections.size(), sampled_count,
				static_cast<unsigned long long>(total_sampled_bytes));
			diag::log_tagged_fmt("binary_map",
				"[binmap_audit] BROKEN_FEATURES resource_tree=not_wired strings_overlay=not_wired (pe_parser::pe_info_t lacks resource_dir_rva/strings; out-of-scope-for-view-audit)");
		}

		out = fresh;
		if (opts.include_entropy) {
			slot.hash = new_hash;
			slot.map = std::move(fresh);
			slot.valid = true;
			slot.stored_unix = static_cast<int64_t>(now_unix_seconds());
		}
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
		diag::log_tagged_fmt("binary_map",
			"pin va=0x%llX inserted=%d total_pins=%zu",
			static_cast<unsigned long long>(va),
			inserted ? 1 : 0, pin_set().size());
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
		diag::log_tagged_fmt("binary_map",
			"unpin va=0x%llX erased=%d total_pins=%zu",
			static_cast<unsigned long long>(va),
			erased ? 1 : 0, pin_set().size());
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
		const bool has_live = driver_bridge::is_loaded()
			&& !driver_bridge::enumerate_modules().empty();
		const bool has_static = function_index::detail::static_pe_active();
		if (!has_live && !has_static)
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
