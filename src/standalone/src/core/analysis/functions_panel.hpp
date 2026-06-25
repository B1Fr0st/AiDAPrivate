#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../helpers/globals.h"
#include "zydis_disasm.hpp"
#include "disasm_view.hpp"
#include "pe_parser.hpp"
#include "symbol_store.hpp"
#include "rename_store.hpp"
#include "work_queue.hpp"
#include "../testlab/test_all_features.hpp"
#include "../../helpers/diag_log.hpp"
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
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <Windows.h>

extern DisasmState g_disasm;

namespace cfg_view {
	void build_cfg(uint64_t entry_address);
}

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
			size_t total_bytes = static_cast<size_t>(count) * entry_size;
			table.reserve(total_bytes);
			const size_t chunk_bytes = 0x10000;
			size_t fetched = 0;
			bool any_chunk_ok = false;
			while (fetched < total_bytes) {
				size_t to_read = total_bytes - fetched;
				if (to_read > chunk_bytes) to_read = chunk_bytes;
				std::vector<uint8_t> piece;
				if (driver_bridge::read_memory(module_base + exception_dir_rva + fetched,
					to_read, piece) && !piece.empty())
				{
					any_chunk_ok = true;
					table.insert(table.end(), piece.begin(), piece.end());
					fetched += piece.size();
					if (piece.size() < to_read) break;
				} else {
					break;
				}
			}
			if (!any_chunk_ok) return false;
			if (table.size() < total_bytes) {
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

		inline bool disk_read_whole_file(const std::string& path, std::vector<uint8_t>& out)
		{
			out.clear();
			HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL, nullptr);
			if (h == INVALID_HANDLE_VALUE) return false;
			LARGE_INTEGER sz{};
			if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1ll << 31)) {
				CloseHandle(h);
				return false;
			}
			out.resize(static_cast<size_t>(sz.QuadPart));
			size_t total = 0;
			while (total < out.size()) {
				DWORD chunk = static_cast<DWORD>(std::min<size_t>(out.size() - total, 1u << 20));
				DWORD got = 0;
				if (!ReadFile(h, out.data() + total, chunk, &got, nullptr) || got == 0) {
					CloseHandle(h);
					out.clear();
					return false;
				}
				total += got;
			}
			CloseHandle(h);
			return true;
		}

		struct disk_section_t {
			std::string name;
			uint32_t    virtual_address = 0;
			uint32_t    virtual_size = 0;
			uint32_t    raw_size = 0;
			uint32_t    raw_offset = 0;
			uint32_t    characteristics = 0;
		};

		struct disk_pe_view_t {
			std::vector<uint8_t>              raw;
			uint64_t                          image_base = 0;
			uint32_t                          size_of_image = 0;
			uint32_t                          entry_rva = 0;
			std::vector<disk_section_t>       sections;
			uint32_t                          exception_dir_rva = 0;
			uint32_t                          exception_dir_size = 0;
			uint32_t                          export_dir_rva = 0;
			uint32_t                          export_dir_size = 0;
			uint32_t                          import_dir_rva = 0;
			uint32_t                          import_dir_size = 0;
			uint32_t                          iat_dir_rva = 0;
			uint32_t                          iat_dir_size = 0;
			bool                              is_pe32_plus = false;
		};

		inline bool disk_parse_pe(disk_pe_view_t& v)
		{
			if (v.raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(v.raw.data());
			if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
			uint32_t pe_off = static_cast<uint32_t>(dos->e_lfanew);
			if (pe_off + sizeof(IMAGE_NT_HEADERS32) > v.raw.size()) return false;
			const auto* nt_common = reinterpret_cast<const IMAGE_NT_HEADERS32*>(v.raw.data() + pe_off);
			if (nt_common->Signature != IMAGE_NT_SIGNATURE) return false;
			const IMAGE_FILE_HEADER& fh = nt_common->FileHeader;
			const uint16_t opt_magic = nt_common->OptionalHeader.Magic;
			v.is_pe32_plus = (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
			const bool is_pe32 = (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
			if (!v.is_pe32_plus && !is_pe32) return false;
			IMAGE_DATA_DIRECTORY exc_dir{};
			IMAGE_DATA_DIRECTORY exp_dir{};
			IMAGE_DATA_DIRECTORY imp_dir{};
			IMAGE_DATA_DIRECTORY iat_dir{};
			if (v.is_pe32_plus) {
				if (pe_off + sizeof(IMAGE_NT_HEADERS64) > v.raw.size()) return false;
				const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(v.raw.data() + pe_off);
				v.image_base = nt64->OptionalHeader.ImageBase;
				v.size_of_image = nt64->OptionalHeader.SizeOfImage;
				v.entry_rva = nt64->OptionalHeader.AddressOfEntryPoint;
				if (nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
					exc_dir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
				if (nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
					exp_dir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				if (nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
					imp_dir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
				if (nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT)
					iat_dir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
			} else {
				v.image_base = nt_common->OptionalHeader.ImageBase;
				v.size_of_image = nt_common->OptionalHeader.SizeOfImage;
				v.entry_rva = nt_common->OptionalHeader.AddressOfEntryPoint;
				if (nt_common->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
					exc_dir = nt_common->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
				if (nt_common->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
					exp_dir = nt_common->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				if (nt_common->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
					imp_dir = nt_common->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
				if (nt_common->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT)
					iat_dir = nt_common->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
			}
			v.exception_dir_rva = exc_dir.VirtualAddress;
			v.exception_dir_size = exc_dir.Size;
			v.export_dir_rva = exp_dir.VirtualAddress;
			v.export_dir_size = exp_dir.Size;
			v.import_dir_rva = imp_dir.VirtualAddress;
			v.import_dir_size = imp_dir.Size;
			v.iat_dir_rva = iat_dir.VirtualAddress;
			v.iat_dir_size = iat_dir.Size;
			uint64_t sec_offset = static_cast<uint64_t>(pe_off)
				+ offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + fh.SizeOfOptionalHeader;
			uint32_t nsec = fh.NumberOfSections > 96 ? 96 : fh.NumberOfSections;
			if (sec_offset + static_cast<uint64_t>(nsec) * sizeof(IMAGE_SECTION_HEADER) > v.raw.size()) return false;
			const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(v.raw.data() + sec_offset);
			for (uint32_t i = 0; i < nsec; ++i) {
				disk_section_t info;
				char nm[9] = {};
				std::memcpy(nm, sec[i].Name, 8);
				nm[8] = 0;
				info.name = nm;
				info.virtual_address = sec[i].VirtualAddress;
				info.virtual_size = sec[i].Misc.VirtualSize;
				info.raw_size = sec[i].SizeOfRawData;
				info.raw_offset = sec[i].PointerToRawData;
				info.characteristics = sec[i].Characteristics;
				v.sections.push_back(std::move(info));
			}
			return true;
		}

		inline bool disk_read_at_rva(const disk_pe_view_t& v, uint32_t rva, void* buf, size_t size)
		{
			for (const auto& s : v.sections) {
				uint32_t end = s.virtual_address + std::max<uint32_t>(s.virtual_size, s.raw_size);
				if (rva >= s.virtual_address && rva < end) {
					uint32_t delta = rva - s.virtual_address;
					if (delta >= s.raw_size) return false;
					if (s.raw_size - delta < size) return false;
					if (s.raw_offset == 0) return false;
					if (static_cast<uint64_t>(s.raw_offset) + delta + size > v.raw.size()) return false;
					std::memcpy(buf, v.raw.data() + s.raw_offset + delta, size);
					return true;
				}
			}
			return false;
		}

		inline std::string disk_read_string_at_rva(const disk_pe_view_t& v, uint32_t rva, size_t max_len)
		{
			std::string out;
			out.reserve(max_len);
			for (size_t i = 0; i < max_len; ++i) {
				uint8_t b = 0;
				if (!disk_read_at_rva(v, rva + static_cast<uint32_t>(i), &b, 1)) break;
				if (b == 0) break;
				out.push_back(static_cast<char>(b));
			}
			return out;
		}

		inline void disk_parse_exports(const disk_pe_view_t& v,
			std::unordered_map<uint64_t, std::string>& out_lookup)
		{
			out_lookup.clear();
			if (v.export_dir_rva == 0 || v.export_dir_size < 40) return;
			uint8_t dir_buf[40] = {};
			if (!disk_read_at_rva(v, v.export_dir_rva, dir_buf, 40)) return;
			uint32_t num_functions = 0;
			uint32_t num_names = 0;
			uint32_t addr_table_rva = 0;
			uint32_t name_table_rva = 0;
			uint32_t ordinal_table_rva = 0;
			std::memcpy(&num_functions, dir_buf + 20, 4);
			std::memcpy(&num_names, dir_buf + 24, 4);
			std::memcpy(&addr_table_rva, dir_buf + 28, 4);
			std::memcpy(&name_table_rva, dir_buf + 32, 4);
			std::memcpy(&ordinal_table_rva, dir_buf + 36, 4);
			if (num_functions == 0 || num_functions > 0x10000) return;
			if (num_names > num_functions) num_names = num_functions;
			std::vector<uint32_t> addr_table(num_functions, 0);
			for (uint32_t i = 0; i < num_functions; ++i) {
				disk_read_at_rva(v, addr_table_rva + i * 4, &addr_table[i], 4);
			}
			std::vector<uint32_t> name_ptrs(num_names, 0);
			std::vector<uint16_t> ordinals(num_names, 0);
			for (uint32_t i = 0; i < num_names; ++i) {
				disk_read_at_rva(v, name_table_rva + i * 4, &name_ptrs[i], 4);
				disk_read_at_rva(v, ordinal_table_rva + i * 2, &ordinals[i], 2);
			}
			uint32_t exp_start = v.export_dir_rva;
			uint32_t exp_end = v.export_dir_rva + v.export_dir_size;
			for (uint32_t i = 0; i < num_names; ++i) {
				uint16_t ord = ordinals[i];
				if (ord >= num_functions) continue;
				uint32_t rva = addr_table[ord];
				if (rva == 0) continue;
				if (rva >= exp_start && rva < exp_end) continue;
				std::string fn = disk_read_string_at_rva(v, name_ptrs[i], 512);
				if (fn.empty()) continue;
				uint64_t va = v.image_base + rva;
				if (out_lookup.find(va) == out_lookup.end()) {
					out_lookup.emplace(va, std::move(fn));
				}
			}
		}

		inline void disk_parse_imports(const disk_pe_view_t& v,
			std::vector<pe_parser::import_entry_t>& out)
		{
			out.clear();
			if (v.import_dir_rva == 0 || v.import_dir_size == 0) return;
			const uint32_t desc_stride = 20;
			uint32_t max_descriptors = v.import_dir_size / desc_stride;
			if (max_descriptors == 0) max_descriptors = 4096;
			if (max_descriptors > 4096) max_descriptors = 4096;
			for (uint32_t i = 0; i < max_descriptors; ++i) {
				uint8_t desc[20] = {};
				if (!disk_read_at_rva(v, v.import_dir_rva + i * desc_stride, desc, 20)) break;
				uint32_t ilt_rva = 0;
				uint32_t name_rva = 0;
				uint32_t iat_rva = 0;
				std::memcpy(&ilt_rva, desc + 0, 4);
				std::memcpy(&name_rva, desc + 12, 4);
				std::memcpy(&iat_rva, desc + 16, 4);
				if (ilt_rva == 0 && iat_rva == 0) break;
				std::string mod_name = disk_read_string_at_rva(v, name_rva, 256);
				uint32_t lookup_rva = (ilt_rva != 0) ? ilt_rva : iat_rva;
				if (lookup_rva == 0) continue;
				const uint32_t entry_stride = v.is_pe32_plus ? 8u : 4u;
				for (uint32_t t = 0; t < 0x10000; ++t) {
					uint64_t thunk_val = 0;
					if (v.is_pe32_plus) {
						if (!disk_read_at_rva(v, lookup_rva + t * entry_stride, &thunk_val, 8)) break;
					} else {
						uint32_t tmp32 = 0;
						if (!disk_read_at_rva(v, lookup_rva + t * entry_stride, &tmp32, 4)) break;
						thunk_val = tmp32;
					}
					if (thunk_val == 0) break;
					pe_parser::import_entry_t entry;
					entry.module_name = mod_name;
					entry.iat_address = v.image_base + iat_rva + t * entry_stride;
					if (v.is_pe32_plus) {
						uint64_t iat_val = 0;
						disk_read_at_rva(v, iat_rva + t * entry_stride, &iat_val, 8);
						entry.bound_address = iat_val;
					} else {
						uint32_t iat_val32 = 0;
						disk_read_at_rva(v, iat_rva + t * entry_stride, &iat_val32, 4);
						entry.bound_address = iat_val32;
					}
					bool is_ordinal = v.is_pe32_plus
						? (thunk_val & 0x8000000000000000ULL) != 0
						: (thunk_val & 0x80000000ULL) != 0;
					if (is_ordinal) {
						entry.ordinal = static_cast<uint16_t>(thunk_val & 0xFFFF);
						char ord_buf[32];
						std::snprintf(ord_buf, sizeof(ord_buf), "Ordinal#%u",
							static_cast<unsigned>(entry.ordinal));
						entry.function_name = ord_buf;
					} else {
						uint32_t hint_name_rva = static_cast<uint32_t>(thunk_val & 0x7FFFFFFFu);
						uint16_t hint = 0;
						disk_read_at_rva(v, hint_name_rva, &hint, 2);
						entry.hint = hint;
						entry.function_name = disk_read_string_at_rva(v, hint_name_rva + 2, 512);
					}
					out.push_back(std::move(entry));
				}
			}
		}

		inline void disk_parse_pdata(const disk_pe_view_t& v,
			std::unordered_map<uint64_t, uint32_t>& out_size_lookup,
			std::vector<uint64_t>& out_starts)
		{
			out_size_lookup.clear();
			out_starts.clear();
			if (!v.is_pe32_plus) return;
			if (v.exception_dir_rva == 0 || v.exception_dir_size < 12) return;
			const uint32_t entry_size = 12;
			uint32_t count = v.exception_dir_size / entry_size;
			if (count == 0 || count > 0x100000) return;
			out_starts.reserve(count);
			out_size_lookup.reserve(count);
			for (uint32_t i = 0; i < count; ++i) {
				uint32_t begin_rva = 0;
				uint32_t end_rva = 0;
				if (!disk_read_at_rva(v, v.exception_dir_rva + i * entry_size + 0, &begin_rva, 4)) break;
				if (!disk_read_at_rva(v, v.exception_dir_rva + i * entry_size + 4, &end_rva, 4)) break;
				if (begin_rva == 0 || end_rva <= begin_rva) continue;
				if (begin_rva >= v.size_of_image) continue;
				uint64_t start_va = v.image_base + begin_rva;
				uint32_t sz = end_rva - begin_rva;
				if (sz > 0x4000000u) sz = 0x4000000u;
				out_starts.push_back(start_va);
				auto it = out_size_lookup.find(start_va);
				if (it == out_size_lookup.end()) out_size_lookup.emplace(start_va, sz);
				else if (sz > it->second) it->second = sz;
			}
		}

		inline std::string disk_section_name_for_va(const disk_pe_view_t& v, uint64_t va)
		{
			if (va < v.image_base) return std::string();
			uint64_t rva64 = va - v.image_base;
			if (rva64 > 0xFFFFFFFFull) return std::string();
			uint32_t rva = static_cast<uint32_t>(rva64);
			for (const auto& s : v.sections) {
				if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
					return s.name;
			}
			return std::string();
		}

		inline bool regular_pdb_file_candidate(const std::filesystem::path& candidate, std::string& out)
		{
			out.clear();
			if (candidate.empty()) return false;
			std::error_code abs_ec;
			std::filesystem::path check = std::filesystem::absolute(candidate, abs_ec);
			if (abs_ec) check = candidate;
			std::error_code type_ec;
			if (!std::filesystem::is_regular_file(check, type_ec) || type_ec) return false;
			std::error_code size_ec;
			const auto size = std::filesystem::file_size(check, size_ec);
			if (size_ec || size == 0) return false;
			out = check.string();
			return true;
		}

		inline std::string disk_pdb_name_for_module(const std::string& display_name)
		{
			std::filesystem::path p(display_name);
			std::string stem = p.stem().string();
			if (stem.empty()) stem = display_name;
			return stem + ".pdb";
		}

		inline bool resolve_full_test_disk_pdb(const std::string& binary_path,
			const std::string& display_name, std::string& out)
		{
			const std::string pdb_name = disk_pdb_name_for_module(display_name);
			std::vector<std::filesystem::path> candidates;
			std::filesystem::path bp(binary_path);
			std::error_code abs_ec;
			std::filesystem::path abs_bp = std::filesystem::absolute(bp, abs_ec);
			if (!abs_ec) bp = abs_bp;
			std::filesystem::path parent = bp.parent_path();
			if (!parent.empty()) candidates.push_back(parent / pdb_name);
			for (const auto& sp : symbol_store::g_state.search_paths) {
				if (!sp.empty()) candidates.emplace_back(std::filesystem::path(sp) / pdb_name);
			}
			for (const auto& candidate : candidates) {
				if (regular_pdb_file_candidate(candidate, out)) return true;
			}
			out.clear();
			return false;
		}

		inline void trigger_disk_pdb_auto_load(const std::string& binary_path,
			const std::string& display_name, uint64_t image_base, uint32_t size_of_image)
		{
			if (binary_path.empty() || display_name.empty()) return;
			std::filesystem::path bp(binary_path);
			std::error_code ec;
			std::filesystem::path parent = bp.parent_path();
			if (!parent.empty()) {
				std::string parent_str = parent.string();
				bool already = false;
				for (const auto& sp : symbol_store::g_state.search_paths) {
					if (_stricmp(sp.c_str(), parent_str.c_str()) == 0) { already = true; break; }
				}
				if (!already) symbol_store::add_search_path(parent_str);
			}
			bool already_loaded_or_loading = false;
			bool already_failed = false;
			bool already_declined = false;
			{
				std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
				auto it = symbol_store::g_state.modules.find(display_name);
				if (it != symbol_store::g_state.modules.end()) {
					already_failed = it->second.failed;
					already_declined = it->second.load_declined;
					if (it->second.pdb.loaded || it->second.loading || already_failed || already_declined) {
						already_loaded_or_loading = true;
					}
				}
			}
			if (already_loaded_or_loading) {
				if (test_all_features::is_unattended_full_test_active()) {
					const std::string pdb_name = disk_pdb_name_for_module(display_name);
					diag::log_tagged_fmt("functions_panel",
						"fulltest_disk_pdb_policy module=%s base=0x%llX size=0x%X pdb=%s local_candidate=<none> cache_path=<none> decision=do_not_load_pdb reason=module_loaded_loading_failed_or_declined prompt_created=0 prompt_suppressed=1 failed=%d declined=%d is_running=%d unattended_active=%d",
						display_name.c_str(),
						static_cast<unsigned long long>(image_base),
						static_cast<unsigned>(size_of_image),
						pdb_name.c_str(),
						already_failed ? 1 : 0,
						already_declined ? 1 : 0,
						test_all_features::is_running() ? 1 : 0,
						test_all_features::is_unattended_full_test_active() ? 1 : 0);
				}
				return;
			}
			if (test_all_features::is_unattended_full_test_active()) {
				std::string local_candidate;
				const bool have_local = resolve_full_test_disk_pdb(binary_path, display_name, local_candidate);
				const std::string pdb_name = disk_pdb_name_for_module(display_name);
				if (have_local) {
					diag::log_tagged_fmt("functions_panel",
						"fulltest_disk_pdb_policy module=%s base=0x%llX size=0x%X pdb=%s local_candidate=%s cache_path=<none> decision=load_local reason=direct_local_pdb_present prompt_created=0 prompt_suppressed=1 failed=0 declined=0 is_running=%d unattended_active=%d",
						display_name.c_str(),
						static_cast<unsigned long long>(image_base),
						static_cast<unsigned>(size_of_image),
						pdb_name.c_str(),
						local_candidate.c_str(),
						test_all_features::is_running() ? 1 : 0,
						test_all_features::is_unattended_full_test_active() ? 1 : 0);
					symbol_store::load_pdb_from_explicit_path(display_name, image_base,
						static_cast<uint64_t>(size_of_image), local_candidate);
					return;
				}
				const char* reason = "no_deterministic_local_pdb_decline_remote_symbol_download";
				diag::log_tagged_fmt("functions_panel",
					"fulltest_disk_pdb_policy module=%s base=0x%llX size=0x%X pdb=%s local_candidate=%s cache_path=<none> decision=do_not_load_pdb reason=%s prompt_created=0 prompt_suppressed=1 failed=0 declined=1 is_running=%d unattended_active=%d",
					display_name.c_str(),
					static_cast<unsigned long long>(image_base),
					static_cast<unsigned>(size_of_image),
					pdb_name.c_str(),
					"<none>",
					reason,
					test_all_features::is_running() ? 1 : 0,
					test_all_features::is_unattended_full_test_active() ? 1 : 0);
				symbol_store::suppress_full_test_pdb_load("functions_panel.trigger_disk_pdb_auto_load",
					display_name, image_base, static_cast<uint64_t>(size_of_image),
					pdb_name, {}, 0, local_candidate, {}, {},
					reason);
				return;
			}
			symbol_store::load_pdb_for_module(display_name, image_base,
				static_cast<uint64_t>(size_of_image));
		}

		inline void build_locked_disk(view_state_t& s, const std::string& path,
			const std::string& display_name)
		{
			disk_pe_view_t v;
			if (!disk_read_whole_file(path, v.raw) || !disk_parse_pe(v)) {
				std::lock_guard<std::mutex> lk(s.mtx);
				s.entries.clear();
				s.cached_module_base = 0;
				s.cached_module_size = 0;
				s.cached_module_name = display_name;
				s.filter_dirty = true;
				s.sort_dirty = true;
				return;
			}

			trigger_disk_pdb_auto_load(path, display_name, v.image_base, v.size_of_image);

			std::unordered_map<uint64_t, uint32_t> size_lookup;
			std::vector<uint64_t> rf_starts;
			disk_parse_pdata(v, size_lookup, rf_starts);

			std::unordered_map<uint64_t, std::string> export_lookup;
			disk_parse_exports(v, export_lookup);

			std::vector<uint64_t> candidate_addrs;
			candidate_addrs.reserve(rf_starts.size() + export_lookup.size() + 4);
			for (uint64_t va : rf_starts) candidate_addrs.push_back(va);
			for (const auto& kv : export_lookup) candidate_addrs.push_back(kv.first);
			if (v.entry_rva != 0) candidate_addrs.push_back(v.image_base + v.entry_rva);

			std::sort(candidate_addrs.begin(), candidate_addrs.end());
			candidate_addrs.erase(std::unique(candidate_addrs.begin(), candidate_addrs.end()),
				candidate_addrs.end());

			std::vector<function_entry_t> built;
			built.reserve(candidate_addrs.size());
			for (uint64_t va : candidate_addrs) {
				if (s.cancel.load(std::memory_order_acquire)) return;
				function_entry_t fn;
				fn.address = va;
				auto sit = size_lookup.find(va);
				fn.size = (sit != size_lookup.end()) ? sit->second : 0;
				auto eit = export_lookup.find(va);
				if (eit != export_lookup.end() && !eit->second.empty()) {
					fn.name = eit->second;
					fn.synthetic_name = false;
				} else {
					std::string rn = rename_store::get(va);
					if (!rn.empty()) {
						fn.name = rn;
						fn.synthetic_name = false;
					} else {
						std::string sym = symbol_store::resolve_symbol_exact(va);
						if (!sym.empty()) {
							fn.name = sym;
							fn.synthetic_name = false;
						} else {
							fn.name = make_synthetic_name(va);
							fn.synthetic_name = true;
						}
					}
				}
				fn.section = disk_section_name_for_va(v, va);
				built.push_back(std::move(fn));
			}

			std::sort(built.begin(), built.end(),
				[](const function_entry_t& a, const function_entry_t& b) {
					return a.address < b.address;
				});

			{
				std::lock_guard<std::mutex> lk(s.mtx);
				s.entries = std::move(built);
				s.cached_module_base = v.image_base;
				s.cached_module_size = v.size_of_image;
				s.cached_module_name = display_name;
				s.filter_dirty = true;
				s.sort_dirty = true;
				s.selected_row = -1;
				s.selected_addr = 0;
			}
		}

		inline void launch_build_if_needed(view_state_t& s) {
			if (s.building.load(std::memory_order_acquire)) return;

			const bool driver_attached = driver_bridge::is_loaded()
				&& driver_bridge::attached_pid() != 0;
			if (driver_attached) {
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
					auto& s2 = state();
					build_locked(s2, base, size, name);
					s2.ready.store(true, std::memory_order_release);
					s2.building.store(false, std::memory_order_release);
				});
				return;
			}

			if (!g_disasm.file.loaded) return;
			if (g_disasm.file.path.empty()) return;
			if (g_disasm.file.path.compare(0, 7, "live://") == 0) return;
			if (g_disasm.file.image_base == 0) return;

			const std::string& disk_path = g_disasm.file.path;
			const std::string& disk_name = g_disasm.file.filename.empty()
				? disk_path : g_disasm.file.filename;
			uint64_t disk_token = std::hash<std::string>{}(disk_path);

			bool need_build = false;
			{
				std::lock_guard<std::mutex> lk(s.mtx);
				if (!s.ready.load(std::memory_order_acquire) ||
					s.cached_module_base != g_disasm.file.image_base ||
					s.cached_pid_token != disk_token)
				{
					need_build = true;
					s.cached_pid_token = disk_token;
				}
			}
			if (!need_build) return;

			bool expected2 = false;
			if (!s.building.compare_exchange_strong(expected2, true,
				std::memory_order_acq_rel))
			{
				return;
			}
			s.cancel.store(false, std::memory_order_release);
			s.ready.store(false, std::memory_order_release);

			std::string path_capture = disk_path;
			std::string name_capture = disk_name;
			work_queue::post([path_capture, name_capture]() {
				auto& s2 = state();
				build_locked_disk(s2, path_capture, name_capture);
				s2.ready.store(true, std::memory_order_release);
				s2.building.store(false, std::memory_order_release);
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

		if (w < 120.f) {
			ImGui::SetNextWindowPos(ImVec2(x, y));
			ImGui::SetNextWindowSize(ImVec2(w, h));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
			ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(th.bg_base));
			const ImGuiWindowFlags narrow_flags =
				ImGuiWindowFlags_NoTitleBar |
				ImGuiWindowFlags_NoResize |
				ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse |
				ImGuiWindowFlags_NoScrollbar |
				ImGuiWindowFlags_NoScrollWithMouse |
				ImGuiWindowFlags_NoBringToFrontOnFocus;
			ImGui::Begin("##functions_panel_root", nullptr, narrow_flags);
			ImDrawList* ndl = ImGui::GetWindowDrawList();
			ImVec2 nwp = ImGui::GetWindowPos();
			ImFont* ncap = aida::ui::fonts::caption();
			if (!ncap) ncap = ImGui::GetFont();
			const char* nmsg = "Functions panel too narrow";
			float nfs = aida::ui::components::detail::ui_fs() * 0.88f;
			ImVec2 nts = ncap->CalcTextSizeA(nfs, FLT_MAX, w - 8.f, nmsg);
			ImVec2 npos = ImVec2(nwp.x + (w - nts.x) * 0.5f, nwp.y + (h - nts.y) * 0.5f);
			ndl->AddText(ncap, nfs, npos, th.text_dim, nmsg);
			ImGui::End();
			ImGui::PopStyleColor();
			ImGui::PopStyleVar(2);
			return;
		}

		const bool compact = (w < 340.f);

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

		const float fs_fp_base = aida::ui::components::detail::ui_fs();
		const float title_fs = fs_fp_base * 1.10f;
		const float title_x = wp.x + pad + 2.f;
		const float title_y = wp.y + 8.f;
		dl->AddText(title_font, title_fs,
			ImVec2(title_x, title_y),
			th.text_primary, "Functions");
		{
			ImVec2 title_size = title_font->CalcTextSizeA(title_fs, FLT_MAX, 0.f, "Functions");
			float underline_y = title_y + title_size.y + 1.f;
			dl->AddLine(ImVec2(title_x, underline_y),
				ImVec2(title_x + 22.f, underline_y),
				th.accent_u32, 2.f);
		}

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

		{
			float shadow_x0 = wp.x + pad;
			float shadow_y0 = wp.y + input_y + input_h;
			float shadow_x1 = shadow_x0 + input_w;
			float shadow_y1 = shadow_y0 + 3.f;
			ImU32 shadow_top = IM_COL32(0, 0, 0, 30);
			ImU32 shadow_bot = IM_COL32(0, 0, 0, 0);
			dl->AddRectFilledMultiColor(
				ImVec2(shadow_x0, shadow_y0),
				ImVec2(shadow_x1, shadow_y1),
				shadow_top, shadow_top, shadow_bot, shadow_bot);
		}

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
			float bfs = fs_fp_base * 0.85f;
			float bw = badge_font->CalcTextSizeA(bfs, FLT_MAX, 0.f, count_buf).x + 16.f;
			float bh = 22.f;
			ImVec2 ba = ImVec2(wp.x + w - pad - bw, wp.y + input_y + (input_h - bh) * 0.5f);
			ImVec2 bb = ImVec2(ba.x + bw, ba.y + bh);
			ImU32 badge_col = building
				? aida::ui::with_alpha(th.warning, 0.55f)
				: aida::ui::with_alpha(th.accent_u32, 0.85f);
			dl->AddRectFilled(ba, bb, badge_col, 6.f);
			ImU32 badge_border = aida::ui::lighten(th.accent_u32, 15);
			dl->AddRect(ba, bb, badge_border, 6.f, 0, 1.f);
			ImU32 text_on_badge = IM_COL32(255, 255, 255, 240);
			dl->AddText(badge_font, bfs,
				ImVec2(ba.x + 8.f, ba.y + (bh - bfs) * 0.5f),
				text_on_badge, count_buf);
		}

		if (!module_name_local.empty()) {
			std::string mod_display = module_name_local;
			if (mod_display.size() > 48) {
				mod_display.resize(48);
				mod_display.append("\xe2\x80\xa6");
			}
			char sub_buf[256];
			std::snprintf(sub_buf, sizeof(sub_buf), "Module: %s", mod_display.c_str());
			float sub_avail = w - (pad + 2.f) * 2.f;
			const float fs_sub = fs_fp_base * 0.85f;
			ImVec2 sub_size = caption_font->CalcTextSizeA(fs_sub, FLT_MAX, 0.f, sub_buf);
			if (sub_size.x > sub_avail && sub_avail > 24.f) {
				std::string cut(sub_buf);
				while (cut.size() > 4) {
					cut.pop_back();
					std::string probe = cut + "\xe2\x80\xa6";
					ImVec2 ps = caption_font->CalcTextSizeA(fs_sub, FLT_MAX, 0.f, probe.c_str());
					if (ps.x <= sub_avail) {
						std::snprintf(sub_buf, sizeof(sub_buf), "%s", probe.c_str());
						break;
					}
				}
			}
			dl->AddText(caption_font, fs_sub,
				ImVec2(wp.x + pad + 2.f, wp.y + header_h - 18.f),
				th.text_dim, sub_buf);
		}

		if (building) {
			float bar_y = wp.y + header_h - 2.f;
			detail::draw_loading_strip(dl,
				ImVec2(wp.x, bar_y),
				ImVec2(wp.x + w, bar_y + 2.f),
				aida::ui::lighten(th.accent_u32, 8));
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
			cfg.body = "Open a binary or attach to a running process to populate the symbol list.";
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

		if (compact) {
			std::vector<int> row_view;
			{
				std::lock_guard<std::mutex> lk(s.mtx);
				row_view = s.sorted_indices;
			}

			ImGui::SetCursorScreenPos(content_pos);
			ImGui::BeginChild("##fn_compact", content_size, false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

			ImDrawList* cdl = ImGui::GetWindowDrawList();
			const float row_h = (std::max)(40.f, fs_fp_base * 2.55f);

			ImGuiListClipper clipper;
			clipper.Begin(static_cast<int>(row_view.size()), row_h);
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

					ImGui::PushID(row_idx);

					ImVec2 row_min = ImGui::GetCursorScreenPos();
					ImVec2 row_max = ImVec2(row_min.x + content_size.x, row_min.y + row_h);

					char btn_label[40];
					std::snprintf(btn_label, sizeof(btn_label), "##fn_cb_%d", row_idx);
					ImGui::InvisibleButton(btn_label, ImVec2(content_size.x, row_h));

					bool is_selected = (s.selected_addr != 0 && s.selected_addr == e.address);
					bool hovered = ImGui::IsItemHovered();
					bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
					bool dbl_clicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
						&& ImGui::IsItemHovered();
					bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);

					if ((row_idx & 1) == 1) {
						cdl->AddRectFilled(row_min, row_max,
							aida::ui::with_alpha(th.panel_bg, 0.35f));
					}
					if (is_selected) {
						cdl->AddRectFilled(row_min, row_max,
							aida::ui::with_alpha(th.selection, 1.f));
						cdl->AddRectFilled(
							ImVec2(row_min.x, row_min.y),
							ImVec2(row_min.x + 3.f, row_max.y),
							th.accent_u32);
					}
					else if (hovered) {
						cdl->AddRectFilled(row_min, row_max,
							aida::ui::with_alpha(th.hover_wash, 1.f));
					}

					float icon_cx = row_min.x + 11.f;
					float icon_cy = row_min.y + row_h * 0.5f;
					if (e.synthetic_name) {
						ImVec2 q0 = ImVec2(icon_cx, icon_cy - 5.f);
						ImVec2 q1 = ImVec2(icon_cx + 5.f, icon_cy);
						ImVec2 q2 = ImVec2(icon_cx, icon_cy + 5.f);
						ImVec2 q3 = ImVec2(icon_cx - 5.f, icon_cy);
						cdl->AddQuad(q0, q1, q2, q3, th.text_dim, 1.f);
					}
					else if (e.section == ".text") {
						cdl->AddCircleFilled(ImVec2(icon_cx, icon_cy), 5.f,
							th.accent_dim, 16);
					}
					else {
						ImVec2 ra = ImVec2(icon_cx - 5.f, icon_cy - 4.f);
						ImVec2 rb = ImVec2(icon_cx + 5.f, icon_cy + 4.f);
						cdl->AddRect(ra, rb, th.text_secondary, 0.f, 0, 1.f);
					}

					const float text_x = row_min.x + 22.f;
					const float name_fs = fs_fp_base * 0.92f;
					const float line1_y = row_min.y + 4.f;
					const float line2_y = row_min.y + name_fs + 8.f;
					const float text_w_avail = content_size.x - 22.f - 6.f;

					ImU32 name_col = e.synthetic_name ? th.text_dim : th.text_primary;
					std::string name_disp = e.name;
					float name_w = code_font->CalcTextSizeA(name_fs, FLT_MAX, 0.f, name_disp.c_str()).x;
					if (name_w > text_w_avail && name_disp.size() > 3) {
						std::string trimmed = name_disp;
						while (trimmed.size() > 1) {
							trimmed.pop_back();
							std::string probe = trimmed + "..";
							float pw = code_font->CalcTextSizeA(name_fs, FLT_MAX, 0.f, probe.c_str()).x;
							if (pw <= text_w_avail) {
								name_disp = probe;
								break;
							}
						}
					}
					cdl->AddText(code_font, name_fs,
						ImVec2(text_x, line1_y), name_col, name_disp.c_str());

					char addr_buf[32];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(e.address));
					const float meta_fs = fs_fp_base * 0.82f;
					ImVec2 addr_size = code_font->CalcTextSizeA(meta_fs, FLT_MAX, 0.f, addr_buf);
					float cursor_x = text_x;
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_address, addr_buf);
					cursor_x += addr_size.x + 5.f;

					ImVec2 dot_size = code_font->CalcTextSizeA(meta_fs, FLT_MAX, 0.f, "\xc2\xb7");
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_dim, "\xc2\xb7");
					cursor_x += dot_size.x + 5.f;

					const char* sec_txt = e.section.empty() ? "\xe2\x80\x94" : e.section.c_str();
					ImVec2 sec_size = code_font->CalcTextSizeA(meta_fs, FLT_MAX, 0.f, sec_txt);
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_secondary, sec_txt);
					cursor_x += sec_size.x + 5.f;

					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_dim, "\xc2\xb7");
					cursor_x += dot_size.x + 5.f;

					char size_buf[24];
					if (e.size == 0) {
						std::snprintf(size_buf, sizeof(size_buf), "-");
					}
					else if (e.size < 1024) {
						std::snprintf(size_buf, sizeof(size_buf), "%uB", e.size);
					}
					else {
						std::snprintf(size_buf, sizeof(size_buf), "%.1fK",
							static_cast<double>(e.size) / 1024.0);
					}
					ImVec2 size_text_size = code_font->CalcTextSizeA(meta_fs, FLT_MAX, 0.f, size_buf);
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_secondary, size_buf);
					cursor_x += size_text_size.x + 5.f;

					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_dim, "\xc2\xb7");
					cursor_x += dot_size.x + 5.f;

					char calls_buf[32];
					std::snprintf(calls_buf, sizeof(calls_buf), "%u/%u",
						e.calls_in, e.calls_out);
					cdl->AddText(code_font, meta_fs,
						ImVec2(cursor_x, line2_y), th.text_dim, calls_buf);

					if (clicked) {
						s.selected_row = row_idx;
						s.selected_addr = e.address;
					}
					if (dbl_clicked) {
						detail::jump_to_disasm(e.address);
					}
					if (right_clicked) {
						s.ctx_row = row_idx;
						s.ctx_addr = e.address;
						s.selected_row = row_idx;
						s.selected_addr = e.address;
						ctx_menu_request = true;
					}

					ImGui::PopID();
				}
			}
			clipper.End();

			ImGui::EndChild();
		}
		else if (ImGui::BeginTable("##fn_table", 5, tflags, outer)) {
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
						!ImGui::GetIO().WantTextInput)
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

					if (is_selected) {
						ImVec2 row_min = ImGui::GetItemRectMin();
						ImVec2 row_max = ImGui::GetItemRectMax();
						ImDrawList* tdl = ImGui::GetWindowDrawList();
						tdl->AddRectFilled(
							ImVec2(row_min.x - 1.f, row_min.y),
							ImVec2(row_min.x + 2.f, row_max.y),
							th.accent_u32);
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
			cfg.body = "Open a binary or attach to a running process to populate the symbol list.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
		}
		else if (ready && shown_count == 0 && total_count > 0) {
			ImVec2 cp = ImVec2(wp.x + pad, wp.y + header_h + 8.f);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::search;
			cfg.title = "No matches";
			cfg.body = "Nothing matches the current filter. Try a shorter query.";
			cfg.max_width = std::min(content_size.x - 32.f, 360.f);
			aida::ui::empty_state::render(cp, content_size, cfg);
		}

		ImGui::PopFont();

		ImGui::End();
		ImGui::PopStyleColor();
		ImGui::PopStyleVar(2);
	}

}
