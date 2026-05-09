#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

#include <Windows.h>

#include "imgui/imgui.h"

#include <openssl/evp.h>
#include <zlib.h>

#include "../infra/work_queue.hpp"
#include "../ui/fonts.hpp"
#include "disasm_theme.hpp"
#include "zydis_disasm.hpp"

namespace file_metadata_banner {

	enum class compute_state_t : int {
		idle = 0,
		pending = 1,
		ready = 2,
		failed = 3
	};

	struct section_info_t {
		std::string  name;
		uint32_t     virtual_address = 0;
		uint32_t     virtual_size = 0;
		uint32_t     raw_size = 0;
		uint32_t     raw_offset = 0;
		uint32_t     characteristics = 0;
		uint32_t     alignment = 0;
	};

	struct metadata_cache_t {
		std::atomic<int>     state{ static_cast<int>(compute_state_t::idle) };
		std::mutex           mtx;
		std::string          source_path;
		uint64_t             source_size = 0;
		uint64_t             source_write_time = 0;
		std::string          file_name;
		std::string          sha256;
		std::string          md5;
		std::string          crc32;
		std::string          compiler;
		std::string          pdb_file_name;
		std::string          os_type;
		std::string          app_type;
		std::string          format_text;
		uint64_t             image_base = 0;
		uint32_t             timestamp = 0;
		std::string          timestamp_text;
		uint16_t             machine = 0;
		uint16_t             characteristics = 0;
		uint16_t             subsystem = 0;
		uint64_t             entry_point_rva = 0;
		std::vector<section_info_t> sections;
		std::string          last_error;
	};

	namespace detail {

		inline metadata_cache_t& cache() {
			static metadata_cache_t s_cache;
			return s_cache;
		}

		inline std::string& last_error_storage() {
			static std::string s_last_error;
			return s_last_error;
		}

		inline void set_last_error(const std::string& msg) {
			last_error_storage() = msg;
		}

		inline std::string to_hex_upper(const uint8_t* data, size_t len) {
			static const char digits[] = "0123456789ABCDEF";
			std::string out;
			out.resize(len * 2);
			for (size_t i = 0; i < len; ++i) {
				out[i * 2 + 0] = digits[(data[i] >> 4) & 0x0F];
				out[i * 2 + 1] = digits[data[i] & 0x0F];
			}
			return out;
		}

		inline bool digest_with(const EVP_MD* md, const std::vector<uint8_t>& bytes, std::string& out_hex) {
			out_hex.clear();
			if (!md) return false;
			EVP_MD_CTX* ctx = EVP_MD_CTX_new();
			if (!ctx) return false;
			unsigned char digest[EVP_MAX_MD_SIZE] = {};
			unsigned int dlen = 0;
			bool ok = false;
			if (EVP_DigestInit_ex(ctx, md, nullptr) == 1
				&& EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) == 1
				&& EVP_DigestFinal_ex(ctx, digest, &dlen) == 1) {
				out_hex = to_hex_upper(digest, dlen);
				ok = true;
			}
			EVP_MD_CTX_free(ctx);
			return ok;
		}

		inline bool read_whole_file(const std::string& path, std::vector<uint8_t>& out, uint64_t& out_size, uint64_t& out_write_time) {
			out.clear();
			out_size = 0;
			out_write_time = 0;
			HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
				nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (h == INVALID_HANDLE_VALUE) {
				set_last_error("file_metadata_banner: cannot open file");
				return false;
			}
			LARGE_INTEGER sz{};
			if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0) {
				CloseHandle(h);
				set_last_error("file_metadata_banner: invalid file size");
				return false;
			}
			FILETIME ft_write{};
			GetFileTime(h, nullptr, nullptr, &ft_write);
			ULARGE_INTEGER wt{};
			wt.LowPart = ft_write.dwLowDateTime;
			wt.HighPart = ft_write.dwHighDateTime;
			out_write_time = wt.QuadPart;
			out_size = static_cast<uint64_t>(sz.QuadPart);
			if (out_size > (1ull << 31)) {
				CloseHandle(h);
				set_last_error("file_metadata_banner: file too large");
				return false;
			}
			out.resize(static_cast<size_t>(out_size));
			size_t total_read = 0;
			while (total_read < out.size()) {
				DWORD chunk = static_cast<DWORD>(std::min<size_t>(out.size() - total_read, 1u << 20));
				DWORD got = 0;
				if (!ReadFile(h, out.data() + total_read, chunk, &got, nullptr) || got == 0) {
					CloseHandle(h);
					set_last_error("file_metadata_banner: read error");
					return false;
				}
				total_read += got;
			}
			CloseHandle(h);
			return true;
		}

		inline std::string format_timestamp_utc(uint32_t ts) {
			if (ts == 0) return "0";
			std::time_t t = static_cast<std::time_t>(ts);
			std::tm tm_buf{};
			gmtime_s(&tm_buf, &t);
			static const char* const wdays[] = { "Sun","Mon","Tue","Wed","Thu","Fri","Sat" };
			static const char* const months[] = { "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec" };
			char buf[64] = {};
			std::snprintf(buf, sizeof(buf), "%s %s %02d %02d:%02d:%02d %04d UTC",
				wdays[tm_buf.tm_wday & 7],
				months[tm_buf.tm_mon & 0x0F],
				tm_buf.tm_mday,
				tm_buf.tm_hour,
				tm_buf.tm_min,
				tm_buf.tm_sec,
				tm_buf.tm_year + 1900);
			return std::string(buf);
		}

		inline std::string machine_to_os_type(uint16_t machine) {
			switch (machine) {
				case IMAGE_FILE_MACHINE_AMD64:
				case IMAGE_FILE_MACHINE_I386:
				case IMAGE_FILE_MACHINE_ARM64:
				case IMAGE_FILE_MACHINE_ARM:
				case IMAGE_FILE_MACHINE_ARMNT:
				case IMAGE_FILE_MACHINE_IA64:
					return "MS Windows";
				default:
					return "MS Windows";
			}
		}

		inline std::string format_application_type(uint16_t machine, uint16_t characteristics, uint16_t subsystem) {
			const bool is_dll = (characteristics & IMAGE_FILE_DLL) != 0;
			const bool is_sys = (subsystem == IMAGE_SUBSYSTEM_NATIVE);
			const char* bitness = "64bit";
			switch (machine) {
				case IMAGE_FILE_MACHINE_I386:
				case IMAGE_FILE_MACHINE_ARM:
				case IMAGE_FILE_MACHINE_ARMNT:
					bitness = "32bit";
					break;
				default:
					bitness = "64bit";
					break;
			}
			if (is_sys && is_dll) {
				char buf[64] = {};
				std::snprintf(buf, sizeof(buf), "Driver %s", bitness);
				return std::string(buf);
			}
			if (is_dll) {
				char buf[64] = {};
				std::snprintf(buf, sizeof(buf), "DLL %s", bitness);
				return std::string(buf);
			}
			char buf[64] = {};
			std::snprintf(buf, sizeof(buf), "Executable %s", bitness);
			return std::string(buf);
		}

		inline std::string format_pe_format(uint16_t machine) {
			switch (machine) {
				case IMAGE_FILE_MACHINE_AMD64: return "Portable executable for AMD64 (PE)";
				case IMAGE_FILE_MACHINE_I386:  return "Portable executable for 80386 (PE)";
				case IMAGE_FILE_MACHINE_ARM64: return "Portable executable for ARM64 (PE)";
				case IMAGE_FILE_MACHINE_ARM:
				case IMAGE_FILE_MACHINE_ARMNT: return "Portable executable for ARM (PE)";
				case IMAGE_FILE_MACHINE_IA64:  return "Portable executable for IA64 (PE)";
				default: {
					char buf[64] = {};
					std::snprintf(buf, sizeof(buf), "Portable executable for machine 0x%04X (PE)", machine);
					return std::string(buf);
				}
			}
		}

		inline std::string section_name_clean(const uint8_t name_field[8]) {
			char tmp[9] = {};
			for (int i = 0; i < 8; ++i)
				tmp[i] = static_cast<char>(name_field[i]);
			tmp[8] = '\0';
			return std::string(tmp);
		}

		inline std::string section_flags_text(uint32_t flags) {
			std::string out;
			auto append = [&out](const char* s) {
				if (!out.empty()) out.push_back(' ');
				out.append(s);
			};
			if (flags & IMAGE_SCN_CNT_CODE) append("Text");
			if (flags & IMAGE_SCN_CNT_INITIALIZED_DATA) append("Data");
			if (flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) append("BSS");
			if (flags & IMAGE_SCN_MEM_DISCARDABLE) append("Discardable");
			if (flags & IMAGE_SCN_MEM_SHARED) append("Shared");
			if (flags & IMAGE_SCN_MEM_EXECUTE) append("Executable");
			if (flags & IMAGE_SCN_MEM_READ) append("Readable");
			if (flags & IMAGE_SCN_MEM_WRITE) append("Writable");
			if (out.empty()) out = "(none)";
			return out;
		}

		inline uint32_t section_alignment_value(uint32_t flags) {
			const uint32_t align_mask = IMAGE_SCN_ALIGN_MASK;
			uint32_t v = (flags & align_mask) >> 20;
			if (v == 0) return 0;
			return 1u << (v - 1);
		}

		inline bool detect_rich_signature(const std::vector<uint8_t>& raw, uint32_t pe_off) {
			if (pe_off < 0x80 || pe_off > raw.size()) return false;
			const uint8_t* base = raw.data();
			for (uint32_t off = 0x80; off + 4 <= pe_off; ++off) {
				if (base[off] == 'R' && base[off + 1] == 'i' && base[off + 2] == 'c' && base[off + 3] == 'h')
					return true;
			}
			return false;
		}

		inline std::string detect_compiler(const std::vector<uint8_t>& raw,
			uint32_t pe_off,
			const std::vector<section_info_t>& secs)
		{
			bool has_eh_frame = false;
			bool has_text = false;
			bool has_pdata = false;
			for (const auto& s : secs) {
				if (s.name == ".text" || s.name == ".text$mn" || s.name == "CODE")
					has_text = true;
				if (s.name == ".eh_fram" || s.name == ".eh_frame" || s.name == ".gnu_deb")
					has_eh_frame = true;
				if (s.name == ".pdata")
					has_pdata = true;
			}
			if (detect_rich_signature(raw, pe_off) && has_text)
				return "Visual C++";
			if (has_eh_frame && has_text)
				return "GCC/MinGW";
			if (has_pdata && has_text)
				return "Visual C++";
			return "unknown";
		}

		inline std::string extract_pdb_path(const std::vector<uint8_t>& raw,
			const IMAGE_NT_HEADERS64* nt64,
			const IMAGE_NT_HEADERS32* nt32,
			bool is_pe32_plus,
			const std::vector<section_info_t>& secs)
		{
			IMAGE_DATA_DIRECTORY dbg_dir{};
			if (is_pe32_plus) {
				if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
					return "(none)";
				dbg_dir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
			} else {
				if (nt32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
					return "(none)";
				dbg_dir = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
			}
			if (dbg_dir.VirtualAddress == 0 || dbg_dir.Size < sizeof(IMAGE_DEBUG_DIRECTORY))
				return "(none)";

			auto rva_to_offset = [&secs](uint32_t rva) -> uint32_t {
				for (const auto& s : secs) {
					if (rva >= s.virtual_address && rva < s.virtual_address + std::max<uint32_t>(s.virtual_size, s.raw_size)) {
						uint32_t delta = rva - s.virtual_address;
						if (delta >= s.raw_size) return 0;
						return s.raw_offset + delta;
					}
				}
				return 0;
			};

			uint32_t dbg_off = rva_to_offset(dbg_dir.VirtualAddress);
			if (dbg_off == 0) return "(none)";
			if (static_cast<uint64_t>(dbg_off) + dbg_dir.Size > raw.size()) return "(none)";

			const uint32_t entry_count = dbg_dir.Size / static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY));
			for (uint32_t i = 0; i < entry_count; ++i) {
				const IMAGE_DEBUG_DIRECTORY* e =
					reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(raw.data() + dbg_off + i * sizeof(IMAGE_DEBUG_DIRECTORY));
				if (e->Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
				if (e->PointerToRawData == 0 || e->SizeOfData < 24) continue;
				if (static_cast<uint64_t>(e->PointerToRawData) + e->SizeOfData > raw.size()) continue;
				const uint8_t* cv = raw.data() + e->PointerToRawData;
				if (cv[0] == 'R' && cv[1] == 'S' && cv[2] == 'D' && cv[3] == 'S') {
					const char* name = reinterpret_cast<const char*>(cv + 24);
					size_t max_len = static_cast<size_t>(e->SizeOfData) - 24;
					size_t actual = 0;
					while (actual < max_len && name[actual] != '\0') ++actual;
					if (actual == 0) return "(none)";
					return std::string(name, actual);
				}
			}
			return "(none)";
		}

		inline bool parse_pe(const std::vector<uint8_t>& raw, metadata_cache_t& target) {
			if (raw.size() < sizeof(IMAGE_DOS_HEADER)) {
				set_last_error("file_metadata_banner: file too small for DOS header");
				return false;
			}
			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
			if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
				set_last_error("file_metadata_banner: not a PE file");
				return false;
			}
			uint32_t pe_off = static_cast<uint32_t>(dos->e_lfanew);
			if (pe_off + sizeof(IMAGE_NT_HEADERS32) > raw.size()) {
				set_last_error("file_metadata_banner: corrupt PE");
				return false;
			}
			const auto* nt_common = reinterpret_cast<const IMAGE_NT_HEADERS32*>(raw.data() + pe_off);
			if (nt_common->Signature != IMAGE_NT_SIGNATURE) {
				set_last_error("file_metadata_banner: invalid NT signature");
				return false;
			}
			const IMAGE_FILE_HEADER& fh = nt_common->FileHeader;
			const uint16_t opt_magic = nt_common->OptionalHeader.Magic;
			const bool is_pe32_plus = (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
			const bool is_pe32 = (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
			if (!is_pe32_plus && !is_pe32) {
				set_last_error("file_metadata_banner: unsupported optional header magic");
				return false;
			}

			const IMAGE_NT_HEADERS64* nt64 = nullptr;
			const IMAGE_NT_HEADERS32* nt32 = nullptr;
			uint64_t image_base = 0;
			uint32_t entry_rva = 0;
			uint16_t subsystem = 0;
			uint64_t opt_offset = pe_off + offsetof(IMAGE_NT_HEADERS32, OptionalHeader);
			uint64_t sec_offset = opt_offset + fh.SizeOfOptionalHeader;
			if (is_pe32_plus) {
				if (pe_off + sizeof(IMAGE_NT_HEADERS64) > raw.size()) {
					set_last_error("file_metadata_banner: corrupt PE32+");
					return false;
				}
				nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + pe_off);
				image_base = nt64->OptionalHeader.ImageBase;
				entry_rva = nt64->OptionalHeader.AddressOfEntryPoint;
				subsystem = nt64->OptionalHeader.Subsystem;
			} else {
				nt32 = nt_common;
				image_base = nt32->OptionalHeader.ImageBase;
				entry_rva = nt32->OptionalHeader.AddressOfEntryPoint;
				subsystem = nt32->OptionalHeader.Subsystem;
			}

			if (sec_offset + static_cast<uint64_t>(fh.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER) > raw.size()) {
				set_last_error("file_metadata_banner: section table out of range");
				return false;
			}

			std::vector<section_info_t> sections;
			sections.reserve(fh.NumberOfSections);
			const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(raw.data() + sec_offset);
			for (WORD i = 0; i < fh.NumberOfSections; ++i) {
				section_info_t info;
				info.name = section_name_clean(reinterpret_cast<const uint8_t*>(sec[i].Name));
				info.virtual_address = sec[i].VirtualAddress;
				info.virtual_size = sec[i].Misc.VirtualSize;
				info.raw_size = sec[i].SizeOfRawData;
				info.raw_offset = sec[i].PointerToRawData;
				info.characteristics = sec[i].Characteristics;
				info.alignment = section_alignment_value(sec[i].Characteristics);
				sections.push_back(std::move(info));
			}

			target.image_base = image_base;
			target.timestamp = fh.TimeDateStamp;
			target.timestamp_text = format_timestamp_utc(fh.TimeDateStamp);
			target.machine = fh.Machine;
			target.characteristics = fh.Characteristics;
			target.subsystem = subsystem;
			target.entry_point_rva = entry_rva;
			target.sections = std::move(sections);
			target.os_type = machine_to_os_type(fh.Machine);
			target.app_type = format_application_type(fh.Machine, fh.Characteristics, subsystem);
			target.format_text = format_pe_format(fh.Machine);
			target.compiler = detect_compiler(raw, pe_off, target.sections);
			target.pdb_file_name = extract_pdb_path(raw, nt64, nt32, is_pe32_plus, target.sections);
			return true;
		}

		inline bool compute_crc32(const std::vector<uint8_t>& bytes, std::string& out_hex) {
			uLong c = ::crc32(0L, Z_NULL, 0);
			const uint8_t* p = bytes.data();
			size_t left = bytes.size();
			while (left > 0) {
				size_t chunk = std::min<size_t>(left, 1u << 20);
				c = ::crc32(c, p, static_cast<uInt>(chunk));
				p += chunk;
				left -= chunk;
			}
			char buf[16] = {};
			std::snprintf(buf, sizeof(buf), "%08lX", static_cast<unsigned long>(c));
			out_hex = buf;
			return true;
		}

		inline void run_compute(const std::string& path) {
			auto& c = cache();
			std::vector<uint8_t> raw;
			uint64_t fsize = 0;
			uint64_t fwrite = 0;
			if (!read_whole_file(path, raw, fsize, fwrite)) {
				std::lock_guard<std::mutex> lk(c.mtx);
				c.last_error = last_error_storage();
				c.state.store(static_cast<int>(compute_state_t::failed), std::memory_order_release);
				return;
			}

			metadata_cache_t staged;
			staged.source_path = path;
			staged.source_size = fsize;
			staged.source_write_time = fwrite;
			size_t sl = path.find_last_of("/\\");
			staged.file_name = (sl != std::string::npos) ? path.substr(sl + 1) : path;

			std::string sha_hex;
			std::string md5_hex;
			std::string crc_hex;
			if (!digest_with(EVP_sha256(), raw, sha_hex)) sha_hex = "(error)";
			if (!digest_with(EVP_md5(), raw, md5_hex)) md5_hex = "(error)";
			if (!compute_crc32(raw, crc_hex)) crc_hex = "(error)";
			staged.sha256 = std::move(sha_hex);
			staged.md5 = std::move(md5_hex);
			staged.crc32 = std::move(crc_hex);

			if (!parse_pe(raw, staged)) {
				staged.last_error = last_error_storage();
				if (staged.compiler.empty()) staged.compiler = "unknown";
				if (staged.os_type.empty()) staged.os_type = "MS Windows";
				if (staged.app_type.empty()) staged.app_type = "Executable";
				if (staged.format_text.empty()) staged.format_text = "Portable executable (PE)";
				if (staged.pdb_file_name.empty()) staged.pdb_file_name = "(none)";
			}

			{
				std::lock_guard<std::mutex> lk(c.mtx);
				c.source_path = std::move(staged.source_path);
				c.source_size = staged.source_size;
				c.source_write_time = staged.source_write_time;
				c.file_name = std::move(staged.file_name);
				c.sha256 = std::move(staged.sha256);
				c.md5 = std::move(staged.md5);
				c.crc32 = std::move(staged.crc32);
				c.compiler = std::move(staged.compiler);
				c.pdb_file_name = std::move(staged.pdb_file_name);
				c.os_type = std::move(staged.os_type);
				c.app_type = std::move(staged.app_type);
				c.format_text = std::move(staged.format_text);
				c.image_base = staged.image_base;
				c.timestamp = staged.timestamp;
				c.timestamp_text = std::move(staged.timestamp_text);
				c.machine = staged.machine;
				c.characteristics = staged.characteristics;
				c.subsystem = staged.subsystem;
				c.entry_point_rva = staged.entry_point_rva;
				c.sections = std::move(staged.sections);
				c.last_error = std::move(staged.last_error);
				c.state.store(static_cast<int>(compute_state_t::ready), std::memory_order_release);
			}
		}

		inline void ensure_started_for(const std::string& path) {
			auto& c = cache();
			bool need_dispatch = false;
			{
				std::lock_guard<std::mutex> lk(c.mtx);
				const int st = c.state.load(std::memory_order_acquire);
				const bool fresh = (st == static_cast<int>(compute_state_t::idle))
					|| (st == static_cast<int>(compute_state_t::failed) && c.source_path != path)
					|| (st == static_cast<int>(compute_state_t::ready) && c.source_path != path);
				if (fresh) {
					c.source_path = path;
					c.file_name.clear();
					c.sha256.clear();
					c.md5.clear();
					c.crc32.clear();
					c.compiler.clear();
					c.pdb_file_name.clear();
					c.os_type.clear();
					c.app_type.clear();
					c.format_text.clear();
					c.sections.clear();
					c.last_error.clear();
					c.image_base = 0;
					c.timestamp = 0;
					c.timestamp_text.clear();
					c.machine = 0;
					c.characteristics = 0;
					c.subsystem = 0;
					c.entry_point_rva = 0;
					c.source_size = 0;
					c.source_write_time = 0;
					c.state.store(static_cast<int>(compute_state_t::pending), std::memory_order_release);
					need_dispatch = true;
				}
			}
			if (need_dispatch) {
				std::string captured = path;
				work_queue::post([captured]() {
					run_compute(captured);
				});
			}
		}

		inline void resolve_module_path(std::string& out_path, std::string& out_filename) {
			out_path.clear();
			out_filename.clear();
			HMODULE mod = GetModuleHandleW(nullptr);
			if (mod) {
				char buf[MAX_PATH] = {};
				DWORD got = GetModuleFileNameA(mod, buf, MAX_PATH);
				if (got > 0 && got < MAX_PATH) {
					out_path.assign(buf, got);
					size_t sl = out_path.find_last_of("/\\");
					out_filename = (sl != std::string::npos) ? out_path.substr(sl + 1) : out_path;
				}
			}
		}

		struct line_t {
			std::string segment_label;
			uint64_t    address = 0;
			std::string text;
			ImU32       color = 0;
			bool        no_address = false;
		};

		inline std::string make_address_prefix(const std::string& seg, uint64_t addr) {
			char buf[64] = {};
			std::snprintf(buf, sizeof(buf), "%s:%08llX", seg.c_str(), static_cast<unsigned long long>(addr));
			return std::string(buf);
		}

		inline std::string format_hex_padded(uint64_t value, int width) {
			char buf[32] = {};
			std::snprintf(buf, sizeof(buf), "%0*llX", width, static_cast<unsigned long long>(value));
			return std::string(buf);
		}

		inline std::string format_decimal_padded(uint64_t value, int width) {
			char buf[32] = {};
			std::snprintf(buf, sizeof(buf), "%*llu.", width, static_cast<unsigned long long>(value));
			return std::string(buf);
		}

		inline void push_text_line(std::vector<line_t>& dst,
			const std::string& seg, uint64_t addr,
			const std::string& text, ImU32 color, bool no_address)
		{
			line_t ln;
			ln.segment_label = seg;
			ln.address = addr;
			ln.text = text;
			ln.color = color;
			ln.no_address = no_address;
			dst.push_back(std::move(ln));
		}

		inline void build_lines(const metadata_cache_t& c,
			const std::string& fallback_path,
			std::vector<line_t>& out)
		{
			out.clear();
			out.reserve(48);

			const ImU32 c_seg = disasm_theme::segment();
			const ImU32 c_addr = disasm_theme::address();
			const ImU32 c_comment = disasm_theme::comment();
			const ImU32 c_banner = disasm_theme::banner();
			const ImU32 c_keyword = disasm_theme::keyword();
			const ImU32 c_directive = disasm_theme::directive();

			(void)c_seg;
			(void)c_addr;

			const uint64_t flat_addr = 0x003FFFFFull;
			const std::string flat = "FLAT";

			push_text_line(out, flat, flat_addr, ";", c_comment, false);
			push_text_line(out, flat, flat_addr, "; +-------------------------------------------------------------------------+", c_banner, false);
			push_text_line(out, flat, flat_addr, "; |             AiDA - Reverse-engineering toolkit by AiDA Team             |", c_banner, false);
			push_text_line(out, flat, flat_addr, "; |                          aida.app - Standalone                          |", c_banner, false);
			push_text_line(out, flat, flat_addr, "; +-------------------------------------------------------------------------+", c_banner, false);
			push_text_line(out, flat, flat_addr, ";", c_comment, false);

			const int state = c.state.load(std::memory_order_acquire);
			const bool ready = (state == static_cast<int>(compute_state_t::ready));
			const bool failed = (state == static_cast<int>(compute_state_t::failed));

			auto val_or_pending = [ready, failed](const std::string& v, const char* fail_text) -> std::string {
				if (ready) return v.empty() ? std::string("(unknown)") : v;
				if (failed) return std::string(fail_text);
				return std::string("(computing...)");
			};

			std::string sha_v = val_or_pending(c.sha256, "(unavailable)");
			std::string md5_v = val_or_pending(c.md5, "(unavailable)");
			std::string crc_v = val_or_pending(c.crc32, "(unavailable)");
			std::string comp_v = val_or_pending(c.compiler, "unknown");

			char buf[512] = {};
			std::snprintf(buf, sizeof(buf), "; Input SHA256 : %s", sha_v.c_str());
			push_text_line(out, flat, flat_addr, buf, c_comment, false);
			std::snprintf(buf, sizeof(buf), "; Input MD5    : %s", md5_v.c_str());
			push_text_line(out, flat, flat_addr, buf, c_comment, false);
			std::snprintf(buf, sizeof(buf), "; Input CRC32  : %s", crc_v.c_str());
			push_text_line(out, flat, flat_addr, buf, c_comment, false);
			std::snprintf(buf, sizeof(buf), "; Compiler     : %s", comp_v.c_str());
			push_text_line(out, flat, flat_addr, buf, c_comment, false);

			push_text_line(out, flat, flat_addr, "", c_comment, true);

			std::string pdb_v = val_or_pending(c.pdb_file_name.empty() ? std::string("(none)") : c.pdb_file_name, "(unavailable)");
			std::string os_v = val_or_pending(c.os_type, "(unknown)");
			std::string app_v = val_or_pending(c.app_type, "(unknown)");

			std::snprintf(buf, sizeof(buf), "; PDB File Name : %s", pdb_v.c_str());
			push_text_line(out, flat, flat_addr, buf, c_comment, false);
			std::snprintf(buf, sizeof(buf), "; OS type         : %s", os_v.c_str());
			push_text_line(out, flat, flat_addr, buf, c_comment, false);
			std::snprintf(buf, sizeof(buf), "; Application type: %s", app_v.c_str());
			push_text_line(out, flat, flat_addr, buf, c_comment, false);

			push_text_line(out, flat, flat_addr, "", c_comment, true);

			push_text_line(out, flat, flat_addr, "                .686p", c_directive, false);
			push_text_line(out, flat, flat_addr, "                .mmx", c_directive, false);
			push_text_line(out, flat, flat_addr, "                .model flat", c_directive, false);

			push_text_line(out, flat, flat_addr, "", c_comment, true);
			push_text_line(out, flat, flat_addr, "; ============================================================================", c_banner, false);
			push_text_line(out, flat, flat_addr, "", c_comment, true);
			push_text_line(out, flat, flat_addr, "; Segment type: Group", c_keyword, false);
			push_text_line(out, flat, flat_addr, "", c_comment, true);

			const uint64_t image_base_eff = ready ? c.image_base : 0x400000ull;
			const std::string header_seg = "HEADER";
			push_text_line(out, header_seg, image_base_eff, "; ============================================================================", c_banner, false);
			push_text_line(out, header_seg, image_base_eff, "", c_comment, true);
			push_text_line(out, header_seg, image_base_eff, "; [00001000 BYTES: COLLAPSED SEGMENT HEADER. PRESS CTRL-NUMPAD+ TO EXPAND]", c_comment, false);

			std::string section_seg_name = ".text";
			uint64_t section_va = image_base_eff + 0x1000ull;
			uint32_t section_vsize = 0;
			uint32_t section_rsize = 0;
			uint32_t section_roff = 0;
			uint32_t section_flags = 0;
			uint32_t section_align = 0;
			int      section_index = 1;

			if (ready && !c.sections.empty()) {
				const section_info_t* primary = nullptr;
				for (const auto& s : c.sections) {
					if (s.characteristics & IMAGE_SCN_MEM_EXECUTE) {
						primary = &s;
						break;
					}
				}
				if (!primary) primary = &c.sections.front();
				section_seg_name = primary->name.empty() ? std::string(".text") : primary->name;
				section_va = c.image_base + primary->virtual_address;
				section_vsize = primary->virtual_size;
				section_rsize = primary->raw_size;
				section_roff = primary->raw_offset;
				section_flags = primary->characteristics;
				section_align = primary->alignment;
				for (size_t i = 0; i < c.sections.size(); ++i) {
					if (&c.sections[i] == primary) {
						section_index = static_cast<int>(i + 1);
						break;
					}
				}
			}

			std::string file_name_disp = ready ? c.source_path : fallback_path;
			if (file_name_disp.empty()) file_name_disp = "(unknown)";

			std::snprintf(buf, sizeof(buf), "; File Name   : %s", file_name_disp.c_str());
			push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

			std::string format_disp = val_or_pending(c.format_text, "Portable executable (PE)");
			std::snprintf(buf, sizeof(buf), "; Format      : %s", format_disp.c_str());
			push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

			std::string image_base_str;
			if (ready) image_base_str = format_hex_padded(c.image_base, 0);
			else image_base_str = "(computing...)";
			std::snprintf(buf, sizeof(buf), "; Imagebase   : %s", image_base_str.c_str());
			push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

			std::string ts_str;
			if (ready) {
				char tb[128] = {};
				std::snprintf(tb, sizeof(tb), "%08X (%s)", c.timestamp, c.timestamp_text.c_str());
				ts_str = tb;
			} else {
				ts_str = "(computing...)";
			}
			std::snprintf(buf, sizeof(buf), "; Timestamp   : %s", ts_str.c_str());
			push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

			std::string sec_va_str = ready
				? format_hex_padded(static_cast<uint64_t>(section_va - c.image_base), 8)
				: std::string("(computing...)");
			std::snprintf(buf, sizeof(buf), "; Section %d. (virtual address %s)", section_index, sec_va_str.c_str());
			push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

			if (ready) {
				std::string vsize_hex = format_hex_padded(section_vsize, 8);
				std::string vsize_dec = format_decimal_padded(section_vsize, 7);
				std::snprintf(buf, sizeof(buf), "; Virtual size                  : %s ( %s)", vsize_hex.c_str(), vsize_dec.c_str());
				push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

				std::string rsize_hex = format_hex_padded(section_rsize, 8);
				std::string rsize_dec = format_decimal_padded(section_rsize, 7);
				std::snprintf(buf, sizeof(buf), "; Section size in file          : %s ( %s)", rsize_hex.c_str(), rsize_dec.c_str());
				push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

				std::string roff_hex = format_hex_padded(section_roff, 8);
				std::snprintf(buf, sizeof(buf), "; Offset to raw data for section: %s", roff_hex.c_str());
				push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

				std::snprintf(buf, sizeof(buf), "; Flags %08X: %s", section_flags, section_flags_text(section_flags).c_str());
				push_text_line(out, section_seg_name, section_va, buf, c_comment, false);

				if (section_align == 0)
					std::snprintf(buf, sizeof(buf), "; Alignment     : default");
				else
					std::snprintf(buf, sizeof(buf), "; Alignment     : %u", section_align);
				push_text_line(out, section_seg_name, section_va, buf, c_comment, false);
			} else {
				push_text_line(out, section_seg_name, section_va, "; Virtual size                  : (computing...)", c_comment, false);
				push_text_line(out, section_seg_name, section_va, "; Section size in file          : (computing...)", c_comment, false);
				push_text_line(out, section_seg_name, section_va, "; Offset to raw data for section: (computing...)", c_comment, false);
				push_text_line(out, section_seg_name, section_va, "; Flags        : (computing...)", c_comment, false);
				push_text_line(out, section_seg_name, section_va, "; Alignment     : (computing...)", c_comment, false);
			}

			push_text_line(out, section_seg_name, section_va, "; ============================================================================", c_banner, false);
		}

	}

	inline void invalidate_cache() {
		auto& c = detail::cache();
		std::lock_guard<std::mutex> lk(c.mtx);
		c.state.store(static_cast<int>(compute_state_t::idle), std::memory_order_release);
		c.source_path.clear();
		c.file_name.clear();
		c.sha256.clear();
		c.md5.clear();
		c.crc32.clear();
		c.compiler.clear();
		c.pdb_file_name.clear();
		c.os_type.clear();
		c.app_type.clear();
		c.format_text.clear();
		c.timestamp_text.clear();
		c.sections.clear();
		c.last_error.clear();
		c.image_base = 0;
		c.timestamp = 0;
		c.machine = 0;
		c.characteristics = 0;
		c.subsystem = 0;
		c.entry_point_rva = 0;
		c.source_size = 0;
		c.source_write_time = 0;
	}

	inline const std::string& last_error() {
		return detail::last_error_storage();
	}

	inline void render() {
		auto& c = detail::cache();

		std::string mod_path;
		std::string mod_name;
		detail::resolve_module_path(mod_path, mod_name);

		if (mod_path.empty()) {
			std::lock_guard<std::mutex> lk(c.mtx);
			if (!c.source_path.empty())
				mod_path = c.source_path;
		}

		if (!mod_path.empty())
			detail::ensure_started_for(mod_path);

		std::vector<detail::line_t> lines;
		{
			std::lock_guard<std::mutex> lk(c.mtx);
			detail::build_lines(c, mod_path, lines);
		}

		if (lines.empty()) return;

		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		const float font_size = code_font->FontSize > 0.f ? code_font->FontSize : ImGui::GetFontSize();
		const float line_height = std::max(font_size + 2.f, ImGui::GetTextLineHeight());

		ImDrawList* dl = ImGui::GetWindowDrawList();
		const ImVec2 origin = ImGui::GetCursorScreenPos();
		const float prefix_width = code_font->CalcTextSizeA(font_size, FLT_MAX, 0.f, "FLAT:00000000").x;
		const float prefix_pad = code_font->CalcTextSizeA(font_size, FLT_MAX, 0.f, "  ").x;
		const float text_x = origin.x + prefix_width + prefix_pad * 4.f;

		const ImU32 col_addr = disasm_theme::address();
		const ImU32 col_seg = disasm_theme::segment();

		float max_text_right = text_x;
		float y = origin.y;
		for (const auto& ln : lines) {
			ImVec2 addr_pos(origin.x, y);
			if (!ln.no_address) {
				char prefix[32] = {};
				std::snprintf(prefix, sizeof(prefix), "%s:%08llX",
					ln.segment_label.c_str(),
					static_cast<unsigned long long>(ln.address));
				size_t colon = ln.segment_label.size();
				dl->AddText(code_font, font_size, addr_pos, col_seg, prefix, prefix + colon);
				ImVec2 colon_pos(origin.x + code_font->CalcTextSizeA(font_size, FLT_MAX, 0.f, prefix, prefix + colon).x, y);
				dl->AddText(code_font, font_size, colon_pos, disasm_theme::separator(), prefix + colon, prefix + colon + 1);
				ImVec2 num_pos(origin.x + code_font->CalcTextSizeA(font_size, FLT_MAX, 0.f, prefix, prefix + colon + 1).x, y);
				dl->AddText(code_font, font_size, num_pos, col_addr, prefix + colon + 1, prefix + std::strlen(prefix));
			}

			if (!ln.text.empty()) {
				ImVec2 tpos(text_x, y);
				dl->AddText(code_font, font_size, tpos, ln.color, ln.text.c_str());
				float w = code_font->CalcTextSizeA(font_size, FLT_MAX, 0.f, ln.text.c_str()).x;
				if (text_x + w > max_text_right) max_text_right = text_x + w;
			}

			y += line_height;
		}

		const float used_height = y - origin.y;
		const float used_width = (max_text_right - origin.x) + 8.f;

		ImGui::Dummy(ImVec2(used_width, used_height));
	}

}
