#pragma once

#include <algorithm>
#include <cstdint>
#include <chrono>
#include <limits>
#include <string>
#include <vector>
#include <cstring>

#include "standalone_driver.hpp"

namespace pe_parser {

struct export_entry_t {
	uint16_t    ordinal = 0;
	std::string name;
	uint32_t    rva = 0;
	uint64_t    address = 0;
	bool        is_forwarded = false;
	std::string forward_name;
};

struct import_entry_t {
	std::string module_name;
	std::string function_name;
	uint16_t    ordinal = 0;
	uint16_t    hint = 0;
	uint64_t    iat_address = 0;
	uint64_t    bound_address = 0;
};

struct section_info_t {
	std::string name;
	uint32_t    virtual_address = 0;
	uint32_t    virtual_size = 0;
	uint32_t    raw_size = 0;
	uint32_t    characteristics = 0;
};

struct pe_info_t {
	uint64_t                    image_base = 0;
	uint64_t                    entry_point = 0;
	uint32_t                    size_of_image = 0;
	std::vector<section_info_t> sections;
	std::vector<export_entry_t> exports;
	std::vector<import_entry_t> imports;
	bool                        is_64bit = false;
	uint32_t                    timestamp = 0;
	uint32_t                    export_dir_rva = 0;
	uint32_t                    export_dir_size = 0;
	uint32_t                    import_dir_rva = 0;
	uint32_t                    import_dir_size = 0;
	uint16_t                    subsystem = 0;
	uint16_t                    characteristics = 0;
};

namespace detail {

inline bool deadline_expired(const std::chrono::steady_clock::time_point* deadline)
{
	return deadline && std::chrono::steady_clock::now() >= *deadline;
}

inline bool read_mem(uint64_t addr, void* buf, size_t size)
{
	std::vector<uint8_t> tmp;
	if (!driver_bridge::read_memory(addr, size, tmp))
		return false;
	if (tmp.size() < size)
		return false;
	std::memcpy(buf, tmp.data(), size);
	return true;
}

inline bool read_mem_partial(uint64_t addr, void* buf, size_t size, size_t& out_read)
{
	std::vector<uint8_t> tmp;
	if (!driver_bridge::read_memory(addr, size, tmp)) {
		out_read = 0;
		return false;
	}
	out_read = tmp.size();
	if (out_read > 0)
		std::memcpy(buf, tmp.data(), out_read);
	return out_read > 0;
}

inline bool read_string_at(uint64_t addr, size_t max_len, std::string& out)
{
	out.clear();
	const size_t chunk = 256;
	size_t total = 0;
	while (total < max_len) {
		size_t to_read = chunk;
		if (total + to_read > max_len) to_read = max_len - total;
		uint8_t buf[256];
		size_t got = 0;
		if (!read_mem_partial(addr + total, buf, to_read, got) || got == 0)
			break;
		for (size_t i = 0; i < got; ++i) {
			if (buf[i] == 0)
				return true;
			out.push_back(static_cast<char>(buf[i]));
		}
		total += got;
	}
	return !out.empty();
}

}

inline std::string format_characteristics(uint32_t chars)
{
	std::string result;
	if (chars & 0x00000020) result += 'C';
	if (chars & 0x00000040) result += 'D';
	if (chars & 0x20000000) result += 'X';
	if (chars & 0x40000000) result += 'R';
	if (chars & 0x80000000) result += 'W';
	if (result.empty()) result = "---";
	return result;
}

inline bool parse_exports(uint64_t module_base, const pe_info_t& pe, std::vector<export_entry_t>& out,
	size_t max_entries = (std::numeric_limits<size_t>::max)(),
	const std::chrono::steady_clock::time_point* deadline = nullptr,
	bool* truncated = nullptr)
{
	out.clear();
	if (truncated) *truncated = false;
	if (pe.export_dir_rva == 0 || pe.export_dir_size == 0)
		return true;
	if (max_entries == 0) {
		if (truncated) *truncated = true;
		return true;
	}
	if (detail::deadline_expired(deadline)) {
		if (truncated) *truncated = true;
		return false;
	}

	uint64_t export_dir_addr = module_base + pe.export_dir_rva;

	uint8_t dir_buf[40];
	if (!detail::read_mem(export_dir_addr, dir_buf, 40))
		return false;

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

	if (num_functions == 0 || num_functions > 0x10000)
		return true;
	if (num_names > num_functions)
		num_names = num_functions;

	const bool bounded = max_entries != (std::numeric_limits<size_t>::max)();
	uint32_t names_to_read = num_names;
	if (bounded) {
		size_t name_cap = max_entries * 4;
		if (name_cap < max_entries)
			name_cap = max_entries;
		if (name_cap > 4096)
			name_cap = 4096;
		if (names_to_read > name_cap) {
			names_to_read = static_cast<uint32_t>(name_cap);
			if (truncated) *truncated = true;
		}
	}

	std::vector<uint32_t> addr_table(num_functions);
	if (!detail::read_mem(module_base + addr_table_rva, addr_table.data(), num_functions * 4))
		return false;

	std::vector<uint32_t> name_ptrs(names_to_read);
	std::vector<uint16_t> ordinals(names_to_read);
	if (names_to_read > 0) {
		if (!detail::read_mem(module_base + name_table_rva, name_ptrs.data(), names_to_read * 4))
			return false;
		if (!detail::read_mem(module_base + ordinal_table_rva, ordinals.data(), names_to_read * 2))
			return false;
	}

	std::vector<std::string> name_lookup(num_functions);
	for (uint32_t i = 0; i < names_to_read; ++i) {
		if (detail::deadline_expired(deadline)) {
			if (truncated) *truncated = true;
			return true;
		}
		if (ordinals[i] < num_functions) {
			std::string fname;
			detail::read_string_at(module_base + name_ptrs[i], 512, fname);
			name_lookup[ordinals[i]] = std::move(fname);
		}
	}

	uint32_t exp_start = pe.export_dir_rva;
	uint32_t exp_end = pe.export_dir_rva + pe.export_dir_size;

	out.reserve(std::min<size_t>(num_functions, max_entries));
	for (uint32_t i = 0; i < num_functions; ++i) {
		if (out.size() >= max_entries) {
			if (truncated) *truncated = true;
			break;
		}
		if (detail::deadline_expired(deadline)) {
			if (truncated) *truncated = true;
			break;
		}
		if (addr_table[i] == 0)
			continue;

		export_entry_t entry;
		entry.ordinal = static_cast<uint16_t>(ordinal_base + i);
		entry.rva = addr_table[i];
		entry.address = module_base + addr_table[i];
		entry.name = name_lookup[i];

		if (addr_table[i] >= exp_start && addr_table[i] < exp_end) {
			entry.is_forwarded = true;
			detail::read_string_at(module_base + addr_table[i], 512, entry.forward_name);
		}

		out.push_back(std::move(entry));
	}

	return true;
}

inline bool parse_imports(uint64_t module_base, const pe_info_t& pe, std::vector<import_entry_t>& out,
	size_t max_entries = (std::numeric_limits<size_t>::max)(),
	const std::chrono::steady_clock::time_point* deadline = nullptr,
	bool* truncated = nullptr)
{
	out.clear();
	if (truncated) *truncated = false;
	if (pe.import_dir_rva == 0 || pe.import_dir_size == 0)
		return true;
	if (max_entries == 0) {
		if (truncated) *truncated = true;
		return true;
	}

	uint64_t import_dir_addr = module_base + pe.import_dir_rva;

	for (uint32_t desc_idx = 0; desc_idx < 4096; ++desc_idx) {
		if (out.size() >= max_entries) {
			if (truncated) *truncated = true;
			break;
		}
		if (detail::deadline_expired(deadline)) {
			if (truncated) *truncated = true;
			break;
		}
		uint8_t desc_buf[20];
		if (!detail::read_mem(import_dir_addr + desc_idx * 20, desc_buf, 20))
			break;

		uint32_t ilt_rva = 0;
		uint32_t name_rva = 0;
		uint32_t iat_rva = 0;
		std::memcpy(&ilt_rva, desc_buf + 0, 4);
		std::memcpy(&name_rva, desc_buf + 12, 4);
		std::memcpy(&iat_rva, desc_buf + 16, 4);

		if (ilt_rva == 0 && iat_rva == 0)
			break;

		std::string mod_name;
		if (name_rva != 0)
			detail::read_string_at(module_base + name_rva, 256, mod_name);

		uint32_t lookup_rva = (ilt_rva != 0) ? ilt_rva : iat_rva;

		for (uint32_t thunk_idx = 0; thunk_idx < 0x10000; ++thunk_idx) {
			if (out.size() >= max_entries) {
				if (truncated) *truncated = true;
				break;
			}
			if (detail::deadline_expired(deadline)) {
				if (truncated) *truncated = true;
				break;
			}
			uint64_t thunk_addr = module_base + lookup_rva + (pe.is_64bit ? thunk_idx * 8 : thunk_idx * 4);
			uint64_t thunk_val = 0;

			if (pe.is_64bit) {
				if (!detail::read_mem(thunk_addr, &thunk_val, 8))
					break;
			} else {
				uint32_t tmp32 = 0;
				if (!detail::read_mem(thunk_addr, &tmp32, 4))
					break;
				thunk_val = tmp32;
			}

			if (thunk_val == 0)
				break;

			import_entry_t entry;
			entry.module_name = mod_name;
			entry.iat_address = module_base + iat_rva + (pe.is_64bit ? thunk_idx * 8 : thunk_idx * 4);

			uint64_t iat_val = 0;
			if (pe.is_64bit)
				detail::read_mem(entry.iat_address, &iat_val, 8);
			else {
				uint32_t tmp32 = 0;
				detail::read_mem(entry.iat_address, &tmp32, 4);
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
				detail::read_mem(module_base + hint_name_rva, &hint, 2);
				entry.hint = hint;
				detail::read_string_at(module_base + hint_name_rva + 2, 512, entry.function_name);
			}

			out.push_back(std::move(entry));
		}
	}

	return true;
}

inline bool parse(uint64_t module_base, pe_info_t& out, bool include_imports_exports = true)
{
	out = {};

	uint16_t dos_magic = 0;
	if (!detail::read_mem(module_base, &dos_magic, 2))
		return false;
	if (dos_magic != 0x5A4D)
		return false;

	uint32_t e_lfanew = 0;
	if (!detail::read_mem(module_base + 0x3C, &e_lfanew, 4))
		return false;
	if (e_lfanew > 0x1000)
		return false;

	uint64_t nt_addr = module_base + e_lfanew;
	uint32_t nt_sig = 0;
	if (!detail::read_mem(nt_addr, &nt_sig, 4))
		return false;
	if (nt_sig != 0x00004550)
		return false;

	uint8_t file_header[20];
	if (!detail::read_mem(nt_addr + 4, file_header, 20))
		return false;

	uint16_t machine = 0;
	std::memcpy(&machine, file_header + 0, 2);
	uint16_t num_sections = 0;
	std::memcpy(&num_sections, file_header + 2, 2);
	std::memcpy(&out.timestamp, file_header + 4, 4);
	uint16_t opt_header_size = 0;
	std::memcpy(&opt_header_size, file_header + 16, 2);
	std::memcpy(&out.characteristics, file_header + 18, 2);

	uint64_t opt_addr = nt_addr + 24;
	uint16_t opt_magic = 0;
	if (!detail::read_mem(opt_addr, &opt_magic, 2))
		return false;

	out.is_64bit = (opt_magic == 0x020B);

	if (out.is_64bit) {
		uint8_t opt_buf[128];
		size_t to_read = (opt_header_size < 128) ? opt_header_size : 128;
		if (!detail::read_mem(opt_addr, opt_buf, to_read))
			return false;

		uint32_t ep_rva = 0;
		std::memcpy(&ep_rva, opt_buf + 16, 4);
		std::memcpy(&out.image_base, opt_buf + 24, 8);
		std::memcpy(&out.size_of_image, opt_buf + 56, 4);
		out.entry_point = module_base + ep_rva;

		if (to_read >= 70)
			std::memcpy(&out.subsystem, opt_buf + 68, 2);

		if (to_read >= 128) {
			std::memcpy(&out.export_dir_rva, opt_buf + 112, 4);
			std::memcpy(&out.export_dir_size, opt_buf + 116, 4);
			std::memcpy(&out.import_dir_rva, opt_buf + 120, 4);
			std::memcpy(&out.import_dir_size, opt_buf + 124, 4);
		}
	} else {
		uint8_t opt_buf[128];
		size_t to_read = (opt_header_size < 128) ? opt_header_size : 128;
		if (!detail::read_mem(opt_addr, opt_buf, to_read))
			return false;

		uint32_t ep_rva = 0;
		std::memcpy(&ep_rva, opt_buf + 16, 4);
		uint32_t image_base_32 = 0;
		std::memcpy(&image_base_32, opt_buf + 28, 4);
		out.image_base = image_base_32;
		std::memcpy(&out.size_of_image, opt_buf + 56, 4);
		out.entry_point = module_base + ep_rva;

		if (to_read >= 70)
			std::memcpy(&out.subsystem, opt_buf + 68, 2);

		if (to_read >= 104) {
			std::memcpy(&out.export_dir_rva, opt_buf + 96, 4);
			std::memcpy(&out.export_dir_size, opt_buf + 100, 4);
		}
		if (to_read >= 112) {
			std::memcpy(&out.import_dir_rva, opt_buf + 104, 4);
			std::memcpy(&out.import_dir_size, opt_buf + 108, 4);
		}
	}

	uint64_t section_start = opt_addr + opt_header_size;
	if (num_sections > 96)
		num_sections = 96;

	for (uint16_t i = 0; i < num_sections; ++i) {
		uint8_t sec_buf[40];
		if (!detail::read_mem(section_start + i * 40, sec_buf, 40))
			break;

		section_info_t sec;
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

	if (include_imports_exports) {
		parse_exports(module_base, out, out.exports);
		parse_imports(module_base, out, out.imports);
	}

	return true;
}

}
