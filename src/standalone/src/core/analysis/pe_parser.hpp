#pragma once

#include <algorithm>
#include <cstdint>
#include <chrono>
#include <limits>
#include <string>
#include <vector>
#include <cstring>

#include "standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"

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

struct parse_options_t {
	bool include_imports_exports = true;
	size_t max_export_entries = (std::numeric_limits<size_t>::max)();
	size_t max_import_entries = (std::numeric_limits<size_t>::max)();
	const std::chrono::steady_clock::time_point* deadline = nullptr;
	bool* truncated = nullptr;
	bool* exports_truncated = nullptr;
	bool* imports_truncated = nullptr;
	bool emit_diagnostics = false;
};

namespace detail {

inline bool deadline_expired(const std::chrono::steady_clock::time_point* deadline)
{
	return deadline && std::chrono::steady_clock::now() >= *deadline;
}

inline uint64_t elapsed_us_since(std::chrono::steady_clock::time_point started)
{
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
		std::chrono::steady_clock::now() - started).count());
}

inline uint64_t deadline_remaining_ms(const std::chrono::steady_clock::time_point* deadline)
{
	if (!deadline)
		return 0;
	const auto now = std::chrono::steady_clock::now();
	if (now >= *deadline)
		return 0;
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - now).count());
}

inline void set_truncated(bool* truncated)
{
	if (truncated)
		*truncated = true;
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

inline bool read_string_at(uint64_t addr, size_t max_len, std::string& out,
	const std::chrono::steady_clock::time_point* deadline = nullptr,
	bool* truncated = nullptr,
	bool emit_diagnostics = false,
	const char* context = "")
{
	out.clear();
	const auto started = std::chrono::steady_clock::now();
	const size_t chunk = 256;
	size_t total = 0;
	bool found_nul = false;
	bool read_failed = false;
	while (total < max_len) {
		if (deadline_expired(deadline)) {
			set_truncated(truncated);
			break;
		}
		size_t to_read = chunk;
		if (total + to_read > max_len) to_read = max_len - total;
		uint8_t buf[256];
		size_t got = 0;
		if (!read_mem_partial(addr + total, buf, to_read, got) || got == 0) {
			read_failed = true;
			break;
		}
		for (size_t i = 0; i < got; ++i) {
			if (buf[i] == 0) {
				found_nul = true;
				if (emit_diagnostics) {
					diag::log_tagged_critical_fmt("pe_parse",
						"read_string_at_exit context=%s addr=0x%llX max_len=%zu bytes_read=%zu found_nul=1 read_failed=0 truncated=%d elapsed_us=%llu deadline_remaining_ms=%llu",
						context ? context : "",
						static_cast<unsigned long long>(addr),
						max_len,
						total + i,
						truncated && *truncated ? 1 : 0,
						static_cast<unsigned long long>(elapsed_us_since(started)),
						static_cast<unsigned long long>(deadline_remaining_ms(deadline)));
				}
				return true;
			}
			out.push_back(static_cast<char>(buf[i]));
		}
		total += got;
	}
	if (total >= max_len && !found_nul)
		set_truncated(truncated);
	if (emit_diagnostics && (elapsed_us_since(started) >= 1000 || (truncated && *truncated) || read_failed)) {
		diag::log_tagged_critical_fmt("pe_parse",
			"read_string_at_exit context=%s addr=0x%llX max_len=%zu bytes_read=%zu found_nul=%d read_failed=%d truncated=%d elapsed_us=%llu deadline_remaining_ms=%llu",
			context ? context : "",
			static_cast<unsigned long long>(addr),
			max_len,
			total,
			found_nul ? 1 : 0,
			read_failed ? 1 : 0,
			truncated && *truncated ? 1 : 0,
			static_cast<unsigned long long>(elapsed_us_since(started)),
			static_cast<unsigned long long>(deadline_remaining_ms(deadline)));
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
	bool* truncated = nullptr,
	bool emit_diagnostics = false)
{
	out.clear();
	if (truncated) *truncated = false;
	const auto started = std::chrono::steady_clock::now();
	uint32_t num_functions = 0;
	uint32_t num_names = 0;
	uint32_t addr_table_rva = 0;
	uint32_t name_table_rva = 0;
	uint32_t ordinal_table_rva = 0;
	uint32_t ordinal_base = 0;
	auto finish = [&](bool ok, const char* reason) {
		if (emit_diagnostics) {
			diag::log_tagged_critical_fmt("pe_parse",
				"parse_exports_exit ok=%d reason=%s module_base=0x%llX export_rva=0x%X export_size=0x%X num_functions=%u num_names=%u out_count=%zu max_entries=%zu truncated=%d elapsed_us=%llu deadline_remaining_ms=%llu",
				ok ? 1 : 0,
				reason ? reason : "",
				static_cast<unsigned long long>(module_base),
				pe.export_dir_rva,
				pe.export_dir_size,
				num_functions,
				num_names,
				out.size(),
				max_entries,
				truncated && *truncated ? 1 : 0,
				static_cast<unsigned long long>(detail::elapsed_us_since(started)),
				static_cast<unsigned long long>(detail::deadline_remaining_ms(deadline)));
		}
		return ok;
	};
	if (emit_diagnostics) {
		diag::log_tagged_critical_fmt("pe_parse",
			"parse_exports_enter module_base=0x%llX export_rva=0x%X export_size=0x%X max_entries=%zu deadline_remaining_ms=%llu",
			static_cast<unsigned long long>(module_base),
			pe.export_dir_rva,
			pe.export_dir_size,
			max_entries,
			static_cast<unsigned long long>(detail::deadline_remaining_ms(deadline)));
	}
	if (pe.export_dir_rva == 0 || pe.export_dir_size == 0)
		return finish(true, "no_export_directory");
	if (max_entries == 0) {
		detail::set_truncated(truncated);
		return finish(true, "max_entries_zero");
	}
	if (detail::deadline_expired(deadline)) {
		detail::set_truncated(truncated);
		return finish(false, "deadline_before_directory");
	}

	uint64_t export_dir_addr = module_base + pe.export_dir_rva;

	uint8_t dir_buf[40];
	if (!detail::read_mem(export_dir_addr, dir_buf, 40))
		return finish(false, "directory_read_failed");

	std::memcpy(&ordinal_base, dir_buf + 16, 4);
	std::memcpy(&num_functions, dir_buf + 20, 4);
	std::memcpy(&num_names, dir_buf + 24, 4);
	std::memcpy(&addr_table_rva, dir_buf + 28, 4);
	std::memcpy(&name_table_rva, dir_buf + 32, 4);
	std::memcpy(&ordinal_table_rva, dir_buf + 36, 4);

	if (num_functions == 0)
		return finish(true, "empty_export_table");
	if (num_functions > 0x10000)
		return finish(true, "function_count_out_of_range");
	if (num_names > num_functions)
		num_names = num_functions;

	std::vector<uint32_t> addr_table(num_functions);
	if (!detail::read_mem(module_base + addr_table_rva, addr_table.data(), num_functions * 4))
		return finish(false, "address_table_read_failed");

	uint32_t exp_start = pe.export_dir_rva;
	uint32_t exp_end = pe.export_dir_rva + pe.export_dir_size;
	if (exp_end < exp_start)
		exp_end = (std::numeric_limits<uint32_t>::max)();

	out.reserve(std::min<size_t>(num_functions, max_entries));
	std::vector<int32_t> ordinal_to_output(num_functions, -1);
	for (uint32_t i = 0; i < num_functions; ++i) {
		if (out.size() >= max_entries) {
			detail::set_truncated(truncated);
			break;
		}
		if (detail::deadline_expired(deadline)) {
			detail::set_truncated(truncated);
			return finish(true, "deadline_function_table");
		}
		if (addr_table[i] == 0)
			continue;

		export_entry_t entry;
		entry.ordinal = static_cast<uint16_t>(ordinal_base + i);
		entry.rva = addr_table[i];
		entry.address = module_base + addr_table[i];
		entry.is_forwarded = addr_table[i] >= exp_start && addr_table[i] < exp_end;

		ordinal_to_output[i] = static_cast<int32_t>(out.size());
		out.push_back(std::move(entry));
	}

	if (num_names == 0 || out.empty() || name_table_rva == 0 || ordinal_table_rva == 0)
		return finish(true, "no_export_names");
	if (detail::deadline_expired(deadline)) {
		detail::set_truncated(truncated);
		return finish(true, "deadline_before_names");
	}

	std::vector<uint32_t> name_ptrs(num_names);
	std::vector<uint16_t> ordinals(num_names);
	if (!detail::read_mem(module_base + name_table_rva, name_ptrs.data(), num_names * 4)) {
		detail::set_truncated(truncated);
		return finish(true, "name_table_read_failed");
	}
	if (!detail::read_mem(module_base + ordinal_table_rva, ordinals.data(), num_names * 2)) {
		detail::set_truncated(truncated);
		return finish(true, "ordinal_table_read_failed");
	}

	for (uint32_t i = 0; i < num_names; ++i) {
		if (detail::deadline_expired(deadline)) {
			detail::set_truncated(truncated);
			return finish(true, "deadline_export_names");
		}
		uint16_t ord = ordinals[i];
		if (ord >= num_functions)
			continue;
		int32_t out_index = ordinal_to_output[ord];
		if (out_index < 0)
			continue;
		std::string fname;
		if (detail::read_string_at(module_base + name_ptrs[i], 512, fname, deadline, truncated, emit_diagnostics, "export_name") && !fname.empty())
			out[static_cast<size_t>(out_index)].name = std::move(fname);
	}

	for (auto& entry : out) {
		if (!entry.is_forwarded)
			continue;
		if (detail::deadline_expired(deadline)) {
			detail::set_truncated(truncated);
			break;
		}
		detail::read_string_at(module_base + entry.rva, 512, entry.forward_name, deadline, truncated, emit_diagnostics, "export_forwarder");
	}

	return finish(true, "ok");
}

inline bool parse_imports(uint64_t module_base, const pe_info_t& pe, std::vector<import_entry_t>& out,
	size_t max_entries = (std::numeric_limits<size_t>::max)(),
	const std::chrono::steady_clock::time_point* deadline = nullptr,
	bool* truncated = nullptr,
	bool emit_diagnostics = false)
{
	out.clear();
	if (truncated) *truncated = false;
	const auto started = std::chrono::steady_clock::now();
	uint32_t last_desc_idx = 0;
	uint32_t last_thunk_idx = 0;
	auto finish = [&](bool ok, const char* reason) {
		if (emit_diagnostics) {
			diag::log_tagged_critical_fmt("pe_parse",
				"parse_imports_exit ok=%d reason=%s module_base=0x%llX import_rva=0x%X import_size=0x%X descriptors_seen=%u last_thunk=%u out_count=%zu max_entries=%zu truncated=%d elapsed_us=%llu deadline_remaining_ms=%llu",
				ok ? 1 : 0,
				reason ? reason : "",
				static_cast<unsigned long long>(module_base),
				pe.import_dir_rva,
				pe.import_dir_size,
				last_desc_idx,
				last_thunk_idx,
				out.size(),
				max_entries,
				truncated && *truncated ? 1 : 0,
				static_cast<unsigned long long>(detail::elapsed_us_since(started)),
				static_cast<unsigned long long>(detail::deadline_remaining_ms(deadline)));
		}
		return ok;
	};
	if (emit_diagnostics) {
		diag::log_tagged_critical_fmt("pe_parse",
			"parse_imports_enter module_base=0x%llX import_rva=0x%X import_size=0x%X max_entries=%zu deadline_remaining_ms=%llu",
			static_cast<unsigned long long>(module_base),
			pe.import_dir_rva,
			pe.import_dir_size,
			max_entries,
			static_cast<unsigned long long>(detail::deadline_remaining_ms(deadline)));
	}
	if (pe.import_dir_rva == 0 || pe.import_dir_size == 0)
		return finish(true, "no_import_directory");
	if (max_entries == 0) {
		detail::set_truncated(truncated);
		return finish(true, "max_entries_zero");
	}

	uint64_t import_dir_addr = module_base + pe.import_dir_rva;
	bool stop = false;

	for (uint32_t desc_idx = 0; desc_idx < 4096 && !stop; ++desc_idx) {
		last_desc_idx = desc_idx;
		last_thunk_idx = 0;
		if (out.size() >= max_entries) {
			detail::set_truncated(truncated);
			break;
		}
		if (detail::deadline_expired(deadline)) {
			detail::set_truncated(truncated);
			break;
		}
		if (emit_diagnostics && (desc_idx % 16) == 0) {
			diag::log_tagged_critical_fmt("pe_parse",
				"parse_imports_descriptor_progress desc_idx=%u out_count=%zu max_entries=%zu truncated=%d deadline_remaining_ms=%llu elapsed_us=%llu",
				desc_idx,
				out.size(),
				max_entries,
				truncated && *truncated ? 1 : 0,
				static_cast<unsigned long long>(detail::deadline_remaining_ms(deadline)),
				static_cast<unsigned long long>(detail::elapsed_us_since(started)));
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
			detail::read_string_at(module_base + name_rva, 256, mod_name, deadline, truncated, emit_diagnostics, "import_module");
		if (detail::deadline_expired(deadline)) {
			detail::set_truncated(truncated);
			break;
		}

		uint32_t lookup_rva = (ilt_rva != 0) ? ilt_rva : iat_rva;

		for (uint32_t thunk_idx = 0; thunk_idx < 0x10000; ++thunk_idx) {
			last_thunk_idx = thunk_idx;
			if (out.size() >= max_entries) {
				detail::set_truncated(truncated);
				stop = true;
				break;
			}
			if (detail::deadline_expired(deadline)) {
				detail::set_truncated(truncated);
				stop = true;
				break;
			}
			if (emit_diagnostics && thunk_idx != 0 && (thunk_idx % 256) == 0) {
				diag::log_tagged_critical_fmt("pe_parse",
					"parse_imports_thunk_progress desc_idx=%u thunk_idx=%u module=%s out_count=%zu max_entries=%zu truncated=%d deadline_remaining_ms=%llu elapsed_us=%llu",
					desc_idx,
					thunk_idx,
					mod_name.c_str(),
					out.size(),
					max_entries,
					truncated && *truncated ? 1 : 0,
					static_cast<unsigned long long>(detail::deadline_remaining_ms(deadline)),
					static_cast<unsigned long long>(detail::elapsed_us_since(started)));
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
				detail::read_string_at(module_base + hint_name_rva + 2, 512, entry.function_name, deadline, truncated, emit_diagnostics, "import_function");
			}

			out.push_back(std::move(entry));
		}
	}

	return finish(true, "ok");
}

inline bool parse(uint64_t module_base, pe_info_t& out, const parse_options_t& options)
{
	out = {};
	if (options.truncated) *options.truncated = false;
	if (options.exports_truncated) *options.exports_truncated = false;
	if (options.imports_truncated) *options.imports_truncated = false;
	bool exports_truncated_local = false;
	bool imports_truncated_local = false;
	bool parse_truncated = false;
	bool* exports_truncated = options.exports_truncated ? options.exports_truncated : &exports_truncated_local;
	bool* imports_truncated = options.imports_truncated ? options.imports_truncated : &imports_truncated_local;
	const auto started = std::chrono::steady_clock::now();
	uint16_t machine = 0;
	uint16_t num_sections = 0;
	uint16_t opt_header_size = 0;
	uint32_t e_lfanew = 0;
	auto aggregate_truncated = [&]() {
		return parse_truncated || (exports_truncated && *exports_truncated) || (imports_truncated && *imports_truncated);
	};
	auto finish = [&](bool ok, const char* reason) {
		if (options.truncated)
			*options.truncated = aggregate_truncated();
		if (options.emit_diagnostics) {
			diag::log_tagged_critical_fmt("pe_parse",
				"pe_parse_exit ok=%d reason=%s module_base=0x%llX include_imports_exports=%d image_base=0x%llX image_size=0x%X entry=0x%llX is64=%d declared_sections=%u sections=%zu exports=%zu imports=%zu export_rva=0x%X export_size=0x%X import_rva=0x%X import_size=0x%X truncated=%d exports_truncated=%d imports_truncated=%d elapsed_us=%llu deadline_remaining_ms=%llu",
				ok ? 1 : 0,
				reason ? reason : "",
				static_cast<unsigned long long>(module_base),
				options.include_imports_exports ? 1 : 0,
				static_cast<unsigned long long>(out.image_base),
				out.size_of_image,
				static_cast<unsigned long long>(out.entry_point),
				out.is_64bit ? 1 : 0,
				num_sections,
				out.sections.size(),
				out.exports.size(),
				out.imports.size(),
				out.export_dir_rva,
				out.export_dir_size,
				out.import_dir_rva,
				out.import_dir_size,
				aggregate_truncated() ? 1 : 0,
				exports_truncated && *exports_truncated ? 1 : 0,
				imports_truncated && *imports_truncated ? 1 : 0,
				static_cast<unsigned long long>(detail::elapsed_us_since(started)),
				static_cast<unsigned long long>(detail::deadline_remaining_ms(options.deadline)));
		}
		return ok;
	};
	if (options.emit_diagnostics) {
		diag::log_tagged_critical_fmt("pe_parse",
			"pe_parse_enter module_base=0x%llX include_imports_exports=%d max_exports=%zu max_imports=%zu deadline_remaining_ms=%llu",
			static_cast<unsigned long long>(module_base),
			options.include_imports_exports ? 1 : 0,
			options.max_export_entries,
			options.max_import_entries,
			static_cast<unsigned long long>(detail::deadline_remaining_ms(options.deadline)));
	}

	if (detail::deadline_expired(options.deadline)) {
		parse_truncated = true;
		return finish(false, "deadline_before_dos");
	}

	uint16_t dos_magic = 0;
	if (!detail::read_mem(module_base, &dos_magic, 2))
		return finish(false, "dos_read_failed");
	if (dos_magic != 0x5A4D)
		return finish(false, "dos_magic_invalid");

	if (!detail::read_mem(module_base + 0x3C, &e_lfanew, 4))
		return finish(false, "elfanew_read_failed");
	if (e_lfanew > 0x1000)
		return finish(false, "elfanew_out_of_range");

	uint64_t nt_addr = module_base + e_lfanew;
	uint32_t nt_sig = 0;
	if (!detail::read_mem(nt_addr, &nt_sig, 4))
		return finish(false, "nt_signature_read_failed");
	if (nt_sig != 0x00004550)
		return finish(false, "nt_signature_invalid");

	uint8_t file_header[20];
	if (!detail::read_mem(nt_addr + 4, file_header, 20))
		return finish(false, "file_header_read_failed");

	std::memcpy(&machine, file_header + 0, 2);
	std::memcpy(&num_sections, file_header + 2, 2);
	std::memcpy(&out.timestamp, file_header + 4, 4);
	std::memcpy(&opt_header_size, file_header + 16, 2);
	std::memcpy(&out.characteristics, file_header + 18, 2);

	uint64_t opt_addr = nt_addr + 24;
	uint16_t opt_magic = 0;
	if (!detail::read_mem(opt_addr, &opt_magic, 2))
		return finish(false, "optional_magic_read_failed");

	out.is_64bit = (opt_magic == 0x020B);

	if (out.is_64bit) {
		uint8_t opt_buf[128];
		size_t to_read = (opt_header_size < 128) ? opt_header_size : 128;
		if (!detail::read_mem(opt_addr, opt_buf, to_read))
			return finish(false, "optional_header_read_failed");

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
			return finish(false, "optional_header_read_failed");

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

	if (options.emit_diagnostics) {
		diag::log_tagged_critical_fmt("pe_parse",
			"pe_parse_headers module_base=0x%llX e_lfanew=0x%X machine=0x%X opt_header_size=%u is64=%d image_base=0x%llX image_size=0x%X entry=0x%llX export_rva=0x%X export_size=0x%X import_rva=0x%X import_size=0x%X deadline_remaining_ms=%llu elapsed_us=%llu",
			static_cast<unsigned long long>(module_base),
			e_lfanew,
			machine,
			opt_header_size,
			out.is_64bit ? 1 : 0,
			static_cast<unsigned long long>(out.image_base),
			out.size_of_image,
			static_cast<unsigned long long>(out.entry_point),
			out.export_dir_rva,
			out.export_dir_size,
			out.import_dir_rva,
			out.import_dir_size,
			static_cast<unsigned long long>(detail::deadline_remaining_ms(options.deadline)),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
	}

	uint64_t section_start = opt_addr + opt_header_size;
	if (num_sections > 96)
		num_sections = 96;

	for (uint16_t i = 0; i < num_sections; ++i) {
		if (detail::deadline_expired(options.deadline)) {
			parse_truncated = true;
			return finish(false, "deadline_sections");
		}
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

	if (options.emit_diagnostics) {
		diag::log_tagged_critical_fmt("pe_parse",
			"pe_parse_sections module_base=0x%llX declared_sections=%u sections=%zu deadline_remaining_ms=%llu elapsed_us=%llu",
			static_cast<unsigned long long>(module_base),
			num_sections,
			out.sections.size(),
			static_cast<unsigned long long>(detail::deadline_remaining_ms(options.deadline)),
			static_cast<unsigned long long>(detail::elapsed_us_since(started)));
	}

	if (options.include_imports_exports) {
		if (detail::deadline_expired(options.deadline)) {
			parse_truncated = true;
			return finish(false, "deadline_before_directories");
		}
		const bool exports_ok = parse_exports(module_base, out, out.exports, options.max_export_entries, options.deadline, exports_truncated, options.emit_diagnostics);
		const bool imports_ok = parse_imports(module_base, out, out.imports, options.max_import_entries, options.deadline, imports_truncated, options.emit_diagnostics);
		if (options.emit_diagnostics) {
			diag::log_tagged_critical_fmt("pe_parse",
				"pe_parse_directories module_base=0x%llX exports_ok=%d imports_ok=%d exports=%zu imports=%zu exports_truncated=%d imports_truncated=%d deadline_remaining_ms=%llu elapsed_us=%llu",
				static_cast<unsigned long long>(module_base),
				exports_ok ? 1 : 0,
				imports_ok ? 1 : 0,
				out.exports.size(),
				out.imports.size(),
				exports_truncated && *exports_truncated ? 1 : 0,
				imports_truncated && *imports_truncated ? 1 : 0,
				static_cast<unsigned long long>(detail::deadline_remaining_ms(options.deadline)),
				static_cast<unsigned long long>(detail::elapsed_us_since(started)));
		}
	}

	return finish(true, "ok");
}

inline bool parse(uint64_t module_base, pe_info_t& out, bool include_imports_exports = true)
{
	parse_options_t options;
	options.include_imports_exports = include_imports_exports;
	return parse(module_base, out, options);
}

inline bool parse_bounded(uint64_t module_base, pe_info_t& out, const parse_options_t& options)
{
	return parse(module_base, out, options);
}

}
