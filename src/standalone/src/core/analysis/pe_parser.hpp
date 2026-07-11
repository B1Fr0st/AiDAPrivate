#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <limits>
#include <optional>
#include <string>
#include <vector>
#include <cstring>
#include <Windows.h>

#include "standalone_driver.hpp"
#include "workspace/analysis_workspace.hpp"
#include "workspace/workspace_registry.hpp"
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

struct runtime_function_entry_t {
	uint32_t begin_rva = 0;
	uint32_t end_rva = 0;
	uint32_t unwind_rva = 0;
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
	uint32_t                    exception_dir_rva = 0;
	uint32_t                    exception_dir_size = 0;
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

inline uint32_t& explicit_read_pid()
{
	thread_local uint32_t pid = 0;
	return pid;
}

struct scoped_read_pid_t {
	uint32_t previous = 0;
	explicit scoped_read_pid_t(uint32_t pid) : previous(explicit_read_pid())
	{
		explicit_read_pid() = pid;
	}
	~scoped_read_pid_t()
	{
		explicit_read_pid() = previous;
	}
};

inline bool checked_add(uint64_t left, uint64_t right, uint64_t& result)
{
	if (left > UINT64_MAX - right) return false;
	result = left + right;
	return true;
}

inline bool valid_image_range(const pe_info_t& pe, uint64_t rva, uint64_t size)
{
	return rva <= pe.size_of_image && size <= pe.size_of_image - rva;
}

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

inline void log_read_mem_failure(uint64_t addr, size_t size, const char* reason)
{
	static std::atomic<std::int64_t> last_log_us{0};
	const std::int64_t now_us = static_cast<std::int64_t>(
		std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
	std::int64_t prev = last_log_us.load(std::memory_order_acquire);
	if (prev != 0 && (now_us - prev) < 1000000)
		return;
	if (!last_log_us.compare_exchange_strong(prev, now_us, std::memory_order_acq_rel))
		return;
	diag::log_tagged_fmt("pe_parse",
		"read_mem_failed addr=0x%llX size=%zu reason=%s driver_attached_pid=%u driver_status=\"%.160s\" driver_last_error=\"%.160s\"",
		static_cast<unsigned long long>(addr),
		size,
		reason ? reason : "",
		driver_bridge::attached_pid(),
		driver_bridge::status().c_str(),
		driver_bridge::last_error().c_str());
}

inline bool read_mem(uint64_t addr, void* buf, size_t size)
{
	std::vector<uint8_t> tmp;
	const uint32_t pid = explicit_read_pid();
	const bool read_ok = pid != 0
		? driver_bridge::read_memory_for(pid, addr, size, tmp)
		: driver_bridge::read_memory(addr, size, tmp);
	if (!read_ok) {
		log_read_mem_failure(addr, size, "driver_bridge_read_memory_failed");
		return false;
	}
	if (tmp.size() < size) {
		log_read_mem_failure(addr, size, "short_read");
		return false;
	}
	std::memcpy(buf, tmp.data(), size);
	return true;
}

inline bool read_mem_partial(uint64_t addr, void* buf, size_t size, size_t& out_read)
{
	std::vector<uint8_t> tmp;
	const uint32_t pid = explicit_read_pid();
	const bool read_ok = pid != 0
		? driver_bridge::read_memory_for(pid, addr, size, tmp)
		: driver_bridge::read_memory(addr, size, tmp);
	if (!read_ok) {
		out_read = 0;
		log_read_mem_failure(addr, size, "driver_bridge_read_memory_failed_partial");
		return false;
	}
	out_read = (std::min)(tmp.size(), size);
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
		uint64_t cursor = 0;
		if (!checked_add(addr, total, cursor) ||
			!read_mem_partial(cursor, buf, to_read, got) || got == 0) {
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

	if (!detail::valid_image_range(pe, pe.export_dir_rva, 40))
		return finish(false, "directory_range_invalid");
	uint64_t export_dir_addr = 0;
	if (!detail::checked_add(module_base, pe.export_dir_rva, export_dir_addr))
		return finish(false, "directory_address_overflow");

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
	if (!detail::valid_image_range(pe, addr_table_rva,
		static_cast<uint64_t>(num_functions) * sizeof(uint32_t)))
		return finish(false, "address_table_range_invalid");

	std::vector<uint32_t> addr_table(num_functions);
	uint64_t addr_table_address = 0;
	if (!detail::checked_add(module_base, addr_table_rva, addr_table_address) ||
		!detail::read_mem(addr_table_address, addr_table.data(), num_functions * 4))
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
		if (!detail::valid_image_range(pe, addr_table[i], 1) ||
			!detail::checked_add(module_base, addr_table[i], entry.address))
			return finish(false, "export_address_invalid");
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
	if (!detail::valid_image_range(pe, name_table_rva,
			static_cast<uint64_t>(num_names) * sizeof(uint32_t)) ||
		!detail::valid_image_range(pe, ordinal_table_rva,
			static_cast<uint64_t>(num_names) * sizeof(uint16_t))) {
		detail::set_truncated(truncated);
		return finish(true, "name_table_range_invalid");
	}
	uint64_t name_table_address = 0;
	uint64_t ordinal_table_address = 0;
	if (!detail::checked_add(module_base, name_table_rva, name_table_address) ||
		!detail::read_mem(name_table_address, name_ptrs.data(), num_names * 4)) {
		detail::set_truncated(truncated);
		return finish(true, "name_table_read_failed");
	}
	if (!detail::checked_add(module_base, ordinal_table_rva, ordinal_table_address) ||
		!detail::read_mem(ordinal_table_address, ordinals.data(), num_names * 2)) {
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
		if (!detail::valid_image_range(pe, name_ptrs[i], 1))
			return finish(false, "export_name_range_invalid");
		uint64_t name_address = 0;
		if (!detail::checked_add(module_base, name_ptrs[i], name_address))
			return finish(false, "export_name_address_overflow");
		const size_t name_limit = static_cast<size_t>((std::min<uint64_t>)(
			512, pe.size_of_image - name_ptrs[i]));
		if (!detail::read_string_at(name_address, name_limit, fname, deadline, truncated,
			emit_diagnostics, "export_name"))
			return finish(false, "export_name_invalid");
		out[static_cast<size_t>(out_index)].name = std::move(fname);
	}

	for (auto& entry : out) {
		if (!entry.is_forwarded)
			continue;
		if (detail::deadline_expired(deadline)) {
			detail::set_truncated(truncated);
			break;
		}
		uint64_t forward_address = 0;
		if (!detail::valid_image_range(pe, entry.rva, 1) ||
			!detail::checked_add(module_base, entry.rva, forward_address))
			return finish(false, "export_forwarder_range_invalid");
		const size_t forward_limit = static_cast<size_t>((std::min<uint64_t>)(
			512, pe.size_of_image - entry.rva));
		if (!detail::read_string_at(forward_address, forward_limit, entry.forward_name,
			deadline, truncated, emit_diagnostics, "export_forwarder"))
			return finish(false, "export_forwarder_invalid");
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

	if (!detail::valid_image_range(pe, pe.import_dir_rva, pe.import_dir_size))
		return finish(false, "directory_range_invalid");
	uint64_t import_dir_addr = 0;
	if (!detail::checked_add(module_base, pe.import_dir_rva, import_dir_addr))
		return finish(false, "directory_address_overflow");
	bool stop = false;
	const uint32_t descriptor_limit = static_cast<uint32_t>((std::min<uint64_t>)(
		4096, pe.import_dir_size / 20));

	for (uint32_t desc_idx = 0; desc_idx < descriptor_limit && !stop; ++desc_idx) {
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
		uint64_t descriptor_address = 0;
		if (!detail::checked_add(import_dir_addr,
			static_cast<uint64_t>(desc_idx) * 20, descriptor_address) ||
			!detail::read_mem(descriptor_address, desc_buf, 20))
			return finish(false, "descriptor_read_failed");

		uint32_t ilt_rva = 0;
		uint32_t name_rva = 0;
		uint32_t iat_rva = 0;
		std::memcpy(&ilt_rva, desc_buf + 0, 4);
		std::memcpy(&name_rva, desc_buf + 12, 4);
		std::memcpy(&iat_rva, desc_buf + 16, 4);

		if (ilt_rva == 0 && iat_rva == 0)
			break;

		std::string mod_name;
		if (name_rva != 0 && detail::valid_image_range(pe, name_rva, 1)) {
			uint64_t module_name_address = 0;
			if (detail::checked_add(module_base, name_rva, module_name_address)) {
				const size_t module_name_limit = static_cast<size_t>((std::min<uint64_t>)(
					256, pe.size_of_image - name_rva));
				if (!detail::read_string_at(module_name_address, module_name_limit, mod_name,
					deadline, truncated, emit_diagnostics, "import_module"))
					return finish(false, "import_module_invalid");
			}
		}
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
			const uint64_t thunk_width = pe.is_64bit ? 8 : 4;
			const uint64_t thunk_offset = static_cast<uint64_t>(thunk_idx) * thunk_width;
			if (!detail::valid_image_range(pe, static_cast<uint64_t>(lookup_rva) + thunk_offset,
					thunk_width))
				return finish(false, "thunk_range_invalid");
			uint64_t thunk_addr = 0;
			if (!detail::checked_add(module_base,
				static_cast<uint64_t>(lookup_rva) + thunk_offset, thunk_addr))
				return finish(false, "thunk_address_overflow");
			uint64_t thunk_val = 0;

			if (pe.is_64bit) {
				if (!detail::read_mem(thunk_addr, &thunk_val, 8))
					return finish(false, "thunk_read_failed");
			} else {
				uint32_t tmp32 = 0;
				if (!detail::read_mem(thunk_addr, &tmp32, 4))
					return finish(false, "thunk_read_failed");
				thunk_val = tmp32;
			}

			if (thunk_val == 0)
				break;

			import_entry_t entry;
			entry.module_name = mod_name;
			if (!detail::valid_image_range(pe, static_cast<uint64_t>(iat_rva) + thunk_offset,
					thunk_width) ||
				!detail::checked_add(module_base,
					static_cast<uint64_t>(iat_rva) + thunk_offset, entry.iat_address))
				return finish(false, "iat_range_invalid");

			uint64_t iat_val = 0;
			if (pe.is_64bit) {
				if (!detail::read_mem(entry.iat_address, &iat_val, 8))
					return finish(false, "iat_read_failed");
			}
			else {
				uint32_t tmp32 = 0;
				if (!detail::read_mem(entry.iat_address, &tmp32, 4))
					return finish(false, "iat_read_failed");
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
				const uint64_t hint_name_value = pe.is_64bit
					? (thunk_val & 0x7FFFFFFFFFFFFFFFULL)
					: (thunk_val & 0x7FFFFFFFULL);
				if (hint_name_value > UINT32_MAX)
					return finish(false, "hint_name_rva_invalid");
				uint32_t hint_name_rva = static_cast<uint32_t>(hint_name_value);
				if (!detail::valid_image_range(pe, hint_name_rva, 3)) {
					detail::set_truncated(truncated);
					return finish(false, "hint_name_range_invalid");
				}
				uint64_t hint_address = 0;
				if (!detail::checked_add(module_base, hint_name_rva, hint_address))
					return finish(false, "hint_name_address_overflow");
				uint16_t hint = 0;
				if (!detail::read_mem(hint_address, &hint, 2))
					return finish(false, "hint_read_failed");
				entry.hint = hint;
				uint64_t function_name_address = 0;
				if (!detail::checked_add(hint_address, 2, function_name_address))
					return finish(false, "function_name_address_overflow");
				const size_t function_name_limit = static_cast<size_t>((std::min<uint64_t>)(
					512, pe.size_of_image - hint_name_rva - 2));
				if (!detail::read_string_at(function_name_address, function_name_limit,
					entry.function_name, deadline, truncated, emit_diagnostics, "import_function"))
					return finish(false, "import_function_invalid");
			}

			out.push_back(std::move(entry));
		}
	}

	return finish(true, "ok");
}

inline aida::analysis::workspace_result_t<pe_info_t> parse_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const parse_options_t& options = {})
{
    using namespace aida::analysis;
    if (!workspace) {
        return workspace_result_t<pe_info_t>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "PE parse requires an explicit workspace", "pe_parser.workspace"));
    }
    if (workspace->target_kind() != target_kind_t::static_file) {
        return workspace_result_t<pe_info_t>::failure(make_workspace_error(
            workspace_error_code_t::live_target_bulk_analysis_unsupported,
            "Complete PE metadata parsing is unavailable for a bounded live snapshot",
            "pe_parser.workspace"));
    }
    if (detail::deadline_expired(options.deadline)) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "PE metadata request deadline expired", "pe_parser.workspace");
        error.deadline = true;
        return workspace_result_t<pe_info_t>::failure(std::move(error));
    }
    const auto image = workspace->image();
    if (!image) {
        return workspace_result_t<pe_info_t>::failure(make_workspace_error(
            workspace_error_code_t::malformed_pe,
            "Workspace has no normalized PE image", "pe_parser.workspace"));
    }
    pe_info_t result;
    result.image_base = image->image_base();
    if (image->entry_rva() != 0) {
        auto entry_point = image->rva_to_va(image->entry_rva());
        if (!entry_point)
            return workspace_result_t<pe_info_t>::failure(entry_point.error());
        result.entry_point = entry_point.value();
    }
    result.size_of_image = image->image_size();
    result.is_64bit = image->architecture() == architecture_id_t::x86_64;
    result.timestamp = image->timestamp();
    result.subsystem = image->subsystem();
    result.characteristics = image->characteristics();
    for (const auto& directory : image->directories()) {
        if (directory.index == 0) {
            result.export_dir_rva = directory.rva;
            result.export_dir_size = directory.size;
        } else if (directory.index == 1) {
            result.import_dir_rva = directory.rva;
            result.import_dir_size = directory.size;
        } else if (directory.index == 3) {
            result.exception_dir_rva = directory.rva;
            result.exception_dir_size = directory.size;
        }
    }
    result.sections.reserve(image->sections().size());
    for (const auto& section : image->sections()) {
        result.sections.push_back(section_info_t{
            section.name,
            section.virtual_address,
            section.virtual_size,
            section.raw_size,
            section.characteristics});
    }
    bool exports_truncated = false;
    bool imports_truncated = false;
    if (options.include_imports_exports) {
        const size_t export_count = (std::min)(image->exports().size(),
            options.max_export_entries);
        result.exports.reserve(export_count);
        for (size_t index = 0; index < export_count; ++index) {
            const auto& entry = image->exports()[index];
            export_entry_t converted;
            converted.ordinal = entry.ordinal > (std::numeric_limits<uint16_t>::max)()
                ? (std::numeric_limits<uint16_t>::max)()
                : static_cast<uint16_t>(entry.ordinal);
            converted.name = entry.name.value_or(std::string{});
            converted.rva = entry.rva;
            auto export_address = image->rva_to_va(entry.rva);
            if (!export_address)
                return workspace_result_t<pe_info_t>::failure(export_address.error());
            converted.address = export_address.value();
            converted.is_forwarded = entry.forwarder.has_value();
            converted.forward_name = entry.forwarder.value_or(std::string{});
            result.exports.push_back(std::move(converted));
        }
        exports_truncated = export_count != image->exports().size();
        const size_t import_count = (std::min)(image->imports().size(),
            options.max_import_entries);
        result.imports.reserve(import_count);
        for (size_t index = 0; index < import_count; ++index) {
            const auto& entry = image->imports()[index];
            import_entry_t converted;
            converted.module_name = entry.library;
            converted.function_name = entry.name.value_or(std::string{});
            converted.ordinal = entry.ordinal.value_or(0);
            converted.hint = entry.hint.value_or(0);
            auto iat_address = image->rva_to_va(entry.iat_rva);
            if (!iat_address)
                return workspace_result_t<pe_info_t>::failure(iat_address.error());
            converted.iat_address = iat_address.value();
            result.imports.push_back(std::move(converted));
        }
        imports_truncated = import_count != image->imports().size();
    }
    if (options.exports_truncated) *options.exports_truncated = exports_truncated;
    if (options.imports_truncated) *options.imports_truncated = imports_truncated;
    if (options.truncated) *options.truncated = exports_truncated || imports_truncated;
    return workspace_result_t<pe_info_t>::success(std::move(result));
}

inline bool parse_live(uint32_t pid, uint64_t module_base, pe_info_t& out,
	const parse_options_t& options)
{
	out = {};
	if (pid == 0 || pid == GetCurrentProcessId() || module_base == 0) return false;
	if (options.truncated) *options.truncated = false;
	if (options.exports_truncated) *options.exports_truncated = false;
	if (options.imports_truncated) *options.imports_truncated = false;
	bool exports_truncated_local = false;
	bool imports_truncated_local = false;
	bool parse_truncated = false;
	bool* exports_truncated = options.exports_truncated
		? options.exports_truncated : &exports_truncated_local;
	bool* imports_truncated = options.imports_truncated
		? options.imports_truncated : &imports_truncated_local;
	detail::scoped_read_pid_t read_scope(pid);
	const auto started = std::chrono::steady_clock::now();
	uint16_t machine = 0;
	uint16_t num_sections = 0;
	uint16_t opt_header_size = 0;
	uint32_t e_lfanew = 0;
	auto aggregate_truncated = [&]() {
		return parse_truncated || *exports_truncated || *imports_truncated;
	};
	auto finish = [&](bool ok, const char* reason) {
		if (options.truncated) *options.truncated = aggregate_truncated();
		if (options.emit_diagnostics) {
			diag::log_tagged_critical_fmt("pe_parse",
				"pe_parse_live_exit ok=%d reason=%s pid=%u module_base=0x%llX include_imports_exports=%d image_base=0x%llX image_size=0x%X entry=0x%llX is64=%d declared_sections=%u sections=%zu exports=%zu imports=%zu truncated=%d elapsed_us=%llu deadline_remaining_ms=%llu",
				ok ? 1 : 0, reason ? reason : "", pid,
				static_cast<unsigned long long>(module_base),
				options.include_imports_exports ? 1 : 0,
				static_cast<unsigned long long>(out.image_base), out.size_of_image,
				static_cast<unsigned long long>(out.entry_point), out.is_64bit ? 1 : 0,
				num_sections, out.sections.size(), out.exports.size(), out.imports.size(),
				aggregate_truncated() ? 1 : 0,
				static_cast<unsigned long long>(detail::elapsed_us_since(started)),
				static_cast<unsigned long long>(detail::deadline_remaining_ms(options.deadline)));
		}
		return ok;
	};
	if (detail::deadline_expired(options.deadline)) {
		parse_truncated = true;
		return finish(false, "deadline_before_dos");
	}
	uint16_t dos_magic = 0;
	if (!detail::read_mem(module_base, &dos_magic, sizeof(dos_magic)))
		return finish(false, "dos_read_failed");
	if (dos_magic != IMAGE_DOS_SIGNATURE)
		return finish(false, "dos_magic_invalid");
	uint64_t elfanew_address = 0;
	if (!detail::checked_add(module_base, 0x3c, elfanew_address) ||
		!detail::read_mem(elfanew_address, &e_lfanew, sizeof(e_lfanew)))
		return finish(false, "elfanew_read_failed");
	if (e_lfanew < sizeof(IMAGE_DOS_HEADER) || e_lfanew > 0x1000)
		return finish(false, "elfanew_out_of_range");
	uint64_t nt_address = 0;
	if (!detail::checked_add(module_base, e_lfanew, nt_address))
		return finish(false, "nt_address_overflow");
	uint32_t nt_signature = 0;
	if (!detail::read_mem(nt_address, &nt_signature, sizeof(nt_signature)))
		return finish(false, "nt_signature_read_failed");
	if (nt_signature != IMAGE_NT_SIGNATURE)
		return finish(false, "nt_signature_invalid");
	uint64_t file_header_address = 0;
	if (!detail::checked_add(nt_address, sizeof(uint32_t), file_header_address))
		return finish(false, "file_header_address_overflow");
	uint8_t file_header[IMAGE_SIZEOF_FILE_HEADER]{};
	if (!detail::read_mem(file_header_address, file_header, sizeof(file_header)))
		return finish(false, "file_header_read_failed");
	std::memcpy(&machine, file_header, sizeof(machine));
	std::memcpy(&num_sections, file_header + 2, sizeof(num_sections));
	std::memcpy(&out.timestamp, file_header + 4, sizeof(out.timestamp));
	std::memcpy(&opt_header_size, file_header + 16, sizeof(opt_header_size));
	std::memcpy(&out.characteristics, file_header + 18, sizeof(out.characteristics));
	if (num_sections > 96 || opt_header_size < 70 || opt_header_size > 0x1000)
		return finish(false, "header_counts_out_of_range");
	uint64_t optional_address = 0;
	if (!detail::checked_add(nt_address, sizeof(uint32_t) + IMAGE_SIZEOF_FILE_HEADER,
		optional_address))
		return finish(false, "optional_header_address_overflow");
	uint8_t optional_header[256]{};
	const size_t optional_read = (std::min<size_t>)(opt_header_size,
		sizeof(optional_header));
	if (!detail::read_mem(optional_address, optional_header, optional_read))
		return finish(false, "optional_header_read_failed");
	uint16_t optional_magic = 0;
	std::memcpy(&optional_magic, optional_header, sizeof(optional_magic));
	if (optional_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
		optional_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return finish(false, "optional_magic_invalid");
	out.is_64bit = optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	uint32_t entry_rva = 0;
	std::memcpy(&entry_rva, optional_header + 16, sizeof(entry_rva));
	if (out.is_64bit) {
		std::memcpy(&out.image_base, optional_header + 24, sizeof(out.image_base));
	} else {
		uint32_t image_base_32 = 0;
		std::memcpy(&image_base_32, optional_header + 28, sizeof(image_base_32));
		out.image_base = image_base_32;
	}
	std::memcpy(&out.size_of_image, optional_header + 56, sizeof(out.size_of_image));
	std::memcpy(&out.subsystem, optional_header + 68, sizeof(out.subsystem));
	if (out.size_of_image == 0 || module_base > UINT64_MAX - out.size_of_image)
		return finish(false, "image_size_invalid");
	if (entry_rva != 0) {
		if (!detail::valid_image_range(out, entry_rva, 1) ||
			!detail::checked_add(module_base, entry_rva, out.entry_point))
			return finish(false, "entry_point_invalid");
	}
	if (out.is_64bit && optional_read >= 128) {
		std::memcpy(&out.export_dir_rva, optional_header + 112, 4);
		std::memcpy(&out.export_dir_size, optional_header + 116, 4);
		std::memcpy(&out.import_dir_rva, optional_header + 120, 4);
		std::memcpy(&out.import_dir_size, optional_header + 124, 4);
		if (optional_read >= 144) {
			std::memcpy(&out.exception_dir_rva, optional_header + 136, 4);
			std::memcpy(&out.exception_dir_size, optional_header + 140, 4);
		}
	} else if (!out.is_64bit && optional_read >= 112) {
		std::memcpy(&out.export_dir_rva, optional_header + 96, 4);
		std::memcpy(&out.export_dir_size, optional_header + 100, 4);
		std::memcpy(&out.import_dir_rva, optional_header + 104, 4);
		std::memcpy(&out.import_dir_size, optional_header + 108, 4);
		if (optional_read >= 128) {
			std::memcpy(&out.exception_dir_rva, optional_header + 120, 4);
			std::memcpy(&out.exception_dir_size, optional_header + 124, 4);
		}
	}
	uint64_t section_table = 0;
	if (!detail::checked_add(optional_address, opt_header_size, section_table))
		return finish(false, "section_table_address_overflow");
	out.sections.reserve(num_sections);
	for (uint16_t index = 0; index < num_sections; ++index) {
		if (detail::deadline_expired(options.deadline)) {
			parse_truncated = true;
			return finish(false, "deadline_sections");
		}
		uint64_t section_address = 0;
		if (!detail::checked_add(section_table,
			static_cast<uint64_t>(index) * IMAGE_SIZEOF_SECTION_HEADER,
			section_address))
			return finish(false, "section_address_overflow");
		uint8_t section_header[IMAGE_SIZEOF_SECTION_HEADER]{};
		if (!detail::read_mem(section_address, section_header, sizeof(section_header)))
			return finish(false, "section_read_failed");
		section_info_t section;
		char name[9]{};
		std::memcpy(name, section_header, 8);
		section.name = name;
		std::memcpy(&section.virtual_size, section_header + 8, 4);
		std::memcpy(&section.virtual_address, section_header + 12, 4);
		std::memcpy(&section.raw_size, section_header + 16, 4);
		std::memcpy(&section.characteristics, section_header + 36, 4);
		const uint64_t mapped_size = section.virtual_size != 0
			? section.virtual_size : section.raw_size;
		if (!detail::valid_image_range(out, section.virtual_address, mapped_size))
			return finish(false, "section_range_invalid");
		out.sections.push_back(std::move(section));
	}
	if (options.include_imports_exports) {
		if (detail::deadline_expired(options.deadline)) {
			parse_truncated = true;
			return finish(false, "deadline_before_directories");
		}
		if (!parse_exports(module_base, out, out.exports, options.max_export_entries,
			options.deadline, exports_truncated, options.emit_diagnostics))
			return finish(false, "exports_invalid");
		if (!parse_imports(module_base, out, out.imports, options.max_import_entries,
			options.deadline, imports_truncated, options.emit_diagnostics))
			return finish(false, "imports_invalid");
	}
	return finish(true, "ok");
}

inline bool parse_live(uint32_t pid, uint64_t module_base, pe_info_t& out,
	bool include_imports_exports = true)
{
	parse_options_t options;
	options.include_imports_exports = include_imports_exports;
	return parse_live(pid, module_base, out, options);
}

inline aida::analysis::workspace_result_t<std::optional<runtime_function_entry_t>>
find_live_runtime_function(uint32_t pid, uint64_t module_base,
	const pe_info_t& pe, uint64_t requested_va,
	const aida::analysis::cancellation_token_t& cancel = {})
{
	using namespace aida::analysis;
	auto fail = [](workspace_error_code_t code, std::string message) {
		return workspace_result_t<std::optional<runtime_function_entry_t>>::failure(
			make_workspace_error(code, std::move(message),
				"pe_parser.live_runtime_function"));
	};
	auto stopped = [&]() {
		auto error = make_workspace_error(
			cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
				: workspace_error_code_t::cancelled,
			cancel.deadline_exceeded() ? "Live function lookup deadline expired"
				: "Live function lookup was cancelled",
			"pe_parser.live_runtime_function");
		error.deadline = cancel.deadline_exceeded();
		error.cancellation = !error.deadline;
		return workspace_result_t<std::optional<runtime_function_entry_t>>::failure(
			std::move(error));
	};
	if (cancel.stop_requested()) return stopped();
	if (pid == 0 || pid == GetCurrentProcessId() || module_base == 0)
		return fail(pid == GetCurrentProcessId()
				? workspace_error_code_t::self_target_refused
				: workspace_error_code_t::invalid_argument,
			"Live function lookup target is invalid");
	if (!pe.is_64bit || pe.exception_dir_rva == 0 ||
		pe.exception_dir_size == 0) {
		return workspace_result_t<std::optional<runtime_function_entry_t>>::success(
			std::nullopt);
	}
	constexpr uint64_t kRuntimeFunctionSize = 12;
	constexpr uint64_t kMaxRuntimeFunctions = 1ULL << 22;
	if (pe.exception_dir_size % kRuntimeFunctionSize != 0 ||
		!detail::valid_image_range(pe, pe.exception_dir_rva,
			pe.exception_dir_size)) {
		return fail(workspace_error_code_t::malformed_pe,
			"PE exception directory range is invalid");
	}
	const uint64_t count = pe.exception_dir_size / kRuntimeFunctionSize;
	if (count == 0 || count > kMaxRuntimeFunctions)
		return fail(workspace_error_code_t::limit_exceeded,
			"PE exception directory exceeds the live lookup budget");
	uint64_t module_end = 0;
	if (!detail::checked_add(module_base, pe.size_of_image, module_end) ||
		requested_va < module_base || requested_va >= module_end) {
		return fail(workspace_error_code_t::out_of_range,
			"Requested live function address is outside the module");
	}
	const uint64_t requested_rva = requested_va - module_base;
	uint64_t table_address = 0;
	if (!detail::checked_add(module_base, pe.exception_dir_rva, table_address))
		return fail(workspace_error_code_t::range_overflow,
			"PE exception directory address overflowed");
	detail::scoped_read_pid_t read_scope(pid);
	auto read_entry = [&](uint64_t index)
		-> workspace_result_t<runtime_function_entry_t> {
		if (cancel.stop_requested()) {
			auto error = make_workspace_error(
				cancel.deadline_exceeded()
					? workspace_error_code_t::deadline_exceeded
					: workspace_error_code_t::cancelled,
				cancel.deadline_exceeded()
					? "Live function lookup deadline expired"
					: "Live function lookup was cancelled",
				"pe_parser.live_runtime_function");
			error.deadline = cancel.deadline_exceeded();
			error.cancellation = !error.deadline;
			return workspace_result_t<runtime_function_entry_t>::failure(
				std::move(error));
		}
		if (index >= count || index > UINT64_MAX / kRuntimeFunctionSize)
			return workspace_result_t<runtime_function_entry_t>::failure(
				make_workspace_error(workspace_error_code_t::range_overflow,
					"Runtime-function table index overflowed",
					"pe_parser.live_runtime_function"));
		uint64_t address = 0;
		if (!detail::checked_add(table_address,
			index * kRuntimeFunctionSize, address)) {
			return workspace_result_t<runtime_function_entry_t>::failure(
				make_workspace_error(workspace_error_code_t::range_overflow,
					"Runtime-function entry address overflowed",
					"pe_parser.live_runtime_function"));
		}
		uint32_t fields[3]{};
		if (!detail::read_mem(address, fields, sizeof(fields))) {
			auto error = make_workspace_error(
				workspace_error_code_t::provider_unavailable,
				"Driver-backed runtime-function entry read failed",
				"pe_parser.live_runtime_function");
			error.address = address_t{address_space_id_t::live_virtual,
				address, architecture_id_t::x86_64,
				architecture_mode_t::x86_64};
			error.size = sizeof(fields);
			return workspace_result_t<runtime_function_entry_t>::failure(
				std::move(error));
		}
		runtime_function_entry_t entry{fields[0], fields[1], fields[2]};
		if (entry.begin_rva >= entry.end_rva ||
			entry.end_rva > pe.size_of_image ||
			(entry.unwind_rva != 0 &&
				entry.unwind_rva >= pe.size_of_image)) {
			return workspace_result_t<runtime_function_entry_t>::failure(
				make_workspace_error(workspace_error_code_t::malformed_pe,
					"Runtime-function entry contains an invalid range",
					"pe_parser.live_runtime_function"));
		}
		return workspace_result_t<runtime_function_entry_t>::success(entry);
	};
	uint64_t lower = 0;
	uint64_t upper = count;
	while (lower < upper) {
		const uint64_t middle = lower + (upper - lower) / 2;
		auto entry = read_entry(middle);
		if (!entry)
			return workspace_result_t<std::optional<runtime_function_entry_t>>::failure(
				entry.error());
		if (entry.value().begin_rva <= requested_rva)
			lower = middle + 1;
		else
			upper = middle;
	}
	if (lower == 0)
		return workspace_result_t<std::optional<runtime_function_entry_t>>::success(
			std::nullopt);
	const uint64_t candidate_index = lower - 1;
	auto candidate = read_entry(candidate_index);
	if (!candidate)
		return workspace_result_t<std::optional<runtime_function_entry_t>>::failure(
			candidate.error());
	if (candidate.value().begin_rva > requested_rva ||
		requested_rva >= candidate.value().end_rva) {
		return workspace_result_t<std::optional<runtime_function_entry_t>>::success(
			std::nullopt);
	}
	if (candidate_index != 0) {
		auto previous = read_entry(candidate_index - 1);
		if (!previous)
			return workspace_result_t<std::optional<runtime_function_entry_t>>::failure(
				previous.error());
		if (previous.value().begin_rva > candidate.value().begin_rva)
			return fail(workspace_error_code_t::malformed_pe,
				"PE exception directory is not ordered");
	}
	if (candidate_index + 1 < count) {
		auto next = read_entry(candidate_index + 1);
		if (!next)
			return workspace_result_t<std::optional<runtime_function_entry_t>>::failure(
				next.error());
		if (next.value().begin_rva < candidate.value().begin_rva)
			return fail(workspace_error_code_t::malformed_pe,
				"PE exception directory is not ordered");
	}
	return workspace_result_t<std::optional<runtime_function_entry_t>>::success(
		std::optional<runtime_function_entry_t>(candidate.value()));
}

inline bool parse(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
                  pe_info_t& out,
                  const parse_options_t& options = {})
{
    auto result = parse_workspace(workspace, options);
    if (!result) {
        out = {};
        return false;
    }
    out = result.take_value();
    return true;
}

inline bool parse(uint64_t module_base, pe_info_t& out, const parse_options_t& options)
{
    out = {};
    auto workspace = aida::analysis::workspace_registry().selected_for_ui();
    if (workspace && workspace->target_kind() == aida::analysis::target_kind_t::static_file) {
        const auto image = workspace->image();
        if (image && image->image_base() == module_base) {
            auto result = parse_workspace(workspace, options);
            if (!result) return false;
            out = result.take_value();
            return true;
        }
    }
    uint32_t pid = 0;
    if (workspace && workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot &&
        workspace->identity().process())
        pid = workspace->identity().process()->pid;
    if (pid == 0) pid = driver_bridge::attached_pid();
    return parse_live(pid, module_base, out, options);
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
