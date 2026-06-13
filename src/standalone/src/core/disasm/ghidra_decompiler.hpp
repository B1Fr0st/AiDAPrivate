#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "work_queue.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "standalone_driver.hpp"
#include "embedded_resources.hpp"
#include "helpers/diag_log.hpp"
#include "zydis_disasm.hpp"
#include "../analysis/pe_parser.hpp"

#include "ghidra_adapters/aida_ghidra_preamble.hpp"
#include "ghidra_adapters/aida_architecture.hpp"
#include "ghidra_adapters/aida_load_image.hpp"
#include "ghidra_adapters/aida_function_db.hpp"
#include "ghidra_adapters/aida_arch_map.hpp"
#include "ghidra_adapters/aida_code_xml_parse.hpp"
#include "ghidra_adapters/aida_print_c.hpp"
#include "ghidra_adapters/aida_pcode_fixup.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "libdecomp.hh"
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include "architecture.hh"
#include "action.hh"
#include "funcdata.hh"
#include "printc.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace ghidra_decompiler {

struct ghidra_result_t {
	uint64_t function_addr = 0;
	std::string function_name;
	std::string pseudocode;
	std::vector<aida_ghidra::code_annotation_t> annotations;
	std::vector<std::pair<int, uint64_t>> line_to_address;
	std::vector<std::pair<std::string, uint64_t>> callees;
	std::string sleigh_id;
	bool complete = false;
	bool is_error = false;
	std::string error_text;
	double elapsed_ms = 0.0;
};

struct batch_entry_t {
	uint64_t address = 0;
	ghidra_result_t result;
};

struct preload_diagnostics_t {
	uint64_t base = 0;
	size_t requested_size = 0;
	size_t first_attempt_bytes = 0;
	size_t total_read = 0;
	size_t chunks_ok = 0;
	size_t chunks_failed = 0;
	size_t chunks_skipped = 0;
	size_t query_ok = 0;
	size_t query_failed = 0;
	size_t skipped_uncommitted = 0;
	size_t skipped_guard = 0;
	size_t skipped_noaccess = 0;
	uint32_t pe_signature = 0;
	uint16_t pe_machine = 0;
	uint16_t pe_sections = 0;
	uint16_t pe_optional_magic = 0;
	uint32_t pe_size_of_image = 0;
	bool whole_read_ok = false;
	bool whole_read_zero_padding = false;
	bool chunked_read = false;
	bool zero_padding = false;
	bool mz = false;
	bool pe_header_ok = false;
};

struct state_t {
	std::mutex init_mtx;
	std::atomic<bool> initialized{false};
	std::string specs_dir;
	std::ostringstream err_stream;
	std::atomic<int> active_decompiles{0};
	std::atomic<bool> shutting_down{false};
	std::atomic<uint64_t> last_loadfill_tick_ms{0};
};

inline state_t g_state;

inline bool buffer_is_zero_padding(const std::vector<uint8_t>& bytes)
{
	if (bytes.empty()) return true;
	size_t zero_count = 0;
	size_t longest = 0;
	size_t cur = 0;
	for (uint8_t b : bytes) {
		if (b == 0) {
			++zero_count;
			++cur;
			if (cur > longest) longest = cur;
		} else {
			cur = 0;
		}
	}
	return longest >= 256 || (bytes.size() >= 256 && zero_count * 100 >= bytes.size() * 90);
}

inline bool decompile_protect_executable(uint32_t protect)
{
	switch (protect & 0xFFu) {
	case PAGE_EXECUTE:
	case PAGE_EXECUTE_READ:
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
		return true;
	default:
		return false;
	}
}

inline bool decompile_section_executable(uint32_t characteristics)
{
	return (characteristics & 0x20000000u) != 0 || (characteristics & 0x00000020u) != 0;
}

inline void decompile_zero_window_stats(const std::vector<uint8_t>& bytes,
                                        size_t offset,
                                        size_t size,
                                        size_t& zero_count,
                                        size_t& longest_zero_run)
{
	zero_count = 0;
	longest_zero_run = 0;
	size_t current = 0;
	const size_t end = (std::min)(bytes.size(), offset + size);
	for (size_t i = offset; i < end; ++i) {
		if (bytes[i] == 0) {
			++zero_count;
			++current;
			if (current > longest_zero_run)
				longest_zero_run = current;
		} else {
			current = 0;
		}
	}
}

inline bool profile_pe_image_header(const std::vector<uint8_t>& bytes, preload_diagnostics_t& diag)
{
	diag.mz = bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z';
	diag.pe_header_ok = false;
	diag.pe_signature = 0;
	diag.pe_machine = 0;
	diag.pe_sections = 0;
	diag.pe_optional_magic = 0;
	diag.pe_size_of_image = 0;
	if (bytes.size() < sizeof(IMAGE_DOS_HEADER))
		return false;

	IMAGE_DOS_HEADER dos{};
	std::memcpy(&dos, bytes.data(), sizeof(dos));
	if (dos.e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	if (dos.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)))
		return false;

	const size_t nt_off = static_cast<size_t>(dos.e_lfanew);
	if (nt_off > bytes.size() || bytes.size() - nt_off < sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER))
		return false;

	std::memcpy(&diag.pe_signature, bytes.data() + nt_off, sizeof(diag.pe_signature));
	if (diag.pe_signature != IMAGE_NT_SIGNATURE)
		return false;

	IMAGE_FILE_HEADER file_header{};
	std::memcpy(&file_header, bytes.data() + nt_off + sizeof(uint32_t), sizeof(file_header));
	diag.pe_machine = file_header.Machine;
	diag.pe_sections = file_header.NumberOfSections;

	const size_t optional_off = nt_off + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
	if (optional_off + sizeof(uint16_t) <= bytes.size())
		std::memcpy(&diag.pe_optional_magic, bytes.data() + optional_off, sizeof(diag.pe_optional_magic));

	if (file_header.SizeOfOptionalHeader >= offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage) + sizeof(uint32_t) &&
		optional_off + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage) + sizeof(uint32_t) <= bytes.size()) {
		std::memcpy(&diag.pe_size_of_image,
			bytes.data() + optional_off + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage),
			sizeof(diag.pe_size_of_image));
	}

	diag.pe_header_ok = diag.pe_sections != 0 &&
		(diag.pe_optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
		 diag.pe_optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
	return diag.pe_header_ok;
}

enum class wd_state_t : uint32_t {
	running   = 0,
	completed = 1,
	cancelled = 2
};

struct active_decompile_guard_t {
	bool was_shutting_down = false;
	std::atomic<bool>* cancel_ref = nullptr;
	active_decompile_guard_t(std::atomic<bool>* cancel = nullptr) : cancel_ref(cancel) {
		g_state.active_decompiles.fetch_add(1, std::memory_order_acq_rel);
		if (g_state.shutting_down.load(std::memory_order_acquire)) {
			was_shutting_down = true;
			if (cancel_ref)
				cancel_ref->store(true, std::memory_order_release);
		}
	}
	~active_decompile_guard_t() {
		g_state.active_decompiles.fetch_sub(1, std::memory_order_acq_rel);
	}
	active_decompile_guard_t(const active_decompile_guard_t&) = delete;
	active_decompile_guard_t& operator=(const active_decompile_guard_t&) = delete;
};

inline bool wait_for_active_decompiles(int budget_ms) {
	int elapsed = 0;
	while (g_state.active_decompiles.load(std::memory_order_acquire) > 0) {
		if (elapsed >= budget_ms) return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		elapsed += 10;
	}
	return true;
}

inline void prepare_shutdown() {
	g_state.shutting_down.store(true, std::memory_order_release);
	wait_for_active_decompiles(2000);
}

namespace detail {

inline std::string get_exe_directory() {
	char path[MAX_PATH] = {};
	GetModuleFileNameA(nullptr, path, MAX_PATH);
	std::string full(path);
	auto pos = full.find_last_of("\\/");
	if (pos != std::string::npos)
		return full.substr(0, pos);
	return ".";
}

inline std::string find_specs_dir() {
	std::string exe_dir = get_exe_directory();
	std::string candidate = exe_dir + "\\ghidra_specs";
	DWORD attr = GetFileAttributesA(candidate.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
		return candidate;

	candidate = exe_dir + "\\..\\ghidra_specs";
	attr = GetFileAttributesA(candidate.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
		return candidate;

#ifdef GHIDRA_SPECS_DIR
#define AIDA_GHIDRA_SPECS_STR_IMPL(x) #x
#define AIDA_GHIDRA_SPECS_STR(x) AIDA_GHIDRA_SPECS_STR_IMPL(x)
	std::string cmake_dir = AIDA_GHIDRA_SPECS_STR(GHIDRA_SPECS_DIR);
	#undef AIDA_GHIDRA_SPECS_STR
	#undef AIDA_GHIDRA_SPECS_STR_IMPL
	attr = GetFileAttributesA(cmake_dir.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
		return cmake_dir;
#endif

	return "";
}

inline aida_ghidra::arch_descriptor_t resolve_arch(const DisasmFile* file) {
	if (file && file->loaded)
		return aida_ghidra::detect_arch_from_pe(*file);
	return aida_ghidra::detect_arch_default_x64();
}

inline pe_parser::pe_info_t* try_parse_pe_info(const DisasmFile* file,
                                                pe_parser::pe_info_t& out_storage)
{
	if (!file || !file->loaded || file->image_base == 0)
		return nullptr;

	out_storage = pe_parser::pe_info_t{};
	out_storage.image_base = file->image_base;
	out_storage.entry_point = file->entry_point;

	for (auto& s : file->sections) {
		if (s.bytes.size() < 0x400)
			continue;
		if (s.va > file->image_base)
			continue;
		uint64_t off = file->image_base - s.va;
		if (off + 0x400 > s.bytes.size())
			continue;
		const uint8_t* p = s.bytes.data() + static_cast<size_t>(off);
		if (p[0] != 'M' || p[1] != 'Z')
			continue;
		uint32_t e_lfanew = 0;
		std::memcpy(&e_lfanew, p + 0x3C, 4);
		if (e_lfanew == 0 || e_lfanew + 0x40 > s.bytes.size() - off)
			continue;
		const uint8_t* nt = p + e_lfanew;
		if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0)
			continue;
		uint16_t magic = 0;
		std::memcpy(&magic, nt + 0x18, 2);
		out_storage.is_64bit = (magic == 0x20B);

		const uint8_t* opt = nt + 0x18;
		uint32_t size_of_image = 0;
		uint32_t timestamp = 0;
		std::memcpy(&timestamp, nt + 8, 4);
		uint32_t opt_size_off = out_storage.is_64bit ? 0x38 : 0x38;
		(void)opt_size_off;
		std::memcpy(&size_of_image, opt + 0x38, 4);
		out_storage.size_of_image = size_of_image;
		out_storage.timestamp = timestamp;

		uint32_t data_dir_off = out_storage.is_64bit ? 0x70 : 0x60;
		const uint8_t* dir = opt + data_dir_off;
		std::memcpy(&out_storage.export_dir_rva, dir + 0 * 8, 4);
		std::memcpy(&out_storage.export_dir_size, dir + 0 * 8 + 4, 4);
		std::memcpy(&out_storage.import_dir_rva, dir + 1 * 8, 4);
		std::memcpy(&out_storage.import_dir_size, dir + 1 * 8 + 4, 4);

		uint16_t num_sections = 0;
		std::memcpy(&num_sections, nt + 6, 2);
		uint16_t opt_size = 0;
		std::memcpy(&opt_size, nt + 0x14, 2);
		const uint8_t* section_table = nt + 0x18 + opt_size;

		size_t section_size_avail = s.bytes.size() - off - (section_table - p);
		size_t can_read = section_size_avail / 40;
		if (num_sections > can_read)
			num_sections = static_cast<uint16_t>(can_read);

		for (uint16_t i = 0; i < num_sections; ++i) {
			const uint8_t* sec = section_table + static_cast<size_t>(i) * 40;
			pe_parser::section_info_t si;
			char name[9] = {};
			std::memcpy(name, sec, 8);
			si.name = name;
			std::memcpy(&si.virtual_size, sec + 8, 4);
			std::memcpy(&si.virtual_address, sec + 12, 4);
			std::memcpy(&si.raw_size, sec + 16, 4);
			std::memcpy(&si.characteristics, sec + 36, 4);
			out_storage.sections.push_back(si);
		}

		break;
	}

	return &out_storage;
}

static constexpr int WATCHDOG_TIMEOUT_MS = 10000;

inline std::vector<std::pair<std::string, uint64_t>>
collect_callees(ghidra::Funcdata* fd)
{
	std::vector<std::pair<std::string, uint64_t>> out;
	if (!fd)
		return out;
	int n = fd->numCalls();
	for (int i = 0; i < n; ++i) {
		ghidra::FuncCallSpecs* spec = fd->getCallSpecs(i);
		if (!spec)
			continue;
		std::string name = spec->getName();
		uint64_t addr = spec->getEntryAddress().getOffset();
		if (name.empty())
			continue;
		out.emplace_back(std::move(name), addr);
	}
	std::sort(out.begin(), out.end());
	out.erase(std::unique(out.begin(), out.end()), out.end());
	return out;
}

inline ghidra_result_t do_decompile(aida_ghidra::architecture_t* arch,
                                    uint64_t entry_addr,
                                    std::atomic<bool>* cancel = nullptr)
{
	ghidra_result_t result;
	result.function_addr = entry_addr;

	auto start_time = std::chrono::high_resolution_clock::now();

	ghidra::AddrSpace* code_space = arch->translate->getDefaultCodeSpace();
	if (!code_space) {
		result.is_error = true;
		result.error_text = "no default code space available";
		return result;
	}

	ghidra::Address addr(code_space, entry_addr);

	const aida_ghidra::function_db_t& db = arch->symbol_database();
	const aida_ghidra::symbol_record_t* known = db.find_by_address(entry_addr);

	std::string func_name;
	bool known_is_callable = known &&
		(known->kind == aida_ghidra::symbol_kind_t::function ||
		 known->kind == aida_ghidra::symbol_kind_t::export_);
	if (known_is_callable && !known->name.empty() && known->name.size() <= 1024) {
		func_name = known->name;
	} else {
		char name_buf[64];
		std::snprintf(name_buf, sizeof(name_buf), "sub_%llx",
		              static_cast<unsigned long long>(entry_addr));
		func_name = name_buf;
	}

	ghidra::Scope* global_scope = arch->symboltab->getGlobalScope();

	ghidra::Funcdata* fd = global_scope->queryFunction(addr);
	if (fd) {
		if (fd->isProcStarted())
			arch->clearAnalysis(fd);
	} else {
		ghidra::FunctionSymbol* sym = global_scope->addFunction(addr, func_name);
		fd = sym ? sym->getFunction() : nullptr;
	}

	if (!fd) {
		result.is_error = true;
		result.error_text = "failed to materialize function symbol";
		return result;
	}

	if (fd->hasNoCode()) {
		result.is_error = true;
		result.error_text = "no code at the specified address";
		return result;
	}

	arch->allacts.getCurrent()->reset(*fd);

	diag::log_tagged_critical_fmt("dec",
		"do_decompile_enter addr=0x%llx tid=%lu",
		static_cast<unsigned long long>(entry_addr),
		static_cast<unsigned long>(GetCurrentThreadId()));

	auto wd_state = std::make_shared<std::atomic<uint32_t>>(
		static_cast<uint32_t>(wd_state_t::running));
	auto watchdog_fired_elapsed_ms = std::make_shared<std::atomic<long long>>(0);

	auto wd_start = std::chrono::steady_clock::now();
	auto deadline = wd_start + std::chrono::milliseconds(WATCHDOG_TIMEOUT_MS);

	std::atomic<bool>* cancel_for_wd = cancel;
	uint64_t wd_addr = entry_addr;
	work_queue::post([wd_state, watchdog_fired_elapsed_ms,
	                  cancel_for_wd, deadline, wd_start, wd_addr]() {
		while (true) {
			uint32_t cur = wd_state->load(std::memory_order_acquire);
			if (cur != static_cast<uint32_t>(wd_state_t::running))
				return;
			auto now = std::chrono::steady_clock::now();
			if (now >= deadline) {
				uint32_t expected = static_cast<uint32_t>(wd_state_t::running);
				if (!wd_state->compare_exchange_strong(expected,
				    static_cast<uint32_t>(wd_state_t::cancelled),
				    std::memory_order_acq_rel, std::memory_order_acquire)) {
					return;
				}
				long long fired_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					now - wd_start).count();
				watchdog_fired_elapsed_ms->store(fired_ms, std::memory_order_release);
				if (cancel_for_wd)
					cancel_for_wd->store(true, std::memory_order_release);
				diag::log_tagged_critical_fmt("dec",
					"do_decompile_watchdog_fired addr=0x%llx elapsed_ms=%lld",
					static_cast<unsigned long long>(wd_addr),
					fired_ms);
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
	});

	auto perform_start = std::chrono::steady_clock::now();

	ghidra::int4 perform_res = -1;
	bool perform_threw = false;
	std::string perform_err_text;

	try {
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		if (aida_ghidra::is_x86_family(arch->getTarget())) {
			aida_ghidra::pcode_fixup_preprocessor_t::fixup_shared_return_jump_to_imports(fd, *arch);
		}
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		perform_res = arch->allacts.getCurrent()->perform(*fd);
	}
	catch (ghidra::LowlevelError& e) {
		perform_threw = true;
		perform_err_text = e.explain;
		perform_res = -1;
	}
	catch (ghidra::DecoderError& e) {
		perform_threw = true;
		perform_err_text = e.explain;
		perform_res = -1;
	}
	catch (std::exception& e) {
		perform_threw = true;
		perform_err_text = e.what();
		perform_res = -1;
	}
	catch (...) {
		perform_threw = true;
		perform_err_text = "unknown exception in perform";
		perform_res = -1;
	}

	auto perform_end = std::chrono::steady_clock::now();
	long long perform_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		perform_end - perform_start).count();

	uint32_t expected_running = static_cast<uint32_t>(wd_state_t::running);
	bool we_completed_first = wd_state->compare_exchange_strong(expected_running,
		static_cast<uint32_t>(wd_state_t::completed),
		std::memory_order_acq_rel, std::memory_order_acquire);
	bool fired = !we_completed_first &&
		(static_cast<wd_state_t>(wd_state->load(std::memory_order_acquire)) == wd_state_t::cancelled);
	bool external_cancel = (cancel && cancel->load(std::memory_order_acquire));

	if (fired) {
		result.is_error = true;
		result.error_text = "Decompilation timed out (function too complex or invalid code).";
		auto end_time = std::chrono::high_resolution_clock::now();
		result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
		diag::log_tagged_critical_fmt("dec",
			"do_decompile_exit addr=0x%llx outcome=timeout fired_at_ms=%lld total_ms=%.2f",
			static_cast<unsigned long long>(entry_addr),
			watchdog_fired_elapsed_ms->load(std::memory_order_acquire),
			result.elapsed_ms);
		return result;
	}

	if (external_cancel) {
		result.is_error = true;
		result.error_text = "Decompilation cancelled.";
		auto end_time = std::chrono::high_resolution_clock::now();
		result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
		return result;
	}

	if (perform_threw) {
		result.is_error = true;
		result.error_text = perform_err_text.empty()
			? std::string("Cannot decompile this function (the address may not contain a valid function).")
			: perform_err_text;
		auto end_time = std::chrono::high_resolution_clock::now();
		result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
		return result;
	}

	(void)perform_res;
	(void)perform_ms;

	std::ostringstream xml_oss;
	bool produced_markup = false;
	try {
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		arch->setPrintLanguage("aida-c-language");
		arch->print->setOutputStream(&xml_oss);
		arch->print->setMarkup(true);
		arch->print->docFunction(fd);
		produced_markup = true;
	}
	catch (...) {
		produced_markup = false;
	}

	if (produced_markup) {
		std::string xml = xml_oss.str();
		aida_ghidra::annotated_code_t parsed;
		if (aida_ghidra::parse_code_xml(fd, xml, parsed) && !parsed.code.empty()) {
			result.pseudocode = std::move(parsed.code);
			result.annotations = std::move(parsed.annotations);
			result.line_to_address = std::move(parsed.line_to_address);
		}
	}

	if (result.pseudocode.empty()) {
		std::ostringstream plain_oss;
		try {
			if (cancel && cancel->load(std::memory_order_acquire))
				throw ghidra::LowlevelError("cancelled");
			arch->print->setMarkup(false);
			arch->print->setOutputStream(&plain_oss);
			arch->print->docFunction(fd);
			result.pseudocode = plain_oss.str();
		}
		catch (ghidra::LowlevelError& e) {
			result.is_error = true;
			result.error_text = std::string("emit failed: ") + e.explain;
			auto end_time = std::chrono::high_resolution_clock::now();
			result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
			return result;
		}
		catch (...) {
			result.is_error = true;
			result.error_text = "emit failed (unknown)";
			auto end_time = std::chrono::high_resolution_clock::now();
			result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
			return result;
		}
	}

	result.function_name = fd->getName();
	result.callees = collect_callees(fd);
	result.sleigh_id = arch->getTarget();
	result.complete = true;

	auto end_time = std::chrono::high_resolution_clock::now();
	result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

	diag::log_tagged_critical_fmt("dec",
		"do_decompile_exit addr=0x%llx outcome=ok total_ms=%.2f pseudocode_bytes=%zu annot=%zu",
		static_cast<unsigned long long>(entry_addr),
		result.elapsed_ms,
		result.pseudocode.size(),
		result.annotations.size());

	return result;
}

struct prepared_arch_t {
	std::unique_ptr<aida_ghidra::architecture_t> arch;
	std::ostringstream err;

	prepared_arch_t(const uint8_t* data,
	                size_t size,
	                uint64_t base,
	                const DisasmFile* file_fallback,
	                std::atomic<bool>* cancel,
	                const std::string& sleigh_id,
	                std::vector<aida_ghidra::region_t> extra_regions = {})
	{
		auto loader = std::make_unique<aida_ghidra::load_image_t>(
			data, size, base, file_fallback, cancel);
		for (auto& reg : extra_regions) {
			loader->add_region(reg.start_va, std::move(reg.data));
		}
		arch = std::make_unique<aida_ghidra::architecture_t>(sleigh_id, &err);
		arch->take_loader(std::move(loader));

		ghidra::DocumentStorage store;
		arch->init(store);
	}

	prepared_arch_t(const prepared_arch_t&) = delete;
	prepared_arch_t& operator=(const prepared_arch_t&) = delete;
};

__declspec(noinline) inline DWORD seh_apply_pdb_types(aida_ghidra::architecture_t* arch)
{
	__try {
		arch->apply_pdb_types();
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

__declspec(noinline) inline DWORD seh_apply_pdb_function_prototypes(aida_ghidra::architecture_t* arch)
{
	__try {
		arch->apply_pdb_function_prototypes();
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

inline void populate_symbols(aida_ghidra::architecture_t& arch,
                             const uint8_t* data,
                             size_t size,
                             uint64_t base,
                             const DisasmFile* file)
{
	auto& db = arch.symbol_database();
	if (file && file->loaded) {
		pe_parser::pe_info_t storage;
		auto pe = try_parse_pe_info(file, storage);
		aida_ghidra::populate_from_pe(db, *file, pe);
	} else {
		db.clear();
		db.image_base = base;
		db.image_size = size;
		db.is_pe = false;
	}
	aida_ghidra::populate_from_driver(db, base);
	aida_ghidra::populate_from_symbol_store(db);
	aida_ghidra::populate_default_noreturn(db);

	diag::log_tagged_critical("dec_pdb", "populate_symbols_pre_apply_pdb_types");
	DWORD seh_types = seh_apply_pdb_types(&arch);
	if (seh_types != 0) {
		std::string last_name = aida_ghidra::architecture_t::current_apply_pdb_name();
		const char* last_stage = aida_ghidra::architecture_t::current_apply_pdb_stage();
		diag::log_tagged_critical_fmt("dec_pdb",
			"populate_symbols_apply_pdb_types_seh_fault code=0x%08X last_stage=%s last_name=%s",
			seh_types,
			last_stage ? last_stage : "<null>",
			last_name.c_str());
	}

	diag::log_tagged_critical("dec_pdb", "populate_symbols_pre_apply_pdb_function_prototypes");
	DWORD seh_protos = seh_apply_pdb_function_prototypes(&arch);
	if (seh_protos != 0) {
		std::string last_name = aida_ghidra::architecture_t::current_apply_pdb_name();
		const char* last_stage = aida_ghidra::architecture_t::current_apply_pdb_stage();
		diag::log_tagged_critical_fmt("dec_pdb",
			"populate_symbols_apply_pdb_function_prototypes_seh_fault code=0x%08X last_stage=%s last_name=%s",
			seh_protos,
			last_stage ? last_stage : "<null>",
			last_name.c_str());
	}
	diag::log_tagged_critical("dec_pdb", "populate_symbols_exit");
}

}

inline bool init(const std::string& specs_dir = "") {
	diag::log_tagged_critical_fmt("dec", "ghidra_init_enter specs_dir_param=%s",
		specs_dir.empty() ? "<empty>" : specs_dir.c_str());
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	if (g_state.initialized.load()) {
		diag::log_tagged_critical("dec", "ghidra_init_exit reason=already_initialized");
		return true;
	}

	std::string dir = specs_dir;
	if (dir.empty())
		dir = detail::find_specs_dir();
	diag::log_tagged_critical_fmt("dec", "ghidra_init_find_specs_dir result=%s",
		dir.empty() ? "<empty>" : dir.c_str());

	if (dir.empty()) {
		diag::log_tagged_critical("dec", "ghidra_init_pre_extract_specs");
		dir = embedded_resources::extract_ghidra_specs();
		diag::log_tagged_critical_fmt("dec", "ghidra_init_post_extract_specs result=%s",
			dir.empty() ? "<empty>" : dir.c_str());
		if (!dir.empty()) {
			static std::string s_temp_specs_dir;
			s_temp_specs_dir = dir;
			std::atexit([]() {
				embedded_resources::delete_specs_dir(s_temp_specs_dir);
			});
		}
	}

	if (dir.empty()) {
		diag::log_tagged_critical("dec", "ghidra_init_exit reason=no_specs_dir");
		return false;
	}

	try {
		g_state.specs_dir = dir;
		std::vector<std::string> paths;
		paths.push_back(dir);
		diag::log_tagged_critical_fmt("dec", "ghidra_init_pre_startDecompilerLibrary dir=%s", dir.c_str());
		ghidra::startDecompilerLibrary(paths);
		diag::log_tagged_critical("dec", "ghidra_init_post_startDecompilerLibrary");
		g_state.initialized.store(true);
		diag::log_tagged_critical("dec", "ghidra_init_exit reason=ok");
		return true;
	}
	catch (ghidra::LowlevelError& err) {
		g_state.err_stream << "ghidra init error: " << err.explain << "\n";
		diag::log_tagged_critical_fmt("dec", "ghidra_init_exit reason=lowlevel_error err=%s", err.explain.c_str());
		return false;
	}
	catch (ghidra::DecoderError& err) {
		g_state.err_stream << "ghidra decoder error: " << err.explain << "\n";
		diag::log_tagged_critical_fmt("dec", "ghidra_init_exit reason=decoder_error err=%s", err.explain.c_str());
		return false;
	}
	catch (...) {
		g_state.err_stream << "ghidra init: unknown error\n";
		diag::log_tagged_critical("dec", "ghidra_init_exit reason=unknown_exception");
		return false;
	}
}

inline ghidra_result_t decompile_function(uint64_t entry_addr,
                                          std::atomic<bool>* cancel = nullptr)
{
	active_decompile_guard_t active_guard(cancel);
	ghidra_result_t result;
	result.function_addr = entry_addr;

	if (active_guard.was_shutting_down) {
		result.is_error = true;
		result.error_text = "decompiler is shutting down";
		return result;
	}

	if (!g_state.initialized.load()) {
		if (!init()) {
			result.is_error = true;
			result.error_text = "ghidra decompiler not initialized: " + g_state.err_stream.str();
			return result;
		}
	}

	const uint32_t attached_pid = driver_bridge::attached_pid();
	auto modules = driver_bridge::enumerate_modules();
	driver_bridge::module_info_t selected_module{};
	bool module_found = false;
	for (const auto& m : modules) {
		const uint64_t end = m.base + static_cast<uint64_t>(m.size);
		if (end <= m.base)
			continue;
		if (entry_addr >= m.base && entry_addr < end) {
			if (!module_found || m.size < selected_module.size) {
				selected_module = m;
				module_found = true;
			}
		}
	}

	pe_parser::pe_info_t pe;
	bool pe_ok = false;
	pe_parser::section_info_t selected_section{};
	bool section_found = false;
	bool section_executable = false;
	uint64_t module_base = module_found ? selected_module.base : 0;
	uint64_t module_size = module_found ? selected_module.size : 0;
	uint64_t section_start = 0;
	uint64_t section_end = 0;
	if (module_found) {
		pe_ok = pe_parser::parse(selected_module.base, pe, false);
		if (pe_ok) {
			const uint64_t rva = entry_addr >= selected_module.base ? entry_addr - selected_module.base : 0;
			for (const auto& s : pe.sections) {
				const uint64_t size = (std::max)(static_cast<uint64_t>(s.virtual_size), static_cast<uint64_t>(s.raw_size));
				if (size == 0)
					continue;
				const uint64_t start = static_cast<uint64_t>(s.virtual_address);
				const uint64_t end = start + size;
				if (end <= start)
					continue;
				if (rva >= start && rva < end) {
					selected_section = s;
					section_found = true;
					section_executable = decompile_section_executable(s.characteristics);
					section_start = selected_module.base + start;
					section_end = selected_module.base + end;
					const uint64_t module_end = selected_module.base + static_cast<uint64_t>(selected_module.size);
					if (module_end > selected_module.base && section_end > module_end)
						section_end = module_end;
					break;
				}
			}
		}
	}

	driver_bridge::memory_region_t region{};
	const bool region_ok = driver_bridge::query_memory(entry_addr, region);
	const bool region_executable = region_ok && decompile_protect_executable(region.protect);
	const bool region_committed = region_ok && region.state == MEM_COMMIT;
	if (!section_found && region_ok) {
		module_base = module_found ? selected_module.base : region.base;
		module_size = module_found ? selected_module.size : region.size;
		section_start = region.base;
		section_end = region.base + region.size;
		section_found = true;
		section_executable = region_executable;
	}

	diag::log_tagged_fmt("ghidra",
		"decompile_function_resolve addr=0x%llX pid=%u module_found=%d module=%s module_base=0x%llX module_size=0x%llX pe_ok=%d section_found=%d section=%s section_start=0x%llX section_end=0x%llX section_exec=%d region_ok=%d region_base=0x%llX region_size=0x%llX region_state=0x%08X region_protect=0x%08X region_type=0x%08X region_exec=%d",
		static_cast<unsigned long long>(entry_addr),
		static_cast<unsigned>(attached_pid),
		module_found ? 1 : 0,
		module_found ? selected_module.name.c_str() : "<none>",
		static_cast<unsigned long long>(module_base),
		static_cast<unsigned long long>(module_size),
		pe_ok ? 1 : 0,
		section_found ? 1 : 0,
		section_found ? selected_section.name.c_str() : "<none>",
		static_cast<unsigned long long>(section_start),
		static_cast<unsigned long long>(section_end),
		section_executable ? 1 : 0,
		region_ok ? 1 : 0,
		static_cast<unsigned long long>(region.base),
		static_cast<unsigned long long>(region.size),
		static_cast<unsigned>(region.state),
		static_cast<unsigned>(region.protect),
		static_cast<unsigned>(region.type),
		region_executable ? 1 : 0);

	if (!section_found || section_end <= section_start || entry_addr < section_start || entry_addr >= section_end) {
		result.is_error = true;
		result.error_text = "failed to resolve an executable module section for the target address";
		return result;
	}
	if (!section_executable) {
		result.is_error = true;
		result.error_text = "target address is not inside an executable section";
		return result;
	}
	if (region_ok) {
		if (!region_committed || (region.protect & PAGE_GUARD) != 0 || (region.protect & PAGE_NOACCESS) != 0) {
			result.is_error = true;
			result.error_text = "target address is not in readable committed executable memory";
			return result;
		}
		const uint64_t region_end = region.base + region.size;
		if (region.base <= entry_addr && region_end > entry_addr) {
			if (section_start < region.base)
				section_start = region.base;
			if (section_end > region_end)
				section_end = region_end;
		}
	}

	constexpr size_t MAX_DECOMPILE_READ = 0x20000;
	uint64_t read_base = section_start;
	if (entry_addr - read_base >= MAX_DECOMPILE_READ) {
		read_base = entry_addr & ~0xFFFULL;
		if (read_base < section_start)
			read_base = section_start;
	}
	uint64_t read_end = section_end;
	if (read_end - read_base > MAX_DECOMPILE_READ)
		read_end = read_base + MAX_DECOMPILE_READ;
	if (entry_addr >= read_end) {
		read_base = entry_addr & ~0xFFFULL;
		if (read_base < section_start)
			read_base = section_start;
		read_end = (std::min)(section_end, read_base + static_cast<uint64_t>(MAX_DECOMPILE_READ));
	}
	const size_t read_size = read_end > read_base ? static_cast<size_t>(read_end - read_base) : 0;
	if (read_size == 0 || entry_addr < read_base || entry_addr >= read_end) {
		result.is_error = true;
		result.error_text = "resolved executable read window does not contain the target address";
		return result;
	}

	std::vector<uint8_t> mem;
	SetLastError(ERROR_SUCCESS);
	const bool read_ok = driver_bridge::read_memory(read_base, read_size, mem);
	const DWORD read_gle = read_ok ? ERROR_SUCCESS : GetLastError();
	if (mem.size() > read_size)
		mem.resize(read_size);
	const size_t entry_offset = entry_addr >= read_base ? static_cast<size_t>(entry_addr - read_base) : mem.size();
	const size_t entry_window = entry_offset < mem.size() ? (std::min)(static_cast<size_t>(256), mem.size() - entry_offset) : 0;
	size_t entry_zero_count = 0;
	size_t entry_longest_zero_run = 0;
	decompile_zero_window_stats(mem, entry_offset, entry_window, entry_zero_count, entry_longest_zero_run);
	const bool entry_window_zero = entry_window == 0 || entry_zero_count == entry_window;
	diag::log_tagged_fmt("ghidra",
		"decompile_function_read addr=0x%llX read_base=0x%llX read_size=%zu read_ok=%d bytes=%zu gle=%lu entry_offset=%zu entry_window=%zu entry_zero=%zu entry_nonzero=%zu entry_longest_zero=%zu module_base=0x%llX module_size=0x%llX section_start=0x%llX section_end=0x%llX region_state=0x%08X region_protect=0x%08X",
		static_cast<unsigned long long>(entry_addr),
		static_cast<unsigned long long>(read_base),
		read_size,
		read_ok ? 1 : 0,
		mem.size(),
		static_cast<unsigned long>(read_gle),
		entry_offset,
		entry_window,
		entry_zero_count,
		entry_window >= entry_zero_count ? entry_window - entry_zero_count : 0,
		entry_longest_zero_run,
		static_cast<unsigned long long>(module_base),
		static_cast<unsigned long long>(module_size),
		static_cast<unsigned long long>(section_start),
		static_cast<unsigned long long>(section_end),
		static_cast<unsigned>(region.state),
		static_cast<unsigned>(region.protect));

	if (!read_ok || mem.empty() || entry_offset >= mem.size()) {
		result.is_error = true;
		result.error_text = "failed to read executable bytes at target address";
		return result;
	}
	if (entry_window_zero) {
		result.is_error = true;
		result.error_text = "selected address resolves to zero-filled entry bytes, not executable function bytes";
		return result;
	}

	DisasmFile context;
	context.path = module_found ? selected_module.path : std::string("live://memory_region");
	context.filename = module_found ? selected_module.name : std::string("memory_region");
	context.image_base = module_base;
	context.entry_point = pe_ok ? pe.entry_point : 0;
	context.text_va = read_base;
	context.loaded = true;
	PESection ps;
	ps.va = read_base;
	ps.bytes = mem;
	ps.is_executable = true;
	context.sections.push_back(std::move(ps));

	auto arch_desc = aida_ghidra::detect_arch_default_x64();

	try {
		detail::prepared_arch_t ta(mem.data(), mem.size(), read_base,
		                           &context, cancel,
		                           arch_desc.sleigh_id);
		detail::populate_symbols(*ta.arch, mem.data(), mem.size(), read_base, &context);
		result = detail::do_decompile(ta.arch.get(), entry_addr, cancel);
	}
	catch (ghidra::LowlevelError& err) {
		result.is_error = true;
		result.error_text = err.explain;
	}
	catch (ghidra::DecoderError& err) {
		result.is_error = true;
		result.error_text = err.explain;
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error";
	}

	return result;
}

inline ghidra_result_t decompile_buffer(const uint8_t* data, size_t size,
                                         uint64_t base_addr, uint64_t entry_addr,
                                         std::atomic<bool>* cancel = nullptr,
                                         const DisasmFile* file_fallback = nullptr)
{
	active_decompile_guard_t active_guard(cancel);
	ghidra_result_t result;
	result.function_addr = entry_addr;

	if (active_guard.was_shutting_down) {
		result.is_error = true;
		result.error_text = "decompiler is shutting down";
		return result;
	}

	if (!g_state.initialized.load()) {
		if (!init()) {
			result.is_error = true;
			result.error_text = "ghidra decompiler not initialized";
			return result;
		}
	}

	if (cancel && cancel->load(std::memory_order_acquire)) {
		result.is_error = true;
		result.error_text = "cancelled";
		return result;
	}

	auto arch_desc = file_fallback
		? detail::resolve_arch(file_fallback)
		: aida_ghidra::detect_arch_default_x64();

	try {
		detail::prepared_arch_t ta(data, size, base_addr,
		                           file_fallback, cancel,
		                           arch_desc.sleigh_id);
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		detail::populate_symbols(*ta.arch, data, size, base_addr, file_fallback);
		if (cancel && cancel->load(std::memory_order_acquire))
			throw ghidra::LowlevelError("cancelled");
		result = detail::do_decompile(ta.arch.get(), entry_addr, cancel);
	}
	catch (ghidra::LowlevelError& e) {
		result.is_error = true;
		result.error_text = e.explain;
	}
	catch (ghidra::DecoderError& e) {
		result.is_error = true;
		result.error_text = e.explain;
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error (buffer mode)";
	}

	return result;
}

inline bool preload_module(uint64_t base, size_t size, std::vector<uint8_t>& out, preload_diagnostics_t* diagnostics = nullptr) {
	preload_diagnostics_t local_diag{};
	preload_diagnostics_t& profile = diagnostics ? *diagnostics : local_diag;
	profile = {};
	profile.base = base;
	profile.requested_size = size;
	out.clear();
	if (size == 0 || size > 0x10000000) {
		diag::log_tagged_fmt("ghidra", "preload_module_reject base=0x%llX size=%zu reason=invalid_size",
			static_cast<unsigned long long>(base), size);
		return false;
	}
	profile.whole_read_ok = driver_bridge::read_memory(base, size, out);
	profile.first_attempt_bytes = out.size();
	if (profile.whole_read_ok && !out.empty()) {
		profile.whole_read_zero_padding = buffer_is_zero_padding(out);
		profile.total_read = out.size();
		const bool pe_ok = profile_pe_image_header(out, profile);
		if (!profile.whole_read_zero_padding || pe_ok) {
			diag::log_tagged_fmt("ghidra",
				"preload_module_whole_ok base=0x%llX requested=%zu bytes=%zu zero=%d mz=%d pe=%d sections=%u image_size=%u",
				static_cast<unsigned long long>(base),
				size,
				out.size(),
				profile.whole_read_zero_padding ? 1 : 0,
				profile.mz ? 1 : 0,
				pe_ok ? 1 : 0,
				static_cast<unsigned>(profile.pe_sections),
				static_cast<unsigned>(profile.pe_size_of_image));
			return true;
		}
	}

	out.assign(size, 0);
	profile.chunked_read = true;
	profile.total_read = 0;
	const uint64_t end = base + static_cast<uint64_t>(size);

	for (size_t offset = 0; offset < size;) {
		const uint64_t addr = base + static_cast<uint64_t>(offset);
		size_t chunk = (std::min)(static_cast<size_t>(0x10000), size - offset);

		driver_bridge::memory_region_t region{};
		if (driver_bridge::query_memory(addr, region)) {
			++profile.query_ok;
			const uint64_t region_end = region.base + region.size;
			if (region.base <= addr && region_end > addr) {
				const uint64_t clipped_end = (std::min)(region_end, end);
				chunk = static_cast<size_t>((std::min<uint64_t>)(clipped_end - addr, static_cast<uint64_t>(chunk)));
				if (chunk == 0)
					chunk = (std::min)(static_cast<size_t>(0x1000), size - offset);
			}
			const bool committed = region.state == MEM_COMMIT;
			const bool guarded = (region.protect & PAGE_GUARD) != 0;
			const bool noaccess = (region.protect & PAGE_NOACCESS) != 0;
			if (!committed || guarded || noaccess) {
				++profile.chunks_skipped;
				if (!committed)
					++profile.skipped_uncommitted;
				if (guarded)
					++profile.skipped_guard;
				if (noaccess)
					++profile.skipped_noaccess;
				offset += chunk;
				continue;
			}
		} else {
			++profile.query_failed;
		}

		std::vector<uint8_t> chunk_data;
		if (driver_bridge::read_memory(addr, chunk, chunk_data) && !chunk_data.empty()) {
			const size_t copied = (std::min)(chunk_data.size(), size - offset);
			std::memcpy(out.data() + offset, chunk_data.data(), copied);
			profile.total_read += copied;
			++profile.chunks_ok;
		} else {
			++profile.chunks_failed;
		}
		offset += chunk;
	}

	profile.zero_padding = buffer_is_zero_padding(out);
	const bool pe_ok = profile_pe_image_header(out, profile);
	const bool accept = profile.total_read != 0 && (!profile.zero_padding || pe_ok);
	diag::log_tagged_fmt("ghidra",
		"preload_module_chunked base=0x%llX size=%zu first_attempt_bytes=%zu total_read=%zu chunks_ok=%zu chunks_failed=%zu chunks_skipped=%zu query_ok=%zu query_failed=%zu skipped_uncommitted=%zu skipped_guard=%zu skipped_noaccess=%zu zero=%d mz=%d pe=%d sections=%u image_size=%u accept=%d",
		static_cast<unsigned long long>(base),
		size,
		profile.first_attempt_bytes,
		profile.total_read,
		profile.chunks_ok,
		profile.chunks_failed,
		profile.chunks_skipped,
		profile.query_ok,
		profile.query_failed,
		profile.skipped_uncommitted,
		profile.skipped_guard,
		profile.skipped_noaccess,
		profile.zero_padding ? 1 : 0,
		profile.mz ? 1 : 0,
		pe_ok ? 1 : 0,
		static_cast<unsigned>(profile.pe_sections),
		static_cast<unsigned>(profile.pe_size_of_image),
		accept ? 1 : 0);

	if (!accept) {
		out.clear();
		return false;
	}
	return true;
}

inline void batch_decompile(const uint8_t* buffer, size_t buf_size, uint64_t base,
                            const std::vector<uint64_t>& entries,
                            std::vector<ghidra_result_t>& results,
                            std::atomic<int>* progress = nullptr,
                            std::atomic<bool>* cancel = nullptr,
                            const DisasmFile* file_fallback = nullptr)
{
	const uint64_t batch_start_ms = GetTickCount64();
	diag::log_tagged_fmt("ghidra",
		"batch_decompile_enter base=0x%llX buf_size=%zu entries=%zu progress_ptr=%p cancel_ptr=%p initialized=%d",
		static_cast<unsigned long long>(base),
		buf_size,
		entries.size(),
		static_cast<void*>(progress),
		static_cast<void*>(cancel),
		g_state.initialized.load() ? 1 : 0);
	results.clear();
	results.resize(entries.size());

	if (entries.empty()) {
		diag::log_tagged_fmt("ghidra",
			"batch_decompile_exit reason=empty elapsed_ms=%llu",
			static_cast<unsigned long long>(GetTickCount64() - batch_start_ms));
		return;
	}

	if (!g_state.initialized.load()) {
		if (!init()) {
			for (auto& r : results) {
				r.is_error = true;
				r.error_text = "ghidra decompiler not initialized";
			}
			diag::log_tagged_fmt("ghidra",
				"batch_decompile_exit reason=init_failed entries=%zu elapsed_ms=%llu",
				entries.size(),
				static_cast<unsigned long long>(GetTickCount64() - batch_start_ms));
			return;
		}
	}

	unsigned int num_threads = std::thread::hardware_concurrency();
	if (num_threads == 0)
		num_threads = 4;
	if (num_threads > static_cast<unsigned int>(entries.size()))
		num_threads = static_cast<unsigned int>(entries.size());

	std::vector<std::vector<size_t>> partitions(num_threads);
	for (size_t i = 0; i < entries.size(); ++i)
		partitions[i % num_threads].push_back(i);

	auto arch_desc = file_fallback
		? detail::resolve_arch(file_fallback)
		: aida_ghidra::detect_arch_default_x64();

	std::atomic<unsigned int> workers_remaining{num_threads};
	diag::log_tagged_fmt("ghidra",
		"batch_decompile_workers base=0x%llX entries=%zu workers=%u sleigh=%s",
		static_cast<unsigned long long>(base),
		entries.size(),
		num_threads,
		arch_desc.sleigh_id.c_str());

	for (unsigned int t = 0; t < num_threads; ++t) {
		if (!work_queue::post([&, t]() {
			const uint64_t worker_start_ms = GetTickCount64();
			auto& my_indices = partitions[t];
			auto finish_worker = [&](const char* reason) {
				const unsigned int before = workers_remaining.fetch_sub(1, std::memory_order_acq_rel);
				diag::log_tagged_fmt("ghidra",
					"batch_worker_exit worker=%u reason=%s assigned=%zu remaining_before=%u remaining_after=%u progress=%d cancel=%d elapsed_ms=%llu",
					t,
					reason,
					my_indices.size(),
					before,
					before == 0 ? 0 : before - 1,
					progress ? progress->load(std::memory_order_relaxed) : -1,
					(cancel && cancel->load(std::memory_order_acquire)) ? 1 : 0,
					static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
			};
			diag::log_tagged_fmt("ghidra",
				"batch_worker_enter worker=%u assigned=%zu tid=%lu",
				t,
				my_indices.size(),
				GetCurrentThreadId());
			if (my_indices.empty()) {
				finish_worker("empty");
				return;
			}

			std::unique_ptr<detail::prepared_arch_t> ta;
			try {
				ta = std::make_unique<detail::prepared_arch_t>(
					buffer, buf_size, base, file_fallback, cancel,
					arch_desc.sleigh_id);
				detail::populate_symbols(*ta->arch, buffer, buf_size, base, file_fallback);
			}
			catch (...) {
				diag::log_tagged_fmt("ghidra",
					"batch_worker_arch_failed worker=%u assigned=%zu",
					t,
					my_indices.size());
				for (size_t idx : my_indices) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "worker architecture init failed";
				}
				if (progress)
					progress->fetch_add(static_cast<int>(my_indices.size()),
					                    std::memory_order_relaxed);
				finish_worker("arch_init_failed");
				return;
			}

			size_t ok_count = 0;
			size_t error_count = 0;
			for (size_t idx : my_indices) {
				if (cancel && cancel->load(std::memory_order_acquire)) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "cancelled";
					++error_count;
					if (progress)
						progress->fetch_add(1, std::memory_order_relaxed);
					continue;
				}

				try {
					results[idx] = detail::do_decompile(ta->arch.get(), entries[idx], cancel);
					if (results[idx].complete && !results[idx].is_error && !results[idx].pseudocode.empty())
						++ok_count;
					else
						++error_count;
				}
				catch (ghidra::LowlevelError& err) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = err.explain;
					++error_count;
				}
				catch (ghidra::DecoderError& err) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = err.explain;
					++error_count;
				}
				catch (...) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "unknown error";
					++error_count;
				}

				if (progress)
					progress->fetch_add(1, std::memory_order_relaxed);
			}
			diag::log_tagged_fmt("ghidra",
				"batch_worker_counts worker=%u ok=%zu errors=%zu assigned=%zu",
				t,
				ok_count,
				error_count,
				my_indices.size());
			finish_worker((cancel && cancel->load(std::memory_order_acquire)) ? "cancelled_or_done" : "done");
		}))
		{
			const unsigned int before = workers_remaining.fetch_sub(1, std::memory_order_acq_rel);
			diag::log_tagged_fmt("ghidra",
				"batch_worker_post_failed worker=%u assigned=%zu remaining_before=%u remaining_after=%u",
				t,
				partitions[t].size(),
				before,
				before == 0 ? 0 : before - 1);
		}
	}

	uint64_t next_wait_log_ms = GetTickCount64() + 1000;
	while (workers_remaining.load(std::memory_order_acquire) > 0) {
		const uint64_t now_ms = GetTickCount64();
		if (now_ms >= next_wait_log_ms) {
			diag::log_tagged_fmt("ghidra",
				"batch_decompile_wait remaining=%u progress=%d cancel=%d elapsed_ms=%llu",
				workers_remaining.load(std::memory_order_acquire),
				progress ? progress->load(std::memory_order_relaxed) : -1,
				(cancel && cancel->load(std::memory_order_acquire)) ? 1 : 0,
				static_cast<unsigned long long>(now_ms - batch_start_ms));
			next_wait_log_ms = now_ms + 1000;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	int ok_total = 0;
	int err_total = 0;
	for (const auto& r : results) {
		if (r.complete && !r.is_error && !r.pseudocode.empty())
			++ok_total;
		else
			++err_total;
	}
	diag::log_tagged_fmt("ghidra",
		"batch_decompile_exit reason=done entries=%zu ok=%d errors=%d progress=%d cancel=%d elapsed_ms=%llu",
		entries.size(),
		ok_total,
		err_total,
		progress ? progress->load(std::memory_order_relaxed) : -1,
		(cancel && cancel->load(std::memory_order_acquire)) ? 1 : 0,
		static_cast<unsigned long long>(GetTickCount64() - batch_start_ms));
}

inline std::string last_error() {
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	return g_state.err_stream.str();
}

inline bool is_initialized() {
	return g_state.initialized.load();
}

inline void shutdown() {
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	if (!g_state.initialized.load())
		return;

	try {
		ghidra::shutdownDecompilerLibrary();
	}
	catch (...) {}

	g_state.initialized.store(false);
}

}
