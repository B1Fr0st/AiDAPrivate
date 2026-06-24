#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include "debugger_engine.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "stealth_engine.hpp"
#include "../analysis/symbol_store.hpp"
#include "../editor/expression_eval.hpp"
#include "../runtime/run_target.hpp"
#include "work_queue.hpp"
#include "event_bus.hpp"
#include "toast_notification.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

namespace {

struct system_handle_entry_t {
	USHORT pid;
	USHORT creator_back_trace_index;
	UCHAR  object_type_index;
	UCHAR  handle_attributes;
	USHORT handle_value;
	PVOID  object;
	ULONG  granted_access;
};

struct system_handle_information_t {
	ULONG number_of_handles;
	system_handle_entry_t handles[1];
};

using nt_query_system_information_fn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

}

namespace debugger_engine {

namespace {

std::string& last_error_ref() {
	static std::string s_last_error;
	return s_last_error;
}

void set_last_error(const std::string& msg) {
	last_error_ref() = msg;
}

constexpr uint64_t ctx_mask_rax = 1ULL << 0;
constexpr uint64_t ctx_mask_rbx = 1ULL << 1;
constexpr uint64_t ctx_mask_rcx = 1ULL << 2;
constexpr uint64_t ctx_mask_rdx = 1ULL << 3;
constexpr uint64_t ctx_mask_rsi = 1ULL << 4;
constexpr uint64_t ctx_mask_rdi = 1ULL << 5;
constexpr uint64_t ctx_mask_rbp = 1ULL << 6;
constexpr uint64_t ctx_mask_rsp = 1ULL << 7;
constexpr uint64_t ctx_mask_r8 = 1ULL << 8;
constexpr uint64_t ctx_mask_r9 = 1ULL << 9;
constexpr uint64_t ctx_mask_r10 = 1ULL << 10;
constexpr uint64_t ctx_mask_r11 = 1ULL << 11;
constexpr uint64_t ctx_mask_r12 = 1ULL << 12;
constexpr uint64_t ctx_mask_r13 = 1ULL << 13;
constexpr uint64_t ctx_mask_r14 = 1ULL << 14;
constexpr uint64_t ctx_mask_r15 = 1ULL << 15;
constexpr uint64_t ctx_mask_rip = 1ULL << 16;
constexpr uint64_t ctx_mask_rflags = 1ULL << 17;
constexpr uint64_t ctx_mask_base = (1ULL << 18) - 1ULL;
constexpr uint64_t ctx_mask_step = ctx_mask_rip | ctx_mask_rsp | ctx_mask_rflags;

uint64_t register_context_mask(const std::string& lower) {
	if      (lower == "rax") return ctx_mask_rax;
	else if (lower == "rbx") return ctx_mask_rbx;
	else if (lower == "rcx") return ctx_mask_rcx;
	else if (lower == "rdx") return ctx_mask_rdx;
	else if (lower == "rsi") return ctx_mask_rsi;
	else if (lower == "rdi") return ctx_mask_rdi;
	else if (lower == "rbp") return ctx_mask_rbp;
	else if (lower == "rsp") return ctx_mask_rsp;
	else if (lower == "r8")  return ctx_mask_r8;
	else if (lower == "r9")  return ctx_mask_r9;
	else if (lower == "r10") return ctx_mask_r10;
	else if (lower == "r11") return ctx_mask_r11;
	else if (lower == "r12") return ctx_mask_r12;
	else if (lower == "r13") return ctx_mask_r13;
	else if (lower == "r14") return ctx_mask_r14;
	else if (lower == "r15") return ctx_mask_r15;
	else if (lower == "rip") return ctx_mask_rip;
	else if (lower == "rflags" || lower == "eflags") return ctx_mask_rflags;
	return 0;
}

bool kernel_target_operations_ready(const char* caller) {
	std::string reason;
	const bool ready = driver_bridge::using_kernel_driver() &&
		driver_bridge::kernel_session_available(&reason) &&
		driver_bridge::dynamic_ioctls_ready();
	if (!ready) {
		diag::log_tagged_fmt("dbg_engine",
			"kernel_target_operations_fail_closed caller=%s loaded=%d kernel=%d dyn_ready=%d reason=%s status=%s last_error=%s",
			caller ? caller : "",
			driver_bridge::is_loaded() ? 1 : 0,
			driver_bridge::using_kernel_driver() ? 1 : 0,
			driver_bridge::dynamic_ioctls_ready() ? 1 : 0,
			reason.empty() ? "<empty>" : reason.c_str(),
			driver_bridge::status().c_str(),
			driver_bridge::last_error().c_str());
	}
	return ready;
}

struct call_stack_symbol_resolution_t {
	uint64_t address = 0;
	uint64_t module_base = 0;
	uint64_t module_size = 0;
	uint64_t module_offset = 0;
	uint64_t symbol_address = 0;
	uint64_t symbol_offset = 0;
	uint64_t elapsed_us = 0;
	std::string module_name;
	std::string function_name;
	std::string source = "none";
	std::string status = "not_attempted";
};

constexpr uint64_t k_call_stack_symbol_max_delta = 0x10000ull;
constexpr uint32_t k_call_stack_export_max_names = 65536u;
constexpr uint32_t k_call_stack_export_max_functions = 65536u;
constexpr uint64_t k_call_stack_export_max_array_bytes = 1024ull * 1024ull;
constexpr uint64_t k_call_stack_total_symbol_budget_us = 150000ull;
constexpr uint64_t k_call_stack_frame_symbol_budget_us = 25000ull;

std::mutex& call_stack_resolver_mutex() {
	static std::mutex m;
	return m;
}

std::unordered_map<uint64_t, call_stack_symbol_resolution_t>& call_stack_resolutions() {
	static std::unordered_map<uint64_t, call_stack_symbol_resolution_t> s;
	return s;
}

uint64_t resolver_elapsed_us(std::chrono::steady_clock::time_point t0) {
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
		std::chrono::steady_clock::now() - t0).count());
}

bool resolver_budget_expired(std::chrono::steady_clock::time_point deadline) {
	return std::chrono::steady_clock::now() >= deadline;
}

std::string lower_ascii_copy(std::string s) {
	for (char& c : s)
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return s;
}

bool module_contains_address(const driver_bridge::module_info_t& m, uint64_t address) {
	return m.base != 0 && m.size != 0 && address >= m.base && (address - m.base) < m.size;
}

const driver_bridge::module_info_t* find_module_for_stack_address(
	const std::vector<driver_bridge::module_info_t>& modules,
	uint64_t address)
{
	for (const auto& m : modules) {
		if (module_contains_address(m, address))
			return &m;
	}
	return nullptr;
}

std::string symbol_name_with_offset(const std::string& name, uint64_t delta) {
	if (name.empty() || delta == 0)
		return name;
	char suffix[40];
	std::snprintf(suffix, sizeof(suffix), "+0x%llX", static_cast<unsigned long long>(delta));
	return name + suffix;
}

std::string module_rva_fallback_name(const driver_bridge::module_info_t& module, uint64_t address) {
	const uint64_t rva = address >= module.base ? address - module.base : 0;
	std::string module_name = module.name.empty() ? "module" : module.name;
	char suffix[40];
	std::snprintf(suffix, sizeof(suffix), "!sub_%llX", static_cast<unsigned long long>(rva));
	return module_name + suffix;
}

std::string combine_resolver_status(const std::string& pdb_status, const std::string& export_status) {
	if (pdb_status.empty())
		return export_status.empty() ? std::string("unresolved") : export_status;
	if (export_status.empty())
		return pdb_status;
	return pdb_status + ";" + export_status;
}

call_stack_symbol_resolution_t module_rva_resolution(
	uint64_t address,
	const driver_bridge::module_info_t* module,
	const char* status,
	std::chrono::steady_clock::time_point t0)
{
	call_stack_symbol_resolution_t result;
	result.address = address;
	if (module != nullptr) {
		result.module_name = module->name;
		result.module_base = module->base;
		result.module_size = module->size;
		result.module_offset = address - module->base;
		result.function_name = module_rva_fallback_name(*module, address);
	} else {
		result.function_name.clear();
	}
	result.source = module != nullptr ? "module_rva" : "none";
	result.status = status ? status : "module_rva_fallback";
	result.symbol_address = address;
	result.symbol_offset = 0;
	result.elapsed_us = resolver_elapsed_us(t0);
	return result;
}

bool read_target_exact(uint64_t address, void* out, size_t size) {
	if (address == 0 || out == nullptr || size == 0)
		return false;
	std::vector<uint8_t> bytes;
	if (!driver_bridge::read_memory(address, size, bytes))
		return false;
	if (bytes.size() < size)
		return false;
	std::memcpy(out, bytes.data(), size);
	return true;
}

bool module_rva_span_valid(const driver_bridge::module_info_t& module, uint32_t rva, uint64_t size) {
	if (module.base == 0 || module.size == 0 || size == 0)
		return false;
	if (rva >= module.size)
		return false;
	return size <= static_cast<uint64_t>(module.size - rva);
}

bool read_module_rva_exact(const driver_bridge::module_info_t& module, uint32_t rva, void* out, size_t size) {
	if (!module_rva_span_valid(module, rva, size))
		return false;
	return read_target_exact(module.base + rva, out, size);
}

template <typename T>
bool read_module_rva_array(const driver_bridge::module_info_t& module, uint32_t rva, uint32_t count, std::vector<T>& out) {
	out.clear();
	if (count == 0)
		return false;
	const uint64_t bytes = static_cast<uint64_t>(count) * sizeof(T);
	if (bytes == 0 || bytes > k_call_stack_export_max_array_bytes)
		return false;
	if (!module_rva_span_valid(module, rva, bytes))
		return false;
	out.resize(static_cast<size_t>(count));
	std::vector<uint8_t> raw;
	if (!driver_bridge::read_memory(module.base + rva, static_cast<size_t>(bytes), raw) || raw.size() < bytes) {
		out.clear();
		return false;
	}
	std::memcpy(out.data(), raw.data(), static_cast<size_t>(bytes));
	return true;
}

std::string read_module_export_name(const driver_bridge::module_info_t& module, uint32_t name_rva) {
	if (name_rva == 0 || name_rva >= module.size)
		return {};
	const size_t max_len = static_cast<size_t>((std::min<uint64_t>)(512ull, static_cast<uint64_t>(module.size - name_rva)));
	if (max_len == 0)
		return {};
	std::vector<uint8_t> bytes;
	if (!driver_bridge::read_memory(module.base + name_rva, max_len, bytes) || bytes.empty())
		return {};
	std::string out;
	out.reserve(bytes.size());
	for (uint8_t b : bytes) {
		if (b == 0)
			break;
		if (b < 0x20 || b > 0x7E)
			return {};
		out.push_back(static_cast<char>(b));
	}
	return out;
}

bool resolve_stack_symbol_from_pdb(const driver_bridge::module_info_t& module,
	uint64_t address,
	call_stack_symbol_resolution_t& out,
	std::string& status,
	std::chrono::steady_clock::time_point budget_deadline)
{
	status.clear();
	const std::string module_name_l = lower_ascii_copy(module.name);
	const auto t0 = std::chrono::steady_clock::now();
	if (resolver_budget_expired(budget_deadline)) {
		status = "pdb_budget_exhausted_before_lock";
		return false;
	}
	std::unique_lock<std::mutex> lk(symbol_store::g_state.mutex, std::try_to_lock);
	if (!lk.owns_lock()) {
		status = "pdb_lock_busy";
		return false;
	}
	for (const auto& kv : symbol_store::g_state.modules) {
		if (resolver_budget_expired(budget_deadline)) {
			status = "pdb_budget_exhausted";
			return false;
		}
		const auto& ms = kv.second;
		const bool range_match = ms.base != 0 && ms.size != 0 && address >= ms.base && (address - ms.base) < ms.size;
		const std::string store_module_name = ms.module_name.empty() ? kv.first : ms.module_name;
		const bool name_base_match = ms.base == module.base && lower_ascii_copy(store_module_name) == module_name_l;
		if (!range_match && !name_base_match)
			continue;
		if (ms.loading) {
			status = "pdb_loading";
			return false;
		}
		if (ms.failed) {
			status = "pdb_failed";
			return false;
		}
		if (!ms.pdb.loaded) {
			status = "pdb_not_loaded";
			return false;
		}

		const uint64_t rva = address - ms.base;
		auto exact = ms.pdb.symbol_by_rva.find(rva);
		if (exact != ms.pdb.symbol_by_rva.end() && exact->second < ms.pdb.symbols.size()) {
			const auto& sym = ms.pdb.symbols[exact->second];
			if (!sym.name.empty()) {
				out.function_name = sym.name;
				out.source = "pdb_exact";
				out.status = "resolved";
				out.symbol_address = ms.base + sym.rva;
				out.symbol_offset = 0;
				status = out.status;
				return true;
			}
		}

		const std::string* best_name = nullptr;
		uint64_t best_rva = 0;
		size_t scanned = 0;
		bool budget_hit = false;
		for (const auto& sym : ms.pdb.symbols) {
			if ((++scanned & 0x7FFu) == 0 && (resolver_elapsed_us(t0) > 3000 || resolver_budget_expired(budget_deadline))) {
				budget_hit = true;
				break;
			}
			if (!sym.is_function || sym.name.empty() || sym.rva > rva)
				continue;
			const uint64_t delta = rva - sym.rva;
			if (delta >= k_call_stack_symbol_max_delta)
				continue;
			if (best_name == nullptr || sym.rva > best_rva) {
				best_name = &sym.name;
				best_rva = sym.rva;
				if (delta == 0)
					break;
			}
		}
		if (best_name != nullptr) {
			const uint64_t delta = rva - best_rva;
			out.function_name = symbol_name_with_offset(*best_name, delta);
			out.source = delta == 0 ? "pdb_exact" : "pdb_nearest";
			out.status = budget_hit ? "resolved_pdb_budgeted" : "resolved";
			out.symbol_address = ms.base + best_rva;
			out.symbol_offset = delta;
			status = out.status;
			return true;
		}
		status = budget_hit ? "pdb_scan_budget_exhausted" : "pdb_no_near_symbol";
		return false;
	}
	status = "pdb_module_missing";
	return false;
}

bool resolve_stack_symbol_from_exports(const driver_bridge::module_info_t& module,
	uint64_t address,
	call_stack_symbol_resolution_t& out,
	std::string& status,
	std::chrono::steady_clock::time_point budget_deadline)
{
	status.clear();
	if (resolver_budget_expired(budget_deadline)) {
		status = "export_budget_exhausted_before_parse";
		return false;
	}
	if (!module_contains_address(module, address)) {
		status = "export_module_mismatch";
		return false;
	}
	const uint64_t target_rva64 = address - module.base;
	if (target_rva64 > 0xFFFFFFFFull) {
		status = "export_target_rva_out_of_range";
		return false;
	}
	const uint32_t target_rva = static_cast<uint32_t>(target_rva64);
	IMAGE_DOS_HEADER dos{};
	if (!read_module_rva_exact(module, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
		status = "export_bad_dos_header";
		return false;
	}
	if (dos.e_lfanew <= 0 || static_cast<uint64_t>(dos.e_lfanew) >= module.size) {
		status = "export_bad_lfanew";
		return false;
	}
	const uint32_t nt_rva = static_cast<uint32_t>(dos.e_lfanew);
	DWORD signature = 0;
	if (!read_module_rva_exact(module, nt_rva, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE) {
		status = "export_bad_nt_signature";
		return false;
	}
	if (nt_rva > 0xFFFFFFFFu - static_cast<uint32_t>(sizeof(DWORD)) - static_cast<uint32_t>(sizeof(IMAGE_FILE_HEADER))) {
		status = "export_nt_header_rva_overflow";
		return false;
	}
	const uint32_t file_header_rva = nt_rva + static_cast<uint32_t>(sizeof(DWORD));
	const uint32_t optional_rva = file_header_rva + static_cast<uint32_t>(sizeof(IMAGE_FILE_HEADER));
	IMAGE_FILE_HEADER file_header{};
	if (!read_module_rva_exact(module, file_header_rva, &file_header, sizeof(file_header))) {
		status = "export_file_header_unreadable";
		return false;
	}
	if (file_header.SizeOfOptionalHeader < static_cast<WORD>(sizeof(WORD))) {
		status = "export_optional_header_too_small";
		return false;
	}
	WORD magic = 0;
	if (!read_module_rva_exact(module, optional_rva, &magic, sizeof(magic))) {
		status = "export_optional_header_unreadable";
		return false;
	}
	DWORD export_rva = 0;
	DWORD export_size = 0;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		IMAGE_OPTIONAL_HEADER64 opt{};
		if (!read_module_rva_exact(module, optional_rva, &opt, sizeof(opt))) {
			status = "export_optional64_unreadable";
			return false;
		}
		if (opt.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
			status = "export_directory_missing";
			return false;
		}
		export_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	} else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		IMAGE_OPTIONAL_HEADER32 opt{};
		if (!read_module_rva_exact(module, optional_rva, &opt, sizeof(opt))) {
			status = "export_optional32_unreadable";
			return false;
		}
		if (opt.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
			status = "export_directory_missing";
			return false;
		}
		export_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	} else {
		status = "export_unknown_optional_magic";
		return false;
	}
	if (export_rva == 0 || export_size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
		status = "export_directory_absent";
		return false;
	}
	IMAGE_EXPORT_DIRECTORY exp{};
	if (!read_module_rva_exact(module, export_rva, &exp, sizeof(exp))) {
		status = "export_directory_unreadable";
		return false;
	}
	if (exp.NumberOfNames == 0 || exp.NumberOfFunctions == 0) {
		status = "export_no_names";
		return false;
	}
	if (exp.AddressOfNames == 0 || exp.AddressOfNameOrdinals == 0 || exp.AddressOfFunctions == 0) {
		status = "export_tables_absent";
		return false;
	}
	uint32_t name_count = exp.NumberOfNames;
	if (name_count > k_call_stack_export_max_names)
		name_count = k_call_stack_export_max_names;
	uint32_t function_count = exp.NumberOfFunctions;
	if (function_count > k_call_stack_export_max_functions)
		function_count = k_call_stack_export_max_functions;

	std::vector<DWORD> name_rvas;
	std::vector<WORD> ordinals;
	std::vector<DWORD> function_rvas;
	if (resolver_budget_expired(budget_deadline)) {
		status = "export_budget_exhausted_before_tables";
		return false;
	}
	if (!read_module_rva_array(module, exp.AddressOfNames, name_count, name_rvas)) {
		status = "export_names_unreadable";
		return false;
	}
	if (!read_module_rva_array(module, exp.AddressOfNameOrdinals, name_count, ordinals)) {
		status = "export_ordinals_unreadable";
		return false;
	}
	if (!read_module_rva_array(module, exp.AddressOfFunctions, function_count, function_rvas)) {
		status = "export_functions_unreadable";
		return false;
	}

	const uint64_t export_end = static_cast<uint64_t>(export_rva) + static_cast<uint64_t>(export_size);
	const auto t0 = std::chrono::steady_clock::now();
	uint64_t best_delta = k_call_stack_symbol_max_delta;
	uint32_t best_rva = 0;
	std::string best_name;
	bool budget_hit = false;
	for (uint32_t i = 0; i < name_count; ++i) {
		if ((i & 0xFFu) == 0 && i != 0 && (resolver_elapsed_us(t0) > 8000 || resolver_budget_expired(budget_deadline))) {
			budget_hit = true;
			break;
		}
		const uint16_t ordinal_index = ordinals[i];
		if (ordinal_index >= function_count)
			continue;
		const uint32_t fn_rva = function_rvas[ordinal_index];
		if (fn_rva == 0 || fn_rva > target_rva)
			continue;
		if (static_cast<uint64_t>(fn_rva) >= export_rva && static_cast<uint64_t>(fn_rva) < export_end)
			continue;
		if (fn_rva >= module.size)
			continue;
		const uint64_t delta = static_cast<uint64_t>(target_rva - fn_rva);
		if (delta >= best_delta || delta >= k_call_stack_symbol_max_delta)
			continue;
		if (resolver_budget_expired(budget_deadline)) {
			budget_hit = true;
			break;
		}
		const std::string candidate_name = read_module_export_name(module, name_rvas[i]);
		if (candidate_name.empty())
			continue;
		best_delta = delta;
		best_rva = fn_rva;
		best_name = candidate_name;
		if (delta == 0)
			break;
	}
	if (!best_name.empty()) {
		out.function_name = symbol_name_with_offset(best_name, best_delta);
		out.source = best_delta == 0 ? "export_exact" : "export_nearest";
		out.status = budget_hit ? "resolved_export_budgeted" : "resolved";
		out.symbol_address = module.base + best_rva;
		out.symbol_offset = best_delta;
		status = out.status;
		return true;
	}
	status = budget_hit ? "export_scan_budget_exhausted" : "export_no_near_name";
	return false;
}

void log_call_stack_symbol_resolution(const call_stack_symbol_resolution_t& r) {
	diag::log_tagged_fmt("dbg_stack_symbol",
		"resolve addr=0x%llX module=%s base=0x%llX size=0x%llX offset=0x%llX source=%s status=%s function=%s symbol=0x%llX symbol_offset=0x%llX elapsed_us=%llu",
		static_cast<unsigned long long>(r.address),
		r.module_name.empty() ? "(none)" : r.module_name.c_str(),
		static_cast<unsigned long long>(r.module_base),
		static_cast<unsigned long long>(r.module_size),
		static_cast<unsigned long long>(r.module_offset),
		r.source.c_str(),
		r.status.c_str(),
		r.function_name.empty() ? "(empty)" : r.function_name.c_str(),
		static_cast<unsigned long long>(r.symbol_address),
		static_cast<unsigned long long>(r.symbol_offset),
		static_cast<unsigned long long>(r.elapsed_us));
}

call_stack_symbol_resolution_t resolve_call_stack_symbol(
	uint64_t address,
	const std::vector<driver_bridge::module_info_t>& modules,
	std::chrono::steady_clock::time_point budget_deadline)
{
	const auto t0 = std::chrono::steady_clock::now();
	call_stack_symbol_resolution_t result;
	result.address = address;
	const auto* module = find_module_for_stack_address(modules, address);
	if (module == nullptr) {
		result.status = "no_module";
		result.elapsed_us = resolver_elapsed_us(t0);
		log_call_stack_symbol_resolution(result);
		return result;
	}
	result.module_name = module->name;
	result.module_base = module->base;
	result.module_size = module->size;
	result.module_offset = address - module->base;
	if (resolver_budget_expired(budget_deadline)) {
		result = module_rva_resolution(address, module, "symbol_budget_exhausted_before_resolution", t0);
		log_call_stack_symbol_resolution(result);
		return result;
	}

	std::string pdb_status;
	if (resolve_stack_symbol_from_pdb(*module, address, result, pdb_status, budget_deadline)) {
		result.elapsed_us = resolver_elapsed_us(t0);
		log_call_stack_symbol_resolution(result);
		return result;
	}
	if (resolver_budget_expired(budget_deadline)) {
		result = module_rva_resolution(address, module, ("symbol_budget_exhausted_after_pdb;" + pdb_status).c_str(), t0);
		log_call_stack_symbol_resolution(result);
		return result;
	}

	std::string export_status;
	if (resolve_stack_symbol_from_exports(*module, address, result, export_status, budget_deadline)) {
		result.elapsed_us = resolver_elapsed_us(t0);
		log_call_stack_symbol_resolution(result);
		return result;
	}

	result.source = "module_rva";
	result.status = combine_resolver_status(pdb_status, export_status) + ";module_rva_fallback";
	result.function_name = module_rva_fallback_name(*module, address);
	result.symbol_address = address;
	result.symbol_offset = 0;
	result.elapsed_us = resolver_elapsed_us(t0);
	diag::log_tagged_fmt("dbg_stack_symbol",
		"module_rva_fallback addr=0x%llX module=%s base=0x%llX offset=0x%llX pdb_status=%s export_status=%s function=%s",
		static_cast<unsigned long long>(address),
		module->name.empty() ? "(none)" : module->name.c_str(),
		static_cast<unsigned long long>(module->base),
		static_cast<unsigned long long>(result.module_offset),
		pdb_status.empty() ? "(empty)" : pdb_status.c_str(),
		export_status.empty() ? "(empty)" : export_status.c_str(),
		result.function_name.c_str());
	log_call_stack_symbol_resolution(result);
	return result;
}

void publish_call_stack_resolutions(const std::vector<call_stack_symbol_resolution_t>& records) {
	std::lock_guard<std::mutex> lk(call_stack_resolver_mutex());
	auto& cache = call_stack_resolutions();
	cache.clear();
	cache.reserve(records.size());
	for (const auto& r : records)
		cache[r.address] = r;
}

expression_eval::context_t build_eval_context(const register_set_t& regs) {
	expression_eval::context_t ctx;
	ctx.rax = regs.rax; ctx.rbx = regs.rbx; ctx.rcx = regs.rcx; ctx.rdx = regs.rdx;
	ctx.rsi = regs.rsi; ctx.rdi = regs.rdi; ctx.rbp = regs.rbp; ctx.rsp = regs.rsp;
	ctx.r8  = regs.r8;  ctx.r9  = regs.r9;  ctx.r10 = regs.r10; ctx.r11 = regs.r11;
	ctx.r12 = regs.r12; ctx.r13 = regs.r13; ctx.r14 = regs.r14; ctx.r15 = regs.r15;
	ctx.rip = regs.rip; ctx.rflags = regs.rflags;
	ctx.read_mem = [](uint64_t addr, size_t size, void* out) -> bool {
		if (out == nullptr || size == 0) return false;
		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory(addr, size, buf)) return false;
		if (buf.size() < size) return false;
		std::memcpy(out, buf.data(), size);
		return true;
	};
	return ctx;
}

void push_log_message_locked(state_t& st, const std::string& msg) {
	std::lock_guard<std::mutex> lk(st.log_mutex);
	if (st.log_messages.size() >= st.log_messages_max) {
		st.log_messages.pop_front();
	}
	st.log_messages.push_back(msg);
}

std::recursive_mutex& thread_ctx_serializer() {
	static std::recursive_mutex m;
	return m;
}

bool resume_thread_for_controlled_run(uint32_t tid, uint32_t previous_suspend_count) {
	uint32_t resumes = previous_suspend_count + 1;
	if (resumes == 0 || resumes > 64)
		resumes = 64;
	diag::log_tagged_fmt("debugger",
		"resume_thread_for_controlled_run_begin tid=%u previous_suspend=%u attempts=%u",
		static_cast<unsigned>(tid),
		static_cast<unsigned>(previous_suspend_count),
		static_cast<unsigned>(resumes));
	uint32_t last_prev = 0;
	for (uint32_t i = 0; i < resumes; ++i) {
		uint32_t prev = 0;
		if (!driver_bridge::resume_thread(tid, &prev)) {
			diag::log_tagged_fmt("debugger",
				"resume_thread_for_controlled_run_failed tid=%u attempt=%u previous_suspend=%u last_prev=%u",
				static_cast<unsigned>(tid),
				static_cast<unsigned>(i + 1),
				static_cast<unsigned>(previous_suspend_count),
				static_cast<unsigned>(last_prev));
			return false;
		}
		last_prev = prev;
		if (prev == 0)
			break;
	}
	diag::log_tagged_fmt("debugger",
		"resume_thread_for_controlled_run_done tid=%u previous_suspend=%u attempts=%u last_prev=%u",
		static_cast<unsigned>(tid),
		static_cast<unsigned>(previous_suspend_count),
		static_cast<unsigned>(resumes),
		static_cast<unsigned>(last_prev));
	return true;
}

bool suspend_contextable_thread(state_t& st, driver_bridge::thread_context_t& ctx, uint32_t& previous_suspend_count) {
	auto try_thread = [&](uint32_t tid, const char* source) -> bool {
		if (tid == 0)
			return false;
		uint32_t saved = 0;
		if (!driver_bridge::suspend_thread(tid, &saved)) {
			diag::log_tagged_fmt("debugger",
				"suspend_contextable_thread_suspend_failed pid=%u tid=%u source=%s",
				static_cast<unsigned>(st.target_pid),
				static_cast<unsigned>(tid),
				source ? source : "unknown");
			return false;
		}
		if (driver_bridge::get_thread_context(tid, ctx)) {
			st.active_tid = tid;
			previous_suspend_count = saved;
			diag::log_tagged_fmt("debugger",
				"suspend_contextable_thread_selected pid=%u tid=%u source=%s rip=0x%llx rsp=0x%llx rflags=0x%llx previous_suspend=%u",
				static_cast<unsigned>(st.target_pid),
				static_cast<unsigned>(tid),
				source ? source : "unknown",
				static_cast<unsigned long long>(ctx.rip),
				static_cast<unsigned long long>(ctx.rsp),
				static_cast<unsigned long long>(ctx.rflags),
				static_cast<unsigned>(saved));
			return true;
		}
		driver_bridge::resume_thread(tid);
		diag::log_tagged_fmt("debugger",
			"suspend_contextable_thread_context_failed pid=%u tid=%u source=%s previous_suspend=%u",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(tid),
			source ? source : "unknown",
			static_cast<unsigned>(saved));
		return false;
	};

	if (try_thread(st.active_tid, "active"))
		return true;

	auto threads = driver_bridge::enumerate_threads();
	for (const auto& th : threads) {
		if (th.owner_pid != st.target_pid || th.tid == st.active_tid)
			continue;
		if (try_thread(th.tid, "enumerated"))
			return true;
	}
	return false;
}

std::vector<driver_bridge::thread_info_t> hardware_breakpoint_threads(state_t& st, const char* reason) {
	std::vector<driver_bridge::thread_info_t> selected;
	if (st.target_pid == 0)
		return selected;
	auto threads = driver_bridge::enumerate_threads();
	if (st.active_tid != 0) {
		for (const auto& t : threads) {
			if (t.owner_pid == st.target_pid && t.tid == st.active_tid) {
				selected.push_back(t);
				diag::log_tagged_fmt("dbg_engine",
					"hwbp_thread_scope reason=%s pid=%u active_tid=%u selected=1 enumerated=%zu",
					reason ? reason : "hwbp",
					static_cast<unsigned>(st.target_pid),
					static_cast<unsigned>(st.active_tid),
					threads.size());
				return selected;
			}
		}
	}
	for (const auto& t : threads) {
		if (t.owner_pid == st.target_pid)
			selected.push_back(t);
	}
	diag::log_tagged_fmt("dbg_engine",
		"hwbp_thread_scope reason=%s pid=%u active_tid=%u selected=%zu enumerated=%zu",
		reason ? reason : "hwbp",
		static_cast<unsigned>(st.target_pid),
		static_cast<unsigned>(st.active_tid),
		selected.size(),
		threads.size());
	return selected;
}

register_set_t capture_registers_from_context(const driver_bridge::thread_context_t& src) {
	register_set_t dst{};
	dst.rax = src.rax; dst.rbx = src.rbx;
	dst.rcx = src.rcx; dst.rdx = src.rdx;
	dst.rsi = src.rsi; dst.rdi = src.rdi;
	dst.rbp = src.rbp; dst.rsp = src.rsp;
	dst.r8  = src.r8;  dst.r9  = src.r9;
	dst.r10 = src.r10; dst.r11 = src.r11;
	dst.r12 = src.r12; dst.r13 = src.r13;
	dst.r14 = src.r14; dst.r15 = src.r15;
	dst.rip = src.rip; dst.rflags = src.rflags;
	dst.cs = src.cs; dst.ss = src.ss;
	dst.dr0 = src.dr0; dst.dr1 = src.dr1;
	dst.dr2 = src.dr2; dst.dr3 = src.dr3;
	dst.dr6 = src.dr6; dst.dr7 = src.dr7;
	return dst;
}

void release_step_suspend_if_previously_suspended(uint32_t tid, uint32_t previous_suspend_count) {
	if (tid != 0 && previous_suspend_count > 0) {
		uint32_t prev = 0;
		const bool ok = driver_bridge::resume_thread(tid, &prev);
		diag::log_tagged_fmt("debugger",
			"release_step_suspend tid=%u previous_suspend=%u resume_ok=%d resume_prev=%u",
			static_cast<unsigned>(tid),
			static_cast<unsigned>(previous_suspend_count),
			ok ? 1 : 0,
			static_cast<unsigned>(prev));
	}
}

}

std::string call_stack_frame_resolver_evidence(uint64_t address) {
	std::lock_guard<std::mutex> lk(call_stack_resolver_mutex());
	const auto& cache = call_stack_resolutions();
	auto it = cache.find(address);
	if (it == cache.end())
		return "source=none status=no_last_resolution";
	const auto& r = it->second;
	std::ostringstream oss;
	oss << "source=" << r.source
		<< " status=" << r.status
		<< " module=" << (r.module_name.empty() ? "(none)" : r.module_name)
		<< " base=0x" << std::hex << std::uppercase << r.module_base
		<< " address=0x" << r.address
		<< " offset=0x" << r.module_offset
		<< " symbol=0x" << r.symbol_address
		<< " symbol_offset=0x" << r.symbol_offset
		<< std::dec << " elapsed_us=" << r.elapsed_us;
	return oss.str();
}

void sync_attached_state();

namespace {

aida::events::subscription_handle_t g_process_exited_sub;
std::atomic<bool> g_event_subscriptions_initialized{false};

void handle_process_exited(const aida::events::process_exited_t& evt) {
	uint32_t attached = driver_bridge::attached_pid();
	if (attached == 0 || attached != evt.process_id)
		return;

	auto& st = g_state;
	st.status.store(dbg_status_t::terminated);
	st.active_tid = 0;
	st.tracing.store(false);

	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		for (auto& bp : st.breakpoints) {
			bp.byte_written = false;
			bp.hw_slot = -1;
		}
		for (auto& ibp : st.internal_breakpoints) {
			ibp.active = false;
		}
	}

	{
		std::lock_guard<std::mutex> lk(st.cache_mtx);
		st.cached_regs = register_set_t{};
		st.cached_threads.clear();
		st.cached_stack.clear();
		st.cached_stack_addr = 0;
		st.cached_dump.clear();
		st.cached_dump_addr = 0;
		st.cached_dump_size = 0;
		st.cached_disasm_bytes.clear();
		st.cached_disasm_base = 0;
	}

	{
		std::lock_guard<std::mutex> lk(st.trap_mtx);
		st.pending_trap_address = 0;
		st.trap_signaled.store(true);
	}
	st.trap_cv.notify_all();

	char buf[160];
	std::snprintf(buf, sizeof(buf),
		"Target process (PID %u) exited; debugger detached state cached.",
		evt.process_id);
	push_log_message_locked(st, buf);
	toast_notification::push(buf, toast_notification::toast_type_t::warning);
}

void ensure_event_subscriptions() {
	bool expected = false;
	if (!g_event_subscriptions_initialized.compare_exchange_strong(expected, true))
		return;
	g_process_exited_sub = aida::events::subscribe(
		aida::events::event_process_exited,
		[](const aida::events::process_exited_t& evt) {
			handle_process_exited(evt);
		});
}

}

void initialize() {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "initialize: entry");
	st.status.store(dbg_status_t::idle);
	ensure_event_subscriptions();
	diag::log_tagged_fmt("dbg_engine", "initialize: done status=idle");
}

void shutdown() {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "shutdown: entry");
	st.tracing.store(false);
	st.worker_active.store(false);
	{
		std::lock_guard<std::mutex> lk(st.trap_mtx);
		st.trap_signaled.store(true);
	}
	st.trap_cv.notify_all();
	while (!st.worker_thread_done.load(std::memory_order_acquire))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	clear_all_breakpoints();
	diag::log_tagged_fmt("dbg_engine", "shutdown: done");
}


int add_breakpoint(uint64_t address, bp_type_t type, const std::string& name,
				   const std::string& condition, int size) {
	auto& st = g_state;
	sync_attached_state();

	int len_bits = 0;
	bool is_hw = (type == bp_type_t::hardware_execute ||
				  type == bp_type_t::hardware_write ||
				  type == bp_type_t::hardware_read);
	if (is_hw) {
		switch (size) {
			case 1: len_bits = 0; break;
			case 2: len_bits = 1; break;
			case 4: len_bits = 3; break;
			case 8: len_bits = 2; break;
			default:
				set_last_error("hw bp size must be 1, 2, 4, or 8 bytes");
				return -1;
		}
	}

	std::lock_guard<std::mutex> lk(st.bp_mutex);


	for (auto& bp : st.breakpoints) {
		if (bp.address == address && bp.type == type) {
			set_last_error("add_breakpoint: duplicate at address/type");
			return -1;
		}
	}

	breakpoint_t bp;
	bp.address = address;
	bp.type = type;
	bp.state = bp_state_t::enabled;
	bp.name = name;
	bp.condition = condition;
	bp.size = is_hw ? size : 1;


	if (type == bp_type_t::software) {
		std::vector<uint8_t> orig;
		if (!driver_bridge::read_memory(address, 1, orig) || orig.empty()) {
			set_last_error("add_breakpoint: read_memory failed");
			diag::log_tagged_fmt("bp",
				"add_breakpoint_read_FAILED addr=0x%llx",
				static_cast<unsigned long long>(address));
			return -1;
		}

		if (orig[0] == 0xCC) {
			bool recovered = false;
			for (const auto& ibp : st.internal_breakpoints) {
				if (ibp.address == address && ibp.active) {
					bp.original_byte = ibp.original_byte;
					bp.byte_written = true;
					recovered = true;
					diag::log_tagged_fmt("bp",
						"add_breakpoint_reuse_internal_byte addr=0x%llx orig=0x%02X",
						static_cast<unsigned long long>(address),
						static_cast<unsigned>(ibp.original_byte));
					break;
				}
			}
			if (!recovered) {
				set_last_error("add_breakpoint: byte already 0xCC and no recoverable original");
				diag::log_tagged_fmt("bp",
					"add_breakpoint_already_cc addr=0x%llx",
					static_cast<unsigned long long>(address));
				return -1;
			}
		} else {
			bp.original_byte = orig[0];

			std::vector<uint8_t> cc{0xCC};
			if (!driver_bridge::write_memory(address, cc)) {
				set_last_error("add_breakpoint: write_memory failed");
				diag::log_tagged_fmt("bp",
					"add_breakpoint_write_FAILED addr=0x%llx",
					static_cast<unsigned long long>(address));
				return -1;
			}

			std::vector<uint8_t> verify;
			if (!driver_bridge::read_memory(address, 1, verify) || verify.empty() || verify[0] != 0xCC) {
				std::vector<uint8_t> restore{bp.original_byte};
				driver_bridge::write_memory(address, restore);
				set_last_error("add_breakpoint: write verification failed");
				diag::log_tagged_fmt("bp",
					"add_breakpoint_verify_FAILED addr=0x%llx",
					static_cast<unsigned long long>(address));
				return -1;
			}
			bp.byte_written = true;
		}
	}


	if (type == bp_type_t::hardware_execute || type == bp_type_t::hardware_write ||
		type == bp_type_t::hardware_read) {
		int slot = -1;
		bool used[4] = {};
		for (auto& existing : st.breakpoints) {
			if (existing.hw_slot >= 0 && existing.hw_slot < 4 &&
				existing.state != bp_state_t::disabled)
				used[existing.hw_slot] = true;
		}
		for (int i = 0; i < 4; ++i) {
			if (!used[i]) { slot = i; break; }
		}
		if (slot == -1) {
			set_last_error("add_breakpoint: no free hardware slot (4 max)");
			return -1;
		}
		bp.hw_slot = slot;

		int hw_type = 0;
		if (type == bp_type_t::hardware_execute)    hw_type = 0;
		else if (type == bp_type_t::hardware_write) hw_type = 1;
		else if (type == bp_type_t::hardware_read)  hw_type = 3;

		bool any_applied = false;
		bool any_failed  = false;
		if (st.target_pid != 0) {
			auto threads = hardware_breakpoint_threads(st, "add_breakpoint");
			for (const auto& t : threads) {
				if (driver_bridge::set_hardware_breakpoint(t.tid, slot, address, hw_type, len_bits))
					any_applied = true;
				else
					any_failed = true;
			}
		}
		if (!any_applied && st.target_pid != 0) {
			set_last_error("add_breakpoint: failed to program any thread's DRx");
			return -1;
		}
		if (any_failed) {
			diag::log_tagged_fmt("bp",
				"add_breakpoint_partial_drx addr=0x%llx slot=%d",
				static_cast<unsigned long long>(address),
				slot);
		}
	}

	int new_index = static_cast<int>(st.breakpoints.size());
	st.breakpoints.push_back(std::move(bp));
	diag::log_tagged_fmt("bp",
		"add_breakpoint_ok addr=0x%llx type=%d size=%d idx=%d hwbp=%d",
		static_cast<unsigned long long>(address),
		static_cast<int>(type),
		is_hw ? size : 1,
		new_index,
		is_hw ? 1 : 0);
	return new_index;
}

bool remove_breakpoint(int index) {
	auto& st = g_state;
	sync_attached_state();
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size()))
		return false;

	auto& bp = st.breakpoints[static_cast<size_t>(index)];

	if (bp.type == bp_type_t::software && bp.byte_written) {
		std::vector<uint8_t> restore{bp.original_byte};
		if (!driver_bridge::write_memory(bp.address, restore)) {
			set_last_error("remove_breakpoint: write_memory failed restoring byte");
			return false;
		}
		bp.byte_written = false;
	}

	if (bp.hw_slot >= 0 && bp.hw_slot < 4 && st.target_pid != 0) {
		auto threads = hardware_breakpoint_threads(st, "remove_breakpoint");
		for (const auto& t : threads) {
			driver_bridge::clear_hardware_breakpoint(t.tid, bp.hw_slot);
		}
	}

	uint64_t removed_addr = bp.address;
	int       removed_type = static_cast<int>(bp.type);
	st.breakpoints.erase(st.breakpoints.begin() + index);
	diag::log_tagged_fmt("bp",
		"remove_breakpoint_ok idx=%d addr=0x%llx type=%d",
		index,
		static_cast<unsigned long long>(removed_addr),
		removed_type);
	return true;
}

bool toggle_breakpoint(int index) {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "toggle_breakpoint: index=%d", index);
	sync_attached_state();
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size())) {
		diag::log_tagged_fmt("dbg_engine", "toggle_breakpoint: index=%d out of range (size=%zu)", index, st.breakpoints.size());
		return false;
	}
	auto& bp = st.breakpoints[static_cast<size_t>(index)];

	bool will_enable = (bp.state == bp_state_t::disabled);

	if (bp.type == bp_type_t::software) {
		if (will_enable && !bp.byte_written) {
			std::vector<uint8_t> orig;
			if (driver_bridge::read_memory(bp.address, 1, orig) && !orig.empty()) {
				bp.original_byte = orig[0];
				std::vector<uint8_t> cc{0xCC};
				if (driver_bridge::write_memory(bp.address, cc))
					bp.byte_written = true;
			}
		} else if (!will_enable && bp.byte_written) {
			std::vector<uint8_t> restore{bp.original_byte};
			if (driver_bridge::write_memory(bp.address, restore))
				bp.byte_written = false;
		}
	}

	if (bp.type == bp_type_t::hardware_execute || bp.type == bp_type_t::hardware_write ||
		bp.type == bp_type_t::hardware_read) {
		if (!will_enable) {
			if (bp.hw_slot >= 0 && bp.hw_slot < 4 && st.target_pid != 0) {
				auto threads = hardware_breakpoint_threads(st, "toggle_breakpoint_off");
				for (const auto& t : threads) {
					driver_bridge::clear_hardware_breakpoint(t.tid, bp.hw_slot);
				}
			}
		} else {
			int slot = -1;
			bool used[4] = {};
			for (auto& existing : st.breakpoints) {
				if (&existing == &bp) continue;
				if (existing.hw_slot >= 0 && existing.hw_slot < 4 &&
					existing.state != bp_state_t::disabled)
					used[existing.hw_slot] = true;
			}
			if (bp.hw_slot >= 0 && bp.hw_slot < 4 && !used[bp.hw_slot])
				slot = bp.hw_slot;
			else {
				for (int i = 0; i < 4; ++i) {
					if (!used[i]) { slot = i; break; }
				}
			}
			if (slot == -1) {
				set_last_error("toggle_breakpoint: no free hardware slot");
				return false;
			}
			bp.hw_slot = slot;

			int hw_type = 0;
			if (bp.type == bp_type_t::hardware_execute)    hw_type = 0;
			else if (bp.type == bp_type_t::hardware_write) hw_type = 1;
			else if (bp.type == bp_type_t::hardware_read)  hw_type = 3;

			int len_bits = 0;
			switch (bp.size) {
				case 1: len_bits = 0; break;
				case 2: len_bits = 1; break;
				case 4: len_bits = 3; break;
				case 8: len_bits = 2; break;
				default: len_bits = 0; break;
			}

			if (st.target_pid != 0) {
				auto threads = hardware_breakpoint_threads(st, "toggle_breakpoint_on");
				for (const auto& t : threads) {
					driver_bridge::set_hardware_breakpoint(t.tid, slot, bp.address, hw_type, len_bits);
				}
			}
		}
	}

	bp.state = will_enable ? bp_state_t::enabled : bp_state_t::disabled;
	diag::log_tagged_fmt("dbg_engine", "toggle_breakpoint: index=%d addr=0x%llX now=%s", index, (unsigned long long)bp.address, will_enable ? "enabled" : "disabled");
	return true;
}

void clear_all_breakpoints() {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "clear_all_breakpoints: entry");
	sync_attached_state();

	std::vector<driver_bridge::thread_info_t> threads;
	if (st.target_pid != 0)
		threads = hardware_breakpoint_threads(st, "clear_all_breakpoints");

	std::lock_guard<std::mutex> lk(st.bp_mutex);

	for (auto& bp : st.breakpoints) {
		if (bp.type == bp_type_t::software && bp.byte_written) {
			std::vector<uint8_t> restore{bp.original_byte};
			driver_bridge::write_memory(bp.address, restore);
			bp.byte_written = false;
		}
		if (bp.hw_slot >= 0 && bp.hw_slot < 4) {
			for (const auto& t : threads) {
				if (t.owner_pid != st.target_pid) continue;
				driver_bridge::clear_hardware_breakpoint(t.tid, bp.hw_slot);
			}
		}
	}
	st.breakpoints.clear();
	for (auto& ibp : st.internal_breakpoints) {
		if (ibp.active) {
			std::vector<uint8_t> restore{ibp.original_byte};
			driver_bridge::write_memory(ibp.address, restore);
			ibp.active = false;
		}
	}
	st.internal_breakpoints.clear();
	diag::log_tagged_fmt("dbg_engine", "clear_all_breakpoints: done");
}


bool run_target() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) {
		set_last_error("run_target: no target attached");
		diag::log_tagged_fmt("debugger",
			"run_target_REJECTED no_target");
		return false;
	}

	auto threads = driver_bridge::enumerate_threads();
	int resumed = 0;
	int failed = 0;
	for (const auto& t : threads) {
		if (t.owner_pid != st.target_pid) continue;
		if (driver_bridge::resume_thread(t.tid))
			++resumed;
		else
			++failed;
	}

	st.status.store(dbg_status_t::running);
	diag::log_tagged_fmt("debugger",
		"run_target_done pid=%u resumed=%d failed=%d",
		static_cast<unsigned>(st.target_pid),
		resumed, failed);
	return resumed > 0 || threads.empty();
}

namespace {

std::string narrow_utf8(const std::wstring& w) {
	if (w.empty()) return std::string();
	int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
		static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
	if (needed <= 0) return std::string();
	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
		out.data(), needed, nullptr, nullptr);
	return out;
}

}

bool spawn_and_attach_target(const run_target::launch_options_t& opts,
                             uint32_t* out_pid,
                             run_target::launch_result_t* out_result) {
	if (out_pid) *out_pid = 0;
	if (out_result) *out_result = run_target::launch_result_t{};

	if (opts.exe_path.empty()) {
		set_last_error("spawn_and_attach_target: empty exe path");
		diag::log_tagged_critical("spawn", "spawn_REJECTED_empty_exe_path");
		return false;
	}

	std::string exe_utf8 = narrow_utf8(opts.exe_path);
	std::string args_utf8 = narrow_utf8(opts.args);
	std::string cwd_utf8 = narrow_utf8(opts.working_dir);
	diag::log_tagged_critical_fmt("spawn",
		"spawn_request exe='%s' args_len=%zu cwd='%s' iso=%d block_net=%d kill_on_exit=%d mem_cap=%u auto_term=%u attach=%d",
		exe_utf8.c_str(), args_utf8.size(),
		cwd_utf8.empty() ? "<inherit>" : cwd_utf8.c_str(),
		static_cast<int>(opts.isolation),
		opts.block_network ? 1 : 0,
		opts.kill_on_host_exit ? 1 : 0,
		static_cast<unsigned>(opts.memory_cap_mb),
		static_cast<unsigned>(opts.auto_terminate_sec),
		opts.attach_after_resume ? 1 : 0);

	run_target::launch_result_t lr{};
	ULONGLONG launch_t0 = GetTickCount64();
	diag::log_tagged_critical_fmt("spawn",
		"spawn_pre_run_target_launch exe='%s' args='%.160s'",
		exe_utf8.c_str(), args_utf8.c_str());
	if (!run_target::launch(opts, lr)) {
		set_last_error(lr.error.empty() ? std::string("launch failed (no detail)") : lr.error);
		diag::log_tagged_critical_fmt("spawn",
			"spawn_launch_FAILED iso=%d err='%s' elapsed_ms=%llu",
			static_cast<int>(opts.isolation),
			lr.error.c_str(),
			static_cast<unsigned long long>(GetTickCount64() - launch_t0));
		run_target::cleanup(lr);
		return false;
	}
	diag::log_tagged_critical_fmt("spawn",
		"spawn_post_run_target_launch ok=1 pid=%u elapsed_ms=%llu",
		static_cast<unsigned>(lr.pid),
		static_cast<unsigned long long>(GetTickCount64() - launch_t0));

	diag::log_tagged_critical_fmt("spawn",
		"spawn_created pid=%u hProc=%p hThr=%p job=%p firewall='%s'",
		static_cast<unsigned>(lr.pid),
		reinterpret_cast<void*>(lr.process_handle),
		reinterpret_cast<void*>(lr.thread_handle),
		reinterpret_cast<void*>(lr.job_handle),
		lr.firewall_rule_name.c_str());

	bool can_attach = (lr.pid != 0)
		&& (opts.isolation != run_target::isolation_t::windows_sandbox);

	bool driver_ok = true;
	if (can_attach && opts.attach_after_resume) {
		ULONGLONG attach_t0 = GetTickCount64();
		diag::log_tagged_critical_fmt("spawn",
			"spawn_pre_driver_attach pid=%u driver_status='%s'",
			static_cast<unsigned>(lr.pid),
			driver_bridge::status().c_str());
		const uint32_t previous_pid = driver_bridge::attached_pid();
		if (previous_pid != 0 && previous_pid != lr.pid)
			stealth_engine::disable_for_detach(previous_pid, "debugger_engine.spawn_attach.replace");
		driver_ok = driver_bridge::attach(lr.pid);
		if (!driver_ok && previous_pid != 0 && driver_bridge::attached_pid() == previous_pid)
			(void)stealth_engine::ensure_default_enabled(previous_pid, "debugger_engine.spawn_attach.restore_failed_switch");
		const bool stealth_ok = driver_ok
			? stealth_engine::ensure_default_enabled(lr.pid, "debugger_engine.spawn_attach")
			: false;
		diag::log_tagged_critical_fmt("spawn",
			"spawn_post_driver_attach pid=%u ok=%d stealth_ok=%d elapsed_ms=%llu driver_pid=%u driver_status='%s' last_error='%s'",
			static_cast<unsigned>(lr.pid),
			driver_ok ? 1 : 0,
			stealth_ok ? 1 : 0,
			static_cast<unsigned long long>(GetTickCount64() - attach_t0),
			driver_bridge::attached_pid(),
			driver_bridge::status().c_str(),
			driver_bridge::last_error().c_str());
		if (!driver_ok) {
			std::string drv_err = driver_bridge::last_error();
			char err[384];
			std::snprintf(err, sizeof(err),
				"driver attach failed for pid=%u: %s",
				static_cast<unsigned>(lr.pid),
				drv_err.empty() ? "(no detail)" : drv_err.c_str());
			set_last_error(err);
			diag::log_tagged_critical_fmt("spawn",
				"spawn_driver_attach_FAILED pid=%u err='%s'",
				static_cast<unsigned>(lr.pid),
				drv_err.empty() ? "(no detail)" : drv_err.c_str());
			HANDLE p = reinterpret_cast<HANDLE>(lr.process_handle);
			if (p) TerminateProcess(p, 0xDEADu);
			run_target::cleanup(lr);
			return false;
		}
		diag::log_tagged_critical_fmt("spawn",
			"spawn_driver_attached pid=%u", static_cast<unsigned>(lr.pid));
	}

	if (lr.thread_handle != 0) {
		diag::log_tagged_critical_fmt("spawn",
			"spawn_pre_kernel_resume_thread pid=%u tid=%u thread_handle=%p",
			static_cast<unsigned>(lr.pid),
			static_cast<unsigned>(lr.thread_id),
			reinterpret_cast<void*>(lr.thread_handle));
		uint32_t prev_count = 0;
		const bool resumed = lr.thread_id != 0 && driver_bridge::resume_thread(lr.thread_id, &prev_count);
		if (!resumed) {
			const DWORD kernel_resume_gle = GetLastError();
			const std::string kernel_resume_error = driver_bridge::last_error();
			diag::log_tagged_critical_fmt("spawn",
				"spawn_kernel_resume_thread_FAILED pid=%u tid=%u driver_status='%s' last_error='%s'",
				static_cast<unsigned>(lr.pid),
				static_cast<unsigned>(lr.thread_id),
				driver_bridge::status().c_str(),
				driver_bridge::last_error().c_str());
			char err[320];
			std::snprintf(err, sizeof(err),
				"kernel resume_thread failed for tid=%u (gle=%lu: %s)",
				static_cast<unsigned>(lr.thread_id),
				static_cast<unsigned long>(kernel_resume_gle),
				kernel_resume_error.empty() ? "(no detail)" : kernel_resume_error.c_str());
			set_last_error(err);
			HANDLE p = reinterpret_cast<HANDLE>(lr.process_handle);
			if (p) TerminateProcess(p, 0xDEADu);
			run_target::cleanup(lr);
			return false;
		}
		diag::log_tagged_critical_fmt("spawn",
			"spawn_resume_thread_ok pid=%u tid=%u prev_suspend_count=%u kernel_path=1",
			static_cast<unsigned>(lr.pid),
			static_cast<unsigned>(lr.thread_id),
			static_cast<unsigned>(prev_count));
		HANDLE p = reinterpret_cast<HANDLE>(lr.process_handle);
		DWORD exit_code = STILL_ACTIVE;
		DWORD wait0 = p ? WaitForSingleObject(p, 0) : WAIT_FAILED;
		BOOL got_exit = p ? GetExitCodeProcess(p, &exit_code) : FALSE;
		diag::log_tagged_critical_fmt("spawn",
			"spawn_post_resume_process_status pid=%u wait0=0x%08lX got_exit=%d exit_code=0x%08lX gle=%lu",
			static_cast<unsigned>(lr.pid),
			static_cast<unsigned long>(wait0),
			got_exit ? 1 : 0,
			static_cast<unsigned long>(exit_code),
			got_exit ? 0 : GetLastError());
	}

	if (can_attach && driver_ok) {
		auto& st = g_state;
		st.target_pid = lr.pid;
		st.status.store(dbg_status_t::running);
		sync_attached_state();
	}

	{
		aida::events::binary_loaded_t evt;
		evt.binary_path = exe_utf8;
		evt.image_base = 0;
		evt.image_size = 0;
		aida::events::publish(aida::events::event_binary_loaded, evt);
	}

	char ok_msg[320];
	if (can_attach && driver_ok) {
		std::snprintf(ok_msg, sizeof(ok_msg),
			"Spawned and attached PID %u (%s)",
			static_cast<unsigned>(lr.pid), exe_utf8.c_str());
	} else if (lr.pid != 0) {
		std::snprintf(ok_msg, sizeof(ok_msg),
			"Spawned PID %u in isolated mode (%s)",
			static_cast<unsigned>(lr.pid), exe_utf8.c_str());
	} else {
		std::snprintf(ok_msg, sizeof(ok_msg),
			"Launched Windows Sandbox session for %s",
			exe_utf8.c_str());
	}
	push_log_message_locked(g_state, ok_msg);
	toast_notification::push(ok_msg, toast_notification::toast_type_t::info);

	if (out_pid) *out_pid = lr.pid;

	HANDLE p_handle = reinterpret_cast<HANDLE>(lr.process_handle);
	HANDLE t_handle = reinterpret_cast<HANDLE>(lr.thread_handle);
	if (out_result) {
		*out_result = lr;
		lr.process_handle = 0;
		lr.thread_handle = 0;
		lr.job_handle = 0;
		lr.firewall_rule_name.clear();
	} else {
		if (t_handle) {
			CloseHandle(t_handle);
			lr.thread_handle = 0;
		}
		if (p_handle) {
			CloseHandle(p_handle);
			lr.process_handle = 0;
		}
		if (lr.job_handle != 0) {
			diag::log_tagged_critical_fmt("spawn",
				"spawn_owns_job job=%p kill_on_host_exit=%d (handle kept open intentionally)",
				reinterpret_cast<void*>(lr.job_handle),
				opts.kill_on_host_exit ? 1 : 0);
		}
		if (!lr.firewall_rule_name.empty()) {
			diag::log_tagged_critical_fmt("spawn",
				"spawn_firewall_rule_persisted name='%s' (manual cleanup: netsh advfirewall firewall delete rule name=\"%s\")",
				lr.firewall_rule_name.c_str(), lr.firewall_rule_name.c_str());
		}
	}

	diag::log_tagged_critical_fmt("spawn",
		"spawn_exit_ok pid=%u", static_cast<unsigned>(out_pid ? *out_pid : 0u));
	return true;
}

bool spawn_and_attach_target(const std::wstring& exe_path,
                             const std::wstring& args,
                             const std::wstring& working_dir,
                             uint32_t* out_pid) {
	run_target::launch_options_t opts;
	opts.exe_path = exe_path;
	opts.args = args;
	opts.working_dir = working_dir;
	opts.isolation = run_target::isolation_t::same_desktop_jobbed;
	opts.block_network = false;
	opts.kill_on_host_exit = true;
	opts.attach_after_resume = true;
	opts.memory_cap_mb = 0;
	opts.auto_terminate_sec = 0;
	return spawn_and_attach_target(opts, out_pid, nullptr);
}

bool pause_target() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) {
		set_last_error("pause_target: no target attached");
		diag::log_tagged_fmt("debugger",
			"pause_target_REJECTED no_target");
		return false;
	}

	auto threads = driver_bridge::enumerate_threads();
	int suspended = 0;
	int failed = 0;
	for (const auto& t : threads) {
		if (t.owner_pid != st.target_pid) continue;
		if (driver_bridge::suspend_thread(t.tid))
			++suspended;
		else
			++failed;
	}

	st.status.store(dbg_status_t::paused);
	diag::log_tagged_fmt("debugger",
		"pause_target_done pid=%u suspended=%d failed=%d",
		static_cast<unsigned>(st.target_pid),
		suspended, failed);
	return suspended > 0 || threads.empty();
}

bool step_into() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0 || st.active_tid == 0) {
		set_last_error("step_into: no attached target or active thread");
		diag::log_tagged_fmt("debugger",
			"step_into_REJECTED pid=%u tid=%u",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(st.active_tid));
		return false;
	}
	st.status.store(dbg_status_t::stepping);

	auto step_start = std::chrono::steady_clock::now();
	auto regs = get_registers();
	if (regs.rip == 0) {
		set_last_error("step_into: rip cache is zero");
		st.status.store(dbg_status_t::paused);
		diag::log_tagged_fmt("debugger",
			"step_into_REJECTED rip_zero pid=%u tid=%u",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(st.active_tid));
		return false;
	}
	uint64_t pre_step_rip = regs.rip;
	diag::log_tagged_fmt("debugger",
		"step_into_begin pid=%u tid=%u rip=0x%llx",
		static_cast<unsigned>(st.target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(pre_step_rip));

	int rearm_bp_index = -1;
	uint64_t rearm_bp_address = 0;
	uint8_t  rearm_bp_original = 0;
	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		for (size_t i = 0; i < st.breakpoints.size(); ++i) {
			auto& bp = st.breakpoints[i];
			if (bp.type != bp_type_t::software) continue;
			if (bp.state == bp_state_t::disabled) continue;
			if (bp.is_internal) continue;
			if (bp.address != pre_step_rip) continue;
			if (bp.byte_written) continue;
			rearm_bp_index = static_cast<int>(i);
			rearm_bp_address = bp.address;
			rearm_bp_original = bp.original_byte;
			break;
		}
	}

	if (st.tracing.load()) {
		std::lock_guard<std::mutex> lk(st.trace_mutex);
		if (static_cast<int>(st.trace_log.size()) < st.trace_max_depth) {
			trace_record_t tr;
			tr.address = regs.rip;
			tr.regs = regs;
			tr.index = static_cast<int>(st.trace_log.size());

			std::vector<uint8_t> code;
			if (driver_bridge::read_memory(regs.rip, 16, code) && !code.empty()) {
				auto ins = zydis_decode_one(code.data(), static_cast<int>(code.size()), regs.rip);
				tr.disasm_text = std::string(ins.mnem) + " " + ins.ops;
			}
			st.trace_log.push_back(std::move(tr));
		}
	}

	{
		std::lock_guard<std::mutex> lk(st.trap_mtx);
		st.trap_signaled.store(false);
		st.pending_trap_address = pre_step_rip;
	}

	std::lock_guard<std::recursive_mutex> step_lk(thread_ctx_serializer());

	uint32_t previous_suspend_count = 0;
	driver_bridge::thread_context_t kctx{};
	if (!suspend_contextable_thread(st, kctx, previous_suspend_count)) {
		set_last_error("step_into: no contextable target thread");
		st.status.store(dbg_status_t::paused);
		return false;
	}
	driver_bridge::thread_context_t original_step_ctx = kctx;
	diag::log_tagged_fmt("debugger",
		"step_into_context_acquired pid=%u tid=%u rip=0x%llx rsp=0x%llx rflags=0x%llx previous_suspend=%u",
		static_cast<unsigned>(st.target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(kctx.rip),
		static_cast<unsigned long long>(kctx.rsp),
		static_cast<unsigned long long>(kctx.rflags),
		static_cast<unsigned>(previous_suspend_count));

	std::vector<uint8_t> step_code;
	const bool step_read_ok = driver_bridge::read_memory(kctx.rip, 16, step_code);
	if (step_read_ok && !step_code.empty()) {
		auto ins = zydis_decode_one(step_code.data(), static_cast<int>(step_code.size()), kctx.rip);
		uint32_t first4 = 0;
		for (size_t i = 0; i < step_code.size() && i < 4; ++i)
			first4 |= static_cast<uint32_t>(step_code[i]) << (i * 8);
		diag::log_tagged_fmt("debugger",
			"step_into_decode_probe pid=%u tid=%u rip=0x%llx read_ok=%d bytes=%zu first4=0x%08X mnem=%s ops=%s len=%u is_nop=%d",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(kctx.rip),
			step_read_ok ? 1 : 0,
			step_code.size(),
			static_cast<unsigned>(first4),
			ins.mnem,
			ins.ops,
			static_cast<unsigned>(ins.len),
			ins.is_nop ? 1 : 0);
		if (ins.is_nop && ins.len > 0 && ins.len <= 15) {
			kctx.rip += static_cast<uint64_t>(ins.len);
			kctx.rflags &= ~0x100ULL;
			if (!driver_bridge::set_thread_context(st.active_tid, kctx, ctx_mask_base)) {
				driver_bridge::set_thread_context(st.active_tid, original_step_ctx, ctx_mask_base);
				diag::log_tagged_fmt("debugger",
					"step_into_context_only_set_FAILED pid=%u tid=%u pre_rip=0x%llx desired_rip=0x%llx rsp=0x%llx prev_suspend=%u",
					static_cast<unsigned>(st.target_pid),
					static_cast<unsigned>(st.active_tid),
					static_cast<unsigned long long>(original_step_ctx.rip),
					static_cast<unsigned long long>(kctx.rip),
					static_cast<unsigned long long>(original_step_ctx.rsp),
					static_cast<unsigned>(previous_suspend_count));
				set_last_error("step_into: context-only step set_thread_context failed");
				st.status.store(dbg_status_t::paused);
				return false;
			}
			auto post_regs = capture_registers_from_context(kctx);
			{
				std::lock_guard<std::mutex> lk(st.reg_mutex);
				st.registers = post_regs;
			}
			signal_trap(post_regs.rip);
			invalidate_cache();
			release_step_suspend_if_previously_suspended(st.active_tid, previous_suspend_count);
			st.status.store(dbg_status_t::paused);
			auto step_dur_us = std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now() - step_start).count();
			diag::log_tagged_fmt("debugger",
				"step_into_context_only pid=%u tid=%u pre_rip=0x%llx post_rip=0x%llx duration_us=%lld",
				static_cast<unsigned>(st.target_pid),
				static_cast<unsigned>(st.active_tid),
				static_cast<unsigned long long>(pre_step_rip),
				static_cast<unsigned long long>(post_regs.rip),
				static_cast<long long>(step_dur_us));
			return true;
		}
	} else {
		diag::log_tagged_fmt("debugger",
			"step_into_decode_probe pid=%u tid=%u rip=0x%llx read_ok=%d bytes=%zu",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(kctx.rip),
			step_read_ok ? 1 : 0,
			step_code.size());
	}

	kctx.rflags |= 0x100ULL;
	diag::log_tagged_fmt("debugger",
		"step_into_trap_arm pid=%u tid=%u rip=0x%llx rsp=0x%llx original_rflags=0x%llx armed_rflags=0x%llx previous_suspend=%u",
		static_cast<unsigned>(st.target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(kctx.rip),
		static_cast<unsigned long long>(kctx.rsp),
		static_cast<unsigned long long>(original_step_ctx.rflags),
		static_cast<unsigned long long>(kctx.rflags),
		static_cast<unsigned>(previous_suspend_count));

	if (!driver_bridge::set_thread_context(st.active_tid, kctx, ctx_mask_base)) {
		driver_bridge::set_thread_context(st.active_tid, original_step_ctx, ctx_mask_base);
		diag::log_tagged_fmt("debugger",
			"step_into_trap_set_FAILED pid=%u tid=%u rip=0x%llx rsp=0x%llx prev_suspend=%u",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(original_step_ctx.rip),
			static_cast<unsigned long long>(original_step_ctx.rsp),
			static_cast<unsigned>(previous_suspend_count));
		set_last_error("step_into: set_thread_context failed");
		st.status.store(dbg_status_t::paused);
		return false;
	}

	if (!resume_thread_for_controlled_run(st.active_tid, previous_suspend_count)) {
		set_last_error("step_into: resume_thread failed");
		st.status.store(dbg_status_t::paused);
		return false;
	}
	diag::log_tagged_fmt("debugger",
		"step_into_thread_released pid=%u tid=%u pre_rip=0x%llx previous_suspend=%u",
		static_cast<unsigned>(st.target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(pre_step_rip),
		static_cast<unsigned>(previous_suspend_count));

	const uint32_t step_timeout_ms = 1500;
	auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(step_timeout_ms);
	register_set_t post_regs{};
	bool advanced = false;
	uint64_t last_probe_rip = 0;
	uint64_t last_probe_rsp = 0;
	uint64_t last_probe_rflags = 0;
	uint32_t probe_count = 0;
	while (std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
		driver_bridge::thread_context_t probe{};
		if (!driver_bridge::get_thread_context(st.active_tid, probe))
			continue;
		++probe_count;
		last_probe_rip = probe.rip;
		last_probe_rsp = probe.rsp;
		last_probe_rflags = probe.rflags;
		if (probe.rip != pre_step_rip) {
			if (!driver_bridge::suspend_thread(st.active_tid)) {
				diag::log_tagged_fmt("debugger",
					"step_into_probe_advanced_suspend_failed pid=%u tid=%u probe_rip=0x%llx",
					static_cast<unsigned>(st.target_pid),
					static_cast<unsigned>(st.active_tid),
					static_cast<unsigned long long>(probe.rip));
				continue;
			}
			driver_bridge::thread_context_t stable{};
			if (driver_bridge::get_thread_context(st.active_tid, stable)) {
				stable.rflags &= ~0x100ULL;
				driver_bridge::set_thread_context(st.active_tid, stable, ctx_mask_base);
				post_regs = capture_registers_from_context(stable);
				advanced = true;
				diag::log_tagged_fmt("debugger",
					"step_into_probe_advanced_stable pid=%u tid=%u pre_rip=0x%llx stable_rip=0x%llx stable_rsp=0x%llx stable_rflags=0x%llx probes=%u",
					static_cast<unsigned>(st.target_pid),
					static_cast<unsigned>(st.active_tid),
					static_cast<unsigned long long>(pre_step_rip),
					static_cast<unsigned long long>(stable.rip),
					static_cast<unsigned long long>(stable.rsp),
					static_cast<unsigned long long>(stable.rflags),
					static_cast<unsigned>(probe_count));
				break;
			}
			probe.rflags &= ~0x100ULL;
			driver_bridge::set_thread_context(st.active_tid, probe, ctx_mask_base);
			post_regs = capture_registers_from_context(probe);
			advanced = true;
			diag::log_tagged_fmt("debugger",
				"step_into_probe_advanced_using_probe_context pid=%u tid=%u probe_rip=0x%llx",
				static_cast<unsigned>(st.target_pid),
				static_cast<unsigned>(st.active_tid),
				static_cast<unsigned long long>(probe.rip));
			break;
		}
	}

	if (!advanced) {
		driver_bridge::suspend_thread(st.active_tid);
		driver_bridge::thread_context_t restore_ctx{};
		if (driver_bridge::get_thread_context(st.active_tid, restore_ctx)) {
			restore_ctx.rflags &= ~0x100ULL;
			driver_bridge::set_thread_context(st.active_tid, restore_ctx, ctx_mask_base);
		}
		st.status.store(dbg_status_t::paused);
		set_last_error("step_into: thread did not advance within timeout");
		uint32_t exit_code = 0;
		const bool alive = driver_bridge::attached_process_alive(&exit_code);
		diag::log_tagged_fmt("debugger",
			"step_into_TIMEOUT pid=%u tid=%u pre_rip=0x%llx last_probe_rip=0x%llx last_probe_rsp=0x%llx last_probe_rflags=0x%llx probes=%u timeout_ms=%u alive=%d exit_code=0x%08X",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(pre_step_rip),
			static_cast<unsigned long long>(last_probe_rip),
			static_cast<unsigned long long>(last_probe_rsp),
			static_cast<unsigned long long>(last_probe_rflags),
			static_cast<unsigned>(probe_count),
			static_cast<unsigned>(step_timeout_ms),
			alive ? 1 : 0,
			static_cast<unsigned>(exit_code));
		invalidate_cache();
		return false;
	}

	{
		std::lock_guard<std::mutex> lk(st.reg_mutex);
		st.registers = post_regs;
	}
	signal_trap(post_regs.rip);

	if (rearm_bp_index >= 0 && post_regs.rip != rearm_bp_address) {
		std::vector<uint8_t> cc{0xCC};
		if (driver_bridge::write_memory(rearm_bp_address, cc)) {
			std::lock_guard<std::mutex> lk(st.bp_mutex);
			if (rearm_bp_index < static_cast<int>(st.breakpoints.size()) &&
				st.breakpoints[static_cast<size_t>(rearm_bp_index)].address == rearm_bp_address) {
				st.breakpoints[static_cast<size_t>(rearm_bp_index)].byte_written = true;
				st.breakpoints[static_cast<size_t>(rearm_bp_index)].original_byte = rearm_bp_original;
			}
		}
	}

	auto bp_action = handle_breakpoint_hit(post_regs.rip);
	invalidate_cache();
	auto step_dur_us = std::chrono::duration_cast<std::chrono::microseconds>(
		std::chrono::steady_clock::now() - step_start).count();
	if (bp_action == bp_hit_action_t::resume) {
		st.status.store(dbg_status_t::running);
		driver_bridge::resume_thread(st.active_tid);
		diag::log_tagged_fmt("debugger",
			"step_into_done_resume pid=%u tid=%u pre_rip=0x%llx post_rip=0x%llx duration_us=%lld",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(pre_step_rip),
			static_cast<unsigned long long>(post_regs.rip),
			static_cast<long long>(step_dur_us));
		return true;
	}

	st.status.store(dbg_status_t::paused);
	diag::log_tagged_fmt("debugger",
		"step_into_done_paused pid=%u tid=%u pre_rip=0x%llx post_rip=0x%llx duration_us=%lld",
		static_cast<unsigned>(st.target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(pre_step_rip),
		static_cast<unsigned long long>(post_regs.rip),
		static_cast<long long>(step_dur_us));
	return true;
}

bool step_over() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) {
		set_last_error("step_over: no target attached");
		diag::log_tagged_fmt("debugger",
			"step_over_REJECTED no_target");
		return false;
	}

	auto regs = get_registers();
	if (regs.rip == 0) {
		set_last_error("step_over: rip cache is zero");
		diag::log_tagged_fmt("debugger",
			"step_over_REJECTED rip_zero pid=%u",
			static_cast<unsigned>(st.target_pid));
		return false;
	}

	std::vector<uint8_t> code;
	if (driver_bridge::read_memory(regs.rip, 16, code) && !code.empty()) {
		auto ins = zydis_decode_one(code.data(), static_cast<int>(code.size()), regs.rip);
		if (ins.is_call) {
			uint64_t target = regs.rip + static_cast<uint64_t>(ins.len);
			diag::log_tagged_fmt("debugger",
				"step_over_via_runto rip=0x%llx call_len=%d target=0x%llx",
				static_cast<unsigned long long>(regs.rip),
				ins.len,
				static_cast<unsigned long long>(target));
			return run_to_address(target, true, 2500);
		}
		diag::log_tagged_fmt("debugger",
			"step_over_via_step_into rip=0x%llx not_call",
			static_cast<unsigned long long>(regs.rip));
	} else {
		diag::log_tagged_fmt("debugger",
			"step_over_decode_read_failed rip=0x%llx fallback_step_into",
			static_cast<unsigned long long>(regs.rip));
	}

	return step_into();
}

bool step_out() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0 || st.active_tid == 0) {
		set_last_error("step_out: no attached target or active thread");
		diag::log_tagged_fmt("debugger",
			"step_out_REJECTED pid=%u tid=%u",
			static_cast<unsigned>(st.target_pid),
			static_cast<unsigned>(st.active_tid));
		return false;
	}

	st.status.store(dbg_status_t::stepping);
	uint64_t ret_addr = 0;
	uint32_t selected_tid = 0;

	{
		std::lock_guard<std::recursive_mutex> step_lk(thread_ctx_serializer());
		uint32_t previous_suspend_count = 0;
		driver_bridge::thread_context_t kctx{};
		if (!suspend_contextable_thread(st, kctx, previous_suspend_count)) {
			set_last_error("step_out: no contextable target thread");
			st.status.store(dbg_status_t::paused);
			return false;
		}
		selected_tid = st.active_tid;

		std::vector<uint8_t> ret_buf;
		if (!driver_bridge::read_memory(kctx.rsp, 8, ret_buf) || ret_buf.size() < 8) {
			release_step_suspend_if_previously_suspended(selected_tid, previous_suspend_count);
			set_last_error("step_out: stack read failed");
			st.status.store(dbg_status_t::paused);
			diag::log_tagged_fmt("debugger",
				"step_out_stack_read_FAILED tid=%u rsp=0x%llx",
				static_cast<unsigned>(selected_tid),
				static_cast<unsigned long long>(kctx.rsp));
			return false;
		}

		std::memcpy(&ret_addr, ret_buf.data(), 8);
		diag::log_tagged_fmt("debugger",
			"step_out_target tid=%u rip=0x%llx rsp=0x%llx ret_addr=0x%llx",
			static_cast<unsigned>(selected_tid),
			static_cast<unsigned long long>(kctx.rip),
			static_cast<unsigned long long>(kctx.rsp),
			static_cast<unsigned long long>(ret_addr));

		std::vector<uint8_t> code;
		if (driver_bridge::read_memory(kctx.rip, 16, code) && !code.empty()) {
			auto ins = zydis_decode_one(code.data(), static_cast<int>(code.size()), kctx.rip);
			if (ins.is_ret) {
				kctx.rip = ret_addr;
				kctx.rsp += 8;
				kctx.rflags &= ~0x100ULL;
				if (!driver_bridge::set_thread_context(selected_tid, kctx, ctx_mask_base)) {
					diag::log_tagged_fmt("debugger",
						"step_out_return_set_FAILED pid=%u tid=%u ret_addr=0x%llx rsp=0x%llx prev_suspend=%u",
						static_cast<unsigned>(st.target_pid),
						static_cast<unsigned>(selected_tid),
						static_cast<unsigned long long>(ret_addr),
						static_cast<unsigned long long>(kctx.rsp),
						static_cast<unsigned>(previous_suspend_count));
					set_last_error("step_out: return context set_thread_context failed");
					st.status.store(dbg_status_t::paused);
					return false;
				}
				auto post_regs = capture_registers_from_context(kctx);
				{
					std::lock_guard<std::mutex> lk(st.reg_mutex);
					st.registers = post_regs;
				}
				signal_trap(post_regs.rip);
				invalidate_cache();
				release_step_suspend_if_previously_suspended(selected_tid, previous_suspend_count);
				st.status.store(dbg_status_t::paused);
				diag::log_tagged_fmt("debugger",
					"step_out_context_return pid=%u tid=%u ret_addr=0x%llx rsp=0x%llx",
					static_cast<unsigned>(st.target_pid),
					static_cast<unsigned>(selected_tid),
					static_cast<unsigned long long>(post_regs.rip),
					static_cast<unsigned long long>(post_regs.rsp));
				return true;
			}
		}

		if (!resume_thread_for_controlled_run(selected_tid, previous_suspend_count)) {
			set_last_error("step_out: resume_thread failed");
			st.status.store(dbg_status_t::paused);
			return false;
		}
	}

	diag::log_tagged_fmt("debugger",
		"step_out_via_runto tid=%u ret_addr=0x%llx",
		static_cast<unsigned>(selected_tid),
		static_cast<unsigned long long>(ret_addr));
	return run_to_address(ret_addr, true, 2500);
}

bool run_to_address(uint64_t address, bool wait_for_completion, uint32_t timeout_ms) {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) {
		set_last_error("run_to_address: no target attached");
		diag::log_tagged_fmt("debugger",
			"run_to_address_REJECTED no_target addr=0x%llx",
			static_cast<unsigned long long>(address));
		return false;
	}

	const uint32_t target_pid = st.target_pid;
	const uint32_t active_tid_at_entry = st.active_tid;
	driver_bridge::memory_region_t region{};
	const bool region_ok = driver_bridge::query_memory_for(target_pid, address, region);
	uint32_t entry_exit_code = 0;
	const bool alive_at_entry = driver_bridge::attached_process_alive(&entry_exit_code);
	diag::log_tagged_fmt("debugger",
		"run_to_address_begin pid=%u active_tid=%u addr=0x%llx wait=%d timeout_ms=%u alive=%d exit_code=0x%08X region_ok=%d region_base=0x%llx region_size=0x%llx region_state=0x%08X region_protect=0x%08X region_type=0x%08X",
		static_cast<unsigned>(target_pid),
		static_cast<unsigned>(active_tid_at_entry),
		static_cast<unsigned long long>(address),
		wait_for_completion ? 1 : 0,
		static_cast<unsigned>(timeout_ms),
		alive_at_entry ? 1 : 0,
		static_cast<unsigned>(entry_exit_code),
		region_ok ? 1 : 0,
		static_cast<unsigned long long>(region.base),
		static_cast<unsigned long long>(region.size),
		static_cast<unsigned>(region.state),
		static_cast<unsigned>(region.protect),
		static_cast<unsigned>(region.type));

	if (wait_for_completion && active_tid_at_entry != 0) {
		uint32_t pre_previous_suspend = 0;
		driver_bridge::thread_context_t pre_ctx{};
		const bool pre_suspend_ok = driver_bridge::suspend_thread(active_tid_at_entry, &pre_previous_suspend);
		const bool pre_context_ok = pre_suspend_ok && driver_bridge::get_thread_context(active_tid_at_entry, pre_ctx);
		diag::log_tagged_fmt("debugger",
			"run_to_address_precheck pid=%u tid=%u suspend_ok=%d previous_suspend=%u context_ok=%d rip=0x%llx rsp=0x%llx rflags=0x%llx target=0x%llx",
			static_cast<unsigned>(target_pid),
			static_cast<unsigned>(active_tid_at_entry),
			pre_suspend_ok ? 1 : 0,
			static_cast<unsigned>(pre_previous_suspend),
			pre_context_ok ? 1 : 0,
			static_cast<unsigned long long>(pre_ctx.rip),
			static_cast<unsigned long long>(pre_ctx.rsp),
			static_cast<unsigned long long>(pre_ctx.rflags),
			static_cast<unsigned long long>(address));
		if (pre_context_ok && (pre_ctx.rip == address || pre_ctx.rip == address + 1)) {
			bool adjusted = false;
			if (pre_ctx.rip == address + 1) {
				pre_ctx.rip = address;
				adjusted = driver_bridge::set_thread_context(active_tid_at_entry, pre_ctx, ctx_mask_base);
			}
			bool release_added_suspend = false;
			uint32_t release_previous = 0;
			if (pre_suspend_ok && pre_previous_suspend > 0) {
				release_added_suspend = driver_bridge::resume_thread(active_tid_at_entry, &release_previous);
			}
			st.active_tid = active_tid_at_entry;
			{
				std::lock_guard<std::mutex> lk(st.reg_mutex);
				st.registers = capture_registers_from_context(pre_ctx);
			}
			signal_trap(address);
			st.status.store(dbg_status_t::paused);
			invalidate_cache();
			uint32_t exit_after = 0;
			const bool alive_after = driver_bridge::attached_process_alive(&exit_after);
			diag::log_tagged_fmt("debugger",
				"run_to_address_ALREADY_REACHED pid=%u tid=%u addr=0x%llx previous_suspend=%u adjusted=%d release_added_suspend=%d release_previous=%u alive=%d exit_code=0x%08X",
				static_cast<unsigned>(target_pid),
				static_cast<unsigned>(active_tid_at_entry),
				static_cast<unsigned long long>(address),
				static_cast<unsigned>(pre_previous_suspend),
				adjusted ? 1 : 0,
				release_added_suspend ? 1 : 0,
				static_cast<unsigned>(release_previous),
				alive_after ? 1 : 0,
				static_cast<unsigned>(exit_after));
			return true;
		}
		if (pre_suspend_ok) {
			uint32_t resume_previous = 0;
			const bool resume_ok = driver_bridge::resume_thread(active_tid_at_entry, &resume_previous);
			diag::log_tagged_fmt("debugger",
				"run_to_address_precheck_release pid=%u tid=%u resume_ok=%d resume_previous=%u previous_suspend=%u",
				static_cast<unsigned>(target_pid),
				static_cast<unsigned>(active_tid_at_entry),
				resume_ok ? 1 : 0,
				static_cast<unsigned>(resume_previous),
				static_cast<unsigned>(pre_previous_suspend));
		}
	}

	std::vector<uint8_t> orig_buf;
	SetLastError(ERROR_SUCCESS);
	const bool read_ok = driver_bridge::read_memory(address, 1, orig_buf);
	const DWORD read_gle = read_ok ? ERROR_SUCCESS : GetLastError();
	if (!read_ok || orig_buf.empty()) {
		set_last_error("run_to_address: read_memory failed");
		diag::log_tagged_fmt("debugger",
			"run_to_address_read_FAILED pid=%u active_tid=%u addr=0x%llx read_ok=%d bytes=%zu gle=%lu region_ok=%d region_base=0x%llx region_size=0x%llx region_state=0x%08X region_protect=0x%08X",
			static_cast<unsigned>(target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(address),
			read_ok ? 1 : 0,
			orig_buf.size(),
			static_cast<unsigned long>(read_gle),
			region_ok ? 1 : 0,
			static_cast<unsigned long long>(region.base),
			static_cast<unsigned long long>(region.size),
			static_cast<unsigned>(region.state),
			static_cast<unsigned>(region.protect));
		return false;
	}

	const uint8_t cc_byte = 0xCC;
	std::vector<uint8_t> cc_buf{cc_byte};
	SetLastError(ERROR_SUCCESS);
	const bool write_ok = driver_bridge::write_memory(address, cc_buf);
	const DWORD write_gle = write_ok ? ERROR_SUCCESS : GetLastError();
	if (!write_ok) {
		set_last_error("run_to_address: write_memory failed");
		diag::log_tagged_fmt("debugger",
			"run_to_address_write_FAILED pid=%u active_tid=%u addr=0x%llx original=0x%02X gle=%lu region_ok=%d region_base=0x%llx region_size=0x%llx region_state=0x%08X region_protect=0x%08X",
			static_cast<unsigned>(target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(address),
			static_cast<unsigned>(orig_buf[0]),
			static_cast<unsigned long>(write_gle),
			region_ok ? 1 : 0,
			static_cast<unsigned long long>(region.base),
			static_cast<unsigned long long>(region.size),
			static_cast<unsigned>(region.state),
			static_cast<unsigned>(region.protect));
		return false;
	}
	diag::log_tagged_fmt("debugger",
		"run_to_address_breakpoint_written pid=%u active_tid=%u addr=0x%llx original=0x%02X replacement=0x%02X",
		static_cast<unsigned>(target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(address),
		static_cast<unsigned>(orig_buf[0]),
		static_cast<unsigned>(cc_byte));

	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);

		bool already_present = false;
		for (auto& ibp : st.internal_breakpoints) {
			if (ibp.address == address) {
				ibp.active = true;
				already_present = true;
				break;
			}
		}
		if (!already_present) {
			internal_bp_t ibp;
			ibp.address = address;
			ibp.original_byte = orig_buf[0];
			ibp.active = true;
			st.internal_breakpoints.push_back(ibp);
		}

		breakpoint_t bp;
		bp.address = address;
		bp.type = bp_type_t::software;
		bp.state = bp_state_t::one_shot;
		bp.is_internal = true;
		bp.original_byte = orig_buf[0];
		bp.byte_written = true;
		st.breakpoints.push_back(std::move(bp));
	}

	{
		std::lock_guard<std::mutex> lk(st.trap_mtx);
		st.trap_signaled.store(false);
		st.pending_trap_address = address;
	}

	auto threads = driver_bridge::enumerate_threads();
	int resume_attempted = 0;
	int resume_succeeded = 0;
	int resume_failed = 0;
	for (const auto& t : threads) {
		if (t.owner_pid != st.target_pid) continue;
		++resume_attempted;
		uint32_t resume_previous = 0;
		SetLastError(ERROR_SUCCESS);
		const bool resume_ok = driver_bridge::resume_thread(t.tid, &resume_previous);
		const DWORD resume_gle = resume_ok ? ERROR_SUCCESS : GetLastError();
		if (resume_ok)
			++resume_succeeded;
		else
			++resume_failed;
		diag::log_tagged_fmt("debugger",
			"run_to_address_resume_thread pid=%u tid=%u ok=%d previous_suspend=%u gle=%lu",
			static_cast<unsigned>(target_pid),
			static_cast<unsigned>(t.tid),
			resume_ok ? 1 : 0,
			static_cast<unsigned>(resume_previous),
			static_cast<unsigned long>(resume_gle));
	}

	st.status.store(dbg_status_t::running);
	diag::log_tagged_fmt("debugger",
		"run_to_address_resume_summary pid=%u active_tid=%u addr=0x%llx attempted=%d succeeded=%d failed=%d wait=%d",
		static_cast<unsigned>(target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(address),
		resume_attempted,
		resume_succeeded,
		resume_failed,
		wait_for_completion ? 1 : 0);

	if (!wait_for_completion) {
		diag::log_tagged_fmt("debugger",
			"run_to_address_armed pid=%u active_tid=%u addr=0x%llx original=0x%02X wait=0",
			static_cast<unsigned>(target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(address),
			static_cast<unsigned>(orig_buf[0]));
		return true;
	}

	const auto wait_start = std::chrono::steady_clock::now();
	auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(timeout_ms);
	bool reached = false;
	uint32_t hit_tid = 0;
	uint64_t last_probe_rip = 0;
	uint64_t last_probe_rsp = 0;
	uint64_t last_probe_rflags = 0;
	uint32_t last_probe_tid = 0;
	uint32_t probe_count = 0;
	uint32_t context_ok_count = 0;
	uint32_t context_fail_count = 0;
	while (std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		auto probe_threads = driver_bridge::enumerate_threads();
		for (const auto& th : probe_threads) {
			if (th.owner_pid != st.target_pid) continue;
			++probe_count;
			driver_bridge::thread_context_t kctx{};
			if (!driver_bridge::get_thread_context(th.tid, kctx)) {
				++context_fail_count;
				continue;
			}
			++context_ok_count;
			last_probe_tid = th.tid;
			last_probe_rip = kctx.rip;
			last_probe_rsp = kctx.rsp;
			last_probe_rflags = kctx.rflags;
			if (kctx.rip == address || kctx.rip == address + 1) {
				reached = true;
				hit_tid = th.tid;
				if (kctx.rip == address + 1) {
					kctx.rip = address;
					driver_bridge::set_thread_context(th.tid, kctx, ctx_mask_base);
				}
				break;
			}
		}
		if (reached) break;
	}

	bool hit_suspend_ok = false;
	bool hit_context_ok = false;
	bool hit_adjusted = false;
	uint32_t hit_previous_suspend = 0;
	uint64_t hit_final_rip = 0;
	uint64_t hit_final_rsp = 0;
	uint64_t hit_final_rflags = 0;
	if (reached && hit_tid != 0) {
		SetLastError(ERROR_SUCCESS);
		hit_suspend_ok = driver_bridge::suspend_thread(hit_tid, &hit_previous_suspend);
		const DWORD hit_suspend_gle = hit_suspend_ok ? ERROR_SUCCESS : GetLastError();
		driver_bridge::thread_context_t hit_ctx{};
		if (hit_suspend_ok) {
			hit_context_ok = driver_bridge::get_thread_context(hit_tid, hit_ctx);
			hit_final_rip = hit_ctx.rip;
			hit_final_rsp = hit_ctx.rsp;
			hit_final_rflags = hit_ctx.rflags;
			if (hit_context_ok && hit_ctx.rip == address + 1) {
				hit_ctx.rip = address;
				hit_adjusted = driver_bridge::set_thread_context(hit_tid, hit_ctx, ctx_mask_base);
				hit_final_rip = hit_ctx.rip;
			}
			if (hit_context_ok) {
				std::lock_guard<std::mutex> lk(st.reg_mutex);
				st.registers = capture_registers_from_context(hit_ctx);
			}
		}
		diag::log_tagged_fmt("debugger",
			"run_to_address_hit_suspend pid=%u tid=%u suspend_ok=%d previous_suspend=%u gle=%lu context_ok=%d rip=0x%llx rsp=0x%llx rflags=0x%llx adjusted=%d target=0x%llx",
			static_cast<unsigned>(target_pid),
			static_cast<unsigned>(hit_tid),
			hit_suspend_ok ? 1 : 0,
			static_cast<unsigned>(hit_previous_suspend),
			static_cast<unsigned long>(hit_suspend_gle),
			hit_context_ok ? 1 : 0,
			static_cast<unsigned long long>(hit_final_rip),
			static_cast<unsigned long long>(hit_final_rsp),
			static_cast<unsigned long long>(hit_final_rflags),
			hit_adjusted ? 1 : 0,
			static_cast<unsigned long long>(address));
	}

	struct suspended_cleanup_thread_t {
		uint32_t tid = 0;
		uint32_t previous_suspend = 0;
		bool suspend_ok = false;
		bool context_ok = false;
		bool adjusted = false;
		uint64_t rip = 0;
		uint64_t rsp = 0;
		uint64_t rflags = 0;
	};
	std::vector<suspended_cleanup_thread_t> cleanup_threads;
	if (!reached) {
		auto cleanup_probe_threads = driver_bridge::enumerate_threads();
		for (const auto& th : cleanup_probe_threads) {
			if (th.owner_pid != target_pid)
				continue;
			suspended_cleanup_thread_t item;
			item.tid = th.tid;
			SetLastError(ERROR_SUCCESS);
			item.suspend_ok = driver_bridge::suspend_thread(th.tid, &item.previous_suspend);
			const DWORD suspend_gle = item.suspend_ok ? ERROR_SUCCESS : GetLastError();
			driver_bridge::thread_context_t kctx{};
			if (item.suspend_ok) {
				item.context_ok = driver_bridge::get_thread_context(th.tid, kctx);
				item.rip = kctx.rip;
				item.rsp = kctx.rsp;
				item.rflags = kctx.rflags;
				if (item.context_ok && kctx.rip == address + 1) {
					kctx.rip = address;
					item.adjusted = driver_bridge::set_thread_context(th.tid, kctx, ctx_mask_base);
					item.rip = kctx.rip;
				}
			}
			diag::log_tagged_fmt("debugger",
				"run_to_address_timeout_suspend pid=%u tid=%u suspend_ok=%d previous_suspend=%u gle=%lu context_ok=%d rip=0x%llx rsp=0x%llx rflags=0x%llx adjusted=%d",
				static_cast<unsigned>(target_pid),
				static_cast<unsigned>(item.tid),
				item.suspend_ok ? 1 : 0,
				static_cast<unsigned>(item.previous_suspend),
				static_cast<unsigned long>(suspend_gle),
				item.context_ok ? 1 : 0,
				static_cast<unsigned long long>(item.rip),
				static_cast<unsigned long long>(item.rsp),
				static_cast<unsigned long long>(item.rflags),
				item.adjusted ? 1 : 0);
			cleanup_threads.push_back(item);
		}
	}

	bool restore_attempted = false;
	bool restore_ok = false;
	DWORD restore_gle = ERROR_SUCCESS;
	int internal_removed = 0;
	int public_removed = 0;
	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		for (auto it = st.internal_breakpoints.begin(); it != st.internal_breakpoints.end(); ) {
			if (it->address == address && it->active) {
				std::vector<uint8_t> restore{it->original_byte};
				SetLastError(ERROR_SUCCESS);
				restore_attempted = true;
				restore_ok = driver_bridge::write_memory(address, restore);
				restore_gle = restore_ok ? ERROR_SUCCESS : GetLastError();
				it = st.internal_breakpoints.erase(it);
				++internal_removed;
			} else {
				++it;
			}
		}
		for (auto it = st.breakpoints.begin(); it != st.breakpoints.end(); ) {
			if (it->address == address && it->is_internal &&
				it->state == bp_state_t::one_shot && it->byte_written) {
				it = st.breakpoints.erase(it);
				++public_removed;
			} else {
				++it;
			}
		}
	}
	diag::log_tagged_fmt("debugger",
		"run_to_address_breakpoint_cleanup pid=%u active_tid=%u addr=0x%llx restore_attempted=%d restore_ok=%d restore_gle=%lu internal_removed=%d public_removed=%d",
		static_cast<unsigned>(target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(address),
		restore_attempted ? 1 : 0,
		restore_ok ? 1 : 0,
		static_cast<unsigned long>(restore_gle),
		internal_removed,
		public_removed);

	if (!reached) {
		set_last_error("run_to_address: timed out waiting for trap");
		st.status.store(dbg_status_t::paused);
		invalidate_cache();
		uint32_t exit_after = 0;
		const bool alive_after = driver_bridge::attached_process_alive(&exit_after);
		const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - wait_start).count();
		diag::log_tagged_fmt("debugger",
			"run_to_address_TIMEOUT pid=%u active_tid=%u addr=0x%llx timeout_ms=%u elapsed_ms=%lld probes=%u context_ok=%u context_fail=%u last_tid=%u last_rip=0x%llx last_rsp=0x%llx last_rflags=0x%llx cleanup_suspended=%zu restore_ok=%d alive=%d exit_code=0x%08X",
			static_cast<unsigned>(target_pid),
			static_cast<unsigned>(st.active_tid),
			static_cast<unsigned long long>(address),
			static_cast<unsigned>(timeout_ms),
			static_cast<long long>(elapsed_ms),
			static_cast<unsigned>(probe_count),
			static_cast<unsigned>(context_ok_count),
			static_cast<unsigned>(context_fail_count),
			static_cast<unsigned>(last_probe_tid),
			static_cast<unsigned long long>(last_probe_rip),
			static_cast<unsigned long long>(last_probe_rsp),
			static_cast<unsigned long long>(last_probe_rflags),
			cleanup_threads.size(),
			restore_ok ? 1 : 0,
			alive_after ? 1 : 0,
			static_cast<unsigned>(exit_after));
		return false;
	}

	if (hit_tid != 0) {
		st.active_tid = hit_tid;
		signal_trap(address);
	}
	st.status.store(dbg_status_t::paused);
	invalidate_cache();
	uint32_t exit_after = 0;
	const bool alive_after = driver_bridge::attached_process_alive(&exit_after);
	const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - wait_start).count();
	diag::log_tagged_fmt("debugger",
		"run_to_address_reached pid=%u active_tid=%u addr=0x%llx hit_tid=%u elapsed_ms=%lld probes=%u context_ok=%u context_fail=%u hit_suspend_ok=%d hit_context_ok=%d hit_rip=0x%llx hit_rsp=0x%llx restore_ok=%d alive=%d exit_code=0x%08X",
		static_cast<unsigned>(target_pid),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(address),
		static_cast<unsigned>(hit_tid),
		static_cast<long long>(elapsed_ms),
		static_cast<unsigned>(probe_count),
		static_cast<unsigned>(context_ok_count),
		static_cast<unsigned>(context_fail_count),
		hit_suspend_ok ? 1 : 0,
		hit_context_ok ? 1 : 0,
		static_cast<unsigned long long>(hit_final_rip),
		static_cast<unsigned long long>(hit_final_rsp),
		restore_ok ? 1 : 0,
		alive_after ? 1 : 0,
		static_cast<unsigned>(exit_after));
	return true;
}


register_set_t get_registers() {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "get_registers: entry pid=%u tid=%u", st.target_pid, st.active_tid);
	sync_attached_state();
	if (st.target_pid == 0 || st.active_tid == 0) {
		diag::log_tagged_fmt("dbg_engine", "get_registers: not attached (pid=%u tid=%u)", st.target_pid, st.active_tid);
		return {};
	}

	std::lock_guard<std::recursive_mutex> ctx_lk(thread_ctx_serializer());

	uint32_t saved_suspend_count = 0;
	bool suspended = driver_bridge::suspend_thread(st.active_tid, &saved_suspend_count);

	driver_bridge::thread_context_t kctx{};
	if (driver_bridge::get_thread_context(st.active_tid, kctx)) {
		std::lock_guard<std::mutex> lk(st.reg_mutex);
		st.registers.rax = kctx.rax; st.registers.rbx = kctx.rbx;
		st.registers.rcx = kctx.rcx; st.registers.rdx = kctx.rdx;
		st.registers.rsi = kctx.rsi; st.registers.rdi = kctx.rdi;
		st.registers.rbp = kctx.rbp; st.registers.rsp = kctx.rsp;
		st.registers.r8  = kctx.r8;  st.registers.r9  = kctx.r9;
		st.registers.r10 = kctx.r10; st.registers.r11 = kctx.r11;
		st.registers.r12 = kctx.r12; st.registers.r13 = kctx.r13;
		st.registers.r14 = kctx.r14; st.registers.r15 = kctx.r15;
		st.registers.rip = kctx.rip; st.registers.rflags = kctx.rflags;
		st.registers.cs = kctx.cs; st.registers.ss = kctx.ss;
		st.registers.dr0 = kctx.dr0; st.registers.dr1 = kctx.dr1;
		st.registers.dr2 = kctx.dr2; st.registers.dr3 = kctx.dr3;
		st.registers.dr6 = kctx.dr6; st.registers.dr7 = kctx.dr7;
	}

	if (suspended)
		driver_bridge::resume_thread(st.active_tid);

	std::lock_guard<std::mutex> lk(st.reg_mutex);
	diag::log_tagged_fmt("dbg_engine", "get_registers: result RIP=0x%llX RAX=0x%llX RSP=0x%llX tid=%u", (unsigned long long)st.registers.rip, (unsigned long long)st.registers.rax, (unsigned long long)st.registers.rsp, st.active_tid);
	return st.registers;
}

bool set_register(const std::string& name, uint64_t value) {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0 || st.active_tid == 0) return false;

	std::lock_guard<std::recursive_mutex> ctx_lk(thread_ctx_serializer());

	uint32_t saved_suspend_count = 0;
	bool suspended = driver_bridge::suspend_thread(st.active_tid, &saved_suspend_count);

	driver_bridge::thread_context_t kctx{};
	if (!driver_bridge::get_thread_context(st.active_tid, kctx)) {
		if (suspended) driver_bridge::resume_thread(st.active_tid);
		return false;
	}

	auto lower = name;
	for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	const uint64_t register_mask = register_context_mask(lower);

	if      (lower == "rax") kctx.rax = value;
	else if (lower == "rbx") kctx.rbx = value;
	else if (lower == "rcx") kctx.rcx = value;
	else if (lower == "rdx") kctx.rdx = value;
	else if (lower == "rsi") kctx.rsi = value;
	else if (lower == "rdi") kctx.rdi = value;
	else if (lower == "rbp") kctx.rbp = value;
	else if (lower == "rsp") kctx.rsp = value;
	else if (lower == "r8")  kctx.r8  = value;
	else if (lower == "r9")  kctx.r9  = value;
	else if (lower == "r10") kctx.r10 = value;
	else if (lower == "r11") kctx.r11 = value;
	else if (lower == "r12") kctx.r12 = value;
	else if (lower == "r13") kctx.r13 = value;
	else if (lower == "r14") kctx.r14 = value;
	else if (lower == "r15") kctx.r15 = value;
	else if (lower == "rip") kctx.rip = value;
	else if (lower == "rflags" || lower == "eflags") kctx.rflags = value;
	else {
		if (suspended) driver_bridge::resume_thread(st.active_tid);
		return false;
	}

	bool ok = driver_bridge::set_thread_context(st.active_tid, kctx, register_mask);
	diag::log_tagged_fmt("cpu",
		"set_register name='%s' value=0x%llx tid=%u mask=0x%llx ok=%d",
		name.c_str(),
		static_cast<unsigned long long>(value),
		static_cast<unsigned>(st.active_tid),
		static_cast<unsigned long long>(register_mask),
		ok ? 1 : 0);

	if (suspended) driver_bridge::resume_thread(st.active_tid);

	if (ok) {
		std::lock_guard<std::mutex> lk(st.reg_mutex);

		if      (lower == "rax") st.registers.rax = value;
		else if (lower == "rbx") st.registers.rbx = value;
		else if (lower == "rcx") st.registers.rcx = value;
		else if (lower == "rdx") st.registers.rdx = value;
		else if (lower == "rsi") st.registers.rsi = value;
		else if (lower == "rdi") st.registers.rdi = value;
		else if (lower == "rbp") st.registers.rbp = value;
		else if (lower == "rsp") st.registers.rsp = value;
		else if (lower == "r8")  st.registers.r8  = value;
		else if (lower == "r9")  st.registers.r9  = value;
		else if (lower == "r10") st.registers.r10 = value;
		else if (lower == "r11") st.registers.r11 = value;
		else if (lower == "r12") st.registers.r12 = value;
		else if (lower == "r13") st.registers.r13 = value;
		else if (lower == "r14") st.registers.r14 = value;
		else if (lower == "r15") st.registers.r15 = value;
		else if (lower == "rip") st.registers.rip = value;
		else if (lower == "rflags" || lower == "eflags") st.registers.rflags = value;
	}
	return ok;
}


std::vector<stack_frame_t> get_call_stack() {
	auto& st = g_state;
	const auto started = std::chrono::steady_clock::now();
	diag::log_tagged_fmt("dbg_engine", "get_call_stack: entry pid=%u tid=%u", st.target_pid, st.active_tid);
	std::vector<stack_frame_t> frames;

	const auto regs_started = std::chrono::steady_clock::now();
	auto regs = get_registers();
	const uint64_t regs_elapsed_us = resolver_elapsed_us(regs_started);
	diag::log_tagged_fmt("dbg_engine",
		"get_call_stack: registers rip=0x%llX rsp=0x%llX rbp=0x%llX elapsed_us=%llu",
		static_cast<unsigned long long>(regs.rip),
		static_cast<unsigned long long>(regs.rsp),
		static_cast<unsigned long long>(regs.rbp),
		static_cast<unsigned long long>(regs_elapsed_us));
	if (regs.rip == 0 || regs.rsp == 0) {
		diag::log_tagged_fmt("dbg_engine", "get_call_stack: empty regs (RIP=0 or RSP=0), returning empty elapsed_us=%llu",
			static_cast<unsigned long long>(resolver_elapsed_us(started)));
		publish_call_stack_resolutions({});
		return frames;
	}

	const auto modules_started = std::chrono::steady_clock::now();
	auto modules = driver_bridge::enumerate_modules();
	diag::log_tagged_fmt("dbg_engine",
		"get_call_stack: modules count=%zu elapsed_us=%llu",
		modules.size(),
		static_cast<unsigned long long>(resolver_elapsed_us(modules_started)));
	std::vector<call_stack_symbol_resolution_t> resolution_records;
	resolution_records.reserve(65);
	std::unordered_map<uint64_t, call_stack_symbol_resolution_t> local_resolution_cache;
	local_resolution_cache.reserve(65);
	const auto symbol_budget_deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(k_call_stack_total_symbol_budget_us);
	std::size_t cache_hits = 0;
	std::size_t cache_misses = 0;
	std::size_t budget_degraded = 0;

	auto resolve = [&](uint64_t addr, std::size_t frame_index) -> stack_frame_t {
		stack_frame_t f;
		f.address = addr;
		const auto frame_started = std::chrono::steady_clock::now();
		call_stack_symbol_resolution_t symbol;
		auto cache_it = local_resolution_cache.find(addr);
		if (cache_it != local_resolution_cache.end()) {
			symbol = cache_it->second;
			++cache_hits;
			symbol.elapsed_us = 0;
			symbol.status += ";cache_hit";
		} else {
			++cache_misses;
			const auto per_frame_deadline = std::min(symbol_budget_deadline, std::chrono::steady_clock::now() + std::chrono::microseconds(k_call_stack_frame_symbol_budget_us));
			symbol = resolve_call_stack_symbol(addr, modules, per_frame_deadline);
			local_resolution_cache.emplace(addr, symbol);
		}
		if (symbol.source == "module_rva" && symbol.status.find("budget") != std::string::npos)
			++budget_degraded;
		if (symbol.function_name.empty()) {
			diag::log_tagged_fmt("dbg_engine",
				"get_call_stack_unresolved_frame addr=0x%llX module=%s offset=0x%llX source=%s status=%s elapsed_us=%llu",
				static_cast<unsigned long long>(symbol.address),
				symbol.module_name.empty() ? "(none)" : symbol.module_name.c_str(),
				static_cast<unsigned long long>(symbol.module_offset),
				symbol.source.c_str(),
				symbol.status.c_str(),
				static_cast<unsigned long long>(symbol.elapsed_us));
		}
		diag::log_tagged_fmt("dbg_engine",
			"get_call_stack_frame_symbol index=%zu addr=0x%llX module=%s offset=0x%llX function=%s source=%s status=%s resolver_elapsed_us=%llu frame_elapsed_us=%llu budget_remaining_us=%lld",
			frame_index,
			static_cast<unsigned long long>(symbol.address),
			symbol.module_name.empty() ? "(none)" : symbol.module_name.c_str(),
			static_cast<unsigned long long>(symbol.module_offset),
			symbol.function_name.empty() ? "(empty)" : symbol.function_name.c_str(),
			symbol.source.c_str(),
			symbol.status.c_str(),
			static_cast<unsigned long long>(symbol.elapsed_us),
			static_cast<unsigned long long>(resolver_elapsed_us(frame_started)),
			static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(symbol_budget_deadline - std::chrono::steady_clock::now()).count()));
		f.module_name = symbol.module_name;
		f.module_offset = symbol.module_offset;
		f.function_name = symbol.function_name;
		resolution_records.push_back(std::move(symbol));
		return f;
	};


	auto first = resolve(regs.rip, 0);
	frames.push_back(std::move(first));


	uint64_t sp = regs.rsp;
	std::vector<uint8_t> stack_bytes;
	const auto stack_read_started = std::chrono::steady_clock::now();
	const bool stack_read_ok = driver_bridge::read_memory(sp, 64u * sizeof(uint64_t), stack_bytes);
	bool stack_read_fallback = false;
	std::size_t stack_read_failures = stack_read_ok ? 0 : 1;
	std::size_t stack_qwords = stack_read_ok ? stack_bytes.size() / sizeof(uint64_t) : 0;
	if (stack_qwords > 64)
		stack_qwords = 64;
	if (stack_qwords == 0) {
		stack_read_fallback = true;
		stack_bytes.clear();
		for (std::size_t i = 0; i < 64; ++i) {
			std::vector<uint8_t> word;
			if (!driver_bridge::read_memory(sp + i * sizeof(uint64_t), sizeof(uint64_t), word) || word.size() < sizeof(uint64_t)) {
				++stack_read_failures;
				break;
			}
			stack_bytes.insert(stack_bytes.end(), word.begin(), word.begin() + sizeof(uint64_t));
			++stack_qwords;
		}
	}
	const uint64_t stack_read_elapsed_us = resolver_elapsed_us(stack_read_started);
	std::size_t invalid_stack_words = 0;
	diag::log_tagged_fmt("dbg_engine",
		"get_call_stack: stack_read rsp=0x%llX ok=%d fallback=%d bytes=%zu qwords=%zu failures=%zu elapsed_us=%llu",
		static_cast<unsigned long long>(sp),
		stack_read_ok ? 1 : 0,
		stack_read_fallback ? 1 : 0,
		stack_bytes.size(),
		stack_qwords,
		stack_read_failures,
		static_cast<unsigned long long>(stack_read_elapsed_us));
	for (std::size_t i = 0; i < stack_qwords; ++i) {
		uint64_t ret = 0;
		std::memcpy(&ret, stack_bytes.data() + i * sizeof(uint64_t), sizeof(ret));
		bool valid = false;
		for (const auto& m : modules) {
			if (module_contains_address(m, ret)) {
				valid = true;
				break;
			}
		}

		if (valid && ret > 0x10000) {
			auto frame = resolve(ret, frames.size());
			frame.return_addr = ret;
			frames.push_back(std::move(frame));
		}
		else {
			++invalid_stack_words;
		}
	}

	{
		std::lock_guard<std::mutex> lk(st.stack_mutex);
		st.call_stack = frames;
	}
	publish_call_stack_resolutions(resolution_records);

	diag::log_tagged_fmt("dbg_engine",
		"get_call_stack: result frames=%zu modules=%zu stack_qwords=%zu stack_read_failures=%zu invalid_stack_words=%zu cache_hits=%zu cache_misses=%zu budget_degraded=%zu elapsed_us=%llu",
		frames.size(),
		modules.size(),
		stack_qwords,
		stack_read_failures,
		invalid_stack_words,
		cache_hits,
		cache_misses,
		budget_degraded,
		static_cast<unsigned long long>(resolver_elapsed_us(started)));
	return frames;
}


std::vector<memory_region_t> get_memory_map() {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "get_memory_map: entry pid=%u", st.target_pid);
	auto regions = driver_bridge::enumerate_memory_regions(4096);
	auto modules = driver_bridge::enumerate_modules();

	std::vector<memory_region_t> map;
	map.reserve(regions.size());

	for (const auto& r : regions) {
		memory_region_t entry;
		entry.base = r.base;
		entry.size = static_cast<uint64_t>(r.size);
		entry.protect = r.protect;
		entry.state = r.state;
		entry.type = r.type;

		for (const auto& m : modules) {
			if (r.base >= m.base && r.base < m.base + m.size) {
				entry.module_name = m.name;
				break;
			}
		}

		map.push_back(std::move(entry));
	}

	{
		std::lock_guard<std::mutex> lk(st.memmap_mutex);
		st.memory_map = map;
	}

	diag::log_tagged_fmt("dbg_engine", "get_memory_map: result regions=%zu", map.size());
	return map;
}


int add_watch(const std::string& expression) {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "add_watch: expr='%s'", expression.c_str());
	std::lock_guard<std::mutex> lk(st.watch_mutex);
	watch_entry_t w;
	w.expression = expression;
	st.watches.push_back(std::move(w));
	int idx = static_cast<int>(st.watches.size()) - 1;
	diag::log_tagged_fmt("dbg_engine", "add_watch: added at index=%d", idx);
	return idx;
}

bool remove_watch(int index) {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "remove_watch: index=%d", index);
	std::lock_guard<std::mutex> lk(st.watch_mutex);
	if (index < 0 || index >= static_cast<int>(st.watches.size())) {
		diag::log_tagged_fmt("dbg_engine", "remove_watch: index=%d out of range (size=%zu)", index, st.watches.size());
		return false;
	}
	st.watches.erase(st.watches.begin() + index);
	diag::log_tagged_fmt("dbg_engine", "remove_watch: removed index=%d", index);
	return true;
}

void refresh_watches() {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "refresh_watches: entry watch_count=%zu", st.watches.size());
	auto regs = get_registers();
	expression_eval::context_t ctx = build_eval_context(regs);
	std::lock_guard<std::mutex> lk(st.watch_mutex);

	for (auto& w : st.watches) {
		if (w.expression.empty()) {
			w.value.clear();
			w.type.clear();
			w.error = "empty expression";
			w.valid = false;
			continue;
		}

		auto er = expression_eval::evaluate(w.expression, ctx);
		if (!er.ok) {
			w.value.clear();
			w.type.clear();
			w.error = er.error;
			w.valid = false;
			continue;
		}

		char hex[20];
		snprintf(hex, sizeof(hex), "0x%016" PRIX64, er.value);
		w.value = hex;
		w.type = "uint64";
		w.error.clear();
		w.valid = true;
	}
}


bool start_trace(int max_records) {
	auto& st = g_state;
	if (st.tracing.load()) {
		diag::log_tagged_fmt("trace",
			"start_trace_REJECTED already_tracing");
		return false;
	}
	st.trace_max_depth = max_records;
	{
		std::lock_guard<std::mutex> lk(st.trace_mutex);
		st.trace_log.clear();
	}
	st.tracing.store(true);
	diag::log_tagged_fmt("trace",
		"start_trace_ok max_records=%d", max_records);
	return true;
}

bool stop_trace() {
	auto& st = g_state;
	bool was = st.tracing.exchange(false);
	size_t n = 0;
	{
		std::lock_guard<std::mutex> lk(st.trace_mutex);
		n = st.trace_log.size();
	}
	diag::log_tagged_fmt("trace",
		"stop_trace was_active=%d records=%zu",
		was ? 1 : 0, n);
	return true;
}


void set_comment(uint64_t address, const std::string& text) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.anno_mutex);
	if (text.empty())
		st.comments.erase(address);
	else
		st.comments[address] = {text, address};
}

void set_label(uint64_t address, const std::string& text) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.anno_mutex);
	if (text.empty())
		st.labels.erase(address);
	else
		st.labels[address] = {text, address};
}

void toggle_bookmark(uint64_t address) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.anno_mutex);
	auto it = std::find(st.bookmarks.begin(), st.bookmarks.end(), address);
	if (it != st.bookmarks.end())
		st.bookmarks.erase(it);
	else
		st.bookmarks.push_back(address);
}

std::string get_comment(uint64_t address) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.anno_mutex);
	auto it = st.comments.find(address);
	return (it != st.comments.end()) ? it->second.text : "";
}

std::string get_label(uint64_t address) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.anno_mutex);
	auto it = st.labels.find(address);
	return (it != st.labels.end()) ? it->second.text : "";
}


void enumerate_handles() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) {
		diag::log_tagged_fmt("handles",
			"enumerate_handles_REJECTED no_target");
		return;
	}

	const auto started = std::chrono::steady_clock::now();
	diag::log_tagged_fmt("handles",
		"enumerate_handles_begin pid=%u",
		static_cast<unsigned>(st.target_pid));

	static auto nt_query = reinterpret_cast<nt_query_system_information_fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
	if (!nt_query) {
		diag::log_tagged_fmt("handles",
			"enumerate_handles_no_nt_query_system_info");
		return;
	}

	ULONG buf_size = 1024 * 1024;
	std::vector<uint8_t> buffer;
	NTSTATUS nts = 0;
	for (int attempt = 0; attempt < 8; ++attempt) {
		buffer.resize(buf_size);
		ULONG returned = 0;
		nts = nt_query(16, buffer.data(), buf_size, &returned);
		if (nts == 0) break;
		if (nts == static_cast<NTSTATUS>(0xC0000004))
			buf_size *= 2;
		else
			return;
	}
	if (nts != 0) return;

	auto* info = reinterpret_cast<system_handle_information_t*>(buffer.data());
	std::vector<handle_info_t> result;

	size_t metadata_attempted = 0;
	size_t metadata_named = 0;
	size_t metadata_typed = 0;
	size_t metadata_abandoned = 0;
	size_t metadata_skipped_budget = 0;
	size_t duplicate_failed = 0;

	for (ULONG i = 0; i < info->number_of_handles; ++i) {
		auto& entry = info->handles[i];
		if (static_cast<uint32_t>(entry.pid) != st.target_pid)
			continue;
		handle_info_t hi;
		hi.handle = entry.handle_value;
		hi.type_index = entry.object_type_index;
		hi.access = entry.granted_access;
		++metadata_skipped_budget;

		result.push_back(std::move(hi));
	}

	std::lock_guard<std::mutex> lk(st.handle_mutex);
	st.handles = std::move(result);
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - started).count();
	diag::log_tagged_fmt("handles",
		"enumerate_handles_done pid=%u handles=%zu metadata_attempted=%zu typed=%zu named=%zu abandoned=%zu duplicate_failed=%zu skipped_budget=%zu metadata_method=none_fail_closed elapsed_ms=%lld",
		static_cast<unsigned>(st.target_pid),
		st.handles.size(),
		metadata_attempted,
		metadata_typed,
		metadata_named,
		metadata_abandoned,
		duplicate_failed,
		metadata_skipped_budget,
		static_cast<long long>(elapsed));
}


void find_strings(size_t min_length) {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) {
		diag::log_tagged_fmt("debugger_strings",
			"find_strings skipped_no_target min_length=%zu",
			min_length);
		return;
	}

	const uint32_t scan_pid = st.target_pid;
	auto enum_regions_logged = [&](const char* phase, size_t retry_index) {
		auto regs = driver_bridge::enumerate_memory_regions(4096);
		diag::log_tagged_fmt("debugger_strings",
			"find_strings_regions phase=%s retry=%zu pid=%u count=%zu",
			phase,
			retry_index,
			scan_pid,
			regs.size());
		return regs;
	};

	auto regions = enum_regions_logged("initial", 0);
	size_t region_retry_count = 0;
	while (regions.empty() && region_retry_count < 2) {
		uint32_t exit_code = 0;
		const bool alive = driver_bridge::attached_process_alive(&exit_code);
		diag::log_tagged_fmt("debugger_strings",
			"find_strings_zero_regions_suspicious pid=%u retry=%zu alive=%d exit_code_or_err=0x%08X",
			scan_pid,
			region_retry_count + 1,
			alive ? 1 : 0,
			exit_code);
		if (!alive)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(60));
		++region_retry_count;
		regions = enum_regions_logged("retry", region_retry_count);
	}

	auto modules = driver_bridge::enumerate_modules();
	diag::log_tagged_fmt("debugger_strings",
		"find_strings_begin pid=%u min_length=%zu regions=%zu retries=%zu modules=%zu",
		scan_pid,
		min_length,
		regions.size(),
		region_retry_count,
		modules.size());

	std::vector<string_ref_t> found;
	st.strings_pages_scanned.store(0, std::memory_order_release);
	st.strings_found_so_far.store(0, std::memory_order_release);
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(4500);
	constexpr size_t max_strings = 10000;

	auto attach_module = [&modules](string_ref_t& sr) {
		for (const auto& m : modules) {
			if (sr.address >= m.base && sr.address < m.base + m.size) {
				sr.module_name = m.name;
				sr.module_offset = sr.address - m.base;
				break;
			}
		}
	};

	auto push_ascii = [&](uint64_t address, const uint8_t* data, size_t len) {
		if (len < min_length || found.size() >= max_strings)
			return;
		string_ref_t sr;
		sr.address = address;
		size_t keep = (len > 512) ? 512 : len;
		sr.value.assign(reinterpret_cast<const char*>(data), keep);
		sr.is_unicode = false;
		attach_module(sr);
		found.push_back(std::move(sr));
		st.strings_found_so_far.store(found.size(), std::memory_order_release);
	};

	auto push_wide = [&](uint64_t address, const uint8_t* data, size_t chars) {
		if (chars < min_length || found.size() >= max_strings)
			return;
		string_ref_t sr;
		sr.address = address;
		size_t keep = (chars > 512) ? 512 : chars;
		sr.value.reserve(keep);
		for (size_t i = 0; i < keep; ++i)
			sr.value.push_back(static_cast<char>(data[i * 2]));
		sr.is_unicode = true;
		attach_module(sr);
		found.push_back(std::move(sr));
		st.strings_found_so_far.store(found.size(), std::memory_order_release);
	};

	auto scan_buffer = [&](uint64_t base, const std::vector<uint8_t>& buf) {
		size_t ascii_start = 0;
		bool in_ascii = false;
		for (size_t i = 0; i < buf.size(); ++i) {
			bool printable = (buf[i] >= 0x20 && buf[i] <= 0x7e);
			if (printable && !in_ascii) {
				ascii_start = i;
				in_ascii = true;
			} else if (!printable && in_ascii) {
				push_ascii(base + ascii_start, buf.data() + ascii_start, i - ascii_start);
				in_ascii = false;
			}
		}
		if (in_ascii)
			push_ascii(base + ascii_start, buf.data() + ascii_start, buf.size() - ascii_start);

		size_t wide_start = 0;
		bool in_wide = false;
		for (size_t i = 0; i + 1 < buf.size(); i += 2) {
			bool printable = (buf[i] >= 0x20 && buf[i] <= 0x7e && buf[i + 1] == 0);
			if (printable && !in_wide) {
				wide_start = i;
				in_wide = true;
			} else if (!printable && in_wide) {
				push_wide(base + wide_start, buf.data() + wide_start, (i - wide_start) / 2);
				in_wide = false;
			}
		}
		if (in_wide)
			push_wide(base + wide_start, buf.data() + wide_start, (buf.size() - wide_start) / 2);
	};

	for (const auto& region : regions) {
		if (st.strings_cancel.load(std::memory_order_acquire)) break;
		if (std::chrono::steady_clock::now() >= deadline) break;
		if (region.state != 0x1000) continue;
		if (region.size > 0x1000000) continue;
		if ((region.protect & PAGE_GUARD) != 0 || (region.protect & 0xff) == PAGE_NOACCESS)
			continue;

		uint64_t remaining = region.size;
		uint64_t cursor = region.base;
		while (remaining != 0) {
			if (st.strings_cancel.load(std::memory_order_acquire)) break;
			if (std::chrono::steady_clock::now() >= deadline) break;
			size_t chunk = static_cast<size_t>((remaining > 0x10000ull) ? 0x10000ull : remaining);
			std::vector<uint8_t> buf;
			if (driver_bridge::read_memory(cursor, chunk, buf) && !buf.empty()) {
				scan_buffer(cursor, buf);
				uint64_t pages = (buf.size() + 0xFFFull) / 0x1000ull;
				st.strings_pages_scanned.fetch_add(pages, std::memory_order_acq_rel);
			} else {
				for (size_t off = 0; off < chunk; off += 0x1000) {
					if (st.strings_cancel.load(std::memory_order_acquire)) break;
					if (std::chrono::steady_clock::now() >= deadline) break;
					size_t page = (chunk - off > 0x1000) ? 0x1000 : (chunk - off);
					std::vector<uint8_t> page_buf;
					if (driver_bridge::read_memory(cursor + off, page, page_buf) && !page_buf.empty())
						scan_buffer(cursor + off, page_buf);
					st.strings_pages_scanned.fetch_add(1, std::memory_order_acq_rel);
				}
			}
			cursor += chunk;
			remaining -= chunk;
			if (found.size() >= max_strings) break;
		}

		if (found.size() >= max_strings) break;
	}

	const size_t final_found_count = found.size();
	{
		std::lock_guard<std::mutex> lk(st.strings_mutex);
		st.strings = std::move(found);
	}
	diag::log_tagged_fmt("debugger_strings",
		"find_strings_complete pid=%u regions=%zu retries=%zu modules=%zu pages_scanned=%llu found=%zu cancelled=%d",
		scan_pid,
		regions.size(),
		region_retry_count,
		modules.size(),
		static_cast<unsigned long long>(st.strings_pages_scanned.load(std::memory_order_acquire)),
		final_found_count,
		st.strings_cancel.load(std::memory_order_acquire) ? 1 : 0);
}


void find_strings_async(size_t min_length) {
	auto& st = g_state;
	bool expected = false;
	if (!st.strings_scanning.compare_exchange_strong(expected, true,
			std::memory_order_acq_rel, std::memory_order_acquire)) {
		diag::log_tagged_fmt("strings",
			"find_strings_async_already_running");
		return;
	}
	st.strings_cancel.store(false, std::memory_order_release);
	st.strings_pages_scanned.store(0, std::memory_order_release);
	st.strings_found_so_far.store(0, std::memory_order_release);

	diag::log_tagged_fmt("strings",
		"find_strings_async_begin min_length=%zu pid=%u",
		min_length,
		static_cast<unsigned>(st.target_pid));

	try {
		const bool posted = work_queue::post([min_length]() {
		try {
			find_strings(min_length);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("strings", "find_strings_async_exception err='%s'", ex.what());
		} catch (...) {
			diag::log_tagged("strings", "find_strings_async_exception err='<unknown>'");
		}
		auto& s = g_state;
		size_t found = 0;
		{
			std::lock_guard<std::mutex> lk(s.strings_mutex);
			found = s.strings.size();
		}
		bool cancelled = s.strings_cancel.load(std::memory_order_acquire);
		diag::log_tagged_fmt("strings",
			"find_strings_async_done found=%zu cancelled=%d pages=%llu",
			found,
			cancelled ? 1 : 0,
			static_cast<unsigned long long>(s.strings_pages_scanned.load()));
		s.strings_cancel.store(false, std::memory_order_release);
		s.strings_scanning.store(false, std::memory_order_release);
		});
		if (!posted) {
			st.strings_scanning.store(false, std::memory_order_release);
			st.strings_cancel.store(false, std::memory_order_release);
			diag::log_tagged_fmt("strings",
				"find_strings_async_POST_FAILED");
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("strings", "find_strings_async_worker_create_failed err='%s'", ex.what());
		st.strings_scanning.store(false, std::memory_order_release);
		st.strings_cancel.store(false, std::memory_order_release);
	} catch (...) {
		diag::log_tagged("strings", "find_strings_async_worker_create_failed err='<unknown>'");
		st.strings_scanning.store(false, std::memory_order_release);
		st.strings_cancel.store(false, std::memory_order_release);
	}
}


void request_strings_cancel() {
	auto& st = g_state;
	if (st.strings_scanning.load(std::memory_order_acquire))
		st.strings_cancel.store(true, std::memory_order_release);
}


std::string format_flags(uint64_t rflags) {
	std::string out;
	if (rflags & 0x0001) out += "CF ";
	if (rflags & 0x0004) out += "PF ";
	if (rflags & 0x0010) out += "AF ";
	if (rflags & 0x0040) out += "ZF ";
	if (rflags & 0x0080) out += "SF ";
	if (rflags & 0x0100) out += "TF ";
	if (rflags & 0x0200) out += "IF ";
	if (rflags & 0x0400) out += "DF ";
	if (rflags & 0x0800) out += "OF ";
	return out;
}

std::string format_protect(uint32_t protect) {
	uint32_t base = protect & 0xFFu;
	const char* base_name = nullptr;
	switch (base) {
		case 0x01: base_name = "NOACCESS"; break;
		case 0x02: base_name = "READONLY"; break;
		case 0x04: base_name = "READWRITE"; break;
		case 0x08: base_name = "WRITECOPY"; break;
		case 0x10: base_name = "EXECUTE"; break;
		case 0x20: base_name = "EXECUTE_READ"; break;
		case 0x40: base_name = "EXECUTE_READWRITE"; break;
		case 0x80: base_name = "EXECUTE_WRITECOPY"; break;
		default: break;
	}
	uint32_t modifiers = protect & ~0xFFu;
	if (base_name && modifiers == 0)
		return base_name;
	if (!base_name) {
		char buf[16];
		snprintf(buf, sizeof(buf), "0x%X", protect);
		return buf;
	}
	std::string out = base_name;
	if (modifiers & 0x100u) out += "|GUARD";
	if (modifiers & 0x200u) out += "|NOCACHE";
	if (modifiers & 0x400u) out += "|WRITECOMBINE";
	uint32_t unknown = modifiers & ~0x700u;
	if (unknown != 0) {
		char buf[16];
		snprintf(buf, sizeof(buf), "|0x%X", unknown);
		out += buf;
	}
	return out;
}


bool set_breakpoint_condition(int index, const std::string& condition) {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "set_breakpoint_condition: index=%d condition='%s'", index, condition.c_str());
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size())) {
		diag::log_tagged_fmt("dbg_engine", "set_breakpoint_condition: index=%d out of range (size=%zu)", index, st.breakpoints.size());
		set_last_error("set_breakpoint_condition: index out of range");
		return false;
	}
	st.breakpoints[static_cast<size_t>(index)].condition = condition;
	diag::log_tagged_fmt("dbg_engine", "set_breakpoint_condition: index=%d condition set ok", index);
	return true;
}

bool set_breakpoint_log(int index, const std::string& log_text, bool auto_continue) {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "set_breakpoint_log: index=%d log_text='%s' auto_continue=%d", index, log_text.c_str(), auto_continue ? 1 : 0);
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size())) {
		diag::log_tagged_fmt("dbg_engine", "set_breakpoint_log: index=%d out of range (size=%zu)", index, st.breakpoints.size());
		set_last_error("set_breakpoint_log: index out of range");
		return false;
	}
	auto& bp = st.breakpoints[static_cast<size_t>(index)];
	bp.log_text = log_text;
	bp.auto_continue = auto_continue;
	diag::log_tagged_fmt("dbg_engine", "set_breakpoint_log: index=%d addr=0x%llX log set ok", index, (unsigned long long)bp.address);
	return true;
}

bp_hit_action_t handle_breakpoint_hit(uint64_t address) {
	auto& st = g_state;

	diag::log_tagged_fmt("dbg_engine", "handle_breakpoint_hit: addr=0x%llX active_tid=%u", (unsigned long long)address, st.active_tid);
	signal_trap(address);

	std::string condition;
	std::string log_text;
	bool        has_bp = false;
	bool        bp_auto_continue = false;
	bool        bp_enabled = true;
	bool        bp_is_internal = false;
	bool        bp_is_one_shot = false;
	uint8_t     bp_original_byte = 0;
	bool        bp_byte_written = false;
	int         bp_index = -1;
	uint64_t    bp_address_matched = address;

	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		const uint64_t probe_addrs[2] = { address, (address > 0) ? address - 1 : 0 };
		for (int pa = 0; pa < 2 && !has_bp; ++pa) {
			uint64_t pa_addr = probe_addrs[pa];
			for (size_t i = 0; i < st.breakpoints.size(); ++i) {
				auto& bp = st.breakpoints[i];
				if (bp.address != pa_addr) continue;
				has_bp = true;
				bp_index = static_cast<int>(i);
				bp_address_matched = pa_addr;
				condition = bp.condition;
				log_text = bp.log_text;
				bp_auto_continue = bp.auto_continue;
				bp_enabled = (bp.state != bp_state_t::disabled);
				bp_is_internal = bp.is_internal;
				bp_is_one_shot = (bp.state == bp_state_t::one_shot);
				bp_original_byte = bp.original_byte;
				bp_byte_written = bp.byte_written;
				bp.hit_count += 1;
				break;
			}
		}

		for (auto it = st.internal_breakpoints.begin(); it != st.internal_breakpoints.end(); ) {
			if ((it->address == address || it->address + 1 == address) && it->active) {
				std::vector<uint8_t> restore{it->original_byte};
				driver_bridge::write_memory(it->address, restore);
				it = st.internal_breakpoints.erase(it);
			} else {
				++it;
			}
		}

		if (has_bp && bp_byte_written) {
			std::vector<uint8_t> restore{bp_original_byte};
			driver_bridge::write_memory(bp_address_matched, restore);
			st.breakpoints[static_cast<size_t>(bp_index)].byte_written = false;
		}

		if (has_bp && bp_is_one_shot) {
			st.breakpoints.erase(st.breakpoints.begin() + bp_index);
		}
	}

	if (has_bp && bp_address_matched == address - 1 && st.active_tid != 0) {
		driver_bridge::thread_context_t adj{};
		if (driver_bridge::get_thread_context(st.active_tid, adj)) {
			if (adj.rip == address) {
				adj.rip = bp_address_matched;
				driver_bridge::set_thread_context(st.active_tid, adj, ctx_mask_base);
			}
		}
	}

	if (!has_bp) {
		return bp_hit_action_t::stop;
	}

	if (bp_is_internal && bp_is_one_shot) {
		return bp_hit_action_t::stop;
	}

	if (!bp_enabled) {
		return bp_hit_action_t::resume;
	}

	register_set_t regs = get_registers();
	expression_eval::context_t ctx = build_eval_context(regs);

	if (!condition.empty()) {
		auto er = expression_eval::evaluate(condition, ctx);
		if (!er.ok) {
			char buf[64];
			snprintf(buf, sizeof(buf), "bp[%d] condition error: ", bp_index);
			set_last_error(std::string(buf) + er.error);
			return bp_hit_action_t::resume;
		}
		if (er.value == 0) {
			return bp_hit_action_t::resume;
		}
	}

	if (!log_text.empty()) {
		std::string rendered = expression_eval::format_log_text(log_text, ctx);
		char prefix[40];
		snprintf(prefix, sizeof(prefix), "[bp@0x%016" PRIX64 "] ",
				 static_cast<uint64_t>(address));
		push_log_message_locked(st, std::string(prefix) + rendered);

		if (bp_auto_continue) {
			return bp_hit_action_t::resume;
		}
	}

	return bp_hit_action_t::stop;
}

std::vector<std::string> pop_log_messages() {
	auto& st = g_state;
	std::vector<std::string> out;
	std::lock_guard<std::mutex> lk(st.log_mutex);
	out.reserve(st.log_messages.size());
	while (!st.log_messages.empty()) {
		out.push_back(std::move(st.log_messages.front()));
		st.log_messages.pop_front();
	}
	return out;
}

size_t log_message_count() {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.log_mutex);
	return st.log_messages.size();
}

const std::string& last_error() {
	return last_error_ref();
}


namespace {

inline uint64_t now_ms() {
	auto tp = std::chrono::steady_clock::now().time_since_epoch();
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(tp).count());
}

}

register_set_t cached_registers() {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.cache_mtx);
	return st.cached_regs;
}

std::vector<cached_thread_t> cached_thread_list() {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.cache_mtx);
	return st.cached_threads;
}

std::vector<uint8_t> cached_stack_bytes(uint64_t& addr_out) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.cache_mtx);
	addr_out = st.cached_stack_addr;
	return st.cached_stack;
}

std::vector<uint8_t> cached_dump_bytes(uint64_t& addr_out, size_t& size_out) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.cache_mtx);
	addr_out = st.cached_dump_addr;
	size_out = st.cached_dump_size;
	return st.cached_dump;
}

bool dump_refresh_in_flight() {
	return g_state.dump_refresh_in_flight.load(std::memory_order_acquire);
}

std::vector<uint8_t> cached_disasm_window(uint64_t& base_out) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.cache_mtx);
	base_out = st.cached_disasm_base;
	return st.cached_disasm_bytes;
}

void sync_attached_state() {
	auto& st = g_state;
	uint32_t live_pid = driver_bridge::attached_pid();
	if (live_pid != 0 && !kernel_target_operations_ready("sync_attached_state"))
		live_pid = 0;
	if (live_pid != st.target_pid) {
		st.target_pid = live_pid;
		st.active_tid = 0;
		std::lock_guard<std::mutex> lk(st.cache_mtx);
		st.cached_regs = register_set_t{};
		st.cached_threads.clear();
		st.cached_stack.clear();
		st.cached_stack_addr = 0;
		st.cached_dump.clear();
		st.cached_dump_addr = 0;
		st.cached_dump_size = 0;
		st.cached_disasm_bytes.clear();
		st.cached_disasm_base = 0;
	}
	if (live_pid != 0 && st.active_tid == 0) {
		auto threads = driver_bridge::enumerate_threads();
		for (const auto& th : threads) {
			if (th.owner_pid == live_pid && th.tid != 0) {
				st.active_tid = th.tid;
				break;
			}
		}
	}
}

void request_refresh(uint32_t max_age_ms) {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) return;
	uint64_t now = now_ms();
	if (now - st.last_refresh_ms.load() < max_age_ms) return;
	bool expected = false;
	if (!st.refresh_in_flight.compare_exchange_strong(expected, true)) return;

	try {
		if (!work_queue::post([]() {
			auto& s = g_state;
			try {
				if (s.active_tid == 0 && s.target_pid != 0) {
					auto threads = driver_bridge::enumerate_threads();
					for (const auto& th : threads) {
						if (th.owner_pid == s.target_pid && th.tid != 0) {
							s.active_tid = th.tid;
							break;
						}
					}
				}
				register_set_t fresh = get_registers();
				{
					std::lock_guard<std::mutex> lk(s.cache_mtx);
					s.cached_regs = fresh;
				}
				s.last_refresh_ms.store(now_ms());
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("debugger", "request_refresh_worker_exception err='%s'", ex.what());
			} catch (...) {
				diag::log_tagged("debugger", "request_refresh_worker_exception err='<unknown>'");
			}
			s.refresh_in_flight.store(false);
		})) {
			diag::log_tagged("debugger", "request_refresh_worker_post_failed");
			st.refresh_in_flight.store(false);
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("debugger", "request_refresh_worker_create_failed err='%s'", ex.what());
		st.refresh_in_flight.store(false);
	} catch (...) {
		diag::log_tagged("debugger", "request_refresh_worker_create_failed err='<unknown>'");
		st.refresh_in_flight.store(false);
	}
}

void request_thread_refresh(uint32_t max_age_ms) {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) return;
	uint64_t now = now_ms();
	if (now - st.last_thread_refresh_ms.load() < max_age_ms) return;
	bool expected = false;
	if (!st.thread_refresh_in_flight.compare_exchange_strong(expected, true)) return;

	try {
		if (!work_queue::post([]() {
			auto& s = g_state;
			try {
				auto raw = driver_bridge::enumerate_threads();
				std::vector<cached_thread_t> entries;
				entries.reserve(raw.size());
				uint32_t pid_filter = s.target_pid;
				for (auto& t : raw) {
					if (pid_filter != 0 && t.owner_pid != pid_filter) continue;
					cached_thread_t e;
					e.tid = t.tid;
					e.owner_pid = t.owner_pid;
					e.priority = t.priority;
					e.state = t.state;
					e.rip = t.rip;
					entries.push_back(e);
				}
				if (s.active_tid == 0 && !entries.empty())
					s.active_tid = entries.front().tid;
				{
					std::lock_guard<std::mutex> lk(s.cache_mtx);
					s.cached_threads = std::move(entries);
				}
				s.last_thread_refresh_ms.store(now_ms());
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("debugger", "request_thread_refresh_worker_exception err='%s'", ex.what());
			} catch (...) {
				diag::log_tagged("debugger", "request_thread_refresh_worker_exception err='<unknown>'");
			}
			s.thread_refresh_in_flight.store(false);
		})) {
			diag::log_tagged("debugger", "request_thread_refresh_worker_post_failed");
			st.thread_refresh_in_flight.store(false);
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("debugger", "request_thread_refresh_worker_create_failed err='%s'", ex.what());
		st.thread_refresh_in_flight.store(false);
	} catch (...) {
		diag::log_tagged("debugger", "request_thread_refresh_worker_create_failed err='<unknown>'");
		st.thread_refresh_in_flight.store(false);
	}
}

void request_stack_refresh(uint64_t rsp, size_t bytes, uint32_t max_age_ms) {
	auto& st = g_state;
	if (rsp == 0 || bytes == 0) return;
	uint64_t now = now_ms();
	if (now - st.last_stack_refresh_ms.load() < max_age_ms) return;
	bool expected = false;
	if (!st.stack_refresh_in_flight.compare_exchange_strong(expected, true)) return;

	try {
		if (!work_queue::post([rsp, bytes]() {
			auto& s = g_state;
			try {
				std::vector<uint8_t> buf;
				driver_bridge::read_memory(rsp, bytes, buf);
				{
					std::lock_guard<std::mutex> lk(s.cache_mtx);
					s.cached_stack_addr = rsp;
					s.cached_stack = std::move(buf);
				}
				s.last_stack_refresh_ms.store(now_ms());
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("debugger", "request_stack_refresh_worker_exception err='%s'", ex.what());
			} catch (...) {
				diag::log_tagged("debugger", "request_stack_refresh_worker_exception err='<unknown>'");
			}
			s.stack_refresh_in_flight.store(false);
		})) {
			diag::log_tagged("debugger", "request_stack_refresh_worker_post_failed");
			st.stack_refresh_in_flight.store(false);
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("debugger", "request_stack_refresh_worker_create_failed err='%s'", ex.what());
		st.stack_refresh_in_flight.store(false);
	} catch (...) {
		diag::log_tagged("debugger", "request_stack_refresh_worker_create_failed err='<unknown>'");
		st.stack_refresh_in_flight.store(false);
	}
}

void request_dump_refresh(uint64_t addr, size_t bytes, uint32_t max_age_ms) {
	auto& st = g_state;
	uint64_t now = now_ms();
	const uint64_t last = st.last_dump_refresh_ms.load();
	const uint64_t age = now >= last ? now - last : 0;
	diag::log_tagged_fmt("debugger_engine", "dump_refresh_request addr=0x%llX bytes=%zu max_age_ms=%u attached_pid=%u last_ms=%llu age_ms=%llu in_flight=%d",
		static_cast<unsigned long long>(addr),
		bytes,
		max_age_ms,
		driver_bridge::attached_pid(),
		static_cast<unsigned long long>(last),
		static_cast<unsigned long long>(age),
		st.dump_refresh_in_flight.load(std::memory_order_acquire) ? 1 : 0);
	if (addr == 0 || bytes == 0) {
		diag::log_tagged_fmt("debugger_engine", "dump_refresh_reject_invalid addr=0x%llX bytes=%zu", static_cast<unsigned long long>(addr), bytes);
		return;
	}
	if (age < max_age_ms) {
		diag::log_tagged_fmt("debugger_engine", "dump_refresh_throttled addr=0x%llX bytes=%zu age_ms=%llu max_age_ms=%u",
			static_cast<unsigned long long>(addr), bytes, static_cast<unsigned long long>(age), max_age_ms);
		return;
	}
	bool expected = false;
	if (!st.dump_refresh_in_flight.compare_exchange_strong(expected, true)) {
		diag::log_tagged_fmt("debugger_engine", "dump_refresh_busy addr=0x%llX bytes=%zu", static_cast<unsigned long long>(addr), bytes);
		return;
	}

	try {
		if (!work_queue::post([addr, bytes, now]() {
			auto& s = g_state;
			const uint64_t worker_start = now_ms();
			diag::log_tagged_fmt("debugger_engine", "dump_refresh_worker_entry addr=0x%llX bytes=%zu request_age_ms=%llu attached_pid=%u",
				static_cast<unsigned long long>(addr),
				bytes,
				static_cast<unsigned long long>(worker_start >= now ? worker_start - now : 0),
				driver_bridge::attached_pid());
			try {
				std::vector<uint8_t> buf;
				SetLastError(ERROR_SUCCESS);
				const bool read_ok = driver_bridge::read_memory(addr, bytes, buf);
				const DWORD gle = read_ok ? ERROR_SUCCESS : GetLastError();
				const std::string status = driver_bridge::status();
				const std::string drv_err = driver_bridge::last_error();
				{
					std::lock_guard<std::mutex> lk(s.cache_mtx);
					s.cached_dump_addr = addr;
					s.cached_dump_size = bytes;
					s.cached_dump = std::move(buf);
				}
				s.last_dump_refresh_ms.store(now_ms());
				size_t cached_size = 0;
				{
					std::lock_guard<std::mutex> lk(s.cache_mtx);
					cached_size = s.cached_dump.size();
				}
				diag::log_tagged_fmt("debugger_engine", "dump_refresh_worker_exit addr=0x%llX bytes=%zu read_ok=%d cached=%zu gle=%lu elapsed_ms=%llu attached_pid=%u driver_status=%s driver_error=%s",
					static_cast<unsigned long long>(addr),
					bytes,
					read_ok ? 1 : 0,
					cached_size,
					static_cast<unsigned long>(gle),
					static_cast<unsigned long long>(now_ms() - worker_start),
					driver_bridge::attached_pid(),
					status.c_str(),
					drv_err.c_str());
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("debugger_engine", "dump_refresh_worker_exception addr=0x%llX bytes=%zu elapsed_ms=%llu err='%s'",
					static_cast<unsigned long long>(addr), bytes, static_cast<unsigned long long>(now_ms() - worker_start), ex.what());
			} catch (...) {
				diag::log_tagged_fmt("debugger_engine", "dump_refresh_worker_exception addr=0x%llX bytes=%zu elapsed_ms=%llu err='<unknown>'",
					static_cast<unsigned long long>(addr), bytes, static_cast<unsigned long long>(now_ms() - worker_start));
			}
			s.dump_refresh_in_flight.store(false);
		})) {
			diag::log_tagged_fmt("debugger_engine", "dump_refresh_worker_post_failed addr=0x%llX bytes=%zu", static_cast<unsigned long long>(addr), bytes);
			st.dump_refresh_in_flight.store(false);
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("debugger_engine", "dump_refresh_worker_create_failed addr=0x%llX bytes=%zu err='%s'", static_cast<unsigned long long>(addr), bytes, ex.what());
		st.dump_refresh_in_flight.store(false);
	} catch (...) {
		diag::log_tagged_fmt("debugger_engine", "dump_refresh_worker_create_failed addr=0x%llX bytes=%zu err='<unknown>'", static_cast<unsigned long long>(addr), bytes);
		st.dump_refresh_in_flight.store(false);
	}
}

bool refresh_disasm_window_now(uint64_t rip, const char* source) {
	auto& s = g_state;
	uint64_t base = (rip > 0x100) ? rip - 0x100 : 0;
	std::vector<uint8_t> buf;
	SetLastError(ERROR_SUCCESS);
	const uint64_t start = now_ms();
	bool read_ok = driver_bridge::read_memory(base, 0x400, buf);
	DWORD gle = read_ok ? ERROR_SUCCESS : GetLastError();
	const uint64_t elapsed = now_ms() - start;
	{
		std::lock_guard<std::mutex> lk(s.cache_mtx);
		s.cached_disasm_base = base;
		s.cached_disasm_bytes = std::move(buf);
	}
	size_t cached_size = 0;
	{
		std::lock_guard<std::mutex> lk(s.cache_mtx);
		cached_size = s.cached_disasm_bytes.size();
	}
	s.last_disasm_refresh_ms.store(now_ms());
	s.disasm_refresh_in_flight.store(false);
	diag::log_tagged_fmt("debugger_engine",
		"disasm_refresh source=%s pid=%u target_pid=%u rip=0x%llX base=0x%llX size=%u read_ok=%d bytes=%zu gle=%lu elapsed_ms=%llu driver_status=%s driver_error=%s",
		source ? source : "unknown",
		driver_bridge::attached_pid(),
		s.target_pid,
		static_cast<unsigned long long>(rip),
		static_cast<unsigned long long>(base),
		0x400u,
		read_ok ? 1 : 0,
		cached_size,
		static_cast<unsigned long>(gle),
		static_cast<unsigned long long>(elapsed),
		driver_bridge::status().c_str(),
		driver_bridge::last_error().c_str());
	return read_ok && cached_size != 0;
}

void request_disasm_refresh(uint64_t rip, uint32_t max_age_ms) {
	auto& st = g_state;
	if (rip == 0) return;
	uint64_t now = now_ms();
	if (now - st.last_disasm_refresh_ms.load() < max_age_ms) return;
	bool expected = false;
	if (!st.disasm_refresh_in_flight.compare_exchange_strong(expected, true)) {
		if (max_age_ms == 0) {
			diag::log_tagged_fmt("debugger_engine",
				"disasm_refresh forced_sync_recover_inflight rip=0x%llX pid=%u target_pid=%u",
				static_cast<unsigned long long>(rip),
				driver_bridge::attached_pid(),
				st.target_pid);
			st.disasm_refresh_in_flight.store(true);
			(void)refresh_disasm_window_now(rip, "forced_sync_recover_inflight");
		}
		return;
	}

	if (max_age_ms == 0) {
		(void)refresh_disasm_window_now(rip, "forced_sync");
		return;
	}

	try {
		if (!work_queue::post([rip]() {
			try {
				(void)refresh_disasm_window_now(rip, "work_queue");
			} catch (const std::exception& ex) {
				g_state.disasm_refresh_in_flight.store(false);
				set_last_error(std::string("request_disasm_refresh worker exception: ") + ex.what());
				diag::log_tagged_fmt("debugger_engine", "disasm_refresh worker_exception rip=0x%llX error=%s",
					static_cast<unsigned long long>(rip), ex.what());
			} catch (...) {
				g_state.disasm_refresh_in_flight.store(false);
				set_last_error("request_disasm_refresh worker unknown exception");
				diag::log_tagged_fmt("debugger_engine", "disasm_refresh worker_unknown_exception rip=0x%llX",
					static_cast<unsigned long long>(rip));
			}
		})) {
			set_last_error("request_disasm_refresh worker post failed");
			diag::log_tagged_fmt("debugger_engine",
				"disasm_refresh worker_post_failed rip=0x%llX pid=%u target_pid=%u",
				static_cast<unsigned long long>(rip),
				driver_bridge::attached_pid(),
				st.target_pid);
			(void)refresh_disasm_window_now(rip, "worker_post_failed_sync");
		}
	} catch (const std::exception& ex) {
		set_last_error(std::string("request_disasm_refresh worker create failed: ") + ex.what());
		diag::log_tagged_fmt("debugger_engine",
			"disasm_refresh worker_create_failed rip=0x%llX pid=%u target_pid=%u err=%s",
			static_cast<unsigned long long>(rip),
			driver_bridge::attached_pid(),
			st.target_pid,
			ex.what());
		(void)refresh_disasm_window_now(rip, "thread_create_failed_sync");
	} catch (...) {
		set_last_error("request_disasm_refresh worker create failed");
		diag::log_tagged_fmt("debugger_engine",
			"disasm_refresh worker_create_failed rip=0x%llX pid=%u target_pid=%u err=<unknown>",
			static_cast<unsigned long long>(rip),
			driver_bridge::attached_pid(),
			st.target_pid);
		(void)refresh_disasm_window_now(rip, "thread_create_failed_sync");
	}
}

void invalidate_cache() {
	auto& st = g_state;
	st.last_refresh_ms.store(0);
	st.last_thread_refresh_ms.store(0);
	st.last_stack_refresh_ms.store(0);
	st.last_dump_refresh_ms.store(0);
	st.last_disasm_refresh_ms.store(0);
	st.disasm_refresh_in_flight.store(false);
}

void signal_trap(uint64_t address) {
	auto& st = g_state;
	{
		std::lock_guard<std::mutex> lk(st.trap_mtx);
		st.pending_trap_address = address;
		st.trap_signaled.store(true);
	}
	st.trap_cv.notify_all();
}

bool wait_for_trap(uint64_t expected_address, uint32_t timeout_ms) {
	auto& st = g_state;
	std::unique_lock<std::mutex> lk(st.trap_mtx);
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	while (!st.trap_signaled.load()) {
		if (st.trap_cv.wait_until(lk, deadline) == std::cv_status::timeout)
			return false;
	}
	if (expected_address != 0 && st.pending_trap_address != expected_address) {
		st.trap_signaled.store(false);
		return false;
	}
	st.trap_signaled.store(false);
	return true;
}

std::vector<breakpoint_t> snapshot_breakpoints() {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	return st.breakpoints;
}

std::vector<watch_entry_t> snapshot_watches() {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.watch_mutex);
	return st.watches;
}

void restore_breakpoints_and_watches(std::vector<breakpoint_t> bps,
									 std::vector<watch_entry_t> ws) {
	auto& st = g_state;
	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		st.breakpoints = std::move(bps);
		int max_id = 0;
		for (const auto& b : st.breakpoints) {
			(void)b;
		}
		if (st.next_bp_id <= static_cast<int>(st.breakpoints.size()))
			st.next_bp_id = static_cast<int>(st.breakpoints.size()) + 1;
		(void)max_id;
	}
	{
		std::lock_guard<std::mutex> lk(st.watch_mutex);
		st.watches = std::move(ws);
	}
}

void clear_breakpoints_and_watches() {
	auto& st = g_state;
	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		st.breakpoints.clear();
		st.internal_breakpoints.clear();
		st.next_bp_id = 1;
	}
	{
		std::lock_guard<std::mutex> lk(st.watch_mutex);
		st.watches.clear();
	}
}

}
