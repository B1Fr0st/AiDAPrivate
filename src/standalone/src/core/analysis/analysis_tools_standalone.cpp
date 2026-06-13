
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include "standalone_compat.hpp"
#include "../disasm/ghidra_decompiler.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "crypto_scanner.hpp"
#include "aob_generator.hpp"
#include "struct_recon_engine.hpp"
#include "fuzzer_engine.hpp"
#include "decrypt_oracle.hpp"
#include "integrity_hunter.hpp"
#include "struct_monitor.hpp"
#include "symbolic_engine.hpp"
#include "deobfuscation_engine.hpp"
#include "stealth_engine.hpp"
#include "pe_parser.hpp"
#include "symbol_store.hpp"
#include "xref_db.hpp"
#include "binary_map.hpp"
#include "standalone_driver.hpp"
#include "../disasm/function_index.hpp"
#include "../helpers/globals.h"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cinttypes>
#include <sstream>
#include <shared_mutex>
#include <string>
#include <vector>
#include <chrono>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

extern DisasmState g_disasm;

namespace analysis_tools {

static size_t bounded_size_param(const json& params, const char* name, size_t fallback, size_t minimum, size_t maximum)
{
	size_t value = fallback;
	auto it = params.find(name);
	if (it != params.end()) {
		if (it->is_number_unsigned()) {
			value = it->get<size_t>();
		} else if (it->is_number_integer()) {
			int64_t signed_value = it->get<int64_t>();
			if (signed_value >= 0)
				value = static_cast<size_t>(signed_value);
		}
	}
	if (value < minimum)
		return minimum;
	if (value > maximum)
		return maximum;
	return value;
}

static uint32_t bounded_u32_param(const json& params, const char* name, uint32_t fallback, uint32_t minimum, uint32_t maximum)
{
	uint32_t value = fallback;
	auto it = params.find(name);
	if (it != params.end()) {
		if (it->is_number_unsigned()) {
			uint64_t unsigned_value = it->get<uint64_t>();
			value = unsigned_value > maximum ? maximum : static_cast<uint32_t>(unsigned_value);
		} else if (it->is_number_integer()) {
			int64_t signed_value = it->get<int64_t>();
			if (signed_value >= 0)
				value = signed_value > static_cast<int64_t>(maximum) ? maximum : static_cast<uint32_t>(signed_value);
		}
	}
	if (value < minimum)
		return minimum;
	if (value > maximum)
		return maximum;
	return value;
}

static std::string lower_ascii(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return value;
}

static const driver_bridge::module_info_t* select_module_by_name(const std::vector<driver_bridge::module_info_t>& modules, const std::string& requested)
{
	if (modules.empty())
		return nullptr;
	if (requested.empty())
		return &modules.front();
	const std::string want = lower_ascii(requested);
	for (const auto& mod : modules) {
		if (lower_ascii(mod.name) == want)
			return &mod;
	}
	for (const auto& mod : modules) {
		const std::string path = lower_ascii(mod.path);
		if (path.size() >= want.size() && path.compare(path.size() - want.size(), want.size(), want) == 0)
			return &mod;
	}
	for (const auto& mod : modules) {
		if (lower_ascii(mod.name).find(want) != std::string::npos || lower_ascii(mod.path).find(want) != std::string::npos)
			return &mod;
	}
	return nullptr;
}

static std::string wide_to_utf8_lossy(const wchar_t* text)
{
	if (!text || !*text)
		return {};
	const int len = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
	if (len <= 1)
		return {};
	std::string out(static_cast<size_t>(len), '\0');
	const int written = WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), len, nullptr, nullptr);
	if (written <= 1)
		return {};
	out.resize(static_cast<size_t>(written - 1));
	return out;
}

static std::vector<driver_bridge::module_info_t> enumerate_modules_toolhelp(uint32_t pid)
{
	std::vector<driver_bridge::module_info_t> result;
	if (pid == 0)
		return result;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snapshot == INVALID_HANDLE_VALUE)
		return result;
	MODULEENTRY32W me{};
	me.dwSize = sizeof(me);
	if (Module32FirstW(snapshot, &me)) {
		do {
			driver_bridge::module_info_t mod;
			mod.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
			mod.size = me.modBaseSize;
			mod.name = wide_to_utf8_lossy(me.szModule);
			mod.path = wide_to_utf8_lossy(me.szExePath);
			result.push_back(std::move(mod));
			me.dwSize = sizeof(me);
		} while (Module32NextW(snapshot, &me));
	}
	CloseHandle(snapshot);
	std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
		return a.base < b.base;
	});
	return result;
}

static bool fast_section_executable(uint32_t characteristics)
{
	return (characteristics & 0x20000000u) != 0;
}

static bool fast_section_readable(uint32_t characteristics)
{
	return (characteristics & 0x40000000u) != 0;
}

static bool fast_section_writable(uint32_t characteristics)
{
	return (characteristics & 0x80000000u) != 0;
}

static tool_result_t analysis_query_binary_map_fast_summary(const json& params)
{
	const uint64_t start_ms = GetTickCount64();
	json phases = json::object();
	auto mark_phase = [&](const char* name, uint64_t phase_start) {
		const uint64_t elapsed = GetTickCount64() - phase_start;
		phases[name] = elapsed;
		diag::log_tagged_fmt("analysis", "binary_map_fast_summary_phase phase=%s elapsed_ms=%llu total_ms=%llu",
			name,
			static_cast<unsigned long long>(elapsed),
			static_cast<unsigned long long>(GetTickCount64() - start_ms));
	};
	const size_t max_functions = bounded_size_param(params, "max_functions", 24, 1, 256);
	const std::string requested_module = params.value("module_name", std::string());
	char buf[32];

	diag::log_tagged_fmt("analysis",
		"binary_map_fast_summary_enter static_loaded=%d attached_pid=%u module_filter=%s max_functions=%zu",
		g_disasm.file.loaded ? 1 : 0,
		driver_bridge::attached_pid(),
		requested_module.c_str(),
		max_functions);

	if (g_disasm.file.loaded) {
		uint64_t phase_start = GetTickCount64();
		json sections = json::array();
		for (size_t i = 0; i < g_disasm.file.sections.size(); ++i) {
			const auto& s = g_disasm.file.sections[i];
			json o;
			o["name"] = ".section" + std::to_string(i);
			std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(s.va));
			o["va"] = buf;
			o["size"] = s.bytes.size();
			o["executable"] = s.is_executable;
			o["readable"] = true;
			o["writable"] = false;
			sections.push_back(std::move(o));
		}
		mark_phase("static_sections", phase_start);

		phase_start = GetTickCount64();
		json functions = json::array();
		uint64_t last_va = 0;
		for (const auto& ins : g_disasm.file.instrs) {
			if (functions.size() >= max_functions)
				break;
			if (ins.addr == 0 || ins.addr == last_va)
				continue;
			last_va = ins.addr;
			json o;
			std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(ins.addr));
			o["va"] = buf;
			o["name"] = std::string("sub_") + buf + "_" + ins.mnem;
			o["xref_count"] = 0;
			o["callee_count"] = 0;
			o["source"] = "static_disasm";
			functions.push_back(std::move(o));
		}
		mark_phase("static_functions", phase_start);

		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(g_disasm.file.image_base));
		json result;
		result["module_name"] = g_disasm.file.filename;
		result["module_path"] = g_disasm.file.path;
		result["architecture"] = "x86_64";
		result["format"] = "PE";
		result["image_base"] = buf;
		result["image_size"] = static_analysis::total_image_size(g_disasm.file);
		result["sections"] = std::move(sections);
		result["functions"] = std::move(functions);
		result["globals"] = json::array();
		result["imports"] = json::array();
		result["exports"] = json::array();
		result["fast_summary"] = true;
		result["phase_timings_ms"] = phases;
		result["elapsed_ms"] = GetTickCount64() - start_ms;
		diag::log_tagged_fmt("analysis",
			"binary_map_fast_summary_exit ok=1 source=static sections=%zu functions=%zu elapsed_ms=%llu",
			result["sections"].size(),
			result["functions"].size(),
			static_cast<unsigned long long>(GetTickCount64() - start_ms));
		return tool_result_t::ok(result);
	}

	uint64_t phase_start = GetTickCount64();
	const uint32_t attached_pid = driver_bridge::attached_pid();
	if (attached_pid == 0)
		return tool_result_t::error("No process is attached and no static binary is loaded.");
	mark_phase("attached_pid", phase_start);

	phase_start = GetTickCount64();
	auto modules = driver_bridge::enumerate_modules();
	const size_t driver_module_count = modules.size();
	if (modules.empty())
		modules = enumerate_modules_toolhelp(attached_pid);
	mark_phase("module_enumeration", phase_start);
	diag::log_tagged_fmt("analysis",
		"binary_map_fast_summary_modules pid=%u driver_count=%zu final_count=%zu",
		attached_pid,
		driver_module_count,
		modules.size());
	if (modules.empty())
		return tool_result_t::error("Module enumeration returned no entries.");

	phase_start = GetTickCount64();
	const driver_bridge::module_info_t* selected = select_module_by_name(modules, requested_module);
	mark_phase("module_select", phase_start);
	if (!selected)
		return tool_result_t::error("Requested module was not found in the attached process.");

	phase_start = GetTickCount64();
	pe_parser::pe_info_t pe;
	const bool pe_ok = pe_parser::parse(selected->base, pe, false);
	mark_phase("pe_parse_headers", phase_start);
	if (!pe_ok)
		return tool_result_t::error("pe_parser::parse failed on the selected module.");

	phase_start = GetTickCount64();
	json sections = json::array();
	for (const auto& s : pe.sections) {
		json o;
		o["name"] = s.name;
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(selected->base + s.virtual_address));
		o["va"] = buf;
		o["size"] = s.virtual_size;
		o["executable"] = fast_section_executable(s.characteristics);
		o["readable"] = fast_section_readable(s.characteristics);
		o["writable"] = fast_section_writable(s.characteristics);
		sections.push_back(std::move(o));
	}
	mark_phase("sections", phase_start);

	phase_start = GetTickCount64();
	json functions = json::array();
	std::vector<uint64_t> emitted;
	auto emit_function = [&](uint64_t va, const std::string& name, const char* source) {
		if (va == 0 || functions.size() >= max_functions)
			return;
		if (std::find(emitted.begin(), emitted.end(), va) != emitted.end())
			return;
		emitted.push_back(va);
		json o;
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(va));
		o["va"] = buf;
		o["name"] = name;
		o["xref_count"] = 0;
		o["callee_count"] = 0;
		o["source"] = source;
		functions.push_back(std::move(o));
	};
	if (pe.entry_point != 0)
		emit_function(selected->base + pe.entry_point, "entry_point", "pe_entry_point");
	for (const auto& s : pe.sections) {
		if (functions.size() >= max_functions)
			break;
		if (!fast_section_executable(s.characteristics))
			continue;
		std::string name = s.name.empty() ? "executable_section_start" : ("section_start_" + s.name);
		emit_function(selected->base + s.virtual_address, name, "executable_section");
	}
	mark_phase("functions", phase_start);

	std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(selected->base));
	json result;
	result["module_name"] = selected->name;
	result["module_path"] = selected->path;
	result["architecture"] = pe.is_64bit ? "x86_64" : "x86";
	result["format"] = "PE";
	result["image_base"] = buf;
	result["image_size"] = pe.size_of_image != 0 ? pe.size_of_image : selected->size;
	result["sections"] = std::move(sections);
	result["functions"] = std::move(functions);
	result["globals"] = json::array();
	result["imports"] = json::array();
	result["exports"] = json::array();
	result["fast_summary"] = true;
	result["phase_timings_ms"] = phases;
	result["elapsed_ms"] = GetTickCount64() - start_ms;
	diag::log_tagged_fmt("analysis",
		"binary_map_fast_summary_exit ok=1 source=live pid=%u module=%s sections=%zu functions=%zu elapsed_ms=%llu",
		attached_pid,
		selected->name.c_str(),
		result["sections"].size(),
		result["functions"].size(),
		static_cast<unsigned long long>(GetTickCount64() - start_ms));
	return tool_result_t::ok(result);
}

static tool_result_t fuzzer_manage_start(const json& params)
{
	std::string target = params.value("target_address", "");
	std::string end = params.value("end_address", "");
	std::string input = params.value("input_address", "");
	diag::log_tagged_fmt("analysis", "fuzzer_manage start target=%s end=%s input=%s",
		target.c_str(), end.c_str(), input.c_str());
	if (target.empty())
		return tool_result_t::error("target_address is required");

	fuzzer_engine::fuzz_config_t cfg;
	cfg.target_address = std::strtoull(target.c_str(), nullptr, 16);
	if (cfg.target_address == 0)
		return tool_result_t::error("invalid target_address");
	if (!end.empty()) {
		cfg.end_address = std::strtoull(end.c_str(), nullptr, 16);
		if (cfg.end_address <= cfg.target_address)
			return tool_result_t::error("end_address must be greater than target_address");
	} else {
		cfg.end_address = cfg.target_address + 1;
	}
	if (!input.empty())
		cfg.input_address = std::strtoull(input.c_str(), nullptr, 16);
	cfg.input_size = static_cast<int>(bounded_u32_param(params, "input_size", 256, 1, 1024 * 1024));
	cfg.max_iterations = bounded_u32_param(params, "max_iterations", 10000, 1, 1000000);
	cfg.pid = driver_bridge::attached_pid();
	auto threads_snap = driver_bridge::enumerate_threads();
	cfg.tid = threads_snap.empty() ? 0 : threads_snap.front().tid;
	if (cfg.pid == 0 || cfg.tid == 0)
		return tool_result_t::error("fuzzer requires an attached process and at least one thread for snapshotting");

	{
		std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
		fuzzer_engine::g_state.config = cfg;
	}
	if (!fuzzer_engine::start_fuzzing())
		return tool_result_t::error("fuzzer is already running or worker queue is unavailable");

	char end_buf[32];
	char input_buf[32];
	std::snprintf(end_buf, sizeof(end_buf), "0x%llX", static_cast<unsigned long long>(cfg.end_address));
	std::snprintf(input_buf, sizeof(input_buf), "0x%llX", static_cast<unsigned long long>(cfg.input_address));
	json result;
	result["status"] = "started";
	result["worker_posted"] = true;
	result["pid"] = cfg.pid;
	result["tid"] = cfg.tid;
	result["thread_count"] = threads_snap.size();
	result["target_address"] = target;
	result["end_address"] = end_buf;
	result["input_address"] = input_buf;
	result["input_size"] = cfg.input_size;
	result["max_iterations"] = cfg.max_iterations;
	result["setup_complete"] = fuzzer_engine::g_state.setup_complete.load();
	result["setup_success"] = fuzzer_engine::g_state.setup_success.load();
	return tool_result_t::ok(result);
}

static tool_result_t fuzzer_manage_stop(const json&)
{
	diag::log_tagged("analysis", "fuzzer_manage stop");
	fuzzer_engine::stop_fuzzing();
	return tool_result_t::ok("Fuzzer stop requested.");
}

static tool_result_t fuzzer_manage_results(const json&)
{
	diag::log_tagged("analysis", "fuzzer_manage results");
	std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
	auto& stats = fuzzer_engine::g_state.stats;
	json result;
	result["running"] = fuzzer_engine::g_state.running.load();
	result["total_executions"] = stats.total_executions;
	result["executions_per_second"] = stats.executions_per_second;
	result["total_crashes"] = stats.total_crashes;
	result["unique_crashes"] = stats.total_unique_crashes;
	result["edge_coverage"] = stats.edge_coverage;
	result["new_coverage_finds"] = stats.new_coverage_finds;
	result["corpus_size"] = stats.corpus_size;
	result["elapsed_seconds"] = stats.elapsed_seconds;
	result["setup_error"] = fuzzer_engine::g_state.setup_error;
	result["worker_active"] = fuzzer_engine::g_state.worker_active.load();
	result["setup_complete"] = fuzzer_engine::g_state.setup_complete.load();
	result["setup_success"] = fuzzer_engine::g_state.setup_success.load();
	json crashes_arr = json::array();
	for (auto& c : fuzzer_engine::g_state.unique_crashes) {
		json cobj;
		cobj["type"] = fuzzer_engine::crash_type_name(c.type);
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(c.instruction_address));
		cobj["instruction_address"] = abuf;
		cobj["description"] = c.description;
		crashes_arr.push_back(cobj);
	}
	result["crashes"] = crashes_arr;
	return tool_result_t::ok(result);
}

static tool_result_t live_monitor_manage_start(const json& params)
{
	std::string addr_str = params.value("address", "");
	int size = params.value("size", 256);
	std::string name = params.value("name", "struct_t");
	std::string backend = params.value("backend", "auto");
	uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 3000, 100, 3500);
	diag::log_tagged_fmt("analysis", "live_monitor_manage start addr=%s size=%d backend=%s",
		addr_str.c_str(), size, backend.c_str());
	if (addr_str.empty())
		return tool_result_t::error("address parameter is required");
	uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
	if (addr == 0)
		return tool_result_t::error("invalid address");
	if (struct_monitor::g_state.active.load())
		return tool_result_t::error("Live monitor already active. Stop it first.");
	if (size <= 0)
		return tool_result_t::error("size must be positive");

	struct_monitor::start(addr, size, name, backend);
	int max_wait = static_cast<int>((timeout_ms + 49) / 50);
	for (int wait = 0; wait < max_wait; ++wait) {
		if (!struct_monitor::g_state.active.load())
			break;
		if (struct_monitor::g_state.session.using_page_guard ||
		    struct_monitor::g_state.session.using_hwbp ||
		    struct_monitor::g_state.session.using_polling)
			break;
		Sleep(50);
	}

	bool active = struct_monitor::g_state.active.load();
	bool page_guard = struct_monitor::g_state.session.using_page_guard;
	bool hwbp = struct_monitor::g_state.session.using_hwbp;
	bool polling = struct_monitor::g_state.session.using_polling;
	char abuf[32];
	std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(addr));
	json result;
	result["address"] = abuf;
	result["size"] = size;
	result["active"] = active;
	result["backend"] = page_guard ? "page_guard" : (hwbp ? "hardware_breakpoint" : (polling ? "polling" : "none"));
	result["page_guard"] = page_guard;
	result["hardware_breakpoint"] = hwbp;
	result["polling"] = polling;
	result["total_captures"] = struct_monitor::g_state.total_captures.load();
	if (!active || (!page_guard && !hwbp && !polling)) {
		struct_monitor::stop();
		for (int wait = 0; wait < 10 && struct_monitor::g_state.active.load(); ++wait)
			Sleep(50);
		return tool_result_t::error("live monitor backend did not become active", result);
	}
	return tool_result_t::ok(result);
}

static tool_result_t live_monitor_snapshot(bool require_captures)
{
	auto accesses = struct_monitor::get_access_snapshot();
	json arr = json::array();
	for (auto& a : accesses) {
		json obj;
		char obuf[16];
		std::snprintf(obuf, sizeof(obuf), "0x%04llX", static_cast<unsigned long long>(a.field_offset));
		obj["offset"] = obuf;
		obj["access_size"] = a.access_size;
		obj["is_write"] = a.is_write;
		obj["inferred_type"] = struct_recon::field_type_name(a.inferred_type);
		obj["hit_count"] = a.hit_count;
		obj["disasm"] = a.disasm;
		char rbuf[32];
		std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(a.rip));
		obj["rip"] = rbuf;
		arr.push_back(obj);
	}
	json result;
	result["active"] = struct_monitor::g_state.active.load();
	result["total_captures"] = struct_monitor::g_state.total_captures.load();
	result["unique_offsets"] = accesses.size();
	result["page_guard"] = struct_monitor::g_state.session.using_page_guard;
	result["hardware_breakpoint"] = struct_monitor::g_state.session.using_hwbp;
	result["polling"] = struct_monitor::g_state.session.using_polling;
	result["accesses"] = arr;
	if (require_captures && accesses.empty())
		return tool_result_t::error("live monitor captured no accesses", result);
	return tool_result_t::ok(result);
}

static tool_result_t live_monitor_manage_stop(const json& params)
{
	diag::log_tagged("analysis", "live_monitor_manage stop");
	if (!struct_monitor::g_state.active.load())
		return tool_result_t::error("No active live monitor session.");
	struct_monitor::stop();
	for (int wait = 0; struct_monitor::g_state.active.load() && wait < 10; ++wait)
		Sleep(50);
	return live_monitor_snapshot(params.value("require_captures", false));
}

static tool_result_t symbolic_manage_deobfuscate(const json& params)
{
	std::string addr_str = params.value("entry_address", "");
	if (addr_str.empty())
		return tool_result_t::error("entry_address is required");
	uint64_t entry = std::strtoull(addr_str.c_str(), nullptr, 16);
	if (entry == 0)
		return tool_result_t::error("invalid entry_address");
	uint32_t max_insns = static_cast<uint32_t>(params.value("max_instructions", 10000));
	auto result = deobfuscation_engine::deobfuscate_function(entry, max_insns);
	json out;
	out["statistics"] = {
		{"total_instructions", result.total_original},
		{"clean_instructions", result.total_clean},
		{"junk_removed", result.removed_junk},
		{"opaque_predicates", result.opaque_predicates_found},
		{"constants_resolved", result.constants_resolved}
	};
	json insns = json::array();
	for (auto& ci : result.clean_instructions) {
		json obj;
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ci.address));
		obj["address"] = abuf;
		obj["disasm"] = ci.disasm;
		obj["is_original"] = !ci.was_junk;
		obj["was_constant_folded"] = ci.was_constant_folded;
		insns.push_back(obj);
	}
	out["clean_instructions"] = insns;
	json opaques = json::array();
	for (auto& op : result.opaques) {
		json obj;
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(op.address));
		obj["address"] = abuf;
		obj["condition_str"] = op.condition_ast;
		obj["always_true"] = op.always_taken;
		opaques.push_back(obj);
	}
	out["opaque_predicates"] = opaques;
	json constants = json::array();
	for (auto& cf : result.constants) {
		json obj;
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(cf.address));
		obj["address"] = abuf;
		obj["original_expression"] = cf.original_ast;
		char vbuf[32];
		std::snprintf(vbuf, sizeof(vbuf), "0x%llX", static_cast<unsigned long long>(cf.concrete_value));
		obj["resolved_value"] = vbuf;
		constants.push_back(obj);
	}
	out["constants"] = constants;
	return tool_result_t::ok(out);
}

static tool_result_t symbolic_manage_slice(const json& params)
{
	std::string start_str = params.value("start_address", "");
	std::string end_str = params.value("end_address", "");
	std::string reg = params.value("target_register", "");
	if (start_str.empty() || end_str.empty() || reg.empty())
		return tool_result_t::error("start_address, end_address, and target_register are required");
	uint64_t start = std::strtoull(start_str.c_str(), nullptr, 16);
	uint64_t end = std::strtoull(end_str.c_str(), nullptr, 16);
	uint32_t max_insns = static_cast<uint32_t>(params.value("max_instructions", 5000));
	auto result = symbolic_engine::slice_to_register(start, end, max_insns, reg);
	json out;
	out["target_register"] = reg;
	out["total_instructions"] = result.total_instructions;
	out["effective_instructions"] = result.effective_count;
	out["removed_count"] = result.total_instructions - result.effective_count;
	json insns = json::array();
	for (auto& ti : result.effective_instructions) {
		json obj;
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ti.address));
		obj["address"] = abuf;
		obj["disasm"] = ti.disasm;
		insns.push_back(obj);
	}
	out["instructions"] = insns;
	return tool_result_t::ok(out);
}

static tool_result_t symbolic_manage_solve_path(const json& params)
{
	std::string start_str = params.value("start_address", "");
	std::string target_str = params.value("target_address", "");
	std::string regs_str = params.value("symbolic_registers", "");
	if (start_str.empty() || target_str.empty() || regs_str.empty())
		return tool_result_t::error("start_address, target_address, and symbolic_registers are required");
	uint64_t start = std::strtoull(start_str.c_str(), nullptr, 16);
	uint64_t target = std::strtoull(target_str.c_str(), nullptr, 16);
	uint32_t max_insns = static_cast<uint32_t>(params.value("max_instructions", 5000));
	std::vector<std::string> sym_regs;
	std::istringstream iss(regs_str);
	std::string tok;
	while (std::getline(iss, tok, ',')) {
		while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
		while (!tok.empty() && tok.back() == ' ') tok.pop_back();
		if (!tok.empty())
			sym_regs.push_back(tok);
	}
	auto result = symbolic_engine::solve_for_path(start, target, max_insns, sym_regs);
	json out;
	out["satisfiable"] = result.satisfiable;
	out["solving_time_ms"] = result.solving_time_ms;
	if (result.satisfiable) {
		json vars = json::object();
		for (auto& kv : result.variable_values) {
			char vbuf[32];
			std::snprintf(vbuf, sizeof(vbuf), "0x%llX", static_cast<unsigned long long>(kv.second));
			vars[kv.first] = vbuf;
		}
		out["solution"] = vars;
	}
	return tool_result_t::ok(out);
}

static tool_result_t analysis_query_imports(const json& params)
{
	if (driver_bridge::attached_pid() == 0)
		return tool_result_t::error("No process is attached; use sessions_manage action=attach_pid first.");
	auto modules = driver_bridge::enumerate_modules();
	if (modules.empty())
		return tool_result_t::error("Module enumeration returned no entries.");
	pe_parser::pe_info_t pe;
	if (!pe_parser::parse(modules.front().base, pe, false))
		return tool_result_t::error("pe_parser::parse failed on the main module.");
	size_t max_entries = bounded_size_param(params, "max_entries", 512, 1, 4096);
	uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 2500, 100, 10000);
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	bool truncated = false;
	bool parsed = pe_parser::parse_imports(modules.front().base, pe, pe.imports, max_entries, &deadline, &truncated);
	if (!parsed)
		truncated = true;
	json arr = json::array();
	char buf[32];
	for (const auto& imp : pe.imports) {
		json o;
		o["module"] = imp.module_name;
		o["function"] = imp.function_name;
		o["ordinal"] = imp.ordinal;
		o["hint"] = imp.hint;
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(imp.iat_address));
		o["iat_address"] = buf;
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(imp.bound_address));
		o["bound_address"] = buf;
		arr.push_back(std::move(o));
	}
	json result;
	result["module"] = modules.front().name;
	result["count"] = arr.size();
	result["truncated"] = truncated;
	result["parse_complete"] = parsed && !truncated;
	result["max_entries"] = max_entries;
	result["timeout_ms"] = timeout_ms;
	result["imports"] = std::move(arr);
	return tool_result_t::ok(result);
}

static tool_result_t analysis_query_exports(const json& params)
{
	if (driver_bridge::attached_pid() == 0)
		return tool_result_t::error("No process is attached; use sessions_manage action=attach_pid first.");
	auto modules = driver_bridge::enumerate_modules();
	if (modules.empty())
		return tool_result_t::error("Module enumeration returned no entries.");
	const std::string requested_module = params.value("module_name", std::string());
	const driver_bridge::module_info_t* selected = select_module_by_name(modules, requested_module);
	if (!selected)
		return tool_result_t::error("Requested module was not found in the attached process.");
	pe_parser::pe_info_t pe;
	if (!pe_parser::parse(selected->base, pe, false))
		return tool_result_t::error("pe_parser::parse failed on the selected module.");
	size_t max_entries = bounded_size_param(params, "max_entries", 512, 1, 4096);
	uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 2500, 100, 10000);
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	bool truncated = false;
	bool parsed = pe_parser::parse_exports(selected->base, pe, pe.exports, max_entries, &deadline, &truncated);
	if (!parsed)
		truncated = true;
	json arr = json::array();
	char buf[32];
	for (const auto& exp : pe.exports) {
		json o;
		o["ordinal"] = exp.ordinal;
		o["name"] = exp.name;
		std::snprintf(buf, sizeof(buf), "0x%X", exp.rva);
		o["rva"] = buf;
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(exp.address));
		o["address"] = buf;
		if (exp.is_forwarded) {
			o["forwarded"] = true;
			o["forward_to"] = exp.forward_name;
		}
		arr.push_back(std::move(o));
	}
	json result;
	result["module"] = selected->name;
	result["module_path"] = selected->path;
	std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(selected->base));
	result["module_base"] = buf;
	result["count"] = arr.size();
	result["truncated"] = truncated;
	result["parse_complete"] = parsed && !truncated;
	result["max_entries"] = max_entries;
	result["timeout_ms"] = timeout_ms;
	result["exports"] = std::move(arr);
	return tool_result_t::ok(result);
}

static tool_result_t analysis_query_types(const json& params)
{
	std::string filter;
	if (params.contains("filter") && params["filter"].is_string()) {
		filter = params["filter"].get<std::string>();
		std::transform(filter.begin(), filter.end(), filter.begin(), [](unsigned char c) {
			return static_cast<char>(std::tolower(c));
		});
	}
	size_t limit = bounded_size_param(params, "limit", 200, 1, 5000);
	json arr = json::array();
	size_t total = 0;
	{
		std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
		for (const auto& kv : symbol_store::g_state.modules) {
			const auto& mod = kv.second;
			for (const auto& s : mod.pdb.structs) {
				std::string lname = lower_ascii(s.name);
				if (!filter.empty() && lname.find(filter) == std::string::npos)
					continue;
				++total;
				if (arr.size() >= limit) continue;
				arr.push_back({{"module", mod.module_name}, {"name", s.name}, {"kind", s.is_union ? "union" : "struct"}, {"size", s.size}, {"member_count", s.members.size()}});
			}
			for (const auto& e : mod.pdb.enums) {
				std::string lname = lower_ascii(e.name);
				if (!filter.empty() && lname.find(filter) == std::string::npos)
					continue;
				++total;
				if (arr.size() >= limit) continue;
				arr.push_back({{"module", mod.module_name}, {"name", e.name}, {"kind", "enum"}, {"member_count", e.members.size()}});
			}
		}
	}
	return tool_result_t::ok(json{{"total", total}, {"returned", arr.size()}, {"types", arr}});
}

static tool_result_t analysis_query_type_definition(const json& params)
{
	if (!params.contains("name") || !params["name"].is_string())
		return tool_result_t::error("'name' is required.");
	std::string want = params["name"].get<std::string>();
	std::string want_module = params.value("module", std::string());
	std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
	for (const auto& kv : symbol_store::g_state.modules) {
		const auto& mod = kv.second;
		if (!want_module.empty() && mod.module_name != want_module) continue;
		for (const auto& s : mod.pdb.structs) {
			if (s.name != want) continue;
			json members = json::array();
			for (const auto& m : s.members) {
				json mj;
				mj["name"] = m.name;
				mj["type"] = m.type_name;
				mj["offset"] = m.offset;
				mj["size"] = m.size;
				if (m.is_pointer) {
					mj["pointer"] = true;
					mj["pointer_depth"] = m.pointer_depth;
				}
				if (m.is_array) {
					mj["array"] = true;
					mj["array_count"] = m.array_count;
				}
				if (m.bit_offset >= 0) mj["bit_offset"] = m.bit_offset;
				if (m.bit_size >= 0) mj["bit_size"] = m.bit_size;
				members.push_back(std::move(mj));
			}
			return tool_result_t::ok(json{{"module", mod.module_name}, {"name", s.name}, {"kind", s.is_union ? "union" : "struct"}, {"size", s.size}, {"members", members}});
		}
		for (const auto& e : mod.pdb.enums) {
			if (e.name != want) continue;
			json members = json::array();
			for (const auto& em : e.members)
				members.push_back({{"name", em.name}, {"value", em.value}});
			return tool_result_t::ok(json{{"module", mod.module_name}, {"name", e.name}, {"kind", "enum"}, {"members", members}});
		}
	}
	if (want == "HANDLE")
		return tool_result_t::ok(json{{"module", "builtin"}, {"name", "HANDLE"}, {"kind", "typedef"}, {"type", "void*"}, {"size", sizeof(void*)}, {"members", json::array()}});
	return tool_result_t::error("Type not found in any loaded module's PDB.");
}

static tool_result_t analysis_query_pdb_symbols(const json& params)
{
	std::string filter;
	if (params.contains("filter") && params["filter"].is_string())
		filter = lower_ascii(params["filter"].get<std::string>());
	std::string want_module = params.value("module", std::string());
	bool funcs_only = params.value("functions_only", false);
	size_t limit = bounded_size_param(params, "limit", 500, 1, 10000);
	json arr = json::array();
	size_t total = 0;
	char buf[32];
	{
		std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
		for (const auto& kv : symbol_store::g_state.modules) {
			const auto& mod = kv.second;
			if (!want_module.empty() && mod.module_name != want_module) continue;
			for (const auto& sym : mod.pdb.symbols) {
				if (funcs_only && !sym.is_function) continue;
				if (!filter.empty() && lower_ascii(sym.name).find(filter) == std::string::npos) continue;
				++total;
				if (arr.size() >= limit) continue;
				json o;
				o["module"] = mod.module_name;
				o["name"] = sym.name;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(mod.base + sym.rva));
				o["address"] = buf;
				std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(sym.rva));
				o["rva"] = buf;
				o["size"] = sym.size;
				o["is_function"] = sym.is_function;
				arr.push_back(std::move(o));
			}
		}
	}
	return tool_result_t::ok(json{{"total", total}, {"returned", arr.size()}, {"symbols", arr}});
}

static tool_result_t analysis_query_binary_map_overview(const json& params)
{
	if (params.value("fast_summary", false) &&
		!params.value("include_imports", false) &&
		!params.value("include_exports", false) &&
		!params.value("include_xrefs", false)) {
		return analysis_query_binary_map_fast_summary(params);
	}
	aida::binary_map::map_options_t opts;
	opts.max_functions = params.value("max_functions", 24);
	opts.max_globals = params.value("max_globals", 12);
	opts.max_callees_per_function = 2;
	opts.include_imports = params.value("include_imports", false);
	opts.include_exports = params.value("include_exports", false);
	opts.include_xrefs = params.value("include_xrefs", false);
	opts.include_entropy = !params.value("fast_summary", false);
	aida::binary_map::map_t m;
	if (!aida::binary_map::generate(opts, m))
		return tool_result_t::error(aida::binary_map::last_error());
	char buf[32];
	json sections = json::array();
	for (const auto& s : m.sections) {
		json o;
		o["name"] = s.name;
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(s.va));
		o["va"] = buf;
		o["size"] = s.size;
		o["executable"] = s.executable;
		o["readable"] = s.readable;
		o["writable"] = s.writable;
		sections.push_back(std::move(o));
	}
	json functions = json::array();
	for (const auto& f : m.functions) {
		json o;
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(f.va));
		o["va"] = buf;
		o["name"] = f.name;
		o["xref_count"] = f.xref_count;
		o["callee_count"] = f.callee_count;
		if (!f.section_name.empty()) o["section"] = f.section_name;
		if (!f.top_callees.empty()) o["top_callees"] = f.top_callees;
		if (f.pinned) o["pinned"] = true;
		functions.push_back(std::move(o));
	}
	json globals = json::array();
	for (const auto& g : m.globals) {
		json o;
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(g.va));
		o["va"] = buf;
		o["name"] = g.name;
		o["xref_count"] = g.xref_count;
		o["writable"] = g.writable;
		if (!g.section_name.empty()) o["section"] = g.section_name;
		globals.push_back(std::move(o));
	}
	std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(m.image_base));
	json result;
	result["module_name"] = m.module_name;
	result["module_path"] = m.module_path;
	result["architecture"] = m.architecture;
	result["format"] = m.format;
	result["image_base"] = buf;
	result["image_size"] = m.image_size;
	result["sections"] = std::move(sections);
	result["functions"] = std::move(functions);
	result["globals"] = std::move(globals);
	result["imports"] = m.imports;
	result["exports"] = m.exports;
	result["fast_summary"] = params.value("fast_summary", false);
	return tool_result_t::ok(result);
}

static tool_result_t analysis_query_xref_db_stats(const json&)
{
	std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
	json arr = json::array();
	size_t total = 0;
	size_t built = 0;
	for (const auto& kv : xref_db::g_state.modules) {
		const auto& mod = kv.second;
		arr.push_back({{"module", mod.name}, {"base", mod.base}, {"size", mod.size}, {"total_xrefs", mod.total_xrefs}, {"built", mod.built}});
		if (mod.built) {
			++built;
			total += mod.total_xrefs;
		}
	}
	return tool_result_t::ok(json{{"module_count", xref_db::g_state.modules.size()}, {"modules_built", built}, {"total_xrefs", total}, {"building", xref_db::g_state.building.load()}, {"progress", xref_db::g_state.progress.load()}, {"modules", arr}});
}

void register_analysis_tools(mcp_standalone::server_t& srv)
{
	srv.register_tool({
		"scan_crypto_constants",
		"Scan the attached process memory for well-known cryptographic constants (AES S-Box, SHA-256, MD5, CRC32, Blowfish, DES, ChaCha20, Base64, etc).",
		{
			{"module_filter", "string", "Optional case-insensitive module name substring to scan", false},
			{"max_regions", "integer", "Maximum committed readable regions to scan (default 4096)", false},
			{"max_bytes", "integer", "Maximum bytes to scan before stopping (0 = unlimited)", false},
			{"max_hits", "integer", "Maximum hits before stopping (0 = unlimited)", false},
			{"range_base", "string", "Optional hex base address limiting the scan to a target range", false},
			{"range_size", "integer", "Optional byte size for range_base-limited scans", false},
			{"timeout_ms", "integer", "Maximum scan time before cancellation (default 4500, max 60000)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			crypto_scanner::process_scan_config_t cfg;
			cfg.module_filter = params.value("module_filter", std::string());
			cfg.max_regions = params.value("max_regions", static_cast<size_t>(4096));
			cfg.max_bytes = params.value("max_bytes", static_cast<uint64_t>(0));
			cfg.max_hits = params.value("max_hits", static_cast<size_t>(0));
			cfg.timeout_ms = bounded_u32_param(params, "timeout_ms", 4500, 100, 60000);
			std::string range_base_str = params.value("range_base", std::string());
			if (!range_base_str.empty())
				cfg.range_base = std::strtoull(range_base_str.c_str(), nullptr, 16);
			cfg.range_size = static_cast<uint64_t>(bounded_size_param(params, "range_size", 0, 0, 64ULL * 1024ULL * 1024ULL));
			if ((!range_base_str.empty() && cfg.range_base == 0) || (cfg.range_size != 0 && cfg.range_base == 0))
				return tool_result_t::error("invalid range_base");
			if (cfg.range_base != 0 && cfg.range_size == 0)
				return tool_result_t::error("range_size must be non-zero when range_base is provided");
			cfg.label_references = false;
			diag::log_tagged_fmt("analysis", "scan_crypto_constants entry module_filter='%s' max_regions=%zu max_bytes=%llu max_hits=%zu timeout_ms=%u range=0x%llX+0x%llX",
				cfg.module_filter.c_str(),
				cfg.max_regions,
				static_cast<unsigned long long>(cfg.max_bytes),
				cfg.max_hits,
				cfg.timeout_ms,
				static_cast<unsigned long long>(cfg.range_base),
				static_cast<unsigned long long>(cfg.range_size));
			if (crypto_scanner::g_state.scanning.load()) {
				diag::log_tagged("analysis", "scan_crypto_constants refused already_scanning");
				return tool_result_t::error("A crypto scan is already in progress.");
			}
			crypto_scanner::scan_process(cfg);
			diag::log_tagged("analysis", "scan_crypto_constants scan_process called waiting");

			int wait = 0;
			int max_wait = static_cast<int>((cfg.timeout_ms + 49) / 50);
			while (crypto_scanner::g_state.scanning.load() && wait < max_wait) {
				Sleep(50);
				++wait;
			}
			bool timed_out = crypto_scanner::g_state.scanning.load();
			if (timed_out) {
				crypto_scanner::cancel();
				for (int stop_wait = 0; crypto_scanner::g_state.scanning.load() && stop_wait < 10; ++stop_wait)
					Sleep(50);
			}

			std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
			auto& results = crypto_scanner::g_state.results;
			diag::log_tagged_fmt("analysis", "scan_crypto_constants complete count=%zu timed_out=%d still_running=%d",
				results.size(), timed_out ? 1 : 0, crypto_scanner::g_state.scanning.load() ? 1 : 0);

			json arr = json::array();
			for (auto& r : results) {
				json obj;
				obj["signature"] = r.signature_name;
				obj["algorithm"] = r.algorithm;
				obj["category"] = crypto_scanner::category_name(r.category);
				char addr_buf[32];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(r.address));
				obj["address"] = addr_buf;
				obj["module"] = r.module_name;
				char off_buf[32];
				std::snprintf(off_buf, sizeof(off_buf), "0x%llX", static_cast<unsigned long long>(r.module_offset));
				obj["module_offset"] = off_buf;
				arr.push_back(obj);
			}

			json result;
			result["count"] = results.size();
			result["results"] = arr;
			result["status"] = crypto_scanner::g_state.scanning.load() ? "cancel_requested" : (timed_out ? "cancelled_by_timeout" : "complete");
			result["timed_out"] = timed_out;
			if (timed_out)
				return tool_result_t{false, "Crypto scan did not complete within the timeout.", result};
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"generate_aob_signature",
		"Generate an AOB (Array of Bytes) signature from a given address. Automatically wildcards RIP-relative and large immediate bytes.",
		{
			{"address", "string", "Hex address to generate signature from (e.g. '0x7FF6A1234567')", true},
			{"instruction_count", "integer", "Number of instructions to include (default: 16)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			int count = params.value("instruction_count", 16);
			diag::log_tagged_fmt("analysis", "generate_aob_signature entry addr=%s count=%d",
				addr_str.c_str(), count);

			if (addr_str.empty()) {
				diag::log_tagged("analysis", "generate_aob_signature refused no_address");
				return tool_result_t::error("address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				diag::log_tagged("analysis", "generate_aob_signature refused invalid_address");
				return tool_result_t::error("invalid address");
			}

			diag::log_tagged_fmt("analysis", "generate_aob_signature generating addr=0x%llX count=%d",
				static_cast<unsigned long long>(addr), count);
			aob_generator::generate_from_address(addr, count, true);

			int wait = 0;
			while (aob_generator::g_state.generating.load() && wait < 100) {
				Sleep(100);
				++wait;
			}

			aob_generator::signature_t sig;
			std::string tool_last_error;
			{
				std::lock_guard<std::mutex> lk(aob_generator::g_state.mutex);
				sig = aob_generator::g_state.current;
				tool_last_error = aob_generator::g_state.last_error;
			}

			if (sig.bytes.empty() || sig.address != addr) {
				std::string err_msg = tool_last_error.empty()
					? std::string("Failed to generate signature (could not read memory or decode instructions)")
					: tool_last_error;
				diag::log_tagged_fmt("analysis", "generate_aob_signature failed addr=0x%llX err=%s",
					static_cast<unsigned long long>(addr), err_msg.c_str());
				return tool_result_t::error(err_msg);
			}

			json result;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(sig.address));
			result["address"] = abuf;
			result["module"] = sig.module_name;
			result["byte_count"] = sig.bytes.size();
			diag::log_tagged_fmt("analysis", "generate_aob_signature complete addr=0x%llX bytes=%zu module=%s",
				static_cast<unsigned long long>(sig.address), sig.bytes.size(), sig.module_name.c_str());
			result["standard"] = aob_generator::format_signature(sig);
			result["ida_style"] = aob_generator::format_ida_signature(sig);
			result["code_pattern"] = aob_generator::format_code_signature(sig);

			int wc = 0;
			for (auto& b : sig.bytes) if (b.wildcard) ++wc;
			result["wildcard_bytes"] = wc;

			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"reconstruct_struct",
		"Reconstruct a C++ struct/class layout from a memory address by analyzing memory contents, detecting VTables, and inferring field types.",
		{
			{"address", "string", "Base address of the struct instance in hex", true},
			{"size", "integer", "Size in bytes to analyze (default: 256)", false},
			{"name", "string", "Name for the struct (default: 'struct_t')", false},
			{"timeout_ms", "integer", "Maximum wait time before returning the current partial layout (default: 4500, max 4500)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			int size = params.value("size", 256);
			std::string name = params.value("name", "struct_t");
			uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 4500, 100, 4500);
			diag::log_tagged_fmt("analysis", "reconstruct_struct entry addr=%s size=%d name=%s",
				addr_str.c_str(), size, name.c_str());

			if (addr_str.empty()) {
				diag::log_tagged("analysis", "reconstruct_struct refused no_address");
				return tool_result_t::error("address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				diag::log_tagged("analysis", "reconstruct_struct refused invalid_address");
				return tool_result_t::error("invalid address");
			}

			diag::log_tagged_fmt("analysis", "reconstruct_struct starting addr=0x%llX size=%d name=%s",
				static_cast<unsigned long long>(addr), size, name.c_str());
			struct_recon::reconstruct_from_snapshot(addr, size, name);

			int wait = 0;
			int max_wait = static_cast<int>((timeout_ms + 49) / 50);
			while (struct_recon::g_state.monitoring.load() && wait < max_wait) {
				Sleep(50);
				++wait;
			}
			bool timed_out = struct_recon::g_state.monitoring.load();
			if (timed_out)
				struct_recon::cancel();

			struct_recon::reconstructed_struct_t result_struct;
			{
				std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
				result_struct = struct_recon::g_state.current;
			}

			diag::log_tagged_fmt("analysis", "reconstruct_struct complete addr=0x%llX name=%s fields=%zu size=%u has_vtable=%d",
				static_cast<unsigned long long>(result_struct.base_address),
				result_struct.name.c_str(), result_struct.fields.size(),
				result_struct.total_size, result_struct.has_vtable ? 1 : 0);
			std::string cpp_output = struct_recon::export_as_cpp(result_struct);

			json result;
			result["name"] = result_struct.name;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(result_struct.base_address));
			result["base_address"] = abuf;
			result["total_size"] = result_struct.total_size;
			result["field_count"] = result_struct.fields.size();
			result["has_vtable"] = result_struct.has_vtable;
			result["cpp_definition"] = cpp_output;
			result["timed_out"] = timed_out;
			result["timeout_ms"] = timeout_ms;

			json fields_arr = json::array();
			for (auto& f : result_struct.fields) {
				json fobj;
				char off_buf[16];
				std::snprintf(off_buf, sizeof(off_buf), "0x%04llX", static_cast<unsigned long long>(f.offset));
				fobj["offset"] = off_buf;
				fobj["size"] = f.size;
				fobj["type"] = struct_recon::field_type_name(f.type);
				fobj["name"] = f.name;
				if (f.type == struct_recon::field_type_t::vtable_ptr) {
					fobj["vtable_entries"] = static_cast<int>(f.vtable_entries.size());
				}
				fields_arr.push_back(fobj);
			}
			result["fields"] = fields_arr;

			return tool_result_t::ok(result);
		}
	});




	srv.register_tool({
		"auto_decrypt_strings",
		"Automatically decrypt obfuscated strings by emulating functions that reference a suspected encrypted region. Finds xrefs to the region, emulates each referencing function, and captures memory writes that produce printable strings.",
		{
			{"region_address", "string", "Hex address of the encrypted string region", true},
			{"region_size", "integer", "Size of the region in bytes (default: 4096)", false},
			{"timeout_ms", "integer", "Maximum wait time before cancellation (default: 4500, max 4500)", false},
			{"search_start", "string", "Optional hex address limiting xref search to a specific range", false},
			{"search_size", "integer", "Optional xref search range size in bytes", false}
		},
		false,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("region_address", "");
			uint64_t size = params.value("region_size", 4096);
			uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 4500, 100, 4500);
			std::string search_start_str = params.value("search_start", "");
			uint64_t search_start = search_start_str.empty()
				? 0
				: std::strtoull(search_start_str.c_str(), nullptr, 16);
			uint64_t search_size = static_cast<uint64_t>(bounded_size_param(params, "search_size", 0, 0, 64ULL * 1024ULL * 1024ULL));
			diag::log_tagged_fmt("analysis", "auto_decrypt_strings entry addr=%s size=%llu",
				addr_str.c_str(), static_cast<unsigned long long>(size));

			if (addr_str.empty()) {
				diag::log_tagged("analysis", "auto_decrypt_strings refused no_region_address");
				return tool_result_t::error("region_address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				diag::log_tagged("analysis", "auto_decrypt_strings refused invalid_region_address");
				return tool_result_t::error("invalid region_address");
			}

			diag::log_tagged_fmt("analysis", "auto_decrypt_strings scanning addr=0x%llX size=%llu",
				static_cast<unsigned long long>(addr), static_cast<unsigned long long>(size));
			decrypt_oracle::scan_and_decrypt(addr, size, timeout_ms, search_start, search_size);

			int wait = 0;
			int max_wait = static_cast<int>((timeout_ms + 99) / 100);
			while (decrypt_oracle::g_state.scanning.load() && wait < max_wait) {
				if (mcp_standalone::current_call_cancelled()) {
					decrypt_oracle::g_state.cancel.store(true, std::memory_order_release);
					xref_engine::cancel_scan();
					break;
				}
				Sleep(100);
				++wait;
			}

			bool timed_out = decrypt_oracle::g_state.scanning.load() ||
				decrypt_oracle::g_state.timed_out.load();
			if (timed_out) {
				decrypt_oracle::g_state.timed_out.store(true, std::memory_order_release);
				decrypt_oracle::g_state.cancel.store(true, std::memory_order_release);
				xref_engine::cancel_scan();
				for (int stop_wait = 0; decrypt_oracle::g_state.scanning.load() && stop_wait < 10; ++stop_wait)
					Sleep(50);
			}

			std::lock_guard<std::mutex> lk(decrypt_oracle::g_state.mutex);
			auto& results = decrypt_oracle::g_state.results;
			diag::log_tagged_fmt("analysis", "auto_decrypt_strings complete count=%zu total_xrefs=%d processed_xrefs=%d timed_out=%d status=%s",
				results.size(),
				decrypt_oracle::g_state.total_xrefs.load(std::memory_order_acquire),
				decrypt_oracle::g_state.processed_xrefs.load(std::memory_order_acquire),
				timed_out ? 1 : 0,
				decrypt_oracle::g_state.status_text.c_str());

			json arr = json::array();
			for (auto& r : results) {
				json obj;
				char fbuf[32];
				std::snprintf(fbuf, sizeof(fbuf), "0x%llX", static_cast<unsigned long long>(r.source_function));
				obj["source_function"] = fbuf;
				char obuf[32];
				std::snprintf(obuf, sizeof(obuf), "0x%llX", static_cast<unsigned long long>(r.encrypted_offset));
				obj["encrypted_offset"] = obuf;
				obj["decrypted_string"] = r.decrypted;
				obj["length"] = r.length;
				obj["confidence"] = r.confidence;
				obj["is_utf16"] = r.is_utf16;
				arr.push_back(obj);
			}

			json result;
			result["count"] = results.size();
			result["results"] = arr;
			result["timed_out"] = timed_out;
			result["total_xrefs"] = decrypt_oracle::g_state.total_xrefs.load(std::memory_order_acquire);
			result["processed_xrefs"] = decrypt_oracle::g_state.processed_xrefs.load(std::memory_order_acquire);
			result["status_text"] = decrypt_oracle::g_state.status_text;
			if (timed_out) {
				result["status"] = "timeout";
				result["cancelled"] = true;
				result["message"] = "auto_decrypt_strings timed out and cancellation was requested";
				return tool_result_t{false, "auto_decrypt_strings timed out and cancellation was requested", result};
			}
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"hunt_integrity_checkers",
		"Find integrity checker threads by monitoring reads on a code region using page guards. Returns discovered checker RIPs, their read frequency, and associated hash comparison addresses.",
		{
			{"target_address", "string", "Hex address of the code region to protect", true},
			{"target_size", "integer", "Size of the region to monitor (default: 4096)", false},
			{"duration_ms", "integer", "How long to monitor in milliseconds (default: 1000, max 4500)", false}
		},
		false,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("target_address", "");
			uint64_t size = bounded_u32_param(params, "target_size", 4096, 1, 1024 * 1024);
			int duration = static_cast<int>(bounded_u32_param(params, "duration_ms", 1000, 100, 4500));

			if (addr_str.empty()) {
				return tool_result_t::error("target_address parameter is required");
			}

			uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
			if (addr == 0) {
				return tool_result_t::error("invalid target_address");
			}

			diag::log_tagged_fmt("integrity_hunter",
				"mcp_hunt_request addr=0x%llX size=%llu duration_ms=%d",
				static_cast<unsigned long long>(addr),
				static_cast<unsigned long long>(size), duration);

			if (!integrity_hunter::start_hunt(addr, size)) {
				diag::log_tagged("integrity_hunter", "mcp_hunt_start_failed");
				return tool_result_t::error("integrity hunter could not start");
			}

			const auto install_start = std::chrono::steady_clock::now();
			while (!integrity_hunter::g_state.install_complete.load() &&
			       (integrity_hunter::g_state.hunting.load() || integrity_hunter::g_state.worker_active.load())) {
				const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - install_start).count();
				if (elapsed >= 6500) {
					diag::log_tagged_fmt("integrity_hunter",
						"mcp_hunt_install_timeout addr=0x%llX size=%llu elapsed_ms=%lld hunting=%d worker=%d",
						static_cast<unsigned long long>(addr),
						static_cast<unsigned long long>(size),
						static_cast<long long>(elapsed),
						integrity_hunter::g_state.hunting.load() ? 1 : 0,
						integrity_hunter::g_state.worker_active.load() ? 1 : 0);
					integrity_hunter::stop_hunt();
					const bool idle = integrity_hunter::wait_until_idle(12000);
					diag::log_tagged_fmt("integrity_hunter", "mcp_hunt_install_timeout_idle idle=%d", idle ? 1 : 0);
					return tool_result_t::error(idle ? "integrity hunter page guard install timed out" : "integrity hunter worker did not stop after install timeout");
				}
				Sleep(25);
			}

			if (!integrity_hunter::g_state.install_success.load()) {
				diag::log_tagged_fmt("integrity_hunter",
					"mcp_hunt_install_failed addr=0x%llX size=%llu install_complete=%d",
					static_cast<unsigned long long>(addr),
					static_cast<unsigned long long>(size),
					integrity_hunter::g_state.install_complete.load() ? 1 : 0);
				integrity_hunter::stop_hunt();
				const bool idle = integrity_hunter::wait_until_idle(12000);
				diag::log_tagged_fmt("integrity_hunter", "mcp_hunt_install_failed_idle idle=%d", idle ? 1 : 0);
				return tool_result_t::error(idle ? "integrity hunter page guard install failed" : "integrity hunter worker did not stop after install failure");
			}

			const auto monitor_start = std::chrono::steady_clock::now();
			while (integrity_hunter::g_state.hunting.load()) {
				const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - monitor_start).count();
				if (elapsed >= duration)
					break;
				Sleep(50);
			}

			integrity_hunter::stop_hunt();
			const bool idle = integrity_hunter::wait_until_idle(12000);
			if (!idle) {
				diag::log_tagged_fmt("integrity_hunter",
					"mcp_hunt_stop_timeout addr=0x%llX size=%llu hunting=%d worker=%d session=%u",
					static_cast<unsigned long long>(addr),
					static_cast<unsigned long long>(size),
					integrity_hunter::g_state.hunting.load() ? 1 : 0,
					integrity_hunter::g_state.worker_active.load() ? 1 : 0,
					integrity_hunter::g_state.pg_session_id.load());
				return tool_result_t::error("integrity hunter worker did not stop cleanly");
			}

			std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
			auto& nodes = integrity_hunter::g_state.nodes;

			json arr = json::array();
			for (size_t i = 0; i < nodes.size(); ++i) {
				auto& n = nodes[i];
				json obj;
				obj["index"] = static_cast<int>(i);
				char rbuf[32];
				std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(n.reader_rip));
				obj["reader_rip"] = rbuf;
				obj["module"] = n.module_name;
				obj["read_count"] = n.read_count;
				obj["reads_per_second"] = n.reads_per_second;
				if (n.hash_compare_addr != 0) {
					char cbuf[32];
					std::snprintf(cbuf, sizeof(cbuf), "0x%llX", static_cast<unsigned long long>(n.hash_compare_addr));
					obj["hash_compare_addr"] = cbuf;
				}
				obj["disasm"] = n.disasm_text;
				obj["neutralized"] = n.neutralized;
				arr.push_back(obj);
			}

			json result;
			result["count"] = nodes.size();
			result["total_reads"] = integrity_hunter::g_state.total_reads.load();
			result["install_complete"] = integrity_hunter::g_state.install_complete.load();
			result["install_success"] = integrity_hunter::g_state.install_success.load();
			result["worker_idle"] = idle;
			result["target_address"] = addr_str;
			result["target_size"] = size;
			result["duration_ms"] = duration;
			result["nodes"] = arr;
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"neutralize_integrity_node",
		"Neutralize a discovered integrity checker by patching its conditional branch to always pass. Use hunt_integrity_checkers first to discover nodes.",
		{
			{"node_index", "integer", "Index of the integrity node to neutralize (from hunt_integrity_checkers results)", true}
		},
		false,
		[](const json& params) -> tool_result_t {
			int index = params.value("node_index", -1);
			diag::log_tagged_fmt("analysis", "neutralize_integrity_node entry index=%d", index);
			if (index < 0) {
				diag::log_tagged("analysis", "neutralize_integrity_node refused invalid_index");
				return tool_result_t::error("node_index parameter is required");
			}

			bool ok = integrity_hunter::neutralize(index);
			diag::log_tagged_fmt("analysis", "neutralize_integrity_node result=%s index=%d",
				ok ? "ok" : "failed", index);

			json result;
			result["neutralized"] = ok;
			result["node_index"] = index;
			if (ok) {
				std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
				if (index < static_cast<int>(integrity_hunter::g_state.nodes.size())) {
					auto& n = integrity_hunter::g_state.nodes[static_cast<size_t>(index)];
					char rbuf[32];
					std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(n.reader_rip));
					result["reader_rip"] = rbuf;
					result["status"] = "neutralized";
				}
			} else {
				return tool_result_t::error("No conditional branch was found near the node RIP.");
			}
			return tool_result_t::ok(result);
		}
	});






	srv.register_tool({
		"taint_trace_register",
		"Perform taint analysis starting from specified registers or memory addresses. Traces taint propagation through all instructions to identify every instruction that touches the tainted data.",
		{{"start_address", "string", "Start address for taint tracing (hex)", true},
		 {"end_address", "string", "End address for taint tracing (hex)", true},
		 {"taint_registers", "string", "Comma-separated register names to taint initially (e.g. rdi,rsi)", false},
		 {"taint_memory", "string", "Comma-separated memory addresses to taint initially (hex)", false},
		 {"max_instructions", "number", "Maximum instructions to process (default 5000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			std::string start_str = params.value("start_address", "");
			std::string end_str = params.value("end_address", "");
			diag::log_tagged_fmt("analysis", "taint_trace_register entry start=%s end=%s",
				start_str.c_str(), end_str.c_str());
			if (start_str.empty() || end_str.empty()) {
				diag::log_tagged("analysis", "taint_trace_register refused missing_params");
				return tool_result_t::error("start_address and end_address are required");
			}

			uint64_t start = std::strtoull(start_str.c_str(), nullptr, 16);
			uint64_t end = std::strtoull(end_str.c_str(), nullptr, 16);
			uint32_t max_insns = static_cast<uint32_t>(params.value("max_instructions", 5000));

			std::vector<std::string> taint_regs;
			{
				std::string regs_str = params.value("taint_registers", "");
				std::istringstream iss(regs_str);
				std::string tok;
				while (std::getline(iss, tok, ',')) {
					while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
					while (!tok.empty() && tok.back() == ' ') tok.pop_back();
					if (!tok.empty())
						taint_regs.push_back(tok);
				}
			}

			std::vector<std::pair<uint64_t, uint32_t>> taint_mem;
			{
				std::string mem_str = params.value("taint_memory", "");
				std::istringstream iss(mem_str);
				std::string tok;
				while (std::getline(iss, tok, ',')) {
					while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
					while (!tok.empty() && tok.back() == ' ') tok.pop_back();
					if (!tok.empty())
						taint_mem.push_back({std::strtoull(tok.c_str(), nullptr, 16), 1});
				}
			}

			diag::log_tagged_fmt("analysis", "taint_trace_register running start=0x%llX end=0x%llX taint_regs=%zu taint_mem=%zu max_insns=%u",
				static_cast<unsigned long long>(start), static_cast<unsigned long long>(end),
				taint_regs.size(), taint_mem.size(), max_insns);
			auto result = symbolic_engine::taint_trace(start, end, max_insns, taint_regs, taint_mem);
			diag::log_tagged_fmt("analysis", "taint_trace_register complete total=%u tainted=%u",
				result.total_processed, result.tainted_count);

			json out;
			out["total_instructions"] = result.total_processed;
			out["tainted_instructions"] = result.tainted_count;

			json insns = json::array();
			for (auto& ti : result.tainted_instructions) {
				json obj;
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ti.address));
				obj["address"] = abuf;
				obj["disasm"] = ti.disasm;

				json src = json::array();
				for (auto& r : ti.read_regs) src.push_back(r);
				obj["source_regs"] = src;

				json dst = json::array();
				for (auto& r : ti.written_regs) dst.push_back(r);
				obj["dest_regs"] = dst;

				insns.push_back(obj);
			}
			out["instructions"] = insns;

			json tainted_regs_out = json::array();
			for (auto& r : result.tainted_registers)
				tainted_regs_out.push_back(r);
			out["final_tainted_registers"] = tainted_regs_out;

			json tainted_mem_out = json::array();
			for (auto addr : result.tainted_memory_addresses) {
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(addr));
				tainted_mem_out.push_back(abuf);
			}
			out["final_tainted_memory"] = tainted_mem_out;

			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"fuzzer_manage",
		"Manage snapshot-based function fuzzing. Actions: start, stop, results.",
		{{"action", "string", "start|stop|results", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"target_address", "string", "Hex address of the function to fuzz", false},
		 {"end_address", "string", "Hex address where execution should stop", false},
		 {"input_address", "string", "Hex address of the input buffer in target memory", false},
		 {"input_size", "integer", "Size of input buffer in bytes", false},
		 {"max_iterations", "integer", "Maximum fuzzing iterations", false}},
		false,
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "start") return fuzzer_manage_start(p);
			if (action == "stop") return fuzzer_manage_stop(p);
			if (action == "results") return fuzzer_manage_results(p);
			return compat_unknown_action("fuzzer_manage", action);
		}
	});

	srv.register_tool({
		"live_monitor_manage",
		"Manage live struct monitoring. Actions: start, stop, status.",
		{{"action", "string", "start|stop|status", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"address", "string", "Base address of the struct in hex", false},
		 {"size", "integer", "Size of the struct in bytes", false},
		 {"name", "string", "Name for the struct", false},
		 {"backend", "string", "Backend preference: auto, page_guard, polling, hardware_breakpoint", false},
		 {"timeout_ms", "integer", "Maximum backend startup wait in milliseconds", false},
		 {"require_captures", "boolean", "Return an error if no accesses were captured", false}},
		false,
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "start") return live_monitor_manage_start(p);
			if (action == "stop") return live_monitor_manage_stop(p);
			if (action == "status") return live_monitor_snapshot(false);
			return compat_unknown_action("live_monitor_manage", action);
		}
	});

	srv.register_tool({
		"symbolic_execution",
		"Run symbolic analysis actions. Actions: deobfuscate, slice_function, solve_path.",
		{{"action", "string", "deobfuscate|slice_function|solve_path", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"entry_address", "string", "Entry address for deobfuscation", false},
		 {"start_address", "string", "Start address for slicing or path solving", false},
		 {"end_address", "string", "End address for slicing", false},
		 {"target_address", "string", "Target address for path solving", false},
		 {"target_register", "string", "Target register for slicing", false},
		 {"symbolic_registers", "string", "Comma-separated symbolic registers", false},
		 {"max_instructions", "number", "Maximum instructions to process", false}},
		true,
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "deobfuscate") return symbolic_manage_deobfuscate(p);
			if (action == "slice_function") return symbolic_manage_slice(p);
			if (action == "solve_path") return symbolic_manage_solve_path(p);
			return compat_unknown_action("symbolic_execution", action);
		}
	});

	srv.register_tool({
		"analysis_query",
		"Query binary analysis metadata. Actions: imports, exports, types, type_definition, pdb_symbols, binary_map_overview, xref_db_stats.",
		{{"action", "string", "imports|exports|types|type_definition|pdb_symbols|binary_map_overview|xref_db_stats", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"module_name", "string", "Optional loaded module name or path suffix", false},
		 {"name", "string", "Type name for type_definition", false},
		 {"module", "string", "Optional module filter", false},
		 {"filter", "string", "Optional substring filter", false},
		 {"limit", "number", "Maximum rows to return", false},
		 {"max_entries", "integer", "Maximum import/export rows to return", false},
		 {"timeout_ms", "integer", "Maximum parse time before returning partial results", false},
		 {"functions_only", "boolean", "Return only function PDB symbols", false},
		 {"max_functions", "number", "Maximum binary-map functions", false},
		 {"max_globals", "number", "Maximum binary-map globals", false},
		 {"include_imports", "boolean", "Include imports in binary-map overview", false},
		 {"include_exports", "boolean", "Include exports in binary-map overview", false},
		 {"include_xrefs", "boolean", "Include xref summaries in binary-map overview", false}},
		true,
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "imports") return analysis_query_imports(p);
			if (action == "exports") return analysis_query_exports(p);
			if (action == "types") return analysis_query_types(p);
			if (action == "type_definition") return analysis_query_type_definition(p);
			if (action == "pdb_symbols") return analysis_query_pdb_symbols(p);
			if (action == "binary_map_overview") return analysis_query_binary_map_overview(p);
			if (action == "xref_db_stats") return analysis_query_xref_db_stats(p);
			return compat_unknown_action("analysis_query", action);
		}
	});
}

}
