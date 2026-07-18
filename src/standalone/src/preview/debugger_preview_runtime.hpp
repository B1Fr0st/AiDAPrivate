#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "shell_preview_platform.hpp"
#include "../core/disasm/zydis_disasm.hpp"
#include "ui_task_executor.hpp"
#include "../core/debugger/debugger_engine.hpp"
#include "../core/editor/expression_eval.hpp"
#include "../core/runtime/standalone_driver.hpp"
#include "../core/analysis/stealth_engine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

inline constexpr std::uint32_t PAGE_NOACCESS = 0x01;
inline constexpr std::uint32_t PAGE_READONLY = 0x02;
inline constexpr std::uint32_t PAGE_READWRITE = 0x04;
inline constexpr std::uint32_t PAGE_WRITECOPY = 0x08;
inline constexpr std::uint32_t PAGE_EXECUTE = 0x10;
inline constexpr std::uint32_t PAGE_EXECUTE_READ = 0x20;
inline constexpr std::uint32_t PAGE_EXECUTE_READWRITE = 0x40;
inline constexpr std::uint32_t PAGE_EXECUTE_WRITECOPY = 0x80;
inline constexpr std::uint32_t MEM_COMMIT = 0x1000;
inline constexpr std::uint32_t MEM_RESERVE = 0x2000;
inline constexpr std::uint32_t MEM_FREE = 0x10000;
inline constexpr std::uint32_t MEM_PRIVATE = 0x20000;
inline constexpr std::uint32_t MEM_MAPPED = 0x40000;
inline constexpr std::uint32_t MEM_IMAGE = 0x1000000;
inline constexpr DWORD PROCESS_TERMINATE = 0x0001;
using HANDLE = void*;
using UINT = unsigned int;

inline HANDLE OpenProcess(DWORD, BOOL, DWORD pid) { return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(pid)); }
inline BOOL TerminateProcess(HANDLE process, UINT);
inline BOOL CloseHandle(HANDLE);

namespace aida::preview::debugger {

struct receipt_t {
	std::string action;
	std::string detail;
	std::uint64_t sequence = 0;
};

inline std::vector<receipt_t> receipts;
inline std::uint64_t next_sequence = 1;
inline bool fixture_initialized = false;

inline void record(std::string action, std::string detail = {}) {
	receipts.push_back({std::move(action), std::move(detail), next_sequence++});
	if (receipts.size() > 256)
		receipts.erase(receipts.begin(), receipts.begin() + 64);
}

inline std::vector<std::uint8_t> bytes_for(std::uint64_t address, std::size_t size) {
	static constexpr std::array<std::uint8_t, 48> code = {
		0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B,
		0xF9, 0x48, 0x8B, 0xDA, 0x48, 0x85, 0xD2, 0x74, 0x14, 0x48, 0x8B, 0x42,
		0x18, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x42, 0x01,
		0x00, 0x00, 0x84, 0xC0, 0x75, 0x05, 0xCC, 0x48, 0x83, 0xC4, 0x30, 0xC3
	};
	std::vector<std::uint8_t> out(size);
	for (std::size_t i = 0; i < size; ++i)
		out[i] = code[static_cast<std::size_t>((address + i) % code.size())];
	return out;
}

inline void initialize_fixture() {
	if (fixture_initialized)
		return;
	fixture_initialized = true;
	auto& state = debugger_engine::g_state;
	state.status.store(debugger_engine::dbg_status_t::paused, std::memory_order_release);
	state.target_pid = 6420;
	state.active_tid = 6872;
	state.registers = {
		0x0000000000000001, 0x000001F61A4D2000, 0x000001F61A4E90F0, 0x0000000000000040,
		0x00007FF7A4C1B6D0, 0x000001F61A4E9100, 0x0000007C52CFF5B0, 0x0000007C52CFF430,
		0x000001F61A4D0000, 0x0000000000000002, 0x00007FFDA19323C0, 0x0000000000000246,
		0x000001F61A4E9000, 0x0000000000000000, 0x00007FF7A4C90000, 0x00007FF7A4C1B420,
		0x00007FF7A4C16A32, 0x0000000000000246,
		0x33, 0x2B, 0x2B, 0x53, 0x2B, 0x2B,
		0, 0, 0, 0, 0, 0
	};
	state.cached_regs = state.registers;
	state.cached_disasm_base = 0x00007FF7A4C16A10;
	state.cached_disasm_bytes = bytes_for(state.cached_disasm_base, 512);
	state.cached_stack_addr = state.registers.rsp;
	state.cached_stack = bytes_for(state.cached_stack_addr, 512);
	state.cached_threads = {
		{6872, 6420, 10, 5, state.registers.rip},
		{7044, 6420, 8, 2, 0x00007FFDA19323C0},
		{7296, 6420, 8, 5, 0x00007FFDA18F1B20},
		{8132, 6420, 8, 2, 0x00007FFDA111C4E0}
	};
	state.breakpoints = {
		{0x00007FF7A4C16A32, debugger_engine::bp_type_t::software, debugger_engine::bp_state_t::enabled, -1, 1, "license_gate", "rax == 1", "authorization branch", 4, 0x75, false, false, true, "", 0, 0, false, true, "", "", "", 0, 0},
		{0x00007FF7A4C1B420, debugger_engine::bp_type_t::hardware_execute, debugger_engine::bp_state_t::enabled, 0, 1, "decrypt_stage", "", "", 1, 0, false, false, false, "", 0, 0, false, true, "", "", "", 0, 0},
		{0x00007FF7A4C208F0, debugger_engine::bp_type_t::hardware_write, debugger_engine::bp_state_t::disabled, 1, 8, "iat_write", "", "", 0, 0, false, false, false, "", 0, 0, false, true, "", "", "", 0, 0}
	};
	state.call_stack = {
		{0x00007FF7A4C16A32, 0x00007FF7A4C16B14, 0x00007FF7A4C00000, 0x001A0000, "sample.exe", "C:/Samples/sample.exe", "validate_license", 0x16A32, 0x00007FF7A4C169D0, 0x62, "pdb", "resolved"},
		{0x00007FF7A4C1B420, 0x00007FF7A4C1B5A8, 0x00007FF7A4C00000, 0x001A0000, "sample.exe", "C:/Samples/sample.exe", "dispatch_command", 0x1B420, 0x00007FF7A4C1B3A0, 0x80, "pdb", "resolved"},
		{0x00007FFDA17B257D, 0x00007FFDA193AF28, 0x00007FFDA1700000, 0x001F0000, "KERNEL32.DLL", "C:/Windows/System32/KERNEL32.DLL", "BaseThreadInitThunk", 0xB257D, 0x00007FFDA17B2560, 0x1D, "export", "resolved"}
	};
	state.memory_map = {
		{0x00007FF7A4C00000, 0x1000, PAGE_READONLY, MEM_COMMIT, MEM_IMAGE, "sample.exe", "PE headers"},
		{0x00007FF7A4C01000, 0x98000, PAGE_EXECUTE_READ, MEM_COMMIT, MEM_IMAGE, "sample.exe", ".text"},
		{0x00007FF7A4C99000, 0x24000, PAGE_READONLY, MEM_COMMIT, MEM_IMAGE, "sample.exe", ".rdata"},
		{0x00007FF7A4CBD000, 0xB000, PAGE_READWRITE, MEM_COMMIT, MEM_IMAGE, "sample.exe", ".data"},
		{0x000001F61A4D0000, 0x21000, PAGE_READWRITE, MEM_COMMIT, MEM_PRIVATE, "", "Process heap"},
		{0x0000007C52C00000, 0x100000, PAGE_READWRITE, MEM_COMMIT, MEM_PRIVATE, "", "Thread stack"}
	};
	state.watches = {
		{"rip", "00007FF7A4C16A32", "uint64_t", "", true, "rip", "", 0, 0, false, true},
		{"poi(rsp)", "00007FF7A4C16B14", "pointer", "", true, "poi(rsp)", "", 0, 0, false, true},
		{"[rbx+18]", "000001F61A4E90F0", "pointer", "", true, "[rbx+18]", "", 0, 0, false, true},
		{"module_base+0x208F0", "00007FF7A4C208F0", "address", "", true, "module_base+0x208F0", "", 0, 0, false, true}
	};
	for (int i = 0; i < 18; ++i) {
		debugger_engine::trace_record_t row;
		row.index = i + 1;
		row.address = 0x00007FF7A4C16A10 + static_cast<std::uint64_t>(i * 4);
		row.regs = state.registers;
		row.regs.rip = row.address;
		row.disasm_text = i % 4 == 0 ? "mov rax, qword ptr [rbx+18h]" : i % 4 == 1 ? "test rax, rax" : i % 4 == 2 ? "je sample.7FF7A4C16A58" : "call sample.decrypt_stage";
		state.trace_log.push_back(std::move(row));
	}
	state.strings = {
		{0x00007FF7A4C9A310, "Debugger detected", "sample.exe", 0x9A310, false},
		{0x00007FF7A4C9A350, "VirtualProtect", "sample.exe", 0x9A350, false},
		{0x00007FF7A4C9A388, "license/heartbeat", "sample.exe", 0x9A388, false},
		{0x00007FF7A4C9A3D0, "AES-256-GCM", "sample.exe", 0x9A3D0, false}
	};
	state.bookmarks = {0x00007FF7A4C16A32, 0x00007FF7A4C1B420, 0x00007FF7A4C208F0};
	state.labels[0x00007FF7A4C16A32] = {"license_gate", 0x00007FF7A4C16A32};
	state.labels[0x00007FF7A4C1B420] = {"decrypt_stage", 0x00007FF7A4C1B420};
	state.handles = {
		{0x78, 7, "Process", "sample-child.exe", 0x001FFFFF},
		{0xB4, 8, "Thread", "TID 7044", 0x001FFFFF},
		{0x124, 28, "File", "C:/Samples/payload.bin", 0x0012019F},
		{0x19C, 37, "Mutant", "AIDA_SAMPLE_MUTEX", 0x001F0001}
	};
	record("fixture_loaded", "Debugger 14-tab state");
}

inline void record_save_dialog(const char* title) {
	record("save_dialog", title ? title : "Save");
}

[[maybe_unused]] inline const bool save_dialog_observer_registered = [] {
	aida::preview::platform::save_dialog_observer = &record_save_dialog;
	return true;
}();

}

namespace run_target {
inline capability_probe_t probe_capabilities() {
	capability_probe_t value;
	value.has_jobobject = true;
	value.has_appcontainer = true;
	value.has_firewall_inet = true;
	value.has_windows_sandbox = true;
	value.has_restricted_token = true;
	value.has_mitigation_policy = true;
	value.has_kernel_sandbox_guard = true;
	value.windows_build = 26100;
	return value;
}
inline bool cleanup(launch_result_t& result) { result.process_handle = 0; result.thread_handle = 0; result.job_handle = 0; aida::preview::debugger::record("sandbox_cleanup", std::to_string(result.pid)); return true; }
}

inline BOOL TerminateProcess(HANDLE process, UINT) { aida::preview::debugger::record("terminate_process", std::to_string(reinterpret_cast<std::uintptr_t>(process))); return TRUE; }
inline BOOL CloseHandle(HANDLE) { return TRUE; }

namespace driver_bridge {
inline bool is_loaded() { return true; }
inline bool using_kernel_driver() { return true; }
inline bool dynamic_ioctls_ready() { return true; }
inline bool kernel_session_available(std::string* reason) { if (reason) *reason = "Preview fixture"; return true; }
inline std::uint32_t attached_pid() { return 6420; }
inline std::string status() { return "Attached · kernel session ready"; }
inline std::string last_error() { return {}; }
inline void detach() { aida::preview::debugger::record("detach", "PID 6420"); }
inline std::vector<module_info_t> enumerate_modules() {
	return {
		{0x00007FF7A4C00000, 0x001A0000, "sample.exe", "C:/Samples/sample.exe"},
		{0x00007FFDA1700000, 0x001F0000, "KERNEL32.DLL", "C:/Windows/System32/KERNEL32.DLL"},
		{0x00007FFDA1900000, 0x00216000, "ntdll.dll", "C:/Windows/System32/ntdll.dll"},
		{0x00007FFDA1280000, 0x000C7000, "ADVAPI32.dll", "C:/Windows/System32/ADVAPI32.dll"}
	};
}
inline std::vector<thread_info_t> enumerate_threads() {
	return {{6872, 6420, 10, 5, 0x00007FF7A4C16A32}, {7044, 6420, 8, 2, 0x00007FFDA19323C0}, {7296, 6420, 8, 5, 0x00007FFDA18F1B20}};
}
inline bool read_memory(std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out) { out = aida::preview::debugger::bytes_for(address, size); return true; }
inline bool write_memory(std::uint64_t address, const std::vector<std::uint8_t>& data) { aida::preview::debugger::record("write_memory", std::to_string(address) + ":" + std::to_string(data.size())); return !data.empty(); }
inline bool protect_memory(std::uint64_t address, std::uint64_t size, std::uint32_t value, std::uint32_t* old) { if (old) *old = PAGE_EXECUTE_READ; aida::preview::debugger::record("protect_memory", std::to_string(address) + ":" + std::to_string(size) + ":" + std::to_string(value)); return true; }
inline bool suspend_thread(std::uint32_t tid, std::uint32_t* previous) { if (previous) *previous = 0; aida::preview::debugger::record("suspend_thread", std::to_string(tid)); return true; }
inline bool resume_thread(std::uint32_t tid, std::uint32_t* previous) { if (previous) *previous = 1; aida::preview::debugger::record("resume_thread", std::to_string(tid)); return true; }
inline bool terminate_thread(std::uint32_t tid, std::uint32_t) { aida::preview::debugger::record("terminate_thread", std::to_string(tid)); return true; }
inline bool close_process_handle(std::uint32_t, std::uint64_t handle) { aida::preview::debugger::record("close_handle", std::to_string(handle)); return true; }
inline bool get_thread_context(std::uint32_t, thread_context_t& context) { auto regs = debugger_engine::g_state.cached_regs; context.rip = regs.rip; context.rsp = regs.rsp; context.rax = regs.rax; context.rbx = regs.rbx; return true; }
inline bool query_thread_information(std::uint32_t, std::uint32_t, void* buffer, std::uint32_t size, std::uint32_t* returned) { if (buffer && size) std::memset(buffer, 0, size); if (returned) *returned = size; return true; }
}

namespace debugger_engine {
inline std::string& preview_last_error() { static std::string value; return value; }
inline void initialize() { aida::preview::debugger::initialize_fixture(); }
inline void shutdown() {}
inline const std::string& last_error() { return preview_last_error(); }
inline bool run_target() { aida::preview::debugger::initialize_fixture(); g_state.status.store(dbg_status_t::running); aida::preview::debugger::record("continue", "running"); return true; }
inline bool pause_target() { g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("pause", "paused"); return true; }
inline bool step_into() { g_state.cached_regs.rip += 3; g_state.registers = g_state.cached_regs; g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("step_into", std::to_string(g_state.cached_regs.rip)); return true; }
inline bool step_over() { g_state.cached_regs.rip += 5; g_state.registers = g_state.cached_regs; g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("step_over", std::to_string(g_state.cached_regs.rip)); return true; }
inline bool step_out() { g_state.cached_regs.rip = 0x00007FF7A4C1B5A8; g_state.registers = g_state.cached_regs; g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("step_out", std::to_string(g_state.cached_regs.rip)); return true; }
inline bool run_to_address(std::uint64_t address, bool, std::uint32_t) { if (address == 0) { preview_last_error() = "run_to_address: invalid address"; return false; } g_state.cached_regs.rip = address; g_state.registers = g_state.cached_regs; g_state.status.store(dbg_status_t::paused); preview_last_error().clear(); aida::preview::debugger::record("run_to_address", std::to_string(address)); return true; }
inline register_set_t get_registers() { aida::preview::debugger::initialize_fixture(); return g_state.registers; }
inline register_set_t cached_registers() { aida::preview::debugger::initialize_fixture(); return g_state.cached_regs; }
inline std::vector<cached_thread_t> cached_thread_list() { aida::preview::debugger::initialize_fixture(); return g_state.cached_threads; }
inline std::vector<std::uint8_t> cached_stack_bytes(std::uint64_t& address) { aida::preview::debugger::initialize_fixture(); address = g_state.cached_stack_addr; return g_state.cached_stack; }
inline std::vector<std::uint8_t> cached_disasm_window(std::uint64_t& base) { aida::preview::debugger::initialize_fixture(); base = g_state.cached_disasm_base; return g_state.cached_disasm_bytes; }
inline void request_refresh(std::uint32_t) { aida::preview::debugger::initialize_fixture(); }
inline void request_thread_refresh(std::uint32_t) { aida::preview::debugger::initialize_fixture(); }
inline void request_stack_refresh(std::uint64_t rsp, std::size_t size, std::uint32_t) { g_state.cached_stack_addr = rsp; g_state.cached_stack = aida::preview::debugger::bytes_for(rsp, size); }
inline void request_disasm_refresh(std::uint64_t rip, std::uint32_t) { g_state.cached_disasm_base = rip > 32 ? rip - 32 : rip; g_state.cached_disasm_bytes = aida::preview::debugger::bytes_for(g_state.cached_disasm_base, 512); }
inline void invalidate_cache() {}
inline bool set_register(const std::string& name, std::uint64_t value) {
	auto& r = g_state.cached_regs;
	if (name == "rip") r.rip = value; else if (name == "rsp") r.rsp = value; else if (name == "rax") r.rax = value; else if (name == "rbx") r.rbx = value; else if (name == "rcx") r.rcx = value; else if (name == "rdx") r.rdx = value; else if (name == "rflags") r.rflags = value; else return false;
	g_state.registers = r;
	aida::preview::debugger::record("set_register", name + "=" + std::to_string(value));
	return true;
}
inline int add_breakpoint(std::uint64_t address, bp_type_t type, const std::string& name, const std::string& condition, int size) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); g_state.breakpoints.push_back({address, type, bp_state_t::enabled, -1, size, name, condition, "", 0, 0, false, false, false, "", 0, 0, false, true, "", "", "", 0, 0}); aida::preview::debugger::record("add_breakpoint", std::to_string(address)); return static_cast<int>(g_state.breakpoints.size() - 1); }
inline bool remove_breakpoint(int index) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); if (index < 0 || index >= static_cast<int>(g_state.breakpoints.size())) return false; g_state.breakpoints.erase(g_state.breakpoints.begin() + index); aida::preview::debugger::record("remove_breakpoint", std::to_string(index)); return true; }
inline bool toggle_breakpoint(int index) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); if (index < 0 || index >= static_cast<int>(g_state.breakpoints.size())) return false; auto& state = g_state.breakpoints[static_cast<std::size_t>(index)].state; state = state == bp_state_t::disabled ? bp_state_t::enabled : bp_state_t::disabled; aida::preview::debugger::record("toggle_breakpoint", std::to_string(index)); return true; }
inline void clear_all_breakpoints() { std::lock_guard<std::mutex> lock(g_state.bp_mutex); g_state.breakpoints.clear(); aida::preview::debugger::record("clear_breakpoints"); }
inline bool set_breakpoint_condition(int index, const std::string& condition) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); if (index < 0 || index >= static_cast<int>(g_state.breakpoints.size())) return false; g_state.breakpoints[static_cast<std::size_t>(index)].condition = condition; return true; }
inline bool set_breakpoint_log(int index, const std::string& text, bool auto_continue) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); if (index < 0 || index >= static_cast<int>(g_state.breakpoints.size())) return false; auto& bp = g_state.breakpoints[static_cast<std::size_t>(index)]; bp.log_text = text; bp.auto_continue = auto_continue; return true; }
inline std::vector<breakpoint_t> snapshot_breakpoints() { std::lock_guard<std::mutex> lock(g_state.bp_mutex); return g_state.breakpoints; }
inline std::vector<stack_frame_t> get_call_stack() { aida::preview::debugger::initialize_fixture(); return g_state.call_stack; }
inline std::vector<memory_region_t> get_memory_map() { aida::preview::debugger::initialize_fixture(); return g_state.memory_map; }
inline int add_watch(const std::string& expression) { std::lock_guard<std::mutex> lock(g_state.watch_mutex); g_state.watches.push_back({expression, "00007FF7A4C16A32", "uint64_t", "", true, expression, "", 0, 0, false, true}); aida::preview::debugger::record("add_watch", expression); return static_cast<int>(g_state.watches.size() - 1); }
inline bool remove_watch(int index) { std::lock_guard<std::mutex> lock(g_state.watch_mutex); if (index < 0 || index >= static_cast<int>(g_state.watches.size())) return false; g_state.watches.erase(g_state.watches.begin() + index); return true; }
inline void refresh_watches() { aida::preview::debugger::record("refresh_watches"); }
inline expression_evaluation_t evaluate_expression(const std::string& expression) {
	aida::preview::debugger::initialize_fixture();
	expression_evaluation_t result;
	if (expression.empty() || expression.size() > 96) {
		result.error = expression.empty() ? "empty expression" : "expression exceeds the 96-byte debugger limit";
		return result;
	}
	const auto registers = g_state.cached_regs;
	expression_eval::context_t context;
	context.rax = registers.rax; context.rbx = registers.rbx; context.rcx = registers.rcx; context.rdx = registers.rdx;
	context.rsi = registers.rsi; context.rdi = registers.rdi; context.rbp = registers.rbp; context.rsp = registers.rsp;
	context.r8 = registers.r8; context.r9 = registers.r9; context.r10 = registers.r10; context.r11 = registers.r11;
	context.r12 = registers.r12; context.r13 = registers.r13; context.r14 = registers.r14; context.r15 = registers.r15;
	context.rip = registers.rip; context.rflags = registers.rflags;
	context.read_mem = [](std::uint64_t address, std::size_t size, void* output) {
		if (!output || size == 0) return false;
		const auto bytes = aida::preview::debugger::bytes_for(address, size);
		if (bytes.size() < size) return false;
		std::memcpy(output, bytes.data(), size);
		return true;
	};
	const auto evaluated = expression_eval::evaluate(expression, context);
	if (!evaluated.ok) {
		result.error = evaluated.error;
		return result;
	}
	char rendered[20]{};
	std::snprintf(rendered, sizeof(rendered), "0x%016llX",
		static_cast<unsigned long long>(evaluated.value));
	result.succeeded = true;
	result.value = evaluated.value;
	result.rendered_value = rendered;
	result.type = "uint64";
	return result;
}
inline bool publish_watch_evaluation(int index, const std::string& expected_expression,
		const expression_evaluation_t& evaluation) {
	std::lock_guard<std::mutex> lock(g_state.watch_mutex);
	if (index < 0 || index >= static_cast<int>(g_state.watches.size())) return false;
	auto& watch = g_state.watches[static_cast<std::size_t>(index)];
	const std::string& retained = watch.persistent_expression.empty() ? watch.expression : watch.persistent_expression;
	if (retained != expected_expression) return false;
	watch.value = evaluation.succeeded ? evaluation.rendered_value : std::string{};
	watch.type = evaluation.succeeded ? evaluation.type : std::string{};
	watch.error = evaluation.succeeded ? std::string{} : evaluation.error;
	watch.valid = evaluation.succeeded;
	g_state.watches_generation.fetch_add(1, std::memory_order_release);
	aida::preview::debugger::record("evaluate_watch", expected_expression);
	return true;
}
inline bool start_trace(int) { g_state.tracing.store(true); aida::preview::debugger::record("trace", "recording"); return true; }
inline bool stop_trace() { g_state.tracing.store(false); aida::preview::debugger::record("trace", "stopped"); return true; }
inline void toggle_bookmark(std::uint64_t address) { auto it = std::find(g_state.bookmarks.begin(), g_state.bookmarks.end(), address); if (it == g_state.bookmarks.end()) g_state.bookmarks.push_back(address); else g_state.bookmarks.erase(it); aida::preview::debugger::record("bookmark", std::to_string(address)); }
inline void set_label(std::uint64_t address, const std::string& text) { g_state.labels[address] = {text, address}; }
inline void enumerate_handles() { aida::preview::debugger::initialize_fixture(); aida::preview::debugger::record("refresh_handles"); }
inline void find_strings_async(std::size_t) { aida::preview::debugger::initialize_fixture(); g_state.strings_scanning.store(false); aida::preview::debugger::record("scan_strings", std::to_string(g_state.strings.size())); }
inline void request_strings_cancel() { g_state.strings_cancel.store(true); aida::preview::debugger::record("cancel_strings"); }
inline std::string format_protect(std::uint32_t value) { if (value & PAGE_EXECUTE_READWRITE) return "ERW"; if (value & PAGE_EXECUTE_READ) return "ER"; if (value & PAGE_READWRITE) return "RW"; if (value & PAGE_READONLY) return "R"; return "---"; }
inline std::string format_flags(std::uint64_t value) { return (value & 0x40) ? "ZF IF" : "IF"; }
inline bool spawn_and_attach_target(const run_target::launch_options_t&, std::uint32_t* pid, run_target::launch_result_t* result) { if (pid) *pid = 6420; if (result) { result->ok = true; result->pid = 6420; } g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("spawn_target", "sample.exe"); return true; }
}

#endif
