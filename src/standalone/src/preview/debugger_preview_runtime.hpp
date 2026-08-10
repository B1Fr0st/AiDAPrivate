#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "shell_preview_platform.hpp"
#include "preview_fixture_controls.hpp"
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
#include <mutex>
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

extern std::vector<receipt_t> receipts;
extern std::uint64_t next_sequence;
extern bool fixture_initialized;
extern fixture_state_t fixture_state;
extern bool driver_available;
extern std::uint64_t process_creation_time_100ns;

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

inline debugger_engine::breakpoint_t make_breakpoint(
		std::uint64_t address,
		debugger_engine::bp_type_t type,
		debugger_engine::bp_state_t state,
		int hw_slot,
		int size,
		std::string name,
		std::string condition,
		std::string log_text,
		int hit_count,
		std::uint8_t original_byte,
		bool byte_written,
		bool readback_verified,
		std::uint64_t mutation_identity) {
	debugger_engine::breakpoint_t breakpoint;
	breakpoint.address = address;
	breakpoint.type = type;
	breakpoint.state = state;
	breakpoint.hw_slot = hw_slot;
	breakpoint.size = size;
	breakpoint.name = std::move(name);
	breakpoint.condition = std::move(condition);
	breakpoint.log_text = std::move(log_text);
	breakpoint.hit_count = hit_count;
	breakpoint.original_byte = original_byte;
	breakpoint.byte_written = byte_written;
	breakpoint.install_state = debugger_engine::breakpoint_install_state_t::installed;
	breakpoint.readback_verified = readback_verified;
	breakpoint.definition_resolved = true;
	breakpoint.mutation_identity = mutation_identity;
	breakpoint.mutation_generation = 1;
	return breakpoint;
}

inline void initialize_fixture() {
	if (fixture_initialized)
		return;
	fixture_initialized = true;
	if (fixture_state == fixture_state_t::empty ||
		fixture_state == fixture_state_t::disconnected)
		return;
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
		make_breakpoint(0x00007FF7A4C16A32, debugger_engine::bp_type_t::software,
			debugger_engine::bp_state_t::enabled, -1, 1, "license_gate", "rax == 1",
			"authorization branch", 4, 0x75, true, true, 1),
		make_breakpoint(0x00007FF7A4C1B420, debugger_engine::bp_type_t::hardware_execute,
			debugger_engine::bp_state_t::enabled, 0, 1, "decrypt_stage", "", "", 1, 0,
			false, true, 2),
		make_breakpoint(0x00007FF7A4C208F0, debugger_engine::bp_type_t::hardware_write,
			debugger_engine::bp_state_t::disabled, 1, 8, "iat_write", "", "", 0, 0,
			false, true, 3)
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

inline void apply_fixture_state(fixture_state_t requested, std::size_t cardinality) {
	fixture_state = requested;
	fixture_initialized = false;
	auto& state = debugger_engine::g_state;
	state.status.store(debugger_engine::dbg_status_t::idle, std::memory_order_release);
	state.target_pid = 0;
	state.active_tid = 0;
	state.registers = {};
	state.cached_regs = {};
	state.cached_threads.clear();
	state.cached_stack.clear();
	state.cached_stack_addr = 0;
	state.cached_dump.clear();
	state.cached_dump_addr = 0;
	state.cached_dump_size = 0;
	state.cached_disasm_bytes.clear();
	state.cached_disasm_base = 0;
	state.breakpoints.clear();
	state.call_stack.clear();
	state.trace_log.clear();
	state.memory_map.clear();
	state.watches.clear();
	state.strings.clear();
	state.handles.clear();
	state.comments.clear();
	state.labels.clear();
	state.bookmarks.clear();
	state.tracing.store(false, std::memory_order_release);
	state.strings_scanning.store(false, std::memory_order_release);
	state.strings_cancel.store(false, std::memory_order_release);
	initialize_fixture();
	driver_available = requested != fixture_state_t::disconnected;
	if (requested == fixture_state_t::empty || requested == fixture_state_t::disconnected) {
		return;
	}
	state.target_pid = 6420;
	state.active_tid = 6872;
	state.status.store(requested == fixture_state_t::loading
		? debugger_engine::dbg_status_t::running
		: requested == fixture_state_t::error
			? debugger_engine::dbg_status_t::terminated
			: debugger_engine::dbg_status_t::paused,
		std::memory_order_release);
	if (cardinality > state.trace_log.size()) {
		const std::size_t bounded = (std::min<std::size_t>)(cardinality, 10000U);
		state.trace_log.reserve(bounded);
		for (std::size_t index = state.trace_log.size(); index < bounded; ++index) {
			debugger_engine::trace_record_t row;
			row.index = static_cast<int>(index + 1U);
			row.address = 0x00007FF7A4C16A10ULL + static_cast<std::uint64_t>(index * 4U);
			row.regs = state.registers;
			row.regs.rip = row.address;
			row.disasm_text = index % 3U == 0U ? "mov rax, qword ptr [rbx+18h]"
				: index % 3U == 1U ? "test rax, rax" : "jne sample.dispatch_command";
			state.trace_log.push_back(std::move(row));
		}
	}
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
inline bool is_loaded() { return aida::preview::debugger::driver_available; }
inline bool using_kernel_driver() { return aida::preview::debugger::driver_available; }
inline bool kernel_session_available(std::string* reason) { if (reason) *reason = aida::preview::debugger::driver_available ? "Preview fixture" : "Preview driver disconnected"; return aida::preview::debugger::driver_available; }
inline std::uint32_t attached_pid() { return aida::preview::debugger::driver_available ? debugger_engine::g_state.target_pid : 0; }
inline std::string status() { return aida::preview::debugger::driver_available
	? "Attached - kernel session ready" : "Disconnected"; }
inline std::string last_error() { return aida::preview::debugger::driver_available ? std::string{} : "Preview driver disconnected"; }
inline void detach() { aida::preview::debugger::record("detach", "PID 6420"); }
inline std::vector<module_info_t> enumerate_modules() {
	if (!aida::preview::debugger::driver_available) return {};
	return {
		{0x00007FF7A4C00000, 0x001A0000, "sample.exe", "C:/Samples/sample.exe"},
		{0x00007FFDA1700000, 0x001F0000, "KERNEL32.DLL", "C:/Windows/System32/KERNEL32.DLL"},
		{0x00007FFDA1900000, 0x00216000, "ntdll.dll", "C:/Windows/System32/ntdll.dll"},
		{0x00007FFDA1280000, 0x000C7000, "ADVAPI32.dll", "C:/Windows/System32/ADVAPI32.dll"}
	};
}
inline std::vector<thread_info_t> enumerate_threads() {
	if (!aida::preview::debugger::driver_available) return {};
	return {{6872, 6420, 10, 5, 0x00007FF7A4C16A32}, {7044, 6420, 8, 2, 0x00007FFDA19323C0}, {7296, 6420, 8, 5, 0x00007FFDA18F1B20}};
}
inline bool read_memory(std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out) { if (!aida::preview::debugger::driver_available) { out.clear(); return false; } out = aida::preview::debugger::bytes_for(address, size); return true; }
inline bool write_memory(std::uint64_t address, const std::vector<std::uint8_t>& data) { aida::preview::debugger::record("write_memory", std::to_string(address) + ":" + std::to_string(data.size())); return !data.empty(); }
inline bool protect_memory(std::uint64_t address, std::uint64_t size, std::uint32_t value, std::uint32_t* old) { if (old) *old = PAGE_EXECUTE_READ; aida::preview::debugger::record("protect_memory", std::to_string(address) + ":" + std::to_string(size) + ":" + std::to_string(value)); return true; }
inline bool suspend_thread(std::uint32_t tid, std::uint32_t* previous) { if (previous) *previous = 0; aida::preview::debugger::record("suspend_thread", std::to_string(tid)); return true; }
inline bool resume_thread(std::uint32_t tid, std::uint32_t* previous) { if (previous) *previous = 1; aida::preview::debugger::record("resume_thread", std::to_string(tid)); return true; }
inline bool terminate_thread(std::uint32_t tid, std::uint32_t) { aida::preview::debugger::record("terminate_thread", std::to_string(tid)); return true; }
inline bool close_process_handle(std::uint32_t, std::uint64_t handle) { aida::preview::debugger::record("close_handle", std::to_string(handle)); return true; }
inline bool get_thread_context(std::uint32_t, thread_context_t& context) { std::lock_guard<std::mutex> lock(debugger_engine::g_state.cache_mtx); const auto regs = debugger_engine::g_state.cached_regs; context.rip = regs.rip; context.rsp = regs.rsp; context.rax = regs.rax; context.rbx = regs.rbx; return true; }
inline bool query_thread_information(std::uint32_t, std::uint32_t, void* buffer, std::uint32_t size, std::uint32_t* returned) { if (buffer && size) std::memset(buffer, 0, size); if (returned) *returned = size; return true; }
}

namespace debugger_engine {
inline std::string& preview_last_error() { static std::string value; return value; }
inline void initialize() { aida::preview::debugger::initialize_fixture(); }
inline void shutdown() {}
inline const std::string& last_error() { return preview_last_error(); }
inline bool run_target() { aida::preview::debugger::initialize_fixture(); g_state.status.store(dbg_status_t::running); aida::preview::debugger::record("continue", "running"); return true; }
inline bool pause_target() { g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("pause", "paused"); return true; }
inline bool step_into() { std::uint64_t rip = 0; { std::scoped_lock lock(g_state.cache_mtx, g_state.reg_mutex); g_state.cached_regs.rip += 3; g_state.registers = g_state.cached_regs; rip = g_state.cached_regs.rip; } g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("step_into", std::to_string(rip)); return true; }
inline bool step_over() { std::uint64_t rip = 0; { std::scoped_lock lock(g_state.cache_mtx, g_state.reg_mutex); g_state.cached_regs.rip += 5; g_state.registers = g_state.cached_regs; rip = g_state.cached_regs.rip; } g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("step_over", std::to_string(rip)); return true; }
inline bool step_out() { constexpr std::uint64_t rip = 0x00007FF7A4C1B5A8; { std::scoped_lock lock(g_state.cache_mtx, g_state.reg_mutex); g_state.cached_regs.rip = rip; g_state.registers = g_state.cached_regs; } g_state.status.store(dbg_status_t::paused); aida::preview::debugger::record("step_out", std::to_string(rip)); return true; }
inline bool run_to_address(std::uint64_t address, bool, std::uint32_t) { if (address == 0) { preview_last_error() = "run_to_address: invalid address"; return false; } { std::scoped_lock lock(g_state.cache_mtx, g_state.reg_mutex); g_state.cached_regs.rip = address; g_state.registers = g_state.cached_regs; } g_state.status.store(dbg_status_t::paused); preview_last_error().clear(); aida::preview::debugger::record("run_to_address", std::to_string(address)); return true; }
inline register_set_t get_registers() { aida::preview::debugger::initialize_fixture(); std::lock_guard<std::mutex> lock(g_state.reg_mutex); return g_state.registers; }
inline register_set_t cached_registers() { aida::preview::debugger::initialize_fixture(); std::lock_guard<std::mutex> lock(g_state.cache_mtx); return g_state.cached_regs; }
inline std::vector<cached_thread_t> cached_thread_list() { aida::preview::debugger::initialize_fixture(); return g_state.cached_threads; }
inline std::vector<std::uint8_t> cached_stack_bytes(std::uint64_t& address) { aida::preview::debugger::initialize_fixture(); address = g_state.cached_stack_addr; return g_state.cached_stack; }
inline std::vector<std::uint8_t> cached_disasm_window(std::uint64_t& base) { aida::preview::debugger::initialize_fixture(); base = g_state.cached_disasm_base; return g_state.cached_disasm_bytes; }
inline void request_refresh(std::uint32_t) { aida::preview::debugger::initialize_fixture(); }
inline void request_thread_refresh(std::uint32_t) { aida::preview::debugger::initialize_fixture(); }
inline void request_stack_refresh(std::uint64_t rsp, std::size_t size, std::uint32_t) { g_state.cached_stack_addr = rsp; g_state.cached_stack = aida::preview::debugger::bytes_for(rsp, size); }
inline void request_disasm_refresh(std::uint64_t rip, std::uint32_t) { g_state.cached_disasm_base = rip > 32 ? rip - 32 : rip; g_state.cached_disasm_bytes = aida::preview::debugger::bytes_for(g_state.cached_disasm_base, 512); }
inline void invalidate_cache() {}
inline bool set_register(const std::string& name, std::uint64_t value) {
	std::scoped_lock lock(g_state.cache_mtx, g_state.reg_mutex);
	auto& r = g_state.cached_regs;
	if (name == "rip") r.rip = value; else if (name == "rsp") r.rsp = value; else if (name == "rax") r.rax = value; else if (name == "rbx") r.rbx = value; else if (name == "rcx") r.rcx = value; else if (name == "rdx") r.rdx = value; else if (name == "rflags") r.rflags = value; else return false;
	g_state.registers = r;
	aida::preview::debugger::record("set_register", name + "=" + std::to_string(value));
	return true;
}
inline int add_breakpoint(std::uint64_t address, bp_type_t type, const std::string& name, const std::string& condition, int size) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); const std::uint64_t identity = static_cast<std::uint64_t>(g_state.breakpoints.size()) + 1024; g_state.breakpoints.push_back(aida::preview::debugger::make_breakpoint(address, type, bp_state_t::enabled, -1, size, name, condition, "", 0, 0, false, true, identity)); aida::preview::debugger::record("add_breakpoint", std::to_string(address)); return static_cast<int>(g_state.breakpoints.size() - 1); }
inline bool remove_breakpoint(int index) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); if (index < 0 || index >= static_cast<int>(g_state.breakpoints.size())) return false; g_state.breakpoints.erase(g_state.breakpoints.begin() + index); aida::preview::debugger::record("remove_breakpoint", std::to_string(index)); return true; }
inline bool toggle_breakpoint(int index) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); if (index < 0 || index >= static_cast<int>(g_state.breakpoints.size())) return false; auto& state = g_state.breakpoints[static_cast<std::size_t>(index)].state; state = state == bp_state_t::disabled ? bp_state_t::enabled : bp_state_t::disabled; aida::preview::debugger::record("toggle_breakpoint", std::to_string(index)); return true; }
inline bool clear_all_breakpoints() { std::lock_guard<std::mutex> lock(g_state.bp_mutex); g_state.breakpoints.clear(); aida::preview::debugger::record("clear_breakpoints"); return true; }
inline bool set_breakpoint_condition(int index, const std::string& condition) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); if (index < 0 || index >= static_cast<int>(g_state.breakpoints.size())) return false; g_state.breakpoints[static_cast<std::size_t>(index)].condition = condition; return true; }
inline bool set_breakpoint_log(int index, const std::string& text, bool auto_continue) { std::lock_guard<std::mutex> lock(g_state.bp_mutex); if (index < 0 || index >= static_cast<int>(g_state.breakpoints.size())) return false; auto& bp = g_state.breakpoints[static_cast<std::size_t>(index)]; bp.log_text = text; bp.auto_continue = auto_continue; return true; }
inline std::vector<breakpoint_t> snapshot_breakpoints() { std::lock_guard<std::mutex> lock(g_state.bp_mutex); return g_state.breakpoints; }
inline std::vector<stack_frame_t> get_call_stack() { aida::preview::debugger::initialize_fixture(); return g_state.call_stack; }
inline std::vector<memory_region_t> get_memory_map() { aida::preview::debugger::initialize_fixture(); return g_state.memory_map; }
inline int add_watch(const std::string& expression) {
	if (expression.empty() || expression.size() > k_max_watch_expression_bytes ||
		expression.find('\n') != std::string::npos || expression.find('\r') != std::string::npos)
		return -1;
	std::lock_guard<std::mutex> lock(g_state.watch_mutex);
	if (g_state.watches.size() >= k_max_watch_count) return -1;
	g_state.watches.push_back({expression, "00007FF7A4C16A32", "uint64_t", "", true, expression, "", 0, 0, false, true});
	g_state.watches_generation.fetch_add(1, std::memory_order_release);
	aida::preview::debugger::record("add_watch", expression);
	return static_cast<int>(g_state.watches.size() - 1);
}
inline bool remove_watch(int index) { std::lock_guard<std::mutex> lock(g_state.watch_mutex); if (index < 0 || index >= static_cast<int>(g_state.watches.size())) return false; g_state.watches.erase(g_state.watches.begin() + index); g_state.watches_generation.fetch_add(1, std::memory_order_release); return true; }
inline expression_eval::context_t preview_watch_expression_context() {
	register_set_t registers;
	{
		std::lock_guard<std::mutex> lock(g_state.cache_mtx);
		registers = g_state.cached_regs;
	}
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
	return context;
}
inline expression_evaluation_t preview_evaluate_expression_with_context(
		const std::string& expression, const expression_eval::context_t& context) {
	expression_evaluation_t result;
	if (expression.empty() || expression.size() > k_max_watch_expression_bytes ||
		expression.find('\n') != std::string::npos || expression.find('\r') != std::string::npos) {
		if (expression.empty()) result.error = "empty expression";
		else if (expression.size() > k_max_watch_expression_bytes) result.error = "expression exceeds the 96-byte debugger limit";
		else result.error = "expression must be a single line";
		return result;
	}
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
inline expression_evaluation_t evaluate_expression(const std::string& expression) {
	aida::preview::debugger::initialize_fixture();
	const auto context = preview_watch_expression_context();
	return preview_evaluate_expression_with_context(expression, context);
}
inline watch_refresh_batch_ptr capture_watch_refresh_batch() {
	auto batch = std::make_shared<watch_refresh_batch_t>();
	std::lock_guard<std::mutex> lock(g_state.watch_mutex);
	batch->generation = g_state.watches_generation.load(std::memory_order_acquire);
	batch->cardinality = g_state.watches.size();
	if (batch->cardinality > k_max_watch_count) {
		batch->error = "watch collection exceeds the 4096-entry refresh limit";
		return batch;
	}
	batch->targets.reserve(batch->cardinality);
	for (const auto& watch : g_state.watches) {
		watch_refresh_target_t target;
		target.expression = watch.expression;
		target.persistent_expression = watch.persistent_expression;
		target.definition_module = watch.definition_module;
		target.definition_module_offset = watch.definition_module_offset;
		target.definition_module_size = watch.definition_module_size;
		target.persistent_definition = watch.persistent_definition;
		target.definition_resolved = watch.definition_resolved;
		if (watch.persistent_definition && !watch.definition_resolved)
			target.unresolved_error = watch.error.empty()
				? "Persisted watch binding is unresolved" : watch.error;
		batch->targets.push_back(std::move(target));
	}
	return batch;
}
inline watch_refresh_evaluation_batch_t evaluate_watch_refresh_batch(
		watch_refresh_batch_ptr batch,
		watch_refresh_cancel_fn_t cancel_requested) {
	watch_refresh_evaluation_batch_t evaluated;
	evaluated.source = std::move(batch);
	if (!evaluated.source) {
		evaluated.error = "watch refresh capture is unavailable";
		return evaluated;
	}
	if (!evaluated.source->valid()) {
		evaluated.error = evaluated.source->error.empty()
			? "watch refresh capture is invalid" : evaluated.source->error;
		return evaluated;
	}
	if (cancel_requested && cancel_requested()) {
		evaluated.cancelled = true;
		return evaluated;
	}
	evaluated.results.resize(evaluated.source->targets.size());
	bool requires_context = false;
	for (const auto& target : evaluated.source->targets) {
		if (!(target.persistent_definition && !target.definition_resolved) &&
			!target.expression.empty() &&
			target.expression.size() <= k_max_watch_expression_bytes &&
			target.expression.find('\n') == std::string::npos &&
			target.expression.find('\r') == std::string::npos) {
			requires_context = true;
			break;
		}
	}
	expression_eval::context_t context;
	if (requires_context) {
		if (cancel_requested && cancel_requested()) {
			evaluated.cancelled = true;
			return evaluated;
		}
		aida::preview::debugger::initialize_fixture();
		context = preview_watch_expression_context();
	}
	for (std::size_t index = 0; index < evaluated.source->targets.size(); ++index) {
		if (cancel_requested && cancel_requested()) {
			evaluated.cancelled = true;
			return evaluated;
		}
		const auto& target = evaluated.source->targets[index];
		auto& result = evaluated.results[index];
		if (target.persistent_definition && !target.definition_resolved) {
			result.error = target.unresolved_error.empty()
				? "Persisted watch binding is unresolved" : target.unresolved_error;
		} else {
			result = preview_evaluate_expression_with_context(target.expression, context);
		}
	}
	return evaluated;
}
inline watch_refresh_publish_result_t publish_watch_refresh_batch(
		const watch_refresh_evaluation_batch_t& batch) {
	if (!batch.source || !batch.source->valid())
		return watch_refresh_publish_result_t::invalid_batch;
	if (batch.cancelled || !batch.error.empty() ||
		batch.results.size() != batch.source->targets.size())
		return watch_refresh_publish_result_t::result_mismatch;
	std::vector<watch_entry_t> updated;
	updated.reserve(batch.source->targets.size());
	for (std::size_t index = 0; index < batch.source->targets.size(); ++index) {
		const auto& target = batch.source->targets[index];
		const auto& result = batch.results[index];
		watch_entry_t watch;
		watch.expression = target.expression;
		watch.value = result.succeeded ? result.rendered_value : std::string{};
		watch.type = result.succeeded ? result.type : std::string{};
		watch.error = result.succeeded ? std::string{} : result.error;
		watch.valid = result.succeeded;
		watch.persistent_expression = target.persistent_expression;
		watch.definition_module = target.definition_module;
		watch.definition_module_offset = target.definition_module_offset;
		watch.definition_module_size = target.definition_module_size;
		watch.persistent_definition = target.persistent_definition;
		watch.definition_resolved = target.definition_resolved;
		updated.push_back(std::move(watch));
	}
	std::lock_guard<std::mutex> lock(g_state.watch_mutex);
	if (g_state.watches_generation.load(std::memory_order_acquire) != batch.source->generation)
		return watch_refresh_publish_result_t::stale_generation;
	if (g_state.watches.size() != batch.source->cardinality ||
		g_state.watches.size() != batch.source->targets.size())
		return watch_refresh_publish_result_t::cardinality_mismatch;
	for (std::size_t index = 0; index < g_state.watches.size(); ++index) {
		const auto& watch = g_state.watches[index];
		const auto& target = batch.source->targets[index];
		if (watch.expression != target.expression ||
			watch.persistent_expression != target.persistent_expression ||
			watch.definition_module != target.definition_module ||
			watch.definition_module_offset != target.definition_module_offset ||
			watch.definition_module_size != target.definition_module_size ||
			watch.persistent_definition != target.persistent_definition ||
			watch.definition_resolved != target.definition_resolved)
			return watch_refresh_publish_result_t::identity_mismatch;
	}
	g_state.watches.swap(updated);
	if (!g_state.watches.empty())
		g_state.watches_generation.fetch_add(1, std::memory_order_release);
	aida::preview::debugger::record("refresh_watches_batch",
		std::to_string(batch.results.size()));
	return watch_refresh_publish_result_t::published;
}
inline void refresh_watches() {
	const auto captured = capture_watch_refresh_batch();
	auto evaluated = evaluate_watch_refresh_batch(captured);
	static_cast<void>(publish_watch_refresh_batch(evaluated));
}
inline bool publish_watch_evaluation(int index, const std::string& expected_expression,
		std::uint64_t expected_watches_generation,
		const expression_evaluation_t& evaluation) {
	std::lock_guard<std::mutex> lock(g_state.watch_mutex);
	if (g_state.watches_generation.load(std::memory_order_acquire) != expected_watches_generation) return false;
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
