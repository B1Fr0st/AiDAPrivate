#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include "debugger_engine.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace {

struct handle_closer_t {
	void operator()(HANDLE h) const {
		if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
	}
};
using unique_handle_t = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_closer_t>;

inline unique_handle_t wrap_handle(HANDLE h) {
	return unique_handle_t((h && h != INVALID_HANDLE_VALUE) ? h : nullptr);
}

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


void initialize() {
	auto& st = g_state;
	st.status.store(dbg_status_t::idle);
}

void shutdown() {
	auto& st = g_state;
	st.tracing.store(false);
	st.worker_active.store(false);
	if (st.worker_thread.joinable()) st.worker_thread.join();
}


int add_breakpoint(uint64_t address, bp_type_t type, const std::string& name,
				   const std::string& condition) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.bp_mutex);


	for (auto& bp : st.breakpoints) {
		if (bp.address == address && bp.type == type)
			return -1;
	}

	breakpoint_t bp;
	bp.address = address;
	bp.type = type;
	bp.state = bp_state_t::enabled;
	bp.name = name;
	bp.condition = condition;


	if (type == bp_type_t::software) {
		std::vector<uint8_t> buf;
		if (driver_bridge::read_memory(address, 1, buf) && !buf.empty()) {
			bp.original_byte = buf[0];
		}
	}


	if (type == bp_type_t::hardware_execute || type == bp_type_t::hardware_write ||
		type == bp_type_t::hardware_read) {
		int slot = -1;
		bool used[4] = {};
		for (auto& existing : st.breakpoints) {
			if (existing.hw_slot >= 0 && existing.hw_slot < 4)
				used[existing.hw_slot] = true;
		}
		for (int i = 0; i < 4; ++i) {
			if (!used[i]) { slot = i; break; }
		}
		if (slot == -1) return -1;
		bp.hw_slot = slot;
	}

	st.breakpoints.push_back(std::move(bp));
	return static_cast<int>(st.breakpoints.size()) - 1;
}

bool remove_breakpoint(int index) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size()))
		return false;
	st.breakpoints.erase(st.breakpoints.begin() + index);
	return true;
}

bool toggle_breakpoint(int index) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size()))
		return false;
	auto& bp = st.breakpoints[static_cast<size_t>(index)];
	bp.state = (bp.state == bp_state_t::enabled) ? bp_state_t::disabled : bp_state_t::enabled;
	return true;
}

void clear_all_breakpoints() {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	st.breakpoints.clear();
}


bool run_target() {
	auto& st = g_state;
	if (st.target_pid == 0) return false;
	st.status.store(dbg_status_t::running);
	return true;
}

bool pause_target() {
	auto& st = g_state;
	if (st.target_pid == 0) return false;
	st.status.store(dbg_status_t::paused);
	return true;
}

bool step_into() {
	auto& st = g_state;
	if (st.target_pid == 0) return false;
	st.status.store(dbg_status_t::stepping);


	auto regs = get_registers();
	if (regs.rip == 0) return false;


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

	st.status.store(dbg_status_t::paused);
	return true;
}

bool step_over() {
	auto& st = g_state;
	if (st.target_pid == 0) return false;

	auto regs = get_registers();
	if (regs.rip == 0) return false;

	std::vector<uint8_t> code;
	if (driver_bridge::read_memory(regs.rip, 16, code) && !code.empty()) {
		auto ins = zydis_decode_one(code.data(), static_cast<int>(code.size()), regs.rip);
		if (ins.is_call)
			return run_to_address(regs.rip + static_cast<uint64_t>(ins.len));
	}

	return step_into();
}

bool step_out() {
	auto& st = g_state;
	if (st.target_pid == 0) return false;


	auto regs = get_registers();
	if (regs.rsp == 0) return false;

	std::vector<uint8_t> ret_buf;
	if (driver_bridge::read_memory(regs.rsp, 8, ret_buf) && ret_buf.size() >= 8) {
		uint64_t ret_addr;
		std::memcpy(&ret_addr, ret_buf.data(), 8);
		return run_to_address(ret_addr);
	}
	return false;
}

bool run_to_address(uint64_t address) {
	auto& st = g_state;
	if (st.target_pid == 0) return false;


	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		breakpoint_t bp;
		bp.address = address;
		bp.type = bp_type_t::software;
		bp.state = bp_state_t::one_shot;
		bp.is_internal = true;
		st.breakpoints.push_back(std::move(bp));
	}

	st.status.store(dbg_status_t::running);
	return true;
}


register_set_t get_registers() {
	auto& st = g_state;
	if (st.target_pid == 0 || st.active_tid == 0) return {};


	auto thread = wrap_handle(OpenThread(
		THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
		FALSE, st.active_tid));
	if (!thread) {
		std::lock_guard<std::mutex> lk(st.reg_mutex);
		return st.registers;
	}

	SuspendThread(thread.get());
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(thread.get(), &ctx)) {
		std::lock_guard<std::mutex> lk(st.reg_mutex);
		st.registers.rax = ctx.Rax; st.registers.rbx = ctx.Rbx;
		st.registers.rcx = ctx.Rcx; st.registers.rdx = ctx.Rdx;
		st.registers.rsi = ctx.Rsi; st.registers.rdi = ctx.Rdi;
		st.registers.rbp = ctx.Rbp; st.registers.rsp = ctx.Rsp;
		st.registers.r8  = ctx.R8;  st.registers.r9  = ctx.R9;
		st.registers.r10 = ctx.R10; st.registers.r11 = ctx.R11;
		st.registers.r12 = ctx.R12; st.registers.r13 = ctx.R13;
		st.registers.r14 = ctx.R14; st.registers.r15 = ctx.R15;
		st.registers.rip = ctx.Rip; st.registers.rflags = ctx.EFlags;
		st.registers.cs = ctx.SegCs; st.registers.ds = ctx.SegDs;
		st.registers.es = ctx.SegEs; st.registers.fs = ctx.SegFs;
		st.registers.gs = ctx.SegGs; st.registers.ss = ctx.SegSs;
		st.registers.dr0 = ctx.Dr0; st.registers.dr1 = ctx.Dr1;
		st.registers.dr2 = ctx.Dr2; st.registers.dr3 = ctx.Dr3;
		st.registers.dr6 = ctx.Dr6; st.registers.dr7 = ctx.Dr7;
	}
	ResumeThread(thread.get());

	std::lock_guard<std::mutex> lk(st.reg_mutex);
	return st.registers;
}

bool set_register(const std::string& name, uint64_t value) {
	auto& st = g_state;
	if (st.target_pid == 0 || st.active_tid == 0) return false;

	auto thread = wrap_handle(OpenThread(
		THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
		FALSE, st.active_tid));
	if (!thread) return false;

	SuspendThread(thread.get());
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(thread.get(), &ctx)) {
		ResumeThread(thread.get());
		return false;
	}

	auto lower = name;
	for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

	if      (lower == "rax") ctx.Rax = value;
	else if (lower == "rbx") ctx.Rbx = value;
	else if (lower == "rcx") ctx.Rcx = value;
	else if (lower == "rdx") ctx.Rdx = value;
	else if (lower == "rsi") ctx.Rsi = value;
	else if (lower == "rdi") ctx.Rdi = value;
	else if (lower == "rbp") ctx.Rbp = value;
	else if (lower == "rsp") ctx.Rsp = value;
	else if (lower == "r8")  ctx.R8  = value;
	else if (lower == "r9")  ctx.R9  = value;
	else if (lower == "r10") ctx.R10 = value;
	else if (lower == "r11") ctx.R11 = value;
	else if (lower == "r12") ctx.R12 = value;
	else if (lower == "r13") ctx.R13 = value;
	else if (lower == "r14") ctx.R14 = value;
	else if (lower == "r15") ctx.R15 = value;
	else if (lower == "rip") ctx.Rip = value;
	else if (lower == "rflags" || lower == "eflags") ctx.EFlags = static_cast<DWORD>(value);
	else {
		ResumeThread(thread.get());
		return false;
	}

	bool ok = SetThreadContext(thread.get(), &ctx) != FALSE;
	ResumeThread(thread.get());

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
	std::vector<stack_frame_t> frames;

	auto regs = get_registers();
	if (regs.rip == 0 || regs.rsp == 0) return frames;

	auto modules = driver_bridge::enumerate_modules();

	auto resolve = [&](uint64_t addr) -> stack_frame_t {
		stack_frame_t f;
		f.address = addr;
		for (const auto& m : modules) {
			if (addr >= m.base && addr < m.base + m.size) {
				f.module_name = m.name;
				f.module_offset = addr - m.base;
				break;
			}
		}
		return f;
	};


	auto first = resolve(regs.rip);
	frames.push_back(std::move(first));


	uint64_t sp = regs.rsp;
	for (int i = 0; i < 64; ++i) {
		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory(sp, 8, buf) || buf.size() < 8) break;

		uint64_t ret;
		std::memcpy(&ret, buf.data(), 8);


		bool valid = false;
		for (const auto& m : modules) {
			if (ret >= m.base && ret < m.base + m.size) {
				valid = true;
				break;
			}
		}

		if (valid && ret > 0x10000) {
			auto frame = resolve(ret);
			frame.return_addr = ret;
			frames.push_back(std::move(frame));
		}
		sp += 8;
	}

	{
		std::lock_guard<std::mutex> lk(st.stack_mutex);
		st.call_stack = frames;
	}

	return frames;
}


std::vector<memory_region_t> get_memory_map() {
	auto& st = g_state;
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

	return map;
}


int add_watch(const std::string& expression) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.watch_mutex);
	watch_entry_t w;
	w.expression = expression;
	st.watches.push_back(std::move(w));
	return static_cast<int>(st.watches.size()) - 1;
}

bool remove_watch(int index) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.watch_mutex);
	if (index < 0 || index >= static_cast<int>(st.watches.size()))
		return false;
	st.watches.erase(st.watches.begin() + index);
	return true;
}

void refresh_watches() {
	auto& st = g_state;
	auto regs = get_registers();
	std::lock_guard<std::mutex> lk(st.watch_mutex);

	for (auto& w : st.watches) {

		auto expr = w.expression;
		for (auto& c : expr) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

		uint64_t val = 0;
		bool found = false;

		if      (expr == "rax") { val = regs.rax; found = true; }
		else if (expr == "rbx") { val = regs.rbx; found = true; }
		else if (expr == "rcx") { val = regs.rcx; found = true; }
		else if (expr == "rdx") { val = regs.rdx; found = true; }
		else if (expr == "rsi") { val = regs.rsi; found = true; }
		else if (expr == "rdi") { val = regs.rdi; found = true; }
		else if (expr == "rbp") { val = regs.rbp; found = true; }
		else if (expr == "rsp") { val = regs.rsp; found = true; }
		else if (expr == "r8")  { val = regs.r8;  found = true; }
		else if (expr == "r9")  { val = regs.r9;  found = true; }
		else if (expr == "r10") { val = regs.r10; found = true; }
		else if (expr == "r11") { val = regs.r11; found = true; }
		else if (expr == "r12") { val = regs.r12; found = true; }
		else if (expr == "r13") { val = regs.r13; found = true; }
		else if (expr == "r14") { val = regs.r14; found = true; }
		else if (expr == "r15") { val = regs.r15; found = true; }
		else if (expr == "rip") { val = regs.rip; found = true; }
		else if (expr == "rflags") { val = regs.rflags; found = true; }
		else {
			char* end_ptr = nullptr;
			val = std::strtoull(expr.c_str(), &end_ptr, 16);
			if (end_ptr && end_ptr != expr.c_str()) {
				std::vector<uint8_t> buf;
				if (driver_bridge::read_memory(val, 8, buf) && buf.size() >= 8) {
					uint64_t deref;
					std::memcpy(&deref, buf.data(), 8);
					char hex[20];
					snprintf(hex, sizeof(hex), "0x%016" PRIX64, deref);
					w.value = hex;
					w.type = "uint64";
					w.valid = true;
					continue;
				}
			}
		}

		if (found) {
			char hex[20];
			snprintf(hex, sizeof(hex), "0x%016" PRIX64, val);
			w.value = hex;
			w.type = "uint64";
			w.valid = true;
		} else {
			w.value = "<error>";
			w.valid = false;
		}
	}
}


bool start_trace(int max_records) {
	auto& st = g_state;
	if (st.tracing.load()) return false;
	st.trace_max_depth = max_records;
	{
		std::lock_guard<std::mutex> lk(st.trace_mutex);
		st.trace_log.clear();
	}
	st.tracing.store(true);
	return true;
}

bool stop_trace() {
	auto& st = g_state;
	st.tracing.store(false);
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
	if (st.target_pid == 0) return;

	static auto nt_query = reinterpret_cast<nt_query_system_information_fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
	if (!nt_query) return;

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
	for (ULONG i = 0; i < info->number_of_handles; ++i) {
		auto& entry = info->handles[i];
		if (static_cast<uint32_t>(entry.pid) != st.target_pid)
			continue;
		handle_info_t hi;
		hi.handle = entry.handle_value;
		hi.type_index = entry.object_type_index;
		hi.access = entry.granted_access;
		result.push_back(std::move(hi));
	}

	std::lock_guard<std::mutex> lk(st.handle_mutex);
	st.handles = std::move(result);
}


void find_strings(size_t min_length) {
	auto& st = g_state;
	if (st.target_pid == 0) return;

	auto regions = driver_bridge::enumerate_memory_regions(4096);
	auto modules = driver_bridge::enumerate_modules();

	std::vector<string_ref_t> found;

	for (const auto& region : regions) {
		if (region.state != 0x1000) continue;
		if (region.size > 0x1000000) continue;

		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), buf))
			continue;


		size_t start = 0;
		bool in_string = false;
		for (size_t i = 0; i < buf.size(); ++i) {
			bool printable = (buf[i] >= 0x20 && buf[i] <= 0x7e);
			if (printable && !in_string) {
				start = i;
				in_string = true;
			} else if (!printable && in_string) {
				size_t len = i - start;
				if (len >= min_length && buf[i] == 0) {
					string_ref_t sr;
					sr.address = region.base + start;
					sr.value = std::string(reinterpret_cast<const char*>(buf.data() + start), len);
					sr.is_unicode = false;
					for (const auto& m : modules) {
						if (sr.address >= m.base && sr.address < m.base + m.size) {
							sr.module_name = m.name;
							sr.module_offset = sr.address - m.base;
							break;
						}
					}
					found.push_back(std::move(sr));
				}
				in_string = false;
			}
		}

		if (found.size() > 100000) break;
	}

	{
		std::lock_guard<std::mutex> lk(st.strings_mutex);
		st.strings = std::move(found);
	}
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
	switch (protect) {
		case 0x01: return "NOACCESS";
		case 0x02: return "READONLY";
		case 0x04: return "READWRITE";
		case 0x08: return "WRITECOPY";
		case 0x10: return "EXECUTE";
		case 0x20: return "EXECUTE_READ";
		case 0x40: return "EXECUTE_READWRITE";
		case 0x80: return "EXECUTE_WRITECOPY";
		default: {
			char buf[16];
			snprintf(buf, sizeof(buf), "0x%X", protect);
			return buf;
		}
	}
}

}
