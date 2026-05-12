#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include "debugger_engine.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "../editor/expression_eval.hpp"
#include "work_queue.hpp"
#include "event_bus.hpp"
#include "toast_notification.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>

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

struct ng_unicode_string_t {
	USHORT  length;
	USHORT  maximum_length;
	wchar_t* buffer;
};

struct ng_object_name_information_t {
	ng_unicode_string_t name;
};

struct ng_object_type_information_t {
	ng_unicode_string_t type_name;
	ULONG total_number_of_objects;
	ULONG total_number_of_handles;
	ULONG total_paged_pool_usage;
	ULONG total_non_paged_pool_usage;
	ULONG total_name_pool_usage;
	ULONG total_handle_table_usage;
	ULONG high_water_number_of_objects;
	ULONG high_water_number_of_handles;
	ULONG high_water_paged_pool_usage;
	ULONG high_water_non_paged_pool_usage;
	ULONG high_water_name_pool_usage;
	ULONG high_water_handle_table_usage;
	ULONG invalid_attributes;
	ULONG generic_mapping[4];
	ULONG valid_access_mask;
	BOOLEAN security_required;
	BOOLEAN maintain_handle_count;
	UCHAR type_index;
	UCHAR reserved_byte;
	ULONG pool_type;
	ULONG default_paged_pool_charge;
	ULONG default_non_paged_pool_charge;
};

using nt_query_object_fn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

constexpr ULONG ng_object_type_information_class = 2;
constexpr ULONG ng_object_name_information_class = 1;

inline std::string utf8_from_unicode_string(const ng_unicode_string_t& us) {
	if (us.buffer == nullptr || us.length == 0)
		return {};
	int wlen = static_cast<int>(us.length / sizeof(wchar_t));
	int needed = WideCharToMultiByte(CP_UTF8, 0, us.buffer, wlen, nullptr, 0, nullptr, nullptr);
	if (needed <= 0) return {};
	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_UTF8, 0, us.buffer, wlen, out.data(), needed, nullptr, nullptr);
	return out;
}

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
	st.status.store(dbg_status_t::idle);
	ensure_event_subscriptions();
}

void shutdown() {
	auto& st = g_state;
	st.tracing.store(false);
	st.worker_active.store(false);
	{
		std::lock_guard<std::mutex> lk(st.trap_mtx);
		st.trap_signaled.store(true);
	}
	st.trap_cv.notify_all();
	if (st.worker_thread.joinable()) st.worker_thread.join();
	clear_all_breakpoints();
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
			return -1;
		}
		if (orig[0] == 0xCC) {
			set_last_error("add_breakpoint: byte already 0xCC");
			return -1;
		}
		bp.original_byte = orig[0];

		std::vector<uint8_t> cc{0xCC};
		if (!driver_bridge::write_memory(address, cc)) {
			set_last_error("add_breakpoint: write_memory failed");
			return -1;
		}

		std::vector<uint8_t> verify;
		if (!driver_bridge::read_memory(address, 1, verify) || verify.empty() || verify[0] != 0xCC) {
			std::vector<uint8_t> restore{bp.original_byte};
			driver_bridge::write_memory(address, restore);
			set_last_error("add_breakpoint: write verification failed");
			return -1;
		}
		bp.byte_written = true;
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
			auto threads = driver_bridge::enumerate_threads();
			for (const auto& t : threads) {
				if (t.owner_pid != st.target_pid) continue;
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
			set_last_error("add_breakpoint: partial DRx programming");
		}
	}

	st.breakpoints.push_back(std::move(bp));
	return static_cast<int>(st.breakpoints.size()) - 1;
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
		auto threads = driver_bridge::enumerate_threads();
		for (const auto& t : threads) {
			if (t.owner_pid != st.target_pid) continue;
			driver_bridge::clear_hardware_breakpoint(t.tid, bp.hw_slot);
		}
	}

	st.breakpoints.erase(st.breakpoints.begin() + index);
	return true;
}

bool toggle_breakpoint(int index) {
	auto& st = g_state;
	sync_attached_state();
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size()))
		return false;
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
				auto threads = driver_bridge::enumerate_threads();
				for (const auto& t : threads) {
					if (t.owner_pid != st.target_pid) continue;
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
				auto threads = driver_bridge::enumerate_threads();
				for (const auto& t : threads) {
					if (t.owner_pid != st.target_pid) continue;
					driver_bridge::set_hardware_breakpoint(t.tid, slot, bp.address, hw_type, len_bits);
				}
			}
		}
	}

	bp.state = will_enable ? bp_state_t::enabled : bp_state_t::disabled;
	return true;
}

void clear_all_breakpoints() {
	auto& st = g_state;
	sync_attached_state();

	std::vector<driver_bridge::thread_info_t> threads;
	if (st.target_pid != 0)
		threads = driver_bridge::enumerate_threads();

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
}


bool run_target() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) return false;

	auto threads = driver_bridge::enumerate_threads();
	bool any_resumed = false;
	for (const auto& t : threads) {
		if (t.owner_pid != st.target_pid) continue;
		if (driver_bridge::resume_thread(t.tid))
			any_resumed = true;
	}

	st.status.store(dbg_status_t::running);
	return any_resumed || threads.empty();
}

bool pause_target() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) return false;

	auto threads = driver_bridge::enumerate_threads();
	bool any_suspended = false;
	for (const auto& t : threads) {
		if (t.owner_pid != st.target_pid) continue;
		if (driver_bridge::suspend_thread(t.tid))
			any_suspended = true;
	}

	st.status.store(dbg_status_t::paused);
	return any_suspended || threads.empty();
}

bool step_into() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0 || st.active_tid == 0) return false;
	st.status.store(dbg_status_t::stepping);

	auto regs = get_registers();
	if (regs.rip == 0) return false;
	uint64_t pre_step_rip = regs.rip;

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

	if (!driver_bridge::suspend_thread(st.active_tid)) {
		set_last_error("step_into: suspend_thread failed");
		return false;
	}

	driver_bridge::thread_context_t kctx{};
	if (!driver_bridge::get_thread_context(st.active_tid, kctx)) {
		driver_bridge::resume_thread(st.active_tid);
		set_last_error("step_into: get_thread_context failed");
		return false;
	}

	kctx.rflags |= 0x100ULL;

	if (!driver_bridge::set_thread_context(st.active_tid, kctx, ~0ULL)) {
		driver_bridge::resume_thread(st.active_tid);
		set_last_error("step_into: set_thread_context failed");
		return false;
	}

	if (!driver_bridge::resume_thread(st.active_tid)) {
		set_last_error("step_into: resume_thread failed");
		return false;
	}

	const uint32_t step_timeout_ms = 5000;
	auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(step_timeout_ms);
	register_set_t post_regs{};
	bool advanced = false;
	while (std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
		driver_bridge::thread_context_t probe{};
		if (!driver_bridge::get_thread_context(st.active_tid, probe))
			continue;
		if (probe.rip != pre_step_rip) {
			driver_bridge::suspend_thread(st.active_tid);
			driver_bridge::thread_context_t stable{};
			if (driver_bridge::get_thread_context(st.active_tid, stable)) {
				post_regs.rax = stable.rax; post_regs.rbx = stable.rbx;
				post_regs.rcx = stable.rcx; post_regs.rdx = stable.rdx;
				post_regs.rsi = stable.rsi; post_regs.rdi = stable.rdi;
				post_regs.rbp = stable.rbp; post_regs.rsp = stable.rsp;
				post_regs.r8  = stable.r8;  post_regs.r9  = stable.r9;
				post_regs.r10 = stable.r10; post_regs.r11 = stable.r11;
				post_regs.r12 = stable.r12; post_regs.r13 = stable.r13;
				post_regs.r14 = stable.r14; post_regs.r15 = stable.r15;
				post_regs.rip = stable.rip; post_regs.rflags = stable.rflags;
				post_regs.cs = stable.cs; post_regs.ss = stable.ss;
				post_regs.dr0 = stable.dr0; post_regs.dr1 = stable.dr1;
				post_regs.dr2 = stable.dr2; post_regs.dr3 = stable.dr3;
				post_regs.dr6 = stable.dr6; post_regs.dr7 = stable.dr7;
			}
			advanced = true;
			break;
		}
	}

	if (!advanced) {
		driver_bridge::suspend_thread(st.active_tid);
		driver_bridge::thread_context_t restore_ctx{};
		if (driver_bridge::get_thread_context(st.active_tid, restore_ctx)) {
			restore_ctx.rflags &= ~0x100ULL;
			driver_bridge::set_thread_context(st.active_tid, restore_ctx, ~0ULL);
		}
		st.status.store(dbg_status_t::paused);
		set_last_error("step_into: thread did not advance within timeout");
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
	if (bp_action == bp_hit_action_t::resume) {
		st.status.store(dbg_status_t::running);
		driver_bridge::resume_thread(st.active_tid);
		return true;
	}

	st.status.store(dbg_status_t::paused);
	return true;
}

bool step_over() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) return false;

	auto regs = get_registers();
	if (regs.rip == 0) return false;

	std::vector<uint8_t> code;
	if (driver_bridge::read_memory(regs.rip, 16, code) && !code.empty()) {
		auto ins = zydis_decode_one(code.data(), static_cast<int>(code.size()), regs.rip);
		if (ins.is_call)
			return run_to_address(regs.rip + static_cast<uint64_t>(ins.len), true, 5000);
	}

	return step_into();
}

bool step_out() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) return false;

	auto regs = get_registers();
	if (regs.rsp == 0) return false;

	std::vector<uint8_t> ret_buf;
	if (driver_bridge::read_memory(regs.rsp, 8, ret_buf) && ret_buf.size() >= 8) {
		uint64_t ret_addr;
		std::memcpy(&ret_addr, ret_buf.data(), 8);
		return run_to_address(ret_addr, true, 30000);
	}
	return false;
}

bool run_to_address(uint64_t address, bool wait_for_completion, uint32_t timeout_ms) {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) return false;

	std::vector<uint8_t> orig_buf;
	if (!driver_bridge::read_memory(address, 1, orig_buf) || orig_buf.empty()) {
		set_last_error("run_to_address: read_memory failed");
		return false;
	}

	const uint8_t cc_byte = 0xCC;
	std::vector<uint8_t> cc_buf{cc_byte};
	if (!driver_bridge::write_memory(address, cc_buf)) {
		set_last_error("run_to_address: write_memory failed");
		return false;
	}

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
	for (const auto& t : threads) {
		if (t.owner_pid != st.target_pid) continue;
		driver_bridge::resume_thread(t.tid);
	}

	st.status.store(dbg_status_t::running);

	if (!wait_for_completion)
		return true;

	auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(timeout_ms);
	bool reached = false;
	uint32_t hit_tid = 0;
	while (std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		auto probe_threads = driver_bridge::enumerate_threads();
		for (const auto& th : probe_threads) {
			if (th.owner_pid != st.target_pid) continue;
			driver_bridge::thread_context_t kctx{};
			if (!driver_bridge::get_thread_context(th.tid, kctx))
				continue;
			if (kctx.rip == address || kctx.rip == address + 1) {
				reached = true;
				hit_tid = th.tid;
				if (kctx.rip == address + 1) {
					kctx.rip = address;
					driver_bridge::set_thread_context(th.tid, kctx, ~0ULL);
				}
				break;
			}
		}
		if (reached) break;
	}

	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		for (auto it = st.internal_breakpoints.begin(); it != st.internal_breakpoints.end(); ) {
			if (it->address == address && it->active) {
				std::vector<uint8_t> restore{it->original_byte};
				driver_bridge::write_memory(address, restore);
				it = st.internal_breakpoints.erase(it);
			} else {
				++it;
			}
		}
		for (auto it = st.breakpoints.begin(); it != st.breakpoints.end(); ) {
			if (it->address == address && it->is_internal &&
				it->state == bp_state_t::one_shot && it->byte_written) {
				it = st.breakpoints.erase(it);
			} else {
				++it;
			}
		}
	}

	if (!reached) {
		set_last_error("run_to_address: timed out waiting for trap");
		st.status.store(dbg_status_t::paused);
		invalidate_cache();
		return false;
	}

	if (hit_tid != 0) {
		st.active_tid = hit_tid;
		signal_trap(address);
	}
	st.status.store(dbg_status_t::paused);
	invalidate_cache();
	return true;
}


register_set_t get_registers() {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0 || st.active_tid == 0) return {};

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

	bool ok = driver_bridge::set_thread_context(st.active_tid, kctx, ~0ULL);

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
	sync_attached_state();
	if (st.target_pid == 0) return;

	static auto nt_query = reinterpret_cast<nt_query_system_information_fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
	if (!nt_query) return;

	static auto nt_query_object = reinterpret_cast<nt_query_object_fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));

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

	HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, st.target_pid);
	HANDLE current_proc = GetCurrentProcess();

	for (ULONG i = 0; i < info->number_of_handles; ++i) {
		auto& entry = info->handles[i];
		if (static_cast<uint32_t>(entry.pid) != st.target_pid)
			continue;
		handle_info_t hi;
		hi.handle = entry.handle_value;
		hi.type_index = entry.object_type_index;
		hi.access = entry.granted_access;

		if (proc != nullptr && nt_query_object != nullptr) {
			HANDLE dup = nullptr;
			if (DuplicateHandle(proc,
								reinterpret_cast<HANDLE>(static_cast<uintptr_t>(entry.handle_value)),
								current_proc, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
				struct query_ctx_t {
					std::mutex              mtx;
					std::condition_variable cv;
					bool                    done = false;
					bool                    ok = false;
					std::vector<uint8_t>    out;
					HANDLE                  target = nullptr;
					ULONG                   info_class = 0;
					nt_query_object_fn      fn = nullptr;
					bool                    handle_owned = true;
				};

				auto run_query = [&](ULONG info_class, std::vector<uint8_t>& out_buf, bool& abandoned) -> bool {
					auto ctx = std::make_shared<query_ctx_t>();
					ctx->target = dup;
					ctx->info_class = info_class;
					ctx->fn = nt_query_object;

					std::thread worker([ctx]() {
						ULONG required = 0;
						std::vector<uint8_t> local_buf(0x1000);
						NTSTATUS st_q = ctx->fn(ctx->target, ctx->info_class,
												 local_buf.data(),
												 static_cast<ULONG>(local_buf.size()),
												 &required);
						if (st_q == static_cast<NTSTATUS>(0xC0000004) && required > 0) {
							local_buf.resize(required);
							st_q = ctx->fn(ctx->target, ctx->info_class,
										   local_buf.data(),
										   static_cast<ULONG>(local_buf.size()),
										   &required);
						}
						bool close_here = false;
						{
							std::lock_guard<std::mutex> lk(ctx->mtx);
							ctx->ok = (st_q == 0);
							if (ctx->ok)
								ctx->out = std::move(local_buf);
							ctx->done = true;
							close_here = !ctx->handle_owned;
						}
						ctx->cv.notify_all();
						if (close_here && ctx->target)
							CloseHandle(ctx->target);
					});
					worker.detach();

					std::unique_lock<std::mutex> lk(ctx->mtx);
					if (!ctx->cv.wait_for(lk, std::chrono::milliseconds(200),
										   [&ctx]() { return ctx->done; })) {
						ctx->handle_owned = false;
						abandoned = true;
						return false;
					}
					if (!ctx->ok) return false;
					out_buf = std::move(ctx->out);
					return true;
				};

				bool abandoned = false;
				std::vector<uint8_t> type_buf;
				if (run_query(ng_object_type_information_class, type_buf, abandoned) &&
					type_buf.size() >= sizeof(ng_object_type_information_t)) {
					auto* tinfo = reinterpret_cast<ng_object_type_information_t*>(type_buf.data());
					hi.type_name = utf8_from_unicode_string(tinfo->type_name);
				}

				if (!abandoned) {
					std::vector<uint8_t> name_buf;
					if (run_query(ng_object_name_information_class, name_buf, abandoned) &&
						name_buf.size() >= sizeof(ng_object_name_information_t)) {
						auto* ninfo = reinterpret_cast<ng_object_name_information_t*>(name_buf.data());
						hi.name = utf8_from_unicode_string(ninfo->name);
					}
				}

				if (!abandoned)
					CloseHandle(dup);
			}
		}

		result.push_back(std::move(hi));
	}

	if (proc != nullptr) CloseHandle(proc);

	std::lock_guard<std::mutex> lk(st.handle_mutex);
	st.handles = std::move(result);
}


void find_strings(size_t min_length) {
	auto& st = g_state;
	sync_attached_state();
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


bool set_breakpoint_condition(int index, const std::string& condition) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size())) {
		set_last_error("set_breakpoint_condition: index out of range");
		return false;
	}
	st.breakpoints[static_cast<size_t>(index)].condition = condition;
	return true;
}

bool set_breakpoint_log(int index, const std::string& log_text, bool auto_continue) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.bp_mutex);
	if (index < 0 || index >= static_cast<int>(st.breakpoints.size())) {
		set_last_error("set_breakpoint_log: index out of range");
		return false;
	}
	auto& bp = st.breakpoints[static_cast<size_t>(index)];
	bp.log_text = log_text;
	bp.auto_continue = auto_continue;
	return true;
}

bp_hit_action_t handle_breakpoint_hit(uint64_t address) {
	auto& st = g_state;

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
				driver_bridge::set_thread_context(st.active_tid, adj, ~0ULL);
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

std::vector<uint8_t> cached_disasm_window(uint64_t& base_out) {
	auto& st = g_state;
	std::lock_guard<std::mutex> lk(st.cache_mtx);
	base_out = st.cached_disasm_base;
	return st.cached_disasm_bytes;
}

void sync_attached_state() {
	auto& st = g_state;
	uint32_t live_pid = driver_bridge::attached_pid();
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

	work_queue::post([]() {
		auto& s = g_state;
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
		s.refresh_in_flight.store(false);
	});
}

void request_thread_refresh(uint32_t max_age_ms) {
	auto& st = g_state;
	sync_attached_state();
	if (st.target_pid == 0) return;
	uint64_t now = now_ms();
	if (now - st.last_thread_refresh_ms.load() < max_age_ms) return;
	bool expected = false;
	if (!st.thread_refresh_in_flight.compare_exchange_strong(expected, true)) return;

	work_queue::post([]() {
		auto& s = g_state;
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
		s.thread_refresh_in_flight.store(false);
	});
}

void request_stack_refresh(uint64_t rsp, size_t bytes, uint32_t max_age_ms) {
	auto& st = g_state;
	if (rsp == 0 || bytes == 0) return;
	uint64_t now = now_ms();
	if (now - st.last_stack_refresh_ms.load() < max_age_ms) return;
	bool expected = false;
	if (!st.stack_refresh_in_flight.compare_exchange_strong(expected, true)) return;

	work_queue::post([rsp, bytes]() {
		auto& s = g_state;
		std::vector<uint8_t> buf;
		driver_bridge::read_memory(rsp, bytes, buf);
		{
			std::lock_guard<std::mutex> lk(s.cache_mtx);
			s.cached_stack_addr = rsp;
			s.cached_stack = std::move(buf);
		}
		s.last_stack_refresh_ms.store(now_ms());
		s.stack_refresh_in_flight.store(false);
	});
}

void request_dump_refresh(uint64_t addr, size_t bytes, uint32_t max_age_ms) {
	auto& st = g_state;
	if (addr == 0 || bytes == 0) return;
	uint64_t now = now_ms();
	if (now - st.last_dump_refresh_ms.load() < max_age_ms) return;
	bool expected = false;
	if (!st.dump_refresh_in_flight.compare_exchange_strong(expected, true)) return;

	work_queue::post([addr, bytes]() {
		auto& s = g_state;
		std::vector<uint8_t> buf;
		driver_bridge::read_memory(addr, bytes, buf);
		{
			std::lock_guard<std::mutex> lk(s.cache_mtx);
			s.cached_dump_addr = addr;
			s.cached_dump_size = bytes;
			s.cached_dump = std::move(buf);
		}
		s.last_dump_refresh_ms.store(now_ms());
		s.dump_refresh_in_flight.store(false);
	});
}

void request_disasm_refresh(uint64_t rip, uint32_t max_age_ms) {
	auto& st = g_state;
	if (rip == 0) return;
	uint64_t now = now_ms();
	if (now - st.last_disasm_refresh_ms.load() < max_age_ms) return;
	bool expected = false;
	if (!st.disasm_refresh_in_flight.compare_exchange_strong(expected, true)) return;

	work_queue::post([rip]() {
		auto& s = g_state;
		uint64_t base = (rip > 0x100) ? rip - 0x100 : 0;
		std::vector<uint8_t> buf;
		driver_bridge::read_memory(base, 0x400, buf);
		{
			std::lock_guard<std::mutex> lk(s.cache_mtx);
			s.cached_disasm_base = base;
			s.cached_disasm_bytes = std::move(buf);
		}
		s.last_disasm_refresh_ms.store(now_ms());
		s.disasm_refresh_in_flight.store(false);
	});
}

void invalidate_cache() {
	auto& st = g_state;
	st.last_refresh_ms.store(0);
	st.last_thread_refresh_ms.store(0);
	st.last_stack_refresh_ms.store(0);
	st.last_dump_refresh_ms.store(0);
	st.last_disasm_refresh_ms.store(0);
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

}
