#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include "debugger_engine.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
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

bool resume_thread_for_controlled_run(uint32_t tid, uint32_t previous_suspend_count) {
	uint32_t resumes = previous_suspend_count + 1;
	if (resumes == 0 || resumes > 64)
		resumes = 64;
	for (uint32_t i = 0; i < resumes; ++i) {
		uint32_t prev = 0;
		if (!driver_bridge::resume_thread(tid, &prev))
			return false;
		if (prev == 0)
			break;
	}
	return true;
}

bool suspend_contextable_thread(state_t& st, driver_bridge::thread_context_t& ctx, uint32_t& previous_suspend_count) {
	auto try_thread = [&](uint32_t tid) -> bool {
		if (tid == 0)
			return false;
		uint32_t saved = 0;
		if (!driver_bridge::suspend_thread(tid, &saved))
			return false;
		if (driver_bridge::get_thread_context(tid, ctx)) {
			st.active_tid = tid;
			previous_suspend_count = saved;
			return true;
		}
		driver_bridge::resume_thread(tid);
		return false;
	};

	if (try_thread(st.active_tid))
		return true;

	auto threads = driver_bridge::enumerate_threads();
	for (const auto& th : threads) {
		if (th.owner_pid != st.target_pid || th.tid == st.active_tid)
			continue;
		if (try_thread(th.tid))
			return true;
	}
	return false;
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
	if (tid != 0 && previous_suspend_count > 0)
		driver_bridge::resume_thread(tid);
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
		auto threads = driver_bridge::enumerate_threads();
		for (const auto& t : threads) {
			if (t.owner_pid != st.target_pid) continue;
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
	diag::log_tagged_fmt("dbg_engine", "toggle_breakpoint: index=%d addr=0x%llX now=%s", index, (unsigned long long)bp.address, will_enable ? "enabled" : "disabled");
	return true;
}

void clear_all_breakpoints() {
	auto& st = g_state;
	diag::log_tagged_fmt("dbg_engine", "clear_all_breakpoints: entry");
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
		driver_ok = driver_bridge::attach(lr.pid);
		diag::log_tagged_critical_fmt("spawn",
			"spawn_post_driver_attach pid=%u ok=%d elapsed_ms=%llu driver_pid=%u driver_status='%s' last_error='%s'",
			static_cast<unsigned>(lr.pid),
			driver_ok ? 1 : 0,
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
		HANDLE t = reinterpret_cast<HANDLE>(lr.thread_handle);
		diag::log_tagged_critical_fmt("spawn",
			"spawn_pre_ResumeThread pid=%u thread_handle=%p",
			static_cast<unsigned>(lr.pid), t);
		DWORD prev_count = ResumeThread(t);
		if (prev_count == static_cast<DWORD>(-1)) {
			DWORD gle = GetLastError();
			char err[256];
			std::snprintf(err, sizeof(err),
				"ResumeThread failed (gle=%lu)", static_cast<unsigned long>(gle));
			set_last_error(err);
			diag::log_tagged_critical_fmt("spawn",
				"spawn_ResumeThread_FAILED pid=%u gle=%lu",
				static_cast<unsigned>(lr.pid),
				static_cast<unsigned long>(gle));
			HANDLE p = reinterpret_cast<HANDLE>(lr.process_handle);
			if (p) TerminateProcess(p, 0xDEADu);
			run_target::cleanup(lr);
			return false;
		}
		diag::log_tagged_critical_fmt("spawn",
			"spawn_ResumeThread_ok pid=%u prev_suspend_count=%lu",
			static_cast<unsigned>(lr.pid),
			static_cast<unsigned long>(prev_count));
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

	std::vector<uint8_t> step_code;
	if (driver_bridge::read_memory(kctx.rip, 16, step_code) && !step_code.empty()) {
		auto ins = zydis_decode_one(step_code.data(), static_cast<int>(step_code.size()), kctx.rip);
		if (ins.is_nop && ins.len > 0 && ins.len <= 15) {
			kctx.rip += static_cast<uint64_t>(ins.len);
			kctx.rflags &= ~0x100ULL;
			if (!driver_bridge::set_thread_context(st.active_tid, kctx, ~0ULL)) {
				driver_bridge::set_thread_context(st.active_tid, original_step_ctx, ~0ULL);
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
	}

	kctx.rflags |= 0x100ULL;

	if (!driver_bridge::set_thread_context(st.active_tid, kctx, ~0ULL)) {
		driver_bridge::set_thread_context(st.active_tid, original_step_ctx, ~0ULL);
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

	const uint32_t step_timeout_ms = 1500;
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
				driver_bridge::set_thread_context(st.active_tid, stable, ~0ULL);
				post_regs = capture_registers_from_context(stable);
				advanced = true;
				break;
			}
			probe.rflags &= ~0x100ULL;
			driver_bridge::set_thread_context(st.active_tid, probe, ~0ULL);
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
				if (!driver_bridge::set_thread_context(selected_tid, kctx, ~0ULL)) {
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

	diag::log_tagged_fmt("debugger",
		"run_to_address_begin addr=0x%llx wait=%d timeout_ms=%u",
		static_cast<unsigned long long>(address),
		wait_for_completion ? 1 : 0,
		static_cast<unsigned>(timeout_ms));

	std::vector<uint8_t> orig_buf;
	if (!driver_bridge::read_memory(address, 1, orig_buf) || orig_buf.empty()) {
		set_last_error("run_to_address: read_memory failed");
		diag::log_tagged_fmt("debugger",
			"run_to_address_read_FAILED addr=0x%llx",
			static_cast<unsigned long long>(address));
		return false;
	}

	const uint8_t cc_byte = 0xCC;
	std::vector<uint8_t> cc_buf{cc_byte};
	if (!driver_bridge::write_memory(address, cc_buf)) {
		set_last_error("run_to_address: write_memory failed");
		diag::log_tagged_fmt("debugger",
			"run_to_address_write_FAILED addr=0x%llx",
			static_cast<unsigned long long>(address));
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
		diag::log_tagged_fmt("debugger",
			"run_to_address_TIMEOUT addr=0x%llx timeout_ms=%u",
			static_cast<unsigned long long>(address),
			static_cast<unsigned>(timeout_ms));
		return false;
	}

	if (hit_tid != 0) {
		st.active_tid = hit_tid;
		signal_trap(address);
	}
	st.status.store(dbg_status_t::paused);
	invalidate_cache();
	diag::log_tagged_fmt("debugger",
		"run_to_address_reached addr=0x%llx hit_tid=%u",
		static_cast<unsigned long long>(address),
		static_cast<unsigned>(hit_tid));
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
	diag::log_tagged_fmt("cpu",
		"set_register name='%s' value=0x%llx tid=%u ok=%d",
		name.c_str(),
		static_cast<unsigned long long>(value),
		static_cast<unsigned>(st.active_tid),
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
	diag::log_tagged_fmt("dbg_engine", "get_call_stack: entry pid=%u tid=%u", st.target_pid, st.active_tid);
	std::vector<stack_frame_t> frames;

	auto regs = get_registers();
	if (regs.rip == 0 || regs.rsp == 0) {
		diag::log_tagged_fmt("dbg_engine", "get_call_stack: empty regs (RIP=0 or RSP=0), returning empty");
		return frames;
	}

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

	diag::log_tagged_fmt("dbg_engine", "get_call_stack: result frames=%zu", frames.size());
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

					if (!work_queue::post([ctx]() {
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
					}))
					{
						std::lock_guard<std::mutex> lk(ctx->mtx);
						ctx->done = true;
						ctx->ok = false;
					}

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

	{
		std::lock_guard<std::mutex> lk(st.strings_mutex);
		st.strings = std::move(found);
	}
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

	bool posted = work_queue::post([min_length]() {
		try {
			find_strings(min_length);
		} catch (...) {}
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
