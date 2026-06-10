#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "standalone_driver.hpp"

namespace packet_callstack {

struct stack_frame_t {
	uint64_t address;
	uint64_t return_address;
	std::string module_name;
	uint64_t module_offset;
};

struct packet_callstack_entry_t {
	uint64_t packet_index;
	uint64_t timestamp;
	uint32_t pid;
	uint32_t tid;
	uint64_t rip;
	uint64_t rsp;
	std::vector<stack_frame_t> frames;
	bool resolved;
};

struct state_t {
	std::deque<packet_callstack_entry_t> entries;
	std::mutex mutex;
	std::atomic<bool> enabled{false};
	size_t max_entries = 4096;
};

inline state_t g_state;

inline void set_enabled(bool en) { g_state.enabled.store(en); }
inline bool is_enabled() { return g_state.enabled.load(); }

inline void push_entry(packet_callstack_entry_t&& entry) {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.entries.push_back(std::move(entry));
	while (g_state.entries.size() > g_state.max_entries)
		g_state.entries.pop_front();
}

inline stack_frame_t local_frame_from_address(uint64_t addr) {
	stack_frame_t frame{};
	frame.address = addr;
	frame.return_address = addr;
	HMODULE module = nullptr;
	if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCSTR>(addr),
		&module)) {
		frame.module_offset = addr - reinterpret_cast<uint64_t>(module);
		char path[MAX_PATH]{};
		DWORD len = GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path)));
		if (len > 0) {
			path[(std::min)(static_cast<size_t>(len), sizeof(path) - 1)] = '\0';
			const char* slash = std::strrchr(path, '\\');
			frame.module_name = slash ? slash + 1 : path;
		}
	}
	return frame;
}

inline bool capture_current_thread(packet_callstack_entry_t& entry) {
	void* frames[32]{};
	USHORT count = CaptureStackBackTrace(0, static_cast<DWORD>(sizeof(frames) / sizeof(frames[0])), frames, nullptr);
	entry.frames.reserve(count);
	for (USHORT i = 0; i < count; ++i) {
		uint64_t addr = reinterpret_cast<uint64_t>(frames[i]);
		if (addr == 0)
			continue;
		if (entry.rip == 0)
			entry.rip = addr;
		entry.frames.push_back(local_frame_from_address(addr));
	}
	entry.resolved = true;
	return !entry.frames.empty();
}

inline void resolve_modules(packet_callstack_entry_t& entry) {
	auto modules = driver_bridge::enumerate_modules();
	if (modules.empty())
		return;

	for (auto& frame : entry.frames) {
		if (!frame.module_name.empty())
			continue;
		for (const auto& m : modules) {
			if (frame.address >= m.base && frame.address < m.base + m.size) {
				frame.module_name = m.name;
				frame.module_offset = frame.address - m.base;
				break;
			}
		}
	}

	entry.resolved = true;
}

inline void capture_for_packet(uint64_t packet_idx, uint64_t timestamp,
                                uint32_t pid, uint32_t tid) {
	if (!g_state.enabled.load())
		return;

	if (!driver_bridge::using_kernel_driver())
		return;

	packet_callstack_entry_t entry{};
	entry.packet_index = packet_idx;
	entry.timestamp = timestamp;
	entry.pid = pid;
	entry.tid = tid;
	entry.resolved = false;

	if (pid == GetCurrentProcessId() && tid == GetCurrentThreadId()) {
		capture_current_thread(entry);
		push_entry(std::move(entry));
		return;
	}

	driver_bridge::thread_context_t ctx{};
	if (!driver_bridge::get_thread_context(tid, ctx)) {
		push_entry(std::move(entry));
		return;
	}

	entry.rip = ctx.rip;
	entry.rsp = ctx.rsp;

	auto modules = driver_bridge::enumerate_modules();

	auto is_code_address = [&](uint64_t addr) -> bool {
		if (addr < 0x10000)
			return false;
		for (const auto& m : modules) {
			if (addr >= m.base && addr < m.base + m.size)
				return true;
		}
		return false;
	};

	auto make_frame = [&](uint64_t addr) -> stack_frame_t {
		stack_frame_t f{};
		f.address = addr;
		f.return_address = addr;
		for (const auto& m : modules) {
			if (addr >= m.base && addr < m.base + m.size) {
				f.module_name = m.name;
				f.module_offset = addr - m.base;
				break;
			}
		}
		return f;
	};

	if (is_code_address(ctx.rip)) {
		entry.frames.push_back(make_frame(ctx.rip));
	}

	constexpr int max_frames = 32;
	uint64_t rbp = ctx.rbp;
	int frame_count = 0;

	while (rbp != 0 && frame_count < max_frames) {
		if (rbp < 0x10000 || rbp == 0xCCCCCCCCCCCCCCCCULL)
			break;

		std::vector<uint8_t> buf;
		if (!driver_bridge::read_memory(rbp, 16, buf) || buf.size() < 16)
			break;

		uint64_t next_rbp = 0;
		uint64_t ret_addr = 0;
		std::memcpy(&next_rbp, buf.data(), 8);
		std::memcpy(&ret_addr, buf.data() + 8, 8);

		if (ret_addr == 0 || !is_code_address(ret_addr))
			break;

		auto frame = make_frame(ret_addr);
		entry.frames.push_back(std::move(frame));
		frame_count++;

		if (next_rbp <= rbp)
			break;

		rbp = next_rbp;
	}

	if (frame_count == 0) {
		constexpr size_t scan_size = 0x200;
		std::vector<uint8_t> stack_buf;
		if (driver_bridge::read_memory(ctx.rsp, scan_size, stack_buf) && stack_buf.size() >= 8) {
			size_t aligned_size = stack_buf.size() & ~static_cast<size_t>(7);
			for (size_t off = 0; off < aligned_size && entry.frames.size() < static_cast<size_t>(max_frames + 1); off += 8) {
				uint64_t val = 0;
				std::memcpy(&val, stack_buf.data() + off, 8);
				if (is_code_address(val)) {
					auto frame = make_frame(val);
					entry.frames.push_back(std::move(frame));
				}
			}
		}
	}

	entry.resolved = !modules.empty();

	push_entry(std::move(entry));
}

inline bool get_callstack(uint64_t packet_idx, packet_callstack_entry_t& out) {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	for (auto& entry : g_state.entries) {
		if (entry.packet_index == packet_idx) {
			if (!entry.resolved)
				resolve_modules(entry);
			out = entry;
			return true;
		}
	}
	return false;
}

inline std::vector<packet_callstack_entry_t> get_recent(size_t max_count) {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	std::vector<packet_callstack_entry_t> result;
	size_t count = (std::min)(max_count, g_state.entries.size());
	auto it = g_state.entries.end();
	std::advance(it, -static_cast<ptrdiff_t>(count));
	result.assign(it, g_state.entries.end());
	return result;
}

inline void clear() {
	std::lock_guard<std::mutex> lk(g_state.mutex);
	g_state.entries.clear();
}

}
