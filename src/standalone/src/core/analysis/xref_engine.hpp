#pragma once

#include <atomic>
#include "work_queue.hpp"
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../infra/critical_work_queue.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"

namespace xref_engine {

enum class xref_type_t : int {
	call,
	jump,
	conditional_jump,
	lea,
	data_ref,
};

struct xref_t {
	uint64_t    from_addr = 0;
	uint64_t    to_addr = 0;
	xref_type_t type = xref_type_t::call;
	std::string disasm_text;
	std::string module_name;
};

struct scan_state_t {
	std::vector<xref_t> results;
	std::mutex          mutex;
	std::atomic<bool>   scanning{false};
	std::atomic<float>  progress{0.f};
	std::atomic<bool>   cancel{false};
};

inline scan_state_t g_state;

inline std::string xref_type_name(xref_type_t t)
{
	switch (t) {
	case xref_type_t::call:             return "CALL";
	case xref_type_t::jump:             return "JMP";
	case xref_type_t::conditional_jump: return "Jcc";
	case xref_type_t::lea:              return "LEA";
	case xref_type_t::data_ref:         return "DATA";
	}
	return "???";
}

inline bool wait_until_idle(uint32_t timeout_ms)
{
	const auto start = std::chrono::steady_clock::now();
	for (;;) {
		if (!g_state.scanning.load(std::memory_order_acquire))
			return true;
		const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - start).count();
		if (elapsed >= static_cast<int64_t>(timeout_ms))
			return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

namespace detail {

inline xref_type_t classify_instruction(const AsmInstr& ins)
{
	if (ins.is_call) return xref_type_t::call;
	if (ins.is_branch) {
		char m0 = ins.mnem[0];
		if (m0 == 'j' || m0 == 'J') {
			if (std::strcmp(ins.mnem, "jmp") == 0 || std::strcmp(ins.mnem, "JMP") == 0)
				return xref_type_t::jump;
			return xref_type_t::conditional_jump;
		}
		return xref_type_t::jump;
	}
	if (std::strncmp(ins.mnem, "lea", 3) == 0 || std::strncmp(ins.mnem, "LEA", 3) == 0)
		return xref_type_t::lea;
	return xref_type_t::data_ref;
}

inline bool extract_target(const uint8_t* code, int code_len, uint64_t ins_addr, const AsmInstr& ins, uint64_t& target)
{
	(void)code;
	(void)code_len;

	if ((ins.is_call || ins.is_branch) && ins.branch_target != 0) {
		target = ins.branch_target;
		return true;
	}

	if (ins.has_mem_op && ins.mem_op.base_reg == static_cast<uint16_t>(ZYDIS_REGISTER_RIP)) {
		int64_t computed = static_cast<int64_t>(ins_addr) + static_cast<int64_t>(ins.len) + ins.mem_op.disp;
		if (computed >= 0) {
			target = static_cast<uint64_t>(computed);
			return true;
		}
	}

	return false;
}

}

inline bool find_xrefs_to(uint64_t target_addr, uint64_t search_start, uint64_t search_size)
{
	if (g_state.scanning.load(std::memory_order_acquire)) {
		g_state.cancel.store(true, std::memory_order_release);
		if (!wait_until_idle(1000))
			return false;
	}

	g_state.scanning.store(true, std::memory_order_release);
	g_state.cancel.store(false, std::memory_order_release);
	g_state.progress.store(0.f, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		g_state.results.clear();
	}

	std::string module_name;
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (target_addr >= m.base && target_addr < m.base + m.size) {
			module_name = m.name;
			break;
		}
	}

	auto worker = [target_addr, search_start, search_size, module_name]() {
		struct scan_finish_t {
			~scan_finish_t() { g_state.scanning.store(false); }
		} scan_finish;

		const size_t page_size = 4096;
		uint64_t total = search_size ? search_size : 1;
		uint64_t scanned = 0;

		for (uint64_t offset = 0; offset < search_size && !g_state.cancel.load(); offset += page_size) {
			size_t chunk = page_size;
			if (offset + chunk > search_size)
				chunk = static_cast<size_t>(search_size - offset);

			std::vector<uint8_t> page_data;
			if (!driver_bridge::read_memory(search_start + offset, chunk, page_data)) {
				scanned += chunk;
				g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total));
				continue;
			}

			const uint8_t* data = page_data.data();
			int sz = static_cast<int>(page_data.size());
			int pos = 0;

			while (pos < sz && !g_state.cancel.load()) {
				int avail = sz - pos;
				if (avail > 15) avail = 15;

				uint64_t ins_addr = search_start + offset + pos;
				AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);
				const int ins_len = (ins.len > 0 && ins.len <= avail) ? ins.len : 1;

				uint64_t resolved_target = 0;
				if (ins.len > 0 && ins.len <= avail && detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved_target)) {
					if (resolved_target == target_addr) {
						xref_t xref;
						xref.from_addr = ins_addr;
						xref.to_addr = target_addr;
						xref.type = detail::classify_instruction(ins);
						char full_text[256];
						snprintf(full_text, sizeof(full_text), "%s %s", ins.mnem, ins.ops);
						xref.disasm_text = full_text;
						xref.module_name = module_name;
						std::lock_guard<std::mutex> lk(g_state.mutex);
						g_state.results.push_back(std::move(xref));
					}
				}

				pos += ins_len;
			}

			scanned += chunk;
			g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total));
		}

	};
	if (search_size <= 0x100000) {
		worker();
		return true;
	}
	if (!critical_work_queue::post(worker) && !work_queue::post(worker)) {
		g_state.scanning.store(false, std::memory_order_release);
		return false;
	}
	return true;
}

inline void find_xrefs_from(uint64_t source_addr, size_t max_instructions, std::vector<xref_t>& out)
{
	out.clear();

	size_t read_size = max_instructions * 15;
	if (read_size > 0x100000) read_size = 0x100000;

	std::vector<uint8_t> mem;
	if (!driver_bridge::read_memory(source_addr, read_size, mem) || mem.empty())
		return;

	std::string module_name;
	auto modules = driver_bridge::enumerate_modules();

	const uint8_t* data = mem.data();
	int sz = static_cast<int>(mem.size());
	int pos = 0;
	size_t count = 0;

	while (pos < sz && count < max_instructions) {
		int avail = sz - pos;
		if (avail > 15) avail = 15;

		uint64_t ins_addr = source_addr + pos;
		AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);
		const int ins_len = (ins.len > 0 && ins.len <= avail) ? ins.len : 1;

		uint64_t resolved_target = 0;
		if (ins.len > 0 && ins.len <= avail && detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved_target)) {
			xref_t xref;
			xref.from_addr = ins_addr;
			xref.to_addr = resolved_target;
			xref.type = detail::classify_instruction(ins);
			char full_text[256];
			snprintf(full_text, sizeof(full_text), "%s %s", ins.mnem, ins.ops);
			xref.disasm_text = full_text;

			for (auto& m : modules) {
				if (resolved_target >= m.base && resolved_target < m.base + m.size) {
					xref.module_name = m.name;
					break;
				}
			}

			out.push_back(std::move(xref));
		}

		if (ins.is_ret)
			break;

		pos += ins_len;
		++count;
	}
}

inline void cancel_scan()
{
	g_state.cancel.store(true);
}

inline bool is_scanning()
{
	return g_state.scanning.load();
}

inline bool find_xrefs_to(uint64_t target_addr)
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (target_addr >= m.base && target_addr < m.base + m.size) {
			return find_xrefs_to(target_addr, m.base, m.size);
		}
	}
	if (!modules.empty()) {
		return find_xrefs_to(target_addr, modules[0].base, modules[0].size);
	}
	return false;
}

}
