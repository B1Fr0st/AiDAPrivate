#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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
	if (ins.is_call || ins.is_branch) {
		if (ins.len == 5 && (code[0] == 0xE8 || code[0] == 0xE9)) {
			int32_t rel = 0;
			std::memcpy(&rel, code + 1, 4);
			target = ins_addr + ins.len + rel;
			return true;
		}
		if (ins.len == 2 && (code[0] >= 0x70 && code[0] <= 0x7F)) {
			int8_t rel = static_cast<int8_t>(code[1]);
			target = ins_addr + ins.len + rel;
			return true;
		}
		if (ins.len == 6 && code[0] == 0x0F && (code[1] >= 0x80 && code[1] <= 0x8F)) {
			int32_t rel = 0;
			std::memcpy(&rel, code + 2, 4);
			target = ins_addr + ins.len + rel;
			return true;
		}
		if (ins.len == 2 && code[0] == 0xEB) {
			int8_t rel = static_cast<int8_t>(code[1]);
			target = ins_addr + ins.len + rel;
			return true;
		}
		if (ins.len >= 6 && code[0] == 0xFF) {
			uint8_t modrm = code[1];
			uint8_t mod = (modrm >> 6) & 3;
			uint8_t rm = modrm & 7;
			if (mod == 0 && rm == 5) {
				int32_t disp = 0;
				std::memcpy(&disp, code + 2, 4);
				target = ins_addr + ins.len + disp;
				return true;
			}
		}
	}

	if (std::strncmp(ins.mnem, "lea", 3) == 0 || std::strncmp(ins.mnem, "LEA", 3) == 0) {
		if (ins.len >= 7) {
			uint8_t rex = code[0];
			int off = 0;
			if ((rex & 0xF0) == 0x40) off = 1;
			if (off < ins.len && code[off] == 0x8D) {
				uint8_t modrm = code[off + 1];
				uint8_t mod = (modrm >> 6) & 3;
				uint8_t rm = modrm & 7;
				if (rm == 5 || (rm == 4 && (code[off + 2] & 7) == 5)) {
					int disp_off = off + 2;
					if (rm == 4) disp_off = off + 3;
					if (mod == 0) {
						int32_t disp = 0;
						std::memcpy(&disp, code + disp_off, 4);
						target = ins_addr + ins.len + disp;
						return true;
					}
				}
			}
		}
	}

	if (ins.len >= 6) {
		bool has_rex = (code[0] & 0xF0) == 0x40;
		int base = has_rex ? 1 : 0;
		uint8_t opcode = code[base];
		bool is_mov_load = (opcode == 0x8B) || (opcode == 0xA1) || (opcode == 0x3B) || (opcode == 0x39);
		if (is_mov_load && base + 1 < ins.len) {
			uint8_t modrm = code[base + 1];
			uint8_t mod = (modrm >> 6) & 3;
			uint8_t rm = modrm & 7;
			if (mod == 0 && rm == 5) {
				int32_t disp = 0;
				int disp_off = base + 2;
				if (rm == 4) disp_off = base + 3;
				if (disp_off + 4 <= ins.len) {
					std::memcpy(&disp, code + disp_off, 4);
					target = ins_addr + ins.len + disp;
					return true;
				}
			}
		}
	}

	return false;
}

}

inline void find_xrefs_to(uint64_t target_addr, uint64_t search_start, uint64_t search_size)
{
	if (g_state.scanning.load())
		return;

	g_state.scanning.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);
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

	std::thread([target_addr, search_start, search_size, module_name]() {
		const size_t page_size = 4096;
		uint64_t total = search_size;
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

				uint64_t resolved_target = 0;
				if (detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved_target)) {
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

				pos += ins.len;
			}

			scanned += chunk;
			g_state.progress.store(static_cast<float>(scanned) / static_cast<float>(total));
		}

		g_state.scanning.store(false);
	}).detach();
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

		uint64_t resolved_target = 0;
		if (detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved_target)) {
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

		pos += ins.len;
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

inline void find_xrefs_to(uint64_t target_addr)
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (target_addr >= m.base && target_addr < m.base + m.size) {
			find_xrefs_to(target_addr, m.base, m.size);
			return;
		}
	}
	if (!modules.empty()) {
		find_xrefs_to(target_addr, modules[0].base, modules[0].size);
	}
}

}
