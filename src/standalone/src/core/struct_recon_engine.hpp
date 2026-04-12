#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "standalone_driver.hpp"
#include "debugger_engine.hpp"
#include "page_guard_engine.hpp"
#include "zydis_disasm.hpp"
#include "imgui/imgui.h"

#ifdef AIDA_STANDALONE
#include <Zydis/Zydis.h>
#endif

namespace struct_recon {

enum class field_type_t : int {
	unknown = 0,
	int8,
	uint8,
	int16,
	uint16,
	int32,
	uint32,
	int64,
	uint64,
	float32,
	float64,
	pointer,
	vtable_ptr,
	c_string,
	wide_string,
	padding,
	nested_struct,
	array,
	COUNT
};

struct access_record_t {
	uint64_t    instruction_addr = 0;
	uint64_t    access_offset = 0;
	int         access_size = 0;
	bool        is_write = false;
	std::string disasm_text;
	int         hit_count = 0;
};

struct vtable_entry_t {
	uint64_t    func_addr = 0;
	int         index = 0;
	std::string name;
};

struct struct_field_t {
	uint64_t    offset = 0;
	int         size = 0;
	field_type_t type = field_type_t::unknown;
	std::string name;
	std::string comment;
	std::vector<access_record_t> accesses;

	std::vector<vtable_entry_t> vtable_entries;
};

struct reconstructed_struct_t {
	std::string name;
	uint64_t    base_address = 0;
	int         total_size = 0;
	std::vector<struct_field_t> fields;
	bool        has_vtable = false;
	uint64_t    vtable_address = 0;
};

struct monitor_config_t {
	uint64_t base_address = 0;
	int      monitor_size = 256;
	bool     use_hwbp = true;
	int      sample_count = 100;
};

struct state_t {
	reconstructed_struct_t current;
	std::vector<access_record_t> access_log;
	std::mutex  mutex;
	std::atomic<bool> monitoring{false};
	std::atomic<bool> cancel{false};
	std::atomic<float> progress{0.f};
	monitor_config_t config;
	char address_input[32] = {};
	char name_input[64] = {};
	char size_input[16] = "256";
	bool active = false;
	std::vector<reconstructed_struct_t> history;
};

inline state_t g_state;

inline const char* field_type_name(field_type_t t)
{
	switch (t) {
	case field_type_t::int8:          return "int8_t";
	case field_type_t::uint8:         return "uint8_t";
	case field_type_t::int16:         return "int16_t";
	case field_type_t::uint16:        return "uint16_t";
	case field_type_t::int32:         return "int32_t";
	case field_type_t::uint32:        return "uint32_t";
	case field_type_t::int64:         return "int64_t";
	case field_type_t::uint64:        return "uint64_t";
	case field_type_t::float32:       return "float";
	case field_type_t::float64:       return "double";
	case field_type_t::pointer:       return "void*";
	case field_type_t::vtable_ptr:    return "vtable*";
	case field_type_t::c_string:      return "char*";
	case field_type_t::wide_string:   return "wchar_t*";
	case field_type_t::padding:       return "pad";
	case field_type_t::nested_struct: return "struct";
	case field_type_t::array:         return "array";
	default: return "unk";
	}
}

inline ImU32 field_type_color(field_type_t t, float alpha)
{
	int a = static_cast<int>(alpha * 255);
	switch (t) {
	case field_type_t::int8:
	case field_type_t::int16:
	case field_type_t::int32:
	case field_type_t::int64:        return IM_COL32(86, 182, 194, a);
	case field_type_t::uint8:
	case field_type_t::uint16:
	case field_type_t::uint32:
	case field_type_t::uint64:       return IM_COL32(209, 154, 102, a);
	case field_type_t::float32:
	case field_type_t::float64:      return IM_COL32(229, 192, 123, a);
	case field_type_t::pointer:      return IM_COL32(152, 195, 121, a);
	case field_type_t::vtable_ptr:   return IM_COL32(224, 108, 117, a);
	case field_type_t::c_string:
	case field_type_t::wide_string:  return IM_COL32(152, 195, 121, a);
	case field_type_t::padding:      return IM_COL32(100, 100, 100, a);
	default: return IM_COL32(171, 178, 191, a);
	}
}

namespace detail {

inline field_type_t infer_type_from_value(const uint8_t* data, int size, uint64_t base_addr)
{
	if (size == 8) {
		uint64_t val;
		std::memcpy(&val, data, 8);

		if (val == 0) return field_type_t::uint64;

		if (val > 0x10000 && val < 0x00007FFFFFFFFFFF) {
			std::vector<uint8_t> test;
			driver_bridge::read_memory(val, 8, test);
			if (test.size() == 8) {
				uint64_t first_entry;
				std::memcpy(&first_entry, test.data(), 8);
				if (first_entry > 0x10000 && first_entry < 0x00007FFFFFFFFFFF) {
					return field_type_t::vtable_ptr;
				}
				return field_type_t::pointer;
			}
		}

		float f;
		std::memcpy(&f, data, 4);
		if (f > -1e10f && f < 1e10f && f != 0.f) {
			double d;
			std::memcpy(&d, data, 8);
			if (d > -1e20 && d < 1e20 && d != 0.0) {
				return field_type_t::float64;
			}
		}

		return field_type_t::uint64;
	}

	if (size == 4) {
		uint32_t val;
		std::memcpy(&val, data, 4);

		float f;
		std::memcpy(&f, data, 4);
		if (f > -1e6f && f < 1e6f && f != 0.f &&
		    val > 0x00800000 && val < 0x7F800000) {
			return field_type_t::float32;
		}

		int32_t ival;
		std::memcpy(&ival, data, 4);
		if (ival < 0) return field_type_t::int32;
		return field_type_t::uint32;
	}

	if (size == 2) {
		int16_t val;
		std::memcpy(&val, data, 2);
		if (val < 0) return field_type_t::int16;
		return field_type_t::uint16;
	}

	if (size == 1) {
		int8_t val;
		std::memcpy(&val, data, 1);
		if (val < 0) return field_type_t::int8;
		return field_type_t::uint8;
	}

	return field_type_t::unknown;
}

inline void detect_vtable(uint64_t base_addr, int struct_size,
                           std::vector<struct_field_t>& fields)
{
	std::vector<uint8_t> data;
	driver_bridge::read_memory(base_addr, 8, data);
	if (data.size() < 8) return;

	uint64_t potential_vtable;
	std::memcpy(&potential_vtable, data.data(), 8);

	if (potential_vtable < 0x10000 || potential_vtable > 0x00007FFFFFFFFFFF)
		return;

	std::vector<uint8_t> vtable_data;
	driver_bridge::read_memory(potential_vtable, 256, vtable_data);
	if (vtable_data.size() < 16) return;

	std::vector<vtable_entry_t> entries;
	for (size_t i = 0; i + 8 <= vtable_data.size(); i += 8) {
		uint64_t func_addr;
		std::memcpy(&func_addr, vtable_data.data() + i, 8);

		if (func_addr < 0x10000 || func_addr > 0x00007FFFFFFFFFFF)
			break;

		std::vector<uint8_t> func_bytes;
		driver_bridge::read_memory(func_addr, 4, func_bytes);
		if (func_bytes.size() < 4) break;

		vtable_entry_t entry;
		entry.func_addr = func_addr;
		entry.index = static_cast<int>(i / 8);
		char buf[32];
		std::snprintf(buf, sizeof(buf), "vfunc_%d", entry.index);
		entry.name = buf;
		entries.push_back(entry);
	}

	if (entries.size() >= 2) {
		for (auto& f : fields) {
			if (f.offset == 0 && f.size == 8) {
				f.type = field_type_t::vtable_ptr;
				f.name = "__vtable";
				f.vtable_entries = std::move(entries);
				return;
			}
		}

		struct_field_t vf;
		vf.offset = 0;
		vf.size = 8;
		vf.type = field_type_t::vtable_ptr;
		vf.name = "__vtable";
		vf.vtable_entries = std::move(entries);
		fields.insert(fields.begin(), vf);
	}
}

}

inline void reconstruct_from_snapshot(uint64_t base_address, int struct_size, const std::string& name)
{
	if (g_state.monitoring.load()) return;
	g_state.monitoring.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);

	std::thread([base_address, struct_size, name]() {
		reconstructed_struct_t result;
		result.base_address = base_address;
		result.total_size = struct_size;
		result.name = name.empty() ? "struct_t" : name;

		std::vector<uint8_t> data;
		driver_bridge::read_memory(base_address, static_cast<size_t>(struct_size), data);
		if (data.empty()) {
			g_state.monitoring.store(false);
			return;
		}

		std::map<uint64_t, struct_field_t> field_map;

		int offset = 0;
		while (offset < struct_size && offset < static_cast<int>(data.size())) {
			int remaining = struct_size - offset;
			int field_size = 0;

			if (remaining >= 8 && (offset % 8 == 0)) {
				field_size = 8;
			} else if (remaining >= 4 && (offset % 4 == 0)) {
				field_size = 4;
			} else if (remaining >= 2 && (offset % 2 == 0)) {
				field_size = 2;
			} else {
				field_size = 1;
			}

			struct_field_t field;
			field.offset = static_cast<uint64_t>(offset);
			field.size = field_size;
			field.type = detail::infer_type_from_value(data.data() + offset, field_size, base_address);

			char fname[32];
			std::snprintf(fname, sizeof(fname), "field_%03X", offset);
			field.name = fname;

			field_map[static_cast<uint64_t>(offset)] = field;
			offset += field_size;

			g_state.progress.store(static_cast<float>(offset) / static_cast<float>(struct_size) * 0.5f);
		}

		g_state.progress.store(0.6f);

		detail::detect_vtable(base_address, struct_size, result.fields);

		g_state.progress.store(0.8f);

		for (auto& [off, field] : field_map) {
			bool already_has = false;
			for (auto& f : result.fields) {
				if (f.offset == off) { already_has = true; break; }
			}
			if (!already_has) {
				result.fields.push_back(field);
			}
		}

		std::sort(result.fields.begin(), result.fields.end(),
			[](const struct_field_t& a, const struct_field_t& b) {
				return a.offset < b.offset;
			});

		result.has_vtable = !result.fields.empty() && result.fields[0].type == field_type_t::vtable_ptr;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = std::move(result);
			g_state.active = true;
		}

		g_state.progress.store(1.f);
		g_state.monitoring.store(false);
	}).detach();
}

namespace insn_analysis {

inline field_type_t infer_type_from_instruction(const AsmInstr& ins_data, int operand_size)
{
	std::string mnem_str(ins_data.mnem);
	for (auto& c : mnem_str) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

	if (mnem_str == "movss" || mnem_str == "addss" || mnem_str == "subss" ||
	    mnem_str == "mulss" || mnem_str == "divss" || mnem_str == "comiss" ||
	    mnem_str == "ucomiss" || mnem_str == "minss" || mnem_str == "maxss" ||
	    mnem_str == "sqrtss" || mnem_str == "cvtss2sd" || mnem_str == "cvtsi2ss") {
		return field_type_t::float32;
	}

	if (mnem_str == "movsd" || mnem_str == "addsd" || mnem_str == "subsd" ||
	    mnem_str == "mulsd" || mnem_str == "divsd" || mnem_str == "comisd" ||
	    mnem_str == "ucomisd" || mnem_str == "minsd" || mnem_str == "maxsd" ||
	    mnem_str == "sqrtsd" || mnem_str == "cvtsd2ss" || mnem_str == "cvtsi2sd") {
		return field_type_t::float64;
	}

	if (mnem_str == "movaps" || mnem_str == "movups" || mnem_str == "movdqa" ||
	    mnem_str == "movdqu" || mnem_str == "addps" || mnem_str == "subps" ||
	    mnem_str == "mulps" || mnem_str == "divps") {
		return field_type_t::float32;
	}

	std::string ops_str(ins_data.ops);
	for (auto& c : ops_str) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

	if (mnem_str == "lea") {
		return field_type_t::pointer;
	}

	if (mnem_str == "test" || mnem_str == "bt" || mnem_str == "bts" || mnem_str == "btr") {
		if (operand_size == 1) return field_type_t::uint8;
	}

	if (mnem_str == "movzx") {
		if (ops_str.find("byte") != std::string::npos) return field_type_t::uint8;
		if (ops_str.find("word") != std::string::npos) return field_type_t::uint16;
	}

	if (mnem_str == "movsx" || mnem_str == "movsxd") {
		if (ops_str.find("byte") != std::string::npos) return field_type_t::int8;
		if (ops_str.find("word") != std::string::npos) return field_type_t::int16;
		if (ops_str.find("dword") != std::string::npos) return field_type_t::int32;
	}

	if (mnem_str == "cmp" || mnem_str == "sub" || mnem_str == "add" || mnem_str == "imul" || mnem_str == "idiv") {
		if (operand_size == 1) return field_type_t::int8;
		if (operand_size == 2) return field_type_t::int16;
		if (operand_size == 4) return field_type_t::int32;
		if (operand_size == 8) return field_type_t::int64;
	}

	if (operand_size == 1) return field_type_t::uint8;
	if (operand_size == 2) return field_type_t::uint16;
	if (operand_size == 4) return field_type_t::uint32;
	if (operand_size == 8) return field_type_t::uint64;

	return field_type_t::unknown;
}

struct decoded_access_t {
	uint64_t rip = 0;
	uint64_t access_addr = 0;
	int      access_size = 0;
	bool     is_write = false;
	field_type_t inferred_type = field_type_t::unknown;
	std::string  disasm;
};

inline decoded_access_t analyze_captured_rip(uint64_t rip, uint64_t fault_addr, uint32_t access_type)
{
	decoded_access_t result;
	result.rip = rip;
	result.access_addr = fault_addr;
	result.is_write = (access_type == 1);

	std::vector<uint8_t> code;
	driver_bridge::read_memory(rip, 16, code);
	if (code.empty()) {
		result.access_size = 8;
		char buf[64];
		std::snprintf(buf, sizeof(buf), "??? [0x%llX]", static_cast<unsigned long long>(rip));
		result.disasm = buf;
		return result;
	}

	AsmInstr ins = zydis_decode_one(code.data(), static_cast<int>(code.size()), rip);

	char disasm_buf[192];
	std::snprintf(disasm_buf, sizeof(disasm_buf), "%s %s", ins.mnem, ins.ops);
	result.disasm = disasm_buf;

	std::string ops_lower(ins.ops);
	for (auto& c : ops_lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

	if (ops_lower.find("byte") != std::string::npos) result.access_size = 1;
	else if (ops_lower.find("word") != std::string::npos && ops_lower.find("dword") == std::string::npos &&
	         ops_lower.find("qword") == std::string::npos) result.access_size = 2;
	else if (ops_lower.find("dword") != std::string::npos) result.access_size = 4;
	else if (ops_lower.find("qword") != std::string::npos) result.access_size = 8;
	else if (ops_lower.find("xmmword") != std::string::npos || ops_lower.find("xmm") != std::string::npos)
		result.access_size = 4;
	else result.access_size = 8;

	result.inferred_type = infer_type_from_instruction(ins, result.access_size);

	return result;
}

}

inline void monitor_with_hwbp(uint64_t base_address, int struct_size, const std::string& name)
{
	if (g_state.monitoring.load()) return;
	g_state.monitoring.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);

	std::thread([base_address, struct_size, name]() {
		reconstructed_struct_t result;
		result.base_address = base_address;
		result.total_size = struct_size;
		result.name = name.empty() ? "struct_t" : name;

		std::vector<uint8_t> data;
		driver_bridge::read_memory(base_address, static_cast<size_t>(struct_size), data);
		if (data.empty()) {
			g_state.monitoring.store(false);
			return;
		}

		std::map<uint64_t, struct_field_t> field_map;
		int offset = 0;
		while (offset < struct_size && offset < static_cast<int>(data.size())) {
			int remaining = struct_size - offset;
			int field_size = 0;
			if (remaining >= 8 && (offset % 8 == 0)) field_size = 8;
			else if (remaining >= 4 && (offset % 4 == 0)) field_size = 4;
			else if (remaining >= 2 && (offset % 2 == 0)) field_size = 2;
			else field_size = 1;

			struct_field_t field;
			field.offset = static_cast<uint64_t>(offset);
			field.size = field_size;
			field.type = detail::infer_type_from_value(data.data() + offset, field_size, base_address);
			char fname[32];
			std::snprintf(fname, sizeof(fname), "field_%03X", offset);
			field.name = fname;
			field_map[static_cast<uint64_t>(offset)] = field;
			offset += field_size;
			g_state.progress.store(static_cast<float>(offset) / static_cast<float>(struct_size) * 0.2f);
		}

		detail::detect_vtable(base_address, struct_size, result.fields);

		for (auto& [off, field] : field_map) {
			bool already_has = false;
			for (auto& f : result.fields) {
				if (f.offset == off) { already_has = true; break; }
			}
			if (!already_has) result.fields.push_back(field);
		}
		std::sort(result.fields.begin(), result.fields.end(),
			[](const struct_field_t& a, const struct_field_t& b) { return a.offset < b.offset; });
		result.has_vtable = !result.fields.empty() && result.fields[0].type == field_type_t::vtable_ptr;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = result;
			g_state.active = true;
		}
		g_state.progress.store(0.25f);

		uint32_t pid = driver_bridge::attached_pid();

		bool use_page_guard = driver_bridge::using_kernel_driver() && pid != 0;
		uint32_t pg_session_id = 0;

		std::vector<uint32_t> tids;
		bool use_hwbp_fallback = false;

		if (use_page_guard) {
			uint64_t page_base = base_address & ~0xFFFULL;
			uint64_t page_end = (base_address + static_cast<uint64_t>(struct_size) + 0xFFF) & ~0xFFFULL;
			uint64_t region_size = page_end - page_base;

			pg_session_id = page_guard_engine::g_pg_engine.install(pid, page_base, region_size);
			if (pg_session_id == 0) {
				use_page_guard = false;
				use_hwbp_fallback = true;
			}
		} else {
			use_hwbp_fallback = true;
		}

		if (use_hwbp_fallback) {
			auto threads = driver_bridge::enumerate_threads();
			for (auto& t : threads) tids.push_back(t.tid);

			int hwbp_offsets[] = {0, 8, 16, 32};
			int num_slots = (std::min)(4, static_cast<int>(std::size(hwbp_offsets)));
			if (!tids.empty()) {
				for (int i = 0; i < num_slots; ++i) {
					if (g_state.cancel.load()) break;
					if (hwbp_offsets[i] >= struct_size) continue;
					uint64_t watch_addr = base_address + static_cast<uint64_t>(hwbp_offsets[i]);
					driver_bridge::set_hardware_breakpoint(tids[0], i, watch_addr, 1, 3);
				}
			}
		}

		g_state.progress.store(0.3f);

		std::map<uint64_t, insn_analysis::decoded_access_t> rip_cache;
		std::map<uint64_t, access_record_t> offset_access_map;
		int sample_count = g_state.config.sample_count;

		for (int sample = 0; sample < sample_count && !g_state.cancel.load(); ++sample) {
			std::this_thread::sleep_for(std::chrono::milliseconds(50));

			float phase_progress = 0.3f + 0.5f * (static_cast<float>(sample) / static_cast<float>(sample_count));
			g_state.progress.store(phase_progress);

			if (use_page_guard && pg_session_id != 0) {
				auto captures = page_guard_engine::g_pg_engine.get_captures(pg_session_id);
				for (auto& cap : captures) {
					if (cap.fault_addr < base_address ||
					    cap.fault_addr >= base_address + static_cast<uint64_t>(struct_size))
						continue;

					auto rip_it = rip_cache.find(cap.rip);
					if (rip_it == rip_cache.end()) {
						auto decoded = insn_analysis::analyze_captured_rip(cap.rip, cap.fault_addr, cap.access_type);
						rip_cache[cap.rip] = decoded;
						rip_it = rip_cache.find(cap.rip);
					}

					auto& decoded = rip_it->second;
					uint64_t field_offset = cap.fault_addr - base_address;

					auto oa_it = offset_access_map.find(field_offset);
					if (oa_it == offset_access_map.end()) {
						access_record_t rec;
						rec.instruction_addr = cap.rip;
						rec.access_offset = field_offset;
						rec.access_size = decoded.access_size;
						rec.is_write = decoded.is_write;
						rec.disasm_text = decoded.disasm;
						rec.hit_count = 1;
						offset_access_map[field_offset] = rec;
					} else {
						oa_it->second.hit_count++;
					}
				}
			}
		}

		g_state.progress.store(0.8f);

		if (use_page_guard && pg_session_id != 0) {
			auto final_caps = page_guard_engine::g_pg_engine.get_captures(pg_session_id);
			for (auto& cap : final_caps) {
				if (cap.fault_addr < base_address ||
				    cap.fault_addr >= base_address + static_cast<uint64_t>(struct_size))
					continue;

				auto rip_it = rip_cache.find(cap.rip);
				if (rip_it == rip_cache.end()) {
					auto decoded = insn_analysis::analyze_captured_rip(cap.rip, cap.fault_addr, cap.access_type);
					rip_cache[cap.rip] = decoded;
					rip_it = rip_cache.find(cap.rip);
				}

				auto& decoded = rip_it->second;
				uint64_t field_offset = cap.fault_addr - base_address;

				auto oa_it = offset_access_map.find(field_offset);
				if (oa_it == offset_access_map.end()) {
					access_record_t rec;
					rec.instruction_addr = cap.rip;
					rec.access_offset = field_offset;
					rec.access_size = decoded.access_size;
					rec.is_write = decoded.is_write;
					rec.disasm_text = decoded.disasm;
					rec.hit_count = 1;
					offset_access_map[field_offset] = rec;
				} else {
					oa_it->second.hit_count++;
				}
			}
			page_guard_engine::g_pg_engine.uninstall(pg_session_id);
		}

		if (use_hwbp_fallback && !tids.empty()) {
			for (int i = 0; i < 4; ++i) {
				driver_bridge::clear_hardware_breakpoint(tids[0], i);
			}
		}

		g_state.progress.store(0.85f);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.access_log.clear();

			for (auto& [off, access_rec] : offset_access_map) {
				g_state.access_log.push_back(access_rec);
			}

			for (auto& field : g_state.current.fields) {
				for (auto& [off, access_rec] : offset_access_map) {
					if (off >= field.offset &&
					    off < field.offset + static_cast<uint64_t>(field.size)) {

						field.accesses.push_back(access_rec);

						auto rip_it = rip_cache.find(access_rec.instruction_addr);
						if (rip_it != rip_cache.end()) {
							auto& decoded = rip_it->second;
							if (decoded.inferred_type != field_type_t::unknown) {
								if (field.type == field_type_t::uint64 ||
								    field.type == field_type_t::uint32 ||
								    field.type == field_type_t::unknown) {
									field.type = decoded.inferred_type;
									field.size = decoded.access_size;
								}
							}
						}
					}
				}
			}

			std::set<uint64_t> existing_offsets;
			for (auto& f : g_state.current.fields) {
				existing_offsets.insert(f.offset);
			}

			for (auto& [off, access_rec] : offset_access_map) {
				if (existing_offsets.count(off) == 0) {
					struct_field_t new_field;
					new_field.offset = off;
					new_field.size = access_rec.access_size;

					auto rip_it = rip_cache.find(access_rec.instruction_addr);
					if (rip_it != rip_cache.end() && rip_it->second.inferred_type != field_type_t::unknown) {
						new_field.type = rip_it->second.inferred_type;
					} else {
						new_field.type = field_type_t::unknown;
					}

					char fname[32];
					std::snprintf(fname, sizeof(fname), "field_%03llX", static_cast<unsigned long long>(off));
					new_field.name = fname;
					new_field.accesses.push_back(access_rec);

					g_state.current.fields.push_back(new_field);
					existing_offsets.insert(off);
				}
			}

			std::sort(g_state.current.fields.begin(), g_state.current.fields.end(),
				[](const struct_field_t& a, const struct_field_t& b) { return a.offset < b.offset; });

			g_state.current.has_vtable = !g_state.current.fields.empty() &&
			                              g_state.current.fields[0].type == field_type_t::vtable_ptr;

			g_state.history.push_back(g_state.current);
		}

		g_state.progress.store(1.f);
		g_state.monitoring.store(false);
	}).detach();
}

inline std::string export_as_cpp(const reconstructed_struct_t& s)
{
	std::string out;
	out += "struct " + s.name + " {\n";

	for (auto& f : s.fields) {
		char line[256];
		if (f.type == field_type_t::vtable_ptr) {
			std::snprintf(line, sizeof(line), "    void** %-20s // 0x%04llX vtable (%zu entries)\n",
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset),
			              f.vtable_entries.size());
		} else if (f.type == field_type_t::padding) {
			std::snprintf(line, sizeof(line), "    uint8_t %-20s // 0x%04llX padding\n",
			              (f.name + "[" + std::to_string(f.size) + "];").c_str(),
			              static_cast<unsigned long long>(f.offset));
		} else {
			std::snprintf(line, sizeof(line), "    %-10s %-20s // 0x%04llX\n",
			              field_type_name(f.type),
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset));
		}
		out += line;
	}

	char size_line[64];
	std::snprintf(size_line, sizeof(size_line), "}; // size: 0x%X (%d bytes)\n",
	              s.total_size, s.total_size);
	out += size_line;
	return out;
}

inline void cancel()
{
	g_state.cancel.store(true);
}

}
