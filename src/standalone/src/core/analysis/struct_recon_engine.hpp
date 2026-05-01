#pragma once

#include <algorithm>
#include "work_queue.hpp"
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
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
#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "imgui/imgui.h"

#include <nlohmann/json.hpp>

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
	vec2,
	vec3,
	vec4,
	mat4x4,
	color_rgba,
	bitfield,
	utf8_string,
	utf16_string,
	bool8,
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

struct value_history_t {
	static constexpr int MAX_ENTRIES = 10;
	std::array<uint64_t, MAX_ENTRIES> values = {};
	int count = 0;
	int write_idx = 0;

	void push(uint64_t v) {
		values[static_cast<size_t>(write_idx)] = v;
		write_idx = (write_idx + 1) % MAX_ENTRIES;
		if (count < MAX_ENTRIES) count++;
	}

	int unique_count() const {
		std::set<uint64_t> s;
		for (int i = 0; i < count; ++i)
			s.insert(values[static_cast<size_t>(i)]);
		return static_cast<int>(s.size());
	}

	int heat_level() const {
		int u = unique_count();
		if (u <= 1) return 0;
		if (u == 2) return 1;
		if (u <= 4) return 2;
		return 3;
	}
};

enum class confidence_t : int {
	hidden = 0,
	weak,
	moderate,
	strong
};

struct type_candidate_t {
	field_type_t type = field_type_t::unknown;
	float        score = 0.f;
	confidence_t confidence = confidence_t::hidden;
};

struct struct_field_t {
	uint64_t    offset = 0;
	int         size = 0;
	field_type_t type = field_type_t::unknown;
	std::string name;
	std::string comment;
	std::vector<access_record_t> accesses;
	std::vector<vtable_entry_t> vtable_entries;
	value_history_t value_history;
	float        type_confidence = 0.f;
	int          array_count = 1;
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
	std::atomic<bool> ai_naming{false};
	std::vector<reconstructed_struct_t> saved_structs;
	bool disk_cache_loaded = false;
};

inline state_t g_state;

inline bool is_valid_utf16_at(uint64_t addr, int& out_len);
inline void detect_arrays(std::vector<struct_field_t>& fields);

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
	case field_type_t::vec2:          return "vec2";
	case field_type_t::vec3:          return "vec3";
	case field_type_t::vec4:          return "vec4";
	case field_type_t::mat4x4:        return "mat4x4";
	case field_type_t::color_rgba:    return "color";
	case field_type_t::bitfield:      return "bitfield";
	case field_type_t::utf8_string:   return "utf8*";
	case field_type_t::utf16_string:  return "utf16*";
	case field_type_t::bool8:         return "bool";
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
	case field_type_t::vec2:
	case field_type_t::vec3:
	case field_type_t::vec4:         return IM_COL32(255, 165, 0, a);
	case field_type_t::mat4x4:       return IM_COL32(255, 140, 50, a);
	case field_type_t::color_rgba:   return IM_COL32(255, 105, 180, a);
	case field_type_t::bitfield:     return IM_COL32(198, 120, 221, a);
	case field_type_t::utf8_string:  return IM_COL32(126, 211, 33, a);
	case field_type_t::utf16_string: return IM_COL32(126, 211, 33, a);
	case field_type_t::bool8:        return IM_COL32(198, 120, 221, a);
	default: return IM_COL32(171, 178, 191, a);
	}
}

namespace detail {

inline float score_pointer64(const uint8_t* data)
{
	uint64_t val;
	std::memcpy(&val, data, 8);

	if (val == 0) return 0.f;
	if (val == 0xFFFFFFFFFFFFFFFFULL) return 0.f;

	uint64_t top16 = val >> 48;
	if (top16 != 0x0000 && top16 != 0x7FFF && top16 != 0xFFFF)
		return 0.f;

	int features_passed = 0;
	int features_total = 5;

	if ((val & 7) == 0) features_passed++;
	if (val >= 0x10000) features_passed++;
	if ((val >> 32) != 0) features_passed++;
	if (val < 0x0000800000000000ULL) features_passed++;

	std::vector<uint8_t> test;
	driver_bridge::read_memory(val, 8, test);
	if (test.size() == 8) features_passed++;

	return static_cast<float>(features_passed) / static_cast<float>(features_total) * 100.f;
}

inline float score_vtable_ptr(const uint8_t* data, uint64_t base_addr)
{
	uint64_t val;
	std::memcpy(&val, data, 8);

	float ptr_score = score_pointer64(data);
	if (ptr_score < 50.f) return 0.f;

	std::vector<uint8_t> vtable_data;
	driver_bridge::read_memory(val, 32, vtable_data);
	if (vtable_data.size() < 16) return 0.f;

	int valid_funcs = 0;
	for (size_t i = 0; i + 8 <= vtable_data.size(); i += 8) {
		uint64_t func;
		std::memcpy(&func, vtable_data.data() + i, 8);
		if (func < 0x10000 || func > 0x0000800000000000ULL) break;
		std::vector<uint8_t> fb;
		driver_bridge::read_memory(func, 4, fb);
		if (fb.size() < 4) break;
		valid_funcs++;
	}

	if (valid_funcs < 2) return 0.f;
	float score = 60.f + static_cast<float>((std::min)(valid_funcs, 10)) * 4.f;
	return (std::min)(score, 100.f);
}

inline float score_float32(const uint8_t* data)
{
	float val;
	std::memcpy(&val, data, 4);

	if (std::isinf(val) || std::isnan(val)) return 0.f;

	uint32_t raw;
	std::memcpy(&raw, data, 4);
	uint32_t exponent = (raw >> 23) & 0xFF;
	if (exponent == 0 && (raw & 0x007FFFFF) != 0) return 0.f;

	int features_passed = 0;
	int features_total = 4;

	float abs_val = std::fabs(val);
	if (abs_val > 1e-6f && abs_val < 1e7f) features_passed++;

	uint32_t mantissa = raw & 0x007FFFFF;
	if (mantissa != 0) features_passed++;

	if (exponent >= 0x60 && exponent <= 0x9F) features_passed++;

	if (raw > 0x00800000 && raw < 0x7F800000) features_passed++;

	return static_cast<float>(features_passed) / static_cast<float>(features_total) * 100.f;
}

inline float score_float64(const uint8_t* data)
{
	double val;
	std::memcpy(&val, data, 8);

	if (std::isinf(val) || std::isnan(val)) return 0.f;

	uint64_t raw;
	std::memcpy(&raw, data, 8);
	uint64_t exponent = (raw >> 52) & 0x7FF;
	if (exponent == 0 && (raw & 0x000FFFFFFFFFFFFFULL) != 0) return 0.f;

	double abs_val = std::fabs(val);
	int features_passed = 0;
	int features_total = 3;

	if (abs_val > 1e-15 && abs_val < 1e15) features_passed++;
	if ((raw & 0x000FFFFFFFFFFFFFULL) != 0) features_passed++;
	if (exponent >= 0x380 && exponent <= 0x440) features_passed++;

	return static_cast<float>(features_passed) / static_cast<float>(features_total) * 100.f;
}

inline float score_string_ptr(const uint8_t* data)
{
	uint64_t val;
	std::memcpy(&val, data, 8);

	if (val < 0x10000 || val > 0x0000800000000000ULL) return 0.f;

	std::vector<uint8_t> str_data;
	driver_bridge::read_memory(val, 256, str_data);
	if (str_data.size() < 4) return 0.f;

	int printable = 0;
	int total = 0;
	int letters = 0;
	for (size_t i = 0; i < str_data.size(); ++i) {
		uint8_t c = str_data[i];
		if (c == 0) break;
		total++;
		if (c >= 0x20 && c < 0x7F) printable++;
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) letters++;
	}

	if (total < 4) return 0.f;

	float ratio = static_cast<float>(printable) / static_cast<float>(total);
	if (ratio < 0.75f || letters == 0) return 0.f;

	float score = ratio * 80.f;
	if (ratio > 0.9f) score += 10.f;
	if (total >= 8) score += 10.f;
	return (std::min)(score, 100.f);
}

inline float score_bool8(const uint8_t* data)
{
	uint8_t val = data[0];
	if (val == 0 || val == 1) return 85.f;
	return 0.f;
}

inline type_candidate_t infer_type_scored(const uint8_t* data, int size, uint64_t base_addr)
{
	type_candidate_t best;
	best.type = field_type_t::unknown;
	best.score = 0.f;
	best.confidence = confidence_t::hidden;

	auto try_candidate = [&](field_type_t t, float s) {
		if (s > best.score) {
			best.type = t;
			best.score = s;
		}
	};

	if (size == 8) {
		uint64_t val;
		std::memcpy(&val, data, 8);

		if (val == 0) {
			best.type = field_type_t::uint64;
			best.score = 30.f;
			best.confidence = confidence_t::weak;
			return best;
		}

		float vtable_s = score_vtable_ptr(data, base_addr);
		try_candidate(field_type_t::vtable_ptr, vtable_s);

		float ptr_s = score_pointer64(data);
		try_candidate(field_type_t::pointer, ptr_s);

		if (ptr_s >= 50.f) {
			float str_s = score_string_ptr(data);
			if (str_s > ptr_s) {
				int str_len = 0;
				if (is_valid_utf16_at(val, str_len) && str_len >= 4)
					try_candidate(field_type_t::utf16_string, str_s + 5.f);
				else
					try_candidate(field_type_t::utf8_string, str_s);
			}
		}

		float f64_s = score_float64(data);
		try_candidate(field_type_t::float64, f64_s);

		if (best.score < 50.f) {
			int64_t ival;
			std::memcpy(&ival, data, 8);
			if (ival < 0) {
				best.type = field_type_t::int64;
				best.score = 40.f;
			} else {
				best.type = field_type_t::uint64;
				best.score = 30.f;
			}
		}
	}
	else if (size == 4) {
		float f32_s = score_float32(data);
		try_candidate(field_type_t::float32, f32_s);

		uint32_t uval;
		std::memcpy(&uval, data, 4);

		int32_t ival;
		std::memcpy(&ival, data, 4);

		if (f32_s < 50.f) {
			if (ival < 0)
				try_candidate(field_type_t::int32, 40.f);
			else
				try_candidate(field_type_t::uint32, 30.f);
		}
	}
	else if (size == 2) {
		int16_t val;
		std::memcpy(&val, data, 2);
		if (val < 0) {
			best.type = field_type_t::int16;
			best.score = 40.f;
		} else {
			best.type = field_type_t::uint16;
			best.score = 30.f;
		}
	}
	else if (size == 1) {
		float bool_s = score_bool8(data);
		if (bool_s > 50.f) {
			best.type = field_type_t::bool8;
			best.score = bool_s;
		} else {
			int8_t val;
			std::memcpy(&val, data, 1);
			if (val < 0) {
				best.type = field_type_t::int8;
				best.score = 40.f;
			} else {
				best.type = field_type_t::uint8;
				best.score = 30.f;
			}
		}
	}

	if (best.score >= 75.f) best.confidence = confidence_t::strong;
	else if (best.score >= 50.f) best.confidence = confidence_t::moderate;
	else if (best.score >= 25.f) best.confidence = confidence_t::weak;
	else best.confidence = confidence_t::hidden;

	return best;
}

inline field_type_t infer_type_from_value(const uint8_t* data, int size, uint64_t base_addr)
{
	return infer_type_scored(data, size, base_addr).type;
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

	auto modules = driver_bridge::enumerate_modules();

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

		bool resolved = false;
		for (auto& m : modules) {
			if (func_addr >= m.base && func_addr < m.base + m.size) {
				uint64_t rva = func_addr - m.base;
				std::string mod_name = m.name;
				size_t dot_pos = mod_name.rfind('.');
				if (dot_pos != std::string::npos)
					mod_name = mod_name.substr(0, dot_pos);

				std::vector<uint8_t> pe_header;
				driver_bridge::read_memory(m.base, 0x1000, pe_header);
				if (pe_header.size() >= 0x40) {
					uint32_t pe_off = 0;
					std::memcpy(&pe_off, pe_header.data() + 0x3C, 4);
					if (pe_off + 0x88 + 8 <= pe_header.size()) {
						uint32_t export_rva = 0, export_size = 0;
						std::memcpy(&export_rva, pe_header.data() + pe_off + 0x88, 4);
						std::memcpy(&export_size, pe_header.data() + pe_off + 0x8C, 4);

						if (export_rva != 0 && export_size != 0) {
							std::vector<uint8_t> export_dir;
							driver_bridge::read_memory(m.base + export_rva,
								(std::min)(export_size, 0x10000u), export_dir);

							if (export_dir.size() >= 40) {
								uint32_t num_funcs = 0, num_names = 0;
								uint32_t addr_table_rva = 0, name_table_rva = 0, ordinal_table_rva = 0;
								std::memcpy(&num_funcs, export_dir.data() + 20, 4);
								std::memcpy(&num_names, export_dir.data() + 24, 4);
								std::memcpy(&addr_table_rva, export_dir.data() + 28, 4);
								std::memcpy(&name_table_rva, export_dir.data() + 32, 4);
								std::memcpy(&ordinal_table_rva, export_dir.data() + 36, 4);

								for (uint32_t ni = 0; ni < num_names && ni < 4096; ++ni) {
									uint32_t name_rva_offset = name_table_rva + ni * 4;
									uint32_t ordinal_offset = ordinal_table_rva + ni * 2;

									if (name_rva_offset < export_rva || ordinal_offset < export_rva)
										continue;
									uint32_t local_name_off = name_rva_offset - export_rva;
									uint32_t local_ord_off = ordinal_offset - export_rva;

									if (local_name_off + 4 > export_dir.size() || local_ord_off + 2 > export_dir.size())
										continue;

									uint32_t name_rva_val = 0;
									std::memcpy(&name_rva_val, export_dir.data() + local_name_off, 4);

									uint16_t ordinal_val = 0;
									std::memcpy(&ordinal_val, export_dir.data() + local_ord_off, 2);

									if (ordinal_val >= num_funcs) continue;
									uint32_t func_rva_offset = addr_table_rva + ordinal_val * 4;
									if (func_rva_offset < export_rva) continue;
									uint32_t local_func_off = func_rva_offset - export_rva;
									if (local_func_off + 4 > export_dir.size()) continue;

									uint32_t func_rva_val = 0;
									std::memcpy(&func_rva_val, export_dir.data() + local_func_off, 4);

									if (static_cast<uint64_t>(func_rva_val) == rva) {
										if (name_rva_val >= export_rva &&
										    name_rva_val - export_rva + 1 <= static_cast<uint32_t>(export_dir.size())) {
											const char* fname = reinterpret_cast<const char*>(
												export_dir.data() + (name_rva_val - export_rva));
											size_t max_len = export_dir.size() - (name_rva_val - export_rva);
											size_t slen = strnlen(fname, max_len);
											entry.name = mod_name + "!" + std::string(fname, slen);
											resolved = true;
											break;
										}
									}
								}
							}
						}
					}
				}

				if (!resolved) {
					char buf[128];
					std::snprintf(buf, sizeof(buf), "%s+0x%llX", mod_name.c_str(),
					              static_cast<unsigned long long>(rva));
					entry.name = buf;
					resolved = true;
				}
				break;
			}
		}

		if (!resolved) {
			char buf[32];
			std::snprintf(buf, sizeof(buf), "vfunc_%d", entry.index);
			entry.name = buf;
		}

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

inline bool is_valid_utf8_at(uint64_t addr, int& out_len)
{
	std::vector<uint8_t> str_data;
	driver_bridge::read_memory(addr, 256, str_data);
	if (str_data.size() < 4) return false;

	int printable = 0;
	int total = 0;
	for (size_t i = 0; i < str_data.size(); ++i) {
		uint8_t c = str_data[i];
		if (c == 0) break;
		total++;
		if (c >= 0x20 && c < 0x7F) printable++;
	}
	out_len = total;
	return total >= 4 && printable > total / 2;
}

inline bool is_valid_utf16_at(uint64_t addr, int& out_len)
{
	std::vector<uint8_t> str_data;
	driver_bridge::read_memory(addr, 512, str_data);
	if (str_data.size() < 8) return false;

	int printable = 0;
	int total = 0;
	for (size_t i = 0; i + 2 <= str_data.size(); i += 2) {
		uint16_t c = 0;
		std::memcpy(&c, str_data.data() + i, 2);
		if (c == 0) break;
		total++;
		if (c >= 0x20 && c < 0x7F) printable++;
	}
	out_len = total;
	return total >= 4 && printable > total / 2;
}

namespace detail {

inline void merge_compound_types(std::vector<struct_field_t>& fields, uint64_t base_address)
{
	for (size_t i = 0; i < fields.size(); ++i) {
		if (fields[i].type == field_type_t::float32 && fields[i].size == 4) {
			int consecutive_floats = 1;
			size_t j = i + 1;
			while (j < fields.size() &&
			       fields[j].type == field_type_t::float32 &&
			       fields[j].size == 4 &&
			       fields[j].offset == fields[j - 1].offset + 4) {
				consecutive_floats++;
				j++;
			}

			if (consecutive_floats == 4) {
				std::vector<uint8_t> color_check;
				driver_bridge::read_memory(base_address + fields[i].offset, 16, color_check);
				bool looks_like_color = false;
				if (color_check.size() == 16) {
					float vals[4];
					std::memcpy(vals, color_check.data(), 16);
					looks_like_color = true;
					for (int k = 0; k < 4; ++k) {
						if (vals[k] < 0.f || vals[k] > 1.0001f) {
							looks_like_color = false;
							break;
						}
					}
				}

				if (looks_like_color) {
					fields[i].type = field_type_t::color_rgba;
					fields[i].size = 16;
				} else {
					fields[i].type = field_type_t::vec4;
					fields[i].size = 16;
				}
				if (fields[i].name.size() >= 6 && fields[i].name.compare(0, 6, "field_") == 0) {
					fields[i].name = "field_" + fields[i].name.substr(6);
				}
				fields.erase(fields.begin() + static_cast<ptrdiff_t>(i) + 1,
				             fields.begin() + static_cast<ptrdiff_t>(i) + 4);
			} else if (consecutive_floats == 3) {
				fields[i].type = field_type_t::vec3;
				fields[i].size = 12;
				if (fields[i].name.size() >= 6 && fields[i].name.compare(0, 6, "field_") == 0) {
					fields[i].name = "field_" + fields[i].name.substr(6);
				}
				fields.erase(fields.begin() + static_cast<ptrdiff_t>(i) + 1,
				             fields.begin() + static_cast<ptrdiff_t>(i) + 3);
			} else if (consecutive_floats == 2) {
				fields[i].type = field_type_t::vec2;
				fields[i].size = 8;
				if (fields[i].name.size() >= 6 && fields[i].name.compare(0, 6, "field_") == 0) {
					fields[i].name = "field_" + fields[i].name.substr(6);
				}
				fields.erase(fields.begin() + static_cast<ptrdiff_t>(i) + 1,
				             fields.begin() + static_cast<ptrdiff_t>(i) + 2);
			}
		}

		if ((fields[i].type == field_type_t::pointer || fields[i].type == field_type_t::uint64) &&
		    fields[i].size == 8) {
			uint64_t ptr_val = 0;
			std::vector<uint8_t> ptr_data;
			driver_bridge::read_memory(base_address + fields[i].offset, 8, ptr_data);
			if (ptr_data.size() == 8) {
				std::memcpy(&ptr_val, ptr_data.data(), 8);
				if (ptr_val > 0x10000 && ptr_val < 0x00007FFFFFFFFFFF) {
					int str_len = 0;
					if (is_valid_utf8_at(ptr_val, str_len)) {
						fields[i].type = field_type_t::utf8_string;
						char cmt[64];
						std::snprintf(cmt, sizeof(cmt), "len=%d", str_len);
						fields[i].comment = cmt;
					} else if (is_valid_utf16_at(ptr_val, str_len)) {
						fields[i].type = field_type_t::utf16_string;
						char cmt[64];
						std::snprintf(cmt, sizeof(cmt), "wlen=%d", str_len);
						fields[i].comment = cmt;
					}
				}
			}
		}

		if (fields[i].type == field_type_t::uint8 && fields[i].size == 1) {
			uint8_t val = 0;
			std::vector<uint8_t> byte_data;
			driver_bridge::read_memory(base_address + fields[i].offset, 1, byte_data);
			if (byte_data.size() == 1) {
				val = byte_data[0];
				if (val == 0 || val == 1) {
					fields[i].type = field_type_t::bool8;
				}
			}
		}
	}

	for (size_t i = 0; i + 15 < fields.size(); ++i) {
		if (fields[i].type != field_type_t::vec4 || fields[i].size != 16) continue;

		bool is_mat = true;
		for (int row = 1; row < 4 && is_mat; ++row) {
			size_t idx = i + static_cast<size_t>(row);
			if (idx >= fields.size()) { is_mat = false; break; }
			if (fields[idx].type != field_type_t::vec4 || fields[idx].size != 16) { is_mat = false; break; }
			if (fields[idx].offset != fields[i].offset + static_cast<uint64_t>(row * 16)) { is_mat = false; break; }
		}

		if (is_mat) {
			fields[i].type = field_type_t::mat4x4;
			fields[i].size = 64;
			fields.erase(fields.begin() + static_cast<ptrdiff_t>(i) + 1,
			             fields.begin() + static_cast<ptrdiff_t>(i) + 4);
		}
	}
}

inline void refine_types_from_accesses(std::vector<struct_field_t>& fields)
{
	for (auto& f : fields) {
		if (f.accesses.empty()) continue;

		bool all_bit_test = true;
		for (auto& acc : f.accesses) {
			std::string lower = acc.disasm_text;
			for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
			if (lower.find("test") == std::string::npos &&
			    lower.find("bt ") == std::string::npos &&
			    lower.find("bts ") == std::string::npos &&
			    lower.find("btr ") == std::string::npos &&
			    lower.find("btc ") == std::string::npos) {
				all_bit_test = false;
				break;
			}
		}

		if (all_bit_test && f.type != field_type_t::vtable_ptr &&
		    f.type != field_type_t::pointer) {
			f.type = field_type_t::bitfield;
		}
	}
}

}

inline void reconstruct_from_snapshot(uint64_t base_address, int struct_size, const std::string& name)
{
	if (g_state.monitoring.load()) return;
	g_state.monitoring.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);

	work_queue::post([base_address, struct_size, name]() {
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

		detail::merge_compound_types(result.fields, base_address);
		detect_arrays(result.fields);

		for (auto& f : result.fields) {
			int elem_size = f.size;
			if (f.array_count > 1) elem_size = f.size / f.array_count;
			if (f.offset + static_cast<uint64_t>(elem_size) <= data.size()) {
				auto scored = detail::infer_type_scored(data.data() + f.offset, elem_size, base_address);
				f.type_confidence = scored.score;
			}
		}

		result.has_vtable = !result.fields.empty() && result.fields[0].type == field_type_t::vtable_ptr;

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = std::move(result);
			g_state.active = true;
		}

		g_state.progress.store(1.f);
		g_state.monitoring.store(false);
	});
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

	work_queue::post([base_address, struct_size, name]() {
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

			detail::merge_compound_types(g_state.current.fields, base_address);
			detail::refine_types_from_accesses(g_state.current.fields);
			detect_arrays(g_state.current.fields);

			g_state.current.has_vtable = !g_state.current.fields.empty() &&
			                              g_state.current.fields[0].type == field_type_t::vtable_ptr;

			g_state.history.push_back(g_state.current);
		}

		g_state.progress.store(1.f);
		g_state.monitoring.store(false);
	});
}

inline std::string export_as_cpp(const reconstructed_struct_t& s)
{
	std::string out;
	out += "#include <cstdint>\n\n";
	out += "struct vec2_t { float x, y; };\n";
	out += "struct vec3_t { float x, y, z; };\n";
	out += "struct vec4_t { float x, y, z, w; };\n";
	out += "struct mat4x4_t { float m[4][4]; };\n";
	out += "struct color_rgba_t { float r, g, b, a; };\n\n";
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
		} else if (f.type == field_type_t::vec2) {
			std::snprintf(line, sizeof(line), "    vec2_t  %-20s // 0x%04llX\n",
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset));
		} else if (f.type == field_type_t::vec3) {
			std::snprintf(line, sizeof(line), "    vec3_t  %-20s // 0x%04llX\n",
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset));
		} else if (f.type == field_type_t::vec4) {
			std::snprintf(line, sizeof(line), "    vec4_t  %-20s // 0x%04llX\n",
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset));
		} else if (f.type == field_type_t::mat4x4) {
			std::snprintf(line, sizeof(line), "    mat4x4_t %-20s // 0x%04llX\n",
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset));
		} else if (f.type == field_type_t::color_rgba) {
			std::snprintf(line, sizeof(line), "    color_rgba_t %-20s // 0x%04llX\n",
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset));
		} else if (f.type == field_type_t::bitfield) {
			std::snprintf(line, sizeof(line), "    uint%d_t %-20s // 0x%04llX bitfield\n",
			              f.size * 8,
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset));
		} else if (f.type == field_type_t::utf8_string) {
			std::snprintf(line, sizeof(line), "    char*   %-20s // 0x%04llX %s\n",
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset),
			              f.comment.c_str());
		} else if (f.type == field_type_t::utf16_string) {
			std::snprintf(line, sizeof(line), "    wchar_t* %-20s // 0x%04llX %s\n",
			              (f.name + ";").c_str(),
			              static_cast<unsigned long long>(f.offset),
			              f.comment.c_str());
		} else if (f.type == field_type_t::bool8) {
			std::snprintf(line, sizeof(line), "    bool    %-20s // 0x%04llX\n",
			              (f.name + ";").c_str(),
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

inline void ai_name_fields()
{
	if (g_state.ai_naming.load()) return;
	if (g_state.monitoring.load()) return;

	reconstructed_struct_t snapshot;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		snapshot = g_state.current;
	}

	if (snapshot.fields.empty()) return;

	g_state.ai_naming.store(true);

	work_queue::post([snapshot]() {
		std::string prompt = "You are analyzing a reconstructed memory structure from a running process.\n";
		prompt += "Base address: 0x";
		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(snapshot.base_address));
		prompt += addr_buf;
		prompt += "\nStruct name: " + snapshot.name + "\n";
		prompt += "Total size: " + std::to_string(snapshot.total_size) + " bytes\n\n";
		prompt += "Fields:\n";

		for (auto& f : snapshot.fields) {
			char line[512];
			std::snprintf(line, sizeof(line), "  offset=0x%04llX  type=%-12s  size=%d  current_name=%s",
			              static_cast<unsigned long long>(f.offset),
			              field_type_name(f.type), f.size, f.name.c_str());
			prompt += line;

			if (!f.accesses.empty()) {
				prompt += "  accesses=[";
				int shown = 0;
				for (auto& acc : f.accesses) {
					if (shown > 0) prompt += ", ";
					char acc_buf[256];
					std::snprintf(acc_buf, sizeof(acc_buf), "{%s, %s, hits=%d}",
					              acc.is_write ? "W" : "R",
					              acc.disasm_text.c_str(),
					              acc.hit_count);
					prompt += acc_buf;
					if (++shown >= 5) break;
				}
				prompt += "]";
			}

			if (!f.vtable_entries.empty()) {
				prompt += "  vtable=[";
				int shown = 0;
				for (auto& ve : f.vtable_entries) {
					if (shown > 0) prompt += ", ";
					prompt += ve.name;
					if (++shown >= 8) break;
				}
				prompt += "]";
			}

			if (!f.comment.empty()) {
				prompt += "  comment=\"" + f.comment + "\"";
			}

			prompt += "\n";
		}

		prompt += "\nBased on the field types, sizes, access patterns, and instruction context, "
		          "suggest descriptive C++ names for each field.\n"
		          "Consider:\n"
		          "- Float32 fields accessed by SSE in groups of 3-4 are likely position/velocity/rotation vectors\n"
		          "- Frequently written float fields near each other are often coordinates\n"
		          "- Pointers accessed early and often are likely vtables or parent pointers\n"
		          "- Bool/uint8 fields with test instructions are flags\n"
		          "- Int32 fields with cmp instructions are likely health, score, ammo, etc.\n"
		          "- String pointers are often names, paths, or descriptions\n\n"
		          "Output ONLY a JSON array of objects with \"offset\" (hex string like \"0x0040\") and \"name\" (the suggested name).\n"
		          "No markdown, no explanations, just the JSON array.";

		auto ai = std::make_unique<standalone_ai_client_t>(g_sa_settings);
		if (!ai->is_available()) {
			g_state.ai_naming.store(false);
			return;
		}

		std::vector<std::pair<std::string, std::string>> history;
		std::string result = ai->chat_blocking(prompt, history, nullptr, nullptr);

		if (result.empty()) {
			g_state.ai_naming.store(false);
			return;
		}

		size_t arr_start = result.find('[');
		size_t arr_end = result.rfind(']');
		if (arr_start == std::string::npos || arr_end == std::string::npos || arr_end <= arr_start) {
			g_state.ai_naming.store(false);
			return;
		}

		std::string json_str = result.substr(arr_start, arr_end - arr_start + 1);

		auto j = nlohmann::json::parse(json_str, nullptr, false);
		if (j.is_discarded() || !j.is_array()) {
			g_state.ai_naming.store(false);
			return;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			for (auto& item : j) {
				if (!item.contains("offset") || !item.contains("name")) continue;

				std::string off_str = item["offset"].get<std::string>();
				std::string new_name = item["name"].get<std::string>();

				uint64_t off = std::strtoull(off_str.c_str(), nullptr, 16);

				for (auto& f : g_state.current.fields) {
					if (f.offset == off) {
						f.name = new_name;
						break;
					}
				}
			}
		}

		g_state.ai_naming.store(false);
	});
}

inline void detect_arrays(std::vector<struct_field_t>& fields)
{
	if (fields.size() < 3) return;

	size_t i = 0;
	while (i < fields.size()) {
		size_t run_start = i;
		field_type_t run_type = fields[i].type;
		int run_size = fields[i].size;

		if (run_type == field_type_t::unknown || run_type == field_type_t::padding ||
		    run_type == field_type_t::vtable_ptr || run_type == field_type_t::nested_struct ||
		    run_type == field_type_t::vec2 || run_type == field_type_t::vec3 ||
		    run_type == field_type_t::vec4 || run_type == field_type_t::mat4x4 ||
		    run_type == field_type_t::color_rgba) {
			++i;
			continue;
		}

		size_t j = i + 1;
		while (j < fields.size() &&
		       fields[j].type == run_type &&
		       fields[j].size == run_size &&
		       fields[j].offset == fields[j - 1].offset + static_cast<uint64_t>(run_size)) {
			++j;
		}

		int count = static_cast<int>(j - run_start);
		if (count >= 3) {
			fields[run_start].array_count = count;
			fields[run_start].size = run_size * count;
			char arr_name[64];
			std::snprintf(arr_name, sizeof(arr_name), "array_%03llX",
			              static_cast<unsigned long long>(fields[run_start].offset));
			fields[run_start].name = arr_name;

			fields.erase(fields.begin() + static_cast<ptrdiff_t>(run_start) + 1,
			             fields.begin() + static_cast<ptrdiff_t>(j));
			i = run_start + 1;
		} else {
			i = j;
		}
	}
}

inline void refresh_value_history()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (!g_state.active) return;

	auto& s = g_state.current;
	if (s.base_address == 0 || s.fields.empty()) return;

	std::vector<uint8_t> data;
	driver_bridge::read_memory(s.base_address, static_cast<size_t>(s.total_size), data);
	if (data.empty()) return;

	for (auto& f : s.fields) {
		if (f.offset + static_cast<uint64_t>(f.size) > data.size()) continue;

		int elem_size = f.size;
		if (f.array_count > 1)
			elem_size = f.size / f.array_count;

		uint64_t val = 0;
		int read_sz = (std::min)(elem_size, 8);
		std::memcpy(&val, data.data() + f.offset, static_cast<size_t>(read_sz));
		f.value_history.push(val);

		auto scored = detail::infer_type_scored(data.data() + f.offset, elem_size, s.base_address);
		if (scored.score > f.type_confidence) {
			f.type_confidence = scored.score;
			if (scored.score >= 50.f && f.array_count <= 1)
				f.type = scored.type;
		}
	}
}

inline std::string get_struct_cache_dir()
{
	const char* appdata = std::getenv("APPDATA");
	if (!appdata) return {};
	return std::string(appdata) + "\\AiDA\\Standalone\\structs";
}

inline void save_struct_to_disk(const reconstructed_struct_t& s)
{
	std::string dir = get_struct_cache_dir();
	if (dir.empty()) return;

	std::error_code ec;
	std::filesystem::create_directories(dir, ec);
	if (ec) return;

	nlohmann::json j;
	j["name"] = s.name;
	j["base_address"] = s.base_address;
	j["total_size"] = s.total_size;
	j["has_vtable"] = s.has_vtable;
	j["vtable_address"] = s.vtable_address;

	nlohmann::json jfields = nlohmann::json::array();
	for (auto& f : s.fields) {
		nlohmann::json jf;
		jf["offset"] = f.offset;
		jf["size"] = f.size;
		jf["type"] = static_cast<int>(f.type);
		jf["name"] = f.name;
		jf["comment"] = f.comment;
		jf["type_confidence"] = f.type_confidence;
		jf["array_count"] = f.array_count;

		if (!f.vtable_entries.empty()) {
			nlohmann::json jvt = nlohmann::json::array();
			for (auto& ve : f.vtable_entries) {
				nlohmann::json jve;
				jve["func_addr"] = ve.func_addr;
				jve["index"] = ve.index;
				jve["name"] = ve.name;
				jvt.push_back(jve);
			}
			jf["vtable_entries"] = jvt;
		}

		jfields.push_back(jf);
	}
	j["fields"] = jfields;

	std::string safe_name = s.name;
	for (auto& c : safe_name) {
		if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' ||
		    c == '"' || c == '<' || c == '>' || c == '|' || c == ' ')
			c = '_';
	}

	std::string path = dir + "\\" + safe_name + ".json";
	std::ofstream ofs(path);
	if (ofs.is_open()) {
		ofs << j.dump(2);
	}
}

inline void load_structs_from_disk()
{
	if (g_state.disk_cache_loaded) return;
	g_state.disk_cache_loaded = true;

	std::string dir = get_struct_cache_dir();
	if (dir.empty()) return;

	std::error_code ec;
	if (!std::filesystem::exists(dir, ec)) return;

	for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
		if (ec) break;
		if (!entry.is_regular_file()) continue;
		if (entry.path().extension() != ".json") continue;

		std::ifstream ifs(entry.path());
		if (!ifs.is_open()) continue;

		auto j = nlohmann::json::parse(ifs, nullptr, false);
		if (j.is_discarded()) continue;

		reconstructed_struct_t s;
		s.name = j.value("name", std::string("unnamed"));
		s.base_address = j.value("base_address", uint64_t(0));
		s.total_size = j.value("total_size", 0);
		s.has_vtable = j.value("has_vtable", false);
		s.vtable_address = j.value("vtable_address", uint64_t(0));

		if (j.contains("fields") && j["fields"].is_array()) {
			for (auto& jf : j["fields"]) {
				struct_field_t f;
				f.offset = jf.value("offset", uint64_t(0));
				f.size = jf.value("size", 0);
				f.type = static_cast<field_type_t>(jf.value("type", 0));
				f.name = jf.value("name", std::string{});
				f.comment = jf.value("comment", std::string{});
				f.type_confidence = jf.value("type_confidence", 0.f);
				f.array_count = jf.value("array_count", 1);

				if (jf.contains("vtable_entries") && jf["vtable_entries"].is_array()) {
					for (auto& jve : jf["vtable_entries"]) {
						vtable_entry_t ve;
						ve.func_addr = jve.value("func_addr", uint64_t(0));
						ve.index = jve.value("index", 0);
						ve.name = jve.value("name", std::string{});
						f.vtable_entries.push_back(ve);
					}
				}

				s.fields.push_back(f);
			}
		}

		g_state.saved_structs.push_back(std::move(s));
	}
}

inline void delete_saved_struct(int index)
{
	if (index < 0 || index >= static_cast<int>(g_state.saved_structs.size())) return;

	std::string dir = get_struct_cache_dir();
	if (!dir.empty()) {
		std::string safe_name = g_state.saved_structs[index].name;
		for (auto& c : safe_name) {
			if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' ||
			    c == '"' || c == '<' || c == '>' || c == '|' || c == ' ')
				c = '_';
		}
		std::string path = dir + "\\" + safe_name + ".json";
		std::error_code ec;
		std::filesystem::remove(path, ec);
	}

	g_state.saved_structs.erase(g_state.saved_structs.begin() + index);
}

inline void cancel()
{
	g_state.cancel.store(true);
}

}
