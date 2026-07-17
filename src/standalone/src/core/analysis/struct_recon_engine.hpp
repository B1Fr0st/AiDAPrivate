#pragma once

#include <algorithm>
#include "theme.hpp"
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <Windows.h>

#include "standalone_driver.hpp"
#include "debugger_engine.hpp"
#include "page_guard_engine.hpp"
#include "zydis_disasm.hpp"
#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "../infra/executor.hpp"
#include "../ui/task_center.hpp"
#include "../../helpers/diag_log.hpp"
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
	std::string source;
	uint32_t    thread_id = 0;
	uint32_t    sample_index = 0;
	uint32_t    capture_session_id = 0;
	bool        initial_value_captured = false;
	uint64_t    initial_value = 0;
	std::vector<uint8_t> initial_bytes;
	bool        value_captured = false;
	bool        value_after_access = false;
	uint64_t    observed_value = 0;
	std::vector<uint8_t> observed_bytes;
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
	std::shared_ptr<const reconstructed_struct_t> publication =
		std::make_shared<const reconstructed_struct_t>();
	uint64_t current_revision = 0;
	std::vector<access_record_t> access_log;
	std::mutex  mutex;
	std::mutex  persistence_mutex;
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
	bool disk_cache_loading = false;
};

inline state_t g_state;

inline void publish_current_locked()
{
	++g_state.current_revision;
	std::atomic_store_explicit(&g_state.publication,
		std::make_shared<const reconstructed_struct_t>(g_state.current),
		std::memory_order_release);
}

inline std::shared_ptr<const reconstructed_struct_t> capture_current_snapshot()
{
	return std::atomic_load_explicit(&g_state.publication, std::memory_order_acquire);
}

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
	const auto& th = aida::ui::resolved();
	switch (t) {
	case field_type_t::int8:
	case field_type_t::int16:
	case field_type_t::int32:
	case field_type_t::int64:        return aida::ui::with_alpha(th.syn_type, alpha);
	case field_type_t::uint8:
	case field_type_t::uint16:
	case field_type_t::uint32:
	case field_type_t::uint64:       return aida::ui::with_alpha(th.syn_number, alpha);
	case field_type_t::float32:
	case field_type_t::float64:      return aida::ui::with_alpha(th.syn_number, alpha);
	case field_type_t::pointer:      return aida::ui::with_alpha(th.syn_string, alpha);
	case field_type_t::vtable_ptr:   return aida::ui::with_alpha(th.error, alpha);
	case field_type_t::c_string:
	case field_type_t::wide_string:  return aida::ui::with_alpha(th.syn_string, alpha);
	case field_type_t::padding:      return aida::ui::with_alpha(th.text_dim, alpha);
	case field_type_t::vec2:
	case field_type_t::vec3:
	case field_type_t::vec4:         return aida::ui::with_alpha(th.warning, alpha);
	case field_type_t::mat4x4:       return aida::ui::with_alpha(th.warning, alpha);
	case field_type_t::color_rgba:   return aida::ui::with_alpha(th.syn_keyword, alpha);
	case field_type_t::bitfield:     return aida::ui::with_alpha(th.syn_keyword, alpha);
	case field_type_t::utf8_string:  return aida::ui::with_alpha(th.syn_string, alpha);
	case field_type_t::utf16_string: return aida::ui::with_alpha(th.syn_string, alpha);
	case field_type_t::bool8:        return aida::ui::with_alpha(th.syn_keyword, alpha);
	default: return aida::ui::with_alpha(th.syn_identifier, alpha);
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

inline bool is_user_canonical_pointer(uint64_t value)
{
	return value >= 0x10000 && value <= 0x00007FFFFFFFFFFFULL;
}

inline uint32_t normalized_page_protect(uint32_t protect)
{
	return protect & 0xFFu;
}

inline bool is_region_committed_accessible(const driver_bridge::memory_region_t& region)
{
	if ((region.state & MEM_COMMIT) == 0)
		return false;
	if ((region.protect & PAGE_GUARD) != 0)
		return false;
	uint32_t protect = normalized_page_protect(region.protect);
	return protect != 0 && protect != PAGE_NOACCESS;
}

inline bool is_region_readable(const driver_bridge::memory_region_t& region)
{
	if (!is_region_committed_accessible(region))
		return false;
	switch (normalized_page_protect(region.protect)) {
	case PAGE_READONLY:
	case PAGE_READWRITE:
	case PAGE_WRITECOPY:
	case PAGE_EXECUTE_READ:
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
		return true;
	default:
		return false;
	}
}

inline bool is_region_executable(const driver_bridge::memory_region_t& region)
{
	if (!is_region_committed_accessible(region))
		return false;
	switch (normalized_page_protect(region.protect)) {
	case PAGE_EXECUTE:
	case PAGE_EXECUTE_READ:
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
		return true;
	default:
		return false;
	}
}

inline bool region_contains_range(const driver_bridge::memory_region_t& region, uint64_t address, uint64_t size)
{
	if (address < region.base)
		return false;
	uint64_t offset = address - region.base;
	if (offset > region.size)
		return false;
	return size <= region.size - offset;
}

inline bool query_readable_target_range(uint64_t address, uint64_t size, driver_bridge::memory_region_t* out = nullptr)
{
	driver_bridge::memory_region_t region{};
	if (!driver_bridge::query_memory(address, region))
		return false;
	if (!is_region_readable(region) || !region_contains_range(region, address, size))
		return false;
	if (out)
		*out = region;
	return true;
}

inline bool query_executable_target_range(uint64_t address, uint64_t size, driver_bridge::memory_region_t* out = nullptr)
{
	driver_bridge::memory_region_t region{};
	if (!driver_bridge::query_memory(address, region))
		return false;
	if (!is_region_executable(region) || !region_contains_range(region, address, size))
		return false;
	if (out)
		*out = region;
	return true;
}

inline float score_vtable_ptr(const uint8_t* data, uint64_t base_addr)
{
	uint64_t val;
	std::memcpy(&val, data, 8);

	float ptr_score = score_pointer64(data);
	if (ptr_score < 50.f) return 0.f;
	if (!is_user_canonical_pointer(val)) return 0.f;
	if (!query_readable_target_range(val, 16)) return 0.f;

	std::vector<uint8_t> vtable_data;
	driver_bridge::read_memory(val, 32, vtable_data);
	if (vtable_data.size() < 16) return 0.f;

	int valid_funcs = 0;
	for (size_t i = 0; i + 8 <= vtable_data.size(); i += 8) {
		uint64_t func;
		std::memcpy(&func, vtable_data.data() + i, 8);
		if (!is_user_canonical_pointer(func)) break;
		if (!query_executable_target_range(func, 4)) break;
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

inline void append_field_evidence(struct_field_t& field, const std::string& evidence)
{
	if (evidence.empty())
		return;
	if (field.comment.find(evidence) != std::string::npos)
		return;
	if (!field.comment.empty())
		field.comment += "; ";
	field.comment += evidence;
}

inline void record_unproven_vtable_candidate(std::vector<struct_field_t>& fields,
                                             uint64_t candidate,
                                             const char* reason,
                                             int sampled_entries,
                                             int proven_entries,
                                             uint64_t failed_entry,
                                             float pointer_score)
{
	char evidence_buf[256];
	std::snprintf(evidence_buf,
	              sizeof(evidence_buf),
	              "unproven_vtable_candidate=0x%llX reason=%s proven_exec=%d sampled=%d failed=0x%llX",
	              static_cast<unsigned long long>(candidate),
	              reason ? reason : "unproven",
	              proven_entries,
	              sampled_entries,
	              static_cast<unsigned long long>(failed_entry));
	std::string evidence = evidence_buf;

	auto apply = [&](struct_field_t& field) {
		if (field.size <= 0)
			field.size = 8;
		if (field.name.empty() || field.name == "__vtable")
			field.name = "field_000";
		if (field.type == field_type_t::vtable_ptr) {
			field.type = pointer_score >= 50.f ? field_type_t::pointer : field_type_t::unknown;
			field.vtable_entries.clear();
		} else if (field.type == field_type_t::unknown && pointer_score >= 50.f) {
			field.type = field_type_t::pointer;
		}
		if (pointer_score > field.type_confidence)
			field.type_confidence = pointer_score;
		append_field_evidence(field, evidence);
	};

	for (auto& field : fields) {
		if (field.offset == 0) {
			apply(field);
			return;
		}
	}

	struct_field_t field;
	field.offset = 0;
	field.size = 8;
	field.type = pointer_score >= 50.f ? field_type_t::pointer : field_type_t::unknown;
	field.name = "field_000";
	field.comment = std::move(evidence);
	field.type_confidence = pointer_score;
	fields.insert(fields.begin(), std::move(field));
}

inline void promote_proven_vtable(std::vector<struct_field_t>& fields, std::vector<vtable_entry_t> entries)
{
	for (auto& field : fields) {
		if (field.offset == 0) {
			field.size = 8;
			field.type = field_type_t::vtable_ptr;
			field.name = "__vtable";
			field.vtable_entries = std::move(entries);
			field.type_confidence = 100.f;
			return;
		}
	}

	struct_field_t field;
	field.offset = 0;
	field.size = 8;
	field.type = field_type_t::vtable_ptr;
	field.name = "__vtable";
	field.vtable_entries = std::move(entries);
	field.type_confidence = 100.f;
	fields.insert(fields.begin(), std::move(field));
}

inline bool has_proven_vtable_field(const struct_field_t& field)
{
	if (field.type != field_type_t::vtable_ptr || field.vtable_entries.size() < 2)
		return false;
	for (const auto& entry : field.vtable_entries) {
		if (!is_user_canonical_pointer(entry.func_addr))
			return false;
		if (!query_executable_target_range(entry.func_addr, 4))
			return false;
	}
	return true;
}

inline void enforce_vtable_field_proof(struct_field_t& field)
{
	if (field.type != field_type_t::vtable_ptr)
		return;
	if (has_proven_vtable_field(field))
		return;
	field.type = field_type_t::pointer;
	field.vtable_entries.clear();
	if (field.name == "__vtable" || field.name.empty())
		field.name = "field_000";
	append_field_evidence(field, "vtable_label_removed_unproven_executable_method_targets");
	if (field.type_confidence > 75.f)
		field.type_confidence = 75.f;
}

inline bool has_proven_vtable_at_zero(std::vector<struct_field_t>& fields)
{
	if (fields.empty() || fields[0].offset != 0)
		return false;
	enforce_vtable_field_proof(fields[0]);
	return has_proven_vtable_field(fields[0]);
}

inline void detect_vtable(uint64_t base_addr, int struct_size,
                           std::vector<struct_field_t>& fields)
{
	if (struct_size < 8)
		return;

	std::vector<uint8_t> data;
	driver_bridge::read_memory(base_addr, 8, data);
	if (data.size() < 8) return;

	uint64_t potential_vtable;
	std::memcpy(&potential_vtable, data.data(), 8);

	if (!is_user_canonical_pointer(potential_vtable))
		return;

	const float pointer_score = score_pointer64(data.data());
	auto record_unproven = [&](const char* reason, int sampled, int proven, uint64_t failed) {
		if (pointer_score >= 50.f)
			record_unproven_vtable_candidate(fields, potential_vtable, reason, sampled, proven, failed, pointer_score);
	};

	if (!query_readable_target_range(potential_vtable, 16)) {
		record_unproven("table_not_committed_readable", 0, 0, potential_vtable);
		return;
	}

	std::vector<uint8_t> vtable_data;
	driver_bridge::read_memory(potential_vtable, 256, vtable_data);
	if (vtable_data.size() < 16) {
		record_unproven("table_read_unproven", 0, 0, potential_vtable);
		return;
	}

	auto modules = driver_bridge::enumerate_modules();

	std::vector<vtable_entry_t> entries;
	int sampled_entries = 0;
	const char* unproven_reason = "insufficient_executable_entries";
	uint64_t failed_entry = 0;

	for (size_t i = 0; i + 8 <= vtable_data.size(); i += 8) {
		uint64_t func_addr;
		std::memcpy(&func_addr, vtable_data.data() + i, 8);

		if (!is_user_canonical_pointer(func_addr)) {
			if (entries.size() < 2) {
				unproven_reason = "entry_noncanonical";
				failed_entry = func_addr;
			}
			break;
		}

		++sampled_entries;
		if (!query_executable_target_range(func_addr, 4)) {
			unproven_reason = "entry_not_committed_executable";
			failed_entry = func_addr;
			break;
		}

		std::vector<uint8_t> func_bytes;
		driver_bridge::read_memory(func_addr, 4, func_bytes);
		if (func_bytes.size() < 4) {
			unproven_reason = "entry_read_unproven";
			failed_entry = func_addr;
			break;
		}

		vtable_entry_t entry;
		entry.func_addr = func_addr;
		entry.index = static_cast<int>(i / 8);

		bool resolved = false;
		for (auto& m : modules) {
			if (func_addr >= m.base && func_addr - m.base < m.size) {
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
		promote_proven_vtable(fields, std::move(entries));
	} else {
		record_unproven(unproven_reason, sampled_entries, static_cast<int>(entries.size()), failed_entry);
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
	if (base_address == 0 || struct_size <= 0 || struct_size > 1024 * 1024) {
		diag::log_tagged_fmt("struct_recon",
			"reconstruct_request_rejected base=0x%llX size=%d",
			static_cast<unsigned long long>(base_address), struct_size);
		return;
	}
	bool expected = false;
	if (!g_state.monitoring.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel))
		return;
	g_state.cancel.store(false);
	g_state.progress.store(0.f);

	auto worker = [base_address, struct_size, name]() {
		reconstructed_struct_t result;
		result.base_address = base_address;
		result.total_size = struct_size;
		result.name = name.empty() ? "struct_t" : name;

		std::vector<uint8_t> data;
		if (!driver_bridge::read_memory(base_address, static_cast<size_t>(struct_size), data) ||
			data.size() != static_cast<size_t>(struct_size)) {
			g_state.monitoring.store(false);
			throw std::runtime_error("The structure snapshot could not read the exact requested target range");
		}

		std::map<uint64_t, struct_field_t> field_map;

		int offset = 0;
		while (offset < struct_size && offset < static_cast<int>(data.size()) && !g_state.cancel.load()) {
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

		if (!g_state.cancel.load())
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

		if (!g_state.cancel.load()) {
			detail::merge_compound_types(result.fields, base_address);
			detect_arrays(result.fields);
		}

		for (auto& f : result.fields) {
			if (g_state.cancel.load()) break;
			int elem_size = f.size;
			if (f.array_count > 1) elem_size = f.size / f.array_count;
			if (f.offset + static_cast<uint64_t>(elem_size) <= data.size()) {
				auto scored = detail::infer_type_scored(data.data() + f.offset, elem_size, base_address);
				f.type_confidence = scored.score;
			}
		}

		result.has_vtable = detail::has_proven_vtable_at_zero(result.fields);
		if (g_state.cancel.load(std::memory_order_acquire)) {
			g_state.progress.store(0.f);
			g_state.monitoring.store(false);
			return;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = std::move(result);
			g_state.active = true;
			publish_current_locked();
		}

		g_state.progress.store(1.f);
		g_state.monitoring.store(false);
	};
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "struct_recon";
	submission.label = "struct_recon.reconstruct_from_snapshot";
	submission.thread_class = "struct_reconstruction";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 2;
	submission.failure_policy = "reject_not_started";
	submission.cancel_hook = []() { g_state.cancel.store(true, std::memory_order_release); };
	submission.body = std::move(worker);
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		g_state.progress.store(1.f);
		g_state.monitoring.store(false);
		return;
	}
	aida::ui::task_center::task_registration_t registration;
	registration.owner = "analysis";
	registration.owner_view = "view.types.struct_recon";
	registration.owner_action = "types.reconstruct_snapshot";
	registration.label = "Reconstruct structure snapshot";
	registration.stage = "Queued";
	registration.progress = -1.f;
	registration.target = "Address " + std::to_string(base_address);
	registration.cancellation_is_safe = true;
	registration.callbacks.cancel = []() {
		g_state.cancel.store(true, std::memory_order_release);
		return true;
	};
	static_cast<void>(aida::ui::task_center::register_executor_job(
		submitted.task_id, std::move(registration)));
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

inline bool disasm_suggests_write(const char* mnem, const char* ops)
{
	std::string m = mnem ? mnem : "";
	std::string o = ops ? ops : "";
	for (auto& c : m) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
	for (auto& c : o) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
	const size_t comma = o.find(',');
	const std::string first = comma == std::string::npos ? o : o.substr(0, comma);
	const bool memory_dest = first.find('[') != std::string::npos;
	if (!memory_dest)
		return false;
	if (m == "cmp" || m == "test" || m == "bt" || m == "lea" || m == "prefetchnta" ||
	    m == "prefetcht0" || m == "prefetcht1" || m == "prefetcht2")
		return false;
	if (m.find("mov") == 0 || m.find("stos") == 0 || m.find("xchg") == 0 || m.find("cmpxchg") == 0 ||
	    m == "add" || m == "sub" || m == "inc" || m == "dec" || m == "and" || m == "or" ||
	    m == "xor" || m == "not" || m == "neg" || m == "imul" || m == "lock")
		return true;
	return memory_dest;
}

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
	if (access_type != 0 && access_type != 1)
		result.is_write = disasm_suggests_write(ins.mnem, ins.ops);

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

struct access_key_t {
	uint64_t offset = 0;
	uint64_t rip = 0;
	int      size = 0;
	bool     is_write = false;

	bool operator<(const access_key_t& other) const {
		if (offset != other.offset) return offset < other.offset;
		if (rip != other.rip) return rip < other.rip;
		if (size != other.size) return size < other.size;
		return is_write < other.is_write;
	}
};

inline uint64_t context_dr_address(const driver_bridge::thread_context_t& ctx, int slot)
{
	switch (slot) {
	case 0: return ctx.dr0;
	case 1: return ctx.dr1;
	case 2: return ctx.dr2;
	case 3: return ctx.dr3;
	default: return 0;
	}
}

inline bool context_reports_hwbp_slot(const driver_bridge::thread_context_t& ctx, int slot, uint64_t expected)
{
	if (slot < 0 || slot > 3 || expected == 0)
		return false;
	const bool dr6_hit = (ctx.dr6 & (1ull << static_cast<unsigned>(slot))) != 0;
	return dr6_hit && context_dr_address(ctx, slot) == expected;
}

inline std::vector<uint64_t> build_watch_offsets(int struct_size)
{
	std::vector<uint64_t> offsets;
	if (struct_size <= 0)
		return offsets;
	const int limit = (std::min)(struct_size, 65536);
	offsets.reserve(static_cast<size_t>(limit));
	std::vector<uint8_t> seen(static_cast<size_t>(limit), 0);
	auto add = [&](int off) {
		if (off < 0 || off >= limit)
			return;
		auto idx = static_cast<size_t>(off);
		if (seen[idx] != 0)
			return;
		seen[idx] = 1;
		offsets.push_back(static_cast<uint64_t>(off));
	};
	for (int i = 0; i < limit; i += 8)
		add(i);
	for (int i = 4; i < limit; i += 8)
		add(i);
	for (int i = 2; i < limit; i += 4)
		add(i);
	for (int i = 1; i < limit; i += 2)
		add(i);
	for (int i = 0; i < limit; ++i)
		add(i);
	return offsets;
}

inline void capture_observed_value(uint64_t base_address,
                                   int struct_size,
                                   const std::vector<uint8_t>& initial_data,
                                   access_record_t& rec,
                                   bool value_after_access)
{
	rec.initial_value_captured = false;
	rec.initial_value = 0;
	rec.initial_bytes.clear();
	rec.value_captured = false;
	rec.value_after_access = value_after_access;
	rec.observed_value = 0;
	rec.observed_bytes.clear();
	if (rec.access_offset >= static_cast<uint64_t>((std::max)(struct_size, 0)))
		return;
	const uint64_t remaining = static_cast<uint64_t>(struct_size) - rec.access_offset;
	const auto requested = static_cast<uint64_t>((std::max)(rec.access_size, 1));
	const size_t read_size = static_cast<size_t>(std::min<uint64_t>(requested, std::min<uint64_t>(remaining, 8)));
	if (read_size == 0)
		return;
	if (rec.access_offset < initial_data.size()) {
		const size_t initial_size = (std::min)(read_size, initial_data.size() - static_cast<size_t>(rec.access_offset));
		rec.initial_bytes.assign(initial_data.begin() + static_cast<std::ptrdiff_t>(rec.access_offset),
		                         initial_data.begin() + static_cast<std::ptrdiff_t>(rec.access_offset + initial_size));
		std::memcpy(&rec.initial_value, rec.initial_bytes.data(), (std::min)(rec.initial_bytes.size(), sizeof(rec.initial_value)));
		rec.initial_value_captured = !rec.initial_bytes.empty();
	}
	std::vector<uint8_t> value;
	if (!driver_bridge::read_memory(base_address + rec.access_offset, read_size, value) || value.empty())
		return;
	rec.observed_bytes = std::move(value);
	std::memcpy(&rec.observed_value, rec.observed_bytes.data(), (std::min)(rec.observed_bytes.size(), sizeof(rec.observed_value)));
	rec.value_captured = true;
}

inline void merge_access_record(std::map<access_key_t, access_record_t>& access_map, access_record_t rec)
{
	if (rec.access_size <= 0)
		rec.access_size = 1;
	access_key_t key{rec.access_offset, rec.instruction_addr, rec.access_size, rec.is_write};
	auto it = access_map.find(key);
	if (it == access_map.end()) {
		access_map.emplace(key, std::move(rec));
	} else {
		it->second.hit_count += (std::max)(rec.hit_count, 1);
		if (!rec.source.empty() && !it->second.source.empty() && rec.source != it->second.source)
			it->second.source = "mixed";
		else if (it->second.source.empty())
			it->second.source = rec.source;
		if (it->second.thread_id == 0)
			it->second.thread_id = rec.thread_id;
		if (it->second.capture_session_id == 0)
			it->second.capture_session_id = rec.capture_session_id;
		it->second.sample_index = (std::min)(it->second.sample_index, rec.sample_index);
		if (rec.initial_value_captured) {
			it->second.initial_value_captured = true;
			it->second.initial_value = rec.initial_value;
			it->second.initial_bytes = std::move(rec.initial_bytes);
		}
		if (rec.value_captured) {
			it->second.value_captured = true;
			it->second.value_after_access = rec.value_after_access;
			it->second.observed_value = rec.observed_value;
			it->second.observed_bytes = std::move(rec.observed_bytes);
		}
	}
}

}

inline void monitor_with_hwbp(uint64_t base_address, int struct_size, const std::string& name)
{
	const uint64_t request_ms = GetTickCount64();
	if (g_state.monitoring.load()) {
		diag::log_tagged_fmt("struct_recon", "monitor_request_rejected base=0x%llX size=%d name=%s monitoring=1 progress=%.3f",
			static_cast<unsigned long long>(base_address),
			struct_size,
			name.c_str(),
			static_cast<double>(g_state.progress.load()));
		return;
	}
	diag::log_tagged_fmt("struct_recon", "monitor_request base=0x%llX size=%d name=%s pid=%u tid=%lu",
		static_cast<unsigned long long>(base_address),
		struct_size,
		name.c_str(),
		driver_bridge::attached_pid(),
		static_cast<unsigned long>(GetCurrentThreadId()));
	g_state.monitoring.store(true);
	g_state.cancel.store(false);
	g_state.progress.store(0.f);

	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "struct_recon";
	submission.label = "struct_recon.monitor_with_hwbp";
	submission.thread_class = "struct_monitor";
	submission.domain = aida::infra::executor::domain_t::long_running;
	submission.priority = 2;
	submission.target_pid = driver_bridge::attached_pid();
	submission.failure_policy = "reject_not_started";
	submission.body = [base_address, struct_size, name, request_ms]() {
		const uint64_t worker_start_ms = GetTickCount64();
		diag::log_tagged_fmt("struct_recon", "monitor_worker_enter base=0x%llX size=%d name=%s pid=%u tid=%lu queued_ms=%llu",
			static_cast<unsigned long long>(base_address),
			struct_size,
			name.c_str(),
			driver_bridge::attached_pid(),
			static_cast<unsigned long>(GetCurrentThreadId()),
			static_cast<unsigned long long>(worker_start_ms - request_ms));
		reconstructed_struct_t result;
		result.base_address = base_address;
		result.total_size = struct_size;
		result.name = name.empty() ? "struct_t" : name;

		std::vector<uint8_t> data;
		diag::log_tagged_fmt("struct_recon", "monitor_initial_read_begin base=0x%llX size=%d pid=%u",
			static_cast<unsigned long long>(base_address),
			struct_size,
			driver_bridge::attached_pid());
		driver_bridge::read_memory(base_address, static_cast<size_t>(struct_size), data);
		diag::log_tagged_fmt("struct_recon", "monitor_initial_read_end base=0x%llX size=%d bytes=%zu status=%s error=%s elapsed_ms=%llu",
			static_cast<unsigned long long>(base_address),
			struct_size,
			data.size(),
			driver_bridge::status().c_str(),
			driver_bridge::last_error().c_str(),
			static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
		if (data.empty()) {
			g_state.monitoring.store(false);
			diag::log_tagged_fmt("struct_recon", "monitor_worker_exit_empty_read base=0x%llX elapsed_ms=%llu",
				static_cast<unsigned long long>(base_address),
				static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
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
		diag::log_tagged_fmt("struct_recon", "monitor_seed_fields_done base=0x%llX fields=%zu data_bytes=%zu elapsed_ms=%llu",
			static_cast<unsigned long long>(base_address),
			field_map.size(),
			data.size(),
			static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));

		detail::detect_vtable(base_address, struct_size, result.fields);
		diag::log_tagged_fmt("struct_recon", "monitor_detect_vtable_done base=0x%llX vtable_fields=%zu elapsed_ms=%llu",
			static_cast<unsigned long long>(base_address),
			result.fields.size(),
			static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));

		for (auto& [off, field] : field_map) {
			bool already_has = false;
			for (auto& f : result.fields) {
				if (f.offset == off) { already_has = true; break; }
			}
			if (!already_has) result.fields.push_back(field);
		}
		std::sort(result.fields.begin(), result.fields.end(),
			[](const struct_field_t& a, const struct_field_t& b) { return a.offset < b.offset; });
		result.has_vtable = detail::has_proven_vtable_at_zero(result.fields);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = result;
			g_state.active = true;
			publish_current_locked();
		}
		diag::log_tagged_fmt("struct_recon", "monitor_post_initial_result base=0x%llX fields=%zu has_vtable=%d elapsed_ms=%llu",
			static_cast<unsigned long long>(base_address),
			result.fields.size(),
			result.has_vtable ? 1 : 0,
			static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
		g_state.progress.store(0.25f);

		uint32_t pid = driver_bridge::attached_pid();

		bool use_page_guard = driver_bridge::using_kernel_driver() && pid != 0;
		uint32_t pg_session_id = 0;

		std::vector<uint32_t> tids;
		std::vector<uint64_t> hwbp_offsets;
		size_t hwbp_thread_count = 0;
		bool use_hwbp_fallback = false;
		diag::log_tagged_fmt("struct_recon", "monitor_backend_select base=0x%llX pid=%u using_kernel=%d use_page_guard_initial=%d",
			static_cast<unsigned long long>(base_address),
			pid,
			driver_bridge::using_kernel_driver() ? 1 : 0,
			use_page_guard ? 1 : 0);

		if (use_page_guard) {
			uint64_t page_base = base_address & ~0xFFFULL;
			uint64_t page_end = (base_address + static_cast<uint64_t>(struct_size) + 0xFFF) & ~0xFFFULL;
			uint64_t region_size = page_end - page_base;

			diag::log_tagged_fmt("struct_recon", "monitor_page_guard_install_begin pid=%u base=0x%llX page_base=0x%llX region_size=0x%llX",
				pid,
				static_cast<unsigned long long>(base_address),
				static_cast<unsigned long long>(page_base),
				static_cast<unsigned long long>(region_size));
			pg_session_id = page_guard_engine::g_pg_engine.install(pid, page_base, region_size);
			diag::log_tagged_fmt("struct_recon", "monitor_page_guard_install_end pid=%u base=0x%llX sid=%u elapsed_ms=%llu",
				pid,
				static_cast<unsigned long long>(base_address),
				pg_session_id,
				static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
			if (pg_session_id == 0) {
				use_page_guard = false;
				use_hwbp_fallback = true;
			}
		} else {
			use_hwbp_fallback = true;
		}
		diag::log_tagged_fmt("struct_recon", "monitor_backend_chosen base=0x%llX pid=%u page_guard=%d sid=%u hwbp=%d",
			static_cast<unsigned long long>(base_address),
			pid,
			use_page_guard ? 1 : 0,
			pg_session_id,
			use_hwbp_fallback ? 1 : 0);

		if (use_hwbp_fallback) {
			diag::log_tagged_fmt("struct_recon", "monitor_hwbp_enum_begin pid=%u base=0x%llX", pid, static_cast<unsigned long long>(base_address));
			auto threads = driver_bridge::enumerate_threads();
			for (auto& t : threads) tids.push_back(t.tid);
			hwbp_offsets = insn_analysis::build_watch_offsets(struct_size);
			hwbp_thread_count = (std::min<size_t>)(tids.size(), 32);
			diag::log_tagged_fmt("struct_recon", "monitor_hwbp_enum_end pid=%u base=0x%llX threads=%zu",
				pid,
				static_cast<unsigned long long>(base_address),
				tids.size());
			diag::log_tagged_fmt("struct_recon", "monitor_hwbp_plan pid=%u base=0x%llX watch_offsets=%zu sampled_threads=%zu slot_count=%zu access_type=read_write len=byte",
				pid,
				static_cast<unsigned long long>(base_address),
				hwbp_offsets.size(),
				hwbp_thread_count,
				(std::min<size_t>)(hwbp_offsets.size(), 4));
		}

		g_state.progress.store(0.3f);

		std::map<uint64_t, insn_analysis::decoded_access_t> rip_cache;
		std::map<insn_analysis::access_key_t, access_record_t> offset_access_map;
		int sample_count = g_state.config.sample_count;
		auto record_access = [&](uint64_t rip,
		                         uint64_t field_offset,
		                         const insn_analysis::decoded_access_t& decoded,
		                         bool value_after_access,
		                         const char* source,
		                         uint32_t tid,
		                         uint32_t sample_index,
		                         uint32_t capture_session_id) {
			if (field_offset >= static_cast<uint64_t>(struct_size))
				return;
			access_record_t rec;
			rec.instruction_addr = rip;
			rec.access_offset = field_offset;
			rec.access_size = decoded.access_size > 0 ? decoded.access_size : 1;
			rec.is_write = decoded.is_write;
			rec.disasm_text = decoded.disasm;
			rec.hit_count = 1;
			rec.source = source ? source : "unknown";
			rec.thread_id = tid;
			rec.sample_index = sample_index;
			rec.capture_session_id = capture_session_id;
			insn_analysis::capture_observed_value(base_address, struct_size, data, rec, value_after_access);
			insn_analysis::merge_access_record(offset_access_map, std::move(rec));
		};
		diag::log_tagged_fmt("struct_recon", "monitor_sample_loop_begin base=0x%llX pid=%u samples=%d page_guard=%d sid=%u hwbp=%d",
			static_cast<unsigned long long>(base_address),
			pid,
			sample_count,
			use_page_guard ? 1 : 0,
			pg_session_id,
			use_hwbp_fallback ? 1 : 0);

		for (int sample = 0; sample < sample_count && !g_state.cancel.load(); ++sample) {
			uint64_t active_hwbp_addrs[4] = {};
			if (use_hwbp_fallback && !hwbp_offsets.empty() && hwbp_thread_count != 0) {
				const size_t slot_count = (std::min<size_t>)(hwbp_offsets.size(), 4);
				const size_t base_index = (static_cast<size_t>(sample) * slot_count) % hwbp_offsets.size();
				for (size_t slot = 0; slot < slot_count; ++slot) {
					const uint64_t off = hwbp_offsets[(base_index + slot) % hwbp_offsets.size()];
					const uint64_t watch_addr = base_address + off;
					active_hwbp_addrs[slot] = watch_addr;
					for (size_t ti = 0; ti < hwbp_thread_count; ++ti) {
						const bool armed = driver_bridge::set_hardware_breakpoint(tids[ti], static_cast<int>(slot), watch_addr, 3, 0);
						if ((sample == 0 || sample + 1 == sample_count) && ti == 0) {
							diag::log_tagged_fmt("struct_recon", "monitor_hwbp_set pid=%u tid=%u slot=%zu offset=0x%llX addr=0x%llX armed=%d status=%s error=%s",
								pid,
								tids[ti],
								slot,
								static_cast<unsigned long long>(off),
								static_cast<unsigned long long>(watch_addr),
								armed ? 1 : 0,
								driver_bridge::status().c_str(),
								driver_bridge::last_error().c_str());
						}
					}
				}
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(50));

			float phase_progress = 0.3f + 0.5f * (static_cast<float>(sample) / static_cast<float>(sample_count));
			g_state.progress.store(phase_progress);

			if (use_hwbp_fallback && active_hwbp_addrs[0] != 0) {
				for (size_t ti = 0; ti < hwbp_thread_count; ++ti) {
					driver_bridge::thread_context_t ctx{};
					if (!driver_bridge::get_thread_context(tids[ti], ctx))
						continue;
					for (int slot = 0; slot < 4; ++slot) {
						if (active_hwbp_addrs[slot] == 0)
							continue;
						if (!insn_analysis::context_reports_hwbp_slot(ctx, slot, active_hwbp_addrs[slot]))
							continue;
						auto decoded = insn_analysis::analyze_captured_rip(ctx.rip, active_hwbp_addrs[slot], 3);
						rip_cache[ctx.rip] = decoded;
						record_access(ctx.rip,
						              active_hwbp_addrs[slot] - base_address,
						              decoded,
						              true,
						              "hwbp",
						              tids[ti],
						              static_cast<uint32_t>(sample),
						              0);
						driver_bridge::thread_context_t next = ctx;
						next.rflags |= 0x10000ull;
						next.dr6 = 0;
						driver_bridge::set_thread_context(tids[ti], next, (1ull << 17) | (1ull << 22));
						diag::log_tagged_fmt("struct_recon", "monitor_hwbp_hit pid=%u tid=%u slot=%d offset=0x%llX rip=0x%llX write=%d offsets=%zu elapsed_ms=%llu",
							pid,
							tids[ti],
							slot,
							static_cast<unsigned long long>(active_hwbp_addrs[slot] - base_address),
							static_cast<unsigned long long>(ctx.rip),
							decoded.is_write ? 1 : 0,
							offset_access_map.size(),
							static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
					}
				}
				for (size_t ti = 0; ti < hwbp_thread_count; ++ti) {
					for (int slot = 0; slot < 4; ++slot) {
						if (active_hwbp_addrs[slot] != 0)
							driver_bridge::clear_hardware_breakpoint(tids[ti], slot);
					}
				}
			}

			if (use_page_guard && pg_session_id != 0) {
				auto captures = page_guard_engine::g_pg_engine.get_captures(pg_session_id);
				if (!captures.empty() || sample == 0 || sample + 1 == sample_count) {
					diag::log_tagged_fmt("struct_recon", "monitor_sample_captures pid=%u sid=%u sample=%d captures=%zu offsets=%zu elapsed_ms=%llu",
						pid,
						pg_session_id,
						sample,
						captures.size(),
						offset_access_map.size(),
						static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
				}
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
					record_access(cap.rip,
					              field_offset,
					              decoded,
					              cap.access_type == 1,
					              "page_guard",
					              0,
					              static_cast<uint32_t>(sample),
					              pg_session_id);
				}
			}
		}
		diag::log_tagged_fmt("struct_recon", "monitor_sample_loop_end base=0x%llX pid=%u cancelled=%d offsets=%zu rip_cache=%zu elapsed_ms=%llu",
			static_cast<unsigned long long>(base_address),
			pid,
			g_state.cancel.load() ? 1 : 0,
			offset_access_map.size(),
			rip_cache.size(),
			static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));

		g_state.progress.store(0.8f);

		if (use_page_guard && pg_session_id != 0) {
			diag::log_tagged_fmt("struct_recon", "monitor_final_captures_begin pid=%u sid=%u offsets=%zu",
				pid,
				pg_session_id,
				offset_access_map.size());
			auto final_caps = page_guard_engine::g_pg_engine.get_captures(pg_session_id);
			diag::log_tagged_fmt("struct_recon", "monitor_final_captures_end pid=%u sid=%u captures=%zu elapsed_ms=%llu",
				pid,
				pg_session_id,
				final_caps.size(),
				static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
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
				record_access(cap.rip,
				              field_offset,
				              decoded,
				              cap.access_type == 1,
				              "page_guard",
				              0,
				              static_cast<uint32_t>((std::max)(sample_count, 0)),
				              pg_session_id);
			}
			diag::log_tagged_fmt("struct_recon", "monitor_page_guard_uninstall_begin pid=%u sid=%u", pid, pg_session_id);
			page_guard_engine::g_pg_engine.uninstall(pg_session_id);
			diag::log_tagged_fmt("struct_recon", "monitor_page_guard_uninstall_end pid=%u sid=%u elapsed_ms=%llu",
				pid,
				pg_session_id,
				static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
		}

		if (use_hwbp_fallback && !tids.empty()) {
			for (size_t ti = 0; ti < hwbp_thread_count; ++ti) {
				for (int i = 0; i < 4; ++i) {
					const bool cleared = driver_bridge::clear_hardware_breakpoint(tids[ti], i);
					if (ti == 0) {
						diag::log_tagged_fmt("struct_recon", "monitor_hwbp_clear pid=%u tid=%u slot=%d cleared=%d",
							pid,
							tids[ti],
							i,
							cleared ? 1 : 0);
					}
				}
			}
		}

		g_state.progress.store(0.85f);

		diag::log_tagged_fmt("struct_recon", "monitor_inference_begin base=0x%llX offsets=%zu rip_cache=%zu elapsed_ms=%llu",
			static_cast<unsigned long long>(base_address),
			offset_access_map.size(),
			rip_cache.size(),
			static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.access_log.clear();

			for (auto& entry : offset_access_map) {
				auto& access_rec = entry.second;
				g_state.access_log.push_back(access_rec);
			}

			for (auto& field : g_state.current.fields) {
				for (auto& entry : offset_access_map) {
					auto& access_rec = entry.second;
					const uint64_t off = access_rec.access_offset;
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

			for (auto& entry : offset_access_map) {
				auto& access_rec = entry.second;
				const uint64_t off = access_rec.access_offset;
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

			g_state.current.has_vtable = detail::has_proven_vtable_at_zero(g_state.current.fields);

			g_state.history.push_back(g_state.current);
			publish_current_locked();
			diag::log_tagged_fmt("struct_recon", "monitor_inference_state base=0x%llX fields=%zu access_log=%zu history=%zu has_vtable=%d",
				static_cast<unsigned long long>(base_address),
				g_state.current.fields.size(),
				g_state.access_log.size(),
				g_state.history.size(),
				g_state.current.has_vtable ? 1 : 0);
		}

		g_state.progress.store(1.f);
		g_state.monitoring.store(false);
		diag::log_tagged_fmt("struct_recon", "monitor_worker_exit base=0x%llX pid=%u cancelled=%d elapsed_ms=%llu",
			static_cast<unsigned long long>(base_address),
			pid,
			g_state.cancel.load() ? 1 : 0,
			static_cast<unsigned long long>(GetTickCount64() - worker_start_ms));
	};
	const bool posted = aida::infra::executor::submit(std::move(submission)).submitted;
	if (!posted) {
		g_state.monitoring.store(false);
		diag::log_tagged_fmt("struct_recon", "monitor_post_failed base=0x%llX size=%d name=%s",
			static_cast<unsigned long long>(base_address),
			struct_size,
			name.c_str());
	}
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

	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "struct_recon";
	submission.label = "struct_recon.ai_name_fields";
	submission.thread_class = "external_ai";
	submission.domain = aida::infra::executor::domain_t::external_tool;
	submission.priority = 3;
	submission.failure_policy = "reject_not_started";
	submission.body = [snapshot]() {
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
			publish_current_locked();
		}

		g_state.ai_naming.store(false);
	};
	if (!aida::infra::executor::submit(std::move(submission)).submitted) {
		diag::log_tagged_fmt("struct_recon", "ai_name_fields_post_failed base=0x%llX fields=%zu",
			static_cast<unsigned long long>(snapshot.base_address),
			snapshot.fields.size());
		g_state.ai_naming.store(false);
	}
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

inline bool refresh_value_history(std::string& error)
{
	uint64_t revision = 0;
	uint64_t base_address = 0;
	int total_size = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mutex);
		if (!g_state.active || g_state.current.base_address == 0 ||
			g_state.current.total_size <= 0 || g_state.current.fields.empty())
		{
			error = "No active reconstructed structure owns a readable live range";
			return false;
		}
		revision = g_state.current_revision;
		base_address = g_state.current.base_address;
		total_size = g_state.current.total_size;
	}

	std::vector<uint8_t> data;
	if (!driver_bridge::read_memory(base_address, static_cast<size_t>(total_size), data) ||
		data.size() != static_cast<size_t>(total_size)) {
		error = "The exact reconstructed live range could not be read";
		return false;
	}

	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (!g_state.active || g_state.current_revision != revision ||
		g_state.current.base_address != base_address ||
		g_state.current.total_size != total_size) {
		error = "The structure revision changed before live values could be published";
		return false;
	}

	for (auto& f : g_state.current.fields) {
		if (f.offset + static_cast<uint64_t>(f.size) > data.size()) continue;

		int elem_size = f.size;
		if (f.array_count > 1)
			elem_size = f.size / f.array_count;

		uint64_t val = 0;
		int read_sz = (std::min)(elem_size, 8);
		std::memcpy(&val, data.data() + f.offset, static_cast<size_t>(read_sz));
		f.value_history.push(val);

		auto scored = detail::infer_type_scored(data.data() + f.offset, elem_size, base_address);
		if (scored.score > f.type_confidence) {
			f.type_confidence = scored.score;
			if (scored.score >= 50.f && f.array_count <= 1)
				f.type = scored.type;
		}
	}
	publish_current_locked();
	error.clear();
	return true;
}

inline constexpr std::size_t max_persisted_structures = 1024;
inline constexpr std::size_t max_persisted_fields = 65536;
inline constexpr std::size_t max_persisted_vtable_entries = 4096;
inline constexpr std::uint64_t max_persisted_file_bytes = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t max_persisted_catalog_bytes = 256ULL * 1024ULL * 1024ULL;

inline std::filesystem::path get_struct_cache_dir()
{
	const char* appdata = std::getenv("APPDATA");
	if (!appdata || !*appdata) return {};
	return std::filesystem::path(appdata) / "AiDA" / "Standalone" / "structs";
}

inline std::filesystem::path persisted_struct_path(const reconstructed_struct_t& structure)
{
	std::string prefix;
	prefix.reserve(48);
	for (const unsigned char character : structure.name) {
		if (prefix.size() >= 48) break;
		if ((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-')
			prefix.push_back(static_cast<char>(character));
		else if (!prefix.empty() && prefix.back() != '_')
			prefix.push_back('_');
	}
	if (prefix.empty()) prefix = "structure";
	std::uint64_t hash = 1469598103934665603ULL;
	for (const unsigned char character : structure.name) {
		hash ^= character;
		hash *= 1099511628211ULL;
	}
	char suffix[24]{};
	std::snprintf(suffix, sizeof(suffix), "_%016llx.json",
		static_cast<unsigned long long>(hash));
	return get_struct_cache_dir() / (prefix + suffix);
}

inline bool validate_persisted_structure(const reconstructed_struct_t& structure,
	std::string& error)
{
	if (structure.name.empty() || structure.name.size() > 256) {
		error = "The structure name must contain between 1 and 256 bytes";
		return false;
	}
	if (structure.total_size <= 0 || structure.total_size > 1024 * 1024 ||
		structure.fields.empty() || structure.fields.size() > max_persisted_fields) {
		error = "The structure size or field count exceeds the persistence contract";
		return false;
	}
	for (const auto& field : structure.fields) {
		if (field.size <= 0 || field.offset > static_cast<std::uint64_t>(structure.total_size) ||
			static_cast<std::uint64_t>(field.size) >
				static_cast<std::uint64_t>(structure.total_size) - field.offset ||
			field.name.empty() || field.name.size() > 256 || field.comment.size() > 4096 ||
			field.array_count <= 0 || field.array_count > 1048576 ||
			!std::isfinite(field.type_confidence) || field.type_confidence < 0.f ||
			field.type_confidence > 100.f || static_cast<int>(field.type) < 0 ||
			static_cast<int>(field.type) >= static_cast<int>(field_type_t::COUNT) ||
			field.vtable_entries.size() > max_persisted_vtable_entries) {
			error = "A structure field violates the bounded persistence contract";
			return false;
		}
		for (const auto& entry : field.vtable_entries) {
			if (entry.index < 0 || entry.name.size() > 256) {
				error = "A virtual-table entry violates the bounded persistence contract";
				return false;
			}
		}
	}
	error.clear();
	return true;
}

inline bool write_persisted_structure(const std::filesystem::path& destination,
	const std::string& payload, std::string& error)
{
	if (payload.empty() || payload.size() > max_persisted_file_bytes) {
		error = "The serialized structure exceeds the 64 MiB persistence limit";
		return false;
	}
	const std::filesystem::path temporary = destination.wstring() + L".tmp-" +
		std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
	HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
	if (file == INVALID_HANDLE_VALUE) {
		error = "The structure temporary file could not be created";
		return false;
	}
	std::size_t written_total = 0;
	bool ok = true;
	while (written_total < payload.size()) {
		const DWORD requested = static_cast<DWORD>((std::min)(payload.size() - written_total,
			static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
		DWORD written = 0;
		if (!WriteFile(file, payload.data() + written_total, requested, &written, nullptr) ||
			written != requested) {
			ok = false;
			break;
		}
		written_total += written;
	}
	LARGE_INTEGER final_size{};
	if (ok && (!FlushFileBuffers(file) || !GetFileSizeEx(file, &final_size) ||
		final_size.QuadPart != static_cast<LONGLONG>(payload.size())))
		ok = false;
	if (!CloseHandle(file)) ok = false;
	if (ok && !MoveFileExW(temporary.c_str(), destination.c_str(),
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		ok = false;
	if (!ok) {
		DeleteFileW(temporary.c_str());
		error = "The structure file could not be written, flushed, verified and atomically replaced";
		return false;
	}
	error.clear();
	return true;
}

inline bool save_struct_to_disk(const reconstructed_struct_t& structure, std::string& error)
{
	std::lock_guard<std::mutex> persistence_lock(g_state.persistence_mutex);
	if (!validate_persisted_structure(structure, error)) return false;
	{
		std::lock_guard<std::mutex> lock(g_state.mutex);
		const bool replacing = std::any_of(g_state.saved_structs.begin(),
			g_state.saved_structs.end(), [&](const reconstructed_struct_t& item) {
				return item.name == structure.name;
			});
		if (!replacing && g_state.saved_structs.size() >= max_persisted_structures) {
			error = "The structure catalog already contains 1024 records";
			return false;
		}
	}
	const auto directory = get_struct_cache_dir();
	if (directory.empty()) {
		error = "The per-user structure persistence directory is unavailable";
		return false;
	}
	std::error_code ec;
	std::filesystem::create_directories(directory, ec);
	if (ec) {
		error = "The per-user structure persistence directory could not be created";
		return false;
	}
	nlohmann::json json;
	json["version"] = 2;
	json["name"] = structure.name;
	json["base_address"] = structure.base_address;
	json["total_size"] = structure.total_size;
	json["has_vtable"] = structure.has_vtable;
	json["vtable_address"] = structure.vtable_address;
	json["fields"] = nlohmann::json::array();
	for (const auto& field : structure.fields) {
		nlohmann::json record{{"offset", field.offset}, {"size", field.size},
			{"type", static_cast<int>(field.type)}, {"name", field.name},
			{"comment", field.comment}, {"type_confidence", field.type_confidence},
			{"array_count", field.array_count}};
		if (!field.vtable_entries.empty()) {
			record["vtable_entries"] = nlohmann::json::array();
			for (const auto& entry : field.vtable_entries)
				record["vtable_entries"].push_back({{"func_addr", entry.func_addr},
					{"index", entry.index}, {"name", entry.name}});
		}
		json["fields"].push_back(std::move(record));
	}
	const std::string payload = json.dump(2);
	if (!write_persisted_structure(persisted_struct_path(structure), payload, error))
		return false;
	{
		std::lock_guard<std::mutex> lock(g_state.mutex);
		auto found = std::find_if(g_state.saved_structs.begin(), g_state.saved_structs.end(),
			[&](const reconstructed_struct_t& item) { return item.name == structure.name; });
		if (found != g_state.saved_structs.end())
			*found = structure;
		else if (g_state.saved_structs.size() < max_persisted_structures)
			g_state.saved_structs.push_back(structure);
	}
	error.clear();
	return true;
}

inline bool parse_persisted_structure(const nlohmann::json& json,
	reconstructed_struct_t& structure, std::string& error, int& format_version)
{
	format_version = 1;
	if (json.is_object() && json.contains("version")) {
		if (!json["version"].is_number_integer() || json["version"].get<int>() != 2) {
			error = "A structure file uses an unsupported persistence version";
			return false;
		}
		format_version = 2;
	}
	if (!json.is_object() || !json.contains("name") ||
		!json["name"].is_string() || !json.contains("base_address") ||
		!json["base_address"].is_number_unsigned() || !json.contains("total_size") ||
		!json["total_size"].is_number_integer() || !json.contains("fields") ||
		!json["fields"].is_array() || json["fields"].size() > max_persisted_fields) {
		error = "A structure file has an unsupported or malformed root record";
		return false;
	}
	structure = {};
	const auto total_size = json["total_size"].get<std::int64_t>();
	if (total_size <= 0 || total_size > 1024 * 1024) {
		error = "A structure file contains an invalid total size";
		return false;
	}
	structure.name = json["name"].get<std::string>();
	structure.base_address = json["base_address"].get<std::uint64_t>();
	structure.total_size = static_cast<int>(total_size);
	if ((json.contains("has_vtable") && !json["has_vtable"].is_boolean()) ||
		(json.contains("vtable_address") && !json["vtable_address"].is_number_unsigned())) {
		error = "A structure file contains malformed virtual-table metadata";
		return false;
	}
	structure.has_vtable = json.value("has_vtable", false);
	structure.vtable_address = json.value("vtable_address", std::uint64_t{0});
	for (const auto& record : json["fields"]) {
		if (!record.is_object() || !record.contains("offset") || !record["offset"].is_number_unsigned() ||
			!record.contains("size") || !record["size"].is_number_integer() ||
			!record.contains("type") || !record["type"].is_number_integer() ||
			!record.contains("name") || !record["name"].is_string() ||
			!record.contains("comment") || !record["comment"].is_string() ||
			!record.contains("type_confidence") || !record["type_confidence"].is_number() ||
			!record.contains("array_count") || !record["array_count"].is_number_integer()) {
			error = "A structure file contains a malformed field record";
			return false;
		}
		struct_field_t field;
		const auto field_size = record["size"].get<std::int64_t>();
		const auto field_type = record["type"].get<std::int64_t>();
		const auto array_count = record["array_count"].get<std::int64_t>();
		if (field_size <= 0 || field_size > 1024 * 1024 || field_type < 0 ||
			field_type >= static_cast<std::int64_t>(field_type_t::COUNT) ||
			array_count <= 0 || array_count > 1048576) {
			error = "A structure file contains an out-of-range field value";
			return false;
		}
		field.offset = record["offset"].get<std::uint64_t>();
		field.size = static_cast<int>(field_size);
		field.type = static_cast<field_type_t>(field_type);
		field.name = record["name"].get<std::string>();
		field.comment = record["comment"].get<std::string>();
		field.type_confidence = record["type_confidence"].get<float>();
		field.array_count = static_cast<int>(array_count);
		if (record.contains("vtable_entries")) {
			if (!record["vtable_entries"].is_array() ||
				record["vtable_entries"].size() > max_persisted_vtable_entries) {
				error = "A structure file contains an oversized virtual-table record";
				return false;
			}
			for (const auto& item : record["vtable_entries"]) {
				if (!item.is_object() || !item.contains("func_addr") ||
					!item["func_addr"].is_number_unsigned() || !item.contains("index") ||
					!item["index"].is_number_integer() || !item.contains("name") ||
					!item["name"].is_string()) {
					error = "A structure file contains a malformed virtual-table entry";
					return false;
				}
				field.vtable_entries.push_back({item["func_addr"].get<std::uint64_t>(),
					item["index"].get<int>(), item["name"].get<std::string>()});
			}
		}
		structure.fields.push_back(std::move(field));
	}
	if (!validate_persisted_structure(structure, error)) return false;
	for (auto& field : structure.fields) detail::enforce_vtable_field_proof(field);
	std::sort(structure.fields.begin(), structure.fields.end(),
		[](const struct_field_t& left, const struct_field_t& right) {
			return left.offset < right.offset;
		});
	structure.has_vtable = detail::has_proven_vtable_at_zero(structure.fields);
	if (!structure.has_vtable) structure.vtable_address = 0;
	error.clear();
	return true;
}

inline bool load_structs_from_disk(std::string& error)
{
	std::lock_guard<std::mutex> persistence_lock(g_state.persistence_mutex);
	{
		std::lock_guard<std::mutex> lock(g_state.mutex);
		if (g_state.disk_cache_loaded) {
			error.clear();
			return true;
		}
		if (g_state.disk_cache_loading) {
			error = "A structure catalog load is already running";
			return false;
		}
		g_state.disk_cache_loading = true;
	}
	const auto finish = [](bool loaded) {
		std::lock_guard<std::mutex> lock(g_state.mutex);
		g_state.disk_cache_loading = false;
		if (loaded) g_state.disk_cache_loaded = true;
	};
	const auto directory = get_struct_cache_dir();
	if (directory.empty()) {
		error = "The per-user structure persistence directory is unavailable";
		finish(false);
		return false;
	}
	std::error_code ec;
	if (!std::filesystem::exists(directory, ec)) {
		if (ec) {
			error = "The structure persistence directory could not be inspected";
			finish(false);
			return false;
		}
		finish(true);
		error.clear();
		return true;
	}
	struct loaded_structure_t {
		reconstructed_struct_t structure;
		int format_version = 1;
	};
	std::vector<loaded_structure_t> loaded;
	std::uint64_t aggregate_bytes = 0;
	std::size_t directory_entries = 0;
	for (std::filesystem::directory_iterator iterator(directory, ec), end;
		!ec && iterator != end; iterator.increment(ec)) {
		if (++directory_entries > 4096) {
			error = "The structure persistence directory exceeds 4096 entries";
			finish(false);
			return false;
		}
		if (!iterator->is_regular_file(ec) || ec || iterator->path().extension() != ".json")
			continue;
		const auto size = iterator->file_size(ec);
		if (ec || size == 0 || size > max_persisted_file_bytes ||
			aggregate_bytes > max_persisted_catalog_bytes - size) {
			error = "A structure file or aggregate catalog exceeds its persistence bound";
			finish(false);
			return false;
		}
		aggregate_bytes += size;
		std::ifstream input(iterator->path(), std::ios::binary);
		if (!input) {
			error = "A structure file could not be opened";
			finish(false);
			return false;
		}
		std::string payload(static_cast<std::size_t>(size), '\0');
		input.read(payload.data(), static_cast<std::streamsize>(payload.size()));
		if (input.gcount() != static_cast<std::streamsize>(payload.size())) {
			error = "A structure file completed with a short read";
			finish(false);
			return false;
		}
		const auto json = nlohmann::json::parse(payload, nullptr, false);
		reconstructed_struct_t structure;
		int format_version = 1;
		if (json.is_discarded() || !parse_persisted_structure(json, structure, error,
				format_version)) {
			if (error.empty()) error = "A structure file contains malformed JSON";
			finish(false);
			return false;
		}
		auto duplicate = std::find_if(loaded.begin(), loaded.end(),
			[&](const loaded_structure_t& item) {
				return item.structure.name == structure.name;
			});
		if (duplicate == loaded.end()) {
			if (loaded.size() >= max_persisted_structures) {
				error = "The structure catalog exceeds 1024 unique records";
				finish(false);
				return false;
			}
			loaded.push_back({std::move(structure), format_version});
		} else if (format_version > duplicate->format_version)
			*duplicate = {std::move(structure), format_version};
	}
	if (ec) {
		error = "The structure persistence directory could not be enumerated completely";
		finish(false);
		return false;
	}
	std::sort(loaded.begin(), loaded.end(), [](const auto& left, const auto& right) {
		return left.structure.name < right.structure.name;
	});
	std::vector<reconstructed_struct_t> staging;
	staging.reserve(loaded.size());
	for (auto& item : loaded) staging.push_back(std::move(item.structure));
	{
		std::lock_guard<std::mutex> lock(g_state.mutex);
		g_state.saved_structs = std::move(staging);
		if (!g_state.saved_structs.empty()) {
			g_state.current = g_state.saved_structs.front();
			g_state.active = true;
			publish_current_locked();
		}
		g_state.disk_cache_loading = false;
		g_state.disk_cache_loaded = true;
	}
	error.clear();
	return true;
}

inline void cancel()
{
	g_state.cancel.store(true);
}

}
