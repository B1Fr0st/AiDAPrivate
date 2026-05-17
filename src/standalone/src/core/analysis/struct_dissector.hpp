#pragma once

#include "standalone_driver.hpp"
#include "../infra/work_queue.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace struct_dissector {

enum class field_type_t : int {
	int8 = 0,
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
	ascii_string,
	utf16_string,
	byte_array,
	padding,
	nested_struct,
	COUNT
};

struct field_def_t {
	std::string   name;
	field_type_t  type = field_type_t::int32;
	uint32_t      offset = 0;
	uint32_t      size = 0;
	uint32_t      array_count = 1;
	int           parent_idx = -1;
	std::vector<int> children;
	bool          is_pointer = false;
	int           pointer_target_struct = -1;
	std::string   description;
};

struct struct_def_t {
	std::string              name;
	std::vector<field_def_t> fields;
	uint32_t                 total_size = 0;
};

struct live_value_t {
	std::vector<uint8_t> raw_bytes;
	std::string          display_text;
	bool                 changed = false;
};

struct state_t {
	std::vector<struct_def_t> structs;
	int                       active_struct = -1;
	uint64_t                  base_address = 0;
	std::vector<live_value_t> cached_values;
	std::mutex                mtx;
	bool                      auto_refresh = false;
	float                     refresh_interval = 0.5f;
	float                     refresh_timer = 0.f;
	std::atomic<bool>         refresh_in_flight{false};
	std::atomic<uint64_t>     refresh_seq{0};
	std::atomic<uint64_t>     last_completed_seq{0};
};

inline state_t g_state;

inline const char* field_type_name(field_type_t t) {
	static const char* names[] = {
		"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
		"Int64", "UInt64", "Float", "Double", "Pointer",
		"ASCII String", "UTF-16 String", "Byte Array", "Padding", "Struct"
	};
	int idx = static_cast<int>(t);
	if (idx >= 0 && idx < static_cast<int>(field_type_t::COUNT))
		return names[idx];
	return "Unknown";
}

inline size_t field_type_size(field_type_t t) {
	switch (t) {
	case field_type_t::int8:          return 1;
	case field_type_t::uint8:         return 1;
	case field_type_t::int16:         return 2;
	case field_type_t::uint16:        return 2;
	case field_type_t::int32:         return 4;
	case field_type_t::uint32:        return 4;
	case field_type_t::int64:         return 8;
	case field_type_t::uint64:        return 8;
	case field_type_t::float32:       return 4;
	case field_type_t::float64:       return 8;
	case field_type_t::pointer:       return 8;
	case field_type_t::ascii_string:  return 0;
	case field_type_t::utf16_string:  return 0;
	case field_type_t::byte_array:    return 0;
	case field_type_t::padding:       return 0;
	case field_type_t::nested_struct: return 0;
	default:                          return 4;
	}
}

inline std::string format_field_value(const std::vector<uint8_t>& bytes, field_type_t type) {
	if (bytes.empty()) return "<no data>";
	char buf[128];
	switch (type) {
	case field_type_t::int8: {
		int8_t v = 0;
		std::memcpy(&v, bytes.data(), std::min<size_t>(bytes.size(), 1));
		std::snprintf(buf, sizeof(buf), "%d", v);
		return buf;
	}
	case field_type_t::uint8: {
		uint8_t v = bytes[0];
		std::snprintf(buf, sizeof(buf), "%u (0x%02X)", v, v);
		return buf;
	}
	case field_type_t::int16: {
		int16_t v = 0;
		if (bytes.size() >= 2) std::memcpy(&v, bytes.data(), 2);
		std::snprintf(buf, sizeof(buf), "%d", v);
		return buf;
	}
	case field_type_t::uint16: {
		uint16_t v = 0;
		if (bytes.size() >= 2) std::memcpy(&v, bytes.data(), 2);
		std::snprintf(buf, sizeof(buf), "%u (0x%04X)", v, v);
		return buf;
	}
	case field_type_t::int32: {
		int32_t v = 0;
		if (bytes.size() >= 4) std::memcpy(&v, bytes.data(), 4);
		std::snprintf(buf, sizeof(buf), "%d (0x%08X)", v, static_cast<uint32_t>(v));
		return buf;
	}
	case field_type_t::uint32: {
		uint32_t v = 0;
		if (bytes.size() >= 4) std::memcpy(&v, bytes.data(), 4);
		std::snprintf(buf, sizeof(buf), "%u (0x%08X)", v, v);
		return buf;
	}
	case field_type_t::int64: {
		int64_t v = 0;
		if (bytes.size() >= 8) std::memcpy(&v, bytes.data(), 8);
		std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
		return buf;
	}
	case field_type_t::uint64: {
		uint64_t v = 0;
		if (bytes.size() >= 8) std::memcpy(&v, bytes.data(), 8);
		std::snprintf(buf, sizeof(buf), "%llu (0x%016llX)", static_cast<unsigned long long>(v), static_cast<unsigned long long>(v));
		return buf;
	}
	case field_type_t::float32: {
		float v = 0.f;
		if (bytes.size() >= 4) std::memcpy(&v, bytes.data(), 4);
		std::snprintf(buf, sizeof(buf), "%.6g", v);
		return buf;
	}
	case field_type_t::float64: {
		double v = 0.0;
		if (bytes.size() >= 8) std::memcpy(&v, bytes.data(), 8);
		std::snprintf(buf, sizeof(buf), "%.10g", v);
		return buf;
	}
	case field_type_t::pointer: {
		uint64_t v = 0;
		if (bytes.size() >= 8) std::memcpy(&v, bytes.data(), 8);
		std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(v));
		return buf;
	}
	case field_type_t::ascii_string: {
		std::string s;
		s.reserve(bytes.size());
		for (auto b : bytes) {
			if (b == 0) break;
			s += (b >= 0x20 && b <= 0x7E) ? static_cast<char>(b) : '.';
		}
		return "\"" + s + "\"";
	}
	case field_type_t::utf16_string: {
		std::string s;
		for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
			uint16_t ch = 0;
			std::memcpy(&ch, bytes.data() + i, 2);
			if (ch == 0) break;
			if (ch >= 0x20 && ch < 0x7F)
				s += static_cast<char>(ch);
			else
				s += '.';
		}
		return "L\"" + s + "\"";
	}
	case field_type_t::byte_array:
	case field_type_t::padding: {
		std::string hex;
		size_t limit = std::min<size_t>(bytes.size(), 32);
		for (size_t i = 0; i < limit; ++i) {
			if (!hex.empty()) hex += ' ';
			char h[4];
			std::snprintf(h, sizeof(h), "%02X", bytes[i]);
			hex += h;
		}
		if (bytes.size() > limit) hex += " ...";
		return hex;
	}
	case field_type_t::nested_struct:
		return "{...}";
	default:
		return "<unknown>";
	}
}

inline void recalc_total_size(struct_def_t& sd) {
	uint32_t max_end = 0;
	for (const auto& f : sd.fields) {
		uint32_t fsz = f.size;
		if (fsz == 0) {
			size_t ts = field_type_size(f.type);
			fsz = static_cast<uint32_t>(ts > 0 ? ts : 1);
		}
		uint32_t end = f.offset + fsz * f.array_count;
		if (end > max_end) max_end = end;
	}
	sd.total_size = max_end;
}

inline int create_struct(const std::string& name) {
	int idx = -1;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		struct_def_t sd;
		sd.name = name;
		sd.total_size = 0;
		g_state.structs.push_back(std::move(sd));
		idx = static_cast<int>(g_state.structs.size()) - 1;
	}
	diag::log_tagged_fmt("dissector",
		"create_struct name='%s' idx=%d total=%zu",
		name.c_str(), idx, static_cast<size_t>(idx + 1));
	return idx;
}

inline int add_field(int struct_idx, const field_def_t& field) {
	int idx = -1;
	uint32_t total_after = 0;
	std::string sd_name;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (struct_idx < 0 || struct_idx >= static_cast<int>(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"add_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return -1;
		}
		auto& sd = g_state.structs[struct_idx];
		field_def_t f = field;
		if (f.size == 0) {
			size_t ts = field_type_size(f.type);
			f.size = static_cast<uint32_t>(ts > 0 ? ts : 1);
		}
		idx = static_cast<int>(sd.fields.size());
		if (f.parent_idx >= 0 && f.parent_idx < static_cast<int>(sd.fields.size()))
			sd.fields[f.parent_idx].children.push_back(idx);
		sd.fields.push_back(std::move(f));
		recalc_total_size(sd);
		total_after = sd.total_size;
		sd_name = sd.name;
	}
	diag::log_tagged_fmt("dissector",
		"add_field struct='%s' field='%s' offset=0x%X size=%u type=%s field_idx=%d total=%u",
		sd_name.c_str(),
		field.name.c_str(),
		field.offset,
		field.size,
		field_type_name(field.type),
		idx,
		total_after);
	return idx;
}

inline bool remove_field(int struct_idx, int field_idx) {
	std::string removed_name;
	std::string sd_name;
	uint32_t total_after = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (struct_idx < 0 || struct_idx >= static_cast<int>(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"remove_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[struct_idx];
		if (field_idx < 0 || field_idx >= static_cast<int>(sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"remove_field rejected reason='bad_field_idx' struct='%s' field_idx=%d field_count=%zu",
				sd.name.c_str(), field_idx, sd.fields.size());
			return false;
		}
		removed_name = sd.fields[field_idx].name;
		sd_name = sd.name;
		int parent = sd.fields[field_idx].parent_idx;
		if (parent >= 0 && parent < static_cast<int>(sd.fields.size())) {
			auto& pc = sd.fields[parent].children;
			pc.erase(std::remove(pc.begin(), pc.end(), field_idx), pc.end());
		}
		sd.fields.erase(sd.fields.begin() + field_idx);
		for (auto& f : sd.fields) {
			if (f.parent_idx > field_idx) --f.parent_idx;
			else if (f.parent_idx == field_idx) f.parent_idx = -1;
			for (auto& ci : f.children) {
				if (ci > field_idx) --ci;
			}
			f.children.erase(
				std::remove_if(f.children.begin(), f.children.end(),
					[&](int c) { return c < 0 || c >= static_cast<int>(sd.fields.size()); }),
				f.children.end());
		}
		recalc_total_size(sd);
		total_after = sd.total_size;
	}
	diag::log_tagged_fmt("dissector",
		"remove_field struct='%s' field='%s' idx=%d total=%u",
		sd_name.c_str(), removed_name.c_str(), field_idx, total_after);
	return true;
}

inline bool rename_struct(int struct_idx, const std::string& new_name) {
	std::string old_name;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (struct_idx < 0 || struct_idx >= static_cast<int>(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_struct rejected reason='bad_idx' idx=%d", struct_idx);
			return false;
		}
		if (new_name.empty()) {
			diag::log_tagged_fmt("dissector",
				"rename_struct rejected reason='empty_name' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[struct_idx];
		old_name = sd.name;
		sd.name = new_name;
	}
	diag::log_tagged_fmt("dissector",
		"rename_struct idx=%d old='%s' new='%s'",
		struct_idx, old_name.c_str(), new_name.c_str());
	return true;
}

inline bool rename_field(int struct_idx, int field_idx, const std::string& new_name) {
	std::string sd_name, old_name;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (struct_idx < 0 || struct_idx >= static_cast<int>(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[struct_idx];
		if (field_idx < 0 || field_idx >= static_cast<int>(sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_field rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		sd_name = sd.name;
		old_name = sd.fields[field_idx].name;
		sd.fields[field_idx].name = new_name;
	}
	diag::log_tagged_fmt("dissector",
		"rename_field struct='%s' field_idx=%d old='%s' new='%s'",
		sd_name.c_str(), field_idx, old_name.c_str(), new_name.c_str());
	return true;
}

inline bool retype_field(int struct_idx, int field_idx, field_type_t new_type) {
	std::string sd_name, fname;
	field_type_t old_type = field_type_t::int32;
	uint32_t total_after = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (struct_idx < 0 || struct_idx >= static_cast<int>(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"retype_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[struct_idx];
		if (field_idx < 0 || field_idx >= static_cast<int>(sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"retype_field rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		auto& f = sd.fields[field_idx];
		old_type = f.type;
		f.type = new_type;
		size_t ts = field_type_size(new_type);
		if (ts > 0) {
			f.size = static_cast<uint32_t>(ts);
		} else if (f.size == 0) {
			f.size = 1;
		}
		recalc_total_size(sd);
		sd_name = sd.name;
		fname = f.name;
		total_after = sd.total_size;
	}
	diag::log_tagged_fmt("dissector",
		"retype_field struct='%s' field='%s' old=%s new=%s total=%u",
		sd_name.c_str(), fname.c_str(),
		field_type_name(old_type), field_type_name(new_type), total_after);
	return true;
}

inline bool set_field_size(int struct_idx, int field_idx, uint32_t new_size) {
	std::string sd_name, fname;
	uint32_t old_size = 0;
	uint32_t total_after = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (struct_idx < 0 || struct_idx >= static_cast<int>(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_size rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[struct_idx];
		if (field_idx < 0 || field_idx >= static_cast<int>(sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_size rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		if (new_size == 0 || new_size > 65536u) {
			diag::log_tagged_fmt("dissector",
				"set_field_size rejected reason='bad_size' new=%u", new_size);
			return false;
		}
		auto& f = sd.fields[field_idx];
		old_size = f.size;
		f.size = new_size;
		recalc_total_size(sd);
		sd_name = sd.name;
		fname = f.name;
		total_after = sd.total_size;
	}
	diag::log_tagged_fmt("dissector",
		"set_field_size struct='%s' field='%s' old=%u new=%u total=%u",
		sd_name.c_str(), fname.c_str(), old_size, new_size, total_after);
	return true;
}

inline bool set_field_comment(int struct_idx, int field_idx, const std::string& comment) {
	std::string sd_name, fname;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (struct_idx < 0 || struct_idx >= static_cast<int>(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_comment rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[struct_idx];
		if (field_idx < 0 || field_idx >= static_cast<int>(sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_comment rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		sd.fields[field_idx].description = comment;
		sd_name = sd.name;
		fname = sd.fields[field_idx].name;
	}
	diag::log_tagged_fmt("dissector",
		"set_field_comment struct='%s' field='%s' bytes=%zu",
		sd_name.c_str(), fname.c_str(), comment.size());
	return true;
}

inline void refresh_values() {
	if (!driver_bridge::is_loaded()) {
		diag::log_tagged_fmt("dissector",
			"refresh_values skipped reason='driver_not_loaded'");
		return;
	}

	bool expected = false;
	if (!g_state.refresh_in_flight.compare_exchange_strong(expected, true)) {
		diag::log_tagged_fmt("dissector",
			"refresh_values skipped reason='in_flight'");
		return;
	}

	uint64_t base = 0;
	uint32_t total_size = 0;
	int active = -1;
	size_t field_count = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		active = g_state.active_struct;
		if (active < 0 || active >= static_cast<int>(g_state.structs.size())) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values skipped reason='no_active_struct'");
			return;
		}
		if (g_state.base_address == 0) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values skipped reason='base_addr_zero' active=%d", active);
			return;
		}
		const auto& sd = g_state.structs[active];
		if (sd.total_size == 0) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values skipped reason='total_size_zero' name='%s'",
				sd.name.c_str());
			return;
		}
		base = g_state.base_address;
		total_size = sd.total_size;
		field_count = sd.fields.size();
	}

	uint64_t seq = g_state.refresh_seq.fetch_add(1) + 1;

	work_queue::post([base, total_size, active, seq, field_count]() {
		std::vector<uint8_t> block;
		bool ok = driver_bridge::read_memory(base, total_size, block);
		if (!ok || block.empty()) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values_read_failed base=0x%llX size=%u",
				static_cast<unsigned long long>(base), total_size);
			return;
		}

		size_t changed_count = 0;
		size_t oor_count = 0;
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			if (active < 0 || active >= static_cast<int>(g_state.structs.size())) {
				g_state.refresh_in_flight.store(false);
				return;
			}
			if (g_state.last_completed_seq.load() > seq) {
				g_state.refresh_in_flight.store(false);
				return;
			}
			const auto& sd = g_state.structs[active];
			g_state.cached_values.resize(sd.fields.size());
			for (size_t i = 0; i < sd.fields.size(); ++i) {
				const auto& f = sd.fields[i];
				uint32_t fsz = f.size * f.array_count;
				if (static_cast<uint64_t>(f.offset) + static_cast<uint64_t>(fsz) > block.size()) {
					g_state.cached_values[i].display_text = "<out of range>";
					g_state.cached_values[i].changed = false;
					++oor_count;
					continue;
				}
				std::vector<uint8_t> raw(block.begin() + f.offset,
					block.begin() + f.offset + fsz);
				bool changed = (raw != g_state.cached_values[i].raw_bytes);
				g_state.cached_values[i].raw_bytes = std::move(raw);
				g_state.cached_values[i].display_text =
					format_field_value(g_state.cached_values[i].raw_bytes, f.type);
				g_state.cached_values[i].changed = changed;
				if (changed) ++changed_count;
			}
			g_state.last_completed_seq.store(seq);
		}

		g_state.refresh_in_flight.store(false);
		diag::log_tagged_fmt("dissector",
			"refresh_values_done base=0x%llX size=%u fields=%zu changed=%zu oor=%zu seq=%llu",
			static_cast<unsigned long long>(base), total_size,
			field_count, changed_count, oor_count,
			static_cast<unsigned long long>(seq));
	});
}

inline std::string auto_detect_type(uint64_t address, size_t size) {
	if (!driver_bridge::is_loaded()) return "unknown";
	if (size == 0) size = 8;
	std::vector<uint8_t> bytes;
	if (!driver_bridge::read_memory(address, size, bytes) || bytes.empty())
		return "unknown";

	if (bytes.size() >= 8) {
		uint64_t v = 0;
		std::memcpy(&v, bytes.data(), 8);
		if (v >= 0x10000ULL && v < 0x00007FFFFFFFFFFFULL && (v & 0xFFF) == 0)
			return "pointer (aligned)";
		if (v >= 0x10000ULL && v < 0x00007FFFFFFFFFFFULL)
			return "pointer";
	}
	if (bytes.size() >= 4) {
		float fv = 0.f;
		std::memcpy(&fv, bytes.data(), 4);
		if (std::isfinite(fv) && std::fabs(fv) > 1e-30f && std::fabs(fv) < 1e30f)
			return "float32";
	}
	if (bytes.size() >= 4) {
		int32_t iv = 0;
		std::memcpy(&iv, bytes.data(), 4);
		if (iv >= -1000000 && iv <= 1000000)
			return "int32";
	}
	bool all_printable = true;
	for (size_t i = 0; i < bytes.size(); ++i) {
		if (bytes[i] == 0) break;
		if (bytes[i] < 0x20 || bytes[i] > 0x7E) { all_printable = false; break; }
	}
	if (all_printable && bytes.size() >= 4 && bytes[0] >= 0x20)
		return "ascii_string";

	return "byte_array";
}

inline std::string export_to_c(int struct_idx) {
	std::lock_guard<std::mutex> lk(g_state.mtx);
	if (struct_idx < 0 || struct_idx >= static_cast<int>(g_state.structs.size())) {
		diag::log_tagged_fmt("dissector",
			"export_to_c rejected reason='bad_idx' idx=%d", struct_idx);
		return {};
	}
	const auto& sd = g_state.structs[struct_idx];
	std::string out;
	out += "typedef struct {\n";
	for (const auto& f : sd.fields) {
		if (f.parent_idx >= 0) continue;
		out += "    ";
		switch (f.type) {
		case field_type_t::int8:          out += "int8_t"; break;
		case field_type_t::uint8:         out += "uint8_t"; break;
		case field_type_t::int16:         out += "int16_t"; break;
		case field_type_t::uint16:        out += "uint16_t"; break;
		case field_type_t::int32:         out += "int32_t"; break;
		case field_type_t::uint32:        out += "uint32_t"; break;
		case field_type_t::int64:         out += "int64_t"; break;
		case field_type_t::uint64:        out += "uint64_t"; break;
		case field_type_t::float32:       out += "float"; break;
		case field_type_t::float64:       out += "double"; break;
		case field_type_t::pointer:       out += "void*"; break;
		case field_type_t::ascii_string:  out += "char"; break;
		case field_type_t::utf16_string:  out += "wchar_t"; break;
		case field_type_t::byte_array:    out += "uint8_t"; break;
		case field_type_t::padding:       out += "uint8_t"; break;
		case field_type_t::nested_struct: out += "uint8_t"; break;
		default:                          out += "uint8_t"; break;
		}
		out += " ";
		out += f.name.empty() ? "field_" + std::to_string(f.offset) : f.name;
		if (f.type == field_type_t::ascii_string || f.type == field_type_t::utf16_string ||
			f.type == field_type_t::byte_array || f.type == field_type_t::padding ||
			f.type == field_type_t::nested_struct) {
			out += "[" + std::to_string(f.size * f.array_count) + "]";
		} else if (f.array_count > 1) {
			out += "[" + std::to_string(f.array_count) + "]";
		}
		out += ";";
		if (!f.description.empty())
			out += " /* " + f.description + " */";
		out += "\n";
	}
	out += "} " + sd.name + "_t;\n";
	diag::log_tagged_fmt("dissector",
		"export_to_c name='%s' fields=%zu bytes=%zu",
		sd.name.c_str(), sd.fields.size(), out.size());
	return out;
}

}
