#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/re_hubs_preview_adapter.hpp"
#else
#include "standalone_driver.hpp"
#include "../infra/executor.hpp"
#include "../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
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

inline bool valid_index(int index, std::size_t count) {
	return index >= 0 && static_cast<std::size_t>(index) < count;
}

inline bool index_fits_int(std::size_t index) {
	return index <= static_cast<std::size_t>((std::numeric_limits<int>::max)());
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline void ensure_preview_fixture() {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!g_state.structs.empty())
		return;
	struct_def_t context;
	context.name = "IMAGE_RUNTIME_CONTEXT";
	context.fields = {
		{"image_base", field_type_t::pointer, 0x00, 8, 1, -1, {}, true, -1, "Mapped image base"},
		{"entry_point", field_type_t::pointer, 0x08, 8, 1, -1, {}, true, -1, "Resolved entry point"},
		{"image_size", field_type_t::uint32, 0x10, 4, 1, -1, {}, false, -1, "Size of image"},
		{"machine", field_type_t::uint16, 0x14, 2, 1, -1, {}, false, -1, "PE machine type"},
		{"section_count", field_type_t::uint16, 0x16, 2, 1, -1, {}, false, -1, "Number of sections"},
		{"flags", field_type_t::uint32, 0x18, 4, 1, -1, {}, false, -1, "Analysis flags"},
		{"module_name", field_type_t::ascii_string, 0x20, 16, 1, -1, {}, false, -1, "Target module"}
	};
	context.total_size = 0x30;
	struct_def_t node;
	node.name = "CONTROL_FLOW_NODE";
	node.fields = {
		{"address", field_type_t::pointer, 0x00, 8, 1, -1, {}, true, -1, "Block start"},
		{"successors", field_type_t::pointer, 0x08, 8, 1, -1, {}, true, -1, "Successor array"},
		{"successor_count", field_type_t::uint32, 0x10, 4, 1, -1, {}, false, -1, "Outgoing edge count"},
		{"instruction_count", field_type_t::uint32, 0x14, 4, 1, -1, {}, false, -1, "Instruction count"},
		{"flags", field_type_t::uint64, 0x18, 8, 1, -1, {}, false, -1, "Node flags"},
		{"confidence", field_type_t::float32, 0x20, 4, 1, -1, {}, false, -1, "Recovery confidence"}
	};
	node.total_size = 0x24;
	g_state.structs = {std::move(context), std::move(node)};
	g_state.active_struct = 0;
	g_state.base_address = 0x0000000140005000ULL;
}
#endif

inline const char* field_type_name(field_type_t t) {
	static const char* names[] = {
		"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
		"Int64", "UInt64", "Float", "Double", "Pointer",
		"ASCII String", "UTF-16 String", "Byte Array", "Padding", "Struct"
	};
	int idx = static_cast<int>(t);
	if (valid_index(idx, static_cast<std::size_t>(field_type_t::COUNT)))
		return names[static_cast<std::size_t>(idx)];
	return "Unknown";
}

inline std::size_t field_type_size(field_type_t t) {
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
		std::memcpy(&v, bytes.data(), (std::min)(bytes.size(), std::size_t{1}));
		std::snprintf(buf, sizeof(buf), "%d", v);
		return buf;
	}
	case field_type_t::uint8: {
		uint8_t v = bytes[0];
		std::snprintf(buf, sizeof(buf), "%u (0x%02X)",
			static_cast<unsigned int>(v), static_cast<unsigned int>(v));
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
		std::snprintf(buf, sizeof(buf), "%u (0x%04X)",
			static_cast<unsigned int>(v), static_cast<unsigned int>(v));
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
		for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
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
		std::size_t limit = (std::min)(bytes.size(), std::size_t{32});
		for (std::size_t i = 0; i < limit; ++i) {
			if (!hex.empty()) hex += ' ';
			char h[4];
			std::snprintf(h, sizeof(h), "%02X", static_cast<unsigned int>(bytes[i]));
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
			std::size_t ts = field_type_size(f.type);
			fsz = static_cast<uint32_t>(ts > 0 ? ts : 1);
		}
		uint32_t end = f.offset + fsz * f.array_count;
		if (end > max_end) max_end = end;
	}
	sd.total_size = max_end;
}

inline int create_struct(const std::string& name) {
	int idx = -1;
	std::size_t total = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!index_fits_int(g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"create_struct rejected reason='index_overflow' total=%zu", g_state.structs.size());
			return -1;
		}
		struct_def_t sd;
		sd.name = name;
		sd.total_size = 0;
		idx = static_cast<int>(g_state.structs.size());
		g_state.structs.push_back(std::move(sd));
		total = g_state.structs.size();
	}
	diag::log_tagged_fmt("dissector",
		"create_struct name='%s' idx=%d total=%zu",
		name.c_str(), idx, total);
	return idx;
}

inline int add_field(int struct_idx, const field_def_t& field) {
	int idx = -1;
	uint32_t total_after = 0;
	std::string sd_name;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"add_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return -1;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		field_def_t f = field;
		if (f.size == 0) {
			std::size_t ts = field_type_size(f.type);
			f.size = static_cast<uint32_t>(ts > 0 ? ts : 1);
		}
		if (!index_fits_int(sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"add_field rejected reason='index_overflow' struct='%s' field_count=%zu",
				sd.name.c_str(), sd.fields.size());
			return -1;
		}
		idx = static_cast<int>(sd.fields.size());
		if (valid_index(f.parent_idx, sd.fields.size()))
			sd.fields[static_cast<std::size_t>(f.parent_idx)].children.push_back(idx);
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
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"remove_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"remove_field rejected reason='bad_field_idx' struct='%s' field_idx=%d field_count=%zu",
				sd.name.c_str(), field_idx, sd.fields.size());
			return false;
		}
		const auto field_index = static_cast<std::size_t>(field_idx);
		removed_name = sd.fields[field_index].name;
		sd_name = sd.name;
		int parent = sd.fields[field_index].parent_idx;
		if (valid_index(parent, sd.fields.size())) {
			auto& pc = sd.fields[static_cast<std::size_t>(parent)].children;
			pc.erase(std::remove(pc.begin(), pc.end(), field_idx), pc.end());
		}
		sd.fields.erase(sd.fields.begin() + static_cast<std::ptrdiff_t>(field_index));
		for (auto& f : sd.fields) {
			if (f.parent_idx > field_idx) --f.parent_idx;
			else if (f.parent_idx == field_idx) f.parent_idx = -1;
			for (auto& ci : f.children) {
				if (ci > field_idx) --ci;
			}
			f.children.erase(
				std::remove_if(f.children.begin(), f.children.end(),
					[&](int c) { return !valid_index(c, sd.fields.size()); }),
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
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_struct rejected reason='bad_idx' idx=%d", struct_idx);
			return false;
		}
		if (new_name.empty()) {
			diag::log_tagged_fmt("dissector",
				"rename_struct rejected reason='empty_name' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
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
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"rename_field rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		const auto field_index = static_cast<std::size_t>(field_idx);
		sd_name = sd.name;
		old_name = sd.fields[field_index].name;
		sd.fields[field_index].name = new_name;
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
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"retype_field rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"retype_field rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		auto& f = sd.fields[static_cast<std::size_t>(field_idx)];
		old_type = f.type;
		f.type = new_type;
		std::size_t ts = field_type_size(new_type);
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
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_size rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
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
		auto& f = sd.fields[static_cast<std::size_t>(field_idx)];
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
		if (!valid_index(struct_idx, g_state.structs.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_comment rejected reason='bad_struct_idx' idx=%d", struct_idx);
			return false;
		}
		auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
		if (!valid_index(field_idx, sd.fields.size())) {
			diag::log_tagged_fmt("dissector",
				"set_field_comment rejected reason='bad_field_idx' struct='%s' field_idx=%d",
				sd.name.c_str(), field_idx);
			return false;
		}
		const auto field_index = static_cast<std::size_t>(field_idx);
		sd.fields[field_index].description = comment;
		sd_name = sd.name;
		fname = sd.fields[field_index].name;
	}
	diag::log_tagged_fmt("dissector",
		"set_field_comment struct='%s' field='%s' bytes=%zu",
		sd_name.c_str(), fname.c_str(), comment.size());
	return true;
}

inline void refresh_values() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	ensure_preview_fixture();
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!valid_index(g_state.active_struct, g_state.structs.size()))
		return;
	const auto& definition = g_state.structs[static_cast<std::size_t>(g_state.active_struct)];
	g_state.cached_values.resize(definition.fields.size());
	const std::uint64_t sequence = g_state.refresh_seq.fetch_add(1) + 1;
	for (std::size_t index = 0; index < definition.fields.size(); ++index) {
		const auto& field = definition.fields[index];
		const std::size_t length = (std::max)(std::size_t{1},
			static_cast<std::size_t>(field.size) * field.array_count);
		std::vector<std::uint8_t> bytes(length);
		for (std::size_t offset = 0; offset < length; ++offset)
			bytes[offset] = static_cast<std::uint8_t>(
				(g_state.base_address + field.offset + offset + sequence * 3) & 0xFFu);
		if (field.type == field_type_t::ascii_string) {
			static constexpr char module[] = "AiDA_Target.exe";
			std::fill(bytes.begin(), bytes.end(), 0);
			std::copy_n(module, (std::min)(sizeof(module) - 1, bytes.size()), bytes.begin());
		}
		auto& value = g_state.cached_values[index];
		value.changed = !value.raw_bytes.empty() && value.raw_bytes != bytes;
		value.raw_bytes = std::move(bytes);
		value.display_text = format_field_value(value.raw_bytes, field.type);
	}
	g_state.last_completed_seq.store(sequence, std::memory_order_release);
	g_state.refresh_in_flight.store(false, std::memory_order_release);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 6,
		"refresh_values", definition.name);
	return;
#else
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
	std::size_t field_count = 0;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		active = g_state.active_struct;
		if (!valid_index(active, g_state.structs.size())) {
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
		const auto& sd = g_state.structs[static_cast<std::size_t>(active)];
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

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "analysis";
	sub.label = "analysis.struct_dissector.refresh_values";
	sub.thread_class = "bounded_task";
	sub.domain = aida::infra::executor::domain_t::diagnostics;
	sub.priority = 4;
	sub.body = [base, total_size, active, seq, field_count]() {
		std::vector<uint8_t> block;
		bool ok = driver_bridge::read_memory(base, total_size, block);
		if (!ok || block.empty()) {
			g_state.refresh_in_flight.store(false);
			diag::log_tagged_fmt("dissector",
				"refresh_values_read_failed base=0x%llX size=%u",
				static_cast<unsigned long long>(base), total_size);
			return;
		}

		std::size_t changed_count = 0;
		std::size_t oor_count = 0;
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			if (!valid_index(active, g_state.structs.size())) {
				g_state.refresh_in_flight.store(false);
				return;
			}
			if (g_state.last_completed_seq.load() > seq) {
				g_state.refresh_in_flight.store(false);
				return;
			}
			const auto& sd = g_state.structs[static_cast<std::size_t>(active)];
			g_state.cached_values.resize(sd.fields.size());
			for (std::size_t i = 0; i < sd.fields.size(); ++i) {
				const auto& f = sd.fields[i];
				const std::size_t field_offset = static_cast<std::size_t>(f.offset);
				const std::size_t field_size = static_cast<std::size_t>(f.size) * f.array_count;
				if (field_offset > block.size() || field_size > block.size() - field_offset) {
					g_state.cached_values[i].display_text = "<out of range>";
					g_state.cached_values[i].changed = false;
					++oor_count;
					continue;
				}
				const auto first = block.begin() + static_cast<std::ptrdiff_t>(field_offset);
				const auto last = first + static_cast<std::ptrdiff_t>(field_size);
				std::vector<uint8_t> raw(first, last);
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
	};
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		g_state.refresh_in_flight.store(false);
		diag::log_tagged_fmt("dissector",
			"refresh_values_post_failed base=0x%llX size=%u fields=%zu seq=%llu",
			static_cast<unsigned long long>(base), total_size, field_count,
			static_cast<unsigned long long>(seq));
	}
#endif
}

inline std::string auto_detect_type(uint64_t address, std::size_t size) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (size >= 16)
		return "byte_array";
	if ((address & 7u) == 0)
		return "pointer";
	if ((address & 3u) == 0)
		return "uint32";
	return "uint8";
#else
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
	for (std::size_t i = 0; i < bytes.size(); ++i) {
		if (bytes[i] == 0) break;
		if (bytes[i] < 0x20 || bytes[i] > 0x7E) { all_printable = false; break; }
	}
	if (all_printable && bytes.size() >= 4 && bytes[0] >= 0x20)
		return "ascii_string";

	return "byte_array";
#endif
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline bool write_preview_value(int field_index, const std::string& text) {
	std::lock_guard<std::mutex> lock(g_state.mtx);
	if (!valid_index(g_state.active_struct, g_state.structs.size()))
		return false;
	const auto& definition = g_state.structs[static_cast<std::size_t>(g_state.active_struct)];
	if (!valid_index(field_index, definition.fields.size()))
		return false;
	g_state.cached_values.resize(definition.fields.size());
	auto& value = g_state.cached_values[static_cast<std::size_t>(field_index)];
	value.display_text = text;
	value.raw_bytes.assign(text.begin(), text.end());
	value.changed = true;
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 6,
		"write_field", definition.fields[static_cast<std::size_t>(field_index)].name);
	return true;
}
#endif

inline std::string export_to_c(int struct_idx) {
	std::lock_guard<std::mutex> lk(g_state.mtx);
	if (!valid_index(struct_idx, g_state.structs.size())) {
		diag::log_tagged_fmt("dissector",
			"export_to_c rejected reason='bad_idx' idx=%d", struct_idx);
		return {};
	}
	const auto& sd = g_state.structs[static_cast<std::size_t>(struct_idx)];
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
