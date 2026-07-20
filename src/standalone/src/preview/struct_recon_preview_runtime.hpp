#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "re_hubs_preview_adapter.hpp"
#include "preview_fixture_controls.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace struct_recon {

enum class field_type_t : int {
	unknown = 0, int8, uint8, int16, uint16, int32, uint32, int64, uint64,
	float32, float64, pointer, vtable_ptr, c_string, wide_string, padding,
	nested_struct, array, vec2, vec3, vec4, mat4x4, color_rgba, bitfield,
	utf8_string, utf16_string, bool8, COUNT
};

struct access_record_t {
	uint64_t instruction_addr = 0;
	uint64_t access_offset = 0;
	int access_size = 0;
	bool is_write = false;
	std::string disasm_text;
	int hit_count = 0;
	std::string source;
	uint32_t thread_id = 0;
	uint32_t sample_index = 0;
	uint32_t capture_session_id = 0;
	bool initial_value_captured = false;
	uint64_t initial_value = 0;
	std::vector<uint8_t> initial_bytes;
	bool value_captured = false;
	bool value_after_access = false;
	uint64_t observed_value = 0;
	std::vector<uint8_t> observed_bytes;
};

struct vtable_entry_t {
	uint64_t func_addr = 0;
	int index = 0;
	std::string name;
};

struct value_history_t {
	static constexpr int MAX_ENTRIES = 10;
	std::array<uint64_t, MAX_ENTRIES> values{};
	int count = 0;
	int write_idx = 0;
	void push(uint64_t value) {
		values[static_cast<std::size_t>(write_idx)] = value;
		write_idx = (write_idx + 1) % MAX_ENTRIES;
		if (count < MAX_ENTRIES)
			++count;
	}
	int unique_count() const {
		std::set<uint64_t> unique;
		for (int index = 0; index < count; ++index)
			unique.insert(values[static_cast<std::size_t>(index)]);
		return static_cast<int>(unique.size());
	}
	int heat_level() const {
		const int unique = unique_count();
		return unique <= 1 ? 0 : unique == 2 ? 1 : unique <= 4 ? 2 : 3;
	}
};

struct struct_field_t {
	uint64_t offset = 0;
	int size = 0;
	field_type_t type = field_type_t::unknown;
	std::string name;
	std::string comment;
	std::vector<access_record_t> accesses;
	std::vector<vtable_entry_t> vtable_entries;
	value_history_t value_history;
	float type_confidence = 0.f;
	int array_count = 1;
};

struct reconstructed_struct_t {
	std::string name;
	uint64_t base_address = 0;
	int total_size = 0;
	std::vector<struct_field_t> fields;
	bool has_vtable = false;
	uint64_t vtable_address = 0;
};

struct state_t {
	reconstructed_struct_t current;
	std::shared_ptr<const reconstructed_struct_t> publication =
		std::make_shared<const reconstructed_struct_t>();
	uint64_t current_revision = 0;
	std::mutex mutex;
	std::atomic<bool> monitoring{false};
	std::atomic<bool> cancel{false};
	std::atomic<float> progress{0.f};
	char address_input[32]{};
	char name_input[64]{};
	char size_input[16] = "256";
	bool active = false;
	std::vector<reconstructed_struct_t> history;
	std::atomic<bool> ai_naming{false};
	std::vector<reconstructed_struct_t> saved_structs;
};

inline state_t g_state;

inline void publish_current_locked() {
	++g_state.current_revision;
	std::atomic_store_explicit(&g_state.publication,
		std::make_shared<const reconstructed_struct_t>(g_state.current),
		std::memory_order_release);
}

inline std::shared_ptr<const reconstructed_struct_t> capture_current_snapshot() {
	return std::atomic_load_explicit(&g_state.publication, std::memory_order_acquire);
}

inline const char* field_type_name(field_type_t type) {
	static constexpr const char* names[] = {
		"unknown", "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t",
		"uint32_t", "int64_t", "uint64_t", "float", "double", "void*",
		"void**", "char*", "wchar_t*", "uint8_t", "struct", "array",
		"vec2_t", "vec3_t", "vec4_t", "mat4x4_t", "color_rgba_t", "bitfield",
		"char*", "wchar_t*", "bool"
	};
	const int index = static_cast<int>(type);
	return index >= 0 && index < static_cast<int>(field_type_t::COUNT) ? names[index] : "unknown";
}

inline access_record_t preview_access(uint64_t address, uint64_t offset,
	int size, bool write, const char* text) {
	access_record_t value;
	value.instruction_addr = address;
	value.access_offset = offset;
	value.access_size = size;
	value.is_write = write;
	value.disasm_text = text;
	value.hit_count = write ? 14 : 37;
	value.source = "Studio trace fixture";
	value.thread_id = 4820;
	return value;
}

inline reconstructed_struct_t preview_structure(uint64_t base, int size, const std::string& name) {
	reconstructed_struct_t result;
	result.name = name.empty() ? "RuntimeImageContext" : name;
	result.base_address = base == 0 ? 0x0000000140005000ULL : base;
	result.total_size = size > 0 ? size : 0x80;
	result.has_vtable = true;
	result.vtable_address = 0x0000000140012000ULL;
	result.fields = {
		{0x00, 8, field_type_t::vtable_ptr, "vtable", "Virtual dispatch table",
			{preview_access(0x1400012C0, 0, 8, false, "mov rax, [rcx]")},
			{{0x140001180, 0, "Initialize"}, {0x1400012C0, 1, "Analyze"}, {0x1400014A0, 2, "Dispatch"}}, {}, 99.f, 1},
		{0x08, 8, field_type_t::pointer, "image_base", "Mapped image base",
			{preview_access(0x1400012D8, 8, 8, false, "mov rdx, [rcx+8]")}, {}, {}, 98.f, 1},
		{0x10, 4, field_type_t::uint32, "image_size", "Size of image",
			{preview_access(0x14000130A, 0x10, 4, false, "mov eax, [rcx+10h]")}, {}, {}, 96.f, 1},
		{0x14, 4, field_type_t::bitfield, "analysis_flags", "Active analysis passes",
			{preview_access(0x140001338, 0x14, 4, true, "or dword ptr [rcx+14h], 4")}, {}, {}, 91.f, 1},
		{0x18, 8, field_type_t::pointer, "entry_point", "Resolved entry point", {}, {}, {}, 97.f, 1},
		{0x20, 4, field_type_t::uint32, "section_count", "Validated PE sections", {}, {}, {}, 94.f, 1},
		{0x24, 4, field_type_t::float32, "confidence", "Recovery confidence", {}, {}, {}, 88.f, 1},
		{0x28, 16, field_type_t::utf8_string, "module_name", "AiDA_Target.exe", {}, {}, {}, 86.f, 1},
		{0x38, 16, field_type_t::array, "section_rvas", "Section RVA table", {}, {}, {}, 82.f, 4},
		{0x48, 8, field_type_t::uint64, "analysis_revision", "Workspace revision", {}, {}, {}, 93.f, 1},
		{0x50, 0x30, field_type_t::padding, "reserved", "Reserved runtime state", {}, {}, {}, 100.f, 1}
	};
	for (std::size_t index = 0; index < result.fields.size(); ++index) {
		result.fields[index].value_history.push(result.base_address + result.fields[index].offset);
		result.fields[index].value_history.push(result.base_address + result.fields[index].offset + index + 1);
	}
	return result;
}

inline void ensure_preview_fixture() {
	std::lock_guard<std::mutex> lock(g_state.mutex);
	if (!g_state.current.fields.empty())
		return;
	g_state.current = preview_structure(0x0000000140005000ULL, 0x80, "RuntimeImageContext");
	g_state.active = true;
	publish_current_locked();
	std::snprintf(g_state.address_input, sizeof(g_state.address_input), "%llX",
		static_cast<unsigned long long>(g_state.current.base_address));
	std::snprintf(g_state.name_input, sizeof(g_state.name_input), "%s", g_state.current.name.c_str());
	std::snprintf(g_state.size_input, sizeof(g_state.size_input), "%d", g_state.current.total_size);
}

inline void configure_preview_fixture(aida::preview::fixture_state_t state,
	std::size_t cardinality) {
	std::lock_guard<std::mutex> lock(g_state.mutex);
	if (state == aida::preview::fixture_state_t::empty ||
		state == aida::preview::fixture_state_t::disconnected) {
		g_state.current = {};
		g_state.active = false;
		publish_current_locked();
		return;
	}
	g_state.current = preview_structure(0x0000000140005000ULL, 0x80,
		"RuntimeImageContext");
	const std::size_t bounded = (std::min<std::size_t>)(cardinality, 4096U);
	if (bounded > g_state.current.fields.size()) {
		g_state.current.fields.reserve(bounded);
		for (std::size_t index = g_state.current.fields.size(); index < bounded; ++index) {
			struct_field_t field;
			field.offset = static_cast<std::uint64_t>(index * 8U);
			field.size = 8;
			field.type = field_type_t::uint64;
			field.name = "field_" + std::to_string(index);
			field.comment = "Deterministic recovered field";
			field.type_confidence = 80.0f + static_cast<float>(index % 20U);
			field.value_history.push(g_state.current.base_address + field.offset);
			g_state.current.fields.push_back(std::move(field));
		}
		g_state.current.total_size = static_cast<int>(bounded * 8U);
	}
	g_state.active = true;
	g_state.monitoring.store(state == aida::preview::fixture_state_t::loading,
		std::memory_order_release);
	g_state.cancel.store(state == aida::preview::fixture_state_t::cancellation_requested,
		std::memory_order_release);
	g_state.progress.store(state == aida::preview::fixture_state_t::loading ? 0.46f : 1.0f,
		std::memory_order_release);
	publish_current_locked();
}

inline void reconstruct_from_snapshot(uint64_t base, int size, const std::string& name) {
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.current = preview_structure(base, size, name);
	g_state.active = true;
	publish_current_locked();
	g_state.progress.store(1.f);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 5, "snapshot", g_state.current.name);
}

inline void monitor_with_hwbp(uint64_t base, int size, const std::string& name) {
	reconstruct_from_snapshot(base, size, name);
	g_state.monitoring.store(false);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 5, "hardware_monitor", name);
}

inline void cancel() {
	g_state.cancel.store(true);
	g_state.monitoring.store(false);
	g_state.progress.store(0.f);
}

inline bool refresh_value_history(std::string& error) {
	std::lock_guard<std::mutex> lock(g_state.mutex);
	for (std::size_t index = 0; index < g_state.current.fields.size(); ++index)
		g_state.current.fields[index].value_history.push(
			g_state.current.base_address + g_state.current.fields[index].offset + index + 7);
	publish_current_locked();
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 5, "refresh", g_state.current.name);
	error.clear();
	return true;
}

inline std::string export_as_cpp(const reconstructed_struct_t& structure) {
	std::string result = "struct " + structure.name + " {\n";
	for (const auto& field : structure.fields) {
		result += "    ";
		result += field_type_name(field.type);
		result += " " + field.name;
		if (field.array_count > 1)
			result += "[" + std::to_string(field.array_count) + "]";
		result += ";\n";
	}
	result += "};\n";
	return result;
}

inline void ai_name_fields() {
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.ai_naming.store(true);
	if (g_state.current.fields.size() > 5)
		g_state.current.fields[5].name = "validated_section_count";
	publish_current_locked();
	g_state.ai_naming.store(false);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 5, "ai_name", g_state.current.name);
}

inline bool save_struct_to_disk(const reconstructed_struct_t& structure, std::string& error) {
	std::lock_guard<std::mutex> lock(g_state.mutex);
	g_state.saved_structs.push_back(structure);
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 5, "save", structure.name);
	error.clear();
	return true;
}

inline bool load_structs_from_disk(std::string& error) {
	std::lock_guard<std::mutex> lock(g_state.mutex);
	if (g_state.saved_structs.empty())
		g_state.saved_structs.push_back(preview_structure(0x140005000ULL, 0x80, "SavedImageContext"));
	g_state.current = g_state.saved_structs.front();
	g_state.active = true;
	publish_current_locked();
	aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types, 5, "load_all",
		std::to_string(g_state.saved_structs.size()));
	error.clear();
	return true;
}

}

namespace struct_monitor {

struct state_t {
	std::atomic<bool> active{false};
	std::atomic<uint64_t> total_captures{0};
	std::atomic<uint64_t> captures_per_second{0};
};

inline state_t g_state;

inline void start(uint64_t base, int size, const std::string& name, const std::string& = "auto") {
	struct_recon::reconstruct_from_snapshot(base, size, name);
	g_state.active.store(true);
	g_state.captures_per_second.store(24);
	g_state.total_captures.fetch_add(128);
}

inline void stop() {
	g_state.active.store(false);
	g_state.captures_per_second.store(0);
}

}

namespace driver_bridge {

inline bool is_loaded() {
	return true;
}

}

namespace function_index::detail {

inline bool static_pe_active() {
	return true;
}

}

#endif
