#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace source_debug_service {

enum class binding_state_t : std::uint8_t {
	pending = 0,
	bound,
	unbound,
	stale,
	error
};

enum class source_state_t : std::uint8_t {
	unavailable = 0,
	loading,
	available,
	missing,
	truncated,
	error
};

struct bound_location_t {
	std::string module_name;
	std::uint64_t module_rva = 0;
	std::uint64_t address = 0;
	std::uint32_t ordinal = 0;
	bool runtime_owned = false;
};

struct definition_t {
	std::string id;
	std::string file_path;
	std::string canonical_path;
	std::uint32_t line = 0;
	bool enabled = true;
	binding_state_t state = binding_state_t::pending;
	std::string detail;
	std::vector<bound_location_t> locations;
	std::uint32_t target_pid = 0;
	std::uint64_t stop_generation = 0;
	std::uint64_t workspace_generation = 0;
	std::uint64_t symbol_generation = 0;
};

struct line_marker_t {
	std::uint32_t line = 0;
	binding_state_t state = binding_state_t::pending;
	bool enabled = true;
	std::string detail;
};

struct source_excerpt_line_t {
	std::uint32_t line = 0;
	std::string text;
	bool current = false;
};

struct current_location_t {
	bool valid = false;
	std::string file_path;
	std::string canonical_path;
	std::string module_name;
	std::uint32_t line = 0;
	std::uint64_t module_rva = 0;
	std::uint64_t address = 0;
	source_state_t source_state = source_state_t::unavailable;
	std::string detail;
	std::vector<source_excerpt_line_t> excerpt;
	bool source_breakpoint_hit = false;
};

struct snapshot_t {
	std::uint64_t generation = 0;
	std::string target_key;
	std::uint32_t target_pid = 0;
	std::uint64_t stop_generation = 0;
	std::uint64_t workspace_generation = 0;
	std::uint64_t symbol_generation = 0;
	bool operation_pending = false;
	std::string operation_label;
	std::string error;
	std::vector<definition_t> definitions;
	std::unordered_map<std::string, std::shared_ptr<const std::vector<line_marker_t>>> markers_by_path;
	current_location_t current;
};

using snapshot_ptr = std::shared_ptr<const snapshot_t>;

struct marker_snapshot_t {
	std::uint64_t generation = 0;
	std::shared_ptr<const std::vector<line_marker_t>> markers;
};

snapshot_ptr snapshot();
marker_snapshot_t markers_for_path(const std::string& path);
std::string canonical_path(const std::string& path);
const char* binding_state_label(binding_state_t state);
const char* source_state_label(source_state_t state);

void begin_frame();
bool request_toggle(const std::string& file_path, std::uint32_t line,
	std::string* error = nullptr);
bool request_remove(const std::string& definition_id, std::string* error = nullptr);
bool request_rebind(std::string* error = nullptr);
bool request_open_source(const std::string& file_path, std::uint32_t line,
	std::string* error = nullptr);
bool request_open_current_source(std::string* error = nullptr);
bool request_open_current_disassembly(std::string* error = nullptr);

}
