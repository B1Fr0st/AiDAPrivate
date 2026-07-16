#pragma once

#include <cstdint>
#include <string>

namespace memory_interaction {

enum class source_t : std::uint8_t {
	none = 0,
	live_process,
	static_binary
};

enum class kind_t : std::uint8_t {
	none = 0,
	scan_result,
	address_entry,
	pointer_chain,
	memory_range,
	patch_record
};

enum class capability_t : std::uint8_t {
	copy_address,
	copy_value,
	copy_previous_value,
	copy_module_offset,
	add_to_address_list,
	open_hex,
	open_disassembly,
	edit_description,
	change_type,
	change_value,
	freeze,
	unfreeze,
	remove,
	stage_patch,
	revert_patch
};

struct runtime_t {
	bool driver_loaded = false;
	bool live_attached = false;
	bool static_loaded = false;
	std::uint32_t target_pid = 0;
	std::uint64_t scan_revision = 0;
};

struct context_t {
	kind_t kind = kind_t::none;
	source_t source = source_t::none;
	std::uint32_t target_pid = 0;
	std::uint64_t scan_revision = 0;
	std::uint64_t address = 0;
	std::uint64_t extent = 0;
	int index = -1;
	bool frozen = false;
	std::string value;
	std::string previous_value;
	std::string module_offset;
};

struct capability_result_t {
	bool enabled = false;
	const char* disabled_reason = nullptr;
};

context_t capture_result(const runtime_t& runtime, std::uint64_t address,
	int index, std::string value, std::string previous_value,
	std::string module_offset);
context_t capture_address(const runtime_t& runtime, std::uint64_t address,
	int index, bool frozen, std::string value);
context_t capture_pointer_chain(const runtime_t& runtime, std::uint64_t address,
	std::uint64_t extent, int index, std::string module_offset);
context_t capture_memory_range(const runtime_t& runtime, std::uint64_t address,
	std::uint64_t extent, int index, std::string module_offset);
context_t capture_patch(const runtime_t& runtime, std::uint64_t address,
	std::uint64_t extent, int index, std::string value);
void select(context_t context);
context_t selected();
void clear_selection();
std::uint64_t selection_generation();
bool is_current(const context_t& context, const runtime_t& runtime);
capability_result_t evaluate(capability_t capability,
	const context_t& context, const runtime_t& runtime);
bool context_key_pressed();

}
