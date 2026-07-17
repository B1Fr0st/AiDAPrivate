#pragma once

#include "struct_dissector.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#endif
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/blur_layer.hpp"
#include "ui/responsive.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "ui/ui_anim.hpp"
#include "ui/toast_notification.hpp"
#include "ui/task_center.hpp"
#include "ui/application_ui_runtime.hpp"
#include "../infra/executor.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "ui/ui_thread_dispatcher.hpp"
#endif
#include "../disasm/disasm_view.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#include "../anti-tamper/webhook.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace struct_dissector_view {

struct field_anim_t {
	aida::ui::flash_t change_flash;
	aida::ui::flash_t write_success;
	std::vector<uint8_t> last_bytes;
	bool                  has_last = false;
	aida::ui::transition_t expand;
	bool                  expanded = false;
};

enum class edit_target_t : int {
	none = 0,
	field_name,
	field_size,
	field_comment,
	struct_name,
	array_count,
	nested_target,
	pointer_target,
	enum_reference,
	bitfield,
	field_alignment,
};

struct ui_state_t {
	int   active_tab = 0;
	int   selected_field = -1;
	std::vector<bool> field_expand;
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	float list_scroll_y = 0.f;
	float list_target_scroll_y = 0.f;
	char  name_buf[128] = {};
	char  field_name_buf[128] = {};
	char  offset_buf[32] = {};
	char  size_buf[32] = {};
	char  edit_value_buf[256] = {};
	char  addr_buf[20] = {};
	char  rename_buf[256] = {};
	char  list_filter[96] = {};
	char  layout_pack_buf[16] = {};
	char  layout_align_buf[16] = {};
	int   editing_field = -1;
	int   add_type = 0;
	int   selected_struct = -1;
	bool  sb_dragging = false;
	float sb_drag_offset = 0.f;
	bool  list_sb_dragging = false;
	float list_sb_drag_offset = 0.f;
	float row_anim_time = 0.f;
	std::unordered_map<int, field_anim_t> field_anims;
	float edit_ring_phase = 0.f;
	bool  addr_buf_seeded = false;
	edit_target_t edit_target = edit_target_t::none;
	int   edit_target_field = -1;
	bool  table_focused = false;
	bool  list_focused = false;
	uint64_t context_refresh_seq = 0;
	uint64_t context_base_address = 0;
	uint32_t context_target_pid = 0;
	uint64_t edit_base_address = 0;
	std::uint64_t pending_remove_structure_id = 0;
	std::uint64_t pending_remove_structure_revision = 0;
	std::uint64_t pending_remove_field_id = 0;
	std::uint64_t edit_structure_id = 0;
	std::uint64_t edit_structure_revision = 0;
	std::uint64_t edit_field_id = 0;
	bool remove_confirmation_requested = false;
	bool inline_edit_popup_requested = false;
	bool layout_popup_requested = false;
	std::string operation_status;
	bool operation_error = false;
	std::uint64_t validation_structure_id = 0;
	std::uint64_t validation_revision = 0;
	struct_dissector::layout_validation_t validation;
};

inline ui_state_t g_ui;

enum class write_review_status_t : std::uint8_t {
	review,
	queued,
	running,
	succeeded,
	failed,
	cancelled,
	stale
};

struct write_review_t {
	bool visible = false;
	bool open_requested = false;
	write_review_status_t status = write_review_status_t::review;
	std::uint64_t serial = 0;
	std::uint32_t pid = 0;
	std::uint64_t address = 0;
	std::uint64_t workspace_generation = 0;
	std::uint64_t structure_identity = 0;
	std::uint64_t base_address = 0;
	int structure_index = -1;
	int field_index = -1;
	std::string structure_name;
	std::string field_name;
	std::vector<std::uint8_t> old_bytes;
	std::vector<std::uint8_t> new_bytes;
	std::string error;
	bool mutation_may_remain = false;
	std::weak_ptr<aida::analysis::analysis_workspace_t> workspace;
	std::shared_ptr<std::atomic<bool>> cancellation;
};

inline write_review_t g_write_review;
inline std::atomic<std::uint64_t> g_write_serial{0};
inline std::atomic<std::uint64_t> g_write_running_serial{0};
inline std::atomic<std::uint64_t> g_write_dispatch_failure{0};
inline std::atomic<std::uint64_t> g_write_dispatch_applied{0};

inline std::uint64_t structure_identity_locked(int structure_index) {
	const auto& state = struct_dissector::g_state;
	if (!struct_dissector::valid_index(structure_index, state.structs.size()))
		return 0;
	const auto& definition = state.structs[static_cast<std::size_t>(structure_index)];
	std::uint64_t hash = 1469598103934665603ULL;
	const auto mix = [&hash](std::uint64_t value) {
		hash ^= value;
		hash *= 1099511628211ULL;
	};
	for (const char character : definition.name)
		mix(static_cast<unsigned char>(character));
	mix(definition.stable_id);
	mix(definition.layout_revision);
	mix(definition.total_size);
	mix(static_cast<std::uint64_t>(definition.kind));
	mix(definition.packing);
	mix(definition.explicit_alignment);
	for (const auto& field : definition.fields) {
		for (const char character : field.name)
			mix(static_cast<unsigned char>(character));
		mix(static_cast<std::uint64_t>(field.type));
		mix(field.offset);
		mix(field.size);
		mix(field.array_count);
		mix(field.stable_id);
		mix(field.target_structure_id);
		mix(field.enum_id);
		mix(field.bit_offset);
		mix(field.bit_width);
		mix(field.explicit_alignment);
		for (const char character : field.referenced_type_name)
			mix(static_cast<unsigned char>(character));
	}
	return hash;
}

inline std::optional<std::vector<std::uint8_t>> parse_preview_field_value(
	const struct_dissector::field_def_t& field, const char* text) {
	if (!text || !*text)
		return {};
	std::vector<std::uint8_t> output;
	const auto append_scalar = [&output](const auto& value) {
		const auto* begin = reinterpret_cast<const std::uint8_t*>(&value);
		output.assign(begin, begin + sizeof(value));
	};
	char* end = nullptr;
	errno = 0;
	switch (field.type) {
		case struct_dissector::field_type_t::ascii_string:
			output.assign(text, text + std::strlen(text));
			break;
		case struct_dissector::field_type_t::utf16_string:
			for (const char character : std::string(text)) {
				output.push_back(static_cast<unsigned char>(character));
				output.push_back(0);
			}
			break;
		case struct_dissector::field_type_t::float32: {
			const float value = std::strtof(text, &end);
			if (errno != 0 || !end || *end != '\0' || !std::isfinite(value)) return {};
			append_scalar(value);
			break;
		}
		case struct_dissector::field_type_t::float64: {
			const double value = std::strtod(text, &end);
			if (errno != 0 || !end || *end != '\0' || !std::isfinite(value)) return {};
			append_scalar(value);
			break;
		}
		case struct_dissector::field_type_t::byte_array:
		case struct_dissector::field_type_t::padding:
		case struct_dissector::field_type_t::nested_struct: {
			int high = -1;
			for (const char character : std::string(text)) {
				const auto byte = static_cast<unsigned char>(character);
				if (std::isspace(byte)) continue;
				int value = byte >= '0' && byte <= '9' ? byte - '0' :
					byte >= 'a' && byte <= 'f' ? byte - 'a' + 10 :
					byte >= 'A' && byte <= 'F' ? byte - 'A' + 10 : -1;
				if (value < 0) return {};
				if (high < 0) high = value;
				else {
					output.push_back(static_cast<std::uint8_t>((high << 4) | value));
					high = -1;
				}
			}
			if (high >= 0) return {};
			break;
		}
		default: {
			const bool signed_type = field.type == struct_dissector::field_type_t::int8 ||
				field.type == struct_dissector::field_type_t::int16 ||
				field.type == struct_dissector::field_type_t::int32 ||
				field.type == struct_dissector::field_type_t::int64;
			const int base = field.type == struct_dissector::field_type_t::pointer ? 16 : 0;
			const std::uint64_t raw = signed_type
				? static_cast<std::uint64_t>(std::strtoll(text, &end, base))
				: std::strtoull(text, &end, base);
			if (errno != 0 || !end || *end != '\0') return {};
			const std::size_t width = field.type == struct_dissector::field_type_t::int8 ||
				field.type == struct_dissector::field_type_t::uint8 ? 1 :
				field.type == struct_dissector::field_type_t::int16 ||
				field.type == struct_dissector::field_type_t::uint16 ? 2 :
				field.type == struct_dissector::field_type_t::int32 ||
				field.type == struct_dissector::field_type_t::uint32 ? 4 : 8;
			output.resize(width);
			std::memcpy(output.data(), &raw, width);
			break;
		}
	}
	return output.empty() ? std::optional<std::vector<std::uint8_t>>{} : std::move(output);
}

inline std::string format_review_bytes(const std::vector<std::uint8_t>& bytes) {
	std::string output;
	const std::size_t shown = (std::min)(bytes.size(), std::size_t{64});
	output.reserve(shown * 3 + 32);
	char encoded[4]{};
	for (std::size_t index = 0; index < shown; ++index) {
		if (!output.empty()) output.push_back(' ');
		std::snprintf(encoded, sizeof(encoded), "%02X", bytes[index]);
		output.append(encoded);
	}
	if (shown != bytes.size())
		output.append(" ... (").append(std::to_string(bytes.size())).append(" bytes)");
	return output;
}

inline std::optional<std::vector<std::uint8_t>> parse_field_value(
	const struct_dissector::field_def_t& field, const char* text) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	return parse_preview_field_value(field, text);
#else
	memory_scanner::value_type_t type = memory_scanner::value_type_t::int32_val;
	bool hex_input = false;
	switch (field.type) {
		case struct_dissector::field_type_t::int8:
		case struct_dissector::field_type_t::uint8:
			type = memory_scanner::value_type_t::byte_val; break;
		case struct_dissector::field_type_t::int16:
		case struct_dissector::field_type_t::uint16:
			type = memory_scanner::value_type_t::int16_val; break;
		case struct_dissector::field_type_t::int32:
		case struct_dissector::field_type_t::uint32:
			type = memory_scanner::value_type_t::int32_val; break;
		case struct_dissector::field_type_t::int64:
		case struct_dissector::field_type_t::uint64:
		case struct_dissector::field_type_t::pointer:
			type = memory_scanner::value_type_t::int64_val;
			hex_input = field.type == struct_dissector::field_type_t::pointer;
			break;
		case struct_dissector::field_type_t::float32:
			type = memory_scanner::value_type_t::float_val; break;
		case struct_dissector::field_type_t::float64:
			type = memory_scanner::value_type_t::double_val; break;
		case struct_dissector::field_type_t::ascii_string:
			type = memory_scanner::value_type_t::string_ascii; break;
		case struct_dissector::field_type_t::utf16_string:
			type = memory_scanner::value_type_t::string_utf16; break;
		default:
			type = memory_scanner::value_type_t::byte_array;
			hex_input = true;
			break;
	}
	auto bytes = memory_scanner::parse_value(text, type, hex_input);
	return bytes.empty() ? std::optional<std::vector<std::uint8_t>>{} : std::move(bytes);
#endif
}

inline bool stage_write_review(const disasm_view::workspace_context_t& context,
	int structure_index, int field_index,
	const struct_dissector::field_def_t& field,
	const struct_dissector::live_value_t& value,
	std::uint64_t base_address, const char* text, std::string& error) {
	if (!context.workspace) {
		error = "The structure is not bound to a current process workspace.";
		return false;
	}
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (!context.workspace->identity().process()) {
		error = "The structure is not bound to a current process workspace.";
		return false;
	}
#endif
	const auto parsed = parse_field_value(field, text);
	if (!parsed) {
		error = "The entered value is invalid for this field type.";
		return false;
	}
	const std::uint64_t span = static_cast<std::uint64_t>(field.size) * field.array_count;
	if (span == 0 || span > 4096 || parsed->size() > span || parsed->size() > 4096) {
		error = "The encoded value does not fit the bounded field range.";
		return false;
	}
	if (value.raw_bytes.size() < parsed->size()) {
		error = "The current field snapshot does not contain every byte that would be replaced.";
		return false;
	}
	if (base_address == 0 || base_address >
		(std::numeric_limits<std::uint64_t>::max)() - field.offset ||
		base_address + field.offset >
		(std::numeric_limits<std::uint64_t>::max)() - (parsed->size() - 1)) {
		error = "The reviewed write range overflows the target address space.";
		return false;
	}
	std::uint64_t identity = 0;
	std::string structure_name;
	{
		std::lock_guard<std::mutex> lock(struct_dissector::g_state.mtx);
		if (!struct_dissector::valid_index(structure_index,
				struct_dissector::g_state.structs.size())) {
			error = "The selected structure no longer exists.";
			return false;
		}
		identity = structure_identity_locked(structure_index);
		structure_name = struct_dissector::g_state.structs[
			static_cast<std::size_t>(structure_index)].name;
	}
	if (g_write_review.cancellation)
		g_write_review.cancellation->store(true, std::memory_order_release);
	g_write_review = {};
	g_write_review.visible = true;
	g_write_review.open_requested = true;
	g_write_review.status = write_review_status_t::review;
	g_write_review.serial = g_write_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	g_write_review.pid = context.workspace->identity().process()
		? context.workspace->identity().process()->pid : 4242;
#else
	g_write_review.pid = context.workspace->identity().process()->pid;
#endif
	g_write_review.address = base_address + field.offset;
	g_write_review.workspace_generation = context.workspace->generation();
	g_write_review.structure_identity = identity;
	g_write_review.base_address = base_address;
	g_write_review.structure_index = structure_index;
	g_write_review.field_index = field_index;
	g_write_review.structure_name = std::move(structure_name);
	g_write_review.field_name = field.name;
	g_write_review.old_bytes.assign(value.raw_bytes.begin(),
		value.raw_bytes.begin() + static_cast<std::ptrdiff_t>(parsed->size()));
	g_write_review.new_bytes = std::move(*parsed);
	g_write_review.workspace = context.workspace;
	error.clear();
	return true;
}

inline bool submit_write_review() {
	if (!g_write_review.visible || g_write_review.status != write_review_status_t::review)
		return false;
	auto workspace = g_write_review.workspace.lock();
	if (!workspace)
		return false;
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	g_write_review.cancellation = cancellation;
	g_write_review.status = write_review_status_t::queued;
	g_write_review.mutation_may_remain = false;
	const auto serial = g_write_review.serial;
	const auto pid = g_write_review.pid;
	const auto address = g_write_review.address;
	const auto workspace_generation = g_write_review.workspace_generation;
	const auto structure_identity = g_write_review.structure_identity;
	const auto base_address = g_write_review.base_address;
	const auto structure_index = g_write_review.structure_index;
	const auto field_index = g_write_review.field_index;
	const auto structure_name = g_write_review.structure_name;
	const auto field_name = g_write_review.field_name;
	const auto old_bytes = g_write_review.old_bytes;
	const auto new_bytes = g_write_review.new_bytes;
	const std::string task_id = "structure.write." + std::to_string(pid) + "." +
		std::to_string(serial);
	aida::ui::task_center::task_registration_t registration;
	registration.id = task_id;
	registration.source = "structure_dissector";
	registration.owner = "Structure Dissector";
	registration.owner_view = "view.types.structures";
	registration.owner_action = "Apply reviewed field write";
	registration.target = "PID " + std::to_string(pid);
	registration.label = "Write and verify structure field";
	registration.stage = "Queued reviewed mutation";
	registration.affected_entity = structure_name + "." + field_name;
	registration.cancellation_is_safe = true;
	registration.callbacks.cancel = [cancellation] {
		bool expected = false;
		return cancellation->compare_exchange_strong(expected, true,
			std::memory_order_acq_rel);
	};
	if (!aida::ui::task_center::register_task(std::move(registration))) {
		g_write_review.status = write_review_status_t::failed;
		g_write_review.error = "Task Center rejected ownership of the reviewed mutation.";
		return false;
	}
	auto result_error = std::make_shared<std::string>();
	auto observed = std::make_shared<std::vector<std::uint8_t>>();
	auto mutation_may_remain = std::make_shared<std::atomic<bool>>(false);
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "structure_dissector";
	submission.label = "structure.write_reviewed_field";
	submission.thread_class = "bounded_task";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 2;
	submission.target_pid = pid;
	submission.generation = workspace_generation;
	submission.cancel_hook = [cancellation] {
		cancellation->store(true, std::memory_order_release);
	};
	submission.body = [workspace, cancellation, result_error, observed, mutation_may_remain, task_id,
		pid, address, workspace_generation, structure_identity, base_address,
		structure_index, field_index, structure_name, field_name,
		old_bytes, new_bytes, serial]() {
		g_write_running_serial.store(serial, std::memory_order_release);
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, 0.1f,
			"Revalidating reviewed target bytes"));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(pid);
		static_cast<void>(address);
#endif
		bool wrote = false;
		if (cancellation->load(std::memory_order_acquire))
			*result_error = "The reviewed mutation was cancelled before it started.";
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		else
			wrote = true;
#else
		else {
			const auto process = workspace ? workspace->identity().process() : std::nullopt;
			bool definition_current = false;
			{
				std::lock_guard<std::mutex> lock(struct_dissector::g_state.mtx);
				definition_current = struct_dissector::g_state.active_struct == structure_index &&
					struct_dissector::g_state.base_address == base_address &&
					structure_identity_locked(structure_index) == structure_identity &&
					struct_dissector::valid_index(structure_index,
						struct_dissector::g_state.structs.size()) &&
					struct_dissector::valid_index(field_index,
						struct_dissector::g_state.structs[
							static_cast<std::size_t>(structure_index)].fields.size());
			}
			if (!workspace || workspace->closing() || workspace->closed() ||
				workspace->generation() != workspace_generation || !process ||
				process->pid != pid || !driver_bridge::is_loaded() ||
				driver_bridge::attached_pid() != pid) {
				*result_error = "The reviewed process or workspace generation is stale.";
			} else if (!definition_current) {
				*result_error = "The reviewed structure, field, or base address is stale.";
			} else {
				std::vector<std::uint8_t> current;
				if (!driver_bridge::read_memory_for(pid, address, old_bytes.size(), current) ||
					current.size() != old_bytes.size())
					*result_error = "The pre-write exact-range read failed.";
				else if (current != old_bytes)
					*result_error = "The target bytes changed after review; no write was performed.";
				else if (cancellation->load(std::memory_order_acquire))
					*result_error = "The reviewed mutation was cancelled before the write.";
				else if (!driver_bridge::write_memory_for(pid, address, new_bytes))
					*result_error = "The driver rejected the reviewed write.";
				else {
					std::string verification_error;
					if (!driver_bridge::read_memory_for(pid, address, new_bytes.size(), *observed) ||
						observed->size() != new_bytes.size())
						verification_error = "The post-write exact-range readback failed.";
					else if (*observed != new_bytes)
						verification_error = "The post-write bytes do not match the reviewed value.";
					else
						wrote = true;
					if (!wrote) {
						std::vector<std::uint8_t> restored;
						const bool rollback_verified =
							driver_bridge::write_memory_for(pid, address, old_bytes) &&
							driver_bridge::read_memory_for(pid, address, old_bytes.size(), restored) &&
							restored == old_bytes;
						*result_error = verification_error + (rollback_verified
							? " The original bytes were restored and verified."
							: " Automatic rollback did not pass exact verification; the target may be partially mutated.");
						mutation_may_remain->store(!rollback_verified, std::memory_order_release);
					}
				}
			}
		}
#endif
		auto publish = [workspace, cancellation, result_error, mutation_may_remain, task_id, pid,
			workspace_generation, structure_identity, base_address, structure_index,
			field_index, new_bytes, serial, wrote]() {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const auto process = workspace ? workspace->identity().process() : std::nullopt;
#else
			static_cast<void>(pid);
#endif
			bool structure_current = false;
			{
				std::lock_guard<std::mutex> lock(struct_dissector::g_state.mtx);
				structure_current = struct_dissector::g_state.active_struct == structure_index &&
					struct_dissector::g_state.base_address == base_address &&
					structure_identity_locked(structure_index) == structure_identity &&
					struct_dissector::valid_index(structure_index,
						struct_dissector::g_state.structs.size()) &&
					struct_dissector::valid_index(field_index,
						struct_dissector::g_state.structs[
							static_cast<std::size_t>(structure_index)].fields.size());
			}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const bool target_current = workspace && !workspace->closing() && !workspace->closed() &&
				workspace->generation() == workspace_generation;
#else
			const bool target_current = workspace && !workspace->closing() && !workspace->closed() &&
				workspace->generation() == workspace_generation && process && process->pid == pid;
#endif
			if (g_write_review.serial != serial)
				return;
			if (!target_current || !structure_current) {
				g_write_review.status = write_review_status_t::stale;
				g_write_review.mutation_may_remain = wrote;
				g_write_review.error = wrote
					? "The write passed exact readback, but the structure, field, target, or workspace changed before publication. Review an inverse write before continuing."
					: "The structure, field, target, or workspace changed before publication.";
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					wrote ? aida::ui::task_center::task_state_t::partial
					      : aida::ui::task_center::task_state_t::cancelled, 1.0f,
					"Discarded stale mutation result", g_write_review.error));
				return;
			}
			if (wrote) {
				g_write_review.status = write_review_status_t::succeeded;
				g_write_review.error.clear();
				g_write_review.mutation_may_remain = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				{
					std::lock_guard<std::mutex> lock(struct_dissector::g_state.mtx);
					auto& values = struct_dissector::g_state.cached_values;
					values.resize(struct_dissector::g_state.structs[
						static_cast<std::size_t>(structure_index)].fields.size());
					auto& value = values[static_cast<std::size_t>(field_index)];
					value.raw_bytes = new_bytes;
					value.display_text = struct_dissector::format_field_value(new_bytes,
						struct_dissector::g_state.structs[static_cast<std::size_t>(structure_index)]
							.fields[static_cast<std::size_t>(field_index)].type);
					value.changed = true;
				}
#else
				struct_dissector::refresh_values();
#endif
				toast_notification::push("Reviewed field write completed and passed exact readback.",
					toast_notification::toast_type_t::success, 3.f);
			} else if (cancellation->load(std::memory_order_acquire)) {
				g_write_review.status = write_review_status_t::cancelled;
				g_write_review.error = "The reviewed mutation was cancelled.";
			} else {
				g_write_review.status = write_review_status_t::failed;
				g_write_review.error = *result_error;
				g_write_review.mutation_may_remain = mutation_may_remain->load(std::memory_order_acquire);
			}
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				g_write_review.status == write_review_status_t::succeeded
					? aida::ui::task_center::task_state_t::completed
					: g_write_review.mutation_may_remain
						? aida::ui::task_center::task_state_t::partial
					: g_write_review.status == write_review_status_t::cancelled
						? aida::ui::task_center::task_state_t::cancelled
						: aida::ui::task_center::task_state_t::failed,
				1.0f, g_write_review.status == write_review_status_t::succeeded
					? "Mutation verified" : g_write_review.mutation_may_remain
						? "Mutation outcome requires review" : "Mutation not applied",
				g_write_review.status == write_review_status_t::succeeded
					? "Exact readback matched reviewed bytes" : g_write_review.error));
		};
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		publish();
#else
		if (!aida::ui_thread::post(std::move(publish), "structure_dissector",
				"publish_reviewed_write", "worker_completion")) {
			g_write_dispatch_failure.store(serial, std::memory_order_release);
			if (wrote)
				g_write_dispatch_applied.store(serial, std::memory_order_release);
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				wrote ? aida::ui::task_center::task_state_t::partial
				      : aida::ui::task_center::task_state_t::failed,
				1.0f, "UI publication rejected", wrote
					? "The write and readback succeeded, but UI publication was rejected"
					: "The mutation result could not be published"));
		}
#endif
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		cancellation->store(true, std::memory_order_release);
		g_write_review.status = write_review_status_t::failed;
		g_write_review.error = "Worker queue rejected the reviewed mutation: " + submitted.reject_reason;
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.0f,
			"Worker queue rejected", submitted.reject_reason));
		return false;
	}
	return true;
}

inline void publish_field_selection(const std::string& structure_name,
	const struct_dissector::field_def_t& field) {
	auto context = disasm_view::capture_selected_workspace();
	if (!context.workspace)
		return;
	aida::workbench::selection_context_t selection;
	selection.kind = aida::workbench::selection_kind_t::entity;
	selection.entity_key = "structure.dissector." + structure_name + ".field." +
		std::to_string(field.offset);
	aida::workbench::document_local_cursor_t cursor;
	cursor.has_position = true;
	cursor.position = field.offset;
	aida::workbench::workbench_shell_workspace_context_t workbench;
	static_cast<void>(aida::workbench::workbench_shell_runtime_t::instance()
		.publish_selection(context.workspace, selection, cursor,
			aida::workbench::navigation_origin_t::inspector, workbench));
}

inline ImU32 type_color_token(struct_dissector::field_type_t tp, float alpha) {
	const auto& th = aida::ui::resolved();
	ImU32 base;
	switch (tp) {
		case struct_dissector::field_type_t::pointer:        base = th.syn_function; break;
		case struct_dissector::field_type_t::ascii_string:
		case struct_dissector::field_type_t::utf16_string:   base = th.syn_string;   break;
		case struct_dissector::field_type_t::float32:
		case struct_dissector::field_type_t::float64:        base = th.syn_number;   break;
		case struct_dissector::field_type_t::padding:        base = th.text_dim;     break;
		case struct_dissector::field_type_t::nested_struct:  base = th.syn_keyword;  break;
		case struct_dissector::field_type_t::byte_array:     base = th.warning;      break;
		case struct_dissector::field_type_t::int8:
		case struct_dissector::field_type_t::int16:
		case struct_dissector::field_type_t::int32:
		case struct_dissector::field_type_t::int64:
		case struct_dissector::field_type_t::uint8:
		case struct_dissector::field_type_t::uint16:
		case struct_dissector::field_type_t::uint32:
		case struct_dissector::field_type_t::uint64:         base = th.syn_number;   break;
		default:                                             base = th.text_primary; break;
	}
	return aida::ui::with_alpha(base, alpha);
}

inline void render_type_glyph(ImDrawList* dl, ImVec2 center,
                              struct_dissector::field_type_t tp, ImU32 color)
{
	switch (tp) {
		case struct_dissector::field_type_t::pointer: {
			dl->AddCircle(center, 5.f, color, 12, 1.2f);
			ImVec2 tip = ImVec2(center.x + 7.f, center.y);
			dl->AddLine(center, tip, color, 1.2f);
			dl->AddTriangleFilled(
				ImVec2(tip.x - 3.f, center.y - 3.f),
				ImVec2(tip.x + 1.f, center.y),
				ImVec2(tip.x - 3.f, center.y + 3.f), color);
			break;
		}
		case struct_dissector::field_type_t::ascii_string:
		case struct_dissector::field_type_t::utf16_string: {
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y - 1.f),
				ImVec2(center.x + 5.f, center.y + 1.f), color, 1.f);
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y + 3.f),
				ImVec2(center.x + 3.f, center.y + 5.f), color, 1.f);
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y - 5.f),
				ImVec2(center.x + 4.f, center.y - 3.f), color, 1.f);
			break;
		}
		case struct_dissector::field_type_t::float32:
		case struct_dissector::field_type_t::float64: {
			dl->AddText(ImGui::GetFont(), aida::ui::components::detail::ui_fs() * 0.85f,
				ImVec2(center.x - 5.f, center.y - 7.f), color, "f");
			break;
		}
		case struct_dissector::field_type_t::nested_struct: {
			ImVec2 a = ImVec2(center.x - 5.f, center.y - 5.f);
			ImVec2 b = ImVec2(center.x + 5.f, center.y + 5.f);
			dl->AddRect(a, b, color, 1.5f, 0, 1.f);
			dl->AddLine(ImVec2(a.x + 2.f, center.y), ImVec2(b.x - 2.f, center.y), color, 1.f);
			break;
		}
		default: {
			dl->AddCircleFilled(center, 2.f, color, 12);
			break;
		}
	}
}

inline field_anim_t& fanim(int idx) { return g_ui.field_anims[idx]; }

inline void render_write_review_modal() {
	const std::uint64_t running_serial = g_write_running_serial.load(std::memory_order_acquire);
	if (running_serial == g_write_review.serial &&
		g_write_review.status == write_review_status_t::queued)
		g_write_review.status = write_review_status_t::running;
	const std::uint64_t dispatch_failure = g_write_dispatch_failure.exchange(0,
		std::memory_order_acq_rel);
	if (dispatch_failure != 0 && dispatch_failure == g_write_review.serial) {
		const bool applied = g_write_dispatch_applied.exchange(0,
			std::memory_order_acq_rel) == dispatch_failure;
		g_write_review.status = applied ? write_review_status_t::succeeded
			: write_review_status_t::failed;
		g_write_review.error = applied
			? "The write and exact readback succeeded, but the UI dispatcher rejected normal publication. Refresh the structure before any inverse write."
			: "The UI dispatcher rejected publication of the mutation result.";
	}
	if (g_write_review.open_requested) {
		g_write_review.open_requested = false;
		ImGui::OpenPopup("Review Structure Field Write##structure_write_review");
	}
	if (!g_write_review.visible)
		return;
	ImGui::SetNextWindowSize(ImVec2(650.0f, 0.0f), ImGuiCond_Appearing);
	if (!ImGui::BeginPopupModal("Review Structure Field Write##structure_write_review",
		nullptr, ImGuiWindowFlags_AlwaysAutoResize))
		return;
	const bool active = g_write_review.status == write_review_status_t::queued ||
		g_write_review.status == write_review_status_t::running;
	ImGui::TextUnformatted("Review the exact process mutation before it is submitted.");
	ImGui::Separator();
	ImGui::Text("Target PID");
	ImGui::SameLine(165.0f);
	ImGui::Text("%u", g_write_review.pid);
	ImGui::Text("Structure / field");
	ImGui::SameLine(165.0f);
	ImGui::Text("%s.%s", g_write_review.structure_name.c_str(),
		g_write_review.field_name.c_str());
	const std::uint64_t end_address = g_write_review.new_bytes.empty()
		? g_write_review.address
		: g_write_review.address + g_write_review.new_bytes.size() - 1;
	ImGui::Text("Address range");
	ImGui::SameLine(165.0f);
	ImGui::Text("0x%016llX - 0x%016llX (%zu bytes)",
		static_cast<unsigned long long>(g_write_review.address),
		static_cast<unsigned long long>(end_address), g_write_review.new_bytes.size());
	ImGui::Text("Old bytes");
	ImGui::SameLine(165.0f);
	const std::string old_text = format_review_bytes(g_write_review.old_bytes);
	ImGui::TextWrapped("%s", old_text.c_str());
	ImGui::Text("New bytes");
	ImGui::SameLine(165.0f);
	const std::string new_text = format_review_bytes(g_write_review.new_bytes);
	ImGui::TextWrapped("%s", new_text.c_str());
	ImGui::Spacing();
	aida::ui::inline_notice("structure_write_consequence", "Process memory will change",
		"Applying this write can change control flow, data interpretation, stability, or process behavior immediately. AiDA revalidates the reviewed old bytes before writing and requires an exact readback match.",
		aida::ui::status_kind_t::warning);
	aida::ui::inline_notice("structure_write_undo", "Undo is explicit",
		"AiDA does not silently roll back a live process mutation. After a verified write, use Stage undo to review the inverse write of these exact old bytes.",
		aida::ui::status_kind_t::neutral);
	const char* status_text = g_write_review.status == write_review_status_t::review ? "Awaiting confirmation" :
		g_write_review.status == write_review_status_t::queued ? "Queued" :
		g_write_review.status == write_review_status_t::running ? "Writing and verifying" :
		g_write_review.status == write_review_status_t::succeeded ? "Verified" :
		g_write_review.status == write_review_status_t::cancelled ? "Cancelled" :
		g_write_review.status == write_review_status_t::stale ? "Stale" : "Failed";
	aida::ui::status_badge(status_text,
		g_write_review.status == write_review_status_t::succeeded
			? aida::ui::status_kind_t::success
			: g_write_review.status == write_review_status_t::review
				? aida::ui::status_kind_t::warning
				: active ? aida::ui::status_kind_t::info : aida::ui::status_kind_t::error);
	if (!g_write_review.error.empty()) {
		ImGui::Spacing();
			aida::ui::inline_notice("structure_write_error",
				g_write_review.status == write_review_status_t::succeeded
					? "Verified with publication warning"
					: g_write_review.mutation_may_remain
						? "Mutation verification and rollback failed" : "Mutation not applied",
			g_write_review.error.c_str(),
			g_write_review.status == write_review_status_t::succeeded
				? aida::ui::status_kind_t::warning : aida::ui::status_kind_t::error);
	}
	ImGui::Separator();
	if (g_write_review.status == write_review_status_t::review) {
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md)) {
			g_write_review.visible = false;
			ImGui::CloseCurrentPopup();
		}
		ImGui::SameLine();
		if (aida::ui::button("Apply and verify", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md))
			submit_write_review();
	} else if (active) {
		if (aida::ui::button("Cancel operation", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md) && g_write_review.cancellation)
			g_write_review.cancellation->store(true, std::memory_order_release);
	} else {
		if ((g_write_review.status == write_review_status_t::succeeded &&
			g_write_review.error.empty()) || g_write_review.mutation_may_remain) {
			if (aida::ui::button("Stage undo", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md)) {
				std::swap(g_write_review.old_bytes, g_write_review.new_bytes);
				g_write_review.serial = g_write_serial.fetch_add(1,
					std::memory_order_acq_rel) + 1;
				g_write_review.status = write_review_status_t::review;
				g_write_review.error.clear();
				g_write_review.cancellation.reset();
			}
			ImGui::SameLine();
		}
		if (aida::ui::button("Close", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md)) {
			g_write_review.visible = false;
			ImGui::CloseCurrentPopup();
		}
	}
	ImGui::EndPopup();
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	struct_dissector::ensure_preview_fixture();
	if (struct_dissector::g_state.cached_values.empty())
		struct_dissector::refresh_values();
#else
	struct_dissector::ensure_persistence_loaded();
	{
		static bool s_types_font_logged_dissector = false;
		if (!s_types_font_logged_dissector) {
			s_types_font_logged_dissector = true;
			anti_tamper::webhook::write_log("types_font", "[types_font] scaled struct_dissector_view");
		}
	}
#endif

	ImGui::SetCursorScreenPos(ImVec2(ImGui::GetWindowPos().x + pos_x,
	                                 ImGui::GetWindowPos().y + pos_y));

	ImGui::BeginChild("##struct_dissector_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
	auto& ui = g_ui;
	auto& st = struct_dissector::g_state;
	const float dt = aida::ui::clock::dt();
	const float line_h = 36.f;
	const float top_bar_h = 52.f;

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wpos = ImGui::GetWindowPos();
	float ox = wpos.x;
	float oy = wpos.y;

	ui.row_anim_time += dt;
	ui.edit_ring_phase += dt;

	const auto& th = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
		aida::ui::with_alpha(th.bg_base, alpha));

	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + width, oy + top_bar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox, oy + top_bar_h - 1.f), ImVec2(ox + width, oy + top_bar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	float bx = ox + 12.f;
	float by = oy + 12.f;

	const float fs_diss_base = aida::ui::components::detail::ui_fs();
	dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
		fs_diss_base * 1.05f, ImVec2(bx, by + 4.f),
		aida::ui::with_alpha(th.text_secondary, alpha), "Base");
	bx += 48.f;

	if (!ui.addr_buf_seeded) {
		uint64_t seed = 0;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			seed = st.base_address;
		}
		if (seed != 0) {
			std::snprintf(ui.addr_buf, sizeof(ui.addr_buf), "%llX",
				static_cast<unsigned long long>(seed));
		}
		ui.addr_buf_seeded = true;
	}

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.border_subtle, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));
	ImGui::PushItemWidth(170.f);
	if (ImGui::InputText("##sd_addr", ui.addr_buf, sizeof(ui.addr_buf),
						 ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
		uint64_t addr = 0;
		if (std::sscanf(ui.addr_buf, "%llx", reinterpret_cast<unsigned long long*>(&addr)) == 1) {
			uint64_t prev = 0;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				prev = st.base_address;
				st.base_address = addr;
			}
			diag::log_tagged_fmt("dissector",
				"base_address_changed prev=0x%llX new=0x%llX",
				static_cast<unsigned long long>(prev),
				static_cast<unsigned long long>(addr));
		} else {
			diag::log_tagged_fmt("dissector",
				"base_address_parse_failed input='%s'", ui.addr_buf);
		}
	}
	ImGui::PopItemWidth();
	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar(2);
	bx += 180.f + 6.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Go", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(48.f, 28.f))) {
		uint64_t addr = 0;
		if (std::sscanf(ui.addr_buf, "%llx", reinterpret_cast<unsigned long long*>(&addr)) == 1) {
			uint64_t prev = 0;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				prev = st.base_address;
				st.base_address = addr;
			}
			diag::log_tagged_fmt("dissector",
				"base_address_go prev=0x%llX new=0x%llX",
				static_cast<unsigned long long>(prev),
				static_cast<unsigned long long>(addr));
			struct_dissector::refresh_values();
		} else {
			diag::log_tagged_fmt("dissector",
				"base_address_go_failed input='%s'", ui.addr_buf);
		}
	}
	bx += 56.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Refresh", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(96.f, 28.f))) {
		diag::log_tagged_fmt("dissector", "refresh_clicked manual=1");
		struct_dissector::refresh_values();
	}
	bx += 102.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	{
		bool auto_now = false;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			auto_now = st.auto_refresh;
		}
		if (aida::ui::toggle_switch("##sd_auto", &auto_now, aida::ui::size_t_::sm)) {
			std::lock_guard<std::mutex> lk(st.mtx);
			st.auto_refresh = auto_now;
		}
	}
	bx += 38.f;
	dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
		fs_diss_base * 0.92f, ImVec2(bx, by + 4.f),
		aida::ui::with_alpha(th.text_dim, alpha), "Auto");
	bx += 42.f + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Export C", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(86.f, 28.f))) {
		int aidx = -1;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			aidx = st.active_struct;
		}
		if (aidx >= 0) {
			std::string c_src = struct_dissector::export_to_c(aidx);
			if (!c_src.empty()) {
				ImGui::SetClipboardText(c_src.c_str());
				diag::log_tagged_fmt("dissector",
					"export_to_c_clipboard idx=%d bytes=%zu",
					aidx, c_src.size());
			}
		} else {
			diag::log_tagged_fmt("dissector",
				"export_to_c_clicked_no_active");
		}
	}
	bx += 92.f;
	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Copy Schema", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(104.f, 28.f))) {
		const std::string schema = struct_dissector::serialize_schema();
		ImGui::SetClipboardText(schema.c_str());
		ui.operation_error = false;
		ui.operation_status = "Versioned structure schema copied";
	}
	bx += 110.f;
	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Import JSON", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(104.f, 28.f))) {
		const char* clipboard = ImGui::GetClipboardText();
		std::string error;
		const bool imported = clipboard && struct_dissector::deserialize_schema(clipboard, error);
		ui.operation_error = !imported;
		ui.operation_status = imported ? "Structure schema imported and validated" :
			(error.empty() ? "Clipboard does not contain a structure schema" : error);
	}
	bx += 110.f;
	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Layout", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(78.f, 28.f)))
		ImGui::OpenPopup("##sd_layout_config");
	if (ui.layout_popup_requested) {
		ui.layout_popup_requested = false;
		ImGui::OpenPopup("##sd_layout_config");
	}
	if (ImGui::BeginPopup("##sd_layout_config")) {
		int structure_index = -1;
		struct_dissector::structure_kind_t kind = struct_dissector::structure_kind_t::structure;
		{
			std::lock_guard<std::mutex> lock(st.mtx);
			structure_index = st.active_struct;
			if (struct_dissector::valid_index(structure_index, st.structs.size()))
				kind = st.structs[static_cast<std::size_t>(structure_index)].kind;
		}
		ImGui::TextDisabled("Structure layout");
		if (ImGui::Button(kind == struct_dissector::structure_kind_t::union_type ? "Convert to Struct" : "Convert to Union")) {
			const bool applied = struct_dissector::set_structure_kind(structure_index,
				kind == struct_dissector::structure_kind_t::union_type
					? struct_dissector::structure_kind_t::structure
					: struct_dissector::structure_kind_t::union_type);
			ui.operation_error = !applied;
			ui.operation_status = applied ? "Structure kind updated" : "Structure kind change rejected";
		}
		ImGui::InputTextWithHint("##sd_pack", "packing: 0,1,2,4,8,16", ui.layout_pack_buf,
			sizeof(ui.layout_pack_buf), ImGuiInputTextFlags_CharsDecimal);
		ImGui::SameLine();
		if (ImGui::Button("Set Pack")) {
			unsigned int value = 0;
			const bool parsed = std::sscanf(ui.layout_pack_buf, "%u", &value) == 1 && value <= 4096;
			const bool applied = parsed && struct_dissector::set_structure_packing(structure_index,
				static_cast<std::uint16_t>(value));
			ui.operation_error = !applied;
			ui.operation_status = applied ? "Packing updated" : "Packing must be 0 or a power of two up to 4096";
		}
		ImGui::InputTextWithHint("##sd_struct_align", "alignment: 0,1,2,4,8,16", ui.layout_align_buf,
			sizeof(ui.layout_align_buf), ImGuiInputTextFlags_CharsDecimal);
		ImGui::SameLine();
		if (ImGui::Button("Set Align")) {
			unsigned int value = 0;
			const bool parsed = std::sscanf(ui.layout_align_buf, "%u", &value) == 1 && value <= 4096;
			const bool applied = parsed && struct_dissector::set_structure_alignment(structure_index,
				static_cast<std::uint16_t>(value));
			ui.operation_error = !applied;
			ui.operation_status = applied ? "Structure alignment updated" : "Alignment must be 0 or a power of two up to 4096";
		}
		ImGui::Separator();
		bool persistence_running = st.persistence_in_flight.load(std::memory_order_acquire);
		ImGui::BeginDisabled(persistence_running);
		if (ImGui::Button("Save Catalog"))
			struct_dissector::request_save_schema();
		ImGui::SameLine();
		if (ImGui::Button("Load Catalog"))
			struct_dissector::request_load_schema();
		ImGui::EndDisabled();
		if (persistence_running) {
			ImGui::SameLine();
			if (ImGui::Button("Cancel"))
				struct_dissector::cancel_persistence();
		}
		std::string persistence_status;
		bool persistence_error = false;
		{
			std::lock_guard<std::mutex> lock(st.mtx);
			persistence_status = st.persistence_status;
			persistence_error = st.persistence_error;
		}
		if (!persistence_status.empty())
			ImGui::TextColored(persistence_error ? ImVec4(0.95f, 0.35f, 0.35f, 1.f) :
				ImVec4(0.45f, 0.82f, 0.95f, 1.f), "%s", persistence_status.c_str());
		ImGui::EndPopup();
	}

	{
		bool auto_now_snap = false;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			auto_now_snap = st.auto_refresh;
			if (auto_now_snap) {
				st.refresh_timer += dt;
				if (st.refresh_timer >= st.refresh_interval) {
					st.refresh_timer = 0.f;
					auto_now_snap = true;
				} else {
					auto_now_snap = false;
				}
			}
		}
		if (auto_now_snap) {
			struct_dissector::refresh_values();
		}
	}

	float body_y = oy + top_bar_h + 4.f;
	float body_h = height - top_bar_h - 4.f;

	bool driver_loaded = true;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	driver_loaded = driver_bridge::is_loaded();
#endif
	if (!driver_loaded) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static bool s_no_driver_logged_diss = false;
		if (!s_no_driver_logged_diss) {
			s_no_driver_logged_diss = true;
			anti_tamper::webhook::write_log("types_audit",
				"[types_audit] dissector_view_no_driver reason='driver_not_loaded'");
		}
#endif
		float callout_h = 36.f;
		ui_anim::render_inline_callout(dl, ox + 8.f, body_y + 4.f, width - 16.f, callout_h,
			"Dissector live values need an attached process. Attach via the debugger to enable Read/Write.",
			ui_anim::callout_kind_t::warn,
			accent_r, accent_g, accent_b, alpha);
		body_y += callout_h + 8.f;
		body_h -= callout_h + 8.f;
	}

	const float kMinDissPanelW = 460.f;
	if (width < kMinDissPanelW) {
		static bool s_logged_diss_narrow = false;
		if (!s_logged_diss_narrow) {
			s_logged_diss_narrow = true;
			::diag::log_tagged_fmt("responsive",
				"struct_dissector_view clamp_overlay width=%.0f min=%.0f",
				width, kMinDissPanelW);
		}
		ImVec2 wp = ImGui::GetWindowPos();
		aida::ui::responsive::draw_clamp_overlay(
			ImVec2(wp.x + pos_x, wp.y + body_y),
			ImVec2(width, body_h),
			"Widen the panel to view the struct dissector");
		ImGui::EndChild();
		return;
	}

	float left_w = std::floor(width * 0.28f);
	if (left_w < 200.f) left_w = 200.f;
	float right_min_w = 240.f;
	if (width - left_w - 1.f < right_min_w) {
		left_w = std::max(160.f, width - right_min_w - 1.f);
	}
	float right_w = width - left_w - 1.f;

	dl->AddLine(ImVec2(ox + left_w, body_y), ImVec2(ox + left_w, body_y + body_h),
		aida::ui::with_alpha(th.border_subtle, alpha));
	bool structure_context_requested = false;
	int structure_context_index = -1;
	aida::ui::context_menu_open_origin_t structure_context_origin =
		aida::ui::context_menu_open_origin_t::menu_key;
	int active_struct_idx = -1;

	{
		float lx = ox;
		float ly = body_y;
		float lw = left_w;
		float lh = body_h;

		dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
			fs_diss_base * 0.95f, ImVec2(lx + 10.f, ly + 8.f),
			aida::ui::with_alpha(th.text_secondary, alpha), "Structures");

		float filter_y = ly + 30.f;
		ImGui::SetCursorScreenPos(ImVec2(lx + 8.f, filter_y));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));
		ImGui::PushItemWidth(lw - 16.f);
		ImGui::InputTextWithHint("##sd_list_filter", "filter structures",
			ui.list_filter, sizeof(ui.list_filter));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();

		float list_y = filter_y + 32.f;
		float list_h = lh - (list_y - ly) - (line_h * 2.f + 16.f);

		ui.list_scroll_y = aida::motion::smooth_lerp(ui.list_scroll_y,
			ui.list_target_scroll_y, 18.f, dt);

		bool list_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(lx, list_y), ImVec2(lx + lw, list_y + list_h));
		if (list_hovered) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f) ui.list_target_scroll_y -= wheel * line_h * 3.f;
		}

		std::vector<std::pair<std::string, uint32_t>> entries;
		std::vector<int> entry_index;
		std::string filter_lc;
		filter_lc.reserve(64);
		for (std::size_t i = 0; i < sizeof(ui.list_filter) && ui.list_filter[i] != '\0'; ++i) {
			char c = ui.list_filter[i];
			if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
			filter_lc.push_back(c);
		}
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			active_struct_idx = st.active_struct;
			entries.reserve(st.structs.size());
			entry_index.reserve(st.structs.size());
			for (std::size_t i = 0; i < st.structs.size(); ++i) {
				auto& sd = st.structs[i];
				if (!filter_lc.empty()) {
					std::string name_lc;
					name_lc.reserve(sd.name.size());
					for (char c : sd.name) {
						if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
						name_lc.push_back(c);
					}
					if (name_lc.find(filter_lc) == std::string::npos) continue;
				}
				if (!struct_dissector::index_fits_int(i)) break;
				entries.emplace_back(sd.name, sd.total_size);
				entry_index.push_back(static_cast<int>(i));
			}
		}
		const std::size_t struct_count = entries.size();

		float content_h = static_cast<float>(struct_count) * line_h;
		if (ui.list_target_scroll_y < 0.f) ui.list_target_scroll_y = 0.f;
		float ms = std::max(0.f, content_h - list_h);
		if (ui.list_target_scroll_y > ms) ui.list_target_scroll_y = ms;

		ImGui::PushClipRect(ImVec2(lx, list_y), ImVec2(lx + lw, list_y + list_h), true);
		if (struct_count == 0) {
			ImFont* hint_font = aida::ui::fonts::body_em();
			if (!hint_font) hint_font = ImGui::GetFont();
			const char* msg = filter_lc.empty() ? "No structs yet" : "No matches";
			const float fs_hint = fs_diss_base * 1.00f;
			ImVec2 sz = hint_font->CalcTextSizeA(fs_hint, FLT_MAX, 0.f, msg);
			dl->AddText(hint_font, fs_hint,
				ImVec2(lx + (lw - sz.x) * 0.5f, list_y + list_h * 0.5f - sz.y * 0.5f),
				aida::ui::with_alpha(th.text_dim, alpha), msg);
		}
		for (std::size_t i = 0; i < struct_count; ++i) {
			int sd_idx = entry_index[i];
			float ry = list_y + static_cast<float>(i) * line_h - ui.list_scroll_y;
			if (ry + line_h < list_y || ry > list_y + list_h) continue;

			ImVec2 a = ImVec2(lx + 4.f, ry);
			ImVec2 b = ImVec2(lx + lw - 4.f, ry + line_h);
			bool hov = ImGui::IsMouseHoveringRect(a, b, true);
			bool sel = (active_struct_idx == sd_idx);

			ImU32 fill = sel
				? aida::ui::with_alpha(th.selection, alpha)
				: (hov ? aida::ui::with_alpha(th.hover_wash, alpha * 0.6f) : 0u);
			if ((fill & 0xFF000000) != 0) {
				dl->AddRectFilled(a, b, fill, 6.f);
			}
			if (sel) {
				dl->AddRectFilled(ImVec2(a.x, a.y),
					ImVec2(a.x + 3.f, b.y), aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
			}

			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				ui.list_focused = true;
				ui.table_focused = false;
				std::string sel_name;
				{
					std::lock_guard<std::mutex> lk(st.mtx);
					if (struct_dissector::valid_index(sd_idx, st.structs.size())) {
						st.active_struct = sd_idx;
						active_struct_idx = sd_idx;
						sel_name = st.structs[static_cast<std::size_t>(sd_idx)].name;
					}
					ui.selected_field = -1;
					ui.editing_field = -1;
					ui.edit_target = edit_target_t::none;
				}
				diag::log_tagged_fmt("dissector",
					"struct_selected idx=%d name='%s'",
					sd_idx, sel_name.c_str());
			}
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
				bool selected = false;
				{
					std::lock_guard<std::mutex> lock(st.mtx);
					if (struct_dissector::valid_index(sd_idx, st.structs.size())) {
						st.active_struct = sd_idx;
						active_struct_idx = sd_idx;
						selected = true;
					}
				}
				if (selected) {
					ui.list_focused = true;
					ui.table_focused = false;
					ui.selected_field = -1;
					ui.editing_field = -1;
					ui.edit_target = edit_target_t::none;
					structure_context_requested = true;
					structure_context_index = sd_idx;
					structure_context_origin =
						aida::ui::context_menu_open_origin_t::pointer;
				}
			}

			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				fs_diss_base * 1.05f, ImVec2(a.x + 10.f, ry + 5.f),
				aida::ui::with_alpha(th.text_primary, alpha),
				entries[i].first.c_str());
			char sz_buf[32];
			std::snprintf(sz_buf, sizeof(sz_buf), "(%u)", entries[i].second);
			ImFont* code_font = aida::ui::fonts::code();
			if (!code_font) code_font = ImGui::GetFont();
			const float fs_diss_count = fs_diss_base * 0.92f;
			ImVec2 sz = code_font->CalcTextSizeA(fs_diss_count, FLT_MAX, 0.f, sz_buf);
			dl->AddText(code_font, fs_diss_count, ImVec2(b.x - sz.x - 8.f, ry + 6.f),
				aida::ui::with_alpha(th.text_dim, alpha), sz_buf);
		}
		ImGui::PopClipRect();

		float ren_y = ly + lh - line_h * 2.f - 8.f;
		ImGui::SetCursorScreenPos(ImVec2(lx + 8.f, ren_y));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));
		ImGui::PushItemWidth(lw - 16.f - 64.f - 4.f);
		ImGui::InputTextWithHint("##sd_rename", "rename selected",
			ui.rename_buf, sizeof(ui.rename_buf));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();
		ImGui::SameLine();
		if (aida::ui::button("Rename", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(64.f, 28.f))) {
			int target_idx = -1;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				target_idx = st.active_struct;
			}
			if (target_idx >= 0 && ui.rename_buf[0] != '\0') {
				if (struct_dissector::rename_struct(target_idx, ui.rename_buf)) {
					ui.rename_buf[0] = '\0';
				}
			} else {
				diag::log_tagged_fmt("dissector",
					"rename_struct_skipped reason='%s'",
					target_idx < 0 ? "no_active" : "empty_name");
			}
		}

		float btn_y = ly + lh - line_h + 2.f;
		ImGui::SetCursorScreenPos(ImVec2(lx + 8.f, btn_y));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));
		ImGui::PushItemWidth(lw * 0.5f);
		ImGui::InputTextWithHint("##sd_newname", "name", ui.name_buf, sizeof(ui.name_buf));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();

		ImGui::SameLine();
		if (aida::ui::button("+", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(28.f, 28.f))) {
			if (ui.name_buf[0] != '\0') {
				int new_idx = struct_dissector::create_struct(ui.name_buf);
				if (new_idx >= 0) {
					std::lock_guard<std::mutex> lk(st.mtx);
					st.active_struct = new_idx;
					ui.selected_field = -1;
					ui.editing_field = -1;
				}
				ui.name_buf[0] = '\0';
			} else {
				diag::log_tagged_fmt("dissector",
					"create_struct_skipped reason='empty_name'");
			}
		}
		ImGui::SameLine();
		if (aida::ui::button("-", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(28.f, 28.f))) {
			std::string deleted_name;
			int removed_idx = -1;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (struct_dissector::valid_index(st.active_struct, st.structs.size())) {
					removed_idx = st.active_struct;
					deleted_name = st.structs[static_cast<std::size_t>(st.active_struct)].name;
				}
			}
			std::string error;
			if (removed_idx >= 0 && struct_dissector::remove_structure(removed_idx, error)) {
				ui.selected_field = -1;
				ui.editing_field = -1;
				ui.edit_target = edit_target_t::none;
				ui.operation_error = false;
				ui.operation_status = "Structure removed";
				diag::log_tagged_fmt("dissector",
					"delete_struct idx=%d name='%s'", removed_idx, deleted_name.c_str());
			} else {
				ui.operation_error = true;
				ui.operation_status = error.empty() ? "No active structure" : error;
				diag::log_tagged_fmt("dissector",
					"delete_struct_skipped reason='%s'", ui.operation_status.c_str());
			}
		}
		{
			std::lock_guard<std::mutex> lock(st.mtx);
			active_struct_idx = st.active_struct;
		}
		const bool active_structure_visible = std::find(
			entry_index.begin(), entry_index.end(), active_struct_idx) !=
			entry_index.end();
		const bool structure_menu_key =
			ImGui::IsKeyPressed(ImGuiKey_Menu, false);
		const bool structure_shift_f10 = ImGui::GetIO().KeyShift &&
			ImGui::IsKeyPressed(ImGuiKey_F10, false);
		if (!structure_context_requested && ui.list_focused &&
			active_struct_idx >= 0 && active_structure_visible &&
			(structure_menu_key || structure_shift_f10)) {
			structure_context_requested = true;
			structure_context_index = active_struct_idx;
			structure_context_origin = structure_menu_key
				? aida::ui::context_menu_open_origin_t::menu_key
				: aida::ui::context_menu_open_origin_t::shift_f10;
		}
	}
	if (structure_context_requested) {
		struct_dissector::struct_def_t snapshot;
		bool valid_structure = false;
		{
			std::lock_guard<std::mutex> lock(st.mtx);
			if (struct_dissector::valid_index(
					structure_context_index, st.structs.size())) {
				snapshot = st.structs[
					static_cast<std::size_t>(structure_context_index)];
				valid_structure = snapshot.stable_id != 0;
			}
		}
		if (valid_structure) {
			const std::uint64_t retained_id = snapshot.stable_id;
			const std::uint64_t retained_revision = snapshot.layout_revision;
			const auto resolve_structure = [retained_id, retained_revision]()
				-> std::optional<int> {
				auto& state = struct_dissector::g_state;
				std::lock_guard<std::mutex> lock(state.mtx);
				const int index =
					struct_dissector::structure_index_by_id_locked(retained_id);
				if (!struct_dissector::valid_index(index, state.structs.size()) ||
					state.structs[static_cast<std::size_t>(index)].stable_id !=
						retained_id ||
					state.structs[static_cast<std::size_t>(index)].layout_revision !=
						retained_revision)
					return std::nullopt;
				return index;
			};
			aida::ui::application_ui::retained_entity_context_t retained;
			retained.owner_id = "types.dissector.structure";
			retained.entity_id = std::to_string(retained_id);
			retained.entity_generation = retained_revision;
			retained.active_view =
				aida::ui::stable_view_id_t("view.types.dissector");
			retained.validate_identity = [resolve_structure] {
				return resolve_structure()
					? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(
						"The structure layout changed; select it again");
			};
			auto add_structure_action = [&retained](std::string id,
				bool enabled, const char* reason,
				std::function<aida::ui::action_handler_result_t()> invoke) {
				aida::ui::application_ui::retained_entity_action_t action;
				action.action_id = std::move(id);
				action.capability = enabled
					? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(reason);
				action.invoke = std::move(invoke);
				retained.actions.push_back(std::move(action));
			};
			add_structure_action("types.dissector.structure.copy_name", true,
				"The retained structure is stale", [resolve_structure] {
					const auto index = resolve_structure();
					if (!index)
						return aida::ui::action_handler_result_t::failed(
							"The retained structure is stale");
					std::string name;
					{
						auto& state = struct_dissector::g_state;
						std::lock_guard<std::mutex> lock(state.mtx);
						if (!struct_dissector::valid_index(
								*index, state.structs.size()))
							return aida::ui::action_handler_result_t::failed(
								"The retained structure is stale");
						name = state.structs[static_cast<std::size_t>(*index)].name;
					}
					ImGui::SetClipboardText(name.c_str());
					return aida::ui::action_handler_result_t::completed();
				});
			add_structure_action(
				"types.dissector.structure.copy_declaration", true,
				"The retained structure is stale", [resolve_structure] {
					const auto index = resolve_structure();
					if (!index)
						return aida::ui::action_handler_result_t::failed(
							"The retained structure is stale");
					const std::string declaration =
						struct_dissector::export_to_c(*index);
					if (declaration.empty())
						return aida::ui::action_handler_result_t::failed(
							"The structure could not be exported");
					ImGui::SetClipboardText(declaration.c_str());
					return aida::ui::action_handler_result_t::completed();
				});
			add_structure_action(
				"types.dissector.structure.configure_layout", true,
				"The retained structure is stale", [resolve_structure] {
					const auto index = resolve_structure();
					if (!index)
						return aida::ui::action_handler_result_t::failed(
							"The retained structure is stale");
					{
						auto& state = struct_dissector::g_state;
						std::lock_guard<std::mutex> lock(state.mtx);
						if (!struct_dissector::valid_index(
								*index, state.structs.size()))
							return aida::ui::action_handler_result_t::failed(
								"The retained structure is stale");
						state.active_struct = *index;
					}
					g_ui.layout_popup_requested = true;
					return aida::ui::action_handler_result_t::completed();
				});
			add_structure_action("types.dissector.structure.toggle_union", true,
				"The retained structure is stale",
				[resolve_structure, kind = snapshot.kind] {
					const auto index = resolve_structure();
					if (!index)
						return aida::ui::action_handler_result_t::failed(
							"The retained structure is stale");
					const bool applied = struct_dissector::set_structure_kind(
						*index, kind == struct_dissector::structure_kind_t::union_type
							? struct_dissector::structure_kind_t::structure
							: struct_dissector::structure_kind_t::union_type);
					return applied
						? aida::ui::action_handler_result_t::completed()
						: aida::ui::action_handler_result_t::failed(
							"The structure kind change failed validation");
				});
			const bool persistence_available =
				!st.persistence_in_flight.load(std::memory_order_acquire);
			add_structure_action("types.dissector.structure.save_catalog",
				persistence_available,
				"Another structure catalog operation is running",
				[resolve_structure] {
					if (!resolve_structure())
						return aida::ui::action_handler_result_t::failed(
							"The retained structure is stale");
					return struct_dissector::request_save_schema()
						? aida::ui::action_handler_result_t::completed(
							"Structure schema save queued")
						: aida::ui::action_handler_result_t::failed(
							"Structure schema save was not queued");
				});
			add_structure_action("types.dissector.structure.load_catalog",
				persistence_available,
				"Another structure catalog operation is running",
				[resolve_structure] {
					if (!resolve_structure())
						return aida::ui::action_handler_result_t::failed(
							"The retained structure is stale");
					return struct_dissector::request_load_schema()
						? aida::ui::action_handler_result_t::completed(
							"Structure schema load queued")
						: aida::ui::action_handler_result_t::failed(
							"Structure schema load was not queued");
				});
			aida::ui::application_ui::open_retained_entity_context_menu(
				std::move(retained), structure_context_origin);
		} else {
			ui.operation_error = true;
			ui.operation_status =
				"The requested structure no longer exists";
		}
	}
	aida::ui::application_ui::render_retained_entity_context_menu(
		"types.dissector.structure");

	{
		float rx = ox + left_w + 1.f;
		float ry_start = body_y;
		float rw = right_w;
		float rh = body_h;

		int active_idx = -1;
		std::size_t field_count = 0;
		std::uint64_t active_base_address = 0;
		std::uint64_t active_structure_id = 0;
		std::uint64_t active_layout_revision = 0;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			active_idx = st.active_struct;
			active_base_address = st.base_address;
			if (struct_dissector::valid_index(active_idx, st.structs.size())) {
				field_count = st.structs[static_cast<std::size_t>(active_idx)].fields.size();
				active_structure_id = st.structs[static_cast<std::size_t>(active_idx)].stable_id;
				active_layout_revision = st.structs[static_cast<std::size_t>(active_idx)].layout_revision;
			}
		}

		if (active_idx < 0) {
			ImVec2 sz = ImVec2(rw, rh);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::memory;
			cfg.title = "No struct selected";
			cfg.body = "Create or select a struct from the list to begin dissecting memory.";
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(ImVec2(rx, ry_start), sz, cfg);
			ImGui::EndChild();
			return;
		}

		const float col_offset_w = 92.f;
		const float col_glyph_w  = 28.f;
		const float col_name_w   = 260.f;
		const float col_type_w   = 144.f;
		const float col_value_w  = std::max(200.f, rw - col_offset_w - col_glyph_w
		                          - col_name_w - col_type_w - 180.f - 12.f);
		const float col_desc_w   = 180.f;

		float hdr_y = ry_start;
		ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
		dl->AddRectFilled(ImVec2(rx, hdr_y), ImVec2(rx + rw, hdr_y + line_h), hdr_bg, 6.f);
		dl->AddLine(ImVec2(rx, hdr_y + line_h - 1.f), ImVec2(rx + rw, hdr_y + line_h - 1.f),
			aida::ui::with_alpha(th.border_subtle, alpha));

		ImFont* head_em = aida::ui::fonts::body_em();
		if (!head_em) head_em = ImGui::GetFont();
		ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
		const float fs_dh = fs_diss_base * 0.95f;
		float hx = rx + 8.f;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Offset");
		hx += col_offset_w + col_glyph_w;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Name");
		hx += col_name_w;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Type");
		hx += col_type_w;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Value");
		hx += col_value_w;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Description");

		float table_y = ry_start + line_h;
		float table_h = rh - line_h - line_h - 8.f;

		ui.scroll_y = aida::motion::smooth_lerp(ui.scroll_y, ui.target_scroll_y, 18.f, dt);

		bool table_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(rx, table_y), ImVec2(rx + rw, table_y + table_h));
		if (table_hovered) {
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
				ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
				ui.table_focused = true;
				ui.list_focused = false;
			}
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f) ui.target_scroll_y -= wheel * line_h * 3.f;
		}

		float content_h = static_cast<float>(field_count) * line_h;
		if (ui.target_scroll_y < 0.f) ui.target_scroll_y = 0.f;
		float ms = std::max(0.f, content_h - table_h);
		if (ui.target_scroll_y > ms) ui.target_scroll_y = ms;

		struct deferred_edit_t {
			edit_target_t target = edit_target_t::none;
			int field_idx = -1;
			std::string seed_text;
		} pending_edit;
		bool ctx_open_request = false;
		int  ctx_open_field = -1;
		aida::ui::context_menu_open_origin_t ctx_open_origin =
			aida::ui::context_menu_open_origin_t::menu_key;
		struct visible_field_t {
			std::size_t index = 0;
			struct_dissector::field_def_t field;
			struct_dissector::live_value_t value;
			bool has_value = false;
		};
		const std::size_t first_visible = static_cast<std::size_t>((std::max)(0,
			static_cast<int>(ui.scroll_y / line_h)));
		const std::size_t visible_capacity = static_cast<std::size_t>((std::max)(1,
			static_cast<int>(table_h / line_h) + 2));
		std::string active_structure_name;
		std::vector<visible_field_t> visible_fields;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			if (struct_dissector::valid_index(active_idx, st.structs.size())) {
				const auto& selected = st.structs[static_cast<std::size_t>(active_idx)];
				active_structure_name = selected.name;
				const std::size_t last_visible = (std::min)(selected.fields.size(),
					first_visible + visible_capacity);
				visible_fields.reserve(last_visible > first_visible
					? last_visible - first_visible : 0);
				for (std::size_t index = first_visible; index < last_visible; ++index) {
					visible_field_t row;
					row.index = index;
					row.field = selected.fields[index];
					if (index < st.cached_values.size()) {
						row.value = st.cached_values[index];
						row.has_value = true;
					}
					visible_fields.push_back(std::move(row));
				}
			}
		}
		if (ui.validation_structure_id != active_structure_id ||
			ui.validation_revision != active_layout_revision) {
			ui.validation = struct_dissector::validate_structure(active_idx);
			ui.validation_structure_id = active_structure_id;
			ui.validation_revision = active_layout_revision;
		}

		ImGui::PushClipRect(ImVec2(rx, table_y), ImVec2(rx + rw, table_y + table_h), true);
		{
			for (auto& row : visible_fields) {
					const std::size_t field_index = row.index;
					if (!struct_dissector::index_fits_int(field_index)) break;
					const int fi = static_cast<int>(field_index);
					float row_y = table_y + static_cast<float>(field_index) * line_h - ui.scroll_y;
					if (row_y + line_h < table_y || row_y > table_y + table_h) continue;

					float entrance_delay = std::min(static_cast<float>(fi) * 0.008f, 0.240f);
					float entrance_t = (ui.row_anim_time - entrance_delay) / 0.32f;
					if (entrance_t < 0.f) entrance_t = 0.f;
					if (entrance_t > 1.f) entrance_t = 1.f;
					float entrance = aida::motion::ease::out_cubic(entrance_t);
					if (entrance < 0.01f) continue;

					bool row_sel = (ui.selected_field == fi);
					bool row_hov = ImGui::IsMouseHoveringRect(
						ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h), false);

					ImU32 row_fill;
					if (row_sel) row_fill = aida::ui::with_alpha(th.selection, alpha);
					else if (row_hov) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
					else row_fill = ((field_index & 1U) != 0U)
						? aida::ui::with_alpha(th.panel_bg, alpha * 0.55f * entrance)
						: 0u;
					if ((row_fill & 0xFF000000) != 0) {
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							row_fill, 4.f);
					}
					if (row_sel) {
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + 3.f, row_y + line_h),
							aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
					}

					auto& fa = fanim(fi);
					float change_v = fa.change_flash.tick(dt, 1.7f);
					if (change_v > 0.001f) {
						ImU32 pulse = aida::ui::with_alpha(th.error, alpha * change_v * 0.4f);
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							pulse, 4.f);
					}
					float write_v = fa.write_success.tick(dt, 2.0f);
					if (write_v > 0.001f) {
						ImU32 pulse = aida::ui::with_alpha(th.success_soft, alpha * write_v * 1.5f);
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							pulse, 4.f);
					}

					const auto& f = row.field;
					if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						ui.selected_field = fi;
						publish_field_selection(active_structure_name, f);
					}
					if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
						ui.selected_field = fi;
						ctx_open_request = true;
						ctx_open_field = fi;
						ctx_open_origin =
							aida::ui::context_menu_open_origin_t::pointer;
						publish_field_selection(active_structure_name, f);
					}
					float fx = rx + 8.f;
					ImFont* code_font = aida::ui::fonts::code();
					if (!code_font) code_font = ImGui::GetFont();

					const float fs_drow_meta = fs_diss_base * 0.95f;
					const float fs_drow_body = fs_diss_base * 1.00f;
					char off_str[16];
					std::snprintf(off_str, sizeof(off_str), "+0x%03X", f.offset);
					dl->AddText(code_font, fs_drow_meta, ImVec2(fx, row_y + 9.f),
						aida::ui::with_alpha(th.text_address, alpha * entrance), off_str);
					fx += col_offset_w;

					ImU32 type_c = type_color_token(f.type, alpha * entrance);
					render_type_glyph(dl, ImVec2(fx + col_glyph_w * 0.5f, row_y + line_h * 0.5f),
						f.type, type_c);
					fx += col_glyph_w;

					float name_x = fx;
					dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
						fs_drow_body, ImVec2(fx, row_y + 9.f),
						aida::ui::with_alpha(th.text_primary, alpha * entrance), f.name.c_str());
					if (row_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
						ImVec2 mp = ImGui::GetMousePos();
						if (mp.x >= name_x && mp.x <= name_x + col_name_w &&
							mp.y >= row_y && mp.y <= row_y + line_h) {
							pending_edit.target = edit_target_t::field_name;
							pending_edit.field_idx = fi;
							pending_edit.seed_text = f.name;
						}
					}
					fx += col_name_w;

					float type_x = fx;
					dl->AddText(code_font, fs_drow_meta, ImVec2(fx, row_y + 9.f),
						type_c, struct_dissector::field_type_name(f.type));
					if (row_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
						ImVec2 mp = ImGui::GetMousePos();
						if (mp.x >= type_x && mp.x <= type_x + col_type_w &&
							mp.y >= row_y && mp.y <= row_y + line_h) {
							ctx_open_request = true;
							ctx_open_field = fi;
							ctx_open_origin =
								aida::ui::context_menu_open_origin_t::pointer;
						}
					}
					fx += col_type_w;

					if (row.has_value) {
						const auto& cv = row.value;
						bool changed_now = cv.changed && fa.has_last && fa.last_bytes != cv.raw_bytes;
						if (changed_now) fa.change_flash.trigger();
						fa.last_bytes = cv.raw_bytes;
						fa.has_last = true;

						ImU32 val_col = aida::ui::with_alpha(th.text_primary, alpha * entrance);
						dl->AddText(code_font, fs_drow_meta, ImVec2(fx, row_y + 9.f),
							val_col, cv.display_text.c_str());

						if (ui.editing_field == fi) {
							float ring_pulse = sinf(ui.edit_ring_phase * 6.f) * 0.5f + 0.5f;
							ImU32 ring = aida::ui::with_alpha(th.accent_hover,
								alpha * (0.45f + ring_pulse * 0.45f));
							dl->AddRect(ImVec2(fx - 2.f, row_y + 1.f),
								ImVec2(fx + col_value_w - 4.f, row_y + line_h - 1.f),
								ring, 5.f, 0, 1.5f);

							ImGui::SetCursorScreenPos(ImVec2(fx, row_y + 1.f));
							ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
								aida::ui::with_alpha(th.panel_header, alpha)));
							ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
								aida::ui::with_alpha(th.text_primary, alpha)));
							ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
							ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 2.f));
							ImGui::PushItemWidth(col_value_w - 8.f);
							bool committed = ImGui::InputText("##sd_edit_val", ui.edit_value_buf,
								sizeof(ui.edit_value_buf),
								ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
							ImGui::PopItemWidth();
							ImGui::PopStyleVar(2);
							ImGui::PopStyleColor(2);
							if (committed) {
								std::string stage_error;
								const auto context = disasm_view::capture_selected_workspace();
								if (!stage_write_review(context, active_idx, fi, f, cv,
									ui.edit_base_address, ui.edit_value_buf, stage_error))
									toast_notification::push(stage_error,
										toast_notification::toast_type_t::error, 5.f);
								ui.editing_field = -1;
							}
							if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
								ui.editing_field = -1;
						}

						if (ui.selected_field == fi && ui.editing_field != fi &&
							ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
							ImVec2 mp = ImGui::GetMousePos();
							if (mp.x >= fx && mp.x <= fx + col_value_w &&
								mp.y >= row_y && mp.y <= row_y + line_h) {
								ui.editing_field = fi;
								ui.edit_base_address = active_base_address;
								std::strncpy(ui.edit_value_buf, cv.display_text.c_str(),
											 sizeof(ui.edit_value_buf) - 1);
								ui.edit_value_buf[sizeof(ui.edit_value_buf) - 1] = '\0';
							}
						}
					}
					fx += col_value_w;

					float desc_x = fx;
					if (!f.description.empty()) {
						dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
							fs_drow_meta, ImVec2(fx, row_y + 9.f),
							aida::ui::with_alpha(th.text_dim, alpha * entrance),
							f.description.c_str());
					} else {
						dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
							fs_drow_meta, ImVec2(fx, row_y + 9.f),
							aida::ui::with_alpha(th.text_dim, alpha * entrance * 0.55f),
							"(comment)");
					}
					if (row_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
						ImVec2 mp = ImGui::GetMousePos();
						if (mp.x >= desc_x && mp.x <= desc_x + col_desc_w &&
							mp.y >= row_y && mp.y <= row_y + line_h) {
							pending_edit.target = edit_target_t::field_comment;
							pending_edit.field_idx = fi;
							pending_edit.seed_text = f.description;
						}
					}
				}
		}
		ImGui::PopClipRect();
		const std::size_t layout_errors = static_cast<std::size_t>(std::count_if(
			ui.validation.issues.begin(), ui.validation.issues.end(), [](const struct_dissector::layout_issue_t& issue) {
				return issue.severity == struct_dissector::layout_issue_severity_t::error;
			}));
		const std::string validation_text = layout_errors == 0
			? "Layout valid · size " + std::to_string(ui.validation.computed_size) +
				" · align " + std::to_string(ui.validation.effective_alignment)
			: std::to_string(layout_errors) + " layout error(s)";
		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			fs_diss_base * 0.9f, ImVec2(rx + 8.f, table_y + table_h + 8.f),
			aida::ui::with_alpha(layout_errors == 0 ? th.success_soft : th.error, alpha), validation_text.c_str());
		if (!ui.operation_status.empty())
			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				fs_diss_base * 0.9f, ImVec2(rx + rw * 0.48f, table_y + table_h + 8.f),
				aida::ui::with_alpha(ui.operation_error ? th.error : th.text_secondary, alpha),
				ui.operation_status.c_str());

		const bool field_menu_key = ImGui::IsKeyPressed(ImGuiKey_Menu, false);
		const bool field_shift_f10 = ImGui::GetIO().KeyShift &&
			ImGui::IsKeyPressed(ImGuiKey_F10, false);
		if (!ctx_open_request && ui.table_focused && ui.selected_field >= 0 &&
			(field_menu_key || field_shift_f10)) {
			ctx_open_request = true;
			ctx_open_field = ui.selected_field;
			ctx_open_origin = field_menu_key
				? aida::ui::context_menu_open_origin_t::menu_key
				: aida::ui::context_menu_open_origin_t::shift_f10;
		}

		if (pending_edit.target != edit_target_t::none && pending_edit.field_idx >= 0) {
			ui.edit_target = pending_edit.target;
			ui.edit_target_field = pending_edit.field_idx;
			ui.edit_structure_id = 0;
			ui.edit_structure_revision = 0;
			ui.edit_field_id = 0;
			{
				std::lock_guard<std::mutex> lock(st.mtx);
				if (struct_dissector::valid_index(active_idx, st.structs.size())) {
					const auto& structure = st.structs[static_cast<std::size_t>(active_idx)];
					if (struct_dissector::valid_index(pending_edit.field_idx,
						structure.fields.size())) {
						ui.edit_structure_id = structure.stable_id;
						ui.edit_structure_revision = structure.layout_revision;
						ui.edit_field_id = structure.fields[
							static_cast<std::size_t>(pending_edit.field_idx)].stable_id;
					}
				}
			}
			std::strncpy(ui.rename_buf, pending_edit.seed_text.c_str(),
				sizeof(ui.rename_buf) - 1);
			ui.rename_buf[sizeof(ui.rename_buf) - 1] = '\0';
			ImGui::OpenPopup("##sd_inline_edit");
			diag::log_tagged_fmt("dissector",
				"inline_edit_open kind=%d field_idx=%d",
				static_cast<int>(pending_edit.target), pending_edit.field_idx);
		}
		if (ctx_open_request && ctx_open_field >= 0) {
			ui.edit_target_field = ctx_open_field;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (struct_dissector::valid_index(active_idx, st.structs.size())) {
					const auto& selected = st.structs[static_cast<std::size_t>(active_idx)];
					if (struct_dissector::valid_index(ctx_open_field, selected.fields.size()))
						publish_field_selection(selected.name,
							selected.fields[static_cast<std::size_t>(ctx_open_field)]);
				}
			}
			ui.context_refresh_seq = st.last_completed_seq.load(std::memory_order_acquire);
			ui.context_base_address = active_base_address;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			ui.context_target_pid = 4242;
#else
			ui.context_target_pid = driver_bridge::attached_pid();
#endif
			diag::log_tagged_fmt("dissector",
				"field_ctx_open field_idx=%d", ctx_open_field);
		}

		if (ImGui::BeginPopup("##sd_inline_edit")) {
			const char* hint = "rename";
			const char* commit = "Rename";
			switch (ui.edit_target) {
			case edit_target_t::field_name:    hint = "field name";    commit = "Rename";     break;
			case edit_target_t::field_size:    hint = "new size";      commit = "Set Size";   break;
			case edit_target_t::field_comment: hint = "comment";       commit = "Set Comment";break;
			case edit_target_t::struct_name:   hint = "struct name";   commit = "Rename";     break;
			case edit_target_t::array_count:   hint = "array count (1-1048576)"; commit = "Set Count"; break;
			case edit_target_t::nested_target: hint = "exact structure name"; commit = "Set Type"; break;
			case edit_target_t::pointer_target: hint = "exact pointee structure name"; commit = "Set Pointer"; break;
			case edit_target_t::enum_reference: hint = "exact enum name"; commit = "Set Enum"; break;
			case edit_target_t::bitfield:      hint = "bit offset:width or none"; commit = "Set Bits"; break;
			case edit_target_t::field_alignment: hint = "alignment (0 or power of two)"; commit = "Align"; break;
			default: break;
			}
			ImGui::TextDisabled("%s", hint);
			ImGui::PushItemWidth(280.f);
			bool accept = ImGui::InputText("##sd_inline_buf", ui.rename_buf,
				sizeof(ui.rename_buf), ImGuiInputTextFlags_EnterReturnsTrue);
			ImGui::PopItemWidth();
			ImGui::SameLine();
			if (ImGui::Button(commit) || accept) {
				int mutation_struct_idx = active_idx;
				int tgt_field = ui.edit_target_field;
				bool edit_identity_valid = true;
				if (ui.edit_structure_id != 0 && ui.edit_field_id != 0) {
					edit_identity_valid = false;
					const auto edit_field_id = ui.edit_field_id;
					std::lock_guard<std::mutex> lock(st.mtx);
					mutation_struct_idx = struct_dissector::structure_index_by_id_locked(
						ui.edit_structure_id);
					if (struct_dissector::valid_index(mutation_struct_idx, st.structs.size())) {
						const auto& structure = st.structs[
							static_cast<std::size_t>(mutation_struct_idx)];
						if (structure.stable_id == ui.edit_structure_id &&
							structure.layout_revision == ui.edit_structure_revision) {
							const auto found = std::find_if(structure.fields.begin(),
								structure.fields.end(), [edit_field_id](const auto& field) {
									return field.stable_id == edit_field_id;
								});
							if (found != structure.fields.end()) {
								const auto distance = static_cast<std::size_t>(
									std::distance(structure.fields.begin(), found));
								if (struct_dissector::index_fits_int(distance)) {
									tgt_field = static_cast<int>(distance);
									edit_identity_valid = true;
								}
							}
						}
					}
				}
				bool applied = false;
				if (edit_identity_valid) switch (ui.edit_target) {
				case edit_target_t::field_name:
					if (tgt_field >= 0 && ui.rename_buf[0] != '\0')
						applied = struct_dissector::rename_field(mutation_struct_idx, tgt_field, ui.rename_buf);
					break;
				case edit_target_t::field_size: {
					uint32_t nsz = 0;
					if (std::sscanf(ui.rename_buf, "%u", &nsz) == 1 && nsz > 0)
						applied = struct_dissector::set_field_size(mutation_struct_idx, tgt_field, nsz);
					else
						diag::log_tagged_fmt("dissector",
							"set_field_size_input_invalid input='%s'", ui.rename_buf);
					break;
				}
				case edit_target_t::field_comment:
					if (tgt_field >= 0)
						applied = struct_dissector::set_field_comment(mutation_struct_idx, tgt_field, ui.rename_buf);
					break;
				case edit_target_t::struct_name:
					if (active_idx >= 0 && ui.rename_buf[0] != '\0')
						applied = struct_dissector::rename_struct(active_idx, ui.rename_buf);
					break;
				case edit_target_t::array_count: {
					unsigned long value = 0;
					char* end = nullptr;
					value = std::strtoul(ui.rename_buf, &end, 0);
					if (end && *end == '\0' && value <= 1048576)
						applied = struct_dissector::set_field_array_count(mutation_struct_idx, tgt_field,
							static_cast<std::uint32_t>(value));
					break;
				}
				case edit_target_t::nested_target:
					applied = struct_dissector::set_field_nested_target_by_name(mutation_struct_idx,
						tgt_field, ui.rename_buf, false);
					break;
				case edit_target_t::pointer_target:
					applied = struct_dissector::set_field_nested_target_by_name(mutation_struct_idx,
						tgt_field, ui.rename_buf, true);
					break;
				case edit_target_t::enum_reference:
					applied = struct_dissector::set_field_enum_reference(mutation_struct_idx,
						tgt_field, ui.rename_buf);
					break;
				case edit_target_t::bitfield: {
					if (std::strcmp(ui.rename_buf, "none") == 0 || std::strcmp(ui.rename_buf, "0") == 0)
						applied = struct_dissector::set_field_bitfield(mutation_struct_idx, tgt_field, 0, 0);
					else {
						unsigned int offset = 0;
						unsigned int width = 0;
						if (std::sscanf(ui.rename_buf, "%u:%u", &offset, &width) == 2 &&
							offset <= 65535 && width <= 65535)
							applied = struct_dissector::set_field_bitfield(mutation_struct_idx, tgt_field,
								static_cast<std::uint16_t>(offset), static_cast<std::uint16_t>(width));
					}
					break;
				}
				case edit_target_t::field_alignment: {
					unsigned int alignment = 0;
					if (std::sscanf(ui.rename_buf, "%u", &alignment) == 1 && alignment <= 4096)
						applied = struct_dissector::set_field_alignment(mutation_struct_idx, tgt_field,
							static_cast<std::uint16_t>(alignment));
					break;
				}
				default: break;
				}
				ui.operation_error = !applied;
				ui.operation_status = applied ? "Structure layout updated" :
					"Layout change rejected; check ranges, overlap, recursion, and alignment";
				ui.edit_target = edit_target_t::none;
				ui.edit_target_field = -1;
				ui.edit_structure_id = 0;
				ui.edit_structure_revision = 0;
				ui.edit_field_id = 0;
				ui.rename_buf[0] = '\0';
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel")) {
				ui.edit_target = edit_target_t::none;
				ui.edit_target_field = -1;
				ui.edit_structure_id = 0;
				ui.edit_structure_revision = 0;
				ui.edit_field_id = 0;
				ui.rename_buf[0] = '\0';
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		} else if (ui.edit_target != edit_target_t::none) {
			ui.edit_target = edit_target_t::none;
			ui.edit_target_field = -1;
			ui.edit_structure_id = 0;
			ui.edit_structure_revision = 0;
			ui.edit_field_id = 0;
		}

		if (ctx_open_request) {
			int tgt_field = ui.edit_target_field;
			struct_dissector::field_def_t field_snapshot;
			struct_dissector::live_value_t value_snapshot;
			bool valid_field = false;
			std::uint64_t retained_structure_id = 0;
			std::uint64_t retained_structure_revision = 0;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (struct_dissector::valid_index(active_idx, st.structs.size())) {
					const auto& selected =
						st.structs[static_cast<std::size_t>(active_idx)];
					const auto& fields = selected.fields;
					if (struct_dissector::valid_index(tgt_field, fields.size())) {
						field_snapshot = fields[static_cast<std::size_t>(tgt_field)];
						retained_structure_id = selected.stable_id;
						retained_structure_revision = selected.layout_revision;
						if (static_cast<std::size_t>(tgt_field) < st.cached_values.size())
							value_snapshot = st.cached_values[static_cast<std::size_t>(tgt_field)];
						valid_field = true;
					}
				}
			}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const bool live_current = valid_field;
#else
			const bool live_current = valid_field && driver_bridge::is_loaded() &&
				driver_bridge::attached_pid() != 0 &&
				driver_bridge::attached_pid() == ui.context_target_pid &&
				active_base_address == ui.context_base_address &&
				st.last_completed_seq.load(std::memory_order_acquire) == ui.context_refresh_seq;
#endif
			if (!valid_field || retained_structure_id == 0 ||
				retained_structure_revision == 0 || field_snapshot.stable_id == 0) {
				ui.operation_error = true;
				ui.operation_status = "The field context is stale; select it again";
			} else {
			aida::ui::application_ui::retained_entity_context_t retained;
			retained.owner_id = "types.dissector.field";
			retained.entity_id = std::to_string(retained_structure_id) + ":" +
				std::to_string(field_snapshot.stable_id);
			retained.entity_generation = retained_structure_revision;
			retained.active_view = aida::ui::stable_view_id_t("view.types.dissector");
			const std::uint64_t retained_field_id = field_snapshot.stable_id;
			const auto resolve_field = [retained_structure_id,
				retained_structure_revision, retained_field_id]()
				-> std::optional<std::pair<int, int>> {
				auto& state = struct_dissector::g_state;
				std::lock_guard<std::mutex> lock(state.mtx);
				const int structure_index =
					struct_dissector::structure_index_by_id_locked(
						retained_structure_id);
				if (!struct_dissector::valid_index(
						structure_index, state.structs.size()))
					return std::nullopt;
				const auto& structure =
					state.structs[static_cast<std::size_t>(structure_index)];
				if (structure.stable_id != retained_structure_id ||
					structure.layout_revision != retained_structure_revision)
					return std::nullopt;
				const auto found = std::find_if(
					structure.fields.begin(), structure.fields.end(),
					[retained_field_id](const auto& field) {
						return field.stable_id == retained_field_id;
					});
				if (found == structure.fields.end())
					return std::nullopt;
				const auto distance = static_cast<std::size_t>(
					std::distance(structure.fields.begin(), found));
				if (!struct_dissector::index_fits_int(distance))
					return std::nullopt;
				return std::pair<int, int>{structure_index,
					static_cast<int>(distance)};
			};
			retained.validate_identity = [resolve_field] {
				return resolve_field()
					? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(
						"The structure or retained field changed; select it again");
			};
			auto add_action = [&retained](std::string id, bool enabled,
				const char* reason,
				std::function<aida::ui::action_handler_result_t()> invoke) {
				aida::ui::application_ui::retained_entity_action_t action;
				action.action_id = std::move(id);
				action.capability = enabled ? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(reason);
				action.invoke = std::move(invoke);
				retained.actions.push_back(std::move(action));
			};
			const auto activate_retained_field = [resolve_field, retained_structure_id,
				retained_structure_revision, retained_field_id]()
				-> std::optional<std::pair<int, int>> {
				const auto resolved = resolve_field();
				if (!resolved)
					return std::nullopt;
				auto& state = struct_dissector::g_state;
				std::lock_guard<std::mutex> lock(state.mtx);
				if (!struct_dissector::valid_index(
						resolved->first, state.structs.size()))
					return std::nullopt;
				const auto& structure =
					state.structs[static_cast<std::size_t>(resolved->first)];
				if (structure.stable_id != retained_structure_id ||
					structure.layout_revision != retained_structure_revision ||
					!struct_dissector::valid_index(
						resolved->second, structure.fields.size()) ||
					structure.fields[static_cast<std::size_t>(resolved->second)].stable_id !=
						retained_field_id)
					return std::nullopt;
				state.active_struct = resolved->first;
				return resolved;
			};
			const auto open_field_edit = [activate_retained_field,
				retained_structure_id, retained_structure_revision, retained_field_id](
				edit_target_t target, std::string seed) {
				const auto resolved = activate_retained_field();
				if (!resolved)
					return aida::ui::action_handler_result_t::failed(
						"The retained field is stale");
				g_ui.edit_target = target;
				g_ui.edit_target_field = resolved->second;
				g_ui.edit_structure_id = retained_structure_id;
				g_ui.edit_structure_revision = retained_structure_revision;
				g_ui.edit_field_id = retained_field_id;
				std::strncpy(g_ui.rename_buf, seed.c_str(),
					sizeof(g_ui.rename_buf) - 1);
				g_ui.rename_buf[sizeof(g_ui.rename_buf) - 1] = '\0';
				ImGui::CloseCurrentPopup();
				g_ui.inline_edit_popup_requested = true;
				return aida::ui::action_handler_result_t::completed();
			};
			const std::string field_name = field_snapshot.name;
			add_action("types.dissector.field.copy_name", valid_field,
				"The retained field is stale", [resolve_field, field_name] {
					if (!resolve_field())
						return aida::ui::action_handler_result_t::failed(
							"The retained field is stale");
					ImGui::SetClipboardText(field_name.c_str());
					return aida::ui::action_handler_result_t::completed();
				});
			add_action("types.dissector.field.copy_offset", valid_field,
				"The retained field is stale", [resolve_field, field_snapshot] {
				if (!resolve_field())
					return aida::ui::action_handler_result_t::failed(
						"The retained field is stale");
				char text[24]{};
				std::snprintf(text, sizeof(text), "0x%X", field_snapshot.offset);
				ImGui::SetClipboardText(text);
				return aida::ui::action_handler_result_t::completed();
			});
			const std::uint64_t absolute_address = ui.context_base_address + field_snapshot.offset;
			add_action("types.dissector.field.copy_absolute_address",
				valid_field && ui.context_base_address != 0,
				"No live base address is selected", [resolve_field, absolute_address] {
				if (!resolve_field())
					return aida::ui::action_handler_result_t::failed(
						"The retained field is stale");
				char text[32]{};
				std::snprintf(text, sizeof(text), "0x%016llX",
					static_cast<unsigned long long>(absolute_address));
				ImGui::SetClipboardText(text);
				return aida::ui::action_handler_result_t::completed();
			});
			const std::string display_value = value_snapshot.display_text;
			add_action("types.dissector.field.copy_current_value",
				live_current && !display_value.empty(),
				"A current live value is unavailable for this field", [resolve_field, display_value] {
				if (!resolve_field()) {
					return aida::ui::action_handler_result_t::failed(
						"The retained field is stale");
				}
				ImGui::SetClipboardText(display_value.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
			add_action("types.dissector.field.edit_live_value",
				live_current && !value_snapshot.raw_bytes.empty(),
				"Attach the original target and reselect the field before editing live memory",
				[activate_retained_field, value_snapshot] {
				const auto resolved = activate_retained_field();
				if (!resolved)
					return aida::ui::action_handler_result_t::failed(
						"The retained field is stale");
				g_ui.editing_field = resolved->second;
				g_ui.edit_base_address = g_ui.context_base_address;
				std::strncpy(g_ui.edit_value_buf,
					value_snapshot.display_text.c_str(),
					sizeof(g_ui.edit_value_buf) - 1);
				g_ui.edit_value_buf[sizeof(g_ui.edit_value_buf) - 1] = '\0';
				return aida::ui::action_handler_result_t::completed();
			});
			add_action("types.dissector.field.refresh_live_value", false,
				"Attach the original target and reselect the field before reading live memory",
				[] { return aida::ui::action_handler_result_t::completed(); });
			add_action("types.dissector.field.rename", valid_field,
				"The retained field is stale", [open_field_edit, field_name] {
				return open_field_edit(edit_target_t::field_name, field_name);
			});
			add_action("types.dissector.field.set_size", valid_field,
				"The retained field is stale", [open_field_edit] {
				return open_field_edit(edit_target_t::field_size, {});
			});
			const std::string field_comment = field_snapshot.description;
			add_action("types.dissector.field.set_comment", valid_field,
				"The retained field is stale", [open_field_edit, field_comment] {
				return open_field_edit(edit_target_t::field_comment, field_comment);
			});
			bool nested_available = false;
			{
				std::lock_guard<std::mutex> lock(st.mtx);
				nested_available = st.structs.size() > 1;
			}
			const auto type_count = static_cast<std::size_t>(struct_dissector::field_type_t::COUNT);
			for (std::size_t type_index = 0; type_index < type_count; ++type_index) {
				add_action("types.dissector.field.change_type." + std::to_string(type_index),
					valid_field && (type_index != static_cast<std::size_t>(struct_dissector::field_type_t::nested_struct) || nested_available),
					nested_available ? "The retained field is stale" : "Create another structure before selecting a nested type",
					[activate_retained_field, open_field_edit, type_index] {
						if (type_index == static_cast<std::size_t>(struct_dissector::field_type_t::nested_struct)) {
							return open_field_edit(edit_target_t::nested_target, {});
						}
						const auto resolved = activate_retained_field();
						if (!resolved)
							return aida::ui::action_handler_result_t::failed(
								"The retained field is stale");
						return struct_dissector::retype_field(resolved->first, resolved->second,
							static_cast<struct_dissector::field_type_t>(type_index))
							? aida::ui::action_handler_result_t::completed()
							: aida::ui::action_handler_result_t::failed("The field type change failed layout validation");
					});
			}
			add_action("types.dissector.field.set_array_count", valid_field,
				"The retained field is stale", [open_field_edit, field_snapshot] {
				return open_field_edit(edit_target_t::array_count,
					std::to_string(field_snapshot.array_count));
			});
			add_action("types.dissector.field.choose_nested", valid_field && nested_available,
				nested_available ? "The retained field is stale" : "Create another structure before linking a nested value",
				[open_field_edit, field_snapshot] {
					return open_field_edit(edit_target_t::nested_target,
						field_snapshot.referenced_type_name);
				});
			add_action("types.dissector.field.choose_pointer_target", valid_field && nested_available,
				nested_available ? "The retained field is stale" : "Create another structure before selecting a pointee type",
				[open_field_edit, field_snapshot] {
					return open_field_edit(edit_target_t::pointer_target,
						field_snapshot.referenced_type_name);
				});
			bool enum_available = false;
			{
				std::lock_guard<std::mutex> lock(st.mtx);
				enum_available = !st.enums.empty();
			}
			add_action("types.dissector.field.choose_enum", valid_field && enum_available,
				enum_available ? "The retained field is stale" : "Import an enum definition before applying an enum type",
				[open_field_edit, field_snapshot] {
					return open_field_edit(edit_target_t::enum_reference,
						field_snapshot.referenced_type_name);
				});
			const std::size_t bitfield_size = field_snapshot.size == 0
				? struct_dissector::field_type_size(field_snapshot.type) : field_snapshot.size;
			const bool bitfield_capable = valid_field && field_snapshot.array_count == 1 &&
				bitfield_size >= 1 && bitfield_size <= 8 && field_snapshot.type != struct_dissector::field_type_t::pointer &&
				field_snapshot.type != struct_dissector::field_type_t::nested_struct;
			add_action("types.dissector.field.configure_bitfield", bitfield_capable,
				"Bitfields require one 1-8 byte non-pointer scalar",
				[open_field_edit, field_snapshot] {
					const std::string seed = field_snapshot.bit_width == 0
						? "0:1" : std::to_string(field_snapshot.bit_offset) + ":" +
							std::to_string(field_snapshot.bit_width);
					return open_field_edit(edit_target_t::bitfield, seed);
				});
			add_action("types.dissector.field.set_alignment", valid_field,
				"The retained field is stale", [open_field_edit, field_snapshot] {
				return open_field_edit(edit_target_t::field_alignment,
					std::to_string(field_snapshot.explicit_alignment));
			});
			add_action("types.dissector.field.remove", valid_field,
				"The retained field is stale", [activate_retained_field,
					retained_structure_id, retained_structure_revision, retained_field_id] {
				const auto resolved = activate_retained_field();
				if (!resolved)
					return aida::ui::action_handler_result_t::failed(
						"The retained field is stale");
				g_ui.pending_remove_structure_id = retained_structure_id;
				g_ui.pending_remove_structure_revision = retained_structure_revision;
				g_ui.pending_remove_field_id = retained_field_id;
				g_ui.remove_confirmation_requested = true;
				return aida::ui::action_handler_result_t::completed();
			});
			aida::ui::application_ui::open_retained_entity_context_menu(
				std::move(retained), ctx_open_origin);
			}
		}
		aida::ui::application_ui::render_retained_entity_context_menu(
			"types.dissector.field");
		if (ui.inline_edit_popup_requested) {
			ui.inline_edit_popup_requested = false;
			ImGui::OpenPopup("##sd_inline_edit");
		}
		if (ui.remove_confirmation_requested) {
			ui.remove_confirmation_requested = false;
			ImGui::OpenPopup("##sd_confirm_remove_field");
		}

		if (ImGui::BeginPopupModal("##sd_confirm_remove_field", nullptr,
			ImGuiWindowFlags_AlwaysAutoResize)) {
			ImGui::TextUnformatted("Remove this field from the structure definition?");
			ImGui::TextDisabled("This backend has no field-removal undo journal.");
			if (ImGui::Button("Cancel", ImVec2(110.f, 0.f))) {
				ui.pending_remove_structure_id = 0;
				ui.pending_remove_structure_revision = 0;
				ui.pending_remove_field_id = 0;
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Remove", ImVec2(110.f, 0.f))) {
				int structure_index = -1;
				int target = -1;
				const auto pending_remove_field_id = ui.pending_remove_field_id;
				{
					std::lock_guard<std::mutex> lock(st.mtx);
					structure_index = struct_dissector::structure_index_by_id_locked(
						ui.pending_remove_structure_id);
					if (struct_dissector::valid_index(structure_index, st.structs.size())) {
						const auto& structure = st.structs[
							static_cast<std::size_t>(structure_index)];
						if (structure.stable_id == ui.pending_remove_structure_id &&
							structure.layout_revision == ui.pending_remove_structure_revision) {
							const auto found = std::find_if(structure.fields.begin(),
								structure.fields.end(), [pending_remove_field_id](const auto& field) {
									return field.stable_id == pending_remove_field_id;
								});
							if (found != structure.fields.end()) {
								const auto distance = static_cast<std::size_t>(
									std::distance(structure.fields.begin(), found));
								if (struct_dissector::index_fits_int(distance))
									target = static_cast<int>(distance);
							}
						}
					}
				}
				if (target >= 0 && struct_dissector::remove_field(structure_index, target)) {
					if (ui.selected_field == target) ui.selected_field = -1;
					if (ui.editing_field == target) ui.editing_field = -1;
				}
				ui.pending_remove_structure_id = 0;
				ui.pending_remove_structure_revision = 0;
				ui.pending_remove_field_id = 0;
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}

		if (content_h > table_h && table_h > 0.f) {
			float bar_x = rx + rw - 10.f;
			float bar_y = table_y;
			float bar_h = table_h;
			float ratio = table_h / content_h;
			float thumb_h = std::max(bar_h * ratio, 24.f);
			float track = bar_h - thumb_h;
			float scroll_ratio = (content_h - table_h > 0.f) ? ui.scroll_y / (content_h - table_h) : 0.f;
			float thumb_y = bar_y + track * scroll_ratio;
			dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + 5.f, bar_y + bar_h),
				aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 2.f);
			dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 5.f, thumb_y + thumb_h),
				aida::ui::with_alpha(th.accent_dim, alpha), 2.f);
		}

		float add_y = ry_start + rh - line_h - 6.f;
		ImGui::SetCursorScreenPos(ImVec2(rx + 8.f, add_y + 2.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));

		ImGui::PushItemWidth(170.f);
		ImGui::InputTextWithHint("##sd_fn", "field name", ui.field_name_buf, sizeof(ui.field_name_buf));
		ImGui::PopItemWidth();
		ImGui::SameLine(0.f, 6.f);

		ImGui::PushItemWidth(80.f);
		ImGui::InputTextWithHint("##sd_fo", "+0x?", ui.offset_buf, sizeof(ui.offset_buf),
						 ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();
		ImGui::SameLine(0.f, 6.f);

		static const char* type_names[] = {
			"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
			"Int64", "UInt64", "Float", "Double", "Pointer",
			"ASCII", "UTF-16", "Bytes", "Padding", "Struct"
		};
		ImGui::PushItemWidth(110.f);
		ImGui::Combo("##sd_ft", &ui.add_type, type_names,
					 static_cast<int>(struct_dissector::field_type_t::COUNT));
		ImGui::PopItemWidth();
		ImGui::SameLine(0.f, 6.f);

		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();

		if (aida::ui::button("Add", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(72.f, 28.f))) {
			if (ui.field_name_buf[0] != '\0') {
				struct_dissector::field_def_t fd;
				fd.name = ui.field_name_buf;
				fd.type = static_cast<struct_dissector::field_type_t>(ui.add_type);
				uint32_t off = 0;
				std::sscanf(ui.offset_buf, "%x", &off);
				fd.offset = off;
				std::size_t ts = struct_dissector::field_type_size(fd.type);
				fd.size = static_cast<uint32_t>(ts > 0 ? ts : 1);
				struct_dissector::add_field(active_idx, fd);
				ui.field_name_buf[0] = '\0';
				ui.offset_buf[0] = '\0';
			} else {
				diag::log_tagged_fmt("dissector",
					"add_field_skipped reason='empty_name'");
			}
		}
		ImGui::SameLine(0.f, 6.f);
		if (aida::ui::button("Del", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(64.f, 28.f))) {
			if (ui.selected_field >= 0) {
				struct_dissector::remove_field(active_idx, ui.selected_field);
				ui.selected_field = -1;
				ui.editing_field = -1;
			} else {
				diag::log_tagged_fmt("dissector",
					"remove_field_skipped reason='no_selection'");
			}
		}
	}

	render_write_review_modal();
	ImGui::EndChild();
}

}
