#pragma once

#include <cstdio>
#include <cstring>
#include <atomic>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "imgui/imgui.h"
#include "pointer_scanner.hpp"
#include "memory_interaction_context.hpp"
#include "memory_scanner.hpp"
#include "../debugger/debugger_view.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ai/entity_evidence_handoff.hpp"
#include "../ui/task_center.hpp"
#include "../infra/executor.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../ui/ui_thread_dispatcher.hpp"
#endif
#include "disasm_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "function_index.hpp"
#endif
#include "hex_view.hpp"
#include "ui_anim.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#include "../../preview/studio_semantics.hpp"
#else
#include "../anti-tamper/webhook.hpp"
#include "../helpers/diag_log.hpp"
#endif
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"

namespace pointer_scanner_view {

struct chain_anim_t {
	float reveal = 0.f;
	float step_flash[16] = {};
	int   hover_step = -1;
};

struct view_state_t {
	std::unordered_map<int, chain_anim_t> chain_anims;
	int   last_selected = -1;
	float anim_clock = 0.f;
	std::string context_chain;
	std::uint64_t map_fingerprint = 0;
	std::uint64_t result_fingerprint = 0;
	std::uint64_t map_generation = 1;
	std::uint64_t result_generation = 1;
	bool observed_map_building = false;
	bool observed_scanning = false;
};

inline view_state_t g_view;

namespace detail {

enum class resolution_status_t : std::uint8_t {
	idle,
	queued,
	running,
	ready,
	failed,
	cancelled,
	stale
};

struct resolution_entry_t {
	resolution_status_t status = resolution_status_t::idle;
	std::vector<std::uint64_t> addresses;
	std::string error;
	std::uint32_t pid = 0;
	std::uint64_t workspace_generation = 0;
	std::uint64_t map_generation = 0;
	std::uint64_t result_generation = 0;
	std::uint64_t serial = 0;
	std::uint64_t touch = 0;
	std::shared_ptr<std::atomic<bool>> cancellation;
};

struct resolution_store_t {
	std::mutex mutex;
	std::unordered_map<std::string, resolution_entry_t> entries;
	std::atomic<std::uint64_t> serial{0};
	std::atomic<std::uint64_t> touch{0};
	std::atomic<std::uint64_t> current_map_generation{1};
	std::atomic<std::uint64_t> current_result_generation{1};
};

inline resolution_store_t g_resolutions;

inline std::uint64_t mix_identity(std::uint64_t hash, std::uint64_t value) {
	hash ^= value;
	return hash * 1099511628211ULL;
}

inline std::uint64_t mix_identity(std::uint64_t hash, const std::string& value) {
	for (const char character : value)
		hash = mix_identity(hash, static_cast<unsigned char>(character));
	return hash;
}

inline std::uint64_t chain_identity_value(const pointer_scanner::pointer_chain_t& chain) {
	std::uint64_t hash = 1469598103934665603ULL;
	hash = mix_identity(hash, static_cast<std::uint64_t>(chain.module_index + 1));
	hash = mix_identity(hash, chain.module_name);
	hash = mix_identity(hash, chain.base_offset);
	hash = mix_identity(hash, chain.is_static ? 1ULL : 0ULL);
	for (const auto offset : chain.offsets)
		hash = mix_identity(hash, static_cast<std::uint64_t>(offset));
	return hash;
}

inline std::string chain_identity_key(const pointer_scanner::pointer_chain_t& chain) {
	char encoded[24]{};
	std::snprintf(encoded, sizeof(encoded), "%016llX",
		static_cast<unsigned long long>(chain_identity_value(chain)));
	return encoded;
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline std::string studio_pointer_entity_id(const char* entity,
	const pointer_scanner::pointer_chain_t& chain, int step = -1) {
	const auto workspace = disasm_view::capture_selected_workspace();
	const std::string workspace_id = workspace.workspace
		? workspace.workspace->identity().binary_id().to_hex() : std::string("none");
	const std::string identity = std::to_string(driver_bridge::attached_pid()) + ":" +
		workspace_id + ":" +
		chain_identity_key(chain) + ":" + std::to_string(step);
	std::string source(entity);
	source.push_back('-');
	source.append(aida::preview::semantics::entity_token(identity));
	return aida::preview::semantics::stable_id("aida.memory", source);
}
#endif

inline std::uint64_t map_fingerprint() {
	auto& state = pointer_scanner::g_state;
	std::lock_guard<std::mutex> lock(state.map_mutex);
	std::uint64_t hash = 1469598103934665603ULL;
	hash = mix_identity(hash, state.last_map_diagnostics.pid);
	hash = mix_identity(hash, state.last_map_diagnostics.duration_ms);
	hash = mix_identity(hash, static_cast<std::uint64_t>(state.map_entry_count));
	for (const auto& module : state.cached_modules) {
		hash = mix_identity(hash, module.base);
		hash = mix_identity(hash, module.size);
		hash = mix_identity(hash, module.name);
	}
	return hash;
}

inline std::uint64_t result_fingerprint() {
	auto& state = pointer_scanner::g_state;
	std::lock_guard<std::mutex> lock(state.results_mutex);
	std::uint64_t hash = 1469598103934665603ULL;
	hash = mix_identity(hash, static_cast<std::uint64_t>(state.results.size()));
	if (!state.results.empty()) {
		hash = mix_identity(hash, chain_identity_value(state.results.front()));
		hash = mix_identity(hash, chain_identity_value(state.results.back()));
	}
	return hash;
}

inline void observe_generations() {
	auto& state = pointer_scanner::g_state;
	const bool building = state.map_building.load(std::memory_order_acquire);
	const bool scanning = state.scanning.load(std::memory_order_acquire);
	const std::uint64_t map_value = map_fingerprint();
	const std::uint64_t result_value = result_fingerprint();
	if (g_view.map_fingerprint != map_value || (g_view.observed_map_building && !building)) {
		g_view.map_fingerprint = map_value;
		++g_view.map_generation;
		g_resolutions.current_map_generation.store(g_view.map_generation, std::memory_order_release);
	}
	if (g_view.result_fingerprint != result_value || (g_view.observed_scanning && !scanning)) {
		g_view.result_fingerprint = result_value;
		++g_view.result_generation;
		g_resolutions.current_result_generation.store(g_view.result_generation, std::memory_order_release);
	}
	g_view.observed_map_building = building;
	g_view.observed_scanning = scanning;
}

inline bool checked_apply_offset(std::uint64_t address, std::int64_t offset,
	std::uint64_t& output) {
	const std::uint64_t magnitude = offset < 0
		? static_cast<std::uint64_t>(-(offset + 1)) + 1
		: static_cast<std::uint64_t>(offset);
	if (offset < 0) {
		if (address < magnitude)
			return false;
		output = address - magnitude;
		return true;
	}
	if (address > (std::numeric_limits<std::uint64_t>::max)() - magnitude)
		return false;
	output = address + magnitude;
	return true;
}

inline bool context_key_pressed() {
	return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
		(ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

inline uint64_t offset_magnitude(int64_t offset) {
	return offset < 0
		? static_cast<uint64_t>(-(offset + 1)) + 1
		: static_cast<uint64_t>(offset);
}

inline std::string format_offset(int64_t off) {
	char buf[32];
	if (off >= 0) snprintf(buf, sizeof(buf), "+0x%llX", static_cast<unsigned long long>(offset_magnitude(off)));
	else          snprintf(buf, sizeof(buf), "-0x%llX", static_cast<unsigned long long>(offset_magnitude(off)));
	return buf;
}

inline std::optional<std::uint64_t> chain_base_address(
	const pointer_scanner::pointer_chain_t& chain) {
	auto& state = pointer_scanner::g_state;
	std::lock_guard<std::mutex> lock(state.map_mutex);
	if (!chain.is_static)
		return chain.base_offset == 0 ? std::optional<std::uint64_t>{} : chain.base_offset;
	if (chain.module_index < 0 ||
		static_cast<std::size_t>(chain.module_index) >= state.cached_modules.size())
		return {};
	const auto module_base = state.cached_modules[static_cast<std::size_t>(chain.module_index)].base;
	if (module_base > (std::numeric_limits<std::uint64_t>::max)() - chain.base_offset)
		return {};
	return module_base + chain.base_offset;
}

inline void prune_resolution_cache_locked() {
	constexpr std::size_t maximum_entries = 256;
	while (g_resolutions.entries.size() > maximum_entries) {
		auto oldest = g_resolutions.entries.end();
		for (auto iterator = g_resolutions.entries.begin();
			iterator != g_resolutions.entries.end(); ++iterator) {
			if (iterator->second.status == resolution_status_t::queued ||
				iterator->second.status == resolution_status_t::running)
				continue;
			if (oldest == g_resolutions.entries.end() ||
				iterator->second.touch < oldest->second.touch)
				oldest = iterator;
		}
		if (oldest == g_resolutions.entries.end())
			break;
		g_resolutions.entries.erase(oldest);
	}
}

inline bool request_chain_resolution(const disasm_view::workspace_context_t& context,
	const pointer_scanner::pointer_chain_t& chain) {
	if (!context.workspace || !context.workspace->identity().process() || chain.offsets.size() > 64)
		return false;
	const auto base = chain_base_address(chain);
	if (!base)
		return false;
	const std::uint32_t pid = context.workspace->identity().process()->pid;
	const std::uint64_t workspace_generation = context.workspace->generation();
	const std::uint64_t map_generation = g_view.map_generation;
	const std::uint64_t result_generation = g_view.result_generation;
	const std::string key = chain_identity_key(chain);
	const std::uint64_t serial = g_resolutions.serial.fetch_add(1,
		std::memory_order_acq_rel) + 1;
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	{
		std::lock_guard<std::mutex> lock(g_resolutions.mutex);
		auto existing = g_resolutions.entries.find(key);
		if (existing != g_resolutions.entries.end() && existing->second.pid == pid &&
			existing->second.workspace_generation == workspace_generation &&
			existing->second.map_generation == map_generation &&
			existing->second.result_generation == result_generation &&
			(existing->second.status == resolution_status_t::queued ||
			 existing->second.status == resolution_status_t::running ||
			 existing->second.status == resolution_status_t::ready)) {
			existing->second.touch = g_resolutions.touch.fetch_add(1,
				std::memory_order_acq_rel) + 1;
			return true;
		}
		if (existing != g_resolutions.entries.end() && existing->second.cancellation)
			existing->second.cancellation->store(true, std::memory_order_release);
		auto& entry = g_resolutions.entries[key];
		entry = {};
		entry.status = resolution_status_t::queued;
		entry.pid = pid;
		entry.workspace_generation = workspace_generation;
		entry.map_generation = map_generation;
		entry.result_generation = result_generation;
		entry.serial = serial;
		entry.touch = g_resolutions.touch.fetch_add(1, std::memory_order_acq_rel) + 1;
		entry.cancellation = cancellation;
		prune_resolution_cache_locked();
	}
	const std::string task_id = "pointer.resolve." + key + "." + std::to_string(serial);
	aida::ui::task_center::task_registration_t registration;
	registration.id = task_id;
	registration.source = "pointer_scanner";
	registration.owner = "Pointer Scanner";
	registration.owner_view = "view.memory.pointers";
	registration.owner_action = "Resolve pointer chain";
	registration.target = "PID " + std::to_string(pid);
	registration.label = "Resolve pointer chain";
	registration.stage = "Queued exact dereference sequence";
	registration.affected_entity = pointer_scanner::chain_to_string(chain);
	registration.cancellation_is_safe = true;
	registration.callbacks.cancel = [cancellation] {
		bool expected = false;
		return cancellation->compare_exchange_strong(expected, true,
			std::memory_order_acq_rel);
	};
	if (!aida::ui::task_center::register_task(std::move(registration))) {
		std::lock_guard<std::mutex> lock(g_resolutions.mutex);
		auto found = g_resolutions.entries.find(key);
		if (found != g_resolutions.entries.end() && found->second.serial == serial) {
			found->second.status = resolution_status_t::failed;
			found->second.error = "Task Center rejected ownership of the pointer resolution";
		}
		return false;
	}
	auto workspace = context.workspace;
	auto offsets = chain.offsets;
	auto addresses = std::make_shared<std::vector<std::uint64_t>>();
	auto error = std::make_shared<std::string>();
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "pointer_scanner";
	submission.label = "pointer.resolve_chain";
	submission.thread_class = "bounded_task";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 4;
	submission.target_pid = pid;
	submission.generation = workspace_generation;
	submission.cancel_hook = [cancellation] {
		cancellation->store(true, std::memory_order_release);
	};
	submission.body = [workspace, offsets = std::move(offsets), addresses, error,
		cancellation, task_id, key, base = *base, pid, workspace_generation,
		map_generation, result_generation, serial]() {
		{
			std::lock_guard<std::mutex> lock(g_resolutions.mutex);
			auto found = g_resolutions.entries.find(key);
			if (found != g_resolutions.entries.end() && found->second.serial == serial)
				found->second.status = resolution_status_t::running;
		}
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, 0.05f,
			"Resolving pointer hops"));
		addresses->reserve(offsets.size() + 1);
		addresses->push_back(base);
		std::uint64_t current = base;
		for (std::size_t index = 0; index < offsets.size(); ++index) {
			if (cancellation->load(std::memory_order_acquire)) {
				*error = "Pointer resolution was cancelled";
				break;
			}
			const auto process = workspace ? workspace->identity().process() : std::nullopt;
			if (!workspace || workspace->closing() || workspace->closed() ||
				workspace->generation() != workspace_generation || !process || process->pid != pid) {
				*error = "Workspace or target changed before the next pointer hop";
				break;
			}
			std::uint64_t pointer = 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			pointer = current ^ (0x1000ULL + static_cast<std::uint64_t>(index) * 0x230ULL);
#else
			std::vector<std::uint8_t> bytes;
			if (!driver_bridge::read_memory_for(pid, current, sizeof(pointer), bytes) ||
				bytes.size() != sizeof(pointer)) {
				*error = "Unreadable pointer at hop " + std::to_string(index + 1) +
					" (exact 8-byte read failed)";
				break;
			}
			std::memcpy(&pointer, bytes.data(), sizeof(pointer));
#endif
			if (!checked_apply_offset(pointer, offsets[index], current) || current == 0) {
				*error = "Pointer arithmetic overflow or null result at hop " +
					std::to_string(index + 1);
				break;
			}
			addresses->push_back(current);
		}
		if (cancellation->load(std::memory_order_acquire) && error->empty())
			*error = "Pointer resolution was cancelled";
		auto publish = [workspace, addresses, error, cancellation, task_id, key, pid,
			workspace_generation, map_generation, result_generation, serial]() {
			const auto process = workspace ? workspace->identity().process() : std::nullopt;
			const bool current = workspace && !workspace->closing() && !workspace->closed() &&
				workspace->generation() == workspace_generation && process && process->pid == pid &&
				g_resolutions.current_map_generation.load(std::memory_order_acquire) == map_generation &&
				g_resolutions.current_result_generation.load(std::memory_order_acquire) == result_generation;
			std::lock_guard<std::mutex> lock(g_resolutions.mutex);
			auto found = g_resolutions.entries.find(key);
			if (found == g_resolutions.entries.end() || found->second.serial != serial)
				return;
			if (!current) {
				found->second.status = resolution_status_t::stale;
				found->second.error = "Target, map, results, or workspace generation changed";
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::cancelled, 1.0f,
					"Discarded stale pointer resolution", found->second.error));
				return;
			}
			found->second.addresses = std::move(*addresses);
			found->second.error = *error;
			if (cancellation->load(std::memory_order_acquire))
				found->second.status = resolution_status_t::cancelled;
			else if (!error->empty())
				found->second.status = resolution_status_t::failed;
			else
				found->second.status = resolution_status_t::ready;
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				found->second.status == resolution_status_t::ready
					? aida::ui::task_center::task_state_t::completed
					: found->second.status == resolution_status_t::cancelled
						? aida::ui::task_center::task_state_t::cancelled
						: aida::ui::task_center::task_state_t::failed,
				1.0f, found->second.status == resolution_status_t::ready
					? "Pointer chain resolved" : "Pointer chain did not resolve",
				found->second.status == resolution_status_t::ready
					? std::to_string(found->second.addresses.size() - 1) + " hops"
					: found->second.error));
		};
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		publish();
#else
		if (!aida::ui_thread::post(std::move(publish), "pointer_scanner",
				"publish_pointer_resolution", "worker_completion")) {
			std::lock_guard<std::mutex> lock(g_resolutions.mutex);
			auto found = g_resolutions.entries.find(key);
			if (found != g_resolutions.entries.end() && found->second.serial == serial) {
				found->second.status = resolution_status_t::failed;
				found->second.error = "UI dispatcher rejected pointer-resolution publication";
			}
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				aida::ui::task_center::task_state_t::failed, 1.0f,
				"UI publication rejected", "The resolved chain was not published"));
		}
#endif
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		std::lock_guard<std::mutex> lock(g_resolutions.mutex);
		auto found = g_resolutions.entries.find(key);
		if (found != g_resolutions.entries.end() && found->second.serial == serial) {
			found->second.status = resolution_status_t::failed;
			found->second.error = "Worker queue rejected pointer resolution: " + submitted.reject_reason;
		}
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.0f,
			"Worker queue rejected", submitted.reject_reason));
		return false;
	}
	return true;
}

inline std::optional<std::uint64_t> resolved_step_address(
	const pointer_scanner::pointer_chain_t& chain, int step,
	resolution_status_t* status = nullptr, std::string* error = nullptr) {
	if (step < 0)
		return {};
	const std::string key = chain_identity_key(chain);
	std::lock_guard<std::mutex> lock(g_resolutions.mutex);
	auto found = g_resolutions.entries.find(key);
	if (found == g_resolutions.entries.end()) {
		if (status) *status = resolution_status_t::idle;
		return {};
	}
	found->second.touch = g_resolutions.touch.fetch_add(1, std::memory_order_acq_rel) + 1;
	if (status) *status = found->second.status;
	if (error) *error = found->second.error;
	if ((found->second.status != resolution_status_t::ready &&
		 found->second.status != resolution_status_t::failed) ||
		static_cast<std::size_t>(step) >= found->second.addresses.size())
		return {};
	return found->second.addresses[static_cast<std::size_t>(step)];
}

inline void render_step_box(ImDrawList* dl, ImVec2 a, ImVec2 b, ImU32 fill, ImU32 border,
	const char* label, ImU32 text_col, float radius)
{
	dl->AddRectFilled(a, b, fill, radius);
	dl->AddRect(a, b, border, radius, 0, 1.f);
	ImVec2 ts = ImGui::CalcTextSize(label);
	ImFont* code_font = aida::ui::fonts::code();
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());
	if (!code_font) code_font = ImGui::GetFont();
	dl->AddText(code_font, code_font_size,
		ImVec2(a.x + (b.x - a.x - ts.x) * 0.5f, a.y + (b.y - a.y - 12.f) * 0.5f),
		text_col, label);
}

inline void render_arrow(ImDrawList* dl, ImVec2 from, ImVec2 to, ImU32 col, float reveal) {
	if (reveal <= 0.001f) return;
	ImVec2 cp1(from.x + (to.x - from.x) * 0.4f, from.y - 6.f);
	ImVec2 cp2(to.x   - (to.x - from.x) * 0.4f, to.y   + 6.f);

	int segments = 24;
	float clip_t = reveal;
	for (int i = 0; i < segments; ++i) {
		float t1 = static_cast<float>(i) / static_cast<float>(segments);
		float t2 = static_cast<float>(i + 1) / static_cast<float>(segments);
		if (t2 > clip_t) t2 = clip_t;
		if (t1 >= clip_t) break;
		auto bez = [&](float tt) {
			float u = 1.f - tt;
			float x = u*u*u*from.x + 3.f*u*u*tt*cp1.x + 3.f*u*tt*tt*cp2.x + tt*tt*tt*to.x;
			float y = u*u*u*from.y + 3.f*u*u*tt*cp1.y + 3.f*u*tt*tt*cp2.y + tt*tt*tt*to.y;
			return ImVec2(x, y);
		};
		dl->AddLine(bez(t1), bez(t2), col, 1.5f);
	}
	if (reveal >= 0.99f) {
		float head = 5.f;
		dl->AddTriangleFilled(
			ImVec2(to.x - head, to.y - head * 0.6f),
			ImVec2(to.x - head, to.y + head * 0.6f),
			to, col);
	}
	float t_sec = aida::ui::clock::seconds() * 0.8f;
	float ph = fmodf(t_sec, 1.f);
	if (ph <= reveal) {
		float u = 1.f - ph;
		float dx = u*u*u*from.x + 3.f*u*u*ph*cp1.x + 3.f*u*ph*ph*cp2.x + ph*ph*ph*to.x;
		float dy = u*u*u*from.y + 3.f*u*u*ph*cp1.y + 3.f*u*ph*ph*cp2.y + ph*ph*ph*to.y;
		dl->AddCircleFilled(ImVec2(dx, dy), 2.f, col, 12);
	}
}

inline void render_chain_diagram(ImDrawList* dl, float ox, float oy, float w, float h,
	int chain_idx, pointer_scanner::pointer_chain_t& chain, float a, chain_anim_t& anim)
{
	const auto& t = aida::ui::resolved();
	ImFont* code_font = aida::ui::fonts::code();
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());
	if (!code_font) code_font = ImGui::GetFont();

	float pad = 14.f;
	float row_y = oy + h * 0.5f - 18.f;
	float box_h = 32.f;
	float gap_w = 56.f;

	const size_t total_steps = chain.offsets.size() + 1;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const std::string chain_semantic_id = studio_pointer_entity_id(
		"pointer-chain", chain);
#endif

	std::vector<float> box_w_arr;
	box_w_arr.reserve(total_steps * 2);

	float total_w = 0.f;
	{
		char base_lbl[96];
		if (chain.is_static && chain.module_index >= 0 &&
			static_cast<size_t>(chain.module_index) < pointer_scanner::g_state.cached_modules.size()) {
			snprintf(base_lbl, sizeof(base_lbl), "%s+0x%llX",
				chain.module_name.c_str(), static_cast<unsigned long long>(chain.base_offset));
		} else {
			snprintf(base_lbl, sizeof(base_lbl), "0x%llX",
				static_cast<unsigned long long>(chain.base_offset));
		}
		ImVec2 ts = ImGui::CalcTextSize(base_lbl);
		float bw = ts.x + 22.f;
		box_w_arr.push_back(bw);
		total_w += bw;
	}

	for (size_t i = 0; i < chain.offsets.size(); ++i) {
		std::string off = format_offset(chain.offsets[i]);
		ImVec2 ts = ImGui::CalcTextSize(off.c_str());
		float bw = ts.x + 18.f;
		box_w_arr.push_back(bw);
		total_w += bw + gap_w;
	}

	float scale = 1.f;
	if (total_w + pad * 2.f > w) {
		scale = (w - pad * 2.f) / total_w;
		if (scale < 0.45f) scale = 0.45f;
		gap_w *= scale;
		for (auto& bw : box_w_arr) bw *= scale;
	}

	float cx = ox + pad;
	int hover_step = -1;

	float dt = aida::ui::clock::dt();
	anim.reveal = aida::motion::smooth_lerp(anim.reveal, 1.f, 14.f, dt);

	{
		float bw = box_w_arr[0];
		ImVec2 ba(cx, row_y);
		ImVec2 bb(cx + bw, row_y + box_h);
		float local_t = anim.reveal * 1.0f;
		float lift = (1.f - aida::motion::ease::out_cubic(local_t)) * 8.f;
		ba.y += lift; bb.y += lift;

		ImU32 fill = chain.is_static ? aida::ui::with_alpha(t.accent_dim, a * 0.55f * local_t)
		                              : aida::ui::with_alpha(t.panel_bg, a * local_t);
		ImU32 border = chain.is_static ? aida::ui::with_alpha(t.accent_u32, a * local_t)
		                                : aida::ui::with_alpha(t.border_subtle, a * local_t);

		ImGui::PushID(chain_idx * 100 + 0);
		ImGui::SetCursorScreenPos(ba);
		ImGui::InvisibleButton("##step0", ImVec2(bw, box_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item(
			studio_pointer_entity_id("pointer-step", chain, 0),
			"pointer-chain-step", false, false, chain_semantic_id);
#endif
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		if (hov) hover_step = 0;
		if (clk) {
			const auto addr = chain_base_address(chain);
			if (addr) {
				const auto context = disasm_view::capture_selected_workspace();
				if (hex_view::request_live_memory(context, *addr, 256))
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
			}
		}
		ImGui::PopID();

		if (hov) {
			anim.step_flash[0] = 1.f;
		}
		float flash = anim.step_flash[0];
		if (flash > 0.f) {
			border = aida::ui::with_alpha(t.accent_u32, a * (0.6f + flash * 0.4f));
			fill = aida::ui::with_alpha(t.accent_glow, a * (0.6f * flash + (chain.is_static ? 0.55f : 0.f)));
		}

		char lbl[96];
		if (chain.is_static && chain.module_index >= 0 &&
			static_cast<size_t>(chain.module_index) < pointer_scanner::g_state.cached_modules.size()) {
			snprintf(lbl, sizeof(lbl), "%s+0x%llX",
				chain.module_name.c_str(), static_cast<unsigned long long>(chain.base_offset));
		} else {
			snprintf(lbl, sizeof(lbl), "0x%llX", static_cast<unsigned long long>(chain.base_offset));
		}
		render_step_box(dl, ba, bb, fill, border, lbl,
			aida::ui::with_alpha(t.text_primary, a * local_t), 8.f);

		cx += bw;
	}

	for (size_t i = 0; i < chain.offsets.size(); ++i) {
		float reveal_offset = static_cast<float>(i + 1) * 0.16f;
		float local_t = (anim.reveal - reveal_offset) / (1.f - reveal_offset + 0.0001f);
		if (local_t < 0.f) local_t = 0.f;
		if (local_t > 1.f) local_t = 1.f;

		ImVec2 from(cx, row_y + box_h * 0.5f);
		ImVec2 to(cx + gap_w, row_y + box_h * 0.5f);
		render_arrow(dl, from, to,
			aida::ui::with_alpha(t.accent_u32, a * local_t), local_t);

		cx += gap_w;

		float bw = box_w_arr[i + 1];
		ImVec2 ba(cx, row_y);
		ImVec2 bb(cx + bw, row_y + box_h);
		float lift = (1.f - aida::motion::ease::out_cubic(local_t)) * 8.f;
		ba.y += lift; bb.y += lift;

		ImU32 fill = aida::ui::with_alpha(t.panel_bg, a * local_t);
		ImU32 border = aida::ui::with_alpha(t.border_subtle, a * local_t);

		int step_idx = static_cast<int>(i + 1);
		ImGui::PushID(chain_idx * 100 + step_idx);
		ImGui::SetCursorScreenPos(ba);
		ImGui::InvisibleButton("##stepn", ImVec2(bw, box_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item(
			studio_pointer_entity_id("pointer-step", chain, step_idx),
			"pointer-chain-step", false, false, chain_semantic_id);
#endif
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		if (hov) hover_step = step_idx;
		if (clk) {
			const auto context = disasm_view::capture_selected_workspace();
			if (const auto addr = resolved_step_address(chain, step_idx)) {
				if (hex_view::request_live_memory(context, *addr, 256))
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
			} else
				request_chain_resolution(context, chain);
		}
		ImGui::PopID();

		if (hov) anim.step_flash[step_idx & 15] = 1.f;
		float flash = anim.step_flash[step_idx & 15];
		if (flash > 0.f) {
			border = aida::ui::with_alpha(t.accent_u32, a * (0.6f + flash * 0.4f));
			fill = aida::ui::with_alpha(t.accent_glow, a * 0.4f * flash);
		}

		std::string off = format_offset(chain.offsets[i]);
		ImU32 dot_col = aida::ui::with_alpha(t.accent_u32, a * local_t);
		float dot_cx = ba.x + 8.f;
		float dot_cy = (ba.y + bb.y) * 0.5f;
		dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), 3.f, dot_col, 12);

		dl->AddRectFilled(ba, bb, fill, 8.f);
		dl->AddRect(ba, bb, border, 8.f, 0, 1.f);
		dl->AddText(code_font, code_font_size,
			ImVec2(dot_cx + 8.f, dot_cy - 6.f),
			aida::ui::with_alpha(t.text_primary, a * local_t), off.c_str());

		cx += bw;
	}

	for (auto& f : anim.step_flash) {
		if (f > 0.f) {
			f -= dt * 1.66f;
			if (f < 0.f) f = 0.f;
		}
	}

	anim.hover_step = hover_step;
	if (hover_step >= 0) {
		resolution_status_t status = resolution_status_t::idle;
		std::string error;
		const auto address = hover_step == 0 ? chain_base_address(chain)
			: resolved_step_address(chain, hover_step, &status, &error);
		char tip[192]{};
		if (address)
			snprintf(tip, sizeof(tip), "Resolved: 0x%llX",
				static_cast<unsigned long long>(*address));
		else if (status == resolution_status_t::queued || status == resolution_status_t::running)
			snprintf(tip, sizeof(tip), "Resolving in background...");
		else if (!error.empty())
			snprintf(tip, sizeof(tip), "Unavailable: %s", error.c_str());
		else
			snprintf(tip, sizeof(tip), "Select the chain to resolve its hops.");
		ImVec2 mp = ImGui::GetMousePos();
		ImVec2 ts = ImGui::CalcTextSize(tip);
		ImVec2 tp(mp.x + 16.f, mp.y - ts.y - 8.f);
		dl->AddRectFilled(ImVec2(tp.x - 6.f, tp.y - 4.f),
			ImVec2(tp.x + ts.x + 6.f, tp.y + ts.y + 4.f),
			aida::ui::with_alpha(t.bg_overlay, 0.95f), 6.f);
		dl->AddRect(ImVec2(tp.x - 6.f, tp.y - 4.f),
			ImVec2(tp.x + ts.x + 6.f, tp.y + ts.y + 4.f),
			aida::ui::with_alpha(t.border_subtle, 1.f), 6.f, 0, 1.f);
		dl->AddText(code_font, code_font_size, tp,
			aida::ui::with_alpha(t.text_primary, 1.f), tip);
	}
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float, float, float)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static bool seeded = false;
	if (!seeded) {
		pointer_scanner::build_reverse_map();
		pointer_scanner::start_scan();
		seeded = true;
	}
#endif
	detail::observe_generations();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float a = alpha;
	auto& st = pointer_scanner::g_state;
	auto& view = g_view;

	const auto& t = aida::ui::resolved();
	ImFont* body_font = aida::ui::fonts::body();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());
	if (!code_font) code_font = ImGui::GetFont();
	float dt = aida::ui::clock::dt();
	view.anim_clock += dt;

	float x0 = wp.x + pos_x;
	float y0 = wp.y + pos_y;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + height),
		aida::ui::with_alpha(t.bg_base, a));

	float toolbar_h = 56.f;
	float config_panel_w = 340.f;
	float row_h = 28.f;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + toolbar_h),
		aida::ui::with_alpha(t.panel_header, a));
	dl->AddLine(ImVec2(x0, y0 + toolbar_h), ImVec2(x0 + width, y0 + toolbar_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	{
		ImFont* hdr_fn = aida::ui::fonts::body_em();
		float hdr_fs = aida::ui::fonts::size_or(hdr_fn, 16.f);
		if (!hdr_fn) hdr_fn = ImGui::GetFont();
		dl->AddText(hdr_fn, hdr_fs,
			ImVec2(x0 + 16.f, y0 + (toolbar_h - hdr_fs) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a), "Pointer Chain Scanner");
	}

	{
		char status_buf[160];
		size_t entries;
		size_t res_count;
		{
			std::lock_guard<std::mutex> lk(st.map_mutex);
			entries = st.map_entry_count;
		}
		{
			std::lock_guard<std::mutex> lk(st.results_mutex);
			res_count = st.results.size();
		}
		snprintf(status_buf, sizeof(status_buf), "Map: %zu  ·  Chains: %zu", entries, res_count);
		ImVec2 ts = ImGui::CalcTextSize(status_buf);
		dl->AddText(body_font, body_font_size,
			ImVec2(x0 + width - ts.x - 16.f, y0 + (toolbar_h - body_font_size) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a), status_buf);
	}

	float cfg_x = x0;
	float cfg_y = y0 + toolbar_h;
	float cfg_h = height - toolbar_h;

	dl->AddRectFilled(ImVec2(cfg_x, cfg_y), ImVec2(cfg_x + config_panel_w, cfg_y + cfg_h),
		aida::ui::with_alpha(t.panel_bg, a));
	dl->AddLine(ImVec2(cfg_x + config_panel_w, cfg_y), ImVec2(cfg_x + config_panel_w, cfg_y + cfg_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	bool live_now = true;
	bool static_pe_now = false;
#else
	bool live_now = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;
	bool static_pe_now = function_index::detail::static_pe_active();
#endif
	float cy = cfg_y + 18.f;
	float cx = cfg_x + 18.f;
	float field_w = config_panel_w - 36.f;

	if (!live_now && !static_pe_now) {
		ui_anim::render_inline_callout(dl, cx, cy, field_w, 36.f,
			"Pointer chain scanning requires a live attach.",
			ui_anim::callout_kind_t::warn, 0.85f, 0.6f, 0.2f, a);
		cy += 44.f;
	}

	{
		ImFont* hfn = aida::ui::fonts::body_em();
		float hfs = aida::ui::fonts::size_or(hfn, 14.f);
		if (!hfn) hfn = ImGui::GetFont();
		dl->AddText(hfn, hfs,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_primary, a), "Configuration");
		cy += hfs + 12.f;
	}

	{
		dl->AddText(body_font, body_font_size,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_dim, a), "Target Address");
		cy += body_font_size + 6.f;
	}

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	aida::ui::input_text("##ptr_addr", st.addr_buf, sizeof(st.addr_buf),
		"e.g. 7FF60012A440", false, ImVec2(field_w, 32.f));
	cy += 44.f;

	auto draw_label_and_value = [&](const char* lbl, int value) {
		ImFont* lblf = aida::ui::fonts::body();
		ImFont* valf = aida::ui::fonts::body_em();
		const float lblfs = aida::ui::fonts::size_or(lblf, ImGui::GetFontSize());
		const float valfs = aida::ui::fonts::size_or(valf, ImGui::GetFontSize());
		if (!lblf) lblf = ImGui::GetFont();
		if (!valf) valf = ImGui::GetFont();
		dl->AddText(lblf, lblfs,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_dim, a), lbl);
		char vbuf[32];
		std::snprintf(vbuf, sizeof(vbuf), "%d", value);
		ImVec2 vts = valf->CalcTextSizeA(valfs, FLT_MAX, 0.f, vbuf);
		float chip_pad_x = 8.f;
		float chip_w = vts.x + chip_pad_x * 2.f;
		float chip_h = valfs + 6.f;
		float chip_x = cx + field_w - chip_w;
		float chip_y = cy - 2.f;
		dl->AddRectFilled(ImVec2(chip_x, chip_y), ImVec2(chip_x + chip_w, chip_y + chip_h),
			aida::ui::with_alpha(t.panel_header, a * 0.9f), chip_h * 0.5f);
		dl->AddText(valf, valfs,
			ImVec2(chip_x + chip_pad_x, chip_y + 3.f),
			aida::ui::with_alpha(t.text_primary, a), vbuf);
		cy += lblfs + 6.f;
	};

	draw_label_and_value("Max Depth", st.config.max_depth);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushItemWidth(field_w);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, aida::ui::with_alpha(t.accent_hover, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::SliderInt("##ptr_depth", &st.config.max_depth, 1, 7, "");
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(4);
	ImGui::PopItemWidth();
	cy += 36.f;

	int max_off = static_cast<int>(st.config.max_offset);
	draw_label_and_value("Max Offset", max_off);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushItemWidth(field_w);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, aida::ui::with_alpha(t.accent_hover, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::SliderInt("##ptr_maxoff", &max_off, 64, 16384, "");
	st.config.max_offset = max_off;
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(4);
	ImGui::PopItemWidth();
	cy += 36.f;

	int struct_sz = static_cast<int>(st.config.struct_size);
	draw_label_and_value("Struct Size", struct_sz);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushItemWidth(field_w);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, a));
	ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, aida::ui::with_alpha(t.accent_hover, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::SliderInt("##ptr_struct", &struct_sz, 64, 16384, "");
	st.config.struct_size = struct_sz;
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(4);
	ImGui::PopItemWidth();
	cy += 40.f;

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool n = st.config.negative_offsets;
		aida::ui::toggle_switch("Negative Offsets##neg", &n, aida::ui::size_t_::sm);
		st.config.negative_offsets = n;
		cy += 28.f;
	}
	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool s = st.config.only_static_bases;
		aida::ui::toggle_switch("Static Bases Only##sb", &s, aida::ui::size_t_::sm);
		st.config.only_static_bases = s;
		cy += 34.f;
	}

	dl->AddLine(ImVec2(cx, cy), ImVec2(cx + field_w, cy),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);
	cy += 14.f;

	bool building = st.map_building.load();
	bool scanning = st.scanning.load();

	if (building) {
		float prog = st.map_progress.load();
		dl->AddText(body_font, body_font_size,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_dim, a), "Building reverse map...");
		aida::ui::render_progress_bar(ImVec2(cx, cy + 18.f), field_w, 6.f, prog, false, true);
		cy += 34.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
			pointer_scanner::cancel_all();
		}
		cy += 44.f;
	} else {
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Build Pointer Map", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f), !live_now)) {
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] pointer_scanner build_reverse_map");
			pointer_scanner::build_reverse_map();
		}
		cy += 46.f;
	}

	if (scanning) {
		float prog = st.scan_progress.load();
		dl->AddText(body_font, body_font_size,
			ImVec2(cx, cy), aida::ui::with_alpha(t.text_dim, a), "Scanning chains...");
		aida::ui::render_progress_bar(ImVec2(cx, cy + 18.f), field_w, 6.f, prog, false, true);
		cy += 34.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
			st.scan_cancel.store(true);
		}
		cy += 44.f;
	} else {
		bool can_scan = !building && st.map_entry_count > 0 && live_now;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Scan Chains", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f), !can_scan)) {
			const char* p = st.addr_buf;
			if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
			st.config.target_address = strtoull(p, nullptr, 16);
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] pointer_scanner scan_chains");
			pointer_scanner::start_scan();
		}
		cy += 46.f;
	}

	dl->AddLine(ImVec2(cx, cy), ImVec2(cx + field_w, cy),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);
	cy += 14.f;

	bool validating = st.validating.load();
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (validating) {
		float prog = st.validate_progress.load();
		dl->AddText(body_font, body_font_size,
			ImVec2(cx, cy - 16.f), aida::ui::with_alpha(t.text_dim, a), "Validating chains...");
		aida::ui::render_progress_bar(ImVec2(cx, cy + 4.f), field_w, 6.f, prog, false, true);
	} else {
		if (aida::ui::button("Validate All", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(field_w, 0.f),
				scanning || building || validating || !live_now)) {
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] pointer_scanner validate_all");
			pointer_scanner::validate_all_results();
		}
	}
	cy += 44.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (aida::ui::button("Clear Results", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
		pointer_scanner::clear_results();
		view.chain_anims.clear();
	}
	cy += 44.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (aida::ui::button("Clear Map", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(field_w, 0.f))) {
		pointer_scanner::clear_map();
	}

	float table_x = cfg_x + config_panel_w + 1.f;
	float table_y = cfg_y;
	float table_w = width - config_panel_w - 1.f;

	float detail_h = 200.f;
	float list_h = cfg_h - detail_h;

	float col_depth_w = 60.f;
	float col_module_w = 160.f;
	float col_base_w = 130.f;
	float col_status_w = 70.f;
	float col_chain_w = table_w - col_depth_w - col_module_w - col_base_w - col_status_w - 32.f;
	if (col_chain_w < 100.f) col_chain_w = 100.f;

	float hdr_h = 28.f;
	dl->AddRectFilled(ImVec2(table_x, table_y),
		ImVec2(table_x + table_w, table_y + hdr_h),
		aida::ui::with_alpha(t.panel_header, a * 0.85f));
	dl->AddLine(ImVec2(table_x, table_y + hdr_h),
		ImVec2(table_x + table_w, table_y + hdr_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	const char* col_names[5] = { "Depth", "Module", "Base+Offset", "Chain", "Valid" };
	float col_widths[5] = { col_depth_w, col_module_w, col_base_w, col_chain_w, col_status_w };
	float hx = table_x + 16.f;
	for (int c = 0; c < 5; ++c) {
		dl->AddText(body_font, body_font_size,
			ImVec2(hx, table_y + (hdr_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), col_names[c]);
		hx += col_widths[c];
	}

	float body_y = table_y + hdr_h;
	float body_h = list_h - hdr_h;

	ImGui::SetCursorScreenPos(ImVec2(table_x, body_y));
	ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
	ImGui::BeginChild("##ptr_results", ImVec2(table_w, body_h), false,
	                   ImGuiWindowFlags_NoScrollbar);

	size_t total = 0;
	{
		std::lock_guard<std::mutex> lock(st.results_mutex);
		total = st.results.size();
	}
	int visible_count = static_cast<int>(body_h / row_h);
	const size_t visible_rows = visible_count > 0 ? static_cast<size_t>(visible_count) : 0;

	float wheel = ImGui::GetIO().MouseWheel;
	ImVec2 mp = ImGui::GetMousePos();
	if (mp.x >= table_x && mp.x <= table_x + table_w && mp.y >= body_y && mp.y <= body_y + body_h) {
		st.target_scroll_y -= wheel * row_h * 3.f;
		if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
		float max_scroll = (total > visible_rows)
			? static_cast<float>(total - visible_rows) * row_h
			: 0.f;
		if (st.target_scroll_y > max_scroll) st.target_scroll_y = max_scroll;
	}
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 20.f, dt);

	int start_row = static_cast<int>(st.scroll_y / row_h);
	if (start_row < 0) start_row = 0;
	const size_t start_index = static_cast<size_t>(start_row);
	const size_t rendered_row_count = visible_rows + 2;
	std::vector<std::pair<size_t, pointer_scanner::pointer_chain_t>> visible_chains;
	{
		std::lock_guard<std::mutex> lock(st.results_mutex);
		const size_t current_total = st.results.size();
		const size_t end_index = (std::min)(current_total, start_index + rendered_row_count);
		visible_chains.reserve(end_index > start_index ? end_index - start_index : 0);
		for (size_t index = start_index; index < end_index; ++index)
			visible_chains.emplace_back(index, st.results[index]);
		total = current_total;
	}
	bool open_chain_context = false;
	auto chain_context_origin = aida::ui::context_menu_open_origin_t::pointer;

	for (auto& [i, chain] : visible_chains) {
		const int visible_row = static_cast<int>(i - start_index);
		float ry = body_y + static_cast<float>(visible_row) * row_h
			- (st.scroll_y - static_cast<float>(start_row) * row_h);
		if (ry + row_h < body_y || ry > body_y + body_h) continue;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const std::string chain_semantic_id = detail::studio_pointer_entity_id(
			"pointer-chain", chain);
		aida::preview::semantics::register_region(chain_semantic_id,
			"pointer-chain-row", ImGui::GetID(chain_semantic_id.c_str()),
			ImVec2(table_x, ry), ImVec2(table_x + table_w, ry + row_h), false, false,
			"aida.dock-window.view.memory.pointers");
#endif

		bool hovered = (mp.x >= table_x && mp.x <= table_x + table_w &&
		                mp.y >= ry && mp.y < ry + row_h);
		bool selected = st.selected_result >= 0 &&
			i == static_cast<size_t>(st.selected_result);

		float row_a = ui_anim::render_row_entrance(visible_row, view.anim_clock, 0.012f);

		if (selected) {
			dl->AddRectFilled(ImVec2(table_x, ry), ImVec2(table_x + table_w, ry + row_h),
				aida::ui::with_alpha(t.selection, a * row_a));
			dl->AddRectFilled(ImVec2(table_x, ry), ImVec2(table_x + 3.f, ry + row_h),
				aida::ui::with_alpha(t.accent_u32, a * row_a));
		} else if (hovered) {
			dl->AddRectFilled(ImVec2(table_x, ry), ImVec2(table_x + table_w, ry + row_h),
				aida::ui::with_alpha(t.hover_wash, a * row_a));
		} else if (i & 1) {
			dl->AddRectFilled(ImVec2(table_x, ry), ImVec2(table_x + table_w, ry + row_h),
				aida::ui::with_alpha(IM_COL32(255, 255, 255, 4), a * row_a));
		}

		if (hovered && ImGui::IsMouseClicked(0)) {
			st.selected_result = static_cast<int>(i);
			detail::request_chain_resolution(disasm_view::capture_selected_workspace(), chain);
			memory_interaction::runtime_t runtime;
			runtime.driver_loaded = driver_bridge::is_loaded();
			runtime.live_attached = driver_bridge::attached_pid() != 0;
			runtime.target_pid = driver_bridge::attached_pid();
			const std::uint64_t base = detail::chain_base_address(chain).value_or(0);
			memory_interaction::select(memory_interaction::capture_pointer_chain(runtime,
				base, static_cast<std::uint64_t>(chain.offsets.size()), static_cast<int>(i),
				pointer_scanner::chain_to_string(chain)));
		}
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			st.selected_result = static_cast<int>(i);
			view.context_chain = pointer_scanner::chain_to_string(chain);
			detail::request_chain_resolution(disasm_view::capture_selected_workspace(), chain);
			open_chain_context = true;
		}

		float rx = table_x + 16.f;
		char buf[32];

		snprintf(buf, sizeof(buf), "%d", chain.depth);
		dl->AddText(body_font, body_font_size,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a * row_a), buf);
		rx += col_depth_w;

		dl->AddText(body_font, body_font_size,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			chain.is_static ? aida::ui::with_alpha(t.accent_u32, a * row_a)
			                 : aida::ui::with_alpha(t.text_dim, a * row_a),
			chain.module_name.empty() ? "dynamic" : chain.module_name.c_str());
		rx += col_module_w;

		snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(chain.base_offset));
		dl->AddText(code_font, code_font_size,
			ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, a * row_a), buf);
		rx += col_base_w;

		std::string chain_str;
		for (size_t j = 0; j < chain.offsets.size(); ++j) {
			if (j > 0) chain_str += " -> ";
			chain_str += detail::format_offset(chain.offsets[j]);
		}

		float avail = col_chain_w - 4.f;
		ImVec2 chain_sz = ImGui::CalcTextSize(chain_str.c_str());
		if (chain_sz.x > avail) {
			size_t trunc = chain_str.size();
			while (trunc > 3) {
				--trunc;
				std::string test = chain_str.substr(0, trunc) + "...";
				if (ImGui::CalcTextSize(test.c_str()).x <= avail) {
					chain_str = test;
					break;
				}
			}
		}
		dl->AddText(code_font, code_font_size,
			ImVec2(rx, ry + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a * row_a), chain_str.c_str());
		rx += col_chain_w;

		ImGui::SetCursorScreenPos(ImVec2(rx, ry + (row_h - 18.f) * 0.5f));
		ImGui::PushID(static_cast<int>(i) + 32768);
		detail::resolution_status_t row_resolution = detail::resolution_status_t::idle;
		static_cast<void>(detail::resolved_step_address(chain,
			static_cast<int>(chain.offsets.size()), &row_resolution));
		const bool row_valid = chain.validated ||
			row_resolution == detail::resolution_status_t::ready;
		aida::ui::pill_kind(row_valid ? "valid" :
			(row_resolution == detail::resolution_status_t::queued ||
			 row_resolution == detail::resolution_status_t::running) ? "busy" : "?",
			row_valid ? aida::ui::components::pill_kind_t::success
			                : aida::ui::components::pill_kind_t::neutral,
			aida::ui::size_t_::sm, true);
		ImGui::PopID();
	}

	auto capture_selected_chain = [&]() -> std::optional<pointer_scanner::pointer_chain_t> {
		if (st.selected_result < 0)
			return {};
		std::lock_guard<std::mutex> lock(st.results_mutex);
		const auto index = static_cast<std::size_t>(st.selected_result);
		if (index >= st.results.size())
			return {};
		return st.results[index];
	};
	auto selected_chain = capture_selected_chain();
	const bool chain_keyboard_context = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
		detail::context_key_pressed() && selected_chain.has_value();
	if (chain_keyboard_context) {
		view.context_chain = pointer_scanner::chain_to_string(*selected_chain);
		detail::request_chain_resolution(disasm_view::capture_selected_workspace(),
			*selected_chain);
		open_chain_context = true;
		chain_context_origin = ImGui::IsKeyPressed(ImGuiKey_Menu, false)
			? aida::ui::context_menu_open_origin_t::menu_key
			: aida::ui::context_menu_open_origin_t::shift_f10;
	}
	ImGui::EndChild();
	ImGui::PopStyleColor();

	if (total == 0) {
		if (scanning || building) {
			float sk_y = body_y + 12.f;
			for (int s = 0; s < 6; ++s) {
				if (sk_y + 24.f > body_y + body_h) break;
				aida::ui::skeleton::render_block(dl,
					ImVec2(table_x + 16.f, sk_y),
					ImVec2(table_x + table_w - 24.f, sk_y + 22.f), 8.f, 1.4f);
				sk_y += 30.f;
			}
		} else {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::dots;
			if (st.map_entry_count == 0) {
				cfg.title = "Build the map first";
				cfg.body = "Click \"Build Pointer Map\" to enumerate every pointer in the target.";
			} else {
				cfg.title = "No chains yet";
				cfg.body = "Enter a target address and click \"Scan Chains\".";
			}
			aida::ui::empty_state::render(ImVec2(table_x, body_y), ImVec2(table_w, body_h), cfg);
		}
	}
	if (open_chain_context) {
		selected_chain = capture_selected_chain();
		if (selected_chain) {
			const auto chain = *selected_chain;
			const std::string chain_text = pointer_scanner::chain_to_string(chain);
			const bool current = chain_text == view.context_chain;
			const auto base_value = detail::chain_base_address(chain);
			detail::resolution_status_t resolution_status = detail::resolution_status_t::idle;
			std::string resolution_error;
			const auto resolved_value = detail::resolved_step_address(chain,
				static_cast<int>(chain.offsets.size()), &resolution_status, &resolution_error);
			const std::uint64_t base = base_value.value_or(0);
			const std::uint64_t resolved = resolved_value.value_or(0);
			const auto workspace = disasm_view::capture_selected_workspace();
			const auto workspace_generation = workspace.workspace ? workspace.workspace->generation() : 0;
			const auto map_generation = view.map_generation;
			const auto result_generation = view.result_generation;
			const auto target_pid = driver_bridge::attached_pid();
			aida::ui::application_ui::retained_entity_context_t retained;
			retained.owner_id = "memory.pointer.chain";
			retained.entity_id = detail::chain_identity_key(chain);
			retained.entity_generation = result_generation;
			retained.active_view = aida::ui::stable_view_id_t("view.memory.pointers");
			retained.validate_identity = [chain, chain_text, workspace, workspace_generation,
				map_generation, result_generation, target_pid]() {
				if (!workspace.workspace || workspace.workspace->generation() != workspace_generation)
					return aida::ui::capability_state_t::unavailable("The pointer workspace generation changed.");
				if (driver_bridge::attached_pid() != target_pid || g_view.map_generation != map_generation ||
					g_view.result_generation != result_generation)
					return aida::ui::capability_state_t::unavailable("The target, pointer map, or results changed.");
				std::lock_guard<std::mutex> lock(pointer_scanner::g_state.results_mutex);
				const bool exists = std::any_of(pointer_scanner::g_state.results.begin(),
					pointer_scanner::g_state.results.end(), [&](const auto& item) {
						return pointer_scanner::chain_to_string(item) == chain_text;
					});
				return exists ? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable("The selected pointer chain is no longer published.");
			};
			auto add = [&](const char* id, bool enabled, const char* reason, auto invoke) {
				retained.actions.push_back({id, enabled ? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(reason), invoke});
			};
			add("memory.pointer.copy_chain", current, "The selected chain is stale.", [chain_text]() {
				ImGui::SetClipboardText(chain_text.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.pointer.copy_cpp", current, "The selected chain is stale.", [chain]() {
				const std::string cpp = pointer_scanner::export_chain_cpp(chain);
				ImGui::SetClipboardText(cpp.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.pointer.copy_base", current && base != 0,
				!current ? "The selected chain is stale." : "The chain has no resolved base address.", [base]() {
				char address[24];
				std::snprintf(address, sizeof(address), "0x%016llX",
					static_cast<unsigned long long>(base));
				ImGui::SetClipboardText(address);
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.pointer.copy_resolved", current && resolved != 0,
				!current ? "The selected chain is stale." : "The chain has no resolved final address.", [resolved]() {
				char address[24];
				std::snprintf(address, sizeof(address), "0x%016llX",
					static_cast<unsigned long long>(resolved));
				ImGui::SetClipboardText(address);
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.pointer.open_base_disassembly", current && base != 0,
				!current ? "The selected chain is stale." : "The chain has no resolved base address.", [base, workspace]() {
				disasm_view::goto_address(base, workspace);
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.pointer.open_resolved_hex", current && resolved != 0 && target_pid != 0,
				!current ? "The selected chain is stale." : resolved == 0
					? "The chain has no resolved final address." : "Attach to the target process first.", [workspace, resolved]() {
				if (hex_view::request_live_memory(workspace, resolved, 256))
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.pointer.add_address", current && resolved != 0 && target_pid != 0,
				!current ? "The selected chain is stale." : resolved == 0
					? "The chain has no resolved final address." : "Attach to the target process first.", [resolved, chain_text]() {
				memory_scanner::add_address(resolved, chain_text,
					memory_scanner::value_type_t::int64_val);
				return aida::ui::action_handler_result_t::completed();
			});
			add("memory.pointer.stage_patch", current && resolved != 0 && target_pid != 0,
				!current ? "The selected chain is stale." : resolved == 0
					? "The chain has no resolved final address." : "Attach to the target process first.", [resolved]() {
				std::string error;
				const bool staged = debugger_view::stage_patch_review(resolved, 1,
					"Staged from pointer chain", &error);
				if (staged)
					aida::ui::application_views::open_or_focus(
						aida::ui::stable_view_id_t("view.debug.patches"));
				return staged ? aida::ui::action_handler_result_t::completed()
					: aida::ui::action_handler_result_t::failed(error.empty()
						? "The patch review could not be staged." : error);
			});
			add("memory.pointer.validate", current && target_pid != 0,
				!current ? "The selected chain is stale." : "Attach to the target process first.", [workspace, chain]() {
				detail::request_chain_resolution(workspace, chain);
				return aida::ui::action_handler_result_t::completed();
			});
			char base_text[24]{};
			char resolved_text[24]{};
			std::snprintf(base_text, sizeof(base_text), "0x%016llX",
				static_cast<unsigned long long>(base));
			std::snprintf(resolved_text, sizeof(resolved_text), "0x%016llX",
				static_cast<unsigned long long>(resolved));
			aida::automation_ui::entity_evidence::snapshot_t evidence;
			evidence.workspace_id = "pid:" + std::to_string(target_pid);
			evidence.source_view_id = "view.memory.pointers";
			evidence.source_kind = "pointer_chain";
			evidence.entity_id = retained.entity_id;
			evidence.display_label = "Pointer chain to " + std::string(resolved_text);
			evidence.excerpt = "PID: " + std::to_string(target_pid) +
				"\nMap generation: " + std::to_string(map_generation) +
				"\nResult generation: " + std::to_string(result_generation) +
				"\nBase: " + base_text + "\nResolved: " + resolved_text +
				"\nChain: " + chain_text;
			evidence.address = resolved != 0 ? resolved : base;
			evidence.revision = map_generation;
			evidence.generation = result_generation;
			evidence.sensitive = true;
			evidence.return_to_source = [chain_text, workspace, workspace_generation,
				map_generation, result_generation, target_pid](std::string& reason) {
			if (!workspace.workspace || workspace.workspace->generation() != workspace_generation ||
				driver_bridge::attached_pid() != target_pid ||
				g_view.map_generation != map_generation ||
				g_view.result_generation != result_generation) {
				reason = "The target, pointer map, results, or workspace generation changed; capture the chain again.";
				return false;
			}
			{
				std::lock_guard<std::mutex> lock(pointer_scanner::g_state.results_mutex);
				const auto found = std::find_if(pointer_scanner::g_state.results.begin(),
					pointer_scanner::g_state.results.end(), [&](const auto& item) {
						return pointer_scanner::chain_to_string(item) == chain_text;
					});
				if (found == pointer_scanner::g_state.results.end()) {
					reason = "The retained pointer chain is no longer published; capture it again.";
					return false;
				}
				pointer_scanner::g_state.selected_result = static_cast<int>(
					std::distance(pointer_scanner::g_state.results.begin(), found));
				g_view.context_chain = chain_text;
			}
			const auto opened = aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.memory.pointers"));
			if (!opened.ok()) {
				reason = opened.detail;
				return false;
			}
			reason.clear();
			return true;
		};
			aida::automation_ui::entity_evidence::append_actions(retained,
				std::move(evidence), current && target_pid != 0
					? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(!current
						? "The retained pointer chain changed; select it again."
						: "Attach to the retained target process before handing off pointer evidence."));
			aida::ui::application_ui::open_retained_entity_context_menu(
				std::move(retained), chain_context_origin);
		}
	}
	aida::ui::application_ui::render_retained_entity_context_menu("memory.pointer.chain");

	float det_x = table_x;
	float det_y = cfg_y + list_h;
	float det_w = table_w;

	dl->AddLine(ImVec2(det_x, det_y), ImVec2(det_x + det_w, det_y),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);
	dl->AddRectFilled(ImVec2(det_x, det_y + 1.f),
		ImVec2(det_x + det_w, det_y + detail_h),
		aida::ui::with_alpha(t.panel_bg, a));

	selected_chain = capture_selected_chain();
	if (selected_chain) {
		auto& chain = *selected_chain;
		auto& anim = view.chain_anims[st.selected_result];
		if (view.last_selected != st.selected_result) {
			anim.reveal = 0.f;
			view.last_selected = st.selected_result;
			detail::request_chain_resolution(disasm_view::capture_selected_workspace(), chain);
		}

		dl->AddText(aida::ui::fonts::body_em(), 13.f,
			ImVec2(det_x + 16.f, det_y + 12.f),
			aida::ui::with_alpha(t.text_primary, a), "Chain Detail");

		{
			float bx = det_x + det_w - 320.f;
			ImGui::SetCursorScreenPos(ImVec2(bx, det_y + 8.f));
			if (aida::ui::button("Copy Chain", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				std::string cs = pointer_scanner::chain_to_string(chain);
				ImGui::SetClipboardText(cs.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(bx + 100.f, det_y + 8.f));
			if (aida::ui::button("Copy C++", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				std::string cs = pointer_scanner::export_chain_cpp(chain);
				ImGui::SetClipboardText(cs.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(bx + 200.f, det_y + 8.f));
			if (aida::ui::button("Goto Base", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::sm)) {
				const uint64_t addr = detail::chain_base_address(chain).value_or(0);
				if (addr != 0) {
					disasm_view::goto_address(addr,
						disasm_view::capture_selected_workspace());
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
				}
			}
		}

		float info_y = det_y + 36.f;
		char info_buf[160];
		snprintf(info_buf, sizeof(info_buf), "Depth %d  ·  %s  ·  %s",
			chain.depth, chain.is_static ? "Static" : "Dynamic",
			chain.validated ? "Validated" : "Not validated");
		dl->AddText(body_font, body_font_size,
			ImVec2(det_x + 16.f, info_y),
			aida::ui::with_alpha(t.text_secondary, a), info_buf);

		float diag_y = det_y + 60.f;
		float diag_h = detail_h - 70.f;
		dl->AddRectFilled(ImVec2(det_x + 12.f, diag_y),
			ImVec2(det_x + det_w - 12.f, diag_y + diag_h),
			aida::ui::with_alpha(t.bg_overlay, a * 0.55f), 10.f);
		dl->AddRect(ImVec2(det_x + 12.f, diag_y),
			ImVec2(det_x + det_w - 12.f, diag_y + diag_h),
			aida::ui::with_alpha(t.border_subtle, a), 10.f, 0, 1.f);

		detail::render_chain_diagram(dl, det_x + 12.f, diag_y, det_w - 24.f, diag_h,
			st.selected_result, chain, a, anim);
	} else if (total > 0) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::flow;
		cfg.title = "Select a chain";
		cfg.body = "Click any row above to inspect its dereference path. Click any step to peek at the resolved memory.";
		aida::ui::empty_state::render(ImVec2(det_x, det_y), ImVec2(det_w, detail_h), cfg);
	}
}

}
