#include "memory_scanner_view.hpp"
#include "memory_scanner.hpp"
#include "scanner_task_center.hpp"
#include "scanner_async_io.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#include "../../preview/studio_semantics.hpp"
#include "../../preview/scan_preview_runtime.hpp"
#else
#include "standalone_driver.hpp"
#include "../anti-tamper/webhook.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../disasm/function_index.hpp"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#endif
#include "disasm_view.hpp"
#include "hex_view.hpp"
#include "../debugger/debugger_view.hpp"
#include "pointer_scanner_view.hpp"
#include "../analysis/struct_dissector_view.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ai/entity_evidence_handoff.hpp"
#include "../network/burp/comparer.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#include "../helpers/helpers.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/win32_dialog.hpp"
#endif
#include "ui_anim.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/design_system.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"
#include "../ui/toast_notification.hpp"
#include "../ui/no_target_overlay.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <initializer_list>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <nlohmann/json.hpp>

namespace memory_scanner_view {

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
std::string studio_memory_entity_id(const char* entity,
	const memory_interaction::context_t& context) {
	const ImGuiWindow* window = ImGui::GetCurrentWindowRead();
	const std::string_view window_name = window && window->Name ? window->Name : "";
	std::string identity;
	if (window_name.find("view.memory.value_scan_results") != std::string_view::npos)
		identity = "results-pane:";
	else if (window_name.find("view.memory.address_list") != std::string_view::npos)
		identity = "address-list-pane:";
	identity += std::to_string(static_cast<unsigned>(context.source)) + ":" +
		std::to_string(context.target_pid) + ":" + std::to_string(context.address) +
		(context.address == 0 ? ":" + std::to_string(context.index) : std::string{});
	std::string source(entity);
	source.push_back('-');
	source.append(aida::preview::semantics::entity_token(identity));
	return aida::preview::semantics::stable_id("aida.memory", source);
}

const char* studio_memory_parent_id() noexcept {
	const ImGuiWindow* window = ImGui::GetCurrentWindowRead();
	const std::string_view window_name = window && window->Name ? window->Name : "";
	if (window_name.find("view.memory.value_scan_results") != std::string_view::npos)
		return "aida.dock-window.view.memory.value-scan-results";
	if (window_name.find("view.memory.address_list") != std::string_view::npos)
		return "aida.dock-window.view.memory.address-list";
	return "aida.dock-window.view.memory.value-scan";
}

std::string studio_memory_surface_id(std::string source) {
	const ImGuiWindow* window = ImGui::GetCurrentWindowRead();
	const std::string_view window_name = window && window->Name ? window->Name : "";
	if (window_name.find("view.memory.value_scan_results") != std::string_view::npos)
		source.insert(0, "results-pane-");
	else if (window_name.find("view.memory.address_list") != std::string_view::npos)
		source.insert(0, "address-list-pane-");
	return aida::preview::semantics::stable_id("aida.memory", source);
}
#endif

namespace {

constexpr float kToolbarHeight       = 56.f;
constexpr float kResultHeaderHeight  = 32.f;
constexpr float kResultRowHeight     = 30.f;
constexpr float kAddrHeaderHeight    = 32.f;
constexpr float kAddrTableHeaderH    = 26.f;
constexpr float kAddrRowHeight       = 30.f;
constexpr float kScrollbarTrackW     = 14.f;
constexpr float kSplitterThickness   = 6.f;
constexpr float kCalloutHeight       = 30.f;
constexpr std::size_t kMaximumMemoryMultiSelection = 4096;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
constexpr int   kRegionRefreshChunk  = 4096;
#endif

constexpr int kColResultAddr     = 0;
constexpr int kColResultValue    = 1;
constexpr int kColResultPrevious = 2;
constexpr int kColResultModule   = 3;

constexpr int kColAddrFreeze     = 0;
constexpr int kColAddrDesc       = 1;
constexpr int kColAddrAddress    = 2;
constexpr int kColAddrType       = 3;
constexpr int kColAddrValue      = 4;

struct column_layout_t {
	float x0 = 0.f;
	float x1 = 0.f;
	float inner_x0 = 0.f;
	float inner_x1 = 0.f;
	const char* title = "";
};

std::atomic<bool> s_open_result_ctx{false};
std::atomic<bool> s_open_address_ctx{false};
std::atomic<int> s_result_context_origin{0};
std::atomic<int> s_address_context_origin{0};
const char* s_current_result_owner_view = "view.memory.value_scan";
const char* s_current_address_owner_view = "view.memory.value_scan";
std::string s_retained_result_owner_view = "view.memory.value_scan";
std::string s_retained_address_owner_view = "view.memory.value_scan";
std::atomic<bool> s_open_add_dialog{false};
std::atomic<uint64_t> s_pending_add_addr{0};
std::atomic<int> s_pending_add_vtype{0};
std::atomic<int> s_pending_edit_value_index{-1};
char s_edit_value_buf[128] = {};
std::atomic<int> s_pending_change_type_index{-1};
int s_pending_change_type_value = 0;

struct value_write_result_t {
	memory_interaction::context_t context;
	memory_scanner::value_type_t value_type = memory_scanner::value_type_t::int32_val;
	bool verified = false;
	bool rollback_verified = false;
	std::string detail;
};

std::atomic<bool> s_value_write_pending{false};
std::shared_ptr<const value_write_result_t> s_value_write_completion;
bool s_value_write_close_requested = false;

memory_interaction::runtime_t runtime_snapshot();

bool address_entry_matches_context(const memory_scanner::address_entry_t& entry,
	const memory_interaction::context_t& context,
	memory_scanner::value_type_t value_type) noexcept {
	return entry.address == context.address && entry.value_type == value_type &&
		entry.target_pid == context.target_pid && entry.target_epoch == context.target_epoch &&
		entry.target_identity.process.creation_time_100ns ==
			context.process_creation_time_100ns;
}

bool request_value_write(const memory_interaction::context_t& context,
	memory_scanner::value_type_t value_type, std::vector<std::uint8_t> expected,
	std::string& error) {
	if (!memory_scanner::validate_target_binding(context.target_pid, context.target_epoch,
		context.process_creation_time_100ns)) {
		error = "The reviewed process identity is no longer attached.";
		return false;
	}
	bool idle = false;
	if (!s_value_write_pending.compare_exchange_strong(idle, true,
		std::memory_order_acq_rel)) {
		error = "Another reviewed memory write is still pending.";
		return false;
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto result = std::make_shared<value_write_result_t>();
	result->context = context;
	result->value_type = value_type;
	result->verified = true;
	result->detail = "Preview memory write verified.";
	{
		std::lock_guard<std::mutex> lock(memory_scanner::g_state.address_mutex);
		if (context.index >= 0 && context.index <
			static_cast<int>(memory_scanner::g_state.address_list.size()) &&
			address_entry_matches_context(memory_scanner::g_state.address_list[
				static_cast<std::size_t>(context.index)], context, value_type))
			memory_scanner::g_state.address_list[static_cast<std::size_t>(context.index)].last_value =
				std::move(expected);
	}
	std::atomic_store_explicit(&s_value_write_completion,
		std::shared_ptr<const value_write_result_t>(std::move(result)),
		std::memory_order_release);
	s_value_write_pending.store(false, std::memory_order_release);
	return true;
#else
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "memory_scanner";
	submission.label = "Write and verify memory value";
	submission.thread_class = "live_memory_mutation";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 4;
	submission.target_pid = context.target_pid;
	submission.generation = context.scan_revision;
	submission.ui_access_policy = "completion_snapshot_only";
	submission.failure_policy = "rollback_and_fail_closed";
	submission.body = [context, value_type, expected = std::move(expected)]() mutable {
		auto result = std::make_shared<value_write_result_t>();
		result->context = context;
		result->value_type = value_type;
		try {
			const auto binding_current = [&context]() {
				return memory_scanner::validate_target_binding(context.target_pid,
					context.target_epoch, context.process_creation_time_100ns);
			};
			const auto current_runtime = runtime_snapshot();
			if (!memory_interaction::is_current(context, current_runtime))
				result->detail = "The target or scan generation changed before the memory write.";
			if (result->detail.empty()) {
				std::lock_guard<std::mutex> lock(memory_scanner::g_state.address_mutex);
				if (context.index < 0 || context.index >=
					static_cast<int>(memory_scanner::g_state.address_list.size()))
					result->detail = "The reviewed address-list entry no longer exists.";
				else {
					const auto& entry = memory_scanner::g_state.address_list[
						static_cast<std::size_t>(context.index)];
					if (!address_entry_matches_context(entry, context, value_type))
						result->detail = "The reviewed address-list entry changed before the write.";
				}
			}
			std::vector<std::uint8_t> original;
			if (result->detail.empty()) {
				if (!binding_current()) {
					result->detail = "The reviewed process identity changed before reading original bytes.";
				} else {
					const bool read = driver_bridge::read_memory(
						context.address, expected.size(), original);
					const bool identity_after_read = binding_current();
					if (!identity_after_read)
						result->detail = "The reviewed process identity changed while original bytes were being read.";
					else if (!read || original.size() != expected.size())
						result->detail = "The original target bytes could not be captured exactly.";
				}
			}
			bool write_attempted = false;
			if (result->detail.empty()) {
				if (!binding_current()) {
					result->detail = "The reviewed process identity changed before the memory write.";
				} else {
					write_attempted = true;
					const bool written = driver_bridge::write_memory(context.address, expected);
					const bool identity_after_write = binding_current();
					if (!identity_after_write)
						result->detail = "The reviewed process identity changed during the memory write.";
					else if (!written)
						result->detail = "The target rejected the reviewed memory write.";
				}
			}
			std::vector<std::uint8_t> observed;
			if (result->detail.empty()) {
				if (!binding_current()) {
					result->detail = "The reviewed process identity changed before memory-write verification.";
				} else {
					const bool readback = driver_bridge::read_memory(context.address,
						expected.size(), observed);
					const bool identity_after_readback = binding_current();
					result->verified = readback && identity_after_readback && observed == expected;
					if (!identity_after_readback)
						result->detail = "The reviewed process identity changed during memory-write verification.";
					else if (!result->verified)
						result->detail = "Memory write verification failed.";
				}
			}
			if (result->verified) {
				std::lock_guard<std::mutex> lock(memory_scanner::g_state.address_mutex);
				result->verified = context.index >= 0 && context.index <
						static_cast<int>(memory_scanner::g_state.address_list.size()) &&
						address_entry_matches_context(memory_scanner::g_state.address_list[
							static_cast<std::size_t>(context.index)], context, value_type);
				if (!result->verified)
					result->detail = "The address-list identity changed while the reviewed write was in flight.";
			}
			if (write_attempted && !result->verified) {
				const std::string failure = result->detail.empty()
					? "Memory write verification failed." : result->detail;
				bool rollback_written = false;
				bool rollback_identity_after_write = false;
				if (binding_current()) {
					rollback_written = driver_bridge::write_memory(context.address, original);
					rollback_identity_after_write = binding_current();
				}
				std::vector<std::uint8_t> rollback_readback;
				bool rollback_read = false;
				bool rollback_identity_after_read = false;
				if (rollback_written && rollback_identity_after_write && binding_current()) {
					rollback_read = driver_bridge::read_memory(context.address,
						original.size(), rollback_readback);
					rollback_identity_after_read = binding_current();
				}
				result->rollback_verified = rollback_written &&
					rollback_identity_after_write && rollback_read &&
					rollback_identity_after_read && rollback_readback == original;
				result->detail = failure + (result->rollback_verified
					? " Original bytes were restored and verified for the exact process identity."
					: " Original-byte restoration was not attempted or could not be verified for the exact process identity.");
			}
			if (result->verified) {
				std::lock_guard<std::mutex> lock(memory_scanner::g_state.address_mutex);
				if (context.index >= 0 && context.index <
					static_cast<int>(memory_scanner::g_state.address_list.size())) {
					auto& entry = memory_scanner::g_state.address_list[
						static_cast<std::size_t>(context.index)];
					if (address_entry_matches_context(entry, context, value_type))
						entry.last_value = expected;
				}
				result->detail = "Memory value written and read back exactly.";
			}
		} catch (const std::exception& exception) {
			result->detail = std::string("Memory write failed: ") + exception.what();
		} catch (...) {
			result->detail = "Memory write failed with an unknown error.";
		}
		const bool verified = result->verified;
		const std::string failure = result->detail;
		std::atomic_store_explicit(&s_value_write_completion,
			std::shared_ptr<const value_write_result_t>(std::move(result)),
			std::memory_order_release);
		s_value_write_pending.store(false, std::memory_order_release);
		if (!verified) throw std::runtime_error(failure);
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		s_value_write_pending.store(false, std::memory_order_release);
		error = submitted.reject_reason.empty()
			? "The memory-write executor rejected the operation." : submitted.reject_reason;
		return false;
	}
	scanner_task_center::register_executor_task(submitted, "view.memory.value_scan",
		"memory.address.write", "Write and verify memory value", context.target_pid, false);
	return true;
#endif
}

bool input_is_active() {
	return ImGui::GetActiveID() != 0 && ImGui::IsAnyItemActive();
}

const char* region_kind_label(uint32_t type, uint32_t state) {
	if (state != 0x1000) return "Unmapped";
	if (type == 0x1000000) return "Image";
	if (type == 0x40000)   return "Mapped";
	if (type == 0x20000)   return "Private";
	return "Region";
}

std::string compose_module_label(const memory_scanner::scan_result_t& r,
								  const std::vector<region_cache_entry_t>& regions)
{
	if (!r.module_name.empty()) {
		char buf[160];
		snprintf(buf, sizeof(buf), "%s+0x%" PRIX64,
			r.module_name.c_str(),
			r.module_offset);
		return std::string(buf);
	}
	if (regions.empty()) return std::string();
	auto it = std::upper_bound(regions.begin(), regions.end(), r.address,
		[](uint64_t addr, const region_cache_entry_t& e) { return addr < e.base; });
	if (it == regions.begin()) return std::string();
	--it;
	if (r.address < it->base || r.address >= it->end) return std::string();
	const char* kind = region_kind_label(it->type, it->state);
	char buf[96];
	snprintf(buf, sizeof(buf), "%s+0x%" PRIX64,
		kind, r.address - it->base);
	return std::string(buf);
}

std::string clip_to_width(ImFont* font, float fs, const std::string& s, float max_w) {
	if (s.empty()) return s;
	ImVec2 full = font->CalcTextSizeA(fs, FLT_MAX, 0.f, s.c_str());
	if (full.x <= max_w) return s;
	const std::string ell("..");
	float ell_w = font->CalcTextSizeA(fs, FLT_MAX, 0.f, ell.c_str()).x;
	if (max_w <= ell_w + 2.f) return ell;
	float budget = max_w - ell_w;
	size_t lo = 0;
	size_t hi = s.size();
	size_t best = 0;
	while (lo <= hi) {
		size_t mid = (lo + hi) / 2;
		ImVec2 w = font->CalcTextSizeA(fs, FLT_MAX, 0.f, s.c_str(), s.c_str() + mid);
		if (w.x <= budget) { best = mid; lo = mid + 1; }
		else {
			if (mid == 0) break;
			hi = mid - 1;
		}
	}
	if (best == 0) return ell;
	std::string out(s.c_str(), s.c_str() + best);
	out += ell;
	return out;
}

void draw_clipped_text(ImDrawList* dl, ImFont* font, float fs,
                       float x, float y, float max_w,
                       ImU32 color, const std::string& s)
{
	if (s.empty()) return;
	std::string disp = clip_to_width(font, fs, s, max_w);
	dl->AddText(font, fs, ImVec2(x, y), color, disp.c_str());
}

void diag_log(const char* msg) {
	diag::log_tagged("value_scan", msg);
}

void diag_logf(const char* fmt, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	_vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
	va_end(ap);
	diag::log_tagged("value_scan", buf);
}

bool ctrl_held() {
	ImGuiIO& io = ImGui::GetIO();
	return io.KeyCtrl;
}
bool shift_held() {
	ImGuiIO& io = ImGui::GetIO();
	return io.KeyShift;
}

memory_interaction::runtime_t runtime_snapshot_locked(std::size_t result_count) {
	memory_interaction::runtime_t runtime;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	runtime.driver_loaded = true;
	runtime.target_pid = memory_scanner::g_state.observed_target_pid.load(
		std::memory_order_acquire);
	runtime.live_attached = runtime.target_pid != 0;
	runtime.static_loaded = true;
#else
	runtime.driver_loaded = driver_bridge::is_loaded();
	runtime.target_pid = driver_bridge::attached_pid();
	runtime.live_attached = runtime.driver_loaded && runtime.target_pid != 0;
	runtime.static_loaded = function_index::detail::static_pe_active();
#endif
	runtime.target_epoch = memory_scanner::g_state.target_epoch.load(
		std::memory_order_acquire);
	runtime.process_creation_time_100ns = memory_scanner::g_state.
		observed_target_creation_time_100ns.load(std::memory_order_acquire);
	runtime.scan_static_binary = memory_scanner::g_state.scan_static_binary;
	runtime.scan_target_pid = memory_scanner::g_state.scan_target_pid;
	runtime.scan_target_epoch = memory_scanner::g_state.scan_target_epoch;
	runtime.scan_process_creation_time_100ns = memory_scanner::g_state.
		scan_target_identity.process.creation_time_100ns;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (runtime.scan_target_pid != 0 && runtime.scan_process_creation_time_100ns == 0)
		runtime.scan_process_creation_time_100ns = runtime.process_creation_time_100ns;
#endif
	runtime.scan_workspace_id = memory_scanner::g_state.scan_workspace_id;
	runtime.scan_workspace_generation = memory_scanner::g_state.scan_workspace_generation;
	const std::uint64_t count_component = static_cast<std::uint64_t>(result_count);
	runtime.scan_revision =
		(static_cast<std::uint64_t>(static_cast<std::uint32_t>(memory_scanner::g_state.scan_count)) << 32U) ^
		count_component;
	return runtime;
}

memory_interaction::runtime_t runtime_snapshot() {
	auto& state = memory_scanner::g_state;
	std::lock_guard<std::mutex> lock(state.results_mutex);
	return runtime_snapshot_locked(state.results.size());
}

std::string s_consumed_memory_action;

bool memory_context_identity_equal(const memory_interaction::context_t& left,
	const memory_interaction::context_t& right) noexcept {
	return left.kind == right.kind && left.source == right.source &&
		left.target_pid == right.target_pid && left.target_epoch == right.target_epoch &&
		left.process_creation_time_100ns == right.process_creation_time_100ns &&
		left.scan_revision == right.scan_revision && left.workspace_id == right.workspace_id &&
		left.workspace_generation == right.workspace_generation &&
		left.owner_workspace_id == right.owner_workspace_id &&
		left.owner_workspace_generation == right.owner_workspace_generation &&
		left.document_id == right.document_id &&
		left.address == right.address && left.extent == right.extent && left.index == right.index;
}

std::vector<memory_interaction::context_t> memory_action_contexts(
	const memory_interaction::context_t& focused) {
	auto contexts = memory_interaction::selected_set();
	const bool compatible = !contexts.empty() && contexts.front().kind == focused.kind &&
		contexts.front().source == focused.source &&
		contexts.front().target_pid == focused.target_pid &&
		contexts.front().target_epoch == focused.target_epoch &&
		contexts.front().process_creation_time_100ns == focused.process_creation_time_100ns &&
		contexts.front().scan_revision == focused.scan_revision &&
		contexts.front().workspace_id == focused.workspace_id &&
		contexts.front().workspace_generation == focused.workspace_generation &&
		contexts.front().owner_workspace_id == focused.owner_workspace_id &&
		contexts.front().owner_workspace_generation == focused.owner_workspace_generation &&
		contexts.front().document_id == focused.document_id;
	if (!compatible || std::none_of(contexts.begin(), contexts.end(), [&](const auto& item) {
		return memory_context_identity_equal(item, focused);
	}))
		contexts.assign(1, focused);
	return contexts;
}

std::uint64_t memory_action_set_hash(
	const std::vector<memory_interaction::context_t>& contexts) noexcept {
	std::uint64_t hash = 1469598103934665603ULL;
	const auto mix = [&](std::uint64_t value) {
		for (unsigned shift = 0; shift < 64; shift += 8) {
			hash ^= static_cast<std::uint8_t>(value >> shift);
			hash *= 1099511628211ULL;
		}
	};
	for (const auto& context : contexts) {
		mix(static_cast<std::uint64_t>(context.kind));
		mix(static_cast<std::uint64_t>(context.source));
		mix(context.target_pid);
		mix(context.target_epoch);
		mix(context.process_creation_time_100ns);
		mix(context.scan_revision);
		mix(context.workspace_generation);
		mix(context.owner_workspace_generation);
		mix(context.document_id);
		mix(context.address);
		mix(context.extent);
		mix(static_cast<std::uint64_t>(static_cast<std::int64_t>(context.index)));
		for (const char character : context.workspace_id)
			mix(static_cast<unsigned char>(character));
		for (const char character : context.owner_workspace_id)
			mix(static_cast<unsigned char>(character));
	}
	return hash;
}

std::string memory_action_entity_id(const memory_interaction::context_t& focused,
	const std::vector<memory_interaction::context_t>& contexts) {
	return std::to_string(focused.address) + ":" + std::to_string(focused.index) + ":" +
		std::to_string(contexts.size()) + ":" + std::to_string(memory_action_set_hash(contexts));
}

constexpr std::size_t kMaximumExactResultSelection = 4096;
constexpr std::size_t kMaximumExactResultBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaximumComparerValueBytes = 1024U * 1024U;
constexpr std::size_t kMaximumEvidenceExcerptBytes = 12U * 1024U;

struct exact_result_set_t {
	std::vector<memory_interaction::context_t> contexts;
	std::vector<memory_scanner::scan_result_t> results;
	memory_scanner::value_type_t value_type = memory_scanner::value_type_t::int32_val;
	memory_interaction::runtime_t runtime;
	std::size_t raw_bytes = 0;
};

bool capture_exact_result_set(
	const std::vector<memory_interaction::context_t>& contexts,
	exact_result_set_t& output, std::string& reason) {
	output = {};
	if (contexts.empty() || contexts.size() > kMaximumExactResultSelection) {
		reason = "Select between 1 and 4096 current memory results.";
		return false;
	}
	const auto first = contexts.front();
	if (first.kind != memory_interaction::kind_t::scan_result) {
		reason = "This action requires memory scan results.";
		return false;
	}
	const auto before = runtime_snapshot();
	for (const auto& context : contexts) {
		if (!memory_context_identity_equal(context, first) &&
			(context.kind != first.kind || context.source != first.source ||
			 context.target_pid != first.target_pid || context.target_epoch != first.target_epoch ||
			 context.process_creation_time_100ns != first.process_creation_time_100ns ||
			 context.scan_revision != first.scan_revision ||
			 context.workspace_id != first.workspace_id ||
			 context.workspace_generation != first.workspace_generation ||
			 context.owner_workspace_id != first.owner_workspace_id ||
			 context.owner_workspace_generation != first.owner_workspace_generation ||
			 context.document_id != first.document_id)) {
			reason = "The selected results do not share one target, scan, workspace, and document identity.";
			return false;
		}
		if (!memory_interaction::is_current(context, before)) {
			reason = "The target, scan publication, workspace, document, or selected result changed.";
			return false;
		}
	}
	auto& state = memory_scanner::g_state;
	{
		std::lock_guard<std::mutex> lock(state.results_mutex);
		output.runtime = runtime_snapshot_locked(state.results.size());
		output.value_type = state.config.value_type;
		output.contexts = contexts;
		output.results.reserve(contexts.size());
		for (const auto& context : contexts) {
			if (context.scan_revision != output.runtime.scan_revision || context.index < 0 ||
				static_cast<std::size_t>(context.index) >= state.results.size()) {
				reason = "The selected result set no longer exists in the current scan publication.";
				return false;
			}
			const auto& result = state.results[static_cast<std::size_t>(context.index)];
			const std::string current = memory_scanner::format_value(result.current_value,
				output.value_type);
			const std::string previous = memory_scanner::format_value(result.previous_value,
				output.value_type);
			if (result.address != context.address || current != context.value ||
				previous != context.previous_value) {
				reason = "A selected result changed after the context menu was opened.";
				return false;
			}
			const std::size_t added = result.current_value.size() + result.previous_value.size();
			if (added > kMaximumExactResultBytes ||
				output.raw_bytes > kMaximumExactResultBytes - added) {
				reason = "The exact selected result payload exceeds the 8 MiB safety limit.";
				return false;
			}
			output.raw_bytes += added;
			output.results.push_back(result);
		}
	}
	const auto after = runtime_snapshot();
	for (const auto& context : contexts) {
		if (!memory_interaction::is_current(context, after)) {
			reason = "The target, scan publication, workspace, or document changed while capturing results.";
			output = {};
			return false;
		}
	}
	reason.clear();
	return true;
}

std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes) {
	static constexpr char digits[] = "0123456789ABCDEF";
	std::string output;
	output.resize(bytes.size() * 2U);
	for (std::size_t index = 0; index < bytes.size(); ++index) {
		output[index * 2U] = digits[bytes[index] >> 4U];
		output[index * 2U + 1U] = digits[bytes[index] & 0x0FU];
	}
	return output;
}

std::string exact_result_source_hint(const memory_interaction::context_t& context) {
	if (context.source == memory_interaction::source_t::live_process)
		return "memory:pid:" + std::to_string(context.target_pid) + ":created:" +
			std::to_string(context.process_creation_time_100ns) + ":epoch:" +
			std::to_string(context.target_epoch) + ":scan:" +
			std::to_string(context.scan_revision) + ":owner:" + context.owner_workspace_id +
			":" + std::to_string(context.owner_workspace_generation) + ":document:" +
			std::to_string(context.document_id);
	return "memory:workspace:" + context.workspace_id + ":generation:" +
		std::to_string(context.workspace_generation) + ":scan:" +
		std::to_string(context.scan_revision) + ":owner:" + context.owner_workspace_id +
		":" + std::to_string(context.owner_workspace_generation) + ":document:" +
		std::to_string(context.document_id);
}

bool build_exact_evidence_excerpt(const exact_result_set_t& snapshot,
	std::string& excerpt, std::string& reason) {
	const auto& first = snapshot.contexts.front();
	std::ostringstream output;
	output << "Source: " << (first.source == memory_interaction::source_t::live_process
		? "live process" : "static binary")
		<< "\nPID: " << first.target_pid
		<< "\nProcess creation: " << first.process_creation_time_100ns
		<< "\nTarget epoch: " << first.target_epoch
		<< "\nScan revision: " << first.scan_revision
		<< "\nWorkspace: " << first.workspace_id
		<< "\nWorkspace generation: " << first.workspace_generation
		<< "\nOwner workspace: " << first.owner_workspace_id
		<< "\nOwner generation: " << first.owner_workspace_generation
		<< "\nDocument: " << first.document_id
		<< "\nSelected rows: " << snapshot.contexts.size();
	for (std::size_t index = 0; index < snapshot.contexts.size(); ++index) {
		const auto& context = snapshot.contexts[index];
		output << "\n[" << index + 1U << "] 0x" << std::uppercase << std::hex
			<< std::setw(16) << std::setfill('0') << context.address << std::dec
			<< " | " << context.value << " | previous=" << context.previous_value
			<< " | " << context.module_offset;
		if (output.tellp() < 0 || static_cast<std::size_t>(output.tellp()) >
			kMaximumEvidenceExcerptBytes) {
			reason = "The complete selected result evidence exceeds the 12 KiB chat limit; export it instead.";
			return false;
		}
	}
	excerpt = output.str();
	if (excerpt.empty() || excerpt.size() > kMaximumEvidenceExcerptBytes) {
		reason = "The complete selected result evidence exceeds the 12 KiB chat limit; export it instead.";
		return false;
	}
	reason.clear();
	return true;
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
bool exact_scan_publication_matches(const exact_result_set_t& snapshot) {
	if (snapshot.contexts.empty() || snapshot.results.size() != snapshot.contexts.size())
		return false;
	auto& state = memory_scanner::g_state;
	std::lock_guard<std::mutex> lock(state.results_mutex);
	const auto runtime = runtime_snapshot_locked(state.results.size());
	const auto& first = snapshot.contexts.front();
	if (runtime.scan_revision != first.scan_revision ||
		runtime.scan_static_binary != (first.source == memory_interaction::source_t::static_binary))
		return false;
	if (first.source == memory_interaction::source_t::live_process) {
		if (!runtime.live_attached || runtime.target_pid != first.target_pid ||
			runtime.target_epoch != first.target_epoch ||
			runtime.process_creation_time_100ns != first.process_creation_time_100ns ||
			runtime.scan_target_pid != first.target_pid ||
			runtime.scan_target_epoch != first.target_epoch ||
			runtime.scan_process_creation_time_100ns != first.process_creation_time_100ns)
			return false;
	} else if (!runtime.static_loaded || runtime.scan_workspace_id != first.workspace_id ||
		runtime.scan_workspace_generation != first.workspace_generation) {
		return false;
	}
	for (std::size_t index = 0; index < snapshot.contexts.size(); ++index) {
		const auto& context = snapshot.contexts[index];
		if (context.index < 0 || static_cast<std::size_t>(context.index) >= state.results.size())
			return false;
		const auto& current = state.results[static_cast<std::size_t>(context.index)];
		const auto& captured = snapshot.results[index];
		if (current.address != context.address || current.address != captured.address ||
			current.current_value != captured.current_value ||
			current.previous_value != captured.previous_value ||
			current.module_name != captured.module_name ||
			current.module_offset != captured.module_offset)
			return false;
	}
	return true;
}
#endif

aida::ui::capability_state_t exact_result_action_capability(
	const std::vector<memory_interaction::context_t>& contexts,
	bool require_pair, bool require_chat_fit = false) {
	exact_result_set_t snapshot;
	std::string reason;
	if (!capture_exact_result_set(contexts, snapshot, reason))
		return aida::ui::capability_state_t::unavailable(reason);
	if (require_pair && snapshot.results.size() != 2U)
		return aida::ui::capability_state_t::unavailable(
			"Select exactly two current scan results to compare.");
	if (require_pair && (snapshot.results[0].current_value.empty() ||
		snapshot.results[1].current_value.empty()))
		return aida::ui::capability_state_t::unavailable(
			"Both selected results must contain current bytes.");
	if (require_pair && (snapshot.results[0].current_value.size() > kMaximumComparerValueBytes ||
		snapshot.results[1].current_value.size() > kMaximumComparerValueBytes))
		return aida::ui::capability_state_t::unavailable(
			"A selected value exceeds the 1 MiB comparer slot limit.");
	if (require_chat_fit) {
		std::string excerpt;
		if (!build_exact_evidence_excerpt(snapshot, excerpt, reason))
			return aida::ui::capability_state_t::unavailable(reason);
	}
	return aida::ui::capability_state_t::available();
}

aida::ui::action_handler_result_t compare_exact_results(
	const std::vector<memory_interaction::context_t>& contexts) {
	exact_result_set_t snapshot;
	std::string reason;
	if (!capture_exact_result_set(contexts, snapshot, reason))
		return aida::ui::action_handler_result_t::failed(reason);
	if (snapshot.results.size() != 2U)
		return aida::ui::action_handler_result_t::failed(
			"Select exactly two current scan results to compare.");
	for (const auto& result : snapshot.results) {
		if (result.current_value.empty() || result.current_value.size() > kMaximumComparerValueBytes)
			return aida::ui::action_handler_result_t::failed(
				"Each comparer value must contain between 1 byte and 1 MiB.");
	}
	for (std::size_t index = 0; index < snapshot.results.size(); ++index) {
		char label[64]{};
		std::snprintf(label, sizeof(label), "Memory 0x%016llX current",
			static_cast<unsigned long long>(snapshot.results[index].address));
		if (aida::burp::comparer::add_slot_from_bytes(label,
			snapshot.results[index].current_value,
			exact_result_source_hint(snapshot.contexts[index])) == 0)
			return aida::ui::action_handler_result_t::failed(
				aida::burp::comparer::last_error().empty()
					? "The comparer rejected a selected memory value."
					: aida::burp::comparer::last_error());
	}
	const auto opened = aida::ui::application_views::open_or_focus(
		aida::ui::stable_view_id_t("view.network.comparer"));
	return opened.ok() ? aida::ui::action_handler_result_t::completed()
		: aida::ui::action_handler_result_t::failed(opened.detail);
}

bool serialize_exact_results(const exact_result_set_t& snapshot,
	std::string& payload, std::string& reason) {
	try {
		const auto& first = snapshot.contexts.front();
		nlohmann::json root;
		root["schema"] = "aida.memory.selected-results.v1";
		root["source"] = first.source == memory_interaction::source_t::live_process
			? "live_process" : "static_binary";
		root["target_pid"] = first.target_pid;
		root["target_epoch"] = first.target_epoch;
		root["process_creation_time_100ns"] = first.process_creation_time_100ns;
		root["scan_revision"] = first.scan_revision;
		root["scan_workspace_id"] = first.workspace_id;
		root["scan_workspace_generation"] = first.workspace_generation;
		root["owner_workspace_id"] = first.owner_workspace_id;
		root["owner_workspace_generation"] = first.owner_workspace_generation;
		root["document_id"] = first.document_id;
		root["value_type"] = memory_scanner::value_type_name(snapshot.value_type);
		root["selected_count"] = snapshot.results.size();
		root["results"] = nlohmann::json::array();
		for (std::size_t index = 0; index < snapshot.results.size(); ++index) {
			const auto& context = snapshot.contexts[index];
			const auto& result = snapshot.results[index];
			root["results"].push_back({
				{"selection_index", context.index},
				{"address", result.address},
				{"address_hex", [&] { char value[24]{}; std::snprintf(value, sizeof(value),
					"0x%016llX", static_cast<unsigned long long>(result.address)); return std::string(value); }()},
				{"current_display", context.value},
				{"previous_display", context.previous_value},
				{"current_bytes_hex", bytes_to_hex(result.current_value)},
				{"previous_bytes_hex", bytes_to_hex(result.previous_value)},
				{"module_name", result.module_name},
				{"module_offset", result.module_offset},
				{"module_offset_display", context.module_offset}
			});
		}
		payload = root.dump(2);
	} catch (const std::exception& error) {
		reason = std::string("Exact memory result serialization failed: ") + error.what();
		return false;
	}
	if (payload.empty() || payload.size() > kMaximumExactResultBytes) {
		reason = "The serialized exact result set exceeds the 8 MiB export limit.";
		payload.clear();
		return false;
	}
	reason.clear();
	return true;
}

aida::ui::action_handler_result_t export_exact_results(
	const std::vector<memory_interaction::context_t>& contexts) {
	exact_result_set_t snapshot;
	std::string reason;
	if (!capture_exact_result_set(contexts, snapshot, reason))
		return aida::ui::action_handler_result_t::failed(reason);
	std::string payload;
	if (!serialize_exact_results(snapshot, payload, reason))
		return aida::ui::action_handler_result_t::failed(reason);
	char path[4096] = "aida-memory-selected-results.json";
	static const char filter[] = "JSON (*.json)\0*.json\0All files (*.*)\0*.*\0\0";
	if (!win32_dialog::show_save_file_dialog(g_hwnd, "Export selected memory results",
		filter, "json", path, sizeof(path), "memory_scanner::export_selected"))
		return aida::ui::action_handler_result_t::completed();
	if (!capture_exact_result_set(contexts, snapshot, reason) ||
		!serialize_exact_results(snapshot, payload, reason))
		return aida::ui::action_handler_result_t::failed(reason);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::scan::record("memory.results.export_selected",
		std::to_string(snapshot.results.size()) + ":" +
		std::to_string(memory_action_set_hash(snapshot.contexts)));
	return aida::ui::action_handler_result_t::completed();
#else
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	auto commit_gate = std::make_shared<std::atomic<std::uint8_t>>(
		scanner_async_io::operation_reversible);
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "scanner.memory";
	submission.label = "scanner.memory.export_selected";
	submission.thread_class = "bounded_task";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 3;
	submission.target_pid = snapshot.contexts.front().target_pid;
	submission.generation = snapshot.contexts.front().scan_revision;
	submission.cancel_hook = [cancellation, commit_gate] {
		std::uint8_t expected = scanner_async_io::operation_reversible;
		if (commit_gate->compare_exchange_strong(expected,
			scanner_async_io::operation_cancelled, std::memory_order_acq_rel,
			std::memory_order_acquire))
			cancellation->store(true, std::memory_order_release);
	};
	submission.body = [snapshot = std::move(snapshot), payload = std::move(payload),
		destination = std::string(path), cancellation, commit_gate]() mutable {
		const auto result = scanner_async_io::atomic_replace(destination, payload, false,
			cancellation, [&snapshot] { return exact_scan_publication_matches(snapshot); },
			commit_gate);
		if (!result.success)
			throw std::runtime_error(result.error.empty()
				? "Selected memory result export did not commit." : result.error);
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted)
		return aida::ui::action_handler_result_t::failed(
			submitted.reject_reason.empty() ? "The memory export worker rejected the operation."
				: submitted.reject_reason);
	scanner_task_center::register_executor_task(submitted, "view.memory.value_scan",
		"memory.result.export_selected", "Export selected memory results",
		contexts.front().target_pid, true, [cancellation, commit_gate] {
			std::uint8_t expected = scanner_async_io::operation_reversible;
			if (commit_gate->compare_exchange_strong(expected,
				scanner_async_io::operation_cancelled, std::memory_order_acq_rel,
				std::memory_order_acquire))
				cancellation->store(true, std::memory_order_release);
			return true;
		});
	return aida::ui::action_handler_result_t::completed();
#endif
}

bool memory_action_is_explicit_batch(memory_interaction::capability_t capability) noexcept {
	switch (capability) {
		case memory_interaction::capability_t::copy_address:
		case memory_interaction::capability_t::copy_value:
		case memory_interaction::capability_t::copy_previous_value:
		case memory_interaction::capability_t::copy_module_offset:
		case memory_interaction::capability_t::add_to_address_list:
		case memory_interaction::capability_t::remove:
		case memory_interaction::capability_t::compare_selected:
		case memory_interaction::capability_t::export_selected:
			return true;
		default:
			return false;
	}
}

const char* memory_action_id(const char* label) {
	if (std::strcmp(label, "Add to address list") == 0) return "memory.result.add_address";
	if (std::strcmp(label, "Open in Hex view") == 0) return "memory.entity.open_hex";
	if (std::strcmp(label, "Open in Disassembly") == 0) return "memory.entity.open_disassembly";
	if (std::strcmp(label, "Copy address") == 0) return "memory.entity.copy_address";
	if (std::strcmp(label, "Copy current value") == 0) return "memory.entity.copy_value";
	if (std::strcmp(label, "Copy previous value") == 0) return "memory.entity.copy_previous";
	if (std::strcmp(label, "Copy module + offset") == 0) return "memory.entity.copy_module_offset";
	if (std::strcmp(label, "Stage patch in Patches view...") == 0) return "memory.entity.stage_patch";
	if (std::strcmp(label, "Edit description") == 0) return "memory.address.edit_description";
	if (std::strcmp(label, "Change type") == 0) return "memory.address.change_type";
	if (std::strcmp(label, "Change value...") == 0) return "memory.address.change_value";
	if (std::strcmp(label, "Freeze") == 0) return "memory.address.freeze";
	if (std::strcmp(label, "Unfreeze") == 0) return "memory.address.unfreeze";
	if (std::strcmp(label, "Remove from address list") == 0) return "memory.address.remove";
	return "";
}

bool context_item(const char* label,
	memory_interaction::capability_t capability,
	const memory_interaction::context_t& context,
	const memory_interaction::runtime_t& runtime,
	const char* = nullptr) {
	const auto evaluated = memory_interaction::evaluate(capability, context, runtime);
	return evaluated.enabled && s_consumed_memory_action == memory_action_id(label);
}

aida::ui::context_menu_open_origin_t retained_origin(int value) {
	return value == 1 ? aida::ui::context_menu_open_origin_t::menu_key
		: value == 2 ? aida::ui::context_menu_open_origin_t::shift_f10
		: aida::ui::context_menu_open_origin_t::pointer;
}

aida::ui::application_ui::retained_entity_context_t make_memory_actions(const char* owner,
	const memory_interaction::context_t& context,
	const memory_interaction::runtime_t& runtime,
	std::initializer_list<std::pair<const char*, memory_interaction::capability_t>> actions) {
	aida::ui::application_ui::retained_entity_context_t retained;
	const auto action_contexts = memory_action_contexts(context);
	const bool multiple = action_contexts.size() > 1;
	retained.owner_id = owner;
	retained.entity_id = memory_action_entity_id(context, action_contexts);
	retained.entity_generation = context.scan_revision;
	const std::string source_view = std::strcmp(owner, "memory.value_scan.result") == 0
		? s_retained_result_owner_view : std::strcmp(owner, "memory.value_scan.address") == 0
		? s_retained_address_owner_view : std::string("view.memory.value_scan");
	retained.active_view = aida::ui::stable_view_id_t(source_view);
	const auto workspace_generation = context.workspace_generation;
	const std::string static_workspace_id = context.workspace_id;
	retained.validate_identity = [action_contexts, workspace_generation, static_workspace_id]() {
		if (!action_contexts.empty() &&
			action_contexts.front().kind == memory_interaction::kind_t::scan_result) {
			exact_result_set_t exact;
			std::string reason;
			if (!capture_exact_result_set(action_contexts, exact, reason))
				return aida::ui::capability_state_t::unavailable(reason);
			return aida::ui::capability_state_t::available();
		}
		const auto current_runtime = runtime_snapshot();
		for (const auto& item : action_contexts) {
			if (!memory_interaction::is_current(item, current_runtime))
				return aida::ui::capability_state_t::unavailable(
					"The target, scan publication, or selected memory entity changed.");
		}
		if (!action_contexts.empty() &&
			action_contexts.front().source == memory_interaction::source_t::static_binary) {
			const auto current_workspace = disasm_view::capture_selected_workspace();
			if (!current_workspace.workspace ||
				current_workspace.workspace->generation() != workspace_generation ||
				current_workspace.workspace->identity().binary_id().to_hex() != static_workspace_id)
				return aida::ui::capability_state_t::unavailable(
					"The static analysis workspace changed; select the memory entity again.");
		}
		return aida::ui::capability_state_t::available();
	};
	for (const auto& [id, capability] : actions) {
		aida::ui::capability_state_t state;
		if (capability == memory_interaction::capability_t::compare_selected) {
			state = exact_result_action_capability(action_contexts, true);
		} else if (capability == memory_interaction::capability_t::export_selected) {
			state = exact_result_action_capability(action_contexts, false);
		} else if (multiple && !memory_action_is_explicit_batch(capability)) {
			state = aida::ui::capability_state_t::unavailable(
				"This action requires exactly one memory row.");
		} else {
			const bool copy_batch = capability == memory_interaction::capability_t::copy_address ||
				capability == memory_interaction::capability_t::copy_value ||
				capability == memory_interaction::capability_t::copy_previous_value ||
				capability == memory_interaction::capability_t::copy_module_offset;
			bool enabled = !copy_batch;
			const char* reason = nullptr;
			for (const auto& item : action_contexts) {
				const auto evaluated = memory_interaction::evaluate(capability, item, runtime);
				if (copy_batch) {
					enabled = enabled || evaluated.enabled;
					if (!reason && !evaluated.enabled) reason = evaluated.disabled_reason;
				} else if (!evaluated.enabled) {
					enabled = false;
					reason = evaluated.disabled_reason;
					break;
				}
			}
			state = enabled ? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(
					reason ? reason : "The memory action is unavailable.");
		}
		if (capability == memory_interaction::capability_t::compare_selected)
			retained.actions.push_back({id, std::move(state), [action_contexts] {
				return compare_exact_results(action_contexts);
			}});
		else if (capability == memory_interaction::capability_t::export_selected)
			retained.actions.push_back({id, std::move(state), [action_contexts] {
				return export_exact_results(action_contexts);
			}});
		else
			retained.actions.push_back({id, std::move(state),
				[]() { return aida::ui::action_handler_result_t::completed(); }});
	}
	if (std::strcmp(owner, "memory.value_scan.address") == 0 &&
		action_contexts.size() == 1U) {
		std::optional<memory_scanner::address_entry_t> retained_entry;
		const int retained_index = context.index;
		{
			std::lock_guard<std::mutex> lock(memory_scanner::g_state.address_mutex);
			if (retained_index >= 0 &&
				retained_index < static_cast<int>(memory_scanner::g_state.address_list.size())) {
				const auto& entry = memory_scanner::g_state.address_list[
					static_cast<std::size_t>(retained_index)];
				if (entry.address == context.address && entry.target_pid == context.target_pid &&
					entry.target_epoch == context.target_epoch &&
					entry.target_identity.process.creation_time_100ns ==
						context.process_creation_time_100ns && entry.frozen == context.frozen)
					retained_entry = entry;
			}
		}
		for (auto& action : retained.actions) {
			const bool unfreeze = action.action_id == "memory.address.unfreeze";
			if (!unfreeze && action.action_id != "memory.address.freeze")
				continue;
			if (!retained_entry)
				action.capability = aida::ui::capability_state_t::unavailable(
					"The exact Address List entry changed before the context menu opened.");
			else if (!unfreeze && retained_entry->last_value.empty())
				action.capability = aida::ui::capability_state_t::unavailable(
					"Freeze requires a current captured value for the retained Address List entry.");
			action.invoke = [context, retained_entry, retained_index, unfreeze] {
				if (!retained_entry || retained_index < 0)
					return aida::ui::action_handler_result_t::failed(
						"The retained Address List entry is unavailable.");
				const auto current_runtime = runtime_snapshot();
				if (!memory_interaction::is_current(context, current_runtime) ||
					!memory_scanner::validate_target_binding(context.target_pid,
						context.target_epoch, context.process_creation_time_100ns))
					return aida::ui::action_handler_result_t::failed(
						"The retained Address List entry or target identity changed.");
				if (!memory_scanner::freeze_address_exact(
						static_cast<std::size_t>(retained_index), !unfreeze, *retained_entry))
					return aida::ui::action_handler_result_t::failed(
						"The exact freeze-state transition was rejected or could not be verified.");
				return aida::ui::action_handler_result_t::completed();
			};
		}
	}
	const bool direct_memory_row = std::strcmp(owner, "memory.value_scan.result") == 0 ||
		std::strcmp(owner, "memory.value_scan.address") == 0;
	if (direct_memory_row) {
		const bool single = action_contexts.size() == 1U;
		const auto exact_gate = [&]() {
			if (!single)
				return aida::ui::capability_state_t::unavailable(
					"This workflow requires exactly one retained memory row.");
			const auto current_runtime = runtime_snapshot();
			if (!memory_interaction::is_current(context, current_runtime))
				return aida::ui::capability_state_t::unavailable(
					"The target, scan publication, workspace, or retained memory row changed.");
			return aida::ui::capability_state_t::available();
		};
		const auto pointer_gate = exact_gate();
		const bool pointer_live = context.source == memory_interaction::source_t::live_process;
		retained.actions.push_back({"memory.entity.pointer_workflow",
			pointer_gate.enabled && pointer_live
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(pointer_gate.enabled
					? "Pointer scanning requires a retained live-process row."
					: pointer_gate.disabled_reason),
			[context, source_view] {
				const auto opened = aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.memory.pointers"));
				if (!opened.ok()) return aida::ui::action_handler_result_t::failed(opened.detail);
				const auto current_runtime = runtime_snapshot();
				if (!memory_interaction::is_current(context, current_runtime))
					return aida::ui::action_handler_result_t::failed(
						"The retained memory row or target identity changed.");
				pointer_scanner_view::staged_target_context_t staged;
				staged.address = context.address;
				staged.target_pid = context.target_pid;
				staged.target_epoch = context.target_epoch;
				staged.process_creation_time_100ns = context.process_creation_time_100ns;
				staged.source_generation = context.kind == memory_interaction::kind_t::scan_result
					? context.scan_revision : context.target_epoch;
				staged.source_view = source_view;
				staged.source_identity = memory_action_entity_id(context, {context});
				staged.validate = [context](std::string& reason) {
					const auto current = runtime_snapshot();
					const bool valid = memory_interaction::is_current(context, current) &&
						memory_scanner::validate_target_binding(context.target_pid,
							context.target_epoch, context.process_creation_time_100ns);
					if (!valid) reason = "The retained memory row, target epoch, or process identity changed.";
					return valid;
				};
				std::string error;
				if (!pointer_scanner_view::stage_target_context(std::move(staged), error))
					return aida::ui::action_handler_result_t::failed(error);
				return aida::ui::action_handler_result_t::completed();
			}});
		const auto structure_gate = exact_gate();
		retained.actions.push_back({"memory.entity.interpret_structure", structure_gate,
			[context, source_view] {
				const auto opened = aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.types.structures"));
				if (!opened.ok()) return aida::ui::action_handler_result_t::failed(opened.detail);
				const auto current_runtime = runtime_snapshot();
				if (!memory_interaction::is_current(context, current_runtime))
					return aida::ui::action_handler_result_t::failed(
						"The retained memory row or source identity changed.");
				struct_dissector_view::staged_target_context_t staged;
				staged.address = context.address;
				staged.target_pid = context.target_pid;
				staged.target_epoch = context.target_epoch;
				staged.process_creation_time_100ns = context.process_creation_time_100ns;
				staged.source_generation = context.kind == memory_interaction::kind_t::scan_result
					? context.scan_revision : context.source == memory_interaction::source_t::live_process
					? context.target_epoch : context.workspace_generation;
				staged.live_process = context.source == memory_interaction::source_t::live_process;
				staged.source_view = source_view;
				staged.source_identity = memory_action_entity_id(context, {context});
				staged.validate = [context](std::string& reason) {
					const auto current = runtime_snapshot();
					if (!memory_interaction::is_current(context, current)) {
						reason = "The retained memory row, scan, target, or workspace identity changed.";
						return false;
					}
					if (context.source == memory_interaction::source_t::live_process &&
						!memory_scanner::validate_target_binding(context.target_pid,
							context.target_epoch, context.process_creation_time_100ns)) {
						reason = "The retained live-process identity changed.";
						return false;
					}
					return true;
				};
				std::string error;
				if (!struct_dissector_view::stage_target_context(std::move(staged), error))
					return aida::ui::action_handler_result_t::failed(error);
				return aida::ui::action_handler_result_t::completed();
			}});
		if (std::strcmp(owner, "memory.value_scan.result") == 0) {
			std::optional<memory_scanner::address_entry_t> retained_entry;
			int retained_index = -1;
			if (single && context.source == memory_interaction::source_t::live_process) {
				std::lock_guard<std::mutex> lock(memory_scanner::g_state.address_mutex);
				for (std::size_t index = 0; index < memory_scanner::g_state.address_list.size(); ++index) {
					const auto& entry = memory_scanner::g_state.address_list[index];
					if (entry.address == context.address && entry.target_pid == context.target_pid &&
						entry.target_epoch == context.target_epoch &&
						entry.target_identity.process.creation_time_100ns ==
							context.process_creation_time_100ns) {
						retained_entry = entry;
						retained_index = static_cast<int>(index);
						break;
					}
				}
			}
			const bool unfreeze = retained_entry && retained_entry->frozen;
			const char* action_id = unfreeze ? "memory.result.unfreeze" : "memory.result.freeze";
			const auto freeze_state = !single
				? aida::ui::capability_state_t::unavailable(
					"Freeze requires exactly one retained scan result.")
				: context.source != memory_interaction::source_t::live_process
				? aida::ui::capability_state_t::unavailable(
					"Static scan results cannot be frozen.")
				: !retained_entry
				? aida::ui::capability_state_t::unavailable(
					"Add this result to the Address List before freezing it.")
				: aida::ui::capability_state_t::available();
			retained.actions.push_back({action_id, freeze_state,
				[context, retained_entry, retained_index, unfreeze] {
					if (!retained_entry || retained_index < 0)
						return aida::ui::action_handler_result_t::failed(
							"The retained Address List entry is unavailable.");
					const auto runtime = runtime_snapshot();
					if (!memory_interaction::is_current(context, runtime) ||
						!memory_scanner::validate_target_binding(context.target_pid,
							context.target_epoch, context.process_creation_time_100ns))
						return aida::ui::action_handler_result_t::failed(
							"The retained scan result or target identity changed.");
					int current_index = -1;
					{
						std::lock_guard<std::mutex> lock(memory_scanner::g_state.address_mutex);
						for (std::size_t index = 0; index < memory_scanner::g_state.address_list.size(); ++index) {
							const auto& entry = memory_scanner::g_state.address_list[index];
							if (entry.address == retained_entry->address &&
								entry.value_type == retained_entry->value_type &&
								entry.target_pid == retained_entry->target_pid &&
								entry.target_epoch == retained_entry->target_epoch &&
								entry.target_identity.process.creation_time_100ns ==
									retained_entry->target_identity.process.creation_time_100ns &&
								entry.description == retained_entry->description &&
								entry.last_value == retained_entry->last_value &&
								entry.frozen == retained_entry->frozen) {
								current_index = static_cast<int>(index);
								break;
							}
						}
					}
					if (current_index < 0)
						return aida::ui::action_handler_result_t::failed(
							"The exact Address List entry changed after the context menu opened.");
					if (!memory_scanner::freeze_address_exact(
							static_cast<std::size_t>(current_index), !unfreeze, *retained_entry))
						return aida::ui::action_handler_result_t::failed(
							"The exact freeze-state transition was rejected or could not be verified.");
					return aida::ui::action_handler_result_t::completed();
				}});
		}
	}
	const char* source_kind = context.kind == memory_interaction::kind_t::scan_result
		? "memory_scan_result" : context.kind == memory_interaction::kind_t::address_entry
		? "memory_address_entry" : "memory_entity";
	char address[24]{};
	std::snprintf(address, sizeof(address), "0x%016llX",
		static_cast<unsigned long long>(context.address));
	aida::automation_ui::entity_evidence::snapshot_t evidence;
	evidence.workspace_id = context.source == memory_interaction::source_t::live_process
		? "pid:" + std::to_string(context.target_pid) + ":created:" +
			std::to_string(context.process_creation_time_100ns) : static_workspace_id;
	evidence.source_view_id = "view.memory.value_scan";
	evidence.source_kind = source_kind;
	evidence.entity_id = retained.entity_id;
	evidence.display_label = multiple ? std::to_string(action_contexts.size()) +
		" selected memory rows" : std::string(source_kind) + " " + address;
	aida::ui::capability_state_t evidence_capability;
	if (context.kind == memory_interaction::kind_t::scan_result) {
		exact_result_set_t exact;
		std::string evidence_reason;
		if (!capture_exact_result_set(action_contexts, exact, evidence_reason) ||
			!build_exact_evidence_excerpt(exact, evidence.excerpt, evidence_reason))
			evidence_capability = aida::ui::capability_state_t::unavailable(evidence_reason);
		else
			evidence_capability = aida::ui::capability_state_t::available();
	} else {
		evidence.excerpt = "Source: " + std::string(context.source == memory_interaction::source_t::live_process
			? "live process" : "static binary") + "\nPID: " + std::to_string(context.target_pid) +
			"\nProcess creation: " + std::to_string(context.process_creation_time_100ns) +
			"\nTarget epoch: " + std::to_string(context.target_epoch) +
			"\nScan revision: " + std::to_string(context.scan_revision) +
			"\nSelected rows: " + std::to_string(action_contexts.size());
		for (std::size_t index = 0; index < action_contexts.size(); ++index) {
			const auto& item = action_contexts[index];
			char item_address[24]{};
			std::snprintf(item_address, sizeof(item_address), "0x%016llX",
				static_cast<unsigned long long>(item.address));
			evidence.excerpt += "\n[" + std::to_string(index + 1) + "] " + item_address +
				" | " + item.value + " | previous=" + item.previous_value +
				" | " + item.module_offset;
		}
		evidence_capability = context.kind != memory_interaction::kind_t::none && context.address != 0
			? aida::ui::capability_state_t::available()
			: aida::ui::capability_state_t::unavailable(
				"A current retained memory entity with a resolved address is required for evidence handoff.");
	}
	evidence.address = context.address;
	evidence.revision = context.scan_revision;
	evidence.generation = context.scan_revision;
	evidence.sensitive = context.source == memory_interaction::source_t::live_process;
	evidence.return_to_source = [context, action_contexts, workspace_generation,
		static_workspace_id](std::string& reason) {
		const auto current_runtime = runtime_snapshot();
		for (const auto& item : action_contexts) {
			if (!memory_interaction::is_current(item, current_runtime)) {
				reason = "The target, scan publication, or retained memory entity changed; capture it again.";
				return false;
			}
		}
		if (context.source == memory_interaction::source_t::static_binary) {
			const auto current_workspace = disasm_view::capture_selected_workspace();
			if (!current_workspace.workspace ||
				current_workspace.workspace->generation() != workspace_generation ||
				current_workspace.workspace->identity().binary_id().to_hex() != static_workspace_id) {
				reason = "The static analysis workspace changed; capture the memory entity again.";
				return false;
			}
		}
		memory_interaction::select_set(action_contexts, context);
		const auto opened = aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.memory.value_scan"));
		if (!opened.ok()) {
			reason = opened.detail;
			return false;
		}
		reason.clear();
		return true;
	};
	aida::automation_ui::entity_evidence::append_actions(retained, std::move(evidence),
		std::move(evidence_capability));
	return retained;
}

void open_memory_actions(const char* owner,
	const memory_interaction::context_t& context,
	const memory_interaction::runtime_t& runtime,
	std::initializer_list<std::pair<const char*, memory_interaction::capability_t>> actions,
	aida::ui::context_menu_open_origin_t origin) {
	aida::ui::application_ui::open_retained_entity_context_menu(
		make_memory_actions(owner, context, runtime, actions), origin);
}

void copy_memory_addresses(const std::vector<memory_interaction::context_t>& contexts) {
	std::ostringstream output;
	output << std::uppercase << std::hex << std::setfill('0');
	for (std::size_t index = 0; index < contexts.size(); ++index) {
		if (index != 0) output << '\n';
		output << "0x" << std::setw(16) << contexts[index].address;
	}
	ImGui::SetClipboardText(output.str().c_str());
}

template <typename Accessor>
void copy_memory_text(const std::vector<memory_interaction::context_t>& contexts,
	Accessor&& accessor) {
	std::string output;
	for (const auto& context : contexts) {
		const auto& value = accessor(context);
		if (value.empty()) continue;
		if (!output.empty()) output.push_back('\n');
		output.append(value);
	}
	ImGui::SetClipboardText(output.c_str());
}

int find_address_index(const memory_interaction::context_t& context) {
	auto& state = memory_scanner::g_state;
	std::lock_guard<std::mutex> lock(state.address_mutex);
	for (std::size_t index = 0; index < state.address_list.size(); ++index) {
		const auto& entry = state.address_list[index];
		if (entry.address == context.address && entry.target_pid == context.target_pid &&
			entry.target_epoch == context.target_epoch &&
			entry.target_identity.process.creation_time_100ns ==
				context.process_creation_time_100ns)
			return static_cast<int>(index);
	}
	return -1;
}

void interactive_scrollbar(scrollbar_state_t& sb,
                           ImDrawList* dl,
                           float ox, float oy, float w, float h,
                           float content_h, float visible_h,
                           float alpha)
{
	if (content_h <= visible_h) {
		sb.dragging = false;
		sb.track_pressed = false;
		return;
	}
	const auto& t = aida::ui::resolved();
	float ratio = visible_h / content_h;
	float thumb_h = std::max(h * ratio, 24.f);
	float track_range = std::max(0.f, h - thumb_h);
	float max_scroll = std::max(0.f, content_h - visible_h);

	if (sb.scroll_y < 0.f) sb.scroll_y = 0.f;
	if (sb.scroll_y > max_scroll) sb.scroll_y = max_scroll;
	if (sb.target_scroll_y < 0.f) sb.target_scroll_y = 0.f;
	if (sb.target_scroll_y > max_scroll) sb.target_scroll_y = max_scroll;

	float scroll_ratio = (max_scroll > 0.f) ? (sb.scroll_y / max_scroll) : 0.f;
	float thumb_y = oy + track_range * scroll_ratio;

	ImVec2 track_min(ox, oy);
	ImVec2 track_max(ox + w, oy + h);
	bool track_hover = ImGui::IsMouseHoveringRect(track_min, track_max, false);
	ImVec2 thumb_min(ox + 3.f, thumb_y);
	ImVec2 thumb_max(ox + w - 3.f, thumb_y + thumb_h);
	bool thumb_hover = ImGui::IsMouseHoveringRect(thumb_min, thumb_max, false);

	float dt = aida::ui::clock::dt();
	float hover_target = (thumb_hover || sb.dragging) ? 1.f : (track_hover ? 0.55f : 0.f);
	sb.hover_anim = ui_anim::smooth_lerp(sb.hover_anim, hover_target, 14.f, dt);
	float press_target = sb.dragging ? 1.f : 0.f;
	sb.press_anim = ui_anim::smooth_lerp(sb.press_anim, press_target, 16.f, dt);

	ImU32 track_bg_idle = aida::ui::with_alpha(t.bg_overlay, 0.18f * alpha);
	ImU32 track_bg_hov  = aida::ui::with_alpha(t.bg_overlay, 0.34f * alpha);
	ImU32 track_bg = aida::ui::mix(track_bg_idle, track_bg_hov, sb.hover_anim);
	dl->AddRectFilled(track_min, track_max, track_bg, w * 0.5f);
	dl->AddRect(track_min, track_max,
		aida::ui::with_alpha(t.border_subtle, 0.55f * alpha), w * 0.5f, 0, 1.f);

	if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
		sb.dragging = false;
		sb.track_pressed = false;
	}

	bool gated = ui_input_gate::popup_blocks_background_input();

	if (!gated && track_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !sb.dragging) {
		if (thumb_hover) {
			sb.dragging = true;
			sb.drag_offset = ImGui::GetMousePos().y - thumb_y;
			diag_logf("scrollbar drag_begin track_y=%.1f thumb_y=%.1f offset=%.1f",
				oy, thumb_y, sb.drag_offset);
		} else {
			sb.track_pressed = true;
			float my = ImGui::GetMousePos().y;
			float page = visible_h * 0.85f;
			float new_scroll = sb.target_scroll_y;
			if (my < thumb_y) new_scroll -= page;
			else new_scroll += page;
			new_scroll = std::clamp(new_scroll, 0.f, max_scroll);
			sb.target_scroll_y = new_scroll;
			diag_logf("scrollbar track_page click_y=%.1f page=%.1f new_target=%.1f",
				my, page, new_scroll);
		}
	}

	if (sb.dragging) {
		float ny = ImGui::GetMousePos().y - sb.drag_offset;
		float r = (track_range > 0.f) ? ((ny - oy) / track_range) : 0.f;
		r = std::clamp(r, 0.f, 1.f);
		sb.scroll_y = r * max_scroll;
		sb.target_scroll_y = sb.scroll_y;
	}

	ImU32 thumb_idle = aida::ui::with_alpha(t.text_dim, 0.42f * alpha);
	ImU32 thumb_hov  = aida::ui::with_alpha(t.accent_u32, 0.78f * alpha);
	ImU32 thumb_drag = aida::ui::with_alpha(t.accent_u32, 0.95f * alpha);
	ImU32 thumb_col = aida::ui::mix(thumb_idle, thumb_hov, sb.hover_anim);
	thumb_col = aida::ui::mix(thumb_col, thumb_drag, sb.press_anim);
	float thumb_radius = (thumb_max.x - thumb_min.x) * 0.5f;
	dl->AddRectFilled(thumb_min, thumb_max, thumb_col, thumb_radius);
	if (sb.hover_anim > 0.04f) {
		dl->AddRect(thumb_min, thumb_max,
			aida::ui::with_alpha(t.accent_hover, 0.45f * sb.hover_anim * alpha),
			thumb_radius, 0, 1.f);
	}
}

void refresh_region_cache_locked(region_cache_t& c) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::vector<region_cache_entry_t> out{
		{0x00007FF7A4C00000ULL, 0x00007FF7A4C36000ULL, 0x1000, 0x20, 0x1000000},
		{0x00007FF7A4C36000ULL, 0x00007FF7A4C7A000ULL, 0x1000, 0x04, 0x1000000},
		{0x000001D42A800000ULL, 0x000001D42AA00000ULL, 0x1000, 0x04, 0x20000}
	};
#else
	auto regs = driver_bridge::enumerate_memory_regions(kRegionRefreshChunk);
	std::vector<region_cache_entry_t> out;
	out.reserve(regs.size());
	for (const auto& r : regs) {
		region_cache_entry_t e;
		e.base = r.base;
		e.end  = r.base + r.size;
		e.state = r.state;
		e.protect = r.protect;
		e.type = r.type;
		out.push_back(e);
	}
	std::sort(out.begin(), out.end(),
		[](const region_cache_entry_t& a, const region_cache_entry_t& b) {
			return a.base < b.base;
		});
#endif
	std::lock_guard<std::mutex> lk(c.mtx);
	c.entries = std::move(out);
	c.generation += 1;
	c.refreshing = false;
}

void request_region_refresh() {
	auto& c = g_ui.region_cache;
	{
		std::lock_guard<std::mutex> lk(c.mtx);
		if (c.refreshing) return;
		c.refreshing = true;
	}
	diag_log("region_cache refresh_post");
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	refresh_region_cache_locked(g_ui.region_cache);
#else
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "scanner";
	sub.label = "scanner.region_cache_refresh";
	sub.thread_class = "scanner_ui_refresh";
	sub.domain = aida::infra::executor::domain_t::diagnostics;
	sub.priority = 4;
	sub.target_pid = driver_bridge::attached_pid();
	sub.body = []() {
		refresh_region_cache_locked(g_ui.region_cache);
		diag::log_tagged("value_scan", "region_cache refresh_done");
	};
	bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
	if (!posted) {
		std::lock_guard<std::mutex> lk(c.mtx);
		c.refreshing = false;
		diag_log("region_cache refresh_post_failed");
	}
#endif
}

void rebuild_sorted_indices(int total) {
	auto& ui = g_ui;
	auto& sc = memory_scanner::g_state;
	if (sc.persisted_config_loaded.exchange(false, std::memory_order_acq_rel)) {
		std::lock_guard<std::mutex> lock(sc.results_mutex);
		std::strncpy(ui.value_buf, sc.config.value_text.c_str(), sizeof(ui.value_buf) - 1);
		ui.value_buf[sizeof(ui.value_buf) - 1] = '\0';
		std::strncpy(ui.value_buf2, sc.config.value_text2.c_str(), sizeof(ui.value_buf2) - 1);
		ui.value_buf2[sizeof(ui.value_buf2) - 1] = '\0';
	}
	const int safe_total = std::max(total, 0);
	if (ui.result_sort_field == result_sort_t::by_index) {
		ui.sorted_result_indices.clear();
		ui.sorted_indices_dirty = false;
		return;
	}
	ui.sorted_result_indices.resize(static_cast<std::size_t>(safe_total));
	for (int i = 0; i < safe_total; ++i)
		ui.sorted_result_indices[static_cast<std::size_t>(i)] = i;

	std::vector<region_cache_entry_t> regions_snapshot;
	{
		std::lock_guard<std::mutex> lk(ui.region_cache.mtx);
		regions_snapshot = ui.region_cache.entries;
	}

	result_sort_t field = ui.result_sort_field;
	bool desc = ui.result_sort_desc;

	if (field != result_sort_t::by_index) {
		auto val_to_double = [&](const memory_scanner::scan_result_t& r,
		                          const std::vector<uint8_t>& bytes) -> double {
			(void)r;
			if (bytes.empty()) return 0.0;
			switch (sc.config.value_type) {
				case memory_scanner::value_type_t::byte_val:
					return static_cast<double>(bytes[0]);
				case memory_scanner::value_type_t::int16_val: {
					int16_t v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return static_cast<double>(v);
				}
				case memory_scanner::value_type_t::int32_val: {
					int32_t v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return static_cast<double>(v);
				}
				case memory_scanner::value_type_t::int64_val: {
					int64_t v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return static_cast<double>(v);
				}
				case memory_scanner::value_type_t::float_val: {
					float v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return static_cast<double>(v);
				}
				case memory_scanner::value_type_t::double_val: {
					double v; std::memcpy(&v, bytes.data(), std::min(bytes.size(), sizeof(v)));
					return v;
				}
				default:
					return 0.0;
			}
		};

		std::vector<std::string> module_labels;
		if (field == result_sort_t::by_module) {
			module_labels.reserve(static_cast<std::size_t>(safe_total));
			for (int index = 0; index < safe_total; ++index)
				module_labels.push_back(compose_module_label(
					sc.results[static_cast<std::size_t>(index)], regions_snapshot));
		}

		std::sort(ui.sorted_result_indices.begin(), ui.sorted_result_indices.end(),
			[&](int aa, int bb) {
				if (aa < 0 || bb < 0) return aa < bb;
				if (aa >= static_cast<int>(sc.results.size()) ||
				    bb >= static_cast<int>(sc.results.size())) return aa < bb;
				const auto& ra = sc.results[static_cast<size_t>(aa)];
				const auto& rb = sc.results[static_cast<size_t>(bb)];
				int cmp = 0;
				switch (field) {
					case result_sort_t::by_address:
						cmp = (ra.address < rb.address) ? -1 : (ra.address > rb.address ? 1 : 0);
						break;
					case result_sort_t::by_value: {
						double da = val_to_double(ra, ra.current_value);
						double db = val_to_double(rb, rb.current_value);
						cmp = (da < db) ? -1 : (da > db ? 1 : 0);
						break;
					}
					case result_sort_t::by_previous: {
						double da = val_to_double(ra, ra.previous_value);
						double db = val_to_double(rb, rb.previous_value);
						cmp = (da < db) ? -1 : (da > db ? 1 : 0);
						break;
					}
					case result_sort_t::by_module: {
						cmp = module_labels[static_cast<std::size_t>(aa)].compare(
							module_labels[static_cast<std::size_t>(bb)]);
						break;
					}
					default: break;
				}
				if (cmp == 0) return ra.address < rb.address;
				return desc ? (cmp > 0) : (cmp < 0);
			});
	}

	ui.sorted_indices_dirty = false;
}

void invalidate_sort() {
	g_ui.sorted_indices_dirty = true;
}

float render_compact_toolbar(ImDrawList* dl, float ox, float oy, float w, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	const float toolbar_h = 120.f;
	const float pad = 10.f;
	const float gap = 6.f;
	const float usable = (std::max)(1.f, w - pad * 2.f);

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + toolbar_h),
		aida::ui::with_alpha(t.panel_header, a));
	dl->AddLine(ImVec2(ox, oy + toolbar_h), ImVec2(ox + w, oy + toolbar_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	const float type_w = (std::clamp)(usable * 0.38f, 82.f, 108.f);
	const float mode_w = (std::max)(80.f, usable - type_w - gap);
	const float row1_y = oy + 7.f;

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, row1_y));
	ImGui::SetNextItemWidth(type_w);
	if (ImGui::BeginCombo("##compact_vtype", memory_scanner::value_type_name(sc.config.value_type))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
			const auto value_type = static_cast<memory_scanner::value_type_t>(i);
			const bool selected = sc.config.value_type == value_type;
			if (ImGui::Selectable(memory_scanner::value_type_name(value_type), selected)) {
				sc.config.value_type = value_type;
				invalidate_sort();
				diag_logf("toolbar value_type_change to=%s",
					memory_scanner::value_type_name(value_type));
			}
		}
		ImGui::EndCombo();
	}

	ImGui::SetCursorScreenPos(ImVec2(ox + pad + type_w + gap, row1_y));
	ImGui::SetNextItemWidth(mode_w);
	if (ImGui::BeginCombo("##compact_smode", memory_scanner::scan_mode_name(sc.config.scan_mode))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::scan_mode_t::COUNT); ++i) {
			const auto scan_mode = static_cast<memory_scanner::scan_mode_t>(i);
			const bool selected = sc.config.scan_mode == scan_mode;
			if (ImGui::Selectable(memory_scanner::scan_mode_name(scan_mode), selected)) {
				sc.config.scan_mode = scan_mode;
				diag_logf("toolbar scan_mode_change to=%s",
					memory_scanner::scan_mode_name(scan_mode));
			}
		}
		ImGui::EndCombo();
	}

	const bool needs_value = sc.config.scan_mode != memory_scanner::scan_mode_t::changed &&
		sc.config.scan_mode != memory_scanner::scan_mode_t::unchanged &&
		sc.config.scan_mode != memory_scanner::scan_mode_t::increased &&
		sc.config.scan_mode != memory_scanner::scan_mode_t::decreased &&
		sc.config.scan_mode != memory_scanner::scan_mode_t::unknown_initial;
	const bool between = sc.config.scan_mode == memory_scanner::scan_mode_t::value_between;
	const float hex_w = 48.f;
	const float row2_y = oy + 42.f;
	float value_x = ox + pad;
	float value_width = usable - hex_w - gap;
	if (needs_value) {
		if (between) {
			const float to_w = 18.f;
			const float field_w = (std::max)(44.f,
				(value_width - to_w - gap * 2.f) * 0.5f);
			ImGui::SetCursorScreenPos(ImVec2(value_x, row2_y));
			ImGui::SetNextItemWidth(field_w);
			ImGui::InputTextWithHint("##compact_val", "min", ui.value_buf, sizeof(ui.value_buf));
			ImGui::SetCursorScreenPos(ImVec2(value_x + field_w + gap, row2_y + 5.f));
			ImGui::TextUnformatted("to");
			ImGui::SetCursorScreenPos(ImVec2(value_x + field_w + gap + to_w + gap, row2_y));
			ImGui::SetNextItemWidth(field_w);
			ImGui::InputTextWithHint("##compact_val2", "max", ui.value_buf2, sizeof(ui.value_buf2));
		} else {
			ImGui::SetCursorScreenPos(ImVec2(value_x, row2_y));
			ImGui::SetNextItemWidth(value_width);
			ImGui::InputTextWithHint("##compact_val", "value", ui.value_buf, sizeof(ui.value_buf));
		}
	} else {
		ImFont* body = aida::ui::fonts::body();
		if (!body) body = ImGui::GetFont();
		const float font_size = aida::ui::fonts::size_or(body, ImGui::GetFontSize());
		dl->PushClipRect(ImVec2(value_x, row2_y),
			ImVec2(value_x + value_width, row2_y + 28.f), true);
		dl->AddText(body, font_size, ImVec2(value_x, row2_y + 5.f),
			aida::ui::with_alpha(t.text_secondary, a), "Uses the previous scan values");
		dl->PopClipRect();
	}

	ImGui::SetCursorScreenPos(ImVec2(ox + w - pad - hex_w, row2_y + 3.f));
	bool hex_input = sc.config.hex_input;
	if (ImGui::Checkbox("Hex", &hex_input)) {
		sc.config.hex_input = hex_input;
		diag_logf("toolbar hex_toggle now=%d", static_cast<int>(hex_input));
	}

	const bool scanning = sc.scanning.load(std::memory_order_acquire);
	bool has_initial_scan = false;
	std::size_t total_found = 0;
	{
		std::lock_guard<std::mutex> lock(sc.results_mutex);
		has_initial_scan = sc.has_initial_scan;
		total_found = sc.total_found;
	}
	const char* primary_action = scanning ? "memory.stop_scan" :
		(has_initial_scan ? "memory.next_scan" : "memory.first_scan");
	std::array<aida::ui::application_ui::action_presentation_t, 3> presentations{
		aida::ui::application_ui::present_action(primary_action),
		aida::ui::application_ui::present_action("memory.undo_scan"),
		aida::ui::application_ui::present_action("memory.new_scan")
	};
	std::array<aida::ui::design::action_t, 3> actions{};
	for (std::size_t index = 0; index < actions.size(); ++index) {
		auto& action = actions[index];
		const auto& presentation = presentations[index];
		action.id = presentation.id.c_str();
		action.label = presentation.label.c_str();
		action.compact_label = index == 0
			? (scanning ? "Stop" : (has_initial_scan ? "Next" : "First"))
			: (index == 1 ? "Undo" : "New");
		action.tooltip = presentation.enabled
			? presentation.description.c_str() : presentation.disabled_reason.c_str();
		action.shortcut = presentation.shortcut.empty() ? nullptr : presentation.shortcut.c_str();
		action.kind = index == 0
			? (scanning ? aida::ui::components::button_kind_t::destructive
				: aida::ui::components::button_kind_t::primary)
			: (index == 1 ? aida::ui::components::button_kind_t::secondary
				: aida::ui::components::button_kind_t::ghost);
		action.enabled = presentation.enabled;
		action.primary = index == 0;
		action.visible = presentation.visible;
	}

	char count_buf[64];
	if (scanning) {
		const int progress = static_cast<int>((std::clamp)(sc.scan_progress.load(), 0.f, 1.f) * 100.f);
		std::snprintf(count_buf, sizeof(count_buf), "%zu / %d%%", total_found, progress);
	} else {
		std::snprintf(count_buf, sizeof(count_buf), "%zu found", total_found);
	}
	ImFont* count_font = aida::ui::fonts::caption();
	if (!count_font) count_font = ImGui::GetFont();
	const float count_fs = aida::ui::fonts::size_or(count_font, ImGui::GetFontSize());
	const ImVec2 count_size = count_font->CalcTextSizeA(count_fs, FLT_MAX, 0.f, count_buf);
	const float count_reserve = (std::min)(usable * 0.38f, count_size.x + gap);
	const float action_width = (std::max)(1.f, usable - count_reserve - gap);
	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + 80.f));
	const auto invoked = aida::ui::design::render_toolbar(
		"memory-scan-compact", actions.data(), actions.size(), action_width);
	if (invoked.invoked && invoked.id) {
		static_cast<void>(aida::ui::application_ui::execute_action(
			invoked.id, aida::ui::action_invocation_source_t::toolbar));
	}
	dl->AddText(count_font, count_fs,
		ImVec2(ox + w - pad - count_size.x, oy + 86.f),
		aida::ui::with_alpha(t.text_secondary, a), count_buf);
	return toolbar_h;
}

float render_toolbar(ImDrawList* dl, float ox, float oy, float w, float a) {
	if (w < 1120.f)
		return render_compact_toolbar(dl, ox, oy, w, a);
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + kToolbarHeight),
		aida::ui::with_alpha(t.panel_header, a));
	ImU32 sheen_top = aida::ui::with_alpha(t.accent_glow, 0.10f * a);
	dl->AddRectFilledMultiColor(ImVec2(ox, oy),
		ImVec2(ox + w, oy + 16.f),
		sheen_top, sheen_top,
		IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
	dl->AddLine(ImVec2(ox, oy + kToolbarHeight),
		ImVec2(ox + w, oy + kToolbarHeight),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	float pad = 14.f;
	float cy = oy + (kToolbarHeight - 36.f) * 0.5f;
	float cx = ox + pad;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 4.f));
	ImGui::PushItemWidth(108.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.bg_elevated, a));
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, aida::ui::with_alpha(t.hover_wash, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
	if (ImGui::BeginCombo("##vtype", memory_scanner::value_type_name(sc.config.value_type))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
			auto vt = static_cast<memory_scanner::value_type_t>(i);
			bool sel = (sc.config.value_type == vt);
			if (ImGui::Selectable(memory_scanner::value_type_name(vt), sel)) {
				if (sc.config.value_type != vt) {
					diag_logf("toolbar value_type_change from=%s to=%s",
						memory_scanner::value_type_name(sc.config.value_type),
						memory_scanner::value_type_name(vt));
					sc.config.value_type = vt;
					invalidate_sort();
				}
			}
		}
		ImGui::EndCombo();
	}
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(5);
	ImGui::PopItemWidth();
	cx += 116.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 4.f));
	ImGui::PushItemWidth(190.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.bg_elevated, a));
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, aida::ui::with_alpha(t.hover_wash, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
	if (ImGui::BeginCombo("##smode", memory_scanner::scan_mode_name(sc.config.scan_mode))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::scan_mode_t::COUNT); ++i) {
			auto sm = static_cast<memory_scanner::scan_mode_t>(i);
			bool sel = (sc.config.scan_mode == sm);
			if (ImGui::Selectable(memory_scanner::scan_mode_name(sm), sel)) {
				if (sc.config.scan_mode != sm) {
					diag_logf("toolbar scan_mode_change to=%s",
						memory_scanner::scan_mode_name(sm));
					sc.config.scan_mode = sm;
				}
			}
		}
		ImGui::EndCombo();
	}
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(5);
	ImGui::PopItemWidth();
	cx += 200.f;

	bool needs_value = (sc.config.scan_mode != memory_scanner::scan_mode_t::changed &&
	                    sc.config.scan_mode != memory_scanner::scan_mode_t::unchanged &&
	                    sc.config.scan_mode != memory_scanner::scan_mode_t::increased &&
	                    sc.config.scan_mode != memory_scanner::scan_mode_t::decreased &&
	                    sc.config.scan_mode != memory_scanner::scan_mode_t::unknown_initial);

	float input_h = 34.f;
	float input_y = oy + (kToolbarHeight - input_h) * 0.5f;
	if (needs_value) {
		float input_w = 200.f;
		ImVec2 ia(cx, input_y);
		ImVec2 ib(cx + input_w, input_y + input_h);
		dl->AddRectFilled(ia, ib, aida::ui::with_alpha(t.bg_elevated, a), 8.f);
		dl->AddRect(ia, ib, aida::ui::with_alpha(t.border_focus, a * 0.55f), 8.f, 0, 1.5f);
		ImGui::SetCursorScreenPos(ImVec2(cx + 4.f, input_y + 2.f));
		ImGui::PushItemWidth(input_w - 8.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
		ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, aida::ui::with_alpha(t.accent_dim, a));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 8.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::InputTextWithHint("##val", "value", ui.value_buf, sizeof(ui.value_buf));
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(5);
		ImGui::PopItemWidth();
		cx += input_w + 10.f;
	}

	if (sc.config.scan_mode == memory_scanner::scan_mode_t::value_between) {
		ImFont* body_fn = aida::ui::fonts::body();
		const float body_fs = aida::ui::fonts::size_or(body_fn, ImGui::GetFontSize());
		dl->AddText(body_fn, body_fs,
			ImVec2(cx, oy + (kToolbarHeight - body_fs) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a), "to");
		cx += 28.f;
		float input2_w = 150.f;
		ImVec2 ia2(cx, input_y);
		ImVec2 ib2(cx + input2_w, input_y + input_h);
		dl->AddRectFilled(ia2, ib2, aida::ui::with_alpha(t.bg_elevated, a), 8.f);
		dl->AddRect(ia2, ib2, aida::ui::with_alpha(t.border_focus, a * 0.55f), 8.f, 0, 1.5f);
		ImGui::SetCursorScreenPos(ImVec2(cx + 4.f, input_y + 2.f));
		ImGui::PushItemWidth(input2_w - 8.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 8.f));
		ImGui::InputTextWithHint("##val2", "max", ui.value_buf2, sizeof(ui.value_buf2));
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(2);
		ImGui::PopItemWidth();
		cx += input2_w + 10.f;
	}

	{
		ImFont* hex_fn = aida::ui::fonts::body();
		const float hex_fs = aida::ui::fonts::size_or(hex_fn, ImGui::GetFontSize());
		float lbl_w = hex_fn->CalcTextSizeA(hex_fs, FLT_MAX, 0.f, "HEX").x;
		float pill_w = lbl_w + 44.f;
		float pill_h = input_h;
		float py = input_y;
		ImGui::SetCursorScreenPos(ImVec2(cx, py));
		ImGui::PushID("hex_toggle");
		ImGui::InvisibleButton("##hex_b", ImVec2(pill_w, pill_h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
		           !ui_input_gate::popup_blocks_background_input();
		bool hov = ImGui::IsItemHovered();
		if (clk) {
			sc.config.hex_input = !sc.config.hex_input;
			diag_logf("toolbar hex_toggle now=%d", static_cast<int>(sc.config.hex_input));
		}
		bool on = sc.config.hex_input;
		ImU32 track = on ? aida::ui::with_alpha(t.accent_dim, a * 0.92f)
		                  : aida::ui::with_alpha(t.bg_elevated, a);
		ImU32 border = on ? aida::ui::with_alpha(t.accent_u32, a * 0.95f)
		                   : aida::ui::with_alpha(t.border_strong, a);
		if (hov) border = aida::ui::with_alpha(t.accent_hover, a);
		ImVec2 pa(cx, py);
		ImVec2 pb(cx + pill_w, py + pill_h);
		dl->AddRectFilled(pa, pb, track, pill_h * 0.5f);
		dl->AddRect(pa, pb, border, pill_h * 0.5f, 0, 1.5f);
		float knob_r = (pill_h - 8.f) * 0.5f;
		float knob_x = on ? (cx + pill_w - knob_r - 6.f) : (cx + knob_r + 6.f);
		float knob_y = py + pill_h * 0.5f;
		dl->AddCircleFilled(ImVec2(knob_x, knob_y), knob_r,
			on ? aida::ui::with_alpha(t.accent_u32, a)
			   : aida::ui::with_alpha(t.text_dim, a * 0.85f), 24);
		ImU32 lbl_col = on ? aida::ui::with_alpha(t.text_primary, a)
		                   : aida::ui::with_alpha(t.text_secondary, a);
		float lbl_x = on ? (cx + 14.f) : (cx + pill_w - lbl_w - 16.f);
		dl->AddText(hex_fn, hex_fs,
			ImVec2(lbl_x, py + (pill_h - hex_fs) * 0.5f),
			lbl_col, "HEX");
		ImGui::PopID();
		cx += pill_w + 14.f;
	}

	const bool scanning = sc.scanning.load(std::memory_order_acquire);
	bool has_initial_scan = false;
	std::size_t total_found = 0;
	{
		std::lock_guard<std::mutex> lock(sc.results_mutex);
		has_initial_scan = sc.has_initial_scan;
		total_found = sc.total_found;
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const bool attached = true;
	const bool static_pe = true;
#else
	const bool attached = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;
	const bool static_pe = function_index::detail::static_pe_active();
#endif
	const auto render_action_button = [&](const char* action_id,
		aida::ui::button_kind_t kind) {
		const auto presentation = aida::ui::application_ui::present_action(action_id);
		const bool clicked = aida::ui::button(presentation.label.c_str(), kind,
			aida::ui::size_t_::md, ImVec2(0.f, 0.f), !presentation.enabled);
		if (!presentation.enabled &&
			ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) &&
			!presentation.disabled_reason.empty())
			ImGui::SetTooltip("%s", presentation.disabled_reason.c_str());
		if (clicked)
			static_cast<void>(aida::ui::application_ui::execute_action(action_id,
				aida::ui::action_invocation_source_t::toolbar));
	};

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (scanning) {
		render_action_button("memory.stop_scan", aida::ui::button_kind_t::destructive);
		cx += 96.f;
	} else if (!has_initial_scan) {
		render_action_button("memory.first_scan", aida::ui::button_kind_t::primary);
		cx += 132.f;
	} else {
		render_action_button("memory.next_scan", aida::ui::button_kind_t::primary);
		cx += 122.f;
	}

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	render_action_button("memory.undo_scan", aida::ui::button_kind_t::secondary);
	cx += 86.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	render_action_button("memory.new_scan", aida::ui::button_kind_t::ghost);
	cx += 108.f;

	float right_cx = ox + w - pad;

	{
		char count_buf[64];
		snprintf(count_buf, sizeof(count_buf), "%zu found", total_found);
		ImFont* body_fn = aida::ui::fonts::body();
		const float body_fs = aida::ui::fonts::size_or(body_fn, ImGui::GetFontSize());
		ImVec2 cts = body_fn->CalcTextSizeA(body_fs, FLT_MAX, 0.f, count_buf);
		right_cx -= cts.x;
		dl->AddText(body_fn, body_fs,
			ImVec2(right_cx, oy + (kToolbarHeight - cts.y) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a), count_buf);
		right_cx -= 12.f;
	}

	if (scanning) {
		float prog = sc.scan_progress.load();
		float ring_r = 12.f;
		right_cx -= (ring_r * 2.f + 4.f);
		float ring_cx = right_cx + ring_r;
		float ring_cy = oy + kToolbarHeight * 0.5f;
		aida::ui::render_progress_ring(ImVec2(ring_cx, ring_cy), ring_r, 2.5f, prog, false);
		char pct_buf[8];
		snprintf(pct_buf, sizeof(pct_buf), "%d%%", static_cast<int>(prog * 100.f));
		ImFont* body_fn = aida::ui::fonts::body();
		const float body_fs = aida::ui::fonts::size_or(body_fn, ImGui::GetFontSize());
		ImVec2 pct_sz = body_fn->CalcTextSizeA(body_fs, FLT_MAX, 0.f, pct_buf);
		dl->AddText(body_fn, body_fs,
			ImVec2(ring_cx - pct_sz.x * 0.5f, ring_cy - pct_sz.y * 0.5f),
			aida::ui::with_alpha(t.text_primary, a), pct_buf);
		right_cx -= 12.f;
	}

	if (static_pe) {
		if (!attached) ui.prefer_static_source = true;
		const bool static_selected = ui.prefer_static_source || !attached;
		const char* lbl = static_selected ? "Static binary" : "Live process";
		ImFont* body_fn = aida::ui::fonts::body();
		const float body_fs = aida::ui::fonts::size_or(body_fn, ImGui::GetFontSize());
		ImVec2 lsz = body_fn->CalcTextSizeA(body_fs, FLT_MAX, 0.f, lbl);
		float pad_x = 10.f;
		float pad_y = 5.f;
		float bw = lsz.x + pad_x * 2.f;
		float bh = lsz.y + pad_y * 2.f;
		right_cx -= bw;
		float by = oy + (kToolbarHeight - bh) * 0.5f;
		ImGui::SetCursorScreenPos(ImVec2(right_cx, by));
		ImGui::BeginDisabled(!attached || has_initial_scan || scanning);
		ImGui::InvisibleButton("##memory_scan_source", ImVec2(bw, bh));
		if (ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input())
			ui.prefer_static_source = !ui.prefer_static_source;
		ImGui::EndDisabled();
		dl->AddRectFilled(ImVec2(right_cx, by),
			ImVec2(right_cx + bw, by + bh),
			aida::ui::with_alpha(static_selected ? t.warning : t.info, 0.18f * a), bh * 0.5f);
		dl->AddRect(ImVec2(right_cx, by),
			ImVec2(right_cx + bw, by + bh),
			aida::ui::with_alpha(static_selected ? t.warning : t.info, 0.65f * a), bh * 0.5f, 0, 1.f);
		dl->AddText(body_fn, body_fs,
			ImVec2(right_cx + pad_x, by + pad_y),
			aida::ui::with_alpha(static_selected ? t.warning : t.info, a), lbl);
		if (attached && !has_initial_scan && !scanning && ImGui::IsItemHovered())
			ImGui::SetTooltip("Switch the next scan between the attached process and static PE image");
		right_cx -= 12.f;
	}
	return kToolbarHeight;
}

void compute_result_columns(float ox, float w,
                            column_layout_t cols[4],
                            float& content_w_total,
                            bool include_scrollbar)
{
	const float pad = 12.f;
	float right_reserve = include_scrollbar ? (kScrollbarTrackW + 12.f) : 12.f;
	float avail = w - pad - right_reserve;
	if (w < 360.f) {
		const float address_w = (std::max)(96.f, avail * 0.62f);
		const float value_w = (std::max)(1.f, avail - address_w);
		const float widths[4] = {address_w, value_w, 0.f, 0.f};
		const char* names[4] = {"Address", "Value", "", ""};
		float cx = ox + pad;
		for (std::size_t index = 0; index < 4U; ++index) {
			cols[index].x0 = cx;
			cols[index].x1 = cx + widths[index];
			cols[index].inner_x0 = cx + (widths[index] > 0.f ? 4.f : 0.f);
			cols[index].inner_x1 = cols[index].x1 - (widths[index] > 0.f ? 4.f : 0.f);
			cols[index].title = names[index];
			cx += widths[index];
		}
		content_w_total = cx - ox;
		return;
	}
	if (w < 560.f) {
		const float address_w = avail * 0.42f;
		const float value_w = avail * 0.25f;
		const float module_w = (std::max)(1.f, avail - address_w - value_w);
		const float widths[4] = {address_w, value_w, 0.f, module_w};
		const char* names[4] = {"Address", "Value", "", "Module"};
		float cx = ox + pad;
		for (std::size_t index = 0; index < 4U; ++index) {
			cols[index].x0 = cx;
			cols[index].x1 = cx + widths[index];
			cols[index].inner_x0 = cx + (widths[index] > 0.f ? 5.f : 0.f);
			cols[index].inner_x1 = cols[index].x1 - (widths[index] > 0.f ? 5.f : 0.f);
			cols[index].title = names[index];
			cx += widths[index];
		}
		content_w_total = cx - ox;
		return;
	}
	float col_addr_w = std::min(180.f, std::max(140.f, avail * 0.20f));
	float col_val_w  = std::min(170.f, std::max(110.f, avail * 0.18f));
	float col_prev_w = std::min(170.f, std::max(110.f, avail * 0.18f));
	float col_mod_w  = avail - col_addr_w - col_val_w - col_prev_w;
	if (col_mod_w < 100.f) col_mod_w = 100.f;

	float widths[4] = { col_addr_w, col_val_w, col_prev_w, col_mod_w };
	const char* names[4] = { "Address", "Value", "Previous", "Module / Region" };
	float cx = ox + pad;
	for (std::size_t i = 0; i < 4U; ++i) {
		cols[i].x0 = cx;
		cols[i].x1 = cx + widths[i];
		cols[i].inner_x0 = cx + 6.f;
		cols[i].inner_x1 = cols[i].x1 - 8.f;
		cols[i].title = names[i];
		cx += widths[i];
	}
	content_w_total = cx - ox;
}

void compute_addr_columns(float ox, float w,
                          column_layout_t cols[5],
                          bool include_scrollbar)
{
	const float pad = 12.f;
	float right_reserve = include_scrollbar ? (kScrollbarTrackW + 12.f) : 12.f;
	float avail = w - pad - right_reserve;
	if (w < 360.f) {
		const float active_w = 42.f;
		const float address_w = (std::max)(92.f, avail * 0.54f);
		const float description_w = (std::max)(1.f, avail - active_w - address_w);
		const float widths[5] = {active_w, description_w, address_w, 0.f, 0.f};
		const char* names[5] = {"On", "Name", "Address", "", ""};
		float cx = ox + pad;
		for (std::size_t index = 0; index < 5U; ++index) {
			cols[index].x0 = cx;
			cols[index].x1 = cx + widths[index];
			cols[index].inner_x0 = cx + (widths[index] > 0.f ? 4.f : 0.f);
			cols[index].inner_x1 = cols[index].x1 - (widths[index] > 0.f ? 4.f : 0.f);
			cols[index].title = names[index];
			cx += widths[index];
		}
		return;
	}
	if (w < 560.f) {
		const float active_w = 48.f;
		const float description_w = avail * 0.25f;
		const float address_w = avail * 0.42f;
		const float value_w = (std::max)(1.f,
			avail - active_w - description_w - address_w);
		const float widths[5] = {active_w, description_w, address_w, 0.f, value_w};
		const char* names[5] = {"On", "Name", "Address", "", "Value"};
		float cx = ox + pad;
		for (std::size_t index = 0; index < 5U; ++index) {
			cols[index].x0 = cx;
			cols[index].x1 = cx + widths[index];
			cols[index].inner_x0 = cx + (widths[index] > 0.f ? 5.f : 0.f);
			cols[index].inner_x1 = cols[index].x1 - (widths[index] > 0.f ? 5.f : 0.f);
			cols[index].title = names[index];
			cx += widths[index];
		}
		return;
	}
	float col_freeze_w = 60.f;
	float col_addr_w = std::min(180.f, std::max(140.f, avail * 0.18f));
	float col_type_w = std::min(120.f, std::max(80.f, avail * 0.10f));
	float reserved = col_freeze_w + col_addr_w + col_type_w;
	float remaining = avail - reserved;
	if (remaining < 200.f) remaining = 200.f;
	float col_desc_w = remaining * 0.55f;
	float col_val_w  = remaining - col_desc_w;
	if (col_val_w < 100.f) {
		col_val_w = 100.f;
		col_desc_w = remaining - col_val_w;
	}

	float widths[5] = { col_freeze_w, col_desc_w, col_addr_w, col_type_w, col_val_w };
	const char* names[5] = { "Active", "Description", "Address", "Type", "Value" };

	float cx = ox + pad;
	for (std::size_t i = 0; i < 5U; ++i) {
		cols[i].x0 = cx;
		cols[i].x1 = cx + widths[i];
		cols[i].inner_x0 = cx + 6.f;
		cols[i].inner_x1 = cols[i].x1 - 8.f;
		cols[i].title = names[i];
		cx += widths[i];
	}
}

ImU32 value_color(const memory_scanner::scan_result_t& r, float a, const aida::ui::theme_t& t) {
	if (r.previous_value.empty() || r.current_value.empty())
		return aida::ui::with_alpha(t.success, a);
	int64_t cv = 0, pv = 0;
	std::memcpy(&cv, r.current_value.data(), std::min(r.current_value.size(), sizeof(int64_t)));
	std::memcpy(&pv, r.previous_value.data(), std::min(r.previous_value.size(), sizeof(int64_t)));
	if (cv > pv) return aida::ui::with_alpha(t.success, a);
	if (cv < pv) return aida::ui::with_alpha(t.error, a);
	return aida::ui::with_alpha(t.text_primary, a);
}

void update_results_diff_flash(int total, std::uint64_t revision) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	ui.flash_revision_age += aida::ui::clock::dt();
	if (ui.last_flash_revision == revision)
		return;
	ui.last_flash_revision = revision;
	ui.flash_revision_age = 0.f;
	ui.last_result_count = static_cast<std::size_t>(total);
	if (total > 10000) {
		ui.row_flash.clear();
		return;
	}
	if (static_cast<int>(ui.row_flash.size()) != total)
		ui.row_flash.resize(static_cast<size_t>(total), 0.f);
	for (int index = 0; index < total; ++index) {
		const auto& result = sc.results[static_cast<std::size_t>(index)];
		const bool initial = sc.scan_count <= 1;
		const bool changed = !result.previous_value.empty() &&
			result.current_value != result.previous_value;
		ui.row_flash[static_cast<std::size_t>(index)] =
			(initial || changed) ? 1.f : 0.f;
	}
}

void handle_multi_select(std::unordered_set<int>& set, int& anchor, int idx, int total) {
	bool ctrl = ctrl_held();
	bool shift = shift_held();
	bool truncated = false;
	if (shift && anchor >= 0 && anchor < total) {
		int lo = std::min(anchor, idx);
		int hi = std::max(anchor, idx);
		if (!ctrl) set.clear();
		for (int k = lo; k <= hi; ++k) {
			if (set.count(k) != 0) continue;
			if (set.size() >= kMaximumMemoryMultiSelection) {
				truncated = true;
				break;
			}
			set.insert(k);
		}
		if (set.count(idx) == 0) {
			if (set.size() >= kMaximumMemoryMultiSelection) set.erase(set.begin());
			set.insert(idx);
			truncated = true;
		}
	} else if (ctrl) {
		anchor = idx;
		auto it = set.find(idx);
		if (it == set.end()) {
			if (set.size() < kMaximumMemoryMultiSelection) set.insert(idx);
			else truncated = true;
		}
		else set.erase(it);
	} else {
		set.clear();
		set.insert(idx);
		anchor = idx;
	}
	if (truncated)
		toast_notification::push("Memory selection is limited to 4,096 rows.",
			toast_notification::toast_type_t::warning, 4.f);
}

void select_result_rows(const memory_interaction::runtime_t& runtime,
	const std::vector<region_cache_entry_t>& regions, int preferred_row) {
	auto& state = memory_scanner::g_state;
	auto& ui = g_ui;
	std::vector<int> rows(ui.result_multi_sel.begin(), ui.result_multi_sel.end());
	std::sort(rows.begin(), rows.end());
	if (rows.size() > kMaximumMemoryMultiSelection)
		rows.resize(kMaximumMemoryMultiSelection);
	std::vector<memory_interaction::context_t> contexts;
	contexts.reserve(rows.size());
	memory_interaction::context_t focused;
	{
		std::lock_guard<std::mutex> lock(state.results_mutex);
		for (const int row : rows) {
			int source_index = row;
			if (row >= 0 && row < static_cast<int>(ui.sorted_result_indices.size()))
				source_index = ui.sorted_result_indices[static_cast<std::size_t>(row)];
			if (source_index < 0 || source_index >= static_cast<int>(state.results.size())) continue;
			const auto& result = state.results[static_cast<std::size_t>(source_index)];
			auto context = memory_interaction::capture_result(runtime, result.address, source_index,
				memory_scanner::format_value(result.current_value, state.config.value_type),
				memory_scanner::format_value(result.previous_value, state.config.value_type),
				compose_module_label(result, regions));
			if (row == preferred_row) focused = context;
			contexts.push_back(std::move(context));
		}
	}
	if (contexts.empty()) {
		ui.selected_result = -1;
		memory_interaction::clear_selection();
		return;
	}
	if (focused.kind == memory_interaction::kind_t::none) focused = contexts.back();
	ui.selected_result = preferred_row >= 0 && ui.result_multi_sel.count(preferred_row) != 0
		? preferred_row : rows.back();
	memory_interaction::select_set(std::move(contexts), std::move(focused));
}

void select_address_rows(const memory_interaction::runtime_t& runtime, int preferred_row) {
	auto& state = memory_scanner::g_state;
	auto& ui = g_ui;
	std::vector<int> rows(ui.address_multi_sel.begin(), ui.address_multi_sel.end());
	std::sort(rows.begin(), rows.end());
	if (rows.size() > kMaximumMemoryMultiSelection)
		rows.resize(kMaximumMemoryMultiSelection);
	std::vector<memory_interaction::context_t> contexts;
	contexts.reserve(rows.size());
	memory_interaction::context_t focused;
	{
		std::lock_guard<std::mutex> lock(state.address_mutex);
		for (const int row : rows) {
			if (row < 0 || row >= static_cast<int>(state.address_list.size())) continue;
			const auto& entry = state.address_list[static_cast<std::size_t>(row)];
			auto context = memory_interaction::capture_address(runtime, entry.address, row,
				entry.frozen, memory_scanner::format_value(entry.last_value, entry.value_type),
				entry.target_pid, entry.target_epoch,
				entry.target_identity.process.creation_time_100ns);
			if (row == preferred_row) focused = context;
			contexts.push_back(std::move(context));
		}
	}
	if (contexts.empty()) {
		ui.selected_address = -1;
		memory_interaction::clear_selection();
		return;
	}
	if (focused.kind == memory_interaction::kind_t::none) focused = contexts.back();
	ui.selected_address = preferred_row >= 0 && ui.address_multi_sel.count(preferred_row) != 0
		? preferred_row : rows.back();
	memory_interaction::select_set(std::move(contexts), std::move(focused));
}

void render_results_pane(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy),
		ImVec2(ox + w, oy + kResultHeaderHeight),
		aida::ui::with_alpha(t.panel_header, a * 0.92f));
	dl->AddLine(ImVec2(ox, oy + kResultHeaderHeight),
		ImVec2(ox + w, oy + kResultHeaderHeight),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	column_layout_t cols[4];
	float content_w_total = 0.f;

	int total = 0;
	{
		std::lock_guard<std::mutex> lk(sc.results_mutex);
		total = static_cast<int>(sc.results.size());
	}
	bool include_sb = total > 0;
	const bool sort_allowed = total <= 10000;
	compute_result_columns(ox, w, cols, content_w_total, include_sb);

	ImFont* hdr_font = aida::ui::fonts::body_em();
	const float hdr_fs = aida::ui::fonts::size_or(hdr_font, ImGui::GetFontSize());

	for (std::size_t c = 0; c < 4U; ++c) {
		if (!cols[c].title || cols[c].title[0] == '\0')
			continue;
		ImVec2 hmin(cols[c].x0, oy);
		ImVec2 hmax(cols[c].x1, oy + kResultHeaderHeight);
		bool hov = ImGui::IsMouseHoveringRect(hmin, hmax, false) &&
			!ui_input_gate::popup_blocks_background_input();
		ImGui::PushID(8000 + static_cast<int>(c));
		ImGui::SetCursorScreenPos(hmin);
		ImGui::InvisibleButton("##rh", ImVec2(hmax.x - hmin.x, hmax.y - hmin.y));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item(
			studio_memory_surface_id(std::string("result-header-") + cols[c].title),
			"memory-scan-action", false, !sort_allowed,
			studio_memory_parent_id());
#endif
		bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input();
		ImGui::PopID();

		if (hov) {
			dl->AddRectFilled(hmin, hmax, aida::ui::with_alpha(t.hover_wash, 0.5f * a));
		}

		ImU32 lbl_col = aida::ui::with_alpha(t.text_secondary, a);
		result_sort_t field = result_sort_t::by_index;
		switch (c) {
			case kColResultAddr:     field = result_sort_t::by_address;  break;
			case kColResultValue:    field = result_sort_t::by_value;    break;
			case kColResultPrevious: field = result_sort_t::by_previous; break;
			case kColResultModule:   field = result_sort_t::by_module;   break;
		}
		bool active = (ui.result_sort_field == field);
		if (active)
			lbl_col = aida::ui::with_alpha(t.accent_u32, a);
		dl->AddText(hdr_font, hdr_fs,
			ImVec2(cols[c].inner_x0, oy + (kResultHeaderHeight - hdr_fs) * 0.5f),
			lbl_col, cols[c].title);

		if (active) {
			float tri_x = cols[c].inner_x0 +
				hdr_font->CalcTextSizeA(hdr_fs, FLT_MAX, 0.f, cols[c].title).x + 8.f;
			float tri_y = oy + kResultHeaderHeight * 0.5f;
			float trh = 5.f;
			ImU32 tcol = aida::ui::with_alpha(t.accent_u32, a);
			if (ui.result_sort_desc) {
				dl->AddTriangleFilled(
					ImVec2(tri_x, tri_y - trh * 0.5f),
					ImVec2(tri_x + trh * 1.5f, tri_y - trh * 0.5f),
					ImVec2(tri_x + trh * 0.75f, tri_y + trh * 0.7f), tcol);
			} else {
				dl->AddTriangleFilled(
					ImVec2(tri_x, tri_y + trh * 0.5f),
					ImVec2(tri_x + trh * 1.5f, tri_y + trh * 0.5f),
					ImVec2(tri_x + trh * 0.75f, tri_y - trh * 0.7f), tcol);
			}
		}

		if (clicked) {
			if (!sort_allowed) {
				toast_notification::push("Refine results below 10,000 rows before changing sort order.",
					toast_notification::toast_type_t::warning, 4.f);
			} else if (ui.result_sort_field == field) {
				if (!ui.result_sort_desc) ui.result_sort_desc = true;
				else { ui.result_sort_field = result_sort_t::by_index; ui.result_sort_desc = false; }
			} else {
				ui.result_sort_field = field;
				ui.result_sort_desc = false;
			}
			invalidate_sort();
			diag_logf("results column_sort_click col=%d field=%d desc=%d",
				static_cast<int>(c), static_cast<int>(ui.result_sort_field),
				static_cast<int>(ui.result_sort_desc));
		}
	}

	float body_y = oy + kResultHeaderHeight;
	float body_h = h - kResultHeaderHeight;
	if (body_h < 1.f) body_h = 1.f;
	int visible_rows = static_cast<int>(body_h / kResultRowHeight);
	if (visible_rows < 1) visible_rows = 1;

	memory_interaction::runtime_t runtime;
	{
		std::lock_guard<std::mutex> lk(sc.results_mutex);
		total = static_cast<int>(sc.results.size());
		runtime = runtime_snapshot_locked(sc.results.size());

		update_results_diff_flash(total, runtime.scan_revision);

	if (total > 10000 && ui.result_sort_field != result_sort_t::by_index) {
		ui.result_sort_field = result_sort_t::by_index;
		ui.result_sort_desc = false;
		ui.sorted_result_indices.clear();
		ui.sorted_indices_dirty = false;
		toast_notification::push("Result sort returned to address order to keep the large scan responsive.",
			toast_notification::toast_type_t::info, 4.f);
	}
	const bool indexed_sort = ui.result_sort_field != result_sort_t::by_index;
		if (ui.sorted_indices_dirty ||
			(indexed_sort && static_cast<int>(ui.sorted_result_indices.size()) != total) ||
			(!indexed_sort && !ui.sorted_result_indices.empty()))
			rebuild_sorted_indices(total);
	}

	{
		uint64_t cur_gen = 0;
		{
			std::lock_guard<std::mutex> rgk(ui.region_cache.mtx);
			cur_gen = ui.region_cache.generation;
		}
		if (cur_gen != ui.last_region_refresh_gen &&
			ui.result_sort_field == result_sort_t::by_module &&
			!ui.sorted_indices_dirty)
		{
			ui.last_region_refresh_gen = cur_gen;
			invalidate_sort();
		}
	}

	float dt = aida::ui::clock::dt();

	bool body_hover = ImGui::IsMouseHoveringRect(
		ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), false) &&
		!ui_input_gate::popup_blocks_background_input();

	if (body_hover) {
		if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
			ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			ui.result_pane_focused = true;
			ui.address_pane_focused = false;
		}
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) {
			ui.result_sb.target_scroll_y -= wheel * kResultRowHeight * 3.f;
			if (wheel > 0.f) ui.user_scrolled_up = true;
			diag_logf("results wheel=%.2f target=%.1f", wheel, ui.result_sb.target_scroll_y);
		}
	}

	float content_h = static_cast<float>(total) * kResultRowHeight;
	float max_scroll = std::max(0.f, content_h - body_h);
	ui.result_sb.target_scroll_y = std::clamp(ui.result_sb.target_scroll_y, 0.f, max_scroll);
	ui_anim::smooth_scroll(ui.result_sb.scroll_y, ui.result_sb.target_scroll_y, 22.f, dt);

	if (ui.result_sb.target_scroll_y >= max_scroll - 1.f) ui.user_scrolled_up = false;

	int first_row = static_cast<int>(ui.result_sb.scroll_y / kResultRowHeight);
	if (first_row < 0) first_row = 0;
	int last_row = std::min(total, first_row + visible_rows + 2);
	struct visible_result_t {
		int row = -1;
		int source_index = -1;
		memory_scanner::scan_result_t value;
	};
	std::vector<visible_result_t> visible_results;
	{
		std::lock_guard<std::mutex> lock(sc.results_mutex);
		total = static_cast<int>(sc.results.size());
		last_row = std::min(total, first_row + visible_rows + 2);
		visible_results.reserve(last_row > first_row
			? static_cast<std::size_t>(last_row - first_row) : 0);
		for (int row = first_row; row < last_row; ++row) {
			int source_index = row;
			if (row >= 0 && row < static_cast<int>(ui.sorted_result_indices.size()))
				source_index = ui.sorted_result_indices[static_cast<std::size_t>(row)];
			if (source_index >= 0 && source_index < total)
				visible_results.push_back({row, source_index,
					sc.results[static_cast<std::size_t>(source_index)]});
		}
	}

	{
		std::lock_guard<std::mutex> rgk(ui.region_cache.mtx);
		if (ui.render_region_generation != ui.region_cache.generation) {
			ui.render_region_snapshot = ui.region_cache.entries;
			ui.render_region_generation = ui.region_cache.generation;
		}
	}
	const auto& regions_snapshot = ui.render_region_snapshot;

	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), true);

	ImFont* code_fn = aida::ui::fonts::code();
	const float code_fs = aida::ui::fonts::size_or(code_fn, ImGui::GetFontSize());
	ImFont* body_fn = aida::ui::fonts::body();
	const float body_fs = aida::ui::fonts::size_or(body_fn, ImGui::GetFontSize());

	int clicked_row = -1;
	int dbl_click_row = -1;
	int right_click_row = -1;

	float row_right_edge = include_sb ? (ox + w - kScrollbarTrackW - 6.f) : (ox + w);

	for (const auto& visible : visible_results) {
		const int i = visible.row;
		const int src_index = visible.source_index;
		const auto& r = visible.value;

		float ry = body_y + static_cast<float>(i) * kResultRowHeight - ui.result_sb.scroll_y;
		if (ry + kResultRowHeight < body_y || ry > body_y + body_h) continue;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const auto result_semantic_context = memory_interaction::capture_result(runtime,
			r.address, src_index,
			memory_scanner::format_value(r.current_value, sc.config.value_type),
			memory_scanner::format_value(r.previous_value, sc.config.value_type),
			compose_module_label(r, regions_snapshot));
		const std::string result_semantic_id = studio_memory_entity_id(
			"result", result_semantic_context);
		aida::preview::semantics::register_region(result_semantic_id,
			"memory-scan-result-row", ImGui::GetID(result_semantic_id.c_str()),
			ImVec2(ox, ry), ImVec2(row_right_edge, ry + kResultRowHeight), false, false,
			studio_memory_parent_id());
#endif

		const float row_entrance = 1.f;
		bool sel = (ui.result_multi_sel.count(i) > 0) || (ui.selected_result == i);
		bool hov = ImGui::IsMouseHoveringRect(
			ImVec2(ox, ry), ImVec2(row_right_edge, ry + kResultRowHeight), false) &&
			!ui_input_gate::popup_blocks_background_input();

		if (sel) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kResultRowHeight),
				aida::ui::with_alpha(t.selection, a * row_entrance));
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + 3.f, ry + kResultRowHeight),
				aida::ui::with_alpha(t.accent_u32, a * row_entrance));
		} else if (hov) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kResultRowHeight),
				aida::ui::with_alpha(t.hover_wash, a * row_entrance));
		} else if (i & 1) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kResultRowHeight),
				aida::ui::with_alpha(t.hover_wash, 0.20f * a * row_entrance));
		}

		float flash = (src_index < static_cast<int>(ui.row_flash.size()))
			? std::max(0.f, ui.row_flash[static_cast<size_t>(src_index)] -
				ui.flash_revision_age * 1.66f) : 0.f;
		if (flash > 0.f) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kResultRowHeight),
				aida::ui::with_alpha(t.accent_glow, a * flash * 0.85f));
		}

		char addr_buf[24];
		if (w < 360.f)
			snprintf(addr_buf, sizeof(addr_buf), "%" PRIX64, r.address);
		else
			snprintf(addr_buf, sizeof(addr_buf), "%016" PRIX64, r.address);
		dl->PushClipRect(ImVec2(cols[kColResultAddr].inner_x0, ry),
			ImVec2(cols[kColResultAddr].inner_x1, ry + kResultRowHeight), true);
		dl->AddText(code_fn, code_fs,
			ImVec2(cols[kColResultAddr].inner_x0, ry + (kResultRowHeight - code_fs) * 0.5f),
			aida::ui::with_alpha(t.text_address, a * row_entrance), addr_buf);
		dl->PopClipRect();

		std::string cur_str = memory_scanner::format_value(r.current_value, sc.config.value_type);
		ImU32 cur_col = value_color(r, a * row_entrance, t);
		float val_w = cols[kColResultValue].inner_x1 - cols[kColResultValue].inner_x0;
		dl->PushClipRect(ImVec2(cols[kColResultValue].inner_x0, ry),
			ImVec2(cols[kColResultValue].inner_x1, ry + kResultRowHeight), true);
		draw_clipped_text(dl, code_fn, code_fs,
			cols[kColResultValue].inner_x0, ry + (kResultRowHeight - code_fs) * 0.5f,
			val_w, cur_col, cur_str);
		dl->PopClipRect();

		if (!r.previous_value.empty()) {
			std::string prev_str = memory_scanner::format_value(r.previous_value, sc.config.value_type);
			float pw = cols[kColResultPrevious].inner_x1 - cols[kColResultPrevious].inner_x0;
			dl->PushClipRect(ImVec2(cols[kColResultPrevious].inner_x0, ry),
				ImVec2(cols[kColResultPrevious].inner_x1, ry + kResultRowHeight), true);
			draw_clipped_text(dl, code_fn, code_fs,
				cols[kColResultPrevious].inner_x0,
				ry + (kResultRowHeight - code_fs) * 0.5f,
				pw, aida::ui::with_alpha(t.text_dim, a * row_entrance), prev_str);
			dl->PopClipRect();
		}

		std::string mod_label = compose_module_label(r, regions_snapshot);
		ImU32 mod_col = aida::ui::with_alpha(t.text_secondary, a * row_entrance);
		if (mod_label.empty()) {
			mod_label = "Unknown";
			mod_col = aida::ui::with_alpha(t.text_dim, a * row_entrance);
		}
		float mod_w = cols[kColResultModule].inner_x1 - cols[kColResultModule].inner_x0;
		dl->PushClipRect(ImVec2(cols[kColResultModule].inner_x0, ry),
			ImVec2(cols[kColResultModule].inner_x1, ry + kResultRowHeight), true);
		draw_clipped_text(dl, body_fn, body_fs,
			cols[kColResultModule].inner_x0,
			ry + (kResultRowHeight - body_fs) * 0.5f,
			mod_w, mod_col, mod_label);
		dl->PopClipRect();

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			clicked_row = i;
		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
			dbl_click_row = i;
		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
			right_click_row = i;
	}

	ImGui::PopClipRect();

	auto capture_result = [&](int source_index) -> std::optional<memory_scanner::scan_result_t> {
		if (source_index < 0)
			return {};
		std::lock_guard<std::mutex> lock(sc.results_mutex);
		if (source_index >= static_cast<int>(sc.results.size()))
			return {};
		return sc.results[static_cast<std::size_t>(source_index)];
	};

	if (clicked_row >= 0) {
		handle_multi_select(ui.result_multi_sel, ui.last_result_anchor, clicked_row, total);
		select_result_rows(runtime, regions_snapshot, clicked_row);
		diag_logf("results row_click idx=%d multi_count=%zu",
			clicked_row, ui.result_multi_sel.size());
	}
	if (dbl_click_row >= 0) {
		int src_index = dbl_click_row;
		if (src_index >= 0 && src_index < static_cast<int>(ui.sorted_result_indices.size()))
			src_index = ui.sorted_result_indices[static_cast<size_t>(src_index)];
		if (const auto result = capture_result(src_index)) {
			uint64_t addr = result->address;
			diag_logf("results dbl_click_add addr=0x%llX", static_cast<unsigned long long>(addr));
			s_pending_add_addr.store(addr);
			s_pending_add_vtype.store(static_cast<int>(sc.config.value_type));
			s_open_add_dialog.store(true);
		}
	}
	if (right_click_row >= 0) {
		s_retained_result_owner_view = s_current_result_owner_view;
		int src_index = right_click_row;
		if (src_index >= 0 && src_index < static_cast<int>(ui.sorted_result_indices.size()))
			src_index = ui.sorted_result_indices[static_cast<size_t>(src_index)];
		if (const auto result = capture_result(src_index)) {
			uint64_t addr = result->address;
			ui.selected_result = right_click_row;
			if (ui.result_multi_sel.count(right_click_row) == 0) {
				ui.result_multi_sel.clear();
				ui.result_multi_sel.insert(right_click_row);
				ui.last_result_anchor = right_click_row;
			}
				ui.result_context = memory_interaction::capture_result(runtime, addr,
				src_index,
				memory_scanner::format_value(result->current_value, sc.config.value_type),
				memory_scanner::format_value(result->previous_value, sc.config.value_type),
				compose_module_label(*result, regions_snapshot));
				select_result_rows(runtime, regions_snapshot, right_click_row);
				ui.result_context = memory_interaction::selected();
			s_result_context_origin.store(0);
			s_open_result_ctx.store(true);
			diag_logf("results right_click row=%d addr=0x%llX",
				right_click_row, static_cast<unsigned long long>(addr));
		}
	}

	if (ui.result_pane_focused && memory_interaction::context_key_pressed() &&
		ui.selected_result >= 0) {
		s_retained_result_owner_view = s_current_result_owner_view;
		int source_index = ui.selected_result;
		if (source_index < static_cast<int>(ui.sorted_result_indices.size()))
			source_index = ui.sorted_result_indices[static_cast<std::size_t>(source_index)];
		if (const auto result = capture_result(source_index)) {
			ui.result_context = memory_interaction::capture_result(runtime,
				result->address, source_index,
				memory_scanner::format_value(result->current_value, sc.config.value_type),
				memory_scanner::format_value(result->previous_value, sc.config.value_type),
				compose_module_label(*result, regions_snapshot));
			select_result_rows(runtime, regions_snapshot, ui.selected_result);
			ui.result_context = memory_interaction::selected();
			s_result_context_origin.store(ImGui::IsKeyPressed(ImGuiKey_Menu, false) ? 1 : 2);
			s_open_result_ctx.store(true);
		}
	}

	if (include_sb) {
		float sb_x = ox + w - kScrollbarTrackW - 4.f;
		interactive_scrollbar(ui.result_sb, dl,
			sb_x, body_y, kScrollbarTrackW, body_h,
			content_h, body_h, a);
	}

	if (total == 0) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::memory;
		cfg.title = sc.has_initial_scan ? "No matches" : "Nothing scanned yet";
		cfg.body = sc.has_initial_scan
			? "Refine your filter or undo to widen the search."
			: "Pick a value type and a comparison, then start a scan.";
		aida::ui::empty_state::render(ImVec2(ox, body_y), ImVec2(w, body_h), cfg);
	} else if (sc.scanning.load() && total < 6) {
		float sk_y = body_y + static_cast<float>(total) * kResultRowHeight + 6.f;
		for (int s = 0; s < 4; ++s) {
			if (sk_y + 16.f > body_y + body_h) break;
			aida::ui::skeleton::render_block(dl,
				ImVec2(ox + 12.f, sk_y),
				ImVec2(ox + w - 24.f, sk_y + 14.f), 6.f, 1.4f);
			sk_y += 22.f;
		}
	}

	float pill_target = (ui.user_scrolled_up && total > visible_rows) ? 1.f : 0.f;
	ui.autoscroll_pill_alpha = aida::motion::smooth_lerp(
		ui.autoscroll_pill_alpha, pill_target, 12.f, dt);
	if (ui.autoscroll_pill_alpha > 0.02f) {
		float pa = ui.autoscroll_pill_alpha;
		const char* lbl = "Jump to bottom";
		ImFont* fnt = aida::ui::fonts::body();
		const float font_fs = aida::ui::fonts::size_or(fnt, ImGui::GetFontSize());
		ImVec2 pts = fnt->CalcTextSizeA(font_fs, FLT_MAX, 0.f, lbl);
		float pad_x = 12.f;
		float pw = pts.x + pad_x * 2.f + 14.f;
		float ph = 28.f;
		float px = ox + w * 0.5f - pw * 0.5f;
		float py = oy + h - ph - 14.f;
		ImVec2 pa_min(px, py - (1.f - pa) * 6.f);
		ImVec2 pa_max(px + pw, py + ph - (1.f - pa) * 6.f);

		dl->AddRectFilled(pa_min, pa_max,
			aida::ui::with_alpha(t.bg_overlay, a * pa * 0.95f), ph * 0.5f);
		dl->AddRect(pa_min, pa_max,
			aida::ui::with_alpha(t.accent_u32, a * pa), ph * 0.5f, 0, 1.f);

		float dot_cx = pa_min.x + pad_x;
		float dot_cy = (pa_min.y + pa_max.y) * 0.5f;
		dl->AddTriangleFilled(
			ImVec2(dot_cx - 5.f, dot_cy - 3.f),
			ImVec2(dot_cx + 5.f, dot_cy - 3.f),
			ImVec2(dot_cx, dot_cy + 4.f),
			aida::ui::with_alpha(t.accent_u32, a * pa));
		dl->AddText(fnt, font_fs,
			ImVec2(dot_cx + 10.f, pa_min.y + (ph - font_fs) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a * pa), lbl);

		ImGui::SetCursorScreenPos(pa_min);
		ImGui::PushID("##scroll_jump");
		ImGui::InvisibleButton("##sj_b", ImVec2(pw, ph));
		if (ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input())
		{
			ui.result_sb.target_scroll_y = max_scroll;
			ui.user_scrolled_up = false;
			diag_log("results jump_to_bottom");
		}
		ImGui::PopID();
	}
}

void render_address_pane(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	const bool compact_header = w < 460.f;
	const float header_h = compact_header ? 64.f : kAddrHeaderHeight;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + header_h),
		aida::ui::with_alpha(t.panel_header, a * 0.92f));
	dl->AddLine(ImVec2(ox, oy + header_h),
		ImVec2(ox + w, oy + header_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	ImFont* h_font = aida::ui::fonts::body_em();
	const float h_fs = aida::ui::fonts::size_or(h_font, ImGui::GetFontSize());
	dl->AddText(h_font, h_fs,
		ImVec2(ox + 12.f, oy + (kAddrHeaderHeight - h_fs) * 0.5f),
		aida::ui::with_alpha(t.text_primary, a), "Address List");

	size_t addr_count = 0;
	{
		std::lock_guard<std::mutex> lk(sc.address_mutex);
		addr_count = sc.address_list.size();
	}
	{
		char count_buf[40];
		snprintf(count_buf, sizeof(count_buf), "%zu items", addr_count);
		ImFont* body_fn = aida::ui::fonts::body();
		const float body_fs = aida::ui::fonts::size_or(body_fn, ImGui::GetFontSize());
		ImVec2 cts = body_fn->CalcTextSizeA(body_fs, FLT_MAX, 0.f, count_buf);
		dl->AddText(body_fn, body_fs,
			ImVec2(ox + 12.f + h_font->CalcTextSizeA(h_fs, FLT_MAX, 0.f, "Address List").x + 12.f,
				oy + (kAddrHeaderHeight - body_fs) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), count_buf);
		(void)cts;
	}

	ImFont* btn_fn = aida::ui::fonts::body();
	const float btn_fs = aida::ui::fonts::size_or(btn_fn, ImGui::GetFontSize());
	if (compact_header) {
		ImGui::SetCursorScreenPos(ImVec2(ox + 10.f, oy + 34.f));
		if (aida::ui::components::button("Add Address",
			aida::ui::components::button_kind_t::secondary,
			aida::ui::components::size_t_::sm, ImVec2(100.f, 26.f))) {
			s_pending_add_addr.store(0);
			s_pending_add_vtype.store(static_cast<int>(sc.config.value_type));
			s_open_add_dialog.store(true);
			diag_log("address add_manual_button");
		}
		ImGui::SetCursorScreenPos(ImVec2(ox + 118.f, oy + 37.f));
		bool auto_refresh = ui.auto_refresh;
		if (ImGui::Checkbox("Auto", &auto_refresh)) {
			ui.auto_refresh = auto_refresh;
			diag_logf("address auto_refresh_toggle now=%d", static_cast<int>(ui.auto_refresh));
		}
		if (ImGui::IsItemHovered())
			ImGui::SetTooltip("Automatically refresh retained address values");
	} else {
		float right_x = ox + w - 12.f;
	{
		const char* lbl = "Auto-refresh";
		ImVec2 lsz = btn_fn->CalcTextSizeA(btn_fs, FLT_MAX, 0.f, lbl);
		float track_w = 36.f;
		float gap = 6.f;
		float total_w = track_w + gap + lsz.x;
		float bx = right_x - total_w;
		float by = oy + (kAddrHeaderHeight - 20.f) * 0.5f;

		ImGui::PushID("##addr_auto_refresh");
		ImGui::SetCursorScreenPos(ImVec2(bx, by));
		ImGui::InvisibleButton("##af_b", ImVec2(total_w, 20.f));
		bool hov = ImGui::IsItemHovered();
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input();
		if (clk) {
			ui.auto_refresh = !ui.auto_refresh;
			diag_logf("address auto_refresh_toggle now=%d", static_cast<int>(ui.auto_refresh));
		}
		bool on = ui.auto_refresh;
		ImU32 trc = aida::ui::with_alpha(on ? t.accent_dim : t.bg_overlay, a);
		ImU32 brd = aida::ui::with_alpha(
			(on ? t.accent_u32 : (hov ? t.border_focus : t.border_strong)), a);
		ImVec2 ta(bx, by);
		ImVec2 tb(bx + track_w, by + 20.f);
		dl->AddRectFilled(ta, tb, trc, 10.f);
		dl->AddRect(ta, tb, brd, 10.f, 0, 1.f);
		float knob_r = (20.f - 4.f) * 0.5f;
		float knob_cx = on ? (bx + track_w - knob_r - 2.f) : (bx + knob_r + 2.f);
		float knob_cy = by + 10.f;
		dl->AddCircleFilled(ImVec2(knob_cx, knob_cy), knob_r,
			IM_COL32(240, 246, 255, 240), 16);
		ImU32 lbl_col = on
			? aida::ui::with_alpha(t.accent_u32, a)
			: aida::ui::with_alpha(t.text_dim, a);
		dl->AddText(btn_fn, btn_fs,
			ImVec2(tb.x + gap, by + (20.f - btn_fs) * 0.5f), lbl_col, lbl);
		ImGui::PopID();
		right_x -= (total_w + 16.f);
	}

	{
		const char* lbl = "Add Address";
		ImVec2 lsz = btn_fn->CalcTextSizeA(btn_fs, FLT_MAX, 0.f, lbl);
		float bw = lsz.x + 22.f;
		float bh = 24.f;
		float bx = right_x - bw;
		float by = oy + (kAddrHeaderHeight - bh) * 0.5f;
		ImGui::PushID("##addr_add_manual");
		ImGui::SetCursorScreenPos(ImVec2(bx, by));
		ImGui::InvisibleButton("##add_b", ImVec2(bw, bh));
		bool hov = ImGui::IsItemHovered();
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
			!ui_input_gate::popup_blocks_background_input();
		if (clk) {
			s_pending_add_addr.store(0);
			s_pending_add_vtype.store(static_cast<int>(sc.config.value_type));
			s_open_add_dialog.store(true);
			diag_log("address add_manual_button");
		}
		ImU32 bg = aida::ui::with_alpha(hov ? t.hover_wash : t.bg_overlay, a * 0.5f);
		ImU32 brd = aida::ui::with_alpha(hov ? t.accent_hover : t.border_strong, a);
		dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh), bg, bh * 0.5f);
		dl->AddRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh), brd, bh * 0.5f, 0, 1.f);
		ImU32 plus_col = aida::ui::with_alpha(hov ? t.accent_u32 : t.text_secondary, a);
		dl->AddText(btn_fn, btn_fs,
			ImVec2(bx + 10.f, by + (bh - btn_fs) * 0.5f), plus_col, lbl);
		ImGui::PopID();
		right_x -= (bw + 8.f);
	}
	}

	column_layout_t cols[5];
	int addr_total = static_cast<int>(addr_count);
	bool include_sb = addr_total > 0;
	compute_addr_columns(ox, w, cols, include_sb);

	float tbl_y0 = oy + header_h;
	dl->AddRectFilled(ImVec2(ox, tbl_y0),
		ImVec2(ox + w, tbl_y0 + kAddrTableHeaderH),
		aida::ui::with_alpha(t.bg_overlay, a * 0.40f));
	ImFont* col_fn = aida::ui::fonts::caption();
	if (!col_fn) col_fn = aida::ui::fonts::body();
	const float col_fs = aida::ui::fonts::size_or(col_fn, ImGui::GetFontSize());
	for (std::size_t c = 0; c < 5U; ++c) {
		if (!cols[c].title || cols[c].title[0] == '\0') continue;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const std::string header_semantic_id = studio_memory_surface_id(
			std::string("address-header-") + cols[c].title);
		aida::preview::semantics::register_region(header_semantic_id,
			"memory-scan-action", ImGui::GetID(header_semantic_id.c_str()),
			ImVec2(cols[c].x0, tbl_y0),
			ImVec2(cols[c].x1, tbl_y0 + kAddrTableHeaderH), false, true,
			studio_memory_parent_id());
#endif
		dl->AddText(col_fn, col_fs,
			ImVec2(cols[c].inner_x0, tbl_y0 + (kAddrTableHeaderH - col_fs) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), cols[c].title);
	}

	float body_y = tbl_y0 + kAddrTableHeaderH;
	float body_h = h - header_h - kAddrTableHeaderH;
	if (body_h < 1.f) body_h = 1.f;
	int visible_rows = static_cast<int>(body_h / kAddrRowHeight);
	if (visible_rows < 1) visible_rows = 1;

	int freeze_toggle_idx = -1;
	std::uint64_t freeze_toggle_address = 0;
	bool freeze_toggle_val = false;
	int delete_idx = -1;
	std::uint64_t delete_address = 0;
	int desc_edit_request_idx = -1;
	int value_edit_request_idx = -1;
	int change_type_request_idx = -1;
	int ctx_addr_request_row = -1;
	memory_interaction::context_t requested_context;
	const auto runtime = runtime_snapshot();

	int total = 0;
	{
		std::lock_guard<std::mutex> lock(sc.address_mutex);
		total = static_cast<int>(sc.address_list.size());
	}

	bool body_hover = ImGui::IsMouseHoveringRect(
		ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), false) &&
		!ui_input_gate::popup_blocks_background_input();
	if (body_hover) {
		if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
			ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			ui.address_pane_focused = true;
			ui.result_pane_focused = false;
		}
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) {
			ui.address_sb.target_scroll_y -= wheel * kAddrRowHeight * 3.f;
			diag_logf("address wheel=%.2f target=%.1f", wheel, ui.address_sb.target_scroll_y);
		}
	}

	float content_h = static_cast<float>(total) * kAddrRowHeight;
	float max_scroll = std::max(0.f, content_h - body_h);
	ui.address_sb.target_scroll_y = std::clamp(ui.address_sb.target_scroll_y, 0.f, max_scroll);
	float dt = aida::ui::clock::dt();
	ui_anim::smooth_scroll(ui.address_sb.scroll_y, ui.address_sb.target_scroll_y, 22.f, dt);

	int first_row = static_cast<int>(ui.address_sb.scroll_y / kAddrRowHeight);
	if (first_row < 0) first_row = 0;
	int last_row = std::min(total, first_row + visible_rows + 2);
	std::vector<std::pair<int, memory_scanner::address_entry_t>> visible_entries;
	{
		std::lock_guard<std::mutex> lock(sc.address_mutex);
		total = static_cast<int>(sc.address_list.size());
		last_row = std::min(total, first_row + visible_rows + 2);
		visible_entries.reserve(last_row > first_row
			? static_cast<std::size_t>(last_row - first_row) : 0);
		for (int index = first_row; index < last_row; ++index)
			visible_entries.emplace_back(index,
				sc.address_list[static_cast<std::size_t>(index)]);
	}

	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), true);

	ImFont* code_fn = aida::ui::fonts::code();
	const float code_fs = aida::ui::fonts::size_or(code_fn, ImGui::GetFontSize());
	ImFont* body_fn = aida::ui::fonts::body();
	const float body_fs = aida::ui::fonts::size_or(body_fn, ImGui::GetFontSize());

	float row_right_edge = include_sb ? (ox + w - kScrollbarTrackW - 6.f) : (ox + w);

	for (auto& [i, e] : visible_entries) {
		float ry = body_y + static_cast<float>(i) * kAddrRowHeight - ui.address_sb.scroll_y;
		if (ry + kAddrRowHeight < body_y || ry > body_y + body_h) continue;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const auto address_semantic_context = memory_interaction::capture_address(runtime,
			e.address, i, e.frozen,
			memory_scanner::format_value(e.last_value, e.value_type), e.target_pid,
			e.target_epoch, e.target_identity.process.creation_time_100ns);
		const std::string address_semantic_id = studio_memory_entity_id(
			"address", address_semantic_context);
		aida::preview::semantics::register_region(address_semantic_id,
			"memory-address-row", ImGui::GetID(address_semantic_id.c_str()),
			ImVec2(ox, ry), ImVec2(row_right_edge, ry + kAddrRowHeight), false, false,
			studio_memory_parent_id());
#endif

		bool sel = (ui.address_multi_sel.count(i) > 0) || (ui.selected_address == i);
		bool hov = ImGui::IsMouseHoveringRect(
			ImVec2(ox, ry), ImVec2(row_right_edge, ry + kAddrRowHeight), false) &&
			!ui_input_gate::popup_blocks_background_input();

		if (sel) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kAddrRowHeight),
				aida::ui::with_alpha(t.selection, a));
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + 3.f, ry + kAddrRowHeight),
				aida::ui::with_alpha(t.accent_u32, a));
		} else if (hov) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kAddrRowHeight),
				aida::ui::with_alpha(t.hover_wash, a));
		} else if (i & 1) {
			dl->AddRectFilled(ImVec2(ox, ry),
				ImVec2(ox + w, ry + kAddrRowHeight),
				aida::ui::with_alpha(t.hover_wash, 0.22f * a));
		}

		{
			float box_w = 16.f;
			float box_h = 16.f;
			float bx = cols[kColAddrFreeze].inner_x0 + 6.f;
			float by = ry + (kAddrRowHeight - box_h) * 0.5f;
			ImGui::PushID(i * 11 + 3);
			ImGui::SetCursorScreenPos(ImVec2(bx, by));
			ImGui::InvisibleButton("##fz", ImVec2(box_w, box_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::semantics::register_last_item(
				aida::preview::semantics::stable_id(address_semantic_id, "freeze"),
				"memory-scan-action", true, false, address_semantic_id);
#endif
			bool fz_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
				!ui_input_gate::popup_blocks_background_input();
			ImGui::PopID();
			bool fzhov = ImGui::IsMouseHoveringRect(
				ImVec2(bx, by), ImVec2(bx + box_w, by + box_h), false);
			if (fz_clicked) {
				const auto context = memory_interaction::capture_address(runtime,
					e.address, i, e.frozen,
					memory_scanner::format_value(e.last_value, e.value_type), e.target_pid,
					e.target_epoch, e.target_identity.process.creation_time_100ns);
				const auto capability = memory_interaction::evaluate(
					e.frozen ? memory_interaction::capability_t::unfreeze :
						memory_interaction::capability_t::freeze,
					context, runtime);
				if (capability.enabled) {
					freeze_toggle_idx = i;
					freeze_toggle_address = e.address;
					freeze_toggle_val = !e.frozen;
					diag_logf("address freeze_toggle idx=%d addr=0x%llX now=%d",
						i, static_cast<unsigned long long>(e.address),
						static_cast<int>(freeze_toggle_val));
				} else {
					toast_notification::push(capability.disabled_reason,
						toast_notification::toast_type_t::warning, 4.f);
				}
			}

			bool is_on = e.frozen;
			ImU32 box_bg = is_on
				? aida::ui::with_alpha(t.accent_dim, a)
				: aida::ui::with_alpha(t.bg_overlay, a);
			ImU32 box_brd = is_on
				? aida::ui::with_alpha(t.accent_u32, a)
				: aida::ui::with_alpha(fzhov ? t.accent_hover : t.border_strong, a);
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + box_w, by + box_h), box_bg, 4.f);
			dl->AddRect(ImVec2(bx, by), ImVec2(bx + box_w, by + box_h), box_brd, 4.f, 0, 1.5f);
			if (is_on) {
				ImU32 chk = aida::ui::with_alpha(t.text_primary, a);
				dl->AddLine(ImVec2(bx + 4.f, by + 8.f), ImVec2(bx + 7.f, by + 12.f), chk, 1.7f);
				dl->AddLine(ImVec2(bx + 7.f, by + 12.f), ImVec2(bx + 12.f, by + 5.f), chk, 1.7f);
			}
			float lock_x = bx + box_w + 8.f;
			float lock_y = ry + (kAddrRowHeight - body_fs) * 0.5f;
			const char* lock_lbl = is_on ? "Locked" : "Free";
			ImU32 lock_col = is_on
				? aida::ui::with_alpha(t.accent_u32, a)
				: aida::ui::with_alpha(t.text_dim, a);
			dl->PushClipRect(
				ImVec2(lock_x, ry),
				ImVec2(cols[kColAddrFreeze].inner_x1, ry + kAddrRowHeight), true);
			dl->AddText(body_fn, body_fs, ImVec2(lock_x, lock_y), lock_col, lock_lbl);
			dl->PopClipRect();
		}

		{
			std::string disp = e.description.empty()
				? std::string("<no description>")
				: e.description;
			ImU32 col = e.description.empty()
				? aida::ui::with_alpha(t.text_dim, a)
				: aida::ui::with_alpha(t.text_primary, a);
			float maxw = cols[kColAddrDesc].inner_x1 - cols[kColAddrDesc].inner_x0;
			dl->PushClipRect(
				ImVec2(cols[kColAddrDesc].inner_x0, ry),
				ImVec2(cols[kColAddrDesc].inner_x1, ry + kAddrRowHeight), true);
			draw_clipped_text(dl, body_fn, body_fs,
				cols[kColAddrDesc].inner_x0,
				ry + (kAddrRowHeight - body_fs) * 0.5f,
				maxw, col, disp);
			dl->PopClipRect();
		}

		{
			char abuf[24];
			if (w < 360.f)
				snprintf(abuf, sizeof(abuf), "%" PRIX64, e.address);
			else
				snprintf(abuf, sizeof(abuf), "%016" PRIX64, e.address);
			float maxw = cols[kColAddrAddress].inner_x1 - cols[kColAddrAddress].inner_x0;
			dl->PushClipRect(
				ImVec2(cols[kColAddrAddress].inner_x0, ry),
				ImVec2(cols[kColAddrAddress].inner_x1, ry + kAddrRowHeight), true);
			draw_clipped_text(dl, code_fn, code_fs,
				cols[kColAddrAddress].inner_x0,
				ry + (kAddrRowHeight - code_fs) * 0.5f,
				maxw, aida::ui::with_alpha(t.text_address, a),
				std::string(abuf));
			dl->PopClipRect();
		}

		{
			const char* tn = memory_scanner::value_type_name(e.value_type);
			float maxw = cols[kColAddrType].inner_x1 - cols[kColAddrType].inner_x0;
			dl->PushClipRect(
				ImVec2(cols[kColAddrType].inner_x0, ry),
				ImVec2(cols[kColAddrType].inner_x1, ry + kAddrRowHeight), true);
			draw_clipped_text(dl, body_fn, body_fs,
				cols[kColAddrType].inner_x0,
				ry + (kAddrRowHeight - body_fs) * 0.5f,
				maxw, aida::ui::with_alpha(t.text_secondary, a),
				std::string(tn));
			dl->PopClipRect();
		}

		{
			std::string val_str = memory_scanner::format_value(e.last_value, e.value_type);
			float maxw = cols[kColAddrValue].inner_x1 - cols[kColAddrValue].inner_x0;
			ImU32 vcol = aida::ui::with_alpha(e.frozen ? t.accent_u32 : t.success, a);
			dl->PushClipRect(
				ImVec2(cols[kColAddrValue].inner_x0, ry),
				ImVec2(cols[kColAddrValue].inner_x1, ry + kAddrRowHeight), true);
			draw_clipped_text(dl, code_fn, code_fs,
				cols[kColAddrValue].inner_x0,
				ry + (kAddrRowHeight - code_fs) * 0.5f,
				maxw, vcol, val_str);
			dl->PopClipRect();
		}

		float mx_now = ImGui::GetMousePos().x;
		bool in_freeze_col = (mx_now >= cols[kColAddrFreeze].x0 && mx_now < cols[kColAddrFreeze].x1);

		if (hov && !in_freeze_col && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			handle_multi_select(ui.address_multi_sel, ui.last_address_anchor, i, total);
			select_address_rows(runtime, i);
			diag_logf("address row_click idx=%d multi=%zu",
				i, ui.address_multi_sel.size());
		}

		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			float mx = ImGui::GetMousePos().x;
			if (mx >= cols[kColAddrDesc].x0 && mx < cols[kColAddrDesc].x1) {
				desc_edit_request_idx = i;
				diag_logf("address desc_edit_request idx=%d", i);
			} else if (mx >= cols[kColAddrValue].x0 && mx < cols[kColAddrValue].x1) {
				const auto context = memory_interaction::capture_address(runtime,
					e.address, i, e.frozen,
					memory_scanner::format_value(e.last_value, e.value_type), e.target_pid,
					e.target_epoch, e.target_identity.process.creation_time_100ns);
				const auto capability = memory_interaction::evaluate(
					memory_interaction::capability_t::change_value, context, runtime);
				if (capability.enabled) {
					value_edit_request_idx = i;
					diag_logf("address value_edit_request idx=%d", i);
				} else {
					toast_notification::push(capability.disabled_reason,
						toast_notification::toast_type_t::warning, 4.f);
				}
			} else if (mx >= cols[kColAddrType].x0 && mx < cols[kColAddrType].x1) {
				change_type_request_idx = i;
				diag_logf("address change_type_request idx=%d", i);
			}
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			s_retained_address_owner_view = s_current_address_owner_view;
			ctx_addr_request_row = i;
			requested_context = memory_interaction::capture_address(runtime,
				e.address, i, e.frozen,
				memory_scanner::format_value(e.last_value, e.value_type), e.target_pid,
				e.target_epoch, e.target_identity.process.creation_time_100ns);
			s_address_context_origin.store(0);
			ui.selected_address = i;
			if (ui.address_multi_sel.count(i) == 0) {
				ui.address_multi_sel.clear();
				ui.address_multi_sel.insert(i);
				ui.last_address_anchor = i;
			}
			select_address_rows(runtime, i);
			requested_context = memory_interaction::selected();
			diag_logf("address right_click idx=%d addr=0x%llX",
				i, static_cast<unsigned long long>(e.address));
		}

		if (sel && ImGui::IsKeyPressed(ImGuiKey_Delete, false) && !input_is_active()) {
			delete_idx = i;
			delete_address = e.address;
			ui.selected_address = -1;
			diag_logf("address key_delete idx=%d", i);
			break;
		}
	}

	auto capture_address_entry = [&](int index) -> std::optional<memory_scanner::address_entry_t> {
		if (index < 0)
			return {};
		std::lock_guard<std::mutex> lock(sc.address_mutex);
		if (index >= static_cast<int>(sc.address_list.size()))
			return {};
		return sc.address_list[static_cast<std::size_t>(index)];
	};
	if (ui.address_pane_focused && memory_interaction::context_key_pressed() &&
		ui.selected_address >= 0) {
		s_retained_address_owner_view = s_current_address_owner_view;
		const int selected = ui.selected_address;
		if (const auto entry = capture_address_entry(selected)) {
			ctx_addr_request_row = selected;
			requested_context = memory_interaction::capture_address(runtime,
				entry->address, selected, entry->frozen,
				memory_scanner::format_value(entry->last_value, entry->value_type),
				entry->target_pid, entry->target_epoch,
				entry->target_identity.process.creation_time_100ns);
			select_address_rows(runtime, selected);
			requested_context = memory_interaction::selected();
			s_address_context_origin.store(ImGui::IsKeyPressed(ImGuiKey_Menu, false) ? 1 : 2);
		}
	}

	ImGui::PopClipRect();

	if (include_sb) {
		float sb_x = ox + w - kScrollbarTrackW - 4.f;
		interactive_scrollbar(ui.address_sb, dl,
			sb_x, body_y, kScrollbarTrackW, body_h,
			content_h, body_h, a);
	}

	if (total == 0) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::dots;
		cfg.title = "Watchlist is empty";
		cfg.body  = "Double-click a result to track. Right-click for more options.";
		aida::ui::empty_state::render(ImVec2(ox, body_y), ImVec2(w, body_h), cfg);
	}

	if (ctx_addr_request_row >= 0) {
		ui.address_context = std::move(requested_context);
		s_open_address_ctx.store(true);
	}

	if (desc_edit_request_idx >= 0) {
		if (const auto entry = capture_address_entry(desc_edit_request_idx)) {
			ui.desc_edit.active = true;
			ui.desc_edit.address_index = desc_edit_request_idx;
			ui.desc_edit.open_from_add_dialog = false;
			_snprintf_s(ui.desc_edit.buf, sizeof(ui.desc_edit.buf), _TRUNCATE,
				"%s", entry->description.c_str());
		}
	}

	if (value_edit_request_idx >= 0) {
		if (const auto entry = capture_address_entry(value_edit_request_idx)) {
			s_pending_edit_value_index.store(value_edit_request_idx);
			std::string vs = memory_scanner::format_value(entry->last_value, entry->value_type);
			_snprintf_s(s_edit_value_buf, sizeof(s_edit_value_buf), _TRUNCATE, "%s", vs.c_str());
		}
	}

	if (change_type_request_idx >= 0) {
		if (const auto entry = capture_address_entry(change_type_request_idx)) {
			s_pending_change_type_index.store(change_type_request_idx);
			s_pending_change_type_value = static_cast<int>(entry->value_type);
		}
	}

	if (freeze_toggle_idx >= 0) {
		const auto current = capture_address_entry(freeze_toggle_idx);
		if (current && current->address == freeze_toggle_address)
			memory_scanner::freeze_address(static_cast<size_t>(freeze_toggle_idx), freeze_toggle_val);
	}
	if (delete_idx >= 0) {
		const auto current = capture_address_entry(delete_idx);
		if (current && current->address == delete_address) {
				auto context = memory_interaction::capture_address(runtime,
					current->address, delete_idx, current->frozen,
					memory_scanner::format_value(current->last_value, current->value_type),
					current->target_pid, current->target_epoch,
					current->target_identity.process.creation_time_100ns);
			ui.address_context = context;
			auto retained = make_memory_actions("memory.value_scan.address",
				context, runtime, {{"memory.address.remove",
					memory_interaction::capability_t::remove}});
			const auto executed = aida::ui::application_ui::execute_retained_entity_action(
				"memory.address.remove", aida::ui::action_invocation_source_t::shortcut,
				retained);
			static_cast<void>(executed);
		}
	}
}

void render_splitter(ImDrawList* dl, float ox, float oy, float w, float a,
                     float& result_h, float& addr_h, float pane_height)
{
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float min_h = 80.f;
	float total = pane_height;

	float split_y = oy;
	ImVec2 a_min(ox + 2.f, split_y);
	ImVec2 a_max(ox + w - 2.f, split_y + kSplitterThickness);

	ImGui::PushID("##scanner_splitter");
	ImGui::SetCursorScreenPos(a_min);
	ImGui::InvisibleButton("##spl", ImVec2(a_max.x - a_min.x, a_max.y - a_min.y));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::semantics::register_last_item(
		studio_memory_surface_id("splitter"), "memory-scan-action", false, false,
		studio_memory_parent_id());
#endif
	bool hov = ImGui::IsItemHovered();
	bool act = ImGui::IsItemActive();
	bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) &&
		!ui_input_gate::popup_blocks_background_input();
	ImGui::PopID();

	if (clicked) {
		ui.splitter_dragging = true;
		diag_log("splitter drag_begin");
	}
	if (ui.splitter_dragging && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
		ui.splitter_dragging = false;
		diag_logf("splitter drag_end ratio=%.3f", ui.result_pane_ratio);
	}
	if (ui.splitter_dragging) {
		float dy = ImGui::GetIO().MouseDelta.y;
		if (std::abs(dy) > 0.5f) {
			ui.result_pane_ratio += dy / total;
			ui.result_pane_ratio = std::clamp(ui.result_pane_ratio,
				min_h / total, 1.f - min_h / total);
		}
	}
	float target = (hov || act) ? 1.f : 0.f;
	ui.splitter_press_anim = ui_anim::smooth_lerp(
		ui.splitter_press_anim, target, 14.f, aida::ui::clock::dt());

	if (hov || act) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);

	ImU32 base = aida::ui::with_alpha(t.border_strong, 0.55f * a);
	ImU32 hi   = aida::ui::with_alpha(t.accent_u32, 0.95f * a);
	ImU32 cur = aida::ui::mix(base, hi, ui.splitter_press_anim);
	dl->AddRectFilled(a_min, a_max, cur, kSplitterThickness * 0.5f);

	if (ui.splitter_press_anim > 0.04f) {
		float cx = (a_min.x + a_max.x) * 0.5f;
		float cy = (a_min.y + a_max.y) * 0.5f;
		ImU32 dotc = aida::ui::with_alpha(t.text_primary, 0.85f * ui.splitter_press_anim * a);
		for (int i = -1; i <= 1; ++i) {
			dl->AddCircleFilled(
				ImVec2(cx + static_cast<float>(i) * 8.f, cy), 1.6f, dotc, 12);
		}
	}

	result_h = total * ui.result_pane_ratio;
	addr_h   = total - result_h - kSplitterThickness;
}

void process_add_dialog() {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	if (s_open_add_dialog.load()) {
		s_open_add_dialog.store(false);
		ImGui::OpenPopup("##value_scan_add_dialog");
		ui.desc_edit.buf[0] = '\0';
		ui.desc_edit.pending_add_address = s_pending_add_addr.load();
		ui.desc_edit.pending_add_value_type = s_pending_add_vtype.load();
		ui.desc_edit.open_from_add_dialog = true;
		diag_logf("dialog add_open addr=0x%llX vtype=%d",
			static_cast<unsigned long long>(ui.desc_edit.pending_add_address),
			ui.desc_edit.pending_add_value_type);
	}

	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 16.f));

	if (aida::ui::design::begin_dialog_exact("##value_scan_add_dialog",
		ImVec2(500.f, 440.f), ImVec2(360.f, 300.f), nullptr,
		ImGuiWindowFlags_NoTitleBar))
	{
		const float footer_height = aida::ui::design::dialog_footer_reserve_height(
			"Add", "Cancel");
		aida::ui::design::begin_dialog_body("value_scan_add_dialog_body",
			footer_height);
		ImFont* h_fn = aida::ui::fonts::h2();
		ImGui::PushFont(h_fn);
		ImGui::TextUnformatted("Add to address list");
		ImGui::PopFont();

		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		char addr_buf[40];
		snprintf(addr_buf, sizeof(addr_buf), "Address: 0x%016llX",
			static_cast<unsigned long long>(ui.desc_edit.pending_add_address));
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary), "%s", addr_buf);
		ImGui::Spacing();

		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim), "Description (optional)");
		ImGui::SetNextItemWidth(-1.f);
		bool focus_now = ImGui::IsWindowAppearing();
		if (focus_now) ImGui::SetKeyboardFocusHere();
		const bool enter_submit = ImGui::InputText("##add_desc", ui.desc_edit.buf,
			sizeof(ui.desc_edit.buf), ImGuiInputTextFlags_EnterReturnsTrue);

		ImGui::Spacing();
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim), "Type");
		const char* current_name = memory_scanner::value_type_name(
			static_cast<memory_scanner::value_type_t>(ui.desc_edit.pending_add_value_type));
		ImGui::SetNextItemWidth(-1.f);
		if (ImGui::BeginCombo("##add_type", current_name)) {
			for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
				bool sel = (ui.desc_edit.pending_add_value_type == i);
				if (ImGui::Selectable(memory_scanner::value_type_name(
					static_cast<memory_scanner::value_type_t>(i)), sel))
				{
					ui.desc_edit.pending_add_value_type = i;
				}
			}
			ImGui::EndCombo();
		}

		aida::ui::design::end_dialog_body();
		const auto footer = aida::ui::design::dialog_footer(
			"value_scan_add_dialog_footer", "Add", true, false, "Cancel");
		if (footer.cancelled) {
			diag_log("dialog add_cancel");
			ImGui::CloseCurrentPopup();
		} else if (footer.confirmed || enter_submit) {
			std::string desc(ui.desc_edit.buf);
			memory_scanner::add_address(
				ui.desc_edit.pending_add_address, desc,
				static_cast<memory_scanner::value_type_t>(
					ui.desc_edit.pending_add_value_type));
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner add_address invoked");
			toast_notification::push("Added to address list.",
				toast_notification::toast_type_t::success, 2.5f);
			diag_logf("dialog add_submit desc='%s' vtype=%d",
				desc.c_str(), ui.desc_edit.pending_add_value_type);
			ImGui::CloseCurrentPopup();
		}
		(void)sc;
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

void process_edit_description_dialog() {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	if (!ui.desc_edit.active || ui.desc_edit.open_from_add_dialog) return;

	static bool s_ed_was_open = false;
	bool is_open_now = ImGui::IsPopupOpen("##value_scan_edit_desc");
	if (s_ed_was_open && !is_open_now) {
		ui.desc_edit.active = false;
		s_ed_was_open = false;
		diag_log("dialog edit_desc_external_close");
		return;
	}
	if (!is_open_now) {
		ImGui::OpenPopup("##value_scan_edit_desc");
	}
	s_ed_was_open = true;

	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 16.f));

	if (aida::ui::design::begin_dialog_exact("##value_scan_edit_desc",
		ImVec2(520.f, 380.f), ImVec2(360.f, 280.f), nullptr,
		ImGuiWindowFlags_NoTitleBar))
	{
		const float footer_height = aida::ui::design::dialog_footer_reserve_height(
			"Save", "Cancel");
		aida::ui::design::begin_dialog_body("value_scan_edit_desc_body",
			footer_height);
		ImFont* h_fn = aida::ui::fonts::h2();
		ImGui::PushFont(h_fn);
		ImGui::TextUnformatted("Edit description");
		ImGui::PopFont();
		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		uint64_t cur_addr = 0;
		{
			std::lock_guard<std::mutex> lk(sc.address_mutex);
			if (ui.desc_edit.address_index >= 0 &&
				ui.desc_edit.address_index < static_cast<int>(sc.address_list.size()))
			{
				cur_addr = sc.address_list[static_cast<size_t>(ui.desc_edit.address_index)].address;
			}
		}
		char abuf[40];
		snprintf(abuf, sizeof(abuf), "Address: 0x%016llX",
			static_cast<unsigned long long>(cur_addr));
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary), "%s", abuf);

		ImGui::Spacing();
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim), "Description");
		ImGui::SetNextItemWidth(-1.f);
		if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
		const bool enter_submit = ImGui::InputText("##edit_desc_in",
			ui.desc_edit.buf, sizeof(ui.desc_edit.buf),
			ImGuiInputTextFlags_EnterReturnsTrue);
		aida::ui::design::end_dialog_body();
		const auto footer = aida::ui::design::dialog_footer(
			"value_scan_edit_desc_footer", "Save", true, false, "Cancel");

		if (footer.cancelled) {
			diag_log("dialog edit_desc_cancel");
			ImGui::CloseCurrentPopup();
			ui.desc_edit.active = false;
			s_ed_was_open = false;
		} else if (footer.confirmed || enter_submit) {
			std::string val(ui.desc_edit.buf);
			{
				std::lock_guard<std::mutex> lk(sc.address_mutex);
				if (ui.desc_edit.address_index >= 0 &&
					ui.desc_edit.address_index < static_cast<int>(sc.address_list.size()))
				{
					sc.address_list[static_cast<size_t>(ui.desc_edit.address_index)].description = val;
				}
			}
			diag_logf("dialog edit_desc_save idx=%d desc='%s'",
				ui.desc_edit.address_index, val.c_str());
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner edit_description");
			ImGui::CloseCurrentPopup();
			ui.desc_edit.active = false;
			s_ed_was_open = false;
		}
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

void process_edit_value_dialog() {
	auto& sc = memory_scanner::g_state;
	int idx = s_pending_edit_value_index.load();
	auto completion = std::atomic_exchange_explicit(&s_value_write_completion,
		std::shared_ptr<const value_write_result_t>{}, std::memory_order_acq_rel);
	if (completion) {
		toast_notification::push(completion->detail,
			completion->verified ? toast_notification::toast_type_t::success
				: toast_notification::toast_type_t::error,
			completion->verified ? 3.f : 6.f);
		if (completion->verified && idx == completion->context.index)
			s_value_write_close_requested = true;
	}
	if (idx < 0) {
		s_value_write_close_requested = false;
		return;
	}

	static bool s_ev_was_open = false;
	bool is_open_now = ImGui::IsPopupOpen("##value_scan_edit_value");
	if (s_ev_was_open && !is_open_now) {
		s_pending_edit_value_index.store(-1);
		s_ev_was_open = false;
		diag_log("dialog edit_value_external_close");
		return;
	}
	if (!is_open_now) {
		ImGui::OpenPopup("##value_scan_edit_value");
	}
	s_ev_was_open = true;

	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 16.f));

	if (aida::ui::design::begin_dialog_exact("##value_scan_edit_value",
		ImVec2(520.f, 440.f), ImVec2(360.f, 300.f), nullptr,
		ImGuiWindowFlags_NoTitleBar))
	{
		const bool write_pending = s_value_write_pending.load(std::memory_order_acquire);
		const float footer_height = aida::ui::design::dialog_footer_reserve_height(
			"Write", "Cancel");
		aida::ui::design::begin_dialog_body("value_scan_edit_value_body",
			footer_height);
		if (s_value_write_close_requested) {
			s_value_write_close_requested = false;
			s_pending_edit_value_index.store(-1);
			s_ev_was_open = false;
			ImGui::CloseCurrentPopup();
		}
		ImFont* h_fn = aida::ui::fonts::h2();
		ImGui::PushFont(h_fn);
		ImGui::TextUnformatted("Change value");
		ImGui::PopFont();
		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		uint64_t addr_v = 0;
		memory_scanner::value_type_t vt = memory_scanner::value_type_t::int32_val;
		std::uint32_t target_pid = 0;
		std::uint64_t target_epoch = 0;
		std::uint64_t process_creation_time_100ns = 0;
		bool frozen = false;
		{
			std::lock_guard<std::mutex> lk(sc.address_mutex);
			if (idx >= 0 && idx < static_cast<int>(sc.address_list.size())) {
				const auto& entry = sc.address_list[static_cast<size_t>(idx)];
				addr_v = entry.address;
				vt = entry.value_type;
				target_pid = entry.target_pid;
				target_epoch = entry.target_epoch;
				process_creation_time_100ns = entry.target_identity.process.creation_time_100ns;
				frozen = entry.frozen;
			}
		}
		char abuf[64];
		snprintf(abuf, sizeof(abuf), "0x%016llX  (%s)",
			static_cast<unsigned long long>(addr_v),
			memory_scanner::value_type_name(vt));
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary), "%s", abuf);
		ImGui::Spacing();
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim), "New value");
		ImGui::SetNextItemWidth(-1.f);
		if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
		ImGui::InputText("##edit_value_in", s_edit_value_buf, sizeof(s_edit_value_buf));
		if (write_pending) ImGui::TextDisabled("Writing, verifying, and retaining rollback bytes...");
		aida::ui::design::end_dialog_body();
		const auto footer = aida::ui::design::dialog_footer(
			"value_scan_edit_value_footer", "Write", !write_pending, true,
			"Cancel", !write_pending);

		if (footer.cancelled) {
			diag_log("dialog edit_value_cancel");
			ImGui::CloseCurrentPopup();
			s_pending_edit_value_index.store(-1);
			s_ev_was_open = false;
		} else if (footer.confirmed) {
			std::string text(s_edit_value_buf);
			const auto runtime = runtime_snapshot();
			const auto context = memory_interaction::capture_address(runtime,
				addr_v, idx, frozen, {}, target_pid, target_epoch,
				process_creation_time_100ns);
			const auto capability = memory_interaction::evaluate(
				memory_interaction::capability_t::change_value, context, runtime);
			if (!capability.enabled) {
				toast_notification::push(capability.disabled_reason,
					toast_notification::toast_type_t::warning, 4.f);
			} else {
				const auto expected_bytes = memory_scanner::parse_value(text, vt, sc.config.hex_input);
				if (expected_bytes.empty()) {
					toast_notification::push("Value is invalid for the selected type.",
						toast_notification::toast_type_t::error, 4.f);
				} else {
					std::string error;
					if (!request_value_write(context, vt, expected_bytes, error))
						toast_notification::push(error,
							toast_notification::toast_type_t::error, 5.f);
					else {
						diag_logf("dialog edit_value_queued addr=0x%llX pid=%u revision=%llu",
							static_cast<unsigned long long>(addr_v), context.target_pid,
							static_cast<unsigned long long>(context.scan_revision));
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
						anti_tamper::webhook::write_log("scan_audit",
							"[scan_audit] memory_scanner write_value queued_for_worker_readback");
#endif
					}
				}
			}
		}
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

void process_change_type_dialog() {
	auto& sc = memory_scanner::g_state;
	int idx = s_pending_change_type_index.load();
	if (idx < 0) return;

	static bool s_ct_was_open = false;
	bool is_open_now = ImGui::IsPopupOpen("##value_scan_change_type");
	if (s_ct_was_open && !is_open_now) {
		s_pending_change_type_index.store(-1);
		s_ct_was_open = false;
		diag_log("dialog change_type_external_close");
		return;
	}
	if (!is_open_now) {
		ImGui::OpenPopup("##value_scan_change_type");
	}
	s_ct_was_open = true;

	const auto& t = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 16.f));

	if (aida::ui::design::begin_dialog_exact("##value_scan_change_type",
		ImVec2(500.f, 360.f), ImVec2(360.f, 260.f), nullptr,
		ImGuiWindowFlags_NoTitleBar))
	{
		const float footer_height = aida::ui::design::dialog_footer_reserve_height(
			"Apply", "Cancel");
		aida::ui::design::begin_dialog_body("value_scan_change_type_body",
			footer_height);
		ImFont* h_fn = aida::ui::fonts::h2();
		ImGui::PushFont(h_fn);
		ImGui::TextUnformatted("Change type");
		ImGui::PopFont();
		ImGui::Spacing();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		const char* current_name = memory_scanner::value_type_name(
			static_cast<memory_scanner::value_type_t>(s_pending_change_type_value));
		ImGui::SetNextItemWidth(-1.f);
		if (ImGui::BeginCombo("##chtype_combo", current_name)) {
			for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
				bool sel = (s_pending_change_type_value == i);
				if (ImGui::Selectable(memory_scanner::value_type_name(
					static_cast<memory_scanner::value_type_t>(i)), sel))
				{
					s_pending_change_type_value = i;
				}
			}
			ImGui::EndCombo();
		}

		aida::ui::design::end_dialog_body();
		const auto footer = aida::ui::design::dialog_footer(
			"value_scan_change_type_footer", "Apply", true, false, "Cancel");

		if (footer.cancelled) {
			diag_log("dialog change_type_cancel");
			ImGui::CloseCurrentPopup();
			s_pending_change_type_index.store(-1);
			s_ct_was_open = false;
		} else if (footer.confirmed) {
			{
				std::lock_guard<std::mutex> lk(sc.address_mutex);
				if (idx >= 0 && idx < static_cast<int>(sc.address_list.size())) {
					sc.address_list[static_cast<size_t>(idx)].value_type =
						static_cast<memory_scanner::value_type_t>(s_pending_change_type_value);
					sc.address_list[static_cast<size_t>(idx)].last_value.clear();
					sc.address_list[static_cast<size_t>(idx)].freeze_value.clear();
				}
			}
			diag_logf("dialog change_type_save idx=%d vtype=%d",
				idx, s_pending_change_type_value);
			ImGui::CloseCurrentPopup();
			s_pending_change_type_index.store(-1);
			s_ct_was_open = false;
		}
		ImGui::EndPopup();
	}

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

void process_result_context_menu() {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto runtime = runtime_snapshot();
	const auto context = ui.result_context;
	const auto action_contexts = memory_action_contexts(context);
	uint64_t ctx_addr = context.address;
	if (s_open_result_ctx.exchange(false))
		open_memory_actions("memory.value_scan.result", context, runtime, {
			{"memory.result.add_address", memory_interaction::capability_t::add_to_address_list},
			{"memory.result.compare_selected", memory_interaction::capability_t::compare_selected},
			{"memory.result.export_selected", memory_interaction::capability_t::export_selected},
			{"memory.entity.open_hex", memory_interaction::capability_t::open_hex},
			{"memory.entity.open_disassembly", memory_interaction::capability_t::open_disassembly},
			{"memory.entity.copy_address", memory_interaction::capability_t::copy_address},
			{"memory.entity.copy_value", memory_interaction::capability_t::copy_value},
			{"memory.entity.copy_previous", memory_interaction::capability_t::copy_previous_value},
			{"memory.entity.copy_module_offset", memory_interaction::capability_t::copy_module_offset},
			{"memory.entity.stage_patch", memory_interaction::capability_t::stage_patch}},
			retained_origin(s_result_context_origin.load()));
	aida::ui::application_ui::render_retained_entity_context_menu("memory.value_scan.result");
	s_consumed_memory_action = aida::ui::application_ui::consume_retained_entity_action(
		"memory.value_scan.result", memory_action_entity_id(context, action_contexts).c_str());
	if (!s_consumed_memory_action.empty()) {
		const size_t multi_count = action_contexts.size();
		if (s_consumed_memory_action == "memory.result.add_address") {
			diag_logf("ctx_result add_to_list count=%zu primary_addr=0x%llX",
				multi_count, static_cast<unsigned long long>(ctx_addr));
			std::vector<uint64_t> addresses;
			addresses.reserve(action_contexts.size());
			for (const auto& item : action_contexts) addresses.push_back(item.address);
			if (addresses.size() == 1) {
				s_pending_add_addr.store(addresses[0]);
				s_pending_add_vtype.store(static_cast<int>(sc.config.value_type));
				s_open_add_dialog.store(true);
			} else {
				for (uint64_t a_ : addresses)
					memory_scanner::add_address(a_, "", sc.config.value_type);
				char msg[64];
				snprintf(msg, sizeof(msg), "Added %zu addresses.", addresses.size());
				toast_notification::push(msg,
					toast_notification::toast_type_t::success, 2.5f);
			}
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner ctx add_to_list");
		}
		if (context_item("Open in Hex view", memory_interaction::capability_t::open_hex,
			context, runtime)) {
			diag_logf("ctx_result open_hex addr=0x%llX",
				static_cast<unsigned long long>(ctx_addr));
			if (ctx_addr != 0) {
				const auto context = disasm_view::capture_selected_workspace();
				if (hex_view::request_live_memory(context, ctx_addr, 256))
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] memory_scanner ctx open_hex");
			}
		}
		if (context_item("Open in Disassembly", memory_interaction::capability_t::open_disassembly,
			context, runtime)) {
			diag_logf("ctx_result open_disasm addr=0x%llX",
				static_cast<unsigned long long>(ctx_addr));
			if (ctx_addr != 0) {
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
				disasm_view::goto_address(ctx_addr,
					disasm_view::capture_selected_workspace());
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] memory_scanner ctx open_disasm");
			}
		}
		if (s_consumed_memory_action == "memory.entity.copy_address") {
			copy_memory_addresses(action_contexts);
			diag_log("ctx_result copy_address");
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] memory_scanner ctx copy_address");
		}
		if (s_consumed_memory_action == "memory.entity.copy_value")
			copy_memory_text(action_contexts, [](const auto& item) -> const std::string& {
				return item.value;
			});
		if (s_consumed_memory_action == "memory.entity.copy_previous")
			copy_memory_text(action_contexts, [](const auto& item) -> const std::string& {
				return item.previous_value;
			});
		if (s_consumed_memory_action == "memory.entity.copy_module_offset")
			copy_memory_text(action_contexts, [](const auto& item) -> const std::string& {
				return item.module_offset;
			});
		if (context_item("Stage patch in Patches view...", memory_interaction::capability_t::stage_patch,
			context, runtime)) {
			std::string error;
			const auto extent = static_cast<std::uint64_t>(
				memory_scanner::value_type_size(sc.config.value_type));
			if (debugger_view::stage_patch_review(ctx_addr, extent,
				"Staged from Value Scan result", &error))
				aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.debug.patches"));
			else
				toast_notification::push(error.c_str(), toast_notification::toast_type_t::warning, 4.f);
		}
	}
	s_consumed_memory_action.clear();
}

void process_address_context_menu() {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto runtime = runtime_snapshot();
	auto context = ui.address_context;
	const auto action_contexts = memory_action_contexts(context);
	uint64_t ctx_addr = context.address;
	int ctx_row = find_address_index(context);
	if (ctx_row < 0)
		context.kind = memory_interaction::kind_t::none;
	if (s_open_address_ctx.exchange(false))
		open_memory_actions("memory.value_scan.address", context, runtime, {
			{"memory.address.edit_description", memory_interaction::capability_t::edit_description},
			{"memory.address.change_type", memory_interaction::capability_t::change_type},
			{"memory.address.change_value", memory_interaction::capability_t::change_value},
			{context.frozen ? "memory.address.unfreeze" : "memory.address.freeze",
				context.frozen ? memory_interaction::capability_t::unfreeze : memory_interaction::capability_t::freeze},
			{"memory.entity.open_hex", memory_interaction::capability_t::open_hex},
			{"memory.entity.open_disassembly", memory_interaction::capability_t::open_disassembly},
			{"memory.entity.copy_address", memory_interaction::capability_t::copy_address},
			{"memory.entity.copy_value", memory_interaction::capability_t::copy_value},
			{"memory.entity.stage_patch", memory_interaction::capability_t::stage_patch},
			{"memory.address.remove", memory_interaction::capability_t::remove}},
			retained_origin(s_address_context_origin.load()));
	aida::ui::application_ui::render_retained_entity_context_menu("memory.value_scan.address");
	s_consumed_memory_action = aida::ui::application_ui::consume_retained_entity_action(
		"memory.value_scan.address", memory_action_entity_id(context, action_contexts).c_str());
	if (!s_consumed_memory_action.empty()) {
		const size_t multi_count = action_contexts.size();
		if (context_item("Edit description", memory_interaction::capability_t::edit_description,
			context, runtime)) {
			diag_logf("ctx_addr edit_description row=%d", ctx_row);
			ui.desc_edit.active = true;
			ui.desc_edit.address_index = ctx_row;
			ui.desc_edit.open_from_add_dialog = false;
			{
				std::lock_guard<std::mutex> lk(sc.address_mutex);
				if (ctx_row >= 0 && ctx_row < static_cast<int>(sc.address_list.size())) {
					_snprintf_s(ui.desc_edit.buf, sizeof(ui.desc_edit.buf), _TRUNCATE,
						"%s", sc.address_list[static_cast<size_t>(ctx_row)].description.c_str());
				}
			}
		}
		if (context_item("Change type", memory_interaction::capability_t::change_type,
			context, runtime)) {
			diag_logf("ctx_addr change_type row=%d", ctx_row);
			s_pending_change_type_index.store(ctx_row);
			{
				std::lock_guard<std::mutex> lk(sc.address_mutex);
				if (ctx_row >= 0 && ctx_row < static_cast<int>(sc.address_list.size())) {
					s_pending_change_type_value = static_cast<int>(
						sc.address_list[static_cast<size_t>(ctx_row)].value_type);
				}
			}
		}
		if (context_item("Change value...", memory_interaction::capability_t::change_value,
			context, runtime, "Enter")) {
			diag_logf("ctx_addr change_value row=%d", ctx_row);
			s_pending_edit_value_index.store(ctx_row);
			std::lock_guard<std::mutex> lk(sc.address_mutex);
			if (ctx_row >= 0 && ctx_row < static_cast<int>(sc.address_list.size())) {
				const auto& e = sc.address_list[static_cast<size_t>(ctx_row)];
				std::string vs = memory_scanner::format_value(e.last_value, e.value_type);
				_snprintf_s(s_edit_value_buf, sizeof(s_edit_value_buf), _TRUNCATE,
					"%s", vs.c_str());
			}
		}
		if (context_item("Open in Hex view", memory_interaction::capability_t::open_hex,
			context, runtime)) {
			diag_logf("ctx_addr open_hex addr=0x%llX",
				static_cast<unsigned long long>(ctx_addr));
			if (ctx_addr != 0) {
				const auto context = disasm_view::capture_selected_workspace();
				if (hex_view::request_live_memory(context, ctx_addr, 256))
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] address_list ctx open_hex");
			}
		}
		if (context_item("Open in Disassembly", memory_interaction::capability_t::open_disassembly,
			context, runtime)) {
			diag_logf("ctx_addr open_disasm addr=0x%llX",
				static_cast<unsigned long long>(ctx_addr));
			if (ctx_addr != 0) {
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
				disasm_view::goto_address(ctx_addr,
					disasm_view::capture_selected_workspace());
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] address_list ctx open_disasm");
			}
		}
		if (s_consumed_memory_action == "memory.entity.copy_address") {
			copy_memory_addresses(action_contexts);
			diag_log("ctx_addr copy_address");
		}
		if (s_consumed_memory_action == "memory.entity.copy_value")
			copy_memory_text(action_contexts, [](const auto& item) -> const std::string& {
				return item.value;
			});
		if (context_item("Stage patch in Patches view...", memory_interaction::capability_t::stage_patch,
			context, runtime)) {
			std::uint64_t extent = 1;
			{
				std::lock_guard<std::mutex> lock(sc.address_mutex);
				if (ctx_row >= 0 && ctx_row < static_cast<int>(sc.address_list.size()))
					extent = static_cast<std::uint64_t>(memory_scanner::value_type_size(
						sc.address_list[static_cast<std::size_t>(ctx_row)].value_type));
			}
			std::string error;
			if (debugger_view::stage_patch_review(ctx_addr, extent,
				"Staged from Memory Address List", &error))
				aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.debug.patches"));
			else
				toast_notification::push(error.c_str(), toast_notification::toast_type_t::warning, 4.f);
		}
		if (s_consumed_memory_action == "memory.address.remove") {
			diag_logf("ctx_addr remove row=%d multi=%zu", ctx_row, multi_count);
			std::vector<int> to_remove;
			to_remove.reserve(action_contexts.size());
			for (const auto& item : action_contexts) {
				const int current_index = find_address_index(item);
				if (current_index >= 0) to_remove.push_back(current_index);
			}
			std::sort(to_remove.begin(), to_remove.end(), std::greater<int>());
			for (int idx : to_remove)
				memory_scanner::remove_address(static_cast<size_t>(idx));
			ui.address_multi_sel.clear();
			ui.selected_address = -1;
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] address_list ctx remove");
		}
	}
	s_consumed_memory_action.clear();
}

}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
void initialize_preview_fixture() {
	static bool seeded = false;
	if (seeded)
		return;
	memory_scanner::scan_config_t config;
	config.value_text = "1337";
	std::snprintf(g_ui.value_buf, sizeof(g_ui.value_buf), "%s", config.value_text.c_str());
	memory_scanner::first_scan(config);
	memory_scanner::add_address(0x00007FF7A4C42030ULL, "player_health",
		memory_scanner::value_type_t::int32_val);
	memory_scanner::add_address(0x00007FF7A4C42108ULL, "session_flags",
		memory_scanner::value_type_t::int32_val);
	seeded = true;
}
#endif

void tick_address_auto_refresh(bool attached) {
	auto& ui = g_ui;
	if (!ui.auto_refresh || !attached)
		return;
	ui.refresh_timer += aida::ui::clock::dt();
	if (ui.refresh_timer < ui.refresh_interval)
		return;
	ui.refresh_timer = 0.f;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	memory_scanner::refresh_address_list();
#else
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "scanner";
	submission.label = "scanner.address_list_refresh";
	submission.thread_class = "scanner_ui_refresh";
	submission.domain = aida::infra::executor::domain_t::diagnostics;
	submission.priority = 4;
	submission.target_pid = driver_bridge::attached_pid();
	submission.body = []() { memory_scanner::refresh_address_list(); };
	if (!aida::infra::executor::submit(std::move(submission)).submitted)
		diag::log_tagged("value_scan", "address_list_refresh_post_failed");
#endif
}

scan_command_state_t scan_command_capability(scan_command_t command) {
	auto& state = memory_scanner::g_state;
	const bool scanning = state.scanning.load(std::memory_order_acquire);
	bool has_initial_scan = false;
	bool has_undo_history = false;
	bool static_scan = false;
	{
		std::lock_guard<std::mutex> lock(state.results_mutex);
		has_initial_scan = state.has_initial_scan;
		has_undo_history = !state.scan_history.empty();
		static_scan = state.scan_static_binary;
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const bool attached = true;
	const bool static_binary = true;
#else
	const bool attached = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;
	const bool static_binary = function_index::detail::static_pe_active();
#endif
	const auto requires_value = [](memory_scanner::scan_mode_t mode) {
		return mode == memory_scanner::scan_mode_t::exact ||
			mode == memory_scanner::scan_mode_t::bigger_than ||
			mode == memory_scanner::scan_mode_t::smaller_than ||
			mode == memory_scanner::scan_mode_t::value_between;
	};
	const auto configured_value_capability = [&]() -> scan_command_state_t {
		if (state.config.value_type == memory_scanner::value_type_t::all_types)
			return {false, "Choose a concrete value type; All Types has no value-scan provider"};
		const bool variable_length =
			state.config.value_type == memory_scanner::value_type_t::string_ascii ||
			state.config.value_type == memory_scanner::value_type_t::string_utf16 ||
			state.config.value_type == memory_scanner::value_type_t::byte_array;
		if (variable_length &&
			(state.config.scan_mode == memory_scanner::scan_mode_t::bigger_than ||
			 state.config.scan_mode == memory_scanner::scan_mode_t::smaller_than ||
			 state.config.scan_mode == memory_scanner::scan_mode_t::value_between ||
			 state.config.scan_mode == memory_scanner::scan_mode_t::increased ||
			 state.config.scan_mode == memory_scanner::scan_mode_t::decreased))
			return {false, "Choose Exact, Changed, Unchanged, or Unknown Initial for variable-length values"};
		if (requires_value(state.config.scan_mode) && g_ui.value_buf[0] == '\0')
			return {false, "Enter the scan value first"};
		if (state.config.scan_mode == memory_scanner::scan_mode_t::value_between &&
			g_ui.value_buf2[0] == '\0')
			return {false, "Enter the upper value for the Between scan first"};
		return {true, {}};
	};

	switch (command) {
	case scan_command_t::first_scan: {
		if (scanning)
			return {false, "A memory scan is already running"};
		if (has_initial_scan)
			return {false, "Start a New Scan before running another First Scan"};
		if (g_ui.prefer_static_source && !static_binary)
			return {false, "The selected static binary source is no longer available"};
		if (!attached && !static_binary)
			return {false, "Attach to a live process or open a static PE workspace before scanning"};
		if (state.config.scan_mode == memory_scanner::scan_mode_t::changed ||
			state.config.scan_mode == memory_scanner::scan_mode_t::unchanged ||
			state.config.scan_mode == memory_scanner::scan_mode_t::increased ||
			state.config.scan_mode == memory_scanner::scan_mode_t::decreased)
			return {false, "Choose an initial comparison or Unknown Initial scan mode"};
		return configured_value_capability();
	}
	case scan_command_t::next_scan:
		if (scanning)
			return {false, "Wait for the active memory scan to finish or stop it first"};
		if (!has_initial_scan)
			return {false, "Run First Scan before refining results"};
		if (static_scan)
			return {false, "Static binary scans are immutable; change the definition and run New Scan"};
		if (!attached)
			return {false, "The scanned live process is no longer attached"};
		if (!memory_scanner::target_binding_current(
				state.scan_target_pid, state.scan_target_epoch))
			return {false, "The attached process changed; start a New Scan for this target"};
		if (state.config.scan_mode == memory_scanner::scan_mode_t::unknown_initial)
			return {false, "Choose a refinement scan mode before running Next Scan"};
		return configured_value_capability();
	case scan_command_t::stop_scan:
		return scanning ? scan_command_state_t{true, {}}
			: scan_command_state_t{false, "No memory scan is running"};
	case scan_command_t::undo_scan:
		if (scanning)
			return {false, "Wait for the active memory scan to finish or stop it first"};
		return has_undo_history ? scan_command_state_t{true, {}}
			: scan_command_state_t{false, "No completed refinement scan is available to undo"};
	case scan_command_t::new_scan:
		if (scanning)
			return {false, "Stop the active memory scan before starting a new scan"};
		return has_initial_scan ? scan_command_state_t{true, {}}
			: scan_command_state_t{false, "The scanner is already ready for a First Scan"};
	}
	return {false, "The memory scan command is invalid"};
}

scan_command_result_t execute_scan_command(scan_command_t command) {
	const auto capability = scan_command_capability(command);
	if (!capability.enabled)
		return {false, capability.disabled_reason};
	auto& state = memory_scanner::g_state;
	auto& ui = g_ui;
	switch (command) {
	case scan_command_t::first_scan: {
		diag_logf("action first_scan val='%s' val2='%s' vtype=%s mode=%s",
			ui.value_buf, ui.value_buf2,
			memory_scanner::value_type_name(state.config.value_type),
			memory_scanner::scan_mode_name(state.config.scan_mode));
		anti_tamper::webhook::write_log("scan_audit",
			"[scan_audit] memory_scanner first_scan invoked");
		state.config.value_text = ui.value_buf;
		state.config.value_text2 = ui.value_buf2;
		bool started = false;
		bool static_started = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		started = memory_scanner::first_scan(state.config);
#else
		if (!ui.prefer_static_source && driver_bridge::is_loaded() &&
			driver_bridge::attached_pid() != 0) {
			started = memory_scanner::first_scan(state.config);
		} else {
			const auto workspace = disasm_view::capture_selected_workspace();
			if (workspace.workspace && workspace.image) {
				started = memory_scanner::first_static_scan(state.config,
					workspace.workspace->provider_handle(), workspace.image,
					workspace.workspace->identity().binary_id().to_hex(),
					workspace.workspace->generation());
				static_started = started;
			}
		}
#endif
		if (!started)
			return {false, "The memory scan engine rejected First Scan; the live target or static workspace changed"};
		ui.selected_result = -1;
		ui.result_multi_sel.clear();
		ui.last_result_anchor = -1;
		ui.result_sb.scroll_y = 0.f;
		ui.result_sb.target_scroll_y = 0.f;
		ui.user_scrolled_up = false;
		request_region_refresh();
		invalidate_sort();
		return {true, static_started ? "Static binary value scan started" :
			"Initial live memory scan started"};
	}
	case scan_command_t::next_scan:
		diag_logf("action next_scan mode=%s val='%s' val2='%s'",
			memory_scanner::scan_mode_name(state.config.scan_mode),
			ui.value_buf, ui.value_buf2);
		anti_tamper::webhook::write_log("scan_audit",
			"[scan_audit] memory_scanner next_scan invoked");
		if (!memory_scanner::next_scan(state.config.scan_mode,
			std::string(ui.value_buf), std::string(ui.value_buf2)))
			return {false, "The memory scan engine rejected Next Scan; the target, scan generation, or worker admission changed"};
		request_region_refresh();
		invalidate_sort();
		return {true, "Memory scan refinement started"};
	case scan_command_t::stop_scan:
		diag_log("action stop_scan");
		return memory_scanner::cancel_scan()
			? scan_command_result_t{true, "Memory scan cancellation requested"}
			: scan_command_result_t{false, "The memory scan completed before cancellation was requested"};
	case scan_command_t::undo_scan:
		diag_log("action undo_scan");
		memory_scanner::undo_scan();
		invalidate_sort();
		ui.selected_result = -1;
		ui.result_multi_sel.clear();
		ui.last_result_anchor = -1;
		return {true, "Previous memory scan result set restored"};
	case scan_command_t::new_scan:
		diag_log("action new_scan");
		memory_scanner::reset_scan();
		invalidate_sort();
		ui.selected_result = -1;
		ui.result_multi_sel.clear();
		ui.last_result_anchor = -1;
		ui.result_sb.scroll_y = 0.f;
		ui.result_sb.target_scroll_y = 0.f;
		ui.user_scrolled_up = false;
		return {true, "Memory scanner reset for a new scan"};
	}
	return {false, "The memory scan command is invalid"};
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float, float, float)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	initialize_preview_fixture();
#endif
	memory_interaction::synchronize_selection(runtime_snapshot());
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##scanner_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;
	float a = alpha;

	const auto& t = aida::ui::resolved();
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.bg_base, a));

	auto& ui = g_ui;
	auto& sc = memory_scanner::g_state;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	bool attached_now = true;
	bool static_pe_now = true;
#else
	bool attached_now = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;
	bool static_pe_now = function_index::detail::static_pe_active();
#endif
	bool any_target = attached_now;

	tick_address_auto_refresh(attached_now);

	if (ui.region_cache.entries.empty() && attached_now) {
		request_region_refresh();
	}

	{
		size_t cur_total = 0;
		{
			std::lock_guard<std::mutex> lk(sc.results_mutex);
			cur_total = sc.results.size();
		}
		if (ui.last_result_count != cur_total) {
			invalidate_sort();
		}
	}

	float callout_h = (!any_target) ? kCalloutHeight : 0.f;

	const float toolbar_h = render_toolbar(dl, ox, oy, w, a);

	if (callout_h > 0.f) {
		ui_anim::render_inline_callout(dl, ox + 12.f, oy + toolbar_h + 4.f,
			w - 24.f, 22.f,
			static_pe_now
				? "Static binary loaded. Value scans and watch mutations require a live process attach."
				: "Value scan needs a live process. Attach a target from the Process Attach panel.",
			ui_anim::callout_kind_t::warn, 0.85f, 0.6f, 0.2f, a);
	}

	float remaining = h - toolbar_h - callout_h;
	if (remaining < 100.f) remaining = 100.f;
	float results_h = 0.f;
	float address_h = 0.f;

	float results_y = oy + toolbar_h + callout_h;
	float split_y = 0.f;

	{
		float panes_total = remaining - kSplitterThickness;
		if (panes_total < 80.f) panes_total = 80.f;
		float r_ratio = ui.result_pane_ratio;
		float min_h = 80.f;
		r_ratio = std::clamp(r_ratio,
			min_h / panes_total, 1.f - min_h / panes_total);
		ui.result_pane_ratio = r_ratio;
		results_h = panes_total * r_ratio;
		address_h = panes_total - results_h;
	}

	render_results_pane(dl, ox, results_y, w, results_h, a);

	split_y = results_y + results_h;
	render_splitter(dl, ox, split_y, w, a, results_h, address_h, remaining - kSplitterThickness);

	render_address_pane(dl, ox, split_y + kSplitterThickness, w, address_h, a);

	ImGui::EndChild();

	process_add_dialog();
	process_edit_description_dialog();
	process_edit_value_dialog();
	process_change_type_dialog();
	process_result_context_menu();
	process_address_context_menu();
}

void render_results(float pos_x, float pos_y, float width, float height,
	float alpha, float, float, float) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	initialize_preview_fixture();
#endif
	const char* previous_owner = s_current_result_owner_view;
	s_current_result_owner_view = "view.memory.value_scan_results";
	const auto runtime = runtime_snapshot();
	memory_interaction::synchronize_selection(runtime);
	bool empty = false;
	{
		std::lock_guard<std::mutex> lock(memory_scanner::g_state.results_mutex);
		empty = memory_scanner::g_state.results.empty();
	}
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##memory_scan_results_pane", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImDrawList* draw_list = ImGui::GetWindowDrawList();
	const ImVec2 window = ImGui::GetWindowPos();
	const bool scanning = memory_scanner::g_state.scanning.load(std::memory_order_acquire);
	const float status_height = scanning ? 40.f : 0.f;
	if (scanning) {
		const auto stop = aida::ui::application_ui::present_action("memory.stop_scan");
		aida::ui::design::action_t action;
		action.id = stop.id.c_str();
		action.label = stop.label.c_str();
		action.compact_label = "Stop";
		action.tooltip = stop.enabled ? stop.description.c_str() : stop.disabled_reason.c_str();
		action.shortcut = stop.shortcut.empty() ? nullptr : stop.shortcut.c_str();
		action.kind = aida::ui::components::button_kind_t::destructive;
		action.enabled = stop.enabled;
		action.primary = true;
		action.visible = stop.visible;
		const int progress = static_cast<int>((std::clamp)(
			memory_scanner::g_state.scan_progress.load(std::memory_order_acquire),
			0.f, 1.f) * 100.f);
		draw_list->AddRectFilled(window, ImVec2(window.x + width, window.y + status_height),
			aida::ui::with_alpha(aida::ui::resolved().panel_header, alpha));
		ImGui::SetCursorScreenPos(ImVec2(window.x + 8.f, window.y + 7.f));
		const float action_width = (std::min)(160.f, (std::max)(80.f, width * 0.32f));
		const auto invoked = aida::ui::design::render_toolbar(
			"memory-scan-results-progress", &action, 1, action_width);
		if (invoked.invoked && invoked.id)
			static_cast<void>(aida::ui::application_ui::execute_action(
				invoked.id, aida::ui::action_invocation_source_t::toolbar));
		ImGui::SetCursorScreenPos(ImVec2(window.x + action_width + 18.f, window.y + 11.f));
		ImGui::Text("Scanning memory... %d%%", progress);
	}
	if (empty && !runtime.live_attached && !runtime.static_loaded)
		aida::ui::no_target_overlay::render(window, ImVec2(width, height),
			"No memory target available",
			"Attach to a running process for live scans, or open a binary for static value discovery.",
			alpha, aida::ui::empty_state::glyph_t::memory, true,
			"no_target.memory.value_scan_results");
	else
		render_results_pane(draw_list, window.x, window.y + status_height, width,
			(std::max)(height - status_height, 1.f), alpha);
	ImGui::EndChild();
	process_add_dialog();
	process_result_context_menu();
	s_current_result_owner_view = previous_owner;
}

void render_address_list(float pos_x, float pos_y, float width, float height,
	float alpha, float, float, float) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	initialize_preview_fixture();
#endif
	const char* previous_owner = s_current_address_owner_view;
	s_current_address_owner_view = "view.memory.address_list";
	const auto runtime = runtime_snapshot();
	memory_interaction::synchronize_selection(runtime);
	tick_address_auto_refresh(runtime.live_attached);
	bool empty = false;
	{
		std::lock_guard<std::mutex> lock(memory_scanner::g_state.address_mutex);
		empty = memory_scanner::g_state.address_list.empty();
	}
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##memory_address_list_pane", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImDrawList* draw_list = ImGui::GetWindowDrawList();
	const ImVec2 window = ImGui::GetWindowPos();
	if (empty && !runtime.live_attached)
		aida::ui::no_target_overlay::render(window, ImVec2(width, height),
			"No live memory target attached",
			"Attach to a running process or launch a target to build and edit a live address list.",
			alpha, aida::ui::empty_state::glyph_t::memory, true,
			"no_target.memory.address_list");
	else
		render_address_pane(draw_list, window.x, window.y, width, height, alpha);
	ImGui::EndChild();
	process_add_dialog();
	process_edit_description_dialog();
	process_edit_value_dialog();
	process_change_type_dialog();
	process_address_context_menu();
	s_current_address_owner_view = previous_owner;
}

}
