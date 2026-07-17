#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#include "../../helpers/win32_dialog.hpp"
#endif
#include "../ui/application_view_registry.hpp"
#include "../ui/task_center.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../../helpers/helpers.h"
#include "binary_map.hpp"
#include "../editor/hex_view.hpp"
#include "disasm_view.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "binary_map_preview_runtime.hpp"
#else
#include "standalone_driver.hpp"
#endif
#include "event_bus.hpp"
#include "toast_notification.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/blur_layer.hpp"
#include "ui/empty_state.hpp"
#include "ui/no_target_overlay.hpp"
#include "ui/responsive.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/ui_task_executor.hpp"
#include "../../preview/hex_preview_adapter.hpp"
#else
#include "../infra/executor.hpp"
#endif
#include "../session/analysis_session.hpp"

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <Windows.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida {
namespace binary_map_view {

	struct fn_pulse_t {
		float v = 0.f;
	};

	enum class display_mode_t : int {
		auto_detect = 0,
		static_only,
		live_only
	};

	enum class active_mode_t : int {
		none = 0,
		pe_static,
		live_process,
		merged
	};

	struct live_region_t {
		uint64_t    base = 0;
		uint64_t    size = 0;
		uint32_t    state = 0;
		uint32_t    protect = 0;
		uint32_t    type = 0;
		std::string module_name;
		std::string module_path;
		std::string section_name;
		std::string info;
		uint32_t    owner_tid = 0;
		bool        is_image = false;
		bool        is_mapped = false;
		bool        is_private = false;
		bool        is_stack = false;
		bool        is_heap = false;
		bool        is_committed = false;
		bool        is_reserved = false;
		bool        is_guard = false;
		bool        is_noaccess = false;
	};

	struct live_snapshot_t {
		std::vector<live_region_t>                regions;
		std::vector<driver_bridge::module_info_t> modules;
		std::vector<driver_bridge::thread_info_t> threads;
		uint64_t                                  process_heap = 0;
		uint64_t                                  total_committed = 0;
		uint64_t                                  total_reserved = 0;
		uint32_t                                  rwx_count = 0;
		uint32_t                                  pid = 0;
		std::string                               process_name;
		int64_t                                   generated_unix = 0;
		uint64_t                                  enum_elapsed_ms = 0;
	};

	struct view_state_t
	{
		std::mutex                              mutex;
		std::shared_ptr<const binary_map::map_t> map = std::make_shared<binary_map::map_t>();
		binary_map::map_options_t               opts;
		std::shared_ptr<const std::string>      rendered_text = std::make_shared<std::string>();
		std::set<std::string>                   collapsed_groups;
		std::set<std::string>                   expanded_imports;
		char                                    filter_buf[160] = {};
		std::string                             filter_lower;
		const live_snapshot_t*                  filtered_live_identity = nullptr;
		std::string                             filtered_live_query;
		std::vector<int>                        filtered_live_indices;
		std::string                             last_error;
		std::string                             live_last_error;
		std::atomic<bool>                       has_map{false};
		std::atomic<bool>                       refreshing{false};
		std::atomic<bool>                       refresh_requested{false};
		std::atomic<std::uint64_t>              refresh_serial{0};
		std::atomic<bool>                       export_pending{false};
		std::atomic<uint64_t>                   selected_va{0};
		std::atomic<int>                        ctx_target{-1};
		uint64_t                                ctx_va = 0;
		std::string                             selected_entity_id;
		float                                   left_split = 0.58f;
		float                                   list_scroll_y = 0.f;
		float                                   list_target_scroll_y = 0.f;
		float                                   row_anim_time = 0.f;
		bool                                    initialized = false;
		bool                                    auto_refreshed_once = false;
		std::string                             last_binary_identity_path;
		uint64_t                                last_binary_identity_base = 0;
		uint32_t                                last_binary_identity_size = 0;
		aida::events::subscription_handle_t     subscription_binary;
		aida::events::subscription_handle_t     subscription_proc_created;
		aida::events::subscription_handle_t     subscription_proc_exited;
		std::unordered_map<uint64_t, aida::ui::flash_t> pin_flashes;
		std::unordered_map<uint64_t, fn_pulse_t>        fn_pulses;
		aida::ui::hover_state_t                 splitter_hover;
		float                                   splitter_hover_v = 0.f;
		uint64_t                                hover_function_va = 0;
		display_mode_t                          mode_pref = display_mode_t::auto_detect;
		std::atomic<int>                        active_mode_atomic{0};
		std::shared_ptr<const live_snapshot_t>  live = std::make_shared<live_snapshot_t>();
		std::atomic<bool>                       live_refreshing{false};
		std::atomic<bool>                       live_refresh_requested{false};
		std::atomic<std::uint64_t>              live_refresh_serial{0};
		std::atomic<int64_t>                    live_last_refresh_unix{0};
		std::atomic<uint64_t>                   live_selected_base{0};
		std::atomic<int>                        live_hover_index{-1};
		float                                   live_list_scroll_y = 0.f;
		float                                   live_list_target_scroll_y = 0.f;
		float                                   canvas_zoom = 1.f;
		float                                   canvas_target_zoom = 1.f;
		double                                  canvas_offset_norm = 0.0;
		double                                  canvas_target_offset_norm = 0.0;
		bool                                    canvas_dragging = false;
		float                                   canvas_drag_anchor = 0.f;
		double                                  canvas_drag_offset_start = 0.0;
		bool                                    change_protect_open = false;
		bool                                    change_protect_popup_requested = false;
		bool                                    refresh_after_pin_requested = false;
		std::atomic<bool>                       change_protect_pending{false};
		uint64_t                                change_protect_addr = 0;
		uint64_t                                change_protect_size = 0;
		int                                     change_protect_choice = 0;
		uint32_t                                change_protect_old = 0;
		std::weak_ptr<aida::analysis::analysis_workspace_t> workspace;
		std::string                             binary_id;
		std::uint64_t                           workspace_generation = 0;
	};

	inline std::mutex& workspace_states_mutex()
	{
		static std::mutex mutex;
		return mutex;
	}

	inline std::unordered_map<std::string, std::shared_ptr<view_state_t>>& workspace_states()
	{
		static std::unordered_map<std::string, std::shared_ptr<view_state_t>> states;
		return states;
	}

	inline std::shared_ptr<view_state_t> state_for(
		const disasm_view::workspace_context_t& context)
	{
		if (!context.workspace) return {};
		const std::string key = context.workspace->identity().binary_id().to_hex();
		std::lock_guard<std::mutex> lock(workspace_states_mutex());
		auto& state = workspace_states()[key];
		if (!state || state->workspace.lock() != context.workspace) {
			state = std::make_shared<view_state_t>();
			state->workspace = context.workspace;
			state->binary_id = key;
			state->workspace_generation = context.workspace->generation();
		}
		return state;
	}

	namespace detail {
		template <typename Invoke>
		inline void add_retained_action(
			aida::ui::application_ui::retained_entity_context_t& context,
			std::string id, bool enabled, const char* reason, Invoke invoke)
		{
			aida::ui::application_ui::retained_entity_action_t action;
			action.action_id = std::move(id);
			action.capability = enabled ? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(reason);
			action.invoke = std::move(invoke);
			context.actions.push_back(std::move(action));
		}

		inline bool keyboard_context_requested(bool selected)
		{
			const ImGuiIO& io = ImGui::GetIO();
			return selected && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
				(ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
					(io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)));
		}

		inline aida::ui::context_menu_open_origin_t context_origin(bool pointer)
		{
			return pointer ? aida::ui::context_menu_open_origin_t::pointer
				: ImGui::IsKeyPressed(ImGuiKey_Menu, false)
				? aida::ui::context_menu_open_origin_t::menu_key
				: aida::ui::context_menu_open_origin_t::shift_f10;
		}
		inline int count_as_int(std::size_t count)
		{
			const auto maximum = static_cast<std::size_t>((std::numeric_limits<int>::max)());
			return count > maximum ? (std::numeric_limits<int>::max)() : static_cast<int>(count);
		}

		inline bool valid_index(int index, std::size_t count)
		{
			return index >= 0 && static_cast<std::size_t>(index) < count;
		}

		inline std::string export_live_snapshot_json(const live_snapshot_t& snap);

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		inline bool atomic_write_exact(const std::string& destination,
			const void* data, std::size_t size, std::string& error)
		{
			if (destination.empty() || (size != 0 && data == nullptr)) {
				error = "The export destination or payload is invalid";
				return false;
			}
			const std::filesystem::path final_path = std::filesystem::u8path(destination);
			static std::atomic<std::uint64_t> sequence{1};
			const std::filesystem::path temporary(final_path.wstring() + L".tmp." +
				std::to_wstring(GetCurrentProcessId()) + L"." +
				std::to_wstring(GetCurrentThreadId()) + L"." +
				std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed)));
			HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
				CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
			if (file == INVALID_HANDLE_VALUE) {
				error = "Creating the export temporary file failed with Win32 error " +
					std::to_string(GetLastError());
				return false;
			}
			bool succeeded = true;
			std::size_t offset = 0;
			const auto* bytes = static_cast<const std::uint8_t*>(data);
			while (offset < size) {
				const DWORD chunk = static_cast<DWORD>((std::min)(size - offset,
					static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
				DWORD written = 0;
				if (!WriteFile(file, bytes + offset, chunk, &written, nullptr)) {
					error = "Writing the export temporary file failed with Win32 error " +
						std::to_string(GetLastError());
					succeeded = false;
					break;
				}
				if (written != chunk) {
					error = "Writing the export temporary file completed with a short write";
					succeeded = false;
					break;
				}
				offset += written;
			}
			if (succeeded && !FlushFileBuffers(file)) {
				error = "Flushing the export temporary file failed with Win32 error " +
					std::to_string(GetLastError());
				succeeded = false;
			}
			LARGE_INTEGER observed_size{};
			if (succeeded && (!GetFileSizeEx(file, &observed_size) ||
				observed_size.QuadPart < 0 ||
				static_cast<std::uint64_t>(observed_size.QuadPart) != size)) {
				error = "The export temporary file size did not match the requested payload";
				succeeded = false;
			}
			if (!CloseHandle(file) && succeeded) {
				error = "Closing the export temporary file failed with Win32 error " +
					std::to_string(GetLastError());
				succeeded = false;
			}
			if (succeeded && !MoveFileExW(temporary.c_str(), final_path.c_str(),
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
				error = "Replacing the export destination failed with Win32 error " +
					std::to_string(GetLastError());
				succeeded = false;
			}
			if (!succeeded)
				DeleteFileW(temporary.c_str());
			return succeeded;
		}

		inline bool queue_snapshot_export(const std::shared_ptr<view_state_t>& state,
			const std::string& destination,
			std::string label,
			std::shared_ptr<const live_snapshot_t> live,
			std::shared_ptr<const std::string> text)
		{
			if (!state || (!live && (!text || text->empty())) || destination.empty())
				return false;
			bool expected = false;
			if (!state->export_pending.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
				return false;
			static std::atomic<std::uint64_t> sequence{1};
			const std::string task_id = "analysis.binary_map.export." +
				std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
			aida::ui::task_center::task_registration_t registration;
			registration.id = task_id;
			registration.source = "analysis.binary_map";
			registration.owner = "Binary Map";
			registration.owner_view = "view.analysis.binary_map";
			registration.owner_action = "analysis.binary_map.export";
			registration.target = destination;
			registration.label = std::move(label);
			registration.stage = "Queued for immutable serialization and atomic export";
			registration.affected_entity = destination;
			registration.callbacks.focus = [] {
				static_cast<void>(aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.analysis.binary_map")));
			};
			registration.callbacks.open_log = registration.callbacks.focus;
			if (!aida::ui::task_center::register_task(std::move(registration))) {
				state->export_pending.store(false, std::memory_order_release);
				return false;
			}
			aida::infra::executor::submission_t submission;
			submission.owner_subsystem = "analysis";
			submission.label = "analysis.binary_map.export";
			submission.thread_class = "bounded_file_io";
			submission.domain = aida::infra::executor::domain_t::external_tool;
			submission.session_id = task_id.c_str();
			submission.target_id = destination.c_str();
			submission.diagnostic_id = task_id.c_str();
			submission.ui_access_policy = "immutable_snapshots_only";
			submission.failure_policy = "typed_diagnostic";
			submission.shutdown_policy = "drain";
			submission.body = [state, task_id, destination,
				live = std::move(live), text = std::move(text)] {
				struct pending_guard_t {
					std::shared_ptr<view_state_t> state;
					~pending_guard_t() {
						state->export_pending.store(false, std::memory_order_release);
					}
				} pending_guard{state};
				static_cast<void>(pending_guard);
				try {
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::running, -1.0f,
						"Serializing an immutable Binary Map snapshot"));
					std::string payload = live ? export_live_snapshot_json(*live) : *text;
					constexpr std::size_t maximum_export_bytes = 64U * 1024U * 1024U;
					if (payload.size() > maximum_export_bytes) {
						static_cast<void>(aida::ui::task_center::update_task(task_id,
							aida::ui::task_center::task_state_t::failed, 1.0f,
							"Binary Map export exceeded the size limit",
							"The serialized export exceeded the 64 MiB bounded export limit",
							"diagnostic." + task_id));
						return;
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::running, -1.0f,
						"Writing a same-directory temporary file"));
					std::string error;
					if (!atomic_write_exact(destination, payload.data(), payload.size(), error)) {
						static_cast<void>(aida::ui::task_center::update_task(task_id,
							aida::ui::task_center::task_state_t::failed, 1.0f,
							"Atomic Binary Map export failed", error,
							"diagnostic." + task_id));
						return;
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::completed, 1.0f,
						"Finished", "Binary Map exported atomically to " + destination));
				} catch (const std::exception& exception) {
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Binary Map export failed", exception.what(),
						"diagnostic." + task_id));
				} catch (...) {
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Binary Map export failed", "Unknown export failure",
						"diagnostic." + task_id));
				}
			};
			const auto submitted = aida::infra::executor::submit(std::move(submission));
			if (!submitted.submitted) {
				state->export_pending.store(false, std::memory_order_release);
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::failed, 1.0f,
					"Executor rejected Binary Map export", submitted.reject_reason,
					"diagnostic." + task_id));
				return false;
			}
			return true;
		}

		inline bool queue_protection_change(const std::shared_ptr<view_state_t>& state,
			const disasm_view::workspace_context_t& context,
			std::uint64_t address, std::uint64_t size, std::uint32_t new_protect)
		{
			if (!state || !context || !context.workspace->identity().process() ||
				address == 0 || size == 0 ||
				address > (std::numeric_limits<std::uint64_t>::max)() - size)
				return false;
			bool expected = false;
			if (!state->change_protect_pending.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
				return false;
			const std::uint32_t pid = context.workspace->identity().process()->pid;
			const std::uint64_t generation = context.workspace->generation();
			static std::atomic<std::uint64_t> sequence{1};
			const std::string task_id = "analysis.binary_map.protect." +
				std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
			char target[160] = {};
			std::snprintf(target, sizeof(target), "PID %u 0x%llX-0x%llX",
				static_cast<unsigned>(pid), static_cast<unsigned long long>(address),
				static_cast<unsigned long long>(address + size));
			aida::ui::task_center::task_registration_t registration;
			registration.id = task_id;
			registration.source = "analysis.binary_map";
			registration.owner = "Binary Map";
			registration.owner_view = "view.analysis.binary_map";
			registration.owner_action = "analysis.binary_map.change_protection";
			registration.target = target;
			registration.label = "Change live memory protection";
			registration.stage = "Queued after reviewed confirmation";
			registration.affected_entity = target;
			registration.callbacks.focus = [] {
				static_cast<void>(aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.analysis.binary_map")));
			};
			registration.callbacks.open_log = registration.callbacks.focus;
			if (!aida::ui::task_center::register_task(std::move(registration))) {
				state->change_protect_pending.store(false, std::memory_order_release);
				return false;
			}
			aida::infra::executor::submission_t submission;
			submission.owner_subsystem = "analysis";
			submission.label = "analysis.binary_map.change_protection";
			submission.thread_class = "live_target_mutation";
			submission.domain = aida::infra::executor::domain_t::feature_worker;
			submission.target_pid = pid;
			submission.generation = generation;
			submission.session_id = task_id.c_str();
			submission.target_id = target;
			submission.diagnostic_id = task_id.c_str();
			submission.ui_access_policy = "immutable_snapshots_only";
			submission.failure_policy = "typed_diagnostic";
			submission.shutdown_policy = "drain";
			submission.body = [state, context, task_id, pid, generation,
				address, size, new_protect] {
				struct pending_guard_t {
					std::shared_ptr<view_state_t> state;
					~pending_guard_t() {
						state->change_protect_pending.store(false, std::memory_order_release);
					}
				} pending_guard{state};
				static_cast<void>(pending_guard);
				try {
					const auto process = context.workspace->identity().process();
					if (context.workspace->generation() != generation || !process ||
						process->pid != pid) {
						static_cast<void>(aida::ui::task_center::update_task(task_id,
							aida::ui::task_center::task_state_t::failed, 1.0f,
							"Target identity changed before mutation",
							"The reviewed PID or workspace generation is no longer current",
							"diagnostic." + task_id));
						return;
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::running, -1.0f,
						"Applying reviewed protection change"));
					std::uint32_t old_protect = 0;
					if (!driver_bridge::protect_memory_for(pid, address, size,
						new_protect, &old_protect)) {
						static_cast<void>(aida::ui::task_center::update_task(task_id,
							aida::ui::task_center::task_state_t::failed, 1.0f,
							"Protection mutation failed",
							"The driver rejected the reviewed protection change",
							"diagnostic." + task_id));
						return;
					}
					bool verified = false;
					const auto regions = driver_bridge::enumerate_memory_regions_for(pid, 8192);
					for (const auto& region : regions) {
						if (address >= region.base && address - region.base < region.size) {
							verified = region.protect == new_protect;
							break;
						}
					}
					state->live_refresh_requested.store(true, std::memory_order_release);
					if (!verified) {
						static_cast<void>(aida::ui::task_center::update_task(task_id,
							aida::ui::task_center::task_state_t::failed, 1.0f,
							"Protection readback did not match",
							"The mutation returned success but the post-operation region snapshot did not confirm the requested protection",
							"diagnostic." + task_id));
						return;
					}
					char summary[160] = {};
					std::snprintf(summary, sizeof(summary),
						"Protection changed and verified: 0x%X -> 0x%X",
						static_cast<unsigned>(old_protect), static_cast<unsigned>(new_protect));
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::completed, 1.0f,
						"Finished", summary));
				} catch (const std::exception& exception) {
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Protection mutation failed", exception.what(),
						"diagnostic." + task_id));
				} catch (...) {
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Protection mutation failed", "Unknown mutation failure",
						"diagnostic." + task_id));
				}
			};
			const auto submitted = aida::infra::executor::submit(std::move(submission));
			if (!submitted.submitted) {
				state->change_protect_pending.store(false, std::memory_order_release);
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::failed, 1.0f,
					"Executor rejected protection mutation", submitted.reject_reason,
					"diagnostic." + task_id));
				return false;
			}
			return true;
		}
#endif

		inline std::size_t hex_request_size(std::uint64_t size)
		{
			constexpr std::uint64_t maximum = 1ULL * 1024ULL * 1024ULL;
			return static_cast<std::size_t>((std::min)(size, maximum));
		}

		inline std::string to_lower_copy(const std::string& s)
		{
			std::string out;
			out.resize(s.size());
			for (std::size_t i = 0; i < s.size(); ++i) {
				const unsigned char c = static_cast<unsigned char>(s[i]);
				out[i] = static_cast<char>(std::tolower(c));
			}
			return out;
		}

		inline bool filter_matches(const std::string& filter_lower, const std::string& text)
		{
			if (filter_lower.empty()) return true;
			std::string lower = to_lower_copy(text);
			return lower.find(filter_lower) != std::string::npos;
		}

		inline std::string format_size_human(uint64_t bytes)
		{
			char buf[48];
			if (bytes >= (1ull << 30)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 30);
				std::snprintf(buf, sizeof(buf), "%.2f GiB", v);
			} else if (bytes >= (1ull << 20)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 20);
				std::snprintf(buf, sizeof(buf), "%.2f MiB", v);
			} else if (bytes >= (1ull << 10)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 10);
				std::snprintf(buf, sizeof(buf), "%.2f KiB", v);
			} else {
				std::snprintf(buf, sizeof(buf), "%llu B",
					static_cast<unsigned long long>(bytes));
			}
			return std::string(buf);
		}

		inline std::string format_protect_word(uint32_t protect)
		{
			if (protect == 0) return "---";
			std::string out;
			const uint32_t base = protect & 0xFF;
			switch (base) {
				case 0x01: out = "----"; break;
				case 0x02: out = "R---"; break;
				case 0x04: out = "RW--"; break;
				case 0x08: out = "RWC-"; break;
				case 0x10: out = "--X-"; break;
				case 0x20: out = "R-X-"; break;
				case 0x40: out = "RWX-"; break;
				case 0x80: out = "RWXC"; break;
				default: {
					char buf[16];
					std::snprintf(buf, sizeof(buf), "0x%02X", base);
					out = buf;
					break;
				}
			}
			if (protect & 0x100) out += " G";
			if (protect & 0x200) out += " NC";
			if (protect & 0x400) out += " WC";
			return out;
		}

		inline std::string format_state_word(uint32_t state)
		{
			if (state == 0x1000)  return "COMMIT";
			if (state == 0x2000)  return "RESERVE";
			if (state == 0x10000) return "FREE";
			char buf[16];
			std::snprintf(buf, sizeof(buf), "0x%X", state);
			return std::string(buf);
		}

		inline std::string format_type_word(uint32_t type)
		{
			if (type == 0x1000000) return "IMAGE";
			if (type == 0x20000)   return "PRIVATE";
			if (type == 0x40000)   return "MAPPED";
			if (type == 0) return "";
			char buf[16];
			std::snprintf(buf, sizeof(buf), "0x%X", type);
			return std::string(buf);
		}

		inline ImU32 section_color(const binary_map::map_section_t& s, float a)
		{
			const auto& t = aida::ui::resolved();
			ImU32 base = t.info;
			if (s.executable && s.writable) base = t.warning;
			else if (s.executable)          base = t.error;
			else if (s.writable)            base = t.success;
			else                            base = t.info;
			return aida::ui::with_alpha(base, a);
		}

		inline ImU32 region_color(const live_region_t& r, float alpha)
		{
			const auto& t = aida::ui::resolved();
			ImU32 base = t.text_dim;
			if (r.is_guard || r.is_noaccess) base = t.error;
			else if (r.is_stack)             base = t.warning;
			else if (r.is_heap)              base = t.info_soft;
			else if (r.is_image)             base = t.success;
			else if (r.is_mapped)            base = t.info;
			else if (r.is_private && r.is_committed) base = t.accent_dim;
			else if (r.is_reserved)          base = t.text_dim;

			float fade = 1.f;
			if (!r.is_committed && !r.is_reserved) fade = 0.32f;
			else if (r.is_reserved) fade = 0.55f;

			return aida::ui::with_alpha(base, alpha * fade);
		}

		inline std::string section_perm_string(const binary_map::map_section_t& s)
		{
			std::string out;
			out += s.readable ? 'R' : '-';
			out += s.writable ? 'W' : '-';
			out += s.executable ? 'X' : '-';
			return out;
		}

		inline std::string region_kind_label(const live_region_t& r)
		{
			if (r.is_guard) return "GUARD";
			if (r.is_noaccess) return "NOACCESS";
			if (r.is_stack) return "STACK";
			if (r.is_heap) return "HEAP";
			if (r.is_image) return "IMAGE";
			if (r.is_mapped) return "MAPPED";
			if (r.is_private && r.is_committed) return "PRIVATE";
			if (r.is_reserved) return "RESERVED";
			return "FREE";
		}

		inline std::string format_function_summary(const binary_map::map_function_t& f)
		{
			std::string callees;
			for (std::size_t i = 0; i < f.top_callees.size() && i < 5; ++i) {
				if (i > 0) callees += ", ";
				callees += f.top_callees[i];
			}
			if (callees.empty()) callees = "(none)";

			char buf[512];
			std::snprintf(buf, sizeof(buf),
				"%s @ 0x%llX (xrefs=%d, callees: %s)",
				f.name.c_str(),
				static_cast<unsigned long long>(f.va),
				f.xref_count,
				callees.c_str());
			return std::string(buf);
		}

		inline void inject_to_chat(const std::string& text)
		{
			if (text.empty()) return;

			const std::size_t cap = sizeof(g_chat_buf) - 1u;
			const std::size_t cur = std::strlen(g_chat_buf);

			if (cur + text.size() < cap) {
				if (cur > 0) {
					if (cur + 2u < cap) {
						g_chat_buf[cur] = '\n';
						g_chat_buf[cur + 1u] = '\n';
						g_chat_buf[cur + 2u] = '\0';
					}
				}
				const std::size_t now = std::strlen(g_chat_buf);
				const std::size_t room = cap - now;
				const std::size_t copy = (text.size() < room) ? text.size() : room;
				std::memcpy(g_chat_buf + now, text.data(), copy);
				g_chat_buf[now + copy] = '\0';
				toast_notification::push("Binary map appended to chat input",
					toast_notification::toast_type_t::info, 3.0f);
			} else {
				ImGui::SetClipboardText(text.c_str());
				toast_notification::push(
					"Binary map exceeds chat buffer; copied to clipboard instead",
					toast_notification::toast_type_t::warning, 4.0f);
			}
		}

		inline bool live_available(const view_state_t& state)
		{
			const auto workspace = state.workspace.lock();
			const auto process = workspace ? workspace->identity().process() :
				std::optional<aida::analysis::process_identity_t>{};
			return driver_bridge::is_loaded()
				&& workspace
				&& workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot
				&& process && process->pid != 0
				&& driver_bridge::can_read_memory();
		}

		inline bool static_available(const view_state_t& state)
		{
			const auto workspace = state.workspace.lock();
			return workspace &&
				workspace->target_kind() == aida::analysis::target_kind_t::static_file &&
				workspace->image() && !workspace->closing() && !workspace->closed();
		}

		inline active_mode_t resolve_active_mode(const view_state_t& state, display_mode_t pref)
		{
			const bool live = live_available(state);
			const bool stat = static_available(state);
			if (pref == display_mode_t::live_only)   return live ? active_mode_t::live_process : active_mode_t::none;
			if (pref == display_mode_t::static_only) return stat ? active_mode_t::pe_static : active_mode_t::none;
			if (live && stat) return active_mode_t::merged;
			if (live)         return active_mode_t::live_process;
			if (stat)         return active_mode_t::pe_static;
			return active_mode_t::none;
		}

		inline void classify_region(live_region_t& r,
			const std::vector<driver_bridge::module_info_t>& modules,
			const std::vector<driver_bridge::thread_info_t>& threads,
			uint64_t process_heap)
		{
			r.is_committed = (r.state == 0x1000);
			r.is_reserved  = (r.state == 0x2000);
			r.is_guard     = (r.protect & 0x100) != 0;
			r.is_noaccess  = ((r.protect & 0xFF) == 0x01);
			r.is_image     = (r.type == 0x1000000);
			r.is_mapped    = (r.type == 0x40000);
			r.is_private   = (r.type == 0x20000);

			for (const auto& m : modules) {
				if (r.base >= m.base && r.base < m.base + static_cast<uint64_t>(m.size)) {
					r.module_name = m.name;
					r.module_path = m.path;
					break;
				}
			}

			for (const auto& th : threads) {
				if (th.rip == 0) continue;
				if (r.base <= th.rip && th.rip < r.base + r.size && r.is_private && r.is_committed) {
					r.is_stack = true;
					r.owner_tid = th.tid;
					break;
				}
			}

			if (!r.is_stack && r.is_private && r.is_committed && process_heap != 0) {
				if (r.base == process_heap) r.is_heap = true;
			}
		}

		inline void perform_refresh(const std::shared_ptr<view_state_t>& state)
		{
			if (!state) return;
			auto& s = *state;
			const auto workspace = s.workspace.lock();
			if (!workspace || workspace->target_kind() != aida::analysis::target_kind_t::static_file) {
				std::lock_guard<std::mutex> lock(s.mutex);
				s.last_error = "Static binary map requires an explicit static workspace.";
				return;
			}
			if (s.refreshing.exchange(true)) {
				diag::log_tagged_fmt("binary_map",
					"refresh SKIPPED already_in_flight");
				return;
			}

			binary_map::map_options_t opts_copy;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				opts_copy = s.opts;
			}

			diag::log_tagged_fmt("binary_map",
				"refresh START max_functions=%d max_globals=%d max_callees=%d imp=%d exp=%d",
				opts_copy.max_functions, opts_copy.max_globals,
				opts_copy.max_callees_per_function,
				opts_copy.include_imports ? 1 : 0,
				opts_copy.include_exports ? 1 : 0);
			const std::uint64_t request_generation = workspace->generation();
			const std::uint64_t refresh_serial = s.refresh_serial.fetch_add(1,
				std::memory_order_acq_rel) + 1;
			const std::string task_id = "binary_map.static_refresh." + s.binary_id + "." +
				std::to_string(refresh_serial);
			aida::ui::task_center::task_registration_t registration;
			registration.id = task_id;
			registration.source = "binary_map";
			registration.owner = "Binary Map";
			registration.owner_view = "view.analysis.binary_map";
			registration.owner_action = "Refresh static map";
			registration.target = workspace->identity().bin_name();
			registration.label = "Generate static Binary Map";
			registration.stage = "Queued workspace analysis";
			registration.affected_entity = workspace->identity().normalized_source_path();
			if (!aida::ui::task_center::register_task(std::move(registration))) {
				s.refreshing.store(false, std::memory_order_release);
				std::lock_guard<std::mutex> lock(s.mutex);
				s.last_error = "Task Center rejected ownership of the static Binary Map refresh.";
				return;
			}

			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "analysis";
			sub.label = "analysis.binary_map.refresh";
			sub.thread_class = "bounded_task";
			sub.domain = aida::infra::executor::domain_t::diagnostics;
			sub.priority = 3;
			sub.generation = request_generation;
			sub.body = [state, workspace, opts_copy, request_generation, task_id]() {
				auto& s = *state;
				struct refresh_guard_t {
					std::shared_ptr<view_state_t> state;
					~refresh_guard_t() {
						state->refreshing.store(false, std::memory_order_release);
					}
				} refresh_guard{state};
				static_cast<void>(refresh_guard);
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::running, 0.05f,
					"Generating static workspace map"));
				try {
				const auto start_clock = std::chrono::steady_clock::now();
				binary_map::clear_cache(workspace);

				binary_map::map_t fresh;
				bool ok = binary_map::generate(workspace, opts_copy, fresh);
				std::string err_copy;
				if (!ok) err_copy = "Workspace binary-map generation failed.";
				if (ok && workspace->generation() != request_generation) {
					ok = false;
					err_copy = "The workspace changed while the Binary Map was being generated.";
					s.refresh_requested.store(true, std::memory_order_release);
				}

				std::size_t f = 0, g_count = 0, i = 0, e = 0, sec = 0;
				std::string mod;
				if (ok) {
					f = fresh.functions.size();
					g_count = fresh.globals.size();
					i = fresh.imports.size();
					e = fresh.exports.size();
					sec = fresh.sections.size();
					mod = fresh.module_name;
				}

				if (ok) {
					auto published_map = std::make_shared<const binary_map::map_t>(std::move(fresh));
					auto rendered = std::make_shared<const std::string>(
						binary_map::render_text(*published_map, opts_copy));
					std::atomic_store_explicit(&s.map, std::move(published_map),
						std::memory_order_release);
					std::atomic_store_explicit(&s.rendered_text, std::move(rendered),
						std::memory_order_release);
				}
				{
					std::lock_guard<std::mutex> g(s.mutex);
					if (ok) {
						s.has_map.store(true);
						s.last_error.clear();
					} else {
						s.last_error = err_copy;
					}
				}
				const auto end_clock = std::chrono::steady_clock::now();
				const auto dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					end_clock - start_clock).count();

				if (ok) {
					diag::log_tagged_fmt("binary_map",
						"refresh DONE module='%s' sections=%zu funcs=%zu globals=%zu imports=%zu exports=%zu duration_ms=%lld",
						mod.c_str(), sec, f, g_count, i, e, static_cast<long long>(dur_ms));
				} else {
					diag::log_tagged_fmt("binary_map",
						"refresh FAILED err='%s' duration_ms=%lld",
						err_copy.c_str(), static_cast<long long>(dur_ms));
				}
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					ok ? aida::ui::task_center::task_state_t::completed
					   : workspace->generation() != request_generation
						? aida::ui::task_center::task_state_t::cancelled
						: aida::ui::task_center::task_state_t::failed,
					1.0f, ok ? "Static map published" : "Static map not published",
					ok ? std::to_string(sec) + " sections, " + std::to_string(f) +
						" functions" : err_copy));
				} catch (const std::exception& exception) {
					{
						std::lock_guard<std::mutex> lock(s.mutex);
						s.last_error = "Static Binary Map refresh failed: " +
							std::string(exception.what());
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Static refresh failed", exception.what()));
				} catch (...) {
					{
						std::lock_guard<std::mutex> lock(s.mutex);
						s.last_error = "Static Binary Map refresh failed with an unknown worker error.";
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Static refresh failed", "Unknown worker error"));
				}
			};
			const auto submitted = aida::infra::executor::submit(std::move(sub));

			if (!submitted.submitted) {
				s.refreshing.store(false);
				{
					std::lock_guard<std::mutex> lock(s.mutex);
					s.last_error = "Worker queue rejected the static Binary Map refresh: " +
						submitted.reject_reason;
				}
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::failed, 1.0f,
					"Worker queue rejected", submitted.reject_reason));
				diag::log_tagged_fmt("binary_map",
					"refresh FAILED post rejected by executor");
			}
		}

		inline void perform_live_refresh(const std::shared_ptr<view_state_t>& state)
		{
			if (!state) return;
			auto& s = *state;
			const auto workspace = s.workspace.lock();
			const auto process = workspace ? workspace->identity().process() :
				std::optional<aida::analysis::process_identity_t>{};
			if (!live_available(s) || !process) {
				diag::log_tagged_fmt("binary_map",
					"live_refresh SKIPPED driver_loaded=%d attached_pid=%u",
					driver_bridge::is_loaded() ? 1 : 0,
					process ? static_cast<unsigned>(process->pid) : 0u);
				return;
			}
			if (s.live_refreshing.exchange(true)) {
				diag::log_tagged_fmt("binary_map",
					"live_refresh SKIPPED already_in_flight");
				return;
			}

			diag::log_tagged_fmt("binary_map",
				"live_refresh START pid=%u",
				static_cast<unsigned>(process->pid));
			const std::uint64_t request_generation = workspace->generation();
			const std::uint64_t refresh_serial = s.live_refresh_serial.fetch_add(1,
				std::memory_order_acq_rel) + 1;
			const std::string task_id = "binary_map.live_refresh." + s.binary_id + "." +
				std::to_string(refresh_serial);
			aida::ui::task_center::task_registration_t registration;
			registration.id = task_id;
			registration.source = "binary_map";
			registration.owner = "Binary Map";
			registration.owner_view = "view.analysis.binary_map";
			registration.owner_action = "Refresh live map";
			registration.target = "PID " + std::to_string(process->pid);
			registration.label = "Enumerate live Binary Map";
			registration.stage = "Queued target enumeration";
			registration.affected_entity = workspace->identity().bin_name();
			if (!aida::ui::task_center::register_task(std::move(registration))) {
				s.live_refreshing.store(false, std::memory_order_release);
				std::lock_guard<std::mutex> lock(s.mutex);
				s.live_last_error = "Task Center rejected ownership of the live Binary Map refresh.";
				return;
			}

			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "analysis";
			sub.label = "analysis.binary_map.live_refresh";
			sub.thread_class = "bounded_task";
			sub.domain = aida::infra::executor::domain_t::diagnostics;
			sub.priority = 3;
			sub.target_pid = process->pid;
			sub.generation = request_generation;
			sub.body = [state, workspace, pid = process->pid, request_generation, task_id]() {
				auto& s = *state;
				struct refresh_guard_t {
					std::shared_ptr<view_state_t> state;
					~refresh_guard_t() {
						state->live_refreshing.store(false, std::memory_order_release);
					}
				} refresh_guard{state};
				static_cast<void>(refresh_guard);
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::running, 0.05f,
					"Enumerating target regions, modules, and threads"));
				try {
				const auto start_clock = std::chrono::steady_clock::now();

				auto regions_raw = driver_bridge::enumerate_memory_regions_for(pid, 8192);
				auto modules     = driver_bridge::enumerate_modules_for(pid);
				auto threads     = driver_bridge::enumerate_threads_for(pid);
				if (regions_raw.empty()) {
					const std::string error = "The target returned no readable memory-region enumeration.";
					{
						std::lock_guard<std::mutex> lock(s.mutex);
						s.live_last_error = error;
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Live enumeration failed", error));
					return;
				}
				const std::string proc_name = workspace->identity().bin_name();

				driver_bridge::peb_info_t peb{};
				uint64_t process_heap = 0;
				if (driver_bridge::read_peb_for(pid, peb)) {
					process_heap = peb.process_heap;
				}

				live_snapshot_t snap;
				snap.modules = std::move(modules);
				snap.threads = std::move(threads);
				snap.process_heap = process_heap;
				snap.pid = pid;
				snap.process_name = proc_name;
				snap.regions.reserve(regions_raw.size());

				uint64_t total_committed = 0;
				uint64_t total_reserved = 0;
				uint32_t rwx = 0;

				for (const auto& src : regions_raw) {
					live_region_t r;
					r.base = src.base;
					r.size = src.size;
					r.state = src.state;
					r.protect = src.protect;
					r.type = src.type;
					classify_region(r, snap.modules, snap.threads, snap.process_heap);

					if (r.is_committed) total_committed += r.size;
					if (r.is_reserved)  total_reserved  += r.size;

					const bool exec  = (r.protect & 0xF0) != 0;
					const uint32_t low = r.protect & 0xFF;
					const bool write = (low == 0x04) || (low == 0x08) || (low == 0x40) || (low == 0x80);
					if (exec && write) ++rwx;

					if (r.is_image && !r.module_name.empty()) {
						r.section_name.clear();
						if (const auto image = workspace->image()) {
							for (const auto& section : image->sections()) {
								const std::uint64_t section_start = image->image_base() +
									section.virtual_address;
								const std::uint64_t section_size = (std::max)(
									static_cast<std::uint64_t>(section.virtual_size),
									static_cast<std::uint64_t>(section.raw_size));
								if (r.base >= section_start && r.base - section_start < section_size) {
									r.section_name = section.name;
									break;
								}
							}
						}
					}

					if (r.is_stack) {
						char buf[64];
						std::snprintf(buf, sizeof(buf), "Thread %u stack",
							static_cast<unsigned>(r.owner_tid));
						r.info = buf;
					} else if (r.is_heap) {
						r.info = "Process heap";
					} else if (r.is_image && !r.module_name.empty()) {
						r.info = r.module_name;
					}

					snap.regions.push_back(std::move(r));
				}

				snap.total_committed = total_committed;
				snap.total_reserved  = total_reserved;
				snap.rwx_count = rwx;
				snap.generated_unix = static_cast<int64_t>(
					std::chrono::duration_cast<std::chrono::seconds>(
						std::chrono::system_clock::now().time_since_epoch()).count());

				const auto end_clock = std::chrono::steady_clock::now();
				snap.enum_elapsed_ms = static_cast<uint64_t>(
					std::chrono::duration_cast<std::chrono::milliseconds>(
						end_clock - start_clock).count());

				const auto current_process = workspace->identity().process();
				if (workspace->generation() != request_generation ||
					!current_process || current_process->pid != pid) {
					s.live_refresh_requested.store(true, std::memory_order_release);
					{
						std::lock_guard<std::mutex> lock(s.mutex);
						s.live_last_error = "The target or workspace changed during live enumeration.";
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::cancelled, 1.0f,
						"Discarded stale live map", "Target PID or workspace generation changed"));
					diag::log_tagged_fmt("binary_map",
						"live_refresh STALE pid=%u request_generation=%llu current_generation=%llu",
						static_cast<unsigned>(pid),
						static_cast<unsigned long long>(request_generation),
						static_cast<unsigned long long>(workspace->generation()));
					return;
				}
				auto published = std::make_shared<const live_snapshot_t>(std::move(snap));
				std::atomic_store_explicit(&s.live, published, std::memory_order_release);
				{
					std::lock_guard<std::mutex> lock(s.mutex);
					s.live_last_error.clear();
				}
				s.live_last_refresh_unix.store(static_cast<int64_t>(
					std::chrono::duration_cast<std::chrono::seconds>(
						std::chrono::system_clock::now().time_since_epoch()).count()));
				diag::log_tagged_fmt("binary_map",
					"live_refresh DONE pid=%u proc='%s' regions=%zu modules=%zu threads=%zu committed=%llu reserved=%llu rwx=%u elapsed_ms=%llu",
					static_cast<unsigned>(published->pid),
					published->process_name.c_str(),
					published->regions.size(),
					published->modules.size(),
					published->threads.size(),
					static_cast<unsigned long long>(published->total_committed),
					static_cast<unsigned long long>(published->total_reserved),
					static_cast<unsigned>(published->rwx_count),
					static_cast<unsigned long long>(published->enum_elapsed_ms));
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::completed, 1.0f,
					"Live map published", std::to_string(published->regions.size()) +
						" regions, " + std::to_string(published->modules.size()) + " modules"));
				} catch (const std::exception& exception) {
					{
						std::lock_guard<std::mutex> lock(s.mutex);
						s.live_last_error = "Live Binary Map refresh failed: " +
							std::string(exception.what());
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Live refresh failed", exception.what()));
				} catch (...) {
					{
						std::lock_guard<std::mutex> lock(s.mutex);
						s.live_last_error = "Live Binary Map refresh failed with an unknown worker error.";
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Live refresh failed", "Unknown worker error"));
				}
			};
			const auto submitted = aida::infra::executor::submit(std::move(sub));

			if (!submitted.submitted) {
				s.live_refreshing.store(false);
				{
					std::lock_guard<std::mutex> lock(s.mutex);
					s.live_last_error = "Worker queue rejected the live Binary Map refresh: " +
						submitted.reject_reason;
				}
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::failed, 1.0f,
					"Worker queue rejected", submitted.reject_reason));
				diag::log_tagged_fmt("binary_map",
					"live_refresh FAILED post rejected by executor");
			}
		}

		inline void ensure_subscriptions(const std::shared_ptr<view_state_t>& state_handle)
		{
			if (!state_handle) return;
			auto& s = *state_handle;
			const std::weak_ptr<view_state_t> weak_state = state_handle;
			const std::weak_ptr<aida::analysis::analysis_workspace_t> weak_workspace = s.workspace;
			if (!s.subscription_binary.valid()) {
				s.subscription_binary = aida::events::subscribe(
					aida::events::event_binary_loaded,
					[weak_state, weak_workspace](const aida::events::binary_loaded_t& payload)
					{
						auto state = weak_state.lock();
						auto workspace = weak_workspace.lock();
						if (!state || !workspace || workspace->identity().normalized_source_path() !=
							payload.binary_path) return;
						auto& vs = *state;
						vs.refresh_requested.store(true);
						vs.live_refresh_requested.store(true);
						bool identity_changed = false;
						{
							std::lock_guard<std::mutex> g(vs.mutex);
							identity_changed =
								vs.last_binary_identity_path != payload.binary_path ||
								vs.last_binary_identity_base != payload.image_base ||
								vs.last_binary_identity_size != payload.image_size;
							vs.last_binary_identity_path = payload.binary_path;
							vs.last_binary_identity_base = payload.image_base;
							vs.last_binary_identity_size = payload.image_size;
						if (identity_changed) {
							std::atomic_store_explicit(&vs.map,
								std::shared_ptr<const binary_map::map_t>(
									std::make_shared<binary_map::map_t>()),
								std::memory_order_release);
							vs.has_map.store(false, std::memory_order_release);
							vs.collapsed_groups.clear();
								vs.expanded_imports.clear();
								std::atomic_store_explicit(&vs.rendered_text,
									std::shared_ptr<const std::string>(std::make_shared<std::string>()),
									std::memory_order_release);
								vs.fn_pulses.clear();
							}
						}
						if (identity_changed) {
							vs.auto_refreshed_once = false;
							vs.selected_va.store(0);
							vs.hover_function_va = 0;
						}
						diag::log_tagged_fmt("binary_map",
							"event_binary_loaded path='%s' image_base=0x%llX image_size=%u identity_changed=%d -> refresh_requested + live_refresh_requested",
							payload.binary_path.c_str(),
							static_cast<unsigned long long>(payload.image_base),
							static_cast<unsigned>(payload.image_size),
							identity_changed ? 1 : 0);
					});
			}
			if (!s.subscription_proc_created.valid()) {
				s.subscription_proc_created = aida::events::subscribe(
					aida::events::event_process_created,
					[weak_state, weak_workspace](const aida::events::process_created_t& payload)
					{
						auto state = weak_state.lock();
						auto workspace = weak_workspace.lock();
						if (!state || !workspace || !workspace->identity().process() ||
							workspace->identity().process()->pid != payload.process_id) return;
						auto& vs = *state;
						vs.live_refresh_requested.store(true);
						diag::log_tagged_fmt("binary_map",
							"event_process_created pid=%u image='%s' -> live_refresh_requested",
							static_cast<unsigned>(payload.process_id),
							payload.image_name.c_str());
					});
			}
			if (!s.subscription_proc_exited.valid()) {
				s.subscription_proc_exited = aida::events::subscribe(
					aida::events::event_process_exited,
					[weak_state, weak_workspace](const aida::events::process_exited_t& payload)
					{
						auto state = weak_state.lock();
						auto workspace = weak_workspace.lock();
						if (!state || !workspace || !workspace->identity().process() ||
							workspace->identity().process()->pid != payload.process_id) return;
						auto& vs = *state;
						std::atomic_store_explicit(&vs.live,
							std::shared_ptr<const live_snapshot_t>(std::make_shared<live_snapshot_t>()),
							std::memory_order_release);
						vs.live_selected_base.store(0);
						vs.live_hover_index.store(-1);
						diag::log_tagged_fmt("binary_map",
							"event_process_exited pid=%u -> live snapshot cleared",
							static_cast<unsigned>(payload.process_id));
					});
			}
		}

		inline void jump_to_address(view_state_t& state, uint64_t va)
		{
			if (va == 0) {
				diag::log_tagged_fmt("binary_map",
					"jump_to_address SKIPPED va=0x0");
				return;
			}
			const auto context = disasm_view::capture_workspace(state.workspace.lock());
			if (!context) return;
			aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
			disasm_view::goto_address(va, context);
			diag::log_tagged_fmt("binary_map",
				"jump_to_disasm va=0x%llX",
				static_cast<unsigned long long>(va));
		}

		inline void set_function_pinned(view_state_t& state, uint64_t va, bool pinned)
		{
			const auto workspace = state.workspace.lock();
			if (!workspace) return;
			if (pinned) binary_map::pin_function(workspace, va);
			else binary_map::unpin_function(workspace, va);
		}

		inline void jump_to_hex(view_state_t& state, uint64_t va, std::size_t size)
		{
			if (va == 0) {
				diag::log_tagged_fmt("binary_map",
					"[binmap_audit] jump_to_hex SKIPPED va=0x0");
				return;
			}
			if (size == 0) size = 0x200;
			const std::size_t kMaxHex = 1u * 1024u * 1024u;
			if (size > kMaxHex) size = kMaxHex;

			const auto context = disasm_view::capture_workspace(state.workspace.lock());
			if (!context) return;
			const bool live_ok = context.workspace->target_kind() ==
				aida::analysis::target_kind_t::live_snapshot;
			bool used_static = false;
			bool ok = false;
			if (live_ok) {
				ok = hex_view::request_live_memory(context, va, size);
			}
			if (!ok) {
				const auto address = disasm_view::typed_address(context, va);
				auto blob = address ? disasm_view::read_bytes(context, *address, size) :
					aida::analysis::workspace_result_t<std::vector<std::uint8_t>>::failure(
						aida::analysis::make_workspace_error(
							aida::analysis::workspace_error_code_t::out_of_range,
							"Address is outside the selected workspace", "binary_map.hex"));
				if (blob && !blob.value().empty()) {
					hex_view::activate(context);
					ok = true;
					used_static = true;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::hex::receipts.push_back({ "binary_map.activate", va });
#endif
				}
			}
			if (ok) {
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
				diag::log_tagged_fmt("binary_map",
					"jump_to_hex va=0x%llX size=%zu path=%s",
					static_cast<unsigned long long>(va), size,
					used_static ? "static_pe" : "live");
			} else {
				toast_notification::push("Hex view: failed to read bytes",
					toast_notification::toast_type_t::warning, 2.5f);
				diag::log_tagged_fmt("binary_map",
					"[binmap_audit] jump_to_hex FAILED va=0x%llX size=%zu live_ok=%d",
					static_cast<unsigned long long>(va), size,
					live_ok ? 1 : 0);
			}
		}

		inline bool dump_region_to_disk(view_state_t& state, uint64_t base, uint64_t size,
			const std::string& kind_label)
		{
			if (size == 0) {
				toast_notification::push("Region has zero size",
					toast_notification::toast_type_t::error, 2.5f);
				return false;
			}
			const uint64_t kMaxDump = 256ULL * 1024ULL * 1024ULL;
			if (size > kMaxDump) {
				toast_notification::push("Region exceeds 256 MiB dump cap",
					toast_notification::toast_type_t::warning, 3.0f);
				return false;
			}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			(void)state;
			char receipt[192];
			std::snprintf(receipt, sizeof(receipt), "Dump %s 0x%016llX (%llu bytes)",
				kind_label.empty() ? "region" : kind_label.c_str(),
				static_cast<unsigned long long>(base),
				static_cast<unsigned long long>(size));
			ImGui::SetClipboardText(receipt);
			toast_notification::push("Region dump receipt copied",
				toast_notification::toast_type_t::info, 3.5f);
			return true;
#else

			char default_name[96] = {};
			std::snprintf(default_name, sizeof(default_name),
				"dump_%s_%016llX_%llu.bin",
				kind_label.empty() ? "region" : kind_label.c_str(),
				static_cast<unsigned long long>(base),
				static_cast<unsigned long long>(size));

			char path_buf[MAX_PATH] = {};
			std::strncpy(path_buf, default_name, sizeof(path_buf) - 1);

			static const char k_dump_filter[] =
				"Binary (*.bin)\0*.bin\0"
				"All files (*.*)\0*.*\0\0";

			if (!win32_dialog::show_save_file_dialog(g_hwnd,
				"Dump Region",
				k_dump_filter,
				"bin",
				path_buf, sizeof(path_buf),
				"binary_map_view::dump_region"))
			{
				diag::log_tagged_fmt("binary_map",
					"dump_region cancelled base=0x%llX size=%llu",
					static_cast<unsigned long long>(base),
					static_cast<unsigned long long>(size));
				return false;
			}
			const auto context = disasm_view::capture_workspace(state.workspace.lock());
			if (!context) return false;
			const std::string output_path = path_buf;
			static std::atomic<std::uint64_t> dump_sequence{1};
			const std::string task_id = "analysis.binary_map.dump." +
				std::to_string(dump_sequence.fetch_add(1, std::memory_order_relaxed));

			diag::log_tagged_critical_fmt("binary_map",
				"dump_region START base=0x%llX size=%llu path='%s'",
				static_cast<unsigned long long>(base),
				static_cast<unsigned long long>(size),
				path_buf);

			aida::ui::task_center::task_registration_t registration;
			registration.id = task_id;
			registration.source = "analysis.binary_map";
			registration.owner = "Binary Map";
			registration.owner_view = "view.analysis.binary_map";
			registration.owner_action = "analysis.binary_map.dump_region";
			registration.target = output_path;
			registration.label = "Dump Binary Map region";
			registration.stage = "Queued for exact target read and atomic dump";
			registration.affected_entity = output_path;
			registration.callbacks.focus = [] {
				static_cast<void>(aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.analysis.binary_map")));
			};
			registration.callbacks.open_log = registration.callbacks.focus;
			if (!aida::ui::task_center::register_task(std::move(registration))) {
				toast_notification::push("Task Center rejected the region dump",
					toast_notification::toast_type_t::error, 3.0f);
				return false;
			}
			aida::infra::executor::submission_t submission;
			submission.owner_subsystem = "analysis";
			submission.label = "analysis.binary_map.dump_region";
			submission.thread_class = "bounded_file_io";
			submission.domain = aida::infra::executor::domain_t::external_tool;
			submission.priority = 2;
			submission.target_pid = context.workspace->identity().process()
				? context.workspace->identity().process()->pid : 0;
			submission.session_id = task_id.c_str();
			submission.target_id = output_path.c_str();
			submission.generation = context.workspace->generation();
			submission.diagnostic_id = task_id.c_str();
			submission.ui_access_policy = "immutable_snapshots_only";
			submission.failure_policy = "typed_diagnostic";
			submission.shutdown_policy = "drain";
			submission.body = [context, base, size, output_path, task_id]() {
				try {
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::running, -1.0f,
						"Reading exact bytes from the captured target identity"));
					std::vector<uint8_t> buffer;
					if (context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot &&
						context.workspace->identity().process()) {
						driver_bridge::read_memory_for(context.workspace->identity().process()->pid,
							base, static_cast<std::size_t>(size), buffer);
					} else if (const auto address = disasm_view::typed_address(context, base)) {
						auto bytes = disasm_view::read_bytes(context, *address,
							static_cast<std::size_t>(size));
						if (bytes) buffer = std::move(bytes.value());
					}
					if (buffer.size() != static_cast<std::size_t>(size)) {
						static_cast<void>(aida::ui::task_center::update_task(task_id,
							aida::ui::task_center::task_state_t::failed, 1.0f,
							"Exact target read failed",
							"Requested " + std::to_string(size) + " bytes but received " +
							std::to_string(buffer.size()), "diagnostic." + task_id));
						return;
					}
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::running, -1.0f,
						"Writing a same-directory temporary file"));
					std::string error;
					if (!atomic_write_exact(output_path, buffer.data(), buffer.size(), error)) {
						static_cast<void>(aida::ui::task_center::update_task(task_id,
							aida::ui::task_center::task_state_t::failed, 1.0f,
							"Atomic region dump failed", error, "diagnostic." + task_id));
						return;
					}
					diag::log_tagged_critical_fmt("binary_map",
						"dump_region DONE bytes=%zu path='%s'", buffer.size(), output_path.c_str());
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::completed, 1.0f,
						"Finished", "Region dumped atomically to " + output_path));
				} catch (const std::exception& exception) {
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Region dump failed", exception.what(), "diagnostic." + task_id));
				} catch (...) {
					static_cast<void>(aida::ui::task_center::update_task(task_id,
						aida::ui::task_center::task_state_t::failed, 1.0f,
						"Region dump failed", "Unknown dump failure", "diagnostic." + task_id));
				}
			};
			const auto submitted = aida::infra::executor::submit(std::move(submission));
			if (!submitted.submitted) {
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::failed, 1.0f,
					"Executor rejected region dump", submitted.reject_reason,
					"diagnostic." + task_id));
				toast_notification::push("The region dump could not be queued; see Task Center",
					toast_notification::toast_type_t::error, 3.0f);
				return false;
			}
			return true;
#endif
		}

		inline std::string make_function_chat_payload(const binary_map::map_function_t& f)
		{
			std::string out = "Binary map function summary:\n";
			out += format_function_summary(f);
			if (!f.section_name.empty()) {
				out += "\nSection: ";
				out += f.section_name;
			}
			if (f.pinned) out += "\n(pinned)";
			out += "\n";
			return out;
		}

		inline std::string make_global_chat_payload(const binary_map::map_global_t& g)
		{
			char buf[256];
			std::snprintf(buf, sizeof(buf),
				"Binary map global: %s @ 0x%llX (xrefs=%d, %s%s)\n",
				g.name.c_str(),
				static_cast<unsigned long long>(g.va),
				g.xref_count,
				g.writable ? "rw" : "ro",
				g.section_name.empty() ? "" : (std::string(", ") + g.section_name).c_str());
			return std::string(buf);
		}

		inline std::string make_region_chat_payload(const live_region_t& r)
		{
			std::string out = "Live memory region:\n";
			char buf[512];
			std::snprintf(buf, sizeof(buf),
				"  Base 0x%016llX  Size %s\n"
				"  Kind %s  State %s  Type %s  Protect %s\n",
				static_cast<unsigned long long>(r.base),
				format_size_human(r.size).c_str(),
				region_kind_label(r).c_str(),
				format_state_word(r.state).c_str(),
				format_type_word(r.type).c_str(),
				format_protect_word(r.protect).c_str());
			out += buf;
			if (!r.module_name.empty()) {
				std::snprintf(buf, sizeof(buf), "  Module %s\n", r.module_name.c_str());
				out += buf;
			}
			if (!r.info.empty()) {
				std::snprintf(buf, sizeof(buf), "  Info %s\n", r.info.c_str());
				out += buf;
			}
			return out;
		}

		inline std::string region_to_json(const live_region_t& r)
		{
			std::string out = "{";
			char buf[256];
			std::snprintf(buf, sizeof(buf), "\"base\":\"0x%016llX\",",
				static_cast<unsigned long long>(r.base)); out += buf;
			std::snprintf(buf, sizeof(buf), "\"size\":%llu,",
				static_cast<unsigned long long>(r.size)); out += buf;
			std::snprintf(buf, sizeof(buf), "\"protect\":\"0x%X\",", r.protect); out += buf;
			std::snprintf(buf, sizeof(buf), "\"state\":\"0x%X\",", r.state); out += buf;
			std::snprintf(buf, sizeof(buf), "\"type\":\"0x%X\",", r.type); out += buf;
			out += "\"kind\":\"" + region_kind_label(r) + "\",";
			out += "\"module\":\"" + r.module_name + "\",";
			out += "\"info\":\"" + r.info + "\"";
			out += "}";
			return out;
		}

		inline std::string export_live_snapshot_json(const live_snapshot_t& snap)
		{
			std::string out;
			char hdr[256];
			std::snprintf(hdr, sizeof(hdr),
				"{\"pid\":%u,\"process\":\"%s\",\"committed\":%llu,\"reserved\":%llu,"
				"\"rwx_count\":%u,\"region_count\":%zu,\"regions\":[",
				static_cast<unsigned>(snap.pid),
				snap.process_name.c_str(),
				static_cast<unsigned long long>(snap.total_committed),
				static_cast<unsigned long long>(snap.total_reserved),
				static_cast<unsigned>(snap.rwx_count),
				snap.regions.size());
			out = hdr;
			for (std::size_t i = 0; i < snap.regions.size(); ++i) {
				if (i) out += ",";
				out += region_to_json(snap.regions[i]);
			}
			out += "]}";
			return out;
		}

		inline bool group_is_collapsed(view_state_t& s, const std::string& key)
		{
			return s.collapsed_groups.count(key) != 0;
		}

		inline void toggle_group(view_state_t& s, const std::string& key)
		{
			auto it = s.collapsed_groups.find(key);
			if (it == s.collapsed_groups.end())
				s.collapsed_groups.insert(key);
			else
				s.collapsed_groups.erase(it);
		}

		inline float section_entropy_normalized(const binary_map::map_section_t& s)
		{
			if (s.sampled_bytes == 0) return 0.f;
			float e = s.entropy;
			if (e < 0.f) e = 0.f;
			if (e > 1.f) e = 1.f;
			return e;
		}

		inline void render_section_strip(ImDrawList* dl, ImVec2 origin, float width,
			const std::vector<binary_map::map_section_t>& sections,
			uint64_t image_size, float alpha, float anim_time, view_state_t& state)
		{
			if (sections.empty()) {
				const auto& t = aida::ui::resolved();
				dl->AddText(ImVec2(origin.x + 8.f, origin.y + 8.f),
					aida::ui::with_alpha(t.text_dim, alpha),
					"(no section table available)");
				return;
			}
			const auto& t = aida::ui::resolved();
			float total_size = 0.f;
			for (const auto& s : sections) total_size += static_cast<float>(s.size);
			if (total_size < 1.f) total_size = 1.f;
			float min_size = static_cast<float>(image_size);
			if (min_size < total_size) min_size = total_size;

			const float strip_h = 38.f;
			const float gap = 2.f;
			float x = origin.x;
			float y = origin.y;

			float anim_p = anim_time * 0.45f;
			if (anim_p > 1.f) anim_p = 1.f;
			float reveal = aida::motion::ease::out_cubic(anim_p);

			float total_w = width - gap * static_cast<float>(sections.size() - 1);
			for (std::size_t i = 0; i < sections.size(); ++i) {
				const auto& s = sections[i];
				float frac = static_cast<float>(s.size) / total_size;
				float sw = total_w * frac;
				if (sw < 28.f) sw = 28.f;
				if (x + sw > origin.x + width) sw = origin.x + width - x;
				if (sw <= 1.f) break;

				float effective_w = sw * reveal;
				ImVec2 a = ImVec2(x, y);
				ImVec2 b = ImVec2(x + effective_w, y + strip_h);

				ImU32 base = section_color(s, alpha);
				ImU32 dim  = aida::ui::with_alpha(base, alpha * 0.32f);

				dl->AddRectFilled(a, b, dim, 4.f);
				dl->AddRectFilledMultiColor(a, b,
					base, base,
					aida::ui::with_alpha(base, alpha * 0.55f),
					aida::ui::with_alpha(base, alpha * 0.55f));
				dl->AddRect(a, b, aida::ui::with_alpha(t.border_subtle, alpha), 4.f, 0, 1.f);

				ImFont* font = aida::ui::fonts::body_em();
				if (!font) font = ImGui::GetFont();
				float fs = aida::ui::fonts::size_or(font, 16.f);
				ImU32 lbl_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 245), alpha);
				ImVec2 ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, s.name.c_str());
				if (effective_w > ts.x + 14.f) {
					dl->AddText(font, fs, ImVec2(a.x + 8.f, a.y + (strip_h - fs) * 0.5f),
						lbl_col, s.name.c_str());

					float perm_w = effective_w - ts.x - 18.f;
					ImFont* perm_font = aida::ui::fonts::caption();
					if (!perm_font) perm_font = font;
					float perm_fs = aida::ui::fonts::size_or(perm_font, 13.f);
					if (perm_w > 36.f) {
						std::string p = section_perm_string(s);
						ImVec2 perm_sz = perm_font->CalcTextSizeA(perm_fs, FLT_MAX, 0.f, p.c_str());
						dl->AddText(perm_font, perm_fs,
							ImVec2(b.x - perm_sz.x - 8.f, a.y + (strip_h - perm_fs) * 0.5f),
							aida::ui::with_alpha(IM_COL32(255, 255, 255, 220), alpha * 0.85f),
							p.c_str());
					}
				}

				ImGui::SetCursorScreenPos(a);
				ImGui::PushID(static_cast<int>(i));
				ImGui::InvisibleButton("##sec", ImVec2(effective_w, strip_h));
				if (ImGui::IsItemHovered()) {
					ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
					ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
					if (ImGui::BeginTooltip()) {
						ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
						ImGui::Text("%s   %s   %s",
							s.name.c_str(),
							section_perm_string(s).c_str(),
							format_size_human(s.size).c_str());
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
							"VA   0x%llX", static_cast<unsigned long long>(s.va));
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
							"End  0x%llX", static_cast<unsigned long long>(s.va + s.size));
						const float ent01 = section_entropy_normalized(s);
						if (s.sampled_bytes > 0) {
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary),
								"Entropy %.2f bits/byte  (%.0f%%)",
								static_cast<double>(ent01) * 8.0,
								static_cast<double>(ent01) * 100.0);
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
								"sampled %s of %s",
								format_size_human(s.sampled_bytes).c_str(),
								format_size_human(s.size).c_str());
							const char* verdict =
								(ent01 > 0.94f) ? "very high (packed/encrypted)" :
								(ent01 > 0.80f) ? "high (compressed)" :
								(ent01 > 0.55f) ? "moderate (mixed code/data)" :
								(ent01 > 0.30f) ? "low (text/structured)" :
								                  "very low (sparse)";
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary),
								"Verdict: %s", verdict);
						} else {
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
								"Entropy: (not sampled)");
						}
						ImGui::PopStyleColor();
						ImGui::EndTooltip();
					}
					ImGui::PopStyleColor();
					ImGui::PopStyleVar();
				}
				if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
					diag::log_tagged_fmt("binary_map",
						"section_strip_click name='%s' va=0x%llX size=%llu perm=%s entropy01=%.3f",
						s.name.c_str(),
						static_cast<unsigned long long>(s.va),
						static_cast<unsigned long long>(s.size),
						section_perm_string(s).c_str(),
						static_cast<double>(section_entropy_normalized(s)));
					detail::jump_to_address(state, s.va);
				}
				if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
					diag::log_tagged_fmt("binary_map",
						"section_strip_right_click_open_hex name='%s' va=0x%llX size=%llu",
						s.name.c_str(),
						static_cast<unsigned long long>(s.va),
						static_cast<unsigned long long>(s.size));
					detail::jump_to_hex(state, s.va, detail::hex_request_size(s.size));
				}
				ImGui::PopID();

				x += sw + gap;
				if (x >= origin.x + width) break;
			}

			float entropy_y = y + strip_h + 4.f;
			x = origin.x;
			for (std::size_t i = 0; i < sections.size(); ++i) {
				const auto& s = sections[i];
				float frac = static_cast<float>(s.size) / total_size;
				float sw = total_w * frac;
				if (sw < 28.f) sw = 28.f;
				if (x + sw > origin.x + width) sw = origin.x + width - x;
				if (sw <= 1.f) break;
				float entropy = section_entropy_normalized(s) * reveal;
				const float bar_track_w = sw - 8.f;
				float bar_w = bar_track_w * entropy;
				if (bar_w < 0.f) bar_w = 0.f;
				if (bar_w > bar_track_w) bar_w = bar_track_w;
				ImU32 ec = (s.sampled_bytes > 0)
					? aida::ui::mix(t.success, t.error, entropy)
					: aida::ui::with_alpha(t.text_dim, alpha * 0.5f);
				const float bar_h = 4.f;
				dl->AddRectFilled(ImVec2(x + 4.f, entropy_y),
					ImVec2(x + 4.f + bar_track_w, entropy_y + bar_h),
					aida::ui::with_alpha(t.border_subtle, alpha * 0.55f), 1.5f);
				if (bar_w > 0.5f) {
					dl->AddRectFilled(ImVec2(x + 4.f, entropy_y),
						ImVec2(x + 4.f + bar_w, entropy_y + bar_h),
						aida::ui::with_alpha(ec, alpha * 0.9f), 1.5f);
				}
				if (s.sampled_bytes > 0) {
					ImFont* tiny = aida::ui::fonts::caption();
					if (!tiny) tiny = ImGui::GetFont();
					const float tiny_fs = aida::ui::fonts::size_or(tiny, 11.f / 0.85f) * 0.85f;
					char ebuf[24];
					std::snprintf(ebuf, sizeof(ebuf), "%.2f",
						static_cast<double>(section_entropy_normalized(s)) * 8.0);
					ImVec2 esz = tiny->CalcTextSizeA(tiny_fs, FLT_MAX, 0.f, ebuf);
					if (sw > esz.x + 18.f) {
						dl->AddText(tiny, tiny_fs,
							ImVec2(x + sw - esz.x - 6.f, entropy_y + bar_h + 2.f),
							aida::ui::with_alpha(ec, alpha * 0.95f), ebuf);
					}
				}
				x += sw + gap;
			}
		}

		inline ImU32 heatmap_color(int xrefs, int max_xrefs, float alpha)
		{
			const auto& t = aida::ui::resolved();
			float v = (max_xrefs > 0) ? static_cast<float>(xrefs) / static_cast<float>(max_xrefs) : 0.f;
			if (v > 1.f) v = 1.f;
			ImU32 cool = t.info_soft;
			ImU32 mid  = t.accent_dim;
			ImU32 hot  = t.warning;
			ImU32 c;
			if (v < 0.5f) {
				c = aida::ui::mix(cool, mid, v * 2.f);
			} else {
				c = aida::ui::mix(mid, hot, (v - 0.5f) * 2.f);
			}
			return aida::ui::with_alpha(c, alpha * (0.45f + v * 0.55f));
		}

		inline void render_function_heatmap(ImDrawList* dl, ImVec2 origin, float width, float height,
			const std::vector<binary_map::map_function_t>& funcs,
			view_state_t& vs, float alpha, float anim_time, uint64_t selected_va)
		{
			const auto& t = aida::ui::resolved();
			vs.hover_function_va = 0;
			if (funcs.empty()) {
				ImVec2 sz = ImVec2(width, height);
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::dots;
				cfg.title = "No functions available";
				cfg.body  = "Run analysis or wait for the binary map to populate.";
				cfg.max_width = 320.f;
				aida::ui::empty_state::render(origin, sz, cfg);
				return;
			}

			int max_xrefs = 0;
			for (const auto& f : funcs)
				if (f.xref_count > max_xrefs) max_xrefs = f.xref_count;
			if (max_xrefs <= 0) max_xrefs = 1;

			const float cell_size = 14.f;
			const float gap = 3.f;
			int cols = static_cast<int>((width + gap) / (cell_size + gap));
			if (cols < 4) cols = 4;
			const int function_count = count_as_int(funcs.size());
			int rows = function_count / cols + (function_count % cols == 0 ? 0 : 1);
			float used_h = static_cast<float>(rows) * (cell_size + gap);
			if (used_h > height) used_h = height;

			float anim_p = anim_time * 0.5f;
			if (anim_p > 1.f) anim_p = 1.f;

			for (std::size_t i = 0; i < funcs.size(); ++i) {
				if (i > static_cast<std::size_t>((std::numeric_limits<int>::max)())) break;
				int r = static_cast<int>(i) / cols;
				int c = static_cast<int>(i) % cols;
				float ax = origin.x + static_cast<float>(c) * (cell_size + gap);
				float ay = origin.y + static_cast<float>(r) * (cell_size + gap);
				if (ay + cell_size > origin.y + used_h) break;

				const auto& fn = funcs[i];
				float entrance = anim_p - static_cast<float>(i) * 0.0008f;
				if (entrance < 0.f) entrance = 0.f;
				if (entrance > 1.f) entrance = 1.f;
				float scale = 0.7f + 0.3f * aida::motion::ease::out_back(entrance);

				ImGui::SetCursorScreenPos(ImVec2(ax, ay));
				ImGui::PushID(static_cast<int>(0x10000000u | static_cast<unsigned>(i)));
				ImGui::InvisibleButton("##bm_heat_cell", ImVec2(cell_size, cell_size));
				const bool hovered = ImGui::IsItemHovered();
				const bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				const bool double_clicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
					&& ImGui::IsItemHovered();
				const bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
				ImGui::PopID();

				bool selected = (selected_va == fn.va) && (fn.va != 0);
				ImU32 fill = heatmap_color(fn.xref_count, max_xrefs, alpha * entrance);
				ImU32 border = aida::ui::with_alpha(t.border_subtle, alpha * 0.6f);
				if (selected) border = aida::ui::with_alpha(t.accent_u32, alpha);

				float ch = cell_size * scale;
				float pad = (cell_size - ch) * 0.5f;
				ImVec2 ca = ImVec2(ax + pad, ay + pad);
				ImVec2 cb = ImVec2(ax + cell_size - pad, ay + cell_size - pad);

				if (fn.pinned) {
					ImU32 ring = aida::ui::with_alpha(t.accent_u32, alpha * 0.85f);
					dl->AddRect(ImVec2(ca.x - 1.f, ca.y - 1.f), ImVec2(cb.x + 1.f, cb.y + 1.f),
						ring, 3.f, 0, 1.5f);
				}

				dl->AddRectFilled(ca, cb, fill, 3.f);
				dl->AddRect(ca, cb, border, 3.f, 0, 1.f);

				auto& pulse = vs.fn_pulses[fn.va];
				if (hovered) pulse.v = aida::motion::smooth_lerp(pulse.v, 1.f, 18.f, aida::ui::clock::dt());
				else         pulse.v = aida::motion::smooth_lerp(pulse.v, 0.f, 12.f, aida::ui::clock::dt());
				if (pulse.v > 0.01f) {
					ImU32 hov_ring = aida::ui::with_alpha(t.accent_hover, alpha * 0.9f * pulse.v);
					float exp = pulse.v * 2.f;
					dl->AddRect(ImVec2(ca.x - exp, ca.y - exp), ImVec2(cb.x + exp, cb.y + exp),
						hov_ring, 4.f, 0, 1.5f);
				}

				if (hovered) {
					vs.hover_function_va = fn.va;
					const ImVec2 mp = ImGui::GetMousePos();
					ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
					ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
					ImGui::SetNextWindowPos(ImVec2(mp.x + 14.f, mp.y + 14.f));
					if (ImGui::Begin("##bm_fn_tip", nullptr,
						ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
						ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
						ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_AlwaysAutoResize |
						ImGuiWindowFlags_NoNav | ImGuiWindowFlags_Tooltip)) {
						ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
						ImGui::TextUnformatted(fn.name.c_str());
						ImGui::PopStyleColor();
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
							"0x%llX", static_cast<unsigned long long>(fn.va));
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_secondary),
							"xrefs %d   callees %d", fn.xref_count, fn.callee_count);
						if (!fn.section_name.empty()) {
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(t.text_dim),
								"in %s", fn.section_name.c_str());
						}
					}
					ImGui::End();
					ImGui::PopStyleColor();
					ImGui::PopStyleVar();
				}
				if (clicked) {
					vs.selected_va.store(fn.va);
					diag::log_tagged_fmt("binary_map",
						"heatmap_select name='%s' va=0x%llX xrefs=%d callees=%d",
						fn.name.c_str(),
						static_cast<unsigned long long>(fn.va),
						fn.xref_count, fn.callee_count);
				}
				if (double_clicked) {
					diag::log_tagged_fmt("binary_map",
						"heatmap_double_click name='%s' va=0x%llX",
						fn.name.c_str(),
						static_cast<unsigned long long>(fn.va));
					jump_to_address(vs, fn.va);
				}
				const bool keyboard_context = keyboard_context_requested(
					selected_va == fn.va);
				if (right_clicked || keyboard_context) {
					diag::log_tagged_fmt("binary_map",
						"heatmap_right_click name='%s' va=0x%llX",
						fn.name.c_str(),
						static_cast<unsigned long long>(fn.va));
					vs.selected_va.store(fn.va);
					aida::ui::application_ui::retained_entity_context_t retained;
					retained.owner_id = "analysis.binary_map.heat_function";
					retained.entity_id = std::to_string(fn.va) + ":" + fn.name;
					retained.entity_generation = vs.workspace_generation;
					retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
					const uint64_t va = fn.va;
					const uint64_t generation = vs.workspace_generation;
					retained.validate_identity = [&vs, va, generation] {
						return vs.workspace_generation == generation && vs.selected_va.load() == va
							? aida::ui::capability_state_t::available()
							: aida::ui::capability_state_t::unavailable(
								"The Binary Map workspace or selected function changed");
					};
					add_retained_action(retained, "analysis.binary_map.function.follow_disassembly",
						true, "", [&vs, va] {
							jump_to_address(vs, va);
							return aida::ui::action_handler_result_t::completed();
						});
					add_retained_action(retained, "analysis.binary_map.function.open_hex",
						true, "", [&vs, va] {
							jump_to_hex(vs, va, 0x400);
							return aida::ui::action_handler_result_t::completed();
						});
					aida::ui::application_ui::open_retained_entity_context_menu(
						std::move(retained), context_origin(right_clicked));
				}
				aida::ui::application_ui::render_retained_entity_context_menu(
					"analysis.binary_map.heat_function");
			}
		}

		inline int region_index_for_va(const std::vector<live_region_t>& regions, uint64_t va)
		{
			for (std::size_t i = 0; i < regions.size(); ++i) {
				const auto& r = regions[i];
				if (va >= r.base && va < r.base + r.size) {
					return i <= static_cast<std::size_t>((std::numeric_limits<int>::max)())
						? static_cast<int>(i)
						: -1;
				}
			}
			return -1;
		}

		inline void render_address_space_canvas(ImDrawList* dl, ImVec2 origin, float width, float height,
			const std::vector<live_region_t>& regions,
			const std::vector<driver_bridge::thread_info_t>& threads,
			view_state_t& vs, float alpha, float, uint64_t selected_base)
		{
			const auto& t = aida::ui::resolved();
			ImVec2 a = origin;
			ImVec2 b = ImVec2(origin.x + width, origin.y + height);

			aida::ui::blur::render_glass_fill(dl, a, b, 8.f, alpha);
			aida::ui::blur::render_glass_border(dl, a, b, 8.f, alpha, 1.f);

			ImFont* hdr_font = aida::ui::fonts::body_em();
			if (!hdr_font) hdr_font = ImGui::GetFont();
			const float hdr_fs = aida::ui::fonts::size_or(hdr_font, 16.f);
			dl->AddText(hdr_font, hdr_fs, ImVec2(a.x + 12.f, a.y + 8.f),
				aida::ui::with_alpha(t.text_secondary, alpha), "Address Space");

			if (regions.empty()) {
				ImFont* body = aida::ui::fonts::body();
				if (!body) body = ImGui::GetFont();
				const float body_fs = aida::ui::fonts::size_or(body, 16.f);
				const char* msg = "Attach to a process or refresh to see live mappings.";
				ImVec2 ts = body->CalcTextSizeA(body_fs, FLT_MAX, 0.f, msg);
				dl->AddText(body, body_fs,
					ImVec2(a.x + (width - ts.x) * 0.5f, a.y + (height - ts.y) * 0.5f),
					aida::ui::with_alpha(t.text_dim, alpha), msg);
				return;
			}

			const float canvas_top = a.y + 36.f;
			const float canvas_bot = b.y - 24.f;
			const float canvas_h = canvas_bot - canvas_top;
			if (canvas_h <= 10.f) return;

			const float canvas_left = a.x + 14.f;
			const float canvas_right = b.x - 110.f;
			const float canvas_w = canvas_right - canvas_left;
			if (canvas_w <= 20.f) return;

			uint64_t va_min = regions.front().base;
			uint64_t va_max = regions.back().base + regions.back().size;
			if (va_max <= va_min) va_max = va_min + 1;
			const double full_span = static_cast<double>(va_max - va_min);

			const float zoom = vs.canvas_zoom;
			const double visible_span = full_span / static_cast<double>(zoom);
			double offset_norm = vs.canvas_offset_norm;
			if (offset_norm < 0.0) offset_norm = 0.0;
			if (offset_norm > 1.0 - 1.0 / static_cast<double>(zoom)) {
				offset_norm = 1.0 - 1.0 / static_cast<double>(zoom);
				if (offset_norm < 0.0) offset_norm = 0.0;
			}
			vs.canvas_offset_norm = offset_norm;
			vs.canvas_target_offset_norm = offset_norm;

			const double view_low_off = offset_norm * full_span;
			const uint64_t view_va_low  = va_min + static_cast<uint64_t>(view_low_off);
			const uint64_t view_va_high = view_va_low + static_cast<uint64_t>(visible_span);

			ImVec2 strip_a = ImVec2(canvas_left, canvas_top);
			ImVec2 strip_b = ImVec2(canvas_right, canvas_bot);
			dl->PushClipRect(strip_a, strip_b, true);
			dl->AddRectFilled(strip_a, strip_b,
				aida::ui::with_alpha(t.panel_header, alpha * 0.45f), 4.f);

			int hover_idx = -1;
			ImVec2 mp = ImGui::GetMousePos();

			for (std::size_t i = 0; i < regions.size(); ++i) {
				const auto& r = regions[i];
				if (r.base + r.size <= view_va_low) continue;
				if (r.base >= view_va_high) break;

				const uint64_t clip_lo = (r.base < view_va_low) ? view_va_low : r.base;
				const uint64_t clip_hi = ((r.base + r.size) > view_va_high) ? view_va_high : (r.base + r.size);
				if (clip_hi <= clip_lo) continue;

				const double lo_frac = static_cast<double>(clip_lo - view_va_low) / visible_span;
				const double hi_frac = static_cast<double>(clip_hi - view_va_low) / visible_span;
				const float yl = canvas_top + static_cast<float>(lo_frac) * canvas_h;
				const float yh = canvas_top + static_cast<float>(hi_frac) * canvas_h;
				const float h = (yh - yl < 2.f) ? 2.f : (yh - yl);

				ImU32 col = region_color(r, alpha);
				dl->AddRectFilled(ImVec2(canvas_left + 2.f, yl),
					ImVec2(canvas_right - 2.f, yl + h), col, 2.f);

				if (mp.x >= canvas_left && mp.x <= canvas_right
					&& mp.y >= yl && mp.y <= yl + h)
				{
					hover_idx = static_cast<int>(i);
				}

				const bool is_selected = (selected_base == r.base && r.base != 0);
				if (is_selected) {
					dl->AddRect(ImVec2(canvas_left, yl - 1.f),
						ImVec2(canvas_right, yl + h + 1.f),
						aida::ui::with_alpha(t.accent_u32, alpha), 2.f, 0, 1.6f);
				}
			}

			for (const auto& th : threads) {
				if (th.rip == 0) continue;
				if (th.rip < view_va_low || th.rip >= view_va_high) continue;
				const double frac = static_cast<double>(th.rip - view_va_low) / visible_span;
				const float ty = canvas_top + static_cast<float>(frac) * canvas_h;
				const ImU32 mark_col = aida::ui::with_alpha(t.accent_glow, alpha);
				dl->AddLine(ImVec2(canvas_left, ty), ImVec2(canvas_right, ty), mark_col, 1.4f);
				dl->AddTriangleFilled(
					ImVec2(canvas_left - 6.f, ty - 4.f),
					ImVec2(canvas_left - 6.f, ty + 4.f),
					ImVec2(canvas_left,       ty),
					mark_col);
			}

			dl->PopClipRect();

			ImGui::SetCursorScreenPos(strip_a);
			ImGui::InvisibleButton("##bm_canvas_strip", ImVec2(canvas_w, canvas_h));
			const bool strip_hov = ImGui::IsItemHovered();
			if (strip_hov) {
				const ImGuiIO& io = ImGui::GetIO();
				if (io.MouseWheel != 0.f) {
					float new_zoom = vs.canvas_zoom * (1.f + io.MouseWheel * 0.18f);
					if (new_zoom < 1.f) new_zoom = 1.f;
					if (new_zoom > 4096.f) new_zoom = 4096.f;
					const double mouse_frac = static_cast<double>((mp.y - canvas_top) / canvas_h);
					const double mouse_va_off = view_low_off + visible_span * mouse_frac;
					const double new_visible_span = full_span / static_cast<double>(new_zoom);
					double new_low_off = mouse_va_off - new_visible_span * mouse_frac;
					if (new_low_off < 0.0) new_low_off = 0.0;
					if (new_low_off > full_span - new_visible_span) new_low_off = full_span - new_visible_span;
					if (new_low_off < 0.0) new_low_off = 0.0;
					vs.canvas_zoom = new_zoom;
					vs.canvas_target_zoom = new_zoom;
					vs.canvas_offset_norm = new_low_off / full_span;
					vs.canvas_target_offset_norm = vs.canvas_offset_norm;
					diag::log_tagged_fmt("binary_map",
						"canvas_zoom new_zoom=%.3f offset_norm=%.4f",
						static_cast<double>(new_zoom),
						vs.canvas_offset_norm);
				}
				if (ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
					if (!vs.canvas_dragging) {
						vs.canvas_dragging = true;
						vs.canvas_drag_anchor = mp.y;
						vs.canvas_drag_offset_start = vs.canvas_offset_norm;
					}
					const float dy = mp.y - vs.canvas_drag_anchor;
					const double dy_frac = static_cast<double>(-dy / canvas_h) / static_cast<double>(zoom);
					double new_off = vs.canvas_drag_offset_start + dy_frac;
					const double max_off = 1.0 - 1.0 / static_cast<double>(zoom);
					if (new_off < 0.0) new_off = 0.0;
					if (new_off > max_off) new_off = max_off;
					vs.canvas_offset_norm = new_off;
					vs.canvas_target_offset_norm = new_off;
				}
			}
			if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
				if (vs.canvas_dragging) {
					diag::log_tagged_fmt("binary_map",
						"canvas_drag_release offset_norm=%.4f zoom=%.3f",
						vs.canvas_offset_norm,
						static_cast<double>(vs.canvas_zoom));
					vs.canvas_dragging = false;
				}
			}

			if (valid_index(hover_idx, regions.size())) {
				const auto& hr = regions[static_cast<std::size_t>(hover_idx)];
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 8.f));
				ImGui::PushStyleColor(ImGuiCol_PopupBg,
					ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
				char tip[768];
				std::snprintf(tip, sizeof(tip),
					"%s\n0x%016llX - 0x%016llX\n%s | %s | %s\n%s",
					hr.module_name.empty() ? region_kind_label(hr).c_str() : hr.module_name.c_str(),
					static_cast<unsigned long long>(hr.base),
					static_cast<unsigned long long>(hr.base + hr.size),
					format_protect_word(hr.protect).c_str(),
					format_state_word(hr.state).c_str(),
					format_type_word(hr.type).c_str(),
					format_size_human(hr.size).c_str());
				ImGui::SetTooltip("%s", tip);
				ImGui::PopStyleColor();
				ImGui::PopStyleVar();

				if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !vs.canvas_dragging) {
					vs.live_selected_base.store(hr.base);
					diag::log_tagged_fmt("binary_map",
						"canvas_select base=0x%llX size=%llu kind=%s",
						static_cast<unsigned long long>(hr.base),
						static_cast<unsigned long long>(hr.size),
						region_kind_label(hr).c_str());
				}
				if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
					diag::log_tagged_fmt("binary_map",
						"canvas_double_click base=0x%llX -> jump_to_disasm",
						static_cast<unsigned long long>(hr.base));
					jump_to_address(vs, hr.base);
				}
			}

			vs.live_hover_index.store(hover_idx);

			ImFont* code_font = aida::ui::fonts::code();
			if (!code_font) code_font = ImGui::GetFont();
			const float tick_fs = aida::ui::fonts::size_or(code_font, 13.f) * 0.95f;
			const int tick_count = 6;
			for (int ti = 0; ti < tick_count; ++ti) {
				const float frac = static_cast<float>(ti) / static_cast<float>(tick_count - 1);
				const float ty = canvas_top + frac * canvas_h;
				dl->AddLine(ImVec2(canvas_right + 4.f, ty), ImVec2(canvas_right + 8.f, ty),
					aida::ui::with_alpha(t.text_dim, alpha), 1.f);
				const uint64_t va = view_va_low + static_cast<uint64_t>(visible_span * static_cast<double>(frac));
				char buf[24];
				std::snprintf(buf, sizeof(buf), "%012" PRIX64, va);
				dl->AddText(code_font, tick_fs,
					ImVec2(canvas_right + 12.f, ty - tick_fs * 0.5f),
					aida::ui::with_alpha(t.text_dim, alpha), buf);
			}

			char zoom_buf[48];
			std::snprintf(zoom_buf, sizeof(zoom_buf), "zoom %.1fx", static_cast<double>(zoom));
			ImFont* cap = aida::ui::fonts::caption();
			if (!cap) cap = ImGui::GetFont();
			const float cap_fs = aida::ui::fonts::size_or(cap, 13.f);
			dl->AddText(cap, cap_fs,
				ImVec2(a.x + 12.f, b.y - cap_fs - 6.f),
				aida::ui::with_alpha(t.text_dim, alpha), zoom_buf);

			char range_buf[64];
			std::snprintf(range_buf, sizeof(range_buf),
				"0x%llX - 0x%llX",
				static_cast<unsigned long long>(view_va_low),
				static_cast<unsigned long long>(view_va_high));
			dl->AddText(cap, cap_fs,
				ImVec2(a.x + 80.f, b.y - cap_fs - 6.f),
				aida::ui::with_alpha(t.text_dim, alpha), range_buf);
		}

		inline void render_legend(ImDrawList* dl, ImVec2 origin, float width, float alpha)
		{
			const auto& t = aida::ui::resolved();
			ImFont* cap = aida::ui::fonts::caption();
			if (!cap) cap = ImGui::GetFont();
			const float fs = aida::ui::fonts::size_or(cap, 13.f);

			struct entry_t { const char* lbl; ImU32 col; };
			entry_t entries[] = {
				{ "image",   aida::ui::with_alpha(t.success, alpha) },
				{ "mapped",  aida::ui::with_alpha(t.info, alpha) },
				{ "private", aida::ui::with_alpha(t.accent_dim, alpha) },
				{ "stack",   aida::ui::with_alpha(t.warning, alpha) },
				{ "heap",    aida::ui::with_alpha(t.info_soft, alpha) },
				{ "guard",   aida::ui::with_alpha(t.error, alpha) },
				{ "reserved", aida::ui::with_alpha(t.text_dim, alpha * 0.6f) }
			};
			float x = origin.x;
			for (auto& e : entries) {
				dl->AddRectFilled(ImVec2(x, origin.y + 4.f),
					ImVec2(x + 10.f, origin.y + 4.f + fs * 0.9f),
					e.col, 2.f);
				dl->AddText(cap, fs, ImVec2(x + 14.f, origin.y + 4.f),
					aida::ui::with_alpha(t.text_secondary, alpha), e.lbl);
				ImVec2 ts = cap->CalcTextSizeA(fs, FLT_MAX, 0.f, e.lbl);
				x += 14.f + ts.x + 14.f;
				if (x > origin.x + width) break;
			}
		}

	}

	inline void initialize(const std::shared_ptr<view_state_t>& state_handle)
	{
		if (!state_handle) return;
		view_state_t& s = *state_handle;
		std::lock_guard<std::mutex> g(s.mutex);
		if (s.initialized) return;
		s.opts.max_functions = 200;
		s.opts.max_globals = 60;
		s.opts.max_callees_per_function = 5;
		s.opts.max_chars = 16384;
		s.opts.include_imports = true;
		s.opts.include_exports = true;
		s.canvas_zoom = 1.f;
		s.canvas_target_zoom = 1.f;
		s.canvas_offset_norm = 0.0;
		s.canvas_target_offset_norm = 0.0;
		detail::ensure_subscriptions(state_handle);
		s.initialized = true;
		diag::log_tagged_fmt("binary_map",
			"view_initialize max_functions=%d max_globals=%d max_chars=%zu include_imp=%d include_exp=%d",
			s.opts.max_functions, s.opts.max_globals, s.opts.max_chars,
			s.opts.include_imports ? 1 : 0, s.opts.include_exports ? 1 : 0);
	}

	inline void initialize()
	{
		initialize(state_for(disasm_view::capture_selected_workspace()));
	}

	inline void shutdown()
	{
		std::vector<std::shared_ptr<view_state_t>> states;
		{
			std::lock_guard<std::mutex> lock(workspace_states_mutex());
			for (const auto& entry : workspace_states()) states.push_back(entry.second);
		}
		for (const auto& handle : states) {
			if (!handle) continue;
			view_state_t& s = *handle;
		std::lock_guard<std::mutex> g(s.mutex);
		if (s.subscription_binary.valid()) {
			aida::events::unsubscribe(s.subscription_binary);
			s.subscription_binary = aida::events::subscription_handle_t{};
		}
		if (s.subscription_proc_created.valid()) {
			aida::events::unsubscribe(s.subscription_proc_created);
			s.subscription_proc_created = aida::events::subscription_handle_t{};
		}
		if (s.subscription_proc_exited.valid()) {
			aida::events::unsubscribe(s.subscription_proc_exited);
			s.subscription_proc_exited = aida::events::subscription_handle_t{};
		}
		s.collapsed_groups.clear();
		s.expanded_imports.clear();
		std::atomic_store_explicit(&s.rendered_text,
			std::shared_ptr<const std::string>(std::make_shared<std::string>()),
			std::memory_order_release);
		std::atomic_store_explicit(&s.map,
			std::shared_ptr<const binary_map::map_t>(std::make_shared<binary_map::map_t>()),
			std::memory_order_release);
		s.has_map.store(false);
		std::atomic_store_explicit(&s.live,
			std::shared_ptr<const live_snapshot_t>(std::make_shared<live_snapshot_t>()),
			std::memory_order_release);
		s.initialized = false;
		}
		std::lock_guard<std::mutex> lock(workspace_states_mutex());
		workspace_states().clear();
	}

	inline std::string last_error()
	{
		auto selected = state_for(disasm_view::capture_selected_workspace());
		if (!selected) return "No selected workspace";
		std::lock_guard<std::mutex> g(selected->mutex);
		if (selected->last_error.empty()) return selected->live_last_error;
		if (selected->live_last_error.empty()) return selected->last_error;
		return selected->last_error + " | " + selected->live_last_error;
	}

	inline void refresh()
	{
		auto state = state_for(disasm_view::capture_selected_workspace());
		if (!state) return;
		state->refresh_requested.store(true);
		state->live_refresh_requested.store(true);
	}

	namespace detail {

		inline void render_pe_left_pane(ImDrawList* dl, view_state_t& s,
			float panel_x, float panel_y, float panel_w, float, float content_y,
			float a, const std::vector<binary_map::map_section_t>& sections_copy,
			const std::vector<binary_map::map_function_t>& functions_copy,
			uint64_t image_size, uint64_t selected_va_local, float full_h)
		{
			const auto& t = aida::ui::resolved();
			ImFont* sec_label = aida::ui::fonts::body_em();
			if (!sec_label) sec_label = ImGui::GetFont();
			const float sec_label_fs = aida::ui::fonts::size_or(sec_label, 16.f);
			dl->AddText(sec_label, sec_label_fs, ImVec2(panel_x, panel_y),
				aida::ui::with_alpha(t.text_secondary, a), "Section Layout");

			float strip_top = panel_y + 24.f;
			render_section_strip(dl, ImVec2(panel_x, strip_top), panel_w,
				sections_copy, image_size, a, s.row_anim_time, s);

			float heat_top = strip_top + 38.f + 44.f;
			{
				ImFont* hh_font = aida::ui::fonts::body_em();
				if (!hh_font) hh_font = ImGui::GetFont();
				const float hh_fs = aida::ui::fonts::size_or(hh_font, 16.f);
				dl->AddText(hh_font, hh_fs, ImVec2(panel_x, heat_top - hh_fs - 6.f),
					aida::ui::with_alpha(t.text_secondary, a), "Function Heatmap");
			}

			float heat_h = full_h - (heat_top - content_y) - 12.f;
			if (heat_h < 120.f) heat_h = 120.f;
			render_function_heatmap(dl, ImVec2(panel_x, heat_top),
				panel_w, heat_h, functions_copy, s, a, s.row_anim_time, selected_va_local);
		}

		inline void render_live_left_pane(ImDrawList* dl, view_state_t& s,
			float panel_x, float panel_y, float panel_w, float, float,
			float a, const std::vector<live_region_t>& regions_copy,
			const std::vector<driver_bridge::thread_info_t>& threads_copy,
			uint64_t selected_base, float full_h)
		{
			const auto& t = aida::ui::resolved();

			ImFont* hdr_font = aida::ui::fonts::body_em();
			if (!hdr_font) hdr_font = ImGui::GetFont();
			const float hdr_fs = aida::ui::fonts::size_or(hdr_font, 16.f);
			dl->AddText(hdr_font, hdr_fs, ImVec2(panel_x, panel_y),
				aida::ui::with_alpha(t.text_secondary, a), "Address Space Map");

			const float canvas_top = panel_y + 24.f;
			float canvas_h = full_h * 0.55f;
			if (canvas_h < 220.f) canvas_h = 220.f;
			if (canvas_h > full_h - 70.f) canvas_h = full_h - 70.f;
			render_address_space_canvas(dl, ImVec2(panel_x, canvas_top),
				panel_w, canvas_h, regions_copy, threads_copy, s, a, s.row_anim_time, selected_base);

			const float legend_y = canvas_top + canvas_h + 4.f;
			render_legend(dl, ImVec2(panel_x + 12.f, legend_y), panel_w - 24.f, a);

			const float stats_y = legend_y + 24.f;
			ImFont* cap = aida::ui::fonts::caption();
			if (!cap) cap = ImGui::GetFont();
			const float cap_fs = aida::ui::fonts::size_or(cap, 13.f);
			const float strong_fs = hdr_fs * 1.05f;

			uint64_t committed = 0, reserved = 0;
			uint32_t rwx = 0;
			uint32_t pid = 0;
			std::string proc;
			std::size_t region_n = 0, module_n = 0, thread_n = 0;
			uint64_t enum_ms = 0;
			const auto live = std::atomic_load_explicit(&s.live, std::memory_order_acquire);
			if (live) {
				committed = live->total_committed;
				reserved  = live->total_reserved;
				rwx       = live->rwx_count;
				pid       = live->pid;
				proc      = live->process_name;
				region_n  = live->regions.size();
				module_n  = live->modules.size();
				thread_n  = live->threads.size();
				enum_ms   = live->enum_elapsed_ms;
			}

			struct stat_pod_t { const char* label; std::string value; ImU32 color; };
			char b_regions[24], b_committed[40], b_reserved[40], b_rwx[24], b_modules[24], b_threads[24];
			std::snprintf(b_regions, sizeof(b_regions), "%zu", region_n);
			std::snprintf(b_modules, sizeof(b_modules), "%zu", module_n);
			std::snprintf(b_threads, sizeof(b_threads), "%zu", thread_n);
			std::snprintf(b_rwx, sizeof(b_rwx), "%u", static_cast<unsigned>(rwx));
			std::string committed_s = format_size_human(committed);
			std::string reserved_s = format_size_human(reserved);
			std::snprintf(b_committed, sizeof(b_committed), "%s", committed_s.c_str());
			std::snprintf(b_reserved, sizeof(b_reserved), "%s", reserved_s.c_str());

			stat_pod_t pods[] = {
				{ "REGIONS",   b_regions,   t.accent_u32 },
				{ "MODULES",   b_modules,   t.info },
				{ "THREADS",   b_threads,   t.info },
				{ "COMMITTED", b_committed, t.success },
				{ "RESERVED",  b_reserved,  t.text_dim },
				{ "RWX",       b_rwx,       rwx > 0 ? t.error : t.success }
			};

			const int pod_count = static_cast<int>(sizeof(pods) / sizeof(pods[0]));
			const float pod_gap = 8.f;
			const float pod_w = (panel_w - 24.f - pod_gap * (pod_count - 1)) / static_cast<float>(pod_count);
			const float pod_h = 56.f;
			float px = panel_x + 12.f;
			for (int i = 0; i < pod_count; ++i) {
				ImVec2 pa(px, stats_y);
				ImVec2 pb(px + pod_w, stats_y + pod_h);
				dl->AddRectFilled(pa, pb,
					aida::ui::with_alpha(t.panel_bg, a * 0.85f), 8.f);
				dl->AddRectFilled(pa, pb,
					aida::ui::with_alpha(t.glass_tint, a * 0.55f), 8.f);
				dl->AddRect(pa, pb,
					aida::ui::with_alpha(t.border_subtle, a), 8.f, 0, 1.f);
				dl->AddRectFilled(pa, ImVec2(pa.x + 3.f, pa.y + pod_h),
					aida::ui::with_alpha(pods[i].color, a * 0.85f), 1.f);
				dl->AddText(cap, cap_fs * 0.95f,
					ImVec2(pa.x + 10.f, pa.y + 6.f),
					aida::ui::with_alpha(t.text_dim, a), pods[i].label);
				dl->AddText(hdr_font, strong_fs,
					ImVec2(pa.x + 10.f, pa.y + 22.f),
					aida::ui::with_alpha(t.text_primary, a), pods[i].value.c_str());
				px += pod_w + pod_gap;
			}

			const float meta_y = stats_y + pod_h + 8.f;
			char meta_buf[128];
			if (pid != 0) {
				std::snprintf(meta_buf, sizeof(meta_buf),
					"PID %u   %s   enum %llu ms",
					static_cast<unsigned>(pid),
					proc.c_str(),
					static_cast<unsigned long long>(enum_ms));
			} else {
				std::snprintf(meta_buf, sizeof(meta_buf), "No attached process");
			}
			dl->AddText(cap, cap_fs, ImVec2(panel_x + 12.f, meta_y),
				aida::ui::with_alpha(t.text_dim, a), meta_buf);
		}

	}

	inline void render(int, int, float w, float h,
		float anim, float, float, float,
		const disasm_view::workspace_context_t& context)
	{
		auto state_handle = state_for(context);
		if (!state_handle) {
			ImGui::BeginChild("##binary_map_view", ImVec2(w, h), false,
				ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
				ImGuiWindowFlags_NoBackground);
			ImVec2 position = ImGui::GetWindowPos();
			aida::ui::no_target_overlay::render(position, ImVec2(w, h),
				"No binary or process",
				"Open a file or attach to a process to inspect its binary map.", anim,
				aida::ui::empty_state::glyph_t::binary_file);
			ImGui::EndChild();
			return;
		}
		view_state_t& s = *state_handle;
		if (!s.initialized) initialize(state_handle);

		const active_mode_t resolved_mode = detail::resolve_active_mode(s, s.mode_pref);
		const int prev_mode = s.active_mode_atomic.exchange(static_cast<int>(resolved_mode));
		if (prev_mode != static_cast<int>(resolved_mode)) {
			diag::log_tagged_fmt("binary_map",
				"mode_switch from=%d to=%d pref=%d live_available=%d static_available=%d",
				prev_mode,
				static_cast<int>(resolved_mode),
				static_cast<int>(s.mode_pref),
				detail::live_available(s) ? 1 : 0,
				detail::static_available(s) ? 1 : 0);
		}

		const bool want_static = (resolved_mode == active_mode_t::pe_static)
			|| (resolved_mode == active_mode_t::merged);
		const bool want_live = (resolved_mode == active_mode_t::live_process)
			|| (resolved_mode == active_mode_t::merged);

		if (s.refresh_requested.exchange(false) && want_static) {
			detail::perform_refresh(state_handle);
		}
		if (s.live_refresh_requested.exchange(false) && want_live) {
			detail::perform_live_refresh(state_handle);
		}

		const auto& t = aida::ui::resolved();
		const float a = anim;
		const float dt = aida::ui::clock::dt();
		s.row_anim_time += dt;

		ImGui::BeginChild("##binary_map_view", ImVec2(w, h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

		const float kBmMinPanelW = 720.f;
		if (w < kBmMinPanelW) {
			static bool s_logged_bm_narrow = false;
			if (!s_logged_bm_narrow) {
				s_logged_bm_narrow = true;
				::diag::log_tagged_fmt("responsive",
					"binary_map_view clamp_overlay width=%.0f min=%.0f",
					w, kBmMinPanelW);
			}
			ImVec2 wpc = ImGui::GetWindowPos();
			aida::ui::responsive::draw_clamp_overlay(
				wpc, ImVec2(w, h),
				"Widen the panel to view the Binary Map");
			ImGui::EndChild();
			return;
		}

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		const float ox = wp.x;
		const float oy = wp.y;

		dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
			aida::ui::with_alpha(t.bg_base, a));

		const float toolbar_h = 92.f;
		const float pad = 12.f;

		ImU32 bar_top = aida::ui::with_alpha(t.panel_header, a * 0.85f);
		ImU32 bar_bot = aida::ui::with_alpha(t.panel_bg, a * 0.85f);
		dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + w, oy + toolbar_h),
			bar_top, bar_top, bar_bot, bar_bot);
		dl->AddLine(ImVec2(ox, oy + toolbar_h - 1.f), ImVec2(ox + w, oy + toolbar_h - 1.f),
			aida::ui::with_alpha(t.border_subtle, a));

		std::size_t live_region_count = 0;
		uint32_t live_pid_now = 0;
		std::string live_proc_name;
		std::string last_error_copy;
		std::string live_last_error_copy;
		const auto map_snapshot = std::atomic_load_explicit(&s.map, std::memory_order_acquire);
		const auto live_snapshot = std::atomic_load_explicit(&s.live, std::memory_order_acquire);
		static const binary_map::map_t empty_map;
		static const std::vector<live_region_t> empty_regions;
		static const std::vector<driver_bridge::thread_info_t> empty_threads;
		static const std::vector<driver_bridge::module_info_t> empty_modules;
		const auto& map = map_snapshot ? *map_snapshot : empty_map;
		const auto& sections_copy = map.sections;
		const auto& functions_copy = map.functions;
		const auto& globals_copy = map.globals;
		const auto& imports_copy = map.imports;
		const auto& exports_copy = map.exports;
		const auto& regions_copy = live_snapshot ? live_snapshot->regions : empty_regions;
		const auto& threads_copy = live_snapshot ? live_snapshot->threads : empty_threads;
		const auto& modules_copy = live_snapshot ? live_snapshot->modules : empty_modules;
		const int total_funcs = detail::count_as_int(map.functions.size());
		const int total_globs = detail::count_as_int(map.globals.size());
		const int total_imports = detail::count_as_int(map.imports.size());
		const int total_exports = detail::count_as_int(map.exports.size());
		const int total_sections = detail::count_as_int(map.sections.size());
		const auto& module_name = map.module_name;
		const auto& module_format = map.format;
		const uint64_t image_base = map.image_base;
		const uint64_t image_size = map.image_size;

		uint64_t selected_va_local = s.selected_va.load();
		uint64_t live_selected_base = s.live_selected_base.load();

		{
			std::unique_lock<std::mutex> lock(s.mutex, std::try_to_lock);
			if (lock.owns_lock()) {
				last_error_copy = s.last_error;
				live_last_error_copy = s.live_last_error;
			}
		}
		if (live_snapshot) {
			live_region_count = live_snapshot->regions.size();
			live_pid_now = live_snapshot->pid;
			live_proc_name = live_snapshot->process_name;
		}

		ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + 6.f));
		ImFont* head = aida::ui::fonts::body_strong();
		if (!head) head = ImGui::GetFont();
		const float head_fs = aida::ui::fonts::size_or(head, 16.f);
		dl->AddText(head, head_fs, ImVec2(ox + pad, oy + 6.f),
			aida::ui::with_alpha(t.text_primary, a), "Binary Map");

		const char* mode_text =
			(resolved_mode == active_mode_t::merged)        ? "merged: static PE + live process" :
			(resolved_mode == active_mode_t::live_process)  ? "live process" :
			(resolved_mode == active_mode_t::pe_static)     ? "static PE" :
			                                                  "no target";
		std::string subtitle;
		if (resolved_mode == active_mode_t::live_process || resolved_mode == active_mode_t::merged) {
			char buf[256];
			if (live_pid_now != 0) {
				std::snprintf(buf, sizeof(buf), "%s  -  PID %u  %s  regions %zu",
					mode_text, static_cast<unsigned>(live_pid_now),
					live_proc_name.c_str(), live_region_count);
			} else {
				std::snprintf(buf, sizeof(buf), "%s  -  no active process", mode_text);
			}
			subtitle = buf;
		} else if (resolved_mode == active_mode_t::pe_static) {
			char buf[256];
			std::snprintf(buf, sizeof(buf), "%s  -  %s  %s  base 0x%llX  %s",
				mode_text,
				module_name.empty() ? "(generating)" : module_name.c_str(),
				module_format.empty() ? "" : module_format.c_str(),
				static_cast<unsigned long long>(image_base),
				detail::format_size_human(image_size).c_str());
			subtitle = buf;
		} else {
			subtitle = "no target";
		}
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		const float code_fs = aida::ui::fonts::size_or(code_font, 14.f);
		dl->AddText(code_font, code_fs, ImVec2(ox + pad + 130.f, oy + 12.f),
			aida::ui::with_alpha(t.text_dim, a), subtitle.c_str());

		float chip_y = oy + 34.f;
		float chip_x = ox + pad;
		ImGui::SetCursorScreenPos(ImVec2(chip_x, chip_y));

		auto render_count_chip = [&](const char* lbl, const char* val, ImU32 col) {
			ImFont* f = aida::ui::fonts::body();
			if (!f) f = ImGui::GetFont();
			float fs = aida::ui::fonts::size_or(f, 16.f);
			float lblw = f->CalcTextSizeA(fs, FLT_MAX, 0.f, lbl).x;
			float valw = f->CalcTextSizeA(fs, FLT_MAX, 0.f, val).x;
			float pad_x = 10.f;
			float w_chip = lblw + valw + pad_x * 2.f + 8.f;
			float h_chip = 24.f;
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 ca = cp;
			ImVec2 cb = ImVec2(cp.x + w_chip, cp.y + h_chip);
			dl->AddRectFilled(ca, cb, aida::ui::with_alpha(col, a * 0.18f), h_chip * 0.5f);
			dl->AddRect(ca, cb, aida::ui::with_alpha(col, a * 0.55f), h_chip * 0.5f, 0, 1.f);
			dl->AddText(f, fs, ImVec2(ca.x + pad_x, ca.y + (h_chip - fs) * 0.5f),
				aida::ui::with_alpha(t.text_secondary, a), lbl);
			dl->AddText(f, fs, ImVec2(ca.x + pad_x + lblw + 8.f, ca.y + (h_chip - fs) * 0.5f),
				aida::ui::with_alpha(col, a), val);
			ImGui::Dummy(ImVec2(w_chip, h_chip));
			ImGui::SameLine(0.f, 8.f);
		};

		char buf_funcs[24], buf_globs[24], buf_imp[24], buf_exp[24], buf_sec[24], buf_regions[24];
		std::snprintf(buf_funcs,   sizeof(buf_funcs),   "%d", total_funcs);
		std::snprintf(buf_globs,   sizeof(buf_globs),   "%d", total_globs);
		std::snprintf(buf_imp,     sizeof(buf_imp),     "%d", total_imports);
		std::snprintf(buf_exp,     sizeof(buf_exp),     "%d", total_exports);
		std::snprintf(buf_sec,     sizeof(buf_sec),     "%d", total_sections);
		std::snprintf(buf_regions, sizeof(buf_regions), "%zu", live_region_count);

		if (want_static) {
			render_count_chip("Sections", buf_sec,   t.info);
			render_count_chip("Functions", buf_funcs, t.accent_u32);
			render_count_chip("Globals",   buf_globs, t.success);
			render_count_chip("Imports",   buf_imp,   t.warning);
			render_count_chip("Exports",   buf_exp,   t.accent_hover);
		}
		if (want_live) {
			render_count_chip("Regions", buf_regions, t.accent_dim);
		}

		float seg_x = ox + pad;
		float seg_y = oy + 60.f;
		float seg_h = 26.f;
		float seg_label_w = 70.f;
		ImFont* cap_font = aida::ui::fonts::caption();
		if (!cap_font) cap_font = ImGui::GetFont();
		const float cap_fs = aida::ui::fonts::size_or(cap_font, 13.f);
		dl->AddText(cap_font, cap_fs, ImVec2(seg_x, seg_y + (seg_h - cap_fs) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), "Mode:");

		struct mode_btn_t { const char* label; display_mode_t value; };
		const mode_btn_t modes_arr[] = {
			{ "Auto",    display_mode_t::auto_detect },
			{ "Static",  display_mode_t::static_only },
			{ "Live",    display_mode_t::live_only }
		};
		const int mode_count = static_cast<int>(sizeof(modes_arr) / sizeof(modes_arr[0]));
		float mode_btn_w = 78.f;
		float mode_btn_x = seg_x + seg_label_w;
		for (int i = 0; i < mode_count; ++i) {
			ImVec2 ma(mode_btn_x, seg_y);
			ImVec2 mb(mode_btn_x + mode_btn_w, seg_y + seg_h);
			const bool sel = (s.mode_pref == modes_arr[i].value);
			ImU32 fill = sel
				? aida::ui::with_alpha(t.accent_u32, a * 0.35f)
				: aida::ui::with_alpha(t.panel_bg, a * 0.65f);
			ImU32 border = sel
				? aida::ui::with_alpha(t.accent_u32, a)
				: aida::ui::with_alpha(t.border_subtle, a);
			dl->AddRectFilled(ma, mb, fill, 5.f);
			dl->AddRect(ma, mb, border, 5.f, 0, sel ? 1.4f : 1.f);
			ImFont* btn_font = aida::ui::fonts::body();
			if (!btn_font) btn_font = ImGui::GetFont();
			const float btn_fs = aida::ui::fonts::size_or(btn_font, 16.f);
			ImVec2 ts = btn_font->CalcTextSizeA(btn_fs, FLT_MAX, 0.f, modes_arr[i].label);
			ImU32 txt_col = sel
				? aida::ui::with_alpha(t.text_primary, a)
				: aida::ui::with_alpha(t.text_secondary, a);
			dl->AddText(btn_font, btn_fs,
				ImVec2(ma.x + (mode_btn_w - ts.x) * 0.5f, ma.y + (seg_h - btn_fs) * 0.5f),
				txt_col, modes_arr[i].label);

			ImGui::SetCursorScreenPos(ma);
			ImGui::PushID(static_cast<int>(0x90000000u | static_cast<unsigned>(i)));
			ImGui::InvisibleButton("##bm_mode_btn", ImVec2(mode_btn_w, seg_h));
			if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
				const display_mode_t prev = s.mode_pref;
				s.mode_pref = modes_arr[i].value;
				diag::log_tagged_fmt("binary_map",
					"mode_toggle prev=%d new=%d",
					static_cast<int>(prev), static_cast<int>(s.mode_pref));
				s.refresh_requested.store(true);
				s.live_refresh_requested.store(true);
			}
			ImGui::PopID();
			mode_btn_x += mode_btn_w + 4.f;
		}

		const float right_anchor = ox + w - pad;
		const float btn_y = oy + 60.f;
		const float btn_w = 102.f;
		const float btn_h = 30.f;
		const float btn_gap = 8.f;
		float bx = right_anchor;

		bx -= btn_w;
		ImGui::SetCursorScreenPos(ImVec2(bx, btn_y));
		bool refreshing_now = s.refreshing.load() || s.live_refreshing.load();
		if (aida::ui::button(refreshing_now ? "Refreshing" : "Refresh",
			aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm,
			ImVec2(btn_w, btn_h),
			refreshing_now, nullptr, refreshing_now)) {
			if (!refreshing_now) {
				diag::log_tagged_fmt("binary_map",
					"toolbar refresh_clicked want_static=%d want_live=%d mode_pref=%d",
					want_static ? 1 : 0, want_live ? 1 : 0,
					static_cast<int>(s.mode_pref));
				if (want_static) s.refresh_requested.store(true);
				if (want_live)   s.live_refresh_requested.store(true);
			}
		}

		bx -= (btn_w + btn_gap);
		ImGui::SetCursorScreenPos(ImVec2(bx, btn_y));
		if (aida::ui::button("To chat", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(btn_w, btn_h))) {
			const auto rendered = std::atomic_load_explicit(&s.rendered_text,
				std::memory_order_acquire);
			std::string payload = rendered ? *rendered : std::string{};
			if (resolved_mode == active_mode_t::live_process) {
				std::string live_payload = "Live memory map:\n";
				uint64_t committed_total = 0;
				uint32_t rwx_total = 0;
				for (const auto& r : regions_copy) {
					if (r.is_committed) committed_total += r.size;
					const bool exec_b  = (r.protect & 0xF0) != 0;
					const uint32_t low_b = r.protect & 0xFF;
					const bool write_b = (low_b == 0x04) || (low_b == 0x08) || (low_b == 0x40) || (low_b == 0x80);
					if (exec_b && write_b) ++rwx_total;
				}
				const std::string committed_str = detail::format_size_human(committed_total);
				char hbuf[200];
				std::snprintf(hbuf, sizeof(hbuf),
					"PID %u %s  regions=%zu  committed=%s  RWX=%u\n",
					static_cast<unsigned>(live_pid_now),
					live_proc_name.c_str(),
					regions_copy.size(),
					committed_str.c_str(),
					static_cast<unsigned>(rwx_total));
				live_payload += hbuf;
				for (std::size_t i = 0; i < regions_copy.size() && i < 64; ++i) {
					live_payload += detail::make_region_chat_payload(regions_copy[i]);
				}
				payload = live_payload;
			}
			diag::log_tagged_fmt("binary_map",
				"toolbar to_chat bytes=%zu module='%s'",
				payload.size(), module_name.c_str());
			if (payload.empty()) {
				toast_notification::push("Binary map is empty; refresh first",
					toast_notification::toast_type_t::warning, 3.0f);
			} else {
				detail::inject_to_chat(payload);
			}
		}

		bx -= (btn_w + btn_gap);
		ImGui::SetCursorScreenPos(ImVec2(bx, btn_y));
		ImGui::PushID("bm_toolbar_copy");
		if (aida::ui::button("Copy", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(btn_w, btn_h))) {
			const auto payload = std::atomic_load_explicit(&s.rendered_text,
				std::memory_order_acquire);
			diag::log_tagged_fmt("binary_map",
				"toolbar copy bytes=%zu module='%s'",
				payload ? payload->size() : 0, module_name.c_str());
			ImGui::SetClipboardText(payload ? payload->c_str() : "");
			toast_notification::push("Binary map copied to clipboard",
				toast_notification::toast_type_t::info, 3.0f);
		}
		ImGui::PopID();

		bx -= (btn_w + btn_gap);
		ImGui::SetCursorScreenPos(ImVec2(bx, btn_y));
		ImGui::PushID("bm_export_live");
		const bool export_pending = s.export_pending.load(std::memory_order_acquire);
		if (aida::ui::button(export_pending ? "Exporting" : "Export",
			aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm,
			ImVec2(btn_w, btn_h), export_pending, nullptr, export_pending)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::string export_receipt;
			if (resolved_mode == active_mode_t::live_process || resolved_mode == active_mode_t::merged) {
				export_receipt = live_snapshot
					? detail::export_live_snapshot_json(*live_snapshot) : std::string{};
			} else {
				const auto rendered = std::atomic_load_explicit(&s.rendered_text,
					std::memory_order_acquire);
				if (rendered) export_receipt = *rendered;
			}
			ImGui::SetClipboardText(export_receipt.c_str());
			toast_notification::push("Export receipt copied",
				toast_notification::toast_type_t::info, 3.0f);
#else
			if (resolved_mode == active_mode_t::live_process || resolved_mode == active_mode_t::merged) {
				char path_buf[MAX_PATH] = {};
				std::snprintf(path_buf, sizeof(path_buf), "memory_map_pid%u.json",
					static_cast<unsigned>(live_snapshot ? live_snapshot->pid : 0));
				static const char k_filter[] =
					"JSON (*.json)\0*.json\0All files (*.*)\0*.*\0\0";
				if (win32_dialog::show_save_file_dialog(g_hwnd,
					"Export Memory Map",
					k_filter,
					"json",
					path_buf, sizeof(path_buf),
					"binary_map_view::export_live"))
				{
					if (!detail::queue_snapshot_export(state_handle, path_buf, "Export live memory map",
						live_snapshot, {}))
						toast_notification::push("The memory-map export could not be queued; see Task Center",
							toast_notification::toast_type_t::error, 3.0f);
				}
			} else {
				const auto payload = std::atomic_load_explicit(&s.rendered_text,
					std::memory_order_acquire);
				char path_buf[MAX_PATH] = "binary_map.txt";
				static const char k_filter[] =
					"Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0";
				if (win32_dialog::show_save_file_dialog(g_hwnd,
					"Export Binary Map",
					k_filter,
					"txt",
					path_buf, sizeof(path_buf),
					"binary_map_view::export_pe"))
				{
					if (!detail::queue_snapshot_export(state_handle, path_buf, "Export static Binary Map",
						{}, payload))
						toast_notification::push("The Binary Map export could not be queued; see Task Center",
							toast_notification::toast_type_t::error, 3.0f);
				}
			}
#endif
		}
		if (export_pending && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
			ImGui::SetTooltip("A Binary Map export is already running");
		ImGui::PopID();

		const float content_y = oy + toolbar_h;
		const float content_h = h - toolbar_h;

		float left_w = std::max(360.f, w * s.left_split);
		float min_left = std::max(360.f, w * 0.35f);
		if (left_w < min_left) left_w = min_left;
		if (left_w > w - 320.f) left_w = w - 320.f;
		const float right_w = w - left_w - 1.f;
		const float split_x = ox + left_w;

		float splitter_target = 0.f;
		ImGui::SetCursorScreenPos(ImVec2(split_x - 4.f, content_y));
		ImGui::InvisibleButton("##bm_splitter", ImVec2(8.f, content_h));
		bool splitter_hov = ImGui::IsItemHovered();
		bool splitter_active = ImGui::IsItemActive();
		bool splitter_released = ImGui::IsItemDeactivated();
		if (splitter_hov) {
			ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
			splitter_target = 1.f;
		}
		if (splitter_active && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
			float dx = ImGui::GetIO().MouseDelta.x;
			float new_left = left_w + dx;
			if (new_left >= min_left && new_left <= w - 320.f)
				s.left_split = new_left / std::max(1.f, w);
			splitter_target = 1.f;
		}
		if (splitter_released) {
			diag::log_tagged_fmt("binary_map",
				"splitter_release left_split=%.3f left_w=%.1f total_w=%.1f",
				s.left_split, left_w, w);
		}
		s.splitter_hover_v = aida::motion::smooth_lerp(s.splitter_hover_v, splitter_target, 16.f, dt);

		ImU32 sep_base = aida::ui::with_alpha(t.border_strong, a * 0.85f);
		ImU32 sep_hov  = aida::ui::with_alpha(t.accent_u32, a * 0.95f);
		ImU32 sep_col  = aida::ui::mix(sep_base, sep_hov, s.splitter_hover_v);
		dl->AddLine(ImVec2(split_x, content_y + 2.f), ImVec2(split_x, content_y + content_h - 2.f),
			sep_col, 1.2f + s.splitter_hover_v * 1.4f);

		const float left_pad = 12.f;
		float panel_x = ox + left_pad;
		float panel_w = left_w - left_pad * 2.f;
		float panel_y = content_y + 8.f;
		float left_full_h = content_h - 16.f;

		if (resolved_mode == active_mode_t::pe_static) {
			detail::render_pe_left_pane(dl, s, panel_x, panel_y, panel_w, content_h, content_y, a,
				sections_copy, functions_copy, image_size, selected_va_local, left_full_h);
		} else if (resolved_mode == active_mode_t::live_process) {
			detail::render_live_left_pane(dl, s, panel_x, panel_y, panel_w, content_h, content_y, a,
				regions_copy, threads_copy, live_selected_base, left_full_h);
		} else if (resolved_mode == active_mode_t::merged) {
			float half = (left_full_h - 12.f) * 0.55f;
			detail::render_live_left_pane(dl, s, panel_x, panel_y, panel_w, content_h, content_y, a,
				regions_copy, threads_copy, live_selected_base, half);
			float pe_y = panel_y + half + 12.f;
			detail::render_pe_left_pane(dl, s, panel_x, pe_y, panel_w, content_h, content_y, a,
				sections_copy, functions_copy, image_size, selected_va_local,
				left_full_h - half - 12.f);
		} else {
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			const float body_fs = aida::ui::fonts::size_or(body, 16.f);
			dl->AddText(body, body_fs,
				ImVec2(panel_x + panel_w * 0.5f - 80.f, panel_y + content_h * 0.4f),
				aida::ui::with_alpha(t.text_dim, a),
				"No target. Use the toolbar to refresh.");
		}

		const float right_x = ox + left_w + 1.f;
		const float right_pad = 12.f;
		ImVec2 r_a = ImVec2(right_x + right_pad, content_y + 8.f);
		ImVec2 r_b = ImVec2(right_x + right_w - right_pad, content_y + content_h - 12.f);

		aida::ui::blur::layer_request_t req;
		req.pos = r_a;
		req.size = ImVec2(r_b.x - r_a.x, r_b.y - r_a.y);
		req.radius = 12.f;
		req.strength = 0.55f;
		req.alpha = a;
		aida::ui::blur::schedule(req);
		aida::ui::blur::render_glass_fill(dl, r_a, r_b, 12.f, a);
		aida::ui::blur::render_glass_border(dl, r_a, r_b, 12.f, a, 1.f);

		float panel_inner_top = r_a.y + 10.f;
		float panel_inner_left = r_a.x + 12.f;
		float panel_inner_w = r_b.x - r_a.x - 24.f;

		ImFont* head_em = aida::ui::fonts::body_em();
		if (!head_em) head_em = ImGui::GetFont();
		const float head_em_fs = aida::ui::fonts::size_or(head_em, 16.f);

		const char* right_header = (resolved_mode == active_mode_t::live_process)
			? "Live Regions"
			: ((resolved_mode == active_mode_t::merged) ? "Layout & Live Regions" : "Layout & Symbols");
		dl->AddText(head_em, head_em_fs, ImVec2(panel_inner_left, panel_inner_top),
			aida::ui::with_alpha(t.text_secondary, a), right_header);

		ImGui::SetCursorScreenPos(ImVec2(r_b.x - 100.f, panel_inner_top - 6.f));
		ImGui::PushID("bm_preview_copy");
		if (aida::ui::button("Copy", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(96.f, 30.f))) {
			const auto payload = std::atomic_load_explicit(&s.rendered_text,
				std::memory_order_acquire);
			diag::log_tagged_fmt("binary_map",
				"preview copy bytes=%zu module='%s'",
				payload ? payload->size() : 0, module_name.c_str());
			ImGui::SetClipboardText(payload ? payload->c_str() : "");
			toast_notification::push("Preview copied to clipboard",
				toast_notification::toast_type_t::info, 3.0f);
		}
		ImGui::PopID();

		float filter_y = panel_inner_top + head_em_fs + 14.f;
		ImGui::SetCursorScreenPos(ImVec2(panel_inner_left, filter_y));
		if (aida::ui::input_text("##bm_filter", s.filter_buf, sizeof(s.filter_buf),
			"Filter sections, regions, modules, imports...", false,
			ImVec2(panel_inner_w, 32.f))) {
			s.filter_lower = detail::to_lower_copy(std::string(s.filter_buf));
		}

		float section_y = filter_y + 42.f;
		float section_inner_h = (r_b.y - section_y) - 12.f;
		ImGui::SetCursorScreenPos(ImVec2(panel_inner_left, section_y));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0,0,0,0));
		ImGui::PushFont(code_font);

		ImGui::BeginChild("##bm_preview_pane", ImVec2(panel_inner_w, section_inner_h), false,
			ImGuiWindowFlags_NoBackground);

		const std::string& filter_lower = s.filter_lower;

		auto draw_section_header = [&](const char* title, int count_value,
		                                const std::string& key) -> bool {
			char hbuf[160];
			std::snprintf(hbuf, sizeof(hbuf), "%s  (%d)", title, count_value);
			const bool collapsed = detail::group_is_collapsed(s, key);
			ImVec2 cp = ImGui::GetCursorScreenPos();
			float row_w = ImGui::GetContentRegionAvail().x;
			float row_h = 30.f;
			bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
			ImU32 fill = hov
				? aida::ui::with_alpha(t.hover_wash, a)
				: aida::ui::with_alpha(t.panel_header, a * 0.55f);
			dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), fill, 6.f);
			ImU32 arrow_col = aida::ui::with_alpha(t.accent_u32, a);
			float arrow_x = cp.x + 12.f;
			float arrow_y = cp.y + row_h * 0.5f;
			ImVec2 a1, a2, a3;
			if (collapsed) {
				a1 = ImVec2(arrow_x, arrow_y - 5.f);
				a2 = ImVec2(arrow_x + 7.f, arrow_y);
				a3 = ImVec2(arrow_x, arrow_y + 5.f);
			} else {
				a1 = ImVec2(arrow_x - 1.f, arrow_y - 2.f);
				a2 = ImVec2(arrow_x + 8.f, arrow_y - 2.f);
				a3 = ImVec2(arrow_x + 3.f, arrow_y + 5.f);
			}
			dl->AddTriangleFilled(a1, a2, a3, arrow_col);

			ImFont* f_strong = aida::ui::fonts::body_em();
			if (!f_strong) f_strong = ImGui::GetFont();
			const float gh_fs = aida::ui::fonts::size_or(f_strong, 16.f);
			dl->AddText(f_strong, gh_fs, ImVec2(cp.x + 30.f, cp.y + (row_h - gh_fs) * 0.5f),
				aida::ui::with_alpha(t.text_primary, a), hbuf);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				detail::toggle_group(s, key);
				diag::log_tagged_fmt("binary_map",
					"group_toggle key='%s' now_collapsed=%d",
					key.c_str(), (!collapsed) ? 1 : 0);
			}
			ImGui::Dummy(ImVec2(row_w, row_h + 6.f));
			return !collapsed;
		};

		auto render_region_row = [&](const live_region_t& r, int idx) {
			ImVec2 cp = ImGui::GetCursorScreenPos();
			float row_w = ImGui::GetContentRegionAvail().x;
			float row_h = 32.f;
			bool sel = (live_selected_base == r.base && r.base != 0);
			ImGui::PushID(static_cast<int>(0x80000000u | static_cast<unsigned>(idx)));
			ImGui::InvisibleButton("##bm_reg_row", ImVec2(row_w, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
			bool double_clicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
				&& ImGui::IsItemHovered();
			if (sel) {
				dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
					aida::ui::with_alpha(t.selection, a), 5.f);
				dl->AddRectFilled(cp, ImVec2(cp.x + 3.f, cp.y + row_h),
					aida::ui::with_alpha(t.accent_u32, a), 1.f);
			} else if (hov) {
				dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
					aida::ui::with_alpha(t.hover_wash, a), 4.f);
			}
			ImU32 dot_col = detail::region_color(r, a);
			dl->AddRectFilled(ImVec2(cp.x + 8.f, cp.y + 7.f),
				ImVec2(cp.x + 16.f, cp.y + row_h - 7.f),
				dot_col, 2.f);

			char addr_buf[24];
			std::snprintf(addr_buf, sizeof(addr_buf), "0x%012llX",
				static_cast<unsigned long long>(r.base));
			ImFont* code_f = aida::ui::fonts::code();
			if (!code_f) code_f = ImGui::GetFont();
			const float code_row_fs = aida::ui::fonts::size_or(code_f, 14.f);
			ImFont* body_f = aida::ui::fonts::body();
			if (!body_f) body_f = ImGui::GetFont();
			const float body_row_fs = aida::ui::fonts::size_or(body_f, 16.f);

			const float addr_y = cp.y + (row_h - code_row_fs) * 0.5f;
			dl->AddText(code_f, code_row_fs,
				ImVec2(cp.x + 24.f, addr_y),
				aida::ui::with_alpha(t.text_address, a), addr_buf);

			std::string sz_s = detail::format_size_human(r.size);
			dl->AddText(code_f, code_row_fs,
				ImVec2(cp.x + 24.f + 140.f, addr_y),
				aida::ui::with_alpha(t.text_secondary, a), sz_s.c_str());

			std::string lbl = detail::region_kind_label(r);
			ImU32 lbl_col = detail::region_color(r, a);
			ImFont* cap_f = aida::ui::fonts::caption();
			if (!cap_f) cap_f = ImGui::GetFont();
			const float cap_row_fs = aida::ui::fonts::size_or(cap_f, 13.f);
			ImVec2 lbl_sz = cap_f->CalcTextSizeA(cap_row_fs, FLT_MAX, 0.f, lbl.c_str());
			const float chip_h = cap_row_fs + 6.f;
			const float chip_y = cp.y + (row_h - chip_h) * 0.5f;
			const float chip_x_start = cp.x + 24.f + 220.f;
			dl->AddRectFilled(ImVec2(chip_x_start, chip_y),
				ImVec2(chip_x_start + lbl_sz.x + 14.f, chip_y + chip_h),
				aida::ui::with_alpha(lbl_col, a * 0.22f), chip_h * 0.5f);
			dl->AddText(cap_f, cap_row_fs,
				ImVec2(chip_x_start + 7.f, chip_y + (chip_h - cap_row_fs) * 0.5f),
				aida::ui::with_alpha(lbl_col, a), lbl.c_str());

			std::string perm_s = detail::format_protect_word(r.protect);
			ImVec2 perm_sz = cap_f->CalcTextSizeA(cap_row_fs, FLT_MAX, 0.f, perm_s.c_str());
			dl->AddText(cap_f, cap_row_fs,
				ImVec2(cp.x + row_w - perm_sz.x - 88.f, chip_y + (chip_h - cap_row_fs) * 0.5f),
				aida::ui::with_alpha(t.text_dim, a), perm_s.c_str());

			if (!r.module_name.empty()) {
				std::string mn = r.module_name;
				if (mn.size() > 24) mn = mn.substr(0, 21) + "...";
				dl->AddText(body_f, body_row_fs,
					ImVec2(cp.x + row_w - 200.f, cp.y + (row_h - body_row_fs) * 0.5f),
					aida::ui::with_alpha(t.text_secondary, a), mn.c_str());
			}

			if (clicked) {
				s.live_selected_base.store(r.base);
				diag::log_tagged_fmt("binary_map",
					"region_row_click base=0x%llX size=%llu kind=%s protect=0x%X",
					static_cast<unsigned long long>(r.base),
					static_cast<unsigned long long>(r.size),
					lbl.c_str(),
					static_cast<unsigned>(r.protect));
			}
			if (double_clicked) {
				diag::log_tagged_fmt("binary_map",
					"region_row_double_click base=0x%llX",
					static_cast<unsigned long long>(r.base));
				detail::jump_to_address(s, r.base);
			}
			const bool keyboard_context = detail::keyboard_context_requested(
				s.live_selected_base.load() == r.base);
			if (right_clicked || keyboard_context) {
				s.live_selected_base.store(r.base);
				s.ctx_va = r.base;
				diag::log_tagged_fmt("binary_map",
					"region_row_right_click base=0x%llX",
					static_cast<unsigned long long>(r.base));
				aida::ui::application_ui::retained_entity_context_t retained;
				retained.owner_id = "analysis.binary_map.region";
				retained.entity_id = std::to_string(r.base) + ":" + std::to_string(r.size);
				retained.entity_generation = s.workspace_generation;
				retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
				const auto retained_live = live_snapshot;
				const auto region = r;
				retained.validate_identity = [&s, retained_live, region] {
					const auto current_live = std::atomic_load_explicit(&s.live, std::memory_order_acquire);
					return current_live == retained_live && s.live_selected_base.load() == region.base
						? aida::ui::capability_state_t::available()
						: aida::ui::capability_state_t::unavailable(
							"The live memory-map publication or selected region changed");
				};
			detail::add_retained_action(retained, "analysis.binary_map.region.follow_disassembly",
				true, "", [&s, region] {
					detail::jump_to_address(s, region.base);
					return aida::ui::action_handler_result_t::completed();
				});
			detail::add_retained_action(retained, "analysis.binary_map.region.open_hex",
				true, "", [&s, region] {
					detail::jump_to_hex(s, region.base, detail::hex_request_size(region.size));
					return aida::ui::action_handler_result_t::completed();
				});
			detail::add_retained_action(retained, "analysis.binary_map.region.dump",
				region.size != 0, "The retained region is empty", [&s, region] {
					detail::dump_region_to_disk(s, region.base, region.size,
						detail::region_kind_label(region));
					return aida::ui::action_handler_result_t::completed();
				});
			detail::add_retained_action(retained, "analysis.binary_map.region.change_protection",
				region.size != 0 && !s.change_protect_pending.load(std::memory_order_acquire),
				s.change_protect_pending.load(std::memory_order_acquire)
					? "Another reviewed protection change is running" : "The retained region is empty",
				[&s, region] {
					s.change_protect_addr = region.base;
					s.change_protect_size = region.size;
					s.change_protect_old = region.protect;
					s.change_protect_choice = 0;
					s.change_protect_open = true;
					s.change_protect_popup_requested = true;
					ImGui::CloseCurrentPopup();
					return aida::ui::action_handler_result_t::completed();
				});
			detail::add_retained_action(retained, "analysis.binary_map.region.copy_va",
				true, "", [region] {
					char vbuf[32];
					std::snprintf(vbuf, sizeof(vbuf), "0x%llX",
						static_cast<unsigned long long>(region.base));
					ImGui::SetClipboardText(vbuf);
					toast_notification::push("Region VA copied",
						toast_notification::toast_type_t::info, 2.0f);
					return aida::ui::action_handler_result_t::completed();
				});
			detail::add_retained_action(retained, "analysis.binary_map.region.copy_json",
				true, "", [region] {
					std::string js = detail::region_to_json(region);
					ImGui::SetClipboardText(js.c_str());
					diag::log_tagged_fmt("binary_map",
						"region_ctx copy_json base=0x%llX bytes=%zu",
						static_cast<unsigned long long>(region.base), js.size());
					toast_notification::push("Region JSON copied",
						toast_notification::toast_type_t::info, 2.0f);
					return aida::ui::action_handler_result_t::completed();
				});
			detail::add_retained_action(retained, "analysis.binary_map.region.send_chat",
				true, "", [region] {
					std::string p = detail::make_region_chat_payload(region);
					detail::inject_to_chat(p);
					return aida::ui::action_handler_result_t::completed();
				});
			aida::ui::application_ui::open_retained_entity_context_menu(
					std::move(retained), detail::context_origin(right_clicked));
			}
			aida::ui::application_ui::render_retained_entity_context_menu(
				"analysis.binary_map.region");
			ImGui::PopID();
		};

		if (resolved_mode == active_mode_t::live_process || resolved_mode == active_mode_t::merged) {
			if (s.filtered_live_identity != live_snapshot.get() ||
				s.filtered_live_query != filter_lower) {
				s.filtered_live_identity = live_snapshot.get();
				s.filtered_live_query = filter_lower;
				s.filtered_live_indices.clear();
				s.filtered_live_indices.reserve(regions_copy.size());
				for (std::size_t i = 0; i < regions_copy.size(); ++i) {
					const auto& region = regions_copy[i];
					if (filter_lower.empty() ||
						detail::filter_matches(filter_lower, region.module_name) ||
						detail::filter_matches(filter_lower, detail::region_kind_label(region)) ||
						detail::filter_matches(filter_lower, region.info) ||
						detail::filter_matches(filter_lower,
							detail::format_protect_word(region.protect))) {
						if (i <= static_cast<std::size_t>((std::numeric_limits<int>::max)()))
							s.filtered_live_indices.push_back(static_cast<int>(i));
					}
				}
			}
			const int header_count = detail::count_as_int(s.filtered_live_indices.size());
			if (draw_section_header("Regions", header_count, "regions")) {
				ImGuiListClipper clipper;
				clipper.Begin(header_count, 32.f);
				while (clipper.Step()) {
					for (int visible = clipper.DisplayStart; visible < clipper.DisplayEnd; ++visible) {
						const int index = s.filtered_live_indices[static_cast<std::size_t>(visible)];
						if (detail::valid_index(index, regions_copy.size()))
							render_region_row(regions_copy[static_cast<std::size_t>(index)], index);
					}
				}
				clipper.End();
			}
			if (draw_section_header("Modules", detail::count_as_int(modules_copy.size()), "modules"))
			{
				int mi = 0;
				for (const auto& m : modules_copy) {
					if (!detail::filter_matches(filter_lower, m.name)) { ++mi; continue; }
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 28.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.hover_wash, a), 4.f);
					}
					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%012llX",
						static_cast<unsigned long long>(m.base));
					ImFont* code_f = aida::ui::fonts::code();
					if (!code_f) code_f = ImGui::GetFont();
					const float crfs = aida::ui::fonts::size_or(code_f, 14.f);
					ImFont* body_f = aida::ui::fonts::body();
					if (!body_f) body_f = ImGui::GetFont();
					const float brfs = aida::ui::fonts::size_or(body_f, 16.f);
					dl->AddText(code_f, crfs, ImVec2(cp.x + 12.f, cp.y + (row_h - crfs) * 0.5f),
						aida::ui::with_alpha(t.text_address, a), addr_buf);
					dl->AddText(body_f, brfs, ImVec2(cp.x + 12.f + 140.f, cp.y + (row_h - brfs) * 0.5f),
						aida::ui::with_alpha(t.text_primary, a), m.name.c_str());
					char sz_buf[24];
					std::snprintf(sz_buf, sizeof(sz_buf), "%s",
						detail::format_size_human(m.size).c_str());
					ImVec2 ssz = code_f->CalcTextSizeA(crfs, FLT_MAX, 0.f, sz_buf);
					dl->AddText(code_f, crfs,
						ImVec2(cp.x + row_w - ssz.x - 12.f, cp.y + (row_h - crfs) * 0.5f),
						aida::ui::with_alpha(t.text_dim, a), sz_buf);
					ImGui::SetCursorScreenPos(cp);
					ImGui::PushID(static_cast<int>(0x91000000u | static_cast<unsigned>(mi)));
					ImGui::InvisibleButton("##bm_mod_row", ImVec2(row_w, row_h));
					if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
						diag::log_tagged_fmt("binary_map",
							"module_row_click name='%s' base=0x%llX size=%u",
							m.name.c_str(),
							static_cast<unsigned long long>(m.base),
							static_cast<unsigned>(m.size));
						s.live_selected_base.store(m.base);
					}
					if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ImGui::IsItemHovered()) {
						detail::jump_to_address(s, m.base);
					}
					const bool module_pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
					const bool module_keyboard_context = detail::keyboard_context_requested(
						s.live_selected_base.load() == m.base);
					if (module_pointer_context || module_keyboard_context) {
						s.live_selected_base.store(m.base);
						aida::ui::application_ui::retained_entity_context_t retained;
						retained.owner_id = "analysis.binary_map.module";
						retained.entity_id = std::to_string(m.base) + ":" + m.name;
						retained.entity_generation = s.workspace_generation;
						retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
						const auto module = m;
						const auto retained_live = live_snapshot;
						retained.validate_identity = [&s, module, retained_live] {
							return std::atomic_load_explicit(&s.live, std::memory_order_acquire) == retained_live &&
								s.live_selected_base.load() == module.base
								? aida::ui::capability_state_t::available()
								: aida::ui::capability_state_t::unavailable(
									"The live module publication or selection changed");
						};
						detail::add_retained_action(retained, "analysis.binary_map.module.follow_disassembly",
							true, "", [&s, module] {
								detail::jump_to_address(s, module.base);
								return aida::ui::action_handler_result_t::completed();
							});
						detail::add_retained_action(retained, "analysis.binary_map.module.open_hex",
							true, "", [&s, module] {
								detail::jump_to_hex(s, module.base, 0x400);
								return aida::ui::action_handler_result_t::completed();
							});
						detail::add_retained_action(retained, "analysis.binary_map.module.copy_name",
							!module.name.empty(), "The retained module has no name", [module] {
							ImGui::SetClipboardText(module.name.c_str());
							toast_notification::push("Module name copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed();
						});
						detail::add_retained_action(retained, "analysis.binary_map.module.copy_path",
							!module.path.empty(), "The retained module has no path", [module] {
							ImGui::SetClipboardText(module.path.c_str());
							toast_notification::push("Module path copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed();
						});
						aida::ui::application_ui::open_retained_entity_context_menu(
							std::move(retained), detail::context_origin(module_pointer_context));
					}
					aida::ui::application_ui::render_retained_entity_context_menu(
						"analysis.binary_map.module");
					ImGui::PopID();
					ImGui::Dummy(ImVec2(row_w, row_h));
					++mi;
				}
			}
		}

		if (resolved_mode == active_mode_t::pe_static || resolved_mode == active_mode_t::merged) {
			if (draw_section_header("Sections", detail::count_as_int(sections_copy.size()), "sections")) {
				int idx = 0;
				const float sec_row_fs = aida::ui::fonts::size_or(code_font, 14.f);
				ImFont* sec_name_font = aida::ui::fonts::body();
				if (!sec_name_font) sec_name_font = code_font;
				const float sec_name_fs = aida::ui::fonts::size_or(sec_name_font, 16.f);
				ImFont* sec_perm_font = aida::ui::fonts::caption();
				if (!sec_perm_font) sec_perm_font = code_font;
				const float sec_perm_fs = aida::ui::fonts::size_or(sec_perm_font, 13.f);
				for (const auto& sec : sections_copy) {
					if (!detail::filter_matches(filter_lower, sec.name)) continue;
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 28.f;
					ImGui::PushID(static_cast<int>(0x30000000 | idx));
					ImGui::InvisibleButton("##bm_sec_row", ImVec2(row_w, row_h));
					bool hov = ImGui::IsItemHovered();
					bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
					bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
					bool double_clicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
						&& ImGui::IsItemHovered();
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.hover_wash, a), 4.f);
					}
					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(sec.va));
					ImU32 sc = detail::section_color(sec, a * 0.85f);
					dl->AddRectFilled(ImVec2(cp.x + 8.f, cp.y + 8.f), ImVec2(cp.x + 16.f, cp.y + row_h - 8.f),
						sc, 2.f);
					const float name_y = cp.y + (row_h - sec_name_fs) * 0.5f;
					const float code_y = cp.y + (row_h - sec_row_fs) * 0.5f;
					const float perm_y = cp.y + (row_h - sec_perm_fs) * 0.5f;
					dl->AddText(sec_name_font, sec_name_fs, ImVec2(cp.x + 24.f, name_y),
						aida::ui::with_alpha(t.text_primary, a), sec.name.c_str());
					dl->AddText(code_font, sec_row_fs, ImVec2(cp.x + 130.f, code_y),
						aida::ui::with_alpha(t.text_address, a), addr_buf);
					std::string sz = detail::format_size_human(sec.size);
					dl->AddText(code_font, sec_row_fs, ImVec2(cp.x + 250.f, code_y),
						aida::ui::with_alpha(t.text_secondary, a), sz.c_str());

					const float ent01 = detail::section_entropy_normalized(sec);
					const float ent_track_x = cp.x + 340.f;
					const float ent_track_w = 84.f;
					const float ent_y = cp.y + (row_h - 6.f) * 0.5f;
					dl->AddRectFilled(ImVec2(ent_track_x, ent_y),
						ImVec2(ent_track_x + ent_track_w, ent_y + 6.f),
						aida::ui::with_alpha(t.border_subtle, a * 0.6f), 1.5f);
					if (sec.sampled_bytes > 0 && ent_track_w > 4.f) {
						float fill_w = ent_track_w * ent01;
						if (fill_w < 0.f) fill_w = 0.f;
						if (fill_w > ent_track_w) fill_w = ent_track_w;
						ImU32 ec = aida::ui::mix(t.success, t.error, ent01);
						dl->AddRectFilled(ImVec2(ent_track_x, ent_y),
							ImVec2(ent_track_x + fill_w, ent_y + 6.f),
							aida::ui::with_alpha(ec, a * 0.9f), 1.5f);
						char ebuf[16];
						std::snprintf(ebuf, sizeof(ebuf), "%.2f",
							static_cast<double>(ent01) * 8.0);
						dl->AddText(sec_perm_font, sec_perm_fs,
							ImVec2(ent_track_x + ent_track_w + 6.f, perm_y),
							aida::ui::with_alpha(t.text_secondary, a), ebuf);
					} else {
						dl->AddText(sec_perm_font, sec_perm_fs,
							ImVec2(ent_track_x + ent_track_w + 6.f, perm_y),
							aida::ui::with_alpha(t.text_dim, a), "--");
					}

					std::string p = detail::section_perm_string(sec);
					ImVec2 perm_sz = sec_perm_font->CalcTextSizeA(sec_perm_fs, FLT_MAX, 0.f, p.c_str());
					dl->AddText(sec_perm_font, sec_perm_fs,
						ImVec2(cp.x + row_w - perm_sz.x - 12.f, perm_y),
						aida::ui::with_alpha(t.text_dim, a), p.c_str());
					if (clicked) {
						diag::log_tagged_fmt("binary_map",
							"section_row_click name='%s' va=0x%llX size=%llu perm=%s",
							sec.name.c_str(),
							static_cast<unsigned long long>(sec.va),
							static_cast<unsigned long long>(sec.size),
							p.c_str());
						detail::jump_to_address(s, sec.va);
					}
					if (double_clicked) {
						diag::log_tagged_fmt("binary_map",
							"section_row_double_click name='%s' va=0x%llX (jump_to_hex)",
							sec.name.c_str(),
							static_cast<unsigned long long>(sec.va));
						detail::jump_to_hex(s, sec.va, detail::hex_request_size(sec.size));
					}
					const bool section_keyboard_context = detail::keyboard_context_requested(
						s.selected_va.load() == sec.va);
					if (right_clicked || section_keyboard_context) {
						s.selected_va.store(sec.va);
						aida::ui::application_ui::retained_entity_context_t retained;
						retained.owner_id = "analysis.binary_map.section";
						retained.entity_id = std::to_string(sec.va) + ":" + sec.name;
						retained.entity_generation = s.workspace_generation;
						retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
						const auto section = sec;
						const auto retained_map = map_snapshot;
						retained.validate_identity = [&s, section, retained_map] {
							return std::atomic_load_explicit(&s.map, std::memory_order_acquire) == retained_map &&
								s.selected_va.load() == section.va
								? aida::ui::capability_state_t::available()
								: aida::ui::capability_state_t::unavailable(
									"The static Binary Map publication or selected section changed");
						};
						detail::add_retained_action(retained, "analysis.binary_map.section.follow_disassembly",
							true, "", [&s, section] { detail::jump_to_address(s, section.va);
								return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.section.open_hex",
							true, "", [&s, section] { detail::jump_to_hex(s, section.va,
								detail::hex_request_size(section.size));
								return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.section.dump",
							section.size != 0, "The retained section is empty", [&s, section] {
								detail::dump_region_to_disk(s, section.va, section.size,
									section.name.empty() ? std::string("section") : section.name);
								return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.section.copy_name",
							!section.name.empty(), "The retained section has no name", [section] {
							ImGui::SetClipboardText(section.name.c_str());
							toast_notification::push("Section name copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.section.copy_va",
							true, "", [section] {
							char text[32]{};
							std::snprintf(text, sizeof(text), "0x%llX",
								static_cast<unsigned long long>(section.va));
							ImGui::SetClipboardText(text);
							toast_notification::push("Section VA copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						aida::ui::application_ui::open_retained_entity_context_menu(
							std::move(retained), detail::context_origin(right_clicked));
					}
					aida::ui::application_ui::render_retained_entity_context_menu(
						"analysis.binary_map.section");
					ImGui::PopID();
					++idx;
				}
			}

			if (draw_section_header("Functions", detail::count_as_int(functions_copy.size()), "functions")) {
				int idx = 0;
				uint64_t cur_sel = s.selected_va.load();
				const float fn_code_fs = aida::ui::fonts::size_or(code_font, 14.f);
				ImFont* fn_name_font = aida::ui::fonts::body();
				if (!fn_name_font) fn_name_font = ImGui::GetFont();
				const float fn_name_fs = aida::ui::fonts::size_or(fn_name_font, 16.f);
				ImFont* fn_chip_font = aida::ui::fonts::caption();
				if (!fn_chip_font) fn_chip_font = code_font;
				const float fn_chip_fs = aida::ui::fonts::size_or(fn_chip_font, 13.f);
				for (auto& fn : functions_copy) {
					if (!detail::filter_matches(filter_lower, fn.name)) continue;
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 36.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
					bool sel = (cur_sel == fn.va) && fn.va != 0;
					if (sel) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.selection, a), 5.f);
						dl->AddRectFilled(cp, ImVec2(cp.x + 3.f, cp.y + row_h),
							aida::ui::with_alpha(t.accent_u32, a), 1.f);
					} else if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.hover_wash, a), 5.f);
					}

					auto& flash = s.pin_flashes[fn.va];
					flash.tick(dt, 3.0f);
					float pin_scale = 1.f + flash.v * 0.6f;
					ImU32 star_col = fn.pinned
						? aida::ui::with_alpha(t.accent_u32, a)
						: aida::ui::with_alpha(t.text_dim, a);
					ImVec2 star_pos = ImVec2(cp.x + 14.f, cp.y + row_h * 0.5f);
					dl->AddCircleFilled(star_pos, 5.f * pin_scale,
						aida::ui::with_alpha(star_col, a * 0.85f), 12);
					if (fn.pinned) {
						dl->AddCircleFilled(star_pos, 7.f * pin_scale,
							aida::ui::with_alpha(t.accent_glow, a * (0.5f + flash.v * 0.5f)), 16);
					}

					ImGui::SetCursorScreenPos(ImVec2(cp.x + 4.f, cp.y));
					ImGui::PushID(static_cast<int>(idx));
					if (ImGui::InvisibleButton("##bm_pin_btn", ImVec2(24.f, row_h))) {
						const bool was_pinned = fn.pinned;
						detail::set_function_pinned(s, fn.va, !was_pinned);
						flash.trigger();
						s.refresh_after_pin_requested = true;
						diag::log_tagged_fmt("binary_map",
							"pin_btn_click name='%s' va=0x%llX was_pinned=%d action=%s",
							fn.name.c_str(),
							static_cast<unsigned long long>(fn.va),
							was_pinned ? 1 : 0,
							was_pinned ? "unpin" : "pin");
					}
					ImGui::PopID();

					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(fn.va));
					const float addr_y = cp.y + 5.f;
					const float name_y = cp.y + (row_h - fn_name_fs) * 0.5f;
					dl->AddText(code_font, fn_code_fs, ImVec2(cp.x + 30.f, addr_y),
						aida::ui::with_alpha(t.text_address, a), addr_buf);
					dl->AddText(fn_name_font, fn_name_fs,
						ImVec2(cp.x + 30.f + 138.f, name_y),
						aida::ui::with_alpha(t.text_primary, a), fn.name.c_str());

					char chip_xref[24];
					std::snprintf(chip_xref, sizeof(chip_xref), "x%d", fn.xref_count);
					char chip_call[24];
					std::snprintf(chip_call, sizeof(chip_call), "c%d", fn.callee_count);
					float chip_h = fn_chip_fs + 6.f;
					float chip_y = cp.y + row_h - chip_h - 4.f;
					float chip_x = cp.x + 30.f + 138.f;

					auto draw_mini_chip = [&](const char* label, ImU32 col) {
						ImFont* f = fn_chip_font;
						float fs = fn_chip_fs;
						ImVec2 sz = f->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
						float pad_x = 7.f;
						float wc = sz.x + pad_x * 2.f;
						float hc = chip_h;
						dl->AddRectFilled(ImVec2(chip_x, chip_y),
							ImVec2(chip_x + wc, chip_y + hc),
							aida::ui::with_alpha(col, a * 0.22f), hc * 0.5f);
						dl->AddText(f, fs, ImVec2(chip_x + pad_x, chip_y + (hc - fs) * 0.5f),
							aida::ui::with_alpha(col, a), label);
						chip_x += wc + 6.f;
					};
					draw_mini_chip(chip_xref, t.info);
					draw_mini_chip(chip_call, t.accent_u32);

					ImGui::SetCursorScreenPos(ImVec2(cp.x + 30.f, cp.y));
					ImGui::PushID(static_cast<int>(0x40000000 | idx));
					ImGui::InvisibleButton("##bm_fn_row", ImVec2(row_w - 30.f, row_h));
					if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
						s.selected_va.store(fn.va);
						diag::log_tagged_fmt("binary_map",
							"function_row_click name='%s' va=0x%llX xrefs=%d callees=%d pinned=%d",
							fn.name.c_str(),
							static_cast<unsigned long long>(fn.va),
							fn.xref_count, fn.callee_count,
							fn.pinned ? 1 : 0);
					}
					if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ImGui::IsItemHovered()) {
						diag::log_tagged_fmt("binary_map",
							"function_row_double_click name='%s' va=0x%llX",
							fn.name.c_str(),
							static_cast<unsigned long long>(fn.va));
						detail::jump_to_address(s, fn.va);
					}
					const bool function_pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
					const bool function_keyboard_context = detail::keyboard_context_requested(sel);
					if (function_pointer_context || function_keyboard_context) {
						s.ctx_target.store(idx);
						s.ctx_va = fn.va;
						s.selected_va.store(fn.va);
						diag::log_tagged_fmt("binary_map",
							"function_row_right_click name='%s' va=0x%llX",
							fn.name.c_str(),
							static_cast<unsigned long long>(fn.va));
						aida::ui::application_ui::retained_entity_context_t retained;
						retained.owner_id = "analysis.binary_map.function";
						retained.entity_id = std::to_string(fn.va) + ":" + fn.name;
						retained.entity_generation = s.workspace_generation;
						retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
						const auto function = fn;
						const auto retained_map = map_snapshot;
						retained.validate_identity = [&s, function, retained_map] {
							return std::atomic_load_explicit(&s.map, std::memory_order_acquire) == retained_map &&
								s.selected_va.load() == function.va
								? aida::ui::capability_state_t::available()
								: aida::ui::capability_state_t::unavailable(
									"The Binary Map function publication or selection changed");
						};
						detail::add_retained_action(retained, "analysis.binary_map.function.send_chat",
							true, "", [function] {
							std::string payload = detail::make_function_chat_payload(function);
							detail::inject_to_chat(payload);
							return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, function.pinned
							? "analysis.binary_map.function.unpin" : "analysis.binary_map.function.pin",
							true, "", [&s, function] {
							detail::set_function_pinned(s, function.va, !function.pinned);
							s.pin_flashes[function.va].trigger();
							s.refresh_after_pin_requested = true;
							return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.function.follow_disassembly",
							true, "", [&s, function] { detail::jump_to_address(s, function.va);
								return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.function.open_hex",
							true, "", [&s, function] { detail::jump_to_hex(s, function.va, 0x400);
								return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.function.copy_va",
							true, "", [function] {
							char vbuf[32];
							std::snprintf(vbuf, sizeof(vbuf), "0x%llX",
								static_cast<unsigned long long>(function.va));
							ImGui::SetClipboardText(vbuf);
							toast_notification::push("Function VA copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.function.copy_name",
							!function.name.empty(), "The retained function has no name", [function] {
							ImGui::SetClipboardText(function.name.c_str());
							toast_notification::push("Function name copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						aida::ui::application_ui::open_retained_entity_context_menu(
							std::move(retained), detail::context_origin(function_pointer_context));
					}
					aida::ui::application_ui::render_retained_entity_context_menu(
						"analysis.binary_map.function");
					ImGui::PopID();
					ImGui::Dummy(ImVec2(row_w, row_h));
					++idx;
				}
			}

			if (draw_section_header("Globals", detail::count_as_int(globals_copy.size()), "globals")) {
				int idx = 0;
				const float gl_code_fs = aida::ui::fonts::size_or(code_font, 14.f);
				ImFont* gl_name_font = aida::ui::fonts::body();
				if (!gl_name_font) gl_name_font = ImGui::GetFont();
				const float gl_name_fs = aida::ui::fonts::size_or(gl_name_font, 16.f);
				ImFont* gl_chip_font = aida::ui::fonts::caption();
				if (!gl_chip_font) gl_chip_font = code_font;
				const float gl_chip_fs = aida::ui::fonts::size_or(gl_chip_font, 13.f);
				for (const auto& gl : globals_copy) {
					if (!detail::filter_matches(filter_lower, gl.name)) continue;
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 30.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
							aida::ui::with_alpha(t.hover_wash, a), 4.f);
					}
					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(gl.va));
					const float gl_code_y = cp.y + (row_h - gl_code_fs) * 0.5f;
					const float gl_name_y = cp.y + (row_h - gl_name_fs) * 0.5f;
					dl->AddText(code_font, gl_code_fs, ImVec2(cp.x + 10.f, gl_code_y),
						aida::ui::with_alpha(t.text_address, a), addr_buf);
					dl->AddText(gl_name_font, gl_name_fs,
						ImVec2(cp.x + 130.f, gl_name_y),
						aida::ui::with_alpha(t.text_primary, a), gl.name.c_str());

					char chip_buf[16];
					std::snprintf(chip_buf, sizeof(chip_buf), "x%d", gl.xref_count);
					ImVec2 sz = gl_chip_font->CalcTextSizeA(gl_chip_fs, FLT_MAX, 0.f, chip_buf);
					float chip_w = sz.x + 14.f;
					float chip_h = gl_chip_fs + 6.f;
					ImVec2 ca = ImVec2(cp.x + row_w - chip_w - 44.f, cp.y + (row_h - chip_h) * 0.5f);
					ImVec2 cb = ImVec2(ca.x + chip_w, ca.y + chip_h);
					dl->AddRectFilled(ca, cb, aida::ui::with_alpha(t.info, a * 0.22f), chip_h * 0.5f);
					dl->AddText(gl_chip_font, gl_chip_fs,
						ImVec2(ca.x + 7.f, ca.y + (chip_h - gl_chip_fs) * 0.5f),
						aida::ui::with_alpha(t.info, a), chip_buf);

					ImU32 perm_col = gl.writable
						? aida::ui::with_alpha(t.success, a)
						: aida::ui::with_alpha(t.text_dim, a);
					dl->AddText(gl_chip_font, gl_chip_fs,
						ImVec2(cp.x + row_w - 30.f, cp.y + (row_h - gl_chip_fs) * 0.5f),
						perm_col, gl.writable ? "rw" : "ro");

					ImGui::SetCursorScreenPos(cp);
					ImGui::PushID(static_cast<int>(0x50000000 | idx));
					ImGui::InvisibleButton("##bm_gl_row", ImVec2(row_w, row_h));
					if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
						s.selected_entity_id = "global:" + std::to_string(gl.va);
						diag::log_tagged_fmt("binary_map",
							"global_row_click name='%s' va=0x%llX xrefs=%d writable=%d",
							gl.name.c_str(),
							static_cast<unsigned long long>(gl.va),
							gl.xref_count,
							gl.writable ? 1 : 0);
						detail::jump_to_hex(s, gl.va, 0x200);
					}
					if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ImGui::IsItemHovered()) {
						detail::jump_to_address(s, gl.va);
					}
					const std::string global_id = "global:" + std::to_string(gl.va);
					const bool global_pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
					const bool global_keyboard_context = detail::keyboard_context_requested(
						s.selected_entity_id == global_id);
					if (global_pointer_context || global_keyboard_context) {
						s.selected_entity_id = global_id;
						aida::ui::application_ui::retained_entity_context_t retained;
						retained.owner_id = "analysis.binary_map.global";
						retained.entity_id = global_id + ":" + gl.name;
						retained.entity_generation = s.workspace_generation;
						retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
						const auto global = gl;
						const auto retained_map = map_snapshot;
						retained.validate_identity = [&s, global_id, retained_map] {
							return std::atomic_load_explicit(&s.map, std::memory_order_acquire) == retained_map &&
								s.selected_entity_id == global_id
								? aida::ui::capability_state_t::available()
								: aida::ui::capability_state_t::unavailable(
									"The Binary Map global publication or selection changed");
						};
						detail::add_retained_action(retained, "analysis.binary_map.global.send_chat",
							true, "", [global] {
							std::string payload = detail::make_global_chat_payload(global);
							detail::inject_to_chat(payload);
							return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.global.open_hex",
							true, "", [&s, global] { detail::jump_to_hex(s, global.va, 0x200);
								return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.global.follow_disassembly",
							true, "", [&s, global] { detail::jump_to_address(s, global.va);
								return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.global.copy_va",
							true, "", [global] {
							char vbuf[32];
							std::snprintf(vbuf, sizeof(vbuf), "0x%llX",
								static_cast<unsigned long long>(global.va));
							ImGui::SetClipboardText(vbuf);
							toast_notification::push("Global VA copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.global.copy_name",
							!global.name.empty(), "The retained global has no name", [global] {
							ImGui::SetClipboardText(global.name.c_str());
							toast_notification::push("Global name copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						aida::ui::application_ui::open_retained_entity_context_menu(
							std::move(retained), detail::context_origin(global_pointer_context));
					}
					aida::ui::application_ui::render_retained_entity_context_menu(
						"analysis.binary_map.global");
					ImGui::PopID();
					++idx;
				}
			}

			if (draw_section_header("Imports", total_imports, "imports")) {
				int imp_idx = 0;
				for (const auto& imp : imports_copy) {
					const auto colon = imp.find(':');
					const std::string dll = (colon == std::string::npos) ? imp : imp.substr(0, colon);
					std::string func_list;
					if (colon != std::string::npos && colon + 1 < imp.size()) {
						std::size_t start = colon + 1;
						while (start < imp.size() && imp[start] == ' ') ++start;
						func_list = imp.substr(start);
					}

					std::vector<std::string> funcs;
					{
						std::size_t pos = 0;
						while (pos < func_list.size()) {
							std::size_t next = func_list.find(',', pos);
							if (next == std::string::npos) next = func_list.size();
							std::string token = func_list.substr(pos, next - pos);
							while (!token.empty() && token.front() == ' ') token.erase(token.begin());
							while (!token.empty() && token.back() == ' ') token.pop_back();
							if (!token.empty()) funcs.push_back(std::move(token));
							pos = next + 1u;
						}
					}

					bool any_match = detail::filter_matches(filter_lower, dll);
					if (!any_match) {
						for (const auto& fn : funcs) {
							if (detail::filter_matches(filter_lower, fn)) {
								any_match = true;
								break;
							}
						}
					}
					if (!any_match) continue;

					const std::string key = std::string("imports::") + dll;
					bool collapsed = detail::group_is_collapsed(s, key);

					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					float row_h = 26.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
					ImU32 fill = hov
						? aida::ui::with_alpha(t.hover_wash, a)
						: aida::ui::with_alpha(t.panel_bg, a * 0.7f);
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), fill, 4.f);
					ImU32 ar = aida::ui::with_alpha(t.accent_u32, a);
					float arrow_x = cp.x + 12.f;
					float arrow_y = cp.y + row_h * 0.5f;
					if (collapsed) {
						dl->AddTriangleFilled(
							ImVec2(arrow_x, arrow_y - 4.f),
							ImVec2(arrow_x + 6.f, arrow_y),
							ImVec2(arrow_x, arrow_y + 4.f), ar);
					} else {
						dl->AddTriangleFilled(
							ImVec2(arrow_x - 1.f, arrow_y - 2.f),
							ImVec2(arrow_x + 7.f, arrow_y - 2.f),
							ImVec2(arrow_x + 3.f, arrow_y + 4.f), ar);
					}
					char hbuf[200];
					std::snprintf(hbuf, sizeof(hbuf), "%s  (%d)",
						dll.c_str(), detail::count_as_int(funcs.size()));
					ImFont* imp_hdr_font = aida::ui::fonts::body_em();
					if (!imp_hdr_font) imp_hdr_font = ImGui::GetFont();
					const float imp_hdr_fs = aida::ui::fonts::size_or(imp_hdr_font, 16.f);
					dl->AddText(imp_hdr_font, imp_hdr_fs,
						ImVec2(cp.x + 28.f, cp.y + (row_h - imp_hdr_fs) * 0.5f),
						aida::ui::with_alpha(t.text_primary, a), hbuf);

					ImGui::SetCursorScreenPos(cp);
					ImGui::PushID(static_cast<int>(0x60000000 | imp_idx));
					ImGui::InvisibleButton("##bm_imp_hdr", ImVec2(row_w, row_h));
					if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
						s.selected_entity_id = "import-dll:" + dll;
						diag::log_tagged_fmt("binary_map",
							"import_dll_toggle dll='%s' funcs=%zu now_collapsed=%d",
							dll.c_str(), funcs.size(), (!collapsed) ? 1 : 0);
						detail::toggle_group(s, key);
					}
					const std::string import_dll_id = "import-dll:" + dll;
					const bool import_dll_pointer = ImGui::IsItemClicked(ImGuiMouseButton_Right);
					const bool import_dll_keyboard = detail::keyboard_context_requested(
						s.selected_entity_id == import_dll_id);
					if (import_dll_pointer || import_dll_keyboard) {
						s.selected_entity_id = import_dll_id;
						aida::ui::application_ui::retained_entity_context_t retained;
						retained.owner_id = "analysis.binary_map.import_dll";
						retained.entity_id = import_dll_id;
						retained.entity_generation = s.workspace_generation;
						retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
						const auto retained_map = map_snapshot;
						retained.validate_identity = [&s, import_dll_id, retained_map] {
							return std::atomic_load_explicit(&s.map, std::memory_order_acquire) == retained_map &&
								s.selected_entity_id == import_dll_id
								? aida::ui::capability_state_t::available()
								: aida::ui::capability_state_t::unavailable(
									"The import publication or selected DLL changed");
						};
						detail::add_retained_action(retained, "analysis.binary_map.import.copy_dll_name",
							!dll.empty(), "The retained import has no DLL name", [dll] {
							ImGui::SetClipboardText(dll.c_str());
							toast_notification::push("DLL name copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.import.copy_function_list",
							!funcs.empty(), "The retained DLL has no imported functions", [funcs] {
							std::string joined;
							for (std::size_t fi = 0; fi < funcs.size(); ++fi) {
								if (fi) joined += "\n";
								joined += funcs[fi];
							}
							ImGui::SetClipboardText(joined.c_str());
							toast_notification::push("Function list copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						aida::ui::application_ui::open_retained_entity_context_menu(
							std::move(retained), detail::context_origin(import_dll_pointer));
					}
					aida::ui::application_ui::render_retained_entity_context_menu(
						"analysis.binary_map.import_dll");
					ImGui::PopID();

					if (!collapsed) {
						const float imp_fn_fs = aida::ui::fonts::size_or(code_font, 14.f);
						const float imp_row_h = imp_fn_fs + 10.f;
						int fn_idx = 0;
						for (const auto& fn : funcs) {
							if (!detail::filter_matches(filter_lower, fn) &&
								!detail::filter_matches(filter_lower, dll)) { ++fn_idx; continue; }
							ImVec2 ip = ImGui::GetCursorScreenPos();
							bool fn_hov = ImGui::IsMouseHoveringRect(ip,
								ImVec2(ip.x + row_w, ip.y + imp_row_h), true);
							if (fn_hov) {
								dl->AddRectFilled(ip, ImVec2(ip.x + row_w, ip.y + imp_row_h),
									aida::ui::with_alpha(t.hover_wash, a * 0.7f), 3.f);
							}
							dl->AddText(code_font, imp_fn_fs,
								ImVec2(ip.x + 36.f, ip.y + (imp_row_h - imp_fn_fs) * 0.5f),
								aida::ui::with_alpha(t.text_secondary, a), fn.c_str());
							ImGui::SetCursorScreenPos(ip);
							ImGui::PushID(static_cast<int>(0x70000000 | (imp_idx * 4096 + fn_idx)));
							ImGui::InvisibleButton("##bm_imp_fn", ImVec2(row_w, imp_row_h));
							if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
								s.selected_entity_id = "import-function:" + dll + "!" + fn;
								std::string clip = dll + "!" + fn;
								ImGui::SetClipboardText(clip.c_str());
								toast_notification::push("Import symbol copied",
									toast_notification::toast_type_t::info, 2.0f);
							}
							const std::string import_function_id = "import-function:" + dll + "!" + fn;
							const bool import_function_pointer = ImGui::IsItemClicked(ImGuiMouseButton_Right);
							const bool import_function_keyboard = detail::keyboard_context_requested(
								s.selected_entity_id == import_function_id);
							if (import_function_pointer || import_function_keyboard) {
								s.selected_entity_id = import_function_id;
								aida::ui::application_ui::retained_entity_context_t retained;
								retained.owner_id = "analysis.binary_map.import_function";
								retained.entity_id = import_function_id;
								retained.entity_generation = s.workspace_generation;
								retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
								const auto retained_map = map_snapshot;
								retained.validate_identity = [&s, import_function_id, retained_map] {
									return std::atomic_load_explicit(&s.map, std::memory_order_acquire) == retained_map &&
										s.selected_entity_id == import_function_id
										? aida::ui::capability_state_t::available()
										: aida::ui::capability_state_t::unavailable(
											"The import publication or selected function changed");
								};
								detail::add_retained_action(retained, "analysis.binary_map.import.copy_qualified_name",
									true, "", [dll, fn] {
									std::string clip = dll + "!" + fn;
									ImGui::SetClipboardText(clip.c_str());
									toast_notification::push("Import symbol copied",
										toast_notification::toast_type_t::info, 2.0f);
									return aida::ui::action_handler_result_t::completed(); });
								detail::add_retained_action(retained, "analysis.binary_map.import.copy_function_name",
									!fn.empty(), "The retained import has no function name", [fn] {
									ImGui::SetClipboardText(fn.c_str());
									return aida::ui::action_handler_result_t::completed(); });
								aida::ui::application_ui::open_retained_entity_context_menu(
									std::move(retained), detail::context_origin(import_function_pointer));
							}
							aida::ui::application_ui::render_retained_entity_context_menu(
								"analysis.binary_map.import_function");
							ImGui::PopID();
							ImGui::Dummy(ImVec2(row_w, imp_row_h));
							++fn_idx;
						}
					}
					++imp_idx;
				}
			}

			if (draw_section_header("Exports", total_exports, "exports")) {
				int idx = 0;
				const float exp_fs = aida::ui::fonts::size_or(code_font, 14.f);
				const float exp_row_h = exp_fs + 10.f;
				for (const auto& ex : exports_copy) {
					if (!detail::filter_matches(filter_lower, ex)) continue;
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float row_w = ImGui::GetContentRegionAvail().x;
					ImGui::PushID(static_cast<int>(0x7E000000 | (idx & 0x00FFFFFF)));
					ImGui::InvisibleButton("##bm_exp_row", ImVec2(row_w, exp_row_h));
					bool hov = ImGui::IsItemHovered();
					bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
					bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + exp_row_h),
							aida::ui::with_alpha(t.hover_wash, a), 3.f);
					}
					dl->AddText(code_font, exp_fs,
						ImVec2(cp.x + 18.f, cp.y + (exp_row_h - exp_fs) * 0.5f),
						aida::ui::with_alpha(t.text_primary, a), ex.c_str());
					uint64_t resolved_va = 0;
					for (const auto& fn : map.functions) {
						if (fn.name == ex) { resolved_va = fn.va; break; }
					}
					if (clicked) {
						s.selected_entity_id = "export:" + ex;
						if (resolved_va != 0) {
							detail::jump_to_address(s, resolved_va);
						} else {
							ImGui::SetClipboardText(ex.c_str());
							toast_notification::push("Export name copied (no VA resolved)",
								toast_notification::toast_type_t::info, 2.5f);
						}
					}
					const std::string export_id = "export:" + ex;
					const bool export_keyboard_context = detail::keyboard_context_requested(
						s.selected_entity_id == export_id);
					if (right_clicked || export_keyboard_context) {
						s.selected_entity_id = export_id;
						aida::ui::application_ui::retained_entity_context_t retained;
						retained.owner_id = "analysis.binary_map.export";
						retained.entity_id = export_id;
						retained.entity_generation = s.workspace_generation;
						retained.active_view = aida::ui::stable_view_id_t("view.analysis.binary_map");
						const auto retained_map = map_snapshot;
						retained.validate_identity = [&s, export_id, retained_map] {
							return std::atomic_load_explicit(&s.map, std::memory_order_acquire) == retained_map &&
								s.selected_entity_id == export_id
								? aida::ui::capability_state_t::available()
								: aida::ui::capability_state_t::unavailable(
									"The export publication or selected symbol changed");
						};
						detail::add_retained_action(retained, "analysis.binary_map.export.follow_disassembly",
							resolved_va != 0, "No function address was resolved for this export",
							[&s, resolved_va] { detail::jump_to_address(s, resolved_va);
								return aida::ui::action_handler_result_t::completed(); });
						detail::add_retained_action(retained, "analysis.binary_map.export.copy_name",
							!ex.empty(), "The retained export has no name", [ex] {
							ImGui::SetClipboardText(ex.c_str());
							toast_notification::push("Export name copied",
								toast_notification::toast_type_t::info, 2.0f);
							return aida::ui::action_handler_result_t::completed(); });
						aida::ui::application_ui::open_retained_entity_context_menu(
							std::move(retained), detail::context_origin(right_clicked));
					}
					aida::ui::application_ui::render_retained_entity_context_menu(
						"analysis.binary_map.export");
					ImGui::PopID();
					ImGui::Dummy(ImVec2(row_w, exp_row_h));
					++idx;
				}
			}
		}

		if (resolved_mode == active_mode_t::pe_static
			&& functions_copy.empty() && !refreshing_now)
		{
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 sz = ImVec2(panel_inner_w, std::max(120.f, section_inner_h * 0.5f));
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
			cfg.title = "No binary loaded";
			cfg.body = last_error_copy.empty()
				? "Open a binary or press Refresh to build the map."
				: last_error_copy;
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(cp, sz, cfg);
		} else if (resolved_mode == active_mode_t::live_process
			&& regions_copy.empty() && !refreshing_now)
		{
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ImVec2 sz = ImVec2(panel_inner_w, std::max(120.f, section_inner_h * 0.5f));
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::memory;
			cfg.title = "No live regions";
			cfg.body = live_last_error_copy.empty()
				? "Press Refresh while attached to enumerate memory regions."
				: live_last_error_copy;
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(cp, sz, cfg);
		}

		ImGui::EndChild();
		ImGui::PopFont();
		ImGui::PopStyleColor(3);

		ImGui::EndChild();

		if (s.change_protect_popup_requested) {
			s.change_protect_popup_requested = false;
			ImGui::OpenPopup("Change Protection");
		}

		if (ImGui::BeginPopupModal("Change Protection", &s.change_protect_open, ImGuiWindowFlags_AlwaysAutoResize)) {
			ImGui::Text("Address: %016llX", static_cast<unsigned long long>(s.change_protect_addr));
			ImGui::Text("Size:    %llu bytes", static_cast<unsigned long long>(s.change_protect_size));
			ImGui::Text("Current: 0x%X", s.change_protect_old);
			ImGui::TextWrapped("This mutates the attached process over the exact range above. "
				"AiDA will read back the resulting region protection, but this operation has no automatic undo.");
			ImGui::Separator();
			const char* labels_arr[] = {
				"PAGE_NOACCESS (0x01)",
				"PAGE_READONLY (0x02)",
				"PAGE_READWRITE (0x04)",
				"PAGE_WRITECOPY (0x08)",
				"PAGE_EXECUTE (0x10)",
				"PAGE_EXECUTE_READ (0x20)",
				"PAGE_EXECUTE_READWRITE (0x40)",
				"PAGE_EXECUTE_WRITECOPY (0x80)"
			};
			const uint32_t values_arr[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
			const int val_count = static_cast<int>(sizeof(values_arr) / sizeof(values_arr[0]));
			if (s.change_protect_choice < 0) s.change_protect_choice = 0;
			if (s.change_protect_choice >= val_count) s.change_protect_choice = val_count - 1;
			ImGui::Combo("##bm_new_protect", &s.change_protect_choice, labels_arr, val_count);
			ImGui::Separator();
			const bool protection_pending = s.change_protect_pending.load(std::memory_order_acquire);
			ImGui::BeginDisabled(protection_pending);
			if (ImGui::Button("Apply", ImVec2(100.f, 0.f))) {
				const uint32_t new_protect = values_arr[s.change_protect_choice];
				diag::log_tagged_critical_fmt("binary_map",
					"change_protect_request addr=0x%llx size=%llu new=0x%X",
					static_cast<unsigned long long>(s.change_protect_addr),
					static_cast<unsigned long long>(s.change_protect_size),
					static_cast<unsigned>(new_protect));
				bool queued = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				std::uint32_t old_protect = 0;
				const auto process = context.workspace->identity().process();
				queued = process && driver_bridge::protect_memory_for(process->pid,
					s.change_protect_addr, s.change_protect_size, new_protect, &old_protect);
				if (queued) s.live_refresh_requested.store(true, std::memory_order_release);
#else
				queued = detail::queue_protection_change(state_handle, context,
					s.change_protect_addr, s.change_protect_size, new_protect);
#endif
				if (!queued)
					toast_notification::push("The reviewed protection change could not be queued; see Task Center",
						toast_notification::toast_type_t::error, 3.0f);
				s.change_protect_open = false;
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndDisabled();
			if (protection_pending && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
				ImGui::SetTooltip("A reviewed protection change is already running");
			ImGui::SameLine();
			if (ImGui::Button("Cancel", ImVec2(100.f, 0.f))) {
				s.change_protect_open = false;
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}

		if (s.refresh_after_pin_requested) {
			s.refresh_after_pin_requested = false;
			s.refresh_requested.store(true);
		}

		if (!s.auto_refreshed_once) {
			if (want_static && !s.refreshing.load()) {
				s.refresh_requested.store(true);
			}
			if (want_live && !s.live_refreshing.load() && detail::live_available(s)) {
				s.live_refresh_requested.store(true);
			}
			s.auto_refreshed_once = true;
		}

		if (want_live && detail::live_available(s) && !s.live_refreshing.load()) {
			const auto process = context.workspace->identity().process();
			const uint32_t live_pid_attached = process ? process->pid : 0;
			uint32_t cached_pid = 0;
			std::size_t cached_regions = 0;
			const auto cached_live = std::atomic_load_explicit(&s.live, std::memory_order_acquire);
			if (cached_live) {
				cached_pid = cached_live->pid;
				cached_regions = cached_live->regions.size();
			}
			if (cached_pid != live_pid_attached || (live_pid_attached != 0 && cached_regions == 0)) {
				diag::log_tagged_fmt("binary_map",
					"live_auto_refresh_trigger cached_pid=%u attached_pid=%u cached_regions=%zu",
					static_cast<unsigned>(cached_pid),
					static_cast<unsigned>(live_pid_attached),
					cached_regions);
				s.live_refresh_requested.store(true);
			}
		}
	}

	inline void render(int x, int y, float w, float h,
		float anim, float anim_x, float anim_y, float anim_z)
	{
		render(x, y, w, h, anim, anim_x, anim_y, anim_z,
			disasm_view::capture_selected_workspace());
	}

}
}
