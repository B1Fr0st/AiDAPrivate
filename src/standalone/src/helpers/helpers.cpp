#include "helpers.h"
#include "globals.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../preview/shell_preview_platform.hpp"
#include "../preview/studio_semantics.hpp"
#else
#include "diag_log.hpp"
#include "win32_dialog.hpp"
#endif
#include "toast_notification.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <dwmapi.h>
#endif
#include <fstream>
#include <filesystem>
#include <array>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>
#include <atomic>
#include <functional>
#include <thread>
#include <chrono>
#include <exception>
#include <utility>
#include <nlohmann/json.hpp>
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "blur.h"
#endif
#include "../assets/icons.h"
#include "../ide_icons.h"
#include "standalone_chat.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "standalone_license.hpp"
#include "anti-tamper/orchestrator.hpp"
#include "anti-tamper/webhook.hpp"
#endif
#include "standalone_settings.hpp"
#include "code_editor.hpp"
#include "disasm_view.hpp"
#include "cfg_view.hpp"
#include "hex_view.hpp"
#include "image_view.hpp"
#include "chat_render.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "standalone_driver.hpp"
#include "mcp_client.hpp"
#include "../core/auth/auth_browser_launch.hpp"
#include "sandbox.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "workspace_search.hpp"
#endif
#include "network_view.hpp"
#include "debugger_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "debugger_engine.hpp"
#endif
#include "spawn_target_dialog.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../core/session/session_health.hpp"
#include "run_target.hpp"
#endif
#include "pseudocode_view.hpp"
#include "scan_hub_view.hpp"
#include "types_hub_view.hpp"
#include "analysis_hub_view.hpp"
#include "source_reconstruct_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../core/infra/executor.hpp"
#include "../core/infra/taskflow_runtime.hpp"
#include "../core/ui/ui_thread_dispatcher.hpp"
#endif
#include "../core/workbench/workbench_shell_integration.hpp"
#include "binary_map_view.hpp"
#include "functions_panel.hpp"
#include "xref_db_view.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "function_index.hpp"
#include "xref_index.hpp"
#include "xref_db.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../core/testlab/test_lab_view.hpp"
#include "../core/testlab/test_all_features.hpp"
#include "../core/testlab/test_all_ui.h"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../core/network/burp/camoufox_bridge.hpp"
#endif
#include "ui_anim.hpp"
#include "agent_picker_view.hpp"
#include "mcp_marketplace_view.hpp"
#include "initial_analysis.hpp"
#include "initial_analysis_view.hpp"
#include "loading_binary_overlay.hpp"
#include "analysis_session.hpp"
#include "empty_state.hpp"
#include "../core/ui/ide_shell.hpp"
#include "../core/ui/workspace_layout.hpp"
#include "../core/ui/application_ui_runtime.hpp"
#include "../core/ui/application_view_registry.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../preview/shell_preview.hpp"
#endif
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <shared_mutex>

render_section_state_t            g_render_section;

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
namespace test_all_features {
	void format_ui_phase_snapshot(char* out, std::size_t cap);
}
#endif

namespace {
	bool shell_full_test_running()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		return false;
#else
		return test_all_features::is_running();
#endif
	}

	void format_shell_ui_phase_snapshot(char* out, std::size_t cap)
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (out && cap > 0)
			out[0] = '\0';
#else
		test_all_features::format_ui_phase_snapshot(out, cap);
#endif
	}


#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::atomic<bool>          g_settings_dirty{false};
	std::condition_variable    g_settings_cv;
	std::mutex                 g_settings_cv_mtx;
	std::atomic<bool>          g_settings_saver_running{false};
	std::atomic<bool>          g_settings_saver_started{false};
	std::atomic<bool>          g_chrome_shutdown_requested{false};

	aida::infra::executor::submit_result_t submit_helpers_executor_task(
		const char* owner_subsystem,
		const char* label,
		aida::infra::executor::domain_t domain,
		const char* thread_class,
		std::function<void()> body,
		int priority = 3)
	{
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = owner_subsystem;
		sub.label = label;
		sub.thread_class = thread_class;
		sub.domain = domain;
		sub.priority = priority;
		sub.body = std::move(body);
		return aida::infra::executor::submit(std::move(sub));
	}

	void settings_saver_loop()
	{
		while (g_settings_saver_running.load()) {
			std::unique_lock<std::mutex> lk(g_settings_cv_mtx);
			g_settings_cv.wait_for(lk, std::chrono::milliseconds(500), [] {
				return g_settings_dirty.load() || !g_settings_saver_running.load();
			});
			lk.unlock();
			if (!g_settings_saver_running.load()) break;
			if (g_settings_dirty.exchange(false)) {
				try {
					g_sa_settings.save();
				} catch (...) {
				}
			}
		}
	}
#endif

	void g_sa_settings_request_save()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::record(aida::preview::shell_action_t::save_file, "settings");
#else
		g_settings_dirty.store(true);
		bool expected = false;
		if (g_settings_saver_started.compare_exchange_strong(expected, true)) {
			g_settings_saver_running.store(true);
			const auto submit_result = submit_helpers_executor_task(
				"settings",
				"settings.saver_loop",
				aida::infra::executor::domain_t::service,
				"long_lived_service",
				[]() { settings_saver_loop(); });
			if (!submit_result.submitted) {
				g_settings_saver_running.store(false);
				g_settings_saver_started.store(false);
			}
		}
		g_settings_cv.notify_one();
#endif
	}

	void log_license_screen_breadcrumb(const char* event, float window_w, float window_h, bool runtime_ready, bool runtime_locked)
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		(void)event;
		(void)window_w;
		(void)window_h;
		(void)runtime_ready;
		(void)runtime_locked;
#else
		const std::string run_id = standalone_license::run_correlation_id();
		const std::string runtime_snapshot = standalone_license::runtime_state_snapshot();
		auto dyn = driver_bridge::dynamic_ioctl_state();
		auto taskflow_snapshot = aida::infra::taskflow_runtime::active_snapshot(64);
		DWORD qs = ::GetQueueStatus(QS_ALLINPUT);
		DWORD qs_changed = LOWORD(qs);
		DWORD qs_current = HIWORD(qs);
		RECT wr{};
		BOOL rect_ok = g_hwnd ? ::GetWindowRect(g_hwnd, &wr) : FALSE;
		DWORD rect_gle = rect_ok ? ERROR_SUCCESS : ::GetLastError();
		const bool activation_worker_active = license::activation_worker_active.load(std::memory_order_acquire);
		const bool arc_transfer_active = standalone_license::is_arc_transfer_in_progress();
		const bool activation_progress_active = license::checking && (activation_worker_active || arc_transfer_active);
		const bool full_test_running = test_all_features::is_running();
		std::string driver_status = driver_bridge::status();
		const char* breadcrumb_event = event ? event : "license_screen_frame_health";
		diag::log_tagged_critical_fmt("license",
			"%s run_id=%s frame=%d tick=%llu tid=%lu runtime_ready=%d runtime_locked=%d validated=%d canonical_valid=%d checking=%d check_failed=%d activation_worker=%d activation_progress=%d activation_phase=%d arc_loaded=%d arc_download=%d arc_transfer=%d full_test=%d key_len=%zu window=%.0fx%.0f hwnd=0x%llX visible=%d enabled=%d iconic=%d rect_ok=%d rect=%ld,%ld,%ld,%ld rect_gle=%lu fg=0x%llX active=0x%llX focus=0x%llX capture=0x%llX qs=0x%08lX qs_changed=0x%04lX qs_current=0x%04lX want_text=%d render_section=%s driver_loaded=%d driver_kernel=%d driver_connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X attached_pid=%u driver_status=%.120s runtime={%.520s}",
			breadcrumb_event,
			run_id.c_str(),
			ImGui::GetFrameCount(),
			static_cast<unsigned long long>(aida::shell_platform::tick_ms()),
			aida::shell_platform::thread_id(),
			runtime_ready ? 1 : 0,
			runtime_locked ? 1 : 0,
			license::validated ? 1 : 0,
			standalone_license::is_valid() ? 1 : 0,
			license::checking ? 1 : 0,
			license::check_failed ? 1 : 0,
			activation_worker_active ? 1 : 0,
			activation_progress_active ? 1 : 0,
			globals::ui::license_activation_phase.load(std::memory_order_acquire),
			standalone_license::is_arc_loaded() ? 1 : 0,
			standalone_license::is_arc_download_in_progress() ? 1 : 0,
			arc_transfer_active ? 1 : 0,
			full_test_running ? 1 : 0,
			std::strlen(license::key_buf),
			window_w,
			window_h,
			static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_hwnd)),
			(g_hwnd && ::IsWindowVisible(g_hwnd)) ? 1 : 0,
			(g_hwnd && ::IsWindowEnabled(g_hwnd)) ? 1 : 0,
			(g_hwnd && ::IsIconic(g_hwnd)) ? 1 : 0,
			rect_ok ? 1 : 0,
			rect_ok ? wr.left : 0,
			rect_ok ? wr.top : 0,
			rect_ok ? wr.right : 0,
			rect_ok ? wr.bottom : 0,
			static_cast<unsigned long>(rect_gle),
			static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(::GetForegroundWindow())),
			static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(::GetActiveWindow())),
			static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(::GetFocus())),
			static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(::GetCapture())),
			static_cast<unsigned long>(qs),
			static_cast<unsigned long>(qs_changed),
			static_cast<unsigned long>(qs_current),
			ImGui::GetIO().WantTextInput ? 1 : 0,
			g_render_section.c_str(),
			dyn.loaded ? 1 : 0,
			dyn.kernel ? 1 : 0,
			dyn.connected ? 1 : 0,
			dyn.ready ? 1 : 0,
			dyn.instance_server_seed,
			dyn.instance_ioctl_seed,
			dyn.global_server_seed,
			dyn.global_ioctl_seed,
			dyn.ioctl_seed_hash,
			dyn.heartbeat_ioctl_seed_hash,
			driver_bridge::attached_pid(),
			driver_status.c_str(),
			runtime_snapshot.c_str());
		diag::log_tagged_critical_fmt("license",
			"%s_taskflow run_id=%s frame=%d accepting=%d shutting_down=%d work_pending=%llu work_active=%u service_pending=%llu service_active=%u critical_pending=%llu critical_active=%u oldest_ms=%llu total_submitted=%llu total_rejected=%llu labels=%.520s",
			breadcrumb_event,
			run_id.c_str(),
			ImGui::GetFrameCount(),
			taskflow_snapshot.accepting ? 1 : 0,
			taskflow_snapshot.shutting_down ? 1 : 0,
			static_cast<unsigned long long>(taskflow_snapshot.work_queue_pending),
			static_cast<unsigned>(taskflow_snapshot.work_queue_active),
			static_cast<unsigned long long>(taskflow_snapshot.service_queue_pending),
			static_cast<unsigned>(taskflow_snapshot.service_queue_active),
			static_cast<unsigned long long>(taskflow_snapshot.critical_queue_pending),
			static_cast<unsigned>(taskflow_snapshot.critical_queue_active),
			static_cast<unsigned long long>(taskflow_snapshot.oldest_active_ms),
			static_cast<unsigned long long>(taskflow_snapshot.total_submitted),
			static_cast<unsigned long long>(taskflow_snapshot.total_rejected),
			taskflow_snapshot.labels_under_pressure.empty() ? "<none>" : taskflow_snapshot.labels_under_pressure.c_str());
#endif
	}

	void request_chrome_shutdown_from_render(const char* source, const char* cleanup_reason)
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		(void)cleanup_reason;
		aida::preview::record(aida::preview::shell_action_t::close_window, source ? source : "render");
#else
		HWND hwnd = g_hwnd;
		BOOL is_window = hwnd ? ::IsWindow(hwnd) : FALSE;
		bool already_requested = g_chrome_shutdown_requested.exchange(true, std::memory_order_acq_rel);
		POINT cursor{};
		::GetCursorPos(&cursor);
		diag::log_tagged_critical_fmt("chrome",
			"shutdown_request source=%s hwnd=0x%llX is_window=%d already=%d cursor=%ld,%ld tid=%lu section=%s",
			source ? source : "<null>",
			(unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
			is_window ? 1 : 0,
			already_requested ? 1 : 0,
			cursor.x,
			cursor.y,
			aida::shell_platform::thread_id(),
			g_render_section.c_str());
		if (already_requested) {
			return;
		}

		file_tabs::write_hot_exit_snapshot_all();
		try {
			test_all_features::cancel_tests();
			aida::burp::camoufox::force_cleanup(cleanup_reason ? cleanup_reason : "chrome.shutdown");
		} catch (...) {
			diag::log_tagged_critical_fmt("chrome",
				"shutdown_camoufox_cleanup_exception source=%s",
				source ? source : "<null>");
		}

		hwnd = g_hwnd;
		is_window = hwnd ? ::IsWindow(hwnd) : FALSE;
		if (hwnd && is_window) {
			::SetLastError(0);
			BOOL posted = ::PostMessageW(hwnd, WM_CLOSE, 0, 0);
			DWORD gle = ::GetLastError();
			diag::log_tagged_critical_fmt("chrome",
				"shutdown_post_wm_close source=%s hwnd=0x%llX ok=%d gle=%lu",
				source ? source : "<null>",
				(unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
				posted ? 1 : 0,
				(unsigned long)gle);
			if (posted) {
				return;
			}
		}

		diag::log_tagged_critical_fmt("chrome",
			"shutdown_post_quit_fallback source=%s hwnd=0x%llX is_window=%d",
			source ? source : "<null>",
			(unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
			is_window ? 1 : 0);
		::PostQuitMessage(0);
#endif
	}

	bool shell_left_mouse_down()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		return aida::preview::mouse_button_down(ImGuiMouseButton_Left);
#else
		return (GetAsyncKeyState(VK_LBUTTON) & 0x8000) && GetForegroundWindow() == g_hwnd;
#endif
	}

	void shell_toggle_maximize()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		globals::ui::maximized = !globals::ui::maximized;
		aida::preview::record(aida::preview::shell_action_t::toggle_maximize,
			globals::ui::maximized ? "maximized" : "restored");
#else
		if (::IsZoomed(g_hwnd))
			::PostMessageW(g_hwnd, WM_SYSCOMMAND, SC_RESTORE, 0);
		else
			::PostMessageW(g_hwnd, WM_SYSCOMMAND, SC_MAXIMIZE, 0);
#endif
	}

	void shell_minimize()
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::record(aida::preview::shell_action_t::minimize_window, "title_bar");
#else
		::PostMessageW(g_hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
#endif
	}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	void shell_move_window(int x, int y)
	{
		SetWindowPos(g_hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
	}
#endif

	const char* center_view_name(center_view_t view)
	{
		switch (view) {
			case center_view_t::code_editor: return "code_editor";
			case center_view_t::disassembly: return "disassembly";
			case center_view_t::hex_view: return "hex_view";
			case center_view_t::welcome: return "welcome";
			case center_view_t::settings_view: return "settings_view";
			case center_view_t::network_view: return "network_view";
			case center_view_t::memory_scanner: return "memory_scanner";
			case center_view_t::debugger_view: return "debugger_view";
			case center_view_t::pseudocode: return "pseudocode";
			case center_view_t::struct_recon: return "struct_recon";
			case center_view_t::crypto_scanner: return "crypto_scanner";
			case center_view_t::aob_generator: return "aob_generator";
			case center_view_t::fuzzer_view: return "fuzzer_view";
			case center_view_t::xref_browser: return "xref_browser";
			case center_view_t::snapshot_diff: return "snapshot_diff";
			case center_view_t::pointer_scanner: return "pointer_scanner";
			case center_view_t::decrypt_oracle: return "decrypt_oracle";
			case center_view_t::integrity_hunter: return "integrity_hunter";
			case center_view_t::symbolic_view: return "symbolic_view";
			case center_view_t::taint_view: return "taint_view";
			case center_view_t::deobfuscation_view: return "deobfuscation_view";
			case center_view_t::stealth_view: return "stealth_view";
			case center_view_t::scan_hub: return "scan_hub";
			case center_view_t::types_hub: return "types_hub";
			case center_view_t::analysis_hub: return "analysis_hub";
			case center_view_t::binary_map: return "binary_map";
			case center_view_t::graph_view: return "graph_view";
			case center_view_t::image_view: return "image_view";
			case center_view_t::test_lab: return "test_lab";
			case center_view_t::workbench: return "workbench";
			case center_view_t::functions_panel: return "functions_panel";
			case center_view_t::xref_database: return "xref_database";
		}
		return "unknown";
	}

	std::optional<aida::workbench::document_kind_t> workbench_document_kind(
		center_view_t view)
	{
		switch (view) {
			case center_view_t::disassembly:
				return aida::workbench::document_kind_t::disassembly;
			case center_view_t::hex_view:
				return aida::workbench::document_kind_t::hex;
			case center_view_t::pseudocode:
				return aida::workbench::document_kind_t::pseudocode;
			case center_view_t::graph_view:
				return aida::workbench::document_kind_t::graph;
			case center_view_t::snapshot_diff:
				return aida::workbench::document_kind_t::diff;
			default:
				return std::nullopt;
		}
	}

	void restore_workbench_center_view(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
	{
		static std::weak_ptr<aida::analysis::analysis_workspace_t> restored_workspace;
		const auto previous = restored_workspace.lock();
		if (!workspace) {
			restored_workspace.reset();
			return;
		}
		if (previous == workspace)
			return;
		aida::workbench::workbench_shell_workspace_context_t context;
		const auto restored =
			aida::workbench::workbench_shell_runtime_t::instance()
				.workspace_context(workspace, context);
		if (!restored) {
			static unsigned long long last_failure_ms = 0;
			const auto now_ms = aida::shell_platform::tick_ms();
			if (now_ms - last_failure_ms >= 5000ULL) {
				last_failure_ms = now_ms;
				diag::log_tagged_fmt(
					"workbench_shell",
					"ui_restore_deferred binary_id=%s code=%u subject=%llu",
					workspace->identity().binary_id().to_hex().c_str(),
					static_cast<unsigned>(restored.code),
					static_cast<unsigned long long>(restored.subject));
			}
			return;
		}
		restored_workspace = workspace;
		if (workspace->identity().target_kind() ==
			aida::analysis::target_kind_t::static_file)
			globals::ui::active_center_view = center_view_t::workbench;
	}

	class workbench_frame_cancellation_t final
		: public aida::workbench::disasm_document::disasm_cancellation_t,
		  public aida::workbench::hex_document::hex_cancellation_t,
		  public aida::workbench::graph_document::graph_layout_cancellation_t,
		  public aida::workbench::diff_document::diff_cancellation_t,
		  public aida::workbench::navigator::navigator_cancellation_t
	{
	public:
		explicit workbench_frame_cancellation_t(std::uint32_t budget_ms)
			: deadline_(std::chrono::steady_clock::now() +
				std::chrono::milliseconds(budget_ms)) {}

		bool cancelled() const noexcept override
		{
			return std::chrono::steady_clock::now() >= deadline_;
		}

	private:
		std::chrono::steady_clock::time_point deadline_;
	};

	struct workbench_ui_state_t final {
		aida::workbench::navigator::navigator_domain_t navigator_domain =
			aida::workbench::navigator::navigator_domain_t::functions;
		std::uint64_t disassembly_offset = 0;
		std::uint64_t hex_offset = 0;
		std::uint64_t diff_offset = 0;
		std::uint64_t diff_total = 0;
		std::uint64_t last_address = 0;
		std::string last_entity_locator;
		std::string pseudocode_identity;
		std::optional<aida::workbench::pseudocode_document::
			pseudocode_request_t> pseudocode_request;
		aida::workbench::graph_document::graph_kind_t graph_kind =
			aida::workbench::graph_document::graph_kind_t::cfg;
		aida::workbench::graph_document::graph_layout_t graph_layout;
		std::uint64_t graph_layout_function_address = 0;
		aida::workbench::diff_document::diff_kind_t diff_kind =
			aida::workbench::diff_document::diff_kind_t::generation;
		aida::analysis::decompiler_profile_id_t pseudocode_profile =
			aida::analysis::decompiler_profile_id_t::balanced;
		std::uint64_t observed_generation = 0;
		std::uint64_t last_touch = 0;
		std::string status;
	};

	workbench_ui_state_t& workbench_ui_state(
		aida::workbench::workspace_id_t workspace)
	{
		static std::map<std::uint64_t, workbench_ui_state_t> states;
		static std::uint64_t touch = 0;
		if (++touch == 0)
			touch = 1;
		auto found = states.find(workspace.value);
		if (found == states.end()) {
			if (states.size() >= 64) {
				const auto oldest = std::min_element(
					states.begin(), states.end(), [](const auto& lhs, const auto& rhs) {
						return lhs.second.last_touch < rhs.second.last_touch;
					});
				if (oldest != states.end())
					states.erase(oldest);
			}
			found = states.try_emplace(workspace.value).first;
		}
		found->second.last_touch = touch;
		return found->second;
	}

	const aida::workbench::document_persistence_dto_t*
	workbench_document(const aida::workbench::workbench_persistence_dto_t& state,
		aida::workbench::document_id_t document)
	{
		const auto found = std::find_if(state.documents.begin(), state.documents.end(),
			[document](const auto& candidate) { return candidate.id == document; });
		return found == state.documents.end() ? nullptr : &*found;
	}

	void render_workbench_disassembly(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		aida::workbench::workbench_shell_workspace_context_t& context,
		workbench_ui_state_t& state)
	{
		if (!context.disassembly_document) {
			ImGui::TextDisabled("Disassembly provider unavailable");
			return;
		}
		const auto total_rows = context.disassembly_document->total_rows();
		if (ImGui::SmallButton("Previous##wb_disasm"))
			state.disassembly_offset = state.disassembly_offset > 256
				? state.disassembly_offset - 256 : 0;
		ImGui::SameLine();
		if (ImGui::SmallButton("Next##wb_disasm"))
			state.disassembly_offset = total_rows > 256U
				? (std::min)(state.disassembly_offset + 256U,
					total_rows - 256U) : 0;
		ImGui::SameLine();
		ImGui::TextDisabled("generation %llu", static_cast<unsigned long long>(
			context.analysis_generation));
		aida::workbench::disasm_document::disasm_page_t page;
		workbench_frame_cancellation_t cancellation(20);
		const auto error = context.disassembly_document->page(
			{state.disassembly_offset, 256}, &cancellation, page);
		if (!error) {
			ImGui::TextDisabled("Disassembly unavailable (%u)",
				static_cast<unsigned>(error.code));
			return;
		}
		if (page.offset != state.disassembly_offset)
			state.disassembly_offset = page.offset;
		for (const auto& row : page.rows) {
			char label[1024];
			_snprintf_s(label, sizeof(label), _TRUNCATE,
				"%016llX  %-10s %s%s%s##wb_disasm_%llu",
				static_cast<unsigned long long>(row.address), row.mnemonic.c_str(),
				row.operands.c_str(), row.overlay ? "  ; " : "",
				row.overlay ? row.overlay->text.c_str() : "",
				static_cast<unsigned long long>(row.id.value));
			const bool selected = state.last_address == row.address;
			if (!ImGui::Selectable(label, selected))
				continue;
			state.last_address = row.address;
			state.last_entity_locator.clear();
			aida::workbench::selection_context_t selection;
			selection.kind = aida::workbench::selection_kind_t::address;
			selection.has_address = true;
			selection.address = row.address;
			selection.extent = row.byte_size;
			aida::workbench::document_local_cursor_t cursor;
			cursor.has_position = true;
			cursor.position = row.address;
			static_cast<void>(
				aida::workbench::workbench_shell_runtime_t::instance()
					.navigate_document(workspace,
						aida::workbench::document_kind_t::disassembly,
						std::nullopt, selection, cursor, context));
		}
	}

	void render_workbench_hex(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		aida::workbench::workbench_shell_workspace_context_t& context,
		workbench_ui_state_t& state)
	{
		if (!context.hex_document) {
			ImGui::TextDisabled("Hex provider unavailable");
			return;
		}
		const auto total_rows = context.hex_document->total_rows();
		if (ImGui::SmallButton("Previous##wb_hex"))
			state.hex_offset = state.hex_offset > 256 ? state.hex_offset - 256 : 0;
		ImGui::SameLine();
		if (ImGui::SmallButton("Next##wb_hex"))
			state.hex_offset = total_rows > 256U
				? (std::min)(state.hex_offset + 256U, total_rows - 256U) : 0;
		aida::workbench::hex_document::hex_page_t page;
		workbench_frame_cancellation_t cancellation(20);
		const auto error = context.hex_document->page(
			{state.hex_offset, 256}, &cancellation, page);
		if (!error) {
			ImGui::TextDisabled("Hex unavailable (%u)",
				static_cast<unsigned>(error.code));
			return;
		}
		if (page.offset != state.hex_offset)
			state.hex_offset = page.offset;
		for (const auto& row : page.rows) {
			char label[2048];
			_snprintf_s(label, sizeof(label), _TRUNCATE,
				"%016llX  %-48s  %s##wb_hex_%llu",
				static_cast<unsigned long long>(row.address), row.hex_text.c_str(),
				row.ascii_text.c_str(),
				static_cast<unsigned long long>(row.id.value));
			if (!ImGui::Selectable(label, state.last_address == row.address))
				continue;
			state.last_address = row.address;
			state.last_entity_locator.clear();
			aida::workbench::selection_context_t selection;
			selection.kind = aida::workbench::selection_kind_t::range;
			selection.has_address = true;
			selection.address = row.address;
			selection.extent = row.byte_count;
			aida::workbench::document_local_cursor_t cursor;
			cursor.has_position = true;
			cursor.position = row.address;
			static_cast<void>(
				aida::workbench::workbench_shell_runtime_t::instance()
					.navigate_document(workspace,
						aida::workbench::document_kind_t::hex,
						std::nullopt, selection, cursor, context));
		}
	}

	void render_workbench_pseudocode(
		aida::workbench::workbench_shell_workspace_context_t& context,
		workbench_ui_state_t& state)
	{
		auto* model = context.pseudocode_document;
		if (!model) {
			ImGui::TextDisabled("Typed pseudocode provider unavailable");
			return;
		}
		if (ImGui::SmallButton("Fast##wb_psv"))
			state.pseudocode_profile = aida::analysis::decompiler_profile_id_t::fast;
		ImGui::SameLine();
		if (ImGui::SmallButton("Balanced##wb_psv"))
			state.pseudocode_profile = aida::analysis::decompiler_profile_id_t::balanced;
		ImGui::SameLine();
		if (ImGui::SmallButton("Thorough##wb_psv"))
			state.pseudocode_profile = aida::analysis::decompiler_profile_id_t::thorough;
		ImGui::SameLine();
		const bool can_request =
			(state.last_address != 0 || !state.last_entity_locator.empty()) &&
			!model->has_pending_requests();
		ImGui::BeginDisabled(!can_request);
		if (ImGui::SmallButton("Decompile (F5)##wb_psv")) {
			aida::workbench::pseudocode_document::pseudocode_request_t request;
			aida::workbench::pseudocode_document::pseudocode_error_t resolved;
			if (!state.last_entity_locator.empty()) {
				const auto locator =
					aida::workbench::pseudocode_document::
						parse_pseudocode_entity_locator(
							state.last_entity_locator);
				resolved = locator
					? model->resolve_request(*locator, state.pseudocode_profile,
						aida::workbench::pseudocode_document::
							k_pseudocode_document_default_timeout_ms, request)
					: aida::workbench::pseudocode_document::pseudocode_error_t{
						aida::workbench::pseudocode_document::
							pseudocode_error_code_t::invalid_argument, 0};
			} else {
				resolved = model->resolve_request(
					state.last_address, state.pseudocode_profile,
					aida::workbench::pseudocode_document::
						k_pseudocode_document_default_timeout_ms, request);
			}
			const auto requested = resolved ? model->request(request) : resolved;
			if (requested || requested.code ==
				aida::workbench::pseudocode_document::
					pseudocode_error_code_t::request_in_progress)
				state.pseudocode_request = request;
			else
				state.status = "Decompiler request rejected (" +
					std::to_string(static_cast<unsigned>(requested.code)) + ")";
		}
		ImGui::EndDisabled();
		const auto* cached = state.pseudocode_request
			? model->cached_document(*state.pseudocode_request)
			: model->cached_document();
		if (cached && cached->state ==
			aida::workbench::pseudocode_document::pseudocode_cache_state_t::requesting) {
			static_cast<void>(model->poll(cached->job_id));
			cached = state.pseudocode_request
				? model->cached_document(*state.pseudocode_request)
				: model->cached_document();
		}
		if (model->has_pending_requests() && cached) {
			ImGui::SameLine();
			if (ImGui::SmallButton("Cancel##wb_psv"))
				static_cast<void>(model->cancel(cached->job_id));
		}
		if (!state.status.empty())
			ImGui::TextDisabled("%s", state.status.c_str());
		aida::workbench::pseudocode_document::pseudocode_page_t page;
		const auto error = model->page({0, 1024}, page);
		if (!error) {
			const auto diagnostics = model->diagnostics();
			for (const auto& diagnostic : diagnostics)
				ImGui::TextWrapped("%s", diagnostic.message.c_str());
			if (diagnostics.empty())
				ImGui::TextDisabled("Select an address and request decompilation explicitly.");
			return;
		}
		for (const auto& line : page.lines) {
			char id[64];
			_snprintf_s(id, sizeof(id), _TRUNCATE, "##wb_psv_%u", line.line_number);
			ImGui::Selectable((line.text + id).c_str(), false);
		}
	}

	void render_workbench_graph(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		aida::workbench::workbench_shell_workspace_context_t& context,
		workbench_ui_state_t& state, float width, float height)
	{
		auto* model = context.graph_document;
		if (!model) {
			ImGui::TextDisabled("Graph provider unavailable");
			return;
		}
		if (ImGui::SmallButton("CFG##wb_graph")) {
			state.graph_kind = aida::workbench::graph_document::graph_kind_t::cfg;
			state.graph_layout = {};
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Call graph##wb_graph")) {
			state.graph_kind = aida::workbench::graph_document::graph_kind_t::call_graph;
			state.graph_layout = {};
		}
		ImGui::SameLine();
		const bool reusable_layout_scope = state.graph_layout.complete &&
			state.graph_layout.snapshot_generation == context.analysis_generation &&
			state.graph_layout.graph_kind == state.graph_kind;
		const auto graph_function_address = state.graph_kind ==
			aida::workbench::graph_document::graph_kind_t::cfg
			? (reusable_layout_scope
				? state.graph_layout_function_address : state.last_address)
			: 0;
		if (ImGui::SmallButton("Layout##wb_graph")) {
			aida::workbench::graph_document::graph_layout_request_t request;
			request.expected_generation = context.analysis_generation;
			request.graph_kind = state.graph_kind;
			request.function_address = graph_function_address;
			request.max_nodes =
				aida::workbench::graph_document::k_graph_document_max_page_size;
			request.max_edges = 8192;
			request.max_iterations = 256;
			request.canvas_width = (std::max)(width, 320.0f);
			request.canvas_height = (std::max)(height - 48.0f, 200.0f);
			workbench_frame_cancellation_t cancellation(40);
			aida::workbench::graph_document::graph_layout_t layout;
			const auto error = model->compute_layout(
				request, &cancellation, layout);
			if (!error) {
				state.graph_layout = {};
				state.status = "Graph layout deferred (" +
					std::to_string(static_cast<unsigned>(error.code)) + ")";
			} else {
				state.graph_layout = std::move(layout);
				state.graph_layout_function_address = graph_function_address;
				state.status.clear();
			}
		}
		const bool layout_current = state.graph_layout.complete &&
			state.graph_layout.snapshot_generation == context.analysis_generation &&
			state.graph_layout.graph_kind == state.graph_kind &&
			state.graph_layout_function_address == graph_function_address;
		aida::workbench::graph_document::graph_page_request_t request;
		request.limit = layout_current
			? aida::workbench::graph_document::k_graph_document_max_page_size
			: 256;
		request.graph_kind = state.graph_kind;
		request.function_address = graph_function_address;
		workbench_frame_cancellation_t cancellation(25);
		aida::workbench::graph_document::graph_page_t page;
		const auto error = model->page(request, &cancellation, page);
		if (!error) {
			ImGui::TextDisabled("Graph materialization deferred (%u)",
				static_cast<unsigned>(error.code));
			return;
		}
		auto navigate = [&](const aida::workbench::graph_document::graph_node_view_t& node) {
			state.last_address = node.address;
			state.last_entity_locator.clear();
			aida::workbench::selection_context_t selection;
			selection.kind = aida::workbench::selection_kind_t::address;
			selection.has_address = true;
			selection.address = node.address;
			selection.entity_key = std::to_string(node.id.value);
			aida::workbench::document_local_cursor_t cursor;
			cursor.has_position = true;
			cursor.position = node.address;
			static_cast<void>(
				aida::workbench::workbench_shell_runtime_t::instance()
					.navigate_document(workspace,
						aida::workbench::document_kind_t::graph,
						std::nullopt, selection, cursor, context));
		};
		if (layout_current && page.total_items <=
			aida::workbench::graph_document::k_graph_document_max_page_size) {
			std::unordered_map<std::uint64_t,
				const aida::workbench::graph_document::graph_node_view_t*> nodes;
			nodes.reserve(page.nodes.size());
			for (const auto& node : page.nodes)
				nodes.emplace(node.id.value, &node);
			std::unordered_map<std::uint64_t,
				const aida::workbench::graph_document::graph_layout_node_t*> positions;
			positions.reserve(state.graph_layout.nodes.size());
			for (const auto& node : state.graph_layout.nodes)
				positions.emplace(node.id.value, &node);
			const auto available = ImGui::GetContentRegionAvail();
			const ImVec2 canvas_size(
				(std::max)(available.x, 1.0f),
				(std::max)(available.y, 1.0f));
			const auto origin = ImGui::GetCursorScreenPos();
			ImGui::InvisibleButton("##wb_graph_canvas", canvas_size);
			auto* draw = ImGui::GetWindowDrawList();
			const auto edge_color = ImGui::GetColorU32(ImGuiCol_Separator);
			for (const auto& edge : state.graph_layout.edges) {
				const auto source = positions.find(edge.source.value);
				const auto target = positions.find(edge.target.value);
				if (source == positions.end() || target == positions.end())
					continue;
				ImVec2 previous(
					origin.x + source->second->x + source->second->width * 0.5f,
					origin.y + source->second->y + source->second->height * 0.5f);
				const auto bends = (std::min)(edge.bend_x.size(), edge.bend_y.size());
				for (std::size_t index = 0; index < bends; ++index) {
					const ImVec2 bend(origin.x + edge.bend_x[index],
						origin.y + edge.bend_y[index]);
					draw->AddLine(previous, bend, edge_color, 1.5f);
					previous = bend;
				}
				const ImVec2 endpoint(
					origin.x + target->second->x + target->second->width * 0.5f,
					origin.y + target->second->y + target->second->height * 0.5f);
				draw->AddLine(previous, endpoint, edge_color, 1.5f);
			}
			const auto mouse = ImGui::GetMousePos();
			const bool clicked = ImGui::IsItemHovered() &&
				ImGui::IsMouseClicked(ImGuiMouseButton_Left);
			const auto normal_color = ImGui::GetColorU32(ImGuiCol_FrameBg);
			const auto selected_color = ImGui::GetColorU32(ImGuiCol_HeaderActive);
			const auto border_color = ImGui::GetColorU32(ImGuiCol_Border);
			const auto text_color = ImGui::GetColorU32(ImGuiCol_Text);
			const aida::workbench::graph_document::graph_node_view_t* clicked_node = nullptr;
			for (const auto& layout_node : state.graph_layout.nodes) {
				const auto view = nodes.find(layout_node.id.value);
				if (view == nodes.end())
					continue;
				const ImVec2 minimum(origin.x + layout_node.x,
					origin.y + layout_node.y);
				const ImVec2 maximum(minimum.x + layout_node.width,
					minimum.y + layout_node.height);
				draw->AddRectFilled(minimum, maximum,
					state.last_address == view->second->address
						? selected_color : normal_color, 4.0f);
				draw->AddRect(minimum, maximum, border_color, 4.0f);
				auto label = view->second->label;
				if (label.size() > 24)
					label.resize(24);
				draw->AddText(ImVec2(minimum.x + 6.0f, minimum.y + 6.0f),
					text_color, label.c_str());
				if (clicked && mouse.x >= minimum.x && mouse.x < maximum.x &&
					mouse.y >= minimum.y && mouse.y < maximum.y)
					clicked_node = view->second;
			}
			if (clicked_node)
				navigate(*clicked_node);
			return;
		}
		for (const auto& node : page.nodes) {
			char label[1024];
			_snprintf_s(label, sizeof(label), _TRUNCATE,
				"%016llX  %s  in:%u out:%u##wb_graph_%llu",
				static_cast<unsigned long long>(node.address), node.label.c_str(),
				node.in_degree, node.out_degree,
				static_cast<unsigned long long>(node.id.value));
			if (!ImGui::Selectable(label, state.last_address == node.address))
				continue;
			navigate(node);
		}
	}

	bool workbench_diff_scope(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		const aida::workbench::workbench_shell_workspace_context_t& context,
		aida::workbench::diff_document::diff_kind_t kind,
		aida::workbench::diff_document::diff_scope_t& scope)
	{
		scope = {};
		scope.kind = kind;
		scope.before.workspace_id = context.workspace.value;
		scope.after.workspace_id = context.workspace.value;
		scope.before.generation = context.analysis_generation;
		scope.after.generation = context.analysis_generation;
		if (kind == aida::workbench::diff_document::diff_kind_t::generation) {
			if (context.analysis_generation < 2)
				return false;
			scope.before.generation = context.analysis_generation - 1U;
			return true;
		}
		if (kind == aida::workbench::diff_document::diff_kind_t::overlay) {
			if (context.overlay_revision == 0)
				return false;
			scope.before.overlay_revision = context.overlay_revision - 1U;
			scope.after.overlay_revision = context.overlay_revision;
			return true;
		}
		const auto workspaces =
			aida::workbench::workbench_shell_runtime_t::instance()
				.analysis_workspaces();
		for (const auto& other : workspaces) {
			if (!other || other == workspace)
				continue;
			aida::workbench::workbench_shell_workspace_context_t other_context;
			const auto loaded =
				aida::workbench::workbench_shell_runtime_t::instance()
					.workspace_context(other, other_context);
			if (!loaded)
				continue;
			scope.after.workspace_id = other_context.workspace.value;
			scope.after.generation = other_context.analysis_generation;
			return true;
		}
		return false;
	}

	void render_workbench_diff(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		aida::workbench::workbench_shell_workspace_context_t& context,
		workbench_ui_state_t& state)
	{
		auto* model = context.diff_document;
		if (!model) {
			ImGui::TextDisabled("Diff provider unavailable");
			return;
		}
		if (ImGui::SmallButton("Generation##wb_diff"))
			state.diff_kind = aida::workbench::diff_document::diff_kind_t::generation;
		ImGui::SameLine();
		if (ImGui::SmallButton("Overlay##wb_diff"))
			state.diff_kind = aida::workbench::diff_document::diff_kind_t::overlay;
		ImGui::SameLine();
		if (ImGui::SmallButton("Workspace##wb_diff"))
			state.diff_kind = aida::workbench::diff_document::diff_kind_t::workspace;
		aida::workbench::diff_document::diff_scope_t scope;
		if (!workbench_diff_scope(workspace, context, state.diff_kind, scope)) {
			ImGui::TextDisabled("The selected diff requires another retained generation, overlay revision, or workspace.");
			return;
		}
		if (ImGui::SmallButton("Previous##wb_diff"))
			state.diff_offset = state.diff_offset > 256 ? state.diff_offset - 256 : 0;
		ImGui::SameLine();
		if (ImGui::SmallButton("Next##wb_diff"))
			state.diff_offset = state.diff_total > 256U
				? (std::min)(state.diff_offset + 256U,
					state.diff_total - 256U) : 0;
		aida::workbench::diff_document::diff_page_t page;
		workbench_frame_cancellation_t cancellation(30);
		const auto error = model->page({state.diff_offset, 256,
			static_cast<aida::workbench::diff_document::diff_domain_t>(0xFF)},
			context.analysis_generation, scope, &cancellation, page);
		if (!error) {
			ImGui::TextDisabled("Diff materialization deferred (%u)",
				static_cast<unsigned>(error.code));
			return;
		}
		state.diff_total = page.total_entries;
		for (std::size_t index = 0; index < page.entries.size(); ++index) {
			const auto& entry = page.entries[index];
			char label[2048];
			_snprintf_s(label, sizeof(label), _TRUNCATE,
				"%016llX  %s  %s -> %s##wb_diff_%llu",
				static_cast<unsigned long long>(entry.address),
				entry.entity_key.c_str(), entry.old_value.c_str(),
				entry.new_value.c_str(),
				static_cast<unsigned long long>(page.offset + index));
			if (!ImGui::Selectable(label, state.last_address == entry.address))
				continue;
			state.last_address = entry.address;
			state.last_entity_locator.clear();
			if (entry.address == 0)
				continue;
			aida::workbench::selection_context_t selection;
			selection.kind = aida::workbench::selection_kind_t::address;
			selection.has_address = true;
			selection.address = entry.address;
			selection.entity_key = entry.entity_key;
			aida::workbench::document_local_cursor_t cursor;
			cursor.has_position = true;
			cursor.position = page.offset + index;
			static_cast<void>(
				aida::workbench::workbench_shell_runtime_t::instance()
					.navigate_document(workspace,
						aida::workbench::document_kind_t::diff,
						std::nullopt, selection, cursor, context));
		}
	}

	void render_workbench_document(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		aida::workbench::workbench_shell_workspace_context_t& context,
		const aida::workbench::document_persistence_dto_t& document,
		workbench_ui_state_t& state, float width, float height)
	{
		if (document.local_state.selection.has_address) {
			state.last_address = document.local_state.selection.address;
			state.last_entity_locator.clear();
		} else if (document.identity.kind ==
				aida::workbench::document_kind_t::pseudocode &&
			document.identity.has_address) {
			state.last_address = document.identity.address;
			state.last_entity_locator.clear();
		} else if (document.identity.kind ==
				aida::workbench::document_kind_t::pseudocode) {
			const auto& encoded = document.identity.provider_key != "analysis"
				? document.identity.provider_key
				: document.local_state.selection.entity_key;
			const auto locator =
				aida::workbench::pseudocode_document::
					parse_pseudocode_entity_locator(encoded);
			const auto canonical = locator
				? aida::workbench::pseudocode_document::
					canonical_pseudocode_entity_locator(*locator)
				: std::nullopt;
			if (canonical && *canonical == encoded) {
				state.last_address = 0;
				state.last_entity_locator = *canonical;
			}
		}
		if (document.identity.kind ==
				aida::workbench::document_kind_t::pseudocode) {
			const std::string identity = !state.last_entity_locator.empty()
				? state.last_entity_locator
				: "native:" + std::to_string(state.last_address);
			if (state.pseudocode_identity != identity) {
				state.pseudocode_identity = identity;
				state.pseudocode_request.reset();
			}
		}
		switch (document.identity.kind) {
		case aida::workbench::document_kind_t::disassembly:
			render_workbench_disassembly(workspace, context, state);
			break;
		case aida::workbench::document_kind_t::hex:
			render_workbench_hex(workspace, context, state);
			break;
		case aida::workbench::document_kind_t::pseudocode:
			render_workbench_pseudocode(context, state);
			break;
		case aida::workbench::document_kind_t::graph:
			render_workbench_graph(workspace, context, state, width, height);
			break;
		case aida::workbench::document_kind_t::diff:
			render_workbench_diff(workspace, context, state);
			break;
		default:
			ImGui::TextDisabled("Document provider is not available for this kind.");
			break;
		}
	}

	void render_workbench_navigator(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		aida::workbench::workbench_shell_workspace_context_t& context,
		workbench_ui_state_t& state)
	{
		using domain_t = aida::workbench::navigator::navigator_domain_t;
		const std::array<std::pair<const char*, domain_t>, 6> domains{{
			{"Functions", domain_t::functions}, {"Imports", domain_t::imports},
			{"Exports", domain_t::exports}, {"Strings", domain_t::strings},
			{"Symbols", domain_t::symbols}, {"Types", domain_t::types}}};
		for (std::size_t index = 0; index < domains.size(); ++index) {
			if (index != 0)
				ImGui::SameLine();
			if (ImGui::SmallButton((std::string(domains[index].first) +
				"##wb_nav_domain").c_str()))
				state.navigator_domain = domains[index].second;
		}
		if (!context.navigator_tree) {
			ImGui::TextDisabled("Navigator provider unavailable");
			return;
		}
		aida::workbench::navigator::navigator_tree_request_t request;
		request.domain = state.navigator_domain;
		request.page.limit = 256;
		workbench_frame_cancellation_t cancellation(20);
		aida::workbench::navigator::navigator_tree_page_t page;
		const auto error = context.navigator_tree->page(request, &cancellation, page);
		if (!error) {
			ImGui::TextDisabled("Navigator deferred (%u)",
				static_cast<unsigned>(error.code));
			return;
		}
		for (const auto& row : page.rows) {
			const auto label = std::string(row.label) + "##wb_nav_" +
				std::to_string(row.id.value);
			if (!ImGui::Selectable(label.c_str(),
				row.has_address && state.last_address == row.address))
				continue;
			if (!row.has_address)
				continue;
			state.last_address = row.address;
			state.last_entity_locator.clear();
			aida::workbench::selection_context_t selection;
			selection.kind = aida::workbench::selection_kind_t::address;
			selection.has_address = true;
			selection.address = row.address;
			selection.entity_key = std::to_string(row.id.value);
			aida::workbench::document_local_cursor_t cursor;
			cursor.has_position = true;
			cursor.position = row.address;
			static_cast<void>(
				aida::workbench::workbench_shell_runtime_t::instance()
					.navigate_document(workspace,
						aida::workbench::document_kind_t::disassembly,
						std::nullopt, selection, cursor, context));
		}
	}

	void render_workbench_inspector(
		const aida::workbench::workbench_shell_workspace_context_t& context)
	{
		ImGui::TextUnformatted("Inspector");
		ImGui::Separator();
		ImGui::Text("Generation: %llu", static_cast<unsigned long long>(
			context.analysis_generation));
		ImGui::Text("Analysis revision: %llu", static_cast<unsigned long long>(
			context.analysis_revision));
		ImGui::Text("Overlay revision: %llu", static_cast<unsigned long long>(
			context.overlay_revision));
		const auto* active = context.inspector_session
			? context.inspector_session->active_context() : nullptr;
		if (!active) {
			ImGui::TextDisabled("No synchronized selection");
			return;
		}
		ImGui::Separator();
		ImGui::Text("Document kind: %u", static_cast<unsigned>(
			active->document.kind));
		if (active->selection.has_address)
			ImGui::Text("Address: 0x%llX", static_cast<unsigned long long>(
				active->selection.address));
		if (!active->selection.entity_key.empty())
			ImGui::TextWrapped("Entity: %s", active->selection.entity_key.c_str());
		static const char* panels[] = {"Identity", "Bytes", "Operands", "Xrefs",
			"Calls", "Stack/locals", "Types", "Overlays", "Diagnostics",
			"Source provenance"};
		ImGui::Separator();
		for (const auto* panel : panels)
			ImGui::BulletText("%s", panel);
	}

	void render_analysis_workbench(
		const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
		float width, float height)
	{
		if (!workspace) {
			ImGui::TextDisabled("No analysis workspace is active");
			return;
		}
		aida::workbench::workbench_shell_workspace_context_t context;
		const auto loaded =
			aida::workbench::workbench_shell_runtime_t::instance()
				.workspace_context(workspace, context);
		if (!loaded || !context.document_host) {
			ImGui::TextDisabled("Workbench unavailable (%u)",
				static_cast<unsigned>(loaded.code));
			return;
		}
		auto& state = workbench_ui_state(context.workspace);
		if (state.observed_generation != context.analysis_generation) {
			state.disassembly_offset = 0;
			state.hex_offset = 0;
			state.diff_offset = 0;
			state.diff_total = 0;
			state.graph_layout = {};
			state.graph_layout_function_address = 0;
			state.status.clear();
			state.observed_generation = context.analysis_generation;
		}
		aida::workbench::document_host::document_host_layout_request_t request;
		request.client_extent.width_pixels = static_cast<std::uint32_t>(
			(std::max)(1.0f, width));
		request.client_extent.height_pixels = static_cast<std::uint32_t>(
			(std::max)(1.0f, height));
		request.dpi = static_cast<std::uint32_t>((std::clamp)(
			96.0f * ImGui::GetIO().DisplayFramebufferScale.x, 48.0f, 768.0f));
		request.average_character_width_pixels = static_cast<std::uint32_t>(
			(std::clamp)(ImGui::CalcTextSize("M").x, 4.0f, 64.0f));
		aida::workbench::document_host::document_host_chrome_t chrome;
		const auto composed = context.document_host->compose(
			context.workspace, request, chrome);
		if (!composed) {
			ImGui::TextDisabled("Workbench layout rejected (%u)",
				static_cast<unsigned>(composed.code));
			return;
		}
		ImGui::PushID(static_cast<int>(context.workspace.value & 0x7FFFFFFFU));
		auto begin_region = [](const char* id,
			const aida::workbench::document_host::document_host_rect_t& bounds) {
			ImGui::SetCursorPos(ImVec2(static_cast<float>(bounds.x),
				static_cast<float>(bounds.y)));
			return ImGui::BeginChild(id,
				ImVec2(static_cast<float>(bounds.width),
					static_cast<float>(bounds.height)), false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings);
		};
		if (chrome.navigator_visible && chrome.navigator_bounds.width != 0 &&
			chrome.navigator_bounds.height != 0) {
			if (begin_region("##wb_navigator", chrome.navigator_bounds))
				render_workbench_navigator(workspace, context, state);
			ImGui::EndChild();
		}
		for (const auto& tab : chrome.tabs) {
			if (!tab.visible)
				continue;
			ImGui::SetCursorPos(ImVec2(static_cast<float>(tab.bounds.x),
				static_cast<float>(tab.bounds.y)));
			if (ImGui::Selectable((tab.label + "##wb_tab_" +
				std::to_string(tab.document.value)).c_str(), tab.selected, 0,
				ImVec2(static_cast<float>(tab.bounds.width),
					static_cast<float>(tab.bounds.height)))) {
				aida::workbench::document_host::document_host_dispatch_t dispatch;
				dispatch.kind = aida::workbench::document_host::
					document_host_dispatch_kind_t::select_document;
				dispatch.document = tab.document;
				aida::workbench::workbench_command_result_t result;
				static_cast<void>(
					aida::workbench::workbench_shell_runtime_t::instance()
						.dispatch_host_command(workspace, dispatch, result, context));
			}
		}
		for (const auto& item : chrome.toolbar) {
			if (!item.visible)
				continue;
			ImGui::SetCursorPos(ImVec2(static_cast<float>(item.bounds.x),
				static_cast<float>(item.bounds.y)));
			ImGui::BeginDisabled(!item.enabled);
			const char* label = ">";
			switch (item.action) {
			case aida::workbench::document_host::document_host_toolbar_action_t::previous_view: label = "<"; break;
			case aida::workbench::document_host::document_host_toolbar_action_t::next_view: label = ">"; break;
			case aida::workbench::document_host::document_host_toolbar_action_t::split_horizontal: label = "H"; break;
			case aida::workbench::document_host::document_host_toolbar_action_t::split_vertical: label = "V"; break;
			case aida::workbench::document_host::document_host_toolbar_action_t::history_back: label = "B"; break;
			case aida::workbench::document_host::document_host_toolbar_action_t::history_forward: label = "F"; break;
			case aida::workbench::document_host::document_host_toolbar_action_t::close_document: label = "X"; break;
			}
			if (ImGui::Button((std::string(label) + "##wb_toolbar_" +
				std::to_string(static_cast<unsigned>(item.action))).c_str(),
				ImVec2(static_cast<float>(item.bounds.width),
					static_cast<float>(item.bounds.height)))) {
				aida::workbench::document_host::document_host_dispatch_t dispatch;
				dispatch.kind = aida::workbench::document_host::
					document_host_dispatch_kind_t::toolbar;
				dispatch.toolbar_action = item.action;
				aida::workbench::workbench_command_result_t result;
				static_cast<void>(
					aida::workbench::workbench_shell_runtime_t::instance()
						.dispatch_host_command(workspace, dispatch, result, context));
			}
			ImGui::EndDisabled();
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("%s", item.tooltip.c_str());
		}
		for (const auto& leaf : chrome.leaves) {
			const auto* document = workbench_document(
				context.persistence, leaf.document);
			if (!document || leaf.bounds.width == 0 || leaf.bounds.height == 0)
				continue;
			const auto id = "##wb_leaf_" + std::to_string(leaf.view.value);
			if (begin_region(id.c_str(), leaf.bounds))
				render_workbench_document(workspace, context, *document, state,
					static_cast<float>(leaf.bounds.width),
					static_cast<float>(leaf.bounds.height));
			ImGui::EndChild();
		}
		if (chrome.inspector_visible && chrome.inspector_bounds.width != 0 &&
			chrome.inspector_bounds.height != 0) {
			if (begin_region("##wb_inspector", chrome.inspector_bounds))
				render_workbench_inspector(context);
			ImGui::EndChild();
		}
		ImGui::PopID();
	}

	void mark_center_render_section(const char* section, center_view_t view, bool overlay_blocking, float vw, float vh)
	{
		g_render_section = section;
		static std::atomic<unsigned long long> s_last_log_ms{0};
		static std::atomic<int> s_last_view{-1000000};
		static std::atomic<int> s_last_full_test{-1};
		const unsigned long long now = aida::shell_platform::tick_ms();
		const int view_raw = static_cast<int>(view);
		const bool full_test = shell_full_test_running();
		const bool view_changed = s_last_view.exchange(view_raw, std::memory_order_acq_rel) != view_raw;
		const bool full_changed = s_last_full_test.exchange(full_test ? 1 : 0, std::memory_order_acq_rel) != (full_test ? 1 : 0);
		unsigned long long last = s_last_log_ms.load(std::memory_order_acquire);
		const unsigned long long interval_ms = full_test ? 1000ULL : 15000ULL;
		const bool due = view_changed || full_changed || now - last >= interval_ms;
		if (due && s_last_log_ms.compare_exchange_strong(last, now, std::memory_order_acq_rel)) {
			diag::log_tagged_critical_fmt("render_center",
				"section=%s view=%s view_id=%d overlay=%d full_test=%d frame=%d vw=%.1f vh=%.1f tid=%lu",
				section ? section : "<null>",
				center_view_name(view),
				view_raw,
				overlay_blocking ? 1 : 0,
				full_test ? 1 : 0,
				ImGui::GetFrameCount(),
				vw,
				vh,
				static_cast<unsigned long>(aida::shell_platform::thread_id()));
		}
	}

	bool text_has_token(const std::string& text, const char* token)
	{
		return token && text.find(token) != std::string::npos;
	}

	bool text_has_positive_field(const std::string& text, const char* field)
	{
		if (!field || !*field)
			return false;
		std::string needle = field;
		needle += "=1";
		return text.find(needle) != std::string::npos;
	}

	std::string runtime_lock_field_value(const std::string& text, const char* field)
	{
		if (!field || !*field)
			return {};
		std::string needle = field;
		needle += "=";
		size_t pos = text.find(needle);
		if (pos == std::string::npos)
			return {};
		pos += needle.size();
		size_t end = text.find_first_of(" \t\r\n", pos);
		if (end == std::string::npos)
			end = text.size();
		return text.substr(pos, end - pos);
	}

	std::string runtime_lock_summary_value(const std::string& detail)
	{
		const std::string needle = "summary=";
		size_t pos = detail.find(needle);
		if (pos == std::string::npos)
			return {};
		pos += needle.size();
		size_t end = detail.find(" evidence_hash=", pos);
		if (end == std::string::npos)
			end = detail.find(" cat=", pos);
		if (end == std::string::npos)
			end = detail.size();
		std::string out = detail.substr(pos, end - pos);
		if (out.size() > 180)
			out = out.substr(0, 180);
		return out;
	}

	void runtime_lock_append_part(std::string& out, const std::string& part)
	{
		if (part.empty())
			return;
		if (!out.empty())
			out += "; ";
		out += part;
	}

	std::string runtime_lock_evidence_message(const std::string& reason, const std::string& detail)
	{
		const std::string joined = reason + " " + detail;
		std::string out;
		const std::string reason_value = runtime_lock_field_value(joined, "reason");
		if (!reason_value.empty())
			runtime_lock_append_part(out, "detector=" + reason_value);
		const std::string summary = runtime_lock_summary_value(detail);
		if (!summary.empty())
			runtime_lock_append_part(out, "evidence=" + summary);
		const std::string owner_pid = runtime_lock_field_value(joined, "first_owner_pid");
		if (!owner_pid.empty() && owner_pid != "0")
			runtime_lock_append_part(out, "owner_pid=" + owner_pid);
		const std::string owner_image = runtime_lock_field_value(joined, "first_owner_image");
		if (!owner_image.empty() && owner_image != "<empty>")
			runtime_lock_append_part(out, "owner=" + owner_image);
		const std::string kernel_status = runtime_lock_field_value(joined, "kernel_status");
		if (!kernel_status.empty())
			runtime_lock_append_part(out, "kernel=" + kernel_status);
		const std::string kernel_confirmed = runtime_lock_field_value(joined, "kernel_confirmed");
		if (!kernel_confirmed.empty())
			runtime_lock_append_part(out, "kernel_confirmed=" + kernel_confirmed);
		return out;
	}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	bool custom_icon_path_render_safe(const std::string& path, uint64_t& size_out, DWORD& attr_out, DWORD& err_out)
	{
		size_out = 0;
		attr_out = 0;
		err_out = ERROR_SUCCESS;
		if (path.empty()) {
			err_out = ERROR_INVALID_PARAMETER;
			return false;
		}
		if (path.rfind("\\\\", 0) == 0 || path.rfind("//", 0) == 0) {
			err_out = ERROR_BAD_NET_NAME;
			return false;
		}
		if (path.size() > MAX_PATH * 4) {
			err_out = ERROR_BAD_LENGTH;
			return false;
		}
		if (path.size() >= 2 && path[1] == ':') {
			char root[4] = { path[0], ':', '\\', '\0' };
			if (GetDriveTypeA(root) == DRIVE_REMOTE) {
				err_out = ERROR_BAD_NET_NAME;
				return false;
			}
		}
		WIN32_FILE_ATTRIBUTE_DATA data{};
		if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data)) {
			err_out = GetLastError();
			return false;
		}
		attr_out = data.dwFileAttributes;
		if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			err_out = ERROR_DIRECTORY;
			return false;
		}
		size_out = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | static_cast<uint64_t>(data.nFileSizeLow);
		if (size_out == 0 || size_out > 32ull * 1024ull * 1024ull) {
			err_out = ERROR_BAD_LENGTH;
			return false;
		}
		return true;
	}
#endif

	std::string runtime_lock_user_message(const std::string& reason, const std::string& detail)
	{
		const std::string joined = reason + " " + detail;
		if (text_has_token(joined, "HANDLE_WRITE") || text_has_token(joined, "HANDLE_VMOP") ||
			text_has_token(joined, "HANDLE_THREAD") || text_has_token(joined, "foreign_handle") ||
			text_has_token(joined, "foreign_mutating_handle"))
			return "Suspicious process handle to AiDA detected. Close that process, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "TARGET_AIDA") || text_has_token(joined, "targeting_aida"))
			return "External tooling is targeting AiDA. Close the tool targeting AiDA, then restart AiDAStandalone.exe.";
        if (text_has_token(joined, "MCP_OFFENSIVE_TOOL") || text_has_token(joined, "offensive_mcp_tool_detected") ||
			text_has_token(joined, "anti_mcp_offensive"))
			return "Offensive MCP tooling detected. Close that MCP tool, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "DBG_TOOL") || text_has_token(joined, "debugger_tool_detected") ||
			text_has_token(joined, "debugger_tool_scan") || text_has_token(joined, "kernel_debugger") ||
			text_has_positive_field(joined, "first_owner_debugger"))
			return "Debugger activity detected. Close the debugger, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "RE_TOOL") || text_has_token(joined, "reverse_engineering") ||
			text_has_positive_field(joined, "first_owner_re"))
			return "Reverse-engineering tool activity detected. Close that tool, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "DUMP_TOOL") || text_has_token(joined, "dump_tool_detected") ||
			text_has_token(joined, "dump_tool_scan") || text_has_positive_field(joined, "first_owner_dump"))
			return "Dumping tool activity detected. Close that tool, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "MEM_SCANNER") || text_has_token(joined, "memory_scanner") ||
			text_has_positive_field(joined, "first_owner_memory"))
			return "Memory scanner activity detected. Close the scanner, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "MCP_PIPE") || text_has_token(joined, "MCP_PROCESS") ||
			text_has_token(joined, "MCP_PORT") || text_has_token(joined, "MCP_CMD") ||
			text_has_token(joined, "mcp_bridge"))
			return "Untrusted MCP bridge activity detected. Close the bridge/tool, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "LOCAL_LLM") || text_has_token(joined, "local_llm"))
			return "Local LLM analysis context detected near AiDA. Close it, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "code_integrity") || text_has_token(joined, "page_mac") ||
			text_has_token(joined, "block_chain"))
			return "Runtime code integrity changed. Close suspicious tooling, then restart AiDAStandalone.exe.";
		if (text_has_token(joined, "kernel_debugger"))
			return "Kernel debugger activity detected. Close it, then restart AiDAStandalone.exe.";
		return "AiDA stopped this runtime session after an integrity failure. Close suspicious tools, then restart AiDAStandalone.exe.";
	}
}

namespace ui_input_gate
{
	bool any_fake_modal_open()
	{
		if (menu_bar::suppress_frames > 0) {
			static int s_last_suppress_frame = -1;
			int frame = ImGui::GetFrameCount();
			if (s_last_suppress_frame != frame) {
				--menu_bar::suppress_frames;
				s_last_suppress_frame = frame;
			}
			return true;
		}
		return globals::ui::process_attach_open
			|| globals::ui::command_palette_open
			|| globals::ui::driver_status_open
			|| globals::ui::shortcuts_dialog_open
			|| aida::mcp_marketplace_view::is_open()
			|| aida::agent_picker::is_open()
			|| menu_bar::any_open;
	}

	bool true_modal_open()
	{
		if (ImGui::GetTopMostPopupModal() != nullptr)
			return true;
		return false;
	}

	bool popup_blocks_background_input()
	{
		if (ImGui::GetTopMostPopupModal() != nullptr)
			return true;
		if (any_fake_modal_open())
			return true;
		return false;
	}

	bool chrome_input_blocked()
	{
		return false;
	}

	bool splitter_input_blocked()
	{
		return true_modal_open();
	}
}

static bool trusted_show_open_file(HWND owner,
	const char* title,
	const char* filter_pairs,
	char* out_path,
	size_t out_path_capacity,
	const char* caller_name)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	(void)owner;
	(void)title;
	(void)filter_pairs;
	(void)caller_name;
	return aida::preview::choose_open_file(out_path, out_path_capacity);
#else
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return win32_dialog::show_open_file_dialog(owner, title, filter_pairs,
		out_path, out_path_capacity, caller_name);
#endif
}

static bool trusted_show_save_file(HWND owner,
	const char* title,
	const char* filter_pairs,
	const char* default_ext,
	char* out_path,
	size_t out_path_capacity,
	const char* caller_name)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	(void)owner;
	(void)title;
	(void)filter_pairs;
	(void)default_ext;
	(void)caller_name;
	return aida::preview::choose_save_file(out_path, out_path_capacity);
#else
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return win32_dialog::show_save_file_dialog(owner, title, filter_pairs, default_ext,
		out_path, out_path_capacity, caller_name);
#endif
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
static bool trusted_show_folder(HWND owner,
	const wchar_t* title,
	std::string& out_path,
	const char* caller_name)
{
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return win32_dialog::show_open_folder_dialog(owner, title, out_path, caller_name);
}
#endif

namespace file_menu_deferred
{
	enum class action_t
	{
		none,
		open_file,
		open_folder
	};

	struct result_t
	{
		action_t action = action_t::none;
		bool ok = false;
		std::string path;
	};

	static std::atomic<int>& pending_action()
	{
		static std::atomic<int> value{ static_cast<int>(action_t::none) };
		return value;
	}

	static std::atomic<bool>& active()
	{
		static std::atomic<bool> value{ false };
		return value;
	}

	static std::atomic<std::uint64_t>& generation()
	{
		static std::atomic<std::uint64_t> value{ 0 };
		return value;
	}

	static std::atomic<std::uint64_t>& active_generation()
	{
		static std::atomic<std::uint64_t> value{ 0 };
		return value;
	}

	static const char* action_name(action_t action)
	{
		switch (action) {
		case action_t::none: return "none";
		case action_t::open_file: return "open_file";
		case action_t::open_folder: return "open_folder";
		}
		return "unknown";
	}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static void clear_active_generation_if_current(std::uint64_t token)
	{
		std::uint64_t expected = token;
		(void)active_generation().compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
	}

	static void store_result(std::uint64_t token, result_t result, const char* source)
	{
		std::string source_copy = source && source[0] ? source : "worker";
		const action_t action = result.action;
		const bool ok = result.ok;
		const std::string path_copy = result.path;
		const bool posted = aida::ui_thread::post([token, action, ok, path_copy, source_copy]() {
			if (!aida::ui_thread::require_owner("file_dialog", "publish_result", source_copy.c_str())) {
				clear_active_generation_if_current(token);
				return;
			}
			const std::uint64_t current = generation().load(std::memory_order_acquire);
			const std::uint64_t active_token = active_generation().load(std::memory_order_acquire);
			const bool stale = token == 0 || token != current;
			if (stale) {
				diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
					"discard_stale source=%s token=%llu current=%llu active_generation=%llu action=%s ok=%d path=%.260s",
					source_copy.c_str(),
					static_cast<unsigned long long>(token),
					static_cast<unsigned long long>(current),
					static_cast<unsigned long long>(active_token),
					action_name(action),
					ok ? 1 : 0,
					path_copy.c_str());
				clear_active_generation_if_current(token);
				return;
			}

			if (action == action_t::open_file) {
				if (ok && !path_copy.empty()) {
					diag::log_tagged_fmt("file_dialog", "deferred_open_file picked path=%.260s", path_copy.c_str());
					diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
						"publish_open_file token=%llu source=%s path=%.260s",
						static_cast<unsigned long long>(token),
						source_copy.c_str(),
						path_copy.c_str());
					file_browser::open_path(path_copy);
				} else {
					diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
						"publish_open_file_cancelled token=%llu source=%s ok=%d",
						static_cast<unsigned long long>(token),
						source_copy.c_str(),
						ok ? 1 : 0);
					diag::log_tagged_critical("file_dialog", "deferred_open_file cancelled_or_failed");
				}
				diag::log_tagged_critical("file_dialog", "deferred_open_file end");
			} else if (action == action_t::open_folder) {
				if (ok && !path_copy.empty()) {
					diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
						"publish_open_folder token=%llu source=%s path=%.260s",
						static_cast<unsigned long long>(token),
						source_copy.c_str(),
						path_copy.c_str());
					file_browser::refresh(path_copy);
					g_sa_settings.workspace.root_path = path_copy;
					g_sa_settings_request_save();
					diag::log_tagged_fmt("file_dialog", "deferred_open_folder picked path=%.260s", path_copy.c_str());
				} else {
					diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
						"publish_open_folder_cancelled token=%llu source=%s ok=%d",
						static_cast<unsigned long long>(token),
						source_copy.c_str(),
						ok ? 1 : 0);
					diag::log_tagged_critical("file_dialog", "deferred_open_folder cancelled_or_failed");
				}
				diag::log_tagged_critical("file_dialog", "deferred_open_folder end");
			} else {
				diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
					"discard_none token=%llu source=%s",
					static_cast<unsigned long long>(token),
					source_copy.c_str());
			}
			clear_active_generation_if_current(token);
		}, "file_dialog", "publish_result", source_copy.c_str());

		diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
			"post_publish source=%s token=%llu action=%s ok=%d posted=%d dispatcher_pending=%zu path=%.260s",
			source_copy.c_str(),
			static_cast<unsigned long long>(token),
			action_name(action),
			ok ? 1 : 0,
			posted ? 1 : 0,
			aida::ui_thread::pending_count(),
			path_copy.c_str());
		if (!posted)
			clear_active_generation_if_current(token);
	}
#endif

	static void request(action_t action)
	{
		const std::uint64_t token = generation().fetch_add(1, std::memory_order_acq_rel) + 1;
		pending_action().store(static_cast<int>(action), std::memory_order_release);
		diag::log_tagged_fmt("file_dialog", "deferred_request action=%d active=%d", static_cast<int>(action), active().load(std::memory_order_acquire) ? 1 : 0);
		diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
			"request token=%llu action=%s active=%d pending_raw=%d active_generation=%llu",
			static_cast<unsigned long long>(token),
			action_name(action),
			active().load(std::memory_order_acquire) ? 1 : 0,
			pending_action().load(std::memory_order_acquire),
			static_cast<unsigned long long>(active_generation().load(std::memory_order_acquire)));
	}
	static void run_pending()
	{
		if (active().load(std::memory_order_acquire))
			return;

		int raw = pending_action().exchange(static_cast<int>(action_t::none), std::memory_order_acq_rel);
		action_t action = static_cast<action_t>(raw);
		if (action == action_t::none)
			return;

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (action == action_t::open_file) {
			aida::preview::record(aida::preview::shell_action_t::open_file, "file_menu_deferred");
			aida::preview::apply_open_file();
		} else if (action == action_t::open_folder) {
			aida::preview::record(aida::preview::shell_action_t::open_folder, "file_menu_deferred");
			aida::preview::apply_open_folder();
		}
		return;
#else

		const std::uint64_t token = generation().load(std::memory_order_acquire);
		active_generation().store(token, std::memory_order_release);
		active().store(true, std::memory_order_release);
		diag::log_tagged_critical_fmt("FILEDIALOG-UI-DISPATCH",
			"worker_start_post token=%llu action=%s active_generation=%llu dispatcher_pending=%zu",
			static_cast<unsigned long long>(token),
			action_name(action),
			static_cast<unsigned long long>(active_generation().load(std::memory_order_acquire)),
			aida::ui_thread::pending_count());
		auto task = [action, token]() {
			try {
				if (action == action_t::open_file) {
					diag::log_tagged_critical("file_dialog", "deferred_open_file worker_begin");
					char buf[MAX_PATH] = {};
					static const char k_open_file_filter[] =
						"All files (*.*)\0*.*\0"
						"C/C++ (*.c;*.cpp;*.h;*.hpp)\0*.c;*.cpp;*.h;*.hpp\0\0";
					bool ok = trusted_show_open_file(nullptr,
						"Open File",
						k_open_file_filter,
						buf, sizeof(buf),
						"file_menu_open");
					active().store(false, std::memory_order_release);
					store_result(token, result_t{ action, ok, ok ? std::string(buf) : std::string() }, "worker_open_file");
					diag::log_tagged_fmt("file_dialog", "deferred_open_file worker_end ok=%d", ok ? 1 : 0);
				} else if (action == action_t::open_folder) {
					diag::log_tagged_critical("file_dialog", "deferred_open_folder worker_begin");
					std::string folder;
					bool ok = trusted_show_folder(nullptr,
						L"Open Workspace Folder",
						folder,
						"workspace_open_folder");
					active().store(false, std::memory_order_release);
					store_result(token, result_t{ action, ok, ok ? folder : std::string() }, "worker_open_folder");
					diag::log_tagged_fmt("file_dialog", "deferred_open_folder worker_end ok=%d", ok ? 1 : 0);
				} else {
					active().store(false, std::memory_order_release);
					store_result(token, result_t{ action_t::none, false, {} }, "worker_none");
				}
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("file_dialog", "deferred_worker exception=%s", ex.what());
				active().store(false, std::memory_order_release);
				store_result(token, result_t{ action, false, {} }, "worker_exception");
			} catch (...) {
				diag::log_tagged_critical("file_dialog", "deferred_worker unknown_exception");
				active().store(false, std::memory_order_release);
				store_result(token, result_t{ action, false, {} }, "worker_unknown_exception");
			}
		};
		bool queued = false;
		try {
			queued = submit_helpers_executor_task(
				"file_dialog",
				"file_dialog.deferred_worker",
				aida::infra::executor::domain_t::feature_worker,
				"bounded_task",
				std::move(task)).submitted;
		} catch (const std::exception& ex) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_fmt("file_dialog", "deferred_post exception=%s", ex.what());
			store_result(token, result_t{ action, false, {} }, "post_exception");
			return;
		} catch (...) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_critical("file_dialog", "deferred_post unknown_exception");
			store_result(token, result_t{ action, false, {} }, "post_unknown_exception");
			return;
		}
		if (!queued) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_critical("file_dialog", "deferred_post failed");
			store_result(token, result_t{ action, false, {} }, "post_failed");
		}
#endif
	}
}

static bool has_any_target()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	return aida::preview::attached_pid() != 0 || analysis_session::session_count() > 0;
#else
	return analysis_session::session_count() > 0
	    || driver_bridge::attached_pid() != 0
	    || analysis_session::active_workspace() != nullptr;
#endif
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
static bool license_activate_impl(const char* key_str,
                                  char* err_buf,
                                  size_t err_buf_size)
{
	if (err_buf && err_buf_size) err_buf[0] = '\0';
	std::string key(key_str ? key_str : "");
	std::string err;
	bool ok = false;
	try {
		ok = standalone_license::activate(g_sa_settings, key, err);
	} catch (const std::exception& ex) {
		err = std::string("Activation worker exception: ") + ex.what();
		ok = false;
	} catch (...) {
		err = "Activation worker threw unknown exception.";
		ok = false;
	}
	if (err_buf && err_buf_size) {
		size_t copy = err.size();
		if (copy >= err_buf_size) copy = err_buf_size - 1;
		memcpy(err_buf, err.data(), copy);
		err_buf[copy] = '\0';
	}
	return ok;
}

__declspec(noinline) static DWORD seh_license_activate(const char* key_str,
                                                       BOOL* out_ok,
                                                       char* err_buf,
                                                       size_t err_buf_size)
{
	*out_ok = FALSE;
	__try {
		bool ok = license_activate_impl(key_str, err_buf, err_buf_size);
		*out_ok = ok ? TRUE : FALSE;
		return 0;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}
#endif



ID3D11ShaderResourceView* helpers::theme_rias = nullptr;
ID3D11ShaderResourceView* helpers::theme_nagi = nullptr;
ID3D11ShaderResourceView* helpers::theme_mio = nullptr;
ID3D11ShaderResourceView* helpers::theme_kaneki = nullptr;
bool helpers::themes_loaded = false;


static ID3D11ShaderResourceView* g_bg_art_srv = nullptr;
static int g_bg_art_w = 0, g_bg_art_h = 0;
static ID3D11ShaderResourceView* g_aida_logo_srv = nullptr;
static int g_aida_logo_w = 0, g_aida_logo_h = 0;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
extern unsigned char background[];
extern unsigned char aidalogo[];
static bool g_bg_art_loaded = false;
static bool g_aida_logo_loaded = false;
static ID3D11ShaderResourceView* g_custom_theme_icon_srv = nullptr;
static int g_custom_theme_icon_w = 0;
static int g_custom_theme_icon_h = 0;
static std::string g_custom_theme_icon_path;
#endif

int helpers::active_tab = 0;
int helpers::active_subsection = 0;
bool helpers::init = false;
static float fadeout = 1.f;

ID3D11ShaderResourceView* helpers::icon_aim = nullptr;
ID3D11ShaderResourceView* helpers::icon_see = nullptr;
ID3D11ShaderResourceView* helpers::icon_misc = nullptr;
ID3D11ShaderResourceView* helpers::icon_settings = nullptr;
ID3D11ShaderResourceView* helpers::icon_player = nullptr;
ID3D11ShaderResourceView* helpers::icon_solitude = nullptr;

int helpers::icon_w = 0;
int helpers::icon_h = 0;
bool helpers::icons_loaded = false;

bool helpers::tab(const char* label, int index, ImVec2 pos, ImVec2 size)
{
	const auto& th = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImVec2 tab_min = ImVec2(wp.x + pos.x, wp.y + pos.y);
	ImVec2 tab_max = ImVec2(tab_min.x + size.x, tab_min.y + size.y);

	bool hovered = ImGui::IsMouseHoveringRect(tab_min, tab_max, false);
	bool clicked = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
	if (clicked) active_tab = index;
	bool active = active_tab == index;

	ImGuiStorage* storage = ImGui::GetStateStorage();
	const ImGuiID index_id = static_cast<ImGuiID>(index);
	const ImGuiID anim_id = ImGuiID{ 1000u } + index_id;
	const ImGuiID hover_id = ImGuiID{ 3000u } + index_id;

	float t = storage->GetFloat(anim_id, active ? 1.0f : 0.0f);
	float ht = storage->GetFloat(hover_id, 0.0f);

	float dt = aida::ui::clock::dt();
	t += ((active ? 1.0f : 0.0f) - t) * std::min(8.0f * dt, 1.0f);
	ht += ((hovered ? 1.0f : 0.0f) - ht) * std::min(12.0f * dt, 1.0f);

	storage->SetFloat(anim_id, t);
	storage->SetFloat(hover_id, ht);

	if (t > 0.01f)
	{
		for (int i = 4; i >= 1; i--)
		{
			const float spread = static_cast<float>(i) * 3.0f;
			dl->AddRectFilled(
				ImVec2(tab_min.x - spread, tab_min.y - spread),
				ImVec2(tab_max.x + spread, tab_max.y + spread),
				aida::ui::with_alpha(th.accent_glow,
					0.08f * t * static_cast<float>(5 - i)),
				6.f + spread);
		}
	}

	if (ht > 0.01f && t < 0.99f)
		dl->AddRectFilled(tab_min, tab_max,
			aida::ui::with_alpha(th.hover_wash, ht * (1.0f - t)), 6.f);

	if (t > 0.01f)
	{
		dl->AddRectFilled(tab_min, tab_max,
			aida::ui::with_alpha(th.selection_strong, t * 0.85f), 6.f);
		dl->AddRectFilled(tab_min, ImVec2(tab_max.x, tab_min.y + 1.f),
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.08f * t), 6.f);
	}

	ImVec2 ts = ImGui::CalcTextSize(label);
	ImVec2 tp = ImVec2(
		tab_min.x + (size.x - ts.x) * 0.5f,
		tab_min.y + (size.y - ts.y) * 0.5f);

	ImU32 text_col = aida::ui::mix(
		aida::ui::mix(th.text_secondary, th.text_primary, ht),
		th.text_primary, t);

	dl->AddText(tp, text_col, label);

	return clicked;
}

void helpers::begin_child(const char* str_id, ImVec2 pos, ImVec2 size, float alpha, ImGuiWindowFlags flags)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();

	ImVec2 r_min = ImVec2(std::round(wp.x + pos.x), std::round(wp.y + pos.y));
	ImVec2 r_max = ImVec2(std::round(r_min.x + size.x), std::round(r_min.y + size.y));

	ImU32 pbg = aida::ui::resolved().panel_bg;
	int pr = (pbg >> 0) & 0xFF, pg = (pbg >> 8) & 0xFF, pb = (pbg >> 16) & 0xFF, pa = (pbg >> 24) & 0xFF;
	dl->AddRectFilled(r_min, r_max,
		IM_COL32(pr, pg, pb, static_cast<int>(static_cast<float>(pa) * alpha)), 8.f);

	bool has_label = str_id && str_id[0] != '\0';
	std::string uid = has_label ? str_id : std::string("##child_") + std::to_string((uintptr_t)&pos);
	float padding = 6;
	ImGui::SetCursorPos(ImVec2(pos.x + padding, pos.y + padding));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
	ImGui::BeginChild(uid.c_str(), ImVec2(size.x - (2 * padding), size.y - (2 * padding)), false,
		ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings | flags);

}

void helpers::end_child()
{
	ImGui::EndChild();
	ImGui::PopStyleVar();
}

int helpers::subsection(const char** labels, int count, ImVec2 pos)
{
	ImDrawList* dl  = ImGui::GetWindowDrawList();
	ImVec2      wp  = ImGui::GetWindowPos();
	float spacing   = 3.0f;
	float avail_w   = ImGui::GetCurrentWindow()->Size.x - (pos.x * 2.0f) + 10.0f;
	const float count_f = static_cast<float>(count);
	float btn_w     = (avail_w - spacing * static_cast<float>(count - 1)) / count_f;
	float x_off     = pos.x - 5.0f;
	float fh        = ImGui::GetFontSize();
	float btn_h     = fh + 6.0f;

	static std::map<int, float> anim;

	for (int i = 0; i < count; i++)
	{
		ImVec2 ts      = ImGui::CalcTextSize(labels[i]);
		ImVec2 btn_min = ImVec2(std::round(wp.x + x_off),         std::round(wp.y + pos.y));
		ImVec2 btn_max = ImVec2(std::round(btn_min.x + btn_w),    std::round(btn_min.y + btn_h));

		bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			active_subsection = i;

		if (anim.find(i) == anim.end()) anim[i] = (active_subsection == i) ? 1.0f : 0.0f;
		float spd = 10.0f * ImGui::GetIO().DeltaTime;
		float tgt = (active_subsection == i) ? 1.0f : 0.0f;
		anim[i] += (tgt - anim[i]) * std::min(spd, 1.0f);
		float t = anim[i];


		if (hovered)
			dl->AddRectFilled(btn_min, btn_max, aida::ui::resolved().hover_wash, 4.f);


		ImU32 text_col = aida::ui::with_alpha(
			aida::ui::mix(aida::ui::resolved().text_secondary, aida::ui::resolved().accent_u32, t),
			0.45f + 0.55f * t);
		ImVec2 tp = ImVec2(btn_min.x + (btn_w - ts.x) * 0.5f, btn_min.y + (btn_h - fh) * 0.5f);
		dl->AddText(tp, text_col, labels[i]);


		float line_hw = btn_w * 0.5f * t;
		float line_cx = btn_min.x + btn_w * 0.5f;
		float line_y  = btn_max.y - 1.0f;
		if (line_hw > 0.5f)
		{
			ImU32 lc = IM_COL32(
				(int)(globals::ui::accent.x * 255),
				(int)(globals::ui::accent.y * 255),
				(int)(globals::ui::accent.z * 255),
				(int)(210 * t));
			dl->AddLine(ImVec2(line_cx - line_hw, line_y),
				        ImVec2(line_cx + line_hw, line_y), lc, 1.5f);
		}

		x_off += btn_w + spacing;
	}
	return active_subsection;
}

int helpers::subsection(const char** labels, int count, ImVec2 pos, int& state)
{
	ImDrawList* dl  = ImGui::GetWindowDrawList();
	ImVec2      wp  = ImGui::GetWindowPos();
	float spacing   = 3.0f;
	float avail_w   = ImGui::GetCurrentWindow()->Size.x - (pos.x * 2.0f) + 10.0f;
	const float count_f = static_cast<float>(count);
	float btn_w     = (avail_w - spacing * static_cast<float>(count - 1)) / count_f;
	float x_off     = pos.x - 5.0f;
	float fh        = ImGui::GetFontSize();
	float btn_h     = fh + 6.0f;

	static std::map<int*, float> anim;

	for (int i = 0; i < count; i++)
	{
		ImVec2 ts      = ImGui::CalcTextSize(labels[i]);
		ImVec2 btn_min = ImVec2(std::round(wp.x + x_off),       std::round(wp.y + pos.y));
		ImVec2 btn_max = ImVec2(std::round(btn_min.x + btn_w),  std::round(btn_min.y + btn_h));

		bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			state = i;

		if (anim.find(&state) == anim.end()) anim[&state] = (state == i) ? 1.0f : 0.0f;
		anim[&state] += ((state == i ? 1.0f : 0.0f) - anim[&state])
			* std::min(10.0f * ImGui::GetIO().DeltaTime, 1.0f);
		float t = anim[&state];

		if (hovered)
			dl->AddRectFilled(btn_min, btn_max, aida::ui::resolved().hover_wash, 4.f);

		ImU32 text_col = aida::ui::with_alpha(
			aida::ui::mix(aida::ui::resolved().text_secondary, aida::ui::resolved().accent_u32, t),
			0.45f + 0.55f * t);
		ImVec2 tp = ImVec2(btn_min.x + (btn_w - ts.x) * 0.5f, btn_min.y + (btn_h - fh) * 0.5f);
		dl->AddText(tp, text_col, labels[i]);

		float line_hw = btn_w * 0.5f * t;
		float line_cx = btn_min.x + btn_w * 0.5f;
		float line_y  = btn_max.y - 1.0f;
		if (line_hw > 0.5f)
		{
			ImU32 lc = IM_COL32(
				(int)(globals::ui::accent.x * 255),
				(int)(globals::ui::accent.y * 255),
				(int)(globals::ui::accent.z * 255),
				(int)(210 * t));
			dl->AddLine(ImVec2(line_cx - line_hw, line_y),
				        ImVec2(line_cx + line_hw, line_y), lc, 1.5f);
		}

		x_off += btn_w + spacing;
	}
	return state;
}

void helpers::add_key(const char* label, CKeybind* keybind)
{
	(void)label;
	ImDrawList* dl = ImGui::GetForegroundDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	ImU32 accent_col = IM_COL32(globals::ui::accent.x * 255, globals::ui::accent.y * 255, globals::ui::accent.z * 255, 255);

	static std::map<CKeybind*, bool>  menu_open;
	static std::map<CKeybind*, float> height_anim;
	static std::map<CKeybind*, float> width_anim;

	if (menu_open.find(keybind) == menu_open.end())   menu_open[keybind] = false;
	if (height_anim.find(keybind) == height_anim.end()) height_anim[keybind] = 0.0f;
	if (width_anim.find(keybind) == width_anim.end())  width_anim[keybind] = 0.0f;

	std::string key_name = keybind->waiting_for_input ? "..." : keybind->get_key_name();
	if (key_name == "lbutton")  key_name = "lmb";
	else if (key_name == "rbutton")  key_name = "rmb";
	else if (key_name == "mbutton")  key_name = "mmb";
	else if (key_name == "xbutton1") key_name = "xb1";
	else if (key_name == "xbutton2") key_name = "xb2";

	const char* options[] = { "Toggle", "Hold", "Always" };

	ImVec2 key_ts = ImGui::CalcTextSize(key_name.c_str());
	float max_opt_w = 0.0f;
	for (int i = 0; i < 3; i++) max_opt_w = std::max(max_opt_w, ImGui::CalcTextSize(options[i]).x);

	float min_w = 30.0f;
	float closed_w = std::max(min_w, key_ts.x + 8.0f);
	float open_w = std::max(min_w, max_opt_w + 14.0f);
	float closed_h = 13.0f;
	float open_h = 45.0f;

	ImVec2 cursor_pos = ImGui::GetCursorPos();
	float child_w = ImGui::GetCurrentWindow()->Size.x;
	float anim_spd = 10.0f * ImGui::GetIO().DeltaTime;
	float tgt = menu_open[keybind] ? 1.0f : 0.0f;

	if (height_anim[keybind] < tgt) height_anim[keybind] = std::min(height_anim[keybind] + anim_spd, tgt);
	else if (height_anim[keybind] > tgt) height_anim[keybind] = std::max(height_anim[keybind] - anim_spd, tgt);
	if (width_anim[keybind] < tgt) width_anim[keybind] = std::min(width_anim[keybind] + anim_spd, tgt);
	else if (width_anim[keybind] > tgt) width_anim[keybind] = std::max(width_anim[keybind] - anim_spd, tgt);

	float cur_w = closed_w + (open_w - closed_w) * width_anim[keybind];
	float cur_h = closed_h + (open_h - closed_h) * height_anim[keybind];
	float x_pos = child_w - cur_w - 5.0f + 5.0f;

	ImGui::SameLine();
	ImGui::SetCursorPosX(x_pos);

	ImVec2 btn_min = ImVec2(wp.x + x_pos, wp.y + cursor_pos.y);
	ImVec2 btn_max = ImVec2(btn_min.x + cur_w, btn_min.y + cur_h);

	bool hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
	bool left_click = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
	bool right_click = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right);

	if (right_click) { menu_open[keybind] = !menu_open[keybind]; keybind->waiting_for_input = false; }
	if (left_click && !menu_open[keybind])
	{
		keybind->waiting_for_input = !keybind->waiting_for_input;
		if (!keybind->waiting_for_input) ImGui::ClearActiveID();
	}
	if (keybind->waiting_for_input && keybind->set_key())
	{
		keybind->waiting_for_input = false;
		ImGui::ClearActiveID();
	}

	float kb_radius = 3.0f;
	dl->AddRect(btn_min, btn_max, IM_COL32(0, 0, 0, 255), kb_radius);
	dl->AddRect(ImVec2(btn_min.x + 1, btn_min.y + 1), ImVec2(btn_max.x - 1, btn_max.y - 1), aida::ui::resolved().border_strong, kb_radius);
	ImU32 kb_fill_top = aida::ui::lighten(aida::ui::resolved().bg_base, aida::ui::is_dark() ? 14 : -6);
	ImU32 kb_fill_bot = aida::ui::darken(aida::ui::resolved().bg_base, aida::ui::is_dark() ? 4 : -2);
	ImU32 kb_fill_mix = aida::ui::mix(kb_fill_top, kb_fill_bot, 0.45f);
	dl->AddRectFilled(
		ImVec2(btn_min.x + 2, btn_min.y + 2), ImVec2(btn_max.x - 2, btn_max.y - 2),
		kb_fill_mix, kb_radius);

	float key_op = 1.0f - height_anim[keybind];
	if (key_op > 0.01f)
	{
		ImU32 tc = keybind->waiting_for_input ? accent_col : aida::ui::with_alpha(aida::ui::resolved().text_primary, key_op);
		ImVec2 tp = ImVec2(std::round(btn_min.x + (cur_w - key_ts.x) * 0.5f), std::round(btn_min.y + (closed_h - key_ts.y) * 0.5f - 1.0f));

		dl->AddText(tp, tc, key_name.c_str());
	}

	if (height_anim[keybind] > 0.01f)
	{
		float opt_h = 13.0f;
		for (int i = 0; i < 3; i++)
		{
			float oy = btn_min.y + 3.0f + static_cast<float>(i) * opt_h;
			if (oy + opt_h > btn_max.y) break;

			ImVec2 opt_min = ImVec2(btn_min.x + 2, oy + 2);
			ImVec2 opt_max = ImVec2(btn_max.x - 2, std::min(oy + opt_h, btn_max.y - 2));

			if (ImGui::IsMouseHoveringRect(opt_min, opt_max) && height_anim[keybind] > 0.99f && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			{
				keybind->type = static_cast<CKeybind::c_keybind_type>(i);
				menu_open[keybind] = false;
			}

			bool sel = keybind->type == i;
			ImVec2 ots = ImGui::CalcTextSize(options[i]);
			ImVec2 otp = ImVec2(std::round(btn_min.x + (cur_w - ots.x) * 0.5f), std::round(oy + (opt_h - ots.y) * 0.5f - 1.0f));
			float op = height_anim[keybind];
			ImU32 oc = sel ?
				IM_COL32((int)(globals::ui::accent.x * 255), (int)(globals::ui::accent.y * 255), (int)(globals::ui::accent.z * 255), (int)(255 * op)) :
				aida::ui::with_alpha(aida::ui::resolved().text_secondary, op);

			if (otp.y + ots.y <= btn_max.y - 2.0f)
			{
				dl->AddText(otp, oc, options[i]);
			}
		}
	}

	if (menu_open[keybind] && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !hovered)
		menu_open[keybind] = false;
}


#include <filesystem>
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <shlobj.h>
#endif

std::string conversations::get_storage_dir()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	return "C:/Preview/AiDA/Standalone/conversations";
#else
	wchar_t* appdata = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
		auto p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"conversations";
		CoTaskMemFree(appdata);
		std::filesystem::create_directories(p);
		return p.string();
	}
	return {};
#endif
}

void conversations::save_current()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (g_chat_messages.empty()) return;
	if (current_id.empty()) current_id = "preview-conversation";
	std::string title = "Untitled";
	for (const auto& message : g_chat_messages) {
		if (message.is_user && !message.text.empty()) {
			title = message.text.substr(0, 80);
			break;
		}
	}
	auto found = std::find_if(history.begin(), history.end(), [](const ConversationSummary& item) {
		return item.id == current_id;
	});
	ConversationSummary summary{ current_id, title, g_chat_messages.front().timestamp, static_cast<int>(g_chat_messages.size()) };
	if (found == history.end()) history.insert(history.begin(), std::move(summary));
	else *found = std::move(summary);
#else
	if (g_chat_messages.empty()) return;
	std::string dir = get_storage_dir();
	if (dir.empty()) return;

	if (current_id.empty()) {
		auto now = std::chrono::system_clock::now().time_since_epoch();
		current_id = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
	}

	nlohmann::json j;
	j["id"] = current_id;
	std::string title;
	for (auto& m : g_chat_messages) {
		if (m.is_user && !m.text.empty()) {
			title = m.text.substr(0, 80);
			break;
		}
	}
	j["title"] = title;
	j["created"] = g_chat_messages.front().timestamp;
	nlohmann::json msgs = nlohmann::json::array();
	for (auto& m : g_chat_messages) {
		nlohmann::json mj;
		mj["text"] = m.text;
		mj["thinking_text"] = m.thinking_text;
		mj["is_user"] = m.is_user;
		mj["has_thinking"] = m.has_thinking;
		mj["timestamp"] = m.timestamp;
		mj["input_tokens"] = m.input_tokens;
		mj["output_tokens"] = m.output_tokens;
		mj["cache_read_tokens"] = m.cache_read_tokens;
		mj["cache_write_tokens"] = m.cache_write_tokens;
		mj["model_id"] = m.model_id;
		msgs.push_back(mj);
	}
	j["messages"] = msgs;

	std::string path = dir + "\\" + current_id + ".json";
	std::ofstream ofs(path, std::ios::trunc);
	if (ofs.is_open()) ofs << j.dump(2);
#endif
}

void conversations::load_conversation(const std::string& id)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	current_id = id;
	g_chat_messages.clear();
	ChatMessage user_message;
	user_message.text = "Show the saved reverse-engineering findings.";
	user_message.is_user = true;
	user_message.timestamp = 1;
	g_chat_messages.push_back(std::move(user_message));
	ChatMessage assistant_message;
	assistant_message.text = "The deterministic Studio conversation fixture is active. All original chat controls and interaction states remain available.";
	assistant_message.timestamp = 2;
	g_chat_messages.push_back(std::move(assistant_message));
	g_chat_scroll_to_bottom = true;
#else
	std::string dir = get_storage_dir();
	if (dir.empty()) return;
	std::string path = dir + "\\" + id + ".json";
	std::ifstream ifs(path);
	if (!ifs.is_open()) return;
	auto j = nlohmann::json::parse(ifs, nullptr, false);
	if (j.is_discarded() || !j.is_object()) return;

	g_chat_messages.clear();
	current_id = j.value("id", id);
	for (auto& mj : j.value("messages", nlohmann::json::array())) {
		ChatMessage m;
		m.text = mj.value("text", "");
		m.thinking_text = mj.value("thinking_text", "");
		m.is_user = mj.value("is_user", false);
		m.has_thinking = mj.value("has_thinking", false);
		m.streaming = false;
		m.timestamp = mj.value("timestamp", (int64_t)0);
		m.input_tokens = mj.value("input_tokens", 0);
		m.output_tokens = mj.value("output_tokens", 0);
		m.cache_read_tokens = mj.value("cache_read_tokens", 0);
		m.cache_write_tokens = mj.value("cache_write_tokens", 0);
		m.model_id = mj.value("model_id", std::string());
		g_chat_messages.push_back(m);
	}
	g_chat_scroll_to_bottom = true;
#endif
}

void conversations::new_chat()
{
	save_current();
	g_chat_messages.clear();
	g_chat_buf[0] = '\0';
	current_id.clear();
	g_chat_scroll_to_bottom = true;
	refresh_history();
}

void conversations::refresh_history()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (history.empty()) {
		history = {
			{ "fixture-analysis", "Entry point analysis", 3, 8 },
			{ "fixture-network", "Protocol reconstruction", 2, 12 },
			{ "fixture-unpack", "Packed sample notes", 1, 6 }
		};
	}
#else
	history.clear();
	std::string dir = get_storage_dir();
	if (dir.empty()) return;
	for (auto& entry : std::filesystem::directory_iterator(dir)) {
		if (!entry.is_regular_file()) continue;
		if (entry.path().extension() != ".json") continue;
		std::ifstream ifs(entry.path());
		auto j = nlohmann::json::parse(ifs, nullptr, false);
		if (j.is_discarded() || !j.is_object()) continue;
		ConversationSummary s;
		s.id = j.value("id", entry.path().stem().string());
		s.title = j.value("title", "Untitled");
		s.created = j.value("created", (int64_t)0);
		auto msgs = j.value("messages", nlohmann::json::array());
		s.msg_count = (int)msgs.size();
		history.push_back(s);
	}
	std::sort(history.begin(), history.end(), [](auto& a, auto& b) { return a.created > b.created; });
#endif
}

void conversations::delete_conversation(const std::string& id)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	history.erase(std::remove_if(history.begin(), history.end(), [&id](const ConversationSummary& item) {
		return item.id == id;
	}), history.end());
	if (current_id == id) new_chat();
#else
	std::string dir = get_storage_dir();
	if (dir.empty()) return;
	std::string path = dir + "\\" + id + ".json";
	std::filesystem::remove(path);
	refresh_history();
#endif
}

static std::string truncate_session_tab_label(const std::string& s, size_t max_chars)
{
	if (s.size() <= max_chars) return s;
	if (max_chars <= 3) return std::string(max_chars, '.');
	return s.substr(0, max_chars - 3) + std::string("...");
}

static void render_session_tabs(float x, float y, float width, float height, float alpha)
{
	const auto& th = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	size_t count = analysis_session::session_count();
	if (!has_any_target()) {
		float pad = 12.f;
		float card_w = width - pad * 2.f;
		if (card_w < 120.f) card_w = 120.f;
		float card_h = height - 4.f;
		ImVec2 a(x + pad, y + 2.f);
		ImVec2 b(a.x + card_w, a.y + card_h);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(th.bg_elevated, 0.5f * alpha), 6.f);
		dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, 0.6f * alpha), 6.f, 0, 1.f);
		const char* msg = "No binary open. Click a file in the Explorer, attach to a process, or press Run.";
		ImVec2 ts = ImGui::CalcTextSize(msg);
		dl->AddText(ImVec2(a.x + (card_w - ts.x) * 0.5f, a.y + (card_h - ts.y) * 0.5f),
			aida::ui::with_alpha(th.text_dim, 0.85f * alpha), msg);

		float plus_sz = 18.f;
		float plus_x0 = b.x + 6.f;
		float plus_y0 = a.y + (card_h - plus_sz) * 0.5f;
		float plus_x1 = plus_x0 + plus_sz;
		float plus_y1 = plus_y0 + plus_sz;
		if (plus_x1 < x + width - 2.f) {
			bool plus_hov = ImGui::IsMouseHoveringRect(ImVec2(plus_x0, plus_y0), ImVec2(plus_x1, plus_y1), false);
			ImU32 plus_bg = aida::ui::with_alpha(plus_hov ? th.accent_u32 : th.bg_elevated, (plus_hov ? 0.65f : 0.45f) * alpha);
			dl->AddRectFilled(ImVec2(plus_x0, plus_y0), ImVec2(plus_x1, plus_y1), plus_bg, 4.f);
			float cx = plus_x0 + plus_sz * 0.5f;
			float cy = plus_y0 + plus_sz * 0.5f;
			ImU32 plus_col = aida::ui::with_alpha(th.text_primary, alpha);
			dl->AddLine(ImVec2(cx - 5.f, cy), ImVec2(cx + 5.f, cy), plus_col, 1.6f);
			dl->AddLine(ImVec2(cx, cy - 5.f), ImVec2(cx, cy + 5.f), plus_col, 1.6f);
			if (plus_hov && !ui_input_gate::popup_blocks_background_input()) {
				ImGui::SetTooltip("New session\nLeft-click: Open File...\nRight-click: Attach to Process...\nMiddle-click: Run...");
				if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::apply_open_file();
#else
					anti_tamper::webhook::write_log("file_dialog", "session_tab_plus left_click open_file_dialog");
					std::string fpath = disasm::open_file_dialog(g_hwnd);
					if (!fpath.empty()) {
						anti_tamper::webhook::write_log("file_dialog", (std::string("session_tab_plus open_file_dialog ok path=") + fpath).c_str());
						analysis_session::open_session(fpath);
					} else {
						anti_tamper::webhook::write_log("file_dialog", "session_tab_plus open_file_dialog cancelled_or_empty");
					}
#endif
				} else if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
					globals::ui::process_attach_open = true;
				} else if (ImGui::IsMouseClicked(ImGuiMouseButton_Middle)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::record(aida::preview::shell_action_t::run_target, "session_tab_plus");
#endif
					spawn_target_dialog::request_open();
				}
			}
		}
		return;
	}
	if (count == 0) {
		return;
	}

	float tab_h = height - 6.f;
	if (tab_h < 22.f) tab_h = 22.f;
	float ty0 = y + (height - tab_h) * 0.5f;
	float ty1 = ty0 + tab_h;

	float pad_outer = 8.f;
	float gap = 4.f;
	float close_btn_sz = 14.f;
	float inner_pad = 10.f;
	float badge_sz = 14.f;
	float badge_gap = 6.f;

	float cursor_x = x + pad_outer;
	size_t active_idx = analysis_session::active_session_idx();
	int    close_intent = -1;
	int    switch_intent = -1;
	int    detach_intent = -1;
	int    reattach_intent = -1;
	int    open_ctx_for = -1;

	for (size_t i = 0; i < count; ++i) {
		const auto sess = analysis_session::session_handle_at(i);
		if (!sess) continue;
		bool is_live = (sess->attached_pid != 0);
		bool is_dead = is_live && !session_health::is_alive(sess->attached_pid);
		std::string label = truncate_session_tab_label(sess->filename.empty() ? sess->path : sess->filename, 20);
		ImVec2 ls = ImGui::CalcTextSize(label.c_str());
		float tab_w = inner_pad + badge_sz + badge_gap + ls.x + 8.f + close_btn_sz + inner_pad;
		if (tab_w < 100.f) tab_w = 100.f;

		float tx0 = cursor_x;
		float tx1 = tx0 + tab_w;
		if (tx1 > x + width - pad_outer - 28.f) break;

		bool is_active = (i == active_idx);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(tx0, ty0), ImVec2(tx1, ty1), false);

		ImU32 fill_top, fill_bot;
		if (is_dead) {
			ImU32 dead_fill = IM_COL32(58, 24, 24, static_cast<int>(180.f * alpha));
			fill_top = dead_fill;
			fill_bot = dead_fill;
		} else if (is_active) {
			fill_top = aida::ui::with_alpha(th.accent_grad_top, 0.30f * alpha);
			fill_bot = aida::ui::with_alpha(th.accent_grad_bot, 0.45f * alpha);
		} else if (hov) {
			fill_top = aida::ui::with_alpha(th.panel_header, 0.85f * alpha);
			fill_bot = aida::ui::with_alpha(th.panel_header, 0.85f * alpha);
		} else {
			fill_top = aida::ui::with_alpha(th.panel_bg, 0.6f * alpha);
			fill_bot = aida::ui::with_alpha(th.panel_bg, 0.6f * alpha);
		}
		ImU32 flat = aida::ui::mix(fill_top, fill_bot, 0.5f);
		dl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1), flat, 6.f);
		if (is_dead) {
			dl->AddRect(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
				IM_COL32(200, 80, 80, static_cast<int>(220.f * alpha)), 6.f, 0, 1.2f);
		} else if (is_active) {
			ui_anim::render_tab_underline_glow(dl, tx0 + 4.f, (tx1 - tx0) - 8.f,
				ty1 - 2.5f, alpha);
		} else {
			dl->AddRect(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
				aida::ui::with_alpha(th.border_subtle, 0.6f * alpha), 6.f, 0, 1.f);
		}

		float badge_x = tx0 + inner_pad;
		float badge_y = ty0 + (tab_h - badge_sz) * 0.5f;
		if (is_live) {
			ImU32 live_dot;
			ImU32 live_glow;
			if (is_dead) {
				live_dot = IM_COL32(120, 120, 120, static_cast<int>(255.f * alpha));
				live_glow = IM_COL32(80, 80, 80, static_cast<int>(60.f * alpha));
			} else {
				live_dot = IM_COL32(232, 80, 80, static_cast<int>(255.f * alpha));
				live_glow = IM_COL32(232, 80, 80, static_cast<int>(80.f * alpha));
			}
			float r = badge_sz * 0.36f;
			float cxr = badge_x + badge_sz * 0.5f;
			float cyr = badge_y + badge_sz * 0.5f;
			dl->AddCircleFilled(ImVec2(cxr, cyr), r + 2.f, live_glow);
			dl->AddCircleFilled(ImVec2(cxr, cyr), r, live_dot);
			if (is_dead) {
				dl->AddLine(ImVec2(cxr - r, cyr - r), ImVec2(cxr + r, cyr + r),
					IM_COL32(255, 110, 110, static_cast<int>(255.f * alpha)), 1.5f);
				dl->AddLine(ImVec2(cxr + r, cyr - r), ImVec2(cxr - r, cyr + r),
					IM_COL32(255, 110, 110, static_cast<int>(255.f * alpha)), 1.5f);
			}
		} else {
			ImU32 page_col = aida::ui::with_alpha(is_active ? th.accent_u32 : th.text_secondary, 0.9f * alpha);
			float px0 = badge_x + 2.f;
			float py0 = badge_y + 1.f;
			float px1 = badge_x + badge_sz - 3.f;
			float py1 = badge_y + badge_sz - 1.f;
			dl->AddRect(ImVec2(px0, py0), ImVec2(px1, py1), page_col, 2.f, 0, 1.4f);
			dl->AddLine(ImVec2(px0 + 2.f, py0 + 3.f), ImVec2(px1 - 2.f, py0 + 3.f), page_col, 1.f);
			dl->AddLine(ImVec2(px0 + 2.f, py0 + 6.f), ImVec2(px1 - 2.f, py0 + 6.f), page_col, 1.f);
			dl->AddLine(ImVec2(px0 + 2.f, py0 + 9.f), ImVec2(px1 - 3.f, py0 + 9.f), page_col, 1.f);
		}

		ImU32 text_col;
		if (is_dead) {
			text_col = IM_COL32(220, 160, 160, static_cast<int>(220.f * alpha));
		} else {
			text_col = is_active
				? aida::ui::with_alpha(th.text_primary, alpha)
				: aida::ui::with_alpha(th.text_secondary, (hov ? 1.f : 0.9f) * alpha);
		}
		float text_x = tx0 + inner_pad + badge_sz + badge_gap;
		float text_y = ty0 + (tab_h - ls.y) * 0.5f;
		dl->AddText(ImVec2(text_x, text_y), text_col, label.c_str());
		if (is_dead) {
			dl->AddLine(ImVec2(text_x, text_y + ls.y * 0.55f),
				ImVec2(text_x + ls.x, text_y + ls.y * 0.55f),
				text_col, 1.2f);
		}

		float cx0 = tx1 - inner_pad - close_btn_sz;
		float cy0 = ty0 + (tab_h - close_btn_sz) * 0.5f;
		float cx1 = cx0 + close_btn_sz;
		float cy1 = cy0 + close_btn_sz;
		bool close_hov = ImGui::IsMouseHoveringRect(ImVec2(cx0, cy0), ImVec2(cx1, cy1), false);
		if (close_hov) {
			dl->AddRectFilled(ImVec2(cx0, cy0), ImVec2(cx1, cy1),
				aida::ui::with_alpha(th.error, 0.5f * alpha), 3.f);
		}
		float pad_x = 3.f;
		dl->AddLine(ImVec2(cx0 + pad_x, cy0 + pad_x), ImVec2(cx1 - pad_x, cy1 - pad_x),
			aida::ui::with_alpha(th.text_secondary, alpha), 1.4f);
		dl->AddLine(ImVec2(cx1 - pad_x, cy0 + pad_x), ImVec2(cx0 + pad_x, cy1 - pad_x),
			aida::ui::with_alpha(th.text_secondary, alpha), 1.4f);

		if (!ui_input_gate::popup_blocks_background_input()) {
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				if (close_hov) close_intent = static_cast<int>(i);
				else if (hov)  switch_intent = static_cast<int>(i);
			}
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Right) && hov && !close_hov) {
				open_ctx_for = static_cast<int>(i);
			}
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Middle) && hov) {
				close_intent = static_cast<int>(i);
			}
		}

		if (hov && !close_hov) {
			if (is_live) {
				if (is_dead) {
					ImGui::SetTooltip("Live session (process exited)\nPID %u\n%s\nRight-click to reattach to a new PID or close.",
						sess->attached_pid,
						sess->filename.empty() ? "(unknown process)" : sess->filename.c_str());
				} else {
					ImGui::SetTooltip("Live session\nPID %u\n%s",
						sess->attached_pid,
						sess->filename.empty() ? "(unknown process)" : sess->filename.c_str());
				}
			} else {
				ImGui::SetTooltip("%s", sess->path.c_str());
			}
		}

		cursor_x = tx1 + gap;
	}

	{
		float plus_sz = 20.f;
		float plus_x0 = cursor_x + 2.f;
		float plus_y0 = ty0 + (tab_h - plus_sz) * 0.5f;
		float plus_x1 = plus_x0 + plus_sz;
		float plus_y1 = plus_y0 + plus_sz;
		if (plus_x1 < x + width - pad_outer) {
			bool plus_hov = ImGui::IsMouseHoveringRect(ImVec2(plus_x0, plus_y0), ImVec2(plus_x1, plus_y1), false);
			ImU32 plus_bg = aida::ui::with_alpha(plus_hov ? th.accent_u32 : th.bg_elevated, (plus_hov ? 0.65f : 0.4f) * alpha);
			dl->AddRectFilled(ImVec2(plus_x0, plus_y0), ImVec2(plus_x1, plus_y1), plus_bg, 4.f);
			float cxp = plus_x0 + plus_sz * 0.5f;
			float cyp = plus_y0 + plus_sz * 0.5f;
			ImU32 plus_col = aida::ui::with_alpha(th.text_primary, alpha);
			dl->AddLine(ImVec2(cxp - 6.f, cyp), ImVec2(cxp + 6.f, cyp), plus_col, 1.6f);
			dl->AddLine(ImVec2(cxp, cyp - 6.f), ImVec2(cxp, cyp + 6.f), plus_col, 1.6f);
			if (plus_hov && !ui_input_gate::popup_blocks_background_input()) {
				ImGui::SetTooltip("New session\nLeft-click: Open File...\nRight-click: Attach to Process...\nMiddle-click: Run...");
				if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::apply_open_file();
#else
					anti_tamper::webhook::write_log("file_dialog", "session_tab_plus(open) left_click");
					std::string fpath = disasm::open_file_dialog(g_hwnd);
					if (!fpath.empty()) {
						anti_tamper::webhook::write_log("file_dialog", (std::string("session_tab_plus(open) ok path=") + fpath).c_str());
						analysis_session::open_session(fpath);
					} else {
						anti_tamper::webhook::write_log("file_dialog", "session_tab_plus(open) cancelled");
					}
#endif
				} else if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
					globals::ui::process_attach_open = true;
				} else if (ImGui::IsMouseClicked(ImGuiMouseButton_Middle)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::record(aida::preview::shell_action_t::run_target, "session_tab_plus");
#else
					spawn_target_dialog::request_open();
#endif
				}
			}
		}
	}

	if (open_ctx_for >= 0) {
		ImGui::OpenPopup("##session_tab_ctx");
		ImGui::GetStateStorage()->SetInt(ImGui::GetID("##session_tab_ctx_idx"), open_ctx_for);
	}

	if (ImGui::BeginPopup("##session_tab_ctx")) {
		int ctx_idx = ImGui::GetStateStorage()->GetInt(ImGui::GetID("##session_tab_ctx_idx"), -1);
		if (ctx_idx >= 0 && ctx_idx < static_cast<int>(analysis_session::session_count())) {
			const auto sess = analysis_session::session_handle_at(static_cast<size_t>(ctx_idx));
			if (sess) {
				bool live = (sess->attached_pid != 0);
				bool dead = live && !session_health::is_alive(sess->attached_pid);
				if (ImGui::MenuItem("Switch to")) {
					switch_intent = ctx_idx;
				}
				if (live) {
					if (dead) {
						if (ImGui::MenuItem("Reattach to running process...")) {
							reattach_intent = ctx_idx;
						}
					}
					if (ImGui::MenuItem("Detach process")) {
						detach_intent = ctx_idx;
					}
				}
				ImGui::Separator();
				if (ImGui::MenuItem("Close session")) {
					close_intent = ctx_idx;
				}
			}
		}
		ImGui::EndPopup();
	}

	if (detach_intent >= 0) {
		analysis_session::close_session(static_cast<size_t>(detach_intent));
	} else if (close_intent >= 0) {
		analysis_session::close_session(static_cast<size_t>(close_intent));
	} else if (switch_intent >= 0) {
		size_t sw_idx = static_cast<size_t>(switch_intent);
		bool ok = analysis_session::switch_session(sw_idx);
		const char* sw_name = "(unknown)";
		const auto sw_sess = analysis_session::session_handle_at(sw_idx);
		if (sw_sess) {
			sw_name = sw_sess->filename.empty()
				? (sw_sess->path.empty() ? "(unnamed)" : sw_sess->path.c_str())
				: sw_sess->filename.c_str();
		}
		char sw_buf[700];
		_snprintf_s(sw_buf, sizeof(sw_buf), _TRUNCATE,
			"session_switch idx=%zu name=%s ok=%d", sw_idx, sw_name, ok ? 1 : 0);
		anti_tamper::webhook::write_log("chrome", sw_buf);
		if (ok) {
			if (const auto workspace = analysis_session::active_workspace()) {
				globals::ui::active_center_view =
					workspace->identity().target_kind() ==
						aida::analysis::target_kind_t::static_file
					? center_view_t::workbench
					: center_view_t::disassembly;
			}
		}
	} else if (reattach_intent >= 0) {
		analysis_session::close_session(static_cast<size_t>(reattach_intent));
		globals::ui::process_attach_open = true;
	}
}

void helpers::render_title()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=entry_before_section\n";
#endif
	g_render_section = "entry";
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=entry_after_section\n";
#endif
	ImVec2 compatibility_position(0.0f, 0.0f);
	ImVec2 compatibility_size(0.0f, 0.0f);
	const bool compatibility_active = aida::ui::ide_shell::compatibility_content_rect(
		compatibility_position, compatibility_size);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=compatibility_rect active="
		<< (compatibility_active ? 1 : 0) << " size=" << compatibility_size.x << "x"
		<< compatibility_size.y << "\n";
#endif
	struct compatibility_geometry_scope_t {
		bool active;
		float width;
		float height;
		~compatibility_geometry_scope_t()
		{
			if (active) {
				globals::ui::window_w = width;
				globals::ui::window_h = height;
			}
		}
	} compatibility_geometry_scope{
		compatibility_active,
		globals::ui::window_w,
		globals::ui::window_h};
	float dt = ImGui::GetIO().DeltaTime;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=before_controls_access dt=" << dt << "\n";
	{
		auto& preview_controls = aida::preview::controls();
		std::cerr << "[AIDA_PREVIEW] render_title stage=controls_access revision="
			<< preview_controls.revision << "\n";
		static std::uint64_t applied_preview_revision = preview_controls.revision;
		std::cerr << "[AIDA_PREVIEW] render_title stage=controls_revision previous="
			<< applied_preview_revision << "\n";
		if (applied_preview_revision != preview_controls.revision) {
			std::cerr << "[AIDA_PREVIEW] render_title stage=controls_apply\n";
			applied_preview_revision = preview_controls.revision;
			menu_bar::open_menu = preview_controls.open_menu;
			menu_bar::any_open = preview_controls.open_menu >= 0;
			if (preview_controls.center_view >= 0 && preview_controls.center_view <= static_cast<int>(center_view_t::workbench))
				globals::ui::active_center_view = static_cast<center_view_t>(preview_controls.center_view);
			if (preview_controls.bottom_tab >= 0 && preview_controls.bottom_tab < static_cast<int>(bottom_tab_t::COUNT)) {
				const char* view_id = preview_controls.bottom_tab == static_cast<int>(bottom_tab_t::mcp_log)
					? "view.mcp_log" : preview_controls.bottom_tab == static_cast<int>(bottom_tab_t::driver_log)
					? "view.driver_log" : preview_controls.bottom_tab == static_cast<int>(bottom_tab_t::sandbox_log)
					? "view.sandbox_log" : preview_controls.bottom_tab == static_cast<int>(bottom_tab_t::terminal)
					? "view.terminal" : "view.output";
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t(view_id));
			}
			conversations::browser_open = preview_controls.chat_history_open;
			globals::ui::process_attach_open = preview_controls.process_dialog_open;
			globals::ui::driver_status_open = preview_controls.driver_dialog_open;
			globals::ui::shortcuts_dialog_open = preview_controls.shortcuts_dialog_open;
		}
	}
	std::cerr << "[AIDA_PREVIEW] render_title stage=controls_scope_complete\n";
#endif
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=preview_controls_ready\n";
#endif
	const auto active_workspace_handle = analysis_session::active_workspace();
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=workspace_handle_ready\n";
	#endif
	restore_workbench_center_view(active_workspace_handle);
	const auto active_workspace_context = disasm_view::capture_workspace(active_workspace_handle);
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=workspace_context_ready\n";
	#endif
	globals::ui::load_timer += dt;
	file_menu_deferred::run_pending();
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=deferred_actions_ready\n";
	#endif
	aida::ui::application_ui::shell_callbacks_t application_callbacks;
	application_callbacks.open_file = [] {
		file_menu_deferred::request(file_menu_deferred::action_t::open_file);
	};
	application_callbacks.open_folder = [] {
		file_menu_deferred::request(file_menu_deferred::action_t::open_folder);
	};
	application_callbacks.save_as = [] {
		char buf[MAX_PATH] = {};
		if (!code_editor::filename.empty())
			strncpy_s(buf, code_editor::filename.c_str(), _TRUNCATE);
		static const char k_save_as_filter[] = "All files (*.*)\0*.*\0\0";
		if (!trusted_show_save_file(g_hwnd, "Save As", k_save_as_filter, nullptr,
			buf, sizeof(buf), "file_menu_save_as"))
			return;
		code_editor::filepath = buf;
		std::string filename = buf;
		const auto separator = filename.find_last_of("\\/");
		if (separator != std::string::npos)
			filename = filename.substr(separator + 1);
		code_editor::filename = filename;
		if (file_tabs::active_tab >= 0 &&
			static_cast<std::size_t>(file_tabs::active_tab) < file_tabs::tabs.size()) {
			auto& tab = file_tabs::tabs[static_cast<std::size_t>(file_tabs::active_tab)];
			tab.filepath = code_editor::filepath;
			tab.filename = code_editor::filename;
		}
		code_editor::save();
	};
	application_callbacks.exit_application = [] {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		POINT cursor{};
		GetCursorPos(&cursor);
		diag::log_tagged_critical_fmt("chrome",
			"file_menu_exit_clicked hwnd=0x%llX cursor=%ld,%ld",
			(unsigned long long)reinterpret_cast<UINT_PTR>(g_hwnd), cursor.x, cursor.y);
#endif
		request_chrome_shutdown_from_render("file_menu_exit", "chrome.file_menu_exit");
	};
	application_callbacks.load_binary = [] {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::apply_open_file();
#else
		std::string fpath = disasm::open_file_dialog(g_hwnd);
		if (fpath.empty()) {
			anti_tamper::webhook::write_log("chrome", "load_pe cancelled");
			return;
		}
		const std::string fpath_copy = fpath;
		const bool posted = aida::ui_thread::post([fpath_copy]() {
			if (!aida::ui_thread::require_owner("analysis_session", "open_session", "load_pe_menu"))
				return;
			const bool ok = analysis_session::open_session(fpath_copy);
			char buf[700];
			if (ok) {
				_snprintf_s(buf, sizeof(buf), _TRUNCATE, "load_pe ok path=%s", fpath_copy.c_str());
			} else {
				const char* err = analysis_session::last_error();
				_snprintf_s(buf, sizeof(buf), _TRUNCATE, "load_pe failed path=%s err=%s",
					fpath_copy.c_str(), err ? err : "(none)");
			}
			anti_tamper::webhook::write_log("chrome", buf);
		}, "analysis_session", "open_session", "load_pe_menu");
		if (!posted) {
			diag::log_tagged_critical_fmt("analysis_session",
				"load_pe_dispatch_failed tid=%lu ui_tid=%lu path=%.260s",
				static_cast<unsigned long>(aida::shell_platform::thread_id()),
				static_cast<unsigned long>(aida::ui_thread::owner_tid()),
				fpath_copy.c_str());
		}
#endif
	};
	application_callbacks.attach_process = [] { globals::ui::process_attach_open = true; };
	application_callbacks.open_settings = [] {
		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.settings"));
	};
	application_callbacks.toggle_maximize = [] { shell_toggle_maximize(); };
	application_callbacks.decompile_or_focus_pseudocode_capability =
		[active_workspace_handle, active_workspace_context] {
			if (active_workspace_handle &&
				active_workspace_handle->identity().target_kind() ==
					aida::analysis::target_kind_t::static_file &&
				globals::ui::active_center_view == center_view_t::workbench) {
				aida::workbench::workbench_shell_workspace_context_t context;
				if (!aida::workbench::workbench_shell_runtime_t::instance()
						.workspace_context(active_workspace_handle, context) ||
					!context.pseudocode_document)
					return aida::ui::capability_state_t::unavailable(
						"The active Workbench has no pseudocode provider");
				const auto* active = workbench_document(context.persistence,
					context.persistence.active_document);
				if (!active)
					return aida::ui::capability_state_t::unavailable(
						"Select an analysis document and address first");
				if (active->local_state.selection.has_address ||
					(active->identity.kind == aida::workbench::document_kind_t::pseudocode &&
					 active->identity.has_address))
					return aida::ui::capability_state_t::available();
				const auto& encoded = active->identity.provider_key != "analysis"
					? active->identity.provider_key
					: active->local_state.selection.entity_key;
				const auto parsed = aida::workbench::pseudocode_document::
					parse_pseudocode_entity_locator(encoded);
				const auto canonical = parsed ? aida::workbench::pseudocode_document::
					canonical_pseudocode_entity_locator(*parsed) : std::nullopt;
				return canonical && *canonical == encoded
					? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(
						"Select an analysis address or managed entity first");
			}
			return pseudocode_view::has_active_tab(active_workspace_context)
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(
					"Open a binary with an available Pseudocode document first");
		};
	application_callbacks.decompile_or_focus_pseudocode =
		[active_workspace_handle, active_workspace_context] {
			if (active_workspace_handle &&
				active_workspace_handle->identity().target_kind() ==
					aida::analysis::target_kind_t::static_file &&
				globals::ui::active_center_view == center_view_t::workbench) {
				aida::workbench::workbench_shell_workspace_context_t context;
				const auto loaded = aida::workbench::workbench_shell_runtime_t::instance()
					.workspace_context(active_workspace_handle, context);
				const auto* active = loaded ? workbench_document(context.persistence,
					context.persistence.active_document) : nullptr;
				const auto address = active && active->local_state.selection.has_address
					? active->local_state.selection.address
					: active && active->identity.kind ==
						aida::workbench::document_kind_t::pseudocode && active->identity.has_address
						? active->identity.address : 0;
				std::optional<aida::analysis::decompiler_entity_locator_t> managed_locator;
				std::string managed_identity;
				if (active) {
					const auto& encoded = active->identity.provider_key != "analysis"
						? active->identity.provider_key
						: active->local_state.selection.entity_key;
					const auto parsed = aida::workbench::pseudocode_document::
						parse_pseudocode_entity_locator(encoded);
					const auto canonical = parsed ? aida::workbench::pseudocode_document::
						canonical_pseudocode_entity_locator(*parsed) : std::nullopt;
					if (canonical && *canonical == encoded) {
						managed_locator = *parsed;
						managed_identity = *canonical;
					}
				}
				if ((address == 0 && !managed_locator) || !context.pseudocode_document)
					return aida::ui::action_handler_result_t::failed(
						"The active Workbench selection cannot be decompiled");
				aida::workbench::workbench_shell_workspace_context_t activated;
				aida::workbench::workbench_error_t opened;
				if (managed_locator) {
					opened = aida::workbench::workbench_shell_runtime_t::instance()
						.activate_entity_document(active_workspace_handle,
							aida::workbench::document_kind_t::pseudocode,
							managed_identity, activated);
				} else {
					const auto document_address = active && active->identity.kind ==
						aida::workbench::document_kind_t::pseudocode && active->identity.has_address
						? active->identity.address : address;
					opened = aida::workbench::workbench_shell_runtime_t::instance()
						.activate_document(active_workspace_handle,
							aida::workbench::document_kind_t::pseudocode,
							document_address, activated);
				}
				if (!opened || !activated.pseudocode_document)
					return aida::ui::action_handler_result_t::failed(
						"The Pseudocode document could not be activated");
				aida::workbench::pseudocode_document::pseudocode_request_t request;
				aida::workbench::pseudocode_document::pseudocode_error_t resolved;
				if (managed_locator) {
					resolved = activated.pseudocode_document->resolve_request(*managed_locator,
						aida::analysis::decompiler_profile_id_t::balanced,
						aida::workbench::pseudocode_document::k_pseudocode_document_default_timeout_ms,
						request);
				} else {
					resolved = activated.pseudocode_document->resolve_request(address,
						aida::analysis::decompiler_profile_id_t::balanced,
						aida::workbench::pseudocode_document::k_pseudocode_document_default_timeout_ms,
						request);
				}
				const auto requested = resolved ? activated.pseudocode_document->request(request) : resolved;
				if (requested || requested.code == aida::workbench::pseudocode_document::
					pseudocode_error_code_t::request_in_progress) {
					static_cast<void>(activated.pseudocode_document->activate(request));
					diag::log_tagged_fmt("ui", "workbench_f5 address=0x%llX managed=%d ok=%d code=%u",
						static_cast<unsigned long long>(address), managed_locator ? 1 : 0,
						requested ? 1 : 0, static_cast<unsigned>(requested.code));
					return aida::ui::action_handler_result_t::completed();
				}
				return aida::ui::action_handler_result_t::failed(
					"The decompiler rejected the active selection");
			}
			if (pseudocode_view::has_active_tab(active_workspace_context)) {
				globals::ui::active_center_view = center_view_t::pseudocode;
				diag::log_tagged("ui", "view_switch to=pseudocode hotkey=F5");
				return aida::ui::action_handler_result_t::completed();
			}
			return aida::ui::action_handler_result_t::failed(
				"No Pseudocode document is available for the active workspace");
		};
	application_callbacks.open_driver_status = [] { globals::ui::driver_status_open = true; };
	application_callbacks.new_chat = [] { conversations::new_chat(); };
	application_callbacks.open_shortcuts = [] {
		globals::ui::shortcuts_dialog_open = true;
		anti_tamper::webhook::write_log("chrome", "shortcuts_popup open=true source=action");
	};
	application_callbacks.persist_workspace = [] {
		g_sa_settings_request_save();
	};
	application_callbacks.action_executed = [](const char* action_id) {
		diag::log_tagged_fmt("ui", "action_executed id=%s", action_id ? action_id : "<null>");
	};
	aida::ui::application_ui::configure_shell_callbacks(std::move(application_callbacks));
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=shell_callbacks_ready\n";
	#endif
	aida::ui::application_ui::begin_frame();
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=application_frame_ready\n";
	#endif

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static bool bg_completed = false;
	if (!bg_completed && globals::ui::bg_init_done && globals::ui::bg_init_done->load(std::memory_order_acquire)) {
		bg_completed = true;
	}
#endif

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	g_render_section = "inline_checks";
	{
		g_render_section = "inline_checks_cross_validation";
		static uint64_t s_frame_ctr = 0;
		standalone_license::cross_validation_sweep(static_cast<int>(s_frame_ctr++));
	}

	{
		g_render_section = "inline_checks_anti_tamper_fast";
		uint64_t tok = anti_tamper::run_inline_check(anti_tamper::CHECK_FAST);
		standalone_license::fold_integrity_token(tok);
		static uint64_t s_inline_log_ctr = 0;
		++s_inline_log_ctr;

		if ((s_inline_log_ctr % 1000) == 0) {
			auto& rt = anti_tamper::state::get();
			const bool heavy_integrity_ready =
				!rt.driver_hardening_active.load(std::memory_order_acquire) &&
				(!rt.license_pending_activation.load(std::memory_order_acquire) ||
					rt.activation_hardening_done.load(std::memory_order_acquire)) &&
				standalone_license::is_arc_loaded() &&
				!standalone_license::is_arc_download_in_progress();
			if (heavy_integrity_ready) {
				(void)submit_helpers_executor_task(
					"anti_tamper",
					"anti_tamper.code_integrity_check",
					aida::infra::executor::domain_t::security_liveness,
					"security_liveness",
					[] {
						try {
							anti_tamper::run_inline_check(anti_tamper::CHECK_CODE_INTEGRITY);
						} catch (...) {
						}
					});
			}
		}
	}

	{
		g_render_section = "inline_checks_gate_ui_render_loop";
		uint64_t gt = standalone_license::inline_gate_check(
			standalone_license::gate_ui_render_loop);
		(void)standalone_license::verify_gate_token(
			standalone_license::gate_ui_render_loop, gt);
	}

	{
		g_render_section = "inline_checks_runtime_lock_state";
		const bool runtime_locked = anti_tamper::state::get().violation_latched.load(std::memory_order_acquire);
		const bool full_test_running = test_all_features::is_running();
		const bool canonical_valid = standalone_license::is_valid();
		static bool s_runtime_lock_logged = false;
		static bool s_full_test_validity_bridge_logged = false;
		if (runtime_locked) {
			std::string reason;
			std::string detail;
			{
				auto& rt = anti_tamper::state::get();
				std::lock_guard<std::mutex> lk(rt.mtx);
				reason = rt.violation_reason;
				detail = rt.violation_detail;
			}
			license::validated = false;
			license::checking = false;
			license::activation_worker_active.store(false, std::memory_order_release);
			license::check_failed = false;
			license::error_msg = runtime_lock_user_message(reason, detail);
			s_full_test_validity_bridge_logged = false;
			if (!s_runtime_lock_logged) {
				diag::log_tagged_fmt("license",
					"DIAG_DIALOG_SUPPRESSED_LICENSE_INPUT source=render_title reason=%.160s",
					reason.c_str());
				s_runtime_lock_logged = true;
			}
		} else if (canonical_valid) {
			const bool recovered = !license::validated || license::check_failed || license::checking;
			license::validated = true;
			license::checking = false;
			license::activation_worker_active.store(false, std::memory_order_release);
			license::check_failed = false;
			license::error_msg.clear();
			s_runtime_lock_logged = false;
			s_full_test_validity_bridge_logged = false;
			if (recovered)
				diag::log_tagged("license", "DIAG_DIALOG_RECOVERED_RUNTIME_VALIDITY");
		} else if (license::preserve_valid_state(runtime_locked, full_test_running)) {
			license::checking = false;
			license::activation_worker_active.store(false, std::memory_order_release);
			license::check_failed = false;
			license::error_msg.clear();
			s_runtime_lock_logged = false;
			if (!s_full_test_validity_bridge_logged) {
				diag::log_tagged_fmt("license",
					"DIAG_DIALOG_SUPPRESSED_TRANSIENT_INVALID source=render_title full_test=1 arc=%d frame=%d",
					standalone_license::is_arc_loaded() ? 1 : 0,
					ImGui::GetFrameCount());
				s_full_test_validity_bridge_logged = true;
			}
		} else {
			s_full_test_validity_bridge_logged = false;
		}
	}

	const bool runtime_locked_for_ready = anti_tamper::state::get().violation_latched.load(std::memory_order_acquire);
	const bool runtime_ready = license::runtime_ready(runtime_locked_for_ready, test_all_features::is_running());
#else
	const bool runtime_ready = aida::preview::runtime_ready();
#endif
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=runtime_ready value=" << (runtime_ready ? 1 : 0) << "\n";
	#endif

	g_render_section = "theme_resolve";
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=theme_resolve_begin active="
		<< themes::active << " count=" << themes::count
		<< " custom_active=" << custom_themes::active_custom
		<< " custom_count=" << custom_themes::list.size() << "\n";
	#endif
	if (custom_themes::active_custom >= 0 &&
		static_cast<std::size_t>(custom_themes::active_custom) < custom_themes::list.size()) {
		auto& ct = custom_themes::list[static_cast<std::size_t>(custom_themes::active_custom)];
		snprintf(themes::resolved_name_buf, sizeof(themes::resolved_name_buf), "%s", ct.name.c_str());
		themes::resolved.name          = themes::resolved_name_buf;
		themes::resolved.accent        = ImVec4(ct.accent[0], ct.accent[1], ct.accent[2], 1.f);
		themes::resolved.bg_base       = ct.bg_base;
		themes::resolved.panel_bg      = ct.panel_bg;
		themes::resolved.panel_header  = ct.panel_header;
		themes::resolved.title_bar     = ct.title_bar;
		themes::resolved.text_primary  = ct.text_primary;
		themes::resolved.text_secondary= ct.text_secondary;
		themes::resolved.text_dim      = ct.text_dim;
		themes::resolved.acrylic_color = ct.acrylic_color;
	} else {
		themes::resolved = themes::presets[themes::active];
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=theme_preset_resolved name="
		<< (themes::resolved.name ? themes::resolved.name : "<null>") << "\n";
	#endif
	globals::ui::accent = aida::ui::resolved().accent;
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=theme_preapply_accent_ready\n";
	#endif

	{
		static int s_last_applied_theme_idx = -1;
		static int s_last_applied_custom_idx = -2;
		int target_custom = custom_themes::active_custom;
		int target_idx = themes::active;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=theme_apply_check target="
			<< target_idx << " custom=" << target_custom
			<< " last=" << s_last_applied_theme_idx
			<< " last_custom=" << s_last_applied_custom_idx << "\n";
		#endif
		if (target_custom != s_last_applied_custom_idx || target_idx != s_last_applied_theme_idx) {
			bool first_apply = (s_last_applied_theme_idx == -1 && s_last_applied_custom_idx == -2);
			s_last_applied_custom_idx = target_custom;
			s_last_applied_theme_idx  = target_idx;
			if (target_custom >= 0 &&
				static_cast<std::size_t>(target_custom) < custom_themes::list.size()) {
				auto& ct = custom_themes::list[static_cast<std::size_t>(target_custom)];
				aida::ui::theme_t base = aida::ui::make_theme_for_index(target_idx);
				base.accent          = ImVec4(ct.accent[0], ct.accent[1], ct.accent[2], 1.f);
				int ar = (int)(ct.accent[0] * 255.f);
				int ag = (int)(ct.accent[1] * 255.f);
				int ab = (int)(ct.accent[2] * 255.f);
				base.accent_u32      = IM_COL32(ar, ag, ab, 255);
				base.accent_hover    = IM_COL32(
					(std::min)(ar + 24, 255),
					(std::min)(ag + 24, 255),
					(std::min)(ab + 24, 255), 255);
				base.accent_dim      = IM_COL32(ar, ag, ab, 130);
				base.accent_glow     = IM_COL32(ar, ag, ab, 50);
				base.accent_grad_top = IM_COL32(
					(std::min)(ar + 18, 255),
					(std::min)(ag + 14, 255),
					(std::min)(ab + 14, 255), 255);
				base.accent_grad_bot = IM_COL32(
					(std::max)(ar - 22, 0),
					(std::max)(ag - 18, 0),
					(std::max)(ab - 18, 0), 255);
				base.border_focus    = IM_COL32(ar, ag, ab, 210);
				base.selection       = IM_COL32(ar, ag, ab, 70);
				base.selection_strong= IM_COL32(ar, ag, ab, 130);
				base.bg_base         = ct.bg_base;
				base.panel_bg        = ct.panel_bg;
				base.panel_header    = ct.panel_header;
				base.title_bar       = ct.title_bar;
				base.text_primary    = ct.text_primary;
				base.text_secondary  = ct.text_secondary;
				base.text_dim        = ct.text_dim;
				base.acrylic_color   = ct.acrylic_color;
				base.name            = ct.name;
				if (first_apply) aida::ui::apply_immediate(base);
				else             aida::ui::apply(base);
			} else {
				#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				std::cerr << "[AIDA_PREVIEW] render_title stage=theme_apply_builtin_begin first="
					<< (first_apply ? 1 : 0) << "\n";
				#endif
				aida::ui::apply_for_index(target_idx, !first_apply);
				#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				std::cerr << "[AIDA_PREVIEW] render_title stage=theme_apply_builtin_complete\n";
				#endif
			}
		}
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=theme_apply_scope_complete\n";
	#endif
	globals::ui::accent = aida::ui::resolved().accent;

	const auto& shell_theme = aida::ui::resolved();
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=shell_theme_resolved\n";
	#endif
	const int th_pb_r = (shell_theme.panel_bg >>  0) & 0xFF;
	const int th_pb_g = (shell_theme.panel_bg >>  8) & 0xFF;
	const int th_pb_b = (shell_theme.panel_bg >> 16) & 0xFF;
	const int th_bb_r = (shell_theme.bg_base >>  0) & 0xFF;
	const int th_bb_g = (shell_theme.bg_base >>  8) & 0xFF;
	const int th_bb_b = (shell_theme.bg_base >> 16) & 0xFF;
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=shell_theme_channels_ready panel="
		<< th_pb_r << ',' << th_pb_g << ',' << th_pb_b
		<< " base=" << th_bb_r << ',' << th_bb_g << ',' << th_bb_b << "\n";
	#endif


	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=agent_shortcuts_begin\n";
	#endif
	chat_handle_agent_shortcuts();
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=agent_shortcuts_complete\n";
	#endif


	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=global_shortcuts_check want_text="
		<< (ImGui::GetIO().WantTextInput ? 1 : 0) << "\n";
	#endif
	if (!ImGui::GetIO().WantTextInput) {
		aida::ui::application_ui::process_global_shortcuts();

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const bool ctrl = ImGui::GetIO().KeyCtrl;
		const bool shift = ImGui::GetIO().KeyShift;
		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_T, false)) {
			test_all_features::post_hotkey_trigger("imgui_ctrl_shift_t");
		}
#endif



	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=global_shortcuts_complete\n";
	#endif

	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=legacy_theme_handles_begin loaded="
		<< (helpers::themes_loaded ? 1 : 0) << "\n";
	#endif
	if (!helpers::themes_loaded) {
		helpers::theme_kaneki = nullptr;
		helpers::theme_rias = nullptr;
		helpers::theme_nagi = nullptr;
		helpers::theme_mio = nullptr;
		helpers::themes_loaded = true;
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=legacy_theme_handles_complete\n";
	#endif


#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (!g_bg_art_loaded && g_pd3dDevice) {
		icon_loader::load(background, 8640831, &g_bg_art_srv,
			&g_bg_art_w, &g_bg_art_h, false);
		g_bg_art_loaded = true;
	}

	if (!g_aida_logo_loaded && g_pd3dDevice) {
		icon_loader::load(aidalogo, 1273853, &g_aida_logo_srv,
			&g_aida_logo_w, &g_aida_logo_h, false);
		g_aida_logo_loaded = true;
	}

	std::string active_custom_icon_path;
	if (custom_themes::active_custom >= 0 &&
		static_cast<std::size_t>(custom_themes::active_custom) < custom_themes::list.size()) {
		active_custom_icon_path = custom_themes::list[
			static_cast<std::size_t>(custom_themes::active_custom)].icon_file_path;
	} else if (!g_sa_settings.custom_icon_path.empty()) {
		active_custom_icon_path = g_sa_settings.custom_icon_path;
	}

	static std::string s_last_rejected_custom_icon_path;
	static std::string s_last_checked_custom_icon_path;
	static bool s_last_checked_custom_icon_ok = false;
	static uint64_t s_last_checked_custom_icon_ms = 0;
	if (!active_custom_icon_path.empty()) {
		const uint64_t now_ms = static_cast<uint64_t>(aida::shell_platform::tick_ms());
		if (active_custom_icon_path != s_last_checked_custom_icon_path ||
			now_ms - s_last_checked_custom_icon_ms >= 5000) {
			uint64_t icon_file_size = 0;
			DWORD icon_file_attrs = 0;
			DWORD icon_file_error = ERROR_SUCCESS;
			s_last_checked_custom_icon_path = active_custom_icon_path;
			s_last_checked_custom_icon_ms = now_ms;
			s_last_checked_custom_icon_ok = custom_icon_path_render_safe(active_custom_icon_path, icon_file_size, icon_file_attrs, icon_file_error);
			if (!s_last_checked_custom_icon_ok &&
				s_last_rejected_custom_icon_path != active_custom_icon_path) {
				diag::log_tagged_critical_fmt("render",
					"custom_theme_icon_rejected path_len=%zu gle=%lu attrs=0x%08lX size=%llu",
					active_custom_icon_path.size(),
					static_cast<unsigned long>(icon_file_error),
					static_cast<unsigned long>(icon_file_attrs),
					static_cast<unsigned long long>(icon_file_size));
				s_last_rejected_custom_icon_path = active_custom_icon_path;
			}
		}
		if (!s_last_checked_custom_icon_ok)
			active_custom_icon_path.clear();
	}

	if (active_custom_icon_path.empty() && g_custom_theme_icon_srv) {
		g_custom_theme_icon_srv->Release();
		g_custom_theme_icon_srv = nullptr;
		g_custom_theme_icon_w = g_custom_theme_icon_h = 0;
		g_custom_theme_icon_path.clear();
	}

	if (!active_custom_icon_path.empty() &&
	    active_custom_icon_path != g_custom_theme_icon_path &&
	    g_pd3dDevice) {
		if (g_custom_theme_icon_srv) {
			g_custom_theme_icon_srv->Release();
			g_custom_theme_icon_srv = nullptr;
		}
		g_custom_theme_icon_w = g_custom_theme_icon_h = 0;
		if (icon_loader::load_file(active_custom_icon_path.c_str(), &g_custom_theme_icon_srv,
			&g_custom_theme_icon_w, &g_custom_theme_icon_h, false))
			g_custom_theme_icon_path = active_custom_icon_path;
		else
			g_custom_theme_icon_path.clear();
	}
#endif

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=loading_query_begin\n";
	bool loading = aida::preview::loading();
	std::cerr << "[AIDA_PREVIEW] render_title stage=loading_query_complete value="
		<< (loading ? 1 : 0) << "\n";
#else
	bool loading = !bg_completed || globals::ui::load_timer < 3.0f;
#endif

	g_render_section = loading ? "loading_screen" : "post_loading";
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=post_loading_section_assigned\n";
	#endif
	{
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static bool s_loading_wait_logged = false;
		static float s_loading_wait_last_log = 0.f;
		if (loading && globals::ui::load_timer >= 5.0f &&
		    (!s_loading_wait_logged || (globals::ui::load_timer - s_loading_wait_last_log) >= 5.0f)) {
			s_loading_wait_logged = true;
			s_loading_wait_last_log = globals::ui::load_timer;
			auto& rt = anti_tamper::state::get();
			bool bg_done_value = globals::ui::bg_init_done &&
				globals::ui::bg_init_done->load(std::memory_order_acquire);
			diag::log_tagged_critical_fmt("render",
				"loading_screen_wait timer=%.2f bg_completed=%d bg_done_ptr=%d bg_done=%d bg_step=%d bg_total=%d license_validated=%d canonical_valid=%d arc_loaded=%d arc_downloading=%d pending_activation=%d at_initialized=%d driver_hardening=%d hardening_active=%d violation=%d",
				globals::ui::load_timer,
				bg_completed ? 1 : 0,
				globals::ui::bg_init_done ? 1 : 0,
				bg_done_value ? 1 : 0,
				globals::ui::bg_init_step.load(std::memory_order_acquire),
				globals::ui::bg_init_total.load(std::memory_order_acquire),
				license::validated ? 1 : 0,
				standalone_license::is_valid() ? 1 : 0,
				standalone_license::is_arc_loaded() ? 1 : 0,
				standalone_license::is_arc_download_in_progress() ? 1 : 0,
				rt.license_pending_activation.load(std::memory_order_acquire) ? 1 : 0,
				rt.initialized.load(std::memory_order_acquire) ? 1 : 0,
				rt.driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
				rt.driver_hardening_active.load(std::memory_order_acquire) ? 1 : 0,
				rt.violation_latched.load(std::memory_order_acquire) ? 1 : 0);
		}
		if (!loading) {
			s_loading_wait_logged = false;
			s_loading_wait_last_log = globals::ui::load_timer;
		}
#endif
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=loading_diagnostics_complete\n";
	#endif

	if (!loading)
	{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=preview_geometry_begin display="
			<< ImGui::GetIO().DisplaySize.x << 'x' << ImGui::GetIO().DisplaySize.y << "\n";
		globals::ui::window_w = ImGui::GetIO().DisplaySize.x > 0.f ? ImGui::GetIO().DisplaySize.x : globals::ui::window_w;
		globals::ui::window_h = ImGui::GetIO().DisplaySize.y > 0.f ? ImGui::GetIO().DisplaySize.y : globals::ui::window_h;
		std::cerr << "[AIDA_PREVIEW] render_title stage=preview_geometry_complete window="
			<< globals::ui::window_w << 'x' << globals::ui::window_h << "\n";
#else
		float tw, th;
		if (!globals::ui::welcome_done) {
			tw = 560.f; th = 360.f;
		} else if (!runtime_ready) {
			tw = 620.f; th = 540.f;
		} else {
			MONITORINFO mi = { sizeof(mi) };
			GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi);
			tw = static_cast<float>(mi.rcWork.right - mi.rcWork.left) * 0.75f;
			th = static_cast<float>(mi.rcWork.bottom - mi.rcWork.top) * 0.75f;
		}


		static bool initial_grow_done = false;
		if (!initial_grow_done) {
			if (globals::ui::welcome_done && runtime_ready) {
				initial_grow_done = true;
				MONITORINFO mi2 = { sizeof(mi2) };
				GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi2);
				float mw = static_cast<float>(mi2.rcWork.right - mi2.rcWork.left);
				float mh = static_cast<float>(mi2.rcWork.bottom - mi2.rcWork.top);
				float normal_w = mw * 0.75f;
				float normal_h = mh * 0.75f;
				if (normal_w < 1000.f && mw >= 1000.f) normal_w = (std::min)(mw, 1000.f);
				if (normal_h < 600.f && mh >= 600.f) normal_h = (std::min)(mh, 600.f);
				int restore_x = static_cast<int>(static_cast<float>(mi2.rcWork.left) + (mw - normal_w) * 0.5f);
				int restore_y = static_cast<int>(static_cast<float>(mi2.rcWork.top) + (mh - normal_h) * 0.5f);
				globals::ui::pre_max_x = static_cast<float>(restore_x);
				globals::ui::pre_max_y = static_cast<float>(restore_y);
				globals::ui::pre_max_w = normal_w;
				globals::ui::pre_max_h = normal_h;
				WINDOWPLACEMENT wp = { sizeof(wp) };
				if (::GetWindowPlacement(g_hwnd, &wp)) {
					wp.flags = 0;
					wp.showCmd = SW_SHOWMAXIMIZED;
					wp.rcNormalPosition.left   = restore_x;
					wp.rcNormalPosition.top    = restore_y;
					wp.rcNormalPosition.right  = restore_x + static_cast<int>(normal_w);
					wp.rcNormalPosition.bottom = restore_y + static_cast<int>(normal_h);
					::SetWindowPlacement(g_hwnd, &wp);
				}
				{
					RECT cr{};
					::GetClientRect(g_hwnd, &cr);
					float cw = static_cast<float>(cr.right - cr.left);
					float chh = static_cast<float>(cr.bottom - cr.top);
					if (cw >= 200.f && chh >= 200.f) {
						globals::ui::window_w = cw;
						globals::ui::window_h = chh;
					} else {
						globals::ui::window_w = normal_w;
						globals::ui::window_h = normal_h;
					}
					static bool disk_initial_geometry_logged = false;
					if (!disk_initial_geometry_logged) {
						disk_initial_geometry_logged = true;
						diag::log_tagged_critical_fmt("render",
							"disk_initial_ide_geometry target=%d,%d work=%d,%d cw=%d ch=%d maximized=1",
							static_cast<int>(normal_w),
							static_cast<int>(normal_h),
							static_cast<int>(mw),
							static_cast<int>(mh),
							static_cast<int>(cw),
							static_cast<int>(chh));
					}
				}
			} else {
				float spd = 12.f;
				float dw = tw - globals::ui::window_w;
				float dh = th - globals::ui::window_h;
				globals::ui::window_w += dw * std::min(spd * dt, 1.f);
				globals::ui::window_h += dh * std::min(spd * dt, 1.f);


				if (std::abs(dw) < 2.f) globals::ui::window_w = tw;
				if (std::abs(dh) < 2.f) globals::ui::window_h = th;

				if (globals::ui::load_timer > 5.0f && !globals::ui::welcome_done) {
					globals::ui::window_w = tw;
					globals::ui::window_h = th;
				}
			}
		}
#endif
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=post_loading_geometry_complete\n";
	#endif


	bool welcome_ready = !loading && globals::ui::window_w >= 470.f && globals::ui::window_h >= 270.f;
	bool ui_ready      = globals::ui::window_w >= 1000.f && globals::ui::window_h >= 600.f;
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=readiness_computed welcome="
		<< (welcome_ready ? 1 : 0) << " ui=" << (ui_ready ? 1 : 0)
		<< " welcome_done=" << (globals::ui::welcome_done ? 1 : 0) << "\n";
	#endif

	if (ui_ready && globals::ui::welcome_done && runtime_ready)
	{
		static float raw = 0.f;
		raw += dt;
		if (raw > 1.f) raw = 1.f;
		globals::ui::ui_alpha = raw * raw;
	}


	if (compatibility_active) {
		globals::ui::window_w = compatibility_size.x;
		globals::ui::window_h = compatibility_size.y;
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=legacy_root_geometry_ready pos="
		<< compatibility_position.x << ',' << compatibility_position.y << " size="
		<< globals::ui::window_w << 'x' << globals::ui::window_h << "\n";
	#endif
	ImGui::SetNextWindowPos(compatibility_active ? compatibility_position : ImVec2(0, 0), ImGuiCond_Always);
	ImGui::SetNextWindowSize(ImVec2(globals::ui::window_w, globals::ui::window_h));
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=legacy_root_next_window_ready\n";
	#endif
	ImGuiWindowFlags legacy_root_flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar |
		ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings;
#if defined(IMGUI_HAS_DOCK)
	legacy_root_flags |= ImGuiWindowFlags_NoDocking;
#endif
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=legacy_root_begin_enter\n";
	#endif
	ImGui::Begin("##main", nullptr, legacy_root_flags);
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=legacy_root_begin_complete\n";
	#endif

	{
		ImVec2 bgwp = ImGui::GetWindowPos();
		const auto& th = aida::ui::resolved();
		ImGui::GetWindowDrawList()->AddRectFilled(
			bgwp,
			ImVec2(bgwp.x + globals::ui::window_w, bgwp.y + globals::ui::window_h),
			th.bg_base, 8.f);
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=legacy_root_background_complete\n";
	std::cerr << "[AIDA_PREVIEW] render_title stage=welcome_branch_check value="
		<< (globals::ui::welcome_done ? 1 : 0) << "\n";
	#endif

	if (!globals::ui::welcome_done && (loading || !welcome_ready || fadeout > 0.f))
	{
		const auto& th = aida::ui::resolved();
		ImVec2 wp = ImGui::GetWindowPos();
		float ww_l = globals::ui::window_w;
		float wh_l = globals::ui::window_h;
		float cx   = wp.x + ww_l * 0.5f;
		float cy   = wp.y + wh_l * 0.5f - 8.f;
		ImDrawList* dl = ImGui::GetWindowDrawList();

		if (loading) {
			fadeout = 1.f;
		} else {
			fadeout -= dt * 1.5f;
			if (fadeout < 0.f) fadeout = 0.f;
		}
		float vis = loading ? 1.f : fadeout;

		dl->AddRectFilled(wp, ImVec2(wp.x + ww_l, wp.y + wh_l),
			th.bg_base, 14.f);

		if (g_bg_art_srv && g_bg_art_w > 0 && g_bg_art_h > 0) {
			float aspect_img = (float)g_bg_art_w / (float)g_bg_art_h;
			float aspect_win = ww_l / wh_l;
			float bg_w, bg_h;
			if (aspect_img > aspect_win) {
				bg_h = wh_l;
				bg_w = bg_h * aspect_img;
			} else {
				bg_w = ww_l;
				bg_h = bg_w / aspect_img;
			}
			float bg_x = wp.x + (ww_l - bg_w) * 0.5f;
			float bg_y = wp.y + (wh_l - bg_h) * 0.5f;
			ImU32 bg_tint = aida::ui::with_alpha(IM_COL32_WHITE, 0.42f * vis);
			dl->AddImageRounded((ImTextureID)g_bg_art_srv,
				ImVec2(bg_x, bg_y), ImVec2(bg_x + bg_w, bg_y + bg_h),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f),
				bg_tint, 14.f);
			dl->AddRectFilled(wp, ImVec2(wp.x + ww_l, wp.y + wh_l),
				aida::ui::with_alpha(th.bg_base, 0.55f * vis), 14.f);
		}

		float aura_r = ww_l * 0.55f;
		ImU32 aura = aida::ui::with_alpha(th.accent_glow, 0.45f * vis);
		for (int i = 0; i < 5; ++i) {
			float rr = aura_r + (float)i * 14.f;
			float fa = (1.f - (float)i / 5.f) * 0.55f;
			dl->AddCircleFilled(ImVec2(cx, cy), rr, aida::ui::with_alpha(aura, fa), 64);
		}

		float reveal_t = std::min(globals::ui::load_timer / 0.480f, 1.f);
		float reveal_eased = aida::motion::ease::out_back(reveal_t);
		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);

		aida::ui::brand::render_constellation(
			dl, ImVec2(cx, cy), 80.f, 12,
			aida::ui::clock::seconds() * 0.4f,
			aida::ui::with_alpha(th.accent_u32, vis), nullptr);

		float logo_size = 96.f;
		if (g_aida_logo_srv && g_aida_logo_w > 0 && g_aida_logo_h > 0) {
			float scale = reveal_eased;
			float ls = logo_size * (0.6f + 0.4f * scale);
			float lcx = cx;
			float lcy = cy - 18.f;
			float aspect = (float)g_aida_logo_w / (float)g_aida_logo_h;
			float lw = ls * aspect;
			float lh = ls;
			ImU32 logo_tint = aida::ui::with_alpha(IM_COL32_WHITE, vis * (0.85f + 0.15f * pulse));
			dl->AddImage((ImTextureID)g_aida_logo_srv,
				ImVec2(lcx - lw * 0.5f, lcy - lh * 0.5f),
				ImVec2(lcx + lw * 0.5f, lcy + lh * 0.5f),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f), logo_tint);
		} else {
			aida::ui::brand::render_logomark(
				dl, ImVec2(cx, cy - 18.f), logo_size,
				reveal_eased, pulse, vis);
		}

		ImFont* display_font = aida::ui::fonts::display();
		if (!display_font) display_font = ImGui::GetFont();
		float wm_scale = 1.0f;
		float wm_size  = 32.f * wm_scale;
		float wm_total_w = aida::ui::brand::wordmark_total_width(display_font, wm_scale);
		float wm_x = cx - wm_total_w * 0.5f;
		float wm_y = cy + logo_size * 0.5f + 12.f;
		float wm_reveal = std::min((globals::ui::load_timer - 0.18f) / 0.62f, 1.f);
		if (wm_reveal < 0.f) wm_reveal = 0.f;
		aida::ui::brand::render_wordmark(dl, ImVec2(wm_x, wm_y), wm_scale,
			display_font, wm_reveal, vis);

		float tag_a = std::min(std::max(globals::ui::load_timer - 1.6f, 0.f) / 0.5f, 1.f) * vis;
		if (tag_a > 0.01f) {
			const char* tag = "Reverse engineering, reimagined.";
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			float ts_x = body->CalcTextSizeA(18.f, FLT_MAX, 0.f, tag).x;
			dl->AddText(body, 18.f,
				ImVec2(cx - ts_x * 0.5f, wm_y + wm_size + 18.f),
				aida::ui::with_alpha(th.text_secondary, tag_a), tag);
		}

		float bar_w = std::min(ww_l * 0.55f, 280.f);
		float bar_h = 3.f;
		float bar_x = cx - bar_w * 0.5f;
		float bar_y = wp.y + wh_l - 60.f;

		int total_steps = globals::ui::bg_init_total.load(std::memory_order_acquire);
		int cur_step    = globals::ui::bg_init_step.load(std::memory_order_acquire);
		if (total_steps < 1) total_steps = 1;
		if (cur_step > total_steps) cur_step = total_steps;
		float prog = (float)cur_step / (float)total_steps;

		static float anim_prog = 0.f;
		anim_prog += (prog - anim_prog) * std::min(8.f * dt, 1.f);

		dl->AddRectFilled(ImVec2(bar_x, bar_y),
			ImVec2(bar_x + bar_w, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, 0.85f * vis), bar_h * 0.5f);

		float fw = bar_w * anim_prog;
		if (fw > 1.f) {
			dl->AddRectFilledMultiColor(
				ImVec2(bar_x, bar_y), ImVec2(bar_x + fw, bar_y + bar_h),
				aida::ui::with_alpha(th.accent_grad_top, vis),
				aida::ui::with_alpha(th.accent_grad_top, vis),
				aida::ui::with_alpha(th.accent_grad_bot, vis),
				aida::ui::with_alpha(th.accent_grad_bot, vis));

			float sweep_period = 1.4f;
			float ph = fmodf(aida::ui::clock::seconds() / sweep_period, 1.f);
			float sx = bar_x + fw * ph - fw * 0.18f;
			float sw = fw * 0.36f;
			if (sw > 4.f) {
				dl->PushClipRect(ImVec2(bar_x, bar_y), ImVec2(bar_x + fw, bar_y + bar_h), true);
				dl->AddRectFilledMultiColor(
					ImVec2(sx, bar_y), ImVec2(sx + sw * 0.5f, bar_y + bar_h),
					IM_COL32(255,255,255,0), aida::ui::with_alpha(IM_COL32(255,255,255,90), vis),
					aida::ui::with_alpha(IM_COL32(255,255,255,90), vis), IM_COL32(255,255,255,0));
				dl->AddRectFilledMultiColor(
					ImVec2(sx + sw * 0.5f, bar_y), ImVec2(sx + sw, bar_y + bar_h),
					aida::ui::with_alpha(IM_COL32(255,255,255,90), vis), IM_COL32(255,255,255,0),
					IM_COL32(255,255,255,0), aida::ui::with_alpha(IM_COL32(255,255,255,90), vis));
				dl->PopClipRect();
			}
		}

		static const char* k_phase_labels[] = {
			"Bootstrapping",
			"Initializing AiDA runtime core",
			"Probing network surface",
			"Arming memory scanner",
			"Spinning up MITM proxy",
			"Loading script engine",
			"Fingerprinting code surface",
			"Activating tamper guard",
			"Ready"
		};
		int phase_idx = cur_step;
		if (phase_idx < 0) phase_idx = 0;
		if (phase_idx > 8) phase_idx = 8;

		static int last_phase = -1;
		static aida::ui::transition_t phase_swap;
		static const char* prev_phase_label = k_phase_labels[0];
		static const char* cur_phase_label  = k_phase_labels[0];
		if (phase_idx != last_phase) {
			prev_phase_label = cur_phase_label;
			cur_phase_label  = k_phase_labels[phase_idx];
			phase_swap.start(0.140f, aida::motion::ease::out_cubic);
			last_phase = phase_idx;
		}
		phase_swap.tick(dt);
		float swap_e = phase_swap.eased();

		ImFont* cap = aida::ui::fonts::body();
		if (!cap) cap = ImGui::GetFont();
		float cap_size = aida::ui::fonts::size_or(cap, 16.f);
		float ph_y = bar_y - cap_size - 8.f;

		ImU32 ph_col = aida::ui::with_alpha(th.text_secondary, vis);
		if (!phase_swap.is_finished() && prev_phase_label) {
			float prev_a = (1.f - swap_e) * vis;
			float prev_y = ph_y - swap_e * 6.f;
			ImVec2 ts_p = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, prev_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_p.x * 0.5f, prev_y),
				aida::ui::with_alpha(th.text_secondary, prev_a), prev_phase_label);

			float cur_y = ph_y + (1.f - swap_e) * 6.f;
			ImVec2 ts_c = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, cur_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_c.x * 0.5f, cur_y),
				aida::ui::with_alpha(th.text_secondary, swap_e * vis), cur_phase_label);
		} else {
			ImVec2 ts_c = cap->CalcTextSizeA(cap_size, FLT_MAX, 0.f, cur_phase_label);
			dl->AddText(cap, cap_size, ImVec2(cx - ts_c.x * 0.5f, ph_y), ph_col, cur_phase_label);
		}

		char step_buf[32];
		snprintf(step_buf, sizeof(step_buf), "%d / %d", cur_step, total_steps);
		float step_sz = cap_size;
		ImVec2 sb_ts = cap->CalcTextSizeA(step_sz, FLT_MAX, 0.f, step_buf);
		dl->AddText(cap, step_sz, ImVec2(cx + bar_w * 0.5f - sb_ts.x, bar_y + bar_h + 12.f),
			aida::ui::with_alpha(th.text_dim, vis), step_buf);

		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static bool preview_loading_dragging = false;
		bool preview_loading_drag = ImGui::IsMouseDragging(ImGuiMouseButton_Left, 2.f);
		if (preview_loading_drag && !preview_loading_dragging)
			aida::preview::record(aida::preview::shell_action_t::move_window, "loading_surface");
		preview_loading_dragging = preview_loading_drag;
		#else
		static POINT drag_start_wnd   = {};
		static POINT drag_start_mouse = {};
		static bool  dragging  = false;
		static bool  last_lmb  = false;
		bool lmb = shell_left_mouse_down();
		if (lmb && !last_lmb) {
			POINT cp; GetCursorPos(&cp);
			RECT wr; GetWindowRect(g_hwnd, &wr);
			if (cp.x >= wr.left && cp.x <= wr.right && cp.y >= wr.top && cp.y <= wr.bottom) {
				dragging = true;
				drag_start_mouse = cp;
				drag_start_wnd = { wr.left, wr.top };
			}
		}
		if (!lmb) dragging = false;
		if (dragging) {
			POINT cp; GetCursorPos(&cp);
			int nx = drag_start_wnd.x + (cp.x - drag_start_mouse.x);
			int ny = drag_start_wnd.y + (cp.y - drag_start_mouse.y);
			shell_move_window(nx, ny);
		}
		last_lmb = lmb;
		#endif

		if (!loading && fadeout <= 0.001f && !globals::ui::welcome_done) {
			globals::ui::welcome_done = true;
			globals::ui::ui_alpha = 0.f;
			globals::ui::welcome_timer = 3.5f;
		}

		ImGui::End();
		return;
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=loading_welcome_branch_complete\n";
	#endif


	if (!globals::ui::welcome_done)
	{
		globals::ui::welcome_done = true;
		globals::ui::ui_alpha = 0.f;
		globals::ui::welcome_timer = 3.5f;
		const auto& th = aida::ui::resolved();
		globals::ui::welcome_timer += dt;
		if (globals::ui::welcome_timer >= 3.5f) { globals::ui::welcome_done = true; globals::ui::ui_alpha = 0.f; }

		ImVec2      wp  = ImGui::GetWindowPos();
		ImDrawList* dl  = ImGui::GetWindowDrawList();
		float       t   = globals::ui::welcome_timer;
		float       ww  = globals::ui::window_w;
		float       wh  = globals::ui::window_h;
		float       cx  = wp.x + ww * 0.5f;
		float       cy  = wp.y + wh * 0.5f - 4.f;

		float fade_in  = std::min(t / 0.6f, 1.f);
		float fade_out = t > 2.6f ? std::max(0.f, 1.f - (t - 2.6f) / 0.9f) : 1.f;
		float base_a   = fade_in * fade_out;

		dl->AddRectFilled(wp, ImVec2(wp.x + ww, wp.y + wh), th.bg_base, 14.f);

		float aura_r = ww * 0.45f;
		for (int i = 0; i < 5; ++i) {
			float rr = aura_r + (float)i * 18.f;
			float fa = (1.f - (float)i / 5.f) * 0.40f * base_a;
			dl->AddCircleFilled(ImVec2(cx, cy),
				rr, aida::ui::with_alpha(th.accent_glow, fa), 64);
		}

		aida::ui::brand::render_constellation(
			dl, ImVec2(cx, cy), 92.f, 12,
			aida::ui::clock::seconds() * 0.4f,
			aida::ui::with_alpha(th.accent_u32, base_a), nullptr);

		float reveal = aida::motion::ease::out_back(std::min(t / 0.480f, 1.f));
		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);
		aida::ui::brand::render_logomark(dl, ImVec2(cx, cy - 26.f), 84.f,
			reveal, pulse, base_a);

		ImFont* display_font = aida::ui::fonts::display();
		if (!display_font) display_font = ImGui::GetFont();
		float wm_total_w = aida::ui::brand::wordmark_total_width(display_font, 1.0f);
		float wm_x = cx - wm_total_w * 0.5f;
		float wm_y = cy + 38.f;
		float wm_reveal = std::min(std::max(t - 0.18f, 0.f) / 0.62f, 1.f);
		aida::ui::brand::render_wordmark(dl, ImVec2(wm_x, wm_y), 1.0f,
			display_font, wm_reveal, base_a);

		float sub_a = std::min(std::max(t - 0.7f, 0.f) / 0.5f, 1.f) * fade_out;
		if (sub_a > 0.01f)
		{
			ImFont* body = aida::ui::fonts::body();
			if (!body) body = ImGui::GetFont();
			float tag_sz = aida::ui::fonts::size_or(body, 16.f);
			const char* tagline = "Reverse engineering, reimagined.";
			ImVec2 ts_t = body->CalcTextSizeA(tag_sz, FLT_MAX, 0.f, tagline);
			dl->AddText(body, tag_sz,
				ImVec2(cx - ts_t.x * 0.5f, wm_y + 32.f + tag_sz),
				aida::ui::with_alpha(th.text_secondary, sub_a), tagline);

			float msg_a = std::min(std::max(t - 1.4f, 0.f) / 0.5f, 1.f) * fade_out;
			if (msg_a > 0.01f)
			{
				const char* msg = runtime_ready
					? "Your session is ready."
					: "Enter your license key to continue.";
				float msg_sz = aida::ui::fonts::size_or(body, 16.f);
				ImVec2 ts_m = body->CalcTextSizeA(msg_sz, FLT_MAX, 0.f, msg);
				dl->AddText(body, msg_sz,
					ImVec2(cx - ts_m.x * 0.5f, wm_y + 32.f + tag_sz + 28.f),
					aida::ui::with_alpha(th.text_dim, msg_a), msg);
			}
		}

		ImGui::End();
		return;
	}
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=welcome_intro_branch_complete\n";
	std::cerr << "[AIDA_PREVIEW] render_title stage=runtime_gate_check value="
		<< (runtime_ready ? 1 : 0) << "\n";
	#endif


	if (!runtime_ready)
	{
		const auto& th = aida::ui::resolved();
		static float license_alpha = 0.f;
		license_alpha += (1.f - license_alpha) * std::min(6.f * dt, 1.f);

		static aida::ui::transition_t card_intro;
		static bool card_intro_started = false;
		if (!card_intro_started) {
			card_intro.start(0.380f, aida::motion::ease::out_back);
			card_intro_started = true;
		}
		card_intro.tick(dt);
		float intro_e = card_intro.eased();
		float intro_scale = 0.94f + 0.06f * intro_e;

		ImVec2 wp   = ImGui::GetWindowPos();
		float  ww   = globals::ui::window_w;
		float  wh   = globals::ui::window_h;
		float  cx   = wp.x + ww * 0.5f;
		float  cy   = wp.y + wh * 0.5f;
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float la  = license_alpha;

		dl->AddRectFilled(wp, ImVec2(wp.x + ww, wp.y + wh), th.bg_base, 14.f);

		if (g_bg_art_srv && g_bg_art_w > 0 && g_bg_art_h > 0) {
			float aspect_img = (float)g_bg_art_w / (float)g_bg_art_h;
			float aspect_win = ww / wh;
			float bg_w, bg_h;
			if (aspect_img > aspect_win) {
				bg_h = wh;
				bg_w = bg_h * aspect_img;
			} else {
				bg_w = ww;
				bg_h = bg_w / aspect_img;
			}
			float bg_x = wp.x + (ww - bg_w) * 0.5f;
			float bg_y = wp.y + (wh - bg_h) * 0.5f;
			ImU32 bg_tint = aida::ui::with_alpha(IM_COL32_WHITE, 0.36f * la);
			dl->AddImageRounded((ImTextureID)g_bg_art_srv,
				ImVec2(bg_x, bg_y), ImVec2(bg_x + bg_w, bg_y + bg_h),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f),
				bg_tint, 14.f);
			dl->AddRectFilled(wp, ImVec2(wp.x + ww, wp.y + wh),
				aida::ui::with_alpha(th.bg_base, 0.55f * la), 14.f);
		}

		float aura_r = ww * 0.45f;
		for (int i = 0; i < 5; ++i) {
			float rr = aura_r + (float)i * 18.f;
			float fa = (1.f - (float)i / 5.f) * 0.30f * la;
			dl->AddCircleFilled(ImVec2(cx, cy), rr,
				aida::ui::with_alpha(th.accent_glow, fa), 64);
		}

		float card_w = std::min(ww - 80.f, 460.f);
		float card_h = std::min(wh - 80.f, 380.f);
		card_w *= intro_scale;
		card_h *= intro_scale;

		static aida::ui::transition_t shake;
		float shake_x = 0.f;
		if (license::check_failed) {
			static bool shake_started = false;
			if (!shake_started) {
				shake.start(0.280f, aida::motion::ease::out_quint);
				shake_started = true;
			}
			shake.tick(dt);
			if (shake.is_finished()) shake_started = false;
			float sp = shake.progress;
			shake_x = sinf(sp * 18.84955f) * 6.f * (1.f - sp);
		} else {
			shake.reset();
		}

		ImVec2 card_a(cx - card_w * 0.5f + shake_x, cy - card_h * 0.5f);
		ImVec2 card_b(card_a.x + card_w, card_a.y + card_h);

		aida::ui::blur::layer_request_t req;
		req.pos = card_a;
		req.size = ImVec2(card_w, card_h);
		req.radius = 16.f;
		req.strength = 0.7f;
		req.alpha = la;
		aida::ui::blur::schedule(req);

		float pad = 22.f;
		float inner_w = card_w - pad * 2.f;
		float content_x = card_a.x + pad;
		float content_y = card_a.y + pad;

		ImVec2 lock_c(cx + shake_x, content_y + 32.f);
		aida::ui::brand::render_lock_icon(dl, lock_c, 52.f,
			th.text_primary, th.accent_u32, la * intro_e);

		ImFont* h1f = aida::ui::fonts::h1();
		ImFont* body = aida::ui::fonts::body();
		ImFont* body_em = aida::ui::fonts::body_em();
		if (!h1f) h1f = ImGui::GetFont();
		if (!body) body = ImGui::GetFont();
		if (!body_em) body_em = ImGui::GetFont();

		float gs = ImGui::GetIO().FontGlobalScale;
		(void)gs;

		const bool runtime_locked = anti_tamper::state::get().violation_latched.load(std::memory_order_acquire);
		{
			static bool s_license_screen_enter_logged = false;
			static uint64_t s_license_screen_last_health_ms = 0;
			const uint64_t now_ms = static_cast<uint64_t>(aida::shell_platform::tick_ms());
			if (!s_license_screen_enter_logged) {
				log_license_screen_breadcrumb("license_screen_enter", ww, wh, runtime_ready, runtime_locked);
				s_license_screen_enter_logged = true;
				s_license_screen_last_health_ms = now_ms;
			} else if (s_license_screen_last_health_ms == 0 || now_ms - s_license_screen_last_health_ms >= 2000) {
				log_license_screen_breadcrumb("license_screen_frame_health", ww, wh, runtime_ready, runtime_locked);
				s_license_screen_last_health_ms = now_ms;
			}
		}
		if (runtime_locked) {
			dl->AddRectFilled(card_a, card_b, aida::ui::with_alpha(th.panel_bg, 0.82f * la), 16.f);
			dl->AddRect(card_a, card_b, aida::ui::with_alpha(th.border_subtle, la), 16.f, 0, 1.2f);
			std::string reason;
			std::string detail;
			{
				auto& rt = anti_tamper::state::get();
				std::lock_guard<std::mutex> lk(rt.mtx);
				reason = rt.violation_reason;
				detail = rt.violation_detail;
			}

			const char* title = "Runtime integrity lock";
			float title_size = 25.f;
			ImVec2 title_ts = h1f->CalcTextSizeA(title_size, FLT_MAX, 0.f, title);
			dl->AddText(h1f, title_size,
				ImVec2(cx - title_ts.x * 0.5f + shake_x, content_y + 76.f),
				aida::ui::with_alpha(th.text_primary, la), title);

			std::string sub = runtime_lock_user_message(reason, detail);
			float sub_size = aida::ui::fonts::size_or(body, 16.f);
			ImVec2 sub_ts = body->CalcTextSizeA(sub_size, inner_w, 0.f, sub.c_str());
			const float sub_y = content_y + 76.f + title_size + 16.f;
			dl->AddText(body, sub_size,
				ImVec2(cx - sub_ts.x * 0.5f + shake_x, sub_y),
				aida::ui::with_alpha(th.text_secondary, la), sub.c_str(), nullptr, inner_w);

			float next_y = sub_y + sub_ts.y + 12.f;
			if (!reason.empty()) {
				std::string msg = "Reason: " + reason;
				ImFont* code = aida::ui::fonts::code();
				if (!code) code = ImGui::GetFont();
				float msg_size = 13.f;
				ImVec2 reason_ts = code->CalcTextSizeA(msg_size, inner_w, 0.f, msg.c_str());
				dl->AddText(code, msg_size,
					ImVec2(cx - reason_ts.x * 0.5f + shake_x, next_y),
					aida::ui::with_alpha(th.text_dim, la), msg.c_str(), nullptr, inner_w);
				next_y += reason_ts.y + 8.f;
			}

			std::string evidence = runtime_lock_evidence_message(reason, detail);
			if (!evidence.empty()) {
				std::string msg = "Evidence: " + evidence;
				ImFont* code = aida::ui::fonts::code();
				if (!code) code = ImGui::GetFont();
				float msg_size = 12.f;
				ImVec2 evidence_ts = code->CalcTextSizeA(msg_size, inner_w, 0.f, msg.c_str());
				dl->AddText(code, msg_size,
					ImVec2(cx - evidence_ts.x * 0.5f + shake_x, next_y),
					aida::ui::with_alpha(th.text_dim, la), msg.c_str(), nullptr, inner_w);
			}

			ImGui::End();
			return;
		}

		const char* title = "Welcome to AiDA";
		float title_size = 26.f;
		ImVec2 title_ts = h1f->CalcTextSizeA(title_size, FLT_MAX, 0.f, title);
		dl->AddText(h1f, title_size,
			ImVec2(cx - title_ts.x * 0.5f + shake_x, content_y + 70.f),
			aida::ui::with_alpha(th.text_primary, la), title);

		const char* sub = "Enter your license key to continue.";
		float sub_size = aida::ui::fonts::size_or(body, 16.f);
		ImVec2 sub_ts = body->CalcTextSizeA(sub_size, FLT_MAX, 0.f, sub);
		dl->AddText(body, sub_size,
			ImVec2(cx - sub_ts.x * 0.5f + shake_x, content_y + 70.f + title_size + 12.f),
			aida::ui::with_alpha(th.text_secondary, la), sub);

		float input_w = inner_w;
		float input_h = 48.f;
		float input_x_screen = content_x;
		float input_y_screen = content_y + 70.f + title_size + 12.f + sub_size + 18.f;

		ImVec2 in_a(input_x_screen, input_y_screen);
		ImVec2 in_b(input_x_screen + input_w, input_y_screen + input_h);

		static aida::ui::hover_state_t input_focus;
		static aida::ui::hover_state_t input_hover;
		static aida::ui::hover_state_t eye_hover;
		static bool show_license = false;
		static bool refocus_input_pending = false;

		bool input_active = false;
		bool enter = false;
		bool input_hovered = ImGui::IsMouseHoveringRect(in_a, in_b);

		input_hover.tick(input_hovered, dt, aida::motion::spring::balanced);

		ImGui::SetCursorScreenPos(ImVec2(in_a.x + 14.f, in_a.y + (input_h - ImGui::GetFontSize()) * 0.5f));
		ImGui::PushID("license_input");
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.f, 0.f, 0.f, 0.f));
		ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, 0.45f * la)));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0.f, 0.f));
		ImGui::SetNextItemWidth(input_w - 56.f);
		if (refocus_input_pending) {
			ImGui::SetKeyboardFocusHere();
			refocus_input_pending = false;
		}

		auto lic_callback = [](ImGuiInputTextCallbackData* data) -> int {
			if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter) {
				ImWchar c = data->EventChar;
				if (c >= 'a' && c <= 'z') {
					data->EventChar = (ImWchar)(c - 'a' + 'A');
					return 0;
				}
				if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')
					return 0;
				return 1;
			}
			if (data->EventFlag == ImGuiInputTextFlags_CallbackEdit) {
				char tmp[256] = {};
				int j = 0;
				int alnum = 0;
				for (int i = 0; i < data->BufTextLen && j < (int)sizeof(tmp) - 1; ++i) {
					char ch = data->Buf[i];
					if (ch == '-') continue;
					if (alnum == 4 && j < (int)sizeof(tmp) - 1) { tmp[j++] = '-'; alnum = 0; }
					tmp[j++] = ch;
					alnum++;
				}
				tmp[j] = '\0';
				if (strcmp(tmp, data->Buf) != 0) {
					data->DeleteChars(0, data->BufTextLen);
					data->InsertChars(0, tmp);
				}
			}
			return 0;
		};

		if (ImGui::GetFrameCount() < 5)
			ImGui::SetKeyboardFocusHere();

		ImGuiInputTextFlags flags = ImGuiInputTextFlags_EnterReturnsTrue |
			ImGuiInputTextFlags_CallbackCharFilter | ImGuiInputTextFlags_CallbackEdit;
		if (!show_license)
			flags |= ImGuiInputTextFlags_Password;
		enter = ImGui::InputText("##license_key", license::key_buf, sizeof(license::key_buf),
			flags, lic_callback);
		input_active = ImGui::IsItemActive();

		ImGui::PopStyleVar();
		ImGui::PopStyleColor(5);
		ImGui::PopID();

		float focus_v = input_focus.tick(input_active, dt, aida::motion::spring::balanced);
		float ring_thick = focus_v * 2.5f + (1.f - focus_v) * 1.2f;
		float input_radius = 12.f;
		aida::ui::blur::layer_request_t in_req;
		in_req.pos = in_a;
		in_req.size = ImVec2(in_b.x - in_a.x, in_b.y - in_a.y);
		in_req.radius = input_radius;
		in_req.strength = 0.55f;
		in_req.alpha = la;
		aida::ui::blur::schedule(in_req);
		ImU32 fill_col = aida::ui::with_alpha(th.bg_base, 0.43f * la);
		dl->AddRectFilled(in_a, in_b, fill_col, input_radius);
		ImU32 ring = aida::ui::mix(th.border_subtle, th.border_focus, focus_v);
		dl->AddRect(in_a, in_b, aida::ui::with_alpha(ring, la), input_radius, 0, ring_thick);

		ImFont* code = aida::ui::fonts::code();
		if (!code) code = ImGui::GetFont();
		float key_sz = 18.f;
		char display_buf[sizeof(license::key_buf)];
		if (show_license) {
			memcpy(display_buf, license::key_buf, sizeof(display_buf));
			display_buf[sizeof(display_buf) - 1] = '\0';
		} else {
			size_t di = 0;
			for (; di < sizeof(display_buf) - 1 && license::key_buf[di] != '\0'; ++di) {
				char ch = license::key_buf[di];
				display_buf[di] = (ch == '-') ? '-' : '*';
			}
			display_buf[di] = '\0';
		}
		if (license::key_buf[0] == '\0' && !input_active) {
			dl->AddText(code, key_sz,
				ImVec2(in_a.x + 16.f, in_a.y + (input_h - key_sz) * 0.5f),
				aida::ui::with_alpha(th.text_dim, la), "AiDA-XXXX-XXXX-XXXX-XXXX");
		} else {
			dl->AddText(code, key_sz,
				ImVec2(in_a.x + 16.f, in_a.y + (input_h - key_sz) * 0.5f),
				aida::ui::with_alpha(th.text_primary, la), display_buf);
			if (input_active) {
				float caret_a = aida::ui::clock::pulse(2.0f, 0.3f, 1.0f);
				float text_w = code->CalcTextSizeA(key_sz, FLT_MAX, 0.f, display_buf).x;
				float cax = in_a.x + 16.f + text_w + 1.f;
				dl->AddLine(ImVec2(cax, in_a.y + 10.f), ImVec2(cax, in_b.y - 10.f),
					aida::ui::with_alpha(th.text_primary, la * caret_a), 1.7f);
			}
		}

		{
			bool activation_worker_active = license::activation_worker_active.load(std::memory_order_acquire);
			bool arc_transfer_active = standalone_license::is_arc_transfer_in_progress();
			bool activation_progress_active = license::checking && (activation_worker_active || arc_transfer_active);
			if (license::checking && !activation_progress_active) {
				license::checking = false;
				globals::ui::license_activation_phase.store(0, std::memory_order_release);
				diag::log_tagged_fmt("license",
					"DIAG_DIALOG_STALE_CHECKING_CLEARED worker=%d arc_transfer=%d arc_wait=%d frame=%d",
					activation_worker_active ? 1 : 0,
					arc_transfer_active ? 1 : 0,
					standalone_license::is_arc_download_in_progress() ? 1 : 0,
					ImGui::GetFrameCount());
				activation_progress_active = false;
			}

			float eye_pad_r = 10.f;
			float eye_w = 28.f;
			float eye_h = 28.f;
			ImVec2 eye_a(in_b.x - eye_pad_r - eye_w, in_a.y + (input_h - eye_h) * 0.5f);
			ImVec2 eye_b(eye_a.x + eye_w, eye_a.y + eye_h);
			bool eye_hov = !activation_progress_active && ImGui::IsMouseHoveringRect(eye_a, eye_b);
			float ehv = eye_hover.tick(eye_hov, dt, aida::motion::spring::balanced);
			if (eye_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				show_license = !show_license;
				refocus_input_pending = true;
			}

			ImU32 eye_glyph = aida::ui::with_alpha(
				aida::ui::mix(th.text_secondary, th.text_primary, ehv), la);

			ImVec2 ec((eye_a.x + eye_b.x) * 0.5f, (eye_a.y + eye_b.y) * 0.5f);
			float ew = eye_w * 0.34f;
			float eh = eye_h * 0.20f;
			float arc_r = (ew * ew + eh * eh) / (2.f * eh);
			float sin_arg = ew / arc_r;
			if (sin_arg > 1.f) sin_arg = 1.f;
			float span = asinf(sin_arg);
			float thick = 1.5f;

			ImVec2 top_center(ec.x, ec.y + (arc_r - eh));
			dl->PathArcTo(top_center, arc_r, -1.5707963f - span, -1.5707963f + span, 20);
			dl->PathStroke(eye_glyph, 0, thick);

			ImVec2 bot_center(ec.x, ec.y - (arc_r - eh));
			dl->PathArcTo(bot_center, arc_r, 1.5707963f - span, 1.5707963f + span, 20);
			dl->PathStroke(eye_glyph, 0, thick);

			float iris_r = eh * 0.78f;
			if (show_license) {
				dl->AddCircleFilled(ec, iris_r, eye_glyph, 16);
			} else {
				dl->AddCircle(ec, iris_r, eye_glyph, 16, thick);
				float sx = ew + 2.f;
				float sy = ew + 2.f;
				dl->AddLine(ImVec2(ec.x - sx * 0.7f, ec.y - sy * 0.55f),
					ImVec2(ec.x + sx * 0.7f, ec.y + sy * 0.55f), eye_glyph, thick + 0.4f);
			}

			if (eye_hov) {
				ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
			}
		}

		bool activation_worker_active = license::activation_worker_active.load(std::memory_order_acquire);
		bool arc_transfer_active = standalone_license::is_arc_transfer_in_progress();
		bool activation_progress_active = license::checking && (activation_worker_active || arc_transfer_active);

		float btn_h = 48.f;
		float btn_y_screen = input_y_screen + input_h + 18.f;
		ImVec2 btn_a(input_x_screen, btn_y_screen);
		ImVec2 btn_b(input_x_screen + input_w, btn_y_screen + btn_h);

		static aida::ui::hover_state_t btn_hover;
		static aida::ui::press_state_t btn_press;
		static aida::ui::flash_t btn_flash;
		bool btn_hov = !activation_progress_active && ImGui::IsMouseHoveringRect(btn_a, btn_b);
		bool btn_held = btn_hov && shell_left_mouse_down();
		float bhov_v = btn_hover.tick(btn_hov, dt, aida::motion::spring::balanced);
		float bprs_v = btn_press.tick(btn_held, dt);
		float bf = btn_flash.tick(dt);

		ImGui::SetCursorScreenPos(btn_a);
		ImGui::InvisibleButton("##activate_btn", ImVec2(input_w, btn_h));
		bool btn_clicked = ImGui::IsItemDeactivated() && ImGui::IsItemHovered() && !activation_progress_active;

		float lift = bhov_v * 2.5f - bprs_v * 2.f;
		float scl = 1.f - (1.f - 0.97f) * bprs_v;
		ImVec2 cb_a(btn_a.x + (1.f - scl) * input_w * 0.5f, btn_a.y + (1.f - scl) * btn_h * 0.5f - lift);
		ImVec2 cb_b(btn_b.x - (1.f - scl) * input_w * 0.5f, btn_b.y - (1.f - scl) * btn_h * 0.5f - lift);
		float btn_radius = 10.f;

		aida::ui::blur::render_drop_shadow(dl, cb_a, cb_b, btn_radius, 4,
			(0.32f + 0.18f * bhov_v) * la, ImVec2(0.f, 4.f + 2.f * bhov_v));

		aida::ui::blur::layer_request_t btn_blur_req;
		btn_blur_req.pos = cb_a;
		btn_blur_req.size = ImVec2(cb_b.x - cb_a.x, cb_b.y - cb_a.y);
		btn_blur_req.radius = btn_radius;
		btn_blur_req.strength = 0.7f;
		btn_blur_req.alpha = la;
		aida::ui::blur::schedule(btn_blur_req);

		ImU32 fill_base = aida::ui::with_alpha(IM_COL32(255, 255, 255, 14), la * (0.6f + 0.4f * bhov_v));
		dl->AddRectFilled(cb_a, cb_b, fill_base, btn_radius);

		ImU32 fill_top = aida::ui::with_alpha(th.accent_grad_top, (0.45f + 0.30f * bhov_v) * la);
		ImU32 fill_bot = aida::ui::with_alpha(th.accent_grad_bot, (0.55f + 0.30f * bhov_v) * la);
		ImU32 fill_avg = aida::ui::mix(fill_top, fill_bot, 0.6f);
		dl->AddRectFilled(cb_a, cb_b, fill_avg, btn_radius);

		ImU32 sheen_top = aida::ui::with_alpha(IM_COL32(255, 255, 255, 70), la);
		ImU32 sheen_bot = aida::ui::with_alpha(IM_COL32(255, 255, 255, 0), la);
		ImU32 sheen_mix = aida::ui::mix(sheen_top, sheen_bot, 0.45f);
		dl->AddRectFilled(
			cb_a, ImVec2(cb_b.x, cb_a.y + (cb_b.y - cb_a.y) * 0.5f),
			sheen_mix, btn_radius, ImDrawFlags_RoundCornersTop);

		dl->AddRect(cb_a, cb_b,
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 180), (0.55f + 0.40f * bhov_v) * la),
			btn_radius, 0, 1.2f);

		if (bf > 0.f) {
			dl->AddRectFilled(cb_a, cb_b,
				aida::ui::with_alpha(IM_COL32(255,255,255,255), bf * 0.22f), btn_radius);
		}
		if (btn_clicked) btn_flash.trigger();

		if (activation_progress_active) {
			ImVec2 ring_c((cb_a.x + cb_b.x) * 0.5f, (cb_a.y + cb_b.y) * 0.5f);
			float t_sec = aida::ui::clock::seconds() * 4.f;
			float arc_len = 1.4f;
			for (int i = 0; i < 24; ++i) {
				float a0 = t_sec + (float)i / 24.f * arc_len;
				float a1 = t_sec + (float)(i + 1) / 24.f * arc_len;
				float fade = 1.f - (float)i / 24.f;
				dl->PathArcTo(ring_c, 10.f, a0, a1, 4);
				dl->PathStroke(aida::ui::with_alpha(IM_COL32(255,255,255,255),
					la * fade), 0, 2.2f);
			}
		} else {
			ImFont* h2f = aida::ui::fonts::h2();
			if (!h2f) h2f = ImGui::GetFont();
			const char* btn_label = "Activate";
			float lbl_size = 18.f;
			ImVec2 ts = h2f->CalcTextSizeA(lbl_size, FLT_MAX, 0.f, btn_label);
			dl->AddText(h2f, lbl_size,
				ImVec2((cb_a.x + cb_b.x) * 0.5f - ts.x * 0.5f, (cb_a.y + cb_b.y) * 0.5f - ts.y * 0.5f),
				aida::ui::with_alpha(IM_COL32(255,255,255,255), la), btn_label);
		}

		if (activation_progress_active) {
			static const char* k_act_phases[] = {
				"Activating license...",
				"Verifying license...",
				"Preparing protected runtime...",
				"Downloading runtime...",
				"Sealing..."
			};
			int act_phase = globals::ui::license_activation_phase.load(std::memory_order_acquire);
			if (arc_transfer_active && act_phase < 3)
				act_phase = 3;
			if (act_phase < 0) act_phase = 0;
			if (act_phase > 4) act_phase = 4;

			float pb_x = input_x_screen;
			float pb_y = btn_y_screen + btn_h + 16.f;
			float pb_w = input_w;
			ImGui::GetWindowDrawList();
			ImGui::SetCursorScreenPos(ImVec2(pb_x, pb_y));
			aida::ui::render_progress_bar(ImVec2(pb_x, pb_y), pb_w, 4.f,
				(float)(act_phase + 1) / 5.f, false, true);

			static int last_act_phase = -1;
			static aida::ui::transition_t act_swap;
			static const char* prev_lbl = k_act_phases[0];
			static const char* cur_lbl  = k_act_phases[0];
			if (act_phase != last_act_phase) {
				prev_lbl = cur_lbl;
				cur_lbl  = k_act_phases[act_phase];
				act_swap.start(0.120f, aida::motion::ease::out_cubic);
				last_act_phase = act_phase;
			}
			act_swap.tick(dt);
			float sw = act_swap.eased();
			ImFont* phase_font = aida::ui::fonts::body();
			if (!phase_font) phase_font = ImGui::GetFont();
			float phase_size = aida::ui::fonts::size_or(phase_font, 16.f);
			float lbl_y = pb_y + 16.f;
			if (!act_swap.is_finished() && prev_lbl) {
				ImVec2 ts_p = phase_font->CalcTextSizeA(phase_size, FLT_MAX, 0.f, prev_lbl);
				dl->AddText(phase_font, phase_size,
					ImVec2(cx - ts_p.x * 0.5f + shake_x, lbl_y - sw * 6.f),
					aida::ui::with_alpha(th.text_secondary, (1.f - sw) * la), prev_lbl);
				ImVec2 ts_c = phase_font->CalcTextSizeA(phase_size, FLT_MAX, 0.f, cur_lbl);
				dl->AddText(phase_font, phase_size,
					ImVec2(cx - ts_c.x * 0.5f + shake_x, lbl_y + (1.f - sw) * 6.f),
					aida::ui::with_alpha(th.text_secondary, sw * la), cur_lbl);
			} else {
				ImVec2 ts_c = phase_font->CalcTextSizeA(phase_size, FLT_MAX, 0.f, cur_lbl);
				dl->AddText(phase_font, phase_size,
					ImVec2(cx - ts_c.x * 0.5f + shake_x, lbl_y),
					aida::ui::with_alpha(th.text_secondary, la), cur_lbl);
			}
		}

		int arc_phase = globals::ui::arc_unseal_phase.load(std::memory_order_acquire);
		if (arc_phase == 1) {
			ImFont* arc_font = aida::ui::fonts::body();
			if (!arc_font) arc_font = ImGui::GetFont();
			const char* msg = "Decrypting runtime core...";
			float arc_size = aida::ui::fonts::size_or(arc_font, 16.f);
			float pill_y = card_b.y + 18.f;
			ImVec2 ts = arc_font->CalcTextSizeA(arc_size, FLT_MAX, 0.f, msg);
			float pill_w = ts.x + 56.f;
			float pill_h = arc_size + 16.f;
			ImVec2 pa(cx - pill_w * 0.5f, pill_y);
			ImVec2 pb(pa.x + pill_w, pa.y + pill_h);
			dl->AddRectFilled(pa, pb, aida::ui::with_alpha(th.info_soft, la), pill_h * 0.5f);
			dl->AddRect(pa, pb, aida::ui::with_alpha(th.info, 0.55f * la), pill_h * 0.5f, 0, 1.f);
			ImVec2 ring_c(pa.x + 20.f, (pa.y + pb.y) * 0.5f);
			aida::ui::render_progress_ring(ring_c, 9.f, 1.6f, 0.f, true);
			dl->AddText(arc_font, arc_size,
				ImVec2(pa.x + 38.f, pa.y + (pill_h - arc_size) * 0.5f),
				aida::ui::with_alpha(th.info, la), msg);
		}

		if ((enter || btn_clicked) && !activation_progress_active && strlen(license::key_buf) > 0)
		{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			license::saved_key = license::key_buf;
			license::validated = true;
			license::checking = false;
			license::activation_worker_active.store(false, std::memory_order_release);
			license::check_failed = false;
			license::error_msg.clear();
			aida::preview::record(aida::preview::shell_action_t::license_activate, "license_activation_receipt");
			aida::preview::set_phase(aida::preview::shell_phase_t::ide);
#else
			const bool submit_runtime_locked = anti_tamper::state::get().violation_latched.load(std::memory_order_acquire);
			if (license::runtime_ready(submit_runtime_locked, test_all_features::is_running())) {
				license::checking = false;
				license::activation_worker_active.store(false, std::memory_order_release);
				license::check_failed = false;
				license::error_msg.clear();
				diag::log_tagged_fmt("license",
					"DIAG_DIALOG_SUBMIT_IGNORED_RUNTIME_READY enter=%d click=%d key_len=%llu frame=%d",
					enter ? 1 : 0, btn_clicked ? 1 : 0,
					static_cast<unsigned long long>(strlen(license::key_buf)),
					ImGui::GetFrameCount());
				ImGui::End();
				return;
			}
			license::checking    = true;
			license::activation_worker_active.store(true, std::memory_order_release);
			license::check_failed = false;
			license::error_msg.clear();
			globals::ui::license_activation_phase.store(0, std::memory_order_release);

			diag::log_tagged_fmt("license",
				"DIAG_DIALOG_SUBMIT enter=%d click=%d key_len=%llu frame=%d",
				enter ? 1 : 0, btn_clicked ? 1 : 0,
				static_cast<unsigned long long>(strlen(license::key_buf)),
				ImGui::GetFrameCount());

			std::string key_copy(license::key_buf);
			const auto submit_result = submit_helpers_executor_task(
				"license",
				"license.activation",
				aida::infra::executor::domain_t::security_liveness,
				"security_liveness",
				[key_copy]() {
				BOOL activation_ok = FALSE;
				char err_buf[1024] = {};
				DWORD seh_code = seh_license_activate(key_copy.c_str(),
				                                     &activation_ok,
				                                     err_buf, sizeof(err_buf));

				try {
					if (seh_code != 0) {
						char dbg[160];
						_snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
							"Activation crashed (SEH 0x%08X). Please retry.",
							static_cast<unsigned int>(seh_code));
						license::error_msg = dbg;
						license::check_failed = true;
					}
					else if (activation_ok) {
						license::saved_key = key_copy;
						license::validated = true;
						license::error_msg.clear();
					}
					else {
						license::error_msg = (err_buf[0] != '\0')
						    ? std::string(err_buf)
						    : std::string("License validation failed.");
						license::check_failed = true;
					}
				} catch (...) {
					license::check_failed = true;
				}
				license::activation_worker_active.store(false, std::memory_order_release);
				license::checking = false;
			});
			if (!submit_result.submitted) {
				license::activation_worker_active.store(false, std::memory_order_release);
				license::checking = false;
				license::check_failed = true;
				license::error_msg = "License activation could not be scheduled.";
				diag::log_tagged_fmt("license",
					"DIAG_DIALOG_SUBMIT_EXECUTOR_REJECT reason=%s frame=%d",
					submit_result.reject_reason.empty() ? "<none>" : submit_result.reject_reason.c_str(),
					ImGui::GetFrameCount());
			}
#endif
		}


		if (license::check_failed && !license::error_msg.empty())
		{
			ImFont* err_font = aida::ui::fonts::body();
			if (!err_font) err_font = ImGui::GetFont();
			float err_font_size = aida::ui::fonts::size_or(err_font, 16.f);
			float err_y = btn_y_screen + btn_h + 24.f;

			float ic_x = card_a.x + pad;
			float ic_y = err_y + 2.f;
			ImVec2 ic_c(ic_x + 11.f, ic_y + 11.f);
			dl->AddCircleFilled(ic_c, 11.f, aida::ui::with_alpha(th.error_soft, la), 16);
			dl->AddCircle(ic_c, 11.f, aida::ui::with_alpha(th.error, la), 16, 1.3f);
			ImFont* bang_font = aida::ui::fonts::body_em();
			if (!bang_font) bang_font = err_font;
			const float bang_font_size = aida::ui::fonts::size_or(bang_font, err_font_size);
			dl->AddText(bang_font, bang_font_size,
				ImVec2(ic_c.x - 3.f, ic_c.y - bang_font_size * 0.5f),
				aida::ui::with_alpha(th.error, la), "!");

			float btn_w_disc = 124.f;
			float btn_h_disc = 34.f;
			float msg_x = ic_x + 30.f;
			float msg_w = inner_w - 30.f - btn_w_disc - 8.f;
			std::string mapped = license::error_msg;
			if (mapped.find("not_found") != std::string::npos) {
				mapped = "This license/session is no longer present on the server. Activate the current key.";
			}
			dl->AddText(err_font, err_font_size, ImVec2(msg_x, err_y),
				aida::ui::with_alpha(th.error, la),
				mapped.c_str(), nullptr, msg_w);

			ImVec2 disc_a(card_b.x - pad - btn_w_disc, err_y - 6.f);
			ImVec2 disc_b(disc_a.x + btn_w_disc, disc_a.y + btn_h_disc);
			static aida::ui::hover_state_t disc_h;
			bool disc_hov = ImGui::IsMouseHoveringRect(disc_a, disc_b);
			float dhv = disc_h.tick(disc_hov, dt, aida::motion::spring::balanced);
			ImGui::SetCursorScreenPos(disc_a);
			ImGui::InvisibleButton("##disc_btn", ImVec2(btn_w_disc, btn_h_disc));
			bool disc_clk = ImGui::IsItemDeactivated() && ImGui::IsItemHovered();
			float disc_radius = 10.f;
			aida::ui::blur::layer_request_t disc_req;
			disc_req.pos = disc_a;
			disc_req.size = ImVec2(btn_w_disc, btn_h_disc);
			disc_req.radius = disc_radius;
			disc_req.strength = 0.55f;
			disc_req.alpha = la;
			aida::ui::blur::schedule(disc_req);
			ImU32 disc_fill = aida::ui::with_alpha(IM_COL32(255, 255, 255, 12), la * (0.6f + 0.6f * dhv));
			dl->AddRectFilled(disc_a, disc_b, disc_fill, disc_radius);
			ImU32 disc_border = aida::ui::with_alpha(th.border_subtle, la * (0.7f + 0.5f * dhv));
			dl->AddRect(disc_a, disc_b, disc_border, disc_radius, 0, 1.2f);
			ImFont* sm_font = aida::ui::fonts::body_em();
			if (!sm_font) sm_font = ImGui::GetFont();
			float disc_lbl = aida::ui::fonts::size_or(sm_font, 16.f);
			ImVec2 dts = sm_font->CalcTextSizeA(disc_lbl, FLT_MAX, 0.f, "Get a key");
			dl->AddText(sm_font, disc_lbl,
				ImVec2((disc_a.x + disc_b.x) * 0.5f - dts.x * 0.5f, (disc_a.y + disc_b.y) * 0.5f - dts.y * 0.5f),
				aida::ui::with_alpha(th.text_primary, la), "Get a key");
			if (disc_clk) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::record(aida::preview::shell_action_t::license_activate,
					"open_key_page:https://discord.gg/aida");
#else
				const auto submitted = aida::auth::submit_open_url_external("https://discord.gg/aida");
				if (!submitted.submitted) {
					toast_notification::push("Camoufox could not queue the key page",
						toast_notification::toast_type_t::error, 5.0f);
				}
#endif
			}
		}

		if (license::validated && standalone_license::is_valid()) {
			static aida::ui::transition_t check_anim;
			static aida::ui::transition_t burst_anim;
			static bool started = false;
			if (!started) {
				check_anim.start(0.220f, aida::motion::ease::out_quint);
				burst_anim.start(0.480f, aida::motion::ease::out_quint, 0.220f);
				started = true;
			}
			check_anim.tick(dt);
			burst_anim.tick(dt);
			ImVec2 cm_c((cb_a.x + cb_b.x) * 0.5f, (cb_a.y + cb_b.y) * 0.5f);
			aida::ui::brand::render_check_drawn(dl, cm_c, 24.f,
				check_anim.eased(), aida::ui::with_alpha(IM_COL32(255,255,255,255), la), 2.5f);
			aida::ui::brand::render_sparkle_burst(dl, cm_c, burst_anim.progress, 36.f,
				aida::ui::with_alpha(th.accent_u32, la), 10);
		}

		{
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			static bool preview_license_dragging = false;
			bool preview_license_drag = ImGui::IsMouseDragging(ImGuiMouseButton_Left, 2.f);
			if (preview_license_drag && !preview_license_dragging)
				aida::preview::record(aida::preview::shell_action_t::move_window, "license_surface");
			preview_license_dragging = preview_license_drag;
			#else
			static POINT lic_drag_wnd = {};
			static POINT lic_drag_mouse = {};
			static bool  lic_dragging = false;
			static bool  lic_last_lmb = false;
			bool lmb = shell_left_mouse_down();
			if (lmb && !lic_last_lmb) {
				POINT cp; GetCursorPos(&cp);
				RECT wr; GetWindowRect(g_hwnd, &wr);
				int local_y = cp.y - wr.top;
				bool over_card = cp.x >= (int)card_a.x && cp.x <= (int)card_b.x &&
				                 cp.y >= (int)card_a.y && cp.y <= (int)card_b.y;
				if (cp.x >= wr.left && cp.x <= wr.right && cp.y >= wr.top && cp.y <= wr.bottom &&
					local_y < (wr.bottom - wr.top) / 2 && !over_card) {
					lic_dragging = true;
					lic_drag_mouse = cp;
					lic_drag_wnd = { wr.left, wr.top };
				}
			}
			if (!lmb) lic_dragging = false;
			if (lic_dragging) {
				POINT cp; GetCursorPos(&cp);
				int nx = lic_drag_wnd.x + (cp.x - lic_drag_mouse.x);
				int ny = lic_drag_wnd.y + (cp.y - lic_drag_mouse.y);
				shell_move_window(nx, ny);
			}
			lic_last_lmb = lmb;
			#endif
		}

		ImGui::End();
		return;
	}


	g_render_section = "ide_layout";
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=runtime_gate_complete\n";
	std::cerr << "[AIDA_PREVIEW] render_title stage=ide_layout_begin alpha="
		<< globals::ui::ui_alpha << " dpi=" << globals::ui::dpi_scale << "\n";
	std::cerr << "[AIDA_PREVIEW] render_title stage=shell_metrics_begin\n";
	#endif
	float a = globals::ui::ui_alpha;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (aida::preview::controls().settle_animations) {
		a = 1.f;
		globals::ui::ui_alpha = 1.f;
	}
#endif


	const auto metrics = aida::ui::shell_metrics(globals::ui::dpi_scale);
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=shell_metrics_complete pad="
		<< metrics.pad << " gap=" << metrics.gap << " title=" << metrics.title_h
		<< " menu=" << metrics.menu_h << "\n";
	#endif
	const float pad      = metrics.pad;
	const float gap      = metrics.gap;
	const float title_h  = metrics.title_h;
	const float menu_h   = metrics.menu_h;
	float ww = globals::ui::window_w;
	float wh = globals::ui::window_h;


	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=layout_sync_complete right_visible="
		<< 0 << " right_width=" << 0 << "\n";
	#endif

	float usable = ww - pad * 2.f - gap * 2.f;
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const float max_right = usable * 0.5f;
	std::cerr << "[AIDA_PREVIEW] render_title stage=settings_geometry_complete usable="
		<< usable << " max_right=" << max_right << "\n";
	#endif

	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=right_animation_complete animated="
		<< 0 << "\n";
	#endif
	float center_w = usable;
	if (center_w < 100.f) center_w = 100.f;

	float chrome_h = title_h + menu_h;
	float total_h  = wh - pad * 2.f - chrome_h;
	float content_top = pad + title_h + menu_h;
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const float right_w = 0.f;
	const float right_total_h = total_h;
	std::cerr << "[AIDA_PREVIEW] render_title stage=ide_geometry_complete center="
		<< center_w << " right=" << right_w << " total_h=" << total_h
		<< " right_total_h=" << right_total_h << " content_top=" << content_top << "\n";
	#endif

	g_render_section = "title_bar";
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=title_bar_push_alpha value=" << a << "\n";
	#endif
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, a);
	#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::cerr << "[AIDA_PREVIEW] render_title stage=title_bar_alpha_ready\n";
	#endif


	{
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_block_entry\n";
		#endif
		ImVec2 wp   = ImGui::GetWindowPos();
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_window_pos_ready x=" << wp.x << " y=" << wp.y << "\n";
		#endif
		ImDrawList* dl = ImGui::GetWindowDrawList();
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_draw_list_ready valid=" << (dl ? 1 : 0) << "\n";
		#endif
		const auto& th_tb = aida::ui::resolved();
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_theme_ready\n";
		#endif

		ImVec2 tb_a(wp.x, wp.y);
		ImVec2 tb_b(wp.x + ww, wp.y + title_h);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_rect_ready ax=" << tb_a.x << " ay=" << tb_a.y
			<< " bx=" << tb_b.x << " by=" << tb_b.y << "\n";
		#endif

		aida::ui::blur::layer_request_t tb_req;
		tb_req.pos = tb_a;
		tb_req.size = ImVec2(ww, title_h);
		tb_req.radius = 0.f;
		tb_req.strength = 0.55f;
		tb_req.alpha = a;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_blur_schedule_begin alpha=" << tb_req.alpha << "\n";
		#endif
		aida::ui::blur::schedule(tb_req);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_blur_schedule_complete\n";
		#endif
		dl->AddRectFilled(tb_a, tb_b, aida::ui::with_alpha(th_tb.title_bar, a), metrics.corner_radius, ImDrawFlags_RoundCornersTop);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_fill_primary_complete\n";
		#endif
		dl->AddRectFilled(tb_a, tb_b, aida::ui::with_alpha(th_tb.glass_tint, a * 0.5f), metrics.corner_radius, ImDrawFlags_RoundCornersTop);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_fill_tint_complete\n";
		#endif
		dl->AddLine(ImVec2(wp.x, wp.y + title_h), ImVec2(wp.x + ww, wp.y + title_h),
			aida::ui::with_alpha(th_tb.border_subtle, a));
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_border_complete\n";
		#endif

		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);
		ImVec2 logo_c(wp.x + pad + metrics.title_logo * 0.5f + gap, wp.y + title_h * 0.5f);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_logo_begin pulse=" << pulse
			<< " texture=" << (g_aida_logo_srv ? 1 : 0) << " width=" << g_aida_logo_w << " height=" << g_aida_logo_h << "\n";
		#endif
		if (g_aida_logo_srv && g_aida_logo_w > 0 && g_aida_logo_h > 0) {
			float ls = metrics.title_logo * (0.95f + 0.05f * pulse);
			float aspect = (float)g_aida_logo_w / (float)g_aida_logo_h;
			float lw = ls * aspect;
			float lh = ls;
			ImU32 logo_tint = aida::ui::with_alpha(IM_COL32_WHITE, a);
			dl->AddImage((ImTextureID)g_aida_logo_srv,
				ImVec2(logo_c.x - lw * 0.5f, logo_c.y - lh * 0.5f),
				ImVec2(logo_c.x + lw * 0.5f, logo_c.y + lh * 0.5f),
				ImVec2(0.f, 0.f), ImVec2(1.f, 1.f), logo_tint);
		} else {
			aida::ui::brand::render_logomark(dl, logo_c, metrics.title_logo, 1.0f, pulse, a);
		}
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_logo_complete\n";
		#endif

		ImFont* h2f = aida::ui::fonts::h2();
		if (!h2f) h2f = ImGui::GetFont();
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_font_ready valid=" << (h2f ? 1 : 0) << "\n";
		#endif
		const char* app_name = "AiDA";
		const float title_font_sz = aida::ui::fonts::size_or(h2f, metrics.title_font);
		const float title_x = logo_c.x + metrics.title_logo * 0.5f + gap * 2.f;
		ImVec2 name_ts = h2f->CalcTextSizeA(title_font_sz, FLT_MAX, 0.f, app_name);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_name_measure_complete width=" << name_ts.x << " height=" << name_ts.y << "\n";
		#endif
		dl->AddText(h2f, title_font_sz,
			ImVec2(title_x, wp.y + (title_h - title_font_sz) * 0.5f),
			aida::ui::with_alpha(th_tb.text_primary, a), app_name);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_name_draw_complete\n";
		#endif

		{
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_breadcrumb_begin\n";
			#endif
			ImFont* body = aida::ui::fonts::caption();
			if (!body) body = ImGui::GetFont();
			const float bc_font_sz = aida::ui::fonts::size_or(body, metrics.caption_font);
			float bc_x = title_x + name_ts.x + gap * 2.f;
			float bc_y = wp.y + (title_h - bc_font_sz) * 0.5f;
			const float status_reserved_w = aida::ui::scale_px(164.f, metrics.scale);
			const float breadcrumb_clip_right = wp.x + ww - pad - gap * 10.f -
				metrics.title_control * 4.f - status_reserved_w;
			dl->PushClipRect(ImVec2(bc_x, wp.y),
				ImVec2((std::max)(bc_x, breadcrumb_clip_right), wp.y + title_h), true);
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_breadcrumb_clip_ready left=" << bc_x
				<< " right=" << breadcrumb_clip_right << "\n";
			#endif
			std::vector<std::string> segs;
			if (active_workspace_context)
				segs.push_back(active_workspace_context.workspace->identity().bin_name());
			if (code_editor::active && !code_editor::filename.empty())
				segs.push_back(code_editor::filename);
			switch (globals::ui::active_center_view) {
				case center_view_t::disassembly: segs.push_back("Disassembly"); break;
				case center_view_t::pseudocode:  segs.push_back("Pseudocode"); break;
				case center_view_t::hex_view:    segs.push_back("Hex"); break;
				case center_view_t::network_view:segs.push_back("Network"); break;
				case center_view_t::scan_hub:    segs.push_back("Scan"); break;
				case center_view_t::types_hub:   segs.push_back("Types"); break;
				case center_view_t::analysis_hub:segs.push_back("Analysis"); break;
				case center_view_t::binary_map:  segs.push_back("Binary Map"); break;
				case center_view_t::debugger_view:segs.push_back("Debugger"); break;
				case center_view_t::graph_view:  segs.push_back("Graph"); break;
				case center_view_t::workbench:   segs.push_back("Workbench"); break;
				case center_view_t::welcome:
				default: break;
			}
			float sep_w = body->CalcTextSizeA(bc_font_sz, FLT_MAX, 0.f, ">").x;
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_breadcrumb_segments_ready count=" << segs.size() << "\n";
			#endif
			for (size_t si = 0; si < segs.size(); ++si) {
				dl->AddText(body, bc_font_sz, ImVec2(bc_x, bc_y),
					aida::ui::with_alpha(th_tb.text_dim, a), ">");
				bc_x += sep_w + gap * 1.5f;
				ImVec2 ss = body->CalcTextSizeA(bc_font_sz, FLT_MAX, 0.f, segs[si].c_str());
				ImVec2 sa(bc_x - gap, bc_y - 2.f);
				ImVec2 sb_pt(bc_x + ss.x + gap, bc_y + ss.y + 2.f);
				bool h_seg = ImGui::IsMouseHoveringRect(sa, sb_pt);
				if (h_seg) dl->AddRectFilled(sa, sb_pt, aida::ui::with_alpha(th_tb.hover_wash, a), metrics.control_radius);
				ImU32 col = (si == segs.size() - 1) ? th_tb.text_primary : th_tb.text_secondary;
				dl->AddText(body, bc_font_sz, ImVec2(bc_x, bc_y - (h_seg ? 1.f : 0.f)),
					aida::ui::with_alpha(col, a), segs[si].c_str());
				bc_x += ss.x + gap * 2.f;
			}
			dl->PopClipRect();
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_breadcrumb_complete\n";
			#endif
		}

		auto draw_ctl = [&](float right_offset, const char* tag) -> std::pair<ImVec2, ImVec2> {
			float ctl_sz = metrics.title_control;
			ImVec2 cp(wp.x + ww - right_offset - ctl_sz, wp.y + (title_h - ctl_sz) * 0.5f);
			ImVec2 ce(cp.x + ctl_sz, cp.y + ctl_sz);
			(void)tag;
			return {cp, ce};
		};

		float ctl_off = pad + gap;

		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_controls_begin\n";
		#endif
		auto [close_a, close_b] = draw_ctl(ctl_off, "x");
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_rect_ready ax=" << close_a.x << " ay=" << close_a.y
			<< " bx=" << close_b.x << " by=" << close_b.y << "\n";
		#endif
		bool close_hov = ImGui::IsMouseHoveringRect(close_a, close_b);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_hover_ready value=" << (close_hov ? 1 : 0) << "\n";
		#endif
		static aida::ui::hover_state_t close_h;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_state_ready\n";
		#endif
		float chv = close_h.tick(close_hov, dt, aida::motion::spring::balanced);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_tick_ready value=" << chv << "\n";
		#endif
		if (chv > 0.01f) {
			dl->AddRectFilled(close_a, close_b,
				aida::ui::with_alpha(th_tb.error, 0.20f * chv * a), metrics.control_radius);
		}
		ImVec2 xc((close_a.x + close_b.x) * 0.5f, (close_a.y + close_b.y) * 0.5f);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_center_ready x=" << xc.x << " y=" << xc.y << "\n";
		#endif
		float xr = 5.f;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_color_begin\n";
		#endif
		ImU32 xcol = aida::ui::mix(th_tb.text_primary, aida::ui::lighten(th_tb.error, 30), chv);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_color_ready value=" << xcol << "\n";
		#endif
		float xth = 1.7f + chv * 0.6f;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_line_one_begin thickness=" << xth << "\n";
		#endif
		dl->AddLine(ImVec2(xc.x - xr, xc.y - xr), ImVec2(xc.x + xr, xc.y + xr),
			aida::ui::with_alpha(xcol, a), xth);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_line_one_complete\n";
		#endif
		dl->AddLine(ImVec2(xc.x + xr, xc.y - xr), ImVec2(xc.x - xr, xc.y + xr),
			aida::ui::with_alpha(xcol, a), xth);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_line_two_complete\n";
		#endif
		if (close_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			POINT cursor{};
			GetCursorPos(&cursor);
			ImVec2 mouse = ImGui::GetIO().MousePos;
			diag::log_tagged_critical_fmt("chrome",
				"close_button_clicked hwnd=0x%llX cursor=%ld,%ld mouse=%.1f,%.1f rect=%.1f,%.1f,%.1f,%.1f blocked=%d",
				(unsigned long long)reinterpret_cast<UINT_PTR>(g_hwnd),
				cursor.x,
				cursor.y,
				mouse.x,
				mouse.y,
				close_a.x,
				close_a.y,
				close_b.x,
				close_b.y,
				ui_input_gate::chrome_input_blocked() ? 1 : 0);
#endif
			request_chrome_shutdown_from_render("close_button", "chrome.close_button");
		}
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_close_complete\n";
		#endif
		ctl_off += metrics.title_control + gap * 1.5f;

		auto [max_a, max_b] = draw_ctl(ctl_off, "m");
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_max_rect_ready\n";
		#endif
		bool max_hov = ImGui::IsMouseHoveringRect(max_a, max_b);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_max_hover_ready value=" << (max_hov ? 1 : 0) << "\n";
		#endif
		static aida::ui::hover_state_t max_h;
		float mhv = max_h.tick(max_hov, dt, aida::motion::spring::balanced);
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_max_tick_ready value=" << mhv << "\n";
		#endif
		if (mhv > 0.01f) {
			dl->AddRectFilled(max_a, max_b,
				aida::ui::with_alpha(th_tb.hover_wash, mhv * a), metrics.control_radius);
		}
		ImVec2 mc((max_a.x + max_b.x) * 0.5f, (max_a.y + max_b.y) * 0.5f);
		float mr = 5.f;
		ImU32 mcol = th_tb.text_primary;
		if (globals::ui::maximized) {
			dl->AddRect(ImVec2(mc.x - mr, mc.y - mr + 1.5f), ImVec2(mc.x + mr - 1.5f, mc.y + mr),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
			dl->AddRect(ImVec2(mc.x - mr + 1.5f, mc.y - mr), ImVec2(mc.x + mr, mc.y + mr - 1.5f),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
		} else {
			dl->AddRect(ImVec2(mc.x - mr, mc.y - mr), ImVec2(mc.x + mr, mc.y + mr),
				aida::ui::with_alpha(mcol, a), 1.f, 0, 1.4f);
		}
		if (max_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			shell_toggle_maximize();
		}
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_max_complete\n";
		#endif
		ctl_off += metrics.title_control + gap * 1.5f;

		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_min_begin\n";
		#endif
		auto [min_a, min_b] = draw_ctl(ctl_off, "n");
		bool min_hov = ImGui::IsMouseHoveringRect(min_a, min_b);
		static aida::ui::hover_state_t min_hh;
		float mnv = min_hh.tick(min_hov, dt, aida::motion::spring::balanced);
		if (mnv > 0.01f) {
			dl->AddRectFilled(min_a, min_b,
				aida::ui::with_alpha(th_tb.hover_wash, mnv * a), metrics.control_radius);
		}
		ImU32 mncol = th_tb.text_primary;
		float minc_x = (min_a.x + min_b.x) * 0.5f;
		float minc_y = (min_a.y + min_b.y) * 0.5f + mnv * 2.f;
		dl->AddLine(ImVec2(minc_x - 5.f, minc_y), ImVec2(minc_x + 5.f, minc_y),
			aida::ui::with_alpha(mncol, a), 1.7f);
		if (min_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			shell_minimize();
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		std::cerr << "[AIDA_PREVIEW] render_title stage=title_min_complete\n";
		#endif
		ctl_off += metrics.title_control + gap * 3.f;


		{
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_theme_toggle_begin\n";
			#endif
			float toggle_sz = metrics.title_control;
			ImVec2 tgl_a(wp.x + ww - ctl_off - toggle_sz, wp.y + (title_h - toggle_sz) * 0.5f);
			ImVec2 tgl_b(tgl_a.x + toggle_sz, tgl_a.y + toggle_sz);
			bool tgl_hov = ImGui::IsMouseHoveringRect(tgl_a, tgl_b);
			static aida::ui::hover_state_t tgl_h;
			float thv = tgl_h.tick(tgl_hov, dt, aida::motion::spring::balanced);
			if (thv > 0.01f) {
				dl->AddRectFilled(tgl_a, tgl_b,
					aida::ui::with_alpha(th_tb.hover_wash, thv * a), metrics.control_radius);
			}
			ImU32 tcol = aida::ui::mix(th_tb.text_secondary, th_tb.text_primary, thv);
			ImVec2 tcc((tgl_a.x + tgl_b.x) * 0.5f, (tgl_a.y + tgl_b.y) * 0.5f);
			bool currently_dark = aida::ui::is_dark();
			if (currently_dark) {
				dl->AddCircle(ImVec2(tcc.x, tcc.y), 6.f, aida::ui::with_alpha(tcol, a), 16, 1.5f);
				for (int ray = 0; ray < 8; ++ray) {
					float angle = static_cast<float>(ray) * 0.785398f;
					float cx = cosf(angle), cy = sinf(angle);
					dl->AddLine(ImVec2(tcc.x + cx * 8.f, tcc.y + cy * 8.f),
						ImVec2(tcc.x + cx * 9.5f, tcc.y + cy * 9.5f),
						aida::ui::with_alpha(tcol, a), 1.5f);
				}
			} else {
				dl->PathArcTo(ImVec2(tcc.x - 1.f, tcc.y), 7.f, 5.5f, 9.95f, 16);
				dl->PathStroke(aida::ui::with_alpha(tcol, a), 0, 1.5f);
			}
			if (tgl_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				int idx = g_sa_settings.active_theme_idx;
				int new_idx;
				switch (idx) {
					case 0: new_idx = 1; break;
					case 1: new_idx = 0; break;
					case 2: new_idx = 3; break;
					case 3: new_idx = 2; break;
					default: new_idx = currently_dark ? 1 : 0; break;
				}
				themes::active = new_idx;
				custom_themes::active_custom = -1;
				themes::changed = true;
				g_sa_settings.active_theme_idx = new_idx;
				g_sa_settings.active_custom_theme_idx = -1;
				aida::ui::apply_for_index(new_idx, true);
				g_sa_settings_request_save();
			}
			if (tgl_hov) ImGui::SetTooltip("Toggle dark/light mode");
			ctl_off += toggle_sz + gap * 2.f;
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_theme_toggle_complete\n";
			#endif
		}

		{
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_workspace_status_begin\n";
			#endif
			const std::string_view status_text = aida::ui::workspace_layout::active_preset_name();
			const float status_w = aida::ui::scale_px(164.f, metrics.scale);
			const float status_h = aida::ui::scale_px(24.f, metrics.scale);
			ImVec2 status_b(wp.x + ww - ctl_off,
				wp.y + (title_h + status_h) * 0.5f);
			ImVec2 status_a(status_b.x - status_w, status_b.y - status_h);
			dl->AddRectFilled(status_a, status_b,
				aida::ui::with_alpha(th_tb.bg_elevated, 0.72f * a), status_h * 0.5f);
			dl->AddRect(status_a, status_b,
				aida::ui::with_alpha(th_tb.border_subtle, 0.92f * a), status_h * 0.5f);
			const ImU32 status_color = active_workspace_context
				? th_tb.accent_u32 : th_tb.success;
			dl->AddCircleFilled(ImVec2(status_a.x + 12.f, status_a.y + status_h * 0.5f),
				3.f, aida::ui::with_alpha(status_color, a), 16);
			ImFont* status_font = aida::ui::fonts::caption();
			if (!status_font) status_font = ImGui::GetFont();
			const float status_fs = aida::ui::fonts::size_or(status_font, metrics.caption_font);
			dl->AddText(status_font, status_fs,
				ImVec2(status_a.x + 22.f, status_a.y + (status_h - status_fs) * 0.5f),
				aida::ui::with_alpha(th_tb.text_secondary, a), status_text.data(),
				status_text.data() + status_text.size());
			ctl_off += status_w + gap * 2.f;
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_workspace_status_complete\n";
			#endif
		}

		{
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			std::cerr << "[AIDA_PREVIEW] render_title stage=title_theme_popup_begin\n";
			#endif
			static int theme_popup_open_frame = 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			static std::uint64_t preview_theme_revision = 0;
			if (aida::preview::controls().theme_popup_open && preview_theme_revision != aida::preview::controls().revision) {
				preview_theme_revision = aida::preview::controls().revision;
				theme_popup_open_frame = ImGui::GetFrameCount();
				ImGui::OpenPopup("##theme_popup");
			}
#endif
			ImVec2 th_pos(wp.x + ww - 200.f, wp.y + 8.f);
			(void)th_pos;
			ImVec2 fake_pos(wp.x + ww - ctl_off - metrics.title_control, wp.y + (title_h - metrics.title_control) * 0.5f);
			(void)fake_pos;
			bool dummy_hov = false;
			(void)dummy_hov;
			(void)theme_popup_open_frame;

			{
				float popup_x = std::min(th_pos.x - 100.f, wp.x + ww - 220.f - 8.f);
				popup_x = std::max(wp.x + 8.f, popup_x);
				ImGui::SetNextWindowPos(ImVec2(popup_x, wp.y + title_h + 2.f));
				ImGui::SetNextWindowBgAlpha(0.96f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, metrics.corner_radius);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(gap * 2.f, gap * 2.f));
				const auto& th_tp = aida::ui::resolved();
				ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(th_tp.bg_overlay));
				ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(th_tp.border_strong));

				if (ImGui::BeginPopup("##theme_popup",
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings))
				{
					ImDrawList* pdl = ImGui::GetWindowDrawList();
					float item_w = 200.f;
					float item_h = 22.f;
					bool popup_clicks_ok = (ImGui::GetFrameCount() > theme_popup_open_frame + 1);


					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_tp.text_secondary), "Built-in Themes");
					ImGui::Spacing();
					for (int ti = 0; ti < themes::count; ti++) {
						auto& tp = themes::presets[ti];
						bool is_active = (custom_themes::active_custom < 0 && themes::active == ti);

						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);

						bool ti_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (ti_hov) pdl->AddRectFilled(rmin, rmax, th_tp.hover_wash, 4.f);
						if (is_active) pdl->AddRectFilled(rmin, rmax, th_tp.selection, 4.f);

						pdl->AddCircleFilled(
							ImVec2(cp.x + 10.f, cp.y + item_h * 0.5f), 4.f,
							IM_COL32((int)(tp.accent.x*255), (int)(tp.accent.y*255),
								(int)(tp.accent.z*255), 255));

						ImU32 name_col = is_active
							? IM_COL32((int)(tp.accent.x*255), (int)(tp.accent.y*255), (int)(tp.accent.z*255), 255)
							: th_tp.text_secondary;
						pdl->AddText(ImVec2(cp.x + 24.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							name_col, tp.name);

						ImGui::Dummy(ImVec2(item_w, item_h));
						if (popup_clicks_ok && ti_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							themes::active = ti;
							custom_themes::active_custom = -1;
							themes::changed = true;
							g_sa_settings.active_theme_idx = ti;
							g_sa_settings.active_custom_theme_idx = -1;
							g_sa_settings_request_save();
							diag::log_tagged_fmt("ui", "theme_changed idx=%d name='%s'",
								ti, tp.name);
						}
					}


					if (!custom_themes::list.empty()) {
						ImGui::Dummy(ImVec2(0, 4));
						ImGui::Separator();
						ImGui::Dummy(ImVec2(0, 2));
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_tp.text_secondary), "Custom Themes");
						ImGui::Spacing();
						for (std::size_t ci = 0; ci < custom_themes::list.size(); ++ci) {
							auto& ct = custom_themes::list[ci];
							const int custom_index = static_cast<int>(ci);
							bool is_active = (custom_themes::active_custom == custom_index);

							ImVec2 cp = ImGui::GetCursorScreenPos();
							ImVec2 rmin = cp;
							ImVec2 rmax(cp.x + item_w, cp.y + item_h);

							bool ci_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
							if (ci_hov) pdl->AddRectFilled(rmin, rmax, th_tp.hover_wash, 4.f);
							if (is_active) pdl->AddRectFilled(rmin, rmax, th_tp.selection, 4.f);

							pdl->AddCircleFilled(
								ImVec2(cp.x + 10.f, cp.y + item_h * 0.5f), 4.f,
								IM_COL32((int)(ct.accent[0]*255), (int)(ct.accent[1]*255),
									(int)(ct.accent[2]*255), 255));

							ImU32 nc = is_active
								? IM_COL32((int)(ct.accent[0]*255), (int)(ct.accent[1]*255), (int)(ct.accent[2]*255), 255)
								: th_tp.text_secondary;
							pdl->AddText(ImVec2(cp.x + 24.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
								nc, ct.name.c_str());


							float edit_w = ImGui::CalcTextSize("Edit").x + 8.f;
							ImVec2 emin(cp.x + item_w - edit_w - 4.f, cp.y + 2.f);
							ImVec2 emax(emin.x + edit_w, cp.y + item_h - 2.f);
							bool ehov = ImGui::IsMouseHoveringRect(emin, emax);
							if (ehov) pdl->AddRectFilled(emin, emax, th_tp.selection, 3.f);
							pdl->AddText(ImVec2(emin.x + 4.f, emin.y + 1.f),
								aida::ui::with_alpha(th_tp.text_secondary, ehov ? 1.f : 0.66f), "Edit");
							if (popup_clicks_ok && ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								custom_themes::editing_idx = custom_index;
								custom_themes::editing_copy = ct;
								custom_themes::editor_open = true;
							}

							ImGui::Dummy(ImVec2(item_w, item_h));
							if (popup_clicks_ok && ci_hov && !ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								custom_themes::active_custom = custom_index;
								themes::changed = true;
								g_sa_settings.active_custom_theme_idx = custom_index;
								g_sa_settings_request_save();
							}
						}
					}


					ImGui::Dummy(ImVec2(0, 4));
					ImGui::Separator();
					ImGui::Dummy(ImVec2(0, 2));


					{
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);
						bool hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (hov) pdl->AddRectFilled(rmin, rmax, th_tp.hover_wash, 4.f);
						pdl->AddText(ImVec2(cp.x + 8.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							aida::ui::with_alpha(th_tp.success, hov ? 1.f : 0.78f), "+ Create New Theme");
						ImGui::Dummy(ImVec2(item_w, item_h));
						if (popup_clicks_ok && hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							custom_themes::editing_idx = -1;
							custom_themes::editing_copy = CustomThemeData{};
							custom_themes::editing_copy.name = "My Theme " + std::to_string(custom_themes::list.size() + 1);
							custom_themes::editor_open = true;
						}
					}


					{
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + item_w, cp.y + item_h);
						bool hov = ImGui::IsMouseHoveringRect(rmin, rmax);
						if (hov) pdl->AddRectFilled(rmin, rmax, th_tp.hover_wash, 4.f);
						pdl->AddText(ImVec2(cp.x + 8.f, cp.y + (item_h - ImGui::GetFontSize()) * 0.5f),
							aida::ui::with_alpha(th_tp.info, hov ? 1.f : 0.78f), "Import Theme...");
						ImGui::Dummy(ImVec2(item_w, item_h));
						if (popup_clicks_ok && hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							char buf[MAX_PATH] = {};
							static const char k_theme_import_filter[] =
								"AiDA Theme (*.json)\0*.json\0"
								"All files (*.*)\0*.*\0\0";
							if (trusted_show_open_file(g_hwnd,
									"Import Theme",
									k_theme_import_filter,
									buf, sizeof(buf),
									"theme_import")) {
								std::ifstream ifs(buf);
								if (ifs.is_open()) {
									try {
										nlohmann::json j;
										ifs >> j;
										CustomThemeData ct;
										ct.name = j.value("name", "Imported Theme");
										if (j.contains("accent") && j["accent"].is_array() && j["accent"].size() >= 3) {
											ct.accent[0] = j["accent"][0].get<float>();
											ct.accent[1] = j["accent"][1].get<float>();
											ct.accent[2] = j["accent"][2].get<float>();
										}
										ct.bg_base       = j.value("bg_base", (uint32_t)ct.bg_base);
										ct.panel_bg      = j.value("panel_bg", (uint32_t)ct.panel_bg);
										ct.panel_header  = j.value("panel_header", (uint32_t)ct.panel_header);
										ct.title_bar     = j.value("title_bar", (uint32_t)ct.title_bar);
										ct.text_primary  = j.value("text_primary", (uint32_t)ct.text_primary);
										ct.text_secondary= j.value("text_secondary", (uint32_t)ct.text_secondary);
										ct.text_dim      = j.value("text_dim", (uint32_t)ct.text_dim);
										ct.acrylic_color = j.value("acrylic_color", (DWORD)ct.acrylic_color);
										ct.icon_index    = j.value("icon_index", ct.icon_index);
										ct.icon_file_path= j.value("icon_file_path", std::string{});
										custom_themes::list.push_back(std::move(ct));
									} catch (...) {}
								}
							}
						}
					}
					ImGui::EndPopup();
				}
				ImGui::PopStyleColor(2);
				ImGui::PopStyleVar(2);
			}


			if (custom_themes::editor_open) {
				float ew = 380.f, eh = 520.f;
				ImGui::SetNextWindowPos(ImVec2((ww - ew) * 0.5f, (globals::ui::window_h - eh) * 0.5f), ImGuiCond_Appearing);
				ImGui::SetNextWindowSize(ImVec2(ew, eh));
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.f, 12.f));
				ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
				ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
				const auto& th_te = aida::ui::resolved();
				ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(th_te.bg_elevated));
				ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(th_te.border_strong));
				ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(th_te.panel_header));
				ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(th_te.text_primary));

				if (ImGui::Begin("##theme_editor", &custom_themes::editor_open,
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse))
				{
					auto& ed = custom_themes::editing_copy;
					float iw2 = ew - 28.f;

					ImGui::TextColored(aida::ui::resolved().accent,
						custom_themes::editing_idx < 0 ? "Create Theme" : "Edit Theme");
					ImGui::Dummy(ImVec2(0, 4));


					static char name_buf[128] = {};
					static bool name_init = false;
					static int name_editing_idx = -2;
					if (!name_init || name_editing_idx != custom_themes::editing_idx ||
						ed.name != name_buf) {
						snprintf(name_buf, sizeof(name_buf), "%s", ed.name.c_str());
						name_init = true;
						name_editing_idx = custom_themes::editing_idx;
					}
					ImGui::Text("Name");
					ImGui::SetNextItemWidth(iw2);
					if (ImGui::InputText("##te_name", name_buf, sizeof(name_buf)))
						ed.name = name_buf;


					ImGui::Text("Accent Color");
					ImGui::SetNextItemWidth(iw2);
					ImGui::ColorEdit3("##te_accent", ed.accent, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel);


					auto u32_edit = [&](const char* label, const char* id, ImU32& col) {
						ImGui::Text("%s", label);
						float c[4];
						c[0] = (float)((col >> 0) & 0xFF) / 255.f;
						c[1] = (float)((col >> 8) & 0xFF) / 255.f;
						c[2] = (float)((col >> 16) & 0xFF) / 255.f;
						c[3] = (float)((col >> 24) & 0xFF) / 255.f;
						ImGui::SetNextItemWidth(iw2);
						if (ImGui::ColorEdit4(id, c, ImGuiColorEditFlags_AlphaBar))
							col = IM_COL32((int)(c[0]*255), (int)(c[1]*255), (int)(c[2]*255), (int)(c[3]*255));
					};
					u32_edit("Background", "##te_bg", ed.bg_base);
					u32_edit("Panel Background", "##te_pbg", ed.panel_bg);
					u32_edit("Panel Header", "##te_phdr", ed.panel_header);
					u32_edit("Title Bar", "##te_tb", ed.title_bar);


					ImGui::Text("Theme Icon (optional)");
					ImGui::SetNextItemWidth(iw2);
					if (aida::ui::components::button("Choose Image File...##te_icon",
						aida::ui::components::button_kind_t::primary,
						aida::ui::components::size_t_::md,
						ImVec2(iw2, 0.f))) {
						char icon_buf[MAX_PATH] = {};
						static const char k_theme_icon_filter[] =
							"Images (*.png;*.jpg;*.jpeg;*.bmp)\0*.png;*.jpg;*.jpeg;*.bmp\0"
							"All files (*.*)\0*.*\0\0";
						if (trusted_show_open_file(g_hwnd,
							"Choose Theme Icon",
							k_theme_icon_filter,
							icon_buf, sizeof(icon_buf),
							"theme_icon_pick")) {
							ed.icon_index = -1;
							ed.icon_file_path = icon_buf;
						}
					}
					if (!ed.icon_file_path.empty()) {
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_te.success), "File: %s",
							ed.icon_file_path.substr(ed.icon_file_path.find_last_of("\\/") + 1).c_str());
						if (aida::ui::components::button("Clear Icon##te_clear",
							aida::ui::components::button_kind_t::ghost,
							aida::ui::components::size_t_::sm)) {
							ed.icon_file_path.clear();
							ed.icon_index = -1;
						}
					}

					ImGui::Dummy(ImVec2(0, 8));


					float btn_w2 = 70.f;
					if (aida::ui::components::button("Save",
						aida::ui::components::button_kind_t::primary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
						ed.name = name_buf;
						if (custom_themes::editing_idx >= 0 &&
							static_cast<std::size_t>(custom_themes::editing_idx) < custom_themes::list.size()) {
							custom_themes::list[
								static_cast<std::size_t>(custom_themes::editing_idx)] = ed;
						} else {
							custom_themes::list.push_back(ed);
							custom_themes::editing_idx = (int)custom_themes::list.size() - 1;
						}
						custom_themes::active_custom = custom_themes::editing_idx;
						themes::changed = true;
						custom_themes::editor_open = false;
						name_init = false;


						nlohmann::json arr = nlohmann::json::array();
						for (auto& ct2 : custom_themes::list) {
							nlohmann::json jt;
							jt["name"] = ct2.name;
							jt["accent"] = { ct2.accent[0], ct2.accent[1], ct2.accent[2] };
							jt["bg_base"] = (uint32_t)ct2.bg_base;
							jt["panel_bg"] = (uint32_t)ct2.panel_bg;
							jt["panel_header"] = (uint32_t)ct2.panel_header;
							jt["title_bar"] = (uint32_t)ct2.title_bar;
							jt["text_primary"] = (uint32_t)ct2.text_primary;
							jt["text_secondary"] = (uint32_t)ct2.text_secondary;
							jt["text_dim"] = (uint32_t)ct2.text_dim;
							jt["acrylic_color"] = (uint32_t)ct2.acrylic_color;
							jt["icon_index"] = ct2.icon_index;
							jt["icon_file_path"] = ct2.icon_file_path;
							arr.push_back(jt);
						}
						g_sa_settings.custom_themes_json = arr.dump();
						g_sa_settings.active_custom_theme_idx = custom_themes::active_custom;
						g_sa_settings_request_save();
					}
					ImGui::SameLine();


					if (aida::ui::components::button("Export",
						aida::ui::components::button_kind_t::secondary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
						char export_buf[MAX_PATH] = {};
						snprintf(export_buf, sizeof(export_buf), "%s.json", name_buf);
						static const char k_theme_export_filter[] =
							"AiDA Theme (*.json)\0*.json\0\0";
						if (trusted_show_save_file(g_hwnd,
							"Export Theme",
							k_theme_export_filter,
							"json",
							export_buf, sizeof(export_buf),
							"theme_export")) {
							nlohmann::json jt;
							jt["name"] = std::string(name_buf);
							jt["accent"] = { ed.accent[0], ed.accent[1], ed.accent[2] };
							jt["bg_base"] = (uint32_t)ed.bg_base;
							jt["panel_bg"] = (uint32_t)ed.panel_bg;
							jt["panel_header"] = (uint32_t)ed.panel_header;
							jt["title_bar"] = (uint32_t)ed.title_bar;
							jt["text_primary"] = (uint32_t)ed.text_primary;
							jt["text_secondary"] = (uint32_t)ed.text_secondary;
							jt["text_dim"] = (uint32_t)ed.text_dim;
							jt["acrylic_color"] = (uint32_t)ed.acrylic_color;
							jt["icon_index"] = ed.icon_index;
							std::ofstream ofs(export_buf, std::ios::trunc);
							if (ofs.is_open()) ofs << jt.dump(2);
						}
					}
					ImGui::SameLine();


					if (custom_themes::editing_idx >= 0) {
						if (aida::ui::components::button("Delete",
							aida::ui::components::button_kind_t::destructive,
							aida::ui::components::size_t_::md,
							ImVec2(btn_w2, 26.f))) {
							int idx = custom_themes::editing_idx;
							custom_themes::list.erase(custom_themes::list.begin() + idx);
							if (custom_themes::active_custom == idx) custom_themes::active_custom = -1;
							else if (custom_themes::active_custom > idx) custom_themes::active_custom--;
							themes::changed = true;
							custom_themes::editor_open = false;
							name_init = false;
						}
						ImGui::SameLine();
					}

					if (aida::ui::components::button("Cancel",
						aida::ui::components::button_kind_t::secondary,
						aida::ui::components::size_t_::md,
						ImVec2(btn_w2, 26.f))) {
						custom_themes::editor_open = false;
						name_init = false;
					}
				}
				ImGui::End();
				ImGui::PopStyleColor(4);
				ImGui::PopStyleVar(4);
			}
		}

		{
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			static bool preview_title_dragging = false;
			bool preview_title_drag = ImGui::IsMouseDragging(ImGuiMouseButton_Left, 2.f) &&
				ImGui::GetIO().MousePos.y >= wp.y && ImGui::GetIO().MousePos.y < wp.y + title_h;
			if (preview_title_drag && !preview_title_dragging)
				aida::preview::record(aida::preview::shell_action_t::move_window, "title_bar");
			preview_title_dragging = preview_title_drag;
			#else
			static POINT tb_drag_wnd = {};
			static POINT tb_drag_mouse = {};
			static bool  tb_dragging = false;
			static bool  tb_last_lmb = false;
			bool lmb = shell_left_mouse_down();
			if (lmb && !tb_last_lmb) {
				POINT cp; GetCursorPos(&cp);
				RECT wr; GetWindowRect(g_hwnd, &wr);
				int local_y = cp.y - wr.top;
				int local_x = cp.x - wr.left;

				if (local_y >= 0 && local_y < (int)title_h && local_x >= 0 && local_x < (int)(ww - 140.f)) {
					tb_dragging = true;
					tb_drag_mouse = cp;
					tb_drag_wnd = { wr.left, wr.top };
				}
			}
			if (!lmb) tb_dragging = false;
			if (tb_dragging) {
				POINT cp; GetCursorPos(&cp);
				int nx = tb_drag_wnd.x + (cp.x - tb_drag_mouse.x);
				int ny = tb_drag_wnd.y + (cp.y - tb_drag_mouse.y);
			shell_move_window(nx, ny);
			}
			tb_last_lmb = lmb;
			#endif
		}
	}


	{
		ImVec2 wp = ImGui::GetWindowPos();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		const auto& th_mb = aida::ui::resolved();
		float my0 = wp.y + title_h;
		float my1 = my0 + menu_h;

		aida::ui::blur::layer_request_t mb_req;
		mb_req.pos = ImVec2(wp.x, my0);
		mb_req.size = ImVec2(ww, menu_h);
		mb_req.radius = 0.f;
		mb_req.strength = 0.4f;
		mb_req.alpha = a;
		aida::ui::blur::schedule(mb_req);
		dl->AddRectFilled(ImVec2(wp.x, my0), ImVec2(wp.x + ww, my1),
			aida::ui::with_alpha(th_mb.panel_header, a));
		dl->AddLine(ImVec2(wp.x, my1), ImVec2(wp.x + ww, my1),
			aida::ui::with_alpha(th_mb.border_subtle, a));

		struct MenuItem {
			const char* label;
			int         id;
		};
		static const MenuItem menus[] = {
			{"File", 0}, {"Edit", 1}, {"View", 2}, {"Navigate", 3},
			{"Analysis", 4}, {"Debugger", 5}, {"Memory", 6}, {"Types", 7},
			{"Network", 8}, {"Workspace", 9}, {"Tools", 10}, {"AI", 11},
			{"Help", 12}, {"More", 13}
		};
		const bool compact_menu = ww < aida::ui::scale_px(1320.f, metrics.scale);

		ImFont* mb_label_font = aida::ui::fonts::lg();
		if (!mb_label_font) mb_label_font = aida::ui::fonts::body();
		if (!mb_label_font) mb_label_font = ImGui::GetFont();
		const float mb_label_size = aida::ui::fonts::size_or(mb_label_font, metrics.menu_font);
		float mx_cursor = wp.x + metrics.menu_pad_x;
		ImGuiStorage* mb_storage = ImGui::GetStateStorage();
		for (int i = 0; i < static_cast<int>(sizeof(menus) / sizeof(menus[0])); i++) {
			if ((compact_menu && i >= 4 && i <= 12) || (!compact_menu && i == 13))
				continue;
			ImVec2 ts = mb_label_font->CalcTextSizeA(mb_label_size, FLT_MAX, 0.f, menus[i].label);
			float btn_w = ts.x + metrics.menu_item_pad_x * 2.f;
			ImVec2 bmin(mx_cursor, my0 + gap * 0.75f);
			ImVec2 bmax(mx_cursor + btn_w, my1 - gap * 0.75f);
			bool is_open = (menu_bar::open_menu == i);

			ImGui::PushID(menus[i].label);
			ImGui::SetCursorScreenPos(bmin);
			ImGui::InvisibleButton("##mb_top", ImVec2(btn_w, bmax.y - bmin.y));
			bool hov = ImGui::IsItemHovered();
			bool clicked_btn = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool focused = ImGui::IsItemFocused();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const std::string menu_semantic_id = aida::preview::semantics::stable_id(
				"aida.menu", menus[i].label);
			aida::preview::semantics::register_last_item(
				menu_semantic_id, "application-menu-trigger");
#endif
			ImGui::PopID();

			ImGuiID mb_hov_id = ImGui::GetID(menus[i].label);
			float h_v = mb_storage->GetFloat(mb_hov_id, 0.f);
			float h_target = (hov || is_open) ? 1.f : 0.f;
			h_v += (h_target - h_v) * std::min(12.f * dt, 1.f);
			mb_storage->SetFloat(mb_hov_id, h_v);

			if (h_v > 0.01f) {
				ImU32 mfill = is_open ? th_mb.selection_strong : th_mb.hover_wash;
				dl->AddRectFilled(bmin, bmax, aida::ui::with_alpha(mfill, h_v * a), metrics.control_radius);
			}
			if (is_open) {
				dl->AddRectFilled(ImVec2(bmin.x + metrics.menu_item_pad_x, bmax.y - 2.f),
					ImVec2(bmax.x - metrics.menu_item_pad_x, bmax.y),
					aida::ui::with_alpha(th_mb.accent_u32, a), 1.f);
			}
			if (focused) {
				dl->AddRect(ImVec2(bmin.x - 1.f, bmin.y - 1.f),
					ImVec2(bmax.x + 1.f, bmax.y + 1.f),
					aida::ui::with_alpha(th_mb.border_focus, 0.82f * a),
					metrics.control_radius + 1.f, 0, 1.5f);
			}

			ImU32 tcol = (hov || is_open) ? th_mb.text_primary : th_mb.text_secondary;
			dl->AddText(mb_label_font, mb_label_size,
				ImVec2(mx_cursor + metrics.menu_item_pad_x, my0 + (menu_h - mb_label_size) * 0.5f),
				aida::ui::with_alpha(tcol, a), menus[i].label);

			bool need_open = false;
			if (clicked_btn) {
				bool was_open = is_open;
				menu_bar::open_menu = was_open ? -1 : i;
				menu_bar::any_open = (menu_bar::open_menu >= 0);
				if (!was_open) need_open = true;
			}
			if (hov && menu_bar::any_open && !is_open) {
				menu_bar::open_menu = i;
				need_open = true;
			}
			is_open = (menu_bar::open_menu == i);


			if (is_open) {
				ImGui::SetNextWindowPos(ImVec2(bmin.x, my1 + 4.f));
				ImGui::SetNextWindowBgAlpha(1.0f);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, metrics.corner_radius);
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(gap * 1.5f, gap * 2.f));
				ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
				ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th_mb.panel_bg, 1.f)));
				ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0,0,0,0));

				char popup_id[32];
				snprintf(popup_id, sizeof(popup_id), "##menu_%d", i);
				if (need_open) ImGui::OpenPopup(popup_id);

				if (i == 2 || i == 13)
					ImGui::SetNextWindowSizeConstraints(ImVec2(320.f, 240.f),
						ImVec2(420.f, ImGui::GetMainViewport()->WorkSize.y * 0.82f));
				if (ImGui::BeginPopup(popup_id)) {
					float mw = 280.f;

					ImVec2 pwp = ImGui::GetWindowPos();
					ImVec2 pws = ImGui::GetWindowSize();
					ImVec2 pa(pwp.x, pwp.y);
					ImVec2 pb(pwp.x + pws.x, pwp.y + pws.y);
					ImDrawList* pdl = ImGui::GetWindowDrawList();
					aida::ui::blur::layer_request_t pr;
					pr.pos = pa; pr.size = pws; pr.radius = metrics.corner_radius; pr.strength = 0.85f; pr.alpha = 1.f;
					aida::ui::blur::schedule(pr);
					aida::ui::blur::render_drop_shadow(pdl, pa, pb, metrics.corner_radius, 5, 0.55f, ImVec2(0.f, gap * 2.f));
					{
						const auto& th_pp = aida::ui::resolved();
						pdl->AddRectFilled(pa, pb,
							aida::ui::with_alpha(th_pp.panel_bg, 1.0f), metrics.corner_radius);
					}
					aida::ui::blur::render_glass_border(pdl, pa, pb, metrics.corner_radius, 1.f, 1.f);

					auto menu_item = [&](const char* label, const char* shortcut, bool enabled = true) -> bool {
						const auto& th_p = aida::ui::resolved();
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImU32 tc = enabled ? th_p.text_primary : th_p.text_dim;
						ImFont* f_label = aida::ui::fonts::lg();
						if (!f_label) f_label = aida::ui::fonts::body();
						if (!f_label) f_label = ImGui::GetFont();
						ImFont* f_short = aida::ui::fonts::body();
						if (!f_short) f_short = f_label;
						const float label_sz = aida::ui::fonts::size_or(f_label, metrics.menu_font);
						const float short_sz = aida::ui::fonts::size_or(f_short, metrics.caption_font);
						const float item_h = (std::max)(aida::ui::scale_px(34.f, metrics.scale),
							(std::max)(label_sz, short_sz) + aida::ui::scale_px(12.f, metrics.scale));
						const float label_pad = aida::ui::scale_px(16.f, metrics.scale);
						const float shortcut_pad = aida::ui::scale_px(14.f, metrics.scale);
						float label_clip_right = cp.x + mw - shortcut_pad;
						if (shortcut && shortcut[0]) {
							ImVec2 sts = f_short->CalcTextSizeA(short_sz, FLT_MAX, 0.f, shortcut);
							label_clip_right = (std::max)(cp.x + label_pad, cp.x + mw - sts.x - shortcut_pad - aida::ui::scale_px(10.f, metrics.scale));
						}
						ImGui::PushID(label);
						ImGui::InvisibleButton("##mi", ImVec2(mw, item_h));
						bool mhov = enabled && ImGui::IsItemHovered();
						bool clicked = enabled && ImGui::IsItemClicked(ImGuiMouseButton_Left);
						ImGui::PopID();
						ImVec2 rmin = cp;
						ImVec2 rmax(cp.x + mw, cp.y + item_h);
						ImDrawList* idl = ImGui::GetWindowDrawList();
						if (mhov) idl->AddRectFilled(rmin, rmax,
							aida::ui::with_alpha(th_p.hover_wash, 1.f),
							aida::ui::scale_px(aida::ui::metrics::radius::md, metrics.scale));
						ImVec4 label_clip(cp.x + label_pad, cp.y, label_clip_right, cp.y + item_h);
						idl->AddText(f_label, label_sz,
							ImVec2(cp.x + label_pad, cp.y + (item_h - label_sz) * 0.5f), tc, label, nullptr, 0.f, &label_clip);
						if (shortcut && shortcut[0]) {
							ImVec2 sts = f_short->CalcTextSizeA(short_sz, FLT_MAX, 0.f, shortcut);
							ImVec4 short_clip(cp.x + mw * 0.45f, cp.y, cp.x + mw - shortcut_pad, cp.y + item_h);
							idl->AddText(f_short, short_sz,
								ImVec2(cp.x + mw - sts.x - shortcut_pad, cp.y + (item_h - short_sz) * 0.5f),
								aida::ui::with_alpha(th_p.text_dim, 1.f), shortcut, nullptr, 0.f, &short_clip);
						}
						if (clicked) { menu_bar::open_menu = -1; menu_bar::any_open = false; menu_bar::suppress_frames = 2; ImGui::CloseCurrentPopup(); }
						return clicked;
					};

					auto menu_sep = [&]() {
						const auto& th_p = aida::ui::resolved();
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImGui::GetWindowDrawList()->AddLine(
							ImVec2(cp.x + 12.f, cp.y + 6.f), ImVec2(cp.x + mw - 12.f, cp.y + 6.f),
							aida::ui::with_alpha(th_p.border_subtle, 1.f));
						ImGui::Dummy(ImVec2(mw, 12.f));
					};

					auto action_menu_item = [&](const char* action_id,
						const char* shortcut_fallback = "",
						const char* label_override = nullptr) -> bool {
						auto presentation = aida::ui::application_ui::present_action(action_id);
						if (!presentation.visible)
							return false;
						const char* label = label_override && *label_override
							? label_override : presentation.label.c_str();
						const char* shortcut = !presentation.shortcut.empty()
							? presentation.shortcut.c_str() : shortcut_fallback;
						const bool selected = menu_item(label, shortcut, presentation.enabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						const std::string action_semantic_id = aida::preview::semantics::stable_id(
							"aida.menu.action", action_id);
						aida::preview::semantics::register_last_item(
							action_semantic_id, "application-menu-action", false,
							!presentation.enabled);
#endif
						if (!presentation.enabled &&
							ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) &&
							!presentation.disabled_reason.empty())
							ImGui::SetTooltip("%s", presentation.disabled_reason.c_str());
						if (selected)
							aida::ui::application_ui::execute_action(
								action_id, aida::ui::action_invocation_source_t::application_menu);
						return selected;
					};

					auto render_view_category = [&](aida::ui::view_category_t category) {
						aida::ui::application_views::for_each_menu_entry(
							[&](const aida::ui::application_views::menu_entry_t& entry) {
								if (entry.category != category)
									return;
								const std::string action_id =
									aida::ui::application_ui::view_action_id(entry.id);
								action_menu_item(action_id.c_str(), "", entry.label.c_str());
							});
					};

					switch (i) {
					case 0:
					{
						action_menu_item("file.new", "Ctrl+N");
						action_menu_item("file.open", "Ctrl+O");
						action_menu_item("file.open_folder", "Ctrl+K");
						menu_sep();
						action_menu_item("file.save", "Ctrl+S");
						action_menu_item("file.save_as", "Ctrl+Shift+S");
						action_menu_item("file.save_all");
						action_menu_item("file.close", "Ctrl+W");
						menu_sep();
						action_menu_item("file.exit", "Alt+F4");
						break;
					}
					case 1:
					{
						action_menu_item("edit.undo", "Ctrl+Z");
						action_menu_item("edit.redo", "Ctrl+Y");
						menu_sep();
						action_menu_item("edit.cut", "Ctrl+X");
						action_menu_item("edit.copy", "Ctrl+C");
						action_menu_item("edit.paste", "Ctrl+V");
						action_menu_item("edit.delete", "Del");
						action_menu_item("edit.select_all", "Ctrl+A");
						menu_sep();
						action_menu_item("edit.find", "Ctrl+F");
						action_menu_item("edit.replace", "Ctrl+H");
						action_menu_item("edit.goto_line", "Ctrl+G");
						menu_sep();
						action_menu_item("edit.preferences", "Ctrl+,");
						break;
					}
					case 2:
					{
						action_menu_item("view.command_palette", "Ctrl+Shift+P");
						action_menu_item("view.global_search", "Ctrl+Shift+F");
						action_menu_item("view.reopen_last_closed");
						action_menu_item("view.open_default_missing");
						action_menu_item("shell.toggle_maximize", "F11");
						menu_sep();
						aida::ui::view_category_t last_category = aida::ui::view_category_t::settings;
						bool first_category = true;
						aida::ui::application_views::for_each_menu_entry(
							[&](const aida::ui::application_views::menu_entry_t& entry) {
								if (first_category || entry.category != last_category) {
									if (!first_category)
										menu_sep();
									menu_item(aida::ui::application_views::category_label(entry.category), "", false);
									last_category = entry.category;
									first_category = false;
								}
								std::string label = entry.open ? "Close " : "Open ";
								label += entry.label;
								const std::string action_id = aida::ui::application_ui::view_action_id(entry.id);
								action_menu_item(action_id.c_str(), "", label.c_str());
							});
						break;
					}
					case 3:
					{
						action_menu_item("view.focus.document.disassembly", "G", "Disassembly");
						action_menu_item("analysis.decompile_or_focus_pseudocode", "F5", "Pseudocode");
						action_menu_item("view.focus.document.graph", "Space", "Graph");
						action_menu_item("view.focus.document.hex", "", "Hex");
						action_menu_item("view.focus.view.analysis.references", "X", "Cross References");
						action_menu_item("view.focus.view.workspace_search", "Ctrl+Shift+F", "Workspace Search");
						break;
					}
					case 4:
					{
						action_menu_item("tools.load_binary");
						action_menu_item("analysis.decompile_or_focus_pseudocode", "F5");
						menu_sep();
						render_view_category(aida::ui::view_category_t::analysis);
						break;
					}
					case 5:
					{
						action_menu_item("tools.attach_process");
						menu_sep();
						render_view_category(aida::ui::view_category_t::debugger);
						break;
					}
					case 6:
					{
						render_view_category(aida::ui::view_category_t::memory);
						break;
					}
					case 7:
					{
						render_view_category(aida::ui::view_category_t::types);
						break;
					}
					case 8:
					{
						render_view_category(aida::ui::view_category_t::network);
						break;
					}
					case 9:
					{
						std::size_t preset_count = 0;
						const auto* presets = aida::ui::workspace_layout::presets(preset_count);
						for (std::size_t preset_index = 0; preset_index < preset_count; ++preset_index) {
							const auto& preset = presets[preset_index];
							if (preset.id == aida::ui::workspace_layout::workspace_preset_t::safe)
								continue;
							std::string action_id = "workspace.switch.";
							action_id.append(preset.stable_id);
							action_menu_item(action_id.c_str(),
								aida::ui::workspace_layout::active_preset() == preset.id ? "Active" : "",
								preset.display_name.data());
						}
						menu_sep();
						action_menu_item("workspace.lock", "", aida::ui::workspace_layout::layout_locked() ? "Unlock Layout" : "Lock Layout");
						action_menu_item("workspace.save");
						action_menu_item("workspace.restore_builtin");
						action_menu_item("workspace.reset_current");
						action_menu_item("workspace.open_missing");
						action_menu_item("workspace.safe");
						break;
					}
					case 10:
					{
						action_menu_item("tools.load_binary");
						action_menu_item("tools.attach_process");
						menu_sep();
						action_menu_item("tools.settings", "", "MCP Servers");
						action_menu_item("tools.driver_status");
						break;
					}
					case 11:
					{
						action_menu_item("ai.new_chat", "Ctrl+L");
						action_menu_item("ai.model_settings");
						menu_sep();
						render_view_category(aida::ui::view_category_t::automation);
						break;
					}
					case 12:
					{
						action_menu_item("help.shortcuts");
						const std::string diagnostics_id =
							aida::ui::application_ui::view_action_id(
								aida::ui::stable_view_id_t("view.diagnostics"));
						action_menu_item(diagnostics_id.c_str(), "", "Diagnostics");
						break;
					}
					case 13:
					{
						menu_item("Analysis", "", false);
						action_menu_item("tools.load_binary");
						render_view_category(aida::ui::view_category_t::analysis);
						menu_sep();
						menu_item("Debugger", "", false);
						action_menu_item("tools.attach_process");
						render_view_category(aida::ui::view_category_t::debugger);
						menu_sep();
						menu_item("Memory", "", false);
						render_view_category(aida::ui::view_category_t::memory);
						menu_sep();
						menu_item("Types and Structures", "", false);
						render_view_category(aida::ui::view_category_t::types);
						menu_sep();
						menu_item("Network", "", false);
						render_view_category(aida::ui::view_category_t::network);
						menu_sep();
						menu_item("Workspace", "", false);
						std::size_t preset_count = 0;
						const auto* presets = aida::ui::workspace_layout::presets(preset_count);
						for (std::size_t preset_index = 0; preset_index < preset_count; ++preset_index) {
							const auto& preset = presets[preset_index];
							if (preset.id == aida::ui::workspace_layout::workspace_preset_t::safe)
								continue;
							std::string action_id = "workspace.switch.";
							action_id.append(preset.stable_id);
							action_menu_item(action_id.c_str(), "", preset.display_name.data());
						}
						action_menu_item("workspace.lock", "",
							aida::ui::workspace_layout::layout_locked() ? "Unlock Layout" : "Lock Layout");
						action_menu_item("workspace.save");
						action_menu_item("workspace.restore_builtin");
						action_menu_item("workspace.reset_current");
						action_menu_item("workspace.open_missing");
						action_menu_item("workspace.safe");
						menu_sep();
						menu_item("Tools", "", false);
						action_menu_item("tools.settings");
						action_menu_item("tools.driver_status");
						menu_sep();
						menu_item("AI", "", false);
						action_menu_item("ai.new_chat", "Ctrl+L");
						action_menu_item("ai.model_settings");
						render_view_category(aida::ui::view_category_t::automation);
						menu_sep();
						menu_item("Help", "", false);
						action_menu_item("help.shortcuts");
						break;
					}
					}
					ImGui::EndPopup();
				} else {
					menu_bar::open_menu = -1;
					menu_bar::any_open = false;
				}
				ImGui::PopStyleColor(2);
				ImGui::PopStyleVar(3);
			}

			mx_cursor += btn_w;
		}


		if (menu_bar::any_open && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
			!ImGui::IsMouseHoveringRect(ImVec2(wp.x, my0), ImVec2(wp.x + ww, my1)) &&
			!ImGui::IsWindowHovered(ImGuiHoveredFlags_AnyWindow)) {
			menu_bar::open_menu = -1;
			menu_bar::any_open = false;
		}


	}


	const auto& th_lp = aida::ui::resolved();
	float ax3 = globals::ui::accent.x, ay3 = globals::ui::accent.y, az3 = globals::ui::accent.z;
	ImU32 ac_full = aida::ui::with_alpha(th_lp.accent_u32, a);

	const float hdr_pad = aida::ui::scale_px(aida::ui::metrics::spacing::md, metrics.scale);
	const float row_h = aida::ui::scale_px(aida::ui::metrics::row::compact, metrics.scale);
	const float row_gap = aida::ui::scale_px(aida::ui::metrics::spacing::xxs, metrics.scale);
	const float tb_vpad = aida::ui::scale_px(aida::ui::metrics::spacing::sm, metrics.scale);
	const float hdr_h    = tb_vpad * 2.f + row_h * 2.f + row_gap;

	ImDrawList* wdl  = ImGui::GetWindowDrawList();
	ImVec2      wp_m = ImGui::GetWindowPos();


	g_render_section = "title_strip_layout";
	float hx0 = wp_m.x + pad, hy0 = wp_m.y + content_top;
	float hx1  = hx0 + center_w;
	float hy1  = hy0 + hdr_h;
	float dc_y1 = wp_m.y + content_top + total_h;

	const auto& th_cp = aida::ui::resolved();

	wdl->AddRectFilled(ImVec2(hx0, hy0), ImVec2(hx1, dc_y1),
		th_cp.panel_bg, metrics.corner_radius);
	wdl->AddRect(ImVec2(hx0, hy0), ImVec2(hx1, dc_y1),
		aida::ui::with_alpha(th_cp.border_subtle, a), metrics.corner_radius, 0, 1.f);


	wdl->AddRectFilled(ImVec2(hx0, hy0), ImVec2(hx1, hy1),
		th_cp.panel_header, metrics.corner_radius, ImDrawFlags_RoundCornersTop);


	const float sep_y = hy0 + hdr_h * 0.5f;
	const float r1_cy = hy0 + hdr_h * 0.25f;
	const float r2_cy = hy0 + hdr_h * 0.75f;


	wdl->AddLine(ImVec2(hx0, sep_y), ImVec2(hx1, sep_y),
		aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 1.f);

	wdl->AddLine(ImVec2(hx0, hy1), ImVec2(hx1, hy1),
		aida::ui::with_alpha(th_lp.hover_wash, 0.55f*a), 1.f);


	auto ghost_btn = [&](const char* label, ImGuiID id_hv, ImGuiID id_fl,
		float bx0, float cy, float bw2) -> bool
	{
		ImGuiStorage* st = ImGui::GetStateStorage();
		ImVec2 ts  = ImGui::CalcTextSize(label);
		float  bh2 = row_h - 2.f;
		float  by0 = cy - bh2 * 0.5f;
		float  bx1 = bx0 + bw2, by1 = by0 + bh2;
		bool   bhv = !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseHoveringRect(ImVec2(bx0,by0), ImVec2(bx1,by1), false);
		bool   bck = bhv && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
		float  bht = st->GetFloat(id_hv, 0.f);
		float  bft = st->GetFloat(id_fl, 0.f);
		bht += ((bhv ? 1.f : 0.f) - bht) * std::min(12.f * dt, 1.f);
		bft += ((bck ? 1.f : 0.f) - bft) * std::min(22.f * dt, 1.f);
		st->SetFloat(id_hv, bht);
		st->SetFloat(id_fl, bft);
		float bg_a  = (bht * 0.72f + bft * 0.20f) * a;
		float brd_a = (0.48f + bht * 0.34f) * a;
		float txt_a = (0.72f + bht * 0.28f) * a;
		wdl->AddRectFilled(ImVec2(bx0,by0), ImVec2(bx1,by1),
			aida::ui::with_alpha(th_lp.hover_wash, bg_a),
			aida::ui::scale_px(aida::ui::metrics::radius::sm, metrics.scale));
		wdl->AddRect(ImVec2(bx0,by0), ImVec2(bx1,by1),
			aida::ui::with_alpha(th_lp.border_subtle, brd_a),
			aida::ui::scale_px(aida::ui::metrics::radius::sm, metrics.scale), 0, 1.f);
		wdl->AddText(ImVec2(bx0 + (bw2 - ts.x) * 0.5f, by0 + (bh2 - ts.y) * 0.5f),
			aida::ui::with_alpha(th_lp.text_secondary, txt_a), label);
		return bck;
	};


	const float rbtn_w  = std::max(
		ImGui::CalcTextSize("Choose File").x,
		ImGui::CalcTextSize("Run").x) + 32.f;
	const float rbtn_x0 = hx1 - hdr_pad - rbtn_w;


	{


		bool row2_has_vt_btn = static_cast<bool>(active_workspace_context);
		float row2_vt_btn_w = 0.f;
		if (row2_has_vt_btn) {
			bool is_hex_view_pre = (globals::ui::active_center_view == center_view_t::hex_view);
			const char* vt_label_pre = is_hex_view_pre ? "View Disassembly" : "View Hex";
			row2_vt_btn_w = ImGui::CalcTextSize(vt_label_pre).x + 32.f;
		}
		const float row2_right_anchor = rbtn_x0 - (row2_has_vt_btn ? (row2_vt_btn_w + 8.f) : 0.f);

		const float strip_chev_w = 18.f;
		const float strip_drop_w = 22.f;
		const float strip_div_w  = 1.f;
		const float strip_lchev_x0 = hx0 + hdr_pad;
		const float strip_lchev_x1 = strip_lchev_x0 + strip_chev_w;
		const float strip_div1_x   = strip_lchev_x1;
		const float strip_tabs_x0  = strip_div1_x + strip_div_w + 4.f;

		const float strip_right_edge = row2_right_anchor - 10.f;
		const float strip_drop_x1  = strip_right_edge;
		const float strip_drop_x0  = strip_drop_x1 - strip_drop_w;
		const float strip_div3_x   = strip_drop_x0 - 2.f;
		const float strip_rchev_x1 = strip_div3_x - strip_div_w;
		const float strip_rchev_x0 = strip_rchev_x1 - strip_chev_w;
		const float strip_div2_x   = strip_rchev_x0 - 2.f;
		const float strip_tabs_x1  = strip_div2_x - strip_div_w - 4.f;

		ImGuiStorage* strip_st = ImGui::GetStateStorage();
		const ImGuiID strip_id_scroll        = ImGui::GetID("##strip_scroll");
		const ImGuiID strip_id_scroll_target = ImGui::GetID("##strip_scroll_target");
		const ImGuiID strip_id_active_sig    = ImGui::GetID("##strip_active_sig");
		float strip_scroll = strip_st->GetFloat(strip_id_scroll, 0.f);
		float strip_scroll_target = strip_st->GetFloat(strip_id_scroll_target, 0.f);

		const float tab_h_strip   = row_h - 2.f;
		const float strip_tab_y0  = r2_cy - tab_h_strip * 0.5f;
		const float strip_tab_y1  = strip_tab_y0 + tab_h_strip;

		struct strip_entry_t {
			std::string label;
			int  kind = 0;
			int  idx  = -1;
			uint64_t addr = 0;
			bool is_active = false;
			bool dirty = false;
			bool error = false;
			float width = 0.f;
		};
		g_render_section = "title_strip_entries_build";
		std::vector<strip_entry_t> strip_entries;
		strip_entries.reserve(file_tabs::tabs.size() + 8);

		const float tab_pad_x_strip = 10.f;
		const float close_sz_strip  = 10.f;

		auto strip_calc_w = [&](const std::string& label) -> float {
			ImVec2 ts = ImGui::CalcTextSize(label.c_str());
			return tab_pad_x_strip * 2.f + ts.x + close_sz_strip + 12.f;
		};

		for (std::size_t ti = 0; ti < file_tabs::tabs.size(); ++ti) {
			auto& tab = file_tabs::tabs[ti];
			const int tab_index = static_cast<int>(ti);
			strip_entry_t e;
			e.label = tab.filename + (tab.dirty ? " *" : "");
			e.kind = 0;
			e.idx = tab_index;
			e.is_active = ((tab_index == file_tabs::active_tab) && code_editor::active &&
			              globals::ui::active_center_view == center_view_t::code_editor);
			e.dirty = tab.dirty;
			e.width = strip_calc_w(e.label);
			strip_entries.push_back(std::move(e));
		}

		{
			g_render_section = "title_strip_psv_snapshot";
			const unsigned long long psv_snap1_t0 = aida::shell_platform::tick_ms();
			auto psv_tabs_for_strip = pseudocode_view::snapshot_tabs(active_workspace_context);
			const unsigned long long psv_snap1_elapsed = aida::shell_platform::tick_ms() - psv_snap1_t0;
			if (psv_snap1_elapsed >= 50ULL) {
				diag::log_tagged_critical_fmt("helpers",
					"helpers_psv_snapshot1_slow elapsed_ms=%llu tabs=%zu tid=%lu tick_ms=%llu",
					psv_snap1_elapsed,
					psv_tabs_for_strip.size(),
					static_cast<unsigned long>(aida::shell_platform::thread_id()),
					static_cast<unsigned long long>(aida::shell_platform::tick_ms()));
			}
			bool psv_view_active = (globals::ui::active_center_view == center_view_t::pseudocode);
			uint64_t active_psv_addr = pseudocode_view::active_tab_address(active_workspace_context);
			for (auto& pt : psv_tabs_for_strip) {
				strip_entry_t e;
				if (!pt.function_name.empty()) e.label = pt.function_name;
				else if (!pt.label.empty()) e.label = pt.label;
				else {
					char nm[64];
					std::snprintf(nm, sizeof(nm), "sub_%llX",
						static_cast<unsigned long long>(pt.addr));
					e.label = nm;
				}
				if (pt.decompiling) e.label += " ...";
				e.kind = 2;
				e.addr = pt.addr;
				e.error = pt.is_error;
				e.is_active = (psv_view_active && pt.addr == active_psv_addr);
				e.width = strip_calc_w(e.label);
				strip_entries.push_back(std::move(e));
			}
		}

		if (hex_view::active(active_workspace_context)) {
			strip_entry_t e;
			const std::string hex_source = hex_view::source_name(active_workspace_context);
			e.label = hex_source.empty()
				? std::string("Hex View")
				: hex_source + " (Hex)";
			e.kind = 3;
			e.is_active = (globals::ui::active_center_view == center_view_t::hex_view);
			e.width = strip_calc_w(e.label);
			strip_entries.push_back(std::move(e));
		}

		float strip_total_w = 0.f;
		for (auto& e : strip_entries) strip_total_w += e.width + 2.f;
		if (strip_total_w > 0.f) strip_total_w -= 2.f;

		const float strip_visible_w = std::max(20.f, strip_tabs_x1 - strip_tabs_x0);
		const bool  strip_has_overflow = (strip_total_w > strip_visible_w + 0.5f);
		const float strip_max_scroll = strip_has_overflow ? (strip_total_w - strip_visible_w) : 0.f;

		{
			float ax_running = 0.f;
			int active_idx = -1;
			for (std::size_t i = 0; i < strip_entries.size(); ++i) {
				auto& e = strip_entries[i];
				if (e.is_active) { active_idx = static_cast<int>(i); break; }
				ax_running += e.width + 2.f;
			}
			if (active_idx >= 0 && strip_has_overflow) {
				const std::size_t active_entry_index = static_cast<std::size_t>(active_idx);
				char sig_buf[64];
				std::snprintf(sig_buf, sizeof(sig_buf), "%d|%s",
					active_idx, strip_entries[active_entry_index].label.c_str());
				ImGuiID sig_id = ImGui::GetID(sig_buf);
				ImGuiID prev_sig_id = (ImGuiID)strip_st->GetInt(strip_id_active_sig, 0);
				if (sig_id != prev_sig_id) {
					float aw = strip_entries[active_entry_index].width;
					float min_off = ax_running + aw - strip_visible_w + 12.f;
					float max_off = ax_running - 12.f;
					if (strip_scroll_target < min_off) strip_scroll_target = min_off;
					if (strip_scroll_target > max_off) strip_scroll_target = max_off;
					strip_st->SetInt(strip_id_active_sig, (int)sig_id);
				}
			}
		}

		if (strip_scroll_target < 0.f) strip_scroll_target = 0.f;
		if (strip_scroll_target > strip_max_scroll) strip_scroll_target = strip_max_scroll;
		strip_scroll = aida::motion::smooth_lerp(strip_scroll, strip_scroll_target, 18.f, dt);
		if (strip_scroll < 0.f) strip_scroll = 0.f;
		if (strip_scroll > strip_max_scroll) strip_scroll = strip_max_scroll;

		wdl->PushClipRect(ImVec2(strip_tabs_x0 - 2.f, strip_tab_y0 - 8.f),
			ImVec2(strip_tabs_x1 + 2.f, strip_tab_y1 + 8.f), true);

		g_render_section = "title_strip_file_tabs_render";
		if (!file_tabs::tabs.empty()) {
			const float tab_pad_x = 10.f;
			const float tab_gap   = 2.f;
			const float close_sz  = 10.f;
			const float tab_h     = row_h - 2.f;
			float tab_x = strip_tabs_x0 - strip_scroll;
			float tab_y = r2_cy - tab_h * 0.5f;

			int close_idx = -1;
			int click_idx = -1;
			int context_idx = -1;
			aida::ui::context_menu_open_origin_t tab_context_origin =
				aida::ui::context_menu_open_origin_t::pointer;
			float active_tx0 = -1.f, active_tx1 = -1.f, active_ty0 = 0.f;
			const ImVec2 tab_cursor_restore = ImGui::GetCursorScreenPos();

			for (std::size_t ti = 0; ti < file_tabs::tabs.size(); ++ti) {
				auto& tab = file_tabs::tabs[ti];
				const int tab_index = static_cast<int>(ti);
				bool is_active = (tab_index == file_tabs::active_tab);


				std::string label = tab.filename;
				if (tab.dirty) label += " *";

				ImVec2 lts = ImGui::CalcTextSize(label.c_str());
				float tw = tab_pad_x * 2.f + lts.x + close_sz + 6.f;

				float tx0 = tab_x, ty0 = tab_y;
				float tx1 = tab_x + tw, ty1 = tab_y + tab_h;

				bool tx_in_view = (tx1 >= strip_tabs_x0 - 2.f) && (tx0 <= strip_tabs_x1 + 2.f);
				bool mouse_in_strip = !ui_input_gate::popup_blocks_background_input() &&
					ImGui::IsMouseHoveringRect(
						ImVec2(strip_tabs_x0, strip_tab_y0 - 4.f),
						ImVec2(strip_tabs_x1, strip_tab_y1 + 4.f), false);
				(void)tx_in_view;

				ImGui::SetCursorScreenPos(ImVec2(tx0, ty0));
				ImGui::PushID(tab_index);
				ImGui::InvisibleButton("##editor_tab", ImVec2(tw, tab_h));
				const bool tab_item_hovered = ImGui::IsItemHovered();
				const bool tab_item_focused = ImGui::IsItemFocused();
				const bool tab_left_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				const bool tab_right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
				ImGui::PopID();
				bool tab_hov = mouse_in_strip && tab_item_hovered;


				if (is_active) {
					wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
						aida::ui::with_alpha(th_lp.selection, 0.86f * a),
						4.f, ImDrawFlags_RoundCornersTop);
					active_tx0 = tx0 + 2.f;
					active_tx1 = tx1 - 2.f;
					active_ty0 = ty0;
				} else if (tab_hov) {
					wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
						aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 4.f, ImDrawFlags_RoundCornersTop);
				}
				if (tab_item_focused)
					wdl->AddRect(ImVec2(tx0 + 1.f, ty0 + 1.f), ImVec2(tx1 - 1.f, ty1 - 1.f),
						aida::ui::with_alpha(th_lp.border_focus, a), 4.f, 0, 1.5f);


				ImU32 tab_col = is_active ? ac_full
				              : aida::ui::with_alpha(th_lp.text_secondary, (tab_hov ? 1.f : 0.78f)*a);
				wdl->AddText(ImVec2(tx0 + tab_pad_x, ty0 + (tab_h - lts.y) * 0.5f),
					tab_col, label.c_str());


				float cx0 = tx1 - tab_pad_x - close_sz;
				float cy0 = ty0 + (tab_h - close_sz) * 0.5f;
				float cx1 = cx0 + close_sz, cy1 = cy0 + close_sz;
				bool close_hov = mouse_in_strip &&
					ImGui::IsMouseHoveringRect(ImVec2(cx0, cy0), ImVec2(cx1, cy1), false);
				if (close_hov) {
					wdl->AddRectFilled(ImVec2(cx0 - 1, cy0 - 1), ImVec2(cx1 + 1, cy1 + 1),
						aida::ui::with_alpha(th_lp.error, 0.16f*a), 3.f);
				}
				ImU32 close_col = close_hov
					? aida::ui::with_alpha(th_lp.error, 0.86f*a)
					: aida::ui::with_alpha(th_lp.text_dim, (is_active ? 0.78f : 0.45f)*a);
				float cmx = (cx0 + cx1) * 0.5f, cmy = (cy0 + cy1) * 0.5f;
				float cr = 3.f;
				wdl->AddLine(ImVec2(cmx - cr, cmy - cr), ImVec2(cmx + cr, cmy + cr), close_col, 1.2f);
				wdl->AddLine(ImVec2(cmx + cr, cmy - cr), ImVec2(cmx - cr, cmy + cr), close_col, 1.2f);


				if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					close_idx = tab_index;
				else if (tab_hov && !close_hov && tab_left_clicked)
					click_idx = tab_index;
				if (tab_hov && tab_right_clicked) {
					context_idx = tab_index;
					tab_context_origin = aida::ui::context_menu_open_origin_t::pointer;
				}
				if (tab_item_focused &&
					(ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
					 ImGui::IsKeyPressed(ImGuiKey_Space, false)))
					click_idx = tab_index;
				if (tab_item_focused &&
					(ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
					 (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)))) {
					context_idx = tab_index;
					tab_context_origin = ImGui::IsKeyPressed(ImGuiKey_Menu, false)
						? aida::ui::context_menu_open_origin_t::menu_key
						: aida::ui::context_menu_open_origin_t::shift_f10;
				}
				if (tab_item_focused && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false) && tab_index > 0)
					click_idx = tab_index - 1;
				if (tab_item_focused && ImGui::IsKeyPressed(ImGuiKey_RightArrow, false) &&
					static_cast<std::size_t>(tab_index + 1) < file_tabs::tabs.size())
					click_idx = tab_index + 1;


				if (ti + 1 < file_tabs::tabs.size()) {
					wdl->AddLine(ImVec2(tx1, ty0 + 3.f), ImVec2(tx1, ty1 - 3.f),
						aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 1.f);
				}

				tab_x = tx1 + tab_gap;
			}
			ImGui::SetCursorScreenPos(tab_cursor_restore);


			if (close_idx >= 0) {
				if (static_cast<std::size_t>(close_idx) < file_tabs::tabs.size() &&
					file_tabs::tabs[static_cast<std::size_t>(close_idx)].dirty) {
					file_tabs::pending_close_idx = close_idx;
					file_tabs::show_close_confirm = true;
				} else {
					file_tabs::close_tab(close_idx);
				}
			}
			else if (click_idx >= 0 && click_idx != file_tabs::active_tab) {
				file_tabs::switch_to(click_idx);
				globals::ui::active_center_view = center_view_t::code_editor;
			}
			if (context_idx >= 0)
				aida::ui::application_ui::open_editor_tab_context_menu(
					context_idx, tab_context_origin);
			aida::ui::application_ui::render_editor_tab_context_menu();

			if (active_tx0 >= 0.f) {
				ImGuiID ct_ulx = ImGui::GetID("##ct_ul_x");
				ImGuiID ct_ulw = ImGui::GetID("##ct_ul_w");
				ImGuiID ct_ulvx = ImGui::GetID("##ct_ul_vx");
				float ct_x = ImGui::GetStateStorage()->GetFloat(ct_ulx, active_tx0);
				float ct_w = ImGui::GetStateStorage()->GetFloat(ct_ulw, active_tx1 - active_tx0);
				float ct_vx = ImGui::GetStateStorage()->GetFloat(ct_ulvx, 0.f);
				float tgt_w = active_tx1 - active_tx0;
				ct_x = aida::motion::spring_step(ct_x, active_tx0, ct_vx,
					aida::motion::spring::balanced, dt);
				ct_w = aida::motion::smooth_lerp(ct_w, tgt_w, 16.f, dt);
				ImGui::GetStateStorage()->SetFloat(ct_ulx, ct_x);
				ImGui::GetStateStorage()->SetFloat(ct_ulw, ct_w);
				ImGui::GetStateStorage()->SetFloat(ct_ulvx, ct_vx);
				ui_anim::render_tab_underline_glow(wdl, ct_x, ct_w, active_ty0 + 1.f, a);
			}

		}


		float next_tab_x_after_disasm = strip_tabs_x0 - strip_scroll;
		if (!file_tabs::tabs.empty()) {
			float last_tab_end = strip_tabs_x0 - strip_scroll;
			for (std::size_t ti = 0; ti < file_tabs::tabs.size(); ++ti) {
				auto& tab = file_tabs::tabs[ti];
				std::string label = tab.filename;
				if (tab.dirty) label += " *";
				ImVec2 lts = ImGui::CalcTextSize(label.c_str());
				float tw = 10.f * 2.f + lts.x + 10.f + 6.f;
				last_tab_end += tw + 2.f;
			}
			next_tab_x_after_disasm = last_tab_end + 4.f;
		}

		{
			g_render_section = "title_strip_psv_render";
			const unsigned long long psv_snap2_t0 = aida::shell_platform::tick_ms();
			auto psv_tabs = pseudocode_view::snapshot_tabs(active_workspace_context);
			const unsigned long long psv_snap2_elapsed = aida::shell_platform::tick_ms() - psv_snap2_t0;
			if (psv_snap2_elapsed >= 50ULL) {
				diag::log_tagged_critical_fmt("helpers",
					"helpers_psv_snapshot2_slow elapsed_ms=%llu tabs=%zu tid=%lu tick_ms=%llu",
					psv_snap2_elapsed,
					psv_tabs.size(),
					static_cast<unsigned long>(aida::shell_platform::thread_id()),
					static_cast<unsigned long long>(aida::shell_platform::tick_ms()));
			}
			if (!psv_tabs.empty()) {
				bool psv_view_active = (globals::ui::active_center_view == center_view_t::pseudocode);
				uint64_t active_psv_addr = pseudocode_view::active_tab_address(active_workspace_context);

				const float p_close_sz = 10.f;
				float tab_h_p = row_h - 2.f;
				uint64_t to_activate_addr = 0;
				uint64_t to_close_addr = 0;

				bool psv_mouse_in_strip = !ui_input_gate::popup_blocks_background_input() &&
					ImGui::IsMouseHoveringRect(
						ImVec2(strip_tabs_x0, strip_tab_y0 - 4.f),
						ImVec2(strip_tabs_x1, strip_tab_y1 + 4.f), false);

				for (auto& pt : psv_tabs) {
					std::string lbl;
					if (!pt.function_name.empty()) {
						lbl = pt.function_name;
					} else if (!pt.label.empty()) {
						lbl = pt.label;
					} else {
						char nm[64];
						std::snprintf(nm, sizeof(nm), "sub_%llX",
							static_cast<unsigned long long>(pt.addr));
						lbl = nm;
					}
					if (pt.decompiling) lbl += " ...";

					ImVec2 plts = ImGui::CalcTextSize(lbl.c_str());
					float ptw = 10.f * 2.f + plts.x + p_close_sz + 12.f;
					float ptx0 = next_tab_x_after_disasm;
					float ptx1 = ptx0 + ptw;
					float pty0 = r2_cy - tab_h_p * 0.5f;
					float pty1 = pty0 + tab_h_p;

					bool ptab_active = (psv_view_active && pt.addr == active_psv_addr);
					bool ptab_hov = psv_mouse_in_strip &&
						ImGui::IsMouseHoveringRect(ImVec2(ptx0, pty0), ImVec2(ptx1, pty1), false);

					if (ptab_active) {
						wdl->AddRectFilled(ImVec2(ptx0, pty0), ImVec2(ptx1, pty1),
							aida::ui::with_alpha(th_lp.selection, 0.86f * a),
							4.f, ImDrawFlags_RoundCornersTop);
						ui_anim::render_tab_underline_glow(wdl, ptx0 + 4.f,
							(ptx1 - ptx0) - 8.f, pty0 + 1.f, a);
					} else if (ptab_hov) {
						wdl->AddRectFilled(ImVec2(ptx0, pty0), ImVec2(ptx1, pty1),
							aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 4.f, ImDrawFlags_RoundCornersTop);
					}

					ImU32 ptab_col = ptab_active ? ac_full
					               : (pt.is_error
					                  ? aida::ui::with_alpha(th_lp.warning, (ptab_hov ? 0.86f : 0.7f)*a)
					                  : aida::ui::with_alpha(th_lp.text_secondary, (ptab_hov ? 1.f : 0.78f)*a));
					wdl->AddText(ImVec2(ptx0 + 10.f, pty0 + (tab_h_p - plts.y) * 0.5f),
						ptab_col, lbl.c_str());
					(void)pty1;

					float pcx0 = ptx1 - p_close_sz - 6.f;
					float pcy0 = pty0 + (tab_h_p - p_close_sz) * 0.5f;
					float pcx1 = pcx0 + p_close_sz;
					float pcy1 = pcy0 + p_close_sz;
					bool pclose_hov = psv_mouse_in_strip &&
						ImGui::IsMouseHoveringRect(ImVec2(pcx0 - 2, pcy0 - 2),
							ImVec2(pcx1 + 2, pcy1 + 2), false);
					if (pclose_hov) {
						wdl->AddRectFilled(ImVec2(pcx0 - 1, pcy0 - 1), ImVec2(pcx1 + 1, pcy1 + 1),
							aida::ui::with_alpha(th_lp.error, 0.16f*a), 3.f);
					}
					ImU32 pclose_col = pclose_hov
						? aida::ui::with_alpha(th_lp.error, 0.86f*a)
						: aida::ui::with_alpha(th_lp.text_dim, (ptab_active ? 0.78f : 0.45f)*a);
					float pcmx = (pcx0 + pcx1) * 0.5f, pcmy = (pcy0 + pcy1) * 0.5f;
					float pcr = 3.f;
					wdl->AddLine(ImVec2(pcmx - pcr, pcmy - pcr), ImVec2(pcmx + pcr, pcmy + pcr), pclose_col, 1.2f);
					wdl->AddLine(ImVec2(pcmx + pcr, pcmy - pcr), ImVec2(pcmx - pcr, pcmy + pcr), pclose_col, 1.2f);

					if (pclose_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						to_close_addr = pt.addr;
					} else if (ptab_hov && !pclose_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						to_activate_addr = pt.addr;
					} else if (ptab_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Middle)) {
						to_close_addr = pt.addr;
					}

					next_tab_x_after_disasm = ptx1 + 4.f;
				}

				if (to_close_addr != 0) {
					pseudocode_view::close_tab_by_addr(active_workspace_context, to_close_addr);
					if (psv_view_active && pseudocode_view::tab_count(active_workspace_context) == 0) {
						globals::ui::active_center_view = center_view_t::disassembly;
					}
				} else if (to_activate_addr != 0) {
					pseudocode_view::activate_tab_by_addr(active_workspace_context, to_activate_addr);
					globals::ui::active_center_view = center_view_t::pseudocode;
				}
			}
		}

		if (hex_view::active(active_workspace_context)) {
			bool hex_is_active = (globals::ui::active_center_view == center_view_t::hex_view);
			const std::string hex_source = hex_view::source_name(active_workspace_context);
			std::string hex_label_str = hex_source.empty()
				? std::string("Hex View")
				: hex_source + " (Hex)";
			const char* hex_label = hex_label_str.c_str();
			ImVec2 hts = ImGui::CalcTextSize(hex_label);
			const float hex_close_sz = 10.f;
			float htw = 10.f * 2.f + hts.x + hex_close_sz + 12.f;
			float tab_h3 = row_h - 2.f;

			float htx0 = next_tab_x_after_disasm;
			float htx1 = htx0 + htw;
			{
				float hty0 = r2_cy - tab_h3 * 0.5f;
				float hty1 = hty0 + tab_h3;

				bool hex_mouse_in_strip = !ui_input_gate::popup_blocks_background_input() &&
					ImGui::IsMouseHoveringRect(
						ImVec2(strip_tabs_x0, strip_tab_y0 - 4.f),
						ImVec2(strip_tabs_x1, strip_tab_y1 + 4.f), false);
				bool htab_hov = hex_mouse_in_strip &&
					ImGui::IsMouseHoveringRect(ImVec2(htx0, hty0), ImVec2(htx1, hty1), false);

				if (hex_is_active) {
					wdl->AddRectFilled(ImVec2(htx0, hty0), ImVec2(htx1, hty1),
						aida::ui::with_alpha(th_lp.selection, 0.86f * a),
						4.f, ImDrawFlags_RoundCornersTop);
					ui_anim::render_tab_underline_glow(wdl, htx0 + 4.f,
						(htx1 - htx0) - 8.f, hty0 + 1.f, a);
				} else if (htab_hov) {
					wdl->AddRectFilled(ImVec2(htx0, hty0), ImVec2(htx1, hty1),
						aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 4.f, ImDrawFlags_RoundCornersTop);
				}

				ImU32 htab_col = hex_is_active ? ac_full
				               : aida::ui::with_alpha(th_lp.text_secondary, (htab_hov ? 1.f : 0.78f)*a);
				wdl->AddText(ImVec2(htx0 + 10.f, hty0 + (tab_h3 - hts.y) * 0.5f),
					htab_col, hex_label);
				(void)hty1;


				float hcx0 = htx1 - hex_close_sz - 6.f;
				float hcy0 = hty0 + (tab_h3 - hex_close_sz) * 0.5f;
				float hcx1 = hcx0 + hex_close_sz;
				float hcy1 = hcy0 + hex_close_sz;
				bool hclose_hov = hex_mouse_in_strip &&
					ImGui::IsMouseHoveringRect(ImVec2(hcx0 - 2, hcy0 - 2), ImVec2(hcx1 + 2, hcy1 + 2), false);
				if (hclose_hov) {
					wdl->AddRectFilled(ImVec2(hcx0 - 1, hcy0 - 1), ImVec2(hcx1 + 1, hcy1 + 1),
						aida::ui::with_alpha(th_lp.error, 0.16f*a), 3.f);
				}
				ImU32 hclose_col = hclose_hov
					? aida::ui::with_alpha(th_lp.error, 0.86f*a)
					: aida::ui::with_alpha(th_lp.text_dim, (hex_is_active ? 0.78f : 0.45f)*a);
				float hcmx = (hcx0 + hcx1) * 0.5f, hcmy = (hcy0 + hcy1) * 0.5f;
				float hcr = 3.f;
				wdl->AddLine(ImVec2(hcmx - hcr, hcmy - hcr), ImVec2(hcmx + hcr, hcmy + hcr), hclose_col, 1.2f);
				wdl->AddLine(ImVec2(hcmx + hcr, hcmy - hcr), ImVec2(hcmx - hcr, hcmy + hcr), hclose_col, 1.2f);

				if (hclose_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					hex_view::close(active_workspace_context);
					if (globals::ui::active_center_view == center_view_t::hex_view)
						globals::ui::active_center_view = center_view_t::code_editor;
				} else if (htab_hov && !hclose_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					globals::ui::active_center_view = center_view_t::hex_view;
				}
			}
		}

		wdl->PopClipRect();

		const bool strip_has_any_entry = !strip_entries.empty();

		if (!strip_has_any_entry) {
			const char* fn_disp = "No file open";
			ImVec2 fn_ts = ImGui::CalcTextSize(fn_disp);
			float  fn_y  = r2_cy - fn_ts.y * 0.5f;
			wdl->AddText(ImVec2(strip_tabs_x0, fn_y),
				aida::ui::with_alpha(th_lp.text_secondary, a), fn_disp);
		}

		bool strip_show_nav = strip_has_overflow || strip_has_any_entry;

		auto strip_draw_chevron = [&](float cx, float cy, bool point_right, ImU32 col) {
			float w = 4.f, h = 6.f;
			if (point_right) {
				wdl->AddLine(ImVec2(cx - w * 0.5f, cy - h * 0.5f),
					ImVec2(cx + w * 0.5f, cy), col, 1.4f);
				wdl->AddLine(ImVec2(cx + w * 0.5f, cy),
					ImVec2(cx - w * 0.5f, cy + h * 0.5f), col, 1.4f);
			} else {
				wdl->AddLine(ImVec2(cx + w * 0.5f, cy - h * 0.5f),
					ImVec2(cx - w * 0.5f, cy), col, 1.4f);
				wdl->AddLine(ImVec2(cx - w * 0.5f, cy),
					ImVec2(cx + w * 0.5f, cy + h * 0.5f), col, 1.4f);
			}
		};

		g_render_section = "title_strip_nav";
		if (strip_show_nav) {
			float chev_y0 = strip_tab_y0 + 2.f;
			float chev_y1 = strip_tab_y1 - 2.f;
			float chev_cy = (chev_y0 + chev_y1) * 0.5f;

			bool strip_mouse_in_chrome = !ui_input_gate::popup_blocks_background_input() &&
				ImGui::IsMouseHoveringRect(
					ImVec2(strip_lchev_x0, strip_tab_y0 - 6.f),
					ImVec2(strip_drop_x1, strip_tab_y1 + 6.f), false);

			bool lchev_enabled = (strip_scroll_target > 0.5f);
			bool lchev_hov = strip_mouse_in_chrome && lchev_enabled &&
				ImGui::IsMouseHoveringRect(
					ImVec2(strip_lchev_x0, chev_y0),
					ImVec2(strip_lchev_x1, chev_y1), false);
			ImU32 lchev_col = lchev_enabled
				? aida::ui::with_alpha(th_lp.text_secondary, (lchev_hov ? 1.f : 0.78f) * a)
				: aida::ui::with_alpha(th_lp.text_dim, 0.45f * a);
			if (lchev_hov) {
				wdl->AddRectFilled(
					ImVec2(strip_lchev_x0, chev_y0),
					ImVec2(strip_lchev_x1, chev_y1),
					aida::ui::with_alpha(th_lp.hover_wash, 0.55f*a), 3.f);
			}
			strip_draw_chevron(
				(strip_lchev_x0 + strip_lchev_x1) * 0.5f, chev_cy, false, lchev_col);
			if (lchev_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				float step = std::max(80.f, strip_visible_w * 0.5f);
				strip_scroll_target -= step;
				if (strip_scroll_target < 0.f) strip_scroll_target = 0.f;
			}

			wdl->AddLine(
				ImVec2(strip_div1_x + 0.5f, strip_tab_y0 + 4.f),
				ImVec2(strip_div1_x + 0.5f, strip_tab_y1 - 4.f),
				aida::ui::with_alpha(th_lp.border_subtle, a), 1.f);

			wdl->AddLine(
				ImVec2(strip_div2_x + strip_div_w * 0.5f, strip_tab_y0 + 4.f),
				ImVec2(strip_div2_x + strip_div_w * 0.5f, strip_tab_y1 - 4.f),
				aida::ui::with_alpha(th_lp.border_subtle, a), 1.f);

			bool rchev_enabled = (strip_scroll_target < strip_max_scroll - 0.5f);
			bool rchev_hov = strip_mouse_in_chrome && rchev_enabled &&
				ImGui::IsMouseHoveringRect(
					ImVec2(strip_rchev_x0, chev_y0),
					ImVec2(strip_rchev_x1, chev_y1), false);
			ImU32 rchev_col = rchev_enabled
				? aida::ui::with_alpha(th_lp.text_secondary, (rchev_hov ? 1.f : 0.78f) * a)
				: aida::ui::with_alpha(th_lp.text_dim, 0.45f * a);
			if (rchev_hov) {
				wdl->AddRectFilled(
					ImVec2(strip_rchev_x0, chev_y0),
					ImVec2(strip_rchev_x1, chev_y1),
					aida::ui::with_alpha(th_lp.hover_wash, 0.55f*a), 3.f);
			}
			strip_draw_chevron(
				(strip_rchev_x0 + strip_rchev_x1) * 0.5f, chev_cy, true, rchev_col);
			if (rchev_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				float step = std::max(80.f, strip_visible_w * 0.5f);
				strip_scroll_target += step;
				if (strip_scroll_target > strip_max_scroll)
					strip_scroll_target = strip_max_scroll;
			}

			wdl->AddLine(
				ImVec2(strip_div3_x + strip_div_w * 0.5f, strip_tab_y0 + 4.f),
				ImVec2(strip_div3_x + strip_div_w * 0.5f, strip_tab_y1 - 4.f),
				aida::ui::with_alpha(th_lp.border_subtle, a), 1.f);

			bool drop_hov = strip_mouse_in_chrome &&
				ImGui::IsMouseHoveringRect(
					ImVec2(strip_drop_x0, chev_y0),
					ImVec2(strip_drop_x1, chev_y1), false);
			ImU32 drop_col = aida::ui::with_alpha(th_lp.text_secondary, (drop_hov ? 1.f : 0.78f) * a);
			if (drop_hov) {
				wdl->AddRectFilled(
					ImVec2(strip_drop_x0, chev_y0),
					ImVec2(strip_drop_x1, chev_y1),
					aida::ui::with_alpha(th_lp.hover_wash, 0.55f*a), 3.f);
			}
			float drop_cx = (strip_drop_x0 + strip_drop_x1) * 0.5f;
			float drop_cy = chev_cy;
			float drop_w_icon = 10.f;
			for (int li = 0; li < 3; ++li) {
				float ly = drop_cy - 3.f + static_cast<float>(li) * 3.f;
				wdl->AddLine(
					ImVec2(drop_cx - drop_w_icon * 0.5f, ly),
					ImVec2(drop_cx + drop_w_icon * 0.5f, ly),
					drop_col, 1.2f);
			}
			if (drop_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				ImGui::OpenPopup("##tab_strip_dropdown");
			}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			static std::uint64_t preview_tab_dropdown_revision = 0;
			if (aida::preview::controls().tab_dropdown_open && preview_tab_dropdown_revision != aida::preview::controls().revision) {
				preview_tab_dropdown_revision = aida::preview::controls().revision;
				ImGui::OpenPopup("##tab_strip_dropdown");
			}
#endif

			g_render_section = "title_strip_dropdown_popup";
			ImGui::SetNextWindowPos(ImVec2(strip_drop_x1 - 280.f, strip_tab_y1 + 4.f),
				ImGuiCond_Always);
			if (ImGui::BeginPopup("##tab_strip_dropdown",
				ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
				ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize)) {

				float pop_w = 280.f;
				float row_h_pop = 26.f;
				ImVec2 pwp = ImGui::GetWindowPos();
				ImDrawList* pdl = ImGui::GetWindowDrawList();
				const auto& th_pp = aida::ui::resolved();

				ImGui::TextUnformatted("Open Tabs");
				ImGui::Dummy(ImVec2(pop_w, 1.f));
				pdl->AddLine(
					ImVec2(pwp.x + 6.f, ImGui::GetCursorScreenPos().y),
					ImVec2(pwp.x + pop_w - 6.f, ImGui::GetCursorScreenPos().y),
					th_pp.border_strong, 1.f);
				ImGui::Dummy(ImVec2(pop_w, 2.f));

				int chosen_kind = -1;
				int chosen_idx = -1;
				uint64_t chosen_addr = 0;

				for (std::size_t ei = 0; ei < strip_entries.size(); ++ei) {
					auto& e = strip_entries[ei];
					ImVec2 cp = ImGui::GetCursorScreenPos();
					ImVec2 rmin(cp.x, cp.y);
					ImVec2 rmax(cp.x + pop_w, cp.y + row_h_pop);
					bool rhov = ImGui::IsMouseHoveringRect(rmin, rmax, false);
					if (e.is_active) {
						pdl->AddRectFilled(rmin, rmax,
							aida::ui::with_alpha(th_pp.selection, 0.86f), 6.f);
					} else if (rhov) {
						pdl->AddRectFilled(rmin, rmax,
							aida::ui::with_alpha(th_pp.hover_wash, 1.f), 6.f);
					}
					const char* kind_tag = "";
					ImU32 kind_col = th_lp.text_dim;
					switch (e.kind) {
						case 0: kind_tag = "TXT"; kind_col = th_lp.text_secondary; break;
						case 1: kind_tag = "ASM"; kind_col = th_lp.syn_number; break;
						case 2: kind_tag = "C  "; kind_col = th_lp.syn_function; break;
						case 3: kind_tag = "HEX"; kind_col = th_lp.syn_keyword; break;
					}
					pdl->AddText(ImVec2(cp.x + 10.f, cp.y + (row_h_pop - ImGui::GetFontSize()) * 0.5f),
						kind_col, kind_tag);
					ImU32 label_col = e.is_active
						? th_pp.accent_u32
						: th_lp.text_primary;
					if (e.error) label_col = th_lp.error;
					pdl->AddText(ImVec2(cp.x + 50.f, cp.y + (row_h_pop - ImGui::GetFontSize()) * 0.5f),
						label_col, e.label.c_str());
					if (e.dirty) {
						pdl->AddCircleFilled(
							ImVec2(cp.x + pop_w - 14.f, cp.y + row_h_pop * 0.5f), 3.f,
							th_lp.warning);
					}
					ImGui::Dummy(ImVec2(pop_w, row_h_pop));
					if (rhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						chosen_kind = e.kind;
						chosen_idx = e.idx;
						chosen_addr = e.addr;
					}
				}

				if (chosen_kind >= 0) {
					if (chosen_kind == 0 && chosen_idx >= 0 && chosen_idx < (int)file_tabs::tabs.size()) {
						file_tabs::switch_to(chosen_idx);
						globals::ui::active_center_view = center_view_t::code_editor;
					} else if (chosen_kind == 1) {
						globals::ui::active_center_view = center_view_t::disassembly;
					} else if (chosen_kind == 2 && chosen_addr != 0) {
						pseudocode_view::activate_tab_by_addr(active_workspace_context, chosen_addr);
						globals::ui::active_center_view = center_view_t::pseudocode;
					} else if (chosen_kind == 3) {
						globals::ui::active_center_view = center_view_t::hex_view;
					}
					ImGui::CloseCurrentPopup();
				}

				ImGui::EndPopup();
			}
		}

		strip_st->SetFloat(strip_id_scroll, strip_scroll);
		strip_st->SetFloat(strip_id_scroll_target, strip_scroll_target);


		g_render_section = "title_hub_nav";
		float hub_active_x0 = 0.f;
		float hub_active_x1 = 0.f;
		float hub_active_y1 = 0.f;
		bool  hub_has_active = false;
		float hub_hover_x0 = 0.f;
		float hub_hover_x1 = 0.f;
		float hub_hover_y1 = 0.f;
		bool  hub_has_hover = false;
		struct shell_hub_overflow_t {
			const char* label;
			center_view_t view;
			bool active;
		};
		std::vector<shell_hub_overflow_t> hub_overflow;
		auto shell_hub_log_click = [&](const char* source, const char* label, center_view_t view, bool blocked, ImVec2 rmin, ImVec2 rmax) {
			diag::log_tagged_fmt("ui",
				"shell_nav_click source=%s label='%s' target=%s blocked=%d rect=%.1f,%.1f,%.1f,%.1f before=%s",
				source,
				label,
				center_view_name(view),
				blocked ? 1 : 0,
				rmin.x,
				rmin.y,
				rmax.x,
				rmax.y,
				center_view_name(globals::ui::active_center_view));
		};
		auto shell_hub_switch = [&](const char* source, const char* label, center_view_t view, bool blocked, ImVec2 rmin, ImVec2 rmax) {
			shell_hub_log_click(source, label, view, blocked, rmin, rmax);
			if (!blocked)
				globals::ui::active_center_view = view;
		};
		const float hub_left_limit = hx0 + hdr_pad + aida::ui::scale_px(72.f, metrics.scale);

		{
			g_render_section = "title_hub_network";
			bool net_is_active = (globals::ui::active_center_view == center_view_t::network_view);
			const char* net_label = "Network";
			ImVec2 nts = ImGui::CalcTextSize(net_label);
			float ntw = 10.f * 2.f + nts.x;
			float ntx0 = rbtn_x0 - ntw - 8.f;
			float ntx1 = ntx0 + ntw;
			float tab_h4 = row_h - 2.f;
			float nty0 = r1_cy - tab_h4 * 0.5f;
			float nty1 = nty0 + tab_h4;

			if (ntx0 > hub_left_limit) {
				ImVec2 saved_cursor = ImGui::GetCursorScreenPos();
				ImVec2 nmin(ntx0, nty0);
				ImVec2 nmax(ntx1, nty1);
				ImGui::SetCursorScreenPos(nmin);
				ImGui::InvisibleButton("##hub_network", ImVec2(ntx1 - ntx0, nty1 - nty0));
				bool ntab_item_hov = ImGui::IsItemHovered();
				bool ntab_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGui::SetCursorScreenPos(saved_cursor);
				bool ntab_blocked = ui_input_gate::popup_blocks_background_input();
				bool ntab_hov = ntab_item_hov && !ntab_blocked;

				if (net_is_active) {
					wdl->AddRectFilled(ImVec2(ntx0, nty0), ImVec2(ntx1, nty1),
						aida::ui::with_alpha(th_lp.selection_strong, 0.88f * a),
						4.f, ImDrawFlags_RoundCornersAll);
					wdl->AddLine(ImVec2(ntx0 + 1.f, nty0 + 0.5f), ImVec2(ntx1 - 1.f, nty0 + 0.5f),
						aida::ui::with_alpha(th_lp.accent_u32, 0.5f * a), 1.f);
					hub_active_x0 = ntx0; hub_active_x1 = ntx1; hub_active_y1 = nty1;
					hub_has_active = true;
				} else if (ntab_hov) {
					wdl->AddRectFilled(ImVec2(ntx0, nty0), ImVec2(ntx1, nty1),
						aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 4.f, ImDrawFlags_RoundCornersTop);
					hub_hover_x0 = ntx0; hub_hover_x1 = ntx1; hub_hover_y1 = nty1;
					hub_has_hover = true;
				}

				ImU32 ntab_col = net_is_active ? ac_full
				               : aida::ui::with_alpha(th_lp.text_secondary, (ntab_hov ? 1.f : 0.78f)*a);
				wdl->AddText(ImVec2(ntx0 + 10.f, nty0 + (tab_h4 - nts.y) * 0.5f),
					ntab_col, net_label);

				if (ntab_clicked)
					shell_hub_switch("hub_tab", net_label, center_view_t::network_view, ntab_blocked, nmin, nmax);
			} else {
				hub_overflow.push_back({ net_label, center_view_t::network_view, net_is_active });
			}
		}


		{
			g_render_section = "title_hub_scan";
			auto scv = globals::ui::active_center_view;
			bool scan_is_active = (scv == center_view_t::scan_hub
				|| scv == center_view_t::memory_scanner
				|| scv == center_view_t::crypto_scanner
				|| scv == center_view_t::aob_generator
				|| scv == center_view_t::xref_browser
				|| scv == center_view_t::snapshot_diff
				|| scv == center_view_t::pointer_scanner
				|| scv == center_view_t::decrypt_oracle
				|| scv == center_view_t::integrity_hunter);
			const char* scan_label = "Scan";
			ImVec2 sts = ImGui::CalcTextSize(scan_label);
			float stw = 10.f * 2.f + sts.x;

			float net_tab_w = 10.f * 2.f + ImGui::CalcTextSize("Network").x;
			float net_tab_x0 = rbtn_x0 - net_tab_w - 8.f;
			float tab_h_s = row_h - 2.f;
			float stx0 = net_tab_x0 - stw - 6.f;
			float stx1 = stx0 + stw;
			float sty0 = r1_cy - tab_h_s * 0.5f;
			float sty1 = sty0 + tab_h_s;

			if (stx0 > hub_left_limit) {
				ImVec2 saved_cursor = ImGui::GetCursorScreenPos();
				ImVec2 smin(stx0, sty0);
				ImVec2 smax(stx1, sty1);
				ImGui::SetCursorScreenPos(smin);
				ImGui::InvisibleButton("##hub_scan", ImVec2(stx1 - stx0, sty1 - sty0));
				bool stab_item_hov = ImGui::IsItemHovered();
				bool stab_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGui::SetCursorScreenPos(saved_cursor);
				bool stab_blocked = ui_input_gate::popup_blocks_background_input();
				bool stab_hov = stab_item_hov && !stab_blocked;

				if (scan_is_active) {
					wdl->AddRectFilled(ImVec2(stx0, sty0), ImVec2(stx1, sty1),
						aida::ui::with_alpha(th_lp.selection_strong, 0.88f * a),
						4.f, ImDrawFlags_RoundCornersAll);
					wdl->AddLine(ImVec2(stx0 + 1.f, sty0 + 0.5f), ImVec2(stx1 - 1.f, sty0 + 0.5f),
						aida::ui::with_alpha(th_lp.accent_u32, 0.5f * a), 1.f);
					hub_active_x0 = stx0; hub_active_x1 = stx1; hub_active_y1 = sty1;
					hub_has_active = true;
				} else if (stab_hov) {
					wdl->AddRectFilled(ImVec2(stx0, sty0), ImVec2(stx1, sty1),
						aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 4.f, ImDrawFlags_RoundCornersTop);
					hub_hover_x0 = stx0; hub_hover_x1 = stx1; hub_hover_y1 = sty1;
					hub_has_hover = true;
				}

				ImU32 stab_col = scan_is_active ? ac_full
				               : aida::ui::with_alpha(th_lp.text_secondary, (stab_hov ? 1.f : 0.78f)*a);
				wdl->AddText(ImVec2(stx0 + 10.f, sty0 + (tab_h_s - sts.y) * 0.5f),
					stab_col, scan_label);

				if (stab_clicked)
					shell_hub_switch("hub_tab", scan_label, center_view_t::scan_hub, stab_blocked, smin, smax);
			} else {
				hub_overflow.push_back({ scan_label, center_view_t::scan_hub, scan_is_active });
			}
		}


		float dtx0 = 0.f;
		{
			bool dbg_is_active = (globals::ui::active_center_view == center_view_t::debugger_view);
			const char* dbg_label = "Debugger";
			ImVec2 dts = ImGui::CalcTextSize(dbg_label);
			float dtw = 10.f * 2.f + dts.x;

			float net_tw = 10.f * 2.f + ImGui::CalcTextSize("Network").x;
			float net_x0 = rbtn_x0 - net_tw - 8.f;
			float scan_tw = 10.f * 2.f + ImGui::CalcTextSize("Scan").x;
			float scan_x0 = net_x0 - scan_tw - 6.f;
			float tab_h_d = row_h - 2.f;
			dtx0 = scan_x0 - dtw - 6.f;
			float dtx1 = dtx0 + dtw;
			float dty0 = r1_cy - tab_h_d * 0.5f;
			float dty1 = dty0 + tab_h_d;

			if (dtx0 > hub_left_limit) {
				ImVec2 saved_cursor = ImGui::GetCursorScreenPos();
				ImVec2 dmin(dtx0, dty0);
				ImVec2 dmax(dtx1, dty1);
				ImGui::SetCursorScreenPos(dmin);
				ImGui::InvisibleButton("##hub_debugger", ImVec2(dtx1 - dtx0, dty1 - dty0));
				bool dtab_item_hov = ImGui::IsItemHovered();
				bool dtab_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGui::SetCursorScreenPos(saved_cursor);
				bool dtab_blocked = ui_input_gate::popup_blocks_background_input();
				bool dtab_hov = dtab_item_hov && !dtab_blocked;

				if (dbg_is_active) {
					wdl->AddRectFilled(ImVec2(dtx0, dty0), ImVec2(dtx1, dty1),
						aida::ui::with_alpha(th_lp.selection_strong, 0.88f * a),
						4.f, ImDrawFlags_RoundCornersAll);
					wdl->AddLine(ImVec2(dtx0 + 1.f, dty0 + 0.5f), ImVec2(dtx1 - 1.f, dty0 + 0.5f),
						aida::ui::with_alpha(th_lp.accent_u32, 0.5f * a), 1.f);
					hub_active_x0 = dtx0; hub_active_x1 = dtx1; hub_active_y1 = dty1;
					hub_has_active = true;
				} else if (dtab_hov) {
					wdl->AddRectFilled(ImVec2(dtx0, dty0), ImVec2(dtx1, dty1),
						aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 4.f, ImDrawFlags_RoundCornersTop);
					hub_hover_x0 = dtx0; hub_hover_x1 = dtx1; hub_hover_y1 = dty1;
					hub_has_hover = true;
				}

				ImU32 dtab_col = dbg_is_active ? ac_full
				               : aida::ui::with_alpha(th_lp.text_secondary, (dtab_hov ? 1.f : 0.78f)*a);
				wdl->AddText(ImVec2(dtx0 + 10.f, dty0 + (tab_h_d - dts.y) * 0.5f),
					dtab_col, dbg_label);

				if (dtab_clicked)
					shell_hub_switch("hub_tab", dbg_label, center_view_t::debugger_view, dtab_blocked, dmin, dmax);
			} else {
				hub_overflow.push_back({ dbg_label, center_view_t::debugger_view, dbg_is_active });
			}
		}


		{
			auto acv = globals::ui::active_center_view;

			auto is_hub_active = [&](center_view_t hub) -> bool {
				if (acv == hub) return true;
				if (hub == center_view_t::types_hub)
					return acv == center_view_t::struct_recon;
				if (hub == center_view_t::analysis_hub)
					return acv == center_view_t::symbolic_view
						|| acv == center_view_t::taint_view
						|| acv == center_view_t::deobfuscation_view
						|| acv == center_view_t::stealth_view
						|| acv == center_view_t::fuzzer_view;
				return false;
			};

			auto add_right_tab = [&](const char* label, center_view_t view_id, float anchor_x0) {
				bool is_active = (acv == view_id) || is_hub_active(view_id);
				ImVec2 lsz = ImGui::CalcTextSize(label);
				float tw = 10.f * 2.f + lsz.x;
				float tx0 = anchor_x0 - tw - 4.f;
				float tx1 = tx0 + tw;
				float th = row_h - 2.f;
				float ty0 = r1_cy - th * 0.5f;
				float ty1 = ty0 + th;
				if (tx0 > hub_left_limit) {
					ImVec2 saved_cursor = ImGui::GetCursorScreenPos();
					ImVec2 tmin(tx0, ty0);
					ImVec2 tmax(tx1, ty1);
					ImGui::SetCursorScreenPos(tmin);
					ImGui::PushID(label);
					ImGui::InvisibleButton("##hub_extra", ImVec2(tx1 - tx0, ty1 - ty0));
					bool item_hov = ImGui::IsItemHovered();
					bool item_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
					ImGui::PopID();
					ImGui::SetCursorScreenPos(saved_cursor);
					bool blocked = ui_input_gate::popup_blocks_background_input();
					bool hov = item_hov && !blocked;
					if (is_active) {
						wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
							aida::ui::with_alpha(th_lp.selection_strong, 0.88f * a),
							4.f, ImDrawFlags_RoundCornersAll);
						wdl->AddLine(ImVec2(tx0 + 1.f, ty0 + 0.5f), ImVec2(tx1 - 1.f, ty0 + 0.5f),
							aida::ui::with_alpha(th_lp.accent_u32, 0.5f * a), 1.f);
						hub_active_x0 = tx0; hub_active_x1 = tx1; hub_active_y1 = ty1;
						hub_has_active = true;
					} else if (hov) {
						wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
							aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 4.f, ImDrawFlags_RoundCornersTop);
						hub_hover_x0 = tx0; hub_hover_x1 = tx1; hub_hover_y1 = ty1;
						hub_has_hover = true;
					}
					ImU32 tc = is_active ? ac_full : aida::ui::with_alpha(th_lp.text_secondary, (hov ? 1.f : 0.78f)*a);
					wdl->AddText(ImVec2(tx0 + 10.f, ty0 + (th - lsz.y) * 0.5f), tc, label);
					if (item_clicked)
						shell_hub_switch("hub_tab", label, view_id, blocked, tmin, tmax);
				} else {
					hub_overflow.push_back({ label, view_id, is_active });
				}
				return tx0;
			};

			float anchor = dtx0;
			anchor = add_right_tab("Types",      center_view_t::types_hub, anchor);
			anchor = add_right_tab("Analysis",   center_view_t::analysis_hub, anchor);
			anchor = add_right_tab("Binary Map", center_view_t::binary_map, anchor);
		}

		if (!hub_overflow.empty()) {
			const char* more_label = "More";
			ImVec2 mts = ImGui::CalcTextSize(more_label);
			float mtw = aida::ui::scale_px(20.f, metrics.scale) + mts.x;
			float mth = row_h - 2.f;
			float mtx0 = hx0 + hdr_pad + aida::ui::scale_px(4.f, metrics.scale);
			float mty0 = r1_cy - mth * 0.5f;
			float mtx1 = mtx0 + mtw;
			float mty1 = mty0 + mth;
			ImVec2 saved_cursor = ImGui::GetCursorScreenPos();
			ImGui::SetCursorScreenPos(ImVec2(mtx0, mty0));
			ImGui::InvisibleButton("##hub_more", ImVec2(mtw, mth));
			bool more_hov = ImGui::IsItemHovered();
			bool more_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::SetCursorScreenPos(saved_cursor);
			if (more_hov) {
				wdl->AddRectFilled(ImVec2(mtx0, mty0), ImVec2(mtx1, mty1),
					aida::ui::with_alpha(th_lp.hover_wash, 0.55f*a), 4.f, ImDrawFlags_RoundCornersAll);
			}
			wdl->AddText(ImVec2(mtx0 + aida::ui::scale_px(10.f, metrics.scale), mty0 + (mth - mts.y) * 0.5f),
				aida::ui::with_alpha(th_lp.text_secondary, (more_hov ? 1.f : 0.78f)*a), more_label);
			if (more_clicked) {
				shell_hub_log_click("hub_overflow_button", more_label, globals::ui::active_center_view, false,
					ImVec2(mtx0, mty0), ImVec2(mtx1, mty1));
				ImGui::OpenPopup("##hub_overflow_popup");
			}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			static std::uint64_t preview_hub_overflow_revision = 0;
			if (aida::preview::controls().hub_overflow_open && preview_hub_overflow_revision != aida::preview::controls().revision) {
				preview_hub_overflow_revision = aida::preview::controls().revision;
				ImGui::OpenPopup("##hub_overflow_popup");
			}
#endif
			ImGui::SetNextWindowPos(ImVec2(mtx0, mty1 + aida::ui::scale_px(4.f, metrics.scale)), ImGuiCond_Always);
			if (ImGui::BeginPopup("##hub_overflow_popup",
				ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
				ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize)) {
				const float pop_w = aida::ui::scale_px(190.f, metrics.scale);
				const float pop_row_h = (std::max)(aida::ui::scale_px(30.f, metrics.scale), ImGui::GetTextLineHeight() + aida::ui::scale_px(10.f, metrics.scale));
				ImDrawList* pdl = ImGui::GetWindowDrawList();
				const auto& th_pp = aida::ui::resolved();
				for (size_t oi = 0; oi < hub_overflow.size(); ++oi) {
					const auto& entry = hub_overflow[oi];
					ImVec2 cp = ImGui::GetCursorScreenPos();
					ImVec2 rmin(cp.x, cp.y);
					ImVec2 rmax(cp.x + pop_w, cp.y + pop_row_h);
					ImGui::PushID(static_cast<int>(oi));
					ImGui::InvisibleButton("##hub_overflow_item", ImVec2(pop_w, pop_row_h));
					bool rhov = ImGui::IsItemHovered();
					bool rclicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
					ImGui::PopID();
					if (entry.active) {
						pdl->AddRectFilled(rmin, rmax,
							aida::ui::with_alpha(th_pp.selection, 0.86f), 6.f);
					} else if (rhov) {
						pdl->AddRectFilled(rmin, rmax,
							aida::ui::with_alpha(th_pp.hover_wash, 1.f), 6.f);
					}
					ImU32 row_col = entry.active ? ac_full : th_pp.text_primary;
					pdl->PushClipRect(rmin, rmax, true);
					pdl->AddText(ImVec2(rmin.x + aida::ui::scale_px(10.f, metrics.scale),
						rmin.y + (pop_row_h - ImGui::GetTextLineHeight()) * 0.5f),
						row_col, entry.label);
					pdl->PopClipRect();
					if (rclicked) {
						shell_hub_switch("hub_overflow", entry.label, entry.view, false, rmin, rmax);
						ImGui::CloseCurrentPopup();
					}
				}
				ImGui::EndPopup();
			}
		}

		{
			ImGuiStorage* hub_st = ImGui::GetStateStorage();
			ImGuiID hub_id_x   = ImGui::GetID("##hub_ul_x");
			ImGuiID hub_id_w   = ImGui::GetID("##hub_ul_w");
			ImGuiID hub_id_v   = ImGui::GetID("##hub_ul_v");
			ImGuiID hub_id_y   = ImGui::GetID("##hub_ul_y");
			ImGuiID hub_id_a   = ImGui::GetID("##hub_ul_a");
			ImGuiID hub_id_init= ImGui::GetID("##hub_ul_init");

			float hub_ul_x = hub_st->GetFloat(hub_id_x, 0.f);
			float hub_ul_w = hub_st->GetFloat(hub_id_w, 0.f);
			float hub_ul_v = hub_st->GetFloat(hub_id_v, 0.f);
			float hub_ul_y = hub_st->GetFloat(hub_id_y, 0.f);
			float hub_ul_a = hub_st->GetFloat(hub_id_a, 0.f);
			bool  hub_init = hub_st->GetInt(hub_id_init, 0) != 0;

			float target_x = hub_ul_x;
			float target_w = hub_ul_w;
			float target_y = hub_ul_y;
			float target_a = 0.f;
			if (hub_has_active) {
				target_x = hub_active_x0 + 4.f;
				target_w = (hub_active_x1 - hub_active_x0) - 8.f;
				target_y = hub_active_y1;
				target_a = 1.f;
			}

			if (!hub_init && hub_has_active) {
				hub_ul_x = target_x;
				hub_ul_w = target_w;
				hub_ul_y = target_y;
				hub_ul_a = target_a;
				hub_init = true;
			}

			if (hub_has_active) {
				hub_ul_x = aida::motion::spring_step(hub_ul_x, target_x, hub_ul_v,
					aida::motion::spring::balanced, dt);
				hub_ul_w = aida::motion::smooth_lerp(hub_ul_w, target_w, 16.f, dt);
				hub_ul_y = aida::motion::smooth_lerp(hub_ul_y, target_y, 18.f, dt);
				hub_ul_a = aida::motion::smooth_lerp(hub_ul_a, target_a, 12.f, dt);
			} else {
				hub_ul_a = aida::motion::smooth_lerp(hub_ul_a, 0.f, 10.f, dt);
			}

			hub_st->SetFloat(hub_id_x, hub_ul_x);
			hub_st->SetFloat(hub_id_w, hub_ul_w);
			hub_st->SetFloat(hub_id_v, hub_ul_v);
			hub_st->SetFloat(hub_id_y, hub_ul_y);
			hub_st->SetFloat(hub_id_a, hub_ul_a);
			hub_st->SetInt(hub_id_init, hub_init ? 1 : 0);

			if (hub_ul_w > 0.5f && hub_ul_a > 0.005f) {
				ui_anim::render_tab_underline_glow(wdl, hub_ul_x, hub_ul_w,
					hub_ul_y - 1.f, a * hub_ul_a);
			}

			ImGuiID hub_id_hx = ImGui::GetID("##hub_uh_x");
			ImGuiID hub_id_hw = ImGui::GetID("##hub_uh_w");
			ImGuiID hub_id_hy = ImGui::GetID("##hub_uh_y");
			ImGuiID hub_id_ha = ImGui::GetID("##hub_uh_a");

			bool show_hover_preview = hub_has_hover
				&& (!hub_has_active
					|| std::abs(hub_hover_x0 - hub_active_x0) > 0.5f);

			if (show_hover_preview) {
				const auto& th_hub2 = aida::ui::resolved();
				float hub_uh_x = hub_st->GetFloat(hub_id_hx, hub_hover_x0 + 4.f);
				float hub_uh_w = hub_st->GetFloat(hub_id_hw, (hub_hover_x1 - hub_hover_x0) - 8.f);
				float hub_uh_y = hub_st->GetFloat(hub_id_hy, hub_hover_y1);
				float hub_uh_a = hub_st->GetFloat(hub_id_ha, 0.f);

				float th_x = hub_hover_x0 + 4.f;
				float th_w = (hub_hover_x1 - hub_hover_x0) - 8.f;
				float th_y = hub_hover_y1;

				hub_uh_x = aida::motion::smooth_lerp(hub_uh_x, th_x, 22.f, dt);
				hub_uh_w = aida::motion::smooth_lerp(hub_uh_w, th_w, 22.f, dt);
				hub_uh_y = aida::motion::smooth_lerp(hub_uh_y, th_y, 22.f, dt);
				hub_uh_a = aida::motion::smooth_lerp(hub_uh_a, 1.f, 14.f, dt);

				hub_st->SetFloat(hub_id_hx, hub_uh_x);
				hub_st->SetFloat(hub_id_hw, hub_uh_w);
				hub_st->SetFloat(hub_id_hy, hub_uh_y);
				hub_st->SetFloat(hub_id_ha, hub_uh_a);

				if (hub_uh_w > 0.5f && hub_uh_a > 0.01f) {
					ImU32 hov_col = aida::ui::with_alpha(th_hub2.accent_u32, a * hub_uh_a * 0.45f);
					wdl->AddLine(
						ImVec2(hub_uh_x, hub_uh_y),
						ImVec2(hub_uh_x + hub_uh_w, hub_uh_y),
						hov_col, 1.5f);
				}
			} else {
				float hub_uh_a = hub_st->GetFloat(hub_id_ha, 0.f);
				hub_uh_a = aida::motion::smooth_lerp(hub_uh_a, 0.f, 14.f, dt);
				hub_st->SetFloat(hub_id_ha, hub_uh_a);
			}
		}

		bool cf_clicked = ghost_btn("Choose File",
			ImGui::GetID("##cfhv"), ImGui::GetID("##cffl"),
			rbtn_x0, r1_cy, rbtn_w);

		if (cf_clicked) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::apply_open_file();
#else
			anti_tamper::webhook::write_log("file_dialog", "chrome.choose_file_clicked invoking_open_file_dialog");
			std::string fpath = disasm::open_file_dialog(g_hwnd);
			if (fpath.empty()) {
				anti_tamper::webhook::write_log("file_dialog", "chrome.choose_file cancelled_or_empty");
				anti_tamper::webhook::write_log("chrome", "choose_file cancelled");
			} else {
				anti_tamper::webhook::write_log("file_dialog",
					(std::string("chrome.choose_file path=") + fpath).c_str());
				std::string fpath_copy = fpath;
				const bool posted = aida::ui_thread::post([fpath_copy]() {
					if (!aida::ui_thread::require_owner("analysis_session", "open_session", "choose_file"))
						return;
					bool ok = analysis_session::open_session(fpath_copy);
					if (ok) {
						char buf[600];
						_snprintf_s(buf, sizeof(buf), _TRUNCATE,
							"choose_file ok path=%s", fpath_copy.c_str());
						anti_tamper::webhook::write_log("chrome", buf);
					} else {
						const char* err = analysis_session::last_error();
						char buf[700];
						_snprintf_s(buf, sizeof(buf), _TRUNCATE,
							"choose_file failed path=%s err=%s",
							fpath_copy.c_str(), err ? err : "(none)");
						anti_tamper::webhook::write_log("chrome", buf);
					}
				}, "analysis_session", "open_session", "choose_file");
				if (!posted) {
					diag::log_tagged_critical_fmt("analysis_session",
						"choose_file_dispatch_failed tid=%lu ui_tid=%lu path=%.260s",
						static_cast<unsigned long>(aida::shell_platform::thread_id()),
						static_cast<unsigned long>(aida::ui_thread::owner_tid()),
						fpath_copy.c_str());
				}
			}
#endif
		}


		if (file_tabs::active_tab >= 0 &&
			static_cast<std::size_t>(file_tabs::active_tab) < file_tabs::tabs.size()) {
			auto& sync_tab = file_tabs::tabs[static_cast<std::size_t>(file_tabs::active_tab)];
			if (code_editor::active && sync_tab.filepath == code_editor::filepath)
				sync_tab.dirty = code_editor::dirty;
		}
	}


	{

		if (active_workspace_context) {
			bool is_hex_view = (globals::ui::active_center_view == center_view_t::hex_view);
			const char* vt_label = is_hex_view ? "View Disassembly" : "View Hex";
			float vtbtn_w = ImGui::CalcTextSize(vt_label).x + 22.f;
			float vtbtn_x = rbtn_x0 - vtbtn_w - 8.f;

			bool vt_clicked = ghost_btn(vt_label,
				ImGui::GetID("##vthv2"), ImGui::GetID("##vtfl2"),
				vtbtn_x, r2_cy, vtbtn_w);

			if (vt_clicked) {
				if (is_hex_view) {
					globals::ui::active_center_view = center_view_t::disassembly;
				} else {
					globals::ui::active_center_view = center_view_t::hex_view;
				}
			}
		}

		bool run_clicked = ghost_btn("Run",
			ImGui::GetID("##drhv"), ImGui::GetID("##drfl"),
			rbtn_x0, r2_cy, rbtn_w);

		static bool s_run_pick_open = false;
		static bool s_run_confirm_open = false;
		static int  s_run_pick_selected = -1;
		static std::string s_run_confirm_path;
		static std::string s_run_confirm_label;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static std::uint64_t preview_run_revision = 0;
		if (preview_run_revision != aida::preview::controls().revision) {
			preview_run_revision = aida::preview::controls().revision;
			s_run_pick_open = aida::preview::controls().run_picker_open;
			s_run_confirm_open = aida::preview::controls().run_confirmation_open;
			s_run_pick_selected = 0;
			s_run_confirm_path = "C:/Preview/ReverseEngineering/samples/sample.exe";
			s_run_confirm_label = "sample.exe";
		}
#endif

		auto launch_session_path = [](const std::string& path) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::record(aida::preview::shell_action_t::run_target, path);
			std::string cwd_v;
			if (!path.empty()) {
				size_t slash = path.find_last_of("\\/");
				if (slash != std::string::npos) cwd_v = path.substr(0, slash);
			}
			spawn_target_dialog::request_open();
			strncpy_s(spawn_target_dialog::detail::exe_buf(), 1024, path.c_str(), _TRUNCATE);
			if (!cwd_v.empty())
				strncpy_s(spawn_target_dialog::detail::cwd_buf(), 1024, cwd_v.c_str(), _TRUNCATE);
			output_log::push(bottom_tab_t::sandbox_log,
				std::string("[Preview] Opening launch choice dialog for: ") + path);
#else
			std::string cwd_v;
			if (!path.empty()) {
				size_t slash = path.find_last_of("\\/");
				if (slash != std::string::npos) cwd_v = path.substr(0, slash);
			}
			spawn_target_dialog::request_open();
			strncpy_s(spawn_target_dialog::detail::exe_buf(), 1024, path.c_str(), _TRUNCATE);
			if (!cwd_v.empty()) {
				strncpy_s(spawn_target_dialog::detail::cwd_buf(), 1024, cwd_v.c_str(), _TRUNCATE);
			}
			output_log::push(bottom_tab_t::sandbox_log,
				std::string("[Run] Opening launch choice dialog for: ") + path);
#endif
		};

		if (run_clicked) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::record(aida::preview::shell_action_t::run_target, "run_button");
			const size_t sess_count = analysis_session::session_count();
			if (sess_count > 1) {
				s_run_pick_selected = static_cast<int>(analysis_session::active_session_idx());
				if (s_run_pick_selected < 0 || s_run_pick_selected >= static_cast<int>(sess_count))
					s_run_pick_selected = 0;
				s_run_pick_open = true;
			} else if (sess_count == 1) {
				const auto sess = analysis_session::session_handle_at(0);
				if (sess && !sess->path.empty())
					launch_session_path(sess->path);
				else
					spawn_target_dialog::request_open();
			} else {
				spawn_target_dialog::request_open();
			}
#else
			size_t sess_count = analysis_session::session_count();
			uint32_t attached = driver_bridge::attached_pid();
			char log_buf[256];

			if (attached != 0) {
				_snprintf_s(log_buf, sizeof(log_buf), _TRUNCATE,
					"run skipped reason=already_running attached_pid=%u sessions=%zu",
					static_cast<unsigned>(attached), sess_count);
				anti_tamper::webhook::write_log("chrome", log_buf);
				output_log::push(bottom_tab_t::sandbox_log,
					std::string("[Run] Skipped: a process is already attached (PID ")
						+ std::to_string(attached) + ").");
			} else if (sess_count > 1) {
				s_run_pick_selected = static_cast<int>(analysis_session::active_session_idx());
				if (s_run_pick_selected < 0 || s_run_pick_selected >= static_cast<int>(sess_count))
					s_run_pick_selected = 0;
				s_run_pick_open = true;
				_snprintf_s(log_buf, sizeof(log_buf), _TRUNCATE,
					"run sessions=%zu choice=picker status=opened",
					sess_count);
				anti_tamper::webhook::write_log("chrome", log_buf);
			} else if (sess_count == 1) {
				const auto sess = analysis_session::session_handle_at(0);
				if (sess && !sess->path.empty()) {
					launch_session_path(sess->path);
					_snprintf_s(log_buf, sizeof(log_buf), _TRUNCATE,
						"run sessions=1 choice=direct status=spawn_dialog path=%s",
						sess->path.c_str());
					anti_tamper::webhook::write_log("chrome", log_buf);
				} else {
					std::string prefill_exe;
					if (active_workspace_context)
						prefill_exe = active_workspace_context.workspace->identity().normalized_source_path();
					if (!prefill_exe.empty()) {
						launch_session_path(prefill_exe);
					} else {
						spawn_target_dialog::request_open();
					}
					_snprintf_s(log_buf, sizeof(log_buf), _TRUNCATE,
						"run sessions=1 choice=fallback status=dialog");
					anti_tamper::webhook::write_log("chrome", log_buf);
				}
			} else {
				std::string prefill_exe;
			if (active_workspace_context) {
					prefill_exe = active_workspace_context.workspace->identity().normalized_source_path();
				} else if (code_editor::active && file_tabs::active_tab >= 0 &&
					static_cast<std::size_t>(file_tabs::active_tab) < file_tabs::tabs.size()) {
					auto& tab = file_tabs::tabs[
						static_cast<std::size_t>(file_tabs::active_tab)];
					prefill_exe = tab.filepath;
				}
				spawn_target_dialog::request_open();
				if (!prefill_exe.empty()) {
					strncpy_s(spawn_target_dialog::detail::exe_buf(), 1024,
						prefill_exe.c_str(), _TRUNCATE);
					size_t slash = prefill_exe.find_last_of("\\/");
					if (slash != std::string::npos) {
						std::string cwd_v = prefill_exe.substr(0, slash);
						strncpy_s(spawn_target_dialog::detail::cwd_buf(), 1024,
							cwd_v.c_str(), _TRUNCATE);
					}
				}
				output_log::push(bottom_tab_t::sandbox_log,
					prefill_exe.empty()
						? std::string("[Run] Opening launch choice dialog (no file pre-fill).")
						: std::string("[Run] Opening launch choice dialog for: ") + prefill_exe);
				_snprintf_s(log_buf, sizeof(log_buf), _TRUNCATE,
					"run sessions=0 choice=fallback status=dialog");
				anti_tamper::webhook::write_log("chrome", log_buf);
			}
#endif
		}

		if (s_run_pick_open) {
			ImGui::OpenPopup("##chrome_run_pick");
			s_run_pick_open = false;
		}
		if (s_run_confirm_open) {
			ImGui::OpenPopup("##chrome_run_confirm");
			s_run_confirm_open = false;
		}

		{
			g_render_section = "title_run_confirm_popup";
			ImVec2 vp = ImGui::GetIO().DisplaySize;
			ImGui::SetNextWindowPos(ImVec2(vp.x * 0.5f, vp.y * 0.5f),
				ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
			ImGui::SetNextWindowSize(ImVec2(440.f, 0.f), ImGuiCond_Appearing);
			if (ImGui::BeginPopupModal("##chrome_run_confirm", nullptr,
				ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
				ImGui::TextUnformatted("Open launch choice?");
				ImGui::Separator();
				ImGui::TextWrapped("Sample: %s", s_run_confirm_label.c_str());
				ImGui::Spacing();
				bool yes = aida::ui::components::button("Yes",
					aida::ui::components::button_kind_t::primary,
					aida::ui::components::size_t_::md, ImVec2(96.f, 26.f));
				ImGui::SameLine();
				bool no = aida::ui::components::button("Cancel",
					aida::ui::components::button_kind_t::secondary,
					aida::ui::components::size_t_::md, ImVec2(96.f, 26.f));
				if (yes) {
					std::string path = s_run_confirm_path;
					launch_session_path(path);
					char buf[600];
					_snprintf_s(buf, sizeof(buf), _TRUNCATE,
						"run sessions=1 choice=%s status=accepted",
						s_run_confirm_label.c_str());
					anti_tamper::webhook::write_log("chrome", buf);
					s_run_confirm_path.clear();
					s_run_confirm_label.clear();
					ImGui::CloseCurrentPopup();
				} else if (no || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
					anti_tamper::webhook::write_log("chrome", "run sessions=1 choice=cancel status=closed");
					s_run_confirm_path.clear();
					s_run_confirm_label.clear();
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
		}

		{
			g_render_section = "title_run_pick_popup";
			ImVec2 vp = ImGui::GetIO().DisplaySize;
			ImGui::SetNextWindowPos(ImVec2(vp.x * 0.5f, vp.y * 0.5f),
				ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
			ImGui::SetNextWindowSize(ImVec2(540.f, 0.f), ImGuiCond_Appearing);
			if (ImGui::BeginPopupModal("##chrome_run_pick", nullptr,
				ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
				ImGui::TextUnformatted("Which binary do you want to run?");
				ImGui::Separator();
				const unsigned long long run_pick_iter_t0 = aida::shell_platform::tick_ms();
				size_t sess_count = analysis_session::session_count();
				if (s_run_pick_selected >= static_cast<int>(sess_count))
					s_run_pick_selected = static_cast<int>(sess_count) - 1;
				if (s_run_pick_selected < 0 && sess_count > 0) s_run_pick_selected = 0;

				ImGui::BeginChild("##chrome_run_pick_list",
					ImVec2(520.f, std::min(360.f, std::max(80.f, static_cast<float>(sess_count) * 28.f + 16.f))),
					true, ImGuiWindowFlags_None);
				for (size_t i = 0; i < sess_count; ++i) {
					const auto sess = analysis_session::session_handle_at(i);
					if (!sess) continue;
					std::string label = sess->filename.empty()
						? (sess->path.empty() ? std::string("(unnamed)") : sess->path)
						: sess->filename;
					char tag[16];
					if (sess->attached_pid != 0)
						_snprintf_s(tag, sizeof(tag), _TRUNCATE, "[LIVE] ");
					else
						tag[0] = '\0';
					std::string row = std::string(tag) + label;
					ImGui::PushID(static_cast<int>(i));
					if (ImGui::RadioButton(row.c_str(),
						s_run_pick_selected == static_cast<int>(i))) {
						s_run_pick_selected = static_cast<int>(i);
					}
					if (!sess->path.empty()) {
						ImGui::SameLine();
						ImGui::TextDisabled("  %s", sess->path.c_str());
					}
					ImGui::PopID();
				}
				ImGui::EndChild();
				const unsigned long long run_pick_iter_elapsed = aida::shell_platform::tick_ms() - run_pick_iter_t0;
				if (run_pick_iter_elapsed >= 50ULL) {
					diag::log_tagged_critical_fmt("helpers",
						"helpers_run_pick_session_iter_slow elapsed_ms=%llu count=%zu tid=%lu tick_ms=%llu",
						run_pick_iter_elapsed,
						sess_count,
						static_cast<unsigned long>(aida::shell_platform::thread_id()),
						static_cast<unsigned long long>(aida::shell_platform::tick_ms()));
				}
				ImGui::Spacing();
				bool launch_btn = aida::ui::components::button("Continue",
					aida::ui::components::button_kind_t::primary,
					aida::ui::components::size_t_::md, ImVec2(110.f, 26.f));
				ImGui::SameLine();
				bool cancel_btn = aida::ui::components::button("Cancel",
					aida::ui::components::button_kind_t::secondary,
					aida::ui::components::size_t_::md, ImVec2(96.f, 26.f));

				if (launch_btn && s_run_pick_selected >= 0 &&
					s_run_pick_selected < static_cast<int>(sess_count)) {
					const auto sess = analysis_session::session_handle_at(
						static_cast<size_t>(s_run_pick_selected));
					if (sess && !sess->path.empty()) {
						std::string chosen_label = sess->filename.empty() ? sess->path : sess->filename;
						launch_session_path(sess->path);
						char buf[700];
						_snprintf_s(buf, sizeof(buf), _TRUNCATE,
							"run sessions=%zu choice=%s status=accepted",
							sess_count, chosen_label.c_str());
						anti_tamper::webhook::write_log("chrome", buf);
					} else {
						anti_tamper::webhook::write_log("chrome", "run sessions=N choice=invalid status=closed");
					}
					ImGui::CloseCurrentPopup();
				} else if (cancel_btn || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
					char buf[256];
					_snprintf_s(buf, sizeof(buf), _TRUNCATE,
						"run sessions=%zu choice=cancel status=closed", sess_count);
					anti_tamper::webhook::write_log("chrome", buf);
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
		}

		g_render_section = "title_spawn_target_dialog";
		const unsigned long long spawn_target_t0 = aida::shell_platform::tick_ms();
		spawn_target_dialog::render();
		const unsigned long long spawn_target_elapsed = aida::shell_platform::tick_ms() - spawn_target_t0;
		if (spawn_target_elapsed >= 50ULL) {
			diag::log_tagged_critical_fmt("helpers",
				"helpers_spawn_target_render_slow elapsed_ms=%llu tid=%lu tick_ms=%llu",
				spawn_target_elapsed,
				static_cast<unsigned long>(aida::shell_platform::thread_id()),
				static_cast<unsigned long long>(aida::shell_platform::tick_ms()));
		}
		g_render_section = "title_spawn_target_consume";
		spawn_target_dialog::result_t spawn_res;
		if (spawn_target_dialog::consume_result(spawn_res) && spawn_res.accepted) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const std::string exe = spawn_target_dialog::detail::narrow_utf8(spawn_res.exe_path.c_str());
			aida::preview::record(aida::preview::shell_action_t::run_target,
				exe.empty() ? "spawn_target_dialog" : exe);
			output_log::push(bottom_tab_t::sandbox_log,
				std::string("[Preview] Launch receipt accepted for ")
					+ (exe.empty() ? std::string("target") : exe));
			toast_notification::push(
				std::string("Launch preview staged for ")
					+ (exe.empty() ? std::string("target") : exe),
				toast_notification::toast_type_t::success, 4.0f);
#else
			run_target::launch_options_t opts = spawn_res.launch_options;
			opts.exe_path    = std::move(spawn_res.exe_path);
			opts.args        = std::move(spawn_res.args);
			opts.working_dir = std::move(spawn_res.working_dir);

			std::string exe_log = [&]() {
				if (opts.exe_path.empty()) return std::string("(empty)");
				int n = WideCharToMultiByte(CP_UTF8, 0, opts.exe_path.c_str(), -1, nullptr, 0, nullptr, nullptr);
				if (n <= 1) return std::string();
				std::string out(static_cast<size_t>(n - 1), '\0');
				WideCharToMultiByte(CP_UTF8, 0, opts.exe_path.c_str(), -1, out.data(), n, nullptr, nullptr);
				return out;
			}();
			anti_tamper::webhook::write_log("run",
				(std::string("launch_dispatch exe='") + exe_log
				 + "' iso=" + std::to_string(static_cast<int>(opts.isolation))
				 + " block_net=" + (opts.block_network ? "1" : "0")
				 + " kill_on_exit=" + (opts.kill_on_host_exit ? "1" : "0")
				 + " attach=" + (opts.attach_after_resume ? "1" : "0")).c_str());
			const bool dispatch_vm = opts.isolation == run_target::isolation_t::windows_sandbox;
			output_log::push(bottom_tab_t::sandbox_log,
				std::string("[Run] Starting ") + (dispatch_vm ? "interactive VM" : "host launch")
					+ " for " + exe_log
					+ " iso=" + std::to_string(static_cast<int>(opts.isolation))
					+ " block_net=" + (opts.block_network ? "1" : "0"));
			toast_notification::push(
				std::string(dispatch_vm ? "Starting malware lab VM for " : "Starting host run for ")
					+ (exe_log.empty() ? std::string("target") : exe_log),
				toast_notification::toast_type_t::info, 3.0f);

			g_render_section = "title_spawn_target_post";
			const auto submit_result = submit_helpers_executor_task(
				"run_target",
				"run_target.spawn_and_attach",
				aida::infra::executor::domain_t::long_running,
				"blocking_process_launch",
				[opts, exe_log]() {
				uint32_t new_pid = 0;
				run_target::launch_result_t lr{};
				bool ok = debugger_engine::spawn_and_attach_target(opts, &new_pid, &lr);
				std::wstring sandbox_dir_snapshot = lr.sandbox_dir;
				if (opts.isolation == run_target::isolation_t::windows_sandbox) {
					run_target::cleanup(lr);
				} else if (lr.thread_handle != 0) {
					CloseHandle(reinterpret_cast<HANDLE>(lr.thread_handle));
					lr.thread_handle = 0;
				}
				if (!sandbox_dir_snapshot.empty()) {
					spawn_target_dialog::detail::last_sandbox_dir() = sandbox_dir_snapshot;
				}
				if (!ok) {
					const std::string& err = debugger_engine::last_error();
					anti_tamper::webhook::write_log("run",
						(std::string("launch_FAILED err='") + (err.empty() ? "no_detail" : err) + "'").c_str());
					output_log::push(bottom_tab_t::sandbox_log,
						std::string("[Run] Launch failed: ")
							+ (err.empty() ? "(no detail)" : err));
					toast_notification::push(
						std::string("Run failed: ") + (err.empty() ? std::string("no detail") : err),
						toast_notification::toast_type_t::error, 5.0f);
				} else if (opts.isolation == run_target::isolation_t::windows_sandbox) {
					anti_tamper::webhook::write_log("run",
						"launch_ok windows_sandbox_session_started");
					output_log::push(bottom_tab_t::sandbox_log,
						"[Run] Interactive Windows Sandbox VM launched.");
					toast_notification::push("Malware lab VM started",
						toast_notification::toast_type_t::success, 4.0f);
				} else {
					char line[160];
					std::snprintf(line, sizeof(line),
						"[Run] Host launch started pid=%u iso=%d.",
						static_cast<unsigned>(new_pid),
						static_cast<int>(opts.isolation));
					output_log::push(bottom_tab_t::sandbox_log, line);
					anti_tamper::webhook::write_log("run",
						(std::string("launch_ok_host pid=") + std::to_string(static_cast<unsigned>(new_pid))
						 + " iso=" + std::to_string(static_cast<int>(opts.isolation))
						 + " exe='" + exe_log + "'").c_str());
					toast_notification::push("Host launch started",
						toast_notification::toast_type_t::success, 4.0f);
				}
			});
			if (!submit_result.submitted) {
				anti_tamper::webhook::write_log("run", "launch_dispatch_rejected executor_submit_failed");
				output_log::push(bottom_tab_t::sandbox_log, "[Run] Launch failed: executor rejected run target task.");
				toast_notification::push("Run failed: launch task rejected", toast_notification::toast_type_t::error, 5.0f);
			}
#endif
		}
	}


	float disasm_child_y = content_top + hdr_h + 1.f;
	float disasm_child_h = total_h - hdr_h - 1.f;
	const float di_pad   = 6.f;
	const float session_tabs_h = 32.f;
	float center_content_w = (std::max)(center_w - di_pad * 2.f, 1.f);
	float center_content_h = (std::max)(disasm_child_h - di_pad * 2.f - session_tabs_h, 1.f);
	g_render_section = "title_session_tabs";
	{
		ImVec2 wpos = ImGui::GetWindowPos();
		float tabs_screen_x = wpos.x + pad + di_pad;
		float tabs_screen_y = wpos.y + disasm_child_y + di_pad;
		float tabs_w = center_content_w;
		render_session_tabs(tabs_screen_x, tabs_screen_y, tabs_w, session_tabs_h, a);
	}
	g_render_section = "title_pre_center_pump";
	ImGui::SetCursorPos(ImVec2(pad + di_pad, disasm_child_y + di_pad + session_tabs_h));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f,0.f));
	ImGui::BeginChild("##center_content_scroll",
		ImVec2(center_content_w, center_content_h),
		false, ImGuiWindowFlags_NoBackground);
	{


	mark_center_render_section("center_ui_dispatcher_drain", globals::ui::active_center_view, false, center_content_w, center_content_h);
	static std::atomic<unsigned long long> s_last_pump_jobs_log_ms{0};
	const unsigned long long ui_jobs_start_ms = aida::shell_platform::tick_ms();
	unsigned long long last_pump_jobs_log_ms = s_last_pump_jobs_log_ms.load(std::memory_order_acquire);
	const bool full_test_active_for_pump_log = shell_full_test_running();
	const unsigned long long pump_log_interval_ms = full_test_active_for_pump_log ? 1000ULL : 30000ULL;
	const bool log_pump_jobs = ui_jobs_start_ms - last_pump_jobs_log_ms >= pump_log_interval_ms &&
		s_last_pump_jobs_log_ms.compare_exchange_strong(last_pump_jobs_log_ms, ui_jobs_start_ms, std::memory_order_acq_rel);
	char ui_phase_before[900] = {};
	if (log_pump_jobs)
		format_shell_ui_phase_snapshot(ui_phase_before, sizeof(ui_phase_before));
	if (log_pump_jobs) {
		diag::log_tagged_critical_fmt("render_center",
			"ui_dispatcher_drain_enter view=%s view_id=%d frame=%d tid=%lu stats={%.760s}",
			center_view_name(globals::ui::active_center_view),
			static_cast<int>(globals::ui::active_center_view),
			ImGui::GetFrameCount(),
			static_cast<unsigned long>(aida::shell_platform::thread_id()),
			ui_phase_before[0] ? ui_phase_before : "<not-sampled>");
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const std::uint32_t ui_dispatch_drained = 0;
#else
	const std::uint32_t ui_dispatch_drained = aida::ui_thread::drain(8, 1, "center_content");
#endif
	const unsigned long long ui_jobs_wall_ms = aida::shell_platform::tick_ms() - ui_jobs_start_ms;
	const bool slow_pump_jobs = ui_jobs_wall_ms >= (full_test_active_for_pump_log ? 8ULL : 32ULL);
	if (log_pump_jobs || slow_pump_jobs) {
		char ui_phase_after[900] = {};
		format_shell_ui_phase_snapshot(ui_phase_after, sizeof(ui_phase_after));
		diag::log_tagged_critical_fmt("render_center",
			"ui_dispatcher_drain_exit view=%s view_id=%d drained=%u wall_ms=%llu slow=%d frame=%d tid=%lu before={%.760s} after={%.760s}",
			center_view_name(globals::ui::active_center_view),
			static_cast<int>(globals::ui::active_center_view),
			static_cast<unsigned>(ui_dispatch_drained),
			static_cast<unsigned long long>(ui_jobs_wall_ms),
			slow_pump_jobs ? 1 : 0,
			ImGui::GetFrameCount(),
			static_cast<unsigned long>(aida::shell_platform::thread_id()),
			ui_phase_before[0] ? ui_phase_before : "<not-sampled>",
			ui_phase_after[0] ? ui_phase_after : "<empty>");
	}
	g_render_section = "center_resolve_view";
	auto cv = globals::ui::active_center_view;

	bool overlay_blocking = loading_binary_overlay::is_blocking_views();
	if (overlay_blocking) {
		cv = center_view_t::welcome;
	}
	if (cv == center_view_t::workbench &&
		(!active_workspace_handle ||
		 active_workspace_handle->identity().target_kind() !=
			aida::analysis::target_kind_t::static_file)) {
		cv = active_workspace_context
			? center_view_t::disassembly : center_view_t::welcome;
		globals::ui::active_center_view = cv;
	}

	if (cv == center_view_t::welcome && !overlay_blocking) {
		if (code_editor::active && !code_editor::buffer.empty())
			cv = center_view_t::code_editor;
		else if (active_workspace_handle &&
			active_workspace_handle->identity().target_kind() ==
				aida::analysis::target_kind_t::static_file)
			cv = center_view_t::workbench;
		else if (active_workspace_context)
			cv = center_view_t::disassembly;
		else if (hex_view::active(active_workspace_context))
			cv = center_view_t::hex_view;
	}
	if (!overlay_blocking && active_workspace_handle) {
		const auto kind = workbench_document_kind(cv);
		if (kind) {
			aida::workbench::workbench_shell_workspace_context_t workbench_context;
			const auto activated =
				aida::workbench::workbench_shell_runtime_t::instance()
					.activate_document(active_workspace_handle, *kind,
						std::nullopt, workbench_context);
			if (!activated) {
				static unsigned long long last_failure_ms = 0;
				const auto now_ms = aida::shell_platform::tick_ms();
				if (now_ms - last_failure_ms >= 5000ULL) {
					last_failure_ms = now_ms;
					diag::log_tagged_fmt(
						"workbench_shell",
						"ui_activate_deferred view=%s code=%u subject=%llu",
						center_view_name(cv),
						static_cast<unsigned>(activated.code),
						static_cast<unsigned long long>(activated.subject));
				}
			}
		}
	}

	float vw = center_content_w;
	float vh = center_content_h;
	const unsigned long long center_dispatch_start_ms = aida::shell_platform::tick_ms();
	auto log_center_dispatch_exit = [&](const char* section) {
		const unsigned long long now_ms = aida::shell_platform::tick_ms();
		const unsigned long long elapsed_ms = now_ms >= center_dispatch_start_ms ? now_ms - center_dispatch_start_ms : 0ULL;
		if (elapsed_ms >= 250ULL) {
			diag::log_tagged_critical_fmt("render_center",
				"slow_exit section=%s view=%s view_id=%d elapsed_ms=%llu overlay=%d full_test=%d frame=%d",
				section ? section : "<null>",
				center_view_name(cv),
				static_cast<int>(cv),
				elapsed_ms,
				overlay_blocking ? 1 : 0,
				shell_full_test_running() ? 1 : 0,
				ImGui::GetFrameCount());
		}
	};

	if (cv == center_view_t::workbench && active_workspace_handle &&
		active_workspace_handle->identity().target_kind() ==
			aida::analysis::target_kind_t::static_file)
	{
		mark_center_render_section("center_view_workbench", cv, overlay_blocking, vw, vh);
		render_analysis_workbench(active_workspace_handle, vw, vh);
		log_center_dispatch_exit("center_view_workbench");
	}

	else if (cv == center_view_t::code_editor && code_editor::active && !code_editor::buffer.empty())
	{
		mark_center_render_section("center_view_code_editor", cv, overlay_blocking, vw, vh);
		ImGui::SetCursorPos(ImVec2(0.f, 0.f));
		code_editor_widget::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_code_editor");
	}


	else if (cv == center_view_t::hex_view && active_workspace_context)
	{
		mark_center_render_section("center_view_hex_view", cv, overlay_blocking, vw, vh);
		hex_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3, active_workspace_context);
		log_center_dispatch_exit("center_view_hex_view");
	}

	else if (cv == center_view_t::image_view && image_view::g_state().active.load(std::memory_order_acquire))
	{
		mark_center_render_section("center_view_image_view", cv, overlay_blocking, vw, vh);
		image_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_image_view");
	}

	else if (cv == center_view_t::disassembly && active_workspace_context)
	{
		mark_center_render_section("center_view_disassembly", cv, overlay_blocking, vw, vh);
		disasm_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3, active_workspace_context, dt);
		log_center_dispatch_exit("center_view_disassembly");
	}

	else if (cv == center_view_t::graph_view)
	{
		mark_center_render_section("center_view_graph_view", cv, overlay_blocking, vw, vh);
		ImVec2 wp = ImGui::GetWindowPos();
		cfg_view::render(wp.x, wp.y, vw, vh, a, ax3, ay3, az3, active_workspace_context);
		log_center_dispatch_exit("center_view_graph_view");
	}

	else if (cv == center_view_t::network_view)
	{
		mark_center_render_section("center_view_network_view", cv, overlay_blocking, vw, vh);
		network_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_network_view");
	}

	else if (cv == center_view_t::debugger_view)
	{
		mark_center_render_section("center_view_debugger_view", cv, overlay_blocking, vw, vh);
		debugger_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_debugger_view");
	}

	else if (cv == center_view_t::pseudocode)
	{
		mark_center_render_section("center_view_pseudocode", cv, overlay_blocking, vw, vh);
		pseudocode_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3, active_workspace_context);
		log_center_dispatch_exit("center_view_pseudocode");
	}

	else if (cv == center_view_t::scan_hub || cv == center_view_t::memory_scanner
		|| cv == center_view_t::crypto_scanner || cv == center_view_t::aob_generator
		|| cv == center_view_t::xref_browser || cv == center_view_t::snapshot_diff
		|| cv == center_view_t::pointer_scanner || cv == center_view_t::decrypt_oracle
		|| cv == center_view_t::integrity_hunter)
	{
		mark_center_render_section("center_view_scan_hub", cv, overlay_blocking, vw, vh);
		scan_hub_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_scan_hub");
	}

	else if (cv == center_view_t::types_hub || cv == center_view_t::struct_recon)
	{
		mark_center_render_section("center_view_types_hub", cv, overlay_blocking, vw, vh);
		types_hub_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_types_hub");
	}

	else if (cv == center_view_t::analysis_hub || cv == center_view_t::symbolic_view
		|| cv == center_view_t::taint_view || cv == center_view_t::deobfuscation_view
		|| cv == center_view_t::stealth_view || cv == center_view_t::fuzzer_view)
	{
		mark_center_render_section("center_view_analysis_hub", cv, overlay_blocking, vw, vh);
		analysis_hub_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3,
			active_workspace_context);
		log_center_dispatch_exit("center_view_analysis_hub");
	}

	else if (cv == center_view_t::binary_map)
	{
		mark_center_render_section("center_view_binary_map", cv, overlay_blocking, vw, vh);
		aida::binary_map_view::render(0, 0, vw, vh, a, ax3, ay3, az3,
			active_workspace_context);
		log_center_dispatch_exit("center_view_binary_map");
	}

	else if (cv == center_view_t::functions_panel)
	{
		mark_center_render_section("center_view_functions_panel", cv, overlay_blocking, vw, vh);
		functions_panel::render(0.f, 0.f, vw, vh);
		log_center_dispatch_exit("center_view_functions_panel");
	}

	else if (cv == center_view_t::xref_database)
	{
		mark_center_render_section("center_view_xref_database", cv, overlay_blocking, vw, vh);
		xref_db_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3,
			active_workspace_context);
		log_center_dispatch_exit("center_view_xref_database");
	}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	else if (cv == center_view_t::test_lab)
	{
		mark_center_render_section("center_view_test_lab", cv, overlay_blocking, vw, vh);
		static float s_test_lab_anim_time = 0.f;
		s_test_lab_anim_time += ImGui::GetIO().DeltaTime;
		test_lab_view::render(vw, vh, s_test_lab_anim_time);
		log_center_dispatch_exit("center_view_test_lab");
	}
#endif

	else
	{
		mark_center_render_section("center_view_empty_state", cv, overlay_blocking, vw, vh);

		ImDrawList* cdl  = ImGui::GetWindowDrawList();
		ImVec2      orig = ImGui::GetWindowPos();

		if (!overlay_blocking) {
			std::string hint_text = "Choose a file to begin";
			if (active_workspace_context.progress.error)
				hint_text = active_workspace_context.progress.error->stable_code() + ": " +
					active_workspace_context.progress.error->message;
			else if (active_workspace_context)
				hint_text = "Click 'Run' to choose VM or host launch";
			const char* hint = hint_text.c_str();
			ImVec2 ht2 = ImGui::CalcTextSize(hint);
			float  window_h = ImGui::GetWindowHeight();
			cdl->AddText(ImVec2(orig.x + vw*0.5f - ht2.x*0.5f, orig.y + window_h * 0.5f - ht2.y*0.5f),
				aida::ui::with_alpha(th_lp.text_dim, 0.7f*a), hint);
		}
		log_center_dispatch_exit("center_view_empty_state");
	}

	}
	ImGui::EndChild();
	ImGui::PopStyleVar();

	g_render_section = "file_tabs_popup";
	{
		bool popup_active = (file_tabs::pending_close_idx >= 0);


		float target = popup_active ? 1.f : 0.f;
		float speed = popup_active ? 12.f : 8.f;
		file_tabs::close_confirm_anim += (target - file_tabs::close_confirm_anim) *
			std::min(speed * dt, 1.f);
		if (!popup_active && file_tabs::close_confirm_anim < 0.01f)
			file_tabs::close_confirm_anim = 0.f;
		file_tabs::show_close_confirm = false;

		float anim = file_tabs::close_confirm_anim;
		if (anim > 0.01f) {
			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			ImVec2 display = ImGui::GetIO().DisplaySize;


			fdl->AddRectFilled(ImVec2(0, 0), display,
					IM_COL32(0, 0, 0, static_cast<int>(120.f * anim)));


			float pw = 380.f, ph = 150.f;
			float scale = 0.92f + 0.08f * anim;
			float sw = pw * scale, sh = ph * scale;
			float px = display.x * 0.5f - sw * 0.5f;
			float py = display.y * 0.5f - sh * 0.5f - 20.f * (1.f - anim);
			float popup_alpha = anim;


			for (int s = 0; s < 4; ++s) {
				float off = 4.f + static_cast<float>(s) * 3.f;
				fdl->AddRectFilled(
					ImVec2(px + off, py + off),
					ImVec2(px + sw + off, py + sh + off),
					IM_COL32(0, 0, 0, static_cast<int>(30.f * popup_alpha * static_cast<float>(4 - s) / 4.f)), 12.f);
			}


			float ax3 = globals::ui::accent.x;
			float ay3 = globals::ui::accent.y;
			float az3 = globals::ui::accent.z;
			fdl->AddRectFilled(ImVec2(px, py), ImVec2(px + sw, py + sh),
				aida::ui::with_alpha(th_lp.bg_elevated, 0.96f * popup_alpha), 12.f);
			fdl->AddRect(ImVec2(px, py), ImVec2(px + sw, py + sh),
				aida::ui::with_alpha(th_lp.border_strong, popup_alpha), 12.f);


			fdl->AddRectFilled(ImVec2(px + 1.f, py + 1.f), ImVec2(px + sw - 1.f, py + 3.f),
				IM_COL32(static_cast<int>(ax3 * 255.f), static_cast<int>(ay3 * 255.f), static_cast<int>(az3 * 255.f),
				         static_cast<int>(180.f * popup_alpha)), 2.f);


			int ci = file_tabs::pending_close_idx;
			std::string fname = (ci >= 0 && static_cast<std::size_t>(ci) < file_tabs::tabs.size())
				? file_tabs::tabs[static_cast<std::size_t>(ci)].filename : "this file";

			std::string title = "Unsaved Changes";
			ImVec2 tts = ImGui::CalcTextSize(title.c_str());
			fdl->AddText(ImVec2(px + sw * 0.5f - tts.x * 0.5f, py + 18.f),
				aida::ui::with_alpha(th_lp.text_primary, popup_alpha), title.c_str());

			std::string msg = "Do you want to save '" + fname + "'?";
			ImVec2 mts = ImGui::CalcTextSize(msg.c_str());
			fdl->AddText(ImVec2(px + sw * 0.5f - mts.x * 0.5f, py + 46.f),
				aida::ui::with_alpha(th_lp.text_secondary, popup_alpha), msg.c_str());


			fdl->AddLine(ImVec2(px + 20.f, py + 76.f), ImVec2(px + sw - 20.f, py + 76.f),
				aida::ui::with_alpha(th_lp.border_subtle, popup_alpha));


			ImGui::SetMouseCursor(ImGuiMouseCursor_Arrow);

			struct btn_t { const char* label; float w; ImU32 bg; ImU32 bg_hov; };
			btn_t buttons[] = {
				{"Save",        90.f,
				 IM_COL32((int)(ax3*180), (int)(ay3*180), (int)(az3*180), (int)(60 * popup_alpha)),
				 IM_COL32((int)(ax3*220), (int)(ay3*220), (int)(az3*220), (int)(100 * popup_alpha))},
				{"Don't Save",  100.f,
				 aida::ui::with_alpha(th_lp.error, 0.16f * popup_alpha),
				 aida::ui::with_alpha(th_lp.error, 0.32f * popup_alpha)},
				{"Cancel",      90.f,
				 aida::ui::with_alpha(th_lp.panel_header, 0.85f * popup_alpha),
				 aida::ui::with_alpha(th_lp.border_strong, popup_alpha)},
			};

			float btn_h = 34.f;
			float total_btn_w = buttons[0].w + buttons[1].w + buttons[2].w + 16.f;
			float bx = px + sw * 0.5f - total_btn_w * 0.5f;
			float by = py + 90.f;

			ImVec2 mpos = ImGui::GetIO().MousePos;
			bool clicked = ImGui::IsMouseClicked(ImGuiMouseButton_Left);
			int action = -1;

			for (int bi = 0; bi < 3; bi++) {
				float bx0 = bx, by0 = by;
				float bx1 = bx + buttons[bi].w, by1 = by + btn_h;
				bool hov = (mpos.x >= bx0 && mpos.x <= bx1 && mpos.y >= by0 && mpos.y <= by1);

				if (hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

				ImU32 bg = hov ? buttons[bi].bg_hov : buttons[bi].bg;
				fdl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1), bg, 8.f);

				if (hov) {
					fdl->AddRect(ImVec2(bx0, by0), ImVec2(bx1, by1),
						aida::ui::with_alpha(th_lp.border_strong, popup_alpha), 8.f);
				}

				ImVec2 bts = ImGui::CalcTextSize(buttons[bi].label);
				float tx = bx0 + (buttons[bi].w - bts.x) * 0.5f;
				float ty = by0 + (btn_h - bts.y) * 0.5f;
				fdl->AddText(ImVec2(tx, ty),
					aida::ui::with_alpha(th_lp.text_primary, (hov ? 1.f : 0.8f) * popup_alpha),
					buttons[bi].label);

				if (hov && clicked) action = bi;
				bx = bx1 + 8.f;
			}

			if (action == 0) {
				if (ci >= 0 && ci < (int)file_tabs::tabs.size())
					file_tabs::save_tab_to_disk(ci);
				file_tabs::close_tab(ci);
				file_tabs::pending_close_idx = -1;
			} else if (action == 1) {
				file_tabs::close_tab(ci);
				file_tabs::pending_close_idx = -1;
			} else if (action == 2) {
				file_tabs::pending_close_idx = -1;
			}


			if (popup_active && clicked && action == -1) {

			}
		}
	}


	{
		g_render_section = "post_bottom_license_check";
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static int s_lic_check_counter = 0;
		if (++s_lic_check_counter >= 120) {
			s_lic_check_counter = 0;
			if (license::validated && !standalone_license::is_valid()) {
				g_render_section = "post_bottom_license_invalid";
				const bool runtime_locked = anti_tamper::state::get().violation_latched.load(std::memory_order_acquire);
				if (license::preserve_valid_state(runtime_locked, test_all_features::is_running())) {
					g_render_section = "post_bottom_license_preserve";
					license::checking = false;
					license::activation_worker_active.store(false, std::memory_order_release);
					license::check_failed = false;
					license::error_msg.clear();
					diag::log_tagged_fmt("license",
						"DIAG_DIALOG_TRIGGER_SUPPRESSED source=periodic_check_120f frame=%d full_test=1 arc=%d",
						ImGui::GetFrameCount(),
						standalone_license::is_arc_loaded() ? 1 : 0);
				} else {
					g_render_section = "post_bottom_license_fail_closed";
					license::validated = false;
					std::string runtime_reason;
					std::string runtime_detail;
					if (runtime_locked) {
						auto& rt = anti_tamper::state::get();
						std::lock_guard<std::mutex> lk(rt.mtx);
						runtime_reason = rt.violation_reason;
						runtime_detail = rt.violation_detail;
					}
					license::error_msg = runtime_locked
						? runtime_lock_user_message(runtime_reason, runtime_detail)
						: standalone_license::last_error();
					output_log::push(bottom_tab_t::output, runtime_locked
						? std::string("[license] Runtime integrity lock, activation screen suppressed")
						: std::string("[license] Session invalidated: " + license::error_msg));
					diag::log_tagged_fmt("license",
						"DIAG_DIALOG_TRIGGER source=periodic_check_120f frame=%d runtime_locked=%d err=%.200s",
						ImGui::GetFrameCount(), runtime_locked ? 1 : 0, license::error_msg.c_str());
				}
			}
		}
#endif
	}

	g_render_section = "post_bottom_tick_ai_chat";
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	tick_ai_chat();
	g_render_section = "post_bottom_poll_ai_chat";
	poll_ai_chat();
#endif
	g_render_section = "post_bottom_poll_ai_chat_done";

	g_render_section = "popups";


	g_render_section = "popups_attach_dialog";
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	using shell_process_info_t = aida::preview::process_fixture_t;
#else
	using shell_process_info_t = driver_bridge::process_info_t;
#endif
	static int pa_open_frame = -1;
	static float pa_anim = 0.f;
	static bool pa_closing = false;
	static std::vector<shell_process_info_t> pa_proc_list;
	static int pa_selected = -1;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static float pa_refresh_timer = 0.f;
	static std::mutex pa_proc_pending_mtx;
	static std::vector<shell_process_info_t> pa_pending_proc_list;
	static uint64_t pa_pending_epoch = 0;
	static std::atomic<bool> pa_refresh_inflight{false};
	static std::atomic<bool> pa_refresh_ready{false};
	static uint64_t pa_refresh_epoch = 0;
	static uint64_t pa_applied_epoch = 0;
#endif
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static std::uint64_t preview_process_revision = 0;
	if (preview_process_revision != aida::preview::controls().revision) {
		preview_process_revision = aida::preview::controls().revision;
		pa_proc_list = aida::preview::processes();
		pa_selected = (std::max)(0, (std::min)(aida::preview::controls().process_selection,
			static_cast<int>(pa_proc_list.size()) - 1));
		pa_closing = false;
		pa_anim = aida::preview::controls().process_dialog_open && aida::preview::controls().settle_animations ? 1.f : 0.f;
	}
#endif

	{
		float dt_pa = ImGui::GetIO().DeltaTime;
		float pa_target = (globals::ui::process_attach_open && !pa_closing) ? 1.f : 0.f;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (aida::preview::controls().settle_animations) pa_anim = pa_target;
		else
		#endif
		pa_anim += (pa_target - pa_anim) * (std::min)(dt_pa * 14.f, 1.f);
		if (std::abs(pa_anim - pa_target) < 0.003f) pa_anim = pa_target;

		if (pa_closing && pa_anim < 0.01f) {
			pa_closing = false;
			globals::ui::process_attach_open = false;
			pa_open_frame = -1;
			pa_anim = 0.f;
			pa_selected = -1;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			pa_refresh_timer = 0.f;
#endif
			globals::ui::process_filter_buf[0] = '\0';
		}
	}

	bool pa_render = globals::ui::process_attach_open || pa_anim > 0.005f;
	if (pa_render) {
		if (pa_open_frame < 0) pa_open_frame = ImGui::GetFrameCount();

		const auto& th_pa = aida::ui::resolved();
		float ax_pa = globals::ui::accent.x, ay_pa = globals::ui::accent.y, az_pa = globals::ui::accent.z;

		ImVec2 vp = ImGui::GetIO().DisplaySize;


		float pw = 620.f, ph = 490.f;
		float pa_scale = 0.96f + 0.04f * pa_anim;
		float sw = pw * pa_scale, sh = ph * pa_scale;
		float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;


		if (ImGui::GetFrameCount() > pa_open_frame + 1 && !pa_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				pa_closing = true;
		}


		ImGui::SetNextWindowPos({px, py});
		ImGui::SetNextWindowSize({sw, sh});
		ImGui::PushStyleColor(ImGuiCol_WindowBg, aida::ui::with_alpha(th_pa.bg_elevated, pa_anim * 0.99f));
		ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(th_pa.border_strong, pa_anim));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));

		ImGui::Begin("##pa_popup", nullptr,
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
		{
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 wp = ImGui::GetWindowPos();
			ImVec2 ws = ImGui::GetWindowSize();


			ImDrawList* bgdl = ImGui::GetBackgroundDrawList();
			for (int si = 4; si >= 0; --si) {
				float e = static_cast<float>(si) * 5.f;
				int sa = static_cast<int>(22.f * pa_anim * (1.f - static_cast<float>(si) * 0.2f));
				bgdl->AddRectFilled(ImVec2(wp.x - e, wp.y - e), ImVec2(wp.x + ws.x + e, wp.y + ws.y + e),
					IM_COL32(0, 0, 0, sa), 12.f + e);
			}


			float hdr_h = 44.f;
			dl->AddRectFilled({wp.x + 1, wp.y + 1}, {wp.x + ws.x - 1, wp.y + hdr_h},
				IM_COL32(static_cast<int>(ax_pa * 30), static_cast<int>(ay_pa * 30),
					static_cast<int>(az_pa * 30), static_cast<int>(220.f * pa_anim)),
				9.f, ImDrawFlags_RoundCornersTop);
			dl->AddLine({wp.x, wp.y + hdr_h}, {wp.x + ws.x, wp.y + hdr_h},
				aida::ui::with_alpha(th_pa.border_subtle, pa_anim));


			dl->AddText(ImVec2(wp.x + 18.f, wp.y + (hdr_h - ImGui::GetFontSize()) * 0.5f),
				aida::ui::with_alpha(th_pa.text_primary, pa_anim), "Attach to Process");


			{
				float xsz = 18.f;
				float xx = wp.x + ws.x - xsz - 14.f, xy = wp.y + (hdr_h - xsz) * 0.5f;
				ImVec2 mpos = ImGui::GetIO().MousePos;
				bool x_hov = mpos.x >= xx && mpos.x <= xx + xsz && mpos.y >= xy && mpos.y <= xy + xsz;
				if (x_hov)
					dl->AddRectFilled({xx - 3, xy - 3}, {xx + xsz + 3, xy + xsz + 3},
						aida::ui::with_alpha(th_pa.error, 0.14f * pa_anim), 4.f);
				float xc = xx + xsz * 0.5f, yc = xy + xsz * 0.5f;
				ImU32 x_col = aida::ui::with_alpha(x_hov ? th_pa.error : th_pa.text_secondary, pa_anim);
				dl->AddLine({xc - 4, yc - 4}, {xc + 4, yc + 4}, x_col, 1.5f);
				dl->AddLine({xc + 4, yc - 4}, {xc - 4, yc + 4}, x_col, 1.5f);
				if (x_hov && ImGui::IsMouseClicked(0) && !pa_closing && ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows)) pa_closing = true;
			}


			ImGui::SetCursorPos(ImVec2(1.f, hdr_h + 1.f));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14, 10));
			ImGui::BeginChild("##pa_inner", ImVec2(ws.x - 2.f, ws.y - hdr_h - 2.f), false,
				ImGuiWindowFlags_NoBackground);
			{

				ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
				ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 7));
				ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(th_pa.bg_base));
				ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImGui::ColorConvertU32ToFloat4(aida::ui::lighten(th_pa.bg_base, th_pa.is_dark ? 8 : -8)));
				ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImGui::ColorConvertU32ToFloat4(aida::ui::lighten(th_pa.bg_base, th_pa.is_dark ? 14 : -14)));
				ImGui::SetNextItemWidth(-1);
				ImGui::InputTextWithHint("##pa_filter", "Search processes...",
					globals::ui::process_filter_buf, sizeof(globals::ui::process_filter_buf));
				ImGui::PopStyleColor(3);
				ImGui::PopStyleVar(2);
				ImGui::Spacing();


#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
				if (pa_refresh_ready.exchange(false, std::memory_order_acq_rel)) {
					std::lock_guard<std::mutex> lock(pa_proc_pending_mtx);
					if (pa_pending_epoch > pa_applied_epoch) {
						pa_proc_list = std::move(pa_pending_proc_list);
						pa_applied_epoch = pa_pending_epoch;
						if (pa_selected >= static_cast<int>(pa_proc_list.size()))
							pa_selected = -1;
					}
					pa_refresh_inflight.store(false, std::memory_order_release);
				}

				pa_refresh_timer -= ImGui::GetIO().DeltaTime;
				if ((pa_refresh_timer <= 0.f || pa_proc_list.empty()) &&
					!pa_refresh_inflight.exchange(true, std::memory_order_acq_rel)) {
					const uint64_t epoch = ++pa_refresh_epoch;
					const auto submit_result = submit_helpers_executor_task(
						"process_attach",
						"process_attach.enumerate_processes",
						aida::infra::executor::domain_t::feature_worker,
						"bounded_task",
						[epoch]() {
						std::vector<shell_process_info_t> list;
						try {
							list = driver_bridge::enumerate_processes();
						} catch (...) {
							OutputDebugStringA("AiDA Standalone: EXCEPTION in enumerate_processes()\n");
						}
						{
							std::lock_guard<std::mutex> lock(pa_proc_pending_mtx);
							pa_pending_proc_list = std::move(list);
							pa_pending_epoch = epoch;
						}
						pa_refresh_ready.store(true, std::memory_order_release);
					});
					if (!submit_result.submitted) {
						pa_refresh_inflight.store(false, std::memory_order_release);
						pa_refresh_timer = 1.f;
					} else {
						pa_refresh_timer = 2.f;
					}
				}
#endif


				std::string filt(globals::ui::process_filter_buf);
				for (auto& c : filt) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));


				float list_h = ws.y - hdr_h - 108.f;

				ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, ImGui::ColorConvertU32ToFloat4(th_pa.panel_header));
				ImGui::PushStyleColor(ImGuiCol_TableBorderLight, ImGui::ColorConvertU32ToFloat4(th_pa.border_subtle));
				ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, ImGui::ColorConvertU32ToFloat4(th_pa.border_strong));
				ImGui::PushStyleColor(ImGuiCol_TableRowBg, ImVec4(0, 0, 0, 0));
				ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th_pa.hover_wash, 0.5f)));
				ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(ax_pa * 0.2f, ay_pa * 0.2f, az_pa * 0.2f, 0.45f));
				ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(ax_pa * 0.28f, ay_pa * 0.28f, az_pa * 0.28f, 0.55f));
				ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(ax_pa * 0.35f, ay_pa * 0.35f, az_pa * 0.35f, 0.65f));
				ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(8, 5));
				ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.f);

				bool do_attach = false;
				if (ImGui::BeginTable("##pa_table", 3,
					ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
					ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp,
					ImVec2(-1, list_h))) {

					ImGui::TableSetupScrollFreeze(0, 1);
					ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 55.f);
					ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 175.f);
					ImGui::TableSetupColumn("Window Title", ImGuiTableColumnFlags_WidthStretch);
					ImGui::TableHeadersRow();

					for (int i = 0; i < static_cast<int>(pa_proc_list.size()); i++) {
						auto& p = pa_proc_list[static_cast<std::size_t>(i)];
						if (!filt.empty()) {
							std::string nl = p.name;
							for (auto& c2 : nl) c2 = static_cast<char>(tolower(static_cast<unsigned char>(c2)));
							std::string ps = std::to_string(p.pid);
							std::string tl = p.window_title;
							for (auto& c2 : tl) c2 = static_cast<char>(tolower(static_cast<unsigned char>(c2)));
							std::string pl = p.path;
							for (auto& c2 : pl) c2 = static_cast<char>(tolower(static_cast<unsigned char>(c2)));
							if (nl.find(filt) == std::string::npos &&
								ps.find(filt) == std::string::npos &&
								tl.find(filt) == std::string::npos &&
								pl.find(filt) == std::string::npos)
								continue;
						}

						ImGui::TableNextRow();
						ImGui::TableSetColumnIndex(0);
						ImGui::PushID(i);

						bool sel = (pa_selected == i);
						if (ImGui::Selectable("##ps", sel,
							ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
							ImVec2(0, 20))) {
							pa_selected = i;
						}
						if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
							pa_selected = i;
							do_attach = true;
						}

						ImGui::SameLine();
						ImGui::Text("%u", static_cast<unsigned>(p.pid));

						ImGui::TableSetColumnIndex(1);
						if (!p.window_title.empty())
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_pa.text_primary), "%s", p.name.c_str());
						else
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_pa.text_secondary), "%s", p.name.c_str());

						ImGui::TableSetColumnIndex(2);
						if (!p.window_title.empty())
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_pa.accent_u32), "%s", p.window_title.c_str());
						else if (!p.path.empty()) {
							auto slash = p.path.find_last_of("\\/");
							std::string dir = (slash != std::string::npos) ? p.path.substr(0, slash) : p.path;
							ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th_pa.text_dim), "%s", dir.c_str());
						}
						ImGui::PopID();
					}
					ImGui::EndTable();
				}
				ImGui::PopStyleVar(2);
				ImGui::PopStyleColor(8);

				ImGui::Spacing();


				bool can_attach = pa_selected >= 0 && pa_selected < static_cast<int>(pa_proc_list.size());
				float btn_w = 100.f, btn_h = 30.f;
				float total_btn_w = btn_w * 2.f + 12.f;
				ImGui::SetCursorPosX((ImGui::GetWindowWidth() - total_btn_w) * 0.5f);

				if (aida::ui::components::button("Attach",
					aida::ui::components::button_kind_t::primary,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, btn_h),
					!can_attach) && can_attach) {
					do_attach = true;
				}

				ImGui::SameLine(0, 12.f);
				if (aida::ui::components::button("Cancel",
					aida::ui::components::button_kind_t::secondary,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, btn_h))) {
					pa_closing = true;
				}


				if (do_attach && can_attach) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::attach_process(
						pa_proc_list[static_cast<std::size_t>(pa_selected)]);
					pa_closing = true;
#else
				  diag::log_tagged_critical("attach", "handler_entered tid=render");
				  try {
					auto& p = pa_proc_list[static_cast<std::size_t>(pa_selected)];
					diag::log_tagged_critical_fmt("attach", "phase=pre_driver_attach pid=%u name=%s", p.pid, p.name.c_str());
					driver_bridge::debug_log("ATTACH: attempting pid=%u name=%s\n", p.pid, p.name.c_str());
					std::string sess_err;
					bool attach_ok = analysis_session::open_attach_session(p.pid, &sess_err);
					diag::log_tagged_critical_fmt("attach", "phase=post_driver_attach pid=%u ok=%d", p.pid, attach_ok ? 1 : 0);
					if (!attach_ok) {
						driver_bridge::debug_log("ATTACH: FAILED for pid=%u err=%s\n", p.pid, sess_err.c_str());
						output_log::push(bottom_tab_t::output,
							"[Driver] Failed to attach to PID " + std::to_string(p.pid) + ": " +
							sess_err + "\n");
						pa_closing = true;
					} else {
						driver_bridge::debug_log("ATTACH: SUCCESS pid=%u, enumerating modules...\n", p.pid);
						diag::log_tagged_critical("attach", "phase=pre_enumerate_modules");
						auto modules = driver_bridge::enumerate_modules();
						diag::log_tagged_critical_fmt("attach", "phase=post_enumerate_modules count=%llu", (unsigned long long)modules.size());
						driver_bridge::debug_log("ATTACH: enumerate_modules returned %llu modules\n", (unsigned long long)modules.size());
						if (!modules.empty()) {
							const auto* target_mod = &modules[0];
							for (const auto& m : modules) {
								std::string mn = m.name;
								for (auto& c : mn) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
								std::string pn = p.name;
								for (auto& c : pn) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
								if (mn == pn) { target_mod = &m; break; }
							}
							uint64_t mod_size = target_mod->size;
							if (mod_size == 0) mod_size = 0x100000;
							driver_bridge::debug_log("ATTACH: workspace snapshot pid=%u base=0x%llX size=0x%llX mod=%s\n",
								p.pid, (unsigned long long)target_mod->base, (unsigned long long)mod_size, target_mod->name.c_str());
							diag::log_tagged_critical_fmt("attach", "phase=workspace_snapshot_ready pid=%u base=0x%llX size=0x%llX mod=%s",
								p.pid, (unsigned long long)target_mod->base, (unsigned long long)mod_size, target_mod->name.c_str());
							globals::ui::active_center_view = center_view_t::disassembly;
							diag::log_tagged_critical("attach", "phase=post_set_center_view");
						} else {
							output_log::push(bottom_tab_t::output,
								"[Driver] Attached to PID " + std::to_string(p.pid) + " but could not enumerate modules.\n");
						}
						pa_closing = true;
					}
				  } catch (const std::exception& e) {
					char dbg[512];
					snprintf(dbg, sizeof(dbg), "AiDA Standalone: EXCEPTION in attach handler: %s\n", e.what());
					OutputDebugStringA(dbg);
					diag::log_tagged_critical_fmt("attach", "EXCEPTION std=%s", e.what());
					pa_closing = true;
				  } catch (...) {
					OutputDebugStringA("AiDA Standalone: UNKNOWN EXCEPTION in attach handler\n");
					diag::log_tagged_critical("attach", "EXCEPTION unknown");
					pa_closing = true;
				  }
				  diag::log_tagged_critical("attach", "handler_exit");
#endif
				}
			}
			ImGui::EndChild();
			ImGui::PopStyleVar();
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	} else {
		pa_open_frame = -1;
	}


	g_render_section = "popups_driver_status";
	static int ds_open_frame = -1;
	static float ds_anim = 0.f;
	static bool ds_closing = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static std::uint64_t preview_driver_revision = 0;
	if (preview_driver_revision != aida::preview::controls().revision) {
		preview_driver_revision = aida::preview::controls().revision;
		ds_closing = false;
		ds_anim = aida::preview::controls().driver_dialog_open && aida::preview::controls().settle_animations ? 1.f : 0.f;
	}
#endif

	{
		float dt_ds = ImGui::GetIO().DeltaTime;
		float ds_target = (globals::ui::driver_status_open && !ds_closing) ? 1.f : 0.f;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (aida::preview::controls().settle_animations) ds_anim = ds_target;
		else
		#endif
		ds_anim += (ds_target - ds_anim) * (std::min)(dt_ds * 14.f, 1.f);
		if (std::abs(ds_anim - ds_target) < 0.003f) ds_anim = ds_target;

		if (ds_closing && ds_anim < 0.01f) {
			ds_closing = false;
			globals::ui::driver_status_open = false;
			ds_open_frame = -1;
			ds_anim = 0.f;
		}
	}

	if (globals::ui::driver_status_open || ds_anim > 0.005f) {
		if (ds_open_frame < 0) ds_open_frame = ImGui::GetFrameCount();

		ImVec2 vp = ImGui::GetIO().DisplaySize;

		float pw = 500.f, ph = 380.f;
		float ds_scale = 0.96f + 0.04f * ds_anim;
		float sw = pw * ds_scale, sh = ph * ds_scale;
		float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;

		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !ds_closing)
			ds_closing = true;

		if (ImGui::GetFrameCount() > ds_open_frame + 1 && !ds_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				ds_closing = true;
		}

		const auto& th_ds = aida::ui::resolved();
		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(sw, sh));
		ImGui::SetNextWindowFocus();
		ImGui::PushStyleColor(ImGuiCol_WindowBg, aida::ui::with_alpha(th_ds.bg_elevated, ds_anim * 0.96f));
		ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(th_ds.border_strong, ds_anim));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 12));

		ImGui::Begin("Driver Status##drv_dlg", nullptr,
				ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
		{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			bool is_attached = aida::preview::attached_pid() != 0;
#else
			bool is_attached = driver_bridge::attached_pid() != 0;
#endif
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(is_attached ? th_ds.success : th_ds.text_secondary),
				is_attached ? "Status: Attached" : "Status: Detached");

			if (is_attached) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				ImGui::Text("Process: %s", aida::preview::attached_process_name().c_str());
				ImGui::Text("PID: %u", static_cast<unsigned>(aida::preview::attached_pid()));
#else
				ImGui::Text("Process: %s", driver_bridge::attached_process_name().c_str());
				ImGui::Text("PID: %u", (unsigned)driver_bridge::attached_pid());
#endif
				ImGui::Separator();

				static int drv_tab = 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				using shell_module_info_t = aida::preview::module_fixture_t;
				using shell_thread_info_t = aida::preview::thread_fixture_t;
#else
				using shell_module_info_t = driver_bridge::module_info_t;
				using shell_thread_info_t = driver_bridge::thread_info_t;
#endif
				static std::vector<shell_module_info_t> ds_mods_cache;
				static std::vector<shell_thread_info_t>  ds_threads_cache;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
				static long long                                  ds_mods_last_ms = 0;
				static long long                                  ds_threads_last_ms = 0;
				static uint32_t                                   ds_mods_cache_pid = 0;
				static uint32_t                                   ds_threads_cache_pid = 0;
				static std::shared_mutex                          ds_mods_mu;
				static std::shared_mutex                          ds_threads_mu;
				static std::atomic<bool>                          ds_mods_in_flight{false};
				static std::atomic<bool>                          ds_threads_in_flight{false};
				long long _ds_now_ms = static_cast<long long>(aida::shell_platform::tick_ms());
#endif
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				if (ds_mods_cache.empty()) ds_mods_cache = aida::preview::modules();
				if (ds_threads_cache.empty()) ds_threads_cache = aida::preview::threads();
				drv_tab = aida::preview::controls().driver_tab;
#endif
				ImGuiTabItemFlags modules_tab_flags = ImGuiTabItemFlags_None;
				ImGuiTabItemFlags threads_tab_flags = ImGuiTabItemFlags_None;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				modules_tab_flags = drv_tab == 0 ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
				threads_tab_flags = drv_tab == 1 ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
#endif
				if (ImGui::BeginTabBar("##drv_tabs")) {
					if (ImGui::BeginTabItem("Modules", nullptr, modules_tab_flags)) {
						drv_tab = 0;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
						uint32_t cur_pid = driver_bridge::attached_pid();
						bool need_refresh = false;
						{
							std::shared_lock<std::shared_mutex> lk(ds_mods_mu);
							if (ds_mods_cache_pid != cur_pid || (_ds_now_ms - ds_mods_last_ms) >= 2000)
								need_refresh = true;
						}
						if (need_refresh) {
							bool expected = false;
							if (ds_mods_in_flight.compare_exchange_strong(expected, true)) {
								const auto submit_result = submit_helpers_executor_task(
									"driver_state",
									"driver_state.enumerate_modules",
									aida::infra::executor::domain_t::feature_worker,
									"bounded_task",
									[cur_pid]() {
									std::vector<driver_bridge::module_info_t> fresh;
									try {
										fresh = driver_bridge::enumerate_modules();
									} catch (...) {
										fresh.clear();
									}
									{
										std::unique_lock<std::shared_mutex> lk(ds_mods_mu);
										ds_mods_cache = std::move(fresh);
										ds_mods_cache_pid = cur_pid;
										ds_mods_last_ms = static_cast<long long>(aida::shell_platform::tick_ms());
									}
									ds_mods_in_flight.store(false);
								});
								if (!submit_result.submitted)
									ds_mods_in_flight.store(false);
							}
						}
#endif
						std::vector<shell_module_info_t> mods_view;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						mods_view = ds_mods_cache;
#else
						{
							std::shared_lock<std::shared_mutex> lk(ds_mods_mu);
							mods_view = ds_mods_cache;
						}
#endif
						ImGui::BeginChild("##mod_list", ImVec2(-1, sh - 180.f));
						ImGuiListClipper clipper;
						clipper.Begin(static_cast<int>(mods_view.size()));
						while (clipper.Step()) {
							for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
								auto& m = mods_view[static_cast<std::size_t>(i)];
								ImGui::Text("0x%llX  %s", (unsigned long long)m.base, m.name.c_str());
							}
						}
						clipper.End();
						ImGui::EndChild();
						ImGui::EndTabItem();
					}
					if (ImGui::BeginTabItem("Threads", nullptr, threads_tab_flags)) {
						drv_tab = 1;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
						uint32_t cur_pid = driver_bridge::attached_pid();
						bool need_refresh = false;
						{
							std::shared_lock<std::shared_mutex> lk(ds_threads_mu);
							if (ds_threads_cache_pid != cur_pid || (_ds_now_ms - ds_threads_last_ms) >= 2000)
								need_refresh = true;
						}
						if (need_refresh) {
							bool expected = false;
							if (ds_threads_in_flight.compare_exchange_strong(expected, true)) {
								const auto submit_result = submit_helpers_executor_task(
									"driver_state",
									"driver_state.enumerate_threads",
									aida::infra::executor::domain_t::feature_worker,
									"bounded_task",
									[cur_pid]() {
									std::vector<driver_bridge::thread_info_t> fresh;
									try {
										fresh = driver_bridge::enumerate_threads();
									} catch (...) {
										fresh.clear();
									}
									{
										std::unique_lock<std::shared_mutex> lk(ds_threads_mu);
										ds_threads_cache = std::move(fresh);
										ds_threads_cache_pid = cur_pid;
										ds_threads_last_ms = static_cast<long long>(aida::shell_platform::tick_ms());
									}
									ds_threads_in_flight.store(false);
								});
								if (!submit_result.submitted)
									ds_threads_in_flight.store(false);
							}
						}
#endif
						std::vector<shell_thread_info_t> threads_view;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
						threads_view = ds_threads_cache;
#else
						{
							std::shared_lock<std::shared_mutex> lk(ds_threads_mu);
							threads_view = ds_threads_cache;
						}
#endif
						ImGui::BeginChild("##thr_list", ImVec2(-1, sh - 180.f));
						ImGuiListClipper clipper;
						clipper.Begin(static_cast<int>(threads_view.size()));
						while (clipper.Step()) {
							for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
								auto& t = threads_view[static_cast<std::size_t>(i)];
								ImGui::Text("TID %u  Priority %d", (unsigned)t.tid, t.priority);
							}
						}
						clipper.End();
						ImGui::EndChild();
						ImGui::EndTabItem();
					}
					ImGui::EndTabBar();
				}
			}

			ImGui::Spacing();
			float btn_w = 80.f;
			if (is_attached) {
				if (aida::ui::components::button("Detach",
					aida::ui::components::button_kind_t::destructive,
					aida::ui::components::size_t_::md,
					ImVec2(btn_w, 26.f))) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
					aida::preview::detach_process();
#else
					driver_bridge::detach();
#endif
				}
				ImGui::SameLine();
			}
			if (aida::ui::components::button("Close",
				aida::ui::components::button_kind_t::secondary,
				aida::ui::components::size_t_::md,
				ImVec2(btn_w, 26.f))) {
				ds_closing = true;
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}


	static int kb_open_frame = -1;
	static float kb_anim = 0.f;
	static bool kb_closing = false;
	static char kb_filter_buf[128] = {0};
	static bool kb_was_open = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static std::uint64_t preview_shortcuts_revision = 0;
	if (preview_shortcuts_revision != aida::preview::controls().revision) {
		preview_shortcuts_revision = aida::preview::controls().revision;
		kb_closing = false;
		kb_anim = aida::preview::controls().shortcuts_dialog_open && aida::preview::controls().settle_animations ? 1.f : 0.f;
	}
#endif

	{
		float dt_kb = ImGui::GetIO().DeltaTime;
		float kb_target = (globals::ui::shortcuts_dialog_open && !kb_closing) ? 1.f : 0.f;
		#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		if (aida::preview::controls().settle_animations) kb_anim = kb_target;
		else
		#endif
		kb_anim += (kb_target - kb_anim) * (std::min)(dt_kb * 14.f, 1.f);
		if (std::abs(kb_anim - kb_target) < 0.003f) kb_anim = kb_target;

		bool now_open = globals::ui::shortcuts_dialog_open;
		if (now_open && !kb_was_open) {
			kb_filter_buf[0] = '\0';
			anti_tamper::webhook::write_log("chrome", "shortcuts_popup open=true");
		} else if (!now_open && kb_was_open) {
			anti_tamper::webhook::write_log("chrome", "shortcuts_popup open=false");
		}
		kb_was_open = now_open;

		if (kb_closing && kb_anim < 0.01f) {
			kb_closing = false;
			globals::ui::shortcuts_dialog_open = false;
			kb_open_frame = -1;
			kb_anim = 0.f;
		}
	}

	g_render_section = "popups_shortcuts";
	if (globals::ui::shortcuts_dialog_open || kb_anim > 0.005f) {
		if (kb_open_frame < 0) kb_open_frame = ImGui::GetFrameCount();

		ImVec2 vp = ImGui::GetIO().DisplaySize;

		float pw = 640.f, ph = 540.f;
		float kb_scale = 0.96f + 0.04f * kb_anim;
		float sw = pw * kb_scale, sh = ph * kb_scale;
		float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;

		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !kb_closing)
			kb_closing = true;

		if (ImGui::GetFrameCount() > kb_open_frame + 1 && !kb_closing &&
			ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ImVec2 mp = ImGui::GetIO().MousePos;
			if (mp.x < px || mp.x > px + sw || mp.y < py || mp.y > py + sh)
				kb_closing = true;
		}

		ImGui::SetNextWindowPos(ImVec2(px, py));
		ImGui::SetNextWindowSize(ImVec2(sw, sh));
		ImGui::SetNextWindowFocus();
		const auto& th_kb = aida::ui::resolved();
		ImGui::PushStyleColor(ImGuiCol_WindowBg, aida::ui::with_alpha(th_kb.bg_elevated, kb_anim * 0.96f));
		ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(th_kb.border_strong, kb_anim));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 14));

		ImGui::Begin("Keyboard Shortcuts##kb_dlg", nullptr,
				ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
		{
			ImVec2 wpos = ImGui::GetWindowPos();
			ImVec2 wsize = ImGui::GetWindowSize();
			ImDrawList* kb_dl = ImGui::GetWindowDrawList();

			ImU32 accent_top = aida::ui::with_alpha(th_kb.accent_grad_top, 0.85f * kb_anim);
			ImU32 accent_bot = aida::ui::with_alpha(th_kb.accent_grad_bot, 0.0f * kb_anim);
			kb_dl->AddRectFilledMultiColor(
				ImVec2(wpos.x, wpos.y),
				ImVec2(wpos.x + wsize.x, wpos.y + 3.f),
				accent_top, accent_top, accent_bot, accent_bot);

			float close_sz = 22.f;
			float close_x0 = wpos.x + wsize.x - close_sz - 14.f;
			float close_y0 = wpos.y + 12.f;
			float close_x1 = close_x0 + close_sz;
			float close_y1 = close_y0 + close_sz;
			bool close_hov = ImGui::IsMouseHoveringRect(
				ImVec2(close_x0, close_y0), ImVec2(close_x1, close_y1), false);
			if (close_hov) {
				kb_dl->AddRectFilled(
					ImVec2(close_x0, close_y0), ImVec2(close_x1, close_y1),
					aida::ui::with_alpha(th_kb.error, 0.32f * kb_anim), 4.f);
			}
			ImU32 close_col = aida::ui::with_alpha(
				close_hov ? th_kb.text_primary : th_kb.text_secondary, kb_anim);
			float ccx = (close_x0 + close_x1) * 0.5f;
			float ccy = (close_y0 + close_y1) * 0.5f;
			float crr = 5.f;
			kb_dl->AddLine(ImVec2(ccx - crr, ccy - crr), ImVec2(ccx + crr, ccy + crr), close_col, 1.6f);
			kb_dl->AddLine(ImVec2(ccx + crr, ccy - crr), ImVec2(ccx - crr, ccy + crr), close_col, 1.6f);
			if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				kb_closing = true;

			ImGui::PushFont(ImGui::GetFont());
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
				aida::ui::with_alpha(th_kb.text_primary, kb_anim)),
				"Keyboard Shortcuts");
			ImGui::PopFont();
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
				aida::ui::with_alpha(th_kb.text_secondary, 0.8f * kb_anim)),
				"Press ESC to close. Type to filter.");
			ImGui::Spacing();

			float ax_f = globals::ui::accent.x;
			float ay_f = globals::ui::accent.y;
			float az_f = globals::ui::accent.z;
			ui_anim::render_filter_input_chip(
				"##kb_filter", kb_filter_buf, sizeof(kb_filter_buf),
				"Search shortcuts...", wsize.x - 56.f,
				ax_f, ay_f, az_f, kb_anim);

			ImGui::Spacing();

			auto str_lower = [](const char* s) -> std::string {
				std::string out;
				out.reserve(s ? std::strlen(s) : 0);
				if (s) {
					for (const char* p = s; *p; ++p) {
						char c = *p;
						if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
						out.push_back(c);
					}
				}
				return out;
			};
			std::string filter_lower = str_lower(kb_filter_buf);
			bool has_filter = !filter_lower.empty();
			const auto shortcuts = aida::ui::application_ui::list_shortcuts();

			ImGui::BeginChild("##kb_scroll",
				ImVec2(-1, sh - 130.f), false, ImGuiWindowFlags_HorizontalScrollbar);

			int total_visible = 0;
			std::string active_category;
			for (std::size_t index = 0; index < shortcuts.size(); ++index) {
				const auto& shortcut = shortcuts[index];
				bool visible = true;
				if (has_filter) {
					const std::string category_lower = str_lower(shortcut.category.c_str());
					const std::string keys_lower = str_lower(shortcut.shortcut.c_str());
					const std::string label_lower = str_lower(shortcut.label.c_str());
					const std::string scope_lower = str_lower(shortcut.scope.c_str());
					visible = category_lower.find(filter_lower) != std::string::npos ||
						keys_lower.find(filter_lower) != std::string::npos ||
						label_lower.find(filter_lower) != std::string::npos ||
						scope_lower.find(filter_lower) != std::string::npos;
				}
				if (!visible)
					continue;
				++total_visible;
				if (active_category != shortcut.category) {
					active_category = shortcut.category;
					ImGui::Spacing();
					ImVec2 hcp = ImGui::GetCursorScreenPos();
					ImDrawList* idl = ImGui::GetWindowDrawList();
					idl->AddRectFilled(ImVec2(hcp.x, hcp.y + 6.f), ImVec2(hcp.x + 3.f, hcp.y + 18.f),
						aida::ui::with_alpha(th_kb.accent_u32, kb_anim), 1.f);
					ImGui::Dummy(ImVec2(8.f, 0.f));
					ImGui::SameLine();
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
						aida::ui::with_alpha(th_kb.text_primary, 0.94f * kb_anim)), "%s", active_category.c_str());
					ImVec2 sep_pos = ImGui::GetCursorScreenPos();
					float row_inner_w = ImGui::GetContentRegionAvail().x;
					idl->AddLine(ImVec2(sep_pos.x, sep_pos.y + 2.f), ImVec2(sep_pos.x + row_inner_w, sep_pos.y + 2.f),
						aida::ui::with_alpha(th_kb.border_subtle, 0.6f * kb_anim), 1.f);
					ImGui::Dummy(ImVec2(0.f, 6.f));
				}

				ImDrawList* idl = ImGui::GetWindowDrawList();
				ImVec2 rcp = ImGui::GetCursorScreenPos();
				float row_h_k = 30.f;
				float row_w = ImGui::GetContentRegionAvail().x;
				bool row_hov = ImGui::IsMouseHoveringRect(rcp, ImVec2(rcp.x + row_w, rcp.y + row_h_k), false);
				if (row_hov)
					idl->AddRectFilled(ImVec2(rcp.x - 2.f, rcp.y), ImVec2(rcp.x + row_w, rcp.y + row_h_k),
						aida::ui::with_alpha(th_kb.hover_wash, 0.5f * kb_anim), 4.f);
				const ImU32 label_color = shortcut.enabled ? th_kb.text_primary : th_kb.text_dim;
				idl->AddText(ImVec2(rcp.x + 6.f, rcp.y + 3.f),
					aida::ui::with_alpha(label_color, 0.92f * kb_anim), shortcut.label.c_str());
				std::string metadata = shortcut.scope;
				if (shortcut.conflict)
					metadata += " / Conflict";
				idl->AddText(ImVec2(rcp.x + 6.f, rcp.y + 16.f),
					aida::ui::with_alpha(shortcut.conflict ? th_kb.warning : th_kb.text_dim, 0.82f * kb_anim),
					metadata.c_str());
				ImVec2 chip_ts = ImGui::CalcTextSize(shortcut.shortcut.c_str());
				float chip_w_est = chip_ts.x + 12.f;
				float chip_x = rcp.x + row_w - chip_w_est - 6.f;
				float chip_y = rcp.y + (row_h_k - (chip_ts.y + 4.f)) * 0.5f;
				ui_anim::render_kbd_chip(idl, chip_x, chip_y, shortcut.shortcut.c_str(), kb_anim);
				ImGui::Dummy(ImVec2(row_w, row_h_k));
				if (row_hov && !shortcut.enabled && !shortcut.disabled_reason.empty())
					ImGui::SetTooltip("%s", shortcut.disabled_reason.c_str());
			}

			if (has_filter && total_visible == 0) {
				ImGui::Spacing();
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
					aida::ui::with_alpha(th_kb.text_dim, 0.85f * kb_anim)),
					"No shortcuts match \"%s\".", kb_filter_buf);
			}

			ImGui::EndChild();

			ImGui::Spacing();
			ImGui::Separator();
			ImGui::Spacing();
			if (aida::ui::components::button("Close",
				aida::ui::components::button_kind_t::secondary,
				aida::ui::components::size_t_::md,
				ImVec2(96.f, 26.f))) {
				kb_closing = true;
			}
		}
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
	}

	g_render_section = "popups_initial_analysis";
	initial_analysis_view::render_frame(active_workspace_context);

	g_render_section = "popups_loading_binary";
	loading_binary_overlay::render();

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	g_render_section = "popups_test_all_features";
	{
		ImGuiIO& io_ta = ImGui::GetIO();
		test_all_features::render_overlay(io_ta.DisplaySize.x, io_ta.DisplaySize.y);
	}
#endif

	g_render_section = "popups_open_binary_confirm";
	file_browser::render_pending_confirm_modal();

	g_render_section = "popups_tool_approval";
	render_tool_approval_dialog();

	g_render_section = "popups_chat_select_text";
	if (chat_select_popup::open) {
		ImGuiIO& io_cs = ImGui::GetIO();
		ImVec2 vp_cs = io_cs.DisplaySize;
		float pw_cs = std::min(820.f, vp_cs.x - 80.f);
		float ph_cs = std::min(640.f, vp_cs.y - 80.f);
		ImGui::SetNextWindowSize(ImVec2(pw_cs, ph_cs), ImGuiCond_Appearing);
		ImGui::SetNextWindowPos(ImVec2((vp_cs.x - pw_cs) * 0.5f, (vp_cs.y - ph_cs) * 0.5f),
			ImGuiCond_Appearing);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.f, 14.f));
		const auto& th_cs = aida::ui::resolved();
		ImGui::PushStyleColor(ImGuiCol_WindowBg, aida::ui::with_alpha(th_cs.bg_elevated, 0.98f));
		ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(th_cs.border_strong, 1.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(th_cs.panel_bg, 1.f));
		bool stay_open = true;
		ImGuiWindowFlags chat_select_window_flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings;
#if defined(IMGUI_HAS_DOCK)
		chat_select_window_flags |= ImGuiWindowFlags_NoDocking;
#endif
		if (ImGui::Begin("Select & Copy Text##aida_chat_select_popup", &stay_open,
				chat_select_window_flags)) {
			ImGui::TextWrapped("Drag to select. Ctrl+C to copy. Ctrl+A selects all.");
			ImGui::Separator();
			float avail_y = ImGui::GetContentRegionAvail().y - 44.f;
			if (avail_y < 80.f) avail_y = 80.f;
			static std::vector<char> sel_buf;
			if (sel_buf.size() < chat_select_popup::text.size() + 1) {
				sel_buf.assign(chat_select_popup::text.size() + 64, 0);
				std::memcpy(sel_buf.data(), chat_select_popup::text.data(), chat_select_popup::text.size());
				sel_buf[chat_select_popup::text.size()] = '\0';
			}
			ImGui::InputTextMultiline("##chat_select_buf",
				sel_buf.data(), sel_buf.size(),
				ImVec2(-1.f, avail_y),
				ImGuiInputTextFlags_ReadOnly);
			ImGui::Spacing();
			if (ImGui::Button("Copy All", ImVec2(120.f, 30.f))) {
				ImGui::SetClipboardText(chat_select_popup::text.c_str());
				toast_notification::push("Message copied to clipboard",
					toast_notification::toast_type_t::info, 2.5f);
			}
			ImGui::SameLine();
			if (ImGui::Button("Close", ImVec2(120.f, 30.f))) {
				stay_open = false;
			}
		}
		ImGui::End();
		ImGui::PopStyleColor(3);
		ImGui::PopStyleVar(2);
		if (!stay_open) {
			chat_select_popup::open = false;
			chat_select_popup::text.clear();
		}
	}

	ImGui::PopStyleVar();
	ImGui::End();
	g_render_section = "done";
}
