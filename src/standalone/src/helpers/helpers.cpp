#include "helpers.h"
#include "globals.h"
#include "diag_log.hpp"
#include "win32_dialog.hpp"
#include "toast_notification.hpp"
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <fstream>
#include <filesystem>
#include <map>
#include <unordered_set>
#include <algorithm>
#include <iostream>
#include <string>
#include <cstring>
#include <atomic>
#include <thread>
#include <chrono>
#include <exception>
#include <nlohmann/json.hpp>
#include "blur.h"
#include "../assets/icons.h"
#include "../ide_icons.h"
#include "zydis_disasm.hpp"
#include "standalone_chat.hpp"
#include "standalone_license.hpp"
#include "anti-tamper/orchestrator.hpp"
#include "anti-tamper/webhook.hpp"
#include "standalone_settings.hpp"
#include "code_editor.hpp"
#include "disasm_view.hpp"
#include "cfg_view.hpp"
#include "hex_view.hpp"
#include "image_view.hpp"
#include "chat_render.hpp"
#include "standalone_driver.hpp"
#include "mcp_client.hpp"
#include "../core/auth/auth_browser_launch.hpp"
#include "sandbox.hpp"
#include "workspace_search.hpp"
#include "terminal_view.hpp"
#include "network_view.hpp"
#include "debugger_view.hpp"
#include "debugger_engine.hpp"
#include "spawn_target_dialog.hpp"
#include "../core/session/session_health.hpp"
#include "run_target.hpp"
#include "pseudocode_view.hpp"
#include "scan_hub_view.hpp"
#include "types_hub_view.hpp"
#include "analysis_hub_view.hpp"
#include "source_reconstruct_view.hpp"
#include "work_queue.hpp"
#include "critical_work_queue.hpp"
#include "functions_panel.hpp"
#include "function_index.hpp"
#include "xref_index.hpp"
#include "xref_db.hpp"
#include "binary_map_view.hpp"
#include "../core/testlab/test_lab_view.hpp"
#include "../core/testlab/test_all_features.hpp"
#include "../core/testlab/test_all_ui.h"
#include "../core/network/burp/camoufox_bridge.hpp"
#include "ui_anim.hpp"
#include "agent_picker_view.hpp"
#include "mcp_marketplace_view.hpp"
#include "initial_analysis.hpp"
#include "initial_analysis_view.hpp"
#include "loading_binary_overlay.hpp"
#include "analysis_session.hpp"
#include "empty_state.hpp"
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>

static ID3D11ShaderResourceView* g_loader_icon_srv  = nullptr;
static int                        g_loader_icon_w    = 0;
static int                        g_loader_icon_h    = 0;
DisasmState                       g_disasm;
render_section_state_t            g_render_section;

namespace test_all_features {
	void format_ui_phase_snapshot(char* out, std::size_t cap);
}

namespace {
	std::atomic<bool>          g_settings_dirty{false};
	std::condition_variable    g_settings_cv;
	std::mutex                 g_settings_cv_mtx;
	std::atomic<bool>          g_settings_saver_running{false};
	std::atomic<bool>          g_settings_saver_started{false};
	std::atomic<bool>          g_chrome_shutdown_requested{false};

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

	void g_sa_settings_request_save()
	{
		g_settings_dirty.store(true);
		bool expected = false;
		if (g_settings_saver_started.compare_exchange_strong(expected, true)) {
			g_settings_saver_running.store(true);
			if (!work_queue::post([]() { settings_saver_loop(); })) {
				g_settings_saver_running.store(false);
				g_settings_saver_started.store(false);
			}
		}
		g_settings_cv.notify_one();
	}

	void log_license_screen_breadcrumb(const char* event, float window_w, float window_h, bool runtime_ready, bool runtime_locked)
	{
		const std::string run_id = standalone_license::run_correlation_id();
		const std::string runtime_snapshot = standalone_license::runtime_state_snapshot();
		auto dyn = driver_bridge::dynamic_ioctl_state();
		auto wq = work_queue::stats();
		auto swq = work_queue::service_stats();
		auto cwq = critical_work_queue::stats();
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
			static_cast<unsigned long long>(GetTickCount64()),
			::GetCurrentThreadId(),
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
			"%s_queues run_id=%s frame=%d work_alive=%d work_pending=%zu work_active=%u work_oldest_ms=%llu work_labels=%.220s svc_alive=%d svc_pending=%zu svc_active=%u svc_oldest_ms=%llu svc_labels=%.220s critical_alive=%d critical_pending=%zu critical_active=%u critical_oldest_ms=%llu critical_labels=%.220s",
			breadcrumb_event,
			run_id.c_str(),
			ImGui::GetFrameCount(),
			wq.alive ? 1 : 0,
			wq.pending,
			wq.active,
			static_cast<unsigned long long>(wq.oldest_active_ms),
			wq.active_labels.c_str(),
			swq.alive ? 1 : 0,
			swq.pending,
			swq.active,
			static_cast<unsigned long long>(swq.oldest_active_ms),
			swq.active_labels.c_str(),
			cwq.alive ? 1 : 0,
			cwq.pending,
			cwq.active,
			static_cast<unsigned long long>(cwq.oldest_active_ms),
			cwq.active_labels.c_str());
	}

	void request_chrome_shutdown_from_render(const char* source, const char* cleanup_reason)
	{
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
			::GetCurrentThreadId(),
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
	}

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
		}
		return "unknown";
	}

	void mark_center_render_section(const char* section, center_view_t view, bool overlay_blocking, float vw, float vh)
	{
		g_render_section = section;
		static std::atomic<unsigned long long> s_last_log_ms{0};
		static std::atomic<int> s_last_view{-1000000};
		static std::atomic<int> s_last_full_test{-1};
		const unsigned long long now = GetTickCount64();
		const int view_raw = static_cast<int>(view);
		const bool full_test = test_all_features::is_running();
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
				static_cast<unsigned long>(GetCurrentThreadId()));
		}
	}

	void log_bottom_panel_lock_busy(const char* op, int tab, unsigned long long known_version, size_t cached_lines, size_t total_lines)
	{
		static std::atomic<unsigned long long> s_last_log_ms{0};
		static std::atomic<unsigned long long> s_busy_count{0};
		const unsigned long long now = GetTickCount64();
		unsigned long long count = s_busy_count.fetch_add(1, std::memory_order_acq_rel) + 1ULL;
		unsigned long long last = s_last_log_ms.load(std::memory_order_acquire);
		if (count != 1ULL && now - last < 500ULL)
			return;
		if (count != 1ULL && !s_last_log_ms.compare_exchange_strong(last, now, std::memory_order_acq_rel))
			return;
		unsigned long owner_tid = 0;
		unsigned long long owner_age = 0;
		int owner_tab = -1;
		int owner_op = 0;
		output_log::snapshot_owner(owner_tid, owner_age, owner_tab, owner_op);
		diag::log_tagged_fmt("ui",
			"BOTTOM_PANEL_LOCK_BUSY op=%s tab=%d known_version=%llu cached=%zu total=%zu busy_count=%llu owner_tid=%lu owner_age_ms=%llu owner_tab=%d owner_op=%s owner_op_id=%d frame=%d section=%s tid=%lu",
			op ? op : "<null>",
			tab,
			known_version,
			cached_lines,
			total_lines,
			count,
			owner_tid,
			owner_age,
			owner_tab,
			output_log::op_name(owner_op),
			owner_op,
			ImGui::GetFrameCount(),
			g_render_section.c_str(),
			static_cast<unsigned long>(GetCurrentThreadId()));
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
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return win32_dialog::show_open_file_dialog(owner, title, filter_pairs,
		out_path, out_path_capacity, caller_name);
}

static bool trusted_show_save_file(HWND owner,
	const char* title,
	const char* filter_pairs,
	const char* default_ext,
	char* out_path,
	size_t out_path_capacity,
	const char* caller_name)
{
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return win32_dialog::show_save_file_dialog(owner, title, filter_pairs, default_ext,
		out_path, out_path_capacity, caller_name);
}

static bool trusted_show_folder(HWND owner,
	const wchar_t* title,
	std::string& out_path,
	const char* caller_name)
{
	anti_tamper::token_chain::trusted_interaction_scope_t trusted_scope;
	return win32_dialog::show_open_folder_dialog(owner, title, out_path, caller_name);
}

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

	static std::atomic<bool>& result_ready()
	{
		static std::atomic<bool> value{ false };
		return value;
	}

	static std::mutex& result_mutex()
	{
		static std::mutex value;
		return value;
	}

	static result_t& result_state()
	{
		static result_t value;
		return value;
	}

	static void store_result(action_t action, bool ok, std::string path)
	{
		{
			std::lock_guard<std::mutex> lock(result_mutex());
			result_state() = result_t{ action, ok, std::move(path) };
		}
		result_ready().store(true, std::memory_order_release);
	}

	static void request(action_t action)
	{
		pending_action().store(static_cast<int>(action), std::memory_order_release);
		diag::log_tagged_fmt("file_dialog", "deferred_request action=%d active=%d", static_cast<int>(action), active().load(std::memory_order_acquire) ? 1 : 0);
	}

	static void run_pending()
	{
		if (result_ready().exchange(false, std::memory_order_acq_rel)) {
			result_t result;
			{
				std::lock_guard<std::mutex> lock(result_mutex());
				result = std::move(result_state());
				result_state() = {};
			}

			if (result.action == action_t::open_file) {
				if (result.ok && !result.path.empty()) {
					diag::log_tagged_fmt("file_dialog", "deferred_open_file picked path=%.260s", result.path.c_str());
					file_browser::open_path(result.path);
				} else {
					diag::log_tagged_critical("file_dialog", "deferred_open_file cancelled_or_failed");
				}
				diag::log_tagged_critical("file_dialog", "deferred_open_file end");
			} else if (result.action == action_t::open_folder) {
				if (result.ok && !result.path.empty()) {
					file_browser::refresh(result.path);
					g_sa_settings.workspace.root_path = result.path;
					g_sa_settings_request_save();
					diag::log_tagged_fmt("file_dialog", "deferred_open_folder picked path=%.260s", result.path.c_str());
				} else {
					diag::log_tagged_critical("file_dialog", "deferred_open_folder cancelled_or_failed");
				}
				diag::log_tagged_critical("file_dialog", "deferred_open_folder end");
			}
		}

		if (active().load(std::memory_order_acquire))
			return;

		int raw = pending_action().exchange(static_cast<int>(action_t::none), std::memory_order_acq_rel);
		action_t action = static_cast<action_t>(raw);
		if (action == action_t::none)
			return;

		active().store(true, std::memory_order_release);
		auto task = [action]() {
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
					store_result(action, ok, ok ? std::string(buf) : std::string());
					diag::log_tagged_fmt("file_dialog", "deferred_open_file worker_end ok=%d", ok ? 1 : 0);
				} else if (action == action_t::open_folder) {
					diag::log_tagged_critical("file_dialog", "deferred_open_folder worker_begin");
					std::string folder;
					bool ok = trusted_show_folder(nullptr,
						L"Open Workspace Folder",
						folder,
						"workspace_open_folder");
					store_result(action, ok, ok ? folder : std::string());
					diag::log_tagged_fmt("file_dialog", "deferred_open_folder worker_end ok=%d", ok ? 1 : 0);
				} else {
					store_result(action_t::none, false, {});
				}
			} catch (const std::exception& ex) {
				diag::log_tagged_fmt("file_dialog", "deferred_worker exception=%s", ex.what());
				store_result(action, false, {});
			} catch (...) {
				diag::log_tagged_critical("file_dialog", "deferred_worker unknown_exception");
				store_result(action, false, {});
			}
			active().store(false, std::memory_order_release);
		};
		bool queued = false;
		try {
			queued = work_queue::post(std::move(task));
		} catch (const std::exception& ex) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_fmt("file_dialog", "deferred_post exception=%s", ex.what());
			store_result(action, false, {});
			return;
		} catch (...) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_critical("file_dialog", "deferred_post unknown_exception");
			store_result(action, false, {});
			return;
		}
		if (!queued) {
			active().store(false, std::memory_order_release);
			diag::log_tagged_critical("file_dialog", "deferred_post failed");
			store_result(action, false, {});
		}
	}
}

static bool has_any_target()
{
	return analysis_session::session_count() > 0
	    || driver_bridge::attached_pid() != 0
	    || g_disasm.file.loaded;
}

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



ID3D11ShaderResourceView* helpers::theme_rias = nullptr;
ID3D11ShaderResourceView* helpers::theme_nagi = nullptr;
ID3D11ShaderResourceView* helpers::theme_mio = nullptr;
ID3D11ShaderResourceView* helpers::theme_kaneki = nullptr;
bool helpers::themes_loaded = false;


extern unsigned char background[];
extern unsigned char aidalogo[];
static ID3D11ShaderResourceView* g_bg_art_srv = nullptr;
static int g_bg_art_w = 0, g_bg_art_h = 0;
static bool g_bg_art_loaded = false;
static ID3D11ShaderResourceView* g_aida_logo_srv = nullptr;
static int g_aida_logo_w = 0, g_aida_logo_h = 0;
static bool g_aida_logo_loaded = false;

static int g_theme_icon_w[4] = {}, g_theme_icon_h[4] = {};
static ID3D11ShaderResourceView* g_custom_theme_icon_srv = nullptr;
static int g_custom_theme_icon_w = 0;
static int g_custom_theme_icon_h = 0;
static std::string g_custom_theme_icon_path;

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
	ImGuiID anim_id = 1000 + index;
	ImGuiID hover_id = 3000 + index;

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
			float spread = i * 3.0f;
			dl->AddRectFilled(
				ImVec2(tab_min.x - spread, tab_min.y - spread),
				ImVec2(tab_max.x + spread, tab_max.y + spread),
				aida::ui::with_alpha(th.accent_glow, 0.08f * t * (5 - i)),
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
	dl->AddRectFilled(r_min, r_max, IM_COL32(pr, pg, pb, (int)(pa * alpha)), 8.f);

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
	float btn_w     = (avail_w - spacing * (count - 1)) / count;
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
	float btn_w     = (avail_w - spacing * (count - 1)) / count;
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
			float oy = btn_min.y + 3.0f + i * opt_h;
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
#include <shlobj.h>

std::string conversations::get_storage_dir()
{
	wchar_t* appdata = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
		auto p = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"conversations";
		CoTaskMemFree(appdata);
		std::filesystem::create_directories(p);
		return p.string();
	}
	return {};
}

void conversations::save_current()
{
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
}

void conversations::load_conversation(const std::string& id)
{
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
}

void conversations::delete_conversation(const std::string& id)
{
	std::string dir = get_storage_dir();
	if (dir.empty()) return;
	std::string path = dir + "\\" + id + ".json";
	std::filesystem::remove(path);
	refresh_history();
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
					anti_tamper::webhook::write_log("file_dialog", "session_tab_plus left_click open_file_dialog");
					std::string fpath = disasm::open_file_dialog(g_hwnd);
					if (!fpath.empty()) {
						anti_tamper::webhook::write_log("file_dialog", (std::string("session_tab_plus open_file_dialog ok path=") + fpath).c_str());
						analysis_session::open_session(fpath);
					} else {
						anti_tamper::webhook::write_log("file_dialog", "session_tab_plus open_file_dialog cancelled_or_empty");
					}
				} else if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
					globals::ui::process_attach_open = true;
				} else if (ImGui::IsMouseClicked(ImGuiMouseButton_Middle)) {
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
		const analysis_session::analysis_session_t* sess = analysis_session::session_at(i);
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
					anti_tamper::webhook::write_log("file_dialog", "session_tab_plus(open) left_click");
					std::string fpath = disasm::open_file_dialog(g_hwnd);
					if (!fpath.empty()) {
						anti_tamper::webhook::write_log("file_dialog", (std::string("session_tab_plus(open) ok path=") + fpath).c_str());
						analysis_session::open_session(fpath);
					} else {
						anti_tamper::webhook::write_log("file_dialog", "session_tab_plus(open) cancelled");
					}
				} else if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
					globals::ui::process_attach_open = true;
				} else if (ImGui::IsMouseClicked(ImGuiMouseButton_Middle)) {
					spawn_target_dialog::request_open();
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
			const auto* sess = analysis_session::session_at(static_cast<size_t>(ctx_idx));
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
		const analysis_session::analysis_session_t* sw_sess = analysis_session::session_at(sw_idx);
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
			if (g_disasm.file.loaded) {
				globals::ui::active_center_view = center_view_t::disassembly;
			}
		}
	} else if (reattach_intent >= 0) {
		analysis_session::close_session(static_cast<size_t>(reattach_intent));
		globals::ui::process_attach_open = true;
	}
}

void helpers::render_title()
{
	g_render_section = "entry";
	float dt = ImGui::GetIO().DeltaTime;
	globals::ui::load_timer += dt;
	file_menu_deferred::run_pending();

	static bool bg_completed = false;
	static float bg_completed_at = 0.f;
	if (!bg_completed && globals::ui::bg_init_done && globals::ui::bg_init_done->load(std::memory_order_acquire)) {
		bg_completed = true;
		bg_completed_at = globals::ui::load_timer;
	}

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
				work_queue::post([] {
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

	g_render_section = "theme_resolve";
	if (custom_themes::active_custom >= 0 &&
	    custom_themes::active_custom < (int)custom_themes::list.size()) {
		auto& ct = custom_themes::list[custom_themes::active_custom];
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
	globals::ui::accent = aida::ui::resolved().accent;

	{
		static int s_last_applied_theme_idx = -1;
		static int s_last_applied_custom_idx = -2;
		int target_custom = custom_themes::active_custom;
		int target_idx = themes::active;
		if (target_custom != s_last_applied_custom_idx || target_idx != s_last_applied_theme_idx) {
			bool first_apply = (s_last_applied_theme_idx == -1 && s_last_applied_custom_idx == -2);
			s_last_applied_custom_idx = target_custom;
			s_last_applied_theme_idx  = target_idx;
			if (target_custom >= 0 && target_custom < (int)custom_themes::list.size()) {
				auto& ct = custom_themes::list[target_custom];
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
				aida::ui::apply_for_index(target_idx, !first_apply);
			}
		}
	}
	globals::ui::accent = aida::ui::resolved().accent;

	const auto& shell_theme = aida::ui::resolved();
	const int th_ph_r = (shell_theme.panel_header >>  0) & 0xFF;
	const int th_ph_g = (shell_theme.panel_header >>  8) & 0xFF;
	const int th_ph_b = (shell_theme.panel_header >> 16) & 0xFF;
	const int th_pb_r = (shell_theme.panel_bg >>  0) & 0xFF;
	const int th_pb_g = (shell_theme.panel_bg >>  8) & 0xFF;
	const int th_pb_b = (shell_theme.panel_bg >> 16) & 0xFF;
	const int th_bb_r = (shell_theme.bg_base >>  0) & 0xFF;
	const int th_bb_g = (shell_theme.bg_base >>  8) & 0xFF;
	const int th_bb_b = (shell_theme.bg_base >> 16) & 0xFF;


	chat_handle_agent_shortcuts();


	if (!ImGui::GetIO().WantTextInput) {
		bool ctrl  = ImGui::GetIO().KeyCtrl;
		bool shift = ImGui::GetIO().KeyShift;

		if (ImGui::IsKeyPressed(ImGuiKey_F11, false)) {
			globals::ui::maximized = !globals::ui::maximized;
			if (globals::ui::maximized) {
				RECT r; GetWindowRect(g_hwnd, &r);
				globals::ui::pre_max_x = (float)r.left;
				globals::ui::pre_max_y = (float)r.top;
				globals::ui::pre_max_w = (float)(r.right - r.left);
				globals::ui::pre_max_h = (float)(r.bottom - r.top);
				MONITORINFO mi = { sizeof(mi) };
				GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi);
				float mw = (float)(mi.rcWork.right - mi.rcWork.left);
				float mh = (float)(mi.rcWork.bottom - mi.rcWork.top);
				globals::ui::window_w = mw;
				globals::ui::window_h = mh;
				SetWindowPos(g_hwnd, nullptr,
					mi.rcWork.left, mi.rcWork.top, (int)mw, (int)mh,
					SWP_NOZORDER);
				SetWindowRgn(g_hwnd, nullptr, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp = DWMWCP_DONOTROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
			} else {
				globals::ui::window_w = globals::ui::pre_max_w;
				globals::ui::window_h = globals::ui::pre_max_h;
				SetWindowPos(g_hwnd, nullptr,
					(int)globals::ui::pre_max_x, (int)globals::ui::pre_max_y,
					(int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h,
					SWP_NOZORDER);
				HRGN rgn = CreateRoundRectRgn(0, 0, (int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h, 16, 16);
				SetWindowRgn(g_hwnd, rgn, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp = DWMWCP_ROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
			}
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_B, false)) {
			globals::ui::panel_left_visible = !globals::ui::panel_left_visible;
			g_sa_settings.workspace.left_visible = globals::ui::panel_left_visible;
			g_sa_settings_request_save();
			diag::log_tagged_fmt("ui", "panel_toggle left_visible=%d hotkey=Ctrl+B",
				static_cast<int>(globals::ui::panel_left_visible));
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_J, false)) {
			globals::ui::panel_right_visible = !globals::ui::panel_right_visible;
			g_sa_settings.workspace.right_visible = globals::ui::panel_right_visible;
			g_sa_settings_request_save();
			diag::log_tagged_fmt("ui", "panel_toggle right_visible=%d hotkey=Ctrl+J",
				static_cast<int>(globals::ui::panel_right_visible));
		}

		if (ctrl && ImGui::IsKeyPressed(ImGuiKey_GraveAccent, false)) {
			globals::ui::panel_bottom_visible = !globals::ui::panel_bottom_visible;
			g_sa_settings.workspace.bottom_visible = globals::ui::panel_bottom_visible;
			g_sa_settings_request_save();
			diag::log_tagged_fmt("ui", "panel_toggle bottom_visible=%d hotkey=Ctrl+`",
				static_cast<int>(globals::ui::panel_bottom_visible));
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_S, false) && code_editor::active) {
			code_editor::save();
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_N, false)) {
			file_tabs::open_or_focus("", "untitled", "");
			globals::ui::active_center_view = center_view_t::code_editor;
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_W, false)) {
			int ci = file_tabs::active_tab;
			if (ci >= 0 && ci < (int)file_tabs::tabs.size() && file_tabs::tabs[ci].dirty) {
				file_tabs::pending_close_idx = ci;
				file_tabs::show_close_confirm = true;
			} else {
				file_tabs::close_tab(ci);
			}
		}

		if (ctrl && !shift && ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
			if (globals::ui::active_center_view == center_view_t::code_editor) {
				if (!file_tabs::tabs.empty()) {
					int next_idx = (file_tabs::active_tab + 1) % (int)file_tabs::tabs.size();
					file_tabs::switch_to(next_idx);
					globals::ui::active_center_view = center_view_t::code_editor;
				}
			} else {
				size_t total = analysis_session::session_count();
				if (total > 0) {
					size_t cur = analysis_session::active_session_idx();
					size_t next = (cur == static_cast<size_t>(-1)) ? 0 : (cur + 1) % total;
					analysis_session::switch_session(next);
				}
			}
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
			if (globals::ui::active_center_view == center_view_t::code_editor) {
				if (!file_tabs::tabs.empty()) {
					int prev_idx = (file_tabs::active_tab - 1 + (int)file_tabs::tabs.size()) %
					               (int)file_tabs::tabs.size();
					file_tabs::switch_to(prev_idx);
					globals::ui::active_center_view = center_view_t::code_editor;
				}
			} else {
				size_t total = analysis_session::session_count();
				if (total > 0) {
					size_t cur = analysis_session::active_session_idx();
					size_t prev = (cur == static_cast<size_t>(-1)) ? (total - 1)
						: ((cur + total - 1) % total);
					analysis_session::switch_session(prev);
				}
			}
		}

		if (ctrl && ImGui::IsKeyPressed(ImGuiKey_Comma, false)) {
			g_settings_open = true;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_P, false)) {
			globals::ui::command_palette_open = !globals::ui::command_palette_open;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
			globals::ui::active_activity = activity_item_t::search;
			globals::ui::panel_left_visible = true;
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_N, false)) {
			globals::ui::active_center_view = center_view_t::network_view;
			diag::log_tagged("ui", "view_switch to=network hotkey=Ctrl+Shift+N");
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_M, false)) {
			globals::ui::active_center_view = center_view_t::scan_hub;
			diag::log_tagged("ui", "view_switch to=scan_hub hotkey=Ctrl+Shift+M");
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_D, false)) {
			globals::ui::active_center_view = center_view_t::debugger_view;
			diag::log_tagged("ui", "view_switch to=debugger hotkey=Ctrl+Shift+D");
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_B, false)) {
			globals::ui::active_center_view = center_view_t::binary_map;
			diag::log_tagged("ui", "view_switch to=binary_map hotkey=Ctrl+Shift+B");
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_T, false)) {
			test_all_features::trigger_from_hotkey("imgui_ctrl_shift_t");
		}

		if (ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
			if (pseudocode_view::has_active_tab()) {
				globals::ui::active_center_view = center_view_t::pseudocode;
				diag::log_tagged("ui", "view_switch to=pseudocode hotkey=F5");
			}
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_X, false)) {
			globals::ui::active_center_view = center_view_t::xref_browser;
			diag::log_tagged("ui", "view_switch to=xref_browser hotkey=Ctrl+Shift+X");
		}

		if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_O, false)) {
			analysis_hub_view::set_sub_tab(analysis_hub_view::sub_tab_t::deobfuscation);
			globals::ui::active_center_view = center_view_t::analysis_hub;
			diag::log_tagged("ui", "view_switch to=analysis_hub hotkey=Ctrl+Shift+O");
		}
	}

	if (!helpers::themes_loaded) {
		helpers::theme_kaneki = nullptr;
		helpers::theme_rias = nullptr;
		helpers::theme_nagi = nullptr;
		helpers::theme_mio = nullptr;
		for (int i = 0; i < 4; ++i) {
			g_theme_icon_w[i] = 0;
			g_theme_icon_h[i] = 0;
		}
		helpers::themes_loaded = true;
	}


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
	    custom_themes::active_custom < (int)custom_themes::list.size()) {
		active_custom_icon_path = custom_themes::list[custom_themes::active_custom].icon_file_path;
	} else if (!g_sa_settings.custom_icon_path.empty()) {
		active_custom_icon_path = g_sa_settings.custom_icon_path;
	}

	static std::string s_last_rejected_custom_icon_path;
	static std::string s_last_checked_custom_icon_path;
	static bool s_last_checked_custom_icon_ok = false;
	static uint64_t s_last_checked_custom_icon_ms = 0;
	if (!active_custom_icon_path.empty()) {
		const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
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


	auto get_active_theme_icon = []() -> ID3D11ShaderResourceView* {
		if (custom_themes::active_custom >= 0 &&
		    custom_themes::active_custom < (int)custom_themes::list.size()) {
			auto& ct = custom_themes::list[custom_themes::active_custom];
			if (ct.icon_index < 0 && g_custom_theme_icon_srv)
				return g_custom_theme_icon_srv;
		}
		return nullptr;
	};

	bool loading = !bg_completed || globals::ui::load_timer < 3.0f;

	g_render_section = loading ? "loading_screen" : "post_loading";
	{
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
	}

	if (!loading)
	{
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
		static bool fileless_initial_geometry_logged = false;
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
				globals::ui::pre_max_x = static_cast<float>(mi2.rcWork.left) + (mw - normal_w) * 0.5f;
				globals::ui::pre_max_y = static_cast<float>(mi2.rcWork.top) + (mh - normal_h) * 0.5f;
				globals::ui::pre_max_w = normal_w;
				globals::ui::pre_max_h = normal_h;
				if (diag::env_flag_enabled("AIDA_FILELESS_LAUNCH")) {
					globals::ui::maximized = false;
					globals::ui::window_w = normal_w;
					globals::ui::window_h = normal_h;
					if (!fileless_initial_geometry_logged) {
						fileless_initial_geometry_logged = true;
						diag::log_tagged_critical_fmt("render",
							"fileless_initial_ide_geometry target=%d,%d work=%d,%d maximized=0",
							static_cast<int>(normal_w),
							static_cast<int>(normal_h),
							static_cast<int>(mw),
							static_cast<int>(mh));
					}
				} else {
					globals::ui::maximized = true;
					globals::ui::window_w = mw;
					globals::ui::window_h = mh;
					SetWindowPos(g_hwnd, nullptr,
						mi2.rcWork.left, mi2.rcWork.top,
						static_cast<int>(mw), static_cast<int>(mh), SWP_NOZORDER);
					SetWindowRgn(g_hwnd, nullptr, TRUE);
					DWM_WINDOW_CORNER_PREFERENCE cp = DWMWCP_DONOTROUND;
					DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
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
	}


	bool welcome_ready = !loading && globals::ui::window_w >= 470.f && globals::ui::window_h >= 270.f;
	bool ui_ready      = globals::ui::window_w >= 1000.f && globals::ui::window_h >= 600.f;

	if (ui_ready && globals::ui::welcome_done && runtime_ready)
	{
		static float raw = 0.f;
		raw += dt;
		if (raw > 1.f) raw = 1.f;
		globals::ui::ui_alpha = raw * raw;
	}


	ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
	ImGui::SetNextWindowSize(ImVec2(globals::ui::window_w, globals::ui::window_h));
	ImGui::Begin("##main", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);

	{
		ImVec2 bgwp = ImGui::GetWindowPos();
		const auto& th = aida::ui::resolved();
		ImGui::GetWindowDrawList()->AddRectFilled(
			bgwp,
			ImVec2(bgwp.x + globals::ui::window_w, bgwp.y + globals::ui::window_h),
			th.bg_base, 8.f);
	}

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
		float cap_size = cap->FontSize;
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
		float step_sz = cap->FontSize;
		ImVec2 sb_ts = cap->CalcTextSizeA(step_sz, FLT_MAX, 0.f, step_buf);
		dl->AddText(cap, step_sz, ImVec2(cx + bar_w * 0.5f - sb_ts.x, bar_y + bar_h + 12.f),
			aida::ui::with_alpha(th.text_dim, vis), step_buf);

		static POINT drag_start_wnd   = {};
		static POINT drag_start_mouse = {};
		static bool  dragging  = false;
		static bool  last_lmb  = false;
		bool lmb = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) && (GetForegroundWindow() == g_hwnd);
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
			SetWindowPos(g_hwnd, nullptr, nx, ny, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
		}
		last_lmb = lmb;

		if (!loading && fadeout <= 0.001f && !globals::ui::welcome_done) {
			globals::ui::welcome_done = true;
			globals::ui::ui_alpha = 0.f;
			globals::ui::welcome_timer = 3.5f;
		}

		ImGui::End();
		return;
	}


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
			float tag_sz = body->FontSize;
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
				float msg_sz = body->FontSize;
				ImVec2 ts_m = body->CalcTextSizeA(msg_sz, FLT_MAX, 0.f, msg);
				dl->AddText(body, msg_sz,
					ImVec2(cx - ts_m.x * 0.5f, wm_y + 32.f + tag_sz + 28.f),
					aida::ui::with_alpha(th.text_dim, msg_a), msg);
			}
		}

		ImGui::End();
		return;
	}


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
		static int shake_seed = 0;
		float shake_x = 0.f;
		if (license::check_failed) {
			static bool shake_started = false;
			if (!shake_started) {
				shake.start(0.280f, aida::motion::ease::out_quint);
				shake_started = true;
				shake_seed++;
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
			const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
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
			float sub_size = body->FontSize;
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
		float sub_size = body->FontSize;
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
		bool btn_held = btn_hov && (GetAsyncKeyState(VK_LBUTTON) & 0x8000);
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
			float phase_size = phase_font->FontSize;
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
			float arc_size = arc_font->FontSize;
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
			work_queue::post([key_copy]() {
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
		}


		if (license::check_failed && !license::error_msg.empty())
		{
			ImFont* err_font = aida::ui::fonts::body();
			if (!err_font) err_font = ImGui::GetFont();
			float err_font_size = err_font->FontSize;
			float err_y = btn_y_screen + btn_h + 24.f;

			float ic_x = card_a.x + pad;
			float ic_y = err_y + 2.f;
			ImVec2 ic_c(ic_x + 11.f, ic_y + 11.f);
			dl->AddCircleFilled(ic_c, 11.f, aida::ui::with_alpha(th.error_soft, la), 16);
			dl->AddCircle(ic_c, 11.f, aida::ui::with_alpha(th.error, la), 16, 1.3f);
			ImFont* bang_font = aida::ui::fonts::body_em();
			if (!bang_font) bang_font = err_font;
			dl->AddText(bang_font, bang_font->FontSize,
				ImVec2(ic_c.x - 3.f, ic_c.y - bang_font->FontSize * 0.5f),
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
			float disc_lbl = sm_font->FontSize;
			ImVec2 dts = sm_font->CalcTextSizeA(disc_lbl, FLT_MAX, 0.f, "Get a key");
			dl->AddText(sm_font, disc_lbl,
				ImVec2((disc_a.x + disc_b.x) * 0.5f - dts.x * 0.5f, (disc_a.y + disc_b.y) * 0.5f - dts.y * 0.5f),
				aida::ui::with_alpha(th.text_primary, la), "Get a key");
			if (disc_clk) {
				aida::auth::open_url_external("https://discord.gg/aida");
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
			static POINT lic_drag_wnd = {};
			static POINT lic_drag_mouse = {};
			static bool  lic_dragging = false;
			static bool  lic_last_lmb = false;
			bool lmb = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) && (GetForegroundWindow() == g_hwnd);
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
				SetWindowPos(g_hwnd, nullptr, nx, ny, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
			}
			lic_last_lmb = lmb;
		}

		ImGui::End();
		return;
	}


	g_render_section = "ide_layout";
	float a = globals::ui::ui_alpha;


	const auto metrics = aida::ui::shell_metrics(globals::ui::dpi_scale);
	const float pad      = metrics.pad;
	const float gap      = metrics.gap;
	const float title_h  = metrics.title_h;
	const float menu_h   = metrics.menu_h;
	float ww = globals::ui::window_w;
	float wh = globals::ui::window_h;


	{
		static bool s_layout_synced = false;
		if (!s_layout_synced) {
			globals::ui::panel_left_w  = g_sa_settings.workspace.left_width;
			globals::ui::panel_right_w = g_sa_settings.workspace.right_width;
			globals::ui::panel_bottom_h = g_sa_settings.workspace.bottom_height;
			globals::ui::panel_left_visible  = g_sa_settings.workspace.left_visible;
			globals::ui::panel_right_visible = g_sa_settings.workspace.right_visible;
			globals::ui::panel_bottom_visible = g_sa_settings.workspace.bottom_visible;
			s_layout_synced = true;
		}
	}

	float ab_for_layout = g_sa_settings.activity_bar_visible ? metrics.activity_bar_w : 0.f;
	float usable = ww - pad * 2.f - gap * 2.f - ab_for_layout;
	float min_panel = metrics.min_panel_w;
	float max_left  = usable * 0.3f;
	float max_right = usable * 0.5f;
	if (g_settings_open) {
		globals::ui::panel_right_visible = true;
		const float settings_min = aida::ui::scale_px(420.f, metrics.scale);
		const float settings_cap = (std::max)(metrics.min_panel_w, usable - aida::ui::scale_px(260.f, metrics.scale));
		const float settings_target = (std::min)(settings_min, settings_cap);
		if (globals::ui::panel_right_w < settings_target)
			globals::ui::panel_right_w = settings_target;
	}

	static float s_anim_left_w  = 0.f;
	static float s_anim_right_w = 0.f;
	static float s_anim_bottom_h = 0.f;
	{
		float target_left  = globals::ui::panel_left_visible  ? globals::ui::panel_left_w  : 0.f;
		float target_right = globals::ui::panel_right_visible ? globals::ui::panel_right_w : 0.f;
		float target_bot   = globals::ui::panel_bottom_visible ? globals::ui::panel_bottom_h : 0.f;
		float anim_speed = std::min(14.f * dt, 1.f);
		s_anim_left_w  += (target_left  - s_anim_left_w)  * anim_speed;
		s_anim_right_w += (target_right - s_anim_right_w) * anim_speed;
		s_anim_bottom_h += (target_bot  - s_anim_bottom_h) * anim_speed;
		if (std::abs(s_anim_left_w  - target_left)  < 1.f) s_anim_left_w  = target_left;
		if (std::abs(s_anim_right_w - target_right) < 1.f) s_anim_right_w = target_right;
		if (std::abs(s_anim_bottom_h - target_bot)  < 1.f) s_anim_bottom_h = target_bot;
	}
	float left_w   = s_anim_left_w;
	float right_w  = s_anim_right_w;
	float center_w = usable - left_w - right_w;
	if (center_w < 200.f) {

		float excess = 200.f - center_w;
		float total_panels = left_w + right_w;
		if (total_panels > 0.f) {
			left_w  -= excess * (left_w / total_panels);
			right_w -= excess * (right_w / total_panels);
		}
		center_w = 200.f;
	}
	if (globals::ui::panel_left_visible && s_anim_left_w >= globals::ui::panel_left_w - 1.f && left_w < min_panel) left_w = min_panel;
	if (globals::ui::panel_right_visible && s_anim_right_w >= globals::ui::panel_right_w - 1.f && right_w < min_panel) right_w = min_panel;
	if (globals::ui::panel_left_visible && s_anim_left_w >= globals::ui::panel_left_w - 1.f)
		globals::ui::panel_left_w = left_w;
	if (globals::ui::panel_right_visible && s_anim_right_w >= globals::ui::panel_right_w - 1.f)
		globals::ui::panel_right_w = right_w;
	center_w = usable - left_w - right_w;
	if (center_w < 100.f) center_w = 100.f;

	float bottom_h = s_anim_bottom_h;
	float chrome_h = title_h + menu_h;
	float total_h  = wh - pad * 2.f - chrome_h - (bottom_h > 1.f ? (bottom_h + gap) : 0.f);
	float right_total_h = wh - pad * 2.f - chrome_h;
	float content_top = pad + title_h + menu_h;

	g_render_section = "title_bar";
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, a);


	{
		ImVec2 wp   = ImGui::GetWindowPos();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		const auto& th_tb = aida::ui::resolved();

		ImVec2 tb_a(wp.x, wp.y);
		ImVec2 tb_b(wp.x + ww, wp.y + title_h);

		aida::ui::blur::layer_request_t tb_req;
		tb_req.pos = tb_a;
		tb_req.size = ImVec2(ww, title_h);
		tb_req.radius = 0.f;
		tb_req.strength = 0.55f;
		tb_req.alpha = a;
		aida::ui::blur::schedule(tb_req);
		dl->AddRectFilled(tb_a, tb_b, aida::ui::with_alpha(th_tb.title_bar, a), metrics.corner_radius, ImDrawFlags_RoundCornersTop);
		dl->AddRectFilled(tb_a, tb_b, aida::ui::with_alpha(th_tb.glass_tint, a * 0.5f), metrics.corner_radius, ImDrawFlags_RoundCornersTop);
		dl->AddLine(ImVec2(wp.x, wp.y + title_h), ImVec2(wp.x + ww, wp.y + title_h),
			aida::ui::with_alpha(th_tb.border_subtle, a));

		float pulse = aida::ui::clock::pulse(0.6f, 0.0f, 1.0f);
		ImVec2 logo_c(wp.x + pad + metrics.title_logo * 0.5f + gap, wp.y + title_h * 0.5f);
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

		ImFont* h2f = aida::ui::fonts::h2();
		if (!h2f) h2f = ImGui::GetFont();
		const char* app_name = "AiDA";
		const float title_font_sz = aida::ui::fonts::size_or(h2f, metrics.title_font);
		const float title_x = logo_c.x + metrics.title_logo * 0.5f + gap * 2.f;
		ImVec2 name_ts = h2f->CalcTextSizeA(title_font_sz, FLT_MAX, 0.f, app_name);
		dl->AddText(h2f, title_font_sz,
			ImVec2(title_x, wp.y + (title_h - title_font_sz) * 0.5f),
			aida::ui::with_alpha(th_tb.text_primary, a), app_name);

		{
			ImFont* body = aida::ui::fonts::caption();
			if (!body) body = ImGui::GetFont();
			const float bc_font_sz = aida::ui::fonts::size_or(body, metrics.caption_font);
			float bc_x = title_x + name_ts.x + gap * 2.f;
			float bc_y = wp.y + (title_h - bc_font_sz) * 0.5f;
			std::vector<std::string> segs;
			if (g_disasm.file.loaded) segs.push_back(g_disasm.file.filename);
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
				case center_view_t::welcome:
				default: break;
			}
			float sep_w = body->CalcTextSizeA(bc_font_sz, FLT_MAX, 0.f, ">").x;
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
		}

		auto draw_ctl = [&](float right_offset, const char* tag) -> std::pair<ImVec2, ImVec2> {
			float ctl_sz = metrics.title_control;
			ImVec2 cp(wp.x + ww - right_offset - ctl_sz, wp.y + (title_h - ctl_sz) * 0.5f);
			ImVec2 ce(cp.x + ctl_sz, cp.y + ctl_sz);
			(void)tag;
			return {cp, ce};
		};

		float ctl_off = pad + gap;

		auto [close_a, close_b] = draw_ctl(ctl_off, "x");
		bool close_hov = ImGui::IsMouseHoveringRect(close_a, close_b);
		static aida::ui::hover_state_t close_h;
		float chv = close_h.tick(close_hov, dt, aida::motion::spring::balanced);
		if (chv > 0.01f) {
			dl->AddRectFilled(close_a, close_b,
				aida::ui::with_alpha(th_tb.error, 0.20f * chv * a), metrics.control_radius);
		}
		ImVec2 xc((close_a.x + close_b.x) * 0.5f, (close_a.y + close_b.y) * 0.5f);
		float xr = 5.f;
		ImU32 xcol = aida::ui::mix(th_tb.text_primary, aida::ui::lighten(th_tb.error, 30), chv);
		float xth = 1.7f + chv * 0.6f;
		dl->AddLine(ImVec2(xc.x - xr, xc.y - xr), ImVec2(xc.x + xr, xc.y + xr),
			aida::ui::with_alpha(xcol, a), xth);
		dl->AddLine(ImVec2(xc.x + xr, xc.y - xr), ImVec2(xc.x - xr, xc.y + xr),
			aida::ui::with_alpha(xcol, a), xth);
		if (close_hov && !ui_input_gate::chrome_input_blocked() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
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
			request_chrome_shutdown_from_render("close_button", "chrome.close_button");
		}
		ctl_off += metrics.title_control + gap * 1.5f;

		auto [max_a, max_b] = draw_ctl(ctl_off, "m");
		bool max_hov = ImGui::IsMouseHoveringRect(max_a, max_b);
		static aida::ui::hover_state_t max_h;
		float mhv = max_h.tick(max_hov, dt, aida::motion::spring::balanced);
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
			if (globals::ui::maximized) {
				globals::ui::maximized = false;
				globals::ui::window_w = globals::ui::pre_max_w;
				globals::ui::window_h = globals::ui::pre_max_h;
				SetWindowPos(g_hwnd, nullptr,
					(int)globals::ui::pre_max_x, (int)globals::ui::pre_max_y,
					(int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h,
					SWP_NOZORDER);
				HRGN rgn = CreateRoundRectRgn(0, 0, (int)globals::ui::pre_max_w, (int)globals::ui::pre_max_h, 16, 16);
				SetWindowRgn(g_hwnd, rgn, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp_w = DWMWCP_ROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp_w, sizeof(cp_w));
			} else {
				RECT wr; GetWindowRect(g_hwnd, &wr);
				globals::ui::pre_max_x = (float)wr.left;
				globals::ui::pre_max_y = (float)wr.top;
				globals::ui::pre_max_w = globals::ui::window_w;
				globals::ui::pre_max_h = globals::ui::window_h;
				globals::ui::maximized = true;
				MONITORINFO mi = { sizeof(mi) };
				GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST), &mi);
				float mw = (float)(mi.rcWork.right - mi.rcWork.left);
				float mh = (float)(mi.rcWork.bottom - mi.rcWork.top);
				globals::ui::window_w = mw;
				globals::ui::window_h = mh;
				SetWindowPos(g_hwnd, nullptr,
					mi.rcWork.left, mi.rcWork.top, (int)mw, (int)mh,
					SWP_NOZORDER);
				SetWindowRgn(g_hwnd, nullptr, TRUE);
				DWM_WINDOW_CORNER_PREFERENCE cp_w = DWMWCP_DONOTROUND;
				DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp_w, sizeof(cp_w));
			}
		}
		ctl_off += metrics.title_control + gap * 1.5f;

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
			ShowWindow(g_hwnd, SW_MINIMIZE);
		ctl_off += metrics.title_control + gap * 3.f;


		{
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
					float angle = ray * 0.785398f;
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
		}

		{
			static int theme_popup_open_frame = 0;
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
						for (int ci = 0; ci < (int)custom_themes::list.size(); ci++) {
							auto& ct = custom_themes::list[ci];
							bool is_active = (custom_themes::active_custom == ci);

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
								custom_themes::editing_idx = ci;
								custom_themes::editing_copy = ct;
								custom_themes::editor_open = true;
							}

							ImGui::Dummy(ImVec2(item_w, item_h));
							if (popup_clicks_ok && ci_hov && !ehov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								custom_themes::active_custom = ci;
								themes::changed = true;
								g_sa_settings.active_custom_theme_idx = ci;
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
					if (!name_init || custom_themes::editing_idx != custom_themes::editing_idx) {
						snprintf(name_buf, sizeof(name_buf), "%s", ed.name.c_str());
						name_init = true;
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
						    custom_themes::editing_idx < (int)custom_themes::list.size()) {
							custom_themes::list[custom_themes::editing_idx] = ed;
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
			static POINT tb_drag_wnd = {};
			static POINT tb_drag_mouse = {};
			static bool  tb_dragging = false;
			static bool  tb_last_lmb = false;
			bool lmb = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) && (GetForegroundWindow() == g_hwnd);
			if (lmb && !tb_last_lmb) {
				POINT cp; GetCursorPos(&cp);
				RECT wr; GetWindowRect(g_hwnd, &wr);
				int local_y = cp.y - wr.top;
				int local_x = cp.x - wr.left;

				if (local_y >= 0 && local_y < (int)title_h && local_x >= 0 && local_x < (int)(ww - 140.f)
					&& !globals::ui::dragging_left_splitter && !globals::ui::dragging_right_splitter) {
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
				SetWindowPos(g_hwnd, nullptr, nx, ny, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
			}
			tb_last_lmb = lmb;
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
			{"File", 0}, {"Edit", 1}, {"View", 2}, {"Tools", 3}, {"AI", 4}, {"Help", 5}
		};

		ImFont* mb_label_font = aida::ui::fonts::lg();
		if (!mb_label_font) mb_label_font = aida::ui::fonts::body();
		if (!mb_label_font) mb_label_font = ImGui::GetFont();
		const float mb_label_size = aida::ui::fonts::size_or(mb_label_font, metrics.menu_font);
		float mx_cursor = wp.x + metrics.menu_pad_x;
		ImGuiStorage* mb_storage = ImGui::GetStateStorage();
		for (int i = 0; i < 6; i++) {
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
							aida::ui::with_alpha(th_p.hover_wash, 1.f), 8.f);
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

					switch (i) {
					case 0:
					{
						if (menu_item("New File", "Ctrl+N")) {
							file_tabs::open_or_focus("", "untitled", "");
							globals::ui::active_center_view = center_view_t::code_editor;
						}
						if (menu_item("Open File...", "Ctrl+O")) {
							file_menu_deferred::request(file_menu_deferred::action_t::open_file);
						}
						if (menu_item("Open Folder...", "Ctrl+K")) {
							file_menu_deferred::request(file_menu_deferred::action_t::open_folder);
						}
						menu_sep();
						if (menu_item("Save", "Ctrl+S", code_editor::active)) {
							code_editor::save();
						}
						if (menu_item("Save As...", "Ctrl+Shift+S", code_editor::active)) {
							char buf[MAX_PATH] = {};
							if (!code_editor::filename.empty())
								strncpy_s(buf, code_editor::filename.c_str(), _TRUNCATE);
							static const char k_save_as_filter[] =
								"All files (*.*)\0*.*\0\0";
							if (trusted_show_save_file(g_hwnd,
								"Save As",
								k_save_as_filter,
								nullptr,
								buf, sizeof(buf),
								"file_menu_save_as")) {
								code_editor::filepath = buf;
								std::string fn = buf;
								auto p = fn.find_last_of("\\/");
								if (p != std::string::npos) fn = fn.substr(p + 1);
								code_editor::filename = fn;
								if (file_tabs::active_tab >= 0 &&
								    file_tabs::active_tab < (int)file_tabs::tabs.size()) {
									auto& at = file_tabs::tabs[file_tabs::active_tab];
									at.filepath = code_editor::filepath;
									at.filename = code_editor::filename;
								}
								code_editor::save();
							}
						}
						menu_sep();
						if (menu_item("Exit", "Alt+F4")) {
							POINT cursor{};
							GetCursorPos(&cursor);
							diag::log_tagged_critical_fmt("chrome",
								"file_menu_exit_clicked hwnd=0x%llX cursor=%ld,%ld",
								(unsigned long long)reinterpret_cast<UINT_PTR>(g_hwnd),
								cursor.x,
								cursor.y);
							request_chrome_shutdown_from_render("file_menu_exit", "chrome.file_menu_exit");
						}
						break;
					}
					case 1:
					{
						if (menu_item("Undo",    "Ctrl+Z", code_editor::active)) {
							code_editor_widget::trigger_undo();
						}
						if (menu_item("Redo",    "Ctrl+Y", code_editor::active)) {
							code_editor_widget::trigger_redo();
						}
						menu_sep();
						menu_item("Cut",     "Ctrl+X", false);
						menu_item("Copy",    "Ctrl+C", false);
						menu_item("Paste",   "Ctrl+V", false);
						menu_sep();
						if (menu_item("Find",    "Ctrl+F", code_editor::active)) {
							code_editor_widget::open_find();
						}
						if (menu_item("Replace", "Ctrl+H", code_editor::active)) {
							code_editor_widget::open_replace();
						}
						break;
					}
					case 2:
					{
						if (menu_item(globals::ui::panel_left_visible ? "Hide Explorer" : "Show Explorer", "Ctrl+B")) {
							globals::ui::panel_left_visible = !globals::ui::panel_left_visible;
							g_sa_settings.workspace.left_visible = globals::ui::panel_left_visible;
							g_sa_settings_request_save();
						}
						if (menu_item(globals::ui::panel_right_visible ? "Hide Chat" : "Show Chat", "Ctrl+J")) {
							globals::ui::panel_right_visible = !globals::ui::panel_right_visible;
							g_sa_settings.workspace.right_visible = globals::ui::panel_right_visible;
							g_sa_settings_request_save();
						}
						if (menu_item(globals::ui::panel_bottom_visible ? "Hide Output" : "Show Output", "Ctrl+`")) {
							globals::ui::panel_bottom_visible = !globals::ui::panel_bottom_visible;
							g_sa_settings.workspace.bottom_visible = globals::ui::panel_bottom_visible;
							g_sa_settings_request_save();
						}
						menu_sep();
						if (menu_item("Editor", "")) globals::ui::active_center_view = center_view_t::code_editor;
						if (menu_item("Disassembly", "")) globals::ui::active_center_view = center_view_t::disassembly;
						if (menu_item("Hex", "")) globals::ui::active_center_view = center_view_t::hex_view;
						if (menu_item("Pseudocode", "")) globals::ui::active_center_view = center_view_t::pseudocode;
						if (menu_item("Graph", "")) globals::ui::active_center_view = center_view_t::graph_view;
						menu_sep();
						if (menu_item("Network", "Ctrl+Shift+N")) globals::ui::active_center_view = center_view_t::network_view;
						if (menu_item("Debugger", "Ctrl+Shift+D")) globals::ui::active_center_view = center_view_t::debugger_view;
						if (menu_item("Scan", "Ctrl+Shift+M")) globals::ui::active_center_view = center_view_t::scan_hub;
						if (menu_item("Types", "")) globals::ui::active_center_view = center_view_t::types_hub;
						if (menu_item("Analysis", "Ctrl+Shift+O")) globals::ui::active_center_view = center_view_t::analysis_hub;
						if (menu_item("Binary Map", "Ctrl+Shift+B")) globals::ui::active_center_view = center_view_t::binary_map;
						if (menu_item("Test Lab", "")) globals::ui::active_center_view = center_view_t::test_lab;
						menu_sep();
						menu_item("Zoom In",  "Ctrl+=", false);
						menu_item("Zoom Out", "Ctrl+-", false);
						break;
					}
					case 3:
					{
						if (menu_item("Load PE File...", "")) {
							std::string fpath = disasm::open_file_dialog(g_hwnd);
							if (fpath.empty()) {
								anti_tamper::webhook::write_log("chrome", "load_pe cancelled");
							} else {
								std::string fpath_copy = fpath;
								work_queue::post([fpath_copy]() {
									bool ok = analysis_session::open_session(fpath_copy);
									if (ok) {
										char buf[600];
										_snprintf_s(buf, sizeof(buf), _TRUNCATE,
											"load_pe ok path=%s", fpath_copy.c_str());
										anti_tamper::webhook::write_log("chrome", buf);
									} else {
										const char* err = analysis_session::last_error();
										char buf[700];
										_snprintf_s(buf, sizeof(buf), _TRUNCATE,
											"load_pe failed path=%s err=%s",
											fpath_copy.c_str(), err ? err : "(none)");
										anti_tamper::webhook::write_log("chrome", buf);
									}
								});
							}
						}
						if (menu_item("Attach to Process...", "")) {
							globals::ui::process_attach_open = true;
						}
						menu_sep();
						if (menu_item("MCP Servers", "")) {
							g_settings_open = true;
						}
						if (menu_item("Driver Status", "")) {
							globals::ui::driver_status_open = true;
						}
						break;
					}
					case 4:
					{
						if (menu_item("New Chat", "Ctrl+L")) {
							conversations::new_chat();
						}
						if (menu_item("Model Settings", "")) {
							g_settings_open = true;
						}
						break;
					}
					case 5:
					{
						if (menu_item("Keyboard Shortcuts", "Ctrl+K Ctrl+S")) {
							globals::ui::shortcuts_dialog_open = true;
							anti_tamper::webhook::write_log("chrome", "shortcuts_popup open=true source=menu");
						}
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


		if (ImGui::GetIO().KeyCtrl) {
			if (ImGui::IsKeyPressed(ImGuiKey_S) && code_editor::active)
				code_editor::save();
			if (ImGui::IsKeyPressed(ImGuiKey_B)) {
				globals::ui::panel_left_visible = !globals::ui::panel_left_visible;
				g_sa_settings.workspace.left_visible = globals::ui::panel_left_visible;
			}
			if (ImGui::IsKeyPressed(ImGuiKey_J)) {
				globals::ui::panel_right_visible = !globals::ui::panel_right_visible;
				g_sa_settings.workspace.right_visible = globals::ui::panel_right_visible;
			}
			if (ImGui::IsKeyPressed(ImGuiKey_GraveAccent)) {
				globals::ui::panel_bottom_visible = !globals::ui::panel_bottom_visible;
				g_sa_settings.workspace.bottom_visible = globals::ui::panel_bottom_visible;
			}
			if (ImGui::IsKeyPressed(ImGuiKey_L)) {
				conversations::new_chat();
			}
			if (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_P)) {
				globals::ui::command_palette_open = !globals::ui::command_palette_open;
				globals::ui::command_palette_buf[0] = '\0';
			}
		}
	}


	{
		ImVec2 wp = ImGui::GetWindowPos();
		float  sp_w = metrics.splitter_w;


		float ab_offset = g_sa_settings.activity_bar_visible ? metrics.activity_bar_w : 0.f;
		float ls_x = wp.x + pad + ab_offset + left_w;
		ImVec2 ls_min(ls_x - sp_w * 0.5f, wp.y + content_top);
		ImVec2 ls_max(ls_x + sp_w * 0.5f + gap, wp.y + content_top + total_h);

		bool ls_hov = globals::ui::panel_left_visible && !ui_input_gate::splitter_input_blocked() && ImGui::IsMouseHoveringRect(ls_min, ls_max);
		if (ls_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			globals::ui::dragging_left_splitter = true;
		if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
			globals::ui::dragging_left_splitter = false;
		if (globals::ui::dragging_left_splitter) {
			float mx = ImGui::GetIO().MousePos.x - wp.x - pad - ab_offset;
			globals::ui::panel_left_w = std::clamp(mx, min_panel, max_left);
			g_sa_settings.workspace.left_width = globals::ui::panel_left_w;
		}
		if (ls_hov || globals::ui::dragging_left_splitter)
			ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);


		float rs_x = wp.x + ww - pad - right_w;
		{


			ImVec2 mpos = ImGui::GetIO().MousePos;
			float rs_y0 = wp.y + content_top;
			float rs_y1 = wp.y + content_top + right_total_h;
			bool rs_in_rect = mpos.x >= (rs_x - 8.f) && mpos.x <= (rs_x + 8.f)
			               && mpos.y >= rs_y0 && mpos.y <= rs_y1;
			bool rs_hov = globals::ui::panel_right_visible && rs_in_rect
			           && !globals::ui::dragging_left_splitter && !globals::ui::dragging_bottom_splitter
			           && !ui_input_gate::splitter_input_blocked();
			if (rs_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				globals::ui::dragging_right_splitter = true;
			if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
				globals::ui::dragging_right_splitter = false;
			if (globals::ui::dragging_right_splitter) {
				float mx = wp.x + ww - mpos.x - pad;
				globals::ui::panel_right_w = std::clamp(mx, min_panel, max_right);
				g_sa_settings.workspace.right_width = globals::ui::panel_right_w;
			}
			if (rs_hov || globals::ui::dragging_right_splitter)
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
		}


		if (bottom_h > 1.f) {
			float right_gap_bs = (right_w > 1.f) ? (right_w + gap) : 0.f;
			float bs_y = wp.y + content_top + total_h;
			ImVec2 bs_min(wp.x + pad, bs_y - sp_w * 0.5f);
			ImVec2 bs_max(wp.x + ww - pad - right_gap_bs, bs_y + sp_w * 0.5f + gap);
			bool bs_hov = !ui_input_gate::splitter_input_blocked() && ImGui::IsMouseHoveringRect(bs_min, bs_max);
			if (bs_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				globals::ui::dragging_bottom_splitter = true;
			if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
				globals::ui::dragging_bottom_splitter = false;
			if (globals::ui::dragging_bottom_splitter) {
				float my = wp.y + wh - pad - ImGui::GetIO().MousePos.y;
				globals::ui::panel_bottom_h = std::clamp(my, aida::ui::scale_px(96.f, metrics.scale), wh * 0.5f);

			}
			if (bs_hov || globals::ui::dragging_bottom_splitter)
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
		}

		left_w   = globals::ui::dragging_left_splitter ? (globals::ui::panel_left_visible ? globals::ui::panel_left_w : 0.f) : s_anim_left_w;
		right_w  = globals::ui::dragging_right_splitter ? (globals::ui::panel_right_visible ? globals::ui::panel_right_w : 0.f) : s_anim_right_w;
		bottom_h = globals::ui::dragging_bottom_splitter ? (globals::ui::panel_bottom_visible ? globals::ui::panel_bottom_h : 0.f) : s_anim_bottom_h;
		if (globals::ui::dragging_left_splitter)   s_anim_left_w  = left_w;
		if (globals::ui::dragging_right_splitter)  s_anim_right_w = right_w;
		if (globals::ui::dragging_bottom_splitter) s_anim_bottom_h = bottom_h;
		center_w = ww - left_w - right_w - pad * 2.f - gap * 2.f - ab_for_layout;
		if (center_w < 200.f) {
			float excess = 200.f - center_w;
			float tp = left_w + right_w;
			if (tp > 0.f) { left_w -= excess * (left_w / tp); right_w -= excess * (right_w / tp); }
			center_w = 200.f;
		}
		total_h = wh - pad * 2.f - chrome_h - (bottom_h > 1.f ? (bottom_h + gap) : 0.f);
		right_total_h = wh - pad * 2.f - chrome_h;

		{
			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			const auto& th_sp = aida::ui::resolved();
			float ax_sp = globals::ui::accent.x, ay_sp = globals::ui::accent.y, az_sp = globals::ui::accent.z;
			ImU32 accent_line = IM_COL32((int)(ax_sp*255),(int)(ay_sp*255),(int)(az_sp*255),(int)(220 * a));
			ImU32 idle_line   = aida::ui::with_alpha(th_sp.border_strong, 0.55f * a);
			float ab_off_line = g_sa_settings.activity_bar_visible ? metrics.activity_bar_w : 0.f;
			if (globals::ui::panel_left_visible && left_w > 1.f) {
				float lsx = wp.x + pad + ab_off_line + left_w + gap * 0.5f;
				bool active = globals::ui::dragging_left_splitter ||
					ImGui::IsMouseHoveringRect(ImVec2(lsx - 4.f, wp.y + content_top),
					                           ImVec2(lsx + 4.f, wp.y + content_top + total_h));
				ImU32 col = active ? accent_line : idle_line;
				fdl->AddLine(ImVec2(lsx, wp.y + content_top + 2.f),
					ImVec2(lsx, wp.y + content_top + total_h - 2.f), col, active ? 1.6f : 1.f);
			}
			if (globals::ui::panel_right_visible && right_w > 1.f) {
				float rsx = wp.x + ww - pad - right_w - gap * 0.5f;
				bool active = globals::ui::dragging_right_splitter ||
					ImGui::IsMouseHoveringRect(ImVec2(rsx - 4.f, wp.y + content_top),
					                           ImVec2(rsx + 4.f, wp.y + content_top + right_total_h));
				ImU32 col = active ? accent_line : idle_line;
				fdl->AddLine(ImVec2(rsx, wp.y + content_top + 2.f),
					ImVec2(rsx, wp.y + content_top + right_total_h - 2.f), col, active ? 1.6f : 1.f);
			}
			if (globals::ui::panel_bottom_visible && bottom_h > 1.f) {
				float right_gap_line = (right_w > 1.f) ? (right_w + gap) : 0.f;
				float bsy = wp.y + content_top + total_h + gap * 0.5f;
				float bx0 = wp.x + pad + ab_off_line;
				float bx1 = wp.x + ww - pad - right_gap_line;
				bool active = globals::ui::dragging_bottom_splitter ||
					ImGui::IsMouseHoveringRect(ImVec2(bx0, bsy - 4.f), ImVec2(bx1, bsy + 4.f));
				ImU32 col = active ? accent_line : idle_line;
				fdl->AddLine(ImVec2(bx0 + 2.f, bsy), ImVec2(bx1 - 2.f, bsy), col, active ? 1.6f : 1.f);
			}
		}
	}

	float ax3 = globals::ui::accent.x, ay3 = globals::ui::accent.y, az3 = globals::ui::accent.z;
	ImU32 ac_full = IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(255*a));
	ImU32 ac_dim  = IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(35*a));
	const auto& th_lp = aida::ui::resolved();


	const float hdr_pad  = 10.f;
	const float row_h    = 22.f;
	const float row_gap  = 1.f;
	const float tb_vpad  = 8.f;
	const float hdr_h    = tb_vpad * 2.f + row_h * 2.f + row_gap;

	ImDrawList* wdl  = ImGui::GetWindowDrawList();
	ImVec2      wp_m = ImGui::GetWindowPos();


	float fb_x = pad;
	float fb_y = content_top;


	if (g_sa_settings.activity_bar_visible) {
		const auto& th_ab = aida::ui::resolved();
		const float ab_w = metrics.activity_bar_w;
		ImVec2 ab_pos(wp_m.x + pad, wp_m.y + content_top);
		ImVec2 ab_end(ab_pos.x + ab_w, ab_pos.y + total_h);

		aida::ui::blur::layer_request_t ab_req;
		ab_req.pos = ab_pos;
		ab_req.size = ImVec2(ab_w, total_h);
		ab_req.radius = 10.f;
		ab_req.strength = 0.55f;
		ab_req.alpha = a;
		aida::ui::blur::schedule(ab_req);
		aida::ui::blur::render_glass_fill(wdl, ab_pos, ab_end, 10.f, a);
		wdl->AddLine(ImVec2(ab_end.x, ab_pos.y), ImVec2(ab_end.x, ab_end.y),
			aida::ui::with_alpha(th_ab.border_subtle, a));

		struct ab_entry { const char* icon; activity_item_t item; const char* tip; };
		static const ab_entry ab_items[] = {
			{ ICON_FILES_EMPTY, activity_item_t::explorer,    "Explorer" },
			{ ICON_SEARCH,      activity_item_t::search,      "Search" },
			{ ICON_HISTORY,     activity_item_t::recent,      "Recent" },
		};
		static const int ab_count = sizeof(ab_items) / sizeof(ab_items[0]);

		float iy = ab_pos.y + 12.f;
		float ab_active_y0 = -1.f, ab_active_y1 = -1.f;
		ImGuiStorage* ab_storage = ImGui::GetStateStorage();
		for (int ai = 0; ai < ab_count; ai++) {
			bool active = (globals::ui::active_activity == ab_items[ai].item);
			float icon_sz = metrics.activity_icon;
			ImVec2 imin(ab_pos.x + (ab_w - icon_sz) * 0.5f, iy);
			ImVec2 imax(imin.x + icon_sz, imin.y + icon_sz);
			ImVec2 saved_cursor = ImGui::GetCursorScreenPos();
			ImGui::SetCursorScreenPos(imin);
			ImGui::PushID(ai);
			ImGui::InvisibleButton("##activity_item", ImVec2(icon_sz, icon_sz));
			bool ihov = ImGui::IsItemHovered();
			bool iclicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			ImGui::SetCursorScreenPos(saved_cursor);

			ImGuiID ab_h_id = ImGui::GetID(ab_items[ai].tip);
			float ah_v = ab_storage->GetFloat(ab_h_id, 0.f);
			float ah_target = ihov ? 1.f : 0.f;
			ah_v += (ah_target - ah_v) * std::min(14.f * dt, 1.f);
			ab_storage->SetFloat(ab_h_id, ah_v);

			float lift = ah_v * 2.f;
			ImVec2 ima(imin.x, imin.y - lift);
			ImVec2 imb(imax.x, imax.y - lift);

			if (active) {
				wdl->AddRectFilled(ima, imb,
					aida::ui::with_alpha(th_ab.selection, a), 8.f);
				aida::ui::blur::render_inner_glow(wdl, ima, imb, 8.f, th_ab.accent_glow, 3);
				ab_active_y0 = ima.y;
				ab_active_y1 = imb.y;
			} else if (ah_v > 0.01f) {
				wdl->AddRectFilled(ima, imb,
					aida::ui::with_alpha(th_ab.hover_wash, ah_v * a), 8.f);
			}

			ImVec2 lts = ImGui::CalcTextSize(ab_items[ai].icon);
			ImU32 ic = active ? aida::ui::with_alpha(th_ab.text_primary, a)
			                  : aida::ui::with_alpha(th_ab.text_dim, a);
			wdl->AddText(ImVec2(ima.x + (icon_sz - lts.x) * 0.5f, ima.y + (icon_sz - lts.y) * 0.5f),
				ic, ab_items[ai].icon);

			if (ihov) {
				aida::ui::tooltip_blur(ab_items[ai].tip, 0.6f);
			}

			bool blocked = ui_input_gate::popup_blocks_background_input();
			if (iclicked) {
				diag::log_tagged_fmt("ui",
					"shell_nav_click source=activity label='%s' blocked=%d rect=%.1f,%.1f,%.1f,%.1f before=%d",
					ab_items[ai].tip,
					blocked ? 1 : 0,
					imin.x,
					imin.y,
					imax.x,
					imax.y,
					static_cast<int>(globals::ui::active_activity));
			}
			if (iclicked && !blocked) {
				if (globals::ui::active_activity == ab_items[ai].item && globals::ui::panel_left_visible) {
					globals::ui::panel_left_visible = false;
				} else {
					globals::ui::active_activity = ab_items[ai].item;
					globals::ui::panel_left_visible = true;
				}
			}
			iy += icon_sz + gap * 2.f;
		}

		if (ab_active_y0 >= 0.f && globals::ui::panel_left_visible) {
			ImGuiID ab_uly = ImGui::GetID("##ab_ul_y");
			ImGuiID ab_uly_v = ImGui::GetID("##ab_ul_yv");
			ImGuiID ab_ulh = ImGui::GetID("##ab_ul_h");
			ImGuiID ab_ulh_v = ImGui::GetID("##ab_ul_hv");
			float ab_line_h_target = (ab_active_y1 - ab_active_y0) * 0.64f;
			float ab_cy_target = ab_active_y0 + (ab_active_y1 - ab_active_y0 - ab_line_h_target) * 0.5f;
			float ab_cy = ab_storage->GetFloat(ab_uly, ab_cy_target);
			float ab_vy = ab_storage->GetFloat(ab_uly_v, 0.f);
			float ab_ch = ab_storage->GetFloat(ab_ulh, ab_line_h_target);
			float ab_vh = ab_storage->GetFloat(ab_ulh_v, 0.f);
			ab_cy = aida::motion::spring_step(ab_cy, ab_cy_target, ab_vy,
				aida::motion::spring::balanced, dt);
			ab_ch = aida::motion::spring_step(ab_ch, ab_line_h_target, ab_vh,
				aida::motion::spring::balanced, dt);
			ab_storage->SetFloat(ab_uly, ab_cy);
			ab_storage->SetFloat(ab_uly_v, ab_vy);
			ab_storage->SetFloat(ab_ulh, ab_ch);
			ab_storage->SetFloat(ab_ulh_v, ab_vh);
			ui_anim::render_tab_underline_glow_vertical(wdl, ab_pos.x + 4.f, ab_cy, ab_ch, a);
		}


		{
			float footer_h = metrics.activity_footer_h;
			ImVec2 fmin(ab_pos.x, ab_end.y - footer_h);
			ImVec2 fmax(ab_pos.x + ab_w, ab_end.y);
			wdl->AddLine(ImVec2(fmin.x + 6.f, fmin.y),
				ImVec2(fmax.x - 6.f, fmin.y),
				aida::ui::with_alpha(th_ab.border_subtle, a * 0.7f), 1.f);

			float gear_sz = metrics.activity_icon * 0.89f;
			ImVec2 gmin(ab_pos.x + (ab_w - gear_sz) * 0.5f, fmin.y + (footer_h - gear_sz) * 0.5f);
			ImVec2 gmax(gmin.x + gear_sz, gmin.y + gear_sz);
			ImVec2 saved_cursor = ImGui::GetCursorScreenPos();
			ImGui::SetCursorScreenPos(gmin);
			ImGui::InvisibleButton("##gear_btn", ImVec2(gear_sz, gear_sz));
			bool ghov = ImGui::IsItemHovered();
			bool gclicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::SetCursorScreenPos(saved_cursor);
			static aida::ui::hover_state_t gear_h;
			float ghv = gear_h.tick(ghov, dt, aida::motion::spring::balanced);
			if (ghv > 0.01f) {
				wdl->AddRectFilled(gmin, gmax,
					aida::ui::with_alpha(th_ab.hover_wash, ghv * a), 8.f);
			}
			ImVec2 gts = ImGui::CalcTextSize(ICON_COG);
			ImU32 gc = ghov ? aida::ui::with_alpha(th_ab.text_primary, a)
			               : aida::ui::with_alpha(th_ab.text_dim, a);
			wdl->AddText(ImVec2(gmin.x + (gear_sz - gts.x) * 0.5f, gmin.y + (gear_sz - gts.y) * 0.5f),
				gc, ICON_COG);
			if (ghov) {
				aida::ui::tooltip_blur("Settings", 0.6f);
			}
			bool gear_blocked = ui_input_gate::popup_blocks_background_input();
			if (gclicked) {
				diag::log_tagged_fmt("ui",
					"shell_nav_click source=activity label='Settings' blocked=%d rect=%.1f,%.1f,%.1f,%.1f",
					gear_blocked ? 1 : 0,
					gmin.x,
					gmin.y,
					gmax.x,
					gmax.y);
			}
			if (gclicked && !gear_blocked)
				g_settings_open = true;
		}

		fb_x = pad + ab_w;
	}

	if (left_w > 1.f && globals::ui::panel_left_visible) {
	g_render_section = "left_panel";
	ImGui::SetCursorPos(ImVec2(fb_x, fb_y));
	begin_child("##filebrowser", ImVec2(fb_x, fb_y), ImVec2(left_w, total_h), a);
	{
		ImDrawList* fdl = ImGui::GetWindowDrawList();
		ImVec2 fwp = ImGui::GetWindowPos();
		float fw = ImGui::GetWindowWidth();
		float fh = ImGui::GetWindowHeight();

		if (globals::ui::active_activity == activity_item_t::search) {
			g_render_section = "left_panel_search";

			const char* search_lbl = "SEARCH";
			float search_hdr_h = 28.f;
			fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + (search_hdr_h - ImGui::GetFontSize()) * 0.5f),
				aida::ui::with_alpha(th_lp.text_dim, a), search_lbl);

			float sy = search_hdr_h + 4.f;
			ImGui::SetCursorPos(ImVec2(6.f, sy));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(th_ph_r, th_ph_g, th_ph_b, (int)(200 * a)));
			ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(th_lp.text_primary, a));
			ImGui::PushItemWidth(fw - 12.f);

			bool changed = ImGui::InputText("##ws_query", workspace_search::g_search.query_buf, sizeof(workspace_search::g_search.query_buf),
				ImGuiInputTextFlags_EnterReturnsTrue);
			if (changed || (ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter, false))) {
				workspace_search::start_search(file_browser::current_dir);
			}

			ImGui::PopItemWidth();
			ImGui::PopStyleColor(2);
			ImGui::PopStyleVar();

			sy += 28.f;

			{
				auto toggle_btn = [&](const char* label, const char* tooltip, bool& state, const char* id) {
					ImVec2 cp = ImGui::GetCursorScreenPos();
					ImVec2 lts = ImGui::CalcTextSize(label);
					float btn_w = lts.x + 10.f;
					float btn_h = 20.f;
					ImVec2 bmin = cp;
					ImVec2 bmax(cp.x + btn_w, cp.y + btn_h);
					bool hov = ImGui::IsMouseHoveringRect(bmin, bmax, false);

					ImU32 bg_col;
					if (state) {
						bg_col = IM_COL32((int)(ax3*180+40), (int)(ay3*180+40), (int)(az3*180+40), (int)(80*a));
					} else if (hov) {
						bg_col = aida::ui::with_alpha(th_lp.hover_wash, a);
					} else {
						bg_col = IM_COL32(0, 0, 0, 0);
					}

					if (state || hov)
						fdl->AddRectFilled(bmin, bmax, bg_col, 3.f);
					if (state)
						fdl->AddRect(bmin, bmax, IM_COL32((int)(ax3*200+55), (int)(ay3*200+55), (int)(az3*200+55), (int)(140*a)), 3.f);

					ImU32 txt_col = state
						? IM_COL32((int)(ax3*200+55), (int)(ay3*200+55), (int)(az3*200+55), (int)(240*a))
						: aida::ui::with_alpha(th_lp.text_secondary, (hov ? 1.f : 0.78f)*a);
					fdl->AddText(ImVec2(bmin.x + 5.f, bmin.y + (btn_h - lts.y) * 0.5f), txt_col, label);

					ImGui::SetCursorScreenPos(cp);
					if (ImGui::InvisibleButton(id, ImVec2(btn_w, btn_h)))
						state = !state;
					if (ImGui::IsItemHovered())
						ImGui::SetTooltip("%s", tooltip);
					ImGui::SameLine(0.f, 4.f);
				};

				ImGui::SetCursorPos(ImVec2(6.f, sy));
				toggle_btn("Aa", "Match Case", workspace_search::g_search.case_sensitive, "##ws_case");
				toggle_btn("W",  "Match Whole Word", workspace_search::g_search.whole_word, "##ws_word");
				toggle_btn(".*", "Use Regular Expression", workspace_search::g_search.use_regex, "##ws_regex");
			}

			sy += 28.f;

			fdl->AddText(ImVec2(fwp.x + 8.f, fwp.y + sy),
				aida::ui::with_alpha(th_lp.text_dim, 0.78f * a), "files to include");
			sy += ImGui::GetFontSize() + 6.f;
			ImGui::SetCursorPos(ImVec2(6.f, sy));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(th_ph_r, th_ph_g, th_ph_b, (int)(200 * a)));
			ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(th_lp.text_primary, a));
			ImGui::PushItemWidth(fw - 12.f);
			ImGui::InputText("##ws_include", workspace_search::g_search.include_buf, sizeof(workspace_search::g_search.include_buf));
			sy += 32.f;

			fdl->AddText(ImVec2(fwp.x + 8.f, fwp.y + sy),
				aida::ui::with_alpha(th_lp.text_dim, 0.78f * a), "files to exclude");
			sy += ImGui::GetFontSize() + 6.f;
			ImGui::SetCursorPos(ImVec2(6.f, sy));
			ImGui::InputText("##ws_exclude", workspace_search::g_search.exclude_buf, sizeof(workspace_search::g_search.exclude_buf));

			ImGui::PopItemWidth();
			ImGui::PopStyleColor(2);
			ImGui::PopStyleVar();

			sy += 28.f;


			if (workspace_search::g_search.searching.load()) {
				fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + sy),
					aida::ui::with_alpha(th_lp.warning, a), "Searching...");
				sy += 18.f;
			} else if (!workspace_search::g_search.results.empty()) {
				char count_buf[64];
				snprintf(count_buf, sizeof(count_buf), "%d results", (int)workspace_search::g_search.results.size());
				fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + sy),
					aida::ui::with_alpha(th_lp.text_dim, a), count_buf);
				sy += 18.f;
			}


			ImGui::SetCursorPos(ImVec2(0.f, sy));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
			ImGui::BeginChild("##ws_results", ImVec2(fw, fh - sy), false, ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings);
			{
				auto& results = workspace_search::g_search.results;

				struct file_group {
					std::string filepath;
					std::string filename;
					int first_idx;
					int count;
				};
				std::vector<file_group> groups;
				for (int ri = 0; ri < (int)results.size() && ri < 500; ri++) {
					auto& r = results[ri];
					if (groups.empty() || groups.back().filepath != r.filepath) {
						file_group g;
						g.filepath = r.filepath;
						g.filename = std::filesystem::path(r.filepath).filename().string();
						g.first_idx = ri;
						g.count = 1;
						groups.push_back(std::move(g));
					} else {
						groups.back().count++;
					}
				}

				static std::unordered_set<std::string> collapsed_files;

				for (auto& grp : groups) {
					ImVec2 gcp = ImGui::GetCursorScreenPos();
					float gh = 22.f;
					ImVec2 gmin(gcp.x, gcp.y);
					ImVec2 gmax(gcp.x + fw, gcp.y + gh);
					bool ghov = ImGui::IsMouseHoveringRect(gmin, gmax, false);

					if (ghov) fdl->AddRectFilled(gmin, gmax, aida::ui::with_alpha(th_lp.hover_wash, 0.45f * a));
					fdl->AddRectFilled(gmin, gmax, aida::ui::with_alpha(th_lp.hover_wash, 0.22f * a));

					bool is_collapsed = collapsed_files.count(grp.filepath) > 0;
					const char* arrow = is_collapsed ? ">" : "v";
					fdl->AddText(ImVec2(gmin.x + 4.f, gmin.y + (gh - ImGui::GetFontSize()) * 0.5f),
						aida::ui::with_alpha(th_lp.text_secondary, a), arrow);

					fdl->AddText(ImVec2(gmin.x + 16.f, gmin.y + (gh - ImGui::GetFontSize()) * 0.5f),
						aida::ui::with_alpha(th_lp.text_primary, a), grp.filename.c_str());

					char cnt_buf[16];
					snprintf(cnt_buf, sizeof(cnt_buf), "%d", grp.count);
					ImVec2 cnt_sz = ImGui::CalcTextSize(cnt_buf);
					float badge_x = gmin.x + 18.f + ImGui::CalcTextSize(grp.filename.c_str()).x + 6.f;
					fdl->AddRectFilled(
						ImVec2(badge_x, gmin.y + 3.f),
						ImVec2(badge_x + cnt_sz.x + 8.f, gmin.y + gh - 3.f),
						IM_COL32((int)(ax3*100+30), (int)(ay3*100+30), (int)(az3*100+30), (int)(120*a)), 6.f);
					fdl->AddText(ImVec2(badge_x + 4.f, gmin.y + (gh - cnt_sz.y) * 0.5f),
						aida::ui::with_alpha(th_lp.text_primary, 0.9f * a), cnt_buf);

					ImGui::Dummy(ImVec2(fw, gh));
					if (ghov && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						if (is_collapsed) collapsed_files.erase(grp.filepath);
						else collapsed_files.insert(grp.filepath);
					}

					if (!is_collapsed) {
						for (int ri = grp.first_idx; ri < grp.first_idx + grp.count; ri++) {
							auto& r = results[ri];
							float item_h2 = 22.f;
							ImVec2 cp2 = ImGui::GetCursorScreenPos();
							ImVec2 rmin2(cp2.x, cp2.y);
							ImVec2 rmax2(cp2.x + fw, cp2.y + item_h2);
							bool rhov = ImGui::IsMouseHoveringRect(rmin2, rmax2, false);
							if (rhov) fdl->AddRectFilled(rmin2, rmax2, aida::ui::with_alpha(th_lp.hover_wash, a));

							char ln_buf[16];
							snprintf(ln_buf, sizeof(ln_buf), "%d", r.line_number);
							fdl->AddText(ImVec2(rmin2.x + 22.f, rmin2.y + (item_h2 - ImGui::GetFontSize()) * 0.5f),
								aida::ui::with_alpha(th_lp.text_dim, 0.78f * a), ln_buf);

							float txt_x = rmin2.x + 22.f + ImGui::CalcTextSize("9999").x + 6.f;
							std::string preview = r.line_text.substr(0, (std::min)((size_t)80, r.line_text.size()));
							fdl->AddText(ImVec2(txt_x, rmin2.y + (item_h2 - ImGui::GetFontSize()) * 0.5f),
								aida::ui::with_alpha(th_lp.text_secondary, a),
								preview.c_str());

							ImGui::Dummy(ImVec2(fw, item_h2));
							if (rhov && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
								std::ifstream ifs(r.filepath, std::ios::binary);
								if (ifs.is_open()) {
									std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
									auto fname = std::filesystem::path(r.filepath).filename().string();
									file_tabs::open_or_focus(r.filepath, fname, content);
									autocomplete::cursor_line = r.line_number - 1;
									autocomplete::cursor_col = r.col_start;
									globals::ui::active_center_view = center_view_t::code_editor;
								}
							}
						}
					}
				}
			}
			ImGui::EndChild();
			ImGui::PopStyleVar();
		} else if (globals::ui::active_activity == activity_item_t::recent) {
			g_render_section = "left_panel_recent";

			const char* rc_lbl = "RECENT";
			fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + 8.f),
				aida::ui::with_alpha(th_lp.text_dim, a), rc_lbl);

			fdl->AddLine(ImVec2(fwp.x + 8.f, fwp.y + 28.f), ImVec2(fwp.x + fw - 8.f, fwp.y + 28.f),
				aida::ui::with_alpha(th_lp.hover_wash, 0.55f * a), 1.f);

			float rc_sy = 36.f;
			float rc_list_h = fh - rc_sy;
			if (rc_list_h < 24.f) rc_list_h = 24.f;
			ImGui::SetCursorPos(ImVec2(0.f, rc_sy));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
			ImGui::BeginChild("##recent_list", ImVec2(fw, rc_list_h), false, ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings);
			{
				std::vector<std::string> recent_list;
				if (!g_sa_settings.recent_workspaces_json.empty()) {
					auto jr = nlohmann::json::parse(g_sa_settings.recent_workspaces_json,
					                                nullptr, false);
					if (!jr.is_discarded() && jr.is_array()) {
						for (auto& el : jr) {
							if (el.is_string()) recent_list.push_back(el.get<std::string>());
						}
					}
				}

				size_t open_count = analysis_session::session_count();
				size_t active_idx = analysis_session::active_session_idx();

				auto paths_eq = [&](const std::string& A, const std::string& B) -> bool {
					if (A.size() != B.size()) return false;
					for (size_t i = 0; i < A.size(); ++i) {
						char ca = A[i];
						char cb = B[i];
						if (ca == '/') ca = '\\';
						if (cb == '/') cb = '\\';
						if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
						if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
						if (ca != cb) return false;
					}
					return true;
				};

				auto leaf_of = [](const std::string& p) -> std::string {
					size_t sl = p.find_last_of("/\\");
					return (sl != std::string::npos) ? p.substr(sl + 1) : p;
				};

				bool any_drawn = false;

				if (open_count > 0) {
					fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + rc_sy - 2.f - ImGui::GetScrollY()),
						aida::ui::with_alpha(th_lp.text_dim, 0.85f * a),
						"OPEN BINARIES");
					ImGui::Dummy(ImVec2(fw, 16.f));

					for (size_t si = 0; si < open_count; ++si) {
						const analysis_session::analysis_session_t* sess = analysis_session::session_at(si);
						if (!sess) continue;
						any_drawn = true;
						float row_h = 38.f;
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin(cp.x, cp.y);
						ImVec2 rmax(cp.x + fw, cp.y + row_h);
						bool hov = ImGui::IsMouseHoveringRect(rmin, rmax, false);
						bool is_active_sess = (si == active_idx);

						if (is_active_sess) {
							fdl->AddRectFilled(rmin, rmax,
								aida::ui::with_alpha(th_lp.selection, a));
							fdl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
								aida::ui::with_alpha(th_lp.accent_u32, a));
						} else if (hov) {
							fdl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(th_lp.hover_wash, a));
						}

						float close_btn_sz = 14.f;
						float cx0 = rmax.x - 10.f - close_btn_sz;
						float cx1 = cx0 + close_btn_sz;
						float cy0 = rmin.y + (row_h - close_btn_sz) * 0.5f;
						float cy1 = cy0 + close_btn_sz;
						bool close_hov = ImGui::IsMouseHoveringRect(ImVec2(cx0, cy0), ImVec2(cx1, cy1), false);

						std::string fname = sess->filename.empty() ? leaf_of(sess->path) : sess->filename;
						fdl->AddText(ImVec2(rmin.x + 12.f, rmin.y + 4.f),
							aida::ui::with_alpha(th_lp.text_primary, a),
							fname.c_str());

						std::string dir_str;
						{
							size_t sl = sess->path.find_last_of("/\\");
							dir_str = (sl != std::string::npos) ? sess->path.substr(0, sl) : sess->path;
							if (dir_str.size() > 42) {
								dir_str = "..." + dir_str.substr(dir_str.size() - 39);
							}
						}
						fdl->AddText(ImVec2(rmin.x + 12.f, rmin.y + 20.f),
							aida::ui::with_alpha(th_lp.text_dim, 0.9f * a),
							dir_str.c_str());

						if (close_hov) {
							fdl->AddRectFilled(ImVec2(cx0, cy0), ImVec2(cx1, cy1),
								aida::ui::with_alpha(th_lp.error, 0.5f * a), 3.f);
						}
						float pad_xs = 3.f;
						fdl->AddLine(ImVec2(cx0 + pad_xs, cy0 + pad_xs), ImVec2(cx1 - pad_xs, cy1 - pad_xs),
							aida::ui::with_alpha(th_lp.text_secondary, a), 1.4f);
						fdl->AddLine(ImVec2(cx1 - pad_xs, cy0 + pad_xs), ImVec2(cx0 + pad_xs, cy1 - pad_xs),
							aida::ui::with_alpha(th_lp.text_secondary, a), 1.4f);

						ImGui::Dummy(ImVec2(fw, row_h));

						if (hov && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							if (close_hov) {
								(void)analysis_session::close_session(si);
							} else {
								(void)analysis_session::switch_session(si);
							}
						}
						if (hov && !close_hov && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
							(void)analysis_session::close_session(si);
						}
					}

					ImGui::Dummy(ImVec2(fw, 6.f));
				}

				std::vector<std::string> closed_list;
				for (auto& p : recent_list) {
					bool is_open = false;
					for (size_t si = 0; si < open_count; ++si) {
						const analysis_session::analysis_session_t* sess = analysis_session::session_at(si);
						if (sess && paths_eq(sess->path, p)) { is_open = true; break; }
					}
					if (!is_open) closed_list.push_back(p);
					if (closed_list.size() >= 10) break;
				}

				if (!closed_list.empty()) {
					ImVec2 hcp = ImGui::GetCursorScreenPos();
					fdl->AddText(ImVec2(fwp.x + 10.f, hcp.y),
						aida::ui::with_alpha(th_lp.text_dim, 0.85f * a),
						"RECENT (CLOSED)");
					ImGui::Dummy(ImVec2(fw, 16.f));

					for (size_t ri = 0; ri < closed_list.size(); ++ri) {
						const std::string& path = closed_list[ri];
						any_drawn = true;
						float row_h = 38.f;
						ImVec2 cp = ImGui::GetCursorScreenPos();
						ImVec2 rmin(cp.x, cp.y);
						ImVec2 rmax(cp.x + fw, cp.y + row_h);
						bool hov = ImGui::IsMouseHoveringRect(rmin, rmax, false);
						if (hov) fdl->AddRectFilled(rmin, rmax,
							aida::ui::with_alpha(th_lp.hover_wash, a));

						std::string fname = leaf_of(path);
						fdl->AddText(ImVec2(rmin.x + 12.f, rmin.y + 4.f),
							aida::ui::with_alpha(th_lp.text_primary, a),
							fname.c_str());

						std::string dir_str;
						{
							size_t sl = path.find_last_of("/\\");
							dir_str = (sl != std::string::npos) ? path.substr(0, sl) : path;
							if (dir_str.size() > 42) {
								dir_str = "..." + dir_str.substr(dir_str.size() - 39);
							}
						}
						fdl->AddText(ImVec2(rmin.x + 12.f, rmin.y + 20.f),
							aida::ui::with_alpha(th_lp.text_dim, 0.9f * a),
							dir_str.c_str());

						ImGui::Dummy(ImVec2(fw, row_h));
						if (hov && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
							anti_tamper::webhook::write_log("file_dialog", (std::string("recent_closed left_click path=") + path).c_str());
							file_browser::pending_open_path          = path;
							file_browser::pending_open_filename      = fname;
							file_browser::pending_open_should_open   = true;
							file_browser::pending_open_modal_visible = true;
						}
					}
				}

				if (!any_drawn) {
					aida::ui::empty_state::config_t cfg;
					cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
					cfg.title = "No recent binaries";
					cfg.body  = "Open a binary from the Explorer to start. It will appear here next time.";
					aida::ui::empty_state::render(ImVec2(fwp.x, fwp.y + rc_sy),
						ImVec2(fw, rc_list_h), cfg);
				}
			}
			ImGui::EndChild();
			ImGui::PopStyleVar();

		} else {
		g_render_section = "left_panel_explorer";

		const char* explorer_lbl = "EXPLORER";
		const float explorer_line_h = ImGui::GetTextLineHeight();
		const float fb_header_h = (std::max)(aida::ui::scale_px(30.f, metrics.scale), explorer_line_h + aida::ui::scale_px(10.f, metrics.scale));
		const float fb_label_y = (fb_header_h - explorer_line_h) * 0.5f;
		const float explorer_row_h = (std::max)(aida::ui::scale_px(24.f, metrics.scale), explorer_line_h + aida::ui::scale_px(8.f, metrics.scale));
		const float explorer_indent_step = aida::ui::scale_px(16.f, metrics.scale);
		const float explorer_indent_base = aida::ui::scale_px(8.f, metrics.scale);

		float tree_y = fb_header_h;
		float fb_scroll_h = fh - tree_y;
		if (fb_scroll_h < 24.f) fb_scroll_h = 24.f;
		ImGui::SetCursorPos(ImVec2(0.f, tree_y));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
		ImGui::BeginChild("##fb_scroll", ImVec2(fw, fb_scroll_h), false, ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings);
		{
			ImDrawList* scl = ImGui::GetWindowDrawList();
			if (file_browser::needs_refresh || file_browser::entries.empty()) {
				g_render_section = "left_panel_explorer_refresh";
				file_browser::refresh();
			}
			g_render_section = "left_panel_explorer_watcher";
			file_browser::tick_watcher();
			g_render_section = "left_panel_explorer_rows";

			for (int fi = 0; fi < (int)file_browser::entries.size(); fi++) {
				auto& ent = file_browser::entries[fi];
				float indent = ent.depth * explorer_indent_step + explorer_indent_base;
				float item_h = explorer_row_h;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				ImVec2 rmin(cp.x, cp.y);
				ImVec2 rmax(cp.x + fw, cp.y + item_h);
				ImGui::PushID(fi);
				ImGui::InvisibleButton("##explorer_row", ImVec2(fw, item_h));
				bool hov = ImGui::IsItemHovered();
				bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGui::PopID();
				bool sel = (fi == file_browser::selected_idx);

				if (sel) scl->AddRectFilled(rmin, rmax, IM_COL32((int)(ax3*60), (int)(ay3*60), (int)(az3*60), (int)(80*a)));
				else if (hov) scl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(th_lp.hover_wash, a));


				const char* icon = ent.is_dir ? (ent.expanded ? "v " : "> ") : "   ";
				ImU32 icon_col = ent.is_dir
					? IM_COL32((int)(ax3*180+60), (int)(ay3*180+60), (int)(az3*180+60), (int)(200*a))
					: aida::ui::with_alpha(th_lp.text_secondary, 0.85f*a);
				ImU32 text_col = ent.is_dir
					? aida::ui::with_alpha(th_lp.text_primary, a)
					: aida::ui::with_alpha(th_lp.text_secondary, a);

				const float text_y = rmin.y + (item_h - explorer_line_h) * 0.5f;
				const float icon_x = rmin.x + indent;
				const float name_x = icon_x + ImGui::CalcTextSize(icon).x;
				scl->PushClipRect(rmin, rmax, true);
				scl->AddText(ImVec2(icon_x, text_y), icon_col, icon);
				scl->AddText(ImVec2(name_x, text_y), text_col, ent.name.c_str());
				scl->PopClipRect();

				if (clicked && !ui_input_gate::popup_blocks_background_input()) {
					file_browser::selected_idx = fi;
					if (ent.is_dir) {
						file_browser::toggle_dir(fi);
					} else {
						anti_tamper::webhook::write_log("file_dialog", (std::string("explorer_tree click idx=") + std::to_string(fi) + " path=" + ent.full_path).c_str());
						file_browser::open_file(fi);
					}
				}
			}
		}
		ImGui::EndChild();
		ImGui::PopStyleVar();

		fdl->AddRectFilled(ImVec2(fwp.x, fwp.y), ImVec2(fwp.x + fw, fwp.y + fb_header_h),
			th_lp.panel_bg);
		fdl->AddLine(ImVec2(fwp.x, fwp.y + fb_header_h - 0.5f),
			ImVec2(fwp.x + fw, fwp.y + fb_header_h - 0.5f),
			aida::ui::with_alpha(th_lp.border_subtle, 0.7f * a), 1.f);
		fdl->AddText(ImVec2(fwp.x + 10.f, fwp.y + fb_label_y),
			aida::ui::with_alpha(th_lp.text_dim, a), explorer_lbl);
		}


		{
			g_render_section = "left_panel_theme_icon";
			ID3D11ShaderResourceView* icon_srv = get_active_theme_icon();
			(void)icon_srv;
		}
	}
	g_render_section = "left_panel_end_child";
	end_child();
	g_render_section = "left_panel_done";
	}

	float ab_extra = g_sa_settings.activity_bar_visible ? metrics.activity_bar_w : 0.f;
	float left_gap = (left_w > 1.f) ? (left_w + gap + ab_extra) : ab_extra;
	float hx0 = wp_m.x + pad + left_gap, hy0 = wp_m.y + content_top;
	float hx1  = hx0 + center_w;
	float hy1  = hy0 + hdr_h;
	float dc_y1 = wp_m.y + content_top + total_h;

	const auto& th_cp = aida::ui::resolved();

	wdl->AddRectFilled(ImVec2(hx0, hy0), ImVec2(hx1, dc_y1),
		th_cp.panel_bg, metrics.corner_radius);


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
		float bg_a  = (bht * 0.10f + bft * 0.08f) * a;
		float brd_a = (0.14f + bht * 0.10f) * a;
		float txt_a = (0.55f + bht * 0.30f) * a;
		wdl->AddRectFilled(ImVec2(bx0,by0), ImVec2(bx1,by1),
			IM_COL32(255,255,255,(int)(bg_a*255)), 3.f);
		wdl->AddRect(ImVec2(bx0,by0), ImVec2(bx1,by1),
			IM_COL32(255,255,255,(int)(brd_a*255)), 3.f, 0, 0.75f);
		wdl->AddText(ImVec2(bx0 + (bw2 - ts.x) * 0.5f, by0 + (bh2 - ts.y) * 0.5f),
			IM_COL32(255,255,255,(int)(txt_a*255)), label);
		return bck;
	};


	auto flat_btn = [&](const char* label, ImGuiID id_hv, float lx, float cy) -> bool
	{
		ImGuiStorage* st = ImGui::GetStateStorage();
		ImVec2 ts  = ImGui::CalcTextSize(label);
		float  tx  = lx;
		float  ty  = cy - ts.y * 0.5f;
		ImVec2 hr0 = ImVec2(tx - 2.f, ty - 2.f);
		ImVec2 hr1 = ImVec2(tx + ts.x + 2.f, ty + ts.y + 2.f);
		bool   bhv = !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseHoveringRect(hr0, hr1, false);
		bool   bck = bhv && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
		float  bht = st->GetFloat(id_hv, 0.f);
		bht += ((bhv ? 1.f : 0.f) - bht) * std::min(12.f * dt, 1.f);
		st->SetFloat(id_hv, bht);
		float txt_a = (0.55f + bht * 0.40f) * a;
		wdl->AddText(ImVec2(tx, ty), IM_COL32(255,255,255,(int)(txt_a*255)), label);

		float uw  = ts.x * bht;
		float ux0 = tx + ts.x * 0.5f - uw * 0.5f;
		float uy  = ty + ts.y + 1.f;
		if (uw > 0.5f)
			wdl->AddLine(ImVec2(ux0, uy), ImVec2(ux0 + uw, uy),
				IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(bht*180*a)), 1.f);
		return bck;
	};


	const float rbtn_w  = std::max(
		ImGui::CalcTextSize("Choose File").x,
		ImGui::CalcTextSize("Run").x) + 32.f;
	const float rbtn_x0 = hx1 - hdr_pad - rbtn_w;


	{


		bool row2_has_vt_btn = g_disasm.file.loaded;
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
		std::vector<strip_entry_t> strip_entries;
		strip_entries.reserve(file_tabs::tabs.size() + 8);

		const float tab_pad_x_strip = 10.f;
		const float close_sz_strip  = 10.f;

		auto strip_calc_w = [&](const std::string& label) -> float {
			ImVec2 ts = ImGui::CalcTextSize(label.c_str());
			return tab_pad_x_strip * 2.f + ts.x + close_sz_strip + 12.f;
		};

		for (int ti = 0; ti < (int)file_tabs::tabs.size(); ti++) {
			auto& tab = file_tabs::tabs[ti];
			strip_entry_t e;
			e.label = tab.filename + (tab.dirty ? " *" : "");
			e.kind = 0;
			e.idx = ti;
			e.is_active = ((ti == file_tabs::active_tab) && code_editor::active &&
			              globals::ui::active_center_view == center_view_t::code_editor);
			e.dirty = tab.dirty;
			e.width = strip_calc_w(e.label);
			strip_entries.push_back(std::move(e));
		}

		{
			auto psv_tabs_for_strip = pseudocode_view::snapshot_tabs();
			bool psv_view_active = (globals::ui::active_center_view == center_view_t::pseudocode);
			uint64_t active_psv_addr = pseudocode_view::active_tab_address();
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

		if (hex_view::g_state.active) {
			strip_entry_t e;
			e.label = hex_view::g_state.source_name.empty()
				? std::string("Hex View")
				: hex_view::g_state.source_name + " (Hex)";
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
			for (int i = 0; i < (int)strip_entries.size(); i++) {
				auto& e = strip_entries[i];
				if (e.is_active) { active_idx = i; break; }
				ax_running += e.width + 2.f;
			}
			if (active_idx >= 0 && strip_has_overflow) {
				char sig_buf[64];
				std::snprintf(sig_buf, sizeof(sig_buf), "%d|%s",
					active_idx, strip_entries[active_idx].label.c_str());
				ImGuiID sig_id = ImGui::GetID(sig_buf);
				ImGuiID prev_sig_id = (ImGuiID)strip_st->GetInt(strip_id_active_sig, 0);
				if (sig_id != prev_sig_id) {
					float aw = strip_entries[active_idx].width;
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

		if (!file_tabs::tabs.empty()) {
			const float tab_pad_x = 10.f;
			const float tab_gap   = 2.f;
			const float close_sz  = 10.f;
			const float tab_h     = row_h - 2.f;
			float tab_x = strip_tabs_x0 - strip_scroll;
			float tab_y = r2_cy - tab_h * 0.5f;

			int close_idx = -1;
			int click_idx = -1;
			float active_tx0 = -1.f, active_tx1 = -1.f, active_ty0 = 0.f;

			for (int ti = 0; ti < (int)file_tabs::tabs.size(); ti++) {
				auto& tab = file_tabs::tabs[ti];
				bool is_active = (ti == file_tabs::active_tab);


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

				bool tab_hov = mouse_in_strip &&
					ImGui::IsMouseHoveringRect(ImVec2(tx0, ty0), ImVec2(tx1, ty1), false);


				if (is_active) {
					wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
						IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(22*a)),
						4.f, ImDrawFlags_RoundCornersTop);
					active_tx0 = tx0 + 2.f;
					active_tx1 = tx1 - 2.f;
					active_ty0 = ty0;
				} else if (tab_hov) {
					wdl->AddRectFilled(ImVec2(tx0, ty0), ImVec2(tx1, ty1),
						aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 4.f, ImDrawFlags_RoundCornersTop);
				}


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
					close_idx = ti;
				else if (tab_hov && !close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					click_idx = ti;


				if (ti < (int)file_tabs::tabs.size() - 1) {
					wdl->AddLine(ImVec2(tx1, ty0 + 3.f), ImVec2(tx1, ty1 - 3.f),
						aida::ui::with_alpha(th_lp.hover_wash, 0.45f*a), 1.f);
				}

				tab_x = tx1 + tab_gap;
			}


			if (close_idx >= 0) {
				if (close_idx < (int)file_tabs::tabs.size() &&
				    file_tabs::tabs[close_idx].dirty) {
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
			for (int ti = 0; ti < (int)file_tabs::tabs.size(); ti++) {
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
			auto psv_tabs = pseudocode_view::snapshot_tabs();
			if (!psv_tabs.empty()) {
				bool psv_view_active = (globals::ui::active_center_view == center_view_t::pseudocode);
				uint64_t active_psv_addr = pseudocode_view::active_tab_address();

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
							IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(22*a)),
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
					pseudocode_view::close_tab_by_addr(to_close_addr);
					if (psv_view_active && pseudocode_view::tab_count() == 0) {
						globals::ui::active_center_view = center_view_t::disassembly;
					}
				} else if (to_activate_addr != 0) {
					pseudocode_view::activate_tab_by_addr(to_activate_addr);
					globals::ui::active_center_view = center_view_t::pseudocode;
				}
			}
		}

		if (hex_view::g_state.active) {
			bool hex_is_active = (globals::ui::active_center_view == center_view_t::hex_view);
			std::string hex_label_str = hex_view::g_state.source_name.empty()
				? std::string("Hex View")
				: hex_view::g_state.source_name + " (Hex)";
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
						IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(22*a)),
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
					hex_view::g_state.active = false;
					hex_view::g_state.data.clear();
					hex_view::g_state.source_name.clear();
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
			for (int li = 0; li < 3; li++) {
				float ly = drop_cy - 3.f + li * 3.f;
				wdl->AddLine(
					ImVec2(drop_cx - drop_w_icon * 0.5f, ly),
					ImVec2(drop_cx + drop_w_icon * 0.5f, ly),
					drop_col, 1.2f);
			}
			if (drop_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				ImGui::OpenPopup("##tab_strip_dropdown");
			}

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

				for (int ei = 0; ei < (int)strip_entries.size(); ei++) {
					auto& e = strip_entries[ei];
					ImVec2 cp = ImGui::GetCursorScreenPos();
					ImVec2 rmin(cp.x, cp.y);
					ImVec2 rmax(cp.x + pop_w, cp.y + row_h_pop);
					bool rhov = ImGui::IsMouseHoveringRect(rmin, rmax, false);
					if (e.is_active) {
						pdl->AddRectFilled(rmin, rmax,
							IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),34), 6.f);
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
						? IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),255)
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
						pseudocode_view::activate_tab_by_addr(chosen_addr);
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
						IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(56*a)),
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
						IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(56*a)),
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
						IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(56*a)),
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
							IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),(int)(56*a)),
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
							IM_COL32((int)(ax3*255),(int)(ay3*255),(int)(az3*255),34), 6.f);
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
			anti_tamper::webhook::write_log("file_dialog", "chrome.choose_file_clicked invoking_open_file_dialog");
			std::string fpath = disasm::open_file_dialog(g_hwnd);
			if (fpath.empty()) {
				anti_tamper::webhook::write_log("file_dialog", "chrome.choose_file cancelled_or_empty");
				anti_tamper::webhook::write_log("chrome", "choose_file cancelled");
			} else {
				anti_tamper::webhook::write_log("file_dialog",
					(std::string("chrome.choose_file path=") + fpath).c_str());
				std::string fpath_copy = fpath;
				work_queue::post([fpath_copy]() {
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
				});
			}
		}


		if (file_tabs::active_tab >= 0 && file_tabs::active_tab < (int)file_tabs::tabs.size()) {
			auto& sync_tab = file_tabs::tabs[file_tabs::active_tab];
			if (code_editor::active && sync_tab.filepath == code_editor::filepath)
				sync_tab.dirty = code_editor::dirty;
		}
	}


	{

		if (g_disasm.file.loaded) {
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
					if (!hex_view::g_state.active || hex_view::g_state.data.empty())
						hex_view::load_from_file(g_disasm.file.path);
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

		auto launch_session_path = [](const std::string& path) {
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
		};

		if (run_clicked) {
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
				const auto* sess = analysis_session::session_at(0);
				if (sess && !sess->path.empty()) {
					launch_session_path(sess->path);
					_snprintf_s(log_buf, sizeof(log_buf), _TRUNCATE,
						"run sessions=1 choice=direct status=spawn_dialog path=%s",
						sess->path.c_str());
					anti_tamper::webhook::write_log("chrome", log_buf);
				} else {
					std::string prefill_exe;
					if (g_disasm.file.loaded && !g_disasm.file.path.empty())
						prefill_exe = g_disasm.file.path;
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
				if (g_disasm.file.loaded && !g_disasm.file.path.empty()) {
					prefill_exe = g_disasm.file.path;
				} else if (code_editor::active && !file_tabs::tabs.empty() &&
					file_tabs::active_tab < (int)file_tabs::tabs.size()) {
					auto& tab = file_tabs::tabs[file_tabs::active_tab];
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
			ImVec2 vp = ImGui::GetIO().DisplaySize;
			ImGui::SetNextWindowPos(ImVec2(vp.x * 0.5f, vp.y * 0.5f),
				ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
			ImGui::SetNextWindowSize(ImVec2(540.f, 0.f), ImGuiCond_Appearing);
			if (ImGui::BeginPopupModal("##chrome_run_pick", nullptr,
				ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
				ImGui::TextUnformatted("Which binary do you want to run?");
				ImGui::Separator();
				size_t sess_count = analysis_session::session_count();
				if (s_run_pick_selected >= static_cast<int>(sess_count))
					s_run_pick_selected = static_cast<int>(sess_count) - 1;
				if (s_run_pick_selected < 0 && sess_count > 0) s_run_pick_selected = 0;

				ImGui::BeginChild("##chrome_run_pick_list",
					ImVec2(520.f, std::min(360.f, std::max(80.f, static_cast<float>(sess_count) * 28.f + 16.f))),
					true, ImGuiWindowFlags_None);
				for (size_t i = 0; i < sess_count; ++i) {
					const auto* sess = analysis_session::session_at(i);
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
					const auto* sess = analysis_session::session_at(
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

		spawn_target_dialog::render();
		spawn_target_dialog::result_t spawn_res;
		if (spawn_target_dialog::consume_result(spawn_res) && spawn_res.accepted) {
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

			work_queue::post([opts, exe_log]() {
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
		}
	}


	float disasm_child_y = content_top + hdr_h + 1.f;
	float disasm_child_h = total_h - hdr_h - 1.f;
	const float di_pad   = 6.f;
	const float session_tabs_h = 32.f;
	float center_content_w = (std::max)(center_w - di_pad * 2.f, 1.f);
	float center_content_h = (std::max)(disasm_child_h - di_pad * 2.f - session_tabs_h, 1.f);
	{
		ImVec2 wpos = ImGui::GetWindowPos();
		float tabs_screen_x = wpos.x + pad + left_gap + di_pad;
		float tabs_screen_y = wpos.y + disasm_child_y + di_pad;
		float tabs_w = center_content_w;
		render_session_tabs(tabs_screen_x, tabs_screen_y, tabs_w, session_tabs_h, a);
	}
	ImGui::SetCursorPos(ImVec2(pad + left_gap + di_pad, disasm_child_y + di_pad + session_tabs_h));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f,0.f));
	ImGui::BeginChild("##center_content_scroll",
		ImVec2(center_content_w, center_content_h),
		false, ImGuiWindowFlags_NoBackground);
	{


	mark_center_render_section("center_pump_ui_thread_jobs", globals::ui::active_center_view, false, center_content_w, center_content_h);
	static std::atomic<unsigned long long> s_last_pump_jobs_log_ms{0};
	const unsigned long long ui_jobs_start_ms = GetTickCount64();
	unsigned long long last_pump_jobs_log_ms = s_last_pump_jobs_log_ms.load(std::memory_order_acquire);
	const bool full_test_active_for_pump_log = test_all_features::is_running();
	const unsigned long long pump_log_interval_ms = full_test_active_for_pump_log ? 1000ULL : 30000ULL;
	const bool log_pump_jobs = ui_jobs_start_ms - last_pump_jobs_log_ms >= pump_log_interval_ms &&
		s_last_pump_jobs_log_ms.compare_exchange_strong(last_pump_jobs_log_ms, ui_jobs_start_ms, std::memory_order_acq_rel);
	char ui_phase_before[900] = {};
	if (log_pump_jobs)
		test_all_features::format_ui_phase_snapshot(ui_phase_before, sizeof(ui_phase_before));
	if (log_pump_jobs) {
		diag::log_tagged_critical_fmt("render_center",
			"pump_ui_thread_jobs_enter view=%s view_id=%d frame=%d tid=%lu stats={%.760s}",
			center_view_name(globals::ui::active_center_view),
			static_cast<int>(globals::ui::active_center_view),
			ImGui::GetFrameCount(),
			static_cast<unsigned long>(GetCurrentThreadId()),
			ui_phase_before[0] ? ui_phase_before : "<not-sampled>");
	}
	test_all_features::pump_ui_thread_jobs();
	const unsigned long long ui_jobs_wall_ms = GetTickCount64() - ui_jobs_start_ms;
	const bool slow_pump_jobs = ui_jobs_wall_ms >= (full_test_active_for_pump_log ? 8ULL : 32ULL);
	if (log_pump_jobs || slow_pump_jobs) {
		char ui_phase_after[900] = {};
		test_all_features::format_ui_phase_snapshot(ui_phase_after, sizeof(ui_phase_after));
		diag::log_tagged_critical_fmt("render_center",
			"pump_ui_thread_jobs_exit view=%s view_id=%d wall_ms=%llu slow=%d frame=%d tid=%lu before={%.760s} after={%.760s}",
			center_view_name(globals::ui::active_center_view),
			static_cast<int>(globals::ui::active_center_view),
			static_cast<unsigned long long>(ui_jobs_wall_ms),
			slow_pump_jobs ? 1 : 0,
			ImGui::GetFrameCount(),
			static_cast<unsigned long>(GetCurrentThreadId()),
			ui_phase_before[0] ? ui_phase_before : "<not-sampled>",
			ui_phase_after[0] ? ui_phase_after : "<empty>");
	}
	g_render_section = "center_resolve_view";
	auto cv = globals::ui::active_center_view;

	bool overlay_blocking = loading_binary_overlay::is_blocking_views();
	if (overlay_blocking) {
		cv = center_view_t::welcome;
	}

	if (cv == center_view_t::welcome && !overlay_blocking) {
		if (code_editor::active && !code_editor::buffer.empty())
			cv = center_view_t::code_editor;
		else if (g_disasm.file.loaded && (g_disasm.live_mode || g_disasm.file.decoding || !g_disasm.file.instrs.empty()))
			cv = center_view_t::disassembly;
		else if (hex_view::g_state.active)
			cv = center_view_t::hex_view;
	}

	float vw = center_content_w;
	float vh = center_content_h;
	const unsigned long long center_dispatch_start_ms = GetTickCount64();
	auto log_center_dispatch_exit = [&](const char* section) {
		const unsigned long long now_ms = GetTickCount64();
		const unsigned long long elapsed_ms = now_ms >= center_dispatch_start_ms ? now_ms - center_dispatch_start_ms : 0ULL;
		if (elapsed_ms >= 250ULL) {
			diag::log_tagged_critical_fmt("render_center",
				"slow_exit section=%s view=%s view_id=%d elapsed_ms=%llu overlay=%d full_test=%d frame=%d",
				section ? section : "<null>",
				center_view_name(cv),
				static_cast<int>(cv),
				elapsed_ms,
				overlay_blocking ? 1 : 0,
				test_all_features::is_running() ? 1 : 0,
				ImGui::GetFrameCount());
		}
	};

	if (cv == center_view_t::code_editor && code_editor::active && !code_editor::buffer.empty())
	{
		mark_center_render_section("center_view_code_editor", cv, overlay_blocking, vw, vh);
		ImGui::SetCursorPos(ImVec2(0.f, 0.f));
		code_editor_widget::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_code_editor");
	}


	else if (cv == center_view_t::hex_view && hex_view::g_state.active)
	{
		mark_center_render_section("center_view_hex_view", cv, overlay_blocking, vw, vh);
		hex_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_hex_view");
	}

	else if (cv == center_view_t::image_view && image_view::g_state().active.load(std::memory_order_acquire))
	{
		mark_center_render_section("center_view_image_view", cv, overlay_blocking, vw, vh);
		image_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_image_view");
	}

	else if (cv == center_view_t::disassembly && g_disasm.file.loaded && (g_disasm.live_mode || g_disasm.file.decoding || !g_disasm.file.instrs.empty()))
	{
		mark_center_render_section("center_view_disassembly", cv, overlay_blocking, vw, vh);
		disasm_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3, g_disasm, dt);
		log_center_dispatch_exit("center_view_disassembly");
	}

	else if (cv == center_view_t::graph_view)
	{
		mark_center_render_section("center_view_graph_view", cv, overlay_blocking, vw, vh);
		ImVec2 wp = ImGui::GetWindowPos();
		cfg_view::render(wp.x, wp.y, vw, vh, a, ax3, ay3, az3);
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
		pseudocode_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
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
		analysis_hub_view::render(0.f, 0.f, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_analysis_hub");
	}

	else if (cv == center_view_t::binary_map)
	{
		mark_center_render_section("center_view_binary_map", cv, overlay_blocking, vw, vh);
		aida::binary_map_view::render(0, 0, vw, vh, a, ax3, ay3, az3);
		log_center_dispatch_exit("center_view_binary_map");
	}

	else if (cv == center_view_t::test_lab)
	{
		mark_center_render_section("center_view_test_lab", cv, overlay_blocking, vw, vh);
		static float s_test_lab_anim_time = 0.f;
		s_test_lab_anim_time += ImGui::GetIO().DeltaTime;
		test_lab_view::render(vw, vh, s_test_lab_anim_time);
		log_center_dispatch_exit("center_view_test_lab");
	}

	else
	{
		mark_center_render_section("center_view_empty_state", cv, overlay_blocking, vw, vh);

		ImDrawList* cdl  = ImGui::GetWindowDrawList();
		ImVec2      orig = ImGui::GetWindowPos();

		if (!overlay_blocking) {
			const char* hint = !g_disasm.file.err.empty()     ? g_disasm.file.err.c_str()
				             : !g_disasm.file.loaded           ? "Choose a file to begin"
				             :                                   "Click 'Run' to choose VM or host launch";
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
				IM_COL32(0, 0, 0, (int)(120 * anim)));


			float pw = 380.f, ph = 150.f;
			float scale = 0.92f + 0.08f * anim;
			float sw = pw * scale, sh = ph * scale;
			float px = display.x * 0.5f - sw * 0.5f;
			float py = display.y * 0.5f - sh * 0.5f - 20.f * (1.f - anim);
			float popup_alpha = anim;


			for (int s = 0; s < 4; s++) {
				float off = 4.f + s * 3.f;
				fdl->AddRectFilled(
					ImVec2(px + off, py + off),
					ImVec2(px + sw + off, py + sh + off),
					IM_COL32(0, 0, 0, (int)(30 * popup_alpha * (4 - s) / 4.f)), 12.f);
			}


			float ax3 = globals::ui::accent.x;
			float ay3 = globals::ui::accent.y;
			float az3 = globals::ui::accent.z;
			fdl->AddRectFilled(ImVec2(px, py), ImVec2(px + sw, py + sh),
				aida::ui::with_alpha(th_lp.bg_elevated, 0.96f * popup_alpha), 12.f);
			fdl->AddRect(ImVec2(px, py), ImVec2(px + sw, py + sh),
				aida::ui::with_alpha(th_lp.border_strong, popup_alpha), 12.f);


			fdl->AddRectFilled(ImVec2(px + 1.f, py + 1.f), ImVec2(px + sw - 1.f, py + 3.f),
				IM_COL32((int)(ax3 * 255), (int)(ay3 * 255), (int)(az3 * 255),
				         (int)(180 * popup_alpha)), 2.f);


			int ci = file_tabs::pending_close_idx;
			std::string fname = (ci >= 0 && ci < (int)file_tabs::tabs.size())
				? file_tabs::tabs[ci].filename : "this file";

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

	g_render_section = "right_panel";
	if (right_w > 1.f) {
	const unsigned long long right_panel_start_ms = GetTickCount64();
	g_render_section = "right_panel_begin_child";
	begin_child("##chat", ImVec2(pad + left_gap + center_w + gap, content_top), ImVec2(right_w, right_total_h), a);
	g_render_section = "right_panel_layout";


	static float s_settings_slide = 0.f;
	{
		float dt_s = ImGui::GetIO().DeltaTime;
		float slide_target = g_settings_open ? 1.f : 0.f;
		s_settings_slide += (slide_target - s_settings_slide) * (std::min)(dt_s * 12.f, 1.f);
		if (std::abs(s_settings_slide - slide_target) < 0.003f) s_settings_slide = slide_target;
	}
	bool settings_visible = g_settings_open || s_settings_slide > 0.005f;


	{
		g_render_section = "right_panel_metrics";
		float ax = globals::ui::accent.x * 255.f;
		float ay = globals::ui::accent.y * 255.f;
		float az = globals::ui::accent.z * 255.f;

		float cw = ImGui::GetWindowWidth();
		float ch = ImGui::GetWindowHeight();
		float frame_h    = ImGui::GetFrameHeight();
		float chat_scroll_y_persistent = 0.f;
		bool  chat_user_scrolled_up = false;


		float line_h     = ImGui::GetFontSize();
		float input_pad  = 10.f;
		float pill_strip_total_h = 34.f;
		int   num_lines  = 1;
		{
			for (const char* p = g_chat_buf; *p; ++p)
				if (*p == '\n') ++num_lines;

			float text_w = cw - frame_h - 4.f - 24.f;
			if (text_w > 0.f) {
				ImVec2 ts = ImGui::CalcTextSize(g_chat_buf, nullptr, false, text_w);
				int wrapped_lines = (int)((ts.y + line_h - 1.f) / line_h);
				if (wrapped_lines > num_lines) num_lines = wrapped_lines;
			}
		}
		int   max_lines  = 8;
		int   vis_lines  = std::max(1, std::min(num_lines, max_lines));
		float input_h    = vis_lines * line_h + input_pad * 2.f;
		float bot_pad    = 6.f;
		float input_y    = ch - input_h - bot_pad;
		float chat_sep_y = input_y - pill_strip_total_h - 4.f;
		float msg_area_h = chat_sep_y - 24.f;


		{
			g_render_section = "right_panel_header";
			const auto& th_ch = aida::ui::resolved();
			ImDrawList* hdr_dl = ImGui::GetWindowDrawList();
			ImVec2 wpos_ch = ImGui::GetWindowPos();
			float gear_sz = 28.f;
			float btn_gap = 6.f;
			float btn_area = gear_sz * 3.f + btn_gap * 2.f + 8.f;
			float hdr_y = 4.f;
			float hdr_h = 28.f;
			float bx = cw - btn_area;
			if (bx < 4.f) bx = 4.f;

			ImGuiStorage* hs = ImGui::GetStateStorage();

			{
				std::string title;
				for (const auto& cs : conversations::history) {
					if (cs.id == conversations::current_id) { title = cs.title; break; }
				}
				if (title.empty()) {
					title = conversations::current_id.empty() ? std::string("New chat") : std::string("Untitled");
				}

				ImFont* tf = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont();
				float tf_size = tf->FontSize > 0.f ? tf->FontSize : 14.f;
				float title_x = 8.f;
				float title_max_w = bx - title_x - 12.f;
				if (title_max_w < 40.f) title_max_w = 40.f;

				ImVec2 ts = tf->CalcTextSizeA(tf_size, FLT_MAX, 0.f, title.c_str());
				if (ts.x > title_max_w) {
					while (title.size() > 1) {
						title.pop_back();
						std::string cand = title + "...";
						if (tf->CalcTextSizeA(tf_size, FLT_MAX, 0.f, cand.c_str()).x <= title_max_w) {
							title = cand;
							break;
						}
					}
					ts = tf->CalcTextSizeA(tf_size, FLT_MAX, 0.f, title.c_str());
				}
				hdr_dl->AddText(tf, tf_size,
					ImVec2(wpos_ch.x + title_x, wpos_ch.y + hdr_y + (hdr_h - tf_size) * 0.5f),
					aida::ui::with_alpha(th_ch.text_primary, 0.92f * a),
					title.c_str());

				ImFont* cf2 = aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont();
				float cf2_size = cf2->FontSize > 0.f ? cf2->FontSize : 12.f;
				int msg_count = static_cast<int>(g_chat_messages.size());
				char meta_buf[64];
				if (msg_count <= 0) std::snprintf(meta_buf, sizeof(meta_buf), "Ready");
				else if (msg_count == 1) std::snprintf(meta_buf, sizeof(meta_buf), "1 message");
				else std::snprintf(meta_buf, sizeof(meta_buf), "%d messages", msg_count);
				ImVec2 meta_ts = cf2->CalcTextSizeA(cf2_size, FLT_MAX, 0.f, meta_buf);
				float meta_x = wpos_ch.x + title_x + ts.x + 12.f;
				if (meta_x + meta_ts.x < wpos_ch.x + bx - 12.f) {
					hdr_dl->AddText(cf2, cf2_size,
						ImVec2(meta_x, wpos_ch.y + hdr_y + (hdr_h - cf2_size) * 0.5f),
						aida::ui::with_alpha(th_ch.text_dim, 0.85f * a),
						meta_buf);
				}
			}

			ImFont* icon_font = aida::ui::fonts::body_strong();
			const float icon_fs = gear_sz * 0.52f;
			auto draw_circle_btn = [&](const char* label, const char* tip,
				const char* icon_render, float bx_local, float by_local,
				ImU32 icon_col_resting) -> bool
			{
				ImVec2 ba(wpos_ch.x + bx_local, wpos_ch.y + by_local);
				ImVec2 bb(ba.x + gear_sz, ba.y + gear_sz);
				ImGui::SetCursorPos(ImVec2(bx_local, by_local));
				ImGui::SetNextItemAllowOverlap();
				ImGui::InvisibleButton(label, ImVec2(gear_sz, gear_sz));
				bool hov = ImGui::IsItemHovered();
				bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGuiID hid = ImGui::GetID(label);
				float hv = hs->GetFloat(hid, 0.f);
				hv += ((hov ? 1.f : 0.f) - hv) * std::min(12.f * dt, 1.f);
				hs->SetFloat(hid, hv);
				if (hv > 0.01f) {
					hdr_dl->AddRectFilled(ba, bb,
						aida::ui::with_alpha(th_ch.hover_wash, hv * a), gear_sz * 0.5f);
				}
				ImU32 ic = aida::ui::mix(icon_col_resting, th_ch.text_primary, hv);
				ImVec2 ic_ts = icon_font->CalcTextSizeA(icon_fs, FLT_MAX, 0.f, icon_render);
				hdr_dl->AddText(icon_font, icon_fs,
					ImVec2((ba.x + bb.x) * 0.5f - ic_ts.x * 0.5f,
					       (ba.y + bb.y) * 0.5f - ic_ts.y * 0.5f),
					aida::ui::with_alpha(ic, a), icon_render);
				if (hov) {
					ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
					if (tip) ImGui::SetTooltip("%s", tip);
				}
				return clicked;
			};

			if (draw_circle_btn("##chat_history", "Conversation history", "H", bx, hdr_y, th_ch.text_primary)) {
				conversations::refresh_history();
				conversations::browser_open = !conversations::browser_open;
			}
			bx += gear_sz + btn_gap;
			if (draw_circle_btn("##new_chat", "New chat", "+", bx, hdr_y, th_ch.text_primary)) {
				conversations::new_chat();
			}
			bx += gear_sz + btn_gap;
			if (draw_circle_btn("##chat_settings", "AI Settings", ICON_COG, bx, hdr_y, th_ch.text_primary)) {
				g_settings_open = true;
			}
			ImGui::SetCursorPosY(hdr_y + hdr_h);
		}


		g_render_section = conversations::browser_open ? "right_panel_history" : "right_panel_messages";
		if (conversations::browser_open) {
			static float history_appear = 0.f;
			static float history_appear_v = 0.f;
			history_appear = aida::motion::spring_step(history_appear, 1.f, history_appear_v,
				aida::motion::spring::balanced, dt);

			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
			ImGui::BeginChild("##history_panel", ImVec2(cw, msg_area_h), false,
				ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

			ImDrawList* hdl = ImGui::GetWindowDrawList();
			ImVec2 hp = ImGui::GetWindowPos();
			const auto& hth = aida::ui::resolved();
			{
				ImVec2 ha(hp.x, hp.y);
				ImVec2 hb(hp.x + cw, hp.y + msg_area_h);
				aida::ui::blur::layer_request_t hr;
				hr.pos = ha; hr.size = ImVec2(cw, msg_area_h);
				hr.radius = 10.f; hr.strength = 0.6f; hr.alpha = history_appear * a;
				aida::ui::blur::schedule(hr);
				aida::ui::blur::render_glass_fill(hdl, ha, hb, 10.f, history_appear * a);
				aida::ui::blur::render_glass_border(hdl, ha, hb, 10.f, history_appear * a, 1.f);

			}

			float pad = 8.f;
			float header_h = 32.f;

			hdl->AddText(ImVec2(hp.x + pad + 2.f, hp.y + (header_h - ImGui::GetFontSize()) * 0.5f),
				aida::ui::with_alpha(hth.text_primary, 0.86f * history_appear * a), "Conversations");

			float close_sz = 20.f;
			float close_x = hp.x + cw - close_sz - pad;
			float close_y = hp.y + (header_h - close_sz) * 0.5f;
			ImVec2 cmin(close_x, close_y);
			ImVec2 cmax(close_x + close_sz, close_y + close_sz);
			bool close_hov = ImGui::IsMouseHoveringRect(cmin, cmax);
			hdl->AddRectFilled(cmin, cmax,
				aida::ui::with_alpha(hth.hover_wash, close_hov ? a : 0.f), 4.f);
			float cx_m = 5.f;
			hdl->AddLine(ImVec2(cmin.x + cx_m, cmin.y + cx_m), ImVec2(cmax.x - cx_m, cmax.y - cx_m),
				aida::ui::with_alpha(hth.text_secondary, 0.9f * a), 1.5f);
			hdl->AddLine(ImVec2(cmax.x - cx_m, cmin.y + cx_m), ImVec2(cmin.x + cx_m, cmax.y - cx_m),
				aida::ui::with_alpha(hth.text_secondary, 0.9f * a), 1.5f);
			ImGui::SetCursorPos(ImVec2(cw - close_sz - pad, (header_h - close_sz) * 0.5f));
			if (ImGui::InvisibleButton("##hist_close", ImVec2(close_sz, close_sz))) {
				conversations::browser_open = false;
				history_appear = 0.f;
			}

			float sep_y = hp.y + header_h;
			hdl->AddLine(ImVec2(hp.x + pad, sep_y), ImVec2(hp.x + cw - pad, sep_y),
				aida::ui::with_alpha(hth.border_subtle, a));

			static char hist_filter[64] = {};
			ImGui::SetCursorPos(ImVec2(pad, header_h + 4.f));
			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(hth.bg_base, 0.8f)));
			ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(hth.border_subtle));
			ImGui::SetNextItemWidth(cw - pad * 2.f);
			ImGui::InputTextWithHint("##hist_search", "Search conversations...", hist_filter, sizeof(hist_filter));
			ImGui::PopStyleColor(2);
			ImGui::PopStyleVar(2);

			float search_h = ImGui::GetItemRectSize().y + 8.f;
			float list_top = header_h + 4.f + search_h;

			std::string filter_lower;
			for (const char* p = hist_filter; *p; p++)
				filter_lower += static_cast<char>(tolower(*p));

			ImGui::SetCursorPos(ImVec2(0, list_top));
			ImGui::BeginChild("##hist_scroll", ImVec2(cw, msg_area_h - list_top), false);

			ImDrawList* ldl = ImGui::GetWindowDrawList();
			ImVec2 lp = ImGui::GetWindowPos();
			ImGuiStorage* hs = ImGui::GetStateStorage();
			float ly = 0.f;
			float card_h = 56.f;
			float card_gap = 4.f;
			float card_pad = pad;
			float card_w = cw - card_pad * 2.f;
			int visible_count = 0;

			for (int i = 0; i < static_cast<int>(conversations::history.size()); i++) {
				auto& c = conversations::history[i];

				if (!filter_lower.empty()) {
					std::string title_lower;
					std::string t = c.title.empty() ? "untitled" : c.title;
					for (char ch2 : t) title_lower += static_cast<char>(tolower(ch2));
					if (title_lower.find(filter_lower) == std::string::npos)
						continue;
				}

				bool is_current = (c.id == conversations::current_id);

				ImGuiID hov_id = ImGui::GetID(("hist_hov_" + std::to_string(i)).c_str());
				float hov_t = hs->GetFloat(hov_id, 0.f);

				ImVec2 card_min(lp.x + card_pad, lp.y + ly - ImGui::GetScrollY());
				ImVec2 card_max(card_min.x + card_w, card_min.y + card_h);

				bool card_hov = ImGui::IsMouseHoveringRect(card_min, card_max);
				hov_t += ((card_hov ? 1.f : 0.f) - hov_t) * std::min(12.f * dt, 1.f);
				hs->SetFloat(hov_id, hov_t);

				float item_alpha = std::min(history_appear * 3.f - static_cast<float>(visible_count) * 0.15f, 1.f);
				if (item_alpha < 0.f) item_alpha = 0.f;
				float ia = item_alpha * a;

				ImU32 card_bg = is_current
					? IM_COL32(static_cast<int>(ax * 0.15f), static_cast<int>(ay * 0.15f), static_cast<int>(az * 0.15f), static_cast<int>((100 + 30 * hov_t) * ia))
					: aida::ui::with_alpha(aida::ui::resolved().hover_wash, (0.33f + 0.67f * hov_t) * ia);
				ldl->AddRectFilled(card_min, card_max, card_bg, 8.f);

				if (is_current) {
					ldl->AddRect(card_min, card_max,
						IM_COL32(static_cast<int>(ax), static_cast<int>(ay), static_cast<int>(az), static_cast<int>(100 * ia)), 8.f, 0, 1.2f);
				} else {
					ldl->AddRect(card_min, card_max,
						aida::ui::with_alpha(aida::ui::resolved().border_subtle, (0.4f + 0.6f * hov_t) * ia), 8.f, 0, 0.6f);
				}

				std::string title = c.title.empty() ? "Untitled" : c.title;
				float title_max_w = card_w - 50.f;
				ImVec2 title_ts = ImGui::CalcTextSize(title.c_str());
				if (title_ts.x > title_max_w) {
					while (title.size() > 3 && ImGui::CalcTextSize(title.c_str()).x > title_max_w - 20.f)
						title.pop_back();
					title += "...";
				}

				ImU32 title_col = is_current
					? IM_COL32(static_cast<int>(ax), static_cast<int>(ay), static_cast<int>(az), static_cast<int>(240 * ia))
					: aida::ui::with_alpha(aida::ui::resolved().text_primary, ia);
				ldl->AddText(ImVec2(card_min.x + 12.f, card_min.y + 10.f), title_col, title.c_str());

				char meta[64];
				snprintf(meta, sizeof(meta), "%d messages", c.msg_count);
				ldl->AddText(ImVec2(card_min.x + 12.f, card_min.y + 10.f + ImGui::GetFontSize() + 4.f),
					aida::ui::with_alpha(aida::ui::resolved().text_dim, ia), meta);

				float del_sz = 22.f;
				float del_x = card_max.x - del_sz - 8.f;
				float del_y = card_min.y + (card_h - del_sz) * 0.5f;
				ImVec2 dmin(del_x, del_y);
				ImVec2 dmax(del_x + del_sz, del_y + del_sz);
				bool del_hov = ImGui::IsMouseHoveringRect(dmin, dmax) && card_hov;

				if (hov_t > 0.1f) {
					ldl->AddRectFilled(dmin, dmax,
						aida::ui::with_alpha(aida::ui::resolved().error, del_hov ? 0.2f * ia : 0.08f * hov_t * ia), 4.f);
					float dm = 6.f;
					ImU32 del_col = aida::ui::with_alpha(aida::ui::resolved().error, (0.47f + 0.31f * (del_hov ? 1.f : 0.f)) * hov_t * ia);
					ldl->AddLine(ImVec2(dmin.x + dm, dmin.y + dm), ImVec2(dmax.x - dm, dmax.y - dm), del_col, 1.5f);
					ldl->AddLine(ImVec2(dmax.x - dm, dmin.y + dm), ImVec2(dmin.x + dm, dmax.y - dm), del_col, 1.5f);
				}

				ImGui::SetCursorPos(ImVec2(card_pad, ly));
				if (ImGui::InvisibleButton(("##hcard_" + c.id).c_str(), ImVec2(card_w - del_sz - 12.f, card_h))) {
					if (!is_current) {
						conversations::save_current();
						conversations::load_conversation(c.id);
						conversations::browser_open = false;
						history_appear = 0.f;
					}
				}

				ImGui::SetCursorPos(ImVec2(card_w + card_pad - del_sz - 8.f, ly + (card_h - del_sz) * 0.5f));
				if (ImGui::InvisibleButton(("##hdel_" + std::to_string(i)).c_str(), ImVec2(del_sz, del_sz))) {
					conversations::delete_conversation(c.id);
					if (is_current) {
						g_chat_messages.clear();
						conversations::current_id.clear();
					}
					conversations::refresh_history();
				}

				ly += card_h + card_gap;
				visible_count++;
			}

			if (visible_count == 0) {
				const char* empty_text = filter_lower.empty()
					? "No saved conversations"
					: "No matching conversations";
				ImVec2 ets = ImGui::CalcTextSize(empty_text);
				float ey = (msg_area_h - list_top) * 0.35f;
				ldl->AddText(ImVec2(lp.x + (cw - ets.x) * 0.5f, lp.y + ey),
					aida::ui::with_alpha(aida::ui::resolved().text_dim, 0.7f * a), empty_text);
			}

			ImGui::SetCursorPos(ImVec2(0, ly));
			ImGui::EndChild();
			ImGui::EndChild();
			ImGui::PopStyleVar();
		} else {

		g_render_section = "right_panel_messages_begin";
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
		ImGui::BeginChild("##chat_msgs", ImVec2(cw, msg_area_h), false,
			ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2      wp2 = ImGui::GetWindowPos();
		wp2.y -= ImGui::GetScrollY();
		ImGuiStorage* s = ImGui::GetStateStorage();
		const auto& th_msg = aida::ui::resolved();

		float cursor_y = 6.f;

		g_render_section = "right_panel_messages_loop";
		for (int mi = 0; mi < (int)g_chat_messages.size(); mi++)
		{
			g_render_section = "right_panel_message_dispatch";
			auto& msg = g_chat_messages[mi];


			ImGuiID appear_id = ImGui::GetID(("appear_" + std::to_string(mi)).c_str());
			float   appear = s->GetFloat(appear_id, 0.f);
			appear += (1.f - appear) * std::min(9.f * ImGui::GetIO().DeltaTime, 1.f);
			s->SetFloat(appear_id, appear);

			float wrap_w = cw - 20.f;

			if (msg.is_user && msg.text.find("<plan_exit_handoff>") != std::string::npos)
			{
				std::string rendered = msg.text;
				size_t spos = rendered.find("<plan_exit_handoff>");
				if (spos != std::string::npos) rendered.erase(spos, sizeof("<plan_exit_handoff>") - 1);
				while (!rendered.empty() && (rendered.back() == '\n' || rendered.back() == ' '))
					rendered.pop_back();
				std::string display = "[plan -> build]";
				if (!rendered.empty()) display += "\n" + rendered;

				ImVec2 ts = ImGui::CalcTextSize(display.c_str(), nullptr, false, wrap_w * 0.78f);
				float bw = ts.x + 16.f;
				float bh = ts.y + 10.f;
				float target_x = (cw - bw) * 0.5f;
				float bx = target_x;
				float by = cursor_y;
				ImVec2 bmin = ImVec2(wp2.x + bx, wp2.y + by);
				ImVec2 bmax = ImVec2(bmin.x + bw, bmin.y + bh);
				dl->AddRectFilled(bmin, bmax,
					IM_COL32((int)(ax * 0.30f + 30), (int)(ay * 0.30f + 25), (int)(az * 0.30f + 60),
						(int)(200 * appear * a)), 8.f);
				dl->AddRect(bmin, bmax,
					IM_COL32((int)(ax * 0.7f), (int)(ay * 0.7f), (int)(az * 0.9f),
						(int)(120 * appear * a)), 8.f, 0, 1.5f);
				dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
					ImVec2(bmin.x + 8.f, bmin.y + 5.f),
					aida::ui::with_alpha(th_msg.text_primary, 0.96f * appear * a),
					display.c_str(), nullptr, wrap_w * 0.78f);
				cursor_y += bh + 8.f;
			}
			else if (msg.is_user)
			{

				if (chat_edit::active && chat_edit::msg_idx == mi) {
					float edit_w = wrap_w - 8.f;
					float edit_pad = 8.f;
					float by = cursor_y;


					ImVec2 edit_ts = ImGui::CalcTextSize(chat_edit::buf, nullptr, false, edit_w - 24.f);
					float text_h = std::max(edit_ts.y + 8.f, ImGui::GetFontSize() * 2.f + 8.f);
					float model_row_h = 22.f;
					float total_edit_h = edit_pad + text_h + edit_pad + model_row_h + edit_pad;

					ImVec2 bmin = ImVec2(wp2.x + 4.f, wp2.y + by);
					ImVec2 bmax = ImVec2(bmin.x + edit_w, bmin.y + total_edit_h);


					dl->AddRectFilled(bmin, bmax,
						IM_COL32((int)(ax * 0.15f + 20), (int)(ay * 0.15f + 15), (int)(az * 0.15f + 30),
							(int)(240 * appear * a)), 8.f);
					dl->AddRect(bmin, bmax,
						IM_COL32((int)(ax * 0.7f), (int)(ay * 0.7f), (int)(az * 0.7f),
							(int)(120 * appear * a)), 8.f, 0, 1.f);


					ImGui::SetCursorPos(ImVec2(4.f + edit_pad, by + edit_pad - ImGui::GetScrollY() + ImGui::GetWindowPos().y - wp2.y - ImGui::GetWindowPos().y));

					float input_y_screen = bmin.y + edit_pad;
					ImGui::SetCursorScreenPos(ImVec2(bmin.x + edit_pad, input_y_screen));
					ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4.f, 4.f));
					ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
					ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
					ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(th_msg.text_primary, 0.94f * a));
					ImGui::PushItemWidth(edit_w - edit_pad * 2.f - 40.f);
					ImGui::InputTextMultiline("##chat_edit_input", chat_edit::buf,
						sizeof(chat_edit::buf),
						ImVec2(edit_w - edit_pad * 2.f - 40.f, text_h),
						ImGuiInputTextFlags_CtrlEnterForNewLine);
					bool send_edit = ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter, false)
						&& !ImGui::GetIO().KeyShift && !ImGui::GetIO().KeyCtrl;
					ImGui::PopItemWidth();
					ImGui::PopStyleColor(2);
					ImGui::PopStyleVar(2);


					float row_y = bmin.y + edit_pad + text_h + 4.f;
					float row_x = bmin.x + edit_pad;


					const char* model_name = g_sa_settings.active_provider_profile_id.empty()
						? "No Model" : nullptr;
					std::string model_display;
					if (!model_name) {
						for (auto& pp : g_sa_settings.provider_profiles) {
							if (pp.id == g_sa_settings.active_provider_profile_id) {
								model_display = pp.display_name + " / " + pp.model;
								break;
							}
						}
						if (model_display.empty()) model_display = "No Model";
					} else {
						model_display = model_name;
					}
					ImVec2 mts = ImGui::CalcTextSize(model_display.c_str());
					dl->AddRectFilled(ImVec2(row_x, row_y), ImVec2(row_x + mts.x + 12.f, row_y + model_row_h - 2.f),
						aida::ui::with_alpha(th_msg.bg_overlay, 0.78f * a), 4.f);
					dl->AddText(ImVec2(row_x + 6.f, row_y + 2.f),
						aida::ui::with_alpha(th_msg.text_secondary, a), model_display.c_str());


					const char* send_label = "Send";
					ImVec2 sts2 = ImGui::CalcTextSize(send_label);
					float send_w = sts2.x + 16.f;
					float send_x = bmax.x - edit_pad - send_w;
					ImVec2 smin(send_x, row_y);
					ImVec2 smax(send_x + send_w, row_y + model_row_h - 2.f);
					bool send_hov = ImGui::IsMouseHoveringRect(smin, smax);

					ImGuiID send_anim_id = ImGui::GetID("##chat_edit_send_anim");
					float send_anim = s->GetFloat(send_anim_id, 0.f);
					send_anim += ((send_hov ? 1.f : 0.f) - send_anim) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(send_anim_id, send_anim);

					dl->AddRectFilled(smin, smax,
						IM_COL32((int)(ax * (0.5f + 0.3f * send_anim)),
								 (int)(ay * (0.5f + 0.3f * send_anim)),
								 (int)(az * (0.5f + 0.3f * send_anim)),
								 (int)((180 + 60 * send_anim) * a)), 4.f);
					dl->AddText(ImVec2(smin.x + 8.f, smin.y + 2.f),
						aida::ui::with_alpha(th_msg.text_primary, 0.96f * a), send_label);


					if ((send_hov && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) || send_edit) {

						std::string new_text(chat_edit::buf);
						if (!new_text.empty()) {

							g_chat_messages.erase(g_chat_messages.begin() + mi, g_chat_messages.end());

							ChatMessage um;
							um.text = new_text;
							um.is_user = true;
							um.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
								std::chrono::system_clock::now().time_since_epoch()).count();
							g_chat_messages.push_back(um);
							g_chat_scroll_to_bottom = true;
						}
						chat_edit::active = false;
						chat_edit::msg_idx = -1;
					}


					if (!ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
						!ImGui::IsMouseHoveringRect(bmin, bmax) && !send_hov) {
						chat_edit::active = false;
						chat_edit::msg_idx = -1;
					}


					if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
						chat_edit::active = false;
						chat_edit::msg_idx = -1;
					}

					cursor_y += total_edit_h + 8.f;
				}
				else
				{


				ImVec2 ts = ImGui::CalcTextSize(msg.text.c_str(), nullptr, false, wrap_w * 0.78f);
				float  bw = ts.x + 16.f;
				float  bh = ts.y + 10.f;


				float target_x = cw - bw - 8.f;
				float bx = target_x + (1.f - appear) * 40.f;
				float by = cursor_y;


				ImVec2 bmin = ImVec2(wp2.x + bx, wp2.y + by);
				ImVec2 bmax = ImVec2(bmin.x + bw, bmin.y + bh);


				ImGuiID uhov_id = ImGui::GetID(("uhov_" + std::to_string(mi)).c_str());
				float uhov_a = s->GetFloat(uhov_id, 0.f);
				bool user_msg_hov = ImGui::IsMouseHoveringRect(bmin, bmax);
				uhov_a += ((user_msg_hov ? 1.f : 0.f) - uhov_a) * std::min(10.f * ImGui::GetIO().DeltaTime, 1.f);
				s->SetFloat(uhov_id, uhov_a);

				dl->AddRectFilled(bmin, bmax,
					IM_COL32((int)(ax * 0.22f + 18), (int)(ay * 0.22f + 12), (int)(az * 0.22f + 28),
						(int)((220 + uhov_a * 25.f) * appear * a)), 8.f);


				if (uhov_a > 0.01f) {
					dl->AddRect(bmin, bmax,
						IM_COL32((int)(ax * 0.6f), (int)(ay * 0.6f), (int)(az * 0.6f),
							(int)(uhov_a * 60.f * appear * a)), 8.f, 0, 1.f);
				}

				dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
					ImVec2(bmin.x + 8.f, bmin.y + 5.f),
					aida::ui::with_alpha(th_msg.text_primary, 0.94f * appear * a),
					msg.text.c_str(), nullptr, wrap_w * 0.78f);


				if (user_msg_hov && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					chat_edit::active = true;
					chat_edit::msg_idx = mi;
					strncpy_s(chat_edit::buf, msg.text.c_str(), _TRUNCATE);
				}


				if (user_msg_hov && !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
					ImGui::OpenPopup(("##user_msg_ctx_" + std::to_string(mi)).c_str());
				}
				if (ImGui::BeginPopup(("##user_msg_ctx_" + std::to_string(mi)).c_str())) {
					if (ImGui::MenuItem("Copy"))
						ImGui::SetClipboardText(msg.text.c_str());
					if (ImGui::MenuItem("Edit")) {
						chat_edit::active = true;
						chat_edit::msg_idx = mi;
						strncpy_s(chat_edit::buf, msg.text.c_str(), _TRUNCATE);
					}
					if (ImGui::MenuItem("Delete")) {
						g_chat_messages.erase(g_chat_messages.begin() + mi);
						mi--;
						ImGui::EndPopup();
						continue;
					}
					ImGui::EndPopup();
				}


				{
					ImGuiID mtime_id = ImGui::GetID(("mtu_" + std::to_string(mi)).c_str());
					float mtime = s->GetFloat(mtime_id, -1.f);
					if (mtime < 0.f) { mtime = (float)ImGui::GetTime(); s->SetFloat(mtime_id, mtime); }
					float elapsed = (float)ImGui::GetTime() - mtime;
					char ts_buf[16];
					if (elapsed < 60.f)        snprintf(ts_buf, sizeof(ts_buf), "just now");
					else if (elapsed < 3600.f) snprintf(ts_buf, sizeof(ts_buf), "%.0fm ago", elapsed / 60.f);
					else                       snprintf(ts_buf, sizeof(ts_buf), "%.0fh ago", elapsed / 3600.f);

					ImGuiID hov_id = ImGui::GetID(("mhu_" + std::to_string(mi)).c_str());
					float hov_a = s->GetFloat(hov_id, 0.f);
					hov_a += ((ImGui::IsMouseHoveringRect(bmin, bmax) ? 1.f : 0.f) - hov_a)
						* std::min(8.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(hov_id, hov_a);

					if (hov_a > 0.01f)
					{
						ImVec2 tts2 = ImGui::CalcTextSize(ts_buf);

						dl->AddText(
							ImVec2(bmin.x - tts2.x - 6.f, bmin.y + (bh - tts2.y) * 0.5f),
							aida::ui::with_alpha(th_msg.text_dim, hov_a * appear * a), ts_buf);
					}
				}

				cursor_y += bh + 18.f;
				}
			}
			else
			{
				if (msg.has_thinking)
				{
					const bool still_thinking = !g_ai_thinking_active && mi == (int)g_chat_messages.size() - 1;

					ImGuiID tid = ImGui::GetID(("think_open_" + std::to_string(mi)).c_str());
					bool    open = s->GetBool(tid, false);

					ImGuiID toa = ImGui::GetID(("toa_" + std::to_string(mi)).c_str());
					float   topen = s->GetFloat(toa, 0.f);
					topen += ((open ? 1.f : 0.f) - topen) * std::min(11.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(toa, topen);

					ImGuiID tstart_id = ImGui::GetID(("tstart_" + std::to_string(mi)).c_str());
					float   tstart    = s->GetFloat(tstart_id, -1.f);
					if (still_thinking && tstart < 0.f) { tstart = (float)ImGui::GetTime(); s->SetFloat(tstart_id, tstart); }
					ImGuiID tdur_id   = ImGui::GetID(("tdur_" + std::to_string(mi)).c_str());
					float   tdur      = s->GetFloat(tdur_id, -1.f);
					if (!still_thinking && tstart > 0.f && tdur < 0.f) { tdur = (float)ImGui::GetTime() - tstart; s->SetFloat(tdur_id, tdur); }

					ImFont* tlabel_font = aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont();
					float   tlabel_fs   = tlabel_font->FontSize > 0.f ? tlabel_font->FontSize : 13.f;
					ImFont* tbody_font  = aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont();
					float   tbody_fs    = tbody_font->FontSize > 0.f ? tbody_font->FontSize : 14.f;

					char think_label[64];
					if (still_thinking) {
						snprintf(think_label, sizeof(think_label), "Thinking");
					} else if (tdur > 0.f) {
						const float secs = tdur;
						if (secs < 1.f)
							snprintf(think_label, sizeof(think_label), "Thought for less than a second");
						else if (secs < 60.f)
							snprintf(think_label, sizeof(think_label), "Thought for %ds", (int)secs);
						else
							snprintf(think_label, sizeof(think_label), "Thought for %dm %ds", (int)(secs / 60.f), (int)secs % 60);
					} else {
						snprintf(think_label, sizeof(think_label), "Show reasoning");
					}

					ImVec2 label_ts = tlabel_font->CalcTextSizeA(tlabel_fs, FLT_MAX, 0.f, think_label);
					const float pill_h   = 22.f;
					const float pad_l    = 10.f;
					const float pad_r    = 8.f;
					const float dot_block_w = 18.f;
					const float chev_w   = 12.f;
					const float gap      = 6.f;
					float  pill_w   = pad_l + dot_block_w + gap + label_ts.x + gap + chev_w + pad_r;
					float  vis_a    = appear * a;

					ImVec2 pmin = ImVec2(wp2.x + 6.f, wp2.y + cursor_y);
					ImVec2 pmax = ImVec2(pmin.x + pill_w, pmin.y + pill_h);

					ImGuiID phov_id = ImGui::GetID(("thp_hov_" + std::to_string(mi)).c_str());
					float   phov_t  = s->GetFloat(phov_id, 0.f);
					bool phover = !ui_input_gate::popup_blocks_background_input() && ImGui::IsMouseHoveringRect(pmin, pmax);
					phov_t += ((phover ? 1.f : 0.f) - phov_t) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(phov_id, phov_t);

					if (phover && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					{
						s->SetBool(tid, !open); open = !open;
					}
					if (phover)
						ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

					dl->AddRectFilled(pmin, pmax,
						aida::ui::with_alpha(th_msg.panel_header, (0.62f + 0.30f * phov_t) * vis_a), pill_h * 0.5f);
					dl->AddRect(pmin, pmax,
						aida::ui::with_alpha(th_msg.border_subtle, (0.55f + 0.35f * phov_t) * vis_a), pill_h * 0.5f, 0, 0.7f);

					{
						const float dot_cy = pmin.y + pill_h * 0.5f;
						const float dot_cx0 = pmin.x + pad_l + 2.f;
						const float spacing = 5.f;
						const float dot_r = 1.7f;
						const float t = (float)ImGui::GetTime();
						for (int di = 0; di < 3; ++di) {
							float ph = t * 4.f - (float)di * 0.55f;
							float s_pulse = 0.5f + 0.5f * sinf(ph);
							float dot_a = still_thinking ? (0.35f + 0.65f * s_pulse) : 0.55f;
							ImU32 dot_col = aida::ui::with_alpha(th_msg.accent_u32, dot_a * vis_a);
							dl->AddCircleFilled(ImVec2(dot_cx0 + (float)di * spacing, dot_cy), dot_r, dot_col, 8);
						}
					}

					ImU32 label_col = still_thinking
						? aida::ui::with_alpha(th_msg.text_primary, (0.85f + 0.15f * phov_t) * vis_a)
						: aida::ui::with_alpha(th_msg.text_secondary, (0.80f + 0.20f * phov_t) * vis_a);
					if (still_thinking) {
						const float t = (float)ImGui::GetTime();
						const float pulse = 0.78f + 0.22f * (0.5f + 0.5f * sinf(t * 2.4f));
						label_col = aida::ui::with_alpha(th_msg.text_primary, pulse * vis_a);
					}
					dl->AddText(tlabel_font, tlabel_fs,
						ImVec2(pmin.x + pad_l + dot_block_w + gap, pmin.y + (pill_h - label_ts.y) * 0.5f),
						label_col, think_label);

					{
						const float chev_cx = pmax.x - pad_r - chev_w * 0.5f;
						const float chev_cy = pmin.y + pill_h * 0.5f;
						const float ext = 3.2f;
						const float ease = topen;
						ImU32 chev_col = aida::ui::with_alpha(th_msg.text_secondary, (0.80f + 0.20f * phov_t) * vis_a);

						const float collapsed_lx = chev_cx - ext * 0.6f;
						const float collapsed_ly_top = chev_cy - ext;
						const float collapsed_ly_bot = chev_cy + ext;
						const float collapsed_tx = chev_cx + ext * 0.6f;
						const float collapsed_ty = chev_cy;

						const float expanded_lx = chev_cx - ext;
						const float expanded_ly = chev_cy - ext * 0.6f;
						const float expanded_tx = chev_cx;
						const float expanded_ty = chev_cy + ext * 0.6f;
						const float expanded_rx = chev_cx + ext;
						const float expanded_ry = chev_cy - ext * 0.6f;

						ImVec2 p_top(
							collapsed_lx + (expanded_lx - collapsed_lx) * ease,
							collapsed_ly_top + (expanded_ly - collapsed_ly_top) * ease);
						ImVec2 p_tip(
							collapsed_tx + (expanded_tx - collapsed_tx) * ease,
							collapsed_ty + (expanded_ty - collapsed_ty) * ease);
						ImVec2 p_bot(
							collapsed_lx + (expanded_rx - collapsed_lx) * ease,
							collapsed_ly_bot + (expanded_ry - collapsed_ly_bot) * ease);

						dl->AddLine(p_top, p_tip, chev_col, 1.4f);
						dl->AddLine(p_bot, p_tip, chev_col, 1.4f);
					}

					cursor_y += pill_h + 4.f;

					if ((topen > 0.01f || open) && !msg.thinking_text.empty())
					{
						const float body_pad_x = 14.f;
						const float body_pad_y = 8.f;
						const float body_pad_l = 18.f;
						const float body_x     = 16.f;
						const float body_w     = std::max(80.f, cw - body_x - 8.f);
						const float text_w     = std::max(40.f, body_w - body_pad_l - body_pad_x);

						ImVec2 text_ts = tbody_font->CalcTextSizeA(tbody_fs, FLT_MAX, text_w, msg.thinking_text.c_str());
						float full_bk_h = text_ts.y + body_pad_y * 2.f;

						ImGuiID bkha = ImGui::GetID(("bkh_" + std::to_string(mi)).c_str());
						float   bk_h = s->GetFloat(bkha, 0.f);
						const float target_h = open ? full_bk_h : 0.f;
						bk_h += (target_h - bk_h) * std::min(11.f * ImGui::GetIO().DeltaTime, 1.f);
						s->SetFloat(bkha, bk_h);

						if (bk_h > 0.5f)
						{
							ImVec2 bkmin = ImVec2(wp2.x + body_x, wp2.y + cursor_y);
							ImVec2 bkmax = ImVec2(bkmin.x + body_w, bkmin.y + bk_h);

							dl->PushClipRect(bkmin, bkmax, true);

							ImU32 chain_col = aida::ui::with_alpha(th_msg.border_strong, topen * vis_a);
							const float chain_x = bkmin.x + 7.5f;
							const float chain_top = bkmin.y + 2.f;
							const float chain_bot = bkmax.y - 2.f;
							const float fade_len = 14.f;
							const float chain_full_h = (chain_bot - chain_top);
							if (chain_full_h > 1.f) {
								const int segs = 16;
								for (int si = 0; si < segs; ++si) {
									float y0 = chain_top + chain_full_h * ((float)si / (float)segs);
									float y1 = chain_top + chain_full_h * ((float)(si + 1) / (float)segs);
									float mid = (y0 + y1) * 0.5f;
									float fade = 1.f;
									if (mid - chain_top < fade_len)
										fade = std::max(0.f, (mid - chain_top) / fade_len);
									else if (chain_bot - mid < fade_len)
										fade = std::max(0.f, (chain_bot - mid) / fade_len);
									dl->AddLine(ImVec2(chain_x, y0), ImVec2(chain_x, y1),
										aida::ui::with_alpha(chain_col, fade), 1.f);
								}
							}

							const float text_x = bkmin.x + body_pad_l;
							const float text_y = bkmin.y + body_pad_y;
							ImU32 body_text_col = aida::ui::with_alpha(th_msg.text_secondary, topen * vis_a);
							dl->AddText(tbody_font, tbody_fs,
								ImVec2(text_x, text_y), body_text_col,
								msg.thinking_text.c_str(), nullptr, text_w);

							dl->PopClipRect();

							cursor_y += bk_h + 6.f;
						}
					}
				}

				if (!msg.text.empty() || msg.streaming)
				{

					float rich_max_w = wrap_w * 0.86f;


					ImGuiID fda = ImGui::GetID(("fda_" + std::to_string(mi)).c_str());
					float   falpha = s->GetFloat(fda, 0.f);
					falpha += (1.f - falpha) * std::min(6.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(fda, falpha);

					float bx = 6.f;
					float by = cursor_y;


					g_render_section = "right_panel_message_parse";
					auto spans = chat_render::parse_markdown(msg.text);
					bool has_code_blocks = false;
					for (auto& sp : spans)
						if (sp.type == chat_render::span_type::code_block) { has_code_blocks = true; break; }


					ImVec2 plain_ts = msg.text.empty()
						? ImVec2(0.f, ImGui::GetFontSize())
						: ImGui::CalcTextSize(msg.text.c_str(), nullptr, false, rich_max_w);


					float est_h = plain_ts.y + 10.f;
					if (has_code_blocks) est_h *= 1.5f;


					ImGuiID bwa = ImGui::GetID(("bw_" + std::to_string(mi)).c_str());
					ImGuiID bha = ImGui::GetID(("bh_" + std::to_string(mi)).c_str());
					float   bw = s->GetFloat(bwa, 10.f);
					float   anim_bh = s->GetFloat(bha, est_h);
					float target_bw = rich_max_w + 16.f;
					bw += (target_bw - bw) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(bwa, bw);

					ImVec2 bmin = ImVec2(wp2.x + bx, wp2.y + by);


					g_render_section = "right_panel_message_render";
					auto rr = chat_render::render_rich_message(
						dl, bmin, bw, msg.text,
						falpha * a, ax, ay, az,
						mi, ImGui::GetIO().DeltaTime, !msg.streaming);
					g_render_section = "right_panel_messages_loop";

					float real_h = std::max(rr.height, ImGui::GetFontSize() + 10.f);


					anim_bh += (real_h - anim_bh) * std::min(12.f * ImGui::GetIO().DeltaTime, 1.f);
					s->SetFloat(bha, anim_bh);


					ImVec2 bmax = ImVec2(bmin.x + bw, bmin.y + anim_bh);


					if (rr.action == chat_render::action_t::retry && mi > 0) {

						for (int ri = mi - 1; ri >= 0; ri--) {
							if (g_chat_messages[ri].is_user) {
								strncpy_s(g_chat_buf, g_chat_messages[ri].text.c_str(), _TRUNCATE);
								g_chat_messages.push_back({ g_chat_buf, "", true, false, false });
								g_chat_scroll_to_bottom = true;
								g_chat_buf[0] = '\0';
								break;
							}
						}
					} else if (rr.action == chat_render::action_t::delete_msg) {
						if (mi >= 0 && mi < (int)g_chat_messages.size()) {
							g_chat_messages.erase(g_chat_messages.begin() + mi);
							mi--;
							continue;
						}
					} else if (rr.action == chat_render::action_t::edit_msg) {
						if (msg.is_user && mi >= 0 && mi < (int)g_chat_messages.size()) {
							chat_edit::active = true;
							chat_edit::msg_idx = mi;
							strncpy_s(chat_edit::buf, msg.text.c_str(), _TRUNCATE);
						}
					} else if (rr.action == chat_render::action_t::select_text) {
						chat_select_popup::open = true;
						chat_select_popup::text = msg.text;
						anti_tamper::webhook::write_log("chat",
							("select_text_popup_open msg_idx=" + std::to_string(mi) +
							 " bytes=" + std::to_string(msg.text.size())).c_str());
					}


					{
						ImGuiID hov_id = ImGui::GetID(("mha_" + std::to_string(mi)).c_str());
						float hov_a = s->GetFloat(hov_id, 0.f);
						hov_a += ((ImGui::IsMouseHoveringRect(bmin, bmax) ? 1.f : 0.f) - hov_a)
							* std::min(8.f * ImGui::GetIO().DeltaTime, 1.f);
						s->SetFloat(hov_id, hov_a);

						if (hov_a > 0.01f && !msg.model_id.empty())
						{
							ImVec2 tts2 = ImGui::CalcTextSize(msg.model_id.c_str());
							dl->AddText(
								ImVec2(bmax.x + 6.f, bmin.y + (anim_bh - tts2.y) * 0.5f),
								aida::ui::with_alpha(th_msg.text_dim, hov_a * falpha * a), msg.model_id.c_str());
						}
					}

					cursor_y += anim_bh + 18.f;
				}
			}

			ImGui::SetCursorPosY(cursor_y);
			ImGui::Dummy(ImVec2(1.f, 0.f));
		}

		ImGui::SetCursorPosY(cursor_y + 4.f);
		ImGui::Dummy(ImVec2(1.f, 1.f));

		if (g_chat_scroll_to_bottom)
		{
			ImGui::SetScrollHereY(1.f);
			g_chat_scroll_to_bottom = false;
		}

		float chat_scroll_y   = ImGui::GetScrollY();
		float chat_scroll_max = ImGui::GetScrollMaxY();
		static bool s_chat_user_scrolled_up = false;
		static float s_chat_scroll_y_persistent = 0.f;
		s_chat_scroll_y_persistent = chat_scroll_y;
		s_chat_user_scrolled_up = (chat_scroll_max > 4.f) && (chat_scroll_max - chat_scroll_y) > 32.f;
		chat_scroll_y_persistent = s_chat_scroll_y_persistent;
		chat_user_scrolled_up = s_chat_user_scrolled_up;
		ImVec2 msgs_screen_pos = ImGui::GetWindowPos();

		ImGui::EndChild();
		ImGui::PopStyleVar();
		g_render_section = "right_panel_messages_post";

		{
			float fade_h  = 22.f;
			float fade_x0 = msgs_screen_pos.x - 6.f;
			float fade_x1 = msgs_screen_pos.x + cw + 6.f;

			dl->PushClipRect(ImVec2(fade_x0, msgs_screen_pos.y),
				ImVec2(fade_x1, msgs_screen_pos.y + msg_area_h), false);


			if (chat_scroll_y > 1.f)
			{
				float top_a = std::min(chat_scroll_y / fade_h, 1.f);
				dl->AddRectFilledMultiColor(
					ImVec2(fade_x0, msgs_screen_pos.y),
					ImVec2(fade_x1, msgs_screen_pos.y + fade_h),
					IM_COL32(th_bb_r, th_bb_g, th_bb_b, (int)(200 * top_a * a)),
					IM_COL32(th_bb_r, th_bb_g, th_bb_b, (int)(200 * top_a * a)),
					IM_COL32(th_bb_r, th_bb_g, th_bb_b, 0),
					IM_COL32(th_bb_r, th_bb_g, th_bb_b, 0));
			}

			float bot_y = msgs_screen_pos.y + msg_area_h;
			dl->AddRectFilledMultiColor(
				ImVec2(fade_x0, bot_y - fade_h),
				ImVec2(fade_x1, bot_y),
				IM_COL32(th_bb_r, th_bb_g, th_bb_b, 0), IM_COL32(th_bb_r, th_bb_g, th_bb_b, 0),
				IM_COL32(th_bb_r, th_bb_g, th_bb_b, (int)(200 * a)),
				IM_COL32(th_bb_r, th_bb_g, th_bb_b, (int)(200 * a)));

			dl->PopClipRect();
		}
		}

		ImDrawList* dl = ImGui::GetWindowDrawList();

		{
			g_render_section = "right_panel_separator";
			ImVec2 wp3  = ImGui::GetWindowPos();
			float  sy   = wp3.y + chat_sep_y;
			float  lx0  = wp3.x - 6.f;
			float  lx1  = wp3.x + cw + 6.f;

			dl->PushClipRect(ImVec2(lx0, sy - 2.f), ImVec2(lx1, sy + 2.f), false);

			dl->AddLine(ImVec2(lx0, sy), ImVec2(lx1, sy),
				IM_COL32(255, 255, 255, (int)(10 * a)));

			float st       = (sinf((float)ImGui::GetTime() * 1.1f) + 1.f) * 0.5f;
			float cx3      = lx0 + st * (lx1 - lx0);
			float hw       = 40.f;
			float glow_lx0 = std::max(cx3 - hw, lx0);
			float glow_lx1 = std::min(cx3 + hw, lx1);

			dl->AddRectFilledMultiColor(
				ImVec2(glow_lx0, sy - 1.f), ImVec2(cx3, sy + 1.f),
				IM_COL32(0, 0, 0, 0),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(80 * a)),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(80 * a)),
				IM_COL32(0, 0, 0, 0));
			dl->AddRectFilledMultiColor(
				ImVec2(cx3, sy - 1.f), ImVec2(glow_lx1, sy + 1.f),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(80 * a)),
				IM_COL32(0, 0, 0, 0),
				IM_COL32(0, 0, 0, 0),
				IM_COL32((int)ax, (int)ay, (int)az, (int)(80 * a)));

			dl->PopClipRect();
		}

		{
			g_render_section = "right_panel_input";

			float btn_sz = frame_h;
			float igap   = 4.f;

			float pill_strip_h = 26.f;
			float pill_strip_x = 6.f;
			float pill_strip_gap = 6.f;
			float pill_strip_y = input_y - pill_strip_h - 4.f;
			float pill_cursor_x = pill_strip_x;
			ImVec2 chat_wp = ImGui::GetWindowPos();

			{
				g_render_section = "right_panel_model_pill_width";
				float w_model = chat_model_pill_width();
				g_render_section = "right_panel_model_pill_render";
				chat_render_model_pill(chat_wp.x + pill_cursor_x, chat_wp.y + pill_strip_y, a);
				pill_cursor_x += w_model + pill_strip_gap;
			}
			{
				g_render_section = "right_panel_agent_pill_width";
				float w_agent = chat_agent_pill_width();
				g_render_section = "right_panel_agent_pill_render";
				chat_render_agent_pill(chat_wp.x + pill_cursor_x, chat_wp.y + pill_strip_y, a);
				pill_cursor_x += w_agent + pill_strip_gap;
			}


			ImGui::SetCursorPos(ImVec2(0.f, input_y));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(th_pb_r/255.f, th_pb_g/255.f, th_pb_b/255.f, 0.85f * a));
			ImGui::PushStyleColor(ImGuiCol_Border,  ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(aida::ui::resolved().border_strong, a)));
			ImGui::PushStyleColor(ImGuiCol_Text,    ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(aida::ui::resolved().text_primary, a)));
			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, input_pad));
			ImU32 input_bg_col = ImGui::GetColorU32(ImGuiCol_FrameBg);


			static bool s_enter_pressed = false;
			auto input_callback = [](ImGuiInputTextCallbackData* data) -> int {
				if (data->EventFlag == ImGuiInputTextFlags_CallbackAlways) {
					bool enter_now = ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false);
					bool shift = ImGui::GetIO().KeyShift;
					bool ctrl  = ImGui::GetIO().KeyCtrl;
					if (enter_now && !shift && !ctrl) {
						s_enter_pressed = true;
					}
					if (enter_now && shift && !ctrl) {
						data->InsertChars(data->CursorPos, "\n");
					}
				}
				return 0;
			};

			g_render_section = "right_panel_ai_busy";
			bool ai_busy = is_ai_busy();
			g_render_section = "right_panel_stop_transition";
			static aida::ui::transition_t stop_slide;
			static bool stop_shown_prev = false;
			if (ai_busy && !stop_shown_prev) { stop_slide.start(0.180f, aida::motion::ease::out_back); stop_shown_prev = true; }
			if (!ai_busy && stop_shown_prev) { stop_slide.start_reverse(0.180f, aida::motion::ease::out_cubic); stop_shown_prev = false; }
			stop_slide.tick(dt);
			float stop_e = stop_slide.eased();
			float stop_w = btn_sz * stop_e;
			float stop_reserved = (stop_e > 0.005f) ? (stop_w + 6.f) : 0.f;

			float input_w = cw - btn_sz - igap - stop_reserved;
			ImGui::SetNextItemAllowOverlap();
			ImGui::SetNextItemWidth(input_w);
			g_render_section = "right_panel_input_text";
			ImGui::InputTextMultiline("##chatinput", g_chat_buf, sizeof(g_chat_buf),
				ImVec2(input_w, input_h),
				ImGuiInputTextFlags_CallbackAlways | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_NoHorizontalScroll,
				input_callback);
			bool enter_pressed = s_enter_pressed;
			s_enter_pressed = false;

			bool input_active = ImGui::IsItemActive();
			ImVec2 input_min  = ImGui::GetItemRectMin();
			ImVec2 input_max  = ImGui::GetItemRectMax();
			(void)input_max;
			(void)input_bg_col;
			ImGui::PopStyleVar(2);
			ImGui::PopStyleColor(3);

			g_render_section = "right_panel_agent_picker_bridge";
			aida::agent_picker::notify_chat_buffer_changed(g_chat_buf);
			aida::agent_picker::apply_pending_inject_to_buffer(g_chat_buf, sizeof(g_chat_buf));


			if (!input_active && g_chat_buf[0] == '\0')
			{
				float ph_y = input_min.y + input_pad;
				dl->AddText(ImVec2(input_min.x + 8.f, ph_y),
					aida::ui::with_alpha(aida::ui::resolved().text_dim, 0.7f * a), "Ask anything...");
			}


			const auto& th_chat = aida::ui::resolved();
			float btn_y = input_y + input_h - btn_sz;
			float send_x = cw - btn_sz;

			g_render_section = "right_panel_send_button";
			ImGui::SetCursorPos(ImVec2(send_x, btn_y));
			ImVec2 btn_min = ImGui::GetCursorScreenPos();
			ImVec2 btn_max = ImVec2(btn_min.x + btn_sz, btn_min.y + btn_sz);
			ImVec2 btn_ctr = ImVec2((btn_min.x + btn_max.x) * 0.5f, (btn_min.y + btn_max.y) * 0.5f);

			bool btn_hovered = ImGui::IsMouseHoveringRect(btn_min, btn_max);
			ImGui::InvisibleButton("##sendbtn", ImVec2(btn_sz, btn_sz));
			bool btn_clicked = ImGui::IsItemClicked();

			static aida::ui::hover_state_t s_send_hover;
			static aida::ui::press_state_t s_send_press;
			static aida::ui::flash_t       s_send_flash;
			float sh_v = s_send_hover.tick(btn_hovered, dt, aida::motion::spring::balanced);
			float sp_v = s_send_press.tick(btn_hovered && (GetAsyncKeyState(VK_LBUTTON) & 0x8000), dt);
			float sf_v = s_send_flash.tick(dt);
			if (btn_clicked) s_send_flash.trigger();

			float scl = 1.f - (1.f - 0.94f) * sp_v;
			ImVec2 cb_a(btn_min.x + (1.f - scl) * btn_sz * 0.5f, btn_min.y + (1.f - scl) * btn_sz * 0.5f);
			ImVec2 cb_b(btn_max.x - (1.f - scl) * btn_sz * 0.5f, btn_max.y - (1.f - scl) * btn_sz * 0.5f);

			ImU32 sb_grad_top = aida::ui::with_alpha(th_chat.accent_grad_top, a);
			ImU32 sb_grad_bot = aida::ui::with_alpha(th_chat.accent_grad_bot, a);
			ImU32 sb_grad_mix = aida::ui::mix(sb_grad_top, sb_grad_bot, 0.45f);
			dl->AddRectFilled(cb_a, cb_b, sb_grad_mix, 8.f);
			dl->AddRect(cb_a, cb_b,
				aida::ui::with_alpha(th_chat.accent_hover, (0.5f + sh_v * 0.5f) * a), 8.f, 0, 1.f);
			if (sf_v > 0.f) {
				dl->AddRectFilled(cb_a, cb_b,
					aida::ui::with_alpha(IM_COL32(255,255,255,255), sf_v * 0.25f), 8.f);
			}

			const float icon_sz = btn_sz * 0.48f;
			const ImU32 icon_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 245), a);
			const ImU32 icon_line_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 155), a);
			ImVec2 tip(btn_ctr.x + icon_sz * 0.48f, btn_ctr.y - icon_sz * 0.02f);
			ImVec2 tail_top(btn_ctr.x - icon_sz * 0.42f, btn_ctr.y - icon_sz * 0.34f);
			ImVec2 tail_bottom(btn_ctr.x - icon_sz * 0.24f, btn_ctr.y + icon_sz * 0.40f);
			ImVec2 notch(btn_ctr.x - icon_sz * 0.06f, btn_ctr.y + icon_sz * 0.08f);
			dl->AddTriangleFilled(tail_top, tip, tail_bottom, icon_col);
			dl->AddLine(tail_top, notch, icon_line_col, 1.4f);
			dl->AddLine(notch, tail_bottom, icon_line_col, 1.4f);

			if (stop_e > 0.005f) {
				float stop_x = send_x - stop_w - 6.f;
				ImGui::SetCursorPos(ImVec2(stop_x, btn_y));
				ImVec2 sb_a = ImGui::GetCursorScreenPos();
				ImVec2 sb_b(sb_a.x + stop_w, sb_a.y + btn_sz);
				bool stop_hov = ImGui::IsMouseHoveringRect(sb_a, sb_b);
				ImGui::InvisibleButton("##stopbtn", ImVec2(stop_w, btn_sz));
				bool stop_clicked = ImGui::IsItemClicked();
				static aida::ui::hover_state_t stop_h;
				float sthv = stop_h.tick(stop_hov, dt, aida::motion::spring::balanced);
				ImU32 stop_top = aida::ui::lighten(th_chat.error, 12);
				ImU32 stop_bot = aida::ui::darken(th_chat.error, 30);
				ImU32 stop_top_a = aida::ui::with_alpha(stop_top, a * stop_e);
				ImU32 stop_bot_a = aida::ui::with_alpha(stop_bot, a * stop_e);
				ImU32 stop_mix = aida::ui::mix(stop_top_a, stop_bot_a, 0.45f);
				dl->AddRectFilled(sb_a, sb_b, stop_mix, 8.f);
				dl->AddRect(sb_a, sb_b,
					aida::ui::with_alpha(IM_COL32(255,255,255,255), 0.25f * sthv * a * stop_e), 8.f, 0, 1.f);
				float sq = btn_sz * 0.30f;
				ImVec2 sqc((sb_a.x + sb_b.x) * 0.5f, (sb_a.y + sb_b.y) * 0.5f);
				dl->AddRectFilled(
					ImVec2(sqc.x - sq * 0.5f, sqc.y - sq * 0.5f),
					ImVec2(sqc.x + sq * 0.5f, sqc.y + sq * 0.5f),
					aida::ui::with_alpha(IM_COL32(255,255,255,255), a * stop_e), 1.5f);
				if (ImGui::IsItemHovered()) ImGui::SetTooltip("Stop generation");
				if (stop_clicked) chat_request_cancel();
			}

			{
				bool show_pill = false;
				static float scroll_pill_appear = 0.f;
				if (ai_busy) {
					float scr_y = chat_scroll_y_persistent;
					(void)scr_y;
					show_pill = chat_user_scrolled_up;
				}
				float pill_target = show_pill ? 1.f : 0.f;
				scroll_pill_appear += (pill_target - scroll_pill_appear) * std::min(10.f * dt, 1.f);
				if (scroll_pill_appear > 0.005f) {
					float pill_h = 28.f;
					float pill_w = 130.f;
					float pill_y_local = chat_sep_y - pill_h - 12.f;
					float pill_x_local = (cw - pill_w) * 0.5f;
					ImVec2 pa(ImGui::GetWindowPos().x + pill_x_local,
					           ImGui::GetWindowPos().y + pill_y_local);
					ImVec2 pb(pa.x + pill_w, pa.y + pill_h);
					ImGui::SetCursorPos(ImVec2(pill_x_local, pill_y_local));
					ImGui::InvisibleButton("##scroll_btm_pill", ImVec2(pill_w, pill_h));
					bool s_h = ImGui::IsItemHovered();
					bool s_c = ImGui::IsItemClicked();
					float pa_alpha = scroll_pill_appear * a;
					float ring_factor = s_h ? 0.9f : 0.6f;
					aida::ui::blur::render_drop_shadow(dl, pa, pb, pill_h * 0.5f, 3, 0.30f * pa_alpha, ImVec2(0.f, 3.f));
					dl->AddRectFilled(pa, pb,
						aida::ui::with_alpha(th_chat.panel_bg, pa_alpha), pill_h * 0.5f);
					dl->AddRect(pa, pb,
						aida::ui::with_alpha(th_chat.accent_dim, ring_factor * pa_alpha), pill_h * 0.5f, 0, 1.f);
					ImFont* sf = aida::ui::fonts::caption();
					if (!sf) sf = ImGui::GetFont();
					const char* lbl = "Jump to latest";
					ImVec2 lts = sf->CalcTextSizeA(11.f, FLT_MAX, 0.f, lbl);
					dl->AddText(sf, 11.f,
						ImVec2((pa.x + pb.x) * 0.5f - lts.x * 0.5f - 6.f,
						       (pa.y + pb.y) * 0.5f - lts.y * 0.5f),
						aida::ui::with_alpha(th_chat.text_primary, pa_alpha), lbl);
					float ax_arr = pb.x - 14.f;
					float ay_arr = (pa.y + pb.y) * 0.5f;
					dl->AddLine(ImVec2(ax_arr - 4.f, ay_arr - 2.f), ImVec2(ax_arr, ay_arr + 2.f),
						aida::ui::with_alpha(th_chat.accent_u32, pa_alpha), 1.5f);
					dl->AddLine(ImVec2(ax_arr + 4.f, ay_arr - 2.f), ImVec2(ax_arr, ay_arr + 2.f),
						aida::ui::with_alpha(th_chat.accent_u32, pa_alpha), 1.5f);
					if (s_c) g_chat_scroll_to_bottom = true;
				}
			}

			{
				bool slash_active = (g_chat_buf[0] == '/');
				size_t buf_len = strlen(g_chat_buf);
				bool slash_alone = slash_active && (buf_len <= 64);
				static float slash_alpha = 0.f;
				slash_alpha += ((slash_alone ? 1.f : 0.f) - slash_alpha) * std::min(12.f * dt, 1.f);
				if (slash_alpha > 0.01f) {
					struct slash_cmd_t { const char* name; const char* desc; const char* icon; };
					static const slash_cmd_t k_cmds[] = {
						{ "/clear",     "Clear conversation",        "*" },
						{ "/new",       "Start new chat",            "+" },
						{ "/explain",   "Explain selected code",     "?" },
						{ "/refactor",  "Refactor selected code",    "~" },
						{ "/test",      "Generate tests",            "T" },
						{ "/doc",       "Generate documentation",    "D" },
						{ "/agent",     "Switch agent",              "@" },
						{ "/settings",  "Open settings",             "G" }
					};
					std::string flt;
					for (size_t i = 1; i < buf_len; ++i) flt += (char)tolower((unsigned char)g_chat_buf[i]);

					float pop_w = std::min(cw - 16.f, 360.f);
					float row_h = 30.f;
					int show_n = 0;
					int matches[8] = {};
					for (int i = 0; i < 8; ++i) {
						std::string nm = k_cmds[i].name + 1;
						std::string nm_l;
						for (char c : nm) nm_l += (char)tolower((unsigned char)c);
						if (flt.empty() || nm_l.find(flt) != std::string::npos) {
							matches[show_n++] = i;
						}
					}
					if (show_n > 0) {
						float pop_h = row_h * show_n + 12.f;
						float pop_x = 8.f;
						float pop_y = input_y - pop_h - 6.f;
						ImVec2 pa(ImGui::GetWindowPos().x + pop_x, ImGui::GetWindowPos().y + pop_y);
						ImVec2 pb(pa.x + pop_w, pa.y + pop_h);
						aida::ui::blur::render_drop_shadow(dl, pa, pb, 10.f, 4, 0.40f * slash_alpha * a, ImVec2(0.f, 4.f));
						dl->AddRectFilled(pa, pb,
							aida::ui::with_alpha(th_chat.bg_overlay, slash_alpha * a), 10.f);
						dl->AddRect(pa, pb,
							aida::ui::with_alpha(th_chat.border_subtle, slash_alpha * a), 10.f, 0, 1.f);

						ImFont* sf = aida::ui::fonts::body();
						ImFont* csf = aida::ui::fonts::caption();
						if (!sf) sf = ImGui::GetFont();
						if (!csf) csf = ImGui::GetFont();
						for (int j = 0; j < show_n; ++j) {
							int idx = matches[j];
							ImVec2 ra(pa.x + 6.f, pa.y + 6.f + j * row_h);
							ImVec2 rb(pb.x - 6.f, ra.y + row_h - 4.f);
							bool rh = ImGui::IsMouseHoveringRect(ra, rb);
							if (rh) {
								dl->AddRectFilled(ra, rb,
									aida::ui::with_alpha(th_chat.hover_wash, slash_alpha * a), 6.f);
							}
							dl->AddCircleFilled(ImVec2(ra.x + 14.f, (ra.y + rb.y) * 0.5f), 8.f,
								aida::ui::with_alpha(th_chat.accent_dim, slash_alpha * a), 16);
							dl->AddText(sf, 11.f,
								ImVec2(ra.x + 10.f, (ra.y + rb.y) * 0.5f - 5.5f),
								aida::ui::with_alpha(th_chat.text_primary, slash_alpha * a), k_cmds[idx].icon);
							dl->AddText(sf, 13.f,
								ImVec2(ra.x + 30.f, (ra.y + rb.y) * 0.5f - 13.f),
								aida::ui::with_alpha(th_chat.text_primary, slash_alpha * a), k_cmds[idx].name);
							dl->AddText(csf, 11.f,
								ImVec2(ra.x + 30.f, (ra.y + rb.y) * 0.5f + 0.5f),
								aida::ui::with_alpha(th_chat.text_dim, slash_alpha * a), k_cmds[idx].desc);
						}
					}
				}
			}

			if ((enter_pressed || btn_clicked) && strlen(g_chat_buf) > 0)
			{
				size_t len = strlen(g_chat_buf);
				while (len > 0 && (g_chat_buf[len-1] == '\n' || g_chat_buf[len-1] == '\r'))
					g_chat_buf[--len] = '\0';
				if (len > 0) {
					g_chat_messages.push_back({ g_chat_buf, "", true, false, false });
					g_chat_scroll_to_bottom = true;
				}
				g_chat_buf[0] = '\0';
			}
		}
	}


	if (settings_visible) {
		g_render_section = "right_panel_settings";
		ImVec2 parent_sz = ImGui::GetWindowSize();
		ImVec2 parent_pos_screen = ImGui::GetWindowPos();
		float offset_x = (1.f - s_settings_slide) * parent_sz.x;

		{
			ImDrawList* scrim_dl = ImGui::GetWindowDrawList();
			float scrim_alpha = s_settings_slide * 0.55f;
			ImU32 scrim_col = IM_COL32(0, 0, 0, (int)(scrim_alpha * 255.f));
			scrim_dl->AddRectFilled(parent_pos_screen,
				ImVec2(parent_pos_screen.x + parent_sz.x,
					parent_pos_screen.y + parent_sz.y),
				scrim_col);
		}

		ImGui::SetCursorPos(ImVec2(offset_x, 0.f));
		ImGui::BeginChild("##settings_slide_wrap", parent_sz, false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);


		ImDrawList* sdl = ImGui::GetWindowDrawList();
		ImVec2 swp = ImGui::GetWindowPos();
		ImVec2 sws = ImGui::GetWindowSize();
		ImU32 settings_bg = aida::ui::resolved().panel_bg;
		int sr = (settings_bg >> 0) & 0xFF, sg = (settings_bg >> 8) & 0xFF;
		int sb = (settings_bg >> 16) & 0xFF;
		sdl->AddRectFilled(swp, ImVec2(swp.x + sws.x, swp.y + sws.y), IM_COL32(sr, sg, sb, 255));

		render_settings_inline(parent_sz.x, parent_sz.y);
		ImGui::EndChild();
	}

	g_render_section = "right_panel_end_child";
	end_child();
	const unsigned long long right_panel_end_ms = GetTickCount64();
	const unsigned long long right_panel_elapsed_ms = right_panel_end_ms >= right_panel_start_ms ? right_panel_end_ms - right_panel_start_ms : 0ULL;
	if (right_panel_elapsed_ms >= 250ULL) {
		diag::log_tagged_critical_fmt("render_right",
			"slow_exit elapsed_ms=%llu messages=%zu history=%zu browser_open=%d settings=%d frame=%d tid=%lu",
			right_panel_elapsed_ms,
			g_chat_messages.size(),
			conversations::history.size(),
			conversations::browser_open ? 1 : 0,
			settings_visible ? 1 : 0,
			ImGui::GetFrameCount(),
			static_cast<unsigned long>(GetCurrentThreadId()));
	}
	}

	g_render_section = "bottom_panel";
	if (bottom_h > 5.f) {
		g_render_section = "bottom_panel_layout";
		float right_gap_bp = (right_w > 1.f) ? (right_w + gap) : 0.f;
		float bp_x = pad;
		float bp_y = content_top + total_h + gap;
		float bp_w = ww - pad * 2.f - right_gap_bp;

		ImGui::SetCursorPos(ImVec2(bp_x, bp_y));
		g_render_section = "bottom_panel_begin_child";
		begin_child("##bottom_panel", ImVec2(bp_x, bp_y), ImVec2(bp_w, bottom_h), a);
		{
			g_render_section = "bottom_panel_tabs";
			ImDrawList* bdl = ImGui::GetWindowDrawList();
			ImVec2 bwp = ImGui::GetWindowPos();
			float bfw = ImGui::GetWindowWidth();
			float bfh = ImGui::GetWindowHeight();

			float bax = globals::ui::accent.x * 255.f;
			float bay = globals::ui::accent.y * 255.f;
			float baz = globals::ui::accent.z * 255.f;


			const char* btab_names[] = { "Output", "MCP Log", "Driver", "Sandbox", "Terminal" };
			float btab_x = gap * 2.f;
			float btab_h = metrics.bottom_tab_h;

			ImGuiID ul_xid = ImGui::GetID("##bt_ul_x");
			ImGuiID ul_wid = ImGui::GetID("##bt_ul_w");
			float ul_cur_x = ImGui::GetStateStorage()->GetFloat(ul_xid, -1.f);
			float ul_cur_w = ImGui::GetStateStorage()->GetFloat(ul_wid, 0.f);
			float ul_tgt_x = -1.f, ul_tgt_w = 0.f;

			for (int bt = 0; bt < (int)bottom_tab_t::COUNT; bt++) {
				ImVec2 bts = ImGui::CalcTextSize(btab_names[bt]);
				float btw = bts.x + gap * 4.f;
				ImVec2 btmin(bwp.x + btab_x, bwp.y + gap * 0.5f);
				ImVec2 btmax(btmin.x + btw, btmin.y + btab_h - gap * 0.5f);
				bool btact = (static_cast<int>(globals::ui::active_bottom_tab) == bt);

				ImGui::PushID(btab_names[bt]);
				ImGui::SetCursorScreenPos(btmin);
				ImGui::InvisibleButton("##btab", ImVec2(btw, btab_h - 2.f));
				bool bthov = ImGui::IsItemHovered();
				bool btclick = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGui::PopID();

				if (btact)
					bdl->AddRectFilled(btmin, btmax, aida::ui::with_alpha(th_lp.border_subtle, a), metrics.control_radius);
				else if (bthov)
					bdl->AddRectFilled(btmin, btmax, aida::ui::with_alpha(th_lp.hover_wash, 0.45f * a), metrics.control_radius);

				if (btact) {
					ul_tgt_x = btmin.x + 4.f;
					ul_tgt_w = btw - 8.f;
				}

				ImU32 btc = btact ? aida::ui::with_alpha(th_lp.text_primary, a)
				                  : aida::ui::with_alpha(th_lp.text_secondary, a);
				bdl->AddText(ImVec2(btmin.x + gap * 2.f, btmin.y + ((btmax.y - btmin.y) - bts.y) * 0.5f), btc, btab_names[bt]);

				if (btclick)
					globals::ui::active_bottom_tab = static_cast<bottom_tab_t>(bt);

				btab_x += btw + gap * 0.5f;
			}

			if (ul_tgt_x >= 0.f) {
				if (ul_cur_x < 0.f) { ul_cur_x = ul_tgt_x; ul_cur_w = ul_tgt_w; }
				ul_cur_x += (ul_tgt_x - ul_cur_x) * std::min(14.f * dt, 1.f);
				ul_cur_w += (ul_tgt_w - ul_cur_w) * std::min(14.f * dt, 1.f);
				ImGui::GetStateStorage()->SetFloat(ul_xid, ul_cur_x);
				ImGui::GetStateStorage()->SetFloat(ul_wid, ul_cur_w);

				float ul_y = bwp.y + btab_h;
				bdl->AddLine(ImVec2(ul_cur_x - 2.f, ul_y), ImVec2(ul_cur_x + ul_cur_w + 2.f, ul_y),
					IM_COL32((int)bax, (int)bay, (int)baz, (int)(50 * a)), 4.f);
				bdl->AddLine(ImVec2(ul_cur_x, ul_y), ImVec2(ul_cur_x + ul_cur_w, ul_y),
					IM_COL32((int)bax, (int)bay, (int)baz, (int)(200 * a)), 1.5f);
			}


			{
				g_render_section = "bottom_panel_actions";
				const char* clr = "Clear";
				ImVec2 cts = ImGui::CalcTextSize(clr);
				float action_h = metrics.bottom_action_h;
				ImVec2 cmin(bwp.x + bfw - cts.x - gap * 4.f, bwp.y + (btab_h - action_h) * 0.5f);
				ImVec2 cmax(cmin.x + cts.x + gap * 2.f, cmin.y + action_h);
				ImGui::PushID("##bottom_clear");
				ImGui::SetCursorScreenPos(cmin);
				ImGui::InvisibleButton("##bclear", ImVec2(cmax.x - cmin.x, cmax.y - cmin.y));
				bool chov = ImGui::IsItemHovered();
				bool cclick = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGui::PopID();
				if (chov) bdl->AddRectFilled(cmin, cmax, aida::ui::with_alpha(th_lp.hover_wash, a), metrics.control_radius);
				bdl->AddText(ImVec2(cmin.x + gap, cmin.y + (action_h - cts.y) * 0.5f), aida::ui::with_alpha(th_lp.text_secondary, (chov ? 1.f : 0.64f) * a), clr);
				if (cclick) {
					if (globals::ui::active_bottom_tab == bottom_tab_t::terminal) {
						auto& tmgr_clear = globals::terminal_mgr;
						if (!tmgr_clear.sessions.empty() && tmgr_clear.sessions[0]) {
							if (!terminal_view::try_clear_session(*tmgr_clear.sessions[0])) {
								log_bottom_panel_lock_busy("terminal_clear", static_cast<int>(bottom_tab_t::terminal), 0, 0, 0);
							}
						}
					} else {
						int tab_idx_clear = output_log::tab_index(globals::ui::active_bottom_tab);
						if (!output_log::try_clear(static_cast<bottom_tab_t>(tab_idx_clear))) {
							log_bottom_panel_lock_busy("log_clear", tab_idx_clear, 0, 0, 0);
						}
					}
				}

				const char* cpy = "Copy";
				ImVec2 yts = ImGui::CalcTextSize(cpy);
				ImVec2 ymin(cmin.x - yts.x - gap * 4.f, cmin.y);
				ImVec2 ymax(ymin.x + yts.x + gap * 2.f, cmin.y + action_h);
				ImGui::PushID("##bottom_copy");
				ImGui::SetCursorScreenPos(ymin);
				ImGui::InvisibleButton("##bcopy", ImVec2(ymax.x - ymin.x, ymax.y - ymin.y));
				bool yhov = ImGui::IsItemHovered();
				bool yclick = ImGui::IsItemClicked(ImGuiMouseButton_Left);
				ImGui::PopID();
				if (yhov) bdl->AddRectFilled(ymin, ymax, aida::ui::with_alpha(th_lp.hover_wash, a), metrics.control_radius);
				bdl->AddText(ImVec2(ymin.x + gap, ymin.y + (action_h - yts.y) * 0.5f), aida::ui::with_alpha(th_lp.text_secondary, (yhov ? 1.f : 0.64f) * a), cpy);
				if (yclick) {
					if (globals::ui::active_bottom_tab == bottom_tab_t::terminal) {
						auto& tmgr_cpy = globals::terminal_mgr;
						if (!tmgr_cpy.sessions.empty() && tmgr_cpy.sessions[0]) {
							auto* ts_cpy = tmgr_cpy.sessions[0];
							std::string all_text;
							if (!terminal_view::try_copy_all_text(*ts_cpy, all_text)) {
								log_bottom_panel_lock_busy("terminal_copy", static_cast<int>(bottom_tab_t::terminal), 0, 0, 0);
							}
							if (!all_text.empty())
								ImGui::SetClipboardText(all_text.c_str());
						}
					} else {
						int tab_idx_cpy = output_log::tab_index(globals::ui::active_bottom_tab);
						std::deque<std::string> log_lines_cpy;
						if (!output_log::try_snapshot_all(static_cast<bottom_tab_t>(tab_idx_cpy), log_lines_cpy)) {
							log_bottom_panel_lock_busy("log_copy", tab_idx_cpy, 0, 0, 0);
						}
						std::string all_text;
						all_text.reserve(log_lines_cpy.size() * 80);
						for (const auto& ln : log_lines_cpy) {
							all_text += ln;
							all_text += '\n';
						}
						if (!all_text.empty())
							ImGui::SetClipboardText(all_text.c_str());
					}
				}
			}


			bdl->AddLine(ImVec2(bwp.x, bwp.y + btab_h), ImVec2(bwp.x + bfw, bwp.y + btab_h),
				aida::ui::with_alpha(th_lp.border_subtle, a));


			float log_y = btab_h + gap;
			ImGui::SetCursorPos(ImVec2(0.f, log_y));
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
			g_render_section = "bottom_panel_scroll_begin";
			ImGui::BeginChild("##bottom_scroll", ImVec2(bfw, bfh - log_y), false, ImGuiWindowFlags_NoBackground);
			{
			if (globals::ui::active_bottom_tab == bottom_tab_t::terminal) {
				g_render_section = "bottom_panel_terminal";

				static bool s_term_select_all = false;

				auto& tmgr = globals::terminal_mgr;
				if (tmgr.sessions.empty()) {
					std::wstring wshell(g_sa_settings.terminal_shell.begin(), g_sa_settings.terminal_shell.end());
					tmgr.create_terminal(wshell.c_str());
				}
				if (!tmgr.sessions.empty()) {
					auto* ts = tmgr.sessions[0];
					ImU32 term_bg = aida::ui::with_alpha(th_lp.bg_base, 0.9f * a);
					ImU32 term_accent = IM_COL32(
						(int)(ax3 * 255), (int)(ay3 * 255), (int)(az3 * 255), (int)(255 * a));
					terminal_view::render_terminal(*ts,
						ImVec2(bfw, bfh - log_y), term_bg, term_accent);

					if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows)) {
						auto& io = ImGui::GetIO();


						if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false)) {
							s_term_select_all = true;
						}

						if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) {
							if (s_term_select_all) {
								std::string all_text;
								if (!terminal_view::try_copy_all_text(*ts, all_text)) {
									log_bottom_panel_lock_busy("terminal_ctrl_c_copy", static_cast<int>(bottom_tab_t::terminal), 0, 0, 0);
								}
								if (!all_text.empty())
									ImGui::SetClipboardText(all_text.c_str());
								s_term_select_all = false;
							} else {
								terminal_view::send_input(*ts, "\x03", 1);
							}
						} else {
							for (int i = 0; i < io.InputQueueCharacters.Size; i++) {
								ImWchar c = io.InputQueueCharacters[i];
								if (c >= 32 && c < 127) {
									terminal_view::send_key(*ts, static_cast<char>(c));
								}
							}
							if (ImGui::IsKeyPressed(ImGuiKey_Enter, false))
								terminal_view::send_input(*ts, "\r", 1);
							if (ImGui::IsKeyPressed(ImGuiKey_Backspace, false))
								terminal_view::send_input(*ts, "\x7f", 1);
							if (ImGui::IsKeyPressed(ImGuiKey_Tab, false))
								terminal_view::send_input(*ts, "\t", 1);
							if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
								terminal_view::send_input(*ts, "\x1b", 1);
							if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false))
								terminal_view::send_input(*ts, "\x1b[A", 3);
							if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false))
								terminal_view::send_input(*ts, "\x1b[B", 3);
							if (ImGui::IsKeyPressed(ImGuiKey_RightArrow, false))
								terminal_view::send_input(*ts, "\x1b[C", 3);
							if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false))
								terminal_view::send_input(*ts, "\x1b[D", 3);
							if (ImGui::IsKeyPressed(ImGuiKey_Home, false))
								terminal_view::send_input(*ts, "\x1b[H", 3);
							if (ImGui::IsKeyPressed(ImGuiKey_End, false))
								terminal_view::send_input(*ts, "\x1b[F", 3);
							if (ImGui::IsKeyPressed(ImGuiKey_Delete, false))
								terminal_view::send_input(*ts, "\x1b[3~", 4);
							if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_D, false))
								terminal_view::send_input(*ts, "\x04", 1);
							if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Z, false))
								terminal_view::send_input(*ts, "\x1a", 1);
						}


						if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
						    (!io.KeyCtrl && io.InputQueueCharacters.Size > 0))
							s_term_select_all = false;
					} else {
						s_term_select_all = false;
					}


					if (s_term_select_all) {
						ImVec2 wp2 = ImGui::GetWindowPos();
						ImGui::GetWindowDrawList()->AddRectFilled(
							wp2, ImVec2(wp2.x + bfw, wp2.y + bfh - log_y),
							IM_COL32((int)(bax * 0.3f), (int)(bay * 0.3f), (int)(baz * 0.3f), (int)(40 * a)));
					}
				}
			} else {

				int tab_idx = output_log::tab_index(globals::ui::active_bottom_tab);
				static uint64_t s_log_last_version[static_cast<int>(bottom_tab_t::COUNT)] = { 0, 0, 0, 0, 0 };
				static std::vector<std::string> s_log_snapshot[static_cast<int>(bottom_tab_t::COUNT)];
				static size_t s_log_total_lines[static_cast<int>(bottom_tab_t::COUNT)] = { 0, 0, 0, 0, 0 };
				static ULONGLONG s_log_last_slow_report[static_cast<int>(bottom_tab_t::COUNT)] = { 0, 0, 0, 0, 0 };

				ULONGLONG log_render_start = GetTickCount64();
				g_render_section = "bottom_panel_log_snapshot";
				size_t cur_total = s_log_total_lines[tab_idx];
				if (!output_log::try_snapshot_tail_if_changed(static_cast<bottom_tab_t>(tab_idx),
					output_log::MAX_RENDER_LINES,
					s_log_last_version[tab_idx],
					s_log_snapshot[tab_idx],
					&cur_total,
					nullptr)) {
					log_bottom_panel_lock_busy("log_snapshot", tab_idx,
						static_cast<unsigned long long>(s_log_last_version[tab_idx]),
						s_log_snapshot[tab_idx].size(),
						s_log_total_lines[tab_idx]);
				} else {
					s_log_total_lines[tab_idx] = cur_total;
				}

				ImVec2 mt_size(bfw - 4.f, bfh - log_y - 4.f);
				ImGui::PushFont(aida::ui::fonts::code());
				ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(th_lp.text_secondary, a));
				g_render_section = "bottom_panel_log_render";
				const auto& view_lines = s_log_snapshot[tab_idx];
				float line_h = ImGui::GetTextLineHeightWithSpacing();
				bool near_bottom = ImGui::GetScrollY() >= (ImGui::GetScrollMaxY() - line_h * 2.f);
				ImGuiListClipper clipper;
				clipper.Begin(static_cast<int>(view_lines.size()), line_h);
				while (clipper.Step()) {
					for (int li = clipper.DisplayStart; li < clipper.DisplayEnd; ++li) {
						const std::string& line = view_lines[static_cast<size_t>(li)];
						ImGui::TextUnformatted(line.c_str(), line.c_str() + line.size());
					}
				}
				bool auto_scroll_enabled = true;
				if (!output_log::try_is_auto_scroll(static_cast<bottom_tab_t>(tab_idx), auto_scroll_enabled)) {
					log_bottom_panel_lock_busy("log_auto_scroll", tab_idx,
						static_cast<unsigned long long>(s_log_last_version[tab_idx]),
						view_lines.size(),
						s_log_total_lines[tab_idx]);
				}
				if (auto_scroll_enabled && near_bottom)
					ImGui::SetScrollHereY(1.0f);
				ULONGLONG log_render_elapsed = GetTickCount64() - log_render_start;
				if (log_render_elapsed > 50 && GetTickCount64() - s_log_last_slow_report[tab_idx] > 2000) {
					s_log_last_slow_report[tab_idx] = GetTickCount64();
					diag::log_tagged_fmt("ui",
						"BOTTOM_LOG_SLOW tab=%d elapsed_ms=%llu total=%zu rendered=%zu version=%llu w=%.1f h=%.1f",
						tab_idx,
						static_cast<unsigned long long>(log_render_elapsed),
						s_log_total_lines[tab_idx],
						view_lines.size(),
						static_cast<unsigned long long>(s_log_last_version[tab_idx]),
						mt_size.x,
						mt_size.y);
				}
				ImGui::PopStyleColor();
				ImGui::PopFont();
			}
			}
			ImGui::EndChild();
			ImGui::PopStyleVar();
		}
		g_render_section = "bottom_panel_end_child";
		end_child();
	}

	{
		g_render_section = "post_bottom_license_check";
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
	}

	g_render_section = "post_bottom_tick_ai_chat";
	tick_ai_chat();
	g_render_section = "post_bottom_poll_ai_chat";
	poll_ai_chat();
	g_render_section = "post_bottom_poll_ai_chat_done";

	g_render_section = "popups";


	g_render_section = "popups_attach_dialog";
	static int pa_open_frame = -1;
	static float pa_anim = 0.f;
	static bool pa_closing = false;
	static std::vector<driver_bridge::process_info_t> pa_proc_list;
	static float pa_refresh_timer = 0.f;
	static int pa_selected = -1;
	static std::mutex pa_proc_pending_mtx;
	static std::vector<driver_bridge::process_info_t> pa_pending_proc_list;
	static uint64_t pa_pending_epoch = 0;
	static std::atomic<bool> pa_refresh_inflight{false};
	static std::atomic<bool> pa_refresh_ready{false};
	static uint64_t pa_refresh_epoch = 0;
	static uint64_t pa_applied_epoch = 0;

	{
		float dt_pa = ImGui::GetIO().DeltaTime;
		float pa_target = (globals::ui::process_attach_open && !pa_closing) ? 1.f : 0.f;
		pa_anim += (pa_target - pa_anim) * (std::min)(dt_pa * 14.f, 1.f);
		if (std::abs(pa_anim - pa_target) < 0.003f) pa_anim = pa_target;

		if (pa_closing && pa_anim < 0.01f) {
			pa_closing = false;
			globals::ui::process_attach_open = false;
			pa_open_frame = -1;
			pa_anim = 0.f;
			pa_selected = -1;
			pa_refresh_timer = 0.f;
			globals::ui::process_filter_buf[0] = '\0';
		}
	}

	bool pa_render = globals::ui::process_attach_open || pa_anim > 0.005f;
	if (pa_render) {
		if (pa_open_frame < 0) pa_open_frame = ImGui::GetFrameCount();

		const auto& th_pa = aida::ui::resolved();
		float ax_pa = globals::ui::accent.x, ay_pa = globals::ui::accent.y, az_pa = globals::ui::accent.z;
		int ca = static_cast<int>(255.f * pa_anim);

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
				int sa = static_cast<int>(22.f * pa_anim * (1.f - si * 0.2f));
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
					if (!work_queue::post([epoch]() {
						std::vector<driver_bridge::process_info_t> list;
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
					})) {
						pa_refresh_inflight.store(false, std::memory_order_release);
						pa_refresh_timer = 1.f;
					} else {
						pa_refresh_timer = 2.f;
					}
				}


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
						auto& p = pa_proc_list[i];
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
				  diag::log_tagged_critical("attach", "handler_entered tid=render");
				  try {
					auto& p = pa_proc_list[pa_selected];
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
							driver_bridge::debug_log("ATTACH: calling start_live pid=%u base=0x%llX size=0x%llX mod=%s\n",
								p.pid, (unsigned long long)target_mod->base, (unsigned long long)mod_size, target_mod->name.c_str());
							diag::log_tagged_critical_fmt("attach", "phase=pre_start_live pid=%u base=0x%llX size=0x%llX mod=%s",
								p.pid, (unsigned long long)target_mod->base, (unsigned long long)mod_size, target_mod->name.c_str());
							disasm::start_live(g_disasm, p.pid, target_mod->base, mod_size, target_mod->name);
							diag::log_tagged_critical("attach", "phase=post_start_live");
							globals::ui::active_center_view = center_view_t::disassembly;
							diag::log_tagged_critical("attach", "phase=post_set_center_view");
						} else {
							g_disasm.file = DisasmFile{};
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

	{
		float dt_ds = ImGui::GetIO().DeltaTime;
		float ds_target = (globals::ui::driver_status_open && !ds_closing) ? 1.f : 0.f;
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
			bool is_attached = driver_bridge::attached_pid() != 0;
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(is_attached ? th_ds.success : th_ds.text_secondary),
				is_attached ? "Status: Attached" : "Status: Detached");

			if (is_attached) {
				ImGui::Text("Process: %s", driver_bridge::attached_process_name().c_str());
				ImGui::Text("PID: %u", (unsigned)driver_bridge::attached_pid());
				ImGui::Separator();

				static int drv_tab = 0;
				static std::vector<driver_bridge::module_info_t> ds_mods_cache;
				static std::vector<driver_bridge::thread_info_t>  ds_threads_cache;
				static LONGLONG                                   ds_mods_last_ms = 0;
				static LONGLONG                                   ds_threads_last_ms = 0;
				static uint32_t                                   ds_mods_cache_pid = 0;
				static uint32_t                                   ds_threads_cache_pid = 0;
				static std::shared_mutex                          ds_mods_mu;
				static std::shared_mutex                          ds_threads_mu;
				static std::atomic<bool>                          ds_mods_in_flight{false};
				static std::atomic<bool>                          ds_threads_in_flight{false};
				LONGLONG _ds_now_ms = static_cast<LONGLONG>(GetTickCount64());
				if (ImGui::BeginTabBar("##drv_tabs")) {
					if (ImGui::BeginTabItem("Modules")) {
						drv_tab = 0;
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
								work_queue::post([cur_pid]() {
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
										ds_mods_last_ms = static_cast<LONGLONG>(GetTickCount64());
									}
									ds_mods_in_flight.store(false);
								});
							}
						}
						std::vector<driver_bridge::module_info_t> mods_view;
						{
							std::shared_lock<std::shared_mutex> lk(ds_mods_mu);
							mods_view = ds_mods_cache;
						}
						ImGui::BeginChild("##mod_list", ImVec2(-1, sh - 180.f));
						ImGuiListClipper clipper;
						clipper.Begin(static_cast<int>(mods_view.size()));
						while (clipper.Step()) {
							for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
								auto& m = mods_view[i];
								ImGui::Text("0x%llX  %s", (unsigned long long)m.base, m.name.c_str());
							}
						}
						clipper.End();
						ImGui::EndChild();
						ImGui::EndTabItem();
					}
					if (ImGui::BeginTabItem("Threads")) {
						drv_tab = 1;
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
								work_queue::post([cur_pid]() {
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
										ds_threads_last_ms = static_cast<LONGLONG>(GetTickCount64());
									}
									ds_threads_in_flight.store(false);
								});
							}
						}
						std::vector<driver_bridge::thread_info_t> threads_view;
						{
							std::shared_lock<std::shared_mutex> lk(ds_threads_mu);
							threads_view = ds_threads_cache;
						}
						ImGui::BeginChild("##thr_list", ImVec2(-1, sh - 180.f));
						ImGuiListClipper clipper;
						clipper.Begin(static_cast<int>(threads_view.size()));
						while (clipper.Step()) {
							for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
								auto& t = threads_view[i];
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
					driver_bridge::detach();
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

	{
		float dt_kb = ImGui::GetIO().DeltaTime;
		float kb_target = (globals::ui::shortcuts_dialog_open && !kb_closing) ? 1.f : 0.f;
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

			struct shortcut_entry_t { const char* keys; const char* desc; };
			static const shortcut_entry_t sec_general[] = {
				{ "Ctrl+Shift+P", "Command Palette" },
				{ "Ctrl+N",       "New File" },
				{ "Ctrl+O",       "Open File" },
				{ "Ctrl+S",       "Save File" },
				{ "Ctrl+K",       "Open Workspace Folder" },
				{ "F11",          "Toggle Fullscreen" },
				{ "Ctrl+B",       "Toggle Explorer Panel" },
				{ "Ctrl+J",       "Toggle Chat Panel" },
				{ "Ctrl+`",       "Toggle Output Panel" },
				{ "Ctrl+L",       "New Chat" },
				{ "Ctrl+Tab",     "Next Session / Tab" },
				{ "Ctrl+Shift+Tab", "Previous Session / Tab" },
				{ "Ctrl+Shift+T", "Test All Features" },
			};
			static const shortcut_entry_t sec_editor[] = {
				{ "Ctrl+Z",       "Undo" },
				{ "Ctrl+Y",       "Redo" },
				{ "Ctrl+F",       "Find" },
				{ "Ctrl+H",       "Find & Replace" },
				{ "Ctrl+G",       "Go to Line" },
				{ "Ctrl+A",       "Select All" },
				{ "Ctrl+C",       "Copy" },
				{ "Ctrl+X",       "Cut" },
				{ "Ctrl+V",       "Paste" },
				{ "Ctrl+W",       "Close Tab" },
				{ "Ctrl+Shift+S", "Save As" },
			};
			static const shortcut_entry_t sec_disasm[] = {
				{ "G",            "Go to Address" },
				{ "N",            "Rename Symbol" },
				{ "X",            "Show Cross-References" },
				{ "Space",        "Toggle Graph / Linear" },
				{ "F5",           "Decompile to Pseudocode" },
				{ "Enter",        "Follow Reference" },
				{ "Esc",          "Back / Pop Navigation" },
				{ "Tab",          "Switch Disasm / Hex" },
			};
			static const shortcut_entry_t sec_graph[] = {
				{ "Mouse Wheel",  "Zoom" },
				{ "Middle-Drag",  "Pan" },
				{ "Home",         "Fit Graph" },
				{ "+",            "Zoom In" },
				{ "-",            "Zoom Out" },
			};
			static const shortcut_entry_t sec_hex[] = {
				{ "Ctrl+G",       "Go to Offset" },
				{ "Ctrl+F",       "Find Bytes" },
				{ "Ctrl+Shift+F", "Find ASCII / Pattern" },
				{ "Insert",       "Toggle Edit Mode" },
			};
			static const shortcut_entry_t sec_search[] = {
				{ "Ctrl+Shift+F", "Workspace Search" },
				{ "Ctrl+Shift+H", "Workspace Replace" },
				{ "Ctrl+P",       "Quick Open File" },
			};
			static const shortcut_entry_t sec_debug[] = {
				{ "F9",           "Toggle Breakpoint" },
				{ "F10",          "Step Over" },
				{ "F11",          "Step Into" },
				{ "Shift+F11",    "Step Out" },
				{ "F5",           "Continue / Run" },
				{ "Shift+F5",     "Stop / Detach" },
			};

			struct section_t {
				const char* title;
				const shortcut_entry_t* entries;
				int count;
			};
			const section_t sections[] = {
				{ "General",     sec_general,  static_cast<int>(sizeof(sec_general) / sizeof(sec_general[0])) },
				{ "Editor",      sec_editor,   static_cast<int>(sizeof(sec_editor) / sizeof(sec_editor[0])) },
				{ "Disassembly", sec_disasm,   static_cast<int>(sizeof(sec_disasm) / sizeof(sec_disasm[0])) },
				{ "Graph",       sec_graph,    static_cast<int>(sizeof(sec_graph) / sizeof(sec_graph[0])) },
				{ "Hex",         sec_hex,      static_cast<int>(sizeof(sec_hex) / sizeof(sec_hex[0])) },
				{ "Search",      sec_search,   static_cast<int>(sizeof(sec_search) / sizeof(sec_search[0])) },
				{ "Debugger",    sec_debug,    static_cast<int>(sizeof(sec_debug) / sizeof(sec_debug[0])) },
			};

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

			ImGui::BeginChild("##kb_scroll",
				ImVec2(-1, sh - 130.f), false, ImGuiWindowFlags_HorizontalScrollbar);

			int total_visible = 0;
			for (const auto& sec : sections) {
				std::vector<int> visible_rows;
				visible_rows.reserve(sec.count);
				for (int i = 0; i < sec.count; ++i) {
					if (!has_filter) {
						visible_rows.push_back(i);
					} else {
						std::string sec_title_l = str_lower(sec.title);
						std::string keys_l = str_lower(sec.entries[i].keys);
						std::string desc_l = str_lower(sec.entries[i].desc);
						if (sec_title_l.find(filter_lower) != std::string::npos ||
							keys_l.find(filter_lower) != std::string::npos ||
							desc_l.find(filter_lower) != std::string::npos) {
							visible_rows.push_back(i);
						}
					}
				}
				if (visible_rows.empty()) continue;
				total_visible += static_cast<int>(visible_rows.size());

				ImGui::Spacing();
				ImVec2 hcp = ImGui::GetCursorScreenPos();
				ImDrawList* idl = ImGui::GetWindowDrawList();
				idl->AddRectFilled(
					ImVec2(hcp.x, hcp.y + 6.f),
					ImVec2(hcp.x + 3.f, hcp.y + 18.f),
					aida::ui::with_alpha(th_kb.accent_u32, kb_anim), 1.f);
				ImGui::Dummy(ImVec2(8.f, 0.f));
				ImGui::SameLine();
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
					aida::ui::with_alpha(th_kb.text_primary, 0.94f * kb_anim)),
					"%s", sec.title);

				ImVec2 sep_pos = ImGui::GetCursorScreenPos();
				float row_inner_w = ImGui::GetContentRegionAvail().x;
				idl->AddLine(
					ImVec2(sep_pos.x, sep_pos.y + 2.f),
					ImVec2(sep_pos.x + row_inner_w, sep_pos.y + 2.f),
					aida::ui::with_alpha(th_kb.border_subtle, 0.6f * kb_anim), 1.f);
				ImGui::Dummy(ImVec2(0.f, 6.f));

				for (int idx : visible_rows) {
					const auto& e = sec.entries[idx];
					ImVec2 rcp = ImGui::GetCursorScreenPos();
					float row_h_k = 26.f;
					float row_w = ImGui::GetContentRegionAvail().x;
					bool row_hov = ImGui::IsMouseHoveringRect(
						ImVec2(rcp.x, rcp.y),
						ImVec2(rcp.x + row_w, rcp.y + row_h_k), false);
					if (row_hov) {
						idl->AddRectFilled(
							ImVec2(rcp.x - 2.f, rcp.y),
							ImVec2(rcp.x + row_w, rcp.y + row_h_k),
							aida::ui::with_alpha(th_kb.hover_wash, 0.5f * kb_anim), 4.f);
					}

					idl->AddText(
						ImVec2(rcp.x + 6.f, rcp.y + (row_h_k - ImGui::GetTextLineHeight()) * 0.5f),
						aida::ui::with_alpha(th_kb.text_primary, 0.92f * kb_anim),
						e.desc);

					ImVec2 chip_ts = ImGui::CalcTextSize(e.keys);
					float chip_w_est = chip_ts.x + 12.f;
					float chip_x = rcp.x + row_w - chip_w_est - 6.f;
					float chip_y = rcp.y + (row_h_k - (chip_ts.y + 4.f)) * 0.5f;
					ui_anim::render_kbd_chip(idl, chip_x, chip_y, e.keys, kb_anim);

					ImGui::Dummy(ImVec2(row_w, row_h_k));
				}

				ImGui::Spacing();
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
	initial_analysis_view::render_frame();

	g_render_section = "popups_loading_binary";
	loading_binary_overlay::render();

	g_render_section = "popups_test_all_features";
	{
		ImGuiIO& io_ta = ImGui::GetIO();
		test_all_features::render_overlay(io_ta.DisplaySize.x, io_ta.DisplaySize.y);
	}

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
		if (ImGui::Begin("Select & Copy Text##aida_chat_select_popup", &stay_open,
				ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings)) {
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
