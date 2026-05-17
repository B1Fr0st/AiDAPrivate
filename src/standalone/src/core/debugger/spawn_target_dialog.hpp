#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <commdlg.h>
#include <ShlObj.h>
#include <shellapi.h>
#include <objbase.h>
#ifdef small
#undef small
#endif

#include <cstring>
#include <cstdio>
#include <string>

#include "imgui/imgui.h"
#include "../ui/components.hpp"
#include "../ui/theme.hpp"
#include "../ui/fonts.hpp"
#include "../helpers/diag_log.hpp"
#include "../helpers/win32_dialog.hpp"
#include "../runtime/run_target.hpp"
#include "../ui/toast_notification.hpp"

extern HWND g_hwnd;

namespace spawn_target_dialog {

struct result_t {
	std::wstring                exe_path;
	std::wstring                args;
	std::wstring                working_dir;
	run_target::launch_options_t launch_options;
	bool                        accepted = false;
};

namespace detail {

inline bool& open_flag() {
	static bool v = false;
	return v;
}

inline bool& should_open() {
	static bool v = false;
	return v;
}

inline char* exe_buf() {
	static char buf[1024] = {};
	return buf;
}

inline char* args_buf() {
	static char buf[2048] = {};
	return buf;
}

inline char* cwd_buf() {
	static char buf[1024] = {};
	return buf;
}

inline bool& pending_result_ready() {
	static bool v = false;
	return v;
}

inline result_t& pending_result() {
	static result_t r;
	return r;
}

inline int& isolation_choice() {
	static int v = static_cast<int>(run_target::isolation_t::same_desktop_jobbed);
	return v;
}

inline bool& block_network_flag() {
	static bool v = true;
	return v;
}

inline bool& kill_on_host_exit_flag() {
	static bool v = true;
	return v;
}

inline int& memory_cap_mb_value() {
	static int v = 0;
	return v;
}

inline int& auto_terminate_sec_value() {
	static int v = 0;
	return v;
}

inline bool& malware_safe_mode_flag() {
	static bool v = true;
	return v;
}

inline bool& log_network_traffic_flag() {
	static bool v = true;
	return v;
}

inline bool& lower_integrity_untrusted_flag() {
	static bool v = false;
	return v;
}

inline bool& allow_child_processes_flag() {
	static bool v = true;
	return v;
}

inline bool& force_mitigations_strict_flag() {
	static bool v = false;
	return v;
}

inline bool& redirect_user_paths_flag() {
	static bool v = true;
	return v;
}

inline bool& register_kernel_guard_flag() {
	static bool v = true;
	return v;
}

inline std::wstring& last_sandbox_dir() {
	static std::wstring v;
	return v;
}

inline void reset_inputs() {
	std::memset(exe_buf(), 0, 1024);
	std::memset(args_buf(), 0, 2048);
	std::memset(cwd_buf(), 0, 1024);
	isolation_choice() = static_cast<int>(run_target::isolation_t::same_desktop_jobbed);
	block_network_flag() = false;
	kill_on_host_exit_flag() = true;
	memory_cap_mb_value() = 0;
	auto_terminate_sec_value() = 0;
	malware_safe_mode_flag() = true;
	log_network_traffic_flag() = true;
	lower_integrity_untrusted_flag() = false;
	allow_child_processes_flag() = true;
	force_mitigations_strict_flag() = false;
	redirect_user_paths_flag() = true;
	register_kernel_guard_flag() = true;
}



inline std::wstring widen_utf8(const char* utf8) {
	if (!utf8 || !*utf8) return std::wstring();
	int needed = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
	if (needed <= 1) return std::wstring();
	std::wstring out(static_cast<size_t>(needed - 1), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out.data(), needed);
	return out;
}

inline std::string narrow_utf8(const wchar_t* w) {
	if (!w || !*w) return std::string();
	int needed = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
	if (needed <= 1) return std::string();
	std::string out(static_cast<size_t>(needed - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), needed, nullptr, nullptr);
	return out;
}

inline std::string parent_dir(const std::string& path) {
	if (path.empty()) return std::string();
	size_t pos = path.find_last_of("\\/");
	if (pos == std::string::npos) return std::string();
	return path.substr(0, pos);
}

inline std::string trim(const char* s) {
	if (!s) return std::string();
	std::string out(s);
	while (!out.empty()) {
		char c = out.back();
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') out.pop_back();
		else break;
	}
	size_t i = 0;
	while (i < out.size()) {
		char c = out[i];
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++i;
		else break;
	}
	if (i > 0) out.erase(0, i);
	return out;
}

inline void browse_executable() {
	diag::log_tagged_critical("file_dialog", "spawn_target.browse_executable invoking show_open_file_dialog_w");
	wchar_t path_buf[1024] = {};
	std::string current = trim(exe_buf());
	if (!current.empty()) {
		std::wstring w = widen_utf8(current.c_str());
		size_t n = w.size();
		if (n >= 1023) n = 1023;
		if (n > 0) std::memcpy(path_buf, w.data(), n * sizeof(wchar_t));
		path_buf[n] = L'\0';
	}

	static const wchar_t k_spawn_exe_filter[] =
		L"Binary files (*.exe;*.dll;*.sys;*.com;*.scr;*.efi;*.cpl)\0*.exe;*.dll;*.sys;*.com;*.scr;*.efi;*.cpl\0"
		L"Executable files (*.exe;*.com;*.scr)\0*.exe;*.com;*.scr\0"
		L"Libraries (*.dll;*.cpl)\0*.dll;*.cpl\0"
		L"Drivers (*.sys;*.efi)\0*.sys;*.efi\0"
		L"All files (*.*)\0*.*\0\0";
	if (!win32_dialog::show_open_file_dialog_w(g_hwnd,
			L"Select target binary (.exe / .dll / .sys)",
			k_spawn_exe_filter,
			path_buf, 1024,
			"spawn_target::browse_executable")) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_executable cancelled_or_failed");
		return;
	}

	std::string sel = narrow_utf8(path_buf);
	if (sel.empty()) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_executable empty_path");
		return;
	}

	{
		DWORD attrs = ::GetFileAttributesW(path_buf);
		if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			diag::log_tagged_critical_fmt("file_dialog",
				"spawn_target.browse_executable missing_or_dir path='%s' attrs=0x%08X",
				sel.c_str(), static_cast<unsigned int>(attrs));
			toast_notification::push(
				"Selected file does not exist on disk: " + sel,
				toast_notification::toast_type_t::error, 5.0f);
			return;
		}
	}

	std::strncpy(exe_buf(), sel.c_str(), 1023);
	exe_buf()[1023] = '\0';

	if (cwd_buf()[0] == '\0') {
		std::string parent = parent_dir(sel);
		if (!parent.empty()) {
			std::strncpy(cwd_buf(), parent.c_str(), 1023);
			cwd_buf()[1023] = '\0';
		}
	}

	diag::log_tagged_critical_fmt("file_dialog",
		"spawn_target.browse_executable ok path='%s'", sel.c_str());
	diag::log_tagged_critical_fmt("dialog",
		"spawn_browse_exe_selected path='%s'", sel.c_str());
}

inline void browse_working_dir() {
	diag::log_tagged_critical("file_dialog", "spawn_target.browse_working_dir invoking show_open_folder_dialog_ex");
	std::string current = trim(cwd_buf());
	std::wstring initial = current.empty() ? std::wstring() : widen_utf8(current.c_str());
	std::string picked;
	if (!win32_dialog::show_open_folder_dialog_ex(g_hwnd,
			L"Select working directory",
			initial.empty() ? nullptr : initial.c_str(),
			picked,
			"spawn_target::browse_working_dir")) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_working_dir cancelled_or_failed");
		return;
	}
	if (picked.empty()) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_working_dir empty_path");
		return;
	}
	std::strncpy(cwd_buf(), picked.c_str(), 1023);
	cwd_buf()[1023] = '\0';
	diag::log_tagged_critical_fmt("file_dialog",
		"spawn_target.browse_working_dir ok path='%s'", picked.c_str());
	diag::log_tagged_critical_fmt("dialog",
		"spawn_browse_cwd_selected path='%s'", picked.c_str());
}

}

inline bool is_open() {
	return detail::open_flag() || detail::should_open();
}

inline void request_open() {
	detail::reset_inputs();
	detail::pending_result_ready() = false;
	detail::pending_result() = result_t{};
	detail::should_open() = true;
	diag::log_tagged_critical("spawn", "spawn_dialog_open_requested");
}

inline bool consume_result(result_t& out) {
	if (!detail::pending_result_ready()) return false;
	out = std::move(detail::pending_result());
	detail::pending_result() = result_t{};
	detail::pending_result_ready() = false;
	return true;
}

inline void render() {
	static int s_last_render_frame = -1;
	int cur_frame = ImGui::GetFrameCount();
	if (s_last_render_frame == cur_frame) return;
	s_last_render_frame = cur_frame;

	if (detail::should_open()) {
		ImGui::OpenPopup("Launch Target###aida_spawn_target_dialog");
		detail::should_open() = false;
		detail::open_flag() = true;
	}

	if (!detail::open_flag()) return;

	const auto& tk = aida::ui::resolved();
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 18.f));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10.f, 12.f));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(tk.bg_overlay));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(tk.border_subtle));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(tk.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_primary));

	ImVec2 viewport_center = ImGui::GetMainViewport()->GetCenter();
	ImGui::SetNextWindowPos(viewport_center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	ImGui::SetNextWindowSizeConstraints(ImVec2(620.f, 0.f), ImVec2(620.f, FLT_MAX));
	ImGui::SetNextWindowSize(ImVec2(620.f, 0.f), ImGuiCond_Appearing);

	bool open_flag_local = true;
	bool launch_now = false;
	bool cancel_now = false;

	if (ImGui::BeginPopupModal("Launch Target###aida_spawn_target_dialog",
	                           &open_flag_local,
	                           ImGuiWindowFlags_NoSavedSettings |
	                           ImGuiWindowFlags_NoResize)) {

		ImFont* title_font = aida::ui::fonts::h1();
		ImFont* body_font  = aida::ui::fonts::body();
		ImFont* caption    = aida::ui::fonts::caption();

		if (title_font) ImGui::PushFont(title_font);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_primary),
		                   "Launch Target");
		if (title_font) ImGui::PopFont();

		if (caption) ImGui::PushFont(caption);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Spawn a binary on the host and immediately attach AiDA's driver.");
		if (caption) ImGui::PopFont();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		if (body_font) ImGui::PushFont(body_font);

		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Executable path");
		float browse_btn_w = 96.f;
		float input_w = ImGui::GetContentRegionAvail().x - browse_btn_w - 10.f;
		if (input_w < 200.f) input_w = 200.f;

		aida::ui::input_text("##spawn_exe_path", detail::exe_buf(), 1024,
		                     "C:\\path\\to\\target.exe", false,
		                     ImVec2(input_w, 36.f));
		ImGui::SameLine();
		if (aida::ui::button("Browse...", aida::ui::button_kind_t::secondary,
		                     aida::ui::size_t_::md,
		                     ImVec2(browse_btn_w, 36.f), false, nullptr, false)) {
			detail::browse_executable();
		}
		ImGui::Dummy(ImVec2(0.f, 2.f));

		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Arguments (optional)");
		aida::ui::input_text("##spawn_args", detail::args_buf(), 2048,
		                     "--example-arg value",
		                     false, ImVec2(0.f, 36.f));
		ImGui::Dummy(ImVec2(0.f, 2.f));

		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Working directory (optional, defaults to executable's directory)");
		aida::ui::input_text("##spawn_cwd", detail::cwd_buf(), 1024,
		                     "C:\\analysis\\workdir", false,
		                     ImVec2(input_w, 36.f));
		ImGui::SameLine();
		if (aida::ui::button("Browse...##cwd", aida::ui::button_kind_t::secondary,
		                     aida::ui::size_t_::md,
		                     ImVec2(browse_btn_w, 36.f), false, nullptr, false)) {
			detail::browse_working_dir();
		}

		if (body_font) ImGui::PopFont();

		ImGui::Dummy(ImVec2(0.f, 10.f));

		if (body_font) ImGui::PushFont(body_font);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Launch options");
		if (body_font) ImGui::PopFont();
		ImGui::Dummy(ImVec2(0.f, 2.f));

		{
			int* iso = &detail::isolation_choice();
			aida::ui::radio_button(
				"Same desktop  (jobbed; interact + driver attach)",
				iso, static_cast<int>(run_target::isolation_t::same_desktop_jobbed));
			aida::ui::radio_button(
				"Malware-safe desktop  (restricted token + kernel guard + network log; UI visible)",
				iso, static_cast<int>(run_target::isolation_t::malware_safe_desktop));
			aida::ui::radio_button(
				"AppContainer  (FS/registry isolated)",
				iso, static_cast<int>(run_target::isolation_t::appcontainer));
			aida::ui::radio_button(
				"Windows Sandbox  (separate desktop, max safety)",
				iso, static_cast<int>(run_target::isolation_t::windows_sandbox));
		}

		ImGui::Dummy(ImVec2(0.f, 4.f));
		{
			bool* bn = &detail::block_network_flag();
			aida::ui::toggle_switch("Block network access", bn, aida::ui::size_t_::sm);
			ImGui::SameLine(0.f, 18.f);
			bool* ke = &detail::kill_on_host_exit_flag();
			aida::ui::toggle_switch("Kill target on AiDA exit", ke, aida::ui::size_t_::sm);
		}

		ImGui::Dummy(ImVec2(0.f, 4.f));
		{
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Memory limit (MB, 0 = no limit)");
			aida::ui::input_int("##spawn_memcap", &detail::memory_cap_mb_value(),
			                    ImVec2(input_w, 36.f));
			if (detail::memory_cap_mb_value() < 0) detail::memory_cap_mb_value() = 0;
		}

		ImGui::Dummy(ImVec2(0.f, 4.f));
		{
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Auto-terminate after (seconds, 0 = no limit)");
			aida::ui::input_int("##spawn_autoterm", &detail::auto_terminate_sec_value(),
			                    ImVec2(input_w, 36.f));
			if (detail::auto_terminate_sec_value() < 0) detail::auto_terminate_sec_value() = 0;
		}

		ImGui::Dummy(ImVec2(0.f, 10.f));

		bool malware_section_available =
			(detail::isolation_choice() == static_cast<int>(run_target::isolation_t::same_desktop_jobbed)
			 || detail::isolation_choice() == static_cast<int>(run_target::isolation_t::malware_safe_desktop));

		if (malware_section_available) {
			if (body_font) ImGui::PushFont(body_font);
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Malware Safety");
			if (body_font) ImGui::PopFont();
			if (caption) ImGui::PushFont(caption);
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Run unknown samples on the host with restricted token, mitigation policy, and per-launch sandbox.");
			if (caption) ImGui::PopFont();
			ImGui::Dummy(ImVec2(0.f, 4.f));

			{
				bool* ms = &detail::malware_safe_mode_flag();
				aida::ui::toggle_switch("Treat as malware (recommended for unknown samples)",
				                       ms, aida::ui::size_t_::sm);
			}
			ImGui::Dummy(ImVec2(0.f, 2.f));
			{
				bool* lt = &detail::log_network_traffic_flag();
				aida::ui::toggle_switch("Log network traffic (driver-level packet capture)",
				                       lt, aida::ui::size_t_::sm);
				ImGui::SameLine(0.f, 18.f);
				bool* kg = &detail::register_kernel_guard_flag();
				aida::ui::toggle_switch("Register kernel sandbox guard",
				                       kg, aida::ui::size_t_::sm);
			}
			ImGui::Dummy(ImVec2(0.f, 2.f));
			{
				bool* lu = &detail::lower_integrity_untrusted_flag();
				aida::ui::toggle_switch("Lower integrity to Untrusted (paranoid)",
				                       lu, aida::ui::size_t_::sm);
				ImGui::SameLine(0.f, 18.f);
				bool* ac = &detail::allow_child_processes_flag();
				aida::ui::toggle_switch("Allow target to spawn children",
				                       ac, aida::ui::size_t_::sm);
			}
			ImGui::Dummy(ImVec2(0.f, 2.f));
			{
				bool* rp = &detail::redirect_user_paths_flag();
				aida::ui::toggle_switch("Redirect AppData/Temp/UserProfile into sandbox",
				                       rp, aida::ui::size_t_::sm);
				ImGui::SameLine(0.f, 18.f);
				bool* fm = &detail::force_mitigations_strict_flag();
				aida::ui::toggle_switch("Strict signature mitigations (may break packers)",
				                       fm, aida::ui::size_t_::sm);
			}

			if (!detail::last_sandbox_dir().empty()) {
				ImGui::Dummy(ImVec2(0.f, 4.f));
				std::string sb_utf8 = detail::narrow_utf8(detail::last_sandbox_dir().c_str());
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
				                   "Last sandbox: %s", sb_utf8.c_str());
				ImGui::SameLine();
				if (aida::ui::button("Open folder##spawn_open_sandbox",
				                     aida::ui::button_kind_t::secondary,
				                     aida::ui::size_t_::sm,
				                     ImVec2(110.f, 28.f), false, nullptr, false)) {
					ShellExecuteW(g_hwnd, L"open", detail::last_sandbox_dir().c_str(),
					              nullptr, nullptr, SW_SHOWNORMAL);
				}
			}
		}

		ImGui::Dummy(ImVec2(0.f, 6.f));

		{
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 pos = ImGui::GetCursorScreenPos();
			float w = ImGui::GetContentRegionAvail().x;
			float pad_x = 14.f;
			float pad_y = 10.f;
			ImFont* warn_font = aida::ui::fonts::body_em();
			if (!warn_font) warn_font = ImGui::GetFont();
			ImFont* base = ImGui::GetFont();
			float fs_title = warn_font->FontSize;
			float fs_body = base->FontSize;

			const bool malware_active =
				malware_section_available && detail::malware_safe_mode_flag();
			const char* warn_title = malware_active
				? "Malware-safe mode active"
				: "Caution: live execution on host";
			const char* warn_body  = malware_active
				? "The target's UI is visible. Host filesystem outside the sandbox folder is protected by token IL + mitigation policy + job UI limits. Network traffic is recorded if the driver is loaded. Persistence sites, raw disk, and kernel handles are gated by WhosWho."
				: "AiDA spawns the target inside a Job Object (and optional AppContainer / Windows Sandbox), optionally blocks the network, then attaches the driver. Containment level is your choice above.";

			ImVec2 ts_title = warn_font->CalcTextSizeA(fs_title, FLT_MAX, w - pad_x * 2.f, warn_title);
			ImVec2 ts_body = base->CalcTextSizeA(fs_body, FLT_MAX, w - pad_x * 2.f, warn_body);
			float box_h = pad_y * 2.f + ts_title.y + 6.f + ts_body.y;
			ImVec2 a = pos;
			ImVec2 b = ImVec2(pos.x + w, pos.y + box_h);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(tk.warning, 0.18f), 8.f);
			dl->AddRect(a, b, aida::ui::with_alpha(tk.warning, 0.65f), 8.f, 0, 1.25f);
			dl->AddText(warn_font, fs_title,
			            ImVec2(a.x + pad_x, a.y + pad_y),
			            tk.warning, warn_title);
			dl->AddText(base, fs_body,
			            ImVec2(a.x + pad_x, a.y + pad_y + ts_title.y + 6.f),
			            aida::ui::with_alpha(tk.text_primary, 0.92f),
			            warn_body, nullptr, w - pad_x * 2.f);
			ImGui::Dummy(ImVec2(w, box_h));
		}

		ImGui::Dummy(ImVec2(0.f, 6.f));

		std::string exe_trim = detail::trim(detail::exe_buf());
		bool launch_disabled = exe_trim.empty();

		float total_w = ImGui::GetContentRegionAvail().x;
		float btn_w = 130.f;
		float gap = 10.f;
		float row_w = btn_w * 2.f + gap;
		float row_x_offset = total_w - row_w;
		if (row_x_offset < 0.f) row_x_offset = 0.f;
		ImGui::Dummy(ImVec2(row_x_offset, 0.f));
		ImGui::SameLine();

		if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
		                     aida::ui::size_t_::md,
		                     ImVec2(btn_w, 40.f), false, nullptr, false)) {
			cancel_now = true;
		}
		ImGui::SameLine(0.f, gap);
		if (aida::ui::button("Launch", aida::ui::button_kind_t::primary,
		                     aida::ui::size_t_::md,
		                     ImVec2(btn_w, 40.f), launch_disabled, nullptr, false)) {
			launch_now = true;
		}

		ImGuiIO& io = ImGui::GetIO();
		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
			cancel_now = true;
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Enter, false) && !launch_disabled)
			launch_now = true;

		if (launch_now && !launch_disabled) {
			std::string args_trim = detail::trim(detail::args_buf());
			std::string cwd_trim  = detail::trim(detail::cwd_buf());

			result_t& pending = detail::pending_result();
			pending.exe_path     = detail::widen_utf8(exe_trim.c_str());
			pending.args         = detail::widen_utf8(args_trim.c_str());
			pending.working_dir  = detail::widen_utf8(cwd_trim.c_str());

			run_target::launch_options_t& lo = pending.launch_options;
			lo.exe_path           = pending.exe_path;
			lo.args               = pending.args;
			lo.working_dir        = pending.working_dir;
			lo.isolation          = static_cast<run_target::isolation_t>(detail::isolation_choice());
			lo.block_network      = detail::block_network_flag();
			lo.kill_on_host_exit  = detail::kill_on_host_exit_flag();
			lo.attach_after_resume = (lo.isolation != run_target::isolation_t::windows_sandbox);
			int mem = detail::memory_cap_mb_value();
			lo.memory_cap_mb      = mem > 0 ? static_cast<uint32_t>(mem) : 0u;
			int term = detail::auto_terminate_sec_value();
			lo.auto_terminate_sec = term > 0 ? static_cast<uint32_t>(term) : 0u;

			const bool iso_supports_malware =
				(lo.isolation == run_target::isolation_t::same_desktop_jobbed
				 || lo.isolation == run_target::isolation_t::malware_safe_desktop);
			lo.malware_safe_mode = iso_supports_malware && detail::malware_safe_mode_flag();
			lo.log_network_traffic = iso_supports_malware && detail::log_network_traffic_flag();
			lo.lower_integrity_untrusted = iso_supports_malware && detail::lower_integrity_untrusted_flag();
			lo.allow_child_processes = !iso_supports_malware || detail::allow_child_processes_flag();
			lo.force_mitigations_strict = iso_supports_malware && detail::force_mitigations_strict_flag();
			lo.redirect_user_paths_to_sandbox = iso_supports_malware && detail::redirect_user_paths_flag();
			lo.register_kernel_sandbox_guard = iso_supports_malware && detail::register_kernel_guard_flag();

			pending.accepted = true;
			detail::pending_result_ready() = true;

			diag::log_tagged_critical_fmt("spawn",
				"spawn_dialog_launch exe='%s' args_len=%zu cwd='%s' iso=%d block_net=%d kill_on_exit=%d mem_cap=%u auto_term=%u malware_safe=%d log_net=%d untrusted=%d allow_children=%d strict=%d redirect_paths=%d kernel_guard=%d",
				exe_trim.c_str(), args_trim.size(),
				cwd_trim.empty() ? "<inherit>" : cwd_trim.c_str(),
				static_cast<int>(lo.isolation),
				lo.block_network ? 1 : 0,
				lo.kill_on_host_exit ? 1 : 0,
				static_cast<unsigned>(lo.memory_cap_mb),
				static_cast<unsigned>(lo.auto_terminate_sec),
				lo.malware_safe_mode ? 1 : 0,
				lo.log_network_traffic ? 1 : 0,
				lo.lower_integrity_untrusted ? 1 : 0,
				lo.allow_child_processes ? 1 : 0,
				lo.force_mitigations_strict ? 1 : 0,
				lo.redirect_user_paths_to_sandbox ? 1 : 0,
				lo.register_kernel_sandbox_guard ? 1 : 0);

			ImGui::CloseCurrentPopup();
			detail::open_flag() = false;
		} else if (cancel_now || !open_flag_local) {
			detail::pending_result_ready() = false;
			detail::pending_result() = result_t{};
			diag::log_tagged_critical("spawn", "spawn_dialog_cancelled");
			ImGui::CloseCurrentPopup();
			detail::open_flag() = false;
		}

		ImGui::EndPopup();
	} else {
		detail::open_flag() = false;
	}

	ImGui::PopStyleColor(4);
	ImGui::PopStyleVar(4);
}

}
