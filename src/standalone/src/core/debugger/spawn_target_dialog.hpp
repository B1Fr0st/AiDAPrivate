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

inline run_target::capability_probe_t& cached_capabilities() {
	static run_target::capability_probe_t p;
	return p;
}

inline int& isolation_choice() {
	static int v = static_cast<int>(run_target::isolation_t::windows_sandbox);
	return v;
}

inline int& run_mode_choice() {
	static int v = 0;
	return v;
}

inline bool& host_confirm_open() {
	static bool v = false;
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
	isolation_choice() = static_cast<int>(run_target::isolation_t::windows_sandbox);
	run_mode_choice() = 0;
	host_confirm_open() = false;
	block_network_flag() = true;
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

inline void open_url(const wchar_t* url) {
	if (!url || !*url) return;
	ShellExecuteW(g_hwnd, L"open", url, nullptr, nullptr, SW_SHOWNORMAL);
}

inline bool prepare_launch_result(bool host_mode) {
	std::string exe_trim = trim(exe_buf());
	if (exe_trim.empty()) return false;
	std::string args_trim = trim(args_buf());
	std::string cwd_trim = host_mode ? trim(cwd_buf()) : std::string();

	result_t& pending = pending_result();
	pending = result_t{};
	pending.exe_path     = widen_utf8(exe_trim.c_str());
	pending.args         = widen_utf8(args_trim.c_str());
	pending.working_dir  = widen_utf8(cwd_trim.c_str());

	run_target::launch_options_t& lo = pending.launch_options;
	lo.exe_path           = pending.exe_path;
	lo.args               = pending.args;
	lo.working_dir        = pending.working_dir;
	lo.isolation          = host_mode
		? run_target::isolation_t::same_desktop_jobbed
		: run_target::isolation_t::windows_sandbox;
	lo.block_network      = block_network_flag();
	lo.kill_on_host_exit  = kill_on_host_exit_flag();
	lo.attach_after_resume = host_mode;
	int mem = memory_cap_mb_value();
	lo.memory_cap_mb      = mem > 0 ? static_cast<uint32_t>(mem) : 0u;
	int term = auto_terminate_sec_value();
	lo.auto_terminate_sec = term > 0 ? static_cast<uint32_t>(term) : 0u;
	lo.malware_safe_mode = false;
	lo.log_network_traffic = false;
	lo.lower_integrity_untrusted = false;
	lo.allow_child_processes = true;
	lo.force_mitigations_strict = false;
	lo.redirect_user_paths_to_sandbox = false;
	lo.register_kernel_sandbox_guard = false;

	pending.accepted = true;
	pending_result_ready() = true;

	diag::log_tagged_critical_fmt("spawn",
		"spawn_dialog_launch exe='%s' args_len=%zu cwd='%s' iso=%d block_net=%d kill_on_exit=%d mem_cap=%u auto_term=%u attach=%d host_mode=%d",
		exe_trim.c_str(), args_trim.size(),
		cwd_trim.empty() ? "<inherit>" : cwd_trim.c_str(),
		static_cast<int>(lo.isolation),
		lo.block_network ? 1 : 0,
		lo.kill_on_host_exit ? 1 : 0,
		static_cast<unsigned>(lo.memory_cap_mb),
		static_cast<unsigned>(lo.auto_terminate_sec),
		lo.attach_after_resume ? 1 : 0,
		host_mode ? 1 : 0);
	return true;
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
	detail::cached_capabilities() = run_target::probe_capabilities();
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
		ImGui::OpenPopup("Malware Lab Run###aida_spawn_target_dialog");
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
	bool close_parent_after_host_confirm = false;

	if (ImGui::BeginPopupModal("Malware Lab Run###aida_spawn_target_dialog",
	                           &open_flag_local,
	                           ImGuiWindowFlags_NoSavedSettings |
	                           ImGuiWindowFlags_NoResize)) {

		ImFont* title_font = aida::ui::fonts::h1();
		ImFont* body_font  = aida::ui::fonts::body();
		ImFont* caption    = aida::ui::fonts::caption();

		if (title_font) ImGui::PushFont(title_font);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_primary),
		                   "Malware Lab Run");
		if (title_font) ImGui::PopFont();

		if (caption) ImGui::PushFont(caption);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Choose Run in VM or Run in Host every time you launch a sample.");
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

		if (body_font) ImGui::PopFont();

		ImGui::Dummy(ImVec2(0.f, 10.f));

		if (body_font) ImGui::PushFont(body_font);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Launch target");
		if (body_font) ImGui::PopFont();
		ImGui::Dummy(ImVec2(0.f, 2.f));

		{
			int& mode = detail::run_mode_choice();
			ImGui::RadioButton("Run in VM", &mode, 0);
			ImGui::SameLine(0.f, 28.f);
			ImGui::RadioButton("Run in Host", &mode, 1);
			detail::isolation_choice() = mode == 0
				? static_cast<int>(run_target::isolation_t::windows_sandbox)
				: static_cast<int>(run_target::isolation_t::same_desktop_jobbed);
		}

		ImGui::Dummy(ImVec2(0.f, 4.f));
		const bool vm_mode = detail::run_mode_choice() == 0;
		if (vm_mode) {
			if (caption) ImGui::PushFont(caption);
			ImGui::TextWrapped("First-time setup for Run in VM");
			ImGui::BulletText("Windows edition: Pro, Enterprise, or Education. Windows Home users need a full VM such as VMware Workstation Pro or VirtualBox.");
			ImGui::BulletText("For QEMU, VirtualBox, or VMware, keep AiDAStandalone.exe on the host. Do not copy AiDAStandalone.exe into the guest VM.");
			ImGui::BulletText("Run only the target sample and your MCP client or guest agent in the guest VM. Route that client through an authenticated host bridge or tunnel that terminates at AiDA's localhost MCP endpoint.");
			ImGui::BulletText("Do not bind AiDA's MCP endpoint directly to a guest, LAN, or untrusted adapter. MCP tools can mutate host files, sessions, debugger state, and process memory.");
			ImGui::BulletText("Custom VM workflows use the normal AiDA MCP tools with explicit target selection, including list_processes, driver_attach, read_memory, query_memory, enumerate_modules, enumerate_threads, and disassemble_address.");
			ImGui::BulletText("Download for full VM fallback: VMware Workstation Pro or Oracle VirtualBox, then a Windows evaluation ISO.");
			ImGui::BulletText("BIOS/UEFI: enable Intel VT-x or AMD-V/SVM, then boot back into Windows.");
			ImGui::BulletText("Admin PowerShell: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All");
			ImGui::BulletText("Reboot, reopen AiDA, press Run, select Run in VM, then Open VM.");
			ImGui::BulletText("The built-in Open VM flow opens the sample inside Windows Sandbox and stages only the sandbox guest bridge, not AiDAStandalone.exe.");
			const auto& caps = detail::cached_capabilities();
			if (!caps.has_windows_sandbox) {
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.warning),
				                   "Windows Sandbox is not available on this PC right now.");
			}
			if (caption) ImGui::PopFont();
			if (aida::ui::button("Sandbox Docs", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(118.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install");
			}
			ImGui::SameLine();
			if (aida::ui::button("WSB Config", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(104.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file");
			}
			ImGui::SameLine();
			if (aida::ui::button("Eval ISO", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(90.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise");
			}
			if (aida::ui::button("VMware", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(92.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://knowledge.broadcom.com/external/article/344595/downloading-vmware-workstation-pro.html");
			}
			ImGui::SameLine();
			if (aida::ui::button("VirtualBox", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(108.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://www.virtualbox.org/wiki/Downloads");
			}
		} else {
			if (caption) ImGui::PushFont(caption);
			ImGui::TextWrapped("Host mode runs the selected binary on this Windows installation. It is not a malware or BYOVD containment boundary and can compromise the host.");
			if (caption) ImGui::PopFont();
			ImGui::Dummy(ImVec2(0.f, 2.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Working directory");
			float browse_btn_w2 = 96.f;
			float input_w2 = ImGui::GetContentRegionAvail().x - browse_btn_w2 - 10.f;
			if (input_w2 < 200.f) input_w2 = 200.f;
			aida::ui::input_text("##spawn_cwd", detail::cwd_buf(), 1024,
			                     "C:\\path\\to\\working-directory", false,
			                     ImVec2(input_w2, 36.f));
			ImGui::SameLine();
			if (aida::ui::button("Browse##cwd", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::md,
			                     ImVec2(browse_btn_w2, 36.f), false, nullptr, false)) {
				detail::browse_working_dir();
			}
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

		if (!detail::last_sandbox_dir().empty()) {
			ImGui::Dummy(ImVec2(0.f, 4.f));
			std::string sb_utf8 = detail::narrow_utf8(detail::last_sandbox_dir().c_str());
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Last VM workspace: %s", sb_utf8.c_str());
			ImGui::SameLine();
			if (aida::ui::button("Open folder##spawn_open_sandbox",
			                     aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm,
			                     ImVec2(110.f, 28.f), false, nullptr, false)) {
				ShellExecuteW(g_hwnd, L"open", detail::last_sandbox_dir().c_str(),
				              nullptr, nullptr, SW_SHOWNORMAL);
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

			const bool host_mode = detail::run_mode_choice() == 1;
			const char* warn_title = host_mode ? "Host execution warning" : "Interactive VM sandbox";
			const char* warn_body  = host_mode
				? "Run in Host starts the selected binary on this Windows installation and may attach AiDA's host driver. Do not use this for malware, cheat loaders, BYOVD samples, unknown drivers, or anything you do not fully trust."
				: "Run in VM copies the sample into a disposable Windows Sandbox workspace, disables clipboard and device redirection, optionally disables networking, and starts the sample in the sandbox window. AiDAStandalone.exe remains on the host; the sandbox receives only the staged sample and guest bridge.";

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
		bool launch_disabled = exe_trim.empty()
			|| (detail::run_mode_choice() == 0 && !detail::cached_capabilities().has_windows_sandbox);

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
		const char* launch_label = detail::run_mode_choice() == 0 ? "Open VM" : "Run Host";
		if (aida::ui::button(launch_label, aida::ui::button_kind_t::primary,
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
			if (detail::run_mode_choice() == 1) {
				detail::host_confirm_open() = true;
				ImGui::OpenPopup("Confirm Host Run###aida_spawn_host_confirm");
			} else if (detail::prepare_launch_result(false)) {
				ImGui::CloseCurrentPopup();
				detail::open_flag() = false;
			}
		} else if (cancel_now || !open_flag_local) {
			detail::pending_result_ready() = false;
			detail::pending_result() = result_t{};
			diag::log_tagged_critical("spawn", "spawn_dialog_cancelled");
			ImGui::CloseCurrentPopup();
			detail::open_flag() = false;
		}

		if (detail::host_confirm_open()) {
			ImGui::SetNextWindowSize(ImVec2(520.f, 0.f), ImGuiCond_Appearing);
			bool confirm_open = true;
			if (ImGui::BeginPopupModal("Confirm Host Run###aida_spawn_host_confirm",
			                           &confirm_open,
			                           ImGuiWindowFlags_NoSavedSettings |
			                           ImGuiWindowFlags_NoResize)) {
				if (title_font) ImGui::PushFont(title_font);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.warning),
				                   "Run in Host?");
				if (title_font) ImGui::PopFont();
				if (caption) ImGui::PushFont(caption);
				ImGui::TextWrapped("This will execute the selected binary on your real desktop, not inside the VM.");
				ImGui::TextWrapped("Cancel unless the file is trusted. Host mode can expose your PC, credentials, kernel, files, and drivers to the sample.");
				if (caption) ImGui::PopFont();
				ImGui::Dummy(ImVec2(0.f, 8.f));
				float cw = ImGui::GetContentRegionAvail().x;
				float cbw = 150.f;
				float cgap = 10.f;
				float cx = cw - cbw * 2.f - cgap;
				if (cx < 0.f) cx = 0.f;
				ImGui::Dummy(ImVec2(cx, 0.f));
				ImGui::SameLine();
				if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
				                     aida::ui::size_t_::md,
				                     ImVec2(cbw, 40.f), false, nullptr, false)) {
					detail::host_confirm_open() = false;
					ImGui::CloseCurrentPopup();
				}
				ImGui::SameLine(0.f, cgap);
				if (aida::ui::button("Run in Host", aida::ui::button_kind_t::destructive,
				                     aida::ui::size_t_::md,
				                     ImVec2(cbw, 40.f), false, nullptr, false)) {
					if (detail::prepare_launch_result(true)) {
						detail::host_confirm_open() = false;
						ImGui::CloseCurrentPopup();
						close_parent_after_host_confirm = true;
					}
				}
				if (!confirm_open) {
					detail::host_confirm_open() = false;
				}
				ImGui::EndPopup();
			} else if (!confirm_open) {
				detail::host_confirm_open() = false;
			}
		}

		if (close_parent_after_host_confirm) {
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
