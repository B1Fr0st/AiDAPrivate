#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <commdlg.h>
#include <shobjidl.h>
#include <shobjidl_core.h>
#include <shlobj.h>
#include <objbase.h>
#include <cstddef>
#include <cstring>
#include <string>

#include "diag_log.hpp"

extern HWND g_hwnd;

namespace win32_dialog {

namespace detail {

inline bool is_valid_filter_pairs(const char* filter_pairs, size_t max_scan)
{
	if (!filter_pairs) return false;
	size_t i = 0;
	bool last_was_zero = false;
	while (i < max_scan) {
		char c = filter_pairs[i];
		if (c == '\0') {
			if (last_was_zero) return true;
			last_was_zero = true;
		} else {
			last_was_zero = false;
		}
		++i;
	}
	return false;
}

inline HWND default_owner(HWND owner)
{
	if (owner != nullptr) return owner;
	return ::g_hwnd;
}

inline bool ensure_apartment(HRESULT& co_init_out, bool& need_uninit_out, const char* caller_name)
{
	co_init_out = CoInitializeEx(nullptr,
		COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	if (co_init_out == S_OK || co_init_out == S_FALSE) {
		need_uninit_out = (co_init_out == S_OK);
		diag::log_tagged_fmt("dialog",
			"%s CoInitializeEx STA ok tid=%lu need_uninit=%d",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(GetCurrentThreadId()),
			need_uninit_out ? 1 : 0);
		return true;
	}
	if (co_init_out == RPC_E_CHANGED_MODE) {
		need_uninit_out = false;
		diag::log_tagged_fmt("dialog",
			"%s CoInitializeEx RPC_E_CHANGED_MODE thread already MTA tid=%lu proceeding via MTA",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(GetCurrentThreadId()));
		return true;
	}
	need_uninit_out = false;
	diag::log_tagged_fmt("dialog",
		"%s CoInitializeEx FAILED hr=0x%08lX tid=%lu",
		caller_name ? caller_name : "win32_dialog",
		static_cast<unsigned long>(co_init_out),
		static_cast<unsigned long>(GetCurrentThreadId()));
	return false;
}

}

inline bool show_open_file_dialog_ex(HWND owner,
	const char* title,
	const char* filter_pairs,
	const char* initial_dir,
	char* out_path,
	size_t out_path_capacity,
	const char* caller_name)
{
	if (!out_path || out_path_capacity < 2) {
		diag::log_tagged_fmt("dialog",
			"%s open invalid out_path buf=%p cap=%zu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<void*>(out_path), out_path_capacity);
		return false;
	}
	out_path[0] = '\0';

	if (!detail::is_valid_filter_pairs(filter_pairs, 4096)) {
		diag::log_tagged_fmt("dialog",
			"%s open invalid filter_pairs missing double-NUL terminator",
			caller_name ? caller_name : "win32_dialog");
		return false;
	}

	HWND used_owner = detail::default_owner(owner);
	DWORD tid = GetCurrentThreadId();
	BOOL is_gui = IsGUIThread(FALSE);
	diag::log_tagged_fmt("dialog",
		"%s open begin hwnd=%p tid=%lu gui=%d initial_dir='%.260s'",
		caller_name ? caller_name : "win32_dialog",
		static_cast<void*>(used_owner), tid, is_gui ? 1 : 0,
		initial_dir ? initial_dir : "");

	HRESULT co_init = E_FAIL;
	bool need_uninit = false;
	if (!detail::ensure_apartment(co_init, need_uninit, caller_name)) {
		return false;
	}

	OPENFILENAMEA ofn = {};
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = used_owner;
	ofn.lpstrFile = out_path;
	ofn.nMaxFile = static_cast<DWORD>(out_path_capacity);
	ofn.lpstrFilter = filter_pairs;
	ofn.nFilterIndex = 1;
	ofn.lpstrTitle = title;
	ofn.lpstrInitialDir = (initial_dir && initial_dir[0]) ? initial_dir : nullptr;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;

	BOOL ok = GetOpenFileNameA(&ofn);
	DWORD cde = ok ? 0 : CommDlgExtendedError();
	DWORD gle = GetLastError();

	if (need_uninit) CoUninitialize();

	if (!ok) {
		diag::log_tagged_fmt("dialog",
			"%s open end ok=0 cde=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(cde),
			static_cast<unsigned long>(gle));
		out_path[0] = '\0';
		return false;
	}

	diag::log_tagged_fmt("dialog",
		"%s open end ok=1 path='%.260s'",
		caller_name ? caller_name : "win32_dialog", out_path);
	return true;
}

inline bool show_open_file_dialog(HWND owner,
	const char* title,
	const char* filter_pairs,
	char* out_path,
	size_t out_path_capacity,
	const char* caller_name)
{
	return show_open_file_dialog_ex(owner, title, filter_pairs,
		nullptr, out_path, out_path_capacity, caller_name);
}

inline bool show_save_file_dialog(HWND owner,
	const char* title,
	const char* filter_pairs,
	const char* default_ext,
	char* out_path,
	size_t out_path_capacity,
	const char* caller_name)
{
	if (!out_path || out_path_capacity < 2) {
		diag::log_tagged_fmt("dialog",
			"%s save invalid out_path buf=%p cap=%zu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<void*>(out_path), out_path_capacity);
		return false;
	}

	if (!detail::is_valid_filter_pairs(filter_pairs, 4096)) {
		diag::log_tagged_fmt("dialog",
			"%s save invalid filter_pairs missing double-NUL terminator",
			caller_name ? caller_name : "win32_dialog");
		return false;
	}

	HWND used_owner = detail::default_owner(owner);
	DWORD tid = GetCurrentThreadId();
	BOOL is_gui = IsGUIThread(FALSE);
	diag::log_tagged_fmt("dialog",
		"%s save begin hwnd=%p tid=%lu gui=%d preset='%.260s'",
		caller_name ? caller_name : "win32_dialog",
		static_cast<void*>(used_owner), tid, is_gui ? 1 : 0, out_path);

	HRESULT co_init = E_FAIL;
	bool need_uninit = false;
	if (!detail::ensure_apartment(co_init, need_uninit, caller_name)) {
		return false;
	}

	OPENFILENAMEA ofn = {};
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = used_owner;
	ofn.lpstrFile = out_path;
	ofn.nMaxFile = static_cast<DWORD>(out_path_capacity);
	ofn.lpstrFilter = filter_pairs;
	ofn.nFilterIndex = 1;
	ofn.lpstrTitle = title;
	ofn.lpstrDefExt = default_ext;
	ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST | OFN_EXPLORER;

	BOOL ok = GetSaveFileNameA(&ofn);
	DWORD cde = ok ? 0 : CommDlgExtendedError();
	DWORD gle = GetLastError();

	if (need_uninit) CoUninitialize();

	if (!ok) {
		diag::log_tagged_fmt("dialog",
			"%s save end ok=0 cde=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(cde),
			static_cast<unsigned long>(gle));
		return false;
	}

	diag::log_tagged_fmt("dialog",
		"%s save end ok=1 path='%.260s'",
		caller_name ? caller_name : "win32_dialog", out_path);
	return true;
}

inline bool show_open_file_dialog_w(HWND owner,
	const wchar_t* title,
	const wchar_t* filter_pairs_w,
	wchar_t* out_path_w,
	size_t out_path_capacity_w_chars,
	const char* caller_name)
{
	if (!out_path_w || out_path_capacity_w_chars < 2 || !filter_pairs_w) {
		diag::log_tagged_fmt("dialog",
			"%s open_w invalid args buf=%p cap=%zu filter=%p",
			caller_name ? caller_name : "win32_dialog",
			static_cast<void*>(out_path_w), out_path_capacity_w_chars,
			static_cast<const void*>(filter_pairs_w));
		return false;
	}

	bool valid = false;
	bool last_zero = false;
	for (size_t i = 0; i < 4096; ++i) {
		wchar_t c = filter_pairs_w[i];
		if (c == L'\0') {
			if (last_zero) { valid = true; break; }
			last_zero = true;
		} else {
			last_zero = false;
		}
	}
	if (!valid) {
		diag::log_tagged_fmt("dialog",
			"%s open_w invalid filter_pairs missing double-NUL terminator",
			caller_name ? caller_name : "win32_dialog");
		return false;
	}

	HWND used_owner = detail::default_owner(owner);
	DWORD tid = GetCurrentThreadId();
	BOOL is_gui = IsGUIThread(FALSE);
	diag::log_tagged_fmt("dialog",
		"%s open_w begin hwnd=%p tid=%lu gui=%d",
		caller_name ? caller_name : "win32_dialog",
		static_cast<void*>(used_owner), tid, is_gui ? 1 : 0);

	HRESULT co_init = E_FAIL;
	bool need_uninit = false;
	if (!detail::ensure_apartment(co_init, need_uninit, caller_name)) {
		return false;
	}

	OPENFILENAMEW ofn = {};
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = used_owner;
	ofn.lpstrFile = out_path_w;
	ofn.nMaxFile = static_cast<DWORD>(out_path_capacity_w_chars);
	ofn.lpstrFilter = filter_pairs_w;
	ofn.nFilterIndex = 1;
	ofn.lpstrTitle = title;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;

	BOOL ok = GetOpenFileNameW(&ofn);
	DWORD cde = ok ? 0 : CommDlgExtendedError();
	DWORD gle = GetLastError();

	if (need_uninit) CoUninitialize();

	if (!ok) {
		diag::log_tagged_fmt("dialog",
			"%s open_w end ok=0 cde=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(cde),
			static_cast<unsigned long>(gle));
		out_path_w[0] = L'\0';
		return false;
	}

	char preview[260] = {};
	WideCharToMultiByte(CP_UTF8, 0, out_path_w, -1, preview, sizeof(preview) - 1, nullptr, nullptr);
	diag::log_tagged_fmt("dialog",
		"%s open_w end ok=1 path='%.260s'",
		caller_name ? caller_name : "win32_dialog", preview);
	return true;
}

inline bool show_open_folder_dialog_ex(HWND owner,
	const wchar_t* title,
	const wchar_t* initial_folder_w,
	std::string& out_path,
	const char* caller_name)
{
	out_path.clear();

	HWND used_owner = detail::default_owner(owner);
	DWORD tid = GetCurrentThreadId();
	BOOL is_gui = IsGUIThread(FALSE);
	diag::log_tagged_fmt("dialog",
		"%s folder begin hwnd=%p tid=%lu gui=%d",
		caller_name ? caller_name : "win32_dialog",
		static_cast<void*>(used_owner), tid, is_gui ? 1 : 0);

	HRESULT co_init = E_FAIL;
	bool need_uninit = false;
	if (!detail::ensure_apartment(co_init, need_uninit, caller_name)) {
		return false;
	}

	IFileOpenDialog* pfd = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr,
		CLSCTX_INPROC_SERVER, IID_IFileOpenDialog,
		reinterpret_cast<void**>(&pfd));
	if (FAILED(hr) || !pfd) {
		diag::log_tagged_fmt("dialog",
			"%s folder CoCreateInstance FAILED hr=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(hr),
			static_cast<unsigned long>(GetLastError()));
		if (need_uninit) CoUninitialize();
		return false;
	}

	DWORD opts = 0;
	hr = pfd->GetOptions(&opts);
	if (FAILED(hr)) {
		diag::log_tagged_fmt("dialog",
			"%s folder GetOptions FAILED hr=0x%08lX",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(hr));
		pfd->Release();
		if (need_uninit) CoUninitialize();
		return false;
	}

	hr = pfd->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM |
		FOS_PATHMUSTEXIST | FOS_NOREADONLYRETURN);
	if (FAILED(hr)) {
		diag::log_tagged_fmt("dialog",
			"%s folder SetOptions FAILED hr=0x%08lX",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(hr));
		pfd->Release();
		if (need_uninit) CoUninitialize();
		return false;
	}

	if (title) pfd->SetTitle(title);

	if (initial_folder_w && initial_folder_w[0]) {
		IShellItem* psi_init = nullptr;
		if (SUCCEEDED(SHCreateItemFromParsingName(initial_folder_w, nullptr,
				IID_IShellItem, reinterpret_cast<void**>(&psi_init))) && psi_init) {
			pfd->SetFolder(psi_init);
			psi_init->Release();
		}
	}

	hr = pfd->Show(used_owner);
	if (FAILED(hr)) {
		if (hr != HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
			diag::log_tagged_fmt("dialog",
				"%s folder Show FAILED hr=0x%08lX gle=%lu",
				caller_name ? caller_name : "win32_dialog",
				static_cast<unsigned long>(hr),
				static_cast<unsigned long>(GetLastError()));
		} else {
			diag::log_tagged_fmt("dialog",
				"%s folder end ok=0 cancelled",
				caller_name ? caller_name : "win32_dialog");
		}
		pfd->Release();
		if (need_uninit) CoUninitialize();
		return false;
	}

	IShellItem* psi = nullptr;
	hr = pfd->GetResult(&psi);
	if (FAILED(hr) || !psi) {
		diag::log_tagged_fmt("dialog",
			"%s folder GetResult FAILED hr=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(hr),
			static_cast<unsigned long>(GetLastError()));
		pfd->Release();
		if (need_uninit) CoUninitialize();
		return false;
	}

	PWSTR wpath = nullptr;
	hr = psi->GetDisplayName(SIGDN_FILESYSPATH, &wpath);
	if (FAILED(hr) || !wpath) {
		diag::log_tagged_fmt("dialog",
			"%s folder GetDisplayName FAILED hr=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(hr),
			static_cast<unsigned long>(GetLastError()));
		psi->Release();
		pfd->Release();
		if (need_uninit) CoUninitialize();
		return false;
	}

	int needed = WideCharToMultiByte(CP_UTF8, 0, wpath, -1,
		nullptr, 0, nullptr, nullptr);
	if (needed > 0) {
		out_path.resize(static_cast<size_t>(needed - 1));
		WideCharToMultiByte(CP_UTF8, 0, wpath, -1,
			out_path.data(), needed, nullptr, nullptr);
	}

	CoTaskMemFree(wpath);
	psi->Release();
	pfd->Release();
	if (need_uninit) CoUninitialize();

	diag::log_tagged_fmt("dialog",
		"%s folder end ok=1 path='%.260s'",
		caller_name ? caller_name : "win32_dialog", out_path.c_str());
	return !out_path.empty();
}

inline bool show_open_folder_dialog(HWND owner,
	const wchar_t* title,
	std::string& out_path,
	const char* caller_name)
{
	return show_open_folder_dialog_ex(owner, title, nullptr, out_path, caller_name);
}

}

#ifdef small
#undef small
#endif
