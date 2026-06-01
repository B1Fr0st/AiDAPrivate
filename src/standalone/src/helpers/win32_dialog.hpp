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
#include <cwchar>
#include <string>
#include <vector>

#include "diag_log.hpp"

extern HWND g_hwnd;

namespace win32_dialog {

namespace detail {

constexpr DWORD kBrokerTimeoutMs = 120000;

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
			"%s CoInitializeEx RPC_E_CHANGED_MODE thread is not STA tid=%lu",
			caller_name ? caller_name : "win32_dialog",
			static_cast<unsigned long>(GetCurrentThreadId()));
		return false;
	}
	need_uninit_out = false;
	diag::log_tagged_fmt("dialog",
		"%s CoInitializeEx FAILED hr=0x%08lX tid=%lu",
		caller_name ? caller_name : "win32_dialog",
		static_cast<unsigned long>(co_init_out),
		static_cast<unsigned long>(GetCurrentThreadId()));
	return false;
}

template <typename T>
inline void release_if(T*& p)
{
	if (p) {
		p->Release();
		p = nullptr;
	}
}

inline HWND normalize_owner(HWND owner, const char* caller_name, const char* action)
{
	HWND used_owner = default_owner(owner);
	if (used_owner && !IsWindow(used_owner)) {
		diag::log_tagged_fmt("dialog",
			"%s %s owner invalid hwnd=%p using null owner",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "dialog",
			static_cast<void*>(used_owner));
		return nullptr;
	}
	if (used_owner) {
		HWND root = GetAncestor(used_owner, GA_ROOT);
		if (root && IsWindow(root))
			used_owner = root;
	}
	return used_owner;
}

inline std::wstring utf16_from_utf8(const char* text)
{
	if (!text || !*text)
		return {};
	int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
		text, -1, nullptr, 0);
	if (needed <= 0) {
		needed = MultiByteToWideChar(CP_ACP, 0, text, -1, nullptr, 0);
		if (needed <= 0)
			return {};
		std::wstring out(static_cast<size_t>(needed), L'\0');
		MultiByteToWideChar(CP_ACP, 0, text, -1, out.data(), needed);
		if (!out.empty() && out.back() == L'\0')
			out.pop_back();
		return out;
	}
	std::wstring out(static_cast<size_t>(needed), L'\0');
	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, out.data(), needed);
	if (!out.empty() && out.back() == L'\0')
		out.pop_back();
	return out;
}

inline std::string utf8_from_utf16(const wchar_t* text)
{
	if (!text || !*text)
		return {};
	int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1,
		nullptr, 0, nullptr, nullptr);
	if (needed <= 0)
		return {};
	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), needed, nullptr, nullptr);
	if (!out.empty() && out.back() == '\0')
		out.pop_back();
	return out;
}

struct filter_spec_storage {
	std::vector<std::wstring> names;
	std::vector<std::wstring> specs_text;
	std::vector<COMDLG_FILTERSPEC> specs;
};

inline bool build_filter_specs_from_a(const char* filter_pairs,
	filter_spec_storage& out,
	const char* caller_name = nullptr,
	const char* action = nullptr)
{
	out = {};
	if (!is_valid_filter_pairs(filter_pairs, 4096)) {
		diag::log_tagged_fmt("dialog",
			"%s %s invalid filter_pairs missing double-NUL terminator",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open");
		return false;
	}
	const char* p = filter_pairs;
	while (*p) {
		const char* name = p;
		size_t name_len = std::strlen(name);
		p += name_len + 1;
		if (!*p)
			break;
		const char* spec = p;
		size_t spec_len = std::strlen(spec);
		p += spec_len + 1;
		out.names.push_back(utf16_from_utf8(name));
		out.specs_text.push_back(utf16_from_utf8(spec));
	}
	if (out.names.empty() || out.names.size() != out.specs_text.size()) {
		diag::log_tagged_fmt("dialog",
			"%s %s invalid filter_pairs parsed=%zu specs=%zu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open",
			out.names.size(), out.specs_text.size());
		return false;
	}
	out.specs.reserve(out.names.size());
	for (size_t i = 0; i < out.names.size(); ++i) {
		out.specs.push_back(COMDLG_FILTERSPEC{out.names[i].c_str(), out.specs_text[i].c_str()});
	}
	return true;
}

inline bool build_filter_specs_from_w(const wchar_t* filter_pairs,
	filter_spec_storage& out,
	const char* caller_name = nullptr,
	const char* action = nullptr)
{
	out = {};
	if (!filter_pairs) {
		diag::log_tagged_fmt("dialog",
			"%s %s invalid null wide filter_pairs",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open_w");
		return false;
	}
	bool valid = false;
	bool last_zero = false;
	for (size_t i = 0; i < 4096; ++i) {
		wchar_t c = filter_pairs[i];
		if (c == L'\0') {
			if (last_zero) { valid = true; break; }
			last_zero = true;
		} else {
			last_zero = false;
		}
	}
	if (!valid) {
		diag::log_tagged_fmt("dialog",
			"%s %s invalid wide filter_pairs missing double-NUL terminator",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open_w");
		return false;
	}
	const wchar_t* p = filter_pairs;
	while (*p) {
		const wchar_t* name = p;
		size_t name_len = std::wcslen(name);
		p += name_len + 1;
		if (!*p)
			break;
		const wchar_t* spec = p;
		size_t spec_len = std::wcslen(spec);
		p += spec_len + 1;
		out.names.emplace_back(name, name + name_len);
		out.specs_text.emplace_back(spec, spec + spec_len);
	}
	if (out.names.empty() || out.names.size() != out.specs_text.size()) {
		diag::log_tagged_fmt("dialog",
			"%s %s invalid wide filter_pairs parsed=%zu specs=%zu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open_w",
			out.names.size(), out.specs_text.size());
		return false;
	}
	out.specs.reserve(out.names.size());
	for (size_t i = 0; i < out.names.size(); ++i) {
		out.specs.push_back(COMDLG_FILTERSPEC{out.names[i].c_str(), out.specs_text[i].c_str()});
	}
	return true;
}

inline bool shell_item_path(IShellItem* psi, std::wstring& out_path_w,
	const char* caller_name,
	const char* action)
{
	out_path_w.clear();
	if (!psi)
		return false;
	PWSTR wpath = nullptr;
	HRESULT hr = psi->GetDisplayName(SIGDN_FILESYSPATH, &wpath);
	if (FAILED(hr) || !wpath) {
		diag::log_tagged_fmt("dialog",
			"%s %s GetDisplayName FAILED hr=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open",
			static_cast<unsigned long>(hr),
			static_cast<unsigned long>(GetLastError()));
		if (wpath)
			CoTaskMemFree(wpath);
		return false;
	}
	out_path_w.assign(wpath);
	CoTaskMemFree(wpath);
	return !out_path_w.empty();
}

inline bool show_file_open_dialog_wide(HWND owner,
	const wchar_t* title,
	const wchar_t* initial_dir_w,
	filter_spec_storage& filters,
	std::wstring& out_path_w,
	const char* caller_name,
	const char* action)
{
	out_path_w.clear();
	HWND used_owner = normalize_owner(owner, caller_name, action);
	DWORD tid = GetCurrentThreadId();
	BOOL is_gui = IsGUIThread(FALSE);
	HWND foreground = GetForegroundWindow();
	diag::log_tagged_fmt("dialog",
		"%s %s begin hwnd=%p fg=%p tid=%lu gui=%d filters=%zu",
		caller_name ? caller_name : "win32_dialog",
		action ? action : "open",
		static_cast<void*>(used_owner),
		static_cast<void*>(foreground),
		tid, is_gui ? 1 : 0,
		filters.specs.size());

	HRESULT co_init = E_FAIL;
	bool need_uninit = false;
	if (!ensure_apartment(co_init, need_uninit, caller_name))
		return false;

	IFileOpenDialog* pfd = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr,
		CLSCTX_INPROC_SERVER, IID_IFileOpenDialog,
		reinterpret_cast<void**>(&pfd));
	if (FAILED(hr) || !pfd) {
		diag::log_tagged_fmt("dialog",
			"%s %s CoCreateInstance FAILED hr=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open",
			static_cast<unsigned long>(hr),
			static_cast<unsigned long>(GetLastError()));
		if (need_uninit) CoUninitialize();
		return false;
	}

	DWORD opts = 0;
	hr = pfd->GetOptions(&opts);
	if (SUCCEEDED(hr)) {
		hr = pfd->SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST |
			FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR);
	}
	if (FAILED(hr)) {
		diag::log_tagged_fmt("dialog",
			"%s %s SetOptions FAILED hr=0x%08lX",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open",
			static_cast<unsigned long>(hr));
		release_if(pfd);
		if (need_uninit) CoUninitialize();
		return false;
	}

	if (title && *title)
		pfd->SetTitle(title);
	if (!filters.specs.empty()) {
		hr = pfd->SetFileTypes(static_cast<UINT>(filters.specs.size()), filters.specs.data());
		if (FAILED(hr)) {
			diag::log_tagged_fmt("dialog",
				"%s %s SetFileTypes FAILED hr=0x%08lX count=%zu",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "open",
				static_cast<unsigned long>(hr),
				filters.specs.size());
			release_if(pfd);
			if (need_uninit) CoUninitialize();
			return false;
		}
		pfd->SetFileTypeIndex(1);
	}

	if (initial_dir_w && initial_dir_w[0]) {
		IShellItem* psi_init = nullptr;
		hr = SHCreateItemFromParsingName(initial_dir_w, nullptr,
			IID_IShellItem, reinterpret_cast<void**>(&psi_init));
		if (SUCCEEDED(hr) && psi_init) {
			pfd->SetFolder(psi_init);
			release_if(psi_init);
		} else {
			diag::log_tagged_fmt("dialog",
				"%s %s initial_dir ignored hr=0x%08lX",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "open",
				static_cast<unsigned long>(hr));
		}
	}

	if (used_owner) {
		SetForegroundWindow(used_owner);
		BringWindowToTop(used_owner);
	}

	ULONGLONG t0 = GetTickCount64();
	hr = pfd->Show(used_owner);
	ULONGLONG elapsed = GetTickCount64() - t0;
	if (FAILED(hr)) {
		if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
			diag::log_tagged_fmt("dialog",
				"%s %s end ok=0 cancelled elapsed_ms=%llu",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "open",
				static_cast<unsigned long long>(elapsed));
		} else {
			diag::log_tagged_fmt("dialog",
				"%s %s Show FAILED hr=0x%08lX gle=%lu elapsed_ms=%llu",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "open",
				static_cast<unsigned long>(hr),
				static_cast<unsigned long>(GetLastError()),
				static_cast<unsigned long long>(elapsed));
		}
		release_if(pfd);
		if (need_uninit) CoUninitialize();
		return false;
	}

	IShellItem* psi = nullptr;
	hr = pfd->GetResult(&psi);
	if (FAILED(hr) || !psi) {
		diag::log_tagged_fmt("dialog",
			"%s %s GetResult FAILED hr=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open",
			static_cast<unsigned long>(hr),
			static_cast<unsigned long>(GetLastError()));
		release_if(pfd);
		if (need_uninit) CoUninitialize();
		return false;
	}

	bool got_path = shell_item_path(psi, out_path_w, caller_name, action);
	release_if(psi);
	release_if(pfd);
	if (need_uninit) CoUninitialize();

	if (!got_path)
		return false;

	std::string preview = utf8_from_utf16(out_path_w.c_str());
	diag::log_tagged_fmt("dialog",
		"%s %s end ok=1 elapsed_ms=%llu path='%.260s'",
		caller_name ? caller_name : "win32_dialog",
		action ? action : "open",
		static_cast<unsigned long long>(elapsed),
		preview.c_str());
	return true;
}

inline bool show_folder_dialog_wide(HWND owner,
	const wchar_t* title,
	const wchar_t* initial_dir_w,
	std::wstring& out_path_w,
	const char* caller_name,
	const char* action)
{
	out_path_w.clear();
	HWND used_owner = normalize_owner(owner, caller_name, action);
	DWORD tid = GetCurrentThreadId();
	BOOL is_gui = IsGUIThread(FALSE);
	HWND foreground = GetForegroundWindow();
	diag::log_tagged_fmt("dialog",
		"%s %s begin hwnd=%p fg=%p tid=%lu gui=%d",
		caller_name ? caller_name : "win32_dialog",
		action ? action : "folder",
		static_cast<void*>(used_owner),
		static_cast<void*>(foreground),
		tid, is_gui ? 1 : 0);

	HRESULT co_init = E_FAIL;
	bool need_uninit = false;
	if (!ensure_apartment(co_init, need_uninit, caller_name))
		return false;

	IFileOpenDialog* pfd = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr,
		CLSCTX_INPROC_SERVER, IID_IFileOpenDialog,
		reinterpret_cast<void**>(&pfd));
	if (FAILED(hr) || !pfd) {
		diag::log_tagged_fmt("dialog",
			"%s %s CoCreateInstance FAILED hr=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "folder",
			static_cast<unsigned long>(hr),
			static_cast<unsigned long>(GetLastError()));
		if (need_uninit) CoUninitialize();
		return false;
	}

	DWORD opts = 0;
	hr = pfd->GetOptions(&opts);
	if (SUCCEEDED(hr)) {
		hr = pfd->SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST |
			FOS_NOCHANGEDIR | FOS_PICKFOLDERS);
	}
	if (FAILED(hr)) {
		diag::log_tagged_fmt("dialog",
			"%s %s SetOptions FAILED hr=0x%08lX",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "folder",
			static_cast<unsigned long>(hr));
		release_if(pfd);
		if (need_uninit) CoUninitialize();
		return false;
	}

	if (title && *title)
		pfd->SetTitle(title);

	if (initial_dir_w && initial_dir_w[0]) {
		IShellItem* psi_init = nullptr;
		hr = SHCreateItemFromParsingName(initial_dir_w, nullptr,
			IID_IShellItem, reinterpret_cast<void**>(&psi_init));
		if (SUCCEEDED(hr) && psi_init) {
			pfd->SetFolder(psi_init);
			release_if(psi_init);
		} else {
			diag::log_tagged_fmt("dialog",
				"%s %s initial_dir ignored hr=0x%08lX",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "folder",
				static_cast<unsigned long>(hr));
		}
	}

	if (used_owner) {
		SetForegroundWindow(used_owner);
		BringWindowToTop(used_owner);
	}

	ULONGLONG t0 = GetTickCount64();
	hr = pfd->Show(used_owner);
	ULONGLONG elapsed = GetTickCount64() - t0;
	if (FAILED(hr)) {
		if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
			diag::log_tagged_fmt("dialog",
				"%s %s end ok=0 cancelled elapsed_ms=%llu",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "folder",
				static_cast<unsigned long long>(elapsed));
		} else {
			diag::log_tagged_fmt("dialog",
				"%s %s Show FAILED hr=0x%08lX gle=%lu elapsed_ms=%llu",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "folder",
				static_cast<unsigned long>(hr),
				static_cast<unsigned long>(GetLastError()),
				static_cast<unsigned long long>(elapsed));
		}
		release_if(pfd);
		if (need_uninit) CoUninitialize();
		return false;
	}

	IShellItem* psi = nullptr;
	hr = pfd->GetResult(&psi);
	if (FAILED(hr) || !psi) {
		diag::log_tagged_fmt("dialog",
			"%s %s GetResult FAILED hr=0x%08lX gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "folder",
			static_cast<unsigned long>(hr),
			static_cast<unsigned long>(GetLastError()));
		release_if(pfd);
		if (need_uninit) CoUninitialize();
		return false;
	}

	bool got_path = shell_item_path(psi, out_path_w, caller_name, action);
	release_if(psi);
	release_if(pfd);
	if (need_uninit) CoUninitialize();

	if (!got_path)
		return false;

	std::string preview = utf8_from_utf16(out_path_w.c_str());
	diag::log_tagged_fmt("dialog",
		"%s %s end ok=1 elapsed_ms=%llu path='%.260s'",
		caller_name ? caller_name : "win32_dialog",
		action ? action : "folder",
		static_cast<unsigned long long>(elapsed),
		preview.c_str());
	return true;
}

inline std::wstring ps_quote(const std::wstring& value)
{
	std::wstring out = L"'";
	for (wchar_t ch : value) {
		if (ch == L'\'')
			out += L"''";
		else
			out.push_back(ch);
	}
	out += L"'";
	return out;
}

inline std::wstring cmd_quote(const std::wstring& value)
{
	std::wstring out = L"\"";
	for (wchar_t ch : value) {
		if (ch == L'"')
			out += L"\\\"";
		else
			out.push_back(ch);
	}
	out += L"\"";
	return out;
}

inline std::wstring filter_pairs_to_winforms(const char* filter_pairs)
{
	if (!is_valid_filter_pairs(filter_pairs, 4096))
		return L"All files (*.*)|*.*";

	std::wstring out;
	const char* p = filter_pairs;
	while (*p) {
		const char* name = p;
		size_t name_len = std::strlen(name);
		p += name_len + 1;
		if (!*p)
			break;
		const char* spec = p;
		size_t spec_len = std::strlen(spec);
		p += spec_len + 1;
		if (!out.empty())
			out.push_back(L'|');
		out += utf16_from_utf8(name);
		out.push_back(L'|');
		out += utf16_from_utf8(spec);
	}
	return out.empty() ? L"All files (*.*)|*.*" : out;
}

inline std::wstring filter_pairs_to_winforms(const wchar_t* filter_pairs)
{
	if (!filter_pairs)
		return L"All files (*.*)|*.*";
	std::wstring out;
	const wchar_t* p = filter_pairs;
	for (size_t scanned = 0; *p && scanned < 4096; ) {
		const wchar_t* name = p;
		size_t name_len = std::wcslen(name);
		p += name_len + 1;
		scanned += name_len + 1;
		if (!*p)
			break;
		const wchar_t* spec = p;
		size_t spec_len = std::wcslen(spec);
		p += spec_len + 1;
		scanned += spec_len + 1;
		if (!out.empty())
			out.push_back(L'|');
		out.append(name, name + name_len);
		out.push_back(L'|');
		out.append(spec, spec + spec_len);
	}
	return out.empty() ? L"All files (*.*)|*.*" : out;
}

inline std::wstring temp_dialog_path(const wchar_t* suffix)
{
	wchar_t temp_dir[MAX_PATH] = {};
	DWORD len = GetTempPathW(MAX_PATH, temp_dir);
	std::wstring dir = (len > 0 && len < MAX_PATH) ? std::wstring(temp_dir) : L".\\";
	return dir + L"aida_dialog_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
		std::to_wstring(GetCurrentThreadId()) + L"_" + std::to_wstring(GetTickCount64()) + suffix;
}

inline bool write_utf16_script(const std::wstring& path, const std::wstring& script)
{
	HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
		FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
	if (h == INVALID_HANDLE_VALUE)
		return false;
	const wchar_t bom = 0xFEFF;
	DWORD written = 0;
	BOOL ok = WriteFile(h, &bom, sizeof(bom), &written, nullptr);
	if (ok && !script.empty()) {
		ok = WriteFile(h, script.data(), static_cast<DWORD>(script.size() * sizeof(wchar_t)),
			&written, nullptr);
	}
	CloseHandle(h);
	return ok == TRUE;
}

inline bool read_utf8_file(const std::wstring& path, std::string& out)
{
	out.clear();
	HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE)
		return false;
	LARGE_INTEGER size = {};
	if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > 32768) {
		CloseHandle(h);
		return false;
	}
	out.resize(static_cast<size_t>(size.QuadPart));
	DWORD read = 0;
	BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
	CloseHandle(h);
	if (!ok || read == 0)
		return false;
	out.resize(read);
	return true;
}

inline bool run_dialog_script(const std::wstring& script,
	std::string& selected_path,
	const char* caller_name,
	const char* action)
{
	selected_path.clear();
	std::wstring script_path = temp_dialog_path(L".ps1");
	std::wstring output_path = temp_dialog_path(L".txt");
	std::wstring full_script = std::wstring(L"$ErrorActionPreference = 'Stop'\r\n") +
		L"$out = " + ps_quote(output_path) + L"\r\n" + script;

	if (!write_utf16_script(script_path, full_script)) {
		diag::log_tagged_fmt("dialog",
			"%s %s broker write_script failed gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open_broker",
			static_cast<unsigned long>(GetLastError()));
		DeleteFileW(script_path.c_str());
		DeleteFileW(output_path.c_str());
		return false;
	}

	std::wstring exe = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	std::wstring cmd = cmd_quote(exe) +
		L" -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File " +
		cmd_quote(script_path);
	std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
	cmdline.push_back(L'\0');

	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	PROCESS_INFORMATION pi = {};
	ULONGLONG t0 = GetTickCount64();
	BOOL created = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
	if (!created) {
		diag::log_tagged_fmt("dialog",
			"%s %s broker CreateProcess failed gle=%lu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open_broker",
			static_cast<unsigned long>(GetLastError()));
		DeleteFileW(script_path.c_str());
		DeleteFileW(output_path.c_str());
		return false;
	}

	DWORD wait_rc = WaitForSingleObject(pi.hProcess, kBrokerTimeoutMs);
	if (wait_rc == WAIT_TIMEOUT) {
		TerminateProcess(pi.hProcess, 124);
		WaitForSingleObject(pi.hProcess, 5000);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		DeleteFileW(script_path.c_str());
		DeleteFileW(output_path.c_str());
		diag::log_tagged_fmt("dialog",
			"%s %s broker timeout elapsed_ms=%llu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open_broker",
			static_cast<unsigned long long>(GetTickCount64() - t0));
		return false;
	}
	DWORD exit_code = 1;
	GetExitCodeProcess(pi.hProcess, &exit_code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	ULONGLONG elapsed = GetTickCount64() - t0;

	bool got_path = exit_code == 0 && read_utf8_file(output_path, selected_path);
	DeleteFileW(script_path.c_str());
	DeleteFileW(output_path.c_str());
	if (!got_path) {
		diag::log_tagged_fmt("dialog",
			"%s %s broker end ok=0 exit=%lu elapsed_ms=%llu",
			caller_name ? caller_name : "win32_dialog",
			action ? action : "open_broker",
			static_cast<unsigned long>(exit_code),
			static_cast<unsigned long long>(elapsed));
		return false;
	}

	while (!selected_path.empty() &&
		(selected_path.back() == '\0' || selected_path.back() == '\r' || selected_path.back() == '\n')) {
		selected_path.pop_back();
	}
	diag::log_tagged_fmt("dialog",
		"%s %s broker end ok=1 elapsed_ms=%llu path='%.260s'",
		caller_name ? caller_name : "win32_dialog",
		action ? action : "open_broker",
		static_cast<unsigned long long>(elapsed),
		selected_path.c_str());
	return !selected_path.empty();
}

inline bool show_open_file_dialog_broker(const wchar_t* title,
	const std::wstring& filter,
	const wchar_t* initial_dir,
	std::string& selected_path,
	const char* caller_name,
	const char* action)
{
	selected_path.clear();
	wchar_t module_path[32768] = {};
	constexpr DWORD module_cap = static_cast<DWORD>(sizeof(module_path) / sizeof(module_path[0]));
	DWORD module_len = GetModuleFileNameW(nullptr, module_path, module_cap);
	if (module_len > 0 && module_len < module_cap) {
		std::wstring broker_path(module_path, module_len);
		size_t slash = broker_path.find_last_of(L"\\/");
		if (slash != std::wstring::npos)
			broker_path.resize(slash + 1);
		else
			broker_path.clear();
		broker_path += L"AIDADialogBroker.exe";
		if (GetFileAttributesW(broker_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
			std::wstring output_path = temp_dialog_path(L".txt");
			std::wstring cmd = cmd_quote(broker_path) +
				L" --mode file --out " + cmd_quote(output_path) +
				L" --title " + cmd_quote(title && title[0] ? std::wstring(title) : L"Open File") +
				L" --filter " + cmd_quote(filter.empty() ? std::wstring(L"All files (*.*)|*.*") : filter);
			if (initial_dir && initial_dir[0])
				cmd += L" --initial " + cmd_quote(initial_dir);
			std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
			cmdline.push_back(L'\0');
			STARTUPINFOW si = {};
			si.cb = sizeof(si);
			si.dwFlags = STARTF_USESHOWWINDOW;
			si.wShowWindow = SW_HIDE;
			PROCESS_INFORMATION pi = {};
			ULONGLONG t0 = GetTickCount64();
			BOOL created = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, FALSE,
				CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
			if (created) {
				DWORD wait_rc = WaitForSingleObject(pi.hProcess, kBrokerTimeoutMs);
				if (wait_rc == WAIT_TIMEOUT) {
					TerminateProcess(pi.hProcess, 124);
					WaitForSingleObject(pi.hProcess, 5000);
					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);
					DeleteFileW(output_path.c_str());
					diag::log_tagged_fmt("dialog",
						"%s %s native_broker timeout elapsed_ms=%llu",
						caller_name ? caller_name : "win32_dialog",
						action ? action : "open_broker",
						static_cast<unsigned long long>(GetTickCount64() - t0));
					return false;
				}
				DWORD exit_code = 1;
				GetExitCodeProcess(pi.hProcess, &exit_code);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				ULONGLONG elapsed = GetTickCount64() - t0;
				bool got_path = exit_code == 0 && read_utf8_file(output_path, selected_path);
				DeleteFileW(output_path.c_str());
				while (!selected_path.empty() &&
					(selected_path.back() == '\0' || selected_path.back() == '\r' || selected_path.back() == '\n')) {
					selected_path.pop_back();
				}
				diag::log_tagged_fmt("dialog",
					"%s %s native_broker end ok=%d exit=%lu elapsed_ms=%llu path='%.260s'",
					caller_name ? caller_name : "win32_dialog",
					action ? action : "open_broker",
					got_path && !selected_path.empty() ? 1 : 0,
					static_cast<unsigned long>(exit_code),
					static_cast<unsigned long long>(elapsed),
					selected_path.c_str());
				return got_path && !selected_path.empty();
			}
			diag::log_tagged_fmt("dialog",
				"%s %s native_broker CreateProcess failed gle=%lu",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "open_broker",
				static_cast<unsigned long>(GetLastError()));
			DeleteFileW(output_path.c_str());
		}
	}

	std::wstring script =
		L"Add-Type -AssemblyName System.Windows.Forms\r\n"
		L"[System.Windows.Forms.Application]::EnableVisualStyles()\r\n"
		L"$dlg = New-Object System.Windows.Forms.OpenFileDialog\r\n"
		L"$dlg.Title = " + ps_quote(title && title[0] ? std::wstring(title) : L"Open File") + L"\r\n"
		L"$dlg.Filter = " + ps_quote(filter.empty() ? std::wstring(L"All files (*.*)|*.*") : filter) + L"\r\n"
		L"$dlg.CheckFileExists = $true\r\n"
		L"$dlg.CheckPathExists = $true\r\n"
		L"$dlg.Multiselect = $false\r\n"
		L"$dlg.RestoreDirectory = $true\r\n";
	if (initial_dir && initial_dir[0])
		script += L"$dlg.InitialDirectory = " + ps_quote(initial_dir) + L"\r\n";
	script +=
		L"if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {\r\n"
		L"  [System.IO.File]::WriteAllText($out, $dlg.FileName, [System.Text.UTF8Encoding]::new($false))\r\n"
		L"  exit 0\r\n"
		L"}\r\n"
		L"exit 1\r\n";
	return run_dialog_script(script, selected_path, caller_name, action);
}

inline bool show_open_folder_dialog_broker(const wchar_t* title,
	const wchar_t* initial_dir,
	std::string& selected_path,
	const char* caller_name,
	const char* action)
{
	selected_path.clear();
	wchar_t module_path[32768] = {};
	constexpr DWORD module_cap = static_cast<DWORD>(sizeof(module_path) / sizeof(module_path[0]));
	DWORD module_len = GetModuleFileNameW(nullptr, module_path, module_cap);
	if (module_len > 0 && module_len < module_cap) {
		std::wstring broker_path(module_path, module_len);
		size_t slash = broker_path.find_last_of(L"\\/");
		if (slash != std::wstring::npos)
			broker_path.resize(slash + 1);
		else
			broker_path.clear();
		broker_path += L"AIDADialogBroker.exe";
		if (GetFileAttributesW(broker_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
			std::wstring output_path = temp_dialog_path(L".txt");
			std::wstring cmd = cmd_quote(broker_path) +
				L" --mode folder --out " + cmd_quote(output_path) +
				L" --title " + cmd_quote(title && title[0] ? std::wstring(title) : L"Open Folder");
			if (initial_dir && initial_dir[0])
				cmd += L" --initial " + cmd_quote(initial_dir);
			std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
			cmdline.push_back(L'\0');
			STARTUPINFOW si = {};
			si.cb = sizeof(si);
			si.dwFlags = STARTF_USESHOWWINDOW;
			si.wShowWindow = SW_HIDE;
			PROCESS_INFORMATION pi = {};
			ULONGLONG t0 = GetTickCount64();
			BOOL created = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, FALSE,
				CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
			if (created) {
				DWORD wait_rc = WaitForSingleObject(pi.hProcess, kBrokerTimeoutMs);
				if (wait_rc == WAIT_TIMEOUT) {
					TerminateProcess(pi.hProcess, 124);
					WaitForSingleObject(pi.hProcess, 5000);
					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);
					DeleteFileW(output_path.c_str());
					diag::log_tagged_fmt("dialog",
						"%s %s native_broker timeout elapsed_ms=%llu",
						caller_name ? caller_name : "win32_dialog",
						action ? action : "folder_broker",
						static_cast<unsigned long long>(GetTickCount64() - t0));
					return false;
				}
				DWORD exit_code = 1;
				GetExitCodeProcess(pi.hProcess, &exit_code);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				ULONGLONG elapsed = GetTickCount64() - t0;
				bool got_path = exit_code == 0 && read_utf8_file(output_path, selected_path);
				DeleteFileW(output_path.c_str());
				while (!selected_path.empty() &&
					(selected_path.back() == '\0' || selected_path.back() == '\r' || selected_path.back() == '\n')) {
					selected_path.pop_back();
				}
				diag::log_tagged_fmt("dialog",
					"%s %s native_broker end ok=%d exit=%lu elapsed_ms=%llu path='%.260s'",
					caller_name ? caller_name : "win32_dialog",
					action ? action : "folder_broker",
					got_path && !selected_path.empty() ? 1 : 0,
					static_cast<unsigned long>(exit_code),
					static_cast<unsigned long long>(elapsed),
					selected_path.c_str());
				return got_path && !selected_path.empty();
			}
			diag::log_tagged_fmt("dialog",
				"%s %s native_broker CreateProcess failed gle=%lu",
				caller_name ? caller_name : "win32_dialog",
				action ? action : "folder_broker",
				static_cast<unsigned long>(GetLastError()));
			DeleteFileW(output_path.c_str());
		}
	}

	std::wstring script =
		L"Add-Type -AssemblyName System.Windows.Forms\r\n"
		L"[System.Windows.Forms.Application]::EnableVisualStyles()\r\n"
		L"$dlg = New-Object System.Windows.Forms.FolderBrowserDialog\r\n"
		L"$dlg.Description = " + ps_quote(title && title[0] ? std::wstring(title) : L"Open Folder") + L"\r\n"
		L"$dlg.ShowNewFolderButton = $true\r\n";
	if (initial_dir && initial_dir[0])
		script += L"$dlg.SelectedPath = " + ps_quote(initial_dir) + L"\r\n";
	script +=
		L"if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {\r\n"
		L"  [System.IO.File]::WriteAllText($out, $dlg.SelectedPath, [System.Text.UTF8Encoding]::new($false))\r\n"
		L"  exit 0\r\n"
		L"}\r\n"
		L"exit 1\r\n";
	return run_dialog_script(script, selected_path, caller_name, action);
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

	diag::log_tagged_fmt("dialog",
		"%s open_direct begin tid=%lu gui=%d",
		caller_name ? caller_name : "win32_dialog",
		static_cast<unsigned long>(GetCurrentThreadId()),
		IsGUIThread(FALSE) ? 1 : 0);
	std::wstring title_w = detail::utf16_from_utf8(title);
	std::wstring initial_dir_w = detail::utf16_from_utf8(initial_dir);
	detail::filter_spec_storage filters;
	if (!detail::build_filter_specs_from_a(filter_pairs, filters, caller_name, "open_direct")) {
		diag::log_tagged_fmt("dialog",
			"%s open_direct filter build failed",
			caller_name ? caller_name : "win32_dialog");
		return false;
	}
	std::wstring result_w;
	if (!detail::show_file_open_dialog_wide(
			owner,
			title_w.empty() ? L"Open File" : title_w.c_str(),
			initial_dir_w.empty() ? nullptr : initial_dir_w.c_str(),
			filters,
			result_w,
			caller_name,
			"open_direct")) {
		return false;
	}
	std::string result = detail::utf8_from_utf16(result_w.c_str());
	if (result.size() >= out_path_capacity) {
		diag::log_tagged_fmt("dialog",
			"%s open_direct path too long len=%zu cap=%zu",
			caller_name ? caller_name : "win32_dialog",
			result.size(), out_path_capacity);
		return false;
	}
	std::memcpy(out_path, result.c_str(), result.size() + 1);

	diag::log_tagged_fmt("dialog",
		"%s open_direct copied path='%.260s'",
		caller_name ? caller_name : "win32_dialog",
		out_path);
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
	out_path_w[0] = L'\0';

	diag::log_tagged_fmt("dialog",
		"%s open_w_direct begin tid=%lu gui=%d",
		caller_name ? caller_name : "win32_dialog",
		static_cast<unsigned long>(GetCurrentThreadId()),
		IsGUIThread(FALSE) ? 1 : 0);
	detail::filter_spec_storage filters;
	if (!detail::build_filter_specs_from_w(filter_pairs_w, filters, caller_name, "open_w_direct")) {
		diag::log_tagged_fmt("dialog",
			"%s open_w_direct filter build failed",
			caller_name ? caller_name : "win32_dialog");
		return false;
	}
	std::wstring result_w;
	if (!detail::show_file_open_dialog_wide(
			owner,
			title && title[0] ? title : L"Open File",
			nullptr,
			filters,
			result_w,
			caller_name,
			"open_w_direct")) {
		return false;
	}
	if (result_w.empty() || result_w.size() >= out_path_capacity_w_chars) {
		diag::log_tagged_fmt("dialog",
			"%s open_w_direct path invalid len=%zu cap=%zu",
			caller_name ? caller_name : "win32_dialog",
			result_w.size(), out_path_capacity_w_chars);
		return false;
	}
	std::memcpy(out_path_w, result_w.c_str(), (result_w.size() + 1) * sizeof(wchar_t));

	diag::log_tagged_fmt("dialog",
		"%s open_w_direct copied",
		caller_name ? caller_name : "win32_dialog");
	return true;
}

inline bool show_open_folder_dialog_ex(HWND owner,
	const wchar_t* title,
	const wchar_t* initial_folder_w,
	std::string& out_path,
	const char* caller_name)
{
	out_path.clear();

	diag::log_tagged_fmt("dialog",
		"%s folder_direct begin tid=%lu gui=%d",
		caller_name ? caller_name : "win32_dialog",
		static_cast<unsigned long>(GetCurrentThreadId()),
		IsGUIThread(FALSE) ? 1 : 0);
	std::wstring result_w;
	bool ok = detail::show_folder_dialog_wide(
		owner,
		title && title[0] ? title : L"Open Folder",
		initial_folder_w,
		result_w,
		caller_name,
		"folder_direct");
	if (ok)
		out_path = detail::utf8_from_utf16(result_w.c_str());
	return ok && !out_path.empty();
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
