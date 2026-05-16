#pragma once

#include <string>
#include <vector>

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shlwapi.h>
#include <shldisp.h>
#include <exdisp.h>
#include <shlguid.h>

#include "anti-tamper/webhook.hpp"

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Uuid.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")

namespace aida {
namespace auth {

	namespace detail {

		inline void browser_log(const char* message)
		{
			anti_tamper::webhook::write_log("auth.browser",
				(std::string("[aida.auth.browser] ") + message).c_str());
		}

		template <typename T>
		class com_ptr_t {
		public:
			com_ptr_t() = default;
			~com_ptr_t() { reset(); }
			com_ptr_t(const com_ptr_t&) = delete;
			com_ptr_t& operator=(const com_ptr_t&) = delete;

			T* operator->() const { return ptr_; }
			T* get() const { return ptr_; }
			T** put() { reset(); return &ptr_; }
			void** put_void() { reset(); return reinterpret_cast<void**>(&ptr_); }
			explicit operator bool() const { return ptr_ != nullptr; }

			void reset()
			{
				if (ptr_) {
					ptr_->Release();
					ptr_ = nullptr;
				}
			}

		private:
			T* ptr_ = nullptr;
		};

		inline std::wstring resolve_default_browser()
		{
			wchar_t buffer[1024] = {};
			DWORD length = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
			const HRESULT hr = AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE,
				L"https", L"open", buffer, &length);
			if (FAILED(hr) || buffer[0] == L'\0')
				return std::wstring();
			std::wstring executable(buffer);
			if (GetFileAttributesW(executable.c_str()) == INVALID_FILE_ATTRIBUTES)
				return std::wstring();
			return executable;
		}

		inline bool launch_via_shell_token(const std::wstring& url)
		{
			const std::wstring browser = resolve_default_browser();
			if (browser.empty()) {
				browser_log("shell_token: could not resolve default browser executable");
				return false;
			}

			const HWND shell_hwnd = GetShellWindow();
			if (!shell_hwnd) {
				browser_log("shell_token: GetShellWindow returned null");
				return false;
			}
			DWORD shell_pid = 0;
			GetWindowThreadProcessId(shell_hwnd, &shell_pid);
			if (shell_pid == 0) {
				browser_log("shell_token: shell process id is 0");
				return false;
			}

			const HANDLE shell_process = OpenProcess(PROCESS_QUERY_INFORMATION,
				FALSE, shell_pid);
			if (!shell_process) {
				browser_log("shell_token: OpenProcess on shell failed");
				return false;
			}
			HANDLE shell_token = nullptr;
			const BOOL token_opened = OpenProcessToken(shell_process,
				TOKEN_DUPLICATE, &shell_token);
			CloseHandle(shell_process);
			if (!token_opened || !shell_token) {
				browser_log("shell_token: OpenProcessToken on shell failed");
				return false;
			}

			HANDLE primary_token = nullptr;
			const BOOL token_duplicated = DuplicateTokenEx(shell_token,
				TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY
					| TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
				nullptr, SecurityImpersonation, TokenPrimary, &primary_token);
			CloseHandle(shell_token);
			if (!token_duplicated || !primary_token) {
				browser_log("shell_token: DuplicateTokenEx failed");
				return false;
			}

			std::wstring command_line = L"\"";
			command_line += browser;
			command_line += L"\" \"";
			command_line += url;
			command_line += L"\"";
			std::vector<wchar_t> command_buffer(command_line.begin(),
				command_line.end());
			command_buffer.push_back(L'\0');

			STARTUPINFOW startup = {};
			startup.cb = sizeof(startup);
			PROCESS_INFORMATION process = {};
			const BOOL created = CreateProcessWithTokenW(primary_token, 0,
				browser.c_str(), command_buffer.data(), 0, nullptr, nullptr,
				&startup, &process);
			CloseHandle(primary_token);
			if (!created) {
				browser_log("shell_token: CreateProcessWithTokenW failed");
				return false;
			}
			CloseHandle(process.hThread);
			CloseHandle(process.hProcess);
			browser_log("opened via duplicated shell token");
			return true;
		}

		inline bool shell_execute_via_explorer(const std::wstring& url)
		{
			com_ptr_t<IShellWindows> shell_windows;
			if (FAILED(CoCreateInstance(CLSID_ShellWindows, nullptr, CLSCTX_LOCAL_SERVER,
					IID_IShellWindows, shell_windows.put_void())) || !shell_windows)
				return false;

			VARIANT loc;
			VariantInit(&loc);
			loc.vt = VT_I4;
			loc.lVal = CSIDL_DESKTOP;
			VARIANT empty;
			VariantInit(&empty);
			long desktop_hwnd = 0;
			com_ptr_t<IDispatch> desktop_disp;
			if (FAILED(shell_windows->FindWindowSW(&loc, &empty, SWC_DESKTOP,
					&desktop_hwnd, SWFO_NEEDDISPATCH, desktop_disp.put()))
				|| !desktop_disp)
				return false;

			com_ptr_t<IShellBrowser> browser;
			if (FAILED(IUnknown_QueryService(desktop_disp.get(), SID_STopLevelBrowser,
					IID_IShellBrowser, browser.put_void())) || !browser)
				return false;

			com_ptr_t<IShellView> view;
			if (FAILED(browser->QueryActiveShellView(view.put())) || !view)
				return false;

			com_ptr_t<IDispatch> view_disp;
			if (FAILED(view->GetItemObject(SVGIO_BACKGROUND, IID_IDispatch,
					view_disp.put_void())) || !view_disp)
				return false;

			com_ptr_t<IShellFolderViewDual> folder_view;
			if (FAILED(view_disp->QueryInterface(IID_IShellFolderViewDual,
					folder_view.put_void())) || !folder_view)
				return false;

			com_ptr_t<IDispatch> app_disp;
			if (FAILED(folder_view->get_Application(app_disp.put())) || !app_disp)
				return false;

			com_ptr_t<IDispatch> shell_dispatch;
			if (FAILED(app_disp->QueryInterface(IID_IDispatch,
					shell_dispatch.put_void())) || !shell_dispatch)
				return false;

			OLECHAR* method_name = const_cast<OLECHAR*>(L"ShellExecute");
			DISPID dispid_shell_execute = 0;
			if (FAILED(shell_dispatch->GetIDsOfNames(IID_NULL, &method_name, 1,
					LOCALE_USER_DEFAULT, &dispid_shell_execute)))
				return false;

			BSTR file = SysAllocString(url.c_str());
			if (!file)
				return false;

			VARIANT args[5];
			for (int idx = 0; idx < 5; ++idx)
				VariantInit(&args[idx]);
			args[4].vt = VT_BSTR;
			args[4].bstrVal = file;
			args[0].vt = VT_I4;
			args[0].lVal = SW_SHOWNORMAL;

			DISPPARAMS params = {};
			params.rgvarg = args;
			params.cArgs = 5;

			const HRESULT exec_hr = shell_dispatch->Invoke(dispid_shell_execute,
				IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &params,
				nullptr, nullptr, nullptr);
			SysFreeString(file);
			return SUCCEEDED(exec_hr);
		}

	}

	inline bool open_url_external(const std::string& url)
	{
		if (url.empty())
			return false;

		const int wlen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(),
			static_cast<int>(url.size()), nullptr, 0);
		if (wlen <= 0)
			return false;
		std::wstring wurl(static_cast<size_t>(wlen), L'\0');
		MultiByteToWideChar(CP_UTF8, 0, url.c_str(), static_cast<int>(url.size()),
			&wurl[0], wlen);

		if (detail::launch_via_shell_token(wurl))
			return true;

		const HRESULT co = CoInitializeEx(nullptr,
			COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		const bool balance_com = (co == S_OK || co == S_FALSE);
		const bool via_shell = detail::shell_execute_via_explorer(wurl);
		if (balance_com)
			CoUninitialize();
		if (via_shell) {
			detail::browser_log("opened via IShellDispatch2 (shell-dispatch fallback)");
			return true;
		}

		const HINSTANCE rc = ShellExecuteW(nullptr, L"open", wurl.c_str(),
			nullptr, nullptr, SW_SHOWNORMAL);
		const bool via_shellexec = reinterpret_cast<INT_PTR>(rc) > 32;
		detail::browser_log(via_shellexec
			? "opened via ShellExecuteW (last-resort fallback; may be elevated)"
			: "ALL launch paths failed");
		return via_shellexec;
	}

}
}
