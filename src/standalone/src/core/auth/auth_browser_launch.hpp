#pragma once

#include <string>

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shlwapi.h>
#include <shldisp.h>
#include <exdisp.h>
#include <shlguid.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Uuid.lib")

namespace aida {
namespace auth {

	namespace detail {

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

			com_ptr_t<IShellDispatch2> shell_dispatch;
			if (FAILED(app_disp->QueryInterface(IID_IShellDispatch2,
					shell_dispatch.put_void())) || !shell_dispatch)
				return false;

			BSTR file = SysAllocString(url.c_str());
			if (!file)
				return false;

			VARIANT v_args;
			VariantInit(&v_args);
			VARIANT v_dir;
			VariantInit(&v_dir);
			VARIANT v_op;
			VariantInit(&v_op);
			VARIANT v_show;
			VariantInit(&v_show);
			v_show.vt = VT_I4;
			v_show.lVal = SW_SHOWNORMAL;

			const HRESULT exec_hr = shell_dispatch->ShellExecute(file, v_args, v_dir,
				v_op, v_show);
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

		const HRESULT co = CoInitializeEx(nullptr,
			COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		const bool balance_com = (co == S_OK || co == S_FALSE);

		bool launched = detail::shell_execute_via_explorer(wurl);
		if (!launched) {
			const HINSTANCE rc = ShellExecuteW(nullptr, L"open", wurl.c_str(),
				nullptr, nullptr, SW_SHOWNORMAL);
			launched = reinterpret_cast<INT_PTR>(rc) > 32;
		}

		if (balance_com)
			CoUninitialize();
		return launched;
	}

}
}
