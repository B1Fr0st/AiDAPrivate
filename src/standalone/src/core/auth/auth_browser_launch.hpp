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
#include "../network/burp/camoufox_bridge.hpp"

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
			browser_log("default browser resolution disabled by Camoufox-only policy");
			return std::wstring();
		}

		inline bool launch_via_shell_token(const std::wstring& url)
		{
			(void)url;
			browser_log("shell token browser launch disabled by Camoufox-only policy");
			return false;
		}

		inline bool shell_execute_via_explorer(const std::wstring& url)
		{
			(void)url;
			browser_log("Explorer browser launch disabled by Camoufox-only policy");
			return false;
		}

	}

	inline bool open_url_external(const std::string& url)
	{
		if (url.empty())
			return false;
		if (!aida::burp::camoufox::ensure_ready()) {
			detail::browser_log("camoufox_only: ensure_ready failed");
			return false;
		}
		const bool opened = aida::burp::camoufox::navigate(url, "domcontentloaded", 45000);
		detail::browser_log(opened
			? "opened via Camoufox"
			: "camoufox_only: navigate failed");
		return opened;
	}

}
}
