#pragma once

#include <string>

#include "anti-tamper/webhook.hpp"
#include "../network/burp/camoufox_bridge.hpp"

namespace aida {
namespace auth {

	namespace detail {

		inline void browser_log(const char* message)
		{
			anti_tamper::webhook::write_log("auth.browser",
				(std::string("[aida.auth.browser] ") + message).c_str());
		}

	}

	inline bool open_url_external(const std::string& url)
	{
		if (url.empty()) {
			detail::browser_log("camoufox_only: empty URL rejected");
			return false;
		}
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
