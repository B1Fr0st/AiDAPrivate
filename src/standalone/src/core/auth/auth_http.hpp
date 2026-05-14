#pragma once

#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace auth {
namespace http {

	struct response_t {
		int status = 0;
		std::string body;
		bool ok = false;
		std::string error;
	};

	using header_list_t = std::vector<std::pair<std::string, std::string>>;

	response_t request(const char* verb,
		const std::string& url,
		const header_list_t& headers,
		const std::string& body,
		const std::string& content_type,
		int timeout_sec);

	response_t get(const std::string& url,
		const header_list_t& headers,
		int timeout_sec);

	response_t post(const std::string& url,
		const header_list_t& headers,
		const std::string& body,
		const std::string& content_type,
		int timeout_sec);

}
}
}
