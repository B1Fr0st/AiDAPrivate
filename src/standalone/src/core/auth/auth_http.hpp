#pragma once

#include <functional>
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

	using stream_chunk_cb_t = std::function<bool(const char* data, size_t len)>;

	struct stream_result_t {
		int status = 0;
		bool ok = false;
		bool cancelled = false;
		std::string error;
	};

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

	stream_result_t stream(const char* verb,
		const std::string& url,
		const header_list_t& headers,
		const std::string& body,
		const std::string& content_type,
		int timeout_sec,
		const stream_chunk_cb_t& on_chunk);

	void cleanup();

}
}
}
