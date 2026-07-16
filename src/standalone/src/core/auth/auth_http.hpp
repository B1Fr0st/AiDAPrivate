#pragma once

#include <cstddef>
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
		bool complete = false;
		bool truncated = false;
		bool cancelled = false;
		std::string error;
	};

	using header_list_t = std::vector<std::pair<std::string, std::string>>;

	using stream_chunk_cb_t = std::function<bool(const char* data, std::size_t len)>;
	using cancel_cb_t = std::function<bool()>;

	struct stream_result_t {
		int status = 0;
		bool ok = false;
		bool complete = false;
		bool truncated = false;
		bool cancelled = false;
		std::string error;
	};

	response_t request(const char* verb,
		const std::string& url,
		const header_list_t& headers,
		const std::string& body,
		const std::string& content_type,
		int timeout_sec,
		const cancel_cb_t& cancelled = {});

	response_t get(const std::string& url,
		const header_list_t& headers,
		int timeout_sec,
		const cancel_cb_t& cancelled = {});

	response_t post(const std::string& url,
		const header_list_t& headers,
		const std::string& body,
		const std::string& content_type,
		int timeout_sec,
		const cancel_cb_t& cancelled = {});

	stream_result_t stream(const char* verb,
		const std::string& url,
		const header_list_t& headers,
		const std::string& body,
		const std::string& content_type,
		int timeout_sec,
		const stream_chunk_cb_t& on_chunk,
		const cancel_cb_t& cancelled = {});

	void cleanup();

}
}
}
