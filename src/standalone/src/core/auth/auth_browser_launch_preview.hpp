#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "auth_preview_platform.hpp"

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace auth {

inline constexpr std::uint64_t kBrowserExternalOperationDeadlineMs = 180000;
inline constexpr int kBrowserExternalNavigationTimeoutMs = 45000;
inline constexpr std::size_t kBrowserExternalMaximumUrlBytes = 8192;
inline constexpr std::uint32_t kBrowserExternalMaximumInFlight = 4;

enum class browser_open_result_t : std::uint8_t {
	opened = 0,
	queued,
	invalid_url,
	queue_rejected,
	cancelled,
	deadline_expired,
	ensure_ready_failed,
	navigate_failed,
	exception
};

struct browser_open_completion_t {
	browser_open_result_t result = browser_open_result_t::exception;
	std::uint64_t request_id = 0;
	std::uint64_t elapsed_ms = 0;

	bool opened() const noexcept { return result == browser_open_result_t::opened; }
};

using browser_open_completion_handler_t = std::function<void(const browser_open_completion_t&)>;

struct browser_open_submission_t {
	bool submitted = false;
	std::uint64_t task_id = 0;
	std::uint64_t request_id = 0;
	browser_open_result_t result = browser_open_result_t::queue_rejected;
	std::string reject_reason;
};

struct canonical_external_url_t {
	bool accepted = false;
	std::string value;
	std::string reason;
};

namespace detail {

struct browser_operation_adapter_t {
	std::function<bool()> ensure_ready;
	std::function<bool(const std::string&, const char*, int)> navigate;
	std::function<void(const std::string&)> log;
};

inline std::atomic<std::uint64_t>& preview_browser_request_id()
{
	static std::atomic<std::uint64_t> value{1};
	return value;
}

inline std::atomic<std::uint32_t>& preview_browser_in_flight()
{
	static std::atomic<std::uint32_t> value{0};
	return value;
}

inline std::atomic<unsigned>& preview_browser_failure()
{
	static std::atomic<unsigned> value{0};
	return value;
}

inline std::mutex& preview_browser_adapter_mutex()
{
	static std::mutex value;
	return value;
}

inline browser_operation_adapter_t& preview_browser_adapter()
{
	static browser_operation_adapter_t value{
		[]() { return false; },
		[](const std::string&, const char*, int) { return false; },
		[](const std::string&) {}
	};
	return value;
}

inline bool ascii_alpha(unsigned char value) noexcept
{
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
}

inline bool ascii_digit(unsigned char value) noexcept
{
	return value >= '0' && value <= '9';
}

inline bool ascii_alnum(unsigned char value) noexcept
{
	return ascii_alpha(value) || ascii_digit(value);
}

inline char ascii_lower(unsigned char value) noexcept
{
	return value >= 'A' && value <= 'Z'
		? static_cast<char>(value + ('a' - 'A')) : static_cast<char>(value);
}

inline int hex_value(unsigned char value) noexcept
{
	if (value >= '0' && value <= '9') return static_cast<int>(value - '0');
	if (value >= 'a' && value <= 'f') return static_cast<int>(value - 'a') + 10;
	if (value >= 'A' && value <= 'F') return static_cast<int>(value - 'A') + 10;
	return -1;
}

inline bool parse_ipv4(const std::string& input, std::array<std::uint8_t, 4>& bytes) noexcept
{
	std::size_t cursor = 0;
	for (std::size_t part = 0; part < bytes.size(); ++part) {
		const std::size_t end = input.find('.', cursor);
		const std::size_t stop = end == std::string::npos ? input.size() : end;
		if (stop == cursor || stop - cursor > 3) return false;
		if (stop - cursor > 1 && input[cursor] == '0') return false;
		unsigned value = 0;
		for (std::size_t index = cursor; index < stop; ++index) {
			const unsigned char ch = static_cast<unsigned char>(input[index]);
			if (!ascii_digit(ch)) return false;
			value = value * 10u + static_cast<unsigned>(ch - '0');
		}
		if (value > 255u) return false;
		bytes[part] = static_cast<std::uint8_t>(value);
		if (part + 1 < bytes.size()) {
			if (end == std::string::npos) return false;
			cursor = end + 1;
		} else if (end != std::string::npos) {
			return false;
		}
	}
	return true;
}

inline bool looks_like_noncanonical_ipv4_literal(const std::string& input) noexcept
{
	if (input.empty()) return false;
	std::size_t cursor = 0;
	while (cursor < input.size()) {
		const std::size_t end = input.find('.', cursor);
		const std::size_t stop = end == std::string::npos ? input.size() : end;
		if (stop == cursor) return false;
		std::size_t digit = cursor;
		bool hexadecimal = false;
		if (stop - cursor > 2 && input[cursor] == '0'
			&& (input[cursor + 1] == 'x' || input[cursor + 1] == 'X')) {
			digit += 2;
			hexadecimal = true;
		}
		for (; digit < stop; ++digit) {
			const unsigned char ch = static_cast<unsigned char>(input[digit]);
			if (hexadecimal ? hex_value(ch) < 0 : !ascii_digit(ch)) return false;
		}
		if (end == std::string::npos) return true;
		cursor = end + 1;
	}
	return false;
}

inline std::string canonical_ipv4(const std::array<std::uint8_t, 4>& bytes)
{
	return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "."
		+ std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
}

inline bool parse_ipv6_piece(const std::string& piece, std::vector<std::uint16_t>& words,
	bool allow_ipv4)
{
	if (piece.empty()) return true;
	std::size_t cursor = 0;
	while (cursor <= piece.size()) {
		const std::size_t end = piece.find(':', cursor);
		const std::size_t stop = end == std::string::npos ? piece.size() : end;
		if (stop == cursor) return false;
		const std::string token = piece.substr(cursor, stop - cursor);
		if (token.find('.') != std::string::npos) {
			if (!allow_ipv4 || end != std::string::npos) return false;
			std::array<std::uint8_t, 4> bytes{};
			if (!parse_ipv4(token, bytes)) return false;
			words.push_back(static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]));
			words.push_back(static_cast<std::uint16_t>((bytes[2] << 8) | bytes[3]));
		} else {
			if (token.size() > 4) return false;
			unsigned value = 0;
			for (const char raw_ch : token) {
				const auto ch = static_cast<unsigned char>(raw_ch);
				const int digit = hex_value(ch);
				if (digit < 0) return false;
				value = (value << 4) | static_cast<unsigned>(digit);
			}
			words.push_back(static_cast<std::uint16_t>(value));
		}
		if (end == std::string::npos) break;
		cursor = end + 1;
	}
	return true;
}

inline bool parse_ipv6(const std::string& input, std::array<std::uint16_t, 8>& output)
{
	if (input.empty()) return false;
	const std::size_t compression = input.find("::");
	if (compression != std::string::npos && input.find("::", compression + 2) != std::string::npos)
		return false;
	std::vector<std::uint16_t> left;
	std::vector<std::uint16_t> right;
	if (compression == std::string::npos) {
		if (!parse_ipv6_piece(input, left, true) || left.size() != 8) return false;
	} else {
		if (!parse_ipv6_piece(input.substr(0, compression), left, false)) return false;
		if (!parse_ipv6_piece(input.substr(compression + 2), right, true)) return false;
		if (left.size() + right.size() >= 8) return false;
	}
	output.fill(0);
	for (std::size_t index = 0; index < left.size(); ++index) output[index] = left[index];
	for (std::size_t index = 0; index < right.size(); ++index)
		output[8 - right.size() + index] = right[index];
	return true;
}

inline std::string canonical_ipv6(const std::array<std::uint16_t, 8>& words)
{
	std::size_t best_begin = words.size();
	std::size_t best_count = 0;
	for (std::size_t index = 0; index < words.size();) {
		if (words[index] != 0) {
			++index;
			continue;
		}
		std::size_t end = index;
		while (end < words.size() && words[end] == 0) ++end;
		if (end - index > best_count && end - index >= 2) {
			best_begin = index;
			best_count = end - index;
		}
		index = end;
	}
	std::string output;
	for (std::size_t index = 0; index < words.size();) {
		if (index == best_begin) {
			output += "::";
			index += best_count;
			continue;
		}
		if (!output.empty() && output.back() != ':') output.push_back(':');
		char buffer[8]{};
		std::snprintf(buffer, sizeof(buffer), "%x", static_cast<unsigned>(words[index]));
		output += buffer;
		++index;
	}
	return output.empty() ? std::string("::") : output;
}

inline bool canonicalize_dns_host(const std::string& input, std::string& output)
{
	if (input.empty() || input.size() > 253 || input.back() == '.') return false;
	output.clear();
	output.reserve(input.size());
	std::size_t cursor = 0;
	while (cursor < input.size()) {
		const std::size_t end = input.find('.', cursor);
		const std::size_t stop = end == std::string::npos ? input.size() : end;
		const std::size_t count = stop - cursor;
		if (count == 0 || count > 63 || input[cursor] == '-' || input[stop - 1] == '-') return false;
		if (!output.empty()) output.push_back('.');
		for (std::size_t index = cursor; index < stop; ++index) {
			const unsigned char ch = static_cast<unsigned char>(input[index]);
			if (!(ascii_alnum(ch) || ch == '-')) return false;
			output.push_back(ascii_lower(ch));
		}
		if (end == std::string::npos) break;
		cursor = end + 1;
	}
	return true;
}

inline bool parse_port(const std::string& input, std::uint16_t& output) noexcept
{
	if (input.empty() || input.size() > 5) return false;
	unsigned value = 0;
	for (const char raw_ch : input) {
		const auto ch = static_cast<unsigned char>(raw_ch);
		if (!ascii_digit(ch)) return false;
		value = value * 10u + static_cast<unsigned>(ch - '0');
	}
	if (value == 0 || value > 65535u) return false;
	output = static_cast<std::uint16_t>(value);
	return true;
}

inline bool unreserved(unsigned char ch) noexcept
{
	return ascii_alnum(ch) || ch == '-' || ch == '.' || ch == '_' || ch == '~';
}

inline bool normalize_component(const std::string& input, std::string& output)
{
	static constexpr char hex[] = "0123456789ABCDEF";
	output.clear();
	output.reserve(input.size());
	for (std::size_t index = 0; index < input.size(); ++index) {
		const unsigned char ch = static_cast<unsigned char>(input[index]);
		if (ch == '%') {
			if (index + 2 >= input.size()) return false;
			const int high = hex_value(static_cast<unsigned char>(input[index + 1]));
			const int low = hex_value(static_cast<unsigned char>(input[index + 2]));
			if (high < 0 || low < 0) return false;
			const unsigned char value = static_cast<unsigned char>((high << 4) | low);
			if (value == 0 || value < 0x20 || value >= 0x7F || value == '\\') return false;
			if (unreserved(value)) {
				output.push_back(static_cast<char>(value));
			} else {
				output.push_back('%');
				output.push_back(hex[value >> 4]);
				output.push_back(hex[value & 0x0F]);
			}
			index += 2;
		} else {
			if (ch == 0 || ch < 0x20 || ch >= 0x7F || ch == '\\') return false;
			output.push_back(static_cast<char>(ch));
		}
	}
	return true;
}

inline std::string remove_dot_segments(const std::string& path)
{
	std::vector<std::string> segments;
	std::size_t cursor = 1;
	const bool trailing = path.size() > 1 && (path.back() == '/'
		|| (path.size() >= 2 && path.compare(path.size() - 2, 2, "/.") == 0)
		|| (path.size() >= 3 && path.compare(path.size() - 3, 3, "/..") == 0));
	while (cursor <= path.size()) {
		const std::size_t end = path.find('/', cursor);
		const std::size_t stop = end == std::string::npos ? path.size() : end;
		const std::string segment = path.substr(cursor, stop - cursor);
		if (segment == "..") {
			if (!segments.empty()) segments.pop_back();
		} else if (segment != ".") {
			segments.push_back(segment);
		}
		if (end == std::string::npos) break;
		cursor = end + 1;
	}
	std::string output = "/";
	for (std::size_t index = 0; index < segments.size(); ++index) {
		if (index != 0) output.push_back('/');
		output += segments[index];
	}
	if (trailing && output.back() != '/') output.push_back('/');
	return output;
}

inline canonical_external_url_t canonicalize_url_impl(const std::string& input)
{
	canonical_external_url_t result;
	if (input.empty()) {
		result.reason = "empty_url";
		return result;
	}
	if (input.size() > kBrowserExternalMaximumUrlBytes) {
		result.reason = "url_too_large";
		return result;
	}
	for (const char raw_ch : input) {
		const auto ch = static_cast<unsigned char>(raw_ch);
		if (ch == 0 || ch <= 0x20 || ch >= 0x7F || ch == '\\') {
			result.reason = "url_forbidden_character";
			return result;
		}
	}
	const std::size_t scheme_end = input.find(':');
	if (scheme_end == std::string::npos || scheme_end + 2 >= input.size()
		|| input[scheme_end + 1] != '/' || input[scheme_end + 2] != '/') {
		result.reason = "url_missing_authority_scheme";
		return result;
	}
	std::string scheme = input.substr(0, scheme_end);
	if (scheme.empty() || !ascii_alpha(static_cast<unsigned char>(scheme.front()))) {
		result.reason = "url_scheme_invalid";
		return result;
	}
	for (char& ch : scheme) {
		const unsigned char value = static_cast<unsigned char>(ch);
		if (!(ascii_alnum(value) || value == '+' || value == '-' || value == '.')) {
			result.reason = "url_scheme_invalid";
			return result;
		}
		ch = ascii_lower(value);
	}
	if (scheme != "http" && scheme != "https") {
		result.reason = "url_scheme_not_allowed";
		return result;
	}
	const std::size_t authority_begin = scheme_end + 3;
	const std::size_t authority_end = input.find_first_of("/?#", authority_begin);
	const std::size_t authority_stop = authority_end == std::string::npos ? input.size() : authority_end;
	const std::string authority = input.substr(authority_begin, authority_stop - authority_begin);
	if (authority.empty() || authority.find('@') != std::string::npos) {
		result.reason = "url_authority_invalid";
		return result;
	}
	std::string host;
	std::string port_text;
	bool port_present = false;
	bool ipv6 = false;
	if (authority.front() == '[') {
		const std::size_t bracket = authority.find(']');
		if (bracket == std::string::npos || bracket == 1) {
			result.reason = "url_ipv6_invalid";
			return result;
		}
		if (bracket + 1 < authority.size()) {
			if (authority[bracket + 1] != ':') {
				result.reason = "url_authority_invalid";
				return result;
			}
			port_text = authority.substr(bracket + 2);
			port_present = true;
		}
		std::array<std::uint16_t, 8> words{};
		if (!parse_ipv6(authority.substr(1, bracket - 1), words)) {
			result.reason = "url_ipv6_invalid";
			return result;
		}
		host = canonical_ipv6(words);
		ipv6 = true;
	} else {
		std::string raw_host = authority;
		const std::size_t colon = authority.find(':');
		if (colon != std::string::npos) {
			if (authority.find(':', colon + 1) != std::string::npos) {
				result.reason = "url_ipv6_brackets_required";
				return result;
			}
			raw_host = authority.substr(0, colon);
			port_text = authority.substr(colon + 1);
			port_present = true;
		}
		std::array<std::uint8_t, 4> bytes{};
		if (parse_ipv4(raw_host, bytes)) {
			host = canonical_ipv4(bytes);
		} else if (looks_like_noncanonical_ipv4_literal(raw_host)) {
			result.reason = "url_ipv4_invalid";
			return result;
		} else if (!canonicalize_dns_host(raw_host, host)) {
			result.reason = "url_host_invalid";
			return result;
		}
	}
	std::uint16_t port = 0;
	if (port_present && !parse_port(port_text, port)) {
		result.reason = "url_port_invalid";
		return result;
	}
	const bool default_port = (scheme == "http" && port == 80)
		|| (scheme == "https" && port == 443);
	std::size_t path_end = input.find_first_of("?#", authority_stop);
	const std::size_t path_stop = path_end == std::string::npos ? input.size() : path_end;
	const std::string raw_path = authority_stop < input.size() && input[authority_stop] == '/'
		? input.substr(authority_stop, path_stop - authority_stop) : std::string("/");
	std::string path;
	if (!normalize_component(raw_path, path)) {
		result.reason = "url_path_encoding_invalid";
		return result;
	}
	path = remove_dot_segments(path);
	std::string suffix;
	if (path_end != std::string::npos && input[path_end] == '?') {
		const std::size_t fragment_position = input.find('#', path_end + 1);
		const std::size_t query_stop = fragment_position == std::string::npos
			? input.size() : fragment_position;
		std::string query;
		if (!normalize_component(input.substr(path_end + 1, query_stop - path_end - 1), query)) {
			result.reason = "url_query_encoding_invalid";
			return result;
		}
		suffix.push_back('?');
		suffix += query;
		path_end = fragment_position;
	}
	if (path_end != std::string::npos && input[path_end] == '#') {
		std::string fragment;
		if (!normalize_component(input.substr(path_end + 1), fragment)) {
			result.reason = "url_fragment_encoding_invalid";
			return result;
		}
		suffix.push_back('#');
		suffix += fragment;
	}
	result.value = scheme + "://" + (ipv6 ? "[" + host + "]" : host);
	if (port != 0 && !default_port) result.value += ":" + std::to_string(port);
	result.value += path;
	result.value += suffix;
	result.accepted = true;
	return result;
}

inline std::uint64_t next_browser_request_id() noexcept
{
	return preview_browser_request_id().fetch_add(1, std::memory_order_acq_rel);
}

inline bool try_acquire_physical_capacity() noexcept
{
	std::uint32_t current = preview_browser_in_flight().load(std::memory_order_acquire);
	while (current < kBrowserExternalMaximumInFlight) {
		if (preview_browser_in_flight().compare_exchange_weak(current, current + 1,
			std::memory_order_acq_rel, std::memory_order_acquire)) return true;
	}
	return false;
}

inline void release_physical_capacity() noexcept
{
	std::uint32_t current = preview_browser_in_flight().load(std::memory_order_acquire);
	while (current != 0 && !preview_browser_in_flight().compare_exchange_weak(current, current - 1,
		std::memory_order_acq_rel, std::memory_order_acquire)) {
	}
}

inline bool consume_browser_fixture_failure(unsigned value) noexcept
{
	unsigned expected = value;
	return preview_browser_failure().compare_exchange_strong(expected, 0,
		std::memory_order_acq_rel, std::memory_order_acquire);
}

inline browser_operation_adapter_t browser_adapter_snapshot()
{
	std::lock_guard<std::mutex> lock(preview_browser_adapter_mutex());
	return preview_browser_adapter();
}

inline std::uint64_t bounded_deadline(std::uint64_t now, std::uint64_t budget) noexcept
{
	return now > (std::numeric_limits<std::uint64_t>::max)() - budget
		? (std::numeric_limits<std::uint64_t>::max)() : now + budget;
}

inline void invoke_completion_noexcept(const browser_open_completion_handler_t& completion,
	const browser_open_completion_t& value) noexcept
{
	if (!completion) return;
	try {
		const std::function<void()> guarded = [&]() { completion(value); };
		aida::infra::win_thread::run_function_seh_guarded(guarded);
	} catch (...) {
	}
}

inline browser_open_completion_t execute_browser_open(const std::string& canonical_url,
	std::uint64_t request_id, std::uint64_t deadline_ms, const std::atomic<bool>* cancelled) noexcept
{
	const std::uint64_t started_ms = aida::infra::executor::now_ms();
	browser_open_result_t result = browser_open_result_t::exception;
	try {
		const browser_operation_adapter_t adapter = browser_adapter_snapshot();
		const std::function<void()> guarded = [&]() {
			if (cancelled && cancelled->load(std::memory_order_acquire)) {
				result = browser_open_result_t::cancelled;
				return;
			}
			if (deadline_ms != 0 && aida::infra::executor::now_ms() >= deadline_ms) {
				result = browser_open_result_t::deadline_expired;
				return;
			}
			if (!adapter.ensure_ready || !adapter.ensure_ready()) {
				result = browser_open_result_t::ensure_ready_failed;
				return;
			}
			if (cancelled && cancelled->load(std::memory_order_acquire)) {
				result = browser_open_result_t::cancelled;
				return;
			}
			const std::uint64_t before_navigation = aida::infra::executor::now_ms();
			if (deadline_ms != 0 && before_navigation >= deadline_ms) {
				result = browser_open_result_t::deadline_expired;
				return;
			}
			int timeout_ms = kBrowserExternalNavigationTimeoutMs;
			if (deadline_ms != 0) {
				const std::uint64_t remaining = deadline_ms - before_navigation;
				if (remaining < static_cast<std::uint64_t>(timeout_ms))
					timeout_ms = static_cast<int>(remaining);
			}
			result = adapter.navigate && adapter.navigate(canonical_url, "domcontentloaded", timeout_ms)
				? browser_open_result_t::opened : browser_open_result_t::navigate_failed;
		};
		if (aida::infra::win_thread::run_function_seh_guarded(guarded) != 0)
			result = browser_open_result_t::exception;
	} catch (...) {
		result = browser_open_result_t::exception;
	}
	const std::uint64_t now = aida::infra::executor::now_ms();
	if (result != browser_open_result_t::opened && cancelled
		&& cancelled->load(std::memory_order_acquire)) result = browser_open_result_t::cancelled;
	if (result != browser_open_result_t::opened && deadline_ms != 0 && now >= deadline_ms
		&& result != browser_open_result_t::cancelled) result = browser_open_result_t::deadline_expired;
	try {
		const browser_operation_adapter_t adapter = browser_adapter_snapshot();
		if (adapter.log) adapter.log(canonical_url);
	} catch (...) {
	}
	return browser_open_completion_t{result, request_id, now >= started_ms ? now - started_ms : 0};
}

enum class async_phase_t : std::uint8_t { queued, running, cancelled_before_start, finished, rejected };

struct async_browser_open_state_t {
	std::atomic<bool> cancelled{false};
	std::atomic<bool> published{false};
	std::atomic<bool> physical_released{false};
	std::atomic<async_phase_t> phase{async_phase_t::queued};
	std::uint64_t request_id = 0;
	std::uint64_t submitted_ms = 0;
	std::uint64_t deadline_ms = 0;
	browser_open_completion_handler_t completion;
};

inline void release_state_capacity(const std::shared_ptr<async_browser_open_state_t>& state) noexcept
{
	if (state && !state->physical_released.exchange(true, std::memory_order_acq_rel))
		release_physical_capacity();
}

struct physical_state_guard_t {
	std::shared_ptr<async_browser_open_state_t> state;
	~physical_state_guard_t() noexcept { release_state_capacity(state); }
};

inline void publish_browser_completion(const std::shared_ptr<async_browser_open_state_t>& state,
	browser_open_result_t result, std::uint64_t elapsed_ms) noexcept
{
	if (!state) return;
	bool expected = false;
	if (!state->published.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel, std::memory_order_acquire)) return;
	invoke_completion_noexcept(state->completion,
		browser_open_completion_t{result, state->request_id, elapsed_ms});
}

inline void cancel_async_state(const std::shared_ptr<async_browser_open_state_t>& state) noexcept
{
	if (!state) return;
	state->cancelled.store(true, std::memory_order_release);
	async_phase_t expected = async_phase_t::queued;
	if (state->phase.compare_exchange_strong(expected, async_phase_t::cancelled_before_start,
		std::memory_order_acq_rel, std::memory_order_acquire)) release_state_capacity(state);
	const std::uint64_t now = aida::infra::executor::now_ms();
	const browser_open_result_t result = state->deadline_ms != 0 && now >= state->deadline_ms
		? browser_open_result_t::deadline_expired : browser_open_result_t::cancelled;
	publish_browser_completion(state, result,
		now >= state->submitted_ms ? now - state->submitted_ms : 0);
}

}

inline canonical_external_url_t canonicalize_external_url(const std::string& input)
{
	try {
		return detail::canonicalize_url_impl(input);
	} catch (...) {
		canonical_external_url_t result;
		result.reason = "url_canonicalization_exception";
		return result;
	}
}

inline std::uint32_t browser_physical_in_flight() noexcept
{
	return detail::preview_browser_in_flight().load(std::memory_order_acquire);
}

inline browser_open_submission_t submit_open_url_external_until(
	std::string url,
	std::uint64_t absolute_deadline_ms,
	browser_open_completion_handler_t completion = {})
{
	browser_open_submission_t output;
	output.request_id = detail::next_browser_request_id();
	canonical_external_url_t canonical;
	try {
		canonical = canonicalize_external_url(url);
	} catch (...) {
		output.result = browser_open_result_t::invalid_url;
		detail::invoke_completion_noexcept(completion,
			browser_open_completion_t{output.result, output.request_id, 0});
		try { output.reject_reason = "url_canonicalization_exception"; } catch (...) {}
		return output;
	}
	if (!canonical.accepted) {
		output.result = browser_open_result_t::invalid_url;
		detail::invoke_completion_noexcept(completion,
			browser_open_completion_t{output.result, output.request_id, 0});
		try { output.reject_reason = canonical.reason; } catch (...) {}
		return output;
	}
	std::shared_ptr<detail::async_browser_open_state_t> state;
	try {
		if (detail::consume_browser_fixture_failure(1)) throw std::bad_alloc();
		state = std::make_shared<detail::async_browser_open_state_t>();
		state->request_id = output.request_id;
		state->submitted_ms = aida::infra::executor::now_ms();
		state->deadline_ms = absolute_deadline_ms == 0
			? detail::bounded_deadline(state->submitted_ms, kBrowserExternalOperationDeadlineMs)
			: absolute_deadline_ms;
		state->completion = std::move(completion);
	} catch (...) {
		output.result = browser_open_result_t::queue_rejected;
		detail::invoke_completion_noexcept(completion,
			browser_open_completion_t{output.result, output.request_id, 0});
		try { output.reject_reason = "browser_state_allocation_failed"; } catch (...) {}
		return output;
	}
	if (!detail::try_acquire_physical_capacity()) {
		output.result = browser_open_result_t::queue_rejected;
		state->physical_released.store(true, std::memory_order_release);
		detail::publish_browser_completion(state, output.result, 0);
		try { output.reject_reason = "browser_capacity_exhausted"; } catch (...) {}
		return output;
	}
	try {
		if (detail::consume_browser_fixture_failure(2))
			throw std::runtime_error("fixture_submission_failure");
		aida::infra::executor::submission_t submission;
		submission.owner_subsystem = "auth_browser";
		submission.label = "auth.browser.camoufox_open";
		submission.thread_class = "external_tool";
		submission.domain = aida::infra::executor::domain_t::external_tool;
		submission.priority = 2;
		submission.deadline_ms = state->deadline_ms;
		submission.capacity_lease = state->request_id;
		submission.no_capacity_reason = "browser_capacity_exhausted";
		submission.lease_token = state->request_id;
		submission.generation = state->request_id;
		submission.ui_access_policy = "none";
		submission.failure_policy = "publish_typed_failure";
		submission.shutdown_policy = "cancel_pending";
		submission.cancel_hook = [state]() noexcept { detail::cancel_async_state(state); };
		submission.body = [state, canonical_url = canonical.value]() noexcept {
			detail::async_phase_t expected = detail::async_phase_t::queued;
			if (!state->phase.compare_exchange_strong(expected, detail::async_phase_t::running,
				std::memory_order_acq_rel, std::memory_order_acquire)) return;
			detail::physical_state_guard_t guard{state};
			const browser_open_completion_t value = detail::execute_browser_open(canonical_url,
				state->request_id, state->deadline_ms, &state->cancelled);
			state->phase.store(detail::async_phase_t::finished, std::memory_order_release);
			detail::publish_browser_completion(state, value.result, value.elapsed_ms);
		};
		const aida::infra::executor::submit_result_t submitted =
			aida::infra::executor::submit(std::move(submission));
		output.submitted = submitted.submitted;
		output.task_id = submitted.task_id;
		if (!submitted.submitted) {
			state->phase.store(detail::async_phase_t::rejected, std::memory_order_release);
			detail::release_state_capacity(state);
			output.result = browser_open_result_t::queue_rejected;
			detail::publish_browser_completion(state, output.result, 0);
			try {
				output.reject_reason = submitted.reject_reason.empty()
					? std::string("executor_rejected") : submitted.reject_reason;
			} catch (...) {
			}
			return output;
		}
	} catch (...) {
		state->phase.store(detail::async_phase_t::rejected, std::memory_order_release);
		detail::release_state_capacity(state);
		output.result = browser_open_result_t::queue_rejected;
		detail::publish_browser_completion(state, output.result, 0);
		try { output.reject_reason = "executor_submission_exception"; } catch (...) {}
		return output;
	}
	output.result = browser_open_result_t::queued;
	return output;
}

inline browser_open_submission_t submit_open_url_external(
	std::string url,
	browser_open_completion_handler_t completion = {})
{
	return submit_open_url_external_until(std::move(url),
		0,
		std::move(completion));
}

inline bool open_url_external_until(const std::string& url,
	std::uint64_t absolute_deadline_ms) noexcept
{
	try {
		const std::uint64_t request_id = detail::next_browser_request_id();
		const canonical_external_url_t canonical = canonicalize_external_url(url);
		if (!canonical.accepted) return false;
		if (!detail::try_acquire_physical_capacity()) return false;
		struct guard_t { ~guard_t() noexcept { detail::release_physical_capacity(); } } guard;
		const std::uint64_t now = aida::infra::executor::now_ms();
		const std::uint64_t deadline = absolute_deadline_ms == 0
			? detail::bounded_deadline(now, kBrowserExternalOperationDeadlineMs)
			: absolute_deadline_ms;
		return detail::execute_browser_open(canonical.value, request_id, deadline, nullptr).opened();
	} catch (...) {
		return false;
	}
}

inline bool open_url_external(const std::string& url) noexcept
{
	return open_url_external_until(url,
		0);
}

inline bool cancel_open_url_external(std::uint64_t task_id) noexcept
{
	try {
		return task_id != 0 && aida::infra::executor::cancel(task_id);
	} catch (...) {
		return false;
	}
}

#if defined(AIDA_C03_AUTH_BROWSER_FIXTURE)
inline void install_browser_operation_fixture(detail::browser_operation_adapter_t adapter)
{
	std::lock_guard<std::mutex> lock(detail::preview_browser_adapter_mutex());
	detail::preview_browser_adapter() = std::move(adapter);
}

inline void reset_browser_operation_fixture()
{
	std::lock_guard<std::mutex> lock(detail::preview_browser_adapter_mutex());
	detail::preview_browser_adapter() = detail::browser_operation_adapter_t{
		[]() { return false; },
		[](const std::string&, const char*, int) { return false; },
		[](const std::string&) {}
	};
}

inline void inject_browser_fixture_failure(unsigned failure)
{
	detail::preview_browser_failure().store(failure, std::memory_order_release);
}
#endif

}
}

#endif
