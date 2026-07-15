#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "auth_preview_platform.hpp"

#include <atomic>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>

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
		[]() { return true; },
		[](const std::string&, const char*, int) { return true; },
		[](const std::string&) {}
	};
	return value;
}

}

inline canonical_external_url_t canonicalize_external_url(const std::string& input)
{
	canonical_external_url_t result;
	if (input.empty()) {
		result.reason = "empty_url";
		return result;
	}
	if (input.size() > kBrowserExternalMaximumUrlBytes) {
		result.reason = "url_too_long";
		return result;
	}
	for (char raw_ch : input) {
		const auto ch = static_cast<unsigned char>(raw_ch);
		if (ch < 0x20 || ch == 0x7f) {
			result.reason = "invalid_character";
			return result;
		}
	}
	std::string scheme;
	scheme.reserve(8);
	const std::size_t separator = input.find("://");
	if (separator == std::string::npos) {
		result.reason = "missing_scheme";
		return result;
	}
	for (std::size_t i = 0; i < separator; ++i)
		scheme.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(input[i]))));
	if (scheme != "https" && scheme != "http") {
		result.reason = "unsupported_scheme";
		return result;
	}
	if (input.size() <= separator + 3) {
		result.reason = "missing_host";
		return result;
	}
	result.accepted = true;
	result.value = input;
	return result;
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
	output.request_id = detail::preview_browser_request_id().fetch_add(1, std::memory_order_acq_rel);
	const canonical_external_url_t canonical = canonicalize_external_url(url);
	if (!canonical.accepted) {
		output.result = browser_open_result_t::invalid_url;
		output.reject_reason = canonical.reason;
		if (completion) completion(browser_open_completion_t{output.result, output.request_id, 0});
		return output;
	}
	if (absolute_deadline_ms != 0 && aida::infra::executor::now_ms() >= absolute_deadline_ms) {
		output.result = browser_open_result_t::deadline_expired;
		output.reject_reason = "deadline_expired";
		if (completion) completion(browser_open_completion_t{output.result, output.request_id, 0});
		return output;
	}
	if (detail::preview_browser_in_flight().load(std::memory_order_acquire)
		>= kBrowserExternalMaximumInFlight) {
		output.result = browser_open_result_t::queue_rejected;
		output.reject_reason = "browser_capacity_exhausted";
		if (completion) completion(browser_open_completion_t{output.result, output.request_id, 0});
		return output;
	}
	detail::preview_browser_in_flight().fetch_add(1, std::memory_order_acq_rel);
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "auth_browser";
	submission.label = "auth.browser.preview_open";
	submission.domain = aida::infra::executor::domain_t::external_tool;
	const std::uint64_t request_id = output.request_id;
	submission.body = [canonical_url = canonical.value, completion, request_id]() {
		browser_open_result_t result = browser_open_result_t::opened;
		unsigned failure = detail::preview_browser_failure().exchange(0, std::memory_order_acq_rel);
		if (failure == 1) {
			result = browser_open_result_t::ensure_ready_failed;
		} else if (failure == 2) {
			result = browser_open_result_t::navigate_failed;
		} else {
			detail::browser_operation_adapter_t adapter;
			{
				std::lock_guard<std::mutex> lock(detail::preview_browser_adapter_mutex());
				adapter = detail::preview_browser_adapter();
			}
			if (adapter.ensure_ready && !adapter.ensure_ready())
				result = browser_open_result_t::ensure_ready_failed;
			else if (adapter.navigate && !adapter.navigate(canonical_url, "domcontentloaded",
				kBrowserExternalNavigationTimeoutMs))
				result = browser_open_result_t::navigate_failed;
			if (adapter.log) adapter.log(canonical_url);
		}
		detail::preview_browser_in_flight().fetch_sub(1, std::memory_order_acq_rel);
		if (completion) completion(browser_open_completion_t{result, request_id, 16});
	};
	submission.cancel_hook = [completion, request_id]() {
		detail::preview_browser_in_flight().fetch_sub(1, std::memory_order_acq_rel);
		if (completion) completion(browser_open_completion_t{
			browser_open_result_t::cancelled, request_id, 0});
	};
	const aida::infra::executor::submit_result_t submitted =
		aida::infra::executor::submit(std::move(submission));
	output.submitted = submitted.submitted;
	output.task_id = submitted.task_id;
	output.result = submitted.submitted
		? browser_open_result_t::queued
		: browser_open_result_t::queue_rejected;
	output.reject_reason = submitted.reject_reason;
	if (!submitted.submitted)
		detail::preview_browser_in_flight().fetch_sub(1, std::memory_order_acq_rel);
	return output;
}

inline browser_open_submission_t submit_open_url_external(
	std::string url,
	browser_open_completion_handler_t completion = {})
{
	return submit_open_url_external_until(std::move(url),
		aida::infra::executor::now_ms() + kBrowserExternalOperationDeadlineMs,
		std::move(completion));
}

inline bool open_url_external_until(const std::string& url,
	std::uint64_t absolute_deadline_ms) noexcept
{
	try {
		const canonical_external_url_t canonical = canonicalize_external_url(url);
		if (!canonical.accepted) return false;
		if (absolute_deadline_ms != 0 && aida::infra::executor::now_ms() >= absolute_deadline_ms)
			return false;
		return true;
	} catch (...) {
		return false;
	}
}

inline bool open_url_external(const std::string& url) noexcept
{
	return open_url_external_until(url,
		aida::infra::executor::now_ms() + kBrowserExternalOperationDeadlineMs);
}

inline bool cancel_open_url_external(std::uint64_t task_id) noexcept
{
	return task_id != 0 && aida::infra::executor::cancel(task_id);
}

inline void install_browser_operation_fixture(detail::browser_operation_adapter_t adapter)
{
	std::lock_guard<std::mutex> lock(detail::preview_browser_adapter_mutex());
	detail::preview_browser_adapter() = std::move(adapter);
}

inline void reset_browser_operation_fixture()
{
	std::lock_guard<std::mutex> lock(detail::preview_browser_adapter_mutex());
	detail::preview_browser_adapter() = detail::browser_operation_adapter_t{
		[]() { return true; },
		[](const std::string&, const char*, int) { return true; },
		[](const std::string&) {}
	};
}

inline void inject_browser_fixture_failure(unsigned failure)
{
	detail::preview_browser_failure().store(failure, std::memory_order_release);
}

}
}

#endif
