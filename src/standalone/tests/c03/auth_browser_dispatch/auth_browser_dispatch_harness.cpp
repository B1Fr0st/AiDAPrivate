#define AIDA_C03_AUTH_BROWSER_FIXTURE 1

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#endif

#include "auth_browser_dispatch_harness.hpp"
#include "../../../src/core/auth/auth_browser_launch.hpp"
#include "../../../src/core/auth/auth_claude_code.hpp"
#include "../../../src/core/auth/auth_codex.hpp"
#include "../../../src/core/auth/auth_copilot.hpp"
#include "../../../src/core/auth/auth_http.hpp"
#include "../../../src/core/auth/auth_store.hpp"
#include "../../../src/core/ai/provider_catalog.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace aida::auth::c03_test {

static_assert(std::is_same_v<decltype(codex::last_error()), std::string>);
static_assert(std::is_same_v<decltype(copilot::last_error()), std::string>);
static_assert(std::is_same_v<decltype(claude_code::last_error()), std::string>);
static_assert(std::is_same_v<decltype(store::last_error()), std::string>);
static_assert(std::is_same_v<decltype(codex::refresh_token(
    std::declval<const http::cancel_cb_t&>(), 1)), bool>);
static_assert(std::is_same_v<decltype(copilot::refresh_token(
    std::declval<const http::cancel_cb_t&>(), 1)), bool>);
static_assert(std::is_same_v<decltype(claude_code::refresh_token(
    std::declval<const http::cancel_cb_t&>(), 1)), bool>);

namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

struct fake_browser_t {
    std::mutex mutex;
    std::condition_variable cv;
    bool block_ready = false;
    bool release_ready = false;
    bool ready_result = true;
    bool navigate_result = true;
    bool throw_ready = false;
    bool seh_ready = false;
    bool throw_log = false;
    bool seh_log = false;
    std::size_t entered = 0;
    std::size_t active = 0;
    std::size_t max_active = 0;
    std::vector<std::string> urls;

    bool ensure_ready()
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            ++entered;
            ++active;
            if (active > max_active) max_active = active;
            cv.notify_all();
            while (block_ready && !release_ready) cv.wait(lock);
            --active;
        }
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        if (seh_ready) RaiseException(0xE1234001u, 0, 0, nullptr);
#endif
        if (throw_ready) throw std::runtime_error("fixture_ready_exception");
        return ready_result;
    }

    bool navigate(const std::string& url, const char*, int)
    {
        std::lock_guard<std::mutex> lock(mutex);
        urls.push_back(url);
        return navigate_result;
    }

    void log(const std::string&)
    {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        if (seh_log) RaiseException(0xE1234002u, 0, 0, nullptr);
#endif
        if (throw_log) throw std::runtime_error("fixture_log_exception");
    }

    void wait_entered(std::size_t count)
    {
        std::unique_lock<std::mutex> lock(mutex);
        require(cv.wait_for(lock, std::chrono::seconds(5), [&]() { return entered >= count; }),
            "browser operation did not enter before fixture deadline");
    }

    void release()
    {
        std::lock_guard<std::mutex> lock(mutex);
        release_ready = true;
        cv.notify_all();
    }
};

detail::browser_operation_adapter_t adapter_for(const std::shared_ptr<fake_browser_t>& fake)
{
    detail::browser_operation_adapter_t adapter;
    adapter.ensure_ready = [fake]() { return fake->ensure_ready(); };
    adapter.navigate = [fake](const std::string& url, const char* wait_until, int timeout_ms) {
        return fake->navigate(url, wait_until, timeout_ms);
    };
    adapter.log = [fake](const std::string& message) { fake->log(message); };
    return adapter;
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
struct socket_guard_t {
	SOCKET value = INVALID_SOCKET;
	~socket_guard_t() noexcept { if (value != INVALID_SOCKET) closesocket(value); }
};

class loopback_http_server_t {
public:
	explicit loopback_http_server_t(std::string response,
		std::chrono::milliseconds response_delay = std::chrono::milliseconds(0))
		: response_(std::move(response)), response_delay_(response_delay)
	{
		WSADATA data{};
		if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
			throw std::runtime_error("HTTP fixture Winsock initialization failed");
		winsock_started_ = true;
		listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listener_ == INVALID_SOCKET) fail_startup("HTTP fixture socket creation failed");
		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		address.sin_port = 0;
		if (bind(listener_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
			fail_startup("HTTP fixture bind failed");
		int address_size = sizeof(address);
		if (getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &address_size) != 0)
			fail_startup("HTTP fixture port discovery failed");
		port_ = ntohs(address.sin_port);
		if (listen(listener_, 4) != 0)
			fail_startup("HTTP fixture listen failed");
		try {
			worker_ = std::thread([this]() noexcept { serve(); });
		} catch (...) {
			fail_startup("HTTP fixture worker creation failed");
		}
	}

	loopback_http_server_t(const loopback_http_server_t&) = delete;
	loopback_http_server_t& operator=(const loopback_http_server_t&) = delete;

	~loopback_http_server_t() noexcept
	{
		finish();
		if (winsock_started_) WSACleanup();
	}

	int port() const noexcept { return port_; }
	unsigned connections() const noexcept { return connections_.load(std::memory_order_acquire); }
	bool failed() const noexcept { return failed_.load(std::memory_order_acquire); }

	void finish() noexcept
	{
		stop_.store(true, std::memory_order_release);
		if (worker_.joinable()) worker_.join();
		if (listener_ != INVALID_SOCKET) {
			closesocket(listener_);
			listener_ = INVALID_SOCKET;
		}
	}

private:
	void fail_startup(const char* message)
	{
		if (listener_ != INVALID_SOCKET) {
			closesocket(listener_);
			listener_ = INVALID_SOCKET;
		}
		if (winsock_started_) {
			WSACleanup();
			winsock_started_ = false;
		}
		throw std::runtime_error(message);
	}

	void serve() noexcept
	{
		while (!stop_.load(std::memory_order_acquire) && connections() < 2) {
			fd_set read_set;
			FD_ZERO(&read_set);
			FD_SET(listener_, &read_set);
			timeval timeout{};
			timeout.tv_usec = 100000;
			const int ready = select(0, &read_set, nullptr, nullptr, &timeout);
			if (ready == 0) continue;
			if (ready == SOCKET_ERROR) {
				failed_.store(true, std::memory_order_release);
				return;
			}
			socket_guard_t client{accept(listener_, nullptr, nullptr)};
			if (client.value == INVALID_SOCKET) {
				failed_.store(true, std::memory_order_release);
				return;
			}
			connections_.fetch_add(1, std::memory_order_acq_rel);
			DWORD io_timeout = 5000;
			if (setsockopt(client.value, SOL_SOCKET, SO_RCVTIMEO,
				reinterpret_cast<const char*>(&io_timeout), sizeof(io_timeout)) != 0
				|| setsockopt(client.value, SOL_SOCKET, SO_SNDTIMEO,
					reinterpret_cast<const char*>(&io_timeout), sizeof(io_timeout)) != 0) {
				failed_.store(true, std::memory_order_release);
				return;
			}
			std::string request;
			char buffer[2048];
			while (request.size() < 65536 && request.find("\r\n\r\n") == std::string::npos) {
				const int count = recv(client.value, buffer, sizeof(buffer), 0);
				if (count <= 0) break;
				request.append(buffer, static_cast<std::size_t>(count));
			}
			if (request.find("\r\n\r\n") == std::string::npos) {
				failed_.store(true, std::memory_order_release);
				continue;
			}
			const auto response_time = std::chrono::steady_clock::now() + response_delay_;
			while (!stop_.load(std::memory_order_acquire)
				&& std::chrono::steady_clock::now() < response_time)
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
			if (stop_.load(std::memory_order_acquire)) continue;
			std::size_t sent = 0;
			while (sent < response_.size()) {
				const int count = send(client.value, response_.data() + sent,
					static_cast<int>((std::min)(response_.size() - sent,
						static_cast<std::size_t>(1 << 20))), 0);
				if (count <= 0) {
					failed_.store(true, std::memory_order_release);
					break;
				}
				sent += static_cast<std::size_t>(count);
			}
			shutdown(client.value, SD_SEND);
		}
	}

	std::string response_;
	std::chrono::milliseconds response_delay_;
	SOCKET listener_ = INVALID_SOCKET;
	int port_ = 0;
	bool winsock_started_ = false;
	std::atomic<bool> stop_{false};
	std::atomic<bool> failed_{false};
	std::atomic<unsigned> connections_{0};
	std::thread worker_;
};

std::string loopback_http_url(int port)
{
	return "http://127.0.0.1:" + std::to_string(port) + "/fixture";
}

SOCKET connect_loopback(int port)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (std::chrono::steady_clock::now() < deadline) {
		SOCKET ipv4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (ipv4 != INVALID_SOCKET) {
			sockaddr_in address{};
			address.sin_family = AF_INET;
			address.sin_port = htons(static_cast<u_short>(port));
			address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			if (connect(ipv4, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0)
				return ipv4;
			closesocket(ipv4);
		}
		SOCKET ipv6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (ipv6 != INVALID_SOCKET) {
			sockaddr_in6 address{};
			address.sin6_family = AF_INET6;
			address.sin6_port = htons(static_cast<u_short>(port));
			address.sin6_addr = in6addr_loopback;
			if (connect(ipv6, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0)
				return ipv6;
			closesocket(ipv6);
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	return INVALID_SOCKET;
}

int send_loopback_request(int port, const std::string& request)
{
	socket_guard_t socket_owner{connect_loopback(port)};
	require(socket_owner.value != INVALID_SOCKET, "provider listener did not accept loopback connection");
	std::size_t sent = 0;
	while (sent < request.size()) {
		const int count = send(socket_owner.value, request.data() + sent,
			static_cast<int>(request.size() - sent), 0);
		require(count > 0, "provider listener request send failed");
		sent += static_cast<std::size_t>(count);
	}
	std::string response;
	char buffer[2048];
	while (response.size() < 16384) {
		const int count = recv(socket_owner.value, buffer, sizeof(buffer), 0);
		if (count <= 0) break;
		response.append(buffer, static_cast<std::size_t>(count));
		if (response.find("\r\n\r\n") != std::string::npos) break;
	}
	require(response.rfind("HTTP/1.1 ", 0) == 0 && response.size() >= 12,
		"provider listener response status line was malformed");
	return std::atoi(response.substr(9, 3).c_str());
}

template <typename State>
void wait_provider_terminal(const State& state)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (!state.done.load(std::memory_order_acquire)
		&& std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
	require(state.done.load(std::memory_order_acquire),
		"provider listener did not publish terminal state before deadline");
}
#endif

void wait_terminal(const std::atomic<unsigned>& count, unsigned expected)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (count.load(std::memory_order_acquire) < expected
        && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
    require(count.load(std::memory_order_acquire) == expected,
        "typed completion did not publish exactly once before fixture deadline");
}

void test_canonical_urls()
{
    const auto first = canonicalize_external_url("HTTPS://Example.COM:443/a/./b/../c/%7euser?q=%41%2f#%7e");
    require(first.accepted, "canonical HTTPS URL was rejected");
    require(first.value == "https://example.com/a/c/~user?q=A%2F#~",
        "canonical HTTPS identity drifted");
    const auto equivalent = canonicalize_external_url("https://example.com/a/c/~user?q=A%2F#~");
    require(equivalent.accepted && equivalent.value == first.value,
        "equivalent URLs did not converge to one execution identity");
    const auto ipv6 = canonicalize_external_url("http://[2001:0DB8:0:0:0:0:0:1]:80");
    require(ipv6.accepted && ipv6.value == "http://[2001:db8::1]/",
        "IPv6 canonicalization failed");
    const auto ipv4 = canonicalize_external_url("http://192.168.1.9:8080/a");
    require(ipv4.accepted && ipv4.value == "http://192.168.1.9:8080/a",
        "IPv4 canonicalization failed");
	const auto padded_port = canonicalize_external_url("HTTPS://EXAMPLE.COM:00443/path");
	require(padded_port.accepted && padded_port.value == "https://example.com/path",
		"equivalent decimal default port did not canonicalize");
	const auto encoded_reserved = canonicalize_external_url(
		"https://example.com/a%2fb?redirect=http%3a%2f%2flocalhost%3a1455%2fauth%2fcallback");
	require(encoded_reserved.accepted
		&& encoded_reserved.value == "https://example.com/a%2Fb?redirect=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback",
		"reserved percent encoding identity drifted");
	std::string unicode_full_stop = "https://example";
	unicode_full_stop.append("\xE3\x80\x82", 3);
	unicode_full_stop += "com/";
	std::string cyrillic_confusable = "https://";
	cyrillic_confusable.append("\xD1\x80", 2);
	cyrillic_confusable += "aypal.example/";
	std::string embedded_nul = "https://example.com/";
	embedded_nul.push_back('\0');
	embedded_nul += "suffix";
	std::string oversized = "https://example.com/";
	oversized.append(kBrowserExternalMaximumUrlBytes, 'a');
	std::string overlong_utf8 = "https://example.com/";
	overlong_utf8.append("\xC0\xAF", 2);
    const std::vector<std::string> rejected = {
        "", "ftp://example.com/", "https://user@example.com/", "https://example.com:/",
        "https://999.1.1.1/", "https://[2001:::1]/", "https://2001:db8::1/",
        "https://example.com/%", "https://example.com/%0d", "https://example.com\\x",
		"https://example.com./", "https://.example.com/", "https://example..com/",
		"https://-example.com/", "https://example-.com/", "https://exa_mple.com/",
		"https://127.1/", "https://0177.0.0.1/", "https://0x7f.0.0.1/",
		"https://2130706433/", "https://example%2Ecom/", "https://%65xample.com/",
		"https://[fe80::1%25eth0]/", "https://[::1]suffix/", "https://[::1]:0/",
		"https://[::1]:65536/", "https://example.com:+443/", "https://example.com: 443/",
		"https://example.com/%E3%80%82", "https://example.com/%7f",
		"https://example.com/\tpath", " https://example.com/", "https://example.com/ ",
		unicode_full_stop, cyrillic_confusable, embedded_nul, oversized, overlong_utf8
    };
    for (const auto& value : rejected)
        require(!canonicalize_external_url(value).accepted, "malformed URL was admitted");
}

void test_preview_fail_closed_paths()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	reset_browser_operation_fixture();
	require(!open_url_external("https://example.com/preview-default"),
		"preview default browser adapter fabricated a synchronous open");
	std::atomic<unsigned> completion{0};
	browser_open_result_t result = browser_open_result_t::opened;
	const auto submitted = submit_open_url_external("https://example.com/preview-default",
		[&](const browser_open_completion_t& value) {
			result = value.result;
			completion.fetch_add(1, std::memory_order_acq_rel);
		});
	require(submitted.submitted, "preview fail-closed operation did not retain async task identity");
	aida::infra::executor::wait_for(submitted.task_id, 5000);
	wait_terminal(completion, 1);
	require(result == browser_open_result_t::ensure_ready_failed,
		"preview default browser adapter did not publish typed unavailability");
	require(browser_physical_in_flight() == 0,
		"preview fail-closed browser operation retained capacity");

	auto codex_state = std::make_shared<codex::codex_login_state_t>();
	auto claude_state = std::make_shared<claude_code::claude_code_login_state_t>();
	copilot::copilot_login_state_t copilot_state;
	require(!codex::start_login(*codex_state), "preview Codex fabricated login startup");
	require(!copilot::start_login(copilot_state, std::optional<std::string>{}),
		"preview Copilot fabricated login startup");
	require(!claude_code::start_login(*claude_state),
		"preview Claude fabricated login startup");
	const auto codex_value = codex::snapshot(*codex_state);
	const auto copilot_value = copilot::snapshot(copilot_state);
	const auto claude_value = claude_code::snapshot(*claude_state);
	require(codex_value.done && codex_value.terminal_phase == 2
		&& codex_value.auth_url.empty() && codex_value.received_code.empty(),
		"preview Codex failure was not typed and secret-free");
	require(copilot_value.done && copilot_value.terminal_phase == 2
		&& copilot_value.device_code.empty() && copilot_value.user_code.empty(),
		"preview Copilot failure was not typed and secret-free");
	require(claude_value.done && claude_value.terminal_phase == 2
		&& claude_value.auth_url.empty() && claude_value.received_code.empty(),
		"preview Claude failure was not typed and secret-free");
	auth_info_t info;
	info.kind = auth_kind_t::api;
	info.api_key = "fixture-secret";
	std::atomic<unsigned> commit_guard_calls{0};
	require(!store::set_if("fixture-provider", info, [&]() {
		commit_guard_calls.fetch_add(1, std::memory_order_acq_rel);
		return true;
	}), "preview auth store fabricated a durable credential write");
	require(commit_guard_calls.load(std::memory_order_acquire) == 0,
		"preview auth store invoked a commit guard without a durable backend");
	std::vector<std::pair<std::string, auth_info_t>> stored;
	require(!store::all(stored) && stored.empty(),
		"preview auth store fabricated a credential snapshot");
#endif
}

void test_provider_model_response_semantics()
{
	const auto openai = aida::provider::catalog::validate_provider_model_list_response(
		"openai", R"({"data":[{"id":"gpt-fixture"}]})");
	require(openai.valid && openai.model_count == 1 && openai.error.empty(),
		"OpenAI-compatible model-list semantics rejected a valid response");
	const auto google = aida::provider::catalog::validate_provider_model_list_response(
		"google", R"({"models":[{"name":"models/gemini-fixture"}]})");
	require(google.valid && google.model_count == 1 && google.error.empty(),
		"Google model-list semantics rejected a valid response");
	for (const auto& fixture : std::vector<std::pair<std::string, std::string>>{
		{"openai", "{}"},
		{"openai", R"({"data":[]})"},
		{"openai", R"({"error":{"message":"denied"},"data":[{"id":"x"}]})"},
		{"openai", R"({"data":[{"id":""}]})"},
		{"google", R"({"models":[{"id":"wrong-field"}]})"},
		{"openai", "{"}}) {
		const auto rejected = aida::provider::catalog::validate_provider_model_list_response(
			fixture.first, fixture.second);
		require(!rejected.valid && rejected.model_count == 0 && !rejected.error.empty(),
			"malformed or empty provider model response was admitted");
	}
}

void test_allocation_submission_and_fault_terminals()
{
    auto fake = std::make_shared<fake_browser_t>();
    install_browser_operation_fixture(adapter_for(fake));
    std::atomic<unsigned> completions{0};
	unsigned expected_completions = 0;
    inject_browser_fixture_failure(1);
    auto allocation = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
        require(value.result == browser_open_result_t::queue_rejected, "allocation failure type drifted");
        completions.fetch_add(1, std::memory_order_acq_rel);
    });
    require(!allocation.submitted && allocation.reject_reason == "browser_state_allocation_failed",
        "allocation rejection contract failed");
    wait_terminal(completions, ++expected_completions);
    require(browser_physical_in_flight() == 0, "allocation rejection retained physical capacity");

    inject_browser_fixture_failure(2);
    auto submission = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
        require(value.result == browser_open_result_t::queue_rejected, "submission failure type drifted");
        completions.fetch_add(1, std::memory_order_acq_rel);
    });
    require(!submission.submitted && submission.reject_reason == "executor_submission_exception",
        "submission exception contract failed");
    wait_terminal(completions, ++expected_completions);
    require(browser_physical_in_flight() == 0, "submission exception retained physical capacity");

    fake->throw_log = true;
    auto log_failure = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t&) {
        completions.fetch_add(1, std::memory_order_acq_rel);
        throw std::runtime_error("fixture_callback_exception");
    });
    require(log_failure.submitted, "throwing logger caused submission rejection");
    aida::infra::executor::wait_for(log_failure.task_id, 5000);
    wait_terminal(completions, ++expected_completions);
    require(browser_physical_in_flight() == 0, "throwing callback retained physical capacity");

	fake->throw_log = false;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    fake->seh_log = true;
    auto seh_callback = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t&) {
        completions.fetch_add(1, std::memory_order_acq_rel);
        RaiseException(0xE1234003u, 0, 0, nullptr);
    });
    require(seh_callback.submitted, "SEH logger caused submission rejection");
    aida::infra::executor::wait_for(seh_callback.task_id, 5000);
    wait_terminal(completions, ++expected_completions);
    require(browser_physical_in_flight() == 0, "SEH callback retained physical capacity");

    fake->seh_log = false;
#endif
    fake->throw_ready = true;
    browser_open_result_t observed = browser_open_result_t::opened;
    auto ready_exception = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
        observed = value.result;
        completions.fetch_add(1, std::memory_order_acq_rel);
    });
    aida::infra::executor::wait_for(ready_exception.task_id, 5000);
	wait_terminal(completions, ++expected_completions);
	require(observed == browser_open_result_t::exception, "operation exception was not typed");
	require(browser_physical_in_flight() == 0, "operation exception retained physical capacity");

	fake->throw_ready = false;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	fake->seh_ready = true;
	observed = browser_open_result_t::opened;
	auto ready_seh = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
		observed = value.result;
		completions.fetch_add(1, std::memory_order_acq_rel);
	});
	aida::infra::executor::wait_for(ready_seh.task_id, 5000);
	wait_terminal(completions, ++expected_completions);
	require(observed == browser_open_result_t::exception, "operation SEH was not typed");
	require(browser_physical_in_flight() == 0, "operation SEH retained physical capacity");

	fake->seh_ready = false;
#endif
	fake->navigate_result = false;
	observed = browser_open_result_t::opened;
	auto navigation_failure = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
		observed = value.result;
		completions.fetch_add(1, std::memory_order_acq_rel);
	});
	aida::infra::executor::wait_for(navigation_failure.task_id, 5000);
	wait_terminal(completions, ++expected_completions);
	require(observed == browser_open_result_t::navigate_failed,
		"navigation failure was not typed");
	require(browser_physical_in_flight() == 0,
		"navigation failure retained physical capacity");
}

void test_global_cap_cancellation_deadline_and_generation()
{
    auto fake = std::make_shared<fake_browser_t>();
    fake->block_ready = true;
    install_browser_operation_fixture(adapter_for(fake));
    std::atomic<unsigned> completions{0};
    std::vector<browser_open_submission_t> submissions;
    for (std::uint32_t i = 0; i < kBrowserExternalMaximumInFlight; ++i) {
        submissions.push_back(submit_open_url_external("https://example.com/cap/" + std::to_string(i),
            [&](const browser_open_completion_t&) { completions.fetch_add(1, std::memory_order_acq_rel); }));
        require(submissions.back().submitted, "capacity fixture could not fill an advertised slot");
		require(submissions.back().task_id != 0, "accepted browser operation lacked task identity");
		for (std::size_t previous = 0; previous + 1 < submissions.size(); ++previous)
			require(submissions[previous].task_id != submissions.back().task_id,
				"browser dispatcher reused a live task identity");
    }
    fake->wait_entered(kBrowserExternalMaximumInFlight);
    require(browser_physical_in_flight() == kBrowserExternalMaximumInFlight,
        "physical operation count did not reach exact cap");
    require(!open_url_external("https://example.com/synchronous-contention"),
        "synchronous provider bypassed global browser cap");
    auto overflow = submit_open_url_external("https://example.com/overflow");
    require(!overflow.submitted && overflow.reject_reason == "browser_capacity_exhausted",
        "asynchronous provider bypassed global browser cap");
    cancel_open_url_external(submissions.front().task_id);
	cancel_open_url_external(submissions.front().task_id);
    wait_terminal(completions, 1);
    require(browser_physical_in_flight() == kBrowserExternalMaximumInFlight,
        "running cancellation released physical capacity before operation return");
    for (std::size_t i = 1; i < submissions.size(); ++i)
        cancel_open_url_external(submissions[i].task_id);
    fake->release();
    for (const auto& submission : submissions)
        aida::infra::executor::wait_for(submission.task_id, 5000);
    wait_terminal(completions, static_cast<unsigned>(submissions.size()));
    require(browser_physical_in_flight() == 0, "cancelled operations did not return all capacity");
    require(fake->max_active <= kBrowserExternalMaximumInFlight, "underlying fake exceeded physical cap");

    auto deadline_fake = std::make_shared<fake_browser_t>();
    deadline_fake->block_ready = true;
    install_browser_operation_fixture(adapter_for(deadline_fake));
    std::atomic<unsigned> deadline_completion{0};
    browser_open_result_t deadline_result = browser_open_result_t::opened;
    const std::uint64_t deadline = aida::infra::executor::now_ms() + 25;
    auto expiring = submit_open_url_external_until("https://example.com/deadline", deadline,
        [&](const browser_open_completion_t& value) {
            deadline_result = value.result;
            deadline_completion.fetch_add(1, std::memory_order_acq_rel);
        });
    deadline_fake->wait_entered(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(35));
    aida::infra::executor::check_deadlines();
    wait_terminal(deadline_completion, 1);
    require(deadline_result == browser_open_result_t::deadline_expired,
        "deadline cancellation did not publish typed timeout");
    require(browser_physical_in_flight() == 1,
        "deadline publication released physical slot while operation was running");
    deadline_fake->release();
    aida::infra::executor::wait_for(expiring.task_id, 5000);
    require(browser_physical_in_flight() == 0, "deadline operation did not return physical slot");

    auto generation_fake = std::make_shared<fake_browser_t>();
    generation_fake->block_ready = true;
    install_browser_operation_fixture(adapter_for(generation_fake));
	std::mutex generation_mutex;
	std::uint64_t generation = 1;
	auto first_state = std::make_shared<codex::codex_login_state_t>();
	std::shared_ptr<codex::codex_login_state_t> current_state = first_state;
    std::atomic<int> committed{0};
	std::atomic<unsigned> generation_completions{0};
    auto stale = submit_open_url_external("https://example.com/generation/one",
		[&, first_state](const browser_open_completion_t&) {
			std::lock_guard<std::mutex> lock(generation_mutex);
			if (generation == 1 && current_state == first_state)
                committed.store(1, std::memory_order_release);
			generation_completions.fetch_add(1, std::memory_order_acq_rel);
        });
    generation_fake->wait_entered(1);
	{
		std::lock_guard<std::mutex> lock(generation_mutex);
		generation = 2;
		current_state = std::make_shared<codex::codex_login_state_t>();
	}
    cancel_open_url_external(stale.task_id);
	cancel_open_url_external(stale.task_id);
    generation_fake->release();
    aida::infra::executor::wait_for(stale.task_id, 5000);
	wait_terminal(generation_completions, 1);
    require(committed.load(std::memory_order_acquire) == 0,
		"late completion mutated replacement state generation");
}

void test_provider_snapshot_races()
{
    copilot::copilot_login_state_t copilot_state;
    codex::codex_login_state_t codex_state;
    claude_code::claude_code_login_state_t claude_state;
    std::atomic<bool> stop{false};
    std::thread writer([&]() {
        for (std::uint64_t i = 1; i <= 2000; ++i) {
            {
                std::lock_guard<std::mutex> lock(copilot_state.mutex);
                copilot_state.user_code = std::to_string(i);
                copilot_state.verification_uri = "https://example.com/" + std::to_string(i);
                copilot_state.last_poll_unix = static_cast<std::int64_t>(i);
                copilot_state.next_poll_unix = static_cast<std::int64_t>(i + 1);
            }
            {
                std::lock_guard<std::mutex> lock(codex_state.mutex);
                codex_state.auth_url = "https://example.com/" + std::to_string(i);
                codex_state.received_code = std::to_string(i);
                codex_state.started_unix = static_cast<std::int64_t>(i);
            }
            {
                std::lock_guard<std::mutex> lock(claude_state.mutex);
                claude_state.auth_url = "https://example.com/" + std::to_string(i);
                claude_state.received_code = std::to_string(i);
                claude_state.started_unix = static_cast<std::int64_t>(i);
            }
        }
        stop.store(true, std::memory_order_release);
    });
    while (!stop.load(std::memory_order_acquire)) {
        const auto copilot_value = copilot::snapshot(copilot_state);
        if (!copilot_value.user_code.empty()) {
            require(copilot_value.verification_uri == "https://example.com/" + copilot_value.user_code,
                "Copilot snapshot exposed a torn string generation");
            require(copilot_value.next_poll_unix == copilot_value.last_poll_unix + 1,
                "Copilot snapshot exposed torn poll timing");
        }
        const auto codex_value = codex::snapshot(codex_state);
        if (!codex_value.received_code.empty())
            require(codex_value.auth_url == "https://example.com/" + codex_value.received_code,
                "Codex snapshot exposed a torn callback generation");
        const auto claude_value = claude_code::snapshot(claude_state);
        if (!claude_value.received_code.empty())
            require(claude_value.auth_url == "https://example.com/" + claude_value.received_code,
                "Claude snapshot exposed a torn callback generation");
    }
	writer.join();
}

void test_provider_terminal_claims_and_owned_errors()
{
	{
		codex::codex_login_state_t state;
		std::atomic<unsigned> claimed{0};
		std::vector<std::thread> contenders;
		for (unsigned index = 0; index < 32; ++index)
			contenders.emplace_back([&]() { if (codex::cancel_login(state)) claimed.fetch_add(1); });
		for (auto& contender : contenders) contender.join();
		const auto value = codex::snapshot(state);
		require(claimed.load() == 1 && value.done && value.cancelled && value.terminal_phase == 3,
			"Codex terminal cancellation was not claimed exactly once");
	}
	{
		copilot::copilot_login_state_t state;
		std::atomic<unsigned> claimed{0};
		std::vector<std::thread> contenders;
		for (unsigned index = 0; index < 32; ++index)
			contenders.emplace_back([&]() { if (copilot::cancel_login(state)) claimed.fetch_add(1); });
		for (auto& contender : contenders) contender.join();
		const auto value = copilot::snapshot(state);
		require(claimed.load() == 1 && value.done && value.cancelled && value.terminal_phase == 3,
			"Copilot terminal cancellation was not claimed exactly once");
	}
	{
		claude_code::claude_code_login_state_t state;
		std::atomic<unsigned> claimed{0};
		std::vector<std::thread> contenders;
		for (unsigned index = 0; index < 32; ++index)
			contenders.emplace_back([&]() { if (claude_code::cancel_login(state)) claimed.fetch_add(1); });
		for (auto& contender : contenders) contender.join();
		const auto value = claude_code::snapshot(state);
		require(claimed.load() == 1 && value.done && value.cancelled && value.terminal_phase == 3,
			"Claude terminal cancellation was not claimed exactly once");
	}
	{
		codex::codex_login_state_t state;
		state.terminal_phase.store(4, std::memory_order_release);
		require(codex::request_cancel(state),
			"Codex exchange-phase cancellation was not synchronously claimed");
		require(!codex::request_cancel(state)
			&& codex::snapshot(state).terminal_phase == 3,
			"Codex exchange-phase cancellation was not terminal and exactly once");
		codex::codex_login_state_t committed;
		committed.terminal_phase.store(1, std::memory_order_release);
		require(!codex::request_cancel(committed),
			"Codex cancellation overwrote a committed credential terminal");
		codex::codex_login_state_t callback_ready;
		callback_ready.terminal_phase.store(5, std::memory_order_release);
		require(codex::request_cancel(callback_ready)
			&& codex::snapshot(callback_ready).terminal_phase == 3,
			"Codex callback-ready cancellation was not synchronously claimed");
	}
	{
		copilot::copilot_login_state_t state;
		state.terminal_phase.store(4, std::memory_order_release);
		require(copilot::request_cancel(state),
			"Copilot exchange-phase cancellation was not synchronously claimed");
		require(!copilot::request_cancel(state)
			&& copilot::snapshot(state).terminal_phase == 3,
			"Copilot exchange-phase cancellation was not terminal and exactly once");
		copilot::copilot_login_state_t committed;
		committed.terminal_phase.store(1, std::memory_order_release);
		require(!copilot::request_cancel(committed),
			"Copilot cancellation overwrote a committed credential terminal");
	}
	{
		claude_code::claude_code_login_state_t state;
		state.terminal_phase.store(4, std::memory_order_release);
		require(claude_code::request_cancel(state),
			"Claude exchange-phase cancellation was not synchronously claimed");
		require(!claude_code::request_cancel(state)
			&& claude_code::snapshot(state).terminal_phase == 3,
			"Claude exchange-phase cancellation was not terminal and exactly once");
		claude_code::claude_code_login_state_t committed;
		committed.terminal_phase.store(1, std::memory_order_release);
		require(!claude_code::request_cancel(committed),
			"Claude cancellation overwrote a committed credential terminal");
		claude_code::claude_code_login_state_t callback_ready;
		callback_ready.terminal_phase.store(5, std::memory_order_release);
		require(claude_code::request_cancel(callback_ready)
			&& claude_code::snapshot(callback_ready).terminal_phase == 3,
			"Claude callback-ready cancellation was not synchronously claimed");
	}
	std::string codex_error = codex::last_error();
	std::string copilot_error = copilot::last_error();
	std::string claude_error = claude_code::last_error();
	std::string store_error = store::last_error();
	codex_error.push_back('x');
	copilot_error.push_back('x');
	claude_error.push_back('x');
	store_error.push_back('x');
	require(codex_error != codex::last_error() || codex_error == "x",
		"Codex error getter exposed mutable shared storage");
	require(copilot_error != copilot::last_error() || copilot_error == "x",
		"Copilot error getter exposed mutable shared storage");
	require(claude_error != claude_code::last_error() || claude_error == "x",
		"Claude error getter exposed mutable shared storage");
	require(store_error != store::last_error() || store_error == "x",
		"store error getter exposed mutable shared storage");
}

void test_real_provider_listener_routing()
{
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto fake = std::make_shared<fake_browser_t>();
	install_browser_operation_fixture(adapter_for(fake));
	auto codex_state = std::make_shared<codex::codex_login_state_t>();
	const std::uint64_t codex_deadline = aida::infra::executor::now_ms() + 10000;
	require(codex::start_login(*codex_state, codex_deadline),
		"Codex real listener fixture failed to start");
	require(send_loopback_request(codex::CODEX_OAUTH_PORT,
		"POST /auth/callback?error=x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 405,
		"Codex listener admitted a non-GET callback method");
	require(send_loopback_request(codex::CODEX_OAUTH_PORT,
		"GET /oauth/auth/callback?error=x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 404,
		"Codex listener admitted a suffix-matched callback path");
	require(send_loopback_request(codex::CODEX_OAUTH_PORT,
		"GET /auth/callback/extra?error=x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 404,
		"Codex listener admitted a callback path extension");
	require(send_loopback_request(codex::CODEX_OAUTH_PORT,
		"GET /auth/callback HTTP/2.0\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 400,
		"Codex listener admitted an unsupported request-line version");
	require(send_loopback_request(codex::CODEX_OAUTH_PORT,
		"GET /auth/callback?code=x&state=%GG HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 400,
		"Codex listener admitted malformed callback percent encoding");
	require(send_loopback_request(codex::CODEX_OAUTH_PORT,
		"GET /auth/callback?code=x&state=a&state=b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 400,
		"Codex listener admitted duplicate callback security fields");
	require(send_loopback_request(codex::CODEX_OAUTH_PORT,
		"GET /auth/callback?code=x&state=%00 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 400,
		"Codex listener admitted a callback control byte");
	require(send_loopback_request(codex::CODEX_OAUTH_PORT,
		"GET /auth/callback?error=access_denied&error_description=fixture HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 200,
		"Codex listener rejected its exact callback route");
	wait_provider_terminal(*codex_state);
	const auto codex_value = codex::snapshot(*codex_state);
	require(codex_value.terminal_phase == 2 && !codex_value.error.empty()
		&& codex_value.received_code.empty(),
		"Codex callback error did not publish one typed terminal state");
	static_cast<void>(codex::cancel_login(*codex_state));

	auto claude_state = std::make_shared<claude_code::claude_code_login_state_t>();
	const std::uint64_t claude_deadline = aida::infra::executor::now_ms() + 10000;
	require(claude_code::start_login(*claude_state, claude_deadline),
		"Claude real listener fixture failed to start");
	const int claude_port = claude_code::snapshot(*claude_state).port;
	require(claude_port > 0, "Claude real listener did not publish its bound port");
	require(send_loopback_request(claude_port,
		"POST /callback?error=x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 405,
		"Claude listener admitted a non-GET callback method");
	require(send_loopback_request(claude_port,
		"GET /callback/extra?error=x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 404,
		"Claude listener admitted a callback path extension");
	require(send_loopback_request(claude_port,
		"GET /callback?code=x&state=%GG HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 400,
		"Claude listener admitted malformed callback percent encoding");
	require(send_loopback_request(claude_port,
		"GET /callback?code=x&state=a&state=b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 400,
		"Claude listener admitted duplicate callback security fields");
	require(send_loopback_request(claude_port,
		"GET /callback HTTP/2.0\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 400,
		"Claude listener admitted an unsupported request-line version");
	require(send_loopback_request(claude_port,
		"GET /callback?error=access_denied&error_description=fixture HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") == 200,
		"Claude listener rejected its canonical callback route");
	wait_provider_terminal(*claude_state);
	const auto claude_value = claude_code::snapshot(*claude_state);
	require(claude_value.terminal_phase == 2 && !claude_value.error.empty()
		&& claude_value.received_code.empty(),
		"Claude callback error did not publish one typed terminal state");
	static_cast<void>(claude_code::cancel_login(*claude_state));
#endif
}

void test_listener_state_raii_and_cancel_pending()
{
	auto codex_state = std::make_shared<codex::codex_login_state_t>();
	auto claude_state = std::make_shared<claude_code::claude_code_login_state_t>();
	require(codex_state->shared_from_this().get() == codex_state.get(),
		"Codex listener state did not retain shared ownership identity");
	require(claude_state->shared_from_this().get() == claude_state.get(),
		"Claude listener state did not retain shared ownership identity");

	auto codex_resource = std::make_shared<int>(1);
	auto claude_resource = std::make_shared<int>(2);
	std::weak_ptr<int> codex_resource_weak = codex_resource;
	std::weak_ptr<int> claude_resource_weak = claude_resource;
	{
		std::lock_guard<std::mutex> lock(codex_state->mutex);
		codex_state->listener_handle = codex_resource;
	}
	{
		std::lock_guard<std::mutex> lock(claude_state->mutex);
		claude_state->listener_handle = claude_resource;
	}
	codex_resource.reset();
	claude_resource.reset();
	require(codex::snapshot(*codex_state).listener_active,
		"Codex listener snapshot lost owned resource");
	require(claude_code::snapshot(*claude_state).listener_active,
		"Claude listener snapshot lost owned resource");
	{
		std::lock_guard<std::mutex> lock(codex_state->mutex);
		codex_state->listener_handle.reset();
	}
	{
		std::lock_guard<std::mutex> lock(claude_state->mutex);
		claude_state->listener_handle.reset();
	}
	require(codex_resource_weak.expired(), "Codex listener resource ownership did not release");
	require(claude_resource_weak.expired(), "Claude listener resource ownership did not release");

	struct listener_fixture_t {
		std::mutex mutex;
		std::condition_variable cv;
		bool entered = false;
		bool stop = false;
		std::atomic<bool> terminal{false};
		std::atomic<unsigned> cancel_hooks{0};
	};
	auto listener = std::make_shared<listener_fixture_t>();
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "auth_provider";
	sub.label = "auth.c03.listener_cancel_pending";
	sub.thread_class = "service_loop";
	sub.domain = aida::infra::executor::domain_t::security_liveness;
	sub.priority = 1;
	sub.shutdown_policy = "cancel_pending";
	sub.cancel_hook = [listener]() noexcept {
		listener->cancel_hooks.fetch_add(1, std::memory_order_acq_rel);
		std::lock_guard<std::mutex> lock(listener->mutex);
		listener->stop = true;
		listener->cv.notify_all();
	};
	sub.body = [listener]() noexcept {
		try {
			std::unique_lock<std::mutex> lock(listener->mutex);
			listener->entered = true;
			listener->cv.notify_all();
			listener->cv.wait(lock, [&]() { return listener->stop; });
		} catch (...) {
		}
		listener->terminal.store(true, std::memory_order_release);
	};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	require(submitted.submitted, "listener cancellation fixture submission was rejected");
	{
		std::unique_lock<std::mutex> lock(listener->mutex);
		require(listener->cv.wait_for(lock, std::chrono::seconds(5),
			[&]() { return listener->entered; }), "listener fixture did not start");
	}
	require(aida::infra::executor::cancel(submitted.task_id),
		"listener cancel-pending request was rejected");
	const auto waited = aida::infra::executor::wait_for(submitted.task_id, 5000);
	require(waited.cancelled, "listener cancel-pending task did not reach cancelled terminal state");
	require(listener->terminal.load(std::memory_order_acquire),
		"listener cancel-pending task skipped terminal publication");
	require(listener->cancel_hooks.load(std::memory_order_acquire) == 1,
		"listener cancel hook did not execute exactly once");
}

void test_http_framing_completeness_and_limits()
{
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	{
		loopback_http_server_t server(
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
		const auto response = http::get(loopback_http_url(server.port()), {}, 5);
		server.finish();
		require(server.connections() >= 1 && !server.failed(),
			"complete HTTP response fixture did not serve a request cleanly");
		require(response.ok && response.complete && !response.truncated
			&& response.status == 200 && response.body == "ok",
			"complete Content-Length response did not publish complete success");
	}
	{
		loopback_http_server_t server(
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
			"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
		std::string body;
		const auto response = http::stream("GET", loopback_http_url(server.port()), {},
			{}, {}, 5, [&](const char* data, std::size_t size) {
				body.append(data, size);
				return true;
			});
		server.finish();
		require(server.connections() == 1 && !server.failed(),
			"complete chunked stream fixture did not serve exactly one request");
		require(response.ok && response.complete && !response.truncated
			&& response.status == 200 && body == "Wikipedia",
			"complete chunked stream did not publish complete success");
	}
	for (const auto& raw : std::vector<std::string>{
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWiki\r\n0\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabc",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nextra"}) {
		loopback_http_server_t server(raw);
		std::string body;
		const auto response = http::stream("GET", loopback_http_url(server.port()), {},
			{}, {}, 5, [&](const char* data, std::size_t size) {
				body.append(data, size);
				return true;
			});
		server.finish();
		require(server.connections() == 1,
			"malformed HTTP stream fixture did not reach the production transport");
		require(!response.ok && !response.complete && !response.error.empty(),
			"malformed or incomplete HTTP framing was admitted as complete");
	}
	{
		loopback_http_server_t server(
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n800001\r\n");
		const auto response = http::stream("GET", loopback_http_url(server.port()), {},
			{}, {}, 5, [](const char*, std::size_t) { return true; });
		server.finish();
		require(!response.ok && !response.complete && response.truncated,
			"oversized chunk framing did not publish explicit truncation");
	}
	{
		std::string body((8u * 1024u * 1024u) + 1u, 'x');
		std::string raw = "HTTP/1.1 200 OK\r\nContent-Length: "
			+ std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
		raw += body;
		loopback_http_server_t server(std::move(raw));
		const auto response = http::get(loopback_http_url(server.port()), {}, 10);
		server.finish();
		require(server.connections() >= 1,
			"oversized HTTP response fixture did not reach the production transport");
		require(!response.ok && !response.complete && response.truncated,
			"oversized full HTTP response did not preserve explicit truncation");
	}
	const auto invalid_url = http::get("https://user@example.com/", {}, 1);
	require(!invalid_url.ok && !invalid_url.complete && invalid_url.status == 0,
		"credential-bearing HTTP authority was admitted");
	const auto forbidden_header = http::request("GET", "http://127.0.0.1:1/", {
		{"Host", "attacker.invalid"}}, {}, {}, 1);
	require(!forbidden_header.ok && !forbidden_header.complete
		&& forbidden_header.status == 0 && !forbidden_header.error.empty(),
		"caller-controlled HTTP framing header was admitted");
	{
		loopback_http_server_t server(
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
			std::chrono::seconds(2));
		std::atomic<bool> cancelled{false};
		std::thread cancel_thread([&]() {
			const auto limit = std::chrono::steady_clock::now() + std::chrono::seconds(1);
			while (server.connections() == 0 && std::chrono::steady_clock::now() < limit)
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			cancelled.store(true, std::memory_order_release);
		});
		const auto started = std::chrono::steady_clock::now();
		const auto response = http::get(loopback_http_url(server.port()), {}, 5,
			[&]() { return cancelled.load(std::memory_order_acquire); });
		const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - started);
		cancel_thread.join();
		server.finish();
		require(server.connections() == 1,
			"cancellable HTTP fixture did not reach the production transport");
		require(response.cancelled && !response.ok && !response.complete
			&& !response.truncated && elapsed < std::chrono::milliseconds(500),
			"HTTP transport cancellation was not typed and bounded");
	}
	{
		bool delivered = false;
		const auto response = http::stream("GET", "http://127.0.0.1:1/", {}, {}, {}, 5,
			[&](const char*, std::size_t) { delivered = true; return true; },
			[]() { return true; });
		require(response.cancelled && !response.ok && !response.complete
			&& !response.truncated && !delivered,
			"pre-cancelled HTTP stream entered transport or delivery");
	}
#endif
}

void test_shutdown_cancel_pending()
{
    auto fake = std::make_shared<fake_browser_t>();
    fake->block_ready = true;
    install_browser_operation_fixture(adapter_for(fake));
    std::atomic<unsigned> completion{0};
    browser_open_result_t result = browser_open_result_t::opened;
    auto pending = submit_open_url_external("https://example.com/shutdown",
        [&](const browser_open_completion_t& value) {
            result = value.result;
            completion.fetch_add(1, std::memory_order_acq_rel);
        });
    fake->wait_entered(1);
	std::atomic<bool> shutdown_probe_done{false};
	std::atomic<bool> worker_shutdown_result{true};
	aida::infra::executor::submission_t shutdown_probe;
	shutdown_probe.owner_subsystem = "auth_browser";
	shutdown_probe.label = "auth.c03.worker_shutdown_retry";
	shutdown_probe.thread_class = "worker_shutdown_probe";
	shutdown_probe.domain = aida::infra::executor::domain_t::general;
	shutdown_probe.shutdown_policy = "drain";
	shutdown_probe.body = [&]() {
		worker_shutdown_result.store(aida::infra::taskflow_runtime::shutdown(1),
			std::memory_order_release);
		shutdown_probe_done.store(true, std::memory_order_release);
	};
	const auto shutdown_submitted = aida::infra::executor::submit(std::move(shutdown_probe));
	require(shutdown_submitted.submitted, "worker-origin shutdown probe submission was rejected");
	const auto shutdown_probe_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (!shutdown_probe_done.load(std::memory_order_acquire)
		&& std::chrono::steady_clock::now() < shutdown_probe_deadline) std::this_thread::yield();
	require(shutdown_probe_done.load(std::memory_order_acquire),
		"worker-origin shutdown did not return within its bounded timeout");
	require(!worker_shutdown_result.load(std::memory_order_acquire),
		"worker-origin shutdown falsely reported complete");
    wait_terminal(completion, 1);
    require(result == browser_open_result_t::cancelled,
        "cancel-pending shutdown did not publish cancellation");
    require(browser_physical_in_flight() == 1,
        "shutdown cancellation released a running physical slot early");
    fake->release();
	aida::infra::executor::wait_for(pending.task_id, 5000);
	aida::infra::executor::wait_for(shutdown_submitted.task_id, 5000);
	require(aida::infra::executor::shutdown(),
		"non-worker shutdown retry did not complete after physical work returned");
    require(browser_physical_in_flight() == 0, "shutdown did not return physical capacity");
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::infra::taskflow_runtime::initialize();
	aida::infra::taskflow_runtime::task_descriptor_t runtime_probe;
	runtime_probe.owner_subsystem = "auth_browser";
	runtime_probe.label = "auth.c03.post_shutdown_runtime_probe";
	runtime_probe.body = []() {};
	const auto runtime_rejected = aida::infra::taskflow_runtime::submit(std::move(runtime_probe));
	require(!runtime_rejected.submitted,
		"preview runtime reopened after completed shutdown");
#endif
    std::atomic<unsigned> rejected_completion{0};
    auto rejected = submit_open_url_external("https://example.com/after-shutdown",
        [&](const browser_open_completion_t& value) {
            require(value.result == browser_open_result_t::queue_rejected,
                "post-shutdown rejection type drifted");
            rejected_completion.fetch_add(1, std::memory_order_acq_rel);
        });
    require(!rejected.submitted, "executor accepted work after atomic shutdown gate");
    wait_terminal(rejected_completion, 1);
    require(browser_physical_in_flight() == 0, "post-shutdown rejection leaked capacity");
}

void test_refresh_cancellation_scope()
{
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const http::cancel_cb_t cancelled = []() noexcept { return true; };
    require(!codex::refresh_token(cancelled, 1) &&
        codex::last_error().find("cancel") != std::string::npos,
        "Codex refresh ignored the pre-cancelled operation scope");
    require(!copilot::refresh_token(cancelled, 1) &&
        copilot::last_error().find("cancel") != std::string::npos,
        "Copilot refresh ignored the pre-cancelled operation scope");
    require(!claude_code::refresh_token(cancelled, 1) &&
        claude_code::last_error().find("cancel") != std::string::npos,
        "Claude refresh ignored the pre-cancelled operation scope");
#endif
}

}

bool run_auth_browser_dispatch_harness(std::string& failure)
{
    try {
        test_canonical_urls();
		test_preview_fail_closed_paths();
		test_provider_model_response_semantics();
        test_allocation_submission_and_fault_terminals();
		test_global_cap_cancellation_deadline_and_generation();
		test_provider_snapshot_races();
		test_provider_terminal_claims_and_owned_errors();
		test_real_provider_listener_routing();
		test_listener_state_raii_and_cancel_pending();
		test_http_framing_completeness_and_limits();
		test_refresh_cancellation_scope();
		test_shutdown_cancel_pending();
        reset_browser_operation_fixture();
        failure.clear();
        return true;
    } catch (const std::exception& ex) {
        failure = ex.what();
    } catch (...) {
        failure = "unknown auth browser dispatch harness failure";
    }
    reset_browser_operation_fixture();
    return false;
}

}

int main()
{
    std::string failure;
    if (!aida::auth::c03_test::run_auth_browser_dispatch_harness(failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    return 0;
}
