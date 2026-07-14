#define AIDA_C03_AUTH_BROWSER_FIXTURE 1

#include "auth_browser_dispatch_harness.hpp"
#include "../../../src/core/auth/auth_browser_launch.hpp"
#include "../../../src/core/auth/auth_claude_code.hpp"
#include "../../../src/core/auth/auth_codex.hpp"
#include "../../../src/core/auth/auth_copilot.hpp"

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace aida::auth::c03_test {

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
        if (seh_ready) RaiseException(0xE1234001u, 0, 0, nullptr);
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
        if (seh_log) RaiseException(0xE1234002u, 0, 0, nullptr);
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
    const std::vector<std::string> rejected = {
        "", "ftp://example.com/", "https://user@example.com/", "https://example.com:/",
        "https://999.1.1.1/", "https://[2001:::1]/", "https://2001:db8::1/",
        "https://example.com/%", "https://example.com/%0d", "https://example.com\\x",
        std::string("https://example.com/\xC0\xAF", 22)
    };
    for (const auto& value : rejected)
        require(!canonicalize_external_url(value).accepted, "malformed URL was admitted");
}

void test_allocation_submission_and_fault_terminals()
{
    auto fake = std::make_shared<fake_browser_t>();
    install_browser_operation_fixture(adapter_for(fake));
    std::atomic<unsigned> completions{0};
    inject_browser_fixture_failure(1);
    auto allocation = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
        require(value.result == browser_open_result_t::queue_rejected, "allocation failure type drifted");
        completions.fetch_add(1, std::memory_order_acq_rel);
    });
    require(!allocation.submitted && allocation.reject_reason == "browser_state_allocation_failed",
        "allocation rejection contract failed");
    wait_terminal(completions, 1);
    require(browser_physical_in_flight() == 0, "allocation rejection retained physical capacity");

    inject_browser_fixture_failure(2);
    auto submission = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
        require(value.result == browser_open_result_t::queue_rejected, "submission failure type drifted");
        completions.fetch_add(1, std::memory_order_acq_rel);
    });
    require(!submission.submitted && submission.reject_reason == "executor_submission_exception",
        "submission exception contract failed");
    wait_terminal(completions, 2);
    require(browser_physical_in_flight() == 0, "submission exception retained physical capacity");

    fake->throw_log = true;
    auto log_failure = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t&) {
        completions.fetch_add(1, std::memory_order_acq_rel);
        throw std::runtime_error("fixture_callback_exception");
    });
    require(log_failure.submitted, "throwing logger caused submission rejection");
    aida::infra::executor::wait_for(log_failure.task_id, 5000);
    wait_terminal(completions, 3);
    require(browser_physical_in_flight() == 0, "throwing callback retained physical capacity");

    fake->throw_log = false;
    fake->seh_log = true;
    auto seh_callback = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t&) {
        completions.fetch_add(1, std::memory_order_acq_rel);
        RaiseException(0xE1234003u, 0, 0, nullptr);
    });
    require(seh_callback.submitted, "SEH logger caused submission rejection");
    aida::infra::executor::wait_for(seh_callback.task_id, 5000);
    wait_terminal(completions, 4);
    require(browser_physical_in_flight() == 0, "SEH callback retained physical capacity");

    fake->seh_log = false;
    fake->throw_ready = true;
    browser_open_result_t observed = browser_open_result_t::opened;
    auto ready_exception = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
        observed = value.result;
        completions.fetch_add(1, std::memory_order_acq_rel);
    });
    aida::infra::executor::wait_for(ready_exception.task_id, 5000);
	wait_terminal(completions, 5);
	require(observed == browser_open_result_t::exception, "operation exception was not typed");
	require(browser_physical_in_flight() == 0, "operation exception retained physical capacity");

	fake->throw_ready = false;
	fake->seh_ready = true;
	observed = browser_open_result_t::opened;
	auto ready_seh = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
		observed = value.result;
		completions.fetch_add(1, std::memory_order_acq_rel);
	});
	aida::infra::executor::wait_for(ready_seh.task_id, 5000);
	wait_terminal(completions, 6);
	require(observed == browser_open_result_t::exception, "operation SEH was not typed");
	require(browser_physical_in_flight() == 0, "operation SEH retained physical capacity");

	fake->seh_ready = false;
	fake->navigate_result = false;
	observed = browser_open_result_t::opened;
	auto navigation_failure = submit_open_url_external("https://example.com/", [&](const browser_open_completion_t& value) {
		observed = value.result;
		completions.fetch_add(1, std::memory_order_acq_rel);
	});
	aida::infra::executor::wait_for(navigation_failure.task_id, 5000);
	wait_terminal(completions, 7);
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
    std::atomic<std::uint64_t> generation{1};
    std::atomic<int> committed{0};
    auto stale = submit_open_url_external("https://example.com/generation/one",
        [&](const browser_open_completion_t&) {
            if (generation.load(std::memory_order_acquire) == 1)
                committed.store(1, std::memory_order_release);
        });
    generation_fake->wait_entered(1);
    generation.store(2, std::memory_order_release);
    cancel_open_url_external(stale.task_id);
    generation_fake->release();
    aida::infra::executor::wait_for(stale.task_id, 5000);
    require(committed.load(std::memory_order_acquire) == 0,
        "late completion mutated replacement generation");
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
	require(waited.completed, "listener cancel-pending task did not reach terminal state");
	require(listener->terminal.load(std::memory_order_acquire),
		"listener cancel-pending task skipped terminal publication");
	require(listener->cancel_hooks.load(std::memory_order_acquire) == 1,
		"listener cancel hook did not execute exactly once");
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
    std::thread shutdown_thread([]() { aida::infra::executor::shutdown(); });
    wait_terminal(completion, 1);
    require(result == browser_open_result_t::cancelled,
        "cancel-pending shutdown did not publish cancellation");
    require(browser_physical_in_flight() == 1,
        "shutdown cancellation released a running physical slot early");
    fake->release();
    shutdown_thread.join();
    require(browser_physical_in_flight() == 0, "shutdown did not return physical capacity");
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

}

bool run_auth_browser_dispatch_harness(std::string& failure)
{
    try {
        test_canonical_urls();
        test_allocation_submission_and_fault_terminals();
		test_global_cap_cancellation_deadline_and_generation();
		test_provider_snapshot_races();
		test_listener_state_raii_and_cancel_pending();
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
