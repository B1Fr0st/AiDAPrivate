#include "../../../../src/core/mcp/mcp_client.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using mcp_client::c03_oauth_fixture::credential_t;
using mcp_client::c03_oauth_fixture::event_t;
using mcp_client::c03_oauth_fixture::fault_point_t;
using mcp_client::c03_oauth_fixture::http_reply_t;
using mcp_client::c03_oauth_fixture::http_request_t;
using mcp_client::oauth_state_t;
using mcp_client::oauth_status_t;
using mcp_client::server_config_t;

class fixture_failure_t final : public std::runtime_error
{
public:
    explicit fixture_failure_t(const std::string& message)
        : std::runtime_error(message)
    {
    }
};

void require(bool condition, const std::string& message)
{
    if (!condition)
        throw fixture_failure_t(message);
}

void require_contains(const std::string& value,
                      const std::string& expected,
                      const std::string& message)
{
    require(value.find(expected) != std::string::npos, message);
}

void erase_text(std::string& value)
{
    std::fill(value.begin(), value.end(), '\0');
    value.clear();
}

server_config_t make_config(const std::string& name, bool dynamic_client = false)
{
    server_config_t config;
    config.name = name;
    config.transport = mcp_client::transport_type_t::http_sse;
    config.url = "https://mcp.fixture.invalid/mcp";
    config.enabled = true;
    config.auto_connect = false;
    config.oauth_enabled = true;
    config.oauth_client_id = dynamic_client ? std::string{} : "fixture-client";
    config.oauth_client_secret = dynamic_client ? std::string{} : "fixture-secret";
    config.oauth_scope = "tools.read tools.write";
    return config;
}

http_reply_t make_reply(std::string body, int status = 200)
{
    http_reply_t reply;
    reply.status = status;
    reply.body = std::move(body);
    return reply;
}

std::string metadata_body(bool dynamic_client = false)
{
    mcp_client::json value = {
        {"token_endpoint", "https://oauth.fixture.invalid/token"},
        {"authorization_endpoint", "https://oauth.fixture.invalid/authorize"}
    };
    if (dynamic_client)
        value["registration_endpoint"] = "https://oauth.fixture.invalid/register";
    return value.dump();
}

std::string token_body(const std::string& access,
                       const std::string& refresh,
                       int64_t expires_in = 3600)
{
    return mcp_client::json({
        {"access_token", access},
        {"refresh_token", refresh},
        {"expires_in", expires_in},
        {"scope", "tools.read tools.write"}
    }).dump();
}

void require_state_scrubbed(const oauth_state_t& state)
{
    require(state.server_name.empty(), "terminal state retained server identity");
    require(state.authorization_url.empty(), "terminal state retained authorization URL");
    require(state.state_token.empty(), "terminal state retained state token");
    require(state.code_verifier.empty(), "terminal state retained PKCE verifier");
    require(state.code_challenge.empty(), "terminal state retained PKCE challenge");
    require(state.client_id.empty(), "terminal state retained client identity");
    require(state.client_secret.empty(), "terminal state retained client secret");
    require(state.redirect_uri.empty(), "terminal state retained redirect URI");
    require(state.token_endpoint.empty(), "terminal state retained token endpoint");
    require(state.authorization_endpoint.empty(), "terminal state retained authorization endpoint");
    require(state.registration_endpoint.empty(), "terminal state retained registration endpoint");
    require(state.scope.empty(), "terminal state retained scope");
    require(state.flow_binding == nullptr, "terminal state retained flow ownership");
}

void begin_flow(const server_config_t& config,
                oauth_state_t& state,
                bool dynamic_client = false)
{
    require(mcp_client::c03_oauth_fixture::add_server(config),
        "fixture server registration failed");
    mcp_client::c03_oauth_fixture::queue_http_reply(
        make_reply(metadata_body(dynamic_client)));
    if (dynamic_client) {
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(
            mcp_client::json({
                {"client_id", "dynamic-client"},
                {"client_secret", "dynamic-secret"}
            }).dump()));
    }
    require(mcp_client::start_auth(config.name, state),
        "fixture OAuth flow did not start");
    require(mcp_client::c03_oauth_fixture::active_flow_count() == 1u,
        "started flow is absent from the bounded registry");
    require(mcp_client::c03_oauth_fixture::active_flow_secret_bytes() != 0u,
        "active flow did not retain its required transient material");
}

void test_exact_once_completion()
{
    const auto config = make_config("exact-once");
    oauth_state_t state;
    begin_flow(config, state);
    require(!mcp_client::finish_auth(config.name, "code-exact"),
        "finish accepted a code before the loopback callback");
    require(!mcp_client::c03_oauth_fixture::deliver_callback(
        config.name, "wrong-state", "code-exact", {}),
        "callback accepted an incorrect state identity");
    std::string state_token = state.state_token;
    require(mcp_client::c03_oauth_fixture::deliver_callback(
        config.name, state_token, "code-exact", {}),
        "validated callback was rejected");
    erase_text(state_token);
    static_cast<void>(mcp_client::c03_oauth_fixture::take_http_requests());
    mcp_client::c03_oauth_fixture::queue_http_reply(
        make_reply(token_body("access-exact", "refresh-exact")));

    std::atomic<unsigned> ready{0};
    std::atomic<bool> go{false};
    std::atomic<bool> first{false};
    std::atomic<bool> second{false};
    auto finish = [&](std::atomic<bool>& result) {
        ready.fetch_add(1, std::memory_order_acq_rel);
        while (!go.load(std::memory_order_acquire))
            std::this_thread::yield();
        result.store(mcp_client::finish_auth(config.name, "code-exact"),
            std::memory_order_release);
    };
    std::thread first_thread(finish, std::ref(first));
    std::thread second_thread(finish, std::ref(second));
    while (ready.load(std::memory_order_acquire) != 2u)
        std::this_thread::yield();
    go.store(true, std::memory_order_release);
    first_thread.join();
    second_thread.join();

    require(first.load(std::memory_order_acquire),
        "first concurrent completion did not observe success");
    require(second.load(std::memory_order_acquire),
        "second concurrent completion did not observe the frozen success");
    require(mcp_client::finish_auth(config.name, "code-exact"),
        "duplicate completion did not return its bounded terminal receipt");
    require(mcp_client::poll_auth(state) == oauth_status_t::authenticated,
        "poll did not project the completed success into public state");
    require(mcp_client::poll_auth(state) == oauth_status_t::authenticated,
        "terminal poll was not idempotent");
    require_state_scrubbed(state);

    credential_t credential;
    require(mcp_client::c03_oauth_fixture::get_credential(config.name, credential),
        "successful completion did not persist a credential");
    require(credential.access == "access-exact", "persisted access token changed");
    require(credential.refresh == "refresh-exact", "persisted refresh token changed");
    require(credential.client_id == "fixture-client", "persisted client identity changed");
    require(credential.redirect_uri.find("http://127.0.0.1:") == 0,
        "persisted redirect URI is not the exact bound loopback identity");

    const auto requests = mcp_client::c03_oauth_fixture::take_http_requests();
    require(requests.size() == 1u, "authorization code exchanged more than once");
    require(requests.front().oauth_request, "token exchange bypassed the bounded OAuth transport");
    require(requests.front().method == "POST", "token exchange used an unexpected method");
    require_contains(requests.front().body, "grant_type=authorization_code",
        "token exchange omitted its grant type");
    require_contains(requests.front().body, "code=code-exact",
        "token exchange omitted the validated code");

    const auto events = mcp_client::c03_oauth_fixture::take_events();
    require(events.size() == 1u, "terminal success did not publish exactly one event");
    require(events.front().status == oauth_status_t::authenticated,
        "terminal success published the wrong status");
    require(events.front().generation != 0u, "terminal event omitted its generation");
    require(mcp_client::c03_oauth_fixture::active_flow_count() == 0u,
        "completed flow remained registered");
    require(mcp_client::c03_oauth_fixture::active_flow_secret_bytes() == 0u,
        "completed flow retained transient secret bytes");
}

void test_callback_and_token_failures()
{
    {
        const auto config = make_config("callback-error");
        oauth_state_t state;
        begin_flow(config, state);
        std::string state_token = state.state_token;
        require(mcp_client::c03_oauth_fixture::deliver_callback(
            config.name, state_token, {}, "authorization_denied"),
            "callback error was not accepted as a terminal callback");
        erase_text(state_token);
        require(mcp_client::poll_auth(state) == oauth_status_t::failed,
            "callback error did not become terminal failure");
        require_state_scrubbed(state);
        require(!mcp_client::has_stored_tokens(config.name),
            "callback error persisted a credential");
        const auto events = mcp_client::c03_oauth_fixture::take_events();
        require(events.size() == 1u && events.front().status == oauth_status_t::failed,
            "callback failure event is missing or duplicated");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("wrong-code");
        oauth_state_t state;
        begin_flow(config, state);
        std::string state_token = state.state_token;
        require(mcp_client::c03_oauth_fixture::deliver_callback(
            config.name, state_token, "validated-code", {}),
            "validated callback failed");
        erase_text(state_token);
        require(!mcp_client::finish_auth(config.name, "different-code"),
            "finish accepted a code different from the callback code");
        require(mcp_client::c03_oauth_fixture::active_flow_count() == 1u,
            "wrong-code rejection consumed the active flow");
        mcp_client::c03_oauth_fixture::queue_http_reply(
            make_reply("{\"access_token\":17}"));
        require(!mcp_client::finish_auth(config.name, "validated-code"),
            "wrong token JSON field type was accepted");
        require(mcp_client::poll_auth(state) == oauth_status_t::failed,
            "wrong token type did not freeze a failure");
        require_state_scrubbed(state);
        require(!mcp_client::has_stored_tokens(config.name),
            "wrong token type persisted a credential");
    }
}

void expect_metadata_failure(const std::string& name, http_reply_t reply)
{
    mcp_client::c03_oauth_fixture::reset();
    const auto config = make_config(name);
    require(mcp_client::c03_oauth_fixture::add_server(config),
        "metadata failure server registration failed");
    mcp_client::c03_oauth_fixture::queue_http_reply(std::move(reply));
    oauth_state_t state;
    require(!mcp_client::start_auth(config.name, state),
        "malformed or rejected metadata started an OAuth flow");
    require(state.done.load(std::memory_order_acquire),
        "metadata failure did not complete public state");
    require(mcp_client::poll_auth(state) == oauth_status_t::failed,
        "metadata failure did not remain terminal");
    require_state_scrubbed(state);
    require(mcp_client::c03_oauth_fixture::active_flow_count() == 0u,
        "metadata failure retained an active flow");
    require(mcp_client::c03_oauth_fixture::active_flow_secret_bytes() == 0u,
        "metadata failure retained transient material");
}

void test_bounded_metadata_and_redirects()
{
    expect_metadata_failure("malformed-json", make_reply("{"));
    expect_metadata_failure("wrong-metadata-type", make_reply(
        "{\"token_endpoint\":7,\"authorization_endpoint\":true}"));

    http_reply_t redirect = make_reply({}, 302);
    redirect.headers["Location"] = "https://redirect.fixture.invalid/metadata";
    expect_metadata_failure("redirect", std::move(redirect));
    const auto redirect_requests = mcp_client::c03_oauth_fixture::take_http_requests();
    require(redirect_requests.size() == 1u,
        "metadata redirect caused more than one bounded request");

    expect_metadata_failure("oversized-metadata",
        make_reply(std::string(256u * 1024u + 1u, 'x')));
    http_reply_t oversized_header = make_reply("{}");
    oversized_header.headers["Content-Length"] = "999999999";
    expect_metadata_failure("oversized-content-length", std::move(oversized_header));

    mcp_client::c03_oauth_fixture::reset();
    {
        auto config = make_config("redirect-mismatch");
        config.oauth_redirect_uri = "http://127.0.0.1:9/mcp/oauth/callback";
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "redirect mismatch server registration failed");
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "configured redirect mismatch was accepted");
        require(mcp_client::c03_oauth_fixture::pending_http_reply_count() == 1u,
            "redirect mismatch performed network discovery before rejection");
        require_state_scrubbed(state);
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        auto config = make_config("insecure-origin");
        config.url = "http://nonloopback.fixture.invalid/mcp";
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "insecure origin server registration failed");
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "non-loopback cleartext OAuth origin was accepted");
        require(mcp_client::c03_oauth_fixture::pending_http_reply_count() == 0u,
            "invalid origin performed a network request");
    }
}

void test_browser_failure_and_allocation()
{
    {
        const auto config = make_config("browser-failure");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "browser failure server registration failed");
        mcp_client::c03_oauth_fixture::set_browser_result(false);
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "Camoufox failure returned start success");
        require(mcp_client::poll_auth(state) == oauth_status_t::failed,
            "Camoufox failure did not freeze terminal failure");
        require_state_scrubbed(state);
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("config-allocation");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "config allocation server registration failed");
        mcp_client::c03_oauth_fixture::fail_next(fault_point_t::config_lookup);
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "config allocation fault escaped as success");
        require(state.done.load(std::memory_order_acquire),
            "config allocation fault left state initializing");
        require_state_scrubbed(state);
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("http-allocation");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "HTTP allocation server registration failed");
        mcp_client::c03_oauth_fixture::fail_next(fault_point_t::http_request);
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "HTTP allocation fault escaped as success");
        require(mcp_client::c03_oauth_fixture::active_flow_count() == 0u,
            "HTTP allocation fault left a flow active");
        require_state_scrubbed(state);
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("browser-allocation");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "browser allocation server registration failed");
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        mcp_client::c03_oauth_fixture::fail_next(fault_point_t::browser);
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "browser allocation fault escaped as success");
        require_state_scrubbed(state);
    }
}

void test_direct_and_trigger_cancellation()
{
    {
        const auto config = make_config("direct-cancel");
        oauth_state_t state;
        begin_flow(config, state);
        require(mcp_client::cancel_auth(state), "direct cancellation was rejected");
        require(mcp_client::poll_auth(state) == oauth_status_t::failed,
            "direct cancellation did not freeze failure");
        require(mcp_client::poll_auth(state) == oauth_status_t::failed,
            "direct cancellation poll was not idempotent");
        require_state_scrubbed(state);
        require(mcp_client::c03_oauth_fixture::active_flow_count() == 0u,
            "direct cancellation retained a flow");
        const auto events = mcp_client::c03_oauth_fixture::take_events();
        require(events.size() == 1u, "direct cancellation event was missing or duplicated");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("queued-cancel");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "queued cancellation server registration failed");
        std::atomic<unsigned> callback_count{0};
        std::atomic<oauth_status_t> callback_status{oauth_status_t::authenticating};
        require(mcp_client::trigger_auth_flow(config.name,
            [&](const std::string&, oauth_status_t status, const std::string&) {
                callback_status.store(status, std::memory_order_release);
                callback_count.fetch_add(1, std::memory_order_acq_rel);
            }), "queued trigger was rejected");
        require(mcp_client::c03_oauth_fixture::pending_task_count() == 1u,
            "queued trigger did not own one bounded task");
        require(mcp_client::cancel_auth(config.name),
            "queued trigger cancellation was rejected");
        require(callback_count.load(std::memory_order_acquire) == 1u,
            "queued cancellation did not invoke exactly one callback");
        require(callback_status.load(std::memory_order_acquire) == oauth_status_t::failed,
            "queued cancellation callback reported success");
        require(mcp_client::c03_oauth_fixture::run_ready_tasks(1u) == 1u,
            "cancelled queued task did not drain");
        require(callback_count.load(std::memory_order_acquire) == 1u,
            "cancelled task invoked its callback twice");
        require(mcp_client::c03_oauth_fixture::pending_task_count() == 0u,
            "cancelled queued task remained pending");
        require(mcp_client::c03_oauth_fixture::active_trigger_count() == 0u,
            "cancelled trigger remained registered");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("throwing-callback");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "throwing callback server registration failed");
        mcp_client::c03_oauth_fixture::set_browser_result(false);
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        std::atomic<unsigned> callback_count{0};
        require(mcp_client::trigger_auth_flow(config.name,
            [&](const std::string&, oauth_status_t, const std::string&) {
                callback_count.fetch_add(1, std::memory_order_acq_rel);
                throw fixture_failure_t("callback exception");
            }), "throwing callback trigger was rejected");
        require(mcp_client::c03_oauth_fixture::run_ready_tasks(1u) == 1u,
            "throwing callback task did not run");
        require(callback_count.load(std::memory_order_acquire) == 1u,
            "throwing callback was not contained exactly once");
        require(mcp_client::c03_oauth_fixture::active_trigger_count() == 0u,
            "throwing callback retained its trigger registration");
    }
}

std::string wait_for_callback_state(const std::string& server_name, std::thread& runner)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        std::string state_token;
        if (mcp_client::c03_oauth_fixture::get_active_state_token(
                server_name, state_token))
            return state_token;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    static_cast<void>(mcp_client::cancel_auth(server_name));
    if (runner.joinable())
        runner.join();
    throw fixture_failure_t("asynchronous trigger did not expose its active flow");
}

void test_asynchronous_trigger_and_deadline()
{
    {
        const auto config = make_config("async-success");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "asynchronous server registration failed");
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        mcp_client::c03_oauth_fixture::queue_http_reply(
            make_reply(token_body("async-access", "async-refresh")));
        std::atomic<unsigned> callback_count{0};
        std::atomic<oauth_status_t> callback_status{oauth_status_t::authenticating};
        require(mcp_client::trigger_auth_flow(config.name,
            [&](const std::string&, oauth_status_t status, const std::string&) {
                callback_status.store(status, std::memory_order_release);
                callback_count.fetch_add(1, std::memory_order_acq_rel);
            }), "asynchronous trigger was rejected");
        require(mcp_client::c03_oauth_fixture::take_http_requests().empty(),
            "trigger performed browser or network work synchronously");
        std::thread runner([]() {
            static_cast<void>(mcp_client::c03_oauth_fixture::run_ready_tasks(1u));
        });
        std::string state_token = wait_for_callback_state(config.name, runner);
        require(mcp_client::c03_oauth_fixture::deliver_callback(
            config.name, state_token, "async-code", {}),
            "asynchronous callback delivery failed");
        erase_text(state_token);
        runner.join();
        require(callback_count.load(std::memory_order_acquire) == 1u,
            "asynchronous trigger callback count is not exact");
        require(callback_status.load(std::memory_order_acquire) == oauth_status_t::authenticated,
            "asynchronous trigger did not report authentication");
        require(mcp_client::c03_oauth_fixture::active_trigger_count() == 0u,
            "successful trigger remained registered");
        require(mcp_client::c03_oauth_fixture::pending_task_count() == 0u,
            "successful trigger task remained pending");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("async-deadline");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "deadline server registration failed");
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        std::atomic<unsigned> callback_count{0};
        std::atomic<oauth_status_t> callback_status{oauth_status_t::authenticating};
        require(mcp_client::trigger_auth_flow(config.name,
            [&](const std::string&, oauth_status_t status, const std::string&) {
                callback_status.store(status, std::memory_order_release);
                callback_count.fetch_add(1, std::memory_order_acq_rel);
            }), "deadline trigger was rejected");
        std::thread runner([]() {
            static_cast<void>(mcp_client::c03_oauth_fixture::run_ready_tasks(1u));
        });
        std::string state_token = wait_for_callback_state(config.name, runner);
        erase_text(state_token);
        mcp_client::c03_oauth_fixture::advance_time(301);
        runner.join();
        require(callback_count.load(std::memory_order_acquire) == 1u,
            "expired trigger callback count is not exact");
        require(callback_status.load(std::memory_order_acquire) == oauth_status_t::failed,
            "expired trigger did not report failure");
        require(mcp_client::c03_oauth_fixture::active_flow_count() == 0u,
            "expired trigger retained its flow");
        require(mcp_client::c03_oauth_fixture::active_trigger_count() == 0u,
            "expired trigger retained its request");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("queued-deadline");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "queued deadline server registration failed");
        std::atomic<unsigned> callback_count{0};
        std::atomic<oauth_status_t> callback_status{oauth_status_t::authenticating};
        require(mcp_client::trigger_auth_flow(config.name,
            [&](const std::string&, oauth_status_t status, const std::string&) {
                callback_status.store(status, std::memory_order_release);
                callback_count.fetch_add(1, std::memory_order_acq_rel);
            }), "queued deadline trigger was rejected");
        mcp_client::c03_oauth_fixture::advance_time(301);
        require(mcp_client::c03_oauth_fixture::run_ready_tasks(1u) == 1u,
            "expired queued trigger task did not drain");
        require(callback_count.load(std::memory_order_acquire) == 1u,
            "expired queued trigger callback count was not exact");
        require(callback_status.load(std::memory_order_acquire) == oauth_status_t::failed,
            "expired queued trigger did not report failure");
        require(mcp_client::c03_oauth_fixture::active_trigger_count() == 0u,
            "expired queued trigger retained its request");
        require(mcp_client::c03_oauth_fixture::pending_task_count() == 0u,
            "expired queued trigger retained its task");
    }
}

void test_dynamic_registration_and_preflight_refresh()
{
    const auto config = make_config("dynamic-refresh", true);
    oauth_state_t state;
    begin_flow(config, state, true);
    require(state.client_id == "dynamic-client", "dynamic client identity was not staged");
    require(state.client_secret == "dynamic-secret", "dynamic client secret was not staged");
    std::string state_token = state.state_token;
    require(mcp_client::c03_oauth_fixture::deliver_callback(
        config.name, state_token, "dynamic-code", {}),
        "dynamic registration callback failed");
    erase_text(state_token);
    mcp_client::c03_oauth_fixture::queue_http_reply(
        make_reply(token_body("dynamic-access", "dynamic-refresh-token", 60)));
    require(mcp_client::finish_auth(config.name, "dynamic-code"),
        "dynamic registration token exchange failed");
    require(mcp_client::poll_auth(state) == oauth_status_t::authenticated,
        "dynamic registration did not complete public state");
    require_state_scrubbed(state);

    credential_t initial;
    require(mcp_client::c03_oauth_fixture::get_credential(config.name, initial),
        "dynamic registration credential was not stored");
    require(initial.client_id == "dynamic-client",
        "dynamic client identity was not durably stored");
    require(initial.metadata.value("mcp_client_secret", std::string{}) == "dynamic-secret",
        "dynamic client secret was not durably stored");
    require(initial.metadata.value("mcp_token_endpoint", std::string{})
            == "https://oauth.fixture.invalid/token",
        "dynamic token endpoint was not durably stored");

    static_cast<void>(mcp_client::c03_oauth_fixture::take_http_requests());
    static_cast<void>(mcp_client::c03_oauth_fixture::take_events());
    mcp_client::c03_oauth_fixture::advance_time(31);
    mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(
        token_body("refreshed-access", "refreshed-refresh", 3600)));
    mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"serverInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}"));
    mcp_client::c03_oauth_fixture::queue_http_reply(make_reply("{}", 202));

    mcp_client::client_t client;
    require(client.connect(config),
        "expired dynamic credential was not refreshed before MCP initialize");
    require(client.is_connected(), "refreshed MCP client is not connected");
    const auto requests = mcp_client::c03_oauth_fixture::take_http_requests();
    require(requests.size() == 3u,
        "refresh and initialize did not use the expected bounded request sequence");
    require(requests[0].oauth_request, "refresh bypassed the OAuth transport");
    require_contains(requests[0].body, "grant_type=refresh_token",
        "refresh request omitted its grant type");
    require_contains(requests[0].body, "client_id=dynamic-client",
        "refresh request omitted the persisted dynamic client identity");
    require_contains(requests[0].body, "client_secret=dynamic-secret",
        "refresh request omitted the persisted dynamic client secret");
    require_contains(requests[0].body, "refresh_token=dynamic-refresh-token",
        "refresh request omitted the persisted refresh token");
    const auto authorization = requests[1].headers.find("Authorization");
    require(authorization != requests[1].headers.end(),
        "MCP initialize omitted its Authorization header");
    require(authorization->second == "Bearer refreshed-access",
        "MCP initialize sent a stale access token");

    credential_t refreshed;
    require(mcp_client::c03_oauth_fixture::get_credential(config.name, refreshed),
        "refreshed credential was not stored");
    require(refreshed.access == "refreshed-access",
        "stored access token was not replaced by refresh");
    require(refreshed.client_id == "dynamic-client",
        "refresh discarded the persisted client identity");
    require(refreshed.metadata.value("mcp_client_secret", std::string{}) == "dynamic-secret",
        "refresh discarded the persisted client secret");
    client.disconnect();
}

void test_config_and_remove_races()
{
    {
        auto config = make_config("config-race");
        oauth_state_t old_state;
        begin_flow(config, old_state);
        std::string old_state_token = old_state.state_token;
        config.url = "https://mcp2.fixture.invalid/mcp";
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "changed configuration was not accepted");
        require(!mcp_client::c03_oauth_fixture::deliver_callback(
            config.name, old_state_token, "stale-code", {}),
            "stale callback reached a replaced configuration generation");
        erase_text(old_state_token);
        require(mcp_client::poll_auth(old_state) == oauth_status_t::failed,
            "replaced configuration did not fail the old state");
        require_state_scrubbed(old_state);
        require(!mcp_client::has_stored_tokens(config.name),
            "replaced configuration persisted stale credentials");

        oauth_state_t current_state;
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        require(mcp_client::start_auth(config.name, current_state),
            "new configuration generation did not start");
        require(mcp_client::poll_auth(old_state) == oauth_status_t::failed,
            "old frozen state changed after a new generation started");
        require(mcp_client::c03_oauth_fixture::active_flow_count() == 1u,
            "old state interaction displaced the new generation");
        require(mcp_client::cancel_auth(current_state),
            "new configuration flow did not cancel cleanly");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("remove-race");
        oauth_state_t state;
        begin_flow(config, state);
        std::string state_token = state.state_token;
        require(mcp_client::c03_oauth_fixture::deliver_callback(
            config.name, state_token, "remove-code", {}),
            "remove race callback failed");
        erase_text(state_token);
        mcp_client::c03_oauth_fixture::queue_http_reply(
            make_reply(token_body("remove-access", "remove-refresh")));
        std::atomic<unsigned> ready{0};
        std::atomic<bool> go{false};
        std::atomic<bool> removed{false};
        std::atomic<bool> finished{false};
        std::thread finish_thread([&]() {
            ready.fetch_add(1, std::memory_order_acq_rel);
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            finished.store(mcp_client::finish_auth(config.name, "remove-code"),
                std::memory_order_release);
        });
        std::thread remove_thread([&]() {
            ready.fetch_add(1, std::memory_order_acq_rel);
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            removed.store(mcp_client::remove_auth(config.name),
                std::memory_order_release);
        });
        while (ready.load(std::memory_order_acquire) != 2u)
            std::this_thread::yield();
        go.store(true, std::memory_order_release);
        finish_thread.join();
        remove_thread.join();
        require(removed.load(std::memory_order_acquire),
            "credential removal failed during the commit race");
        static_cast<void>(finished.load(std::memory_order_acquire));
        credential_t credential;
        require(!mcp_client::c03_oauth_fixture::get_credential(config.name, credential),
            "remove race left a stale credential behind");
        require(mcp_client::c03_oauth_fixture::active_flow_count() == 0u,
            "remove race left a flow active");
        require(mcp_client::c03_oauth_fixture::active_flow_secret_bytes() == 0u,
            "remove race retained transient material");
        const auto events = mcp_client::c03_oauth_fixture::take_events();
        require(events.size() == 1u, "remove race published a missing or duplicate event");
    }
}

void test_capacity_and_generation_exhaustion()
{
    std::vector<std::unique_ptr<oauth_state_t>> states;
    states.reserve(128u);
    for (size_t index = 0; index < 128u; ++index) {
        const auto config = make_config("capacity-" + std::to_string(index));
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "bounded configuration registry rejected an in-range entry");
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        auto state = std::make_unique<oauth_state_t>();
        require(mcp_client::start_auth(config.name, *state),
            "bounded flow registry rejected an in-range flow");
        states.push_back(std::move(state));
    }
    require(mcp_client::c03_oauth_fixture::active_flow_count() == 128u,
        "bounded flow registry did not reach its exact capacity");
    require(!mcp_client::c03_oauth_fixture::add_server(make_config("capacity-overflow")),
        "bounded configuration registry accepted its 129th identity");
    oauth_state_t duplicate;
    require(!mcp_client::start_auth("capacity-0", duplicate),
        "bounded flow registry accepted a duplicate active identity");
    mcp_client::c03_oauth_fixture::reset();
    states.clear();

    {
        const auto config = make_config("flow-generation");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "flow generation server registration failed");
        mcp_client::c03_oauth_fixture::set_flow_generation(
            (std::numeric_limits<std::uint64_t>::max)());
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "flow generation wrapped instead of failing closed");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("trigger-generation");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "trigger generation server registration failed");
        mcp_client::c03_oauth_fixture::set_trigger_generation(
            (std::numeric_limits<std::uint64_t>::max)());
        require(!mcp_client::trigger_auth_flow(config.name, {}),
            "trigger generation wrapped instead of failing closed");
        require(mcp_client::c03_oauth_fixture::pending_task_count() == 0u,
            "exhausted trigger generation submitted a task");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        auto config = make_config("config-generation");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "config generation server registration failed");
        mcp_client::c03_oauth_fixture::set_config_generation(config.name,
            (std::numeric_limits<std::uint64_t>::max)());
        config.url = "https://changed.fixture.invalid/mcp";
        require(!mcp_client::c03_oauth_fixture::add_server(config),
            "configuration generation wrapped instead of failing closed");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("auth-epoch");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "auth epoch server registration failed");
        mcp_client::c03_oauth_fixture::set_auth_epoch(config.name,
            (std::numeric_limits<std::uint64_t>::max)());
        mcp_client::c03_oauth_fixture::queue_http_reply(make_reply(metadata_body()));
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "credential epoch wrapped instead of failing closed");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("unix-deadline-overflow");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "unix deadline overflow server registration failed");
        mcp_client::c03_oauth_fixture::set_time(
            (std::numeric_limits<int64_t>::max)());
        oauth_state_t state;
        require(!mcp_client::start_auth(config.name, state),
            "unix authorization deadline wrapped instead of failing closed");
        require_state_scrubbed(state);
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("task-deadline-overflow");
        require(mcp_client::c03_oauth_fixture::add_server(config),
            "task deadline overflow server registration failed");
        mcp_client::c03_oauth_fixture::advance_time(
            (std::numeric_limits<int64_t>::max)());
        require(!mcp_client::trigger_auth_flow(config.name, {}),
            "task deadline wrapped instead of failing closed");
        require(mcp_client::c03_oauth_fixture::pending_task_count() == 0u,
            "task deadline overflow submitted work");
        require(mcp_client::c03_oauth_fixture::active_trigger_count() == 0u,
            "task deadline overflow retained a trigger");
    }
}

void test_terminal_fault_containment()
{
    {
        const auto config = make_config("store-fault");
        oauth_state_t state;
        begin_flow(config, state);
        std::string state_token = state.state_token;
        require(mcp_client::c03_oauth_fixture::deliver_callback(
            config.name, state_token, "store-code", {}),
            "store fault callback failed");
        erase_text(state_token);
        mcp_client::c03_oauth_fixture::queue_http_reply(
            make_reply(token_body("store-access", "store-refresh")));
        mcp_client::c03_oauth_fixture::fail_next(fault_point_t::credential_store);
        require(!mcp_client::finish_auth(config.name, "store-code"),
            "credential store allocation fault escaped as success");
        require(mcp_client::poll_auth(state) == oauth_status_t::failed,
            "credential store allocation fault left state exchanging");
        require_state_scrubbed(state);
        require(!mcp_client::has_stored_tokens(config.name),
            "credential store fault retained a credential");
    }

    mcp_client::c03_oauth_fixture::reset();
    {
        const auto config = make_config("event-fault");
        oauth_state_t state;
        begin_flow(config, state);
        std::string state_token = state.state_token;
        require(mcp_client::c03_oauth_fixture::deliver_callback(
            config.name, state_token, "event-code", {}),
            "event fault callback failed");
        erase_text(state_token);
        mcp_client::c03_oauth_fixture::queue_http_reply(
            make_reply(token_body("event-access", "event-refresh")));
        mcp_client::c03_oauth_fixture::fail_next(fault_point_t::event_publish);
        require(mcp_client::finish_auth(config.name, "event-code"),
            "transient event allocation fault changed credential commit result");
        require(mcp_client::poll_auth(state) == oauth_status_t::authenticated,
            "event allocation fault left state nonterminal");
        require_state_scrubbed(state);
        const auto events = mcp_client::c03_oauth_fixture::take_events();
        require(events.size() == 1u,
            "transient event allocation fault lost or duplicated the terminal event");
    }
}

using test_t = std::pair<const char*, std::function<void()>>;

}

int main()
{
    const std::vector<test_t> tests = {
        {"exact_once_completion", test_exact_once_completion},
        {"callback_and_token_failures", test_callback_and_token_failures},
        {"bounded_metadata_and_redirects", test_bounded_metadata_and_redirects},
        {"browser_failure_and_allocation", test_browser_failure_and_allocation},
        {"direct_and_trigger_cancellation", test_direct_and_trigger_cancellation},
        {"asynchronous_trigger_and_deadline", test_asynchronous_trigger_and_deadline},
        {"dynamic_registration_and_preflight_refresh", test_dynamic_registration_and_preflight_refresh},
        {"config_and_remove_races", test_config_and_remove_races},
        {"capacity_and_generation_exhaustion", test_capacity_and_generation_exhaustion},
        {"terminal_fault_containment", test_terminal_fault_containment}
    };

    unsigned failures = 0;
    for (const auto& test : tests) {
        mcp_client::c03_oauth_fixture::reset();
        try {
            test.second();
            std::cout << "PASS " << test.first << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "FAIL " << test.first << ": " << error.what() << '\n';
        } catch (...) {
            ++failures;
            std::cerr << "FAIL " << test.first << ": unknown exception\n";
        }
        mcp_client::c03_oauth_fixture::reset();
    }
    if (failures != 0u) {
        std::cerr << "FAILED " << failures << " of " << tests.size() << '\n';
        return 1;
    }
    std::cout << "PASSED " << tests.size() << " MCP OAuth staging domains\n";
    return 0;
}
