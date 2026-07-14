#include "mcp_client_auth_harness.hpp"
#include "../../assertion_telemetry/assertion_telemetry.hpp"

#include "../../../../src/core/mcp/mcp_standalone.hpp"

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace aida::standalone::tests::c03::security {
namespace {

using mcp_standalone::local_request_auth_input_t;
using mcp_standalone::local_request_auth_status_t;

constexpr const char* k_capability =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
constexpr const char* k_run_binding =
    "run-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

void require(bool condition, const char* message) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

local_request_auth_input_t valid_request() {
    local_request_auth_input_t input;
    input.method = "POST";
    input.path = "/mcp";
    input.remote_address = "127.0.0.1";
    input.host = "127.0.0.1:19191";
    input.authorization = std::string("Bearer ") + k_capability;
    input.run_binding = k_run_binding;
    input.bound_port = 19191;
    return input;
}

void require_rejected(local_request_auth_input_t input,
                      local_request_auth_status_t expected,
                      const char* message) {
    const auto result = mcp_standalone::authorize_local_request(
        input, k_capability, k_run_binding);
    require(!result.allowed && !result.capability_authenticated &&
            result.status == expected, message);
}

}

bool run_mcp_client_auth_harness(std::string& failure) {
    try {
        const auto accepted = mcp_standalone::authorize_local_request(
            valid_request(), k_capability, k_run_binding);
        require(accepted.allowed && accepted.capability_authenticated &&
                accepted.status == local_request_auth_status_t::allowed,
                "valid bound localhost capability was rejected");
        require(mcp_standalone::verify_local_route_capability(
                    valid_request().authorization, k_run_binding, std::string_view{},
                    k_capability, k_run_binding),
                "independent route capability verifier rejected valid credentials");

        auto localhost_host = valid_request();
        localhost_host.host = "LOCALHOST:19191";
        const auto localhost_result = mcp_standalone::authorize_local_request(
            localhost_host, k_capability, k_run_binding);
        require(localhost_result.allowed && localhost_result.capability_authenticated,
                "case-normalized localhost Host was rejected");

        auto health = valid_request();
        health.method = "GET";
        health.path = "/health";
        health.authorization.clear();
        health.run_binding.clear();
        const auto health_result = mcp_standalone::authorize_local_request(
            health, k_capability, k_run_binding);
        require(health_result.allowed && !health_result.capability_authenticated &&
                health_result.status == local_request_auth_status_t::health_read_only,
                "GET-only health exception was rejected");

        auto remote = valid_request();
        remote.remote_address = "10.0.0.7";
        require_rejected(std::move(remote), local_request_auth_status_t::invalid_remote,
                         "non-loopback request was accepted");

        auto rebinding = valid_request();
        rebinding.host = "attacker.example";
        require_rejected(std::move(rebinding), local_request_auth_status_t::invalid_host,
                         "DNS-rebinding Host was accepted");

        auto smuggled_host = valid_request();
        smuggled_host.host = "127.0.0.1:19191@attacker.example";
        require_rejected(std::move(smuggled_host), local_request_auth_status_t::invalid_host,
                         "userinfo Host smuggling was accepted");

        auto browser = valid_request();
        browser.origin = "https://attacker.example";
        require_rejected(std::move(browser),
                         local_request_auth_status_t::browser_origin_forbidden,
                         "browser-origin request was accepted");

        auto missing = valid_request();
        missing.authorization.clear();
        require_rejected(std::move(missing), local_request_auth_status_t::capability_missing,
                         "missing capability was accepted");

        auto wrong = valid_request();
        wrong.authorization.back() = wrong.authorization.back() == '0' ? '1' : '0';
        require_rejected(std::move(wrong), local_request_auth_status_t::capability_rejected,
                          "wrong capability was accepted");
        require(!mcp_standalone::verify_local_route_capability(
                    "Bearer ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    k_run_binding, std::string_view{}, k_capability, k_run_binding),
                "independent route capability verifier accepted a wrong capability");

        auto truncated = valid_request();
        truncated.authorization.pop_back();
        require_rejected(std::move(truncated), local_request_auth_status_t::capability_rejected,
                         "truncated capability was accepted");

        auto wrong_scheme = valid_request();
        wrong_scheme.authorization.replace(0, 6, "bearer");
        require_rejected(std::move(wrong_scheme), local_request_auth_status_t::capability_rejected,
                         "noncanonical bearer scheme was accepted");

        auto missing_run = valid_request();
        missing_run.run_binding.clear();
        require_rejected(std::move(missing_run), local_request_auth_status_t::run_binding_missing,
                         "missing run binding was accepted");

        auto replay = valid_request();
        replay.run_binding =
            "run-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        require_rejected(std::move(replay), local_request_auth_status_t::run_binding_rejected,
                          "prior-run replay binding was accepted");
        require(!mcp_standalone::verify_local_route_capability(
                    std::string("Bearer ") + k_capability,
                    "run-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    std::string_view{}, k_capability, k_run_binding),
                "independent route capability verifier accepted a prior-run binding");

        auto health_post = valid_request();
        health_post.path = "/health";
        health_post.authorization.clear();
        health_post.run_binding.clear();
        require_rejected(std::move(health_post),
                         local_request_auth_status_t::capability_missing,
                         "POST health request received the read-only exception");

        auto browser_health = health;
        browser_health.origin = "null";
        require_rejected(std::move(browser_health),
                          local_request_auth_status_t::browser_origin_forbidden,
                          "browser-origin health response was exposed");
        require(!mcp_standalone::verify_local_route_capability(
                    std::string("Bearer ") + k_capability,
                    k_run_binding, "https://attacker.example",
                    k_capability, k_run_binding),
                "independent route capability verifier accepted a browser origin");

        failure.clear();
        return true;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    } catch (...) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(
			"mcp client authorization harness failed with an unknown exception");
        failure = "mcp client authorization harness failed with an unknown exception";
        return false;
    }
}

}
