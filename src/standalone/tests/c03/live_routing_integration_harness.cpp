#include "live_routing_integration_harness.hpp"

#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/live_routing_integration.hpp"
#include "../../src/core/mcp/compat/debugger_lane.hpp"
#include "../../src/core/mcp/compat/effect_policy.hpp"
#include "../../src/core/mcp/compat/target_resolver.hpp"
#include "../../src/core/mcp/compat/workspace_adapter.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace aida::standalone::mcp::compat::test {
namespace {

using namespace aida::standalone::mcp::compat;

void require(bool condition, std::string_view message) {
    aida::analysis::c03_test::assertion_telemetry::record_assertion(
        condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

class fake_debugger_adapter_t final : public debugger_adapter_t {
public:
    fake_debugger_adapter_t() {
        identity_.pid = 4242U;
        identity_.process_creation_identity = 0xDEADBEEFCAFEULL;
        identity_.module_base = 0x0000000140000000ULL;
        identity_.module_size = 0x8000U;
        identity_.attach_generation = 1U;
        identity_.attached = true;
    }

    debugger_adapter_result_t<debugger_target_identity_t> identity(
        const protocol::cancellation_token_t& cancellation,
        std::chrono::steady_clock::time_point deadline) override {
        if (cancellation.cancelled()) {
            return debugger_adapter_result_t<debugger_target_identity_t>::failure(
                debugger_adapter_error_code_t::cancelled);
        }
        if (std::chrono::steady_clock::now() > deadline) {
            return debugger_adapter_result_t<debugger_target_identity_t>::failure(
                debugger_adapter_error_code_t::deadline_exceeded);
        }
        return debugger_adapter_result_t<debugger_target_identity_t>::success(identity_);
    }

    debugger_adapter_result_t<debugger_adapter_response_t> execute(
        const debugger_adapter_request_t& request) override {
        if (request.cancellation.cancelled()) {
            return debugger_adapter_result_t<debugger_adapter_response_t>::failure(
                debugger_adapter_error_code_t::cancelled);
        }
        debugger_adapter_response_t response;
        response.structured = protocol::json::object();
        response.structured["status"] = "ok";
        response.structured["tool"] = request.tool_name;
        return debugger_adapter_result_t<debugger_adapter_response_t>::success(std::move(response));
    }

    void set_pid(std::uint32_t pid) noexcept { identity_.pid = pid; }
    void set_process_creation_identity(std::uint64_t value) noexcept {
        identity_.process_creation_identity = value;
    }
    void set_attach_generation(std::uint64_t gen) noexcept {
        identity_.attach_generation = gen;
    }
    const debugger_target_identity_t& current_identity() const noexcept { return identity_; }

private:
    debugger_target_identity_t identity_{};
};

target_record_t make_live_target(std::uint64_t target_id, std::uint32_t pid,
                                  std::uint64_t creation_identity,
                                  std::uint64_t module_base, std::uint64_t module_size) {
    target_record_t record;
    record.target_id = target_id;
    record.pid = pid;
    record.process_creation_identity = creation_identity;
    record.bin_name = "test_target.exe";
    record.generation = 1;
    record.attach_generation = 1;
    record.live = true;
    record.live_capture_base = module_base;
    record.live_capture_size = module_size;
    record.live_snapshot_permitted = true;
    record.live_snapshot_maximum_bytes = 1024ULL * 1024ULL;
    record.revision = 1;
    return record;
}

void verify_identity_binding() {
    target_resolver_t resolver;
    effect_lock_manager_t lock_manager;
    auto adapter = std::make_unique<fake_debugger_adapter_t>();
    debugger_lane_t lane(*adapter);

    auto record = make_live_target(1, 4242U, 0xDEADBEEFCAFEULL,
                                    0x0000000140000000ULL, 0x8000U);
    auto status = resolver.publish(record);
    require(status.succeeded(), "failed to publish live target");

    live_routing_integration_t routing(resolver, lock_manager, lane);

    target_selector_t selector;
    selector.pid = 4242U;

    auto bind = routing.bind_identity(selector);
    require(bind.has_value(), "identity binding failed for live target");
    require(bind.value().pid == 4242U, "bound pid mismatch");
    require(bind.value().process_creation_identity == 0xDEADBEEFCAFEULL,
            "bound process_creation_identity mismatch");
    require(bind.value().module_base == 0x0000000140000000ULL,
            "bound module_base mismatch");
    require(bind.value().module_size == 0x8000U,
            "bound module_size mismatch");
    require(bind.value().attach_generation == 1U,
            "bound attach_generation mismatch");
}

void verify_bounded_snapshot_enforcement() {
    target_resolver_t resolver;
    effect_lock_manager_t lock_manager;
    auto adapter = std::make_unique<fake_debugger_adapter_t>();
    debugger_lane_t lane(*adapter);

    auto record = make_live_target(1, 4242U, 0xDEADBEEFCAFEULL,
                                    0x0000000140000000ULL, 0x8000U);
    resolver.publish(record);

    live_routing_limits_t limits;
    limits.maximum_snapshot_bytes = 4096U;
    std::atomic_uint32_t snapshot_calls{0};
    live_snapshot_handler_t snapshot_reader = [&snapshot_calls](
        const adapter_call_context_t& context,
        const bounded_live_snapshot_request_t& request) {
        snapshot_calls.fetch_add(1, std::memory_order_relaxed);
        if (!context.target) {
            return adapter_result_t<bounded_live_snapshot_t>::failure({
                adapter_error_code_t::target_resolution_failed,
                "fixture_target_resolution_missing",
                1,
                0,
            });
        }
        const auto& target = context.target->target();
        bounded_live_snapshot_t result;
        result.bytes.resize(static_cast<std::size_t>(request.size));
        for (std::size_t index = 0; index < result.bytes.size(); ++index)
            result.bytes[index] = static_cast<std::uint8_t>((request.address + index) & 0xffU);
        result.process_creation_identity = target.process_creation_identity;
        result.attach_generation = target.attach_generation;
        result.generation = target.generation;
        return adapter_result_t<bounded_live_snapshot_t>::success(std::move(result));
    };
    live_routing_integration_t routing(
        resolver, lock_manager, lane, limits, std::move(snapshot_reader));

    target_selector_t selector;
    selector.pid = 4242U;

    live_routing_snapshot_request_t req;
    req.target = selector;
    req.address = 0x0000000140000000ULL;
    req.size = 4096U;

    auto snap = routing.capture_bounded_snapshot(req);
    require(snap.has_value(), "bounded snapshot within limits was rejected");
    require(snap.value().bytes.size() == 4096U, "snapshot bytes size mismatch");
    require(!snap.value().truncated, "within-limit snapshot was truncated");
    require(snapshot_calls.load(std::memory_order_relaxed) == 1U,
            "fake snapshot backend invocation count mismatch");

    req.size = 8192U;
    auto oversize = routing.capture_bounded_snapshot(req);
    require(!oversize.has_value(), "oversized snapshot was accepted");
    require(oversize.error().code == live_routing_error_code_t::snapshot_budget_exceeded,
            "oversized snapshot did not return budget_exceeded");
    require(oversize.error().expected == 4096U, "oversized snapshot expected limit mismatch");
    require(oversize.error().actual == 8192U, "oversized snapshot actual mismatch");
    require(snapshot_calls.load(std::memory_order_relaxed) == 1U,
            "oversized snapshot reached the fake backend");

    req.size = 4096U;
    req.address = 0x0000000140000000ULL + 0x8000U;
    auto oob = routing.capture_bounded_snapshot(req);
    require(!oob.has_value(), "out-of-bounds snapshot was accepted");
    require(oob.error().code == live_routing_error_code_t::module_identity_mismatch,
            "out-of-bounds snapshot did not return module_identity_mismatch");
    require(snapshot_calls.load(std::memory_order_relaxed) == 1U,
            "out-of-bounds snapshot reached the fake backend");

    req.address = 0x0000000140000000ULL;
    req.cancellation = protocol::cancellation_token_t::create(true);
    const auto cancelled = routing.capture_bounded_snapshot(req);
    require(!cancelled.has_value() &&
            cancelled.error().code == live_routing_error_code_t::snapshot_cancelled,
            "cancelled snapshot request was not rejected");
    require(snapshot_calls.load(std::memory_order_relaxed) == 1U,
            "cancelled snapshot request reached the fake backend");

    req.cancellation = protocol::cancellation_token_t::create(false);
    req.deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
    const auto expired = routing.capture_bounded_snapshot(req);
    require(!expired.has_value() &&
            expired.error().code == live_routing_error_code_t::snapshot_deadline_exceeded,
            "expired snapshot request was not rejected");
    require(snapshot_calls.load(std::memory_order_relaxed) == 1U,
            "expired snapshot request reached the fake backend");

    req.deadline.reset();
    req.expected_generation = 999U;
    const auto stale = routing.capture_bounded_snapshot(req);
    require(!stale.has_value() &&
            stale.error().code == live_routing_error_code_t::target_not_resolved,
            "stale snapshot generation was accepted");
    require(snapshot_calls.load(std::memory_order_relaxed) == 1U,
            "stale snapshot generation reached the fake backend");

    std::atomic_uint32_t mismatch_mode{0};
    std::atomic_uint32_t mismatch_calls{0};
    live_snapshot_handler_t mismatched_reader = [&mismatch_mode, &mismatch_calls](
        const adapter_call_context_t& context,
        const bounded_live_snapshot_request_t& request) {
        mismatch_calls.fetch_add(1, std::memory_order_relaxed);
        const auto& target = context.target->target();
        bounded_live_snapshot_t result;
        result.bytes.assign(static_cast<std::size_t>(request.size), 0x5aU);
        result.process_creation_identity = target.process_creation_identity;
        result.attach_generation = target.attach_generation;
        result.generation = target.generation;
        const auto mode = mismatch_mode.load(std::memory_order_relaxed);
        if (mode == 0U) ++result.process_creation_identity;
        else if (mode == 1U) ++result.attach_generation;
        else ++result.generation;
        return adapter_result_t<bounded_live_snapshot_t>::success(std::move(result));
    };
    live_routing_integration_t mismatched_routing(
        resolver, lock_manager, lane, limits, std::move(mismatched_reader));
    req.expected_generation = 1U;
    for (std::uint32_t mode = 0; mode < 3U; ++mode) {
        mismatch_mode.store(mode, std::memory_order_relaxed);
        const auto mismatch = mismatched_routing.capture_bounded_snapshot(req);
        require(!mismatch.has_value() &&
                mismatch.error().code == live_routing_error_code_t::process_identity_mismatch,
                "mismatched fake snapshot identity was accepted");
    }
    require(mismatch_calls.load(std::memory_order_relaxed) == 3U &&
            mismatched_routing.completed_snapshot_requests() == 0U,
            "mismatched fake snapshots were counted as completed");
}

void verify_debugger_lane_serialization() {
    target_resolver_t resolver;
    effect_lock_manager_t lock_manager;
    auto adapter = std::make_unique<fake_debugger_adapter_t>();
    debugger_lane_t lane(*adapter);

    auto record = make_live_target(1, 4242U, 0xDEADBEEFCAFEULL,
                                    0x0000000140000000ULL, 0x8000U);
    resolver.publish(record);

    live_routing_integration_t routing(resolver, lock_manager, lane);

    live_routing_invocation_context_t ctx;
    ctx.contract_name = "dbg_status";
    ctx.effect = contract_effect_t::debugger_read;

    auto result1 = routing.dispatch_debugger(ctx, protocol::json::object());
    require(result1.has_value(), "first debugger dispatch failed");

    auto result2 = routing.dispatch_debugger(ctx, protocol::json::object());
    require(result2.has_value(), "second debugger dispatch failed");

    require(routing.completed_debugger_requests() >= 2U,
            "debugger request counter did not track completions");
}

void verify_static_mutation_blocked_from_live_write() {
    target_resolver_t resolver;
    effect_lock_manager_t lock_manager;
    auto adapter = std::make_unique<fake_debugger_adapter_t>();
    debugger_lane_t lane(*adapter);

    auto record = make_live_target(1, 4242U, 0xDEADBEEFCAFEULL,
                                    0x0000000140000000ULL, 0x8000U);
    resolver.publish(record);

    live_routing_integration_t routing(resolver, lock_manager, lane);

    auto block = routing.verify_static_mutation_safety(
        "dbg_write", contract_effect_t::workspace_overlay_mutation);
    require(!block.has_value(),
            "static mutation handler was allowed to perform live write");
    require(block.error().code ==
            live_routing_error_code_t::static_mutation_blocked_live_write,
            "static mutation block did not return correct error code");

    require(routing.blocked_static_mutations() >= 1U,
            "blocked mutation counter did not track the rejection");
}

void verify_stale_generation_rejected() {
    target_resolver_t resolver;
    effect_lock_manager_t lock_manager;
    auto adapter = std::make_unique<fake_debugger_adapter_t>();
    debugger_lane_t lane(*adapter);

    auto record = make_live_target(1, 4242U, 0xDEADBEEFCAFEULL,
                                    0x0000000140000000ULL, 0x8000U);
    resolver.publish(record);

    live_routing_integration_t routing(resolver, lock_manager, lane);

    target_selector_t selector;
    selector.pid = 4242U;

    auto stale_bind = routing.bind_identity(selector, 999U);
    require(!stale_bind.has_value(),
            "stale generation binding was accepted");
    require(stale_bind.error().code == live_routing_error_code_t::target_not_resolved,
            "stale generation binding did not return target_not_resolved");
}

void verify_unsupported_effect_rejected() {
    target_resolver_t resolver;
    effect_lock_manager_t lock_manager;
    auto adapter = std::make_unique<fake_debugger_adapter_t>();
    debugger_lane_t lane(*adapter);

    live_routing_integration_t routing(resolver, lock_manager, lane);

    live_routing_invocation_context_t ctx;
    ctx.contract_name = "dbg_status";
    ctx.effect = contract_effect_t::isolated_python;

    auto result = routing.dispatch_debugger(ctx, protocol::json::object());
    require(!result.has_value(), "unsupported effect was accepted for debugger dispatch");
    require(result.error().code == live_routing_error_code_t::unsupported_live_effect,
            "unsupported effect did not return correct error code");
}

void verify_live_target_detection() {
    target_resolver_t resolver;
    effect_lock_manager_t lock_manager;
    auto adapter = std::make_unique<fake_debugger_adapter_t>();
    debugger_lane_t lane(*adapter);

    auto record = make_live_target(1, 4242U, 0xDEADBEEFCAFEULL,
                                    0x0000000140000000ULL, 0x8000U);
    resolver.publish(record);

    target_record_t static_record;
    static_record.target_id = 2;
    static_record.pid = 9999U;
    static_record.process_creation_identity = 0xAAAULL;
    static_record.bin_name = "static_target.exe";
    static_record.generation = 1;
    static_record.live = false;
    resolver.publish(static_record);

    live_routing_integration_t routing(resolver, lock_manager, lane);

    target_selector_t live_sel;
    live_sel.pid = 4242U;
    require(routing.is_live_target(live_sel), "live target was not detected as live");

    target_selector_t static_sel;
    static_sel.pid = 9999U;
    require(!routing.is_live_target(static_sel), "static target was detected as live");

    target_selector_t missing_sel;
    missing_sel.pid = 12345U;
    require(!routing.is_live_target(missing_sel), "missing target was detected as live");
}

}

void run_live_routing_integration_harness() {
    verify_identity_binding();
    verify_bounded_snapshot_enforcement();
    verify_debugger_lane_serialization();
    verify_static_mutation_blocked_from_live_write();
    verify_stale_generation_rejected();
    verify_unsupported_effect_rejected();
    verify_live_target_detection();
}

}

int main() {
    try {
        aida::standalone::mcp::compat::test::run_live_routing_integration_harness();
        std::cout << "live_routing_integration_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
