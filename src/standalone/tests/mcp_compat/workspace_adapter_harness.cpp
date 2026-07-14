#include "workspace_adapter_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/workspace_adapter.hpp"

#include <chrono>
#include <cstdint>
#include <future>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;

void require(bool condition, std::string_view message) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

target_record_t make_static_target(std::uint64_t target_id, std::uint32_t pid,
                                   std::uint64_t process_creation_identity,
                                   std::string bin_name, std::uint64_t generation) {
    target_record_t target;
    target.target_id = target_id;
    target.pid = pid;
    target.process_creation_identity = process_creation_identity;
    target.bin_name = std::move(bin_name);
    target.generation = generation;
    target.attach_generation = generation + 0x1000ULL;
    return target;
}

target_record_t make_live_target(std::uint64_t target_id, std::uint32_t pid,
                                 std::uint64_t process_creation_identity,
                                 bool snapshot_permitted) {
    auto target = make_static_target(target_id, pid, process_creation_identity, "live-target.exe", 0x51ULL);
    target.live = true;
    target.live_capture_base = 0x180001000ULL;
    target.live_capture_size = 0x100ULL;
    target.live_snapshot_permitted = snapshot_permitted;
    target.live_snapshot_maximum_bytes = snapshot_permitted ? 8ULL : 0ULL;
    return target;
}

adapter_result_t<adapter_response_t> response(std::string payload) {
    return adapter_result_t<adapter_response_t>::success({std::move(payload), false});
}

void verify_target_resolution() {
    target_resolver_t resolver;
    require(static_cast<bool>(resolver.publish(make_static_target(1, 101, 0x1001, "Alpha.exe", 7))),
            "initial target publication failed");
    require(static_cast<bool>(resolver.publish(make_static_target(2, 202, 0x2002, "AlphaTools.exe", 9))),
            "second target publication failed");

    const auto unresolved = resolver.resolve({});
    require(!unresolved &&
                unresolved.error().code == target_resolution_error_code_t::target_selection_required,
            "implicit multi-target resolution was not rejected");

    target_selector_t substring_selector;
    substring_selector.bin_name = "alpha";
    const auto ambiguous = resolver.resolve(substring_selector);
    require(!ambiguous && ambiguous.error().code == target_resolution_error_code_t::target_ambiguous,
            "ambiguous binary-name resolution was not rejected");

    target_selector_t exact_name_selector;
    exact_name_selector.bin_name = R"(C:\fixtures\ALPHATOOLS.EXE)";
    const auto named = resolver.resolve(exact_name_selector, 9);
    require(named && named.value().target().target_id == 2,
            "binary-name resolution did not select the requested target");

    target_selector_t pid_selector;
    pid_selector.pid = 101;
    auto resolved = resolver.resolve(pid_selector, 7);
    require(resolved && resolved.value().target().target_id == 1,
            "pid resolution did not select the requested target");
    const auto stale_resolution = std::move(resolved).take_value();

    require(static_cast<bool>(resolver.publish(make_static_target(1, 101, 0x1001, "Alpha.exe", 8))),
            "generation update publication failed");
    const auto stale = resolver.validate_current(stale_resolution, 7);
    require(!stale && stale.error.code == target_resolution_error_code_t::target_generation_stale,
            "stale generation was accepted");

    target_resolver_t pid_reuse_resolver;
    require(static_cast<bool>(pid_reuse_resolver.publish(make_static_target(11, 303, 0x3003, "first.exe", 3))),
            "pid reuse fixture first publication failed");
    target_selector_t reused_pid_selector;
    reused_pid_selector.pid = 303;
    auto old_resolution = pid_reuse_resolver.resolve(reused_pid_selector);
    require(static_cast<bool>(old_resolution), "pid reuse fixture first resolution failed");
    const auto old_target = std::move(old_resolution).take_value();
    require(static_cast<bool>(pid_reuse_resolver.publish(make_static_target(12, 303, 0x4004, "second.exe", 4))),
            "pid reuse fixture replacement publication failed");
    const auto reused = pid_reuse_resolver.validate_current(old_target);
    require(!reused && reused.error.code == target_resolution_error_code_t::target_pid_reused,
            "reused pid was accepted as the original process");
}

void verify_effect_policy() {
    const auto* query_contract = find_contract("get_bytes");
    const auto* overlay_contract = find_contract("rename");
    const auto* debugger_contract = find_contract("dbg_status");
    const auto* python_contract = find_contract("py_exec_file");
    require(query_contract != nullptr && overlay_contract != nullptr && debugger_contract != nullptr &&
                python_contract != nullptr,
            "required compatibility contracts are missing");
    const auto query_policy = effect_policy_for(*query_contract);
    const auto overlay_policy = effect_policy_for(*overlay_contract);
    const auto debugger_policy = effect_policy_for(*debugger_contract);
    const auto python_policy = effect_policy_for(*python_contract);
    require(query_policy && overlay_policy && debugger_policy && python_policy,
            "generated contract effect policy was rejected");
    require(query_policy.value().mode == effect_lock_mode_t::shared &&
                overlay_policy.value().mode == effect_lock_mode_t::unique &&
                debugger_policy.value().mode == effect_lock_mode_t::effect &&
                debugger_policy.value().contract_lock == contract_lock_t::debugger_lane &&
                python_policy.value().mode == effect_lock_mode_t::effect &&
                python_policy.value().contract_lock == contract_lock_t::python_worker,
            "shared unique effect policy classification changed");

    effect_lock_manager_t locks;
    auto query_lease = locks.acquire(query_policy.value(), 41);
    require(static_cast<bool>(query_lease), "workspace shared lock acquisition failed");
    bool overlay_blocked = false;
    std::thread overlay_waiter([&locks, &overlay_policy, &overlay_blocked] {
        auto blocked_overlay = locks.acquire(overlay_policy.value(), 41,
                                             std::chrono::steady_clock::now());
        overlay_blocked = !blocked_overlay &&
            blocked_overlay.error.code == effect_policy_error_code_t::lock_busy;
    });
    overlay_waiter.join();
    require(overlay_blocked,
            "overlay transaction was not blocked by a shared workspace lock");
    auto debugger_lease = locks.acquire(debugger_policy.value(), 41);
    require(static_cast<bool>(debugger_lease), "debugger effect lock acquisition failed");
    auto python_lease = locks.acquire(python_policy.value(), 41);
    require(static_cast<bool>(python_lease),
            "isolated Python lane was blocked by the debugger lane");
    bool debugger_blocked = false;
    std::thread debugger_waiter([&locks, &debugger_policy, &debugger_blocked] {
        auto blocked_debugger = locks.acquire(debugger_policy.value(), 42,
                                              std::chrono::steady_clock::now());
        debugger_blocked = !blocked_debugger &&
            blocked_debugger.error.code == effect_policy_error_code_t::lock_busy;
    });
    debugger_waiter.join();
    require(debugger_blocked,
            "global debugger effect lane admitted concurrent control");
    bool python_blocked = false;
    std::thread python_waiter([&locks, &python_policy, &python_blocked] {
        auto blocked_python = locks.acquire(python_policy.value(), 42,
                                            std::chrono::steady_clock::now());
        python_blocked = !blocked_python &&
            blocked_python.error.code == effect_policy_error_code_t::lock_busy;
    });
    python_waiter.join();
    require(python_blocked,
            "global isolated Python lane admitted concurrent execution");
}

void verify_workspace_adapter() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(make_static_target(21, 404, 0x5005, "adapter.exe", 11))),
            "adapter target publication failed");

    std::uint32_t query_calls = 0;
    std::uint32_t overlay_calls = 0;
    std::uint32_t analysis_calls = 0;
    std::uint32_t decompile_calls = 0;
    std::uint32_t checkpoint_calls = 0;
    std::uint32_t debugger_calls = 0;
    std::uint32_t isolated_python_calls = 0;
    bool schedule_generation_update = false;
    std::future<target_resolver_status_t> generation_update;
    workspace_adapter_handlers_t handlers;
    handlers.query = [&resolver, &query_calls, &schedule_generation_update, &generation_update](
                         const adapter_call_context_t& context, const adapter_request_t&) {
        ++query_calls;
        require(context.contract != nullptr && context.target.has_value(),
                "query adapter context was not target-bound");
        if (schedule_generation_update) {
            require(!generation_update.valid(),
                    "target generation publication was scheduled more than once");
            const auto target = context.target->target();
            std::promise<void> publication_started;
            auto publication_started_future = publication_started.get_future();
            generation_update = std::async(
                std::launch::async,
                [&resolver, target, publication_started = std::move(publication_started)]() mutable {
                    publication_started.set_value();
                    return resolver.publish(make_static_target(
                        target.target_id, target.pid, target.process_creation_identity,
                        target.bin_name, target.generation + 1));
                });
            publication_started_future.wait();
            require(generation_update.wait_for(std::chrono::milliseconds(50)) ==
                        std::future_status::timeout,
                    "target generation changed while the adapter handler was executing");
        }
        return response("query");
    };
    handlers.overlay = [&overlay_calls](const adapter_call_context_t& context, const adapter_request_t&) {
        ++overlay_calls;
        require(context.effect.mode == effect_lock_mode_t::unique,
                "overlay adapter did not receive a unique workspace lease");
        return response("overlay");
    };
    handlers.analysis = [&analysis_calls](const adapter_call_context_t&, const adapter_request_t&) {
        ++analysis_calls;
        return response("analysis");
    };
    handlers.decompilation = [&decompile_calls](const adapter_call_context_t&, const adapter_request_t&) {
        ++decompile_calls;
        return response("decompilation");
    };
    handlers.checkpoint = [&checkpoint_calls](const adapter_call_context_t& context, const adapter_request_t&) {
        ++checkpoint_calls;
        require(context.effect.mutates_workspace, "checkpoint adapter was not marked mutating");
        return response("checkpoint");
    };
    handlers.debugger = [&debugger_calls](const adapter_call_context_t& context, const adapter_request_t&) {
        ++debugger_calls;
        require(context.effect.mode == effect_lock_mode_t::effect,
                "debugger adapter did not receive the effect lane");
        return response("debugger");
    };
    handlers.isolated_python = [&isolated_python_calls](
                                   const adapter_call_context_t& context,
                                   const adapter_request_t&) {
        ++isolated_python_calls;
        require(context.contract != nullptr && context.contract->name == "py_exec_file" &&
                    context.effect.contract_lock == contract_lock_t::python_worker,
                "isolated Python adapter did not receive its generated worker contract");
        return response("isolated_python");
    };
    workspace_adapter_t adapter(resolver, locks, std::move(handlers));

    adapter_request_t request;
    request.target.pid = 404;
    request.expected_generation = 11;
    require(adapter.query("get_bytes", request) && query_calls == 1,
            "workspace query adapter did not dispatch");
    require(adapter.overlay("rename", request) && overlay_calls == 1,
            "workspace overlay adapter did not dispatch");
    require(adapter.analyze("analyze_function", request) && analysis_calls == 1,
            "analysis adapter did not dispatch");
    require(adapter.decompile("decompile", request) && decompile_calls == 1,
            "decompilation adapter did not dispatch");
    require(adapter.checkpoint("idb_save", request) && checkpoint_calls == 1,
            "checkpoint adapter did not dispatch");
    require(adapter.debug("dbg_status", request) && debugger_calls == 1,
            "debugger adapter did not dispatch");
    require(!adapter.overlay("get_bytes", request),
            "workspace read contract was accepted as an overlay mutation");

    adapter_request_t name_request;
    name_request.target.bin_name = R"(C:\workspace\ADAPTER.EXE)";
    name_request.expected_generation = 11;
    require(adapter.query("get_bytes", name_request) && query_calls == 2,
            "workspace adapter did not route a normalized binary name");
    require(adapter.execute_isolated_python("py_exec_file", name_request) &&
                isolated_python_calls == 1,
            "isolated Python adapter did not dispatch through its runtime lane");

    schedule_generation_update = true;
    const auto pinned = adapter.query("get_bytes", request);
    require(pinned && query_calls == 3,
            "execution-pinned adapter query did not complete");
    require(generation_update.valid() &&
                generation_update.wait_for(std::chrono::seconds(2)) == std::future_status::ready,
            "target publication did not resume after the adapter execution pin released");
    require(static_cast<bool>(generation_update.get()),
            "deferred target generation publication failed");
    schedule_generation_update = false;
    const auto stale = adapter.query("get_bytes", request);
    require(!stale && stale.error().stable_code == "target_generation_stale" && query_calls == 3,
            "adapter dispatched after its pinned target generation changed");
}

void verify_live_snapshot_bounds() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(make_live_target(31, 505, 0x6006, false))),
            "live denial fixture publication failed");

    std::uint32_t snapshot_calls = 0;
    workspace_adapter_handlers_t handlers;
    handlers.live_snapshot = [&snapshot_calls](const adapter_call_context_t& context,
                                                const bounded_live_snapshot_request_t& request) {
        ++snapshot_calls;
        const auto& target = context.target->target();
        bounded_live_snapshot_t snapshot;
        snapshot.bytes.assign(static_cast<std::size_t>(request.size), 0xa5U);
        snapshot.process_creation_identity = target.process_creation_identity;
        snapshot.attach_generation = target.attach_generation;
        snapshot.generation = target.generation;
        return adapter_result_t<bounded_live_snapshot_t>::success(std::move(snapshot));
    };
    workspace_adapter_t adapter(resolver, locks, std::move(handlers), {16});

    bounded_live_snapshot_request_t request;
    request.target.pid = 505;
    request.expected_generation = 0x51ULL;
    request.address = 0x180001000ULL;
    request.size = 4;
    const auto denied = adapter.capture_live_snapshot(request);
    require(!denied && denied.error().code == adapter_error_code_t::live_snapshot_denied &&
                snapshot_calls == 0,
            "live snapshot denial did not fail closed before backend invocation");

    require(static_cast<bool>(resolver.publish(make_live_target(31, 505, 0x6006, true))),
            "live permission update publication failed");
    request.size = 9;
    const auto oversized = adapter.capture_live_snapshot(request);
    require(!oversized && oversized.error().code == adapter_error_code_t::live_snapshot_bounds &&
                snapshot_calls == 0,
            "per-target live snapshot bound was not enforced");

    request.size = 4;
    const auto captured = adapter.capture_live_snapshot(request);
    require(captured && captured.value().bytes.size() == 4 && snapshot_calls == 1,
            "bounded live snapshot was not captured through the debugger effect lane");
}

}

bool run_workspace_adapter_harness(std::string& failure) {
    try {
        verify_target_resolution();
        verify_effect_policy();
        verify_workspace_adapter();
        verify_live_snapshot_bounds();
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
