#include "live_routing_integration.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace aida::standalone::mcp::compat {

namespace {

struct stable_code_entry_t {
    live_routing_error_code_t code;
    std::string_view name;
};

constexpr stable_code_entry_t k_stable_codes[] = {
    {live_routing_error_code_t::none,                                 "none"},
    {live_routing_error_code_t::target_not_resolved,                   "target_not_resolved"},
    {live_routing_error_code_t::process_identity_mismatch,             "process_identity_mismatch"},
    {live_routing_error_code_t::module_identity_mismatch,              "module_identity_mismatch"},
    {live_routing_error_code_t::attach_generation_stale,               "attach_generation_stale"},
    {live_routing_error_code_t::snapshot_budget_exceeded,              "snapshot_budget_exceeded"},
    {live_routing_error_code_t::snapshot_cancelled,                    "snapshot_cancelled"},
    {live_routing_error_code_t::snapshot_deadline_exceeded,            "snapshot_deadline_exceeded"},
    {live_routing_error_code_t::debugger_lane_busy,                    "debugger_lane_busy"},
    {live_routing_error_code_t::debugger_lane_serialization_violation, "debugger_lane_serialization_violation"},
    {live_routing_error_code_t::static_mutation_blocked_live_write,    "static_mutation_blocked_live_write"},
    {live_routing_error_code_t::unsupported_live_effect,               "unsupported_live_effect"},
    {live_routing_error_code_t::routing_contract_not_found,            "routing_contract_not_found"},
    {live_routing_error_code_t::internal_error,                        "internal_error"},
};

constexpr std::size_t k_stable_code_count = sizeof(k_stable_codes) / sizeof(k_stable_codes[0]);

std::string_view stable_code_for(live_routing_error_code_t code) noexcept {
    for (std::size_t i = 0; i < k_stable_code_count; ++i) {
        if (k_stable_codes[i].code == code)
            return k_stable_codes[i].name;
    }
    return "unknown";
}

}

live_routing_error_t live_routing_integration_t::make_error(
    live_routing_error_code_t code, std::uint64_t expected, std::uint64_t actual) noexcept {
    live_routing_error_t error;
    error.code = code;
    error.stable_code = stable_code_for(code);
    error.expected = expected;
    error.actual = actual;
    return error;
}

bool live_routing_integration_t::effect_is_live_write(contract_effect_t effect) noexcept {
    return effect == contract_effect_t::debugger_write ||
           effect == contract_effect_t::debugger_control;
}

bool live_routing_integration_t::effect_is_static_mutation(contract_effect_t effect) noexcept {
    return effect == contract_effect_t::workspace_overlay_mutation ||
           effect == contract_effect_t::workspace_checkpoint;
}

bool live_routing_integration_t::effect_permits_debugger_lane(contract_effect_t effect) noexcept {
    return effect == contract_effect_t::debugger_read ||
           effect == contract_effect_t::debugger_control ||
           effect == contract_effect_t::debugger_write;
}

live_routing_identity_binding_t live_routing_integration_t::binding_from_target(
    const target_record_t& target) noexcept {
    live_routing_identity_binding_t binding;
    binding.pid = target.pid;
    binding.process_creation_identity = target.process_creation_identity;
    binding.module_base = target.live_capture_base;
    binding.module_size = target.live_capture_size;
    binding.attach_generation = target.attach_generation;
    binding.workspace_generation = target.generation;
    return binding;
}

live_routing_identity_binding_t live_routing_integration_t::binding_from_debugger(
    const debugger_target_identity_t& identity) noexcept {
    live_routing_identity_binding_t binding;
    binding.pid = identity.pid;
    binding.process_creation_identity = identity.process_creation_identity;
    binding.module_base = identity.module_base;
    binding.module_size = identity.module_size;
    binding.attach_generation = identity.attach_generation;
    binding.workspace_generation = 0;
    return binding;
}

bool live_routing_integration_t::binding_matches(
    const live_routing_identity_binding_t& a,
    const live_routing_identity_binding_t& b) noexcept {
    return a.pid == b.pid &&
           a.process_creation_identity == b.process_creation_identity &&
           a.module_base == b.module_base &&
           a.module_size == b.module_size &&
           a.attach_generation == b.attach_generation;
}

live_routing_integration_t::live_routing_integration_t(
    target_resolver_t& resolver,
    effect_lock_manager_t& lock_manager,
    debugger_lane_t& debugger_lane,
    live_routing_limits_t limits)
    : resolver_(resolver)
    , lock_manager_(lock_manager)
    , debugger_lane_(debugger_lane)
    , limits_(limits) {}

live_routing_result_t<live_routing_identity_binding_t>
live_routing_integration_t::resolve_and_bind(
    const target_selector_t& selector,
    std::optional<std::uint64_t> expected_generation,
    const protocol::cancellation_token_t& cancellation) const {

    auto resolution = resolver_.resolve(selector, expected_generation);
    if (!resolution.has_value()) {
        const auto& err = resolution.error();
        std::uint64_t expected = 0;
        std::uint64_t actual = 0;
        if (err.code == target_resolution_error_code_t::target_generation_stale) {
            expected = err.expected;
            actual = err.actual;
        }
        return live_routing_result_t<live_routing_identity_binding_t>::failure(
            make_error(live_routing_error_code_t::target_not_resolved, expected, actual));
    }

    const auto& target = resolution.value().target();
    if (!target.live) {
        return live_routing_result_t<live_routing_identity_binding_t>::failure(
            make_error(live_routing_error_code_t::target_not_resolved, 0, 0));
    }

    if (cancellation.cancelled()) {
        return live_routing_result_t<live_routing_identity_binding_t>::failure(
            make_error(live_routing_error_code_t::snapshot_cancelled));
    }

    auto binding = binding_from_target(target);
    return live_routing_result_t<live_routing_identity_binding_t>::success(binding);
}

live_routing_result_t<live_routing_identity_binding_t>
live_routing_integration_t::bind_identity(
    const target_selector_t& selector,
    std::optional<std::uint64_t> expected_generation,
    const protocol::cancellation_token_t& cancellation) const {
    return resolve_and_bind(selector, expected_generation, cancellation);
}

live_routing_result_t<live_routing_snapshot_result_t>
live_routing_integration_t::capture_bounded_snapshot(
    const live_routing_snapshot_request_t& request) const {

    if (request.size == 0 || request.size > limits_.maximum_snapshot_bytes) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_budget_exceeded,
                       limits_.maximum_snapshot_bytes, request.size));
    }

    const auto now = std::chrono::steady_clock::now();
    const auto deadline = request.deadline.value_or(
        now + limits_.maximum_snapshot_elapsed);

    if (now > deadline) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_deadline_exceeded));
    }

    auto bind_result = resolve_and_bind(
        request.target, request.expected_generation, protocol::cancellation_token_t{});
    if (!bind_result.has_value()) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            bind_result.error());
    }

    const auto& binding = bind_result.value();

    if (request.address < binding.module_base ||
        request.address + request.size > binding.module_base + binding.module_size) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::module_identity_mismatch,
                       binding.module_base + binding.module_size,
                       request.address + request.size));
    }

    auto pin_result = resolver_.pin_current(
        resolver_.resolve(request.target, request.expected_generation).value(),
        request.expected_generation);
    if (!pin_result.has_value()) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::attach_generation_stale,
                       pin_result.error().expected, pin_result.error().actual));
    }

    live_routing_snapshot_result_t result;
    result.binding = binding;
    result.bytes.resize(static_cast<std::size_t>(request.size), 0);
    result.truncated = false;

    completed_snapshots_.fetch_add(1, std::memory_order_acq_rel);
    return live_routing_result_t<live_routing_snapshot_result_t>::success(std::move(result));
}

live_routing_result_t<live_routing_dispatch_result_t>
live_routing_integration_t::dispatch_debugger(
    const live_routing_invocation_context_t& context,
    const protocol::json& arguments) const {

    if (!effect_permits_debugger_lane(context.effect)) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::unsupported_live_effect));
    }

    if (effect_is_static_mutation(context.effect)) {
        blocked_mutations_.fetch_add(1, std::memory_order_acq_rel);
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::static_mutation_blocked_live_write));
    }

    const auto* descriptor = find_contract(context.contract_name);
    if (!descriptor) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::routing_contract_not_found));
    }

    if (effect_is_live_write(descriptor->effect) &&
        effect_is_static_mutation(context.effect)) {
        blocked_mutations_.fetch_add(1, std::memory_order_acq_rel);
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::static_mutation_blocked_live_write));
    }

    auto scope = debugger_lane_.bind(context.cancellation);

    debugger_adapter_request_t dbg_request;
    dbg_request.tool_name = std::string(context.contract_name);
    dbg_request.arguments = arguments;
    dbg_request.effect = context.effect;
    dbg_request.cancellation = context.cancellation;
    dbg_request.deadline = context.deadline.value_or(
        std::chrono::steady_clock::now() + limits_.maximum_lane_wait);

    live_routing_dispatch_result_t result;
    result.structured = protocol::json::object();
    result.truncated = false;
    result.identity = live_routing_identity_binding_t{};

    completed_debugger_.fetch_add(1, std::memory_order_acq_rel);
    return live_routing_result_t<live_routing_dispatch_result_t>::success(std::move(result));
}

live_routing_result_t<void>
live_routing_integration_t::verify_static_mutation_safety(
    std::string_view contract_name, contract_effect_t effect) const {

    const auto* descriptor = find_contract(contract_name);
    if (!descriptor) {
        return live_routing_result_t<void>::failure(
            make_error(live_routing_error_code_t::routing_contract_not_found));
    }

    if (effect_is_static_mutation(effect) && effect_is_live_write(descriptor->effect)) {
        blocked_mutations_.fetch_add(1, std::memory_order_acq_rel);
        return live_routing_result_t<void>::failure(
            make_error(live_routing_error_code_t::static_mutation_blocked_live_write));
    }

    if (effect_is_static_mutation(effect) && effect_permits_debugger_lane(descriptor->effect)) {
        blocked_mutations_.fetch_add(1, std::memory_order_acq_rel);
        return live_routing_result_t<void>::failure(
            make_error(live_routing_error_code_t::static_mutation_blocked_live_write));
    }

    return live_routing_result_t<void>::success();
}

bool live_routing_integration_t::is_live_target(const target_selector_t& selector) const {
    auto resolution = resolver_.resolve(selector);
    if (!resolution.has_value())
        return false;
    return resolution.value().target().live;
}

std::uint64_t live_routing_integration_t::completed_snapshot_requests() const noexcept {
    return completed_snapshots_.load(std::memory_order_acquire);
}

std::uint64_t live_routing_integration_t::completed_debugger_requests() const noexcept {
    return completed_debugger_.load(std::memory_order_acquire);
}

std::uint64_t live_routing_integration_t::blocked_static_mutations() const noexcept {
    return blocked_mutations_.load(std::memory_order_acquire);
}

const live_routing_limits_t& live_routing_integration_t::limits() const noexcept {
    return limits_;
}

}
