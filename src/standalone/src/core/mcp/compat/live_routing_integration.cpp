#include "live_routing_integration.hpp"

#include <algorithm>
#include <exception>
#include <limits>
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
    {live_routing_error_code_t::debugger_request_invalid,              "debugger_request_invalid"},
    {live_routing_error_code_t::debugger_cancelled,                    "debugger_cancelled"},
    {live_routing_error_code_t::debugger_deadline_exceeded,            "debugger_deadline_exceeded"},
    {live_routing_error_code_t::debugger_adapter_rejected,             "debugger_adapter_rejected"},
};

constexpr std::size_t k_stable_code_count = sizeof(k_stable_codes) / sizeof(k_stable_codes[0]);

std::string_view stable_code_for(live_routing_error_code_t code) noexcept {
    for (std::size_t i = 0; i < k_stable_code_count; ++i) {
        if (k_stable_codes[i].code == code)
            return k_stable_codes[i].name;
    }
    return "unknown";
}

std::optional<std::uint64_t> unsigned_integer(const protocol::json& value) noexcept {
    try {
        if (value.is_number_unsigned()) {
            return value.get<std::uint64_t>();
        }
        if (value.is_number_integer()) {
            const auto signed_value = value.get<std::int64_t>();
            if (signed_value >= 0) {
                return static_cast<std::uint64_t>(signed_value);
            }
        }
    } catch (const std::exception&) {
    }
    return std::nullopt;
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
    return effect == contract_effect_t::debugger_write;
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
    binding.target_id = target.target_id;
    binding.pid = target.pid;
    binding.process_creation_identity = target.process_creation_identity;
    binding.module_base = target.live_capture_base;
    binding.module_size = target.live_capture_size;
    binding.attach_generation = target.attach_generation;
    binding.workspace_generation = target.generation;
    return binding;
}

live_routing_integration_t::live_routing_integration_t(
    target_resolver_t& resolver,
    effect_lock_manager_t& lock_manager,
    debugger_lane_t& debugger_lane,
    live_routing_limits_t limits,
    live_snapshot_handler_t snapshot_reader)
    : resolver_(resolver)
    , lock_manager_(lock_manager)
    , debugger_lane_(debugger_lane)
    , limits_(limits)
    , snapshot_reader_(std::move(snapshot_reader)) {}

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
    const auto completed = completed_snapshots_.load(std::memory_order_acquire);
    if (completed >= limits_.maximum_snapshots_per_request) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_budget_exceeded,
                       limits_.maximum_snapshots_per_request, completed));
    }
    if (request.size == 0 || request.size > limits_.maximum_snapshot_bytes) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_budget_exceeded,
                       limits_.maximum_snapshot_bytes, request.size));
    }

    const auto now = std::chrono::steady_clock::now();
    const auto maximum_deadline = now + limits_.maximum_snapshot_elapsed;
    const auto deadline = request.deadline
        ? (std::min)(*request.deadline, maximum_deadline)
        : maximum_deadline;
    if (request.cancellation.cancelled()) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_cancelled));
    }
    if (now >= deadline) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_deadline_exceeded));
    }

    auto resolution = resolver_.resolve(request.target, request.expected_generation);
    if (!resolution) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::target_not_resolved,
                       resolution.error().expected, resolution.error().actual));
    }
    auto target = std::move(resolution).take_value();
    const auto& resolved = target.target();
    if (!resolved.live || !resolved.live_snapshot_permitted ||
        resolved.live_snapshot_maximum_bytes == 0) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::target_not_resolved));
    }
    const auto maximum_bytes = (std::min)(
        limits_.maximum_snapshot_bytes, resolved.live_snapshot_maximum_bytes);
    if (request.size > maximum_bytes) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_budget_exceeded,
                       maximum_bytes, request.size));
    }
    if (request.address < resolved.live_capture_base) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::module_identity_mismatch,
                       resolved.live_capture_base, request.address));
    }
    const auto module_offset = request.address - resolved.live_capture_base;
    if (module_offset > resolved.live_capture_size ||
        request.size > resolved.live_capture_size - module_offset) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::module_identity_mismatch,
                       resolved.live_capture_size, module_offset));
    }
    if (!snapshot_reader_) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::internal_error));
    }

    const effect_lock_policy_t policy{
        contract_effect_t::debugger_read,
        contract_lock_t::debugger_lane,
        effect_lock_mode_t::effect,
        true,
        false,
    };
    auto lease = lock_manager_.acquire(policy, resolved.target_id, deadline);
    if (!lease) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::debugger_lane_busy));
    }

    auto pin_result = resolver_.pin_current(target, request.expected_generation);
    if (!pin_result) {
        const auto code = pin_result.error.code ==
                target_resolution_error_code_t::target_pid_reused
            ? live_routing_error_code_t::process_identity_mismatch
            : pin_result.error.code ==
                    target_resolution_error_code_t::target_generation_stale
                ? live_routing_error_code_t::attach_generation_stale
                : live_routing_error_code_t::target_not_resolved;
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(code, pin_result.error.expected, pin_result.error.actual));
    }

    const auto& pinned = pin_result.pin.target();
    const adapter_call_context_t call_context{
        nullptr,
        std::optional<target_resolution_t>{pin_result.pin.resolution()},
        policy,
    };
    bounded_live_snapshot_request_t source_request;
    source_request.target = request.target;
    source_request.expected_generation = request.expected_generation;
    source_request.address = request.address;
    source_request.size = request.size;
    source_request.deadline = deadline;
    auto source = snapshot_reader_(call_context, source_request);
    if (!source) {
        const auto code = source.error().code == adapter_error_code_t::live_snapshot_bounds
            ? live_routing_error_code_t::module_identity_mismatch
            : source.error().code == adapter_error_code_t::live_snapshot_invalid
                ? live_routing_error_code_t::process_identity_mismatch
                : source.error().code == adapter_error_code_t::live_snapshot_denied
                    ? live_routing_error_code_t::target_not_resolved
                    : live_routing_error_code_t::internal_error;
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(code, source.error().expected, source.error().actual));
    }
    if (request.cancellation.cancelled()) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_cancelled));
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::snapshot_deadline_exceeded));
    }
    auto snapshot = std::move(source).take_value();
    if (snapshot.bytes.size() != request.size ||
        snapshot.process_creation_identity != pinned.process_creation_identity ||
        snapshot.attach_generation != pinned.attach_generation ||
        snapshot.generation != pinned.generation) {
        return live_routing_result_t<live_routing_snapshot_result_t>::failure(
            make_error(live_routing_error_code_t::process_identity_mismatch,
                       pinned.process_creation_identity,
                       snapshot.process_creation_identity));
    }

    live_routing_snapshot_result_t result;
    result.binding = binding_from_target(pinned);
    result.bytes = std::move(snapshot.bytes);
    result.truncated = false;

    completed_snapshots_.fetch_add(1, std::memory_order_acq_rel);
    return live_routing_result_t<live_routing_snapshot_result_t>::success(std::move(result));
}

live_routing_result_t<live_routing_dispatch_result_t>
live_routing_integration_t::dispatch_debugger(
    const live_routing_invocation_context_t& context,
    const protocol::json& arguments) const {

    if (effect_is_static_mutation(context.effect)) {
        blocked_mutations_.fetch_add(1, std::memory_order_acq_rel);
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::static_mutation_blocked_live_write));
    }

    if (!effect_permits_debugger_lane(context.effect)) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::unsupported_live_effect));
    }

    if (!arguments.is_object()) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::debugger_request_invalid));
    }

    const auto* descriptor = find_contract(context.contract_name);
    if (!descriptor) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::routing_contract_not_found));
    }

    if (descriptor->effect != context.effect ||
        descriptor->lock != contract_lock_t::debugger_lane ||
        !effect_permits_debugger_lane(descriptor->effect) ||
        (effect_is_live_write(descriptor->effect) && descriptor->name != "dbg_write")) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::unsupported_live_effect));
    }

    const auto policy = effect_policy_for(*descriptor);
    if (!policy || policy.value().effect != descriptor->effect ||
        policy.value().contract_lock != contract_lock_t::debugger_lane) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::unsupported_live_effect));
    }

    target_selector_t selector;
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        const auto parsed = unsigned_integer(*pid);
        if (!parsed || *parsed == 0 ||
            *parsed > (std::numeric_limits<std::uint32_t>::max)()) {
            return live_routing_result_t<live_routing_dispatch_result_t>::failure(
                make_error(live_routing_error_code_t::debugger_request_invalid));
        }
        selector.pid = static_cast<std::uint32_t>(*parsed);
    }
    if (const auto bin_name = arguments.find("bin_name");
        bin_name != arguments.end()) {
        if (!bin_name->is_string() ||
            bin_name->get_ref<const std::string&>().empty()) {
            return live_routing_result_t<live_routing_dispatch_result_t>::failure(
                make_error(live_routing_error_code_t::debugger_request_invalid));
        }
        selector.bin_name = bin_name->get<std::string>();
    }

    auto resolution = resolver_.resolve(selector, context.expected_generation);
    if (!resolution) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::target_not_resolved,
                       resolution.error().expected, resolution.error().actual));
    }
    auto target = std::move(resolution).take_value();
    if (!target.target().live) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::target_not_resolved));
    }

    const auto now = std::chrono::steady_clock::now();
    const auto maximum_deadline = now + limits_.maximum_lane_wait;
    const auto deadline = context.deadline
        ? (std::min)(*context.deadline, maximum_deadline)
        : maximum_deadline;
    if (context.cancellation.cancelled()) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::debugger_cancelled));
    }
    if (deadline <= now) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::debugger_deadline_exceeded));
    }

    auto lease = lock_manager_.acquire(
        policy.value(), target.target().target_id, deadline);
    if (!lease) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::debugger_lane_busy));
    }

    auto execution_pin = resolver_.pin_current(target, context.expected_generation);
    if (!execution_pin) {
        const auto code = execution_pin.error.code ==
                target_resolution_error_code_t::target_pid_reused
            ? live_routing_error_code_t::process_identity_mismatch
            : execution_pin.error.code ==
                    target_resolution_error_code_t::target_generation_stale
                ? live_routing_error_code_t::attach_generation_stale
                : live_routing_error_code_t::target_not_resolved;
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(code, execution_pin.error.expected,
                       execution_pin.error.actual));
    }

    protocol::json backend_arguments = arguments;
    backend_arguments.erase("pid");
    backend_arguments.erase("bin_name");

    adapter_request_t request;
    request.target = std::move(selector);
    request.expected_generation = context.expected_generation;
    request.deadline = deadline;
    try {
        request.payload = backend_arguments.dump();
    } catch (const std::exception&) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::debugger_request_invalid));
    }

    const adapter_call_context_t adapter_context{
        descriptor,
        std::optional<target_resolution_t>{execution_pin.pin.resolution()},
        policy.value(),
    };
    const auto lane_scope = debugger_lane_.bind(context.cancellation);
    (void)lane_scope;
    auto lane_handler = debugger_lane_.workspace_handler();
    auto executed = lane_handler(adapter_context, request);
    if (!executed) {
        live_routing_error_code_t code =
            live_routing_error_code_t::debugger_adapter_rejected;
        if (executed.error().stable_code == "debugger_pid_reused") {
            code = live_routing_error_code_t::process_identity_mismatch;
        } else if (executed.error().stable_code == "debugger_module_changed") {
            code = live_routing_error_code_t::module_identity_mismatch;
        } else if (executed.error().stable_code ==
                   "debugger_attach_generation_stale") {
            code = live_routing_error_code_t::attach_generation_stale;
        } else if (executed.error().stable_code == "debugger_cancelled") {
            code = live_routing_error_code_t::debugger_cancelled;
        } else if (executed.error().stable_code == "debugger_deadline_exceeded") {
            code = live_routing_error_code_t::debugger_deadline_exceeded;
        } else if (executed.error().stable_code == "debugger_request_rejected" ||
                   executed.error().code == adapter_error_code_t::operation_not_permitted ||
                   executed.error().code == adapter_error_code_t::effect_policy_failed) {
            code = live_routing_error_code_t::debugger_lane_serialization_violation;
        }
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(code, executed.error().expected, executed.error().actual));
    }

    auto adapter_response = std::move(executed).take_value();
    protocol::json structured = protocol::json::parse(
        adapter_response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::debugger_adapter_rejected));
    }
    if (context.cancellation.cancelled()) {
        return live_routing_result_t<live_routing_dispatch_result_t>::failure(
            make_error(live_routing_error_code_t::debugger_cancelled));
    }

    live_routing_dispatch_result_t result;
    result.structured = std::move(structured);
    result.truncated = adapter_response.truncated;
    result.identity = binding_from_target(execution_pin.pin.target());

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

    if (descriptor->effect != effect) {
        blocked_mutations_.fetch_add(1, std::memory_order_acq_rel);
        return live_routing_result_t<void>::failure(
            make_error(effect_is_static_mutation(effect) || effect_is_live_write(effect)
                    ? live_routing_error_code_t::static_mutation_blocked_live_write
                    : live_routing_error_code_t::unsupported_live_effect));
    }
    if (effect_permits_debugger_lane(effect) !=
        (descriptor->lock == contract_lock_t::debugger_lane)) {
        return live_routing_result_t<void>::failure(
            make_error(live_routing_error_code_t::unsupported_live_effect));
    }

    return live_routing_result_t<void>::success();
}

bool live_routing_integration_t::is_live_target(const target_selector_t& selector) const {
    auto resolution = resolver_.resolve(selector);
    if (!resolution)
        return false;
    const auto target = std::move(resolution).take_value();
    return target.target().live;
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
