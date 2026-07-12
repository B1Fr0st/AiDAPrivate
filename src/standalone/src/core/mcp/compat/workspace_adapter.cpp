#include "workspace_adapter.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace aida::standalone::mcp::compat {

namespace {

std::string_view stable_code_for(adapter_error_code_t code) noexcept {
    switch (code) {
    case adapter_error_code_t::none:
        return "ok";
    case adapter_error_code_t::invalid_request:
        return "adapter_request_invalid";
    case adapter_error_code_t::contract_not_found:
        return "adapter_contract_not_found";
    case adapter_error_code_t::operation_not_permitted:
        return "adapter_operation_not_permitted";
    case adapter_error_code_t::target_resolution_failed:
        return "adapter_target_resolution_failed";
    case adapter_error_code_t::effect_policy_failed:
        return "adapter_effect_policy_failed";
    case adapter_error_code_t::effect_lock_busy:
        return "adapter_effect_lock_busy";
    case adapter_error_code_t::backend_unavailable:
        return "adapter_backend_unavailable";
    case adapter_error_code_t::backend_rejected:
        return "adapter_backend_rejected";
    case adapter_error_code_t::live_snapshot_denied:
        return "adapter_live_snapshot_denied";
    case adapter_error_code_t::live_snapshot_bounds:
        return "adapter_live_snapshot_bounds";
    case adapter_error_code_t::live_snapshot_invalid:
        return "adapter_live_snapshot_invalid";
    }
    return "adapter_unknown";
}

}

workspace_adapter_t::workspace_adapter_t(target_resolver_t& resolver,
                                         effect_lock_manager_t& lock_manager,
                                         workspace_adapter_handlers_t handlers,
                                         live_snapshot_limits_t live_snapshot_limits)
    : resolver_(resolver),
      lock_manager_(lock_manager),
      handlers_(std::move(handlers)),
      live_snapshot_limits_(live_snapshot_limits) {}

adapter_error_t workspace_adapter_t::make_error(adapter_error_code_t code, std::uint64_t expected,
                                                std::uint64_t actual) noexcept {
    return {code, stable_code_for(code), expected, actual};
}

adapter_error_t workspace_adapter_t::from_target_error(
    const target_resolution_error_t& error) noexcept {
    return {adapter_error_code_t::target_resolution_failed, error.stable_code,
            error.expected, error.actual};
}

adapter_error_t workspace_adapter_t::from_effect_error(const effect_policy_error_t& error) noexcept {
    const auto code = error.code == effect_policy_error_code_t::lock_busy
        ? adapter_error_code_t::effect_lock_busy
        : adapter_error_code_t::effect_policy_failed;
    return {code, error.stable_code, 0, 0};
}

bool workspace_adapter_t::operation_accepts(adapter_operation_t operation,
                                             contract_effect_t effect) noexcept {
    switch (operation) {
    case adapter_operation_t::query:
        return effect == contract_effect_t::workspace_read ||
            effect == contract_effect_t::registry_read;
    case adapter_operation_t::overlay:
        return effect == contract_effect_t::workspace_overlay_mutation;
    case adapter_operation_t::analysis:
    case adapter_operation_t::decompilation:
        return effect == contract_effect_t::workspace_read;
    case adapter_operation_t::checkpoint:
        return effect == contract_effect_t::workspace_checkpoint;
    case adapter_operation_t::debugger:
        return effect == contract_effect_t::debugger_read ||
            effect == contract_effect_t::debugger_control ||
            effect == contract_effect_t::debugger_write;
    case adapter_operation_t::isolated_python:
        return effect == contract_effect_t::isolated_python;
    }
    return false;
}

bool workspace_adapter_t::request_has_target_selector(const adapter_request_t& request) noexcept {
    return request.target.pid.has_value() || request.target.bin_name.has_value();
}

bool workspace_adapter_t::live_range_contains(const target_record_t& target, std::uint64_t address,
                                               std::uint64_t size) noexcept {
    if (!target.live || target.live_capture_base == 0 || target.live_capture_size == 0 ||
        address < target.live_capture_base || size == 0 ||
        size > (std::numeric_limits<std::uint64_t>::max)() - address) {
        return false;
    }
    return address + size <= target.live_capture_base + target.live_capture_size;
}

const adapter_handler_t* workspace_adapter_t::handler_for(adapter_operation_t operation) const noexcept {
    switch (operation) {
    case adapter_operation_t::query:
        return &handlers_.query;
    case adapter_operation_t::overlay:
        return &handlers_.overlay;
    case adapter_operation_t::analysis:
        return &handlers_.analysis;
    case adapter_operation_t::decompilation:
        return &handlers_.decompilation;
    case adapter_operation_t::checkpoint:
        return &handlers_.checkpoint;
    case adapter_operation_t::debugger:
        return &handlers_.debugger;
    case adapter_operation_t::isolated_python:
        return &handlers_.isolated_python;
    }
    return nullptr;
}

adapter_result_t<adapter_response_t> workspace_adapter_t::execute(
    std::string_view contract_name, adapter_operation_t operation,
    const adapter_request_t& request) const {
    const auto* contract = find_contract(contract_name);
    if (contract == nullptr) {
        return adapter_result_t<adapter_response_t>::failure(
            make_error(adapter_error_code_t::contract_not_found));
    }
    if (!operation_accepts(operation, contract->effect)) {
        return adapter_result_t<adapter_response_t>::failure(
            make_error(adapter_error_code_t::operation_not_permitted));
    }
    const auto policy = effect_policy_for(*contract);
    if (!policy) {
        return adapter_result_t<adapter_response_t>::failure(from_effect_error(policy.error));
    }

    std::optional<target_resolution_t> target;
    if (contract->target_dependent) {
        auto resolution = resolver_.resolve(request.target, request.expected_generation);
        if (!resolution) {
            return adapter_result_t<adapter_response_t>::failure(from_target_error(resolution.error()));
        }
        target = std::move(resolution).take_value();
    } else if (request_has_target_selector(request) || request.expected_generation) {
        return adapter_result_t<adapter_response_t>::failure(
            make_error(adapter_error_code_t::invalid_request));
    }

    auto lease = lock_manager_.acquire(policy.value(), target ? target->target().target_id : 0,
                                       request.deadline);
    if (!lease) {
        return adapter_result_t<adapter_response_t>::failure(from_effect_error(lease.error));
    }

    std::optional<target_execution_pin_t> execution_pin;
    if (target) {
        auto pin = resolver_.pin_current(*target, request.expected_generation);
        if (!pin) {
            return adapter_result_t<adapter_response_t>::failure(from_target_error(pin.error));
        }
        execution_pin.emplace(std::move(pin.pin));
    }
    const auto* handler = handler_for(operation);
    if (handler == nullptr || !*handler) {
        return adapter_result_t<adapter_response_t>::failure(
            make_error(adapter_error_code_t::backend_unavailable));
    }
    const adapter_call_context_t context{
        contract,
        execution_pin
            ? std::optional<target_resolution_t>{execution_pin->resolution()}
            : std::optional<target_resolution_t>{},
        policy.value()};
    return (*handler)(context, request);
}

adapter_result_t<adapter_response_t> workspace_adapter_t::query(
    std::string_view contract_name, const adapter_request_t& request) const {
    return execute(contract_name, adapter_operation_t::query, request);
}

adapter_result_t<adapter_response_t> workspace_adapter_t::overlay(
    std::string_view contract_name, const adapter_request_t& request) const {
    return execute(contract_name, adapter_operation_t::overlay, request);
}

adapter_result_t<adapter_response_t> workspace_adapter_t::analyze(
    std::string_view contract_name, const adapter_request_t& request) const {
    return execute(contract_name, adapter_operation_t::analysis, request);
}

adapter_result_t<adapter_response_t> workspace_adapter_t::decompile(
    std::string_view contract_name, const adapter_request_t& request) const {
    return execute(contract_name, adapter_operation_t::decompilation, request);
}

adapter_result_t<adapter_response_t> workspace_adapter_t::checkpoint(
    std::string_view contract_name, const adapter_request_t& request) const {
    return execute(contract_name, adapter_operation_t::checkpoint, request);
}

adapter_result_t<adapter_response_t> workspace_adapter_t::debug(
    std::string_view contract_name, const adapter_request_t& request) const {
    return execute(contract_name, adapter_operation_t::debugger, request);
}

adapter_result_t<adapter_response_t> workspace_adapter_t::execute_isolated_python(
    std::string_view contract_name, const adapter_request_t& request) const {
    return execute(contract_name, adapter_operation_t::isolated_python, request);
}

adapter_result_t<bounded_live_snapshot_t> workspace_adapter_t::capture_live_snapshot(
    const bounded_live_snapshot_request_t& request) const {
    if (live_snapshot_limits_.maximum_bytes == 0 || request.size == 0 || request.address == 0 ||
        request.size > live_snapshot_limits_.maximum_bytes) {
        return adapter_result_t<bounded_live_snapshot_t>::failure(
            make_error(adapter_error_code_t::live_snapshot_bounds,
                       live_snapshot_limits_.maximum_bytes, request.size));
    }
    auto resolution = resolver_.resolve(request.target, request.expected_generation);
    if (!resolution) {
        return adapter_result_t<bounded_live_snapshot_t>::failure(from_target_error(resolution.error()));
    }
    auto target = std::move(resolution).take_value();
    const auto& resolved_record = target.target();
    if (!resolved_record.live || !resolved_record.live_snapshot_permitted ||
        resolved_record.live_snapshot_maximum_bytes == 0) {
        return adapter_result_t<bounded_live_snapshot_t>::failure(
            make_error(adapter_error_code_t::live_snapshot_denied));
    }
    const auto maximum_bytes = (std::min)(live_snapshot_limits_.maximum_bytes,
                                          resolved_record.live_snapshot_maximum_bytes);
    if (request.size > maximum_bytes ||
        !live_range_contains(resolved_record, request.address, request.size)) {
        return adapter_result_t<bounded_live_snapshot_t>::failure(
            make_error(adapter_error_code_t::live_snapshot_bounds, maximum_bytes, request.size));
    }
    if (!handlers_.live_snapshot) {
        return adapter_result_t<bounded_live_snapshot_t>::failure(
            make_error(adapter_error_code_t::backend_unavailable));
    }

    const effect_lock_policy_t policy{contract_effect_t::debugger_read,
                                      contract_lock_t::debugger_lane,
                                      effect_lock_mode_t::effect, true, false};
    auto lease = lock_manager_.acquire(policy, resolved_record.target_id, request.deadline);
    if (!lease) {
        return adapter_result_t<bounded_live_snapshot_t>::failure(from_effect_error(lease.error));
    }

    auto execution_pin = resolver_.pin_current(target, request.expected_generation);
    if (!execution_pin) {
        return adapter_result_t<bounded_live_snapshot_t>::failure(
            from_target_error(execution_pin.error));
    }
    const auto& record = execution_pin.pin.target();
    const adapter_call_context_t context{
        nullptr, std::optional<target_resolution_t>{execution_pin.pin.resolution()}, policy};
    auto snapshot = handlers_.live_snapshot(context, request);
    if (!snapshot) {
        return snapshot;
    }
    const auto& result = snapshot.value();
    if (result.bytes.size() != request.size ||
        result.process_creation_identity != record.process_creation_identity ||
        result.attach_generation != record.attach_generation || result.generation != record.generation) {
        return adapter_result_t<bounded_live_snapshot_t>::failure(
            make_error(adapter_error_code_t::live_snapshot_invalid));
    }
    return snapshot;
}

std::vector<target_record_t> workspace_adapter_t::list_targets() const {
    return resolver_.snapshot();
}

}
