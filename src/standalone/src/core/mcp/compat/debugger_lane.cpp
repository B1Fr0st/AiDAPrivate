#include "debugger_lane.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <stdexcept>

namespace aida::standalone::mcp::compat {

std::timed_mutex debugger_lane_t::global_lane_mutex_;
thread_local const debugger_lane_t::invocation_scope_t* debugger_lane_t::active_scope_ = nullptr;

namespace {

bool range_is_valid(std::uint64_t base, std::uint64_t size) noexcept {
    return base != 0 && size != 0 &&
        base <= (std::numeric_limits<std::uint64_t>::max)() - (size - 1);
}

class active_request_guard_t final {
public:
    active_request_guard_t(std::atomic_uint64_t& active,
                           std::atomic_uint64_t& peak) noexcept
        : active_(active) {
        const std::uint64_t current = active_.fetch_add(1, std::memory_order_acq_rel) + 1;
        std::uint64_t observed = peak.load(std::memory_order_acquire);
        while (observed < current &&
               !peak.compare_exchange_weak(
                   observed, current, std::memory_order_acq_rel, std::memory_order_acquire)) {
        }
    }

    ~active_request_guard_t() noexcept {
        active_.fetch_sub(1, std::memory_order_acq_rel);
    }

    active_request_guard_t(const active_request_guard_t&) = delete;
    active_request_guard_t& operator=(const active_request_guard_t&) = delete;

private:
    std::atomic_uint64_t& active_;
};

}

debugger_lane_t::invocation_scope_t::invocation_scope_t(
    const debugger_lane_t& owner,
    const protocol::cancellation_token_t& cancellation)
    : owner_(&owner),
      cancellation_(cancellation),
      previous_(debugger_lane_t::active_scope_),
      thread_id_(std::this_thread::get_id()) {
    debugger_lane_t::active_scope_ = this;
}

debugger_lane_t::invocation_scope_t::~invocation_scope_t() noexcept {
    if (thread_id_ != std::this_thread::get_id() || debugger_lane_t::active_scope_ != this) {
        std::terminate();
    }
    debugger_lane_t::active_scope_ = previous_;
}

debugger_lane_t::debugger_lane_t(debugger_adapter_t& adapter,
                                 debugger_lane_limits_t limits)
    : adapter_(adapter), limits_(limits) {
    if (limits_.maximum_lock_wait.count() <= 0 ||
        limits_.maximum_lock_wait > std::chrono::seconds(30) ||
        limits_.lock_poll_interval.count() <= 0 ||
        limits_.lock_poll_interval > std::chrono::milliseconds(100) ||
        limits_.lock_poll_interval > limits_.maximum_lock_wait) {
        throw std::invalid_argument("debugger lane limits are invalid or unbounded");
    }
}

debugger_lane_t::invocation_scope_t debugger_lane_t::bind(
    const protocol::cancellation_token_t& cancellation) const {
    return invocation_scope_t(*this, cancellation);
}

adapter_handler_t debugger_lane_t::workspace_handler() {
    return [this](const adapter_call_context_t& context,
                  const adapter_request_t& request) {
        return handle(context, request);
    };
}

std::uint64_t debugger_lane_t::completed_requests() const noexcept {
    return completed_requests_.load(std::memory_order_acquire);
}

std::uint64_t debugger_lane_t::peak_concurrency() const noexcept {
    return peak_concurrency_.load(std::memory_order_acquire);
}

adapter_result_t<adapter_response_t> debugger_lane_t::handle(
    const adapter_call_context_t& context,
    const adapter_request_t& request) {
    const invocation_scope_t* scope = active_scope_;
    if (scope == nullptr || scope->owner_ != this ||
        scope->thread_id_ != std::this_thread::get_id()) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::request_rejected));
    }
    const auto& cancellation = scope->cancellation_;
    if (cancellation.cancelled()) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::cancelled));
    }
    if (context.contract == nullptr || !context.target ||
        context.contract->lock != contract_lock_t::debugger_lane ||
        context.effect.contract_lock != contract_lock_t::debugger_lane ||
        context.contract->effect != context.effect.effect ||
        (context.contract->effect != contract_effect_t::debugger_read &&
         context.contract->effect != contract_effect_t::debugger_control &&
         context.contract->effect != contract_effect_t::debugger_write) ||
        (context.contract->effect == contract_effect_t::debugger_write &&
         context.contract->name != "dbg_write")) {
        return adapter_result_t<adapter_response_t>::failure(
            adapter_error_t{adapter_error_code_t::operation_not_permitted,
                            "debugger_effect_policy_rejected", 0, 0});
    }

    const auto& target = context.target->target();
    if (!target.live || target.pid == 0 || target.process_creation_identity == 0 ||
        target.attach_generation == 0 ||
        !range_is_valid(target.live_capture_base, target.live_capture_size)) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::attach_lost));
    }

    protocol::json arguments = protocol::json::parse(request.payload, nullptr, false);
    if (arguments.is_discarded() || !arguments.is_object()) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::request_rejected));
    }

    const auto now = std::chrono::steady_clock::now();
    const auto maximum_deadline = now + limits_.maximum_lock_wait;
    const auto deadline = request.deadline
        ? (std::min)(*request.deadline, maximum_deadline)
        : maximum_deadline;
    if (deadline <= now) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::deadline_exceeded));
    }

    std::unique_lock<std::timed_mutex> lane_lock(global_lane_mutex_, std::defer_lock);
    while (!lane_lock.owns_lock()) {
        if (cancellation.cancelled()) {
            return adapter_result_t<adapter_response_t>::failure(
                workspace_error(debugger_adapter_error_code_t::cancelled));
        }
        const auto current = std::chrono::steady_clock::now();
        if (current >= deadline) {
            return adapter_result_t<adapter_response_t>::failure(
                workspace_error(debugger_adapter_error_code_t::deadline_exceeded));
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - current);
        const auto wait = (std::min)(limits_.lock_poll_interval,
                                     (std::max)(remaining, std::chrono::milliseconds(1)));
        if (lane_lock.try_lock_for(wait)) {
            break;
        }
    }

    if (cancellation.cancelled()) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::cancelled));
    }
    active_request_guard_t active_guard(active_requests_, peak_concurrency_);

    const debugger_target_identity_t expected{
        target.pid,
        target.process_creation_identity,
        target.live_capture_base,
        target.live_capture_size,
        target.attach_generation,
        true,
    };

    debugger_adapter_result_t<debugger_target_identity_t> before =
        debugger_adapter_result_t<debugger_target_identity_t>::failure(
            debugger_adapter_error_code_t::internal_error);
    try {
        before = adapter_.identity(cancellation, deadline);
    } catch (const std::exception&) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::internal_error));
    } catch (...) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::internal_error));
    }
    if (!before) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(before.error().code, before.error().expected,
                            before.error().actual));
    }
    if (const auto mismatch = compare_identity(expected, before.value())) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(mismatch.code, mismatch.expected, mismatch.actual));
    }
    if (cancellation.cancelled()) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::cancelled));
    }

    debugger_adapter_request_t adapter_request;
    adapter_request.tool_name.assign(
        context.contract->name.data(), context.contract->name.size());
    adapter_request.arguments = std::move(arguments);
    adapter_request.expected_identity = expected;
    adapter_request.effect = context.contract->effect;
    adapter_request.cancellation = cancellation;
    adapter_request.deadline = deadline;

    debugger_adapter_result_t<debugger_adapter_response_t> executed =
        debugger_adapter_result_t<debugger_adapter_response_t>::failure(
            debugger_adapter_error_code_t::internal_error);
    try {
        executed = adapter_.execute(adapter_request);
    } catch (const std::exception&) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::internal_error));
    } catch (...) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::internal_error));
    }
    if (cancellation.cancelled()) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::cancelled));
    }
    if (!executed) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(executed.error().code, executed.error().expected,
                            executed.error().actual));
    }
    if (!executed.value().structured.is_object()) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::invalid_response));
    }

    debugger_adapter_result_t<debugger_target_identity_t> after =
        debugger_adapter_result_t<debugger_target_identity_t>::failure(
            debugger_adapter_error_code_t::internal_error);
    try {
        after = adapter_.identity(cancellation, deadline);
    } catch (const std::exception&) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::internal_error));
    } catch (...) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::internal_error));
    }
    const bool permit_detach = permits_detach_after(
        context.contract->name, executed.value().structured);
    if (!after) {
        if (!(permit_detach &&
              after.error().code == debugger_adapter_error_code_t::attach_lost)) {
            return adapter_result_t<adapter_response_t>::failure(
                workspace_error(after.error().code, after.error().expected,
                                after.error().actual));
        }
    } else if (!after.value().attached) {
        if (!permit_detach) {
            return adapter_result_t<adapter_response_t>::failure(
                workspace_error(debugger_adapter_error_code_t::attach_lost));
        }
    } else if (const auto mismatch = compare_identity(expected, after.value())) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(mismatch.code, mismatch.expected, mismatch.actual));
    }
    if (cancellation.cancelled()) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::cancelled));
    }
    if (std::chrono::steady_clock::now() > deadline) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::deadline_exceeded));
    }

    adapter_response_t response;
    try {
        response.payload = executed.value().structured.dump();
    } catch (const std::exception&) {
        return adapter_result_t<adapter_response_t>::failure(
            workspace_error(debugger_adapter_error_code_t::invalid_response));
    }
    response.truncated = executed.value().truncated;
    completed_requests_.fetch_add(1, std::memory_order_acq_rel);
    return adapter_result_t<adapter_response_t>::success(std::move(response));
}

adapter_error_t debugger_lane_t::workspace_error(
    debugger_adapter_error_code_t code,
    std::uint64_t expected,
    std::uint64_t actual) noexcept {
    const adapter_error_code_t adapter_code =
        code == debugger_adapter_error_code_t::unavailable
            ? adapter_error_code_t::backend_unavailable
            : adapter_error_code_t::backend_rejected;
    return adapter_error_t{adapter_code, stable_error_code(code), expected, actual};
}

std::string_view debugger_lane_t::stable_error_code(
    debugger_adapter_error_code_t code) noexcept {
    switch (code) {
    case debugger_adapter_error_code_t::none:
        return "debugger_ok";
    case debugger_adapter_error_code_t::unavailable:
        return "debugger_unavailable";
    case debugger_adapter_error_code_t::attach_lost:
        return "debugger_attach_lost";
    case debugger_adapter_error_code_t::pid_reused:
        return "debugger_pid_reused";
    case debugger_adapter_error_code_t::module_changed:
        return "debugger_module_changed";
    case debugger_adapter_error_code_t::attach_generation_stale:
        return "debugger_attach_generation_stale";
    case debugger_adapter_error_code_t::breakpoint_conflict:
        return "debugger_breakpoint_conflict";
    case debugger_adapter_error_code_t::partial_read:
        return "debugger_partial_read";
    case debugger_adapter_error_code_t::partial_write:
        return "debugger_partial_write";
    case debugger_adapter_error_code_t::cancelled:
        return "debugger_cancelled";
    case debugger_adapter_error_code_t::deadline_exceeded:
        return "debugger_deadline_exceeded";
    case debugger_adapter_error_code_t::request_rejected:
        return "debugger_request_rejected";
    case debugger_adapter_error_code_t::invalid_response:
        return "debugger_invalid_response";
    case debugger_adapter_error_code_t::internal_error:
        return "debugger_internal_error";
    }
    return "debugger_internal_error";
}

bool debugger_lane_t::valid_identity(
    const debugger_target_identity_t& identity) noexcept {
    return identity.attached && identity.pid != 0 &&
        identity.process_creation_identity != 0 && identity.attach_generation != 0 &&
        range_is_valid(identity.module_base, identity.module_size);
}

debugger_adapter_error_t debugger_lane_t::compare_identity(
    const debugger_target_identity_t& expected,
    const debugger_target_identity_t& actual) noexcept {
    if (!valid_identity(actual)) {
        return {debugger_adapter_error_code_t::attach_lost, 1, actual.attached ? 1ULL : 0ULL};
    }
    if (actual.pid != expected.pid) {
        return {debugger_adapter_error_code_t::pid_reused, expected.pid, actual.pid};
    }
    if (actual.process_creation_identity != expected.process_creation_identity) {
        return {debugger_adapter_error_code_t::pid_reused,
                expected.process_creation_identity,
                actual.process_creation_identity};
    }
    if (actual.module_base != expected.module_base ||
        actual.module_size != expected.module_size) {
        return {debugger_adapter_error_code_t::module_changed,
                expected.module_base,
                actual.module_base};
    }
    if (actual.attach_generation != expected.attach_generation) {
        return {debugger_adapter_error_code_t::attach_generation_stale,
                expected.attach_generation,
                actual.attach_generation};
    }
    return {};
}

bool debugger_lane_t::permits_detach_after(
    std::string_view tool_name,
    const protocol::json& response) noexcept {
    if (tool_name == "dbg_exit") {
        return true;
    }
    const auto exited = response.find("exited");
    return exited != response.end() && exited->is_boolean() && exited->get<bool>();
}

}
