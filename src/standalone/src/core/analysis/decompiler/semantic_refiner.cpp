#include "semantic_refiner.hpp"
#include "pseudocode_readability.hpp"

#include "../../infra/taskflow_runtime.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

namespace aida::analysis {

struct semantic_refiner_execution_state_t {
    static constexpr std::size_t k_proof_slots = 4;
    std::array<std::atomic<bool>, k_proof_slots> slot_busy{};
};

namespace {

constexpr auto k_worker_poll_interval = std::chrono::milliseconds(1);
constexpr auto k_worker_cancel_grace = std::chrono::milliseconds(2);

decompiler_diagnostic_t make_diagnostic(
    decompiler_diagnostic_code_t code,
    std::string key,
    const source_coordinate_t* coordinate,
    std::uint32_t& ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = code == decompiler_diagnostic_code_t::invalid_contract ||
                             code == decompiler_diagnostic_code_t::unsupported_provider
        ? decompiler_diagnostic_severity_t::error
        : decompiler_diagnostic_severity_t::warning;
    result.code = code;
    result.localization_key = std::move(key);
    if (coordinate)
        result.coordinate = *coordinate;
    result.ordinal = ordinal++;
    return result;
}

decompiler_unknown_t make_unknown(
    const semantic_refinement_query_t& query,
    decompiler_unknown_reason_t reason,
    std::string token)
{
    decompiler_unknown_t result;
    result.reason = reason;
    result.stable_token = std::move(token);
    result.coordinate = query.coordinate;
    result.provenance = decompiler_fact_provenance_t::semantic_proof;
    return result;
}

bool valid_query(const semantic_refinement_query_t& query,
                 const decompiler_entity_key_t& entity,
                 std::uint32_t max_ir_nodes)
{
    triton_z3_proof_request_t request;
    request.entity = entity;
    request.coordinate = query.coordinate;
    request.ordinal = query.ordinal;
    request.stable_id = query.stable_id;
    request.static_ir = query.static_ir;
    request.refinement_key = query.refinement_key;
    request.limits = {1, 1, 1, max_ir_nodes};
    return valid_triton_z3_proof_request(request);
}

std::uint32_t profile_ir_limit(const decompiler_profile_budget_t& profile) noexcept
{
    constexpr auto adapter_limit = static_cast<std::uint64_t>(4096);
    return static_cast<std::uint32_t>(
        std::min(std::min(profile.max_hir_nodes, profile.max_ast_nodes), adapter_limit));
}

bool query_sequence_valid(const std::vector<semantic_refinement_query_t>& queries,
                          const decompiler_entity_key_t& entity,
                          std::uint32_t max_ir_nodes)
{
    if (max_ir_nodes == 0)
        return queries.empty();
    std::string previous_id;
    std::uint64_t expected_ordinal = 1;
    for (const auto& query : queries) {
        if (!valid_query(query, entity, max_ir_nodes) || query.ordinal != expected_ordinal ||
            (!previous_id.empty() && query.stable_id <= previous_id))
            return false;
        previous_id = query.stable_id;
        ++expected_ordinal;
    }
    return true;
}

decompiler_unknown_reason_t map_unknown_reason(triton_z3_unknown_reason_t value)
{
    switch (value) {
    case triton_z3_unknown_reason_t::solver_unknown:
        return decompiler_unknown_reason_t::provider_abstained;
    case triton_z3_unknown_reason_t::unsupported_semantics:
        return decompiler_unknown_reason_t::unsupported_instruction;
    case triton_z3_unknown_reason_t::resource_limit:
        return decompiler_unknown_reason_t::bounded_analysis_limit;
    case triton_z3_unknown_reason_t::dependency_unavailable:
    case triton_z3_unknown_reason_t::none:
        return decompiler_unknown_reason_t::provider_abstained;
    }
    return decompiler_unknown_reason_t::provider_abstained;
}

decompiler_semantic_proof_availability_t map_adapter_availability(
    triton_z3_adapter_availability_t value) noexcept
{
    switch (value) {
    case triton_z3_adapter_availability_t::ready:
        return decompiler_semantic_proof_availability_t::ready;
    case triton_z3_adapter_availability_t::local_triton_unavailable:
        return decompiler_semantic_proof_availability_t::triton_unavailable;
    case triton_z3_adapter_availability_t::local_z3_unavailable:
        return decompiler_semantic_proof_availability_t::z3_unavailable;
    case triton_z3_adapter_availability_t::local_z3_not_linked:
        return decompiler_semantic_proof_availability_t::z3_not_linked;
    }
    return decompiler_semantic_proof_availability_t::adapter_denied;
}

void append_pending_unknowns(
    semantic_refinement_result_t& result,
    const std::vector<semantic_refinement_query_t>& queries,
    std::size_t first,
    decompiler_unknown_reason_t reason,
    const std::string& prefix)
{
    for (std::size_t index = first; index < queries.size(); ++index)
        result.unknowns.push_back(make_unknown(queries[index], reason, prefix + ":" + queries[index].stable_id));
}

bool response_within_claimed_limits(
    const triton_z3_proof_response_t& response,
    const triton_z3_proof_limits_t& limits) noexcept
{
    return response.elapsed_wall_clock_ms <= limits.max_wall_clock_ms &&
           response.elapsed_cpu_ms <= limits.max_cpu_ms &&
           response.peak_memory_bytes <= limits.max_memory_bytes;
}

std::chrono::steady_clock::time_point deadline_after(
    std::chrono::steady_clock::time_point now,
    std::uint64_t milliseconds) noexcept
{
    const auto available = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::time_point::max() - now).count();
    if (available <= 0 || milliseconds >= static_cast<std::uint64_t>(available))
        return std::chrono::steady_clock::time_point::max();
    return now + std::chrono::milliseconds(milliseconds);
}

std::uint64_t remaining_milliseconds(
    std::chrono::steady_clock::time_point now,
    std::chrono::steady_clock::time_point deadline) noexcept
{
    if (now >= deadline)
        return 0;
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now).count();
    constexpr std::int64_t per_millisecond = 1000000;
    return static_cast<std::uint64_t>((nanoseconds + per_millisecond - 1) / per_millisecond);
}

bool remaining_limits(
    const decompiler_profile_budget_t& profile,
    std::chrono::steady_clock::time_point function_deadline,
    std::uint64_t consumed_cpu_ms,
    triton_z3_proof_limits_t& result) noexcept
{
    const auto now = std::chrono::steady_clock::now();
    if (now >= function_deadline || consumed_cpu_ms >= profile.max_cpu_ms)
        return false;
    result.max_wall_clock_ms = remaining_milliseconds(now, function_deadline);
    result.max_cpu_ms = profile.max_cpu_ms - consumed_cpu_ms;
    result.max_memory_bytes = profile.max_memory_bytes;
    result.max_ir_nodes = profile_ir_limit(profile);
    return valid_triton_z3_proof_limits(result);
}

std::uint64_t saturating_add(std::uint64_t lhs, std::uint64_t rhs) noexcept
{
    return rhs > std::numeric_limits<std::uint64_t>::max() - lhs
        ? std::numeric_limits<std::uint64_t>::max()
        : lhs + rhs;
}

std::uint64_t elapsed_milliseconds(
    std::chrono::steady_clock::time_point begin,
    std::chrono::steady_clock::time_point end) noexcept
{
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
    if (nanoseconds <= 0)
        return 0;
    constexpr std::int64_t per_millisecond = 1000000;
    return static_cast<std::uint64_t>((nanoseconds + per_millisecond - 1) / per_millisecond);
}

#if defined(_WIN32)
bool thread_cpu_milliseconds(HANDLE thread, std::uint64_t& result) noexcept
{
    FILETIME created{};
    FILETIME exited{};
    FILETIME kernel{};
    FILETIME user{};
    if (GetThreadTimes(thread, &created, &exited, &kernel, &user) == 0)
        return false;
    ULARGE_INTEGER kernel_ticks{};
    kernel_ticks.LowPart = kernel.dwLowDateTime;
    kernel_ticks.HighPart = kernel.dwHighDateTime;
    ULARGE_INTEGER user_ticks{};
    user_ticks.LowPart = user.dwLowDateTime;
    user_ticks.HighPart = user.dwHighDateTime;
    const auto ticks = kernel_ticks.QuadPart + user_ticks.QuadPart;
    result = ticks == 0 ? 0 : (ticks + 9999ULL) / 10000ULL;
    return true;
}
#else
bool thread_cpu_milliseconds(std::thread::native_handle_type, std::uint64_t&) noexcept
{
    return false;
}
#endif

enum class proof_worker_terminal_t : std::uint8_t {
    completed = 1,
    caller_cancelled = 2,
    caller_deadline = 3,
    wall_limit = 4,
    cpu_limit = 5,
    adapter_busy = 6,
    launch_failure = 7,
    adapter_failure = 8,
    cpu_measurement_failure = 9
};

struct proof_worker_result_t {
    proof_worker_terminal_t terminal = proof_worker_terminal_t::launch_failure;
    triton_z3_proof_response_t response;
    std::uint64_t measured_wall_clock_ms = 0;
    std::uint64_t measured_cpu_ms = 0;
    bool invoked = false;
};

struct proof_worker_state_t {
    std::mutex mutex;
    std::condition_variable condition;
    triton_z3_proof_response_t response;
    bool complete = false;
    bool failed = false;
    bool cpu_valid = false;
    std::uint64_t cpu_ms = 0;
    std::atomic<std::uintptr_t> worker_thread_handle{0};
    std::atomic<bool> caller_abandoned{false};
};

proof_worker_result_t bounded_prove(
    const std::shared_ptr<triton_z3_adapter_t>& adapter,
    const std::shared_ptr<semantic_refiner_execution_state_t>& execution_state,
    const triton_z3_proof_request_t& request,
    const cancellation_token_t& caller_cancel)
{
    proof_worker_result_t result;
    std::size_t slot = semantic_refiner_execution_state_t::k_proof_slots;
    for (std::size_t index = 0; index < semantic_refiner_execution_state_t::k_proof_slots; ++index) {
        bool expected = false;
        if (execution_state->slot_busy[index].compare_exchange_strong(
                expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
            slot = index;
            break;
        }
    }
    if (slot == semantic_refiner_execution_state_t::k_proof_slots) {
        result.terminal = proof_worker_terminal_t::adapter_busy;
        return result;
    }

    const auto begin = std::chrono::steady_clock::now();
    auto query_deadline = deadline_after(begin, request.limits.max_wall_clock_ms);
    const auto caller_deadline = caller_cancel.deadline();
    if (caller_deadline && *caller_deadline < query_deadline)
        query_deadline = *caller_deadline;
    cancellation_source_t worker_cancel(query_deadline);
    const auto worker_token = worker_cancel.token();
    const auto state = std::make_shared<proof_worker_state_t>();

    infra::taskflow_runtime::task_descriptor_t worker_desc;
    worker_desc.domain = infra::taskflow_runtime::executor_domain_t::external_tool;
    worker_desc.owner_subsystem = "semantic_refiner";
    worker_desc.label = "semantic_refiner.bounded_prove";
    worker_desc.priority = 1;
    worker_desc.shutdown_policy = "cancel_pending";
#if defined(_WIN32)
    {
        const auto deadline_gap = std::chrono::duration_cast<std::chrono::milliseconds>(
            query_deadline - std::chrono::steady_clock::now()).count();
        worker_desc.deadline_ms = static_cast<std::uint64_t>(GetTickCount64()) +
            static_cast<std::uint64_t>(deadline_gap > 0 ? deadline_gap : 0);
    }
#endif
    worker_desc.cancellable_body = [adapter, execution_state, request, state, worker_token, slot](
        const infra::taskflow_runtime::cancellation_token_t&) {
#if defined(_WIN32)
        const HANDLE self_handle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, GetCurrentThreadId());
        if (self_handle)
            state->worker_thread_handle.store(
                reinterpret_cast<std::uintptr_t>(self_handle), std::memory_order_release);
#endif
        triton_z3_proof_response_t response;
        bool failed = false;
        try {
            response = adapter->prove(request, worker_token);
        } catch (...) {
            failed = true;
        }
        std::uint64_t cpu_ms = 0;
#if defined(_WIN32)
        const bool cpu_valid = thread_cpu_milliseconds(GetCurrentThread(), cpu_ms);
#else
        const bool cpu_valid = false;
#endif
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->response = std::move(response);
            state->failed = failed;
            state->cpu_valid = cpu_valid;
            state->cpu_ms = cpu_ms;
            state->complete = true;
        }
        execution_state->slot_busy[slot].store(false, std::memory_order_release);
        state->condition.notify_all();
#if defined(_WIN32)
        if (state->caller_abandoned.load(std::memory_order_acquire)) {
            const std::uintptr_t handle_value =
                state->worker_thread_handle.exchange(0, std::memory_order_acq_rel);
            if (handle_value != 0)
                CloseHandle(reinterpret_cast<HANDLE>(handle_value));
        }
#endif
    };
    worker_desc.cancel_hook = [worker_cancel]() mutable {
        worker_cancel.request_cancel();
    };
    auto worker_submission = infra::taskflow_runtime::submit(std::move(worker_desc));
    if (!worker_submission.submitted) {
        execution_state->slot_busy[slot].store(false, std::memory_order_release);
        result.terminal = proof_worker_terminal_t::launch_failure;
        return result;
    }
    result.invoked = true;

    const auto close_worker_handle = [&]() {
#if defined(_WIN32)
        const std::uintptr_t handle_value =
            state->worker_thread_handle.exchange(0, std::memory_order_acq_rel);
        if (handle_value != 0)
            CloseHandle(reinterpret_cast<HANDLE>(handle_value));
#endif
    };

    const auto finish_early = [&](proof_worker_terminal_t terminal) {
        worker_cancel.request_cancel();
        bool complete = false;
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            state->condition.wait_for(lock, k_worker_cancel_grace, [&] { return state->complete; });
            complete = state->complete;
        }
        if (complete) {
            infra::taskflow_runtime::wait_for(worker_submission.handle, 5000);
        } else {
            state->caller_abandoned.store(true, std::memory_order_release);
            infra::taskflow_runtime::cancel(worker_submission.handle);
        }
        close_worker_handle();
        result.terminal = terminal;
        result.measured_wall_clock_ms = elapsed_milliseconds(begin, std::chrono::steady_clock::now());
        return result;
    };

    for (;;) {
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->complete)
                break;
        }
        if (caller_cancel.cancellation_requested())
            return finish_early(proof_worker_terminal_t::caller_cancelled);
        if (caller_cancel.deadline_exceeded())
            return finish_early(proof_worker_terminal_t::caller_deadline);
        if (std::chrono::steady_clock::now() >= query_deadline) {
            const auto terminal = caller_deadline && query_deadline == *caller_deadline
                ? proof_worker_terminal_t::caller_deadline
                : proof_worker_terminal_t::wall_limit;
            return finish_early(terminal);
        }
#if defined(_WIN32)
        std::uint64_t cpu_ms = 0;
        const std::uintptr_t handle_value =
            state->worker_thread_handle.load(std::memory_order_acquire);
        if (handle_value != 0 &&
            thread_cpu_milliseconds(reinterpret_cast<HANDLE>(handle_value), cpu_ms) &&
            cpu_ms > request.limits.max_cpu_ms)
            return finish_early(proof_worker_terminal_t::cpu_limit);
#endif
        std::unique_lock<std::mutex> lock(state->mutex);
        auto wake = std::chrono::steady_clock::now() + k_worker_poll_interval;
        if (query_deadline < wake)
            wake = query_deadline;
        state->condition.wait_until(lock, wake, [&] { return state->complete; });
    }

    infra::taskflow_runtime::wait_for(worker_submission.handle, 5000);
    close_worker_handle();
    result.measured_wall_clock_ms = elapsed_milliseconds(begin, std::chrono::steady_clock::now());
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        result.response = state->response;
        result.measured_cpu_ms = state->cpu_ms;
        if (state->failed) {
            result.terminal = proof_worker_terminal_t::adapter_failure;
            return result;
        }
        if (!state->cpu_valid) {
            result.terminal = proof_worker_terminal_t::cpu_measurement_failure;
            return result;
        }
    }
    if (caller_cancel.cancellation_requested()) {
        result.terminal = proof_worker_terminal_t::caller_cancelled;
        return result;
    }
    if (caller_cancel.deadline_exceeded()) {
        result.terminal = proof_worker_terminal_t::caller_deadline;
        return result;
    }
    if (result.measured_wall_clock_ms > request.limits.max_wall_clock_ms) {
        result.terminal = proof_worker_terminal_t::wall_limit;
        return result;
    }
    if (result.measured_cpu_ms > request.limits.max_cpu_ms) {
        result.terminal = proof_worker_terminal_t::cpu_limit;
        return result;
    }
    result.terminal = proof_worker_terminal_t::completed;
    return result;
}

}

semantic_refiner_t::semantic_refiner_t(std::shared_ptr<triton_z3_adapter_t> adapter)
    : adapter_(adapter ? std::move(adapter) : make_triton_z3_adapter()),
      execution_state_(std::make_shared<semantic_refiner_execution_state_t>()) {}

semantic_refinement_result_t semantic_refiner_t::refine(
    const semantic_refinement_request_t& request,
    const cancellation_token_t& cancel) const
{
    semantic_refinement_result_t result;
    result.unknowns = request.function.unknowns;
    std::uint32_t diagnostic_ordinal = 1;

    const auto profile_validation = validate_decompiler_profile(request.profile);
    if (!profile_validation.valid()) {
        result.status = semantic_refinement_status_t::input_rejected;
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "semantic_refiner.profile.invalid",
            nullptr,
            diagnostic_ordinal));
        return result;
    }
    if (request.profile.profile != decompiler_profile_id_t::thorough ||
        !request.profile.semantic_proofs_enabled || request.profile.max_semantic_queries == 0) {
        result.status = semantic_refinement_status_t::profile_rejected;
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "semantic_refiner.profile.thorough_required",
            nullptr,
            diagnostic_ordinal));
        return result;
    }
    if (!validate_hir_function(request.function).valid() ||
        !query_sequence_valid(request.queries, request.function.entity, profile_ir_limit(request.profile))) {
        result.status = semantic_refinement_status_t::input_rejected;
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "semantic_refiner.request.invalid",
            nullptr,
            diagnostic_ordinal));
        return result;
    }
    if (cancel.stop_requested()) {
        result.status = semantic_refinement_status_t::cancelled;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_cancelled");
        result.diagnostics.push_back(make_diagnostic(
            cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                      : decompiler_diagnostic_code_t::cancelled,
            cancel.deadline_exceeded() ? "semantic_refiner.cancelled.deadline" : "semantic_refiner.cancelled",
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }

    triton_z3_adapter_capabilities_t capabilities;
    try {
        capabilities = adapter_->capabilities();
    } catch (...) {
        result.status = semantic_refinement_status_t::adapter_denied;
        result.availability = decompiler_semantic_proof_availability_t::adapter_denied;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::unsupported_provider,
            "semantic_refiner.adapter.capability_failure",
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }
    if (capabilities.target_execution_supported) {
        result.status = semantic_refinement_status_t::adapter_denied;
        result.availability = decompiler_semantic_proof_availability_t::adapter_denied;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::unsupported_provider,
            "semantic_refiner.adapter.target_execution_forbidden",
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }
    if (!capabilities.valid()) {
        result.status = semantic_refinement_status_t::adapter_denied;
        result.availability = decompiler_semantic_proof_availability_t::adapter_denied;
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::unsupported_provider,
            "semantic_refiner.adapter.invalid_capability_contract",
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }
    if (!capabilities.available()) {
        result.status = semantic_refinement_status_t::adapter_denied;
        result.availability = map_adapter_availability(capabilities.availability);
        append_pending_unknowns(result, request.queries, 0,
            decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_code_t::unsupported_provider,
            "semantic_refiner.adapter." + triton_z3_adapter_availability_key(capabilities.availability),
            request.queries.empty() ? nullptr : &request.queries.front().coordinate,
            diagnostic_ordinal));
        return result;
    }
    result.availability = decompiler_semantic_proof_availability_t::ready;

    const auto function_deadline = deadline_after(
        std::chrono::steady_clock::now(), request.profile.max_wall_clock_ms);
    std::uint64_t consumed_cpu_ms = 0;
    bool has_semantic_unknown = false;
    for (std::size_t index = 0; index < request.queries.size(); ++index) {
        const auto& query = request.queries[index];
        if (index >= request.profile.max_semantic_queries) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_budget_exhausted");
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "semantic_refiner.budget.query_limit",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        }
        if (cancel.stop_requested()) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_cancelled");
            result.diagnostics.push_back(make_diagnostic(
                cancel.deadline_exceeded() ? decompiler_diagnostic_code_t::deadline_exceeded
                                          : decompiler_diagnostic_code_t::cancelled,
                cancel.deadline_exceeded() ? "semantic_refiner.cancelled.deadline" : "semantic_refiner.cancelled",
                &query.coordinate,
                diagnostic_ordinal));
            result.status = semantic_refinement_status_t::cancelled;
            return result;
        }

        triton_z3_proof_limits_t limits;
        if (!remaining_limits(request.profile, function_deadline, consumed_cpu_ms, limits)) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_budget_exhausted");
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "semantic_refiner.budget.elapsed_limit",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        }

        triton_z3_proof_request_t proof_request;
        proof_request.entity = request.function.entity;
        proof_request.coordinate = query.coordinate;
        proof_request.ordinal = query.ordinal;
        proof_request.stable_id = query.stable_id;
        proof_request.static_ir = query.static_ir;
        proof_request.refinement_key = query.refinement_key;
        proof_request.limits = limits;

        const auto worker = bounded_prove(adapter_, execution_state_, proof_request, cancel);
        if (worker.invoked)
            ++result.adapter_invocations;
        consumed_cpu_ms = saturating_add(consumed_cpu_ms, worker.measured_cpu_ms);

        if (worker.terminal == proof_worker_terminal_t::caller_cancelled ||
            worker.terminal == proof_worker_terminal_t::caller_deadline) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_cancelled");
            const bool deadline = worker.terminal == proof_worker_terminal_t::caller_deadline;
            result.diagnostics.push_back(make_diagnostic(
                deadline ? decompiler_diagnostic_code_t::deadline_exceeded
                         : decompiler_diagnostic_code_t::cancelled,
                deadline ? "semantic_refiner.cancelled.deadline" : "semantic_refiner.cancelled",
                &query.coordinate,
                diagnostic_ordinal));
            result.status = semantic_refinement_status_t::cancelled;
            return result;
        }
        const bool function_wall_exhausted = worker.terminal == proof_worker_terminal_t::completed &&
                                             std::chrono::steady_clock::now() >= function_deadline;
        if (worker.terminal == proof_worker_terminal_t::wall_limit ||
            worker.terminal == proof_worker_terminal_t::cpu_limit || function_wall_exhausted) {
            const bool wall_limit = worker.terminal == proof_worker_terminal_t::wall_limit ||
                                    function_wall_exhausted;
            result.unknowns.push_back(make_unknown(query,
                wall_limit
                    ? decompiler_unknown_reason_t::semantic_timeout
                    : decompiler_unknown_reason_t::bounded_analysis_limit,
                wall_limit
                    ? "semantic_timeout:" + query.stable_id
                    : "semantic_cpu_limit:" + query.stable_id));
            append_pending_unknowns(result, request.queries, index + 1,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_budget_exhausted");
            result.diagnostics.push_back(make_diagnostic(
                wall_limit
                    ? decompiler_diagnostic_code_t::deadline_exceeded
                    : decompiler_diagnostic_code_t::resource_limit,
                wall_limit
                    ? "semantic_refiner.worker.deadline"
                    : "semantic_refiner.worker.cpu_limit",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        }
        if (worker.terminal == proof_worker_terminal_t::adapter_busy ||
            worker.terminal == proof_worker_terminal_t::launch_failure) {
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::unsupported_provider,
                worker.terminal == proof_worker_terminal_t::adapter_busy
                    ? "semantic_refiner.adapter.worker_busy"
                    : "semantic_refiner.adapter.worker_launch_failure",
                &query.coordinate,
                diagnostic_ordinal));
            result.status = semantic_refinement_status_t::adapter_denied;
            result.availability = decompiler_semantic_proof_availability_t::adapter_denied;
            return result;
        }
        if (worker.terminal == proof_worker_terminal_t::adapter_failure ||
            worker.terminal == proof_worker_terminal_t::cpu_measurement_failure) {
            result.unknowns.push_back(make_unknown(query,
                decompiler_unknown_reason_t::provider_abstained,
                "semantic_adapter_failure:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::provider_failure,
                worker.terminal == proof_worker_terminal_t::adapter_failure
                    ? "semantic_refiner.adapter.exception"
                    : "semantic_refiner.adapter.cpu_measurement_unavailable",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            continue;
        }

        const auto& response = worker.response;
        if (!valid_triton_z3_proof_response(response)) {
            result.unknowns.push_back(make_unknown(query,
                decompiler_unknown_reason_t::provider_abstained,
                "semantic_adapter_invalid_response:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::provider_failure,
                "semantic_refiner.adapter.invalid_response",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            continue;
        }
        if (!response_within_claimed_limits(response, limits)) {
            const bool timing_limit = response.elapsed_wall_clock_ms > limits.max_wall_clock_ms ||
                                      response.elapsed_cpu_ms > limits.max_cpu_ms;
            result.unknowns.push_back(make_unknown(query,
                timing_limit ? decompiler_unknown_reason_t::semantic_timeout
                             : decompiler_unknown_reason_t::bounded_analysis_limit,
                timing_limit ? "semantic_timeout:" + query.stable_id
                             : "semantic_memory_limit:" + query.stable_id));
            append_pending_unknowns(result, request.queries, index + 1,
                decompiler_unknown_reason_t::bounded_analysis_limit, "semantic_budget_exhausted");
            result.diagnostics.push_back(make_diagnostic(
                timing_limit ? decompiler_diagnostic_code_t::deadline_exceeded
                             : decompiler_diagnostic_code_t::resource_limit,
                "semantic_refiner.adapter.reported_limit_exceeded",
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        }

        switch (response.status) {
        case triton_z3_proof_status_t::proved: {
            if (response.refinement_key != query.refinement_key) {
                result.unknowns.push_back(make_unknown(query,
                    decompiler_unknown_reason_t::provider_abstained,
                    "semantic_adapter_mismatched_proof:" + query.stable_id));
                result.diagnostics.push_back(make_diagnostic(
                    decompiler_diagnostic_code_t::provider_failure,
                    "semantic_refiner.adapter.mismatched_proof",
                    &query.coordinate,
                    diagnostic_ordinal));
                has_semantic_unknown = true;
                break;
            }
            semantic_refinement_fact_t fact;
            fact.ordinal = query.ordinal;
            fact.stable_id = query.stable_id;
            fact.refinement_key = query.refinement_key;
            fact.coordinate = query.coordinate;
            result.facts.push_back(std::move(fact));
            break;
        }
        case triton_z3_proof_status_t::disproved:
            break;
        case triton_z3_proof_status_t::unknown:
            result.unknowns.push_back(make_unknown(query,
                map_unknown_reason(response.unknown_reason), "semantic_unknown:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                response.diagnostic_key.empty() ? "semantic_refiner.adapter.unknown" : response.diagnostic_key,
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        case triton_z3_proof_status_t::timeout:
            result.unknowns.push_back(make_unknown(query,
                decompiler_unknown_reason_t::semantic_timeout, "semantic_timeout:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::deadline_exceeded,
                response.diagnostic_key.empty() ? "semantic_refiner.adapter.timeout" : response.diagnostic_key,
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        case triton_z3_proof_status_t::cancelled:
            result.unknowns.push_back(make_unknown(query,
                decompiler_unknown_reason_t::provider_abstained,
                "semantic_adapter_cancelled:" + query.stable_id));
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::provider_failure,
                response.diagnostic_key.empty() ? "semantic_refiner.adapter.unexpected_cancel" : response.diagnostic_key,
                &query.coordinate,
                diagnostic_ordinal));
            has_semantic_unknown = true;
            break;
        case triton_z3_proof_status_t::denied:
            append_pending_unknowns(result, request.queries, index,
                decompiler_unknown_reason_t::provider_abstained, "semantic_adapter_denied");
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_code_t::unsupported_provider,
                response.diagnostic_key.empty() ? "semantic_refiner.adapter.denied" : response.diagnostic_key,
                &query.coordinate,
                diagnostic_ordinal));
            result.status = semantic_refinement_status_t::adapter_denied;
            result.availability = decompiler_semantic_proof_availability_t::adapter_denied;
            return result;
        }
    }

    result.status = has_semantic_unknown
        ? semantic_refinement_status_t::completed_with_unknowns
        : semantic_refinement_status_t::completed;
    return result;
}

}
