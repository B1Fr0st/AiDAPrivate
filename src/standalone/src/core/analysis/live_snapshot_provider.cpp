#include "live_snapshot_provider.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <new>
#include <thread>
#include <type_traits>

namespace aida::analysis::c03 {
namespace {

class steady_live_snapshot_clock_t final : public live_snapshot_clock_t {
public:
    live_request_budget_t::time_point_t now() const noexcept override
    {
        return live_request_budget_t::clock_t::now();
    }
};

bool range_contains(std::uint64_t outer_base, std::uint64_t outer_size,
                    std::uint64_t inner_base, std::uint64_t inner_size) noexcept
{
    if (outer_base == 0 || outer_size == 0 || inner_base == 0 || inner_size == 0 ||
        outer_size > (std::numeric_limits<std::uint64_t>::max)() - outer_base ||
        inner_size > (std::numeric_limits<std::uint64_t>::max)() - inner_base)
        return false;
    const auto outer_end = outer_base + outer_size;
    const auto inner_end = inner_base + inner_size;
    return inner_base >= outer_base && inner_end <= outer_end;
}

live_snapshot_error_code_t map_budget_error(live_request_budget_error_code_t code) noexcept
{
    switch (code) {
    case live_request_budget_error_code_t::cancelled:
        return live_snapshot_error_code_t::cancelled;
    case live_request_budget_error_code_t::deadline_exceeded:
        return live_snapshot_error_code_t::deadline_exceeded;
    case live_request_budget_error_code_t::result_byte_limit_exceeded:
        return live_snapshot_error_code_t::result_byte_limit_exceeded;
    case live_request_budget_error_code_t::adapter_byte_limit_exceeded:
        return live_snapshot_error_code_t::adapter_byte_limit_exceeded;
    case live_request_budget_error_code_t::page_limit_exceeded:
    case live_request_budget_error_code_t::page_size_limit_exceeded:
        return live_snapshot_error_code_t::page_limit_exceeded;
    case live_request_budget_error_code_t::arithmetic_overflow:
        return live_snapshot_error_code_t::arithmetic_overflow;
    case live_request_budget_error_code_t::none:
    case live_request_budget_error_code_t::invalid_limits:
        return live_snapshot_error_code_t::invalid_request;
    }
    return live_snapshot_error_code_t::invalid_request;
}

live_snapshot_error_t map_budget_error(const live_request_budget_error_t& error,
                                       std::string_view phase) noexcept
{
    return make_live_snapshot_error(map_budget_error(error.code), phase,
                                    error.expected, error.actual);
}

live_snapshot_error_t normalize_adapter_error(const live_snapshot_error_t& error,
                                              std::string_view phase) noexcept
{
    switch (error.code) {
    case live_snapshot_error_code_t::cancelled:
    case live_snapshot_error_code_t::deadline_exceeded:
    case live_snapshot_error_code_t::pid_reused:
    case live_snapshot_error_code_t::process_identity_changed:
    case live_snapshot_error_code_t::module_unloaded:
    case live_snapshot_error_code_t::module_remapped:
    case live_snapshot_error_code_t::allocation_failed:
        return make_live_snapshot_error(error.code, phase, error.expected, error.actual);
    default:
        return make_live_snapshot_error(live_snapshot_error_code_t::adapter_failure, phase,
                                        error.expected, error.actual);
    }
}

bool invalidates_cached_identity(live_snapshot_error_code_t code) noexcept
{
    return code == live_snapshot_error_code_t::pid_reused ||
        code == live_snapshot_error_code_t::process_identity_changed ||
        code == live_snapshot_error_code_t::module_unloaded ||
        code == live_snapshot_error_code_t::module_remapped;
}

constexpr auto k_adapter_wait_quantum = std::chrono::milliseconds(1);

live_request_budget_t::clock_t::duration adapter_wait_quantum() noexcept
{
    const auto converted = std::chrono::duration_cast<live_request_budget_t::clock_t::duration>(
        k_adapter_wait_quantum);
    return converted > live_request_budget_t::clock_t::duration::zero()
        ? converted
        : live_request_budget_t::clock_t::duration(1);
}

live_request_budget_t::time_point_t make_wall_deadline(
    std::chrono::milliseconds maximum_elapsed) noexcept
{
    const auto now = live_request_budget_t::clock_t::now();
    const auto remaining = live_request_budget_t::time_point_t::max() - now;
    const auto remaining_milliseconds =
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    if (maximum_elapsed >= remaining_milliseconds)
        return live_request_budget_t::time_point_t::max();
    return now + std::chrono::duration_cast<live_request_budget_t::clock_t::duration>(
        maximum_elapsed);
}

live_snapshot_result_t<void> checkpoint_request(
    live_request_budget_t& budget, const live_snapshot_operation_context_t& context,
    const live_snapshot_clock_t& clock, std::string_view phase) noexcept
{
    const auto checkpoint =
        budget.checkpoint(context.cancellation.stop_requested(), clock.now());
    if (!checkpoint) {
        return live_snapshot_result_t<void>::failure(
            map_budget_error(checkpoint.error(), phase));
    }
    if (live_request_budget_t::clock_t::now() >= context.wall_deadline) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::deadline_exceeded, phase));
    }
    return live_snapshot_result_t<void>::success();
}

live_snapshot_result_t<void> lock_request_mutex(
    std::unique_lock<std::timed_mutex>& lock, live_request_budget_t& budget,
    const live_snapshot_operation_context_t& context, const live_snapshot_clock_t& clock,
    std::string_view phase) noexcept
{
    try {
        for (;;) {
            auto checkpoint = checkpoint_request(budget, context, clock, phase);
            if (!checkpoint)
                return checkpoint;
            if (lock.try_lock()) {
                checkpoint = checkpoint_request(budget, context, clock, phase);
                if (!checkpoint)
                    lock.unlock();
                return checkpoint;
            }

            const auto wall_now = live_request_budget_t::clock_t::now();
            if (wall_now >= context.wall_deadline) {
                return live_snapshot_result_t<void>::failure(
                    make_live_snapshot_error(live_snapshot_error_code_t::deadline_exceeded,
                                             phase));
            }
            const auto delay = (std::min)(context.wall_deadline - wall_now,
                                          adapter_wait_quantum());
            if (lock.try_lock_for(delay)) {
                checkpoint = checkpoint_request(budget, context, clock, phase);
                if (!checkpoint)
                    lock.unlock();
                return checkpoint;
            }
        }
    } catch (...) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::adapter_failure, phase));
    }
}

template <typename value_t>
struct adapter_call_state_t final {
    std::mutex mutex;
    std::condition_variable wake;
    std::optional<live_snapshot_result_t<value_t>> result;
};

template <typename value_t, typename operation_t>
live_snapshot_result_t<value_t> invoke_adapter_call_bounded(
    std::atomic_bool* call_active, std::shared_ptr<const live_snapshot_clock_t> clock,
    live_request_budget_t& budget, const live_snapshot_operation_context_t& context,
    std::string_view phase, operation_t&& operation) noexcept
{
    for (;;) {
        const auto checkpoint = checkpoint_request(budget, context, *clock, phase);
        if (!checkpoint)
            return live_snapshot_result_t<value_t>::failure(checkpoint.error());

        bool expected = false;
        if (call_active->compare_exchange_weak(expected, true, std::memory_order_acq_rel,
                                               std::memory_order_acquire))
            break;

        const auto wall_now = live_request_budget_t::clock_t::now();
        if (wall_now >= context.wall_deadline) {
            return live_snapshot_result_t<value_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::deadline_exceeded, phase));
        }
        const auto delay = (std::min)(context.wall_deadline - wall_now,
                                      adapter_wait_quantum());
        std::this_thread::sleep_for(delay);
    }

    bool release_call = true;
    try {
        auto state = std::make_shared<adapter_call_state_t<value_t>>();
        live_snapshot_cancellation_source_t call_cancellation;
        auto call_context = context;
        call_context.cancellation = call_cancellation.token();
        const auto caller_cancellation = context.cancellation;
        using operation_value_t = std::decay_t<operation_t>;

        std::thread worker(
            [state, call_active, call_context, caller_cancellation,
             operation = operation_value_t(std::forward<operation_t>(operation))]() mutable {
                auto result = live_snapshot_result_t<value_t>::failure(
                    make_live_snapshot_error(live_snapshot_error_code_t::adapter_failure,
                                             "adapter_call"));
                try {
                    if (caller_cancellation.stop_requested() ||
                        call_context.cancellation.stop_requested()) {
                        result = live_snapshot_result_t<value_t>::failure(
                            make_live_snapshot_error(live_snapshot_error_code_t::cancelled,
                                                     "adapter_call"));
                    } else if (live_request_budget_t::clock_t::now() >=
                               call_context.wall_deadline) {
                        result = live_snapshot_result_t<value_t>::failure(
                            make_live_snapshot_error(live_snapshot_error_code_t::deadline_exceeded,
                                                     "adapter_call"));
                    } else {
                        result = operation(call_context);
                    }
                } catch (const std::bad_alloc&) {
                    result = live_snapshot_result_t<value_t>::failure(
                        make_live_snapshot_error(live_snapshot_error_code_t::allocation_failed,
                                                 "adapter_call"));
                } catch (...) {
                    result = live_snapshot_result_t<value_t>::failure(
                        make_live_snapshot_error(live_snapshot_error_code_t::adapter_failure,
                                                 "adapter_call"));
                }

                call_active->store(false, std::memory_order_release);
                {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    state->result.emplace(std::move(result));
                }
                state->wake.notify_one();
            });
        release_call = false;
        worker.detach();

        for (;;) {
            std::optional<live_snapshot_result_t<value_t>> completed;
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                if (state->result)
                    completed.emplace(std::move(state->result.value()));
            }
            if (completed) {
                const auto final = checkpoint_request(budget, context, *clock, phase);
                if (!final)
                    return live_snapshot_result_t<value_t>::failure(final.error());
                return std::move(completed.value());
            }

            const auto checkpoint = checkpoint_request(budget, context, *clock, phase);
            if (!checkpoint) {
                call_cancellation.request_stop();
                return live_snapshot_result_t<value_t>::failure(checkpoint.error());
            }

            const auto wall_now = live_request_budget_t::clock_t::now();
            const auto delay = (std::min)(context.wall_deadline - wall_now,
                                          adapter_wait_quantum());
            std::unique_lock<std::mutex> lock(state->mutex);
            state->wake.wait_for(lock, delay, [&state] { return state->result.has_value(); });
        }
    } catch (const std::bad_alloc&) {
        if (release_call)
            call_active->store(false, std::memory_order_release);
        return live_snapshot_result_t<value_t>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::allocation_failed, phase));
    } catch (...) {
        if (release_call)
            call_active->store(false, std::memory_order_release);
        return live_snapshot_result_t<value_t>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::adapter_failure, phase));
    }
}

}

std::string_view live_snapshot_error_code_name(live_snapshot_error_code_t code) noexcept
{
    switch (code) {
    case live_snapshot_error_code_t::none:
        return "none";
    case live_snapshot_error_code_t::invalid_request:
        return "invalid_request";
    case live_snapshot_error_code_t::invalid_adapter:
        return "invalid_adapter";
    case live_snapshot_error_code_t::cancelled:
        return "cancelled";
    case live_snapshot_error_code_t::deadline_exceeded:
        return "deadline_exceeded";
    case live_snapshot_error_code_t::pid_reused:
        return "pid_reused";
    case live_snapshot_error_code_t::process_identity_changed:
        return "process_identity_changed";
    case live_snapshot_error_code_t::module_unloaded:
        return "module_unloaded";
    case live_snapshot_error_code_t::module_remapped:
        return "module_remapped";
    case live_snapshot_error_code_t::range_invalid:
        return "range_invalid";
    case live_snapshot_error_code_t::result_byte_limit_exceeded:
        return "result_byte_limit_exceeded";
    case live_snapshot_error_code_t::adapter_byte_limit_exceeded:
        return "adapter_byte_limit_exceeded";
    case live_snapshot_error_code_t::page_limit_exceeded:
        return "page_limit_exceeded";
    case live_snapshot_error_code_t::cache_limit_exceeded:
        return "cache_limit_exceeded";
    case live_snapshot_error_code_t::partial_read:
        return "partial_read";
    case live_snapshot_error_code_t::adapter_failure:
        return "adapter_failure";
    case live_snapshot_error_code_t::arithmetic_overflow:
        return "arithmetic_overflow";
    case live_snapshot_error_code_t::allocation_failed:
        return "allocation_failed";
    }
    return "unknown";
}

live_snapshot_error_t make_live_snapshot_error(live_snapshot_error_code_t code,
                                                std::string_view phase,
                                                std::uint64_t expected,
                                                std::uint64_t actual) noexcept
{
    return {code, live_snapshot_error_code_name(code), phase, expected, actual};
}

live_snapshot_cancellation_t::live_snapshot_cancellation_t(
    std::shared_ptr<const std::atomic_bool> state) noexcept
    : state_(std::move(state))
{
}

bool live_snapshot_cancellation_t::stop_requested() const noexcept
{
    return state_ && state_->load(std::memory_order_acquire);
}

live_snapshot_cancellation_source_t::live_snapshot_cancellation_source_t()
    : state_(std::make_shared<std::atomic_bool>(false))
{
}

live_snapshot_cancellation_t live_snapshot_cancellation_source_t::token() const noexcept
{
    return live_snapshot_cancellation_t(state_);
}

void live_snapshot_cancellation_source_t::request_stop() noexcept
{
    state_->store(true, std::memory_order_release);
}

live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>
live_snapshot_provider_t::open(std::shared_ptr<const live_snapshot_adapter_t> adapter,
                               live_snapshot_request_t request,
                               std::shared_ptr<const live_snapshot_clock_t> clock,
                               const live_snapshot_cancellation_t& cancellation)
{
    if (!adapter) {
        return live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::invalid_adapter, "open"));
    }
    if (!request.valid()) {
        return live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::invalid_request, "open"));
    }
    try {
        if (!clock)
            clock = std::make_shared<steady_live_snapshot_clock_t>();
        auto provider = std::shared_ptr<live_snapshot_provider_t>(
            new live_snapshot_provider_t(std::move(adapter), std::move(request), std::move(clock)));
        const auto started = provider->clock_->now();
        auto budget_result = live_request_budget_t::create(provider->request_.limits, started);
        if (!budget_result) {
            return live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
                map_budget_error(budget_result.error(), "open"));
        }
        auto budget = std::move(budget_result).take_value();
        const live_snapshot_operation_context_t context{
            cancellation, budget.deadline(),
            make_wall_deadline(provider->request_.limits.maximum_elapsed)};
        const auto identity_result = provider->validate_identity(budget, context);
        if (!identity_result) {
            return live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
                identity_result.error());
        }
        return live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>::success(
            std::move(provider));
    } catch (const std::bad_alloc&) {
        return live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::allocation_failed, "open"));
    } catch (...) {
        return live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::adapter_failure, "open"));
    }
}

live_snapshot_provider_t::live_snapshot_provider_t(
    std::shared_ptr<const live_snapshot_adapter_t> adapter, live_snapshot_request_t request,
    std::shared_ptr<const live_snapshot_clock_t> clock)
    : adapter_(std::move(adapter)), request_(std::move(request)), clock_(std::move(clock))
{
}

live_snapshot_cache_stats_t live_snapshot_provider_t::cache_stats() const
{
    std::unique_lock<std::timed_mutex> lock(cache_mutex_);
    return {static_cast<std::uint32_t>(cache_.size()), cached_bytes_, cache_hits_,
            cache_misses_, cache_evictions_};
}

live_snapshot_result_t<void> live_snapshot_provider_t::validate_current_identity(
    const live_snapshot_cancellation_t& cancellation) const
{
    const auto started = clock_->now();
    auto budget_result = live_request_budget_t::create(request_.limits, started);
    if (!budget_result)
        return live_snapshot_result_t<void>::failure(map_budget_error(budget_result.error(), "validate"));
    auto budget = std::move(budget_result).take_value();
    const live_snapshot_operation_context_t context{
        cancellation, budget.deadline(), make_wall_deadline(request_.limits.maximum_elapsed)};
    std::unique_lock<std::timed_mutex> operation_lock(operation_mutex_, std::defer_lock);
    const auto locked =
        lock_request_mutex(operation_lock, budget, context, *clock_, "validate_lock");
    if (!locked)
        return locked;
    const auto identity = validate_identity(budget, context);
    if (!identity && invalidates_cached_identity(identity.error().code)) {
        std::unique_lock<std::timed_mutex> cache_lock(cache_mutex_);
        clear_cache();
    }
    return identity;
}

live_snapshot_result_t<live_process_identity_t>
live_snapshot_provider_t::query_process_bounded(
    live_request_budget_t& budget, const live_snapshot_operation_context_t& context) const
{
    const auto adapter = adapter_;
    return invoke_adapter_call_bounded<live_process_identity_t>(
        &adapter->call_active_, clock_, budget, context, "process_query",
        [adapter, pid = request_.process.pid](const live_snapshot_operation_context_t& call_context) {
            return adapter->query_process(pid, call_context);
        });
}

live_snapshot_result_t<live_module_identity_t>
live_snapshot_provider_t::query_module_bounded(
    const live_process_identity_t& process, live_request_budget_t& budget,
    const live_snapshot_operation_context_t& context) const
{
    const auto adapter = adapter_;
    const auto module_base = request_.module.base;
    return invoke_adapter_call_bounded<live_module_identity_t>(
        &adapter->call_active_, clock_, budget, context, "module_query",
        [adapter, process, module_base](const live_snapshot_operation_context_t& call_context) {
            return adapter->query_module(process, module_base, call_context);
        });
}

live_snapshot_result_t<live_snapshot_adapter_page_t>
live_snapshot_provider_t::read_page_bounded(
    std::uint64_t address, std::uint64_t size, live_request_budget_t& budget,
    const live_snapshot_operation_context_t& context) const
{
    const auto adapter = adapter_;
    const auto process = request_.process;
    const auto module = request_.module;
    return invoke_adapter_call_bounded<live_snapshot_adapter_page_t>(
        &adapter->call_active_, clock_, budget, context, "read_adapter",
        [adapter, process, module, address, size](
            const live_snapshot_operation_context_t& call_context) {
            return adapter->read_page(process, module, address, size, call_context);
        });
}

live_snapshot_result_t<void> live_snapshot_provider_t::validate_identity(
    live_request_budget_t& budget, const live_snapshot_operation_context_t& context) const
{
    auto checkpoint = budget.checkpoint(context.cancellation.stop_requested(), clock_->now());
    if (!checkpoint)
        return live_snapshot_result_t<void>::failure(map_budget_error(checkpoint.error(), "identity_before"));

    auto process_result = query_process_bounded(budget, context);
    if (!process_result)
        return live_snapshot_result_t<void>::failure(
            normalize_adapter_error(process_result.error(), "process_query"));
    const auto observed_process = process_result.value();
    if (!observed_process.valid()) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::invalid_adapter, "process_query"));
    }
    if (observed_process.pid != request_.process.pid) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::process_identity_changed,
                                     "process_query", request_.process.pid, observed_process.pid));
    }
    if (observed_process.creation_identity != request_.process.creation_identity) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::pid_reused, "process_query",
                                     request_.process.creation_identity,
                                     observed_process.creation_identity));
    }

    checkpoint = budget.checkpoint(context.cancellation.stop_requested(), clock_->now());
    if (!checkpoint)
        return live_snapshot_result_t<void>::failure(map_budget_error(checkpoint.error(), "module_before"));

    auto module_result = query_module_bounded(observed_process, budget, context);
    if (!module_result)
        return live_snapshot_result_t<void>::failure(
            normalize_adapter_error(module_result.error(), "module_query"));
    const auto observed_module = module_result.value();
    if (!observed_module.valid()) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::invalid_adapter, "module_query"));
    }
    if (observed_module != request_.module) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::module_remapped, "module_query",
                                     request_.module.mapping_identity,
                                     observed_module.mapping_identity));
    }

    checkpoint = budget.checkpoint(context.cancellation.stop_requested(), clock_->now());
    if (!checkpoint)
        return live_snapshot_result_t<void>::failure(map_budget_error(checkpoint.error(), "identity_after"));
    return live_snapshot_result_t<void>::success();
}

live_snapshot_result_t<live_snapshot_read_t> live_snapshot_provider_t::read(
    std::uint64_t address, std::uint64_t size,
    const live_snapshot_cancellation_t& cancellation)
{
    if (!range_contains(request_.window_base, request_.window_size, address, size)) {
        return live_snapshot_result_t<live_snapshot_read_t>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::range_invalid, "read"));
    }
    if (size > (std::numeric_limits<std::size_t>::max)()) {
        return live_snapshot_result_t<live_snapshot_read_t>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::arithmetic_overflow, "read",
                                     (std::numeric_limits<std::size_t>::max)(), size));
    }

    const auto started = clock_->now();
    auto budget_result = live_request_budget_t::create(request_.limits, started);
    if (!budget_result)
        return live_snapshot_result_t<live_snapshot_read_t>::failure(
            map_budget_error(budget_result.error(), "read"));
    auto budget = std::move(budget_result).take_value();
    const live_snapshot_operation_context_t context{
        cancellation, budget.deadline(), make_wall_deadline(request_.limits.maximum_elapsed)};

    std::unique_lock<std::timed_mutex> operation_lock(operation_mutex_, std::defer_lock);
    const auto locked =
        lock_request_mutex(operation_lock, budget, context, *clock_, "read_lock");
    if (!locked)
        return live_snapshot_result_t<live_snapshot_read_t>::failure(locked.error());

    auto budget_check = budget.reserve_result_bytes(size, cancellation.stop_requested(), clock_->now());
    if (!budget_check) {
        return live_snapshot_result_t<live_snapshot_read_t>::failure(
            map_budget_error(budget_check.error(), "read_result"));
    }

    const auto window_offset = address - request_.window_base;
    const auto read_end = address + size;
    const auto page_bytes = static_cast<std::uint64_t>(request_.limits.maximum_page_bytes);
    const auto first_page = window_offset / page_bytes;
    const auto last_page = (read_end - 1U - request_.window_base) / page_bytes;
    const auto page_count = last_page - first_page + 1U;
    if (page_count > (std::numeric_limits<std::uint32_t>::max)()) {
        return live_snapshot_result_t<live_snapshot_read_t>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::page_limit_exceeded, "read_pages",
                                     request_.limits.maximum_pages_per_request, page_count));
    }
    budget_check = budget.reserve_pages(static_cast<std::uint32_t>(page_count),
                                        cancellation.stop_requested(), clock_->now());
    if (!budget_check) {
        return live_snapshot_result_t<live_snapshot_read_t>::failure(
            map_budget_error(budget_check.error(), "read_pages"));
    }

    const auto before = validate_identity(budget, context);
    if (!before) {
        std::unique_lock<std::timed_mutex> cache_lock(cache_mutex_);
        clear_cache();
        return live_snapshot_result_t<live_snapshot_read_t>::failure(before.error());
    }

    live_snapshot_read_t output;
    output.address = address;
    try {
        output.bytes.resize(static_cast<std::size_t>(size));
    } catch (const std::bad_alloc&) {
        return live_snapshot_result_t<live_snapshot_read_t>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::allocation_failed, "read_result"));
    }

    for (std::uint64_t page_index = first_page; page_index <= last_page; ++page_index) {
        const auto checkpoint = checkpoint_request(budget, context, *clock_, "read_page");
        if (!checkpoint) {
            return live_snapshot_result_t<live_snapshot_read_t>::failure(checkpoint.error());
        }
        const auto page_offset = page_index * page_bytes;
        const auto page_address = request_.window_base + page_offset;
        const auto remaining_window_bytes = request_.window_size - page_offset;
        const auto requested_page_size = (std::min)(page_bytes, remaining_window_bytes);
        const auto page_end = page_address + requested_page_size;
        const auto copy_start = (std::max)(address, page_address);
        const auto copy_end = (std::min)(read_end, page_end);
        const auto source_offset = static_cast<std::size_t>(copy_start - page_address);
        const auto destination_offset = static_cast<std::size_t>(copy_start - address);
        const auto copy_size = static_cast<std::size_t>(copy_end - copy_start);

        bool cache_hit = false;
        {
            std::unique_lock<std::timed_mutex> cache_lock(cache_mutex_);
            const auto cache_entry = cache_.find(page_address);
            if (cache_entry != cache_.end()) {
                touch_cache_entry(cache_entry);
                ++cache_hits_;
                std::copy_n(cache_entry->second.bytes.data() + source_offset, copy_size,
                            output.bytes.data() + destination_offset);
                cache_hit = true;
            }
        }
        if (cache_hit)
            continue;

        budget_check = budget.reserve_adapter_bytes(requested_page_size,
                                                     cancellation.stop_requested(), clock_->now());
        if (!budget_check) {
            return live_snapshot_result_t<live_snapshot_read_t>::failure(
                map_budget_error(budget_check.error(), "read_adapter"));
        }

        auto page_result = read_page_bounded(page_address, requested_page_size, budget, context);
        if (!page_result) {
            const auto error = normalize_adapter_error(page_result.error(), "read_adapter");
            if (invalidates_cached_identity(error.code) ||
                error.code == live_snapshot_error_code_t::cancelled ||
                error.code == live_snapshot_error_code_t::deadline_exceeded) {
                std::unique_lock<std::timed_mutex> cache_lock(cache_mutex_);
                clear_cache();
            }
            return live_snapshot_result_t<live_snapshot_read_t>::failure(error);
        }
        auto page = std::move(page_result).take_value();
        const auto post_read = checkpoint_request(budget, context, *clock_, "read_adapter");
        if (!post_read)
            return live_snapshot_result_t<live_snapshot_read_t>::failure(post_read.error());
        if (page.address != page_address) {
            return live_snapshot_result_t<live_snapshot_read_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::invalid_adapter,
                                         "read_adapter", page_address, page.address));
        }
        if (page.bytes.size() != requested_page_size) {
            return live_snapshot_result_t<live_snapshot_read_t>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::partial_read,
                                         "read_adapter", requested_page_size,
                                         page.bytes.size()));
        }

        {
            std::unique_lock<std::timed_mutex> cache_lock(cache_mutex_);
            const auto cached = cache_page(page_address, std::move(page.bytes));
            if (!cached)
                return live_snapshot_result_t<live_snapshot_read_t>::failure(cached.error());
            const auto cache_entry = cache_.find(page_address);
            if (cache_entry == cache_.end()) {
                return live_snapshot_result_t<live_snapshot_read_t>::failure(
                    make_live_snapshot_error(live_snapshot_error_code_t::invalid_adapter,
                                             "read_adapter"));
            }
            ++cache_misses_;
            std::copy_n(cache_entry->second.bytes.data() + source_offset, copy_size,
                        output.bytes.data() + destination_offset);
        }
    }

    const auto after = validate_identity(budget, context);
    if (!after) {
        std::unique_lock<std::timed_mutex> cache_lock(cache_mutex_);
        clear_cache();
        return live_snapshot_result_t<live_snapshot_read_t>::failure(after.error());
    }
    return live_snapshot_result_t<live_snapshot_read_t>::success(std::move(output));
}

live_snapshot_result_t<void> live_snapshot_provider_t::cache_page(
    std::uint64_t address, std::vector<std::uint8_t> bytes)
{
    if (bytes.empty() || bytes.size() > request_.limits.maximum_cached_bytes) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::cache_limit_exceeded, "cache_page",
                                     request_.limits.maximum_cached_bytes, bytes.size()));
    }
    while (!cache_lru_.empty() &&
           (cache_.size() >= request_.limits.maximum_cached_pages ||
            cached_bytes_ > request_.limits.maximum_cached_bytes - bytes.size())) {
        evict_oldest_cache_entry();
    }
    if (cache_.size() >= request_.limits.maximum_cached_pages ||
        cached_bytes_ > request_.limits.maximum_cached_bytes - bytes.size()) {
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::cache_limit_exceeded, "cache_page",
                                     request_.limits.maximum_cached_bytes, bytes.size()));
    }
    try {
        cache_lru_.push_front(address);
        const auto position = cache_lru_.begin();
        const auto inserted = cache_.emplace(address, cache_entry_t{std::move(bytes), position});
        if (!inserted.second) {
            cache_lru_.pop_front();
            return live_snapshot_result_t<void>::failure(
                make_live_snapshot_error(live_snapshot_error_code_t::invalid_adapter, "cache_page"));
        }
        cached_bytes_ += inserted.first->second.bytes.size();
    } catch (const std::bad_alloc&) {
        if (!cache_lru_.empty() && cache_lru_.front() == address && cache_.find(address) == cache_.end())
            cache_lru_.pop_front();
        return live_snapshot_result_t<void>::failure(
            make_live_snapshot_error(live_snapshot_error_code_t::allocation_failed, "cache_page"));
    }
    return live_snapshot_result_t<void>::success();
}

void live_snapshot_provider_t::touch_cache_entry(
    std::unordered_map<std::uint64_t, cache_entry_t>::iterator entry) noexcept
{
    cache_lru_.splice(cache_lru_.begin(), cache_lru_, entry->second.lru_position);
    entry->second.lru_position = cache_lru_.begin();
}

void live_snapshot_provider_t::clear_cache() noexcept
{
    cache_.clear();
    cache_lru_.clear();
    cached_bytes_ = 0;
}

void live_snapshot_provider_t::evict_oldest_cache_entry() noexcept
{
    if (cache_lru_.empty())
        return;
    const auto address = cache_lru_.back();
    const auto entry = cache_.find(address);
    if (entry != cache_.end()) {
        cached_bytes_ -= entry->second.bytes.size();
        cache_.erase(entry);
    }
    cache_lru_.pop_back();
    ++cache_evictions_;
}

}
