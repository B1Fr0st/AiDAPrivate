#pragma once

#include "parallel_pass.hpp"

#include "../../../helpers/diag_log.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <stdexcept>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace aida::analysis {

enum class parallel_scope_domain_t : std::uint8_t {
    feature_worker = 0,
    general = 1
};

namespace detail {

inline aida::infra::taskflow_runtime::executor_domain_t parallel_scope_executor_domain(
    parallel_scope_domain_t domain) noexcept {
    return domain == parallel_scope_domain_t::general
        ? aida::infra::taskflow_runtime::executor_domain_t::general
        : aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
}

}

class shard_join_t final {
public:
    shard_join_t() = default;
    ~shard_join_t() { wait_noexcept(); }
    shard_join_t(shard_join_t&& other) noexcept
        : state_(std::move(other.state_)), cancel_flag_(std::move(other.cancel_flag_)) {}
    shard_join_t& operator=(shard_join_t&& other) noexcept {
        if (this != &other) {
            wait_noexcept();
            state_ = std::move(other.state_);
            cancel_flag_ = std::move(other.cancel_flag_);
        }
        return *this;
    }
    shard_join_t(const shard_join_t&) = delete;
    shard_join_t& operator=(const shard_join_t&) = delete;

    struct passkey_t {
    private:
        passkey_t() = default;
        template <typename F>
        friend shard_join_t run_shards_async(std::size_t, parallel_scope_domain_t,
            const char*, F&&, std::uint32_t);
    };

    shard_join_t(passkey_t, std::shared_ptr<detail::parallel_exec_state_base_t> state,
        std::shared_ptr<std::atomic<bool>> cancel_flag) noexcept
        : state_(std::move(state)), cancel_flag_(std::move(cancel_flag)) {}

    bool valid() const noexcept { return static_cast<bool>(state_); }

    void request_cancel() noexcept {
        if (cancel_flag_)
            cancel_flag_->store(true, std::memory_order_release);
    }

    void wait() {
        if (!state_)
            return;
        state_->wait_complete();
        auto completed = std::move(state_);
        state_.reset();
        completed->rethrow_first_exception();
    }

private:
    void wait_noexcept() noexcept {
        if (!state_)
            return;
        try {
            state_->wait_complete();
        } catch (...) {
        }
        state_.reset();
    }

    std::shared_ptr<detail::parallel_exec_state_base_t> state_;
    std::shared_ptr<std::atomic<bool>> cancel_flag_;
};

template <typename F>
shard_join_t run_shards_async(std::size_t item_count,
    parallel_scope_domain_t domain, const char* label, F&& item_fn,
    std::uint32_t workers = 0)
{
    namespace rt = aida::infra::taskflow_runtime;
    if (item_count == 0)
        return shard_join_t{};
    auto cancel_flag = std::make_shared<std::atomic<bool>>(false);
    auto gate = [cancel_flag] {
        return !cancel_flag->load(std::memory_order_acquire);
    };
    using state_t = detail::parallel_exec_state_t<detail::parallel_no_local_t,
        decltype(gate), std::decay_t<F>>;
    auto state = std::make_shared<state_t>(gate, std::forward<F>(item_fn));
    state->item_count = item_count;
    state->remaining.store(item_count, std::memory_order_relaxed);
    state->exceptions.assign(item_count, nullptr);
    const auto resolved = workers == 0 ? parallel_worker_count() : workers;
    const std::size_t participants = (std::min<std::size_t>)(
        static_cast<std::size_t>((std::max<std::uint32_t>)(1U, resolved)),
        item_count);
    std::size_t submitted = 0;
    for (std::size_t index = 0; index < participants; ++index) {
        rt::task_descriptor_t desc;
        desc.domain = detail::parallel_scope_executor_domain(domain);
        desc.owner_subsystem = "analysis_workspace";
        desc.label = label;
        desc.body = [state]() { state->run_participant(); };
        if (rt::submit(std::move(desc)).submitted)
            ++submitted;
    }
    if (submitted == 0) {
        state->exceptions[0] = std::make_exception_ptr(
            std::runtime_error("parallel_scope_submit_failed"));
        state->drain_abandoned();
        diag::log_tagged_fmt("parallel_scope",
            "parallel_scope_submit_failed label=%s items=%zu participants=%zu tid=%lu",
            label ? label : "<unnamed>",
            static_cast<unsigned long long>(item_count),
            static_cast<unsigned long long>(participants),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
    return shard_join_t{shard_join_t::passkey_t{}, state, cancel_flag};
}

}
