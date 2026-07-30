#pragma once

#include "tile_decode_orchestrator.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

namespace aida::analysis {

struct decode_work_item_t final {
    tile_decode_request_t request;
    std::uint32_t shard_index = 0;
};

struct decode_worker_pool_statistics_t final {
    std::uint64_t completion_push_count = 0;
    std::uint64_t steal_count = 0;
    std::uint64_t backpressure_wait_count = 0;
    std::uint64_t inline_drain_count = 0;
    std::uint64_t max_queue_depth_seen = 0;
};

class decode_worker_pool_t final {
public:
    static constexpr std::uint32_t maximum_shard_slots = 64;

    using lease_hook_t = bool (*)(void* context, std::uint32_t worker_index);
    using completion_signal_t = void (*)(void* context);

    static workspace_result_t<std::unique_ptr<decode_worker_pool_t>> create(
        std::uint32_t worker_count,
        const production_tile_decode_executor_options_t& options,
        std::uint64_t maximum_frontier_wave,
        const cancellation_token_t& cancellation);
    ~decode_worker_pool_t();

    decode_worker_pool_t(const decode_worker_pool_t&) = delete;
    decode_worker_pool_t& operator=(const decode_worker_pool_t&) = delete;
    decode_worker_pool_t(decode_worker_pool_t&&) = delete;
    decode_worker_pool_t& operator=(decode_worker_pool_t&&) = delete;

    void bind_snapshot(const provider_snapshot_t& snapshot) noexcept;
    workspace_result_t<void> submit(std::uint32_t home_worker,
                                    decode_work_item_t item);
    bool pop_completion(std::uint32_t shard_slot,
                        tile_decode_completion_t& out);
    bool wait_completion(std::uint32_t shard_slot,
                         tile_decode_completion_t& out);
    void request_stop() noexcept;
    bool drained() const noexcept;
    bool has_fatal() const noexcept;
    workspace_error_t fatal_error() const;
    std::uint32_t worker_count() const noexcept;

    void set_lease_hook(lease_hook_t hook, void* context) noexcept;
    void clear_lease_hook() noexcept;
    void set_completion_signal(completion_signal_t signal, void* context) noexcept;
    void clear_completion_signal() noexcept;
    decode_worker_pool_statistics_t statistics() const noexcept;

private:
    struct worker_state_t;
    struct impl_t;
    explicit decode_worker_pool_t(std::unique_ptr<impl_t> impl) noexcept;

    std::unique_ptr<impl_t> impl_;
};

}
