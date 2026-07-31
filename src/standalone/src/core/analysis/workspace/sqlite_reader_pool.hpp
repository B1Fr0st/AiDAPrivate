#pragma once

#include "analysis_workspace.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

struct sqlite3;

namespace aida::analysis {

inline constexpr std::size_t sqlite_reader_pool_min_readers = 2;
inline constexpr std::size_t sqlite_reader_pool_max_readers = 8;
inline constexpr std::size_t sqlite_reader_pool_default_statement_cache_capacity = 16;

std::size_t sqlite_reader_pool_default_size() noexcept;

using sqlite_reader_connection_factory_t =
    std::function<workspace_result_t<sqlite3*>()>;

struct sqlite_reader_pool_options_t {
    std::size_t reader_count = 0;
    std::chrono::milliseconds acquire_timeout{2500};
    std::size_t statement_cache_capacity =
        sqlite_reader_pool_default_statement_cache_capacity;
};

struct sqlite_reader_pool_stats_t {
    std::uint64_t acquisitions = 0;
    std::uint64_t immediate_acquisitions = 0;
    std::uint64_t waits = 0;
    std::uint64_t wait_ns_total = 0;
    std::uint64_t wait_ns_max = 0;
    std::uint64_t timeouts = 0;
    std::uint64_t cancellations = 0;
    std::size_t readers = 0;
    std::size_t idle = 0;
    std::size_t outstanding = 0;
    bool closing = false;
};

class sqlite_reader_pool_t final
    : public std::enable_shared_from_this<sqlite_reader_pool_t> {
public:
    class lease_t final {
    public:
        lease_t() = default;
        ~lease_t();
        lease_t(lease_t&& other) noexcept;
        lease_t& operator=(lease_t&& other) noexcept;
        lease_t(const lease_t&) = delete;
        lease_t& operator=(const lease_t&) = delete;

        sqlite3* get() const noexcept { return connection_; }
        explicit operator bool() const noexcept { return connection_ != nullptr; }
        void reset() noexcept;

    private:
        lease_t(std::shared_ptr<sqlite_reader_pool_t> pool, sqlite3* connection)
            : pool_(std::move(pool)), connection_(connection) {
        }

        std::shared_ptr<sqlite_reader_pool_t> pool_;
        sqlite3* connection_ = nullptr;

        friend class sqlite_reader_pool_t;
    };

    static workspace_result_t<std::shared_ptr<sqlite_reader_pool_t>>
        create(sqlite_reader_connection_factory_t factory,
               sqlite_reader_pool_options_t options = {});

    ~sqlite_reader_pool_t();
    sqlite_reader_pool_t(const sqlite_reader_pool_t&) = delete;
    sqlite_reader_pool_t& operator=(const sqlite_reader_pool_t&) = delete;

    workspace_result_t<lease_t> acquire(const cancellation_token_t& cancel = {});
    sqlite_reader_pool_stats_t stats() const;
    void close() noexcept;

private:
    struct state_t;

    explicit sqlite_reader_pool_t(std::shared_ptr<state_t> state)
        : state_(std::move(state)) {
    }

    void release(sqlite3* connection) noexcept;

    std::shared_ptr<state_t> state_;
};

}
