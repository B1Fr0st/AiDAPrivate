#include "sqlite_reader_pool.hpp"

#include "analysis_metrics.hpp"
#include "sqlite_statement_cache.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

workspace_error_t reader_pool_error(workspace_error_code_t code,
                                    std::string message) {
    return make_workspace_error(code, std::move(message), "sqlite_reader_pool");
}

workspace_error_t reader_pool_cancelled(const cancellation_token_t& cancel) {
    auto error = reader_pool_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                   : workspace_error_code_t::cancelled,
        "workspace database reader pool acquisition was cancelled");
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

}

struct sqlite_reader_pool_t::state_t {
    sqlite_reader_connection_factory_t factory;
    sqlite_reader_pool_options_t options;
    mutable std::mutex mutex;
    std::condition_variable idle_cv;
    std::vector<sqlite3*> idle;
    std::vector<sqlite3*> all;
    std::unordered_map<sqlite3*, std::shared_ptr<sqlite_statement_cache_t>> caches;
    std::size_t outstanding = 0;
    bool closing = false;
    bool interrupted = false;
    std::uint64_t acquisitions = 0;
    std::uint64_t immediate_acquisitions = 0;
    std::uint64_t waits = 0;
    std::uint64_t wait_ns_total = 0;
    std::uint64_t wait_ns_max = 0;
    std::uint64_t timeouts = 0;
    std::uint64_t cancellations = 0;
};

std::size_t sqlite_reader_pool_default_size() noexcept {
    const unsigned hardware = std::thread::hardware_concurrency();
    const std::size_t quarter = hardware == 0
        ? sqlite_reader_pool_min_readers
        : static_cast<std::size_t>(hardware / 4U);
    return (std::min)((std::max)(quarter, sqlite_reader_pool_min_readers),
                      sqlite_reader_pool_max_readers);
}

sqlite_reader_pool_t::lease_t::~lease_t() {
    reset();
}

sqlite_reader_pool_t::lease_t::lease_t(lease_t&& other) noexcept
    : pool_(std::move(other.pool_)), connection_(other.connection_) {
    other.connection_ = nullptr;
}

sqlite_reader_pool_t::lease_t&
sqlite_reader_pool_t::lease_t::operator=(lease_t&& other) noexcept {
    if (this != &other) {
        reset();
        pool_ = std::move(other.pool_);
        connection_ = other.connection_;
        other.connection_ = nullptr;
    }
    return *this;
}

void sqlite_reader_pool_t::lease_t::reset() noexcept {
    if (!connection_)
        return;
    sqlite3* connection = connection_;
    connection_ = nullptr;
    auto pool = std::move(pool_);
    pool_.reset();
    if (pool)
        pool->release(connection);
}

workspace_result_t<std::shared_ptr<sqlite_reader_pool_t>>
sqlite_reader_pool_t::create(sqlite_reader_connection_factory_t factory,
                             sqlite_reader_pool_options_t options) {
    if (!factory) {
        return workspace_result_t<std::shared_ptr<sqlite_reader_pool_t>>::failure(
            reader_pool_error(workspace_error_code_t::invalid_argument,
                              "workspace database reader pool requires a connection factory"));
    }
    if (options.acquire_timeout <= std::chrono::milliseconds::zero()) {
        return workspace_result_t<std::shared_ptr<sqlite_reader_pool_t>>::failure(
            reader_pool_error(workspace_error_code_t::invalid_argument,
                              "workspace database reader pool acquire timeout must be positive"));
    }
    std::size_t reader_count = options.reader_count;
    if (reader_count == 0)
        reader_count = sqlite_reader_pool_default_size();
    reader_count = (std::min)((std::max)(reader_count, sqlite_reader_pool_min_readers),
                              sqlite_reader_pool_max_readers);
    auto state = std::make_shared<state_t>();
    state->factory = std::move(factory);
    state->options = options;
    state->idle.reserve(reader_count);
    for (std::size_t index = 0; index < reader_count; ++index) {
        auto connection = state->factory();
        if (!connection) {
            for (sqlite3* opened : state->all) {
                sqlite_statement_cache_unregister(opened);
                state->caches.erase(opened);
                sqlite3_close_v2(opened);
            }
            state->idle.clear();
            state->all.clear();
            return workspace_result_t<std::shared_ptr<sqlite_reader_pool_t>>::failure(
                connection.error());
        }
        sqlite3* database = connection.take_value();
        auto cache = std::make_shared<sqlite_statement_cache_t>(
            options.statement_cache_capacity == 0
                ? sqlite_reader_pool_default_statement_cache_capacity
                : options.statement_cache_capacity);
        sqlite_statement_cache_register(database, cache);
        state->caches.emplace(database, std::move(cache));
        state->idle.push_back(database);
        state->all.push_back(database);
    }
    return workspace_result_t<std::shared_ptr<sqlite_reader_pool_t>>::success(
        std::shared_ptr<sqlite_reader_pool_t>(
            new sqlite_reader_pool_t(std::move(state))));
}

sqlite_reader_pool_t::~sqlite_reader_pool_t() {
    close();
}

workspace_result_t<sqlite_reader_pool_t::lease_t>
sqlite_reader_pool_t::acquire(const cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        return workspace_result_t<lease_t>::failure(reader_pool_cancelled(cancel));
    }
    const auto started = std::chrono::steady_clock::now();
    auto deadline = started + state_->options.acquire_timeout;
    if (cancel.deadline())
        deadline = (std::min)(deadline, *cancel.deadline());
    const auto record_wait = [&] {
        const auto waited_ns = static_cast<std::uint64_t>(
            (std::max<std::int64_t>)(0,
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - started).count()));
        state_->wait_ns_total += waited_ns;
        if (waited_ns > state_->wait_ns_max)
            state_->wait_ns_max = waited_ns;
        workspace_io_metrics().add(workspace_io_metric_t::reader_pool_wait_ns_total,
                                   waited_ns);
        workspace_io_metrics().set_max(workspace_io_metric_t::reader_pool_wait_ns_max,
                                       waited_ns);
    };
    bool waited = false;
    std::unique_lock<std::mutex> lock(state_->mutex);
    for (;;) {
        if (state_->closing) {
            return workspace_result_t<lease_t>::failure(reader_pool_error(
                workspace_error_code_t::workspace_closing,
                "workspace database reader pool is closing"));
        }
        if (!state_->idle.empty()) {
            sqlite3* connection = state_->idle.back();
            state_->idle.pop_back();
            ++state_->outstanding;
            ++state_->acquisitions;
            if (waited) {
                record_wait();
            } else {
                ++state_->immediate_acquisitions;
            }
            workspace_io_metrics().add(
                workspace_io_metric_t::reader_pool_acquisitions, 1);
            return workspace_result_t<lease_t>::success(
                lease_t(shared_from_this(), connection));
        }
        if (cancel.stop_requested()) {
            ++state_->cancellations;
            return workspace_result_t<lease_t>::failure(reader_pool_cancelled(cancel));
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            ++state_->timeouts;
            if (waited)
                record_wait();
            workspace_io_metrics().add(workspace_io_metric_t::reader_pool_timeouts, 1);
            auto error = reader_pool_error(
                workspace_error_code_t::deadline_exceeded,
                "workspace database reader pool acquisition timed out");
            error.deadline = true;
            return workspace_result_t<lease_t>::failure(std::move(error));
        }
        if (!waited) {
            waited = true;
            ++state_->waits;
        }
        const auto remaining_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto slice = (std::min)(std::chrono::milliseconds{10}, remaining_ms);
        state_->idle_cv.wait_for(lock, slice);
    }
}

sqlite_reader_pool_stats_t sqlite_reader_pool_t::stats() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    sqlite_reader_pool_stats_t result;
    result.acquisitions = state_->acquisitions;
    result.immediate_acquisitions = state_->immediate_acquisitions;
    result.waits = state_->waits;
    result.wait_ns_total = state_->wait_ns_total;
    result.wait_ns_max = state_->wait_ns_max;
    result.timeouts = state_->timeouts;
    result.cancellations = state_->cancellations;
    result.readers = state_->all.size();
    result.idle = state_->idle.size();
    result.outstanding = state_->outstanding;
    result.closing = state_->closing;
    return result;
}

void sqlite_reader_pool_t::release(sqlite3* connection) noexcept {
    if (!connection)
        return;
    if (!sqlite3_get_autocommit(connection))
        sqlite3_exec(connection, "ROLLBACK", nullptr, nullptr, nullptr);
    std::lock_guard<std::mutex> lock(state_->mutex);
    state_->idle.push_back(connection);
    if (state_->outstanding != 0)
        --state_->outstanding;
    state_->idle_cv.notify_all();
}

void sqlite_reader_pool_t::close() noexcept {
    std::vector<sqlite3*> connections;
    {
        std::unique_lock<std::mutex> lock(state_->mutex);
        if (state_->closing && state_->all.empty())
            return;
        state_->closing = true;
        if (!state_->interrupted) {
            state_->interrupted = true;
            for (sqlite3* connection : state_->all)
                sqlite3_interrupt(connection);
        }
        state_->idle_cv.notify_all();
        state_->idle_cv.wait(lock, [&] { return state_->outstanding == 0; });
        connections = std::move(state_->all);
        state_->all.clear();
        state_->idle.clear();
    }
    for (sqlite3* connection : connections) {
        sqlite_statement_cache_unregister(connection);
        auto found = state_->caches.find(connection);
        if (found != state_->caches.end()) {
            found->second.reset();
            state_->caches.erase(found);
        }
        sqlite3_close_v2(connection);
    }
}

}
