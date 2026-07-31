#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace aida::analysis {

inline std::atomic<std::uint64_t>& global_statement_cache_hits() noexcept {
    static std::atomic<std::uint64_t> hits{0};
    return hits;
}

inline std::atomic<std::uint64_t>& global_statement_cache_misses() noexcept {
    static std::atomic<std::uint64_t> misses{0};
    return misses;
}

class sqlite_statement_cache_t final {
public:
    explicit sqlite_statement_cache_t(std::size_t capacity = 64)
        : capacity_(capacity == 0 ? 1 : capacity) {
    }

    ~sqlite_statement_cache_t() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& entry : entries_) {
            if (entry.statement)
                sqlite3_finalize(entry.statement);
            entry.statement = nullptr;
        }
        entries_.clear();
        index_.clear();
    }

    sqlite_statement_cache_t(const sqlite_statement_cache_t&) = delete;
    sqlite_statement_cache_t& operator=(const sqlite_statement_cache_t&) = delete;

    sqlite3_stmt* acquire(sqlite3* database, const char* sql, int& status) {
        status = SQLITE_OK;
        if (!database || !sql || !*sql)
            return nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto found = index_.find(sql);
            if (found != index_.end()) {
                sqlite3_stmt* statement = found->second->statement;
                entries_.erase(found->second);
                index_.erase(found);
                hits_.fetch_add(1, std::memory_order_relaxed);
                global_statement_cache_hits().fetch_add(1, std::memory_order_relaxed);
                sqlite3_reset(statement);
                sqlite3_clear_bindings(statement);
                return statement;
            }
            misses_.fetch_add(1, std::memory_order_relaxed);
            global_statement_cache_misses().fetch_add(1, std::memory_order_relaxed);
        }
        sqlite3_stmt* statement = nullptr;
        status = sqlite3_prepare_v3(database, sql, -1, SQLITE_PREPARE_PERSISTENT,
                                    &statement, nullptr);
        if (status != SQLITE_OK) {
            if (statement)
                sqlite3_finalize(statement);
            return nullptr;
        }
        return statement;
    }

    void release(const std::string& sql, sqlite3_stmt* statement) {
        if (!statement)
            return;
        sqlite3_reset(statement);
        sqlite3_clear_bindings(statement);
        std::lock_guard<std::mutex> lock(mutex_);
        if (index_.find(sql) != index_.end()) {
            sqlite3_finalize(statement);
            return;
        }
        while (entries_.size() >= capacity_) {
            auto& oldest = entries_.back();
            if (oldest.statement)
                sqlite3_finalize(oldest.statement);
            index_.erase(oldest.sql);
            entries_.pop_back();
        }
        entries_.push_front(entry_t{sql, statement});
        index_.emplace(entries_.front().sql, entries_.begin());
    }

    std::size_t size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

    std::size_t capacity() const noexcept { return capacity_; }

    std::uint64_t hits() const noexcept {
        return hits_.load(std::memory_order_relaxed);
    }

    std::uint64_t misses() const noexcept {
        return misses_.load(std::memory_order_relaxed);
    }

private:
    struct entry_t {
        std::string sql;
        sqlite3_stmt* statement = nullptr;
    };

    using entry_list_t = std::list<entry_t>;

    const std::size_t capacity_;
    mutable std::mutex mutex_;
    entry_list_t entries_;
    std::unordered_map<std::string, typename entry_list_t::iterator> index_;
    std::atomic<std::uint64_t> hits_{0};
    std::atomic<std::uint64_t> misses_{0};
};

namespace detail {

inline std::mutex& statement_cache_registry_mutex() noexcept {
    static std::mutex mutex;
    return mutex;
}

inline std::unordered_map<sqlite3*, std::weak_ptr<sqlite_statement_cache_t>>&
statement_cache_registry() noexcept {
    static std::unordered_map<sqlite3*, std::weak_ptr<sqlite_statement_cache_t>> registry;
    return registry;
}

}

inline void sqlite_statement_cache_register(
    sqlite3* database, const std::shared_ptr<sqlite_statement_cache_t>& cache) {
    if (!database || !cache)
        return;
    std::lock_guard<std::mutex> lock(detail::statement_cache_registry_mutex());
    detail::statement_cache_registry()[database] = cache;
}

inline void sqlite_statement_cache_unregister(sqlite3* database) {
    if (!database)
        return;
    std::lock_guard<std::mutex> lock(detail::statement_cache_registry_mutex());
    detail::statement_cache_registry().erase(database);
}

inline std::shared_ptr<sqlite_statement_cache_t>
sqlite_statement_cache_lookup(sqlite3* database) {
    if (!database)
        return {};
    std::lock_guard<std::mutex> lock(detail::statement_cache_registry_mutex());
    auto found = detail::statement_cache_registry().find(database);
    if (found == detail::statement_cache_registry().end())
        return {};
    auto cache = found->second.lock();
    if (!cache)
        detail::statement_cache_registry().erase(found);
    return cache;
}

}
