#pragma once

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../analysis/workspace/workspace_types.hpp"

namespace comment_store {

class workspace_store_t {
public:
    explicit workspace_store_t(aida::analysis::binary_id_t binary_id)
        : binary_id_(std::move(binary_id)) {}

    const aida::analysis::binary_id_t& binary_id() const noexcept { return binary_id_; }

    void set(aida::analysis::address_t address, std::string text) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        if (text.empty())
            values_.erase(address);
        else
            values_[address] = std::move(text);
    }

    std::string get(const aida::analysis::address_t& address) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto found = values_.find(address);
        return found == values_.end() ? std::string() : found->second;
    }

    bool has(const aida::analysis::address_t& address) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return values_.find(address) != values_.end();
    }

    std::vector<std::pair<aida::analysis::address_t, std::string>> snapshot() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::pair<aida::analysis::address_t, std::string>> output;
        output.reserve(values_.size());
        for (const auto& item : values_)
            output.push_back(item);
        std::sort(output.begin(), output.end(),
            [](const auto& left, const auto& right) { return left.first < right.first; });
        return output;
    }

    void replace(const std::vector<std::pair<aida::analysis::address_t, std::string>>& values) {
        std::unordered_map<aida::analysis::address_t, std::string,
            aida::analysis::address_hash_t> next;
        next.reserve(values.size());
        for (const auto& item : values) {
            if (!item.second.empty())
                next.insert_or_assign(item.first, item.second);
        }
        std::unique_lock<std::shared_mutex> lock(mutex_);
        values_.swap(next);
    }

private:
    aida::analysis::binary_id_t binary_id_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<aida::analysis::address_t, std::string,
        aida::analysis::address_hash_t> values_;
};

namespace detail {

inline std::shared_mutex& mutex() {
    static std::shared_mutex m;
    return m;
}

inline std::unordered_map<uint64_t, std::string>& map() {
    static std::unordered_map<uint64_t, std::string> m;
    return m;
}

}

inline void set(uint64_t addr, std::string text) {
    std::unique_lock<std::shared_mutex> lk(detail::mutex());
    if (text.empty())
        detail::map().erase(addr);
    else
        detail::map()[addr] = std::move(text);
}

inline std::string get(uint64_t addr) {
    std::shared_lock<std::shared_mutex> lk(detail::mutex());
    auto& m = detail::map();
    auto it = m.find(addr);
    if (it == m.end())
        return std::string();
    return it->second;
}

inline bool has(uint64_t addr) {
    std::shared_lock<std::shared_mutex> lk(detail::mutex());
    auto& m = detail::map();
    return m.find(addr) != m.end();
}

}
