#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <utility>
#include <vector>

#include "../analysis/workspace/workspace_types.hpp"

namespace nav_history {

inline constexpr size_t kMaxEntries = 256;

class workspace_history_t {
public:
    explicit workspace_history_t(aida::analysis::binary_id_t binary_id,
                                 std::size_t capacity = kMaxEntries)
        : binary_id_(std::move(binary_id)), capacity_(capacity == 0 ? 1 : capacity) {}

    const aida::analysis::binary_id_t& binary_id() const noexcept { return binary_id_; }

    void push(aida::analysis::address_t address) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!entries_.empty() && entries_.back() == address)
            return;
        if (entries_.size() >= capacity_)
            entries_.erase(entries_.begin(),
                entries_.begin() + static_cast<std::ptrdiff_t>(
                    entries_.size() - capacity_ + 1));
        entries_.push_back(address);
    }

    bool pop(aida::analysis::address_t* output) {
        if (!output)
            return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (entries_.empty())
            return false;
        *output = entries_.back();
        entries_.pop_back();
        return true;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.clear();
    }

    std::vector<aida::analysis::address_t> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_;
    }

private:
    aida::analysis::binary_id_t binary_id_;
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::vector<aida::analysis::address_t> entries_;
};

inline std::mutex& mutex_ref() {
    static std::mutex m;
    return m;
}

inline std::vector<uint64_t>& stack_ref() {
    static std::vector<uint64_t> s;
    return s;
}

inline void push(uint64_t addr) {
    if (addr == 0) return;
    std::lock_guard<std::mutex> lk(mutex_ref());
    auto& s = stack_ref();
    if (!s.empty() && s.back() == addr) return;
    if (s.size() >= kMaxEntries) {
        s.erase(s.begin(), s.begin() + (s.size() - kMaxEntries + 1));
    }
    s.push_back(addr);
}

inline bool pop(uint64_t* out_addr) {
    if (!out_addr) return false;
    std::lock_guard<std::mutex> lk(mutex_ref());
    auto& s = stack_ref();
    if (s.empty()) return false;
    *out_addr = s.back();
    s.pop_back();
    return true;
}

inline void clear() {
    std::lock_guard<std::mutex> lk(mutex_ref());
    stack_ref().clear();
}

inline size_t size() {
    std::lock_guard<std::mutex> lk(mutex_ref());
    return stack_ref().size();
}

}
