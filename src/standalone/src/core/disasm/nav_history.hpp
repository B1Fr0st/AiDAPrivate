#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

namespace nav_history {

inline constexpr size_t kMaxEntries = 256;

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
