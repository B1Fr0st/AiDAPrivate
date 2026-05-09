#pragma once

#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace comment_store {

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
