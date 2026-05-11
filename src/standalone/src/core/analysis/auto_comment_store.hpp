#pragma once

#include <cstdint>
#include <functional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace auto_comment_store {

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

inline void clear() {
	std::unique_lock<std::shared_mutex> lk(detail::mutex());
	detail::map().clear();
}

inline size_t clear_in_range(uint64_t lo, uint64_t hi) {
	if (lo > hi)
		return 0;
	std::unique_lock<std::shared_mutex> lk(detail::mutex());
	auto& m = detail::map();
	size_t removed = 0;
	for (auto it = m.begin(); it != m.end(); ) {
		if (it->first >= lo && it->first < hi) {
			it = m.erase(it);
			++removed;
		} else {
			++it;
		}
	}
	return removed;
}

inline size_t clear_module(uint64_t base, uint64_t size) {
	if (size == 0)
		return 0;
	return clear_in_range(base, base + size);
}

inline void enumerate(const std::function<void(uint64_t, const std::string&)>& visitor) {
	if (!visitor)
		return;
	std::shared_lock<std::shared_mutex> lk(detail::mutex());
	for (const auto& kv : detail::map())
		visitor(kv.first, kv.second);
}

inline std::vector<std::pair<uint64_t, std::string>> snapshot() {
	std::shared_lock<std::shared_mutex> lk(detail::mutex());
	std::vector<std::pair<uint64_t, std::string>> out;
	out.reserve(detail::map().size());
	for (const auto& kv : detail::map())
		out.emplace_back(kv.first, kv.second);
	return out;
}

}
