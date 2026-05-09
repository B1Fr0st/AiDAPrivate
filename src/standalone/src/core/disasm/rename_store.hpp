#pragma once

#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace rename_store {

struct state_t {
	std::unordered_map<uint64_t, std::string> names;
	std::shared_mutex                         mutex;
};

inline state_t& g_state() {
	static state_t s;
	return s;
}

inline void set(uint64_t addr, std::string name) {
	auto& s = g_state();
	std::unique_lock<std::shared_mutex> lk(s.mutex);
	if (name.empty()) {
		s.names.erase(addr);
		return;
	}
	s.names[addr] = std::move(name);
}

inline std::string get(uint64_t addr) {
	auto& s = g_state();
	std::shared_lock<std::shared_mutex> lk(s.mutex);
	auto it = s.names.find(addr);
	if (it == s.names.end()) return std::string();
	return it->second;
}

inline bool has(uint64_t addr) {
	auto& s = g_state();
	std::shared_lock<std::shared_mutex> lk(s.mutex);
	return s.names.find(addr) != s.names.end();
}

inline void clear(uint64_t addr) {
	auto& s = g_state();
	std::unique_lock<std::shared_mutex> lk(s.mutex);
	s.names.erase(addr);
}

inline std::string resolve_or(uint64_t addr, std::string fallback) {
	auto& s = g_state();
	std::shared_lock<std::shared_mutex> lk(s.mutex);
	auto it = s.names.find(addr);
	if (it != s.names.end()) return it->second;
	return fallback;
}

}
