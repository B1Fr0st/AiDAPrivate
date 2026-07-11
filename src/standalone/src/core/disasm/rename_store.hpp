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

namespace rename_store {

class workspace_store_t {
public:
	explicit workspace_store_t(aida::analysis::binary_id_t binary_id)
		: binary_id_(std::move(binary_id)) {}

	const aida::analysis::binary_id_t& binary_id() const noexcept { return binary_id_; }

	void set(aida::analysis::address_t address, std::string name) {
		std::unique_lock<std::shared_mutex> lock(mutex_);
		if (name.empty())
			names_.erase(address);
		else
			names_[address] = std::move(name);
	}

	std::string get(const aida::analysis::address_t& address) const {
		std::shared_lock<std::shared_mutex> lock(mutex_);
		auto found = names_.find(address);
		return found == names_.end() ? std::string() : found->second;
	}

	bool has(const aida::analysis::address_t& address) const {
		std::shared_lock<std::shared_mutex> lock(mutex_);
		return names_.find(address) != names_.end();
	}

	void clear(const aida::analysis::address_t& address) {
		std::unique_lock<std::shared_mutex> lock(mutex_);
		names_.erase(address);
	}

	std::string resolve_or(const aida::analysis::address_t& address,
		std::string fallback) const {
		std::shared_lock<std::shared_mutex> lock(mutex_);
		auto found = names_.find(address);
		return found == names_.end() ? std::move(fallback) : found->second;
	}

	std::vector<std::pair<aida::analysis::address_t, std::string>> snapshot() const {
		std::shared_lock<std::shared_mutex> lock(mutex_);
		std::vector<std::pair<aida::analysis::address_t, std::string>> output;
		output.reserve(names_.size());
		for (const auto& item : names_)
			output.push_back(item);
		std::sort(output.begin(), output.end(),
			[](const auto& left, const auto& right) { return left.first < right.first; });
		return output;
	}

private:
	aida::analysis::binary_id_t binary_id_;
	mutable std::shared_mutex mutex_;
	std::unordered_map<aida::analysis::address_t, std::string,
		aida::analysis::address_hash_t> names_;
};

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
