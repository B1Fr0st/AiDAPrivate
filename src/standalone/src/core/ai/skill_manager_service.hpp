#pragma once

#include "skills.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace aida::skill_manager_service {

enum class operation_state_t : std::uint8_t {
	idle,
	loading,
	succeeded,
	failed,
	cancelled
};

struct snapshot_t {
	std::uint64_t generation = 0;
	operation_state_t state = operation_state_t::idle;
	std::string operation;
	std::string detail;
	std::vector<aida::skills::skill_metadata_t> skills;
	std::set<std::string> disabled;
	std::vector<std::string> remote_urls;
	std::map<std::string, aida::skills::remote_index_t> remote_indices;
	std::string resolved_name;
	std::string resolved_body;
	std::vector<std::string> resolved_hints;
};

using snapshot_ptr = std::shared_ptr<const snapshot_t>;

snapshot_ptr snapshot();
void begin_frame();
const aida::skills::skill_metadata_t* find(const snapshot_ptr& publication,
	const std::string& name);
bool request_reindex(std::string* error = nullptr);
bool request_resolve(const std::string& name, std::string* error = nullptr);
bool request_set_enabled(const std::string& name, bool enabled,
	std::string* error = nullptr);
bool request_add_remote_url(const std::string& url, std::string* error = nullptr);
bool request_remove_remote_url(const std::string& url, std::string* error = nullptr);
bool request_fetch_remote(const std::string& url, std::string* error = nullptr);
bool request_install(const std::string& url, const std::string& name,
	std::string* error = nullptr);
bool request_uninstall(const std::string& name, std::uint64_t reviewed_generation,
	std::string* error = nullptr);

}
