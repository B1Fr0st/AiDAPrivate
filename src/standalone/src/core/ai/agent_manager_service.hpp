#pragma once

#include "agent_registry.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace aida::agent_manager_service {

enum class operation_state_t : std::uint8_t {
	idle = 0,
	loading,
	succeeded,
	failed,
	cancelled
};

struct snapshot_t {
	std::uint64_t generation = 0;
	std::uint64_t catalog_generation = 0;
	operation_state_t state = operation_state_t::idle;
	std::string operation;
	std::string detail;
	std::vector<aida::agent::agent_info_t> agents;
};

using snapshot_ptr = std::shared_ptr<const snapshot_t>;

snapshot_ptr snapshot();
void begin_frame();
bool request_reload(std::string* error = nullptr);
bool request_upsert(const aida::agent::agent_info_t& definition,
	const std::string& replaced_identity, std::uint64_t expected_catalog_generation,
	std::string* error = nullptr);
bool request_duplicate(const std::string& source_identity,
	const std::string& new_identity, std::uint64_t expected_catalog_generation,
	std::string* error = nullptr);
bool request_delete(const std::string& identity,
	std::uint64_t expected_catalog_generation, std::string* error = nullptr);
const aida::agent::agent_info_t* find(const snapshot_ptr& publication,
	const std::string& identity);

}
