#pragma once

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace vm_guest_bridge {

struct active_session_t {
	bool active = false;
	std::wstring session_dir;
	std::wstring bridge_dir;
	std::wstring sample_path;
	uint64_t started_ms = 0;
};

void activate(const std::wstring& session_dir, const std::wstring& sample_path);
void deactivate();
bool is_active();
active_session_t current();

nlohmann::json request(const std::string& command,
                       const nlohmann::json& params,
                       uint32_t timeout_ms,
                       std::string* error_out);

std::string artifact_host_path(const std::string& artifact_name);

}
