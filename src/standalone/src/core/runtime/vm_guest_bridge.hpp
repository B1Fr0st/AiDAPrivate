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
	std::string bridge_kind;
	uint64_t started_ms = 0;
};

void activate(const std::wstring& session_dir, const std::wstring& sample_path);
bool activate_bridge(const std::wstring& session_dir,
                     const std::wstring& bridge_dir,
                     const std::wstring& sample_path,
                     const std::string& bridge_kind,
                     std::string* error_out = nullptr);
void deactivate();
bool is_active();
active_session_t current();
bool prepare_bridge_directory(const std::wstring& bridge_dir,
                              const std::wstring& guest_sample_path,
                              const std::wstring& guest_args,
                              std::string* error_out = nullptr);
nlohmann::json status_snapshot();

nlohmann::json request(const std::string& command,
                       const nlohmann::json& params,
                       uint32_t timeout_ms,
                       std::string* error_out);

std::string artifact_host_path(const std::string& artifact_name);

}
