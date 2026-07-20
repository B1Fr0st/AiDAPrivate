#pragma once

#include <cstddef>
#include <string>

#include <nlohmann/json.hpp>

#include "../../mcp/mcp_standalone.hpp"

namespace aida {
namespace burp {
namespace project {

inline constexpr std::size_t maximum_project_file_bytes =
    64ULL * 1024ULL * 1024ULL;

bool initialize();
void shutdown();
nlohmann::json export_json();
bool import_json(const nlohmann::json& doc, bool replace_existing);
bool save_to_file(const std::string& path);
bool load_from_file(const std::string& path, bool replace_existing);
std::string last_error();
void register_project_tools(mcp_standalone::server_t& srv);

}
}
}
