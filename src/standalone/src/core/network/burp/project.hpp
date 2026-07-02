#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace project {

bool initialize();
void shutdown();
nlohmann::json export_json();
bool import_json(const nlohmann::json& doc, bool replace_existing);
bool save_to_file(const std::string& path);
bool load_from_file(const std::string& path, bool replace_existing);
std::string last_error();

}
}
}
