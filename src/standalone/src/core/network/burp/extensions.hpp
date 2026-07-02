#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace extensions {

struct script_descriptor_t
{
    std::string id;
    std::string name;
    std::string language;
    std::string relative_path;
    std::uintmax_t size_bytes = 0;
};

struct tool_descriptor_t
{
    std::string name;
    std::string description;
    bool read_only = true;
    std::string script_id;
    nlohmann::json input_schema = nlohmann::json::object();
};

struct extension_record_t
{
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::string manifest_path;
    bool enabled = false;
    bool valid = false;
    std::string validation_error;
    std::vector<script_descriptor_t> scripts;
    std::vector<tool_descriptor_t> tools;
};

struct registry_snapshot_t
{
    std::string root;
    std::uint64_t generation = 0;
    std::string last_error;
    std::vector<extension_record_t> extensions;
};

std::filesystem::path approved_extension_root();
bool refresh(std::string* error = nullptr);
registry_snapshot_t snapshot();
std::optional<extension_record_t> find_extension(const std::string& id);
bool set_enabled(const std::string& id, bool enabled, std::string* error = nullptr);
nlohmann::json snapshot_json(bool include_disabled = true, bool include_descriptors = true);
std::string last_error();

}
}
}
