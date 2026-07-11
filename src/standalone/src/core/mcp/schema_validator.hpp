#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace mcp_standalone::ida_compat
{
    using json = nlohmann::json;

    struct schema_error_t
    {
        std::string path;
        std::string message;
        std::string schema_fragment;
    };

    struct validation_result_t
    {
        bool valid = true;
        std::vector<schema_error_t> errors;
        std::string summary() const;
    };

    validation_result_t validate_tool_args(
        const std::string& tool_name,
        const json& args,
        const json& schema);

    validation_result_t validate_tool_args(
        const std::string& tool_name,
        const json& args);

    validation_result_t schema_validator_status();

    void register_schema_validator();
}
