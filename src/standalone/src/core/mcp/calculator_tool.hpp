#pragma once

#include "mcp_standalone.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace mcp_standalone::ida_compat
{
    using json = nlohmann::json;

    struct calc_request_t
    {
        std::string id;
        std::string expression;
        std::string format = "hex";
    };

    struct calc_result_t
    {
        std::string id;
        bool success = false;
        std::string value_decimal;
        std::string value_hex;
        std::string value_binary;
        std::string value_octal;
        std::string error;
        json extra = json::object();
    };

    static constexpr std::size_t CALC_MAX_ITEMS = 128;
    static constexpr std::size_t CALC_MAX_TOKENS = 4096;
    static constexpr std::size_t CALC_MAX_NESTING = 128;
    static constexpr std::size_t CALC_MAX_BITS = 65536;

    tool_result_t tool_calculate(const json& params, const workspace_request_context_t& ctx);
    void register_calculator_tool(server_t& server);
}
