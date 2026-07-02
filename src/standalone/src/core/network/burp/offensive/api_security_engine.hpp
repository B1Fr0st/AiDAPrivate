#pragma once

#include "../../../mcp/mcp_standalone.hpp"

namespace aida {
namespace burp {
namespace offensive {
namespace api_security {

mcp_standalone::tool_result_t discover(const nlohmann::json& params);
mcp_standalone::tool_result_t param_fuzz(const nlohmann::json& params);
mcp_standalone::tool_result_t mass_assignment(const nlohmann::json& params);
mcp_standalone::tool_result_t authz_matrix(const nlohmann::json& params);
mcp_standalone::tool_result_t rate_limit_test(const nlohmann::json& params);
mcp_standalone::tool_result_t schema_diff(const nlohmann::json& params);
mcp_standalone::tool_result_t get_status(const nlohmann::json& params);
mcp_standalone::tool_result_t get_results(const nlohmann::json& params);

}
}
}
}
