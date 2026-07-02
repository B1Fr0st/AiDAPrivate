#pragma once

#include "../../../mcp/mcp_standalone.hpp"

namespace aida {
namespace burp {
namespace offensive {
namespace client_attack {

mcp_standalone::tool_result_t csrf_test(const nlohmann::json& params);
mcp_standalone::tool_result_t clickjacking_test(const nlohmann::json& params);
mcp_standalone::tool_result_t postmessage_scan(const nlohmann::json& params);
mcp_standalone::tool_result_t prototype_pollution(const nlohmann::json& params);
mcp_standalone::tool_result_t dom_clobbering(const nlohmann::json& params);
mcp_standalone::tool_result_t cors_exploit(const nlohmann::json& params);
mcp_standalone::tool_result_t get_status(const nlohmann::json& params);
mcp_standalone::tool_result_t get_results(const nlohmann::json& params);

}
}
}
}
