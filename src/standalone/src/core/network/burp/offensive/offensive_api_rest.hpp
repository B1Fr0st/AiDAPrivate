#pragma once

#include "../../../mcp/mcp_standalone.hpp"

namespace aida {
namespace burp {
namespace offensive {

void register_api_rest_tools(mcp_standalone::server_t& srv);
void register_api_security_tools(mcp_standalone::server_t& srv);

}
}
}
