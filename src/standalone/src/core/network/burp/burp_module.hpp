#pragma once

#include "../../mcp/mcp_standalone.hpp"

namespace aida {
namespace burp {

bool initialize();
void shutdown();

void register_all_tools(mcp_standalone::server_t& srv);

}
}
