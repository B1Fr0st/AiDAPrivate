#pragma once

#include "../../mcp/mcp_standalone.hpp"

namespace aida {
namespace burp {
namespace scan_orchestrator {

bool initialize();
void shutdown();
void register_tools(mcp_standalone::server_t& srv);

}

void register_scan_orchestrator_tools(mcp_standalone::server_t& srv);

}
}
