#pragma once

#include "debugger_lane.hpp"
#include "../registry/tool_types.hpp"

#include <functional>
#include <memory>

namespace mcp_standalone {

class server_t;
class tool_registry_t;

struct c03_compatibility_runtime_config_t {
    std::function<std::unique_ptr<
        aida::standalone::mcp::compat::debugger_adapter_t>(
            const workspace_request_context_t&)> debugger_adapter_factory;
};

void register_c03_compatibility_tools(server_t& server);
void register_c03_compatibility_tools(tool_registry_t& registry);
void register_c03_compatibility_tools(
    tool_registry_t& registry,
    c03_compatibility_runtime_config_t config);
c03_compatibility_runtime_config_t
make_application_c03_compatibility_runtime_config();
tool_validation_hook_t c03_compatibility_validation_hook();

}
