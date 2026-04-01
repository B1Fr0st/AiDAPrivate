// standalone_tools_fwd.hpp — Forward declarations for ported tool registration
// functions.  Called from register_standalone_tools() in mcp_standalone_tools.cpp.

#pragma once

namespace mcp_standalone { class server_t; }

namespace driver_tools       { void register_driver_tools(mcp_standalone::server_t& srv); }
namespace network_tools      { void register_network_tools(mcp_standalone::server_t& srv); }
namespace net_security_tools { void register_net_security_tools(mcp_standalone::server_t& srv); }
namespace emulation_tools    { void register_emulation_tools(mcp_standalone::server_t& srv); }
namespace debugger_tools     { void register_debugger_tools(mcp_standalone::server_t& srv); }
