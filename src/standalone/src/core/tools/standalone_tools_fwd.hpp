

#pragma once

namespace mcp_standalone { class server_t; }

namespace driver_tools       { void register_driver_tools(mcp_standalone::server_t& srv); }
namespace network_tools      { void register_network_tools(mcp_standalone::server_t& srv); }
namespace net_security_tools { void register_net_security_tools(mcp_standalone::server_t& srv); }
namespace emulation_tools    { void register_emulation_tools(mcp_standalone::server_t& srv); }
namespace debugger_tools     { void register_debugger_tools(mcp_standalone::server_t& srv); }
namespace coding_tools       { void register_coding_tools(mcp_standalone::server_t& srv); }
namespace workflow_tools     { void register_workflow_tools(mcp_standalone::server_t& srv); }
namespace scanner_tools      { void register_scanner_tools(mcp_standalone::server_t& srv); }
namespace analysis_tools     { void register_analysis_tools(mcp_standalone::server_t& srv); }
