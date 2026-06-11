

#pragma once

namespace mcp_standalone { class server_t; }
namespace tool_repetition { class detector_t; }

namespace driver_tools       { void register_driver_tools(mcp_standalone::server_t& srv); }
namespace network_tools      { void register_network_tools(mcp_standalone::server_t& srv); }
namespace gameproto_tools    { void register_gameproto_tools(mcp_standalone::server_t& srv); }
namespace net_proto_tools    { void register_net_proto_tools(mcp_standalone::server_t& srv); }
namespace net_security_tools { void register_net_security_tools(mcp_standalone::server_t& srv); }
namespace emulation_tools    { void register_emulation_tools(mcp_standalone::server_t& srv); }
namespace debugger_tools     { void register_debugger_tools(mcp_standalone::server_t& srv); }
namespace thread_intel_tools { void register_thread_intel_tools(mcp_standalone::server_t& srv); }
namespace coding_tools       { void register_coding_tools(mcp_standalone::server_t& srv); }
namespace re_tools           { void register_re_tools(mcp_standalone::server_t& srv); }
namespace protected_re_tools { void register_protected_re_tools(mcp_standalone::server_t& srv); }
namespace workflow_tools     {
    void register_workflow_tools(mcp_standalone::server_t& srv);
    void shutdown_services();
    tool_repetition::detector_t& get_repetition_detector();
}
namespace scanner_tools      { void register_scanner_tools(mcp_standalone::server_t& srv); }
namespace analysis_tools     { void register_analysis_tools(mcp_standalone::server_t& srv); }
namespace disasm_tools       { void register_disasm_tools(mcp_standalone::server_t& srv); }
namespace decompile_tools    { void register_decompile_tools(mcp_standalone::server_t& srv); }
namespace session_tools_ext  { void register_tools(mcp_standalone::server_t& srv); }
