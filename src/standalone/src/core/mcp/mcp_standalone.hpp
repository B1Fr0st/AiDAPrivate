#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <functional>
#include <vector>
#include <map>

#include <nlohmann/json.hpp>

namespace mcp_standalone
{
    using json = nlohmann::json;

    static constexpr int JSONRPC_PARSE_ERROR      = -32700;
    static constexpr int JSONRPC_INVALID_REQUEST  = -32600;
    static constexpr int JSONRPC_METHOD_NOT_FOUND = -32601;
    static constexpr int JSONRPC_INVALID_PARAMS   = -32602;
    static constexpr int JSONRPC_INTERNAL_ERROR   = -32603;

    static constexpr const char* PROTOCOL_VERSION = "2024-11-05";
    static constexpr const char* SERVER_NAME      = "AiDA Standalone";
    static constexpr const char* SERVER_VERSION   = "1.0.0";

    struct tool_result_t
    {
        bool        success = true;
        std::string text;
        json        data;

        static tool_result_t ok(const char* t) { return {true, std::string(t), {}}; }
        static tool_result_t ok(const std::string& t) { return {true, t, {}}; }
        static tool_result_t ok(const json& j) { return {true, j.dump(2), j}; }
        static tool_result_t ok(const std::string& t, const json& d) { return {true, t, d}; }
        static tool_result_t error(const std::string& e) { return {false, e, {}}; }
    };

    struct tool_param_t
    {
        std::string name;
        std::string type;
        std::string description;
        bool        required = false;
    };

    struct tool_def_t
    {
        std::string name;
        std::string description;
        std::vector<tool_param_t> params;
        bool read_only = true;
        std::function<tool_result_t(const json& params)> handler;
    };

    class server_t
    {
    public:
        server_t();
        ~server_t();

        bool start(int port);
        void stop();
        bool is_running() const { return _running.load(); }
        int  get_port() const { return _port; }
        void register_tool(tool_def_t tool);
        void write_client_configs() const;
        const std::vector<tool_def_t>& get_tools() const { return _tools; }

    private:
        friend std::string handle_body(server_t*, const std::string&);
        void server_thread_func(int port);
        json handle_initialize(const json& id, const json& params);
        json handle_tools_list(const json& id, const json& params);
        json handle_tools_call(const json& id, const json& params);
        json handle_resources_list(const json& id, const json& params);
        json handle_resources_read(const json& id, const json& params);
        json handle_prompts_list(const json& id, const json& params);
        json handle_prompts_get(const json& id, const json& params);
        json handle_ping(const json& id, const json& params);
        json route_request(const json& request);
        json make_result(const json& id, const json& result);
        json make_error(const json& id, int code, const std::string& msg);
        json tool_schema(const tool_def_t& tool) const;
        std::vector<tool_def_t> _tools;
        std::mutex _tools_mtx;
        std::thread _server_thread;
        std::atomic<bool> _running{false};
        std::atomic<bool> _stop_requested{false};
        void* _active_server = nullptr;
        std::mutex _server_mtx;
        int _port = 0;
    };

    void register_standalone_tools(server_t& server);

}
