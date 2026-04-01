#pragma once


#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>
#include <cstdint>

#include <nlohmann/json.hpp>

namespace mcp_client
{

using json = nlohmann::json;


enum class transport_type_t
{
    http_sse,
    stdio
};

struct server_config_t
{
    std::string       name;
    transport_type_t  transport      = transport_type_t::http_sse;
    std::string       url;
    std::string       command;
    std::vector<std::string> args;
    std::map<std::string, std::string> env;
    std::string       api_key;
    bool              enabled        = true;
    bool              auto_connect   = true;
};


struct remote_tool_t
{
    std::string server_name;
    std::string name;
    std::string description;
    json        input_schema;
    json        annotations;
};


struct remote_resource_t
{
    std::string server_name;
    std::string uri;
    std::string name;
    std::string description;
    std::string mime_type;
};


struct call_result_t
{
    bool        success = false;
    std::string text;
    json        data;

    static call_result_t ok(const std::string& t)                { return {true,  t, {}}; }
    static call_result_t ok(const std::string& t, const json& d) { return {true,  t, d};  }
    static call_result_t error(const std::string& e)             { return {false, e, {}}; }
};

enum class connection_state_t
{
    disconnected,
    connecting,
    connected,
    reconnecting,
    error
};


class client_t
{
public:
    client_t();
    ~client_t();


    client_t(const client_t&)            = delete;
    client_t& operator=(const client_t&) = delete;
    client_t(client_t&&) noexcept;
    client_t& operator=(client_t&&) noexcept;


    bool connect(const server_config_t& cfg);


    void disconnect();


    bool reconnect();


    std::vector<remote_tool_t> list_tools();


    call_result_t call_tool(const std::string& tool_name, const json& arguments);


    std::vector<remote_resource_t> list_resources();


    std::string read_resource(const std::string& uri);


    bool                 is_connected()  const;
    connection_state_t   state()         const;
    const std::string&   server_name()   const;
    const std::string&   last_error()    const;
    const server_config_t& config()      const;


    const std::vector<remote_tool_t>& cached_tools() const;

private:

    json rpc_request(const std::string& method, const json& params = json::object());
    json send_rpc(const json& request);


    json send_http(const json& request);
    json send_stdio(const json& request);


    bool  launch_stdio_process();
    void  kill_stdio_process();
    std::string read_line_from_stdout();
    void        write_to_stdin(const std::string& data);


    mutable std::mutex          _mtx;
    server_config_t             _cfg;
    connection_state_t          _state = connection_state_t::disconnected;
    std::string                 _server_name_str;
    std::string                 _server_version;
    std::string                 _last_error;
    std::vector<remote_tool_t>  _cached_tools;
    int                         _next_id = 1;


    void*   _child_process  = nullptr;
    void*   _child_stdin_w  = nullptr;
    void*   _child_stdout_r = nullptr;
};


class manager_t
{
public:
    manager_t();
    ~manager_t();


    void add_server(const server_config_t& cfg);


    void remove_server(const std::string& name);


    void connect_all();


    void disconnect_all();


    bool connect_server(const std::string& name);


    void disconnect_server(const std::string& name);


    std::vector<remote_tool_t> get_all_tools();


    call_result_t call_tool(const std::string& qualified_name, const json& arguments);


    size_t tool_count() const;


    std::vector<remote_resource_t> get_all_resources();
    std::string read_resource(const std::string& server_name, const std::string& uri);


    struct server_status_t
    {
        std::string        name;
        connection_state_t state;
        std::string        error;
        size_t             tool_count;
    };

    std::vector<server_status_t> get_status() const;


    void poll();

private:
    struct entry_t
    {
        server_config_t cfg;
        client_t        client;
    };

    mutable std::mutex        _mtx;
    std::vector<entry_t>      _entries;
};

}
