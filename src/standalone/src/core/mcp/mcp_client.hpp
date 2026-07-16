#pragma once


#include <string>
#include <vector>
#include <map>
#include <memory>
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

struct oauth_request_control_t;


enum class transport_type_t
{
    http_sse,
    stdio
};

enum class transport_mode_t
{
    auto_detect,
    streamable_http,
    sse_legacy,
    stdio_local
};

enum class oauth_status_t
{
    not_required,
    needs_auth,
    needs_client_registration,
    authenticated,
    authenticating,
    failed
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
    bool              oauth_enabled  = true;
    std::string       oauth_client_id;
    std::string       oauth_client_secret;
    std::string       oauth_scope;
    std::string       oauth_redirect_uri;
};


struct remote_tool_t
{
    std::string server_name;
    std::string name;
    std::string original_name;
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


struct prompt_argument_t
{
    std::string name;
    std::string description;
    bool        required = false;
};


struct remote_prompt_t
{
    std::string                    server_name;
    std::string                    name;
    std::string                    description;
    std::vector<prompt_argument_t> arguments;
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


struct oauth_state_t
{
    std::string server_name;
    std::string authorization_url;
    std::string state_token;
    std::string code_verifier;
    std::string code_challenge;
    std::string client_id;
    std::string client_secret;
    std::string redirect_uri;
    std::string token_endpoint;
    std::string authorization_endpoint;
    std::string registration_endpoint;
    std::string scope;
    int callback_port = 0;
    int64_t deadline_unix = 0;
    std::atomic<bool> done{false};
    std::atomic<bool> cancelled{false};
    std::atomic<bool> terminalizing{false};
    std::atomic<oauth_status_t> terminal_status{oauth_status_t::authenticating};
    std::string error;
    void* flow_binding = nullptr;

    oauth_state_t() = default;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    ~oauth_state_t() = default;
#else
    ~oauth_state_t();
#endif
    oauth_state_t(const oauth_state_t&) = delete;
    oauth_state_t& operator=(const oauth_state_t&) = delete;
};


using auth_completion_callback_t = std::function<void(const std::string& server_name, oauth_status_t final_status, const std::string& error)>;


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


    std::vector<remote_prompt_t> list_prompts();


    std::string get_prompt(const std::string& prompt_name,
                           const std::map<std::string, std::string>& arguments);


    bool                 is_connected()  const;
    connection_state_t   state()         const;
    const std::string&   server_name()   const;
    std::string          last_error()    const;
    const server_config_t& config()      const;
    std::uint32_t        child_process_id() const;


    const std::vector<remote_tool_t>& cached_tools() const;

    oauth_status_t oauth_status() const;

    transport_mode_t active_transport_mode() const;

    bool poll_notifications();

private:

    json rpc_request(const std::string& method, const json& params = json::object());
    bool send_rpc(json& out, const json& request, int http_read_timeout_sec = 30);


    bool send_http(json& out, const json& request, int read_timeout_sec = 30);
    bool send_stdio(json& out, const json& request, int read_timeout_sec);

    bool perform_remote_handshake();
    bool perform_initialize_locked();
    bool ensure_access_token_fresh_locked();
    bool refresh_access_token_locked();
    void process_notification(const json& notif);
    bool detect_oauth_metadata();
    void scrub_sensitive_state_locked() noexcept;

    bool dispatch_inbound_request(const json& request, json& response_out);
    json build_roots_list_result() const;
    void send_inbound_response(const json& response);
    bool post_outbound_http_message(const json& message);


    bool  launch_stdio_process();
    void  kill_stdio_process();
    bool  read_line_from_stdout(std::string& out, std::uint32_t timeout_ms);
    bool  write_to_stdin(const std::string& data);


    mutable std::mutex          _mtx;
    server_config_t             _cfg;
    connection_state_t          _state = connection_state_t::disconnected;
    std::string                 _server_name_str;
    std::string                 _server_version;
    std::string                 _last_error;
    std::vector<remote_tool_t>  _cached_tools;
    int                         _next_id = 1;

    transport_mode_t            _transport_mode = transport_mode_t::auto_detect;
    std::string                 _sse_session_id;
    std::string                 _sse_post_path;
    std::string                 _streamable_session_id;

    oauth_status_t              _oauth_status = oauth_status_t::not_required;
    std::string                 _oauth_token_endpoint;
    mutable std::mutex          _oauth_request_mutex;
    std::shared_ptr<oauth_request_control_t> _oauth_request_control;


    void*   _child_process  = nullptr;
    void*   _child_stdin_w  = nullptr;
    void*   _child_stdout_r = nullptr;
    std::uint32_t _child_process_id = 0;
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


    std::vector<remote_prompt_t> get_all_prompts();
    std::string                  get_prompt(const std::string& server_name,
                                            const std::string& prompt_name,
                                            const std::map<std::string, std::string>& arguments);


    struct server_status_t
    {
        std::string        name;
        connection_state_t state;
        std::string        error;
        size_t             tool_count;
        oauth_status_t     oauth;
    };

    std::vector<server_status_t> get_status() const;


    void poll();


    bool refresh_tools(const std::string& name);


    bool find_config(const std::string& name, server_config_t& out) const;


    json mcp_tool_list_json();

private:
    struct entry_t
    {
        server_config_t cfg;
        client_t        client;
        ~entry_t();
    };

    mutable std::mutex                          _mtx;
    std::vector<std::shared_ptr<entry_t>>       _entries;
    std::vector<std::string>                    _in_flight_connects;
};


bool supports_oauth(const std::string& server_name);
bool has_stored_tokens(const std::string& server_name);
bool start_auth(const std::string& server_name, oauth_state_t& out_state);
oauth_status_t poll_auth(oauth_state_t& state);
bool finish_auth(const std::string& server_name, const std::string& authorization_code);
bool remove_auth(const std::string& server_name);
oauth_status_t auth_status(const std::string& server_name);
bool cancel_auth(oauth_state_t& state);
bool cancel_auth(const std::string& server_name);
bool trigger_auth_flow(const std::string& server_name, auth_completion_callback_t on_complete);

std::string last_error();

#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
namespace c03_oauth_fixture
{

struct http_reply_t
{
    bool transport_ok = true;
    int status = 200;
    std::string body;
    std::map<std::string, std::string> headers;
    std::string error;
};

struct http_request_t
{
    bool oauth_request = false;
    std::string method;
    std::string url;
    std::string body;
    std::map<std::string, std::string> headers;
};

struct credential_t
{
    std::string access;
    std::string refresh;
    int64_t expires_unix = 0;
    json metadata = json::object();
    std::string client_id;
    std::string redirect_uri;
    std::vector<std::string> scopes;
};

struct event_t
{
    std::string server_name;
    oauth_status_t status = oauth_status_t::failed;
    std::string error;
    std::uint64_t generation = 0;
};

enum class fault_point_t
{
    config_lookup,
    http_request,
    browser,
    credential_store,
    event_publish
};

void reset();
void set_time(int64_t unix_seconds);
void advance_time(int64_t seconds);
bool add_server(const server_config_t& config);
void set_browser_result(bool result);
void fail_next(fault_point_t point);
void queue_http_reply(http_reply_t reply);
std::vector<http_request_t> take_http_requests();
size_t run_ready_tasks(size_t maximum);
size_t pending_task_count();
size_t pending_http_reply_count();
size_t active_flow_count();
size_t active_trigger_count();
size_t active_flow_secret_bytes();
bool get_active_state_token(const std::string& server_name, std::string& state_token);
bool deliver_callback(const std::string& server_name,
                      const std::string& state_token,
                      const std::string& code,
                      const std::string& error);
bool get_credential(const std::string& server_name, credential_t& credential);
std::vector<event_t> take_events();
void set_flow_generation(std::uint64_t generation);
void set_trigger_generation(std::uint64_t generation);
void set_auth_epoch(const std::string& server_name, std::uint64_t epoch);
void set_config_generation(const std::string& server_name, std::uint64_t generation);

}
#endif

}
