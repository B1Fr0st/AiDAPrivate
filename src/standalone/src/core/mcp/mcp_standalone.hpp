#pragma once
#include <string>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <vector>
#include <map>
#include <memory>

#include <nlohmann/json.hpp>

namespace mcp_standalone
{
    using json = nlohmann::json;

    static constexpr int JSONRPC_PARSE_ERROR      = -32700;
    static constexpr int JSONRPC_INVALID_REQUEST  = -32600;
    static constexpr int JSONRPC_METHOD_NOT_FOUND = -32601;
    static constexpr int JSONRPC_INVALID_PARAMS   = -32602;
    static constexpr int JSONRPC_INTERNAL_ERROR   = -32603;

    static constexpr const char* PROTOCOL_VERSION = "2025-06-18";
    static constexpr const char* SERVER_NAME      = "aida-pro-mcp";
    static constexpr const char* SERVER_VERSION   = "1.0.0";

    struct tool_result_t
    {
        bool        success = true;
        std::string text;
        json        data;
        std::string error_code;
        json        error_details;

        static tool_result_t ok(const char* t) { return {true, std::string(t), {}, {}, {}}; }
        static tool_result_t ok(const std::string& t) { return {true, t, {}, {}, {}}; }
        static tool_result_t ok(const json& j) { return {true, j.dump(2), j, {}, {}}; }
        static tool_result_t ok(const std::string& t, const json& d) { return {true, t, d, {}, {}}; }
        static tool_result_t error(const std::string& e) { return {false, e, {}, {}, {}}; }
        static tool_result_t error(const std::string& e, const json& d) { return {false, e, d, {}, {}}; }
        static tool_result_t error(const std::string& e, const std::string& code, const json& d = json::object()) { return {false, e, d, code, d}; }
    };

    struct tool_param_t
    {
        std::string name;
        std::string type;
        std::string description;
        bool        required = false;
    };

    enum class tool_visibility_t : int
    {
        external_visible = 0,
        internal_only    = 1,
        ide_chat_only    = 2
    };

    using cancel_token_ptr_t = std::shared_ptr<std::atomic<bool>>;

    cancel_token_ptr_t make_call_cancel_token(bool cancelled = false);
    void signal_call_cancel_token(const cancel_token_ptr_t& token) noexcept;
    std::atomic<bool>* current_cancel_token() noexcept;
    bool current_call_cancelled() noexcept;
    const char* current_call_diag_id() noexcept;
    const char* current_call_request_id() noexcept;
    const char* current_call_tool_name() noexcept;
    std::uint64_t current_call_deadline_ms() noexcept;

    class scoped_call_cancel_t
    {
    public:
        scoped_call_cancel_t() = default;
        explicit scoped_call_cancel_t(cancel_token_ptr_t token);
        ~scoped_call_cancel_t();
        scoped_call_cancel_t(const scoped_call_cancel_t&) = delete;
        scoped_call_cancel_t& operator=(const scoped_call_cancel_t&) = delete;
        scoped_call_cancel_t(scoped_call_cancel_t&& other) noexcept;
        scoped_call_cancel_t& operator=(scoped_call_cancel_t&& other) noexcept;
        void cancel() noexcept;
        cancel_token_ptr_t token() const noexcept { return _token; }

    private:
        void release() noexcept;
        cancel_token_ptr_t _token;
        std::atomic<bool>* _previous = nullptr;
        bool _active = false;
    };

    class scoped_call_metadata_t
    {
    public:
        scoped_call_metadata_t(const std::string& diag_id, const std::string& tool_name, std::uint64_t deadline_ms);
        scoped_call_metadata_t(const std::string& diag_id, const std::string& request_id, const std::string& tool_name, std::uint64_t deadline_ms);
        ~scoped_call_metadata_t();
        scoped_call_metadata_t(const scoped_call_metadata_t&) = delete;
        scoped_call_metadata_t& operator=(const scoped_call_metadata_t&) = delete;

    private:
        std::string _prev_diag;
        std::string _prev_request;
        std::string _prev_tool;
        std::uint64_t _prev_deadline = 0;
        bool _active = false;
    };

    void set_ide_lifecycle_ready(bool ready) noexcept;
    bool lifecycle_authorized(std::string* reason = nullptr);
    void format_runtime_diagnostic_snapshot(char* out, std::size_t cap) noexcept;
    json active_session_policy_debug_snapshot();

    struct tool_def_t
    {
        std::string name;
        std::string description;
        std::vector<tool_param_t> params;
        bool read_only = true;
        std::function<tool_result_t(const json& params)> handler;
        tool_visibility_t visibility = tool_visibility_t::external_visible;
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
        bool register_tool(tool_def_t tool);
        tool_result_t call_registered_tool(const std::string& name, const json& arguments, bool external_visible_only);
        tool_result_t describe_tools(const json& params);
        void write_client_configs() const;
        const std::vector<tool_def_t>& get_tools() const { return _tools; }

    private:
        friend std::string handle_body(server_t*, const std::string&, const std::function<bool()>&);
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
        json tool_schema(const tool_def_t& tool, bool compact) const;
        std::vector<tool_def_t> _tools;
        std::mutex _tools_mtx;
        std::atomic<bool> _server_done{true};
        std::atomic<bool> _running{false};
        std::atomic<bool> _stop_requested{false};
        void* _active_server = nullptr;
        std::mutex _server_mtx;
        std::atomic<std::uint32_t> _server_worker_tid{0};
        int _port = 0;
    };

    void register_standalone_tools(server_t& server);
    std::string handle_body(server_t* self, const std::string& body, const std::function<bool()>& connection_closed = {});

    struct target_scope_t
    {
        bool        ok = false;
        bool        swapped = false;
        bool        resolved = false;
        size_t      prev_active_idx = static_cast<size_t>(-1);
        size_t      target_idx      = static_cast<size_t>(-1);
        std::string resolved_id;
        std::string err;

        target_scope_t() = default;
        target_scope_t(const target_scope_t&) = delete;
        target_scope_t& operator=(const target_scope_t&) = delete;
        target_scope_t(target_scope_t&&) noexcept;
        target_scope_t& operator=(target_scope_t&&) noexcept;
        ~target_scope_t();
    };

    target_scope_t resolve_target(const json& args, std::string* out_err);

}
