#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#include "mcp_standalone.hpp"
#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "arc/arc.h"
#include "zydis_disasm.hpp"
#include "sandbox.hpp"
#include "../infra/work_queue.hpp"
#include "../session/analysis_session.hpp"
#include "../../helpers/diag_log.hpp"
#include <httplib.h>
#include <sstream>
#include <fstream>
#include <random>
#include <set>
#include <queue>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <memory>

namespace mcp_standalone
{
static std::string json_dump_safe(const json& j, int indent = -1)
{
    try { return j.dump(indent); }
    catch (...) { return "{}"; }
}

static std::string generate_session_id()
{

    unsigned char rnd[16] = {};
    NTSTATUS st = BCryptGenRandom(nullptr, rnd, sizeof(rnd),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {

        auto t = std::chrono::steady_clock::now().time_since_epoch().count();
        for (size_t i = 0; i < sizeof(rnd); ++i)
            rnd[i] = static_cast<unsigned char>((t >> (i * 8)) ^ i);
    }
    char buf[48];
    snprintf(buf, sizeof(buf),
             "sa-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7],
             rnd[8], rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14], rnd[15]);
    return buf;
}

static std::string read_env_var(const char* name)
{
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || !value)
        return {};
    std::string result(value);
    free(value);
    return result;
}

static std::string sanitize_utf8(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size(); )
    {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            result += static_cast<char>(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size()) {
            result += input[i]; result += input[i+1]; i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size()) {
            result += input[i]; result += input[i+1]; result += input[i+2]; i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size()) {
            result += input[i]; result += input[i+1]; result += input[i+2]; result += input[i+3]; i += 4;
        } else {
            result += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return result;
}

static std::string snake_to_title(const std::string& name)
{
    std::string result;
    bool cap = true;
    for (char c : name) {
        if (c == '_') {
            result += ' ';
            cap = true;
        } else {
            result += cap ? static_cast<char>(toupper(c)) : c;
            cap = false;
        }
    }
    return result;
}

static std::string format_sse_event(const std::string& event_type, const std::string& data)
{
    std::string result;
    if (!event_type.empty())
        result += "event: " + event_type + "\n";
    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line))
        result += "data: " + line + "\n";
    result += "\n";
    return result;
}

struct sse_session_t
{
    std::string id;
    std::mutex  mtx;
    std::queue<std::string> events;
    std::atomic<bool> closed{false};

    void push_event(const std::string& event)
    {
        std::lock_guard<std::mutex> lk(mtx);
        events.push(event);
    }

    bool wait_event(std::string& out, int timeout_ms)
    {
        const DWORD start_tick = GetTickCount();
        const DWORD timeout = static_cast<DWORD>(timeout_ms < 0 ? 0 : timeout_ms);
        for (;;)
        {
            {
                std::lock_guard<std::mutex> lk(mtx);
                if (closed.load(std::memory_order_acquire))
                    return false;
                if (!events.empty()) {
                    out = std::move(events.front());
                    events.pop();
                    return true;
                }
            }
            const DWORD elapsed = GetTickCount() - start_tick;
            if (elapsed >= timeout)
                return false;
            const DWORD remaining = timeout - elapsed;
            Sleep(remaining < 50u ? remaining : 50u);
        }
    }

    void close() { closed.store(true, std::memory_order_release); }
};

static bool sse_provider_step_impl(
    sse_session_t* session,
    httplib::DataSink* sink,
    size_t offset,
    std::atomic<bool>* stop_requested)
{
    if (offset == 0) {
        std::string evt = format_sse_event("endpoint",
            "/message?sessionId=" + session->id);
        if (!sink->write(evt.c_str(), evt.size())) { session->close(); return false; }
    }
    std::string event;
    if (session->wait_event(event, 2000)) {
        if (!sink->write(event.c_str(), event.size())) { session->close(); return false; }
    } else if (session->closed.load(std::memory_order_acquire)) {
        return false;
    } else if (stop_requested && stop_requested->load(std::memory_order_acquire)) {
        session->close();
        return false;
    } else {
        const char ka[] = ": keepalive\n\n";
        if (!sink->write(ka, sizeof(ka) - 1u)) { session->close(); return false; }
    }
    return !session->closed.load(std::memory_order_acquire);
}

__declspec(noinline) static DWORD seh_sse_provider_step(
    sse_session_t* session,
    httplib::DataSink* sink,
    size_t offset,
    std::atomic<bool>* stop_requested,
    bool* out_continue)
{
    *out_continue = false;
    __try {
        *out_continue = sse_provider_step_impl(session, sink, offset, stop_requested);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

namespace
{
    std::mutex                                                       g_in_flight_mutex;
    std::map<std::string, std::shared_ptr<std::atomic<bool>>>        g_in_flight_cancels;
    thread_local std::atomic<bool>*                                  tls_current_cancel_token = nullptr;

    std::string cancel_key_for_id(const json& id)
    {
        if (id.is_null())              return std::string{"\1null"};
        if (id.is_string())            return std::string{"s:"} + id.get<std::string>();
        if (id.is_number_integer())    return std::string{"i:"} + std::to_string(id.get<long long>());
        if (id.is_number_unsigned())   return std::string{"u:"} + std::to_string(id.get<unsigned long long>());
        if (id.is_number_float())      return std::string{"f:"} + std::to_string(id.get<double>());
        return std::string{"j:"} + id.dump();
    }

    std::shared_ptr<std::atomic<bool>> register_in_flight_call(const json& id)
    {
        auto token = std::make_shared<std::atomic<bool>>(false);
        std::lock_guard<std::mutex> lk(g_in_flight_mutex);
        g_in_flight_cancels[cancel_key_for_id(id)] = token;
        return token;
    }

    void unregister_in_flight_call(const json& id)
    {
        std::lock_guard<std::mutex> lk(g_in_flight_mutex);
        g_in_flight_cancels.erase(cancel_key_for_id(id));
    }

    bool signal_in_flight_cancel(const json& id)
    {
        std::shared_ptr<std::atomic<bool>> token;
        {
            std::lock_guard<std::mutex> lk(g_in_flight_mutex);
            auto it = g_in_flight_cancels.find(cancel_key_for_id(id));
            if (it == g_in_flight_cancels.end()) return false;
            token = it->second;
        }
        if (token) token->store(true, std::memory_order_release);
        return true;
    }

    struct cancel_scope_t
    {
        json                              id;
        std::shared_ptr<std::atomic<bool>> token;
        std::atomic<bool>*                previous = nullptr;

        cancel_scope_t(const json& request_id)
            : id(request_id)
        {
            token = register_in_flight_call(id);
            previous = tls_current_cancel_token;
            tls_current_cancel_token = token.get();
        }

        cancel_scope_t(const cancel_scope_t&) = delete;
        cancel_scope_t& operator=(const cancel_scope_t&) = delete;

        ~cancel_scope_t()
        {
            tls_current_cancel_token = previous;
            unregister_in_flight_call(id);
        }
    };
}

std::atomic<bool>* current_cancel_token() noexcept
{
    return tls_current_cancel_token;
}

bool current_call_cancelled() noexcept
{
    std::atomic<bool>* tok = tls_current_cancel_token;
    return tok && tok->load(std::memory_order_acquire);
}

server_t::server_t()  = default;
server_t::~server_t() { stop(); }

bool server_t::register_tool(tool_def_t tool)
{
    bool already_has_binary_id = false;
    for (const auto& p : tool.params) {
        if (p.name == "binary_id") { already_has_binary_id = true; break; }
    }
    bool is_session_tool = tool.name.rfind("sessions_", 0) == 0;
    if (!already_has_binary_id && !is_session_tool) {
        tool.params.push_back(tool_param_t{
            "binary_id",
            "string",
            "Optional session id to target (returned by sessions_list). When omitted the active session is used.",
            false
        });
    }
    std::lock_guard<std::mutex> lk(_tools_mtx);
    auto dup = std::find_if(_tools.begin(), _tools.end(), [&](const tool_def_t& existing) {
        return existing.name == tool.name;
    });
    if (dup != _tools.end()) {
        if (tool.name == "decompile_function" &&
            dup->visibility == tool_visibility_t::external_visible &&
            tool.visibility == tool_visibility_t::external_visible) {
            diag::log_tagged_fmt("mcp_srv",
                "register_tool duplicate replaced name='%s' visibility=%d",
                tool.name.c_str(), static_cast<int>(tool.visibility));
            *dup = std::move(tool);
            return true;
        }
        diag::log_tagged_fmt("mcp_srv",
            "register_tool duplicate skipped name='%s' existing_visibility=%d new_visibility=%d",
            tool.name.c_str(), static_cast<int>(dup->visibility), static_cast<int>(tool.visibility));
        return false;
    }
    _tools.push_back(std::move(tool));
    return true;
}

json server_t::make_result(const json& id, const json& result)
{
    json r;
    r["jsonrpc"] = "2.0";
    r["id"]      = id;
    r["result"]  = result;
    return r;
}

json server_t::make_error(const json& id, int code, const std::string& msg)
{
    json r;
    r["jsonrpc"]          = "2.0";
    r["id"]               = id;
    r["error"]["code"]    = code;
    r["error"]["message"] = msg;
    return r;
}

json server_t::tool_schema(const tool_def_t& tool) const
{
    json input_schema;
    input_schema["type"] = "object";
    json properties = json::object();
    json required_arr = json::array();

    for (const auto& p : tool.params) {
        json desc;
        desc["type"]        = p.type;
        desc["description"] = p.description;
        properties[p.name] = desc;
        if (p.required) required_arr.push_back(p.name);
    }

    input_schema["properties"] = properties;
    if (!required_arr.empty()) input_schema["required"] = required_arr;

    json annotations;
    annotations["title"]           = snake_to_title(tool.name);
    annotations["readOnlyHint"]    = tool.read_only;
    annotations["destructiveHint"] = (!tool.read_only);
    annotations["idempotentHint"]  = tool.read_only;
    annotations["openWorldHint"]   = (tool.name == "sandbox_execute");

    json t;
    t["name"]        = tool.name;
    t["description"] = tool.description;
    t["inputSchema"] = input_schema;
    t["annotations"] = annotations;
    return t;
}

json server_t::handle_initialize(const json& id, const json&)
{
    diag::log_tagged_fmt("mcp_srv", "handle_initialize entry");
    json capabilities;
    capabilities["tools"]     = {{"listChanged", true}};
    capabilities["resources"] = {{"listChanged", true}};
    capabilities["prompts"]   = {{"listChanged", true}};
    capabilities["logging"]   = json::object();

    json server_info;
    server_info["name"]    = SERVER_NAME;
    server_info["version"] = SERVER_VERSION;

    static const char* instructions =
        "You are connected to AiDA Standalone - a reverse-engineering assistant "
        "that operates through a kernel-backed live inspection bridge, "
        "Zydis for disassembly, and Windows Sandbox for safe sample execution.\n\n"
        "## Capabilities\n"
        "- Read live process memory from an attached process\n"
        "- Disassemble x64 code at any address or from PE files\n"
        "- Attach to / detach from running processes\n"
        "- Execute untrusted binaries in Windows Sandbox\n"
        "- Convert numbers between bases (hex, decimal, binary, ASCII)\n\n"
        "## Tool usage guidelines\n"
        "- Always call `driver_status` first to check backend state\n"
        "- Call `driver_load` when kernel backend is not active and deep runtime access is required\n"
        "- Call `driver_attach` with a PID or process name before memory operations\n"
        "- Use `disassemble_address` for live memory; `disassemble_file` for PE files\n"
        "- Use `sandbox_execute` for running untrusted binaries safely\n"
        "- For number conversions, ALWAYS use `convert_number` - never convert manually\n";

    json result;
    result["protocolVersion"] = PROTOCOL_VERSION;
    result["capabilities"]    = capabilities;
    result["serverInfo"]      = server_info;
    result["instructions"]    = instructions;
    return make_result(id, result);
}

json server_t::handle_ping(const json& id, const json&)
{
    return make_result(id, json::object());
}

json server_t::handle_tools_list(const json& id, const json&)
{
    json tools_arr = json::array();
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        for (const auto& t : _tools) {
            if (t.visibility != tool_visibility_t::external_visible) continue;
            tools_arr.push_back(tool_schema(t));
        }
    }
    json result;
    result["tools"] = tools_arr;
    return make_result(id, result);
}

json server_t::handle_tools_call(const json& id, const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    const std::string early_name = params["name"].get<std::string>();
    diag::log_tagged_fmt("mcp_srv", "handle_tools_call tool='%s'", early_name.c_str());

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_mcp_tool_exec);
        if (!standalone_license::verify_tool_runtime(
                standalone_license::gate_mcp_tool_exec, gt, early_name)) {
            return make_error(id, -32000,
                standalone_license::decode_status_string(
                    standalone_license::str_session_revoked));
        }
    }

    std::string tool_name = early_name;
    json arguments = params.contains("arguments") && params["arguments"].is_object()
                   ? params["arguments"] : json::object();

    const tool_def_t* found = nullptr;
    std::function<tool_result_t(const json&)> handler_copy;
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        for (const auto& t : _tools) {
            if (t.name == tool_name) {
                if (t.visibility != tool_visibility_t::external_visible) {
                    return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
                }
                found = &t;
                handler_copy = t.handler;
                break;
            }
        }
    }

    if (!found)
    {
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call unknown_tool='%s'", tool_name.c_str());
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);
    }

    diag::log_tagged_fmt("mcp_srv", "handle_tools_call dispatching tool='%s'", tool_name.c_str());
    cancel_scope_t scope(id);

    tool_result_t tr;
    try {
        tr = handler_copy(arguments);
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call exception tool='%s' what='%s'",
            tool_name.c_str(), e.what());
        tr = tool_result_t::error(std::string("Tool threw exception: ") + e.what());
    } catch (...) {
        diag::log_tagged_fmt("mcp_srv", "handle_tools_call unknown_exception tool='%s'", tool_name.c_str());
        tr = tool_result_t::error("Tool threw unknown exception");
    }
    diag::log_tagged_fmt("mcp_srv", "handle_tools_call result tool='%s' success=%d",
        tool_name.c_str(), (int)tr.success);

    if (scope.token && scope.token->load(std::memory_order_acquire)) {
        json cancel_result;
        cancel_result["content"] = json::array({
            json{{"type", "text"}, {"text", "Tool call cancelled by client request."}}
        });
        cancel_result["isError"] = true;
        return make_result(id, cancel_result);
    }

    json content = json::array();
    if (!tr.text.empty()) {
        content.push_back({{"type", "text"}, {"text", sanitize_utf8(tr.text)}});
    }
    if (!tr.data.is_null() && !tr.data.empty()) {
        content.push_back({{"type", "text"}, {"text", sanitize_utf8(json_dump_safe(tr.data, 2))}});
    }
    if (content.empty()) {
        content.push_back({{"type", "text"}, {"text", tr.success
            ? "Tool executed successfully (no output)."
            : "Tool execution failed (no details)."}});
    }

    json result;
    result["content"] = content;
    if (!tr.success) result["isError"] = true;
    return make_result(id, result);
}

json server_t::handle_resources_list(const json& id, const json&)
{
    json resources = json::array();

    resources.push_back({
        {"uri",         "standalone://driver-status"},
        {"name",        "Driver Status"},
        {"description", "Current driver and process attachment state"},
        {"mimeType",    "application/json"}
    });

    resources.push_back({
        {"uri",         "standalone://loaded-file"},
        {"name",        "Loaded File Info"},
        {"description", "Information about the currently loaded PE file"},
        {"mimeType",    "application/json"}
    });

    json result;
    result["resources"] = resources;
    return make_result(id, result);
}

json server_t::handle_resources_read(const json& id, const json& params)
{
    if (!params.contains("uri") || !params["uri"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'uri'");

    std::string uri = params["uri"].get<std::string>();
    json text_content;

    if (uri == "standalone://driver-status") {
        json status;
        status["ready"]       = driver_bridge::is_loaded();
        status["attached_pid"]= driver_bridge::attached_pid();
        status["status"]      = driver_bridge::status();
        text_content = status;
    }
    else if (uri == "standalone://loaded-file") {
        text_content = json{{"info", "Use disassemble_file tool to load and inspect PE files."}};
    }
    else {
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown resource URI: " + uri);
    }

    json contents = json::array();
    contents.push_back({
        {"uri",      uri},
        {"mimeType", "application/json"},
        {"text",     json_dump_safe(text_content, 2)}
    });

    json result;
    result["contents"] = contents;
    return make_result(id, result);
}

json server_t::handle_prompts_list(const json& id, const json&)
{
    json prompts = json::array();

    prompts.push_back({
        {"name",        "analyze_memory"},
        {"description", "Read and analyze memory at an address in the attached process"},
        {"arguments",   json::array({
            {{"name", "address"}, {"description", "Hex address to analyze"}, {"required", true}},
            {{"name", "size"},    {"description", "Number of bytes to read (default 256)"}, {"required", false}}
        })}
    });

    prompts.push_back({
        {"name",        "disassemble_region"},
        {"description", "Disassemble code at an address in the attached process"},
        {"arguments",   json::array({
            {{"name", "address"}, {"description", "Hex address to disassemble"}, {"required", true}},
            {{"name", "count"},   {"description", "Max instructions (default 50)"}, {"required", false}}
        })}
    });

    prompts.push_back({
        {"name",        "sandbox_analysis"},
        {"description", "Run a binary in Windows Sandbox and analyze its output"},
        {"arguments",   json::array({
            {{"name", "path"}, {"description", "Path to the executable to analyze"}, {"required", true}}
        })}
    });

    json result;
    result["prompts"] = prompts;
    return make_result(id, result);
}

json server_t::handle_prompts_get(const json& id, const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string name = params["name"].get<std::string>();
    json arguments = params.value("arguments", json::object());

    json messages = json::array();

    if (name == "analyze_memory") {
        std::string addr = arguments.value("address", "");
        if (addr.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        std::string prompt =
            "Read and analyze the memory at address " + addr + " in the attached process.\n"
            "Use the read_memory tool to fetch the bytes, then:\n"
            "1. Show a hex dump of the data\n"
            "2. Identify any strings or recognizable patterns\n"
            "3. Disassemble if the region appears to contain code\n"
            "4. Note any pointers or interesting values\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else if (name == "disassemble_region") {
        std::string addr = arguments.value("address", "");
        if (addr.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        std::string prompt =
            "Disassemble the code at address " + addr + " in the attached process.\n"
            "Use the disassemble_address tool, then:\n"
            "1. Identify the function's purpose\n"
            "2. Analyze control flow (branches, loops, calls)\n"
            "3. Note any system calls, API calls, or string references\n"
            "4. Look for security-relevant patterns\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else if (name == "sandbox_analysis") {
        std::string path = arguments.value("path", "");
        if (path.empty())
            return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'path'");

        std::string prompt =
            "Execute the binary at '" + path + "' in Windows Sandbox.\n"
            "Use the sandbox_execute tool, then:\n"
            "1. Examine the stdout/stderr output\n"
            "2. Check if the process timed out or was killed\n"
            "3. Note the peak memory usage\n"
            "4. Investigate any suspicious behavior indicators\n";

        messages.push_back({
            {"role", "user"},
            {"content", {{"type", "text"}, {"text", prompt}}}
        });
    }
    else {
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown prompt: " + name);
    }

    json result;
    result["description"] = name;
    result["messages"]    = messages;
    return make_result(id, result);
}

json server_t::route_request(const json& msg)
{
    if (!msg.is_object())
        return make_error(nullptr, JSONRPC_INVALID_REQUEST, "Request must be a JSON object");

    std::string method = msg.value("method", "");
    diag::log_tagged_fmt("mcp_srv", "route_request method='%s'", method.c_str());
    if (method.empty())
        return make_error(msg.value("id", json(nullptr)), JSONRPC_INVALID_REQUEST, "Missing 'method' field");

    json id     = msg.contains("id") ? msg["id"] : json(nullptr);
    json params = msg.value("params", json::object());
    bool is_notification = !msg.contains("id");

    if (method == "initialize")               return handle_initialize(id, params);
    if (method == "notifications/initialized") return json();
    if (method == "ping")                     return handle_ping(id, params);
    if (method == "tools/list")               return handle_tools_list(id, params);
    if (method == "tools/call")               return handle_tools_call(id, params);
    if (method == "resources/list")           return handle_resources_list(id, params);
    if (method == "resources/read")           return handle_resources_read(id, params);
    if (method == "prompts/list")             return handle_prompts_list(id, params);
    if (method == "prompts/get")              return handle_prompts_get(id, params);
    if (method == "notifications/cancelled") {
        if (params.is_object() && params.contains("requestId"))
            signal_in_flight_cancel(params["requestId"]);
        return json();
    }
    if (method == "logging/setLevel")
        return json();
    if (is_notification)                      return json();

    return make_error(id, JSONRPC_METHOD_NOT_FOUND, "Unknown method: " + method);
}

std::string handle_body(server_t* self, const std::string& body)
{
    json parsed;
    try { parsed = json::parse(body); }
    catch (const json::parse_error& e) {
        return json_dump_safe(self->make_error(nullptr, JSONRPC_PARSE_ERROR,
            std::string("JSON parse error: ") + e.what()));
    }

    if (parsed.is_array()) {
        if (parsed.empty())
            return json_dump_safe(self->make_error(nullptr, JSONRPC_INVALID_REQUEST, "Empty batch"));
        json responses = json::array();
        for (const auto& item : parsed) {
            json response = self->route_request(item);
            if (!response.is_null()) responses.push_back(response);
        }
        if (responses.empty()) return "";
        return json_dump_safe(responses);
    }

    json response = self->route_request(parsed);
    if (response.is_null()) return "";
    return json_dump_safe(response);
}

bool server_t::start(int port)
{
    diag::log_tagged_fmt("mcp_srv", "start entry port=%d", port);
    if (_running.load())
    {
        diag::log_tagged_fmt("mcp_srv", "start already running port=%d", port);
        return true;
    }

    _stop_requested = false;
    _port = 0;

    _server_done.store(false, std::memory_order_release);
    if (!work_queue::post([this, port]() {
            diag::log_tagged_fmt("mcp_srv", "server_thread starting port=%d", port);
            server_thread_func(port);
            diag::log_tagged_fmt("mcp_srv", "server_thread exited port=%d", port);
            _server_done.store(true, std::memory_order_release);
        }))
    {
        diag::log_tagged_fmt("mcp_srv", "start work_queue post fail");
        _server_done.store(true, std::memory_order_release);
        return false;
    }


    for (int i = 0; i < 20 && !_running.load() && !_stop_requested.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));

    diag::log_tagged_fmt("mcp_srv", "start result running=%d port=%d",
        (int)_running.load(), _port);
    return _running.load();
}

void server_t::stop()
{
    diag::log_tagged_fmt("mcp_srv", "stop entry running=%d", (int)_running.load());
    if (!_running.load() && _server_done.load(std::memory_order_acquire))
    {
        diag::log_tagged_fmt("mcp_srv", "stop already stopped");
        return;
    }
    _stop_requested = true;
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        if (_active_server)
            static_cast<httplib::Server*>(_active_server)->stop();
    }
    while (!_server_done.load(std::memory_order_acquire))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    diag::log_tagged_fmt("mcp_srv", "stop done");
}

void server_t::server_thread_func(int port)
{
    diag::log_tagged_fmt("mcp_srv", "server_thread_func entry port=%d", port);
    httplib::Server svr;
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = &svr;
    }

    std::string session_id = generate_session_id();
    diag::log_tagged_fmt("mcp_srv", "server_thread_func session_id='%s'", session_id.c_str());

    svr.set_default_headers({
        {"Access-Control-Allow-Origin",  "*"},
        {"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Accept"},
        {"Access-Control-Expose-Headers", "Mcp-Session-Id"}
    });

    svr.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.status = 204;
    });

    svr.Post("/mcp", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        diag::log_tagged_fmt("mcp_srv", "POST /mcp body_len=%zu", req.body.size());
        std::string response_body = handle_body(this, req.body);
        res.set_header("Mcp-Session-Id", session_id);
        if (response_body.empty())
            res.status = 202;
        else
            res.set_content(response_body, "application/json");
    });

    svr.Get("/mcp", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);
        std::string accept = req.get_header_value("Accept");
        bool wants_sse = accept.find("text/event-stream") != std::string::npos;

        if (wants_sse) {
            res.set_header("Cache-Control", "no-cache");
            res.set_chunked_content_provider(
                "text/event-stream",
                [this](size_t offset, httplib::DataSink& sink) -> bool {
                    if (offset == 0) {
                        const char connected[] = ": connected\n\n";
                        if (!sink.write(connected, sizeof(connected) - 1u)) return false;
                    }
                    const char ka[] = ": keepalive\n\n";
                    for (int i = 0; i < 6; ++i) {
                        for (int slice = 0; slice < 50; ++slice) {
                            if (_stop_requested.load(std::memory_order_acquire)) return false;
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                        if (_stop_requested.load(std::memory_order_acquire)) return false;
                        if (!sink.write(ka, sizeof(ka) - 1u)) return false;
                    }
                    return true;
                }, nullptr);
        } else {
            res.set_content("event: endpoint\ndata: /mcp\n\n", "text/event-stream");
        }
    });

    svr.Delete("/mcp", [&session_id](const httplib::Request&, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.Get("/health", [this](const httplib::Request&, httplib::Response& res) {
        json health;
        health["status"]      = "ok";
        health["server"]      = SERVER_NAME;
        health["version"]     = SERVER_VERSION;
        size_t tool_count = 0;
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools)
              if (t.visibility == tool_visibility_t::external_visible) ++tool_count; }
        health["tools_count"] = tool_count;
        health["driver"]      = driver_bridge::is_loaded();
        health["attached"]    = driver_bridge::attached_pid();
        res.set_content(json_dump_safe(health), "application/json");
    });

    svr.Get("/api/tools", [this](const httplib::Request&, httplib::Response& res) {
        json tools_arr = json::array();
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools) {
              if (t.visibility != tool_visibility_t::external_visible) continue;
              tools_arr.push_back(tool_schema(t));
          } }
        res.set_content(json_dump_safe(tools_arr, 2), "application/json");
    });

    svr.Post("/api/tools/call", [this](const httplib::Request& req, httplib::Response& res) {
        diag::log_tagged_fmt("mcp_srv", "POST /api/tools/call body_len=%zu", req.body.size());
        json body;
        try { body = json::parse(req.body); }
        catch (const json::parse_error& e) {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", e.what()}}), "application/json");
            return;
        }

        std::string tool_name = body.value("name", "");
        json arguments = body.value("arguments", json::object());

        if (tool_name.empty()) {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing 'name' field"}}), "application/json");
            return;
        }

        const tool_def_t* found = nullptr;
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools) {
              if (t.name == tool_name) {
                  if (t.visibility != tool_visibility_t::external_visible) {
                      res.status = 404;
                      res.set_content(json_dump_safe({{"error", "Unknown tool: " + tool_name}}), "application/json");
                      return;
                  }
                  found = &t;
                  break;
              }
          } }

        if (!found) {
            res.status = 404;
            res.set_content(json_dump_safe({{"error", "Unknown tool: " + tool_name}}), "application/json");
            return;
        }

        tool_result_t tr;
        try { tr = found->handler(arguments); }
        catch (const std::exception& e) { tr = tool_result_t::error(e.what()); }

        json resp;
        resp["success"] = tr.success;
        resp["output"]  = sanitize_utf8(tr.text);
        if (!tr.data.is_null() && !tr.data.empty()) resp["data"] = tr.data;
        res.set_content(json_dump_safe(resp, 2), "application/json");
    });

    std::map<std::string, std::shared_ptr<sse_session_t>> sse_sessions;
    std::mutex sse_mtx;

    svr.Get("/sse", [this, &sse_sessions, &sse_mtx](const httplib::Request&, httplib::Response& res) {
        auto session = std::make_shared<sse_session_t>();
        session->id = generate_session_id();
        { std::lock_guard<std::mutex> lk(sse_mtx); sse_sessions[session->id] = session; }

        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");

        std::atomic<bool>* stop_ptr = &_stop_requested;
        res.set_chunked_content_provider(
            "text/event-stream",
            [session, stop_ptr](size_t offset, httplib::DataSink& sink) -> bool {
                bool cont = false;
                DWORD seh = seh_sse_provider_step(session.get(), &sink, offset, stop_ptr, &cont);
                if (seh != 0) {
                    session->close();
                    return false;
                }
                return cont;
            },
            [session, &sse_sessions, &sse_mtx](bool) {
                session->close();
                std::lock_guard<std::mutex> lk(sse_mtx);
                sse_sessions.erase(session->id);
            });
    });

    svr.Post("/message", [this, &sse_sessions, &sse_mtx](const httplib::Request& req, httplib::Response& res) {
        std::string sid = req.get_param_value("sessionId");
        if (sid.empty()) {
            res.status = 400;
            res.set_content(json_dump_safe(make_error(nullptr,
                JSONRPC_INVALID_REQUEST, "Missing sessionId query parameter")), "application/json");
            return;
        }

        std::shared_ptr<sse_session_t> session;
        { std::lock_guard<std::mutex> lk(sse_mtx);
          auto it = sse_sessions.find(sid);
          if (it == sse_sessions.end()) {
              res.status = 404;
              res.set_content(json_dump_safe(make_error(nullptr,
                  JSONRPC_INVALID_REQUEST, "Unknown or expired session: " + sid)), "application/json");
              return;
          }
          session = it->second;
        }

        std::string response_body = handle_body(this, req.body);
        if (!response_body.empty()) {
            std::string event = format_sse_event("message", response_body);
            session->push_event(event);
        }
        res.status = 202;
        res.set_content("Accepted", "text/plain");
    });

    svr.Post("/sse", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        std::string response_body = handle_body(this, req.body);
        res.set_header("Mcp-Session-Id", session_id);
        if (response_body.empty()) res.status = 202;
        else res.set_content(response_body, "application/json");
    });

    svr.Delete("/sse", [&session_id](const httplib::Request&, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.set_socket_options([](socket_t sock) {
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&yes), sizeof(yes));
    });

    int bound_port = 0;
    if (port > 0 && svr.bind_to_port("127.0.0.1", port))
        bound_port = port;
    if (bound_port <= 0)
        bound_port = svr.bind_to_any_port("127.0.0.1");

    if (bound_port <= 0) {
        diag::log_tagged_fmt("mcp_srv", "server_thread_func bind fail port=%d", port);
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = nullptr;
        _stop_requested = true;
        return;
    }

    _port = bound_port;
    _running = true;
    diag::log_tagged_fmt("mcp_srv", "server_thread_func listening bound_port=%d", bound_port);

    svr.listen_after_bind();

    diag::log_tagged_fmt("mcp_srv", "server_thread_func listen_after_bind returned port=%d", bound_port);
    _running = false;
    { std::lock_guard<std::mutex> lk(_server_mtx); _active_server = nullptr; }
}

static std::string get_home_dir()
{
    char buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, buf)))
        return buf;
    return read_env_var("USERPROFILE");
}

static std::string get_appdata_dir()
{
    char buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, buf)))
        return buf;
    return read_env_var("APPDATA");
}

static std::string expand_path(const char* tmpl)
{
    if (!tmpl || !*tmpl) return "";
    std::string path(tmpl);

    if (path.size() >= 1 && path[0] == '~') {
        std::string home = get_home_dir();
        if (home.empty()) return "";
        if (path.size() >= 2 && (path[1] == '/' || path[1] == '\\'))
            path = home + path.substr(1);
        else if (path.size() == 1)
            path = home;
    }

    size_t pos = path.find("%APPDATA%");
    if (pos != std::string::npos) {
        std::string appdata = get_appdata_dir();
        if (appdata.empty()) return "";
        path.replace(pos, 9, appdata);
    }

    for (auto& c : path) if (c == '/') c = '\\';
    return path;
}

static bool ensure_dir(const std::string& dir)
{
    if (dir.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return std::filesystem::is_directory(dir, ec);
}

static bool ensure_parent_dir(const std::string& path)
{
    auto p = std::filesystem::path(path).parent_path();
    if (p.empty()) return true;
    return ensure_dir(p.string());
}

static bool read_file_to_string(const std::string& path, std::string& out)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

static bool write_string_to_file(const std::string& path, const std::string& content)
{
    if (!ensure_parent_dir(path)) return false;
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs << content;
    return ofs.good();
}

static std::string strip_jsonc(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    bool in_string = false, in_line = false, in_block = false;

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (in_line)  { if (c == '\n') { in_line = false; result += '\n'; } continue; }
        if (in_block) { if (c == '*' && i+1 < input.size() && input[i+1] == '/') { in_block = false; ++i; } continue; }
        if (in_string) { result += c; if (c == '\\' && i+1 < input.size()) result += input[++i]; else if (c == '"') in_string = false; continue; }
        if (c == '"') { in_string = true; result += c; continue; }
        if (c == '/' && i+1 < input.size()) {
            if (input[i+1] == '/') { in_line = true; ++i; continue; }
            if (input[i+1] == '*') { in_block = true; ++i; continue; }
        }
        if (c == ',') {
            size_t j = i+1;
            while (j < input.size() && (input[j]==' '||input[j]=='\t'||input[j]=='\n'||input[j]=='\r')) ++j;
            if (j < input.size() && (input[j] == '}' || input[j] == ']')) continue;
        }
        result += c;
    }
    return result;
}

static bool parse_json_file(const std::string& path, json& out, bool allow_jsonc)
{
    std::string raw;
    if (!read_file_to_string(path, raw)) return false;
    try { out = json::parse(raw); return true; }
    catch (const json::parse_error&) {
        if (!allow_jsonc) return false;
    }
    try { out = json::parse(strip_jsonc(raw)); return true; }
    catch (const json::parse_error&) { return false; }
}

static bool write_json_file(const std::string& path, const json& data)
{
    return write_string_to_file(path, json_dump_safe(data, 2) + "\n");
}

static const char* MCP_NAME = "aida-standalone-mcp";

struct client_cfg_t {
    const char* name;
    enum { URL, SERVERURL, VSCODE, VSCODE_JSON, CLINE, ZED, CODEX, CLAUDE_CODE, CLAUDE_BRIDGE } format;
    const char* win_path;
};

static const client_cfg_t g_clients[] = {
    { "Amazon Q",        client_cfg_t::URL,          "~/.aws/amazonq/mcp_config.json" },
    { "Claude",          client_cfg_t::CLAUDE_BRIDGE, "%APPDATA%/Claude/claude_desktop_config.json" },
    { "Copilot CLI",     client_cfg_t::URL,          "~/.copilot/mcp-config.json" },
    { "Cursor",          client_cfg_t::URL,          "~/.cursor/mcp.json" },
    { "Gemini CLI",      client_cfg_t::URL,          "~/.gemini/settings.json" },
    { "Kiro",            client_cfg_t::URL,          "~/.kiro/mcp_config.json" },
    { "LM Studio",       client_cfg_t::URL,          "~/.lmstudio/mcp.json" },
    { "Windsurf",        client_cfg_t::SERVERURL,    "~/.codeium/windsurf/mcp_config.json" },
    { "VS Code",         client_cfg_t::VSCODE,       "%APPDATA%/Code/User/settings.json" },
    { "VS Code Insiders",client_cfg_t::VSCODE,       "%APPDATA%/Code - Insiders/User/settings.json" },
    { "VS Code (mcp.json)", client_cfg_t::VSCODE_JSON, "%APPDATA%/Code/User/mcp.json" },
    { "Cline",           client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" },
    { "Roo Code",        client_cfg_t::CLINE,        "%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json" },
    { "Zed",             client_cfg_t::ZED,          "%APPDATA%/Zed/settings.json" },
    { "Codex",           client_cfg_t::CODEX,        "~/.codex/config.toml" },
    { "Claude Code",     client_cfg_t::CLAUDE_CODE,  "~/.claude.json" },
};

static bool write_mcpservers(const std::string& path, const std::string& url, const char* key)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    config["mcpServers"][MCP_NAME] = json::object();
    config["mcpServers"][MCP_NAME]["type"] = "sse";
    config["mcpServers"][MCP_NAME][key] = url;
    return write_json_file(path, config);
}

static bool write_vscode(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcp") || !config["mcp"].is_object()) config["mcp"] = json::object();
    if (!config["mcp"].contains("servers") || !config["mcp"]["servers"].is_object())
        config["mcp"]["servers"] = json::object();
    config["mcp"]["servers"][MCP_NAME] = {{"type", "sse"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_vscode_json(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("servers") || !config["servers"].is_object())
        config["servers"] = json::object();
    config["servers"][MCP_NAME] = {{"type", "sse"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_cline(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    json entry;
    entry["url"] = url;
    entry["disabled"] = false;
    entry["autoApprove"] = json::array();
    config["mcpServers"][MCP_NAME] = entry;
    return write_json_file(path, config);
}

static bool write_zed(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, true);
    if (!config.is_object()) config = json::object();
    if (!config.contains("context_servers") || !config["context_servers"].is_object())
        config["context_servers"] = json::object();
    config["context_servers"][MCP_NAME] = {{"settings", {{"url", url}}}};
    return write_json_file(path, config);
}

static bool write_codex(const std::string& path, const std::string& url)
{
    std::string content;
    if (std::filesystem::exists(path)) read_file_to_string(path, content);
    std::string marker = "[mcp_servers.aida-standalone-mcp]";
    size_t pos = content.find(marker);
    std::string section = marker + "\ntype = \"sse\"\nurl = \"" + url + "\"\n";
    if (pos != std::string::npos) {
        size_t end = content.find("\n[", pos + marker.size());
        if (end == std::string::npos) end = content.size(); else end += 1;
        content.replace(pos, end - pos, section);
    } else {
        if (!content.empty() && content.back() != '\n') content += "\n";
        content += "\n" + section;
    }
    return write_string_to_file(path, content);
}

static bool write_claude_code(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    config["mcpServers"][MCP_NAME] = {{"type", "sse"}, {"url", url}};
    return write_json_file(path, config);
}

static bool write_claude_bridge(const std::string& path, const std::string& url)
{
    json config;
    if (std::filesystem::exists(path)) parse_json_file(path, config, false);
    if (!config.is_object()) config = json::object();
    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();
    config["mcpServers"][MCP_NAME] = {{"command", "npx"}, {"args", json::array({"-y", "mcp-bridge", url})}};
    return write_json_file(path, config);
}

void server_t::write_client_configs() const
{
    if (!_running.load()) return;

    std::string port_str = std::to_string(_port);
    std::string http_url = "http://127.0.0.1:" + port_str + "/mcp";
    std::string sse_url  = "http://127.0.0.1:" + port_str + "/sse";

    std::set<std::string> written;
    int ok = 0, skip = 0, fail = 0;

    for (const auto& def : g_clients) {
        std::string path = expand_path(def.win_path);
        if (path.empty()) { ++skip; continue; }
        if (written.count(path)) continue;

        if (path.find("globalStorage") != std::string::npos) {
            auto parent = std::filesystem::path(path).parent_path();
            std::error_code ec;
            if (!std::filesystem::is_directory(parent, ec)) { ++skip; continue; }
        }

        bool success = false;
        switch (def.format) {
        case client_cfg_t::URL:          success = write_mcpservers(path, sse_url, "url"); break;
        case client_cfg_t::SERVERURL:    success = write_mcpservers(path, sse_url, "serverUrl"); break;
        case client_cfg_t::VSCODE:       success = write_vscode(path, sse_url); break;
        case client_cfg_t::VSCODE_JSON:  success = write_vscode_json(path, sse_url); break;
        case client_cfg_t::CLINE:        success = write_cline(path, sse_url); break;
        case client_cfg_t::ZED:          success = write_zed(path, http_url); break;
        case client_cfg_t::CODEX:        success = write_codex(path, sse_url); break;
        case client_cfg_t::CLAUDE_CODE:  success = write_claude_code(path, sse_url); break;
        case client_cfg_t::CLAUDE_BRIDGE:success = write_claude_bridge(path, sse_url); break;
        }

        if (success) { written.insert(path); ++ok; }
        else ++fail;
    }
}


target_scope_t::target_scope_t(target_scope_t&& other) noexcept
    : ok(other.ok),
      swapped(other.swapped),
      resolved(other.resolved),
      prev_active_idx(other.prev_active_idx),
      target_idx(other.target_idx),
      resolved_id(std::move(other.resolved_id)),
      err(std::move(other.err))
{
    other.ok = false;
    other.swapped = false;
    other.resolved = false;
    other.prev_active_idx = static_cast<size_t>(-1);
    other.target_idx = static_cast<size_t>(-1);
}

target_scope_t& target_scope_t::operator=(target_scope_t&& other) noexcept
{
    if (this != &other) {
        ok = other.ok;
        swapped = other.swapped;
        resolved = other.resolved;
        prev_active_idx = other.prev_active_idx;
        target_idx = other.target_idx;
        resolved_id = std::move(other.resolved_id);
        err = std::move(other.err);
        other.ok = false;
        other.swapped = false;
        other.resolved = false;
        other.prev_active_idx = static_cast<size_t>(-1);
        other.target_idx = static_cast<size_t>(-1);
    }
    return *this;
}

target_scope_t::~target_scope_t()
{
    if (!ok) return;
    if (!swapped) return;
    if (prev_active_idx == static_cast<size_t>(-1)) return;
    if (prev_active_idx >= analysis_session::session_count()) return;
    (void)analysis_session::switch_session(prev_active_idx);
    diag::log_tagged_fmt("mcp_standalone",
        "target_scope_restore restored_idx=%llu",
        static_cast<unsigned long long>(prev_active_idx));
}

target_scope_t resolve_target(const json& args, std::string* out_err)
{
    target_scope_t scope;
    scope.ok = true;
    scope.resolved = false;

    if (args.is_null() || !args.is_object()) {
        return scope;
    }

    std::string binary_id;
    if (args.contains("binary_id") && args["binary_id"].is_string()) {
        binary_id = args["binary_id"].get<std::string>();
    } else if (args.contains("session_id") && args["session_id"].is_string()) {
        binary_id = args["session_id"].get<std::string>();
    }

    std::string file_path;
    if (binary_id.empty() && args.contains("file_path") && args["file_path"].is_string()) {
        file_path = args["file_path"].get<std::string>();
    }

    uint32_t target_pid = 0;
    if (binary_id.empty() && file_path.empty()) {
        for (const char* key : {"target_pid", "process_id", "pid"}) {
            if (!args.contains(key)) continue;
            const auto& v = args[key];
            if (v.is_number_unsigned()) {
                target_pid = static_cast<uint32_t>(v.get<uint64_t>());
            } else if (v.is_number_integer()) {
                int64_t s = v.get<int64_t>();
                if (s > 0) target_pid = static_cast<uint32_t>(s);
            } else if (v.is_string()) {
                std::string s = v.get<std::string>();
                if (!s.empty()) {
                    try { target_pid = static_cast<uint32_t>(std::stoul(s, nullptr, 0)); }
                    catch (...) { target_pid = 0; }
                }
            }
            if (target_pid != 0) break;
        }
    }

    size_t resolved_idx = static_cast<size_t>(-1);
    if (!binary_id.empty()) {
        size_t idx = 0;
        if (analysis_session::find_session_by_id(binary_id, &idx)) {
            resolved_idx = idx;
        } else {
            scope.ok = false;
            scope.err = "binary_id '" + binary_id + "' not found in active sessions";
            if (out_err) *out_err = scope.err;
            diag::log_tagged_fmt("mcp_standalone",
                "resolve_target binary_id='%s' not_found", binary_id.c_str());
            return scope;
        }
    } else if (!file_path.empty()) {
        size_t idx = 0;
        if (analysis_session::find_session_by_path(file_path, &idx)) {
            resolved_idx = idx;
        } else {
            scope.ok = false;
            scope.err = "file_path '" + file_path + "' not found in active sessions";
            if (out_err) *out_err = scope.err;
            return scope;
        }
    } else if (target_pid != 0) {
        size_t idx = 0;
        if (analysis_session::find_session_by_pid(target_pid, &idx)) {
            resolved_idx = idx;
        }
    }

    if (resolved_idx == static_cast<size_t>(-1)) {
        return scope;
    }

    size_t cur = analysis_session::active_session_idx();
    scope.prev_active_idx = cur;
    scope.target_idx = resolved_idx;
    scope.resolved = true;

    auto sum = analysis_session::summarize_session_at(resolved_idx);
    scope.resolved_id = sum.id;

    if (cur == resolved_idx) {
        diag::log_tagged_fmt("mcp_standalone",
            "resolve_target id='%s' idx=%llu already_active",
            scope.resolved_id.c_str(),
            static_cast<unsigned long long>(resolved_idx));
        return scope;
    }

    if (!analysis_session::switch_session(resolved_idx)) {
        scope.ok = false;
        scope.err = std::string("switch_session failed: ") + analysis_session::last_error();
        if (out_err) *out_err = scope.err;
        diag::log_tagged_fmt("mcp_standalone",
            "resolve_target switch_failed target_idx=%llu err='%s'",
            static_cast<unsigned long long>(resolved_idx), scope.err.c_str());
        return scope;
    }

    scope.swapped = true;
    diag::log_tagged_fmt("mcp_standalone",
        "resolve_target id='%s' resolved_idx=%llu swapped=1 prev_idx=%llu",
        scope.resolved_id.c_str(),
        static_cast<unsigned long long>(resolved_idx),
        static_cast<unsigned long long>(cur));
    return scope;
}


}
