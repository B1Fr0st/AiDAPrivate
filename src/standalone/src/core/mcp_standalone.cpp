#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
#include <httplib.h>
#include <sstream>
#include <fstream>
#include <random>
#include <set>
#include <queue>
#include <condition_variable>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace mcp_standalone
{
static std::string json_dump_safe(const json& j, int indent = -1)
{
    try { return j.dump(indent); }
    catch (...) { return "{}"; }
}

static std::string generate_session_id()
{
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::mt19937_64 rng(now ^ (++counter));
    char buf[64];
    snprintf(buf, sizeof(buf), "sa-%016llx-%04llx",
             static_cast<unsigned long long>(rng()),
             static_cast<unsigned long long>(counter.load()));
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
    std::condition_variable cv;
    std::queue<std::string> events;
    std::atomic<bool> closed{false};

    void push_event(const std::string& event)
    {
        { std::lock_guard<std::mutex> lk(mtx); events.push(event); }
        cv.notify_one();
    }

    bool wait_event(std::string& out, int timeout_ms)
    {
        std::unique_lock<std::mutex> lk(mtx);
        if (cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
            [this] { return !events.empty() || closed.load(); }))
        {
            if (closed.load()) return false;
            if (!events.empty()) { out = std::move(events.front()); events.pop(); return true; }
        }
        return false;
    }

    void close() { closed.store(true); cv.notify_all(); }
};

server_t::server_t()  = default;
server_t::~server_t() { stop(); }

void server_t::register_tool(tool_def_t tool)
{
    std::lock_guard<std::mutex> lk(_tools_mtx);
    _tools.push_back(std::move(tool));
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
    json capabilities;
    capabilities["tools"]     = {{"listChanged", true}};
    capabilities["resources"] = {{"listChanged", true}};
    capabilities["prompts"]   = {{"listChanged", true}};
    capabilities["logging"]   = json::object();

    json server_info;
    server_info["name"]    = SERVER_NAME;
    server_info["version"] = SERVER_VERSION;

    static const char* instructions =
        "You are connected to AiDA Standalone â€” a reverse-engineering assistant "
        "that operates through a kernel-backed live inspection bridge (with user-mode fallback), "
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
        "- For number conversions, ALWAYS use `convert_number` â€” never convert manually\n";

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
        for (const auto& t : _tools)
            tools_arr.push_back(tool_schema(t));
    }
    json result;
    result["tools"] = tools_arr;
    return make_result(id, result);
}

json server_t::handle_tools_call(const json& id, const json& params)
{

    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_mcp_tool_exec);
        if (standalone_license::verify_gate_token(
                standalone_license::gate_mcp_tool_exec, gt) < 0.5) {
            return make_error(id, -32000,
                standalone_license::decode_status_string(
                    standalone_license::str_session_revoked));
        }

        // ARC validation: hash tool name and verify via ARC module
        if (standalone_license::is_arc_loaded()) {
            if (!params.contains("name") || !params["name"].is_string())
                return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");
            const std::string early_name = params["name"].get<std::string>();
            uint64_t name_hash = 14695981039346656037ULL;
            for (char c : early_name) {
                name_hash ^= static_cast<uint8_t>(c);
                name_hash *= 1099511628211ULL;
            }
            uint64_t arc_result = standalone_license::arc_validate_tool(name_hash, gt);
            if (arc_result == 0) {
                return make_error(id, -32000, "Service unavailable.");
            }
        }
    }

    if (!params.contains("name") || !params["name"].is_string())
        return make_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string tool_name = params["name"].get<std::string>();
    json arguments = params.contains("arguments") && params["arguments"].is_object()
                   ? params["arguments"] : json::object();

    const tool_def_t* found = nullptr;
    {
        std::lock_guard<std::mutex> lk(_tools_mtx);
        for (const auto& t : _tools) {
            if (t.name == tool_name) { found = &t; break; }
        }
    }

    if (!found)
        return make_error(id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + tool_name);

    tool_result_t tr;
    try {
        tr = found->handler(arguments);
    } catch (const std::exception& e) {
        tr = tool_result_t::error(std::string("Tool threw exception: ") + e.what());
    } catch (...) {
        tr = tool_result_t::error("Tool threw unknown exception");
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
    if (method == "notifications/cancelled" || method == "logging/setLevel")
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
    if (_running.load()) return true;

    _stop_requested = false;
    _port = 0;

    try {
        _server_thread = std::thread([this, port]() { server_thread_func(port); });
    } catch (const std::exception&) {
        return false;
    }


    for (int i = 0; i < 20 && !_running.load() && !_stop_requested.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));

    return _running.load();
}

void server_t::stop()
{
    if (!_running.load() && !_server_thread.joinable()) return;
    _stop_requested = true;
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        if (_active_server)
            static_cast<httplib::Server*>(_active_server)->stop();
    }
    if (_server_thread.joinable()) _server_thread.join();
}

void server_t::server_thread_func(int port)
{
    httplib::Server svr;
    {
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = &svr;
    }

    std::string session_id = generate_session_id();

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
                        std::string evt = ": connected\n\n";
                        if (!sink.write(evt.c_str(), evt.size())) return false;
                    }
                    for (int i = 0; i < 15; ++i) {
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        if (_stop_requested.load()) return false;
                    }
                    std::string ka = ": keepalive\n\n";
                    return sink.write(ka.c_str(), ka.size());
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
        size_t tool_count;
        { std::lock_guard<std::mutex> lk(_tools_mtx); tool_count = _tools.size(); }
        health["tools_count"] = tool_count;
        health["driver"]      = driver_bridge::is_loaded();
        health["attached"]    = driver_bridge::attached_pid();
        res.set_content(json_dump_safe(health), "application/json");
    });

    svr.Get("/api/tools", [this](const httplib::Request&, httplib::Response& res) {
        json tools_arr = json::array();
        { std::lock_guard<std::mutex> lk(_tools_mtx);
          for (const auto& t : _tools) tools_arr.push_back(tool_schema(t)); }
        res.set_content(json_dump_safe(tools_arr, 2), "application/json");
    });

    svr.Post("/api/tools/call", [this](const httplib::Request& req, httplib::Response& res) {
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
          for (const auto& t : _tools) { if (t.name == tool_name) { found = &t; break; } } }

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

        res.set_chunked_content_provider(
            "text/event-stream",
            [this, session](size_t offset, httplib::DataSink& sink) -> bool {
                if (offset == 0) {
                    std::string evt = format_sse_event("endpoint",
                        "/message?sessionId=" + session->id);
                    if (!sink.write(evt.c_str(), evt.size())) { session->close(); return false; }
                }
                std::string event;
                if (session->wait_event(event, 2000)) {
                    if (!sink.write(event.c_str(), event.size())) { session->close(); return false; }
                } else if (session->closed.load()) {
                    return false;
                } else if (_stop_requested.load()) {
                    session->close(); return false;
                } else {
                    std::string ka = ": keepalive\n\n";
                    if (!sink.write(ka.c_str(), ka.size())) { session->close(); return false; }
                }
                return !session->closed.load();
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
        std::lock_guard<std::mutex> lk(_server_mtx);
        _active_server = nullptr;
        _stop_requested = true;
        return;
    }

    _port = bound_port;
    _running = true;

    svr.listen_after_bind();

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


}
