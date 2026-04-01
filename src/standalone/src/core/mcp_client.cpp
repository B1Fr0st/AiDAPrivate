

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "mcp_client.hpp"

#include <httplib.h>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

namespace mcp_client
{


static std::string sanitize_utf8(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size();) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            result += static_cast<char>(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size()) {
            result += input[i]; result += input[i + 1]; i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size()) {
            result += input[i]; result += input[i + 1]; result += input[i + 2]; i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size()) {
            result += input[i]; result += input[i + 1]; result += input[i + 2]; result += input[i + 3]; i += 4;
        } else {
            result += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return result;
}

static std::string json_dump_safe(const json& j, int indent = -1)
{
    try { return j.dump(indent); }
    catch (...) { return "{}"; }
}


static bool parse_url(const std::string& url, std::string& host_out, std::string& path_out)
{

    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        host_out = url;
        path_out = "/";
        return true;
    }


    size_t path_start = url.find('/', scheme_end + 3);
    if (path_start == std::string::npos) {
        host_out = url;
        path_out = "/";
    } else {
        host_out = url.substr(0, path_start);
        path_out = url.substr(path_start);
        if (path_out.empty()) path_out = "/";
    }
    return true;
}


client_t::client_t() = default;

client_t::~client_t()
{
    disconnect();
}

client_t::client_t(client_t&& o) noexcept
{
    std::lock_guard<std::mutex> lk(o._mtx);
    _cfg              = std::move(o._cfg);
    _state            = o._state;
    _server_name_str  = std::move(o._server_name_str);
    _server_version   = std::move(o._server_version);
    _last_error       = std::move(o._last_error);
    _cached_tools     = std::move(o._cached_tools);
    _next_id          = o._next_id;
    _child_process    = o._child_process;
    _child_stdin_w    = o._child_stdin_w;
    _child_stdout_r   = o._child_stdout_r;
    o._child_process  = nullptr;
    o._child_stdin_w  = nullptr;
    o._child_stdout_r = nullptr;
    o._state          = connection_state_t::disconnected;
}

client_t& client_t::operator=(client_t&& o) noexcept
{
    if (this != &o) {
        disconnect();
        std::lock_guard<std::mutex> lk(o._mtx);
        std::lock_guard<std::mutex> lk2(_mtx);
        _cfg              = std::move(o._cfg);
        _state            = o._state;
        _server_name_str  = std::move(o._server_name_str);
        _server_version   = std::move(o._server_version);
        _last_error       = std::move(o._last_error);
        _cached_tools     = std::move(o._cached_tools);
        _next_id          = o._next_id;
        _child_process    = o._child_process;
        _child_stdin_w    = o._child_stdin_w;
        _child_stdout_r   = o._child_stdout_r;
        o._child_process  = nullptr;
        o._child_stdin_w  = nullptr;
        o._child_stdout_r = nullptr;
        o._state          = connection_state_t::disconnected;
    }
    return *this;
}

bool client_t::connect(const server_config_t& cfg)
{
    std::lock_guard<std::mutex> lk(_mtx);


    if (_state == connection_state_t::connected)
    {

        _mtx.unlock();
        disconnect();
        _mtx.lock();
    }

    _cfg   = cfg;
    _state = connection_state_t::connecting;
    _last_error.clear();
    _cached_tools.clear();


    if (_cfg.transport == transport_type_t::stdio) {
        if (!launch_stdio_process()) {
            _state = connection_state_t::error;
            return false;
        }
    }


    json init_req = rpc_request("initialize", {
        {"protocolVersion", "2024-11-05"},
        {"capabilities", {}},
        {"clientInfo", {
            {"name", "AiDA Standalone"},
            {"version", "1.0.0"}
        }}
    });

    json response;
    try {
        response = send_rpc(init_req);
    } catch (const std::exception& e) {
        _last_error = std::string("Initialize failed: ") + e.what();
        _state = connection_state_t::error;
        kill_stdio_process();
        return false;
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "Unknown initialization error");
        _state = connection_state_t::error;
        kill_stdio_process();
        return false;
    }


    if (response.contains("result")) {
        const auto& result = response["result"];
        if (result.contains("serverInfo")) {
            _server_name_str = result["serverInfo"].value("name", _cfg.name);
            _server_version  = result["serverInfo"].value("version", "");
        }
    }

    if (_server_name_str.empty())
        _server_name_str = _cfg.name;


    json notif;
    notif["jsonrpc"] = "2.0";
    notif["method"]  = "notifications/initialized";
    try {
        send_rpc(notif);
    } catch (...) {

    }

    _state = connection_state_t::connected;
    return true;
}

void client_t::disconnect()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state == connection_state_t::disconnected)
        return;

    kill_stdio_process();
    _state = connection_state_t::disconnected;
    _cached_tools.clear();
}

bool client_t::reconnect()
{
    server_config_t cfg;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        cfg = _cfg;
    }
    disconnect();
    return connect(cfg);
}

std::vector<remote_tool_t> client_t::list_tools()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        _last_error = "Not connected";
        return {};
    }

    json req = rpc_request("tools/list");
    json response;
    try {
        response = send_rpc(req);
    } catch (const std::exception& e) {
        _last_error = std::string("tools/list failed: ") + e.what();
        return _cached_tools;
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "tools/list error");
        return _cached_tools;
    }

    _cached_tools.clear();
    if (response.contains("result") && response["result"].contains("tools")) {
        for (const auto& t : response["result"]["tools"]) {
            remote_tool_t tool;
            tool.server_name  = _server_name_str;
            tool.name         = t.value("name", "");
            tool.description  = t.value("description", "");
            if (t.contains("inputSchema"))
                tool.input_schema = t["inputSchema"];
            if (t.contains("annotations"))
                tool.annotations = t["annotations"];
            if (!tool.name.empty())
                _cached_tools.push_back(std::move(tool));
        }
    }

    return _cached_tools;
}

call_result_t client_t::call_tool(const std::string& tool_name, const json& arguments)
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return call_result_t::error("Not connected to " + _cfg.name);

    json req = rpc_request("tools/call", {
        {"name", tool_name},
        {"arguments", arguments}
    });

    json response;
    try {
        response = send_rpc(req);
    } catch (const std::exception& e) {
        return call_result_t::error(std::string("tools/call failed: ") + e.what());
    }

    if (response.contains("error")) {
        return call_result_t::error(
            response["error"].value("message", "Tool execution error"));
    }

    if (!response.contains("result"))
        return call_result_t::error("Empty result from server");

    const auto& result = response["result"];


    std::string text;
    json data;
    if (result.contains("content") && result["content"].is_array()) {
        for (const auto& block : result["content"]) {
            if (block.value("type", "") == "text") {
                if (!text.empty()) text += "\n";
                text += block.value("text", "");
            } else {

                if (data.is_null()) data = json::array();
                data.push_back(block);
            }
        }
    }

    bool is_error = result.value("isError", false);
    if (is_error)
        return call_result_t::error(text.empty() ? "Tool returned error" : text);

    return call_result_t::ok(sanitize_utf8(text), data);
}

std::vector<remote_resource_t> client_t::list_resources()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return {};

    json req = rpc_request("resources/list");
    json response;
    try {
        response = send_rpc(req);
    } catch (const std::exception& e) {
        _last_error = std::string("resources/list failed: ") + e.what();
        return {};
    }

    std::vector<remote_resource_t> resources;
    if (response.contains("result") && response["result"].contains("resources")) {
        for (const auto& r : response["result"]["resources"]) {
            remote_resource_t res;
            res.server_name = _server_name_str;
            res.uri         = r.value("uri", "");
            res.name        = r.value("name", "");
            res.description = r.value("description", "");
            res.mime_type   = r.value("mimeType", "");
            if (!res.uri.empty())
                resources.push_back(std::move(res));
        }
    }

    return resources;
}

std::string client_t::read_resource(const std::string& uri)
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return {};

    json req = rpc_request("resources/read", {{"uri", uri}});
    json response;
    try {
        response = send_rpc(req);
    } catch (const std::exception& e) {
        _last_error = std::string("resources/read failed: ") + e.what();
        return {};
    }

    if (response.contains("result") && response["result"].contains("contents")) {
        const auto& contents = response["result"]["contents"];
        if (contents.is_array() && !contents.empty()) {
            return contents[0].value("text", json_dump_safe(contents[0]));
        }
    }

    return {};
}

bool client_t::is_connected() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _state == connection_state_t::connected;
}

connection_state_t client_t::state() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _state;
}

const std::string& client_t::server_name() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _server_name_str;
}

const std::string& client_t::last_error() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _last_error;
}

const server_config_t& client_t::config() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _cfg;
}

const std::vector<remote_tool_t>& client_t::cached_tools() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _cached_tools;
}


json client_t::rpc_request(const std::string& method, const json& params)
{

    json req;
    req["jsonrpc"] = "2.0";
    req["method"]  = method;


    if (method.find("notifications/") == std::string::npos)
        req["id"] = _next_id++;

    if (!params.is_null() && !params.empty())
        req["params"] = params;

    return req;
}

json client_t::send_rpc(const json& request)
{

    switch (_cfg.transport) {
    case transport_type_t::http_sse:
        return send_http(request);
    case transport_type_t::stdio:
        return send_stdio(request);
    default:
        throw std::runtime_error("Unsupported transport type");
    }
}


json client_t::send_http(const json& request)
{


    std::string host, path;
    if (!parse_url(_cfg.url, host, path))
        throw std::runtime_error("Invalid MCP server URL: " + _cfg.url);

    httplib::Client cli(host);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(120);
    cli.set_write_timeout(10);
    cli.enable_server_certificate_verification(false);

    httplib::Headers headers = {
        {"Content-Type", "application/json"},
        {"Accept",       "application/json"}
    };

    if (!_cfg.api_key.empty())
        headers.emplace("Authorization", "Bearer " + _cfg.api_key);

    const std::string body = json_dump_safe(request);
    auto res = cli.Post(path, headers, body, "application/json");

    if (!res)
        throw std::runtime_error("HTTP request failed: " + httplib::to_string(res.error()));

    if (res->status < 200 || res->status >= 300)
        throw std::runtime_error("HTTP " + std::to_string(res->status) + ": " + res->body);


    json response = json::parse(res->body, nullptr, false);
    if (response.is_discarded())
        throw std::runtime_error("Invalid JSON response from MCP server");

    return response;
}


bool client_t::launch_stdio_process()
{


    if (_cfg.command.empty()) {
        _last_error = "No command specified for stdio transport";
        return false;
    }


    std::string cmdline = _cfg.command;
    for (const auto& arg : _cfg.args)
        cmdline += " " + arg;


    std::vector<wchar_t> env_block;
    if (!_cfg.env.empty()) {

        wchar_t* current_env = GetEnvironmentStringsW();
        if (current_env) {

            const wchar_t* p = current_env;
            while (*p) {
                size_t len = wcslen(p) + 1;
                env_block.insert(env_block.end(), p, p + len);
                p += len;
            }
            FreeEnvironmentStringsW(current_env);
        }

        for (const auto& [key, val] : _cfg.env) {
            std::wstring entry;
            entry.reserve(key.size() + val.size() + 2);
            for (char c : key)   entry += static_cast<wchar_t>(c);
            entry += L'=';
            for (char c : val)   entry += static_cast<wchar_t>(c);
            entry += L'\0';
            env_block.insert(env_block.end(), entry.begin(), entry.end());
        }
        env_block.push_back(L'\0');
    }


    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE stdin_read  = nullptr, stdin_write  = nullptr;
    HANDLE stdout_read = nullptr, stdout_write = nullptr;

    if (!CreatePipe(&stdin_read, &stdin_write, &sa, 0) ||
        !CreatePipe(&stdout_read, &stdout_write, &sa, 0))
    {
        _last_error = "Failed to create pipes for stdio transport";
        if (stdin_read)   CloseHandle(stdin_read);
        if (stdin_write)  CloseHandle(stdin_write);
        if (stdout_read)  CloseHandle(stdout_read);
        if (stdout_write) CloseHandle(stdout_write);
        return false;
    }


    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput   = stdin_read;
    si.hStdOutput  = stdout_write;
    si.hStdError   = GetStdHandle(STD_ERROR_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};


    std::wstring wcmdline;
    wcmdline.reserve(cmdline.size() + 1);
    for (char c : cmdline) wcmdline += static_cast<wchar_t>(c);

    BOOL created = CreateProcessW(
        nullptr,
        wcmdline.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        env_block.empty() ? nullptr : env_block.data(),
        nullptr,
        &si, &pi
    );


    CloseHandle(stdin_read);
    CloseHandle(stdout_write);

    if (!created) {
        _last_error = "Failed to launch MCP server process: " + cmdline;
        CloseHandle(stdin_write);
        CloseHandle(stdout_read);
        return false;
    }

    CloseHandle(pi.hThread);
    _child_process  = pi.hProcess;
    _child_stdin_w  = stdin_write;
    _child_stdout_r = stdout_read;


    Sleep(200);


    DWORD exit_code = 0;
    if (GetExitCodeProcess(static_cast<HANDLE>(_child_process), &exit_code) &&
        exit_code != STILL_ACTIVE)
    {
        _last_error = "MCP server process exited immediately (code " + std::to_string(exit_code) + ")";
        kill_stdio_process();
        return false;
    }

    return true;
}

void client_t::kill_stdio_process()
{


    if (_child_stdin_w) {
        CloseHandle(static_cast<HANDLE>(_child_stdin_w));
        _child_stdin_w = nullptr;
    }
    if (_child_stdout_r) {
        CloseHandle(static_cast<HANDLE>(_child_stdout_r));
        _child_stdout_r = nullptr;
    }
    if (_child_process) {
        TerminateProcess(static_cast<HANDLE>(_child_process), 0);
        WaitForSingleObject(static_cast<HANDLE>(_child_process), 3000);
        CloseHandle(static_cast<HANDLE>(_child_process));
        _child_process = nullptr;
    }
}

std::string client_t::read_line_from_stdout()
{

    if (!_child_stdout_r)
        throw std::runtime_error("stdio: no stdout handle");

    std::string line;
    char ch;
    DWORD read_bytes;

    while (true) {
        BOOL ok = ReadFile(static_cast<HANDLE>(_child_stdout_r), &ch, 1, &read_bytes, nullptr);
        if (!ok || read_bytes == 0) {
            if (line.empty())
                throw std::runtime_error("stdio: child process closed stdout");
            break;
        }
        if (ch == '\n')
            break;
        if (ch != '\r')
            line += ch;
    }

    return line;
}

void client_t::write_to_stdin(const std::string& data)
{

    if (!_child_stdin_w)
        throw std::runtime_error("stdio: no stdin handle");

    std::string msg = data + "\n";
    DWORD written;
    BOOL ok = WriteFile(
        static_cast<HANDLE>(_child_stdin_w),
        msg.c_str(),
        static_cast<DWORD>(msg.size()),
        &written, nullptr
    );
    if (!ok)
        throw std::runtime_error("stdio: failed to write to child stdin");
}

json client_t::send_stdio(const json& request)
{


    const std::string body = json_dump_safe(request);
    write_to_stdin(body);


    if (!request.contains("id"))
        return json::object();


    std::string response_str = read_line_from_stdout();

    json response = json::parse(response_str, nullptr, false);
    if (response.is_discarded())
        throw std::runtime_error("stdio: invalid JSON response");

    return response;
}


manager_t::manager_t()  = default;
manager_t::~manager_t() { disconnect_all(); }

void manager_t::add_server(const server_config_t& cfg)
{
    std::lock_guard<std::mutex> lk(_mtx);


    for (auto& e : _entries) {
        if (e.cfg.name == cfg.name) {
            e.cfg = cfg;
            return;
        }
    }

    _entries.push_back({cfg, client_t{}});
}

void manager_t::remove_server(const std::string& name)
{
    std::lock_guard<std::mutex> lk(_mtx);

    auto it = std::find_if(_entries.begin(), _entries.end(),
        [&](const entry_t& e) { return e.cfg.name == name; });

    if (it != _entries.end()) {
        it->client.disconnect();
        _entries.erase(it);
    }
}

void manager_t::connect_all()
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (e.cfg.enabled && e.cfg.auto_connect &&
            e.client.state() != connection_state_t::connected)
        {
            e.client.connect(e.cfg);
            if (e.client.is_connected())
                e.client.list_tools();
        }
    }
}

void manager_t::disconnect_all()
{
    std::lock_guard<std::mutex> lk(_mtx);
    for (auto& e : _entries)
        e.client.disconnect();
}

bool manager_t::connect_server(const std::string& name)
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (e.cfg.name == name) {
            bool ok = e.client.connect(e.cfg);
            if (ok) e.client.list_tools();
            return ok;
        }
    }
    return false;
}

void manager_t::disconnect_server(const std::string& name)
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (e.cfg.name == name) {
            e.client.disconnect();
            return;
        }
    }
}

std::vector<remote_tool_t> manager_t::get_all_tools()
{
    std::lock_guard<std::mutex> lk(_mtx);

    std::vector<remote_tool_t> all;
    for (auto& e : _entries) {
        if (e.client.is_connected()) {
            const auto& tools = e.client.cached_tools();
            all.insert(all.end(), tools.begin(), tools.end());
        }
    }
    return all;
}

call_result_t manager_t::call_tool(const std::string& qualified_name, const json& arguments)
{
    std::lock_guard<std::mutex> lk(_mtx);


    size_t sep = qualified_name.find("::");
    if (sep != std::string::npos) {
        std::string server = qualified_name.substr(0, sep);
        std::string tool   = qualified_name.substr(sep + 2);

        for (auto& e : _entries) {
            if (e.cfg.name == server && e.client.is_connected())
                return e.client.call_tool(tool, arguments);
        }
        return call_result_t::error("MCP server '" + server + "' not found or not connected");
    }


    for (auto& e : _entries) {
        if (!e.client.is_connected()) continue;
        for (const auto& t : e.client.cached_tools()) {
            if (t.name == qualified_name)
                return e.client.call_tool(qualified_name, arguments);
        }
    }

    return call_result_t::error("MCP tool '" + qualified_name + "' not found on any connected server");
}

size_t manager_t::tool_count() const
{
    std::lock_guard<std::mutex> lk(_mtx);

    size_t count = 0;
    for (const auto& e : _entries) {
        if (e.client.is_connected())
            count += e.client.cached_tools().size();
    }
    return count;
}

std::vector<remote_resource_t> manager_t::get_all_resources()
{
    std::lock_guard<std::mutex> lk(_mtx);

    std::vector<remote_resource_t> all;
    for (auto& e : _entries) {
        if (e.client.is_connected()) {
            auto res = e.client.list_resources();
            all.insert(all.end(), res.begin(), res.end());
        }
    }
    return all;
}

std::string manager_t::read_resource(const std::string& server_name, const std::string& uri)
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (e.cfg.name == server_name && e.client.is_connected())
            return e.client.read_resource(uri);
    }
    return {};
}

std::vector<manager_t::server_status_t> manager_t::get_status() const
{
    std::lock_guard<std::mutex> lk(_mtx);

    std::vector<server_status_t> result;
    result.reserve(_entries.size());

    for (const auto& e : _entries) {
        result.push_back({
            e.cfg.name,
            e.client.state(),
            e.client.last_error(),
            e.client.cached_tools().size()
        });
    }

    return result;
}

void manager_t::poll()
{
    std::lock_guard<std::mutex> lk(_mtx);

    for (auto& e : _entries) {
        if (!e.cfg.enabled || !e.cfg.auto_connect)
            continue;

        auto st = e.client.state();
        if (st == connection_state_t::error ||
            st == connection_state_t::disconnected)
        {

            e.client.connect(e.cfg);
            if (e.client.is_connected())
                e.client.list_tools();
        }
    }
}

}
