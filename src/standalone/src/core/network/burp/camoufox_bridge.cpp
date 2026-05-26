#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "camoufox_bridge.hpp"
#include "camoufox_install.hpp"

#include "../../infra/event_bus.hpp"
#include "../../infra/work_queue.hpp"
#include "../../mcp/mcp_client.hpp"
#include "../../../helpers/diag_log.hpp"

#include <windows.h>
#include <shellapi.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace aida {
namespace burp {
namespace camoufox {

namespace {

struct singleton_t
{
    std::recursive_mutex                    mtx;
    std::shared_ptr<mcp_client::client_t>   client;
    bridge_state_t                          state              = bridge_state_t::stopped;
    std::string                             last_error;
    std::string                             server_command;
    uint32_t                                child_pid          = 0;
    uint64_t                                launched_ms        = 0;
    uint64_t                                last_call_ms       = 0;
    std::atomic<uint64_t>                   total_calls{0};
    std::atomic<uint64_t>                   total_errors{0};
    bool                                    browser_open       = false;
    std::string                             active_page_url;
    std::string                             cached_python_path;
    launch_config_t                         active_cfg;
};

inline singleton_t& sg()
{
    static singleton_t s;
    return s;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

std::string hex64(uint64_t v)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i)
    {
        out[static_cast<size_t>(i)] = kHex[v & 0xFu];
        v >>= 4;
    }
    return out;
}

std::string init_script_name(const std::string& js)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : js)
    {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return std::string("aida:inline:") + hex64(h) + ":" + std::to_string(js.size());
}

std::wstring utf8_to_wide(const std::string& s)
{
    if (s.empty()) return {};
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (wlen <= 0) return {};
    std::wstring out;
    out.resize(static_cast<size_t>(wlen));
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), wlen);
    return out;
}

std::string wide_to_utf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out;
    out.resize(static_cast<size_t>(len));
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), out.data(), len, nullptr, nullptr);
    return out;
}

bool path_exists_w(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring parent_dir_w(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return {};
    return path.substr(0, pos);
}

std::wstring join_path_w(const std::wstring& a, const std::wstring& b)
{
    if (a.empty()) return b;
    if (b.empty()) return a;
    wchar_t last = a.back();
    if (last == L'\\' || last == L'/') return a + b;
    return a + L"\\" + b;
}

bool append_unique_path(std::vector<std::wstring>& paths, const std::wstring& path)
{
    if (path.empty()) return false;
    for (const auto& existing : paths)
    {
        if (_wcsicmp(existing.c_str(), path.c_str()) == 0) return false;
    }
    paths.push_back(path);
    return true;
}

std::wstring executable_dir_w()
{
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;)
    {
        DWORD got = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (got == 0) return {};
        if (got < buffer.size())
            return parent_dir_w(std::wstring(buffer.data(), got));
        buffer.resize(buffer.size() * 2);
        if (buffer.size() > 32768) return {};
    }
}

std::wstring current_dir_w()
{
    DWORD need = GetCurrentDirectoryW(0, nullptr);
    if (need == 0) return {};
    std::wstring out;
    out.resize(need);
    DWORD got = GetCurrentDirectoryW(need, out.data());
    if (got == 0 || got >= need) return {};
    out.resize(got);
    return out;
}

std::vector<std::wstring> runtime_base_dirs()
{
    std::vector<std::wstring> bases;
    std::wstring exe_dir = executable_dir_w();
    append_unique_path(bases, exe_dir);
    append_unique_path(bases, current_dir_w());
    append_unique_path(bases, parent_dir_w(exe_dir));
    return bases;
}

void append_bundled_python_candidates(std::vector<std::string>& candidates)
{
    std::vector<std::wstring> rels = {
        L"python\\python.exe",
        L"python-3.12\\python.exe",
        L"Python312\\python.exe",
        L"runtime\\python\\python.exe",
        L"deps\\python\\python.exe",
        L"deps\\python-3.12\\python.exe",
        L"deps\\Python312\\python.exe"
    };
    for (const auto& base : runtime_base_dirs())
    {
        for (const auto& rel : rels)
        {
            std::wstring candidate = join_path_w(base, rel);
            if (path_exists_w(candidate))
                candidates.push_back(wide_to_utf8(candidate));
        }
    }
}

bool try_search_path(const wchar_t* exe_name, std::string& out_path)
{
    wchar_t buffer[MAX_PATH * 2] = {0};
    DWORD got = SearchPathW(nullptr, exe_name, nullptr, static_cast<DWORD>(sizeof(buffer) / sizeof(wchar_t)), buffer, nullptr);
    if (got == 0 || got >= sizeof(buffer) / sizeof(wchar_t)) return false;
    out_path = wide_to_utf8(buffer);
    return !out_path.empty();
}

bool try_python_directory(const std::wstring& base, std::string& out_path)
{
    DWORD attr = GetFileAttributesW(base.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) return false;

    std::wstring pattern = base + L"\\Python*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;

    std::wstring best;
    int best_minor = -1;
    int best_major = -1;
    do
    {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        std::wstring name = fd.cFileName;
        if (name.size() < 8) continue;
        if (name.compare(0, 6, L"Python") != 0) continue;
        std::wstring digits = name.substr(6);
        int major = 0, minor = 0;
        if (digits.size() >= 2)
        {
            major = digits[0] - L'0';
            if (digits.size() >= 3) minor = (digits[1] - L'0') * 10 + (digits[2] - L'0');
            else minor = digits[1] - L'0';
        }
        if (major < 3) continue;
        if (major == 3 && (minor < 10 || minor > 13)) continue;
        if (major > 3) continue;
        if (major > best_major || (major == best_major && minor > best_minor))
        {
            std::wstring candidate = base + L"\\" + name + L"\\python.exe";
            if (path_exists_w(candidate))
            {
                best = candidate;
                best_major = major;
                best_minor = minor;
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    if (best.empty()) return false;
    out_path = wide_to_utf8(best);
    return !out_path.empty();
}

bool try_env_python_root(const wchar_t* env_name, const wchar_t* suffix, std::string& out_path)
{
    wchar_t root[MAX_PATH] = {0};
    DWORD got = GetEnvironmentVariableW(env_name, root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return false;
    std::wstring base = std::wstring(root) + suffix;
    return try_python_directory(base, out_path);
}

bool try_known_python_roots(std::string& out_path)
{
    if (try_env_python_root(L"ProgramFiles", L"", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles", L"\\Python", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles(x86)", L"", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles(x86)", L"\\Python", out_path)) return true;
    if (try_env_python_root(L"LOCALAPPDATA", L"\\Programs\\Python", out_path)) return true;
    return false;
}

bool spawn_capture(const std::string& cmdline, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout)
{
    out_exit_code = 0;
    out_stdout.clear();

    SECURITY_ATTRIBUTES sa{};
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return false;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    std::wstring wcmdline = utf8_to_wide(cmdline);
    BOOL ok = CreateProcessW(nullptr, wcmdline.empty() ? nullptr : wcmdline.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!ok)
    {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("camoufox", "spawn_capture create_failed gle=%lu cmd_len=%zu timeout_ms=%lu",
            gle, cmdline.size(), static_cast<unsigned long>(timeout_ms));
        CloseHandle(rd);
        return false;
    }
    CloseHandle(pi.hThread);

    char buf[4096];
    DWORD elapsed = 0;
    const DWORD step = 100;
    while (true)
    {
        DWORD avail = 0;
        if (PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) && avail > 0)
        {
            DWORD got = 0;
            if (ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got > 0)
                out_stdout.append(buf, buf + got);
        }
        DWORD w = WaitForSingleObject(pi.hProcess, step);
        if (w == WAIT_OBJECT_0) break;
        elapsed += step;
        if (timeout_ms != INFINITE && elapsed >= timeout_ms)
        {
            TerminateProcess(pi.hProcess, 1);
            diag::log_tagged_fmt("camoufox", "spawn_capture timeout elapsed_ms=%lu cmd_len=%zu captured_len=%zu",
                static_cast<unsigned long>(elapsed), cmdline.size(), out_stdout.size());
            CloseHandle(pi.hProcess);
            CloseHandle(rd);
            return false;
        }
    }
    while (true)
    {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) || avail == 0) break;
        DWORD got = 0;
        if (!ReadFile(rd, buf, sizeof(buf), &got, nullptr) || got == 0) break;
        out_stdout.append(buf, buf + got);
    }
    GetExitCodeProcess(pi.hProcess, &out_exit_code);
    diag::log_tagged_fmt("camoufox", "spawn_capture exit code=%lu cmd_len=%zu captured_len=%zu",
        out_exit_code, cmdline.size(), out_stdout.size());
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return true;
}

std::string compact_child_output(std::string s, size_t limit = 1600)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    s = s.substr(a, b - a);
    for (char& c : s) {
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    if (s.size() > limit) {
        s.resize(limit);
        s += "...";
    }
    return s;
}

const char* json_type_name(const nlohmann::json& j)
{
    if (j.is_object()) return "object";
    if (j.is_array()) return "array";
    if (j.is_string()) return "string";
    if (j.is_boolean()) return "boolean";
    if (j.is_number()) return "number";
    if (j.is_null()) return "null";
    return "other";
}

std::string json_shape(const nlohmann::json& j, size_t max_keys = 12)
{
    std::ostringstream oss;
    oss << json_type_name(j);
    if (j.is_object())
    {
        oss << "{";
        size_t n = 0;
        for (auto it = j.begin(); it != j.end() && n < max_keys; ++it, ++n)
        {
            if (n) oss << ",";
            oss << it.key() << ":" << json_type_name(it.value());
        }
        if (j.size() > max_keys) oss << ",...";
        oss << "}";
    }
    else if (j.is_array())
    {
        oss << "[" << j.size() << "]";
    }
    return oss.str();
}

struct url_log_t
{
    std::string host;
    std::string path;
    bool has_query = false;
    bool has_fragment = false;
    size_t length = 0;
};

url_log_t summarize_url_for_log(const std::string& url)
{
    url_log_t out;
    out.length = url.size();
    size_t host_start = 0;
    size_t scheme = url.find("://");
    if (scheme != std::string::npos) host_start = scheme + 3;
    size_t host_end = url.find_first_of("/?#", host_start);
    if (host_end == std::string::npos) host_end = url.size();
    if (host_end > host_start) out.host = url.substr(host_start, host_end - host_start);
    size_t path_start = url.find('/', host_start);
    size_t query_pos = url.find('?', host_start);
    size_t frag_pos = url.find('#', host_start);
    out.has_query = query_pos != std::string::npos;
    out.has_fragment = frag_pos != std::string::npos;
    size_t path_end = url.size();
    if (query_pos != std::string::npos) path_end = query_pos;
    if (frag_pos != std::string::npos && frag_pos < path_end) path_end = frag_pos;
    if (path_start != std::string::npos && path_start < path_end) out.path = url.substr(path_start, path_end - path_start);
    if (out.path.empty()) out.path = "/";
    if (out.path.size() > 240)
    {
        out.path.resize(240);
        out.path += "...";
    }
    if (out.host.empty()) out.host = "<relative>";
    return out;
}

bool query_python_version(const std::string& python_path, int& major, int& minor, std::string& detail)
{
    major = 0;
    minor = 0;
    detail.clear();
    DWORD code = 0;
    std::string captured;
    std::string cmd = std::string("\"") + python_path + "\" -c \"import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')\"";
    if (!spawn_capture(cmd, 3000, code, captured))
    {
        detail = "version probe timed out or failed to spawn";
        return false;
    }
    if (code != 0)
    {
        detail = compact_child_output(captured);
        if (detail.empty()) detail = "version probe exit=" + std::to_string(code);
        return false;
    }
    int maj = 0;
    int min = 0;
    if (sscanf_s(captured.c_str(), "%d.%d", &maj, &min) != 2)
    {
        detail = compact_child_output(captured);
        if (detail.empty()) detail = "version probe returned no version";
        return false;
    }
    major = maj;
    minor = min;
    detail = compact_child_output(captured);
    return true;
}

bool supported_camoufox_python(const std::string& python_path, std::string* reason = nullptr)
{
    int major = 0;
    int minor = 0;
    std::string detail;
    if (!query_python_version(python_path, major, minor, detail))
    {
        if (reason) *reason = detail;
        return false;
    }
    if (major == 3 && minor >= 10 && minor <= 13)
    {
        if (reason) *reason = "python " + detail;
        return true;
    }
    if (reason)
    {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "python %d.%d outside supported camoufox range 3.10-3.13", major, minor);
        *reason = buf;
    }
    return false;
}

void publish_state(bridge_state_t st, const std::string& err)
{
    bridge_state_changed_t ev;
    ev.state     = st;
    ev.last_error = err;
    ev.child_pid = sg().child_pid;
    aida::events::publish(kBridgeStateChanged, ev);
}

void set_error_locked(const std::string& msg)
{
    sg().last_error = msg;
    diag::log_tagged("camoufox", msg.c_str());
}

void clear_error_locked()
{
    if (!sg().last_error.empty())
    {
        diag::log_tagged_fmt("camoufox", "clearing_last_error previous_len=%zu", sg().last_error.size());
        sg().last_error.clear();
    }
}

std::string ascii_lower_copy(std::string s)
{
    for (char& c : s)
    {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return s;
}

bool is_driver_closed_error(const std::string& msg)
{
    std::string s = ascii_lower_copy(msg);
    return s.find("connection closed while reading from the driver") != std::string::npos ||
           s.find("target page, context or browser has been closed") != std::string::npos ||
           s.find("browser has been closed") != std::string::npos ||
           s.find("browsercontext.add_init_script: connection closed") != std::string::npos ||
           s.find("page.add_init_script: connection closed") != std::string::npos ||
           s.find("page.goto: connection closed") != std::string::npos ||
           s.find("page.evaluate: connection closed") != std::string::npos ||
           s.find("page.title: connection closed") != std::string::npos ||
           s.find("page.screenshot: connection closed") != std::string::npos ||
           s.find("page.wait_for_selector: connection closed") != std::string::npos ||
           s.find("page.type: connection closed") != std::string::npos;
}

void disconnect_client_async(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason)
{
    if (!cli) return;
    std::thread([cli, reason]() {
        diag::log_tagged_fmt("camoufox", "disconnect_async start reason=%s", reason.c_str());
        cli->disconnect();
        diag::log_tagged_fmt("camoufox", "disconnect_async done reason=%s", reason.c_str());
    }).detach();
}

void terminate_process_id_async(uint32_t pid, const std::string& reason)
{
    if (pid == 0) return;
    std::thread([pid, reason]() {
        HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
        if (!h) {
            diag::log_tagged_fmt("camoufox", "terminate_process open_failed pid=%lu reason=%s gle=%lu",
                static_cast<unsigned long>(pid), reason.c_str(), static_cast<unsigned long>(GetLastError()));
            return;
        }
        BOOL ok = TerminateProcess(h, 1);
        DWORD gle = ok ? 0 : GetLastError();
        WaitForSingleObject(h, 3000);
        CloseHandle(h);
        diag::log_tagged_fmt("camoufox", "terminate_process pid=%lu reason=%s ok=%d gle=%lu",
            static_cast<unsigned long>(pid), reason.c_str(), ok ? 1 : 0, static_cast<unsigned long>(gle));
    }).detach();
}

bool parse_text_to_json(const std::string& text, nlohmann::json& out)
{
    if (text.empty())
    {
        out = nlohmann::json::object();
        return true;
    }
    try
    {
        out = nlohmann::json::parse(text);
        return true;
    }
    catch (...)
    {
        out = nlohmann::json::object();
        out["raw_text"] = text;
        return false;
    }
}

call_result_t to_bridge_result(const mcp_client::call_result_t& r)
{
    call_result_t out;
    out.ok   = r.success;
    out.text = r.text;
    if (!r.data.is_null())
    {
        out.data = r.data;
    }
    else
    {
        nlohmann::json parsed;
        parse_text_to_json(r.text, parsed);
        out.data = std::move(parsed);
    }
    if (!r.success)
    {
        out.error = r.text;
    }
    else if (out.data.is_object() && out.data.contains("error") && out.data["error"].is_string())
    {
        out.ok    = false;
        out.error = out.data["error"].get<std::string>();
    }
    diag::log_tagged_fmt("camoufox", "mcp_result_shape success=%d text_len=%zu data_shape=%s error_len=%zu",
        static_cast<int>(r.success), r.text.size(), json_shape(out.data).c_str(), out.error.size());
    return out;
}

std::string trim_ascii_lower(std::string s)
{
    size_t first = 0;
    while (first < s.size())
    {
        char c = s[first];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        ++first;
    }
    size_t last = s.size();
    while (last > first)
    {
        char c = s[last - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        --last;
    }
    std::string out = s.substr(first, last - first);
    for (char& c : out)
    {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return out;
}

bool is_document_click_selector(const std::string& selector)
{
    const std::string s = trim_ascii_lower(selector);
    return s == "body" || s == "html" || s == ":root" || s == "document" || s == "document.body";
}

call_result_t call_with_deadline(const std::string& tool_name, const nlohmann::json& args, int timeout_ms);

std::string evaluate_result_error(const call_result_t& r)
{
    if (!r.error.empty()) return r.error;
    try
    {
        if (r.data.is_object())
        {
            auto err = r.data.find("error");
            if (err != r.data.end() && err->is_string()) return err->get<std::string>();
            auto value = r.data.find("value");
            if (value != r.data.end() && value->is_object())
            {
                auto value_err = value->find("error");
                if (value_err != value->end() && value_err->is_string()) return value_err->get<std::string>();
            }
        }
    }
    catch (...) {}
    return {};
}

bool dispatch_dom_click(const std::string& selector, std::string& out_error)
{
    const std::string quoted = nlohmann::json(selector).dump();
    std::string expr;
    expr.reserve(quoted.size() + 2400);
    expr += "(()=>{";
    expr += "const selector=" + quoted + ";";
    expr += "const normalized=String(selector).trim().toLowerCase();";
    expr += "const directDocument=normalized==='document'||normalized==='document.body';";
    expr += "const el=directDocument?(document.body||document.documentElement):document.querySelector(selector);";
    expr += "if(!el)return {error:'Element not found: '+selector};";
    expr += "const target=el===document?document.body||document.documentElement:el;";
    expr += "if(!target)return {error:'No clickable target: '+selector};";
    expr += "let rect={left:0,top:0,width:1,height:1};";
    expr += "try{if(target.getBoundingClientRect)rect=target.getBoundingClientRect();}catch(e){}";
    expr += "const vw=window.innerWidth||document.documentElement.clientWidth||1;";
    expr += "const vh=window.innerHeight||document.documentElement.clientHeight||1;";
    expr += "let x=rect.left+(rect.width>0?rect.width/2:1);";
    expr += "let y=rect.top+(rect.height>0?rect.height/2:1);";
    expr += "x=Math.max(0,Math.min(vw-1,Math.round(x)));";
    expr += "y=Math.max(0,Math.min(vh-1,Math.round(y)));";
    expr += "if(target.scrollIntoView)try{target.scrollIntoView({block:'center',inline:'center',behavior:'instant'});}catch(e){}";
    expr += "const init={bubbles:true,cancelable:true,composed:true,view:window,button:0,buttons:1,clientX:x,clientY:y,screenX:x,screenY:y};";
    expr += "function fire(type){let ev=null;try{ev=type.indexOf('pointer')===0&&window.PointerEvent?new PointerEvent(type,Object.assign({pointerId:1,pointerType:'mouse',isPrimary:true},init)):new MouseEvent(type,init);}catch(e){ev=document.createEvent('MouseEvents');ev.initMouseEvent(type,true,true,window,1,x,y,x,y,false,false,false,false,0,null);}target.dispatchEvent(ev);}";
    expr += "try{if(target.focus)target.focus({preventScroll:true});}catch(e){}";
    expr += "fire('pointerover');fire('mouseover');fire('pointermove');fire('mousemove');fire('pointerdown');fire('mousedown');fire('pointerup');fire('mouseup');";
    expr += "if(typeof target.click==='function')target.click();else fire('click');";
    expr += "return {status:'clicked',selector:selector,mode:'dom_dispatch',x:x,y:y};";
    expr += "})()";

    nlohmann::json args;
    args["expression"] = expr;
    args["await_promise"] = false;
    call_result_t r = call_with_deadline("evaluate_js", args, 15000);
    out_error = evaluate_result_error(r);
    if (!r.ok || !out_error.empty())
    {
        if (out_error.empty()) out_error = "DOM click dispatch failed";
        diag::log_tagged_fmt("camoufox", "dispatch_dom_click failed selector=%s ok=%d err=%s",
            selector.c_str(), static_cast<int>(r.ok), out_error.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "dispatch_dom_click ok selector=%s", selector.c_str());
    return true;
}

call_result_t call_with_deadline(const std::string& tool_name, const nlohmann::json& args, int timeout_ms)
{
    call_result_t fail;
    fail.ok = false;

    std::shared_ptr<mcp_client::client_t> cli;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        if (sg().state == bridge_state_t::ready && sg().client)
        {
            cli = sg().client;
        }
    }

    if (!cli)
    {
        bridge_state_t old_state = bridge_state_t::stopped;
        bool had_client = false;
        std::string old_error;
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            old_state = sg().state;
            had_client = sg().client != nullptr;
            old_error = sg().last_error;
        }
        diag::log_tagged_fmt("camoufox", "call_with_deadline recovering tool=%s state=%d client=%d old_err_len=%zu",
            tool_name.c_str(), static_cast<int>(old_state), static_cast<int>(had_client), old_error.size());
        if (!ensure_ready())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            fail.error = sg().last_error;
            if (fail.error.empty())
                fail.error = old_state == bridge_state_t::stopped
                    ? "camoufox bridge is not running; call burp_headless_start with headless=false first"
                    : "camoufox bridge not ready";
            diag::log_tagged_fmt("camoufox", "call_with_deadline recovery_failed tool=%s state=%d client=%d err_len=%zu args_shape=%s",
                tool_name.c_str(), static_cast<int>(sg().state), static_cast<int>(sg().client != nullptr),
                fail.error.size(), json_shape(args).c_str());
            return fail;
        }
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            if (sg().state == bridge_state_t::ready && sg().client)
                cli = sg().client;
            else
                fail.error = sg().last_error.empty() ? std::string("camoufox bridge not ready after recovery") : sg().last_error;
        }
        if (!cli)
        {
            diag::log_tagged_fmt("camoufox", "call_with_deadline recovery_no_client tool=%s err=%s",
                tool_name.c_str(), fail.error.c_str());
            return fail;
        }
    }

    if (timeout_ms <= 0) timeout_ms = 30000;

    struct shared_state_t
    {
        std::mutex                       mtx;
        std::condition_variable          cv;
        bool                             done = false;
        mcp_client::call_result_t        result;
    };
    auto state = std::make_shared<shared_state_t>();

    const uint64_t t0 = now_ms();
    sg().total_calls.fetch_add(1, std::memory_order_relaxed);
    diag::log_tagged_fmt("camoufox", "call_with_deadline dispatch tool=%s timeout_ms=%d args_shape=%s",
        tool_name.c_str(), timeout_ms, json_shape(args).c_str());

    bool posted = work_queue::post([state, cli, tool_name, args]() {
        mcp_client::call_result_t r = cli->call_tool(tool_name, args);
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->result = std::move(r);
            state->done   = true;
        }
        state->cv.notify_all();
    });

    if (!posted)
    {
        fail.error = "work_queue::post failed";
        sg().total_errors.fetch_add(1, std::memory_order_relaxed);
        diag::log_tagged_fmt("camoufox", "call_with_deadline post_failed tool=%s", tool_name.c_str());
        return fail;
    }

    std::unique_lock<std::mutex> lk(state->mtx);
    bool got = state->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&state]() { return state->done; });
    if (!got)
    {
        std::shared_ptr<mcp_client::client_t> timed_out_client;
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                timed_out_client = sg().client;
                sg().client.reset();
                diag::log_tagged_fmt("camoufox", "timeout %dms on %s; detaching client for recovery", timeout_ms, tool_name.c_str());
                sg().state           = bridge_state_t::error;
                sg().last_error      = std::string("call_tool timeout: ") + tool_name;
                sg().browser_open    = false;
                sg().active_page_url.clear();
                sg().child_pid       = 0;
            }
            else
            {
                diag::log_tagged_fmt("camoufox", "timeout %dms on %s; current client already changed", timeout_ms, tool_name.c_str());
            }
        }
        if (timed_out_client)
        {
            std::thread([timed_out_client, tool_name]() {
                diag::log_tagged_fmt("camoufox", "timeout_disconnect_async start tool=%s", tool_name.c_str());
                timed_out_client->disconnect();
                diag::log_tagged_fmt("camoufox", "timeout_disconnect_async done tool=%s", tool_name.c_str());
            }).detach();
        }
        publish_state(bridge_state_t::error, std::string("timeout on ") + tool_name);
        sg().total_errors.fetch_add(1, std::memory_order_relaxed);
        fail.error = std::string("camoufox call_tool timeout: ") + tool_name;
        bridge_call_completed_t ev{tool_name, false, now_ms() - t0};
        aida::events::publish(kBridgeCallCompleted, ev);
        return fail;
    }

    mcp_client::call_result_t result = std::move(state->result);
    lk.unlock();

    call_result_t out = to_bridge_result(result);
    const bool driver_closed = !out.ok && is_driver_closed_error(out.error);
    {
        std::lock_guard<std::recursive_mutex> g(sg().mtx);
        sg().last_call_ms = now_ms();
        if (out.ok)
        {
            if (sg().client == cli) clear_error_locked();
        }
        else if (driver_closed)
        {
            sg().last_error = std::string("camoufox driver closed during ") + tool_name + ": " + out.error;
        }
    }
    if (!out.ok) sg().total_errors.fetch_add(1, std::memory_order_relaxed);
    if (driver_closed)
    {
        std::shared_ptr<mcp_client::client_t> closed_client;
        std::string state_error = std::string("camoufox driver closed during ") + tool_name + ": " + out.error;
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                closed_client = sg().client;
                sg().client.reset();
                sg().state = bridge_state_t::error;
                sg().browser_open = false;
                sg().active_page_url.clear();
                sg().child_pid = 0;
            }
            sg().last_error = state_error;
        }
        diag::log_tagged_fmt("camoufox", "driver_closed invalidated tool=%s err=%s", tool_name.c_str(), out.error.c_str());
        disconnect_client_async(closed_client, tool_name);
        publish_state(bridge_state_t::error, state_error);
    }
    bridge_call_completed_t ev{tool_name, out.ok, now_ms() - t0};
    aida::events::publish(kBridgeCallCompleted, ev);
    diag::log_tagged_fmt("camoufox", "call_with_deadline complete tool=%s ok=%d elapsed_ms=%llu data_shape=%s error_len=%zu",
        tool_name.c_str(), static_cast<int>(out.ok), static_cast<unsigned long long>(ev.duration_ms),
        json_shape(out.data).c_str(), out.error.size());
    return out;
}

bool wait_for_tool_listed(mcp_client::client_t* cli, const std::string& tool_name, int timeout_ms)
{
    const uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms);
    while (true)
    {
        auto tools = cli->list_tools();
        for (const auto& t : tools)
        {
            if (t.original_name == tool_name) return true;
        }
        if (now_ms() >= deadline) return false;
        Sleep(500);
    }
}

bool probe_module_installed_locked(const std::string& python_path)
{
    std::string cmdline = std::string("\"") + python_path + "\" -c \"import camoufox_reverse_mcp\"";
    diag::log_tagged_fmt("camoufox", "module_probe start python=%s module=camoufox_reverse_mcp", python_path.c_str());
    DWORD code = 0;
    std::string captured;
    if (!spawn_capture(cmdline, 3000, code, captured))
    {
        sg().last_error = "camoufox_reverse_mcp not installed and automatic setup did not complete";
        diag::log_tagged("camoufox", sg().last_error.c_str());
        return false;
    }
    if (code != 0)
    {
        sg().last_error = "camoufox_reverse_mcp not installed and automatic setup did not complete";
        const std::string detail = compact_child_output(captured, 400);
        diag::log_tagged_fmt("camoufox", "module_probe failed exit=%lu captured_len=%zu out=%.400s",
            code, captured.size(), detail.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "module_probe ok exit=%lu captured_len=%zu", code, captured.size());
    return true;
}

bool preflight_server_entry_locked(const std::string& python_path, const launch_config_t& cfg)
{
    const std::string module = cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : cfg.server_module;
    std::string cmdline;
    if (module == "camoufox_reverse_mcp")
        cmdline = std::string("\"") + python_path + "\" -m camoufox_reverse_mcp --help";
    else
        cmdline = std::string("\"") + python_path + "\" -c \"import importlib; importlib.import_module('" + module + "')\"";
    diag::log_tagged_fmt("camoufox", "server_preflight start python=%s module=%s", python_path.c_str(), module.c_str());

    DWORD code = 0;
    std::string captured;
    if (!spawn_capture(cmdline, 4000, code, captured))
    {
        sg().last_error = std::string("camoufox MCP server preflight failed to spawn or timed out: ") + module;
        diag::log_tagged("camoufox", sg().last_error.c_str());
        return false;
    }
    if (code != 0)
    {
        std::string detail = compact_child_output(captured);
        sg().last_error = std::string("camoufox MCP server preflight failed: ") + (detail.empty() ? std::string("exit=") + std::to_string(code) : detail);
        diag::log_tagged_fmt("camoufox", "server preflight failed module=%s exit=%lu out=%.400s",
            module.c_str(), code, detail.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "server preflight ok module=%s captured_len=%zu", module.c_str(), captured.size());
    return true;
}

bool prepare_install_for_launch_locked(std::string& python_path)
{
    install::status_t st = install::get_status();
    if (st.state == install::install_state_t::unknown ||
        st.state == install::install_state_t::checking)
        st = install::probe();
    if (!st.python_path.empty()) python_path = st.python_path;

    if (st.state != install::install_state_t::ok)
    {
        if (st.state == install::install_state_t::missing_python)
        {
            sg().last_error = st.last_message.empty() ? install::last_error() : st.last_message;
            if (sg().last_error.empty()) sg().last_error = "supported Python 3.10-3.13 interpreter not found for Camoufox";
            diag::log_tagged_fmt("camoufox", "prepare_install_for_launch missing_python err=%s", sg().last_error.c_str());
            return false;
        }

        std::string setup_log;
        bool ready = false;
        try { ready = install::ensure_ready(setup_log); } catch (...) { ready = false; }
        st = install::get_status();
        if (!st.python_path.empty()) python_path = st.python_path;
        if (!ready || st.state != install::install_state_t::ok)
        {
            sg().last_error = install::last_error();
            if (sg().last_error.empty()) sg().last_error = st.last_message;
            if (sg().last_error.empty()) sg().last_error = "camoufox dependency setup did not reach ready state";
            const std::string detail = compact_child_output(setup_log);
            if (!detail.empty() && sg().last_error.find(detail) == std::string::npos)
                sg().last_error += ": " + detail;
            diag::log_tagged_fmt("camoufox", "prepare_install_for_launch setup_failed state=%d err=%s",
                static_cast<int>(st.state), sg().last_error.c_str());
            return false;
        }
    }
    return true;
}

nlohmann::json build_launch_args(const launch_config_t& cfg)
{
    nlohmann::json j;
    j["headless"]     = cfg.headless;
    j["os_type"]      = cfg.os.empty() ? std::string("auto") : cfg.os;
    j["locale"]       = cfg.locale.empty() ? std::string("auto") : cfg.locale;
    j["humanize"]     = cfg.humanize;
    j["geoip"]        = cfg.geoip;
    j["block_images"] = cfg.block_images;
    j["block_webrtc"] = cfg.block_webrtc;
    j["enable_trace"] = cfg.enable_trace;
    if (!cfg.proxy.empty()) j["proxy"] = cfg.proxy;
    return j;
}

}

bool ensure_python_available(std::string& out_python_path)
{
    diag::log_tagged_fmt("camoufox", "ensure_python_available entry");
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    if (!sg().cached_python_path.empty() && path_exists_w(utf8_to_wide(sg().cached_python_path)))
    {
        std::string reason;
        if (supported_camoufox_python(sg().cached_python_path, &reason))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available cached path=%s %s", sg().cached_python_path.c_str(), reason.c_str());
            out_python_path = sg().cached_python_path;
            return true;
        }
        diag::log_tagged_fmt("camoufox", "ensure_python_available cached rejected path=%s reason=%s",
            sg().cached_python_path.c_str(), reason.c_str());
        sg().cached_python_path.clear();
    }
    std::vector<std::string> candidates;
    append_bundled_python_candidates(candidates);
    std::string found;
    if (try_search_path(L"python.exe", found)) candidates.push_back(found);
    found.clear();
    if (try_search_path(L"python3.exe", found)) candidates.push_back(found);
    found.clear();
    if (try_known_python_roots(found)) candidates.push_back(found);
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    for (const std::string& candidate : candidates)
    {
        std::string reason;
        if (!supported_camoufox_python(candidate, &reason))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available rejected path=%s reason=%s", candidate.c_str(), reason.c_str());
            continue;
        }
        diag::log_tagged_fmt("camoufox", "ensure_python_available found path=%s %s", candidate.c_str(), reason.c_str());
        sg().cached_python_path = candidate;
        out_python_path         = candidate;
        return true;
    }
    diag::log_tagged_fmt("camoufox", "ensure_python_available python_not_found");
    set_error_locked("supported Python 3.10-3.13 interpreter not found for camoufox");
    return false;
}

bool start_bridge(const launch_config_t& cfg)
{
    launch_config_t effective_cfg = cfg;
    if (effective_cfg.headless)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge forcing_visible requested_headless=1");
        effective_cfg.headless = false;
    }
    diag::log_tagged_fmt("camoufox", "start_bridge entry headless=%d module=%s",
        static_cast<int>(effective_cfg.headless), effective_cfg.server_module.c_str());
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);

    if (sg().state == bridge_state_t::ready && sg().client)
    {
        if (!is_driver_closed_error(sg().last_error))
        {
            diag::log_tagged_fmt("camoufox", "start_bridge already_ready reusing");
            sg().active_cfg = effective_cfg;
            return true;
        }
        diag::log_tagged_fmt("camoufox", "start_bridge invalidating_ready_driver_closed err=%s", sg().last_error.c_str());
        sg().client->disconnect();
        sg().client.reset();
        sg().browser_open = false;
        sg().active_page_url.clear();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
    }
    if (sg().state == bridge_state_t::starting)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge already_starting rejected");
        set_error_locked("camoufox bridge already starting");
        return false;
    }
    diag::log_tagged_fmt("camoufox", "start_bridge state->starting");

    if (sg().client)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge disconnecting_stale_client state=%d browser_open=%d",
            static_cast<int>(sg().state), static_cast<int>(sg().browser_open));
        sg().client->disconnect();
        sg().client.reset();
        sg().browser_open = false;
        sg().active_page_url.clear();
        sg().child_pid = 0;
    }
    sg().state          = bridge_state_t::starting;
    sg().last_error.clear();
    publish_state(bridge_state_t::starting, std::string());

    std::string python_path = effective_cfg.python_executable;
    if (!python_path.empty())
    {
        std::string reason;
        if (!supported_camoufox_python(python_path, &reason))
        {
            diag::log_tagged_fmt("camoufox", "start_bridge explicit_python_rejected path=%s reason=%s",
                python_path.c_str(), reason.c_str());
            python_path.clear();
        }
    }
    if (python_path.empty())
    {
        if (!ensure_python_available(python_path))
        {
            std::string setup_log;
            bool ready = false;
            try { ready = install::ensure_ready(setup_log); } catch (...) { ready = false; }
            if (!ready || !ensure_python_available(python_path))
            {
                sg().last_error = install::last_error();
                if (sg().last_error.empty()) sg().last_error = compact_child_output(setup_log);
                if (sg().last_error.empty()) sg().last_error = "supported Python 3.10-3.13 interpreter not found for Camoufox";
                sg().state = bridge_state_t::error;
                publish_state(bridge_state_t::error, sg().last_error);
                return false;
            }
        }
    }

    if (!prepare_install_for_launch_locked(python_path))
    {
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (!probe_module_installed_locked(python_path))
    {
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (!preflight_server_entry_locked(python_path, effective_cfg))
    {
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    mcp_client::server_config_t scfg;
    scfg.name      = "camoufox-reverse";
    scfg.transport = mcp_client::transport_type_t::stdio;
    scfg.command   = python_path;
    scfg.args.push_back("-m");
    scfg.args.push_back(effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    for (const auto& a : effective_cfg.extra_args) scfg.args.push_back(a);
    scfg.env["PYTHONIOENCODING"] = "utf-8";
    scfg.enabled                 = true;
    scfg.auto_connect            = false;
    scfg.oauth_enabled           = false;

    sg().client = std::make_shared<mcp_client::client_t>();

    if (!sg().client->connect(scfg))
    {
        std::string inner = sg().client->last_error();
        sg().client.reset();
        sg().state      = bridge_state_t::error;
        sg().last_error = std::string("client connect failed: ") + (inner.empty() ? std::string("(no detail)") : inner);
        diag::log_tagged("camoufox", sg().last_error.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    int wait_ms = effective_cfg.launch_timeout_ms > 0 ? effective_cfg.launch_timeout_ms : 180000;
    if (wait_ms < 5000) wait_ms = 5000;
    if (wait_ms > 120000) wait_ms = 120000;
    if (!wait_for_tool_listed(sg().client.get(), "launch_browser", wait_ms))
    {
        std::string inner = sg().client->last_error();
        sg().client->disconnect();
        sg().client.reset();
        sg().state      = bridge_state_t::error;
        sg().last_error = std::string("camoufox MCP server did not expose launch_browser within timeout; mcp last_error=") + inner;
        diag::log_tagged("camoufox", sg().last_error.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    sg().server_command = python_path + " -m " + (effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    sg().child_pid      = sg().client ? sg().client->child_process_id() : 0;
    sg().launched_ms    = now_ms();
    sg().active_cfg     = effective_cfg;

    nlohmann::json args = build_launch_args(effective_cfg);
    struct launch_state_t
    {
        std::mutex                mtx;
        std::condition_variable   cv;
        bool                      done = false;
        mcp_client::call_result_t result;
    };
    auto launch_state = std::make_shared<launch_state_t>();
    auto launch_client = sg().client;
    const uint32_t launch_child_pid = sg().child_pid;
    int launch_wait_ms = effective_cfg.launch_timeout_ms > 0 ? effective_cfg.launch_timeout_ms : 180000;
    if (launch_wait_ms < 15000) launch_wait_ms = 15000;
    if (launch_wait_ms > 240000) launch_wait_ms = 240000;
    bool launch_posted = work_queue::post([launch_state, launch_client, args]() {
        mcp_client::call_result_t r = launch_client->call_tool("launch_browser", args);
        {
            std::lock_guard<std::mutex> lk(launch_state->mtx);
            launch_state->result = std::move(r);
            launch_state->done = true;
        }
        launch_state->cv.notify_all();
    });
    if (!launch_posted)
    {
        auto failed_client = sg().client;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        sg().last_error = "launch_browser dispatch failed";
        diag::log_tagged("camoufox", sg().last_error.c_str());
        disconnect_client_async(failed_client, "launch_browser_dispatch_failed");
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    mcp_client::call_result_t launch;
    {
        std::unique_lock<std::mutex> launch_lk(launch_state->mtx);
        bool launch_done = launch_state->cv.wait_for(launch_lk, std::chrono::milliseconds(launch_wait_ms),
            [&launch_state]() { return launch_state->done; });
        if (!launch_done)
        {
            auto timed_out_client = sg().client;
            sg().client.reset();
            sg().browser_open = false;
            sg().active_page_url.clear();
            sg().child_pid = 0;
            sg().state = bridge_state_t::error;
            sg().last_error = std::string("launch_browser timeout after ") + std::to_string(launch_wait_ms) + "ms";
            diag::log_tagged("camoufox", sg().last_error.c_str());
            terminate_process_id_async(launch_child_pid, "launch_browser_timeout");
            disconnect_client_async(timed_out_client, "launch_browser_timeout");
            publish_state(bridge_state_t::error, sg().last_error);
            return false;
        }
        launch = std::move(launch_state->result);
    }
    if (!launch.success)
    {
        sg().last_error = std::string("launch_browser failed: ") + launch.text;
        diag::log_tagged("camoufox", sg().last_error.c_str());
        auto failed_client = sg().client;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        disconnect_client_async(failed_client, "launch_browser_failed");
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    nlohmann::json parsed;
    parse_text_to_json(launch.text, parsed);
    if (parsed.is_object() && parsed.contains("error") && parsed["error"].is_string())
    {
        sg().last_error = std::string("launch_browser returned error: ") + parsed["error"].get<std::string>();
        diag::log_tagged("camoufox", sg().last_error.c_str());
        auto failed_client = sg().client;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        disconnect_client_async(failed_client, "launch_browser_returned_error");
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    sg().browser_open = true;
    sg().state        = bridge_state_t::ready;
    sg().last_error.clear();
    diag::log_tagged_fmt("camoufox", "bridge ready (python=%s)", python_path.c_str());
    publish_state(bridge_state_t::ready, std::string());
    return true;
}

bool stop_bridge()
{
    diag::log_tagged_fmt("camoufox", "stop_bridge entry");
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    if (sg().state == bridge_state_t::stopped)
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge already_stopped");
        sg().client.reset();
        return true;
    }
    if (sg().client && sg().browser_open)
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge sending_close_browser");
        mcp_client::call_result_t r = sg().client->call_tool("close_browser", nlohmann::json::object());
        (void)r;
        sg().browser_open    = false;
        sg().active_page_url.clear();
    }
    if (sg().client) sg().client->disconnect();
    sg().client.reset();
    sg().child_pid = 0;
    sg().state = bridge_state_t::stopped;
    sg().last_error.clear();
    publish_state(bridge_state_t::stopped, std::string());
    diag::log_tagged("camoufox", "bridge stopped");
    return true;
}

bool is_ready()
{
    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
    if (!lk.owns_lock())
    {
        diag::log_tagged_fmt("camoufox", "is_ready busy result=0");
        return false;
    }
    bool ready = sg().state == bridge_state_t::ready && sg().client != nullptr && !is_driver_closed_error(sg().last_error);
    diag::log_tagged_fmt("camoufox", "is_ready result=%d", static_cast<int>(ready));
    return ready;
}

bool ensure_ready()
{
    diag::log_tagged_fmt("camoufox", "ensure_ready entry");
    if (is_ready()) {
        diag::log_tagged_fmt("camoufox", "ensure_ready already_ready");
        return true;
    }
    install::status_t st = install::get_status();
    if (st.state == install::install_state_t::unknown ||
        st.state == install::install_state_t::checking)
        st = install::probe();
    if (st.state == install::install_state_t::missing_python)
    {
        std::string setup_log;
        bool setup_ready = false;
        try { setup_ready = install::ensure_ready(setup_log); } catch (...) { setup_ready = false; }
        st = install::get_status();
        if (!setup_ready || st.state != install::install_state_t::ok)
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().last_error = install::last_error();
            if (sg().last_error.empty()) sg().last_error = compact_child_output(setup_log);
            if (sg().last_error.empty()) sg().last_error = "camoufox dependency setup did not reach ready state";
            diag::log_tagged_fmt("camoufox", "ensure_ready install_not_ready state=%d err=%s",
                static_cast<int>(st.state), sg().last_error.c_str());
            return false;
        }
    }
    launch_config_t cfg;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        cfg = sg().active_cfg;
    }
    cfg.headless = false;
    if (cfg.server_module.empty()) cfg.server_module = "camoufox_reverse_mcp";
    if (cfg.python_executable.empty()) cfg.python_executable = st.python_path;
    diag::log_tagged_fmt("camoufox", "ensure_ready starting_bridge python=%s module=%s has_proxy=%d",
        cfg.python_executable.c_str(), cfg.server_module.c_str(), static_cast<int>(!cfg.proxy.empty()));
    return start_bridge(cfg);
}

bridge_status_t get_status()
{
    bridge_status_t s;
    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
    if (!lk.owns_lock())
    {
        s.state = bridge_state_t::starting;
        s.last_error = "camoufox bridge state is busy";
        s.total_calls = sg().total_calls.load(std::memory_order_relaxed);
        s.total_errors = sg().total_errors.load(std::memory_order_relaxed);
        diag::log_tagged_fmt("camoufox", "get_status busy calls=%llu errors=%llu",
            static_cast<unsigned long long>(s.total_calls),
            static_cast<unsigned long long>(s.total_errors));
        return s;
    }
    s.state           = sg().state;
    s.last_error      = sg().last_error;
    s.server_command  = sg().server_command;
    s.child_pid       = sg().child_pid;
    s.launched_ms     = sg().launched_ms;
    s.last_call_ms    = sg().last_call_ms;
    s.total_calls     = sg().total_calls.load(std::memory_order_relaxed);
    s.total_errors    = sg().total_errors.load(std::memory_order_relaxed);
    s.browser_open    = sg().browser_open;
    s.active_page_url = sg().active_page_url;
    if (s.state == bridge_state_t::ready && is_driver_closed_error(s.last_error))
    {
        s.state = bridge_state_t::error;
        s.browser_open = false;
        s.active_page_url.clear();
    }
    const url_log_t u = summarize_url_for_log(s.active_page_url);
    diag::log_tagged_fmt("camoufox", "get_status state=%d browser_open=%d calls=%llu errors=%llu active_host=%s active_path=%s query=%d url_len=%zu",
        static_cast<int>(s.state), static_cast<int>(s.browser_open),
        static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors), u.host.c_str(), u.path.c_str(),
        static_cast<int>(u.has_query), u.length);
    return s;
}

call_result_t call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms)
{
    diag::log_tagged_fmt("camoufox", "call_tool entry tool=%s timeout_ms=%d args_shape=%s", tool_name.c_str(), timeout_ms, json_shape(args).c_str());
    call_result_t r = call_with_deadline(tool_name, args.is_null() ? nlohmann::json::object() : args, timeout_ms);
    diag::log_tagged_fmt("camoufox", "call_tool result tool=%s ok=%d data_shape=%s text_len=%zu error_len=%zu",
        tool_name.c_str(), static_cast<int>(r.ok), json_shape(r.data).c_str(), r.text.size(), r.error.size());
    return r;
}

bool launch_browser(const launch_config_t& cfg)
{
    diag::log_tagged_fmt("camoufox", "launch_browser entry headless=%d", static_cast<int>(cfg.headless));
    return start_bridge(cfg);
}

bool close_browser()
{
    diag::log_tagged_fmt("camoufox", "close_browser entry");
    return stop_bridge();
}

bool navigate(const std::string& url, const std::string& wait_until, int timeout_ms)
{
    const url_log_t u = summarize_url_for_log(url);
    diag::log_tagged_fmt("camoufox", "navigate entry host=%s path=%s query=%d fragment=%d url_len=%zu wait_until=%s timeout_ms=%d",
        u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query), static_cast<int>(u.has_fragment), u.length, wait_until.c_str(), timeout_ms);
    if (url.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("navigate: url is empty");
        return false;
    }
    if (!ensure_ready())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        if (sg().last_error.empty()) set_error_locked("navigate: camoufox bridge not ready");
        return false;
    }
    nlohmann::json a;
    a["url"]                  = url;
    a["wait_until"]           = wait_until.empty() ? std::string("load") : wait_until;
    a["collect_response_chain"] = true;
    a["clear_network_capture"]  = true;
    a["include_title"]          = false;
    int call_timeout = timeout_ms > 0 ? timeout_ms + 5000 : 35000;
    call_result_t r = call_with_deadline("navigate", a, call_timeout);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "navigate failed host=%s path=%s err=%s", u.host.c_str(), u.path.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("navigate failed: ") + r.error);
        return false;
    }
    if (r.data.is_object() && r.data.contains("url") && r.data["url"].is_string())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().active_page_url = r.data["url"].get<std::string>();
        const url_log_t f = summarize_url_for_log(sg().active_page_url);
        diag::log_tagged_fmt("camoufox", "navigate ok final_host=%s final_path=%s query=%d url_len=%zu",
            f.host.c_str(), f.path.c_str(), static_cast<int>(f.has_query), f.length);
    } else {
        diag::log_tagged_fmt("camoufox", "navigate ok host=%s path=%s query=%d", u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query));
    }
    return true;
}

bool reload(const std::string& wait_until)
{
    diag::log_tagged_fmt("camoufox", "reload entry wait_until=%s", wait_until.c_str());
    nlohmann::json a;
    a["wait_until"] = wait_until.empty() ? std::string("load") : wait_until;
    call_result_t r = call_with_deadline("reload", a, 35000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "reload failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("reload failed: ") + r.error);
        return false;
    }
    if (r.data.is_object() && r.data.contains("url") && r.data["url"].is_string())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().active_page_url = r.data["url"].get<std::string>();
        const url_log_t u = summarize_url_for_log(sg().active_page_url);
        diag::log_tagged_fmt("camoufox", "reload ok host=%s path=%s query=%d url_len=%zu",
            u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query), u.length);
    } else {
        diag::log_tagged_fmt("camoufox", "reload ok");
    }
    return true;
}

call_result_t evaluate_js(const std::string& expression, bool await_promise)
{
    diag::log_tagged_fmt("camoufox", "evaluate_js entry expr_len=%zu await=%d",
        expression.size(), static_cast<int>(await_promise));
    nlohmann::json a;
    a["expression"]    = expression;
    a["await_promise"] = await_promise;
    call_result_t r = call_with_deadline("evaluate_js", a, 60000);
    diag::log_tagged_fmt("camoufox", "evaluate_js result ok=%d", static_cast<int>(r.ok));
    return r;
}

bool add_init_script(const std::string& js)
{
    diag::log_tagged_fmt("camoufox", "add_init_script entry js_len=%zu", js.size());
    if (js.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("add_init_script: script body is empty");
        return false;
    }

    static const char* const kPresetNames[] = {
        "xhr", "fetch", "crypto", "websocket", "debugger_bypass",
        "cookie", "runtime_probe", "xss_sentinel", "alert_capture",
        "eval_capture", "function_capture", "setTimeout_capture",
        "location_capture"
    };
    for (const char* name : kPresetNames)
    {
        if (js == name)
        {
            diag::log_tagged_fmt("camoufox", "add_init_script preset=%s", name);
            nlohmann::json a;
            a["preset"]     = name;
            a["persistent"] = true;
            call_result_t r = call_with_deadline("inject_hook_preset", a, 30000);
            if (!r.ok)
            {
                diag::log_tagged_fmt("camoufox", "add_init_script preset_failed preset=%s err=%s",
                    name, r.error.c_str());
                std::lock_guard<std::recursive_mutex> lk(sg().mtx);
                set_error_locked(std::string("add_init_script (preset) failed: ") + r.error);
                return false;
            }
            diag::log_tagged_fmt("camoufox", "add_init_script preset_ok preset=%s", name);
            return true;
        }
    }

    diag::log_tagged_fmt("camoufox", "add_init_script inline_script js_len=%zu", js.size());
    nlohmann::json a;
    a["script"] = js;
    a["name"] = init_script_name(js);
    call_result_t r = call_with_deadline("add_init_script", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "add_init_script inline_failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("add_init_script failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "add_init_script inline_ok");
    return true;
}

call_result_t get_console_logs(size_t max_records)
{
    diag::log_tagged_fmt("camoufox", "get_console_logs entry max_records=%zu", max_records);
    nlohmann::json a;
    if (max_records == 0) max_records = 200;
    call_result_t r = call_with_deadline("get_console_logs", a, 15000);
    if (r.ok && r.data.is_array() && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    diag::log_tagged_fmt("camoufox", "get_console_logs result ok=%d count=%zu",
        static_cast<int>(r.ok), r.data.is_array() ? r.data.size() : static_cast<size_t>(0));
    return r;
}

call_result_t list_network_requests(size_t max_records)
{
    diag::log_tagged_fmt("camoufox", "list_network_requests entry max_records=%zu", max_records);
    nlohmann::json a;
    call_result_t r = call_with_deadline("list_network_requests", a, 30000);
    if (r.ok && (!r.data.is_array() || r.data.empty()))
    {
        static const char* kPerfEntriesJs = R"JS((function(){
var out=[];
try {
var nav=performance.getEntriesByType('navigation') || [];
var res=performance.getEntriesByType('resource') || [];
function push(e, kind) {
out.push({
url: String(e.name || location.href || ''),
entry_type: kind,
initiator_type: String(e.initiatorType || kind),
start_time: Number(e.startTime || 0),
duration: Number(e.duration || 0),
transfer_size: Number(e.transferSize || 0)
});
}
for (var i=0;i<nav.length;i++) push(nav[i], 'navigation');
for (var j=0;j<res.length;j++) push(res[j], 'resource');
} catch(e) {}
return JSON.stringify(out);
})())JS";
        call_result_t fb = evaluate_js(kPerfEntriesJs, true);
        nlohmann::json records = nlohmann::json::array();
        if (fb.ok)
        {
            if (fb.data.is_array())
            {
                records = fb.data;
            }
            else if (fb.data.is_string())
            {
                nlohmann::json parsed;
                parse_text_to_json(fb.data.get<std::string>(), parsed);
                if (parsed.is_array()) records = std::move(parsed);
            }
            else if (fb.data.is_object())
            {
                for (const char* key : {"value", "result", "data"})
                {
                    auto it = fb.data.find(key);
                    if (it == fb.data.end())
                        continue;
                    if (it->is_array())
                    {
                        records = *it;
                        break;
                    }
                    if (it->is_string())
                    {
                        nlohmann::json parsed;
                        parse_text_to_json(it->get<std::string>(), parsed);
                        if (parsed.is_array())
                        {
                            records = std::move(parsed);
                            break;
                        }
                    }
                }
            }
        }
        if (!records.empty())
        {
            diag::log_tagged_fmt("camoufox", "list_network_requests performance_fallback count=%zu", records.size());
            r.data = std::move(records);
        }
        else
        {
            diag::log_tagged_fmt("camoufox", "list_network_requests performance_fallback empty ok=%d err=%s",
                static_cast<int>(fb.ok), fb.error.c_str());
        }
    }
    if (r.ok && r.data.is_array() && max_records > 0 && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    diag::log_tagged_fmt("camoufox", "list_network_requests result ok=%d count=%zu",
        static_cast<int>(r.ok), r.data.is_array() ? r.data.size() : static_cast<size_t>(0));
    return r;
}

call_result_t get_page_info()
{
    diag::log_tagged_fmt("camoufox", "get_page_info entry");
    nlohmann::json a;
    call_result_t r = call_with_deadline("get_page_info", a, 15000);
    if (r.ok && r.data.is_object() && r.data.contains("url") && r.data["url"].is_string())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().active_page_url = r.data["url"].get<std::string>();
        const url_log_t u = summarize_url_for_log(sg().active_page_url);
        diag::log_tagged_fmt("camoufox", "get_page_info ok host=%s path=%s query=%d url_len=%zu",
            u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query), u.length);
    } else {
        diag::log_tagged_fmt("camoufox", "get_page_info ok no_url_in_result");
    }
    return r;
}

bool take_screenshot(const std::string& output_path, bool full_page)
{
    diag::log_tagged_fmt("camoufox", "take_screenshot entry path=%s full_page=%d",
        output_path.c_str(), static_cast<int>(full_page));
    if (output_path.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("take_screenshot: output_path is empty");
        return false;
    }
    nlohmann::json a;
    a["full_page"] = full_page;
    call_result_t r = call_with_deadline("take_screenshot", a, 45000);
    if (!r.ok)
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("take_screenshot failed: ") + r.error);
        return false;
    }
    if (!r.data.is_object() || !r.data.contains("screenshot_base64") || !r.data["screenshot_base64"].is_string())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("take_screenshot: missing screenshot_base64 in response");
        return false;
    }

    const std::string& b64 = r.data["screenshot_base64"].get_ref<const std::string&>();
    static const int8_t decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> decoded;
    decoded.reserve((b64.size() / 4) * 3);
    int buf_val = 0;
    int buf_bits = 0;
    for (char c : b64)
    {
        unsigned uc = static_cast<unsigned char>(c);
        int v = decode_table[uc];
        if (v == -2) break;
        if (v < 0) continue;
        buf_val = (buf_val << 6) | v;
        buf_bits += 6;
        if (buf_bits >= 8)
        {
            buf_bits -= 8;
            decoded.push_back(static_cast<uint8_t>((buf_val >> buf_bits) & 0xFF));
        }
    }

    std::wstring wpath = utf8_to_wide(output_path);
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("take_screenshot: cannot create file ") + output_path);
        return false;
    }
    DWORD written = 0;
    BOOL wrote_ok = WriteFile(h, decoded.data(), static_cast<DWORD>(decoded.size()), &written, nullptr);
    CloseHandle(h);
    if (!wrote_ok || written != decoded.size())
    {
        diag::log_tagged_fmt("camoufox", "take_screenshot write_failed path=%s written=%lu decoded=%zu",
            output_path.c_str(), static_cast<unsigned long>(written), decoded.size());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("take_screenshot: write failed for ") + output_path);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "take_screenshot ok path=%s bytes=%zu", output_path.c_str(), decoded.size());
    return true;
}

bool take_snapshot(std::string& out_text)
{
    diag::log_tagged_fmt("camoufox", "take_snapshot entry");
    out_text.clear();
    nlohmann::json a;
    call_result_t r = call_with_deadline("take_snapshot", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "take_snapshot failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("take_snapshot failed: ") + r.error);
        return false;
    }
    if (r.data.is_object() && r.data.contains("snapshot"))
    {
        out_text = r.data["snapshot"].dump(2);
        diag::log_tagged_fmt("camoufox", "take_snapshot ok snapshot_len=%zu", out_text.size());
        return true;
    }
    out_text = r.text;
    diag::log_tagged_fmt("camoufox", "take_snapshot ok text_len=%zu", out_text.size());
    return true;
}

bool click(const std::string& selector)
{
    diag::log_tagged_fmt("camoufox", "click entry selector=%s", selector.c_str());
    if (selector.empty())
    {
        diag::log_tagged_fmt("camoufox", "click empty_selector");
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("click: selector is empty");
        return false;
    }
    if (is_document_click_selector(selector))
    {
        std::string dispatch_error;
        if (!dispatch_dom_click(selector, dispatch_error))
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            set_error_locked(std::string("click failed: ") + dispatch_error);
            return false;
        }
        diag::log_tagged_fmt("camoufox", "click ok selector=%s mode=dom_dispatch", selector.c_str());
        return true;
    }
    nlohmann::json a;
    a["selector"] = selector;
    call_result_t r = call_with_deadline("click", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "click failed selector=%s err=%s", selector.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("click failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "click ok selector=%s", selector.c_str());
    return true;
}

bool type_text(const std::string& selector, const std::string& text)
{
    diag::log_tagged_fmt("camoufox", "type_text entry selector=%s text_len=%zu", selector.c_str(), text.size());
    if (selector.empty())
    {
        diag::log_tagged_fmt("camoufox", "type_text empty_selector");
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("type_text: selector is empty");
        return false;
    }
    nlohmann::json a;
    a["selector"] = selector;
    a["text"]     = text;
    call_result_t r = call_with_deadline("type_text", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "type_text failed selector=%s err=%s", selector.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("type_text failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "type_text ok selector=%s", selector.c_str());
    return true;
}

bool wait_for(const std::string& selector, int timeout_ms)
{
    diag::log_tagged_fmt("camoufox", "wait_for entry selector=%s timeout_ms=%d", selector.c_str(), timeout_ms);
    if (selector.empty())
    {
        diag::log_tagged_fmt("camoufox", "wait_for empty_selector");
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("wait_for: selector is empty");
        return false;
    }
    nlohmann::json a;
    a["selector"] = selector;
    a["timeout"]  = timeout_ms > 0 ? timeout_ms : 5000;
    int call_timeout = (timeout_ms > 0 ? timeout_ms : 5000) + 5000;
    call_result_t r = call_with_deadline("wait_for", a, call_timeout);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "wait_for failed selector=%s err=%s", selector.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("wait_for failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "wait_for ok selector=%s", selector.c_str());
    return true;
}

bool reset_browser_state()
{
    diag::log_tagged_fmt("camoufox", "reset_browser_state entry");
    nlohmann::json a;
    a["clear_persistent_hooks"] = true;
    a["clear_network_capture"]  = true;
    a["clear_active_routes"]    = true;
    a["clear_cookies"]          = false;
    a["clear_storage"]          = false;
    call_result_t r = call_with_deadline("reset_browser_state", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "reset_browser_state failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("reset_browser_state failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "reset_browser_state ok");
    return true;
}

bool inject_hook_preset(const std::string& preset_name)
{
    diag::log_tagged_fmt("camoufox", "inject_hook_preset entry preset=%s", preset_name.c_str());
    if (preset_name.empty())
    {
        diag::log_tagged_fmt("camoufox", "inject_hook_preset empty_preset");
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("inject_hook_preset: preset_name is empty");
        return false;
    }
    nlohmann::json a;
    a["preset"]     = preset_name;
    a["persistent"] = true;
    call_result_t r = call_with_deadline("inject_hook_preset", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "inject_hook_preset failed preset=%s err=%s", preset_name.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("inject_hook_preset failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "inject_hook_preset ok preset=%s", preset_name.c_str());
    return true;
}

bool hook_function(const std::string& target, const std::string& mode)
{
    diag::log_tagged_fmt("camoufox", "hook_function entry target=%s mode=%s", target.c_str(), mode.c_str());
    if (target.empty())
    {
        diag::log_tagged_fmt("camoufox", "hook_function empty_target");
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("hook_function: target is empty");
        return false;
    }
    nlohmann::json a;
    a["function_path"] = target;
    a["mode"]          = mode.empty() ? std::string("trace") : mode;
    call_result_t r = call_with_deadline("hook_function", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "hook_function failed target=%s err=%s", target.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("hook_function failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "hook_function ok target=%s mode=%s", target.c_str(), mode.empty() ? "trace" : mode.c_str());
    return true;
}

bool remove_hooks()
{
    diag::log_tagged_fmt("camoufox", "remove_hooks entry");
    nlohmann::json a;
    a["keep_persistent"] = false;
    call_result_t r = call_with_deadline("remove_hooks", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "remove_hooks failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("remove_hooks failed: ") + r.error);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "remove_hooks ok");
    return true;
}

std::string last_error()
{
    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
    if (!lk.owns_lock())
    {
        diag::log_tagged_fmt("camoufox", "last_error queried busy");
        return "camoufox bridge state is busy";
    }
    std::string e = sg().last_error;
    diag::log_tagged_fmt("camoufox", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
