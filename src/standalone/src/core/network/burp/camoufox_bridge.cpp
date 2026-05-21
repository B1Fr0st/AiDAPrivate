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
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
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

bool try_search_path(const wchar_t* exe_name, std::string& out_path)
{
    wchar_t buffer[MAX_PATH * 2] = {0};
    DWORD got = SearchPathW(nullptr, exe_name, nullptr, static_cast<DWORD>(sizeof(buffer) / sizeof(wchar_t)), buffer, nullptr);
    if (got == 0 || got >= sizeof(buffer) / sizeof(wchar_t)) return false;
    out_path = wide_to_utf8(buffer);
    return !out_path.empty();
}

bool try_local_appdata_python(std::string& out_path)
{
    wchar_t local_app[MAX_PATH] = {0};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", local_app, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return false;
    std::wstring base = std::wstring(local_app) + L"\\Programs\\Python";
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
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return true;
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
    return out;
}

call_result_t call_with_deadline(const std::string& tool_name, const nlohmann::json& args, int timeout_ms)
{
    call_result_t fail;
    fail.ok = false;

    std::shared_ptr<mcp_client::client_t> cli;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        if (sg().state != bridge_state_t::ready || !sg().client)
        {
            fail.error = "camoufox bridge not ready";
            return fail;
        }
        cli = sg().client;
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
        return fail;
    }

    std::unique_lock<std::mutex> lk(state->mtx);
    bool got = state->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&state]() { return state->done; });
    if (!got)
    {
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client)
            {
                diag::log_tagged_fmt("camoufox", "timeout %dms on %s; disconnecting", timeout_ms, tool_name.c_str());
                sg().client->disconnect();
                sg().state           = bridge_state_t::error;
                sg().last_error      = std::string("call_tool timeout: ") + tool_name;
                sg().browser_open    = false;
                sg().active_page_url.clear();
            }
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
    {
        std::lock_guard<std::recursive_mutex> g(sg().mtx);
        sg().last_call_ms = now_ms();
    }
    if (!out.ok) sg().total_errors.fetch_add(1, std::memory_order_relaxed);
    bridge_call_completed_t ev{tool_name, out.ok, now_ms() - t0};
    aida::events::publish(kBridgeCallCompleted, ev);
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
    DWORD code = 0;
    std::string captured;
    if (!spawn_capture(cmdline, 15000, code, captured))
    {
        sg().last_error = "camoufox_reverse_mcp not installed; run: pip install -e C:/Users/ruar1337/AiDAPrivate/camoufox-reverse-mcp";
        diag::log_tagged("camoufox", sg().last_error.c_str());
        return false;
    }
    if (code != 0)
    {
        sg().last_error = "camoufox_reverse_mcp not installed; run: pip install -e C:/Users/ruar1337/AiDAPrivate/camoufox-reverse-mcp";
        diag::log_tagged_fmt("camoufox", "module probe exit=%lu out=%.200s", code, captured.c_str());
        return false;
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
    j["block_images"] = cfg.block_images;
    j["block_webrtc"] = cfg.block_webrtc;
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
        diag::log_tagged_fmt("camoufox", "ensure_python_available cached path=%s", sg().cached_python_path.c_str());
        out_python_path = sg().cached_python_path;
        return true;
    }
    std::string found;
    if (try_search_path(L"python.exe", found)
        || try_search_path(L"py.exe", found)
        || try_search_path(L"python3.exe", found)
        || try_local_appdata_python(found))
    {
        diag::log_tagged_fmt("camoufox", "ensure_python_available found path=%s", found.c_str());
        sg().cached_python_path = found;
        out_python_path         = found;
        return true;
    }
    diag::log_tagged_fmt("camoufox", "ensure_python_available python_not_found");
    set_error_locked("python interpreter not found on PATH or in %LOCALAPPDATA%\\Programs\\Python");
    return false;
}

bool start_bridge(const launch_config_t& cfg)
{
    diag::log_tagged_fmt("camoufox", "start_bridge entry headless=%d module=%s",
        static_cast<int>(cfg.headless), cfg.server_module.c_str());
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);

    if (sg().state == bridge_state_t::ready && sg().client)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge already_ready reusing");
        sg().active_cfg = cfg;
        return true;
    }
    if (sg().state == bridge_state_t::starting)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge already_starting rejected");
        set_error_locked("camoufox bridge already starting");
        return false;
    }
    diag::log_tagged_fmt("camoufox", "start_bridge state->starting");

    sg().state          = bridge_state_t::starting;
    sg().last_error.clear();
    publish_state(bridge_state_t::starting, std::string());

    std::string python_path = cfg.python_executable;
    if (python_path.empty())
    {
        if (!ensure_python_available(python_path))
        {
            sg().state = bridge_state_t::error;
            publish_state(bridge_state_t::error, sg().last_error);
            return false;
        }
    }

    if (!probe_module_installed_locked(python_path))
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
    scfg.args.push_back(cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : cfg.server_module);
    for (const auto& a : cfg.extra_args) scfg.args.push_back(a);
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

    int wait_ms = cfg.launch_timeout_ms > 0 ? cfg.launch_timeout_ms : 60000;
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

    sg().server_command = python_path + " -m " + (cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : cfg.server_module);
    sg().launched_ms    = now_ms();
    sg().active_cfg     = cfg;

    nlohmann::json args = build_launch_args(cfg);
    mcp_client::call_result_t launch = sg().client->call_tool("launch_browser", args);
    if (!launch.success)
    {
        sg().last_error = std::string("launch_browser failed: ") + launch.text;
        diag::log_tagged("camoufox", sg().last_error.c_str());
        sg().client->disconnect();
        sg().client.reset();
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    nlohmann::json parsed;
    parse_text_to_json(launch.text, parsed);
    if (parsed.is_object() && parsed.contains("error") && parsed["error"].is_string())
    {
        sg().last_error = std::string("launch_browser returned error: ") + parsed["error"].get<std::string>();
        diag::log_tagged("camoufox", sg().last_error.c_str());
        sg().client->disconnect();
        sg().client.reset();
        sg().state = bridge_state_t::error;
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    sg().browser_open = true;
    sg().state        = bridge_state_t::ready;
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
    sg().state = bridge_state_t::stopped;
    sg().last_error.clear();
    publish_state(bridge_state_t::stopped, std::string());
    diag::log_tagged("camoufox", "bridge stopped");
    return true;
}

bool is_ready()
{
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    bool ready = sg().state == bridge_state_t::ready && sg().client != nullptr;
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
    if (st.state != install::install_state_t::ok &&
        st.state != install::install_state_t::available)
    {
        diag::log_tagged_fmt("camoufox", "ensure_ready install_not_ready state=%d", static_cast<int>(st.state));
        return false;
    }
    diag::log_tagged_fmt("camoufox", "ensure_ready starting_bridge python=%s", st.python_path.c_str());
    launch_config_t cfg;
    cfg.headless = true;
    cfg.python_executable = st.python_path;
    return start_bridge(cfg);
}

bridge_status_t get_status()
{
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    bridge_status_t s;
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
    diag::log_tagged_fmt("camoufox", "get_status state=%d browser_open=%d calls=%llu errors=%llu url=%s",
        static_cast<int>(s.state), static_cast<int>(s.browser_open),
        static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors), s.active_page_url.c_str());
    return s;
}

call_result_t call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms)
{
    diag::log_tagged_fmt("camoufox", "call_tool entry tool=%s timeout_ms=%d", tool_name.c_str(), timeout_ms);
    call_result_t r = call_with_deadline(tool_name, args.is_null() ? nlohmann::json::object() : args, timeout_ms);
    diag::log_tagged_fmt("camoufox", "call_tool result tool=%s ok=%d", tool_name.c_str(), static_cast<int>(r.ok));
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
    diag::log_tagged_fmt("camoufox", "navigate entry url=%s wait_until=%s timeout_ms=%d",
        url.c_str(), wait_until.c_str(), timeout_ms);
    if (url.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("navigate: url is empty");
        return false;
    }
    nlohmann::json a;
    a["url"]                  = url;
    a["wait_until"]           = wait_until.empty() ? std::string("load") : wait_until;
    a["collect_response_chain"] = true;
    a["clear_network_capture"]  = true;
    int call_timeout = timeout_ms > 0 ? timeout_ms + 5000 : 35000;
    call_result_t r = call_with_deadline("navigate", a, call_timeout);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "navigate failed url=%s err=%s", url.c_str(), r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("navigate failed: ") + r.error);
        return false;
    }
    if (r.data.is_object() && r.data.contains("url") && r.data["url"].is_string())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().active_page_url = r.data["url"].get<std::string>();
        diag::log_tagged_fmt("camoufox", "navigate ok final_url=%s", sg().active_page_url.c_str());
    } else {
        diag::log_tagged_fmt("camoufox", "navigate ok url=%s", url.c_str());
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
        diag::log_tagged_fmt("camoufox", "reload ok url=%s", sg().active_page_url.c_str());
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
    a["expression"]    = std::string("(function(){ try { ") + js + std::string(" } catch(e) { return { __aida_init_error: String(e) }; } return { __aida_init_ok: true }; })()");
    a["await_promise"] = false;
    call_result_t r = call_with_deadline("evaluate_js", a, 30000);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "add_init_script inline_failed err=%s", r.error.c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("add_init_script (evaluate_js) failed: ") + r.error);
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
        diag::log_tagged_fmt("camoufox", "get_page_info ok url=%s", sg().active_page_url.c_str());
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
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    std::string e = sg().last_error;
    diag::log_tagged_fmt("camoufox", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
