#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "camoufox_install.hpp"
#include "camoufox_bridge.hpp"

#include "../../infra/work_queue.hpp"
#include "../../../helpers/diag_log.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace aida {
namespace burp {
namespace camoufox {
namespace install {

namespace {

struct singleton_t
{
    std::mutex          mtx;
    status_t            status;
    std::string         last_error;
    std::atomic<bool>   busy{false};
    std::atomic<bool>   probing{false};
    std::atomic<bool>   initialized{false};
};

inline singleton_t& sg()
{
    static singleton_t s;
    return s;
}

const char* state_label(install_state_t s)
{
    switch (s)
    {
        case install_state_t::unknown:         return "unknown";
        case install_state_t::checking:        return "checking";
        case install_state_t::available:       return "available";
        case install_state_t::missing_python:  return "missing_python";
        case install_state_t::missing_module:  return "missing_module";
        case install_state_t::missing_browser: return "missing_browser";
        case install_state_t::installing:      return "installing";
        case install_state_t::install_failed:  return "install_failed";
        case install_state_t::ok:              return "ok";
    }
    return "unknown";
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

std::string quote_arg(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s)
    {
        if (c == '"') out += "\\\"";
        else out.push_back(c);
    }
    out.push_back('"');
    return out;
}

bool find_executable(const wchar_t* exe_name, std::string& out_path)
{
    wchar_t buffer[MAX_PATH * 2] = {};
    DWORD got = SearchPathW(nullptr, exe_name, nullptr, static_cast<DWORD>(sizeof(buffer) / sizeof(wchar_t)), buffer, nullptr);
    if (got == 0 || got >= sizeof(buffer) / sizeof(wchar_t)) return false;
    out_path = wide_to_utf8(buffer);
    return !out_path.empty();
}

bool spawn_capture_streaming(const std::string& cmdline, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_log)
{
    out_exit_code = 0;

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
                out_log.append(buf, buf + got);
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
        out_log.append(buf, buf + got);
    }
    GetExitCodeProcess(pi.hProcess, &out_exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return true;
}

std::string trim_view(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

std::string compact_log(std::string s, size_t limit = 1200)
{
    s = trim_view(s);
    for (char& c : s) {
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    if (s.size() > limit) {
        s.resize(limit);
        s += "...";
    }
    return s;
}

void set_status_locked(install_state_t st, const std::string& msg);

bool run_install_command(const std::string& python,
                         const char* status_msg,
                         const std::string& uv_args,
                         const std::string& pip_args,
                         const char* fail_msg,
                         std::string& out_log)
{
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::installing, status_msg ? status_msg : "installing camoufox dependencies");
    }

    DWORD code = 0;
    std::string uv_path;
    if (find_executable(L"uv.exe", uv_path))
    {
        std::string uv_log;
        std::string cmd = quote_arg(uv_path) + " pip install --python " + quote_arg(python) + " " + uv_args;
        if (spawn_capture_streaming(cmd, 600000, code, uv_log) && code == 0)
        {
            out_log += uv_log;
            return true;
        }
        out_log += uv_log;
        std::string detail = compact_log(uv_log);
        diag::log_tagged_fmt("camoufox_install", "uv install failed code=%lu out=%.400s", code, detail.c_str());
    }

    code = 0;
    std::string pip_log;
    std::string cmd = quote_arg(python) + " -m pip install " + pip_args;
    if (spawn_capture_streaming(cmd, 600000, code, pip_log) && code == 0)
    {
        out_log += pip_log;
        return true;
    }
    out_log += pip_log;
    std::string detail = compact_log(out_log);
    std::lock_guard<std::mutex> lk(sg().mtx);
    sg().last_error = detail.empty()
        ? (fail_msg ? fail_msg : "camoufox dependency install failed")
        : std::string(fail_msg ? fail_msg : "camoufox dependency install failed") + ": " + detail;
    set_status_locked(install_state_t::install_failed, sg().last_error);
    return false;
}

status_t snapshot_status(const char* fallback_message = nullptr)
{
    std::lock_guard<std::mutex> lk(sg().mtx);
    status_t st = sg().status;
    if (fallback_message && st.last_message.empty()) st.last_message = fallback_message;
    return st;
}

void set_status_locked(install_state_t st, const std::string& msg)
{
    sg().status.state        = st;
    sg().status.last_message = msg;
    diag::log_tagged_fmt("camoufox_install", "[%s] %s", state_label(st), msg.c_str());
}

struct probe_guard_t
{
    bool active = true;
    ~probe_guard_t()
    {
        if (active) sg().probing.store(false, std::memory_order_release);
    }
};

constexpr DWORD kInteractiveProbeTimeoutMs = 1500;
constexpr DWORD kBackgroundProbeTimeoutMs = 1500;

status_t probe_impl(bool allow_when_busy, DWORD timeout_ms);

}

bool initialize()
{
    bool expected = false;
    if (!sg().initialized.compare_exchange_strong(expected, true)) return true;
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.state = install_state_t::unknown;
    }
    work_queue::post([]() {
        if (sg().busy.exchange(true)) return;
        try {
            probe_impl(true, kBackgroundProbeTimeoutMs);
        } catch (...) {
            std::lock_guard<std::mutex> lk(sg().mtx);
            sg().last_error = "camoufox startup probe failed";
            set_status_locked(install_state_t::install_failed, sg().last_error);
        }
        sg().busy.store(false, std::memory_order_release);
    });
    return true;
}

void shutdown()
{
    bool expected = true;
    if (!sg().initialized.compare_exchange_strong(expected, false)) return;
}

namespace {

status_t probe_impl(bool allow_when_busy, DWORD timeout_ms)
{
    if (!allow_when_busy && sg().busy.load(std::memory_order_acquire))
        return snapshot_status("camoufox install task already running");

    bool expected = false;
    if (!sg().probing.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return snapshot_status("camoufox probe already running");
    probe_guard_t probe_guard;

    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::checking, "probing python environment");
    }

    std::string python;
    if (!camoufox::ensure_python_available(python))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_python, "python interpreter not found");
        sg().status.python_path.clear();
        sg().last_error = "python interpreter not found";
        return sg().status;
    }
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.python_path = python;
    }

    std::string captured;
    DWORD exit_code = 0;
    std::string cmd = std::string("\"") + python + "\" -c \"import camoufox_reverse_mcp; "
                       "print(getattr(camoufox_reverse_mcp, '__version__', 'unknown'))\"";
    if (!spawn_capture_streaming(cmd, timeout_ms, exit_code, captured))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_module, "module probe spawn failed");
        sg().last_error = "module probe spawn failed";
        return sg().status;
    }
    if (exit_code != 0)
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_module, "camoufox_reverse_mcp not importable");
        sg().status.module_version.clear();
        sg().last_error = "camoufox_reverse_mcp not importable";
        return sg().status;
    }
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.module_version = trim_view(captured);
    }

    std::string runtime_log;
    DWORD runtime_exit = 0;
    std::string runtime_cmd = std::string("\"") + python + "\" -c \"import camoufox; print('ok')\"";
    if (!spawn_capture_streaming(runtime_cmd, timeout_ms, runtime_exit, runtime_log))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_module, "camoufox runtime import probe spawn failed");
        sg().last_error = "camoufox runtime import probe spawn failed";
        return sg().status;
    }
    if (runtime_exit != 0)
    {
        std::string detail = compact_log(runtime_log);
        if (detail.empty()) detail = "exit=" + std::to_string(runtime_exit);
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = std::string("camoufox runtime import failed: ") + detail;
        sg().status.browser_path.clear();
        set_status_locked(install_state_t::missing_module, sg().last_error);
        return sg().status;
    }

    std::string browser_log;
    DWORD browser_exit = 0;
    std::string browser_cmd = std::string("\"") + python + "\" -c \"from camoufox.pkgman import installed_verstr; "
                              "print(installed_verstr())\"";
    if (!spawn_capture_streaming(browser_cmd, timeout_ms, browser_exit, browser_log))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_browser, "browser probe spawn failed");
        sg().last_error = "browser probe spawn failed";
        return sg().status;
    }
    if (browser_exit != 0)
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_browser, "camoufox browser not installed (run python -m camoufox fetch)");
        sg().status.browser_path.clear();
        sg().last_error = "camoufox browser not installed";
        return sg().status;
    }
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.browser_path = trim_view(browser_log);

        set_status_locked(install_state_t::ok, "python + camoufox_reverse_mcp + camoufox browser ready");
        sg().last_error.clear();
        return sg().status;
    }
}

}

status_t probe()
{
    return probe_impl(false, kInteractiveProbeTimeoutMs);
}

bool ensure_ready(std::string& out_log)
{
    out_log.clear();

    status_t st = probe_impl(true, 5000);
    if (st.state == install_state_t::missing_python)
        return false;

    if (st.state == install_state_t::missing_module)
    {
        bool ok = false;
        if (st.last_message.find("camoufox runtime import") != std::string::npos)
            ok = repair_runtime_dependencies(out_log);
        else
            ok = pip_install_module(out_log);
        if (!ok) return false;
        st = probe_impl(true, 5000);
        if (st.state == install_state_t::missing_module &&
            st.last_message.find("camoufox runtime import") != std::string::npos)
        {
            if (!repair_runtime_dependencies(out_log)) return false;
            st = probe_impl(true, 5000);
        }
    }

    if (st.state == install_state_t::missing_browser ||
        st.state == install_state_t::available)
    {
        if (!fetch_browser(out_log)) return false;
        st = probe_impl(true, 5000);
    }

    if (st.state == install_state_t::ok)
        return true;

    std::lock_guard<std::mutex> lk(sg().mtx);
    sg().last_error = st.last_message.empty() ? "camoufox automatic setup did not reach ready state" : st.last_message;
    set_status_locked(install_state_t::install_failed, sg().last_error);
    return false;
}

bool pip_install_module(std::string& out_log)
{
    out_log.clear();

    std::string python;
    if (!camoufox::ensure_python_available(python))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "python interpreter not found";
        set_status_locked(install_state_t::missing_python, sg().last_error);
        return false;
    }

    if (!run_install_command(python,
        "installing camoufox-reverse-mcp",
        "-e C:/Users/ruar1337/AiDAPrivate/camoufox-reverse-mcp",
        "--upgrade-strategy only-if-needed -e C:/Users/ruar1337/AiDAPrivate/camoufox-reverse-mcp",
        "camoufox-reverse-mcp install failed",
        out_log))
        return false;
    std::lock_guard<std::mutex> lk(sg().mtx);
    set_status_locked(install_state_t::available, "pip install completed");
    sg().last_error.clear();
    return true;
}

bool repair_runtime_dependencies(std::string& out_log)
{
    out_log.clear();

    std::string python;
    if (!camoufox::ensure_python_available(python))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "python interpreter not found";
        set_status_locked(install_state_t::missing_python, sg().last_error);
        return false;
    }

    if (!run_install_command(python,
        "repairing camoufox runtime dependencies",
        "--reinstall --no-cache ua-parser ua-parser-builtins \"camoufox[geoip]>=0.4.0\"",
        "--upgrade --force-reinstall --no-cache-dir ua-parser ua-parser-builtins \"camoufox[geoip]>=0.4.0\"",
        "camoufox dependency repair failed",
        out_log))
        return false;
    std::lock_guard<std::mutex> lk(sg().mtx);
    set_status_locked(install_state_t::available, "camoufox runtime dependencies repaired");
    sg().last_error.clear();
    return true;
}

bool fetch_browser(std::string& out_log)
{
    out_log.clear();

    std::string python;
    if (!camoufox::ensure_python_available(python))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "python interpreter not found";
        set_status_locked(install_state_t::missing_python, sg().last_error);
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::installing, "running python -m camoufox fetch");
    }
    std::string cmd = std::string("\"") + python + "\" -m camoufox fetch";
    DWORD code = 0;
    if (!spawn_capture_streaming(cmd, 600000, code, out_log))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "camoufox fetch timed out or failed to spawn";
        set_status_locked(install_state_t::install_failed, sg().last_error);
        return false;
    }
    if (code != 0)
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "camoufox fetch exited with non-zero status";
        set_status_locked(install_state_t::install_failed, sg().last_error);
        return false;
    }
    std::lock_guard<std::mutex> lk(sg().mtx);
    set_status_locked(install_state_t::available, "camoufox browser fetched");
    sg().last_error.clear();
    return true;
}

bool pip_install_async()
{
    bool expected = false;
    if (!sg().busy.compare_exchange_strong(expected, true))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "install task already running";
        return false;
    }
    bool posted = work_queue::post([]() {
        std::string log;
        try { pip_install_module(log); } catch (...) {}
        sg().busy.store(false, std::memory_order_release);
    });
    if (!posted) sg().busy.store(false, std::memory_order_release);
    return posted;
}

bool repair_runtime_dependencies_async()
{
    bool expected = false;
    if (!sg().busy.compare_exchange_strong(expected, true))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "install task already running";
        return false;
    }
    bool posted = work_queue::post([]() {
        std::string log;
        try { repair_runtime_dependencies(log); } catch (...) {}
        sg().busy.store(false, std::memory_order_release);
    });
    if (!posted) sg().busy.store(false, std::memory_order_release);
    return posted;
}

bool fetch_browser_async()
{
    bool expected = false;
    if (!sg().busy.compare_exchange_strong(expected, true))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "install task already running";
        return false;
    }
    bool posted = work_queue::post([]() {
        std::string log;
        try { fetch_browser(log); } catch (...) {}
        sg().busy.store(false, std::memory_order_release);
    });
    if (!posted) sg().busy.store(false, std::memory_order_release);
    return posted;
}

status_t get_status()
{
    std::lock_guard<std::mutex> lk(sg().mtx);
    return sg().status;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(sg().mtx);
    return sg().last_error;
}

}
}
}
}
