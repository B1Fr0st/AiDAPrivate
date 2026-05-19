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

void set_status_locked(install_state_t st, const std::string& msg)
{
    sg().status.state        = st;
    sg().status.last_message = msg;
    diag::log_tagged_fmt("camoufox_install", "[%s] %s", state_label(st), msg.c_str());
}

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
        status_t st = probe();
        if (st.state == install_state_t::missing_module)
        {
            std::string log;
            pip_install_module(log);
        }
        st = probe();
        if (st.state == install_state_t::missing_browser)
        {
            std::string log;
            fetch_browser(log);
        }
        probe();
        sg().busy.store(false);
    });
    return true;
}

void shutdown()
{
    bool expected = true;
    if (!sg().initialized.compare_exchange_strong(expected, false)) return;
}

status_t probe()
{
    std::lock_guard<std::mutex> lk(sg().mtx);
    set_status_locked(install_state_t::checking, "probing python environment");

    std::string python;
    if (!camoufox::ensure_python_available(python))
    {
        set_status_locked(install_state_t::missing_python, "python interpreter not found");
        sg().status.python_path.clear();
        sg().last_error = "python interpreter not found";
        return sg().status;
    }
    sg().status.python_path = python;

    std::string captured;
    DWORD exit_code = 0;
    std::string cmd = std::string("\"") + python + "\" -c \"import camoufox_reverse_mcp; "
                       "print(getattr(camoufox_reverse_mcp, '__version__', 'unknown'))\"";
    if (!spawn_capture_streaming(cmd, 20000, exit_code, captured))
    {
        set_status_locked(install_state_t::missing_module, "module probe spawn failed");
        sg().last_error = "module probe spawn failed";
        return sg().status;
    }
    if (exit_code != 0)
    {
        set_status_locked(install_state_t::missing_module, "camoufox_reverse_mcp not importable");
        sg().status.module_version.clear();
        sg().last_error = "camoufox_reverse_mcp not importable";
        return sg().status;
    }
    sg().status.module_version = trim_view(captured);

    std::string browser_log;
    DWORD browser_exit = 0;
    std::string browser_cmd = std::string("\"") + python + "\" -c \"from camoufox.pkgman import installed_verstr; "
                              "print(installed_verstr())\"";
    if (!spawn_capture_streaming(browser_cmd, 20000, browser_exit, browser_log))
    {
        set_status_locked(install_state_t::missing_browser, "browser probe spawn failed");
        sg().last_error = "browser probe spawn failed";
        return sg().status;
    }
    if (browser_exit != 0)
    {
        set_status_locked(install_state_t::missing_browser, "camoufox browser not installed (run python -m camoufox fetch)");
        sg().status.browser_path.clear();
        sg().last_error = "camoufox browser not installed";
        return sg().status;
    }
    sg().status.browser_path = trim_view(browser_log);

    set_status_locked(install_state_t::ok, "python + camoufox_reverse_mcp + camoufox browser ready");
    sg().last_error.clear();
    return sg().status;
}

bool pip_install_module(std::string& out_log)
{
    out_log.clear();
    std::lock_guard<std::mutex> lk(sg().mtx);

    std::string python;
    if (!camoufox::ensure_python_available(python))
    {
        sg().last_error = "python interpreter not found";
        set_status_locked(install_state_t::missing_python, sg().last_error);
        return false;
    }

    set_status_locked(install_state_t::installing, "running pip install -e camoufox-reverse-mcp");
    std::string cmd = std::string("\"") + python + "\" -m pip install --upgrade-strategy only-if-needed "
                       "-e C:/Users/ruar1337/AiDAPrivate/camoufox-reverse-mcp";
    DWORD code = 0;
    if (!spawn_capture_streaming(cmd, 600000, code, out_log))
    {
        sg().last_error = "pip install timed out or failed to spawn";
        set_status_locked(install_state_t::install_failed, sg().last_error);
        return false;
    }
    if (code != 0)
    {
        sg().last_error = "pip install exited with non-zero status";
        set_status_locked(install_state_t::install_failed, sg().last_error);
        return false;
    }
    set_status_locked(install_state_t::available, "pip install completed");
    sg().last_error.clear();
    return true;
}

bool fetch_browser(std::string& out_log)
{
    out_log.clear();
    std::lock_guard<std::mutex> lk(sg().mtx);

    std::string python;
    if (!camoufox::ensure_python_available(python))
    {
        sg().last_error = "python interpreter not found";
        set_status_locked(install_state_t::missing_python, sg().last_error);
        return false;
    }

    set_status_locked(install_state_t::installing, "running python -m camoufox fetch");
    std::string cmd = std::string("\"") + python + "\" -m camoufox fetch";
    DWORD code = 0;
    if (!spawn_capture_streaming(cmd, 600000, code, out_log))
    {
        sg().last_error = "camoufox fetch timed out or failed to spawn";
        set_status_locked(install_state_t::install_failed, sg().last_error);
        return false;
    }
    if (code != 0)
    {
        sg().last_error = "camoufox fetch exited with non-zero status";
        set_status_locked(install_state_t::install_failed, sg().last_error);
        return false;
    }
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
    return work_queue::post([]() {
        std::string log;
        pip_install_module(log);
        sg().busy.store(false, std::memory_order_release);
    });
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
    return work_queue::post([]() {
        std::string log;
        fetch_browser(log);
        sg().busy.store(false, std::memory_order_release);
    });
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
