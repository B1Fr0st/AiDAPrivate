#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>

#ifdef small
#undef small
#endif

#include "browser_launch.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace browser {

namespace {

struct tracked_pid_t
{
    uint32_t    pid = 0;
    std::string browser_path;
    std::string profile_path;
    uint16_t    proxy_port = 0;
    uint64_t    launched_ms = 0;
};

struct state_t
{
    std::mutex                  mtx;
    std::vector<tracked_pid_t>  tracked;
    std::atomic<bool>           initialized{false};
    std::mutex                  err_mtx;
    std::string                 last_err;
};

state_t& s()
{
    static state_t st;
    return st;
}

void set_err(const std::string& msg)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = msg;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string wide_to_utf8(const wchar_t* w)
{
    if (!w) return std::string();
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return std::string();
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring utf8_to_wide(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

bool file_exists(const std::string& p)
{
    if (p.empty()) return false;
    std::wstring wp = utf8_to_wide(p);
    DWORD attrs = GetFileAttributesW(wp.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool is_process_alive(uint32_t pid)
{
    if (pid == 0) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) return false;
    DWORD code = 0;
    bool alive = false;
    if (GetExitCodeProcess(h, &code))
        alive = (code == STILL_ACTIVE);
    CloseHandle(h);
    return alive;
}

std::string local_appdata_dir()
{
    PWSTR known = nullptr;
    std::string out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &known)) && known) {
        out = wide_to_utf8(known);
        CoTaskMemFree(known);
    }
    if (out.empty()) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("LOCALAPPDATA", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) out.assign(buf, len);
    }
    if (out.empty()) out = "C:\\Users\\Public";
    return out;
}

std::string program_files()
{
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("ProgramFiles", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) return std::string(buf, len);
    return "C:\\Program Files";
}

std::string program_files_x86()
{
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("ProgramFiles(x86)", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) return std::string(buf, len);
    return "C:\\Program Files (x86)";
}

std::string registry_string_hkcu(const char* subkey, const char* value)
{
    HKEY k = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &k) != ERROR_SUCCESS) return std::string();
    char buf[1024] = {};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    LONG rc = RegQueryValueExA(k, value, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS) return std::string();
    if (type != REG_SZ && type != REG_EXPAND_SZ) return std::string();
    if (sz > 0 && buf[sz - 1] == '\0') sz--;
    return std::string(buf, sz);
}

bool quote_path(const std::string& in, std::wstring& out)
{
    std::wstring w = utf8_to_wide(in);
    if (w.empty()) return false;
    out.clear();
    out.reserve(w.size() + 4);
    out.push_back(L'"');
    out.append(w);
    out.push_back(L'"');
    return true;
}

}

bool initialize()
{
    diag::log_tagged_fmt("browser", "initialize entry");
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("browser", "initialize already_initialized");
        return true;
    }
    diag::log_tagged("burp_browser", "initialized");
    diag::log_tagged_fmt("browser", "initialize done");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("browser", "shutdown entry");
    auto& st = s();
    if (!st.initialized.exchange(false)) {
        diag::log_tagged_fmt("browser", "shutdown not_initialized skipping");
        return;
    }
    std::lock_guard<std::mutex> lk(st.mtx);
    size_t n = st.tracked.size();
    st.tracked.clear();
    diag::log_tagged_fmt("browser", "shutdown done cleared_tracked=%zu", n);
}

bool detect_edge_path(std::string& out_path)
{
    diag::log_tagged_fmt("browser", "detect_edge_path entry");
    std::string candidates[4];
    candidates[0] = program_files_x86() + "\\Microsoft\\Edge\\Application\\msedge.exe";
    candidates[1] = program_files() + "\\Microsoft\\Edge\\Application\\msedge.exe";
    candidates[2] = local_appdata_dir() + "\\Microsoft\\Edge\\Application\\msedge.exe";
    candidates[3] = registry_string_hkcu("SOFTWARE\\Microsoft\\Edge\\BLBeacon", "InstallLocation");
    for (auto& p : candidates) {
        if (!p.empty() && file_exists(p)) {
            diag::log_tagged_fmt("browser", "detect_edge_path found path=%s", p.c_str());
            out_path = p;
            return true;
        }
    }
    HKEY k = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
                      0, KEY_READ, &k) == ERROR_SUCCESS) {
        char buf[1024] = {};
        DWORD sz = sizeof(buf);
        DWORD type = 0;
        LONG rc = RegQueryValueExA(k, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
        RegCloseKey(k);
        if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            if (sz > 0 && buf[sz - 1] == '\0') sz--;
            std::string p(buf, sz);
            if (file_exists(p)) {
                diag::log_tagged_fmt("browser", "detect_edge_path found_via_registry path=%s", p.c_str());
                out_path = p;
                return true;
            }
        }
    }
    diag::log_tagged_fmt("browser", "detect_edge_path not_found");
    set_err("edge_not_detected");
    return false;
}

bool detect_chrome_path(std::string& out_path)
{
    diag::log_tagged_fmt("browser", "detect_chrome_path entry");
    std::string candidates[3];
    candidates[0] = program_files() + "\\Google\\Chrome\\Application\\chrome.exe";
    candidates[1] = program_files_x86() + "\\Google\\Chrome\\Application\\chrome.exe";
    candidates[2] = local_appdata_dir() + "\\Google\\Chrome\\Application\\chrome.exe";
    for (auto& p : candidates) {
        if (!p.empty() && file_exists(p)) {
            diag::log_tagged_fmt("browser", "detect_chrome_path found path=%s", p.c_str());
            out_path = p;
            return true;
        }
    }
    HKEY k = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe",
                      0, KEY_READ, &k) == ERROR_SUCCESS) {
        char buf[1024] = {};
        DWORD sz = sizeof(buf);
        DWORD type = 0;
        LONG rc = RegQueryValueExA(k, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
        RegCloseKey(k);
        if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            if (sz > 0 && buf[sz - 1] == '\0') sz--;
            std::string p(buf, sz);
            if (file_exists(p)) {
                diag::log_tagged_fmt("browser", "detect_chrome_path found_via_registry path=%s", p.c_str());
                out_path = p;
                return true;
            }
        }
    }
    diag::log_tagged_fmt("browser", "detect_chrome_path not_found");
    set_err("chrome_not_detected");
    return false;
}

std::string profile_root()
{
    std::string base = local_appdata_dir();
    base += "\\AiDA";
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    diag::log_tagged_fmt("browser", "profile_root result=%s", base.c_str());
    return base;
}

std::string compute_profile_path(const std::string& subdir)
{
    std::string sd = subdir.empty() ? std::string("BurpBrowser") : subdir;
    diag::log_tagged_fmt("browser", "compute_profile_path entry subdir=%s", sd.c_str());
    std::string base = profile_root();
    base += "\\";
    for (char c : sd) {
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' ||
            c == '<' || c == '>' || c == '|') {
            base.push_back('_');
        } else {
            base.push_back(c);
        }
    }
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    diag::log_tagged_fmt("browser", "compute_profile_path result=%s", base.c_str());
    return base;
}

namespace {

void remove_directory_recursive(const std::string& path)
{
    if (path.empty()) return;
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

std::wstring build_command_line(const std::string& browser_path,
                                const browser_launch_config_t& cfg,
                                const std::string& profile_path)
{
    std::wstring cmd;
    std::wstring quoted;
    if (!quote_path(browser_path, quoted)) return std::wstring();
    cmd.append(quoted);

    char proxy_arg[256];
    _snprintf_s(proxy_arg, sizeof(proxy_arg), _TRUNCATE,
                " --proxy-server=%s:%u", cfg.proxy_host.c_str(),
                static_cast<unsigned>(cfg.proxy_port));
    cmd.append(utf8_to_wide(proxy_arg));

    std::wstring quoted_profile;
    if (quote_path(std::string("--user-data-dir=") + profile_path, quoted_profile)) {
        cmd.push_back(L' ');
        cmd.append(quoted_profile);
    }

    cmd.append(L" --no-first-run");
    cmd.append(L" --no-default-browser-check");
    cmd.append(L" --disable-features=msEdgeUserDataIntegrity");
    cmd.append(L" --disable-sync");
    cmd.append(L" --proxy-bypass-list=<-loopback>");
    cmd.append(L" --disable-features=ChromeWhatsNewUI,MSAccountAuthMenu");

    if (cfg.ignore_cert_errors) {
        cmd.append(L" --ignore-certificate-errors");
        cmd.append(L" --test-type");
    }

    if (!cfg.initial_url.empty()) {
        std::wstring qurl;
        if (quote_path(cfg.initial_url, qurl)) {
            cmd.push_back(L' ');
            cmd.append(qurl);
        }
    } else {
        cmd.append(L" about:blank");
    }

    return cmd;
}

}

bool launch(const browser_launch_config_t& cfg, uint32_t& out_pid)
{
    diag::log_tagged_fmt("browser", "launch entry prefer_chrome=%d proxy=%s:%u url=%s ignore_cert=%d",
        static_cast<int>(cfg.prefer_chrome), cfg.proxy_host.c_str(),
        static_cast<unsigned>(cfg.proxy_port), cfg.initial_url.c_str(),
        static_cast<int>(cfg.ignore_cert_errors));
    out_pid = 0;
    auto& st = s();
    if (!st.initialized.load()) initialize();

    std::string browser_path;
    if (cfg.prefer_chrome) {
        diag::log_tagged_fmt("browser", "launch prefer_chrome=true trying_chrome_first");
        if (!detect_chrome_path(browser_path)) {
            diag::log_tagged_fmt("browser", "launch chrome_not_found trying_edge");
            if (!detect_edge_path(browser_path)) {
                diag::log_tagged_fmt("browser", "launch no_chromium_browser_detected");
                set_err("no_chromium_browser_detected");
                return false;
            }
        }
    } else {
        diag::log_tagged_fmt("browser", "launch prefer_edge=true trying_edge_first");
        if (!detect_edge_path(browser_path)) {
            diag::log_tagged_fmt("browser", "launch edge_not_found trying_chrome");
            if (!detect_chrome_path(browser_path)) {
                diag::log_tagged_fmt("browser", "launch no_chromium_browser_detected");
                set_err("no_chromium_browser_detected");
                return false;
            }
        }
    }
    diag::log_tagged_fmt("browser", "launch browser_path=%s", browser_path.c_str());

    std::string profile_path = compute_profile_path(cfg.profile_subdir);
    if (cfg.clear_profile_first) {
        diag::log_tagged_fmt("browser", "launch clearing_profile profile=%s", profile_path.c_str());
        remove_directory_recursive(profile_path);
        std::error_code ec;
        std::filesystem::create_directories(profile_path, ec);
    }

    std::wstring cmdline = build_command_line(browser_path, cfg, profile_path);
    if (cmdline.empty()) {
        diag::log_tagged_fmt("browser", "launch build_cmdline_failed");
        set_err("build_cmdline_failed");
        return false;
    }
    diag::log_tagged_fmt("browser", "launch cmdline_built launching process");

    std::vector<wchar_t> cmd_mutable(cmdline.begin(), cmdline.end());
    cmd_mutable.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    PROCESS_INFORMATION pi{};
    DWORD flags = CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT;
    BOOL ok = CreateProcessW(nullptr,
                             cmd_mutable.data(),
                             nullptr,
                             nullptr,
                             FALSE,
                             flags,
                             nullptr,
                             nullptr,
                             &si,
                             &pi);
    if (!ok) {
        DWORD err = GetLastError();
        char msg[128];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "createprocess_failed code=%lu", err);
        diag::log_tagged_fmt("browser", "launch createprocess_failed code=%lu", err);
        set_err(msg);
        return false;
    }

    out_pid = static_cast<uint32_t>(pi.dwProcessId);
    diag::log_tagged_fmt("browser", "launch createprocess_ok pid=%u", out_pid);

    tracked_pid_t rec;
    rec.pid = out_pid;
    rec.browser_path = browser_path;
    rec.profile_path = profile_path;
    rec.proxy_port = cfg.proxy_port;
    rec.launched_ms = now_ms();

    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.tracked.push_back(rec);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    diag::log_tagged("burp_browser", "launched");
    diag::log_tagged_fmt("browser", "launch ok pid=%u browser=%s", out_pid, browser_path.c_str());
    return true;
}

bool kill(uint32_t pid)
{
    diag::log_tagged_fmt("browser", "kill entry pid=%u", pid);
    if (pid == 0) {
        diag::log_tagged_fmt("browser", "kill pid_zero rejected");
        return false;
    }
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (!h) {
        diag::log_tagged_fmt("browser", "kill open_process_failed pid=%u", pid);
        set_err("kill_open_failed");
        return false;
    }
    BOOL ok = TerminateProcess(h, 0);
    if (ok) WaitForSingleObject(h, 2000);
    CloseHandle(h);
    diag::log_tagged_fmt("browser", "kill terminate_result=%d pid=%u", static_cast<int>(ok != 0), pid);

    auto& st = s();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.tracked.erase(std::remove_if(st.tracked.begin(), st.tracked.end(),
                                        [pid](const tracked_pid_t& r) { return r.pid == pid; }),
                        st.tracked.end());
    }
    return ok != 0;
}

bool kill_all()
{
    diag::log_tagged_fmt("browser", "kill_all entry");
    auto& st = s();
    std::vector<uint32_t> pids;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        pids.reserve(st.tracked.size());
        for (const auto& r : st.tracked) pids.push_back(r.pid);
    }
    diag::log_tagged_fmt("browser", "kill_all killing count=%zu", pids.size());
    bool all_ok = true;
    for (uint32_t pid : pids) {
        if (!kill(pid)) all_ok = false;
    }
    diag::log_tagged_fmt("browser", "kill_all done all_ok=%d", static_cast<int>(all_ok));
    return all_ok;
}

void register_browser_pid(uint32_t pid)
{
    diag::log_tagged_fmt("browser", "register_browser_pid entry pid=%u", pid);
    if (pid == 0) {
        diag::log_tagged_fmt("browser", "register_browser_pid pid_zero rejected");
        return;
    }
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& r : st.tracked) {
        if (r.pid == pid) {
            diag::log_tagged_fmt("browser", "register_browser_pid already_tracked pid=%u", pid);
            return;
        }
    }
    tracked_pid_t rec;
    rec.pid = pid;
    rec.launched_ms = now_ms();
    st.tracked.push_back(rec);
    diag::log_tagged_fmt("browser", "register_browser_pid registered pid=%u total=%zu", pid, st.tracked.size());
}

std::vector<browser_status_t> list_running()
{
    diag::log_tagged_fmt("browser", "list_running entry");
    auto& st = s();
    std::vector<tracked_pid_t> snapshot;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        snapshot = st.tracked;
    }
    std::vector<browser_status_t> out;
    out.reserve(snapshot.size());
    std::vector<uint32_t> to_remove;
    for (const auto& r : snapshot) {
        browser_status_t s;
        s.pid = r.pid;
        s.browser_path = r.browser_path;
        s.profile_path = r.profile_path;
        s.proxy_port = r.proxy_port;
        s.launched_ms = r.launched_ms;
        s.running = is_process_alive(r.pid);
        if (!s.running) {
            diag::log_tagged_fmt("browser", "list_running dead_process pid=%u removing", r.pid);
            to_remove.push_back(r.pid);
        } else {
            diag::log_tagged_fmt("browser", "list_running alive pid=%u", r.pid);
        }
        out.push_back(s);
    }
    if (!to_remove.empty()) {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.tracked.erase(std::remove_if(st.tracked.begin(), st.tracked.end(),
                                        [&to_remove](const tracked_pid_t& r) {
                                            for (uint32_t p : to_remove) if (p == r.pid) return true;
                                            return false;
                                        }),
                         st.tracked.end());
    }
    diag::log_tagged_fmt("browser", "list_running result count=%zu dead_removed=%zu",
        out.size(), to_remove.size());
    return out;
}

std::string last_error()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    diag::log_tagged_fmt("browser", "last_error queried val=%s", st.last_err.c_str());
    return st.last_err;
}

}
}
}
