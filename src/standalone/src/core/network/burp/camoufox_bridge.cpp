#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "camoufox_bridge.hpp"
#include "camoufox_install.hpp"

#include "../../infra/event_bus.hpp"
#include "../../infra/win_thread.hpp"
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
#include <cwctype>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace camoufox {

namespace {

struct singleton_t
{
    std::recursive_mutex                    mtx;
    std::recursive_mutex                    operation_mtx;
    std::shared_ptr<mcp_client::client_t>   client;
    bridge_state_t                          state              = bridge_state_t::stopped;
    std::string                             last_error;
    std::string                             server_command;
    uint32_t                                child_pid          = 0;
    uint64_t                                launched_ms        = 0;
    uint64_t                                last_call_ms       = 0;
    std::atomic<uint64_t>                   total_calls{0};
    std::atomic<uint64_t>                   total_errors{0};
    std::atomic<uint64_t>                   next_request_id{1};
    bool                                    browser_open       = false;
    std::string                             active_page_url;
    std::string                             active_page_title;
    bool                                    page_verified      = false;
    bool                                    cleanup_pending    = false;
    uint64_t                                generation         = 0;
    uint64_t                                cleanup_generation = 0;
    uint64_t                                last_launch_ms     = 0;
    uint64_t                                last_nav_ms        = 0;
    uint64_t                                last_cleanup_ms    = 0;
    uint64_t                                last_verified_ms   = 0;
    std::atomic<bool>                       stop_requested{false};
    std::atomic<uint64_t>                   stop_epoch{0};
    std::string                             cached_python_path;
    launch_config_t                         active_cfg;
    std::vector<std::shared_ptr<mcp_client::client_t>> poisoned_clients;
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

uint64_t next_request_id()
{
    return sg().next_request_id.fetch_add(1, std::memory_order_relaxed);
}

constexpr int kToolListWaitMaxMs = 5000;
constexpr int kLaunchWaitMinMs = 5000;
constexpr int kLaunchWaitMaxMs = 120000;
constexpr int kBundledVisibleLaunchWaitMinMs = 70000;
constexpr int kReadinessProbeTimeoutMs = 10000;
constexpr int kNavigationWaitMaxMs = 50000;

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

bool find_bundled_camoufox_executable(std::string& out_path)
{
    const std::wstring name = L"camoufox-135.0.1-beta.24-win.x86_64";
    const auto bases = runtime_base_dirs();
    for (const auto& base : bases)
    {
        std::wstring candidate = join_path_w(join_path_w(join_path_w(base, L"deps"), name), L"camoufox.exe");
        if (path_exists_w(candidate))
        {
            out_path = wide_to_utf8(candidate);
            diag::log_tagged_fmt("camoufox", "bundled_browser_executable selected path=%s base=%s",
                out_path.c_str(), wide_to_utf8(base).c_str());
            return !out_path.empty();
        }
        candidate = join_path_w(join_path_w(base, name), L"camoufox.exe");
        if (path_exists_w(candidate))
        {
            out_path = wide_to_utf8(candidate);
            diag::log_tagged_fmt("camoufox", "bundled_browser_executable selected path=%s base=%s",
                out_path.c_str(), wide_to_utf8(base).c_str());
            return !out_path.empty();
        }
    }
    diag::log_tagged_fmt("camoufox", "bundled_browser_executable missing base_count=%zu", bases.size());
    return false;
}

std::wstring local_appdata_aida_root()
{
    wchar_t root[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return {};
    return join_path_w(root, L"AiDA");
}

void append_bundled_python_candidates(std::vector<std::string>& candidates)
{
    std::vector<std::wstring> rels = {
        L"camoufox-runtime\\python.exe",
        L"camoufox-runtime\\Python312\\python.exe",
        L"camoufox-runtime\\Python312-3.12.10-x64\\python.exe",
        L"camoufox-python\\python.exe",
        L"python-3.12.10-x64\\python.exe",
        L"python\\python.exe",
        L"python-3.12\\python.exe",
        L"Python312\\python.exe",
        L"Python312-3.12.10-x64\\python.exe",
        L"runtime\\python\\python.exe",
        L"runtime\\python\\Python312-3.12.10-x64\\python.exe",
        L"runtimes\\python\\Python312-3.12.10-x64\\python.exe",
        L"deps\\camoufox-runtime\\python.exe",
        L"deps\\camoufox-runtime\\Python312\\python.exe",
        L"deps\\camoufox-runtime\\Python312-3.12.10-x64\\python.exe",
        L"deps\\camoufox-python\\python.exe",
        L"deps\\python-3.12.10-x64\\python.exe",
        L"deps\\python\\python.exe",
        L"deps\\python-3.12\\python.exe",
        L"deps\\Python312\\python.exe",
        L"deps\\Python312-3.12.10-x64\\python.exe",
        L"deps\\runtime\\python\\python.exe",
        L"deps\\runtime\\python\\Python312-3.12.10-x64\\python.exe",
        L"deps\\runtimes\\python\\Python312-3.12.10-x64\\python.exe"
    };
    const auto bases = runtime_base_dirs();
    size_t found_count = 0;
    for (const auto& base : bases)
    {
        for (const auto& rel : rels)
        {
            std::wstring candidate = join_path_w(base, rel);
            if (path_exists_w(candidate))
            {
                candidates.push_back(wide_to_utf8(candidate));
                ++found_count;
                diag::log_tagged_fmt("camoufox", "bundled_python_candidate found path=%s base=%s rel=%s",
                    candidates.back().c_str(), wide_to_utf8(base).c_str(), wide_to_utf8(rel).c_str());
            }
        }
    }
    diag::log_tagged_fmt("camoufox", "bundled_python_candidate scan complete base_count=%zu rel_count=%zu found=%zu",
        bases.size(), rels.size(), found_count);
}

void append_app_local_python_candidates(std::vector<std::string>& candidates)
{
    std::wstring root = local_appdata_aida_root();
    if (root.empty()) return;
    std::wstring exact = join_path_w(join_path_w(join_path_w(join_path_w(root, L"runtimes"), L"python"), L"Python312-3.12.10-x64"), L"python.exe");
    if (path_exists_w(exact)) candidates.push_back(wide_to_utf8(exact));
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
    std::wstring aida_root = local_appdata_aida_root();
    if (!aida_root.empty() && try_python_directory(join_path_w(join_path_w(aida_root, L"runtimes"), L"python"), out_path)) return true;
    if (try_env_python_root(L"ProgramFiles", L"", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles", L"\\Python", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles(x86)", L"", out_path)) return true;
    if (try_env_python_root(L"ProgramFiles(x86)", L"\\Python", out_path)) return true;
    if (try_env_python_root(L"LOCALAPPDATA", L"\\Programs\\Python", out_path)) return true;
    return false;
}

bool is_windows_store_python_alias(const std::string& path)
{
    std::wstring w = utf8_to_wide(path);
    if (w.empty()) return false;
    for (wchar_t& c : w) if (c == L'/') c = L'\\';
    std::wstring lower = w;
    std::wstring needle = L"\\microsoft\\windowsapps\\";
    for (wchar_t& c : lower) c = static_cast<wchar_t>(std::towlower(c));
    return lower.find(needle) != std::wstring::npos;
}

std::string compact_child_output_tail(std::string s, size_t limit);

bool spawn_capture(const std::string& cmdline, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout)
{
    out_exit_code = 0;
    out_stdout.clear();

    SECURITY_ATTRIBUTES sa{};
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0))
    {
        const DWORD gle = GetLastError();
        out_stdout = "spawn pipe create failed gle=" + std::to_string(gle);
        diag::log_tagged_fmt("camoufox", "spawn_capture pipe_create_failed gle=%lu cmd_len=%zu timeout_ms=%lu",
            gle, cmdline.size(), static_cast<unsigned long>(timeout_ms));
        return false;
    }
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
        out_stdout = "spawn create failed gle=" + std::to_string(gle);
        diag::log_tagged_fmt("camoufox", "spawn_capture create_failed gle=%lu cmd_len=%zu timeout_ms=%lu",
            gle, cmdline.size(), static_cast<unsigned long>(timeout_ms));
        CloseHandle(rd);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "spawn_capture process_started pid=%lu cmd_len=%zu timeout_ms=%lu",
        static_cast<unsigned long>(pi.dwProcessId), cmdline.size(), static_cast<unsigned long>(timeout_ms));
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
            std::string tail = compact_child_output_tail(out_stdout, 600);
            out_stdout += " spawn timeout elapsed_ms=" + std::to_string(elapsed) + " output_tail=" + tail;
            diag::log_tagged_fmt("camoufox", "spawn_capture timeout pid=%lu elapsed_ms=%lu cmd_len=%zu captured_len=%zu tail=%.600s",
                static_cast<unsigned long>(pi.dwProcessId),
                static_cast<unsigned long>(elapsed), cmdline.size(), out_stdout.size(), tail.c_str());
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
    diag::log_tagged_fmt("camoufox", "spawn_capture exit pid=%lu code=%lu cmd_len=%zu captured_len=%zu tail=%.600s",
        static_cast<unsigned long>(pi.dwProcessId), out_exit_code, cmdline.size(), out_stdout.size(),
        compact_child_output_tail(out_stdout, 600).c_str());
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

std::string compact_child_output_tail(std::string s, size_t limit = 1600)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    s = s.substr(a, b - a);
    for (char& c : s) {
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    if (s.size() > limit) {
        s = s.substr(s.size() - limit);
        s.insert(0, "...");
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

bool process_alive(uint32_t pid)
{
    if (pid == 0) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (!h)
    {
        diag::log_tagged_fmt("camoufox", "process_alive open_failed pid=%lu gle=%lu",
            static_cast<unsigned long>(pid), static_cast<unsigned long>(GetLastError()));
        return false;
    }
    DWORD exit_code = 0;
    BOOL ok = GetExitCodeProcess(h, &exit_code);
    DWORD gle = ok ? 0 : GetLastError();
    CloseHandle(h);
    const bool alive = ok && exit_code == STILL_ACTIVE;
    diag::log_tagged_fmt("camoufox", "process_alive pid=%lu alive=%d gle=%lu exit=%lu",
        static_cast<unsigned long>(pid), static_cast<int>(alive), static_cast<unsigned long>(gle),
        static_cast<unsigned long>(ok ? exit_code : 0));
    return alive;
}

const char* bridge_state_name(bridge_state_t state)
{
    switch (state)
    {
        case bridge_state_t::stopped: return "stopped";
        case bridge_state_t::starting: return "starting";
        case bridge_state_t::ready: return "ready";
        case bridge_state_t::error: return "error";
    }
    return "unknown";
}

struct action_snapshot_t
{
    bridge_state_t state = bridge_state_t::stopped;
    uint64_t generation = 0;
    uint32_t child_pid = 0;
    bool client = false;
    bool browser_open = false;
    bool page_verified = false;
    bool child_alive = false;
    bool cleanup_pending = false;
    uint64_t total_calls = 0;
    uint64_t total_errors = 0;
    size_t last_error_len = 0;
};

action_snapshot_t action_snapshot()
{
    action_snapshot_t s;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        s.state = sg().state;
        s.generation = sg().generation;
        s.child_pid = sg().child_pid;
        s.client = sg().client != nullptr;
        s.browser_open = sg().browser_open;
        s.page_verified = sg().page_verified;
        s.cleanup_pending = sg().cleanup_pending;
        s.total_calls = sg().total_calls.load(std::memory_order_relaxed);
        s.total_errors = sg().total_errors.load(std::memory_order_relaxed);
        s.last_error_len = sg().last_error.size();
    }
    s.child_alive = process_alive(s.child_pid);
    return s;
}

std::string selector_for_log(const std::string& selector)
{
    std::string out;
    out.reserve((std::min)(selector.size(), static_cast<size_t>(180)));
    for (char c : selector)
    {
        if (out.size() >= 180)
            break;
        if (c == '\r' || c == '\n' || c == '\t')
            out.push_back(' ');
        else
            out.push_back(c);
    }
    if (selector.size() > out.size())
        out += "...";
    return out.empty() ? std::string("<empty>") : out;
}

void log_action_phase(const char* action, const char* phase, uint64_t request_id, const std::string& selector, int timeout_ms, size_t text_len, const action_snapshot_t& s, uint64_t elapsed_ms, const char* failure_phase = "")
{
    const std::string safe_selector = selector_for_log(selector);
    diag::log_tagged_fmt("camoufox",
        "action_%s action=%s request_id=%llu selector=%s timeout_ms=%d text_len=%zu generation=%llu child_pid=%lu state=%s client=%d browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d calls=%llu errors=%llu err_len=%zu elapsed_ms=%llu failure_phase=%s",
        phase,
        action,
        static_cast<unsigned long long>(request_id),
        safe_selector.c_str(),
        timeout_ms,
        text_len,
        static_cast<unsigned long long>(s.generation),
        static_cast<unsigned long>(s.child_pid),
        bridge_state_name(s.state),
        static_cast<int>(s.client),
        static_cast<int>(s.browser_open),
        static_cast<int>(s.page_verified),
        static_cast<int>(s.child_alive),
        static_cast<int>(s.cleanup_pending),
        static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors),
        s.last_error_len,
        static_cast<unsigned long long>(elapsed_ms),
        failure_phase ? failure_phase : "");
}

void clear_page_state_locked()
{
    sg().browser_open = false;
    sg().active_page_url.clear();
    sg().active_page_title.clear();
    sg().page_verified = false;
    sg().last_verified_ms = 0;
}

int clamp_launch_wait_ms(int requested)
{
    int wait_ms = requested > 0 ? requested : kLaunchWaitMaxMs;
    if (wait_ms < kLaunchWaitMinMs) wait_ms = kLaunchWaitMinMs;
    if (wait_ms > kLaunchWaitMaxMs) wait_ms = kLaunchWaitMaxMs;
    return wait_ms;
}

int clamp_navigation_call_wait_ms(int requested)
{
    int wait_ms = requested > 0 ? requested + 5000 : 35000;
    if (wait_ms < 5000) wait_ms = 5000;
    if (wait_ms > kNavigationWaitMaxMs) wait_ms = kNavigationWaitMaxMs;
    return wait_ms;
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

void disconnect_client_sync(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason);

void disconnect_client_async(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason)
{
    if (!cli) return;
    auto disconnect_task = [cli, reason]() {
        diag::log_tagged_fmt("camoufox", "disconnect_async start reason=%s", reason.c_str());
        cli->disconnect();
        diag::log_tagged_fmt("camoufox", "disconnect_async done reason=%s", reason.c_str());
    };
    std::string thread_err;
    if (!aida::infra::win_thread::start_detached(disconnect_task, &thread_err,
            aida::infra::win_thread::default_stack_reserve, "camoufox.disconnect")) {
        diag::log_tagged_fmt("camoufox", "disconnect_async_thread_failed reason=%s err=%s",
            reason.c_str(), thread_err.c_str());
        disconnect_client_sync(cli, reason);
    }
}

void disconnect_client_sync(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason)
{
    if (!cli) return;
    const uint64_t t0 = now_ms();
    diag::log_tagged_fmt("camoufox", "disconnect_sync start reason=%s", reason.c_str());
    cli->disconnect();
    diag::log_tagged_fmt("camoufox", "disconnect_sync done reason=%s elapsed_ms=%llu",
        reason.c_str(), static_cast<unsigned long long>(now_ms() - t0));
}

void terminate_process_id_sync(uint32_t pid, const std::string& reason)
{
    if (pid == 0) return;
    const uint64_t t0 = now_ms();
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (!h) {
        diag::log_tagged_fmt("camoufox", "terminate_process open_failed pid=%lu reason=%s gle=%lu",
            static_cast<unsigned long>(pid), reason.c_str(), static_cast<unsigned long>(GetLastError()));
        return;
    }
    BOOL ok = TerminateProcess(h, 1);
    DWORD gle = ok ? 0 : GetLastError();
    DWORD wait_rc = WaitForSingleObject(h, 3000);
    CloseHandle(h);
    diag::log_tagged_fmt("camoufox", "terminate_process pid=%lu reason=%s ok=%d gle=%lu wait_rc=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(pid), reason.c_str(), ok ? 1 : 0, static_cast<unsigned long>(gle),
        static_cast<unsigned long>(wait_rc), static_cast<unsigned long long>(now_ms() - t0));
}

void terminate_process_id_async(uint32_t pid, const std::string& reason)
{
    if (pid == 0) return;
    auto terminate_task = [pid, reason]() {
        terminate_process_id_sync(pid, reason);
    };
    std::string thread_err;
    if (!aida::infra::win_thread::start_detached(terminate_task, &thread_err,
            aida::infra::win_thread::default_stack_reserve, "camoufox.terminate")) {
        diag::log_tagged_fmt("camoufox", "terminate_process_thread_failed pid=%lu reason=%s err=%s",
            static_cast<unsigned long>(pid), reason.c_str(), thread_err.c_str());
        terminate_process_id_sync(pid, reason);
    }
}

void mark_cleanup_started_locked(uint64_t generation)
{
    sg().cleanup_pending = true;
    sg().cleanup_generation = generation;
}

void mark_cleanup_finished(uint64_t generation, uint64_t elapsed_ms, const std::string& reason)
{
    std::unique_lock<std::recursive_mutex> lk(sg().mtx);
    if (sg().cleanup_generation == generation)
    {
        sg().cleanup_pending = false;
        sg().last_cleanup_ms = elapsed_ms;
    }
    diag::log_tagged_fmt("camoufox", "cleanup_state_done generation=%llu current_generation=%llu pending=%d reason=%s elapsed_ms=%llu",
        static_cast<unsigned long long>(generation), static_cast<unsigned long long>(sg().generation),
        static_cast<int>(sg().cleanup_pending), reason.c_str(), static_cast<unsigned long long>(elapsed_ms));
}

void quarantine_client_locked(std::shared_ptr<mcp_client::client_t> cli, const std::string& reason)
{
    if (!cli) return;
    sg().poisoned_clients.push_back(std::move(cli));
    diag::log_tagged_critical_fmt("camoufox", "client_quarantined reason=%s retained=%zu",
        reason.c_str(), sg().poisoned_clients.size());
}

void cleanup_poisoned_client_async(uint32_t child_pid, const std::string& reason, uint64_t generation)
{
    if (child_pid == 0)
    {
        mark_cleanup_finished(generation, 0, reason);
        return;
    }
    auto cleanup_task = [child_pid, reason, generation]() {
        const uint64_t t0 = now_ms();
        diag::log_tagged_critical_fmt("camoufox", "cleanup_poisoned start generation=%llu reason=%s child_pid=%lu",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid));
        terminate_process_id_sync(child_pid, reason);
        mark_cleanup_finished(generation, now_ms() - t0, reason);
    };
    std::string thread_err;
    if (!aida::infra::win_thread::start_detached(cleanup_task, &thread_err,
            aida::infra::win_thread::default_stack_reserve, "camoufox.cleanup_poisoned")) {
        diag::log_tagged_fmt("camoufox", "cleanup_poisoned_thread_failed generation=%llu reason=%s err=%s",
            static_cast<unsigned long long>(generation), reason.c_str(), thread_err.c_str());
        cleanup_task();
    }
}

void cleanup_client_async(std::shared_ptr<mcp_client::client_t> cli, uint32_t child_pid, const std::string& reason, uint64_t generation)
{
    if (!cli && child_pid == 0)
    {
        mark_cleanup_finished(generation, 0, reason);
        return;
    }
    auto cleanup_task = [cli, child_pid, reason, generation]() {
        const uint64_t t0 = now_ms();
        diag::log_tagged_fmt("camoufox", "cleanup_async start generation=%llu reason=%s child_pid=%lu client=%d",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            static_cast<int>(cli != nullptr));
        if (child_pid != 0)
            terminate_process_id_sync(child_pid, reason);
        if (cli)
        {
            disconnect_client_sync(cli, reason);
            diag::log_tagged_fmt("camoufox", "cleanup_async disconnected generation=%llu reason=%s",
                static_cast<unsigned long long>(generation), reason.c_str());
        }
        mark_cleanup_finished(generation, now_ms() - t0, reason);
    };
    std::string thread_err;
    if (!aida::infra::win_thread::start_detached(cleanup_task, &thread_err,
            aida::infra::win_thread::default_stack_reserve, "camoufox.cleanup")) {
        diag::log_tagged_fmt("camoufox", "cleanup_async_thread_failed generation=%llu reason=%s err=%s",
            static_cast<unsigned long long>(generation), reason.c_str(), thread_err.c_str());
        cleanup_task();
    }
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

std::string hex_u64(ULONG_PTR value)
{
    char buf[32] = {};
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return std::string(buf);
}

struct guarded_mcp_call_context_t
{
    mcp_client::client_t* client = nullptr;
    const std::string* tool_name = nullptr;
    const nlohmann::json* args = nullptr;
    mcp_client::call_result_t* result = nullptr;
    char error[1024] = {};
    DWORD status = ERROR_SUCCESS;
    bool native_exception = false;
    bool cpp_exception = false;
    DWORD exception_code = ERROR_SUCCESS;
    void* exception_address = nullptr;
    DWORD exception_info_count = 0;
    ULONG_PTR exception_info[4] = {};
};

__declspec(noinline) DWORD guarded_mcp_call_cpp(guarded_mcp_call_context_t* ctx)
{
    if (!ctx || !ctx->client || !ctx->tool_name || !ctx->args || !ctx->result)
    {
        if (ctx)
        {
            ctx->status = ERROR_INVALID_PARAMETER;
            std::snprintf(ctx->error, sizeof(ctx->error), "invalid guarded MCP call context");
        }
        return ERROR_INVALID_PARAMETER;
    }

    try
    {
        *ctx->result = ctx->client->call_tool(*ctx->tool_name, *ctx->args);
        ctx->status = ERROR_SUCCESS;
        return ERROR_SUCCESS;
    }
    catch (const std::exception& ex)
    {
        ctx->cpp_exception = true;
        ctx->status = 0xE06D7363u;
        std::snprintf(ctx->error, sizeof(ctx->error), "C++ exception in MCP call_tool(%s): %.820s",
            ctx->tool_name->c_str(), ex.what());
        return ctx->status;
    }
    catch (...)
    {
        ctx->cpp_exception = true;
        ctx->status = 0xE06D7363u;
        std::snprintf(ctx->error, sizeof(ctx->error), "unknown C++ exception in MCP call_tool(%s)",
            ctx->tool_name->c_str());
        return ctx->status;
    }
}

LONG guarded_mcp_call_seh_filter(EXCEPTION_POINTERS* ep, guarded_mcp_call_context_t* ctx)
{
    if (ctx)
    {
        ctx->native_exception = true;
        ctx->status = 0xC0000005u;
        if (ep && ep->ExceptionRecord)
        {
            EXCEPTION_RECORD* rec = ep->ExceptionRecord;
            ctx->exception_code = rec->ExceptionCode;
            ctx->status = rec->ExceptionCode;
            ctx->exception_address = rec->ExceptionAddress;
            ctx->exception_info_count = static_cast<DWORD>(rec->NumberParameters > 4 ? 4 : rec->NumberParameters);
            for (DWORD i = 0; i < ctx->exception_info_count; ++i)
                ctx->exception_info[i] = rec->ExceptionInformation[i];
        }
        const char* tool = ctx->tool_name ? ctx->tool_name->c_str() : "<null>";
        std::snprintf(ctx->error, sizeof(ctx->error),
            "native exception in MCP call_tool(%s): code=0x%08lX addr=%p info_count=%lu info0=%s info1=%s",
            tool,
            static_cast<unsigned long>(ctx->exception_code ? ctx->exception_code : ctx->status),
            ctx->exception_address,
            static_cast<unsigned long>(ctx->exception_info_count),
            hex_u64(ctx->exception_info[0]).c_str(),
            hex_u64(ctx->exception_info[1]).c_str());
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

__declspec(noinline) DWORD guarded_mcp_call(guarded_mcp_call_context_t* ctx)
{
    __try
    {
        return guarded_mcp_call_cpp(ctx);
    }
    __except (guarded_mcp_call_seh_filter(GetExceptionInformation(), ctx))
    {
        return ctx ? ctx->status : 0xC0000005u;
    }
}

mcp_client::call_result_t guarded_mcp_failure_result(const std::string& tool_name, const guarded_mcp_call_context_t& ctx, DWORD status)
{
    std::string message = ctx.error[0] ? std::string(ctx.error) : std::string("MCP call_tool failed under guard");
    nlohmann::json data = nlohmann::json::object();
    data["error"] = message;
    data["tool"] = tool_name;
    data["guard_status"] = static_cast<uint32_t>(status);
    data["native_exception"] = ctx.native_exception;
    data["cpp_exception"] = ctx.cpp_exception;
    if (ctx.native_exception)
    {
        data["exception_code"] = static_cast<uint32_t>(ctx.exception_code);
        data["exception_address"] = hex_u64(reinterpret_cast<ULONG_PTR>(ctx.exception_address));
        data["exception_info_count"] = static_cast<uint32_t>(ctx.exception_info_count);
        data["exception_info0"] = hex_u64(ctx.exception_info[0]);
        data["exception_info1"] = hex_u64(ctx.exception_info[1]);
    }
    return mcp_client::call_result_t{false, message, data};
}

bool data_has_native_exception(const nlohmann::json& data)
{
    try
    {
        return data.is_object() && data.contains("native_exception") && data["native_exception"].is_boolean() && data["native_exception"].get<bool>();
    }
    catch (...) {}
    return false;
}

bool result_has_native_exception(const mcp_client::call_result_t& r)
{
    return data_has_native_exception(r.data);
}

bool result_has_native_exception(const call_result_t& r)
{
    return data_has_native_exception(r.data);
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

call_result_t call_with_deadline(const std::string& tool_name, const nlohmann::json& args, int timeout_ms, uint64_t request_id = 0);

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

int clamp_direct_action_call_timeout_ms(int requested_ms, int fallback_ms)
{
    int out = requested_ms > 0 ? requested_ms : fallback_ms;
    if (out < 1500) out = 1500;
    if (out > 15000) out = 15000;
    return out;
}

nlohmann::json direct_action_payload(const call_result_t& r)
{
    if (r.data.is_object())
    {
        auto value = r.data.find("value");
        if (value != r.data.end() && !value->is_null())
            return *value;
    }
    return r.data;
}

std::string direct_action_error(const call_result_t& r)
{
    std::string err = evaluate_result_error(r);
    if (!err.empty()) return err;
    nlohmann::json payload = direct_action_payload(r);
    try
    {
        if (payload.is_object())
        {
            auto payload_err = payload.find("error");
            if (payload_err != payload.end() && payload_err->is_string())
                return payload_err->get<std::string>();
        }
    }
    catch (...) {}
    return {};
}

call_result_t direct_action_fail(const char* action, uint64_t request_id, const std::string& selector, int timeout_ms, size_t text_len, uint64_t start_ms, const std::string& phase, const std::string& error)
{
    call_result_t out;
    out.ok = false;
    out.error = error.empty() ? std::string(action) + " failed" : error;
    out.data = nlohmann::json::object();
    out.data["status"] = "failed";
    out.data["action"] = action;
    out.data["request_id"] = request_id;
    out.data["phase"] = phase;
    out.data["elapsed_ms"] = now_ms() - start_ms;
    out.data["selector"] = selector;
    out.data["text_length"] = text_len;
    out.data["error"] = out.error;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().last_call_ms = now_ms();
        set_error_locked(std::string(action) + " failed: " + out.error);
    }
    sg().total_errors.fetch_add(1, std::memory_order_relaxed);
    bridge_call_completed_t ev{action, false, now_ms() - start_ms};
    aida::events::publish(kBridgeCallCompleted, ev);
    log_action_phase(action, "exit", request_id, selector, timeout_ms, text_len, action_snapshot(), ev.duration_ms, phase.c_str());
    return out;
}

call_result_t direct_action_ok(const char* action, uint64_t request_id, const std::string& selector, int timeout_ms, size_t text_len, uint64_t start_ms, nlohmann::json payload)
{
    call_result_t out;
    out.ok = true;
    if (!payload.is_object())
    {
        nlohmann::json wrapped;
        wrapped["value"] = payload;
        payload = std::move(wrapped);
    }
    auto status_it = payload.find("status");
    if (status_it == payload.end())
        payload["status"] = "ok";
    payload["action"] = action;
    payload["request_id"] = request_id;
    payload["elapsed_ms"] = now_ms() - start_ms;
    payload["selector"] = selector;
    payload["text_length"] = text_len;
    out.data = std::move(payload);
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().last_call_ms = now_ms();
        clear_error_locked();
    }
    bridge_call_completed_t ev{action, true, now_ms() - start_ms};
    aida::events::publish(kBridgeCallCompleted, ev);
    log_action_phase(action, "exit", request_id, selector, timeout_ms, text_len, action_snapshot(), ev.duration_ms);
    return out;
}

call_result_t dispatch_dom_click_action(const std::string& selector, int timeout_ms, uint64_t request_id)
{
    const uint64_t start_ms = now_ms();
    log_action_phase("click", "entry", request_id, selector, timeout_ms, 0, action_snapshot(), 0);
    if (selector.empty())
        return direct_action_fail("click", request_id, selector, timeout_ms, 0, start_ms, "validate_selector", "click: selector is empty");

    const std::string quoted = nlohmann::json(selector).dump();
    std::string expr;
    expr.reserve(quoted.size() + 2600);
    expr += "(()=>{";
    expr += "const selector=" + quoted + ";";
    expr += "const normalized=String(selector).trim().toLowerCase();";
    expr += "const directDocument=normalized==='document'||normalized==='document.body'||normalized==='body'||normalized==='html'||normalized===':root';";
    expr += "let el=null;try{el=directDocument?(document.body||document.documentElement):document.querySelector(selector);}catch(e){return {error:'Invalid selector: '+selector};}";
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
    const int call_timeout = clamp_direct_action_call_timeout_ms(timeout_ms, 5000);
    log_action_phase("click", "dispatch", request_id, selector, call_timeout, 0, action_snapshot(), now_ms() - start_ms);
    call_result_t r = call_with_deadline("evaluate_js", args, call_timeout, request_id);
    std::string err = direct_action_error(r);
    if (!r.ok || !err.empty())
    {
        if (err.empty()) err = "DOM click dispatch failed";
        diag::log_tagged_fmt("camoufox", "dispatch_dom_click failed request_id=%llu selector=%s ok=%d err=%s",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), static_cast<int>(r.ok), err.c_str());
        return direct_action_fail("click", request_id, selector, call_timeout, 0, start_ms, "evaluate_js", err);
    }
    diag::log_tagged_fmt("camoufox", "dispatch_dom_click ok request_id=%llu selector=%s",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str());
    return direct_action_ok("click", request_id, selector, call_timeout, 0, start_ms, direct_action_payload(r));
}

call_result_t dispatch_dom_type_text_action(const std::string& selector, const std::string& text, int timeout_ms, int delay_ms, uint64_t request_id)
{
    const uint64_t start_ms = now_ms();
    log_action_phase("type_text", "entry", request_id, selector, timeout_ms, text.size(), action_snapshot(), 0);
    if (selector.empty())
        return direct_action_fail("type_text", request_id, selector, timeout_ms, text.size(), start_ms, "validate_selector", "type_text: selector is empty");

    const std::string quoted_selector = nlohmann::json(selector).dump();
    const std::string quoted_text = nlohmann::json(text).dump();
    std::string expr;
    expr.reserve(quoted_selector.size() + quoted_text.size() + 2600);
    expr += "(()=>{";
    expr += "const selector=" + quoted_selector + ";";
    expr += "const text=" + quoted_text + ";";
    expr += "let el=null;try{el=document.querySelector(selector);}catch(e){return {error:'Invalid selector: '+selector};}";
    expr += "if(!el)return {error:'Element not found: '+selector};";
    expr += "const tag=String(el.tagName||'').toLowerCase();";
    expr += "const editable=!!el.isContentEditable||tag==='input'||tag==='textarea';";
    expr += "if(!editable)return {error:'Element is not editable: '+selector};";
    expr += "try{if(el.scrollIntoView)el.scrollIntoView({block:'center',inline:'center',behavior:'instant'});}catch(e){}";
    expr += "try{if(el.focus)el.focus({preventScroll:true});}catch(e){}";
    expr += "function fire(type,extra){let ev=null;try{ev=type==='input'||type==='beforeinput'?new InputEvent(type,Object.assign({bubbles:true,cancelable:true,composed:true,data:text,inputType:'insertText'},extra||{})):new Event(type,{bubbles:true,cancelable:true,composed:true});}catch(e){ev=document.createEvent('Event');ev.initEvent(type,true,true);}el.dispatchEvent(ev);}";
    expr += "fire('beforeinput');";
    expr += "try{if(el.isContentEditable){el.textContent=text;}else{const proto=tag==='textarea'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;const desc=Object.getOwnPropertyDescriptor(proto,'value');if(desc&&desc.set)desc.set.call(el,text);else el.value=text;}}catch(e){return {error:'Element value set failed: '+selector};}";
    expr += "fire('input');fire('change');";
    expr += "return {status:'typed',selector:selector,mode:'dom_value',value_length:String(text).length,delay_ms:" + std::to_string(delay_ms < 0 ? 0 : delay_ms) + "};";
    expr += "})()";

    nlohmann::json args;
    args["expression"] = expr;
    args["await_promise"] = false;
    const int call_timeout = clamp_direct_action_call_timeout_ms(timeout_ms, 5000);
    log_action_phase("type_text", "dispatch", request_id, selector, call_timeout, text.size(), action_snapshot(), now_ms() - start_ms);
    call_result_t r = call_with_deadline("evaluate_js", args, call_timeout, request_id);
    std::string err = direct_action_error(r);
    if (!r.ok || !err.empty())
    {
        if (err.empty()) err = "DOM type_text dispatch failed";
        diag::log_tagged_fmt("camoufox", "dispatch_dom_type_text failed request_id=%llu selector=%s ok=%d err=%s text_len=%zu",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), static_cast<int>(r.ok), err.c_str(), text.size());
        return direct_action_fail("type_text", request_id, selector, call_timeout, text.size(), start_ms, "evaluate_js", err);
    }
    diag::log_tagged_fmt("camoufox", "dispatch_dom_type_text ok request_id=%llu selector=%s text_len=%zu",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), text.size());
    return direct_action_ok("type_text", request_id, selector, call_timeout, text.size(), start_ms, direct_action_payload(r));
}

bool payload_bool_or(const nlohmann::json& payload, const char* key, bool fallback)
{
    if (!payload.is_object()) return fallback;
    auto it = payload.find(key);
    if (it == payload.end() || !it->is_boolean()) return fallback;
    return it->get<bool>();
}

call_result_t dispatch_dom_wait_for_selector_action(const std::string& selector, int timeout_ms, uint64_t request_id)
{
    const uint64_t start_ms = now_ms();
    int effective_timeout = timeout_ms > 0 ? timeout_ms : 5000;
    if (effective_timeout < 250) effective_timeout = 250;
    if (effective_timeout > 30000) effective_timeout = 30000;
    log_action_phase("wait_for", "entry", request_id, selector, effective_timeout, 0, action_snapshot(), 0);
    if (selector.empty())
        return direct_action_fail("wait_for", request_id, selector, effective_timeout, 0, start_ms, "validate_selector", "wait_for: selector is empty");

    const std::string quoted_selector = nlohmann::json(selector).dump();
    std::string expr;
    expr.reserve(quoted_selector.size() + 1200);
    expr += "(()=>{";
    expr += "const selector=" + quoted_selector + ";";
    expr += "let el=null;try{el=document.querySelector(selector);}catch(e){return {error:'Invalid selector: '+selector};}";
    expr += "if(!el)return {status:'waiting',found:false,selector:selector};";
    expr += "let visible=true;try{const style=getComputedStyle(el);const rect=el.getBoundingClientRect();visible=style.visibility!=='hidden'&&style.display!=='none'&&rect.width>=0&&rect.height>=0;}catch(e){}";
    expr += "return {status:'found',found:true,visible:visible,selector:selector};";
    expr += "})()";

    nlohmann::json args;
    args["expression"] = expr;
    args["await_promise"] = false;
    size_t attempts = 0;
    while (now_ms() - start_ms <= static_cast<uint64_t>(effective_timeout))
    {
        ++attempts;
        if (sg().stop_requested.load(std::memory_order_acquire))
            return direct_action_fail("wait_for", request_id, selector, effective_timeout, 0, start_ms, "cancel", "wait_for cancelled by stop request");
        const int eval_timeout = clamp_direct_action_call_timeout_ms(effective_timeout, 2000);
        log_action_phase("wait_for", "poll", request_id, selector, effective_timeout, 0, action_snapshot(), now_ms() - start_ms);
        call_result_t r = call_with_deadline("evaluate_js", args, eval_timeout, request_id);
        std::string err = direct_action_error(r);
        if (!r.ok || !err.empty())
        {
            if (err.empty()) err = "DOM wait_for poll failed";
            diag::log_tagged_fmt("camoufox", "dispatch_dom_wait_for failed request_id=%llu selector=%s ok=%d err=%s attempts=%zu",
                static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), static_cast<int>(r.ok), err.c_str(), attempts);
            return direct_action_fail("wait_for", request_id, selector, effective_timeout, 0, start_ms, "evaluate_js", err);
        }
        nlohmann::json payload = direct_action_payload(r);
        if (payload_bool_or(payload, "found", false))
        {
            payload["attempts"] = attempts;
            diag::log_tagged_fmt("camoufox", "dispatch_dom_wait_for ok request_id=%llu selector=%s attempts=%zu elapsed_ms=%llu",
                static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), attempts,
                static_cast<unsigned long long>(now_ms() - start_ms));
            return direct_action_ok("wait_for", request_id, selector, effective_timeout, 0, start_ms, std::move(payload));
        }
        Sleep(50);
    }
    return direct_action_fail("wait_for", request_id, selector, effective_timeout, 0, start_ms, "selector_timeout", "wait_for timed out before selector appeared");
}

call_result_t call_with_deadline(const std::string& tool_name, const nlohmann::json& args, int timeout_ms, uint64_t request_id)
{
    call_result_t fail;
    fail.ok = false;
    if (request_id == 0)
        request_id = next_request_id();

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
        diag::log_tagged_fmt("camoufox", "call_with_deadline phase=recovering request_id=%llu tool=%s state=%d client=%d old_err_len=%zu",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(old_state), static_cast<int>(had_client), old_error.size());
        if (!ensure_ready())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            fail.error = sg().last_error;
            if (fail.error.empty())
                fail.error = old_state == bridge_state_t::stopped
                    ? "camoufox bridge is not running; call burp_headless_start with headless=false first"
                    : "camoufox bridge not ready";
            diag::log_tagged_fmt("camoufox", "call_with_deadline phase=recovery_failed request_id=%llu tool=%s state=%d client=%d err_len=%zu args_shape=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(sg().state), static_cast<int>(sg().client != nullptr),
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
            diag::log_tagged_fmt("camoufox", "call_with_deadline phase=recovery_no_client request_id=%llu tool=%s err=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), fail.error.c_str());
            return fail;
        }
    }

    if (timeout_ms <= 0) timeout_ms = 30000;

    struct shared_state_t
    {
        std::mutex                       mtx;
        std::condition_variable          cv;
        bool                             done = false;
        bool                             cancelled = false;
        uint64_t                         generation = 0;
        uint32_t                         child_pid = 0;
        mcp_client::call_result_t        result;
    };
    auto state = std::make_shared<shared_state_t>();
    {
        std::lock_guard<std::recursive_mutex> g(sg().mtx);
        state->generation = sg().generation;
        state->child_pid = sg().child_pid;
    }

    const uint64_t t0 = now_ms();
    sg().total_calls.fetch_add(1, std::memory_order_relaxed);
    diag::log_tagged_fmt("camoufox", "call_with_deadline phase=dispatch request_id=%llu tool=%s timeout_ms=%d generation=%llu child_pid=%lu args_shape=%s",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), timeout_ms, static_cast<unsigned long long>(state->generation),
        static_cast<unsigned long>(state->child_pid), json_shape(args).c_str());

    std::string call_thread_err;
    bool posted = aida::infra::win_thread::start_detached([state, cli, tool_name, args, request_id]() {
        const uint64_t worker_start = now_ms();
        mcp_client::call_result_t r;
        guarded_mcp_call_context_t call_ctx;
        call_ctx.client = cli.get();
        call_ctx.tool_name = &tool_name;
        call_ctx.args = &args;
        call_ctx.result = &r;
        diag::log_tagged_fmt("camoufox", "call_worker phase=enter request_id=%llu tool=%s generation=%llu child_pid=%lu",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(state->generation),
            static_cast<unsigned long>(state->child_pid));
        DWORD guard_status = guarded_mcp_call(&call_ctx);
        if (guard_status != ERROR_SUCCESS)
        {
            r = guarded_mcp_failure_result(tool_name, call_ctx, guard_status);
            diag::log_tagged_critical_fmt("camoufox", "call_with_deadline phase=guarded_failure request_id=%llu tool=%s generation=%llu child_pid=%lu status=0x%08lX native=%d cpp=%d elapsed_ms=%llu err=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(state->generation),
                static_cast<unsigned long>(state->child_pid), static_cast<unsigned long>(guard_status),
                static_cast<int>(call_ctx.native_exception), static_cast<int>(call_ctx.cpp_exception),
                static_cast<unsigned long long>(now_ms() - worker_start), r.text.c_str());
        }
        diag::log_tagged_fmt("camoufox", "call_worker phase=exit request_id=%llu tool=%s success=%d text_len=%zu data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(r.success),
            r.text.size(), json_shape(r.data).c_str(), static_cast<unsigned long long>(now_ms() - worker_start));
        bool cancelled = false;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            cancelled = state->cancelled;
            generation = state->generation;
            child_pid = state->child_pid;
            state->result = std::move(r);
            state->done   = true;
        }
        state->cv.notify_all();
        if (cancelled)
        {
            diag::log_tagged_fmt("camoufox", "call_worker_late_result request_id=%llu tool=%s generation=%llu child_pid=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                static_cast<unsigned long long>(now_ms() - worker_start));
        }
    }, &call_thread_err, aida::infra::win_thread::default_stack_reserve, "camoufox.call");

    if (!posted)
    {
        fail.error = std::string("camoufox call thread failed: ") + call_thread_err;
        sg().total_errors.fetch_add(1, std::memory_order_relaxed);
        diag::log_tagged_fmt("camoufox", "call_with_deadline phase=thread_failed request_id=%llu tool=%s err=%s",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), call_thread_err.c_str());
        return fail;
    }

    std::unique_lock<std::mutex> lk(state->mtx);
    const uint64_t wait_start_ms = now_ms();
    bool cancelled_by_stop = false;
    while (!state->done)
    {
        if (sg().stop_requested.load(std::memory_order_acquire))
        {
            cancelled_by_stop = true;
            break;
        }
        const uint64_t elapsed = now_ms() - wait_start_ms;
        if (elapsed >= static_cast<uint64_t>(timeout_ms))
            break;
        const uint64_t remaining = static_cast<uint64_t>(timeout_ms) - elapsed;
        state->cv.wait_for(lk, std::chrono::milliseconds(static_cast<int>(std::min<uint64_t>(remaining, 250))), [&state]() { return state->done; });
    }
    bool got = state->done;
    if (!got)
    {
        std::shared_ptr<mcp_client::client_t> timed_out_client;
        uint32_t timed_out_child_pid = 0;
        uint64_t timed_out_generation = 0;
        state->cancelled = true;
        timed_out_child_pid = state->child_pid;
        timed_out_generation = state->generation;
        lk.unlock();
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                timed_out_client = sg().client;
                sg().client.reset();
                diag::log_tagged_fmt("camoufox", "call_with_deadline phase=%s request_id=%llu timeout_ms=%d tool=%s failure_phase=mcp_response_wait action=detach_client generation=%llu child_pid=%lu",
                    cancelled_by_stop ? "cancel" : "timeout", static_cast<unsigned long long>(request_id), timeout_ms, tool_name.c_str(), static_cast<unsigned long long>(sg().generation),
                    static_cast<unsigned long>(sg().child_pid));
                sg().state           = bridge_state_t::error;
                sg().last_error      = cancelled_by_stop
                    ? std::string("call_tool cancelled by stop request: ") + tool_name
                    : std::string("call_tool timeout: ") + tool_name;
                clear_page_state_locked();
                mark_cleanup_started_locked(sg().generation);
                timed_out_child_pid = sg().child_pid;
                timed_out_generation = sg().generation;
                sg().child_pid       = 0;
            }
            else
            {
                diag::log_tagged_fmt("camoufox", "call_with_deadline phase=%s request_id=%llu timeout_ms=%d tool=%s failure_phase=mcp_response_wait action=current_client_changed generation=%llu",
                    cancelled_by_stop ? "cancel" : "timeout", static_cast<unsigned long long>(request_id), timeout_ms, tool_name.c_str(), static_cast<unsigned long long>(sg().generation));
            }
        }
        if (timed_out_client)
            cleanup_client_async(timed_out_client, timed_out_child_pid, std::string(cancelled_by_stop ? "cancel_" : "timeout_") + tool_name, timed_out_generation);
        publish_state(bridge_state_t::error, std::string(cancelled_by_stop ? "cancelled " : "timeout on ") + tool_name);
        sg().total_errors.fetch_add(1, std::memory_order_relaxed);
        fail.error = cancelled_by_stop
            ? std::string("camoufox call_tool cancelled by stop request: ") + tool_name
            : std::string("camoufox call_tool timeout: ") + tool_name;
        bridge_call_completed_t ev{tool_name, false, now_ms() - t0};
        aida::events::publish(kBridgeCallCompleted, ev);
        return fail;
    }

    mcp_client::call_result_t result = std::move(state->result);
    lk.unlock();

    call_result_t out = to_bridge_result(result);
    const bool driver_closed = !out.ok && is_driver_closed_error(out.error);
    const bool native_exception = !out.ok && result_has_native_exception(out);
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
        else if (native_exception)
        {
            sg().last_error = std::string("camoufox native exception during ") + tool_name + ": " + out.error;
        }
    }
    if (!out.ok) sg().total_errors.fetch_add(1, std::memory_order_relaxed);
    if (native_exception)
    {
        std::shared_ptr<mcp_client::client_t> poisoned_client;
        uint32_t poisoned_child_pid = 0;
        uint64_t poisoned_generation = 0;
        std::string state_error = std::string("camoufox native exception during ") + tool_name + ": " + out.error;
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                poisoned_client = sg().client;
                poisoned_child_pid = sg().child_pid;
                poisoned_generation = sg().generation;
                sg().client.reset();
                sg().state = bridge_state_t::error;
                clear_page_state_locked();
                mark_cleanup_started_locked(sg().generation);
                quarantine_client_locked(std::move(poisoned_client), std::string("native_exception_") + tool_name);
                sg().child_pid = 0;
            }
            sg().last_error = state_error;
        }
        diag::log_tagged_critical_fmt("camoufox", "native_exception invalidated request_id=%llu tool=%s generation=%llu child_pid=%lu err=%s",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(poisoned_generation),
            static_cast<unsigned long>(poisoned_child_pid), out.error.c_str());
        cleanup_poisoned_client_async(poisoned_child_pid, std::string("native_exception_") + tool_name, poisoned_generation);
        publish_state(bridge_state_t::error, state_error);
    }
    else if (driver_closed)
    {
        std::shared_ptr<mcp_client::client_t> closed_client;
        uint32_t closed_child_pid = 0;
        uint64_t closed_generation = 0;
        std::string state_error = std::string("camoufox driver closed during ") + tool_name + ": " + out.error;
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                closed_client = sg().client;
                closed_child_pid = sg().child_pid;
                closed_generation = sg().generation;
                sg().client.reset();
                sg().state = bridge_state_t::error;
                clear_page_state_locked();
                mark_cleanup_started_locked(sg().generation);
                sg().child_pid = 0;
            }
            sg().last_error = state_error;
        }
        diag::log_tagged_fmt("camoufox", "driver_closed invalidated request_id=%llu tool=%s generation=%llu child_pid=%lu err=%s",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(closed_generation),
            static_cast<unsigned long>(closed_child_pid), out.error.c_str());
        cleanup_client_async(closed_client, closed_child_pid, std::string("driver_closed_") + tool_name, closed_generation);
        publish_state(bridge_state_t::error, state_error);
    }
    bridge_call_completed_t ev{tool_name, out.ok, now_ms() - t0};
    aida::events::publish(kBridgeCallCompleted, ev);
    diag::log_tagged_fmt("camoufox", "call_with_deadline phase=complete request_id=%llu tool=%s ok=%d elapsed_ms=%llu data_shape=%s error_len=%zu",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(out.ok), static_cast<unsigned long long>(ev.duration_ms),
        json_shape(out.data).c_str(), out.error.size());
    return out;
}

bool wait_for_tool_listed(mcp_client::client_t* cli, const std::string& tool_name, int timeout_ms)
{
    const uint64_t start = now_ms();
    const uint64_t deadline = now_ms() + static_cast<uint64_t>(timeout_ms);
    uint64_t attempts = 0;
    while (true)
    {
        ++attempts;
        if (sg().stop_requested.load(std::memory_order_acquire))
        {
            diag::log_tagged_fmt("camoufox", "wait_for_tool_listed cancelled tool=%s attempts=%llu elapsed_ms=%llu",
                tool_name.c_str(), static_cast<unsigned long long>(attempts),
                static_cast<unsigned long long>(now_ms() - start));
            return false;
        }
        auto tools = cli->list_tools();
        for (const auto& t : tools)
        {
            if (t.original_name == tool_name)
            {
                diag::log_tagged_fmt("camoufox", "wait_for_tool_listed ok tool=%s attempts=%llu elapsed_ms=%llu tool_count=%zu",
                    tool_name.c_str(), static_cast<unsigned long long>(attempts),
                    static_cast<unsigned long long>(now_ms() - start), tools.size());
                return true;
            }
        }
        if (now_ms() >= deadline)
        {
            diag::log_tagged_fmt("camoufox", "wait_for_tool_listed timeout tool=%s attempts=%llu elapsed_ms=%llu timeout_ms=%d last_count=%zu",
                tool_name.c_str(), static_cast<unsigned long long>(attempts),
                static_cast<unsigned long long>(now_ms() - start), timeout_ms, tools.size());
            return false;
        }
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
        std::string detail = compact_child_output_tail(captured, 600);
        sg().last_error = detail.empty()
            ? std::string("camoufox_reverse_mcp not installed and automatic setup did not complete")
            : std::string("camoufox_reverse_mcp module probe failed to spawn: ") + detail;
        diag::log_tagged_fmt("camoufox", "module_probe spawn_failed detail=%.600s", detail.c_str());
        return false;
    }
    if (code != 0)
    {
        sg().last_error = "camoufox_reverse_mcp not installed and automatic setup did not complete";
        const std::string detail = compact_child_output_tail(captured, 400);
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
        std::string detail = compact_child_output_tail(captured, 600);
        sg().last_error = detail.empty()
            ? std::string("camoufox MCP server preflight failed to spawn or timed out: ") + module
            : std::string("camoufox MCP server preflight failed to spawn or timed out: ") + module + ": " + detail;
        diag::log_tagged_fmt("camoufox", "server_preflight spawn_failed module=%s detail=%.600s",
            module.c_str(), detail.c_str());
        return false;
    }
    if (code != 0)
    {
        std::string detail = compact_child_output_tail(captured);
        sg().last_error = std::string("camoufox MCP server preflight failed: ") + (detail.empty() ? std::string("exit=") + std::to_string(code) : detail);
        diag::log_tagged_fmt("camoufox", "server preflight failed module=%s exit=%lu out=%.400s",
            module.c_str(), code, detail.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "server preflight ok module=%s captured_len=%zu", module.c_str(), captured.size());
    return true;
}

bool wait_for_existing_start_bridge_result(const launch_config_t& cfg, uint64_t caller_start_ms)
{
    int wait_ms = clamp_launch_wait_ms(cfg.launch_timeout_ms);
    if (wait_ms < kBundledVisibleLaunchWaitMinMs)
        wait_ms = kBundledVisibleLaunchWaitMinMs;
    if (wait_ms < 5000)
        wait_ms = 5000;
    const uint64_t wait_limit_ms = static_cast<uint64_t>(wait_ms) + 5000;
    const uint64_t wait_start_ms = now_ms();
    uint64_t last_log_ms = 0;
    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_wait_begin wait_ms=%llu requested_timeout_ms=%d caller_elapsed_ms=%llu",
        static_cast<unsigned long long>(wait_limit_ms), cfg.launch_timeout_ms,
        static_cast<unsigned long long>(wait_start_ms - caller_start_ms));
    for (;;)
    {
        const uint64_t now = now_ms();
        if (sg().stop_requested.load(std::memory_order_acquire))
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().last_error = "camoufox bridge start cancelled by stop request";
            diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_cancelled elapsed_ms=%llu",
                static_cast<unsigned long long>(now - wait_start_ms));
            return false;
        }
        bridge_state_t state = bridge_state_t::starting;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        bool has_client = false;
        bool browser_open = false;
        bool page_verified = false;
        bool cleanup_pending = false;
        bool child_alive = false;
        std::string err;
        bool inspected = false;
        {
            std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
            if (lk.owns_lock())
            {
                inspected = true;
                state = sg().state;
                generation = sg().generation;
                child_pid = sg().child_pid;
                has_client = sg().client != nullptr;
                browser_open = sg().browser_open;
                page_verified = sg().page_verified;
                cleanup_pending = sg().cleanup_pending;
                err = sg().last_error;
                child_alive = process_alive(child_pid);
                const bool ready = state == bridge_state_t::ready && has_client && browser_open && page_verified && child_alive &&
                    !cleanup_pending && !is_driver_closed_error(err);
                if (ready)
                {
                    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_reuse_ready generation=%llu child_pid=%lu elapsed_ms=%llu",
                        static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                        static_cast<unsigned long long>(now_ms() - wait_start_ms));
                    return true;
                }
                if (state != bridge_state_t::starting && !cleanup_pending)
                {
                    if (err.empty())
                        err = "camoufox bridge operation finished without ready state";
                    sg().last_error = err;
                    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_terminal state=%d generation=%llu child_pid=%lu client=%d browser_open=%d page_verified=%d child_alive=%d elapsed_ms=%llu err=%s",
                        static_cast<int>(state), static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                        static_cast<int>(has_client), static_cast<int>(browser_open), static_cast<int>(page_verified),
                        static_cast<int>(child_alive), static_cast<unsigned long long>(now_ms() - wait_start_ms), err.c_str());
                    return false;
                }
            }
        }
        if (now - last_log_ms >= 1000)
        {
            diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_wait state=%d generation=%llu child_pid=%lu inspected=%d client=%d browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d elapsed_ms=%llu limit_ms=%llu err_len=%zu",
                static_cast<int>(state), static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                static_cast<int>(inspected), static_cast<int>(has_client), static_cast<int>(browser_open),
                static_cast<int>(page_verified), static_cast<int>(child_alive), static_cast<int>(cleanup_pending),
                static_cast<unsigned long long>(now - wait_start_ms), static_cast<unsigned long long>(wait_limit_ms), err.size());
            last_log_ms = now;
        }
        if (now - wait_start_ms >= wait_limit_ms)
            break;
        Sleep(100);
    }
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    sg().last_error = "camoufox bridge operation still busy";
    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_wait_timeout state=%d generation=%llu child_pid=%lu client=%d browser_open=%d page_verified=%d cleanup_pending=%d elapsed_ms=%llu",
        static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
        static_cast<int>(sg().client != nullptr), static_cast<int>(sg().browser_open), static_cast<int>(sg().page_verified),
        static_cast<int>(sg().cleanup_pending), static_cast<unsigned long long>(now_ms() - wait_start_ms));
    return false;
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
    j["window_width"] = cfg.window_width > 0 ? cfg.window_width : 1280;
    j["window_height"] = cfg.window_height > 0 ? cfg.window_height : 900;
    j["launch_timeout_ms"] = cfg.launch_timeout_ms > 2000 ? cfg.launch_timeout_ms - 1000 : cfg.launch_timeout_ms;
    if (!cfg.proxy.empty()) j["proxy"] = cfg.proxy;
    if (!cfg.browser_executable.empty())
    {
        j["executable_path"] = cfg.browser_executable;
        j["ff_version"] = 135;
    }
    return j;
}

std::string camoufox_debug_log_path()
{
    std::wstring dir = executable_dir_w();
    if (dir.empty()) dir = current_dir_w();
    if (dir.empty()) return "aida_camoufox_debug.log";
    std::string out = wide_to_utf8(join_path_w(dir, L"aida_camoufox_debug.log"));
    return out.empty() ? std::string("aida_camoufox_debug.log") : out;
}

int json_int_or(const nlohmann::json& j, const char* key, int fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end()) return fallback;
    if (it->is_number_integer() || it->is_number_unsigned()) return it->get<int>();
    if (it->is_number_float()) return static_cast<int>(it->get<double>());
    return fallback;
}

double json_double_or(const nlohmann::json& j, const char* key, double fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end() || !it->is_number()) return fallback;
    return it->get<double>();
}

std::string json_string_or(const nlohmann::json& j, const char* key, const std::string& fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return fallback;
    return it->get<std::string>();
}

bool json_bool_or(const nlohmann::json& j, const char* key, bool fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end() || !it->is_boolean()) return fallback;
    return it->get<bool>();
}

size_t json_array_size_or_zero(const nlohmann::json& j, const char* key)
{
    if (!j.is_object()) return 0;
    auto it = j.find(key);
    if (it == j.end() || !it->is_array()) return 0;
    return it->size();
}

}

bool ensure_python_available(std::string& out_python_path)
{
    diag::log_tagged_fmt("camoufox", "ensure_python_available entry");
    std::string cached_python_path;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        cached_python_path = sg().cached_python_path;
    }
    if (!cached_python_path.empty() && path_exists_w(utf8_to_wide(cached_python_path)))
    {
        std::string reason;
        if (supported_camoufox_python(cached_python_path, &reason))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available cached path=%s %s", cached_python_path.c_str(), reason.c_str());
            out_python_path = cached_python_path;
            return true;
        }
        diag::log_tagged_fmt("camoufox", "ensure_python_available cached rejected path=%s reason=%s",
            cached_python_path.c_str(), reason.c_str());
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            if (_stricmp(sg().cached_python_path.c_str(), cached_python_path.c_str()) == 0)
                sg().cached_python_path.clear();
        }
    }
    std::vector<std::string> candidates;
    append_bundled_python_candidates(candidates);
    append_app_local_python_candidates(candidates);
    std::string found;
    if (try_search_path(L"python.exe", found)) candidates.push_back(found);
    found.clear();
    if (try_search_path(L"python3.exe", found)) candidates.push_back(found);
    found.clear();
    if (try_known_python_roots(found)) candidates.push_back(found);
    std::vector<std::string> unique_candidates;
    for (const auto& candidate : candidates)
    {
        bool seen = false;
        for (const auto& existing : unique_candidates)
        {
            if (_stricmp(existing.c_str(), candidate.c_str()) == 0)
            {
                seen = true;
                break;
            }
        }
        if (!seen) unique_candidates.push_back(candidate);
    }
    candidates.swap(unique_candidates);
    diag::log_tagged_fmt("camoufox", "ensure_python_available candidate_count=%zu", candidates.size());
    for (const std::string& candidate : candidates)
    {
        if (is_windows_store_python_alias(candidate))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available rejected path=%s reason=windows store python alias", candidate.c_str());
            continue;
        }
        std::string reason;
        if (!supported_camoufox_python(candidate, &reason))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available rejected path=%s reason=%s", candidate.c_str(), reason.c_str());
            continue;
        }
        diag::log_tagged_fmt("camoufox", "ensure_python_available found path=%s %s", candidate.c_str(), reason.c_str());
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().cached_python_path = candidate;
        }
        out_python_path         = candidate;
        return true;
    }
    diag::log_tagged_fmt("camoufox", "ensure_python_available python_not_found");
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked("supported Python 3.10-3.13 interpreter not found for camoufox");
    }
    return false;
}

bool start_bridge(const launch_config_t& cfg)
{
    const uint64_t bridge_start_ms = now_ms();
    std::unique_lock<std::recursive_mutex> op_lk(sg().operation_mtx, std::try_to_lock);
    if (!op_lk.owns_lock())
        return wait_for_existing_start_bridge_result(cfg, bridge_start_ms);
    const uint64_t start_stop_epoch = sg().stop_epoch.load(std::memory_order_acquire);
    launch_config_t effective_cfg = cfg;
    if (effective_cfg.headless)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge forcing_visible requested_headless=1");
        effective_cfg.headless = false;
    }
    diag::log_tagged_fmt("camoufox", "start_bridge entry headless=%d module=%s window=%dx%d requested_timeout_ms=%d",
        static_cast<int>(effective_cfg.headless), effective_cfg.server_module.c_str(),
        effective_cfg.window_width, effective_cfg.window_height, effective_cfg.launch_timeout_ms);
    std::unique_lock<std::recursive_mutex> lk(sg().mtx);

    diag::log_tagged_fmt("camoufox", "start_bridge state_snapshot state=%d generation=%llu client=%d browser_open=%d page_verified=%d child_pid=%lu cleanup_pending=%d",
        static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation),
        static_cast<int>(sg().client != nullptr), static_cast<int>(sg().browser_open),
        static_cast<int>(sg().page_verified), static_cast<unsigned long>(sg().child_pid),
        static_cast<int>(sg().cleanup_pending));
    if (sg().cleanup_pending)
    {
        const uint64_t wait_start = now_ms();
        const uint64_t observed_cleanup_generation = sg().cleanup_generation;
        diag::log_tagged_fmt("camoufox", "start_bridge cleanup_wait_begin generation=%llu cleanup_generation=%llu",
            static_cast<unsigned long long>(sg().generation),
            static_cast<unsigned long long>(observed_cleanup_generation));
        while (sg().cleanup_pending && now_ms() - wait_start < 5000)
        {
            lk.unlock();
            Sleep(50);
            lk.lock();
        }
        diag::log_tagged_fmt("camoufox", "start_bridge cleanup_wait_end pending=%d generation=%llu cleanup_generation=%llu elapsed_ms=%llu",
            static_cast<int>(sg().cleanup_pending),
            static_cast<unsigned long long>(sg().generation),
            static_cast<unsigned long long>(sg().cleanup_generation),
            static_cast<unsigned long long>(now_ms() - wait_start));
    }
    if (sg().cleanup_pending)
    {
        set_error_locked("camoufox bridge cleanup still pending");
        diag::log_tagged_fmt("camoufox", "start_bridge rejected cleanup_pending generation=%llu cleanup_generation=%llu",
            static_cast<unsigned long long>(sg().generation), static_cast<unsigned long long>(sg().cleanup_generation));
        return false;
    }

    if (sg().state == bridge_state_t::ready && sg().client)
    {
        const bool child_alive = process_alive(sg().child_pid);
        if (!is_driver_closed_error(sg().last_error) && sg().browser_open && sg().page_verified && child_alive)
        {
            diag::log_tagged_fmt("camoufox", "start_bridge already_ready reusing generation=%llu child_pid=%lu active_url_len=%zu title_len=%zu",
                static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
                sg().active_page_url.size(), sg().active_page_title.size());
            sg().active_cfg = effective_cfg;
            sg().last_launch_ms = now_ms() - bridge_start_ms;
            return true;
        }
        diag::log_tagged_fmt("camoufox", "start_bridge invalidating_unverified_ready generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d err=%s",
            static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
            static_cast<int>(child_alive), static_cast<int>(sg().browser_open), static_cast<int>(sg().page_verified),
            sg().last_error.c_str());
        auto stale_client = sg().client;
        const uint32_t stale_pid = sg().child_pid;
        if (stale_client)
            stale_client->disconnect();
        if (stale_pid != 0)
            terminate_process_id_sync(stale_pid, "start_bridge_unverified_ready");
        sg().client.reset();
        clear_page_state_locked();
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
        clear_page_state_locked();
        sg().child_pid = 0;
    }
    if (sg().stop_epoch.load(std::memory_order_acquire) != start_stop_epoch)
    {
        sg().last_error = "camoufox bridge start cancelled by stop request";
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        diag::log_tagged_fmt("camoufox", "start_bridge cancelled_before_launch elapsed_ms=%llu",
            static_cast<unsigned long long>(sg().last_launch_ms));
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    sg().stop_requested.store(false, std::memory_order_release);
    const uint64_t start_generation = ++sg().generation;
    sg().cleanup_pending = false;
    sg().cleanup_generation = start_generation;
    sg().state          = bridge_state_t::starting;
    sg().last_error.clear();
    sg().last_launch_ms = 0;
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

    if (effective_cfg.browser_executable.empty())
    {
        std::string bundled_browser;
        if (find_bundled_camoufox_executable(bundled_browser))
            effective_cfg.browser_executable = bundled_browser;
    }
    DWORD browser_attr = INVALID_FILE_ATTRIBUTES;
    if (!effective_cfg.browser_executable.empty())
        browser_attr = GetFileAttributesW(utf8_to_wide(effective_cfg.browser_executable).c_str());
    diag::log_tagged_fmt("camoufox", "start_bridge browser_executable=%s exists=%d attr=0x%08lX",
        effective_cfg.browser_executable.empty() ? "<empty>" : effective_cfg.browser_executable.c_str(),
        static_cast<int>(browser_attr != INVALID_FILE_ATTRIBUTES && (browser_attr & FILE_ATTRIBUTE_DIRECTORY) == 0),
        static_cast<unsigned long>(browser_attr));

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
    const std::string child_debug_log = camoufox_debug_log_path();
    scfg.env["PYTHONIOENCODING"] = "utf-8";
    scfg.env["AIDA_CAMOUFOX_DEBUG_LOG"] = child_debug_log;
    if (!effective_cfg.browser_executable.empty())
        scfg.env["AIDA_CAMOUFOX_EXECUTABLE"] = effective_cfg.browser_executable;
    scfg.enabled                 = true;
    scfg.auto_connect            = false;
    scfg.oauth_enabled           = false;

    sg().client = std::make_shared<mcp_client::client_t>();

    diag::log_tagged_fmt("camoufox", "start_bridge mcp_connect_begin generation=%llu command=%s module=%s args=%zu env_pythonio=%d env_browser=%d env_debug_log=%d debug_log=%s browser_exists=%d",
        static_cast<unsigned long long>(start_generation),
        scfg.command.c_str(),
        (effective_cfg.server_module.empty() ? "camoufox_reverse_mcp" : effective_cfg.server_module.c_str()),
        scfg.args.size(),
        static_cast<int>(scfg.env.find("PYTHONIOENCODING") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_EXECUTABLE") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_DEBUG_LOG") != scfg.env.end()),
        child_debug_log.c_str(),
        static_cast<int>(browser_attr != INVALID_FILE_ATTRIBUTES && (browser_attr & FILE_ATTRIBUTE_DIRECTORY) == 0));
    if (!sg().client->connect(scfg))
    {
        std::string inner = sg().client->last_error();
        sg().client.reset();
        sg().state      = bridge_state_t::error;
        sg().last_error = std::string("client connect failed: ") + (inner.empty() ? std::string("(no detail)") : inner);
        diag::log_tagged_fmt("camoufox", "start_bridge mcp_connect_failed generation=%llu err=%s",
            static_cast<unsigned long long>(start_generation), sg().last_error.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    sg().server_command = python_path + " -m " + (effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    sg().child_pid      = sg().client ? sg().client->child_process_id() : 0;
    sg().launched_ms    = now_ms();
    diag::log_tagged_fmt("camoufox", "start_bridge connected generation=%llu child_pid=%lu command=%s",
        static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid),
        sg().server_command.c_str());

    int launch_wait_ms = clamp_launch_wait_ms(effective_cfg.launch_timeout_ms);
    if (!effective_cfg.headless && !effective_cfg.browser_executable.empty() && launch_wait_ms < kBundledVisibleLaunchWaitMinMs)
        launch_wait_ms = kBundledVisibleLaunchWaitMinMs;
    int wait_ms = launch_wait_ms / 4;
    if (wait_ms < 5000) wait_ms = 5000;
    if (wait_ms > kToolListWaitMaxMs) wait_ms = kToolListWaitMaxMs;
    if (effective_cfg.launch_timeout_ms != launch_wait_ms)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge launch_timeout_clamped requested_ms=%d effective_ms=%d tool_list_ms=%d generation=%llu",
            effective_cfg.launch_timeout_ms, launch_wait_ms, wait_ms, static_cast<unsigned long long>(start_generation));
    }
    effective_cfg.launch_timeout_ms = launch_wait_ms;
    diag::log_tagged_fmt("camoufox", "start_bridge waiting_for_tool tool=launch_browser wait_ms=%d generation=%llu child_pid=%lu",
        wait_ms, static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid));
    if (!wait_for_tool_listed(sg().client.get(), "launch_browser", wait_ms))
    {
        std::string inner = sg().client->last_error();
        const uint32_t failed_pid = sg().child_pid;
        sg().client->disconnect();
        sg().client.reset();
        sg().state      = bridge_state_t::error;
        sg().last_error = std::string("camoufox MCP server did not expose launch_browser within timeout; mcp last_error=") + inner;
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        diag::log_tagged("camoufox", sg().last_error.c_str());
        terminate_process_id_async(failed_pid, "launch_browser_tool_missing");
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    sg().active_cfg     = effective_cfg;

    nlohmann::json args = build_launch_args(effective_cfg);
    diag::log_tagged_fmt("camoufox", "launch_browser request headless=%d has_proxy=%d os=%s locale=%s window=%dx%d timeout_ms=%d",
        static_cast<int>(effective_cfg.headless), static_cast<int>(!effective_cfg.proxy.empty()),
        (effective_cfg.os.empty() ? "auto" : effective_cfg.os.c_str()),
        (effective_cfg.locale.empty() ? "auto" : effective_cfg.locale.c_str()),
        json_int_or(args, "window_width", -1), json_int_or(args, "window_height", -1),
        effective_cfg.launch_timeout_ms);
    struct launch_state_t
    {
        std::mutex                mtx;
        std::condition_variable   cv;
        bool                      done = false;
        bool                      cancelled = false;
        uint64_t                  generation = 0;
        uint32_t                  child_pid = 0;
        mcp_client::call_result_t result;
    };
    auto launch_state = std::make_shared<launch_state_t>();
    auto launch_client = sg().client;
    const uint32_t launch_child_pid = sg().child_pid;
    {
        std::lock_guard<std::mutex> launch_state_lk(launch_state->mtx);
        launch_state->generation = start_generation;
        launch_state->child_pid = launch_child_pid;
    }
    const uint64_t launch_call_start_ms = now_ms();
    std::string launch_thread_err;
    bool launch_posted = aida::infra::win_thread::start_detached([launch_state, launch_client, args]() {
        const uint64_t worker_start = now_ms();
        const std::string launch_tool = "launch_browser";
        mcp_client::call_result_t r;
        guarded_mcp_call_context_t call_ctx;
        call_ctx.client = launch_client.get();
        call_ctx.tool_name = &launch_tool;
        call_ctx.args = &args;
        call_ctx.result = &r;
        DWORD guard_status = guarded_mcp_call(&call_ctx);
        if (guard_status != ERROR_SUCCESS)
        {
            r = guarded_mcp_failure_result(launch_tool, call_ctx, guard_status);
            diag::log_tagged_critical_fmt("camoufox", "launch_browser guarded_failure generation=%llu child_pid=%lu status=0x%08lX native=%d cpp=%d elapsed_ms=%llu err=%s",
                static_cast<unsigned long long>(launch_state->generation),
                static_cast<unsigned long>(launch_state->child_pid), static_cast<unsigned long>(guard_status),
                static_cast<int>(call_ctx.native_exception), static_cast<int>(call_ctx.cpp_exception),
                static_cast<unsigned long long>(now_ms() - worker_start), r.text.c_str());
        }
        bool cancelled = false;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        {
            std::lock_guard<std::mutex> lk(launch_state->mtx);
            cancelled = launch_state->cancelled;
            generation = launch_state->generation;
            child_pid = launch_state->child_pid;
            launch_state->result = std::move(r);
            launch_state->done = true;
        }
        launch_state->cv.notify_all();
        if (cancelled)
        {
            diag::log_tagged_fmt("camoufox", "launch_browser worker_late_result generation=%llu child_pid=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                static_cast<unsigned long long>(now_ms() - worker_start));
        }
    }, &launch_thread_err, aida::infra::win_thread::default_stack_reserve, "camoufox.launch");
    if (!launch_posted)
    {
        auto failed_client = sg().client;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        sg().last_error = std::string("launch_browser dispatch thread failed: ") + launch_thread_err;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation);
        diag::log_tagged_fmt("camoufox", "launch_browser dispatch_thread_failed generation=%llu child_pid=%lu err=%s",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(launch_child_pid),
            launch_thread_err.c_str());
        cleanup_client_async(failed_client, launch_child_pid, "launch_browser_dispatch_failed", start_generation);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    mcp_client::call_result_t launch;
    {
        std::unique_lock<std::mutex> launch_lk(launch_state->mtx);
        const uint64_t launch_wait_start_ms = now_ms();
        bool launch_cancelled_by_stop = false;
        while (!launch_state->done)
        {
            if (sg().stop_requested.load(std::memory_order_acquire))
            {
                launch_cancelled_by_stop = true;
                break;
            }
            const uint64_t elapsed = now_ms() - launch_wait_start_ms;
            if (elapsed >= static_cast<uint64_t>(launch_wait_ms))
                break;
            const uint64_t remaining = static_cast<uint64_t>(launch_wait_ms) - elapsed;
            launch_state->cv.wait_for(launch_lk, std::chrono::milliseconds(static_cast<int>(std::min<uint64_t>(remaining, 250))),
                [&launch_state]() { return launch_state->done; });
        }
        bool launch_done = launch_state->done;
        if (!launch_done)
        {
            launch_state->cancelled = true;
            auto timed_out_client = sg().client;
            const uint32_t timed_out_pid = sg().child_pid;
            sg().client.reset();
            clear_page_state_locked();
            sg().child_pid = 0;
            sg().state = bridge_state_t::error;
            sg().last_error = launch_cancelled_by_stop
                ? std::string("launch_browser cancelled by stop request")
                : std::string("launch_browser timeout after ") + std::to_string(launch_wait_ms) + "ms";
            sg().last_launch_ms = now_ms() - bridge_start_ms;
            mark_cleanup_started_locked(start_generation);
            diag::log_tagged_fmt("camoufox", "launch_browser %s generation=%llu child_pid=%lu elapsed_ms=%llu requested_ms=%d effective_ms=%d",
                launch_cancelled_by_stop ? "cancelled" : "timeout",
                static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(timed_out_pid),
                static_cast<unsigned long long>(sg().last_launch_ms), cfg.launch_timeout_ms, launch_wait_ms);
            cleanup_client_async(timed_out_client, timed_out_pid, launch_cancelled_by_stop ? "launch_browser_cancelled" : "launch_browser_timeout", start_generation);
            publish_state(bridge_state_t::error, sg().last_error);
            return false;
        }
        launch = std::move(launch_state->result);
    }
    const uint64_t launch_elapsed_ms = now_ms() - launch_call_start_ms;
    diag::log_tagged_fmt("camoufox", "launch_browser response success=%d generation=%llu child_pid=%lu elapsed_ms=%llu text_len=%zu data_shape=%s error_len=%zu",
        static_cast<int>(launch.success), static_cast<unsigned long long>(start_generation),
        static_cast<unsigned long>(launch_child_pid), static_cast<unsigned long long>(launch_elapsed_ms),
        launch.text.size(), json_shape(launch.data).c_str(), launch.success ? static_cast<size_t>(0) : launch.text.size());
    if (!launch.success)
    {
        const bool native_exception = result_has_native_exception(launch);
        sg().last_error = std::string("launch_browser failed: ") + launch.text;
        diag::log_tagged_fmt("camoufox", "launch_browser failed generation=%llu child_pid=%lu response_tail=%.900s",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(launch_child_pid),
            compact_child_output_tail(launch.text, 900).c_str());
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation);
        if (native_exception)
        {
            quarantine_client_locked(std::move(failed_client), "launch_browser_native_exception");
            cleanup_poisoned_client_async(failed_pid, "launch_browser_native_exception", start_generation);
        }
        else
        {
            cleanup_client_async(failed_client, failed_pid, "launch_browser_failed", start_generation);
        }
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    nlohmann::json parsed;
    parse_text_to_json(launch.text, parsed);
    if (parsed.is_object())
    {
        const nlohmann::json diagnostics = parsed.contains("diagnostics") && parsed["diagnostics"].is_object()
            ? parsed["diagnostics"] : nlohmann::json::object();
        const nlohmann::json window = diagnostics.contains("window") && diagnostics["window"].is_object()
            ? diagnostics["window"] : nlohmann::json::object();
        const nlohmann::json bounds = diagnostics.contains("page_bounds") && diagnostics["page_bounds"].is_object()
            ? diagnostics["page_bounds"] : nlohmann::json::object();
        const nlohmann::json viewport = diagnostics.contains("viewport") && diagnostics["viewport"].is_object()
            ? diagnostics["viewport"] : nlohmann::json::object();
        diag::log_tagged_fmt("camoufox", "launch_browser parsed status=%s diag_elapsed_ms=%d window=%dx%d requested=%dx%d work_area=%dx%d viewport=%dx%d inner=%dx%d outer=%dx%d pos=%d,%d screen=%dx%d avail=%dx%d dpr=%.2f",
            json_string_or(parsed, "status", "unknown").c_str(),
            json_int_or(diagnostics, "elapsed_ms", -1),
            json_int_or(window, "width", -1), json_int_or(window, "height", -1),
            json_int_or(window, "requested_width", -1), json_int_or(window, "requested_height", -1),
            json_int_or(window.contains("work_area") && window["work_area"].is_object() ? window["work_area"] : nlohmann::json::object(), "width", -1),
            json_int_or(window.contains("work_area") && window["work_area"].is_object() ? window["work_area"] : nlohmann::json::object(), "height", -1),
            json_int_or(viewport, "width", -1), json_int_or(viewport, "height", -1),
            json_int_or(bounds, "innerWidth", -1), json_int_or(bounds, "innerHeight", -1),
            json_int_or(bounds, "outerWidth", -1), json_int_or(bounds, "outerHeight", -1),
            json_int_or(bounds, "screenX", -1), json_int_or(bounds, "screenY", -1),
            json_int_or(bounds, "screenWidth", -1), json_int_or(bounds, "screenHeight", -1),
            json_int_or(bounds, "availWidth", -1), json_int_or(bounds, "availHeight", -1),
            json_double_or(bounds, "devicePixelRatio", 0.0));
    }
    if (parsed.is_object() && parsed.contains("error") && parsed["error"].is_string())
    {
        sg().last_error = std::string("launch_browser returned error: ") + parsed["error"].get<std::string>();
        diag::log_tagged_fmt("camoufox", "launch_browser returned_error generation=%llu child_pid=%lu err=%s response_tail=%.900s",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid),
            parsed["error"].get<std::string>().c_str(), compact_child_output_tail(launch.text, 900).c_str());
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation);
        cleanup_client_async(failed_client, failed_pid, "launch_browser_returned_error", start_generation);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (sg().stop_requested.load(std::memory_order_acquire))
    {
        sg().last_error = "launch_browser cancelled by stop request";
        auto cancelled_client = sg().client;
        const uint32_t cancelled_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation);
        diag::log_tagged_fmt("camoufox", "launch_browser cancelled_by_stop generation=%llu child_pid=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(cancelled_pid),
            static_cast<unsigned long long>(sg().last_launch_ms));
        cleanup_client_async(cancelled_client, cancelled_pid, "launch_browser_cancelled_by_stop", start_generation);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (sg().child_pid == 0 || !process_alive(sg().child_pid))
    {
        sg().last_error = "launch_browser child process is not alive after launch";
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation);
        diag::log_tagged_fmt("camoufox", "launch_browser child_not_alive generation=%llu child_pid=%lu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(failed_pid));
        cleanup_client_async(failed_client, failed_pid, "launch_browser_child_not_alive", start_generation);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    sg().browser_open = true;
    sg().state = bridge_state_t::ready;
    sg().page_verified = false;
    nlohmann::json page_args;
    call_result_t page = call_with_deadline("get_page_info", page_args, kReadinessProbeTimeoutMs);
    if (!page.ok || !page.data.is_object() || !page.data.contains("url") || !page.data["url"].is_string())
    {
        std::string err = page.error.empty() ? std::string("launch readiness probe did not return page URL") : page.error;
        sg().last_error = std::string("launch readiness failed: ") + err;
        auto failed_client = sg().client;
        const uint32_t failed_pid = sg().child_pid;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation);
        diag::log_tagged_fmt("camoufox", "launch_browser readiness_failed generation=%llu child_pid=%lu err=%s data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(failed_pid),
            err.c_str(), json_shape(page.data).c_str(), static_cast<unsigned long long>(sg().last_launch_ms));
        cleanup_client_async(failed_client, failed_pid, "launch_browser_readiness_failed", start_generation);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    sg().active_page_url = page.data["url"].get<std::string>();
    sg().active_page_title = json_string_or(page.data, "title", std::string());
    sg().page_verified = true;
    sg().last_verified_ms = now_ms();
    sg().state = bridge_state_t::ready;
    sg().last_error.clear();
    sg().last_launch_ms = now_ms() - bridge_start_ms;
    const url_log_t ready_url = summarize_url_for_log(sg().active_page_url);
    diag::log_tagged_fmt("camoufox", "bridge ready generation=%llu child_pid=%lu python=%s active_host=%s active_path=%s query=%d url_len=%zu title_len=%zu elapsed_ms=%llu",
        static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid), python_path.c_str(),
        ready_url.host.c_str(), ready_url.path.c_str(), static_cast<int>(ready_url.has_query),
        ready_url.length, sg().active_page_title.size(), static_cast<unsigned long long>(sg().last_launch_ms));
    publish_state(bridge_state_t::ready, std::string());
    return true;
}

bool stop_bridge()
{
    const uint64_t stop_start_ms = now_ms();
    const uint64_t stop_epoch = sg().stop_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
    diag::log_tagged_fmt("camoufox", "stop_bridge entry epoch=%llu",
        static_cast<unsigned long long>(stop_epoch));
    sg().stop_requested.store(true, std::memory_order_release);
    std::unique_lock<std::recursive_mutex> op_lk(sg().operation_mtx, std::try_to_lock);
    if (!op_lk.owns_lock())
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge waiting_for_operation_cancel_signal");
        op_lk.lock();
        diag::log_tagged_fmt("camoufox", "stop_bridge operation_lock_acquired_after_wait elapsed_ms=%llu",
            static_cast<unsigned long long>(now_ms() - stop_start_ms));
    }
    std::shared_ptr<mcp_client::client_t> cli;
    bool browser_open = false;
    uint32_t child_pid = 0;
    uint64_t stop_generation = 0;
    {
        std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::defer_lock);
        const uint64_t state_wait_start_ms = now_ms();
        while (!lk.try_lock())
        {
            if (now_ms() - state_wait_start_ms >= 5000)
                break;
            Sleep(10);
        }
        if (!lk.owns_lock())
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge busy_stop_requested elapsed_ms=%llu",
                static_cast<unsigned long long>(now_ms() - stop_start_ms));
            return false;
        }
        if (now_ms() - state_wait_start_ms != 0)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge state_lock_acquired elapsed_ms=%llu",
                static_cast<unsigned long long>(now_ms() - state_wait_start_ms));
        }
        diag::log_tagged_fmt("camoufox", "stop_bridge state_snapshot state=%d generation=%llu child_pid=%lu browser_open=%d page_verified=%d cleanup_pending=%d",
            static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation),
            static_cast<unsigned long>(sg().child_pid), static_cast<int>(sg().browser_open),
            static_cast<int>(sg().page_verified), static_cast<int>(sg().cleanup_pending));
        if (sg().state == bridge_state_t::stopped)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge already_stopped");
            sg().client.reset();
            clear_page_state_locked();
            sg().child_pid = 0;
            sg().cleanup_pending = false;
            sg().last_cleanup_ms = now_ms() - stop_start_ms;
            return true;
        }
        cli = sg().client;
        browser_open = sg().browser_open;
        child_pid = sg().child_pid;
        stop_generation = ++sg().generation;
        sg().client.reset();
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().state = bridge_state_t::stopped;
        sg().last_error.clear();
        mark_cleanup_started_locked(stop_generation);
    }
    if (cli && browser_open)
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge scheduling_cleanup generation=%llu child_pid=%lu close_browser=1",
            static_cast<unsigned long long>(stop_generation), static_cast<unsigned long>(child_pid));
        auto close_task = [cli]() {
            const std::string tool_name = "close_browser";
            const nlohmann::json args = nlohmann::json::object();
            mcp_client::call_result_t r;
            guarded_mcp_call_context_t call_ctx;
            call_ctx.client = cli.get();
            call_ctx.tool_name = &tool_name;
            call_ctx.args = &args;
            call_ctx.result = &r;
            DWORD guard_status = guarded_mcp_call(&call_ctx);
            if (guard_status != ERROR_SUCCESS)
            {
                r = guarded_mcp_failure_result(tool_name, call_ctx, guard_status);
                diag::log_tagged_critical_fmt("camoufox", "stop_bridge close_browser guarded_failure status=0x%08lX native=%d cpp=%d err=%s",
                    static_cast<unsigned long>(guard_status), static_cast<int>(call_ctx.native_exception),
                    static_cast<int>(call_ctx.cpp_exception), r.text.c_str());
                if (result_has_native_exception(r))
                {
                    std::lock_guard<std::recursive_mutex> g(sg().mtx);
                    quarantine_client_locked(cli, "stop_bridge_close_browser_native_exception");
                    return;
                }
            }
            cli->disconnect();
        };
        std::string close_thread_err;
        if (!aida::infra::win_thread::start_detached(close_task, &close_thread_err,
                aida::infra::win_thread::default_stack_reserve, "camoufox.close")) {
            diag::log_tagged_fmt("camoufox", "stop_bridge close_browser_thread_failed err=%s", close_thread_err.c_str());
            close_task();
        }
        cleanup_client_async(nullptr, child_pid, "stop_bridge", stop_generation);
    }
    else if (cli)
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge scheduling_cleanup generation=%llu child_pid=%lu close_browser=0",
            static_cast<unsigned long long>(stop_generation), static_cast<unsigned long>(child_pid));
        cleanup_client_async(cli, child_pid, "stop_bridge", stop_generation);
    }
    else
    {
        cleanup_client_async(nullptr, child_pid, "stop_bridge", stop_generation);
    }
    publish_state(bridge_state_t::stopped, std::string());
    diag::log_tagged_fmt("camoufox", "bridge stopped generation=%llu elapsed_ms=%llu",
        static_cast<unsigned long long>(stop_generation), static_cast<unsigned long long>(now_ms() - stop_start_ms));
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
    const bool child_alive = process_alive(sg().child_pid);
    bool ready = sg().state == bridge_state_t::ready &&
        sg().client != nullptr &&
        sg().browser_open &&
        sg().page_verified &&
        child_alive &&
        !is_driver_closed_error(sg().last_error);
    if (sg().state == bridge_state_t::ready && !ready)
    {
        sg().state = bridge_state_t::error;
        if (sg().last_error.empty())
            sg().last_error = "camoufox bridge readiness verification failed";
        if (!child_alive || !sg().browser_open || !sg().page_verified)
            clear_page_state_locked();
    }
    diag::log_tagged_fmt("camoufox", "is_ready result=%d state=%d generation=%llu client=%d browser_open=%d page_verified=%d child_pid=%lu child_alive=%d err_len=%zu",
        static_cast<int>(ready), static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation),
        static_cast<int>(sg().client != nullptr), static_cast<int>(sg().browser_open),
        static_cast<int>(sg().page_verified), static_cast<unsigned long>(sg().child_pid),
        static_cast<int>(child_alive), sg().last_error.size());
    return ready;
}

bool ensure_ready()
{
    const uint64_t t0 = now_ms();
    diag::log_tagged_fmt("camoufox", "ensure_ready entry");
    if (is_ready()) {
        diag::log_tagged_fmt("camoufox", "ensure_ready already_ready elapsed_ms=%llu",
            static_cast<unsigned long long>(now_ms() - t0));
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
    bool ok = start_bridge(cfg);
    diag::log_tagged_fmt("camoufox", "ensure_ready exit ok=%d elapsed_ms=%llu err_len=%zu",
        static_cast<int>(ok), static_cast<unsigned long long>(now_ms() - t0), last_error().size());
    return ok;
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
    s.active_page_title = sg().active_page_title;
    s.page_verified   = sg().page_verified;
    s.cleanup_pending = sg().cleanup_pending;
    s.generation      = sg().generation;
    s.last_launch_ms  = sg().last_launch_ms;
    s.last_nav_ms     = sg().last_nav_ms;
    s.last_cleanup_ms = sg().last_cleanup_ms;
    s.last_verified_ms = sg().last_verified_ms;
    s.child_alive     = process_alive(s.child_pid);
    if (s.state == bridge_state_t::ready && is_driver_closed_error(s.last_error))
    {
        s.state = bridge_state_t::error;
        s.browser_open = false;
        s.active_page_url.clear();
        s.active_page_title.clear();
        s.page_verified = false;
    }
    if (s.state == bridge_state_t::ready && (!s.child_alive || !s.browser_open || !s.page_verified))
    {
        s.state = bridge_state_t::error;
        s.browser_open = false;
        s.active_page_url.clear();
        s.active_page_title.clear();
        s.page_verified = false;
        if (s.last_error.empty())
            s.last_error = "camoufox bridge readiness verification failed";
    }
    const url_log_t u = summarize_url_for_log(s.active_page_url);
    diag::log_tagged_fmt("camoufox", "get_status state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu active_host=%s active_path=%s query=%d url_len=%zu title_len=%zu",
        static_cast<int>(s.state), static_cast<unsigned long long>(s.generation),
        static_cast<unsigned long>(s.child_pid), static_cast<int>(s.child_alive),
        static_cast<int>(s.browser_open), static_cast<int>(s.page_verified), static_cast<int>(s.cleanup_pending),
        static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors), u.host.c_str(), u.path.c_str(),
        static_cast<int>(u.has_query), u.length, s.active_page_title.size());
    return s;
}

call_result_t call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t request_id = next_request_id();
    nlohmann::json safe_args = args.is_null() ? nlohmann::json::object() : args;
    const action_snapshot_t entry = action_snapshot();
    diag::log_tagged_fmt("camoufox", "call_tool entry request_id=%llu tool=%s timeout_ms=%d args_shape=%s generation=%llu child_pid=%lu state=%s browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), timeout_ms, json_shape(safe_args).c_str(),
        static_cast<unsigned long long>(entry.generation), static_cast<unsigned long>(entry.child_pid),
        bridge_state_name(entry.state), static_cast<int>(entry.browser_open), static_cast<int>(entry.page_verified),
        static_cast<int>(entry.child_alive), static_cast<int>(entry.cleanup_pending));
    call_result_t r;
    if (tool_name == "click")
    {
        r = dispatch_dom_click_action(json_string_or(safe_args, "selector", std::string()), timeout_ms, request_id);
    }
    else if (tool_name == "type_text")
    {
        const std::string selector = json_string_or(safe_args, "selector", std::string());
        if (!safe_args.is_object() || !safe_args.contains("text") || !safe_args["text"].is_string())
        {
            r = direct_action_fail("type_text", request_id, selector, timeout_ms, 0, now_ms(), "validate_text", "type_text: text is required");
        }
        else
        {
            r = dispatch_dom_type_text_action(
                selector,
                safe_args["text"].get<std::string>(),
                timeout_ms,
                json_int_or(safe_args, "delay", 0),
                request_id);
        }
    }
    else if (tool_name == "wait_for")
    {
        const std::string selector = json_string_or(safe_args, "selector", std::string());
        const std::string url_pattern = json_string_or(safe_args, "url_pattern", std::string());
        if (!selector.empty())
        {
            const int selector_timeout = json_int_or(safe_args, "timeout", timeout_ms > 0 ? timeout_ms : 5000);
            r = dispatch_dom_wait_for_selector_action(selector, selector_timeout, request_id);
        }
        else if (url_pattern.empty())
        {
            r = direct_action_fail("wait_for", request_id, std::string(), timeout_ms, 0, now_ms(), "validate_target", "wait_for: selector or url_pattern is required");
        }
        else
        {
            r = call_with_deadline(tool_name, safe_args, timeout_ms, request_id);
        }
    }
    else
    {
        r = call_with_deadline(tool_name, safe_args, timeout_ms, request_id);
    }
    const action_snapshot_t exit = action_snapshot();
    diag::log_tagged_fmt("camoufox", "call_tool result request_id=%llu tool=%s ok=%d data_shape=%s text_len=%zu error_len=%zu generation=%llu child_pid=%lu state=%s browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(r.ok), json_shape(r.data).c_str(), r.text.size(), r.error.size(),
        static_cast<unsigned long long>(exit.generation), static_cast<unsigned long>(exit.child_pid),
        bridge_state_name(exit.state), static_cast<int>(exit.browser_open), static_cast<int>(exit.page_verified),
        static_cast<int>(exit.child_alive), static_cast<int>(exit.cleanup_pending));
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t nav_start_ms = now_ms();
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
    uint64_t nav_generation = 0;
    uint32_t nav_child_pid = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        nav_generation = sg().generation;
        nav_child_pid = sg().child_pid;
    }
    nlohmann::json a;
    a["url"]                  = url;
    a["wait_until"]           = wait_until.empty() ? std::string("load") : wait_until;
    a["collect_response_chain"] = true;
    a["clear_network_capture"]  = true;
    a["include_title"]          = false;
    int call_timeout = clamp_navigation_call_wait_ms(timeout_ms);
    if (timeout_ms > 0 && call_timeout != timeout_ms + 5000)
    {
        diag::log_tagged_fmt("camoufox", "navigate timeout_clamped requested_ms=%d call_timeout_ms=%d generation=%llu child_pid=%lu",
            timeout_ms, call_timeout, static_cast<unsigned long long>(nav_generation),
            static_cast<unsigned long>(nav_child_pid));
    }
    diag::log_tagged_fmt("camoufox", "navigate dispatch generation=%llu child_pid=%lu call_timeout_ms=%d",
        static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid), call_timeout);
    call_result_t r = call_with_deadline("navigate", a, call_timeout);
    if (!r.ok && is_driver_closed_error(r.error))
    {
        diag::log_tagged_fmt("camoufox", "navigate driver_closed_retry host=%s path=%s err=%s",
            u.host.c_str(), u.path.c_str(), r.error.c_str());
        if (ensure_ready())
        {
            {
                std::lock_guard<std::recursive_mutex> lk(sg().mtx);
                nav_generation = sg().generation;
                nav_child_pid = sg().child_pid;
            }
            r = call_with_deadline("navigate", a, call_timeout);
        }
    }
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "navigate failed generation=%llu child_pid=%lu host=%s path=%s err=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            u.host.c_str(), u.path.c_str(), r.error.c_str(), static_cast<unsigned long long>(now_ms() - nav_start_ms));
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(std::string("navigate failed: ") + r.error);
        sg().last_nav_ms = now_ms() - nav_start_ms;
        return false;
    }
    if (r.data.is_object())
    {
        const std::string response_url = json_string_or(r.data, "url", std::string());
        const std::string response_title = json_string_or(r.data, "title", std::string());
        const int initial_status = json_int_or(r.data, "initial_status", -1);
        const int final_status = json_int_or(r.data, "final_status", -1);
        const bool navigation_timed_out = json_bool_or(r.data, "navigation_timed_out", false);
        const std::string title_error = json_string_or(r.data, "title_error", std::string());
        const size_t warning_count = json_array_size_or_zero(r.data, "warnings");
        if (!response_url.empty())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().active_page_url = response_url;
            sg().active_page_title = response_title;
            sg().page_verified = true;
            sg().last_verified_ms = now_ms();
            sg().last_nav_ms = now_ms() - nav_start_ms;
            const url_log_t f = summarize_url_for_log(sg().active_page_url);
            diag::log_tagged_fmt("camoufox", "navigate ok_from_response generation=%llu child_pid=%lu final_host=%s final_path=%s query=%d url_len=%zu title_len=%zu initial_status=%d final_status=%d nav_timeout=%d warnings=%zu title_error_len=%zu elapsed_ms=%llu",
                static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
                f.host.c_str(), f.path.c_str(), static_cast<int>(f.has_query), f.length,
                sg().active_page_title.size(), initial_status, final_status,
                navigation_timed_out ? 1 : 0, warning_count, title_error.size(),
                static_cast<unsigned long long>(sg().last_nav_ms));
            return true;
        }
        diag::log_tagged_fmt("camoufox", "navigate response_missing_url generation=%llu child_pid=%lu host=%s path=%s data_shape=%s initial_status=%d final_status=%d nav_timeout=%d warnings=%zu title_error_len=%zu elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            u.host.c_str(), u.path.c_str(), json_shape(r.data).c_str(), initial_status, final_status,
            navigation_timed_out ? 1 : 0, warning_count, title_error.size(),
            static_cast<unsigned long long>(now_ms() - nav_start_ms));
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "navigate response_unusable generation=%llu child_pid=%lu host=%s path=%s data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            u.host.c_str(), u.path.c_str(), json_shape(r.data).c_str(),
            static_cast<unsigned long long>(now_ms() - nav_start_ms));
    }
    call_result_t page = get_page_info();
    if (!page.ok || !page.data.is_object() || !page.data.contains("url") || !page.data["url"].is_string())
    {
        std::string err = page.error.empty() ? std::string("post-navigation page verification did not return URL") : page.error;
        diag::log_tagged_fmt("camoufox", "navigate page_verify_failed generation=%llu child_pid=%lu host=%s path=%s err=%s data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(nav_child_pid),
            u.host.c_str(), u.path.c_str(), err.c_str(), json_shape(page.data).c_str(),
            static_cast<unsigned long long>(now_ms() - nav_start_ms));
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().page_verified = false;
        sg().last_nav_ms = now_ms() - nav_start_ms;
        set_error_locked(std::string("navigate page verification failed: ") + err);
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().active_page_url = page.data["url"].get<std::string>();
        sg().active_page_title = json_string_or(page.data, "title", std::string());
        sg().page_verified = true;
        sg().last_verified_ms = now_ms();
        sg().last_nav_ms = now_ms() - nav_start_ms;
        const url_log_t f = summarize_url_for_log(sg().active_page_url);
        diag::log_tagged_fmt("camoufox", "navigate ok generation=%llu child_pid=%lu final_host=%s final_path=%s query=%d url_len=%zu title_len=%zu elapsed_ms=%llu",
            static_cast<unsigned long long>(nav_generation), static_cast<unsigned long>(sg().child_pid),
            f.host.c_str(), f.path.c_str(), static_cast<int>(f.has_query), f.length,
            sg().active_page_title.size(), static_cast<unsigned long long>(sg().last_nav_ms));
    }
    return true;
}

bool reload(const std::string& wait_until)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    call_result_t page = get_page_info();
    if (!page.ok || !page.data.is_object() || !page.data.contains("url") || !page.data["url"].is_string())
    {
        std::string err = page.error.empty() ? std::string("post-reload page verification did not return URL") : page.error;
        diag::log_tagged_fmt("camoufox", "reload page_verify_failed err=%s data_shape=%s",
            err.c_str(), json_shape(page.data).c_str());
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().page_verified = false;
        set_error_locked(std::string("reload page verification failed: ") + err);
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().active_page_url = page.data["url"].get<std::string>();
        sg().active_page_title = json_string_or(page.data, "title", std::string());
        sg().page_verified = true;
        sg().last_verified_ms = now_ms();
        const url_log_t u = summarize_url_for_log(sg().active_page_url);
        diag::log_tagged_fmt("camoufox", "reload ok generation=%llu child_pid=%lu host=%s path=%s query=%d url_len=%zu title_len=%zu",
            static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
            u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query), u.length, sg().active_page_title.size());
    }
    return true;
}

call_result_t evaluate_js(const std::string& expression, bool await_promise)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "list_network_requests entry max_records=%zu", max_records);
    nlohmann::json a;
    call_result_t r = call_with_deadline("list_network_requests", a, 30000);
    if (r.ok && r.data.is_object())
    {
        for (const char* key : {"requests", "items", "records", "data", "result"})
        {
            auto it = r.data.find(key);
            if (it != r.data.end() && it->is_array())
            {
                r.data = *it;
                break;
            }
        }
    }
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "get_page_info entry");
    nlohmann::json a;
    call_result_t r = call_with_deadline("get_page_info", a, 15000);
    if (r.ok && r.data.is_object() && r.data.contains("url") && r.data["url"].is_string())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().active_page_url = r.data["url"].get<std::string>();
        sg().active_page_title = json_string_or(r.data, "title", std::string());
        sg().page_verified = true;
        sg().last_verified_ms = now_ms();
        const url_log_t u = summarize_url_for_log(sg().active_page_url);
        const nlohmann::json bounds = r.data.contains("window_bounds") && r.data["window_bounds"].is_object()
            ? r.data["window_bounds"] : nlohmann::json::object();
        diag::log_tagged_fmt("camoufox", "get_page_info ok generation=%llu child_pid=%lu host=%s path=%s query=%d url_len=%zu title_len=%zu viewport=%dx%d inner=%dx%d outer=%dx%d pos=%d,%d screen=%dx%d avail=%dx%d dpr=%.2f",
            static_cast<unsigned long long>(sg().generation), static_cast<unsigned long>(sg().child_pid),
            u.host.c_str(), u.path.c_str(), static_cast<int>(u.has_query), u.length,
            sg().active_page_title.size(),
            json_int_or(r.data, "viewport_width", -1), json_int_or(r.data, "viewport_height", -1),
            json_int_or(bounds, "innerWidth", -1), json_int_or(bounds, "innerHeight", -1),
            json_int_or(bounds, "outerWidth", -1), json_int_or(bounds, "outerHeight", -1),
            json_int_or(bounds, "screenX", -1), json_int_or(bounds, "screenY", -1),
            json_int_or(bounds, "screenWidth", -1), json_int_or(bounds, "screenHeight", -1),
            json_int_or(bounds, "availWidth", -1), json_int_or(bounds, "availHeight", -1),
            json_double_or(bounds, "devicePixelRatio", 0.0));
    }
    else if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "get_page_info failed err=%s data_shape=%s text_len=%zu",
            r.error.c_str(), json_shape(r.data).c_str(), r.text.size());
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "get_page_info missing_url data_shape=%s text_len=%zu",
            json_shape(r.data).c_str(), r.text.size());
    }
    return r;
}

bool take_screenshot(const std::string& output_path, bool full_page)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t request_id = next_request_id();
    diag::log_tagged_fmt("camoufox", "click entry request_id=%llu selector=%s", static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str());
    call_result_t r = dispatch_dom_click_action(selector, 5000, request_id);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "click failed request_id=%llu selector=%s err=%s",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), r.error.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "click ok request_id=%llu selector=%s", static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str());
    return true;
}

bool type_text(const std::string& selector, const std::string& text)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t request_id = next_request_id();
    diag::log_tagged_fmt("camoufox", "type_text entry request_id=%llu selector=%s text_len=%zu",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), text.size());
    call_result_t r = dispatch_dom_type_text_action(selector, text, 5000, 0, request_id);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "type_text failed request_id=%llu selector=%s err=%s text_len=%zu",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), r.error.c_str(), text.size());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "type_text ok request_id=%llu selector=%s text_len=%zu",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), text.size());
    return true;
}

bool wait_for(const std::string& selector, int timeout_ms)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    const uint64_t request_id = next_request_id();
    diag::log_tagged_fmt("camoufox", "wait_for entry request_id=%llu selector=%s timeout_ms=%d",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), timeout_ms);
    call_result_t r = dispatch_dom_wait_for_selector_action(selector, timeout_ms, request_id);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "wait_for failed request_id=%llu selector=%s err=%s",
            static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str(), r.error.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "wait_for ok request_id=%llu selector=%s",
        static_cast<unsigned long long>(request_id), selector_for_log(selector).c_str());
    return true;
}

bool reset_browser_state()
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
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
