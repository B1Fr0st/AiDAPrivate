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
#include <tlhelp32.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cwctype>
#include <cstring>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace camoufox {

namespace {

struct singleton_t
{
    std::string                             session_id          = "default";
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
    std::atomic<uint64_t>                   next_activity_token{1};
    std::atomic<uint32_t>                   active_activities{0};
    bool                                    browser_open       = false;
    std::string                             active_page_id;
    std::string                             active_page_url;
    std::string                             active_page_title;
    std::vector<page_status_t>              pages;
    std::string                             active_profile_dir;
    bool                                    page_verified      = false;
    bool                                    cleanup_pending    = false;
    uint64_t                                generation         = 0;
    uint64_t                                cleanup_generation = 0;
    uint64_t                                cleanup_started_ms = 0;
    uint32_t                                cleanup_child_pid  = 0;
    std::string                             cleanup_profile_dir;
    std::string                             cleanup_reason;
    uint64_t                                last_launch_ms     = 0;
    uint64_t                                last_nav_ms        = 0;
    uint64_t                                last_cleanup_ms    = 0;
    uint64_t                                last_verified_ms   = 0;
    std::atomic<bool>                       stop_requested{false};
    std::atomic<uint64_t>                   stop_epoch{0};
    std::atomic<uint32_t>                   tracked_child_pid{0};
    std::string                             cached_python_path;
    launch_config_t                         active_cfg;
    std::vector<std::shared_ptr<mcp_client::client_t>> poisoned_clients;
};

inline singleton_t& sg()
{
    static singleton_t s;
    return s;
}

struct managed_session_t
{
    std::recursive_mutex                  mtx;
    std::recursive_mutex                  operation_mtx;
    std::shared_ptr<mcp_client::client_t> client;
    std::string                           session_id;
    bridge_state_t                        state = bridge_state_t::stopped;
    std::string                           last_error;
    std::string                           server_command;
    uint32_t                              child_pid = 0;
    uint64_t                              launched_ms = 0;
    uint64_t                              last_call_ms = 0;
    std::atomic<uint64_t>                 total_calls{0};
    std::atomic<uint64_t>                 total_errors{0};
    std::atomic<uint64_t>                 next_request_id{1};
    bool                                  browser_open = false;
    bool                                  page_verified = false;
    bool                                  cleanup_pending = false;
    std::string                           active_page_id;
    std::string                           active_page_url;
    std::string                           active_page_title;
    std::string                           active_profile_dir;
    std::vector<page_status_t>            pages;
    uint64_t                              generation = 0;
    uint64_t                              last_launch_ms = 0;
    uint64_t                              last_nav_ms = 0;
    uint64_t                              last_cleanup_ms = 0;
    uint64_t                              last_verified_ms = 0;
    std::atomic<bool>                     stop_requested{false};
    launch_config_t                       active_cfg;
};

std::recursive_mutex& sessions_mtx()
{
    static std::recursive_mutex m;
    return m;
}

std::map<std::string, std::shared_ptr<managed_session_t>>& managed_sessions()
{
    static std::map<std::string, std::shared_ptr<managed_session_t>> sessions;
    return sessions;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

bool post_bridge_task(const char* name, std::function<void()> task)
{
    const uint64_t t0 = now_ms();
    bool posted = false;
    try
    {
        posted = work_queue::post(std::move(task));
    }
    catch (...)
    {
        posted = false;
    }
    const auto st = work_queue::stats();
    diag::log_tagged_fmt("camoufox", "work_queue_post name=%s posted=%d alive=%d shutting_down=%d workers=%zu pending=%zu active=%lu elapsed_ms=%llu",
        name ? name : "<null>",
        posted ? 1 : 0,
        st.alive ? 1 : 0,
        st.shutting_down ? 1 : 0,
        st.workers,
        st.pending,
        static_cast<unsigned long>(st.active),
        static_cast<unsigned long long>(now_ms() - t0));
    return posted;
}

uint64_t next_request_id()
{
    return sg().next_request_id.fetch_add(1, std::memory_order_relaxed);
}

constexpr int kToolListWaitMaxMs = 5000;
constexpr int kLaunchWaitMinMs = 5000;
constexpr int kLaunchWaitMaxMs = 120000;
constexpr int kBundledVisibleLaunchWaitMinMs = 70000;
constexpr int kTestLabLaunchWaitDefaultMs = 15000;
constexpr int kTestLabLaunchWaitMaxMs = 15000;
constexpr int kReadinessProbeTimeoutMs = 10000;
constexpr int kNavigationWaitMaxMs = 50000;
constexpr uint64_t kPythonDiscoveryBudgetMs = 15000;
constexpr uint64_t kActivityDrainWaitMs = 45000;
thread_local uint32_t g_bridge_activity_depth = 0;

const char* safe_reason(const char* reason)
{
    return (reason && reason[0]) ? reason : "unspecified";
}

std::atomic<bool>& prewarm_default_requested()
{
    static std::atomic<bool> requested{false};
    return requested;
}

bool prewarm_default_disabled()
{
    char value[32] = {};
    DWORD n = GetEnvironmentVariableA("AIDA_CAMOUFOX_PREWARM", value, static_cast<DWORD>(sizeof(value)));
    if (n == 0) return false;
    value[sizeof(value) - 1] = '\0';
    return _stricmp(value, "0") == 0 ||
           _stricmp(value, "false") == 0 ||
           _stricmp(value, "no") == 0 ||
           _stricmp(value, "off") == 0 ||
           _stricmp(value, "disabled") == 0;
}

bool env_flag_enabled_a(const char* name)
{
    if (!name || !name[0]) return false;
    char value[32] = {};
    DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
    if (n == 0 || n >= static_cast<DWORD>(sizeof(value))) return false;
    value[sizeof(value) - 1] = '\0';
    return _stricmp(value, "1") == 0 ||
           _stricmp(value, "true") == 0 ||
           _stricmp(value, "yes") == 0 ||
           _stricmp(value, "on") == 0;
}

int env_int_a(const char* name, int fallback)
{
    if (!name || !name[0]) return fallback;
    char value[32] = {};
    DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
    if (n == 0 || n >= static_cast<DWORD>(sizeof(value))) return fallback;
    value[sizeof(value) - 1] = '\0';
    char* end = nullptr;
    long parsed = std::strtol(value, &end, 10);
    if (end == value) return fallback;
    while (end && *end)
    {
        if (*end != ' ' && *end != '\t') return fallback;
        ++end;
    }
    if (parsed < 0 || parsed > 1000000) return fallback;
    return static_cast<int>(parsed);
}

bool read_env_path_a(const char* name, std::string& out)
{
    out.clear();
    if (!name || !name[0]) return false;
    DWORD need = GetEnvironmentVariableA(name, nullptr, 0);
    if (need == 0 || need > 32768) return false;
    std::string value;
    value.resize(need);
    DWORD got = GetEnvironmentVariableA(name, value.data(), need);
    if (got == 0 || got >= need) return false;
    value.resize(got);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '"'))
        value.erase(value.begin());
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '"'))
        value.pop_back();
    if (value.empty()) return false;
    out = value;
    return true;
}

bool env_path_configured_a(const char* name)
{
    std::string value;
    return read_env_path_a(name, value);
}

bool read_env_path_w(const wchar_t* name, std::wstring& out)
{
    out.clear();
    if (!name || !name[0]) return false;
    DWORD need = GetEnvironmentVariableW(name, nullptr, 0);
    if (need == 0 || need > 32768) return false;
    std::wstring value;
    value.resize(need);
    DWORD got = GetEnvironmentVariableW(name, value.data(), need);
    if (got == 0 || got >= need) return false;
    value.resize(got);
    while (!value.empty() && (value.front() == L' ' || value.front() == L'\t' || value.front() == L'"'))
        value.erase(value.begin());
    while (!value.empty() && (value.back() == L' ' || value.back() == L'\t' || value.back() == L'"'))
        value.pop_back();
    if (value.empty()) return false;
    out = value;
    return true;
}

bool system_python_discovery_allowed()
{
    return env_flag_enabled_a("AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON");
}

void enforce_private_launch_config(launch_config_t& cfg)
{
    cfg.block_webrtc = true;
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

bool directory_exists_w(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

struct executable_image_probe_t
{
    DWORD machine = 0;
    LARGE_INTEGER size{};
};

bool probe_executable_image_w(const std::wstring& path, executable_image_probe_t& out, DWORD& gle)
{
    out = {};
    gle = ERROR_SUCCESS;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        gle = GetLastError();
        return false;
    }

    auto close_fail = [&](DWORD err) {
        CloseHandle(h);
        gle = err;
        return false;
    };

    if (!GetFileSizeEx(h, &out.size))
        return close_fail(GetLastError());
    if (out.size.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)))
        return close_fail(ERROR_BAD_EXE_FORMAT);

    IMAGE_DOS_HEADER dos{};
    DWORD read = 0;
    if (!ReadFile(h, &dos, static_cast<DWORD>(sizeof(dos)), &read, nullptr))
        return close_fail(GetLastError());
    if (read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return close_fail(ERROR_BAD_EXE_FORMAT);

    const LONGLONG nt_min = static_cast<LONGLONG>(sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    if (dos.e_lfanew <= 0 || static_cast<LONGLONG>(dos.e_lfanew) > out.size.QuadPart - nt_min)
        return close_fail(ERROR_BAD_EXE_FORMAT);

    LARGE_INTEGER pos{};
    pos.QuadPart = dos.e_lfanew;
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
        return close_fail(GetLastError());

    struct nt_probe_t
    {
        DWORD signature = 0;
        IMAGE_FILE_HEADER file_header{};
    } nt_probe;

    read = 0;
    if (!ReadFile(h, &nt_probe, static_cast<DWORD>(sizeof(nt_probe)), &read, nullptr))
        return close_fail(GetLastError());
    if (read != sizeof(nt_probe) || nt_probe.signature != IMAGE_NT_SIGNATURE)
        return close_fail(ERROR_BAD_EXE_FORMAT);
    if (nt_probe.file_header.Machine != IMAGE_FILE_MACHINE_I386 &&
        nt_probe.file_header.Machine != IMAGE_FILE_MACHINE_AMD64)
        return close_fail(ERROR_BAD_EXE_FORMAT);

    out.machine = nt_probe.file_header.Machine;
    CloseHandle(h);
    return true;
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

void append_path_and_ancestors(std::vector<std::wstring>& paths, const std::wstring& path, size_t depth)
{
    std::wstring current = path;
    for (size_t i = 0; i < depth && !current.empty(); ++i)
    {
        append_unique_path(paths, current);
        current = parent_dir_w(current);
    }
}

void append_env_path_roots(std::vector<std::wstring>& paths, const wchar_t* name, size_t depth)
{
    std::wstring value;
    if (read_env_path_w(name, value))
        append_path_and_ancestors(paths, value, depth);
}

void append_camoufox_sidecar_roots(std::vector<std::wstring>& paths)
{
    append_env_path_roots(paths, L"AIDA_CAMOUFOX_EXECUTABLE", 6);
    append_env_path_roots(paths, L"AIDA_CAMOUFOX_PYTHON", 6);
    append_env_path_roots(paths, L"AIDA_CAMOUFOX_MCP_EXECUTABLE", 6);
    wchar_t local[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (got != 0 && got < MAX_PATH)
    {
        std::wstring aida_root = join_path_w(local, L"AiDA");
        append_unique_path(paths, aida_root);
        append_unique_path(paths, join_path_w(join_path_w(aida_root, L"camoufox"), L"current"));
        append_unique_path(paths, join_path_w(join_path_w(join_path_w(aida_root, L"embedded"), L"camoufox"), L"current"));
    }
    std::vector<wchar_t> temp(32768);
    DWORD temp_len = GetTempPathW(static_cast<DWORD>(temp.size()), temp.data());
    if (temp_len != 0 && temp_len < static_cast<DWORD>(temp.size()))
    {
        std::wstring temp_root(temp.data(), temp_len);
        append_unique_path(paths, join_path_w(temp_root, L"AiDA"));
        append_unique_path(paths, join_path_w(join_path_w(temp_root, L"AiDA"), L"camoufox"));
        append_unique_path(paths, join_path_w(join_path_w(join_path_w(temp_root, L"AiDA"), L"camoufox"), L"current"));
        append_unique_path(paths, join_path_w(temp_root, L"aida-camoufox"));
        append_unique_path(paths, join_path_w(join_path_w(temp_root, L"aida-camoufox"), L"current"));
    }
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
    append_camoufox_sidecar_roots(bases);
    std::wstring exe_dir = executable_dir_w();
    append_unique_path(bases, exe_dir);
    append_unique_path(bases, current_dir_w());
    append_unique_path(bases, parent_dir_w(exe_dir));
    append_unique_path(bases, parent_dir_w(parent_dir_w(exe_dir)));
    wchar_t local[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (got != 0 && got < MAX_PATH)
    {
        append_unique_path(bases, join_path_w(join_path_w(join_path_w(local, L"AiDA"), L"camoufox"), L"current"));
        append_unique_path(bases, join_path_w(join_path_w(join_path_w(join_path_w(local, L"AiDA"), L"embedded"), L"camoufox"), L"current"));
    }
    return bases;
}

std::vector<std::wstring> aida_runtime_base_dirs()
{
    std::vector<std::wstring> bases;
    append_camoufox_sidecar_roots(bases);
    std::wstring exe_dir = executable_dir_w();
    append_unique_path(bases, exe_dir);
    append_unique_path(bases, current_dir_w());
    append_unique_path(bases, parent_dir_w(exe_dir));
    append_unique_path(bases, parent_dir_w(parent_dir_w(exe_dir)));
    wchar_t local[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (got != 0 && got < MAX_PATH)
    {
        std::wstring aida_root = join_path_w(local, L"AiDA");
        append_unique_path(bases, aida_root);
        append_unique_path(bases, join_path_w(aida_root, L"current"));
        append_unique_path(bases, join_path_w(aida_root, L"runtime"));
        append_unique_path(bases, join_path_w(aida_root, L"embedded"));
    }
    return bases;
}

bool is_bundled_browser_dir(const std::wstring& dir)
{
    return path_exists_w(join_path_w(dir, L"camoufox.exe")) &&
        path_exists_w(join_path_w(dir, L"application.ini")) &&
        directory_exists_w(join_path_w(dir, L"browser"));
}

bool find_bundled_camoufox_executable(std::string& out_path)
{
    const std::wstring name = L"camoufox-135.0.1-beta.24-win.x86_64";
    const auto bases = runtime_base_dirs();
    for (const auto& base : bases)
    {
        std::wstring candidate_dir = base;
        if (is_bundled_browser_dir(candidate_dir))
        {
            const std::wstring candidate = join_path_w(candidate_dir, L"camoufox.exe");
            out_path = wide_to_utf8(candidate);
            diag::log_tagged_fmt("camoufox", "bundled_browser_executable selected path=%s base=%s",
                out_path.c_str(), wide_to_utf8(base).c_str());
            return !out_path.empty();
        }
        candidate_dir = join_path_w(join_path_w(base, L"deps"), name);
        if (is_bundled_browser_dir(candidate_dir))
        {
            const std::wstring candidate = join_path_w(candidate_dir, L"camoufox.exe");
            out_path = wide_to_utf8(candidate);
            diag::log_tagged_fmt("camoufox", "bundled_browser_executable selected path=%s base=%s",
                out_path.c_str(), wide_to_utf8(base).c_str());
            return !out_path.empty();
        }
        candidate_dir = join_path_w(base, name);
        if (is_bundled_browser_dir(candidate_dir))
        {
            const std::wstring candidate = join_path_w(candidate_dir, L"camoufox.exe");
            out_path = wide_to_utf8(candidate);
            diag::log_tagged_fmt("camoufox", "bundled_browser_executable selected path=%s base=%s",
                out_path.c_str(), wide_to_utf8(base).c_str());
            return !out_path.empty();
        }
    }
    diag::log_tagged_fmt("camoufox", "bundled_browser_executable missing base_count=%zu", bases.size());
    return false;
}

bool find_bundled_reverse_mcp_executable(std::string& out_path)
{
    const std::vector<std::wstring> rels = {
        L".deps\\AiDA_CamoufoxReverseMcp.exe",
        L".deps\\camoufox-reverse-mcp.exe",
        L".deps\\camoufox_reverse_mcp.exe",
        L"deps\\AiDA_CamoufoxReverseMcp.exe",
        L"deps\\camoufox-reverse-mcp.exe",
        L"deps\\camoufox_reverse_mcp.exe",
        L"deps\\camoufox-reverse-mcp\\AiDA_CamoufoxReverseMcp.exe",
        L"deps\\camoufox-reverse-mcp\\camoufox-reverse-mcp.exe",
        L"AiDA_CamoufoxReverseMcp.exe",
        L"camoufox-reverse-mcp.exe",
        L"camoufox_reverse_mcp.exe",
    };
    const auto bases = aida_runtime_base_dirs();
    for (const auto& base : bases)
    {
        for (const auto& rel : rels)
        {
            const std::wstring candidate = join_path_w(base, rel);
            if (path_exists_w(candidate))
            {
                out_path = wide_to_utf8(candidate);
                diag::log_tagged_fmt("camoufox", "bundled_reverse_mcp_executable selected path=%s base=%s rel=%s",
                    out_path.c_str(), wide_to_utf8(base).c_str(), wide_to_utf8(rel).c_str());
                return !out_path.empty();
            }
        }
    }
    diag::log_tagged_fmt("camoufox", "bundled_reverse_mcp_executable missing base_count=%zu rel_count=%zu",
        bases.size(), rels.size());
    return false;
}

bool resolve_reverse_mcp_executable(const launch_config_t& cfg, std::string& out_path)
{
    out_path.clear();
    if (!cfg.server_executable.empty())
        out_path = cfg.server_executable;
    if (out_path.empty())
        read_env_path_a("AIDA_CAMOUFOX_MCP_EXECUTABLE", out_path);
    if (out_path.empty())
        find_bundled_reverse_mcp_executable(out_path);
    if (out_path.empty())
        return false;
    DWORD attr = GetFileAttributesW(utf8_to_wide(out_path).c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        diag::log_tagged_fmt("camoufox", "reverse_mcp_executable rejected path=%s attr=0x%08lX",
            out_path.c_str(), static_cast<unsigned long>(attr));
        out_path.clear();
        return false;
    }
    return true;
}

bool should_prefer_developer_python_runtime(const launch_config_t& cfg)
{
    if (env_flag_enabled_a("AIDA_FILELESS_LAUNCH"))
        return false;
    if (!cfg.server_executable.empty())
        return false;
    if (env_path_configured_a("AIDA_CAMOUFOX_MCP_EXECUTABLE"))
        return false;
    return true;
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
        L"deps\\runtimes\\python\\Python312-3.12.10-x64\\python.exe",
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
        L"runtimes\\python\\Python312-3.12.10-x64\\python.exe"
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

std::wstring normalized_lower_path(std::wstring value)
{
    for (wchar_t& c : value)
    {
        if (c == L'/') c = L'\\';
        c = static_cast<wchar_t>(std::towlower(c));
    }
    while (!value.empty() && (value.back() == L'\\' || value.back() == L'/'))
        value.pop_back();
    return value;
}

bool path_under_root_w(const std::wstring& path, const std::wstring& root)
{
    std::wstring p = normalized_lower_path(path);
    std::wstring r = normalized_lower_path(root);
    if (p.empty() || r.empty() || p.size() <= r.size())
        return false;
    return p.compare(0, r.size(), r) == 0 && p[r.size()] == L'\\';
}

std::wstring camoufox_profile_root_w()
{
    std::wstring root = local_appdata_aida_root();
    if (root.empty()) root = executable_dir_w();
    if (root.empty()) root = current_dir_w();
    if (root.empty()) return {};
    return join_path_w(root, L"camoufox-profiles");
}

bool remove_directory_tree_w(const std::wstring& dir, uint32_t& files_removed, uint32_t& dirs_removed)
{
    DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
        return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    if ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return DeleteFileW(dir.c_str()) != FALSE;
    std::wstring pattern = join_path_w(dir, L"*");
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
        do
        {
            const std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..")
                continue;
            const std::wstring child = join_path_w(dir, name);
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                if (!remove_directory_tree_w(child, files_removed, dirs_removed))
                {
                    FindClose(h);
                    return false;
                }
            }
            else
            {
                SetFileAttributesW(child.c_str(), fd.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY);
                if (!DeleteFileW(child.c_str()))
                {
                    FindClose(h);
                    return false;
                }
                ++files_removed;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    SetFileAttributesW(dir.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
    if (!RemoveDirectoryW(dir.c_str()))
        return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    ++dirs_removed;
    return true;
}

void purge_generated_profile_dir(const std::string& profile_dir, const std::string& reason)
{
    if (profile_dir.empty())
        return;
    const std::wstring profile_w = utf8_to_wide(profile_dir);
    const std::wstring root_w = camoufox_profile_root_w();
    if (profile_w.empty() || root_w.empty() || !path_under_root_w(profile_w, root_w))
    {
        diag::log_tagged_fmt("camoufox", "profile_cleanup refused reason=%s profile_dir=%s root=%s",
            reason.c_str(), profile_dir.c_str(), wide_to_utf8(root_w).c_str());
        return;
    }
    uint32_t files_removed = 0;
    uint32_t dirs_removed = 0;
    const uint64_t t0 = now_ms();
    const bool ok = remove_directory_tree_w(profile_w, files_removed, dirs_removed);
    const DWORD gle = ok ? 0 : GetLastError();
    diag::log_tagged_fmt("camoufox", "profile_cleanup result=%d gle=%lu reason=%s profile_dir=%s files=%lu dirs=%lu elapsed_ms=%llu",
        ok ? 1 : 0,
        static_cast<unsigned long>(gle),
        reason.c_str(),
        profile_dir.c_str(),
        static_cast<unsigned long>(files_removed),
        static_cast<unsigned long>(dirs_removed),
        static_cast<unsigned long long>(now_ms() - t0));
}

bool is_app_controlled_python_path(const std::string& path)
{
    std::wstring w = utf8_to_wide(path);
    if (w.empty()) return false;
    for (const auto& base : runtime_base_dirs())
    {
        if (path_under_root_w(w, base))
            return true;
    }
    std::wstring app_root = local_appdata_aida_root();
    if (!app_root.empty() && path_under_root_w(w, app_root))
        return true;
    return false;
}

std::wstring parent_directory_w(std::wstring path)
{
    for (wchar_t& c : path)
    {
        if (c == L'/') c = L'\\';
    }
    while (!path.empty() && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return {};
    return path.substr(0, slash);
}

std::wstring quote_arg_w(const std::wstring& value)
{
    std::wstring out;
    out.reserve(value.size() + 2);
    out.push_back(L'"');
    for (wchar_t ch : value)
    {
        if (ch == L'"')
            out.push_back(L'\\');
        out.push_back(ch);
    }
    out.push_back(L'"');
    return out;
}

std::string compact_child_output_tail(std::string s, size_t limit);

bool spawn_capture_impl(const std::wstring& application_path, std::wstring cmdline, const std::wstring& working_directory, const char* label, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout)
{
    out_exit_code = 0;
    out_stdout.clear();
    const char* spawn_label = (label && label[0]) ? label : "process";
    const std::string app_log = application_path.empty() ? std::string("<cmdline>") : wide_to_utf8(application_path);
    const std::string cwd_log = working_directory.empty() ? std::string("<inherit>") : wide_to_utf8(working_directory);
    const uint64_t t0 = now_ms();
    DWORD app_attr = INVALID_FILE_ATTRIBUTES;
    DWORD cwd_attr = INVALID_FILE_ATTRIBUTES;
    if (!application_path.empty())
        app_attr = GetFileAttributesW(application_path.c_str());
    if (!working_directory.empty())
        cwd_attr = GetFileAttributesW(working_directory.c_str());
    diag::log_tagged_fmt("camoufox", "spawn_capture entry label=%s app=%s cwd=%s app_exists=%d cwd_exists=%d cmd_len=%zu timeout_ms=%lu",
        spawn_label,
        app_log.c_str(),
        cwd_log.c_str(),
        static_cast<int>(application_path.empty() || (app_attr != INVALID_FILE_ATTRIBUTES && (app_attr & FILE_ATTRIBUTE_DIRECTORY) == 0)),
        static_cast<int>(working_directory.empty() || (cwd_attr != INVALID_FILE_ATTRIBUTES && (cwd_attr & FILE_ATTRIBUTE_DIRECTORY) != 0)),
        cmdline.size(),
        static_cast<unsigned long>(timeout_ms));

    SECURITY_ATTRIBUTES sa{};
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0))
    {
        const DWORD gle = GetLastError();
        out_stdout = "spawn pipe create failed gle=" + std::to_string(gle);
        diag::log_tagged_fmt("camoufox", "spawn_capture pipe_create_failed label=%s gle=%lu cmd_len=%zu timeout_ms=%lu elapsed_ms=%llu",
            spawn_label, gle, cmdline.size(), static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        return false;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    HANDLE child_stdin = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (child_stdin == INVALID_HANDLE_VALUE)
    {
        const DWORD gle = GetLastError();
        out_stdout = "spawn stdin create failed gle=" + std::to_string(gle);
        diag::log_tagged_fmt("camoufox", "spawn_capture stdin_create_failed label=%s gle=%lu elapsed_ms=%llu",
            spawn_label, gle, static_cast<unsigned long long>(now_ms() - t0));
        CloseHandle(wr);
        CloseHandle(rd);
        return false;
    }

    STARTUPINFOEXW sx{};
    sx.StartupInfo.cb         = sizeof(sx);
    sx.StartupInfo.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    sx.StartupInfo.hStdOutput = wr;
    sx.StartupInfo.hStdError  = wr;
    sx.StartupInfo.hStdInput  = child_stdin;
    sx.StartupInfo.wShowWindow = SW_HIDE;

    SIZE_T attr_bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_bytes);
    std::vector<uint8_t> attr_storage;
    bool attr_ready = false;
    if (attr_bytes != 0)
    {
        attr_storage.resize(attr_bytes);
        sx.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_storage.data());
        if (InitializeProcThreadAttributeList(sx.lpAttributeList, 1, 0, &attr_bytes))
        {
            HANDLE inherited_handles[] = { wr, child_stdin };
            if (UpdateProcThreadAttribute(
                    sx.lpAttributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    inherited_handles,
                    sizeof(inherited_handles),
                    nullptr,
                    nullptr))
            {
                attr_ready = true;
            }
            else
            {
                const DWORD gle = GetLastError();
                diag::log_tagged_fmt("camoufox", "spawn_capture handle_list_update_failed label=%s gle=%lu",
                    spawn_label, gle);
                DeleteProcThreadAttributeList(sx.lpAttributeList);
                sx.lpAttributeList = nullptr;
            }
        }
        else
        {
            const DWORD gle = GetLastError();
            diag::log_tagged_fmt("camoufox", "spawn_capture handle_list_init_failed label=%s gle=%lu",
                spawn_label, gle);
            sx.lpAttributeList = nullptr;
        }
    }
    if (!attr_ready)
    {
        out_stdout = "spawn handle inheritance isolation failed";
        diag::log_tagged_fmt("camoufox", "spawn_capture handle_list_unavailable label=%s elapsed_ms=%llu",
            spawn_label, static_cast<unsigned long long>(now_ms() - t0));
        CloseHandle(wr);
        CloseHandle(child_stdin);
        CloseHandle(rd);
        return false;
    }

    PROCESS_INFORMATION pi{};
    DWORD create_flags = CREATE_NO_WINDOW;
    create_flags |= EXTENDED_STARTUPINFO_PRESENT;
    sx.StartupInfo.cb = sizeof(sx);
    const uint64_t create_t0 = now_ms();
    diag::log_tagged_fmt("camoufox", "spawn_capture create_begin label=%s app=%s cwd=%s cmd_len=%zu timeout_ms=%lu handle_list=%d elapsed_ms=%llu",
        spawn_label,
        app_log.c_str(),
        cwd_log.c_str(),
        cmdline.size(),
        static_cast<unsigned long>(timeout_ms),
        attr_ready ? 1 : 0,
        static_cast<unsigned long long>(create_t0 - t0));
    std::wstring primary_cmdline = cmdline;
    BOOL ok = CreateProcessW(
        application_path.empty() ? nullptr : application_path.c_str(),
        primary_cmdline.empty() ? nullptr : primary_cmdline.data(),
        nullptr,
        nullptr,
        TRUE,
        create_flags,
        nullptr,
        working_directory.empty() ? nullptr : working_directory.c_str(),
        &sx.StartupInfo,
        &pi);
    DWORD create_gle = ok ? 0 : GetLastError();
    diag::log_tagged_fmt("camoufox", "spawn_capture create_result label=%s ok=%d gle=%lu elapsed_ms=%llu create_elapsed_ms=%llu cmd_len=%zu",
        spawn_label,
        ok ? 1 : 0,
        create_gle,
        static_cast<unsigned long long>(now_ms() - t0),
        static_cast<unsigned long long>(now_ms() - create_t0),
        cmdline.size());
    if (attr_ready)
        DeleteProcThreadAttributeList(sx.lpAttributeList);
    if (!ok && create_gle == ERROR_INVALID_PARAMETER)
    {
        STARTUPINFOW si{};
        si.cb         = sizeof(si);
        si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = wr;
        si.hStdError  = wr;
        si.hStdInput  = child_stdin;
        si.wShowWindow = SW_HIDE;
        const uint64_t fallback_t0 = now_ms();
        std::wstring fallback_cmdline = cmdline;
        SetLastError(0);
        ok = CreateProcessW(
            application_path.empty() ? nullptr : application_path.c_str(),
            fallback_cmdline.empty() ? nullptr : fallback_cmdline.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            working_directory.empty() ? nullptr : working_directory.c_str(),
            &si,
            &pi);
        create_gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("camoufox", "spawn_capture fallback_create_result label=%s ok=%d gle=%lu elapsed_ms=%llu fallback_elapsed_ms=%llu cmd_len=%zu",
            spawn_label,
            ok ? 1 : 0,
            create_gle,
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<unsigned long long>(now_ms() - fallback_t0),
            cmdline.size());
    }
    CloseHandle(wr);
    CloseHandle(child_stdin);
    if (!ok)
    {
        out_stdout = "spawn create failed gle=" + std::to_string(create_gle);
        diag::log_tagged_fmt("camoufox", "spawn_capture create_failed label=%s gle=%lu app=%s cwd=%s cmd_len=%zu timeout_ms=%lu elapsed_ms=%llu",
            spawn_label, create_gle, app_log.c_str(), cwd_log.c_str(), cmdline.size(),
            static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        CloseHandle(rd);
        return false;
    }
    diag::log_tagged_fmt("camoufox", "spawn_capture process_started label=%s pid=%lu cmd_len=%zu timeout_ms=%lu elapsed_ms=%llu",
        spawn_label, static_cast<unsigned long>(pi.dwProcessId), cmdline.size(),
        static_cast<unsigned long>(timeout_ms), static_cast<unsigned long long>(now_ms() - t0));
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
            diag::log_tagged_fmt("camoufox", "spawn_capture timeout label=%s pid=%lu elapsed_ms=%lu cmd_len=%zu captured_len=%zu tail=%.600s",
                spawn_label, static_cast<unsigned long>(pi.dwProcessId),
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
    diag::log_tagged_fmt("camoufox", "spawn_capture exit label=%s pid=%lu code=%lu cmd_len=%zu captured_len=%zu elapsed_ms=%llu tail=%.600s",
        spawn_label, static_cast<unsigned long>(pi.dwProcessId), out_exit_code, cmdline.size(), out_stdout.size(),
        static_cast<unsigned long long>(now_ms() - t0),
        compact_child_output_tail(out_stdout, 600).c_str());
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return true;
}

bool spawn_capture(const std::string& cmdline, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout)
{
    return spawn_capture_impl({}, utf8_to_wide(cmdline), {}, "cmdline", timeout_ms, out_exit_code, out_stdout);
}

bool spawn_python_capture(const std::string& python_path, const std::wstring& args, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout, const char* label)
{
    std::wstring app = utf8_to_wide(python_path);
    std::wstring cmdline = quote_arg_w(app);
    if (!args.empty())
    {
        cmdline.push_back(L' ');
        cmdline.append(args);
    }
    return spawn_capture_impl(app, std::move(cmdline), parent_directory_w(app), label, timeout_ms, out_exit_code, out_stdout);
}

bool spawn_executable_capture(const std::string& executable_path, const std::wstring& args, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_stdout, const char* label)
{
    std::wstring app = utf8_to_wide(executable_path);
    std::wstring cmdline = quote_arg_w(app);
    if (!args.empty())
    {
        cmdline.push_back(L' ');
        cmdline.append(args);
    }
    return spawn_capture_impl(app, std::move(cmdline), parent_directory_w(app), label, timeout_ms, out_exit_code, out_stdout);
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

std::string read_file_tail_for_log(const std::string& path, size_t max_bytes)
{
    if (path.empty() || max_bytes == 0)
        return {};
    std::wstring wpath = utf8_to_wide(path);
    if (wpath.empty())
        return {};
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return {};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0)
    {
        CloseHandle(h);
        return {};
    }
    const uint64_t total = static_cast<uint64_t>(size.QuadPart);
    const uint64_t take = std::min<uint64_t>(total, static_cast<uint64_t>(max_bytes));
    LARGE_INTEGER pos{};
    pos.QuadPart = static_cast<LONGLONG>(total - take);
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
    {
        CloseHandle(h);
        return {};
    }
    std::string out;
    out.resize(static_cast<size_t>(take));
    DWORD got = 0;
    BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &got, nullptr);
    CloseHandle(h);
    if (!ok || got == 0)
        return {};
    out.resize(got);
    return compact_child_output_tail(out, max_bytes);
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

struct process_tree_entry_t
{
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    std::string exe;
};

struct process_tree_reap_result_t
{
    size_t before = 0;
    size_t descendants_before = 0;
    size_t after = 0;
    size_t alive_after = 0;
    uint64_t elapsed_ms = 0;
};

bool contains_process_pid(const std::vector<process_tree_entry_t>& entries, uint32_t pid)
{
    for (const auto& entry : entries)
    {
        if (entry.pid == pid)
            return true;
    }
    return false;
}

std::string compact_process_tree(const std::vector<process_tree_entry_t>& entries)
{
    std::ostringstream oss;
    const size_t limit = std::min<size_t>(entries.size(), 32);
    for (size_t i = 0; i < limit; ++i)
    {
        if (i) oss << ",";
        oss << entries[i].pid << "<-" << entries[i].parent_pid;
        if (!entries[i].exe.empty())
            oss << ":" << entries[i].exe;
    }
    if (entries.size() > limit)
        oss << ",...";
    return oss.str();
}

std::vector<process_tree_entry_t> enumerate_process_tree(uint32_t root_pid)
{
    std::vector<process_tree_entry_t> all;
    std::vector<process_tree_entry_t> tree;
    if (root_pid == 0)
        return tree;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        diag::log_tagged_fmt("camoufox", "process_tree_snapshot_failed root_pid=%lu gle=%lu",
            static_cast<unsigned long>(root_pid), static_cast<unsigned long>(GetLastError()));
        tree.push_back({root_pid, 0, std::string()});
        return tree;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            process_tree_entry_t entry;
            entry.pid = static_cast<uint32_t>(pe.th32ProcessID);
            entry.parent_pid = static_cast<uint32_t>(pe.th32ParentProcessID);
            entry.exe = wide_to_utf8(pe.szExeFile);
            all.push_back(std::move(entry));
        } while (Process32NextW(snapshot, &pe));
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "process_tree_process32first_failed root_pid=%lu gle=%lu",
            static_cast<unsigned long>(root_pid), static_cast<unsigned long>(GetLastError()));
    }
    CloseHandle(snapshot);

    for (const auto& entry : all)
    {
        if (entry.pid == root_pid)
        {
            tree.push_back(entry);
            break;
        }
    }
    if (tree.empty())
        tree.push_back({root_pid, 0, std::string()});

    for (size_t i = 0; i < tree.size(); ++i)
    {
        const uint32_t parent = tree[i].pid;
        for (const auto& entry : all)
        {
            if (entry.parent_pid == parent && !contains_process_pid(tree, entry.pid))
                tree.push_back(entry);
        }
    }
    return tree;
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
    sg().active_page_id.clear();
    sg().active_page_url.clear();
    sg().active_page_title.clear();
    sg().pages.clear();
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

bool test_lab_launch_fail_fast_enabled(const launch_config_t& cfg)
{
    return cfg.testlab_fast_probe || env_flag_enabled_a("AIDA_CAMOUFOX_TESTLAB_FAST_PROBE");
}

int test_lab_launch_wait_ms(const launch_config_t& cfg)
{
    int wait_ms = env_int_a("AIDA_CAMOUFOX_TESTLAB_LAUNCH_MS", 0);
    if (wait_ms <= 0)
        wait_ms = cfg.launch_timeout_ms > 0 ? cfg.launch_timeout_ms : kTestLabLaunchWaitDefaultMs;
    if (wait_ms < kLaunchWaitMinMs) wait_ms = kLaunchWaitMinMs;
    if (wait_ms > kTestLabLaunchWaitMaxMs) wait_ms = kTestLabLaunchWaitMaxMs;
    return wait_ms;
}

int effective_launch_wait_ms(const launch_config_t& cfg, bool bundled_visible_launch)
{
    if (test_lab_launch_fail_fast_enabled(cfg))
        return test_lab_launch_wait_ms(cfg);
    int wait_ms = clamp_launch_wait_ms(cfg.launch_timeout_ms);
    if (bundled_visible_launch && wait_ms < kBundledVisibleLaunchWaitMinMs)
        wait_ms = kBundledVisibleLaunchWaitMinMs;
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
    const uint64_t t0 = now_ms();
    major = 0;
    minor = 0;
    detail.clear();
    diag::log_tagged_fmt("camoufox", "python_version_probe begin path=%s timeout_ms=3000",
        python_path.c_str());
    DWORD code = 0;
    std::string captured;
    if (!spawn_python_capture(python_path, L"-I -S -c \"import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')\"", 3000, code, captured, "python_version_probe"))
    {
        detail = "version probe timed out or failed to spawn";
        diag::log_tagged_fmt("camoufox", "python_version_probe spawn_failed path=%s elapsed_ms=%llu detail=%s",
            python_path.c_str(), static_cast<unsigned long long>(now_ms() - t0),
            compact_child_output(captured).c_str());
        return false;
    }
    if (code != 0)
    {
        detail = compact_child_output(captured);
        if (detail.empty()) detail = "version probe exit=" + std::to_string(code);
        diag::log_tagged_fmt("camoufox", "python_version_probe exit_failed path=%s code=%lu elapsed_ms=%llu detail=%s",
            python_path.c_str(), static_cast<unsigned long>(code),
            static_cast<unsigned long long>(now_ms() - t0), detail.c_str());
        return false;
    }
    int maj = 0;
    int min = 0;
    if (sscanf_s(captured.c_str(), "%d.%d", &maj, &min) != 2)
    {
        detail = compact_child_output(captured);
        if (detail.empty()) detail = "version probe returned no version";
        diag::log_tagged_fmt("camoufox", "python_version_probe parse_failed path=%s elapsed_ms=%llu detail=%s",
            python_path.c_str(), static_cast<unsigned long long>(now_ms() - t0),
            detail.c_str());
        return false;
    }
    major = maj;
    minor = min;
    detail = compact_child_output(captured);
    diag::log_tagged_fmt("camoufox", "python_version_probe ok path=%s version=%d.%d elapsed_ms=%llu detail=%s",
        python_path.c_str(), major, minor, static_cast<unsigned long long>(now_ms() - t0),
        detail.c_str());
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
    if (!post_bridge_task("camoufox.disconnect", disconnect_task)) {
        diag::log_tagged_fmt("camoufox", "disconnect_async_post_failed reason=%s",
            reason.c_str());
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

void terminate_process_id_sync(uint32_t pid, const std::string& reason, uint32_t parent_pid = 0, const std::string& exe = std::string())
{
    if (pid == 0) return;
    const uint64_t t0 = now_ms();
    DWORD before_exit = 0;
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) {
        diag::log_tagged_fmt("camoufox", "terminate_process open_failed pid=%lu parent_pid=%lu exe=%s reason=%s gle=%lu",
            static_cast<unsigned long>(pid), static_cast<unsigned long>(parent_pid), exe.c_str(),
            reason.c_str(), static_cast<unsigned long>(GetLastError()));
        return;
    }
    BOOL before_ok = GetExitCodeProcess(h, &before_exit);
    bool already_exited = before_ok && before_exit != STILL_ACTIVE;
    BOOL ok = already_exited ? TRUE : TerminateProcess(h, 1);
    DWORD gle = ok ? 0 : GetLastError();
    DWORD wait_rc = already_exited ? WAIT_OBJECT_0 : WaitForSingleObject(h, 3000);
    DWORD after_exit = 0;
    BOOL after_ok = GetExitCodeProcess(h, &after_exit);
    CloseHandle(h);
    diag::log_tagged_fmt("camoufox", "terminate_process pid=%lu parent_pid=%lu exe=%s reason=%s already_exited=%d before_ok=%d before_exit=%lu ok=%d gle=%lu wait_rc=%lu after_ok=%d after_exit=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(pid), static_cast<unsigned long>(parent_pid), exe.c_str(), reason.c_str(),
        already_exited ? 1 : 0, before_ok ? 1 : 0, static_cast<unsigned long>(before_ok ? before_exit : 0),
        ok ? 1 : 0, static_cast<unsigned long>(gle), static_cast<unsigned long>(wait_rc),
        after_ok ? 1 : 0, static_cast<unsigned long>(after_ok ? after_exit : 0),
        static_cast<unsigned long long>(now_ms() - t0));
}

process_tree_reap_result_t terminate_process_tree_sync(uint32_t root_pid, const std::string& reason)
{
    process_tree_reap_result_t result;
    if (root_pid == 0)
        return result;
    const uint64_t t0 = now_ms();
    std::vector<process_tree_entry_t> tree = enumerate_process_tree(root_pid);
    result.before = tree.size();
    result.descendants_before = tree.size() > 0 ? tree.size() - 1 : 0;
    diag::log_tagged_fmt("camoufox", "process_tree_reap_begin root_pid=%lu reason=%s count=%zu entries=%s",
        static_cast<unsigned long>(root_pid), reason.c_str(), tree.size(), compact_process_tree(tree).c_str());
    for (auto it = tree.rbegin(); it != tree.rend(); ++it)
        terminate_process_id_sync(it->pid, reason, it->parent_pid, it->exe);
    std::vector<process_tree_entry_t> remaining = enumerate_process_tree(root_pid);
    size_t alive_remaining = 0;
    for (const auto& entry : remaining)
    {
        if (process_alive(entry.pid))
            ++alive_remaining;
    }
    result.after = remaining.size();
    result.alive_after = alive_remaining;
    result.elapsed_ms = now_ms() - t0;
    diag::log_tagged_fmt("camoufox", "process_tree_reap_end root_pid=%lu reason=%s before=%zu after=%zu alive_after=%zu entries_after=%s elapsed_ms=%llu",
        static_cast<unsigned long>(root_pid), reason.c_str(), tree.size(), remaining.size(), alive_remaining,
        compact_process_tree(remaining).c_str(), static_cast<unsigned long long>(result.elapsed_ms));
    return result;
}

void terminate_process_id_async(uint32_t pid, const std::string& reason)
{
    if (pid == 0) return;
    auto terminate_task = [pid, reason]() {
        terminate_process_tree_sync(pid, reason);
    };
    if (!post_bridge_task("camoufox.terminate", terminate_task)) {
        diag::log_tagged_fmt("camoufox", "terminate_process_post_failed pid=%lu reason=%s",
            static_cast<unsigned long>(pid), reason.c_str());
        terminate_process_tree_sync(pid, reason);
    }
}

void mark_cleanup_started_locked(uint64_t generation, uint32_t child_pid = 0, const std::string& reason = std::string())
{
    sg().cleanup_pending = true;
    sg().cleanup_generation = generation;
    sg().cleanup_started_ms = now_ms();
    sg().cleanup_child_pid = child_pid == 0 ? sg().child_pid : child_pid;
    if (!sg().active_profile_dir.empty() || sg().cleanup_profile_dir.empty())
        sg().cleanup_profile_dir = sg().active_profile_dir;
    sg().cleanup_reason = reason;
    const auto tree = sg().cleanup_child_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(sg().cleanup_child_pid);
    const size_t descendant_count = tree.size() > 0 ? tree.size() - 1 : 0;
    diag::log_tagged_fmt("camoufox", "cleanup_state_begin generation=%llu child_pid=%lu descendants=%zu profile_dir=%s reason=%s state=%d current_generation=%llu pending=%d",
        static_cast<unsigned long long>(generation), static_cast<unsigned long>(sg().cleanup_child_pid),
        descendant_count, sg().cleanup_profile_dir.empty() ? "<empty>" : sg().cleanup_profile_dir.c_str(),
        sg().cleanup_reason.c_str(), static_cast<int>(sg().state),
        static_cast<unsigned long long>(sg().generation), static_cast<int>(sg().cleanup_pending));
}

void mark_cleanup_finished(uint64_t generation, uint64_t elapsed_ms, const std::string& reason)
{
    std::string cleanup_profile_dir;
    bool should_purge_profile = false;
    std::unique_lock<std::recursive_mutex> lk(sg().mtx);
    const uint64_t age_ms = sg().cleanup_started_ms == 0 ? 0 : now_ms() - sg().cleanup_started_ms;
    const uint32_t cleanup_pid = sg().cleanup_child_pid;
    const std::string cleanup_reason = sg().cleanup_reason;
    cleanup_profile_dir = sg().cleanup_profile_dir;
    if (sg().cleanup_generation == generation)
    {
        sg().cleanup_pending = false;
        sg().last_cleanup_ms = elapsed_ms;
        sg().cleanup_started_ms = 0;
        sg().cleanup_child_pid = 0;
        sg().cleanup_profile_dir.clear();
        sg().cleanup_reason.clear();
        if (cleanup_pid != 0 && sg().tracked_child_pid.load(std::memory_order_acquire) == cleanup_pid)
            sg().tracked_child_pid.store(0, std::memory_order_release);
        if (sg().active_profile_dir == cleanup_profile_dir)
            sg().active_profile_dir.clear();
        should_purge_profile = true;
    }
    diag::log_tagged_fmt("camoufox", "cleanup_state_done generation=%llu current_generation=%llu pending=%d child_pid=%lu profile_dir=%s started_age_ms=%llu start_reason=%s reason=%s elapsed_ms=%llu",
        static_cast<unsigned long long>(generation), static_cast<unsigned long long>(sg().generation),
        static_cast<int>(sg().cleanup_pending), static_cast<unsigned long>(cleanup_pid),
        cleanup_profile_dir.empty() ? "<empty>" : cleanup_profile_dir.c_str(),
        static_cast<unsigned long long>(age_ms), cleanup_reason.c_str(), reason.c_str(),
        static_cast<unsigned long long>(elapsed_ms));
    lk.unlock();
    if (should_purge_profile)
        purge_generated_profile_dir(cleanup_profile_dir, reason);
}

std::string cleanup_profile_dir_snapshot(uint64_t generation)
{
    std::lock_guard<std::recursive_mutex> lk(sg().mtx);
    if (sg().cleanup_generation == generation && !sg().cleanup_profile_dir.empty())
        return sg().cleanup_profile_dir;
    return sg().active_profile_dir;
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
        const std::string profile_dir = cleanup_profile_dir_snapshot(generation);
        diag::log_tagged_critical_fmt("camoufox", "cleanup_poisoned start generation=%llu reason=%s child_pid=%lu profile_dir=%s",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            profile_dir.empty() ? "<empty>" : profile_dir.c_str());
        const process_tree_reap_result_t reap = terminate_process_tree_sync(child_pid, reason);
        diag::log_tagged_critical_fmt("camoufox", "cleanup_poisoned reap generation=%llu reason=%s child_pid=%lu descendants_before=%zu alive_after=%zu success=%d elapsed_ms=%llu",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            reap.descendants_before, reap.alive_after, reap.alive_after == 0 ? 1 : 0,
            static_cast<unsigned long long>(reap.elapsed_ms));
        mark_cleanup_finished(generation, now_ms() - t0, reason);
    };
    if (!post_bridge_task("camoufox.cleanup_poisoned", cleanup_task)) {
        diag::log_tagged_fmt("camoufox", "cleanup_poisoned_post_failed generation=%llu reason=%s",
            static_cast<unsigned long long>(generation), reason.c_str());
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
        const std::string profile_dir = cleanup_profile_dir_snapshot(generation);
        process_tree_reap_result_t reap;
        diag::log_tagged_fmt("camoufox", "cleanup_async start generation=%llu reason=%s child_pid=%lu client=%d profile_dir=%s",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            static_cast<int>(cli != nullptr), profile_dir.empty() ? "<empty>" : profile_dir.c_str());
        if (child_pid != 0)
            reap = terminate_process_tree_sync(child_pid, reason);
        diag::log_tagged_fmt("camoufox", "cleanup_async reap generation=%llu reason=%s child_pid=%lu descendants_before=%zu alive_after=%zu success=%d reap_elapsed_ms=%llu",
            static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
            reap.descendants_before, reap.alive_after, child_pid == 0 || reap.alive_after == 0 ? 1 : 0,
            static_cast<unsigned long long>(reap.elapsed_ms));
        mark_cleanup_finished(generation, now_ms() - t0, reason);
        if (cli)
        {
            disconnect_client_sync(cli, reason);
            diag::log_tagged_fmt("camoufox", "cleanup_async disconnected generation=%llu reason=%s",
                static_cast<unsigned long long>(generation), reason.c_str());
        }
        diag::log_tagged_fmt("camoufox", "cleanup_async done generation=%llu reason=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(generation), reason.c_str(),
            static_cast<unsigned long long>(now_ms() - t0));
    };
    if (!post_bridge_task("camoufox.cleanup", cleanup_task)) {
        diag::log_tagged_fmt("camoufox", "cleanup_async_post_failed generation=%llu reason=%s",
            static_cast<unsigned long long>(generation), reason.c_str());
        cleanup_task();
    }
}

void cleanup_client_reap_now_detach_disconnect(std::shared_ptr<mcp_client::client_t> cli, uint32_t child_pid, const std::string& reason, uint64_t generation)
{
    const uint64_t t0 = now_ms();
    diag::log_tagged_fmt("camoufox", "cleanup_sync_reap_begin generation=%llu reason=%s child_pid=%lu client=%d",
        static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
        static_cast<int>(cli != nullptr));
    process_tree_reap_result_t reap;
    if (child_pid != 0)
        reap = terminate_process_tree_sync(child_pid, reason);
    diag::log_tagged_fmt("camoufox", "cleanup_sync_reap_result generation=%llu reason=%s child_pid=%lu descendants_before=%zu alive_after=%zu success=%d reap_elapsed_ms=%llu",
        static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
        reap.descendants_before, reap.alive_after, child_pid == 0 || reap.alive_after == 0 ? 1 : 0,
        static_cast<unsigned long long>(reap.elapsed_ms));
    mark_cleanup_finished(generation, now_ms() - t0, reason);
    if (cli)
        disconnect_client_async(cli, reason + ":post_reap_disconnect");
    diag::log_tagged_fmt("camoufox", "cleanup_sync_reap_end generation=%llu reason=%s child_pid=%lu client_detached=%d elapsed_ms=%llu",
        static_cast<unsigned long long>(generation), reason.c_str(), static_cast<unsigned long>(child_pid),
        static_cast<int>(cli != nullptr), static_cast<unsigned long long>(now_ms() - t0));
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

bool parse_json_text_relaxed(const std::string& text, nlohmann::json& out)
{
    if (text.empty())
        return false;
    try
    {
        out = nlohmann::json::parse(text);
        return true;
    }
    catch (...) {}
    size_t first = std::string::npos;
    const size_t arr = text.find('[');
    const size_t obj = text.find('{');
    if (arr != std::string::npos && obj != std::string::npos)
        first = std::min(arr, obj);
    else if (arr != std::string::npos)
        first = arr;
    else
        first = obj;
    if (first == std::string::npos)
        return false;
    const char close_ch = text[first] == '[' ? ']' : '}';
    const size_t last = text.rfind(close_ch);
    if (last == std::string::npos || last <= first)
        return false;
    try
    {
        out = nlohmann::json::parse(text.substr(first, last - first + 1));
        return true;
    }
    catch (...) {}
    return false;
}

nlohmann::json normalize_console_log_data(const nlohmann::json& data)
{
    if (data.is_array())
        return data;
    if (data.is_string())
    {
        const std::string text = data.get<std::string>();
        nlohmann::json parsed;
        if (parse_json_text_relaxed(text, parsed))
            return normalize_console_log_data(parsed);
        nlohmann::json entry = nlohmann::json::object();
        entry["text"] = text;
        return nlohmann::json::array({entry});
    }
    if (data.is_object())
    {
        if (data.contains("text") && data["text"].is_string())
            return nlohmann::json::array({data});
        const char* keys[] = { "value", "result", "logs", "records", "items" };
        for (const char* key : keys)
        {
            if (!data.contains(key))
                continue;
            nlohmann::json nested = normalize_console_log_data(data[key]);
            if (!nested.empty())
                return nested;
        }
        if (data.contains("raw_text") && data["raw_text"].is_string())
        {
            const std::string text = data["raw_text"].get<std::string>();
            nlohmann::json parsed;
            if (parse_json_text_relaxed(text, parsed))
                return normalize_console_log_data(parsed);
            nlohmann::json entry = nlohmann::json::object();
            entry["text"] = text;
            return nlohmann::json::array({entry});
        }
    }
    return nlohmann::json::array();
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
                    ? "camoufox bridge is not running; call launch_browser before browser navigation or instrumentation"
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

    bool posted = post_bridge_task("camoufox.call", [state, cli, tool_name, args, request_id]() {
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
    });

    if (!posted)
    {
        fail.error = "camoufox call dispatch post failed";
        sg().total_errors.fetch_add(1, std::memory_order_relaxed);
        diag::log_tagged_fmt("camoufox", "call_with_deadline phase=post_failed request_id=%llu tool=%s",
            static_cast<unsigned long long>(request_id), tool_name.c_str());
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
                mark_cleanup_started_locked(sg().generation, sg().child_pid, std::string(cancelled_by_stop ? "cancel_" : "timeout_") + tool_name);
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
                mark_cleanup_started_locked(sg().generation, poisoned_child_pid, std::string("native_exception_") + tool_name);
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
        bool retained_evaluate_client = false;
        uint32_t retain_child_pid = 0;
        uint64_t retain_generation = 0;
        bool retain_browser_open = false;
        bool retain_page_verified = false;
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli)
            {
                retain_child_pid = sg().child_pid;
                retain_generation = sg().generation;
                retain_browser_open = sg().browser_open;
                retain_page_verified = sg().page_verified;
            }
        }
        if (tool_name == "evaluate_js" && retain_child_pid != 0 && retain_browser_open && retain_page_verified && process_alive(retain_child_pid))
        {
            std::lock_guard<std::recursive_mutex> g(sg().mtx);
            if (sg().client == cli && sg().child_pid == retain_child_pid && sg().generation == retain_generation)
            {
                retained_evaluate_client = true;
                sg().last_error = "camoufox evaluate_js transient transport failure";
            }
        }
        if (retained_evaluate_client)
        {
            diag::log_tagged_fmt("camoufox", "driver_closed retained_evaluate_client request_id=%llu tool=%s generation=%llu child_pid=%lu browser_open=%d page_verified=%d err=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<unsigned long long>(retain_generation),
                static_cast<unsigned long>(retain_child_pid), retain_browser_open ? 1 : 0, retain_page_verified ? 1 : 0, out.error.c_str());
        }
        else
        {
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
                    mark_cleanup_started_locked(sg().generation, closed_child_pid, std::string("driver_closed_") + tool_name);
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
    diag::log_tagged_fmt("camoufox", "module_probe start python=%s module=camoufox_reverse_mcp", python_path.c_str());
    DWORD code = 0;
    std::string captured;
    if (!spawn_python_capture(python_path, L"-I -c \"import camoufox_reverse_mcp\"", 3000, code, captured, "module_probe"))
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
    std::wstring args;
    if (module == "camoufox_reverse_mcp")
        args = L"-I -m camoufox_reverse_mcp --help";
    else
        args = std::wstring(L"-I -c \"import importlib; importlib.import_module('") + utf8_to_wide(module) + L"')\"";
    diag::log_tagged_fmt("camoufox", "server_preflight start python=%s module=%s", python_path.c_str(), module.c_str());

    DWORD code = 0;
    std::string captured;
    if (!spawn_python_capture(python_path, args, 4000, code, captured, "server_preflight"))
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

bool preflight_server_executable_locked(const std::string& server_executable)
{
    diag::log_tagged_fmt("camoufox", "server_exe_preflight start path=%s", server_executable.c_str());
    if (server_executable.empty())
    {
        sg().last_error = "camoufox MCP executable preflight failed: empty executable path";
        diag::log_tagged("camoufox", sg().last_error.c_str());
        return false;
    }
    const std::wstring path = utf8_to_wide(server_executable);
    if (path.empty())
    {
        sg().last_error = "camoufox MCP executable preflight failed: path encoding conversion failed";
        diag::log_tagged("camoufox", sg().last_error.c_str());
        return false;
    }
    const DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        const DWORD gle = attr == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_DIRECTORY;
        sg().last_error = "camoufox MCP executable preflight failed: executable path is unavailable gle=" + std::to_string(gle);
        diag::log_tagged_fmt("camoufox", "server_exe_preflight unavailable path=%s attr=0x%08lX gle=%lu",
            server_executable.c_str(), static_cast<unsigned long>(attr), static_cast<unsigned long>(gle));
        return false;
    }
    executable_image_probe_t image_probe;
    DWORD probe_gle = ERROR_SUCCESS;
    if (!probe_executable_image_w(path, image_probe, probe_gle))
    {
        sg().last_error = "camoufox MCP executable preflight failed: executable image probe failed gle=" + std::to_string(probe_gle);
        diag::log_tagged_fmt("camoufox", "server_exe_preflight image_probe_failed path=%s attr=0x%08lX gle=%lu size=%lld machine=0x%04lX",
            server_executable.c_str(), static_cast<unsigned long>(attr), static_cast<unsigned long>(probe_gle),
            static_cast<long long>(image_probe.size.QuadPart), static_cast<unsigned long>(image_probe.machine));
        return false;
    }
    diag::log_tagged_fmt("camoufox", "server_exe_preflight ok path=%s attr=0x%08lX machine=0x%04lX size=%lld",
        server_executable.c_str(), static_cast<unsigned long>(attr), static_cast<unsigned long>(image_probe.machine),
        static_cast<long long>(image_probe.size.QuadPart));
    return true;
}

bool wait_for_existing_start_bridge_result(const launch_config_t& cfg, uint64_t caller_start_ms)
{
    int wait_ms = effective_launch_wait_ms(cfg, true);
    if (wait_ms < 5000)
        wait_ms = 5000;
    const uint64_t wait_limit_ms = static_cast<uint64_t>(wait_ms) + 5000;
    const uint64_t wait_start_ms = now_ms();
    uint64_t last_log_ms = 0;
    diag::log_tagged_fmt("camoufox", "start_bridge operation_busy_wait_begin wait_ms=%llu requested_timeout_ms=%d testlab_fast_probe=%d caller_elapsed_ms=%llu",
        static_cast<unsigned long long>(wait_limit_ms), cfg.launch_timeout_ms,
        test_lab_launch_fail_fast_enabled(cfg) ? 1 : 0,
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
    const bool testlab_fast_probe = test_lab_launch_fail_fast_enabled(cfg);
    const int launch_timeout_ms = testlab_fast_probe ? test_lab_launch_wait_ms(cfg) : cfg.launch_timeout_ms;
    j["session_id"]    = cfg.session_id.empty() ? std::string("default") : cfg.session_id;
    j["headless"]     = cfg.headless;
    j["os_type"]      = cfg.os.empty() ? std::string("auto") : cfg.os;
    j["locale"]       = cfg.locale.empty() ? std::string("auto") : cfg.locale;
    j["humanize"]     = cfg.humanize;
    j["geoip"]        = cfg.geoip;
    j["block_images"] = cfg.block_images;
    j["block_webrtc"] = true;
    j["webrtc_policy"] = "disabled";
    j["ua_policy"] = "camoufox_native";
    j["enable_trace"] = cfg.enable_trace;
    j["window_width"] = cfg.window_width > 0 ? cfg.window_width : 1280;
    j["window_height"] = cfg.window_height > 0 ? cfg.window_height : 900;
    j["launch_timeout_ms"] = launch_timeout_ms > 2000 ? launch_timeout_ms - 1000 : launch_timeout_ms;
    if (testlab_fast_probe)
        j["aida_testlab_fast_probe"] = true;
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
    std::string configured;
    if (read_env_path_a("AIDA_CAMOUFOX_DEBUG_LOG", configured))
        return configured;
    if (env_flag_enabled_a("AIDA_FILELESS_LAUNCH"))
    {
        wchar_t temp[MAX_PATH + 1] = {};
        DWORD got = GetTempPathW(MAX_PATH, temp);
        if (got != 0 && got < MAX_PATH)
        {
            std::wstring root = join_path_w(std::wstring(temp), L"AiDA");
            CreateDirectoryW(root.c_str(), nullptr);
            std::wstring camoufox_root = join_path_w(root, L"camoufox");
            CreateDirectoryW(camoufox_root.c_str(), nullptr);
            std::string out = wide_to_utf8(join_path_w(camoufox_root, L"aida_camoufox_debug.log"));
            if (!out.empty()) return out;
        }
    }
    std::wstring dir = executable_dir_w();
    if (dir.empty()) dir = current_dir_w();
    if (dir.empty()) return "aida_camoufox_debug.log";
    std::string out = wide_to_utf8(join_path_w(dir, L"aida_camoufox_debug.log"));
    return out.empty() ? std::string("aida_camoufox_debug.log") : out;
}

std::string camoufox_working_dir_path()
{
    std::wstring dir = executable_dir_w();
    if (dir.empty()) dir = current_dir_w();
    return wide_to_utf8(dir);
}

std::string camoufox_profile_root_path()
{
    std::wstring root = local_appdata_aida_root();
    if (root.empty()) root = executable_dir_w();
    if (root.empty()) root = current_dir_w();
    if (root.empty()) return {};
    return wide_to_utf8(join_path_w(root, L"camoufox-profiles"));
}

void populate_internal_camoufox_env(mcp_client::server_config_t& scfg, const std::string& session_id, const std::string& browser_executable, const std::string& debug_log)
{
    scfg.env["PYTHONIOENCODING"] = "utf-8";
    scfg.env["AIDA_CAMOUFOX_DEBUG_LOG"] = debug_log;
    scfg.env["AIDA_CAMOUFOX_SESSION_ID"] = session_id.empty() ? std::string("default") : session_id;
    const std::string work_dir = camoufox_working_dir_path();
    if (!work_dir.empty())
        scfg.env["AIDA_CAMOUFOX_WORKING_DIR"] = work_dir;
    const std::string profile_root = camoufox_profile_root_path();
    if (!profile_root.empty())
        scfg.env["AIDA_CAMOUFOX_PROFILE_ROOT"] = profile_root;
    if (!browser_executable.empty())
        scfg.env["AIDA_CAMOUFOX_EXECUTABLE"] = browser_executable;
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

std::string last_camoufox_debug_event_from_tail(const std::string& tail)
{
    if (tail.empty()) return {};
    const std::string prefix = "AIDA_CAMOUFOX ";
    std::size_t end = tail.size();
    while (end > 0)
    {
        std::size_t begin = tail.rfind('\n', end - 1);
        std::size_t line_begin = begin == std::string::npos ? 0 : begin + 1;
        std::string line = tail.substr(line_begin, end - line_begin);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        std::size_t pos = line.find(prefix);
        if (pos != std::string::npos)
        {
            nlohmann::json parsed = nlohmann::json::parse(line.substr(pos + prefix.size()), nullptr, false);
            if (parsed.is_object())
            {
                std::string event = json_string_or(parsed, "event", std::string());
                if (!event.empty())
                {
                    std::string out = event;
                    const int elapsed = json_int_or(parsed, "elapsed_ms", -1);
                    const int uptime = json_int_or(parsed, "uptime_ms", -1);
                    if (elapsed >= 0)
                        out += " elapsed_ms=" + std::to_string(elapsed);
                    if (uptime >= 0)
                        out += " uptime_ms=" + std::to_string(uptime);
                    return out;
                }
            }
        }
        if (begin == std::string::npos)
            break;
        end = begin;
    }
    return {};
}

std::string launch_profile_dir_from_response(const nlohmann::json& parsed)
{
    if (!parsed.is_object())
        return {};
    auto diagnostics_it = parsed.find("diagnostics");
    if (diagnostics_it == parsed.end() || !diagnostics_it->is_object())
        return {};
    auto profile_it = diagnostics_it->find("profile");
    if (profile_it == diagnostics_it->end() || !profile_it->is_object())
        return {};
    return json_string_or(*profile_it, "profile_dir", std::string());
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

uint64_t json_u64_or(const nlohmann::json& j, const char* key, uint64_t fallback)
{
    if (!j.is_object()) return fallback;
    auto it = j.find(key);
    if (it == j.end()) return fallback;
    if (it->is_number_unsigned()) return it->get<uint64_t>();
    if (it->is_number_integer()) return static_cast<uint64_t>(it->get<int64_t>());
    return fallback;
}

page_status_t page_status_from_json(const nlohmann::json& j)
{
    page_status_t p;
    if (!j.is_object()) return p;
    p.page_id      = json_string_or(j, "page_id", std::string());
    p.context_id   = json_string_or(j, "context_id", std::string());
    p.url          = json_string_or(j, "url", std::string());
    p.title        = json_string_or(j, "title", std::string());
    p.guid         = json_string_or(j, "guid", std::string());
    p.active       = json_bool_or(j, "active", false);
    p.closed       = json_bool_or(j, "closed", false);
    p.created_ms   = json_u64_or(j, "created_ms", 0);
    p.last_used_ms = json_u64_or(j, "last_used_ms", 0);
    return p;
}

void merge_page_locked(const page_status_t& incoming)
{
    if (incoming.page_id.empty()) return;
    for (auto& existing : sg().pages)
    {
        if (existing.page_id == incoming.page_id)
        {
            existing = incoming;
            return;
        }
    }
    sg().pages.push_back(incoming);
}

void update_page_cache_from_json_locked(const nlohmann::json& data, const char* source)
{
    if (!data.is_object()) return;
    std::vector<page_status_t> parsed_pages;
    auto pages_it = data.find("pages");
    if (pages_it != data.end() && pages_it->is_array())
    {
        for (const auto& item : *pages_it)
        {
            page_status_t p = page_status_from_json(item);
            if (!p.page_id.empty())
                parsed_pages.push_back(std::move(p));
        }
    }
    auto page_it = data.find("page");
    if (page_it != data.end() && page_it->is_object())
    {
        page_status_t p = page_status_from_json(*page_it);
        if (!p.page_id.empty())
            parsed_pages.push_back(std::move(p));
    }
    const std::string direct_page_id = json_string_or(data, "page_id", std::string());
    if (!direct_page_id.empty())
    {
        bool already = false;
        for (const auto& p : parsed_pages)
        {
            if (p.page_id == direct_page_id)
            {
                already = true;
                break;
            }
        }
        if (!already)
        {
            page_status_t p = page_status_from_json(data);
            if (p.page_id.empty()) p.page_id = direct_page_id;
            parsed_pages.push_back(std::move(p));
        }
    }
    if (pages_it != data.end() && pages_it->is_array())
        sg().pages.clear();
    for (const auto& p : parsed_pages)
        merge_page_locked(p);
    const std::string active_page_id = json_string_or(data, "active_page_id", direct_page_id);
    if (!active_page_id.empty())
        sg().active_page_id = active_page_id;
    if (sg().active_page_id.empty() && !sg().pages.empty())
        sg().active_page_id = sg().pages.front().page_id;
    if (data.contains("url") && data["url"].is_string())
        sg().active_page_url = data["url"].get<std::string>();
    if (data.contains("title") && data["title"].is_string())
        sg().active_page_title = data["title"].get<std::string>();
    for (const auto& p : sg().pages)
    {
        if (!sg().active_page_id.empty() && p.page_id == sg().active_page_id)
        {
            if (!p.url.empty()) sg().active_page_url = p.url;
            if (!p.title.empty()) sg().active_page_title = p.title;
            break;
        }
    }
    diag::log_tagged_fmt("camoufox", "page_cache_update source=%s active_page_id=%s page_count=%zu url_len=%zu title_len=%zu",
        source ? source : "unknown", sg().active_page_id.c_str(), sg().pages.size(),
        sg().active_page_url.size(), sg().active_page_title.size());
}

void merge_page_locked(managed_session_t& session, const page_status_t& incoming)
{
    if (incoming.page_id.empty()) return;
    for (auto& existing : session.pages)
    {
        if (existing.page_id == incoming.page_id)
        {
            existing = incoming;
            return;
        }
    }
    session.pages.push_back(incoming);
}

void update_page_cache_from_json_locked(managed_session_t& session, const nlohmann::json& data, const char* source)
{
    if (!data.is_object()) return;
    std::vector<page_status_t> parsed_pages;
    auto pages_it = data.find("pages");
    if (pages_it != data.end() && pages_it->is_array())
    {
        for (const auto& item : *pages_it)
        {
            page_status_t p = page_status_from_json(item);
            if (!p.page_id.empty())
                parsed_pages.push_back(std::move(p));
        }
    }
    auto page_it = data.find("page");
    if (page_it != data.end() && page_it->is_object())
    {
        page_status_t p = page_status_from_json(*page_it);
        if (!p.page_id.empty())
            parsed_pages.push_back(std::move(p));
    }
    const std::string direct_page_id = json_string_or(data, "page_id", std::string());
    if (!direct_page_id.empty())
    {
        bool already = false;
        for (const auto& p : parsed_pages)
        {
            if (p.page_id == direct_page_id)
            {
                already = true;
                break;
            }
        }
        if (!already)
        {
            page_status_t p = page_status_from_json(data);
            if (p.page_id.empty()) p.page_id = direct_page_id;
            parsed_pages.push_back(std::move(p));
        }
    }
    if (pages_it != data.end() && pages_it->is_array())
        session.pages.clear();
    for (const auto& p : parsed_pages)
        merge_page_locked(session, p);
    const std::string active_page_id = json_string_or(data, "active_page_id", direct_page_id);
    if (!active_page_id.empty())
        session.active_page_id = active_page_id;
    if (session.active_page_id.empty() && !session.pages.empty())
        session.active_page_id = session.pages.front().page_id;
    if (data.contains("url") && data["url"].is_string())
        session.active_page_url = data["url"].get<std::string>();
    if (data.contains("title") && data["title"].is_string())
        session.active_page_title = data["title"].get<std::string>();
    for (const auto& p : session.pages)
    {
        if (!session.active_page_id.empty() && p.page_id == session.active_page_id)
        {
            if (!p.url.empty()) session.active_page_url = p.url;
            if (!p.title.empty()) session.active_page_title = p.title;
            break;
        }
    }
    diag::log_tagged_fmt("camoufox", "managed_page_cache_update session_id=%s source=%s active_page_id=%s page_count=%zu url_len=%zu title_len=%zu",
        session.session_id.c_str(), source ? source : "unknown", session.active_page_id.c_str(),
        session.pages.size(), session.active_page_url.size(), session.active_page_title.size());
}

std::string normalize_session_id(const std::string& session_id)
{
    std::string out = session_id.empty() ? std::string("default") : session_id;
    for (char& c : out)
    {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':' || c == '.';
        if (!ok) c = '_';
    }
    if (out.empty()) out = "default";
    if (out.size() > 96) out.resize(96);
    return out;
}

bool is_default_session_id(const std::string& session_id)
{
    const std::string normalized = normalize_session_id(session_id);
    return normalized == "default";
}

bool tool_accepts_page_id_directly(const std::string& tool_name)
{
    return tool_name == "launch_browser" ||
           tool_name == "close_browser" ||
           tool_name == "status" ||
           tool_name == "list_pages" ||
           tool_name == "new_page" ||
           tool_name == "select_page" ||
           tool_name == "close_page" ||
           tool_name == "navigate" ||
           tool_name == "reload" ||
           tool_name == "take_screenshot" ||
           tool_name == "take_snapshot" ||
           tool_name == "click" ||
           tool_name == "type_text" ||
           tool_name == "wait_for" ||
           tool_name == "get_page_info" ||
           tool_name == "evaluate_js" ||
           tool_name == "get_console_logs" ||
           tool_name == "list_network_requests";
}

call_result_t page_target_select_failure(const std::string& tool_name, const std::string& session_id, const std::string& page_id, const call_result_t& select_result)
{
    call_result_t out;
    out.ok = false;
    out.error = std::string("camoufox page target select failed before ") + tool_name + " session_id=" + session_id + " page_id=" + page_id;
    if (!select_result.error.empty())
        out.error += std::string(": ") + select_result.error;
    out.data = nlohmann::json{
        {"error", out.error},
        {"session_id", session_id},
        {"page_id", page_id},
        {"tool", tool_name},
        {"select_page", select_result.data}
    };
    return out;
}

std::shared_ptr<managed_session_t> get_managed_session(const std::string& session_id, bool create)
{
    const std::string normalized = normalize_session_id(session_id);
    if (normalized == "default") return {};
    std::lock_guard<std::recursive_mutex> lk(sessions_mtx());
    auto& sessions = managed_sessions();
    auto it = sessions.find(normalized);
    if (it != sessions.end())
        return it->second;
    if (!create)
        return {};
    auto session = std::make_shared<managed_session_t>();
    session->session_id = normalized;
    session->active_cfg.session_id = normalized;
    sessions.emplace(normalized, session);
    return session;
}

uint32_t managed_session_count()
{
    std::lock_guard<std::recursive_mutex> lk(sessions_mtx());
    uint32_t count = 1;
    for (const auto& item : managed_sessions())
    {
        if (item.second)
            ++count;
    }
    return count;
}

}

bool ensure_python_available(std::string& out_python_path)
{
    const uint64_t t0 = now_ms();
    const bool allow_system_python = system_python_discovery_allowed();
    diag::log_tagged_fmt("camoufox", "ensure_python_available entry budget_ms=%llu",
        static_cast<unsigned long long>(kPythonDiscoveryBudgetMs));
    std::string cached_python_path;
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        cached_python_path = sg().cached_python_path;
    }
    if (!cached_python_path.empty() && path_exists_w(utf8_to_wide(cached_python_path)))
    {
        if (!allow_system_python && !is_app_controlled_python_path(cached_python_path))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available cached rejected path=%s reason=system_python_discovery_disabled elapsed_ms=%llu",
                cached_python_path.c_str(), static_cast<unsigned long long>(now_ms() - t0));
        }
        else
        {
            std::string reason;
            if (supported_camoufox_python(cached_python_path, &reason))
            {
                diag::log_tagged_fmt("camoufox", "ensure_python_available cached path=%s %s elapsed_ms=%llu",
                    cached_python_path.c_str(), reason.c_str(), static_cast<unsigned long long>(now_ms() - t0));
                out_python_path = cached_python_path;
                return true;
            }
            diag::log_tagged_fmt("camoufox", "ensure_python_available cached rejected path=%s reason=%s elapsed_ms=%llu",
                cached_python_path.c_str(), reason.c_str(), static_cast<unsigned long long>(now_ms() - t0));
        }
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            if (_stricmp(sg().cached_python_path.c_str(), cached_python_path.c_str()) == 0)
                sg().cached_python_path.clear();
        }
    }
    std::vector<std::string> candidates;
    std::string env_python;
    if (read_env_path_a("AIDA_CAMOUFOX_PYTHON", env_python))
    {
        if (allow_system_python || is_app_controlled_python_path(env_python))
            candidates.push_back(env_python);
        else
            diag::log_tagged_fmt("camoufox", "ensure_python_available env_python_skipped path=%s policy=AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON", env_python.c_str());
    }
    append_bundled_python_candidates(candidates);
    append_app_local_python_candidates(candidates);
    const size_t app_controlled_candidates = candidates.size();
    if (allow_system_python)
    {
        std::string found;
        if (try_search_path(L"python.exe", found)) candidates.push_back(found);
        found.clear();
        if (try_search_path(L"python3.exe", found)) candidates.push_back(found);
        found.clear();
        if (try_known_python_roots(found)) candidates.push_back(found);
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "ensure_python_available system_python_candidates_skipped app_controlled_candidates=%zu policy=AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON",
            app_controlled_candidates);
    }
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
    diag::log_tagged_fmt("camoufox", "ensure_python_available candidate_count=%zu elapsed_ms=%llu",
        candidates.size(), static_cast<unsigned long long>(now_ms() - t0));
    for (size_t candidate_index = 0; candidate_index < candidates.size(); ++candidate_index)
    {
        const std::string& candidate = candidates[candidate_index];
        const uint64_t candidate_start_ms = now_ms();
        const uint64_t total_before_ms = candidate_start_ms >= t0 ? candidate_start_ms - t0 : 0;
        if (total_before_ms >= kPythonDiscoveryBudgetMs)
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available budget_exhausted before_candidate index=%zu total=%zu elapsed_ms=%llu",
                candidate_index, candidates.size(), static_cast<unsigned long long>(total_before_ms));
            break;
        }
        diag::log_tagged_fmt("camoufox", "ensure_python_available candidate_begin index=%zu total=%zu path=%s elapsed_ms=%llu",
            candidate_index + 1, candidates.size(), candidate.c_str(), static_cast<unsigned long long>(total_before_ms));
        if (is_windows_store_python_alias(candidate))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available rejected path=%s reason=windows store python alias candidate_elapsed_ms=%llu elapsed_ms=%llu",
                candidate.c_str(), static_cast<unsigned long long>(now_ms() - candidate_start_ms),
                static_cast<unsigned long long>(now_ms() - t0));
            continue;
        }
        std::string reason;
        if (!supported_camoufox_python(candidate, &reason))
        {
            diag::log_tagged_fmt("camoufox", "ensure_python_available rejected path=%s reason=%s candidate_elapsed_ms=%llu elapsed_ms=%llu",
                candidate.c_str(), reason.c_str(), static_cast<unsigned long long>(now_ms() - candidate_start_ms),
                static_cast<unsigned long long>(now_ms() - t0));
            continue;
        }
        diag::log_tagged_fmt("camoufox", "ensure_python_available found path=%s %s candidate_elapsed_ms=%llu elapsed_ms=%llu",
            candidate.c_str(), reason.c_str(), static_cast<unsigned long long>(now_ms() - candidate_start_ms),
            static_cast<unsigned long long>(now_ms() - t0));
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            sg().cached_python_path = candidate;
        }
        out_python_path         = candidate;
        return true;
    }
    diag::log_tagged_fmt("camoufox", "ensure_python_available python_not_found candidate_count=%zu elapsed_ms=%llu budget_ms=%llu",
        candidates.size(), static_cast<unsigned long long>(now_ms() - t0),
        static_cast<unsigned long long>(kPythonDiscoveryBudgetMs));
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        set_error_locked(allow_system_python
            ? "supported Python 3.10-3.13 interpreter not found for Camoufox"
            : std::string("Camoufox app-local Python runtime missing\n") + install::setup_instructions());
    }
    return false;
}

bool start_bridge(const launch_config_t& cfg)
{
    if (!is_default_session_id(cfg.session_id))
        return start_bridge(cfg, cfg.session_id);
    const uint64_t bridge_start_ms = now_ms();
    std::unique_lock<std::recursive_mutex> op_lk(sg().operation_mtx, std::try_to_lock);
    if (!op_lk.owns_lock())
        return wait_for_existing_start_bridge_result(cfg, bridge_start_ms);
    const uint64_t start_stop_epoch = sg().stop_epoch.load(std::memory_order_acquire);
    launch_config_t effective_cfg = cfg;
    enforce_private_launch_config(effective_cfg);
    if (effective_cfg.session_id.empty())
        effective_cfg.session_id = "default";
    if (effective_cfg.headless)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge forcing_visible requested_headless=1");
        effective_cfg.headless = false;
    }
    diag::log_tagged_fmt("camoufox", "start_bridge entry session_id=%s headless=%d module=%s window=%dx%d requested_timeout_ms=%d",
        effective_cfg.session_id.c_str(),
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
        const uint32_t observed_cleanup_pid = sg().cleanup_child_pid;
        const uint64_t observed_cleanup_started_ms = sg().cleanup_started_ms;
        const std::string observed_cleanup_reason = sg().cleanup_reason;
        diag::log_tagged_fmt("camoufox", "start_bridge cleanup_wait_begin generation=%llu cleanup_generation=%llu cleanup_child_pid=%lu cleanup_age_ms=%llu cleanup_reason=%s",
            static_cast<unsigned long long>(sg().generation),
            static_cast<unsigned long long>(observed_cleanup_generation),
            static_cast<unsigned long>(observed_cleanup_pid),
            static_cast<unsigned long long>(observed_cleanup_started_ms == 0 ? 0 : now_ms() - observed_cleanup_started_ms),
            observed_cleanup_reason.c_str());
        while (sg().cleanup_pending && now_ms() - wait_start < 5000)
        {
            lk.unlock();
            Sleep(50);
            lk.lock();
        }
        diag::log_tagged_fmt("camoufox", "start_bridge cleanup_wait_end pending=%d generation=%llu cleanup_generation=%llu cleanup_child_pid=%lu elapsed_ms=%llu",
            static_cast<int>(sg().cleanup_pending),
            static_cast<unsigned long long>(sg().generation),
            static_cast<unsigned long long>(sg().cleanup_generation),
            static_cast<unsigned long>(sg().cleanup_child_pid),
            static_cast<unsigned long long>(now_ms() - wait_start));
    }
    if (sg().cleanup_pending)
    {
        const uint64_t forced_generation = sg().cleanup_generation;
        const uint32_t forced_pid = sg().cleanup_child_pid;
        const uint64_t cleanup_age_ms = sg().cleanup_started_ms == 0 ? 0 : now_ms() - sg().cleanup_started_ms;
        const std::string cleanup_reason = sg().cleanup_reason;
        sg().cleanup_pending = false;
        sg().last_cleanup_ms = cleanup_age_ms;
        sg().cleanup_started_ms = 0;
        sg().cleanup_child_pid = 0;
        sg().cleanup_profile_dir.clear();
        sg().cleanup_reason.clear();
        diag::log_tagged_fmt("camoufox", "start_bridge cleanup_force_clear generation=%llu cleanup_generation=%llu forced_pid=%lu cleanup_age_ms=%llu cleanup_reason=%s",
            static_cast<unsigned long long>(sg().generation), static_cast<unsigned long long>(forced_generation),
            static_cast<unsigned long>(forced_pid), static_cast<unsigned long long>(cleanup_age_ms),
            cleanup_reason.c_str());
        lk.unlock();
        if (forced_pid != 0)
            terminate_process_tree_sync(forced_pid, std::string("start_bridge_stale_cleanup:") + cleanup_reason);
        lk.lock();
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
            terminate_process_tree_sync(stale_pid, "start_bridge_unverified_ready");
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
    sg().session_id     = effective_cfg.session_id;
    sg().last_error.clear();
    sg().active_page_id.clear();
    sg().pages.clear();
    sg().active_profile_dir.clear();
    sg().last_launch_ms = 0;
    publish_state(bridge_state_t::starting, std::string());

    std::string python_path = effective_cfg.python_executable;
    const bool prefer_developer_python = should_prefer_developer_python_runtime(effective_cfg);
    std::string server_executable;
    bool use_server_executable = resolve_reverse_mcp_executable(effective_cfg, server_executable);
    bool developer_python_ready = !python_path.empty();
    lk.unlock();
    if (!use_server_executable)
    {
        if (prefer_developer_python && python_path.empty())
            developer_python_ready = ensure_python_available(python_path);
        else
            developer_python_ready = !python_path.empty();
    }
    lk.lock();
    if (sg().stop_epoch.load(std::memory_order_acquire) != start_stop_epoch)
    {
        sg().last_error = "camoufox bridge start cancelled during Python runtime probe";
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        diag::log_tagged_fmt("camoufox", "start_bridge cancelled_after_python_probe elapsed_ms=%llu",
            static_cast<unsigned long long>(sg().last_launch_ms));
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    diag::log_tagged_fmt("camoufox", "start_bridge server_executable_resolve use_exe=%d prefer_python=%d python_ready=%d python=%s path=%s",
        static_cast<int>(use_server_executable),
        prefer_developer_python ? 1 : 0,
        developer_python_ready ? 1 : 0,
        python_path.empty() ? "<empty>" : python_path.c_str(),
        server_executable.empty() ? "<empty>" : server_executable.c_str());

    if (!use_server_executable && !python_path.empty())
    {
        std::string reason;
        if (!system_python_discovery_allowed() && !is_app_controlled_python_path(python_path))
        {
            reason = "explicit Python path is outside AiDA-controlled Camoufox runtime roots";
            diag::log_tagged_fmt("camoufox", "start_bridge explicit_python_rejected path=%s reason=%s",
                python_path.c_str(), reason.c_str());
            python_path.clear();
        }
        else if (!supported_camoufox_python(python_path, &reason))
        {
            diag::log_tagged_fmt("camoufox", "start_bridge explicit_python_rejected path=%s reason=%s",
                python_path.c_str(), reason.c_str());
            python_path.clear();
        }
    }
    if (!use_server_executable && python_path.empty())
    {
        if (!ensure_python_available(python_path))
        {
            std::string setup_log;
            bool ready = false;
            const uint64_t setup_start_ms = now_ms();
            diag::log_tagged_fmt("camoufox", "start_bridge setup_begin generation=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(start_generation),
                static_cast<unsigned long long>(setup_start_ms - bridge_start_ms));
            try { ready = install::ensure_ready(setup_log); } catch (...) { ready = false; }
            diag::log_tagged_fmt("camoufox", "start_bridge setup_end generation=%llu ready=%d setup_elapsed_ms=%llu setup_log_len=%zu install_err=%s",
                static_cast<unsigned long long>(start_generation), static_cast<int>(ready),
                static_cast<unsigned long long>(now_ms() - setup_start_ms), setup_log.size(),
                install::last_error().c_str());
            if (!ready || !ensure_python_available(python_path))
            {
                sg().last_error = install::last_error();
                if (sg().last_error.empty()) sg().last_error = compact_child_output(setup_log);
                if (sg().last_error.empty()) sg().last_error = install::setup_instructions();
                sg().state = bridge_state_t::error;
                publish_state(bridge_state_t::error, sg().last_error);
                return false;
            }
        }
    }

    if (effective_cfg.browser_executable.empty())
    {
        std::string env_browser;
        if (read_env_path_a("AIDA_CAMOUFOX_EXECUTABLE", env_browser))
            effective_cfg.browser_executable = env_browser;
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
    if (effective_cfg.browser_executable.empty() || browser_attr == INVALID_FILE_ATTRIBUTES || (browser_attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        sg().last_error = effective_cfg.browser_executable.empty()
            ? std::string("Camoufox browser executable not found\n") + install::setup_instructions()
            : std::string("Configured Camoufox browser executable is unavailable\n") + install::setup_instructions();
        sg().state = bridge_state_t::error;
        diag::log_tagged_fmt("camoufox", "start_bridge browser_required_failed generation=%llu err=%s",
            static_cast<unsigned long long>(start_generation), sg().last_error.c_str());
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }

    if (use_server_executable)
    {
        if (!preflight_server_executable_locked(server_executable))
        {
            sg().state = bridge_state_t::error;
            publish_state(bridge_state_t::error, sg().last_error);
            return false;
        }
    }
    else
    {
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
    }

    mcp_client::server_config_t scfg;
    scfg.name      = "camoufox-reverse";
    scfg.transport = mcp_client::transport_type_t::stdio;
    scfg.command   = use_server_executable ? server_executable : python_path;
    if (!use_server_executable)
    {
        scfg.args.push_back("-I");
        scfg.args.push_back("-m");
        scfg.args.push_back(effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    }
    for (const auto& a : effective_cfg.extra_args) scfg.args.push_back(a);
    if (use_server_executable)
        scfg.env["AIDA_CAMOUFOX_MCP_EXECUTABLE"] = server_executable;
    else
        scfg.env["AIDA_CAMOUFOX_PYTHON"] = python_path;
    if (!use_server_executable && system_python_discovery_allowed())
        scfg.env["AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON"] = "1";
    const std::string child_debug_log = camoufox_debug_log_path();
    populate_internal_camoufox_env(scfg, effective_cfg.session_id, effective_cfg.browser_executable, child_debug_log);
    scfg.enabled                 = true;
    scfg.auto_connect            = false;
    scfg.oauth_enabled           = false;

    sg().client = std::make_shared<mcp_client::client_t>();

    diag::log_tagged_fmt("camoufox", "start_bridge mcp_connect_begin generation=%llu command=%s module=%s args=%zu env_pythonio=%d env_browser=%d env_debug_log=%d env_workdir=%d env_profile=%d debug_log=%s browser_exists=%d",
        static_cast<unsigned long long>(start_generation),
        scfg.command.c_str(),
        use_server_executable ? "<frozen-executable>" : (effective_cfg.server_module.empty() ? "camoufox_reverse_mcp" : effective_cfg.server_module.c_str()),
        scfg.args.size(),
        static_cast<int>(scfg.env.find("PYTHONIOENCODING") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_EXECUTABLE") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_DEBUG_LOG") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_WORKING_DIR") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_PROFILE_ROOT") != scfg.env.end()),
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
    sg().server_command = use_server_executable
        ? server_executable
        : python_path + " -m " + (effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    sg().child_pid      = sg().client ? sg().client->child_process_id() : 0;
    sg().tracked_child_pid.store(sg().child_pid, std::memory_order_release);
    sg().launched_ms    = now_ms();
    diag::log_tagged_fmt("camoufox", "start_bridge connected generation=%llu child_pid=%lu command=%s",
        static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid),
        sg().server_command.c_str());

    const bool bundled_visible_launch = !effective_cfg.headless && !effective_cfg.browser_executable.empty();
    const bool testlab_fast_probe = test_lab_launch_fail_fast_enabled(effective_cfg);
    int launch_wait_ms = effective_launch_wait_ms(effective_cfg, bundled_visible_launch);
    int wait_ms = launch_wait_ms / 4;
    if (wait_ms < 5000) wait_ms = 5000;
    if (wait_ms > kToolListWaitMaxMs) wait_ms = kToolListWaitMaxMs;
    if (effective_cfg.launch_timeout_ms != launch_wait_ms || testlab_fast_probe)
    {
        diag::log_tagged_fmt("camoufox", "start_bridge launch_timeout_clamped requested_ms=%d effective_ms=%d tool_list_ms=%d generation=%llu bundled_visible=%d testlab_fast_probe=%d",
            effective_cfg.launch_timeout_ms, launch_wait_ms, wait_ms, static_cast<unsigned long long>(start_generation),
            bundled_visible_launch ? 1 : 0, testlab_fast_probe ? 1 : 0);
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
    diag::log_tagged_fmt("camoufox", "launch_browser request headless=%d has_proxy=%d os=%s locale=%s window=%dx%d timeout_ms=%d testlab_fast_probe=%d",
        static_cast<int>(effective_cfg.headless), static_cast<int>(!effective_cfg.proxy.empty()),
        (effective_cfg.os.empty() ? "auto" : effective_cfg.os.c_str()),
        (effective_cfg.locale.empty() ? "auto" : effective_cfg.locale.c_str()),
        json_int_or(args, "window_width", -1), json_int_or(args, "window_height", -1),
        effective_cfg.launch_timeout_ms, testlab_fast_probe ? 1 : 0);
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
    uint64_t last_launch_wait_log_ms = launch_call_start_ms;
    uint64_t last_launch_tree_log_ms = 0;
    bool launch_posted = post_bridge_task("camoufox.launch", [launch_state, launch_client, args]() {
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
    });
    if (!launch_posted)
    {
        auto failed_client = sg().client;
        sg().client.reset();
        sg().child_pid = 0;
        sg().state = bridge_state_t::error;
        sg().last_error = "launch_browser dispatch post failed";
        clear_page_state_locked();
        sg().last_launch_ms = now_ms() - bridge_start_ms;
        mark_cleanup_started_locked(start_generation, launch_child_pid, "launch_browser_dispatch_failed");
        diag::log_tagged_fmt("camoufox", "launch_browser dispatch_post_failed generation=%llu child_pid=%lu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(launch_child_pid));
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
            const uint64_t wall_elapsed = now_ms() - launch_call_start_ms;
            if (wall_elapsed == 0 || now_ms() - last_launch_wait_log_ms >= 1000)
            {
                const uint64_t now_wait_log = now_ms();
                const uint64_t remaining_ms = elapsed >= static_cast<uint64_t>(launch_wait_ms)
                    ? 0 : static_cast<uint64_t>(launch_wait_ms) - elapsed;
                const bool tree_due = last_launch_tree_log_ms == 0 || now_wait_log - last_launch_tree_log_ms >= 5000;
                std::string tree_text;
                if (tree_due && launch_child_pid != 0)
                {
                    tree_text = compact_process_tree(enumerate_process_tree(launch_child_pid));
                    last_launch_tree_log_ms = now_wait_log;
                }
                diag::log_tagged_fmt("camoufox", "launch_browser wait generation=%llu child_pid=%lu elapsed_ms=%llu remaining_ms=%llu stop_requested=%d worker_done=%d active=%lu cleanup_pending=%d cleanup_generation=%llu cleanup_child_pid=%lu cleanup_reason=%s debug_tail_len=%zu process_tree=%s",
                    static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(launch_child_pid),
                    static_cast<unsigned long long>(wall_elapsed), static_cast<unsigned long long>(remaining_ms),
                    sg().stop_requested.load(std::memory_order_acquire) ? 1 : 0,
                    launch_state->done ? 1 : 0,
                    static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
                    sg().cleanup_pending ? 1 : 0, static_cast<unsigned long long>(sg().cleanup_generation),
                    static_cast<unsigned long>(sg().cleanup_child_pid), sg().cleanup_reason.c_str(),
                    read_file_tail_for_log(child_debug_log, 2000).size(),
                    tree_text.empty() ? "<not-sampled>" : tree_text.c_str());
                last_launch_wait_log_ms = now_wait_log;
            }
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
            const std::string cleanup_reason = launch_cancelled_by_stop ? "launch_browser_cancelled" : "launch_browser_timeout";
            mark_cleanup_started_locked(start_generation, timed_out_pid, cleanup_reason);
            const std::string timeout_tree = timed_out_pid == 0 ? std::string() : compact_process_tree(enumerate_process_tree(timed_out_pid));
            const std::string debug_tail = read_file_tail_for_log(child_debug_log, 6000);
            const std::string debug_phase = last_camoufox_debug_event_from_tail(debug_tail);
            diag::log_tagged_fmt("camoufox", "launch_browser %s generation=%llu child_pid=%lu elapsed_ms=%llu requested_ms=%d effective_ms=%d stop_requested=%d active=%lu cleanup_pending=%d debug_phase=%s process_tree=%s debug_tail_len=%zu debug_tail=%.6000s",
                launch_cancelled_by_stop ? "cancelled" : "timeout",
                static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(timed_out_pid),
                static_cast<unsigned long long>(sg().last_launch_ms), cfg.launch_timeout_ms, launch_wait_ms,
                sg().stop_requested.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
                sg().cleanup_pending ? 1 : 0,
                debug_phase.empty() ? "<none>" : debug_phase.c_str(),
                timeout_tree.empty() ? "<empty>" : timeout_tree.c_str(),
                debug_tail.size(), debug_tail.c_str());
            cleanup_client_reap_now_detach_disconnect(timed_out_client, timed_out_pid, cleanup_reason, start_generation);
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
        mark_cleanup_started_locked(start_generation, failed_pid, native_exception ? "launch_browser_native_exception" : "launch_browser_failed");
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
        const std::string parsed_profile_dir = launch_profile_dir_from_response(parsed);
        if (!parsed_profile_dir.empty())
            sg().active_profile_dir = parsed_profile_dir;
        diag::log_tagged_fmt("camoufox", "launch_browser parsed status=%s diag_elapsed_ms=%d profile_dir=%s window=%dx%d requested=%dx%d work_area=%dx%d viewport=%dx%d inner=%dx%d outer=%dx%d pos=%d,%d screen=%dx%d avail=%dx%d dpr=%.2f",
            json_string_or(parsed, "status", "unknown").c_str(),
            json_int_or(diagnostics, "elapsed_ms", -1),
            parsed_profile_dir.empty() ? "<empty>" : parsed_profile_dir.c_str(),
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
        mark_cleanup_started_locked(start_generation, failed_pid, "launch_browser_returned_error");
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
        mark_cleanup_started_locked(start_generation, cancelled_pid, "launch_browser_cancelled_by_stop");
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
        mark_cleanup_started_locked(start_generation, failed_pid, "launch_browser_child_not_alive");
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
        mark_cleanup_started_locked(start_generation, failed_pid, "launch_browser_readiness_failed");
        diag::log_tagged_fmt("camoufox", "launch_browser readiness_failed generation=%llu child_pid=%lu err=%s data_shape=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(failed_pid),
            err.c_str(), json_shape(page.data).c_str(), static_cast<unsigned long long>(sg().last_launch_ms));
        cleanup_client_async(failed_client, failed_pid, "launch_browser_readiness_failed", start_generation);
        publish_state(bridge_state_t::error, sg().last_error);
        return false;
    }
    update_page_cache_from_json_locked(page.data, "launch_readiness");
    if (sg().active_page_url.empty())
        sg().active_page_url = page.data["url"].get<std::string>();
    if (sg().active_page_title.empty())
        sg().active_page_title = json_string_or(page.data, "title", std::string());
    sg().page_verified = true;
    sg().last_verified_ms = now_ms();
    sg().state = bridge_state_t::ready;
    sg().last_error.clear();
    sg().last_launch_ms = now_ms() - bridge_start_ms;
    const url_log_t ready_url = summarize_url_for_log(sg().active_page_url);
    diag::log_tagged_fmt("camoufox", "bridge ready generation=%llu child_pid=%lu python=%s profile_dir=%s active_host=%s active_path=%s query=%d url_len=%zu title_len=%zu elapsed_ms=%llu",
        static_cast<unsigned long long>(start_generation), static_cast<unsigned long>(sg().child_pid), python_path.c_str(),
        sg().active_profile_dir.empty() ? "<empty>" : sg().active_profile_dir.c_str(),
        ready_url.host.c_str(), ready_url.path.c_str(), static_cast<int>(ready_url.has_query),
        ready_url.length, sg().active_page_title.size(), static_cast<unsigned long long>(sg().last_launch_ms));
    publish_state(bridge_state_t::ready, std::string());
    return true;
}

uint64_t begin_activity(const char* owner)
{
    const uint64_t token = sg().next_activity_token.fetch_add(1, std::memory_order_relaxed);
    const uint32_t active = sg().active_activities.fetch_add(1, std::memory_order_acq_rel) + 1;
    ++g_bridge_activity_depth;
    const auto status = get_status();
    diag::log_tagged_fmt("camoufox", "activity_begin owner=%s token=%llu active=%lu tls_depth=%lu caller_pid=%lu caller_tid=%lu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu",
        safe_reason(owner), static_cast<unsigned long long>(token), static_cast<unsigned long>(active),
        static_cast<unsigned long>(g_bridge_activity_depth), static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()), static_cast<int>(status.state),
        static_cast<unsigned long long>(status.generation), static_cast<unsigned long>(status.child_pid),
        status.child_alive ? 1 : 0, status.browser_open ? 1 : 0, status.page_verified ? 1 : 0,
        status.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(status.total_errors));
    return token;
}

void end_activity(uint64_t token, const char* owner)
{
    uint32_t previous = sg().active_activities.load(std::memory_order_acquire);
    while (previous != 0 && !sg().active_activities.compare_exchange_weak(previous, previous - 1, std::memory_order_acq_rel, std::memory_order_acquire)) {}
    if (g_bridge_activity_depth != 0)
        --g_bridge_activity_depth;
    const uint32_t active = sg().active_activities.load(std::memory_order_acquire);
    const auto status = get_status();
    diag::log_tagged_fmt("camoufox", "activity_end owner=%s token=%llu active=%lu tls_depth=%lu caller_pid=%lu caller_tid=%lu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu",
        safe_reason(owner), static_cast<unsigned long long>(token), static_cast<unsigned long>(active),
        static_cast<unsigned long>(g_bridge_activity_depth), static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()), static_cast<int>(status.state),
        static_cast<unsigned long long>(status.generation), static_cast<unsigned long>(status.child_pid),
        status.child_alive ? 1 : 0, status.browser_open ? 1 : 0, status.page_verified ? 1 : 0,
        status.cleanup_pending ? 1 : 0, static_cast<unsigned long long>(status.total_errors));
}

bool stop_bridge(const char* reason)
{
    const uint64_t stop_start_ms = now_ms();
    const uint64_t stop_epoch = sg().stop_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
    const char* stop_reason = safe_reason(reason);
    diag::log_tagged_fmt("camoufox", "stop_bridge entry epoch=%llu reason=%s active=%lu tls_depth=%lu caller_pid=%lu caller_tid=%lu",
        static_cast<unsigned long long>(stop_epoch), stop_reason,
        static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
        static_cast<unsigned long>(g_bridge_activity_depth), static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    sg().stop_requested.store(true, std::memory_order_release);
    diag::log_tagged_fmt("camoufox", "stop_bridge stop_requested_set epoch=%llu reason=%s",
        static_cast<unsigned long long>(stop_epoch), stop_reason);
    if (g_bridge_activity_depth == 0)
    {
        const uint64_t activity_wait_start_ms = now_ms();
        uint64_t last_activity_log_ms = activity_wait_start_ms;
        while (sg().active_activities.load(std::memory_order_acquire) != 0 &&
            now_ms() - activity_wait_start_ms < kActivityDrainWaitMs)
        {
            const uint64_t now = now_ms();
            if (now - last_activity_log_ms >= 1000)
            {
                const auto status = get_status();
                diag::log_tagged_fmt("camoufox", "stop_bridge waiting_for_activity reason=%s active=%lu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d elapsed_ms=%llu limit_ms=%llu",
                    stop_reason, static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)),
                    static_cast<int>(status.state), static_cast<unsigned long long>(status.generation),
                    static_cast<unsigned long>(status.child_pid), status.child_alive ? 1 : 0,
                    status.browser_open ? 1 : 0, status.page_verified ? 1 : 0,
                    status.cleanup_pending ? 1 : 0,
                    static_cast<unsigned long long>(now - activity_wait_start_ms),
                    static_cast<unsigned long long>(kActivityDrainWaitMs));
                last_activity_log_ms = now;
            }
            Sleep(25);
        }
        const uint32_t active_after_wait = sg().active_activities.load(std::memory_order_acquire);
        if (active_after_wait != 0)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge activity_wait_timeout reason=%s active=%lu elapsed_ms=%llu",
                stop_reason, static_cast<unsigned long>(active_after_wait),
                static_cast<unsigned long long>(now_ms() - activity_wait_start_ms));
        }
        else if (now_ms() != activity_wait_start_ms)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge activity_wait_drained reason=%s elapsed_ms=%llu",
                stop_reason, static_cast<unsigned long long>(now_ms() - activity_wait_start_ms));
        }
    }
    else
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge activity_wait_bypass reason=%s tls_depth=%lu active=%lu",
            stop_reason, static_cast<unsigned long>(g_bridge_activity_depth),
            static_cast<unsigned long>(sg().active_activities.load(std::memory_order_acquire)));
    }
    std::unique_lock<std::recursive_mutex> op_lk(sg().operation_mtx, std::try_to_lock);
    if (!op_lk.owns_lock())
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge waiting_for_operation_cancel_signal reason=%s", stop_reason);
        op_lk.lock();
        diag::log_tagged_fmt("camoufox", "stop_bridge operation_lock_acquired_after_wait reason=%s elapsed_ms=%llu",
            stop_reason, static_cast<unsigned long long>(now_ms() - stop_start_ms));
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
            diag::log_tagged_fmt("camoufox", "stop_bridge busy_stop_requested reason=%s elapsed_ms=%llu",
                stop_reason, static_cast<unsigned long long>(now_ms() - stop_start_ms));
            return false;
        }
        if (now_ms() - state_wait_start_ms != 0)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge state_lock_acquired reason=%s elapsed_ms=%llu",
                stop_reason, static_cast<unsigned long long>(now_ms() - state_wait_start_ms));
        }
        diag::log_tagged_fmt("camoufox", "stop_bridge state_snapshot reason=%s state=%d generation=%llu child_pid=%lu browser_open=%d page_verified=%d cleanup_pending=%d",
            stop_reason,
            static_cast<int>(sg().state), static_cast<unsigned long long>(sg().generation),
            static_cast<unsigned long>(sg().child_pid), static_cast<int>(sg().browser_open),
            static_cast<int>(sg().page_verified), static_cast<int>(sg().cleanup_pending));
        if (sg().state == bridge_state_t::stopped)
        {
            diag::log_tagged_fmt("camoufox", "stop_bridge already_stopped reason=%s", stop_reason);
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
        mark_cleanup_started_locked(stop_generation, child_pid, std::string("stop_bridge:") + stop_reason);
    }
    if (cli && browser_open)
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge scheduling_cleanup reason=%s generation=%llu child_pid=%lu close_browser=1",
            stop_reason, static_cast<unsigned long long>(stop_generation), static_cast<unsigned long>(child_pid));
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
        if (!post_bridge_task("camoufox.close", close_task)) {
            diag::log_tagged("camoufox", "stop_bridge close_browser_post_failed");
            close_task();
        }
        cleanup_client_async(nullptr, child_pid, std::string("stop_bridge:") + stop_reason, stop_generation);
    }
    else if (cli)
    {
        diag::log_tagged_fmt("camoufox", "stop_bridge scheduling_cleanup reason=%s generation=%llu child_pid=%lu close_browser=0",
            stop_reason, static_cast<unsigned long long>(stop_generation), static_cast<unsigned long>(child_pid));
        cleanup_client_async(cli, child_pid, std::string("stop_bridge:") + stop_reason, stop_generation);
    }
    else
    {
        cleanup_client_async(nullptr, child_pid, std::string("stop_bridge:") + stop_reason, stop_generation);
    }
    publish_state(bridge_state_t::stopped, std::string());
    diag::log_tagged_fmt("camoufox", "bridge stopped reason=%s generation=%llu elapsed_ms=%llu",
        stop_reason, static_cast<unsigned long long>(stop_generation), static_cast<unsigned long long>(now_ms() - stop_start_ms));
    return true;
}

bool force_cleanup(const char* reason)
{
    const uint64_t t0 = now_ms();
    const char* cleanup_reason = safe_reason(reason);
    const uint64_t epoch = sg().stop_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
    sg().stop_requested.store(true, std::memory_order_release);

    std::shared_ptr<mcp_client::client_t> cli;
    uint32_t child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
    std::string profile_dir;
    bridge_state_t state_before = bridge_state_t::stopped;
    bool browser_open = false;
    bool page_verified = false;
    bool cleanup_pending = false;
    uint64_t generation = epoch;
    bool state_locked = false;
    bool cleanup_marked = false;

    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::defer_lock);
    const uint64_t lock_start = now_ms();
    while (!(state_locked = lk.try_lock()))
    {
        if (now_ms() - lock_start >= 750)
            break;
        Sleep(10);
    }

    if (state_locked)
    {
        state_before = sg().state;
        browser_open = sg().browser_open;
        page_verified = sg().page_verified;
        cleanup_pending = sg().cleanup_pending;
        if (sg().child_pid != 0)
            child_pid = sg().child_pid;
        else if (sg().cleanup_child_pid != 0)
            child_pid = sg().cleanup_child_pid;
        else if (child_pid == 0)
            child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
        profile_dir = !sg().active_profile_dir.empty() ? sg().active_profile_dir : sg().cleanup_profile_dir;
        cli = sg().client;
        generation = ++sg().generation;
        sg().client.reset();
        sg().server_command.clear();
        clear_page_state_locked();
        sg().child_pid = 0;
        sg().state = bridge_state_t::stopped;
        sg().last_error.clear();
        if (child_pid != 0 || cli)
        {
            mark_cleanup_started_locked(generation, child_pid, std::string("force_cleanup:") + cleanup_reason);
            cleanup_marked = true;
        }
        else
        {
            sg().cleanup_pending = false;
            sg().last_cleanup_ms = now_ms() - t0;
        }
        sg().active_profile_dir.clear();
        lk.unlock();
    }

    const std::vector<process_tree_entry_t> before_tree = child_pid == 0 ? std::vector<process_tree_entry_t>() : enumerate_process_tree(child_pid);
    const size_t descendants_before = before_tree.size() > 0 ? before_tree.size() - 1 : 0;
    diag::log_tagged_critical_fmt("camoufox", "force_cleanup_begin epoch=%llu generation=%llu reason=%s state_locked=%d lock_elapsed_ms=%llu state_before=%d child_pid=%lu descendants=%zu profile_dir=%s browser_open=%d page_verified=%d cleanup_pending=%d client=%d",
        static_cast<unsigned long long>(epoch), static_cast<unsigned long long>(generation), cleanup_reason,
        state_locked ? 1 : 0, static_cast<unsigned long long>(now_ms() - lock_start),
        static_cast<int>(state_before), static_cast<unsigned long>(child_pid), descendants_before,
        profile_dir.empty() ? "<empty>" : profile_dir.c_str(), browser_open ? 1 : 0, page_verified ? 1 : 0,
        cleanup_pending ? 1 : 0, cli ? 1 : 0);

    process_tree_reap_result_t reap;
    if (child_pid != 0)
        reap = terminate_process_tree_sync(child_pid, std::string("force_cleanup:") + cleanup_reason);
    else
        diag::log_tagged_critical_fmt("camoufox", "force_cleanup_no_pid epoch=%llu generation=%llu reason=%s", static_cast<unsigned long long>(epoch), static_cast<unsigned long long>(generation), cleanup_reason);

    if (cli)
        disconnect_client_async(cli, std::string("force_cleanup:") + cleanup_reason + ":disconnect");

    if (cleanup_marked)
        mark_cleanup_finished(generation, now_ms() - t0, std::string("force_cleanup:") + cleanup_reason);
    else if (child_pid != 0 && reap.alive_after == 0 && sg().tracked_child_pid.load(std::memory_order_acquire) == child_pid)
        sg().tracked_child_pid.store(0, std::memory_order_release);

    const bool success = child_pid == 0 || reap.alive_after == 0;
    publish_state(bridge_state_t::stopped, std::string());
    diag::log_tagged_critical_fmt("camoufox", "force_cleanup_end epoch=%llu generation=%llu reason=%s success=%d child_pid=%lu descendants_before=%zu alive_after=%zu profile_dir=%s elapsed_ms=%llu",
        static_cast<unsigned long long>(epoch), static_cast<unsigned long long>(generation), cleanup_reason,
        success ? 1 : 0, static_cast<unsigned long>(child_pid), reap.descendants_before, reap.alive_after,
        profile_dir.empty() ? "<empty>" : profile_dir.c_str(), static_cast<unsigned long long>(now_ms() - t0));
    return success;
}

bool wait_until_idle(uint32_t timeout_ms, const char* reason)
{
    const uint64_t t0 = now_ms();
    const char* wait_reason = safe_reason(reason);
    const uint64_t limit_ms = timeout_ms == 0 ? 1 : static_cast<uint64_t>(timeout_ms);
    uint64_t last_log_ms = 0;
    for (;;)
    {
        const uint64_t now = now_ms();
        std::unique_lock<std::recursive_mutex> op_lk(sg().operation_mtx, std::try_to_lock);
        const bool operation_idle = op_lk.owns_lock();
        const uint32_t active = sg().active_activities.load(std::memory_order_acquire);
        bridge_state_t state = bridge_state_t::stopped;
        uint64_t generation = 0;
        uint32_t child_pid = 0;
        bool cleanup_pending = false;
        bool child_alive = false;
        size_t err_len = 0;
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            state = sg().state;
            generation = sg().generation;
            child_pid = sg().child_pid != 0 ? sg().child_pid : sg().cleanup_child_pid;
            cleanup_pending = sg().cleanup_pending;
            err_len = sg().last_error.size();
        }
        if (operation_idle && active == 0 && !cleanup_pending)
        {
            child_alive = process_alive(child_pid);
            diag::log_tagged_fmt("camoufox", "wait_until_idle ok reason=%s elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d err_len=%zu",
                wait_reason, static_cast<unsigned long long>(now - t0), static_cast<int>(state),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                child_alive ? 1 : 0, err_len);
            return true;
        }
        if (now - t0 >= limit_ms)
        {
            child_alive = process_alive(child_pid);
            diag::log_tagged_fmt("camoufox", "wait_until_idle timeout reason=%s elapsed_ms=%llu limit_ms=%llu operation_idle=%d active=%lu state=%d generation=%llu child_pid=%lu child_alive=%d cleanup_pending=%d err_len=%zu",
                wait_reason, static_cast<unsigned long long>(now - t0), static_cast<unsigned long long>(limit_ms),
                operation_idle ? 1 : 0, static_cast<unsigned long>(active), static_cast<int>(state),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                child_alive ? 1 : 0, cleanup_pending ? 1 : 0, err_len);
            return false;
        }
        if (now - last_log_ms >= 1000)
        {
            child_alive = process_alive(child_pid);
            diag::log_tagged_fmt("camoufox", "wait_until_idle wait reason=%s elapsed_ms=%llu limit_ms=%llu operation_idle=%d active=%lu state=%d generation=%llu child_pid=%lu child_alive=%d cleanup_pending=%d err_len=%zu",
                wait_reason, static_cast<unsigned long long>(now - t0), static_cast<unsigned long long>(limit_ms),
                operation_idle ? 1 : 0, static_cast<unsigned long>(active), static_cast<int>(state),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                child_alive ? 1 : 0, cleanup_pending ? 1 : 0, err_len);
            last_log_ms = now;
        }
        Sleep(50);
    }
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
    {
        diag::log_tagged_fmt("camoufox", "ensure_ready probe_begin state=%d elapsed_ms=%llu",
            static_cast<int>(st.state), static_cast<unsigned long long>(now_ms() - t0));
        st = install::probe();
        diag::log_tagged_fmt("camoufox", "ensure_ready probe_end state=%d python=%s message=%s elapsed_ms=%llu",
            static_cast<int>(st.state), st.python_path.empty() ? "<empty>" : st.python_path.c_str(),
            st.last_message.empty() ? "<empty>" : st.last_message.c_str(),
            static_cast<unsigned long long>(now_ms() - t0));
    }
    if (st.state != install::install_state_t::ok)
    {
        std::string setup_log;
        bool setup_ready = false;
        const uint64_t setup_start_ms = now_ms();
        diag::log_tagged_fmt("camoufox", "ensure_ready setup_begin state=%d elapsed_ms=%llu",
            static_cast<int>(st.state), static_cast<unsigned long long>(setup_start_ms - t0));
        try { setup_ready = install::ensure_ready(setup_log); } catch (...) { setup_ready = false; }
        st = install::get_status();
        diag::log_tagged_fmt("camoufox", "ensure_ready setup_end ready=%d state=%d python=%s setup_elapsed_ms=%llu setup_log_len=%zu err=%s",
            static_cast<int>(setup_ready), static_cast<int>(st.state),
            st.python_path.empty() ? "<empty>" : st.python_path.c_str(),
            static_cast<unsigned long long>(now_ms() - setup_start_ms), setup_log.size(),
            install::last_error().c_str());
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
    std::string server_executable;
    const bool use_server_executable = resolve_reverse_mcp_executable(cfg, server_executable);
    if (use_server_executable && cfg.server_executable.empty())
        cfg.server_executable = server_executable;
    if (cfg.python_executable.empty()) cfg.python_executable = st.python_path;
    if (!use_server_executable && cfg.python_executable.empty())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        sg().last_error = st.last_message.empty()
            ? "Camoufox Python runtime unavailable after dependency setup"
            : st.last_message;
        diag::log_tagged_fmt("camoufox", "ensure_ready missing_python_after_setup state=%d err=%s",
            static_cast<int>(st.state), sg().last_error.c_str());
        return false;
    }
    diag::log_tagged_fmt("camoufox", "ensure_ready starting_bridge mode=%s command=%s module=%s has_proxy=%d",
        use_server_executable ? "frozen_executable" : "python",
        use_server_executable ? cfg.server_executable.c_str() : cfg.python_executable.c_str(),
        cfg.server_module.c_str(),
        static_cast<int>(!cfg.proxy.empty()));
    bool ok = start_bridge(cfg);
    diag::log_tagged_fmt("camoufox", "ensure_ready exit ok=%d elapsed_ms=%llu err_len=%zu",
        static_cast<int>(ok), static_cast<unsigned long long>(now_ms() - t0), last_error().size());
    return ok;
}

bool prewarm_default_async(const char* reason)
{
    const char* owner = safe_reason(reason);
    if (prewarm_default_disabled())
    {
        diag::log_tagged_fmt("camoufox", "prewarm_default_disabled reason=%s", owner);
        return true;
    }
    bridge_status_t before = get_status();
    const bool ready = before.state == bridge_state_t::ready &&
                       before.child_alive &&
                       before.browser_open &&
                       before.page_verified;
    if (ready)
    {
        prewarm_default_requested().store(true, std::memory_order_release);
        diag::log_tagged_fmt("camoufox", "prewarm_default_already_ready reason=%s generation=%llu child_pid=%lu last_launch_ms=%llu last_nav_ms=%llu",
            owner,
            static_cast<unsigned long long>(before.generation),
            static_cast<unsigned long>(before.child_pid),
            static_cast<unsigned long long>(before.last_launch_ms),
            static_cast<unsigned long long>(before.last_nav_ms));
        return true;
    }
    bool expected = false;
    if (!prewarm_default_requested().compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        diag::log_tagged_fmt("camoufox", "prewarm_default_already_requested reason=%s state=%d child_pid=%lu browser_open=%d page_verified=%d child_alive=%d",
            owner,
            static_cast<int>(before.state),
            static_cast<unsigned long>(before.child_pid),
            before.browser_open ? 1 : 0,
            before.page_verified ? 1 : 0,
            before.child_alive ? 1 : 0);
        return true;
    }
    std::string reason_copy(owner);
    bool posted = work_queue::post([reason_copy]() {
        const uint64_t t0 = now_ms();
        diag::log_tagged_fmt("camoufox", "prewarm_default_worker_begin reason=%s pid=%lu tid=%lu",
            reason_copy.c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        bool ok = false;
        try { ok = ensure_ready(); } catch (...) { ok = false; }
        bridge_status_t after = get_status();
        diag::log_tagged_fmt("camoufox", "prewarm_default_worker_end reason=%s ok=%d elapsed_ms=%llu state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d last_launch_ms=%llu last_nav_ms=%llu err_len=%zu",
            reason_copy.c_str(),
            ok ? 1 : 0,
            static_cast<unsigned long long>(now_ms() - t0),
            static_cast<int>(after.state),
            static_cast<unsigned long long>(after.generation),
            static_cast<unsigned long>(after.child_pid),
            after.child_alive ? 1 : 0,
            after.browser_open ? 1 : 0,
            after.page_verified ? 1 : 0,
            static_cast<unsigned long long>(after.last_launch_ms),
            static_cast<unsigned long long>(after.last_nav_ms),
            after.last_error.size());
        if (!ok)
            prewarm_default_requested().store(false, std::memory_order_release);
    });
    if (!posted)
    {
        prewarm_default_requested().store(false, std::memory_order_release);
        diag::log_tagged_fmt("camoufox", "prewarm_default_post_failed reason=%s state=%d child_pid=%lu",
            owner,
            static_cast<int>(before.state),
            static_cast<unsigned long>(before.child_pid));
        return false;
    }
    diag::log_tagged_fmt("camoufox", "prewarm_default_posted reason=%s state=%d child_pid=%lu browser_open=%d page_verified=%d child_alive=%d",
        owner,
        static_cast<int>(before.state),
        static_cast<unsigned long>(before.child_pid),
        before.browser_open ? 1 : 0,
        before.page_verified ? 1 : 0,
        before.child_alive ? 1 : 0);
    return true;
}

call_result_t managed_call_with_deadline(const std::shared_ptr<managed_session_t>& session, const std::string& tool_name, const nlohmann::json& args, int timeout_ms, bool allow_starting = false)
{
    call_result_t fail;
    fail.ok = false;
    if (!session)
    {
        fail.error = "camoufox managed session is unavailable";
        return fail;
    }
    if (timeout_ms <= 0) timeout_ms = 30000;
    const uint64_t request_id = session->next_request_id.fetch_add(1, std::memory_order_relaxed);
    std::shared_ptr<mcp_client::client_t> cli;
    uint64_t generation = 0;
    uint32_t child_pid = 0;
    bridge_state_t session_state = bridge_state_t::stopped;
    bool has_client = false;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session_state = session->state;
        has_client = static_cast<bool>(session->client);
        if (session->client && (session->state == bridge_state_t::ready || (allow_starting && session->state == bridge_state_t::starting)))
            cli = session->client;
        generation = session->generation;
        child_pid = session->child_pid;
    }
    if (!cli)
    {
        diag::log_tagged_fmt("camoufox", "managed_call not_ready session_id=%s request_id=%llu tool=%s state=%d has_client=%d allow_starting=%d generation=%llu child_pid=%lu last_error=%s",
            session->session_id.c_str(),
            static_cast<unsigned long long>(request_id),
            tool_name.c_str(),
            static_cast<int>(session_state),
            has_client ? 1 : 0,
            allow_starting ? 1 : 0,
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(child_pid),
            session->last_error.c_str());
        fail.error = session->last_error.empty() ? std::string("camoufox managed session is not ready") : session->last_error;
        return fail;
    }
    struct shared_state_t
    {
        std::mutex                mtx;
        std::condition_variable   cv;
        bool                      done = false;
        bool                      cancelled = false;
        mcp_client::call_result_t result;
    };
    auto state = std::make_shared<shared_state_t>();
    const uint64_t t0 = now_ms();
    session->total_calls.fetch_add(1, std::memory_order_relaxed);
    diag::log_tagged_fmt("camoufox", "managed_call dispatch session_id=%s request_id=%llu tool=%s timeout_ms=%d generation=%llu child_pid=%lu args_shape=%s",
        session->session_id.c_str(), static_cast<unsigned long long>(request_id), tool_name.c_str(), timeout_ms,
        static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid), json_shape(args).c_str());
    bool posted = post_bridge_task("camoufox.session.call", [state, cli, tool_name, args, request_id, generation, child_pid, sid = session->session_id]() {
        const uint64_t worker_start = now_ms();
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
            diag::log_tagged_critical_fmt("camoufox", "managed_call guarded_failure session_id=%s request_id=%llu tool=%s generation=%llu child_pid=%lu status=0x%08lX native=%d cpp=%d elapsed_ms=%llu err=%s",
                sid.c_str(), static_cast<unsigned long long>(request_id), tool_name.c_str(),
                static_cast<unsigned long long>(generation), static_cast<unsigned long>(child_pid),
                static_cast<unsigned long>(guard_status), static_cast<int>(call_ctx.native_exception),
                static_cast<int>(call_ctx.cpp_exception), static_cast<unsigned long long>(now_ms() - worker_start), r.text.c_str());
        }
        {
            std::lock_guard<std::mutex> lk(state->mtx);
            state->result = std::move(r);
            state->done = true;
        }
        state->cv.notify_all();
    });
    if (!posted)
    {
        fail.error = "camoufox managed call dispatch post failed";
        session->total_errors.fetch_add(1, std::memory_order_relaxed);
        return fail;
    }
    std::unique_lock<std::mutex> lk(state->mtx);
    const bool got = state->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&state]() { return state->done; });
    if (!got)
    {
        state->cancelled = true;
        lk.unlock();
        uint32_t timed_out_pid = 0;
        {
            std::lock_guard<std::recursive_mutex> slk(session->mtx);
            timed_out_pid = session->child_pid;
            session->state = bridge_state_t::error;
            session->last_error = std::string("camoufox managed call timeout: ") + tool_name;
            session->client.reset();
            session->browser_open = false;
            session->page_verified = false;
        }
        if (timed_out_pid != 0)
            terminate_process_id_async(timed_out_pid, std::string("managed_timeout_") + session->session_id + "_" + tool_name);
        session->total_errors.fetch_add(1, std::memory_order_relaxed);
        fail.error = std::string("camoufox managed call timeout: ") + tool_name;
        return fail;
    }
    mcp_client::call_result_t result = std::move(state->result);
    lk.unlock();
    call_result_t out = to_bridge_result(result);
    {
        std::lock_guard<std::recursive_mutex> slk(session->mtx);
        session->last_call_ms = now_ms();
        if (out.ok)
        {
            session->last_error.clear();
            if (out.data.is_object())
                update_page_cache_from_json_locked(*session, out.data, tool_name.c_str());
        }
        else
        {
            session->last_error = out.error;
            session->total_errors.fetch_add(1, std::memory_order_relaxed);
        }
    }
    diag::log_tagged_fmt("camoufox", "managed_call complete session_id=%s request_id=%llu tool=%s ok=%d elapsed_ms=%llu data_shape=%s err_len=%zu",
        session->session_id.c_str(), static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(out.ok),
        static_cast<unsigned long long>(now_ms() - t0), json_shape(out.data).c_str(), out.error.size());
    return out;
}

bridge_status_t managed_status(const std::shared_ptr<managed_session_t>& session)
{
    bridge_status_t s;
    if (!session)
    {
        s.state = bridge_state_t::stopped;
        s.session_count = managed_session_count();
        return s;
    }
    std::lock_guard<std::recursive_mutex> lk(session->mtx);
    s.session_id = session->session_id;
    s.active_session_id = session->session_id;
    s.state = session->state;
    s.last_error = session->last_error;
    s.server_command = session->server_command;
    s.child_pid = session->child_pid;
    s.launched_ms = session->launched_ms;
    s.last_call_ms = session->last_call_ms;
    s.total_calls = session->total_calls.load(std::memory_order_relaxed);
    s.total_errors = session->total_errors.load(std::memory_order_relaxed);
    s.browser_open = session->browser_open;
    s.active_page_id = session->active_page_id;
    s.active_page_url = session->active_page_url;
    s.active_page_title = session->active_page_title;
    s.active_profile_dir = session->active_profile_dir;
    s.page_verified = session->page_verified;
    s.cleanup_pending = session->cleanup_pending;
    s.generation = session->generation;
    s.last_launch_ms = session->last_launch_ms;
    s.last_nav_ms = session->last_nav_ms;
    s.last_cleanup_ms = session->last_cleanup_ms;
    s.last_verified_ms = session->last_verified_ms;
    s.pages = session->pages;
    s.page_count = static_cast<uint32_t>(session->pages.size());
    s.session_count = managed_session_count();
    s.child_alive = process_alive(s.child_pid);
    if (s.state == bridge_state_t::ready && (!s.child_alive || !s.browser_open || !s.page_verified))
    {
        s.state = bridge_state_t::error;
        if (s.last_error.empty())
            s.last_error = "camoufox managed session readiness verification failed";
    }
    return s;
}

bool start_managed_bridge(const launch_config_t& cfg, const std::string& session_id)
{
    const uint64_t t0 = now_ms();
    const std::string sid = normalize_session_id(session_id);
    auto session = get_managed_session(sid, true);
    if (!session) return start_bridge(cfg);
    std::unique_lock<std::recursive_mutex> op_lk(session->operation_mtx, std::try_to_lock);
    if (!op_lk.owns_lock())
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->last_error = "camoufox managed session operation already active";
        return false;
    }
    launch_config_t effective_cfg = cfg;
    enforce_private_launch_config(effective_cfg);
    effective_cfg.session_id = sid;
    if (effective_cfg.headless)
    {
        diag::log_tagged_fmt("camoufox", "managed_start forcing_visible session_id=%s requested_headless=1", sid.c_str());
        effective_cfg.headless = false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        if (session->state == bridge_state_t::ready && session->client && session->browser_open && session->page_verified && process_alive(session->child_pid))
        {
            session->active_cfg = effective_cfg;
            session->last_launch_ms = now_ms() - t0;
            diag::log_tagged_fmt("camoufox", "managed_start reuse_ready session_id=%s child_pid=%lu page_count=%zu",
                sid.c_str(), static_cast<unsigned long>(session->child_pid), session->pages.size());
            return true;
        }
    }
    std::string python_path = effective_cfg.python_executable;
    const bool prefer_developer_python = should_prefer_developer_python_runtime(effective_cfg);
    std::string server_executable;
    bool use_server_executable = resolve_reverse_mcp_executable(effective_cfg, server_executable);
    bool developer_python_ready = !python_path.empty();
    if (!use_server_executable)
    {
        if (prefer_developer_python && python_path.empty())
            developer_python_ready = ensure_python_available(python_path);
        else
            developer_python_ready = !python_path.empty();
    }
    diag::log_tagged_fmt("camoufox", "managed_start server_executable_resolve session_id=%s use_exe=%d prefer_python=%d python_ready=%d python=%s path=%s",
        sid.c_str(), static_cast<int>(use_server_executable),
        prefer_developer_python ? 1 : 0,
        developer_python_ready ? 1 : 0,
        python_path.empty() ? "<empty>" : python_path.c_str(),
        server_executable.empty() ? "<empty>" : server_executable.c_str());

    if (!use_server_executable && !python_path.empty())
    {
        std::string reason;
        if (!system_python_discovery_allowed() && !is_app_controlled_python_path(python_path))
        {
            reason = "explicit Python path is outside AiDA-controlled Camoufox runtime roots";
            diag::log_tagged_fmt("camoufox", "managed_start explicit_python_rejected session_id=%s path=%s reason=%s",
                sid.c_str(), python_path.c_str(), reason.c_str());
            python_path.clear();
        }
        else if (!supported_camoufox_python(python_path, &reason))
        {
            diag::log_tagged_fmt("camoufox", "managed_start explicit_python_rejected session_id=%s path=%s reason=%s",
                sid.c_str(), python_path.c_str(), reason.c_str());
            python_path.clear();
        }
    }
    if (!use_server_executable)
    {
        diag::log_tagged_fmt("camoufox", "managed_start python_resolve_begin session_id=%s explicit=%d elapsed_ms=%llu",
            sid.c_str(), static_cast<int>(!python_path.empty()),
            static_cast<unsigned long long>(now_ms() - t0));
        if (python_path.empty() && !ensure_python_available(python_path))
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            session->state = bridge_state_t::error;
            session->last_error = last_error();
            if (session->last_error.empty()) session->last_error = install::setup_instructions();
            diag::log_tagged_fmt("camoufox", "managed_start python_resolve_failed session_id=%s elapsed_ms=%llu err=%s",
                sid.c_str(), static_cast<unsigned long long>(now_ms() - t0), session->last_error.c_str());
            return false;
        }
        diag::log_tagged_fmt("camoufox", "managed_start python_resolve_end session_id=%s python=%s elapsed_ms=%llu",
            sid.c_str(), python_path.c_str(), static_cast<unsigned long long>(now_ms() - t0));
    }
    if (effective_cfg.browser_executable.empty())
    {
        std::string env_browser;
        if (read_env_path_a("AIDA_CAMOUFOX_EXECUTABLE", env_browser))
            effective_cfg.browser_executable = env_browser;
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
    diag::log_tagged_fmt("camoufox", "managed_start browser_executable session_id=%s path=%s exists=%d attr=0x%08lX",
        sid.c_str(),
        effective_cfg.browser_executable.empty() ? "<empty>" : effective_cfg.browser_executable.c_str(),
        static_cast<int>(browser_attr != INVALID_FILE_ATTRIBUTES && (browser_attr & FILE_ATTRIBUTE_DIRECTORY) == 0),
        static_cast<unsigned long>(browser_attr));
    if (effective_cfg.browser_executable.empty() || browser_attr == INVALID_FILE_ATTRIBUTES || (browser_attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->state = bridge_state_t::error;
        session->last_error = effective_cfg.browser_executable.empty()
            ? std::string("Camoufox browser executable not found\n") + install::setup_instructions()
            : std::string("Configured Camoufox browser executable is unavailable\n") + install::setup_instructions();
        diag::log_tagged_fmt("camoufox", "managed_start browser_required_failed session_id=%s err=%s",
            sid.c_str(), session->last_error.c_str());
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        const uint64_t preflight_start_ms = now_ms();
        diag::log_tagged_fmt("camoufox", "managed_start preflight_begin session_id=%s command=%s browser=%s elapsed_ms=%llu",
            sid.c_str(), use_server_executable ? server_executable.c_str() : python_path.c_str(),
            effective_cfg.browser_executable.empty() ? "<empty>" : effective_cfg.browser_executable.c_str(),
            static_cast<unsigned long long>(preflight_start_ms - t0));
        bool preflight_ok = false;
        if (use_server_executable)
            preflight_ok = preflight_server_executable_locked(server_executable);
        else
            preflight_ok = prepare_install_for_launch_locked(python_path) && probe_module_installed_locked(python_path) && preflight_server_entry_locked(python_path, effective_cfg);
        if (!preflight_ok)
        {
            std::lock_guard<std::recursive_mutex> slk(session->mtx);
            session->state = bridge_state_t::error;
            session->last_error = sg().last_error.empty() ? std::string("camoufox managed session preflight failed") : sg().last_error;
            diag::log_tagged_fmt("camoufox", "managed_start preflight_failed session_id=%s preflight_elapsed_ms=%llu elapsed_ms=%llu err=%s",
                sid.c_str(), static_cast<unsigned long long>(now_ms() - preflight_start_ms),
                static_cast<unsigned long long>(now_ms() - t0), session->last_error.c_str());
            return false;
        }
        diag::log_tagged_fmt("camoufox", "managed_start preflight_end session_id=%s preflight_elapsed_ms=%llu elapsed_ms=%llu",
            sid.c_str(), static_cast<unsigned long long>(now_ms() - preflight_start_ms),
            static_cast<unsigned long long>(now_ms() - t0));
    }
    mcp_client::server_config_t scfg;
    scfg.name = std::string("camoufox-reverse-") + sid;
    scfg.transport = mcp_client::transport_type_t::stdio;
    scfg.command = use_server_executable ? server_executable : python_path;
    if (!use_server_executable)
    {
        scfg.args.push_back("-I");
        scfg.args.push_back("-m");
        scfg.args.push_back(effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
    }
    for (const auto& a : effective_cfg.extra_args) scfg.args.push_back(a);
    if (use_server_executable)
        scfg.env["AIDA_CAMOUFOX_MCP_EXECUTABLE"] = server_executable;
    else
        scfg.env["AIDA_CAMOUFOX_PYTHON"] = python_path;
    if (!use_server_executable && system_python_discovery_allowed())
        scfg.env["AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON"] = "1";
    populate_internal_camoufox_env(scfg, sid, effective_cfg.browser_executable, camoufox_debug_log_path());
    scfg.enabled = true;
    scfg.auto_connect = false;
    scfg.oauth_enabled = false;
    auto cli = std::make_shared<mcp_client::client_t>();
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->state = bridge_state_t::starting;
        session->last_error.clear();
        session->cleanup_pending = false;
        session->browser_open = false;
        session->page_verified = false;
        session->pages.clear();
        session->active_page_id.clear();
        session->generation++;
    }
    diag::log_tagged_fmt("camoufox", "managed_start connect session_id=%s command=%s module=%s env_browser=%d env_workdir=%d env_profile=%d",
        sid.c_str(), scfg.command.c_str(), use_server_executable ? "<frozen-executable>" : (scfg.args.size() > 2 ? scfg.args[2].c_str() : "<missing>"),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_EXECUTABLE") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_WORKING_DIR") != scfg.env.end()),
        static_cast<int>(scfg.env.find("AIDA_CAMOUFOX_PROFILE_ROOT") != scfg.env.end()));
    if (!cli->connect(scfg))
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->state = bridge_state_t::error;
        session->last_error = std::string("managed client connect failed: ") + cli->last_error();
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client = cli;
        session->server_command = use_server_executable
            ? server_executable
            : python_path + " -m " + (effective_cfg.server_module.empty() ? std::string("camoufox_reverse_mcp") : effective_cfg.server_module);
        session->child_pid = cli->child_process_id();
        session->launched_ms = now_ms();
        session->active_cfg = effective_cfg;
    }
    const bool bundled_visible_launch = !effective_cfg.headless && !effective_cfg.browser_executable.empty();
    const bool testlab_fast_probe = test_lab_launch_fail_fast_enabled(effective_cfg);
    int launch_wait_ms = effective_launch_wait_ms(effective_cfg, bundled_visible_launch);
    if (effective_cfg.launch_timeout_ms != launch_wait_ms || testlab_fast_probe)
    {
        diag::log_tagged_fmt("camoufox", "managed_start launch_timeout_clamped session_id=%s requested_ms=%d effective_ms=%d bundled_visible=%d testlab_fast_probe=%d",
            sid.c_str(), effective_cfg.launch_timeout_ms, launch_wait_ms,
            bundled_visible_launch ? 1 : 0, testlab_fast_probe ? 1 : 0);
    }
    int tool_wait_ms = std::min<int>(std::max<int>(launch_wait_ms / 4, 5000), kToolListWaitMaxMs);
    if (!wait_for_tool_listed(cli.get(), "launch_browser", tool_wait_ms))
    {
        const uint32_t pid = cli->child_process_id();
        cli->disconnect();
        terminate_process_id_async(pid, std::string("managed_launch_tool_missing_") + sid);
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::error;
        session->last_error = "camoufox managed MCP server did not expose launch_browser within timeout";
        return false;
    }
    effective_cfg.launch_timeout_ms = launch_wait_ms;
    nlohmann::json args = build_launch_args(effective_cfg);
    call_result_t launch = managed_call_with_deadline(session, "launch_browser", args, launch_wait_ms, true);
    if (!launch.ok)
    {
        const uint32_t pid = cli->child_process_id();
        cli->disconnect();
        terminate_process_id_async(pid, std::string("managed_launch_failed_") + sid);
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::error;
        session->last_error = launch.error.empty() ? std::string("camoufox managed launch_browser failed") : launch.error;
        return false;
    }
    call_result_t page = managed_call_with_deadline(session, "get_page_info", nlohmann::json::object(), kReadinessProbeTimeoutMs, true);
    if (!page.ok || !page.data.is_object() || !page.data.contains("url") || !page.data["url"].is_string())
    {
        const uint32_t pid = cli->child_process_id();
        cli->disconnect();
        terminate_process_id_async(pid, std::string("managed_readiness_failed_") + sid);
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::error;
        session->last_error = page.error.empty() ? std::string("camoufox managed readiness probe failed") : page.error;
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        update_page_cache_from_json_locked(*session, page.data, "managed_readiness");
        if (session->active_page_url.empty()) session->active_page_url = page.data["url"].get<std::string>();
        if (session->active_page_title.empty()) session->active_page_title = json_string_or(page.data, "title", std::string());
        session->browser_open = true;
        session->page_verified = true;
        session->state = bridge_state_t::ready;
        session->last_error.clear();
        session->last_verified_ms = now_ms();
        session->last_launch_ms = now_ms() - t0;
    }
    diag::log_tagged_fmt("camoufox", "managed_start ready session_id=%s child_pid=%lu elapsed_ms=%llu",
        sid.c_str(), static_cast<unsigned long>(cli->child_process_id()), static_cast<unsigned long long>(now_ms() - t0));
    return true;
}

bool stop_managed_bridge(const std::string& session_id, const char* reason)
{
    const std::string sid = normalize_session_id(session_id);
    auto session = get_managed_session(sid, false);
    if (!session) return true;
    const uint64_t t0 = now_ms();
    const char* stop_reason = safe_reason(reason);
    std::unique_lock<std::recursive_mutex> op_lk(session->operation_mtx);
    std::shared_ptr<mcp_client::client_t> cli;
    uint32_t child_pid = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        cli = session->client;
        child_pid = session->child_pid;
    }
    if (cli)
    {
        (void)managed_call_with_deadline(session, "close_browser", nlohmann::json::object(), 10000);
        cli->disconnect();
    }
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->client.reset();
        session->child_pid = 0;
        session->state = bridge_state_t::stopped;
        session->browser_open = false;
        session->page_verified = false;
        session->pages.clear();
        session->active_page_id.clear();
        session->active_page_url.clear();
        session->active_page_title.clear();
        session->last_error.clear();
        session->last_cleanup_ms = 0;
    }
    if (child_pid != 0)
        terminate_process_id_async(child_pid, std::string("managed_stop_") + sid + "_" + stop_reason);
    {
        std::lock_guard<std::recursive_mutex> lk(session->mtx);
        session->last_cleanup_ms = now_ms() - t0;
    }
    diag::log_tagged_fmt("camoufox", "managed_stop session_id=%s reason=%s child_pid=%lu elapsed_ms=%llu",
        sid.c_str(), stop_reason, static_cast<unsigned long>(child_pid), static_cast<unsigned long long>(now_ms() - t0));
    return true;
}

bridge_status_t get_status()
{
    bridge_status_t s;
    std::unique_lock<std::recursive_mutex> lk(sg().mtx, std::try_to_lock);
    if (!lk.owns_lock())
    {
        s.state = bridge_state_t::starting;
        s.last_error = "camoufox bridge state is busy";
        s.child_pid = sg().tracked_child_pid.load(std::memory_order_acquire);
        s.child_alive = process_alive(s.child_pid);
        s.total_calls = sg().total_calls.load(std::memory_order_relaxed);
        s.total_errors = sg().total_errors.load(std::memory_order_relaxed);
        s.session_id = "default";
        s.active_session_id = "default";
        s.session_count = managed_session_count();
        diag::log_tagged_fmt("camoufox", "get_status busy child_pid=%lu child_alive=%d calls=%llu errors=%llu",
            static_cast<unsigned long>(s.child_pid), s.child_alive ? 1 : 0,
            static_cast<unsigned long long>(s.total_calls),
            static_cast<unsigned long long>(s.total_errors));
        return s;
    }
    s.state           = sg().state;
    s.session_id      = sg().session_id.empty() ? std::string("default") : sg().session_id;
    s.active_session_id = s.session_id;
    s.session_count   = managed_session_count();
    s.last_error      = sg().last_error;
    s.server_command  = sg().server_command;
    s.child_pid       = sg().child_pid;
    s.launched_ms     = sg().launched_ms;
    s.last_call_ms    = sg().last_call_ms;
    s.total_calls     = sg().total_calls.load(std::memory_order_relaxed);
    s.total_errors    = sg().total_errors.load(std::memory_order_relaxed);
    s.browser_open    = sg().browser_open;
    s.active_page_id  = sg().active_page_id;
    s.active_page_url = sg().active_page_url;
    s.active_page_title = sg().active_page_title;
    s.pages           = sg().pages;
    s.page_count      = static_cast<uint32_t>(sg().pages.size());
    s.active_profile_dir = sg().active_profile_dir;
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
        s.active_page_id.clear();
        s.active_page_url.clear();
        s.active_page_title.clear();
        s.pages.clear();
        s.page_count = 0;
        s.active_profile_dir.clear();
        s.page_verified = false;
    }
    if (s.state == bridge_state_t::ready && (!s.child_alive || !s.browser_open || !s.page_verified))
    {
        s.state = bridge_state_t::error;
        s.browser_open = false;
        s.active_page_id.clear();
        s.active_page_url.clear();
        s.active_page_title.clear();
        s.pages.clear();
        s.page_count = 0;
        s.active_profile_dir.clear();
        s.page_verified = false;
        if (s.last_error.empty())
            s.last_error = "camoufox bridge readiness verification failed";
    }
    const url_log_t u = summarize_url_for_log(s.active_page_url);
    diag::log_tagged_fmt("camoufox", "get_status session_id=%s state=%d generation=%llu child_pid=%lu child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu profile_dir=%s active_page_id=%s page_count=%u active_host=%s active_path=%s query=%d url_len=%zu title_len=%zu",
        s.session_id.c_str(),
        static_cast<int>(s.state), static_cast<unsigned long long>(s.generation),
        static_cast<unsigned long>(s.child_pid), static_cast<int>(s.child_alive),
        static_cast<int>(s.browser_open), static_cast<int>(s.page_verified), static_cast<int>(s.cleanup_pending),
        static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors),
        s.active_profile_dir.empty() ? "<empty>" : s.active_profile_dir.c_str(),
        s.active_page_id.c_str(), static_cast<unsigned>(s.page_count),
        u.host.c_str(), u.path.c_str(),
        static_cast<int>(u.has_query), u.length, s.active_page_title.size());
    return s;
}

bridge_status_t get_status(const std::string& session_id)
{
    if (is_default_session_id(session_id))
        return get_status();
    return managed_status(get_managed_session(session_id, false));
}

bool start_bridge(const launch_config_t& cfg, const std::string& session_id)
{
    const std::string sid = normalize_session_id(session_id.empty() ? cfg.session_id : session_id);
    if (is_default_session_id(sid))
    {
        launch_config_t effective = cfg;
        effective.session_id = "default";
        return start_bridge(effective);
    }
    return start_managed_bridge(cfg, sid);
}

bool stop_bridge(const std::string& session_id, const char* reason)
{
    if (is_default_session_id(session_id))
        return stop_bridge(reason);
    return stop_managed_bridge(session_id, reason);
}

bool force_cleanup(const std::string& session_id, const char* reason)
{
    if (is_default_session_id(session_id))
        return force_cleanup(reason);
    return stop_managed_bridge(session_id, reason ? reason : "force_cleanup");
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
    const std::string requested_page_id = json_string_or(safe_args, "page_id", std::string());
    std::string restore_page_id;
    bool legacy_page_target_selected = false;
    if (!requested_page_id.empty() && !tool_accepts_page_id_directly(tool_name))
    {
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            restore_page_id = sg().active_page_id;
        }
        const int select_timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, 15000) : 15000;
        nlohmann::json select_args;
        select_args["page_id"] = requested_page_id;
        diag::log_tagged_fmt("camoufox", "call_tool legacy_page_target_select request_id=%llu tool=%s page_id=%s restore_page_id=%s timeout_ms=%d",
            static_cast<unsigned long long>(request_id), tool_name.c_str(), requested_page_id.c_str(), restore_page_id.c_str(), select_timeout_ms);
        call_result_t select_result = call_with_deadline("select_page", select_args, select_timeout_ms);
        if (!select_result.ok)
        {
            diag::log_tagged_fmt("camoufox", "call_tool legacy_page_target_select_failed request_id=%llu tool=%s page_id=%s err=%s data_shape=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), requested_page_id.c_str(),
                select_result.error.c_str(), json_shape(select_result.data).c_str());
            return page_target_select_failure(tool_name, "default", requested_page_id, select_result);
        }
        if (select_result.data.is_object())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            update_page_cache_from_json_locked(select_result.data, "legacy_page_target_select");
        }
        safe_args.erase("page_id");
        legacy_page_target_selected = true;
    }
    const bool has_page_target = !requested_page_id.empty() && tool_accepts_page_id_directly(tool_name);
    if (tool_name == "click" && !has_page_target)
    {
        r = dispatch_dom_click_action(json_string_or(safe_args, "selector", std::string()), timeout_ms, request_id);
    }
    else if (tool_name == "type_text" && !has_page_target)
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
    else if (tool_name == "wait_for" && !has_page_target)
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
    if (r.ok && r.data.is_object())
    {
        std::lock_guard<std::recursive_mutex> lk(sg().mtx);
        update_page_cache_from_json_locked(r.data, tool_name.c_str());
    }
    if (legacy_page_target_selected && !restore_page_id.empty() && restore_page_id != requested_page_id)
    {
        const int restore_timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, 15000) : 15000;
        nlohmann::json restore_args;
        restore_args["page_id"] = restore_page_id;
        call_result_t restore_result = call_with_deadline("select_page", restore_args, restore_timeout_ms);
        if (restore_result.ok && restore_result.data.is_object())
        {
            std::lock_guard<std::recursive_mutex> lk(sg().mtx);
            update_page_cache_from_json_locked(restore_result.data, "legacy_page_target_restore");
        }
        else if (!restore_result.ok)
        {
            diag::log_tagged_fmt("camoufox", "call_tool legacy_page_target_restore_failed request_id=%llu tool=%s requested_page_id=%s restore_page_id=%s err=%s data_shape=%s",
                static_cast<unsigned long long>(request_id), tool_name.c_str(), requested_page_id.c_str(), restore_page_id.c_str(),
                restore_result.error.c_str(), json_shape(restore_result.data).c_str());
        }
    }
    const action_snapshot_t exit = action_snapshot();
    diag::log_tagged_fmt("camoufox", "call_tool result request_id=%llu tool=%s ok=%d data_shape=%s text_len=%zu error_len=%zu generation=%llu child_pid=%lu state=%s browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        static_cast<unsigned long long>(request_id), tool_name.c_str(), static_cast<int>(r.ok), json_shape(r.data).c_str(), r.text.size(), r.error.size(),
        static_cast<unsigned long long>(exit.generation), static_cast<unsigned long>(exit.child_pid),
        bridge_state_name(exit.state), static_cast<int>(exit.browser_open), static_cast<int>(exit.page_verified),
        static_cast<int>(exit.child_alive), static_cast<int>(exit.cleanup_pending));
    return r;
}

call_result_t call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms, const std::string& session_id)
{
    if (is_default_session_id(session_id))
        return call_tool(tool_name, args, timeout_ms);
    auto session = get_managed_session(session_id, false);
    if (!session)
    {
        call_result_t out;
        out.ok = false;
        out.error = std::string("camoufox session is not running: ") + normalize_session_id(session_id);
        out.data = nlohmann::json{{"error", out.error}, {"session_id", normalize_session_id(session_id)}};
        return out;
    }
    std::lock_guard<std::recursive_mutex> op_lk(session->operation_mtx);
    nlohmann::json safe_args = args.is_null() ? nlohmann::json::object() : args;
    const std::string requested_page_id = json_string_or(safe_args, "page_id", std::string());
    std::string restore_page_id;
    bool legacy_page_target_selected = false;
    if (!requested_page_id.empty() && !tool_accepts_page_id_directly(tool_name))
    {
        {
            std::lock_guard<std::recursive_mutex> lk(session->mtx);
            restore_page_id = session->active_page_id;
        }
        const int select_timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, 15000) : 15000;
        nlohmann::json select_args;
        select_args["page_id"] = requested_page_id;
        diag::log_tagged_fmt("camoufox", "managed_call legacy_page_target_select session_id=%s tool=%s page_id=%s restore_page_id=%s timeout_ms=%d",
            session->session_id.c_str(), tool_name.c_str(), requested_page_id.c_str(), restore_page_id.c_str(), select_timeout_ms);
        call_result_t select_result = managed_call_with_deadline(session, "select_page", select_args, select_timeout_ms);
        if (!select_result.ok)
        {
            diag::log_tagged_fmt("camoufox", "managed_call legacy_page_target_select_failed session_id=%s tool=%s page_id=%s err=%s data_shape=%s",
                session->session_id.c_str(), tool_name.c_str(), requested_page_id.c_str(),
                select_result.error.c_str(), json_shape(select_result.data).c_str());
            return page_target_select_failure(tool_name, session->session_id, requested_page_id, select_result);
        }
        safe_args.erase("page_id");
        legacy_page_target_selected = true;
    }
    call_result_t r = managed_call_with_deadline(session, tool_name, safe_args, timeout_ms);
    if (legacy_page_target_selected && !restore_page_id.empty() && restore_page_id != requested_page_id)
    {
        const int restore_timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, 15000) : 15000;
        nlohmann::json restore_args;
        restore_args["page_id"] = restore_page_id;
        call_result_t restore_result = managed_call_with_deadline(session, "select_page", restore_args, restore_timeout_ms);
        if (!restore_result.ok)
        {
            diag::log_tagged_fmt("camoufox", "managed_call legacy_page_target_restore_failed session_id=%s tool=%s requested_page_id=%s restore_page_id=%s err=%s data_shape=%s",
                session->session_id.c_str(), tool_name.c_str(), requested_page_id.c_str(), restore_page_id.c_str(),
                restore_result.error.c_str(), json_shape(restore_result.data).c_str());
        }
    }
    return r;
}

bool launch_browser(const launch_config_t& cfg)
{
    diag::log_tagged_fmt("camoufox", "launch_browser entry headless=%d", static_cast<int>(cfg.headless));
    return start_bridge(cfg);
}

bool close_browser(const char* reason)
{
    diag::log_tagged_fmt("camoufox", "close_browser entry reason=%s caller_pid=%lu caller_tid=%lu",
        safe_reason(reason), static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return stop_bridge(reason);
}

call_result_t list_pages(const std::string& session_id)
{
    return call_tool("list_pages", nlohmann::json::object(), 15000, session_id);
}

call_result_t new_page(const std::string& session_id, const std::string& page_id, const std::string& url, bool make_active)
{
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    if (!url.empty()) args["url"] = url;
    args["make_active"] = make_active;
    return call_tool("new_page", args, 30000, session_id);
}

call_result_t select_page(const std::string& session_id, const std::string& page_id)
{
    nlohmann::json args;
    args["page_id"] = page_id;
    return call_tool("select_page", args, 15000, session_id);
}

call_result_t close_page(const std::string& session_id, const std::string& page_id)
{
    nlohmann::json args;
    args["page_id"] = page_id;
    return call_tool("close_page", args, 15000, session_id);
}

bool navigate(const std::string& url, const std::string& wait_until, int timeout_ms, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return navigate(url, wait_until, timeout_ms);
    nlohmann::json args;
    args["url"] = url;
    args["wait_until"] = wait_until.empty() ? std::string("domcontentloaded") : wait_until;
    args["collect_response_chain"] = true;
    args["clear_network_capture"] = true;
    args["include_title"] = false;
    if (!page_id.empty()) args["page_id"] = page_id;
    const int call_timeout = clamp_navigation_call_wait_ms(timeout_ms);
    call_result_t r = call_tool("navigate", args, call_timeout, session_id);
    if (!r.ok)
    {
        diag::log_tagged_fmt("camoufox", "navigate targeted failed session_id=%s page_id=%s err=%s",
            normalize_session_id(session_id).c_str(), page_id.c_str(), r.error.c_str());
        return false;
    }
    return true;
}

bool reload(const std::string& wait_until, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return reload(wait_until);
    nlohmann::json args;
    args["wait_until"] = wait_until.empty() ? std::string("domcontentloaded") : wait_until;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("reload", args, 35000, session_id).ok;
}

call_result_t evaluate_js(const std::string& expression, bool await_promise, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return evaluate_js(expression, await_promise);
    nlohmann::json args;
    args["expression"] = expression;
    args["await_promise"] = await_promise;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("evaluate_js", args, 60000, session_id);
}

call_result_t get_page_info(const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return get_page_info();
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("get_page_info", args, 15000, session_id);
}

call_result_t get_console_logs(size_t max_records, const std::string& session_id, const std::string& page_id)
{
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    call_result_t r = call_tool("get_console_logs", args, 15000, session_id);
    if (r.ok)
        r.data = normalize_console_log_data(r.data);
    if (r.ok && r.data.is_array() && max_records > 0 && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    return r;
}

call_result_t list_network_requests(size_t max_records, const std::string& session_id, const std::string& page_id)
{
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    call_result_t r = call_tool("list_network_requests", args, 30000, session_id);
    if (r.ok && r.data.is_object())
    {
        auto it = r.data.find("requests");
        if (it != r.data.end() && it->is_array())
            r.data = *it;
    }
    if (r.ok && r.data.is_array() && max_records > 0 && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    return r;
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
    a["wait_until"]           = wait_until.empty() ? std::string("domcontentloaded") : wait_until;
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
            update_page_cache_from_json_locked(r.data, "navigate_response");
            if (sg().active_page_url.empty()) sg().active_page_url = response_url;
            if (sg().active_page_title.empty()) sg().active_page_title = response_title;
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
        update_page_cache_from_json_locked(page.data, "navigate_verify");
        if (sg().active_page_url.empty()) sg().active_page_url = page.data["url"].get<std::string>();
        if (sg().active_page_title.empty()) sg().active_page_title = json_string_or(page.data, "title", std::string());
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
    a["wait_until"] = wait_until.empty() ? std::string("domcontentloaded") : wait_until;
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
        update_page_cache_from_json_locked(page.data, "reload_verify");
        if (sg().active_page_url.empty()) sg().active_page_url = page.data["url"].get<std::string>();
        if (sg().active_page_title.empty()) sg().active_page_title = json_string_or(page.data, "title", std::string());
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
    std::string warning_text;
    if (r.data.is_object() && r.data.contains("warning") && r.data["warning"].is_string())
    {
        warning_text = r.data["warning"].get<std::string>();
    }
    diag::log_tagged_fmt("camoufox", "add_init_script inline_ok data_shape=%s text_len=%zu warning=%s",
        json_shape(r.data).c_str(), r.text.size(), warning_text.c_str());
    return true;
}

call_result_t get_console_logs(size_t max_records)
{
    std::lock_guard<std::recursive_mutex> op_lk(sg().operation_mtx);
    diag::log_tagged_fmt("camoufox", "get_console_logs entry max_records=%zu", max_records);
    nlohmann::json a;
    if (max_records == 0) max_records = 200;
    call_result_t r = call_with_deadline("get_console_logs", a, 15000);
    if (r.ok)
        r.data = normalize_console_log_data(r.data);
    if (r.ok && r.data.is_array() && r.data.size() > max_records)
    {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = r.data.size() - max_records; i < r.data.size(); ++i) trimmed.push_back(r.data[i]);
        r.data = std::move(trimmed);
    }
    diag::log_tagged_fmt("camoufox", "get_console_logs result ok=%d count=%zu data_shape=%s",
        static_cast<int>(r.ok), r.data.is_array() ? r.data.size() : static_cast<size_t>(0),
        json_shape(r.data).c_str());
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
        update_page_cache_from_json_locked(r.data, "get_page_info");
        if (sg().active_page_url.empty()) sg().active_page_url = r.data["url"].get<std::string>();
        if (sg().active_page_title.empty()) sg().active_page_title = json_string_or(r.data, "title", std::string());
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

bool take_screenshot(const std::string& output_path, bool full_page, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return take_screenshot(output_path, full_page);
    if (output_path.empty())
        return false;
    nlohmann::json args;
    args["full_page"] = full_page;
    if (!page_id.empty()) args["page_id"] = page_id;
    call_result_t r = call_tool("take_screenshot", args, 45000, session_id);
    if (!r.ok || !r.data.is_object() || !r.data.contains("screenshot_base64") || !r.data["screenshot_base64"].is_string())
        return false;
    const std::string b64 = r.data["screenshot_base64"].get<std::string>();
    std::vector<uint8_t> decoded;
    decoded.reserve((b64.size() / 4) * 3);
    int val = 0;
    int bits = -8;
    auto decode_char = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    for (unsigned char c : b64)
    {
        if (c == '=') break;
        int d = decode_char(c);
        if (d < 0) continue;
        val = (val << 6) + d;
        bits += 6;
        if (bits >= 0)
        {
            decoded.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    std::wstring wpath = utf8_to_wide(output_path);
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, decoded.data(), static_cast<DWORD>(decoded.size()), &written, nullptr);
    CloseHandle(h);
    return ok && static_cast<size_t>(written) == decoded.size();
}

bool take_snapshot(std::string& out_text, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return take_snapshot(out_text);
    out_text.clear();
    nlohmann::json args;
    if (!page_id.empty()) args["page_id"] = page_id;
    call_result_t r = call_tool("take_snapshot", args, 30000, session_id);
    if (!r.ok)
        return false;
    if (r.data.is_object() && r.data.contains("snapshot"))
        out_text = r.data["snapshot"].dump(2);
    else
        out_text = r.text;
    return true;
}

bool click(const std::string& selector, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return click(selector);
    nlohmann::json args;
    args["selector"] = selector;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("click", args, 30000, session_id).ok;
}

bool type_text(const std::string& selector, const std::string& text, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return type_text(selector, text);
    nlohmann::json args;
    args["selector"] = selector;
    args["text"] = text;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("type_text", args, 30000, session_id).ok;
}

bool wait_for(const std::string& selector, int timeout_ms, const std::string& session_id, const std::string& page_id)
{
    if (is_default_session_id(session_id) && page_id.empty())
        return wait_for(selector, timeout_ms);
    nlohmann::json args;
    args["selector"] = selector;
    args["timeout"] = timeout_ms;
    if (!page_id.empty()) args["page_id"] = page_id;
    return call_tool("wait_for", args, timeout_ms > 0 ? timeout_ms + 5000 : 45000, session_id).ok;
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
