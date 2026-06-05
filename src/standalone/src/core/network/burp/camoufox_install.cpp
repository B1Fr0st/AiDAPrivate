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
#include <winhttp.h>
#include <softpub.h>
#include <wintrust.h>
#include <bcrypt.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <system_error>
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
    std::atomic<uint64_t> probe_sequence{0};
    uint64_t             last_ok_tick_ms = 0;
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

bool spawn_capture_streaming(const std::string& cmdline, DWORD timeout_ms, DWORD& out_exit_code, std::string& out_log);
std::string trim_view(const std::string& s);
std::string compact_log(std::string s, size_t limit = 1200);
std::string compact_log_tail(std::string s, size_t limit = 1200);
void set_status_locked(install_state_t st, const std::string& msg);
bool get_cached_ready_status(status_t& out, const char* caller);

constexpr wchar_t kPythonInstallerHost[] = L"www.python.org";
constexpr wchar_t kPythonInstallerPath[] = L"/ftp/python/3.12.10/python-3.12.10-amd64.exe";
constexpr wchar_t kPythonInstallerName[] = L"python-3.12.10-amd64.exe";
constexpr wchar_t kPythonRuntimeDirName[] = L"Python312-3.12.10-x64";
constexpr uint64_t kPythonInstallerSize = 26964224ull;
constexpr char kPythonInstallerSha256[] = "67b5635e80ea51072b87941312d00ec8927c4db9ba18938f7ad2d27b328b95fb";
constexpr DWORD kPythonInstallerDownloadDeadlineMs = 180000;
constexpr DWORD kPythonRuntimeInstallTimeoutMs = 300000;

bool env_flag_enabled(const wchar_t* name)
{
    wchar_t value[32] = {};
    DWORD got = GetEnvironmentVariableW(name, value, static_cast<DWORD>(_countof(value)));
    if (got == 0 || got >= static_cast<DWORD>(_countof(value))) return false;
    return _wcsicmp(value, L"1") == 0 ||
           _wcsicmp(value, L"true") == 0 ||
           _wcsicmp(value, L"yes") == 0 ||
           _wcsicmp(value, L"on") == 0;
}

bool setup_bootstrap_allowed()
{
    return env_flag_enabled(L"AIDA_CAMOUFOX_ALLOW_SETUP_BOOTSTRAP");
}

bool file_exists_w(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool directory_exists_w(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
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

bool discover_reverse_mcp_source_dir(std::wstring& out_dir)
{
    const std::wstring name = L"camoufox-reverse-mcp";
    for (const auto& base : runtime_base_dirs())
    {
        std::wstring candidate = join_path_w(join_path_w(base, L"deps"), name);
        if (file_exists_w(join_path_w(candidate, L"pyproject.toml")))
        {
            out_dir = candidate;
            return true;
        }
        candidate = join_path_w(base, name);
        if (file_exists_w(join_path_w(candidate, L"pyproject.toml")))
        {
            out_dir = candidate;
            return true;
        }
    }
    return false;
}

bool discover_bundled_browser_dir(std::wstring& out_dir)
{
    const std::wstring name = L"camoufox-135.0.1-beta.24-win.x86_64";
    const auto bases = runtime_base_dirs();
    for (const auto& base : bases)
    {
        std::wstring candidate = join_path_w(join_path_w(base, L"deps"), name);
        if (file_exists_w(join_path_w(candidate, L"camoufox.exe")))
        {
            out_dir = candidate;
            diag::log_tagged_fmt("camoufox_install", "bundled_browser selected path=%s base=%s",
                wide_to_utf8(candidate).c_str(), wide_to_utf8(base).c_str());
            return true;
        }
        candidate = join_path_w(base, name);
        if (file_exists_w(join_path_w(candidate, L"camoufox.exe")))
        {
            out_dir = candidate;
            diag::log_tagged_fmt("camoufox_install", "bundled_browser selected path=%s base=%s",
                wide_to_utf8(candidate).c_str(), wide_to_utf8(base).c_str());
            return true;
        }
    }
    diag::log_tagged_fmt("camoufox_install", "bundled_browser missing base_count=%zu", bases.size());
    return false;
}

bool discover_bundled_python_installer(std::wstring& out_path)
{
    const std::vector<std::wstring> rels = {
        std::wstring(L"deps\\") + kPythonInstallerName,
        std::wstring(L"deps\\camoufox-runtime\\") + kPythonInstallerName,
        std::wstring(L"deps\\camoufox-python\\") + kPythonInstallerName,
        std::wstring(L"deps\\python\\") + kPythonInstallerName,
        std::wstring(L"deps\\python-3.12\\") + kPythonInstallerName,
        std::wstring(L"deps\\python-3.12.10-x64\\") + kPythonInstallerName,
        std::wstring(L"deps\\Python312\\") + kPythonInstallerName,
        std::wstring(L"deps\\Python312-3.12.10-x64\\") + kPythonInstallerName,
        std::wstring(L"deps\\setup-cache\\python\\3.12.10-x64\\") + kPythonInstallerName,
        std::wstring(L"camoufox-runtime\\") + kPythonInstallerName,
        std::wstring(L"camoufox-python\\") + kPythonInstallerName,
        std::wstring(L"python\\") + kPythonInstallerName,
        std::wstring(L"python-3.12\\") + kPythonInstallerName,
        std::wstring(L"python-3.12.10-x64\\") + kPythonInstallerName,
        std::wstring(L"Python312\\") + kPythonInstallerName,
        std::wstring(L"Python312-3.12.10-x64\\") + kPythonInstallerName,
        std::wstring(kPythonInstallerName)
    };
    for (const auto& base : runtime_base_dirs())
    {
        for (const auto& rel : rels)
        {
            std::wstring candidate = join_path_w(base, rel);
            if (file_exists_w(candidate))
            {
                out_path = candidate;
                return true;
            }
        }
    }
    return false;
}

bool discover_bundled_python_runtime(std::wstring& out_python)
{
    const std::vector<std::wstring> rels = {
        L"deps\\camoufox-runtime\\python.exe",
        L"deps\\camoufox-runtime\\Python312\\python.exe",
        L"deps\\camoufox-runtime\\Python312-3.12.10-x64\\python.exe",
        L"deps\\camoufox-python\\python.exe",
        L"deps\\python-3.12\\python.exe",
        L"deps\\python-3.12.10-x64\\python.exe",
        L"deps\\Python312\\python.exe",
        L"deps\\Python312-3.12.10-x64\\python.exe",
        L"deps\\runtime\\python\\python.exe",
        L"deps\\runtime\\python\\Python312-3.12.10-x64\\python.exe",
        L"deps\\runtimes\\python\\Python312-3.12.10-x64\\python.exe",
        L"camoufox-runtime\\python.exe",
        L"camoufox-runtime\\Python312\\python.exe",
        L"camoufox-runtime\\Python312-3.12.10-x64\\python.exe",
        L"camoufox-python\\python.exe",
        L"python\\python.exe",
        L"python-3.12\\python.exe",
        L"python-3.12.10-x64\\python.exe",
        L"Python312\\python.exe",
        L"Python312-3.12.10-x64\\python.exe",
        L"runtime\\python\\python.exe",
        L"runtime\\python\\Python312-3.12.10-x64\\python.exe",
        L"runtimes\\python\\Python312-3.12.10-x64\\python.exe"
    };
    const auto bases = runtime_base_dirs();
    for (const auto& base : bases)
    {
        for (const auto& rel : rels)
        {
            std::wstring candidate = join_path_w(base, rel);
            if (file_exists_w(candidate))
            {
                out_python = candidate;
                diag::log_tagged_fmt("camoufox_install", "bundled_python_runtime selected path=%s base=%s rel=%s",
                    wide_to_utf8(candidate).c_str(), wide_to_utf8(base).c_str(), wide_to_utf8(rel).c_str());
                return true;
            }
        }
    }
    diag::log_tagged_fmt("camoufox_install", "bundled_python_runtime missing base_count=%zu rel_count=%zu",
        bases.size(), rels.size());
    return false;
}

bool discover_bundled_wheelhouse_dir(std::wstring& out_dir)
{
    const std::vector<std::wstring> rels = {
        L"deps\\camoufox-wheelhouse",
        L"deps\\wheelhouse",
        L"deps\\wheels",
        L"camoufox-wheelhouse",
        L"wheelhouse",
        L"wheels"
    };
    const auto bases = runtime_base_dirs();
    for (const auto& base : bases)
    {
        for (const auto& rel : rels)
        {
            std::wstring candidate = join_path_w(base, rel);
            if (directory_exists_w(candidate))
            {
                out_dir = candidate;
                diag::log_tagged_fmt("camoufox_install", "bundled_wheelhouse selected path=%s base=%s rel=%s",
                    wide_to_utf8(candidate).c_str(), wide_to_utf8(base).c_str(), wide_to_utf8(rel).c_str());
                return true;
            }
        }
    }
    diag::log_tagged_fmt("camoufox_install", "bundled_wheelhouse missing base_count=%zu rel_count=%zu",
        bases.size(), rels.size());
    return false;
}

std::wstring local_appdata_camoufox_cache()
{
    wchar_t root[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return {};
    return join_path_w(join_path_w(join_path_w(root, L"camoufox"), L"camoufox"), L"Cache");
}

std::wstring local_appdata_aida_root()
{
    wchar_t root[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return {};
    return join_path_w(root, L"AiDA");
}

std::wstring local_appdata_python_target()
{
    std::wstring root = local_appdata_aida_root();
    if (root.empty()) return {};
    return join_path_w(join_path_w(join_path_w(root, L"runtimes"), L"python"), kPythonRuntimeDirName);
}

std::wstring local_appdata_setup_cache()
{
    std::wstring root = local_appdata_aida_root();
    if (root.empty()) return {};
    return join_path_w(join_path_w(join_path_w(root, L"setup-cache"), L"python"), L"3.12.10-x64");
}

bool write_text_file_w(const std::wstring& path, const char* data, std::string& log)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        log += "CreateFile failed for " + wide_to_utf8(path) + " err=" + std::to_string(GetLastError()) + "\n";
        return false;
    }
    DWORD len = static_cast<DWORD>(std::strlen(data));
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, len, &written, nullptr);
    CloseHandle(h);
    if (!ok || written != len)
    {
        log += "WriteFile failed for " + wide_to_utf8(path) + " err=" + std::to_string(GetLastError()) + "\n";
        return false;
    }
    return true;
}

struct winhttp_handle_t
{
    HINTERNET h = nullptr;
    explicit winhttp_handle_t(HINTERNET v = nullptr) : h(v) {}
    ~winhttp_handle_t() { if (h) WinHttpCloseHandle(h); }
    winhttp_handle_t(const winhttp_handle_t&) = delete;
    winhttp_handle_t& operator=(const winhttp_handle_t&) = delete;
};

bool download_python_installer_w(const std::wstring& destination, std::string& log)
{
    namespace fs = std::filesystem;
    const ULONGLONG start_ms = GetTickCount64();
    diag::log_tagged_fmt("camoufox_install", "python_download start dest=%s expected_bytes=%llu deadline_ms=%lu",
        wide_to_utf8(destination).c_str(),
        static_cast<unsigned long long>(kPythonInstallerSize),
        static_cast<unsigned long>(kPythonInstallerDownloadDeadlineMs));
    std::error_code ec;
    fs::create_directories(fs::path(parent_dir_w(destination)), ec);
    if (ec)
    {
        log += "create_directories failed for Python setup cache: " + ec.message() + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download create_directories_failed err=%s elapsed_ms=%llu",
            ec.message().c_str(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }

    winhttp_handle_t session(WinHttpOpen(L"AiDA-CamoufoxSetup/1.0",
                                         WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                         WINHTTP_NO_PROXY_NAME,
                                         WINHTTP_NO_PROXY_BYPASS,
                                         0));
    if (!session.h)
        session.h = WinHttpOpen(L"AiDA-CamoufoxSetup/1.0",
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME,
                                WINHTTP_NO_PROXY_BYPASS,
                                0);
    if (!session.h)
    {
        log += "WinHttpOpen failed err=" + std::to_string(GetLastError()) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download WinHttpOpen_failed gle=%lu elapsed_ms=%llu",
            GetLastError(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    WinHttpSetTimeouts(session.h, 30000, 30000, 30000, 30000);

    winhttp_handle_t connect(WinHttpConnect(session.h, kPythonInstallerHost, INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!connect.h)
    {
        log += "WinHttpConnect failed err=" + std::to_string(GetLastError()) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download WinHttpConnect_failed gle=%lu elapsed_ms=%llu",
            GetLastError(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }

    winhttp_handle_t request(WinHttpOpenRequest(connect.h,
                                                L"GET",
                                                kPythonInstallerPath,
                                                nullptr,
                                                WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                WINHTTP_FLAG_SECURE));
    if (!request.h)
    {
        log += "WinHttpOpenRequest failed err=" + std::to_string(GetLastError()) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download WinHttpOpenRequest_failed gle=%lu elapsed_ms=%llu",
            GetLastError(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }

    diag::log_tagged_fmt("camoufox_install", "python_download request_send host=%ls path=%ls",
        kPythonInstallerHost, kPythonInstallerPath);
    if (!WinHttpSendRequest(request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    {
        log += "Python installer download send failed err=" + std::to_string(GetLastError()) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download request_send_failed gle=%lu elapsed_ms=%llu",
            GetLastError(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    diag::log_tagged_fmt("camoufox_install", "python_download request_sent elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    diag::log_tagged_fmt("camoufox_install", "python_download receive_response_start elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    if (!WinHttpReceiveResponse(request.h, nullptr))
    {
        log += "Python installer download receive failed err=" + std::to_string(GetLastError()) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download receive_response_failed gle=%lu elapsed_ms=%llu",
            GetLastError(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    diag::log_tagged_fmt("camoufox_install", "python_download receive_response_ok elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - start_ms));

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request.h,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status,
                             &status_size,
                             WINHTTP_NO_HEADER_INDEX) ||
        status < 200 || status >= 300)
    {
        log += "Python installer download returned HTTP status " + std::to_string(status) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download bad_status status=%lu elapsed_ms=%llu",
            status, static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    diag::log_tagged_fmt("camoufox_install", "python_download response_status=%lu elapsed_ms=%llu",
        status, static_cast<unsigned long long>(GetTickCount64() - start_ms));

    std::wstring tmp = destination + L".tmp";
    HANDLE hf = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
    {
        log += "CreateFile failed for Python installer err=" + std::to_string(GetLastError()) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download CreateFile_failed gle=%lu elapsed_ms=%llu",
            GetLastError(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }

    uint64_t total = 0;
    uint64_t next_progress = 4ull * 1024ull * 1024ull;
    ULONGLONG last_progress_ms = start_ms;
    std::vector<char> chunk;
    for (;;)
    {
        const ULONGLONG now_ms = GetTickCount64();
        if (now_ms - start_ms >= kPythonInstallerDownloadDeadlineMs)
        {
            CloseHandle(hf);
            DeleteFileW(tmp.c_str());
            log += "Python installer download deadline exceeded bytes=" + std::to_string(total) + "\n";
            diag::log_tagged_fmt("camoufox_install", "python_download deadline_exceeded bytes=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(total), static_cast<unsigned long long>(now_ms - start_ms));
            return false;
        }
        DWORD available = 0;
        if (now_ms - last_progress_ms >= 5000)
        {
            diag::log_tagged_fmt("camoufox_install", "python_download query_available_enter bytes=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(total),
                static_cast<unsigned long long>(now_ms - start_ms));
        }
        if (!WinHttpQueryDataAvailable(request.h, &available))
        {
            log += "WinHttpQueryDataAvailable failed err=" + std::to_string(GetLastError()) + "\n";
            diag::log_tagged_fmt("camoufox_install", "python_download query_available_failed gle=%lu bytes=%llu elapsed_ms=%llu",
                GetLastError(), static_cast<unsigned long long>(total), static_cast<unsigned long long>(GetTickCount64() - start_ms));
            CloseHandle(hf);
            DeleteFileW(tmp.c_str());
            return false;
        }
        if (now_ms - last_progress_ms >= 5000)
        {
            diag::log_tagged_fmt("camoufox_install", "python_download query_available_exit available=%lu bytes=%llu elapsed_ms=%llu",
                available,
                static_cast<unsigned long long>(total),
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
        }
        if (available == 0) break;
        chunk.resize(available);
        DWORD read = 0;
        if (!WinHttpReadData(request.h, chunk.data(), available, &read))
        {
            log += "WinHttpReadData failed err=" + std::to_string(GetLastError()) + "\n";
            diag::log_tagged_fmt("camoufox_install", "python_download read_failed gle=%lu bytes=%llu elapsed_ms=%llu",
                GetLastError(), static_cast<unsigned long long>(total), static_cast<unsigned long long>(GetTickCount64() - start_ms));
            CloseHandle(hf);
            DeleteFileW(tmp.c_str());
            return false;
        }
        if (read == 0) break;
        DWORD written = 0;
        if (!WriteFile(hf, chunk.data(), read, &written, nullptr) || written != read)
        {
            log += "WriteFile failed for Python installer err=" + std::to_string(GetLastError()) + "\n";
            diag::log_tagged_fmt("camoufox_install", "python_download write_failed gle=%lu bytes=%llu read=%lu written=%lu elapsed_ms=%llu",
                GetLastError(), static_cast<unsigned long long>(total), read, written,
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            CloseHandle(hf);
            DeleteFileW(tmp.c_str());
            return false;
        }
        total += read;
        const ULONGLONG progress_now_ms = GetTickCount64();
        if (total >= next_progress || progress_now_ms - last_progress_ms >= 5000)
        {
            diag::log_tagged_fmt("camoufox_install", "python_download progress bytes=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(total),
                static_cast<unsigned long long>(progress_now_ms - start_ms));
            last_progress_ms = progress_now_ms;
            while (next_progress <= total)
                next_progress += 4ull * 1024ull * 1024ull;
        }
    }
    CloseHandle(hf);

    if (total != kPythonInstallerSize)
    {
        DeleteFileW(tmp.c_str());
        log += "Python installer download size mismatch bytes=" + std::to_string(total) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download size_mismatch bytes=%llu expected=%llu elapsed_ms=%llu",
            static_cast<unsigned long long>(total),
            static_cast<unsigned long long>(kPythonInstallerSize),
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    if (!MoveFileExW(tmp.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        log += "MoveFileEx failed for Python installer err=" + std::to_string(GetLastError()) + "\n";
        diag::log_tagged_fmt("camoufox_install", "python_download move_failed gle=%lu elapsed_ms=%llu",
            GetLastError(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        DeleteFileW(tmp.c_str());
        return false;
    }
    log += "downloaded Python installer bytes=" + std::to_string(total) + "\n";
    diag::log_tagged_fmt("camoufox_install", "python_download complete bytes=%llu elapsed_ms=%llu",
        static_cast<unsigned long long>(total),
        static_cast<unsigned long long>(GetTickCount64() - start_ms));
    return true;
}

std::string hex_lower(const std::array<unsigned char, 32>& bytes)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        out[i * 2] = kHex[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[bytes[i] & 0x0F];
    }
    return out;
}

bool sha256_file_w(const std::wstring& path, std::string& out_hex, std::string& log)
{
    out_hex.clear();
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
    {
        log += "CreateFile failed for sha256 err=" + std::to_string(GetLastError()) + "\n";
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::array<unsigned char, 32> digest{};
    bool ok = false;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (BCRYPT_SUCCESS(st))
        st = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    if (BCRYPT_SUCCESS(st))
    {
        std::array<unsigned char, 65536> buf{};
        for (;;)
        {
            DWORD read = 0;
            if (!ReadFile(hf, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr))
            {
                log += "ReadFile failed for sha256 err=" + std::to_string(GetLastError()) + "\n";
                break;
            }
            if (read == 0)
            {
                st = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
                ok = BCRYPT_SUCCESS(st);
                if (!ok) log += "BCryptFinishHash failed status=" + std::to_string(static_cast<long>(st)) + "\n";
                break;
            }
            st = BCryptHashData(hash, buf.data(), read, 0);
            if (!BCRYPT_SUCCESS(st))
            {
                log += "BCryptHashData failed status=" + std::to_string(static_cast<long>(st)) + "\n";
                break;
            }
        }
    }
    else
    {
        log += "BCrypt SHA256 setup failed status=" + std::to_string(static_cast<long>(st)) + "\n";
    }
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(hf);
    if (!ok) return false;
    out_hex = hex_lower(digest);
    return true;
}

bool verify_authenticode_w(const std::wstring& path, std::string& log)
{
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path.c_str();

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.pFile = &file_info;
    data.dwProvFlags = WTD_SAFER_FLAG;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    if (status == ERROR_SUCCESS) return true;
    log += "Authenticode verification failed for " + wide_to_utf8(path) + " status=" + std::to_string(status) + "\n";
    return false;
}

bool verify_python_installer_w(const std::wstring& path, std::string& log)
{
    WIN32_FILE_ATTRIBUTE_DATA attrs{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attrs))
    {
        log += "GetFileAttributesEx failed for Python installer err=" + std::to_string(GetLastError()) + "\n";
        return false;
    }
    uint64_t size = (static_cast<uint64_t>(attrs.nFileSizeHigh) << 32) | attrs.nFileSizeLow;
    if (size != kPythonInstallerSize)
    {
        log += "Python installer size mismatch bytes=" + std::to_string(size) + "\n";
        return false;
    }

    std::string sha;
    if (!sha256_file_w(path, sha, log)) return false;
    if (_stricmp(sha.c_str(), kPythonInstallerSha256) != 0)
    {
        log += "Python installer sha256 mismatch got=" + sha + "\n";
        return false;
    }
    if (!verify_authenticode_w(path, log)) return false;
    log += "verified Python installer sha256=" + sha + "\n";
    return true;
}

bool copy_directory_tree_w(const std::wstring& src, const std::wstring& dst, std::string& log)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::create_directories(fs::path(dst), ec);
    if (ec)
    {
        log += "create_directories failed for " + wide_to_utf8(dst) + ": " + ec.message() + "\n";
        return false;
    }
    fs::path src_path(src);
    fs::path dst_path(dst);
    for (fs::recursive_directory_iterator it(src_path, ec), end; it != end && !ec; it.increment(ec))
    {
        fs::path rel = fs::relative(it->path(), src_path, ec);
        if (ec) break;
        fs::path target = dst_path / rel;
        if (it->is_directory(ec))
        {
            fs::create_directories(target, ec);
        }
        else if (it->is_regular_file(ec))
        {
            fs::create_directories(target.parent_path(), ec);
            if (!ec)
                fs::copy_file(it->path(), target, fs::copy_options::overwrite_existing, ec);
        }
    }
    if (ec)
    {
        log += "copy_directory failed from " + wide_to_utf8(src) + " to " + wide_to_utf8(dst) + ": " + ec.message() + "\n";
        return false;
    }
    return true;
}

bool remove_directory_tree_w(const std::wstring& dir, std::string& log)
{
    namespace fs = std::filesystem;
    std::wstring root = local_appdata_aida_root();
    bool under_root = !root.empty() && dir.size() > root.size() && _wcsnicmp(dir.c_str(), root.c_str(), root.size()) == 0;
    if (under_root)
    {
        wchar_t sep = dir[root.size()];
        under_root = sep == L'\\' || sep == L'/';
    }
    if (!under_root)
    {
        log += "refusing to repair Python runtime outside AiDA local app data\n";
        return false;
    }
    std::error_code ec;
    fs::remove_all(fs::path(dir), ec);
    if (ec)
    {
        log += "remove_all failed for Python runtime: " + ec.message() + "\n";
        return false;
    }
    return true;
}

bool validate_app_local_python_w(const std::wstring& python_exe, std::string& log)
{
    if (!file_exists_w(python_exe)) return false;
    DWORD code = 0;
    std::string captured;
    std::string cmd = quote_arg(wide_to_utf8(python_exe)) +
        " -c \"import sys, pip; assert sys.version_info.major == 3 and 10 <= sys.version_info.minor <= 13; print(f'{sys.version_info.major}.{sys.version_info.minor}')\"";
    if (!spawn_capture_streaming(cmd, 30000, code, captured))
    {
        log += "app-local Python validation spawn failed\n";
        return false;
    }
    if (code != 0)
    {
        log += "app-local Python validation failed: " + compact_log(captured) + "\n";
        return false;
    }
    log += "validated app-local Python runtime version=" + compact_log(captured) + "\n";
    return true;
}

bool bootstrap_python_runtime(std::string& out_log)
{
    const ULONGLONG start_ms = GetTickCount64();
    diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime entry");
    std::wstring target_dir = local_appdata_python_target();
    if (target_dir.empty())
    {
        out_log += "LOCALAPPDATA not available for Python bootstrap\n";
        diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime no_localappdata elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }
    std::wstring python_exe = join_path_w(target_dir, L"python.exe");
    if (file_exists_w(python_exe))
    {
        std::string validation_log;
        if (validate_app_local_python_w(python_exe, validation_log))
        {
            out_log += validation_log;
            diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime existing_valid elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            return true;
        }
        out_log += validation_log;
        {
            std::lock_guard<std::mutex> lk(sg().mtx);
            set_status_locked(install_state_t::installing, "repairing app-local Python runtime");
        }
        if (!remove_directory_tree_w(target_dir, out_log)) return false;
    }
    else
    {
        DWORD attr = GetFileAttributesW(target_dir.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            std::lock_guard<std::mutex> lk(sg().mtx);
            set_status_locked(install_state_t::installing, "removing partial Python runtime");
            if (!remove_directory_tree_w(target_dir, out_log)) return false;
        }
    }

    std::wstring bundled_python;
    if (discover_bundled_python_runtime(bundled_python))
    {
        std::string validation_log;
        if (validate_app_local_python_w(bundled_python, validation_log))
        {
            out_log += validation_log;
            out_log += "using bundled Python runtime " + wide_to_utf8(bundled_python) + "\n";
            diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime bundled_runtime_valid elapsed_ms=%llu python=%s",
                static_cast<unsigned long long>(GetTickCount64() - start_ms),
                wide_to_utf8(bundled_python).c_str());
            return true;
        }
        out_log += validation_log;
        out_log += "bundled Python runtime validation failed at " + wide_to_utf8(bundled_python) + "\n";
        diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime bundled_runtime_invalid elapsed_ms=%llu python=%s",
            static_cast<unsigned long long>(GetTickCount64() - start_ms),
            wide_to_utf8(bundled_python).c_str());
        return false;
    }

    if (!setup_bootstrap_allowed())
    {
        out_log += "bundled Python runtime not found; installer/download bootstrap disabled\n";
        diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime setup_bootstrap_disabled elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms));
        return false;
    }

    std::wstring cache_dir = local_appdata_setup_cache();
    if (cache_dir.empty())
    {
        out_log += "LOCALAPPDATA not available for setup cache\n";
        return false;
    }
    std::wstring installer = join_path_w(cache_dir, kPythonInstallerName);

    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::installing, "locating Python 3.12 runtime installer");
    }

    bool using_bundled_installer = false;
    if (!file_exists_w(installer))
    {
        std::wstring bundled_installer;
        if (discover_bundled_python_installer(bundled_installer))
        {
            installer = bundled_installer;
            using_bundled_installer = true;
            out_log += "using bundled Python installer " + wide_to_utf8(installer) + "\n";
            std::lock_guard<std::mutex> lk(sg().mtx);
            set_status_locked(install_state_t::installing, "using bundled Python 3.12 runtime installer");
        }
        else if (!setup_bootstrap_allowed())
        {
            out_log += "bundled Python runtime/installer not found; online setup bootstrap disabled\n";
            diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime online_download_disabled elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            return false;
        }
        else if (!download_python_installer_w(installer, out_log))
        {
            diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime download_failed elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            return false;
        }
    }
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::installing, "verifying Python 3.12 runtime installer");
    }
    if (!verify_python_installer_w(installer, out_log))
    {
        if (using_bundled_installer) return false;
        DeleteFileW(installer.c_str());
        out_log += "discarded invalid cached Python installer\n";
        if (!setup_bootstrap_allowed()) {
            out_log += "cached Python installer invalid; online setup bootstrap disabled\n";
            diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime redownload_disabled elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            return false;
        }
        if (!download_python_installer_w(installer, out_log)) {
            diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime redownload_failed elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            return false;
        }
        if (!verify_python_installer_w(installer, out_log)) {
            diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime verify_after_redownload_failed elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            return false;
        }
    }

    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::installing, "installing Python 3.12 runtime");
    }

    std::string cmd = quote_arg(wide_to_utf8(installer)) +
        " /quiet InstallAllUsers=0 PrependPath=0 AppendPath=0 Include_launcher=0 Include_pip=1 Include_test=0 Include_doc=0 Include_tcltk=0 Shortcuts=0 SimpleInstall=1 TargetDir=" +
        quote_arg(wide_to_utf8(target_dir));
    DWORD code = 0;
    std::string install_log;
    diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime installer_start timeout_ms=%lu",
        static_cast<unsigned long>(kPythonRuntimeInstallTimeoutMs));
    if (!spawn_capture_streaming(cmd, kPythonRuntimeInstallTimeoutMs, code, install_log))
    {
        out_log += install_log;
        out_log += "Python installer timed out or failed to spawn\n";
        diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime installer_failed elapsed_ms=%llu log_len=%zu",
            static_cast<unsigned long long>(GetTickCount64() - start_ms), install_log.size());
        return false;
    }
    out_log += install_log;
    if (code != 0 && code != 3010)
    {
        out_log += "Python installer exited with code=" + std::to_string(code) + "\n";
        diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime installer_bad_exit code=%lu elapsed_ms=%llu log_len=%zu",
            code, static_cast<unsigned long long>(GetTickCount64() - start_ms), install_log.size());
        return false;
    }
    if (!file_exists_w(python_exe))
    {
        out_log += "Python installer completed but python.exe was not found at " + wide_to_utf8(python_exe) + "\n";
        return false;
    }
    if (!validate_app_local_python_w(python_exe, out_log)) return false;
    const std::string metadata = std::string("{\"component\":\"camoufox-python\",\"version\":\"3.12.10\",\"arch\":\"x64\",\"source\":\"https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe\",\"sha256\":\"") +
        kPythonInstallerSha256 + "\"}";
    if (!write_text_file_w(join_path_w(target_dir, L"aida-runtime.json"), metadata.c_str(), out_log)) return false;
    out_log += "installed Python runtime at " + wide_to_utf8(python_exe) + "\n";
    diag::log_tagged_fmt("camoufox_install", "bootstrap_python_runtime complete elapsed_ms=%llu python=%s",
        static_cast<unsigned long long>(GetTickCount64() - start_ms),
        wide_to_utf8(python_exe).c_str());
    return true;
}

bool ensure_python_for_setup(std::string& python, std::string& out_log)
{
    if (camoufox::ensure_python_available(python)) return true;
    if (bootstrap_python_runtime(out_log) && camoufox::ensure_python_available(python)) return true;
    std::lock_guard<std::mutex> lk(sg().mtx);
    sg().last_error = out_log.empty() ? "python interpreter not found" : compact_log(out_log);
    set_status_locked(install_state_t::missing_python, sg().last_error);
    return false;
}

bool query_camoufox_install_dir(const std::string& python, std::wstring& out_dir, std::string& out_log)
{
    DWORD code = 0;
    std::string captured;
    std::string cmd = quote_arg(python) + " -c \"from camoufox.pkgman import INSTALL_DIR; print(INSTALL_DIR)\"";
    if (spawn_capture_streaming(cmd, 30000, code, captured) && code == 0)
    {
        std::string path = trim_view(captured);
        if (!path.empty())
        {
            out_dir = utf8_to_wide(path);
            return !out_dir.empty();
        }
    }
    out_log += captured;
    out_dir = local_appdata_camoufox_cache();
    return !out_dir.empty();
}

bool install_browser_from_bundle(const std::string& python, std::string& out_log)
{
    std::wstring source;
    if (!discover_bundled_browser_dir(source)) return false;

    std::wstring install_dir;
    if (!query_camoufox_install_dir(python, install_dir, out_log))
    {
        out_log += "could not resolve Camoufox install cache directory\n";
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::installing, "installing bundled camoufox browser payload");
    }

    if (!copy_directory_tree_w(source, install_dir, out_log)) return false;
    const char* version_json = "{\"version\":\"135.0.1\",\"release\":\"beta.24\"}";
    if (!write_text_file_w(join_path_w(install_dir, L"version.json"), version_json, out_log)) return false;

    out_log += "installed bundled Camoufox browser from " + wide_to_utf8(source) + "\n";
    return true;
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
    const ULONGLONG start_ms = GetTickCount64();
    diag::log_tagged_fmt("camoufox_install", "spawn_capture_streaming start cmd_len=%zu timeout_ms=%lu",
        cmdline.size(), static_cast<unsigned long>(timeout_ms));

    SECURITY_ATTRIBUTES sa{};
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0))
    {
        const DWORD gle = GetLastError();
        out_log += "spawn pipe create failed gle=" + std::to_string(gle) + "\n";
        diag::log_tagged_fmt("camoufox_install", "spawn_capture_streaming pipe_create_failed gle=%lu cmd_len=%zu elapsed_ms=%llu",
            gle, cmdline.size(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
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
        const DWORD gle = GetLastError();
        out_log += "spawn create failed gle=" + std::to_string(gle) + "\n";
        diag::log_tagged_fmt("camoufox_install", "spawn_capture_streaming create_failed gle=%lu cmd_len=%zu elapsed_ms=%llu",
            gle, cmdline.size(), static_cast<unsigned long long>(GetTickCount64() - start_ms));
        CloseHandle(rd);
        return false;
    }
    diag::log_tagged_fmt("camoufox_install", "spawn_capture_streaming process_started pid=%lu cmd_len=%zu",
        static_cast<unsigned long>(pi.dwProcessId), cmdline.size());
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
            std::string tail = compact_log_tail(out_log, 600);
            out_log += "spawn timeout elapsed_ms=" + std::to_string(elapsed) + " output_tail=" + tail + "\n";
            diag::log_tagged_fmt("camoufox_install", "spawn_capture_streaming timeout pid=%lu elapsed_ms=%lu cmd_len=%zu captured_len=%zu tail=%.600s",
                static_cast<unsigned long>(pi.dwProcessId),
                static_cast<unsigned long>(elapsed),
                cmdline.size(),
                out_log.size(),
                tail.c_str());
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
    std::string tail = compact_log_tail(out_log, 600);
    diag::log_tagged_fmt("camoufox_install", "spawn_capture_streaming exit pid=%lu code=%lu elapsed_ms=%llu captured_len=%zu tail=%.600s",
        static_cast<unsigned long>(pi.dwProcessId),
        static_cast<unsigned long>(out_exit_code),
        static_cast<unsigned long long>(GetTickCount64() - start_ms),
        out_log.size(),
        tail.c_str());
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

std::string compact_log(std::string s, size_t limit)
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

std::string compact_log_tail(std::string s, size_t limit)
{
    s = trim_view(s);
    for (char& c : s) {
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    if (s.size() > limit) {
        s = s.substr(s.size() - limit);
        s.insert(0, "...");
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
    std::wstring wheelhouse_dir;
    if (discover_bundled_wheelhouse_dir(wheelhouse_dir))
    {
        std::string wheel_log;
        std::string cmd = quote_arg(python) + " -m pip install --no-index --find-links " +
            quote_arg(wide_to_utf8(wheelhouse_dir)) + " " + pip_args;
        diag::log_tagged_fmt("camoufox_install", "wheelhouse install start path=%s args_len=%zu",
            wide_to_utf8(wheelhouse_dir).c_str(), pip_args.size());
        if (spawn_capture_streaming(cmd, 600000, code, wheel_log) && code == 0)
        {
            out_log += wheel_log;
            diag::log_tagged_fmt("camoufox_install", "wheelhouse install ok path=%s", wide_to_utf8(wheelhouse_dir).c_str());
            return true;
        }
        out_log += wheel_log;
        std::string detail = compact_log(wheel_log);
        diag::log_tagged_fmt("camoufox_install", "wheelhouse install failed code=%lu path=%s out=%.400s",
            code, wide_to_utf8(wheelhouse_dir).c_str(), detail.c_str());
        code = 0;
    }

    if (!setup_bootstrap_allowed())
    {
        const std::string detail = out_log.empty()
            ? std::string("bundled camoufox wheelhouse not found; online dependency install disabled")
            : std::string("bundled camoufox wheelhouse failed; online dependency install disabled: ") + compact_log(out_log);
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = detail;
        set_status_locked(install_state_t::install_failed, sg().last_error);
        return false;
    }

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

bool get_cached_ready_status(status_t& out, const char* caller)
{
    status_t st;
    uint64_t ok_tick = 0;
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        st = sg().status;
        ok_tick = sg().last_ok_tick_ms;
    }
    if (st.state != install_state_t::ok) return false;

    const bool has_module = !st.module_version.empty();
    const bool python_exists = !st.python_path.empty() && file_exists_w(utf8_to_wide(st.python_path));
    const bool browser_exists = !st.browser_path.empty() && file_exists_w(utf8_to_wide(st.browser_path));
    const uint64_t age_ms = ok_tick == 0 ? 0 : static_cast<uint64_t>(GetTickCount64() - ok_tick);
    if (has_module && python_exists && browser_exists)
    {
        diag::log_tagged_fmt("camoufox_install", "probe_cached_ready caller=%s age_ms=%llu python=%s module=%s browser=%s",
            caller ? caller : "unknown",
            static_cast<unsigned long long>(age_ms),
            st.python_path.c_str(),
            st.module_version.c_str(),
            st.browser_path.c_str());
        out = st;
        return true;
    }

    diag::log_tagged_fmt("camoufox_install", "probe_cached_ready_stale caller=%s age_ms=%llu has_module=%d python_exists=%d browser_exists=%d python=%s browser=%s",
        caller ? caller : "unknown",
        static_cast<unsigned long long>(age_ms),
        static_cast<int>(has_module),
        static_cast<int>(python_exists),
        static_cast<int>(browser_exists),
        st.python_path.empty() ? "<empty>" : st.python_path.c_str(),
        st.browser_path.empty() ? "<empty>" : st.browser_path.c_str());
    return false;
}

void set_status_locked(install_state_t st, const std::string& msg)
{
    sg().status.state        = st;
    sg().status.last_message = msg;
    if (st == install_state_t::ok)
        sg().last_ok_tick_ms = GetTickCount64();
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

constexpr DWORD kInteractiveProbeTimeoutMs = 5000;
constexpr DWORD kBackgroundProbeTimeoutMs = 5000;
constexpr DWORD kSetupProbeTimeoutMs = 5000;

status_t probe_impl(bool allow_when_busy, DWORD timeout_ms);

}

bool initialize()
{
    bool expected = false;
    if (!sg().initialized.compare_exchange_strong(expected, true)) return true;
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.state = install_state_t::unknown;
        sg().status.last_message = "camoufox bundled runtime will be probed on first browser use";
        sg().last_error.clear();
    }
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
    const uint64_t probe_id = sg().probe_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    const ULONGLONG probe_start_ms = GetTickCount64();
    status_t cached;
    if (get_cached_ready_status(cached, allow_when_busy ? "setup" : "probe"))
    {
        diag::log_tagged_fmt("camoufox_install", "probe_begin id=%llu cached=1 allow_busy=%d timeout_ms=%lu state=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(probe_id),
            static_cast<int>(allow_when_busy),
            static_cast<unsigned long>(timeout_ms),
            state_label(cached.state),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));
        return cached;
    }

    if (!allow_when_busy && sg().busy.load(std::memory_order_acquire))
    {
        diag::log_tagged_fmt("camoufox_install", "probe_busy id=%llu allow_busy=0 timeout_ms=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(probe_id),
            static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));
        return snapshot_status("camoufox install task already running");
    }

    bool expected = false;
    if (!sg().probing.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        diag::log_tagged_fmt("camoufox_install", "probe_already_running id=%llu allow_busy=%d timeout_ms=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(probe_id),
            static_cast<int>(allow_when_busy),
            static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));
        return snapshot_status("camoufox probe already running");
    }
    probe_guard_t probe_guard;

    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        diag::log_tagged_fmt("camoufox_install", "probe_begin id=%llu cached=0 allow_busy=%d timeout_ms=%lu previous_state=%s previous_msg=%s",
            static_cast<unsigned long long>(probe_id),
            static_cast<int>(allow_when_busy),
            static_cast<unsigned long>(timeout_ms),
            state_label(sg().status.state),
            sg().status.last_message.empty() ? "<empty>" : sg().status.last_message.c_str());
        set_status_locked(install_state_t::checking, "probing python environment");
    }

    std::string python;
    if (!camoufox::ensure_python_available(python))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_python, "python interpreter not found");
        sg().status.python_path.clear();
        sg().last_error = "python interpreter not found";
        diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu python failed elapsed_ms=%llu",
            static_cast<unsigned long long>(probe_id),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));
        return sg().status;
    }
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.python_path = python;
    }
    diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu python ok path=%s elapsed_ms=%llu",
        static_cast<unsigned long long>(probe_id),
        python.c_str(),
        static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));

    std::string captured;
    DWORD exit_code = 0;
    std::string cmd = std::string("\"") + python + "\" -c \"import camoufox_reverse_mcp; "
                       "print(getattr(camoufox_reverse_mcp, '__version__', 'unknown'))\"";
    const ULONGLONG module_start_ms = GetTickCount64();
    if (!spawn_capture_streaming(cmd, timeout_ms, exit_code, captured))
    {
        std::string detail = compact_log_tail(captured);
        std::string msg = detail.empty() ? std::string("module probe spawn failed") : std::string("module probe spawn failed: ") + detail;
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_module, msg);
        sg().last_error = msg;
        diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu module spawn_failed elapsed_ms=%llu total_ms=%llu detail=%.600s",
            static_cast<unsigned long long>(probe_id),
            static_cast<unsigned long long>(GetTickCount64() - module_start_ms),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms),
            detail.c_str());
        return sg().status;
    }
    diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu module exit=%lu captured_len=%zu elapsed_ms=%llu total_ms=%llu",
        static_cast<unsigned long long>(probe_id),
        static_cast<unsigned long>(exit_code),
        captured.size(),
        static_cast<unsigned long long>(GetTickCount64() - module_start_ms),
        static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));
    if (exit_code != 0)
    {
        std::string detail = compact_log_tail(captured);
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = detail.empty()
            ? std::string("camoufox_reverse_mcp not importable")
            : std::string("camoufox_reverse_mcp not importable: ") + detail;
        set_status_locked(install_state_t::missing_module, sg().last_error);
        sg().status.module_version.clear();
        return sg().status;
    }
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.module_version = trim_view(captured);
    }

    std::wstring bundled_browser_dir;
    if (discover_bundled_browser_dir(bundled_browser_dir))
    {
        const std::string browser_path = wide_to_utf8(join_path_w(bundled_browser_dir, L"camoufox.exe"));
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.browser_path = browser_path;
        set_status_locked(install_state_t::ok, "python + camoufox_reverse_mcp + bundled camoufox browser ready");
        sg().last_error.clear();
        diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu bundled_browser fast_ok path=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(probe_id),
            browser_path.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));
        return sg().status;
    }
    diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu bundled_browser fast_missing fallback=runtime_probe elapsed_ms=%llu",
        static_cast<unsigned long long>(probe_id),
        static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));

    std::string runtime_log;
    DWORD runtime_exit = 0;
    std::string runtime_cmd = std::string("\"") + python + "\" -c \"import importlib.util, sys; ok=importlib.util.find_spec('camoufox.async_api') and importlib.util.find_spec('playwright.async_api'); print('ok' if ok else 'missing'); sys.exit(0 if ok else 2)\"";
    const ULONGLONG runtime_start_ms = GetTickCount64();
    if (!spawn_capture_streaming(runtime_cmd, timeout_ms, runtime_exit, runtime_log))
    {
        std::string detail = compact_log_tail(runtime_log);
        std::string msg = detail.empty() ? std::string("camoufox runtime import probe spawn failed") : std::string("camoufox runtime import probe spawn failed: ") + detail;
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_module, msg);
        sg().last_error = msg;
        diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu runtime spawn_failed elapsed_ms=%llu total_ms=%llu detail=%.600s",
            static_cast<unsigned long long>(probe_id),
            static_cast<unsigned long long>(GetTickCount64() - runtime_start_ms),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms),
            detail.c_str());
        return sg().status;
    }
    diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu runtime exit=%lu captured_len=%zu elapsed_ms=%llu total_ms=%llu tail=%.400s",
        static_cast<unsigned long long>(probe_id),
        static_cast<unsigned long>(runtime_exit),
        runtime_log.size(),
        static_cast<unsigned long long>(GetTickCount64() - runtime_start_ms),
        static_cast<unsigned long long>(GetTickCount64() - probe_start_ms),
        compact_log_tail(runtime_log, 400).c_str());
    if (runtime_exit != 0)
    {
        std::string detail = compact_log_tail(runtime_log);
        if (detail.empty()) detail = "exit=" + std::to_string(runtime_exit);
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = std::string("camoufox runtime import failed: ") + detail;
        sg().status.browser_path.clear();
        set_status_locked(install_state_t::missing_module, sg().last_error);
        return sg().status;
    }

    if (discover_bundled_browser_dir(bundled_browser_dir))
    {
        const std::string browser_path = wide_to_utf8(join_path_w(bundled_browser_dir, L"camoufox.exe"));
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.browser_path = browser_path;
        set_status_locked(install_state_t::ok, "python + camoufox_reverse_mcp + bundled camoufox browser ready");
        sg().last_error.clear();
        diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu bundled_browser ok path=%s elapsed_ms=%llu",
            static_cast<unsigned long long>(probe_id),
            browser_path.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));
        return sg().status;
    }
    diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu bundled_browser missing fallback=installed_verstr elapsed_ms=%llu",
        static_cast<unsigned long long>(probe_id),
        static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));

    std::string browser_log;
    DWORD browser_exit = 0;
    std::string browser_cmd = std::string("\"") + python + "\" -c \"from camoufox.pkgman import installed_verstr; "
                              "print(installed_verstr())\"";
    const ULONGLONG browser_start_ms = GetTickCount64();
    if (!spawn_capture_streaming(browser_cmd, timeout_ms, browser_exit, browser_log))
    {
        std::string detail = compact_log_tail(browser_log);
        std::string msg = detail.empty() ? std::string("browser probe spawn failed") : std::string("browser probe spawn failed: ") + detail;
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::missing_browser, msg);
        sg().last_error = msg;
        diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu installed_verstr spawn_failed elapsed_ms=%llu total_ms=%llu detail=%.600s",
            static_cast<unsigned long long>(probe_id),
            static_cast<unsigned long long>(GetTickCount64() - browser_start_ms),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms),
            detail.c_str());
        return sg().status;
    }
    diag::log_tagged_fmt("camoufox_install", "probe_step id=%llu installed_verstr exit=%lu captured_len=%zu elapsed_ms=%llu total_ms=%llu tail=%.400s",
        static_cast<unsigned long long>(probe_id),
        static_cast<unsigned long>(browser_exit),
        browser_log.size(),
        static_cast<unsigned long long>(GetTickCount64() - browser_start_ms),
        static_cast<unsigned long long>(GetTickCount64() - probe_start_ms),
        compact_log_tail(browser_log, 400).c_str());
    if (browser_exit != 0)
    {
        if (discover_bundled_browser_dir(bundled_browser_dir))
        {
            std::lock_guard<std::mutex> lk(sg().mtx);
            sg().status.browser_path = wide_to_utf8(join_path_w(bundled_browser_dir, L"camoufox.exe"));
            set_status_locked(install_state_t::ok, "python + camoufox_reverse_mcp + bundled camoufox browser ready");
            sg().last_error.clear();
            return sg().status;
        }
        std::string detail = compact_log_tail(browser_log);
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = detail.empty()
            ? std::string("camoufox browser not installed")
            : std::string("camoufox browser not installed: ") + detail;
        set_status_locked(install_state_t::missing_browser, sg().last_error);
        sg().status.browser_path.clear();
        return sg().status;
    }
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().status.browser_path = trim_view(browser_log);

        set_status_locked(install_state_t::ok, "python + camoufox_reverse_mcp + camoufox browser ready");
        sg().last_error.clear();
        diag::log_tagged_fmt("camoufox_install", "probe_done id=%llu state=ok elapsed_ms=%llu",
            static_cast<unsigned long long>(probe_id),
            static_cast<unsigned long long>(GetTickCount64() - probe_start_ms));
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

    status_t st = probe_impl(true, kSetupProbeTimeoutMs);
    if (st.state == install_state_t::missing_python)
    {
        std::string python;
        if (!ensure_python_for_setup(python, out_log)) return false;
        st = probe_impl(true, kSetupProbeTimeoutMs);
    }

    if (st.state == install_state_t::missing_module)
    {
        bool ok = false;
        if (st.last_message.find("camoufox runtime import") != std::string::npos)
            ok = repair_runtime_dependencies(out_log);
        else
            ok = pip_install_module(out_log);
        if (!ok) return false;
        st = probe_impl(true, kSetupProbeTimeoutMs);
        if (st.state == install_state_t::missing_module &&
            st.last_message.find("camoufox runtime import") != std::string::npos)
        {
            if (!repair_runtime_dependencies(out_log)) return false;
            st = probe_impl(true, kSetupProbeTimeoutMs);
        }
    }

    if (st.state == install_state_t::missing_browser ||
        st.state == install_state_t::available)
    {
        if (!fetch_browser(out_log)) return false;
        st = probe_impl(true, kSetupProbeTimeoutMs);
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
    if (!ensure_python_for_setup(python, out_log)) return false;

    std::wstring module_dir;
    if (!discover_reverse_mcp_source_dir(module_dir))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "camoufox-reverse-mcp package source not found beside AiDAStandalone";
        set_status_locked(install_state_t::install_failed, sg().last_error);
        return false;
    }

    const std::string module_arg = quote_arg(wide_to_utf8(module_dir));
    if (!run_install_command(python,
        "installing camoufox-reverse-mcp",
        "-e " + module_arg,
        "--upgrade-strategy only-if-needed -e " + module_arg,
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
    if (!ensure_python_for_setup(python, out_log)) return false;

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
    if (!ensure_python_for_setup(python, out_log)) return false;

    if (install_browser_from_bundle(python, out_log))
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::available, "bundled camoufox browser installed");
        sg().last_error.clear();
        return true;
    }

    if (!setup_bootstrap_allowed())
    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = "bundled Camoufox browser payload not found; online camoufox fetch disabled";
        set_status_locked(install_state_t::install_failed, sg().last_error);
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
        std::string detail = compact_log(out_log);
        std::lock_guard<std::mutex> lk(sg().mtx);
        sg().last_error = detail.empty()
            ? std::string("camoufox fetch exited with non-zero status")
            : std::string("camoufox fetch exited with non-zero status: ") + detail;
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
