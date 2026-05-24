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

#include <atomic>
#include <chrono>
#include <cstdio>
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
void set_status_locked(install_state_t st, const std::string& msg);

bool file_exists_w(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
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
    for (const auto& base : runtime_base_dirs())
    {
        std::wstring candidate = join_path_w(join_path_w(base, L"deps"), name);
        if (file_exists_w(join_path_w(candidate, L"camoufox.exe")))
        {
            out_dir = candidate;
            return true;
        }
        candidate = join_path_w(base, name);
        if (file_exists_w(join_path_w(candidate, L"camoufox.exe")))
        {
            out_dir = candidate;
            return true;
        }
    }
    return false;
}

bool discover_bundled_python_installer(std::wstring& out_path)
{
    const std::wstring name = L"python-3.12.10-amd64.exe";
    for (const auto& base : runtime_base_dirs())
    {
        std::wstring candidate = join_path_w(join_path_w(base, L"deps"), name);
        if (file_exists_w(candidate))
        {
            out_path = candidate;
            return true;
        }
        candidate = join_path_w(base, name);
        if (file_exists_w(candidate))
        {
            out_path = candidate;
            return true;
        }
    }
    return false;
}

std::wstring local_appdata_camoufox_cache()
{
    wchar_t root[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return {};
    return join_path_w(join_path_w(join_path_w(root, L"camoufox"), L"camoufox"), L"Cache");
}

std::wstring local_appdata_python_target()
{
    wchar_t root[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return {};
    return join_path_w(join_path_w(join_path_w(root, L"Programs"), L"Python"), L"Python312");
}

std::wstring local_appdata_setup_cache()
{
    wchar_t root[MAX_PATH] = {};
    DWORD got = GetEnvironmentVariableW(L"LOCALAPPDATA", root, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) return {};
    return join_path_w(join_path_w(root, L"AiDA"), L"setup-cache");
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
    std::error_code ec;
    fs::create_directories(fs::path(parent_dir_w(destination)), ec);
    if (ec)
    {
        log += "create_directories failed for Python setup cache: " + ec.message() + "\n";
        return false;
    }

    const wchar_t* host = L"www.python.org";
    const wchar_t* path = L"/ftp/python/3.12.10/python-3.12.10-amd64.exe";
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
        return false;
    }
    WinHttpSetTimeouts(session.h, 30000, 30000, 30000, 300000);

    winhttp_handle_t connect(WinHttpConnect(session.h, host, INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!connect.h)
    {
        log += "WinHttpConnect failed err=" + std::to_string(GetLastError()) + "\n";
        return false;
    }

    winhttp_handle_t request(WinHttpOpenRequest(connect.h,
                                                L"GET",
                                                path,
                                                nullptr,
                                                WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                WINHTTP_FLAG_SECURE));
    if (!request.h)
    {
        log += "WinHttpOpenRequest failed err=" + std::to_string(GetLastError()) + "\n";
        return false;
    }

    if (!WinHttpSendRequest(request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.h, nullptr))
    {
        log += "Python installer download request failed err=" + std::to_string(GetLastError()) + "\n";
        return false;
    }

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
        return false;
    }

    std::wstring tmp = destination + L".tmp";
    HANDLE hf = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
    {
        log += "CreateFile failed for Python installer err=" + std::to_string(GetLastError()) + "\n";
        return false;
    }

    uint64_t total = 0;
    std::vector<char> chunk;
    for (;;)
    {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.h, &available))
        {
            log += "WinHttpQueryDataAvailable failed err=" + std::to_string(GetLastError()) + "\n";
            CloseHandle(hf);
            DeleteFileW(tmp.c_str());
            return false;
        }
        if (available == 0) break;
        chunk.resize(available);
        DWORD read = 0;
        if (!WinHttpReadData(request.h, chunk.data(), available, &read))
        {
            log += "WinHttpReadData failed err=" + std::to_string(GetLastError()) + "\n";
            CloseHandle(hf);
            DeleteFileW(tmp.c_str());
            return false;
        }
        if (read == 0) break;
        DWORD written = 0;
        if (!WriteFile(hf, chunk.data(), read, &written, nullptr) || written != read)
        {
            log += "WriteFile failed for Python installer err=" + std::to_string(GetLastError()) + "\n";
            CloseHandle(hf);
            DeleteFileW(tmp.c_str());
            return false;
        }
        total += read;
    }
    CloseHandle(hf);

    if (total < 10ull * 1024ull * 1024ull)
    {
        DeleteFileW(tmp.c_str());
        log += "Python installer download was unexpectedly small\n";
        return false;
    }
    if (!MoveFileExW(tmp.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        log += "MoveFileEx failed for Python installer err=" + std::to_string(GetLastError()) + "\n";
        DeleteFileW(tmp.c_str());
        return false;
    }
    log += "downloaded Python installer bytes=" + std::to_string(total) + "\n";
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

bool bootstrap_python_runtime(std::string& out_log)
{
    std::wstring target_dir = local_appdata_python_target();
    if (target_dir.empty())
    {
        out_log += "LOCALAPPDATA not available for Python bootstrap\n";
        return false;
    }
    std::wstring python_exe = join_path_w(target_dir, L"python.exe");
    if (file_exists_w(python_exe)) return true;

    std::wstring cache_dir = local_appdata_setup_cache();
    if (cache_dir.empty())
    {
        out_log += "LOCALAPPDATA not available for setup cache\n";
        return false;
    }
    std::wstring installer = join_path_w(cache_dir, L"python-3.12.10-amd64.exe");

    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::installing, "downloading Python 3.12 runtime");
    }

    if (!file_exists_w(installer))
    {
        std::wstring bundled_installer;
        if (discover_bundled_python_installer(bundled_installer))
            installer = bundled_installer;
        else if (!download_python_installer_w(installer, out_log))
            return false;
    }
    if (!verify_authenticode_w(installer, out_log))
        return false;

    {
        std::lock_guard<std::mutex> lk(sg().mtx);
        set_status_locked(install_state_t::installing, "installing Python 3.12 runtime");
    }

    std::string cmd = quote_arg(wide_to_utf8(installer)) +
        " /quiet InstallAllUsers=0 PrependPath=0 AppendPath=0 Include_launcher=0 Include_pip=1 Include_test=0 Include_doc=0 Include_tcltk=0 Shortcuts=0 SimpleInstall=1 TargetDir=" +
        quote_arg(wide_to_utf8(target_dir));
    DWORD code = 0;
    std::string install_log;
    if (!spawn_capture_streaming(cmd, 1200000, code, install_log))
    {
        out_log += install_log;
        out_log += "Python installer timed out or failed to spawn\n";
        return false;
    }
    out_log += install_log;
    if (code != 0 && code != 3010)
    {
        out_log += "Python installer exited with code=" + std::to_string(code) + "\n";
        return false;
    }
    if (!file_exists_w(python_exe))
    {
        out_log += "Python installer completed but python.exe was not found at " + wide_to_utf8(python_exe) + "\n";
        return false;
    }
    out_log += "installed Python runtime at " + wide_to_utf8(python_exe) + "\n";
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

constexpr DWORD kInteractiveProbeTimeoutMs = 30000;
constexpr DWORD kBackgroundProbeTimeoutMs = 30000;
constexpr DWORD kSetupProbeTimeoutMs = 30000;

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
        std::string detail = compact_log(captured);
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
        std::string detail = compact_log(browser_log);
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
