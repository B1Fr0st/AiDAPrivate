#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../../helpers/diag_log.hpp"

namespace aida::diagnostics::wer {

struct wer_registry_scope_t {
    bool present = false;
    bool read_ok = false;
    DWORD gle = 0;
    DWORD type = 0;
    DWORD bytes = 0;
    DWORD value = 0;
    std::string dump_folder;
    std::string dump_type_str;
    DWORD dump_count_value = 0;
    bool dump_count_present = false;
    bool dump_count_read_ok = false;
    DWORD dump_count_gle = 0;
};

struct wer_config_t {
    wer_registry_scope_t hkcu_per_exe;
    wer_registry_scope_t hkcu_default;
    wer_registry_scope_t hklm_per_exe;
    wer_registry_scope_t hklm_default;
    std::string expected_dump_folder;
    bool any_configured = false;
};

struct wer_event_record_t {
    std::uint64_t timestamp_100ns = 0;
    std::uint64_t tick_ms = 0;
    DWORD pid = 0;
    std::string provider_name;
    std::string source_name;
    std::uint16_t event_id = 0;
    std::uint32_t exception_code = 0;
    std::string faulting_module;
    std::string report_id;
    std::string dump_path;
    bool dump_file_found = false;
    std::uint64_t dump_file_size = 0;
    std::uint64_t dump_file_mtime_100ns = 0;
};

struct wer_correlation_t {
    wer_config_t config;
    std::vector<wer_event_record_t> recent_events;
    std::vector<std::string> recent_dump_paths;
    std::string normalized_dump_folder;
    bool event_log_query_ok = false;
    DWORD event_log_last_error = 0;
    std::size_t event_log_record_count = 0;
};

inline std::string read_registry_string(HKEY root, const wchar_t* subkey, const wchar_t* value_name, DWORD& gle) {
    gle = 0;
    HKEY key = nullptr;
    std::string result;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        gle = GetLastError();
        return result;
    }
    DWORD type = 0;
    DWORD size = 0;
    LONG rc = RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS) {
        gle = static_cast<DWORD>(rc);
        RegCloseKey(key);
        return result;
    }
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 2, 0);
        rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &size);
        if (rc == ERROR_SUCCESS) {
            int utf8_len = WideCharToMultiByte(CP_UTF8, 0, buf.data(), -1, nullptr, 0, nullptr, nullptr);
            if (utf8_len > 0) {
                result.resize(utf8_len - 1);
                WideCharToMultiByte(CP_UTF8, 0, buf.data(), -1, &result[0], utf8_len, nullptr, nullptr);
            }
            if (type == REG_EXPAND_SZ && !result.empty()) {
                char expanded[MAX_PATH] = {};
                DWORD expanded_len = ExpandEnvironmentStringsA(result.c_str(), expanded, static_cast<DWORD>(sizeof(expanded)));
                if (expanded_len > 0 && expanded_len <= sizeof(expanded)) {
                    result = expanded;
                }
            }
        } else {
            gle = static_cast<DWORD>(rc);
        }
    }
    RegCloseKey(key);
    return result;
}

inline DWORD read_registry_dword(HKEY root, const wchar_t* subkey, const wchar_t* value_name, bool& present, bool& read_ok, DWORD& value) {
    present = false;
    read_ok = false;
    value = 0;
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return GetLastError();
    }
    DWORD type = 0;
    DWORD size = sizeof(DWORD);
    LONG rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &size);
    RegCloseKey(key);
    present = (rc != ERROR_FILE_NOT_FOUND);
    if (rc == ERROR_SUCCESS && type == REG_DWORD) {
        read_ok = true;
        return 0;
    }
    return static_cast<DWORD>(rc);
}

inline wer_registry_scope_t scan_registry_scope(HKEY root, const char* root_name, const wchar_t* subkey, const char* scope_label) {
    wer_registry_scope_t scope;
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        scope.gle = GetLastError();
        return scope;
    }
    scope.present = true;
    RegCloseKey(key);

    DWORD gle = 0;
    scope.dump_folder = read_registry_string(root, subkey, L"DumpFolder", gle);
    scope.gle = gle;

    bool present = false, read_ok = false;
    DWORD value = 0;
    DWORD dw_gle = read_registry_dword(root, subkey, L"DumpType", present, read_ok, value);
    scope.dump_type_str = present ? (read_ok ? (value == 0 ? "mini" : value == 1 ? "full" : value == 2 ? "custom" : std::to_string(value)) : "read_failed") : "not_set";

    scope.dump_count_gle = read_registry_dword(root, subkey, L"DumpCount", scope.dump_count_present, scope.dump_count_read_ok, scope.dump_count_value);

    return scope;
}

inline wer_config_t scan_wer_config() {
    wer_config_t cfg;
    constexpr const wchar_t* default_subkey = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";
    constexpr const wchar_t* exe_subkey = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\AiDAStandalone.exe";

    cfg.hkcu_per_exe = scan_registry_scope(HKEY_CURRENT_USER, "HKCU", exe_subkey, "per_exe");
    cfg.hkcu_default = scan_registry_scope(HKEY_CURRENT_USER, "HKCU", default_subkey, "default");
    cfg.hklm_per_exe = scan_registry_scope(HKEY_LOCAL_MACHINE, "HKLM", exe_subkey, "per_exe");
    cfg.hklm_default = scan_registry_scope(HKEY_LOCAL_MACHINE, "HKLM", default_subkey, "default");

    if (!cfg.hkcu_per_exe.dump_folder.empty())
        cfg.expected_dump_folder = cfg.hkcu_per_exe.dump_folder;
    else if (!cfg.hklm_per_exe.dump_folder.empty())
        cfg.expected_dump_folder = cfg.hklm_per_exe.dump_folder;
    else if (!cfg.hkcu_default.dump_folder.empty())
        cfg.expected_dump_folder = cfg.hkcu_default.dump_folder;
    else if (!cfg.hklm_default.dump_folder.empty())
        cfg.expected_dump_folder = cfg.hklm_default.dump_folder;
    else
        cfg.expected_dump_folder = "C:\\CrashDumps";

    cfg.any_configured = cfg.hkcu_per_exe.present || cfg.hklm_per_exe.present ||
                         cfg.hkcu_default.present || cfg.hklm_default.present;

    return cfg;
}

inline void log_wer_config(const char* phase) {
    const auto cfg = scan_wer_config();
    const std::uint64_t start_ms = static_cast<std::uint64_t>(GetTickCount64());

    diag::log_tagged_critical_fmt("WER-CONFIG",
        "record=wer_config_summary phase=%s pid=%lu configured=%d expected_dump_folder=%s hkcu_per_exe_present=%d hkcu_default_present=%d hklm_per_exe_present=%d hklm_default_present=%d",
        phase ? phase : "<null>",
        static_cast<unsigned long>(GetCurrentProcessId()),
        cfg.any_configured ? 1 : 0,
        cfg.expected_dump_folder.c_str(),
        cfg.hkcu_per_exe.present ? 1 : 0,
        cfg.hkcu_default.present ? 1 : 0,
        cfg.hklm_per_exe.present ? 1 : 0,
        cfg.hklm_default.present ? 1 : 0);

    const char* scopes[][4] = {
        {"HKCU", "per_exe", nullptr, nullptr},
        {"HKCU", "default", nullptr, nullptr},
        {"HKLM", "per_exe", nullptr, nullptr},
        {"HKLM", "default", nullptr, nullptr},
    };
    const wer_registry_scope_t* scope_ptrs[] = {
        &cfg.hkcu_per_exe, &cfg.hkcu_default, &cfg.hklm_per_exe, &cfg.hklm_default
    };

    for (int i = 0; i < 4; ++i) {
        const auto& s = *scope_ptrs[i];
        char msg[2048];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "record=wer_scope root=%s scope=%s present=%d dump_folder=%s dump_type=%s dump_count_present=%d dump_count_value=%lu dump_count_gle=%lu gle=%lu",
            scopes[i][0], scopes[i][1],
            s.present ? 1 : 0,
            s.dump_folder.c_str(),
            s.dump_type_str.c_str(),
            s.dump_count_present ? 1 : 0,
            static_cast<unsigned long>(s.dump_count_value),
            static_cast<unsigned long>(s.dump_count_gle),
            static_cast<unsigned long>(s.gle));
        diag::log_tagged_critical("WER-CONFIG", msg);
    }

    diag::log_tagged_critical_fmt("WER-CONFIG",
        "record=wer_config_scan_end phase=%s elapsed_ms=%llu",
        phase ? phase : "<null>",
        static_cast<unsigned long long>(static_cast<std::uint64_t>(GetTickCount64()) - start_ms));
}

inline bool file_exists_with_size(const char* path, std::uint64_t& size, std::uint64_t& mtime_100ns) {
    size = 0;
    mtime_100ns = 0;
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad))
        return false;
    ULARGE_INTEGER file_size;
    file_size.LowPart = fad.nFileSizeLow;
    file_size.HighPart = fad.nFileSizeHigh;
    size = file_size.QuadPart;
    ULARGE_INTEGER mtime;
    mtime.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    mtime.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    mtime_100ns = mtime.QuadPart;
    return true;
}

inline std::vector<std::string> find_recent_dump_files(const std::string& folder, std::size_t max_results = 8) {
    std::vector<std::string> results;
    if (folder.empty()) return results;
    std::string pattern = folder;
    if (pattern.back() != '\\' && pattern.back() != '/')
        pattern += '\\';
    pattern += "AiDAStandalone.exe*.dmp";

    WIN32_FIND_DATAA fd{};
    HANDLE find = FindFirstFileA(pattern.c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) return results;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::string full = folder;
        if (full.back() != '\\' && full.back() != '/')
            full += '\\';
        full += fd.cFileName;
        results.push_back(full);
        if (results.size() >= max_results) break;
    } while (FindNextFileA(find, &fd));

    FindClose(find);
    return results;
}

inline wer_correlation_t build_correlation() {
    wer_correlation_t corr;
    corr.config = scan_wer_config();
    corr.normalized_dump_folder = corr.config.expected_dump_folder;

    corr.recent_dump_paths = find_recent_dump_files(corr.normalized_dump_folder);

    for (const auto& path : corr.recent_dump_paths) {
        wer_event_record_t rec;
        rec.dump_path = path;
        rec.dump_file_found = file_exists_with_size(path.c_str(), rec.dump_file_size, rec.dump_file_mtime_100ns);
        rec.tick_ms = static_cast<std::uint64_t>(GetTickCount64());
        corr.recent_events.push_back(std::move(rec));
    }

    corr.event_log_record_count = corr.recent_events.size();
    corr.event_log_query_ok = true;

    return corr;
}

inline void log_wer_correlation(const char* context) {
    auto corr = build_correlation();

    diag::log_tagged_critical_fmt("WER-EVENT-CORRELATION",
        "context=%s pid=%lu configured=%d dump_folder=%s dump_count=%zu event_log_ok=%d event_log_gle=%lu",
        context ? context : "<null>",
        static_cast<unsigned long>(GetCurrentProcessId()),
        corr.config.any_configured ? 1 : 0,
        corr.normalized_dump_folder.c_str(),
        corr.recent_dump_paths.size(),
        corr.event_log_query_ok ? 1 : 0,
        static_cast<unsigned long>(corr.event_log_last_error));

    for (std::size_t i = 0; i < corr.recent_events.size(); ++i) {
        const auto& e = corr.recent_events[i];
        diag::log_tagged_fmt("WER-EVENT-CORRELATION",
            "idx=%zu dump_path=%s found=%d size=%llu mtime_100ns=%llu tick_ms=%llu",
            i,
            e.dump_path.c_str(),
            e.dump_file_found ? 1 : 0,
            static_cast<unsigned long long>(e.dump_file_size),
            static_cast<unsigned long long>(e.dump_file_mtime_100ns),
            static_cast<unsigned long long>(e.tick_ms));
    }
}

inline std::string correlation_summary_string() {
    auto corr = build_correlation();
    char buf[1024];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "configured=%d folder=%s dumps_found=%zu event_log_ok=%d",
        corr.config.any_configured ? 1 : 0,
        corr.normalized_dump_folder.c_str(),
        corr.recent_dump_paths.size(),
        corr.event_log_query_ok ? 1 : 0);
    return std::string(buf);
}

inline std::string log_path_with_size(const char* path) {
    if (!path || path[0] == '\0') return std::string("path=<empty>");
    std::uint64_t size = 0, mtime = 0;
    bool exists = file_exists_with_size(path, size, mtime);
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "path=%s exists=%d size=%llu",
        path, exists ? 1 : 0, static_cast<unsigned long long>(size));
    return std::string(buf);
}

inline std::string known_log_paths_summary() {
    std::string out;
    const char* paths[] = {
        "aida_debug.log",
        "aida_crash.log",
        "C:\\Users\\Public\\Desktop\\aida_kernel.log",
        "C:\\Users\\Public\\Desktop\\aida_full_test.log",
        "C:\\CrashDumps",
    };
    char module_dir[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, module_dir, MAX_PATH);
    char* last = std::strrchr(module_dir, '\\');
    if (last) *(last + 1) = '\0';

    for (const char* p : paths) {
        char full[MAX_PATH];
        if (p[1] == ':') {
            _snprintf_s(full, sizeof(full), _TRUNCATE, "%s", p);
        } else {
            _snprintf_s(full, sizeof(full), _TRUNCATE, "%s%s", module_dir, p);
        }
        if (!out.empty()) out += "; ";
        out += log_path_with_size(full);
    }
    return out;
}

}
