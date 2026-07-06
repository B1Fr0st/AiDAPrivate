#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winevt.h>

#include <cstdint>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../../helpers/diag_log.hpp"

#pragma comment(lib, "wevtapi.lib")

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
    std::int64_t event_dump_delta_ms = 0;
    bool dump_correlated = false;
    std::string app_path;
    std::string exception_code_raw;
};

struct wer_correlation_t {
    wer_config_t config;
    std::vector<wer_event_record_t> recent_events;
    std::vector<std::string> recent_dump_paths;
    std::string normalized_dump_folder;
    bool event_log_query_ok = false;
    DWORD event_log_last_error = 0;
    std::size_t event_log_record_count = 0;
    std::uint64_t current_process_start_100ns = 0;
    std::uint64_t event_log_elapsed_ms = 0;
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

inline std::string wide_to_utf8(PCWSTR wstr) {
    if (!wstr) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string out(static_cast<std::size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &out[0], len, nullptr, nullptr);
    return out;
}

inline std::uint32_t parse_exception_code(const std::string& s) {
    if (s.empty()) return 0;
    const char* p = s.c_str();
    if (s.size() > 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        return static_cast<std::uint32_t>(std::strtoul(p + 2, nullptr, 16));
    if (std::strspn(p, "0123456789") == s.size())
        return static_cast<std::uint32_t>(std::strtoul(p, nullptr, 10));
    return static_cast<std::uint32_t>(std::strtoul(p, nullptr, 16));
}

inline bool contains_ci(const std::string& haystack, const char* needle) {
    if (!needle || !needle[0]) return false;
    std::string h = haystack;
    std::string n = needle;
    for (auto& c : h) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    for (auto& c : n) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return h.find(n) != std::string::npos;
}

struct evt_log_query_result_t {
    std::vector<wer_event_record_t> events;
    bool query_ok = false;
    DWORD last_error = 0;
    std::uint64_t elapsed_ms = 0;
};

struct evt_extracted_t {
    bool valid = false;
    std::string provider_name;
    std::uint16_t event_id = 0;
    std::uint64_t timestamp_100ns = 0;
    DWORD pid = 0;
    std::string app_name;
    std::string module_name;
    std::string exception_code_str;
    std::string report_id;
    std::string app_path;
    std::string faulting_app_name;
    std::string faulting_module_name;
    std::string original_app_name;
};

inline evt_extracted_t extract_event_fields(EVT_HANDLE event) {
    evt_extracted_t out;
    static PCWSTR kValuePaths[] = {
        L"Event/System/Provider/@Name",
        L"Event/System/EventID",
        L"Event/System/TimeCreated/@SystemTime",
        L"Event/System/Execution/@ProcessID",
        L"Event/EventData/Data[@Name='AppName']",
        L"Event/EventData/Data[@Name='ModuleName']",
        L"Event/EventData/Data[@Name='ExceptionCode']",
        L"Event/EventData/Data[@Name='ReportId']",
        L"Event/EventData/Data[@Name='AppPath']",
        L"Event/EventData/Data[@Name='FaultingApplicationName']",
        L"Event/EventData/Data[@Name='FaultingModuleName']",
        L"Event/EventData/Data[@Name='OriginalAppName']",
    };
    static const DWORD kValueCount = sizeof(kValuePaths) / sizeof(kValuePaths[0]);

    EVT_HANDLE ctx = EvtCreateRenderContext(kValueCount, kValuePaths, EvtRenderContextValues);
    if (!ctx) return out;

    std::vector<unsigned char> buffer;
    DWORD buf_size = 4096;
    buffer.resize(buf_size);
    DWORD used = 0;
    DWORD prop_count = 0;
    BOOL ok = EvtRender(ctx, event, EvtRenderEventValues, buf_size, buffer.data(), &used, &prop_count);
    if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(used);
        ok = EvtRender(ctx, event, EvtRenderEventValues, used, buffer.data(), &used, &prop_count);
    }
    EvtClose(ctx);
    if (!ok || prop_count < kValueCount) return out;

    PEVT_VARIANT vars = reinterpret_cast<PEVT_VARIANT>(buffer.data());

    if (vars[0].Type == EvtVarTypeString && vars[0].StringVal)
        out.provider_name = wide_to_utf8(vars[0].StringVal);

    if (vars[1].Type == EvtVarTypeUInt16)
        out.event_id = vars[1].UInt16Val;
    else if (vars[1].Type == EvtVarTypeUInt32)
        out.event_id = static_cast<std::uint16_t>(vars[1].UInt32Val);
    else if (vars[1].Type == EvtVarTypeInt32)
        out.event_id = static_cast<std::uint16_t>(vars[1].Int32Val);

    if (vars[2].Type == EvtVarTypeFileTime) {
        out.timestamp_100ns = static_cast<std::uint64_t>(vars[2].FileTimeVal);
    }

    if (vars[3].Type == EvtVarTypeUInt32)
        out.pid = vars[3].UInt32Val;
    else if (vars[3].Type == EvtVarTypeUInt64)
        out.pid = static_cast<DWORD>(vars[3].UInt64Val);

    auto get_str = [&](std::size_t idx) -> std::string {
        if (vars[idx].Type == EvtVarTypeString && vars[idx].StringVal)
            return wide_to_utf8(vars[idx].StringVal);
        return std::string();
    };
    out.app_name = get_str(4);
    out.module_name = get_str(5);
    out.exception_code_str = get_str(6);
    out.report_id = get_str(7);
    out.app_path = get_str(8);
    out.faulting_app_name = get_str(9);
    out.faulting_module_name = get_str(10);
    out.original_app_name = get_str(11);

    out.valid = true;
    return out;
}

inline evt_log_query_result_t query_wer_event_log(std::size_t max_events) {
    evt_log_query_result_t result;
    const std::uint64_t start_ms = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t time_budget_ms = 2000;
    if (max_events == 0) max_events = 32;

    EVT_HANDLE query_handle = EvtQuery(
        nullptr,
        L"Application",
        L"*[System[(EventID=1000 or EventID=1001)]]",
        EvtQueryChannelPath | EvtQueryReverseDirection);

    if (!query_handle) {
        result.query_ok = false;
        result.last_error = GetLastError();
        result.elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - start_ms;
        return result;
    }

    const DWORD kBatchSize = 16;
    const std::size_t kMaxRawEvents = 256;
    std::vector<EVT_HANDLE> event_handles;
    event_handles.resize(kBatchSize);

    std::size_t collected = 0;
    std::size_t raw_fetched = 0;
    while (collected < max_events && raw_fetched < kMaxRawEvents) {
        DWORD returned = 0;
        BOOL ok = EvtNext(query_handle, kBatchSize, event_handles.data(), 0, 0, &returned);
        if (!ok || returned == 0)
            break;
        raw_fetched += returned;

        for (DWORD i = 0; i < returned && collected < max_events; ++i) {
            evt_extracted_t ext = extract_event_fields(event_handles[i]);
            EvtClose(event_handles[i]);
            event_handles[i] = nullptr;

            if (!ext.valid) continue;

            const std::string& app_ref = !ext.app_name.empty() ? ext.app_name :
                                         !ext.faulting_app_name.empty() ? ext.faulting_app_name :
                                         !ext.original_app_name.empty() ? ext.original_app_name :
                                         !ext.app_path.empty() ? ext.app_path : ext.app_name;

            if (!contains_ci(app_ref, "AiDAStandalone"))
                continue;

            wer_event_record_t rec;
            rec.timestamp_100ns = ext.timestamp_100ns;
            rec.tick_ms = static_cast<std::uint64_t>(GetTickCount64());
            rec.pid = ext.pid;
            rec.provider_name = ext.provider_name;
            rec.source_name = ext.provider_name;
            rec.event_id = ext.event_id;
            rec.exception_code_raw = ext.exception_code_str;
            rec.exception_code = parse_exception_code(ext.exception_code_str);

            if (!ext.module_name.empty())
                rec.faulting_module = ext.module_name;
            else if (!ext.faulting_module_name.empty())
                rec.faulting_module = ext.faulting_module_name;

            rec.report_id = ext.report_id;
            rec.app_path = ext.app_path;

            result.events.push_back(std::move(rec));
            ++collected;
        }

        for (DWORD i = 0; i < returned; ++i) {
            if (event_handles[i]) {
                EvtClose(event_handles[i]);
                event_handles[i] = nullptr;
            }
        }

        if (returned < kBatchSize)
            break;
        if (static_cast<std::uint64_t>(GetTickCount64()) - start_ms > time_budget_ms)
            break;
    }

    for (std::size_t i = 0; i < event_handles.size(); ++i) {
        if (event_handles[i]) {
            EvtClose(event_handles[i]);
            event_handles[i] = nullptr;
        }
    }

    EvtClose(query_handle);

    result.query_ok = true;
    result.elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - start_ms;
    return result;
}

inline std::uint64_t current_process_start_100ns() {
    FILETIME creation{}, exit_time{}, kernel{}, user{};
    if (GetProcessTimes(GetCurrentProcess(), &creation, &exit_time, &kernel, &user)) {
        ULARGE_INTEGER ul;
        ul.LowPart = creation.dwLowDateTime;
        ul.HighPart = creation.dwHighDateTime;
        return ul.QuadPart;
    }
    return 0;
}

struct dump_info_t {
    std::string path;
    bool found = false;
    std::uint64_t size = 0;
    std::uint64_t mtime_100ns = 0;
    bool matched = false;
};

inline wer_correlation_t build_correlation() {
    wer_correlation_t corr;
    corr.config = scan_wer_config();
    corr.normalized_dump_folder = corr.config.expected_dump_folder;
    corr.current_process_start_100ns = current_process_start_100ns();

    corr.recent_dump_paths = find_recent_dump_files(corr.normalized_dump_folder);

    std::vector<dump_info_t> dumps;
    dumps.reserve(corr.recent_dump_paths.size());
    for (const auto& path : corr.recent_dump_paths) {
        dump_info_t d;
        d.path = path;
        d.found = file_exists_with_size(path.c_str(), d.size, d.mtime_100ns);
        dumps.push_back(std::move(d));
    }

    evt_log_query_result_t evt_result = query_wer_event_log(32);
    corr.event_log_query_ok = evt_result.query_ok;
    corr.event_log_last_error = evt_result.last_error;
    corr.event_log_elapsed_ms = evt_result.elapsed_ms;
    corr.event_log_record_count = evt_result.events.size();

    for (auto& evt : evt_result.events) {
        bool found_match = false;
        std::size_t best_idx = 0;
        std::uint64_t best_abs_delta = 0;
        for (std::size_t i = 0; i < dumps.size(); ++i) {
            if (!dumps[i].found || dumps[i].matched) continue;
            if (dumps[i].mtime_100ns == 0) continue;
            std::int64_t delta = static_cast<std::int64_t>(dumps[i].mtime_100ns) -
                                 static_cast<std::int64_t>(evt.timestamp_100ns);
            std::uint64_t abs_delta = delta < 0 ? static_cast<std::uint64_t>(-delta)
                                                 : static_cast<std::uint64_t>(delta);
            if (!found_match || abs_delta < best_abs_delta) {
                found_match = true;
                best_abs_delta = abs_delta;
                best_idx = i;
            }
        }
        if (found_match && best_abs_delta <= 1200000000ULL) {
            dumps[best_idx].matched = true;
            evt.dump_path = dumps[best_idx].path;
            evt.dump_file_found = dumps[best_idx].found;
            evt.dump_file_size = dumps[best_idx].size;
            evt.dump_file_mtime_100ns = dumps[best_idx].mtime_100ns;
            evt.event_dump_delta_ms = static_cast<std::int64_t>(
                (dumps[best_idx].mtime_100ns - evt.timestamp_100ns) / 10000ULL);
            evt.dump_correlated = true;
        }
        corr.recent_events.push_back(std::move(evt));
    }

    for (const auto& d : dumps) {
        if (d.matched) continue;
        wer_event_record_t rec;
        rec.dump_path = d.path;
        rec.dump_file_found = d.found;
        rec.dump_file_size = d.size;
        rec.dump_file_mtime_100ns = d.mtime_100ns;
        rec.timestamp_100ns = d.mtime_100ns;
        rec.tick_ms = static_cast<std::uint64_t>(GetTickCount64());
        corr.recent_events.push_back(std::move(rec));
    }

    return corr;
}

inline void log_wer_correlation(const char* context) {
    auto corr = build_correlation();

    diag::log_tagged_critical_fmt("WER-EVENT-CORRELATION",
        "context=%s pid=%lu configured=%d dump_folder=%s dump_count=%zu event_log_ok=%d event_log_gle=%lu event_log_records=%zu event_log_elapsed_ms=%llu proc_start_100ns=%llu",
        context ? context : "<null>",
        static_cast<unsigned long>(GetCurrentProcessId()),
        corr.config.any_configured ? 1 : 0,
        corr.normalized_dump_folder.c_str(),
        corr.recent_dump_paths.size(),
        corr.event_log_query_ok ? 1 : 0,
        static_cast<unsigned long>(corr.event_log_last_error),
        corr.event_log_record_count,
        static_cast<unsigned long long>(corr.event_log_elapsed_ms),
        static_cast<unsigned long long>(corr.current_process_start_100ns));

    for (std::size_t i = 0; i < corr.recent_events.size(); ++i) {
        const auto& e = corr.recent_events[i];
        diag::log_tagged_fmt("WER-EVENT-CORRELATION",
            "idx=%zu event_id=%u provider=%s source=%s exception_code=0x%08X exception_code_raw=%s faulting_module=%s report_id=%s pid=%lu timestamp_100ns=%llu tick_ms=%llu dump_path=%s found=%d size=%llu mtime_100ns=%llu dump_correlated=%d event_dump_delta_ms=%lld app_path=%s",
            i,
            static_cast<unsigned>(e.event_id),
            e.provider_name.c_str(),
            e.source_name.c_str(),
            static_cast<unsigned long>(e.exception_code),
            e.exception_code_raw.c_str(),
            e.faulting_module.c_str(),
            e.report_id.c_str(),
            static_cast<unsigned long>(e.pid),
            static_cast<unsigned long long>(e.timestamp_100ns),
            static_cast<unsigned long long>(e.tick_ms),
            e.dump_path.c_str(),
            e.dump_file_found ? 1 : 0,
            static_cast<unsigned long long>(e.dump_file_size),
            static_cast<unsigned long long>(e.dump_file_mtime_100ns),
            e.dump_correlated ? 1 : 0,
            static_cast<long long>(e.event_dump_delta_ms),
            e.app_path.c_str());
    }
}

inline std::string correlation_summary_string() {
    auto corr = build_correlation();
    char buf[1024];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "configured=%d folder=%s dumps_found=%zu event_log_ok=%d event_log_gle=%lu event_log_records=%zu event_log_elapsed_ms=%llu proc_start_100ns=%llu",
        corr.config.any_configured ? 1 : 0,
        corr.normalized_dump_folder.c_str(),
        corr.recent_dump_paths.size(),
        corr.event_log_query_ok ? 1 : 0,
        static_cast<unsigned long>(corr.event_log_last_error),
        corr.event_log_record_count,
        static_cast<unsigned long long>(corr.event_log_elapsed_ms),
        static_cast<unsigned long long>(corr.current_process_start_100ns));
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
