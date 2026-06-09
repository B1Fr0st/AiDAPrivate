#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "cert_profile_manager.hpp"
#include "helpers/diag_log.hpp"
#include "../../infra/work_queue.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <fstream>
#include <future>
#include <iterator>
#include <memory>
#include <sstream>
#include <type_traits>
#include <utility>

namespace cert_intercept {
namespace profiles {
namespace {

using json = nlohmann::json;

constexpr uint32_t kPrepareTimeoutMs = 12000;
constexpr uint32_t kTrustCheckTimeoutMs = 3500;
constexpr long kBoundedProfileMaxWorkers = 4;
std::atomic<long> g_bounded_profile_workers{0};

uint64_t tick_ms() {
    return static_cast<uint64_t>(GetTickCount64());
}

uint64_t elapsed_since(uint64_t start_ms) {
    const uint64_t now = tick_ms();
    return now >= start_ms ? now - start_ms : 0;
}

void prime_status_paths(firefox_profile_status_t& status,
                        const std::string& proxy_host,
                        uint16_t proxy_port) {
    const std::filesystem::path root = intercept_root();
    status.profile_path = root / L"firefox-profile";
    status.user_js_path = status.profile_path / L"user.js";
    status.policies_path = status.profile_path / L"distribution" / L"policies.json";
    const std::filesystem::path ca_root = root / L"ca";
    status.ca_pem_path = ca_root / L"aida_root_ca.pem";
    status.ca_der_path = ca_root / L"aida_root_ca.der";
    status.proxy_endpoint = proxy_host + ":" + std::to_string(static_cast<unsigned>(proxy_port));
}

void finish_status(firefox_profile_status_t& status, uint64_t start_ms, const char* op) {
    status.elapsed_ms = elapsed_since(start_ms);
    if (op && *op) status.last_operation = op;
}

cert_generator::root_ca_t duplicate_root_ca_for_worker(const cert_generator::root_ca_t& ca,
                                                       firefox_profile_status_t* status,
                                                       const char* op) {
    cert_generator::root_ca_t copy;
    if (!ca.valid || !ca.key || !ca.cert) {
        if (status) {
            status->error = "root_ca_not_valid";
            status->last_operation = op ? op : "duplicate_root_ca";
        }
        return copy;
    }
    if (EVP_PKEY_up_ref(ca.key.get()) != 1) {
        if (status) {
            status->error = "root_ca_key_ref_failed";
            status->last_operation = op ? op : "duplicate_root_ca";
        }
        return copy;
    }
    copy.key.reset(ca.key.get());
    if (X509_up_ref(ca.cert.get()) != 1) {
        if (status) {
            status->error = "root_ca_cert_ref_failed";
            status->last_operation = op ? op : "duplicate_root_ca";
        }
        return copy;
    }
    copy.cert.reset(ca.cert.get());
    copy.valid = true;
    return copy;
}

template <typename T>
struct bounded_value_t {
    bool completed = false;
    bool threw = false;
    bool timed_out = false;
    DWORD win32_error = ERROR_SUCCESS;
    uint64_t elapsed_ms = 0;
    T value{};
    std::string exception;
};

template <typename T, typename Fn>
bounded_value_t<T> run_bounded_value(const char* tag,
                                     const char* op,
                                     uint32_t timeout_ms,
                                     Fn&& fn) {
    const uint64_t start_ms = tick_ms();
    const long active = g_bounded_profile_workers.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (active > kBoundedProfileMaxWorkers) {
        g_bounded_profile_workers.fetch_sub(1, std::memory_order_acq_rel);
        bounded_value_t<T> result;
        result.completed = true;
        result.threw = true;
        result.win32_error = ERROR_BUSY;
        result.elapsed_ms = elapsed_since(start_ms);
        result.exception = "bounded_profile_worker_limit";
        diag::log_tagged_fmt(tag, "%s worker_limit active=%ld limit=%ld elapsed_ms=%llu",
            op, active, kBoundedProfileMaxWorkers,
            static_cast<unsigned long long>(result.elapsed_ms));
        return result;
    }
    auto promise = std::make_shared<std::promise<bounded_value_t<T>>>();
    auto future = promise->get_future();
    diag::log_tagged_fmt(tag, "%s worker_start timeout_ms=%u active=%ld pid=%lu tid=%lu",
        op, timeout_ms, active,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    using task_t = typename std::decay<Fn>::type;
    std::shared_ptr<task_t> task_ptr;
    try {
        task_ptr = std::make_shared<task_t>(std::forward<Fn>(fn));
    } catch (const std::exception& ex) {
        g_bounded_profile_workers.fetch_sub(1, std::memory_order_acq_rel);
        bounded_value_t<T> result;
        result.threw = true;
        result.exception = ex.what();
        result.win32_error = GetLastError();
        result.elapsed_ms = elapsed_since(start_ms);
        diag::log_tagged_fmt(tag, "%s task_init_failed err=%s gle=%lu elapsed_ms=%llu",
            op, result.exception.c_str(), static_cast<unsigned long>(result.win32_error),
            static_cast<unsigned long long>(result.elapsed_ms));
        return result;
    } catch (...) {
        g_bounded_profile_workers.fetch_sub(1, std::memory_order_acq_rel);
        bounded_value_t<T> result;
        result.threw = true;
        result.exception = "task_initialization_failed";
        result.win32_error = GetLastError();
        result.elapsed_ms = elapsed_since(start_ms);
        diag::log_tagged_fmt(tag, "%s task_init_failed err=%s gle=%lu elapsed_ms=%llu",
            op, result.exception.c_str(), static_cast<unsigned long>(result.win32_error),
            static_cast<unsigned long long>(result.elapsed_ms));
        return result;
    }
    const bool started = work_queue::post([promise, start_ms, tag, op, task_ptr]() mutable {
        bounded_value_t<T> result;
        SetLastError(ERROR_SUCCESS);
        try {
            result.value = (*task_ptr)();
        } catch (const std::exception& ex) {
            result.threw = true;
            result.exception = ex.what();
        } catch (...) {
            result.threw = true;
            result.exception = "unknown_exception";
        }
        result.win32_error = GetLastError();
        result.completed = true;
        result.elapsed_ms = elapsed_since(start_ms);
        const long remaining = g_bounded_profile_workers.fetch_sub(1, std::memory_order_acq_rel) - 1;
        diag::log_tagged_fmt(tag, "%s worker_exit completed=1 threw=%d gle=%lu active_after=%ld elapsed_ms=%llu",
            op, result.threw ? 1 : 0, static_cast<unsigned long>(result.win32_error),
            remaining,
            static_cast<unsigned long long>(result.elapsed_ms));
        try {
            promise->set_value(std::move(result));
        } catch (...) {
        }
    });
    if (!started) {
        g_bounded_profile_workers.fetch_sub(1, std::memory_order_acq_rel);
        bounded_value_t<T> result;
        result.threw = true;
        result.exception = "work_queue_post_failed";
        result.win32_error = ERROR_NOT_READY;
        result.elapsed_ms = elapsed_since(start_ms);
        diag::log_tagged_fmt(tag, "%s work_queue_post_failed err=%s gle=%lu elapsed_ms=%llu",
            op, result.exception.c_str(), static_cast<unsigned long>(result.win32_error),
            static_cast<unsigned long long>(result.elapsed_ms));
        return result;
    }

    if (future.wait_for(std::chrono::milliseconds(timeout_ms)) != std::future_status::ready) {
        bounded_value_t<T> result;
        result.timed_out = true;
        result.elapsed_ms = elapsed_since(start_ms);
        result.win32_error = WAIT_TIMEOUT;
        diag::log_tagged_fmt(tag, "%s timeout timeout_ms=%u elapsed_ms=%llu",
            op, timeout_ms, static_cast<unsigned long long>(result.elapsed_ms));
        return result;
    }
    bounded_value_t<T> result = future.get();
    diag::log_tagged_fmt(tag, "%s wait_done threw=%d gle=%lu elapsed_ms=%llu",
        op, result.threw ? 1 : 0, static_cast<unsigned long>(result.win32_error),
        static_cast<unsigned long long>(result.elapsed_ms));
    return result;
}

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

std::filesystem::path local_appdata() {
    const uint64_t start_ms = tick_ms();
    diag::log_tagged_fmt("cert_profile_fx", "local_appdata begin pid=%lu tid=%lu",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    PWSTR known = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &known)) && known) {
        std::filesystem::path out(known);
        CoTaskMemFree(known);
        diag::log_tagged_fmt("cert_profile_fx", "local_appdata known_folder path=%s elapsed_ms=%llu",
            out.u8string().c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
        return out;
    }
    wchar_t buf[MAX_PATH] = {};
    SetLastError(ERROR_SUCCESS);
    DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    DWORD gle = GetLastError();
    if (len > 0 && len < MAX_PATH) {
        std::filesystem::path out(buf);
        diag::log_tagged_fmt("cert_profile_fx", "local_appdata env path=%s len=%lu gle=%lu elapsed_ms=%llu",
            out.u8string().c_str(), static_cast<unsigned long>(len),
            static_cast<unsigned long>(gle), static_cast<unsigned long long>(elapsed_since(start_ms)));
        return out;
    }
    diag::log_tagged_fmt("cert_profile_fx", "local_appdata fallback len=%lu gle=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(len), static_cast<unsigned long>(gle),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    return std::filesystem::path(L"C:\\Users\\Public");
}

std::string env_string(const char* name, const char* fallback) {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA(name, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) return std::string(buf, len);
    return fallback ? std::string(fallback) : std::string();
}

bool file_exists(const std::string& path) {
    if (path.empty()) return false;
    std::wstring w = utf8_to_wide(path);
    if (w.empty()) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return false;
    }
    SetLastError(ERROR_SUCCESS);
    DWORD attrs = GetFileAttributesW(w.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

constexpr uint64_t kMaxProfileFileBytes = 16ull * 1024ull * 1024ull;

std::string win32_error_text(DWORD gle) {
    return std::string("gle=") + std::to_string(static_cast<unsigned long>(gle));
}

bool read_file_bytes_win32(const std::filesystem::path& path, std::vector<uint8_t>& out, std::string& error) {
    const uint64_t start_ms = tick_ms();
    out.clear();
    const std::string path_s = path.u8string();
    SetLastError(ERROR_SUCCESS);
    DWORD attrs = GetFileAttributesW(path.c_str());
    DWORD attr_gle = GetLastError();
    diag::log_tagged_fmt("cert_profile_fx", "read_file_bytes begin path=%s attrs=0x%08lX attr_gle=%lu pid=%lu tid=%lu",
        path_s.c_str(),
        static_cast<unsigned long>(attrs),
        static_cast<unsigned long>(attr_gle),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    SetLastError(ERROR_SUCCESS);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        error = win32_error_text(gle);
        diag::log_tagged_fmt("cert_profile_fx", "read_file_bytes open_failed path=%s gle=%lu elapsed_ms=%llu",
            path_s.c_str(), static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 || static_cast<uint64_t>(size.QuadPart) > kMaxProfileFileBytes) {
        DWORD gle = GetLastError();
        if (gle == ERROR_SUCCESS)
            gle = ERROR_FILE_TOO_LARGE;
        error = win32_error_text(gle);
        diag::log_tagged_fmt("cert_profile_fx", "read_file_bytes size_failed path=%s gle=%lu size=%lld elapsed_ms=%llu",
            path_s.c_str(), static_cast<unsigned long>(gle), static_cast<long long>(size.QuadPart),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<size_t>(size.QuadPart));
    size_t offset = 0;
    while (offset < out.size()) {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(out.size() - offset, 1u << 20));
        DWORD got = 0;
        SetLastError(ERROR_SUCCESS);
        if (!ReadFile(h, out.data() + offset, chunk, &got, nullptr)) {
            DWORD gle = GetLastError();
            error = win32_error_text(gle);
            diag::log_tagged_fmt("cert_profile_fx", "read_file_bytes read_failed path=%s gle=%lu offset=%zu chunk=%lu elapsed_ms=%llu",
                path_s.c_str(), static_cast<unsigned long>(gle), offset, static_cast<unsigned long>(chunk),
                static_cast<unsigned long long>(elapsed_since(start_ms)));
            CloseHandle(h);
            return false;
        }
        if (got == 0) {
            error = "short_read";
            diag::log_tagged_fmt("cert_profile_fx", "read_file_bytes short_read path=%s offset=%zu expected=%zu elapsed_ms=%llu",
                path_s.c_str(), offset, out.size(),
                static_cast<unsigned long long>(elapsed_since(start_ms)));
            CloseHandle(h);
            return false;
        }
        offset += got;
    }
    CloseHandle(h);
    diag::log_tagged_fmt("cert_profile_fx", "read_file_bytes done path=%s bytes=%zu elapsed_ms=%llu",
        path_s.c_str(), out.size(), static_cast<unsigned long long>(elapsed_since(start_ms)));
    return true;
}

bool write_file_bytes_win32(const std::filesystem::path& path, const uint8_t* data, size_t size, std::string& error) {
    const uint64_t start_ms = tick_ms();
    const std::string path_s = path.u8string();
    SetLastError(ERROR_SUCCESS);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        error = win32_error_text(gle);
        diag::log_tagged_fmt("cert_profile_fx", "write_file_bytes open_failed path=%s gle=%lu bytes=%zu elapsed_ms=%llu",
            path_s.c_str(), static_cast<unsigned long>(gle), size,
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    size_t offset = 0;
    while (offset < size) {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(size - offset, 1u << 20));
        DWORD wrote = 0;
        SetLastError(ERROR_SUCCESS);
        const uint8_t* chunk_data = data ? data + offset : nullptr;
        if (!WriteFile(h, chunk_data, chunk, &wrote, nullptr) || wrote != chunk) {
            DWORD gle = GetLastError();
            if (gle == ERROR_SUCCESS)
                gle = ERROR_WRITE_FAULT;
            error = win32_error_text(gle);
            diag::log_tagged_fmt("cert_profile_fx", "write_file_bytes write_failed path=%s gle=%lu offset=%zu chunk=%lu wrote=%lu elapsed_ms=%llu",
                path_s.c_str(), static_cast<unsigned long>(gle), offset,
                static_cast<unsigned long>(chunk), static_cast<unsigned long>(wrote),
                static_cast<unsigned long long>(elapsed_since(start_ms)));
            CloseHandle(h);
            return false;
        }
        offset += wrote;
    }
    SetLastError(ERROR_SUCCESS);
    BOOL flush_ok = FlushFileBuffers(h);
    DWORD flush_gle = GetLastError();
    CloseHandle(h);
    if (!flush_ok) {
        error = win32_error_text(flush_gle);
        diag::log_tagged_fmt("cert_profile_fx", "write_file_bytes flush_failed path=%s gle=%lu bytes=%zu elapsed_ms=%llu",
            path_s.c_str(), static_cast<unsigned long>(flush_gle), size,
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    diag::log_tagged_fmt("cert_profile_fx", "write_file_bytes done path=%s bytes=%zu elapsed_ms=%llu",
        path_s.c_str(), size, static_cast<unsigned long long>(elapsed_since(start_ms)));
    return true;
}

bool file_nonempty(const std::filesystem::path& path) {
    const uint64_t start_ms = tick_ms();
    std::error_code ec;
    const bool regular = std::filesystem::is_regular_file(path, ec) && !ec;
    uintmax_t size = 0;
    if (regular) size = std::filesystem::file_size(path, ec);
    const bool ok = regular && !ec && size > 0;
    diag::log_tagged_fmt("cert_profile_fx", "file_nonempty path=%s regular=%d size=%llu ok=%d ec=%s elapsed_ms=%llu",
        path.u8string().c_str(), regular ? 1 : 0, static_cast<unsigned long long>(size),
        ok ? 1 : 0, ec ? ec.message().c_str() : "",
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    return ok;
}

bool read_text_file(const std::filesystem::path& path, std::string& out) {
    const uint64_t start_ms = tick_ms();
    std::string error;
    std::vector<uint8_t> bytes;
    if (!read_file_bytes_win32(path, bytes, error)) {
        diag::log_tagged_fmt("cert_profile_fx", "read_text_file failed path=%s err=%s elapsed_ms=%llu",
            path.u8string().c_str(), error.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    if (bytes.empty())
        out.clear();
    else
        out.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    diag::log_tagged_fmt("cert_profile_fx", "read_text_file done path=%s bytes=%zu elapsed_ms=%llu",
        path.u8string().c_str(), out.size(), static_cast<unsigned long long>(elapsed_since(start_ms)));
    return true;
}

bool text_has(const std::string& text, const std::string& needle) {
    return text.find(needle) != std::string::npos;
}

std::string json_escaped_path(const std::filesystem::path& path);
std::string js_string_literal(std::string value);

bool policies_declare_ca_install(const std::filesystem::path& path) {
    std::string text;
    if (!read_text_file(path, text)) return false;
    try {
        json parsed = json::parse(text);
        auto& certs = parsed["policies"]["Certificates"];
        return certs.value("ImportEnterpriseRoots", false) &&
            certs.contains("Install") &&
            certs["Install"].is_array() &&
            !certs["Install"].empty();
    } catch (...) {
        return false;
    }
}

bool policies_declare_ca_install(const std::filesystem::path& path,
                                 const std::filesystem::path& pem_path,
                                 const std::filesystem::path& der_path) {
    std::string text;
    if (!read_text_file(path, text)) return false;
    try {
        json parsed = json::parse(text);
        auto& certs = parsed["policies"]["Certificates"];
        if (!certs.value("ImportEnterpriseRoots", false)) return false;
        if (!certs.contains("Install") || !certs["Install"].is_array()) return false;
        bool has_pem = false;
        bool has_der = false;
        const std::string pem = json_escaped_path(pem_path);
        const std::string der = json_escaped_path(der_path);
        for (const auto& item : certs["Install"]) {
            if (!item.is_string()) continue;
            const std::string value = item.get<std::string>();
            has_pem = has_pem || value == pem;
            has_der = has_der || value == der;
        }
        return has_pem && has_der;
    } catch (...) {
        return false;
    }
}

bool user_js_matches(const std::filesystem::path& path, const std::string& proxy_host, uint16_t proxy_port) {
    std::string text;
    if (!read_text_file(path, text)) return false;
    return text_has(text, "security.enterprise_roots.enabled\", true") &&
        text_has(text, "network.proxy.type\", 1") &&
        text_has(text, "network.proxy.http\", \"" + js_string_literal(proxy_host) + "\"") &&
        text_has(text, "network.proxy.http_port\", " + std::to_string(static_cast<unsigned>(proxy_port))) &&
        text_has(text, "network.proxy.ssl\", \"" + js_string_literal(proxy_host) + "\"") &&
        text_has(text, "network.proxy.ssl_port\", " + std::to_string(static_cast<unsigned>(proxy_port))) &&
        text_has(text, "network.http.http3.enabled\", false");
}

bool current_ca_files_match(const cert_generator::root_ca_t& ca,
                            const std::filesystem::path& pem_path,
                            const std::filesystem::path& der_path) {
    const uint64_t start_ms = tick_ms();
    diag::log_tagged_fmt("cert_profile_fx", "current_ca_files_match begin pem=%s der=%s",
        pem_path.u8string().c_str(), der_path.u8string().c_str());
    std::string expected_pem;
    if (!cert_generator::export_ca_certificate_pem(ca, expected_pem)) {
        diag::log_tagged_fmt("cert_profile_fx", "current_ca_files_match pem_export_failed elapsed_ms=%llu",
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    std::string actual_pem;
    if (!read_text_file(pem_path, actual_pem) || actual_pem != expected_pem) {
        diag::log_tagged_fmt("cert_profile_fx", "current_ca_files_match pem_mismatch expected=%zu actual=%zu elapsed_ms=%llu",
            expected_pem.size(), actual_pem.size(), static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    std::vector<uint8_t> expected_der;
    if (!cert_generator::export_ca_certificate_der(ca, expected_der)) {
        diag::log_tagged_fmt("cert_profile_fx", "current_ca_files_match der_export_failed elapsed_ms=%llu",
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    std::string der_error;
    std::vector<uint8_t> actual_der;
    if (!read_file_bytes_win32(der_path, actual_der, der_error)) {
        diag::log_tagged_fmt("cert_profile_fx", "current_ca_files_match der_read_failed err=%s elapsed_ms=%llu",
            der_error.c_str(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    const bool match = actual_der == expected_der;
    diag::log_tagged_fmt("cert_profile_fx", "current_ca_files_match done match=%d expected_der=%zu actual_der=%zu elapsed_ms=%llu",
        match ? 1 : 0, expected_der.size(), actual_der.size(),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    return match;
}

std::string registry_app_path() {
    const uint64_t start_ms = tick_ms();
    HKEY k = nullptr;
    LONG open_rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe",
                      0, KEY_READ, &k);
    diag::log_tagged_fmt("cert_profile_fx", "registry_app_path RegOpenKeyExA rc=%ld elapsed_ms=%llu",
        static_cast<long>(open_rc), static_cast<unsigned long long>(elapsed_since(start_ms)));
    if (open_rc != ERROR_SUCCESS) {
        return std::string();
    }
    char buf[1024] = {};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    LONG rc = RegQueryValueExA(k, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(k);
    diag::log_tagged_fmt("cert_profile_fx", "registry_app_path RegQueryValueExA rc=%ld type=%lu size=%lu elapsed_ms=%llu",
        static_cast<long>(rc), static_cast<unsigned long>(type), static_cast<unsigned long>(sz),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return std::string();
    if (sz > 0 && buf[sz - 1] == '\0') sz--;
    std::string value(buf, sz);
    if (type == REG_EXPAND_SZ) {
        char expanded[2048] = {};
        DWORD expanded_len = ExpandEnvironmentStringsA(value.c_str(), expanded, static_cast<DWORD>(sizeof(expanded)));
        if (expanded_len > 0 && expanded_len < sizeof(expanded)) value.assign(expanded);
        diag::log_tagged_fmt("cert_profile_fx", "registry_app_path expand len=%lu path=%s elapsed_ms=%llu",
            static_cast<unsigned long>(expanded_len), value.c_str(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
    } else {
        diag::log_tagged_fmt("cert_profile_fx", "registry_app_path value path=%s elapsed_ms=%llu",
            value.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
    }
    return value;
}

std::string json_escaped_path(const std::filesystem::path& path) {
    return path.u8string();
}

std::string js_string_literal(std::string value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        if (ch == '\\' || ch == '"') out.push_back('\\');
        out.push_back(ch);
    }
    return out;
}

bool write_text_if_changed(const std::filesystem::path& path, const std::string& text, std::string& error) {
    const uint64_t start_ms = tick_ms();
    const std::string path_s = path.u8string();
    const std::string parent_s = path.parent_path().u8string();
    diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed begin path=%s bytes=%zu",
        path_s.c_str(), text.size());
    std::error_code ec;
    SetLastError(ERROR_SUCCESS);
    DWORD parent_attrs_before = GetFileAttributesW(path.parent_path().c_str());
    DWORD parent_gle_before = GetLastError();
    diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed mkdir begin parent=%s attrs_before=0x%08lX gle_before=%lu",
        parent_s.c_str(),
        static_cast<unsigned long>(parent_attrs_before),
        static_cast<unsigned long>(parent_gle_before));
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        error = ec.message();
        diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed mkdir_failed path=%s err=%s elapsed_ms=%llu",
            parent_s.c_str(), error.c_str(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    SetLastError(ERROR_SUCCESS);
    DWORD parent_attrs_after = GetFileAttributesW(path.parent_path().c_str());
    DWORD parent_gle_after = GetLastError();
    diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed mkdir done parent=%s attrs_after=0x%08lX gle_after=%lu elapsed_ms=%llu",
        parent_s.c_str(),
        static_cast<unsigned long>(parent_attrs_after),
        static_cast<unsigned long>(parent_gle_after),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    std::vector<uint8_t> current;
    std::string read_error;
    if (read_file_bytes_win32(path, current, read_error)) {
        if (current.size() == text.size() &&
            (text.empty() || std::memcmp(current.data(), text.data(), text.size()) == 0)) {
            diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed unchanged path=%s elapsed_ms=%llu",
                path_s.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
            return true;
        }
        diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed content_changed path=%s old=%zu new=%zu elapsed_ms=%llu",
            path_s.c_str(), current.size(), text.size(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
    } else {
        diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed existing_read_miss path=%s err=%s elapsed_ms=%llu",
            path_s.c_str(), read_error.c_str(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
    }
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(text.data());
    if (!write_file_bytes_win32(path, bytes, text.size(), error)) {
        diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed write_failed path=%s err=%s elapsed_ms=%llu",
            path_s.c_str(), error.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    diag::log_tagged_fmt("cert_profile_fx", "write_text_if_changed wrote path=%s bytes=%zu elapsed_ms=%llu",
        path_s.c_str(), text.size(), static_cast<unsigned long long>(elapsed_since(start_ms)));
    return true;
}

bool write_bytes_if_changed(const std::filesystem::path& path, const std::vector<uint8_t>& bytes, std::string& error) {
    const uint64_t start_ms = tick_ms();
    const std::string path_s = path.u8string();
    const std::string parent_s = path.parent_path().u8string();
    diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed begin path=%s bytes=%zu",
        path_s.c_str(), bytes.size());
    std::error_code ec;
    SetLastError(ERROR_SUCCESS);
    DWORD parent_attrs_before = GetFileAttributesW(path.parent_path().c_str());
    DWORD parent_gle_before = GetLastError();
    diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed mkdir begin parent=%s attrs_before=0x%08lX gle_before=%lu",
        parent_s.c_str(),
        static_cast<unsigned long>(parent_attrs_before),
        static_cast<unsigned long>(parent_gle_before));
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        error = ec.message();
        diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed mkdir_failed path=%s err=%s elapsed_ms=%llu",
            parent_s.c_str(), error.c_str(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    SetLastError(ERROR_SUCCESS);
    DWORD parent_attrs_after = GetFileAttributesW(path.parent_path().c_str());
    DWORD parent_gle_after = GetLastError();
    diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed mkdir done parent=%s attrs_after=0x%08lX gle_after=%lu elapsed_ms=%llu",
        parent_s.c_str(),
        static_cast<unsigned long>(parent_attrs_after),
        static_cast<unsigned long>(parent_gle_after),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    std::vector<uint8_t> current;
    std::string read_error;
    if (read_file_bytes_win32(path, current, read_error)) {
        if (current == bytes) {
            diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed unchanged path=%s elapsed_ms=%llu",
                path_s.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
            return true;
        }
        diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed content_changed path=%s old=%zu new=%zu elapsed_ms=%llu",
            path_s.c_str(), current.size(), bytes.size(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
    } else {
        diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed existing_read_miss path=%s err=%s elapsed_ms=%llu",
            path_s.c_str(), read_error.c_str(),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
    }
    const uint8_t* data = bytes.empty() ? nullptr : bytes.data();
    if (!write_file_bytes_win32(path, data, bytes.size(), error)) {
        diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed write_failed path=%s err=%s elapsed_ms=%llu",
            path_s.c_str(), error.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
        return false;
    }
    diag::log_tagged_fmt("cert_profile_fx", "write_bytes_if_changed wrote path=%s bytes=%zu elapsed_ms=%llu",
        path_s.c_str(), bytes.size(), static_cast<unsigned long long>(elapsed_since(start_ms)));
    return true;
}

std::string user_js_text(const std::string& proxy_host, uint16_t proxy_port) {
    std::ostringstream ss;
    ss << "user_pref(\"security.enterprise_roots.enabled\", true);\n";
    ss << "user_pref(\"network.proxy.type\", 1);\n";
    ss << "user_pref(\"network.proxy.http\", \"" << js_string_literal(proxy_host) << "\");\n";
    ss << "user_pref(\"network.proxy.http_port\", " << static_cast<unsigned>(proxy_port) << ");\n";
    ss << "user_pref(\"network.proxy.ssl\", \"" << js_string_literal(proxy_host) << "\");\n";
    ss << "user_pref(\"network.proxy.ssl_port\", " << static_cast<unsigned>(proxy_port) << ");\n";
    ss << "user_pref(\"network.proxy.no_proxies_on\", \"localhost, 127.0.0.1, ::1\");\n";
    ss << "user_pref(\"network.http.http3.enabled\", false);\n";
    return ss.str();
}

json policies_json(const std::filesystem::path& pem_path, const std::filesystem::path& der_path) {
    json root;
    root["policies"]["Certificates"]["ImportEnterpriseRoots"] = true;
    root["policies"]["Certificates"]["Install"] = json::array({
        json_escaped_path(pem_path),
        json_escaped_path(der_path)
    });
    return root;
}

}

std::filesystem::path intercept_root() {
    return local_appdata() / L"AiDA" / L"Standalone" / L"intercept";
}

std::filesystem::path ca_export_root() {
    return intercept_root() / L"ca";
}

std::filesystem::path firefox_profile_root() {
    return intercept_root() / L"firefox-profile";
}

bool detect_firefox_path(std::string& out_path) {
    const uint64_t start_ms = tick_ms();
    diag::log_tagged_fmt("cert_profile_fx", "detect_firefox_path begin pid=%lu tid=%lu",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    std::vector<std::string> candidates;
    candidates.push_back(env_string("ProgramFiles", "C:\\Program Files") + "\\Mozilla Firefox\\firefox.exe");
    candidates.push_back(env_string("ProgramFiles(x86)", "C:\\Program Files (x86)") + "\\Mozilla Firefox\\firefox.exe");
    candidates.push_back(registry_app_path());
    for (const auto& candidate : candidates) {
        SetLastError(ERROR_SUCCESS);
        const bool exists = file_exists(candidate);
        const DWORD gle = GetLastError();
        diag::log_tagged_fmt("cert_profile_fx", "detect_firefox_path candidate path=%s exists=%d gle=%lu elapsed_ms=%llu",
            candidate.c_str(), exists ? 1 : 0, static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        if (exists) {
            out_path = candidate;
            diag::log_tagged_fmt("cert_profile_fx", "detect_firefox_path found path=%s elapsed_ms=%llu",
                out_path.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
            return true;
        }
    }
    out_path.clear();
    diag::log_tagged_fmt("cert_profile_fx", "detect_firefox_path not_found elapsed_ms=%llu",
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    return false;
}

public_ca_export_t export_public_ca_files(const cert_generator::root_ca_t& ca) {
    const uint64_t start_ms = tick_ms();
    public_ca_export_t result;
    result.directory = ca_export_root();
    result.pem_path = result.directory / L"aida_root_ca.pem";
    result.der_path = result.directory / L"aida_root_ca.der";
    diag::log_tagged_fmt("cert_profile_fx", "export_public_ca_files begin dir=%s pem=%s der=%s ca_valid=%d",
        result.directory.u8string().c_str(), result.pem_path.u8string().c_str(),
        result.der_path.u8string().c_str(), ca.valid ? 1 : 0);

    std::string pem;
    if (!cert_generator::export_ca_certificate_pem(ca, pem)) {
        result.error = "pem_export_failed";
        diag::log_tagged_fmt("cert_profile_fx", "export_public_ca_files pem_export_failed elapsed_ms=%llu",
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return result;
    }
    std::vector<uint8_t> der;
    if (!cert_generator::export_ca_certificate_der(ca, der)) {
        result.error = "der_export_failed";
        diag::log_tagged_fmt("cert_profile_fx", "export_public_ca_files der_export_failed elapsed_ms=%llu",
            static_cast<unsigned long long>(elapsed_since(start_ms)));
        return result;
    }
    if (!write_text_if_changed(result.pem_path, pem, result.error)) {
        diag::log_tagged_fmt("cert_profile_fx", "export_public_ca_files pem_write_failed err=%s elapsed_ms=%llu",
            result.error.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
        return result;
    }
    if (!write_bytes_if_changed(result.der_path, der, result.error)) {
        diag::log_tagged_fmt("cert_profile_fx", "export_public_ca_files der_write_failed err=%s elapsed_ms=%llu",
            result.error.c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
        return result;
    }
    result.ok = true;
    diag::log_tagged_fmt("cert_profile_fx", "export_public_ca_files done pem_len=%zu der_len=%zu elapsed_ms=%llu",
        pem.size(), der.size(), static_cast<unsigned long long>(elapsed_since(start_ms)));
    return result;
}

bounded_value_t<bool> query_current_user_ca_trust_bounded(const cert_generator::root_ca_t& ca,
                                                          uint32_t timeout_ms) {
    firefox_profile_status_t duplicate_status;
    cert_generator::root_ca_t ca_copy = duplicate_root_ca_for_worker(ca, &duplicate_status, "current_user_ca_trust_duplicate");
    if (!ca_copy.valid) {
        bounded_value_t<bool> result;
        result.completed = true;
        result.value = false;
        result.win32_error = ERROR_INVALID_DATA;
        result.exception = duplicate_status.error;
        return result;
    }
    return run_bounded_value<bool>("cert_profile_fx", "current_user_ca_trust", timeout_ms,
        [ca_copy = std::move(ca_copy)]() mutable {
            return cert_generator::is_root_ca_installed(ca_copy);
        });
}

void log_prepare_exit(const firefox_profile_status_t& status, const char* phase) {
    diag::log_tagged_fmt("cert_profile_fx",
        "prepare_firefox_profile %s ok=%d prepared=%d files=%d trust=%d trust_verified=%d firefox=%d timeout=%d timeout_ms=%u elapsed_ms=%llu gle=%lu op=%s error=%s profile=%s user_js=%s policies=%s ca_pem=%s ca_der=%s firefox_path=%s",
        phase,
        status.ok ? 1 : 0,
        status.prepared ? 1 : 0,
        status.profile_files_valid ? 1 : 0,
        status.current_user_ca_trusted ? 1 : 0,
        status.trust_readiness_verified ? 1 : 0,
        status.firefox_detected ? 1 : 0,
        status.timed_out ? 1 : 0,
        static_cast<unsigned>(status.timeout_ms),
        static_cast<unsigned long long>(status.elapsed_ms),
        static_cast<unsigned long>(status.last_win32_error),
        status.last_operation.c_str(),
        status.error.c_str(),
        status.profile_path.u8string().c_str(),
        status.user_js_path.u8string().c_str(),
        status.policies_path.u8string().c_str(),
        status.ca_pem_path.u8string().c_str(),
        status.ca_der_path.u8string().c_str(),
        status.firefox_path.c_str());
}

firefox_profile_status_t prepare_firefox_profile_impl(const cert_generator::root_ca_t& ca,
                                                      const std::string& proxy_host,
                                                      uint16_t proxy_port) {
    const uint64_t start_ms = tick_ms();
    firefox_profile_status_t status;
    status.timeout_ms = kPrepareTimeoutMs;
    prime_status_paths(status, proxy_host, proxy_port);
    status.last_operation = "entry";
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile_impl entry profile=%s proxy=%s ca_valid=%d pid=%lu tid=%lu",
        status.profile_path.u8string().c_str(),
        status.proxy_endpoint.c_str(),
        ca.valid ? 1 : 0,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (!ca.valid || !ca.cert) {
        status.error = "root_ca_not_valid";
        finish_status(status, start_ms, "validate_root_ca");
        log_prepare_exit(status, "fail");
        return status;
    }

    std::error_code ec;
    status.last_operation = "create_profile_dir";
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile create_profile_dir begin path=%s",
        status.profile_path.u8string().c_str());
    std::filesystem::create_directories(status.profile_path, ec);
    if (ec) {
        status.error = ec.message();
        status.last_win32_error = GetLastError();
        finish_status(status, start_ms, "create_profile_dir");
        log_prepare_exit(status, "fail");
        return status;
    }
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile create_profile_dir done elapsed_ms=%llu",
        static_cast<unsigned long long>(elapsed_since(start_ms)));

    status.last_operation = "export_public_ca_files";
    public_ca_export_t exported = export_public_ca_files(ca);
    status.ca_exported = exported.ok;
    status.ca_pem_path = exported.pem_path;
    status.ca_der_path = exported.der_path;
    if (!exported.ok) {
        status.error = exported.error;
        status.last_win32_error = GetLastError();
        finish_status(status, start_ms, "export_public_ca_files");
        log_prepare_exit(status, "fail");
        return status;
    }
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile export_ca ok pem=%s der=%s elapsed_ms=%llu",
        status.ca_pem_path.u8string().c_str(),
        status.ca_der_path.u8string().c_str(),
        static_cast<unsigned long long>(elapsed_since(start_ms)));

    std::filesystem::path policy_dir = status.profile_path / L"distribution";
    status.policies_path = policy_dir / L"policies.json";
    std::string error;
    status.last_operation = "write_user_js";
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile write_user_js begin path=%s elapsed_ms=%llu",
        status.user_js_path.u8string().c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
    if (!write_text_if_changed(status.user_js_path, user_js_text(proxy_host, proxy_port), error)) {
        status.error = error;
        status.last_win32_error = GetLastError();
        finish_status(status, start_ms, "write_user_js");
        log_prepare_exit(status, "fail");
        return status;
    }
    json policy = policies_json(status.ca_pem_path, status.ca_der_path);
    status.last_operation = "write_policies";
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile write_policies begin path=%s elapsed_ms=%llu",
        status.policies_path.u8string().c_str(), static_cast<unsigned long long>(elapsed_since(start_ms)));
    if (!write_text_if_changed(status.policies_path, policy.dump(2), error)) {
        status.error = error;
        status.last_win32_error = GetLastError();
        finish_status(status, start_ms, "write_policies");
        log_prepare_exit(status, "fail");
        return status;
    }
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile profile_files_written elapsed_ms=%llu",
        static_cast<unsigned long long>(elapsed_since(start_ms)));

    status.last_operation = "detect_firefox_path";
    status.firefox_detected = detect_firefox_path(status.firefox_path);
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile firefox_detected=%d path=%s elapsed_ms=%llu",
        status.firefox_detected ? 1 : 0,
        status.firefox_path.c_str(),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    std::ostringstream launch;
    if (status.firefox_detected) {
        launch << '"' << status.firefox_path << "\" --no-remote --profile \"" << status.profile_path.u8string() << "\"";
    } else {
        launch << "firefox.exe --no-remote --profile \"" << status.profile_path.u8string() << "\"";
    }
    status.launch_arguments = launch.str();
    status.enterprise_roots_enabled = true;
    status.policy_install_declared = true;
    status.proxy_configured = true;
    status.http3_disabled = true;
    status.last_operation = "check_ca_files_nonempty";
    status.ca_files_nonempty = file_nonempty(status.ca_pem_path) && file_nonempty(status.ca_der_path);
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile trust_check begin ca_nonempty=%d timeout_ms=%u elapsed_ms=%llu",
        status.ca_files_nonempty ? 1 : 0,
        static_cast<unsigned>(kTrustCheckTimeoutMs),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    status.last_operation = "current_user_ca_trust";
    bounded_value_t<bool> trust = query_current_user_ca_trust_bounded(ca, kTrustCheckTimeoutMs);
    bool trust_check_timed_out = false;
    bool trust_check_threw = false;
    std::string trust_check_exception;
    if (trust.timed_out) {
        trust_check_timed_out = true;
        status.last_win32_error = trust.win32_error;
        status.notes.push_back("Current-user CA trust verification exceeded the bounded Test Lab budget");
    } else if (trust.threw) {
        trust_check_threw = true;
        trust_check_exception = trust.exception;
        status.last_win32_error = trust.win32_error;
        status.notes.push_back(trust.exception);
    } else {
        status.current_user_ca_trusted = trust.value;
        status.last_win32_error = trust.win32_error;
    }
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile trust_check end trusted=%d timed_out=%d threw=%d gle=%lu worker_elapsed_ms=%llu elapsed_ms=%llu",
        status.current_user_ca_trusted ? 1 : 0,
        trust.timed_out ? 1 : 0,
        trust.threw ? 1 : 0,
        static_cast<unsigned long>(trust.win32_error),
        static_cast<unsigned long long>(trust.elapsed_ms),
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    status.runtime_validation_performed = false;
    status.runtime_validation_valid = false;
    status.last_operation = "validate_profile_files";
    const bool user_js_valid = user_js_matches(status.user_js_path, proxy_host, proxy_port);
    const bool policies_valid = policies_declare_ca_install(status.policies_path, status.ca_pem_path, status.ca_der_path);
    const bool ca_files_match = current_ca_files_match(ca, status.ca_pem_path, status.ca_der_path);
    status.profile_files_valid = status.ca_files_nonempty &&
        user_js_valid &&
        policies_valid &&
        ca_files_match;
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile validation state ca_nonempty=%d user_js=%d policies=%d ca_match=%d proxy=%d http3=%d elapsed_ms=%llu",
        status.ca_files_nonempty ? 1 : 0,
        user_js_valid ? 1 : 0,
        policies_valid ? 1 : 0,
        ca_files_match ? 1 : 0,
        status.proxy_configured ? 1 : 0,
        status.http3_disabled ? 1 : 0,
        static_cast<unsigned long long>(elapsed_since(start_ms)));
    if (!status.profile_files_valid) {
        status.error = "profile_validation_failed";
        finish_status(status, start_ms, "validate_profile_files");
        log_prepare_exit(status, "fail");
        return status;
    }
    status.trust_readiness_verified = status.current_user_ca_trusted ||
        (status.profile_files_valid && status.policy_install_declared && ca_files_match);
    if (!status.trust_readiness_verified) {
        if (trust_check_timed_out) {
            status.timed_out = true;
            status.error = "current_user_ca_trust_timeout";
        } else if (trust_check_threw) {
            status.error = "current_user_ca_trust_exception";
            if (!trust_check_exception.empty())
                status.notes.push_back(trust_check_exception);
        } else {
            status.error = "current_user_ca_not_trusted";
        }
        finish_status(status, start_ms, "current_user_ca_trust");
        log_prepare_exit(status, "dependency_boundary");
        return status;
    }
    if (!status.current_user_ca_trusted)
        status.notes.push_back("Dedicated Firefox profile CA policy and profile files verify browser trust readiness without requiring a global Windows trust prompt");
    status.prepared = true;
    status.ok = true;
    status.notes.push_back("Firefox profile user.js enables current-user enterprise roots and proxy routing");
    status.notes.push_back("Policy artifact declares public AiDA CA install without modifying the Firefox install directory");
    status.notes.push_back("HTTP/3 is disabled in the dedicated profile to keep traffic on the configured proxy path");
    status.notes.push_back("Runtime browser trust validation is not performed during profile preparation");
    finish_status(status, start_ms, "complete");
    log_prepare_exit(status, "success");
    diag::log_tagged_fmt("cert_profile_fx", "prepare_firefox_profile success launch=%s", status.launch_arguments.c_str());
    return status;
}

firefox_profile_status_t prepare_firefox_profile(const cert_generator::root_ca_t& ca,
                                                 const std::string& proxy_host,
                                                 uint16_t proxy_port) {
    const uint64_t start_ms = tick_ms();
    firefox_profile_status_t timeout_status;
    timeout_status.timeout_ms = kPrepareTimeoutMs;
    timeout_status.last_operation = "prepare_firefox_profile";
    timeout_status.proxy_endpoint = proxy_host + ":" + std::to_string(static_cast<unsigned>(proxy_port));
    cert_generator::root_ca_t ca_copy = duplicate_root_ca_for_worker(ca, &timeout_status, "prepare_root_ca_duplicate");
    if (!ca_copy.valid) {
        timeout_status.last_win32_error = ERROR_INVALID_DATA;
        finish_status(timeout_status, start_ms, "prepare_root_ca_duplicate");
        log_prepare_exit(timeout_status, "fail");
        return timeout_status;
    }
    auto result = run_bounded_value<firefox_profile_status_t>("cert_profile_fx", "prepare_firefox_profile", kPrepareTimeoutMs,
        [ca_copy = std::move(ca_copy), proxy_host, proxy_port]() mutable {
            return prepare_firefox_profile_impl(ca_copy, proxy_host, proxy_port);
        });
    if (result.timed_out) {
        timeout_status.timed_out = true;
        timeout_status.error = "prepare_firefox_profile_timeout";
        timeout_status.last_win32_error = result.win32_error;
        finish_status(timeout_status, start_ms, "prepare_firefox_profile");
        timeout_status.notes.push_back("Firefox profile preparation exceeded the bounded Test Lab budget");
        log_prepare_exit(timeout_status, "timeout");
        return timeout_status;
    }
    if (result.threw) {
        timeout_status.error = "prepare_firefox_profile_exception";
        timeout_status.last_win32_error = result.win32_error;
        timeout_status.notes.push_back(result.exception);
        finish_status(timeout_status, start_ms, "prepare_firefox_profile");
        log_prepare_exit(timeout_status, "exception");
        return timeout_status;
    }
    result.value.timeout_ms = kPrepareTimeoutMs;
    result.value.elapsed_ms = result.elapsed_ms;
    if (result.value.last_win32_error == 0) result.value.last_win32_error = result.win32_error;
    log_prepare_exit(result.value, "return");
    return result.value;
}

firefox_profile_status_t inspect_firefox_profile() {
    const uint64_t start_ms = tick_ms();
    firefox_profile_status_t status;
    status.timeout_ms = kTrustCheckTimeoutMs;
    status.last_operation = "inspect_entry";
    status.profile_path = firefox_profile_root();
    status.user_js_path = status.profile_path / L"user.js";
    status.policies_path = status.profile_path / L"distribution" / L"policies.json";
    status.ca_pem_path = ca_export_root() / L"aida_root_ca.pem";
    status.ca_der_path = ca_export_root() / L"aida_root_ca.der";
    diag::log_tagged_fmt("cert_profile_fx", "inspect_firefox_profile entry profile=%s",
        status.profile_path.u8string().c_str());
    status.firefox_detected = detect_firefox_path(status.firefox_path);
    status.ca_files_nonempty = file_nonempty(status.ca_pem_path) && file_nonempty(status.ca_der_path);
    status.ca_exported = status.ca_files_nonempty;

    std::string user_js;
    if (read_text_file(status.user_js_path, user_js)) {
        status.enterprise_roots_enabled = text_has(user_js, "security.enterprise_roots.enabled\", true");
        status.proxy_configured = text_has(user_js, "network.proxy.type\", 1") &&
            text_has(user_js, "network.proxy.http") &&
            text_has(user_js, "network.proxy.ssl");
        status.http3_disabled = text_has(user_js, "network.http.http3.enabled\", false");
    }

    status.policy_install_declared = policies_declare_ca_install(status.policies_path, status.ca_pem_path, status.ca_der_path);
    bool ca_matches_current = false;
    bool trust_check_timed_out = false;
    bool trust_check_threw = false;
    std::string trust_check_exception;
    if (cert_generator::is_ready()) {
        const auto& ca = cert_generator::get_root_ca();
        status.last_operation = "inspect_current_ca_files_match";
        ca_matches_current = current_ca_files_match(ca, status.ca_pem_path, status.ca_der_path);
        status.last_operation = "inspect_current_user_ca_trust";
        bounded_value_t<bool> trust = query_current_user_ca_trust_bounded(ca, kTrustCheckTimeoutMs);
        if (trust.timed_out) {
            trust_check_timed_out = true;
            status.last_win32_error = trust.win32_error;
            status.notes.push_back("Current-user CA trust verification exceeded the bounded inspection budget");
        } else if (trust.threw) {
            trust_check_threw = true;
            trust_check_exception = trust.exception;
            status.last_win32_error = trust.win32_error;
            status.notes.push_back(trust.exception);
        } else {
            status.current_user_ca_trusted = trust.value;
            status.last_win32_error = trust.win32_error;
        }
    } else {
        status.notes.push_back("Current AiDA CA is not loaded locally; profile trust readiness is unverifiable");
    }
    status.runtime_validation_performed = false;
    status.runtime_validation_valid = false;
    status.profile_files_valid = status.ca_files_nonempty &&
        status.enterprise_roots_enabled &&
        status.proxy_configured &&
        status.http3_disabled &&
        status.policy_install_declared &&
        ca_matches_current;
    status.trust_readiness_verified = status.current_user_ca_trusted ||
        (status.profile_files_valid && status.policy_install_declared && ca_matches_current);
    status.prepared = std::filesystem::exists(status.profile_path) && status.profile_files_valid && status.trust_readiness_verified;
    if (!status.prepared) {
        if (trust_check_timed_out) {
            status.timed_out = true;
            status.error = "current_user_ca_trust_timeout";
        } else if (trust_check_threw) {
            status.error = "current_user_ca_trust_exception";
            if (!trust_check_exception.empty())
                status.notes.push_back(trust_check_exception);
        } else {
            status.error = status.profile_files_valid ? "firefox_profile_trust_unverified" : "firefox_profile_not_prepared";
        }
    } else if (!status.current_user_ca_trusted) {
        status.notes.push_back("Dedicated Firefox profile CA policy and profile files verify browser trust readiness without requiring a global Windows trust prompt");
    }
    if (status.firefox_detected) {
        std::ostringstream launch;
        launch << '"' << status.firefox_path << "\" --no-remote --profile \"" << status.profile_path.u8string() << "\"";
        status.launch_arguments = launch.str();
    } else {
        std::ostringstream launch;
        launch << "firefox.exe --no-remote --profile \"" << status.profile_path.u8string() << "\"";
        status.launch_arguments = launch.str();
    }
    status.ok = status.prepared;
    finish_status(status, start_ms, "inspect_complete");
    log_prepare_exit(status, "inspect");
    return status;
}

firefox_profile_status_t launch_firefox_profile(const firefox_profile_status_t& prepared_status) {
    firefox_profile_status_t status = prepared_status;
    if (!status.prepared || !status.profile_files_valid) {
        status.ok = false;
        status.error = "firefox_profile_not_prepared";
        return status;
    }
    if (!status.firefox_detected && !detect_firefox_path(status.firefox_path)) {
        status.ok = false;
        status.error = "firefox_not_detected";
        return status;
    }

    std::ostringstream launch;
    launch << '"' << status.firefox_path << "\" --no-remote --profile \"" << status.profile_path.u8string() << "\"";
    status.launch_arguments = launch.str();

    std::wstring command = utf8_to_wide(status.launch_arguments);
    if (command.empty()) {
        status.ok = false;
        status.error = "launch_command_encoding_failed";
        return status;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    BOOL created = CreateProcessW(
        nullptr,
        mutable_command.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_PROCESS_GROUP,
        nullptr,
        nullptr,
        &si,
        &pi);
    if (!created) {
        status.ok = false;
        status.error = "create_process_failed_" + std::to_string(GetLastError());
        return status;
    }

    status.launched = true;
    status.launched_pid = static_cast<uint32_t>(pi.dwProcessId);
    status.post_launch_profile_validated = false;
    uint32_t launched_pid = status.launched_pid;
    DWORD exit_code = 0;
    bool process_alive = GetExitCodeProcess(pi.hProcess, &exit_code) && exit_code == STILL_ACTIVE;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    firefox_profile_status_t checked = inspect_firefox_profile();
    status.profile_files_valid = checked.profile_files_valid;
    status.current_user_ca_trusted = checked.current_user_ca_trusted;
    status.trust_readiness_verified = checked.trust_readiness_verified;
    status.timed_out = checked.timed_out;
    status.timeout_ms = checked.timeout_ms;
    status.last_win32_error = checked.last_win32_error;
    status.elapsed_ms = checked.elapsed_ms;
    status.last_operation = checked.last_operation;
    status.runtime_validation_performed = false;
    status.runtime_validation_valid = false;
    status.post_launch_profile_validated = process_alive && status.profile_files_valid && status.trust_readiness_verified;
    status.launched = true;
    status.launched_pid = launched_pid;
    status.ok = status.post_launch_profile_validated;
    if (!status.ok) status.error = "post_launch_profile_validation_failed";
    status.notes = checked.notes;
    status.notes.push_back("Firefox process was launched; network browser trust validation was not performed locally");
    if (!process_alive) status.notes.push_back("Firefox process exited before post-launch profile validation completed");
    return status;
}

}
}
