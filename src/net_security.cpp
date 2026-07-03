#include "net_security.hpp"

#ifdef __NT__
#include "standalone/src/helpers/diag_log.hpp"
#include "standalone/src/core/infra/work_queue.hpp"
#include "standalone/src/core/runtime/standalone_driver.hpp"
#include "../driver/comm.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <wincrypt.h>
#include <shlobj.h>
#include <bcrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

extern std::unique_ptr<voyager::device_t> device;

using json = nlohmann::json;


static std::string bytes_to_hex(const std::uint8_t* data, std::size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (std::size_t i = 0; i < len; i++) {
        char hex[3];
        std::snprintf(hex, sizeof(hex), "%02x", data[i]);
        result += hex;
    }
    return result;
}

static std::string bytes_to_hex_upper(const std::uint8_t* data, std::size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (std::size_t i = 0; i < len; i++) {
        char hex[3];
        std::snprintf(hex, sizeof(hex), "%02X", data[i]);
        result += hex;
    }
    return result;
}

static std::vector<std::uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    std::string clean;
    for (char c : hex) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            clean += c;
    }
    out.reserve(clean.size() / 2);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return 0;
        };
        out.push_back(static_cast<std::uint8_t>((nib(clean[i]) << 4) | nib(clean[i + 1])));
    }
    return out;
}

static std::uint64_t get_timestamp_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

static bool valid_cert_store_name_text(const std::string& name) {
    if (name.empty() || name.size() > 64)
        return false;
    for (unsigned char c : name) {
        const bool ok = (c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') ||
                        c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

static std::wstring widen_ascii_text(const std::string& s) {
    std::wstring out;
    out.reserve(s.size());
    for (unsigned char c : s)
        out.push_back(static_cast<wchar_t>(c));
    return out;
}

static std::wstring quote_windows_arg_text(const std::wstring& arg) {
    std::wstring out;
    out.push_back(L'"');
    size_t slash_count = 0;
    for (wchar_t ch : arg) {
        if (ch == L'\\') {
            ++slash_count;
            continue;
        }
        if (ch == L'"') {
            out.append(slash_count * 2 + 1, L'\\');
            out.push_back(ch);
            slash_count = 0;
            continue;
        }
        if (slash_count != 0) {
            out.append(slash_count, L'\\');
            slash_count = 0;
        }
        out.push_back(ch);
    }
    if (slash_count != 0)
        out.append(slash_count * 2, L'\\');
    out.push_back(L'"');
    return out;
}

static std::wstring certutil_exe_path_text() {
    wchar_t sys_dir[MAX_PATH] = {};
    UINT len = GetSystemDirectoryW(sys_dir, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        std::wstring path(sys_dir, sys_dir + len);
        if (!path.empty() && path.back() != L'\\')
            path.push_back(L'\\');
        path += L"certutil.exe";
        return path;
    }
    return L"certutil.exe";
}

static bool write_temp_cert_der_file_text(const std::uint8_t* data, std::size_t len, std::wstring& out_path, DWORD& gle) {
    out_path.clear();
    gle = ERROR_SUCCESS;
    if (!data || len == 0 || len > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())) {
        gle = ERROR_INVALID_PARAMETER;
        return false;
    }
    wchar_t temp_dir[MAX_PATH] = {};
    DWORD dir_len = GetTempPathW(MAX_PATH, temp_dir);
    if (dir_len == 0 || dir_len >= MAX_PATH) {
        gle = GetLastError();
        return false;
    }
    wchar_t temp_file[MAX_PATH] = {};
    if (GetTempFileNameW(temp_dir, L"AID", 0, temp_file) == 0) {
        gle = GetLastError();
        return false;
    }
    HANDLE h = CreateFileW(temp_file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        gle = GetLastError();
        DeleteFileW(temp_file);
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, static_cast<DWORD>(len), &written, nullptr);
    DWORD write_gle = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    if (!ok || written != static_cast<DWORD>(len)) {
        gle = ok ? ERROR_WRITE_FAULT : write_gle;
        DeleteFileW(temp_file);
        return false;
    }
    out_path = temp_file;
    return true;
}

static bool run_certutil_args_text(const std::vector<std::wstring>& args, DWORD timeout_ms,
                                   DWORD& exit_code, DWORD& gle, DWORD& elapsed_ms) {
    exit_code = 0xFFFFFFFFu;
    gle = ERROR_SUCCESS;
    elapsed_ms = 0;
    std::wstring cmd = quote_windows_arg_text(certutil_exe_path_text());
    for (const auto& arg : args) {
        cmd.push_back(L' ');
        cmd += quote_windows_arg_text(arg);
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    DWORD start = GetTickCount();
    std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back(L'\0');
    BOOL created = CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi);
    if (!created) {
        gle = GetLastError();
        elapsed_ms = GetTickCount() - start;
        return false;
    }
    DWORD wait = WaitForSingleObject(pi.hProcess, timeout_ms);
    elapsed_ms = GetTickCount() - start;
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(pi.hProcess, 2000);
        gle = ERROR_TIMEOUT;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    if (wait != WAIT_OBJECT_0) {
        gle = GetLastError();
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
        gle = GetLastError();
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exit_code == 0;
}

static bool run_certutil_store_add_text(bool system_wide, const std::string& store_name, const std::wstring& cert_path,
                                        DWORD& exit_code, DWORD& gle, DWORD& elapsed_ms) {
    std::vector<std::wstring> args;
    args.push_back(L"-f");
    if (!system_wide)
        args.push_back(L"-user");
    args.push_back(L"-addstore");
    args.push_back(widen_ascii_text(store_name));
    args.push_back(cert_path);
    return run_certutil_args_text(args, 15000, exit_code, gle, elapsed_ms);
}

static bool run_certutil_store_delete_text(bool system_wide, const std::string& store_name, const std::string& thumbprint,
                                           DWORD& exit_code, DWORD& gle, DWORD& elapsed_ms) {
    std::vector<std::wstring> args;
    args.push_back(L"-f");
    if (!system_wide)
        args.push_back(L"-user");
    args.push_back(L"-delstore");
    args.push_back(widen_ascii_text(store_name));
    args.push_back(widen_ascii_text(thumbprint));
    return run_certutil_args_text(args, 15000, exit_code, gle, elapsed_ms);
}

static bool run_certutil_store_probe_text(bool system_wide, const std::string& store_name, const std::string& thumbprint,
                                          DWORD& exit_code, DWORD& gle, DWORD& elapsed_ms) {
    std::vector<std::wstring> args;
    if (!system_wide)
        args.push_back(L"-user");
    args.push_back(L"-store");
    args.push_back(widen_ascii_text(store_name));
    args.push_back(widen_ascii_text(thumbprint));
    return run_certutil_args_text(args, 10000, exit_code, gle, elapsed_ms);
}

static bool is_plausible_pointer(std::uint64_t val) {
    return val > 0x10000 && val < 0x00007FFFFFFFFFFF;
}

static bool all_zero(const std::uint8_t* data, std::size_t len) {
    for (std::size_t i = 0; i < len; i++)
        if (data[i] != 0) return false;
    return true;
}

static bool looks_like_random(const std::uint8_t* data, std::size_t len) {
    if (len < 16) return false;
    if (all_zero(data, len)) return false;

    std::uint32_t histogram[256] = {};
    for (std::size_t i = 0; i < len; i++)
        histogram[data[i]]++;
    std::uint32_t unique_count = 0;
    std::uint32_t max_freq = 0;
    for (auto& h : histogram) {
        if (h > 0) unique_count++;
        if (h > max_freq) max_freq = h;
    }


    if (unique_count < (len / 2)) return false;


    if (max_freq > len / 4 + 1) return false;


    std::size_t seq_run = 0;
    for (std::size_t i = 1; i < len; i++) {
        int diff = static_cast<int>(data[i]) - static_cast<int>(data[i - 1]);
        if (diff == 1 || diff == -1) {
            seq_run++;
            if (seq_run >= len / 3) return false;
        } else {
            seq_run = 0;
        }
    }

    return true;
}

static bool netsec_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static void netsec_skip_ascii_space(const std::vector<std::uint8_t>& buf, std::size_t actual, std::size_t& pos) {
    while (pos < actual && (buf[pos] == ' ' || buf[pos] == '\t'))
        ++pos;
}

static bool netsec_read_hex_token(const std::vector<std::uint8_t>& buf, std::size_t actual,
                                  std::size_t& pos, std::size_t min_chars,
                                  std::size_t max_chars, std::string& out) {
    out.clear();
    while (pos < actual && out.size() < max_chars) {
        const char c = static_cast<char>(buf[pos]);
        if (!netsec_hex_char(c))
            break;
        out.push_back(c);
        ++pos;
    }
    return out.size() >= min_chars;
}

static bool netsec_scan_should_stop(const tls_key_scan_config_t& config,
                                    key_scan_diagnostics_t& diag,
                                    ULONGLONG start_ms) {
    if (config.cancel_flag && !config.cancel_flag->load(std::memory_order_acquire)) {
        diag.cancelled = true;
        if (diag.early_exit_reason.empty())
            diag.early_exit_reason = "cancelled";
        return true;
    }
    if (config.timeout_ms != 0 && GetTickCount64() - start_ms >= config.timeout_ms) {
        diag.deadline_expired = true;
        diag.truncated = true;
        if (diag.early_exit_reason.empty())
            diag.early_exit_reason = "deadline";
        return true;
    }
    if (config.max_regions != 0 && diag.regions_seen >= config.max_regions) {
        diag.truncated = true;
        if (diag.early_exit_reason.empty())
            diag.early_exit_reason = "max_regions";
        return true;
    }
    if (config.max_read_attempts != 0 && diag.read_attempts >= config.max_read_attempts) {
        diag.truncated = true;
        if (diag.early_exit_reason.empty())
            diag.early_exit_reason = "max_read_attempts";
        return true;
    }
    if (config.max_read_bytes != 0 && diag.read_bytes >= config.max_read_bytes) {
        diag.truncated = true;
        if (diag.early_exit_reason.empty())
            diag.early_exit_reason = "max_read_bytes";
        return true;
    }
    return false;
}

static void netsec_finish_diag(key_scan_diagnostics_t& diag, ULONGLONG start_ms, std::uint64_t keys_found) {
    diag.elapsed_ms = GetTickCount64() - start_ms;
    diag.keys_found = keys_found;
    if (diag.early_exit_reason.empty())
        diag.early_exit_reason = "complete";
}

static std::vector<tls_session_key_t> netsec_scan_tls_keylog_range(std::uint32_t pid,
                                                                    const tls_key_scan_config_t& config,
                                                                    key_scan_diagnostics_t& diag,
                                                                    ULONGLONG start_ms) {
    std::vector<tls_session_key_t> keys;
    if (!device || !device->is_connected() || config.hint_address == 0 || config.hint_size < 32)
        return keys;

    const std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    diag.hint_used = true;
    ++diag.regions_seen;
    ++diag.regions_committed;
    constexpr std::size_t CHUNK = 0x10000;
    constexpr std::size_t OVERLAP = 256;
    const std::uint64_t limit = config.max_read_bytes != 0
        ? std::min<std::uint64_t>(config.hint_size, config.max_read_bytes)
        : static_cast<std::uint64_t>(config.hint_size);
    std::vector<std::uint8_t> buf(CHUNK);
    static const char* labels[] = {
        "CLIENT_RANDOM ",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET ",
        "CLIENT_TRAFFIC_SECRET_0 ",
        "SERVER_TRAFFIC_SECRET_0 ",
        "EXPORTER_SECRET ",
    };

    for (std::uint64_t off = 0; off < limit && !netsec_scan_should_stop(config, diag, start_ms); off += CHUNK - OVERLAP) {
        const std::size_t to_read = static_cast<std::size_t>(std::min<std::uint64_t>(CHUNK, limit - off));
        if (to_read < 32)
            break;
        std::memset(buf.data(), 0, buf.size());
        ++diag.read_attempts;
        const std::size_t actual = device->read_raw(config.hint_address + off, buf.data(), to_read);
        diag.read_bytes += actual;
        if (actual < 32) {
            ++diag.read_short;
            if (diag.first_short_read_va == 0)
                diag.first_short_read_va = config.hint_address + off;
            continue;
        }

        for (const char* label : labels) {
            const std::size_t label_len = std::strlen(label);
            for (std::size_t i = 0; i + label_len + 64 + 1 + 64 < actual; ++i) {
                if (keys.size() >= config.max_results) {
                    diag.early_exit_reason = "max_results";
                    goto tls_range_done;
                }
                if (netsec_scan_should_stop(config, diag, start_ms))
                    goto tls_range_done;
                bool match = true;
                for (std::size_t j = 0; j < label_len; ++j) {
                    if (buf[i + j] != static_cast<std::uint8_t>(label[j])) {
                        match = false;
                        break;
                    }
                }
                if (!match)
                    continue;
                ++diag.candidate_hits;
                if (diag.first_hit_elapsed_ms == 0)
                    diag.first_hit_elapsed_ms = GetTickCount64() - start_ms;
                std::size_t pos = i + label_len;
                std::string cr_hex;
                if (!netsec_read_hex_token(buf, actual, pos, 64, 64, cr_hex)) {
                    ++diag.reject_count;
                    continue;
                }
                netsec_skip_ascii_space(buf, actual, pos);
                std::string secret_hex;
                if (!netsec_read_hex_token(buf, actual, pos, 64, 128, secret_hex)) {
                    ++diag.reject_count;
                    continue;
                }
                tls_session_key_t key;
                const bool client_random_label = std::strcmp(label, "CLIENT_RANDOM ") == 0;
                key.label = client_random_label ? "CLIENT_RANDOM" : std::string(label, label_len - 1);
                key.client_random = hex_to_bytes(cr_hex);
                key.secret = hex_to_bytes(secret_hex);
                key.tls_version = client_random_label ? 0x0303 : 0x0304;
                key.timestamp = get_timestamp_ms();
                key.pid = pid;
                key.library = "KeylogHint";
                bool duplicate = false;
                for (const auto& existing : keys) {
                    if (existing.label == key.label && existing.client_random == key.client_random) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                    keys.push_back(std::move(key));
            }
        }
    }

tls_range_done:
    device->set_process_id(saved_pid);
    if (saved_pid != 0)
        device->solve_dtb();
    return keys;
}

static std::vector<quic_key_info_t> netsec_scan_quic_keylog_range(std::uint32_t pid,
                                                                   const tls_key_scan_config_t& config,
                                                                   key_scan_diagnostics_t& diag,
                                                                   ULONGLONG start_ms,
                                                                   bool has_msquic) {
    std::vector<quic_key_info_t> keys;
    if (!device || !device->is_connected() || config.hint_address == 0 || config.hint_size < 32)
        return keys;

    const std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    diag.hint_used = true;
    ++diag.regions_seen;
    ++diag.regions_committed;
    constexpr std::size_t CHUNK = 0x10000;
    constexpr std::size_t OVERLAP = 256;
    const std::uint64_t limit = config.max_read_bytes != 0
        ? std::min<std::uint64_t>(config.hint_size, config.max_read_bytes)
        : static_cast<std::uint64_t>(config.hint_size);
    std::vector<std::uint8_t> buf(CHUNK);
    static const char* quic_labels[] = {
        "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
        "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET ",
        "QUIC_CLIENT_TRAFFIC_SECRET_0 ",
        "QUIC_SERVER_TRAFFIC_SECRET_0 ",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET ",
        "CLIENT_TRAFFIC_SECRET_0 ",
        "SERVER_TRAFFIC_SECRET_0 ",
    };

    for (std::uint64_t off = 0; off < limit && !netsec_scan_should_stop(config, diag, start_ms); off += CHUNK - OVERLAP) {
        const std::size_t to_read = static_cast<std::size_t>(std::min<std::uint64_t>(CHUNK, limit - off));
        if (to_read < 32)
            break;
        std::memset(buf.data(), 0, buf.size());
        ++diag.read_attempts;
        const std::size_t actual = device->read_raw(config.hint_address + off, buf.data(), to_read);
        diag.read_bytes += actual;
        if (actual < 32) {
            ++diag.read_short;
            if (diag.first_short_read_va == 0)
                diag.first_short_read_va = config.hint_address + off;
            continue;
        }

        for (const char* label : quic_labels) {
            const std::size_t label_len = std::strlen(label);
            for (std::size_t i = 0; i + label_len + 64 + 1 + 64 < actual; ++i) {
                if (keys.size() >= config.max_results) {
                    diag.early_exit_reason = "max_results";
                    goto quic_range_done;
                }
                if (netsec_scan_should_stop(config, diag, start_ms))
                    goto quic_range_done;
                bool match = true;
                for (std::size_t j = 0; j < label_len; ++j) {
                    if (buf[i + j] != static_cast<std::uint8_t>(label[j])) {
                        match = false;
                        break;
                    }
                }
                if (!match)
                    continue;
                ++diag.candidate_hits;
                if (diag.first_hit_elapsed_ms == 0)
                    diag.first_hit_elapsed_ms = GetTickCount64() - start_ms;
                std::size_t pos = i + label_len;
                std::string cr_hex;
                if (!netsec_read_hex_token(buf, actual, pos, 64, 64, cr_hex)) {
                    ++diag.reject_count;
                    continue;
                }
                netsec_skip_ascii_space(buf, actual, pos);
                std::string secret_hex;
                if (!netsec_read_hex_token(buf, actual, pos, 64, 128, secret_hex)) {
                    ++diag.reject_count;
                    continue;
                }
                quic_key_info_t key;
                key.label = std::string(label, label_len - 1);
                key.client_random = hex_to_bytes(cr_hex);
                key.secret = hex_to_bytes(secret_hex);
                key.pid = pid;
                key.library = has_msquic ? "msquic" : "BoringSSL-QUIC";
                bool duplicate = false;
                for (const auto& existing : keys) {
                    if (existing.label == key.label && existing.client_random == key.client_random) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                    keys.push_back(std::move(key));
            }
        }
    }

quic_range_done:
    device->set_process_id(saved_pid);
    if (saved_pid != 0)
        device->solve_dtb();
    return keys;
}

static std::vector<dtls_key_info_t> netsec_scan_dtls_range(std::uint32_t pid,
                                                           const tls_key_scan_config_t& config,
                                                           key_scan_diagnostics_t& diag,
                                                           ULONGLONG start_ms) {
    std::vector<dtls_key_info_t> keys;
    if (!device || !device->is_connected() || config.hint_address == 0 || config.hint_size < 96)
        return keys;

    const std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    diag.hint_used = true;
    ++diag.regions_seen;
    ++diag.regions_committed;
    std::uint64_t hint_limit = config.hint_size;
    if (config.max_read_bytes != 0)
        hint_limit = std::min<std::uint64_t>(hint_limit, config.max_read_bytes);
    const std::size_t to_read = static_cast<std::size_t>(std::min<std::uint64_t>(hint_limit, 0x100000));
    std::vector<std::uint8_t> buf(to_read);
    ++diag.read_attempts;
    const std::size_t actual = device->read_raw(config.hint_address, buf.data(), to_read);
    diag.read_bytes += actual;
    if (actual < 96) {
        ++diag.read_short;
        diag.first_short_read_va = config.hint_address;
        device->set_process_id(saved_pid);
        if (saved_pid != 0)
            device->solve_dtb();
        return keys;
    }

    for (std::size_t i = 0; i + 2 <= actual && !netsec_scan_should_stop(config, diag, start_ms); i += 2) {
        const std::uint16_t ver = (static_cast<std::uint16_t>(buf[i]) << 8) | buf[i + 1];
        if (ver != 0xFEFF && ver != 0xFEFD)
            continue;
        ++diag.candidate_hits;
        if (diag.first_hit_elapsed_ms == 0)
            diag.first_hit_elapsed_ms = GetTickCount64() - start_ms;
        for (int search_off = -128; search_off < 128; search_off += 8) {
            const std::int64_t cr_pos = static_cast<std::int64_t>(i) + search_off;
            if (cr_pos < 0 || cr_pos + 80 > static_cast<std::int64_t>(actual))
                continue;
            const std::uint8_t* cr = buf.data() + cr_pos;
            const std::uint8_t* ms = buf.data() + cr_pos + 32;
            if (!looks_like_random(cr, 32) || !looks_like_random(ms, 48)) {
                ++diag.reject_count;
                continue;
            }
            dtls_key_info_t key;
            key.dtls_version = ver;
            key.client_random.assign(cr, cr + 32);
            key.master_secret.assign(ms, ms + 48);
            key.pid = pid;
            key.library = "DTLS";
            keys.push_back(std::move(key));
            if (keys.size() >= config.max_results) {
                diag.early_exit_reason = "max_results";
                goto dtls_range_done;
            }
            break;
        }
    }

dtls_range_done:
    device->set_process_id(saved_pid);
    if (saved_pid != 0)
        device->solve_dtb();
    return keys;
}


static bool hmac_sha256(const std::uint8_t* key, std::size_t key_len,
                        const std::uint8_t* data, std::size_t data_len,
                        std::uint8_t out[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hash_obj_size = 0, cb_data = 0;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return false;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hash_obj_size),
                          sizeof(hash_obj_size), &cb_data, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    std::vector<std::uint8_t> hash_obj(hash_obj_size);
    if (BCryptCreateHash(hAlg, &hHash, hash_obj.data(), hash_obj_size,
                         const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    if (BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0) == 0) {
        if (BCryptFinishHash(hHash, out, 32, 0) == 0)
            ok = true;
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool hkdf_extract(const std::uint8_t* salt, std::size_t salt_len,
                          const std::uint8_t* ikm, std::size_t ikm_len,
                          std::uint8_t prk[32]) {
    if (salt_len == 0) {
        std::uint8_t zero_salt[32] = {};
        return hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    }
    return hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static bool hkdf_expand(const std::uint8_t prk[32],
                         const std::uint8_t* info, std::size_t info_len,
                         std::uint8_t* okm, std::size_t okm_len) {
    std::uint8_t t[32] = {};
    std::size_t t_len = 0;
    std::uint8_t counter = 1;
    std::size_t offset = 0;

    while (offset < okm_len) {
        std::vector<std::uint8_t> input;
        input.reserve(t_len + info_len + 1);
        input.insert(input.end(), t, t + t_len);
        input.insert(input.end(), info, info + info_len);
        input.push_back(counter);

        if (!hmac_sha256(prk, 32, input.data(), input.size(), t))
            return false;

        t_len = 32;
        std::size_t to_copy = std::min(static_cast<std::size_t>(32), okm_len - offset);
        std::memcpy(okm + offset, t, to_copy);
        offset += to_copy;
        counter++;

        if (counter == 0) return false;
    }
    return true;
}

static bool hkdf_expand_label(const std::uint8_t prk[32],
                               const char* label, std::size_t label_len,
                               const std::uint8_t* context, std::size_t context_len,
                               std::uint8_t* okm, std::size_t okm_len) {
    const char* prefix = "tls13 ";
    std::size_t prefix_len = 6;
    std::size_t full_label_len = prefix_len + label_len;

    std::vector<std::uint8_t> hkdf_label;
    hkdf_label.reserve(2 + 1 + full_label_len + 1 + context_len);

    hkdf_label.push_back(static_cast<std::uint8_t>((okm_len >> 8) & 0xFF));
    hkdf_label.push_back(static_cast<std::uint8_t>(okm_len & 0xFF));

    hkdf_label.push_back(static_cast<std::uint8_t>(full_label_len));
    hkdf_label.insert(hkdf_label.end(),
                       reinterpret_cast<const std::uint8_t*>(prefix),
                       reinterpret_cast<const std::uint8_t*>(prefix) + prefix_len);
    hkdf_label.insert(hkdf_label.end(),
                       reinterpret_cast<const std::uint8_t*>(label),
                       reinterpret_cast<const std::uint8_t*>(label) + label_len);

    hkdf_label.push_back(static_cast<std::uint8_t>(context_len));
    if (context_len > 0)
        hkdf_label.insert(hkdf_label.end(), context, context + context_len);

    return hkdf_expand(prk, hkdf_label.data(), hkdf_label.size(), okm, okm_len);
}

static bool aes_ecb_encrypt(const std::uint8_t key[16],
                             const std::uint8_t in[16],
                             std::uint8_t out[16]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return false;

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
                          static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_ECB)), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD key_obj_size = 0, cb_data = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      reinterpret_cast<PUCHAR>(&key_obj_size), sizeof(key_obj_size), &cb_data, 0);

    std::vector<std::uint8_t> key_obj(key_obj_size);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj.data(), key_obj_size,
                                    const_cast<PUCHAR>(key), 16, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    ULONG result_len = 0;
    std::uint8_t input_copy[16];
    std::memcpy(input_copy, in, 16);
    if (BCryptEncrypt(hKey, input_copy, 16, nullptr, nullptr, 0, out, 16, &result_len, 0) == 0)
        ok = (result_len == 16);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}


namespace net_security {

TlsKeyExtractor& TlsKeyExtractor::instance() {
    static TlsKeyExtractor inst;
    return inst;
}

bool TlsKeyExtractor::find_module_in_process(std::uint32_t pid, const char* module_name,
                                               std::uint64_t& base, std::uint32_t& size) {
    if (!device || !device->is_connected()) return false;


    std::uint32_t saved_pid = device->get_process_id();
    std::uint64_t saved_base = device->get_base_address();


    std::uint32_t actual_pid = (pid == 0) ? saved_pid : pid;
    if (actual_pid == 0) return false;

    device->set_process_id(actual_pid);
    device->solve_dtb();


    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || peb.ldr_address == 0) {
        device->set_process_id(saved_pid);
        device->set_base_address(saved_base);
        return false;
    }


    std::uint64_t ldr_data = peb.ldr_address;
    std::uint64_t list_head = ldr_data + 0x20;

    std::uint8_t flink_buf[8] = {};
    if (device->read_raw(list_head, flink_buf, 8) != 8) {
        device->set_process_id(saved_pid);
        device->set_base_address(saved_base);
        return false;
    }
    std::uint64_t current = *reinterpret_cast<std::uint64_t*>(flink_buf);
    std::string target(module_name);
    for (auto& c : target) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    bool found = false;
    for (int i = 0; i < 512 && current != 0 && current != list_head; i++) {


        std::uint64_t entry_start = current - 0x10;

        std::uint8_t entry_buf[0x70] = {};
        if (device->read_raw(entry_start, entry_buf, sizeof(entry_buf)) != sizeof(entry_buf))
            break;

        std::uint64_t dll_base = *reinterpret_cast<std::uint64_t*>(entry_buf + 0x30);
        std::uint32_t image_size = *reinterpret_cast<std::uint32_t*>(entry_buf + 0x40);


        std::uint16_t name_len = *reinterpret_cast<std::uint16_t*>(entry_buf + 0x58);
        std::uint64_t name_ptr = *reinterpret_cast<std::uint64_t*>(entry_buf + 0x60);

        if (name_len > 0 && name_len < 520 && is_plausible_pointer(name_ptr)) {
            std::vector<wchar_t> name_buf(name_len / 2 + 1, 0);
            if (device->read_raw(name_ptr, name_buf.data(), name_len) == name_len) {
                std::string name_narrow;
                for (auto wc : name_buf) {
                    if (wc == 0) break;
                    name_narrow += static_cast<char>(std::tolower(static_cast<unsigned char>(wc & 0xFF)));
                }
                if (name_narrow.find(target) != std::string::npos) {
                    base = dll_base;
                    size = image_size;
                    found = true;
                    break;
                }
            }
        }


        std::uint8_t next_buf[8] = {};
        if (device->read_raw(current, next_buf, 8) != 8) break;
        std::uint64_t next = *reinterpret_cast<std::uint64_t*>(next_buf);
        if (next == current) break;
        current = next;
    }

    device->set_process_id(saved_pid);
    device->set_base_address(saved_base);
    if (saved_pid != 0) device->solve_dtb();
    return found;
}

std::vector<std::uint64_t> TlsKeyExtractor::scan_for_pattern(
    std::uint32_t pid, std::uint64_t start, std::uint64_t size,
    const std::uint8_t* pattern, const std::uint8_t* mask, std::size_t pattern_len) {

    std::vector<std::uint64_t> results;
    if (!device || !device->is_connected() || pattern_len == 0 || size == 0) return results;

    constexpr std::size_t CHUNK = 0x10000;
    std::vector<std::uint8_t> buffer(CHUNK + pattern_len);

    std::uint32_t saved_pid = device->get_process_id();
    if (pid != 0 && pid != saved_pid) {
        device->set_process_id(pid);
        device->solve_dtb();
    }

    for (std::uint64_t offset = 0; offset < size; offset += CHUNK) {
        std::size_t read_size = static_cast<std::size_t>(
            ((offset + CHUNK + pattern_len) > size) ? (size - offset) : (CHUNK + pattern_len));
        if (read_size < pattern_len) break;

        std::memset(buffer.data(), 0, buffer.size());
        std::size_t actual = device->read_raw(start + offset, buffer.data(), read_size);
        if (actual < pattern_len) continue;

        for (std::size_t i = 0; i <= actual - pattern_len; i++) {
            bool match = true;
            for (std::size_t j = 0; j < pattern_len; j++) {
                if (mask && mask[j] == 0) continue;
                if (buffer[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) {
                results.push_back(start + offset + i);
                if (results.size() >= 256) goto done;
            }
        }
    }
done:
    if (pid != 0 && pid != saved_pid) {
        device->set_process_id(saved_pid);
        device->solve_dtb();
    }
    return results;
}

bool TlsKeyExtractor::read_process_memory(std::uint32_t pid, std::uint64_t address, void* buffer, std::size_t size) {
    if (!device || !device->is_connected()) return false;
    std::uint32_t saved_pid = device->get_process_id();
    if (pid != 0 && pid != saved_pid) {
        device->set_process_id(pid);
        device->solve_dtb();
    }
    std::size_t read = device->read_raw(address, buffer, size);
    if (pid != 0 && pid != saved_pid) {
        device->set_process_id(saved_pid);
        device->solve_dtb();
    }
    return read == size;
}

bool TlsKeyExtractor::validate_client_random(const std::uint8_t* data, std::size_t len) {
    return len == 32 && looks_like_random(data, len);
}

bool TlsKeyExtractor::validate_master_secret(const std::uint8_t* data, std::size_t len) {
    return (len == 48 || len == 32 || len == 64) && looks_like_random(data, len);
}


std::vector<tls_session_key_t> TlsKeyExtractor::scan_schannel(std::uint32_t pid) {
    std::vector<tls_session_key_t> keys;
    if (!device || !device->is_connected()) return keys;

    std::uint64_t schannel_base = 0;
    std::uint32_t schannel_size = 0;


    if (!find_module_in_process(pid, "schannel.dll", schannel_base, schannel_size))
        return keys;


    std::uint64_t ncrypt_base = 0;
    std::uint32_t ncrypt_size = 0;
    find_module_in_process(pid, "ncrypt.dll", ncrypt_base, ncrypt_size);


    std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);

    for (const auto& region : regions) {

        if (region.state != 0x1000) continue;
        if (region.size > 0x1000000) continue;
        if (region.size < 80) continue;


        constexpr std::size_t CHUNK = 0x10000;
        std::vector<std::uint8_t> buf(CHUNK);

        for (std::uint64_t off = 0; off < region.size; off += CHUNK - 80) {
            std::size_t to_read = static_cast<std::size_t>(
                std::min(static_cast<std::uint64_t>(CHUNK), region.size - off));
            if (to_read < 80) break;

            std::memset(buf.data(), 0, CHUNK);
            std::size_t actual = device->read_raw(region.base + off, buf.data(), to_read);
            if (actual < 80) continue;


            for (std::size_t i = 0; i + 80 <= actual; i++) {
                const std::uint8_t* candidate_cr = buf.data() + i;
                if (!looks_like_random(candidate_cr, 32)) continue;


                for (std::size_t secret_offset : {32ULL, 40ULL, 48ULL}) {
                    if (i + secret_offset + 48 > actual) break;
                    const std::uint8_t* candidate_ms = buf.data() + i + secret_offset;
                    if (!looks_like_random(candidate_ms, 48)) continue;


                    tls_session_key_t key;
                    key.label = "CLIENT_RANDOM";
                    key.client_random.assign(candidate_cr, candidate_cr + 32);
                    key.secret.assign(candidate_ms, candidate_ms + 48);
                    key.tls_version = 0x0303;
                    key.timestamp = get_timestamp_ms();
                    key.pid = pid;
                    key.library = "SChannel";


                    std::string cr_hex = bytes_to_hex(candidate_cr, 32);
                    if (_seen_keys.find(cr_hex) == _seen_keys.end()) {
                        _seen_keys[cr_hex] = key;
                        keys.push_back(key);
                    }

                    i += secret_offset + 48 - 1;
                    break;
                }

                if (keys.size() >= 64) goto schannel_done;
            }
        }
    }
schannel_done:
    device->set_process_id(saved_pid);
    if (saved_pid != 0) device->solve_dtb();
    return keys;
}


std::vector<tls_session_key_t> TlsKeyExtractor::scan_openssl(std::uint32_t pid) {
    std::vector<tls_session_key_t> keys;
    if (!device || !device->is_connected()) return keys;


    std::uint64_t libssl_base = 0, libcrypto_base = 0;
    std::uint32_t libssl_size = 0, libcrypto_size = 0;


    bool has_libssl = find_module_in_process(pid, "libssl", libssl_base, libssl_size) ||
                      find_module_in_process(pid, "ssleay32", libssl_base, libssl_size) ||
                      find_module_in_process(pid, "ssl-3", libssl_base, libssl_size);

    if (!has_libssl) {

        has_libssl = find_module_in_process(pid, "libssl-1_1", libssl_base, libssl_size) ||
                     find_module_in_process(pid, "libssl-3", libssl_base, libssl_size);
    }


    std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);


    const std::uint8_t mk_len_pattern[] = { 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    for (const auto& region : regions) {
        if (region.state != 0x1000) continue;
        if (region.size > 0x1000000 || region.size < 128) continue;

        constexpr std::size_t CHUNK = 0x10000;
        std::vector<std::uint8_t> buf(CHUNK);

        for (std::uint64_t off = 0; off < region.size; off += CHUNK - 128) {
            std::size_t to_read = static_cast<std::size_t>(
                std::min(static_cast<std::uint64_t>(CHUNK), region.size - off));
            if (to_read < 128) break;

            std::memset(buf.data(), 0, CHUNK);
            std::size_t actual = device->read_raw(region.base + off, buf.data(), to_read);
            if (actual < 128) continue;

            for (std::size_t i = 48; i + 56 <= actual; i++) {

                std::uint64_t val64 = *reinterpret_cast<std::uint64_t*>(buf.data() + i);
                if (val64 != 48) continue;


                const std::uint8_t* candidate_ms = buf.data() + i - 48;
                if (!looks_like_random(candidate_ms, 48)) continue;


                bool found_cr = false;
                for (int cr_offset = -256; cr_offset < 0; cr_offset += 8) {
                    std::int64_t cr_pos = static_cast<std::int64_t>(i) - 48 + cr_offset;
                    if (cr_pos < 0 || cr_pos + 32 > static_cast<std::int64_t>(actual)) continue;
                    const std::uint8_t* candidate_cr = buf.data() + cr_pos;
                    if (!looks_like_random(candidate_cr, 32)) continue;

                    tls_session_key_t key;
                    key.label = "CLIENT_RANDOM";
                    key.client_random.assign(candidate_cr, candidate_cr + 32);
                    key.secret.assign(candidate_ms, candidate_ms + 48);
                    key.tls_version = 0x0303;
                    key.timestamp = get_timestamp_ms();
                    key.pid = pid;
                    key.library = "OpenSSL";

                    std::string cr_hex = bytes_to_hex(candidate_cr, 32);
                    if (_seen_keys.find(cr_hex) == _seen_keys.end()) {
                        _seen_keys[cr_hex] = key;
                        keys.push_back(key);
                        found_cr = true;
                        break;
                    }
                }

                if (!found_cr) {

                    tls_session_key_t key;
                    key.label = "RSA";
                    key.secret.assign(candidate_ms, candidate_ms + 48);
                    key.tls_version = 0x0303;
                    key.timestamp = get_timestamp_ms();
                    key.pid = pid;
                    key.library = "OpenSSL";
                    keys.push_back(key);
                }

                if (keys.size() >= 64) goto openssl_done;
            }
        }
    }
openssl_done:
    device->set_process_id(saved_pid);
    if (saved_pid != 0) device->solve_dtb();
    return keys;
}


std::vector<tls_session_key_t> TlsKeyExtractor::scan_nss(std::uint32_t pid) {
    std::vector<tls_session_key_t> keys;
    if (!device || !device->is_connected()) return keys;


    std::uint64_t nss_base = 0;
    std::uint32_t nss_size = 0;

    bool has_nss = find_module_in_process(pid, "nss3.dll", nss_base, nss_size) ||
                   find_module_in_process(pid, "ssl3.dll", nss_base, nss_size);

    if (!has_nss) return keys;


    std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);

    for (const auto& region : regions) {
        if (region.state != 0x1000) continue;
        if (region.size > 0x1000000 || region.size < 80) continue;

        constexpr std::size_t CHUNK = 0x10000;
        std::vector<std::uint8_t> buf(CHUNK);

        for (std::uint64_t off = 0; off < region.size; off += CHUNK - 80) {
            std::size_t to_read = static_cast<std::size_t>(
                std::min(static_cast<std::uint64_t>(CHUNK), region.size - off));
            if (to_read < 80) break;

            std::memset(buf.data(), 0, CHUNK);
            std::size_t actual = device->read_raw(region.base + off, buf.data(), to_read);
            if (actual < 80) continue;


            for (std::size_t i = 0; i + 80 <= actual; i++) {
                const std::uint8_t* candidate_ms = buf.data() + i;
                const std::uint8_t* candidate_cr = buf.data() + i + 48;

                if (!looks_like_random(candidate_ms, 48)) continue;
                if (!looks_like_random(candidate_cr, 32)) continue;

                tls_session_key_t key;
                key.label = "CLIENT_RANDOM";
                key.client_random.assign(candidate_cr, candidate_cr + 32);
                key.secret.assign(candidate_ms, candidate_ms + 48);
                key.tls_version = 0x0303;
                key.timestamp = get_timestamp_ms();
                key.pid = pid;
                key.library = "NSS";

                std::string cr_hex = bytes_to_hex(candidate_cr, 32);
                if (_seen_keys.find(cr_hex) == _seen_keys.end()) {
                    _seen_keys[cr_hex] = key;
                    keys.push_back(key);
                }

                if (keys.size() >= 64) goto nss_done;
                i += 79;
            }
        }
    }
nss_done:
    device->set_process_id(saved_pid);
    if (saved_pid != 0) device->solve_dtb();
    return keys;
}


std::vector<tls_session_key_t> TlsKeyExtractor::scan_boringssl(std::uint32_t pid) {
    std::vector<tls_session_key_t> keys;
    if (!device || !device->is_connected()) return keys;

    std::uint64_t boringssl_base = 0;
    std::uint32_t boringssl_size = 0;
    bool has_boringssl = find_module_in_process(pid, "electron.exe", boringssl_base, boringssl_size) ||
                         find_module_in_process(pid, "libcef.dll", boringssl_base, boringssl_size);

    if (!has_boringssl) return keys;


    std::vector<std::string> keylog_paths;


    {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("SSLKEYLOGFILE", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH)
            keylog_paths.emplace_back(buf, len);
    }


    {
        char profile[MAX_PATH] = {};
        DWORD plen = GetEnvironmentVariableA("USERPROFILE", profile, MAX_PATH);
        if (plen > 0 && plen < MAX_PATH) {
            std::string home(profile, plen);
            const char* suffixes[] = {
                "\\sslkeys.log", "\\sslkeylog.txt", "\\ssl_keylog.txt",
                "\\Downloads\\sslkeylog.txt", "\\Downloads\\sslkeys.log",
                "\\Desktop\\sslkeylog.txt"
            };
            for (const char* suffix : suffixes)
                keylog_paths.push_back(home + suffix);
        }
    }


    for (const auto& kpath : keylog_paths) {
        if (GetFileAttributesA(kpath.c_str()) == INVALID_FILE_ATTRIBUTES) continue;

        auto file_keys = read_keylog_file(kpath);
        for (auto& k : file_keys) {
            k.pid = pid;
            if (k.library.empty()) k.library = "BoringSSL/KeylogFile";
            std::string dedup;
            if (!k.label.empty() && !k.client_random.empty())
                dedup = k.label + ":" + bytes_to_hex(k.client_random.data(), k.client_random.size());
            else if (!k.client_random.empty())
                dedup = bytes_to_hex(k.client_random.data(), k.client_random.size());
            else
                continue;
            if (_seen_keys.find(dedup) == _seen_keys.end()) {
                _seen_keys[dedup] = k;
                keys.push_back(k);
            }
        }
        if (!keys.empty()) return keys;
    }


    {
        std::uint32_t saved_pid = device->get_process_id();
        device->set_process_id(pid);
        device->solve_dtb();

        voyager::device_t::peb_info peb{};
        if (device->read_peb(peb) && peb.ldr_address != 0) {

            std::uint64_t peb_base = 0;


            std::uint64_t peb_estimated = peb.ldr_address - 0x18;
            std::uint8_t pp_buf[8] = {};
            if (device->read_raw(peb_estimated + 0x20, pp_buf, 8) == 8) {
                std::uint64_t proc_params = *reinterpret_cast<std::uint64_t*>(pp_buf);
                if (is_plausible_pointer(proc_params)) {


                    std::uint8_t env_buf[8] = {};
                    std::uint8_t env_size_buf[8] = {};
                    if (device->read_raw(proc_params + 0x80, env_buf, 8) == 8 &&
                        device->read_raw(proc_params + 0x3F0, env_size_buf, 8) == 8) {
                        std::uint64_t env_ptr = *reinterpret_cast<std::uint64_t*>(env_buf);
                        std::uint64_t env_size = *reinterpret_cast<std::uint64_t*>(env_size_buf);
                        if (is_plausible_pointer(env_ptr) && env_size > 0 && env_size < 0x100000) {

                            std::size_t read_size = static_cast<std::size_t>(std::min(env_size, static_cast<std::uint64_t>(0x40000)));
                            std::vector<std::uint8_t> env_data(read_size);
                            std::size_t actual = device->read_raw(env_ptr, env_data.data(), read_size);
                            if (actual >= 32) {

                                const wchar_t* env_str = reinterpret_cast<const wchar_t*>(env_data.data());
                                std::size_t env_wchars = actual / 2;
                                const wchar_t* needle = L"SSLKEYLOGFILE=";
                                std::size_t needle_len = 14;
                                for (std::size_t i = 0; i + needle_len < env_wchars; i++) {
                                    if (env_str[i] == 0 && i > 0) {

                                    }
                                    bool match = true;
                                    for (std::size_t j = 0; j < needle_len; j++) {
                                        wchar_t c = env_str[i + j];
                                        wchar_t n = needle[j];
                                        if (c >= L'a' && c <= L'z') c -= 32;
                                        if (n >= L'a' && n <= L'z') n -= 32;
                                        if (c != n) { match = false; break; }
                                    }
                                    if (!match) continue;


                                    std::string target_keylog;
                                    for (std::size_t j = i + needle_len; j < env_wchars && env_str[j] != 0; j++) {
                                        target_keylog += static_cast<char>(env_str[j] & 0xFF);
                                    }
                                    if (!target_keylog.empty() &&
                                        GetFileAttributesA(target_keylog.c_str()) != INVALID_FILE_ATTRIBUTES) {
                                        auto file_keys = read_keylog_file(target_keylog);
                                        for (auto& k : file_keys) {
                                            k.pid = pid;
                                            if (k.library.empty()) k.library = "BoringSSL/ProcessKeylog";
                                            std::string dedup;
                                            if (!k.label.empty() && !k.client_random.empty())
                                                dedup = k.label + ":" + bytes_to_hex(k.client_random.data(), k.client_random.size());
                                            else if (!k.client_random.empty())
                                                dedup = bytes_to_hex(k.client_random.data(), k.client_random.size());
                                            else
                                                continue;
                                            if (_seen_keys.find(dedup) == _seen_keys.end()) {
                                                _seen_keys[dedup] = k;
                                                keys.push_back(k);
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        device->set_process_id(saved_pid);
        if (saved_pid != 0) device->solve_dtb();
        if (!keys.empty()) return keys;
    }


    return keys;
}


std::vector<tls_session_key_t> TlsKeyExtractor::scan_generic_patterns(std::uint32_t pid) {
    std::vector<tls_session_key_t> keys;
    if (!device || !device->is_connected()) return keys;

    std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);


    const char* keylog_prefix = "CLIENT_RANDOM ";
    const std::uint8_t* pattern = reinterpret_cast<const std::uint8_t*>(keylog_prefix);
    std::size_t pattern_len = 14;

    for (const auto& region : regions) {
        if (region.state != 0x1000) continue;
        if (region.size > 0x2000000 || region.size < 128) continue;

        constexpr std::size_t CHUNK = 0x10000;
        std::vector<std::uint8_t> buf(CHUNK);

        for (std::uint64_t off = 0; off < region.size; off += CHUNK - 256) {
            std::size_t to_read = static_cast<std::size_t>(
                std::min(static_cast<std::uint64_t>(CHUNK), region.size - off));
            if (to_read < 128) break;

            std::memset(buf.data(), 0, CHUNK);
            std::size_t actual = device->read_raw(region.base + off, buf.data(), to_read);
            if (actual < 128) continue;


            for (std::size_t i = 0; i + pattern_len + 64 + 1 + 96 < actual; i++) {
                bool prefix_match = true;
                for (std::size_t j = 0; j < pattern_len; j++) {
                    if (buf[i + j] != pattern[j]) { prefix_match = false; break; }
                }
                if (!prefix_match) continue;


                std::size_t pos = i + pattern_len;

                std::string cr_hex_str;
                while (pos < actual && cr_hex_str.size() < 64) {
                    char c = static_cast<char>(buf[pos]);
                    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                        cr_hex_str += c;
                    else break;
                    pos++;
                }
                if (cr_hex_str.size() != 64) continue;


                while (pos < actual && (buf[pos] == ' ' || buf[pos] == '\t')) pos++;


                std::string ms_hex_str;
                while (pos < actual && ms_hex_str.size() < 96) {
                    char c = static_cast<char>(buf[pos]);
                    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                        ms_hex_str += c;
                    else break;
                    pos++;
                }
                if (ms_hex_str.size() < 64) continue;

                tls_session_key_t key;
                key.label = "CLIENT_RANDOM";
                key.client_random = hex_to_bytes(cr_hex_str);
                key.secret = hex_to_bytes(ms_hex_str);
                key.tls_version = 0x0303;
                key.timestamp = get_timestamp_ms();
                key.pid = pid;
                key.library = "KeylogBuffer";

                if (_seen_keys.find(cr_hex_str) == _seen_keys.end()) {
                    _seen_keys[cr_hex_str] = key;
                    keys.push_back(key);
                }

                if (keys.size() >= 64) goto generic_done;
            }


            static const char* tls13_labels[] = {
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
                "SERVER_HANDSHAKE_TRAFFIC_SECRET ",
                "CLIENT_TRAFFIC_SECRET_0 ",
                "SERVER_TRAFFIC_SECRET_0 ",
                "EXPORTER_SECRET ",
            };

            for (const char* label : tls13_labels) {
                std::size_t label_len = std::strlen(label);
                for (std::size_t i = 0; i + label_len + 64 + 1 + 64 < actual; i++) {
                    bool match = true;
                    for (std::size_t j = 0; j < label_len; j++) {
                        if (buf[i + j] != static_cast<std::uint8_t>(label[j])) { match = false; break; }
                    }
                    if (!match) continue;

                    std::size_t pos = i + label_len;
                    std::string cr_hex_str;
                    while (pos < actual && cr_hex_str.size() < 64) {
                        char c = static_cast<char>(buf[pos]);
                        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                            cr_hex_str += c;
                        else break;
                        pos++;
                    }
                    if (cr_hex_str.size() != 64) continue;

                    while (pos < actual && (buf[pos] == ' ' || buf[pos] == '\t')) pos++;

                    std::string secret_hex_str;
                    while (pos < actual && secret_hex_str.size() < 128) {
                        char c = static_cast<char>(buf[pos]);
                        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                            secret_hex_str += c;
                        else break;
                        pos++;
                    }
                    if (secret_hex_str.size() < 64) continue;

                    tls_session_key_t key;

                    key.label = std::string(label, label_len - 1);
                    key.client_random = hex_to_bytes(cr_hex_str);
                    key.secret = hex_to_bytes(secret_hex_str);
                    key.tls_version = 0x0304;
                    key.timestamp = get_timestamp_ms();
                    key.pid = pid;
                    key.library = "KeylogBuffer";

                    std::string dedup_key = key.label + ":" + cr_hex_str;
                    if (_seen_keys.find(dedup_key) == _seen_keys.end()) {
                        _seen_keys[dedup_key] = key;
                        keys.push_back(key);
                    }

                    if (keys.size() >= 64) goto generic_done;
                }
            }
        }
    }
generic_done:
    device->set_process_id(saved_pid);
    if (saved_pid != 0) device->solve_dtb();
    return keys;
}


static std::vector<tls_session_key_t> scan_tls13_secrets_impl(
    voyager::device_t* dev, std::uint32_t pid,
    std::map<std::string, tls_session_key_t>& seen_keys) {

    std::vector<tls_session_key_t> keys;
    if (!dev || !dev->is_connected()) return keys;

    std::uint32_t saved_pid = dev->get_process_id();
    dev->set_process_id(pid);
    dev->solve_dtb();

    auto regions = dev->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);


    for (const auto& region : regions) {
        if (region.state != 0x1000) continue;
        if (region.size > 0x2000000 || region.size < 128) continue;

        constexpr std::size_t CHUNK = 0x10000;
        std::vector<std::uint8_t> buf(CHUNK);

        for (std::uint64_t off = 0; off < region.size; off += CHUNK - 128) {
            std::size_t to_read = static_cast<std::size_t>(
                std::min(static_cast<std::uint64_t>(CHUNK), region.size - off));
            if (to_read < 128) break;

            std::memset(buf.data(), 0, CHUNK);
            std::size_t actual = dev->read_raw(region.base + off, buf.data(), to_read);
            if (actual < 128) continue;


            for (std::size_t i = 64; i + 2 <= actual; i += 2) {
                std::uint16_t ver = (static_cast<std::uint16_t>(buf[i]) << 8) | buf[i + 1];
                if (ver != 0x0304) continue;


                for (int cr_off = -128; cr_off < -16; cr_off += 8) {
                    std::int64_t cr_pos = static_cast<std::int64_t>(i) + cr_off;
                    if (cr_pos < 0) continue;
                    if (cr_pos + 32 > static_cast<std::int64_t>(actual)) continue;

                    const std::uint8_t* cr = buf.data() + cr_pos;
                    if (!looks_like_random(cr, 32)) continue;


                    static const char* tls13_labels[] = {
                        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                        "CLIENT_TRAFFIC_SECRET_0",
                        "SERVER_TRAFFIC_SECRET_0",
                    };

                    int secret_idx = 0;
                    for (std::size_t sec_off = 32; sec_off <= 128 && secret_idx < 4; sec_off += 32) {
                        std::int64_t sec_pos = cr_pos + static_cast<std::int64_t>(sec_off);
                        if (sec_pos < 0 || sec_pos + 32 > static_cast<std::int64_t>(actual)) break;

                        const std::uint8_t* secret = buf.data() + sec_pos;
                        if (!looks_like_random(secret, 32)) {

                            continue;
                        }

                        tls_session_key_t key;
                        key.label = tls13_labels[secret_idx];
                        key.client_random.assign(cr, cr + 32);
                        key.secret.assign(secret, secret + 32);
                        key.tls_version = 0x0304;
                        key.timestamp = get_timestamp_ms();
                        key.pid = pid;
                        key.library = "TLS1.3-Structure";

                        std::string dedup = key.label + ":" +
                                            bytes_to_hex(cr, 32);
                        if (seen_keys.find(dedup) == seen_keys.end()) {
                            seen_keys[dedup] = key;
                            keys.push_back(key);
                        }
                        secret_idx++;
                    }

                    if (secret_idx > 0) {

                        i += 128;
                        break;
                    }
                }

                if (keys.size() >= 64) goto tls13_done;
            }
        }
    }
tls13_done:
    dev->set_process_id(saved_pid);
    if (saved_pid != 0) dev->solve_dtb();
    return keys;
}


std::vector<tls_session_key_t> TlsKeyExtractor::extract_keys(const tls_key_scan_config_t& config) {
    const ULONGLONG start_ms = GetTickCount64();
    std::vector<tls_session_key_t> all_keys;
    key_scan_diagnostics_t diag;
    diag.requested_pid = config.pid;
    diag.attached_pid = device && device->is_connected() ? device->get_process_id() : 0;
    diag.timeout_ms = config.timeout_ms;
    diag.max_results = config.max_results;
    diag.max_regions = config.max_regions;
    diag.max_read_attempts = config.max_read_attempts;
    diag.max_read_bytes = config.max_read_bytes;
    diag.hint_address = config.hint_address;
    diag.hint_size = config.hint_size;
    diag.hint_only = config.hint_only;

    std::uint32_t pid = config.pid;
    if (pid == 0 && device && device->is_connected())
        pid = device->get_process_id();
    diag.effective_pid = pid;
    if (pid == 0 || config.max_results == 0) {
        diag.early_exit_reason = pid == 0 ? "no_effective_pid" : "max_results_zero";
        netsec_finish_diag(diag, start_ms, 0);
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_tls_scan = diag;
        return all_keys;
    }

    if (config.hint_address != 0 && config.hint_size != 0) {
        auto hinted = netsec_scan_tls_keylog_range(pid, config, diag, start_ms);
        all_keys.insert(all_keys.end(), hinted.begin(), hinted.end());
        if (!all_keys.empty()) {
            std::lock_guard<std::mutex> lock(_mutex);
            for (const auto& key : all_keys) {
                std::string dedup = key.label;
                if (!key.client_random.empty())
                    dedup += ":" + bytes_to_hex(key.client_random.data(), key.client_random.size());
                else if (!key.secret.empty())
                    dedup += ":" + bytes_to_hex(key.secret.data(), std::min<std::size_t>(key.secret.size(), 16));
                _seen_keys[dedup] = key;
            }
        }
        if (config.hint_only || all_keys.size() >= config.max_results || netsec_scan_should_stop(config, diag, start_ms)) {
            if (all_keys.size() > config.max_results)
                all_keys.resize(config.max_results);
            if (diag.early_exit_reason.empty())
                diag.early_exit_reason = config.hint_only ? "hint_only_complete" : "hint_complete";
            netsec_finish_diag(diag, start_ms, all_keys.size());
            diag::log_tagged_fmt("net_sec", "tls_extract_keys bounded_done requested_pid=%u effective_pid=%u keys=%zu hint_used=%d hint_only=%d elapsed_ms=%llu reason=%s deadline=%d cancelled=%d",
                config.pid,
                pid,
                all_keys.size(),
                diag.hint_used ? 1 : 0,
                config.hint_only ? 1 : 0,
                static_cast<unsigned long long>(diag.elapsed_ms),
                diag.early_exit_reason.c_str(),
                diag.deadline_expired ? 1 : 0,
                diag.cancelled ? 1 : 0);
            std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
            _last_tls_scan = diag;
            return all_keys;
        }
    }
    if (config.hint_only) {
        diag.early_exit_reason = "hint_missing";
        netsec_finish_diag(diag, start_ms, all_keys.size());
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_tls_scan = diag;
        return all_keys;
    }

    std::lock_guard<std::mutex> lock(_mutex);
    if (config.scan_schannel && all_keys.size() < config.max_results && !netsec_scan_should_stop(config, diag, start_ms)) {
        auto keys = scan_schannel(pid);
        all_keys.insert(all_keys.end(), keys.begin(), keys.end());
    }
    if (config.scan_openssl && all_keys.size() < config.max_results && !netsec_scan_should_stop(config, diag, start_ms)) {
        auto keys = scan_openssl(pid);
        all_keys.insert(all_keys.end(), keys.begin(), keys.end());
    }
    if (config.scan_nss && all_keys.size() < config.max_results && !netsec_scan_should_stop(config, diag, start_ms)) {
        auto keys = scan_nss(pid);
        all_keys.insert(all_keys.end(), keys.begin(), keys.end());
    }
    if (config.scan_boringssl && all_keys.size() < config.max_results && !netsec_scan_should_stop(config, diag, start_ms)) {
        auto keys = scan_boringssl(pid);
        all_keys.insert(all_keys.end(), keys.begin(), keys.end());
    }


    if (config.scan_generic && all_keys.size() < config.max_results && !netsec_scan_should_stop(config, diag, start_ms)) {
        auto keys = scan_generic_patterns(pid);
        all_keys.insert(all_keys.end(), keys.begin(), keys.end());
    }


    if (config.scan_tls13_structures && all_keys.size() < config.max_results && !netsec_scan_should_stop(config, diag, start_ms)) {
        auto keys = scan_tls13_secrets_impl(device.get(), pid, _seen_keys);
        all_keys.insert(all_keys.end(), keys.begin(), keys.end());
    }

    if (all_keys.size() > config.max_results)
        all_keys.resize(config.max_results);

    netsec_finish_diag(diag, start_ms, all_keys.size());
    diag::log_tagged_fmt("net_sec", "tls_extract_keys scan_done requested_pid=%u effective_pid=%u keys=%zu elapsed_ms=%llu reason=%s deadline=%d cancelled=%d hint_used=%d",
        config.pid,
        pid,
        all_keys.size(),
        static_cast<unsigned long long>(diag.elapsed_ms),
        diag.early_exit_reason.c_str(),
        diag.deadline_expired ? 1 : 0,
        diag.cancelled ? 1 : 0,
        diag.hint_used ? 1 : 0);
    {
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_tls_scan = diag;
    }
    return all_keys;
}

std::map<std::string, tls_session_key_t> TlsKeyExtractor::get_seen_keys() const {
    std::unique_lock<std::mutex> lock(_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::get_seen_keys busy tid=%lu",
            static_cast<unsigned long>(GetCurrentThreadId()));
        return {};
    }
    return _seen_keys;
}

key_scan_diagnostics_t TlsKeyExtractor::last_tls_scan_diagnostics() const {
    std::lock_guard<std::mutex> lock(_diagnostics_mutex);
    return _last_tls_scan;
}


std::vector<quic_key_info_t> TlsKeyExtractor::extract_quic_keys(std::uint32_t pid) {
    tls_key_scan_config_t config;
    config.pid = pid;
    return extract_quic_keys(config);
}

std::vector<quic_key_info_t> TlsKeyExtractor::extract_quic_keys(const tls_key_scan_config_t& config) {
    const ULONGLONG start_ms = GetTickCount64();
    std::vector<quic_key_info_t> keys;
    key_scan_diagnostics_t diag;
    diag.requested_pid = config.pid;
    diag.attached_pid = device && device->is_connected() ? device->get_process_id() : 0;
    diag.timeout_ms = config.timeout_ms;
    diag.max_results = config.max_results;
    diag.max_regions = config.max_regions;
    diag.max_read_attempts = config.max_read_attempts;
    diag.max_read_bytes = config.max_read_bytes;
    diag.hint_address = config.hint_address;
    diag.hint_size = config.hint_size;
    diag.hint_only = config.hint_only;

    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "quic_extract_keys backend_unavailable device_not_connected");
        diag.early_exit_reason = "device_not_connected";
        netsec_finish_diag(diag, start_ms, 0);
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_quic_scan = diag;
        return keys;
    }

    std::uint32_t pid = config.pid;
    if (pid == 0) pid = device->get_process_id();
    if (pid == 0) {
        diag::log_tagged("net_sec", "quic_extract_keys rejected pid=0");
        diag.early_exit_reason = "no_effective_pid";
        netsec_finish_diag(diag, start_ms, 0);
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_quic_scan = diag;
        return keys;
    }
    diag.effective_pid = pid;
    if (config.max_results == 0) {
        diag.early_exit_reason = "max_results_zero";
        netsec_finish_diag(diag, start_ms, 0);
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_quic_scan = diag;
        return keys;
    }


    std::uint64_t msquic_base = 0;
    std::uint32_t msquic_size = 0;
    bool has_msquic = find_module_in_process(pid, "msquic.dll", msquic_base, msquic_size);
    diag::log_tagged_fmt("net_sec", "quic_extract_keys scan_start requested_pid=%u effective_pid=%u has_msquic=%d msquic_base=0x%llX msquic_size=0x%X current_device_pid=%u timeout_ms=%u max_results=%u max_regions=%u max_reads=%u max_bytes=%llu hint=0x%llX hint_size=%u hint_only=%d",
        config.pid,
        pid,
        has_msquic ? 1 : 0,
        static_cast<unsigned long long>(msquic_base),
        msquic_size,
        device->get_process_id(),
        config.timeout_ms,
        config.max_results,
        config.max_regions,
        config.max_read_attempts,
        static_cast<unsigned long long>(config.max_read_bytes),
        static_cast<unsigned long long>(config.hint_address),
        config.hint_size,
        config.hint_only ? 1 : 0);

    if (config.hint_address != 0 && config.hint_size != 0) {
        auto hinted = netsec_scan_quic_keylog_range(pid, config, diag, start_ms, has_msquic);
        keys.insert(keys.end(), hinted.begin(), hinted.end());
        if (config.hint_only || keys.size() >= config.max_results || netsec_scan_should_stop(config, diag, start_ms)) {
            if (keys.size() > config.max_results)
                keys.resize(config.max_results);
            if (diag.early_exit_reason.empty())
                diag.early_exit_reason = config.hint_only ? "hint_only_complete" : "hint_complete";
            netsec_finish_diag(diag, start_ms, keys.size());
            diag::log_tagged_fmt("net_sec", "quic_extract_keys scan_done requested_pid=%u effective_pid=%u keys=%zu regions=%llu committed=%llu read_attempts=%llu read_bytes=%llu label_hits=%llu reject=%llu elapsed_ms=%llu reason=%s deadline=%d cancelled=%d truncated=%d",
                config.pid,
                pid,
                keys.size(),
                static_cast<unsigned long long>(diag.regions_seen),
                static_cast<unsigned long long>(diag.regions_committed),
                static_cast<unsigned long long>(diag.read_attempts),
                static_cast<unsigned long long>(diag.read_bytes),
                static_cast<unsigned long long>(diag.candidate_hits),
                static_cast<unsigned long long>(diag.reject_count),
                static_cast<unsigned long long>(diag.elapsed_ms),
                diag.early_exit_reason.c_str(),
                diag.deadline_expired ? 1 : 0,
                diag.cancelled ? 1 : 0,
                diag.truncated ? 1 : 0);
            std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
            _last_quic_scan = diag;
            return keys;
        }
    }
    if (config.hint_only) {
        diag.early_exit_reason = "hint_missing";
        netsec_finish_diag(diag, start_ms, keys.size());
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_quic_scan = diag;
        return keys;
    }


    std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    const ULONGLONG enum_start = GetTickCount64();
    auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);
    diag.enumerate_elapsed_ms = GetTickCount64() - enum_start;
    diag::log_tagged_fmt("net_sec", "quic_extract_keys regions_enumerated pid=%u count=%zu saved_pid=%u device_pid=%u",
        pid,
        regions.size(),
        saved_pid,
        device->get_process_id());

    static const char* quic_labels[] = {
        "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
        "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET ",
        "QUIC_CLIENT_TRAFFIC_SECRET_0 ",
        "QUIC_SERVER_TRAFFIC_SECRET_0 ",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET ",
        "CLIENT_TRAFFIC_SECRET_0 ",
        "SERVER_TRAFFIC_SECRET_0 ",
    };

    std::size_t label_hits = 0;
    std::size_t reject_client_random = 0;
    std::size_t reject_separator = 0;
    std::size_t reject_secret = 0;
    std::size_t region_logs = 0;
    std::size_t hit_logs = 0;
    std::size_t reject_logs = 0;

    for (const auto& region : regions) {
        if (netsec_scan_should_stop(config, diag, start_ms))
            break;
        ++diag.regions_seen;
        if (region.state != 0x1000) {
            ++diag.regions_skipped_state;
            continue;
        }
        if (region.size > 0x2000000 || region.size < 128) {
            ++diag.regions_skipped_size;
            continue;
        }
        ++diag.regions_committed;
        if (region_logs < 16) {
            diag::log_tagged_fmt("net_sec", "quic_extract_keys region pid=%u index=%zu base=0x%llX size=0x%llX state=0x%X protect=0x%X",
                pid,
                static_cast<std::size_t>(diag.regions_seen - 1),
                static_cast<unsigned long long>(region.base),
                static_cast<unsigned long long>(region.size),
                region.state,
                region.protect);
            ++region_logs;
        }

        constexpr std::size_t CHUNK = 0x10000;
        std::vector<std::uint8_t> buf(CHUNK);

        for (std::uint64_t off = 0; off < region.size; off += CHUNK - 256) {
            if (netsec_scan_should_stop(config, diag, start_ms))
                goto quic_done;
            std::size_t to_read = static_cast<std::size_t>(
                std::min(static_cast<std::uint64_t>(CHUNK), region.size - off));
            if (to_read < 128) break;

            std::memset(buf.data(), 0, CHUNK);
            ++diag.read_attempts;
            std::size_t actual = device->read_raw(region.base + off, buf.data(), to_read);
            diag.read_bytes += actual;
            if (actual < 128) {
                ++diag.read_short;
                if (diag.first_short_read_va == 0)
                    diag.first_short_read_va = region.base + off;
                continue;
            }

            for (const char* label : quic_labels) {
                std::size_t label_len = std::strlen(label);
                for (std::size_t i = 0; i + label_len + 64 + 1 + 64 < actual; i++) {
                    if (keys.size() >= config.max_results) {
                        diag.early_exit_reason = "max_results";
                        goto quic_done;
                    }
                    if (netsec_scan_should_stop(config, diag, start_ms))
                        goto quic_done;
                    bool match = true;
                    for (std::size_t j = 0; j < label_len; j++) {
                        if (buf[i + j] != static_cast<std::uint8_t>(label[j])) { match = false; break; }
                    }
                    if (!match) continue;

                    ++label_hits;
                    ++diag.candidate_hits;
                    if (diag.first_hit_elapsed_ms == 0)
                        diag.first_hit_elapsed_ms = GetTickCount64() - start_ms;
                    const std::uint64_t hit_va = region.base + off + i;
                    if (hit_logs < 16) {
                        diag::log_tagged_fmt("net_sec", "quic_extract_keys label_hit pid=%u va=0x%llX label=%.*s chunk_actual=%zu region_base=0x%llX region_size=0x%llX",
                            pid,
                            static_cast<unsigned long long>(hit_va),
                            static_cast<int>(label_len - 1),
                            label,
                            actual,
                            static_cast<unsigned long long>(region.base),
                            static_cast<unsigned long long>(region.size));
                        ++hit_logs;
                    }

                    std::size_t pos = i + label_len;
                    std::string cr_hex;
                    while (pos < actual && cr_hex.size() < 64) {
                        char c = static_cast<char>(buf[pos]);
                        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                            cr_hex += c;
                        else break;
                        pos++;
                    }
                    if (cr_hex.size() != 64) {
                        ++reject_client_random;
                        ++diag.reject_count;
                        if (reject_logs < 16) {
                            diag::log_tagged_fmt("net_sec", "quic_extract_keys reject_client_random pid=%u va=0x%llX label=%.*s chars=%zu pos=%zu actual=%zu",
                                pid,
                                static_cast<unsigned long long>(hit_va),
                                static_cast<int>(label_len - 1),
                                label,
                                cr_hex.size(),
                                pos,
                                actual);
                            ++reject_logs;
                        }
                        continue;
                    }

                    bool separator_seen = false;
                    while (pos < actual && (buf[pos] == ' ' || buf[pos] == '\t')) {
                        separator_seen = true;
                        pos++;
                    }
                    if (!separator_seen) {
                        ++reject_separator;
                        ++diag.reject_count;
                        if (reject_logs < 16) {
                            diag::log_tagged_fmt("net_sec", "quic_extract_keys reject_separator pid=%u va=0x%llX label=%.*s pos=%zu actual=%zu",
                                pid,
                                static_cast<unsigned long long>(hit_va),
                                static_cast<int>(label_len - 1),
                                label,
                                pos,
                                actual);
                            ++reject_logs;
                        }
                        continue;
                    }

                    std::string secret_hex;
                    while (pos < actual && secret_hex.size() < 128) {
                        char c = static_cast<char>(buf[pos]);
                        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                            secret_hex += c;
                        else break;
                        pos++;
                    }
                    if (secret_hex.size() < 64) {
                        ++reject_secret;
                        ++diag.reject_count;
                        if (reject_logs < 16) {
                            diag::log_tagged_fmt("net_sec", "quic_extract_keys reject_secret pid=%u va=0x%llX label=%.*s chars=%zu pos=%zu actual=%zu",
                                pid,
                                static_cast<unsigned long long>(hit_va),
                                static_cast<int>(label_len - 1),
                                label,
                                secret_hex.size(),
                                pos,
                                actual);
                            ++reject_logs;
                        }
                        continue;
                    }

                    quic_key_info_t key;
                    key.label = std::string(label, label_len - 1);
                    key.client_random = hex_to_bytes(cr_hex);
                    key.secret = hex_to_bytes(secret_hex);
                    key.pid = pid;
                    key.library = has_msquic ? "msquic" : "BoringSSL-QUIC";
                    keys.push_back(key);
                    diag::log_tagged_fmt("net_sec", "quic_extract_keys parsed_key pid=%u va=0x%llX label=%s client_random_len=%zu secret_len=%zu library=%s count=%zu",
                        pid,
                        static_cast<unsigned long long>(hit_va),
                        key.label.c_str(),
                        key.client_random.size(),
                        key.secret.size(),
                        key.library.c_str(),
                        keys.size());

                    if (keys.size() >= config.max_results) {
                        diag.early_exit_reason = "max_results";
                        goto quic_done;
                    }
                }
            }
        }
    }
quic_done:
    netsec_finish_diag(diag, start_ms, keys.size());
    diag::log_tagged_fmt("net_sec", "quic_extract_keys scan_done requested_pid=%u effective_pid=%u keys=%zu regions=%llu committed=%llu skipped_state=%llu skipped_size=%llu read_attempts=%llu read_bytes=%llu read_short=%llu first_short_read_va=0x%llX label_hits=%zu reject_client_random=%zu reject_separator=%zu reject_secret=%zu elapsed_ms=%llu enumerate_ms=%llu first_hit_ms=%llu reason=%s deadline=%d cancelled=%d truncated=%d saved_pid=%u restore_needed=%d",
        config.pid,
        pid,
        keys.size(),
        static_cast<unsigned long long>(diag.regions_seen),
        static_cast<unsigned long long>(diag.regions_committed),
        static_cast<unsigned long long>(diag.regions_skipped_state),
        static_cast<unsigned long long>(diag.regions_skipped_size),
        static_cast<unsigned long long>(diag.read_attempts),
        static_cast<unsigned long long>(diag.read_bytes),
        static_cast<unsigned long long>(diag.read_short),
        static_cast<unsigned long long>(diag.first_short_read_va),
        label_hits,
        reject_client_random,
        reject_separator,
        reject_secret,
        static_cast<unsigned long long>(diag.elapsed_ms),
        static_cast<unsigned long long>(diag.enumerate_elapsed_ms),
        static_cast<unsigned long long>(diag.first_hit_elapsed_ms),
        diag.early_exit_reason.c_str(),
        diag.deadline_expired ? 1 : 0,
        diag.cancelled ? 1 : 0,
        diag.truncated ? 1 : 0,
        saved_pid,
        saved_pid != 0 ? 1 : 0);
    device->set_process_id(saved_pid);
    if (saved_pid != 0) device->solve_dtb();
    {
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_quic_scan = diag;
    }
    return keys;
}

key_scan_diagnostics_t TlsKeyExtractor::last_quic_scan_diagnostics() const {
    std::lock_guard<std::mutex> lock(_diagnostics_mutex);
    return _last_quic_scan;
}


std::vector<dtls_key_info_t> TlsKeyExtractor::extract_dtls_keys(std::uint32_t pid) {
    tls_key_scan_config_t config;
    config.pid = pid;
    return extract_dtls_keys(config);
}

std::vector<dtls_key_info_t> TlsKeyExtractor::extract_dtls_keys(const tls_key_scan_config_t& config) {
    const ULONGLONG start_ms = GetTickCount64();
    std::vector<dtls_key_info_t> keys;
    key_scan_diagnostics_t diag;
    diag.requested_pid = config.pid;
    diag.attached_pid = device && device->is_connected() ? device->get_process_id() : 0;
    diag.timeout_ms = config.timeout_ms;
    diag.max_results = config.max_results;
    diag.max_regions = config.max_regions;
    diag.max_read_attempts = config.max_read_attempts;
    diag.max_read_bytes = config.max_read_bytes;
    diag.hint_address = config.hint_address;
    diag.hint_size = config.hint_size;
    diag.hint_only = config.hint_only;

    if (!device || !device->is_connected()) {
        diag.early_exit_reason = "device_not_connected";
        netsec_finish_diag(diag, start_ms, 0);
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_dtls_scan = diag;
        return keys;
    }

    std::uint32_t pid = config.pid;
    if (pid == 0) pid = device->get_process_id();
    diag.effective_pid = pid;
    if (pid == 0 || config.max_results == 0) {
        diag.early_exit_reason = pid == 0 ? "no_effective_pid" : "max_results_zero";
        netsec_finish_diag(diag, start_ms, 0);
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_dtls_scan = diag;
        return keys;
    }

    diag::log_tagged_fmt("net_sec", "dtls_extract_keys scan_start requested_pid=%u effective_pid=%u timeout_ms=%u max_results=%u max_regions=%u max_reads=%u max_bytes=%llu hint=0x%llX hint_size=%u hint_only=%d current_device_pid=%u",
        config.pid,
        pid,
        config.timeout_ms,
        config.max_results,
        config.max_regions,
        config.max_read_attempts,
        static_cast<unsigned long long>(config.max_read_bytes),
        static_cast<unsigned long long>(config.hint_address),
        config.hint_size,
        config.hint_only ? 1 : 0,
        device->get_process_id());

    if (config.hint_address != 0 && config.hint_size != 0) {
        auto hinted = netsec_scan_dtls_range(pid, config, diag, start_ms);
        keys.insert(keys.end(), hinted.begin(), hinted.end());
        if (config.hint_only || keys.size() >= config.max_results || netsec_scan_should_stop(config, diag, start_ms)) {
            if (keys.size() > config.max_results)
                keys.resize(config.max_results);
            if (diag.early_exit_reason.empty())
                diag.early_exit_reason = config.hint_only ? "hint_only_complete" : "hint_complete";
            netsec_finish_diag(diag, start_ms, keys.size());
            diag::log_tagged_fmt("net_sec", "dtls_extract_keys scan_done requested_pid=%u effective_pid=%u keys=%zu regions=%llu committed=%llu read_attempts=%llu read_bytes=%llu hits=%llu reject=%llu elapsed_ms=%llu reason=%s deadline=%d cancelled=%d truncated=%d",
                config.pid,
                pid,
                keys.size(),
                static_cast<unsigned long long>(diag.regions_seen),
                static_cast<unsigned long long>(diag.regions_committed),
                static_cast<unsigned long long>(diag.read_attempts),
                static_cast<unsigned long long>(diag.read_bytes),
                static_cast<unsigned long long>(diag.candidate_hits),
                static_cast<unsigned long long>(diag.reject_count),
                static_cast<unsigned long long>(diag.elapsed_ms),
                diag.early_exit_reason.c_str(),
                diag.deadline_expired ? 1 : 0,
                diag.cancelled ? 1 : 0,
                diag.truncated ? 1 : 0);
            std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
            _last_dtls_scan = diag;
            return keys;
        }
    }
    if (config.hint_only) {
        diag.early_exit_reason = "hint_missing";
        netsec_finish_diag(diag, start_ms, keys.size());
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_dtls_scan = diag;
        return keys;
    }


    std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    const ULONGLONG enum_start = GetTickCount64();
    auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);
    diag.enumerate_elapsed_ms = GetTickCount64() - enum_start;

    for (const auto& region : regions) {
        if (netsec_scan_should_stop(config, diag, start_ms))
            break;
        ++diag.regions_seen;
        if (region.state != 0x1000) {
            ++diag.regions_skipped_state;
            continue;
        }
        if (region.size > 0x1000000 || region.size < 128) {
            ++diag.regions_skipped_size;
            continue;
        }
        ++diag.regions_committed;

        constexpr std::size_t CHUNK = 0x10000;
        std::vector<std::uint8_t> buf(CHUNK);

        for (std::uint64_t off = 0; off < region.size; off += CHUNK - 128) {
            if (netsec_scan_should_stop(config, diag, start_ms))
                goto dtls_done;
            std::size_t to_read = static_cast<std::size_t>(
                std::min(static_cast<std::uint64_t>(CHUNK), region.size - off));
            if (to_read < 128) break;

            std::memset(buf.data(), 0, CHUNK);
            ++diag.read_attempts;
            std::size_t actual = device->read_raw(region.base + off, buf.data(), to_read);
            diag.read_bytes += actual;
            if (actual < 128) {
                ++diag.read_short;
                if (diag.first_short_read_va == 0)
                    diag.first_short_read_va = region.base + off;
                continue;
            }

            for (std::size_t i = 0; i + 128 <= actual; i += 8) {
                if (keys.size() >= config.max_results) {
                    diag.early_exit_reason = "max_results";
                    goto dtls_done;
                }
                if (netsec_scan_should_stop(config, diag, start_ms))
                    goto dtls_done;

                std::uint16_t ver = (static_cast<std::uint16_t>(buf[i]) << 8) | buf[i + 1];
                if (ver != 0xFEFF && ver != 0xFEFD) continue;
                ++diag.candidate_hits;
                if (diag.first_hit_elapsed_ms == 0)
                    diag.first_hit_elapsed_ms = GetTickCount64() - start_ms;


                for (int search_off = -128; search_off < 128; search_off += 8) {
                    std::int64_t cr_pos = static_cast<std::int64_t>(i) + search_off;
                    if (cr_pos < 0 || cr_pos + 80 > static_cast<std::int64_t>(actual)) continue;

                    const std::uint8_t* cr = buf.data() + cr_pos;
                    const std::uint8_t* ms = buf.data() + cr_pos + 32;

                    if (!looks_like_random(cr, 32)) {
                        ++diag.reject_count;
                        continue;
                    }
                    if (!looks_like_random(ms, 48)) {
                        ++diag.reject_count;
                        continue;
                    }

                    dtls_key_info_t key;
                    key.dtls_version = ver;
                    key.client_random.assign(cr, cr + 32);
                    key.master_secret.assign(ms, ms + 48);
                    key.pid = pid;
                    key.library = "DTLS";
                    keys.push_back(key);

                    if (keys.size() >= config.max_results) {
                        diag.early_exit_reason = "max_results";
                        goto dtls_done;
                    }
                    i += 80;
                    break;
                }
            }
        }
    }
dtls_done:
    netsec_finish_diag(diag, start_ms, keys.size());
    diag::log_tagged_fmt("net_sec", "dtls_extract_keys scan_done requested_pid=%u effective_pid=%u keys=%zu regions=%llu committed=%llu skipped_state=%llu skipped_size=%llu read_attempts=%llu read_bytes=%llu read_short=%llu first_short_read_va=0x%llX hits=%llu rejects=%llu elapsed_ms=%llu enumerate_ms=%llu first_hit_ms=%llu reason=%s deadline=%d cancelled=%d truncated=%d saved_pid=%u restore_needed=%d",
        config.pid,
        pid,
        keys.size(),
        static_cast<unsigned long long>(diag.regions_seen),
        static_cast<unsigned long long>(diag.regions_committed),
        static_cast<unsigned long long>(diag.regions_skipped_state),
        static_cast<unsigned long long>(diag.regions_skipped_size),
        static_cast<unsigned long long>(diag.read_attempts),
        static_cast<unsigned long long>(diag.read_bytes),
        static_cast<unsigned long long>(diag.read_short),
        static_cast<unsigned long long>(diag.first_short_read_va),
        static_cast<unsigned long long>(diag.candidate_hits),
        static_cast<unsigned long long>(diag.reject_count),
        static_cast<unsigned long long>(diag.elapsed_ms),
        static_cast<unsigned long long>(diag.enumerate_elapsed_ms),
        static_cast<unsigned long long>(diag.first_hit_elapsed_ms),
        diag.early_exit_reason.c_str(),
        diag.deadline_expired ? 1 : 0,
        diag.cancelled ? 1 : 0,
        diag.truncated ? 1 : 0,
        saved_pid,
        saved_pid != 0 ? 1 : 0);
    device->set_process_id(saved_pid);
    if (saved_pid != 0) device->solve_dtb();
    {
        std::lock_guard<std::mutex> diag_lock(_diagnostics_mutex);
        _last_dtls_scan = diag;
    }
    return keys;
}

key_scan_diagnostics_t TlsKeyExtractor::last_dtls_scan_diagnostics() const {
    std::lock_guard<std::mutex> lock(_diagnostics_mutex);
    return _last_dtls_scan;
}


std::vector<tls_session_key_t> TlsKeyExtractor::read_keylog_file(const std::string& path) {
    std::vector<tls_session_key_t> keys;
    std::ifstream file(path);
    if (!file.is_open()) return keys;

    std::string line;
    while (std::getline(file, line)) {

        if (line.empty() || line[0] == '#') continue;


        std::size_t pos1 = line.find(' ');
        if (pos1 == std::string::npos || pos1 == 0) continue;

        std::string label = line.substr(0, pos1);
        std::size_t pos2 = pos1 + 1;
        while (pos2 < line.size() && line[pos2] == ' ') pos2++;

        std::size_t pos3 = line.find(' ', pos2);
        if (pos3 == std::string::npos) continue;

        std::string cr_hex = line.substr(pos2, pos3 - pos2);
        std::size_t pos4 = pos3 + 1;
        while (pos4 < line.size() && line[pos4] == ' ') pos4++;

        std::string secret_hex = line.substr(pos4);

        while (!secret_hex.empty() && (secret_hex.back() == '\r' || secret_hex.back() == '\n' ||
               secret_hex.back() == ' ' || secret_hex.back() == '\t'))
            secret_hex.pop_back();

        if (cr_hex.size() < 32 || secret_hex.size() < 32) continue;

        tls_session_key_t key;
        key.label = label;
        key.client_random = hex_to_bytes(cr_hex);
        key.secret = hex_to_bytes(secret_hex);
        key.timestamp = get_timestamp_ms();
        key.library = "KeylogFile";


        if (label == "CLIENT_RANDOM" || label == "RSA")
            key.tls_version = 0x0303;
        else
            key.tls_version = 0x0304;

        keys.push_back(key);
    }
    return keys;
}


std::string TlsKeyExtractor::find_tshark_path() {
    auto env_var = [](const char* name) -> std::string {
        char env_buffer[32767] = {};
        DWORD len = GetEnvironmentVariableA(name, env_buffer, static_cast<DWORD>(sizeof(env_buffer)));
        if (len == 0 || len >= sizeof(env_buffer))
            return {};
        return std::string(env_buffer, len);
    };
    auto trim_path = [](std::string path) -> std::string {
        while (!path.empty() && (path.front() == '"' || path.front() == '\'' || path.front() == ' ' || path.front() == '\t'))
            path.erase(path.begin());
        while (!path.empty() && (path.back() == '"' || path.back() == '\'' || path.back() == ' ' || path.back() == '\t'))
            path.pop_back();
        return path;
    };
    std::vector<std::string> candidates;
    auto add_unique = [&](const std::string& raw_path) {
        std::string path = trim_path(raw_path);
        if (path.empty())
            return;
        if (std::find(candidates.begin(), candidates.end(), path) == candidates.end())
            candidates.push_back(path);
    };
    auto add_candidate = [&](const std::string& raw_path) {
        std::string path = trim_path(raw_path);
        if (path.empty())
            return;
        add_unique(path);
        std::filesystem::path fs_path(path);
        if (!fs_path.has_extension() || _stricmp(fs_path.extension().string().c_str(), ".exe") != 0)
            add_unique((fs_path / "tshark.exe").string());
    };
    auto add_base_candidates = [&](const std::filesystem::path& base) {
        if (base.empty())
            return;
        add_candidate((base / "tshark.exe").string());
        add_candidate((base / "Wireshark" / "tshark.exe").string());
        add_candidate((base / "wireshark" / "tshark.exe").string());
        add_candidate((base / "deps" / "tshark.exe").string());
        add_candidate((base / "deps" / "Wireshark" / "tshark.exe").string());
        add_candidate((base / "deps" / "wireshark" / "tshark.exe").string());
        add_candidate((base / "tools" / "Wireshark" / "tshark.exe").string());
        add_candidate((base / "third_party" / "Wireshark" / "tshark.exe").string());
        add_candidate((base / "vendor" / "Wireshark" / "tshark.exe").string());
    };
    add_candidate(env_var("AIDA_TSHARK"));
    add_candidate(env_var("TSHARK_PATH"));
    const std::string program_files = env_var("ProgramFiles");
    if (!program_files.empty())
        add_candidate(program_files + "\\Wireshark\\tshark.exe");
    const std::string program_files_x86 = env_var("ProgramFiles(x86)");
    if (!program_files_x86.empty())
        add_candidate(program_files_x86 + "\\Wireshark\\tshark.exe");
    const std::string path_env = env_var("PATH");
    size_t start = 0;
    while (start <= path_env.size()) {
        const size_t end = path_env.find(';', start);
        const std::string dir = path_env.substr(start, end == std::string::npos ? std::string::npos : end - start);
        add_candidate(dir);
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    char module_path[MAX_PATH] = {};
    DWORD module_len = GetModuleFileNameA(nullptr, module_path, MAX_PATH);
    if (module_len > 0 && module_len < MAX_PATH) {
        std::filesystem::path base = std::filesystem::path(std::string(module_path, module_len)).parent_path();
        for (int i = 0; i < 4 && !base.empty(); ++i) {
            add_base_candidates(base);
            base = base.parent_path();
        }
    }
    std::error_code ec;
    std::filesystem::path current = std::filesystem::current_path(ec);
    if (!ec) {
        for (int i = 0; i < 4 && !current.empty(); ++i) {
            add_base_candidates(current);
            current = current.parent_path();
        }
    }
    for (const auto& path : candidates) {
        DWORD attrs = GetFileAttributesA(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
            return path;
    }
    char buf[MAX_PATH] = {};
    DWORD len = SearchPathA(nullptr, "tshark.exe", nullptr, MAX_PATH, buf, nullptr);
    if (len > 0 && len < MAX_PATH)
        return std::string(buf, len);

    return "";
}


bool TlsKeyExtractor::ensure_sslkeylogfile_env(const std::string& path) {
    std::string keylog_path = path;
    if (keylog_path.empty()) {
        char profile[MAX_PATH] = {};
        DWORD plen = GetEnvironmentVariableA("USERPROFILE", profile, MAX_PATH);
        if (plen > 0 && plen < MAX_PATH)
            keylog_path = std::string(profile, plen) + "\\sslkeys.log";
        else
            return false;
    }


    char existing[MAX_PATH] = {};
    DWORD elen = GetEnvironmentVariableA("SSLKEYLOGFILE", existing, MAX_PATH);
    if (elen > 0 && std::string(existing, elen) == keylog_path)
        return true;


    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Environment", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "SSLKEYLOGFILE", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(keylog_path.c_str()),
                       static_cast<DWORD>(keylog_path.size() + 1));
        RegCloseKey(hKey);


        DWORD_PTR result = 0;
        SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                            reinterpret_cast<LPARAM>("Environment"),
                            SMTO_ABORTIFHUNG, 5000, &result);


        SetEnvironmentVariableA("SSLKEYLOGFILE", keylog_path.c_str());
        return true;
    }
    return false;
}


pcap_decrypt_result_t TlsKeyExtractor::decrypt_pcap_with_tshark(
    const std::string& pcap_path, const std::string& keylog_path,
    const std::string& display_filter, std::uint32_t timeout_ms) {

    const ULONGLONG start_ms = GetTickCount64();
    pcap_decrypt_result_t result;
    result.pcap_file_used = pcap_path;
    result.keylog_file_used = keylog_path;
    result.timeout_ms = std::max<std::uint32_t>(1000, std::min<std::uint32_t>(timeout_ms, 60000));

    if (GetFileAttributesA(pcap_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        result.error_message = "PCAP file not found: " + pcap_path;
        result.win32_error = GetLastError();
        result.elapsed_ms = GetTickCount64() - start_ms;
        return result;
    }

    if (GetFileAttributesA(keylog_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        result.error_message = "Keylog file not found: " + keylog_path;
        result.win32_error = GetLastError();
        result.elapsed_ms = GetTickCount64() - start_ms;
        return result;
    }

    std::string tshark = find_tshark_path();
    result.tshark_path = tshark;
    if (tshark.empty()) {
        result.error_message = "tshark not found. Install Wireshark to enable PCAP decryption.";
        result.dependency_unavailable = true;
        result.elapsed_ms = GetTickCount64() - start_ms;
        return result;
    }


    std::string cmd = "\"" + tshark + "\"";
    cmd += " -n -r \"" + pcap_path + "\"";
    cmd += " -o \"tls.keylog_file:" + keylog_path + "\"";
    if (!display_filter.empty())
        cmd += " -Y \"" + display_filter + "\"";
    cmd += " -T json -l";

    std::error_code pcap_ec;
    std::error_code keylog_ec;
    const std::uint64_t pcap_size = std::filesystem::file_size(pcap_path, pcap_ec);
    const std::uint64_t keylog_size = std::filesystem::file_size(keylog_path, keylog_ec);
    diag::log_tagged_fmt("net_sec", "tshark_decrypt launch_prepare tshark=%s pcap=%s pcap_size=%llu pcap_size_ok=%d keylog=%s keylog_size=%llu keylog_size_ok=%d filter=%s timeout_ms=%u",
        tshark.c_str(),
        pcap_path.c_str(),
        static_cast<unsigned long long>(pcap_size),
        pcap_ec ? 0 : 1,
        keylog_path.c_str(),
        static_cast<unsigned long long>(keylog_size),
        keylog_ec ? 0 : 1,
        display_filter.c_str(),
        result.timeout_ms);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hStdoutRead = nullptr, hStdoutWrite = nullptr;
    HANDLE hStderrRead = nullptr, hStderrWrite = nullptr;
    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        result.error_message = "Failed to create pipe for tshark output";
        result.win32_error = GetLastError();
        result.elapsed_ms = GetTickCount64() - start_ms;
        return result;
    }
    if (!CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0)) {
        result.error_message = "Failed to create pipe for tshark stderr";
        result.win32_error = GetLastError();
        CloseHandle(hStdoutRead);
        CloseHandle(hStdoutWrite);
        result.elapsed_ms = GetTickCount64() - start_ms;
        return result;
    }
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStderrWrite;

    PROCESS_INFORMATION pi{};

    std::vector<char> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back('\0');

    if (!CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        result.win32_error = GetLastError();
        CloseHandle(hStdoutRead);
        CloseHandle(hStdoutWrite);
        CloseHandle(hStderrRead);
        CloseHandle(hStderrWrite);
        result.error_message = "Failed to launch tshark: error " + std::to_string(result.win32_error);
        result.elapsed_ms = GetTickCount64() - start_ms;
        return result;
    }

    result.launched = true;
    result.process_id = pi.dwProcessId;
    result.launch_elapsed_ms = GetTickCount64() - start_ms;
    CloseHandle(hStdoutWrite);
    CloseHandle(hStderrWrite);
    diag::log_tagged_fmt("net_sec", "tshark_decrypt process_started pid=%lu launch_elapsed_ms=%llu timeout_ms=%u",
        static_cast<unsigned long>(pi.dwProcessId),
        static_cast<unsigned long long>(result.launch_elapsed_ms),
        result.timeout_ms);


    constexpr std::size_t MAX_OUTPUT = 16 * 1024 * 1024;
    std::string stdout_output;
    std::string stderr_output;
    stdout_output.reserve(1024 * 1024);
    stderr_output.reserve(16 * 1024);
    std::atomic<std::uint64_t> stdout_bytes{0};
    std::atomic<std::uint64_t> stderr_bytes{0};
    std::atomic<std::uint64_t> first_stdout_ms{0};
    std::atomic<std::uint64_t> first_stderr_ms{0};

    auto drain_pipe = [&](HANDLE pipe, std::string& sink, std::atomic<std::uint64_t>& byte_counter,
                          std::atomic<std::uint64_t>& first_byte_elapsed) {
        char read_buf[8192];
        DWORD bytes_read = 0;
        while (ReadFile(pipe, read_buf, sizeof(read_buf), &bytes_read, nullptr) && bytes_read > 0) {
            const std::uint64_t old = byte_counter.fetch_add(bytes_read, std::memory_order_acq_rel);
            if (old == 0)
                first_byte_elapsed.store(GetTickCount64() - start_ms, std::memory_order_release);
            if (sink.size() < MAX_OUTPUT) {
                const std::size_t room = MAX_OUTPUT - sink.size();
                sink.append(read_buf, std::min<std::size_t>(room, bytes_read));
            }
        }
        CloseHandle(pipe);
    };

    std::thread stdout_thread(drain_pipe, hStdoutRead, std::ref(stdout_output), std::ref(stdout_bytes), std::ref(first_stdout_ms));
    std::thread stderr_thread(drain_pipe, hStderrRead, std::ref(stderr_output), std::ref(stderr_bytes), std::ref(first_stderr_ms));

    DWORD wait_status = WAIT_TIMEOUT;
    while (true) {
        wait_status = WaitForSingleObject(pi.hProcess, 50);
        if (wait_status == WAIT_OBJECT_0 || wait_status == WAIT_FAILED)
            break;
        if (GetTickCount64() - start_ms >= result.timeout_ms) {
            result.killed_on_deadline = true;
            result.dependency_slow = true;
            TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
            WaitForSingleObject(pi.hProcess, 2000);
            break;
        }
    }
    result.wait_status = wait_status;

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    result.exit_code = exit_code;

    if (stdout_thread.joinable())
        stdout_thread.join();
    if (stderr_thread.joinable())
        stderr_thread.join();

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    result.raw_output = stdout_output;
    result.stderr_output = stderr_output.size() > 8192 ? stderr_output.substr(0, 8192) : stderr_output;
    result.stdout_bytes = stdout_bytes.load(std::memory_order_acquire);
    result.stderr_bytes = stderr_bytes.load(std::memory_order_acquire);
    result.first_stdout_elapsed_ms = first_stdout_ms.load(std::memory_order_acquire);
    result.first_stderr_elapsed_ms = first_stderr_ms.load(std::memory_order_acquire);
    result.elapsed_ms = GetTickCount64() - start_ms;

    diag::log_tagged_fmt("net_sec", "tshark_decrypt process_exit pid=%u exit_code=%u wait_status=%u killed=%d dependency_slow=%d elapsed_ms=%llu stdout_bytes=%llu stderr_bytes=%llu first_stdout_ms=%llu first_stderr_ms=%llu",
        result.process_id,
        result.exit_code,
        result.wait_status,
        result.killed_on_deadline ? 1 : 0,
        result.dependency_slow ? 1 : 0,
        static_cast<unsigned long long>(result.elapsed_ms),
        static_cast<unsigned long long>(result.stdout_bytes),
        static_cast<unsigned long long>(result.stderr_bytes),
        static_cast<unsigned long long>(result.first_stdout_elapsed_ms),
        static_cast<unsigned long long>(result.first_stderr_elapsed_ms));

    if (result.killed_on_deadline) {
        result.error_message = "tshark exceeded decrypt deadline";
        return result;
    }

    if (exit_code != 0 && stdout_output.empty()) {
        result.error_message = "tshark exited with code " + std::to_string(exit_code);
        if (!stderr_output.empty())
            result.error_message += ": " + stderr_output.substr(0, 512);
        return result;
    }


    try {
        const ULONGLONG parse_start = GetTickCount64();
        auto json_arr = nlohmann::json::parse(stdout_output);
        result.json_parse_elapsed_ms = GetTickCount64() - parse_start;
        result.total_packets = static_cast<std::uint32_t>(json_arr.size());

        for (const auto& pkt : json_arr) {
            if (!pkt.contains("_source") || !pkt["_source"].contains("layers")) continue;
            const auto& layers = pkt["_source"]["layers"];


            if (!layers.contains("http2")) continue;

            result.decrypted_packets++;
            const auto& http2 = layers["http2"];


            auto process_http2_stream = [&](const nlohmann::json& stream) {
                pcap_decrypt_result_t::http2_frame_t frame;

                if (stream.contains("http2.stream")) {
                    const auto& s = stream["http2.stream"];

                    auto get_str = [&](const char* key) -> std::string {
                        if (s.contains(key)) {
                            auto& v = s[key];
                            if (v.is_string()) return v.get<std::string>();
                        }
                        return "";
                    };

                    frame.stream_id = get_str("http2.streamid");
                    frame.frame_type = get_str("http2.type");


                    if (s.contains("http2.header")) {
                        auto& hdrs = s["http2.header"];
                        auto process_hdr = [&](const nlohmann::json& h) {
                            std::string name, value;
                            if (h.contains("http2.header.name") && h["http2.header.name"].is_string())
                                name = h["http2.header.name"].get<std::string>();
                            if (h.contains("http2.header.value") && h["http2.header.value"].is_string())
                                value = h["http2.header.value"].get<std::string>();
                            if (!name.empty()) {
                                frame.headers[name] = value;
                                if (name == ":method") frame.method = value;
                                else if (name == ":path") frame.url = value;
                                else if (name == ":authority") frame.authority = value;
                                else if (name == "content-type") frame.content_type = value;
                                else if (name == ":status") {
                                    try { frame.status_code = static_cast<std::uint32_t>(std::stoul(value)); } catch (...) {}
                                }
                            }
                        };
                        if (hdrs.is_array()) {
                            for (const auto& h : hdrs) process_hdr(h);
                        } else if (hdrs.is_object()) {
                            process_hdr(hdrs);
                        }
                    }


                    if (s.contains("http2.data.data") && s["http2.data.data"].is_string())
                        frame.body = s["http2.data.data"].get<std::string>();
                }

                if (!frame.stream_id.empty() || !frame.method.empty() || frame.status_code != 0)
                    result.http2_frames.push_back(std::move(frame));
            };

            if (http2.is_array()) {
                for (const auto& stream : http2) process_http2_stream(stream);
            } else if (http2.is_object()) {
                process_http2_stream(http2);
            }
        }
    } catch (const std::exception& ex) {

        if (result.raw_output.size() < 10) {
            result.error_message = std::string("No packets matched the filter '") + display_filter +
                                   "'. TLS decryption may have failed - ensure the keylog file has valid keys for this capture.";
        } else {
            result.error_message = std::string("Failed to parse tshark JSON output: ") + ex.what();
        }
    }

    result.success = (result.decrypted_packets > 0);
    result.elapsed_ms = GetTickCount64() - start_ms;
    diag::log_tagged_fmt("net_sec", "tshark_decrypt parse_done success=%d total_packets=%u decrypted=%u http2_frames=%zu parse_ms=%llu elapsed_ms=%llu error=%s",
        result.success ? 1 : 0,
        result.total_packets,
        result.decrypted_packets,
        result.http2_frames.size(),
        static_cast<unsigned long long>(result.json_parse_elapsed_ms),
        static_cast<unsigned long long>(result.elapsed_ms),
        result.error_message.empty() ? "<none>" : result.error_message.c_str());

    return result;
}


bool TlsKeyExtractor::write_keylog_file(const std::string& path,
                                          const std::vector<tls_session_key_t>& keys, bool append) {
    std::ios_base::openmode mode = std::ios::out;
    if (append) mode |= std::ios::app;

    std::ofstream file(path, mode);
    if (!file.is_open()) return false;

    for (const auto& key : keys) {
        if (key.client_random.empty() || key.secret.empty()) continue;


        file << key.label << " "
             << bytes_to_hex(key.client_random.data(), key.client_random.size()) << " "
             << bytes_to_hex(key.secret.data(), key.secret.size()) << "\n";
    }

    file.flush();
    return file.good();
}

void TlsKeyExtractor::keylog_worker_loop(const char* mode, std::uint64_t generation) {
    keylog_config_t config;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        config = _keylog_config;
    }
    const DWORD tid = GetCurrentThreadId();
    _keylog_worker_tid.store(tid, std::memory_order_release);
    diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::worker enter mode=%s generation=%llu active=%d pid=%u output_file=%s poll_interval_ms=%u tid=%lu",
        mode ? mode : "",
        static_cast<unsigned long long>(generation),
        _keylog_active.load(std::memory_order_acquire) ? 1 : 0,
        config.pid,
        config.output_file.c_str(),
        config.poll_interval_ms,
        static_cast<unsigned long>(tid));
    try {
        while (_keylog_active.load(std::memory_order_acquire) &&
               _keylog_generation.load(std::memory_order_acquire) == generation) {
            tls_key_scan_config_t scan_cfg;
            scan_cfg.pid = config.pid;
            scan_cfg.scan_schannel = config.scan_schannel;
            scan_cfg.scan_openssl = config.scan_openssl;
            scan_cfg.scan_nss = config.scan_nss;
            scan_cfg.scan_boringssl = config.scan_boringssl;
            scan_cfg.scan_generic = config.scan_generic;
            scan_cfg.scan_tls13_structures = config.scan_tls13_structures;
            scan_cfg.max_results = config.max_results;
            scan_cfg.timeout_ms = config.scan_timeout_ms;
            scan_cfg.hint_address = config.hint_address;
            scan_cfg.hint_size = config.hint_size;
            scan_cfg.hint_only = config.hint_only;
            scan_cfg.cancel_flag = &_keylog_active;

            const ULONGLONG t0 = GetTickCount64();
            auto keys = extract_keys(scan_cfg);
            auto scan_diag = last_tls_scan_diagnostics();
            diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::worker scan_done mode=%s requested_pid=%u effective_pid=%u keys=%zu elapsed_ms=%llu scan_reason=%s deadline=%d cancelled=%d hint_used=%d generation=%llu",
                mode ? mode : "",
                scan_cfg.pid,
                scan_diag.effective_pid,
                keys.size(),
                static_cast<unsigned long long>(GetTickCount64() - t0),
                scan_diag.early_exit_reason.c_str(),
                scan_diag.deadline_expired ? 1 : 0,
                scan_diag.cancelled ? 1 : 0,
                scan_diag.hint_used ? 1 : 0,
                static_cast<unsigned long long>(generation));
            if (!keys.empty()) {
                const bool wrote = write_keylog_file(config.output_file, keys, config.append);
                diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::worker write_keylog mode=%s wrote=%d path=%s keys=%zu",
                    mode ? mode : "",
                    wrote ? 1 : 0,
                    config.output_file.c_str(),
                    keys.size());
            }

            const std::uint32_t poll_interval_ms = config.poll_interval_ms == 0 ? 50u : config.poll_interval_ms;
            for (std::uint32_t elapsed = 0;
                 elapsed < poll_interval_ms &&
                 _keylog_active.load(std::memory_order_acquire) &&
                 _keylog_generation.load(std::memory_order_acquire) == generation;
                 elapsed += 50) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::worker exception mode=%s err=%s",
            mode ? mode : "", ex.what());
    } catch (...) {
        diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::worker exception mode=%s err=unknown",
            mode ? mode : "");
    }
    const bool current_generation = _keylog_generation.load(std::memory_order_acquire) == generation;
    if (current_generation)
        _keylog_worker_done.store(true, std::memory_order_release);
    _keylog_worker_tid.store(0, std::memory_order_release);
    _keylog_worker_cv.notify_all();
    diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::worker exit mode=%s generation=%llu current=%d active=%d tid=%lu",
        mode ? mode : "",
        static_cast<unsigned long long>(generation),
        current_generation ? 1 : 0,
        _keylog_active.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long>(tid));
}

bool TlsKeyExtractor::wait_keylog_worker_done(std::uint64_t generation, DWORD timeout_ms) {
    std::unique_lock<std::mutex> lock(_keylog_worker_mutex);
    const bool signaled = _keylog_worker_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this, generation]() {
        return _keylog_worker_done.load(std::memory_order_acquire) ||
               _keylog_generation.load(std::memory_order_acquire) != generation;
    });
    return signaled &&
           _keylog_generation.load(std::memory_order_acquire) == generation &&
           _keylog_worker_done.load(std::memory_order_acquire);
}

bool TlsKeyExtractor::start_keylog(const keylog_config_t& config) {
    std::lock_guard<std::mutex> lifecycle_lock(_keylog_lifecycle_mutex);
    diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::start_keylog entry active=%d pid=%u output_file=%s poll_interval_ms=%u append=%d tid=%lu",
        _keylog_active.load(std::memory_order_acquire) ? 1 : 0,
        config.pid,
        config.output_file.c_str(),
        config.poll_interval_ms,
        config.append ? 1 : 0,
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (_keylog_active.load(std::memory_order_acquire)) {
        diag::log_tagged("net_sec", "TlsKeyExtractor::start_keylog rejected active=1");
        return false;
    }

    if (!_keylog_worker_done.load(std::memory_order_acquire)) {
        const std::uint64_t previous_generation = _keylog_generation.load(std::memory_order_acquire);
        const ULONGLONG wait_start = GetTickCount64();
        const bool previous_done = wait_keylog_worker_done(previous_generation, 1000);
        diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::start_keylog previous_worker_done=%d generation=%llu elapsed_ms=%llu",
            previous_done ? 1 : 0,
            static_cast<unsigned long long>(previous_generation),
            static_cast<unsigned long long>(GetTickCount64() - wait_start));
        if (!previous_done)
            return false;
    }

    {
        std::lock_guard<std::mutex> lock(_mutex);
        _keylog_config = config;
    }
    _keylog_active.store(true, std::memory_order_release);
    const std::uint64_t generation = _keylog_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    _keylog_worker_done.store(false, std::memory_order_release);
    _keylog_worker_tid.store(0, std::memory_order_release);

    bool worker_started = false;
    DWORD post_err = ERROR_SUCCESS;
    try {
        worker_started = work_queue::post_service([this, generation]() {
            keylog_worker_loop("work_queue_service", generation);
        });
        post_err = GetLastError();
    } catch (const std::exception& ex) {
        post_err = GetLastError();
        if (post_err == ERROR_SUCCESS)
            post_err = ERROR_NOT_ENOUGH_MEMORY;
        diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::start_keylog worker_post_exception generation=%llu gle=%lu err=%s",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(post_err),
            ex.what());
    } catch (...) {
        post_err = GetLastError();
        if (post_err == ERROR_SUCCESS)
            post_err = ERROR_NOT_ENOUGH_MEMORY;
        diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::start_keylog worker_post_exception generation=%llu gle=%lu err=unknown",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(post_err));
    }
    if (!worker_started) {
        if (post_err == ERROR_SUCCESS)
            post_err = ERROR_NOT_READY;
        _keylog_active.store(false, std::memory_order_release);
        _keylog_worker_done.store(true, std::memory_order_release);
        _keylog_worker_cv.notify_all();
        diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::start_keylog worker_post_failed generation=%llu gle=%lu",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(post_err));
        return false;
    }

    diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::start_keylog started generation=%llu",
        static_cast<unsigned long long>(generation));
    return true;
}

bool TlsKeyExtractor::stop_keylog() {
    std::lock_guard<std::mutex> lifecycle_lock(_keylog_lifecycle_mutex);
    const ULONGLONG t0 = GetTickCount64();
    const std::uint64_t generation = _keylog_generation.load(std::memory_order_acquire);
    keylog_config_t config;
    {
        std::unique_lock<std::mutex> lock(_mutex, std::try_to_lock);
        if (lock.owns_lock())
            config = _keylog_config;
        else
            config.stop_wait_ms = 350;
    }
    const DWORD wait_ms = static_cast<DWORD>(std::max<std::uint32_t>(50, std::min<std::uint32_t>(config.stop_wait_ms, 5000)));
    diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::stop_keylog entry active=%d worker_done=%d generation=%llu worker_tid=%lu tid=%lu",
        _keylog_active.load(std::memory_order_acquire) ? 1 : 0,
        _keylog_worker_done.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(_keylog_worker_tid.load(std::memory_order_acquire)),
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (!_keylog_active.load(std::memory_order_acquire)) {
        if (!_keylog_worker_done.load(std::memory_order_acquire)) {
            const bool done = wait_keylog_worker_done(generation, wait_ms);
            diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::stop_keylog inactive_worker_done=%d generation=%llu wait_ms=%lu elapsed_ms=%llu",
                done ? 1 : 0,
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long>(wait_ms),
                static_cast<unsigned long long>(GetTickCount64() - t0));
        } else {
            diag::log_tagged("net_sec", "TlsKeyExtractor::stop_keylog rejected active=0");
        }
        return false;
    }
    _keylog_active.store(false, std::memory_order_release);
    const bool done = wait_keylog_worker_done(generation, wait_ms);
    diag::log_tagged_fmt("net_sec", "TlsKeyExtractor::stop_keylog worker_done=%d generation=%llu worker_tid=%lu wait_ms=%lu elapsed_ms=%llu",
        done ? 1 : 0,
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(_keylog_worker_tid.load(std::memory_order_acquire)),
        static_cast<unsigned long>(wait_ms),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return done;
}


CertificateInjector& CertificateInjector::instance() {
    static CertificateInjector inst;
    return inst;
}

cert_injection_result_t CertificateInjector::inject_certificate(const cert_injection_config_t& config) {
    const ULONGLONG t0 = GetTickCount64();
    cert_injection_result_t result;
    diag::log_tagged_fmt("net_sec", "inject_certificate entry store=%s system_wide=%d der_size=%zu pem_len=%zu tid=%lu",
        config.store_name.c_str(),
        config.system_wide ? 1 : 0,
        config.cert_der.size(),
        config.cert_pem.size(),
        static_cast<unsigned long>(GetCurrentThreadId()));

    std::vector<std::uint8_t> cert_data;
    if (!config.cert_der.empty()) {
        cert_data = config.cert_der;
    } else if (!config.cert_pem.empty()) {

        DWORD der_size = 0;
        diag::log_tagged_fmt("net_sec", "inject_certificate CryptStringToBinary size enter elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        if (!CryptStringToBinaryA(config.cert_pem.c_str(), static_cast<DWORD>(config.cert_pem.size()),
                                  CRYPT_STRING_BASE64HEADER, nullptr, &der_size, nullptr, nullptr) || der_size == 0) {
            diag::log_tagged_fmt("net_sec", "inject_certificate CryptStringToBinary size failed gle=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            result.success = false;
            return result;
        }
        cert_data.resize(der_size);
        diag::log_tagged_fmt("net_sec", "inject_certificate CryptStringToBinary data enter der_size=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(der_size),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        if (!CryptStringToBinaryA(config.cert_pem.c_str(), static_cast<DWORD>(config.cert_pem.size()),
                                  CRYPT_STRING_BASE64HEADER, cert_data.data(), &der_size, nullptr, nullptr)) {
            diag::log_tagged_fmt("net_sec", "inject_certificate CryptStringToBinary data failed gle=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            result.success = false;
            return result;
        }
        cert_data.resize(der_size);
    } else {
        diag::log_tagged("net_sec", "inject_certificate rejected empty certificate data");
        result.success = false;
        return result;
    }


    diag::log_tagged_fmt("net_sec", "inject_certificate CertCreateCertificateContext enter der_size=%zu elapsed_ms=%llu",
        cert_data.size(),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    PCCERT_CONTEXT cert_ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        cert_data.data(), static_cast<DWORD>(cert_data.size()));
    if (!cert_ctx) {
        diag::log_tagged_fmt("net_sec", "inject_certificate CertCreateCertificateContext failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(GetLastError()),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        result.success = false;
        return result;
    }


    BYTE thumb[20] = {};
    DWORD thumb_size = 20;
    diag::log_tagged_fmt("net_sec", "inject_certificate CryptHashCertificate enter elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!CryptHashCertificate(0, CALG_SHA1, 0, cert_ctx->pbCertEncoded,
                              cert_ctx->cbCertEncoded, thumb, &thumb_size)) {
        diag::log_tagged_fmt("net_sec", "inject_certificate CryptHashCertificate failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(GetLastError()),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        CertFreeCertificateContext(cert_ctx);
        return result;
    }
    result.thumbprint = bytes_to_hex_upper(thumb, thumb_size);


    char subject_buf[256] = {};
    CertGetNameStringA(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                       subject_buf, sizeof(subject_buf));
    result.subject_cn = subject_buf;


    std::string store_name = config.store_name.empty() ? "ROOT" : config.store_name;
    result.store_name = store_name;


    if (!valid_cert_store_name_text(store_name)) {
        diag::log_tagged_fmt("net_sec", "inject_certificate invalid_store store=%s elapsed_ms=%llu",
            store_name.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        CertFreeCertificateContext(cert_ctx);
        result.success = false;
        return result;
    }

    std::wstring temp_cert_path;
    DWORD temp_gle = ERROR_SUCCESS;
    diag::log_tagged_fmt("net_sec", "inject_certificate temp_write enter store=%s der_size=%zu elapsed_ms=%llu",
        store_name.c_str(),
        cert_data.size(),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!write_temp_cert_der_file_text(cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded, temp_cert_path, temp_gle)) {
        diag::log_tagged_fmt("net_sec", "inject_certificate temp_write failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(temp_gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        CertFreeCertificateContext(cert_ctx);
        result.success = false;
        return result;
    }

    DWORD add_exit = 0;
    DWORD add_gle = ERROR_SUCCESS;
    DWORD add_elapsed = 0;
    diag::log_tagged_fmt("net_sec", "inject_certificate certutil_add enter store=%s system_wide=%d elapsed_ms=%llu",
        store_name.c_str(),
        config.system_wide ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - t0));
    const bool add_ok = run_certutil_store_add_text(config.system_wide, store_name, temp_cert_path, add_exit, add_gle, add_elapsed);
    diag::log_tagged_fmt("net_sec", "inject_certificate certutil_add result ok=%d exit=%lu gle=%lu child_elapsed_ms=%lu elapsed_ms=%llu",
        add_ok ? 1 : 0,
        static_cast<unsigned long>(add_exit),
        static_cast<unsigned long>(add_gle),
        static_cast<unsigned long>(add_elapsed),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    DeleteFileW(temp_cert_path.c_str());

    DWORD probe_exit = 0;
    DWORD probe_gle = ERROR_SUCCESS;
    DWORD probe_elapsed = 0;
    const bool probe_ok = add_ok &&
        run_certutil_store_probe_text(config.system_wide, store_name, result.thumbprint, probe_exit, probe_gle, probe_elapsed);
    diag::log_tagged_fmt("net_sec", "inject_certificate certutil_probe result ok=%d exit=%lu gle=%lu child_elapsed_ms=%lu elapsed_ms=%llu",
        probe_ok ? 1 : 0,
        static_cast<unsigned long>(probe_exit),
        static_cast<unsigned long>(probe_gle),
        static_cast<unsigned long>(probe_elapsed),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    if (add_ok && probe_ok) {
        result.success = true;
        result.method = config.system_wide ? "CertUtilSystemStore" : "CertUtilUserStore";
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _injected.push_back(result.thumbprint);
        }
        diag::log_tagged_fmt("net_sec", "inject_certificate certutil ok thumbprint_len=%zu elapsed_ms=%llu",
            result.thumbprint.size(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
    } else {
        diag::log_tagged_fmt("net_sec", "inject_certificate certutil failed add_ok=%d probe_ok=%d elapsed_ms=%llu",
            add_ok ? 1 : 0,
            probe_ok ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - t0));
    }

    CertFreeCertificateContext(cert_ctx);
    diag::log_tagged_fmt("net_sec", "inject_certificate exit success=%d elapsed_ms=%llu",
        result.success ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return result;
}

bool CertificateInjector::remove_certificate(const std::string& thumbprint, const std::string& store_name) {
    const ULONGLONG t0 = GetTickCount64();
    diag::log_tagged_fmt("net_sec", "remove_certificate entry thumbprint_len=%zu store=%s tid=%lu",
        thumbprint.size(), store_name.c_str(), static_cast<unsigned long>(GetCurrentThreadId()));

    std::string sn = store_name.empty() ? "ROOT" : store_name;
    if (!valid_cert_store_name_text(sn) || thumbprint.empty()) {
        diag::log_tagged_fmt("net_sec", "remove_certificate invalid_input store=%s thumbprint_len=%zu elapsed_ms=%llu",
            sn.c_str(),
            thumbprint.size(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }

    DWORD del_exit = 0;
    DWORD del_gle = ERROR_SUCCESS;
    DWORD del_elapsed = 0;
    diag::log_tagged_fmt("net_sec", "remove_certificate certutil_delete enter store=%s elapsed_ms=%llu",
        sn.c_str(),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    bool removed = run_certutil_store_delete_text(false, sn, thumbprint, del_exit, del_gle, del_elapsed);
    diag::log_tagged_fmt("net_sec", "remove_certificate certutil_delete result ok=%d exit=%lu gle=%lu child_elapsed_ms=%lu elapsed_ms=%llu",
        removed ? 1 : 0,
        static_cast<unsigned long>(del_exit),
        static_cast<unsigned long>(del_gle),
        static_cast<unsigned long>(del_elapsed),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    if (removed) {
        std::lock_guard<std::mutex> lock(_mutex);
        _injected.erase(
            std::remove(_injected.begin(), _injected.end(), thumbprint),
            _injected.end());
    }
    diag::log_tagged_fmt("net_sec", "remove_certificate exit removed=%d elapsed_ms=%llu",
        removed ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return removed;
}

bool CertificateInjector::generate_ca_certificate(const std::string& cn, std::uint32_t validity_days,
                                                    std::vector<std::uint8_t>& out_cert_der,
                                                    std::vector<std::uint8_t>& out_key_der,
                                                    bool export_private_key) {
    const ULONGLONG t0 = GetTickCount64();
    out_cert_der.clear();
    out_key_der.clear();

    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;

    diag::log_tagged_fmt("net_sec", "generate_ca_certificate entry cn_len=%zu validity_days=%u export_private_key=%d tid=%lu",
        cn.size(), validity_days, export_private_key ? 1 : 0, static_cast<unsigned long>(GetCurrentThreadId()));

    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptAcquireContext enter elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!CryptAcquireContextA(&hProv, nullptr, nullptr,
                               PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptAcquireContext failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }
    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptAcquireContext ok elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));


    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptGenKey enter elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!CryptGenKey(hProv, AT_SIGNATURE, (2048u << 16) | CRYPT_EXPORTABLE, &hKey)) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptGenKey failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        CryptReleaseContext(hProv, 0);
        return false;
    }
    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptGenKey ok elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));


    std::string subject = "CN=" + cn;
    DWORD encoded_size = 0;
    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CertStrToName size enter subject_len=%zu elapsed_ms=%llu",
        subject.size(),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!CertStrToNameA(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR,
                   nullptr, nullptr, &encoded_size, nullptr) || encoded_size == 0) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("net_sec", "generate_ca_certificate CertStrToName size failed gle=%lu subject_len=%zu elapsed_ms=%llu",
            static_cast<unsigned long>(gle), subject.size(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }
    std::vector<BYTE> encoded_name(encoded_size);
    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CertStrToName encode enter encoded_size=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(encoded_size),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!CertStrToNameA(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR,
                   nullptr, encoded_name.data(), &encoded_size, nullptr)) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("net_sec", "generate_ca_certificate CertStrToName encode failed gle=%lu encoded_size=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(gle), static_cast<unsigned long>(encoded_size),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }
    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CertStrToName ok encoded_size=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(encoded_size),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    CERT_NAME_BLOB name_blob;
    name_blob.cbData = encoded_size;
    name_blob.pbData = encoded_name.data();


    SYSTEMTIME now_sys, expiry_sys;
    GetSystemTime(&now_sys);
    FILETIME ft;
    SystemTimeToFileTime(&now_sys, &ft);
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    ul.QuadPart += static_cast<ULONGLONG>(validity_days) * 24ULL * 3600ULL * 10000000ULL;
    ft.dwLowDateTime = ul.LowPart;
    ft.dwHighDateTime = ul.HighPart;
    FileTimeToSystemTime(&ft, &expiry_sys);


    CRYPT_KEY_PROV_INFO kpi = {};
    kpi.pwszContainerName = nullptr;
    kpi.dwProvType = PROV_RSA_FULL;
    kpi.dwKeySpec = AT_SIGNATURE;

    CRYPT_ALGORITHM_IDENTIFIER algo = {};
    algo.pszObjId = const_cast<char*>(szOID_RSA_SHA256RSA);


    CERT_BASIC_CONSTRAINTS2_INFO bc = {};
    bc.fCA = TRUE;
    bc.fPathLenConstraint = FALSE;

    BYTE bc_encoded[32] = {};
    DWORD bc_encoded_size = sizeof(bc_encoded);
    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptEncodeObject enter elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                      &bc, bc_encoded, &bc_encoded_size)) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptEncodeObject failed gle=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    CERT_EXTENSION ext = {};
    ext.pszObjId = const_cast<char*>(szOID_BASIC_CONSTRAINTS2);
    ext.fCritical = TRUE;
    ext.Value.cbData = bc_encoded_size;
    ext.Value.pbData = bc_encoded;

    CERT_EXTENSIONS exts = {};
    exts.cExtension = 1;
    exts.rgExtension = &ext;

    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CertCreateSelfSignCertificate enter elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - t0));
    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(
        hProv, &name_blob, 0, &kpi, &algo,
        &now_sys, &expiry_sys, &exts);
    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CertCreateSelfSignCertificate cert=%p gle=%lu elapsed_ms=%llu",
        cert,
        static_cast<unsigned long>(cert ? 0 : GetLastError()),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    if (cert) {
        out_cert_der.assign(cert->pbCertEncoded, cert->pbCertEncoded + cert->cbCertEncoded);


        out_key_der.clear();
        if (export_private_key) {
            DWORD key_blob_size = 0;
            diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptExportKey size enter elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - t0));
            if (CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, nullptr, &key_blob_size)) {
                out_key_der.resize(key_blob_size);
                diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptExportKey data enter key_blob_size=%lu elapsed_ms=%llu",
                    static_cast<unsigned long>(key_blob_size),
                    static_cast<unsigned long long>(GetTickCount64() - t0));
                if (CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, out_key_der.data(), &key_blob_size)) {
                    out_key_der.resize(key_blob_size);
                } else {
                    DWORD gle = GetLastError();
                    diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptExportKey data failed gle=%lu elapsed_ms=%llu",
                        static_cast<unsigned long>(gle),
                        static_cast<unsigned long long>(GetTickCount64() - t0));
                    SecureZeroMemory(out_key_der.data(), out_key_der.size());
                    out_key_der.clear();
                }
            } else {
                DWORD gle = GetLastError();
                diag::log_tagged_fmt("net_sec", "generate_ca_certificate CryptExportKey size failed gle=%lu elapsed_ms=%llu",
                    static_cast<unsigned long>(gle),
                    static_cast<unsigned long long>(GetTickCount64() - t0));
            }
        }

        CertFreeCertificateContext(cert);
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    diag::log_tagged_fmt("net_sec", "generate_ca_certificate exit ok=%d cert_size=%zu key_exported=%d key_size=%zu elapsed_ms=%llu",
        out_cert_der.empty() ? 0 : 1,
        out_cert_der.size(),
        out_key_der.empty() ? 0 : 1,
        out_key_der.size(),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    return !out_cert_der.empty();
}

std::vector<CertificateInjector::cert_info_t> CertificateInjector::list_certificates(const std::string& store_name) {
    std::vector<cert_info_t> result;

    std::string sn = store_name.empty() ? "ROOT" : store_name;
    std::wstring store_name_w(sn.begin(), sn.end());

    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
        store_name_w.c_str());
    if (!hStore) return result;

    PCCERT_CONTEXT ctx = nullptr;
    while ((ctx = CertEnumCertificatesInStore(hStore, ctx)) != nullptr) {
        cert_info_t info;

        BYTE thumb[20] = {};
        DWORD thumb_size = 20;
        CryptHashCertificate(0, CALG_SHA1, 0, ctx->pbCertEncoded,
                             ctx->cbCertEncoded, thumb, &thumb_size);
        info.thumbprint = bytes_to_hex_upper(thumb, thumb_size);

        char buf[256] = {};
        CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf, sizeof(buf));
        info.subject = buf;

        CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, buf, sizeof(buf));
        info.issuer = buf;

        SYSTEMTIME st;
        FileTimeToSystemTime(&ctx->pCertInfo->NotBefore, &st);
        char time_buf[64];
        std::snprintf(time_buf, sizeof(time_buf), "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
        info.not_before = time_buf;

        FileTimeToSystemTime(&ctx->pCertInfo->NotAfter, &st);
        std::snprintf(time_buf, sizeof(time_buf), "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
        info.not_after = time_buf;


        PCERT_EXTENSION bc_ext = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
            ctx->pCertInfo->cExtension, ctx->pCertInfo->rgExtension);
        if (bc_ext) {
            CERT_BASIC_CONSTRAINTS2_INFO bc = {};
            DWORD bc_size = sizeof(bc);
            if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                                  bc_ext->Value.pbData, bc_ext->Value.cbData, 0, &bc, &bc_size)) {
                info.is_ca = (bc.fCA != 0);
            }
        }

        result.push_back(std::move(info));
    }

    CertCloseStore(hStore, 0);
    return result;
}


CertPinBypasser& CertPinBypasser::instance() {
    static CertPinBypasser inst;
    return inst;
}

namespace {

std::string pin_method_name(pin_bypass_method method) {
    switch (method) {
    case pin_bypass_method::windows_trust: return "windows_trust";
    case pin_bypass_method::windows_chain_policy: return "windows_chain_policy";
    case pin_bypass_method::windows_tls: return "windows_tls";
    case pin_bypass_method::managed_dotnet: return "managed_dotnet";
    default: return "all";
    }
}

std::vector<std::string> requested_pin_methods(pin_bypass_method method) {
    if (method != pin_bypass_method::all) return { pin_method_name(method) };
    return {
        pin_method_name(pin_bypass_method::windows_trust),
        pin_method_name(pin_bypass_method::windows_chain_policy),
        pin_method_name(pin_bypass_method::windows_tls),
        pin_method_name(pin_bypass_method::managed_dotnet)
    };
}

}

pin_bypass_result_t CertPinBypasser::bypass_pins(const pin_bypass_config_t& config) {
    pin_bypass_result_t result;

    std::uint32_t pid = config.pid;
    if (pid == 0 && device && device->is_connected())
        pid = device->get_process_id();

    result.success = false;
    result.read_only = true;
    result.legacy_patching_disabled = true;
    result.methods_requested = requested_pin_methods(config.method);
    result.disabled_operations = {
        "target_process_code_writes",
        "certificate_verification_force_success",
        "browser_tls_internal_scanning",
        "managed_runtime_flag_rewrites"
    };
    result.diagnostic_summary = pid == 0
        ? "No target process was selected; normal certificate interception uses proxy, trust, Camoufox, and provider diagnostics"
        : "Legacy in-process certificate validation modification is disabled for normal builds";
    result.recommended_action = "Use cert_intercept diagnostics, controlled Camoufox launch, or script handoff for explicit authorized analysis";
    return result;
}

bool CertPinBypasser::revert_bypass(std::uint32_t pid) {
    std::vector<patch_record_t> records;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _active_patches.find(pid);
        if (it == _active_patches.end()) return false;
        records = it->second;
    }

    if (!device || !device->is_connected()) return false;

    std::uint32_t saved_pid = device->get_process_id();
    device->set_process_id(pid);
    device->solve_dtb();

    bool all_ok = true;
    for (const auto& patch : records) {
        device->protect_memory(patch.address, 4096, 0x40);
        if (device->write_raw(patch.address, patch.original_bytes.data(),
                               patch.original_bytes.size()) != patch.original_bytes.size()) {
            all_ok = false;
        }
    }

    device->set_process_id(saved_pid);
    if (saved_pid != 0) device->solve_dtb();

    {
        std::lock_guard<std::mutex> lock(_mutex);
        _active_patches.erase(pid);
    }
    return all_ok;
}

bool CertPinBypasser::is_bypass_active(std::uint32_t pid) const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _active_patches.find(pid) != _active_patches.end();
}


QuicAnalyzer& QuicAnalyzer::instance() {
    static QuicAnalyzer inst;
    return inst;
}

bool QuicAnalyzer::parse_quic_header(const std::uint8_t* data, std::size_t len, quic_header_t& out) {
    if (len < 1) return false;

    out.is_long_header = (data[0] & 0x80) != 0;

    if (out.is_long_header) {

        if (len < 7) return false;

        out.packet_type = (data[0] >> 4) & 0x03;
        out.version = (static_cast<std::uint32_t>(data[1]) << 24) |
                      (static_cast<std::uint32_t>(data[2]) << 16) |
                      (static_cast<std::uint32_t>(data[3]) << 8) |
                       static_cast<std::uint32_t>(data[4]);

        std::size_t pos = 5;
        std::uint8_t dcid_len = data[pos++];
        if (pos + dcid_len > len) return false;
        out.dcid.assign(data + pos, data + pos + dcid_len);
        pos += dcid_len;

        if (pos >= len) return false;
        std::uint8_t scid_len = data[pos++];
        if (pos + scid_len > len) return false;
        out.scid.assign(data + pos, data + pos + scid_len);
        pos += scid_len;


        if (out.packet_type == 0) {

            if (pos >= len) return false;
            std::uint8_t first_byte = data[pos++];
            std::uint8_t len_bytes = 1 << (first_byte >> 6);
            out.token_length = first_byte & 0x3F;
            for (std::uint8_t b = 1; b < len_bytes && pos < len; b++) {
                out.token_length = (out.token_length << 8) | data[pos++];
            }
            pos += out.token_length;


            if (pos >= len) return false;
            first_byte = data[pos++];
            len_bytes = 1 << (first_byte >> 6);
            out.payload_length = first_byte & 0x3F;
            for (std::uint8_t b = 1; b < len_bytes && pos < len; b++) {
                out.payload_length = (out.payload_length << 8) | data[pos++];
            }
        }
        return true;
    } else {


        out.packet_type = 0xFF;

        if (len >= 1) {

            std::size_t dcid_len = std::min(len - 1, static_cast<std::size_t>(20));
            out.dcid.assign(data + 1, data + 1 + dcid_len);
        }
        return true;
    }
}

std::vector<quic_connection_info_t> QuicAnalyzer::detect_quic_connections(std::uint32_t filter_pid) {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<quic_connection_info_t> connections;

    if (!device || !device->is_connected()) return connections;

    bool cap_active = false;
    std::uint32_t cap_cnt = 0, cap_drp = 0;
    device->get_capture_status(cap_active, cap_cnt, cap_drp);
    if (!cap_active)
        device->start_capture(filter_pid, 0, 17);

    auto dpi_results = device->get_dpi_results(filter_pid, 17, 0, 0);

    auto packets = device->get_captured_packets(32);

    std::map<std::string, quic_connection_info_t> conn_map;

    for (const auto& pkt : packets) {
        if (pkt.protocol != 17) continue;
        if (pkt.payload.size() < 5) continue;

        quic_header_t hdr;
        std::size_t quic_offset = 0;
        bool parsed = parse_quic_header(pkt.payload.data(), pkt.payload.size(), hdr);
        if (!parsed || !hdr.is_long_header) {
            const std::size_t scan_limit = std::min<std::size_t>(pkt.payload.size(), 96);
            for (std::size_t off = 1; off + 5 < scan_limit; ++off) {
                if ((pkt.payload[off] & 0xC0) != 0xC0)
                    continue;
                quic_header_t candidate;
                if (!parse_quic_header(pkt.payload.data() + off, pkt.payload.size() - off, candidate))
                    continue;
                if (!candidate.is_long_header || candidate.version == 0 || candidate.dcid.empty())
                    continue;
                hdr = std::move(candidate);
                quic_offset = off;
                parsed = true;
                break;
            }
        }
        if (!parsed) continue;
        if (!hdr.is_long_header && hdr.dcid.empty()) continue;
        diag::log_tagged_fmt("net_sec", "quic_detect packet pid=%u payload=%zu offset=%zu long=%d version=0x%08X dcid=%zu scid=%zu",
            pkt.pid,
            pkt.payload.size(),
            quic_offset,
            hdr.is_long_header ? 1 : 0,
            hdr.version,
            hdr.dcid.size(),
            hdr.scid.size());


        std::string key = bytes_to_hex(pkt.local_addr, 4) + ":" +
                          std::to_string(pkt.local_port) + "-" +
                          bytes_to_hex(pkt.remote_addr, 4) + ":" +
                          std::to_string(pkt.remote_port);

        auto& conn = conn_map[key];
        conn.pid = pkt.pid;
        std::memcpy(conn.src_addr, pkt.local_addr, 16);
        std::memcpy(conn.dst_addr, pkt.remote_addr, 16);
        conn.src_port = pkt.local_port;
        conn.dst_port = pkt.remote_port;
        conn.address_family = pkt.address_family;

        if (hdr.is_long_header) {
            std::memcpy(conn.version, &hdr.version, 4);
            conn.dcid = hdr.dcid;
            conn.scid = hdr.scid;
        }

        if (pkt.direction == 1) {
            conn.packets_sent++;
            conn.bytes_sent += pkt.payload_size;
        } else {
            conn.packets_recv++;
            conn.bytes_recv += pkt.payload_size;
        }

        if (hdr.version != 0) {
            conn.tls_version = 0x0304;
        }
    }

    for (auto& [k, conn] : conn_map) {
        conn.alpn = "h3";
        connections.push_back(std::move(conn));
    }

    return connections;
}

quic_initial_decrypt_result_t QuicAnalyzer::decrypt_initial_packet(
    const std::uint8_t* packet_data, std::size_t packet_len) {

    std::lock_guard<std::mutex> lock(_mutex);
    quic_initial_decrypt_result_t result;

    if (!packet_data || packet_len < 20) {
        result.success = false;
        return result;
    }

    quic_header_t hdr;
    if (!parse_quic_header(packet_data, packet_len, hdr) || !hdr.is_long_header) {
        result.success = false;
        return result;
    }

    if (hdr.packet_type != 0) {
        result.success = false;
        return result;
    }

    result.quic_version = hdr.version;
    result.dcid = hdr.dcid;
    result.scid = hdr.scid;
    result.packet_type = "Initial";

    std::uint8_t client_key[16], client_iv[12], client_hp[16];
    std::uint8_t server_key[16], server_iv[12], server_hp[16];

    if (!derive_initial_keys(hdr.dcid.data(), hdr.dcid.size(), hdr.version,
                              client_key, client_iv, client_hp,
                              server_key, server_iv, server_hp)) {
        result.success = true;
        result.packet_number = 0;
        return result;
    }


    std::size_t pn_offset = 7 + hdr.dcid.size() + hdr.scid.size();


    if (pn_offset < packet_len) {
        std::size_t tpos = pn_offset;
        std::uint8_t first = packet_data[tpos];
        std::uint8_t len_bytes = static_cast<std::uint8_t>(1u << (first >> 6));
        std::uint64_t token_len = first & 0x3F;
        tpos++;
        for (std::uint8_t b = 1; b < len_bytes && tpos < packet_len; b++) {
            token_len = (token_len << 8) | packet_data[tpos++];
        }
        tpos += static_cast<std::size_t>(token_len);


        if (tpos < packet_len) {
            first = packet_data[tpos];
            len_bytes = static_cast<std::uint8_t>(1u << (first >> 6));
            tpos++;
            for (std::uint8_t b = 1; b < len_bytes && tpos < packet_len; b++) {
                tpos++;
            }
        }
        pn_offset = tpos;
    }

    if (pn_offset + 4 + 16 > packet_len) {
        result.success = true;
        result.packet_number = 0;
        return result;
    }


    std::uint8_t sample[16];
    std::memcpy(sample, packet_data + pn_offset + 4, 16);

    std::uint8_t mask[16];
    if (!aes_ecb_encrypt(client_hp, sample, mask)) {
        result.success = true;
        result.packet_number = 0;
        return result;
    }


    std::vector<std::uint8_t> pkt(packet_data, packet_data + packet_len);


    pkt[0] ^= (mask[0] & 0x0F);

    std::uint8_t pn_length = (pkt[0] & 0x03) + 1;


    for (std::uint8_t i = 0; i < pn_length && (pn_offset + i) < pkt.size(); i++) {
        pkt[pn_offset + i] ^= mask[1 + i];
    }


    std::uint64_t pn = 0;
    for (std::uint8_t i = 0; i < pn_length; i++) {
        pn = (pn << 8) | pkt[pn_offset + i];
    }
    result.packet_number = pn;


    std::uint8_t nonce[12];
    std::memcpy(nonce, client_iv, 12);
    for (std::uint8_t i = 0; i < 8; i++) {
        nonce[11 - i] ^= static_cast<std::uint8_t>((pn >> (8 * i)) & 0xFF);
    }

    std::size_t aad_len = pn_offset + pn_length;
    std::size_t ciphertext_offset = aad_len;
    if (ciphertext_offset + 16 > pkt.size()) {
        result.success = true;
        return result;
    }
    std::size_t ciphertext_len = pkt.size() - ciphertext_offset;


    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                              static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0) == 0) {

            DWORD key_obj_size = 0, cb = 0;
            BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&key_obj_size), sizeof(key_obj_size), &cb, 0);
            std::vector<std::uint8_t> key_obj(key_obj_size);

            if (BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj.data(), key_obj_size,
                                            const_cast<PUCHAR>(client_key), 16, 0) == 0) {


                std::size_t payload_len = ciphertext_len - 16;
                std::uint8_t tag[16];
                std::memcpy(tag, pkt.data() + ciphertext_offset + payload_len, 16);

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
                BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
                authInfo.pbNonce = nonce;
                authInfo.cbNonce = 12;
                authInfo.pbAuthData = pkt.data();
                authInfo.cbAuthData = static_cast<ULONG>(aad_len);
                authInfo.pbTag = tag;
                authInfo.cbTag = 16;

                result.decrypted_payload.resize(payload_len);
                ULONG decrypted_len = 0;

                NTSTATUS status = BCryptDecrypt(
                    hKey, pkt.data() + ciphertext_offset, static_cast<ULONG>(payload_len),
                    &authInfo, nullptr, 0,
                    result.decrypted_payload.data(), static_cast<ULONG>(payload_len),
                    &decrypted_len, 0);

                if (status == 0) {
                    result.decrypted_payload.resize(decrypted_len);


                    std::size_t pos = 0;
                    while (pos < result.decrypted_payload.size()) {
                        std::uint8_t frame_type = result.decrypted_payload[pos];
                        if (frame_type == 0x00) { pos++; continue; }
                        if (frame_type == 0x06) {
                            pos++;

                            if (pos >= result.decrypted_payload.size()) break;
                            std::uint8_t fb = result.decrypted_payload[pos];
                            std::uint8_t vlen = static_cast<std::uint8_t>(1u << (fb >> 6));
                            pos++;
                            for (std::uint8_t v = 1; v < vlen && pos < result.decrypted_payload.size(); v++) {
                                pos++;
                            }

                            if (pos >= result.decrypted_payload.size()) break;
                            fb = result.decrypted_payload[pos];
                            vlen = static_cast<std::uint8_t>(1u << (fb >> 6));
                            std::uint64_t crypto_len = fb & 0x3F;
                            pos++;
                            for (std::uint8_t v = 1; v < vlen && pos < result.decrypted_payload.size(); v++) {
                                crypto_len = (crypto_len << 8) | result.decrypted_payload[pos++];
                            }

                            if (pos + crypto_len <= result.decrypted_payload.size()) {
                                result.crypto_frame_hex = bytes_to_hex(
                                    result.decrypted_payload.data() + pos,
                                    static_cast<std::size_t>(crypto_len));
                            }
                            break;
                        }
                        break;
                    }
                } else {
                    result.decrypted_payload.clear();
                }

                BCryptDestroyKey(hKey);
            }
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    SecureZeroMemory(client_key, sizeof(client_key));
    SecureZeroMemory(client_iv, sizeof(client_iv));
    SecureZeroMemory(client_hp, sizeof(client_hp));
    SecureZeroMemory(server_key, sizeof(server_key));
    SecureZeroMemory(server_iv, sizeof(server_iv));
    SecureZeroMemory(server_hp, sizeof(server_hp));

    result.success = true;
    return result;
}

bool QuicAnalyzer::derive_initial_keys(const std::uint8_t* dcid, std::size_t dcid_len,
                                         std::uint32_t version,
                                         std::uint8_t* client_key, std::uint8_t* client_iv, std::uint8_t* client_hp,
                                         std::uint8_t* server_key, std::uint8_t* server_iv, std::uint8_t* server_hp) {

    if (!dcid || dcid_len == 0) return false;


    const std::uint8_t salt_v1[] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    const std::uint8_t salt_v2[] = {
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
    };

    const std::uint8_t* salt;
    std::size_t salt_len;

    if (version == 0x6b3343cf) {
        salt = salt_v2;
        salt_len = sizeof(salt_v2);
    } else {
        salt = salt_v1;
        salt_len = sizeof(salt_v1);
    }

    std::uint8_t initial_secret[32];
    if (!hkdf_extract(salt, salt_len, dcid, dcid_len, initial_secret))
        return false;

    std::uint8_t client_secret[32];
    if (!hkdf_expand_label(initial_secret, "client in", 9, nullptr, 0, client_secret, 32))
        return false;

    std::uint8_t server_secret[32];
    if (!hkdf_expand_label(initial_secret, "server in", 9, nullptr, 0, server_secret, 32))
        return false;

    const char* key_label = "quic key";
    const char* iv_label  = "quic iv";
    const char* hp_label  = "quic hp";

    if (!hkdf_expand_label(client_secret, key_label, 8, nullptr, 0, client_key, 16)) return false;
    if (!hkdf_expand_label(client_secret, iv_label,  7, nullptr, 0, client_iv,  12)) return false;
    if (!hkdf_expand_label(client_secret, hp_label,  7, nullptr, 0, client_hp,  16)) return false;

    if (!hkdf_expand_label(server_secret, key_label, 8, nullptr, 0, server_key, 16)) return false;
    if (!hkdf_expand_label(server_secret, iv_label,  7, nullptr, 0, server_iv,  12)) return false;
    if (!hkdf_expand_label(server_secret, hp_label,  7, nullptr, 0, server_hp,  16)) return false;

    SecureZeroMemory(initial_secret, sizeof(initial_secret));
    SecureZeroMemory(client_secret, sizeof(client_secret));
    SecureZeroMemory(server_secret, sizeof(server_secret));

    return true;
}

std::vector<quic_key_info_t> QuicAnalyzer::extract_quic_traffic_keys(std::uint32_t pid) {
    return TlsKeyExtractor::instance().extract_quic_keys(pid);
}


DtlsAnalyzer& DtlsAnalyzer::instance() {
    static DtlsAnalyzer inst;
    return inst;
}

bool DtlsAnalyzer::parse_dtls_record(const std::uint8_t* data, std::size_t len, dtls_record_t& out) {


    if (len < 13) return false;

    out.content_type = data[0];
    out.version = (static_cast<std::uint16_t>(data[1]) << 8) | data[2];


    if (out.version != 0xFEFF && out.version != 0xFEFD && out.version != 0x0101) {


        if (data[1] != 0xFE) return false;
    }

    out.epoch = (static_cast<std::uint16_t>(data[3]) << 8) | data[4];
    out.sequence = 0;
    for (int i = 0; i < 6; i++) {
        out.sequence = (out.sequence << 8) | data[5 + i];
    }
    out.length = (static_cast<std::uint16_t>(data[11]) << 8) | data[12];


    if (out.content_type >= 20 && out.content_type <= 25) {
        out.is_handshake = (out.content_type == 22);
        if (out.is_handshake && len >= 14) {
            out.handshake_type = data[13];
        }
        return true;
    }

    return false;
}

std::vector<dtls_session_info_t> DtlsAnalyzer::detect_dtls_sessions(std::uint32_t filter_pid) {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<dtls_session_info_t> sessions;

    if (!device || !device->is_connected()) return sessions;

    bool cap_active = false;
    std::uint32_t cap_cnt = 0, cap_drp = 0;
    device->get_capture_status(cap_active, cap_cnt, cap_drp);
    if (!cap_active)
        device->start_capture(filter_pid, 0, 17);

    auto packets = device->get_captured_packets(32);

    for (const auto& pkt : packets) {
        if (pkt.protocol != 17) continue;
        if (pkt.payload.size() < 13) continue;
        if (filter_pid != 0 && pkt.pid != filter_pid) continue;

        dtls_record_t rec;
        std::size_t dtls_offset = 0;
        bool parsed = parse_dtls_record(pkt.payload.data(), pkt.payload.size(), rec);
        if (!parsed) {
            const std::size_t scan_limit = std::min<std::size_t>(pkt.payload.size(), 96);
            for (std::size_t off = 1; off + 13 <= scan_limit; ++off) {
                if (pkt.payload[off] < 20 || pkt.payload[off] > 25)
                    continue;
                if (pkt.payload[off + 1] != 0xFE && pkt.payload[off + 1] != 0x01)
                    continue;
                dtls_record_t candidate;
                if (!parse_dtls_record(pkt.payload.data() + off, pkt.payload.size() - off, candidate))
                    continue;
                rec = candidate;
                dtls_offset = off;
                parsed = true;
                break;
            }
        }
        if (!parsed) continue;
        diag::log_tagged_fmt("net_sec", "dtls_detect packet pid=%u payload=%zu offset=%zu version=0x%04X content_type=%u",
            pkt.pid,
            pkt.payload.size(),
            dtls_offset,
            rec.version,
            rec.content_type);

        dtls_session_info_t session;
        session.pid = pkt.pid;
        std::memcpy(session.src_addr, pkt.local_addr, 16);
        std::memcpy(session.dst_addr, pkt.remote_addr, 16);
        session.src_port = pkt.local_port;
        session.dst_port = pkt.remote_port;
        session.address_family = pkt.address_family;
        session.dtls_version = rec.version;
        session.epoch = rec.epoch;
        session.sequence_number = rec.sequence;
        session.content_type = rec.content_type;
        session.payload.assign(pkt.payload.begin(), pkt.payload.end());

        if (rec.is_handshake) {
            session.state = "handshake";
        } else if (rec.content_type == 23) {
            session.state = "established";
        } else if (rec.content_type == 21) {
            session.state = "closing";
        } else {
            session.state = "unknown";
        }

        sessions.push_back(std::move(session));
    }

    return sessions;
}

std::vector<dtls_key_info_t> DtlsAnalyzer::extract_dtls_keys(std::uint32_t pid) {
    return TlsKeyExtractor::instance().extract_dtls_keys(pid);
}


static std::string extract_tls_sni(const std::uint8_t* data, std::size_t len) {
    if (len < 44 || data[0] != 0x16) return "";

    std::uint16_t rec_len = (static_cast<std::uint16_t>(data[3]) << 8) | data[4];
    if (static_cast<std::size_t>(5) + rec_len > len) return "";

    if (data[5] != 0x01) return "";

    std::size_t pos = 9;
    if (pos + 34 > len) return "";
    pos += 2;
    pos += 32;

    if (pos >= len) return "";
    std::uint8_t sid_len = data[pos++];
    pos += sid_len;

    if (pos + 2 > len) return "";
    std::uint16_t cs_len = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2 + cs_len;

    if (pos >= len) return "";
    std::uint8_t cm_len = data[pos++];
    pos += cm_len;

    if (pos + 2 > len) return "";
    std::uint16_t ext_total = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;

    std::size_t ext_end = pos + ext_total;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        std::uint16_t ext_type = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
        std::uint16_t ext_data_len = (static_cast<std::uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;

        if (ext_type == 0x0000 && ext_data_len >= 5 && pos + ext_data_len <= ext_end) {
            std::size_t sni_pos = pos + 2;
            if (sni_pos < ext_end && data[sni_pos] == 0x00) {
                sni_pos++;
                if (sni_pos + 2 <= ext_end) {
                    std::uint16_t name_len = (static_cast<std::uint16_t>(data[sni_pos]) << 8) | data[sni_pos + 1];
                    sni_pos += 2;
                    if (name_len > 0 && name_len < 256 && sni_pos + name_len <= ext_end) {
                        std::string sni(reinterpret_cast<const char*>(data + sni_pos), name_len);
                        for (auto& c : sni) {
                            if (c < 0x20 || c > 0x7E) return "";
                        }
                        return sni;
                    }
                }
            }
            break;
        }

        pos += ext_data_len;
    }

    return "";
}


AutoResponder& AutoResponder::instance() {
    static AutoResponder inst;
    return inst;
}

std::uint32_t AutoResponder::add_rule(const autoresponder_rule_t& rule) {
    std::lock_guard<std::mutex> lock(_mutex);
    std::uint32_t id = _next_rule_id++;
    autoresponder_rule_t stored = rule;
    stored.rule_id = id;
    stored.match_count = 0;
    stored.last_match_time = 0;
    _rules[id] = std::move(stored);
    return id;
}

bool AutoResponder::update_rule(std::uint32_t rule_id, const autoresponder_rule_t& rule) {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _rules.find(rule_id);
    if (it == _rules.end()) return false;
    auto match_count = it->second.match_count;
    auto last_match = it->second.last_match_time;
    it->second = rule;
    it->second.rule_id = rule_id;
    it->second.match_count = match_count;
    it->second.last_match_time = last_match;
    return true;
}

bool AutoResponder::remove_rule(std::uint32_t rule_id) {
    std::lock_guard<std::mutex> lock(_mutex);
    return _rules.erase(rule_id) > 0;
}

bool AutoResponder::enable_rule(std::uint32_t rule_id, bool enabled) {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _rules.find(rule_id);
    if (it == _rules.end()) return false;
    it->second.enabled = enabled;
    return true;
}

void AutoResponder::clear_rules() {
    std::lock_guard<std::mutex> lock(_mutex);
    _rules.clear();
}

std::vector<autoresponder_rule_t> AutoResponder::list_rules() const {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<autoresponder_rule_t> result;
    result.reserve(_rules.size());
    for (const auto& [id, rule] : _rules)
        result.push_back(rule);
    return result;
}

const autoresponder_rule_t* AutoResponder::get_rule(std::uint32_t rule_id) const {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _rules.find(rule_id);
    return (it != _rules.end()) ? &it->second : nullptr;
}

bool AutoResponder::match_pattern(const autoresponder_rule_t& rule,
                                   const std::string& method, const std::string& url,
                                   const std::map<std::string, std::string>& headers,
                                   const std::string& body) {
    if (!rule.enabled) return false;


    if (!rule.match_method.empty() && rule.match_method != method)
        return false;

    switch (rule.match_type) {
        case autoresponder_match_type::exact_url:
            return url == rule.match_pattern;

        case autoresponder_match_type::prefix_url:
            return url.find(rule.match_pattern) == 0 ||
                   url.find(rule.match_pattern) != std::string::npos;

        case autoresponder_match_type::regex_url: {
            try {
                std::regex rx(rule.match_pattern, std::regex_constants::ECMAScript | std::regex_constants::icase);
                return std::regex_search(url, rx);
            } catch (...) {
                return false;
            }
        }

        case autoresponder_match_type::method_and_url:
            return method == rule.match_method &&
                   (url == rule.match_pattern || url.find(rule.match_pattern) != std::string::npos);

        case autoresponder_match_type::header_contains: {
            for (const auto& [name, value] : headers) {
                if (value.find(rule.match_pattern) != std::string::npos)
                    return true;
                if (name.find(rule.match_pattern) != std::string::npos)
                    return true;
            }
            return false;
        }

        case autoresponder_match_type::body_contains:
            return body.find(rule.match_pattern) != std::string::npos;

        case autoresponder_match_type::sni_contains: {
            std::string lower_url = url;
            std::string lower_pat = rule.match_pattern;
            for (auto& c : lower_url) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (auto& c : lower_pat) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return lower_url.find(lower_pat) != std::string::npos;
        }
    }

    return false;
}

std::string AutoResponder::build_response(const autoresponder_rule_t& rule) {
    std::string response;

    std::uint32_t status = rule.status_code ? rule.status_code : 200;
    std::string reason = rule.status_reason.empty() ? "OK" : rule.status_reason;

    response += "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";

    for (const auto& [name, value] : rule.response_headers) {
        response += name + ": " + value + "\r\n";
    }

    std::string body;
    if (!rule.response_file_path.empty()) {
        std::ifstream file(rule.response_file_path, std::ios::binary);
        if (file.is_open()) {
            body.assign(std::istreambuf_iterator<char>(file),
                        std::istreambuf_iterator<char>());
        }
    } else {
        body = rule.response_body;
    }


    bool has_content_length = false;
    for (const auto& [name, value] : rule.response_headers) {
        std::string lower_name = name;
        for (auto& c : lower_name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower_name == "content-length") { has_content_length = true; break; }
    }
    if (!has_content_length) {
        response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }

    response += "\r\n";
    response += body;
    return response;
}

AutoResponder::match_result_t AutoResponder::match_request(
    const std::string& method, const std::string& url,
    const std::map<std::string, std::string>& headers,
    const std::string& body) {

    std::lock_guard<std::mutex> lock(_mutex);
    match_result_t result;


    std::vector<autoresponder_rule_t*> sorted;
    sorted.reserve(_rules.size());
    for (auto& [id, rule] : _rules)
        sorted.push_back(&rule);
    std::sort(sorted.begin(), sorted.end(),
              [](const autoresponder_rule_t* a, const autoresponder_rule_t* b) {
                  return a->priority < b->priority;
              });

    for (auto* rule : sorted) {
        if (match_pattern(*rule, method, url, headers, body)) {
            rule->match_count++;
            rule->last_match_time = get_timestamp_ms();

            result.matched = true;
            result.rule_id = rule->rule_id;

            if (rule->drop_request) {
                result.response_body.clear();
                return result;
            }

            if (rule->passthrough) {
                result.matched = false;
                return result;
            }

            std::string full_response = build_response(*rule);


            auto header_end = full_response.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                std::string header_section = full_response.substr(0, header_end);
                auto first_line_end = header_section.find("\r\n");
                if (first_line_end != std::string::npos) {
                    result.response_status_line = header_section.substr(0, first_line_end);
                    result.response_headers_str = header_section.substr(first_line_end + 2);
                }
                result.response_body = full_response.substr(header_end + 4);
            }

            return result;
        }
    }

    return result;
}

void AutoResponder::worker_loop(const char* mode, std::uint64_t generation) {
    const DWORD tid = GetCurrentThreadId();
    _worker_tid.store(tid, std::memory_order_release);
    diag::log_tagged_fmt("net_sec", "AutoResponder::worker enter mode=%s generation=%llu active=%d tid=%lu",
        mode ? mode : "",
        static_cast<unsigned long long>(generation),
        _active.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long>(tid));
    try {
        while (_active.load(std::memory_order_acquire) &&
               _worker_generation.load(std::memory_order_acquire) == generation) {
            if (!device || !device->is_connected()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }

            auto held = device->get_held_packets();
            for (const auto& pkt : held) {
                if (pkt.payload.empty()) {
                    device->intercept_op(3, 0, 0, 0, pkt.hold_id, nullptr, 0, nullptr, nullptr);
                    continue;
                }

                if (pkt.payload.size() > 5 && pkt.payload[0] == 0x16) {
                    std::string sni = extract_tls_sni(pkt.payload.data(), pkt.payload.size());
                    if (!sni.empty()) {
                        std::string https_url = "https://" + sni + "/";
                        auto tls_match = match_request("CONNECT", https_url, {{"Host", sni}}, "");
                        if (tls_match.matched) {
                            std::uint32_t delay = 0;
                            {
                                std::lock_guard<std::mutex> rule_lock(_mutex);
                                auto rule_it = _rules.find(tls_match.rule_id);
                                if (rule_it != _rules.end())
                                    delay = rule_it->second.latency_ms;
                            }
                            if (delay > 0) {
                                for (std::uint32_t elapsed = 0;
                                     elapsed < delay && _active.load();
                                     elapsed += 10) {
                                    std::this_thread::sleep_for(std::chrono::milliseconds(
                                        std::min(10u, delay - elapsed)));
                                }
                            }
                            device->intercept_op(4, 0, 0, 0, pkt.hold_id, nullptr, 0, nullptr, nullptr);
                            continue;
                        }
                    }
                    device->intercept_op(3, 0, 0, 0, pkt.hold_id, nullptr, 0, nullptr, nullptr);
                    continue;
                }

                std::string payload_str(pkt.payload.begin(), pkt.payload.end());
                std::string method, url;
                std::map<std::string, std::string> headers;
                std::string body;

                auto first_line_end = payload_str.find("\r\n");
                if (first_line_end == std::string::npos) {
                    device->intercept_op(3, 0, 0, 0, pkt.hold_id, nullptr, 0, nullptr, nullptr);
                    continue;
                }
                std::string first_line = payload_str.substr(0, first_line_end);

                auto sp1 = first_line.find(' ');
                if (sp1 == std::string::npos) {
                    device->intercept_op(3, 0, 0, 0, pkt.hold_id, nullptr, 0, nullptr, nullptr);
                    continue;
                }
                method = first_line.substr(0, sp1);
                auto sp2 = first_line.find(' ', sp1 + 1);
                if (sp2 == std::string::npos)
                    url = first_line.substr(sp1 + 1);
                else
                    url = first_line.substr(sp1 + 1, sp2 - sp1 - 1);

                if (method != "GET" && method != "POST" && method != "PUT" &&
                    method != "DELETE" && method != "HEAD" && method != "OPTIONS" &&
                    method != "PATCH" && method != "CONNECT") {
                    device->intercept_op(3, 0, 0, 0, pkt.hold_id, nullptr, 0, nullptr, nullptr);
                    continue;
                }

                std::size_t pos = first_line_end + 2;
                while (pos < payload_str.size()) {
                    auto next = payload_str.find("\r\n", pos);
                    if (next == std::string::npos || next == pos) break;
                    std::string line = payload_str.substr(pos, next - pos);
                    auto colon = line.find(':');
                    if (colon != std::string::npos) {
                        std::string name = line.substr(0, colon);
                        std::string value = line.substr(colon + 1);
                        while (!value.empty() && value[0] == ' ') value.erase(0, 1);
                        headers[name] = value;

                        if (name == "Host" && !url.empty() && url[0] == '/') {
                            url = "http://" + value + url;
                        }
                    }
                    pos = next + 2;
                }
                auto body_start = payload_str.find("\r\n\r\n");
                if (body_start != std::string::npos && body_start + 4 < payload_str.size())
                    body = payload_str.substr(body_start + 4);

                auto match = match_request(method, url, headers, body);
                if (match.matched) {
                    std::uint32_t delay = 0;
                    {
                        std::lock_guard<std::mutex> rule_lock(_mutex);
                        auto rule_it = _rules.find(match.rule_id);
                        if (rule_it != _rules.end())
                            delay = rule_it->second.latency_ms;
                    }
                    if (delay > 0) {
                        for (std::uint32_t elapsed = 0;
                             elapsed < delay && _active.load();
                             elapsed += 10) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(
                                std::min(10u, delay - elapsed)));
                        }
                    }

                    if (match.response_body.empty() && match.response_status_line.empty()) {
                        device->intercept_op(4, 0, 0, 0, pkt.hold_id, nullptr, 0, nullptr, nullptr);
                    } else {
                        std::string full_resp = match.response_status_line + "\r\n" +
                                                match.response_headers_str + "\r\n\r\n" +
                                                match.response_body;
                        device->intercept_op(5, 0, 0, 0, pkt.hold_id,
                            reinterpret_cast<const std::uint8_t*>(full_resp.data()),
                            static_cast<std::uint32_t>(full_resp.size()),
                            nullptr, nullptr);
                    }
                } else {
                    device->intercept_op(3, 0, 0, 0, pkt.hold_id, nullptr, 0, nullptr, nullptr);
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("net_sec", "AutoResponder::worker exception mode=%s err=%s",
            mode ? mode : "", ex.what());
    } catch (...) {
        diag::log_tagged_fmt("net_sec", "AutoResponder::worker exception mode=%s err=unknown",
            mode ? mode : "");
    }
    const bool current_generation = _worker_generation.load(std::memory_order_acquire) == generation;
    if (current_generation)
        _worker_done.store(true, std::memory_order_release);
    _worker_tid.store(0, std::memory_order_release);
    _worker_cv.notify_all();
    diag::log_tagged_fmt("net_sec", "AutoResponder::worker exit mode=%s generation=%llu current=%d active=%d tid=%lu",
        mode ? mode : "",
        static_cast<unsigned long long>(generation),
        current_generation ? 1 : 0,
        _active.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long>(tid));
}

bool AutoResponder::wait_worker_done(std::uint64_t generation, DWORD timeout_ms) {
    std::unique_lock<std::mutex> lock(_worker_mutex);
    const bool signaled = _worker_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this, generation]() {
        return _worker_done.load(std::memory_order_acquire) ||
               _worker_generation.load(std::memory_order_acquire) != generation;
    });
    return signaled &&
           _worker_generation.load(std::memory_order_acquire) == generation &&
           _worker_done.load(std::memory_order_acquire);
}

bool AutoResponder::start() {
    std::lock_guard<std::mutex> lifecycle_lock(_lifecycle_mutex);
    const DWORD entry_tid = GetCurrentThreadId();
    const ULONGLONG entry_tick = GetTickCount64();
    std::string session_reason;
    const bool kernel_session_ok = driver_bridge::kernel_session_available(&session_reason);
    diag::log_tagged_critical_fmt("net_sec",
        "AutoResponder::start entry active=%d device=%p connected=%d session_valid=%d session_reason=%.96s tid=%lu tick_ms=%llu",
        _active.load() ? 1 : 0,
        device.get(),
        device && device->is_connected() ? 1 : 0,
        kernel_session_ok ? 1 : 0,
        session_reason.empty() ? "ok" : session_reason.c_str(),
        static_cast<unsigned long>(entry_tid),
        static_cast<unsigned long long>(entry_tick));
    if (_active.load()) {
        diag::log_tagged_critical("net_sec", "AutoResponder::start already_active");
        return true;
    }

    if (!kernel_session_ok) {
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start rejected session_invalidated reason=%.96s tid=%lu",
            session_reason.empty() ? "kernel_session_unavailable" : session_reason.c_str(),
            static_cast<unsigned long>(entry_tid));
        return false;
    }

    if (!_worker_done.load(std::memory_order_acquire)) {
        const std::uint64_t previous_generation = _worker_generation.load(std::memory_order_acquire);
        const ULONGLONG wait_start = GetTickCount64();
        const bool previous_done = wait_worker_done(previous_generation, 1000);
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start previous_worker_done=%d generation=%llu elapsed_ms=%llu tid=%lu",
            previous_done ? 1 : 0,
            static_cast<unsigned long long>(previous_generation),
            static_cast<unsigned long long>(GetTickCount64() - wait_start),
            static_cast<unsigned long>(entry_tid));
        if (!previous_done)
            return false;
    }

    if (!device || !device->is_connected()) {
        diag::log_tagged_critical("net_sec", "AutoResponder::start rejected driver_unavailable");
        return false;
    }

    bool cap_active = false;
    std::uint32_t cap_count = 0, cap_drop = 0;
    {
        const ULONGLONG t0 = GetTickCount64();
        ::SetLastError(0);
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start get_capture_status_pre tid=%lu tick_ms=%llu",
            static_cast<unsigned long>(entry_tid),
            static_cast<unsigned long long>(t0));
        device->get_capture_status(cap_active, cap_count, cap_drop);
        const DWORD gle = ::GetLastError();
        const ULONGLONG t1 = GetTickCount64();
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start get_capture_status_post elapsed_ms=%llu cap_active=%d cap_count=%u cap_drop=%u gle=%lu tid=%lu tick_ms=%llu",
            static_cast<unsigned long long>(t1 - t0),
            cap_active ? 1 : 0,
            cap_count,
            cap_drop,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long>(entry_tid),
            static_cast<unsigned long long>(t1));
    }
    bool started_capture = false;
    if (!cap_active) {
        const ULONGLONG t0 = GetTickCount64();
        ::SetLastError(0);
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start start_capture_pre tid=%lu tick_ms=%llu",
            static_cast<unsigned long>(entry_tid),
            static_cast<unsigned long long>(t0));
        bool capture_started = device->start_capture(0, 0, 0);
        const DWORD gle = ::GetLastError();
        const ULONGLONG t1 = GetTickCount64();
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start start_capture_post elapsed_ms=%llu ok=%d gle=%lu tid=%lu tick_ms=%llu",
            static_cast<unsigned long long>(t1 - t0),
            capture_started ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long>(entry_tid),
            static_cast<unsigned long long>(t1));
        if (!capture_started)
            return false;
        started_capture = true;
    }

    bool intercept_started = false;
    {
        const ULONGLONG t0 = GetTickCount64();
        ::SetLastError(0);
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start intercept_pre op=1 tid=%lu tick_ms=%llu",
            static_cast<unsigned long>(entry_tid),
            static_cast<unsigned long long>(t0));
        intercept_started = device->intercept_op(1, 0, 0, 6);
        const DWORD gle = ::GetLastError();
        const ULONGLONG t1 = GetTickCount64();
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start intercept_post op=1 elapsed_ms=%llu ok=%d gle=%lu tid=%lu tick_ms=%llu",
            static_cast<unsigned long long>(t1 - t0),
            intercept_started ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long>(entry_tid),
            static_cast<unsigned long long>(t1));
    }
    if (!intercept_started) {
        if (started_capture) {
            const ULONGLONG t0 = GetTickCount64();
            ::SetLastError(0);
            diag::log_tagged_critical_fmt("net_sec",
                "AutoResponder::start rollback_stop_capture_pre tid=%lu tick_ms=%llu",
                static_cast<unsigned long>(entry_tid),
                static_cast<unsigned long long>(t0));
            bool capture_stopped = device->stop_capture();
            const DWORD gle = ::GetLastError();
            const ULONGLONG t1 = GetTickCount64();
            diag::log_tagged_critical_fmt("net_sec",
                "AutoResponder::start rollback_stop_capture_post elapsed_ms=%llu ok=%d gle=%lu tid=%lu tick_ms=%llu",
                static_cast<unsigned long long>(t1 - t0),
                capture_stopped ? 1 : 0,
                static_cast<unsigned long>(gle),
                static_cast<unsigned long>(entry_tid),
                static_cast<unsigned long long>(t1));
        }
        return false;
    }

    _active.store(true);
    const std::uint64_t generation = _worker_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    _worker_done.store(false, std::memory_order_release);
    _worker_tid.store(0, std::memory_order_release);

    const ULONGLONG post_t0 = GetTickCount64();
    diag::log_tagged_critical_fmt("net_sec",
        "AutoResponder::start work_queue_post_pre generation=%llu tid=%lu tick_ms=%llu",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(entry_tid),
        static_cast<unsigned long long>(post_t0));
    bool worker_started = false;
    DWORD post_err = ERROR_SUCCESS;
    try {
        worker_started = work_queue::post([this, generation]() {
            worker_loop("work_queue", generation);
        });
        post_err = GetLastError();
    } catch (const std::exception& ex) {
        post_err = GetLastError();
        if (post_err == ERROR_SUCCESS)
            post_err = ERROR_NOT_ENOUGH_MEMORY;
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start worker_post_exception generation=%llu gle=%lu err=%s",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(post_err),
            ex.what());
    } catch (...) {
        post_err = GetLastError();
        if (post_err == ERROR_SUCCESS)
            post_err = ERROR_NOT_ENOUGH_MEMORY;
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start worker_post_exception generation=%llu gle=%lu err=unknown",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(post_err));
    }
    const ULONGLONG post_t1 = GetTickCount64();
    diag::log_tagged_critical_fmt("net_sec",
        "AutoResponder::start work_queue_post_post elapsed_ms=%llu ok=%d gle=%lu generation=%llu tid=%lu tick_ms=%llu",
        static_cast<unsigned long long>(post_t1 - post_t0),
        worker_started ? 1 : 0,
        static_cast<unsigned long>(post_err),
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(entry_tid),
        static_cast<unsigned long long>(post_t1));
    if (!worker_started) {
        if (post_err == ERROR_SUCCESS)
            post_err = ERROR_NOT_READY;
        _active.store(false);
        _worker_done.store(true, std::memory_order_release);
        _worker_cv.notify_all();
        if (device && device->is_connected()) {
            const ULONGLONG rb_t0 = GetTickCount64();
            ::SetLastError(0);
            diag::log_tagged_critical_fmt("net_sec",
                "AutoResponder::start rollback_intercept_pre op=2 generation=%llu tid=%lu tick_ms=%llu",
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long>(entry_tid),
                static_cast<unsigned long long>(rb_t0));
            bool stopped = device->intercept_op(2, 0, 0, 0);
            const DWORD stopped_gle = ::GetLastError();
            const ULONGLONG rb_t1 = GetTickCount64();
            diag::log_tagged_critical_fmt("net_sec",
                "AutoResponder::start rollback_intercept_post op=2 elapsed_ms=%llu ok=%d gle=%lu generation=%llu tid=%lu tick_ms=%llu",
                static_cast<unsigned long long>(rb_t1 - rb_t0),
                stopped ? 1 : 0,
                static_cast<unsigned long>(stopped_gle),
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long>(entry_tid),
                static_cast<unsigned long long>(rb_t1));
            bool capture_stopped = true;
            if (started_capture) {
                const ULONGLONG cap_t0 = GetTickCount64();
                ::SetLastError(0);
                diag::log_tagged_critical_fmt("net_sec",
                    "AutoResponder::start rollback_stop_capture_pre generation=%llu tid=%lu tick_ms=%llu",
                    static_cast<unsigned long long>(generation),
                    static_cast<unsigned long>(entry_tid),
                    static_cast<unsigned long long>(cap_t0));
                capture_stopped = device->stop_capture();
                const DWORD cap_gle = ::GetLastError();
                const ULONGLONG cap_t1 = GetTickCount64();
                diag::log_tagged_critical_fmt("net_sec",
                    "AutoResponder::start rollback_stop_capture_post elapsed_ms=%llu ok=%d gle=%lu generation=%llu tid=%lu tick_ms=%llu",
                    static_cast<unsigned long long>(cap_t1 - cap_t0),
                    capture_stopped ? 1 : 0,
                    static_cast<unsigned long>(cap_gle),
                    static_cast<unsigned long long>(generation),
                    static_cast<unsigned long>(entry_tid),
                    static_cast<unsigned long long>(cap_t1));
            }
            diag::log_tagged_critical_fmt("net_sec",
                "AutoResponder::start rollback_summary intercept_stop=%d capture_stop=%d generation=%llu",
                stopped ? 1 : 0,
                capture_stopped ? 1 : 0,
                static_cast<unsigned long long>(generation));
        }
        diag::log_tagged_critical_fmt("net_sec",
            "AutoResponder::start worker_post_failed generation=%llu gle=%lu",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(post_err));
        return false;
    }
    diag::log_tagged_critical_fmt("net_sec",
        "AutoResponder::start worker_posted generation=%llu tid=%lu",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(entry_tid));

    diag::log_tagged_critical("net_sec", "AutoResponder::start ok");
    return true;
}

bool AutoResponder::stop() {
    std::lock_guard<std::mutex> lifecycle_lock(_lifecycle_mutex);
    const ULONGLONG t0 = GetTickCount64();
    const std::uint64_t generation = _worker_generation.load(std::memory_order_acquire);
    diag::log_tagged_fmt("net_sec", "AutoResponder::stop entry active=%d worker_done=%d generation=%llu worker_tid=%lu device=%p connected=%d tid=%lu",
        _active.load() ? 1 : 0,
        _worker_done.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(_worker_tid.load(std::memory_order_acquire)),
        device.get(),
        device && device->is_connected() ? 1 : 0,
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (!_active.load()) {
        if (!_worker_done.load(std::memory_order_acquire)) {
            const bool done = wait_worker_done(generation, 1000);
            diag::log_tagged_fmt("net_sec", "AutoResponder::stop inactive_worker_done=%d generation=%llu elapsed_ms=%llu",
                done ? 1 : 0,
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long long>(GetTickCount64() - t0));
        } else {
            diag::log_tagged("net_sec", "AutoResponder::stop inactive_noop");
        }
        return true;
    }
    _active.store(false);
    if (device && device->is_connected()) {
        bool stopped = device->intercept_op(2, 0, 0, 0);
        diag::log_tagged_fmt("net_sec", "AutoResponder::stop intercept_stop result=%d elapsed_ms=%llu",
            stopped ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - t0));
    }

    diag::log_tagged_fmt("net_sec", "AutoResponder::stop worker_wait_begin generation=%llu elapsed_ms=%llu",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(GetTickCount64() - t0));
    const bool done = wait_worker_done(generation, 1000);
    diag::log_tagged_fmt("net_sec", "AutoResponder::stop worker_wait_done=%d generation=%llu worker_tid=%lu elapsed_ms=%llu",
        done ? 1 : 0,
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long>(_worker_tid.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(GetTickCount64() - t0));

    diag::log_tagged_fmt("net_sec", "AutoResponder::stop exit active=%d worker_done=%d elapsed_ms=%llu",
        _active.load() ? 1 : 0,
        _worker_done.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return true;
}

bool AutoResponder::import_rules(const std::string& json_str) {
    std::lock_guard<std::mutex> lock(_mutex);
    try {
        auto j = nlohmann::json::parse(json_str);
        if (!j.is_array()) return false;

        for (const auto& item : j) {
            autoresponder_rule_t rule;
            rule.enabled = item.value("enabled", true);
            rule.priority = item.value("priority", 0);

            std::string match_type_str = item.value("match_type", "prefix_url");
            if (match_type_str == "exact_url") rule.match_type = autoresponder_match_type::exact_url;
            else if (match_type_str == "prefix_url") rule.match_type = autoresponder_match_type::prefix_url;
            else if (match_type_str == "regex_url") rule.match_type = autoresponder_match_type::regex_url;
            else if (match_type_str == "method_and_url") rule.match_type = autoresponder_match_type::method_and_url;
            else if (match_type_str == "header_contains") rule.match_type = autoresponder_match_type::header_contains;
            else if (match_type_str == "body_contains") rule.match_type = autoresponder_match_type::body_contains;
            else if (match_type_str == "sni_contains") rule.match_type = autoresponder_match_type::sni_contains;

            rule.match_pattern = item.value("match_pattern", "");
            rule.match_method = item.value("match_method", "");
            rule.status_code = item.value("status_code", 200);
            rule.status_reason = item.value("status_reason", "");
            rule.response_body = item.value("response_body", "");
            rule.response_file_path = item.value("response_file_path", "");
            rule.latency_ms = item.value("latency_ms", 0u);
            rule.drop_request = item.value("drop_request", false);
            rule.passthrough = item.value("passthrough", false);

            if (item.contains("response_headers") && item["response_headers"].is_object()) {
                for (auto it = item["response_headers"].begin(); it != item["response_headers"].end(); ++it) {
                    rule.response_headers[it.key()] = it.value().get<std::string>();
                }
            }

            std::uint32_t id = _next_rule_id++;
            rule.rule_id = id;
            _rules[id] = std::move(rule);
        }
        return true;
    } catch (...) {
        return false;
    }
}

std::string AutoResponder::export_rules() const {
    std::lock_guard<std::mutex> lock(_mutex);
    nlohmann::json arr = nlohmann::json::array();

    for (const auto& [id, rule] : _rules) {
        nlohmann::json item;
        item["rule_id"] = rule.rule_id;
        item["enabled"] = rule.enabled;
        item["priority"] = rule.priority;

        switch (rule.match_type) {
            case autoresponder_match_type::exact_url: item["match_type"] = "exact_url"; break;
            case autoresponder_match_type::prefix_url: item["match_type"] = "prefix_url"; break;
            case autoresponder_match_type::regex_url: item["match_type"] = "regex_url"; break;
            case autoresponder_match_type::method_and_url: item["match_type"] = "method_and_url"; break;
            case autoresponder_match_type::header_contains: item["match_type"] = "header_contains"; break;
            case autoresponder_match_type::body_contains: item["match_type"] = "body_contains"; break;
            case autoresponder_match_type::sni_contains: item["match_type"] = "sni_contains"; break;
        }

        item["match_pattern"] = rule.match_pattern;
        item["match_method"] = rule.match_method;
        item["status_code"] = rule.status_code;
        item["status_reason"] = rule.status_reason;
        item["response_body"] = rule.response_body;
        item["response_file_path"] = rule.response_file_path;
        item["latency_ms"] = rule.latency_ms;
        item["drop_request"] = rule.drop_request;
        item["passthrough"] = rule.passthrough;
        item["match_count"] = rule.match_count;

        nlohmann::json hdrs = nlohmann::json::object();
        for (const auto& [name, value] : rule.response_headers)
            hdrs[name] = value;
        item["response_headers"] = hdrs;

        arr.push_back(item);
    }

    return arr.dump(2);
}

}

#endif
