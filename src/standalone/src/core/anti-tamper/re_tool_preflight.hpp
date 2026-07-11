#pragma once

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <cwchar>
#include <cstring>
#include <cstdint>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

#include "helpers/diag_log.hpp"

namespace re_tool_preflight {

    struct window_sig_t {
        const wchar_t* sig;
        int len;
    };

    constexpr window_sig_t kWindowSigs[] = {
        { L"Cheat Engine",      12 },
        { L"x64dbg",             5 },
        { L"x32dbg",             5 },
        { L"OllyDbg",            7 },
        { L"Ghidra",             6 },
        { L"HxD",                3 },
        { L"Process Hacker",    15 },
        { L"Process Explorer",  17 },
        { L"ScyllaHide",        10 },
        { L"API Monitor",       11 },
        { L"WinDbg",             6 },
        { L"dnSpy",              5 },
        { L"ILSpy",              5 },
    };
    constexpr int kNumWindowSigs = sizeof(kWindowSigs) / sizeof(kWindowSigs[0]);

    struct ida_pattern_t {
        const wchar_t* pattern;
        int len;
        bool has_wildcard;
    };

    constexpr ida_pattern_t kIdaPatterns[] = {
        { L"ida",               3, false },
        { L"ida pro",           7, false },
        { L"ida",               3, true  },
    };
    constexpr int kNumIdaPatterns = sizeof(kIdaPatterns) / sizeof(kIdaPatterns[0]);

    struct preflight_result_t {
        bool re_tool_detected;
        bool ida_detected;
        wchar_t detected_title[512];
        const wchar_t* detected_sig;
    };

    __forceinline void lowercase_wide(wchar_t* buf, int len) {
        for (int i = 0; i < len && buf[i]; ++i) {
            if (buf[i] >= L'A' && buf[i] <= L'Z')
                buf[i] = buf[i] - L'A' + L'a';
            else if (buf[i] >= 0x0410 && buf[i] <= 0x042F)
                buf[i] = buf[i] - 0x0410 + 0x0430;
        }
    }

    __forceinline bool wcsistr_contains(const wchar_t* haystack, int haystack_len, const wchar_t* needle, int needle_len) {
        if (haystack_len < needle_len || needle_len == 0)
            return false;
        for (int i = 0; i <= haystack_len - needle_len; ++i) {
            bool match = true;
            for (int j = 0; j < needle_len; ++j) {
                wchar_t a = haystack[i + j] | 0x20;
                wchar_t b = needle[j] | 0x20;
                if (a != b) {
                    match = false;
                    break;
                }
            }
            if (match)
                return true;
        }
        return false;
    }

    __forceinline bool is_word_boundary_char(wchar_t ch) {
        return !((ch >= L'a' && ch <= L'z') ||
                 (ch >= L'A' && ch <= L'Z') ||
                 (ch >= L'0' && ch <= L'9') ||
                 (ch >= 0x0430 && ch <= 0x044F) ||
                 (ch >= 0x0410 && ch <= 0x042F) ||
                 ch == L'_');
    }

    __forceinline bool match_ida_word_boundary(const wchar_t* title, int title_len) {
        if (title_len < 3)
            return false;

        const wchar_t ida[] = L"ida";
        const int ida_len = 3;

        for (int i = 0; i <= title_len - ida_len; ++i) {
            bool prefix_ok = (i == 0) || is_word_boundary_char(title[i - 1]);
            if (!prefix_ok)
                continue;

            bool match = true;
            for (int j = 0; j < ida_len; ++j) {
                if ((title[i + j] | 0x20) != (ida[j] | 0x20)) {
                    match = false;
                    break;
                }
            }
            if (!match)
                continue;

            int after_pos = i + ida_len;
            bool suffix_ok = (after_pos >= title_len) || is_word_boundary_char(title[after_pos]);
            if (suffix_ok)
                return true;

            if (after_pos < title_len && (title[after_pos] | 0x20) == L' ') {
                const wchar_t pro[] = L"pro";
                const int pro_len = 3;
                int pro_start = after_pos + 1;
                if (pro_start + pro_len <= title_len) {
                    bool pro_match = true;
                    for (int j = 0; j < pro_len; ++j) {
                        if ((title[pro_start + j] | 0x20) != (pro[j] | 0x20)) {
                            pro_match = false;
                            break;
                        }
                    }
                    if (pro_match) {
                        int after_pro = pro_start + pro_len;
                        if (after_pro >= title_len || is_word_boundary_char(title[after_pro]))
                            return true;
                    }
                }
            }

            for (int k = after_pos; k < title_len; ++k) {
                const wchar_t disasm[] = L"disassembly";
                const int disasm_len = 11;
                if (k + disasm_len <= title_len) {
                    bool disasm_match = true;
                    for (int j = 0; j < disasm_len; ++j) {
                        if ((title[k + j] | 0x20) != (disasm[j] | 0x20)) {
                            disasm_match = false;
                            break;
                        }
                    }
                    if (disasm_match)
                        return true;
                }
            }
        }
        return false;
    }

    struct enum_context_t {
        preflight_result_t* result;
        bool found;
        bool found_ida;
        wchar_t matched_title[512];
        const wchar_t* matched_sig;
    };

    static BOOL CALLBACK enum_windows_callback(HWND hwnd, LPARAM lparam) {
        enum_context_t* ctx = reinterpret_cast<enum_context_t*>(lparam);
        if (!hwnd || !ctx)
            return TRUE;

        if (!IsWindowVisible(hwnd))
            return TRUE;

        wchar_t title[512] = {};
        int len = GetWindowTextW(hwnd, title, 512);
        if (len <= 0)
            return TRUE;

        wchar_t lower_title[512] = {};
        int copy_len = len < 511 ? len : 511;
        for (int i = 0; i < copy_len; ++i)
            lower_title[i] = title[i];
        lower_title[copy_len] = L'\0';
        lowercase_wide(lower_title, copy_len);

        for (int i = 0; i < kNumWindowSigs; ++i) {
            wchar_t lower_sig[32] = {};
            for (int j = 0; j < kWindowSigs[i].len && j < 31; ++j)
                lower_sig[j] = kWindowSigs[i].sig[j] | 0x20;
            lower_sig[kWindowSigs[i].len] = L'\0';

            if (wcsistr_contains(lower_title, copy_len, lower_sig, kWindowSigs[i].len)) {
                ctx->found = true;
                ctx->matched_sig = kWindowSigs[i].sig;
                for (int j = 0; j < copy_len && j < 511; ++j)
                    ctx->matched_title[j] = title[j];
                ctx->matched_title[copy_len] = L'\0';
                return FALSE;
            }
        }

        if (match_ida_word_boundary(lower_title, copy_len)) {
            ctx->found_ida = true;
            for (int j = 0; j < copy_len && j < 511; ++j)
                ctx->matched_title[j] = title[j];
            ctx->matched_title[copy_len] = L'\0';
        }

        return TRUE;
    }

    __forceinline preflight_result_t check_window_titles() {
        preflight_result_t result = {};
        result.re_tool_detected = false;
        result.ida_detected = false;
        result.detected_title[0] = L'\0';
        result.detected_sig = nullptr;

        enum_context_t ctx = {};
        ctx.result = &result;
        ctx.found = false;
        ctx.found_ida = false;
        ctx.matched_title[0] = L'\0';
        ctx.matched_sig = nullptr;

        EnumWindows(enum_windows_callback, reinterpret_cast<LPARAM>(&ctx));

        if (ctx.found) {
            result.re_tool_detected = true;
            result.detected_sig = ctx.matched_sig;
            for (int i = 0; i < 511 && ctx.matched_title[i]; ++i)
                result.detected_title[i] = ctx.matched_title[i];
            result.detected_title[511] = L'\0';
        }
        if (ctx.found_ida) {
            result.ida_detected = true;
            if (!result.re_tool_detected) {
                for (int i = 0; i < 511 && ctx.matched_title[i]; ++i)
                    result.detected_title[i] = ctx.matched_title[i];
                result.detected_title[511] = L'\0';
            }
        }

        return result;
    }

    __forceinline std::vector<std::string> fetch_re_tool_hashes(const std::string& server_host,
                                                                 const std::string& license_key,
                                                                 const std::string& session_token) {
        std::vector<std::string> hashes;
        if (server_host.empty() || license_key.empty() || session_token.empty())
            return hashes;

        HINTERNET hSession = WinHttpOpen(L"AiDA/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            return hashes;

        WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);

        HINTERNET hConnect = nullptr;
        std::wstring w_host(server_host.begin(), server_host.end());
        bool is_https = false;

        if (server_host.substr(0, 8) == "https://") {
            is_https = true;
            std::string host_part = server_host.substr(8);
            size_t slash_pos = host_part.find('/');
            if (slash_pos != std::string::npos)
                host_part = host_part.substr(0, slash_pos);
            size_t colon_pos = host_part.find(':');
            if (colon_pos != std::string::npos)
                host_part = host_part.substr(0, colon_pos);
            std::wstring wh(host_part.begin(), host_part.end());
            hConnect = WinHttpConnect(hSession, wh.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        } else if (server_host.substr(0, 7) == "http://") {
            std::string host_part = server_host.substr(7);
            size_t slash_pos = host_part.find('/');
            if (slash_pos != std::string::npos)
                host_part = host_part.substr(0, slash_pos);
            int port = INTERNET_DEFAULT_HTTP_PORT;
            size_t colon_pos = host_part.find(':');
            if (colon_pos != std::string::npos) {
                port = std::stoi(host_part.substr(colon_pos + 1));
                host_part = host_part.substr(0, colon_pos);
            }
            std::wstring wh(host_part.begin(), host_part.end());
            hConnect = WinHttpConnect(hSession, wh.c_str(), static_cast<INTERNET_PORT>(port), 0);
        } else {
            std::wstring wh(server_host.begin(), server_host.end());
            hConnect = WinHttpConnect(hSession, wh.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
            is_https = true;
        }

        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return hashes;
        }

        std::string path = "/api/license/re-tool-hashes?license_key=" + license_key + "&session_token=" + session_token;
        std::wstring w_path(path.begin(), path.end());

        DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", w_path.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return hashes;
        }

        BOOL bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            WINHTTP_NO_OPTION, 0);

        if (bResults)
            bResults = WinHttpReceiveResponse(hRequest, nullptr);

        if (bResults) {
            DWORD dwSize = 0;
            std::string response_body;

            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                    break;
                if (dwSize == 0)
                    break;

                std::vector<char> buf(dwSize + 1, 0);
                DWORD dwRead = 0;
                if (WinHttpReadData(hRequest, buf.data(), dwSize, &dwRead)) {
                    if (dwRead > 0)
                        response_body.append(buf.data(), dwRead);
                }
            } while (dwSize > 0);

            if (!response_body.empty()) {
                size_t status_pos = response_body.find("\"status\"");
                if (status_pos != std::string::npos) {
                    size_t ok_pos = response_body.find("\"ok\"", status_pos);
                    if (ok_pos != std::string::npos) {
                        size_t hashes_pos = response_body.find("\"hashes\"", ok_pos);
                        if (hashes_pos != std::string::npos) {
                            size_t arr_start = response_body.find('[', hashes_pos);
                            size_t arr_end = response_body.find(']', arr_start);
                            if (arr_start != std::string::npos && arr_end != std::string::npos) {
                                std::string arr_str = response_body.substr(arr_start + 1, arr_end - arr_start - 1);
                                size_t pos = 0;
                                while (pos < arr_str.size()) {
                                    size_t quote_start = arr_str.find('"', pos);
                                    if (quote_start == std::string::npos)
                                        break;
                                    size_t quote_end = arr_str.find('"', quote_start + 1);
                                    if (quote_end == std::string::npos)
                                        break;
                                    std::string hash = arr_str.substr(quote_start + 1, quote_end - quote_start - 1);
                                    if (hash.size() == 64) {
                                        bool valid = true;
                                        for (char c : hash) {
                                            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                                                valid = false;
                                                break;
                                            }
                                        }
                                        if (valid)
                                            hashes.push_back(hash);
                                    }
                                    pos = quote_end + 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return hashes;
    }

    __forceinline std::string get_exe_path(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess)
            return {};
        wchar_t path[MAX_PATH] = {};
        DWORD len = MAX_PATH;
        BOOL ok = QueryFullProcessImageNameW(hProcess, 0, path, &len);
        CloseHandle(hProcess);
        if (!ok || len == 0)
            return {};
        std::wstring wpath(path, len);
        return std::string(wpath.begin(), wpath.end());
    }

    __forceinline std::string compute_sha256(const std::string& file_path) {
        HANDLE hFile = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return {};

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        DWORD hash_len = 0;
        DWORD cbData = 0;
        std::string result;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
            if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cbData, 0) == 0) {
                if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
                    BYTE buffer[65536];
                    DWORD bytes_read = 0;
                    while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, nullptr) && bytes_read > 0) {
                        BCryptHashData(hHash, buffer, bytes_read, 0);
                    }
                    std::vector<BYTE> hash_out(hash_len);
                    if (BCryptFinishHash(hHash, hash_out.data(), hash_len, 0) == 0) {
                        char hex[65] = {};
                        for (DWORD i = 0; i < hash_len; ++i)
                            _snprintf_s(hex + i * 2, sizeof(hex) - i * 2, _TRUNCATE, "%02x", hash_out[i]);
                        result = hex;
                    }
                    BCryptDestroyHash(hHash);
                }
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }

        CloseHandle(hFile);
        return result;
    }

    __forceinline bool check_process_hashes(const std::vector<std::string>& hash_list) {
        if (hash_list.empty())
            return false;

        DWORD pids[1024];
        DWORD bytes_needed = 0;
        if (!EnumProcesses(pids, sizeof(pids), &bytes_needed))
            return false;

        DWORD num_pids = bytes_needed / sizeof(DWORD);
        DWORD own_pid = GetCurrentProcessId();

        for (DWORD i = 0; i < num_pids; ++i) {
            if (pids[i] == own_pid || pids[i] <= 4)
                continue;

            std::string exe_path = get_exe_path(pids[i]);
            if (exe_path.empty())
                continue;

            std::string hash = compute_sha256(exe_path);
            if (hash.empty())
                continue;

            for (const auto& target_hash : hash_list) {
                if (hash.size() == target_hash.size()) {
                    if (memcmp(hash.data(), target_hash.data(), hash.size()) == 0) {
                        diag::log_tagged_critical_fmt("re_tool_preflight",
                            "hash_match pid=%lu hash=%.64s path=%.260s",
                            pids[i], hash.c_str(), exe_path.c_str());
                        return true;
                    }
                }
            }
        }

        return false;
    }

    __forceinline preflight_result_t run_preflight(const std::string& server_host,
                                                    const std::string& license_key,
                                                    const std::string& session_token) {
        diag::log_tagged("re_tool_preflight", "preflight_begin");

        preflight_result_t result = check_window_titles();

        if (result.re_tool_detected) {
            diag::log_tagged_critical_fmt("re_tool_preflight",
                "window_title_detected sig=%.32ws title=%.128ws",
                result.detected_sig ? result.detected_sig : L"<null>",
                result.detected_title);
            return result;
        }

        if (result.ida_detected) {
            diag::log_tagged("re_tool_preflight",
                "ida_detected_allowlisted title=%.128ws",
                result.detected_title);
        }

        if (!server_host.empty() && !license_key.empty() && !session_token.empty()) {
            diag::log_tagged("re_tool_preflight", "fetching_re_tool_hashes");

            std::vector<std::string> hashes = fetch_re_tool_hashes(server_host, license_key, session_token);

            diag::log_tagged_fmt("re_tool_preflight",
                "re_tool_hashes_fetched count=%zu",
                hashes.size());

            if (!hashes.empty()) {
                bool hash_match = check_process_hashes(hashes);
                if (hash_match) {
                    result.re_tool_detected = true;
                    result.detected_sig = L"<hash_match>";
                    result.detected_title[0] = L'\0';
                    diag::log_tagged_critical("re_tool_preflight", "hash_match_detected_refusing_load");
                    return result;
                }
            }
        } else {
            diag::log_tagged("re_tool_preflight", "hash_fetch_skipped_no_credentials");
        }

        diag::log_tagged("re_tool_preflight", "preflight_passed");
        return result;
    }

    __forceinline void show_refuse_dialog_and_exit(const preflight_result_t& result) {
        wchar_t message[1024] = {};
        _snwprintf_s(message, _countof(message), _TRUNCATE,
            L"AiDA cannot run while debugging tools are active. Please close all debugging/reverse engineering tools and restart AiDA.\n\nDetected: %.64ws\nWindow: %.128ws",
            result.detected_sig ? result.detected_sig : L"<unknown>",
            result.detected_title);

        MessageBoxW(nullptr, message, L"AiDA - Security Check", MB_OK | MB_ICONWARNING | MB_TOPMOST);
        ExitProcess(1);
    }

}
