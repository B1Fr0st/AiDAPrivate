#include "driver_loader.hpp"
#include "whoswho_encrypted.h"
#include "sentinel_encrypted.h"
#ifdef AIDA_LEGACY_DRIVER_MAPPER_AVAILABLE
#include "windmapper_embedded.h"
#endif
#ifdef AIDA_STANDALONE
#include "helpers/diag_log.hpp"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <shlobj.h>
#include <objbase.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_OBJECT_PATH_NOT_FOUND
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xC000003AL)
#endif
#ifndef STATUS_IMAGE_ALREADY_LOADED
#define STATUS_IMAGE_ALREADY_LOADED ((NTSTATUS)0xC000010EL)
#endif
#ifndef STATUS_INVALID_IMAGE_HASH
#define STATUS_INVALID_IMAGE_HASH ((NTSTATUS)0xC0000428L)
#endif

namespace
{
    bool g_loaded = false;
    std::string s_last_error;

    void loader_diag(const char* msg)
    {
#ifdef AIDA_STANDALONE
        diag::log_tagged_critical("driver_loader", msg);
#else
        (void)msg;
#endif
    }

    void loader_diag_fmt(const char* fmt, ...)
    {
#ifdef AIDA_STANDALONE
        char buf[2048];
        va_list ap;
        va_start(ap, fmt);
        _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
        va_end(ap);
        diag::log_tagged_critical("driver_loader", buf);
#else
        (void)fmt;
#endif
    }

    void set_last_error(const char* msg)
    {
        s_last_error.assign(msg ? msg : "");
        if (!s_last_error.empty())
            loader_diag_fmt("last_error=\"%s\"", s_last_error.c_str());
    }

    void set_last_error(const std::string& msg)
    {
        s_last_error = msg;
        if (!s_last_error.empty())
            loader_diag_fmt("last_error=\"%s\"", s_last_error.c_str());
    }

    void set_last_error_status(const char* prefix, NTSTATUS status)
    {
        char buf[64] = {};
        std::snprintf(buf, sizeof(buf), " (NTSTATUS=0x%08lX)",
                      static_cast<unsigned long>(status));
        std::string out = prefix ? prefix : "";
        out += buf;
        set_last_error(out);
    }

    void set_last_error_fmt(const char* fmt, ...)
    {
        char buf[512];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        set_last_error(buf);
    }

    std::string utf8_from_wide(const std::wstring& w)
    {
        if (w.empty())
            return {};
        int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
            return {};
        std::string out(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
        return out;
    }

    bool should_keep_stage()
    {
#ifndef AIDA_ALLOW_UNSAFE_DRIVER_STAGE_PRESERVE
        return false;
#else
        wchar_t env[16] = {};
        DWORD n = GetEnvironmentVariableW(L"AIDA_KEEP_DRIVER_STAGE", env, static_cast<DWORD>(_countof(env)));
        if (n == 0)
            n = GetEnvironmentVariableW(L"AIDA_KEEP_STAGE", env, static_cast<DWORD>(_countof(env)));
        return n > 0 && env[0] != L'\0' && env[0] != L'0';
#endif
    }

    bool legacy_mapper_enabled()
    {
#ifndef AIDA_LEGACY_DRIVER_MAPPER_AVAILABLE
        return false;
#else
        wchar_t env[16] = {};
        DWORD n = GetEnvironmentVariableW(L"AIDA_DISABLE_LEGACY_DRIVER_MAPPER", env, static_cast<DWORD>(_countof(env)));
        if (n == 0 || n >= static_cast<DWORD>(_countof(env)))
            return true;
        return !(env[0] == L'1' || _wcsicmp(env, L"true") == 0 || _wcsicmp(env, L"yes") == 0);
#endif
    }

    const char* nt_status_name(NTSTATUS status)
    {
        switch (static_cast<unsigned long>(status)) {
        case 0x00000000UL: return "STATUS_SUCCESS";
        case 0xC0000035UL: return "STATUS_OBJECT_NAME_COLLISION";
        case 0xC000010EUL: return "STATUS_IMAGE_ALREADY_LOADED";
        case 0xC0000061UL: return "STATUS_PRIVILEGE_NOT_HELD";
        case 0xC0000034UL: return "STATUS_OBJECT_NAME_NOT_FOUND";
        case 0xC000003AUL: return "STATUS_OBJECT_PATH_NOT_FOUND";
        case 0xC0000428UL: return "STATUS_INVALID_IMAGE_HASH";
        case 0xC000036BUL: return "STATUS_DRIVER_BLOCKED_CRITICAL";
        case 0xC0000603UL: return "STATUS_IMAGE_CERT_REVOKED";
        default: return "STATUS_UNKNOWN";
        }
    }

    bool nt_success(NTSTATUS status)
    {
        return status >= 0;
    }

    bool native_load_status_ok(NTSTATUS status)
    {
        return nt_success(status) ||
            status == STATUS_OBJECT_NAME_COLLISION ||
            status == STATUS_IMAGE_ALREADY_LOADED;
    }

    bool verify_blob_integrity(const unsigned char* data, unsigned long size,
                               unsigned long expected_size)
    {
        if (size != expected_size)
            return false;
        if (size < 64 || data[0] != 'M' || data[1] != 'Z')
            return false;
        uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(data + 0x3C);
        if (e_lfanew >= size - 4)
            return false;
        if (data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E' ||
            data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0)
            return false;
        return true;
    }

    std::wstring get_module_dir();
    std::wstring random_token(size_t bytes);

    std::wstring get_stage_dir()
    {
#ifdef AIDA_ALLOW_UNSAFE_DRIVER_STAGE_PRESERVE
        wchar_t override_dir[MAX_PATH] = {};
        DWORD override_len = GetEnvironmentVariableW(L"AIDA_DRIVER_STAGE_DIR", override_dir, MAX_PATH);
        if (override_len > 0 && override_len < MAX_PATH) {
            std::filesystem::path p(override_dir);
            std::error_code ec;
            std::filesystem::create_directories(p, ec);
            if (!ec)
                return p.wstring();
            loader_diag_fmt("stage_override_create_failed path=\"%s\" ec=%lu",
                utf8_from_wide(p.wstring()).c_str(),
                static_cast<unsigned long>(ec.value()));
        }
#endif

        std::wstring token = random_token(8);
        if (token.empty())
            return {};
        wchar_t* local = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &local)) || !local)
            return {};
        std::filesystem::path p(local);
        CoTaskMemFree(local);
        p /= L"AiDA";
        p /= L"Standalone";
        p /= L"AiDADriverStage";
        p /= token;
        std::error_code ec;
        std::filesystem::create_directories(p, ec);
        if (ec)
            return {};
        return p.wstring();
    }

    std::wstring get_module_dir()
    {
        wchar_t path[MAX_PATH] = {};
        DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return {};
        std::filesystem::path p(path);
        return p.parent_path().wstring();
    }

    std::wstring resolve_mapper_log_path()
    {
        PWSTR docs = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_CREATE, nullptr, &docs)) && docs) {
            std::filesystem::path path(docs);
            CoTaskMemFree(docs);
            return (path / L"windmapper.log").wstring();
        }
        if (docs)
            CoTaskMemFree(docs);

        std::wstring module_dir = get_module_dir();
        if (!module_dir.empty())
            return (std::filesystem::path(module_dir) / L"WindMapper_debug.log").wstring();
        return {};
    }

    std::wstring random_token(size_t bytes)
    {
        std::wstring out;
        unsigned char raw[32] = {};
        if (bytes > sizeof(raw))
            bytes = sizeof(raw);
        if (BCryptGenRandom(nullptr, raw, static_cast<ULONG>(bytes),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return out;
        static const wchar_t* hex = L"0123456789abcdef";
        out.reserve(bytes * 2);
        for (size_t i = 0; i < bytes; ++i) {
            out.push_back(hex[(raw[i] >> 4) & 0xF]);
            out.push_back(hex[raw[i] & 0xF]);
        }
        return out;
    }

    std::wstring make_stage_path(const std::wstring& dir, const wchar_t* ext)
    {
        if (dir.empty())
            return {};
        if (!ext || !*ext)
            return {};
        std::wstring token = random_token(12);
        if (token.empty())
            return {};
        std::wstring name = token;
        std::filesystem::path p = std::filesystem::path(dir) / (name + ext);
        return p.wstring();
    }

    bool aes_gcm_decrypt(const unsigned char* ciphertext, unsigned long ciphertext_len,
                         const unsigned char* key, unsigned long key_len,
                         const unsigned char* nonce, unsigned long nonce_len,
                         const unsigned char* tag, unsigned long tag_len,
                         unsigned char* plaintext, unsigned long plaintext_len)
    {
        if (!ciphertext || !key || !nonce || !tag || !plaintext)
            return false;
        if (key_len != 32 || nonce_len != 12 || tag_len != 16)
            return false;
        if (ciphertext_len != plaintext_len)
            return false;

        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            set_last_error_status("BCryptOpenAlgorithmProvider failed", status);
            return false;
        }

        status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                                   reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                   sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            set_last_error_status("BCryptSetProperty(GCM) failed", status);
            return false;
        }

        DWORD object_length = 0;
        DWORD got = 0;
        status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&object_length),
                                   sizeof(object_length), &got, 0);
        if (!BCRYPT_SUCCESS(status) || got != sizeof(object_length) || object_length == 0) {
            BCryptCloseAlgorithmProvider(alg, 0);
            set_last_error_status("BCryptGetProperty(OBJECT_LENGTH) failed", status);
            return false;
        }

        std::vector<unsigned char> key_object(object_length, 0);
        BCRYPT_KEY_HANDLE hkey = nullptr;
        status = BCryptGenerateSymmetricKey(alg, &hkey,
                                            key_object.data(), object_length,
                                            const_cast<PUCHAR>(key), key_len, 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            set_last_error_status("BCryptGenerateSymmetricKey failed", status);
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = {};
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(nonce);
        info.cbNonce = nonce_len;
        info.pbAuthData = nullptr;
        info.cbAuthData = 0;
        info.pbTag = const_cast<PUCHAR>(tag);
        info.cbTag = tag_len;
        info.pbMacContext = nullptr;
        info.cbMacContext = 0;
        info.cbAAD = 0;
        info.cbData = 0;
        info.dwFlags = 0;

        ULONG out_len = 0;
        status = BCryptDecrypt(hkey,
                               const_cast<PUCHAR>(ciphertext), ciphertext_len,
                               &info,
                               nullptr, 0,
                               plaintext, plaintext_len,
                               &out_len, 0);

        BCryptDestroyKey(hkey);
        SecureZeroMemory(key_object.data(), key_object.size());
        BCryptCloseAlgorithmProvider(alg, 0);

        if (status == STATUS_AUTH_TAG_MISMATCH) {
            SecureZeroMemory(plaintext, plaintext_len);
            set_last_error("AES-GCM tag mismatch (driver blob tampered)");
            return false;
        }
        if (!BCRYPT_SUCCESS(status)) {
            SecureZeroMemory(plaintext, plaintext_len);
            set_last_error_status("BCryptDecrypt failed", status);
            return false;
        }
        if (out_len != plaintext_len) {
            SecureZeroMemory(plaintext, plaintext_len);
            set_last_error("AES-GCM decrypt produced unexpected length");
            return false;
        }
        return true;
    }

    bool decrypt_and_write(const unsigned char* ciphertext, unsigned long ciphertext_len,
                           const unsigned char* key, unsigned long key_len,
                           const unsigned char* nonce, unsigned long nonce_len,
                           const unsigned char* tag, unsigned long tag_len,
                           const std::wstring& out_path,
                           const char* label)
    {
        const std::string out_path_utf8 = utf8_from_wide(out_path);
        loader_diag_fmt("stage_write_begin label=%s path=\"%s\" bytes=%lu",
            label ? label : "?",
            out_path_utf8.empty() ? "<empty>" : out_path_utf8.c_str(),
            ciphertext_len);

        auto* buf = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, ciphertext_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf) {
            set_last_error_fmt("VirtualAlloc failed for %s decrypt buffer gle=%lu bytes=%lu",
                label ? label : "driver", static_cast<unsigned long>(GetLastError()), ciphertext_len);
            return false;
        }

        if (!aes_gcm_decrypt(ciphertext, ciphertext_len,
                             key, key_len,
                             nonce, nonce_len,
                             tag, tag_len,
                             buf, ciphertext_len)) {
            SecureZeroMemory(buf, ciphertext_len);
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        if (!verify_blob_integrity(buf, ciphertext_len, ciphertext_len)) {
            SecureZeroMemory(buf, ciphertext_len);
            VirtualFree(buf, 0, MEM_RELEASE);
            set_last_error_fmt("Decrypted %s blob failed PE integrity check", label ? label : "driver");
            return false;
        }

        HANDLE hf = CreateFileW(out_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            DWORD gle = GetLastError();
            SecureZeroMemory(buf, ciphertext_len);
            VirtualFree(buf, 0, MEM_RELEASE);
            set_last_error_fmt("CreateFileW failed for staged %s gle=%lu path=\"%s\"",
                label ? label : "driver", static_cast<unsigned long>(gle),
                out_path_utf8.empty() ? "<empty>" : out_path_utf8.c_str());
            return false;
        }

        DWORD written = 0;
        BOOL ok = WriteFile(hf, buf, ciphertext_len, &written, nullptr);
        DWORD write_gle = GetLastError();
        FlushFileBuffers(hf);
        CloseHandle(hf);
        SecureZeroMemory(buf, ciphertext_len);
        VirtualFree(buf, 0, MEM_RELEASE);

        if (!ok || written != ciphertext_len) {
            set_last_error_fmt("WriteFile failed for staged %s ok=%d written=%lu expected=%lu gle=%lu path=\"%s\"",
                label ? label : "driver",
                ok ? 1 : 0,
                static_cast<unsigned long>(written),
                ciphertext_len,
                static_cast<unsigned long>(write_gle),
                out_path_utf8.empty() ? "<empty>" : out_path_utf8.c_str());
            return false;
        }
        loader_diag_fmt("stage_write_ok label=%s path=\"%s\" bytes=%lu",
            label ? label : "?",
            out_path_utf8.empty() ? "<empty>" : out_path_utf8.c_str(),
            ciphertext_len);
        return true;
    }

    bool file_exists(const std::wstring& path)
    {
        DWORD attr = GetFileAttributesW(path.c_str());
        return attr != INVALID_FILE_ATTRIBUTES;
    }

    bool posix_delete_file(const std::wstring& path, DWORD* out_gle)
    {
        if (out_gle)
            *out_gle = ERROR_SUCCESS;
        HANDLE hf = CreateFileW(path.c_str(), DELETE | SYNCHRONIZE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            if (out_gle)
                *out_gle = GetLastError();
            return !file_exists(path);
        }
        struct disposition_info_ex_t {
            DWORD Flags;
        };
        disposition_info_ex_t info = {};
        info.Flags = 0x00000001UL | 0x00000002UL | 0x00000010UL;
        BOOL ok = SetFileInformationByHandle(
            hf,
            static_cast<FILE_INFO_BY_HANDLE_CLASS>(21),
            &info,
            sizeof(info));
        DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(hf);
        if (out_gle)
            *out_gle = gle;
        return ok || !file_exists(path);
    }

    bool secure_delete(const std::wstring& path)
    {
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE | DELETE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size;
            if (GetFileSizeEx(hf, &size) && size.QuadPart > 0) {
                unsigned char zeros[65536];
                SecureZeroMemory(zeros, sizeof(zeros));
                LARGE_INTEGER pos = {};
                SetFilePointerEx(hf, pos, nullptr, FILE_BEGIN);
                LONGLONG remaining = size.QuadPart;
                while (remaining > 0) {
                    DWORD chunk = remaining > static_cast<LONGLONG>(sizeof(zeros))
                        ? static_cast<DWORD>(sizeof(zeros))
                        : static_cast<DWORD>(remaining);
                    DWORD written = 0;
                    if (!WriteFile(hf, zeros, chunk, &written, nullptr) || written == 0)
                        break;
                    remaining -= written;
                }
                FlushFileBuffers(hf);
            }
            CloseHandle(hf);
        }
        BOOL deleted = DeleteFileW(path.c_str());
        DWORD delete_gle = deleted ? ERROR_SUCCESS : GetLastError();
        if (!deleted && (delete_gle == ERROR_ACCESS_DENIED ||
                         delete_gle == ERROR_SHARING_VIOLATION ||
                         delete_gle == ERROR_CANNOT_MAKE ||
                         delete_gle == ERROR_INVALID_PARAMETER)) {
            DWORD posix_gle = ERROR_SUCCESS;
            bool posix_ok = posix_delete_file(path, &posix_gle);
            loader_diag_fmt("stage_posix_delete path=\"%s\" ok=%d gle=%lu",
                utf8_from_wide(path).c_str(),
                posix_ok ? 1 : 0,
                static_cast<unsigned long>(posix_gle));
            return posix_ok || !file_exists(path);
        }
        return deleted || !file_exists(path);
    }

    bool cleanup_stage_file(const std::wstring& path, const char* label)
    {
        if (path.empty())
            return true;
        const std::string path_utf8 = utf8_from_wide(path);
        if (should_keep_stage()) {
            loader_diag_fmt("stage_preserved label=%s path=\"%s\"",
                label ? label : "?",
                path_utf8.empty() ? "<empty>" : path_utf8.c_str());
            return false;
        }
        loader_diag_fmt("stage_delete label=%s path=\"%s\"",
            label ? label : "?",
            path_utf8.empty() ? "<empty>" : path_utf8.c_str());
        bool ok = secure_delete(path);
        loader_diag_fmt("stage_delete_result label=%s ok=%d exists_after=%d path=\"%s\"",
            label ? label : "?",
            ok ? 1 : 0,
            file_exists(path) ? 1 : 0,
            path_utf8.empty() ? "<empty>" : path_utf8.c_str());
        return ok;
    }

    bool cleanup_stage_dir(const std::wstring& path)
    {
        if (path.empty() || should_keep_stage())
            return path.empty();
        std::error_code remove_ec;
        std::filesystem::remove(path, remove_ec);
        std::error_code exists_ec;
        bool gone = !std::filesystem::exists(path, exists_ec);
        loader_diag_fmt("stage_dir_delete path=\"%s\" ec=%lu",
            utf8_from_wide(path).c_str(),
            static_cast<unsigned long>(remove_ec.value()));
        loader_diag_fmt("stage_dir_delete_result ok=%d exists_after=%d path=\"%s\"",
            gone ? 1 : 0,
            gone ? 0 : 1,
            utf8_from_wide(path).c_str());
        return gone;
    }

    bool enable_load_driver_privilege()
    {
        const ULONGLONG started = GetTickCount64();
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            loader_diag_fmt("privilege_open_token_failed gle=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(GetTickCount64() - started));
            return false;
        }
        LUID luid = {};
        if (!LookupPrivilegeValueW(nullptr, L"SeLoadDriverPrivilege", &luid)) {
            DWORD gle = GetLastError();
            CloseHandle(token);
            loader_diag_fmt("privilege_lookup_failed gle=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(gle),
                static_cast<unsigned long long>(GetTickCount64() - started));
            return false;
        }
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        DWORD gle = GetLastError();
        CloseHandle(token);
        bool ok = adjusted && gle == ERROR_SUCCESS;
        loader_diag_fmt("privilege_adjust name=SeLoadDriverPrivilege ok=%d gle=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - started));
        return ok;
    }

    bool set_reg_dword(HKEY key, const wchar_t* name, DWORD value)
    {
        return RegSetValueExW(key, name, 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(value)) == ERROR_SUCCESS;
    }

    bool set_reg_string(HKEY key, const wchar_t* name, const std::wstring& value, DWORD type)
    {
        return RegSetValueExW(key, name, 0, type,
            reinterpret_cast<const BYTE*>(value.c_str()),
            static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    }

    std::wstring make_service_name(const wchar_t* prefix)
    {
        std::wstring token = random_token(8);
        if (token.empty())
            return {};
        std::wstring out = prefix && *prefix ? prefix : L"AiDA";
        out += L"_";
        out += token;
        return out;
    }

    bool delete_service_registry_tree(const std::wstring& service_name, const char* label)
    {
        if (service_name.empty())
            return true;
        std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Services\\";
        subkey += service_name;
        LSTATUS st = RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.c_str());
        HKEY probe = nullptr;
        LSTATUS probe_st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_QUERY_VALUE, &probe);
        if (probe)
            RegCloseKey(probe);
        bool exists_after = probe_st == ERROR_SUCCESS;
        bool ok = (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND) && !exists_after;
        loader_diag_fmt("native_service_delete label=%s service=\"%s\" ok=%d status=%lu exists_after=%d probe_status=%lu",
            label ? label : "?",
            utf8_from_wide(service_name).c_str(),
            ok ? 1 : 0,
            static_cast<unsigned long>(st),
            exists_after ? 1 : 0,
            static_cast<unsigned long>(probe_st));
        return ok;
    }

    bool create_native_driver_service(const std::wstring& service_name,
                                      const std::wstring& image_path,
                                      const char* label)
    {
        const ULONGLONG started = GetTickCount64();
        if (service_name.empty() || image_path.empty()) {
            loader_diag_fmt("native_service_create_invalid label=%s service_empty=%d image_empty=%d",
                label ? label : "?",
                service_name.empty() ? 1 : 0,
                image_path.empty() ? 1 : 0);
            return false;
        }

        std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Services\\";
        subkey += service_name;
        HKEY key = nullptr;
        DWORD disposition = 0;
        LSTATUS st = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE,
            nullptr, &key, &disposition);
        if (st != ERROR_SUCCESS) {
            loader_diag_fmt("native_service_create_failed label=%s service=\"%s\" status=%lu elapsed_ms=%llu",
                label ? label : "?",
                utf8_from_wide(service_name).c_str(),
                static_cast<unsigned long>(st),
                static_cast<unsigned long long>(GetTickCount64() - started));
            return false;
        }

        std::wstring nt_image_path = L"\\??\\";
        nt_image_path += image_path;
        bool ok = set_reg_string(key, L"ImagePath", nt_image_path, REG_EXPAND_SZ) &&
            set_reg_dword(key, L"Type", 1) &&
            set_reg_dword(key, L"Start", 3) &&
            set_reg_dword(key, L"ErrorControl", 1);
        DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
        RegFlushKey(key);
        RegCloseKey(key);

        loader_diag_fmt("native_service_create label=%s service=\"%s\" disposition=%lu ok=%d gle=%lu image=\"%s\" elapsed_ms=%llu",
            label ? label : "?",
            utf8_from_wide(service_name).c_str(),
            static_cast<unsigned long>(disposition),
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            utf8_from_wide(image_path).c_str(),
            static_cast<unsigned long long>(GetTickCount64() - started));
        if (!ok)
            delete_service_registry_tree(service_name, label);
        return ok;
    }

    struct native_unicode_string_t {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    };

    using nt_load_driver_t = NTSTATUS(NTAPI*)(native_unicode_string_t*);

    bool nt_load_driver_service(const std::wstring& service_name,
                                const char* label,
                                NTSTATUS* out_status)
    {
        const ULONGLONG started = GetTickCount64();
        if (out_status)
            *out_status = STATUS_OBJECT_NAME_NOT_FOUND;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            ntdll = LoadLibraryW(L"ntdll.dll");
        if (!ntdll) {
            loader_diag_fmt("native_ntdll_load_failed label=%s gle=%lu",
                label ? label : "?",
                static_cast<unsigned long>(GetLastError()));
            return false;
        }
        auto nt_load_driver = reinterpret_cast<nt_load_driver_t>(
            GetProcAddress(ntdll, "NtLoadDriver"));
        if (!nt_load_driver) {
            loader_diag_fmt("native_ntload_resolve_failed label=%s gle=%lu",
                label ? label : "?",
                static_cast<unsigned long>(GetLastError()));
            return false;
        }

        std::wstring native_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        native_path += service_name;
        native_unicode_string_t us = {};
        us.Length = static_cast<USHORT>(native_path.size() * sizeof(wchar_t));
        us.MaximumLength = static_cast<USHORT>((native_path.size() + 1) * sizeof(wchar_t));
        us.Buffer = native_path.data();

        loader_diag_fmt("native_ntload_begin label=%s service=\"%s\" path=\"%s\" pid=%lu tid=%lu",
            label ? label : "?",
            utf8_from_wide(service_name).c_str(),
            utf8_from_wide(native_path).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        NTSTATUS status = nt_load_driver(&us);
        if (out_status)
            *out_status = status;
        loader_diag_fmt("native_ntload_end label=%s status=0x%08lX status_name=%s ok=%d elapsed_ms=%llu",
            label ? label : "?",
            static_cast<unsigned long>(status),
            nt_status_name(status),
            native_load_status_ok(status) ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - started));
        return native_load_status_ok(status);
    }

    bool load_staged_native_driver(const std::wstring& image_path,
                                   const wchar_t* service_prefix,
                                   const char* label,
                                   NTSTATUS* out_status,
                                   bool* out_registry_deleted)
    {
        if (out_registry_deleted)
            *out_registry_deleted = false;
        std::wstring service_name = make_service_name(service_prefix);
        if (service_name.empty()) {
            if (out_status)
                *out_status = STATUS_OBJECT_NAME_NOT_FOUND;
            return false;
        }
        delete_service_registry_tree(service_name, label);
        if (!create_native_driver_service(service_name, image_path, label)) {
            if (out_status)
                *out_status = STATUS_OBJECT_PATH_NOT_FOUND;
            if (out_registry_deleted)
                *out_registry_deleted = delete_service_registry_tree(service_name, label);
            return false;
        }
        NTSTATUS status = STATUS_SUCCESS;
        bool loaded = nt_load_driver_service(service_name, label, &status);
        bool deleted = delete_service_registry_tree(service_name, label);
        if (out_status)
            *out_status = status;
        if (out_registry_deleted)
            *out_registry_deleted = deleted;
        return loaded && deleted;
    }

    bool initialize_with_native_services()
    {
        const ULONGLONG started = GetTickCount64();
        loader_diag_fmt("native_load_begin pid=%lu tid=%lu",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));

        if (!enable_load_driver_privilege()) {
            set_last_error("Native driver load failed: SeLoadDriverPrivilege is unavailable");
            return false;
        }

        std::wstring stage = get_stage_dir();
        if (stage.empty()) {
            set_last_error("Failed to resolve LocalAppData stage directory");
            return false;
        }
        loader_diag_fmt("native_stage_dir=\"%s\" keep_stage=%d",
            utf8_from_wide(stage).c_str(), should_keep_stage() ? 1 : 0);

        std::wstring whoswho_path = make_stage_path(stage, L".sys");
        std::wstring sentinel_path = make_stage_path(stage, L".sys");
        if (whoswho_path.empty() || sentinel_path.empty()) {
            cleanup_stage_dir(stage);
            set_last_error("Failed to allocate native driver stage paths");
            return false;
        }
        loader_diag_fmt("native_stage_paths whoswho=\"%s\" sentinel=\"%s\"",
            utf8_from_wide(whoswho_path).c_str(),
            utf8_from_wide(sentinel_path).c_str());

        bool whoswho_written = decrypt_and_write(g_whoswho_ciphertext, g_whoswho_ciphertext_len,
                                                 g_whoswho_key, sizeof(g_whoswho_key),
                                                 g_whoswho_nonce, sizeof(g_whoswho_nonce),
                                                 g_whoswho_tag, sizeof(g_whoswho_tag),
                                                 whoswho_path, "whoswho");
        bool sentinel_written = false;
        if (whoswho_written) {
            sentinel_written = decrypt_and_write(g_sentinel_ciphertext, g_sentinel_ciphertext_len,
                                                 g_sentinel_key, sizeof(g_sentinel_key),
                                                 g_sentinel_nonce, sizeof(g_sentinel_nonce),
                                                 g_sentinel_tag, sizeof(g_sentinel_tag),
                                                 sentinel_path, "sentinel");
        }

        NTSTATUS whoswho_status = STATUS_OBJECT_NAME_NOT_FOUND;
        NTSTATUS sentinel_status = STATUS_OBJECT_NAME_NOT_FOUND;
        bool whoswho_registry_deleted = true;
        bool sentinel_registry_deleted = true;
        bool whoswho_loaded = false;
        bool sentinel_loaded = false;
        bool whoswho_deleted = false;
        bool sentinel_deleted = false;

        if (whoswho_written && sentinel_written) {
            whoswho_loaded = load_staged_native_driver(whoswho_path, L"AiDAWhosWho",
                "whoswho", &whoswho_status, &whoswho_registry_deleted);
            whoswho_deleted = cleanup_stage_file(whoswho_path, "whoswho");
            if (whoswho_loaded && whoswho_deleted) {
                sentinel_loaded = load_staged_native_driver(sentinel_path, L"AiDASentinel",
                    "sentinel", &sentinel_status, &sentinel_registry_deleted);
            }
            sentinel_deleted = cleanup_stage_file(sentinel_path, "sentinel");
        } else {
            whoswho_deleted = cleanup_stage_file(whoswho_path, "whoswho");
            sentinel_deleted = cleanup_stage_file(sentinel_path, "sentinel");
        }

        bool stage_dir_deleted = cleanup_stage_dir(stage);

        loader_diag_fmt("native_load_summary whoswho_written=%d sentinel_written=%d whoswho_loaded=%d sentinel_loaded=%d whoswho_status=0x%08lX whoswho_status_name=%s sentinel_status=0x%08lX sentinel_status_name=%s whoswho_reg_deleted=%d sentinel_reg_deleted=%d whoswho_file_deleted=%d sentinel_file_deleted=%d stage_dir_deleted=%d elapsed_ms=%llu",
            whoswho_written ? 1 : 0,
            sentinel_written ? 1 : 0,
            whoswho_loaded ? 1 : 0,
            sentinel_loaded ? 1 : 0,
            static_cast<unsigned long>(whoswho_status),
            nt_status_name(whoswho_status),
            static_cast<unsigned long>(sentinel_status),
            nt_status_name(sentinel_status),
            whoswho_registry_deleted ? 1 : 0,
            sentinel_registry_deleted ? 1 : 0,
            whoswho_deleted ? 1 : 0,
            sentinel_deleted ? 1 : 0,
            stage_dir_deleted ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - started));

        if (!whoswho_written || !sentinel_written)
            return false;
        if (!whoswho_deleted || !sentinel_deleted) {
            set_last_error_fmt("Native driver load failed closed: staged driver cleanup failed whoswho_deleted=%d sentinel_deleted=%d",
                whoswho_deleted ? 1 : 0,
                sentinel_deleted ? 1 : 0);
            return false;
        }
        if (!stage_dir_deleted) {
            set_last_error("Native driver load failed closed: stage directory cleanup failed");
            return false;
        }
        if (!whoswho_registry_deleted || !sentinel_registry_deleted) {
            set_last_error_fmt("Native driver load failed closed: service registry cleanup failed whoswho_reg_deleted=%d sentinel_reg_deleted=%d",
                whoswho_registry_deleted ? 1 : 0,
                sentinel_registry_deleted ? 1 : 0);
            return false;
        }
        if (!whoswho_loaded) {
            set_last_error_fmt("Native WhosWho load failed status=0x%08lX status_name=%s",
                static_cast<unsigned long>(whoswho_status),
                nt_status_name(whoswho_status));
            return false;
        }
        if (!sentinel_loaded) {
            set_last_error_fmt("Native Sentinel load failed status=0x%08lX status_name=%s",
                static_cast<unsigned long>(sentinel_status),
                nt_status_name(sentinel_status));
            return false;
        }

        loader_diag("native_load_success");
        return true;
    }

}

namespace driver_loader
{
    bool is_driver_loaded()
    {
        return g_loaded;
    }

    void mark_already_loaded()
    {
        g_loaded = true;
        s_last_error.clear();
    }

    const std::string& last_error()
    {
        return s_last_error;
    }

    bool initialize_and_load()
    {
        if (g_loaded)
            return true;

        s_last_error.clear();
        loader_diag("initialize_and_load_begin");

        if (initialize_with_native_services()) {
            g_loaded = true;
            loader_diag("initialize_and_load_success mode=native_services");
            return true;
        }

        std::string native_error = s_last_error;

        if (!legacy_mapper_enabled()) {
            loader_diag("legacy_mapper_disabled");
            if (!native_error.empty()) {
                set_last_error(native_error + "; legacy mapper disabled for normal startup");
            } else {
                set_last_error("Native driver load failed; legacy mapper disabled for normal startup");
            }
            return false;
        }

#ifndef AIDA_LEGACY_DRIVER_MAPPER_AVAILABLE
        (void)native_error;
        return false;
#else
        loader_diag("legacy_mapper_enabled");
        std::wstring stage = get_stage_dir();
        if (stage.empty()) {
            set_last_error("Failed to resolve LocalAppData stage directory");
            return false;
        }
        loader_diag_fmt("stage_dir=\"%s\" keep_stage=%d",
            utf8_from_wide(stage).c_str(), should_keep_stage() ? 1 : 0);

        std::wstring mapper_path = make_stage_path(stage, L".exe");
        std::wstring whoswho_path = make_stage_path(stage, L".sys");
        std::wstring sentinel_path = make_stage_path(stage, L".sys");
        if (mapper_path.empty() || whoswho_path.empty() || sentinel_path.empty()) {
            set_last_error("Failed to allocate driver stage paths");
            cleanup_stage_dir(stage);
            return false;
        }
        loader_diag_fmt("stage_paths mapper=\"%s\" whoswho=\"%s\" sentinel=\"%s\"",
            utf8_from_wide(mapper_path).c_str(),
            utf8_from_wide(whoswho_path).c_str(),
            utf8_from_wide(sentinel_path).c_str());

        if (!decrypt_and_write(g_windmapper_ciphertext, g_windmapper_ciphertext_len,
                               g_windmapper_key, sizeof(g_windmapper_key),
                               g_windmapper_nonce, sizeof(g_windmapper_nonce),
                               g_windmapper_tag, sizeof(g_windmapper_tag),
                               mapper_path, "windmapper")) {
            cleanup_stage_file(mapper_path, "windmapper");
            cleanup_stage_dir(stage);
            return false;
        }

        if (!decrypt_and_write(g_whoswho_ciphertext, g_whoswho_ciphertext_len,
                               g_whoswho_key, sizeof(g_whoswho_key),
                               g_whoswho_nonce, sizeof(g_whoswho_nonce),
                               g_whoswho_tag, sizeof(g_whoswho_tag),
                               whoswho_path, "whoswho")) {
            cleanup_stage_file(mapper_path, "windmapper");
            cleanup_stage_file(whoswho_path, "whoswho");
            cleanup_stage_dir(stage);
            return false;
        }

        if (!decrypt_and_write(g_sentinel_ciphertext, g_sentinel_ciphertext_len,
                               g_sentinel_key, sizeof(g_sentinel_key),
                               g_sentinel_nonce, sizeof(g_sentinel_nonce),
                               g_sentinel_tag, sizeof(g_sentinel_tag),
                               sentinel_path, "sentinel")) {
            cleanup_stage_file(mapper_path, "windmapper");
            cleanup_stage_file(whoswho_path, "whoswho");
            cleanup_stage_file(sentinel_path, "sentinel");
            cleanup_stage_dir(stage);
            return false;
        }

        std::wstring cmdline = L"\"" + mapper_path + L"\" \"" +
                               whoswho_path + L"\" \"" + sentinel_path + L"\"";
        loader_diag_fmt("mapper_cmdline=\"%s\"", utf8_from_wide(cmdline).c_str());

        std::wstring mapper_log_path = resolve_mapper_log_path();
        if (!mapper_log_path.empty()) {
            SetEnvironmentVariableW(L"AIDA_MAPPER_LOG", mapper_log_path.c_str());
            loader_diag_fmt("mapper_log_path=\"%s\"", utf8_from_wide(mapper_log_path).c_str());
        } else {
            SetEnvironmentVariableW(L"AIDA_MAPPER_LOG", nullptr);
            loader_diag("mapper_log_path=<unresolved>");
        }

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};
        loader_diag("mapper_create_process_begin");
        BOOL created = CreateProcessW(
            mapper_path.c_str(),
            &cmdline[0],
            nullptr, nullptr,
            FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            nullptr, nullptr,
            &si, &pi);

        if (!created) {
            DWORD gle = GetLastError();
            cleanup_stage_file(mapper_path, "windmapper");
            cleanup_stage_file(whoswho_path, "whoswho");
            cleanup_stage_file(sentinel_path, "sentinel");
            cleanup_stage_dir(stage);
            if (gle == ERROR_VIRUS_INFECTED || gle == ERROR_VIRUS_DELETED) {
                set_last_error_fmt("Security software blocked mapper stage gle=%lu mapper=\"%s\" stage_dir=\"%s\"",
                    static_cast<unsigned long>(gle),
                    utf8_from_wide(mapper_path).c_str(),
                    utf8_from_wide(stage).c_str());
            } else {
                set_last_error_fmt("CreateProcessW failed for mapper stage gle=%lu mapper=\"%s\"",
                    static_cast<unsigned long>(gle), utf8_from_wide(mapper_path).c_str());
            }
            return false;
        }
        loader_diag_fmt("mapper_create_process_ok pid=%lu tid=%lu",
            static_cast<unsigned long>(pi.dwProcessId),
            static_cast<unsigned long>(pi.dwThreadId));

        HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
        if (hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
            jeli.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                    &jeli, sizeof(jeli));
            BOOL assigned = AssignProcessToJobObject(hJob, pi.hProcess);
            loader_diag_fmt("mapper_job assigned=%d gle=%lu",
                assigned ? 1 : 0, static_cast<unsigned long>(GetLastError()));
        } else {
            loader_diag_fmt("mapper_job create_failed gle=%lu", static_cast<unsigned long>(GetLastError()));
        }

        DWORD resume_result = ResumeThread(pi.hThread);
        if (resume_result == static_cast<DWORD>(-1)) {
            loader_diag_fmt("mapper_resume_failed gle=%lu",
                static_cast<unsigned long>(GetLastError()));
        } else {
            loader_diag_fmt("mapper_resume_ok previous_suspend_count=%lu",
                static_cast<unsigned long>(resume_result));
        }

        DWORD wait_result = WaitForSingleObject(pi.hProcess, 90000);
        DWORD wait_gle = GetLastError();
        loader_diag_fmt("mapper_wait result=0x%08lX gle=%lu",
            static_cast<unsigned long>(wait_result),
            static_cast<unsigned long>(wait_gle));

        DWORD exit_code = 1;
        BOOL got_exit = GetExitCodeProcess(pi.hProcess, &exit_code);
        DWORD exit_gle = GetLastError();
        loader_diag_fmt("mapper_exit got=%d code=0x%08lX gle=%lu log=\"%s\"",
            got_exit ? 1 : 0,
            static_cast<unsigned long>(exit_code),
            static_cast<unsigned long>(exit_gle),
            mapper_log_path.empty() ? "<unresolved>" : utf8_from_wide(mapper_log_path).c_str());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (hJob)
            CloseHandle(hJob);

        bool mapper_deleted = cleanup_stage_file(mapper_path, "windmapper");
        bool whoswho_deleted = cleanup_stage_file(whoswho_path, "whoswho");
        bool sentinel_deleted = cleanup_stage_file(sentinel_path, "sentinel");
        bool legacy_stage_dir_deleted = cleanup_stage_dir(stage);
        if (!mapper_deleted || !whoswho_deleted || !sentinel_deleted || !legacy_stage_dir_deleted) {
            set_last_error_fmt("Mapper stage cleanup failed mapper_deleted=%d whoswho_deleted=%d sentinel_deleted=%d stage_dir_deleted=%d",
                mapper_deleted ? 1 : 0,
                whoswho_deleted ? 1 : 0,
                sentinel_deleted ? 1 : 0,
                legacy_stage_dir_deleted ? 1 : 0);
            return false;
        }

        if (wait_result == WAIT_TIMEOUT) {
            set_last_error_fmt("Mapper stage timed out after 90000 ms log=\"%s\"",
                mapper_log_path.empty() ? "<unresolved>" : utf8_from_wide(mapper_log_path).c_str());
            return false;
        }
        if (wait_result == WAIT_FAILED) {
            set_last_error_fmt("WaitForSingleObject failed for mapper gle=%lu log=\"%s\"",
                static_cast<unsigned long>(wait_gle),
                mapper_log_path.empty() ? "<unresolved>" : utf8_from_wide(mapper_log_path).c_str());
            return false;
        }

        if (exit_code != 0) {
            set_last_error_fmt("Mapper stage exited with non-zero status exit_code=0x%08lX log=\"%s\"",
                static_cast<unsigned long>(exit_code),
                mapper_log_path.empty() ? "<unresolved>" : utf8_from_wide(mapper_log_path).c_str());
            return false;
        }

        g_loaded = true;

        loader_diag("initialize_and_load_success");
        return true;
#endif
    }
}
