#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <string>

namespace aida
{
namespace vuln
{
namespace embedded_libz3
{

#ifndef IDR_LIBZ3_DLL_AIDA
#define IDR_LIBZ3_DLL_AIDA  601
#endif

inline std::atomic<HMODULE>     g_z3_module{nullptr};
inline std::atomic<bool>        g_z3_attempted{false};
inline std::wstring             g_z3_temp_path;
inline HMODULE                  g_z3_self_handle = nullptr;

inline HMODULE locate_self_module()
{
    if (g_z3_self_handle != nullptr)
        return g_z3_self_handle;
    HMODULE h = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                           | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&locate_self_module),
                           &h))
    {
        g_z3_self_handle = h;
    }
    return h;
}

inline bool load_resource_bytes(const void*& out_data, size_t& out_size)
{
    HMODULE self = locate_self_module();
    if (!self)
        return false;
    HRSRC hr = FindResourceW(self, MAKEINTRESOURCEW(IDR_LIBZ3_DLL_AIDA), MAKEINTRESOURCEW(10));
    if (!hr) return false;
    HGLOBAL hg = LoadResource(self, hr);
    if (!hg) return false;
    out_data = LockResource(hg);
    out_size = SizeofResource(self, hr);
    return out_data != nullptr && out_size > 0;
}

inline std::wstring make_temp_path()
{
    wchar_t tmp_dir[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tmp_dir))
        return {};
    wchar_t tmp_file[MAX_PATH] = {};
    if (!GetTempFileNameW(tmp_dir, L"az3", 0, tmp_file))
        return {};
    DeleteFileW(tmp_file);
    std::wstring path(tmp_file);
    path += L".dll";
    return path;
}

inline bool write_to_file(const void* data, size_t size, const std::wstring& path)
{
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
                            nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    BOOL ok = WriteFile(hf, data, static_cast<DWORD>(size), &written, nullptr);
    FlushFileBuffers(hf);
    CloseHandle(hf);
    return ok && written == static_cast<DWORD>(size);
}

inline bool ensure_loaded()
{
    if (g_z3_module.load(std::memory_order_acquire) != nullptr)
        return true;
    bool expected = false;
    if (!g_z3_attempted.compare_exchange_strong(expected, true,
                                                std::memory_order_acq_rel))
    {
        return g_z3_module.load(std::memory_order_acquire) != nullptr;
    }

    HMODULE existing = GetModuleHandleW(L"libz3.dll");
    if (existing != nullptr)
    {
        g_z3_module.store(existing, std::memory_order_release);
        return true;
    }

    const void* data = nullptr;
    size_t size = 0;
    if (!load_resource_bytes(data, size))
    {
        OutputDebugStringA("aida_plugin_embedded_libz3: resource not found\n");
        return false;
    }

    g_z3_temp_path = make_temp_path();
    if (g_z3_temp_path.empty())
        return false;

    if (!write_to_file(data, size, g_z3_temp_path))
    {
        OutputDebugStringA("aida_plugin_embedded_libz3: failed to write temp\n");
        return false;
    }

    HMODULE m = LoadLibraryW(g_z3_temp_path.c_str());
    if (!m)
    {
        DeleteFileW(g_z3_temp_path.c_str());
        OutputDebugStringA("aida_plugin_embedded_libz3: LoadLibrary failed\n");
        return false;
    }

    g_z3_module.store(m, std::memory_order_release);
    MoveFileExW(g_z3_temp_path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    return true;
}

inline void cleanup()
{
    HMODULE m = g_z3_module.exchange(nullptr, std::memory_order_acq_rel);
    if (m != nullptr)
    {
        FreeLibrary(m);
    }
    if (!g_z3_temp_path.empty())
    {
        DeleteFileW(g_z3_temp_path.c_str());
        g_z3_temp_path.clear();
    }
}

}
}
}
