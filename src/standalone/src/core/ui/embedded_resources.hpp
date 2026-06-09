#pragma once


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>


#define IDR_LIBZ3_DLL       101
#define IDR_Z3_MSVCP140_DLL 102
#define IDR_Z3_MSVCP140_1_DLL 103
#define IDR_Z3_MSVCP140_2_DLL 104
#define IDR_Z3_MSVCP140_ATOMIC_WAIT_DLL 105
#define IDR_Z3_MSVCP140_CODECVT_IDS_DLL 106
#define IDR_Z3_VCOMP140_DLL 107
#define IDR_Z3_VCRUNTIME140_DLL 108
#define IDR_Z3_VCRUNTIME140_1_DLL 109
#define IDR_Z3_VCRUNTIME140_THREADS_DLL 110
#define IDR_GHIDRA_SLA      201
#define IDR_GHIDRA_PSPEC    202
#define IDR_GHIDRA_CSPEC    203
#define IDR_GHIDRA_LDEFS    204

namespace embedded_resources {

namespace detail {


inline bool write_resource_to_file(const void* data, size_t size,
                                   const std::wstring& path)
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


inline bool load_resource(int id, const void*& out_data, size_t& out_size)
{
    HRSRC hr = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!hr) return false;
    HGLOBAL hg = LoadResource(nullptr, hr);
    if (!hg) return false;
    out_data = LockResource(hg);
    out_size = SizeofResource(nullptr, hr);
    return out_data != nullptr && out_size > 0;
}


inline std::wstring make_temp_path(const wchar_t* prefix, const wchar_t* ext)
{
    wchar_t tmp_dir[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tmp_dir))
        return {};
    wchar_t tmp_file[MAX_PATH] = {};
    if (!GetTempFileNameW(tmp_dir, prefix, 0, tmp_file))
        return {};


    DeleteFileW(tmp_file);
    std::wstring path(tmp_file);
    path += ext;
    return path;
}

inline std::wstring make_temp_dir()
{
    wchar_t tmp_dir[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tmp_dir))
        return {};
    wchar_t tmp_file[MAX_PATH] = {};
    if (!GetTempFileNameW(tmp_dir, L"gsp", 0, tmp_file))
        return {};

    DeleteFileW(tmp_file);
    std::wstring dir(tmp_file);
    dir += L"_d";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

}


inline std::wstring g_z3_temp_path;
inline std::wstring g_z3_temp_dir;
inline std::vector<std::wstring> g_z3_written_paths;
inline HMODULE      g_z3_module = nullptr;

namespace detail {
    inline std::mutex& z3_mutex() { static std::mutex m; return m; }
}


inline bool extract_and_load_z3()
{
    std::lock_guard<std::mutex> lk(detail::z3_mutex());

    struct z3_file {
        int resource_id;
        const wchar_t* filename;
    };

    static const z3_file files[] = {
        { IDR_Z3_MSVCP140_DLL, L"msvcp140.dll" },
        { IDR_Z3_MSVCP140_1_DLL, L"msvcp140_1.dll" },
        { IDR_Z3_MSVCP140_2_DLL, L"msvcp140_2.dll" },
        { IDR_Z3_MSVCP140_ATOMIC_WAIT_DLL, L"msvcp140_atomic_wait.dll" },
        { IDR_Z3_MSVCP140_CODECVT_IDS_DLL, L"msvcp140_codecvt_ids.dll" },
        { IDR_Z3_VCOMP140_DLL, L"vcomp140.dll" },
        { IDR_Z3_VCRUNTIME140_DLL, L"vcruntime140.dll" },
        { IDR_Z3_VCRUNTIME140_1_DLL, L"vcruntime140_1.dll" },
        { IDR_Z3_VCRUNTIME140_THREADS_DLL, L"vcruntime140_threads.dll" },
        { IDR_LIBZ3_DLL, L"libz3.dll" },
    };

    if (g_z3_module)
        return true;

    if (HMODULE existing = GetModuleHandleW(L"libz3.dll")) {
        g_z3_module = existing;
        wchar_t preload_dir[32768]{};
        constexpr DWORD preload_dir_count = static_cast<DWORD>(sizeof(preload_dir) / sizeof(preload_dir[0]));
        DWORD n = GetEnvironmentVariableW(L"AIDA_Z3_PRELOAD_DIR", preload_dir, preload_dir_count);
        if (n > 0 && n < preload_dir_count) {
            g_z3_temp_dir = preload_dir;
            g_z3_temp_path = g_z3_temp_dir + L"\\libz3.dll";
            g_z3_written_paths.clear();
            g_z3_written_paths.reserve(sizeof(files) / sizeof(files[0]));
            for (const auto& f : files)
                g_z3_written_paths.push_back(g_z3_temp_dir + L"\\" + f.filename);
        }
        return true;
    }

    std::wstring tmp_dir = detail::make_temp_dir();
    if (tmp_dir.empty())
        return false;

    std::vector<std::wstring> written;
    written.reserve(sizeof(files) / sizeof(files[0]));

    auto cleanup_on_failure = [&]() {
        for (auto it = written.rbegin(); it != written.rend(); ++it)
            DeleteFileW(it->c_str());
        RemoveDirectoryW(tmp_dir.c_str());
    };

    for (const auto& f : files) {
        const void* data = nullptr;
        size_t size = 0;
        if (!detail::load_resource(f.resource_id, data, size)) {
            OutputDebugStringA("embedded_resources: z3 resource not found\n");
            cleanup_on_failure();
            return false;
        }

        std::wstring path = tmp_dir + L"\\" + f.filename;
        if (!detail::write_resource_to_file(data, size, path)) {
            OutputDebugStringA("embedded_resources: failed to write z3 resource to temp\n");
            cleanup_on_failure();
            return false;
        }
        written.push_back(std::move(path));
    }

    std::wstring tmp_path = tmp_dir + L"\\libz3.dll";

    HMODULE mod = LoadLibraryExW(tmp_path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!mod) {
        cleanup_on_failure();
        OutputDebugStringA("embedded_resources: LoadLibrary failed for temp libz3.dll\n");
        return false;
    }

    g_z3_temp_path = std::move(tmp_path);
    g_z3_temp_dir  = std::move(tmp_dir);
    g_z3_written_paths = std::move(written);
    g_z3_module    = mod;

    for (const auto& path : g_z3_written_paths)
        MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    MoveFileExW(g_z3_temp_dir.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);

    return true;
}


inline void cleanup_z3()
{
    std::lock_guard<std::mutex> lk(detail::z3_mutex());
    if (g_z3_module) {
        FreeLibrary(g_z3_module);
        g_z3_module = nullptr;
    }
    for (auto it = g_z3_written_paths.rbegin(); it != g_z3_written_paths.rend(); ++it)
        DeleteFileW(it->c_str());
    g_z3_written_paths.clear();
    if (!g_z3_temp_dir.empty())
        RemoveDirectoryW(g_z3_temp_dir.c_str());
    g_z3_temp_path.clear();
    g_z3_temp_dir.clear();
}


inline std::string extract_ghidra_specs()
{
    std::wstring dir = detail::make_temp_dir();
    if (dir.empty())
        return {};

    struct spec_file {
        int resource_id;
        const wchar_t* filename;
    };

    static const spec_file specs[] = {
        { IDR_GHIDRA_SLA,   L"x86-64.sla" },
        { IDR_GHIDRA_PSPEC, L"x86-64.pspec" },
        { IDR_GHIDRA_CSPEC, L"x86-64-win.cspec" },
        { IDR_GHIDRA_LDEFS, L"x86.ldefs" },
    };

    std::vector<std::wstring> written;
    written.reserve(sizeof(specs) / sizeof(specs[0]));

    auto cleanup_on_failure = [&]() {
        for (const auto& w : written)
            DeleteFileW(w.c_str());
        RemoveDirectoryW(dir.c_str());
    };

    for (auto& s : specs) {
        const void* data = nullptr;
        size_t size = 0;
        if (!detail::load_resource(s.resource_id, data, size)) {
            OutputDebugStringA("embedded_resources: ghidra spec resource not found\n");
            cleanup_on_failure();
            return {};
        }

        std::wstring file_path = dir + L"\\" + s.filename;
        if (!detail::write_resource_to_file(data, size, file_path)) {
            OutputDebugStringA("embedded_resources: failed to write ghidra spec file\n");
            cleanup_on_failure();
            return {};
        }
        written.push_back(std::move(file_path));
    }


    char narrow[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, dir.c_str(), -1, narrow, MAX_PATH, nullptr, nullptr);
    return std::string(narrow);
}


inline void delete_specs_dir(const std::string& dir)
{
    if (dir.empty()) return;

    wchar_t wide[MAX_PATH] = {};
    MultiByteToWideChar(CP_ACP, 0, dir.c_str(), -1, wide, MAX_PATH);

    static const wchar_t* filenames[] = {
        L"x86-64.sla", L"x86-64.pspec", L"x86-64-win.cspec", L"x86.ldefs"
    };
    for (auto* fn : filenames) {
        std::wstring path = std::wstring(wide) + L"\\" + fn;
        DeleteFileW(path.c_str());
    }
    RemoveDirectoryW(wide);
}

}
