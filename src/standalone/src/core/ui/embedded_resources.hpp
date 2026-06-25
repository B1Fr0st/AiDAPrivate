#pragma once


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <utility>
#include <vector>


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
