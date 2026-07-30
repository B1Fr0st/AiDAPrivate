#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>

#include <MemPDB/MemPDB.hpp>

#include "kernel_symbols.hpp"
#include "standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

namespace kernel_symbols
{
    namespace
    {
        struct kernel_module_t
        {
            std::uint64_t base = 0;
            std::uint32_t size = 0;
            std::string   name;
            std::string   path;
        };

        struct sys_module_entry_t
        {
            HANDLE   Section;
            PVOID    MappedBase;
            PVOID    ImageBase;
            ULONG    ImageSize;
            ULONG    Flags;
            USHORT   LoadOrderIndex;
            USHORT   InitOrderIndex;
            USHORT   LoadCount;
            USHORT   OffsetToFileName;
            UCHAR    FullPathName[256];
        };

        struct sys_module_info_t
        {
            ULONG              NumberOfModules;
            sys_module_entry_t Modules[1];
        };

        using nt_query_system_information_fn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

        struct symbol_entry_t
        {
            std::uint64_t va = 0;
            std::string   name;
        };

        struct snapshot_t
        {
            MemPDB::PDB                 pdb;
            std::uint64_t               module_base = 0;
            std::uint64_t               module_size = 0;
            std::vector<symbol_entry_t> by_va;
        };

        std::mutex                                  g_state_mtx;
        state_t                                     g_state            = state_t::not_started;
        std::string                                 g_detail;
        std::string                                 g_last_error;
        std::string                                 g_pdb_name;
        std::string                                 g_cache_path;
        std::uint64_t                               g_ntos_base        = 0;
        std::uint64_t                               g_ntos_size        = 0;
        std::uint64_t                               g_function_count   = 0;
        std::uint64_t                               g_global_count     = 0;
        std::uint64_t                               g_struct_count     = 0;
        std::uint64_t                               g_load_ms          = 0;
        bool                                        g_from_cache       = false;
        bool                                        g_loader_active    = false;
        std::uint64_t                               g_generation       = 0;
        std::shared_ptr<const snapshot_t>           g_snapshot;

        std::mutex                                  g_modules_mtx;
        std::vector<kernel_module_t>                g_modules;
        std::chrono::steady_clock::time_point       g_modules_at{};

        constexpr std::uint64_t k_max_symbol_offset   = 0x100000ULL;
        constexpr std::uint64_t k_max_pdb_size        = 512ULL * 1024ULL * 1024ULL;
        constexpr std::uint64_t k_min_pdb_size        = 64ULL * 1024ULL;
        constexpr std::uint64_t k_canonical_kernel_lo = 0xFFFF000000000000ULL;

        const char k_msf_magic[32] = {
            'M','i','c','r','o','s','o','f','t',' ','C','/','C','+','+',' ',
            'M','S','F',' ','7','.','0','0','\r','\n','\x1a','D','S',
            '\0','\0','\0'
        };

        std::string hex_u64(std::uint64_t value)
        {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
            return std::string(buf);
        }

        std::string hex_u64_lower(std::uint64_t value)
        {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(value));
            return std::string(buf);
        }

        std::string trim_copy(const std::string& text)
        {
            std::size_t first = 0;
            while (first < text.size() && std::isspace(static_cast<unsigned char>(text[first])))
                ++first;
            std::size_t last = text.size();
            while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1])))
                --last;
            return text.substr(first, last - first);
        }

        std::string lower_copy(std::string text)
        {
            std::transform(text.begin(), text.end(), text.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return text;
        }

        bool parse_full_number(const std::string& text, std::uint64_t& out)
        {
            out = 0;
            if (text.empty())
                return false;
            try
            {
                std::size_t idx = 0;
                const unsigned long long value = std::stoull(text, &idx, 0);
                if (idx != text.size())
                    return false;
                out = static_cast<std::uint64_t>(value);
                return true;
            }
            catch (...)
            {
                return false;
            }
        }

        std::shared_ptr<const snapshot_t> current_snapshot()
        {
            std::lock_guard<std::mutex> lock(g_state_mtx);
            return g_snapshot;
        }

        bool generation_current(std::uint64_t gen)
        {
            std::lock_guard<std::mutex> lock(g_state_mtx);
            return gen == g_generation;
        }

        bool query_kernel_module_list(std::vector<kernel_module_t>& out, std::string& error)
        {
            out.clear();
            error.clear();
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll)
            {
                error = "GetModuleHandleW(ntdll) failed gle=" + std::to_string(GetLastError());
                diag::log_tagged_fmt("ksym", "module_query failed stage=resolve_ntdll gle=%lu",
                    static_cast<unsigned long>(GetLastError()));
                return false;
            }
            auto pNtQuerySystemInformation = reinterpret_cast<nt_query_system_information_fn>(
                GetProcAddress(ntdll, "NtQuerySystemInformation"));
            if (!pNtQuerySystemInformation)
            {
                error = "GetProcAddress(NtQuerySystemInformation) failed gle=" + std::to_string(GetLastError());
                diag::log_tagged_fmt("ksym", "module_query failed stage=resolve_ntqsi gle=%lu",
                    static_cast<unsigned long>(GetLastError()));
                return false;
            }
            constexpr ULONG SystemModuleInformation = 11;
            ULONG needed = 0;
            const LONG probe = pNtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
            if (needed == 0)
                needed = 256 * 1024;
            needed += 16384;
            std::vector<std::uint8_t> buffer(needed, 0);
            const LONG status = pNtQuerySystemInformation(
                SystemModuleInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
            diag::log_tagged_fmt("ksym",
                "module_query qsi probe_status=0x%08X final_status=0x%08X bytes_returned=%lu buffer_size=%zu",
                static_cast<unsigned int>(probe), static_cast<unsigned int>(status),
                static_cast<unsigned long>(needed), buffer.size());
            if (status < 0)
            {
                error = "NtQuerySystemInformation(SystemModuleInformation) failed ntstatus=0x" + hex_u64_lower(static_cast<std::uint32_t>(status));
                return false;
            }
            if (buffer.size() < sizeof(ULONG))
            {
                error = "SystemModuleInformation buffer too small";
                return false;
            }
            const auto* info = reinterpret_cast<const sys_module_info_t*>(buffer.data());
            const ULONG count = info->NumberOfModules;
            const std::size_t min_size = sizeof(ULONG) + static_cast<std::size_t>(count) * sizeof(sys_module_entry_t);
            if (count > 4096 || min_size > buffer.size())
            {
                error = "SystemModuleInformation bounds validation failed count=" + std::to_string(count);
                diag::log_tagged_fmt("ksym", "module_query failed stage=bounds count=%lu min_size=%zu buffer_size=%zu",
                    static_cast<unsigned long>(count), min_size, buffer.size());
                return false;
            }
            out.reserve(count);
            for (ULONG i = 0; i < count; ++i)
            {
                const sys_module_entry_t& entry = info->Modules[i];
                kernel_module_t mod;
                mod.base = reinterpret_cast<std::uint64_t>(entry.ImageBase);
                mod.size = entry.ImageSize;
                const char* raw = reinterpret_cast<const char*>(entry.FullPathName);
                std::size_t len = 0;
                while (len < sizeof(entry.FullPathName) && raw[len] != '\0')
                    ++len;
                mod.path.assign(raw, len);
                mod.name = mod.path;
                if (entry.OffsetToFileName < mod.path.size())
                    mod.name = mod.path.substr(entry.OffsetToFileName);
                else
                {
                    const std::size_t slash = mod.path.find_last_of("\\/");
                    if (slash != std::string::npos)
                        mod.name = mod.path.substr(slash + 1);
                }
                out.push_back(std::move(mod));
            }
            diag::log_tagged_fmt("ksym", "module_query ok count=%lu", static_cast<unsigned long>(count));
            return true;
        }

        bool find_module_containing(std::uint64_t va, kernel_module_t& out)
        {
            std::lock_guard<std::mutex> lock(g_modules_mtx);
            const auto now = std::chrono::steady_clock::now();
            if (g_modules.empty() || now - g_modules_at > std::chrono::seconds(30))
            {
                std::vector<kernel_module_t> fresh;
                std::string err;
                if (query_kernel_module_list(fresh, err))
                {
                    g_modules = std::move(fresh);
                    g_modules_at = now;
                    diag::log_tagged_fmt("ksym", "module_cache refreshed count=%zu", g_modules.size());
                }
                else
                {
                    diag::log_tagged_fmt("ksym", "module_cache refresh failed error=\"%s\" stale_count=%zu",
                        err.c_str(), g_modules.size());
                    if (g_modules.empty())
                        return false;
                }
            }
            for (const auto& mod : g_modules)
            {
                if (mod.base != 0 && va >= mod.base && va - mod.base < mod.size)
                {
                    out = mod;
                    return true;
                }
            }
            return false;
        }

        std::wstring local_appdata_dir()
        {
            PWSTR raw = nullptr;
            if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw) == S_OK && raw != nullptr)
            {
                std::wstring out(raw);
                CoTaskMemFree(raw);
                return out;
            }
            wchar_t buf[MAX_PATH] = {};
            if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH) > 0)
                return std::wstring(buf);
            return {};
        }

        std::string wide_to_utf8(const std::wstring& wide)
        {
            if (wide.empty())
                return {};
            const int needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                nullptr, 0, nullptr, nullptr);
            if (needed <= 0)
                return {};
            std::string out(static_cast<std::size_t>(needed), '\0');
            WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                out.data(), needed, nullptr, nullptr);
            return out;
        }

        bool pdb_name_valid(const std::string& name)
        {
            if (name.empty() || name.size() > 128)
                return false;
            if (name.find("..") != std::string::npos)
                return false;
            for (const char c : name)
            {
                const unsigned char u = static_cast<unsigned char>(c);
                if (u < 0x20 || u > 0x7E || c == '/' || c == '\\' || c == ':')
                    return false;
            }
            return true;
        }

        bool pdb_bytes_valid(const std::byte* data, std::size_t size)
        {
            if (size < k_min_pdb_size || size > k_max_pdb_size)
                return false;
            return std::memcmp(data, k_msf_magic, sizeof(k_msf_magic)) == 0;
        }

        struct debug_record_t
        {
            bool        found = false;
            std::string pdb_name;
            std::string guid_age;
            std::uint32_t age = 0;
            std::uint8_t guid[16] = {};
        };

        bool read_debug_record(std::uint64_t base, debug_record_t& out, std::string& error)
        {
            out = {};
            error.clear();
            std::vector<std::uint8_t> page;
            if (!driver_bridge::read_kernel_memory(base, 0x1000, page) || page.size() < 0x400)
            {
                error = "kernel read of ntoskrnl headers failed status=" + driver_bridge::status()
                    + " error=" + driver_bridge::last_error();
                diag::log_tagged_fmt("ksym",
                    "debug_header read failed va=0x%llX got=%zu status=\"%s\" error=\"%s\"",
                    static_cast<unsigned long long>(base), page.size(),
                    driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
                return false;
            }
            IMAGE_DOS_HEADER dos{};
            std::memcpy(&dos, page.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE)
            {
                error = "ntoskrnl DOS signature mismatch";
                diag::log_tagged_fmt("ksym", "debug_header bad_dos_magic=0x%04X", dos.e_magic);
                return false;
            }
            const std::uint64_t e_lfanew = static_cast<std::uint64_t>(static_cast<std::int64_t>(dos.e_lfanew));
            if (e_lfanew + sizeof(IMAGE_NT_HEADERS64) > page.size())
            {
                error = "ntoskrnl e_lfanew outside first page e_lfanew=" + hex_u64(e_lfanew);
                diag::log_tagged_fmt("ksym", "debug_header e_lfanew out of range e_lfanew=0x%llX page=%zu",
                    static_cast<unsigned long long>(e_lfanew), page.size());
                return false;
            }
            IMAGE_NT_HEADERS64 nth{};
            std::memcpy(&nth, page.data() + e_lfanew, sizeof(nth));
            if (nth.Signature != IMAGE_NT_SIGNATURE ||
                nth.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
                nth.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                error = "ntoskrnl NT headers validation failed";
                diag::log_tagged_fmt("ksym",
                    "debug_header bad_nt sig=0x%08X machine=0x%04X magic=0x%04X",
                    nth.Signature, nth.FileHeader.Machine, nth.OptionalHeader.Magic);
                return false;
            }
            const auto& debug_dir = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            if (debug_dir.VirtualAddress == 0 || debug_dir.Size < sizeof(IMAGE_DEBUG_DIRECTORY))
            {
                error = "ntoskrnl has no debug directory";
                diag::log_tagged_fmt("ksym", "debug_header no_debug_dir rva=0x%08X size=0x%08X",
                    debug_dir.VirtualAddress, debug_dir.Size);
                return false;
            }
            const std::uint64_t dir_count64 = debug_dir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            const std::size_t dir_count = static_cast<std::size_t>((std::min)(dir_count64, 64ULL));
            const std::size_t dir_bytes = dir_count * sizeof(IMAGE_DEBUG_DIRECTORY);
            std::vector<std::uint8_t> dir_buf;
            if (!driver_bridge::read_kernel_memory(base + debug_dir.VirtualAddress, dir_bytes, dir_buf) ||
                dir_buf.size() < dir_bytes)
            {
                error = "kernel read of debug directory failed status=" + driver_bridge::status()
                    + " error=" + driver_bridge::last_error();
                diag::log_tagged_fmt("ksym",
                    "debug_header dir_read failed va=0x%llX want=%zu got=%zu",
                    static_cast<unsigned long long>(base + debug_dir.VirtualAddress),
                    dir_bytes, dir_buf.size());
                return false;
            }
            diag::log_tagged_fmt("ksym",
                "debug_header dir rva=0x%08X size=0x%08X entries=%zu",
                debug_dir.VirtualAddress, debug_dir.Size, dir_count);
            for (std::size_t i = 0; i < dir_count; ++i)
            {
                IMAGE_DEBUG_DIRECTORY entry{};
                std::memcpy(&entry, dir_buf.data() + i * sizeof(entry), sizeof(entry));
                if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData < 25 ||
                    entry.AddressOfRawData == 0)
                    continue;
                const std::size_t cv_size = (std::min)(static_cast<std::size_t>(entry.SizeOfData),
                    static_cast<std::size_t>(0x1000));
                std::vector<std::uint8_t> cv;
                if (!driver_bridge::read_kernel_memory(base + entry.AddressOfRawData, cv_size, cv) ||
                    cv.size() < 25)
                {
                    diag::log_tagged_fmt("ksym",
                        "debug_header cv_read failed va=0x%llX want=%zu got=%zu",
                        static_cast<unsigned long long>(base + entry.AddressOfRawData),
                        cv_size, cv.size());
                    continue;
                }
                if (std::memcmp(cv.data(), "RSDS", 4) != 0)
                {
                    diag::log_tagged_fmt("ksym", "debug_header cv signature mismatch entry=%zu sig=%02X%02X%02X%02X",
                        i, cv[0], cv[1], cv[2], cv[3]);
                    continue;
                }
                std::memcpy(out.guid, cv.data() + 4, 16);
                std::uint32_t age = 0;
                std::memcpy(&age, cv.data() + 20, 4);
                out.age = age;
                const std::size_t name_cap = (std::min)(cv.size() - 24, static_cast<std::size_t>(128));
                std::size_t name_len = 0;
                while (name_len < name_cap && cv[24 + name_len] != '\0')
                    ++name_len;
                out.pdb_name.assign(reinterpret_cast<const char*>(cv.data() + 24), name_len);
                if (!pdb_name_valid(out.pdb_name))
                {
                    error = "RSDS pdb name failed validation name_len=" + std::to_string(name_len);
                    diag::log_tagged_fmt("ksym", "debug_header pdb_name invalid len=%zu", name_len);
                    return false;
                }
                std::uint32_t d1 = 0;
                std::uint16_t d2 = 0, d3 = 0;
                std::memcpy(&d1, out.guid, 4);
                std::memcpy(&d2, out.guid + 4, 2);
                std::memcpy(&d3, out.guid + 6, 2);
                char guid_buf[40] = {};
                int n = std::snprintf(guid_buf, sizeof(guid_buf), "%08X%04X%04X", d1, d2, d3);
                for (int b = 0; b < 8 && n > 0 && n < 32; ++b)
                    n += std::snprintf(guid_buf + n, sizeof(guid_buf) - static_cast<std::size_t>(n),
                        "%02X", out.guid[8 + b]);
                out.guid_age.assign(guid_buf, static_cast<std::size_t>(n));
                out.guid_age += std::to_string(age);
                out.found = true;
                diag::log_tagged_fmt("ksym",
                    "debug_header rsds entry=%zu pdb=\"%s\" guid_age=\"%s\" age=%u cv_size=%u",
                    i, out.pdb_name.c_str(), out.guid_age.c_str(), age, entry.SizeOfData);
                return true;
            }
            error = "no CodeView RSDS record found in ntoskrnl debug directory";
            diag::log_tagged_fmt("ksym", "debug_header no_rsds entries=%zu", dir_count);
            return false;
        }

        bool write_file_atomic(const std::filesystem::path& target,
                               const void* data, std::size_t size,
                               std::string& error)
        {
            error.clear();
            std::error_code ec;
            const std::filesystem::path parent = target.parent_path();
            if (!parent.empty())
                std::filesystem::create_directories(parent, ec);
            const std::filesystem::path tmp = target.wstring() +
                L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
                std::to_wstring(static_cast<unsigned long long>(GetTickCount64()));
            {
                std::ofstream stream(tmp, std::ios::binary | std::ios::trunc);
                if (!stream)
                {
                    error = "cache temp file open failed gle=" + std::to_string(GetLastError());
                    return false;
                }
                stream.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
                stream.flush();
                if (!stream)
                {
                    error = "cache temp file write failed gle=" + std::to_string(GetLastError());
                    stream.close();
                    DeleteFileW(tmp.c_str());
                    return false;
                }
            }
            if (!MoveFileExW(tmp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                error = "cache rename failed gle=" + std::to_string(GetLastError());
                DeleteFileW(tmp.c_str());
                return false;
            }
            return true;
        }

        void load_main(std::uint64_t gen) noexcept;
        void start_loader_locked()
        {
            g_loader_active = true;
            g_state = state_t::loading;
            g_detail = "load scheduled";
            g_last_error.clear();
            ++g_generation;
            const std::uint64_t gen = g_generation;
            diag::log_tagged_fmt("ksym", "loader armed gen=%llu tid=%lu",
                static_cast<unsigned long long>(gen),
                static_cast<unsigned long>(GetCurrentThreadId()));
            try
            {
                std::thread([gen]() { load_main(gen); }).detach();
            }
            catch (const std::exception& ex)
            {
                g_loader_active = false;
                g_state = state_t::failed;
                g_detail = "loader_spawn";
                g_last_error = std::string("loader thread creation failed: ") + ex.what();
                diag::log_tagged_fmt("ksym", "loader spawn failed gen=%llu error=\"%s\"",
                    static_cast<unsigned long long>(gen), ex.what());
            }
        }

        void finish_load(std::uint64_t gen, state_t result, const std::string& stage,
                         const std::string& error, const std::shared_ptr<const snapshot_t>& snap,
                         std::uint64_t load_ms, bool from_cache,
                         std::uint64_t fn_count, std::uint64_t global_count, std::uint64_t struct_count)
        {
            std::lock_guard<std::mutex> lock(g_state_mtx);
            g_loader_active = false;
            if (gen != g_generation)
            {
                diag::log_tagged_fmt("ksym",
                    "load stale gen=%llu current=%llu stage=%s; rearm=%d",
                    static_cast<unsigned long long>(gen),
                    static_cast<unsigned long long>(g_generation),
                    stage.c_str(), g_state == state_t::not_started ? 1 : 0);
                if (g_state == state_t::not_started)
                    start_loader_locked();
                return;
            }
            g_state = result;
            g_detail = stage;
            g_last_error = error;
            g_load_ms = load_ms;
            g_from_cache = from_cache;
            g_function_count = fn_count;
            g_global_count = global_count;
            g_struct_count = struct_count;
            if (result == state_t::ready)
                g_snapshot = snap;
        }

        void fail_load(std::uint64_t gen, const std::string& stage, const std::string& error,
                       std::uint64_t load_ms)
        {
            diag::log_tagged_fmt("ksym",
                "load failed stage=%s error=\"%s\" elapsed_ms=%llu gen=%llu",
                stage.c_str(), error.c_str(),
                static_cast<unsigned long long>(load_ms),
                static_cast<unsigned long long>(gen));
            finish_load(gen, state_t::failed, stage, error, nullptr, load_ms, false, 0, 0, 0);
        }

        void load_main(std::uint64_t gen) noexcept
        {
            const auto t_start = std::chrono::steady_clock::now();
            const auto elapsed_ms = [&t_start]() {
                return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t_start).count());
            };
            try
            {
                diag::log_tagged_fmt("ksym",
                    "load entry gen=%llu pid=%lu tid=%lu",
                    static_cast<unsigned long long>(gen),
                    static_cast<unsigned long>(GetCurrentProcessId()),
                    static_cast<unsigned long>(GetCurrentThreadId()));

                std::string session_reason;
                if (!driver_bridge::using_kernel_driver() ||
                    !driver_bridge::kernel_session_available(&session_reason))
                {
                    fail_load(gen, "bridge_check",
                        "kernel driver session unavailable: " + session_reason +
                            " status=" + driver_bridge::status() + " last_error=" + driver_bridge::last_error(),
                        elapsed_ms());
                    return;
                }
                diag::log_tagged_fmt("ksym", "phase=bridge_check ok status=\"%s\"",
                    driver_bridge::status().c_str());

                std::vector<kernel_module_t> modules;
                std::string error;
                if (!query_kernel_module_list(modules, error))
                {
                    fail_load(gen, "module_query", error, elapsed_ms());
                    return;
                }
                std::uint64_t ntos_base = 0;
                std::uint64_t ntos_size = 0;
                for (const auto& mod : modules)
                {
                    const std::string lower = lower_copy(mod.path.empty() ? mod.name : mod.path);
                    if (lower.find("ntoskrnl") != std::string::npos ||
                        lower.find("ntkrnlmp") != std::string::npos ||
                        lower.find("ntkrnlpa") != std::string::npos ||
                        lower.find("ntkrpamp") != std::string::npos)
                    {
                        ntos_base = mod.base;
                        ntos_size = mod.size;
                        break;
                    }
                }
                if (ntos_base == 0 || ntos_size == 0)
                {
                    fail_load(gen, "module_query", "ntoskrnl module not found in SystemModuleInformation",
                        elapsed_ms());
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(g_state_mtx);
                    g_ntos_base = ntos_base;
                    g_ntos_size = ntos_size;
                }
                {
                    std::lock_guard<std::mutex> lock(g_modules_mtx);
                    g_modules = modules;
                    g_modules_at = std::chrono::steady_clock::now();
                }
                diag::log_tagged_fmt("ksym",
                    "phase=module_query ok ntos_base=0x%llX ntos_size=0x%llX modules=%zu",
                    static_cast<unsigned long long>(ntos_base),
                    static_cast<unsigned long long>(ntos_size), modules.size());

                debug_record_t record;
                if (!read_debug_record(ntos_base, record, error))
                {
                    fail_load(gen, "debug_header", error, elapsed_ms());
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(g_state_mtx);
                    g_pdb_name = record.pdb_name;
                }

                const std::wstring appdata = local_appdata_dir();
                if (appdata.empty())
                {
                    fail_load(gen, "cache", "SHGetKnownFolderPath(FOLDERID_LocalAppData) failed", elapsed_ms());
                    return;
                }
                const std::filesystem::path pdb_dir = std::filesystem::path(appdata) / L"AiDA" /
                    L"Standalone" / L"symbols" / record.pdb_name / record.guid_age;
                const std::filesystem::path pdb_path = pdb_dir / record.pdb_name;
                {
                    std::lock_guard<std::mutex> lock(g_state_mtx);
                    g_cache_path = wide_to_utf8(pdb_path.wstring());
                }

                std::vector<std::byte> pdb_bytes;
                bool from_cache = false;
                {
                    std::error_code ec;
                    const auto file_size = std::filesystem::file_size(pdb_path, ec);
                    if (!ec && file_size >= k_min_pdb_size && file_size <= k_max_pdb_size)
                    {
                        std::ifstream stream(pdb_path, std::ios::binary);
                        if (stream)
                        {
                            pdb_bytes.resize(static_cast<std::size_t>(file_size));
                            stream.read(reinterpret_cast<char*>(pdb_bytes.data()),
                                static_cast<std::streamsize>(pdb_bytes.size()));
                            if (stream && pdb_bytes_valid(pdb_bytes.data(), pdb_bytes.size()))
                            {
                                from_cache = true;
                                diag::log_tagged_fmt("ksym",
                                    "phase=cache hit path=\"%s\" size=%llu",
                                    wide_to_utf8(pdb_path.wstring()).c_str(),
                                    static_cast<unsigned long long>(file_size));
                            }
                            else
                            {
                                diag::log_tagged_fmt("ksym",
                                    "phase=cache invalid path=\"%s\" read_ok=%d; redownloading",
                                    wide_to_utf8(pdb_path.wstring()).c_str(), stream ? 1 : 0);
                                pdb_bytes.clear();
                            }
                        }
                    }
                    else if (!ec)
                    {
                        diag::log_tagged_fmt("ksym",
                            "phase=cache size_out_of_range path=\"%s\" size=%llu",
                            wide_to_utf8(pdb_path.wstring()).c_str(),
                            static_cast<unsigned long long>(file_size));
                    }
                }

                if (!from_cache)
                {
                    const auto t_dl = std::chrono::steady_clock::now();
                    try
                    {
                        MemPDB::SymbolServer server;
                        pdb_bytes = server.Download(record.pdb_name, record.guid_age);
                    }
                    catch (const MemPDB::Error& ex)
                    {
                        fail_load(gen, "download",
                            std::string("symbol server download failed: ") + ex.what(), elapsed_ms());
                        return;
                    }
                    catch (const std::exception& ex)
                    {
                        fail_load(gen, "download",
                            std::string("symbol server download failed: ") + ex.what(), elapsed_ms());
                        return;
                    }
                    const auto dl_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t_dl).count();
                    diag::log_tagged_fmt("ksym",
                        "phase=download done pdb=\"%s\" guid_age=\"%s\" size=%zu dl_ms=%lld",
                        record.pdb_name.c_str(), record.guid_age.c_str(), pdb_bytes.size(),
                        static_cast<long long>(dl_ms));
                    if (!pdb_bytes_valid(pdb_bytes.data(), pdb_bytes.size()))
                    {
                        fail_load(gen, "download",
                            "downloaded PDB failed MSF validation size=" + std::to_string(pdb_bytes.size()),
                            elapsed_ms());
                        return;
                    }
                    if (!write_file_atomic(pdb_path, pdb_bytes.data(), pdb_bytes.size(), error))
                    {
                        diag::log_tagged_fmt("ksym",
                            "phase=cache write failed path=\"%s\" error=\"%s\"; continuing with in-memory copy",
                            wide_to_utf8(pdb_path.wstring()).c_str(), error.c_str());
                    }
                    else
                    {
                        diag::log_tagged_fmt("ksym",
                            "phase=cache stored path=\"%s\" size=%zu",
                            wide_to_utf8(pdb_path.wstring()).c_str(), pdb_bytes.size());
                    }
                }

                if (!generation_current(gen))
                {
                    finish_load(gen, state_t::failed, "stale", "load superseded before parse",
                        elapsed_ms(), nullptr, 0, false, 0, 0, 0);
                    return;
                }

                const auto t_parse = std::chrono::steady_clock::now();
                MemPDB::ParseOptions options;
                options.ResolveFunctions = true;
                options.ResolveSizes = false;
                options.ResolveArguments = false;
                options.ResolveGlobals = true;
                options.ResolveStructs = true;
                options.InternStrings = true;
                options.Parallel = true;

                std::optional<MemPDB::PDB> parsed_opt;
                try
                {
                    parsed_opt.emplace(MemPDB::PDB::ParseFromMemory(std::move(pdb_bytes), options));
                }
                catch (const MemPDB::Error& ex)
                {
                    fail_load(gen, "parse", std::string("PDB parse failed: ") + ex.what(), elapsed_ms());
                    return;
                }
                catch (const std::exception& ex)
                {
                    fail_load(gen, "parse", std::string("PDB parse failed: ") + ex.what(), elapsed_ms());
                    return;
                }
                MemPDB::PDB& parsed = *parsed_opt;
                const auto parse_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t_parse).count();
                const auto parse_info = parsed.GetParseInfo();
                diag::log_tagged_fmt("ksym",
                    "phase=parse done ms=%lld functions=%zu globals=%zu structs=%zu modules=%zu symbols=%zu",
                    static_cast<long long>(parse_ms),
                    parsed.FunctionCount(), parsed.GlobalCount(), parsed.StructCount(),
                    parse_info.moduleCount, parse_info.symbolCount);

                if (!generation_current(gen))
                {
                    finish_load(gen, state_t::failed, "stale", "load superseded after parse",
                        elapsed_ms(), nullptr, 0, false, 0, 0, 0);
                    return;
                }

                const auto t_index = std::chrono::steady_clock::now();
                auto snap = std::make_shared<snapshot_t>();
                snap->module_base = ntos_base;
                snap->module_size = ntos_size;
                const std::size_t fn_count = parsed.FunctionCount();
                const std::size_t global_count = parsed.GlobalCount();
                const std::size_t struct_count = parsed.StructCount();
                snap->by_va.reserve(fn_count + global_count);
                for (std::size_t i = 0; i < fn_count; ++i)
                {
                    const auto fn = parsed.FunctionAt(i);
                    if (fn.RVA == 0 || fn.Name.empty())
                        continue;
                    snap->by_va.push_back({ ntos_base + fn.RVA, std::string(fn.Name) });
                }
                for (std::size_t i = 0; i < global_count; ++i)
                {
                    const auto gl = parsed.GlobalAt(i);
                    if (gl.RVA == 0 || gl.Name.empty())
                        continue;
                    snap->by_va.push_back({ ntos_base + gl.RVA, std::string(gl.Name) });
                }
                std::sort(snap->by_va.begin(), snap->by_va.end(),
                    [](const symbol_entry_t& a, const symbol_entry_t& b) { return a.va < b.va; });
                snap->pdb = std::move(parsed);
                const auto index_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t_index).count();
                diag::log_tagged_fmt("ksym",
                    "phase=index done ms=%lld indexed=%zu dropped=%zu",
                    static_cast<long long>(index_ms), snap->by_va.size(),
                    (fn_count + global_count) - snap->by_va.size());

                finish_load(gen, state_t::ready, "ready", {}, snap, elapsed_ms(), from_cache,
                    static_cast<std::uint64_t>(fn_count),
                    static_cast<std::uint64_t>(global_count),
                    static_cast<std::uint64_t>(struct_count));
                diag::log_tagged_fmt("ksym",
                    "load complete gen=%llu from_cache=%d total_ms=%llu functions=%zu globals=%zu structs=%zu indexed=%zu",
                    static_cast<unsigned long long>(gen), from_cache ? 1 : 0,
                    static_cast<unsigned long long>(elapsed_ms()),
                    fn_count, global_count, struct_count, snap->by_va.size());
            }
            catch (const std::exception& ex)
            {
                fail_load(gen, "unexpected_exception", ex.what(), elapsed_ms());
            }
            catch (...)
            {
                fail_load(gen, "unexpected_exception", "unknown exception", elapsed_ms());
            }
        }
    }

    void ensure_started()
    {
        std::lock_guard<std::mutex> lock(g_state_mtx);
        if (g_loader_active)
            return;
        if (g_state == state_t::ready)
            return;
        start_loader_locked();
    }

    void request_reload()
    {
        std::lock_guard<std::mutex> lock(g_state_mtx);
        ++g_generation;
        g_snapshot.reset();
        g_state = state_t::not_started;
        g_detail.clear();
        g_last_error.clear();
        g_function_count = 0;
        g_global_count = 0;
        g_struct_count = 0;
        g_load_ms = 0;
        g_from_cache = false;
        diag::log_tagged_fmt("ksym", "reload requested gen=%llu loader_active=%d",
            static_cast<unsigned long long>(g_generation), g_loader_active ? 1 : 0);
        if (!g_loader_active)
            start_loader_locked();
    }

    bool ready()
    {
        std::lock_guard<std::mutex> lock(g_state_mtx);
        return g_state == state_t::ready && g_snapshot != nullptr;
    }

    status_t status()
    {
        std::lock_guard<std::mutex> lock(g_state_mtx);
        status_t out;
        out.state = g_state;
        out.detail = g_detail;
        out.last_error = g_last_error;
        out.pdb_name = g_pdb_name;
        out.cache_path = g_cache_path;
        out.ntoskrnl_base = g_ntos_base;
        out.ntoskrnl_size = g_ntos_size;
        out.function_count = g_function_count;
        out.global_count = g_global_count;
        out.struct_count = g_struct_count;
        out.load_duration_ms = g_load_ms;
        out.from_cache = g_from_cache;
        return out;
    }

    const char* state_name(state_t state) noexcept
    {
        switch (state)
        {
        case state_t::not_started: return "not_started";
        case state_t::loading:     return "loading";
        case state_t::ready:       return "ready";
        case state_t::failed:      return "failed";
        }
        return "unknown";
    }

    std::optional<lookup_result_t> lookup(std::uint64_t va)
    {
        const auto snap = current_snapshot();
        if (!snap)
            return std::nullopt;
        if (va >= snap->module_base && va - snap->module_base < snap->module_size)
        {
            const auto& entries = snap->by_va;
            const auto it = std::upper_bound(entries.begin(), entries.end(), va,
                [](std::uint64_t value, const symbol_entry_t& entry) { return value < entry.va; });
            if (it == entries.begin())
                return std::nullopt;
            const auto& best = *(it - 1);
            const std::uint64_t offset = va - best.va;
            if (offset > k_max_symbol_offset)
                return std::nullopt;
            lookup_result_t out;
            out.resolved = true;
            out.module = "nt";
            out.symbol = best.name;
            out.symbol_base_va = best.va;
            out.offset = offset;
            out.exact = offset == 0;
            return out;
        }
        kernel_module_t mod;
        if (!find_module_containing(va, mod))
            return std::nullopt;
        lookup_result_t out;
        out.resolved = false;
        out.module = mod.name;
        out.symbol_base_va = mod.base;
        out.offset = va - mod.base;
        out.exact = out.offset == 0;
        return out;
    }

    std::string format(std::uint64_t va)
    {
        const auto hit = lookup(va);
        if (!hit)
            return hex_u64(va);
        std::string out;
        if (hit->resolved)
            out = hit->module + "!" + hit->symbol;
        else
            out = hit->module;
        if (hit->offset != 0)
            out += "+0x" + hex_u64_lower(hit->offset);
        return out;
    }

    std::optional<std::uint64_t> resolve(const std::string& expression)
    {
        const std::string expr = trim_copy(expression);
        if (expr.empty())
            return std::nullopt;
        std::uint64_t numeric = 0;
        if (parse_full_number(expr, numeric))
            return numeric;

        std::uint64_t add_off = 0;
        std::uint64_t sub_off = 0;
        std::string head = expr;
        for (;;)
        {
            const std::size_t pos = head.find_last_of("+-");
            if (pos == std::string::npos || pos == 0)
                break;
            const std::string off_text = head.substr(pos + 1);
            std::uint64_t off_value = 0;
            if (off_text.empty() || !parse_full_number(off_text, off_value))
                break;
            if (head[pos] == '+')
                add_off += off_value;
            else
                sub_off += off_value;
            head = head.substr(0, pos);
        }
        if (head.empty())
            return std::nullopt;
        if (parse_full_number(head, numeric))
        {
            if (add_off == 0 && sub_off == 0)
                return std::nullopt;
            return numeric + add_off - sub_off;
        }

        std::string module;
        std::string name = head;
        const std::size_t bang = head.find('!');
        if (bang != std::string::npos)
        {
            module = head.substr(0, bang);
            name = head.substr(bang + 1);
        }
        if (name.empty())
            return std::nullopt;
        if (!module.empty())
        {
            const std::string mod_lower = lower_copy(module);
            static const char* const aliases[] = {
                "nt", "ntoskrnl", "ntoskrnl.exe", "ntkrnlmp", "ntkrnlmp.exe",
                "ntkrnlpa", "ntkrnlpa.exe", "ntkrpamp", "ntkrpamp.exe", "kernel"
            };
            bool alias = false;
            for (const char* candidate : aliases)
            {
                if (mod_lower == candidate)
                {
                    alias = true;
                    break;
                }
            }
            if (!alias)
                return std::nullopt;
        }

        const auto snap = current_snapshot();
        if (!snap)
            return std::nullopt;
        std::uint64_t rva = 0;
        if (const auto fn = snap->pdb.TryResolveFunction(name))
            rva = fn->RVA;
        else if (const auto gl = snap->pdb.TryResolveGlobal(name))
            rva = gl->RVA;
        else
            return std::nullopt;
        return snap->module_base + rva + add_off - sub_off;
    }

    std::optional<struct_desc_t> describe_struct(const std::string& name)
    {
        if (name.empty())
            return std::nullopt;
        const auto snap = current_snapshot();
        if (!snap)
            return std::nullopt;
        std::optional<MemPDB::Struct> layout = snap->pdb.TryResolveStruct(name);
        if (!layout && name.front() != '_')
            layout = snap->pdb.TryResolveStruct("_" + name);
        if (!layout)
            return std::nullopt;
        struct_desc_t out;
        out.name = std::string(layout->Name);
        out.size = layout->Size;
        out.fields.reserve(layout->Fields.size());
        for (const auto& field : layout->Fields)
        {
            struct_field_desc_t desc;
            desc.name = std::string(field.Name);
            desc.type = std::string(field.TypeName);
            desc.offset = field.Offset;
            desc.size = field.Size;
            out.fields.push_back(std::move(desc));
        }
        return out;
    }

    std::vector<decoded_field_t> decode_struct_buffer(const struct_desc_t& desc,
                                                      const std::vector<std::uint8_t>& bytes,
                                                      std::uint64_t base_va)
    {
        (void)base_va;
        std::vector<decoded_field_t> out;
        out.reserve(desc.fields.size());
        for (const auto& field : desc.fields)
        {
            decoded_field_t decoded;
            decoded.name = field.name;
            decoded.type = field.type;
            decoded.offset = field.offset;
            decoded.size = field.size;
            const std::uint64_t avail64 = bytes.size() > field.offset
                ? static_cast<std::uint64_t>(bytes.size() - field.offset)
                : 0;
            const std::size_t avail = static_cast<std::size_t>(
                (std::min)(avail64, static_cast<std::uint64_t>(field.size)));
            const std::uint8_t* data = field.offset < bytes.size()
                ? bytes.data() + field.offset
                : nullptr;
            if ((field.size == 1 || field.size == 2 || field.size == 4 || field.size == 8) &&
                avail == field.size && data != nullptr)
            {
                std::uint64_t value = 0;
                for (std::size_t i = 0; i < field.size; ++i)
                    value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
                decoded.value = hex_u64(value);
                if (field.size == 8 && value >= k_canonical_kernel_lo)
                {
                    if (lookup(value))
                        decoded.annotation = format(value);
                }
            }
            else if (field.size != 0)
            {
                static constexpr char digits[] = "0123456789ABCDEF";
                const std::size_t cap = (std::min)(avail, static_cast<std::size_t>(32));
                std::string snippet;
                snippet.reserve(cap * 2);
                for (std::size_t i = 0; i < cap; ++i)
                {
                    snippet.push_back(digits[data[i] >> 4]);
                    snippet.push_back(digits[data[i] & 0x0F]);
                }
                decoded.value = snippet;
                decoded.truncated = avail < field.size;
            }
            out.push_back(std::move(decoded));
        }
        return out;
    }
}
