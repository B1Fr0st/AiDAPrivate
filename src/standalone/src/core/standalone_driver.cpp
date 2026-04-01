#define WIN32_LEAN_AND_MEAN
#include "standalone_driver.hpp"
#include "driver_loader.hpp"
#include "comm.h"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdarg>
#include <cctype>
#include <cstdio>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace
{
    driver_bridge::log_fn_t     g_log_fn;
    driver_bridge::confirm_fn_t g_confirm_fn;
    std::mutex                  g_callback_mtx;

    std::mutex      g_state_mtx;
    HANDLE          g_process = nullptr;
    uint32_t        g_pid = 0;
    std::string     g_process_name;
    std::string     g_last_error;
    bool            g_initialized = false;
    bool            g_kernel_mode = false;

    struct handle_closer
    {
        void operator()(HANDLE h) const
        {
            if (h && h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    };

    using unique_handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_closer>;

    unique_handle make_handle(HANDLE h)
    {
        return unique_handle((h && h != INVALID_HANDLE_VALUE) ? h : nullptr);
    }

    void logf(const char* fmt, ...)
    {
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        OutputDebugStringA(buf);
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        if (g_log_fn)
            g_log_fn(buf);
    }

    void set_last_error_locked(const std::string& text)
    {
        g_last_error = text;
        if (!text.empty())
            logf("AiDA Standalone: %s\n", text.c_str());
    }

    std::string utf8_from_wide(const wchar_t* text)
    {
        if (!text || !*text)
            return {};
        char narrow[MAX_PATH * 2] = {};
        WideCharToMultiByte(CP_UTF8, 0, text, -1, narrow, sizeof(narrow), nullptr, nullptr);
        return narrow;
    }

    bool refresh_process_name_locked()
    {
        g_process_name.clear();
        if (!g_process)
            return false;

        wchar_t path[MAX_PATH] = {};
        DWORD len = static_cast<DWORD>(std::size(path));
        if (QueryFullProcessImageNameW(g_process, 0, path, &len) && len > 0) {
            std::wstring full(path, path + len);
            auto slash = full.find_last_of(L"\\/");
            g_process_name = utf8_from_wide(slash == std::wstring::npos ? full.c_str() : full.c_str() + slash + 1);
            return true;
        }
        return false;
    }

    std::string process_name_from_pid(uint32_t pid)
    {
        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot)
            return {};

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(snapshot.get(), &pe))
            return {};

        do {
            if (pe.th32ProcessID == pid)
                return utf8_from_wide(pe.szExeFile);
        } while (Process32NextW(snapshot.get(), &pe));

        return {};
    }

    void close_process_handle_locked()
    {
        if (g_process) {
            CloseHandle(g_process);
            g_process = nullptr;
        }
    }

    std::string to_lower_copy(std::string text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return text;
    }
}

namespace driver_bridge
{
    void set_log_callback(log_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_log_fn = std::move(fn);
    }

    void set_confirm_callback(confirm_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_confirm_fn = std::move(fn);
    }

    bool initialize()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_initialized)
            return true;

        g_kernel_mode = false;
        set_last_error_locked({});

        if (driver_loader::initialize_and_load() && device && device->connect()) {
            g_kernel_mode = true;
            g_initialized = true;
            logf("AiDA Standalone: Live inspection bridge initialized with kernel driver backend.\n");
            return true;
        }

        g_initialized = true;
        logf("AiDA Standalone: Kernel driver unavailable, using user-mode fallback bridge.\n");
        return true;
    }

    bool load_kernel_driver()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_kernel_mode && device && device->is_connected())
            return true;

        if (!driver_loader::initialize_and_load()) {
            set_last_error_locked("Failed to load the kernel driver.");
            return false;
        }
        if (!device || !device->connect()) {
            set_last_error_locked("Kernel driver loaded, but user-mode bridge failed to connect to device.");
            return false;
        }

        g_kernel_mode = true;
        g_initialized = true;
        set_last_error_locked({});
        logf("AiDA Standalone: Kernel driver backend is active.\n");
        return true;
    }

    bool is_loaded()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_initialized;
    }

    bool using_kernel_driver()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_kernel_mode && device && device->is_connected();
    }

    bool attach(uint32_t pid)
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_kernel_mode && device && device->is_connected()) {
            device->set_process_id(pid);
            device->solve_dtb();
            if (device->get_dtb() == 0) {
                set_last_error_locked("Kernel bridge failed to resolve target DTB.");
                return false;
            }
            const auto image_base = device->find_image();
            if (image_base != 0)
                device->set_base_address(image_base);
        }

        unique_handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        close_process_handle_locked();
        g_process = process.release();
        g_pid = pid;
        if (!refresh_process_name_locked())
            g_process_name = process_name_from_pid(pid);

        if (!g_kernel_mode && !g_process) {
            set_last_error_locked("Failed to open the target process for read-only inspection.");
            return false;
        }

        set_last_error_locked({});
        logf("AiDA Standalone: Attached to PID %u (%s).\n",
             g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str());
        return true;
    }

    bool attach_by_name(const std::string& process_name)
    {
        uint32_t kernel_pid = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            if (g_kernel_mode && device && device->is_connected()) {
                kernel_pid = device->find_process(process_name.c_str());
            }
        }
        if (kernel_pid != 0)
            return attach(kernel_pid);

        auto lowered = to_lower_copy(process_name);
        for (const auto& proc : enumerate_processes()) {
            if (to_lower_copy(proc.name) == lowered)
                return attach(proc.pid);
        }

        std::lock_guard<std::mutex> lk(g_state_mtx);
        set_last_error_locked("Process not found: " + process_name);
        return false;
    }

    void detach()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        close_process_handle_locked();
        g_pid = 0;
        g_process_name.clear();
        if (g_kernel_mode && device && device->is_connected())
            device->clear_process_context();
        set_last_error_locked({});
    }

    std::string status()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (!g_initialized)
            return "Live inspection bridge: not initialized";
        const bool kernel_active = g_kernel_mode && device && device->is_connected();
        if (g_pid == 0) {
            return kernel_active
                ? "Live inspection bridge: kernel backend ready (no process attached)"
                : "Live inspection bridge: user-mode backend ready (no process attached)";
        }

        char buf[256];
        snprintf(buf, sizeof(buf), "Live inspection bridge: %s attached to PID %u (%s)",
                 kernel_active ? "kernel backend" : "user-mode backend",
                 g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str());
        return buf;
    }

    std::string last_error()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_last_error;
    }

    uint32_t attached_pid()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_pid;
    }

    std::string attached_process_name()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_process_name;
    }

    std::vector<process_info_t> enumerate_processes()
    {
        std::vector<process_info_t> result;

        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot)
            return result;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(snapshot.get(), &pe))
            return result;

        do {
            process_info_t proc;
            proc.pid = pe.th32ProcessID;
            proc.name = utf8_from_wide(pe.szExeFile);
            result.push_back(std::move(proc));
        } while (Process32NextW(snapshot.get(), &pe));

        std::sort(result.begin(), result.end(), [](const process_info_t& a, const process_info_t& b) {
            return a.pid < b.pid;
        });
        return result;
    }

    std::vector<module_info_t> enumerate_modules()
    {
        std::vector<module_info_t> result;
        const uint32_t pid = attached_pid();
        if (!pid)
            return result;

        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (!snapshot)
            return result;

        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);
        if (!Module32FirstW(snapshot.get(), &me))
            return result;

        do {
            module_info_t mod;
            mod.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
            mod.size = me.modBaseSize;
            mod.name = utf8_from_wide(me.szModule);
            mod.path = utf8_from_wide(me.szExePath);
            result.push_back(std::move(mod));
        } while (Module32NextW(snapshot.get(), &me));

        std::sort(result.begin(), result.end(), [](const module_info_t& a, const module_info_t& b) {
            return a.base < b.base;
        });
        return result;
    }

    std::vector<thread_info_t> enumerate_threads()
    {
        std::vector<thread_info_t> result;
        const uint32_t pid = attached_pid();
        if (!pid)
            return result;

        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (!snapshot)
            return result;

        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        if (!Thread32First(snapshot.get(), &te))
            return result;

        do {
            if (te.th32OwnerProcessID != pid)
                continue;
            thread_info_t info;
            info.tid = te.th32ThreadID;
            info.owner_pid = te.th32OwnerProcessID;
            info.priority = te.tpBasePri;
            result.push_back(std::move(info));
        } while (Thread32Next(snapshot.get(), &te));

        std::sort(result.begin(), result.end(), [](const thread_info_t& a, const thread_info_t& b) {
            return a.tid < b.tid;
        });
        return result;
    }

    std::vector<memory_region_t> enumerate_memory_regions(size_t max_regions)
    {
        std::vector<memory_region_t> result;
        HANDLE process = nullptr;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (kernel_mode) {
            const auto regions = device->enumerate_memory_regions(0, 0, false);
            for (const auto& src : regions) {
                memory_region_t region;
                region.base = src.base;
                region.size = src.size;
                region.state = src.state;
                region.protect = src.protect;
                region.type = src.type;
                result.push_back(region);
                if (result.size() >= max_regions)
                    break;
            }
            return result;
        }

        if (!process)
            return result;

        uint64_t address = 0;
        MEMORY_BASIC_INFORMATION mbi = {};
        while (result.size() < max_regions &&
               VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            memory_region_t region;
            region.base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            region.size = mbi.RegionSize;
            region.state = mbi.State;
            region.protect = mbi.Protect;
            region.type = mbi.Type;
            result.push_back(region);

            const uint64_t next = region.base + region.size;
            if (next <= address)
                break;
            address = next;
        }

        return result;
    }

    bool query_memory(uint64_t address, memory_region_t& region)
    {
        HANDLE process = nullptr;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (kernel_mode) {
            voyager::device_t::memory_region_info info = {};
            if (!device->query_memory(address, info))
                return false;

            region.base = info.base;
            region.size = info.size;
            region.state = info.state;
            region.protect = info.protect;
            region.type = info.type;
            return true;
        }

        if (!process)
            return false;

        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
            return false;

        region.base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        region.size = mbi.RegionSize;
        region.state = mbi.State;
        region.protect = mbi.Protect;
        region.type = mbi.Type;
        return true;
    }

    bool read_memory(uint64_t address, size_t size, std::vector<uint8_t>& out)
    {
        out.clear();
        HANDLE process = nullptr;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (size == 0)
            return false;

        if (kernel_mode) {
            out.resize(size);
            const auto bytes_read = device->read_raw(address, out.data(), size);
            if (bytes_read == 0) {
                out.clear();
                return false;
            }
            out.resize(bytes_read);
            return true;
        }

        if (!process)
            return false;

        out.resize(size);
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), out.data(), size, &bytes_read) || bytes_read == 0) {
            out.clear();
            return false;
        }
        out.resize(static_cast<size_t>(bytes_read));
        return true;
    }

    bool read_string(uint64_t address, size_t max_length, std::string& out)
    {
        out.clear();
        if (max_length == 0)
            return false;

        std::vector<uint8_t> bytes;
        if (!read_memory(address, max_length, bytes))
            return false;

        for (uint8_t b : bytes) {
            if (b == 0)
                break;
            out.push_back(static_cast<char>(b));
        }
        return !out.empty();
    }
}
