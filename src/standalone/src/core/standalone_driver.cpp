#define WIN32_LEAN_AND_MEAN
#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "driver_loader.hpp"
#include "toast_notification.hpp"
#include "arc/arc.h"
#include "comm.h"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdarg>
#include <cctype>
#include <cstdio>
#include <cstring>
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
    std::vector<driver_bridge::pre_detach_fn_t> g_pre_detach_hooks;
    std::mutex                  g_callback_mtx;

    std::mutex      g_state_mtx;
    HANDLE          g_process = nullptr;


    const arc_comm_vtable_t* get_arc_vtable()
    {
        return standalone_license::get_arc_comm_bridge();
    }
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
        if (!text.empty()) {
            logf("AiDA Standalone: %s\n", text.c_str());
            toast_notification::push(text);
        }
    }

    void require_kernel_fail(const char* func_name)
    {
        logf("AiDA Standalone: %s requires kernel driver.\n", func_name);
        toast_notification::push(std::string(func_name) + " requires kernel driver");
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

    void add_pre_detach_callback(pre_detach_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_pre_detach_hooks.push_back(std::move(fn));
    }

    bool initialize()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_initialized)
            return true;

        g_kernel_mode = false;
        set_last_error_locked({});

        driver_loader::initialize_and_load();

        if (device && device->connect()) {
            g_kernel_mode = true;
            g_initialized = true;
            logf("AiDA Standalone: Live inspection bridge initialized with kernel driver backend.\n");
            return true;
        }

        g_initialized = true;
        logf("AiDA Standalone: Kernel driver unavailable. Live inspection operations require the kernel driver and will not function until it is loaded.\n");
        return true;
    }

    bool load_kernel_driver()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_kernel_mode && device && device->is_connected())
            return true;

        driver_loader::initialize_and_load();

        if (!device || !device->connect()) {
            set_last_error_locked("Failed to connect to the kernel driver.");
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

        {
            uint64_t gt = standalone_license::inline_gate_check(
                standalone_license::gate_driver_attach);
            if (standalone_license::verify_gate_token(
                    standalone_license::gate_driver_attach, gt) < 0.5) {
                return false;
            }
        }

        std::lock_guard<std::mutex> lk(g_state_mtx);

        DWORD access = PROCESS_QUERY_LIMITED_INFORMATION;
        unique_handle process(OpenProcess(access, FALSE, pid));
        if (!process) {
            set_last_error_locked("OpenProcess failed for PID " + std::to_string(pid) +
                                  " (error " + std::to_string(GetLastError()) + ")");
            return false;
        }

        close_process_handle_locked();
        g_process = process.release();
        g_pid = pid;
        if (!refresh_process_name_locked())
            g_process_name = process_name_from_pid(pid);

        bool kernel_ok = g_kernel_mode && device && device->is_connected();
        if (kernel_ok) {
            const auto* vtable = get_arc_vtable();
            if (vtable && vtable->set_process_id && vtable->solve_dtb &&
                vtable->get_dtb && vtable->find_image && vtable->set_base_address) {
                vtable->set_process_id(pid);
                uint64_t dtb = vtable->solve_dtb();
                if (dtb != 0) {
                    const auto image_base = vtable->find_image();
                    if (image_base != 0)
                        vtable->set_base_address(image_base);
                    device->set_process_id(pid);
                    device->solve_dtb();
                    if (image_base != 0)
                        device->set_base_address(image_base);
                } else {
                    kernel_ok = false;
                }
            } else {
                device->set_process_id(pid);
                device->solve_dtb();
                if (device->get_dtb() == 0) {
                    kernel_ok = false;
                } else {
                    const auto image_base = device->find_image();
                    if (image_base != 0)
                        device->set_base_address(image_base);
                }
            }

            if (kernel_ok) {
                device->solve_kernel_dtb();
                if (device->get_kernel_dtb() != 0) {
                    logf("AiDA Standalone: Kernel DTB solved: 0x%llX\n",
                         static_cast<unsigned long long>(device->get_kernel_dtb()));
                }
            }
        }

        set_last_error_locked({});
        if (kernel_ok) {
            logf("AiDA Standalone: Attached to PID %u (%s) via kernel driver. DTB=0x%llX\n",
                 g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str(),
                 static_cast<unsigned long long>(device->get_dtb()));
        } else {
            logf("AiDA Standalone: Attached to PID %u (%s) via user-mode handle.\n",
                 g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str());
        }
        return true;
    }

    bool attach_by_name(const std::string& process_name)
    {
        uint32_t kernel_pid = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            if (g_kernel_mode && device && device->is_connected()) {
                const auto* vtable = get_arc_vtable();
                if (vtable && vtable->find_process) {
                    kernel_pid = vtable->find_process(process_name.c_str());
                } else {
                    kernel_pid = device->find_process(process_name.c_str());
                }
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


        {
            std::lock_guard<std::mutex> lk(g_callback_mtx);
            for (auto& hook : g_pre_detach_hooks) {
                if (hook) hook();
            }
        }

        std::lock_guard<std::mutex> lk(g_state_mtx);
        close_process_handle_locked();
        g_pid = 0;
        g_process_name.clear();
        if (g_kernel_mode && device && device->is_connected()) {
            const auto* vtable = get_arc_vtable();
            if (vtable && vtable->clear_process_context) {
                vtable->clear_process_context();
            } else {
                device->clear_process_context();
            }
        }
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
                : "Live inspection bridge: kernel driver required (not loaded)";
        }

        char buf[256];
        snprintf(buf, sizeof(buf), "Live inspection bridge: %s attached to PID %u (%s)",
                 kernel_active ? "kernel backend" : "kernel driver required (not loaded)",
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

    struct enum_main_window_ctx {
        DWORD pid;
        HWND  result;
    };

    static BOOL CALLBACK find_main_window_cb(HWND hwnd, LPARAM lParam)
    {
        auto* ctx = reinterpret_cast<enum_main_window_ctx*>(lParam);
        DWORD wnd_pid = 0;
        GetWindowThreadProcessId(hwnd, &wnd_pid);
        if (wnd_pid != ctx->pid) return TRUE;
        if (GetWindow(hwnd, GW_OWNER)) return TRUE;
        if (!IsWindowVisible(hwnd)) return TRUE;
        ctx->result = hwnd;
        return FALSE;
    }

    static std::string get_window_title(DWORD pid)
    {
        enum_main_window_ctx ctx{pid, nullptr};
        EnumWindows(find_main_window_cb, reinterpret_cast<LPARAM>(&ctx));
        if (!ctx.result) return {};
        wchar_t buf[256] = {};
        if (!GetWindowTextW(ctx.result, buf, 256)) return {};
        return utf8_from_wide(buf);
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

        DWORD self_pid = GetCurrentProcessId();

        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
                continue;
            if (pe.th32ProcessID == self_pid)
                continue;

            process_info_t proc;
            proc.pid  = pe.th32ProcessID;
            proc.name = utf8_from_wide(pe.szExeFile);

            auto hProc = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID));
            if (hProc) {
                wchar_t path_buf[MAX_PATH] = {};
                DWORD path_len = static_cast<DWORD>(std::size(path_buf));
                if (QueryFullProcessImageNameW(hProc.get(), 0, path_buf, &path_len) && path_len > 0)
                    proc.path = utf8_from_wide(path_buf);
            }

            proc.window_title = get_window_title(pe.th32ProcessID);

            result.push_back(std::move(proc));
        } while (Process32NextW(snapshot.get(), &pe));

        std::sort(result.begin(), result.end(), [](const process_info_t& a, const process_info_t& b) {
            if (!a.window_title.empty() && b.window_title.empty()) return true;
            if (a.window_title.empty() && !b.window_title.empty()) return false;
            return a.pid < b.pid;
        });
        return result;
    }

    static std::vector<module_info_t> enumerate_modules_usermode(uint32_t pid, HANDLE process)
    {
        std::vector<module_info_t> result;

        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (!snapshot)
            return result;

        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snapshot.get(), &me)) {
            do {
                module_info_t mod;
                mod.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                mod.size = me.modBaseSize;
                mod.name = utf8_from_wide(me.szModule);
                mod.path = utf8_from_wide(me.szExePath);
                result.push_back(std::move(mod));
            } while (Module32NextW(snapshot.get(), &me));
        }

        std::sort(result.begin(), result.end(), [](const module_info_t& a, const module_info_t& b) {
            return a.base < b.base;
        });
        return result;
    }

    std::vector<module_info_t> enumerate_modules()
    {
        std::vector<module_info_t> result;
        const uint32_t pid = attached_pid();
        if (!pid)
            return result;

        HANDLE process = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
        }

        if (process) {
            result = enumerate_modules_usermode(pid, process);
        }

        if (!result.empty()) {
            logf("AiDA Standalone: enumerate_modules: resolved %zu modules via user-mode snapshot for PID %u.\n",
                 result.size(), pid);
            return result;
        }

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (!kernel_mode) {
            logf("AiDA Standalone: enumerate_modules: no modules resolved for PID %u.\n", pid);
            return result;
        }

        voyager::device_t::peb_info peb{};
        if (!device->read_peb(peb) || peb.ldr_address == 0) {
            logf("AiDA Standalone: enumerate_modules: failed to read PEB/LDR for PID %u.\n", pid);
            return result;
        }

        const uint64_t list_head = peb.ldr_address + 0x10;
        uint64_t current = device->read<uint64_t>(list_head);
        if (current == 0 || current == list_head) {
            logf("AiDA Standalone: enumerate_modules: LDR list empty for PID %u.\n", pid);
            return result;
        }

        int max_iter = 1024;
        while (current != list_head && current != 0 && max_iter-- > 0) {
            const uint64_t dll_base = device->read<uint64_t>(current + 0x30);
            const uint32_t size_of_image = device->read<uint32_t>(current + 0x40);

            const uint16_t full_name_len = device->read<uint16_t>(current + 0x48);
            const uint64_t full_name_ptr = device->read<uint64_t>(current + 0x50);
            const uint16_t base_name_len = device->read<uint16_t>(current + 0x58);
            const uint64_t base_name_ptr = device->read<uint64_t>(current + 0x60);

            std::string base_name;
            if (base_name_ptr != 0 && base_name_len > 0 && base_name_len <= 520) {
                std::vector<uint8_t> raw(base_name_len, 0);
                if (device->read_raw(base_name_ptr, raw.data(), base_name_len) > 0) {
                    base_name.reserve(base_name_len / 2);
                    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                        uint16_t wc = raw[i] | (static_cast<uint16_t>(raw[i + 1]) << 8);
                        if (wc == 0) break;
                        base_name += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
                    }
                }
            }

            std::string full_path;
            if (full_name_ptr != 0 && full_name_len > 0 && full_name_len <= 1024) {
                std::vector<uint8_t> raw(full_name_len, 0);
                if (device->read_raw(full_name_ptr, raw.data(), full_name_len) > 0) {
                    full_path.reserve(full_name_len / 2);
                    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                        uint16_t wc = raw[i] | (static_cast<uint16_t>(raw[i + 1]) << 8);
                        if (wc == 0) break;
                        full_path += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
                    }
                }
            }

            if (dll_base != 0 && !base_name.empty()) {
                module_info_t mod;
                mod.base = dll_base;
                mod.size = size_of_image;
                mod.name = std::move(base_name);
                mod.path = std::move(full_path);
                result.push_back(std::move(mod));
            }

            const uint64_t next = device->read<uint64_t>(current);
            if (next == current || next == 0)
                break;
            current = next;
        }

        std::sort(result.begin(), result.end(), [](const module_info_t& a, const module_info_t& b) {
            return a.base < b.base;
        });

        logf("AiDA Standalone: enumerate_modules: resolved %zu modules via kernel LDR walk for PID %u.\n",
             result.size(), pid);
        return result;
    }

    std::vector<thread_info_t> enumerate_threads()
    {
        std::vector<thread_info_t> result;
        const uint32_t pid = attached_pid();
        if (!pid)
            return result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (!kernel_mode) {
            auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
            if (snapshot) {
                THREADENTRY32 te = {};
                te.dwSize = sizeof(te);
                if (Thread32First(snapshot.get(), &te)) {
                    do {
                        if (te.th32OwnerProcessID == pid) {
                            thread_info_t t;
                            t.tid = te.th32ThreadID;
                            t.owner_pid = pid;
                            t.priority = te.tpBasePri;
                            t.state = 0;
                            t.rip = 0;
                            result.push_back(t);
                        }
                    } while (Thread32Next(snapshot.get(), &te));
                }
            }
            std::sort(result.begin(), result.end(), [](const thread_info_t& a, const thread_info_t& b) {
                return a.tid < b.tid;
            });
            logf("AiDA Standalone: enumerate_threads: resolved %zu threads via user-mode snapshot for PID %u.\n",
                 result.size(), pid);
            return result;
        }

        const auto* vtable = get_arc_vtable();
        if (vtable && vtable->enumerate_threads) {
            struct enum_ctx { std::vector<thread_info_t>* out; uint32_t pid; };
            enum_ctx ctx{&result, pid};
            vtable->enumerate_threads(
                [](const arc_comm_vtable_t::thread_info_t* info, void* user) {
                    auto* c = static_cast<enum_ctx*>(user);
                    thread_info_t t;
                    t.tid = info->tid;
                    t.owner_pid = c->pid;
                    t.priority = 0;
                    t.state = info->state;
                    t.rip = info->rip;
                    c->out->push_back(t);
                },
                &ctx);
        } else {
            auto kernel_threads = device->enumerate_threads();
            result.reserve(kernel_threads.size());
            for (const auto& kt : kernel_threads) {
                thread_info_t t;
                t.tid = kt.tid;
                t.owner_pid = pid;
                t.priority = 0;
                t.state = kt.state;
                t.rip = kt.rip;
                result.push_back(t);
            }
        }

        std::sort(result.begin(), result.end(), [](const thread_info_t& a, const thread_info_t& b) {
            return a.tid < b.tid;
        });

        logf("AiDA Standalone: enumerate_threads: resolved %zu threads via kernel IOCTL for PID %u.\n",
             result.size(), pid);
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
            const auto* vtable = get_arc_vtable();
            if (vtable && vtable->enumerate_memory_regions) {
                struct enum_ctx { std::vector<memory_region_t>* out; size_t max; };
                enum_ctx ctx{&result, max_regions};
                vtable->enumerate_memory_regions(
                    [](const arc_comm_vtable_t::memory_region_info_t* info, void* user) {
                        auto* c = static_cast<enum_ctx*>(user);
                        if (c->out->size() >= c->max) return;
                        memory_region_t region;
                        region.base    = info->base;
                        region.size    = info->size;
                        region.state   = info->state;
                        region.protect = info->protect;
                        region.type    = info->type;
                        c->out->push_back(region);
                    },
                    &ctx);
            } else {
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
            }
            return result;
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
            const auto* vtable = get_arc_vtable();
            if (vtable && vtable->query_memory) {
                arc_comm_vtable_t::memory_region_info_t arc_info{};
                if (!vtable->query_memory(address, &arc_info))
                    return false;
                region.base    = arc_info.base;
                region.size    = arc_info.size;
                region.state   = arc_info.state;
                region.protect = arc_info.protect;
                region.type    = arc_info.type;
                return true;
            } else {
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
        }

        return false;
    }

    bool read_memory(uint64_t address, size_t size, std::vector<uint8_t>& out)
    {

        {
            uint64_t gt = standalone_license::inline_gate_check(
                standalone_license::gate_driver_read_mem);
            if (standalone_license::verify_gate_token(
                    standalone_license::gate_driver_read_mem, gt) < 0.5) {
                out.clear();
                return false;
            }
        }

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
            size_t bytes_read = 0;
            const auto* vtable = get_arc_vtable();
            if (vtable && vtable->read_raw) {
                bytes_read = vtable->read_raw(address, out.data(), size);
            } else {
                bytes_read = device->read_raw(address, out.data(), size);
            }

            if (bytes_read == 0) {
                bool re_resolved = false;
                {
                    std::lock_guard<std::mutex> lk(g_state_mtx);
                    if (vtable && vtable->solve_dtb && vtable->get_dtb) {
                        uint64_t new_dtb = vtable->solve_dtb();
                        re_resolved = (new_dtb != 0);
                    } else if (device) {
                        device->solve_dtb();
                        re_resolved = (device->get_dtb() != 0);
                    }
                }

                if (re_resolved) {
                    std::memset(out.data(), 0, size);
                    if (vtable && vtable->read_raw) {
                        bytes_read = vtable->read_raw(address, out.data(), size);
                    } else {
                        bytes_read = device->read_raw(address, out.data(), size);
                    }
                }

                if (bytes_read == 0) {
                    out.clear();
                    return false;
                }
            }

            out.resize(bytes_read);
            return true;
        }

        return false;
    }

    bool write_memory(uint64_t address, const std::vector<uint8_t>& data)
    {
        {
            uint64_t gt = standalone_license::inline_gate_check(
                standalone_license::gate_driver_read_mem);
            if (standalone_license::verify_gate_token(
                    standalone_license::gate_driver_read_mem, gt) < 0.5) {
                return false;
            }
        }

        if (data.empty())
            return false;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (kernel_mode) {
            size_t bytes_written = 0;
            const auto* vtable = get_arc_vtable();
            if (vtable && vtable->write_raw) {
                bytes_written = vtable->write_raw(address, data.data(), data.size());
            } else {
                bytes_written = device->write_raw(address, data.data(), data.size());
            }


            if (bytes_written == 0) {
                bool re_resolved = false;
                {
                    std::lock_guard<std::mutex> lk(g_state_mtx);
                    if (vtable && vtable->solve_dtb && vtable->get_dtb) {
                        uint64_t new_dtb = vtable->solve_dtb();
                        re_resolved = (new_dtb != 0);
                    } else if (device) {
                        device->solve_dtb();
                        re_resolved = (device->get_dtb() != 0);
                    }
                }

                if (re_resolved) {
                    if (vtable && vtable->write_raw) {
                        bytes_written = vtable->write_raw(address, data.data(), data.size());
                    } else {
                        bytes_written = device->write_raw(address, data.data(), data.size());
                    }
                }
            }

            return bytes_written > 0;
        }

        return false;
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


    bool read_kernel_memory(uint64_t address, size_t size, std::vector<uint8_t>& out)
    {
        out.clear();
        if (size == 0)
            return false;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("read_kernel_memory");
            return false;
        }

        out.resize(size);
        const size_t bytes_read = device->read_kernel_raw(address, out.data(), size);
        if (bytes_read == 0) {
            out.clear();
            return false;
        }
        out.resize(bytes_read);
        return true;
    }

    bool write_kernel_memory(uint64_t address, const std::vector<uint8_t>& data)
    {
        if (data.empty())
            return false;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("write_kernel_memory");
            return false;
        }

        const size_t bytes_written = device->write_kernel_raw(address, data.data(), data.size());
        return bytes_written > 0;
    }


    uint64_t allocate_memory(size_t size)
    {
        if (size == 0)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            return 0;
        }

        return device->allocate_memory(size);
    }

    bool free_memory(uint64_t address)
    {
        if (address == 0)
            return false;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            return false;
        }

        return device->free_memory(address);
    }

    bool protect_memory(uint64_t address, uint64_t size, uint32_t new_protect, uint32_t* old_protect)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            return false;
        }

        return device->protect_memory(address, size, new_protect, old_protect);
    }


    bool get_thread_context(uint32_t tid, thread_context_t& ctx)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            return false;
        }

        voyager::device_t::thread_context kctx{};
        if (!device->get_thread_context(tid, kctx))
            return false;

        ctx.rax = kctx.rax;  ctx.rbx = kctx.rbx;  ctx.rcx = kctx.rcx;  ctx.rdx = kctx.rdx;
        ctx.rsi = kctx.rsi;  ctx.rdi = kctx.rdi;  ctx.rbp = kctx.rbp;  ctx.rsp = kctx.rsp;
        ctx.r8  = kctx.r8;   ctx.r9  = kctx.r9;   ctx.r10 = kctx.r10;  ctx.r11 = kctx.r11;
        ctx.r12 = kctx.r12;  ctx.r13 = kctx.r13;  ctx.r14 = kctx.r14;  ctx.r15 = kctx.r15;
        ctx.rip = kctx.rip;  ctx.rflags = kctx.rflags;
        ctx.cs  = kctx.cs;   ctx.ss  = kctx.ss;
        ctx.dr0 = kctx.dr0;  ctx.dr1 = kctx.dr1;  ctx.dr2 = kctx.dr2;  ctx.dr3 = kctx.dr3;
        ctx.dr6 = kctx.dr6;  ctx.dr7 = kctx.dr7;
        return true;
    }

    bool set_thread_context(uint32_t tid, const thread_context_t& ctx, uint64_t register_mask)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            return false;
        }

        voyager::device_t::thread_context kctx{};
        kctx.rax = ctx.rax;  kctx.rbx = ctx.rbx;  kctx.rcx = ctx.rcx;  kctx.rdx = ctx.rdx;
        kctx.rsi = ctx.rsi;  kctx.rdi = ctx.rdi;  kctx.rbp = ctx.rbp;  kctx.rsp = ctx.rsp;
        kctx.r8  = ctx.r8;   kctx.r9  = ctx.r9;   kctx.r10 = ctx.r10;  kctx.r11 = ctx.r11;
        kctx.r12 = ctx.r12;  kctx.r13 = ctx.r13;  kctx.r14 = ctx.r14;  kctx.r15 = ctx.r15;
        kctx.rip = ctx.rip;  kctx.rflags = ctx.rflags;
        kctx.cs  = ctx.cs;   kctx.ss  = ctx.ss;
        kctx.dr0 = ctx.dr0;  kctx.dr1 = ctx.dr1;  kctx.dr2 = ctx.dr2;  kctx.dr3 = ctx.dr3;
        kctx.dr6 = ctx.dr6;  kctx.dr7 = ctx.dr7;
        return device->set_thread_context(tid, kctx, register_mask);
    }

    bool suspend_thread(uint32_t tid, uint32_t* prev_count)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            return false;
        }

        return device->suspend_thread(tid, prev_count);
    }

    bool resume_thread(uint32_t tid, uint32_t* prev_count)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            return false;
        }

        return device->resume_thread(tid, prev_count);
    }


    bool read_peb(peb_info_t& out)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("read_peb");
            return false;
        }

        voyager::device_t::peb_info kpeb{};
        if (!device->read_peb(kpeb))
            return false;

        out.peb_address     = kpeb.peb_address;
        out.image_base      = kpeb.image_base;
        out.being_debugged  = kpeb.being_debugged;
        out.nt_global_flag  = kpeb.nt_global_flag;
        out.ldr_address     = kpeb.ldr_address;
        out.process_heap    = kpeb.process_heap;
        out.number_of_heaps = kpeb.number_of_heaps;
        out.max_heaps       = kpeb.max_heaps;
        out.process_heaps   = kpeb.process_heaps;
        return true;
    }

    uint64_t resolve_export(uint64_t module_base, const char* export_name)
    {
        if (module_base == 0 || !export_name || !*export_name)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("resolve_export");
            return 0;
        }

        return device->resolve_export(module_base, export_name);
    }

    uint64_t virtual_to_physical(uint64_t virtual_address)
    {
        if (virtual_address == 0)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("virtual_to_physical");
            return 0;
        }

        return device->virtual_to_physical(virtual_address);
    }


    std::vector<net_connection_info_t> enumerate_connections(uint32_t filter_pid, uint32_t filter_protocol)
    {
        std::vector<net_connection_info_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("enumerate_connections");
            return result;
        }

        auto raw = device->enumerate_connections(filter_pid, filter_protocol);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            net_connection_info_t c;
            c.pid            = src.pid;
            c.protocol       = src.protocol;
            c.state          = src.state;
            c.local_port     = src.local_port;
            c.remote_port    = src.remote_port;
            c.address_family = src.address_family;
            std::memcpy(c.local_addr,  src.local_addr,  sizeof(c.local_addr));
            std::memcpy(c.remote_addr, src.remote_addr, sizeof(c.remote_addr));
            std::memcpy(c.process_path, src.process_path, sizeof(c.process_path));
            result.push_back(c);
        }
        return result;
    }


    bool start_capture(uint32_t filter_pid, uint32_t filter_port, uint32_t filter_protocol, const uint8_t* filter_ip, uint32_t max_payload)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("start_capture");
            return false;
        }

        return device->start_capture(filter_pid, filter_port, filter_protocol, filter_ip, max_payload);
    }

    bool stop_capture()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("stop_capture");
            return false;
        }

        return device->stop_capture();
    }

    bool get_capture_status(bool& active, uint32_t& captured, uint32_t& dropped)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return false;

        return device->get_capture_status(active, captured, dropped);
    }

    std::vector<captured_packet_t> get_captured_packets(uint32_t max_packets)
    {
        std::vector<captured_packet_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return result;

        auto raw = device->get_captured_packets(max_packets);
        result.reserve(raw.size());
        for (auto& src : raw) {
            captured_packet_t pkt;
            pkt.timestamp      = src.timestamp;
            pkt.pid            = src.pid;
            pkt.protocol       = src.protocol;
            pkt.direction      = src.direction;
            pkt.payload_size   = src.payload_size;
            pkt.local_port     = src.local_port;
            pkt.remote_port    = src.remote_port;
            pkt.address_family = src.address_family;
            std::memcpy(pkt.local_addr,  src.local_addr,  sizeof(pkt.local_addr));
            std::memcpy(pkt.remote_addr, src.remote_addr, sizeof(pkt.remote_addr));
            pkt.payload = std::move(src.payload);
            result.push_back(std::move(pkt));
        }
        return result;
    }


    std::vector<dns_entry_t> get_dns_queries(uint32_t filter_pid)
    {
        std::vector<dns_entry_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return result;

        auto raw = device->get_dns_queries(filter_pid);
        result.reserve(raw.size());
        for (auto& src : raw) {
            dns_entry_t entry;
            entry.timestamp     = src.timestamp;
            entry.pid           = src.pid;
            entry.query_type    = src.query_type;
            entry.domain        = std::move(src.domain);
            std::memcpy(entry.resolved_addr, src.resolved_addr, sizeof(entry.resolved_addr));
            entry.response_code = src.response_code;
            entry.ttl           = src.ttl;
            result.push_back(std::move(entry));
        }
        return result;
    }


    bool add_filter_rule(uint32_t action, uint32_t direction, uint32_t protocol, uint32_t pid, uint32_t port, const uint8_t* ip_addr, const uint8_t* ip_mask, uint32_t* out_rule_id)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("add_filter_rule");
            return false;
        }

        return device->add_filter_rule(action, direction, protocol, pid, port, ip_addr, ip_mask, out_rule_id);
    }

    bool remove_filter_rule(uint32_t rule_id)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("remove_filter_rule");
            return false;
        }

        return device->remove_filter_rule(rule_id);
    }

    bool clear_filter_rules()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("clear_filter_rules");
            return false;
        }

        return device->clear_filter_rules();
    }


    bool get_network_stats(network_stats_t& stats)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return false;

        voyager::device_t::network_stats ks{};
        if (!device->get_network_stats(ks))
            return false;

        stats.bytes_sent          = ks.bytes_sent;
        stats.bytes_received      = ks.bytes_received;
        stats.packets_sent        = ks.packets_sent;
        stats.packets_received    = ks.packets_received;
        stats.active_connections  = ks.active_connections;
        stats.capture_active      = ks.capture_active;
        stats.total_captured      = ks.total_captured;
        stats.total_dropped       = ks.total_dropped;
        stats.total_dns_logged    = ks.total_dns_logged;
        stats.active_filter_rules = ks.active_filter_rules;
        return true;
    }

    bool bw_monitor_op(uint32_t operation, uint32_t filter_pid, bw_stats_t* out_stats)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("bw_monitor_op");
            return false;
        }

        voyager::device_t::bw_stats raw{};
        bool ok = device->bw_monitor_op(operation, filter_pid, out_stats ? &raw : nullptr);
        if (ok && out_stats) {
            out_stats->total_bytes_sent    = raw.total_bytes_sent;
            out_stats->total_bytes_recv    = raw.total_bytes_recv;
            out_stats->total_packets_sent  = raw.total_packets_sent;
            out_stats->total_packets_recv  = raw.total_packets_recv;
            out_stats->bps_in              = raw.bps_in;
            out_stats->bps_out             = raw.bps_out;
            out_stats->active              = raw.active;
        }
        return ok;
    }

    std::vector<bw_process_info_t> get_bw_per_process(uint32_t filter_pid)
    {
        std::vector<bw_process_info_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return result;

        auto raw = device->get_bw_per_process(filter_pid);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            bw_process_info_t bw;
            bw.pid           = src.pid;
            bw.bytes_sent    = src.bytes_sent;
            bw.bytes_recv    = src.bytes_recv;
            bw.packets_sent  = src.packets_sent;
            bw.packets_recv  = src.packets_recv;
            bw.last_activity = src.last_activity;
            result.push_back(bw);
        }
        return result;
    }


    uint64_t call_function(uint64_t function_address, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
    {
        if (function_address == 0)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("call_function");
            return 0;
        }

        const auto* vtable = get_arc_vtable();
        if (vtable && vtable->remote_call)
            return vtable->remote_call(function_address, arg1, arg2, arg3, arg4);

        return device->call_function(function_address, arg1, arg2, arg3, arg4);
    }

    uint64_t find_gadget(const char* pattern, size_t pattern_size)
    {
        if (!pattern || pattern_size == 0)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("find_gadget");
            return 0;
        }

        return device->find_gadget(pattern, pattern_size);
    }

    bool set_hardware_breakpoint(uint32_t tid, int index, uint64_t address, int type, int size)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("set_hardware_breakpoint");
            return false;
        }

        return device->set_hardware_breakpoint(tid, index, address, type, size);
    }

    bool clear_hardware_breakpoint(uint32_t tid, int index)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("clear_hardware_breakpoint");
            return false;
        }

        return device->clear_hardware_breakpoint(tid, index);
    }

    bool spoof_debug_flags(uint32_t* result_flags)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("spoof_debug_flags");
            return false;
        }

        return device->spoof_debug_flags(result_flags);
    }

    bool refresh_heartbeat()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return false;

        return device->refresh_heartbeat();
    }

    bool register_dll_protection(uint64_t module_base, uint64_t text_va, uint32_t text_size,
                                 uint64_t expected_hash, uint32_t check_interval_ms)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("register_dll_protection");
            return false;
        }

        return device->register_dll_protection(module_base, text_va, text_size,
                                               expected_hash, check_interval_ms);
    }

    bool query_dll_protection(dll_protect_status_t& out)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("query_dll_protection");
            return false;
        }

        voyager::device_t::dll_protect_status raw{};
        if (!device->query_dll_protection(raw))
            return false;

        out.status         = raw.status;
        out.current_hash   = raw.current_hash;
        out.expected_hash  = raw.expected_hash;
        out.last_check_tsc = raw.last_check_tsc;
        return true;
    }

    bool unregister_dll_protection()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("unregister_dll_protection");
            return false;
        }

        return device->unregister_dll_protection();
    }

    bool traffic_redirect_op(uint32_t operation, uint32_t rule_id, uint32_t protocol,
                             uint32_t match_port, const uint8_t* match_addr,
                             uint32_t redirect_port, const uint8_t* redirect_addr,
                             uint32_t af, uint32_t* out_rule_id, uint32_t exclude_pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("traffic_redirect_op");
            return false;
        }

        return device->traffic_redirect_op(operation, rule_id, protocol, match_port, match_addr,
                                           redirect_port, redirect_addr, af, out_rule_id, exclude_pid);
    }

    bool inject_packet(uint32_t direction, uint32_t protocol, uint32_t af,
                       uint32_t src_port, uint32_t dst_port,
                       const uint8_t* src_addr, const uint8_t* dst_addr,
                       const uint8_t* payload, uint32_t payload_size,
                       uint32_t tcp_flags, uint32_t tcp_seq, uint32_t tcp_ack)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("inject_packet");
            return false;
        }

        return device->inject_packet(direction, protocol, af, src_port, dst_port,
                                     src_addr, dst_addr, payload, payload_size,
                                     tcp_flags, tcp_seq, tcp_ack);
    }

    bool kill_connection(uint32_t protocol, uint32_t af,
                         uint32_t src_port, uint32_t dst_port,
                         const uint8_t* src_addr, const uint8_t* dst_addr,
                         uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("kill_connection");
            return false;
        }

        return device->kill_connection(protocol, af, src_port, dst_port, src_addr, dst_addr, pid);
    }

    bool intercept_op(uint32_t operation, uint32_t filter_pid, uint32_t filter_port,
                      uint32_t filter_protocol, uint64_t hold_id,
                      const uint8_t* modify_payload, uint32_t modify_size,
                      uint32_t* out_held_count, bool* out_active)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("intercept_op");
            return false;
        }

        return device->intercept_op(operation, filter_pid, filter_port, filter_protocol,
                                    hold_id, modify_payload, modify_size,
                                    out_held_count, out_active);
    }

    bool dns_spoof_op(uint32_t operation, uint32_t rule_id, const char* domain,
                      const uint8_t* spoof_addr, uint32_t af,
                      uint32_t ttl, uint32_t* out_rule_id)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("dns_spoof_op");
            return false;
        }

        return device->dns_spoof_op(operation, rule_id, domain, spoof_addr, af, ttl, out_rule_id);
    }

    bool packet_mod_rule_op(uint32_t operation, uint32_t rule_id,
                            uint32_t direction, uint32_t protocol,
                            uint32_t port, uint32_t pid,
                            const uint8_t* pattern, uint32_t pattern_size,
                            const uint8_t* replacement, uint32_t replace_size,
                            uint32_t* out_rule_id)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("packet_mod_rule_op");
            return false;
        }

        return device->packet_mod_rule_op(operation, rule_id, direction, protocol,
                                          port, pid, pattern, pattern_size,
                                          replacement, replace_size, out_rule_id);
    }

    bool stream_reassemble_op(uint32_t operation, uint32_t src_port, uint32_t dst_port,
                              uint32_t pid, const uint8_t* src_addr,
                              const uint8_t* dst_addr,
                              std::vector<uint8_t>* out_data,
                              uint32_t* out_packets, uint32_t* out_truncated)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("stream_reassemble_op");
            return false;
        }

        return device->stream_reassemble_op(operation, src_port, dst_port, pid,
                                            src_addr, dst_addr, out_data,
                                            out_packets, out_truncated);
    }

    bool sniff_net_buffers_start(uint64_t address, uint32_t buf_reg, uint32_t size_reg,
                                 uint32_t max_captures, uint32_t tid, uint32_t bp_index)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("sniff_net_buffers_start");
            return false;
        }

        return device->sniff_net_buffers_start(address, buf_reg, size_reg, max_captures, tid, bp_index);
    }

    bool sniff_net_buffers_stop()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("sniff_net_buffers_stop");
            return false;
        }

        return device->sniff_net_buffers_stop();
    }

    std::vector<sniff_result_t> sniff_net_buffers_get(bool& active)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            active = false;
            return {};
        }

        auto raw = device->sniff_net_buffers_get(active);
        std::vector<sniff_result_t> out;
        out.reserve(raw.size());
        for (auto& r : raw) {
            sniff_result_t sr;
            sr.timestamp = r.timestamp;
            sr.thread_id = r.thread_id;
            sr.buffer    = std::move(r.buffer);
            out.push_back(std::move(sr));
        }
        return out;
    }

    std::vector<dpi_result_t> get_dpi_results(uint32_t filter_pid, uint32_t filter_protocol, uint32_t filter_port, uint32_t flags)
    {
        std::vector<dpi_result_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->get_dpi_results(filter_pid, filter_protocol, filter_port, flags);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            dpi_result_t d;
            d.timestamp      = src.timestamp;
            d.direction      = src.direction;
            d.protocol       = src.protocol;
            d.src_port       = src.src_port;
            d.dst_port       = src.dst_port;
            d.pid            = src.pid;
            d.payload_size   = src.payload_size;
            d.af             = src.af;
            std::memcpy(d.src_addr, src.src_addr, 16);
            std::memcpy(d.dst_addr, src.dst_addr, 16);
            d.tcp_flags      = src.tcp_flags;
            d.tcp_window     = src.tcp_window;
            d.is_http        = src.is_http;
            d.is_tls         = src.is_tls;
            d.is_dns         = src.is_dns;
            d.http_method    = src.http_method;
            d.tls_version    = src.tls_version;
            d.tls_content_type = src.tls_content_type;
            d.http_host      = src.http_host;
            d.http_path      = src.http_path;
            d.tls_sni        = src.tls_sni;
            result.push_back(std::move(d));
        }
        return result;
    }

    std::vector<wfp_callout_info_t> enumerate_wfp_callouts(const std::string& filter_module)
    {
        std::vector<wfp_callout_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->enumerate_wfp_callouts(filter_module);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            wfp_callout_info_t c;
            c.classify_fn          = src.classify_fn;
            c.notify_fn            = src.notify_fn;
            c.flow_delete_fn       = src.flow_delete_fn;
            c.owning_module_base   = src.owning_module_base;
            c.callout_id           = src.callout_id;
            c.layer_id             = src.layer_id;
            c.flags                = src.flags;
            c.callout_key_str      = src.callout_key_str;
            c.applicable_layer_str = src.applicable_layer_str;
            c.owning_module        = src.owning_module;
            result.push_back(std::move(c));
        }
        return result;
    }

    std::vector<socket_info_t> get_socket_handles(uint32_t target_pid)
    {
        std::vector<socket_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->get_socket_handles(target_pid);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            socket_info_t s;
            s.handle_value     = src.handle_value;
            s.afd_endpoint_addr = src.afd_endpoint_addr;
            s.pid              = src.pid;
            s.protocol         = src.protocol;
            s.state            = src.state;
            s.local_port       = src.local_port;
            s.remote_port      = src.remote_port;
            s.address_family   = src.address_family;
            std::memcpy(s.local_addr, src.local_addr, 16);
            std::memcpy(s.remote_addr, src.remote_addr, 16);
            result.push_back(s);
        }
        return result;
    }

    std::vector<tcpip_connection_t> dump_tcpip_connections(uint32_t target_pid, uint32_t filter_protocol)
    {
        std::vector<tcpip_connection_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->dump_tcpip_connections(target_pid, filter_protocol);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            tcpip_connection_t c;
            c.tcb_address        = src.tcb_address;
            c.owning_module_base = src.owning_module_base;
            c.pid                = src.pid;
            c.protocol           = src.protocol;
            c.state              = src.state;
            c.local_port         = src.local_port;
            c.remote_port        = src.remote_port;
            c.address_family     = src.address_family;
            std::memcpy(c.local_addr, src.local_addr, 16);
            std::memcpy(c.remote_addr, src.remote_addr, 16);
            c.create_time        = src.create_time;
            c.bytes_in           = src.bytes_in;
            c.bytes_out          = src.bytes_out;
            result.push_back(c);
        }
        return result;
    }

    std::vector<net_iface_info_t> enumerate_interfaces()
    {
        std::vector<net_iface_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->enumerate_interfaces();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            net_iface_info_t ifc;
            ifc.if_index    = src.if_index;
            ifc.if_type     = src.if_type;
            ifc.mtu         = src.mtu;
            ifc.oper_status = src.oper_status;
            ifc.speed       = src.speed;
            std::memcpy(ifc.mac_addr, src.mac_addr, 6);
            std::memcpy(ifc.ipv4_addr, src.ipv4_addr, 4);
            std::memcpy(ifc.ipv4_mask, src.ipv4_mask, 4);
            std::memcpy(ifc.ipv6_addr, src.ipv6_addr, 16);
            ifc.name        = src.name;
            ifc.description = src.description;
            ifc.in_octets   = src.in_octets;
            ifc.out_octets  = src.out_octets;
            result.push_back(std::move(ifc));
        }
        return result;
    }

    std::vector<held_packet_info_t> get_held_packets()
    {
        std::vector<held_packet_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->get_held_packets();
        result.reserve(raw.size());
        for (auto& src : raw) {
            held_packet_info_t h;
            h.hold_id      = src.hold_id;
            h.timestamp    = src.timestamp;
            h.direction    = src.direction;
            h.protocol     = src.protocol;
            h.src_port     = src.src_port;
            h.dst_port     = src.dst_port;
            h.pid          = src.pid;
            h.payload_size = src.payload_size;
            h.af           = src.af;
            std::memcpy(h.src_addr, src.src_addr, 16);
            std::memcpy(h.dst_addr, src.dst_addr, 16);
            h.payload      = std::move(src.payload);
            result.push_back(std::move(h));
        }
        return result;
    }

    std::vector<mod_rule_info_t> list_packet_mod_rules()
    {
        std::vector<mod_rule_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->list_packet_mod_rules();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            mod_rule_info_t r;
            r.rule_id     = src.rule_id;
            r.direction   = src.direction;
            r.protocol    = src.protocol;
            r.port        = src.port;
            r.pid         = src.pid;
            r.match_count = src.match_count;
            r.active      = src.active;
            result.push_back(r);
        }
        return result;
    }

    std::vector<redirect_rule_info_t> list_redirect_rules()
    {
        std::vector<redirect_rule_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->list_redirect_rules();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            redirect_rule_info_t r;
            r.rule_id       = src.rule_id;
            r.protocol      = src.protocol;
            r.match_port    = src.match_port;
            r.redirect_port = src.redirect_port;
            r.af            = src.af;
            r.match_count   = src.match_count;
            r.active        = src.active;
            result.push_back(r);
        }
        return result;
    }

    std::vector<dns_spoof_info_t> list_dns_spoof_rules()
    {
        std::vector<dns_spoof_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->list_dns_spoof_rules();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            dns_spoof_info_t r;
            r.rule_id     = src.rule_id;
            r.domain      = src.domain;
            r.af          = src.af;
            r.match_count = src.match_count;
            r.active      = src.active;
            r.ttl         = src.ttl;
            result.push_back(std::move(r));
        }
        return result;
    }

    bool fingerprint_op(uint32_t operation)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("fingerprint_op");
            return false;
        }
        return device->fingerprint_op(operation);
    }

    std::vector<fingerprint_info_t> get_fingerprints()
    {
        std::vector<fingerprint_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->get_fingerprints();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            fingerprint_info_t f;
            std::memcpy(f.remote_addr, src.remote_addr, 16);
            f.af             = src.af;
            f.ttl            = src.ttl;
            f.window_size    = src.window_size;
            f.mss            = src.mss;
            f.window_scale   = src.window_scale;
            f.df_flag        = src.df_flag;
            f.sack_permitted = src.sack_permitted;
            f.nop_count      = src.nop_count;
            f.os_guess       = src.os_guess;
            result.push_back(std::move(f));
        }
        return result;
    }

    bool export_pcap(uint32_t filter_pid, uint32_t filter_protocol, uint32_t max_packets, pcap_export_result_t* out)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("export_pcap");
            return false;
        }

        voyager::device_t::pcap_export_result raw{};
        bool ok = device->export_pcap(filter_pid, filter_protocol, max_packets, out ? &raw : nullptr);
        if (ok && out) {
            out->header.magic_number  = raw.header.magic_number;
            out->header.version_major = raw.header.version_major;
            out->header.version_minor = raw.header.version_minor;
            out->header.thiszone      = raw.header.thiszone;
            out->header.sigfigs       = raw.header.sigfigs;
            out->header.snaplen       = raw.header.snaplen;
            out->header.network       = raw.header.network;
            out->packets.reserve(raw.packets.size());
            for (auto& src : raw.packets) {
                pcap_packet_t p;
                p.ts_sec  = src.ts_sec;
                p.ts_usec = src.ts_usec;
                p.data    = std::move(src.data);
                out->packets.push_back(std::move(p));
            }
        }
        return ok;
    }
}
