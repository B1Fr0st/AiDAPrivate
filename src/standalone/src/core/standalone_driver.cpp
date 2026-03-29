

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "standalone_driver.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <memory>
#include <mutex>


#define __pro_h
#define __kernwin_hpp

#ifndef OBFSTR
#define OBFSTR(s) s
#endif


static driver_bridge::log_fn_t     g_log_fn;
static driver_bridge::confirm_fn_t g_confirm_fn;
static std::mutex                  g_callback_mtx;


static void msg(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    OutputDebugStringA(buf);

    std::lock_guard<std::mutex> lk(g_callback_mtx);
    if (g_log_fn) g_log_fn(buf);
}


static int qvsnprintf(char* buf, size_t size, const char* fmt, va_list ap)
{
    return vsnprintf(buf, size, fmt, ap);
}


#define ASKBTN_NO   0
#define ASKBTN_YES  1
static int ask_yn(int , const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lk(g_callback_mtx);
    if (g_confirm_fn) {
        return g_confirm_fn(buf) ? ASKBTN_YES : ASKBTN_NO;
    }

    return ASKBTN_NO;
}


#include "../../../../driver/comm.h"


#define __NT__
#include "../../../../src/driver_loader.hpp"
#include "../../../../src/driver_loader.cpp"


extern std::unique_ptr<voyager::device_t> device;

void driver_bridge::set_log_callback(log_fn_t fn)
{
    std::lock_guard<std::mutex> lk(g_callback_mtx);
    g_log_fn = std::move(fn);
}

void driver_bridge::set_confirm_callback(confirm_fn_t fn)
{
    std::lock_guard<std::mutex> lk(g_callback_mtx);
    g_confirm_fn = std::move(fn);
}

bool driver_bridge::initialize()
{


    return driver_loader::initialize_and_load();
}

bool driver_bridge::is_loaded()
{
    return driver_loader::is_driver_loaded();
}

bool driver_bridge::attach(uint32_t pid)
{
    if (!is_loaded()) {
        msg("AiDA Standalone: Driver not loaded.\n");
        return false;
    }


    if (!device)
        device = std::make_unique<voyager::device_t>();

    if (!device->is_connected()) {
        if (!device->connect()) {
            msg("AiDA Standalone: Failed to connect to driver.\n");
            return false;
        }
    }


    device->set_process_id(pid);
    device->clear_process_context();


    uint64_t base = device->find_image();
    if (base == 0) {
        msg("AiDA Standalone: Failed to find process image base for PID %u.\n", pid);
        return false;
    }
    device->set_base_address(base);


    device->solve_dtb();

    msg("AiDA Standalone: Attached to PID %u (base=0x%llX, dtb=0x%llX).\n",
        pid, base, device->get_dtb());
    return true;
}

void driver_bridge::detach()
{
    if (device) {
        device->clear_process_context();
        msg("AiDA Standalone: Detached from process.\n");
    }
}

std::string driver_bridge::status()
{
    if (!is_loaded())
        return "Driver: Not loaded";

    if (!device || !device->is_connected())
        return "Driver: Loaded (not connected)";

    uint32_t pid = device->get_process_id();
    if (pid == 0)
        return "Driver: Connected (no process attached)";

    char buf[256];
    snprintf(buf, sizeof(buf),
        "Driver: Attached to PID %u | Base=0x%llX | DTB=0x%llX",
        pid,
        (unsigned long long)device->get_base_address(),
        (unsigned long long)device->get_dtb());
    return buf;
}

uint32_t driver_bridge::attached_pid()
{
    if (device && device->is_connected())
        return device->get_process_id();
    return 0;
}

std::vector<driver_bridge::process_info_t> driver_bridge::enumerate_processes()
{
    std::vector<process_info_t> result;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return result;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            process_info_t info;
            info.pid = pe.th32ProcessID;

            char narrow[260] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                narrow, sizeof(narrow), nullptr, nullptr);
            info.name = narrow;
            result.push_back(std::move(info));
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}
