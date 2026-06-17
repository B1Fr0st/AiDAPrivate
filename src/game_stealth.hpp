#pragma once

#ifdef __NT__

#include <windows.h>

#include <kernwin.hpp>

namespace game_stealth {

namespace {

static constexpr wchar_t kSpoofTitle[] = L"Untitled - Notepad";

static qtimer_t g_timer{nullptr};
static HWND     g_hwnd{nullptr};
static wchar_t  g_real_title[512]{};

struct find_hwnd_ctx_t { DWORD pid; HWND result; };

static BOOL CALLBACK find_main_hwnd_cb(HWND hwnd, LPARAM lp)
{
    if (!IsWindowVisible(hwnd))
        return TRUE;
    if (GetWindow(hwnd, GW_OWNER) != nullptr)
        return TRUE;

    auto* ctx = reinterpret_cast<find_hwnd_ctx_t*>(lp);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid)
        return TRUE;

    wchar_t title[2] = {};
    GetWindowTextW(hwnd, title, 2);
    if (title[0] == L'\0')
        return TRUE;

    ctx->result = hwnd;
    return FALSE;
}

static HWND find_ida_main_window()
{
    find_hwnd_ctx_t ctx{ GetCurrentProcessId(), nullptr };
    EnumWindows(find_main_hwnd_cb, reinterpret_cast<LPARAM>(&ctx));
    return ctx.result;
}

static void spoof_now(HWND hwnd)
{
    wchar_t current[512] = {};
    GetWindowTextW(hwnd, current, 512);
    if (wcscmp(current, kSpoofTitle) != 0)
    {
        wcscpy_s(g_real_title, current);
        SetWindowTextW(hwnd, kSpoofTitle);
    }
}

static int idaapi stealth_tick(void*)
{
    if (g_hwnd == nullptr)
        g_hwnd = find_ida_main_window();
    if (g_hwnd != nullptr && IsWindow(g_hwnd))
        spoof_now(g_hwnd);
    return 2000;
}

} // namespace

inline void install()
{
    g_hwnd = find_ida_main_window();
    if (g_hwnd != nullptr)
        spoof_now(g_hwnd);
    g_timer = register_timer(2000, stealth_tick, nullptr);
}

inline void shutdown()
{
    if (g_timer != nullptr)
    {
        unregister_timer(g_timer);
        g_timer = nullptr;
    }

    if (g_hwnd != nullptr && IsWindow(g_hwnd))
        SetWindowTextW(g_hwnd, g_real_title[0] ? g_real_title : L"IDA");

    g_hwnd = nullptr;
}

} // namespace game_stealth

#endif // __NT__
