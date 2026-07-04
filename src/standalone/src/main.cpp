#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/freetype/freetype.h"
#include "verdana.h"
#include "ide_icons.h"
#include <d3d11.h>
#include <tchar.h>
#include <windowsx.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <algorithm>
#include "helpers/helpers.h"
#include "helpers/blur.h"
#include <dwmapi.h>
#include <shellscalingapi.h>
#include "helpers/globals.h"
#include "core/ui/clock.hpp"
#include "core/ui/motion.hpp"
#include "core/ui/transition.hpp"
#include "core/ui/theme.hpp"
#include "core/ui/blur_layer.hpp"
#include "core/ui/components.hpp"
#include "core/ui/fonts.hpp"
#include "standalone_chat.hpp"
#include "standalone_license.hpp"
#include "standalone_settings.hpp"
#include "standalone_driver.hpp"
#include "standalone_tools_fwd.hpp"
#include "core/runtime/arc_loader.hpp"
#include "core/runtime/diagnostic_exception_scope.hpp"
#include "core/runtime/manual_map_tls.hpp"
#include "core/anti-tamper/orchestrator.hpp"
#include "core/anti-tamper/hv_preflight.hpp"
#include "core/anti-tamper/mcp_posture.hpp"
#include "core/anti-tamper/enforcement.hpp"
#include "core/runtime/reason_ids.hpp"
#include "network_view.hpp"
#include "memory_scanner.hpp"
#include "mitm_proxy.hpp"
#include "script_engine.hpp"
#include "toast_notification.hpp"
#include "source_reconstruct_view.hpp"
#include "command_palette_view.hpp"
#include "agent_picker_view.hpp"
#include "settings_overlay.hpp"
#include "work_queue.hpp"
#include "critical_work_queue.hpp"
#include "core/session/session_health.hpp"
#include "core/testlab/test_all_features.hpp"
#include "core/network/burp/camoufox_bridge.hpp"
#include "helpers/stb_image.h"
#include <dxgi1_3.h>

#include "embedded_resources.hpp"
#include "helpers/diag_log.hpp"
#include "hardware_id/hardware_id_v2.hpp"
#include "core/anti-tamper/cff.hpp"
#include "core/anti-tamper/virtualizer.hpp"
#include "core/disasm/function_index.hpp"
#include "core/analysis/pdb_parser.hpp"
#include "core/auth/auth_http.hpp"
#include "core/ui/loading_binary_overlay.hpp"
#include <shellapi.h>
#include <shobjidl.h>
#include <dbghelp.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dbghelp.lib")

extern "C" {
#include <openssl/applink.c>
}

namespace test_all_features {
    void format_ui_phase_snapshot(char* out, std::size_t cap);
}

#include <thread>
#include <cstdarg>
#include <set>
#include <atomic>
#include <exception>
#include <functional>
#include <cwchar>
#include <cstring>
#include <cstdint>
#include <sstream>
#include <string>
#if defined(_M_X64)
#include <intrin.h>
#endif

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "Shcore.lib")

namespace aida_early_startup {

static constexpr DWORD kMaxLogBytes = 1024u * 1024u;
static std::atomic<const char*> g_phase{ "image_static_init_pending" };
static std::atomic<bool> g_veh_installed{ false };
static std::atomic<bool> g_fatal_exception_written{ false };
static std::atomic<bool> g_status_exception_written{ false };
static std::atomic<bool> g_unhandled_exception_written{ false };
static std::atomic<bool> g_normal_diagnostics_reached{ false };
static std::atomic<long> g_write_active{ 0 };

static size_t bounded_strlen(const char* s, size_t cap)
{
    if (!s)
        return 0;
    size_t n = 0;
    while (n < cap && s[n] != '\0')
        ++n;
    return n;
}

static size_t bounded_wcslen(const wchar_t* s, size_t cap)
{
    if (!s)
        return 0;
    size_t n = 0;
    while (n < cap && s[n] != L'\0')
        ++n;
    return n;
}

static uint64_t fnv1a_wide(const wchar_t* s, size_t cap)
{
    uint64_t h = 14695981039346656037ULL;
    if (!s)
        return h;
    for (size_t i = 0; i < cap && s[i] != L'\0'; ++i) {
        wchar_t ch = s[i];
        h ^= static_cast<uint8_t>(ch & 0xFFu);
        h *= 1099511628211ULL;
        h ^= static_cast<uint8_t>((ch >> 8) & 0xFFu);
        h *= 1099511628211ULL;
    }
    return h;
}

static void wide_to_utf8(const wchar_t* in, char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;
    int wrote = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, in, -1, out, static_cast<int>(cap), nullptr, nullptr);
    if (wrote <= 0)
        wrote = WideCharToMultiByte(CP_ACP, 0, in, -1, out, static_cast<int>(cap), nullptr, nullptr);
    if (wrote <= 0)
        _snprintf_s(out, cap, _TRUNCATE, "<wide_conversion_failed_gle_%lu>", GetLastError());
}

static bool build_exe_log_path(wchar_t* out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = L'\0';
    wchar_t exe[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return false;
    wchar_t* last = wcsrchr(exe, L'\\');
    if (!last)
        return false;
    *(last + 1) = L'\0';
    _snwprintf_s(out, cap, _TRUNCATE, L"%saida_early_startup.log", exe);
    return out[0] != L'\0';
}

static bool append_file(const wchar_t* path, const char* line)
{
    if (!path || !line)
        return false;
    size_t len = bounded_strlen(line, 8192);
    if (len == 0)
        return false;
    DWORD creation = OPEN_ALWAYS;
    WIN32_FILE_ATTRIBUTE_DATA existing{};
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &existing)) {
        ULARGE_INTEGER size{};
        size.LowPart = existing.nFileSizeLow;
        size.HighPart = existing.nFileSizeHigh;
        if (size.QuadPart > kMaxLogBytes)
            creation = CREATE_ALWAYS;
    }
    HANDLE h = CreateFileW(path,
        FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        creation,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, line, static_cast<DWORD>(len), &written, nullptr);
    FlushFileBuffers(h);
    CloseHandle(h);
    return ok && written == static_cast<DWORD>(len);
}

static size_t image_size_from_headers(HMODULE image)
{
    if (!image)
        return 0;
    __try {
        auto* base = reinterpret_cast<const uint8_t*>(image);
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000)
            return 0;
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return 0;
        return static_cast<size_t>(nt->OptionalHeader.SizeOfImage);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static void token_elevation_and_session(int& elevated, DWORD& session, int& session_ok)
{
    elevated = -1;
    session = 0xFFFFFFFFu;
    session_ok = 0;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{};
        DWORD cb = 0;
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &cb))
            elevated = te.TokenIsElevated ? 1 : 0;
        CloseHandle(token);
    }
    DWORD sid = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sid)) {
        session = sid;
        session_ok = 1;
    }
}

static void write_line(const char* event_name, const char* detail)
{
    if (g_write_active.exchange(1, std::memory_order_acq_rel) != 0)
        return;

    wchar_t exe[MAX_PATH] = {};
    wchar_t cwd[MAX_PATH] = {};
    DWORD exe_len = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    DWORD exe_gle = exe_len ? 0 : GetLastError();
    DWORD cwd_len = GetCurrentDirectoryW(MAX_PATH, cwd);
    DWORD cwd_gle = (cwd_len > 0 && cwd_len < MAX_PATH) ? 0 : GetLastError();
    const wchar_t* cmd = GetCommandLineW();
    const size_t cmd_len = bounded_wcslen(cmd, 32768);
    const uint64_t cmd_hash = fnv1a_wide(cmd, 32768);
    int elevated = -1;
    DWORD session = 0xFFFFFFFFu;
    int session_ok = 0;
    token_elevation_and_session(elevated, session, session_ok);

    HMODULE image = GetModuleHandleW(nullptr);
    const uintptr_t image_base = reinterpret_cast<uintptr_t>(image);
    const size_t image_size = image_size_from_headers(image);
    const uintptr_t image_end = image_base + image_size;
    MEMORY_BASIC_INFORMATION mbi{};
    if (image)
        VirtualQuery(image, &mbi, sizeof(mbi));

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    BOOL fad_ok = exe_len > 0 && exe_len < MAX_PATH
        ? GetFileAttributesExW(exe, GetFileExInfoStandard, &fad)
        : FALSE;

    char exe_u8[1024] = {};
    char cwd_u8[1024] = {};
    wide_to_utf8(exe, exe_u8, sizeof(exe_u8));
    wide_to_utf8(cwd, cwd_u8, sizeof(cwd_u8));

    SYSTEMTIME st{};
    GetLocalTime(&st);
    const char* phase = g_phase.load(std::memory_order_acquire);
    const bool normal_diag = g_normal_diagnostics_reached.load(std::memory_order_acquire);
    char line[8192] = {};
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u] [early_startup] event=%s phase=%s detail=%s normal_diag=%d pid=%lu tid=%lu tick=%llu exe_len=%lu exe_gle=%lu exe=%s module=%s cwd_len=%lu cwd_gle=%lu cwd=%s cmd_len=%llu cmd_hash=0x%016llX elevated=%d session=%lu session_ok=%d image_base=0x%016llX image_end=0x%016llX image_size=0x%llX mbi_base=0x%016llX mbi_alloc=0x%016llX mbi_size=0x%llX mbi_state=0x%08lX mbi_protect=0x%08lX exe_write_ok=%d exe_write_ft=0x%08lX%08lX build=%s_%s\r\n",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds,
        event_name ? event_name : "<null>",
        phase ? phase : "<null>",
        detail ? detail : "<null>",
        normal_diag ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        static_cast<unsigned long>(exe_len),
        static_cast<unsigned long>(exe_gle),
        exe_u8,
        exe_u8,
        static_cast<unsigned long>(cwd_len),
        static_cast<unsigned long>(cwd_gle),
        cwd_u8,
        static_cast<unsigned long long>(cmd_len),
        static_cast<unsigned long long>(cmd_hash),
        elevated,
        static_cast<unsigned long>(session),
        session_ok,
        static_cast<unsigned long long>(image_base),
        static_cast<unsigned long long>(image_end),
        static_cast<unsigned long long>(image_size),
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mbi.BaseAddress)),
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mbi.AllocationBase)),
        static_cast<unsigned long long>(mbi.RegionSize),
        static_cast<unsigned long>(mbi.State),
        static_cast<unsigned long>(mbi.Protect),
        fad_ok ? 1 : 0,
        fad_ok ? fad.ftLastWriteTime.dwHighDateTime : 0,
        fad_ok ? fad.ftLastWriteTime.dwLowDateTime : 0,
        __DATE__,
        __TIME__);

    wchar_t path[MAX_PATH] = {};
    if (build_exe_log_path(path, _countof(path)))
        append_file(path, line);

    g_write_active.store(0, std::memory_order_release);
}

static bool is_fatal_exception_code(DWORD code)
{
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_INVALID_DISPOSITION:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
        return true;
    default:
        return code == 0xC0000409u || code == 0x40000015u;
    }
}

static bool is_status_exception_code(DWORD code)
{
    return code == STATUS_SINGLE_STEP || code == EXCEPTION_BREAKPOINT || code == STATUS_GUARD_PAGE_VIOLATION;
}

static void write_exception_line(const char* handler, EXCEPTION_POINTERS* ep, bool allow_all)
{
    if (!ep || !ep->ExceptionRecord)
        return;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const bool fatal = is_fatal_exception_code(code);
    const bool status = is_status_exception_code(code);
    if (!allow_all && !fatal && !status)
        return;
    std::atomic<bool>* gate = allow_all ? &g_unhandled_exception_written : (fatal ? &g_fatal_exception_written : &g_status_exception_written);
    bool expected = false;
    if (!gate->compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    CONTEXT* ctx = ep->ContextRecord;
    uintptr_t rip = 0;
    uintptr_t rsp = 0;
    uintptr_t rbp = 0;
#if defined(_M_X64)
    if (ctx) {
        rip = static_cast<uintptr_t>(ctx->Rip);
        rsp = static_cast<uintptr_t>(ctx->Rsp);
        rbp = static_cast<uintptr_t>(ctx->Rbp);
    }
#endif
    const uintptr_t addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    HMODULE crash_mod = nullptr;
    wchar_t crash_mod_w[MAX_PATH] = L"<unknown>";
    char crash_mod_u8[1024] = "<unknown>";
    if (ep->ExceptionRecord->ExceptionAddress &&
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(ep->ExceptionRecord->ExceptionAddress),
            &crash_mod) &&
        crash_mod) {
        GetModuleFileNameW(crash_mod, crash_mod_w, MAX_PATH);
        wide_to_utf8(crash_mod_w, crash_mod_u8, sizeof(crash_mod_u8));
    }
    const uintptr_t crash_mod_base = reinterpret_cast<uintptr_t>(crash_mod);
    const uintptr_t module_off = crash_mod_base && addr >= crash_mod_base ? addr - crash_mod_base : 0;
    const unsigned long params = static_cast<unsigned long>(ep->ExceptionRecord->NumberParameters);
    const unsigned long long p0 = ep->ExceptionRecord->NumberParameters > 0
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[0])
        : 0ULL;
    const unsigned long long p1 = ep->ExceptionRecord->NumberParameters > 1
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[1])
        : 0ULL;
    char detail[1024] = {};
    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
        "handler=%s exception code=0x%08lX fatal=%d status=%d flags=0x%08lX addr=0x%016llX rip=0x%016llX rsp=0x%016llX rbp=0x%016llX module=%s module_off=0x%llX params=%lu p0=0x%016llX p1=0x%016llX last_error=%lu",
        handler ? handler : "<null>",
        static_cast<unsigned long>(code),
        fatal ? 1 : 0,
        status ? 1 : 0,
        static_cast<unsigned long>(ep->ExceptionRecord->ExceptionFlags),
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long long>(rip),
        static_cast<unsigned long long>(rsp),
        static_cast<unsigned long long>(rbp),
        crash_mod_u8,
        static_cast<unsigned long long>(module_off),
        params,
        p0,
        p1,
        GetLastError());
    write_line(allow_all ? "unhandled_exception" : (fatal ? "veh_first_chance_fatal_exception" : "veh_first_chance_status_exception"), detail);
}

static LONG CALLBACK early_veh(EXCEPTION_POINTERS* ep)
{
    write_exception_line("early_veh", ep, false);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI early_unhandled(EXCEPTION_POINTERS* ep)
{
    write_exception_line("early_unhandled", ep, true);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void install()
{
    bool expected = false;
    PVOID veh = nullptr;
    bool added_veh = g_veh_installed.compare_exchange_strong(expected, true, std::memory_order_acq_rel);
    if (added_veh)
        veh = AddVectoredExceptionHandler(1, early_veh);
    SetUnhandledExceptionFilter(early_unhandled);
    char detail[160] = {};
    _snprintf_s(detail, sizeof(detail), _TRUNCATE, "early_veh=0x%016llX early_veh_added=%d unhandled_set=1 gle=%lu", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(veh)), added_veh ? 1 : 0, GetLastError());
    write_line("install", detail);
}

static void mark(const char* phase)
{
    g_phase.store(phase ? phase : "<null>", std::memory_order_release);
    write_line("phase", phase ? phase : "<null>");
}

static void mark_normal_diagnostics_reached()
{
    g_normal_diagnostics_reached.store(true, std::memory_order_release);
    mark("normal_diag_reached");
}

struct bootstrap_t {
    bootstrap_t()
    {
        g_phase.store("static_ctor_enter", std::memory_order_release);
        install();
        mark("static_ctor_exit");
    }
};

static bootstrap_t g_bootstrap;

}

ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static HANDLE                   g_FrameLatencyWaitableObject = nullptr;
static UINT                     g_SwapChainResizeFlags = 0;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static ID3D11BlendState* blend_state = nullptr;
static HICON g_aidaWindowIcon = nullptr;

helpers helper;
HWND g_hwnd = nullptr;
static constexpr const wchar_t* kAidaWindowTitle = L"AiDA Standalone";
static constexpr int kAidaFullTestHotkeyId = 0xA1DA;
static constexpr UINT kAidaQueuedPeekFlags = PM_REMOVE | PM_QS_INPUT | PM_QS_POSTMESSAGE | PM_QS_PAINT | PM_QS_SENDMESSAGE;
static constexpr UINT kAidaSendOnlyPeekFlags = PM_REMOVE | PM_QS_SENDMESSAGE;
static constexpr DWORD kAidaNonSendQueueBits = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY | QS_ALLPOSTMESSAGE;
static constexpr DWORD kAidaPumpQueueBits = kAidaNonSendQueueBits | QS_SENDMESSAGE;
static constexpr DWORD kAidaInteractiveQueueBits = QS_INPUT | QS_POSTMESSAGE | QS_HOTKEY | QS_ALLPOSTMESSAGE;
static constexpr UINT kAidaPresentSyncInterval = 1;
static constexpr UINT kAidaPresentFlags = 0;
static constexpr DWORD kAidaInteractiveWaitMs = 1;
static constexpr DWORD kAidaForegroundActiveWaitMs = 8;
static constexpr DWORD kAidaForegroundIdleWaitMs = 24;
static constexpr DWORD kAidaBackgroundActiveWaitMs = 16;
static constexpr DWORD kAidaBackgroundIdleWaitMs = 75;
static constexpr DWORD kAidaPreRenderWaitMs = 16;
static constexpr uint64_t kAidaRecentInputWakeMs = 100ULL;
static constexpr DWORD kAidaResizeCoalesceMs = 16;
static constexpr uint64_t kAidaResizeChurnWindowMs = 1000ULL;
static constexpr uint32_t kAidaResizeChurnThreshold = 4;
static constexpr uint64_t kAidaRuntimeAcceptanceLogIntervalMs = 30000ULL;
static constexpr uint64_t kAidaForegroundIdleHeartbeatMs = 250ULL;
static constexpr uint64_t kAidaBackgroundIdleHeartbeatMs = 1000ULL;
static constexpr uint64_t kAidaFullTestHeartbeatMs = 250ULL;
static constexpr uint64_t kAidaModalHeartbeatMs = 16ULL;
static constexpr uint64_t kAidaFramePacingLogIntervalMs = 10000ULL;
static constexpr uint32_t kAidaDirtyStartup = 0x00000001u;
static constexpr uint32_t kAidaDirtyMessage = 0x00000002u;
static constexpr uint32_t kAidaDirtyResize = 0x00000004u;
static constexpr uint32_t kAidaDirtyState = 0x00000008u;
static constexpr uint32_t kAidaDirtyInput = 0x00000010u;
static constexpr uint32_t kAidaDirtyCursor = 0x00000020u;
static constexpr uint32_t kAidaDirtyOverlay = 0x00000040u;
static constexpr uint32_t kAidaDirtyTheme = 0x00000080u;
static constexpr uint32_t kAidaDirtyModal = 0x00000100u;
static constexpr uint32_t kAidaDirtyProgress = 0x00000200u;
static constexpr uint32_t kAidaDirtyHeartbeat = 0x00000400u;
static constexpr uint32_t kAidaDirtyWork = 0x00000800u;
static constexpr uint32_t kAidaDirtySecurity = 0x00001000u;
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

inline int prev_w = 0;
inline int prev_h = 0;
static uint64_t g_ResizeRequestTickMs = 0;

struct resize_perf_state_t {
    uint64_t requests = 0;
    uint64_t applied = 0;
    uint64_t skipped_redundant = 0;
    uint64_t coalesced = 0;
    uint64_t render_target_recreates = 0;
    uint64_t blur_resize_calls = 0;
    uint64_t churn_window_start_ms = 0;
    uint32_t churn_window_recreates = 0;
    uint64_t last_churn_log_ms = 0;
    int blur_w = 0;
    int blur_h = 0;
};

static resize_perf_state_t g_resize_perf;

struct gpu_frame_sample_t {
    bool available = false;
    bool valid = false;
    bool disjoint = false;
    bool pending = false;
    HRESULT data_hr = S_FALSE;
    HRESULT create_hr = S_OK;
    uint64_t frame = 0;
    uint64_t ready_frame = 0;
    uint64_t frequency = 0;
    uint64_t begin = 0;
    uint64_t end = 0;
    double gpu_ms = 0.0;
    uint64_t samples = 0;
    uint64_t misses = 0;
};

struct gpu_frame_query_state_t {
    ID3D11Query* disjoint = nullptr;
    ID3D11Query* begin = nullptr;
    ID3D11Query* end = nullptr;
    bool active = false;
    bool pending = false;
    uint64_t active_frame = 0;
    uint64_t pending_frame = 0;
    HRESULT create_hr = S_OK;
    uint64_t samples = 0;
    uint64_t misses = 0;
    gpu_frame_sample_t last;
};

static gpu_frame_query_state_t g_gpu_frame_query;

ImFont* g_font_ui_400 = nullptr;
ImFont* g_font_ui_500 = nullptr;
ImFont* g_font_ui_600 = nullptr;
ImFont* g_font_ui_700 = nullptr;
ImFont* g_font_ui_400_lg = nullptr;
ImFont* g_font_ui_500_sm = nullptr;
ImFont* g_font_ui_700_xl = nullptr;
ImFont* g_font_code_400 = nullptr;
ImFont* g_font_code_600 = nullptr;
ImFont* g_font_code_400_lg = nullptr;

static bool font_file_exists(const std::string& path)
{
    DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static std::string repo_fonts_dir()
{
    char exe[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    std::string s = exe;
    size_t cut = s.find_last_of('\\');
    if (cut != std::string::npos) s = s.substr(0, cut);
    return s + "\\fonts";
}

static std::string user_fonts_dir()
{
    char appdata[MAX_PATH] = {};
    if (!GetEnvironmentVariableA("LOCALAPPDATA", appdata, MAX_PATH))
        return {};
    return std::string(appdata) + "\\Microsoft\\Windows\\Fonts";
}

static std::string sys_fonts_dir()
{
    char win_dir[MAX_PATH] = {};
    GetWindowsDirectoryA(win_dir, MAX_PATH);
    return std::string(win_dir) + "\\Fonts";
}

static ImFont* load_font_with_fallbacks(ImGuiIO& io,
                                         const char* embed_data, size_t embed_size,
                                         const std::vector<std::string>& candidate_paths,
                                         float pixel_size,
                                         const ImFontConfig& cfg_in)
{
    diag::log_tagged_critical_fmt("fonts",
        "load_font_enter px=%.2f candidates=%zu embed_size=%zu atlas=0x%llX",
        pixel_size,
        candidate_paths.size(),
        embed_size,
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)));
    ImFontConfig cfg = cfg_in;
    cfg.FontDataOwnedByAtlas = true;
    for (const auto& p : candidate_paths) {
        if (font_file_exists(p)) {
            const char* leaf = p.c_str();
            const char* slash = std::strrchr(leaf, '\\');
            if (slash) leaf = slash + 1;
            diag::log_tagged_critical_fmt("fonts",
                "load_font_file_pre leaf=%.120s path_len=%zu px=%.2f",
                leaf,
                p.size(),
                pixel_size);
            ImFont* f = io.Fonts->AddFontFromFileTTF(p.c_str(), pixel_size, &cfg);
            diag::log_tagged_critical_fmt("fonts",
                "load_font_file_post leaf=%.120s font=0x%llX atlas_count=%d",
                leaf,
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(f)),
                io.Fonts ? io.Fonts->Fonts.Size : -1);
            if (f) return f;
        }
    }
    if (embed_data && embed_size > 0) {
        diag::log_tagged_critical_fmt("fonts",
            "load_font_embed_alloc_pre bytes=%zu px=%.2f",
            embed_size,
            pixel_size);
        void* copy = IM_ALLOC(embed_size);
        diag::log_tagged_critical_fmt("fonts",
            "load_font_embed_alloc_post ptr=0x%llX bytes=%zu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(copy)),
            embed_size);
        if (!copy) return nullptr;
        memcpy(copy, embed_data, embed_size);
        ImFont* f = io.Fonts->AddFontFromMemoryTTF(copy, (int)embed_size, pixel_size, &cfg);
        diag::log_tagged_critical_fmt("fonts",
            "load_font_embed_post font=0x%llX atlas_count=%d",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(f)),
            io.Fonts ? io.Fonts->Fonts.Size : -1);
        return f;
    }
    diag::log_tagged_critical_fmt("fonts", "load_font_none px=%.2f", pixel_size);
    return nullptr;
}

static void merge_icon_font(ImGuiIO& io, float pixel_size)
{
    diag::log_tagged_critical_fmt("fonts",
        "merge_icon_enter px=%.2f icon_bytes=%u atlas=0x%llX count=%d",
        pixel_size,
        ide_icon_font_size,
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)),
        io.Fonts ? io.Fonts->Fonts.Size : -1);
    static const ImWchar icon_ranges[] = { ICON_MIN_IDE, ICON_MAX_IDE, 0 };
    ImFontConfig icon_cfg{};
    icon_cfg.MergeMode = true;
    icon_cfg.PixelSnapH = true;
    icon_cfg.GlyphMinAdvanceX = pixel_size * 0.92f;
    icon_cfg.GlyphOffset = ImVec2(0.f, pixel_size * 0.05f);
    icon_cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    diag::log_tagged_critical_fmt("fonts",
        "merge_icon_config builder_flags=0x%X",
        icon_cfg.FontBuilderFlags);
    void* icon_data_copy = IM_ALLOC(ide_icon_font_size);
    diag::log_tagged_critical_fmt("fonts",
        "merge_icon_alloc_post ptr=0x%llX bytes=%u",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(icon_data_copy)),
        ide_icon_font_size);
    if (!icon_data_copy) return;
    memcpy(icon_data_copy, ide_icon_font_data, ide_icon_font_size);
    ImFont* merged = io.Fonts->AddFontFromMemoryTTF(icon_data_copy, ide_icon_font_size, pixel_size, &icon_cfg, icon_ranges);
    diag::log_tagged_critical_fmt("fonts",
        "merge_icon_post font=0x%llX atlas_count=%d",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(merged)),
        io.Fonts ? io.Fonts->Fonts.Size : -1);
}

static void rebuild_fonts(float dpi_scale)
{
    ImGuiIO& io = ImGui::GetIO();
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_enter dpi_scale=%.3f ctx=0x%llX atlas=0x%llX count=%d builder_before=0x%llX flags_before=0x%X",
        dpi_scale,
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ImGui::GetCurrentContext())),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)),
        io.Fonts ? io.Fonts->Fonts.Size : -1,
        io.Fonts ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->FontBuilderIO)) : 0ULL,
        io.Fonts ? io.Fonts->FontBuilderFlags : 0U);
    io.Fonts->Clear();
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_clear_post atlas=0x%llX count=%d builder=0x%llX flags=0x%X",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)),
        io.Fonts ? io.Fonts->Fonts.Size : -1,
        io.Fonts ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->FontBuilderIO)) : 0ULL,
        io.Fonts ? io.Fonts->FontBuilderFlags : 0U);

    const auto font_policy = aida::ui::fonts::policy_for_dpi(dpi_scale);
    const float screen_factor = 1.0f;
    const float texture_scale = font_policy.scale;
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_scale screen_factor=%.3f texture_scale=%.3f body=%.2f caption=%.2f code=%.2f",
        screen_factor,
        texture_scale,
        font_policy.body_px,
        font_policy.caption_px,
        font_policy.code_px);
    const float base = font_policy.body_px;
    const float lg   = font_policy.large_px;
    const float sm   = font_policy.caption_px;
    const float xl   = font_policy.display_px;
    const float code = font_policy.code_px;
    const float code_lg = font_policy.code_large_px;
    io.FontGlobalScale = 1.0f;

    const bool enable_lcd = font_policy.enable_lcd;
    constexpr unsigned int lcd_flag_value = 1u << 10;

    auto cfg_ui_smooth = [&](float multiply) {
        ImFontConfig c{};
        c.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_NoHinting;
        if (enable_lcd) c.FontBuilderFlags |= lcd_flag_value;
        c.PixelSnapH = false;
        c.OversampleH = 3;
        c.OversampleV = 1;
        c.RasterizerMultiply = multiply;
        return c;
    };
    auto cfg_ui_hinted = [&](float multiply) {
        ImFontConfig c{};
        c.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
        if (enable_lcd) c.FontBuilderFlags |= lcd_flag_value;
        c.PixelSnapH = false;
        c.OversampleH = 3;
        c.OversampleV = 1;
        c.RasterizerMultiply = multiply;
        return c;
    };
    auto cfg_mono = [&](float multiply) {
        ImFontConfig c{};
        c.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
        c.PixelSnapH = true;
        c.OversampleH = 2;
        c.OversampleV = 1;
        c.RasterizerMultiply = multiply;
        return c;
    };
    auto cfg_caption = [&](float multiply) {
        ImFontConfig c = cfg_ui_hinted(multiply);
        c.PixelSnapH = true;
        c.OversampleH = 2;
        return c;
    };

    const std::string repo_dir = repo_fonts_dir();
    const std::string user_dir = user_fonts_dir();
    const std::string sys_dir  = sys_fonts_dir();
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_dirs repo_len=%zu user_len=%zu sys_len=%zu",
        repo_dir.size(),
        user_dir.size(),
        sys_dir.size());

    auto inter_paths = [&](const char* fname) -> std::vector<std::string> {
        std::vector<std::string> v;
        v.push_back(repo_dir + "\\" + fname);
        v.push_back(repo_dir + "\\inter\\" + fname);
        if (!user_dir.empty()) v.push_back(user_dir + "\\" + fname);
        v.push_back(sys_dir + "\\" + fname);
        return v;
    };
    auto seguivar      = sys_dir + "\\seguivar.ttf";
    auto segoe_var_alt = sys_dir + "\\SegoeUIVariable.ttf";
    auto segoe_ui      = sys_dir + "\\segoeui.ttf";
    auto segoe_uib     = sys_dir + "\\segoeuib.ttf";
    auto segoe_uisl    = sys_dir + "\\segoeuisl.ttf";

    auto inter_400 = inter_paths("Inter-Regular.ttf");
    inter_400.push_back(seguivar); inter_400.push_back(segoe_var_alt);
    inter_400.push_back(segoe_uisl); inter_400.push_back(segoe_ui);

    auto inter_500 = inter_paths("Inter-Medium.ttf");
    inter_500.push_back(seguivar); inter_500.push_back(segoe_var_alt); inter_500.push_back(segoe_ui);

    auto inter_600 = inter_paths("Inter-SemiBold.ttf");
    inter_600.push_back(seguivar); inter_600.push_back(segoe_var_alt); inter_600.push_back(segoe_uib); inter_600.push_back(segoe_ui);

    auto inter_700 = inter_paths("Inter-Bold.ttf");
    inter_700.push_back(seguivar); inter_700.push_back(segoe_var_alt); inter_700.push_back(segoe_uib); inter_700.push_back(segoe_ui);

    auto jbm_paths = [&](const char* fname) -> std::vector<std::string> {
        std::vector<std::string> v;
        v.push_back(repo_dir + "\\" + fname);
        v.push_back(repo_dir + "\\jetbrains-mono\\" + fname);
        if (!user_dir.empty()) v.push_back(user_dir + "\\" + fname);
        v.push_back(sys_dir + "\\" + fname);
        return v;
    };
    auto cascadia_mono = sys_dir + "\\CascadiaMono.ttf";
    auto cascadia_code = sys_dir + "\\CascadiaCode.ttf";
    auto consolas      = sys_dir + "\\consola.ttf";
    auto consolasb     = sys_dir + "\\consolab.ttf";

    auto jbm_400 = jbm_paths("JetBrainsMono-Regular.ttf");
    jbm_400.push_back(cascadia_mono); jbm_400.push_back(cascadia_code); jbm_400.push_back(consolas);

    auto jbm_600 = jbm_paths("JetBrainsMono-SemiBold.ttf");
    jbm_600.push_back(cascadia_mono); jbm_600.push_back(consolasb); jbm_600.push_back(consolas);

    ImFontConfig c_400 = cfg_ui_hinted(1.08f);
    ImFontConfig c_500 = cfg_ui_hinted(1.08f);
    ImFontConfig c_600 = cfg_ui_hinted(1.05f);
    ImFontConfig c_700 = cfg_ui_hinted(1.05f);
    ImFontConfig c_caption = cfg_caption(1.08f);
    ImFontConfig c_mono = cfg_mono(1.00f);

    g_font_ui_400 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_400, base, c_400);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui400 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_400)));
    merge_icon_font(io, base);
    diag::log_tagged_critical("fonts", "rebuild_fonts_icon_merge_post");

    g_font_ui_500 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_500, base, c_500);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui500 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_500)));
    g_font_ui_600 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_600, base, c_600);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui600 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_600)));
    g_font_ui_700 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_700, base, c_700);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui700 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_700)));
    g_font_ui_400_lg = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_400, lg, c_400);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui400_lg font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_400_lg)));
    g_font_ui_500_sm = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_500, sm, c_caption);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui500_sm font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_500_sm)));
    g_font_ui_700_xl = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_700, xl, c_700);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_ui700_xl font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_700_xl)));

    g_font_code_400 = load_font_with_fallbacks(io, nullptr, 0, jbm_400, code, c_mono);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_code400 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_code_400)));
    g_font_code_600 = load_font_with_fallbacks(io, nullptr, 0, jbm_600, code, c_mono);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_code600 font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_code_600)));
    g_font_code_400_lg = load_font_with_fallbacks(io, nullptr, 0, jbm_400, code_lg, c_mono);
    diag::log_tagged_critical_fmt("fonts", "rebuild_fonts_code400_lg font=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_code_400_lg)));
    if (!g_font_code_400) g_font_code_400 = g_font_ui_400;
    if (!g_font_code_600) g_font_code_600 = g_font_code_400;
    if (!g_font_code_400_lg) g_font_code_400_lg = g_font_code_400;

    g_code_font = g_font_code_400;
    if (!g_font_ui_400) g_font_ui_400 = io.Fonts->Fonts.empty() ? nullptr : io.Fonts->Fonts[0];
    if (!g_font_ui_500) g_font_ui_500 = g_font_ui_400;
    if (!g_font_ui_600) g_font_ui_600 = g_font_ui_400;
    if (!g_font_ui_700) g_font_ui_700 = g_font_ui_400;
    if (!g_font_ui_400_lg) g_font_ui_400_lg = g_font_ui_400;
    if (!g_font_ui_500_sm) g_font_ui_500_sm = g_font_ui_400;
    if (!g_font_ui_700_xl) g_font_ui_700_xl = g_font_ui_700;

    io.FontDefault = g_font_ui_400;
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_build_pre default=0x%llX atlas_count=%d config_count=%d builder=0x%llX flags=0x%X",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.FontDefault)),
        io.Fonts ? io.Fonts->Fonts.Size : -1,
        io.Fonts ? io.Fonts->ConfigData.Size : -1,
        io.Fonts ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->FontBuilderIO)) : 0ULL,
        io.Fonts ? io.Fonts->FontBuilderFlags : 0U);
    io.Fonts->Build();
    diag::log_tagged_critical_fmt("fonts",
        "rebuild_fonts_build_post atlas_count=%d tex_alpha=0x%llX tex_rgba=0x%llX tex_w=%d tex_h=%d use_colors=%d",
        io.Fonts ? io.Fonts->Fonts.Size : -1,
        io.Fonts ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->TexPixelsAlpha8)) : 0ULL,
        io.Fonts ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts->TexPixelsRGBA32)) : 0ULL,
        io.Fonts ? io.Fonts->TexWidth : 0,
        io.Fonts ? io.Fonts->TexHeight : 0,
        (io.Fonts && io.Fonts->TexPixelsUseColors) ? 1 : 0);
    extern bool g_imgui_dx11_initialized;
    if (g_imgui_dx11_initialized) {
        diag::log_tagged_critical("fonts", "rebuild_fonts_dx11_invalidate_pre");
        ImGui_ImplDX11_InvalidateDeviceObjects();
        diag::log_tagged_critical("fonts", "rebuild_fonts_dx11_invalidate_post");
    }
    diag::log_tagged_critical("fonts", "rebuild_fonts_exit");
}

bool g_imgui_dx11_initialized = false;

static DWORD compute_acrylic_color_for_theme()
{
    aida::manual_map_tls::ensure_current_thread();
    const auto& t = aida::ui::resolved();
    return ((DWORD)t.acrylic_color & 0x00FFFFFFu) | (0xFFu << 24);
}

void set_acrylic_color(HWND hwnd)
{
    aida::manual_map_tls::ensure_current_thread();
    struct ACCENT_POLICY { DWORD AccentState; DWORD AccentFlags; DWORD GradientColor; DWORD AnimationId; };
    struct WINCOMPATTRDATA { DWORD Attribute; PVOID pData; ULONG DataSize; };

    auto SetWindowCompositionAttribute = (BOOL(WINAPI*)(HWND, void*))
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetWindowCompositionAttribute");
    aida::manual_map_tls::ensure_current_thread();
    if (!SetWindowCompositionAttribute) return;

    DWORD color = compute_acrylic_color_for_theme();
    ACCENT_POLICY accent = { 3, 2, color, 0 };

    WINCOMPATTRDATA data = { 19, &accent, sizeof(accent) };
    SetWindowCompositionAttribute(hwnd, &data);
    aida::manual_map_tls::ensure_current_thread();
    diag::log_tagged_fmt("ui", "acrylic_set color=0x%08X alpha=0xFF (forced opaque)", color);
}

static bool os_prefers_dark()
{
    HKEY hk;
    LONG ok = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        0, KEY_READ, &hk);
    if (ok != ERROR_SUCCESS) return true;
    DWORD val = 1, sz = sizeof(val), type = 0;
    ok = RegQueryValueExW(hk, L"AppsUseLightTheme", nullptr, &type,
                          reinterpret_cast<BYTE*>(&val), &sz);
    RegCloseKey(hk);
    if (ok != ERROR_SUCCESS) return true;
    return val == 0;
}

static void apply_initial_theme()
{
    aida::manual_map_tls::ensure_current_thread();
    diag::log_tagged_critical_fmt("theme",
        "apply_initial_theme_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida::ui::apply_immediate(aida::ui::detail::make_aida_dark());
    aida::manual_map_tls::ensure_current_thread();
    diag::log_tagged_critical_fmt("theme",
        "apply_initial_theme_exit pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
}

static void apply_os_theme_animated()
{
}

static void crash_log_write(const char* msg)
{
    aida::manual_map_tls::ensure_current_thread();
    diag::log_tagged("main", msg);
}

static void crash_log_fmt(const char* fmt, ...)
{
    aida::manual_map_tls::ensure_current_thread();
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    diag::log_tagged("main", buf);
}

static void startup_log_critical(const char* detail)
{
    aida::manual_map_tls::ensure_current_thread();
    std::string run_id = standalone_license::run_correlation_id();
    char tagged[2300] = {};
    _snprintf_s(tagged, sizeof(tagged), _TRUNCATE,
        "run_id=%s %s",
        run_id.c_str(),
        detail ? detail : "<null>");
    anti_tamper::webhook::write_log_critical("startup", tagged);
}

static void startup_log_critical_fmt(const char* fmt, ...)
{
    aida::manual_map_tls::ensure_current_thread();
    char buf[2048] = {};
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    startup_log_critical(buf);
}

static HANDLE& single_instance_mutex_handle()
{
    static HANDLE h = nullptr;
    return h;
}

static void focus_existing_aida_window()
{
    HWND existing = FindWindowW(L"AiDAStandaloneWindow", kAidaWindowTitle);
    if (!existing) {
        startup_log_critical_fmt("single_instance_existing_window_missing pid=%lu tid=%lu gle=%lu",
            GetCurrentProcessId(), GetCurrentThreadId(), GetLastError());
        return;
    }
    BOOL iconic = IsIconic(existing);
    ShowWindow(existing, iconic ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(existing);
    PostMessageW(existing, WM_APP + 0x1DA, 0, 0);
    startup_log_critical_fmt("single_instance_existing_window_focused hwnd=0x%llX iconic=%d pid=%lu tid=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(existing)),
        iconic ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId());
}

static bool acquire_single_instance_gate()
{
    HANDLE h = CreateMutexW(nullptr, TRUE, L"Local\\AiDAStandalone_8E9F73D8_SingleInstance");
    DWORD gle = GetLastError();
    if (!h) {
        startup_log_critical_fmt("single_instance_mutex_create_failed gle=%lu pid=%lu tid=%lu",
            gle, GetCurrentProcessId(), GetCurrentThreadId());
        crash_log_fmt("single_instance_mutex_create_failed gle=%lu", gle);
        return false;
    }
    if (gle == ERROR_ALREADY_EXISTS) {
        startup_log_critical_fmt("single_instance_duplicate_exit pid=%lu tid=%lu mutex=0x%llX",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(h)));
        focus_existing_aida_window();
        CloseHandle(h);
        crash_log_write("single_instance_duplicate_exit");
        return false;
    }
    single_instance_mutex_handle() = h;
    startup_log_critical_fmt("single_instance_acquired pid=%lu tid=%lu mutex=0x%llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(h)));
    return true;
}

static void release_single_instance_gate()
{
    HANDLE& h = single_instance_mutex_handle();
    if (!h) return;
    ReleaseMutex(h);
    CloseHandle(h);
    diag::log_tagged_critical_fmt("main", "single_instance_released pid=%lu tid=%lu",
        GetCurrentProcessId(), GetCurrentThreadId());
    h = nullptr;
}

static const char* startup_bg_phase_label(int step)
{
    switch (step)
    {
    case 0: return "Bootstrapping";
    case 1: return "Initializing AiDA runtime core";
    case 2: return "Probing network surface";
    case 3: return "Arming memory scanner";
    case 4: return "Spinning up MITM proxy";
    case 5: return "Loading script engine";
    case 6: return "Fingerprinting code surface";
    case 7: return "Activating tamper guard";
    case 8: return "Ready";
    default: return "<out_of_range>";
    }
}

static void startup_store_bg_step(int step, const char* source, const char* phase)
{
    int before = globals::ui::bg_init_step.load(std::memory_order_acquire);
    globals::ui::bg_init_step.store(step, std::memory_order_release);
    startup_log_critical_fmt(
        "bg_init_step_transition source=%s phase=%s before=%d after=%d label=%s pid=%lu tid=%lu tick=%llu",
        source ? source : "unknown",
        phase ? phase : "unknown",
        before,
        step,
        startup_bg_phase_label(step),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
}

static uint64_t diag_fnv1a64(const void* data, size_t len)
{
    if (!data)
        return 0;
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(p[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

static std::string generate_startup_run_correlation_id()
{
    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);
    uint64_t entropy[8] = {};
    entropy[0] = static_cast<uint64_t>(GetCurrentProcessId());
    entropy[1] = static_cast<uint64_t>(GetCurrentThreadId());
    entropy[2] = static_cast<uint64_t>(GetTickCount64());
    entropy[3] = static_cast<uint64_t>(qpc.QuadPart);
    entropy[4] = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&entropy));
#if defined(_M_X64)
    entropy[5] = static_cast<uint64_t>(__rdtsc());
#else
    entropy[5] = entropy[2] ^ entropy[3];
#endif
    entropy[6] = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)));
    entropy[7] = diag_fnv1a64(entropy, sizeof(entropy) - sizeof(entropy[7]));
    const uint64_t h1 = diag_fnv1a64(entropy, sizeof(entropy));
    entropy[0] ^= h1;
    entropy[4] += h1;
    const uint64_t h2 = diag_fnv1a64(entropy, sizeof(entropy));
    char buf[80] = {};
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%08lX-%016llX-%016llX",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(h1),
        static_cast<unsigned long long>(h2));
    return std::string(buf);
}

static void format_message_pump_stall_context(char* out, size_t cap);

namespace aida_tracer {
    inline std::atomic<uint64_t> g_render_frame{0};
    inline std::atomic<uint64_t> g_render_last_tick_ms{0};
    inline std::atomic<uint64_t> g_render_phase_id{0};
    inline std::atomic<const char*> g_render_phase_name{"<startup>"};
    inline std::atomic<DWORD> g_render_thread_id{0};
    inline std::atomic<uint64_t> g_attach_phase_id{0};
    inline std::atomic<const char*> g_attach_phase_name{"<idle>"};
    inline std::atomic<const char*> g_dispatch_stage{"<idle>"};
    inline std::atomic<UINT> g_dispatch_msg{0};
    inline std::atomic<UINT_PTR> g_dispatch_hwnd{0};
    inline std::atomic<UINT_PTR> g_dispatch_wparam{0};
    inline std::atomic<LONG_PTR> g_dispatch_lparam{0};
    inline std::atomic<DWORD> g_peek_queue_status{0};
    inline std::atomic<DWORD> g_peek_last_error{0};
    inline std::atomic<UINT> g_peek_remove_flags{kAidaQueuedPeekFlags};
    inline std::atomic<UINT_PTR> g_peek_filter_hwnd{0};
    inline std::atomic<uint64_t> g_peek_send_only_defers{0};
    inline std::atomic<uint64_t> g_peek_send_only_flushes{0};
    inline std::atomic<const char*> g_wndproc_stage{"<idle>"};
    inline std::atomic<UINT> g_wndproc_msg{0};
    inline std::atomic<UINT_PTR> g_wndproc_hwnd{0};
    inline std::atomic<UINT_PTR> g_wndproc_wparam{0};
    inline std::atomic<LONG_PTR> g_wndproc_lparam{0};
    inline std::atomic<uint64_t> g_wndproc_enter_count{0};
    inline std::atomic<uint64_t> g_wndproc_exit_count{0};
    inline std::atomic<uint64_t> g_peek_call_count{0};
    inline std::atomic<uint64_t> g_peek_return_count{0};
    inline std::atomic<uint64_t> g_dispatch_enter_count{0};
    inline std::atomic<uint64_t> g_dispatch_exit_count{0};
    inline std::atomic<uint64_t> g_last_thread_snapshot_ms{0};
    inline std::atomic<uint64_t> g_dx11_frame{0};
    inline std::atomic<uint64_t> g_dx11_enter_tick_ms{0};
    inline std::atomic<UINT_PTR> g_dx11_draw_data{0};
    inline std::atomic<UINT_PTR> g_dx11_device{0};
    inline std::atomic<UINT_PTR> g_dx11_context{0};
    inline std::atomic<UINT_PTR> g_dx11_rtv{0};
    inline std::atomic<uint64_t> g_dx11_cmd_lists{0};
    inline std::atomic<uint64_t> g_dx11_vtx_count{0};
    inline std::atomic<uint64_t> g_dx11_idx_count{0};
    inline std::atomic<int> g_dx11_display_w1000{0};
    inline std::atomic<int> g_dx11_display_h1000{0};
    inline std::atomic<int> g_dx11_fb_scale_w1000{0};
    inline std::atomic<int> g_dx11_fb_scale_h1000{0};
    inline std::atomic<long> g_dx11_device_removed{S_OK};
    inline std::atomic<uint64_t> g_dx11_draw_cmd_count{0};
    inline std::atomic<uint64_t> g_dx11_user_callback_count{0};
    inline std::atomic<uint64_t> g_dx11_reset_callback_count{0};
    inline std::atomic<uint64_t> g_dx11_expected_blur_callback_count{0};
    inline std::atomic<uint64_t> g_dx11_unexpected_callback_count{0};
    inline std::atomic<UINT_PTR> g_dx11_first_callback{0};
    inline std::atomic<UINT_PTR> g_dx11_first_callback_data{0};
    inline std::atomic<UINT_PTR> g_dx11_first_texture{0};
    inline std::atomic<uint64_t> g_dx11_texture_hash{0};
    inline std::atomic<uint64_t> g_dx11_max_elem_count{0};
    inline std::atomic<uint32_t> g_dx11_bad_flags{0};
    inline std::atomic<int> g_dx11_bad_list{ -1 };
    inline std::atomic<int> g_dx11_bad_cmd{ -1 };
    inline std::atomic<uint64_t> g_present_frame{0};
    inline std::atomic<uint64_t> g_present_enter_tick_ms{0};
    inline std::atomic<UINT_PTR> g_present_swapchain{0};
    inline std::atomic<long> g_present_hr{S_OK};
    inline std::atomic<bool> g_stop{false};

    inline const char* message_name(UINT msg) {
        switch (msg) {
        case WM_NULL: return "WM_NULL";
        case WM_CREATE: return "WM_CREATE";
        case WM_DESTROY: return "WM_DESTROY";
        case WM_MOVE: return "WM_MOVE";
        case WM_SIZE: return "WM_SIZE";
        case WM_ACTIVATE: return "WM_ACTIVATE";
        case WM_SETFOCUS: return "WM_SETFOCUS";
        case WM_KILLFOCUS: return "WM_KILLFOCUS";
        case WM_ENABLE: return "WM_ENABLE";
        case WM_SETREDRAW: return "WM_SETREDRAW";
        case WM_SETTEXT: return "WM_SETTEXT";
        case WM_GETTEXT: return "WM_GETTEXT";
        case WM_GETTEXTLENGTH: return "WM_GETTEXTLENGTH";
        case WM_PAINT: return "WM_PAINT";
        case WM_CLOSE: return "WM_CLOSE";
        case WM_QUIT: return "WM_QUIT";
        case WM_ERASEBKGND: return "WM_ERASEBKGND";
        case WM_SYSCOLORCHANGE: return "WM_SYSCOLORCHANGE";
        case WM_SHOWWINDOW: return "WM_SHOWWINDOW";
        case WM_SETTINGCHANGE: return "WM_SETTINGCHANGE";
        case WM_DEVMODECHANGE: return "WM_DEVMODECHANGE";
        case WM_ACTIVATEAPP: return "WM_ACTIVATEAPP";
        case WM_FONTCHANGE: return "WM_FONTCHANGE";
        case WM_TIMECHANGE: return "WM_TIMECHANGE";
        case WM_CANCELMODE: return "WM_CANCELMODE";
        case WM_SETCURSOR: return "WM_SETCURSOR";
        case WM_MOUSEACTIVATE: return "WM_MOUSEACTIVATE";
        case WM_CHILDACTIVATE: return "WM_CHILDACTIVATE";
        case WM_QUEUESYNC: return "WM_QUEUESYNC";
        case WM_GETMINMAXINFO: return "WM_GETMINMAXINFO";
        case WM_WINDOWPOSCHANGING: return "WM_WINDOWPOSCHANGING";
        case WM_WINDOWPOSCHANGED: return "WM_WINDOWPOSCHANGED";
        case WM_CONTEXTMENU: return "WM_CONTEXTMENU";
        case WM_STYLECHANGING: return "WM_STYLECHANGING";
        case WM_STYLECHANGED: return "WM_STYLECHANGED";
        case WM_DISPLAYCHANGE: return "WM_DISPLAYCHANGE";
        case WM_GETICON: return "WM_GETICON";
        case WM_SETICON: return "WM_SETICON";
        case WM_NCCREATE: return "WM_NCCREATE";
        case WM_NCDESTROY: return "WM_NCDESTROY";
        case WM_NCCALCSIZE: return "WM_NCCALCSIZE";
        case WM_NCHITTEST: return "WM_NCHITTEST";
        case WM_NCPAINT: return "WM_NCPAINT";
        case WM_NCACTIVATE: return "WM_NCACTIVATE";
        case WM_GETDLGCODE: return "WM_GETDLGCODE";
        case WM_SYNCPAINT: return "WM_SYNCPAINT";
        case WM_NCMOUSEMOVE: return "WM_NCMOUSEMOVE";
        case WM_NCLBUTTONDOWN: return "WM_NCLBUTTONDOWN";
        case WM_NCLBUTTONUP: return "WM_NCLBUTTONUP";
        case WM_NCLBUTTONDBLCLK: return "WM_NCLBUTTONDBLCLK";
        case WM_KEYDOWN: return "WM_KEYDOWN";
        case WM_KEYUP: return "WM_KEYUP";
        case WM_CHAR: return "WM_CHAR";
        case WM_SYSKEYDOWN: return "WM_SYSKEYDOWN";
        case WM_SYSKEYUP: return "WM_SYSKEYUP";
        case WM_SYSCHAR: return "WM_SYSCHAR";
        case WM_INITDIALOG: return "WM_INITDIALOG";
        case WM_COMMAND: return "WM_COMMAND";
        case WM_SYSCOMMAND: return "WM_SYSCOMMAND";
        case WM_TIMER: return "WM_TIMER";
        case WM_HSCROLL: return "WM_HSCROLL";
        case WM_VSCROLL: return "WM_VSCROLL";
        case WM_INITMENU: return "WM_INITMENU";
        case WM_INITMENUPOPUP: return "WM_INITMENUPOPUP";
        case WM_MENUSELECT: return "WM_MENUSELECT";
        case WM_MENUCHAR: return "WM_MENUCHAR";
        case WM_ENTERIDLE: return "WM_ENTERIDLE";
        case WM_MOUSEMOVE: return "WM_MOUSEMOVE";
        case WM_LBUTTONDOWN: return "WM_LBUTTONDOWN";
        case WM_LBUTTONUP: return "WM_LBUTTONUP";
        case WM_LBUTTONDBLCLK: return "WM_LBUTTONDBLCLK";
        case WM_RBUTTONDOWN: return "WM_RBUTTONDOWN";
        case WM_RBUTTONUP: return "WM_RBUTTONUP";
        case WM_RBUTTONDBLCLK: return "WM_RBUTTONDBLCLK";
        case WM_MBUTTONDOWN: return "WM_MBUTTONDOWN";
        case WM_MBUTTONUP: return "WM_MBUTTONUP";
        case WM_MOUSEWHEEL: return "WM_MOUSEWHEEL";
        case WM_XBUTTONDOWN: return "WM_XBUTTONDOWN";
        case WM_XBUTTONUP: return "WM_XBUTTONUP";
        case WM_MOUSELEAVE: return "WM_MOUSELEAVE";
        case WM_MOUSEHOVER: return "WM_MOUSEHOVER";
        case WM_MOUSEHWHEEL: return "WM_MOUSEHWHEEL";
        case WM_PARENTNOTIFY: return "WM_PARENTNOTIFY";
        case WM_ENTERMENULOOP: return "WM_ENTERMENULOOP";
        case WM_EXITMENULOOP: return "WM_EXITMENULOOP";
        case WM_NEXTMENU: return "WM_NEXTMENU";
        case WM_SIZING: return "WM_SIZING";
        case WM_CAPTURECHANGED: return "WM_CAPTURECHANGED";
        case WM_MOVING: return "WM_MOVING";
        case WM_POWERBROADCAST: return "WM_POWERBROADCAST";
        case WM_DEVICECHANGE: return "WM_DEVICECHANGE";
        case WM_ENTERSIZEMOVE: return "WM_ENTERSIZEMOVE";
        case WM_EXITSIZEMOVE: return "WM_EXITSIZEMOVE";
        case WM_DROPFILES: return "WM_DROPFILES";
        case WM_DPICHANGED: return "WM_DPICHANGED";
        default: return "WM_UNKNOWN";
        }
    }

    inline void set_dispatch_state(const char* stage, const MSG& msg) {
        g_dispatch_msg.store(msg.message, std::memory_order_release);
        g_dispatch_hwnd.store(reinterpret_cast<UINT_PTR>(msg.hwnd), std::memory_order_release);
        g_dispatch_wparam.store(static_cast<UINT_PTR>(msg.wParam), std::memory_order_release);
        g_dispatch_lparam.store(static_cast<LONG_PTR>(msg.lParam), std::memory_order_release);
        g_dispatch_stage.store(stage, std::memory_order_release);
    }

    inline void clear_dispatch_state() {
        g_dispatch_stage.store("<idle>", std::memory_order_release);
    }

    inline void set_peek_state(DWORD queue_status, DWORD last_error) {
        g_peek_queue_status.store(queue_status, std::memory_order_release);
        g_peek_last_error.store(last_error, std::memory_order_release);
    }

    inline void set_peek_call_shape(UINT remove_flags, HWND filter_hwnd) {
        g_peek_remove_flags.store(remove_flags, std::memory_order_release);
        g_peek_filter_hwnd.store(reinterpret_cast<UINT_PTR>(filter_hwnd), std::memory_order_release);
    }

    inline bool should_log_wndproc_input_message(UINT msg) {
        switch (msg) {
        case WM_MOUSEACTIVATE:
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
        case WM_RBUTTONDBLCLK:
        case WM_MBUTTONDOWN:
        case WM_MBUTTONUP:
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
        case WM_XBUTTONDOWN:
        case WM_XBUTTONUP:
        case WM_CAPTURECHANGED:
            return true;
        default:
            return false;
        }
    }

    inline bool should_log_wndproc_completion(UINT msg, uint64_t elapsed_ms) {
        if (elapsed_ms >= 32)
            return true;
        switch (msg) {
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
        case WM_QUERYENDSESSION:
        case WM_ENDSESSION:
        case WM_SYSCOMMAND:
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_NCLBUTTONDOWN:
        case WM_NCLBUTTONUP:
        case WM_MOUSEACTIVATE:
        case WM_DPICHANGED:
        case WM_SETTINGCHANGE:
            return true;
        default:
            return should_log_wndproc_input_message(msg);
        }
    }

    inline bool is_shutdown_stall_context(const char* phase_name, UINT dispatch_msg, UINT wndproc_msg) {
        if (phase_name && std::strncmp(phase_name, "shutdown", 8) == 0)
            return true;
        switch (dispatch_msg) {
        case WM_QUIT:
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
            return true;
        default:
            break;
        }
        switch (wndproc_msg) {
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
            return true;
        default:
            return false;
        }
    }

    inline void set_wndproc_state(const char* stage, HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        g_wndproc_msg.store(msg, std::memory_order_release);
        g_wndproc_hwnd.store(reinterpret_cast<UINT_PTR>(hwnd), std::memory_order_release);
        g_wndproc_wparam.store(static_cast<UINT_PTR>(wParam), std::memory_order_release);
        g_wndproc_lparam.store(static_cast<LONG_PTR>(lParam), std::memory_order_release);
        g_wndproc_stage.store(stage, std::memory_order_release);
        if (stage && strcmp(stage, "enter") == 0)
            g_wndproc_enter_count.fetch_add(1, std::memory_order_acq_rel);
    }

    inline void clear_wndproc_state() {
        g_wndproc_stage.store("<idle>", std::memory_order_release);
        g_wndproc_exit_count.fetch_add(1, std::memory_order_acq_rel);
    }

    inline int scaled_1000(float v) {
        return static_cast<int>(v * 1000.0f);
    }

    inline bool sane_float(float v) {
        return v == v && v > -10000000.0f && v < 10000000.0f;
    }

    inline uint64_t mix_u64(uint64_t h, uint64_t v) {
        h ^= v + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
        return h;
    }

    inline void describe_address(uint64_t va, char* out, size_t out_size) {
        if (!out || out_size == 0) return;
        out[0] = 0;
        MEMORY_BASIC_INFORMATION mbi{};
        HMODULE mod = nullptr;
        char module_path[MAX_PATH * 4] = {};
        char mapped_path[MAX_PATH * 4] = {};
        const bool have_mbi = VirtualQuery(reinterpret_cast<LPCVOID>(va), &mbi, sizeof(mbi)) != 0;
        DWORD module_len = 0;
        DWORD module_gle = 0;
        DWORD mapped_len = 0;
        DWORD mapped_gle = 0;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(va), &mod) && mod) {
            module_len = GetModuleFileNameA(mod, module_path, static_cast<DWORD>(sizeof(module_path)));
            module_gle = module_len ? 0 : GetLastError();
        }
        mapped_len = GetMappedFileNameA(GetCurrentProcess(), reinterpret_cast<LPVOID>(va), mapped_path, static_cast<DWORD>(sizeof(mapped_path)));
        mapped_gle = mapped_len ? 0 : GetLastError();
        uint64_t mod_base = static_cast<uint64_t>(reinterpret_cast<UINT_PTR>(mod));
        uint64_t mod_off = (mod_base != 0 && va >= mod_base) ? (va - mod_base) : 0;
        _snprintf_s(out, out_size, _TRUNCATE,
            "addr=0x%016llX mbi=%d base=0x%016llX alloc=0x%016llX protect=0x%lX state=0x%lX type=0x%lX module=0x%016llX mod_off=0x%llX path='%s' path_len=%lu path_gle=%lu mapped='%s' mapped_len=%lu mapped_gle=%lu",
            static_cast<unsigned long long>(va),
            have_mbi ? 1 : 0,
            have_mbi ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mbi.BaseAddress)) : 0ull,
            have_mbi ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mbi.AllocationBase)) : 0ull,
            have_mbi ? static_cast<unsigned long>(mbi.Protect) : 0ul,
            have_mbi ? static_cast<unsigned long>(mbi.State) : 0ul,
            have_mbi ? static_cast<unsigned long>(mbi.Type) : 0ul,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mod)),
            static_cast<unsigned long long>(mod_off),
            module_path[0] ? module_path : "<none>",
            static_cast<unsigned long>(module_len),
            static_cast<unsigned long>(module_gle),
            mapped_path[0] ? mapped_path : "<none>",
            static_cast<unsigned long>(mapped_len),
            static_cast<unsigned long>(mapped_gle));
    }

    inline void capture_render_thread_snapshot(DWORD render_tid, uint64_t age_ms) {
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        uint64_t prev = g_last_thread_snapshot_ms.load(std::memory_order_acquire);
        if (prev != 0 && now >= prev && now - prev < 30000)
            return;
        g_last_thread_snapshot_ms.store(now, std::memory_order_release);

        HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, render_tid);
        DWORD open_gle = th ? 0 : GetLastError();
        DWORD exit_code = 0;
        DWORD exit_gle = 0;
        BOOL exit_ok = FALSE;
        FILETIME create_time{};
        FILETIME exit_time{};
        FILETIME kernel_time{};
        FILETIME user_time{};
        DWORD times_gle = 0;
        BOOL times_ok = FALSE;
        if (th) {
            SetLastError(0);
            exit_ok = GetExitCodeThread(th, &exit_code);
            exit_gle = exit_ok ? 0 : GetLastError();
            SetLastError(0);
            times_ok = GetThreadTimes(th, &create_time, &exit_time, &kernel_time, &user_time);
            times_gle = times_ok ? 0 : GetLastError();
            CloseHandle(th);
        }

        diag::log_tagged_critical_fmt("tracer",
            "render_thread_snapshot_no_suspend tid=%lu age_ms=%llu open_ok=%d open_gle=%lu exit_ok=%d exit_code=0x%08lX exit_gle=%lu times_ok=%d times_gle=%lu kernel_time_low=0x%08lX kernel_time_high=0x%08lX user_time_low=0x%08lX user_time_high=0x%08lX peek_calls=%llu peek_returns=%llu dispatch_enter=%llu dispatch_exit=%llu wnd_enter=%llu wnd_exit=%llu",
            render_tid,
            static_cast<unsigned long long>(age_ms),
            th ? 1 : 0,
            static_cast<unsigned long>(open_gle),
            exit_ok ? 1 : 0,
            static_cast<unsigned long>(exit_code),
            static_cast<unsigned long>(exit_gle),
            times_ok ? 1 : 0,
            static_cast<unsigned long>(times_gle),
            static_cast<unsigned long>(kernel_time.dwLowDateTime),
            static_cast<unsigned long>(kernel_time.dwHighDateTime),
            static_cast<unsigned long>(user_time.dwLowDateTime),
            static_cast<unsigned long>(user_time.dwHighDateTime),
            static_cast<unsigned long long>(g_peek_call_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_peek_return_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_exit_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_exit_count.load(std::memory_order_acquire)));

        HANDLE stack_th = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
            FALSE,
            render_tid);
        const DWORD stack_open_gle = stack_th ? 0 : GetLastError();
        if (!stack_th) {
            diag::log_tagged_critical_fmt("tracer",
                "render_thread_stack_open_fail tid=%lu gle=%lu",
                render_tid,
                static_cast<unsigned long>(stack_open_gle));
            return;
        }

        DWORD suspend_count = static_cast<DWORD>(-1);
        unsigned frames_walked = 0;
        const char* abort_reason = nullptr;
        const uint64_t suspend_t0 = static_cast<uint64_t>(GetTickCount64());
        diag::log_tagged_critical_fmt("tracer",
            "render_thread_stack_begin tid=%lu age_ms=%llu",
            render_tid,
            static_cast<unsigned long long>(age_ms));

        __try {
            suspend_count = SuspendThread(stack_th);
            if (suspend_count == static_cast<DWORD>(-1)) {
                abort_reason = "suspend_failed";
            } else {
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_FULL;
                if (!GetThreadContext(stack_th, &ctx)) {
                    abort_reason = "get_thread_context_failed";
                } else {
                    STACKFRAME64 frame{};
#if defined(_M_X64)
                    frame.AddrPC.Offset = ctx.Rip;
                    frame.AddrPC.Mode = AddrModeFlat;
                    frame.AddrFrame.Offset = ctx.Rbp;
                    frame.AddrFrame.Mode = AddrModeFlat;
                    frame.AddrStack.Offset = ctx.Rsp;
                    frame.AddrStack.Mode = AddrModeFlat;
                    const DWORD machine = IMAGE_FILE_MACHINE_AMD64;
#else
                    frame.AddrPC.Offset = ctx.Eip;
                    frame.AddrPC.Mode = AddrModeFlat;
                    frame.AddrFrame.Offset = ctx.Ebp;
                    frame.AddrFrame.Mode = AddrModeFlat;
                    frame.AddrStack.Offset = ctx.Esp;
                    frame.AddrStack.Mode = AddrModeFlat;
                    const DWORD machine = IMAGE_FILE_MACHINE_I386;
#endif
                    HANDLE proc = GetCurrentProcess();
                    constexpr unsigned kMaxFrames = 64;
                    for (unsigned i = 0; i < kMaxFrames; ++i) {
                        const uint64_t walk_now = static_cast<uint64_t>(GetTickCount64());
                        if (walk_now - suspend_t0 >= 50ULL) {
                            abort_reason = "suspend_budget_exceeded";
                            break;
                        }
                        if (!StackWalk64(
                                machine,
                                proc,
                                stack_th,
                                &frame,
                                machine == IMAGE_FILE_MACHINE_AMD64 ? &ctx : nullptr,
                                nullptr,
                                SymFunctionTableAccess64,
                                SymGetModuleBase64,
                                nullptr)) {
                            abort_reason = "stack_walk_end_or_fail";
                            break;
                        }
                        if (frame.AddrPC.Offset == 0)
                            break;
                        char module_path[MAX_PATH] = {};
                        unsigned long long module_base = 0;
                        unsigned long long module_off = frame.AddrPC.Offset;
                        HMODULE mod = nullptr;
                        if (GetModuleHandleExA(
                                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(static_cast<UINT_PTR>(frame.AddrPC.Offset)),
                                &mod) &&
                            mod) {
                            module_base = static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mod));
                            module_off = frame.AddrPC.Offset - module_base;
                            GetModuleFileNameA(mod, module_path, sizeof(module_path));
                        }
                        const char* short_name = module_path;
                        for (const char* p = module_path; *p; ++p) {
                            if (*p == '\\' || *p == '/')
                                short_name = p + 1;
                        }
                        diag::log_tagged_critical_fmt("tracer",
                            "render_thread_stack idx=%u rip=0x%llX module=%s base=0x%llX offset=0x%llX frame_rbp=0x%llX frame_rsp=0x%llX",
                            i,
                            static_cast<unsigned long long>(frame.AddrPC.Offset),
                            short_name[0] ? short_name : "<unknown>",
                            module_base,
                            module_off,
                            static_cast<unsigned long long>(frame.AddrFrame.Offset),
                            static_cast<unsigned long long>(frame.AddrStack.Offset));
                        ++frames_walked;
                    }
                }
                ResumeThread(stack_th);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (suspend_count != static_cast<DWORD>(-1))
                ResumeThread(stack_th);
            abort_reason = "seh_exception";
        }

        const uint64_t suspend_elapsed = static_cast<uint64_t>(GetTickCount64()) - suspend_t0;
        diag::log_tagged_critical_fmt("tracer",
            "render_thread_stack_end tid=%lu frames=%u suspend_count=%lu elapsed_ms=%llu reason=%s",
            render_tid,
            frames_walked,
            static_cast<unsigned long>(suspend_count),
            static_cast<unsigned long long>(suspend_elapsed),
            abort_reason ? abort_reason : "ok");

        CloseHandle(stack_th);
    }

    inline void mark_render_phase(const char* name) {
        g_render_phase_name.store(name, std::memory_order_release);
        g_render_phase_id.fetch_add(1, std::memory_order_acq_rel);
    }
    inline void mark_attach_phase(const char* name) {
        g_attach_phase_name.store(name, std::memory_order_release);
        g_attach_phase_id.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("attach", "phase=%s", name);
    }
    inline void render_pulse(uint64_t frame) {
        g_render_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
        g_render_frame.store(frame, std::memory_order_release);
        g_render_last_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
    }

    inline void set_dx11_draw_state(const char* stage,
                                    uint64_t frame,
                                    ImDrawData* dd,
                                    ID3D11Device* device,
                                    ID3D11DeviceContext* context,
                                    ID3D11RenderTargetView* rtv,
                                    HRESULT device_removed) {
        g_dx11_frame.store(frame, std::memory_order_release);
        g_dx11_enter_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        g_dx11_draw_data.store(reinterpret_cast<UINT_PTR>(dd), std::memory_order_release);
        g_dx11_device.store(reinterpret_cast<UINT_PTR>(device), std::memory_order_release);
        g_dx11_context.store(reinterpret_cast<UINT_PTR>(context), std::memory_order_release);
        g_dx11_rtv.store(reinterpret_cast<UINT_PTR>(rtv), std::memory_order_release);
        g_dx11_cmd_lists.store(dd ? static_cast<uint64_t>(dd->CmdListsCount) : 0, std::memory_order_release);
        g_dx11_vtx_count.store(dd ? static_cast<uint64_t>(dd->TotalVtxCount) : 0, std::memory_order_release);
        g_dx11_idx_count.store(dd ? static_cast<uint64_t>(dd->TotalIdxCount) : 0, std::memory_order_release);
        g_dx11_display_w1000.store(dd ? scaled_1000(dd->DisplaySize.x) : 0, std::memory_order_release);
        g_dx11_display_h1000.store(dd ? scaled_1000(dd->DisplaySize.y) : 0, std::memory_order_release);
        g_dx11_fb_scale_w1000.store(dd ? scaled_1000(dd->FramebufferScale.x) : 0, std::memory_order_release);
        g_dx11_fb_scale_h1000.store(dd ? scaled_1000(dd->FramebufferScale.y) : 0, std::memory_order_release);
        g_dx11_device_removed.store(static_cast<long>(device_removed), std::memory_order_release);
        mark_render_phase(stage);
    }

    inline uint32_t inspect_dx11_draw_data(ImDrawData* dd, uint64_t frame) {
        uint64_t draw_cmds = 0;
        uint64_t user_callbacks = 0;
        uint64_t reset_callbacks = 0;
        uint64_t expected_blur_callbacks = 0;
        uint64_t unexpected_callbacks = 0;
        UINT_PTR first_callback = 0;
        UINT_PTR first_callback_data = 0;
        UINT_PTR first_unexpected_callback = 0;
        UINT_PTR first_unexpected_callback_data = 0;
        UINT_PTR first_texture = 0;
        uint64_t texture_hash = 14695981039346656037ULL;
        uint64_t max_elem_count = 0;
        uint32_t bad_flags = 0;
        int bad_list = -1;
        int bad_cmd = -1;
        ImDrawCallback expected_blur_callback = Blur::ExpectedCallback();

        if (!dd) {
            bad_flags |= 0x00000001u;
        } else {
            if (!sane_float(dd->DisplaySize.x) || !sane_float(dd->DisplaySize.y) ||
                !sane_float(dd->FramebufferScale.x) || !sane_float(dd->FramebufferScale.y) ||
                dd->DisplaySize.x < 0.0f || dd->DisplaySize.y < 0.0f ||
                dd->FramebufferScale.x <= 0.0f || dd->FramebufferScale.y <= 0.0f) {
                bad_flags |= 0x00000002u;
            }
            if (dd->CmdListsCount < 0 || dd->CmdListsCount > 4096 ||
                dd->TotalVtxCount < 0 || dd->TotalVtxCount > 4000000 ||
                dd->TotalIdxCount < 0 || dd->TotalIdxCount > 8000000) {
                bad_flags |= 0x00000004u;
            }
            if (dd->CmdListsCount > 0 && !dd->CmdLists.Data) {
                bad_flags |= 0x00000008u;
            }
            if (dd->CmdLists.Size != dd->CmdListsCount) {
                bad_flags |= 0x00000100u;
            }
            int list_count = dd->CmdListsCount;
            if (list_count < 0) list_count = 0;
            if (list_count > 4096) list_count = 4096;
            if (list_count > dd->CmdLists.Size)
                list_count = dd->CmdLists.Size;
            for (int i = 0; i < list_count; ++i) {
                ImDrawList* list = dd->CmdLists.Data ? dd->CmdLists[i] : nullptr;
                if (!list) {
                    bad_flags |= 0x00000010u;
                    if (bad_list < 0) bad_list = i;
                    continue;
                }
                if (list->CmdBuffer.Size < 0 || list->CmdBuffer.Size > 200000 ||
                    list->VtxBuffer.Size < 0 || list->VtxBuffer.Size > 4000000 ||
                    list->IdxBuffer.Size < 0 || list->IdxBuffer.Size > 8000000) {
                    bad_flags |= 0x00000020u;
                    if (bad_list < 0) bad_list = i;
                }
                int cmd_count = list->CmdBuffer.Size;
                if (cmd_count < 0) cmd_count = 0;
                if (cmd_count > 200000) cmd_count = 200000;
                for (int j = 0; j < cmd_count; ++j) {
                    ImDrawCmd& cmd = list->CmdBuffer[j];
                    ++draw_cmds;
                    ImTextureID tex_id = cmd.GetTexID();
                    UINT_PTR tex = 0;
                    std::memcpy(&tex, &tex_id, std::min(sizeof(tex), sizeof(tex_id)));
                    if (first_texture == 0 && tex != 0)
                        first_texture = tex;
                    texture_hash = mix_u64(texture_hash, static_cast<uint64_t>(tex));
                    texture_hash = mix_u64(texture_hash, static_cast<uint64_t>(cmd.ElemCount));
                    if (cmd.ElemCount > max_elem_count)
                        max_elem_count = cmd.ElemCount;
                    if (!sane_float(cmd.ClipRect.x) || !sane_float(cmd.ClipRect.y) ||
                        !sane_float(cmd.ClipRect.z) || !sane_float(cmd.ClipRect.w) ||
                        cmd.ClipRect.z < cmd.ClipRect.x || cmd.ClipRect.w < cmd.ClipRect.y) {
                        bad_flags |= 0x00000040u;
                        if (bad_list < 0) bad_list = i;
                        if (bad_cmd < 0) bad_cmd = j;
                    }
                    uint64_t idx_size = static_cast<uint64_t>(list->IdxBuffer.Size);
                    uint64_t vtx_size = static_cast<uint64_t>(list->VtxBuffer.Size);
                    uint64_t idx_offset = static_cast<uint64_t>(cmd.IdxOffset);
                    uint64_t elem_count = static_cast<uint64_t>(cmd.ElemCount);
                    if (idx_offset > idx_size ||
                        static_cast<uint64_t>(cmd.VtxOffset) > vtx_size ||
                        elem_count > idx_size ||
                        idx_offset + elem_count > idx_size) {
                        bad_flags |= 0x00000080u;
                        if (bad_list < 0) bad_list = i;
                        if (bad_cmd < 0) bad_cmd = j;
                    }
                    if (cmd.UserCallback) {
                        if (cmd.UserCallback == ImDrawCallback_ResetRenderState) {
                            ++reset_callbacks;
                        } else if (expected_blur_callback && cmd.UserCallback == expected_blur_callback) {
                            ++user_callbacks;
                            ++expected_blur_callbacks;
                            if (first_callback == 0) {
                                first_callback = reinterpret_cast<UINT_PTR>(cmd.UserCallback);
                                first_callback_data = reinterpret_cast<UINT_PTR>(cmd.UserCallbackData);
                            }
                        } else {
                            ++user_callbacks;
                            ++unexpected_callbacks;
                            if (first_callback == 0) {
                                first_callback = reinterpret_cast<UINT_PTR>(cmd.UserCallback);
                                first_callback_data = reinterpret_cast<UINT_PTR>(cmd.UserCallbackData);
                            }
                            if (first_unexpected_callback == 0) {
                                first_unexpected_callback = reinterpret_cast<UINT_PTR>(cmd.UserCallback);
                                first_unexpected_callback_data = reinterpret_cast<UINT_PTR>(cmd.UserCallbackData);
                            }
                        }
                    }
                }
            }
        }

        g_dx11_draw_cmd_count.store(draw_cmds, std::memory_order_release);
        g_dx11_user_callback_count.store(user_callbacks, std::memory_order_release);
        g_dx11_reset_callback_count.store(reset_callbacks, std::memory_order_release);
        g_dx11_expected_blur_callback_count.store(expected_blur_callbacks, std::memory_order_release);
        g_dx11_unexpected_callback_count.store(unexpected_callbacks, std::memory_order_release);
        g_dx11_first_callback.store(first_callback, std::memory_order_release);
        g_dx11_first_callback_data.store(first_callback_data, std::memory_order_release);
        g_dx11_first_texture.store(first_texture, std::memory_order_release);
        g_dx11_texture_hash.store(texture_hash, std::memory_order_release);
        g_dx11_max_elem_count.store(max_elem_count, std::memory_order_release);
        g_dx11_bad_flags.store(bad_flags, std::memory_order_release);
        g_dx11_bad_list.store(bad_list, std::memory_order_release);
        g_dx11_bad_cmd.store(bad_cmd, std::memory_order_release);

        if (bad_flags != 0 || unexpected_callbacks != 0) {
            diag::log_tagged_critical_fmt("render",
                "dx11_drawdata_inspect frame=%llu bad=0x%08lX bad_list=%d bad_cmd=%d lists=%d total_vtx=%d total_idx=%d draw_cmds=%llu callbacks=%llu expected_blur_callbacks=%llu unexpected_callbacks=%llu reset_callbacks=%llu first_cb=0x%llX cb_data=0x%llX first_unexpected_cb=0x%llX unexpected_cb_data=0x%llX first_tex=0x%llX tex_hash=0x%016llX max_elem=%llu full_test=%d",
                static_cast<unsigned long long>(frame),
                static_cast<unsigned long>(bad_flags),
                bad_list,
                bad_cmd,
                dd ? dd->CmdListsCount : -1,
                dd ? dd->TotalVtxCount : -1,
                dd ? dd->TotalIdxCount : -1,
                static_cast<unsigned long long>(draw_cmds),
                static_cast<unsigned long long>(user_callbacks),
                static_cast<unsigned long long>(expected_blur_callbacks),
                static_cast<unsigned long long>(unexpected_callbacks),
                static_cast<unsigned long long>(reset_callbacks),
                static_cast<unsigned long long>(first_callback),
                static_cast<unsigned long long>(first_callback_data),
                static_cast<unsigned long long>(first_unexpected_callback),
                static_cast<unsigned long long>(first_unexpected_callback_data),
                static_cast<unsigned long long>(first_texture),
                static_cast<unsigned long long>(texture_hash),
                static_cast<unsigned long long>(max_elem_count),
                test_all_features::is_running() ? 1 : 0);
            if (unexpected_callbacks != 0 && first_unexpected_callback != 0) {
                char cb_desc[1200] = {};
                describe_address(static_cast<uint64_t>(first_unexpected_callback), cb_desc, sizeof(cb_desc));
                diag::log_tagged_critical_fmt("render",
                    "dx11_drawdata_unexpected_callback frame=%llu callbacks=%llu first_unexpected_cb=0x%llX cb_data=0x%llX desc={%.1000s}",
                    static_cast<unsigned long long>(frame),
                    static_cast<unsigned long long>(unexpected_callbacks),
                    static_cast<unsigned long long>(first_unexpected_callback),
                    static_cast<unsigned long long>(first_unexpected_callback_data),
                    cb_desc[0] ? cb_desc : "<empty>");
            }
        } else if (user_callbacks != 0 || reset_callbacks != 0) {
            static std::atomic<uint64_t> s_last_expected_callback_hash{0};
            static std::atomic<uint64_t> s_last_expected_callback_log_ms{0};
            static std::atomic<uint64_t> s_expected_callback_suppressed{0};
            uint64_t callback_hash = 14695981039346656037ULL;
            callback_hash = mix_u64(callback_hash, user_callbacks);
            callback_hash = mix_u64(callback_hash, expected_blur_callbacks);
            callback_hash = mix_u64(callback_hash, reset_callbacks);
            callback_hash = mix_u64(callback_hash, first_callback);
            callback_hash = mix_u64(callback_hash, first_texture);
            callback_hash = mix_u64(callback_hash, texture_hash);
            callback_hash = mix_u64(callback_hash, max_elem_count);
            const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
            const uint64_t last_hash = s_last_expected_callback_hash.load(std::memory_order_acquire);
            const uint64_t last_log_ms = s_last_expected_callback_log_ms.load(std::memory_order_acquire);
            if (last_log_ms == 0 || callback_hash != last_hash || now_ms - last_log_ms >= 30000ULL) {
                const uint64_t suppressed = s_expected_callback_suppressed.exchange(0, std::memory_order_acq_rel);
                s_last_expected_callback_hash.store(callback_hash, std::memory_order_release);
                s_last_expected_callback_log_ms.store(now_ms, std::memory_order_release);
                diag::log_tagged_fmt("render",
                    "dx11_drawdata_callbacks frame=%llu callbacks=%llu expected_blur_callbacks=%llu unexpected_callbacks=%llu reset_callbacks=%llu first_cb=0x%llX cb_data=0x%llX tex_hash=0x%016llX max_elem=%llu suppressed=%llu full_test=%d",
                    static_cast<unsigned long long>(frame),
                    static_cast<unsigned long long>(user_callbacks),
                    static_cast<unsigned long long>(expected_blur_callbacks),
                    static_cast<unsigned long long>(unexpected_callbacks),
                    static_cast<unsigned long long>(reset_callbacks),
                    static_cast<unsigned long long>(first_callback),
                    static_cast<unsigned long long>(first_callback_data),
                    static_cast<unsigned long long>(texture_hash),
                    static_cast<unsigned long long>(max_elem_count),
                    static_cast<unsigned long long>(suppressed),
                    test_all_features::is_running() ? 1 : 0);
            } else {
                s_expected_callback_suppressed.fetch_add(1, std::memory_order_acq_rel);
            }
        }
        return bad_flags;
    }

    inline void set_present_state(const char* stage, uint64_t frame, IDXGISwapChain* sc, HRESULT hr) {
        g_present_frame.store(frame, std::memory_order_release);
        g_present_enter_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        g_present_swapchain.store(reinterpret_cast<UINT_PTR>(sc), std::memory_order_release);
        g_present_hr.store(static_cast<long>(hr), std::memory_order_release);
        mark_render_phase(stage);
    }

    inline void run_tracer_thread() {
        uint64_t prev_frame = 0;
        uint64_t prev_render_phase_id = 0;
        uint64_t stall_streak = 0;
        uint64_t last_peek_rescue_ms = 0;
        const uint64_t kStallThresholdMs = 2000;
        while (!g_stop.load(std::memory_order_acquire)) {
            ::Sleep(250);

            uint64_t now = static_cast<uint64_t>(GetTickCount64());
            uint64_t frame = g_render_frame.load(std::memory_order_acquire);
            uint64_t last_tick = g_render_last_tick_ms.load(std::memory_order_acquire);
            uint64_t phase_id = g_render_phase_id.load(std::memory_order_acquire);
            const char* phase_name = g_render_phase_name.load(std::memory_order_acquire);
            const char* render_section = g_render_section.c_str();
            uint64_t attach_phase_id = g_attach_phase_id.load(std::memory_order_acquire);
            const char* attach_phase = g_attach_phase_name.load(std::memory_order_acquire);
            DWORD render_tid = g_render_thread_id.load(std::memory_order_acquire);
            const char* dispatch_stage = g_dispatch_stage.load(std::memory_order_acquire);
            UINT dispatch_msg = g_dispatch_msg.load(std::memory_order_acquire);
            UINT_PTR dispatch_hwnd = g_dispatch_hwnd.load(std::memory_order_acquire);
            UINT_PTR dispatch_wparam = g_dispatch_wparam.load(std::memory_order_acquire);
            LONG_PTR dispatch_lparam = g_dispatch_lparam.load(std::memory_order_acquire);
            DWORD peek_status = g_peek_queue_status.load(std::memory_order_acquire);
            DWORD peek_error = g_peek_last_error.load(std::memory_order_acquire);
            const char* wndproc_stage = g_wndproc_stage.load(std::memory_order_acquire);
            UINT wndproc_msg = g_wndproc_msg.load(std::memory_order_acquire);
            UINT_PTR wndproc_hwnd = g_wndproc_hwnd.load(std::memory_order_acquire);
            UINT_PTR wndproc_wparam = g_wndproc_wparam.load(std::memory_order_acquire);
            LONG_PTR wndproc_lparam = g_wndproc_lparam.load(std::memory_order_acquire);
            uint64_t dx11_enter = g_dx11_enter_tick_ms.load(std::memory_order_acquire);
            uint64_t present_enter = g_present_enter_tick_ms.load(std::memory_order_acquire);
            uint64_t dx11_age = (dx11_enter > 0 && now >= dx11_enter) ? (now - dx11_enter) : 0;
            uint64_t present_age = (present_enter > 0 && now >= present_enter) ? (now - present_enter) : 0;

            uint64_t age_ms = (last_tick > 0 && now >= last_tick) ? (now - last_tick) : 0;
            bool render_stalled = (last_tick > 0 && age_ms > kStallThresholdMs && frame == prev_frame
                                   && phase_id == prev_render_phase_id);

            if (render_stalled) {
                stall_streak++;
                const uint64_t peek_calls = g_peek_call_count.load(std::memory_order_acquire);
                const uint64_t peek_returns = g_peek_return_count.load(std::memory_order_acquire);
                const bool stuck_in_peek =
                    phase_name && std::strcmp(phase_name, "peek_message_call") == 0 &&
                    peek_calls > peek_returns;
                if (stuck_in_peek && now - last_peek_rescue_ms >= 1000) {
                    last_peek_rescue_ms = now;
                    ::SetLastError(0);
                    BOOL thread_posted = render_tid ? ::PostThreadMessageW(render_tid, WM_NULL, 0, 0) : FALSE;
                    DWORD thread_gle = ::GetLastError();
                    BOOL hwnd_posted = FALSE;
                    DWORD hwnd_gle = 0;
                    HWND rescue_hwnd = g_hwnd;
                    if (rescue_hwnd && ::IsWindow(rescue_hwnd)) {
                        ::SetLastError(0);
                        hwnd_posted = ::PostMessageW(rescue_hwnd, WM_NULL, 0, 0);
                        hwnd_gle = ::GetLastError();
                        ::InvalidateRect(rescue_hwnd, nullptr, FALSE);
                    }
                    diag::log_tagged_critical_fmt("tracer",
                        "peek_rescue frame=%llu age_ms=%llu render_tid=%lu calls=%llu returns=%llu thread_posted=%d thread_gle=%lu hwnd=0x%llX hwnd_posted=%d hwnd_gle=%lu qs=0x%08lX flags=0x%08X",
                        static_cast<unsigned long long>(frame),
                        static_cast<unsigned long long>(age_ms),
                        render_tid,
                        static_cast<unsigned long long>(peek_calls),
                        static_cast<unsigned long long>(peek_returns),
                        thread_posted ? 1 : 0,
                        static_cast<unsigned long>(thread_gle),
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(rescue_hwnd)),
                        hwnd_posted ? 1 : 0,
                        static_cast<unsigned long>(hwnd_gle),
                        static_cast<unsigned long>(peek_status),
                        g_peek_remove_flags.load(std::memory_order_acquire));
                }
                if (stall_streak == 1 || (stall_streak % 20ULL) == 0ULL) {
                    char stall_context[4600] = {};
                    format_message_pump_stall_context(stall_context, sizeof(stall_context));
                    diag::log_tagged_critical_fmt("tracer",
                        "RENDER_STALL streak=%llu frame=%llu age_ms=%llu phase=%s section=%s phase_id=%llu render_tid=%lu attach=%s attach_id=%llu peek_qs=0x%08lX peek_gle=%lu peek_flags=0x%08X peek_filter=0x%llX send_only_defers=%llu send_only_flushes=%llu dispatch=%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX wndproc=%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX dx_frame=%llu dx_age_ms=%llu dx_dd=0x%llX dx_dev=0x%llX dx_ctx=0x%llX dx_rtv=0x%llX dx_lists=%llu dx_draw_cmds=%llu dx_vtx=%llu dx_idx=%llu dx_callbacks=%llu dx_reset_callbacks=%llu dx_first_cb=0x%llX dx_cb_data=0x%llX dx_first_tex=0x%llX dx_tex_hash=0x%016llX dx_max_elem=%llu dx_bad=0x%08lX dx_bad_at=%d,%d dx_disp1000=%d,%d dx_fb1000=%d,%d dx_removed=0x%08lX present_frame=%llu present_age_ms=%llu present_sc=0x%llX present_hr=0x%08lX tracer_tid=%lu ctx={%.3600s}",
                        (unsigned long long)stall_streak,
                        (unsigned long long)frame,
                        (unsigned long long)age_ms,
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        (unsigned long long)phase_id,
                        render_tid,
                        attach_phase ? attach_phase : "<null>",
                        (unsigned long long)attach_phase_id,
                        static_cast<unsigned long>(peek_status),
                        static_cast<unsigned long>(peek_error),
                        g_peek_remove_flags.load(std::memory_order_acquire),
                        static_cast<unsigned long long>(g_peek_filter_hwnd.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_peek_send_only_defers.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_peek_send_only_flushes.load(std::memory_order_acquire)),
                        dispatch_stage ? dispatch_stage : "<null>",
                        message_name(dispatch_msg),
                        dispatch_msg,
                        (unsigned long long)dispatch_hwnd,
                        (unsigned long long)dispatch_wparam,
                        (unsigned long long)dispatch_lparam,
                        wndproc_stage ? wndproc_stage : "<null>",
                        message_name(wndproc_msg),
                        wndproc_msg,
                        (unsigned long long)wndproc_hwnd,
                        (unsigned long long)wndproc_wparam,
                        (unsigned long long)wndproc_lparam,
                        static_cast<unsigned long long>(g_dx11_frame.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(dx11_age),
                        static_cast<unsigned long long>(g_dx11_draw_data.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_device.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_context.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_rtv.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_cmd_lists.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_draw_cmd_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_vtx_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_idx_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_user_callback_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_reset_callback_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_first_callback.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_first_callback_data.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_first_texture.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_texture_hash.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_dx11_max_elem_count.load(std::memory_order_acquire)),
                        static_cast<unsigned long>(g_dx11_bad_flags.load(std::memory_order_acquire)),
                        g_dx11_bad_list.load(std::memory_order_acquire),
                        g_dx11_bad_cmd.load(std::memory_order_acquire),
                        g_dx11_display_w1000.load(std::memory_order_acquire),
                        g_dx11_display_h1000.load(std::memory_order_acquire),
                        g_dx11_fb_scale_w1000.load(std::memory_order_acquire),
                        g_dx11_fb_scale_h1000.load(std::memory_order_acquire),
                        static_cast<unsigned long>(g_dx11_device_removed.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_present_frame.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(present_age),
                        static_cast<unsigned long long>(g_present_swapchain.load(std::memory_order_acquire)),
                        static_cast<unsigned long>(g_present_hr.load(std::memory_order_acquire)),
                        GetCurrentThreadId(),
                        stall_context[0] ? stall_context : "<empty>");
                    const bool shutdown_context = is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg);
                    const bool sustained_hang = age_ms >= 10000ULL && (stall_streak == 32ULL || (stall_streak % 120ULL) == 0ULL);
                    if (render_tid != 0 && sustained_hang && !shutdown_context)
                        capture_render_thread_snapshot(render_tid, age_ms);
                }
                static uint64_t s_last_dbghelp_recovery_ms = 0;
                const bool render_disasm_section = render_section &&
                    std::strcmp(render_section, "center_view_disassembly") == 0;
                const bool dbghelp_in_progress = pdb_parser::g_dbghelp_load_state.in_progress;
                const uint64_t dbghelp_started_ms = pdb_parser::g_dbghelp_load_state.started_ms;
                const uint64_t dbghelp_owner_age_ms = (dbghelp_in_progress && dbghelp_started_ms != 0 && now >= dbghelp_started_ms)
                    ? (now - dbghelp_started_ms)
                    : 0ULL;
                const bool dbghelp_actually_stuck = dbghelp_in_progress && dbghelp_owner_age_ms > 30000ULL;
                const bool dbghelp_recovery_eligible = age_ms > 60000ULL && render_disasm_section && dbghelp_actually_stuck &&
                    !is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg);
                if (dbghelp_recovery_eligible && (s_last_dbghelp_recovery_ms == 0 ||
                                                  now - s_last_dbghelp_recovery_ms >= 30000ULL)) {
                    s_last_dbghelp_recovery_ms = now;
                    const bool quarantined_before = pdb_parser::dbghelp_is_quarantined();
                    bool quarantine_triggered = false;
                    if (!quarantined_before) {
                        pdb_parser::quarantine_dbghelp_and_recycle();
                        quarantine_triggered = true;
                    }
                    HWND rescue_hwnd = g_hwnd;
                    BOOL nudge_posted = FALSE;
                    DWORD nudge_gle = 0;
                    if (rescue_hwnd && ::IsWindow(rescue_hwnd)) {
                        ::SetLastError(0);
                        nudge_posted = ::PostMessageW(rescue_hwnd, WM_NULL, 0, 0);
                        nudge_gle = ::GetLastError();
                        ::InvalidateRect(rescue_hwnd, nullptr, FALSE);
                    }
                    diag::log_tagged_critical_fmt("tracer",
                        "render_stall_recovery_attempt age_ms=%llu phase=%s section=%s render_tid=%lu dbghelp_in_progress=%d dbghelp_owner_age_ms=%llu quarantine_triggered=%d quarantined_before=%d nudge_posted=%d nudge_gle=%lu",
                        static_cast<unsigned long long>(age_ms),
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        render_tid,
                        dbghelp_in_progress ? 1 : 0,
                        static_cast<unsigned long long>(dbghelp_owner_age_ms),
                        quarantine_triggered ? 1 : 0,
                        quarantined_before ? 1 : 0,
                        nudge_posted ? 1 : 0,
                        static_cast<unsigned long>(nudge_gle));
                } else if (age_ms > 60000ULL && render_disasm_section &&
                           !is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg) &&
                           (s_last_dbghelp_recovery_ms == 0 ||
                            now - s_last_dbghelp_recovery_ms >= 30000ULL)) {
                    s_last_dbghelp_recovery_ms = now;
                    diag::log_tagged_critical_fmt("tracer",
                        "render_stall_recovery_skipped age_ms=%llu phase=%s section=%s render_tid=%lu reason=dbghelp_not_in_flight dbghelp_in_progress=%d dbghelp_owner_age_ms=%llu",
                        static_cast<unsigned long long>(age_ms),
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        render_tid,
                        dbghelp_in_progress ? 1 : 0,
                        static_cast<unsigned long long>(dbghelp_owner_age_ms));
                }
            } else {
                stall_streak = 0;
            }

            prev_frame = frame;
            prev_render_phase_id = phase_id;
        }
    }

    inline void start() {
        diag::log_tagged_critical("tracer", "tracer_thread_starting");
        startup_log_critical_fmt("tracer_thread_post_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        bool posted = work_queue::post_service_labeled("render_tracer", []() {
            startup_log_critical_fmt("tracer_thread_entry pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            run_tracer_thread();
            startup_log_critical_fmt("tracer_thread_exit pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        startup_log_critical_fmt("tracer_thread_post_post posted=%d pid=%lu tid=%lu tick=%llu",
            posted ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        diag::log_tagged_critical("tracer", "tracer_thread_started");
    }
}

namespace aida_focus_monitor {
    inline std::atomic<bool> g_focused{true};
    inline std::atomic<bool> g_stop{false};

    inline bool foreground_belongs_to_process(HWND hwnd) {
        HWND fg = ::GetForegroundWindow();
        if (!fg) return false;
        if (fg == hwnd) return true;
        DWORD pid = 0;
        ::GetWindowThreadProcessId(fg, &pid);
        return pid == ::GetCurrentProcessId();
    }

    inline void start(HWND hwnd) {
        const uint64_t start_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("focus_monitor_start_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(start_tick));
        g_stop.store(false, std::memory_order_release);
        g_focused.store(foreground_belongs_to_process(hwnd), std::memory_order_release);
        bool posted = work_queue::post_service_labeled("focus_monitor", [hwnd]() {
            startup_log_critical_fmt("focus_monitor_worker_enter hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            while (!g_stop.load(std::memory_order_acquire)) {
                g_focused.store(foreground_belongs_to_process(hwnd), std::memory_order_release);
                ::Sleep(200);
            }
            startup_log_critical_fmt("focus_monitor_worker_exit hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        startup_log_critical_fmt("focus_monitor_start_post posted=%d focused=%d elapsed_ms=%llu hwnd=0x%llX",
            posted ? 1 : 0,
            g_focused.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_tick),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
    }

    inline void stop() {
        g_stop.store(true, std::memory_order_release);
    }

    inline bool focused() {
        return g_focused.load(std::memory_order_acquire);
    }
}

static void format_tracer_crash_snapshot(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    POINT cursor{};
    GetCursorPos(&cursor);
    int imgui_ctx = 0;
    int imgui_frame = -1;
    __try {
        imgui_ctx = ImGui::GetCurrentContext() ? 1 : 0;
        if (imgui_ctx)
            imgui_frame = ImGui::GetFrameCount();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        imgui_ctx = -1;
        imgui_frame = -2;
    }
    const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
    const char* render_section = g_render_section.c_str();
    const char* dispatch_stage = aida_tracer::g_dispatch_stage.load(std::memory_order_acquire);
    const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
    _snprintf_s(out, cap, _TRUNCATE,
        "render_frame=%llu render_tick=%llu render_phase=%s render_section=%s render_tid=%lu "
        "peek_qs=0x%08lX peek_gle=%lu peek_flags=0x%08X peek_filter=0x%llX peek_calls=%llu peek_returns=%llu send_only_defers=%llu send_only_flushes=%llu "
        "dispatch_stage=%s dispatch_msg=%s(0x%04X) dispatch_hwnd=0x%llX dispatch_wp=0x%llX dispatch_lp=0x%llX dispatch_enter=%llu dispatch_exit=%llu "
        "wndproc_stage=%s wndproc_msg=%s(0x%04X) wndproc_hwnd=0x%llX wndproc_wp=0x%llX wndproc_lp=0x%llX wnd_enter=%llu wnd_exit=%llu "
        "dx_frame=%llu dx_dd=0x%llX dx_dev=0x%llX dx_ctx=0x%llX dx_rtv=0x%llX dx_lists=%llu dx_draw_cmds=%llu dx_vtx=%llu dx_idx=%llu dx_callbacks=%llu dx_bad=0x%08lX dx_bad_at=%d,%d dx_removed=0x%08lX "
        "present_frame=%llu present_sc=0x%llX present_hr=0x%08lX imgui_ctx=%d imgui_frame=%d cursor=%ld,%ld buttons=0x%04X fg=0x%llX active=0x%llX focus=0x%llX capture=0x%llX",
        static_cast<unsigned long long>(aida_tracer::g_render_frame.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_render_last_tick_ms.load(std::memory_order_acquire)),
        render_phase ? render_phase : "<null>",
        render_section ? render_section : "<null>",
        aida_tracer::g_render_thread_id.load(std::memory_order_acquire),
        static_cast<unsigned long>(aida_tracer::g_peek_queue_status.load(std::memory_order_acquire)),
        static_cast<unsigned long>(aida_tracer::g_peek_last_error.load(std::memory_order_acquire)),
        aida_tracer::g_peek_remove_flags.load(std::memory_order_acquire),
        static_cast<unsigned long long>(aida_tracer::g_peek_filter_hwnd.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_peek_call_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_peek_return_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_peek_send_only_defers.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_peek_send_only_flushes.load(std::memory_order_acquire)),
        dispatch_stage ? dispatch_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_dispatch_msg.load(std::memory_order_acquire)),
        aida_tracer::g_dispatch_msg.load(std::memory_order_acquire),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_hwnd.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_wparam.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_lparam.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_enter_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dispatch_exit_count.load(std::memory_order_acquire)),
        wndproc_stage ? wndproc_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_wndproc_msg.load(std::memory_order_acquire)),
        aida_tracer::g_wndproc_msg.load(std::memory_order_acquire),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_hwnd.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_wparam.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_lparam.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_enter_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_wndproc_exit_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_frame.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_draw_data.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_device.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_context.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_rtv.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_cmd_lists.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_draw_cmd_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_vtx_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_idx_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_dx11_user_callback_count.load(std::memory_order_acquire)),
        static_cast<unsigned long>(aida_tracer::g_dx11_bad_flags.load(std::memory_order_acquire)),
        aida_tracer::g_dx11_bad_list.load(std::memory_order_acquire),
        aida_tracer::g_dx11_bad_cmd.load(std::memory_order_acquire),
        static_cast<unsigned long>(aida_tracer::g_dx11_device_removed.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_present_frame.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(aida_tracer::g_present_swapchain.load(std::memory_order_acquire)),
        static_cast<unsigned long>(aida_tracer::g_present_hr.load(std::memory_order_acquire)),
        imgui_ctx,
        imgui_frame,
        cursor.x,
        cursor.y,
        static_cast<unsigned>((GetAsyncKeyState(VK_LBUTTON) & 0x8000 ? 1u : 0u) |
            (GetAsyncKeyState(VK_RBUTTON) & 0x8000 ? 2u : 0u) |
            (GetAsyncKeyState(VK_MBUTTON) & 0x8000 ? 4u : 0u) |
            (GetAsyncKeyState(VK_XBUTTON1) & 0x8000 ? 8u : 0u) |
            (GetAsyncKeyState(VK_XBUTTON2) & 0x8000 ? 16u : 0u)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetForegroundWindow())),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetActiveWindow())),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetFocus())),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetCapture())));
}

namespace aida_shutdown_diag {
    inline std::atomic<const char*> g_phase{"running"};
    inline std::atomic<uint64_t> g_phase_tick_ms{0};

    inline void mark(const char* phase)
    {
        const char* value = phase ? phase : "<null>";
        g_phase.store(value, std::memory_order_release);
        g_phase_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        diag::log_tagged_critical_fmt("shutdown",
            "phase=%s pid=%lu tid=%lu tick=%llu",
            value,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
    }

    inline uint64_t phase_age_ms()
    {
        const uint64_t tick = g_phase_tick_ms.load(std::memory_order_acquire);
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        return tick != 0 && now >= tick ? now - tick : 0;
    }
}

static void run_phase_1_2_self_tests()
{
    crash_log_write("phase_1_2_test:start");

    {
        int visited[4] = {0, 0, 0, 0};
        int order[8] = {0};
        int order_pos = 0;
        CFF_BEGIN(p12_test_a)
        CFF_STATE(p12_test_a, 0)
        {
            visited[0]++;
            if (order_pos < 8) order[order_pos++] = 0;
            CFF_GOTO(p12_test_a, 1);
        }
        CFF_STATE(p12_test_a, 1)
        {
            visited[1]++;
            if (order_pos < 8) order[order_pos++] = 1;
            CFF_GOTO(p12_test_a, 2);
        }
        CFF_STATE(p12_test_a, 2)
        {
            visited[2]++;
            if (order_pos < 8) order[order_pos++] = 2;
            CFF_GOTO(p12_test_a, 3);
        }
        CFF_STATE(p12_test_a, 3)
        {
            visited[3]++;
            if (order_pos < 8) order[order_pos++] = 3;
            CFF_EXIT(p12_test_a);
        }
        CFF_END(p12_test_a)

        bool ok = visited[0] == 1 && visited[1] == 1 && visited[2] == 1 && visited[3] == 1;
        crash_log_fmt("phase_1_2_test:cff_exec ok=%d v=[%d,%d,%d,%d] order=[%d,%d,%d,%d]",
                      ok ? 1 : 0,
                      visited[0], visited[1], visited[2], visited[3],
                      order[0], order[1], order[2], order[3]);
    }

    {
        anti_tamper::cff::detail::cff_ctx_t ctx =
            anti_tamper::cff::detail::init_ctx(0xA1B2C3D4E5F60718ULL);
        const uint64_t fixed_plain = 5;
        const int sample_count = 10;
        uint64_t samples[sample_count] = {};
        for (int i = 0; i < sample_count; ++i)
            samples[i] = anti_tamper::cff::detail::encrypt_state(ctx, fixed_plain);

        std::set<uint64_t> uniq;
        for (int i = 0; i < sample_count; ++i)
            uniq.insert(samples[i]);

        bool all_distinct = uniq.size() == static_cast<size_t>(sample_count);
        crash_log_fmt(
            "phase_1_2_test:cff_distinctness all_distinct=%d unique=%zu of %d",
            all_distinct ? 1 : 0, uniq.size(), sample_count);
        for (int i = 0; i < sample_count; ++i)
            crash_log_fmt("phase_1_2_test:cff_sample [%d]=0x%016llX", i,
                          static_cast<unsigned long long>(samples[i]));
    }

    {
        const uint64_t seed = 0xC0DECAFE5EEDB001ULL;
        const uint8_t plaintext[16] = {
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x11
        };
        uint8_t encrypted[16] = {};
        uint8_t decrypted[16] = {};

        anti_tamper::virtualizer::detail::cipher_stream_t enc_s;
        anti_tamper::virtualizer::detail::cipher_stream_init(enc_s, seed);
        for (int i = 0; i < 16; ++i)
            encrypted[i] = anti_tamper::virtualizer::detail::cipher_stream_xcrypt(enc_s, plaintext[i], true);

        anti_tamper::virtualizer::detail::cipher_stream_t dec_s;
        anti_tamper::virtualizer::detail::cipher_stream_init(dec_s, seed);
        for (int i = 0; i < 16; ++i)
            decrypted[i] = anti_tamper::virtualizer::detail::cipher_stream_xcrypt(dec_s, encrypted[i], false);

        bool roundtrip_ok = memcmp(plaintext, decrypted, 16) == 0;

        uint64_t old_key = seed;
        uint8_t old_xor_stream[16] = {};
        for (int i = 0; i < 16; ++i)
        {
            old_xor_stream[i] = static_cast<uint8_t>(old_key & 0xFF);
            old_key ^= old_key << 13;
            old_key ^= old_key >> 7;
            old_key ^= old_key << 17;
        }

        bool differs_from_old = false;
        uint8_t new_keystream[16];
        for (int i = 0; i < 16; ++i)
            new_keystream[i] = static_cast<uint8_t>(plaintext[i] ^ encrypted[i]);
        for (int i = 0; i < 16; ++i)
        {
            if (new_keystream[i] != old_xor_stream[i])
            {
                differs_from_old = true;
                break;
            }
        }

        bool input_dependent = false;
        {
            uint8_t alt_plain[16];
            memcpy(alt_plain, plaintext, 16);
            alt_plain[0] ^= 0xFF;
            uint8_t alt_enc[16];
            anti_tamper::virtualizer::detail::cipher_stream_t alt_s;
            anti_tamper::virtualizer::detail::cipher_stream_init(alt_s, seed);
            for (int i = 0; i < 16; ++i)
                alt_enc[i] = anti_tamper::virtualizer::detail::cipher_stream_xcrypt(alt_s, alt_plain[i], true);
            uint8_t alt_keystream[16];
            for (int i = 0; i < 16; ++i)
                alt_keystream[i] = static_cast<uint8_t>(alt_plain[i] ^ alt_enc[i]);

            for (int i = 1; i < 16; ++i)
            {
                if (alt_keystream[i] != new_keystream[i])
                {
                    input_dependent = true;
                    break;
                }
            }
        }

        crash_log_fmt(
            "phase_1_2_test:vm_stream roundtrip=%d diff_from_old_xor=%d input_dependent=%d",
            roundtrip_ok ? 1 : 0,
            differs_from_old ? 1 : 0,
            input_dependent ? 1 : 0);

        char enc_hex[64] = {};
        char old_hex[64] = {};
        char new_hex[64] = {};
        for (int i = 0; i < 16; ++i)
        {
            _snprintf_s(enc_hex + i * 2, sizeof(enc_hex) - i * 2, _TRUNCATE,
                        "%02X", encrypted[i]);
            _snprintf_s(old_hex + i * 2, sizeof(old_hex) - i * 2, _TRUNCATE,
                        "%02X", old_xor_stream[i]);
            _snprintf_s(new_hex + i * 2, sizeof(new_hex) - i * 2, _TRUNCATE,
                        "%02X", new_keystream[i]);
        }
        crash_log_fmt("phase_1_2_test:vm_stream encrypted=%s", enc_hex);
        crash_log_fmt("phase_1_2_test:vm_stream old_xor_ks=%s", old_hex);
        crash_log_fmt("phase_1_2_test:vm_stream new_ks=%s", new_hex);
    }

    crash_log_write("phase_1_2_test:done");
}

static std::wstring widen_message_text(const std::string& text)
{
    if (text.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (len <= 0) return std::wstring(text.begin(), text.end());
    std::wstring out;
    out.resize(static_cast<size_t>(len));
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), len);
    return out;
}

static void show_ban_refuse_ui_and_exit(const std::string& reason, const std::string& message)
{
    std::wstring final_message = widen_message_text(message.empty()
        ? std::string("AiDA cannot start because this machine or network is banned.")
        : message);
    if (!reason.empty()) {
        final_message += L"\n\nCode: ";
        final_message += widen_message_text(reason);
    }
    MessageBoxW(nullptr, final_message.c_str(), L"AiDA",
        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
    ExitProcess(1);
}

static std::string mcp_posture_refusal_detail(const anti_tamper::mcp_posture::report_t& report)
{
    const anti_tamper::mcp_posture::finding_t* denied = nullptr;
    std::size_t denied_count = 0;
    for (const auto& finding : report.findings) {
        if (!finding.deny)
            continue;
        if (!denied)
            denied = &finding;
        ++denied_count;
    }
    if (!denied)
        return {};
    std::ostringstream out;
    out << "Detected MCP entry:";
    if (!denied->source.empty())
        out << "\nSource: " << denied->source;
    if (!denied->config_path.empty())
        out << "\nConfig: " << denied->config_path;
    if (!denied->server_name.empty())
        out << "\nServer: " << denied->server_name;
    out << "\nTransport: " << anti_tamper::mcp_posture::detail::transport_name(denied->transport);
    if (!denied->reason.empty())
        out << "\nReason: " << denied->reason;
    if (!denied->command.empty())
        out << "\nCommand: " << denied->command;
    if (!denied->url.empty())
        out << "\nURL: " << denied->url;
    if (!denied->remediation.empty())
        out << "\n\nAction: " << denied->remediation;
    if (denied_count > 1)
        out << "\n\nAdditional denied MCP entries: " << (denied_count - 1);
    return out.str();
}

static void show_mcp_posture_refuse_ui_and_exit(const anti_tamper::mcp_posture::report_t& report)
{
    char summary[64] = {};
    _snprintf_s(summary, sizeof(summary), _TRUNCATE, "0x%016llX",
        static_cast<unsigned long long>(report.summary_hash));
    startup_log_critical_fmt("mcp_posture_refuse_ui_enter trusted=%d denied=%d latched=%d summary_hash=%s reason_hash=0x%016llX",
        report.trusted ? 1 : 0,
        report.denied ? 1 : 0,
        report.latched ? 1 : 0,
        summary,
        static_cast<unsigned long long>(diag_fnv1a64(report.reason.data(), report.reason.size())));
    crash_log_fmt("mcp_posture_refuse summary_hash=%s", summary);
    std::wstring final_message = L"AiDA cannot start because untrusted or suspicious MCP tooling is configured on this system.";
    const std::string detail = mcp_posture_refusal_detail(report);
    if (!detail.empty()) {
        const auto denied = std::find_if(report.findings.begin(), report.findings.end(), [](const auto& f) { return f.deny; });
        if (denied != report.findings.end()) {
            startup_log_critical_fmt("mcp_posture_refuse_detail source=%s server=%s reason=%s config=%s command=%s url=%s",
                denied->source.c_str(),
                denied->server_name.c_str(),
                denied->reason.c_str(),
                denied->config_path.c_str(),
                denied->command.c_str(),
                denied->url.c_str());
        }
        final_message += L"\n\n";
        final_message += widen_message_text(detail);
    }
    final_message += L"\n\nCode: mcp_posture_untrusted";
    final_message += L"\nSummary: ";
    final_message += widen_message_text(summary);
    MessageBoxW(nullptr, final_message.c_str(), L"AiDA",
        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
    std::string extra = std::string("mcp_posture_untrusted summary_hash=") + summary;
    anti_tamper::enforce_violation_id(
        aida::reason_ids::reason_id_from_string("mcp_posture_untrusted"),
        extra);
    ExitProcess(1);
}

__declspec(noinline) static DWORD cpp_render_title(helpers* h, uint64_t frame_number, ImGuiErrorRecoveryState* imgui_state_backup)
{
    try {
        h->render_title();
    } catch (const std::exception& e) {
        ImGui::ErrorRecoveryTryToRecoverState(imgui_state_backup);
        diag::log_tagged_critical_fmt("render",
            "CPP_in_render_title frame=%llu section=%s what=%s",
            (unsigned long long)frame_number,
            g_render_section.c_str(),
            e.what());
        return 0xE06D7363u;
    } catch (...) {
        ImGui::ErrorRecoveryTryToRecoverState(imgui_state_backup);
        diag::log_tagged_critical_fmt("render",
            "CPP_in_render_title frame=%llu section=%s what=<unknown>",
            (unsigned long long)frame_number,
            g_render_section.c_str());
        return 0xE06D7363u;
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_title(helpers* h, uint64_t frame_number)
{
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);

    __try {
        return cpp_render_title(h, frame_number, &imgui_state_backup);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
}

__declspec(noinline) static DWORD seh_render_source_reconstruct(uint64_t frame_number)
{
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);
    __try {
        source_reconstruct_view::render(1.0f, globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_toast(uint64_t frame_number)
{
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);
    __try {
        toast_notification::render();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_imgui_render()
{
    __try {
        ImGui::Render();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_imgui_dx11_render(ImDrawData* dd, uint64_t frame_number)
{
    HRESULT removed = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
    aida_tracer::set_dx11_draw_state("imgui_dx11_render_enter",
        frame_number,
        dd,
        g_pd3dDevice,
        g_pd3dDeviceContext,
        g_mainRenderTargetView,
        removed);
    __try {
        removed = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
        aida_tracer::set_dx11_draw_state("imgui_dx11_render_call",
            frame_number,
            dd,
            g_pd3dDevice,
            g_pd3dDeviceContext,
            g_mainRenderTargetView,
            removed);
        uint32_t draw_bad = aida_tracer::inspect_dx11_draw_data(dd, frame_number);
        if (draw_bad != 0) {
            diag::log_tagged_critical_fmt("render",
                "imgui_dx11_render_skipped_invalid_draw_data frame=%llu bad=0x%08lX",
                static_cast<unsigned long long>(frame_number),
                static_cast<unsigned long>(draw_bad));
            aida_tracer::set_dx11_draw_state("imgui_dx11_render_invalid_skip",
                frame_number,
                dd,
                g_pd3dDevice,
                g_pd3dDeviceContext,
                g_mainRenderTargetView,
                removed);
            return 0;
        }
        ImGui_ImplDX11_RenderDrawData(dd);
        removed = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
        aida_tracer::set_dx11_draw_state("imgui_dx11_render_returned",
            frame_number,
            dd,
            g_pd3dDevice,
            g_pd3dDeviceContext,
            g_mainRenderTargetView,
            removed);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        removed = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
        aida_tracer::set_dx11_draw_state("imgui_dx11_render_seh",
            frame_number,
            dd,
            g_pd3dDevice,
            g_pd3dDeviceContext,
            g_mainRenderTargetView,
            removed);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_imgui_new_frame()
{
    __try {
        ImGui::NewFrame();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_dx11_new_frame()
{
    __try {
        ImGui_ImplDX11_NewFrame();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_win32_new_frame()
{
    __try {
        ImGui_ImplWin32_NewFrame();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_swapchain_present(IDXGISwapChain* sc, HRESULT* hr_out, uint64_t frame_number)
{
    aida_tracer::set_present_state("present_enter", frame_number, sc, hr_out ? *hr_out : E_POINTER);
    if (!sc || !hr_out) {
        if (hr_out)
            *hr_out = E_POINTER;
        aida_tracer::set_present_state("present_missing_pointer", frame_number, sc, E_POINTER);
        return 0;
    }
    __try {
        aida_tracer::set_present_state("present_call", frame_number, sc, hr_out ? *hr_out : E_POINTER);
        *hr_out = sc->Present(kAidaPresentSyncInterval, kAidaPresentFlags);
        aida_tracer::set_present_state("present_returned", frame_number, sc, *hr_out);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida_tracer::set_present_state("present_seh", frame_number, sc, hr_out ? *hr_out : E_POINTER);
        return GetExceptionCode();
    }
    return 0;
}

static void configure_frame_latency_waitable()
{
    if (g_FrameLatencyWaitableObject) {
        CloseHandle(g_FrameLatencyWaitableObject);
        g_FrameLatencyWaitableObject = nullptr;
    }
    if (!g_pSwapChain)
        return;
    IDXGISwapChain2* sc2 = nullptr;
    HRESULT qi = g_pSwapChain->QueryInterface(__uuidof(IDXGISwapChain2), reinterpret_cast<void**>(&sc2));
    if (FAILED(qi) || !sc2) {
        diag::log_tagged_fmt("render", "frame_latency_waitable_unavailable qi=0x%08X", static_cast<unsigned>(qi));
        return;
    }
    HRESULT set_hr = sc2->SetMaximumFrameLatency(1);
    HANDLE waitable = sc2->GetFrameLatencyWaitableObject();
    if (SUCCEEDED(set_hr) && waitable) {
        g_FrameLatencyWaitableObject = waitable;
        diag::log_tagged_critical_fmt("render", "frame_latency_waitable_enabled handle=0x%llX set_hr=0x%08X flags=0x%08X",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(waitable)),
            static_cast<unsigned>(set_hr),
            g_SwapChainResizeFlags);
    } else {
        diag::log_tagged_fmt("render", "frame_latency_waitable_disabled set_hr=0x%08X handle=0x%llX flags=0x%08X",
            static_cast<unsigned>(set_hr),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(waitable)),
            g_SwapChainResizeFlags);
    }
    sc2->Release();
}

static bool aida_cursor_over_window(HWND hwnd)
{
    if (!hwnd || !::IsWindow(hwnd))
        return false;
    POINT cursor{};
    if (!::GetCursorPos(&cursor))
        return false;
    RECT rc{};
    if (!::GetWindowRect(hwnd, &rc))
        return false;
    return ::PtInRect(&rc, cursor) != FALSE;
}

__declspec(noinline) static DWORD seh_resize_buffers(IDXGISwapChain* sc, UINT w, UINT h, HRESULT* hr_out, uint64_t frame_number, const char* source)
{
    if (hr_out)
        *hr_out = E_POINTER;
    if (!sc || !hr_out) {
        diag::log_tagged_critical_fmt("render",
            "resize_missing_pointer source=%s frame=%llu sc=0x%llX hr_out=0x%llX w=%u h=%u",
            source ? source : "<null>",
            static_cast<unsigned long long>(frame_number),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(sc)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hr_out)),
            w,
            h);
        return 0;
    }
    __try {
        *hr_out = sc->ResizeBuffers(0, w, h, DXGI_FORMAT_UNKNOWN, g_SwapChainResizeFlags);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    diag::log_tagged_critical_fmt("render",
        "resize_buffers_result source=%s frame=%llu w=%u h=%u hr=0x%08X",
        source ? source : "<null>",
        static_cast<unsigned long long>(frame_number),
        w,
        h,
        static_cast<unsigned>(*hr_out));
    return 0;
}

static void release_gpu_frame_queries()
{
    if (g_gpu_frame_query.end) { g_gpu_frame_query.end->Release(); g_gpu_frame_query.end = nullptr; }
    if (g_gpu_frame_query.begin) { g_gpu_frame_query.begin->Release(); g_gpu_frame_query.begin = nullptr; }
    if (g_gpu_frame_query.disjoint) { g_gpu_frame_query.disjoint->Release(); g_gpu_frame_query.disjoint = nullptr; }
    g_gpu_frame_query = {};
}

static void initialize_gpu_frame_queries()
{
    release_gpu_frame_queries();
    if (!g_pd3dDevice || !g_pd3dDeviceContext)
        return;
    D3D11_QUERY_DESC desc{};
    desc.Query = D3D11_QUERY_TIMESTAMP_DISJOINT;
    HRESULT hr_disjoint = g_pd3dDevice->CreateQuery(&desc, &g_gpu_frame_query.disjoint);
    desc.Query = D3D11_QUERY_TIMESTAMP;
    HRESULT hr_begin = SUCCEEDED(hr_disjoint) ? g_pd3dDevice->CreateQuery(&desc, &g_gpu_frame_query.begin) : hr_disjoint;
    HRESULT hr_end = SUCCEEDED(hr_begin) ? g_pd3dDevice->CreateQuery(&desc, &g_gpu_frame_query.end) : hr_begin;
    HRESULT hr = FAILED(hr_disjoint) ? hr_disjoint : (FAILED(hr_begin) ? hr_begin : hr_end);
    g_gpu_frame_query.create_hr = hr;
    g_gpu_frame_query.last.create_hr = hr;
    if (FAILED(hr) || !g_gpu_frame_query.disjoint || !g_gpu_frame_query.begin || !g_gpu_frame_query.end) {
        diag::log_tagged_fmt("render",
            "gpu_frame_query_unavailable hr=0x%08X disjoint=0x%llX begin=0x%llX end=0x%llX device=0x%llX ctx=0x%llX",
            static_cast<unsigned>(hr),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_gpu_frame_query.disjoint)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_gpu_frame_query.begin)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_gpu_frame_query.end)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)));
        release_gpu_frame_queries();
        g_gpu_frame_query.create_hr = hr;
        g_gpu_frame_query.last.create_hr = hr;
    }
}

static void collect_gpu_frame_query(uint64_t frame_number)
{
    if (!g_gpu_frame_query.pending || !g_pd3dDeviceContext ||
        !g_gpu_frame_query.disjoint || !g_gpu_frame_query.begin || !g_gpu_frame_query.end)
        return;
    D3D11_QUERY_DATA_TIMESTAMP_DISJOINT disjoint{};
    UINT64 begin_ts = 0;
    UINT64 end_ts = 0;
    HRESULT hr_disjoint = g_pd3dDeviceContext->GetData(g_gpu_frame_query.disjoint, &disjoint, sizeof(disjoint), D3D11_ASYNC_GETDATA_DONOTFLUSH);
    if (hr_disjoint == S_FALSE) {
        ++g_gpu_frame_query.misses;
        g_gpu_frame_query.last.pending = true;
        g_gpu_frame_query.last.misses = g_gpu_frame_query.misses;
        return;
    }
    HRESULT hr_begin = SUCCEEDED(hr_disjoint) ? g_pd3dDeviceContext->GetData(g_gpu_frame_query.begin, &begin_ts, sizeof(begin_ts), D3D11_ASYNC_GETDATA_DONOTFLUSH) : hr_disjoint;
    if (hr_begin == S_FALSE) {
        ++g_gpu_frame_query.misses;
        g_gpu_frame_query.last.pending = true;
        g_gpu_frame_query.last.misses = g_gpu_frame_query.misses;
        return;
    }
    HRESULT hr_end = SUCCEEDED(hr_begin) ? g_pd3dDeviceContext->GetData(g_gpu_frame_query.end, &end_ts, sizeof(end_ts), D3D11_ASYNC_GETDATA_DONOTFLUSH) : hr_begin;
    if (hr_end == S_FALSE) {
        ++g_gpu_frame_query.misses;
        g_gpu_frame_query.last.pending = true;
        g_gpu_frame_query.last.misses = g_gpu_frame_query.misses;
        return;
    }
    HRESULT hr = FAILED(hr_disjoint) ? hr_disjoint : (FAILED(hr_begin) ? hr_begin : hr_end);
    g_gpu_frame_query.pending = false;
    ++g_gpu_frame_query.samples;
    gpu_frame_sample_t sample{};
    sample.available = true;
    sample.create_hr = g_gpu_frame_query.create_hr;
    sample.data_hr = hr;
    sample.frame = g_gpu_frame_query.pending_frame;
    sample.ready_frame = frame_number;
    sample.frequency = disjoint.Frequency;
    sample.begin = begin_ts;
    sample.end = end_ts;
    sample.disjoint = disjoint.Disjoint != FALSE;
    sample.pending = false;
    sample.samples = g_gpu_frame_query.samples;
    sample.misses = g_gpu_frame_query.misses;
    sample.valid = SUCCEEDED(hr) && !sample.disjoint && sample.frequency != 0 && end_ts >= begin_ts;
    if (sample.valid)
        sample.gpu_ms = (static_cast<double>(end_ts - begin_ts) * 1000.0) / static_cast<double>(sample.frequency);
    g_gpu_frame_query.last = sample;
}

static void begin_gpu_frame_query(uint64_t frame_number)
{
    collect_gpu_frame_query(frame_number);
    if (g_gpu_frame_query.pending || g_gpu_frame_query.active || !g_pd3dDeviceContext ||
        !g_gpu_frame_query.disjoint || !g_gpu_frame_query.begin || !g_gpu_frame_query.end)
        return;
    g_pd3dDeviceContext->Begin(g_gpu_frame_query.disjoint);
    g_pd3dDeviceContext->End(g_gpu_frame_query.begin);
    g_gpu_frame_query.active = true;
    g_gpu_frame_query.active_frame = frame_number;
}

static void end_gpu_frame_query(uint64_t frame_number)
{
    if (!g_gpu_frame_query.active || !g_pd3dDeviceContext ||
        !g_gpu_frame_query.disjoint || !g_gpu_frame_query.begin || !g_gpu_frame_query.end)
        return;
    g_pd3dDeviceContext->End(g_gpu_frame_query.end);
    g_pd3dDeviceContext->End(g_gpu_frame_query.disjoint);
    g_gpu_frame_query.active = false;
    g_gpu_frame_query.pending = true;
    g_gpu_frame_query.pending_frame = g_gpu_frame_query.active_frame ? g_gpu_frame_query.active_frame : frame_number;
    g_gpu_frame_query.last.pending = true;
}

static gpu_frame_sample_t latest_gpu_frame_sample(uint64_t frame_number)
{
    collect_gpu_frame_query(frame_number);
    gpu_frame_sample_t sample = g_gpu_frame_query.last;
    sample.pending = g_gpu_frame_query.pending;
    sample.create_hr = g_gpu_frame_query.create_hr;
    sample.samples = g_gpu_frame_query.samples;
    sample.misses = g_gpu_frame_query.misses;
    return sample;
}

static void record_resize_recreate(const char* source, UINT w, UINT h, uint64_t frame_number)
{
    const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
    if (g_resize_perf.churn_window_start_ms == 0 || now_ms - g_resize_perf.churn_window_start_ms > kAidaResizeChurnWindowMs) {
        g_resize_perf.churn_window_start_ms = now_ms;
        g_resize_perf.churn_window_recreates = 0;
    }
    ++g_resize_perf.churn_window_recreates;
    if (g_resize_perf.churn_window_recreates >= kAidaResizeChurnThreshold &&
        now_ms - g_resize_perf.last_churn_log_ms >= kAidaResizeChurnWindowMs) {
        g_resize_perf.last_churn_log_ms = now_ms;
        diag::log_tagged_fmt("render",
            "resize_churn source=%s frame=%llu w=%u h=%u window_ms=%llu recreates=%u requests=%llu applied=%llu coalesced=%llu skipped=%llu rt_recreates=%llu blur_resizes=%llu",
            source ? source : "<null>",
            static_cast<unsigned long long>(frame_number),
            w,
            h,
            static_cast<unsigned long long>(now_ms - g_resize_perf.churn_window_start_ms),
            static_cast<unsigned>(g_resize_perf.churn_window_recreates),
            static_cast<unsigned long long>(g_resize_perf.requests),
            static_cast<unsigned long long>(g_resize_perf.applied),
            static_cast<unsigned long long>(g_resize_perf.coalesced),
            static_cast<unsigned long long>(g_resize_perf.skipped_redundant),
            static_cast<unsigned long long>(g_resize_perf.render_target_recreates),
            static_cast<unsigned long long>(g_resize_perf.blur_resize_calls));
    }
}

static bool resize_swapchain_and_target(UINT w, UINT h, uint64_t frame_number, const char* source)
{
    CleanupRenderTarget();
    HRESULT resize_hr = S_OK;
    DWORD resize_seh = seh_resize_buffers(g_pSwapChain, w, h, &resize_hr, frame_number, source);
    if (resize_seh != 0 || FAILED(resize_hr)) {
        diag::log_tagged_critical_fmt("render",
            "resize_failed source=%s frame=%llu w=%u h=%u seh=0x%08X hr=0x%08X device_removed=0x%08X",
            source ? source : "<null>",
            static_cast<unsigned long long>(frame_number),
            w,
            h,
            resize_seh,
            static_cast<unsigned>(resize_hr),
            static_cast<unsigned>(g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER));
        CreateRenderTarget();
        return false;
    }
    ++g_resize_perf.applied;
    CreateRenderTarget();
    record_resize_recreate(source, w, h, frame_number);
    return true;
}

__declspec(noinline) static DWORD seh_clear_main_render_target(ID3D11DeviceContext* ctx, ID3D11RenderTargetView* rtv, const float* color, HRESULT* removed_out, uint64_t frame_number)
{
    if (removed_out)
        *removed_out = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
    if (!ctx || !rtv || !color) {
        diag::log_tagged_critical_fmt("render",
            "clear_missing_pointer frame=%llu ctx=0x%llX rtv=0x%llX color=0x%llX device_removed=0x%08X",
            static_cast<unsigned long long>(frame_number),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ctx)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(rtv)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(color)),
            static_cast<unsigned>(removed_out ? *removed_out : E_POINTER));
        return ERROR_INVALID_HANDLE;
    }
    __try {
        ID3D11RenderTargetView* local_rtv = rtv;
        ctx->OMSetRenderTargets(1, &local_rtv, nullptr);
        ctx->ClearRenderTargetView(rtv, color);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        if (removed_out)
            *removed_out = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
        return GetExceptionCode();
    }
    if (removed_out)
        *removed_out = g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER;
    return 0;
}

__declspec(noinline) static DWORD seh_render_command_palette(uint64_t frame_number)
{
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);
    __try {
        aida::command_palette::render();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_agent_picker(uint64_t frame_number)
{
    ImGuiErrorRecoveryState imgui_state_backup;
    ImGui::ErrorRecoveryStoreState(&imgui_state_backup);
    __try {
        aida::agent_picker::render_if_open();
        if (aida::agent_picker::consume_manager_request()) {
            aida::settings_overlay::open();
            aida::settings_overlay::set_active_tab(aida::settings_overlay::tab_agents);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ImGui::ErrorRecoveryTryToRecoverState(&imgui_state_backup);
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static bool safe_read_qword(const void* p, uintptr_t& out)
{
    __try {
        out = *reinterpret_cast<const uintptr_t*>(p);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out = 0;
        return false;
    }
}

static const char* crash_basename_ptr(const char* path)
{
    if (!path)
        return "<none>";
    const char* slash = std::strrchr(path, '\\');
    const char* fwd = std::strrchr(path, '/');
    const char* base = slash && fwd ? (slash > fwd ? slash : fwd) : (slash ? slash : fwd);
    return base ? base + 1 : path;
}

static void format_current_thread_description(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    using get_thread_description_t = HRESULT(WINAPI*)(HANDLE, PWSTR*);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    auto fn = kernel ? reinterpret_cast<get_thread_description_t>(GetProcAddress(kernel, "GetThreadDescription")) : nullptr;
    if (!fn) {
        HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
        fn = kernelbase ? reinterpret_cast<get_thread_description_t>(GetProcAddress(kernelbase, "GetThreadDescription")) : nullptr;
    }
    if (!fn) {
        _snprintf_s(out, cap, _TRUNCATE, "<unavailable>");
        return;
    }
    PWSTR desc = nullptr;
    HRESULT hr = fn(GetCurrentThread(), &desc);
    if (SUCCEEDED(hr) && desc) {
        int wrote = WideCharToMultiByte(CP_UTF8, 0, desc, -1, out, static_cast<int>(cap), nullptr, nullptr);
        if (wrote <= 0)
            _snprintf_s(out, cap, _TRUNCATE, "<convert_failed gle=%lu>", GetLastError());
        LocalFree(desc);
        if (out[0] == 0)
            _snprintf_s(out, cap, _TRUNCATE, "<empty>");
        return;
    }
    _snprintf_s(out, cap, _TRUNCATE, "<hr=0x%08lX>", static_cast<unsigned long>(hr));
}

static void append_stack_module_token(char* out, size_t cap, int idx, uintptr_t value)
{
    if (!out || cap == 0)
        return;
    size_t len = 0;
    while (len < cap && out[len] != 0)
        ++len;
    if (len >= cap - 1)
        return;
    HMODULE mod = nullptr;
    char path[MAX_PATH] = {};
    const bool have_mod = value != 0 &&
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(value), &mod) &&
        mod;
    if (have_mod)
        GetModuleFileNameA(mod, path, static_cast<DWORD>(sizeof(path)));
    const uintptr_t base = reinterpret_cast<uintptr_t>(mod);
    const uintptr_t off = have_mod && value >= base ? value - base : 0;
    _snprintf_s(out + len, cap - len, _TRUNCATE,
        "%s[%02d]=0x%016llX:%s+0x%llX",
        len == 0 ? "" : " ",
        idx,
        static_cast<unsigned long long>(value),
        have_mod ? crash_basename_ptr(path) : "no_module",
        static_cast<unsigned long long>(off));
}

static void format_context_stack_modules(CONTEXT* ctx, char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    if (!ctx) {
        _snprintf_s(out, cap, _TRUNCATE, "<no_context>");
        return;
    }
#if defined(_M_X64)
    const uintptr_t* rsp_ptr = reinterpret_cast<const uintptr_t*>(ctx->Rsp);
#else
    const uintptr_t* rsp_ptr = reinterpret_cast<const uintptr_t*>(ctx->Esp);
#endif
    for (int i = 0; i < 32; ++i) {
        uintptr_t value = 0;
        if (!safe_read_qword(rsp_ptr + i, value))
            break;
        if (value == 0)
            continue;
        HMODULE mod = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(value), &mod) || !mod)
            continue;
        append_stack_module_token(out, cap, i, value);
    }
    if (out[0] == 0)
        _snprintf_s(out, cap, _TRUNCATE, "<no_module_stack_values>");
}

static void format_work_queue_crash_snapshot(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    const auto work = work_queue::stats();
    const auto service = work_queue::service_stats();
    const auto critical = critical_work_queue::stats();
    _snprintf_s(out, cap, _TRUNCATE,
        "work{alive=%d shutdown=%d workers=%zu pending=%zu active=%u active_labels=%u oldest_active_ms=%llu posted=%llu started=%llu finished=%llu rejected=%llu labels=%.700s} service{alive=%d shutdown=%d workers=%zu pending=%zu active=%u active_labels=%u oldest_active_ms=%llu posted=%llu started=%llu finished=%llu rejected=%llu labels=%.700s} critical{alive=%d shutdown=%d workers=%zu pending=%zu active=%u active_labels=%u oldest_active_ms=%llu posted=%llu started=%llu finished=%llu rejected=%llu labels=%.700s}",
        work.alive ? 1 : 0,
        work.shutting_down ? 1 : 0,
        work.workers,
        work.pending,
        work.active,
        work.active_label_count,
        static_cast<unsigned long long>(work.oldest_active_ms),
        static_cast<unsigned long long>(work.posted),
        static_cast<unsigned long long>(work.started),
        static_cast<unsigned long long>(work.finished),
        static_cast<unsigned long long>(work.rejected),
        work.active_labels.empty() ? "<none>" : work.active_labels.c_str(),
        service.alive ? 1 : 0,
        service.shutting_down ? 1 : 0,
        service.workers,
        service.pending,
        service.active,
        service.active_label_count,
        static_cast<unsigned long long>(service.oldest_active_ms),
        static_cast<unsigned long long>(service.posted),
        static_cast<unsigned long long>(service.started),
        static_cast<unsigned long long>(service.finished),
        static_cast<unsigned long long>(service.rejected),
        service.active_labels.empty() ? "<none>" : service.active_labels.c_str(),
        critical.alive ? 1 : 0,
        critical.shutting_down ? 1 : 0,
        critical.workers,
        critical.pending,
        critical.active,
        critical.active_label_count,
        static_cast<unsigned long long>(critical.oldest_active_ms),
        static_cast<unsigned long long>(critical.posted),
        static_cast<unsigned long long>(critical.started),
        static_cast<unsigned long long>(critical.finished),
        static_cast<unsigned long long>(critical.rejected),
        critical.active_labels.empty() ? "<none>" : critical.active_labels.c_str());
}

static DWORD count_current_process_threads(DWORD* err_out)
{
    if (err_out)
        *err_out = 0;
    const DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        if (err_out)
            *err_out = GetLastError();
        return 0;
    }
    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    DWORD count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                ++count;
            te.dwSize = sizeof(te);
        } while (Thread32Next(snap, &te));
    } else if (err_out) {
        *err_out = GetLastError();
    }
    CloseHandle(snap);
    return count;
}

static uint64_t filetime_to_u64(const FILETIME& ft)
{
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

struct process_cpu_delta_t {
    bool valid = false;
    DWORD gle = 0;
    DWORD logical_processors = 1;
    uint64_t wall_ms = 0;
    uint64_t busy_100ns = 0;
    double cpu_percent = 0.0;
};

static process_cpu_delta_t sample_current_process_cpu(uint64_t now_ms)
{
    static uint64_t s_last_wall_ms = 0;
    static uint64_t s_last_busy_100ns = 0;
    static DWORD s_logical_processors = 0;
    process_cpu_delta_t out{};
    if (s_logical_processors == 0) {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        s_logical_processors = std::max<DWORD>(1, si.dwNumberOfProcessors);
    }
    out.logical_processors = s_logical_processors;
    FILETIME create_time{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    SetLastError(0);
    if (!GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &kernel_time, &user_time)) {
        out.gle = GetLastError();
        return out;
    }
    const uint64_t busy_100ns = filetime_to_u64(kernel_time) + filetime_to_u64(user_time);
    if (s_last_wall_ms != 0 && now_ms > s_last_wall_ms && busy_100ns >= s_last_busy_100ns) {
        out.valid = true;
        out.wall_ms = now_ms - s_last_wall_ms;
        out.busy_100ns = busy_100ns - s_last_busy_100ns;
        const double capacity_100ns = static_cast<double>(out.wall_ms) * 10000.0 * static_cast<double>(s_logical_processors);
        if (capacity_100ns > 0.0)
            out.cpu_percent = std::min(100.0, (static_cast<double>(out.busy_100ns) * 100.0) / capacity_100ns);
    }
    s_last_wall_ms = now_ms;
    s_last_busy_100ns = busy_100ns;
    return out;
}

struct process_io_delta_t {
    bool valid = false;
    DWORD gle = 0;
    std::uint64_t wall_ms = 0;
    std::uint64_t read_ops_delta = 0;
    std::uint64_t write_ops_delta = 0;
    std::uint64_t other_ops_delta = 0;
    std::uint64_t read_bytes_delta = 0;
    std::uint64_t write_bytes_delta = 0;
    std::uint64_t other_bytes_delta = 0;
    std::uint64_t total_read_bytes = 0;
    std::uint64_t total_write_bytes = 0;
};

static process_io_delta_t sample_process_io_delta(uint64_t now_ms)
{
    static IO_COUNTERS s_last{};
    static uint64_t s_last_ms = 0;
    process_io_delta_t out{};
    IO_COUNTERS cur{};
    SetLastError(0);
    if (!GetProcessIoCounters(GetCurrentProcess(), &cur)) {
        out.gle = GetLastError();
        return out;
    }
    out.total_read_bytes = static_cast<std::uint64_t>(cur.ReadTransferCount);
    out.total_write_bytes = static_cast<std::uint64_t>(cur.WriteTransferCount);
    if (s_last_ms != 0 && now_ms >= s_last_ms &&
        cur.ReadTransferCount >= s_last.ReadTransferCount &&
        cur.WriteTransferCount >= s_last.WriteTransferCount &&
        cur.OtherTransferCount >= s_last.OtherTransferCount) {
        out.valid = true;
        out.wall_ms = now_ms - s_last_ms;
        out.read_ops_delta = static_cast<std::uint64_t>(cur.ReadOperationCount - s_last.ReadOperationCount);
        out.write_ops_delta = static_cast<std::uint64_t>(cur.WriteOperationCount - s_last.WriteOperationCount);
        out.other_ops_delta = static_cast<std::uint64_t>(cur.OtherOperationCount - s_last.OtherOperationCount);
        out.read_bytes_delta = static_cast<std::uint64_t>(cur.ReadTransferCount - s_last.ReadTransferCount);
        out.write_bytes_delta = static_cast<std::uint64_t>(cur.WriteTransferCount - s_last.WriteTransferCount);
        out.other_bytes_delta = static_cast<std::uint64_t>(cur.OtherTransferCount - s_last.OtherTransferCount);
    }
    s_last = cur;
    s_last_ms = now_ms;
    return out;
}

struct file_delta_t {
    bool valid = false;
    bool reset = false;
    DWORD gle = 0;
    std::uint64_t size = 0;
    std::uint64_t delta = 0;
};

struct log_file_delta_snapshot_t {
    file_delta_t debug_log;
    file_delta_t kernel_log;
    file_delta_t full_test_log;
    file_delta_t camoufox_log;
};

static bool query_file_size_bytes(const char* path, std::uint64_t& size, DWORD& gle)
{
    size = 0;
    gle = 0;
    if (!path || !*path) {
        gle = ERROR_INVALID_PARAMETER;
        return false;
    }
    WIN32_FILE_ATTRIBUTE_DATA data{};
    SetLastError(0);
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &data)) {
        gle = GetLastError();
        return false;
    }
    ULARGE_INTEGER v{};
    v.LowPart = data.nFileSizeLow;
    v.HighPart = data.nFileSizeHigh;
    size = v.QuadPart;
    return true;
}

static file_delta_t sample_one_file_delta(const char* path, std::uint64_t& previous_size, bool& previous_valid)
{
    file_delta_t out{};
    std::uint64_t size = 0;
    DWORD gle = 0;
    if (!query_file_size_bytes(path, size, gle)) {
        out.gle = gle;
        previous_valid = false;
        previous_size = 0;
        return out;
    }
    out.valid = true;
    out.size = size;
    if (previous_valid) {
        if (size >= previous_size) {
            out.delta = size - previous_size;
        } else {
            out.reset = true;
            out.delta = size;
        }
    }
    previous_valid = true;
    previous_size = size;
    return out;
}

static log_file_delta_snapshot_t sample_log_file_deltas()
{
    static std::uint64_t s_debug_size = 0;
    static std::uint64_t s_kernel_size = 0;
    static std::uint64_t s_full_test_size = 0;
    static std::uint64_t s_camoufox_size = 0;
    static bool s_debug_valid = false;
    static bool s_kernel_valid = false;
    static bool s_full_test_valid = false;
    static bool s_camoufox_valid = false;
    char log_dir[MAX_PATH] = {};
    _snprintf_s(log_dir, sizeof(log_dir), _TRUNCATE, "%s", diag::resolve_log_dir());
    char debug_path[MAX_PATH] = {};
    const char* cached_debug = diag::cached_log_path();
    if (cached_debug && cached_debug[0])
        _snprintf_s(debug_path, sizeof(debug_path), _TRUNCATE, "%s", cached_debug);
    else
        _snprintf_s(debug_path, sizeof(debug_path), _TRUNCATE, "%saida_debug.log", log_dir);
    char full_test_path[MAX_PATH] = {};
    char camoufox_path[MAX_PATH] = {};
    _snprintf_s(full_test_path, sizeof(full_test_path), _TRUNCATE, "%saida_full_test.log", log_dir);
    _snprintf_s(camoufox_path, sizeof(camoufox_path), _TRUNCATE, "%saida_camoufox_debug.log", log_dir);
    log_file_delta_snapshot_t out{};
    out.debug_log = sample_one_file_delta(debug_path, s_debug_size, s_debug_valid);
    out.kernel_log = sample_one_file_delta("C:\\Users\\Public\\Desktop\\aida_kernel.log", s_kernel_size, s_kernel_valid);
    out.full_test_log = sample_one_file_delta(full_test_path, s_full_test_size, s_full_test_valid);
    out.camoufox_log = sample_one_file_delta(camoufox_path, s_camoufox_size, s_camoufox_valid);
    return out;
}

struct defender_process_snapshot_t {
    bool valid = false;
    DWORD gle = 0;
    std::uint32_t msmpeng = 0;
    std::uint32_t mpcmdrun = 0;
};

static defender_process_snapshot_t sample_defender_processes()
{
    defender_process_snapshot_t out{};
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        out.gle = GetLastError();
        return out;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) {
        out.gle = GetLastError();
        CloseHandle(snap);
        return out;
    }
    do {
        if (_wcsicmp(pe.szExeFile, L"MsMpEng.exe") == 0)
            ++out.msmpeng;
        else if (_wcsicmp(pe.szExeFile, L"MpCmdRun.exe") == 0)
            ++out.mpcmdrun;
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    out.valid = true;
    return out;
}

struct frame_wait_result_t {
    DWORD requested_ms = 0;
    DWORD actual_ms = 0;
    DWORD result = WAIT_TIMEOUT;
    DWORD gle = 0;
    std::uint64_t immediate_timeout_streak = 0;
    bool waitable_present = false;
    bool frame_latency_signaled = false;
    bool input_available = false;
};

static frame_wait_result_t wait_for_frame_latency_or_input(DWORD requested_ms)
{
    frame_wait_result_t out{};
    out.requested_ms = requested_ms;
    HANDLE waitable = g_FrameLatencyWaitableObject;
    out.waitable_present = waitable != nullptr;
    const uint64_t wait_start_ms = static_cast<uint64_t>(GetTickCount64());
    SetLastError(0);
    if (waitable) {
        HANDLE handles[1] = { waitable };
        out.result = MsgWaitForMultipleObjectsEx(1, handles, requested_ms, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        out.frame_latency_signaled = out.result == WAIT_OBJECT_0;
        out.input_available = out.result == WAIT_OBJECT_0 + 1;
    } else {
        out.result = MsgWaitForMultipleObjectsEx(0, nullptr, requested_ms, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        out.input_available = out.result == WAIT_OBJECT_0;
    }
    if (out.result == WAIT_FAILED)
        out.gle = GetLastError();
    out.actual_ms = static_cast<DWORD>(std::min<uint64_t>(static_cast<uint64_t>(GetTickCount64()) - wait_start_ms, 0xFFFFFFFFULL));
    static std::atomic<std::uint64_t> s_immediate_timeout_streak{0};
    const bool immediate_timeout = out.waitable_present && requested_ms != 0 && out.result == WAIT_TIMEOUT && out.actual_ms == 0 && !out.input_available && !out.frame_latency_signaled;
    if (immediate_timeout)
        out.immediate_timeout_streak = s_immediate_timeout_streak.fetch_add(1, std::memory_order_acq_rel) + 1;
    else
        s_immediate_timeout_streak.store(0, std::memory_order_release);
    return out;
}

struct draw_data_metrics_t {
    int draw_lists = 0;
    int draw_cmds = 0;
    int callbacks = 0;
    int reset_callbacks = 0;
    int expected_blur_callbacks = 0;
    int unexpected_callbacks = 0;
    int total_vtx = 0;
    int total_idx = 0;
};

static draw_data_metrics_t collect_draw_data_metrics(ImDrawData* draw_data)
{
    draw_data_metrics_t out{};
    if (!draw_data)
        return out;
    out.draw_lists = draw_data->CmdListsCount;
    out.total_vtx = draw_data->TotalVtxCount;
    out.total_idx = draw_data->TotalIdxCount;
    if (draw_data->CmdListsCount > 0 && !draw_data->CmdLists.Data)
        return out;
    const int list_count = draw_data->CmdListsCount > 0 ? draw_data->CmdListsCount : 0;
    ImDrawCallback expected_blur_callback = Blur::ExpectedCallback();
    for (int list_index = 0; list_index < list_count; ++list_index) {
        const ImDrawList* list = draw_data->CmdLists[list_index];
        if (!list)
            continue;
        out.draw_cmds += list->CmdBuffer.Size;
        for (int cmd_index = 0; cmd_index < list->CmdBuffer.Size; ++cmd_index) {
            const ImDrawCmd& cmd = list->CmdBuffer[cmd_index];
            if (!cmd.UserCallback)
                continue;
            if (cmd.UserCallback == ImDrawCallback_ResetRenderState)
                ++out.reset_callbacks;
            else {
                ++out.callbacks;
                if (expected_blur_callback && cmd.UserCallback == expected_blur_callback)
                    ++out.expected_blur_callbacks;
                else
                    ++out.unexpected_callbacks;
            }
        }
    }
    return out;
}

static void format_message_pump_stall_context(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    char full_snapshot[1700] = {};
    char ui_phase[900] = {};
    char queue_snapshot[2600] = {};
    test_all_features::format_debug_snapshot(full_snapshot, sizeof(full_snapshot));
    test_all_features::format_ui_phase_snapshot(ui_phase, sizeof(ui_phase));
    format_work_queue_crash_snapshot(queue_snapshot, sizeof(queue_snapshot));
    DWORD thread_err = 0;
    const DWORD threads = count_current_process_threads(&thread_err);
    DWORD handles = 0;
    const BOOL handle_ok = GetProcessHandleCount(GetCurrentProcess(), &handles);
    const DWORD handle_err = handle_ok ? 0UL : GetLastError();
    const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
    const char* render_section = g_render_section.c_str();
    const char* dispatch_stage = aida_tracer::g_dispatch_stage.load(std::memory_order_acquire);
    const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
    _snprintf_s(out, cap, _TRUNCATE,
        "pid=%lu tid=%lu threads=%lu thread_err=%lu handles=%lu handle_ok=%d handle_err=%lu "
        "render_phase=%s render_section=%s dispatch_stage=%s dispatch_msg=%s(0x%04X) wndproc_stage=%s wndproc_msg=%s(0x%04X) "
        "full_test_running=%d ui={%.760s} full={%.1200s} queues={%.1800s}",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long>(threads),
        static_cast<unsigned long>(thread_err),
        static_cast<unsigned long>(handles),
        handle_ok ? 1 : 0,
        static_cast<unsigned long>(handle_err),
        render_phase ? render_phase : "<null>",
        render_section ? render_section : "<null>",
        dispatch_stage ? dispatch_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_dispatch_msg.load(std::memory_order_acquire)),
        aida_tracer::g_dispatch_msg.load(std::memory_order_acquire),
        wndproc_stage ? wndproc_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_wndproc_msg.load(std::memory_order_acquire)),
        aida_tracer::g_wndproc_msg.load(std::memory_order_acquire),
        test_all_features::is_running() ? 1 : 0,
        ui_phase[0] ? ui_phase : "<empty>",
        full_snapshot[0] ? full_snapshot : "<empty>",
        queue_snapshot[0] ? queue_snapshot : "<empty>");
}

static void format_shutdown_crash_snapshot(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    char thread_desc[512] = {};
    char queue_snapshot[2400] = {};
    format_current_thread_description(thread_desc, sizeof(thread_desc));
    format_work_queue_crash_snapshot(queue_snapshot, sizeof(queue_snapshot));
    const char* shutdown_phase = aida_shutdown_diag::g_phase.load(std::memory_order_acquire);
    const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
    const char* dispatch_stage = aida_tracer::g_dispatch_stage.load(std::memory_order_acquire);
    const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
    std::string latch_source = anti_tamper::runtime_integrity_latch_source_snapshot();
    _snprintf_s(out, cap, _TRUNCATE,
        "shutdown_phase=%s shutdown_phase_age_ms=%llu tid=%lu thread_desc=%s render_phase=%s dispatch_stage=%s dispatch_msg=%s(0x%04X) wndproc_stage=%s wndproc_msg=%s(0x%04X) queues={%s} latch_source={%.700s}",
        shutdown_phase ? shutdown_phase : "<null>",
        static_cast<unsigned long long>(aida_shutdown_diag::phase_age_ms()),
        GetCurrentThreadId(),
        thread_desc[0] ? thread_desc : "<none>",
        render_phase ? render_phase : "<null>",
        dispatch_stage ? dispatch_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_dispatch_msg.load(std::memory_order_acquire)),
        aida_tracer::g_dispatch_msg.load(std::memory_order_acquire),
        wndproc_stage ? wndproc_stage : "<null>",
        aida_tracer::message_name(aida_tracer::g_wndproc_msg.load(std::memory_order_acquire)),
        aida_tracer::g_wndproc_msg.load(std::memory_order_acquire),
        queue_snapshot,
        latch_source.empty() ? "<none>" : latch_source.c_str());
}

__declspec(noinline) static DWORD seh_init_standalone_chat()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_init_standalone_chat_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        init_standalone_chat();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        startup_log_critical_fmt("seh_init_standalone_chat_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_init_standalone_chat_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static DWORD seh_network_view_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_network_view_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        network_view::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        startup_log_critical_fmt("seh_network_view_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_network_view_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static DWORD seh_memory_scanner_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_memory_scanner_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        memory_scanner::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        startup_log_critical_fmt("seh_memory_scanner_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_memory_scanner_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static DWORD seh_mitm_proxy_pre_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        mitm_proxy::pre_initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static DWORD seh_script_engine_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_script_engine_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    bool ok = false;
    __try {
        ok = script_engine::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        startup_log_critical_fmt("seh_script_engine_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_script_engine_initialize_exit ok=%d initialized=%d elapsed_ms=%llu last_err=%lu",
        ok ? 1 : 0,
        script_engine::is_initialized() ? 1 : 0,
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return ok ? 0 : ERROR_NOT_READY;
}

static std::atomic<bool> g_authorized_features_initialized{false};
static std::atomic<bool> g_authorized_features_posted{false};
static std::atomic<bool> g_camoufox_prewarm_posted{false};
static std::atomic<bool> g_script_engine_startup_init_posted{false};

static void post_script_engine_startup_initialize()
{
    if (script_engine::is_initialized()) {
        startup_log_critical_fmt("script_engine_startup_async_skip already_initialized=1 pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        return;
    }

    bool expected = false;
    if (!g_script_engine_startup_init_posted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        startup_log_critical_fmt("script_engine_startup_async_skip already_posted=1 initialized=%d pid=%lu tid=%lu tick=%llu",
            script_engine::is_initialized() ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        return;
    }

    const uint64_t queued_at = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("script_engine_startup_async_posting pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(queued_at));
    std::function<void()> init_task = [queued_at]() {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("script_engine_startup_async_enter pid=%lu tid=%lu queued_ms=%llu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started - queued_at),
            static_cast<unsigned long long>(started));
        DWORD seh = seh_script_engine_initialize();
        startup_log_critical_fmt("script_engine_startup_async_exit seh=0x%08X initialized=%d elapsed_ms=%llu last_err=%lu",
            seh,
            script_engine::is_initialized() ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        if (seh != 0 && !script_engine::is_initialized())
            g_script_engine_startup_init_posted.store(false, std::memory_order_release);
    };

    bool posted_service = false;
    bool posted_work = false;
    try {
        posted_service = work_queue::post_service_labeled("script_engine_startup_init", init_task);
        if (!posted_service)
            posted_work = work_queue::post_labeled("script_engine_startup_init_fallback", init_task);
        startup_log_critical_fmt("script_engine_startup_async_posted pid=%lu tid=%lu service=%d work=%d elapsed_ms=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            posted_service ? 1 : 0,
            posted_work ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at));
    } catch (const std::exception& e) {
        g_script_engine_startup_init_posted.store(false, std::memory_order_release);
        startup_log_critical_fmt("script_engine_startup_async_post_exception elapsed_ms=%llu what=%.160s",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at),
            e.what());
    } catch (...) {
        g_script_engine_startup_init_posted.store(false, std::memory_order_release);
        startup_log_critical_fmt("script_engine_startup_async_post_exception elapsed_ms=%llu what=<unknown>",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at));
    }

    if (!posted_service && !posted_work && !script_engine::is_initialized()) {
        const uint64_t inline_started = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("script_engine_startup_inline_fallback_enter pid=%lu tid=%lu queued_ms=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(inline_started - queued_at));
        DWORD seh = seh_script_engine_initialize();
        startup_log_critical_fmt("script_engine_startup_inline_fallback_exit seh=0x%08X initialized=%d elapsed_ms=%llu last_err=%lu",
            seh,
            script_engine::is_initialized() ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - inline_started),
            static_cast<unsigned long>(GetLastError()));
        if (seh != 0 && !script_engine::is_initialized())
            g_script_engine_startup_init_posted.store(false, std::memory_order_release);
    }
}

static void run_authorized_feature_initializers(const char* source)
{
    auto run = [source](const char* phase, DWORD(*fn)()) {
        DWORD seh = 0;
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("authorized_feature_phase_pre source=%s phase=%s pid=%lu tid=%lu tick=%llu",
            source ? source : "unknown",
            phase ? phase : "unknown",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        diag::log_tagged_fmt("bg_init", "%s_start source=%s", phase, source ? source : "unknown");
        try {
            seh = fn();
        } catch (const std::exception& e) {
            startup_log_critical_fmt("authorized_feature_phase_cpp_exception source=%s phase=%s elapsed_ms=%llu what=%.160s",
                source ? source : "unknown",
                phase ? phase : "unknown",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                e.what());
            diag::log_tagged_fmt("bg_init", "%s_cpp_exception source=%s what=%s",
                phase, source ? source : "unknown", e.what());
            return false;
        } catch (...) {
            startup_log_critical_fmt("authorized_feature_phase_cpp_exception source=%s phase=%s elapsed_ms=%llu what=<unknown>",
                source ? source : "unknown",
                phase ? phase : "unknown",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            diag::log_tagged_fmt("bg_init", "%s_cpp_exception source=%s what=<unknown>",
                phase, source ? source : "unknown");
            return false;
        }
        if (seh != 0) {
            startup_log_critical_fmt("authorized_feature_phase_seh source=%s phase=%s code=0x%08X last_err=%lu elapsed_ms=%llu",
                source ? source : "unknown",
                phase ? phase : "unknown",
                seh,
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            diag::log_tagged_fmt("bg_init", "%s_seh source=%s code=0x%08X last_err=%lu",
                phase, source ? source : "unknown", seh, GetLastError());
            return false;
        }
        startup_log_critical_fmt("authorized_feature_phase_post source=%s phase=%s seh=0x%08X elapsed_ms=%llu last_err=%lu",
            source ? source : "unknown",
            phase ? phase : "unknown",
            seh,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        diag::log_tagged_fmt("bg_init", "%s_ok source=%s", phase, source ? source : "unknown");
        return true;
    };

    bool ok = true;
    ok = run("network_view_init", seh_network_view_initialize) && ok;
    ok = run("memory_scanner_init", seh_memory_scanner_initialize) && ok;
    ok = run("mitm_proxy_pre_init", seh_mitm_proxy_pre_initialize) && ok;
    startup_log_critical_fmt("authorized_feature_phase_async_post source=%s phase=script_engine_init pid=%lu tid=%lu tick=%llu",
        source ? source : "unknown",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_fmt("bg_init", "script_engine_init_async_start source=%s", source ? source : "unknown");
    post_script_engine_startup_initialize();
    g_authorized_features_initialized.store(ok, std::memory_order_release);
    if (!ok)
        g_authorized_features_posted.store(false, std::memory_order_release);
    startup_log_critical_fmt("authorized_feature_initializers_done source=%s ok=%d pid=%lu tid=%lu tick=%llu",
        source ? source : "unknown",
        ok ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_fmt("bg_init", "authorized_feature_initializers_done source=%s ok=%d",
        source ? source : "unknown", ok ? 1 : 0);
}

__declspec(noinline) static DWORD seh_snapshot_code_hashes()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_snapshot_code_hashes_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        bool ok = standalone_license::snapshot_code_hashes();
        startup_log_critical_fmt("seh_snapshot_code_hashes_call_post ok=%d elapsed_ms=%llu last_err=%lu",
            ok ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        if (!ok)
            return ERROR_GEN_FAILURE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        startup_log_critical_fmt("seh_snapshot_code_hashes_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_snapshot_code_hashes_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) static void cpp_anti_tamper_initialize(bool& out_result)
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("cpp_anti_tamper_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    try
    {
        out_result = anti_tamper::initialize();
        startup_log_critical_fmt("cpp_anti_tamper_initialize_exit result=%d elapsed_ms=%llu last_err=%lu",
            out_result ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
    }
    catch (const std::exception& e)
    {
        startup_log_critical_fmt("cpp_anti_tamper_initialize_exception elapsed_ms=%llu what=%.160s",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            e.what());
        diag::log_tagged_fmt("bg_init", "anti_tamper_initialize_cpp_exception what=%s", e.what());
        out_result = false;
    }
    catch (...)
    {
        startup_log_critical_fmt("cpp_anti_tamper_initialize_exception elapsed_ms=%llu what=<unknown>",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        diag::log_tagged("bg_init", "anti_tamper_initialize_unknown_cpp_exception");
        out_result = false;
    }
}

__declspec(noinline) static DWORD seh_anti_tamper_initialize(bool& out_result)
{
    out_result = false;
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_anti_tamper_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        cpp_anti_tamper_initialize(out_result);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        startup_log_critical_fmt("seh_anti_tamper_initialize_exception code=0x%08X result=%d elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            out_result ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_anti_tamper_initialize_exit result=%d elapsed_ms=%llu last_err=%lu",
        out_result ? 1 : 0,
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

static void log_driver_bridge_initialize_call_post(bool ok, uint64_t started)
{
    std::string status = driver_bridge::status();
    startup_log_critical_fmt("seh_driver_bridge_initialize_call_post ok=%d loaded=%d kernel=%d status=%.160s elapsed_ms=%llu last_err=%lu",
        ok ? 1 : 0,
        driver_bridge::is_loaded() ? 1 : 0,
        driver_bridge::using_kernel_driver() ? 1 : 0,
        status.c_str(),
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
}

__declspec(noinline) static DWORD seh_driver_bridge_initialize_raw(bool* out_ok)
{
    __try {
        if (out_ok)
            *out_ok = driver_bridge::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_driver_bridge_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    bool ok = false;
    startup_log_critical_fmt("seh_driver_bridge_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    DWORD seh = seh_driver_bridge_initialize_raw(&ok);
    if (seh != 0) {
        startup_log_critical_fmt("seh_driver_bridge_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            seh,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return seh;
    }
    log_driver_bridge_initialize_call_post(ok, started);
    startup_log_critical_fmt("seh_driver_bridge_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

static bool aida_is_fatal_exception_code(DWORD code)
{
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_INVALID_DISPOSITION:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
        return true;
    default:
        return code == 0xC0000409u;
    }
}

static void aida_write_first_chance_crash_log(EXCEPTION_POINTERS* ep)
{
    static std::atomic<bool> written{false};
    if (!ep || !ep->ExceptionRecord || !aida_is_fatal_exception_code(ep->ExceptionRecord->ExceptionCode))
        return;
    bool expected = false;
    if (!written.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    CONTEXT* ctx = ep->ContextRecord;
    HMODULE exe_base = GetModuleHandleA(nullptr);
    uintptr_t exe_addr = reinterpret_cast<uintptr_t>(exe_base);
    uintptr_t rip = ctx ? static_cast<uintptr_t>(ctx->Rip) : 0;
    uintptr_t rsp = ctx ? static_cast<uintptr_t>(ctx->Rsp) : 0;
    uintptr_t rbp = ctx ? static_cast<uintptr_t>(ctx->Rbp) : 0;
    uintptr_t crash_addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    uintptr_t rip_offset = exe_addr && rip >= exe_addr ? rip - exe_addr : 0;
    uintptr_t addr_offset = exe_addr && crash_addr >= exe_addr ? crash_addr - exe_addr : 0;
    unsigned long param_count = static_cast<unsigned long>(ep->ExceptionRecord->NumberParameters);
    unsigned long long p0 = ep->ExceptionRecord->NumberParameters > 0
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[0])
        : 0ULL;
    unsigned long long p1 = ep->ExceptionRecord->NumberParameters > 1
        ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[1])
        : 0ULL;

    char tracer_snapshot[2600] = {};
    format_tracer_crash_snapshot(tracer_snapshot, sizeof(tracer_snapshot));
    char shutdown_snapshot[4200] = {};
    char stack_modules[2200] = {};
    format_shutdown_crash_snapshot(shutdown_snapshot, sizeof(shutdown_snapshot));
    format_context_stack_modules(ctx, stack_modules, sizeof(stack_modules));
    char buf[8192];
    snprintf(buf, sizeof(buf),
        "FIRST_CHANCE_FATAL_EXCEPTION: code=0x%08X addr=0x%016llX addr_off_exe=0x%llX rip=0x%016llX rip_off_exe=0x%llX rsp=0x%016llX rbp=0x%016llX tid=%lu flags=0x%08X params=%lu p0=0x%016llX p1=0x%016llX last_error=%lu stack_modules={%s} shutdown={%s} tracer={%s}",
        ep->ExceptionRecord->ExceptionCode,
        static_cast<unsigned long long>(crash_addr),
        static_cast<unsigned long long>(addr_offset),
        static_cast<unsigned long long>(rip),
        static_cast<unsigned long long>(rip_offset),
        static_cast<unsigned long long>(rsp),
        static_cast<unsigned long long>(rbp),
        GetCurrentThreadId(),
        ep->ExceptionRecord->ExceptionFlags,
        param_count,
        p0,
        p1,
        GetLastError(),
        stack_modules,
        shutdown_snapshot,
        tracer_snapshot);
    diag::write_crash_log(buf, false);
    diag::log_tagged_critical("veh_crash", buf);
}

static LONG CALLBACK aida_diagnostic_veh(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == STATUS_SINGLE_STEP &&
        (anti_tamper::anti_dump::read_intercept::consume_pending_single_step(ep, "diagnostic_veh") ||
            anti_tamper::anti_dump::read_intercept::consume_orphan_single_step(ep, "diagnostic_veh_orphan")))
    {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == 0x40010006u || code == 0x4001000Au || code == DBG_PRINTEXCEPTION_C ||
        code == DBG_PRINTEXCEPTION_WIDE_C ||
        code == 0x406D1388u ||
        code == 0xE06D7363u ||
        code == 0x06D007E0u ||
        code == STATUS_GUARD_PAGE_VIOLATION ||
        code == STATUS_SINGLE_STEP ||
        code == EXCEPTION_BREAKPOINT)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (code == EXCEPTION_PRIV_INSTRUCTION &&
        anti_tamper::anti_emulation::expected_privileged_instruction_probe_active())
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (aida::diagnostic_exception_scope::active())
    {
        unsigned long long p0 = ep->ExceptionRecord->NumberParameters > 0
            ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[0])
            : 0ULL;
        unsigned long long p1 = ep->ExceptionRecord->NumberParameters > 1
            ? static_cast<unsigned long long>(ep->ExceptionRecord->ExceptionInformation[1])
            : 0ULL;
        diag::log_tagged_critical_fmt("veh",
            "scoped_first_chance scope=%s code=0x%08X addr=0x%016llX tid=%lu flags=0x%08X params=%lu p0=0x%016llX p1=0x%016llX",
            aida::diagnostic_exception_scope::label(),
            code,
            (unsigned long long)reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress),
            GetCurrentThreadId(),
            ep->ExceptionRecord->ExceptionFlags,
            (unsigned long)ep->ExceptionRecord->NumberParameters,
            p0,
            p1);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    aida_write_first_chance_crash_log(ep);
    if (!ep->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;
    HMODULE crash_mod = nullptr;
    char crash_mod_name[MAX_PATH] = "<unknown>";
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &crash_mod);
    if (crash_mod) GetModuleFileNameA(crash_mod, crash_mod_name, MAX_PATH);
    HMODULE exe_base = GetModuleHandleA(nullptr);
    uintptr_t rip_off_exe = ep->ContextRecord->Rip - reinterpret_cast<uintptr_t>(exe_base);
    uintptr_t addr_off_mod = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress)
        - reinterpret_cast<uintptr_t>(crash_mod);
    char test_all_snapshot[1200] = {};
    test_all_features::format_debug_snapshot(test_all_snapshot, sizeof(test_all_snapshot));
    diag::log_tagged_critical_fmt("veh",
        "code=0x%08X addr=0x%016llX rip=0x%016llX rip_off_exe=0x%llX "
        "mod=%s mod_off=0x%llX tid=%lu params=%lu p0=0x%016llX p1=0x%016llX test_all={%s}",
        code,
        (unsigned long long)reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress),
        (unsigned long long)ep->ContextRecord->Rip,
        (unsigned long long)rip_off_exe,
        crash_mod_name, (unsigned long long)addr_off_mod,
        GetCurrentThreadId(),
        (unsigned long)ep->ExceptionRecord->NumberParameters,
        (unsigned long long)(ep->ExceptionRecord->NumberParameters > 0
            ? ep->ExceptionRecord->ExceptionInformation[0] : 0ULL),
        (unsigned long long)(ep->ExceptionRecord->NumberParameters > 1
            ? ep->ExceptionRecord->ExceptionInformation[1] : 0ULL),
        test_all_snapshot);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void log_disk_backed_startup_state(const char* phase)
{
    char module[MAX_PATH] = {};
    char cwd[MAX_PATH] = {};
    char camoufox_exe[MAX_PATH] = {};
    char camoufox_mcp[MAX_PATH] = {};
    char camoufox_python[MAX_PATH] = {};
    char camoufox_setup[32] = {};
    GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
    GetCurrentDirectoryA(static_cast<DWORD>(sizeof(cwd)), cwd);
    GetEnvironmentVariableA("AIDA_CAMOUFOX_EXECUTABLE", camoufox_exe, static_cast<DWORD>(sizeof(camoufox_exe)));
    GetEnvironmentVariableA("AIDA_CAMOUFOX_MCP_EXECUTABLE", camoufox_mcp, static_cast<DWORD>(sizeof(camoufox_mcp)));
    GetEnvironmentVariableA("AIDA_CAMOUFOX_PYTHON", camoufox_python, static_cast<DWORD>(sizeof(camoufox_python)));
    GetEnvironmentVariableA("AIDA_CAMOUFOX_ALLOW_SETUP_BOOTSTRAP", camoufox_setup, static_cast<DWORD>(sizeof(camoufox_setup)));

    std::uintptr_t teb = 0;
    std::uintptr_t peb = 0;
    std::uintptr_t tls_vector = 0;
    std::uintptr_t tls_slot51 = 0;
#if defined(_M_X64)
    teb = static_cast<std::uintptr_t>(__readgsqword(0x30));
    peb = static_cast<std::uintptr_t>(__readgsqword(0x60));
    tls_vector = static_cast<std::uintptr_t>(__readgsqword(0x58));
#endif
    if (tls_vector)
        safe_read_qword(reinterpret_cast<const void*>(tls_vector + 51u * sizeof(void*)), tls_slot51);

    HMODULE image = GetModuleHandleA(nullptr);
    MEMORY_BASIC_INFORMATION mbi{};
    if (image)
        VirtualQuery(image, &mbi, sizeof(mbi));

    diag::log_tagged_critical_fmt("main",
        "disk_backed_startup_state phase=%s pid=%lu tid=%lu module=%s cwd=%s camoufox_exe=%s camoufox_mcp=%s camoufox_python=%s camoufox_setup=%s image_base=0x%016llX alloc_base=0x%016llX mbi_base=0x%016llX mbi_size=0x%llX mbi_state=0x%08lX mbi_protect=0x%08lX teb=0x%016llX peb=0x%016llX tls_vector=0x%016llX tls_slot51=0x%016llX",
        phase ? phase : "",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        module,
        cwd,
        camoufox_exe,
        camoufox_mcp,
        camoufox_python,
        camoufox_setup,
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(image)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(mbi.AllocationBase)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress)),
        static_cast<unsigned long long>(mbi.RegionSize),
        mbi.State,
        mbi.Protect,
        static_cast<unsigned long long>(teb),
        static_cast<unsigned long long>(peb),
        static_cast<unsigned long long>(tls_vector),
        static_cast<unsigned long long>(tls_slot51));
}

int main(int, char**)
{
    aida_early_startup::install();
    aida_early_startup::mark("main_enter");
    aida_early_startup::mark("manual_map_tls_pre");
    aida::manual_map_tls::ensure_current_thread();
    aida_early_startup::mark("manual_map_tls_current_thread_ok");
    const std::string startup_run_id = generate_startup_run_correlation_id();
    standalone_license::set_run_correlation_id(startup_run_id);
    aida_early_startup::mark("run_correlation_id_set");
    aida_early_startup::mark("diagnostic_exception_scope_initialize_pre");
    bool diagnostic_scope_ready = aida::diagnostic_exception_scope::initialize();
    aida_early_startup::mark(diagnostic_scope_ready ? "diagnostic_exception_scope_initialized" : "diagnostic_exception_scope_failed");
    aida_early_startup::mark("diagnostic_veh_install_pre");
    PVOID diagnostic_veh = AddVectoredExceptionHandler(1, aida_diagnostic_veh);
    aida_early_startup::mark(diagnostic_veh ? "diagnostic_veh_installed" : "diagnostic_veh_install_failed");
    aida_early_startup::mark("normal_diag_log_pre");
    diag::log_tagged_critical("main", "diagnostic_veh_installed");
    diag::log_tagged_critical_fmt("startup",
        "run_correlation_generated run_id=%s pid=%lu tid=%lu tick=%llu",
        startup_run_id.c_str(),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida_early_startup::mark_normal_diagnostics_reached();
    aida_early_startup::mark("disk_backed_startup_state_pre");
    log_disk_backed_startup_state("post_veh");
    aida_early_startup::mark("normal_startup_state_logged");
    aida_early_startup::mark("single_instance_gate_pre");
    if (!acquire_single_instance_gate()) {
        diag::log_tagged_critical("main", "single_instance_gate_refused");
        aida_early_startup::mark("single_instance_gate_refused");
        return 0;
    }
    aida_early_startup::mark("single_instance_gate_acquired");
    startup_log_critical_fmt("main_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    crash_log_write("main_enter");

    startup_log_critical_fmt("work_queue_initialize_pre pid=%lu tid=%lu tick=%llu pool_size=%d",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        work_queue::POOL_SIZE);
    work_queue::initialize();
    startup_log_critical_fmt("work_queue_initialize_post pid=%lu tid=%lu tick=%llu pool_size=%d",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        work_queue::POOL_SIZE);
    crash_log_write("work_queue_init_ok");

    startup_log_critical_fmt("work_queue_service_initialize_pre pid=%lu tid=%lu tick=%llu pool_size=%d",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        work_queue::SERVICE_POOL_SIZE);
    work_queue::initialize_services();
    startup_log_critical_fmt("work_queue_service_initialize_post pid=%lu tid=%lu tick=%llu pool_size=%d",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        work_queue::SERVICE_POOL_SIZE);
    crash_log_write("work_queue_service_init_ok");

    startup_log_critical_fmt("critical_work_queue_initialize_pre pid=%lu tid=%lu tick=%llu pool_size=%d",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        critical_work_queue::POOL_SIZE);
    critical_work_queue::initialize();
    startup_log_critical_fmt("critical_work_queue_initialize_post pid=%lu tid=%lu tick=%llu pool_size=%d",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        critical_work_queue::POOL_SIZE);
    crash_log_write("critical_work_queue_init_ok");

    startup_log_critical_fmt("tracer_start_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida_tracer::start();
    startup_log_critical_fmt("tracer_start_post pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));

    {
        const uint64_t hwid_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("hwid_collect_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(hwid_tick));
        aida::hardware_id::v2::collection_t collection{};
        std::string hwid_err;
        bool hwid_ok = aida::hardware_id::v2::collect(collection, hwid_err);
        std::string hwid_hex = hwid_ok
            ? aida::hardware_id::v2::hash_to_hex(collection.hwid_hash)
            : std::string("unavailable");
        uint32_t collected = 0;
        char factor_log[900] = {};
        size_t factor_off = 0;
        for (const auto& factor : collection.factors) {
            if (factor.collected) ++collected;
            std::string fh = aida::hardware_id::v2::hash_to_hex(factor.factor_hash);
            int wrote = _snprintf_s(factor_log + factor_off,
                sizeof(factor_log) - factor_off,
                _TRUNCATE,
                "%s%u:%s:%zu:%s",
                factor_off == 0 ? "" : ",",
                static_cast<unsigned>(factor.id),
                factor.collected ? fh.substr(0, 8).c_str() : "miss",
                factor.bytes.size(),
                factor.id == aida::hardware_id::v2::kFactorIdTpmEkSha256 ? "tpm_disabled" : "hw");
            if (wrote <= 0) break;
            factor_off += static_cast<size_t>(wrote);
            if (factor_off >= sizeof(factor_log) - 1) break;
        }
        char hwid_log_msg[512];
        _snprintf_s(hwid_log_msg, sizeof(hwid_log_msg), _TRUNCATE,
            "hwid_v2_composition ok=%d mask=0x%08X collected=%u tpm=%d tpm_policy=disabled hwid=%.16s err=%.96s",
            hwid_ok ? 1 : 0,
            collection.factor_present_mask,
            collected,
            collection.tpm_present ? 1 : 0,
            hwid_hex.c_str(),
            hwid_ok ? "" : hwid_err.c_str());
        startup_log_critical_fmt("hwid_collect_post ok=%d mask=0x%08X collected=%u factors=%zu elapsed_ms=%llu err_hash=0x%016llX",
            hwid_ok ? 1 : 0,
            collection.factor_present_mask,
            collected,
            collection.factors.size(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - hwid_tick),
            static_cast<unsigned long long>(diag_fnv1a64(hwid_err.data(), hwid_err.size())));
        crash_log_write(hwid_log_msg);
        char hwid_factor_msg[1024];
        _snprintf_s(hwid_factor_msg, sizeof(hwid_factor_msg), _TRUNCATE,
            "hwid_v2_factors %s", factor_log);
        crash_log_write(hwid_factor_msg);
        SecureZeroMemory(collection.hwid_hash.data(), collection.hwid_hash.size());
        for (auto& factor : collection.factors) {
            SecureZeroMemory(factor.factor_hash.data(), factor.factor_hash.size());
            if (!factor.bytes.empty()) SecureZeroMemory(factor.bytes.data(), factor.bytes.size());
        }
    }

    run_phase_1_2_self_tests();

    startup_log_critical_fmt("arc_import_cache_prime_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    arc_loader::prime_import_cache();
    startup_log_critical_fmt("arc_import_cache_prime_post pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    crash_log_write("arc_import_cache_primed");

    SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* ep) -> LONG {
        if (ep && ep->ExceptionRecord &&
            ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP &&
            (anti_tamper::anti_dump::read_intercept::consume_pending_single_step(ep, "unhandled_filter") ||
                anti_tamper::anti_dump::read_intercept::consume_orphan_single_step(ep, "unhandled_filter_orphan")))
        {
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (ep && ep->ExceptionRecord && ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
        {
            HMODULE single_step_mod = nullptr;
            char single_step_module[MAX_PATH] = "<unknown>";
            uintptr_t single_step_addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
            if (ep->ExceptionRecord->ExceptionAddress &&
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &single_step_mod) &&
                single_step_mod)
            {
                GetModuleFileNameA(single_step_mod, single_step_module, MAX_PATH);
            }
            const uintptr_t single_step_module_base = reinterpret_cast<uintptr_t>(single_step_mod);
            const uintptr_t single_step_module_offset = single_step_module_base && single_step_addr >= single_step_module_base
                ? single_step_addr - single_step_module_base
                : 0;
            const char* early_phase = aida_early_startup::g_phase.load(std::memory_order_acquire);
            const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
            char single_step_buf[1024] = {};
            _snprintf_s(single_step_buf, sizeof(single_step_buf), _TRUNCATE,
                "single_step_unconsumed code=0x%08X pid=%lu tid=%lu addr=0x%016llX module=%s module_offset=0x%llX phase=%s render_phase=%s note=not_consumed_by_earlier_handlers",
                ep->ExceptionRecord->ExceptionCode,
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(single_step_addr),
                single_step_module,
                static_cast<unsigned long long>(single_step_module_offset),
                early_phase ? early_phase : "<unknown>",
                render_phase ? render_phase : "<unknown>");
            crash_log_write(single_step_buf);
            diag::write_crash_log(single_step_buf, false);
            diag::log_tagged_critical("exception", single_step_buf);
        }

        standalone_anti_dump::handle_strip::clear_critical_flags();

        char buf[16384];
        HMODULE crash_mod = nullptr;
        char crash_mod_name[MAX_PATH] = "<unknown>";
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &crash_mod);
        if (crash_mod)
            GetModuleFileNameA(crash_mod, crash_mod_name, MAX_PATH);

        HMODULE exe_base = GetModuleHandleA(nullptr);
        uintptr_t rip_offset = ep->ContextRecord->Rip - reinterpret_cast<uintptr_t>(exe_base);
        uintptr_t addr_offset = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress) - reinterpret_cast<uintptr_t>(crash_mod);
        char test_all_snapshot[1200] = {};
        test_all_features::format_debug_snapshot(test_all_snapshot, sizeof(test_all_snapshot));
        char tracer_snapshot[2600] = {};
        format_tracer_crash_snapshot(tracer_snapshot, sizeof(tracer_snapshot));
        char shutdown_snapshot[4200] = {};
        char stack_module_buf[2200] = {};
        format_shutdown_crash_snapshot(shutdown_snapshot, sizeof(shutdown_snapshot));
        format_context_stack_modules(ep->ContextRecord, stack_module_buf, sizeof(stack_module_buf));

        char stack_buf[512] = {};
        {
            const uintptr_t* rsp_ptr = reinterpret_cast<const uintptr_t*>(ep->ContextRecord->Rsp);
            int off = 0;
            for (int i = 0; i < 12 && off < static_cast<int>(sizeof(stack_buf) - 32); ++i) {
                uintptr_t v = 0;
                if (!safe_read_qword(rsp_ptr + i, v)) break;
                off += _snprintf_s(stack_buf + off, sizeof(stack_buf) - off, _TRUNCATE,
                    "%s[%02d]=%016llX", (i == 0 ? "" : " "), i * 8,
                    static_cast<unsigned long long>(v));
            }
        }

        snprintf(buf, sizeof(buf),
            "EXCEPTION: code=0x%08X addr=0x%016llX tid=%lu\n"
            "CrashModule=%s ModuleOffset=0x%llX\n"
            "ExeBase=0x%p RipOffsetFromExe=0x%llX\n"
            "Flags=0x%08X NumParams=%lu\n"
            "Info[0]=0x%016llX Info[1]=0x%016llX\n"
            "Rax=%016llX Rcx=%016llX Rdx=%016llX Rbx=%016llX\n"
            "Rsp=%016llX Rbp=%016llX Rsi=%016llX Rdi=%016llX\n"
            "R8=%016llX R9=%016llX R10=%016llX R11=%016llX\n"
            "R12=%016llX R13=%016llX R14=%016llX R15=%016llX\n"
            "Rip=%016llX\n"
            "EFlags=%08lX Dr6=%016llX Dr7=%016llX\n"
            "Stack: %s\n"
            "StackModules=%s\n"
            "ShutdownSnapshot=%s\n"
            "TestAllSnapshot=%s\n"
            "TracerSnapshot=%s\n"
            "LastError=%lu\n",
            ep->ExceptionRecord->ExceptionCode,
            reinterpret_cast<unsigned long long>(ep->ExceptionRecord->ExceptionAddress),
            GetCurrentThreadId(),
            crash_mod_name,
            static_cast<unsigned long long>(addr_offset),
            exe_base,
            static_cast<unsigned long long>(rip_offset),
            ep->ExceptionRecord->ExceptionFlags,
            ep->ExceptionRecord->NumberParameters,
            ep->ExceptionRecord->NumberParameters > 0 ? ep->ExceptionRecord->ExceptionInformation[0] : 0ULL,
            ep->ExceptionRecord->NumberParameters > 1 ? ep->ExceptionRecord->ExceptionInformation[1] : 0ULL,
            ep->ContextRecord->Rax, ep->ContextRecord->Rcx,
            ep->ContextRecord->Rdx, ep->ContextRecord->Rbx,
            ep->ContextRecord->Rsp, ep->ContextRecord->Rbp,
            ep->ContextRecord->Rsi, ep->ContextRecord->Rdi,
            ep->ContextRecord->R8,  ep->ContextRecord->R9,
            ep->ContextRecord->R10, ep->ContextRecord->R11,
            ep->ContextRecord->R12, ep->ContextRecord->R13,
            ep->ContextRecord->R14, ep->ContextRecord->R15,
            ep->ContextRecord->Rip,
            static_cast<unsigned long>(ep->ContextRecord->EFlags),
            static_cast<unsigned long long>(ep->ContextRecord->Dr6),
            static_cast<unsigned long long>(ep->ContextRecord->Dr7),
            stack_buf,
            stack_module_buf,
            shutdown_snapshot,
            test_all_snapshot,
            tracer_snapshot,
            GetLastError());

        crash_log_write(buf);
        diag::write_crash_log(buf, false);

        anti_tamper::webhook::send_debug_log("crash", buf, true);

        return EXCEPTION_CONTINUE_SEARCH;
    });
    crash_log_write("exception_filter_set");

    {
        const uint64_t hv_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("hv_preflight_run_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(hv_tick));
        auto r = anti_tamper::hv_preflight::run();
        startup_log_critical_fmt("hv_preflight_run_post result=%u ms_hv=%d hvci=%d vbs=%d elapsed_ms=%llu",
            static_cast<unsigned>(r.result),
            anti_tamper::hv_preflight::g_ms_hv_approved ? 1 : 0,
            anti_tamper::hv_preflight::g_hvci_enabled ? 1 : 0,
            anti_tamper::hv_preflight::g_vbs_enabled ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - hv_tick));
        crash_log_write("hv_preflight_done");
        if (r.result != anti_tamper::hv_preflight::result_t::allow)
        {
            startup_log_critical_fmt("hv_preflight_refuse_ui_enter result=%u pid=%lu tid=%lu tick=%llu",
                static_cast<unsigned>(r.result),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            anti_tamper::hv_preflight::show_refuse_ui_and_exit(r);
        }
    }

    {
        const uint64_t settings_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("settings_load_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(settings_tick));
        bool settings_loaded = g_sa_settings.load();
        g_sa_settings.editor_line_numbers   = true;
        g_sa_settings.editor_word_wrap      = true;
        g_sa_settings.editor_minimap        = true;
        g_sa_settings.editor_bracket_match  = true;
        g_sa_settings.editor_highlight_line = true;
        g_sa_settings.editor_auto_complete  = true;
        g_sa_settings.ghost_text_enabled    = true;
        g_sa_settings.auto_save_enabled     = true;
        crash_log_fmt("startup_settings_loaded=%d", settings_loaded ? 1 : 0);
        try {
            auto mcp_report = anti_tamper::mcp_posture::scan_startup_posture(g_sa_settings);
            startup_log_critical_fmt("mcp_posture_scan_post trusted=%d denied=%d latched=%d files=%zu servers=%zu suspicious=%zu summary_hash=0x%016llX elapsed_ms=%llu",
                mcp_report.trusted ? 1 : 0,
                mcp_report.denied ? 1 : 0,
                mcp_report.latched ? 1 : 0,
                mcp_report.files_seen,
                mcp_report.servers_seen,
                mcp_report.suspicious,
                static_cast<unsigned long long>(mcp_report.summary_hash),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - settings_tick));
            if (!mcp_report.trusted)
                show_mcp_posture_refuse_ui_and_exit(mcp_report);
        } catch (const std::exception& e) {
            anti_tamper::mcp_posture::report_t mcp_report;
            mcp_report.scanned = true;
            mcp_report.trusted = false;
            mcp_report.denied = true;
            mcp_report.reason = "scan_exception";
            mcp_report.summary_hash = anti_tamper::mcp_posture::sanitized_summary_hash(mcp_report);
            startup_log_critical_fmt("mcp_posture_scan_exception elapsed_ms=%llu what_hash=0x%016llX",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - settings_tick),
                static_cast<unsigned long long>(diag_fnv1a64(e.what(), std::strlen(e.what()))));
            show_mcp_posture_refuse_ui_and_exit(mcp_report);
        } catch (...) {
            anti_tamper::mcp_posture::report_t mcp_report;
            mcp_report.scanned = true;
            mcp_report.trusted = false;
            mcp_report.denied = true;
            mcp_report.reason = "scan_exception";
            mcp_report.summary_hash = anti_tamper::mcp_posture::sanitized_summary_hash(mcp_report);
            startup_log_critical_fmt("mcp_posture_scan_unknown_exception elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - settings_tick));
            show_mcp_posture_refuse_ui_and_exit(mcp_report);
        }
        std::string ban_reason;
        std::string ban_message;
        if (standalone_license::startup_ban_check(g_sa_settings, ban_reason, ban_message)) {
            startup_log_critical_fmt("startup_ban_refuse reason_hash=0x%016llX reason_len=%zu elapsed_ms=%llu",
                static_cast<unsigned long long>(diag_fnv1a64(ban_reason.data(), ban_reason.size())),
                ban_reason.size(),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - settings_tick));
            crash_log_fmt("startup_ban_refuse reason=%.128s", ban_reason.c_str());
            show_ban_refuse_ui_and_exit(ban_reason, ban_message);
        }
        startup_log_critical_fmt("settings_load_post loaded=%d elapsed_ms=%llu",
            settings_loaded ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - settings_tick));
        crash_log_write("startup_ban_check_passed");
    }

    HRESULT aumid_hr = ::SetCurrentProcessExplicitAppUserModelID(L"AiDA.Standalone.IDE");
    startup_log_critical_fmt("appusermodelid hr=0x%08lX",
        static_cast<unsigned long>(aumid_hr));

    startup_log_critical_fmt("dpi_awareness_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    startup_log_critical_fmt("dpi_awareness_post last_err=%lu",
        static_cast<unsigned long>(GetLastError()));
    crash_log_write("dpi_awareness_set");

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"AiDAStandaloneWindow", nullptr };
    startup_log_critical_fmt("register_class_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    ATOM class_atom = ::RegisterClassExW(&wc);
    startup_log_critical_fmt("register_class_post atom=%u last_err=%lu",
        static_cast<unsigned>(class_atom),
        static_cast<unsigned long>(GetLastError()));
    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);
    crash_log_fmt("screen=%dx%d", screen_w, screen_h);
    startup_log_critical_fmt("create_window_pre screen_w=%d screen_h=%d pid=%lu tid=%lu tick=%llu",
        screen_w,
        screen_h,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    constexpr DWORD kAidaWindowStyle =
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
    constexpr DWORD kAidaWindowExStyle = WS_EX_APPWINDOW;
    HWND hwnd = ::CreateWindowExW(kAidaWindowExStyle,
                                  wc.lpszClassName,
                                  kAidaWindowTitle,
                                  kAidaWindowStyle,
                                  (screen_w - 200) / 2,
                                  (screen_h - 250) / 2,
                                  200,
                                  250,
                                  nullptr,
                                  nullptr,
                                  wc.hInstance,
                                  nullptr);
    g_hwnd = hwnd;
    startup_log_critical_fmt("create_window_post hwnd=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(GetLastError()));
    startup_log_critical_fmt(
        "window_style_post style=0x%08lX exstyle=0x%08lX hwnd=0x%llX last_err=%lu",
        static_cast<unsigned long>(::GetWindowLongPtrW(hwnd, GWL_STYLE)),
        static_cast<unsigned long>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(GetLastError()));
    crash_log_fmt("hwnd=%p", hwnd);


    {
        extern unsigned char aidalogo[];
        int iw2 = 0, ih2 = 0, ic = 0;
        unsigned char* px = stbi_load_from_memory(aidalogo, 1273853, &iw2, &ih2, &ic, 4);
        if (px && iw2 > 0 && ih2 > 0) {

            for (int i = 0; i < iw2 * ih2 * 4; i += 4)
                std::swap(px[i], px[i + 2]);
            HBITMAP hbm_color = CreateBitmap(iw2, ih2, 1, 32, px);
            HBITMAP hbm_mask  = CreateBitmap(iw2, ih2, 1, 1, nullptr);
            ICONINFO ii = {};
            ii.fIcon    = TRUE;
            ii.hbmColor = hbm_color;
            ii.hbmMask  = hbm_mask;
            HICON hIcon = CreateIconIndirect(&ii);
            if (hIcon) {
                g_aidaWindowIcon = hIcon;
                SendMessageW(hwnd, WM_SETICON, ICON_BIG,   (LPARAM)hIcon);
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }
            DeleteObject(hbm_color);
            DeleteObject(hbm_mask);
            stbi_image_free(px);
        }
    }
    crash_log_write("creating_d3d");
    startup_log_critical_fmt("create_d3d_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    if (!CreateDeviceD3D(hwnd))
    {
        startup_log_critical_fmt("create_d3d_failed hwnd=0x%llX last_err=%lu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            static_cast<unsigned long>(GetLastError()));
        crash_log_write("d3d_creation_FAILED");
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }
    startup_log_critical_fmt("create_d3d_post device=0x%llX ctx=0x%llX swapchain=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pSwapChain)),
        static_cast<unsigned long>(GetLastError()));
    crash_log_fmt("d3d_ok device=%p ctx=%p swapchain=%p", g_pd3dDevice, g_pd3dDeviceContext, g_pSwapChain);

    startup_log_critical_fmt("show_window_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    ::ShowWindow(hwnd, SW_SHOW);
    aida::manual_map_tls::ensure_current_thread();
    const MARGINS margin = { -1 };
    DwmExtendFrameIntoClientArea(hwnd, &margin);
    aida::manual_map_tls::ensure_current_thread();
    DWM_WINDOW_CORNER_PREFERENCE corner = DWMWCP_ROUND;
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));
    aida::manual_map_tls::ensure_current_thread();

    COLORREF border_color = RGB(33, 35, 39);
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border_color, sizeof(border_color));
    aida::manual_map_tls::ensure_current_thread();
    aida::manual_map_tls::ensure_current_thread();

    set_acrylic_color(hwnd);
    aida::manual_map_tls::ensure_current_thread();
    ::UpdateWindow(hwnd);
    aida::manual_map_tls::ensure_current_thread();
    startup_log_critical_fmt("show_window_post hwnd=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(GetLastError()));
    ::SetLastError(0);
    const BOOL full_test_hotkey_ok = ::RegisterHotKey(hwnd, kAidaFullTestHotkeyId,
        MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT, 'T');
    startup_log_critical_fmt("hotkey_register ctrl_shift_t ok=%d id=0x%X hwnd=0x%llX gle=%lu",
        full_test_hotkey_ok ? 1 : 0,
        kAidaFullTestHotkeyId,
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(GetLastError()));
    crash_log_write("window_shown_acrylic_set");

    {
        ::DragAcceptFiles(hwnd, TRUE);
        HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
        using ChangeWMFEx_t = BOOL(WINAPI*)(HWND, UINT, DWORD, void*);
        auto pChangeWMFEx = user32
            ? reinterpret_cast<ChangeWMFEx_t>(::GetProcAddress(user32, "ChangeWindowMessageFilterEx"))
            : nullptr;
        if (pChangeWMFEx) {
            pChangeWMFEx(hwnd, WM_DROPFILES, 1u, nullptr);
            pChangeWMFEx(hwnd, 0x0049u, 1u, nullptr);
            pChangeWMFEx(hwnd, WM_COPYDATA, 1u, nullptr);
            diag::log_tagged("dragdrop", "msg_filter_relaxed for elevated drop");
        } else {
            diag::log_tagged("dragdrop", "ChangeWindowMessageFilterEx unavailable");
        }
        diag::log_tagged("dragdrop", "DragAcceptFiles enabled on main window");
    }

    IMGUI_CHECKVERSION();
    aida::manual_map_tls::ensure_current_thread();
    startup_log_critical_fmt("imgui_context_create_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    ImGui::CreateContext();
    aida::manual_map_tls::ensure_current_thread();
    startup_log_critical_fmt("imgui_context_create_post ctx=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ImGui::GetCurrentContext())));
    crash_log_write("imgui_context_created");
    aida::manual_map_tls::ensure_current_thread();
    startup_log_critical_fmt("imgui_getio_pre ctx=0x%llX pid=%lu tid=%lu tick=%llu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ImGui::GetCurrentContext())),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    ImGuiIO& io = ImGui::GetIO();
    startup_log_critical_fmt("imgui_getio_post io=0x%llX fonts=0x%llX config=0x%08X",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(&io)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(io.Fonts)),
        static_cast<unsigned>(io.ConfigFlags));
    aida::manual_map_tls::ensure_current_thread();
    startup_log_critical_fmt("imgui_config_flags_pre flags=0x%08X nav_capture=%d",
        static_cast<unsigned>(io.ConfigFlags),
        io.ConfigNavCaptureKeyboard ? 1 : 0);
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
    io.ConfigNavCaptureKeyboard = false;
    startup_log_critical_fmt("imgui_config_flags_post flags=0x%08X nav_capture=%d",
        static_cast<unsigned>(io.ConfigFlags),
        io.ConfigNavCaptureKeyboard ? 1 : 0);


    {
        aida::manual_map_tls::ensure_current_thread();
        startup_log_critical_fmt("dpi_scale_query_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        UINT dpi = GetDpiForWindow(hwnd);
        aida::manual_map_tls::ensure_current_thread();
        globals::ui::dpi_scale = (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
        aida::ui::set_dpi_scale(globals::ui::dpi_scale);
        startup_log_critical_fmt("dpi_scale_query_post dpi=%u scale=%.3f last_err=%lu",
            dpi,
            globals::ui::dpi_scale,
            static_cast<unsigned long>(GetLastError()));
    }

    aida::manual_map_tls::ensure_current_thread();
    startup_log_critical_fmt("apply_initial_theme_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    apply_initial_theme();
    aida::manual_map_tls::ensure_current_thread();
    startup_log_critical_fmt("apply_initial_theme_post pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));

    startup_log_critical_fmt("rebuild_fonts_pre dpi_scale=%.3f pid=%lu tid=%lu tick=%llu",
        globals::ui::dpi_scale,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    rebuild_fonts(globals::ui::dpi_scale);
    startup_log_critical_fmt("rebuild_fonts_post ui400=0x%llX code400=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_ui_400)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_font_code_400)));

    crash_log_write("fonts_built");
    startup_log_critical_fmt("imgui_backend_win32_pre hwnd=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
    ImGui_ImplWin32_Init(hwnd);
    startup_log_critical_fmt("imgui_backend_win32_post last_err=%lu",
        static_cast<unsigned long>(GetLastError()));
    crash_log_write("imgui_win32_init_ok");
    startup_log_critical_fmt("imgui_backend_dx11_pre device=0x%llX ctx=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)));
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
    g_imgui_dx11_initialized = true;
    startup_log_critical_fmt("imgui_backend_dx11_post initialized=%d last_err=%lu",
        g_imgui_dx11_initialized ? 1 : 0,
        static_cast<unsigned long>(GetLastError()));
    crash_log_write("imgui_dx11_init_ok");
    D3D11_BLEND_DESC blend_desc = {};
    blend_desc.RenderTarget[0].BlendEnable = TRUE;
    blend_desc.RenderTarget[0].SrcBlend = D3D11_BLEND_ONE;
    blend_desc.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
    blend_desc.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
    blend_desc.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
    blend_desc.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
    blend_desc.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
    blend_desc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    startup_log_critical_fmt("blend_state_create_pre device=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)));
    g_pd3dDevice->CreateBlendState(&blend_desc, &blend_state);
    g_pd3dDeviceContext->OMSetBlendState(blend_state, nullptr, 0xffffffff);
    startup_log_critical_fmt("blend_state_create_post blend=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(blend_state)),
        static_cast<unsigned long>(GetLastError()));
    crash_log_fmt("blend_state=%p", blend_state);
    startup_log_critical_fmt("blur_init_pre device=0x%llX ctx=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)));
    Blur::Init(g_pd3dDevice, g_pd3dDeviceContext, 100, 130);
    startup_log_critical_fmt("blur_init_post last_err=%lu",
        static_cast<unsigned long>(GetLastError()));
    crash_log_write("blur_init_ok");

    static std::atomic<bool> bg_init_done{false};
    globals::ui::bg_init_done = &bg_init_done;
    globals::ui::bg_init_total.store(8, std::memory_order_release);
    globals::ui::bg_init_step.store(0, std::memory_order_release);
    startup_log_critical_fmt("bg_init_config total=%d initial_step=%d label=%s pid=%lu tid=%lu tick=%llu",
        globals::ui::bg_init_total.load(std::memory_order_acquire),
        globals::ui::bg_init_step.load(std::memory_order_acquire),
        startup_bg_phase_label(globals::ui::bg_init_step.load(std::memory_order_acquire)),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    startup_log_critical_fmt("bg_init_critical_post_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    bool bg_posted = critical_work_queue::post_labeled("startup.bg_init", []() {
        const uint64_t thread_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("bg_init_thread_entry pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(thread_tick));
        diag::log_tagged("bg_init", "thread_entry");

        auto run_step = [](const char* start_log, const char* phase, const char* ok_log, int step, auto&& fn) {
            bool cpp_ok = true;
            DWORD seh_code = 0;
            const uint64_t started = static_cast<uint64_t>(GetTickCount64());
            startup_log_critical_fmt("bg_init_run_step_pre phase=%s start_log=%s target_step=%d target_label=%s pid=%lu tid=%lu tick=%llu",
                phase ? phase : "unknown",
                start_log ? start_log : "unknown",
                step,
                startup_bg_phase_label(step),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(started));
            startup_store_bg_step(step, "bg_init_worker_enter", phase);
            diag::log_tagged("bg_init", start_log);
            try {
                seh_code = fn();
            } catch (const std::exception& e) {
                cpp_ok = false;
                startup_log_critical_fmt("bg_init_run_step_cpp_exception phase=%s elapsed_ms=%llu what=%.160s",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                    e.what());
                diag::log_tagged_fmt("bg_init", "%s_cpp_exception what=%s", phase, e.what());
            } catch (...) {
                cpp_ok = false;
                startup_log_critical_fmt("bg_init_run_step_cpp_exception phase=%s elapsed_ms=%llu what=<unknown>",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                diag::log_tagged_fmt("bg_init", "%s_cpp_exception what=<unknown>", phase);
            }
            if (seh_code != 0) {
                startup_log_critical_fmt("bg_init_run_step_seh phase=%s code=0x%08X last_err=%lu elapsed_ms=%llu",
                    phase ? phase : "unknown",
                    seh_code,
                    static_cast<unsigned long>(GetLastError()),
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                diag::log_tagged_fmt("bg_init", "%s_seh code=0x%08X last_err=%lu", phase, seh_code, GetLastError());
            }
            if (cpp_ok && seh_code == 0)
                diag::log_tagged("bg_init", ok_log);
            else
                diag::log_tagged_fmt("bg_init", "%s_failed cpp=%d seh=0x%08X", phase, cpp_ok ? 1 : 0, seh_code);
            startup_log_critical_fmt("bg_init_run_step_post phase=%s cpp=%d seh=0x%08X elapsed_ms=%llu last_err=%lu",
                phase ? phase : "unknown",
                cpp_ok ? 1 : 0,
                seh_code,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                static_cast<unsigned long>(GetLastError()));
            startup_store_bg_step(step, "bg_init_worker", phase);
        };

        run_step("init_standalone_chat_start", "init_standalone_chat", "standalone_chat_init_ok", 1,
            []() { return seh_init_standalone_chat(); });

        const bool runtime_authorized = license::validated &&
            standalone_license::is_valid() &&
            standalone_license::is_arc_loaded();
        diag::log_tagged_fmt("bg_init", "runtime_authorized_after_chat validated=%d valid=%d arc=%d",
            license::validated ? 1 : 0,
            standalone_license::is_valid() ? 1 : 0,
            standalone_license::is_arc_loaded() ? 1 : 0);

        if (runtime_authorized)
        {
            run_step("network_view_init_start", "network_view_init", "network_view_init_ok", 2,
                []() { return seh_network_view_initialize(); });

            run_step("memory_scanner_init_start", "memory_scanner_init", "memory_scanner_init_ok", 3,
                []() { return seh_memory_scanner_initialize(); });

            run_step("mitm_proxy_pre_init_start", "mitm_proxy_pre_init", "mitm_proxy_pre_init_ok", 4,
                []() { return seh_mitm_proxy_pre_initialize(); });

            startup_log_critical_fmt("bg_init_script_engine_async_pre phase=script_engine_init target_step=5 target_label=%s pid=%lu tid=%lu tick=%llu",
                startup_bg_phase_label(5),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            diag::log_tagged("bg_init", "script_engine_init_async_start");
            post_script_engine_startup_initialize();
            startup_store_bg_step(5, "bg_init_worker", "script_engine_init_async_posted");
            diag::log_tagged("bg_init", "script_engine_init_async_posted");
            g_authorized_features_initialized.store(true, std::memory_order_release);
            g_authorized_features_posted.store(true, std::memory_order_release);
        }
        else
        {
            diag::log_tagged("bg_init", "feature_init_deferred_until_arc_authorized");
            startup_store_bg_step(5, "bg_init_worker", "feature_init_deferred_until_arc_authorized");
        }

        if (runtime_authorized)
        {
            run_step("code_hashes_snapshot_start", "code_hashes_snapshot", "code_hashes_snapshot_ok", 6,
                []() { return seh_snapshot_code_hashes(); });
        }
        else
        {
            diag::log_tagged_fmt("bg_init",
                "code_hashes_snapshot_waiting_for_arc_authorized validated=%d valid=%d arc=%d",
                license::validated ? 1 : 0,
                standalone_license::is_valid() ? 1 : 0,
                standalone_license::is_arc_loaded() ? 1 : 0);
        }

        {
            startup_store_bg_step(7, "bg_init_worker", "pre_activation_anti_tamper_initialize_entering");
            const uint64_t anti_tamper_tick = static_cast<uint64_t>(GetTickCount64());
            driver_bridge::dynamic_ioctl_state_t pre_at_dyn{};
            {
                pre_at_dyn = driver_bridge::dynamic_ioctl_state();
                auto& at_rt = anti_tamper::state::get();
                startup_log_critical_fmt("anti_tamper_pre_activation_state initialized=%d driver_hardening=%d hardening_active=%d violation=%d runtime_authorized=%d validated=%d valid=%d arc=%d dyn_loaded=%d dyn_kernel=%d dyn_connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
                    at_rt.initialized.load(std::memory_order_acquire) ? 1 : 0,
                    at_rt.driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
                    at_rt.driver_hardening_active.load(std::memory_order_acquire) ? 1 : 0,
                    at_rt.violation_latched.load(std::memory_order_acquire) ? 1 : 0,
                    runtime_authorized ? 1 : 0,
                    license::validated ? 1 : 0,
                    standalone_license::is_valid() ? 1 : 0,
                    standalone_license::is_arc_loaded() ? 1 : 0,
                    pre_at_dyn.loaded ? 1 : 0,
                    pre_at_dyn.kernel ? 1 : 0,
                    pre_at_dyn.connected ? 1 : 0,
                    pre_at_dyn.ready ? 1 : 0,
                    pre_at_dyn.instance_server_seed,
                    pre_at_dyn.instance_ioctl_seed,
                    pre_at_dyn.global_server_seed,
                    pre_at_dyn.global_ioctl_seed,
                    pre_at_dyn.ioctl_seed_hash,
                    pre_at_dyn.heartbeat_ioctl_seed_hash);
            }
            const bool pre_activation_driver_unseeded = pre_at_dyn.loaded && pre_at_dyn.kernel && pre_at_dyn.connected && !pre_at_dyn.ready;
            if (!runtime_authorized && pre_activation_driver_unseeded)
            {
                startup_log_critical_fmt("anti_tamper_initialize_deferred_dynamic_ioctl_not_ready runtime_authorized=0 validated=%d valid=%d arc=%d dyn_loaded=%d dyn_kernel=%d dyn_connected=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
                    license::validated ? 1 : 0,
                    standalone_license::is_valid() ? 1 : 0,
                    standalone_license::is_arc_loaded() ? 1 : 0,
                    pre_at_dyn.loaded ? 1 : 0,
                    pre_at_dyn.kernel ? 1 : 0,
                    pre_at_dyn.connected ? 1 : 0,
                    pre_at_dyn.instance_server_seed,
                    pre_at_dyn.instance_ioctl_seed,
                    pre_at_dyn.global_server_seed,
                    pre_at_dyn.global_ioctl_seed,
                    pre_at_dyn.ioctl_seed_hash,
                    pre_at_dyn.heartbeat_ioctl_seed_hash);
                diag::log_tagged("bg_init", "pre_activation_anti_tamper_initialize_deferred_dynamic_ioctl_not_ready");
            }
            else
            {
                startup_log_critical_fmt("anti_tamper_initialize_call_pre pid=%lu tid=%lu tick=%llu runtime_authorized=%d validated=%d valid=%d arc=%d",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(anti_tamper_tick),
                runtime_authorized ? 1 : 0,
                license::validated ? 1 : 0,
                standalone_license::is_valid() ? 1 : 0,
                standalone_license::is_arc_loaded() ? 1 : 0);
            diag::log_tagged("bg_init", "pre_activation_anti_tamper_initialize_entering");
            bool at_result = false;
            DWORD seh_at = 0;
            try {
                seh_at = seh_anti_tamper_initialize(at_result);
            } catch (const std::exception& e) {
                startup_log_critical_fmt("anti_tamper_initialize_cpp_exception elapsed_ms=%llu what=%.160s",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - anti_tamper_tick),
                    e.what());
                diag::log_tagged_fmt("bg_init", "anti_tamper_initialize_cpp_exception what=%s", e.what());
            } catch (...) {
                startup_log_critical_fmt("anti_tamper_initialize_cpp_exception elapsed_ms=%llu what=<unknown>",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - anti_tamper_tick));
                diag::log_tagged("bg_init", "anti_tamper_initialize_cpp_exception what=<unknown>");
            }
            if (seh_at != 0)
                diag::log_tagged_fmt("bg_init", "anti_tamper_initialize_seh code=0x%08X last_err=%lu", seh_at, GetLastError());
            startup_log_critical_fmt("anti_tamper_initialize_call_post result=%d seh=0x%08X violation=%d elapsed_ms=%llu last_err=%lu",
                at_result ? 1 : 0,
                seh_at,
                anti_tamper::state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - anti_tamper_tick),
                static_cast<unsigned long>(GetLastError()));
            diag::log_tagged_fmt("bg_init", "anti_tamper_initialize_result=%d", at_result ? 1 : 0);
            if (!at_result) {
                diag::log_tagged_critical_fmt("bg_init",
                    "pre_activation_anti_tamper_initialize_failed_fail_closed runtime_authorized=%d validated=%d valid=%d arc=%d seh=0x%08X violation=%d",
                    runtime_authorized ? 1 : 0,
                    license::validated ? 1 : 0,
                    standalone_license::is_valid() ? 1 : 0,
                    standalone_license::is_arc_loaded() ? 1 : 0,
                    seh_at,
                    anti_tamper::state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0);
                anti_tamper::enforce_violation_id(
                    aida::reason_ids::reason_id_from_string("anti_tamper_initialize_failed"),
                    "anti_tamper_initialize_failed_pre_activation");
            }
            }
        }
        startup_store_bg_step(8, "bg_init_worker", "bg_init_all_steps_done");

        diag::log_tagged("bg_init", "session_health_init_start");
        const uint64_t session_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("session_health_initialize_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(session_tick));
        try {
            (void)session_health::initialize();
            startup_log_critical_fmt("session_health_initialize_post ok=1 elapsed_ms=%llu last_err=%lu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - session_tick),
                static_cast<unsigned long>(GetLastError()));
            diag::log_tagged("bg_init", "session_health_init_ok");
        } catch (const std::exception& e) {
            startup_log_critical_fmt("session_health_initialize_cpp_exception elapsed_ms=%llu what=%.160s",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - session_tick),
                e.what());
            diag::log_tagged_fmt("bg_init", "session_health_init_cpp_exception what=%s", e.what());
        } catch (...) {
            startup_log_critical_fmt("session_health_initialize_cpp_exception elapsed_ms=%llu what=<unknown>",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - session_tick));
            diag::log_tagged("bg_init", "session_health_init_cpp_exception what=<unknown>");
        }

        bg_init_done.store(true, std::memory_order_release);
        startup_log_critical_fmt("bg_init_thread_exit elapsed_ms=%llu final_step=%d pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - thread_tick),
            globals::ui::bg_init_step.load(std::memory_order_acquire),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        diag::log_tagged("bg_init", "thread_exit");
    });
    startup_log_critical_fmt("bg_init_critical_post_post posted=%d pid=%lu tid=%lu tick=%llu",
        bg_posted ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));


    driver_bridge::set_log_callback([](const std::string& msg) {
        crash_log_write(msg.c_str());
    });
    startup_log_critical_fmt("driver_bridge_log_callback_set pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));


    startup_log_critical_fmt("driver_bridge_init_critical_post_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    {
        auto dyn = driver_bridge::dynamic_ioctl_state();
        startup_log_critical_fmt("driver_bridge_launch_context before_post loaded=%d kernel=%d connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
            dyn.loaded ? 1 : 0,
            dyn.kernel ? 1 : 0,
            dyn.connected ? 1 : 0,
            dyn.ready ? 1 : 0,
            dyn.instance_server_seed,
            dyn.instance_ioctl_seed,
            dyn.global_server_seed,
            dyn.global_ioctl_seed,
            dyn.ioctl_seed_hash,
            dyn.heartbeat_ioctl_seed_hash);
    }
    bool driver_posted = critical_work_queue::post_labeled("startup.driver_bridge_init", [] {
        const uint64_t driver_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("driver_bridge_init_thread_entry pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(driver_tick));
        diag::log_tagged("drv_init", "thread_entry");
        DWORD seh_dbi = seh_driver_bridge_initialize();
        if (seh_dbi != 0)
            diag::log_tagged_fmt("drv_init", "driver_bridge_initialize_seh code=0x%08X last_err=%lu", seh_dbi, GetLastError());
        {
            auto dyn = driver_bridge::dynamic_ioctl_state();
            startup_log_critical_fmt("driver_bridge_launch_context after_initialize seh=0x%08X loaded=%d kernel=%d connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
                seh_dbi,
                dyn.loaded ? 1 : 0,
                dyn.kernel ? 1 : 0,
                dyn.connected ? 1 : 0,
                dyn.ready ? 1 : 0,
                dyn.instance_server_seed,
                dyn.instance_ioctl_seed,
                dyn.global_server_seed,
                dyn.global_ioctl_seed,
                dyn.ioctl_seed_hash,
                dyn.heartbeat_ioctl_seed_hash);
        }
        if (seh_dbi == 0 && driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            auto& at_rt = anti_tamper::state::get();
            if (at_rt.initialized.load(std::memory_order_acquire) &&
                !at_rt.driver_hardening_done.load(std::memory_order_acquire))
            {
                startup_log_critical_fmt("driver_bridge_init_anti_tamper_retry_pre pid=%lu tid=%lu tick=%llu",
                    GetCurrentProcessId(),
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(GetTickCount64()));
                bool at_ok = false;
                DWORD at_seh = seh_anti_tamper_initialize(at_ok);
                startup_log_critical_fmt("driver_bridge_init_anti_tamper_retry_post seh=0x%08X ok=%d driver_hardening=%d elapsed_anchor_tick=%llu last_err=%lu",
                    at_seh,
                    at_ok ? 1 : 0,
                    at_rt.driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
                    static_cast<unsigned long long>(GetTickCount64()),
                    static_cast<unsigned long>(GetLastError()));
                if (at_seh != 0 || !at_ok)
                {
                    diag::log_tagged_critical_fmt("drv_init",
                        "driver_bridge_init_anti_tamper_retry_failed seh=0x%08X ok=%d driver_hardening=%d violation=%d",
                        at_seh,
                        at_ok ? 1 : 0,
                        at_rt.driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
                        at_rt.violation_latched.load(std::memory_order_acquire) ? 1 : 0);
                    anti_tamper::enforce_violation_id(
                        aida::reason_ids::reason_id_from_string("driver_bridge_init_anti_tamper_retry_failed"),
                        "driver_bridge_init_anti_tamper_retry_failed");
                }
                else if (!at_rt.driver_hardening_done.load(std::memory_order_acquire))
                {
                    auto dyn = driver_bridge::dynamic_ioctl_state();
                    diag::log_tagged_critical_fmt("drv_init",
                        "driver_bridge_init_anti_tamper_retry_deferred driver_hardening=0 ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X",
                        dyn.ready ? 1 : 0,
                        dyn.instance_server_seed,
                        dyn.instance_ioctl_seed,
                        dyn.global_server_seed,
                        dyn.global_ioctl_seed,
                        dyn.ioctl_seed_hash);
                }
            }
        }
        startup_log_critical_fmt("driver_bridge_init_thread_exit seh=0x%08X loaded=%d kernel=%d status=%.160s elapsed_ms=%llu last_err=%lu",
            seh_dbi,
            driver_bridge::is_loaded() ? 1 : 0,
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::status().c_str(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - driver_tick),
            static_cast<unsigned long>(GetLastError()));
        diag::log_tagged("drv_init", "thread_exit");
    });
    startup_log_critical_fmt("driver_bridge_init_critical_post_post posted=%d pid=%lu tid=%lu tick=%llu",
        driver_posted ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    crash_log_write("driver_bridge_thread_launched");


    ImVec4 clear_color = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    crash_log_write("entering_render_loop");
    startup_log_critical_fmt("focus_monitor_main_start_pre hwnd=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
    aida_focus_monitor::start(hwnd);
    const int ui_prior_priority = GetThreadPriority(GetCurrentThread());
    const BOOL ui_priority_set = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    startup_log_critical_fmt("render_loop_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_critical_fmt("render",
        "ui_thread_priority prior=%d set=%d current=%d gle=%lu",
        ui_prior_priority,
        ui_priority_set ? 1 : 0,
        GetThreadPriority(GetCurrentThread()),
        ui_priority_set ? 0UL : GetLastError());


    bool done = false;
    static int prev_state = -1;
    static uint64_t frame_number = 0;
    static uint64_t skipped_render_frames = 0;
    while (!done)
    {
        const uint64_t frame_start_tick_ms = static_cast<uint64_t>(GetTickCount64());
        uint32_t pumped_messages = 0;
        uint32_t pumped_input_messages = 0;
        uint32_t pumped_resize_messages = 0;
        uint32_t pumped_paint_messages = 0;
        static uint64_t s_last_input_event_tick_ms = 0;
        static DWORD s_last_input_msg_time = 0;
        static UINT s_last_input_msg = 0;
        static uint64_t s_input_event_count = 0;
        static uint64_t s_last_input_event_log_ms = 0;
        static POINT s_last_input_cursor{};
        static bool s_last_input_cursor_valid = false;
        const uint64_t input_events_at_frame_start = s_input_event_count;
        aida_tracer::render_pulse(frame_number);
        aida_tracer::mark_render_phase("frame_top");
        if (frame_number < 5)
            crash_log_fmt("frame_begin #%llu", frame_number);

        {
            static DWORD s_last_acrylic_applied = 0;
            DWORD now_acrylic = ((DWORD)aida::ui::resolved().acrylic_color & 0x00FFFFFFu) | (0xFFu << 24);
            if (themes::changed || s_last_acrylic_applied != now_acrylic)
            {
                themes::changed = false;
                s_last_acrylic_applied = now_acrylic;

                struct ACCENT_POLICY_T { DWORD AccentState; DWORD AccentFlags; DWORD GradientColor; DWORD AnimationId; };
                struct WINCOMPATTRDATA_T { DWORD Attribute; PVOID pData; ULONG DataSize; };
                auto SetWCA = (BOOL(WINAPI*)(HWND, void*))
                    GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetWindowCompositionAttribute");
                if (SetWCA) {
                    ACCENT_POLICY_T ap = { 3, 2, now_acrylic, 0 };
                    WINCOMPATTRDATA_T wd = { 19, &ap, sizeof(ap) };
                    SetWCA(hwnd, &wd);
                    diag::log_tagged_fmt("ui", "acrylic_reapplied color=0x%08X", now_acrylic);
                }
            }
        }


        aida_tracer::mark_render_phase("peek_message_begin");
        MSG msg;
        static uint64_t sent_with_queued_last_log_ms = 0;
        for (;;)
        {
            aida_tracer::mark_render_phase("peek_message_probe");
            DWORD queue_status_before = ::GetQueueStatus(QS_ALLINPUT);
            const DWORD queue_changed = LOWORD(queue_status_before);
            const DWORD queue_current = HIWORD(queue_status_before);
            if (queue_current == 0) {
                aida_tracer::set_peek_state(queue_status_before, 0);
                aida_tracer::set_peek_call_shape(kAidaQueuedPeekFlags, nullptr);
            }
            const bool send_message_pending = (queue_current & QS_SENDMESSAGE) != 0;
            const bool non_send_pending = (queue_current & kAidaNonSendQueueBits) != 0;
            const bool send_only_pending = send_message_pending && !non_send_pending;
            const bool sent_deferred_for_queued = send_message_pending && non_send_pending;
            if (send_only_pending) {
                aida_tracer::set_peek_state(queue_status_before, 0);
                aida_tracer::set_peek_call_shape(kAidaSendOnlyPeekFlags, nullptr);
                aida_tracer::mark_render_phase("peek_message_send_only_drain");
                ::SetLastError(0);
                MSG sent_probe{};
                const uint64_t drain_start = static_cast<uint64_t>(GetTickCount64());
                BOOL sent_probe_result = ::PeekMessage(&sent_probe, nullptr, 0U, 0U, kAidaSendOnlyPeekFlags);
                const DWORD sent_probe_gle = ::GetLastError();
                const uint64_t drain_elapsed = static_cast<uint64_t>(GetTickCount64()) - drain_start;
                aida_tracer::set_peek_state(queue_status_before, sent_probe_gle);
                if (drain_elapsed >= 50) {
                    char stall_context[4600] = {};
                    format_message_pump_stall_context(stall_context, sizeof(stall_context));
                    diag::log_tagged_critical_fmt("msgpump",
                        "send_only_drain_slow frame=%llu elapsed_ms=%llu result=%d gle=%lu qs=0x%08lX current=0x%04lX changed=0x%04lX flags=0x%08X ctx={%.3600s}",
                        (unsigned long long)frame_number,
                        (unsigned long long)drain_elapsed,
                        sent_probe_result ? 1 : 0,
                        static_cast<unsigned long>(sent_probe_gle),
                        static_cast<unsigned long>(queue_status_before),
                        static_cast<unsigned long>(queue_current),
                        static_cast<unsigned long>(queue_changed),
                        kAidaSendOnlyPeekFlags,
                        stall_context[0] ? stall_context : "<empty>");
                }
                continue;
            }
            const UINT peek_remove_flags = kAidaQueuedPeekFlags;
            HWND peek_filter = nullptr;
            ::SetLastError(0);
            aida_tracer::set_peek_state(queue_status_before, 0);
            aida_tracer::set_peek_call_shape(peek_remove_flags, peek_filter);
            if (sent_deferred_for_queued) {
                const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
                if (now_ms - sent_with_queued_last_log_ms >= 1000) {
                    sent_with_queued_last_log_ms = now_ms;
                    aida_tracer::mark_render_phase("peek_message_queued_before_send");
                    diag::log_tagged_critical_fmt("msgpump",
                        "send_deferred_for_queued frame=%llu qs=0x%08lX current=0x%04lX changed=0x%04lX non_send=0x%04lX send=0x%04lX flags=0x%08X hwnd=0x%llX fg=0x%llX active=0x%llX focus=0x%llX tid=%lu",
                        (unsigned long long)frame_number,
                        static_cast<unsigned long>(queue_status_before),
                        static_cast<unsigned long>(queue_current),
                        static_cast<unsigned long>(queue_changed),
                        static_cast<unsigned long>(queue_current & kAidaNonSendQueueBits),
                        static_cast<unsigned long>(queue_current & QS_SENDMESSAGE),
                        peek_remove_flags,
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(::GetForegroundWindow())),
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(::GetActiveWindow())),
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(::GetFocus())),
                        ::GetCurrentThreadId());
                } else {
                    aida_tracer::mark_render_phase("peek_message_queued_before_send");
                }
            }
            uint64_t peek_start = static_cast<uint64_t>(GetTickCount64());
            aida_tracer::mark_render_phase("peek_message_call");
            aida_tracer::g_peek_call_count.fetch_add(1, std::memory_order_acq_rel);
            BOOL has_message = ::PeekMessage(&msg, peek_filter, 0U, 0U, peek_remove_flags);
            aida_tracer::g_peek_return_count.fetch_add(1, std::memory_order_acq_rel);
            DWORD peek_gle = ::GetLastError();
            uint64_t peek_elapsed = static_cast<uint64_t>(GetTickCount64()) - peek_start;
            aida_tracer::set_peek_state(queue_status_before, peek_gle);
            if (peek_elapsed >= 50) {
                char stall_context[4600] = {};
                format_message_pump_stall_context(stall_context, sizeof(stall_context));
                const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
                const char* render_section = g_render_section.c_str();
                const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
                diag::log_tagged_critical_fmt("msgpump",
                    "peek_slow frame=%llu elapsed_ms=%llu has_message=%d qs=0x%08lX gle=%lu flags=0x%08X filter=0x%llX msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX render_phase=%s render_section=%s wndproc_stage=%s ctx={%.3600s}",
                    (unsigned long long)frame_number,
                    (unsigned long long)peek_elapsed,
                    has_message ? 1 : 0,
                    static_cast<unsigned long>(queue_status_before),
                    static_cast<unsigned long>(peek_gle),
                    peek_remove_flags,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(peek_filter),
                    has_message ? aida_tracer::message_name(msg.message) : "<none>",
                    has_message ? msg.message : 0,
                    has_message ? (unsigned long long)reinterpret_cast<UINT_PTR>(msg.hwnd) : 0ull,
                    has_message ? (unsigned long long)static_cast<UINT_PTR>(msg.wParam) : 0ull,
                    has_message ? (unsigned long long)static_cast<LONG_PTR>(msg.lParam) : 0ull,
                    render_phase ? render_phase : "<null>",
                    render_section ? render_section : "<null>",
                    wndproc_stage ? wndproc_stage : "<null>",
                    stall_context[0] ? stall_context : "<empty>");
            }
            if (!has_message)
                break;

            ++pumped_messages;
            bool input_message = false;
            switch (msg.message) {
            case WM_MOUSEMOVE:
            case WM_NCMOUSEMOVE:
            case WM_LBUTTONDOWN:
            case WM_LBUTTONUP:
            case WM_LBUTTONDBLCLK:
            case WM_RBUTTONDOWN:
            case WM_RBUTTONUP:
            case WM_RBUTTONDBLCLK:
            case WM_MBUTTONDOWN:
            case WM_MBUTTONUP:
            case WM_XBUTTONDOWN:
            case WM_XBUTTONUP:
            case WM_NCLBUTTONDOWN:
            case WM_NCLBUTTONUP:
            case WM_NCLBUTTONDBLCLK:
            case WM_MOUSEWHEEL:
            case WM_MOUSEHWHEEL:
            case WM_KEYDOWN:
            case WM_KEYUP:
            case WM_CHAR:
            case WM_HOTKEY:
            case WM_SETFOCUS:
            case WM_KILLFOCUS:
            case WM_ACTIVATE:
            case WM_ACTIVATEAPP:
            case WM_CAPTURECHANGED:
            case WM_MOUSEACTIVATE:
                input_message = true;
                ++pumped_input_messages;
                break;
            case WM_SIZE:
            case WM_MOVE:
            case WM_DPICHANGED:
                ++pumped_resize_messages;
                break;
            case WM_PAINT:
            case WM_NCPAINT:
            case WM_ERASEBKGND:
                ++pumped_paint_messages;
                break;
            default:
                break;
            }
            if (input_message) {
                const uint64_t input_now_ms = static_cast<uint64_t>(GetTickCount64());
                const DWORD input_msg_age_ms = static_cast<DWORD>(GetTickCount() - msg.time);
                POINT input_cursor{};
                const bool input_cursor_ok = GetCursorPos(&input_cursor) != FALSE;
                const bool pointer_motion_msg = msg.message == WM_MOUSEMOVE || msg.message == WM_NCMOUSEMOVE;
                const bool cursor_changed = input_cursor_ok && (!s_last_input_cursor_valid || input_cursor.x != s_last_input_cursor.x || input_cursor.y != s_last_input_cursor.y);
                s_last_input_event_tick_ms = input_now_ms;
                s_last_input_msg_time = msg.time;
                s_last_input_msg = msg.message;
                ++s_input_event_count;
                LARGE_INTEGER qpc{};
                QueryPerformanceCounter(&qpc);
                const bool log_input_event = !pointer_motion_msg || cursor_changed || input_now_ms - s_last_input_event_log_ms >= 500ULL;
                if (log_input_event) {
                    s_last_input_event_log_ms = input_now_ms;
                    diag::log_tagged_fmt("msgpump",
                        "input_event_received frame=%llu msg=%s(0x%04X) msg_time=%lu age_ms=%lu qpc=%lld tick=%llu hwnd=0x%llX wp=0x%llX lp=0x%llX cursor_ok=%d cursor=%ld,%ld qs=0x%08lX pumped=%u pumped_input=%u",
                        static_cast<unsigned long long>(frame_number),
                        aida_tracer::message_name(msg.message),
                        msg.message,
                        static_cast<unsigned long>(msg.time),
                        static_cast<unsigned long>(input_msg_age_ms),
                        static_cast<long long>(qpc.QuadPart),
                        static_cast<unsigned long long>(input_now_ms),
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(msg.hwnd)),
                        static_cast<unsigned long long>(static_cast<UINT_PTR>(msg.wParam)),
                        static_cast<unsigned long long>(static_cast<LONG_PTR>(msg.lParam)),
                        input_cursor_ok ? 1 : 0,
                        input_cursor_ok ? input_cursor.x : 0,
                        input_cursor_ok ? input_cursor.y : 0,
                        static_cast<unsigned long>(GetQueueStatus(kAidaInteractiveQueueBits)),
                        pumped_messages,
                        pumped_input_messages);
                }
                if (input_cursor_ok) {
                    s_last_input_cursor = input_cursor;
                    s_last_input_cursor_valid = true;
                }
            }

            bool close_related_msg = msg.message == WM_CLOSE || msg.message == WM_DESTROY ||
                msg.message == WM_NCDESTROY || msg.message == WM_QUIT ||
                msg.message == WM_SYSCOMMAND || msg.message == WM_LBUTTONDOWN ||
                msg.message == WM_LBUTTONUP || msg.message == WM_NCLBUTTONDOWN ||
                msg.message == WM_NCLBUTTONUP || msg.message == WM_MOUSEACTIVATE;
            if (close_related_msg) {
                POINT cursor{};
                GetCursorPos(&cursor);
                diag::log_tagged_critical_fmt("msgpump",
                    "dequeued frame=%llu msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX cursor=%ld,%ld fg=0x%llX active=0x%llX",
                    (unsigned long long)frame_number,
                    aida_tracer::message_name(msg.message),
                    msg.message,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(msg.hwnd),
                    (unsigned long long)static_cast<UINT_PTR>(msg.wParam),
                    (unsigned long long)static_cast<LONG_PTR>(msg.lParam),
                    cursor.x,
                    cursor.y,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(GetForegroundWindow()),
                    (unsigned long long)reinterpret_cast<UINT_PTR>(GetActiveWindow()));
            }

            aida_tracer::mark_render_phase("peek_message_got");
            aida_tracer::set_dispatch_state("translate_enter", msg);
            ::TranslateMessage(&msg);
            aida_tracer::set_dispatch_state("dispatch_enter", msg);
            aida_tracer::g_dispatch_enter_count.fetch_add(1, std::memory_order_acq_rel);
            uint64_t dispatch_start = static_cast<uint64_t>(GetTickCount64());
            LRESULT dispatch_result = ::DispatchMessage(&msg);
            aida_tracer::g_dispatch_exit_count.fetch_add(1, std::memory_order_acq_rel);
            uint64_t dispatch_elapsed = static_cast<uint64_t>(GetTickCount64()) - dispatch_start;
            if (dispatch_elapsed >= 50 || close_related_msg) {
                char stall_context[4600] = {};
                if (dispatch_elapsed >= 50)
                    format_message_pump_stall_context(stall_context, sizeof(stall_context));
                const char* render_phase = aida_tracer::g_render_phase_name.load(std::memory_order_acquire);
                const char* render_section = g_render_section.c_str();
                const char* wndproc_stage = aida_tracer::g_wndproc_stage.load(std::memory_order_acquire);
                diag::log_tagged_critical_fmt("msgpump",
                    "dispatch_slow frame=%llu elapsed_ms=%llu result=0x%llX msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX render_phase=%s render_section=%s wndproc_stage=%s ctx={%.3600s}",
                    (unsigned long long)frame_number,
                    (unsigned long long)dispatch_elapsed,
                    (unsigned long long)dispatch_result,
                    aida_tracer::message_name(msg.message),
                    msg.message,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(msg.hwnd),
                    (unsigned long long)static_cast<UINT_PTR>(msg.wParam),
                    (unsigned long long)static_cast<LONG_PTR>(msg.lParam),
                    render_phase ? render_phase : "<null>",
                    render_section ? render_section : "<null>",
                    wndproc_stage ? wndproc_stage : "<null>",
                    stall_context[0] ? stall_context : "<empty>");
            }
            aida_tracer::clear_dispatch_state();
            if (msg.message == WM_QUIT)
                done = true;
        }
        aida_tracer::mark_render_phase("peek_message_done");
        if (done)
            break;

        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
        {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        static bool ide_resize_applied = false;
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            const UINT resize_w = g_ResizeWidth;
            const UINT resize_h = g_ResizeHeight;
            const uint64_t resize_now_ms = static_cast<uint64_t>(GetTickCount64());
            const uint64_t resize_age_ms = g_ResizeRequestTickMs != 0 && resize_now_ms >= g_ResizeRequestTickMs ? resize_now_ms - g_ResizeRequestTickMs : kAidaResizeCoalesceMs;
            const DWORD resize_qs = ::GetQueueStatus(kAidaInteractiveQueueBits);
            const bool resize_input_pending = (HIWORD(resize_qs) & kAidaInteractiveQueueBits) != 0;
            if (resize_age_ms < kAidaResizeCoalesceMs && resize_input_pending) {
                ++g_resize_perf.coalesced;
                static uint64_t s_last_resize_coalesce_log_ms = 0;
                if (resize_now_ms - s_last_resize_coalesce_log_ms >= 1000ULL) {
                    s_last_resize_coalesce_log_ms = resize_now_ms;
                    diag::log_tagged_fmt("render",
                        "resize_coalesce w=%u h=%u age_ms=%llu frame=%llu qs=0x%08lX requests=%llu coalesced=%llu applied=%llu skipped=%llu",
                        resize_w,
                        resize_h,
                        static_cast<unsigned long long>(resize_age_ms),
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long>(resize_qs),
                        static_cast<unsigned long long>(g_resize_perf.requests),
                        static_cast<unsigned long long>(g_resize_perf.coalesced),
                        static_cast<unsigned long long>(g_resize_perf.applied),
                        static_cast<unsigned long long>(g_resize_perf.skipped_redundant));
                }
                Sleep(1);
                continue;
            }
            diag::log_tagged_critical_fmt("render", "resize_pre w=%u h=%u frame=%llu",
                resize_w, resize_h, (unsigned long long)frame_number);
            if ((int)resize_w == prev_w && (int)resize_h == prev_h) {
                ++g_resize_perf.skipped_redundant;
                g_ResizeWidth = g_ResizeHeight = 0;
                g_ResizeRequestTickMs = 0;
                diag::log_tagged_critical_fmt("render",
                    "resize_skip_redundant w=%u h=%u prev_w=%d prev_h=%d frame=%llu skipped=%llu",
                    resize_w,
                    resize_h,
                    prev_w,
                    prev_h,
                    (unsigned long long)frame_number,
                    static_cast<unsigned long long>(g_resize_perf.skipped_redundant));
            } else {
                if (!resize_swapchain_and_target(resize_w, resize_h, frame_number, "wm_size_pending")) {
                    g_ResizeWidth = g_ResizeHeight = 0;
                    g_ResizeRequestTickMs = 0;
                    Sleep(1);
                    continue;
                }

                if (ide_resize_applied) {
                    globals::ui::window_w = (float)resize_w;
                    globals::ui::window_h = (float)resize_h;
                    diag::log_tagged_critical_fmt("render",
                        "wm_size_window_geometry_mirror w=%u h=%u maximized=%d frame=%llu",
                        resize_w,
                        resize_h,
                        globals::ui::maximized ? 1 : 0,
                        (unsigned long long)frame_number);
                }
                ::SetWindowRgn(hwnd, nullptr, TRUE);
                g_ResizeWidth = g_ResizeHeight = 0;
                g_ResizeRequestTickMs = 0;
                prev_w = static_cast<int>(resize_w);
                prev_h = static_cast<int>(resize_h);
                diag::log_tagged_critical("render", "resize_post_create_target_done");
            }
        }

        int iw = (int)globals::ui::window_w;
        int ih = (int)globals::ui::window_h;


        int cur_state = 0;
        const bool runtime_locked = anti_tamper::state::get().violation_latched.load(std::memory_order_acquire);
        const bool license_ready = license::runtime_ready(runtime_locked, test_all_features::is_running());
        if (globals::ui::load_timer >= 3.0f) cur_state = 1;
        if (globals::ui::welcome_done && !license_ready) cur_state = 2;
        if (globals::ui::welcome_done && license_ready) cur_state = 3;
        bool state_changed = (cur_state != prev_state);
        if (state_changed) prev_state = cur_state;

        static bool s_arc_startup_gate_passed = false;
        if (!s_arc_startup_gate_passed && cur_state == 3 && standalone_license::is_arc_loaded())
        {
            globals::ui::arc_unseal_phase.store(1, std::memory_order_release);
            uint8_t gate_nonce[32] = {};
            std::string sess_tok = standalone_license::get_arc_bind_token();
            if (sess_tok.empty())
                sess_tok = standalone_license::get_session_token();
            size_t cp = sess_tok.size();
            if (cp > sizeof(gate_nonce)) cp = sizeof(gate_nonce);
            if (cp > 0)
                memcpy(gate_nonce, sess_tok.data(), cp);
            const uint64_t gate_nonce_hash = diag_fnv1a64(gate_nonce, sizeof(gate_nonce));
            diag::log_tagged_critical_fmt("license",
                "arc_render_gate_nonce_source bind_token_len=%zu used_len=%zu nonce_hash=0x%016llX",
                sess_tok.size(), cp,
                static_cast<unsigned long long>(gate_nonce_hash));

            uint8_t poly_seed[32] = {};
            uint32_t poly_seed_len = 0;
            constexpr uint32_t kPolymorphismSeedFeatureId = 1u;
            bool unseal_ok = standalone_license::arc_unseal_feature_blocking(
                kPolymorphismSeedFeatureId,
                gate_nonce, sizeof(gate_nonce),
                poly_seed, &poly_seed_len, sizeof(poly_seed));
            if (!unseal_ok || poly_seed_len != 32) {
                diag::log_tagged_critical_fmt("license",
                    "arc_render_gate_unseal_FAIL unseal_ok=%d poly_seed_len=%u bind_token_len=%zu",
                    unseal_ok ? 1 : 0, poly_seed_len, sess_tok.size());
                globals::ui::arc_unseal_phase.store(3, std::memory_order_release);
                SecureZeroMemory(poly_seed, sizeof(poly_seed));
                SecureZeroMemory(gate_nonce, sizeof(gate_nonce));
                __fastfail(0xA1DAFA17u);
            }
            SecureZeroMemory(poly_seed, sizeof(poly_seed));
            SecureZeroMemory(gate_nonce, sizeof(gate_nonce));
            s_arc_startup_gate_passed = true;
            globals::ui::arc_unseal_phase.store(2, std::memory_order_release);
        }
        if (s_arc_startup_gate_passed && license_ready) {
            if (!g_authorized_features_initialized.load(std::memory_order_acquire) &&
                !g_authorized_features_posted.exchange(true, std::memory_order_acq_rel))
            {
                startup_log_critical_fmt("render_authorized_feature_critical_post_pre frame=%llu pid=%lu tid=%lu tick=%llu",
                    static_cast<unsigned long long>(frame_number),
                    GetCurrentProcessId(),
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(GetTickCount64()));
                bool posted = critical_work_queue::post_labeled("render.authorized_feature_init", [] {
                    startup_log_critical_fmt("render_authorized_feature_worker_enter pid=%lu tid=%lu tick=%llu",
                        GetCurrentProcessId(),
                        GetCurrentThreadId(),
                        static_cast<unsigned long long>(GetTickCount64()));
                    run_authorized_feature_initializers("render_authorized");
                    startup_log_critical_fmt("render_authorized_feature_worker_exit pid=%lu tid=%lu tick=%llu",
                        GetCurrentProcessId(),
                        GetCurrentThreadId(),
                        static_cast<unsigned long long>(GetTickCount64()));
                });
                startup_log_critical_fmt("render_authorized_feature_critical_post_post posted=%d frame=%llu",
                    posted ? 1 : 0,
                    static_cast<unsigned long long>(frame_number));
                if (!posted)
                {
                    g_authorized_features_posted.store(false, std::memory_order_release);
                    diag::log_tagged("bg_init", "authorized_feature_initializers_critical_post_failed");
                }
            }
            mark_ide_ready_for_mcp_services();
            start_authorized_mcp_services();
            if (!g_camoufox_prewarm_posted.exchange(true, std::memory_order_acq_rel))
            {
                bool prewarm_posted = aida::burp::camoufox::prewarm_default_async("render_authorized");
                startup_log_critical_fmt("camoufox_prewarm_request posted=%d frame=%llu pid=%lu tid=%lu tick=%llu",
                    prewarm_posted ? 1 : 0,
                    static_cast<unsigned long long>(frame_number),
                    GetCurrentProcessId(),
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(GetTickCount64()));
                if (!prewarm_posted)
                    g_camoufox_prewarm_posted.store(false, std::memory_order_release);
            }
        }


        if (cur_state == 3 && ide_resize_applied) {
            RECT wr; GetWindowRect(hwnd, &wr);
            int actual_w = wr.right - wr.left;
            int actual_h = wr.bottom - wr.top;

            if (actual_w > 200 && actual_h > 200) {
                if (abs(actual_w - iw) > 2 || abs(actual_h - ih) > 2) {
                    globals::ui::window_w = (float)actual_w;
                    globals::ui::window_h = (float)actual_h;
                    iw = actual_w;
                    ih = actual_h;
                }
            }
        }

        if (iw != prev_w || ih != prev_h)
        {
            diag::log_tagged_critical_fmt("render",
                "second_resize_pre iw=%d ih=%d prev_w=%d prev_h=%d cur_state=%d ide_resize_applied=%d frame=%llu",
                iw, ih, prev_w, prev_h, cur_state, ide_resize_applied ? 1 : 0,
                (unsigned long long)frame_number);
            if (!globals::ui::maximized) {
                if (cur_state < 3) {

                    int cx = (screen_w - iw) / 2;
                    int cy = (screen_h - ih) / 2;
                    SetWindowPos(hwnd, nullptr, cx, cy, iw, ih, SWP_NOZORDER);
                } else if (!ide_resize_applied) {

                    int cx = (screen_w - iw) / 2;
                    int cy = (screen_h - ih) / 2;
                    SetWindowPos(hwnd, nullptr, cx, cy, iw, ih, SWP_NOZORDER);
                } else {

                    SetWindowPos(hwnd, nullptr, 0, 0, iw, ih, SWP_NOZORDER | SWP_NOMOVE);
                }
            }
            if (cur_state == 3 && ((iw >= 1000 && ih >= 600) || (globals::ui::welcome_done && license::runtime_ready(anti_tamper::state::get().violation_latched.load(std::memory_order_acquire), test_all_features::is_running()))))
                ide_resize_applied = true;

            ::SetWindowRgn(hwnd, nullptr, TRUE);
            DWM_WINDOW_CORNER_PREFERENCE cp = globals::ui::maximized ? DWMWCP_DONOTROUND : DWMWCP_ROUND;
            DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
            if (!resize_swapchain_and_target(static_cast<UINT>(iw), static_cast<UINT>(ih), frame_number, "layout_size_change")) {
                Sleep(1);
                continue;
            }
            prev_w = iw;
            prev_h = ih;
            diag::log_tagged_critical("render", "second_resize_post");
        }

        ImGuiIO& pre_frame_io = ImGui::GetIO();
        const uint64_t dirty_now_ms = static_cast<uint64_t>(GetTickCount64());
        static bool dirty_state_initialized = false;
        static uint64_t last_render_tick_ms = 0;
        static uint64_t last_overlay_dirty_version = 0;
        static uint32_t last_theme_generation = 0;
        static int last_dirty_state = -1;
        static bool last_full_test_running = false;
        static bool last_bulk_busy = false;
        static bool last_activation_progress = false;
        static bool last_ai_thinking = false;
        static POINT last_cursor_pos{};
        static bool last_cursor_valid = false;
        static bool last_cursor_over = false;
        POINT cursor_pos{};
        const bool cursor_pos_ok = ::GetCursorPos(&cursor_pos) != FALSE;
        const bool cursor_moved = cursor_pos_ok && (!last_cursor_valid || cursor_pos.x != last_cursor_pos.x || cursor_pos.y != last_cursor_pos.y);
        const bool cursor_over_aida_pre = aida_cursor_over_window(hwnd);
        const bool cursor_over_changed = !dirty_state_initialized || cursor_over_aida_pre != last_cursor_over;
        const bool cursor_motion_relevant = cursor_moved && (cursor_over_aida_pre || last_cursor_over || aida_focus_monitor::focused());
        const uint64_t overlay_dirty_version = test_all_features::overlay_dirty_version();
        const uint32_t theme_generation = aida::ui::theme_generation();
        static uint64_t theme_animation_until_ms = 0;
        if (!dirty_state_initialized || themes::changed || theme_generation != last_theme_generation)
            theme_animation_until_ms = dirty_now_ms + 300ull;
        const bool theme_animation_pre = dirty_now_ms < theme_animation_until_ms;
        const bool foreground_pre = aida_focus_monitor::focused();
        const bool foreground_like_pre = foreground_pre || cursor_over_aida_pre;
        const DWORD dirty_qs = ::GetQueueStatus(kAidaInteractiveQueueBits);
        const bool interactive_pending_pre = (HIWORD(dirty_qs) & kAidaInteractiveQueueBits) != 0;
        const bool full_test_running_pre = test_all_features::is_running();
        const bool bulk_busy_pre = function_index::static_bulk_in_progress();
        const bool ai_thinking_pre = g_ai_thinking_active;
        const bool activation_progress_pre =
            license::checking ||
            license::activation_worker_active.load(std::memory_order_acquire) ||
            standalone_license::is_arc_download_in_progress() ||
            standalone_license::is_arc_transfer_in_progress();
        const bool modal_or_animation_pre =
            globals::ui::command_palette_open ||
            globals::ui::process_attach_open ||
            globals::ui::driver_status_open ||
            globals::ui::shortcuts_dialog_open ||
            g_settings_open ||
            menu_bar::any_open ||
            aida::agent_picker::is_open() ||
            source_reconstruct_view::is_open() ||
            theme_animation_pre;
        const bool input_active_pre =
            cursor_motion_relevant ||
            pre_frame_io.MouseWheel != 0.0f ||
            pre_frame_io.MouseWheelH != 0.0f ||
            pre_frame_io.WantTextInput ||
            pre_frame_io.WantCaptureKeyboard ||
            pre_frame_io.KeyCtrl ||
            pre_frame_io.KeyShift ||
            pre_frame_io.KeyAlt ||
            pre_frame_io.KeySuper;
        const bool last_input_seen_pre = s_last_input_event_tick_ms != 0;
        const uint64_t last_input_age_pre_ms = last_input_seen_pre && dirty_now_ms >= s_last_input_event_tick_ms ? dirty_now_ms - s_last_input_event_tick_ms : 0ULL;
        const bool recent_input_pre = last_input_seen_pre && last_input_age_pre_ms <= kAidaRecentInputWakeMs;
        uint32_t dirty_mask = 0;
        if (!dirty_state_initialized || frame_number < 5)
            dirty_mask |= kAidaDirtyStartup;
        if (pumped_messages != 0 || pumped_paint_messages != 0)
            dirty_mask |= kAidaDirtyMessage;
        if (pumped_resize_messages != 0 || g_ResizeWidth != 0 || g_ResizeHeight != 0 || iw != prev_w || ih != prev_h)
            dirty_mask |= kAidaDirtyResize;
        if (cur_state != last_dirty_state)
            dirty_mask |= kAidaDirtyState;
        if (pumped_input_messages != 0 || interactive_pending_pre || input_active_pre)
            dirty_mask |= kAidaDirtyInput;
        if (cursor_over_changed || cursor_motion_relevant)
            dirty_mask |= kAidaDirtyCursor;
        if (globals::ui::test_all_visible && overlay_dirty_version != last_overlay_dirty_version)
            dirty_mask |= kAidaDirtyOverlay;
        if (themes::changed || theme_generation != last_theme_generation || theme_animation_pre)
            dirty_mask |= kAidaDirtyTheme;
        if (modal_or_animation_pre)
            dirty_mask |= kAidaDirtyModal;
        if (full_test_running_pre != last_full_test_running ||
            activation_progress_pre != last_activation_progress ||
            ai_thinking_pre != last_ai_thinking ||
            activation_progress_pre ||
            ai_thinking_pre)
            dirty_mask |= kAidaDirtyProgress;
        if (bulk_busy_pre != last_bulk_busy)
            dirty_mask |= kAidaDirtyWork;
        const uint64_t since_render_ms = last_render_tick_ms != 0 && dirty_now_ms >= last_render_tick_ms ? dirty_now_ms - last_render_tick_ms : 0;
        uint64_t heartbeat_ms = foreground_like_pre ? kAidaForegroundIdleHeartbeatMs : kAidaBackgroundIdleHeartbeatMs;
        if (full_test_running_pre || bulk_busy_pre)
            heartbeat_ms = kAidaFullTestHeartbeatMs;
        if (modal_or_animation_pre || activation_progress_pre || ai_thinking_pre)
            heartbeat_ms = kAidaModalHeartbeatMs;
        if (!dirty_state_initialized || since_render_ms >= heartbeat_ms)
            dirty_mask |= kAidaDirtyHeartbeat | kAidaDirtySecurity;
        const bool dirty_fast_mask_pre = (dirty_mask & (kAidaDirtyInput | kAidaDirtyCursor | kAidaDirtyResize | kAidaDirtyMessage)) != 0;
        const bool wake_fast_pre =
            dirty_fast_mask_pre ||
            interactive_pending_pre ||
            input_active_pre ||
            recent_input_pre ||
            pumped_messages != 0 ||
            modal_or_animation_pre ||
            activation_progress_pre;
        DWORD idle_wait_request_ms = kAidaBackgroundIdleWaitMs;
        if (wake_fast_pre)
            idle_wait_request_ms = kAidaInteractiveWaitMs;
        else if (foreground_like_pre)
            idle_wait_request_ms = (full_test_running_pre || bulk_busy_pre || activation_progress_pre) ? kAidaForegroundActiveWaitMs : kAidaForegroundIdleWaitMs;
        else if (full_test_running_pre || bulk_busy_pre)
            idle_wait_request_ms = kAidaBackgroundActiveWaitMs;
        frame_wait_result_t pre_render_wait{};
        if (dirty_mask == 0) {
            aida_tracer::mark_render_phase("idle_frame_wait");
            const frame_wait_result_t idle_wait = wait_for_frame_latency_or_input(idle_wait_request_ms);
            ++skipped_render_frames;
            static uint64_t s_last_skip_wait_log_ms = 0;
            const bool skip_wait_anomaly = idle_wait.result == WAIT_FAILED || (idle_wait.waitable_present && idle_wait.actual_ms == 0 && !idle_wait.input_available && !idle_wait.frame_latency_signaled);
            if (skip_wait_anomaly && dirty_now_ms - s_last_skip_wait_log_ms >= 5000ull) {
                s_last_skip_wait_log_ms = dirty_now_ms;
                diag::log_tagged_fmt("render",
                    "dirty_skip_anomaly skipped=%llu waitable=%d request_ms=%lu actual_ms=%lu result=0x%08lX gle=%lu input=%d signaled=%d immediate_timeout_streak=%llu qs=0x%08lX foreground=%d cursor_over=%d recent_input=%d input_seen=%d last_input_msg=0x%04X last_input_age_ms=%llu full_test=%d bulk_busy=%d",
                    static_cast<unsigned long long>(skipped_render_frames),
                    idle_wait.waitable_present ? 1 : 0,
                    static_cast<unsigned long>(idle_wait.requested_ms),
                    static_cast<unsigned long>(idle_wait.actual_ms),
                    static_cast<unsigned long>(idle_wait.result),
                    static_cast<unsigned long>(idle_wait.gle),
                    idle_wait.input_available ? 1 : 0,
                    idle_wait.frame_latency_signaled ? 1 : 0,
                    static_cast<unsigned long long>(idle_wait.immediate_timeout_streak),
                    static_cast<unsigned long>(dirty_qs),
                    foreground_pre ? 1 : 0,
                    cursor_over_aida_pre ? 1 : 0,
                    recent_input_pre ? 1 : 0,
                    last_input_seen_pre ? 1 : 0,
                    static_cast<unsigned>(s_last_input_msg),
                    static_cast<unsigned long long>(last_input_age_pre_ms),
                    full_test_running_pre ? 1 : 0,
                    bulk_busy_pre ? 1 : 0);
            }
            aida_tracer::mark_render_phase("idle_frame_skipped");
            continue;
        }
        DWORD pre_render_wait_ms = kAidaPreRenderWaitMs;
        if ((dirty_mask & (kAidaDirtyInput | kAidaDirtyCursor | kAidaDirtyResize | kAidaDirtyMessage)) != 0)
            pre_render_wait_ms = 0;
        aida_tracer::mark_render_phase("pre_render_wait");
        pre_render_wait = wait_for_frame_latency_or_input(pre_render_wait_ms);
        aida_tracer::mark_render_phase("pre_render_wait_done");
        if (pre_render_wait.input_available && (dirty_mask & (kAidaDirtyInput | kAidaDirtyCursor | kAidaDirtyResize | kAidaDirtyMessage)) == 0) {
            ++skipped_render_frames;
            aida_tracer::mark_render_phase("pre_render_input_requeue");
            continue;
        }
        dirty_state_initialized = true;
        last_render_tick_ms = dirty_now_ms;
        last_overlay_dirty_version = overlay_dirty_version;
        last_theme_generation = theme_generation;
        last_dirty_state = cur_state;
        last_full_test_running = full_test_running_pre;
        last_bulk_busy = bulk_busy_pre;
        last_activation_progress = activation_progress_pre;
        last_ai_thinking = ai_thinking_pre;
        if (cursor_pos_ok) {
            last_cursor_pos = cursor_pos;
            last_cursor_valid = true;
        }
        last_cursor_over = cursor_over_aida_pre;

        if (frame_number < 5)
            crash_log_write("dx11_new_frame");
        aida_tracer::mark_render_phase("dx11_new_frame");
        DWORD seh_dxnf = seh_dx11_new_frame();
        if (seh_dxnf != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_dx11_new_frame code=0x%08X frame=%llu",
                seh_dxnf, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_write("win32_new_frame");
        aida_tracer::mark_render_phase("win32_new_frame");
        DWORD seh_w32 = seh_win32_new_frame();
        if (seh_w32 != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_win32_new_frame code=0x%08X frame=%llu",
                seh_w32, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_write("imgui_new_frame");
        aida_tracer::mark_render_phase("imgui_new_frame");
        DWORD seh_inf = seh_imgui_new_frame();
        if (seh_inf != 0)
        {
            diag::log_tagged_critical_fmt("render", "SEH_in_imgui_new_frame code=0x%08X frame=%llu",
                seh_inf, (unsigned long long)frame_number);
            diag::log_tagged_critical_fmt("render", "skip_frame_after_imgui_new_frame_exception code=0x%08X frame=%llu",
                seh_inf, (unsigned long long)frame_number);
            aida_tracer::mark_render_phase("imgui_new_frame_exception_skip");
            frame_number++;
            Sleep(1);
            continue;
        }

        aida::ui::clock::tick();
        aida::ui::tick_theme_animation(aida::ui::clock::dt());
        {
            const auto& __t = aida::ui::resolved();
            themes::resolved.name = "AiDA";
            themes::resolved.accent = __t.accent;
            themes::resolved.bg_base = __t.bg_base;
            themes::resolved.panel_bg = __t.panel_bg;
            themes::resolved.panel_header = __t.panel_header;
            themes::resolved.title_bar = __t.title_bar;
            themes::resolved.text_primary = __t.text_primary;
            themes::resolved.text_secondary = __t.text_secondary;
            themes::resolved.text_dim = __t.text_dim;
            themes::resolved.acrylic_color = (DWORD)__t.acrylic_color;
            globals::ui::accent = __t.accent;
        }

        {
            if (frame_number < 5)
                crash_log_write("render_title_entering");

            aida_tracer::mark_render_phase("render_title");
            DWORD seh_rt = seh_render_title(&helper, frame_number);
            if (seh_rt != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_render_title code=0x%08X frame=%llu section=%s",
                    seh_rt, (unsigned long long)frame_number, g_render_section.c_str());

            if (frame_number < 5)
                crash_log_write("render_title_done");

            aida_tracer::mark_render_phase("render_command_palette");
            DWORD seh_cp = seh_render_command_palette(frame_number);
            if (seh_cp != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_command_palette code=0x%08X frame=%llu",
                    seh_cp, (unsigned long long)frame_number);

            aida_tracer::mark_render_phase("render_agent_picker");
            DWORD seh_ap = seh_render_agent_picker(frame_number);
            if (seh_ap != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_agent_picker code=0x%08X frame=%llu",
                    seh_ap, (unsigned long long)frame_number);

            aida_tracer::mark_render_phase("render_source_reconstruct");
            DWORD seh_sr = seh_render_source_reconstruct(frame_number);
            if (seh_sr != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_source_reconstruct code=0x%08X frame=%llu",
                    seh_sr, (unsigned long long)frame_number);

            if (frame_number < 5)
                crash_log_write("source_reconstruct_done");

            DWORD seh_toast = seh_render_toast(frame_number);
            if (seh_toast != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_toast code=0x%08X frame=%llu",
                    seh_toast, (unsigned long long)frame_number);

            if (frame_number < 5)
                crash_log_write("toast_done");
        }

        const float clear_color_with_alpha[4] = { 0.0f, 0.0f, 0.0f, 0.0f };

        if (frame_number < 5)
            crash_log_write("render_submit");
        HRESULT clear_removed = S_OK;
        DWORD seh_clear = seh_clear_main_render_target(g_pd3dDeviceContext, g_mainRenderTargetView, clear_color_with_alpha, &clear_removed, frame_number);
        if (seh_clear != 0) {
            diag::log_tagged_critical_fmt("render",
                "SEH_in_clear_main_render_target code=0x%08X frame=%llu device_removed=0x%08X ctx=0x%llX rtv=0x%llX",
                seh_clear,
                static_cast<unsigned long long>(frame_number),
                static_cast<unsigned>(clear_removed),
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)),
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_mainRenderTargetView)));
            Sleep(1);
            frame_number++;
            continue;
        }
        aida_tracer::mark_render_phase("imgui_render");
        DWORD seh_ir = seh_imgui_render();
        if (seh_ir != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_imgui_render code=0x%08X frame=%llu",
                seh_ir, (unsigned long long)frame_number);
        ImDrawData* draw_data = ImGui::GetDrawData();
        const draw_data_metrics_t draw_metrics = collect_draw_data_metrics(draw_data);
        begin_gpu_frame_query(frame_number);
        aida_tracer::mark_render_phase("imgui_dx11_render");
        DWORD seh_idr = seh_imgui_dx11_render(draw_data, frame_number);
        if (seh_idr != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_imgui_dx11_render code=0x%08X frame=%llu",
                seh_idr, (unsigned long long)frame_number);
        g_pd3dDeviceContext->OMSetBlendState(blend_state, nullptr, 0xffffffff);
        end_gpu_frame_query(frame_number);

        aida_tracer::mark_render_phase("present");
        HRESULT hr = S_OK;
        const uint64_t present_start_tick_ms = static_cast<uint64_t>(GetTickCount64());
        DWORD seh_present = seh_swapchain_present(g_pSwapChain, &hr, frame_number);
        const uint64_t present_elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - present_start_tick_ms;
        collect_gpu_frame_query(frame_number);
        if (seh_present != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_present code=0x%08X frame=%llu",
                seh_present, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_fmt("present_hr=0x%08X", hr);
        else if ((hr & 0x80000000u) || hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET)
            diag::log_tagged_critical_fmt("render", "present_hr_NONZERO=0x%08X frame=%llu",
                hr, (unsigned long long)frame_number);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);

        const uint64_t timing_now_ms = static_cast<uint64_t>(GetTickCount64());
        const uint64_t frame_elapsed_ms = timing_now_ms - frame_start_tick_ms;
        const bool input_seen_present = s_last_input_event_tick_ms != 0;
        const uint64_t input_age_present_ms = input_seen_present && timing_now_ms >= s_last_input_event_tick_ms ? timing_now_ms - s_last_input_event_tick_ms : 0ULL;
        const uint64_t input_events_this_frame = s_input_event_count >= input_events_at_frame_start ? s_input_event_count - input_events_at_frame_start : 0ULL;
        const bool present_failed = (hr & 0x80000000u) || hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET;
        const bool frame_slow = frame_elapsed_ms >= 250ULL || present_elapsed_ms >= 100ULL;
        if (frame_number < 5)
            crash_log_fmt("frame_end #%llu", frame_number);
        {
            static uint64_t s_last_frame_timing_log_ms = 0;
            if ((present_failed || frame_slow) && (timing_now_ms - s_last_frame_timing_log_ms) >= 5000ULL) {
                s_last_frame_timing_log_ms = timing_now_ms;
                const DWORD timing_qs = ::GetQueueStatus(kAidaInteractiveQueueBits);
                diag::log_tagged_fmt("render",
                    "frame_timing_sample frame=%llu frame_ms=%llu present_ms=%llu sync=%u flags=0x%08X hr=0x%08X cursor_over=%d foreground=%d interactive_pending=%d qs=0x%08lX threads_active=%lu tid=%lu",
                    static_cast<unsigned long long>(frame_number),
                    static_cast<unsigned long long>(frame_elapsed_ms),
                    static_cast<unsigned long long>(present_elapsed_ms),
                    static_cast<unsigned>(kAidaPresentSyncInterval),
                    static_cast<unsigned>(kAidaPresentFlags),
                    static_cast<unsigned>(hr),
                    aida_cursor_over_window(hwnd) ? 1 : 0,
                    aida_focus_monitor::focused() ? 1 : 0,
                    (HIWORD(timing_qs) & kAidaInteractiveQueueBits) != 0 ? 1 : 0,
                    static_cast<unsigned long>(timing_qs),
                    static_cast<unsigned long>(count_current_process_threads(nullptr)),
                    ::GetCurrentThreadId());
            }
        }
        frame_number++;

        {
            const uint64_t tick_now_ms = static_cast<uint64_t>(GetTickCount64());
            uint32_t idle_block_mask = 0;
            if (bulk_busy_pre) idle_block_mask |= 0x00000001u;
            if (full_test_running_pre) idle_block_mask |= 0x00000002u;
            if (activation_progress_pre) idle_block_mask |= 0x00000004u;
            if (input_active_pre) idle_block_mask |= 0x00000008u;
            if (interactive_pending_pre) idle_block_mask |= 0x00000010u;
            if (cursor_over_aida_pre) idle_block_mask |= 0x00000020u;
            if (modal_or_animation_pre) idle_block_mask |= 0x00000040u;
            if (wake_fast_pre) idle_block_mask |= 0x00000080u;
            if (recent_input_pre) idle_block_mask |= 0x00000100u;
            if (dirty_fast_mask_pre) idle_block_mask |= 0x00000200u;

            static uint64_t s_last_idle_pacing_probe_ms = 0;
            static uint64_t s_last_idle_pacing_log_ms = 0;
            if (tick_now_ms - s_last_idle_pacing_probe_ms >= 5000ULL) {
                s_last_idle_pacing_probe_ms = tick_now_ms;
                DWORD thread_err = 0;
                const DWORD thread_count = count_current_process_threads(&thread_err);
                const auto wq = work_queue::stats();
                const auto svc = work_queue::service_stats();
                const auto cq = critical_work_queue::stats();
                const bool idle_unhealthy =
                    thread_err != 0 ||
                    wq.pending != 0 ||
                    svc.pending != 0 ||
                    cq.pending != 0 ||
                    wq.oldest_active_ms >= 30000ULL ||
                    svc.oldest_active_ms >= 30000ULL ||
                    cq.oldest_active_ms >= 30000ULL;
                if (idle_unhealthy && tick_now_ms - s_last_idle_pacing_log_ms >= 30000ULL) {
                    s_last_idle_pacing_log_ms = tick_now_ms;
                    diag::log_tagged_fmt("render",
                        "idle_pacing_anomaly frame=%llu pre_render_wait_ms=%lu idle_wait_request_ms=%lu dirty_mask=0x%08X block_mask=0x%08X foreground=%d foreground_like=%d cursor_over=%d recent_input=%d last_input_age_ms=%llu interactive_pending=%d qs=0x%08lX bulk_busy=%d full_test=%d skipped=%llu threads=%lu thread_err=%lu wq_active=%u wq_pending=%zu wq_oldest_ms=%llu svc_active=%u svc_pending=%zu svc_oldest_ms=%llu cq_active=%u cq_pending=%zu cq_oldest_ms=%llu",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long>(pre_render_wait.actual_ms),
                        static_cast<unsigned long>(idle_wait_request_ms),
                        static_cast<unsigned>(dirty_mask),
                        static_cast<unsigned>(idle_block_mask),
                        foreground_pre ? 1 : 0,
                        foreground_like_pre ? 1 : 0,
                        cursor_over_aida_pre ? 1 : 0,
                        recent_input_pre ? 1 : 0,
                        static_cast<unsigned long long>(last_input_age_pre_ms),
                        interactive_pending_pre ? 1 : 0,
                        static_cast<unsigned long>(dirty_qs),
                        bulk_busy_pre ? 1 : 0,
                        full_test_running_pre ? 1 : 0,
                        static_cast<unsigned long long>(skipped_render_frames),
                        static_cast<unsigned long>(thread_count),
                        static_cast<unsigned long>(thread_err),
                        static_cast<unsigned>(wq.active),
                        wq.pending,
                        static_cast<unsigned long long>(wq.oldest_active_ms),
                        static_cast<unsigned>(svc.active),
                        svc.pending,
                        static_cast<unsigned long long>(svc.oldest_active_ms),
                        static_cast<unsigned>(cq.active),
                        cq.pending,
                        static_cast<unsigned long long>(cq.oldest_active_ms));
                    diag::log_tagged_fmt("render",
                        "idle_pacing_queue frame=%llu queue=general attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu active=%u pending=%zu oldest_ms=%llu label_count=%u healthy_long=%u hot=%u not_queryable=%u top_cpu={%.700s} labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(wq.post_attempts),
                        static_cast<unsigned long long>(wq.posted),
                        static_cast<unsigned long long>(wq.rejected),
                        static_cast<unsigned long long>(wq.started),
                        static_cast<unsigned long long>(wq.finished),
                        static_cast<unsigned>(wq.active),
                        wq.pending,
                        static_cast<unsigned long long>(wq.oldest_active_ms),
                        static_cast<unsigned>(wq.active_label_count),
                        static_cast<unsigned>(wq.healthy_long_lived),
                        static_cast<unsigned>(wq.hot_workers),
                        static_cast<unsigned>(wq.not_queryable_workers),
                        wq.top_cpu_labels.empty() ? "<none>" : wq.top_cpu_labels.c_str(),
                        wq.active_labels.empty() ? "<none>" : wq.active_labels.c_str());
                    diag::log_tagged_fmt("render",
                        "idle_pacing_queue frame=%llu queue=service attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu active=%u pending=%zu oldest_ms=%llu label_count=%u healthy_long=%u hot=%u not_queryable=%u top_cpu={%.700s} labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(svc.post_attempts),
                        static_cast<unsigned long long>(svc.posted),
                        static_cast<unsigned long long>(svc.rejected),
                        static_cast<unsigned long long>(svc.started),
                        static_cast<unsigned long long>(svc.finished),
                        static_cast<unsigned>(svc.active),
                        svc.pending,
                        static_cast<unsigned long long>(svc.oldest_active_ms),
                        static_cast<unsigned>(svc.active_label_count),
                        static_cast<unsigned>(svc.healthy_long_lived),
                        static_cast<unsigned>(svc.hot_workers),
                        static_cast<unsigned>(svc.not_queryable_workers),
                        svc.top_cpu_labels.empty() ? "<none>" : svc.top_cpu_labels.c_str(),
                        svc.active_labels.empty() ? "<none>" : svc.active_labels.c_str());
                    diag::log_tagged_fmt("render",
                        "idle_pacing_queue frame=%llu queue=critical attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu active=%u pending=%zu oldest_ms=%llu label_count=%u healthy_long=%u hot=%u not_queryable=%u top_cpu={%.700s} labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(cq.post_attempts),
                        static_cast<unsigned long long>(cq.posted),
                        static_cast<unsigned long long>(cq.rejected),
                        static_cast<unsigned long long>(cq.started),
                        static_cast<unsigned long long>(cq.finished),
                        static_cast<unsigned>(cq.active),
                        cq.pending,
                        static_cast<unsigned long long>(cq.oldest_active_ms),
                        static_cast<unsigned>(cq.active_label_count),
                        static_cast<unsigned>(cq.healthy_long_lived),
                        static_cast<unsigned>(cq.hot_workers),
                        static_cast<unsigned>(cq.not_queryable_workers),
                        cq.top_cpu_labels.empty() ? "<none>" : cq.top_cpu_labels.c_str(),
                        cq.active_labels.empty() ? "<none>" : cq.active_labels.c_str());
                    work_queue::log_stuck_workers(30000ULL, 8);
                    work_queue::log_service_stuck_workers(30000ULL, 8);
                    critical_work_queue::log_stuck_workers(30000ULL, 8);
                }
            }
            static uint64_t s_last_frame_pacing_log_ms = 0;
            static uint64_t s_last_frame_pacing_frame = 0;
            static uint64_t s_last_frame_pacing_skipped = 0;
            static uint64_t s_last_frame_pacing_input_events = 0;
            const bool wait_failed = pre_render_wait.result == WAIT_FAILED;
            if (s_last_frame_pacing_log_ms == 0) {
                s_last_frame_pacing_log_ms = tick_now_ms;
                s_last_frame_pacing_frame = frame_number;
                s_last_frame_pacing_skipped = skipped_render_frames;
                s_last_frame_pacing_input_events = s_input_event_count;
                (void)sample_current_process_cpu(tick_now_ms);
                (void)sample_process_io_delta(tick_now_ms);
                (void)sample_log_file_deltas();
            } else {
                const uint64_t since_pacing_log_ms = tick_now_ms >= s_last_frame_pacing_log_ms ? tick_now_ms - s_last_frame_pacing_log_ms : 0ULL;
                const bool pacing_due = since_pacing_log_ms >= kAidaFramePacingLogIntervalMs;
                const bool pacing_anomaly = wait_failed || present_failed || frame_slow || (pre_render_wait.waitable_present && pre_render_wait.requested_ms != 0 && pre_render_wait.actual_ms == 0 && !pre_render_wait.frame_latency_signaled);
                if (pacing_due || (pacing_anomaly && since_pacing_log_ms >= 5000ULL)) {
                    DWORD thread_err = 0;
                    const DWORD thread_count = count_current_process_threads(&thread_err);
                    const auto wq = work_queue::stats();
                    const auto svc = work_queue::service_stats();
                    const auto cq = critical_work_queue::stats();
                    const process_cpu_delta_t cpu = sample_current_process_cpu(tick_now_ms);
                    const process_io_delta_t proc_io = sample_process_io_delta(tick_now_ms);
                    const log_file_delta_snapshot_t log_files = sample_log_file_deltas();
                    const defender_process_snapshot_t defender = sample_defender_processes();
                    const uint64_t frame_delta = frame_number >= s_last_frame_pacing_frame ? frame_number - s_last_frame_pacing_frame : 0ULL;
                    const uint64_t skipped_delta = skipped_render_frames >= s_last_frame_pacing_skipped ? skipped_render_frames - s_last_frame_pacing_skipped : 0ULL;
                    const uint64_t input_events_delta = s_input_event_count >= s_last_frame_pacing_input_events ? s_input_event_count - s_last_frame_pacing_input_events : 0ULL;
                    const double fps = since_pacing_log_ms != 0 ? (static_cast<double>(frame_delta) * 1000.0) / static_cast<double>(since_pacing_log_ms) : 0.0;
                    const auto overlay_perf = test_all_features::overlay_perf_snapshot();
                    const gpu_frame_sample_t gpu = latest_gpu_frame_sample(frame_number);
                    const auto log_stats = diag::async_log_stats();
                    const auto blur_stats = Blur::SnapshotStats();
                    diag::log_tagged_fmt("render",
                        "frame_pacing_sample frame=%llu frames_delta=%llu skipped_delta=%llu skipped_total=%llu fps=%.2f cpu_pct=%.2f cpu_valid=%d cpu_wall_ms=%llu cpu_busy_100ns=%llu cpu_gle=%lu logical_processors=%lu gpu_available=%d gpu_valid=%d gpu_pending=%d gpu_ms=%.3f gpu_frame=%llu gpu_ready_frame=%llu gpu_disjoint=%d gpu_data_hr=0x%08X gpu_create_hr=0x%08X gpu_frequency=%llu gpu_samples=%llu gpu_misses=%llu sync=%u flags=0x%08X frame_ms=%llu present_ms=%llu waitable=%d pre_wait_request_ms=%lu pre_wait_actual_ms=%lu pre_wait_result=0x%08lX pre_wait_gle=%lu pre_wait_input=%d pre_wait_signaled=%d dirty_mask=0x%08X idle_wait_request_ms=%lu foreground=%d foreground_like=%d cursor_over=%d interactive_pending=%d qs=0x%08lX block_mask=0x%08X bulk_busy=%d full_test=%d modal=%d activation=%d ai_thinking=%d pumped=%u pumped_input=%u pumped_resize=%u pumped_paint=%u draw_lists=%d draw_cmds=%d draw_vtx=%d draw_idx=%d callbacks=%d reset_callbacks=%d overlay_visible=%d overlay_running=%d overlay_total=%zu overlay_cached=%zu overlay_rendered=%zu overlay_log_version=%llu overlay_dirty=0x%016llX overlay_snapshot_changed=%d overlay_snapshot_busy=%d overlay_lock_busy=%llu overlay_render_us=%llu resize_requests=%llu resize_applied=%llu resize_coalesced=%llu resize_skipped=%llu rt_recreates=%llu blur_resizes=%llu threads=%lu thread_err=%lu wq_active=%u wq_pending=%zu wq_oldest_ms=%llu wq_healthy_long=%u wq_hot=%u wq_not_queryable=%u svc_active=%u svc_pending=%zu svc_oldest_ms=%llu svc_healthy_long=%u svc_hot=%u svc_not_queryable=%u cq_active=%u cq_pending=%zu cq_oldest_ms=%llu cq_healthy_long=%u cq_hot=%u cq_not_queryable=%u",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(frame_delta),
                        static_cast<unsigned long long>(skipped_delta),
                        static_cast<unsigned long long>(skipped_render_frames),
                        fps,
                        cpu.cpu_percent,
                        cpu.valid ? 1 : 0,
                        static_cast<unsigned long long>(cpu.wall_ms),
                        static_cast<unsigned long long>(cpu.busy_100ns),
                        static_cast<unsigned long>(cpu.gle),
                        static_cast<unsigned long>(cpu.logical_processors),
                        gpu.available ? 1 : 0,
                        gpu.valid ? 1 : 0,
                        gpu.pending ? 1 : 0,
                        gpu.gpu_ms,
                        static_cast<unsigned long long>(gpu.frame),
                        static_cast<unsigned long long>(gpu.ready_frame),
                        gpu.disjoint ? 1 : 0,
                        static_cast<unsigned>(gpu.data_hr),
                        static_cast<unsigned>(gpu.create_hr),
                        static_cast<unsigned long long>(gpu.frequency),
                        static_cast<unsigned long long>(gpu.samples),
                        static_cast<unsigned long long>(gpu.misses),
                        static_cast<unsigned>(kAidaPresentSyncInterval),
                        static_cast<unsigned>(kAidaPresentFlags),
                        static_cast<unsigned long long>(frame_elapsed_ms),
                        static_cast<unsigned long long>(present_elapsed_ms),
                        pre_render_wait.waitable_present ? 1 : 0,
                        static_cast<unsigned long>(pre_render_wait.requested_ms),
                        static_cast<unsigned long>(pre_render_wait.actual_ms),
                        static_cast<unsigned long>(pre_render_wait.result),
                        static_cast<unsigned long>(pre_render_wait.gle),
                        pre_render_wait.input_available ? 1 : 0,
                        pre_render_wait.frame_latency_signaled ? 1 : 0,
                        static_cast<unsigned>(dirty_mask),
                        static_cast<unsigned long>(idle_wait_request_ms),
                        foreground_pre ? 1 : 0,
                        foreground_like_pre ? 1 : 0,
                        cursor_over_aida_pre ? 1 : 0,
                        interactive_pending_pre ? 1 : 0,
                        static_cast<unsigned long>(dirty_qs),
                        static_cast<unsigned>(idle_block_mask),
                        bulk_busy_pre ? 1 : 0,
                        full_test_running_pre ? 1 : 0,
                        modal_or_animation_pre ? 1 : 0,
                        activation_progress_pre ? 1 : 0,
                        ai_thinking_pre ? 1 : 0,
                        pumped_messages,
                        pumped_input_messages,
                        pumped_resize_messages,
                        pumped_paint_messages,
                        draw_metrics.draw_lists,
                        draw_metrics.draw_cmds,
                        draw_metrics.total_vtx,
                        draw_metrics.total_idx,
                        draw_metrics.callbacks,
                        draw_metrics.reset_callbacks,
                        overlay_perf.visible ? 1 : 0,
                        overlay_perf.running ? 1 : 0,
                        overlay_perf.total_log_lines,
                        overlay_perf.cached_log_lines,
                        overlay_perf.rendered_log_rows,
                        static_cast<unsigned long long>(overlay_perf.log_version),
                        static_cast<unsigned long long>(overlay_perf.dirty_version),
                        overlay_perf.snapshot_changed ? 1 : 0,
                        overlay_perf.snapshot_busy ? 1 : 0,
                        static_cast<unsigned long long>(overlay_perf.lock_busy_total),
                        static_cast<unsigned long long>(overlay_perf.render_elapsed_us),
                        static_cast<unsigned long long>(g_resize_perf.requests),
                        static_cast<unsigned long long>(g_resize_perf.applied),
                        static_cast<unsigned long long>(g_resize_perf.coalesced),
                        static_cast<unsigned long long>(g_resize_perf.skipped_redundant),
                        static_cast<unsigned long long>(g_resize_perf.render_target_recreates),
                        static_cast<unsigned long long>(g_resize_perf.blur_resize_calls),
                        static_cast<unsigned long>(thread_count),
                        static_cast<unsigned long>(thread_err),
                        static_cast<unsigned>(wq.active),
                        wq.pending,
                        static_cast<unsigned long long>(wq.oldest_active_ms),
                        static_cast<unsigned>(wq.healthy_long_lived),
                        static_cast<unsigned>(wq.hot_workers),
                        static_cast<unsigned>(wq.not_queryable_workers),
                        static_cast<unsigned>(svc.active),
                        svc.pending,
                        static_cast<unsigned long long>(svc.oldest_active_ms),
                        static_cast<unsigned>(svc.healthy_long_lived),
                        static_cast<unsigned>(svc.hot_workers),
                        static_cast<unsigned>(svc.not_queryable_workers),
                        static_cast<unsigned>(cq.active),
                        cq.pending,
                        static_cast<unsigned long long>(cq.oldest_active_ms),
                        static_cast<unsigned>(cq.healthy_long_lived),
                        static_cast<unsigned>(cq.hot_workers),
                        static_cast<unsigned>(cq.not_queryable_workers));
                    diag::log_tagged_fmt("render",
                        "frame_pacing_io frame=%llu present_hr=0x%08X wait_immediate_timeout_streak=%llu input_seen=%d last_input_msg=0x%04X last_input_msg_time=%lu last_input_age_newframe_ms=%llu input_to_present_ms=%llu input_events_delta=%llu input_events_this_frame=%llu proc_io_valid=%d proc_io_gle=%lu proc_io_wall_ms=%llu proc_read_ops_delta=%llu proc_write_ops_delta=%llu proc_other_ops_delta=%llu proc_read_bytes_delta=%llu proc_write_bytes_delta=%llu proc_other_bytes_delta=%llu proc_total_read_bytes=%llu proc_total_write_bytes=%llu debug_log_valid=%d debug_log_size=%llu debug_log_delta=%llu debug_log_reset=%d debug_log_gle=%lu kernel_log_valid=%d kernel_log_size=%llu kernel_log_delta=%llu kernel_log_reset=%d kernel_log_gle=%lu full_test_log_valid=%d full_test_log_size=%llu full_test_log_delta=%llu full_test_log_reset=%d full_test_log_gle=%lu camoufox_log_valid=%d camoufox_log_size=%llu camoufox_log_delta=%llu camoufox_log_reset=%d camoufox_log_gle=%lu defender_valid=%d defender_gle=%lu defender_msmpeng=%u defender_mpcmdrun=%u log_started=%d log_start_failed=%d log_queue_depth=%llu log_max_queue_depth=%llu log_queue_lock_busy=%d log_file_lock_busy=%d log_queued=%llu log_queued_bytes=%llu log_written=%llu log_written_bytes=%llu log_direct=%llu log_force_batches=%llu log_force_flushes=%llu log_normal_flushes=%llu log_flush_ms_total=%llu log_flush_ms_max=%llu log_flush_failures=%llu log_last_flush_error=%llu log_pending_flush_bytes=%llu log_tag_events=%llu log_tag_bytes=%llu log_tag_forced=%llu log_coalesced_success=%llu log_coalesced_bytes=%llu log_coalesced_summaries=%llu log_force_downgraded=%llu",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned>(hr),
                        static_cast<unsigned long long>(pre_render_wait.immediate_timeout_streak),
                        input_seen_present ? 1 : 0,
                        static_cast<unsigned>(s_last_input_msg),
                        static_cast<unsigned long>(s_last_input_msg_time),
                        static_cast<unsigned long long>(last_input_age_pre_ms),
                        static_cast<unsigned long long>(input_age_present_ms),
                        static_cast<unsigned long long>(input_events_delta),
                        static_cast<unsigned long long>(input_events_this_frame),
                        proc_io.valid ? 1 : 0,
                        static_cast<unsigned long>(proc_io.gle),
                        static_cast<unsigned long long>(proc_io.wall_ms),
                        static_cast<unsigned long long>(proc_io.read_ops_delta),
                        static_cast<unsigned long long>(proc_io.write_ops_delta),
                        static_cast<unsigned long long>(proc_io.other_ops_delta),
                        static_cast<unsigned long long>(proc_io.read_bytes_delta),
                        static_cast<unsigned long long>(proc_io.write_bytes_delta),
                        static_cast<unsigned long long>(proc_io.other_bytes_delta),
                        static_cast<unsigned long long>(proc_io.total_read_bytes),
                        static_cast<unsigned long long>(proc_io.total_write_bytes),
                        log_files.debug_log.valid ? 1 : 0,
                        static_cast<unsigned long long>(log_files.debug_log.size),
                        static_cast<unsigned long long>(log_files.debug_log.delta),
                        log_files.debug_log.reset ? 1 : 0,
                        static_cast<unsigned long>(log_files.debug_log.gle),
                        log_files.kernel_log.valid ? 1 : 0,
                        static_cast<unsigned long long>(log_files.kernel_log.size),
                        static_cast<unsigned long long>(log_files.kernel_log.delta),
                        log_files.kernel_log.reset ? 1 : 0,
                        static_cast<unsigned long>(log_files.kernel_log.gle),
                        log_files.full_test_log.valid ? 1 : 0,
                        static_cast<unsigned long long>(log_files.full_test_log.size),
                        static_cast<unsigned long long>(log_files.full_test_log.delta),
                        log_files.full_test_log.reset ? 1 : 0,
                        static_cast<unsigned long>(log_files.full_test_log.gle),
                        log_files.camoufox_log.valid ? 1 : 0,
                        static_cast<unsigned long long>(log_files.camoufox_log.size),
                        static_cast<unsigned long long>(log_files.camoufox_log.delta),
                        log_files.camoufox_log.reset ? 1 : 0,
                        static_cast<unsigned long>(log_files.camoufox_log.gle),
                        defender.valid ? 1 : 0,
                        static_cast<unsigned long>(defender.gle),
                        static_cast<unsigned>(defender.msmpeng),
                        static_cast<unsigned>(defender.mpcmdrun),
                        log_stats.started ? 1 : 0,
                        log_stats.start_failed ? 1 : 0,
                        static_cast<unsigned long long>(log_stats.queue_depth),
                        static_cast<unsigned long long>(log_stats.max_queue_depth),
                        log_stats.queue_lock_busy ? 1 : 0,
                        log_stats.file_lock_busy ? 1 : 0,
                        static_cast<unsigned long long>(log_stats.queued_items),
                        static_cast<unsigned long long>(log_stats.queued_bytes),
                        static_cast<unsigned long long>(log_stats.written_items),
                        static_cast<unsigned long long>(log_stats.written_bytes),
                        static_cast<unsigned long long>(log_stats.direct_items),
                        static_cast<unsigned long long>(log_stats.force_batches),
                        static_cast<unsigned long long>(log_stats.force_flushes),
                        static_cast<unsigned long long>(log_stats.normal_flushes),
                        static_cast<unsigned long long>(log_stats.flush_elapsed_ms_total),
                        static_cast<unsigned long long>(log_stats.flush_elapsed_ms_max),
                        static_cast<unsigned long long>(log_stats.flush_failures),
                        static_cast<unsigned long long>(log_stats.last_flush_error),
                        static_cast<unsigned long long>(log_stats.bytes_pending_flush),
                        static_cast<unsigned long long>(log_stats.tag_metric_events),
                        static_cast<unsigned long long>(log_stats.tag_metric_bytes),
                        static_cast<unsigned long long>(log_stats.tag_metric_forced),
                        static_cast<unsigned long long>(log_stats.coalesced_success_events),
                        static_cast<unsigned long long>(log_stats.coalesced_success_bytes),
                        static_cast<unsigned long long>(log_stats.coalesced_success_summaries),
                        static_cast<unsigned long long>(log_stats.coalesced_success_force_downgrades));
                    diag::log_tagged_fmt("render",
                        "frame_pacing_log_tags frame=%llu top_tags={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        log_stats.top_tags.empty() ? "<none>" : log_stats.top_tags.c_str());
                    diag::log_tagged_fmt("render",
                        "frame_pacing_blur frame=%llu callbacks=%d expected_blur_callbacks=%d unexpected_callbacks=%d reset_callbacks=%d draw_requests=%llu blur_callbacks=%llu suppressed_full_test=%llu slow=%llu slow_suppressed=%llu cache_reuse=%llu adaptive_fallback=%llu last_cache_age_ms=%llu pressure_until_ms=%llu invalid=%llu no_rtv=%llu total_area=%llu last_area=%llu total_ms=%llu copy_ms=%llu h_ms=%llu v_ms=%llu restore_ms=%llu last_total_ms=%llu last_copy_ms=%llu last_h_ms=%llu last_v_ms=%llu last_restore_ms=%llu removed=0x%08lX",
                        static_cast<unsigned long long>(frame_number),
                        draw_metrics.callbacks,
                        draw_metrics.expected_blur_callbacks,
                        draw_metrics.unexpected_callbacks,
                        draw_metrics.reset_callbacks,
                        static_cast<unsigned long long>(blur_stats.draw_requests),
                        static_cast<unsigned long long>(blur_stats.callbacks),
                        static_cast<unsigned long long>(blur_stats.suppressed_full_test),
                        static_cast<unsigned long long>(blur_stats.slow_callbacks),
                        static_cast<unsigned long long>(blur_stats.slow_suppressed),
                        static_cast<unsigned long long>(blur_stats.cache_reuse),
                        static_cast<unsigned long long>(blur_stats.adaptive_fallback),
                        static_cast<unsigned long long>(blur_stats.last_cache_age_ms),
                        static_cast<unsigned long long>(blur_stats.pressure_until_ms),
                        static_cast<unsigned long long>(blur_stats.invalid_callbacks),
                        static_cast<unsigned long long>(blur_stats.no_rtv),
                        static_cast<unsigned long long>(blur_stats.total_area),
                        static_cast<unsigned long long>(blur_stats.last_area),
                        static_cast<unsigned long long>(blur_stats.total_elapsed_ms),
                        static_cast<unsigned long long>(blur_stats.copy_elapsed_ms),
                        static_cast<unsigned long long>(blur_stats.horizontal_elapsed_ms),
                        static_cast<unsigned long long>(blur_stats.vertical_elapsed_ms),
                        static_cast<unsigned long long>(blur_stats.restore_elapsed_ms),
                        static_cast<unsigned long long>(blur_stats.last_elapsed_ms),
                        static_cast<unsigned long long>(blur_stats.last_copy_ms),
                        static_cast<unsigned long long>(blur_stats.last_horizontal_ms),
                        static_cast<unsigned long long>(blur_stats.last_vertical_ms),
                        static_cast<unsigned long long>(blur_stats.last_restore_ms),
                        static_cast<unsigned long>(blur_stats.last_device_removed));
                    diag::log_tagged_fmt("render",
                        "frame_pacing_queue frame=%llu queue=general attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu active=%u pending=%zu oldest_ms=%llu label_count=%u healthy_long=%u hot=%u not_queryable=%u top_cpu={%.700s} labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(wq.post_attempts),
                        static_cast<unsigned long long>(wq.posted),
                        static_cast<unsigned long long>(wq.rejected),
                        static_cast<unsigned long long>(wq.started),
                        static_cast<unsigned long long>(wq.finished),
                        static_cast<unsigned>(wq.active),
                        wq.pending,
                        static_cast<unsigned long long>(wq.oldest_active_ms),
                        static_cast<unsigned>(wq.active_label_count),
                        static_cast<unsigned>(wq.healthy_long_lived),
                        static_cast<unsigned>(wq.hot_workers),
                        static_cast<unsigned>(wq.not_queryable_workers),
                        wq.top_cpu_labels.empty() ? "<none>" : wq.top_cpu_labels.c_str(),
                        wq.active_labels.empty() ? "<none>" : wq.active_labels.c_str());
                    diag::log_tagged_fmt("render",
                        "frame_pacing_queue frame=%llu queue=service attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu active=%u pending=%zu oldest_ms=%llu label_count=%u healthy_long=%u hot=%u not_queryable=%u top_cpu={%.700s} labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(svc.post_attempts),
                        static_cast<unsigned long long>(svc.posted),
                        static_cast<unsigned long long>(svc.rejected),
                        static_cast<unsigned long long>(svc.started),
                        static_cast<unsigned long long>(svc.finished),
                        static_cast<unsigned>(svc.active),
                        svc.pending,
                        static_cast<unsigned long long>(svc.oldest_active_ms),
                        static_cast<unsigned>(svc.active_label_count),
                        static_cast<unsigned>(svc.healthy_long_lived),
                        static_cast<unsigned>(svc.hot_workers),
                        static_cast<unsigned>(svc.not_queryable_workers),
                        svc.top_cpu_labels.empty() ? "<none>" : svc.top_cpu_labels.c_str(),
                        svc.active_labels.empty() ? "<none>" : svc.active_labels.c_str());
                    diag::log_tagged_fmt("render",
                        "frame_pacing_queue frame=%llu queue=critical attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu active=%u pending=%zu oldest_ms=%llu label_count=%u healthy_long=%u hot=%u not_queryable=%u top_cpu={%.700s} labels={%.900s}",
                        static_cast<unsigned long long>(frame_number),
                        static_cast<unsigned long long>(cq.post_attempts),
                        static_cast<unsigned long long>(cq.posted),
                        static_cast<unsigned long long>(cq.rejected),
                        static_cast<unsigned long long>(cq.started),
                        static_cast<unsigned long long>(cq.finished),
                        static_cast<unsigned>(cq.active),
                        cq.pending,
                        static_cast<unsigned long long>(cq.oldest_active_ms),
                        static_cast<unsigned>(cq.active_label_count),
                        static_cast<unsigned>(cq.healthy_long_lived),
                        static_cast<unsigned>(cq.hot_workers),
                        static_cast<unsigned>(cq.not_queryable_workers),
                        cq.top_cpu_labels.empty() ? "<none>" : cq.top_cpu_labels.c_str(),
                        cq.active_labels.empty() ? "<none>" : cq.active_labels.c_str());
                    static uint64_t s_last_post_test_cpu_correlation_ms = 0;
                    const bool post_test_cpu_pressure = !full_test_running_pre && cpu.valid && cpu.cpu_percent >= 25.0;
                    if (post_test_cpu_pressure && (s_last_post_test_cpu_correlation_ms == 0 || tick_now_ms - s_last_post_test_cpu_correlation_ms >= 10000ULL)) {
                        s_last_post_test_cpu_correlation_ms = tick_now_ms;
                        diag::log_tagged_fmt("render",
                            "post_test_cpu_correlation frame=%llu cpu_pct=%.2f cpu_wall_ms=%llu cpu_busy_100ns=%llu proc_io_valid=%d proc_write_bytes_delta=%llu proc_read_bytes_delta=%llu debug_log_delta=%llu kernel_log_delta=%llu full_test_log_delta=%llu camoufox_log_delta=%llu defender_valid=%d defender_msmpeng=%u defender_mpcmdrun=%u wq_top_cpu={%.700s} svc_top_cpu={%.700s} cq_top_cpu={%.700s} wq_labels={%.900s} svc_labels={%.900s} cq_labels={%.900s}",
                            static_cast<unsigned long long>(frame_number),
                            cpu.cpu_percent,
                            static_cast<unsigned long long>(cpu.wall_ms),
                            static_cast<unsigned long long>(cpu.busy_100ns),
                            proc_io.valid ? 1 : 0,
                            static_cast<unsigned long long>(proc_io.write_bytes_delta),
                            static_cast<unsigned long long>(proc_io.read_bytes_delta),
                            static_cast<unsigned long long>(log_files.debug_log.delta),
                            static_cast<unsigned long long>(log_files.kernel_log.delta),
                            static_cast<unsigned long long>(log_files.full_test_log.delta),
                            static_cast<unsigned long long>(log_files.camoufox_log.delta),
                            defender.valid ? 1 : 0,
                            static_cast<unsigned>(defender.msmpeng),
                            static_cast<unsigned>(defender.mpcmdrun),
                            wq.top_cpu_labels.empty() ? "<none>" : wq.top_cpu_labels.c_str(),
                            svc.top_cpu_labels.empty() ? "<none>" : svc.top_cpu_labels.c_str(),
                            cq.top_cpu_labels.empty() ? "<none>" : cq.top_cpu_labels.c_str(),
                            wq.active_labels.empty() ? "<none>" : wq.active_labels.c_str(),
                            svc.active_labels.empty() ? "<none>" : svc.active_labels.c_str(),
                            cq.active_labels.empty() ? "<none>" : cq.active_labels.c_str());
                    }
                    s_last_frame_pacing_log_ms = tick_now_ms;
                    s_last_frame_pacing_frame = frame_number;
                    s_last_frame_pacing_skipped = skipped_render_frames;
                    s_last_frame_pacing_input_events = s_input_event_count;
                    static uint64_t s_last_runtime_acceptance_log_ms = 0;
                    if (s_last_runtime_acceptance_log_ms == 0 || tick_now_ms - s_last_runtime_acceptance_log_ms >= kAidaRuntimeAcceptanceLogIntervalMs) {
                        s_last_runtime_acceptance_log_ms = tick_now_ms;
                        diag::log_tagged_fmt("render",
                            "runtime_acceptance_sample frame=%llu fps=%.2f cpu_pct=%.2f cpu_valid=%d gpu_available=%d gpu_valid=%d gpu_pending=%d gpu_ms=%.3f sync=%u flags=0x%08X waitable=%d dirty_mask=0x%08X skipped_total=%llu overlay_visible=%d overlay_running=%d overlay_rendered=%zu overlay_render_us=%llu resize_requests=%llu resize_applied=%llu resize_coalesced=%llu resize_skipped=%llu rt_recreates=%llu blur_resizes=%llu threads=%lu wq_active=%u wq_pending=%zu svc_active=%u svc_pending=%zu cq_active=%u cq_pending=%zu",
                            static_cast<unsigned long long>(frame_number),
                            fps,
                            cpu.cpu_percent,
                            cpu.valid ? 1 : 0,
                            gpu.available ? 1 : 0,
                            gpu.valid ? 1 : 0,
                            gpu.pending ? 1 : 0,
                            gpu.gpu_ms,
                            static_cast<unsigned>(kAidaPresentSyncInterval),
                            static_cast<unsigned>(kAidaPresentFlags),
                            pre_render_wait.waitable_present ? 1 : 0,
                            static_cast<unsigned>(dirty_mask),
                            static_cast<unsigned long long>(skipped_render_frames),
                            overlay_perf.visible ? 1 : 0,
                            overlay_perf.running ? 1 : 0,
                            overlay_perf.rendered_log_rows,
                            static_cast<unsigned long long>(overlay_perf.render_elapsed_us),
                            static_cast<unsigned long long>(g_resize_perf.requests),
                            static_cast<unsigned long long>(g_resize_perf.applied),
                            static_cast<unsigned long long>(g_resize_perf.coalesced),
                            static_cast<unsigned long long>(g_resize_perf.skipped_redundant),
                            static_cast<unsigned long long>(g_resize_perf.render_target_recreates),
                            static_cast<unsigned long long>(g_resize_perf.blur_resize_calls),
                            static_cast<unsigned long>(thread_count),
                            static_cast<unsigned>(wq.active),
                            wq.pending,
                            static_cast<unsigned>(svc.active),
                            svc.pending,
                            static_cast<unsigned>(cq.active),
                            cq.pending);
                    }
                }
            }
        }
    }

    aida_shutdown_diag::mark("shutdown_sequence_begin");
    diag::log_tagged_critical_fmt("main",
        "shutdown_sequence_begin frame=%llu done=%d hwnd=0x%llX tid=%lu",
        (unsigned long long)frame_number,
        done ? 1 : 0,
        (unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
        GetCurrentThreadId());
    aida_tracer::mark_render_phase("shutdown_sequence_begin");
    {
        char queue_snapshot[2400] = {};
        format_work_queue_crash_snapshot(queue_snapshot, sizeof(queue_snapshot));
        diag::log_tagged_critical_fmt("main", "shutdown_queue_snapshot_pre %s", queue_snapshot);
    }
    aida_shutdown_diag::mark("shutdown_testlab_cancel");
    test_all_features::cancel_tests();
    diag::log_tagged_critical("main", "shutdown_testlab_cancel_done");
    aida_shutdown_diag::mark("shutdown_camoufox_force_cleanup");
    try {
        aida::burp::camoufox::force_cleanup("main.shutdown_sequence");
        diag::log_tagged_critical("main", "shutdown_camoufox_force_cleanup_done");
    } catch (...) {
        diag::log_tagged_critical("main", "shutdown_camoufox_force_cleanup_exception");
    }
    aida_shutdown_diag::mark("shutdown_focus_monitor");
    aida_focus_monitor::stop();
    diag::log_tagged_critical("main", "shutdown_focus_monitor_done");
    aida_shutdown_diag::mark("shutdown_prelude_begin");
    diag::log_tagged_critical("main", "shutdown_prelude_begin");
    try {
        aida_shutdown_diag::mark("shutdown_session_health");
        bool session_health_stopped = session_health::shutdown_and_wait(2500);
        diag::log_tagged_critical_fmt("main", "shutdown_session_health_done stopped=%d",
            session_health_stopped ? 1 : 0);
    } catch (...) {
        diag::log_tagged_critical("main", "shutdown_session_health_exception");
    }
    try {
        aida_shutdown_diag::mark("shutdown_license_workers");
        standalone_license::stop_background_workers("main.shutdown_prelude", 2500);
        diag::log_tagged_critical("main", "shutdown_license_workers_done");
    } catch (...) {
        diag::log_tagged_critical("main", "shutdown_license_workers_exception");
    }
    aida_shutdown_diag::mark("shutdown_driver_bridge_deferred");
    diag::log_tagged_critical("main", "shutdown_driver_bridge_deferred reason=queue_drain_required");
    aida_shutdown_diag::mark("shutdown_prelude_done");
    diag::log_tagged_critical("main", "shutdown_prelude_done");
    aida_shutdown_diag::mark("shutdown_anti_tamper");
    anti_tamper::shutdown();
    diag::log_tagged_critical("main", "shutdown_anti_tamper_done");
    aida_shutdown_diag::mark("shutdown_terminal");
    globals::terminal_mgr.shutdown();
    diag::log_tagged_critical("main", "shutdown_terminal_done");

    aida_shutdown_diag::mark("shutdown_network");
    {
        char network_queue_pre[2400] = {};
        format_work_queue_crash_snapshot(network_queue_pre, sizeof(network_queue_pre));
        diag::log_tagged_critical_fmt("main", "shutdown_network_cleanup_pre %s", network_queue_pre);
    }
    const uint64_t shutdown_network_start_ms = static_cast<uint64_t>(GetTickCount64());
    network_view::shutdown();
    const uint64_t shutdown_network_elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - shutdown_network_start_ms;
    {
        char network_queue_post[2400] = {};
        format_work_queue_crash_snapshot(network_queue_post, sizeof(network_queue_post));
        diag::log_tagged_critical_fmt("main", "shutdown_network_cleanup_done elapsed_ms=%llu %s",
            static_cast<unsigned long long>(shutdown_network_elapsed_ms),
            network_queue_post);
    }
    aida_shutdown_diag::mark("shutdown_script_engine");
    script_engine::shutdown();
    diag::log_tagged_critical("main", "shutdown_script_engine_done");
    aida_shutdown_diag::mark("shutdown_workflow_tools");
    workflow_tools::shutdown_services();
    diag::log_tagged_critical("main", "shutdown_workflow_tools_done");
    aida_shutdown_diag::mark("shutdown_chat");
    shutdown_standalone_chat();
    diag::log_tagged_critical("main", "shutdown_chat_done");
    aida_shutdown_diag::mark("shutdown_auth_http");
    aida::auth::http::cleanup();
    diag::log_tagged_critical("main", "shutdown_auth_http_done");
    aida_shutdown_diag::mark("shutdown_blur");
    Blur::Shutdown();
    diag::log_tagged_critical("main", "shutdown_blur_done");
    aida_shutdown_diag::mark("shutdown_imgui_dx11");
    ImGui_ImplDX11_Shutdown();
    diag::log_tagged_critical("main", "shutdown_imgui_dx11_done");

    aida_shutdown_diag::mark("shutdown_imgui_win32");
    ImGui_ImplWin32_Shutdown();
    diag::log_tagged_critical("main", "shutdown_imgui_win32_done");
    aida_shutdown_diag::mark("shutdown_imgui_context");
    ImGui::DestroyContext();
    diag::log_tagged_critical("main", "shutdown_imgui_context_done");

    aida_shutdown_diag::mark("shutdown_d3d");
    CleanupDeviceD3D();
    diag::log_tagged_critical("main", "shutdown_d3d_done");
    aida_shutdown_diag::mark("shutdown_hotkey_unregister");
    ::SetLastError(0);
    BOOL hotkey_unregistered = ::UnregisterHotKey(hwnd, kAidaFullTestHotkeyId);
    diag::log_tagged_critical_fmt("main", "shutdown_hotkey_unregister ok=%d gle=%lu",
        hotkey_unregistered ? 1 : 0,
        static_cast<unsigned long>(GetLastError()));
    aida_shutdown_diag::mark("shutdown_destroy_window");
    ::DestroyWindow(hwnd);
    diag::log_tagged_critical("main", "shutdown_destroy_window_done");
    aida_shutdown_diag::mark("shutdown_unregister_class");
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    diag::log_tagged_critical("main", "shutdown_unregister_done");

    aida_shutdown_diag::mark("shutdown_exit_process");
    diag::log_tagged_critical("main", "shutdown_exit_process_pre");
    release_single_instance_gate();
    diag::flush_async_logs(5000);
    ExitProcess(0);
    return 0;
}

bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    DXGI_SWAP_CHAIN_DESC optimized_sd = sd;
    optimized_sd.BufferDesc.RefreshRate.Numerator = 0;
    optimized_sd.BufferDesc.RefreshRate.Denominator = 1;
    optimized_sd.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
#if defined(DXGI_SWAP_EFFECT_FLIP_DISCARD)
    optimized_sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
#else
    optimized_sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
#endif
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &optimized_sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &optimized_sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (FAILED(res)) {
        if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
        if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
        if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
        g_SwapChainResizeFlags = 0;
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
        if (res == DXGI_ERROR_UNSUPPORTED)
            res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    } else {
        g_SwapChainResizeFlags = optimized_sd.Flags;
    }
    if (res != S_OK)
        return false;

    configure_frame_latency_waitable();
    CreateRenderTarget();
    initialize_gpu_frame_queries();
    return true;
}

void CleanupDeviceD3D()
{
    release_gpu_frame_queries();
    CleanupRenderTarget();
    if (g_FrameLatencyWaitableObject) { CloseHandle(g_FrameLatencyWaitableObject); g_FrameLatencyWaitableObject = nullptr; }
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    g_SwapChainResizeFlags = 0;
    g_resize_perf.blur_w = 0;
    g_resize_perf.blur_h = 0;
}

void CreateRenderTarget()
{
    ++g_resize_perf.render_target_recreates;
    ID3D11Texture2D* pBackBuffer = nullptr;
    HRESULT hr_get = E_POINTER;
    HRESULT hr_rtv = E_POINTER;
    DWORD seh_get = 0;
    DWORD seh_rtv = 0;
    aida_tracer::mark_render_phase("create_render_target_get_buffer");
    if (!g_pSwapChain || !g_pd3dDevice) {
        diag::log_tagged_critical_fmt("render",
            "create_render_target_missing_device swapchain=0x%llX device=0x%llX ctx=0x%llX",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pSwapChain)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDeviceContext)));
        return;
    }
    __try {
        hr_get = g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        seh_get = GetExceptionCode();
    }
    if (seh_get != 0 || FAILED(hr_get) || !pBackBuffer) {
        diag::log_tagged_critical_fmt("render",
            "create_render_target_get_buffer_failed seh=0x%08X hr=0x%08X backbuffer=0x%llX swapchain=0x%llX device_removed=0x%08X",
            seh_get,
            static_cast<unsigned>(hr_get),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(pBackBuffer)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pSwapChain)),
            static_cast<unsigned>(g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER));
        if (pBackBuffer)
            pBackBuffer->Release();
        return;
    }
    aida_tracer::mark_render_phase("create_render_target_create_rtv");
    __try {
        hr_rtv = g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        seh_rtv = GetExceptionCode();
    }
    if (seh_rtv != 0 || FAILED(hr_rtv) || !g_mainRenderTargetView) {
        diag::log_tagged_critical_fmt("render",
            "create_render_target_rtv_failed seh=0x%08X hr=0x%08X backbuffer=0x%llX rtv=0x%llX device=0x%llX device_removed=0x%08X",
            seh_rtv,
            static_cast<unsigned>(hr_rtv),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(pBackBuffer)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_mainRenderTargetView)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_pd3dDevice)),
            static_cast<unsigned>(g_pd3dDevice ? g_pd3dDevice->GetDeviceRemovedReason() : E_POINTER));
        pBackBuffer->Release();
        return;
    }

    D3D11_TEXTURE2D_DESC d{};
    __try {
        pBackBuffer->GetDesc(&d);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        diag::log_tagged_critical_fmt("render",
            "create_render_target_get_desc_seh code=0x%08X backbuffer=0x%llX rtv=0x%llX",
            GetExceptionCode(),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(pBackBuffer)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_mainRenderTargetView)));
        pBackBuffer->Release();
        return;
    }
    int bw = (int)(d.Width  / 4u);
    int bh = (int)(d.Height / 4u);
    if (bw < 64) bw = 64;
    if (bh < 64) bh = 64;
    const bool blur_size_changed = bw != g_resize_perf.blur_w || bh != g_resize_perf.blur_h;
    if (blur_size_changed) {
        Blur::Resize(bw, bh);
        g_resize_perf.blur_w = bw;
        g_resize_perf.blur_h = bh;
        ++g_resize_perf.blur_resize_calls;
    }
    aida::ui::blur::mark_supported(true);

    pBackBuffer->Release();
    diag::log_tagged_critical_fmt("render",
        "create_render_target_ok backbuffer=0x%llX rtv=0x%llX desc=%ux%u blur=%dx%d blur_resize=%d rt_recreates=%llu blur_resizes=%llu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(pBackBuffer)),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(g_mainRenderTargetView)),
        d.Width,
        d.Height,
        bw,
        bh,
        blur_size_changed ? 1 : 0,
        static_cast<unsigned long long>(g_resize_perf.render_target_recreates),
        static_cast<unsigned long long>(g_resize_perf.blur_resize_calls));
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

__declspec(noinline) static DWORD seh_imgui_wndproc_handler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT* result_out)
{
    if (result_out)
        *result_out = 0;
    __try {
        if (!result_out)
            return ERROR_INVALID_PARAMETER;
        *result_out = ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    aida::manual_map_tls::ensure_current_thread();
    aida_tracer::set_wndproc_state("enter", hWnd, msg, wParam, lParam);
    uint64_t wnd_start = static_cast<uint64_t>(GetTickCount64());
    const bool trace_input_msg = aida_tracer::should_log_wndproc_input_message(msg);
    auto finish = [&](const char* path, LRESULT result) -> LRESULT {
        uint64_t elapsed = static_cast<uint64_t>(GetTickCount64()) - wnd_start;
        if (aida_tracer::should_log_wndproc_completion(msg, elapsed)) {
            POINT cursor{};
            GetCursorPos(&cursor);
            diag::log_tagged_critical_fmt("wndproc",
                "exit path=%s elapsed_ms=%llu result=0x%llX msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX cursor=%ld,%ld fg=0x%llX active=0x%llX",
                path,
                (unsigned long long)elapsed,
                (unsigned long long)result,
                aida_tracer::message_name(msg),
                msg,
                (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
                (unsigned long long)static_cast<UINT_PTR>(wParam),
                (unsigned long long)static_cast<LONG_PTR>(lParam),
                cursor.x,
                cursor.y,
                (unsigned long long)reinterpret_cast<UINT_PTR>(GetForegroundWindow()),
                (unsigned long long)reinterpret_cast<UINT_PTR>(GetActiveWindow()));
        }
        aida_tracer::clear_wndproc_state();
        return result;
    };

    auto log_session_shutdown = [&](const char* source) {
        char snapshot[2200] = {};
        test_all_features::format_debug_snapshot(snapshot, sizeof(snapshot));
        const bool full_test_running = test_all_features::is_running();
        diag::log_tagged_critical_fmt("session",
            "%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX full_test_running=%d shutdown=%d closeapp=%d critical=%d logoff=%d snapshot=%s",
            source ? source : "session_event",
            aida_tracer::message_name(msg),
            msg,
            (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
            (unsigned long long)static_cast<UINT_PTR>(wParam),
            (unsigned long long)static_cast<LONG_PTR>(lParam),
            full_test_running ? 1 : 0,
            wParam ? 1 : 0,
            (lParam & ENDSESSION_CLOSEAPP) ? 1 : 0,
            (lParam & ENDSESSION_CRITICAL) ? 1 : 0,
            (lParam & ENDSESSION_LOGOFF) ? 1 : 0,
            snapshot);
        if (full_test_running)
            test_all_features::log_external_session_event(source, msg,
                static_cast<std::uintptr_t>(wParam),
                static_cast<std::intptr_t>(lParam));
    };

    if (msg == WM_GETICON)
        return finish("geticon_fast", reinterpret_cast<LRESULT>(g_aidaWindowIcon));

    if (msg == WM_QUERYENDSESSION) {
        aida_tracer::set_wndproc_state("queryendsession", hWnd, msg, wParam, lParam);
        log_session_shutdown("WM_QUERYENDSESSION");
        return finish("queryendsession_allow", TRUE);
    }

    if (msg == WM_ENDSESSION) {
        aida_tracer::set_wndproc_state("endsession", hWnd, msg, wParam, lParam);
        log_session_shutdown(wParam ? "WM_ENDSESSION_COMMIT" : "WM_ENDSESSION_CANCEL");
        return finish("endsession", 0);
    }

    if (msg == WM_HOTKEY && static_cast<int>(wParam) == kAidaFullTestHotkeyId) {
        const WORD mods = LOWORD(lParam);
        const WORD vk = HIWORD(lParam);
        const bool foreground = aida_focus_monitor::foreground_belongs_to_process(hWnd);
        diag::log_tagged_critical_fmt("ui",
            "test_all_start hotkey=WM_HOTKEY id=0x%X mods=0x%04X vk=0x%04X foreground=%d hwnd=0x%llX",
            static_cast<unsigned>(wParam),
            static_cast<unsigned>(mods),
            static_cast<unsigned>(vk),
            foreground ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)));
        if (!foreground)
            return finish("hotkey_full_test_ignored_foreground", 0);
        const bool accepted = test_all_features::trigger_from_hotkey("win32_ctrl_shift_t");
        return finish(accepted ? "hotkey_full_test_accepted" : "hotkey_full_test_rejected", 0);
    }

    if (msg == WM_CLOSE ||
        (msg == WM_SYSCOMMAND && ((wParam & 0xfff0) == SC_CLOSE))) {
        const bool sys_close = (msg == WM_SYSCOMMAND);
        aida_shutdown_diag::mark(sys_close ? "wndproc_syscommand_close_destroy" : "wndproc_wm_close_destroy");
        ::SetLastError(0);
        BOOL destroyed = ::DestroyWindow(hWnd);
        DWORD gle = ::GetLastError();
        diag::log_tagged_critical_fmt("wndproc",
            "close_destroy source=%s hwnd=0x%llX destroyed=%d gle=%lu tid=%lu",
            sys_close ? "WM_SYSCOMMAND_SC_CLOSE" : "WM_CLOSE",
            (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
            destroyed ? 1 : 0,
            static_cast<unsigned long>(gle),
            GetCurrentThreadId());
        if (!destroyed)
            ::PostQuitMessage(0);
        return finish(sys_close ? "syscommand_close_destroy" : "close_destroy", 0);
    }

    if (msg == WM_DESTROY) {
        aida_shutdown_diag::mark("wndproc_destroy_post_quit");
        diag::log_tagged_critical_fmt("wndproc",
            "destroy_post_quit hwnd=0x%llX tid=%lu",
            (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
            GetCurrentThreadId());
        ::PostQuitMessage(0);
        return finish("destroy", 0);
    }

    if (trace_input_msg) {
        POINT cursor{};
        GetCursorPos(&cursor);
        diag::log_tagged_critical_fmt("wndproc",
            "imgui_handler_call msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX cursor=%ld,%ld fg=0x%llX active=0x%llX focus=0x%llX capture=0x%llX",
            aida_tracer::message_name(msg),
            msg,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
            static_cast<unsigned long long>(static_cast<UINT_PTR>(wParam)),
            static_cast<unsigned long long>(static_cast<LONG_PTR>(lParam)),
            cursor.x,
            cursor.y,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetForegroundWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetActiveWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetFocus())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetCapture())));
    }
    aida_tracer::set_wndproc_state("imgui_enter", hWnd, msg, wParam, lParam);
    LRESULT imgui_result = 0;
    DWORD imgui_seh = 0;
    {
        aida::diagnostic_exception_scope::scope_t exception_scope("WndProc.ImGui_ImplWin32_WndProcHandler");
        imgui_seh = seh_imgui_wndproc_handler(hWnd, msg, wParam, lParam, &imgui_result);
    }
    const uint64_t imgui_elapsed = static_cast<uint64_t>(GetTickCount64()) - wnd_start;
    if (trace_input_msg || imgui_seh != 0 || imgui_elapsed >= 32) {
        POINT cursor{};
        GetCursorPos(&cursor);
        diag::log_tagged_critical_fmt("wndproc",
            "imgui_handler_return msg=%s(0x%04X) elapsed_ms=%llu seh=0x%08X result=0x%llX hwnd=0x%llX cursor=%ld,%ld fg=0x%llX active=0x%llX focus=0x%llX capture=0x%llX",
            aida_tracer::message_name(msg),
            msg,
            static_cast<unsigned long long>(imgui_elapsed),
            imgui_seh,
            static_cast<unsigned long long>(imgui_result),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
            cursor.x,
            cursor.y,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetForegroundWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetActiveWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetFocus())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetCapture())));
    }
    if (imgui_seh != 0)
        aida_tracer::set_wndproc_state("imgui_seh_recovered", hWnd, msg, wParam, lParam);
    else if (imgui_result)
        return finish("imgui", true);
    aida_tracer::set_wndproc_state("switch_enter", hWnd, msg, wParam, lParam);

    switch (msg)
    {
    case WM_GETTEXTLENGTH:
        return finish("gettextlength", static_cast<LRESULT>(std::wcslen(kAidaWindowTitle)));
    case WM_GETTEXT:
    {
        wchar_t* out = reinterpret_cast<wchar_t*>(lParam);
        size_t capacity = static_cast<size_t>(wParam);
        if (!out || capacity == 0)
            return finish("gettext_empty", 0);
        size_t title_len = std::wcslen(kAidaWindowTitle);
        size_t copy_len = (std::min)(title_len, capacity - 1);
        if (copy_len > 0)
            std::memcpy(out, kAidaWindowTitle, copy_len * sizeof(wchar_t));
        out[copy_len] = L'\0';
        return finish("gettext", static_cast<LRESULT>(copy_len));
    }
    case WM_ERASEBKGND:
        return finish("erasebkgnd", 1);
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        BeginPaint(hWnd, &ps);
        EndPaint(hWnd, &ps);
        return finish("paint", 0);
    }
    case WM_NCCALCSIZE:
    {
        if (wParam == TRUE)
        {
            NCCALCSIZE_PARAMS* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(lParam);
            RECT* rect = &params->rgrc[0];
            const bool zoomed = ::IsZoomed(hWnd) != FALSE;
            diag::log_tagged_fmt("wndproc",
                "nccalcsize zoomed=%d before=(%ld,%ld,%ld,%ld) dpi=%u",
                zoomed ? 1 : 0,
                rect->left, rect->top, rect->right, rect->bottom,
                static_cast<unsigned>(::GetDpiForWindow(hWnd)));
            if (zoomed)
            {
                const UINT dpi = ::GetDpiForWindow(hWnd);
                const int frame_x = ::GetSystemMetricsForDpi(SM_CXFRAME, dpi);
                const int frame_y = ::GetSystemMetricsForDpi(SM_CYFRAME, dpi);
                const int padding = ::GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
                const int inset = frame_x + padding;
                const int inset_y = frame_y + padding;
                rect->left   += inset;
                rect->right  -= inset;
                rect->top    += inset_y;
                rect->bottom -= inset_y;
                HMONITOR hm = ::MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
                MONITORINFO mi = { sizeof(mi) };
                if (::GetMonitorInfoW(hm, &mi))
                {
                    rect->left   = mi.rcWork.left;
                    rect->top    = mi.rcWork.top;
                    rect->right  = mi.rcWork.right;
                    rect->bottom = mi.rcWork.bottom;
                }
            }
            return finish("nccalcsize_zero_nc", 0);
        }
        break;
    }
    case WM_NCHITTEST:
    {

        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        RECT rc; GetWindowRect(hWnd, &rc);
        const int border = static_cast<int>(6 * globals::ui::dpi_scale);
        bool left   = pt.x < rc.left   + border;
        bool right  = pt.x > rc.right  - border;
        bool top    = pt.y < rc.top    + border;
        bool bottom = pt.y > rc.bottom - border;


        if (globals::ui::welcome_done &&
            license::runtime_ready(anti_tamper::state::get().violation_latched.load(std::memory_order_acquire),
                test_all_features::is_running()) &&
            !::IsZoomed(hWnd)) {
            if (top    && left)  return finish("nchittest_top_left", HTTOPLEFT);
            if (top    && right) return finish("nchittest_top_right", HTTOPRIGHT);
            if (bottom && left)  return finish("nchittest_bottom_left", HTBOTTOMLEFT);
            if (bottom && right) return finish("nchittest_bottom_right", HTBOTTOMRIGHT);
            if (left)            return finish("nchittest_left", HTLEFT);
            if (right)           return finish("nchittest_right", HTRIGHT);
            if (top)             return finish("nchittest_top", HTTOP);
            if (bottom)          return finish("nchittest_bottom", HTBOTTOM);
        }
        return finish("nchittest_client", HTCLIENT);
    }
    case WM_SIZE:
    {
        if (wParam == SIZE_MINIMIZED)
        {
            diag::log_tagged_critical_fmt("wndproc",
                "size_minimized hwnd=0x%llX iconic=%d zoomed=%d",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
                ::IsIconic(hWnd) ? 1 : 0,
                ::IsZoomed(hWnd) ? 1 : 0);
            return finish("size_minimized", 0);
        }
        const bool now_zoomed = (wParam == SIZE_MAXIMIZED) ||
                                (wParam == SIZE_RESTORED && ::IsZoomed(hWnd));
        globals::ui::maximized = now_zoomed;
        DWM_WINDOW_CORNER_PREFERENCE cp = now_zoomed ? DWMWCP_DONOTROUND : DWMWCP_ROUND;
        DwmSetWindowAttribute(hWnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        g_ResizeRequestTickMs = static_cast<uint64_t>(GetTickCount64());
        ++g_resize_perf.requests;
        diag::log_tagged_critical_fmt("wndproc",
            "size hwnd=0x%llX wp=%llu w=%u h=%u zoomed=%d resize_requests=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hWnd)),
            static_cast<unsigned long long>(static_cast<UINT_PTR>(wParam)),
            g_ResizeWidth,
            g_ResizeHeight,
            now_zoomed ? 1 : 0,
            static_cast<unsigned long long>(g_resize_perf.requests));
        return finish("size", 0);
    }
    case WM_GETMINMAXINFO:
    {

        HMONITOR hm = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi = { sizeof(mi) };
        if (GetMonitorInfoW(hm, &mi)) {
            auto* mm = reinterpret_cast<MINMAXINFO*>(lParam);
            mm->ptMaxPosition.x = mi.rcWork.left - mi.rcMonitor.left;
            mm->ptMaxPosition.y = mi.rcWork.top - mi.rcMonitor.top;
            mm->ptMaxSize.x = mi.rcWork.right - mi.rcWork.left;
            mm->ptMaxSize.y = mi.rcWork.bottom - mi.rcWork.top;
        }
        return finish("getminmaxinfo", 0);
    }
    case WM_SYSCOMMAND:
    {
        const UINT cmd = static_cast<UINT>(wParam) & 0xFFF0u;
        diag::log_tagged_critical_fmt("wndproc",
            "syscommand cmd=0x%04X wp=0x%llX lp=0x%llX zoomed=%d iconic=%d",
            cmd,
            static_cast<unsigned long long>(static_cast<UINT_PTR>(wParam)),
            static_cast<unsigned long long>(static_cast<LONG_PTR>(lParam)),
            ::IsZoomed(hWnd) ? 1 : 0,
            ::IsIconic(hWnd) ? 1 : 0);
        if (cmd == SC_KEYMENU)
            return finish("syscommand_keymenu", 0);
        break;
    }
    case WM_SETFOCUS:
        g_SwapChainOccluded = false;
        ::InvalidateRect(hWnd, nullptr, FALSE);
        return finish("setfocus", 0);
    case WM_KILLFOCUS:
        return finish("killfocus", 0);
    case WM_ACTIVATE:
        g_SwapChainOccluded = false;
        ::InvalidateRect(hWnd, nullptr, FALSE);
        return finish("activate", 0);
    case WM_ACTIVATEAPP:
        if (wParam == TRUE) {
            g_SwapChainOccluded = false;
            if (::IsWindow(hWnd) && !::IsIconic(hWnd)) {
                aida_tracer::set_wndproc_state("activateapp_acrylic", hWnd, msg, wParam, lParam);
                set_acrylic_color(hWnd);
                aida_tracer::set_wndproc_state("activateapp_invalidate", hWnd, msg, wParam, lParam);
                ::InvalidateRect(hWnd, nullptr, FALSE);
            }
        }
        return finish("activateapp", 0);
    case WM_DPICHANGED:
    {
        UINT dpi = HIWORD(wParam);
        globals::ui::dpi_scale = (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
        aida::ui::set_dpi_scale(globals::ui::dpi_scale);
        RECT* suggested = reinterpret_cast<RECT*>(lParam);
        aida_tracer::set_wndproc_state("dpichanged_setwindowpos", hWnd, msg, wParam, lParam);
        SetWindowPos(hWnd, nullptr,
            suggested->left, suggested->top,
            suggested->right - suggested->left,
            suggested->bottom - suggested->top,
            SWP_NOZORDER | SWP_NOACTIVATE);
        aida_tracer::set_wndproc_state("dpichanged_rebuild_fonts", hWnd, msg, wParam, lParam);
        rebuild_fonts(globals::ui::dpi_scale);
        aida::ui::apply_imgui_style(aida::ui::resolved());
        return finish("dpichanged", 0);
    }
    case WM_SETTINGCHANGE:
    {
        if (lParam) {
            const wchar_t* p = reinterpret_cast<const wchar_t*>(lParam);
            if (p && (wcscmp(p, L"ImmersiveColorSet") == 0 ||
                      wcscmp(p, L"WindowsThemeElement") == 0)) {
                aida_tracer::set_wndproc_state("settingchange_apply_theme", hWnd, msg, wParam, lParam);
                apply_os_theme_animated();
            }
        }
        return finish("settingchange", 0);
    }
    case WM_DROPFILES:
    {
        HDROP hdrop = reinterpret_cast<HDROP>(wParam);
        if (hdrop) {
            aida_tracer::set_wndproc_state("dropfiles_query_count", hWnd, msg, wParam, lParam);
            UINT count = ::DragQueryFileW(hdrop, 0xFFFFFFFFu, nullptr, 0);
            diag::log_tagged_fmt("dragdrop", "WM_DROPFILES count=%u", count);
            if (count > 0) {
                wchar_t wpath[MAX_PATH] = {};
                aida_tracer::set_wndproc_state("dropfiles_query_path", hWnd, msg, wParam, lParam);
                UINT got = ::DragQueryFileW(hdrop, 0, wpath, MAX_PATH);
                if (got > 0) {
                    char path_utf8[MAX_PATH * 4] = {};
                    aida_tracer::set_wndproc_state("dropfiles_utf8", hWnd, msg, wParam, lParam);
                    int n = ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1,
                        path_utf8, sizeof(path_utf8), nullptr, nullptr);
                    if (n > 0) {
                        diag::log_tagged_fmt("dragdrop", "drop accepted path=%s", path_utf8);
                        aida_tracer::set_wndproc_state("dropfiles_open_path", hWnd, msg, wParam, lParam);
                        file_browser::open_path(std::string(path_utf8));
                    } else {
                        diag::log_tagged("dragdrop", "drop path utf8 conversion failed");
                    }
                }
            }
            aida_tracer::set_wndproc_state("dropfiles_finish", hWnd, msg, wParam, lParam);
            ::DragFinish(hdrop);
        }
        return finish("dropfiles", 0);
    }
    }
    aida_tracer::set_wndproc_state("defwindowproc_enter", hWnd, msg, wParam, lParam);
    LRESULT def_result = ::DefWindowProcW(hWnd, msg, wParam, lParam);
    return finish("defwindowproc", def_result);
}
