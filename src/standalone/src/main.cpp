#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/freetype/freetype.h"
#include "verdana.h"
#include "ide_icons.h"
#include <d3d11.h>
#include <tchar.h>
#include <windowsx.h>
#include <psapi.h>
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
#include "helpers/stb_image.h"

#include "embedded_resources.hpp"
#include "helpers/diag_log.hpp"
#include "hardware_id/hardware_id_v2.hpp"
#include "core/anti-tamper/cff.hpp"
#include "core/anti-tamper/virtualizer.hpp"
#include "core/disasm/function_index.hpp"
#include "core/auth/auth_http.hpp"
#include "core/ui/loading_binary_overlay.hpp"
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

extern "C" {
#include <openssl/applink.c>
}

#include <delayimp.h>
#include <thread>
#include <cstdarg>
#include <set>
#include <atomic>
#include <exception>
#include <cwchar>
#include <cstring>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "Shcore.lib")


static FARPROC WINAPI delay_load_hook(unsigned dliNotify, PDelayLoadInfo pdli)
{
    if (dliNotify == dliNotePreLoadLibrary) {
        if (pdli && pdli->szDll && _stricmp(pdli->szDll, "libz3.dll") == 0) {
            if (embedded_resources::g_z3_module)
                return reinterpret_cast<FARPROC>(embedded_resources::g_z3_module);
        }
    }
    return nullptr;
}

extern "C" const PfnDliHook __pfnDliNotifyHook2 = delay_load_hook;

ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static ID3D11BlendState* blend_state = nullptr;

helpers helper;
HWND g_hwnd = nullptr;
static constexpr const wchar_t* kAidaWindowTitle = L"AiDA Standalone";
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

inline int prev_w = 0;
inline int prev_h = 0;

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
    ImFontConfig cfg = cfg_in;
    cfg.FontDataOwnedByAtlas = true;
    for (const auto& p : candidate_paths) {
        if (font_file_exists(p)) {
            ImFont* f = io.Fonts->AddFontFromFileTTF(p.c_str(), pixel_size, &cfg);
            if (f) return f;
        }
    }
    if (embed_data && embed_size > 0) {
        void* copy = IM_ALLOC(embed_size);
        memcpy(copy, embed_data, embed_size);
        return io.Fonts->AddFontFromMemoryTTF(copy, (int)embed_size, pixel_size, &cfg);
    }
    return nullptr;
}

static void merge_icon_font(ImGuiIO& io, float pixel_size)
{
    static const ImWchar icon_ranges[] = { ICON_MIN_IDE, ICON_MAX_IDE, 0 };
    ImFontConfig icon_cfg{};
    icon_cfg.MergeMode = true;
    icon_cfg.PixelSnapH = true;
    icon_cfg.GlyphMinAdvanceX = pixel_size;
    icon_cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    void* icon_data_copy = IM_ALLOC(ide_icon_font_size);
    memcpy(icon_data_copy, ide_icon_font_data, ide_icon_font_size);
    io.Fonts->AddFontFromMemoryTTF(icon_data_copy, ide_icon_font_size, pixel_size, &icon_cfg, icon_ranges);
}

static void rebuild_fonts(float dpi_scale)
{
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();

    float screen_factor = 1.0f;
    {
        HMONITOR hm = MonitorFromWindow(g_hwnd ? g_hwnd : GetDesktopWindow(), MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{ sizeof(mi) };
        if (GetMonitorInfoW(hm, &mi)) {
            int mw = mi.rcMonitor.right - mi.rcMonitor.left;
            int mh = mi.rcMonitor.bottom - mi.rcMonitor.top;
            int diag = (int)sqrtf((float)(mw * mw + mh * mh));
            if (diag >= 3000) screen_factor = 1.35f;
            else if (diag >= 2400) screen_factor = 1.25f;
            else if (diag >= 2050) screen_factor = 1.18f;
            else screen_factor = 1.10f;
        }
    }

    const float texture_scale = dpi_scale * screen_factor;
    const float base = 16.0f * texture_scale;
    const float lg   = 18.0f * texture_scale;
    const float sm   = 13.0f * texture_scale;
    const float xl   = 32.0f * texture_scale;
    const float code = 14.0f * texture_scale;
    const float code_lg = 28.0f * texture_scale;
    io.FontGlobalScale = 1.0f;

    const bool enable_lcd = dpi_scale >= 1.5f;
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
        c.OversampleH = 1;
        c.OversampleV = 1;
        c.RasterizerMultiply = multiply;
        return c;
    };

    const std::string repo_dir = repo_fonts_dir();
    const std::string user_dir = user_fonts_dir();
    const std::string sys_dir  = sys_fonts_dir();

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

    ImFontConfig c_400 = cfg_ui_smooth(1.15f);
    ImFontConfig c_500 = cfg_ui_smooth(1.15f);
    ImFontConfig c_600 = cfg_ui_hinted(1.05f);
    ImFontConfig c_700 = cfg_ui_hinted(1.05f);
    ImFontConfig c_mono = cfg_mono(1.00f);

    g_font_ui_400 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_400, base, c_400);
    merge_icon_font(io, base);

    g_font_ui_500 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_500, base, c_500);
    g_font_ui_600 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_600, base, c_600);
    g_font_ui_700 = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                              inter_700, base, c_700);
    g_font_ui_400_lg = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_400, lg, c_400);
    g_font_ui_500_sm = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_500, sm, c_500);
    g_font_ui_700_xl = load_font_with_fallbacks(io, (const char*)verdana, sizeof(verdana),
                                                 inter_700, xl, c_700);

    g_font_code_400 = load_font_with_fallbacks(io, nullptr, 0, jbm_400, code, c_mono);
    g_font_code_600 = load_font_with_fallbacks(io, nullptr, 0, jbm_600, code, c_mono);
    g_font_code_400_lg = load_font_with_fallbacks(io, nullptr, 0, jbm_400, code_lg, c_mono);
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
    io.Fonts->Build();
    extern bool g_imgui_dx11_initialized;
    if (g_imgui_dx11_initialized) {
        ImGui_ImplDX11_InvalidateDeviceObjects();
    }
}

bool g_imgui_dx11_initialized = false;

static DWORD compute_acrylic_color_for_theme()
{
    const auto& t = aida::ui::resolved();
    return ((DWORD)t.acrylic_color & 0x00FFFFFFu) | (0xFFu << 24);
}

void set_acrylic_color(HWND hwnd)
{
    struct ACCENT_POLICY { DWORD AccentState; DWORD AccentFlags; DWORD GradientColor; DWORD AnimationId; };
    struct WINCOMPATTRDATA { DWORD Attribute; PVOID pData; ULONG DataSize; };

    auto SetWindowCompositionAttribute = (BOOL(WINAPI*)(HWND, void*))
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetWindowCompositionAttribute");
    if (!SetWindowCompositionAttribute) return;

    DWORD color = compute_acrylic_color_for_theme();
    ACCENT_POLICY accent = { 3, 2, color, 0 };

    WINCOMPATTRDATA data = { 19, &accent, sizeof(accent) };
    SetWindowCompositionAttribute(hwnd, &data);
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
    aida::ui::apply_immediate(aida::ui::detail::make_aida_dark());
}

static void apply_os_theme_animated()
{
}

static void crash_log_write(const char* msg)
{
    diag::log_tagged("main", msg);
}

static void crash_log_fmt(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    diag::log_tagged("main", buf);
}

static void startup_log_critical(const char* detail)
{
    anti_tamper::webhook::write_log_critical("startup", detail ? detail : "<null>");
}

static void startup_log_critical_fmt(const char* fmt, ...)
{
    char buf[2048] = {};
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    startup_log_critical(buf);
}

static const char* startup_bg_phase_label(int step)
{
    switch (step)
    {
    case 0: return "Bootstrapping";
    case 1: return "Initializing chat engine";
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
        if (prev != 0 && now >= prev && now - prev < 5000)
            return;
        g_last_thread_snapshot_ms.store(now, std::memory_order_release);

        HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, render_tid);
        if (!th) {
            diag::log_tagged_critical_fmt("tracer", "render_thread_snapshot_open_failed tid=%lu age_ms=%llu gle=%lu",
                render_tid, static_cast<unsigned long long>(age_ms), GetLastError());
            return;
        }

        DWORD suspend_count = SuspendThread(th);
        if (suspend_count == static_cast<DWORD>(-1)) {
            DWORD gle = GetLastError();
            CloseHandle(th);
            diag::log_tagged_critical_fmt("tracer", "render_thread_snapshot_suspend_failed tid=%lu age_ms=%llu gle=%lu",
                render_tid, static_cast<unsigned long long>(age_ms), gle);
            return;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        BOOL got_ctx = GetThreadContext(th, &ctx);
#if defined(_M_X64)
        uint64_t rip = got_ctx ? static_cast<uint64_t>(ctx.Rip) : 0;
        uint64_t rsp = got_ctx ? static_cast<uint64_t>(ctx.Rsp) : 0;
        uint64_t rbp = got_ctx ? static_cast<uint64_t>(ctx.Rbp) : 0;
        uint64_t rax = got_ctx ? static_cast<uint64_t>(ctx.Rax) : 0;
        uint64_t rcx = got_ctx ? static_cast<uint64_t>(ctx.Rcx) : 0;
        uint64_t rdx = got_ctx ? static_cast<uint64_t>(ctx.Rdx) : 0;
        uint64_t r8 = got_ctx ? static_cast<uint64_t>(ctx.R8) : 0;
        uint64_t r9 = got_ctx ? static_cast<uint64_t>(ctx.R9) : 0;
#else
        uint64_t rip = got_ctx ? static_cast<uint64_t>(ctx.Eip) : 0;
        uint64_t rsp = got_ctx ? static_cast<uint64_t>(ctx.Esp) : 0;
        uint64_t rbp = got_ctx ? static_cast<uint64_t>(ctx.Ebp) : 0;
        uint64_t rax = got_ctx ? static_cast<uint64_t>(ctx.Eax) : 0;
        uint64_t rcx = got_ctx ? static_cast<uint64_t>(ctx.Ecx) : 0;
        uint64_t rdx = got_ctx ? static_cast<uint64_t>(ctx.Edx) : 0;
        uint64_t r8 = 0;
        uint64_t r9 = 0;
#endif
        char rip_desc[1024] = {};
        describe_address(rip, rip_desc, sizeof(rip_desc));

        uint64_t stack_values[64] = {};
        SIZE_T copied = 0;
        if (rsp != 0)
            ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(rsp), stack_values, sizeof(stack_values), &copied);

        ResumeThread(th);
        CloseHandle(th);

        diag::log_tagged_critical_fmt("tracer",
            "render_thread_snapshot tid=%lu age_ms=%llu suspend_count=%lu ctx=%d rip=0x%016llX rsp=0x%016llX rbp=0x%016llX rax=0x%016llX rcx=0x%016llX rdx=0x%016llX r8=0x%016llX r9=0x%016llX peek_calls=%llu peek_returns=%llu dispatch_enter=%llu dispatch_exit=%llu wnd_enter=%llu wnd_exit=%llu %s",
            render_tid,
            static_cast<unsigned long long>(age_ms),
            static_cast<unsigned long>(suspend_count),
            got_ctx ? 1 : 0,
            static_cast<unsigned long long>(rip),
            static_cast<unsigned long long>(rsp),
            static_cast<unsigned long long>(rbp),
            static_cast<unsigned long long>(rax),
            static_cast<unsigned long long>(rcx),
            static_cast<unsigned long long>(rdx),
            static_cast<unsigned long long>(r8),
            static_cast<unsigned long long>(r9),
            static_cast<unsigned long long>(g_peek_call_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_peek_return_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_exit_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_exit_count.load(std::memory_order_acquire)),
            rip_desc);
        diag::log_tagged_critical_fmt("tracer",
            "render_thread_stack copied=%llu q0=0x%016llX q1=0x%016llX q2=0x%016llX q3=0x%016llX q4=0x%016llX q5=0x%016llX q6=0x%016llX q7=0x%016llX q8=0x%016llX q9=0x%016llX q10=0x%016llX q11=0x%016llX",
            static_cast<unsigned long long>(copied),
            static_cast<unsigned long long>(stack_values[0]),
            static_cast<unsigned long long>(stack_values[1]),
            static_cast<unsigned long long>(stack_values[2]),
            static_cast<unsigned long long>(stack_values[3]),
            static_cast<unsigned long long>(stack_values[4]),
            static_cast<unsigned long long>(stack_values[5]),
            static_cast<unsigned long long>(stack_values[6]),
            static_cast<unsigned long long>(stack_values[7]),
            static_cast<unsigned long long>(stack_values[8]),
            static_cast<unsigned long long>(stack_values[9]),
            static_cast<unsigned long long>(stack_values[10]),
            static_cast<unsigned long long>(stack_values[11]));
        for (size_t i = 0; i < 64; ++i) {
            if (stack_values[i] == 0)
                continue;
            char slot_desc[1024] = {};
            describe_address(stack_values[i], slot_desc, sizeof(slot_desc));
            diag::log_tagged_critical_fmt("tracer",
                "render_thread_stack_slot idx=%llu value=0x%016llX %s",
                static_cast<unsigned long long>(i),
                static_cast<unsigned long long>(stack_values[i]),
                slot_desc);
        }
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
        UINT_PTR first_callback = 0;
        UINT_PTR first_callback_data = 0;
        UINT_PTR first_texture = 0;
        uint64_t texture_hash = 14695981039346656037ULL;
        uint64_t max_elem_count = 0;
        uint32_t bad_flags = 0;
        int bad_list = -1;
        int bad_cmd = -1;

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
                        } else {
                            ++user_callbacks;
                            if (first_callback == 0) {
                                first_callback = reinterpret_cast<UINT_PTR>(cmd.UserCallback);
                                first_callback_data = reinterpret_cast<UINT_PTR>(cmd.UserCallbackData);
                            }
                        }
                    }
                }
            }
        }

        g_dx11_draw_cmd_count.store(draw_cmds, std::memory_order_release);
        g_dx11_user_callback_count.store(user_callbacks, std::memory_order_release);
        g_dx11_reset_callback_count.store(reset_callbacks, std::memory_order_release);
        g_dx11_first_callback.store(first_callback, std::memory_order_release);
        g_dx11_first_callback_data.store(first_callback_data, std::memory_order_release);
        g_dx11_first_texture.store(first_texture, std::memory_order_release);
        g_dx11_texture_hash.store(texture_hash, std::memory_order_release);
        g_dx11_max_elem_count.store(max_elem_count, std::memory_order_release);
        g_dx11_bad_flags.store(bad_flags, std::memory_order_release);
        g_dx11_bad_list.store(bad_list, std::memory_order_release);
        g_dx11_bad_cmd.store(bad_cmd, std::memory_order_release);

        if (bad_flags != 0 || user_callbacks != 0) {
            diag::log_tagged_critical_fmt("render",
                "dx11_drawdata_inspect frame=%llu bad=0x%08lX bad_list=%d bad_cmd=%d lists=%d total_vtx=%d total_idx=%d draw_cmds=%llu callbacks=%llu reset_callbacks=%llu first_cb=0x%llX cb_data=0x%llX first_tex=0x%llX tex_hash=0x%016llX max_elem=%llu full_test=%d",
                static_cast<unsigned long long>(frame),
                static_cast<unsigned long>(bad_flags),
                bad_list,
                bad_cmd,
                dd ? dd->CmdListsCount : -1,
                dd ? dd->TotalVtxCount : -1,
                dd ? dd->TotalIdxCount : -1,
                static_cast<unsigned long long>(draw_cmds),
                static_cast<unsigned long long>(user_callbacks),
                static_cast<unsigned long long>(reset_callbacks),
                static_cast<unsigned long long>(first_callback),
                static_cast<unsigned long long>(first_callback_data),
                static_cast<unsigned long long>(first_texture),
                static_cast<unsigned long long>(texture_hash),
                static_cast<unsigned long long>(max_elem_count),
                test_all_features::is_running() ? 1 : 0);
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
        const uint64_t kStallThresholdMs = 2000;
        while (!g_stop.load(std::memory_order_acquire)) {
            ::Sleep(250);

            uint64_t now = static_cast<uint64_t>(GetTickCount64());
            uint64_t frame = g_render_frame.load(std::memory_order_acquire);
            uint64_t last_tick = g_render_last_tick_ms.load(std::memory_order_acquire);
            uint64_t phase_id = g_render_phase_id.load(std::memory_order_acquire);
            const char* phase_name = g_render_phase_name.load(std::memory_order_acquire);
            const char* render_section = g_render_section;
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
                if (stall_streak == 1 || (stall_streak % 20ULL) == 0ULL) {
                    diag::log_tagged_critical_fmt("tracer",
                        "RENDER_STALL streak=%llu frame=%llu age_ms=%llu phase=%s section=%s phase_id=%llu render_tid=%lu attach=%s attach_id=%llu peek_qs=0x%08lX peek_gle=%lu dispatch=%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX wndproc=%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX dx_frame=%llu dx_age_ms=%llu dx_dd=0x%llX dx_dev=0x%llX dx_ctx=0x%llX dx_rtv=0x%llX dx_lists=%llu dx_draw_cmds=%llu dx_vtx=%llu dx_idx=%llu dx_callbacks=%llu dx_reset_callbacks=%llu dx_first_cb=0x%llX dx_cb_data=0x%llX dx_first_tex=0x%llX dx_tex_hash=0x%016llX dx_max_elem=%llu dx_bad=0x%08lX dx_bad_at=%d,%d dx_disp1000=%d,%d dx_fb1000=%d,%d dx_removed=0x%08lX present_frame=%llu present_age_ms=%llu present_sc=0x%llX present_hr=0x%08lX tracer_tid=%lu",
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
                        GetCurrentThreadId());
                    capture_render_thread_snapshot(render_tid, age_ms);
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
        bool posted = work_queue::post([]() {
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
        bool posted = work_queue::post([hwnd]() {
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
            g_render_section ? g_render_section : "<null>",
            e.what());
        return 0xE06D7363u;
    } catch (...) {
        ImGui::ErrorRecoveryTryToRecoverState(imgui_state_backup);
        diag::log_tagged_critical_fmt("render",
            "CPP_in_render_title frame=%llu section=%s what=<unknown>",
            (unsigned long long)frame_number,
            g_render_section ? g_render_section : "<null>");
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
    __try {
        aida_tracer::set_present_state("present_call", frame_number, sc, hr_out ? *hr_out : E_POINTER);
        *hr_out = sc->Present(1, 0);
        aida_tracer::set_present_state("present_returned", frame_number, sc, *hr_out);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        aida_tracer::set_present_state("present_seh", frame_number, sc, hr_out ? *hr_out : E_POINTER);
        return GetExceptionCode();
    }
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
    __try {
        script_engine::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        startup_log_critical_fmt("seh_script_engine_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_script_engine_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

static std::atomic<bool> g_authorized_features_initialized{false};
static std::atomic<bool> g_authorized_features_posted{false};

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
    ok = run("script_engine_init", seh_script_engine_initialize) && ok;
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

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "FIRST_CHANCE_FATAL_EXCEPTION: code=0x%08X addr=0x%016llX addr_off_exe=0x%llX rip=0x%016llX rip_off_exe=0x%llX rsp=0x%016llX rbp=0x%016llX tid=%lu flags=0x%08X params=%lu p0=0x%016llX p1=0x%016llX last_error=%lu",
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
        GetLastError());
    diag::write_crash_log(buf, false);
    diag::log_tagged_critical("veh_crash", buf);
}

static LONG CALLBACK aida_diagnostic_veh(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
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

int main(int, char**)
{
    AddVectoredExceptionHandler(1, aida_diagnostic_veh);
    diag::log_tagged_critical("main", "diagnostic_veh_installed");
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
        standalone_anti_dump::handle_strip::clear_critical_flags();

        char buf[4096];
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
            "Stack: %s\n"
            "TestAllSnapshot=%s\n"
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
            stack_buf,
            test_all_snapshot,
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

    startup_log_critical_fmt("z3_extract_load_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    crash_log_write("extracting_z3");
    embedded_resources::extract_and_load_z3();
    startup_log_critical_fmt("z3_extract_load_post module=0x%llX last_err=%lu",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(embedded_resources::g_z3_module)),
        static_cast<unsigned long>(GetLastError()));
    crash_log_fmt("z3_loaded module=%p", embedded_resources::g_z3_module);
    std::atexit(embedded_resources::cleanup_z3);

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
    HWND hwnd = ::CreateWindowExW(WS_EX_LAYERED | WS_EX_APPWINDOW, wc.lpszClassName, kAidaWindowTitle, WS_POPUP, (screen_w - 200) / 2, (screen_h - 250) / 2, 200, 250, nullptr, nullptr, wc.hInstance, nullptr);
    g_hwnd = hwnd;
    startup_log_critical_fmt("create_window_post hwnd=0x%llX last_err=%lu",
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
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    const MARGINS margin = { -1 };
    DwmExtendFrameIntoClientArea(hwnd, &margin);
    DWM_WINDOW_CORNER_PREFERENCE corner = DWMWCP_ROUND;
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));

    COLORREF border_color = RGB(33, 35, 39);
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border_color, sizeof(border_color));
    SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA);

    set_acrylic_color(hwnd);
    ::UpdateWindow(hwnd);
    startup_log_critical_fmt("show_window_post hwnd=0x%llX last_err=%lu",
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
    startup_log_critical_fmt("imgui_context_create_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    ImGui::CreateContext();
    startup_log_critical_fmt("imgui_context_create_post ctx=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ImGui::GetCurrentContext())));
    crash_log_write("imgui_context_created");
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
    io.ConfigNavCaptureKeyboard = false;


    {
        UINT dpi = GetDpiForWindow(hwnd);
        globals::ui::dpi_scale = (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
    }

    apply_initial_theme();

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
    globals::ui::bg_init_total.store(7, std::memory_order_release);
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
    bool bg_posted = critical_work_queue::post([]() {
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

            run_step("script_engine_init_start", "script_engine_init", "script_engine_init_ok", 5,
                []() { return seh_script_engine_initialize(); });
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
        startup_store_bg_step(7, "bg_init_worker", "bg_init_all_steps_done");

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
    bool driver_posted = critical_work_queue::post([] {
        const uint64_t driver_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("driver_bridge_init_thread_entry pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(driver_tick));
        diag::log_tagged("drv_init", "thread_entry");
        DWORD seh_dbi = seh_driver_bridge_initialize();
        if (seh_dbi != 0)
            diag::log_tagged_fmt("drv_init", "driver_bridge_initialize_seh code=0x%08X last_err=%lu", seh_dbi, GetLastError());
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
    startup_log_critical_fmt("render_loop_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));


    bool done = false;
    static int prev_state = -1;
    static uint64_t frame_number = 0;
    while (!done)
    {
        aida_tracer::render_pulse(frame_number);
        aida_tracer::mark_render_phase("frame_top");
        if (frame_number < 5)
            crash_log_fmt("frame_begin #%llu", frame_number);
        else if ((frame_number % 600ULL) == 0ULL)
            diag::log_tagged_critical_fmt("render", "alive frame=%llu", (unsigned long long)frame_number);

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
        for (;;)
        {
            aida_tracer::mark_render_phase("peek_message_call");
            DWORD queue_status_before = ::GetQueueStatus(QS_ALLINPUT);
            ::SetLastError(0);
            aida_tracer::set_peek_state(queue_status_before, 0);
            uint64_t peek_start = static_cast<uint64_t>(GetTickCount64());
            aida_tracer::g_peek_call_count.fetch_add(1, std::memory_order_acq_rel);
            BOOL has_message = ::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE);
            aida_tracer::g_peek_return_count.fetch_add(1, std::memory_order_acq_rel);
            DWORD peek_gle = ::GetLastError();
            uint64_t peek_elapsed = static_cast<uint64_t>(GetTickCount64()) - peek_start;
            aida_tracer::set_peek_state(queue_status_before, peek_gle);
            if (peek_elapsed >= 50) {
                diag::log_tagged_critical_fmt("msgpump",
                    "peek_slow frame=%llu elapsed_ms=%llu has_message=%d qs=0x%08lX gle=%lu msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX",
                    (unsigned long long)frame_number,
                    (unsigned long long)peek_elapsed,
                    has_message ? 1 : 0,
                    static_cast<unsigned long>(queue_status_before),
                    static_cast<unsigned long>(peek_gle),
                    has_message ? aida_tracer::message_name(msg.message) : "<none>",
                    has_message ? msg.message : 0,
                    has_message ? (unsigned long long)reinterpret_cast<UINT_PTR>(msg.hwnd) : 0ull,
                    has_message ? (unsigned long long)static_cast<UINT_PTR>(msg.wParam) : 0ull,
                    has_message ? (unsigned long long)static_cast<LONG_PTR>(msg.lParam) : 0ull);
            }
            if (!has_message)
                break;

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
                diag::log_tagged_critical_fmt("msgpump",
                    "dispatch_slow frame=%llu elapsed_ms=%llu result=0x%llX msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX",
                    (unsigned long long)frame_number,
                    (unsigned long long)dispatch_elapsed,
                    (unsigned long long)dispatch_result,
                    aida_tracer::message_name(msg.message),
                    msg.message,
                    (unsigned long long)reinterpret_cast<UINT_PTR>(msg.hwnd),
                    (unsigned long long)static_cast<UINT_PTR>(msg.wParam),
                    (unsigned long long)static_cast<LONG_PTR>(msg.lParam));
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

        if (!aida_focus_monitor::focused())
        {
            ::Sleep(1);
        }

        static bool ide_resize_applied = false;
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            diag::log_tagged_critical_fmt("render", "resize_pre w=%d h=%d frame=%llu",
                g_ResizeWidth, g_ResizeHeight, (unsigned long long)frame_number);
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);

            if (ide_resize_applied) {
                globals::ui::window_w = (float)g_ResizeWidth;
                globals::ui::window_h = (float)g_ResizeHeight;
            }
            if (globals::ui::maximized) {
                SetWindowRgn(hwnd, nullptr, TRUE);
            } else {
                HRGN rgn = CreateRoundRectRgn(0, 0, g_ResizeWidth, g_ResizeHeight, 16, 16);
                SetWindowRgn(hwnd, rgn, TRUE);
            }
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
            diag::log_tagged_critical("render", "resize_post_create_target_done");
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
                bool posted = critical_work_queue::post([] {
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
            if (cur_state == 3 && iw >= 1000 && ih >= 600)
                ide_resize_applied = true;

            if (globals::ui::maximized) {
                SetWindowRgn(hwnd, nullptr, TRUE);
                DWM_WINDOW_CORNER_PREFERENCE cp = DWMWCP_DONOTROUND;
                DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
            } else {
                HRGN rgn = CreateRoundRectRgn(0, 0, iw, ih, 16, 16);
                SetWindowRgn(hwnd, rgn, TRUE);
                DWM_WINDOW_CORNER_PREFERENCE cp = DWMWCP_ROUND;
                DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cp, sizeof(cp));
            }
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, iw, ih, DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
            prev_w = iw;
            prev_h = ih;
            diag::log_tagged_critical("render", "second_resize_post");
        }

        if (frame_number < 5)
            crash_log_write("dx11_new_frame");
        if ((frame_number >= 270ULL && frame_number <= 320ULL))
            diag::log_tagged_critical_fmt("render", "phase=pre_dx11_new_frame frame=%llu", (unsigned long long)frame_number);
        aida_tracer::mark_render_phase("dx11_new_frame");
        DWORD seh_dxnf = seh_dx11_new_frame();
        if (seh_dxnf != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_dx11_new_frame code=0x%08X frame=%llu",
                seh_dxnf, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_write("win32_new_frame");
        if ((frame_number >= 270ULL && frame_number <= 320ULL))
            diag::log_tagged_critical_fmt("render", "phase=pre_win32_new_frame frame=%llu", (unsigned long long)frame_number);
        aida_tracer::mark_render_phase("win32_new_frame");
        DWORD seh_w32 = seh_win32_new_frame();
        if (seh_w32 != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_win32_new_frame code=0x%08X frame=%llu",
                seh_w32, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_write("imgui_new_frame");
        if ((frame_number >= 270ULL && frame_number <= 320ULL))
            diag::log_tagged_critical_fmt("render", "phase=pre_imgui_new_frame frame=%llu", (unsigned long long)frame_number);
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
        aida::ui::blur::clear_pending();
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
            if ((frame_number >= 270ULL && frame_number <= 320ULL))
                diag::log_tagged_critical_fmt("render", "phase=pre_render_title frame=%llu section=%s",
                    (unsigned long long)frame_number, g_render_section ? g_render_section : "?");

            aida_tracer::mark_render_phase("render_title");
            DWORD seh_rt = seh_render_title(&helper, frame_number);
            if (seh_rt != 0)
                diag::log_tagged_critical_fmt("render", "SEH_in_render_title code=0x%08X frame=%llu section=%s",
                    seh_rt, (unsigned long long)frame_number, g_render_section ? g_render_section : "?");

            if (frame_number < 5)
                crash_log_write("render_title_done");
            if ((frame_number >= 270ULL && frame_number <= 320ULL))
                diag::log_tagged_critical_fmt("render", "phase=post_render_title frame=%llu section=%s",
                    (unsigned long long)frame_number, g_render_section ? g_render_section : "?");

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
            if ((frame_number >= 270ULL && frame_number <= 320ULL))
                diag::log_tagged_critical_fmt("render", "phase=post_toast frame=%llu", (unsigned long long)frame_number);
        }

        const float clear_color_with_alpha[4] = { 0.0f, 0.0f, 0.0f, 0.0f };

        if (frame_number < 5)
            crash_log_write("render_submit");
        if ((frame_number >= 270ULL && frame_number <= 320ULL))
            diag::log_tagged_critical_fmt("render", "phase=pre_omset frame=%llu", (unsigned long long)frame_number);
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        if ((frame_number >= 270ULL && frame_number <= 320ULL))
            diag::log_tagged_critical_fmt("render", "phase=pre_imgui_render frame=%llu", (unsigned long long)frame_number);
        aida_tracer::mark_render_phase("imgui_render");
        DWORD seh_ir = seh_imgui_render();
        if (seh_ir != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_imgui_render code=0x%08X frame=%llu",
                seh_ir, (unsigned long long)frame_number);
        if ((frame_number >= 270ULL && frame_number <= 320ULL))
            diag::log_tagged_critical_fmt("render", "phase=pre_imgui_dx11 frame=%llu", (unsigned long long)frame_number);
        aida_tracer::mark_render_phase("imgui_dx11_render");
        DWORD seh_idr = seh_imgui_dx11_render(ImGui::GetDrawData(), frame_number);
        if (seh_idr != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_imgui_dx11_render code=0x%08X frame=%llu",
                seh_idr, (unsigned long long)frame_number);
        g_pd3dDeviceContext->OMSetBlendState(blend_state, nullptr, 0xffffffff);

        if ((frame_number >= 270ULL && frame_number <= 320ULL))
            diag::log_tagged_critical_fmt("render", "phase=pre_present frame=%llu", (unsigned long long)frame_number);
        aida_tracer::mark_render_phase("present");
        HRESULT hr = S_OK;
        DWORD seh_present = seh_swapchain_present(g_pSwapChain, &hr, frame_number);
        if (seh_present != 0)
            diag::log_tagged_critical_fmt("render", "SEH_in_present code=0x%08X frame=%llu",
                seh_present, (unsigned long long)frame_number);
        if (frame_number < 5)
            crash_log_fmt("present_hr=0x%08X", hr);
        else if ((hr & 0x80000000u) || hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET)
            diag::log_tagged_critical_fmt("render", "present_hr_NONZERO=0x%08X frame=%llu",
                hr, (unsigned long long)frame_number);
        if ((frame_number >= 270ULL && frame_number <= 320ULL))
            diag::log_tagged_critical_fmt("render", "phase=frame_end frame=%llu hr=0x%08X",
                (unsigned long long)frame_number, hr);

        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);

        if (frame_number < 5)
            crash_log_fmt("frame_end #%llu", frame_number);
        frame_number++;

        {
            static uint64_t s_last_interaction_ms = 0;
            static ImVec2   s_last_mouse_pos = ImVec2(-1.f, -1.f);
            const uint64_t now_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            ImGuiIO& io = ImGui::GetIO();
            bool interacted = false;
            if (io.MouseDelta.x != 0.f || io.MouseDelta.y != 0.f) interacted = true;
            if (s_last_mouse_pos.x != io.MousePos.x || s_last_mouse_pos.y != io.MousePos.y) {
                s_last_mouse_pos = io.MousePos;
                interacted = true;
            }
            if (io.MouseWheel != 0.f || io.MouseWheelH != 0.f) interacted = true;
            for (int b = 0; b < IM_ARRAYSIZE(io.MouseDown); ++b) {
                if (io.MouseDown[b]) { interacted = true; break; }
            }
            if (io.WantTextInput || io.WantCaptureKeyboard) interacted = true;
            if (ImGui::IsAnyItemActive() || ImGui::IsAnyItemFocused()) interacted = true;
            if (ImGui::IsMouseDragging(ImGuiMouseButton_Left, 1.0f)
                || ImGui::IsMouseDragging(ImGuiMouseButton_Right, 1.0f)
                || ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 1.0f))
                interacted = true;
            if (io.KeyCtrl || io.KeyShift || io.KeyAlt || io.KeySuper) interacted = true;
            if (g_ResizeWidth != 0 || g_ResizeHeight != 0) interacted = true;
            if (interacted) s_last_interaction_ms = now_ms;

            const bool bulk_busy = function_index::static_bulk_in_progress();
            const uint64_t since_interaction_ms = (now_ms > s_last_interaction_ms)
                ? (now_ms - s_last_interaction_ms) : 0ull;
            const bool foreground = aida_focus_monitor::focused();

            bool may_sleep = true;
            if (bulk_busy) may_sleep = false;
            if (since_interaction_ms < 500ull) may_sleep = false;
            if (io.WantTextInput || io.WantCaptureKeyboard) may_sleep = false;
            if (ImGui::IsAnyItemActive()) may_sleep = false;
            if (!foreground) may_sleep = true;

            if (may_sleep) {
                ::Sleep(foreground ? 1u : 33u);
            }
        }
    }


    diag::log_tagged_critical_fmt("main",
        "shutdown_sequence_begin frame=%llu done=%d hwnd=0x%llX tid=%lu",
        (unsigned long long)frame_number,
        done ? 1 : 0,
        (unsigned long long)reinterpret_cast<UINT_PTR>(hwnd),
        GetCurrentThreadId());
    aida_tracer::mark_render_phase("shutdown_sequence_begin");
    test_all_features::cancel_tests();
    diag::log_tagged_critical("main", "shutdown_testlab_cancel_done");
    aida_focus_monitor::stop();
    diag::log_tagged_critical("main", "shutdown_focus_monitor_done");
    anti_tamper::shutdown();
    diag::log_tagged_critical("main", "shutdown_anti_tamper_done");
    globals::terminal_mgr.shutdown();
    diag::log_tagged_critical("main", "shutdown_terminal_done");

    network_view::shutdown();
    diag::log_tagged_critical("main", "shutdown_network_done");
    script_engine::shutdown();
    diag::log_tagged_critical("main", "shutdown_script_engine_done");
    workflow_tools::shutdown_services();
    diag::log_tagged_critical("main", "shutdown_workflow_tools_done");
    shutdown_standalone_chat();
    diag::log_tagged_critical("main", "shutdown_chat_done");
    aida::auth::http::cleanup();
    diag::log_tagged_critical("main", "shutdown_auth_http_done");
    Blur::Shutdown();
    diag::log_tagged_critical("main", "shutdown_blur_done");
    ImGui_ImplDX11_Shutdown();
    diag::log_tagged_critical("main", "shutdown_imgui_dx11_done");

    ImGui_ImplWin32_Shutdown();
    diag::log_tagged_critical("main", "shutdown_imgui_win32_done");
    ImGui::DestroyContext();
    diag::log_tagged_critical("main", "shutdown_imgui_context_done");

    CleanupDeviceD3D();
    diag::log_tagged_critical("main", "shutdown_d3d_done");
    ::DestroyWindow(hwnd);
    diag::log_tagged_critical("main", "shutdown_destroy_window_done");
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    diag::log_tagged_critical("main", "shutdown_unregister_done");

    diag::log_tagged_critical("main", "shutdown_exit_process_pre");
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
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (!pBackBuffer) return;
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);

    D3D11_TEXTURE2D_DESC d{};
    pBackBuffer->GetDesc(&d);
    int bw = (int)(d.Width  / 4u);
    int bh = (int)(d.Height / 4u);
    if (bw < 64) bw = 64;
    if (bh < 64) bh = 64;
    Blur::Resize(bw, bh);
    aida::ui::blur::mark_supported(true);

    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    aida_tracer::set_wndproc_state("enter", hWnd, msg, wParam, lParam);
    uint64_t wnd_start = static_cast<uint64_t>(GetTickCount64());
    auto finish = [&](const char* path, LRESULT result) -> LRESULT {
        uint64_t elapsed = static_cast<uint64_t>(GetTickCount64()) - wnd_start;
        if (elapsed >= 50 || msg == WM_CLOSE || msg == WM_DESTROY || msg == WM_NCDESTROY ||
            msg == WM_SYSCOMMAND || msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP ||
            msg == WM_NCLBUTTONDOWN || msg == WM_NCLBUTTONUP || msg == WM_MOUSEACTIVATE ||
            msg == WM_DPICHANGED || msg == WM_SETTINGCHANGE) {
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

    aida_tracer::set_wndproc_state("imgui_enter", hWnd, msg, wParam, lParam);
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
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
            !globals::ui::maximized) {
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
        if (wParam == SIZE_MINIMIZED)
            return finish("size_minimized", 0);
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return finish("size", 0);
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
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return finish("syscommand_keymenu", 0);
        break;
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
        RECT* suggested = reinterpret_cast<RECT*>(lParam);
        aida_tracer::set_wndproc_state("dpichanged_setwindowpos", hWnd, msg, wParam, lParam);
        SetWindowPos(hWnd, nullptr,
            suggested->left, suggested->top,
            suggested->right - suggested->left,
            suggested->bottom - suggested->top,
            SWP_NOZORDER | SWP_NOACTIVATE);
        aida_tracer::set_wndproc_state("dpichanged_rebuild_fonts", hWnd, msg, wParam, lParam);
        rebuild_fonts(globals::ui::dpi_scale);
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
    case WM_DESTROY:
        diag::log_tagged_critical_fmt("wndproc",
            "destroy_post_quit hwnd=0x%llX tid=%lu",
            (unsigned long long)reinterpret_cast<UINT_PTR>(hWnd),
            GetCurrentThreadId());
        ::PostQuitMessage(0);
        return finish("destroy", 0);
    }
    aida_tracer::set_wndproc_state("defwindowproc_enter", hWnd, msg, wParam, lParam);
    LRESULT def_result = ::DefWindowProcW(hWnd, msg, wParam, lParam);
    return finish("defwindowproc", def_result);
}
