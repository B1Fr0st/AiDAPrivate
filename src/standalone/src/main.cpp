#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/freetype/freetype.h"
#include "verdana.h"
#include "ide_icons.h"
#include <d3d11.h>
#include <tchar.h>
#include <windowsx.h>
#include <algorithm>
#include "helpers/helpers.h"
#include "helpers/blur.h"
#include <dwmapi.h>
#include <shellscalingapi.h>
#include "helpers/globals.h"
#include "standalone_chat.hpp"
#include "standalone_license.hpp"
#include "standalone_settings.hpp"
#include "standalone_driver.hpp"
#include "core/runtime/arc_loader.hpp"
#include "core/anti-tamper/orchestrator.hpp"
#include "core/anti-tamper/hv_preflight.hpp"
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
#include "helpers/stb_image.h"

#include "embedded_resources.hpp"
#include "helpers/diag_log.hpp"
#include "hardware_id/hardware_id.hpp"
#include "core/anti-tamper/cff.hpp"
#include "core/anti-tamper/virtualizer.hpp"

extern "C" {
#include <openssl/applink.c>
}

#include <delayimp.h>
#include <thread>
#include <cstdarg>
#include <set>

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
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

inline int prev_w = 0;
inline int prev_h = 0;

static void rebuild_fonts(float dpi_scale)
{
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();

    float font_size = 14.0f * dpi_scale;

    ImFontConfig cfg{};
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting;
    cfg.PixelSnapH = false;
    cfg.RasterizerMultiply = 1.0f;
    io.Fonts->AddFontFromMemoryTTF(
        (void*)verdana, sizeof(verdana), font_size, &cfg);

    {
        static const ImWchar icon_ranges[] = { ICON_MIN_IDE, ICON_MAX_IDE, 0 };
        ImFontConfig icon_cfg{};
        icon_cfg.MergeMode = true;
        icon_cfg.PixelSnapH = true;
        icon_cfg.GlyphMinAdvanceX = font_size;
        icon_cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting;
        void* icon_data_copy = IM_ALLOC(ide_icon_font_size);
        memcpy(icon_data_copy, ide_icon_font_data, ide_icon_font_size);
        io.Fonts->AddFontFromMemoryTTF(icon_data_copy, ide_icon_font_size, font_size, &icon_cfg, icon_ranges);
    }

    {
        char win_dir[MAX_PATH];
        GetWindowsDirectoryA(win_dir, MAX_PATH);
        std::string consolas_path = std::string(win_dir) + "\\Fonts\\consola.ttf";
        ImFontConfig mono_cfg{};
        mono_cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting;
        mono_cfg.PixelSnapH = true;
        mono_cfg.RasterizerMultiply = 1.0f;
        g_code_font = io.Fonts->AddFontFromFileTTF(consolas_path.c_str(), font_size, &mono_cfg);
    }

    io.Fonts->Build();
    ImGui_ImplDX11_InvalidateDeviceObjects();
}

void set_acrylic_color(HWND hwnd)
{
    struct ACCENT_POLICY { DWORD AccentState; DWORD AccentFlags; DWORD GradientColor; DWORD AnimationId; };
    struct WINCOMPATTRDATA { DWORD Attribute; PVOID pData; ULONG DataSize; };

    auto SetWindowCompositionAttribute = (BOOL(WINAPI*)(HWND, void*))
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetWindowCompositionAttribute");
    if (!SetWindowCompositionAttribute) return;


    DWORD color = (DWORD(5) << 0) | (DWORD(12) << 8) | (DWORD(65) << 16) | (DWORD(0xC0) << 24);
    ACCENT_POLICY accent = { 3, 2, color, 0 };

    WINCOMPATTRDATA data = { 19, &accent, sizeof(accent) };
    SetWindowCompositionAttribute(hwnd, &data);
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

__declspec(noinline) static DWORD seh_render_title(helpers* h, uint64_t frame_number)
{
    __try {
        h->render_title();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_source_reconstruct(uint64_t frame_number)
{
    __try {
        source_reconstruct_view::render(1.0f, globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_toast(uint64_t frame_number)
{
    __try {
        toast_notification::render();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_command_palette(uint64_t frame_number)
{
    __try {
        aida::command_palette::render();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_render_agent_picker(uint64_t frame_number)
{
    __try {
        aida::agent_picker::render_if_open();
        if (aida::agent_picker::consume_manager_request()) {
            aida::settings_overlay::open();
            aida::settings_overlay::set_active_tab(aida::settings_overlay::tab_agents);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
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
    __try {
        init_standalone_chat();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_network_view_initialize()
{
    __try {
        network_view::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_memory_scanner_initialize()
{
    __try {
        memory_scanner::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_mitm_proxy_pre_initialize()
{
    __try {
        mitm_proxy::pre_initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_script_engine_initialize()
{
    __try {
        script_engine::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_snapshot_code_hashes()
{
    __try {
        standalone_license::snapshot_code_hashes();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_anti_tamper_initialize(bool& out_result)
{
    out_result = false;
    __try {
        out_result = anti_tamper::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) static DWORD seh_driver_bridge_initialize()
{
    __try {
        driver_bridge::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

int main(int, char**)
{
    crash_log_write("main_enter");

    {
        aida::hardware_id::anchor_set_t anchors = aida::hardware_id::collect_user_mode();
        aida::hardware_id::tpm_attest_t tpm{};
        bool tpm_ok = aida::hardware_id::collect_tpm_attestation(tpm);
        aida::hardware_id::composite_t composite = tpm_ok
            ? aida::hardware_id::hash_anchors_with_tpm(anchors, tpm)
            : aida::hardware_id::hash_anchors(anchors);
        char hwid_log_msg[512];
        _snprintf_s(hwid_log_msg, sizeof(hwid_log_msg), _TRUNCATE,
            "hwid_composition tpm_present=%d ek_pub_sha=%.16s pcr_composite=%.16s composite_hwid=%.16s anchors=%d",
            tpm_ok ? 1 : 0,
            tpm.ek_pub_sha256.c_str(),
            tpm.pcr_composite_sha256.c_str(),
            composite.hardware_id_sha256.c_str(),
            composite.anchor_count);
        crash_log_write(hwid_log_msg);
    }

    run_phase_1_2_self_tests();

    arc_loader::prime_import_cache();
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
            GetLastError());

        crash_log_write(buf);

        char crash_path[MAX_PATH];
        _snprintf_s(crash_path, sizeof(crash_path), _TRUNCATE, "%saida_crash.log", diag::resolve_log_dir());

        HANDLE hf = CreateFileA(crash_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hf, buf, static_cast<DWORD>(strlen(buf)), &written, nullptr);
            CloseHandle(hf);
        }

        anti_tamper::webhook::send_debug_log("crash", buf, true);

        return EXCEPTION_CONTINUE_SEARCH;
    });
    crash_log_write("exception_filter_set");

    {
        auto r = anti_tamper::hv_preflight::run();
        crash_log_write("hv_preflight_done");
        if (r.result != anti_tamper::hv_preflight::result_t::allow)
            anti_tamper::hv_preflight::show_refuse_ui_and_exit(r);
    }

    {
        bool settings_loaded = g_sa_settings.load();
        crash_log_fmt("startup_settings_loaded=%d", settings_loaded ? 1 : 0);
        std::string ban_reason;
        std::string ban_message;
        if (standalone_license::startup_ban_check(g_sa_settings, ban_reason, ban_message)) {
            crash_log_fmt("startup_ban_refuse reason=%.128s", ban_reason.c_str());
            show_ban_refuse_ui_and_exit(ban_reason, ban_message);
        }
        crash_log_write("startup_ban_check_passed");
    }

    crash_log_write("extracting_z3");
    embedded_resources::extract_and_load_z3();
    crash_log_fmt("z3_loaded module=%p", embedded_resources::g_z3_module);
    std::atexit(embedded_resources::cleanup_z3);

    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    crash_log_write("dpi_awareness_set");

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"AiDAStandaloneWindow", nullptr };
    ::RegisterClassExW(&wc);
    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);
    crash_log_fmt("screen=%dx%d", screen_w, screen_h);
    HWND hwnd = ::CreateWindowExW(WS_EX_LAYERED | WS_EX_APPWINDOW, wc.lpszClassName, L"AiDA Standalone", WS_POPUP, (screen_w - 200) / 2, (screen_h - 250) / 2, 200, 250, nullptr, nullptr, wc.hInstance, nullptr);
    g_hwnd = hwnd;
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
    if (!CreateDeviceD3D(hwnd))
    {
        crash_log_write("d3d_creation_FAILED");
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }
    crash_log_fmt("d3d_ok device=%p ctx=%p swapchain=%p", g_pd3dDevice, g_pd3dDeviceContext, g_pSwapChain);

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
    crash_log_write("window_shown_acrylic_set");

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    crash_log_write("imgui_context_created");
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;


    ImGuiStyle& style = ImGui::GetStyle();
    style.ChildBorderSize = 0.0f;
    style.WindowBorderSize = 0.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.059f, 0.059f, 0.078f, 1.f);
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.f, 0.f, 0.f, 0.f);
    style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.35f, 0.33f, 0.48f, 0.30f);
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.45f, 0.42f, 0.60f, 0.50f);
    style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.55f, 0.50f, 0.72f, 0.65f);

    style.WindowRounding = 8.0f;
    style.ChildRounding = 6.0f;
    style.FrameRounding = 6.0f;
    style.PopupRounding = 8.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 4.0f;
    style.ScrollbarSize = 4.f;
    {
        UINT dpi = GetDpiForWindow(hwnd);
        globals::ui::dpi_scale = (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
    }

    float font_size = 14.0f * globals::ui::dpi_scale;
    ImFontConfig cfg{};
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting;
    cfg.PixelSnapH = false;
    cfg.RasterizerMultiply = 1.0f;


    io.Fonts->AddFontFromMemoryTTF(
        (void*)verdana, sizeof(verdana), font_size, &cfg);


    {
        static const ImWchar icon_ranges[] = { ICON_MIN_IDE, ICON_MAX_IDE, 0 };
        ImFontConfig icon_cfg{};
        icon_cfg.MergeMode = true;
        icon_cfg.PixelSnapH = true;
        icon_cfg.GlyphMinAdvanceX = font_size;
        icon_cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting;
        void* icon_data_copy = IM_ALLOC(ide_icon_font_size);
        memcpy(icon_data_copy, ide_icon_font_data, ide_icon_font_size);
        io.Fonts->AddFontFromMemoryTTF(icon_data_copy, ide_icon_font_size, font_size, &icon_cfg, icon_ranges);
    }

    {
        char win_dir[MAX_PATH];
        GetWindowsDirectoryA(win_dir, MAX_PATH);
        std::string consolas_path = std::string(win_dir) + "\\Fonts\\consola.ttf";
        ImFontConfig mono_cfg{};
        mono_cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting;
        mono_cfg.PixelSnapH = true;
        mono_cfg.RasterizerMultiply = 1.0f;
        g_code_font = io.Fonts->AddFontFromFileTTF(consolas_path.c_str(), font_size, &mono_cfg);
    }

    crash_log_write("fonts_built");
    ImGui_ImplWin32_Init(hwnd);
    crash_log_write("imgui_win32_init_ok");
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
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
    g_pd3dDevice->CreateBlendState(&blend_desc, &blend_state);
    g_pd3dDeviceContext->OMSetBlendState(blend_state, nullptr, 0xffffffff);
    crash_log_fmt("blend_state=%p", blend_state);
    Blur::Init(g_pd3dDevice, g_pd3dDeviceContext, 100, 130);
    crash_log_write("blur_init_ok");

    work_queue::initialize();
    crash_log_write("work_queue_init_ok");


    static std::atomic<bool> bg_init_done{false};
    globals::ui::bg_init_done = &bg_init_done;
    std::thread([]() {
        diag::log_tagged("bg_init", "thread_entry");

        diag::log_tagged("bg_init", "init_standalone_chat_start");
        DWORD seh_chat = seh_init_standalone_chat();
        if (seh_chat != 0)
            diag::log_tagged_fmt("bg_init", "init_standalone_chat_seh code=0x%08X last_err=%lu", seh_chat, GetLastError());
        diag::log_tagged("bg_init", "standalone_chat_init_ok");

        diag::log_tagged("bg_init", "network_view_init_start");
        DWORD seh_nv = seh_network_view_initialize();
        if (seh_nv != 0)
            diag::log_tagged_fmt("bg_init", "network_view_init_seh code=0x%08X last_err=%lu", seh_nv, GetLastError());
        diag::log_tagged("bg_init", "network_view_init_ok");

        diag::log_tagged("bg_init", "memory_scanner_init_start");
        DWORD seh_ms = seh_memory_scanner_initialize();
        if (seh_ms != 0)
            diag::log_tagged_fmt("bg_init", "memory_scanner_init_seh code=0x%08X last_err=%lu", seh_ms, GetLastError());
        diag::log_tagged("bg_init", "memory_scanner_init_ok");

        diag::log_tagged("bg_init", "mitm_proxy_pre_init_start");
        DWORD seh_mp = seh_mitm_proxy_pre_initialize();
        if (seh_mp != 0)
            diag::log_tagged_fmt("bg_init", "mitm_proxy_pre_init_seh code=0x%08X last_err=%lu", seh_mp, GetLastError());
        diag::log_tagged("bg_init", "mitm_proxy_pre_init_ok");

        diag::log_tagged("bg_init", "script_engine_init_start");
        DWORD seh_se = seh_script_engine_initialize();
        if (seh_se != 0)
            diag::log_tagged_fmt("bg_init", "script_engine_init_seh code=0x%08X last_err=%lu", seh_se, GetLastError());
        diag::log_tagged("bg_init", "script_engine_init_ok");

        diag::log_tagged("bg_init", "code_hashes_snapshot_start");
        DWORD seh_ch = seh_snapshot_code_hashes();
        if (seh_ch != 0)
            diag::log_tagged_fmt("bg_init", "code_hashes_snapshot_seh code=0x%08X last_err=%lu", seh_ch, GetLastError());
        diag::log_tagged("bg_init", "code_hashes_snapshot_ok");

        diag::log_tagged("bg_init", "anti_tamper_initialize_entering");
        bool at_result = false;
        DWORD seh_at = seh_anti_tamper_initialize(at_result);
        if (seh_at != 0)
            diag::log_tagged_fmt("bg_init", "anti_tamper_initialize_seh code=0x%08X last_err=%lu", seh_at, GetLastError());
        diag::log_tagged_fmt("bg_init", "anti_tamper_initialize_result=%d", at_result ? 1 : 0);

        bg_init_done.store(true, std::memory_order_release);
        diag::log_tagged("bg_init", "thread_exit");
    }).detach();


    driver_bridge::set_log_callback([](const std::string& msg) {
        crash_log_write(msg.c_str());
    });


    std::thread([] {
        diag::log_tagged("drv_init", "thread_entry");
        DWORD seh_dbi = seh_driver_bridge_initialize();
        if (seh_dbi != 0)
            diag::log_tagged_fmt("drv_init", "driver_bridge_initialize_seh code=0x%08X last_err=%lu", seh_dbi, GetLastError());
        diag::log_tagged("drv_init", "thread_exit");
    }).detach();
    crash_log_write("driver_bridge_thread_launched");


    ImVec4 clear_color = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    crash_log_write("entering_render_loop");


    bool done = false;
    static int prev_state = -1;
    static uint64_t frame_number = 0;
    while (!done)
    {
        if (frame_number < 5)
            crash_log_fmt("frame_begin #%llu", frame_number);

        if (themes::changed)
        {
            themes::changed = false;

            auto& t = themes::resolved;
            globals::ui::accent = t.accent;


            struct ACCENT_POLICY_T { DWORD AccentState; DWORD AccentFlags; DWORD GradientColor; DWORD AnimationId; };
            struct WINCOMPATTRDATA_T { DWORD Attribute; PVOID pData; ULONG DataSize; };
            auto SetWCA = (BOOL(WINAPI*)(HWND, void*))
                GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetWindowCompositionAttribute");
            if (SetWCA) {
                ACCENT_POLICY_T ap = { 3, 2, t.acrylic_color, 0 };
                WINCOMPATTRDATA_T wd = { 19, &ap, sizeof(ap) };
                SetWCA(hwnd, &wd);
            }
        }


        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
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
        }

        int iw = (int)globals::ui::window_w;
        int ih = (int)globals::ui::window_h;


        int cur_state = 0;
        if (globals::ui::load_timer >= 3.0f) cur_state = 1;
        if (globals::ui::welcome_done && !license::validated) cur_state = 2;
        if (globals::ui::welcome_done && license::validated) cur_state = 3;
        bool state_changed = (cur_state != prev_state);
        if (state_changed) prev_state = cur_state;

        static bool s_arc_startup_gate_passed = false;
        if (!s_arc_startup_gate_passed && cur_state == 3 && standalone_license::is_arc_loaded())
        {
            uint8_t gate_nonce[32] = {};
            const std::string sess_tok = standalone_license::get_session_token();
            size_t cp = sess_tok.size();
            if (cp > sizeof(gate_nonce)) cp = sizeof(gate_nonce);
            if (cp > 0)
                memcpy(gate_nonce, sess_tok.data(), cp);

            uint8_t poly_seed[32] = {};
            uint32_t poly_seed_len = 0;
            constexpr uint32_t kPolymorphismSeedFeatureId = 1u;
            bool unseal_ok = standalone_license::arc_unseal_feature_blocking(
                kPolymorphismSeedFeatureId,
                gate_nonce, sizeof(gate_nonce),
                poly_seed, &poly_seed_len, sizeof(poly_seed));
            if (!unseal_ok || poly_seed_len != 32) {
                SecureZeroMemory(poly_seed, sizeof(poly_seed));
                SecureZeroMemory(gate_nonce, sizeof(gate_nonce));
                __fastfail(0xA1DAFA17u);
            }
            SecureZeroMemory(poly_seed, sizeof(poly_seed));
            SecureZeroMemory(gate_nonce, sizeof(gate_nonce));
            s_arc_startup_gate_passed = true;
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
        }

        if (frame_number < 5)
            crash_log_write("dx11_new_frame");
        ImGui_ImplDX11_NewFrame();
        if (frame_number < 5)
            crash_log_write("win32_new_frame");
        ImGui_ImplWin32_NewFrame();
        if (frame_number < 5)
            crash_log_write("imgui_new_frame");
        ImGui::NewFrame();

        {
            if (frame_number < 5)
                crash_log_write("render_title_entering");

            DWORD seh_rt = seh_render_title(&helper, frame_number);
            if (seh_rt != 0)
                crash_log_fmt("SEH_in_render_title code=0x%08X frame=%llu section=%s", seh_rt, frame_number, g_render_section);

            if (frame_number < 5)
                crash_log_write("render_title_done");

            DWORD seh_cp = seh_render_command_palette(frame_number);
            if (seh_cp != 0)
                crash_log_fmt("SEH_in_command_palette code=0x%08X frame=%llu", seh_cp, frame_number);

            DWORD seh_ap = seh_render_agent_picker(frame_number);
            if (seh_ap != 0)
                crash_log_fmt("SEH_in_agent_picker code=0x%08X frame=%llu", seh_ap, frame_number);

            DWORD seh_sr = seh_render_source_reconstruct(frame_number);
            if (seh_sr != 0)
                crash_log_fmt("SEH_in_source_reconstruct code=0x%08X frame=%llu", seh_sr, frame_number);

            if (frame_number < 5)
                crash_log_write("source_reconstruct_done");

            DWORD seh_toast = seh_render_toast(frame_number);
            if (seh_toast != 0)
                crash_log_fmt("SEH_in_toast code=0x%08X frame=%llu", seh_toast, frame_number);

            if (frame_number < 5)
                crash_log_write("toast_done");
        }

        const float clear_color_with_alpha[4] = { 0.0f, 0.0f, 0.0f, 0.0f };

        if (frame_number < 5)
            crash_log_write("render_submit");
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pd3dDeviceContext->OMSetBlendState(blend_state, nullptr, 0xffffffff);

        HRESULT hr = g_pSwapChain->Present(1, 0);
        if (frame_number < 5)
            crash_log_fmt("present_hr=0x%08X", hr);

        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);

        if (frame_number < 5)
            crash_log_fmt("frame_end #%llu", frame_number);
        frame_number++;
    }


    anti_tamper::shutdown();
    globals::terminal_mgr.shutdown();

    network_view::shutdown();
    script_engine::shutdown();
    shutdown_standalone_chat();
    Blur::Shutdown();
    ImGui_ImplDX11_Shutdown();

    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

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
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_NCHITTEST:
    {

        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        RECT rc; GetWindowRect(hWnd, &rc);
        const int border = static_cast<int>(6 * globals::ui::dpi_scale);
        bool left   = pt.x < rc.left   + border;
        bool right  = pt.x > rc.right  - border;
        bool top    = pt.y < rc.top    + border;
        bool bottom = pt.y > rc.bottom - border;


        if (globals::ui::welcome_done && license::validated && !globals::ui::maximized) {
            if (top    && left)  return HTTOPLEFT;
            if (top    && right) return HTTOPRIGHT;
            if (bottom && left)  return HTBOTTOMLEFT;
            if (bottom && right) return HTBOTTOMRIGHT;
            if (left)            return HTLEFT;
            if (right)           return HTRIGHT;
            if (top)             return HTTOP;
            if (bottom)          return HTBOTTOM;
        }
        return HTCLIENT;
    }
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
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
        return 0;
    }
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_ACTIVATEAPP:
        if (wParam == TRUE) {
            g_SwapChainOccluded = false;
            if (::IsWindow(hWnd) && !::IsIconic(hWnd)) {
                ::SetWindowPos(hWnd, HWND_TOP, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                ::ShowWindow(hWnd, SW_SHOW);
                set_acrylic_color(hWnd);
                ::InvalidateRect(hWnd, nullptr, TRUE);
            }
        }
        return 0;
    case WM_DPICHANGED:
    {
        UINT dpi = HIWORD(wParam);
        globals::ui::dpi_scale = (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
        RECT* suggested = reinterpret_cast<RECT*>(lParam);
        SetWindowPos(hWnd, nullptr,
            suggested->left, suggested->top,
            suggested->right - suggested->left,
            suggested->bottom - suggested->top,
            SWP_NOZORDER | SWP_NOACTIVATE);
        rebuild_fonts(globals::ui::dpi_scale);
        return 0;
    }
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
