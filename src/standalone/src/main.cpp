#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/freetype/freetype.h"
#include "verdana.h"
#include <d3d11.h>
#include <tchar.h>
#include <windowsx.h>
#include <algorithm>
#include "helpers/helpers.h"
#include "helpers/blur.h"
#include <dwmapi.h>
#include "helpers/globals.h"
#include "core/standalone_chat.hpp"
#include "helpers/stb_image.h"

#pragma comment(lib, "dwmapi.lib")

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

int main(int, char**)
{
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"AiDAStandaloneWindow", nullptr };
    ::RegisterClassExW(&wc);
    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);
    HWND hwnd = ::CreateWindowExW(WS_EX_TOPMOST | WS_EX_LAYERED, wc.lpszClassName, L"AiDA Standalone", WS_POPUP, (screen_w - 200) / 2, (screen_h - 250) / 2, 200, 250, nullptr, nullptr, wc.hInstance, nullptr);
    g_hwnd = hwnd;


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
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

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

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
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
    ImFontConfig cfg{};
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting;
    cfg.PixelSnapH = false;
    cfg.RasterizerMultiply = 1.0f;


    io.Fonts->AddFontFromMemoryTTF(
        (void*)verdana, sizeof(verdana), 14, &cfg);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
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
    Blur::Init(g_pd3dDevice, g_pd3dDeviceContext, 100, 130);
    init_standalone_chat();


    ImVec4 clear_color = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);


    bool done = false;
    static int prev_state = -1;
    while (!done)
    {


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
                HRGN rgn = CreateRectRgn(0, 0, g_ResizeWidth, g_ResizeHeight);
                SetWindowRgn(hwnd, rgn, TRUE);
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
        if (globals::ui::load_timer >= 1.5f) cur_state = 1;
        if (globals::ui::welcome_done && !license::validated) cur_state = 2;
        if (globals::ui::welcome_done && license::validated) cur_state = 3;
        bool state_changed = (cur_state != prev_state);
        if (state_changed) prev_state = cur_state;


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
                } else if (state_changed) {

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
                HRGN rgn = CreateRectRgn(0, 0, iw, ih);
                SetWindowRgn(hwnd, rgn, TRUE);
            } else {
                HRGN rgn = CreateRoundRectRgn(0, 0, iw, ih, 16, 16);
                SetWindowRgn(hwnd, rgn, TRUE);
            }
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, iw, ih, DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
            prev_w = iw;
            prev_h = ih;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        {

            helper.render_title();

        }

        const float clear_color_with_alpha[4] = { 0.0f, 0.0f, 0.0f, 0.0f };

        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pd3dDeviceContext->OMSetBlendState(blend_state, nullptr, 0xffffffff);

        HRESULT hr = g_pSwapChain->Present(1, 0);

        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

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
        const int border = 6;
        bool left   = pt.x < rc.left   + border;
        bool right  = pt.x > rc.right  - border;
        bool top    = pt.y < rc.top    + border;
        bool bottom = pt.y > rc.bottom - border;


        if (globals::ui::welcome_done && license::validated) {
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
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
