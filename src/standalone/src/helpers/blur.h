#pragma once
#include <d3d11.h>
#include <cstdint>
#include "imgui/imgui_internal.h"

class Blur {
public:
    struct Stats {
        std::uint64_t draw_requests = 0;
        std::uint64_t callbacks = 0;
        std::uint64_t suppressed_full_test = 0;
        std::uint64_t invalid_callbacks = 0;
        std::uint64_t no_rtv = 0;
        std::uint64_t slow_callbacks = 0;
        std::uint64_t slow_suppressed = 0;
        std::uint64_t cache_reuse = 0;
        std::uint64_t adaptive_fallback = 0;
        std::uint64_t interactive_fallback = 0;
        std::uint64_t throttle_fallback = 0;
        std::uint64_t last_cache_age_ms = 0;
        std::uint64_t pressure_until_ms = 0;
        std::uint64_t input_pressure_until_ms = 0;
        std::uint64_t total_area = 0;
        std::uint64_t last_area = 0;
        std::uint64_t total_elapsed_ms = 0;
        std::uint64_t copy_elapsed_ms = 0;
        std::uint64_t horizontal_elapsed_ms = 0;
        std::uint64_t vertical_elapsed_ms = 0;
        std::uint64_t restore_elapsed_ms = 0;
        std::uint64_t last_elapsed_ms = 0;
        std::uint64_t last_copy_ms = 0;
        std::uint64_t last_horizontal_ms = 0;
        std::uint64_t last_vertical_ms = 0;
        std::uint64_t last_restore_ms = 0;
        long last_device_removed = 0;
    };

    static void Init(ID3D11Device* device, ID3D11DeviceContext* ctx, int w, int h);
    static void Resize(int w, int h);
    static void Draw(ImDrawList* dl, ImVec2 min, ImVec2 max);
    static void Shutdown();
    static void ApplyPass(ID3D11ShaderResourceView* src, ID3D11RenderTargetView* dst, bool horizontal);
    static ImDrawCallback ExpectedCallback();
    static Stats SnapshotStats();
    static void SetInteractionPressure(bool active, std::uint64_t until_ms);
    static bool InteractionPressureActive();

    static ID3D11Device* s_device;
    static ID3D11DeviceContext* s_ctx;
    static ID3D11Texture2D* s_copy;
    static ID3D11Texture2D* s_pingpong[2];
    static ID3D11ShaderResourceView* s_srv[3];
    static ID3D11RenderTargetView* s_rtv[2];
    static ID3D11PixelShader* s_ps[2];
    static ID3D11VertexShader* s_vs;
    static ID3D11SamplerState* s_sampler;
    static ID3D11Buffer* s_cb;
    static int                      s_w, s_h;
};
