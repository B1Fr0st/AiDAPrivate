#include "blur.h"
#include "blur_shaders.hpp"
#include "diag_log.hpp"
#include "../core/ui/theme.hpp"
#include "../core/testlab/test_all_features.hpp"
#include <atomic>

ID3D11Device* Blur::s_device = nullptr;
ID3D11DeviceContext* Blur::s_ctx = nullptr;
ID3D11Texture2D* Blur::s_copy = nullptr;
ID3D11Texture2D* Blur::s_pingpong[2] = {};
ID3D11ShaderResourceView* Blur::s_srv[3] = {};
ID3D11RenderTargetView* Blur::s_rtv[2] = {};
ID3D11PixelShader* Blur::s_ps[2] = {};
ID3D11VertexShader* Blur::s_vs = nullptr;
ID3D11SamplerState* Blur::s_sampler = nullptr;
ID3D11Buffer* Blur::s_cb = nullptr;
int                       Blur::s_w = 0;
int                       Blur::s_h = 0;

namespace {
std::atomic<std::uint64_t> g_blur_draw_requests{0};
std::atomic<std::uint64_t> g_blur_callbacks{0};
std::atomic<std::uint64_t> g_blur_suppressed_full_test{0};
std::atomic<std::uint64_t> g_blur_invalid_callbacks{0};
std::atomic<std::uint64_t> g_blur_no_rtv{0};
std::atomic<std::uint64_t> g_blur_slow_callbacks{0};
std::atomic<std::uint64_t> g_blur_slow_suppressed{0};
std::atomic<std::uint64_t> g_blur_cache_reuse{0};
std::atomic<std::uint64_t> g_blur_adaptive_fallback{0};
std::atomic<std::uint64_t> g_blur_cache_rect_key{0};
std::atomic<std::uint64_t> g_blur_cache_last_ms{0};
std::atomic<std::uint64_t> g_blur_last_cache_age_ms{0};
std::atomic<std::uint64_t> g_blur_pressure_until_ms{0};
std::atomic<std::uint64_t> g_blur_total_area{0};
std::atomic<std::uint64_t> g_blur_last_area{0};
std::atomic<std::uint64_t> g_blur_total_elapsed_ms{0};
std::atomic<std::uint64_t> g_blur_copy_elapsed_ms{0};
std::atomic<std::uint64_t> g_blur_horizontal_elapsed_ms{0};
std::atomic<std::uint64_t> g_blur_vertical_elapsed_ms{0};
std::atomic<std::uint64_t> g_blur_restore_elapsed_ms{0};
std::atomic<std::uint64_t> g_blur_last_elapsed_ms{0};
std::atomic<std::uint64_t> g_blur_last_copy_ms{0};
std::atomic<std::uint64_t> g_blur_last_horizontal_ms{0};
std::atomic<std::uint64_t> g_blur_last_vertical_ms{0};
std::atomic<std::uint64_t> g_blur_last_restore_ms{0};
std::atomic<long> g_blur_last_device_removed{0};

std::uint64_t blur_rect_area(const ImVec2& min, const ImVec2& max)
{
    const float w = max.x > min.x ? max.x - min.x : 0.0f;
    const float h = max.y > min.y ? max.y - min.y : 0.0f;
    if (!(w > 0.0f && w < 100000.0f) || !(h > 0.0f && h < 100000.0f))
        return 0;
    return static_cast<std::uint64_t>(w) * static_cast<std::uint64_t>(h);
}

std::uint64_t blur_rect_key(const ImVec2& min, const ImVec2& max, int w, int h)
{
    std::uint64_t key = 14695981039346656037ULL;
    const int coords[6] = {
        static_cast<int>(min.x),
        static_cast<int>(min.y),
        static_cast<int>(max.x),
        static_cast<int>(max.y),
        w,
        h
    };
    for (int v : coords) {
        key ^= static_cast<std::uint64_t>(static_cast<std::uint32_t>(v));
        key *= 1099511628211ULL;
    }
    return key;
}

void blur_draw_fallback(ImDrawList* dl, ImVec2 min, ImVec2 max, float fill_alpha)
{
    const auto& th = aida::ui::resolved();
    dl->AddRectFilled(min, max, aida::ui::with_alpha(th.glass_tint, fill_alpha), 8.0f);
    dl->AddRect(min, max, th.border_subtle, 8.0f);
}
}

void Blur::Init(ID3D11Device* device, ID3D11DeviceContext* ctx, int w, int h)
{
    if (!device || !ctx || w <= 0 || h <= 0) return;
    s_device = device; s_ctx = ctx; s_w = w; s_h = h;

    D3D11_TEXTURE2D_DESC td = {};
    td.Width = w; td.Height = h; td.MipLevels = 1; td.ArraySize = 1;
    td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    device->CreateTexture2D(&td, nullptr, &s_copy);
    device->CreateShaderResourceView(s_copy, nullptr, &s_srv[0]);

    td.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
    device->CreateTexture2D(&td, nullptr, &s_pingpong[0]);
    device->CreateTexture2D(&td, nullptr, &s_pingpong[1]);
    device->CreateShaderResourceView(s_pingpong[0], nullptr, &s_srv[1]);
    device->CreateShaderResourceView(s_pingpong[1], nullptr, &s_srv[2]);
    device->CreateRenderTargetView(s_pingpong[0], nullptr, &s_rtv[0]);
    device->CreateRenderTargetView(s_pingpong[1], nullptr, &s_rtv[1]);

    if (!s_copy || !s_pingpong[0] || !s_pingpong[1] || !s_srv[0] || !s_srv[1] || !s_srv[2] || !s_rtv[0] || !s_rtv[1]) {
        Shutdown();
        return;
    }

    HRESULT hr_vs = device->CreateVertexShader(blur_shaders::fullscreen_vs, blur_shaders::fullscreen_vs_size, nullptr, &s_vs);
    HRESULT hr_h = device->CreatePixelShader(blur_shaders::horizontal_ps, blur_shaders::horizontal_ps_size, nullptr, &s_ps[0]);
    HRESULT hr_v = device->CreatePixelShader(blur_shaders::vertical_ps, blur_shaders::vertical_ps_size, nullptr, &s_ps[1]);
    if (FAILED(hr_vs) || FAILED(hr_h) || FAILED(hr_v) || !s_vs || !s_ps[0] || !s_ps[1]) {
        Shutdown();
        return;
    }

    D3D11_SAMPLER_DESC sd = {};
    sd.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
    sd.AddressU = sd.AddressV = sd.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
    device->CreateSamplerState(&sd, &s_sampler);

    D3D11_BUFFER_DESC bd = {};
    bd.ByteWidth = 16; bd.Usage = D3D11_USAGE_DYNAMIC;
    bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER; bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    device->CreateBuffer(&bd, nullptr, &s_cb);
    if (!s_sampler || !s_cb) Shutdown();
}

void Blur::ApplyPass(ID3D11ShaderResourceView* src, ID3D11RenderTargetView* dst, bool horizontal)
{
    if (!s_ctx || !s_cb || !src || !dst || !s_vs || !s_ps[horizontal ? 0 : 1]) return;
    D3D11_MAPPED_SUBRESOURCE mapped;
    if (FAILED(s_ctx->Map(s_cb, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped))) return;
    float* cb = (float*)mapped.pData;
    cb[0] = horizontal ? 1.0f / s_w : 0.0f;
    cb[1] = horizontal ? 0.0f : 1.0f / s_h;
    cb[2] = cb[3] = 0.0f;
    s_ctx->Unmap(s_cb, 0);

    D3D11_VIEWPORT vp = { 0, 0, (float)s_w, (float)s_h, 0, 1 };
    s_ctx->RSSetViewports(1, &vp);
    s_ctx->OMSetRenderTargets(1, &dst, nullptr);
    s_ctx->VSSetShader(s_vs, nullptr, 0);
    s_ctx->PSSetShader(s_ps[horizontal ? 0 : 1], nullptr, 0);
    s_ctx->PSSetShaderResources(0, 1, &src);
    s_ctx->PSSetSamplers(0, 1, &s_sampler);
    s_ctx->PSSetConstantBuffers(0, 1, &s_cb);
    s_ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
    s_ctx->IASetInputLayout(nullptr);
    s_ctx->Draw(4, 0);

    ID3D11ShaderResourceView* null_srv = nullptr;
    s_ctx->PSSetShaderResources(0, 1, &null_srv);
}

struct BlurCallbackData { ImVec2 min, max; };

static void BlurCallback(const ImDrawList*, const ImDrawCmd* cmd)
{
    auto* data = cmd ? (BlurCallbackData*)cmd->UserCallbackData : nullptr;
    ULONGLONG start = GetTickCount64();
    g_blur_callbacks.fetch_add(1, std::memory_order_acq_rel);

    if (!cmd || !data || !Blur::s_ctx || !Blur::s_device || !Blur::s_copy || !Blur::s_rtv[0] || !Blur::s_rtv[1] || !Blur::s_srv[0] || !Blur::s_srv[1]) {
        g_blur_invalid_callbacks.fetch_add(1, std::memory_order_acq_rel);
        g_blur_last_area.store(0, std::memory_order_release);
        diag::log_tagged_critical_fmt("render",
            "blur_callback_invalid cmd=0x%llX data=0x%llX ctx=0x%llX device=0x%llX copy=0x%llX rtv0=0x%llX rtv1=0x%llX srv0=0x%llX srv1=0x%llX",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(cmd)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(data)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(Blur::s_ctx)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(Blur::s_device)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(Blur::s_copy)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(Blur::s_rtv[0])),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(Blur::s_rtv[1])),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(Blur::s_srv[0])),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(Blur::s_srv[1])));
        delete data;
        return;
    }
    const std::uint64_t area = blur_rect_area(data->min, data->max);
    g_blur_total_area.fetch_add(area, std::memory_order_acq_rel);
    g_blur_last_area.store(area, std::memory_order_release);

    ID3D11RenderTargetView* oldRTV = nullptr;
    ID3D11DepthStencilView* oldDSV = nullptr;
    UINT oldVPCount = 1;
    D3D11_VIEWPORT oldVP{};
    ID3D11VertexShader* oldVS = nullptr;
    ID3D11PixelShader* oldPS = nullptr;
    ID3D11ShaderResourceView* oldSRV = nullptr;
    ID3D11SamplerState* oldSamp = nullptr;
    ID3D11Buffer* oldCB = nullptr;

    ULONGLONG phase_start = GetTickCount64();
    Blur::s_ctx->OMGetRenderTargets(1, &oldRTV, &oldDSV);
    Blur::s_ctx->RSGetViewports(&oldVPCount, &oldVP);
    Blur::s_ctx->VSGetShader(&oldVS, nullptr, nullptr);
    Blur::s_ctx->PSGetShader(&oldPS, nullptr, nullptr);
    Blur::s_ctx->PSGetShaderResources(0, 1, &oldSRV);
    Blur::s_ctx->PSGetSamplers(0, 1, &oldSamp);
    Blur::s_ctx->PSGetConstantBuffers(0, 1, &oldCB);
    const ULONGLONG capture_elapsed = GetTickCount64() - phase_start;

    ID3D11Resource* rtRes = nullptr;
    ULONGLONG copy_elapsed = 0;
    ULONGLONG horizontal_elapsed = 0;
    ULONGLONG vertical_elapsed = 0;
    bool computed_blur = false;
    if (oldRTV)
        oldRTV->GetResource(&rtRes);
    if (rtRes) {
        phase_start = GetTickCount64();
        Blur::s_ctx->CopyResource(Blur::s_copy, rtRes);
        copy_elapsed = GetTickCount64() - phase_start;
        phase_start = GetTickCount64();
        Blur::ApplyPass(Blur::s_srv[0], Blur::s_rtv[0], true);
        horizontal_elapsed = GetTickCount64() - phase_start;
        phase_start = GetTickCount64();
        Blur::ApplyPass(Blur::s_srv[1], Blur::s_rtv[1], false);
        vertical_elapsed = GetTickCount64() - phase_start;
        computed_blur = true;
        rtRes->Release();
    } else {
        g_blur_no_rtv.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("render",
            "blur_callback_no_rtv old_rtv=0x%llX old_dsv=0x%llX vp_count=%u",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(oldRTV)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(oldDSV)),
            oldVPCount);
    }

    phase_start = GetTickCount64();
    Blur::s_ctx->OMSetRenderTargets(1, &oldRTV, oldDSV);
    if (oldVPCount > 0)
        Blur::s_ctx->RSSetViewports(1, &oldVP);
    Blur::s_ctx->VSSetShader(oldVS, nullptr, 0);
    Blur::s_ctx->PSSetShader(oldPS, nullptr, 0);
    Blur::s_ctx->PSSetShaderResources(0, 1, &oldSRV);
    Blur::s_ctx->PSSetSamplers(0, 1, &oldSamp);
    Blur::s_ctx->PSSetConstantBuffers(0, 1, &oldCB);
    const ULONGLONG restore_elapsed = GetTickCount64() - phase_start;

    if (oldRTV) oldRTV->Release();
    if (oldDSV) oldDSV->Release();
    if (oldVS)  oldVS->Release();
    if (oldPS)  oldPS->Release();
    if (oldSRV) oldSRV->Release();
    if (oldSamp) oldSamp->Release();
    if (oldCB)  oldCB->Release();

    ULONGLONG elapsed = GetTickCount64() - start;
    HRESULT removed = Blur::s_device ? Blur::s_device->GetDeviceRemovedReason() : E_POINTER;
    g_blur_total_elapsed_ms.fetch_add(static_cast<std::uint64_t>(elapsed), std::memory_order_acq_rel);
    g_blur_copy_elapsed_ms.fetch_add(static_cast<std::uint64_t>(copy_elapsed), std::memory_order_acq_rel);
    g_blur_horizontal_elapsed_ms.fetch_add(static_cast<std::uint64_t>(horizontal_elapsed), std::memory_order_acq_rel);
    g_blur_vertical_elapsed_ms.fetch_add(static_cast<std::uint64_t>(vertical_elapsed), std::memory_order_acq_rel);
    g_blur_restore_elapsed_ms.fetch_add(static_cast<std::uint64_t>(restore_elapsed), std::memory_order_acq_rel);
    g_blur_last_elapsed_ms.store(static_cast<std::uint64_t>(elapsed), std::memory_order_release);
    g_blur_last_copy_ms.store(static_cast<std::uint64_t>(copy_elapsed), std::memory_order_release);
    g_blur_last_horizontal_ms.store(static_cast<std::uint64_t>(horizontal_elapsed), std::memory_order_release);
    g_blur_last_vertical_ms.store(static_cast<std::uint64_t>(vertical_elapsed), std::memory_order_release);
    g_blur_last_restore_ms.store(static_cast<std::uint64_t>(restore_elapsed), std::memory_order_release);
    g_blur_last_device_removed.store(static_cast<long>(removed), std::memory_order_release);
    if (computed_blur) {
        const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
        g_blur_cache_rect_key.store(blur_rect_key(data->min, data->max, Blur::s_w, Blur::s_h), std::memory_order_release);
        g_blur_cache_last_ms.store(now_ms, std::memory_order_release);
        g_blur_last_cache_age_ms.store(0, std::memory_order_release);
        if (elapsed >= 8)
            g_blur_pressure_until_ms.store(now_ms + 250ULL, std::memory_order_release);
    }
    if (elapsed >= 8) {
        const std::uint64_t slow_count = g_blur_slow_callbacks.fetch_add(1, std::memory_order_acq_rel) + 1;
        static std::atomic<std::uint64_t> s_last_slow_log_ms{0};
        static std::atomic<std::uint64_t> s_last_slow_area_bucket{0};
        static std::atomic<long> s_last_slow_removed{0};
        const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
        const std::uint64_t area_bucket = area / 4096ULL;
        const std::uint64_t last_log_ms = s_last_slow_log_ms.load(std::memory_order_acquire);
        const bool changed = area_bucket != s_last_slow_area_bucket.load(std::memory_order_acquire) ||
            static_cast<long>(removed) != s_last_slow_removed.load(std::memory_order_acquire);
        if (last_log_ms == 0 || now_ms - last_log_ms >= 5000ULL || (changed && now_ms - last_log_ms >= 1000ULL)) {
            const std::uint64_t suppressed = g_blur_slow_suppressed.exchange(0, std::memory_order_acq_rel);
            s_last_slow_log_ms.store(now_ms, std::memory_order_release);
            s_last_slow_area_bucket.store(area_bucket, std::memory_order_release);
            s_last_slow_removed.store(static_cast<long>(removed), std::memory_order_release);
            diag::log_tagged_critical_fmt("render",
                "blur_callback_slow elapsed_ms=%llu capture_ms=%llu copy_ms=%llu h_ms=%llu v_ms=%llu restore_ms=%llu rect=%d,%d,%d,%d area=%llu callbacks=%llu slow=%llu suppressed=%llu vp_count=%u removed=0x%08lX",
                static_cast<unsigned long long>(elapsed),
                static_cast<unsigned long long>(capture_elapsed),
                static_cast<unsigned long long>(copy_elapsed),
                static_cast<unsigned long long>(horizontal_elapsed),
                static_cast<unsigned long long>(vertical_elapsed),
                static_cast<unsigned long long>(restore_elapsed),
                static_cast<int>(data->min.x),
                static_cast<int>(data->min.y),
                static_cast<int>(data->max.x),
                static_cast<int>(data->max.y),
                static_cast<unsigned long long>(area),
                static_cast<unsigned long long>(g_blur_callbacks.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(slow_count),
                static_cast<unsigned long long>(suppressed),
                oldVPCount,
                static_cast<unsigned long>(removed));
        } else {
            g_blur_slow_suppressed.fetch_add(1, std::memory_order_acq_rel);
        }
    }

    delete data;
}

void Blur::Draw(ImDrawList* dl, ImVec2 min, ImVec2 max)
{
    if (!dl || !s_srv[2] || !s_ctx || !s_copy || !s_rtv[0] || !s_rtv[1] || !s_vs || !s_ps[0] || !s_ps[1]) return;
    g_blur_draw_requests.fetch_add(1, std::memory_order_acq_rel);
    if (test_all_features::is_running()) {
        g_blur_suppressed_full_test.fetch_add(1, std::memory_order_acq_rel);
        static ULONGLONG s_last_log = 0;
        ULONGLONG now = GetTickCount64();
        if (s_last_log == 0 || now - s_last_log >= 5000) {
            s_last_log = now;
            diag::log_tagged_critical_fmt("render",
                "blur_callback_suppressed_full_test min=%d,%d max=%d,%d w=%d h=%d",
                static_cast<int>(min.x),
                static_cast<int>(min.y),
                static_cast<int>(max.x),
                static_cast<int>(max.y),
                s_w,
                s_h);
        }
        blur_draw_fallback(dl, min, max, 0.30f);
        return;
    }

    const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t rect_key = blur_rect_key(min, max, s_w, s_h);
    const std::uint64_t cached_key = g_blur_cache_rect_key.load(std::memory_order_acquire);
    const std::uint64_t cached_ms = g_blur_cache_last_ms.load(std::memory_order_acquire);
    const std::uint64_t pressure_until = g_blur_pressure_until_ms.load(std::memory_order_acquire);
    const bool cache_usable = cached_key == rect_key && cached_ms != 0 && now_ms >= cached_ms && now_ms - cached_ms <= 250ULL;
    if (cache_usable && now_ms < pressure_until) {
        const std::uint64_t cache_age_ms = now_ms - cached_ms;
        g_blur_cache_reuse.fetch_add(1, std::memory_order_acq_rel);
        g_blur_last_cache_age_ms.store(cache_age_ms, std::memory_order_release);
        dl->AddImage((ImTextureID)s_srv[2], min, max);
        blur_draw_fallback(dl, min, max, 2.0f);
        const auto& th = aida::ui::resolved();
        dl->AddLine(ImVec2(min.x + 2, min.y + 1), ImVec2(max.x - 2, min.y + 1), aida::ui::with_alpha(th.border_strong, 1.5f));
        return;
    }
    if (now_ms < pressure_until && cached_ms == 0) {
        g_blur_adaptive_fallback.fetch_add(1, std::memory_order_acq_rel);
        static ULONGLONG s_last_fallback_log = 0;
        ULONGLONG now = GetTickCount64();
        if (s_last_fallback_log == 0 || now - s_last_fallback_log >= 5000) {
            s_last_fallback_log = now;
            diag::log_tagged_fmt("render",
                "blur_adaptive_fallback reason=no_cache min=%d,%d max=%d,%d w=%d h=%d pressure_remaining_ms=%llu",
                static_cast<int>(min.x),
                static_cast<int>(min.y),
                static_cast<int>(max.x),
                static_cast<int>(max.y),
                s_w,
                s_h,
                static_cast<unsigned long long>(pressure_until - now_ms));
        }
        blur_draw_fallback(dl, min, max, 0.30f);
        return;
    }

    auto* data = new BlurCallbackData{ min, max };
    dl->AddCallback(BlurCallback, data);
    dl->AddImage((ImTextureID)s_srv[2], min, max);
    dl->AddCallback(ImDrawCallback_ResetRenderState, nullptr);

    blur_draw_fallback(dl, min, max, 2.0f);
    const auto& th = aida::ui::resolved();
    dl->AddLine(ImVec2(min.x + 2, min.y + 1), ImVec2(max.x - 2, min.y + 1), aida::ui::with_alpha(th.border_strong, 1.5f));
}

ImDrawCallback Blur::ExpectedCallback()
{
    return BlurCallback;
}

Blur::Stats Blur::SnapshotStats()
{
    Stats s;
    s.draw_requests = g_blur_draw_requests.load(std::memory_order_acquire);
    s.callbacks = g_blur_callbacks.load(std::memory_order_acquire);
    s.suppressed_full_test = g_blur_suppressed_full_test.load(std::memory_order_acquire);
    s.invalid_callbacks = g_blur_invalid_callbacks.load(std::memory_order_acquire);
    s.no_rtv = g_blur_no_rtv.load(std::memory_order_acquire);
    s.slow_callbacks = g_blur_slow_callbacks.load(std::memory_order_acquire);
    s.slow_suppressed = g_blur_slow_suppressed.load(std::memory_order_acquire);
    s.cache_reuse = g_blur_cache_reuse.load(std::memory_order_acquire);
    s.adaptive_fallback = g_blur_adaptive_fallback.load(std::memory_order_acquire);
    s.last_cache_age_ms = g_blur_last_cache_age_ms.load(std::memory_order_acquire);
    s.pressure_until_ms = g_blur_pressure_until_ms.load(std::memory_order_acquire);
    s.total_area = g_blur_total_area.load(std::memory_order_acquire);
    s.last_area = g_blur_last_area.load(std::memory_order_acquire);
    s.total_elapsed_ms = g_blur_total_elapsed_ms.load(std::memory_order_acquire);
    s.copy_elapsed_ms = g_blur_copy_elapsed_ms.load(std::memory_order_acquire);
    s.horizontal_elapsed_ms = g_blur_horizontal_elapsed_ms.load(std::memory_order_acquire);
    s.vertical_elapsed_ms = g_blur_vertical_elapsed_ms.load(std::memory_order_acquire);
    s.restore_elapsed_ms = g_blur_restore_elapsed_ms.load(std::memory_order_acquire);
    s.last_elapsed_ms = g_blur_last_elapsed_ms.load(std::memory_order_acquire);
    s.last_copy_ms = g_blur_last_copy_ms.load(std::memory_order_acquire);
    s.last_horizontal_ms = g_blur_last_horizontal_ms.load(std::memory_order_acquire);
    s.last_vertical_ms = g_blur_last_vertical_ms.load(std::memory_order_acquire);
    s.last_restore_ms = g_blur_last_restore_ms.load(std::memory_order_acquire);
    s.last_device_removed = g_blur_last_device_removed.load(std::memory_order_acquire);
    return s;
}

void Blur::Resize(int w, int h)
{
    if (!s_device) return;
    if (w <= 0 || h <= 0) return;
    if (w == s_w && h == s_h) return;
    g_blur_cache_rect_key.store(0, std::memory_order_release);
    g_blur_cache_last_ms.store(0, std::memory_order_release);
    g_blur_last_cache_age_ms.store(0, std::memory_order_release);
    g_blur_pressure_until_ms.store(0, std::memory_order_release);

    if (s_copy) { s_copy->Release(); s_copy = nullptr; }
    if (s_pingpong[0]) { s_pingpong[0]->Release(); s_pingpong[0] = nullptr; }
    if (s_pingpong[1]) { s_pingpong[1]->Release(); s_pingpong[1] = nullptr; }
    for (int i = 0; i < 3; i++) if (s_srv[i]) { s_srv[i]->Release(); s_srv[i] = nullptr; }
    for (int i = 0; i < 2; i++) if (s_rtv[i]) { s_rtv[i]->Release(); s_rtv[i] = nullptr; }

    s_w = w; s_h = h;

    D3D11_TEXTURE2D_DESC td = {};
    td.Width = w; td.Height = h; td.MipLevels = 1; td.ArraySize = 1;
    td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    s_device->CreateTexture2D(&td, nullptr, &s_copy);
    if (s_copy) s_device->CreateShaderResourceView(s_copy, nullptr, &s_srv[0]);

    td.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
    s_device->CreateTexture2D(&td, nullptr, &s_pingpong[0]);
    s_device->CreateTexture2D(&td, nullptr, &s_pingpong[1]);
    if (s_pingpong[0]) {
        s_device->CreateShaderResourceView(s_pingpong[0], nullptr, &s_srv[1]);
        s_device->CreateRenderTargetView(s_pingpong[0], nullptr, &s_rtv[0]);
    }
    if (s_pingpong[1]) {
        s_device->CreateShaderResourceView(s_pingpong[1], nullptr, &s_srv[2]);
        s_device->CreateRenderTargetView(s_pingpong[1], nullptr, &s_rtv[1]);
    }
}

void Blur::Shutdown()
{
    g_blur_cache_rect_key.store(0, std::memory_order_release);
    g_blur_cache_last_ms.store(0, std::memory_order_release);
    g_blur_last_cache_age_ms.store(0, std::memory_order_release);
    g_blur_pressure_until_ms.store(0, std::memory_order_release);
    if (s_copy) { s_copy->Release();        s_copy = nullptr; }
    if (s_pingpong[0]) { s_pingpong[0]->Release(); s_pingpong[0] = nullptr; }
    if (s_pingpong[1]) { s_pingpong[1]->Release(); s_pingpong[1] = nullptr; }
    for (int i = 0; i < 3; i++) if (s_srv[i]) { s_srv[i]->Release(); s_srv[i] = nullptr; }
    for (int i = 0; i < 2; i++) if (s_rtv[i]) { s_rtv[i]->Release(); s_rtv[i] = nullptr; }
    if (s_ps[0]) { s_ps[0]->Release();  s_ps[0] = nullptr; }
    if (s_ps[1]) { s_ps[1]->Release();  s_ps[1] = nullptr; }
    if (s_vs) { s_vs->Release();     s_vs = nullptr; }
    if (s_sampler) { s_sampler->Release(); s_sampler = nullptr; }
    if (s_cb) { s_cb->Release();     s_cb = nullptr; }
}
