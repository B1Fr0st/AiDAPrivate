#include "blur.h"
#include "blur_shaders.hpp"
#include "diag_log.hpp"
#include "../core/ui/theme.hpp"
#include "../core/testlab/test_all_features.hpp"

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

    if (!cmd || !data || !Blur::s_ctx || !Blur::s_device || !Blur::s_copy || !Blur::s_rtv[0] || !Blur::s_rtv[1] || !Blur::s_srv[0] || !Blur::s_srv[1]) {
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

    ID3D11RenderTargetView* oldRTV = nullptr;
    ID3D11DepthStencilView* oldDSV = nullptr;
    UINT oldVPCount = 1;
    D3D11_VIEWPORT oldVP{};
    ID3D11VertexShader* oldVS = nullptr;
    ID3D11PixelShader* oldPS = nullptr;
    ID3D11ShaderResourceView* oldSRV = nullptr;
    ID3D11SamplerState* oldSamp = nullptr;
    ID3D11Buffer* oldCB = nullptr;

    Blur::s_ctx->OMGetRenderTargets(1, &oldRTV, &oldDSV);
    Blur::s_ctx->RSGetViewports(&oldVPCount, &oldVP);
    Blur::s_ctx->VSGetShader(&oldVS, nullptr, nullptr);
    Blur::s_ctx->PSGetShader(&oldPS, nullptr, nullptr);
    Blur::s_ctx->PSGetShaderResources(0, 1, &oldSRV);
    Blur::s_ctx->PSGetSamplers(0, 1, &oldSamp);
    Blur::s_ctx->PSGetConstantBuffers(0, 1, &oldCB);

    ID3D11Resource* rtRes = nullptr;
    if (oldRTV)
        oldRTV->GetResource(&rtRes);
    if (rtRes) {
        Blur::s_ctx->CopyResource(Blur::s_copy, rtRes);
        Blur::ApplyPass(Blur::s_srv[0], Blur::s_rtv[0], true);
        Blur::ApplyPass(Blur::s_srv[1], Blur::s_rtv[1], false);
        rtRes->Release();
    } else {
        diag::log_tagged_critical_fmt("render",
            "blur_callback_no_rtv old_rtv=0x%llX old_dsv=0x%llX vp_count=%u",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(oldRTV)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(oldDSV)),
            oldVPCount);
    }

    Blur::s_ctx->OMSetRenderTargets(1, &oldRTV, oldDSV);
    if (oldVPCount > 0)
        Blur::s_ctx->RSSetViewports(1, &oldVP);
    Blur::s_ctx->VSSetShader(oldVS, nullptr, 0);
    Blur::s_ctx->PSSetShader(oldPS, nullptr, 0);
    Blur::s_ctx->PSSetShaderResources(0, 1, &oldSRV);
    Blur::s_ctx->PSSetSamplers(0, 1, &oldSamp);
    Blur::s_ctx->PSSetConstantBuffers(0, 1, &oldCB);

    if (oldRTV) oldRTV->Release();
    if (oldDSV) oldDSV->Release();
    if (oldVS)  oldVS->Release();
    if (oldPS)  oldPS->Release();
    if (oldSRV) oldSRV->Release();
    if (oldSamp) oldSamp->Release();
    if (oldCB)  oldCB->Release();

    ULONGLONG elapsed = GetTickCount64() - start;
    if (elapsed >= 8) {
        HRESULT removed = Blur::s_device ? Blur::s_device->GetDeviceRemovedReason() : E_POINTER;
        diag::log_tagged_critical_fmt("render",
            "blur_callback_slow elapsed_ms=%llu rect=%d,%d,%d,%d vp_count=%u removed=0x%08lX",
            static_cast<unsigned long long>(elapsed),
            static_cast<int>(data->min.x),
            static_cast<int>(data->min.y),
            static_cast<int>(data->max.x),
            static_cast<int>(data->max.y),
            oldVPCount,
            static_cast<unsigned long>(removed));
    }

    delete data;
}

void Blur::Draw(ImDrawList* dl, ImVec2 min, ImVec2 max)
{
    if (!dl || !s_srv[2] || !s_ctx || !s_copy || !s_rtv[0] || !s_rtv[1] || !s_vs || !s_ps[0] || !s_ps[1]) return;
    if (test_all_features::is_running()) {
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
        const auto& th = aida::ui::resolved();
        dl->AddRectFilled(min, max, aida::ui::with_alpha(th.glass_tint, 0.30f), 8.0f);
        dl->AddRect(min, max, th.border_subtle, 8.0f);
        return;
    }
    auto* data = new BlurCallbackData{ min, max };
    dl->AddCallback(BlurCallback, data);
    dl->AddImage((ImTextureID)s_srv[2], min, max);
    dl->AddCallback(ImDrawCallback_ResetRenderState, nullptr);

    const auto& th = aida::ui::resolved();
    dl->AddRectFilled(min, max, aida::ui::with_alpha(th.glass_tint, 2.0f), 8.0f);
    dl->AddRect(min, max, th.border_subtle, 8.0f);
    dl->AddLine(ImVec2(min.x + 2, min.y + 1), ImVec2(max.x - 2, min.y + 1), aida::ui::with_alpha(th.border_strong, 1.5f));
}

void Blur::Resize(int w, int h)
{
    if (!s_device) return;
    if (w <= 0 || h <= 0) return;
    if (w == s_w && h == s_h) return;

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
