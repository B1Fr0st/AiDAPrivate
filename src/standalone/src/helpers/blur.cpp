#include "blur.h"
#include "../core/ui/theme.hpp"

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

static const char* vs_src = R"(
struct VS_OUT { float4 pos : SV_POSITION; float2 uv : TEXCOORD; };
VS_OUT main(uint id : SV_VertexID) {
    VS_OUT o;
    o.uv  = float2((id & 1) ? 1.0 : 0.0, (id & 2) ? 1.0 : 0.0);
    o.pos = float4(o.uv * float2(2,-2) + float2(-1,1), 0, 1);
    return o;
}
)";

static const char* ps_h_src = R"(
Texture2D tex : register(t0);
SamplerState smp : register(s0);
cbuffer CB : register(b0) { float2 texel; float2 pad; }
struct PS_IN { float4 pos : SV_POSITION; float2 uv : TEXCOORD; };
float4 main(PS_IN i) : SV_Target {
    float w[5] = { 0.227027, 0.194595, 0.121622, 0.054054, 0.016216 };
    float4 c = tex.Sample(smp, i.uv) * w[0];
    for (int k = 1; k < 5; k++) {
        c += tex.Sample(smp, i.uv + float2(texel.x * k, 0)) * w[k];
        c += tex.Sample(smp, i.uv - float2(texel.x * k, 0)) * w[k];
    }
    return c;
}
)";

static const char* ps_v_src = R"(
Texture2D tex : register(t0);
SamplerState smp : register(s0);
cbuffer CB : register(b0) { float2 texel; float2 pad; }
struct PS_IN { float4 pos : SV_POSITION; float2 uv : TEXCOORD; };
float4 main(PS_IN i) : SV_Target {
    float w[5] = { 0.227027, 0.194595, 0.121622, 0.054054, 0.016216 };
    float4 c = tex.Sample(smp, i.uv) * w[0];
    for (int k = 1; k < 5; k++) {
        c += tex.Sample(smp, i.uv + float2(0, texel.y * k)) * w[k];
        c += tex.Sample(smp, i.uv - float2(0, texel.y * k)) * w[k];
    }
    return c;
}
)";

void Blur::Init(ID3D11Device* device, ID3D11DeviceContext* ctx, int w, int h)
{
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

    ID3DBlob* blob = nullptr;
    D3DCompile(vs_src, strlen(vs_src), nullptr, nullptr, nullptr, "main", "vs_4_0", 0, 0, &blob, nullptr);
    device->CreateVertexShader(blob->GetBufferPointer(), blob->GetBufferSize(), nullptr, &s_vs); blob->Release();
    D3DCompile(ps_h_src, strlen(ps_h_src), nullptr, nullptr, nullptr, "main", "ps_4_0", 0, 0, &blob, nullptr);
    device->CreatePixelShader(blob->GetBufferPointer(), blob->GetBufferSize(), nullptr, &s_ps[0]); blob->Release();
    D3DCompile(ps_v_src, strlen(ps_v_src), nullptr, nullptr, nullptr, "main", "ps_4_0", 0, 0, &blob, nullptr);
    device->CreatePixelShader(blob->GetBufferPointer(), blob->GetBufferSize(), nullptr, &s_ps[1]); blob->Release();

    D3D11_SAMPLER_DESC sd = {};
    sd.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
    sd.AddressU = sd.AddressV = sd.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
    device->CreateSamplerState(&sd, &s_sampler);

    D3D11_BUFFER_DESC bd = {};
    bd.ByteWidth = 16; bd.Usage = D3D11_USAGE_DYNAMIC;
    bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER; bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    device->CreateBuffer(&bd, nullptr, &s_cb);
}

void Blur::ApplyPass(ID3D11ShaderResourceView* src, ID3D11RenderTargetView* dst, bool horizontal)
{
    D3D11_MAPPED_SUBRESOURCE mapped;
    s_ctx->Map(s_cb, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
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
    auto* data = (BlurCallbackData*)cmd->UserCallbackData;

    ID3D11RenderTargetView* oldRTV = nullptr;
    ID3D11DepthStencilView* oldDSV = nullptr;
    UINT oldVPCount = 1;
    D3D11_VIEWPORT oldVP;
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
    oldRTV->GetResource(&rtRes);
    Blur::s_ctx->CopyResource(Blur::s_copy, rtRes);
    rtRes->Release();

    Blur::ApplyPass(Blur::s_srv[0], Blur::s_rtv[0], true);
    Blur::ApplyPass(Blur::s_srv[1], Blur::s_rtv[1], false);

    Blur::s_ctx->OMSetRenderTargets(1, &oldRTV, oldDSV);
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

    delete data;
}

void Blur::Draw(ImDrawList* dl, ImVec2 min, ImVec2 max)
{
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
