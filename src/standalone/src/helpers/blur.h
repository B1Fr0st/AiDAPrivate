#pragma once
#include <d3d11.h>
#include <d3dcompiler.h>
#include "imgui/imgui_internal.h"
#pragma comment(lib, "d3dcompiler.lib")

class Blur {
public:
    static void Init(ID3D11Device* device, ID3D11DeviceContext* ctx, int w, int h);
    static void Resize(int w, int h);
    static void Draw(ImDrawList* dl, ImVec2 min, ImVec2 max);
    static void Shutdown();
    static void ApplyPass(ID3D11ShaderResourceView* src, ID3D11RenderTargetView* dst, bool horizontal);

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
