#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include "helpers.h"
#include <d3d11.h>

extern ID3D11Device* g_pd3dDevice;

bool icon_loader::load(const unsigned char* data, int size, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h, bool force_white)
{
    if (!out_srv || !out_w || !out_h)
        return false;
    *out_srv = nullptr;
    *out_w = 0;
    *out_h = 0;
    if (!data || size <= 0 || !g_pd3dDevice)
        return false;

    int w = 0, h = 0, channels = 0;
    unsigned char* pixels = stbi_load_from_memory(data, size, &w, &h, &channels, 4);
    if (!pixels) return false;
    if (w <= 0 || h <= 0)
    {
        stbi_image_free(pixels);
        return false;
    }

    if (force_white)
        for (int i = 0; i < w * h * 4; i += 4)
        {
            pixels[i + 0] = 255;
            pixels[i + 1] = 255;
            pixels[i + 2] = 255;
        }

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = w;
    desc.Height = h;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA sd = {};
    sd.pSysMem = pixels;
    sd.SysMemPitch = w * 4;

    ID3D11Texture2D* tex = nullptr;
    HRESULT hr = g_pd3dDevice->CreateTexture2D(&desc, &sd, &tex);
    if (FAILED(hr) || !tex)
    {
        stbi_image_free(pixels);
        return false;
    }
    hr = g_pd3dDevice->CreateShaderResourceView(tex, nullptr, out_srv);
    tex->Release();
    stbi_image_free(pixels);
    if (FAILED(hr) || !*out_srv)
        return false;

    *out_w = w;
    *out_h = h;
    return true;
}

bool icon_loader::load_file(const char* path, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h, bool force_white)
{
    if (!path || !*path || !out_srv || !out_w || !out_h)
        return false;
    *out_srv = nullptr;
    *out_w = 0;
    *out_h = 0;
    if (!g_pd3dDevice)
        return false;

    int w = 0, h = 0, channels = 0;
    unsigned char* pixels = stbi_load(path, &w, &h, &channels, 4);
    if (!pixels)
        return false;
    if (w <= 0 || h <= 0)
    {
        stbi_image_free(pixels);
        return false;
    }

    if (force_white) {
        for (int i = 0; i < w * h * 4; i += 4) {
            pixels[i + 0] = 255;
            pixels[i + 1] = 255;
            pixels[i + 2] = 255;
        }
    }

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = w;
    desc.Height = h;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA sd = {};
    sd.pSysMem = pixels;
    sd.SysMemPitch = w * 4;

    ID3D11Texture2D* tex = nullptr;
    if (FAILED(g_pd3dDevice->CreateTexture2D(&desc, &sd, &tex)) || !tex) {
        stbi_image_free(pixels);
        return false;
    }
    const HRESULT hr = g_pd3dDevice->CreateShaderResourceView(tex, nullptr, out_srv);
    tex->Release();
    stbi_image_free(pixels);
    if (FAILED(hr) || !*out_srv)
        return false;

    *out_w = w;
    *out_h = h;
    return true;
}
