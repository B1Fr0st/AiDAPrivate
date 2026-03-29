#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include "helpers.h"
#include <d3d11.h>

extern ID3D11Device* g_pd3dDevice;

bool icon_loader::load(const unsigned char* data, int size, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h, bool force_white)
{
    int w, h, channels;
    unsigned char* pixels = stbi_load_from_memory(data, size, &w, &h, &channels, 4);
    if (!pixels) return false;

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
    g_pd3dDevice->CreateTexture2D(&desc, &sd, &tex);
    g_pd3dDevice->CreateShaderResourceView(tex, nullptr, out_srv);
    tex->Release();
    stbi_image_free(pixels);

    *out_w = w;
    *out_h = h;
    return true;
}
