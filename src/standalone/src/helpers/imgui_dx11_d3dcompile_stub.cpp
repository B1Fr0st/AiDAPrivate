#include "helpers/imgui_dx11_shaders.hpp"

#include <d3dcompiler.h>
#include <cstring>
#include <new>

namespace {

class static_shader_blob final : public ID3DBlob {
public:
    static_shader_blob(const void* data, SIZE_T size) : data_(data), size_(size) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override
    {
        if (!out) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ID3DBlob)) {
            *out = static_cast<ID3DBlob*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&refs_));
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        LONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) delete this;
        return static_cast<ULONG>(refs);
    }

    LPVOID STDMETHODCALLTYPE GetBufferPointer() override
    {
        return const_cast<void*>(data_);
    }

    SIZE_T STDMETHODCALLTYPE GetBufferSize() override
    {
        return size_;
    }

private:
    volatile LONG refs_ = 1;
    const void* data_ = nullptr;
    SIZE_T size_ = 0;
};

}

extern "C" HRESULT WINAPI D3DCompile(
    LPCVOID src_data,
    SIZE_T src_data_size,
    LPCSTR source_name,
    const D3D_SHADER_MACRO* defines,
    ID3DInclude* include_handler,
    LPCSTR entrypoint,
    LPCSTR target,
    UINT flags1,
    UINT flags2,
    ID3DBlob** code,
    ID3DBlob** error_messages)
{
    (void)src_data;
    (void)src_data_size;
    (void)source_name;
    (void)defines;
    (void)include_handler;
    (void)flags1;
    (void)flags2;

    if (error_messages) *error_messages = nullptr;
    if (!code) return E_POINTER;
    *code = nullptr;
    if (!entrypoint || std::strcmp(entrypoint, "main") != 0 || !target) return E_INVALIDARG;

    const void* data = nullptr;
    SIZE_T size = 0;
    if (std::strncmp(target, "vs_", 3) == 0) {
        data = imgui_dx11_shaders::vertex_shader;
        size = imgui_dx11_shaders::vertex_shader_size;
    } else if (std::strncmp(target, "ps_", 3) == 0) {
        data = imgui_dx11_shaders::pixel_shader;
        size = imgui_dx11_shaders::pixel_shader_size;
    } else {
        return E_INVALIDARG;
    }

    static_shader_blob* blob = new (std::nothrow) static_shader_blob(data, size);
    if (!blob) return E_OUTOFMEMORY;
    *code = blob;
    return S_OK;
}
