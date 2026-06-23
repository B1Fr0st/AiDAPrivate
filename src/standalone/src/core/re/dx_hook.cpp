#include "dx_hook.hpp"

#include "artifact_store.hpp"
#include "vmt.hpp"
#include "../infra/work_queue.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cwchar>
#include <cstring>
#include <cstddef>
#include <d3d11.h>
#include <d3d12.h>
#include <dxgi.h>
#include <fstream>
#include <gdiplus.h>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

#pragma comment(lib, "gdiplus.lib")

extern ID3D11Device* g_pd3dDevice;

namespace re::dx_hook
{
namespace
{
struct slot_entry_t
{
    std::string name;
    std::uint32_t slot = 0;
    std::uint64_t local_va = 0;
    std::uint64_t target_va = 0;
    std::uint64_t target_rva = 0;
    std::string module_name;
    std::string hint;
    std::string local_prologue;
    std::string target_prologue;
    std::string target_bytes;
    std::string api_family;
    std::string role;
    std::string abi_signature;
    std::string validation_reason;
    json capability_evidence = json::object();
    bool target_executable = false;
    bool validated = false;
};

using pfn_d3d11_create_device_t = HRESULT(WINAPI*)(IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT, UINT, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
using pfn_d3d11_create_device_and_swap_chain_t = HRESULT(WINAPI*)(IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT, UINT, const DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
using pfn_d3d12_create_device_t = HRESULT(WINAPI*)(IUnknown*, D3D_FEATURE_LEVEL, REFIID, void**);

struct slot_abi_t
{
    const char* api_family = "";
    const char* role = "";
    const char* signature = "";
    const char* first_arg = "";
    std::uint32_t expected_slot = UINT32_MAX;
    bool loader_export = false;
    bool dispatchable_handle = false;
};

slot_abi_t slot_abi_for(const slot_entry_t& entry)
{
    const std::string name = entry.name;
    const std::string module = lower_ascii(entry.module_name);
    if (name == "D3D11CreateDevice") return {"d3d11", "snapshot_marker", "HRESULT D3D11CreateDevice(IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT, UINT, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**)", "IDXGIAdapter*", UINT32_MAX, true, false};
    if (name == "CreateDXGIFactory" || name == "CreateDXGIFactory1" || name == "CreateDXGIFactory2") return {"dxgi", "snapshot_marker", "HRESULT CreateDXGIFactory*(REFIID riid, void** ppFactory)", "REFIID", UINT32_MAX, true, false};
    if (name == "DrawInstanced" && module.find("d3d12") != std::string::npos) return {"d3d12", "draw", "ID3D12GraphicsCommandList::DrawInstanced(UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation)", "ID3D12GraphicsCommandList*", 12, false, false};
    if (name == "DrawIndexedInstanced" && module.find("d3d12") != std::string::npos) return {"d3d12", "draw", "ID3D12GraphicsCommandList::DrawIndexedInstanced(UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation)", "ID3D12GraphicsCommandList*", 13, false, false};
    if (name == "Dispatch" && module.find("d3d12") != std::string::npos) return {"d3d12", "compute_dispatch", "ID3D12GraphicsCommandList::Dispatch(UINT ThreadGroupCountX, UINT ThreadGroupCountY, UINT ThreadGroupCountZ)", "ID3D12GraphicsCommandList*", 14, false, false};
    if (name == "IASetVertexBuffers" && module.find("d3d12") != std::string::npos) return {"d3d12", "vertex_buffer_bind", "ID3D12GraphicsCommandList::IASetVertexBuffers(UINT StartSlot, UINT NumViews, const D3D12_VERTEX_BUFFER_VIEW* pViews)", "ID3D12GraphicsCommandList*", 44, false, false};
    if (name == "OMSetRenderTargets" && module.find("d3d12") != std::string::npos) return {"d3d12", "render_target_bind", "ID3D12GraphicsCommandList::OMSetRenderTargets(UINT NumRenderTargetDescriptors, const D3D12_CPU_DESCRIPTOR_HANDLE* pRenderTargetDescriptors, BOOL RTsSingleHandleToDescriptorRange, const D3D12_CPU_DESCRIPTOR_HANDLE* pDepthStencilDescriptor)", "ID3D12GraphicsCommandList*", 46, false, false};
    if (name == "VSSetConstantBuffers") return {"d3d11", "cbuffer_bind", "ID3D11DeviceContext::VSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers)", "ID3D11DeviceContext*", 7, false, false};
    if (name == "PSSetConstantBuffers") return {"d3d11", "cbuffer_bind", "ID3D11DeviceContext::PSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers)", "ID3D11DeviceContext*", 16, false, false};
    if (name == "GSSetConstantBuffers") return {"d3d11", "cbuffer_bind", "ID3D11DeviceContext::GSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers)", "ID3D11DeviceContext*", 22, false, false};
    if (name == "HSSetConstantBuffers") return {"d3d11", "cbuffer_bind", "ID3D11DeviceContext::HSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers)", "ID3D11DeviceContext*", 62, false, false};
    if (name == "DSSetConstantBuffers") return {"d3d11", "cbuffer_bind", "ID3D11DeviceContext::DSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers)", "ID3D11DeviceContext*", 66, false, false};
    if (name == "CSSetConstantBuffers") return {"d3d11", "cbuffer_bind", "ID3D11DeviceContext::CSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers)", "ID3D11DeviceContext*", 71, false, false};
    if (name == "DrawIndexed") return {"d3d11", "draw", "ID3D11DeviceContext::DrawIndexed(UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation)", "ID3D11DeviceContext*", 12, false, false};
    if (name == "Draw") return {"d3d11", "draw", "ID3D11DeviceContext::Draw(UINT VertexCount, UINT StartVertexLocation)", "ID3D11DeviceContext*", 13, false, false};
    if (name == "DrawIndexedInstanced") return {"d3d11", "draw", "ID3D11DeviceContext::DrawIndexedInstanced(UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation)", "ID3D11DeviceContext*", 20, false, false};
    if (name == "DrawInstanced") return {"d3d11", "draw", "ID3D11DeviceContext::DrawInstanced(UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation)", "ID3D11DeviceContext*", 21, false, false};
    if (name == "IASetVertexBuffers") return {"d3d11", "vertex_buffer_bind", "ID3D11DeviceContext::IASetVertexBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppVertexBuffers, const UINT* pStrides, const UINT* pOffsets)", "ID3D11DeviceContext*", 18, false, false};
    if (name == "SetGraphicsRootConstantBufferView") return {"d3d12", "cbuffer_bind", "ID3D12GraphicsCommandList::SetGraphicsRootConstantBufferView(UINT RootParameterIndex, D3D12_GPU_VIRTUAL_ADDRESS BufferLocation)", "ID3D12GraphicsCommandList*", 38, false, false};
    if (name == "IDXGISwapChain::Present") return {"dxgi", "present", "IDXGISwapChain::Present(UINT SyncInterval, UINT Flags)", "IDXGISwapChain*", 8, false, false};
    if (name == "vkQueuePresentKHR") return {"vulkan", "present", "VkResult vkQueuePresentKHR(VkQueue queue, const VkPresentInfoKHR* pPresentInfo)", "VkQueue", UINT32_MAX, true, true};
    if (name == "vkCmdDraw") return {"vulkan", "draw", "void vkCmdDraw(VkCommandBuffer commandBuffer, uint32_t vertexCount, uint32_t instanceCount, uint32_t firstVertex, uint32_t firstInstance)", "VkCommandBuffer", UINT32_MAX, true, true};
    if (name == "vkCmdDrawIndexed") return {"vulkan", "draw", "void vkCmdDrawIndexed(VkCommandBuffer commandBuffer, uint32_t indexCount, uint32_t instanceCount, uint32_t firstIndex, int32_t vertexOffset, uint32_t firstInstance)", "VkCommandBuffer", UINT32_MAX, true, true};
    if (name == "vkGetDeviceProcAddr") return {"vulkan", "proc_addr", "PFN_vkVoidFunction vkGetDeviceProcAddr(VkDevice device, const char* pName)", "VkDevice", UINT32_MAX, true, true};
    if (name == "vkGetInstanceProcAddr") return {"vulkan", "proc_addr", "PFN_vkVoidFunction vkGetInstanceProcAddr(VkInstance instance, const char* pName)", "VkInstance", UINT32_MAX, true, true};
    return {};
}

bool read_local_bytes(std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out)
{
    out.clear();
    if (address == 0 || size == 0)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    if ((mbi.State & MEM_COMMIT) == 0 || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
        return false;
    const auto region_base = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
    const std::uint64_t region_end = region_base + static_cast<std::uint64_t>(mbi.RegionSize);
    if (region_end <= address)
        return false;
    const std::size_t readable = static_cast<std::size_t>(std::min<std::uint64_t>(size, region_end - address));
    if (readable == 0)
        return false;
    out.resize(readable);
    std::memcpy(out.data(), reinterpret_cast<const void*>(address), readable);
    return true;
}

bool bytes_are_uniform(const std::vector<std::uint8_t>& bytes, std::uint8_t value)
{
    return !bytes.empty() && std::all_of(bytes.begin(), bytes.end(), [value](std::uint8_t b) { return b == value; });
}

bool bytes_prefix_match(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b, std::size_t min_len)
{
    if (a.size() < min_len || b.size() < min_len)
        return false;
    return std::equal(a.begin(), a.begin() + static_cast<std::ptrdiff_t>(min_len), b.begin());
}

bool branch_or_call_opcode(std::uint8_t b)
{
    return b == 0xE8 || b == 0xE9 || b == 0xEB || b == 0xFF;
}

std::uint64_t relative_branch_target(std::uint64_t va, const std::vector<std::uint8_t>& bytes)
{
    if (bytes.empty())
        return 0;
    if ((bytes[0] == 0xE8 || bytes[0] == 0xE9) && bytes.size() >= 5)
    {
        std::int32_t rel = 0;
        std::memcpy(&rel, bytes.data() + 1, sizeof(rel));
        return va + 5ull + static_cast<std::int64_t>(rel);
    }
    if (bytes[0] == 0xEB && bytes.size() >= 2)
    {
        const auto rel = static_cast<std::int8_t>(bytes[1]);
        return va + 2ull + static_cast<std::int64_t>(rel);
    }
    return 0;
}

bool prologue_bytes_plausible(const std::vector<std::uint8_t>& bytes, std::string& reason)
{
    if (bytes.empty())
    {
        reason = "target_bytes_unreadable";
        return false;
    }
    const std::uint8_t b0 = bytes[0];
    if (b0 == 0x00)
    {
        reason = "null_prologue";
        return false;
    }
    if (b0 == 0xCC || b0 == 0xC3 || b0 == 0xCB)
    {
        reason = "trap_or_return_prologue";
        return false;
    }
    if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z')
    {
        reason = "pe_header_not_code";
        return false;
    }
    if (bytes.size() >= 2 && bytes[0] == 0x0F && bytes[1] == 0x0B)
    {
        reason = "ud2_prologue";
        return false;
    }
    if (b0 == 0xF4 || b0 == 0xCD)
    {
        reason = "privileged_or_interrupt_prologue";
        return false;
    }
    if (bytes_are_uniform(bytes, 0x00))
    {
        reason = "zero_filled_prologue";
        return false;
    }
    if (bytes_are_uniform(bytes, 0xCC))
    {
        reason = "int3_filled_prologue";
        return false;
    }
    reason = "accepted_code_prologue";
    return true;
}

std::string api_param(const json& params)
{
    std::string api = lower_ascii(string_param(params, "api", "auto"));
    if (api.empty())
        api = "auto";
    return api;
}

bool api_supported(const std::string& api, bool allow_auto)
{
    return (allow_auto && api == "auto") ||
           api == "d3d11" ||
           api == "d3d12" ||
           api == "dxgi" ||
           api == "vulkan";
}

json supported_api_values(bool allow_auto)
{
    json apis = json::array();
    if (allow_auto)
        apis.push_back("auto");
    apis.push_back("d3d11");
    apis.push_back("d3d12");
    apis.push_back("dxgi");
    apis.push_back("vulkan");
    return apis;
}

std::uint64_t module_base_local(const char* name, bool allow_load = true)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "module_base_local enter pid=%lu tid=%lu module=%s allow_load=%d",
                         static_cast<unsigned long>(GetCurrentProcessId()),
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         name ? name : "",
                         allow_load ? 1 : 0);
    HMODULE mod = GetModuleHandleA(name);
    diag::log_tagged_fmt("dx_hook", "module_base_local getmodule pid=%lu tid=%lu module=%s base=%s gle=%lu elapsed_ms=%llu",
                         static_cast<unsigned long>(GetCurrentProcessId()),
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         name ? name : "",
                         sa_format_address(reinterpret_cast<std::uint64_t>(mod)).c_str(),
                         static_cast<unsigned long>(GetLastError()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!mod)
    {
        if (!allow_load)
        {
            diag::log_tagged_fmt("dx_hook", "module_base_local no_load pid=%lu tid=%lu module=%s elapsed_ms=%llu",
                                 static_cast<unsigned long>(GetCurrentProcessId()),
                                 static_cast<unsigned long>(GetCurrentThreadId()),
                                 name ? name : "",
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return 0;
        }
        SetLastError(ERROR_SUCCESS);
        diag::log_tagged_fmt("dx_hook", "module_base_local load_begin pid=%lu tid=%lu module=%s elapsed_ms=%llu",
                             static_cast<unsigned long>(GetCurrentProcessId()),
                             static_cast<unsigned long>(GetCurrentThreadId()),
                             name ? name : "",
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        mod = LoadLibraryA(name);
        diag::log_tagged_fmt("dx_hook", "module_base_local load_end pid=%lu tid=%lu module=%s base=%s gle=%lu elapsed_ms=%llu",
                             static_cast<unsigned long>(GetCurrentProcessId()),
                             static_cast<unsigned long>(GetCurrentThreadId()),
                             name ? name : "",
                             sa_format_address(reinterpret_cast<std::uint64_t>(mod)).c_str(),
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
    }
    return reinterpret_cast<std::uint64_t>(mod);
}

bool dx_call_cancelled(const char* phase, std::uint32_t pid, std::uint64_t started_ms)
{
    if (mcp_standalone::current_call_cancelled())
    {
        diag::log_tagged_fmt("dx_hook", "cancelled pid=%u phase=%s elapsed_ms=%llu diag_id=%s",
                             pid,
                             phase ? phase : "",
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0 && GetTickCount64() >= deadline)
    {
        diag::log_tagged_fmt("dx_hook", "deadline_reached pid=%u phase=%s elapsed_ms=%llu diag_id=%s",
                             pid,
                             phase ? phase : "",
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    return false;
}

bool target_module_loaded(std::uint32_t pid, const char* module_name)
{
    const bool loaded = module_name && find_module_by_name(pid, module_name).has_value();
    diag::log_tagged_fmt("dx_hook", "target_module_loaded pid=%u module=%s loaded=%d",
                         pid,
                         module_name ? module_name : "",
                         loaded ? 1 : 0);
    return loaded;
}

std::uint64_t map_local_to_target(std::uint32_t pid, const char* module_name, std::uint64_t local_va, bool allow_local_load = true)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "map_local_to_target enter pid=%u tid=%lu module=%s local_va=%s allow_local_load=%d",
                         pid,
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         module_name ? module_name : "",
                         sa_format_address(local_va).c_str(),
                         allow_local_load ? 1 : 0);
    const std::uint64_t local_base = module_base_local(module_name, allow_local_load);
    if (local_base == 0 || local_va < local_base)
    {
        diag::log_tagged_fmt("dx_hook", "map_local_to_target local_invalid pid=%u module=%s local_base=%s local_va=%s elapsed_ms=%llu",
                             pid,
                             module_name ? module_name : "",
                             sa_format_address(local_base).c_str(),
                             sa_format_address(local_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return 0;
    }
    auto target_module = find_module_by_name(pid, module_name);
    if (!target_module)
    {
        diag::log_tagged_fmt("dx_hook", "map_local_to_target target_module_missing pid=%u module=%s local_base=%s local_va=%s rva=%s elapsed_ms=%llu",
                             pid,
                             module_name ? module_name : "",
                             sa_format_address(local_base).c_str(),
                             sa_format_address(local_va).c_str(),
                             sa_format_address(local_va - local_base).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return 0;
    }
    const std::uint64_t rva = local_va - local_base;
    const std::uint64_t target = target_module->base + rva;
    diag::log_tagged_fmt("dx_hook", "map_local_to_target exit pid=%u module=%s local_base=%s target_base=%s target_end=%s rva=%s target_va=%s elapsed_ms=%llu",
                         pid,
                         module_name ? module_name : "",
                         sa_format_address(local_base).c_str(),
                         sa_format_address(target_module->base).c_str(),
                         sa_format_address(target_module->base + static_cast<std::uint64_t>(target_module->size)).c_str(),
                         sa_format_address(rva).c_str(),
                         sa_format_address(target).c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return target;
}

struct local_owner_t
{
    bool ok = false;
    std::string module_name;
    std::string module_path;
    std::uint64_t base = 0;
    std::uint64_t rva = 0;
};

std::string filename_leaf(const char* path)
{
    if (!path || !*path)
        return {};
    const char* slash = std::strrchr(path, '\\');
    const char* fslash = std::strrchr(path, '/');
    const char* leaf = slash && fslash ? std::max(slash, fslash) + 1 : (slash ? slash + 1 : (fslash ? fslash + 1 : path));
    return leaf && *leaf ? std::string(leaf) : std::string(path);
}

local_owner_t local_owner_for_address(std::uint64_t local_va)
{
    local_owner_t owner;
    if (local_va == 0)
        return owner;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<const void*>(local_va), &mbi, sizeof(mbi)) != sizeof(mbi) || !mbi.AllocationBase)
    {
        diag::log_tagged_fmt("dx_hook", "local_owner query_failed local_va=%s gle=%lu",
                             sa_format_address(local_va).c_str(),
                             static_cast<unsigned long>(GetLastError()));
        return owner;
    }
    char path[MAX_PATH] = {};
    const DWORD len = GetModuleFileNameA(reinterpret_cast<HMODULE>(mbi.AllocationBase), path, static_cast<DWORD>(sizeof(path)));
    if (len == 0)
    {
        diag::log_tagged_fmt("dx_hook", "local_owner module_name_failed local_va=%s allocation_base=%s gle=%lu",
                             sa_format_address(local_va).c_str(),
                             sa_format_address(reinterpret_cast<std::uint64_t>(mbi.AllocationBase)).c_str(),
                             static_cast<unsigned long>(GetLastError()));
        return owner;
    }
    owner.ok = true;
    owner.module_path.assign(path, path + std::min<DWORD>(len, static_cast<DWORD>(sizeof(path) - 1)));
    owner.module_name = filename_leaf(owner.module_path.c_str());
    owner.base = reinterpret_cast<std::uint64_t>(mbi.AllocationBase);
    owner.rva = local_va >= owner.base ? local_va - owner.base : 0;
    diag::log_tagged_fmt("dx_hook", "local_owner resolved local_va=%s owner_module=%s owner_base=%s owner_rva=%s path='%s'",
                         sa_format_address(local_va).c_str(),
                         owner.module_name.c_str(),
                         sa_format_address(owner.base).c_str(),
                         sa_format_address(owner.rva).c_str(),
                         owner.module_path.c_str());
    return owner;
}

std::uint64_t map_local_slot_to_target(std::uint32_t pid,
                                       const char* slot_name,
                                       std::uint32_t slot,
                                       std::uint64_t local_va,
                                       const char* fallback_module,
                                       bool allow_fallback_load,
                                       std::string& module_name)
{
    const std::uint64_t started_ms = GetTickCount64();
    const local_owner_t owner = local_owner_for_address(local_va);
    if (owner.ok && !owner.module_name.empty())
    {
        module_name = owner.module_name;
        auto target_module = find_module_by_name(pid, owner.module_name);
        const bool rva_in_range = target_module && owner.rva < static_cast<std::uint64_t>(target_module->size);
        const std::uint64_t target_va = rva_in_range ? target_module->base + owner.rva : 0;
        diag::log_tagged_fmt("dx_hook",
                             "map_local_slot owner_map pid=%u name=%s slot=%u local_va=%s owner_module=%s owner_rva=%s target_module_match=%d target_base=%s target_size=%llu target_va=%s elapsed_ms=%llu",
                             pid,
                             slot_name ? slot_name : "",
                             slot,
                             sa_format_address(local_va).c_str(),
                             owner.module_name.c_str(),
                             sa_format_address(owner.rva).c_str(),
                             target_module ? 1 : 0,
                             target_module ? sa_format_address(target_module->base).c_str() : "0x0",
                             target_module ? static_cast<unsigned long long>(target_module->size) : 0ull,
                             sa_format_address(target_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (target_va != 0)
            return target_va;
    }

    if (!fallback_module || !*fallback_module)
        return 0;
    if (owner.ok && _stricmp(owner.module_name.c_str(), fallback_module) == 0)
        return 0;
    module_name = fallback_module;
    const std::uint64_t fallback = map_local_to_target(pid, fallback_module, local_va, allow_fallback_load);
    diag::log_tagged_fmt("dx_hook",
                         "map_local_slot fallback_map pid=%u name=%s slot=%u local_va=%s fallback_module=%s target_va=%s allow_load=%d elapsed_ms=%llu",
                         pid,
                         slot_name ? slot_name : "",
                         slot,
                         sa_format_address(local_va).c_str(),
                         fallback_module,
                         sa_format_address(fallback).c_str(),
                         allow_fallback_load ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return fallback;
}

std::string local_prologue_hint(std::uint64_t local_va)
{
    if (local_va == 0)
        return "unavailable";
    auto* ptr = reinterpret_cast<const std::uint8_t*>(local_va);
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) != sizeof(mbi) ||
        (mbi.State & MEM_COMMIT) == 0 ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
        return "unreadable";
    AsmInstr ins = zydis_decode_one(ptr, 16, local_va);
    return classify_instruction_hint(ins) + ":" + disasm_text(ins);
}

json prologue_signature_evidence(std::uint32_t pid,
                                 std::uint64_t local_va,
                                 std::uint64_t target_va,
                                 const std::vector<std::uint8_t>& target_bytes,
                                 const AsmInstr& target_ins,
                                 bool& accepted,
                                 std::string& reason);

void finalize_slot(std::uint32_t pid, slot_entry_t& entry)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "finalize_slot enter pid=%u tid=%lu name=%s slot=%u module=%s local_va=%s target_va=%s",
                         pid,
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         entry.name.c_str(),
                         entry.slot,
                         entry.module_name.c_str(),
                         sa_format_address(entry.local_va).c_str(),
                         sa_format_address(entry.target_va).c_str());
    const slot_abi_t abi = slot_abi_for(entry);
    entry.api_family = abi.api_family;
    entry.role = abi.role;
    entry.abi_signature = abi.signature;
    entry.capability_evidence["api_family"] = entry.api_family.empty() ? json(nullptr) : json(entry.api_family);
    entry.capability_evidence["role"] = entry.role.empty() ? json(nullptr) : json(entry.role);
    entry.capability_evidence["abi_signature"] = entry.abi_signature.empty() ? json(nullptr) : json(entry.abi_signature);
    entry.capability_evidence["first_argument"] = (abi.first_arg && *abi.first_arg) ? json(abi.first_arg) : json(nullptr);
    entry.capability_evidence["expected_slot"] = abi.expected_slot == UINT32_MAX ? json(nullptr) : json(abi.expected_slot);
    entry.capability_evidence["observed_slot"] = entry.slot;
    entry.capability_evidence["slot_index_matches"] = abi.expected_slot == UINT32_MAX ? json(nullptr) : json(entry.slot == abi.expected_slot);
    entry.capability_evidence["loader_export"] = abi.loader_export;
    entry.capability_evidence["dispatchable_handle_first_arg"] = abi.dispatchable_handle;
    entry.local_prologue = local_prologue_hint(entry.local_va);
    entry.hint = entry.local_prologue;
    if (entry.target_va == 0)
    {
        entry.validated = false;
        entry.validation_reason = "target_address_unresolved";
        entry.capability_evidence["validation_reason"] = entry.validation_reason;
        diag::log_tagged_fmt("dx_hook", "finalize_slot no_target pid=%u name=%s slot=%u local_hint=%s elapsed_ms=%llu",
                             pid,
                             entry.name.c_str(),
                             entry.slot,
                             entry.local_prologue.c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return;
    }
    auto mod = find_module_by_name(pid, entry.module_name);
    if (mod && entry.target_va >= mod->base && entry.target_va < mod->base + static_cast<std::uint64_t>(mod->size))
        entry.target_rva = entry.target_va - mod->base;
    auto owner_mod = find_module_for_address(pid, entry.target_va);
    entry.capability_evidence["module_hint_found"] = mod.has_value();
    entry.capability_evidence["owner_module"] = owner_mod ? json(module_json(*owner_mod)) : json(nullptr);
    diag::log_tagged_fmt("dx_hook", "finalize_slot module pid=%u name=%s module=%s module_found=%d module_base=%s module_end=%s target_rva=%s",
                         pid,
                         entry.name.c_str(),
                         entry.module_name.c_str(),
                         mod ? 1 : 0,
                         mod ? sa_format_address(mod->base).c_str() : "0x0",
                         mod ? sa_format_address(mod->base + static_cast<std::uint64_t>(mod->size)).c_str() : "0x0",
                         entry.target_rva ? sa_format_address(entry.target_rva).c_str() : "0x0");
    driver_bridge::memory_region_t region{};
    diag::log_tagged_fmt("dx_hook", "finalize_slot query_begin pid=%u name=%s target_va=%s",
                         pid,
                         entry.name.c_str(),
                         sa_format_address(entry.target_va).c_str());
    entry.target_executable = query_region(pid, entry.target_va, region) && is_committed(region) && is_executable(region) && !is_guarded(region);
    diag::log_tagged_fmt("dx_hook", "finalize_slot query_end pid=%u name=%s target_va=%s region_base=%s region_size=%llu protect=0x%08lX state=0x%08lX type=0x%08lX executable=%d",
                         pid,
                         entry.name.c_str(),
                         sa_format_address(entry.target_va).c_str(),
                         sa_format_address(region.base).c_str(),
                         static_cast<unsigned long long>(region.size),
                         static_cast<unsigned long>(region.protect),
                         static_cast<unsigned long>(region.state),
                         static_cast<unsigned long>(region.type),
                         entry.target_executable ? 1 : 0);
    entry.capability_evidence["memory_region"] = region_json(region);
    std::vector<std::uint8_t> bytes;
    diag::log_tagged_fmt("dx_hook", "finalize_slot read_begin pid=%u name=%s target_va=%s bytes=32",
                         pid,
                         entry.name.c_str(),
                         sa_format_address(entry.target_va).c_str());
    AsmInstr ins{};
    if (read_bytes(pid, entry.target_va, 32, bytes) && !bytes.empty())
    {
        entry.target_bytes = bytes_to_hex(bytes, 32);
        ins = zydis_decode_one(bytes.data(), static_cast<int>(std::min<std::size_t>(bytes.size(), 32)), entry.target_va);
        entry.target_prologue = classify_instruction_hint(ins) + ":" + disasm_text(ins);
        diag::log_tagged_fmt("dx_hook", "finalize_slot read_decode pid=%u name=%s target_va=%s bytes_read=%zu prologue=%s raw=%s",
                             pid,
                             entry.name.c_str(),
                             sa_format_address(entry.target_va).c_str(),
                             bytes.size(),
                             entry.target_prologue.c_str(),
                             entry.target_bytes.c_str());
    }
    else
    {
        entry.target_prologue = "unreadable";
        diag::log_tagged_fmt("dx_hook", "finalize_slot read_failed pid=%u name=%s target_va=%s bytes_read=%zu",
                             pid,
                             entry.name.c_str(),
                             sa_format_address(entry.target_va).c_str(),
                             bytes.size());
    }
    bool prologue_signature_ok = false;
    std::string prologue_reason;
    json prologue_evidence = prologue_signature_evidence(pid, entry.local_va, entry.target_va, bytes, ins, prologue_signature_ok, prologue_reason);
    const bool first_instruction_decoded = entry.target_prologue.find("unknown:") != 0 && entry.target_prologue != "unreadable";
    const bool prologue_ok = prologue_signature_ok && first_instruction_decoded;
    const bool slot_ok = abi.expected_slot == UINT32_MAX || entry.slot == abi.expected_slot;
    const bool module_ok = owner_mod.has_value();
    const bool abi_known = !entry.api_family.empty() && !entry.role.empty() && !entry.abi_signature.empty();
    int validation_score = 0;
    if (entry.target_executable) validation_score += 2;
    if (first_instruction_decoded) validation_score += 2;
    if (prologue_signature_ok) validation_score += 2;
    if (slot_ok) validation_score += 2;
    if (module_ok) validation_score += 1;
    if (abi_known) validation_score += 1;
    const bool prefix16_match = prologue_evidence.contains("local_target_prefix16_match") && prologue_evidence["local_target_prefix16_match"].is_boolean() && prologue_evidence["local_target_prefix16_match"].get<bool>();
    const bool prefix8_match = prologue_evidence.contains("local_target_prefix8_match") && prologue_evidence["local_target_prefix8_match"].is_boolean() && prologue_evidence["local_target_prefix8_match"].get<bool>();
    if (prefix16_match) validation_score += 2;
    else if (prefix8_match) validation_score += 1;
    entry.validated = entry.target_executable && prologue_ok && slot_ok && module_ok && abi_known;
    if (!entry.target_executable)
        entry.validation_reason = "target_region_not_executable";
    else if (!prologue_ok)
        entry.validation_reason = prologue_reason;
    else if (!slot_ok)
        entry.validation_reason = "unexpected_com_vtable_slot";
    else if (!module_ok)
        entry.validation_reason = "target_module_owner_unresolved";
    else if (!abi_known)
        entry.validation_reason = "abi_signature_unknown";
    else
        entry.validation_reason = "validated";
    entry.capability_evidence["target_prologue_validation"] = prologue_reason;
    entry.capability_evidence["target_first_instruction_decoded"] = first_instruction_decoded;
    entry.capability_evidence["prologue_signature"] = std::move(prologue_evidence);
    entry.capability_evidence["abi_known"] = abi_known;
    entry.capability_evidence["validation_score"] = validation_score;
    entry.capability_evidence["validation_reason"] = entry.validation_reason;
    diag::log_tagged_fmt("dx_hook", "finalize_slot exit pid=%u name=%s slot=%u target_va=%s target_rva=%s executable=%d validated=%d reason=%s elapsed_ms=%llu",
                         pid,
                         entry.name.c_str(),
                         entry.slot,
                         sa_format_address(entry.target_va).c_str(),
                         entry.target_rva ? sa_format_address(entry.target_rva).c_str() : "0x0",
                         entry.target_executable ? 1 : 0,
                         entry.validated ? 1 : 0,
                         entry.validation_reason.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
}

void push_slot(json& map, const slot_entry_t& slot)
{
    json obj;
    obj["slot"] = slot.slot;
    obj["address"] = slot.target_va ? json(sa_format_address(slot.target_va)) : json(nullptr);
    obj["local_address"] = slot.local_va ? json(sa_format_address(slot.local_va)) : json(nullptr);
    obj["module"] = slot.module_name;
    obj["hint"] = slot.hint;
    obj["validated"] = slot.validated;
    obj["target_executable"] = slot.target_executable;
    obj["target_module_rva"] = slot.target_rva ? json(sa_format_address(slot.target_rva)) : json(nullptr);
    obj["local_prologue"] = slot.local_prologue;
    obj["target_prologue"] = slot.target_prologue;
    obj["target_prologue_bytes"] = slot.target_bytes;
    obj["api_family"] = slot.api_family.empty() ? json(nullptr) : json(slot.api_family);
    obj["role"] = slot.role.empty() ? json(nullptr) : json(slot.role);
    obj["abi_signature"] = slot.abi_signature.empty() ? json(nullptr) : json(slot.abi_signature);
    obj["validation_reason"] = slot.validation_reason.empty() ? json(nullptr) : json(slot.validation_reason);
    obj["evidence"] = {
        {"dummy_vtable_slot", slot.slot},
        {"local_va", slot.local_va ? json(sa_format_address(slot.local_va)) : json(nullptr)},
        {"target_va", slot.target_va ? json(sa_format_address(slot.target_va)) : json(nullptr)},
        {"target_module", slot.module_name},
        {"target_rva", slot.target_rva ? json(sa_format_address(slot.target_rva)) : json(nullptr)},
        {"target_executable_region", slot.target_executable},
        {"target_first_instruction", slot.target_prologue},
        {"target_first_32_bytes", slot.target_bytes},
        {"capability", slot.capability_evidence}
    };
    map[slot.name] = std::move(obj);
}

std::map<std::string, std::uint32_t> d3d11_context_slots()
{
    return {
        {"VSSetConstantBuffers", 7},
        {"PSSetConstantBuffers", 16},
        {"GSSetConstantBuffers", 22},
        {"HSSetConstantBuffers", 62},
        {"DSSetConstantBuffers", 66},
        {"CSSetConstantBuffers", 71},
        {"DrawIndexed", 12},
        {"Draw", 13},
        {"DrawIndexedInstanced", 20},
        {"DrawInstanced", 21},
        {"IASetVertexBuffers", 18}
    };
}

std::string dx_protection_name(std::uint32_t protect)
{
    switch (protect & 0xFFu)
    {
    case PAGE_NOACCESS: return "NOACCESS";
    case PAGE_READONLY: return "READONLY";
    case PAGE_READWRITE: return "READWRITE";
    case PAGE_WRITECOPY: return "WRITECOPY";
    case PAGE_EXECUTE: return "EXECUTE";
    case PAGE_EXECUTE_READ: return "EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
    default: return sa_format_address(protect);
    }
}

bool parse_first_address_param(const json& params, const std::vector<const char*>& keys, std::uint64_t& out)
{
    for (const char* key : keys)
    {
        if (parse_address_param(params, key, out) && out != 0)
            return true;
    }
    out = 0;
    return false;
}

std::vector<std::uint32_t> fixture_slot_indices_param(const json& params)
{
    std::vector<std::uint32_t> out;
    auto add_value = [&](const json& value) {
        std::uint64_t v = 0;
        if (parse_u64_value(value, v) && v <= 512)
        {
            const auto idx = static_cast<std::uint32_t>(v);
            if (std::find(out.begin(), out.end(), idx) == out.end())
                out.push_back(idx);
        }
    };
    for (const char* key : { "fixture_slot", "fixture_slot_index", "slot_index", "slot" })
    {
        auto it = params.find(key);
        if (it == params.end())
            continue;
        if (it->is_array())
        {
            for (const auto& value : *it)
                add_value(value);
        }
        else
        {
            add_value(*it);
        }
    }
    return out;
}

std::vector<std::string> fixture_slot_names_param(const json& params)
{
    std::vector<std::string> out;
    auto add_name = [&](std::string value) {
        value = trim_ascii(value);
        if (value.empty())
            return;
        if (std::find(out.begin(), out.end(), value) == out.end())
            out.push_back(std::move(value));
    };
    for (const char* key : { "fixture_slot_name", "slot_name", "method", "slot_method" })
    {
        auto it = params.find(key);
        if (it == params.end())
            continue;
        if (it->is_array())
        {
            for (const auto& value : *it)
            {
                if (value.is_string())
                    add_name(value.get<std::string>());
            }
        }
        else if (it->is_string())
        {
            add_name(it->get<std::string>());
        }
    }
    return out;
}

bool read_remote_u64_array(std::uint32_t pid, std::uint64_t address, std::uint32_t count, std::vector<std::uint64_t>& out, json& evidence)
{
    out.clear();
    evidence = json{{"address", address ? json(sa_format_address(address)) : json(nullptr)}, {"requested_entries", count}, {"read_ok", false}, {"entries_read", 0}};
    if (address == 0 || count == 0)
    {
        evidence["reason"] = "missing_address_or_count";
        return false;
    }
    count = std::min<std::uint32_t>(count, 512);
    std::vector<std::uint8_t> bytes;
    const std::size_t bytes_requested = static_cast<std::size_t>(count) * sizeof(std::uint64_t);
    evidence["bytes_requested"] = bytes_requested;
    const bool ok = read_bytes(pid, address, bytes_requested, bytes);
    const std::uint32_t entries_read = static_cast<std::uint32_t>(bytes.size() / sizeof(std::uint64_t));
    evidence["read_ok"] = ok && entries_read != 0;
    evidence["bytes_read"] = bytes.size();
    evidence["entries_read"] = entries_read;
    if (entries_read == 0)
    {
        evidence["reason"] = ok ? "empty_read" : "read_failed";
        return false;
    }
    out.resize(entries_read);
    std::memcpy(out.data(), bytes.data(), static_cast<std::size_t>(entries_read) * sizeof(std::uint64_t));
    return true;
}

std::string read_remote_string(std::uint32_t pid, std::uint64_t address, std::size_t max_len, bool& read_ok)
{
    read_ok = false;
    if (address == 0 || max_len == 0)
        return {};
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, address, max_len, bytes) || bytes.empty())
        return {};
    read_ok = true;
    const auto nul = std::find(bytes.begin(), bytes.end(), 0);
    const std::size_t len = static_cast<std::size_t>(nul - bytes.begin());
    return std::string(reinterpret_cast<const char*>(bytes.data()), len);
}

json module_owner_for_address(std::uint32_t pid, std::uint64_t address)
{
    auto mod = find_module_for_address(pid, address);
    if (!mod)
        return json{{"found", false}};
    json owner = module_json(*mod);
    owner["found"] = true;
    owner["end"] = sa_format_address(mod->base + static_cast<std::uint64_t>(mod->size));
    owner["rva"] = address >= mod->base ? json(sa_format_address(address - mod->base)) : json(nullptr);
    return owner;
}

json memory_region_for_address(std::uint32_t pid, std::uint64_t address, bool& region_ok)
{
    region_ok = false;
    driver_bridge::memory_region_t region{};
    if (address == 0 || !query_region(pid, address, region))
        return json{{"found", false}};
    region_ok = true;
    json out = region_json(region);
    out["found"] = true;
    out["protect_name"] = dx_protection_name(region.protect);
    out["committed"] = is_committed(region);
    out["readable"] = is_readable(region);
    out["writable"] = is_writable(region);
    out["executable"] = is_executable(region);
    out["guarded"] = is_guarded(region);
    return out;
}

json prologue_signature_evidence(std::uint32_t pid,
                                 std::uint64_t local_va,
                                 std::uint64_t target_va,
                                 const std::vector<std::uint8_t>& target_bytes,
                                 const AsmInstr& target_ins,
                                 bool& accepted,
                                 std::string& reason)
{
    accepted = prologue_bytes_plausible(target_bytes, reason);
    const std::string target_mnemonic = lower_ascii(target_ins.mnem);
    const bool decoded = !target_mnemonic.empty() && target_mnemonic != "db" && target_mnemonic != "??";
    if (accepted && (!decoded || target_mnemonic == "ret" || target_mnemonic == "int3" || target_mnemonic == "ud2" || target_mnemonic == "hlt"))
    {
        accepted = false;
        reason = decoded ? "terminal_or_trap_instruction" : "instruction_decode_failed";
    }

    std::vector<std::uint8_t> local_bytes;
    const bool local_read_ok = read_local_bytes(local_va, 32, local_bytes);
    const bool prefix8 = local_read_ok && bytes_prefix_match(local_bytes, target_bytes, 8);
    const bool prefix16 = local_read_ok && bytes_prefix_match(local_bytes, target_bytes, 16);
    local_owner_t local_owner = local_owner_for_address(local_va);
    const std::uint64_t rel_target = relative_branch_target(target_va, target_bytes);
    bool rel_region_ok = false;
    json rel_region = rel_target ? memory_region_for_address(pid, rel_target, rel_region_ok) : json(nullptr);
    json evidence;
    evidence["accepted"] = accepted;
    evidence["reason"] = reason;
    evidence["decoded"] = decoded;
    evidence["mnemonic"] = target_mnemonic.empty() ? json(nullptr) : json(target_mnemonic);
    evidence["instruction"] = disasm_text(target_ins);
    evidence["instruction_length"] = target_ins.len;
    evidence["is_branch"] = target_ins.is_branch;
    evidence["is_call"] = target_ins.is_call;
    evidence["is_ret"] = target_ins.is_ret;
    evidence["control_transfer_opcode"] = !target_bytes.empty() && branch_or_call_opcode(target_bytes[0]);
    evidence["relative_branch_target"] = rel_target ? json(sa_format_address(rel_target)) : json(nullptr);
    evidence["relative_branch_region"] = rel_region;
    evidence["target_first_32_bytes"] = bytes_to_hex(target_bytes, 32);
    evidence["local_read_ok"] = local_read_ok;
    evidence["local_first_32_bytes"] = local_read_ok ? json(bytes_to_hex(local_bytes, 32)) : json(nullptr);
    evidence["local_target_prefix8_match"] = local_read_ok ? json(prefix8) : json(nullptr);
    evidence["local_target_prefix16_match"] = local_read_ok ? json(prefix16) : json(nullptr);
    evidence["local_owner_module"] = local_owner.ok ? json(local_owner.module_name) : json(nullptr);
    evidence["local_owner_rva"] = local_owner.ok ? json(sa_format_address(local_owner.rva)) : json(nullptr);
    evidence["signature_strength"] = prefix16 ? "local_target_prefix16" : (prefix8 ? "local_target_prefix8" : (decoded ? "decoded_prologue" : "byte_screen_only"));
    return evidence;
}

tool_result_t find_device_vtable_static_fixture(const json& params, std::uint32_t pid, const std::string& api, std::uint64_t started_ms)
{
    std::uint64_t vtable_va = 0;
    if (!parse_first_address_param(params, { "fixture_vtable_va", "vtable_va" }, vtable_va))
    {
        json out{{"fixture_args_accepted", false}, {"reason", "fixture_vtable_va is required for static fixture discovery"}};
        return tool_result_t::error("fixture_vtable_va is required for static fixture discovery", out);
    }

    std::uint64_t slot_names_va = 0;
    std::uint64_t slot_addresses_va = 0;
    parse_first_address_param(params, { "fixture_slot_names_va", "slot_names_va" }, slot_names_va);
    parse_first_address_param(params, { "fixture_slot_addresses_va", "slot_addresses_va" }, slot_addresses_va);
    std::uint64_t slot_count_u64 = 0;
    if (params.contains("fixture_slot_count"))
        parse_u64_value(params["fixture_slot_count"], slot_count_u64);
    if (slot_count_u64 == 0 && params.contains("slot_count"))
        parse_u64_value(params["slot_count"], slot_count_u64);
    std::uint32_t slot_count = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(slot_count_u64 ? slot_count_u64 : 64, 1, 128));
    const std::string fixture_kind = string_param(params, "fixture_kind", "static_fixture");
    auto requested_indices = fixture_slot_indices_param(params);
    auto requested_names = fixture_slot_names_param(params);
    const auto d3d_slots = d3d11_context_slots();

    json names_read;
    json addresses_read;
    std::vector<std::uint64_t> name_ptrs;
    std::vector<std::uint64_t> compact_addresses;
    read_remote_u64_array(pid, slot_names_va, slot_names_va ? slot_count : 0, name_ptrs, names_read);
    read_remote_u64_array(pid, slot_addresses_va, slot_addresses_va ? slot_count : 0, compact_addresses, addresses_read);

    struct compact_slot_t
    {
        std::uint32_t compact_index = 0;
        std::uint32_t slot_index = 0;
        std::string name;
        std::uint64_t name_va = 0;
        std::uint64_t compact_address = 0;
        bool name_read_ok = false;
    };

    std::vector<compact_slot_t> compact_slots;
    const std::uint32_t compact_limit = std::max<std::uint32_t>(slot_count, static_cast<std::uint32_t>(std::max(name_ptrs.size(), compact_addresses.size())));
    for (std::uint32_t i = 0; i < compact_limit && i < 128; ++i)
    {
        compact_slot_t s;
        s.compact_index = i;
        s.slot_index = i;
        if (i < name_ptrs.size())
        {
            s.name_va = name_ptrs[i];
            s.name = read_remote_string(pid, s.name_va, 128, s.name_read_ok);
        }
        if (s.name.empty())
            s.name = "slot_" + std::to_string(i);
        auto known = d3d_slots.find(s.name);
        if (known != d3d_slots.end())
            s.slot_index = known->second;
        if (i < compact_addresses.size())
            s.compact_address = compact_addresses[i];
        compact_slots.push_back(std::move(s));
    }

    for (const std::string& name : requested_names)
    {
        auto known = d3d_slots.find(name);
        if (known != d3d_slots.end() && std::find(requested_indices.begin(), requested_indices.end(), known->second) == requested_indices.end())
            requested_indices.push_back(known->second);
    }

    auto slot_requested = [&](const compact_slot_t& slot) {
        if (requested_indices.empty() && requested_names.empty())
            return true;
        if (std::find(requested_indices.begin(), requested_indices.end(), slot.slot_index) != requested_indices.end())
            return true;
        const std::string slot_lower = lower_ascii(slot.name);
        for (const auto& name : requested_names)
        {
            if (slot_lower == lower_ascii(name))
                return true;
        }
        return false;
    };

    std::uint32_t max_slot_index = 0;
    bool have_candidate = false;
    for (const auto& s : compact_slots)
    {
        if (!slot_requested(s))
            continue;
        max_slot_index = std::max(max_slot_index, s.slot_index);
        have_candidate = true;
    }
    for (std::uint32_t idx : requested_indices)
    {
        max_slot_index = std::max(max_slot_index, idx);
        have_candidate = true;
    }
    if (!have_candidate)
        max_slot_index = slot_count > 0 ? slot_count - 1 : 0;
    max_slot_index = std::min<std::uint32_t>(max_slot_index, 511);

    json vtable_read;
    std::vector<std::uint64_t> vtable_entries;
    read_remote_u64_array(pid, vtable_va, max_slot_index + 1, vtable_entries, vtable_read);

    bool vtable_region_ok = false;
    const json vtable_region = memory_region_for_address(pid, vtable_va, vtable_region_ok);
    json slot_map = json::object();
    json slots = json::array();
    std::size_t resolved = 0;

    auto append_slot = [&](std::uint32_t slot_index, const std::string& slot_name, std::uint32_t compact_index, std::uint64_t name_va, bool name_read_ok, std::uint64_t compact_address) {
        const bool have_vtable_value = slot_index < vtable_entries.size();
        const std::uint64_t vtable_value = have_vtable_value ? vtable_entries[slot_index] : 0;
        const std::uint64_t slot_va = vtable_value ? vtable_value : compact_address;
        bool region_ok = false;
        json region = memory_region_for_address(pid, slot_va, region_ok);
        json owner = module_owner_for_address(pid, slot_va);
        const std::string owner_name = owner.value("name", std::string("unknown"));
        std::vector<std::uint8_t> prologue;
        std::string prologue_hex;
        std::string prologue_text = "unreadable";
        AsmInstr ins{};
        if (slot_va != 0 && read_bytes(pid, slot_va, 16, prologue) && !prologue.empty())
        {
            prologue_hex = bytes_to_hex(prologue, 16);
            ins = zydis_decode_one(prologue.data(), static_cast<int>(std::min<std::size_t>(prologue.size(), 16)), slot_va);
            prologue_text = classify_instruction_hint(ins) + ":" + disasm_text(ins);
        }
        const bool executable = region_ok && region.value("executable", false) && !region.value("guarded", false);
        bool prologue_ok = false;
        std::string prologue_reason;
        json prologue_evidence = prologue_signature_evidence(pid, 0, slot_va, prologue, ins, prologue_ok, prologue_reason);
        const bool decoded = prologue_text.find("unknown:") != 0 && prologue_text != "unreadable";
        const bool validated = slot_va != 0 && executable && prologue_ok && decoded;
        if (slot_va != 0)
            ++resolved;
        json row;
        row["slot"] = slot_index;
        row["slot_index"] = slot_index;
        row["slot_name"] = slot_name;
        row["compact_index"] = compact_index;
        row["address"] = slot_va ? json(sa_format_address(slot_va)) : json(nullptr);
        row["slot_va"] = slot_va ? json(sa_format_address(slot_va)) : json(nullptr);
        row["module"] = owner_name;
        row["module_owner"] = owner;
        row["memory_region"] = region;
        row["memory_protection"] = region.value("protect_name", std::string("unknown"));
        row["target_executable"] = executable;
        row["validated"] = validated;
        row["validation_reason"] = validated ? "validated" : (slot_va == 0 ? "target_address_unresolved" : (!executable ? "target_region_not_executable" : prologue_reason));
        row["target_prologue"] = prologue_text;
        row["target_prologue_bytes"] = prologue_hex;
        row["vtable_slot_entry_va"] = sa_format_address(vtable_va + static_cast<std::uint64_t>(slot_index) * sizeof(std::uint64_t));
        row["vtable_value"] = vtable_value ? json(sa_format_address(vtable_value)) : json(nullptr);
        row["fixture_address_array_value"] = compact_address ? json(sa_format_address(compact_address)) : json(nullptr);
        row["fixture_name_va"] = name_va ? json(sa_format_address(name_va)) : json(nullptr);
        row["fixture_name_read_ok"] = name_read_ok;
        row["vtable_read_value_available"] = have_vtable_value;
        row["vtable_matches_address_array"] = vtable_value != 0 && compact_address != 0 ? json(vtable_value == compact_address) : json(nullptr);
        row["evidence"] = json{{"fixture_kind", fixture_kind},
                                {"slot_index", slot_index},
                                {"slot_name", slot_name},
                                {"slot_va", slot_va ? json(sa_format_address(slot_va)) : json(nullptr)},
                                {"module_owner", owner},
                                {"memory_region", region},
                                {"memory_protection", region.value("protect_name", std::string("unknown"))},
                                {"vtable_slot_entry_va", sa_format_address(vtable_va + static_cast<std::uint64_t>(slot_index) * sizeof(std::uint64_t))},
                                {"vtable_value", vtable_value ? json(sa_format_address(vtable_value)) : json(nullptr)},
                                {"target_first_instruction", prologue_text},
                                {"target_first_16_bytes", prologue_hex},
                                {"target_prologue_validation", prologue_reason},
                                {"prologue_signature", prologue_evidence}};
        slots.push_back(row);
        slot_map[slot_name] = std::move(row);
    };

    std::vector<std::uint32_t> emitted_indices;
    for (const auto& s : compact_slots)
    {
        if (!slot_requested(s))
            continue;
        append_slot(s.slot_index, s.name, s.compact_index, s.name_va, s.name_read_ok, s.compact_address);
        emitted_indices.push_back(s.slot_index);
    }
    for (std::uint32_t idx : requested_indices)
    {
        if (std::find(emitted_indices.begin(), emitted_indices.end(), idx) != emitted_indices.end())
            continue;
        std::string name = "slot_" + std::to_string(idx);
        for (const auto& kv : d3d_slots)
        {
            if (kv.second == idx)
            {
                name = kv.first;
                break;
            }
        }
        append_slot(idx, name, idx, 0, false, 0);
    }

    json result;
    result["process_id"] = pid;
    result["api"] = api;
    result["fixture_static_mode"] = true;
    result["fixture_args_accepted"] = true;
    result["fixture_kind"] = fixture_kind;
    result["fixture_vtable_va"] = sa_format_address(vtable_va);
    result["fixture_slot_names_va"] = slot_names_va ? json(sa_format_address(slot_names_va)) : json(nullptr);
    result["fixture_slot_addresses_va"] = slot_addresses_va ? json(sa_format_address(slot_addresses_va)) : json(nullptr);
    result["fixture_slot_count"] = slot_count;
    result["requested_slot_indices"] = requested_indices;
    result["requested_slot_names"] = requested_names;
    result["vtable_read"] = vtable_read;
    result["vtable_read_status"] = vtable_read.value("read_ok", false) ? "ok" : "failed";
    result["vtable_region"] = vtable_region;
    result["slot_map"] = std::move(slot_map);
    result["slots"] = std::move(slots);
    result["count"] = result["slots"].size();
    result["resolved"] = resolved;
    result["names_array_read"] = names_read;
    result["addresses_array_read"] = addresses_read;
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("dx_hook",
                         "find_device_vtable static_fixture_exit pid=%u api=%s kind=%s vtable=%s read_ok=%d slots=%zu resolved=%zu elapsed_ms=%llu",
                         pid,
                         api.c_str(),
                         fixture_kind.c_str(),
                         sa_format_address(vtable_va).c_str(),
                         vtable_read.value("read_ok", false) ? 1 : 0,
                         result["slots"].size(),
                         resolved,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("DX static fixture vtable discovery completed", result);
}

std::size_t resolved_slot_count(const std::vector<slot_entry_t>& slots)
{
    std::size_t resolved = 0;
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0)
            ++resolved;
    }
    return resolved;
}

std::vector<slot_entry_t> discover_d3d11_from_live_context(std::uint32_t pid)
{
    const std::uint64_t started_ms = GetTickCount64();
    std::vector<slot_entry_t> slots;
    ID3D11Device* device = g_pd3dDevice;
    diag::log_tagged_fmt("dx_hook", "discover_d3d11_live enter pid=%u tid=%lu device=%p",
                         pid,
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         device);
    if (!device)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d11_live no_device pid=%u elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }

    device->AddRef();
    ID3D11DeviceContext* context = nullptr;
    diag::log_tagged_fmt("dx_hook", "discover_d3d11_live get_context_begin pid=%u device=%p", pid, device);
    device->GetImmediateContext(&context);
    diag::log_tagged_fmt("dx_hook", "discover_d3d11_live get_context_end pid=%u context=%p elapsed_ms=%llu",
                         pid,
                         context,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!context)
    {
        device->Release();
        diag::log_tagged_fmt("dx_hook", "discover_d3d11_live no_context pid=%u elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }

    auto vtable = *reinterpret_cast<std::uint64_t**>(context);
    diag::log_tagged_fmt("dx_hook", "discover_d3d11_live vtable pid=%u context=%p vtable=%p",
                         pid,
                         context,
                         vtable);
    if (vtable)
    {
        for (const auto& [name, index] : d3d11_context_slots())
        {
            if (dx_call_cancelled("discover_d3d11_live_slots", pid, started_ms))
                break;
            slot_entry_t entry;
            entry.name = name;
            entry.slot = index;
            entry.local_va = vtable[index];
            diag::log_tagged_fmt("dx_hook", "discover_d3d11_live slot_begin pid=%u name=%s index=%u local_va=%s",
                                 pid,
                                 entry.name.c_str(),
                                 entry.slot,
                                 sa_format_address(entry.local_va).c_str());
            entry.target_va = map_local_slot_to_target(pid, entry.name.c_str(), entry.slot, entry.local_va, "d3d11.dll", false, entry.module_name);
            finalize_slot(pid, entry);
            diag::log_tagged_fmt("dx_hook", "discover_d3d11_live slot_end pid=%u name=%s index=%u target_va=%s validated=%d hint=%s",
                                 pid,
                                 entry.name.c_str(),
                                 entry.slot,
                                 sa_format_address(entry.target_va).c_str(),
                                 entry.validated ? 1 : 0,
                                 entry.hint.c_str());
            slots.push_back(std::move(entry));
        }
    }
    context->Release();
    device->Release();
    diag::log_tagged_fmt("dx_hook", "discover_d3d11_live cleanup pid=%u context=%p device=%p slots=%zu resolved=%zu elapsed_ms=%llu",
                         pid,
                         context,
                         device,
                         slots.size(),
                         resolved_slot_count(slots),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return slots;
}

std::vector<slot_entry_t> discover_d3d11(std::uint32_t pid, bool allow_dummy_device = true)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 enter pid=%u tid=%lu allow_dummy_device=%d",
                         pid,
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         allow_dummy_device ? 1 : 0);
    std::vector<slot_entry_t> slots;
    auto live_slots = discover_d3d11_from_live_context(pid);
    if (dx_call_cancelled("discover_d3d11_after_live", pid, started_ms))
        return live_slots;
    if (!live_slots.empty() && resolved_slot_count(live_slots) != 0)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 live_exit pid=%u slots=%zu resolved=%zu elapsed_ms=%llu",
                             pid,
                             live_slots.size(),
                             resolved_slot_count(live_slots),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return live_slots;
    }
    if (!live_slots.empty())
        slots = std::move(live_slots);
    if (!allow_dummy_device)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 dummy_skipped pid=%u slots=%zu resolved=%zu elapsed_ms=%llu",
                             pid,
                             slots.size(),
                             resolved_slot_count(slots),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    if (dx_call_cancelled("discover_d3d11_before_load", pid, started_ms))
        return slots;
    SetLastError(ERROR_SUCCESS);
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 load_begin pid=%u module=d3d11.dll elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    HMODULE d3d11 = LoadLibraryA("d3d11.dll");
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 load_end pid=%u module=d3d11.dll base=%s gle=%lu elapsed_ms=%llu",
                         pid,
                         sa_format_address(reinterpret_cast<std::uint64_t>(d3d11)).c_str(),
                         static_cast<unsigned long>(GetLastError()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!d3d11)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 load_failed pid=%u gle=%lu elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    SetLastError(ERROR_SUCCESS);
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 proc_begin pid=%u proc=D3D11CreateDevice elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    auto create_device = reinterpret_cast<pfn_d3d11_create_device_t>(GetProcAddress(d3d11, "D3D11CreateDevice"));
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 proc_end pid=%u proc=D3D11CreateDevice addr=%p gle=%lu elapsed_ms=%llu",
                         pid,
                         reinterpret_cast<void*>(create_device),
                         static_cast<unsigned long>(GetLastError()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!create_device)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 proc_missing pid=%u gle=%lu elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    D3D_FEATURE_LEVEL level{};
    const std::uint64_t create_start_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 dummy_create_begin pid=%u driver_type=%u elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned>(D3D_DRIVER_TYPE_NULL),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    HRESULT hr = create_device(nullptr, D3D_DRIVER_TYPE_NULL, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &device, &level, &context);
    const std::uint64_t create_elapsed_ms = GetTickCount64() - create_start_ms;
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 dummy_create_end pid=%u hr=0x%08lX device=%p context=%p feature=0x%08X create_ms=%llu elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long>(hr),
                         device,
                         context,
                         static_cast<unsigned>(level),
                         static_cast<unsigned long long>(create_elapsed_ms),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (FAILED(hr) || !device || !context)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 create_failed pid=%u hr=0x%08lX device=%d context=%d create_ms=%llu elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long>(hr),
                             device ? 1 : 0,
                             context ? 1 : 0,
                             static_cast<unsigned long long>(create_elapsed_ms),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (context) context->Release();
        if (device) device->Release();
        return slots;
    }
    auto vtable = *reinterpret_cast<std::uint64_t**>(context);
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 dummy_vtable pid=%u context=%p vtable=%p",
                         pid,
                         context,
                         vtable);
    if (!vtable)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 dummy_vtable_missing pid=%u context=%p elapsed_ms=%llu",
                             pid,
                             context,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 cleanup_begin pid=%u context=%p device=%p",
                             pid,
                             context,
                             device);
        context->Release();
        device->Release();
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 exit pid=%u slots=%zu create_ms=%llu elapsed_ms=%llu",
                             pid,
                             slots.size(),
                             static_cast<unsigned long long>(create_elapsed_ms),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    slots.clear();
    for (const auto& [name, index] : d3d11_context_slots())
    {
        if (dx_call_cancelled("discover_d3d11_dummy_slots", pid, started_ms))
            break;
        slot_entry_t entry;
        entry.name = name;
        entry.slot = index;
        entry.local_va = vtable[index];
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 dummy_slot_begin pid=%u name=%s index=%u local_va=%s",
                             pid,
                             entry.name.c_str(),
                             entry.slot,
                             sa_format_address(entry.local_va).c_str());
        entry.target_va = map_local_slot_to_target(pid, entry.name.c_str(), entry.slot, entry.local_va, "d3d11.dll", true, entry.module_name);
        finalize_slot(pid, entry);
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 dummy_slot_end pid=%u name=%s index=%u target_va=%s validated=%d hint=%s",
                             pid,
                             entry.name.c_str(),
                             entry.slot,
                             sa_format_address(entry.target_va).c_str(),
                             entry.validated ? 1 : 0,
                             entry.hint.c_str());
        slots.push_back(std::move(entry));
    }
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 cleanup_begin pid=%u context=%p device=%p",
                         pid,
                         context,
                         device);
    context->Release();
    device->Release();
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 cleanup_end pid=%u elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    diag::log_tagged_fmt("dx_hook", "discover_d3d11 exit pid=%u slots=%zu create_ms=%llu elapsed_ms=%llu",
                         pid,
                         slots.size(),
                         static_cast<unsigned long long>(create_elapsed_ms),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return slots;
}

std::vector<slot_entry_t> discover_d3d12(std::uint32_t pid, bool allow_dummy_device = true)
{
    const std::uint64_t started_ms = GetTickCount64();
    std::vector<slot_entry_t> slots;
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 enter pid=%u tid=%lu allow_dummy_device=%d",
                         pid,
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         allow_dummy_device ? 1 : 0);
    if (!allow_dummy_device)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 dummy_skipped pid=%u elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 exit pid=%u slots=0 resolved=0 elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    if (dx_call_cancelled("discover_d3d12_before_load", pid, started_ms))
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 exit pid=%u slots=0 resolved=0 cancelled=1 elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    SetLastError(ERROR_SUCCESS);
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 load_begin pid=%u module=d3d12.dll elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    HMODULE d3d12 = LoadLibraryA("d3d12.dll");
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 load_end pid=%u module=d3d12.dll base=%s gle=%lu elapsed_ms=%llu",
                         pid,
                         sa_format_address(reinterpret_cast<std::uint64_t>(d3d12)).c_str(),
                         static_cast<unsigned long>(GetLastError()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!d3d12)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 load_failed pid=%u gle=%lu elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 exit pid=%u slots=0 resolved=0 elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    if (dx_call_cancelled("discover_d3d12_before_proc", pid, started_ms))
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 exit pid=%u slots=0 resolved=0 cancelled=1 elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    SetLastError(ERROR_SUCCESS);
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 proc_begin pid=%u proc=D3D12CreateDevice elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    auto create_device = reinterpret_cast<pfn_d3d12_create_device_t>(GetProcAddress(d3d12, "D3D12CreateDevice"));
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 proc_end pid=%u proc=D3D12CreateDevice addr=%p gle=%lu elapsed_ms=%llu",
                         pid,
                         reinterpret_cast<void*>(create_device),
                         static_cast<unsigned long>(GetLastError()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!create_device)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 proc_missing pid=%u gle=%lu elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 exit pid=%u slots=0 resolved=0 elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    ID3D12Device* device = nullptr;
    const std::uint64_t create_start_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 device_create_begin pid=%u feature=0x%08X elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned>(D3D_FEATURE_LEVEL_11_0),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    HRESULT hr = create_device(nullptr, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), reinterpret_cast<void**>(&device));
    const std::uint64_t create_elapsed_ms = GetTickCount64() - create_start_ms;
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 device_create_end pid=%u hr=0x%08lX device=%p create_ms=%llu elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long>(hr),
                         device,
                         static_cast<unsigned long long>(create_elapsed_ms),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (FAILED(hr) || !device)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 create_failed pid=%u hr=0x%08lX device=%d elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long>(hr),
                             device ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 exit pid=%u slots=0 resolved=0 elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    if (dx_call_cancelled("discover_d3d12_after_device", pid, started_ms))
    {
        device->Release();
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 exit pid=%u slots=0 resolved=0 cancelled=1 elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    ID3D12CommandAllocator* alloc = nullptr;
    ID3D12GraphicsCommandList* list = nullptr;
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 allocator_create_begin pid=%u elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    hr = device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, __uuidof(ID3D12CommandAllocator), reinterpret_cast<void**>(&alloc));
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 allocator_create_end pid=%u hr=0x%08lX alloc=%p elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long>(hr),
                         alloc,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (SUCCEEDED(hr) && alloc)
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 command_list_create_begin pid=%u elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        hr = device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, alloc, nullptr, __uuidof(ID3D12GraphicsCommandList), reinterpret_cast<void**>(&list));
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 command_list_create_end pid=%u hr=0x%08lX list=%p elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long>(hr),
                             list,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
    }
    if (SUCCEEDED(hr) && list)
    {
        auto vtable = *reinterpret_cast<std::uint64_t**>(list);
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 vtable pid=%u list=%p vtable=%p elapsed_ms=%llu",
                             pid,
                             list,
                             vtable,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        std::map<std::string, std::uint32_t> wanted = {
            {"DrawInstanced", 12},
            {"DrawIndexedInstanced", 13},
            {"Dispatch", 14},
            {"SetGraphicsRootConstantBufferView", 38},
            {"IASetVertexBuffers", 44},
            {"OMSetRenderTargets", 46}
        };
        for (const auto& [name, index] : wanted)
        {
            if (dx_call_cancelled("discover_d3d12_slots", pid, started_ms))
                break;
            slot_entry_t entry;
            entry.name = name;
            entry.slot = index;
            entry.local_va = vtable[index];
            diag::log_tagged_fmt("dx_hook", "discover_d3d12 slot_begin pid=%u name=%s index=%u local_va=%s",
                                 pid,
                                 entry.name.c_str(),
                                 entry.slot,
                                 sa_format_address(entry.local_va).c_str());
            entry.target_va = map_local_slot_to_target(pid, entry.name.c_str(), entry.slot, entry.local_va, "d3d12.dll", true, entry.module_name);
            finalize_slot(pid, entry);
            diag::log_tagged_fmt("dx_hook", "discover_d3d12 slot_end pid=%u name=%s index=%u target_va=%s validated=%d hint=%s",
                                 pid,
                                 entry.name.c_str(),
                                 entry.slot,
                                 sa_format_address(entry.target_va).c_str(),
                                 entry.validated ? 1 : 0,
                                 entry.hint.c_str());
            slots.push_back(std::move(entry));
        }
    }
    else
    {
        diag::log_tagged_fmt("dx_hook", "discover_d3d12 command_list_unavailable pid=%u hr=0x%08lX alloc=%p list=%p elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long>(hr),
                             alloc,
                             list,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
    }
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 cleanup_begin pid=%u list=%p alloc=%p device=%p",
                         pid,
                         list,
                         alloc,
                         device);
    if (list) list->Release();
    if (alloc) alloc->Release();
    device->Release();
    diag::log_tagged_fmt("dx_hook", "discover_d3d12 exit pid=%u slots=%zu resolved=%zu elapsed_ms=%llu",
                         pid,
                         slots.size(),
                         resolved_slot_count(slots),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return slots;
}

std::vector<slot_entry_t> discover_dxgi_present(std::uint32_t pid, bool allow_dummy_swapchain = true)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present enter pid=%u tid=%lu allow_dummy_swapchain=%d",
                         pid,
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         allow_dummy_swapchain ? 1 : 0);
    std::vector<slot_entry_t> slots;
    if (!allow_dummy_swapchain)
    {
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present dummy_skipped pid=%u elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present exit pid=%u local_va=0x0 target_va=0x0 hint=dummy_skipped elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    if (dx_call_cancelled("discover_dxgi_present_before_load", pid, started_ms))
    {
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present exit pid=%u local_va=0x0 target_va=0x0 hint=cancelled elapsed_ms=%llu",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return slots;
    }
    SetLastError(ERROR_SUCCESS);
    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present load_begin pid=%u module=d3d11.dll elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    HMODULE d3d11 = LoadLibraryA("d3d11.dll");
    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present load_end pid=%u module=d3d11.dll base=%s gle=%lu elapsed_ms=%llu",
                         pid,
                         sa_format_address(reinterpret_cast<std::uint64_t>(d3d11)).c_str(),
                         static_cast<unsigned long>(GetLastError()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    SetLastError(ERROR_SUCCESS);
    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present proc_begin pid=%u proc=D3D11CreateDeviceAndSwapChain elapsed_ms=%llu",
                         pid,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    auto create_swap_chain = d3d11 ? reinterpret_cast<pfn_d3d11_create_device_and_swap_chain_t>(GetProcAddress(d3d11, "D3D11CreateDeviceAndSwapChain")) : nullptr;
    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present proc_end pid=%u proc=D3D11CreateDeviceAndSwapChain addr=%p gle=%lu elapsed_ms=%llu",
                         pid,
                         reinterpret_cast<void*>(create_swap_chain),
                         static_cast<unsigned long>(GetLastError()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    slot_entry_t entry;
    entry.name = "IDXGISwapChain::Present";
    entry.slot = 8;
    entry.module_name = "dxgi.dll";
    if (create_swap_chain)
    {
        if (dx_call_cancelled("discover_dxgi_present_before_window", pid, started_ms))
        {
            diag::log_tagged_fmt("dx_hook", "discover_dxgi_present exit pid=%u local_va=0x0 target_va=0x0 hint=cancelled elapsed_ms=%llu",
                                 pid,
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return slots;
        }
        const char* cls = "AiDA_RE_DummySwapChainWindow";
        WNDCLASSA wc{};
        wc.lpfnWndProc = DefWindowProcA;
        wc.hInstance = GetModuleHandleA(nullptr);
        wc.lpszClassName = cls;
        SetLastError(ERROR_SUCCESS);
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present register_class_begin pid=%u class=%s hinst=%p",
                             pid,
                             cls,
                             wc.hInstance);
        const ATOM atom = RegisterClassA(&wc);
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present register_class_end pid=%u class=%s atom=%u gle=%lu elapsed_ms=%llu",
                             pid,
                             cls,
                             static_cast<unsigned>(atom),
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        SetLastError(ERROR_SUCCESS);
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present window_create_begin pid=%u class=%s elapsed_ms=%llu",
                             pid,
                             cls,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        HWND hwnd = CreateWindowExA(0, cls, cls, WS_OVERLAPPEDWINDOW, 0, 0, 16, 16, nullptr, nullptr, wc.hInstance, nullptr);
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present window_create_end pid=%u hwnd=%p gle=%lu elapsed_ms=%llu",
                             pid,
                             hwnd,
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (hwnd)
        {
            DXGI_SWAP_CHAIN_DESC desc{};
            desc.BufferCount = 1;
            desc.BufferDesc.Width = 16;
            desc.BufferDesc.Height = 16;
            desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            desc.OutputWindow = hwnd;
            desc.SampleDesc.Count = 1;
            desc.Windowed = TRUE;
            desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
            IDXGISwapChain* swap = nullptr;
            ID3D11Device* device = nullptr;
            ID3D11DeviceContext* context = nullptr;
            D3D_FEATURE_LEVEL level{};
            const D3D_DRIVER_TYPE drivers[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP, D3D_DRIVER_TYPE_REFERENCE};
            for (D3D_DRIVER_TYPE driver_type : drivers)
            {
                if (dx_call_cancelled("discover_dxgi_present_create_loop", pid, started_ms))
                    break;
                const std::uint64_t create_start_ms = GetTickCount64();
                diag::log_tagged_fmt("dx_hook", "discover_dxgi_present create_begin pid=%u driver_type=%u hwnd=%p elapsed_ms=%llu",
                                     pid,
                                     static_cast<unsigned>(driver_type),
                                     hwnd,
                                     static_cast<unsigned long long>(GetTickCount64() - started_ms));
                HRESULT hr = create_swap_chain(nullptr, driver_type, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &desc, &swap, &device, &level, &context);
                diag::log_tagged_fmt("dx_hook", "discover_dxgi_present create_attempt pid=%u driver_type=%u hr=0x%08lX swap=%d elapsed_ms=%llu",
                                     pid,
                                     static_cast<unsigned>(driver_type),
                                     static_cast<unsigned long>(hr),
                                     swap ? 1 : 0,
                                     static_cast<unsigned long long>(GetTickCount64() - create_start_ms));
                if (SUCCEEDED(hr) && swap)
                    break;
                if (context) { context->Release(); context = nullptr; }
                if (device) { device->Release(); device = nullptr; }
                if (swap) { swap->Release(); swap = nullptr; }
            }
            if (swap)
            {
                auto vtable = *reinterpret_cast<std::uint64_t**>(swap);
                diag::log_tagged_fmt("dx_hook", "discover_dxgi_present vtable pid=%u swap=%p vtable=%p slot=%u",
                                     pid,
                                     swap,
                                     vtable,
                                     entry.slot);
                if (vtable)
                {
                    entry.local_va = vtable[8];
                    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present slot_map_begin pid=%u local_va=%s module=dxgi.dll",
                                         pid,
                                         sa_format_address(entry.local_va).c_str());
                    entry.target_va = map_local_slot_to_target(pid, entry.name.c_str(), entry.slot, entry.local_va, "dxgi.dll", true, entry.module_name);
                    finalize_slot(pid, entry);
                    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present slot_map_end pid=%u local_va=%s target_va=%s validated=%d hint=%s",
                                         pid,
                                         sa_format_address(entry.local_va).c_str(),
                                         sa_format_address(entry.target_va).c_str(),
                                         entry.validated ? 1 : 0,
                                         entry.hint.c_str());
                }
                else
                {
                    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present vtable_missing pid=%u swap=%p elapsed_ms=%llu",
                                         pid,
                                         swap,
                                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
                }
            }
            diag::log_tagged_fmt("dx_hook", "discover_dxgi_present cleanup_com_begin pid=%u context=%p device=%p swap=%p",
                                 pid,
                                 context,
                                 device,
                                 swap);
            if (context) context->Release();
            if (device) device->Release();
            if (swap) swap->Release();
            diag::log_tagged_fmt("dx_hook", "discover_dxgi_present cleanup_window_begin pid=%u hwnd=%p", pid, hwnd);
            DestroyWindow(hwnd);
            diag::log_tagged_fmt("dx_hook", "discover_dxgi_present cleanup_window_end pid=%u hwnd=%p gle=%lu elapsed_ms=%llu",
                                 pid,
                                 hwnd,
                                 static_cast<unsigned long>(GetLastError()),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
        }
        SetLastError(ERROR_SUCCESS);
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present unregister_class_begin pid=%u class=%s hinst=%p",
                             pid,
                             cls,
                             wc.hInstance);
        const BOOL unregistered = UnregisterClassA(cls, wc.hInstance);
        diag::log_tagged_fmt("dx_hook", "discover_dxgi_present unregister_class_end pid=%u class=%s ok=%d gle=%lu elapsed_ms=%llu",
                             pid,
                             cls,
                             unregistered ? 1 : 0,
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
    }
    if (entry.local_va == 0 || entry.target_va == 0)
        entry.hint = "dummy_swapchain_present_unavailable";
    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present exit pid=%u local_va=%s target_va=%s hint=%s elapsed_ms=%llu",
                         pid,
                         sa_format_address(entry.local_va).c_str(),
                         sa_format_address(entry.target_va).c_str(),
                         entry.hint.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    slots.push_back(std::move(entry));
    return slots;
}

json scan_qword_references(std::uint32_t pid, std::uint64_t target, std::size_t limit, std::size_t max_regions, const char* phase)
{
    const std::uint64_t started_ms = GetTickCount64();
    json refs = json::array();
    if (target == 0 || limit == 0)
        return refs;
    std::size_t scanned = 0;
    for (const auto& region : regions_for(pid, 2048))
    {
        if (dx_call_cancelled(phase, pid, started_ms))
            break;
        if (refs.size() >= limit || scanned >= max_regions)
            break;
        if (!is_readable(region) || is_executable(region) || is_guarded(region) || region.size < sizeof(std::uint64_t))
            continue;
        if (region.type != MEM_PRIVATE && region.type != MEM_MAPPED && region.type != MEM_IMAGE)
            continue;
        ++scanned;
        std::vector<std::uint8_t> bytes;
        const std::size_t read_size = static_cast<std::size_t>(std::min<std::uint64_t>(region.size, 128ull * 1024ull));
        if (!read_bytes(pid, region.base, read_size, bytes) || bytes.size() < sizeof(std::uint64_t))
            continue;
        const std::size_t aligned = bytes.size() & ~static_cast<std::size_t>(7);
        for (std::size_t off = 0; off + sizeof(std::uint64_t) <= aligned && refs.size() < limit; off += sizeof(std::uint64_t))
        {
            std::uint64_t value = 0;
            std::memcpy(&value, bytes.data() + off, sizeof(value));
            if (value != target)
                continue;
            json row;
            row["slot_va"] = sa_format_address(region.base + off);
            row["value"] = sa_format_address(value);
            row["region"] = region_json(region);
            row["writable"] = is_writable(region);
            refs.push_back(std::move(row));
        }
    }
    diag::log_tagged_fmt("dx_hook", "scan_qword_references pid=%u target=%s refs=%zu scanned_regions=%zu max_regions=%zu elapsed_ms=%llu",
                         pid,
                         sa_format_address(target).c_str(),
                         refs.size(),
                         scanned,
                         max_regions,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return refs;
}

std::vector<slot_entry_t> discover_vulkan(std::uint32_t pid, bool allow_local_load = true)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "discover_vulkan enter pid=%u tid=%lu allow_local_load=%d",
                         pid,
                         static_cast<unsigned long>(GetCurrentThreadId()),
                         allow_local_load ? 1 : 0);
    std::vector<slot_entry_t> slots;
    auto target = find_module_by_name(pid, "vulkan-1.dll");
    diag::log_tagged_fmt("dx_hook", "discover_vulkan target_module pid=%u loaded=%d base=%s size=%llu elapsed_ms=%llu",
                         pid,
                         target ? 1 : 0,
                         target ? sa_format_address(target->base).c_str() : "0x0",
                         target ? static_cast<unsigned long long>(target->size) : 0ull,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    HMODULE vulkan = reinterpret_cast<HMODULE>(module_base_local("vulkan-1.dll", allow_local_load));
    if (!vulkan && dx_call_cancelled("discover_vulkan_load", pid, started_ms))
        return slots;
    const char* names[] = {"vkQueuePresentKHR", "vkCmdDraw", "vkCmdDrawIndexed", "vkGetDeviceProcAddr", "vkGetInstanceProcAddr"};
    for (const char* name : names)
    {
        if (dx_call_cancelled("discover_vulkan_exports", pid, started_ms))
            break;
        slot_entry_t entry;
        entry.name = name;
        entry.module_name = "vulkan-1.dll";
        SetLastError(ERROR_SUCCESS);
        diag::log_tagged_fmt("dx_hook", "discover_vulkan proc_begin pid=%u export=%s elapsed_ms=%llu",
                             pid,
                             name,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        entry.local_va = vulkan ? reinterpret_cast<std::uint64_t>(GetProcAddress(vulkan, name)) : 0;
        diag::log_tagged_fmt("dx_hook", "discover_vulkan proc_end pid=%u export=%s local_va=%s gle=%lu elapsed_ms=%llu",
                             pid,
                             name,
                             sa_format_address(entry.local_va).c_str(),
                             static_cast<unsigned long>(GetLastError()),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (target)
        {
            entry.target_va = driver_bridge::resolve_export_for(pid, target->base, name);
            entry.module_name = "vulkan-1.dll";
            if (entry.target_va == 0 && entry.local_va != 0)
                entry.target_va = map_local_slot_to_target(pid, entry.name.c_str(), entry.slot, entry.local_va, "vulkan-1.dll", allow_local_load, entry.module_name);
        }
        else
        {
            entry.target_va = entry.local_va != 0 ? map_local_slot_to_target(pid, entry.name.c_str(), entry.slot, entry.local_va, "vulkan-1.dll", allow_local_load, entry.module_name) : 0;
        }
        if (target)
        {
            finalize_slot(pid, entry);
            if (entry.target_va != 0 && (entry.role == "draw" || entry.role == "present"))
            {
                json refs = scan_qword_references(pid, entry.target_va, 16, 96, "discover_vulkan_dispatch_refs");
                const std::size_t ref_count = refs.size();
                entry.capability_evidence["dispatch_pointer_references"] = std::move(refs);
                entry.capability_evidence["dispatch_pointer_reference_count"] = ref_count;
                entry.capability_evidence["target_kind"] = "vulkan_loader_export_or_layer_trampoline";
                entry.capability_evidence["loader_export_hookable"] = entry.target_va != 0;
                entry.capability_evidence["loader_export_unproven"] = true;
                entry.capability_evidence["device_dispatch_target_proven"] = false;
                entry.capability_evidence["live_dispatch_target_proof"] = nullptr;
                entry.capability_evidence["dispatch_reference_semantics"] = "diagnostic_qword_references_not_live_dispatch_table_proof";
                entry.capability_evidence["device_dispatch_limit"] = "no live VkDevice/VkCommandBuffer dispatch table target was supplied or validated";
                entry.validated = false;
                entry.validation_reason = "vulkan_live_dispatch_target_unproven";
                entry.capability_evidence["validation_reason"] = entry.validation_reason;
            }
            else if (entry.target_va != 0 && entry.role == "proc_addr")
            {
                entry.capability_evidence["target_kind"] = "vulkan_proc_address_resolver_export";
                entry.capability_evidence["resolver_export"] = true;
                entry.capability_evidence["loader_export_unproven"] = true;
                entry.capability_evidence["device_dispatch_target_proven"] = false;
                entry.capability_evidence["device_dispatch_limit"] = "resolver export is not a live draw/present dispatch target";
                entry.validated = false;
                entry.validation_reason = "vulkan_proc_address_export_unproven";
                entry.capability_evidence["validation_reason"] = entry.validation_reason;
            }
        }
        else
        {
            entry.hint = "vulkan_not_loaded_in_target";
            entry.validation_reason = "vulkan_not_loaded_in_target";
            entry.capability_evidence["target_kind"] = "unavailable";
            entry.capability_evidence["validation_reason"] = entry.validation_reason;
        }
        diag::log_tagged_fmt("dx_hook", "discover_vulkan slot_end pid=%u export=%s local_va=%s target_va=%s validated=%d hint=%s",
                             pid,
                             entry.name.c_str(),
                             sa_format_address(entry.local_va).c_str(),
                             sa_format_address(entry.target_va).c_str(),
                             entry.validated ? 1 : 0,
                             entry.hint.c_str());
        slots.push_back(std::move(entry));
    }
    diag::log_tagged_fmt("dx_hook", "discover_vulkan exit pid=%u slots=%zu resolved=%zu elapsed_ms=%llu",
                         pid,
                         slots.size(),
                         resolved_slot_count(slots),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return slots;
}

json slots_to_result(std::uint32_t pid, const std::string& api, const std::vector<slot_entry_t>& slots)
{
    json slot_map = json::object();
    std::size_t resolved = 0;
    std::size_t validated = 0;
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0)
            ++resolved;
        if (slot.validated)
            ++validated;
        push_slot(slot_map, slot);
    }
    json result;
    result["process_id"] = pid;
    result["api"] = api;
    result["slot_map"] = std::move(slot_map);
    result["count"] = result["slot_map"].size();
    result["resolved_count"] = resolved;
    result["validated_count"] = validated;
    result["discovery_status"] = slots.empty() ? "no_targets_resolved" : (validated != 0 ? "validated_targets_available" : (resolved != 0 ? "resolved_but_unvalidated" : "no_targets_resolved"));
    return result;
}

std::vector<slot_entry_t> discover_api(std::uint32_t pid, const std::string& api, bool allow_dummy_device = true)
{
    if (api == "d3d11") return discover_d3d11(pid, allow_dummy_device);
    if (api == "d3d12") return discover_d3d12(pid, allow_dummy_device);
    if (api == "dxgi") return discover_dxgi_present(pid, allow_dummy_device);
    if (api == "vulkan") return discover_vulkan(pid, allow_dummy_device);
    if (api != "auto") return {};
    std::vector<slot_entry_t> out;
    if (target_module_loaded(pid, "d3d11.dll"))
    {
        auto d3d11 = discover_d3d11(pid, allow_dummy_device);
        out.insert(out.end(), d3d11.begin(), d3d11.end());
    }
    if (target_module_loaded(pid, "d3d12.dll"))
    {
        auto d3d12 = discover_d3d12(pid, allow_dummy_device);
        out.insert(out.end(), d3d12.begin(), d3d12.end());
    }
    if (target_module_loaded(pid, "dxgi.dll"))
    {
        auto dxgi = discover_dxgi_present(pid, allow_dummy_device);
        out.insert(out.end(), dxgi.begin(), dxgi.end());
    }
    if (target_module_loaded(pid, "vulkan-1.dll"))
    {
        auto vk = discover_vulkan(pid, allow_dummy_device);
        out.insert(out.end(), vk.begin(), vk.end());
    }
    return out;
}

std::optional<slot_entry_t> export_marker_target(std::uint32_t pid,
                                                 const std::string& module_name,
                                                 const std::string& export_name,
                                                 const std::string& action)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "export_marker enter pid=%u action=%s module=%s export=%s",
                         pid,
                         action.c_str(),
                         module_name.c_str(),
                         export_name.c_str());
    auto module = find_module_by_name(pid, module_name);
    if (!module)
    {
        diag::log_tagged_fmt("dx_hook", "export_marker module_missing pid=%u module=%s export=%s elapsed_ms=%llu",
                             pid,
                             module_name.c_str(),
                             export_name.c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return std::nullopt;
    }
    const std::uint64_t target = driver_bridge::resolve_export_for(pid, module->base, export_name.c_str());
    diag::log_tagged_fmt("dx_hook", "export_marker resolved pid=%u module=%s base=%s end=%s export=%s target=%s elapsed_ms=%llu",
                         pid,
                         module_name.c_str(),
                         sa_format_address(module->base).c_str(),
                         sa_format_address(module->base + static_cast<std::uint64_t>(module->size)).c_str(),
                         export_name.c_str(),
                         sa_format_address(target).c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (target == 0)
        return std::nullopt;
    slot_entry_t entry;
    entry.name = export_name;
    entry.slot = 0;
    entry.target_va = target;
    entry.module_name = module_name;
    finalize_slot(pid, entry);
    entry.hint = "snapshot_export_marker:" + export_name + ":" + entry.target_prologue;
    diag::log_tagged_fmt("dx_hook", "export_marker exit pid=%u action=%s module=%s export=%s target=%s validated=%d elapsed_ms=%llu",
                         pid,
                         action.c_str(),
                         module_name.c_str(),
                         export_name.c_str(),
                         sa_format_address(entry.target_va).c_str(),
                         entry.validated ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return entry;
}

std::optional<slot_entry_t> snapshot_marker_target(std::uint32_t pid, const std::string& api, const std::string& action)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "snapshot_marker enter pid=%u api=%s action=%s",
                         pid,
                         api.c_str(),
                         action.c_str());
    std::vector<std::pair<std::string, std::string>> candidates;
    if (action == "present")
    {
        candidates.push_back({"dxgi.dll", "CreateDXGIFactory2"});
        candidates.push_back({"dxgi.dll", "CreateDXGIFactory1"});
        candidates.push_back({"dxgi.dll", "CreateDXGIFactory"});
        candidates.push_back({"d3d11.dll", "D3D11CreateDevice"});
    }
    else
    {
        candidates.push_back({"d3d11.dll", "D3D11CreateDevice"});
    }
    if (api == "vulkan" && action == "present")
        candidates.insert(candidates.begin(), {"vulkan-1.dll", "vkQueuePresentKHR"});
    if (api == "vulkan" && action == "draw")
    {
        candidates.clear();
        candidates.push_back({"vulkan-1.dll", "vkCmdDrawIndexed"});
        candidates.push_back({"vulkan-1.dll", "vkCmdDraw"});
    }
    for (const auto& candidate : candidates)
    {
        auto target = export_marker_target(pid, candidate.first, candidate.second, action);
        if (target && target->target_va != 0)
        {
            diag::log_tagged_fmt("dx_hook", "snapshot_marker exit pid=%u api=%s action=%s module=%s export=%s target=%s elapsed_ms=%llu",
                                 pid,
                                 api.c_str(),
                                 action.c_str(),
                                 candidate.first.c_str(),
                                 candidate.second.c_str(),
                                 sa_format_address(target->target_va).c_str(),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return target;
        }
    }
    diag::log_tagged_fmt("dx_hook", "snapshot_marker miss pid=%u api=%s action=%s elapsed_ms=%llu",
                         pid,
                         api.c_str(),
                         action.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return std::nullopt;
}

std::optional<slot_entry_t> choose_hook_target(std::uint32_t pid, const std::string& api, const std::string& action, bool snapshot_only = false)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "choose_hook_target enter pid=%u api=%s action=%s snapshot_only=%d",
                         pid,
                         api.c_str(),
                         action.c_str(),
                         snapshot_only ? 1 : 0);
    if (snapshot_only)
    {
        auto marker = snapshot_marker_target(pid, api, action);
        if (marker && marker->target_va != 0)
        {
            diag::log_tagged_fmt("dx_hook", "choose_hook_target snapshot_marker pid=%u api=%s action=%s target=%s elapsed_ms=%llu",
                                 pid,
                                 api.c_str(),
                                 action.c_str(),
                                 sa_format_address(marker->target_va).c_str(),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return marker;
        }
        diag::log_tagged_fmt("dx_hook", "choose_hook_target snapshot_marker_missing pid=%u api=%s action=%s elapsed_ms=%llu",
                             pid,
                             api.c_str(),
                             action.c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return std::nullopt;
    }
    if (action == "present")
    {
        auto present = api == "vulkan" ? discover_vulkan(pid, true) : discover_dxgi_present(pid, true);
        if (!present.empty())
        {
            for (const auto& candidate : present)
            {
                if (candidate.target_va == 0 || candidate.role != "present" || !candidate.validated)
                    continue;
                diag::log_tagged_fmt("dx_hook", "choose_hook_target present_validated pid=%u api=%s name=%s target=%s elapsed_ms=%llu",
                                     pid,
                                     api.c_str(),
                                     candidate.name.c_str(),
                                     sa_format_address(candidate.target_va).c_str(),
                                     static_cast<unsigned long long>(GetTickCount64() - started_ms));
                return candidate;
            }
            for (const auto& candidate : present)
            {
                if (candidate.target_va == 0 || candidate.role != "present")
                    continue;
                diag::log_tagged_fmt("dx_hook", "choose_hook_target present_exact pid=%u api=%s name=%s target=%s elapsed_ms=%llu",
                                     pid,
                                     api.c_str(),
                                     candidate.name.c_str(),
                                     sa_format_address(candidate.target_va).c_str(),
                                     static_cast<unsigned long long>(GetTickCount64() - started_ms));
                return candidate;
            }
        }
    }
    auto slots = discover_api(pid, api, true);
    diag::log_tagged_fmt("dx_hook", "choose_hook_target slots pid=%u api=%s action=%s slots=%zu resolved=%zu elapsed_ms=%llu",
                         pid,
                         api.c_str(),
                         action.c_str(),
                         slots.size(),
                         resolved_slot_count(slots),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    for (const auto& slot : slots)
    {
        if (slot.target_va == 0 || !slot.validated)
            continue;
        if (action == "draw" && slot.role == "draw")
        {
            diag::log_tagged_fmt("dx_hook", "choose_hook_target draw_validated pid=%u name=%s target=%s elapsed_ms=%llu",
                                 pid,
                                 slot.name.c_str(),
                                 sa_format_address(slot.target_va).c_str(),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return slot;
        }
        if (action == "present" && slot.role == "present")
        {
            diag::log_tagged_fmt("dx_hook", "choose_hook_target present_validated_slot pid=%u name=%s target=%s elapsed_ms=%llu",
                                 pid,
                                 slot.name.c_str(),
                                 sa_format_address(slot.target_va).c_str(),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return slot;
        }
    }
    for (const auto& slot : slots)
    {
        if (slot.target_va == 0)
            continue;
        if (action == "draw" && slot.role == "draw")
        {
            diag::log_tagged_fmt("dx_hook", "choose_hook_target draw_slot pid=%u name=%s target=%s elapsed_ms=%llu",
                                 pid,
                                 slot.name.c_str(),
                                 sa_format_address(slot.target_va).c_str(),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return slot;
        }
        if (action == "present" && slot.role == "present")
        {
            diag::log_tagged_fmt("dx_hook", "choose_hook_target present_slot pid=%u name=%s target=%s elapsed_ms=%llu",
                                 pid,
                                 slot.name.c_str(),
                                 sa_format_address(slot.target_va).c_str(),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return slot;
        }
    }
    diag::log_tagged_fmt("dx_hook", "choose_hook_target miss pid=%u api=%s action=%s elapsed_ms=%llu",
                         pid,
                         api.c_str(),
                         action.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return std::nullopt;
}

json dx_record_json(const store::dx_hook_record_t& record)
{
    json out;
    out["hook_id"] = record.id;
    out["process_id"] = record.pid;
    out["api"] = record.api;
    out["action"] = record.action;
    out["target_va"] = sa_format_address(record.target_va);
    out["hw_slot"] = record.hw_slot;
    out["capture_cbuffers"] = record.capture_cbuffers;
    out["capture_vertex_buffers"] = record.capture_vertex_buffers;
    out["max_captures"] = record.max_captures;
    out["created_ms"] = record.created_ms;
    out["thread_count"] = record.tids.size();
    out["capture_count"] = record.captures.size();
    out["positive_capture_count"] = record.captures.size();
    out["captures"] = record.captures;
    return out;
}

struct matrix_eval_t
{
    bool plausible = false;
    bool view_like = false;
    bool projection_like = false;
    bool viewproj_like = false;
    double score = 0.0;
    double determinant = 0.0;
    double orthogonality_error = 1.0;
    double row_orthogonality_error = 1.0;
    double column_orthogonality_error = 1.0;
    double inverse_residual = 1.0;
    double row_translation_abs = 0.0;
    double column_translation_abs = 0.0;
    double identity_error = 1.0;
    bool static_null_view = false;
    std::string reason;
    std::string type;
    std::string orientation;
};

double vec3_norm(float a, float b, float c)
{
    return std::sqrt(static_cast<double>(a) * a + static_cast<double>(b) * b + static_cast<double>(c) * c);
}

double vec3_dot(float ax, float ay, float az, float bx, float by, float bz)
{
    return static_cast<double>(ax) * bx + static_cast<double>(ay) * by + static_cast<double>(az) * bz;
}

double det3x3_rows(const float* f)
{
    return static_cast<double>(f[0]) * (static_cast<double>(f[5]) * f[10] - static_cast<double>(f[6]) * f[9]) -
           static_cast<double>(f[1]) * (static_cast<double>(f[4]) * f[10] - static_cast<double>(f[6]) * f[8]) +
           static_cast<double>(f[2]) * (static_cast<double>(f[4]) * f[9] - static_cast<double>(f[5]) * f[8]);
}

double identity_matrix_error4x4(const float* f)
{
    double error = 0.0;
    for (int i = 0; i < 16; ++i)
    {
        const double expected = (i == 0 || i == 5 || i == 10 || i == 15) ? 1.0 : 0.0;
        error = std::max(error, std::fabs(static_cast<double>(f[i]) - expected));
    }
    return error;
}

double inverse_residual3x3_rows(const float* f, double det)
{
    if (std::fabs(det) < 0.0000001)
        return 1.0;
    const double a = f[0], b = f[1], c = f[2];
    const double d = f[4], e = f[5], g = f[6];
    const double h = f[8], i = f[9], j = f[10];
    const double inv_det = 1.0 / det;
    const double inv[9] = {
        (e * j - g * i) * inv_det,
        (c * i - b * j) * inv_det,
        (b * g - c * e) * inv_det,
        (g * h - d * j) * inv_det,
        (a * j - c * h) * inv_det,
        (c * d - a * g) * inv_det,
        (d * i - e * h) * inv_det,
        (b * h - a * i) * inv_det,
        (a * e - b * d) * inv_det
    };
    const double m[9] = {a, b, c, d, e, g, h, i, j};
    double residual = 0.0;
    for (int row = 0; row < 3; ++row)
    {
        for (int col = 0; col < 3; ++col)
        {
            double v = 0.0;
            for (int k = 0; k < 3; ++k)
                v += m[row * 3 + k] * inv[k * 3 + col];
            const double expected = row == col ? 1.0 : 0.0;
            residual = std::max(residual, std::fabs(v - expected));
        }
    }
    return residual;
}

matrix_eval_t evaluate_matrix4x4(const float* f, double world_max)
{
    matrix_eval_t eval;
    double max_abs = 0.0;
    int near_zero = 0;
    for (int i = 0; i < 16; ++i)
    {
        if (!std::isfinite(f[i]))
        {
            eval.reason = "nonfinite";
            return eval;
        }
        const double av = std::fabs(static_cast<double>(f[i]));
        max_abs = std::max(max_abs, av);
        if (av < 0.000001)
            ++near_zero;
    }
    eval.identity_error = identity_matrix_error4x4(f);
    eval.static_null_view = eval.identity_error <= 0.0005;
    const double max_component = std::max<double>(world_max * 4.0, 1000000.0);
    if (max_abs <= 0.000001)
    {
        eval.reason = "all_zero";
        return eval;
    }
    if (max_abs > max_component)
    {
        eval.reason = "component_out_of_range";
        return eval;
    }
    if (near_zero >= 15)
    {
        eval.reason = "too_sparse";
        return eval;
    }

    const double r0 = vec3_norm(f[0], f[1], f[2]);
    const double r1 = vec3_norm(f[4], f[5], f[6]);
    const double r2 = vec3_norm(f[8], f[9], f[10]);
    const double c0 = vec3_norm(f[0], f[4], f[8]);
    const double c1 = vec3_norm(f[1], f[5], f[9]);
    const double c2 = vec3_norm(f[2], f[6], f[10]);
    const double min_axis = std::min({r0, r1, r2, c0, c1, c2});
    const double max_axis = std::max({r0, r1, r2, c0, c1, c2});
    if (min_axis < 0.0001 || max_axis > 10000.0)
    {
        eval.reason = "axis_norm_out_of_range";
        return eval;
    }

    const double rd01 = std::fabs(vec3_dot(f[0], f[1], f[2], f[4], f[5], f[6]) / std::max(0.000001, r0 * r1));
    const double rd02 = std::fabs(vec3_dot(f[0], f[1], f[2], f[8], f[9], f[10]) / std::max(0.000001, r0 * r2));
    const double rd12 = std::fabs(vec3_dot(f[4], f[5], f[6], f[8], f[9], f[10]) / std::max(0.000001, r1 * r2));
    const double cd01 = std::fabs(vec3_dot(f[0], f[4], f[8], f[1], f[5], f[9]) / std::max(0.000001, c0 * c1));
    const double cd02 = std::fabs(vec3_dot(f[0], f[4], f[8], f[2], f[6], f[10]) / std::max(0.000001, c0 * c2));
    const double cd12 = std::fabs(vec3_dot(f[1], f[5], f[9], f[2], f[6], f[10]) / std::max(0.000001, c1 * c2));
    eval.row_orthogonality_error = std::max({rd01, rd02, rd12});
    eval.column_orthogonality_error = std::max({cd01, cd02, cd12});
    eval.orthogonality_error = std::min(eval.row_orthogonality_error, eval.column_orthogonality_error);
    eval.determinant = det3x3_rows(f);
    eval.inverse_residual = inverse_residual3x3_rows(f, eval.determinant);
    const double abs_det = std::fabs(eval.determinant);

    eval.row_translation_abs = std::max({std::fabs(static_cast<double>(f[12])), std::fabs(static_cast<double>(f[13])), std::fabs(static_cast<double>(f[14]))});
    eval.column_translation_abs = std::max({std::fabs(static_cast<double>(f[3])), std::fabs(static_cast<double>(f[7])), std::fabs(static_cast<double>(f[11]))});
    const bool row_translation_ok = eval.row_translation_abs <= world_max;
    const bool column_translation_ok = eval.column_translation_abs <= world_max;
    if (!row_translation_ok && !column_translation_ok)
    {
        eval.reason = "translation_out_of_range";
        return eval;
    }

    const bool row_view_norms = r0 >= 0.35 && r0 <= 3.25 && r1 >= 0.35 && r1 <= 3.25 && r2 >= 0.35 && r2 <= 3.25;
    const bool col_view_norms = c0 >= 0.35 && c0 <= 3.25 && c1 >= 0.35 && c1 <= 3.25 && c2 >= 0.35 && c2 <= 3.25;
    const bool row_view_like = row_view_norms && eval.row_orthogonality_error <= 0.35 && abs_det >= 0.05 && abs_det <= 8.0 && eval.inverse_residual <= 0.35 && row_translation_ok && std::fabs(static_cast<double>(f[15]) - 1.0) <= 0.10;
    const bool col_view_like = col_view_norms && eval.column_orthogonality_error <= 0.35 && abs_det >= 0.05 && abs_det <= 8.0 && eval.inverse_residual <= 0.35 && column_translation_ok && std::fabs(static_cast<double>(f[15]) - 1.0) <= 0.10;
    eval.view_like = row_view_like || col_view_like;
    if (eval.view_like)
        eval.orientation = (!col_view_like || eval.row_orthogonality_error <= eval.column_orthogonality_error) ? "row_major" : "column_major";

    const double perspective_terms = std::fabs(static_cast<double>(f[3])) + std::fabs(static_cast<double>(f[7])) + std::fabs(static_cast<double>(f[11]));
    const double row_perspective_terms = std::fabs(static_cast<double>(f[12])) + std::fabs(static_cast<double>(f[13])) + std::fabs(static_cast<double>(f[14]));
    const bool projection_diag = std::fabs(static_cast<double>(f[0])) >= 0.0001 && std::fabs(static_cast<double>(f[5])) >= 0.0001;
    const bool projection_tail = std::fabs(static_cast<double>(f[15])) <= 0.10 &&
                                 (std::fabs(static_cast<double>(f[11])) >= 0.10 || std::fabs(static_cast<double>(f[14])) >= 0.0001);
    const bool projection_zero_shape = std::fabs(static_cast<double>(f[1])) + std::fabs(static_cast<double>(f[2])) +
                                       std::fabs(static_cast<double>(f[4])) + std::fabs(static_cast<double>(f[6])) <=
                                       std::max(0.75, (std::fabs(static_cast<double>(f[0])) + std::fabs(static_cast<double>(f[5]))) * 0.35);
    eval.projection_like = projection_diag && projection_tail && projection_zero_shape;
    if (eval.projection_like && eval.orientation.empty())
        eval.orientation = "projection_shape";
    eval.viewproj_like = !eval.view_like && !eval.projection_like && (perspective_terms >= 0.10 || row_perspective_terms >= 0.10) && abs_det >= 0.00000001 && max_axis <= 10000.0;
    if (eval.viewproj_like)
        eval.orientation = perspective_terms >= row_perspective_terms ? "column_vector_viewproj_or_projection_product" : "row_vector_viewproj_or_projection_product";

    if (!eval.view_like && !eval.projection_like && !eval.viewproj_like)
    {
        eval.reason = "shape_rejected";
        return eval;
    }

    eval.plausible = true;
    eval.reason = "accepted";
    eval.score = 0.45;
    if (eval.view_like)
    {
        eval.type = "view";
        eval.score += 0.25;
        if (eval.inverse_residual <= 0.10)
            eval.score += 0.08;
    }
    else if (eval.projection_like)
    {
        eval.type = "projection";
        eval.score += 0.20;
    }
    else
    {
        eval.type = "viewproj";
        eval.score += 0.15;
    }
    eval.score += std::max(0.0, 0.20 - eval.orthogonality_error * 0.20);
    if (abs_det >= 0.10 && abs_det <= 4.0)
        eval.score += 0.08;
    eval.score = std::min(0.98, eval.score);
    return eval;
}

bool plausible_matrix4x4(const float* f, double world_max)
{
    return evaluate_matrix4x4(f, world_max).plausible;
}

json preview_floats(const std::vector<std::uint8_t>& bytes)
{
    json arr = json::array();
    const std::size_t n = std::min<std::size_t>(16, bytes.size() / sizeof(float));
    for (std::size_t i = 0; i < n; ++i)
    {
        float value = 0.0f;
        std::memcpy(&value, bytes.data() + i * sizeof(float), sizeof(float));
        arr.push_back(value);
    }
    return arr;
}

json register_snapshot(const driver_bridge::thread_context_t& ctx)
{
    return json{
        {"rip", sa_format_address(ctx.rip)},
        {"rsp", sa_format_address(ctx.rsp)},
        {"rbp", sa_format_address(ctx.rbp)},
        {"rax", sa_format_address(ctx.rax)},
        {"rbx", sa_format_address(ctx.rbx)},
        {"rcx", sa_format_address(ctx.rcx)},
        {"rdx", sa_format_address(ctx.rdx)},
        {"rsi", sa_format_address(ctx.rsi)},
        {"rdi", sa_format_address(ctx.rdi)},
        {"r8", sa_format_address(ctx.r8)},
        {"r9", sa_format_address(ctx.r9)},
        {"r10", sa_format_address(ctx.r10)},
        {"r11", sa_format_address(ctx.r11)},
        {"r12", sa_format_address(ctx.r12)},
        {"r13", sa_format_address(ctx.r13)},
        {"r14", sa_format_address(ctx.r14)},
        {"r15", sa_format_address(ctx.r15)}
    };
}

std::uint64_t stack_arg64(std::uint32_t pid, std::uint64_t rsp, std::uint32_t index)
{
    std::uint64_t value = 0;
    read_u64(pid, rsp + 0x28ull + static_cast<std::uint64_t>(index) * 8ull, value);
    return value;
}

std::uint32_t matrix_run_count(const std::vector<std::uint8_t>& bytes, std::size_t off, std::size_t stride, double world_max, std::uint32_t max_count)
{
    std::uint32_t count = 0;
    for (std::size_t cursor = off; cursor + stride <= bytes.size() && count < max_count; cursor += stride)
    {
        float f[16] = {};
        if (stride == 64)
        {
            std::memcpy(f, bytes.data() + cursor, 64);
        }
        else
        {
            std::memcpy(f, bytes.data() + cursor, 48);
            f[15] = 1.0f;
        }
        if (!plausible_matrix4x4(f, world_max))
            break;
        ++count;
    }
    return count;
}

float float_from_u32(std::uint32_t value)
{
    float out = 0.0f;
    std::memcpy(&out, &value, sizeof(out));
    return out;
}

struct matrix_decode_result_t
{
    std::uint32_t count = 0;
    std::size_t stride = 0;
    std::size_t offset = 0;
    std::uint32_t xor_key = 0;
    std::string decode = "raw_float32";
    matrix_eval_t first_eval;
};

bool decode_matrix_words(const std::vector<std::uint8_t>& bytes,
                         std::size_t off,
                         std::size_t stride,
                         std::uint32_t xor_key,
                         float* out)
{
    if (off + stride > bytes.size() || (stride != 48 && stride != 64))
        return false;
    std::fill(out, out + 16, 0.0f);
    const std::size_t words = stride / sizeof(std::uint32_t);
    for (std::size_t i = 0; i < words; ++i)
    {
        std::uint32_t word = 0;
        std::memcpy(&word, bytes.data() + off + i * sizeof(std::uint32_t), sizeof(word));
        word ^= xor_key;
        out[i] = float_from_u32(word);
    }
    if (stride == 48)
        out[15] = 1.0f;
    return true;
}

std::uint32_t matrix_run_count_decoded(const std::vector<std::uint8_t>& bytes,
                                       std::size_t off,
                                       std::size_t stride,
                                       std::uint32_t xor_key,
                                       double world_max,
                                       std::uint32_t max_count,
                                       matrix_eval_t* first_eval)
{
    std::uint32_t count = 0;
    for (std::size_t cursor = off; cursor + stride <= bytes.size() && count < max_count; cursor += stride)
    {
        float f[16] = {};
        if (!decode_matrix_words(bytes, cursor, stride, xor_key, f))
            break;
        matrix_eval_t eval = evaluate_matrix4x4(f, world_max);
        if (!eval.plausible)
            break;
        if (count == 0 && first_eval)
            *first_eval = eval;
        ++count;
    }
    return count;
}

std::vector<std::uint32_t> matrix_xor_key_candidates(const std::vector<std::uint8_t>& bytes, std::size_t off, std::size_t stride)
{
    std::vector<std::uint32_t> keys;
    auto push_key = [&](std::uint32_t key) {
        if (std::find(keys.begin(), keys.end(), key) == keys.end())
            keys.push_back(key);
    };
    push_key(0);
    if (off + stride > bytes.size())
        return keys;
    const std::uint32_t expected_one = 0x3F800000u;
    const std::uint32_t expected_zero = 0u;
    const std::size_t words = stride / sizeof(std::uint32_t);
    const std::uint32_t one_indices[] = {0, 5, 10, 15};
    const std::uint32_t zero_indices[] = {3, 7, 11, 12, 13, 14};
    for (std::uint32_t idx : one_indices)
    {
        if (idx >= words)
            continue;
        std::uint32_t word = 0;
        std::memcpy(&word, bytes.data() + off + static_cast<std::size_t>(idx) * sizeof(std::uint32_t), sizeof(word));
        push_key(word ^ expected_one);
    }
    for (std::uint32_t idx : zero_indices)
    {
        if (idx >= words)
            continue;
        std::uint32_t word = 0;
        std::memcpy(&word, bytes.data() + off + static_cast<std::size_t>(idx) * sizeof(std::uint32_t), sizeof(word));
        push_key(word ^ expected_zero);
    }
    return keys;
}

matrix_decode_result_t best_matrix_decode_run(const std::vector<std::uint8_t>& bytes,
                                              double world_max,
                                              std::uint32_t max_count,
                                              std::size_t max_probe_bytes)
{
    matrix_decode_result_t best;
    const std::size_t probe_end = std::min<std::size_t>(bytes.size(), max_probe_bytes);
    for (std::size_t off = 0; off + 48 <= probe_end; off += 16)
    {
        for (std::size_t stride : {64ull, 48ull})
        {
            if (off + stride > bytes.size())
                continue;
            for (std::uint32_t key : matrix_xor_key_candidates(bytes, off, stride))
            {
                matrix_eval_t first;
                const std::uint32_t count = matrix_run_count_decoded(bytes, off, stride, key, world_max, max_count, &first);
                if (count == 0)
                    continue;
                const bool better = count > best.count ||
                                    (count == best.count && key == 0 && best.xor_key != 0) ||
                                    (count == best.count && stride == 64 && best.stride == 48);
                if (!better)
                    continue;
                best.count = count;
                best.stride = stride;
                best.offset = off;
                best.xor_key = key;
                best.decode = key == 0 ? "raw_float32" : "xor32_float32";
                best.first_eval = first;
            }
        }
    }
    return best;
}

std::optional<json> make_cbuffer_candidate(std::uint32_t pid,
                                           int slot,
                                           std::uint64_t va,
                                           std::uint64_t object_va,
                                           std::uint64_t field_offset,
                                           const std::string& source,
                                           double source_confidence)
{
    driver_bridge::memory_region_t region{};
    if (va == 0 || !query_region(pid, va, region) || !is_readable(region) || is_executable(region))
        return std::nullopt;
    const std::uint64_t end = region.base + region.size;
    if (end <= va)
        return std::nullopt;
    const std::uint64_t available = end - va;
    if (available < 16)
        return std::nullopt;
    std::vector<std::uint8_t> bytes;
    const std::size_t read_size = static_cast<std::size_t>(std::min<std::uint64_t>(available, 4096));
    if (!read_bytes(pid, va, read_size, bytes) || bytes.empty())
        return std::nullopt;
    const std::uint32_t matrices64 = matrix_run_count(bytes, 0, 64, 1000000.0, 256);
    const std::uint32_t matrices48 = matrix_run_count(bytes, 0, 48, 1000000.0, 256);
    const std::uint32_t matrix_count = std::max(matrices64, matrices48);
    double confidence = source_confidence;
    if (is_writable(region))
        confidence += 0.10;
    if (matrix_count > 0)
        confidence += std::min(0.45, static_cast<double>(matrix_count) * 0.05);
    json row;
    row["slot"] = slot >= 0 ? json(slot) : json(nullptr);
    row["va"] = sa_format_address(va);
    row["size"] = available;
    row["preview_floats"] = preview_floats(bytes);
    row["source"] = source;
    row["confidence"] = std::min(0.98, confidence);
    row["object_va"] = object_va ? json(sa_format_address(object_va)) : json(nullptr);
    row["object_field_offset"] = field_offset ? json(sa_format_address(field_offset)) : json(nullptr);
    row["matrix_count"] = matrix_count;
    row["matrix_size"] = matrices64 >= matrices48 ? 64 : 48;
    row["region"] = region_json(region);
    return row;
}

json make_gpu_va_candidate(int slot,
                           std::uint64_t gpu_va,
                           std::uint64_t size,
                           const std::string& source,
                           double confidence)
{
    json row;
    row["slot"] = slot >= 0 ? json(slot) : json(nullptr);
    row["va"] = gpu_va ? json(sa_format_address(gpu_va)) : json(nullptr);
    row["gpu_va"] = gpu_va ? json(sa_format_address(gpu_va)) : json(nullptr);
    row["size"] = size;
    row["source"] = source;
    row["confidence"] = confidence;
    row["cpu_va_mapped"] = false;
    row["mapping_proof"] = "gpu_virtual_address_not_proven_as_cpu_va";
    return row;
}

void append_unique_candidate(json& arr, const json& candidate, std::set<std::uint64_t>& seen, std::size_t limit)
{
    if (arr.size() >= limit || !candidate.contains("va"))
        return;
    std::uint64_t va = 0;
    if (!parse_u64_value(candidate["va"], va) || va == 0 || seen.count(va) != 0)
        return;
    seen.insert(va);
    arr.push_back(candidate);
}

void stamp_candidate_rows(json& rows,
                          const std::string& evidence_class,
                          const std::string& provenance,
                          bool diagnostic_only,
                          const std::string& argument_source)
{
    if (!rows.is_array())
        return;
    for (auto& row : rows)
    {
        if (!row.is_object())
            continue;
        if (!row.contains("evidence_class"))
            row["evidence_class"] = evidence_class;
        if (!row.contains("bound_state_provenance"))
            row["bound_state_provenance"] = provenance;
        if (!row.contains("diagnostic_only"))
            row["diagnostic_only"] = diagnostic_only;
        if (!row.contains("bind_call_args_source"))
            row["bind_call_args_source"] = diagnostic_only ? json(nullptr) : json(argument_source);
    }
}

void collect_explicit_cbuffer_candidates(std::uint32_t pid,
                                         const json& params,
                                         json& out,
                                         std::set<std::uint64_t>& seen,
                                         std::size_t limit,
                                         const std::string& source)
{
    for (const char* key : {"matrix_buffer_va", "matrix_va", "candidate_va", "cbuffer_va", "buffer_va", "va"})
    {
        std::uint64_t va = 0;
        if (!parse_address_param(params, key, va) || va == 0)
            continue;
        auto row = make_cbuffer_candidate(pid, -1, va, 0, 0, source, 0.70);
        if (row)
        {
            (*row)["explicit_param"] = key;
            append_unique_candidate(out, *row, seen, limit);
        }
    }
    if (!params.contains("candidates") || !params["candidates"].is_array())
        return;
    for (const auto& item : params["candidates"])
    {
        if (!item.is_object())
            continue;
        std::uint64_t va = 0;
        if (!parse_address_param(item, "va", va) && !parse_address_param(item, "matrix_buffer_va", va) && !parse_address_param(item, "candidate_va", va))
            continue;
        auto row = make_cbuffer_candidate(pid, -1, va, 0, 0, source, 0.70);
        if (row)
            append_unique_candidate(out, *row, seen, limit);
    }
}

json explicit_cbuffer_candidates(std::uint32_t pid, const json& params, std::size_t limit, const std::string& source)
{
    json out = json::array();
    std::set<std::uint64_t> seen;
    collect_explicit_cbuffer_candidates(pid, params, out, seen, limit, source);
    return out;
}

void collect_pointer_candidates(std::uint32_t pid,
                                std::uint64_t base,
                                std::size_t bytes_to_read,
                                const std::string& source,
                                int slot,
                                json& out,
                                std::set<std::uint64_t>& seen,
                                std::size_t limit)
{
    if (base == 0 || out.size() >= limit)
        return;
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, base, bytes_to_read, bytes) || bytes.size() < sizeof(std::uint64_t))
        return;
    const std::size_t aligned = bytes.size() & ~static_cast<std::size_t>(7);
    for (std::size_t off = 0; off + 8 <= aligned && out.size() < limit; off += 8)
    {
        std::uint64_t ptr = 0;
        std::memcpy(&ptr, bytes.data() + off, sizeof(ptr));
        auto row = make_cbuffer_candidate(pid, slot, ptr, base, static_cast<std::uint64_t>(off), source, 0.30);
        if (row)
            append_unique_candidate(out, *row, seen, limit);
    }
}

void collect_resource_array_candidates(std::uint32_t pid,
                                       std::uint64_t start_slot,
                                       std::uint64_t count,
                                       std::uint64_t pp_buffers,
                                       json& out,
                                       std::set<std::uint64_t>& seen,
                                       std::size_t limit,
                                       const std::string& pointer_source = "d3d_resource_object_pointer_snapshot",
                                       const std::string& object_source = "d3d_resource_object_bytes",
                                       double object_confidence = 0.25)
{
    if (pp_buffers == 0 || count == 0 || out.size() >= limit)
        return;
    const std::uint64_t safe_count = std::min<std::uint64_t>(count, 64);
    std::vector<std::uint8_t> ptrs;
    if (!read_bytes(pid, pp_buffers, static_cast<std::size_t>(safe_count * sizeof(std::uint64_t)), ptrs))
        return;
    for (std::uint64_t i = 0; i < safe_count && out.size() < limit; ++i)
    {
        if ((i + 1) * 8 > ptrs.size())
            break;
        std::uint64_t resource = 0;
        std::memcpy(&resource, ptrs.data() + static_cast<std::size_t>(i * 8), sizeof(resource));
        if (resource == 0)
            continue;
        const int slot = start_slot + i <= 0x7FFFFFFFull ? static_cast<int>(start_slot + i) : -1;
        collect_pointer_candidates(pid, resource, 0x300, pointer_source, slot, out, seen, limit);
        if (out.size() < limit)
        {
            auto row = make_cbuffer_candidate(pid, slot, resource, resource, 0, object_source, object_confidence);
            if (row)
                append_unique_candidate(out, *row, seen, limit);
        }
    }
}

json collect_d3d12_vertex_buffer_views(std::uint32_t pid,
                                       std::uint64_t start_slot,
                                       std::uint64_t count,
                                       std::uint64_t views_va,
                                       std::size_t limit)
{
    json out = json::array();
    std::set<std::uint64_t> seen;
    if (views_va == 0 || count == 0)
        return out;
    const std::uint64_t safe_count = std::min<std::uint64_t>(count, 64);
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, views_va, static_cast<std::size_t>(safe_count * 16ull), bytes))
        return out;
    for (std::uint64_t i = 0; i < safe_count && out.size() < limit; ++i)
    {
        const std::size_t off = static_cast<std::size_t>(i * 16ull);
        if (off + 16 > bytes.size())
            break;
        std::uint64_t gpu_va = 0;
        std::uint32_t size = 0;
        std::uint32_t stride = 0;
        std::memcpy(&gpu_va, bytes.data() + off, sizeof(gpu_va));
        std::memcpy(&size, bytes.data() + off + 8, sizeof(size));
        std::memcpy(&stride, bytes.data() + off + 12, sizeof(stride));
        if (gpu_va == 0)
            continue;
        const int slot = start_slot + i <= 0x7FFFFFFFull ? static_cast<int>(start_slot + i) : -1;
        auto row = make_cbuffer_candidate(pid, slot, gpu_va, views_va, static_cast<std::uint64_t>(off), "d3d12_vertex_live_bind_view_cpu_mapped_gpu_va", 0.50);
        if (row)
        {
            (*row)["gpu_va"] = sa_format_address(gpu_va);
            (*row)["view_size_bytes"] = size;
            (*row)["stride_bytes"] = stride;
            (*row)["cpu_va_mapped"] = true;
            append_unique_candidate(out, *row, seen, limit);
            continue;
        }
        json unmapped = make_gpu_va_candidate(slot, gpu_va, size, "d3d12_vertex_live_bind_view_gpu_va", 0.42);
        unmapped["view_array_va"] = sa_format_address(views_va);
        unmapped["view_offset"] = off;
        unmapped["stride_bytes"] = stride;
        append_unique_candidate(out, unmapped, seen, limit);
    }
    return out;
}

json collect_vertex_buffer_candidates_from_context(std::uint32_t pid, const driver_bridge::thread_context_t& ctx, const store::dx_hook_record_t& record)
{
    json out = json::array();
    std::set<std::uint64_t> seen;
    const std::size_t limit = record.max_captures ? record.max_captures : 32;
    const std::string api = lower_ascii(record.api);
    if (api.find("d3d11") != std::string::npos)
    {
        collect_resource_array_candidates(pid, ctx.rdx, ctx.r8, ctx.r9, out, seen, limit,
                                          "d3d11_vertex_live_bind_resource_array_pointer",
                                          "d3d11_vertex_live_bind_resource_object",
                                          0.30);
        std::uint64_t strides = stack_arg64(pid, ctx.rsp, 0);
        std::uint64_t offsets = stack_arg64(pid, ctx.rsp, 1);
        for (auto& row : out)
        {
            row["stride_array_va"] = strides ? json(sa_format_address(strides)) : json(nullptr);
            row["offset_array_va"] = offsets ? json(sa_format_address(offsets)) : json(nullptr);
            if (row.contains("slot") && row["slot"].is_number_integer() && row["slot"].get<int>() >= 0)
            {
                const std::uint64_t slot_index = static_cast<std::uint64_t>(row["slot"].get<int>());
                if (slot_index >= ctx.rdx)
                {
                    const std::uint64_t array_index = slot_index - ctx.rdx;
                    std::uint32_t stride_value = 0;
                    std::uint32_t offset_value = 0;
                    if (strides != 0 && read_u32(pid, strides + array_index * sizeof(std::uint32_t), stride_value))
                        row["stride_bytes"] = stride_value;
                    if (offsets != 0 && read_u32(pid, offsets + array_index * sizeof(std::uint32_t), offset_value))
                        row["offset_bytes"] = offset_value;
                }
            }
        }
    }
    else if (api.find("d3d12") != std::string::npos)
    {
        out = collect_d3d12_vertex_buffer_views(pid, ctx.rdx, ctx.r8, ctx.r9, limit);
    }
    stamp_candidate_rows(out, "live_breakpoint_vertex_bind_call_args", "live_vertex_buffer_bind_breakpoint_context", false, "thread_context_registers");
    return out;
}

json scan_memory_cbuffer_candidates(std::uint32_t pid, std::size_t limit, double world_max, std::size_t max_regions)
{
    const std::uint64_t started_ms = GetTickCount64();
    json out = json::array();
    std::set<std::uint64_t> seen;
    std::size_t scanned_regions = 0;
    for (const auto& region : regions_for(pid, 4096))
    {
        if (dx_call_cancelled("scan_memory_cbuffer_candidates_regions", pid, started_ms))
            break;
        if (out.size() >= limit || scanned_regions >= max_regions)
            break;
        if (!is_readable(region) || is_executable(region) || region.size < 64 || region.size > 32ull * 1024ull * 1024ull)
            continue;
        if (region.type != MEM_PRIVATE && region.type != MEM_MAPPED)
            continue;
        ++scanned_regions;
        std::vector<std::uint8_t> bytes;
        const std::size_t read_size = static_cast<std::size_t>(std::min<std::uint64_t>(region.size, 256ull * 1024ull));
        if (!read_bytes(pid, region.base, read_size, bytes) || bytes.size() < 64)
            continue;
        for (std::size_t off = 0; off + 64 <= bytes.size() && out.size() < limit; off += 16)
        {
            if ((off & 0xFFFu) == 0 && dx_call_cancelled("scan_memory_cbuffer_candidates_bytes", pid, started_ms))
                break;
            const std::uint32_t run64 = matrix_run_count(bytes, off, 64, world_max, 256);
            const std::uint32_t run48 = matrix_run_count(bytes, off, 48, world_max, 256);
            const std::uint32_t best = std::max(run64, run48);
            if (best == 0)
                continue;
            auto row = make_cbuffer_candidate(pid, -1, region.base + off, 0, 0, "bounded_private_memory_matrix_scan", 0.35);
            if (!row)
                continue;
            (*row)["matrix_count"] = best;
            (*row)["matrix_size"] = run64 >= run48 ? 64 : 48;
            (*row)["confidence"] = std::min(0.95, 0.38 + static_cast<double>(best) * 0.04);
            append_unique_candidate(out, *row, seen, limit);
            off += (run64 >= run48 ? 64ull : 48ull) * std::max<std::uint32_t>(best, 1);
        }
    }
    diag::log_tagged_fmt("dx_hook", "scan_memory_cbuffer_candidates exit pid=%u regions=%zu max_regions=%zu results=%zu elapsed_ms=%llu",
                         pid,
                         scanned_regions,
                         max_regions,
                         out.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return out;
}

json collect_cbuffer_candidates_from_context(std::uint32_t pid, const driver_bridge::thread_context_t& ctx, const store::dx_hook_record_t& record)
{
    json out = json::array();
    std::set<std::uint64_t> seen;
    const std::string api = lower_ascii(record.api);
    const bool cbuffer_bind = record.action == "cbuffer_bind";
    if (cbuffer_bind && api.find("d3d11") != std::string::npos)
        collect_resource_array_candidates(pid, ctx.rdx, ctx.r8, ctx.r9, out, seen, record.max_captures ? record.max_captures : 32,
                                          "d3d11_cbuffer_live_bind_resource_array_pointer",
                                          "d3d11_cbuffer_live_bind_resource_object",
                                          0.55);
    if (cbuffer_bind && api.find("d3d12") != std::string::npos)
    {
        auto row = make_cbuffer_candidate(pid, static_cast<int>(ctx.rdx), ctx.r8, 0, 0, "d3d12_root_cbv_live_bind_gpu_va_cpu_mapped_candidate", 0.40);
        if (row)
        {
            (*row)["gpu_va"] = sa_format_address(ctx.r8);
            (*row)["cpu_va_mapped"] = true;
            (*row)["mapping_proof"] = "gpu_va_matches_readable_process_region";
            append_unique_candidate(out, *row, seen, record.max_captures ? record.max_captures : 32);
        }
        else if (ctx.r8 != 0)
        {
            json unmapped = make_gpu_va_candidate(static_cast<int>(ctx.rdx), ctx.r8, 0, "d3d12_root_cbv_live_bind_gpu_va", 0.50);
            append_unique_candidate(out, unmapped, seen, record.max_captures ? record.max_captures : 32);
        }
    }
    stamp_candidate_rows(out, "live_breakpoint_cbuffer_bind_call_args", "live_cbuffer_bind_breakpoint_context", false, "thread_context_registers");
    return out;
}

json dx_args_json(std::uint32_t pid, const driver_bridge::thread_context_t& ctx, const store::dx_hook_record_t& record)
{
    json args;
    args["this"] = sa_format_address(ctx.rcx);
    args["arg0"] = ctx.rdx;
    args["arg1"] = ctx.r8;
    args["arg2"] = ctx.r9;
    args["stack_arg0"] = stack_arg64(pid, ctx.rsp, 0);
    args["stack_arg1"] = stack_arg64(pid, ctx.rsp, 1);
    const std::string api = lower_ascii(record.api);
    if (record.action == "present" && api.find("vulkan") != std::string::npos)
    {
        args["queue"] = sa_format_address(ctx.rcx);
        args["present_info"] = sa_format_address(ctx.rdx);
    }
    else if (record.action == "present")
    {
        args["swap_chain"] = sa_format_address(ctx.rcx);
        args["sync_interval"] = ctx.rdx;
        args["flags"] = ctx.r8;
    }
    else if (record.action == "cbuffer_bind")
    {
        if (lower_ascii(record.api).find("d3d11") != std::string::npos)
        {
            args["start_slot"] = ctx.rdx;
            args["buffer_count"] = ctx.r8;
            args["buffer_array"] = sa_format_address(ctx.r9);
        }
        else if (lower_ascii(record.api).find("d3d12") != std::string::npos)
        {
            args["root_parameter_index"] = ctx.rdx;
            args["buffer_location"] = sa_format_address(ctx.r8);
        }
    }
    else if (record.action == "vertex_buffer_bind")
    {
        if (api.find("d3d11") != std::string::npos)
        {
            args["start_slot"] = ctx.rdx;
            args["buffer_count"] = ctx.r8;
            args["buffer_array"] = sa_format_address(ctx.r9);
            args["stride_array"] = sa_format_address(stack_arg64(pid, ctx.rsp, 0));
            args["offset_array"] = sa_format_address(stack_arg64(pid, ctx.rsp, 1));
        }
        else if (api.find("d3d12") != std::string::npos)
        {
            args["start_slot"] = ctx.rdx;
            args["view_count"] = ctx.r8;
            args["vertex_buffer_views"] = sa_format_address(ctx.r9);
        }
    }
    else if (record.action == "draw")
    {
        if (api.find("vulkan") != std::string::npos)
        {
            args["command_buffer"] = sa_format_address(ctx.rcx);
            args["vertex_or_index_count"] = ctx.rdx;
            args["instance_count"] = ctx.r8;
            args["first_vertex_or_index"] = ctx.r9;
            args["vertex_offset_or_first_instance"] = stack_arg64(pid, ctx.rsp, 0);
            args["first_instance"] = stack_arg64(pid, ctx.rsp, 1);
        }
        else
        {
            args["index_or_vertex_count"] = ctx.rdx;
            args["instance_or_start_index"] = ctx.r8;
            args["start_index_or_vertex"] = ctx.r9;
            args["stack_draw_arg0"] = stack_arg64(pid, ctx.rsp, 0);
            args["stack_draw_arg1"] = stack_arg64(pid, ctx.rsp, 1);
        }
    }
    return args;
}

void append_capture(store::dx_hook_record_t record, json capture)
{
    record.captures.push_back(std::move(capture));
    const std::size_t limit = record.max_captures == 0 ? 16 : record.max_captures;
    while (record.captures.size() > limit)
        record.captures.erase(record.captures.begin());
    store::update_dx_hook(record);
}

std::uint64_t context_dr_address(const driver_bridge::thread_context_t& ctx, int slot)
{
    switch (slot)
    {
    case 0: return ctx.dr0;
    case 1: return ctx.dr1;
    case 2: return ctx.dr2;
    case 3: return ctx.dr3;
    default: return 0;
    }
}

json make_debug_capture(std::uint32_t pid,
                        std::uint32_t tid,
                        const driver_bridge::thread_context_t& ctx,
                        const store::dx_hook_record_t& record,
                        std::uint64_t exception_address,
                        const std::string& backend)
{
    json cap;
    cap["event_type"] = backend == "hardware_breakpoint_kernel_context" ? "breakpoint_hit" : "snapshot";
    cap["backend"] = backend;
    cap["timestamp_ms"] = unix_time_ms();
    cap["process_id"] = pid;
    cap["thread_id"] = tid;
    cap["target_va"] = sa_format_address(record.target_va);
    cap["exception_address"] = exception_address ? json(sa_format_address(exception_address)) : json(nullptr);
    cap["hw_slot"] = record.hw_slot;
    cap["action"] = record.action;
    cap["api"] = record.api;
    cap["registers"] = register_snapshot(ctx);
    const std::uint64_t slot_address = context_dr_address(ctx, record.hw_slot);
    cap["breakpoint_evidence"] = {
        {"slot_address", slot_address ? json(sa_format_address(slot_address)) : json(nullptr)},
        {"target_va", record.target_va ? json(sa_format_address(record.target_va)) : json(nullptr)},
        {"slot_matches_target", slot_address != 0 && slot_address == record.target_va},
        {"dr6", sa_format_address(ctx.dr6)},
        {"dr7", sa_format_address(ctx.dr7)},
        {"dr6_slot_hit", record.hw_slot >= 0 && record.hw_slot <= 3 ? json((ctx.dr6 & (1ull << static_cast<unsigned>(record.hw_slot))) != 0) : json(nullptr)},
        {"rip_matches_target", ctx.rip == record.target_va},
        {"context_backend", backend}
    };
    cap["args"] = dx_args_json(pid, ctx, record);
    auto mod = find_module_for_address(pid, record.target_va);
    if (mod)
    {
        cap["target_module"] = mod->name;
        cap["target_module_rva"] = sa_format_address(record.target_va - mod->base);
    }
    else
    {
        cap["target_module"] = nullptr;
        cap["target_module_rva"] = nullptr;
    }
    if (record.capture_cbuffers || record.action == "cbuffer_bind")
        cap["cbuffers"] = collect_cbuffer_candidates_from_context(pid, ctx, record);
    else
        cap["cbuffers"] = json::array();
    if (record.capture_vertex_buffers || record.action == "vertex_buffer_bind")
        cap["vertex_buffers"] = collect_vertex_buffer_candidates_from_context(pid, ctx, record);
    else
        cap["vertex_buffers"] = json::array();
    const bool live_cbuffer_bind = backend == "hardware_breakpoint_kernel_context" && record.action == "cbuffer_bind";
    const bool live_vertex_bind = backend == "hardware_breakpoint_kernel_context" && record.action == "vertex_buffer_bind";
    cap["evidence"] = {
        {"source", backend},
        {"thread_context_captured", backend == "hardware_breakpoint_kernel_context"},
        {"cbuffer_source", live_cbuffer_bind ? "live_breakpoint_bind_call_args" : (record.capture_cbuffers ? "primary_draw_hook_no_cbuffer_bind_args" : "disabled")},
        {"vertex_buffer_source", live_vertex_bind ? "live_breakpoint_bind_call_args" : (record.capture_vertex_buffers ? "primary_draw_hook_no_vertex_bind_args" : "disabled")},
        {"gpu_texture_readback", false}
    };
    return cap;
}

json make_snapshot_capture(std::uint32_t pid,
                           const store::dx_hook_record_t& record,
                           const std::string& reason,
                           const json* params = nullptr,
                           bool allow_memory_fallback = true)
{
    json cap;
    cap["event_type"] = "snapshot";
    cap["backend"] = "bounded_snapshot_fallback";
    cap["timestamp_ms"] = unix_time_ms();
    cap["process_id"] = pid;
    cap["thread_id"] = nullptr;
    cap["target_va"] = record.target_va ? json(sa_format_address(record.target_va)) : json(nullptr);
    cap["hw_slot"] = record.hw_slot;
    cap["action"] = record.action;
    cap["api"] = record.api;
    cap["reason"] = reason;
    const std::size_t limit = record.max_captures ? record.max_captures : 32;
    json explicit_rows = params ? explicit_cbuffer_candidates(pid, *params, limit, "explicit_cbuffer_candidate") : json::array();
    const bool explicit_used = !explicit_rows.empty();
    cap["cbuffers"] = json::array();
    if (record.capture_cbuffers || record.action == "cbuffer_bind")
    {
        if (explicit_used)
            cap["cbuffers"] = std::move(explicit_rows);
        else if (allow_memory_fallback)
            cap["cbuffers"] = scan_memory_cbuffer_candidates(pid, limit, 1000000.0, 512);
    }
    stamp_candidate_rows(cap["cbuffers"],
                         "bounded_diagnostic_candidate",
                         explicit_used ? "explicit_diagnostic_candidate" : (allow_memory_fallback ? "bounded_snapshot_fallback" : "memory_fallback_disabled"),
                         true,
                         "");
    cap["vertex_buffers"] = json::array();
    cap["evidence"] = {
        {"source", "bounded_snapshot_fallback"},
        {"thread_context_captured", false},
        {"cbuffer_source", explicit_used ? "explicit_cbuffer_candidate" : (allow_memory_fallback ? "bounded_private_memory_matrix_scan" : "memory_fallback_disabled")},
        {"vertex_buffer_source", record.capture_vertex_buffers ? "requires_live_bind_context" : "disabled"},
        {"gpu_texture_readback", false}
    };
    return cap;
}

void refresh_snapshot_records(std::uint32_t pid, const std::string& reason, const json* params = nullptr, bool allow_memory_fallback = true)
{
    for (auto record : store::list_dx_hooks(pid))
    {
        if (!record.captures.empty())
            continue;
        if (!record.capture_cbuffers && record.action != "cbuffer_bind")
            continue;
        append_capture(record, make_snapshot_capture(pid, record, reason, params, allow_memory_fallback));
    }
}

std::vector<json> stored_cbuffer_rows(std::uint32_t pid)
{
    std::vector<json> out;
    for (const auto& record : store::list_dx_hooks(pid))
    {
        for (const auto& cap : record.captures)
        {
            if (!cap.contains("cbuffers") || !cap["cbuffers"].is_array())
                continue;
            const std::string backend = cap.value("backend", std::string());
            const std::string event_type = cap.value("event_type", std::string());
            const bool live_bound = backend == "hardware_breakpoint_kernel_context" &&
                                    event_type == "breakpoint_hit" &&
                                    record.action == "cbuffer_bind";
            if (!live_bound)
                continue;
            for (const auto& cb : cap["cbuffers"])
            {
                json row = cb;
                row["bound_state_provenance"] = "live_cbuffer_bind_breakpoint_context";
                row["capture_backend"] = backend;
                row["capture_event_type"] = event_type;
                row["capture_hook_id"] = record.id;
                row["capture_action"] = record.action;
                out.push_back(std::move(row));
            }
        }
    }
    return out;
}

bool dx_context_matches_record(const driver_bridge::thread_context_t& ctx, const store::dx_hook_record_t& record)
{
    if (record.target_va == 0 || record.hw_slot < 0 || record.hw_slot > 3)
        return false;
    const std::uint64_t slot_address = context_dr_address(ctx, record.hw_slot);
    const bool slot_matches = slot_address == record.target_va;
    const bool dr6_hit = (ctx.dr6 & (1ull << static_cast<unsigned>(record.hw_slot))) != 0;
    if (dr6_hit && slot_matches)
        return true;
    return slot_matches && ctx.rip == record.target_va;
}

void remove_dx_thread(std::uint32_t pid, std::uint32_t tid)
{
    for (auto record : store::list_dx_hooks(pid))
    {
        auto& tids = record.tids;
        const auto before = tids.size();
        tids.erase(std::remove(tids.begin(), tids.end(), tid), tids.end());
        if (tids.size() != before)
            store::update_dx_hook(record);
    }
}

bool capture_dx_breakpoint_hit(std::uint32_t pid, std::uint32_t tid, const driver_bridge::thread_context_t& ctx)
{
    bool matched = false;
    for (auto record : store::list_dx_hooks(pid))
    {
        if (!dx_context_matches_record(ctx, record))
            continue;
        append_capture(record, make_debug_capture(pid, tid, ctx, record, ctx.rip, "hardware_breakpoint_kernel_context"));
        matched = true;
    }
    if (matched)
    {
        driver_bridge::thread_context_t next = ctx;
        next.rflags |= 0x10000ull;
        next.dr6 = 0;
        SetLastError(ERROR_SUCCESS);
        const bool set_ok = driver_bridge::set_thread_context(tid, next, (1ull << 17) | (1ull << 22));
        const DWORD gle = set_ok ? ERROR_SUCCESS : GetLastError();
        diag::log_tagged_fmt("dx_hook",
            "kernel_context_hit_resume pid=%u tid=%u set_ok=%d gle=%lu rip=%s dr6=0x%llX dr7=0x%llX",
            pid,
            tid,
            set_ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            sa_format_address(ctx.rip).c_str(),
            static_cast<unsigned long long>(ctx.dr6),
            static_cast<unsigned long long>(ctx.dr7));
    }
    return matched;
}

void arm_dx_records_for_thread(std::uint32_t pid, std::uint32_t tid)
{
    if (tid == 0)
        return;
    for (auto record : store::list_dx_hooks(pid))
    {
        if (record.target_va == 0 || record.hw_slot < 0 || record.hw_slot > 3)
            continue;
        if (driver_bridge::set_hardware_breakpoint(tid, record.hw_slot, record.target_va, 0, 0))
        {
            if (std::find(record.tids.begin(), record.tids.end(), tid) == record.tids.end())
            {
                record.tids.push_back(tid);
                store::update_dx_hook(record);
            }
        }
    }
}

void clear_dx_record_breakpoints(std::uint32_t pid)
{
    for (const auto& record : store::list_dx_hooks(pid))
    {
        for (auto tid : record.tids)
            driver_bridge::clear_hardware_breakpoint(tid, record.hw_slot);
    }
}

void clear_dx_record_breakpoints(const store::dx_hook_record_t& record)
{
    for (auto tid : record.tids)
        driver_bridge::clear_hardware_breakpoint(tid, record.hw_slot);
}

void clear_dx_record_breakpoints(const std::vector<store::dx_hook_record_t>& records)
{
    for (const auto& record : records)
        clear_dx_record_breakpoints(record);
}

std::size_t armed_thread_count_for_ids(std::uint32_t pid, const std::vector<std::string>& ids)
{
    std::size_t total = 0;
    for (const auto& record : store::list_dx_hooks(pid))
    {
        if (std::find(ids.begin(), ids.end(), record.id) != ids.end())
            total += record.tids.size();
    }
    return total;
}

std::vector<std::uint32_t> dx_armed_threads(std::uint32_t pid)
{
    std::vector<std::uint32_t> tids;
    for (const auto& record : store::list_dx_hooks(pid))
    {
        for (const auto tid : record.tids)
        {
            if (tid != 0 && std::find(tids.begin(), tids.end(), tid) == tids.end())
                tids.push_back(tid);
        }
    }
    return tids;
}

void poll_dx_thread_contexts(std::uint32_t pid)
{
    for (const auto tid : dx_armed_threads(pid))
    {
        driver_bridge::thread_context_t ctx{};
        SetLastError(ERROR_SUCCESS);
        if (!driver_bridge::get_thread_context(tid, ctx))
        {
            const DWORD gle = GetLastError();
            diag::log_tagged_fmt("dx_hook",
                "kernel_context_poll_get_failed pid=%u tid=%u gle=%lu driver_error=%s",
                pid,
                tid,
                static_cast<unsigned long>(gle),
                driver_bridge::last_error().c_str());
            if (gle == ERROR_INVALID_PARAMETER || gle == ERROR_NOT_FOUND || gle == ERROR_INVALID_HANDLE)
                remove_dx_thread(pid, tid);
            continue;
        }
        capture_dx_breakpoint_hit(pid, tid, ctx);
    }
}

struct dx_debug_state_t
{
    std::atomic<bool> running{false};
    std::atomic<bool> polling{false};
    std::atomic<bool> attached{false};
    std::atomic<DWORD> error{0};
    std::atomic<std::uint32_t> pid{0};
};

dx_debug_state_t& dx_debug_state()
{
    static dx_debug_state_t state;
    return state;
}

void dx_debug_loop()
{
    auto& state = dx_debug_state();
    const std::uint32_t pid = state.pid.load(std::memory_order_acquire);
    if (pid == 0 || !driver_bridge::using_kernel_driver())
    {
        state.error.store(pid == 0 ? ERROR_INVALID_PARAMETER : ERROR_INVALID_HANDLE, std::memory_order_release);
        state.attached.store(false, std::memory_order_release);
        state.polling.store(false, std::memory_order_release);
        state.running.store(false, std::memory_order_release);
        diag::log_tagged_fmt("dx_hook",
            "kernel_context_loop_exit_invalid pid=%u kernel=%d",
            pid,
            driver_bridge::using_kernel_driver() ? 1 : 0);
        return;
    }
    state.error.store(0, std::memory_order_release);
    state.attached.store(true, std::memory_order_release);
    for (const auto& th : threads_for(pid))
        arm_dx_records_for_thread(pid, th.tid);
    std::uint64_t poll_count = 0;
    while (state.polling.load(std::memory_order_acquire))
    {
        if (!driver_bridge::using_kernel_driver())
        {
            state.error.store(ERROR_INVALID_HANDLE, std::memory_order_release);
            state.polling.store(false, std::memory_order_release);
            break;
        }
        if (store::list_dx_hooks(pid).empty())
            break;
        if ((poll_count++ % 20) == 0)
        {
            for (const auto& th : threads_for(pid))
                arm_dx_records_for_thread(pid, th.tid);
        }
        poll_dx_thread_contexts(pid);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    clear_dx_record_breakpoints(pid);
    state.attached.store(false, std::memory_order_release);
    state.polling.store(false, std::memory_order_release);
    state.pid.store(0, std::memory_order_release);
    state.running.store(false, std::memory_order_release);
    diag::log_tagged_fmt("dx_hook",
        "kernel_context_loop_exit pid=%u polls=%llu",
        pid,
        static_cast<unsigned long long>(poll_count));
}

bool start_dx_debug_loop(std::uint32_t pid, std::string& error)
{
    auto& state = dx_debug_state();
    if (state.running.load(std::memory_order_acquire))
    {
        if (state.pid.load(std::memory_order_acquire) == pid && state.attached.load(std::memory_order_acquire))
        {
            for (const auto& th : threads_for(pid))
                arm_dx_records_for_thread(pid, th.tid);
            return true;
        }
        error = "another DirectX kernel context consumer is already active";
        return false;
    }
    state.pid.store(pid, std::memory_order_release);
    state.error.store(ERROR_IO_PENDING, std::memory_order_release);
    state.attached.store(false, std::memory_order_release);
    state.polling.store(true, std::memory_order_release);
    state.running.store(true, std::memory_order_release);
    if (!work_queue::post_service([]() { dx_debug_loop(); }))
    {
        state.polling.store(false, std::memory_order_release);
        state.running.store(false, std::memory_order_release);
        error = "failed to schedule DirectX kernel context consumer";
        return false;
    }
    for (int i = 0; i < 80; ++i)
    {
        if (state.attached.load(std::memory_order_acquire))
            return true;
        if (!state.running.load(std::memory_order_acquire))
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    const DWORD gle = state.error.load(std::memory_order_acquire);
    error = "DirectX kernel context consumer failed or timed out, error=" + std::to_string(static_cast<unsigned long>(gle));
    return false;
}

void stop_dx_debug_loop(std::uint32_t pid)
{
    auto& state = dx_debug_state();
    if (state.pid.load(std::memory_order_acquire) != pid)
        return;
    state.polling.store(false, std::memory_order_release);
    for (int i = 0; i < 80 && state.running.load(std::memory_order_acquire); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
}

std::optional<slot_entry_t> choose_cbuffer_target(std::uint32_t pid, const std::string& api)
{
    auto slots = discover_api(pid, api, true);
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0 && slot.role == "cbuffer_bind" && slot.validated)
            return slot;
    }
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0 && slot.role == "cbuffer_bind")
            return slot;
    }
    return std::nullopt;
}

std::optional<slot_entry_t> choose_vertex_buffer_target(std::uint32_t pid, const std::string& api)
{
    auto slots = discover_api(pid, api, true);
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0 && slot.role == "vertex_buffer_bind" && slot.validated)
            return slot;
    }
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0 && slot.role == "vertex_buffer_bind")
            return slot;
    }
    return std::nullopt;
}

std::filesystem::path default_capture_path(std::uint32_t pid, const std::string& format)
{
    std::ostringstream name;
    name << "dx_render_capture_" << pid << "_" << unix_time_ms() << (format == "rgba" ? ".rgba" : ".png");
    return appdata_re_dir() / name.str();
}

struct window_candidate_t
{
    HWND hwnd = nullptr;
    RECT rect{};
    std::wstring title;
    std::wstring cls;
};

BOOL CALLBACK enum_target_windows(HWND hwnd, LPARAM param)
{
    auto* data = reinterpret_cast<std::pair<std::uint32_t, std::vector<window_candidate_t>>*>(param);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != data->first || !IsWindowVisible(hwnd))
        return TRUE;
    RECT rect{};
    if (!GetWindowRect(hwnd, &rect) || rect.right <= rect.left || rect.bottom <= rect.top)
        return TRUE;
    window_candidate_t candidate;
    candidate.hwnd = hwnd;
    candidate.rect = rect;
    wchar_t title[256] = {};
    wchar_t cls[128] = {};
    GetWindowTextW(hwnd, title, 255);
    GetClassNameW(hwnd, cls, 127);
    candidate.title = title;
    candidate.cls = cls;
    data->second.push_back(std::move(candidate));
    return TRUE;
}

std::optional<window_candidate_t> find_target_window(std::uint32_t pid)
{
    std::pair<std::uint32_t, std::vector<window_candidate_t>> data;
    data.first = pid;
    EnumWindows(enum_target_windows, reinterpret_cast<LPARAM>(&data));
    if (data.second.empty())
        return std::nullopt;
    std::sort(data.second.begin(), data.second.end(), [](const auto& a, const auto& b) {
        const auto area_a = static_cast<std::uint64_t>(a.rect.right - a.rect.left) * static_cast<std::uint64_t>(a.rect.bottom - a.rect.top);
        const auto area_b = static_cast<std::uint64_t>(b.rect.right - b.rect.left) * static_cast<std::uint64_t>(b.rect.bottom - b.rect.top);
        return area_a > area_b;
    });
    return data.second.front();
}

std::string wide_to_utf8(const std::wstring& value)
{
    if (value.empty())
        return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

bool capture_window_rgba(HWND hwnd, std::vector<std::uint8_t>& rgba, int& width, int& height, std::string& method, std::string& error)
{
    RECT rect{};
    if (!GetWindowRect(hwnd, &rect))
    {
        error = "GetWindowRect failed";
        return false;
    }
    width = rect.right - rect.left;
    height = rect.bottom - rect.top;
    if (width <= 0 || height <= 0 || width > 8192 || height > 8192)
    {
        error = "window dimensions are outside the bounded capture range";
        return false;
    }
    HDC window_dc = GetWindowDC(hwnd);
    if (!window_dc)
    {
        error = "GetWindowDC failed";
        return false;
    }
    HDC mem_dc = CreateCompatibleDC(window_dc);
    HBITMAP bitmap = mem_dc ? CreateCompatibleBitmap(window_dc, width, height) : nullptr;
    HGDIOBJ old = bitmap ? SelectObject(mem_dc, bitmap) : nullptr;
    BOOL drawn = FALSE;
    if (bitmap)
    {
        drawn = PrintWindow(hwnd, mem_dc, 0x00000002);
        method = drawn ? "PrintWindow(PW_RENDERFULLCONTENT)" : "BitBlt(window_dc)";
        if (!drawn)
            drawn = BitBlt(mem_dc, 0, 0, width, height, window_dc, 0, 0, SRCCOPY | CAPTUREBLT);
    }
    if (!drawn)
    {
        error = "PrintWindow and BitBlt failed";
        if (old) SelectObject(mem_dc, old);
        if (bitmap) DeleteObject(bitmap);
        if (mem_dc) DeleteDC(mem_dc);
        ReleaseDC(hwnd, window_dc);
        return false;
    }
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = width;
    bi.bmiHeader.biHeight = -height;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    std::vector<std::uint8_t> bgra(static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4u);
    const int lines = GetDIBits(mem_dc, bitmap, 0, static_cast<UINT>(height), bgra.data(), &bi, DIB_RGB_COLORS);
    if (old) SelectObject(mem_dc, old);
    DeleteObject(bitmap);
    DeleteDC(mem_dc);
    ReleaseDC(hwnd, window_dc);
    if (lines != height)
    {
        error = "GetDIBits failed";
        return false;
    }
    rgba.resize(bgra.size());
    for (std::size_t i = 0; i + 3 < bgra.size(); i += 4)
    {
        rgba[i + 0] = bgra[i + 2];
        rgba[i + 1] = bgra[i + 1];
        rgba[i + 2] = bgra[i + 0];
        rgba[i + 3] = 0xFF;
    }
    return true;
}

bool write_binary_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes, std::string& error)
{
    if (bytes.size() > 256ull * 1024ull * 1024ull)
    {
        error = "capture exceeds bounded file size";
        return false;
    }
    std::error_code ec;
    const auto parent = path.parent_path();
    if (!parent.empty())
        std::filesystem::create_directories(parent, ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        error = "failed to open output path";
        return false;
    }
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out)
    {
        error = "failed to write output bytes";
        return false;
    }
    return true;
}

int png_encoder_clsid(CLSID& clsid)
{
    UINT count = 0;
    UINT bytes = 0;
    Gdiplus::GetImageEncodersSize(&count, &bytes);
    if (count == 0 || bytes == 0)
        return -1;
    std::vector<std::uint8_t> storage(bytes);
    auto* encoders = reinterpret_cast<Gdiplus::ImageCodecInfo*>(storage.data());
    if (Gdiplus::GetImageEncoders(count, bytes, encoders) != Gdiplus::Ok)
        return -1;
    for (UINT i = 0; i < count; ++i)
    {
        if (std::wcscmp(encoders[i].MimeType, L"image/png") == 0)
        {
            clsid = encoders[i].Clsid;
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool write_png_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& rgba, int width, int height, std::string& error)
{
    if (width <= 0 || height <= 0 || rgba.size() != static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4u)
    {
        error = "invalid RGBA buffer";
        return false;
    }
    std::error_code ec;
    const auto parent = path.parent_path();
    if (!parent.empty())
        std::filesystem::create_directories(parent, ec);
    Gdiplus::GdiplusStartupInput input;
    ULONG_PTR token = 0;
    if (Gdiplus::GdiplusStartup(&token, &input, nullptr) != Gdiplus::Ok)
    {
        error = "GdiplusStartup failed";
        return false;
    }
    Gdiplus::Bitmap bitmap(width, height, PixelFormat32bppARGB);
    Gdiplus::Rect rect(0, 0, width, height);
    Gdiplus::BitmapData data{};
    if (bitmap.LockBits(&rect, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &data) != Gdiplus::Ok)
    {
        Gdiplus::GdiplusShutdown(token);
        error = "GDI+ bitmap lock failed";
        return false;
    }
    for (int y = 0; y < height; ++y)
    {
        auto* dst = static_cast<std::uint8_t*>(data.Scan0) + static_cast<std::ptrdiff_t>(y) * data.Stride;
        const auto* src = rgba.data() + static_cast<std::size_t>(y) * static_cast<std::size_t>(width) * 4u;
        for (int x = 0; x < width; ++x)
        {
            dst[x * 4 + 0] = src[x * 4 + 2];
            dst[x * 4 + 1] = src[x * 4 + 1];
            dst[x * 4 + 2] = src[x * 4 + 0];
            dst[x * 4 + 3] = src[x * 4 + 3];
        }
    }
    bitmap.UnlockBits(&data);
    CLSID clsid{};
    if (png_encoder_clsid(clsid) < 0)
    {
        Gdiplus::GdiplusShutdown(token);
        error = "PNG encoder not available";
        return false;
    }
    const Gdiplus::Status status = bitmap.Save(path.wstring().c_str(), &clsid, nullptr);
    Gdiplus::GdiplusShutdown(token);
    if (status != Gdiplus::Ok)
    {
        error = "GDI+ PNG save failed";
        return false;
    }
    return true;
}
}

tool_result_t find_device_vtable(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const std::string api = api_param(params);
    diag::log_tagged_fmt("dx_hook", "find_device_vtable enter pid=%u api=%s", scope.pid(), api.c_str());
    if (!api_supported(api, true))
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["supported_apis"] = supported_api_values(true);
        result["discovery_attempted"] = false;
        return tool_result_t::error("Unsupported DX API value.", result);
    }
    if (params.contains("fixture_vtable_va") || params.contains("vtable_va"))
        return find_device_vtable_static_fixture(params, scope.pid(), api, started_ms);
    if (api == "auto")
    {
        json apis = json::array();
        auto push_auto_api = [&](const char* api_name, const char* module_name) {
            if (dx_call_cancelled("find_device_vtable_auto", scope.pid(), started_ms))
                return;
            if (!target_module_loaded(scope.pid(), module_name))
            {
                json skipped = slots_to_result(scope.pid(), api_name, {});
                skipped["discovery_status"] = "module_not_loaded";
                skipped["capability_evidence"] = {
                    {"target_module", module_name},
                    {"target_module_loaded", false},
                    {"dummy_extraction_attempted", false},
                    {"reason", "target_process_has_not_loaded_api_module"}
                };
                apis.push_back(std::move(skipped));
                return;
            }
            apis.push_back(slots_to_result(scope.pid(), api_name, discover_api(scope.pid(), api_name, true)));
        };
        if (!dx_call_cancelled("find_device_vtable_auto_d3d11", scope.pid(), started_ms))
            push_auto_api("d3d11", "d3d11.dll");
        else
            apis.push_back(slots_to_result(scope.pid(), "d3d11", {}));
        if (!dx_call_cancelled("find_device_vtable_auto_d3d12", scope.pid(), started_ms))
            push_auto_api("d3d12", "d3d12.dll");
        else
            apis.push_back(slots_to_result(scope.pid(), "d3d12", {}));
        if (!dx_call_cancelled("find_device_vtable_auto_dxgi", scope.pid(), started_ms))
            push_auto_api("dxgi", "dxgi.dll");
        else
            apis.push_back(slots_to_result(scope.pid(), "dxgi", {}));
        if (!dx_call_cancelled("find_device_vtable_auto_vulkan", scope.pid(), started_ms))
            push_auto_api("vulkan", "vulkan-1.dll");
        else
            apis.push_back(slots_to_result(scope.pid(), "vulkan", {}));
        json result;
        result["process_id"] = scope.pid();
        result["api"] = "auto";
        result["apis"] = std::move(apis);
        diag::log_tagged_fmt("dx_hook", "find_device_vtable exit pid=%u api=auto elapsed_ms=%llu",
                             scope.pid(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::ok(result);
    }
    if (dx_call_cancelled("find_device_vtable_before_explicit", scope.pid(), started_ms))
        return tool_result_t::error("DX vtable discovery cancelled.");
    auto slots = api == "dxgi" ? discover_dxgi_present(scope.pid(), true) : discover_api(scope.pid(), api, true);
    std::size_t resolved = 0;
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0)
            ++resolved;
    }
    diag::log_tagged_fmt("dx_hook", "find_device_vtable exit pid=%u api=%s slots=%zu resolved=%zu elapsed_ms=%llu",
                         scope.pid(),
                         api.c_str(),
                         slots.size(),
                         resolved,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(slots_to_result(scope.pid(), api, slots));
}

tool_result_t hook_manage(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    if (action == "remove")
    {
        diag::log_tagged_fmt("dx_hook", "hook_manage remove_enter action=%s", action.c_str());
        if (!unsafe_confirmed(p))
            return unsafe_required("dx_hook_manage remove");
        active_process_scope_t scope(p);
        if (!scope.ok())
            return tool_result_t::error(scope.error());
        diag::log_tagged_fmt("dx_hook", "hook_manage remove_scope pid=%u", scope.pid());
        std::size_t cleared = 0;
        for (const auto& record : store::list_dx_hooks(scope.pid()))
        {
            diag::log_tagged_fmt("dx_hook", "hook_manage remove_record pid=%u hook_id=%s action=%s target=%s tids=%zu hw_slot=%d",
                                 scope.pid(),
                                 record.id.c_str(),
                                 record.action.c_str(),
                                 sa_format_address(record.target_va).c_str(),
                                 record.tids.size(),
                                 record.hw_slot);
            for (auto tid : record.tids)
            {
                if (driver_bridge::clear_hardware_breakpoint(tid, record.hw_slot))
                    ++cleared;
            }
        }
        const std::size_t removed = store::remove_dx_hooks(scope.pid());
        stop_dx_debug_loop(scope.pid());
        diag::log_tagged_fmt("dx_hook", "hook_manage remove_exit pid=%u removed=%zu cleared=%zu elapsed_ms=%llu",
                             scope.pid(),
                             removed,
                             cleared,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        json result;
        result["process_id"] = scope.pid();
        result["removed_count"] = removed;
        result["cleared_breakpoints"] = cleared;
        return tool_result_t::ok("DX hooks removed.", result);
    }

    if (action != "draw" && action != "present")
        return compat_unknown_action("dx_hook_manage", action);
    if (!unsafe_confirmed(p))
        return unsafe_required("dx_hook_manage");

    active_process_scope_t scope(p);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    const std::string api = api_param(p);
    const std::string callback_mode = lower_ascii(string_param(p, "callback_mode", "hw_bp"));
    const bool snapshot_only = callback_mode == "snapshot" || callback_mode == "polling";
    const bool hwbp_mode = callback_mode == "hw_bp" || callback_mode == "hwbp" || callback_mode == "hardware_breakpoint" || callback_mode == "kernel_context";
    if (!api_supported(api, true))
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["callback_mode"] = callback_mode;
        result["supported_apis"] = supported_api_values(true);
        result["hook_target_resolution_attempted"] = false;
        return tool_result_t::error("Unsupported DX API value.", result);
    }
    if (snapshot_only)
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["callback_mode"] = callback_mode;
        result["supported_callback_modes"] = {"hw_bp", "hwbp", "hardware_breakpoint", "kernel_context", "vmt_patch"};
        result["snapshot_backend"] = {
            {"available", false},
            {"reason", "bounded snapshots are diagnostic candidates, not hook hit evidence"}
        };
        return tool_result_t::error("callback_mode='snapshot'/'polling' cannot install a DX hook.", result);
    }
    if (!snapshot_only && !hwbp_mode && callback_mode != "vmt_patch")
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["callback_mode"] = callback_mode;
        result["supported_callback_modes"] = {"hw_bp", "hwbp", "hardware_breakpoint", "kernel_context", "vmt_patch"};
        result["debug_event_consumer_capability"] = {
            {"available", false},
            {"reason", "the available backend consumes hardware-breakpoint state through kernel thread contexts, not a Windows debug-event exception stream"}
        };
        return tool_result_t::error("Unsupported DX callback_mode for this backend.", result);
    }
    if (hwbp_mode && !driver_bridge::using_kernel_driver())
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["callback_mode"] = callback_mode;
        result["capture_backend"] = "none";
        result["kernel_context_consumer"] = false;
        result["capability"] = {
            {"available", false},
            {"reason", "DX hardware-breakpoint hooks require the kernel driver thread-context backend"}
        };
        return tool_result_t::error("DX kernel-context hardware-breakpoint backend is unavailable.", result);
    }
    diag::log_tagged_fmt("dx_hook", "hook_manage enter pid=%u action=%s api=%s callback_mode=%s snapshot_only=%d",
                         scope.pid(),
                         action.c_str(),
                         api.c_str(),
                         callback_mode.c_str(),
                         snapshot_only ? 1 : 0);
    const std::uint64_t target_start_ms = GetTickCount64();
    const auto target = choose_hook_target(scope.pid(), api, action, snapshot_only);
    diag::log_tagged_fmt("dx_hook", "hook_manage target pid=%u action=%s ok=%d name=%s target_va=%s elapsed_ms=%llu",
                         scope.pid(),
                         action.c_str(),
                         target && target->target_va != 0 ? 1 : 0,
                         target ? target->name.c_str() : "",
                         target && target->target_va != 0 ? sa_format_address(target->target_va).c_str() : "0x0",
                         static_cast<unsigned long long>(GetTickCount64() - target_start_ms));
    if (!target || target->target_va == 0)
        return tool_result_t::error("Could not resolve a hook target for requested API/action.");
    if (!target->validated)
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["target_name"] = target->name;
        result["target_va"] = sa_format_address(target->target_va);
        result["validation_reason"] = target->validation_reason.empty() ? "unvalidated_target" : target->validation_reason;
        result["target_evidence"] = target->capability_evidence;
        result["allow_unvalidated_target"] = false;
        result["fail_closed"] = true;
        return tool_result_t::error("Resolved hook target did not pass API/ABI validation.", result);
    }

    const bool capture_cbuffers = bool_param(p, "capture_cbuffers", target->api_family != "vulkan");
    const bool capture_vertex_buffers = bool_param(p, "capture_vertex_buffers", false);
    if (capture_vertex_buffers && target->api_family == "vulkan")
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["target_name"] = target->name;
        result["target_va"] = sa_format_address(target->target_va);
        result["capture_vertex_buffers"] = true;
        result["capability"] = {
            {"available", false},
            {"reason", "Vulkan vertex buffer state is command-buffer state and is not externally recoverable from vkCmdDraw loader export arguments"},
            {"supported_gpu_apis", {"d3d11", "d3d12"}}
        };
        return tool_result_t::error("capture_vertex_buffers is not supported for Vulkan draw hooks without a command-buffer decoder.", result);
    }
    if (capture_vertex_buffers && snapshot_only)
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["callback_mode"] = callback_mode;
        result["capture_vertex_buffers"] = true;
        result["capability"] = {
            {"available", false},
            {"reason", "vertex-buffer capture requires live IASetVertexBuffers breakpoint context; bounded snapshots cannot recover current bind-call arguments"}
        };
        return tool_result_t::error("capture_vertex_buffers requires a live hardware-breakpoint context backend.", result);
    }

    if (callback_mode == "vmt_patch")
    {
        if (target->api_family == "vulkan")
        {
            json result;
            result["process_id"] = scope.pid();
            result["target_name"] = target->name;
            result["target_va"] = sa_format_address(target->target_va);
            result["callback_mode"] = callback_mode;
            result["capability"] = "vmt_patch_requires_com_vtable_target";
            return tool_result_t::error("callback_mode='vmt_patch' is only valid for COM vtable based D3D/DXGI targets.", result);
        }
        std::uint64_t callback_va = 0;
        std::uint64_t vtable_va = 0;
        if (!parse_address_param(p, "callback_va", callback_va) || callback_va == 0)
        {
            json result;
            result["process_id"] = scope.pid();
            result["target_name"] = target->name;
            result["target_slot"] = target->slot;
            result["target_va"] = sa_format_address(target->target_va);
            result["required"] = {"callback_va", "vtable_va"};
            result["capability"] = "vmt_patch_requires_caller_supplied_in_process_callback";
            return tool_result_t::error("'callback_va' is required for callback_mode='vmt_patch'.", result);
        }
        if (!parse_address_param(p, "vtable_va", vtable_va) || vtable_va == 0)
        {
            json result;
            result["process_id"] = scope.pid();
            result["target_name"] = target->name;
            result["target_slot"] = target->slot;
            result["target_va"] = sa_format_address(target->target_va);
            result["callback_va"] = sa_format_address(callback_va);
            result["required"] = {"vtable_va"};
            result["capability"] = "vmt_patch_requires_proven_target_vtable";
            return tool_result_t::error("'vtable_va' is required for callback_mode='vmt_patch'.", result);
        }
        driver_bridge::memory_region_t callback_region{};
        if (!query_region(scope.pid(), callback_va, callback_region) || !is_committed(callback_region) || !is_executable(callback_region) || is_guarded(callback_region))
        {
            json result;
            result["process_id"] = scope.pid();
            result["target_name"] = target->name;
            result["target_slot"] = target->slot;
            result["target_va"] = sa_format_address(target->target_va);
            result["callback_va"] = sa_format_address(callback_va);
            result["callback_region"] = region_json(callback_region);
            result["capability"] = "vmt_patch_callback_must_be_executable_in_target_process";
            return tool_result_t::error("'callback_va' must point to executable target-process code.", result);
        }
        std::uint64_t vtable_slot_value = 0;
        const std::uint64_t vtable_slot_va = vtable_va + static_cast<std::uint64_t>(target->slot) * sizeof(std::uint64_t);
        if (!read_u64(scope.pid(), vtable_slot_va, vtable_slot_value) || vtable_slot_value != target->target_va)
        {
            json result;
            result["process_id"] = scope.pid();
            result["target_name"] = target->name;
            result["target_slot"] = target->slot;
            result["target_va"] = sa_format_address(target->target_va);
            result["vtable_va"] = sa_format_address(vtable_va);
            result["vtable_slot_va"] = sa_format_address(vtable_slot_va);
            result["observed_slot_value"] = vtable_slot_value ? json(sa_format_address(vtable_slot_value)) : json(nullptr);
            result["capability"] = "vmt_patch_requires_matching_target_vtable_slot";
            return tool_result_t::error("Supplied vtable_va does not contain the resolved DX target at the requested slot.", result);
        }
        json vmt_params;
        vmt_params["action"] = "install";
        vmt_params["process_id"] = scope.pid();
        vmt_params["vtable_va"] = sa_format_address(vtable_va);
        vmt_params["slot"] = target->slot;
        vmt_params["callback_va"] = sa_format_address(callback_va);
        vmt_params["method"] = lower_ascii(string_param(p, "vmt_method", string_param(p, "method", "patch_vtable")));
        vmt_params["confirm_unsafe"] = true;
        std::uint64_t object_va = 0;
        if (parse_address_param(p, "object_va", object_va) && object_va != 0)
            vmt_params["object_va"] = sa_format_address(object_va);
        if (p.contains("copy_slots"))
            vmt_params["copy_slots"] = p["copy_slots"];
        auto vmt_result = re::vmt::hook_manage(vmt_params);
        json result = vmt_result.data.is_null() ? json::object() : vmt_result.data;
        result["process_id"] = scope.pid();
        result["dx_action"] = action;
        result["dx_api"] = api;
        result["dx_target_name"] = target->name;
        result["dx_target_va"] = sa_format_address(target->target_va);
        result["dx_target_validation"] = target->capability_evidence;
        result["callback_mode"] = callback_mode;
        result["capture_backend"] = "vmt_patch";
        if (!vmt_result.success)
            return tool_result_t::error(vmt_result.text, result);
        return tool_result_t::ok("DX VMT patch installed through VMT hook manager.", result);
    }

    const int hw_slot = static_cast<int>(numeric_param(p, "hw_slot", action == "draw" ? 1 : 0, 0, 3));
    store::dx_hook_record_t record;
    record.id = store::next_id("dx");
    record.pid = scope.pid();
    record.api = api == "auto" ? target->module_name : api;
    record.action = action;
    record.target_va = target->target_va;
    record.hw_slot = hw_slot;
    record.capture_cbuffers = capture_cbuffers;
    record.capture_vertex_buffers = capture_vertex_buffers;
    record.max_captures = static_cast<std::uint32_t>(numeric_param(p, "max_captures", 16, 1, 1024));
    record.created_ms = unix_time_ms();

    std::optional<slot_entry_t> required_cbuffer_target;
    if (action == "draw" && record.capture_cbuffers)
    {
        const std::uint64_t bind_start_ms = GetTickCount64();
        required_cbuffer_target = choose_cbuffer_target(scope.pid(), api);
        diag::log_tagged_fmt("dx_hook", "hook_manage cbuffer_preflight pid=%u ok=%d name=%s target_va=%s elapsed_ms=%llu",
                             scope.pid(),
                             required_cbuffer_target && required_cbuffer_target->target_va != 0 ? 1 : 0,
                             required_cbuffer_target ? required_cbuffer_target->name.c_str() : "",
                             required_cbuffer_target && required_cbuffer_target->target_va != 0 ? sa_format_address(required_cbuffer_target->target_va).c_str() : "0x0",
                             static_cast<unsigned long long>(GetTickCount64() - bind_start_ms));
        if (!required_cbuffer_target || required_cbuffer_target->target_va == 0 || !required_cbuffer_target->validated)
        {
            json result;
            result["process_id"] = scope.pid();
            result["api"] = api;
            result["action"] = action;
            result["capture_cbuffers"] = true;
            result["target_name"] = target->name;
            result["target_va"] = sa_format_address(target->target_va);
            result["cbuffer_bind_target"] = required_cbuffer_target ? json{
                {"name", required_cbuffer_target->name},
                {"target_va", required_cbuffer_target->target_va ? json(sa_format_address(required_cbuffer_target->target_va)) : json(nullptr)},
                {"validated", required_cbuffer_target->validated},
                {"validation_reason", required_cbuffer_target->validation_reason},
                {"evidence", required_cbuffer_target->capability_evidence}
            } : json(nullptr);
            result["capability"] = {
                {"available", false},
                {"reason", "capture_cbuffers requires a validated cbuffer bind target for live bind-call context"}
            };
            return tool_result_t::error("Could not resolve a validated cbuffer bind target.", result);
        }
    }

    std::optional<slot_entry_t> required_vertex_target;
    if (action == "draw" && record.capture_vertex_buffers)
    {
        const std::uint64_t vb_start_ms = GetTickCount64();
        required_vertex_target = choose_vertex_buffer_target(scope.pid(), api);
        diag::log_tagged_fmt("dx_hook", "hook_manage vertex_preflight pid=%u ok=%d name=%s target_va=%s elapsed_ms=%llu",
                             scope.pid(),
                             required_vertex_target && required_vertex_target->target_va != 0 ? 1 : 0,
                             required_vertex_target ? required_vertex_target->name.c_str() : "",
                             required_vertex_target && required_vertex_target->target_va != 0 ? sa_format_address(required_vertex_target->target_va).c_str() : "0x0",
                             static_cast<unsigned long long>(GetTickCount64() - vb_start_ms));
        if (!required_vertex_target || required_vertex_target->target_va == 0 || !required_vertex_target->validated)
        {
            json result;
            result["process_id"] = scope.pid();
            result["api"] = api;
            result["action"] = action;
            result["capture_vertex_buffers"] = true;
            result["target_name"] = target->name;
            result["target_va"] = sa_format_address(target->target_va);
            result["vertex_bind_target"] = required_vertex_target ? json{
                {"name", required_vertex_target->name},
                {"target_va", required_vertex_target->target_va ? json(sa_format_address(required_vertex_target->target_va)) : json(nullptr)},
                {"validated", required_vertex_target->validated},
                {"validation_reason", required_vertex_target->validation_reason},
                {"evidence", required_vertex_target->capability_evidence}
            } : json(nullptr);
            result["capability"] = {
                {"available", false},
                {"reason", "capture_vertex_buffers requires a validated IASetVertexBuffers target for live bind-call context"}
            };
            return tool_result_t::error("Could not resolve a validated vertex-buffer bind target.", result);
        }
    }

    std::vector<store::dx_hook_record_t> prepared_records;
    std::size_t primary_threads_seen = 0;
    for (const auto& th : threads_for(scope.pid()))
    {
        ++primary_threads_seen;
        if (driver_bridge::set_hardware_breakpoint(th.tid, hw_slot, target->target_va, 0, 0))
            record.tids.push_back(th.tid);
    }
    diag::log_tagged_fmt("dx_hook", "hook_manage primary_record pid=%u action=%s target_va=%s threads_seen=%zu armed=%zu",
                         scope.pid(),
                         action.c_str(),
                         sa_format_address(target->target_va).c_str(),
                         primary_threads_seen,
                         record.tids.size());
    if (record.tids.empty())
    {
        clear_dx_record_breakpoints(record);
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["target_name"] = target->name;
        result["target_va"] = sa_format_address(target->target_va);
        result["threads_seen"] = primary_threads_seen;
        result["armed_threads"] = 0;
        result["hook_record_persisted"] = false;
        result["capture_backend"] = "none";
        result["kernel_context_consumer"] = false;
        result["snapshot_fallback_used"] = false;
        result["capability"] = {
            {"available", false},
            {"reason", "hardware breakpoints could not be armed on any target thread"}
        };
        return tool_result_t::error("DX hook could not arm a hardware breakpoint on any target thread.", result);
    }
    prepared_records.push_back(record);

    json auxiliary = nullptr;
    json auxiliary_vertex = nullptr;
    if (action == "draw" && record.capture_cbuffers)
    {
        auto bind_target = required_cbuffer_target;
        diag::log_tagged_fmt("dx_hook", "hook_manage cbuffer_target pid=%u ok=%d name=%s target_va=%s elapsed_ms=%llu",
                             scope.pid(),
                             bind_target && bind_target->target_va != 0 ? 1 : 0,
                             bind_target ? bind_target->name.c_str() : "",
                             bind_target && bind_target->target_va != 0 ? sa_format_address(bind_target->target_va).c_str() : "0x0",
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (bind_target && bind_target->target_va != 0)
        {
            store::dx_hook_record_t bind_record;
            bind_record.id = store::next_id("dx");
            bind_record.pid = scope.pid();
            bind_record.api = api == "auto" ? bind_target->module_name : api;
            bind_record.action = "cbuffer_bind";
            bind_record.target_va = bind_target->target_va;
            bind_record.hw_slot = hw_slot == 3 ? 0 : hw_slot + 1;
            bind_record.capture_cbuffers = true;
            bind_record.capture_vertex_buffers = false;
            bind_record.max_captures = record.max_captures;
            bind_record.created_ms = unix_time_ms();
            std::size_t bind_threads_seen = 0;
            for (const auto& th : threads_for(scope.pid()))
            {
                ++bind_threads_seen;
                if (driver_bridge::set_hardware_breakpoint(th.tid, bind_record.hw_slot, bind_target->target_va, 0, 0))
                    bind_record.tids.push_back(th.tid);
            }
            diag::log_tagged_fmt("dx_hook", "hook_manage cbuffer_record pid=%u target_va=%s threads_seen=%zu armed=%zu",
                                 scope.pid(),
                                 sa_format_address(bind_target->target_va).c_str(),
                                 bind_threads_seen,
                                 bind_record.tids.size());
            if (bind_record.tids.empty())
            {
                clear_dx_record_breakpoints(prepared_records);
                clear_dx_record_breakpoints(bind_record);
                json result;
                result["process_id"] = scope.pid();
                result["api"] = api;
                result["action"] = action;
                result["capture_cbuffers"] = true;
                result["target_name"] = bind_target->name;
                result["target_va"] = sa_format_address(bind_target->target_va);
                result["threads_seen"] = bind_threads_seen;
                result["armed_threads"] = 0;
                result["hook_record_persisted"] = false;
                result["capture_backend"] = "none";
                result["kernel_context_consumer"] = false;
                result["snapshot_fallback_used"] = false;
                result["capability"] = {
                    {"available", false},
                    {"reason", "cbuffer capture requires a live hardware-breakpoint bind-call context"}
                };
                return tool_result_t::error("DX cbuffer bind hook could not arm a hardware breakpoint on any target thread.", result);
            }
            prepared_records.push_back(bind_record);
            auxiliary = dx_record_json(bind_record);
            auxiliary["target_name"] = bind_target->name;
            auxiliary["target_hint"] = bind_target->hint;
        }
    }
    if (action == "draw" && record.capture_vertex_buffers)
    {
        const std::uint64_t vb_start_ms = GetTickCount64();
        auto vb_target = required_vertex_target;
        diag::log_tagged_fmt("dx_hook", "hook_manage vertex_target pid=%u ok=%d name=%s target_va=%s elapsed_ms=%llu",
                             scope.pid(),
                             vb_target && vb_target->target_va != 0 ? 1 : 0,
                             vb_target ? vb_target->name.c_str() : "",
                             vb_target && vb_target->target_va != 0 ? sa_format_address(vb_target->target_va).c_str() : "0x0",
                             static_cast<unsigned long long>(GetTickCount64() - vb_start_ms));
        if (vb_target && vb_target->target_va != 0)
        {
            store::dx_hook_record_t vb_record;
            vb_record.id = store::next_id("dx");
            vb_record.pid = scope.pid();
            vb_record.api = api == "auto" ? vb_target->module_name : api;
            vb_record.action = "vertex_buffer_bind";
            vb_record.target_va = vb_target->target_va;
            vb_record.hw_slot = hw_slot >= 2 ? 0 : hw_slot + 2;
            vb_record.capture_cbuffers = false;
            vb_record.capture_vertex_buffers = true;
            vb_record.max_captures = record.max_captures;
            vb_record.created_ms = unix_time_ms();
            std::size_t vb_threads_seen = 0;
            for (const auto& th : threads_for(scope.pid()))
            {
                ++vb_threads_seen;
                if (driver_bridge::set_hardware_breakpoint(th.tid, vb_record.hw_slot, vb_target->target_va, 0, 0))
                    vb_record.tids.push_back(th.tid);
            }
            diag::log_tagged_fmt("dx_hook", "hook_manage vertex_record pid=%u target_va=%s threads_seen=%zu armed=%zu",
                                 scope.pid(),
                                 sa_format_address(vb_target->target_va).c_str(),
                                 vb_threads_seen,
                                 vb_record.tids.size());
            if (vb_record.tids.empty())
            {
                clear_dx_record_breakpoints(prepared_records);
                clear_dx_record_breakpoints(vb_record);
                json result;
                result["process_id"] = scope.pid();
                result["api"] = api;
                result["action"] = action;
                result["capture_vertex_buffers"] = true;
                result["target_name"] = vb_target->name;
                result["target_va"] = sa_format_address(vb_target->target_va);
                result["threads_seen"] = vb_threads_seen;
                result["armed_threads"] = 0;
                result["hook_record_persisted"] = false;
                result["capture_backend"] = "none";
                result["kernel_context_consumer"] = false;
                result["snapshot_fallback_used"] = false;
                result["capability"] = {
                    {"available", false},
                    {"reason", "vertex-buffer capture requires a live hardware-breakpoint bind-call context"}
                };
                return tool_result_t::error("DX vertex-buffer bind hook could not arm a hardware breakpoint on any target thread.", result);
            }
            prepared_records.push_back(vb_record);
            auxiliary_vertex = dx_record_json(vb_record);
            auxiliary_vertex["target_name"] = vb_target->name;
            auxiliary_vertex["target_hint"] = vb_target->hint;
        }
    }

    std::vector<std::string> installed_hook_ids;
    for (const auto& prepared : prepared_records)
    {
        store::add_dx_hook(prepared);
        installed_hook_ids.push_back(prepared.id);
        if (prepared.id == record.id)
            record = prepared;
    }

    std::string debug_error;
    bool debug_started = start_dx_debug_loop(scope.pid(), debug_error);
    for (const auto& updated : store::list_dx_hooks(scope.pid()))
    {
        if (updated.id == record.id)
        {
            record = updated;
            break;
        }
    }
    std::size_t total_armed_threads = armed_thread_count_for_ids(scope.pid(), installed_hook_ids);
    if (debug_started && total_armed_threads == 0)
    {
        debug_error = "hardware breakpoints could not be armed on any target thread";
        stop_dx_debug_loop(scope.pid());
        debug_started = false;
        for (const auto& updated : store::list_dx_hooks(scope.pid()))
        {
            if (updated.id == record.id)
            {
                record = updated;
                break;
            }
        }
    }
    if (!debug_started)
    {
        for (const auto& updated : store::list_dx_hooks(scope.pid()))
        {
            if (std::find(installed_hook_ids.begin(), installed_hook_ids.end(), updated.id) != installed_hook_ids.end())
                clear_dx_record_breakpoints(updated);
        }
        stop_dx_debug_loop(scope.pid());
        for (const auto& id : installed_hook_ids)
            store::remove_dx_hook(id);
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["action"] = action;
        result["capture_cbuffers"] = record.capture_cbuffers;
        result["capture_vertex_buffers"] = record.capture_vertex_buffers;
        result["callback_mode"] = callback_mode;
        result["fallback_reason"] = debug_error.empty() ? "hardware breakpoint backend unavailable" : debug_error;
        result["installed_hook_ids_removed"] = installed_hook_ids;
        result["capture_backend"] = "none";
        result["kernel_context_consumer"] = false;
        result["snapshot_fallback_used"] = false;
        result["capability"] = {
            {"available", false},
            {"reason", "DX hooks require an active kernel-context breakpoint consumer; bounded snapshots are not accepted as hook evidence"}
        };
        return tool_result_t::error("DX hook could not be armed with kernel-context capture.", result);
    }

    json result = dx_record_json(record);
    result["hook_id"] = record.id;
    result["target_name"] = target->name;
    result["target_hint"] = target->hint;
    result["callback_mode"] = callback_mode;
    result["capture_backend"] = "hardware_breakpoint_kernel_context";
    result["debug_event_consumer"] = false;
    result["kernel_context_consumer"] = true;
    result["fallback_reason"] = nullptr;
    result["armed_threads"] = total_armed_threads;
    result["auxiliary_cbuffer_hook"] = std::move(auxiliary);
    result["auxiliary_vertex_buffer_hook"] = std::move(auxiliary_vertex);
    result["snapshot_capture_seeded"] = false;
    result["snapshot_capture_count"] = 0;
    result["event_capture_count"] = record.captures.size();
    result["functional_snapshot_evidence"] = false;
    result["functional_event_evidence"] = !record.captures.empty();
    result["debug_event_consumer_capability"] = {
        {"available", false},
        {"reason", "driver debug event channel exposes image/process lifecycle events, not breakpoint exception contexts"},
        {"live_hit_backend", "kernel_thread_context_polling"}
    };
    diag::log_tagged_fmt("dx_hook", "hook_manage exit pid=%u action=%s hook_id=%s debug_started=%d armed_threads=%zu elapsed_ms=%llu",
                         scope.pid(),
                         action.c_str(),
                         record.id.c_str(),
                         debug_started ? 1 : 0,
                         total_armed_threads,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("DX hook armed with kernel-context capture.", result);
}

tool_result_t list_bound_cbuffers(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const std::string api = api_param(params);
    if (!api_supported(api, true))
    {
        json result;
        result["process_id"] = scope.pid();
        result["api"] = api;
        result["supported_apis"] = supported_api_values(true);
        result["count"] = 0;
        result["actual_bound_count"] = 0;
        result["fallback_count"] = 0;
        return tool_result_t::error("Unsupported DX API value.", result);
    }
    const bool include_snapshot_fallback = bool_param(params, "include_snapshot_fallback", false);
    json actual = json::array();
    json fallback = json::array();
    std::set<std::uint64_t> actual_seen;
    std::set<std::uint64_t> fallback_seen;
    for (const auto& record : store::list_dx_hooks(scope.pid()))
    {
        for (const auto& cap : record.captures)
        {
            if (cap.contains("cbuffers") && cap["cbuffers"].is_array())
            {
                const std::string backend = cap.value("backend", std::string());
                const std::string event_type = cap.value("event_type", std::string());
                const bool live_bound = event_type == "breakpoint_hit" &&
                                        record.action == "cbuffer_bind" &&
                                        backend == "hardware_breakpoint_kernel_context";
                for (const auto& cb : cap["cbuffers"])
                {
                    json row = cb;
                    row["bound_state_provenance"] = live_bound ? "live_cbuffer_bind_breakpoint_context" : "fallback_snapshot_or_memory_candidate";
                    row["evidence_class"] = live_bound ? "live_breakpoint_cbuffer_bind_call_args" : "bounded_diagnostic_candidate";
                    row["diagnostic_only"] = !live_bound;
                    row["capture_backend"] = backend.empty() ? json(nullptr) : json(backend);
                    row["capture_event_type"] = event_type.empty() ? json(nullptr) : json(event_type);
                    row["capture_hook_id"] = record.id;
                    row["capture_action"] = record.action;
                    row["bind_call_args_source"] = live_bound ? json("thread_context_registers") : json(nullptr);
                    if (live_bound)
                        append_unique_candidate(actual, row, actual_seen, 128);
                    else
                        append_unique_candidate(fallback, row, fallback_seen, 128);
                }
            }
        }
    }
    if (include_snapshot_fallback && fallback.empty())
    {
        refresh_snapshot_records(scope.pid(), "list_bound_cbuffers requested bounded fallback evidence", &params, true);
        for (const auto& record : store::list_dx_hooks(scope.pid()))
        {
            for (const auto& cap : record.captures)
            {
                if (!cap.contains("cbuffers") || !cap["cbuffers"].is_array())
                    continue;
                const std::string event_type = cap.value("event_type", std::string());
                if (event_type == "breakpoint_hit")
                    continue;
                for (const auto& cb : cap["cbuffers"])
                {
                    json row = cb;
                    row["bound_state_provenance"] = "bounded_snapshot_fallback";
                    row["evidence_class"] = "bounded_diagnostic_candidate";
                    row["diagnostic_only"] = true;
                    row["capture_backend"] = cap.value("backend", std::string());
                    row["capture_event_type"] = event_type.empty() ? json(nullptr) : json(event_type);
                    row["capture_hook_id"] = record.id;
                    row["capture_action"] = record.action;
                    row["bind_call_args_source"] = nullptr;
                    append_unique_candidate(fallback, row, fallback_seen, 128);
                }
            }
        }
    }
    if (include_snapshot_fallback)
    {
        collect_explicit_cbuffer_candidates(scope.pid(), params, fallback, fallback_seen, 128, "explicit_cbuffer_candidate");
        stamp_candidate_rows(fallback, "bounded_diagnostic_candidate", "explicit_or_bounded_diagnostic_candidate", true, "");
    }
    json combined = json::array();
    std::set<std::uint64_t> combined_seen;
    for (const auto& row : actual)
        append_unique_candidate(combined, row, combined_seen, 128);
    if (include_snapshot_fallback)
    {
        for (const auto& row : fallback)
            append_unique_candidate(combined, row, combined_seen, 128);
    }
    json result;
    result["process_id"] = scope.pid();
    result["api"] = api;
    result["cbuffers"] = std::move(combined);
    result["count"] = result["cbuffers"].size();
    result["actual_bound_cbuffers"] = std::move(actual);
    result["actual_bound_count"] = result["actual_bound_cbuffers"].size();
    result["fallback_cbuffers"] = include_snapshot_fallback ? std::move(fallback) : json::array();
    result["fallback_count"] = result["fallback_cbuffers"].size();
    result["include_snapshot_fallback"] = include_snapshot_fallback;
    result["capture_source"] = result["actual_bound_count"].get<std::size_t>() != 0 ? "hardware_breakpoint_bind_context" :
                               (result["fallback_count"].get<std::size_t>() != 0 ? "bounded_snapshot_or_explicit_candidate" : "none");
    return tool_result_t::ok(result);
}

tool_result_t identify_bone_buffer(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const double world_max = number_param(params, "world_unit_max", 100000.0, 1.0, 1000000000.0);
    const std::uint32_t min_bones = static_cast<std::uint32_t>(numeric_param(params, "min_bones", 4, 1, 1024));
    const std::uint32_t max_bones = static_cast<std::uint32_t>(numeric_param(params, "max_bones", 256, min_bones, 4096));
    const bool allow_memory_fallback = bool_param(params, "allow_memory_fallback", false);
    bool used_memory_fallback = false;
    refresh_snapshot_records(scope.pid(), "identify_bone_buffer requested current bounded evidence", &params, allow_memory_fallback);
    json candidates = json::array();
    std::set<std::uint64_t> evaluated;
    auto evaluate_candidate = [&](const json& source, const std::string& source_name) {
        if (!source.contains("va"))
            return;
        std::uint64_t va = 0;
        if (!parse_u64_value(source["va"], va) || va == 0)
            return;
        if (!evaluated.insert(va).second)
            return;
        std::uint64_t size = 0;
        if (source.contains("size"))
            parse_u64_value(source["size"], size);
        if (size == 0)
        {
            driver_bridge::memory_region_t region{};
            if (query_region(scope.pid(), va, region) && region.base + region.size > va)
                size = region.base + region.size - va;
        }
        if (size < 64ull * min_bones)
            return;
        std::vector<std::uint8_t> bytes;
        const std::size_t read_size = static_cast<std::size_t>(std::min<std::uint64_t>(size, std::max<std::uint64_t>(64ull * max_bones + 256ull, 8192ull)));
        if (!read_bytes(scope.pid(), va, read_size, bytes) || bytes.size() < 48ull * min_bones)
            return;
        matrix_decode_result_t decoded = best_matrix_decode_run(bytes, world_max, max_bones, 512);
        if (decoded.count < min_bones)
            return;
        json row;
        row["cbuffer_slot"] = source.contains("slot") ? source["slot"] : json(nullptr);
        row["va"] = sa_format_address(va + decoded.offset);
        row["base_va"] = sa_format_address(va);
        row["decode_offset"] = decoded.offset;
        row["bone_count"] = decoded.count;
        row["matrix_count"] = decoded.count;
        row["bone_count_semantics"] = "matrix_run_count_not_validated_skeleton_bone_count";
        row["matrix_size"] = decoded.stride;
        row["decode"] = decoded.decode;
        row["xor_key"] = decoded.xor_key == 0 ? json(nullptr) : json(sa_format_address(decoded.xor_key));
        row["candidate_kind"] = "matrix_run_evidence";
        row["proven_skeleton"] = false;
        row["skeleton_hierarchy_provenance"] = nullptr;
        row["model_provenance"] = nullptr;
        row["provenance_limit"] = "no hierarchy, parent-index, bone-name, mesh, or model ownership evidence is recovered by this tool";
        row["matrix_type"] = decoded.first_eval.type;
        row["matrix_orientation"] = decoded.first_eval.orientation;
        row["determinant3x3"] = decoded.first_eval.determinant;
        row["orthogonality_error"] = decoded.first_eval.orthogonality_error;
        row["row_orthogonality_error"] = decoded.first_eval.row_orthogonality_error;
        row["column_orthogonality_error"] = decoded.first_eval.column_orthogonality_error;
        row["inverse_residual3x3"] = decoded.first_eval.inverse_residual;
        row["row_translation_abs"] = decoded.first_eval.row_translation_abs;
        row["column_translation_abs"] = decoded.first_eval.column_translation_abs;
        row["identity_error"] = decoded.first_eval.identity_error;
        double source_confidence = 0.40;
        if (source.contains("confidence") && source["confidence"].is_number())
            source_confidence = source["confidence"].get<double>();
        double confidence = source_confidence + static_cast<double>(decoded.count) / static_cast<double>(std::max<std::uint32_t>(max_bones, 1)) * 0.42;
        if (source_name == "dx_hook_cbuffer_capture")
            confidence += 0.18;
        else if (source_name == "explicit_cbuffer_candidate")
            confidence += 0.10;
        else if (source_name == "bounded_private_memory_matrix_scan")
            confidence -= 0.06;
        if (decoded.decode == "xor32_float32")
            confidence += 0.06;
        if (decoded.offset != 0)
            confidence -= 0.03;
        row["confidence"] = std::min(0.99, std::max(0.0, confidence));
        row["source"] = source_name;
        row["evidence"] = source;
        candidates.push_back(std::move(row));
    };

    for (const auto& cb : stored_cbuffer_rows(scope.pid()))
    {
        if (candidates.size() >= 64)
            break;
        evaluate_candidate(cb, "dx_hook_cbuffer_capture");
    }

    for (const auto& cb : explicit_cbuffer_candidates(scope.pid(), params, 64, "explicit_cbuffer_candidate"))
    {
        if (candidates.size() >= 64)
            break;
        evaluate_candidate(cb, "explicit_cbuffer_candidate");
    }

    if (candidates.empty() && allow_memory_fallback)
    {
        json scanned = scan_memory_cbuffer_candidates(scope.pid(), 64, world_max, 512);
        used_memory_fallback = !scanned.empty();
        for (const auto& row : scanned)
            evaluate_candidate(row, "bounded_private_memory_matrix_scan");
    }
    std::sort(candidates.begin(), candidates.end(), [](const json& a, const json& b) {
        const double ca = a.contains("confidence") && a["confidence"].is_number() ? a["confidence"].get<double>() : 0.0;
        const double cb = b.contains("confidence") && b["confidence"].is_number() ? b["confidence"].get<double>() : 0.0;
        if (ca != cb)
            return ca > cb;
        const std::uint64_t ba = a.contains("bone_count") && a["bone_count"].is_number_unsigned() ? a["bone_count"].get<std::uint64_t>() : 0;
        const std::uint64_t bb = b.contains("bone_count") && b["bone_count"].is_number_unsigned() ? b["bone_count"].get<std::uint64_t>() : 0;
        return ba > bb;
    });
    json result;
    result["process_id"] = scope.pid();
    result["allow_memory_fallback"] = allow_memory_fallback;
    result["used_memory_fallback"] = used_memory_fallback;
    result["candidates"] = std::move(candidates);
    result["count"] = result["candidates"].size();
    result["found"] = !result["candidates"].empty();
    result["proven_skeleton"] = false;
    result["finding_semantics"] = "matrix_run_candidate_only";
    result["provenance_limit"] = "no hierarchy, parent-index, bone-name, mesh, or model ownership evidence is recovered by this tool";
    result["heuristics"] = {
        {"matrix_strides", {64, 48}},
        {"decoders", {"raw_float32", "xor32_float32_uniform_key"}},
        {"memory_fallback_default", false},
        {"runtime_clear_data_limit", "buffers must be CPU-readable or captured as clear GPU-bound data; per-element encryption or shader-only decode cannot be proven externally"}
    };
    result["capture_source"] = "none";
    if (!result["candidates"].empty() && result["candidates"][0].contains("source") && result["candidates"][0]["source"].is_string())
        result["capture_source"] = result["candidates"][0]["source"].get<std::string>();
    if (!result["candidates"].empty())
    {
        result["best"] = result["candidates"][0];
        return tool_result_t::ok("Matrix-run candidate evidence found; skeleton hierarchy/model provenance is not proven.", result);
    }
    result["best"] = nullptr;
    result["failure_reason"] = allow_memory_fallback ? "no_matrix_run_candidate_found" : "no_matrix_run_candidate_found_in_captured_or_explicit_sources";
    return tool_result_t::ok("No matrix-run bone-palette candidate found.", result);
}

tool_result_t map_resource_to_va(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    std::uint64_t handle = 0;
    if (!parse_address_param(params, "resource_handle", handle) &&
        !parse_address_param(params, "descriptor_handle", handle) &&
        !parse_address_param(params, "cbv_descriptor_va", handle) &&
        !parse_address_param(params, "resource_va", handle))
        return tool_result_t::error("'resource_handle' is required.");
    if (handle == 0)
        return tool_result_t::error("'resource_handle' is required.");
    const std::size_t max_candidates = static_cast<std::size_t>(numeric_param(params, "max_candidates", 64, 1, 256));
    std::vector<std::uint8_t> bytes;
    driver_bridge::memory_region_t handle_region{};
    const bool handle_region_ok = query_region(scope.pid(), handle, handle_region);
    const bool handle_readable = handle_region_ok && is_readable(handle_region) && !is_guarded(handle_region);
    if (!read_bytes(scope.pid(), handle, 0x400, bytes))
    {
        json result;
        result["process_id"] = scope.pid();
        result["resource_handle"] = sa_format_address(handle);
        result["candidates"] = json::array();
        result["count"] = 0;
        result["va"] = nullptr;
        result["handle_region"] = handle_region_ok ? json(region_json(handle_region)) : json(nullptr);
        result["capability"] = {
            {"cpu_readable", false},
            {"gpu_virtual_address_possible", !handle_readable},
            {"mapping_proof", "resource_handle_not_readable_as_process_va"}
        };
        return tool_result_t::error("Failed to read resource object or descriptor as target-process memory.", result);
    }
    json candidates = json::array();
    std::set<std::uint64_t> seen;
    auto append_candidate = [&](json row) {
        std::uint64_t key = 0;
        if (row.contains("candidate_va"))
            parse_u64_value(row["candidate_va"], key);
        if (key == 0 && row.contains("va"))
            parse_u64_value(row["va"], key);
        if (key != 0 && !seen.insert(key).second)
            return;
        if (candidates.size() < max_candidates)
            candidates.push_back(std::move(row));
    };
    auto make_pointer_row = [&](std::uint64_t ptr,
                                std::uint64_t owner,
                                std::uint64_t offset,
                                const std::string& source,
                                const std::string& chain,
                                double confidence) -> std::optional<json> {
        driver_bridge::memory_region_t region{};
        if (ptr == 0 || !query_region(scope.pid(), ptr, region))
            return std::nullopt;
        json row;
        row["field_offset"] = sa_format_address(offset);
        row["owner_va"] = sa_format_address(owner);
        row["candidate_va"] = sa_format_address(ptr);
        row["va"] = sa_format_address(ptr);
        row["source"] = source;
        row["chain"] = chain;
        row["region"] = region_json(region);
        row["readable"] = is_readable(region);
        row["writable"] = is_writable(region);
        row["executable"] = is_executable(region);
        row["guarded"] = is_guarded(region);
        row["confidence"] = confidence;
        row["mapping_proof"] = is_readable(region) && !is_executable(region) && !is_guarded(region) ? "cpu_readable_process_va" : (is_executable(region) ? "executable_pointer_not_resource_backing" : "nonreadable_pointer");
        std::vector<std::uint8_t> preview;
        if (is_readable(region) && !is_guarded(region) && read_bytes(scope.pid(), ptr, 128, preview) && !preview.empty())
        {
            row["preview_floats"] = preview_floats(preview);
            const std::uint32_t run64 = matrix_run_count(preview, 0, 64, 1000000.0, 16);
            const std::uint32_t run48 = matrix_run_count(preview, 0, 48, 1000000.0, 16);
            row["matrix_count"] = std::max(run64, run48);
            row["matrix_size"] = run64 >= run48 ? 64 : 48;
            if (!is_executable(region) && std::max(run64, run48) != 0)
                row["confidence"] = std::min(0.98, confidence + 0.20);
        }
        return row;
    };
    auto append_gpu_candidate = [&](std::uint64_t gpu_va, std::uint64_t size, std::uint64_t owner, std::uint64_t offset, const std::string& source) {
        if (gpu_va == 0 || candidates.size() >= max_candidates)
            return;
        json row = make_gpu_va_candidate(-1, gpu_va, size, source, 0.44);
        row["candidate_va"] = sa_format_address(gpu_va);
        row["owner_va"] = sa_format_address(owner);
        row["field_offset"] = sa_format_address(offset);
        row["mapping_proof"] = "gpu_virtual_address_not_proven_as_cpu_va";
        append_candidate(std::move(row));
    };

    if (handle_readable && !is_executable(handle_region))
    {
        json direct;
        direct["candidate_va"] = sa_format_address(handle);
        direct["va"] = sa_format_address(handle);
        direct["source"] = "resource_handle_direct_region";
        direct["chain"] = "resource_handle";
        direct["region"] = region_json(handle_region);
        direct["readable"] = true;
        direct["writable"] = is_writable(handle_region);
        direct["executable"] = false;
        direct["confidence"] = 0.40;
        direct["mapping_proof"] = "caller_supplied_cpu_readable_process_va";
        append_candidate(std::move(direct));
    }

    std::uint64_t vtable_va = 0;
    read_u64(scope.pid(), handle, vtable_va);
    json vtable_evidence;
    vtable_evidence["vtable_va"] = vtable_va ? json(sa_format_address(vtable_va)) : json(nullptr);
    vtable_evidence["method_count_sampled"] = 0;
    vtable_evidence["executable_method_count"] = 0;
    if (vtable_va != 0)
    {
        std::vector<std::uint8_t> vtable_bytes;
        if (read_bytes(scope.pid(), vtable_va, 16 * sizeof(std::uint64_t), vtable_bytes) && vtable_bytes.size() >= sizeof(std::uint64_t))
        {
            json methods = json::array();
            const std::size_t entries = std::min<std::size_t>(16, vtable_bytes.size() / sizeof(std::uint64_t));
            std::size_t executable_methods = 0;
            for (std::size_t i = 0; i < entries; ++i)
            {
                std::uint64_t fn = 0;
                std::memcpy(&fn, vtable_bytes.data() + i * sizeof(std::uint64_t), sizeof(fn));
                driver_bridge::memory_region_t fn_region{};
                const bool executable = fn != 0 && query_region(scope.pid(), fn, fn_region) && is_executable(fn_region) && !is_guarded(fn_region);
                if (executable)
                    ++executable_methods;
                methods.push_back({{"slot", i}, {"va", fn ? json(sa_format_address(fn)) : json(nullptr)}, {"executable", executable}, {"owner", fn ? module_owner_for_address(scope.pid(), fn) : json(nullptr)}});
            }
            vtable_evidence["method_count_sampled"] = entries;
            vtable_evidence["executable_method_count"] = executable_methods;
            vtable_evidence["methods"] = std::move(methods);
        }
    }

    for (std::size_t off = 0; off + 8 <= bytes.size(); off += 8)
    {
        std::uint64_t ptr = 0;
        std::memcpy(&ptr, bytes.data() + off, sizeof(ptr));
        if (auto row = make_pointer_row(ptr, handle, static_cast<std::uint64_t>(off), "resource_object_qword_pointer", "resource_handle+" + sa_format_address(off), 0.35))
            append_candidate(*row);
        if (off + 12 <= bytes.size())
        {
            std::uint32_t size32 = 0;
            std::memcpy(&size32, bytes.data() + off + 8, sizeof(size32));
            if (ptr != 0 && size32 != 0 && size32 <= 512u * 1024u * 1024u && (ptr & 0xFu) == 0)
            {
                driver_bridge::memory_region_t ptr_region{};
                if (query_region(scope.pid(), ptr, ptr_region) && is_readable(ptr_region) && !is_guarded(ptr_region))
                {
                    if (auto row = make_pointer_row(ptr, handle, static_cast<std::uint64_t>(off), "d3d12_cbv_descriptor_buffer_location_cpu_mapped", "descriptor.BufferLocation", 0.72))
                    {
                        (*row)["descriptor_size_bytes"] = size32;
                        (*row)["gpu_va"] = sa_format_address(ptr);
                        (*row)["cpu_va_mapped"] = true;
                        append_candidate(*row);
                    }
                }
                else
                {
                    append_gpu_candidate(ptr, size32, handle, static_cast<std::uint64_t>(off), "d3d12_cbv_descriptor_gpu_va");
                }
            }
        }
        if (candidates.size() >= max_candidates)
            break;
    }

    json first_level = candidates;
    for (const auto& row : first_level)
    {
        if (candidates.size() >= max_candidates)
            break;
        std::uint64_t base = 0;
        if (!row.contains("candidate_va") || !parse_u64_value(row["candidate_va"], base) || base == 0)
            continue;
        if (row.contains("executable") && row["executable"].is_boolean() && row["executable"].get<bool>())
            continue;
        std::vector<std::uint8_t> nested;
        if (!read_bytes(scope.pid(), base, 0x180, nested) || nested.size() < sizeof(std::uint64_t))
            continue;
        for (std::size_t off = 0; off + sizeof(std::uint64_t) <= nested.size() && candidates.size() < max_candidates; off += sizeof(std::uint64_t))
        {
            std::uint64_t ptr = 0;
            std::memcpy(&ptr, nested.data() + off, sizeof(ptr));
            if (auto nested_row = make_pointer_row(ptr, base, static_cast<std::uint64_t>(off), "resource_nested_qword_pointer", row.value("chain", std::string("resource")) + "->" + sa_format_address(off), 0.28))
                append_candidate(*nested_row);
        }
    }
    std::sort(candidates.begin(), candidates.end(), [](const json& a, const json& b) {
        const double ca = a.contains("confidence") && a["confidence"].is_number() ? a["confidence"].get<double>() : 0.0;
        const double cb = b.contains("confidence") && b["confidence"].is_number() ? b["confidence"].get<double>() : 0.0;
        if (ca != cb)
            return ca > cb;
        const bool ae = a.contains("executable") && a["executable"].is_boolean() && a["executable"].get<bool>();
        const bool be = b.contains("executable") && b["executable"].is_boolean() && b["executable"].get<bool>();
        return !ae && be;
    });
    json result;
    result["process_id"] = scope.pid();
    result["resource_handle"] = sa_format_address(handle);
    result["handle_region"] = handle_region_ok ? json(region_json(handle_region)) : json(nullptr);
    result["com_vtable_evidence"] = std::move(vtable_evidence);
    result["candidates"] = std::move(candidates);
    result["count"] = result["candidates"].size();
    result["va"] = result["candidates"].empty() ? json(nullptr) : result["candidates"][0]["candidate_va"];
    result["capability"] = {
        {"cpu_pointer_walk", true},
        {"max_candidates", max_candidates},
        {"gpu_virtual_address_mapping_proven", !result["candidates"].empty() && result["candidates"][0].contains("cpu_va_mapped") && result["candidates"][0]["cpu_va_mapped"].is_boolean() && result["candidates"][0]["cpu_va_mapped"].get<bool>()},
        {"descriptor_gpu_va_reported_as_cpu_va", false}
    };
    return tool_result_t::ok(result);
}

tool_result_t dump_render_targets(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    if (!unsafe_confirmed(params))
        return unsafe_required("dx_dump_render_targets");
    std::string format = lower_ascii(string_param(params, "format", "png"));
    if (format != "png" && format != "rgba")
        return tool_result_t::error("'format' must be 'png' or 'rgba'.");
    const bool allow_window_fallback = bool_param(params, "allow_window_fallback", false);
    std::size_t render_target_bind_captures = 0;
    for (const auto& record : store::list_dx_hooks(scope.pid()))
    {
        for (const auto& cap : record.captures)
        {
            if (cap.contains("render_targets") && cap["render_targets"].is_array() && !cap["render_targets"].empty())
                render_target_bind_captures += cap["render_targets"].size();
        }
    }
    json gpu_readback_capability = {
        {"available", false},
        {"preferred", true},
        {"attempted", false},
        {"reason", "external process has no safe ID3D11DeviceContext/ID3D12CommandQueue readback path or shared render-target handle"},
        {"render_target_bind_captures", render_target_bind_captures},
        {"requires", {"in_process_capture_callback", "device_context_or_command_queue", "staging_readback_resource_or_shared_handle"}}
    };
    json result;
    result["process_id"] = scope.pid();
    result["format"] = format;
    result["captured"] = false;
    result["source"] = "gpu_render_target_readback";
    result["gpu_texture_memory"] = false;
    result["gpu_readback_capability"] = gpu_readback_capability;
    result["allow_window_fallback"] = allow_window_fallback;
    result["window_fallback_available"] = false;
    result["window_capture_backend"] = "disabled_kernel_only_policy";
    result["output_path"] = nullptr;
    result["bytes_written"] = 0;
    result["required_capability"] = "kernel_gpu_resource_readback_or_trusted_in_process_graphics_callback";
    result["reason"] = "GPU render-target textures cannot be read through the current kernel driver interface, and user-mode window capture fallback is disabled by stealth policy.";
    result["evidence"] = {
        {"process_window_validated", false},
        {"bounded_file_write", false},
        {"render_target_readback", false},
        {"frame_capture_only", false},
        {"window_frame_is_gpu_memory", false}
    };
    return tool_result_t::error("GPU render-target readback is unavailable under kernel-only stealth policy.", result);
}

tool_result_t find_view_matrix(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const bool cbuffers_only = bool_param(params, "scan_cbuffers_only", true);
    const bool allow_memory_fallback = bool_param(params, "allow_memory_fallback", false);
    const double world_max = number_param(params, "world_unit_max", 1000000.0, 1.0, 1000000000.0);
    json out = json::array();
    std::map<std::string, std::uint64_t> rejection_counts;
    std::map<std::string, std::uint64_t> provenance_counts;
    std::map<std::uint64_t, std::uint32_t> temporal_hits;
    std::set<std::string> seen_keys;
    std::uint64_t inspected_candidates = 0;
    std::uint64_t high_confidence = 0;
    std::uint64_t fallback_accepted = 0;
    constexpr std::size_t kMaxResults = 128;
    constexpr std::size_t kMaxFallbackResults = 16;
    bool used_memory_fallback = false;
    refresh_snapshot_records(scope.pid(), "find_view_matrix requested current bounded evidence", &params, allow_memory_fallback);
    json stored_rows = stored_cbuffer_rows(scope.pid());
    for (const auto& cb : stored_rows)
    {
        std::uint64_t va = 0;
        if (cb.contains("va") && parse_u64_value(cb["va"], va) && va != 0)
            ++temporal_hits[va];
    }
    auto inspect_candidate = [&](const json& candidate, const std::string& source) {
        if (!candidate.contains("va") || out.size() >= kMaxResults)
            return;
        ++inspected_candidates;
        ++provenance_counts[source];
        std::uint64_t va = 0;
        if (!parse_u64_value(candidate["va"], va) || va == 0)
        {
            ++rejection_counts["bad_va"];
            return;
        }
        driver_bridge::memory_region_t region{};
        if (!query_region(scope.pid(), va, region) || !is_readable(region) || is_executable(region) || is_guarded(region))
        {
            ++rejection_counts["region_not_readable"];
            return;
        }
        int slot = -1;
        if (candidate.contains("slot") && candidate["slot"].is_number_integer())
            slot = candidate["slot"].get<int>();
        std::ostringstream key;
        if (slot >= 0)
            key << std::hex << region.base << ":" << slot;
        else
            key << std::hex << va;
        if (!seen_keys.insert(key.str()).second)
        {
            ++rejection_counts["duplicate_region_slot"];
            return;
        }
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(scope.pid(), va, 64, bytes) || bytes.size() < 64)
        {
            ++rejection_counts["read_failed"];
            return;
        }
        float f[16] = {};
        std::memcpy(f, bytes.data(), 64);
        matrix_eval_t eval = evaluate_matrix4x4(f, world_max);
        if (!eval.plausible)
        {
            ++rejection_counts[eval.reason.empty() ? "matrix_rejected" : eval.reason];
            return;
        }
        if (eval.view_like && eval.static_null_view)
        {
            ++rejection_counts["identity_static_null_view"];
            return;
        }
        json row;
        row["va"] = sa_format_address(va);
        double source_confidence = 0.50;
        if (candidate.contains("confidence") && candidate["confidence"].is_number())
            source_confidence = candidate["confidence"].get<double>();
        const bool fallback_source = source == "bounded_private_memory_matrix_scan";
        const std::uint32_t hits = temporal_hits.count(va) ? temporal_hits[va] : 0;
        double confidence = source_confidence + eval.score * 0.35;
        if (source == "dx_hook_cbuffer_capture")
            confidence += 0.18;
        else if (source == "explicit_cbuffer_candidate")
            confidence += 0.12;
        else if (fallback_source)
            confidence -= 0.08;
        if (hits > 1)
            confidence += std::min(0.18, static_cast<double>(hits) * 0.06);
        confidence = std::min(0.98, std::max(0.0, confidence));
        if (fallback_source)
        {
            if (fallback_accepted >= kMaxFallbackResults)
            {
                ++rejection_counts["fallback_cap"];
                return;
            }
            if (confidence < 0.70)
            {
                ++rejection_counts["fallback_low_confidence"];
                return;
            }
            ++fallback_accepted;
        }
        if (confidence >= 0.75)
            ++high_confidence;
        row["confidence"] = confidence;
        row["matrix_type"] = eval.type;
        row["matrix_orientation"] = eval.orientation;
        row["determinant3x3"] = eval.determinant;
        row["orthogonality_error"] = eval.orthogonality_error;
        row["row_orthogonality_error"] = eval.row_orthogonality_error;
        row["column_orthogonality_error"] = eval.column_orthogonality_error;
        row["inverse_residual3x3"] = eval.inverse_residual;
        row["row_translation_abs"] = eval.row_translation_abs;
        row["column_translation_abs"] = eval.column_translation_abs;
        row["identity_error"] = eval.identity_error;
        row["static_null_view"] = eval.static_null_view;
        row["temporal_hits"] = hits;
        row["preview_floats"] = preview_floats(bytes);
        row["source"] = source;
        row["region"] = region_json(region);
        row["evidence"] = candidate;
        out.push_back(std::move(row));
    };

    for (const auto& cb : explicit_cbuffer_candidates(scope.pid(), params, 128, "explicit_cbuffer_candidate"))
    {
        if (dx_call_cancelled("find_view_matrix_explicit_candidates", scope.pid(), started_ms))
            break;
        inspect_candidate(cb, "explicit_cbuffer_candidate");
        if (out.size() >= kMaxResults)
            break;
    }

    for (const auto& cb : stored_rows)
    {
        if (dx_call_cancelled("find_view_matrix_stored_cbuffer_candidates", scope.pid(), started_ms))
            break;
        inspect_candidate(cb, "dx_hook_cbuffer_capture");
        if (out.size() >= kMaxResults)
            break;
    }

    if (allow_memory_fallback && out.size() < kMaxResults && !dx_call_cancelled("find_view_matrix_memory_fallback", scope.pid(), started_ms))
    {
        const std::size_t fallback_limit = std::min<std::size_t>(kMaxFallbackResults, kMaxResults - static_cast<std::size_t>(out.size()));
        json scanned = scan_memory_cbuffer_candidates(scope.pid(), fallback_limit, world_max, cbuffers_only ? 512 : 4096);
        for (const auto& row : scanned)
        {
            inspect_candidate(row, "bounded_private_memory_matrix_scan");
            if (out.size() >= kMaxResults)
                break;
        }
        used_memory_fallback = !scanned.empty();
    }
    else if (!allow_memory_fallback)
    {
        diag::log_tagged_fmt("dx_hook",
                             "find_view_matrix memory_fallback_skipped pid=%u scan_cbuffers_only=%d allow_memory_fallback=0 accepted=%zu stored_rows=%zu elapsed_ms=%llu",
                             scope.pid(),
                             cbuffers_only ? 1 : 0,
                             out.size(),
                             stored_rows.size(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
    }
    std::sort(out.begin(), out.end(), [](const json& a, const json& b) {
        const double ca = a.contains("confidence") && a["confidence"].is_number() ? a["confidence"].get<double>() : 0.0;
        const double cb = b.contains("confidence") && b["confidence"].is_number() ? b["confidence"].get<double>() : 0.0;
        if (ca != cb)
            return ca > cb;
        const std::uint64_t ha = a.contains("temporal_hits") && a["temporal_hits"].is_number_unsigned() ? a["temporal_hits"].get<std::uint64_t>() : 0;
        const std::uint64_t hb = b.contains("temporal_hits") && b["temporal_hits"].is_number_unsigned() ? b["temporal_hits"].get<std::uint64_t>() : 0;
        return ha > hb;
    });
    json result;
    result["process_id"] = scope.pid();
    result["scan_cbuffers_only"] = cbuffers_only;
    result["allow_memory_fallback"] = allow_memory_fallback;
    result["used_cbuffer_capture"] = provenance_counts["dx_hook_cbuffer_capture"] != 0;
    result["used_memory_fallback"] = used_memory_fallback;
    result["inspected_candidates"] = inspected_candidates;
    result["stored_cbuffer_candidates"] = stored_rows.size();
    result["high_confidence_count"] = high_confidence;
    result["identity_static_null_rejected"] = rejection_counts["identity_static_null_view"];
    result["finding_semantics"] = "matrix_candidate_evidence_not_camera_object";
    result["rejection_counts"] = rejection_counts;
    result["provenance_counts"] = provenance_counts;
    result["results"] = std::move(out);
    result["count"] = result["results"].size();
    result["found"] = !result["results"].empty();
    if (result["results"].empty())
        result["failure_reason"] = allow_memory_fallback ? "no_plausible_nonidentity_matrix_candidate_found" : "no_plausible_nonidentity_matrix_candidate_found_in_captured_or_explicit_sources";
    result["best"] = result["results"].empty() ? json(nullptr) : result["results"][0];
    diag::log_tagged_fmt("dx_hook",
                         "find_view_matrix exit pid=%u count=%zu inspected=%llu high_confidence=%llu explicit=%llu cbuffer=%llu fallback=%llu rejected_bad_va=%llu rejected_read=%llu rejected_shape=%llu rejected_duplicate=%llu used_memory_fallback=%d elapsed_ms=%llu",
                         scope.pid(),
                         result["results"].size(),
                         static_cast<unsigned long long>(inspected_candidates),
                         static_cast<unsigned long long>(high_confidence),
                         static_cast<unsigned long long>(provenance_counts["explicit_cbuffer_candidate"]),
                         static_cast<unsigned long long>(provenance_counts["dx_hook_cbuffer_capture"]),
                         static_cast<unsigned long long>(provenance_counts["bounded_private_memory_matrix_scan"]),
                         static_cast<unsigned long long>(rejection_counts["bad_va"]),
                         static_cast<unsigned long long>(rejection_counts["read_failed"]),
                         static_cast<unsigned long long>(rejection_counts["shape_rejected"]),
                         static_cast<unsigned long long>(rejection_counts["duplicate_region_slot"]),
                         used_memory_fallback ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}
}
