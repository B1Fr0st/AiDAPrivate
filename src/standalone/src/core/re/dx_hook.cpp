#include "dx_hook.hpp"

#include "artifact_store.hpp"
#include "vmt.hpp"
#include "../infra/work_queue.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cfloat>
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
    out["target_name"] = record.target_name;
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

struct quat_eval_t
{
    bool plausible = false;
    double score = 0.0;
    double quat_norm_error = 1.0;
    double translation_abs = 0.0;
    double scale_abs = 0.0;
    std::string reason;
    std::string type;
    matrix_eval_t matrix_eval;
};

struct dual_quat_eval_t
{
    bool plausible = false;
    double score = 0.0;
    double real_norm_error = 1.0;
    double dual_constraint_error = 1.0;
    double translation_abs = 0.0;
    std::string reason;
    std::string type;
    matrix_eval_t matrix_eval;
};

struct srt_eval_t
{
    bool plausible = false;
    double score = 0.0;
    double quat_norm_error = 1.0;
    double translation_abs = 0.0;
    double scale_min = 0.0;
    double scale_max = 0.0;
    std::string reason;
    std::string type;
    matrix_eval_t matrix_eval;
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

float float_from_u32(std::uint32_t value);

double quat_norm(float x, float y, float z, float w)
{
    return std::sqrt(static_cast<double>(x) * x +
                     static_cast<double>(y) * y +
                     static_cast<double>(z) * z +
                     static_cast<double>(w) * w);
}

bool quat_normalized(float x, float y, float z, float w, double tolerance = 0.02)
{
    const double n = quat_norm(x, y, z, w);
    return std::isfinite(n) && n > 0.01 && std::fabs(n - 1.0) <= tolerance;
}

void quat_to_matrix3x3_row_major(float qx, float qy, float qz, float qw, float out[9])
{
    const double xx = qx * qx, yy = qy * qy, zz = qz * qz;
    const double xy = qx * qy, xz = qx * qz, yz = qy * qz;
    const double wx = qw * qx, wy = qw * qy, wz = qw * qz;
    out[0] = static_cast<float>(1.0 - 2.0 * (yy + zz));
    out[1] = static_cast<float>(2.0 * (xy - wz));
    out[2] = static_cast<float>(2.0 * (xz + wy));
    out[3] = static_cast<float>(2.0 * (xy + wz));
    out[4] = static_cast<float>(1.0 - 2.0 * (xx + zz));
    out[5] = static_cast<float>(2.0 * (yz - wx));
    out[6] = static_cast<float>(2.0 * (xz - wy));
    out[7] = static_cast<float>(2.0 * (yz + wx));
    out[8] = static_cast<float>(1.0 - 2.0 * (xx + yy));
}

void quat_to_matrix4x4_row_major(float qx, float qy, float qz, float qw,
                                 float tx, float ty, float tz, float out[16])
{
    std::fill(out, out + 16, 0.0f);
    float r[9];
    quat_to_matrix3x3_row_major(qx, qy, qz, qw, r);
    out[0] = r[0]; out[1] = r[1]; out[2] = r[2];
    out[4] = r[3]; out[5] = r[4]; out[6] = r[5];
    out[8] = r[6]; out[9] = r[7]; out[10] = r[8];
    out[12] = tx; out[13] = ty; out[14] = tz;
    out[15] = 1.0f;
}

void quat_to_matrix4x4_column_major(float qx, float qy, float qz, float qw,
                                    float tx, float ty, float tz, float out[16])
{
    std::fill(out, out + 16, 0.0f);
    float r[9];
    quat_to_matrix3x3_row_major(qx, qy, qz, qw, r);
    out[0] = r[0]; out[4] = r[1]; out[8]  = r[2];
    out[1] = r[3]; out[5] = r[4]; out[9]  = r[5];
    out[2] = r[6]; out[6] = r[7]; out[10] = r[8];
    out[3] = tx; out[7] = ty; out[11] = tz;
    out[15] = 1.0f;
}

void dual_quat_to_matrix4x4_row_major(float rx, float ry, float rz, float rw,
                                       float dx, float dy, float dz, float dw,
                                       float out[16])
{
    std::fill(out, out + 16, 0.0f);
    float r[9];
    quat_to_matrix3x3_row_major(rx, ry, rz, rw, r);
    out[0] = r[0]; out[1] = r[1]; out[2] = r[2];
    out[4] = r[3]; out[5] = r[4]; out[6] = r[5];
    out[8] = r[6]; out[9] = r[7]; out[10] = r[8];
    const double tx = 2.0 * (dx * rw - dy * rz + dz * ry - dw * rx);
    const double ty = 2.0 * (dy * rw + dx * rz - dz * rx - dw * ry);
    const double tz = 2.0 * (dz * rw - dx * ry + dy * rx - dw * rz);
    out[12] = static_cast<float>(tx);
    out[13] = static_cast<float>(ty);
    out[14] = static_cast<float>(tz);
    out[15] = 1.0f;
}

void dual_quat_to_matrix4x4_column_major(float rx, float ry, float rz, float rw,
                                          float dx, float dy, float dz, float dw,
                                          float out[16])
{
    std::fill(out, out + 16, 0.0f);
    float r[9];
    quat_to_matrix3x3_row_major(rx, ry, rz, rw, r);
    out[0] = r[0]; out[4] = r[1]; out[8]  = r[2];
    out[1] = r[3]; out[5] = r[4]; out[9]  = r[5];
    out[2] = r[6]; out[6] = r[7]; out[10] = r[8];
    const double tx = 2.0 * (dx * rw - dy * rz + dz * ry - dw * rx);
    const double ty = 2.0 * (dy * rw + dx * rz - dz * rx - dw * ry);
    const double tz = 2.0 * (dz * rw - dx * ry + dy * rx - dw * rz);
    out[3]  = static_cast<float>(tx);
    out[7]  = static_cast<float>(ty);
    out[11] = static_cast<float>(tz);
    out[15] = 1.0f;
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

quat_eval_t evaluate_quat_pos(const float* data, double world_max)
{
    quat_eval_t eval;
    for (int i = 0; i < 7; ++i)
    {
        if (!std::isfinite(data[i]))
        {
            eval.reason = "nonfinite";
            return eval;
        }
    }
    const float qx = data[0], qy = data[1], qz = data[2], qw = data[3];
    const float px = data[4], py = data[5], pz = data[6];
    const double n = quat_norm(qx, qy, qz, qw);
    eval.quat_norm_error = std::fabs(n - 1.0);
    if (!quat_normalized(qx, qy, qz, qw))
    {
        eval.reason = "quat_not_normalized";
        return eval;
    }
    eval.translation_abs = std::max({std::fabs(static_cast<double>(px)),
                                      std::fabs(static_cast<double>(py)),
                                      std::fabs(static_cast<double>(pz))});
    if (eval.translation_abs > world_max)
    {
        eval.reason = "translation_out_of_range";
        return eval;
    }
    float mat_row[16];
    quat_to_matrix4x4_row_major(qx, qy, qz, qw, px, py, pz, mat_row);
    matrix_eval_t m_eval = evaluate_matrix4x4(mat_row, world_max);
    eval.matrix_eval = m_eval;
    float mat_col[16];
    quat_to_matrix4x4_column_major(qx, qy, qz, qw, px, py, pz, mat_col);
    matrix_eval_t m_eval_col = evaluate_matrix4x4(mat_col, world_max);
    if (!m_eval.plausible && !m_eval_col.plausible)
    {
        eval.reason = "converted_matrix_rejected";
        return eval;
    }
    eval.plausible = true;
    eval.reason = "accepted";
    eval.type = "quat_pos";
    eval.score = 0.50;
    eval.score += std::max(0.0, 0.20 - eval.quat_norm_error * 10.0);
    if (eval.translation_abs > 0.001)
        eval.score += 0.10;
    if (m_eval.plausible)
        eval.score += m_eval.score * 0.15;
    else
        eval.score += m_eval_col.score * 0.15;
    eval.score = std::min(0.95, eval.score);
    return eval;
}

bool plausible_quat_pos(const float* data, double world_max)
{
    return evaluate_quat_pos(data, world_max).plausible;
}

dual_quat_eval_t evaluate_dual_quat(const float* data, double world_max)
{
    dual_quat_eval_t eval;
    for (int i = 0; i < 8; ++i)
    {
        if (!std::isfinite(data[i]))
        {
            eval.reason = "nonfinite";
            return eval;
        }
    }
    const float rx = data[0], ry = data[1], rz = data[2], rw = data[3];
    const float dx = data[4], dy = data[5], dz = data[6], dw = data[7];
    const double rn = quat_norm(rx, ry, rz, rw);
    eval.real_norm_error = std::fabs(rn - 1.0);
    if (!quat_normalized(rx, ry, rz, rw))
    {
        eval.reason = "real_quat_not_normalized";
        return eval;
    }
    const double dot_rd = static_cast<double>(rx) * dx +
                          static_cast<double>(ry) * dy +
                          static_cast<double>(rz) * dz +
                          static_cast<double>(rw) * dw;
    eval.dual_constraint_error = std::fabs(dot_rd);
    if (eval.dual_constraint_error > 0.05)
    {
        eval.reason = "dual_constraint_violated";
        return eval;
    }
    float mat_row[16];
    dual_quat_to_matrix4x4_row_major(rx, ry, rz, rw, dx, dy, dz, dw, mat_row);
    matrix_eval_t m_eval = evaluate_matrix4x4(mat_row, world_max);
    eval.matrix_eval = m_eval;
    float mat_col[16];
    dual_quat_to_matrix4x4_column_major(rx, ry, rz, rw, dx, dy, dz, dw, mat_col);
    matrix_eval_t m_eval_col = evaluate_matrix4x4(mat_col, world_max);
    if (!m_eval.plausible && !m_eval_col.plausible)
    {
        eval.reason = "converted_matrix_rejected";
        return eval;
    }
    eval.translation_abs = std::max({std::fabs(static_cast<double>(mat_row[12])),
                                      std::fabs(static_cast<double>(mat_row[13])),
                                      std::fabs(static_cast<double>(mat_row[14]))});
    if (eval.translation_abs > world_max)
    {
        eval.reason = "translation_out_of_range";
        return eval;
    }
    eval.plausible = true;
    eval.reason = "accepted";
    eval.type = "dual_quat";
    eval.score = 0.50;
    eval.score += std::max(0.0, 0.20 - eval.real_norm_error * 10.0);
    eval.score += std::max(0.0, 0.15 - eval.dual_constraint_error * 3.0);
    if (eval.translation_abs > 0.001)
        eval.score += 0.05;
    if (m_eval.plausible)
        eval.score += m_eval.score * 0.10;
    else
        eval.score += m_eval_col.score * 0.10;
    eval.score = std::min(0.95, eval.score);
    return eval;
}

bool plausible_dual_quat(const float* data, double world_max)
{
    return evaluate_dual_quat(data, world_max).plausible;
}

srt_eval_t evaluate_srt_quat(const float* data, double world_max)
{
    srt_eval_t eval;
    for (int i = 0; i < 10; ++i)
    {
        if (!std::isfinite(data[i]))
        {
            eval.reason = "nonfinite";
            return eval;
        }
    }
    const float sx = data[0], sy = data[1], sz = data[2];
    const float qx = data[3], qy = data[4], qz = data[5], qw = data[6];
    const float tx = data[7], ty = data[8], tz = data[9];
    eval.scale_min = std::min({std::fabs(static_cast<double>(sx)),
                                std::fabs(static_cast<double>(sy)),
                                std::fabs(static_cast<double>(sz))});
    eval.scale_max = std::max({std::fabs(static_cast<double>(sx)),
                                std::fabs(static_cast<double>(sy)),
                                std::fabs(static_cast<double>(sz))});
    if (eval.scale_min < 0.001 || eval.scale_max > 1000.0)
    {
        eval.reason = "scale_out_of_range";
        return eval;
    }
    if (!quat_normalized(qx, qy, qz, qw))
    {
        eval.reason = "quat_not_normalized";
        return eval;
    }
    eval.quat_norm_error = std::fabs(quat_norm(qx, qy, qz, qw) - 1.0);
    eval.translation_abs = std::max({std::fabs(static_cast<double>(tx)),
                                      std::fabs(static_cast<double>(ty)),
                                      std::fabs(static_cast<double>(tz))});
    if (eval.translation_abs > world_max)
    {
        eval.reason = "translation_out_of_range";
        return eval;
    }
    float r[9];
    quat_to_matrix3x3_row_major(qx, qy, qz, qw, r);
    float mat[16] = {};
    mat[0]  = r[0] * sx; mat[1]  = r[1] * sy; mat[2]  = r[2] * sz;
    mat[4]  = r[3] * sx; mat[5]  = r[4] * sy; mat[6]  = r[5] * sz;
    mat[8]  = r[6] * sx; mat[9]  = r[7] * sy; mat[10] = r[8] * sz;
    mat[12] = tx; mat[13] = ty; mat[14] = tz;
    mat[15] = 1.0f;
    matrix_eval_t m_eval = evaluate_matrix4x4(mat, world_max);
    eval.matrix_eval = m_eval;
    if (!m_eval.plausible)
    {
        eval.reason = "converted_matrix_rejected";
        return eval;
    }
    eval.plausible = true;
    eval.reason = "accepted";
    eval.type = "srt_quat";
    eval.score = 0.50;
    eval.score += std::max(0.0, 0.15 - eval.quat_norm_error * 10.0);
    if (eval.scale_min >= 0.1 && eval.scale_max <= 10.0)
        eval.score += 0.10;
    if (eval.translation_abs > 0.001)
        eval.score += 0.05;
    eval.score += m_eval.score * 0.15;
    eval.score = std::min(0.95, eval.score);
    return eval;
}

bool plausible_srt_quat(const float* data, double world_max)
{
    return evaluate_srt_quat(data, world_max).plausible;
}

srt_eval_t evaluate_srt_mat3x3(const float* data, double world_max)
{
    srt_eval_t eval;
    for (int i = 0; i < 15; ++i)
    {
        if (!std::isfinite(data[i]))
        {
            eval.reason = "nonfinite";
            return eval;
        }
    }
    const float sx = data[0], sy = data[1], sz = data[2];
    const float* rot = data + 3;
    const float tx = data[12], ty = data[13], tz = data[14];
    eval.scale_min = std::min({std::fabs(static_cast<double>(sx)),
                                std::fabs(static_cast<double>(sy)),
                                std::fabs(static_cast<double>(sz))});
    eval.scale_max = std::max({std::fabs(static_cast<double>(sx)),
                                std::fabs(static_cast<double>(sy)),
                                std::fabs(static_cast<double>(sz))});
    if (eval.scale_min < 0.001 || eval.scale_max > 1000.0)
    {
        eval.reason = "scale_out_of_range";
        return eval;
    }
    const double r0 = vec3_norm(rot[0], rot[1], rot[2]);
    const double r1 = vec3_norm(rot[3], rot[4], rot[5]);
    const double r2 = vec3_norm(rot[6], rot[7], rot[8]);
    if (r0 < 0.01 || r1 < 0.01 || r2 < 0.01)
    {
        eval.reason = "rotation_row_zero";
        return eval;
    }
    const double rd01 = std::fabs(vec3_dot(rot[0], rot[1], rot[2], rot[3], rot[4], rot[5]) / std::max(0.000001, r0 * r1));
    const double rd02 = std::fabs(vec3_dot(rot[0], rot[1], rot[2], rot[6], rot[7], rot[8]) / std::max(0.000001, r0 * r2));
    const double rd12 = std::fabs(vec3_dot(rot[3], rot[4], rot[5], rot[6], rot[7], rot[8]) / std::max(0.000001, r1 * r2));
    const double max_orth_err = std::max({rd01, rd02, rd12});
    if (max_orth_err > 0.35)
    {
        eval.reason = "rotation_not_orthogonal";
        return eval;
    }
    eval.translation_abs = std::max({std::fabs(static_cast<double>(tx)),
                                      std::fabs(static_cast<double>(ty)),
                                      std::fabs(static_cast<double>(tz))});
    if (eval.translation_abs > world_max)
    {
        eval.reason = "translation_out_of_range";
        return eval;
    }
    float mat[16] = {};
    mat[0]  = rot[0] * sx; mat[1]  = rot[1] * sy; mat[2]  = rot[2] * sz;
    mat[4]  = rot[3] * sx; mat[5]  = rot[4] * sy; mat[6]  = rot[5] * sz;
    mat[8]  = rot[6] * sx; mat[9]  = rot[7] * sy; mat[10] = rot[8] * sz;
    mat[12] = tx; mat[13] = ty; mat[14] = tz;
    mat[15] = 1.0f;
    matrix_eval_t m_eval = evaluate_matrix4x4(mat, world_max);
    eval.matrix_eval = m_eval;
    if (!m_eval.plausible)
    {
        eval.reason = "converted_matrix_rejected";
        return eval;
    }
    eval.plausible = true;
    eval.reason = "accepted";
    eval.type = "srt_mat3x3";
    eval.score = 0.50;
    if (max_orth_err <= 0.10)
        eval.score += 0.15;
    else
        eval.score += std::max(0.0, 0.15 - max_orth_err * 0.15);
    if (eval.scale_min >= 0.1 && eval.scale_max <= 10.0)
        eval.score += 0.10;
    if (eval.translation_abs > 0.001)
        eval.score += 0.05;
    eval.score += m_eval.score * 0.15;
    eval.score = std::min(0.95, eval.score);
    return eval;
}

bool plausible_srt_mat3x3(const float* data, double world_max)
{
    return evaluate_srt_mat3x3(data, world_max).plausible;
}

bool plausible_matrix3x4_64_pad(const float* f, double world_max)
{
    float mat[16] = {};
    std::memcpy(mat, f, 48);
    mat[15] = 1.0f;
    if (!plausible_matrix4x4(mat, world_max))
        return false;
    const std::uint32_t* tail = reinterpret_cast<const std::uint32_t*>(f) + 12;
    bool all_zero = true;
    bool small_int_meta = true;
    for (int i = 0; i < 4; ++i)
    {
        std::uint32_t word = 0;
        std::memcpy(&word, tail + i, sizeof(word));
        if (word != 0)
            all_zero = false;
        float fv = float_from_u32(word);
        if (!std::isfinite(fv) || std::fabs(static_cast<double>(fv)) > 100000.0)
            small_int_meta = false;
    }
    return all_zero || small_int_meta;
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

bool plausible_bone_format(const float* raw, std::size_t stride, double world_max);

std::uint32_t matrix_run_count(const std::vector<std::uint8_t>& bytes, std::size_t off, std::size_t stride, double world_max, std::uint32_t max_count)
{
    std::uint32_t count = 0;
    for (std::size_t cursor = off; cursor + stride <= bytes.size() && count < max_count; cursor += stride)
    {
        float f[16] = {};
        if (stride == 64)
            std::memcpy(f, bytes.data() + cursor, 64);
        else if (stride == 48)
        {
            std::memcpy(f, bytes.data() + cursor, 48);
            f[15] = 1.0f;
        }
        else
        {
            float raw[16];
            std::memcpy(raw, bytes.data() + cursor, std::min(stride, sizeof(raw)));
            if (!plausible_bone_format(raw, stride, world_max))
                break;
            ++count;
            continue;
        }
        if (stride == 64 && !plausible_matrix4x4(f, world_max))
        {
            if (!plausible_matrix3x4_64_pad(reinterpret_cast<const float*>(bytes.data() + cursor), world_max))
                break;
        }
        else if (stride == 48 && !plausible_matrix4x4(f, world_max))
            break;
        ++count;
    }
    return count;
}

std::uint32_t matrix_run_count_interleaved(const std::vector<std::uint8_t>& bytes,
                                            std::size_t off,
                                            std::size_t matrix_stride,
                                            std::size_t entry_stride,
                                            double world_max,
                                            std::uint32_t max_count)
{
    if (entry_stride < matrix_stride || entry_stride == 0)
        return 0;
    std::uint32_t count = 0;
    for (std::size_t cursor = off; cursor + matrix_stride <= bytes.size() && count < max_count; cursor += entry_stride)
    {
        float raw[16] = {};
        std::memcpy(raw, bytes.data() + cursor, std::min(matrix_stride, sizeof(raw)));
        if (matrix_stride == 64)
        {
            if (!plausible_matrix4x4(raw, world_max) && !plausible_matrix3x4_64_pad(raw, world_max))
                break;
        }
        else if (matrix_stride == 48)
        {
            float mat[16] = {};
            std::memcpy(mat, raw, 48);
            mat[15] = 1.0f;
            if (!plausible_matrix4x4(mat, world_max))
                break;
        }
        else
        {
            if (!plausible_bone_format(raw, matrix_stride, world_max))
                break;
        }
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

enum class bone_format_t : std::uint8_t
{
    matrix4x4_64      = 0,
    matrix3x4_48      = 1,
    matrix3x4_64_pad  = 2,
    quat_pos_28       = 3,
    dual_quat_32      = 4,
    srt_quat_40       = 5,
    srt_mat3x3_60     = 6,
    srt_quat_52_pad   = 7,
    unknown           = 255
};

inline const char* bone_format_name(bone_format_t fmt)
{
    switch (fmt)
    {
    case bone_format_t::matrix4x4_64:    return "matrix4x4_64";
    case bone_format_t::matrix3x4_48:    return "matrix3x4_48";
    case bone_format_t::matrix3x4_64_pad:return "matrix3x4_64_padded";
    case bone_format_t::quat_pos_28:     return "quat_pos_28";
    case bone_format_t::dual_quat_32:    return "dual_quat_32";
    case bone_format_t::srt_quat_40:     return "srt_quat_40";
    case bone_format_t::srt_mat3x3_60:   return "srt_mat3x3_60";
    case bone_format_t::srt_quat_52_pad: return "srt_quat_52_padded";
    default:                             return "unknown";
    }
}

inline std::size_t bone_format_stride(bone_format_t fmt)
{
    switch (fmt)
    {
    case bone_format_t::matrix4x4_64:    return 64;
    case bone_format_t::matrix3x4_48:    return 48;
    case bone_format_t::matrix3x4_64_pad:return 64;
    case bone_format_t::quat_pos_28:     return 28;
    case bone_format_t::dual_quat_32:    return 32;
    case bone_format_t::srt_quat_40:     return 40;
    case bone_format_t::srt_mat3x3_60:   return 60;
    case bone_format_t::srt_quat_52_pad: return 52;
    default:                             return 0;
    }
}

struct matrix_decode_result_t
{
    std::uint32_t count = 0;
    std::size_t stride = 0;
    std::size_t offset = 0;
    std::uint32_t xor_key = 0;
    std::string decode = "raw_float32";
    matrix_eval_t first_eval;
    bone_format_t format = bone_format_t::unknown;
    std::size_t entry_stride = 0;
};

enum class decode_algorithm_t : std::uint8_t
{
    raw_float32       = 0,
    xor_uniform       = 1,
    xor_rolling       = 2,
    xor_multi_key     = 3,
    additive_byte     = 4,
    additive_word     = 5,
    custom            = 6,
};

struct multi_decode_result_t
{
    decode_algorithm_t algorithm = decode_algorithm_t::raw_float32;
    std::uint32_t count = 0;
    std::size_t stride = 0;
    std::size_t offset = 0;
    std::vector<std::uint32_t> key_words;
    std::uint32_t uniform_key = 0;
    std::uint32_t rolling_seed = 0;
    std::uint32_t rolling_multiplier = 0;
    std::uint32_t rolling_increment = 0;
    std::uint32_t additive_key = 0;
    std::string algorithm_name;
    matrix_eval_t first_eval;
    bone_format_t format = bone_format_t::unknown;
    std::size_t entry_stride = 0;
};

struct decryption_analysis_t
{
    decode_algorithm_t algorithm = decode_algorithm_t::custom;
    std::vector<std::uint8_t> derived_key_bytes;
    std::uint32_t key_length = 0;
    std::string key_pattern;
    std::string algorithm_name;
    std::vector<std::uint32_t> key_words;
    bool verified = false;
    std::string verification_detail;
    std::size_t match_bytes = 0;
    std::size_t total_bytes = 0;
    std::uint32_t uniform_key = 0;
    std::uint32_t rolling_seed = 0;
    std::uint32_t rolling_multiplier = 0;
    std::uint32_t rolling_increment = 0;
    std::uint32_t additive_key = 0;
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

bool decode_words_generic(const std::vector<std::uint8_t>& bytes,
                           std::size_t off, std::size_t stride,
                           std::uint32_t xor_key, float* out, std::size_t out_count)
{
    if (off + stride > bytes.size())
        return false;
    const std::size_t words = stride / sizeof(std::uint32_t);
    if (words > out_count)
        return false;
    for (std::size_t i = 0; i < words; ++i)
    {
        std::uint32_t word = 0;
        std::memcpy(&word, bytes.data() + off + i * sizeof(std::uint32_t), sizeof(word));
        word ^= xor_key;
        out[i] = float_from_u32(word);
    }
    return true;
}

bool decode_to_matrix4x4(const std::vector<std::uint8_t>& bytes,
                          std::size_t off, std::size_t stride,
                          std::uint32_t xor_key, bone_format_t format,
                          float out[16])
{
    std::fill(out, out + 16, 0.0f);
    if (off + stride > bytes.size())
        return false;
    switch (format)
    {
    case bone_format_t::matrix4x4_64:
    case bone_format_t::matrix3x4_64_pad:
        return decode_matrix_words(bytes, off, 64, xor_key, out);
    case bone_format_t::matrix3x4_48:
        return decode_matrix_words(bytes, off, 48, xor_key, out);
    case bone_format_t::quat_pos_28:
    {
        float data[7];
        if (!decode_words_generic(bytes, off, 28, xor_key, data, 7))
            return false;
        quat_to_matrix4x4_row_major(data[0], data[1], data[2], data[3],
                                     data[4], data[5], data[6], out);
        return true;
    }
    case bone_format_t::dual_quat_32:
    {
        float data[8];
        if (!decode_words_generic(bytes, off, 32, xor_key, data, 8))
            return false;
        dual_quat_to_matrix4x4_row_major(data[0], data[1], data[2], data[3],
                                          data[4], data[5], data[6], data[7], out);
        return true;
    }
    case bone_format_t::srt_quat_40:
    {
        float data[10];
        if (!decode_words_generic(bytes, off, 40, xor_key, data, 10))
            return false;
        float r[9];
        quat_to_matrix3x3_row_major(data[3], data[4], data[5], data[6], r);
        out[0]  = r[0] * data[0]; out[1]  = r[1] * data[1]; out[2]  = r[2] * data[2];
        out[4]  = r[3] * data[0]; out[5]  = r[4] * data[1]; out[6]  = r[5] * data[2];
        out[8]  = r[6] * data[0]; out[9]  = r[7] * data[1]; out[10] = r[8] * data[2];
        out[12] = data[7]; out[13] = data[8]; out[14] = data[9];
        out[15] = 1.0f;
        return true;
    }
    case bone_format_t::srt_mat3x3_60:
    {
        float data[15];
        if (!decode_words_generic(bytes, off, 60, xor_key, data, 15))
            return false;
        out[0]  = data[3] * data[0]; out[1]  = data[4] * data[1]; out[2]  = data[5] * data[2];
        out[4]  = data[6] * data[0]; out[5]  = data[7] * data[1]; out[6]  = data[8] * data[2];
        out[8]  = data[9] * data[0]; out[9]  = data[10] * data[1]; out[10] = data[11] * data[2];
        out[12] = data[12]; out[13] = data[13]; out[14] = data[14];
        out[15] = 1.0f;
        return true;
    }
    case bone_format_t::srt_quat_52_pad:
    {
        float data[10];
        if (!decode_words_generic(bytes, off, 40, xor_key, data, 10))
            return false;
        float r[9];
        quat_to_matrix3x3_row_major(data[3], data[4], data[5], data[6], r);
        out[0]  = r[0] * data[0]; out[1]  = r[1] * data[1]; out[2]  = r[2] * data[2];
        out[4]  = r[3] * data[0]; out[5]  = r[4] * data[1]; out[6]  = r[5] * data[2];
        out[8]  = r[6] * data[0]; out[9]  = r[7] * data[1]; out[10] = r[8] * data[2];
        out[12] = data[7]; out[13] = data[8]; out[14] = data[9];
        out[15] = 1.0f;
        return true;
    }
    default:
        return false;
    }
}

bool plausible_bone_format(const float* raw, std::size_t stride, double world_max)
{
    switch (stride)
    {
    case 64:
    {
        float mat[16];
        std::memcpy(mat, raw, 64);
        if (plausible_matrix4x4(mat, world_max))
            return true;
        return plausible_matrix3x4_64_pad(raw, world_max);
    }
    case 48:
    {
        float mat[16] = {};
        std::memcpy(mat, raw, 48);
        mat[15] = 1.0f;
        return plausible_matrix4x4(mat, world_max);
    }
    case 28:
        return plausible_quat_pos(raw, world_max);
    case 32:
        return plausible_dual_quat(raw, world_max);
    case 40:
        return plausible_srt_quat(raw, world_max);
    case 52:
        return plausible_srt_quat(raw, world_max);
    case 60:
        return plausible_srt_mat3x3(raw, world_max);
    default:
        return false;
    }
}

std::uint32_t matrix_run_count_decoded(const std::vector<std::uint8_t>& bytes,
                                        std::size_t off, std::size_t stride,
                                        std::uint32_t xor_key, double world_max,
                                        std::uint32_t max_count, matrix_eval_t* first_eval)
{
    std::uint32_t count = 0;
    for (std::size_t cursor = off; cursor + stride <= bytes.size() && count < max_count; cursor += stride)
    {
        if (stride == 48 || stride == 64)
        {
            float f[16] = {};
            if (!decode_matrix_words(bytes, cursor, stride, xor_key, f))
                break;
            if (stride == 64 && !plausible_matrix4x4(f, world_max))
            {
                if (!plausible_matrix3x4_64_pad(f, world_max))
                    break;
            }
            else if (stride == 48 && !plausible_matrix4x4(f, world_max))
                break;
            matrix_eval_t eval = evaluate_matrix4x4(f, world_max);
            if (count == 0 && first_eval)
                *first_eval = eval;
            ++count;
        }
        else
        {
            float raw[16];
            if (!decode_words_generic(bytes, cursor, stride, xor_key, raw, 16))
                break;
            if (!plausible_bone_format(raw, stride, world_max))
                break;
            float mat[16] = {};
            bone_format_t fmt = bone_format_t::unknown;
            switch (stride)
            {
            case 28: fmt = bone_format_t::quat_pos_28; break;
            case 32: fmt = bone_format_t::dual_quat_32; break;
            case 40: fmt = bone_format_t::srt_quat_40; break;
            case 52: fmt = bone_format_t::srt_quat_52_pad; break;
            case 60: fmt = bone_format_t::srt_mat3x3_60; break;
            }
            decode_to_matrix4x4(bytes, cursor, stride, xor_key, fmt, mat);
            matrix_eval_t eval = evaluate_matrix4x4(mat, world_max);
            if (count == 0 && first_eval)
                *first_eval = eval;
            ++count;
        }
    }
    return count;
}

std::vector<std::uint32_t> format_xor_key_candidates(const std::vector<std::uint8_t>& bytes,
                                                      std::size_t off, std::size_t stride)
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
    auto read_word = [&](std::size_t idx) -> std::uint32_t {
        std::uint32_t word = 0;
        std::memcpy(&word, bytes.data() + off + idx * sizeof(std::uint32_t), sizeof(word));
        return word;
    };
    if (stride == 48 || stride == 64)
    {
        const std::uint32_t one_indices[] = {0, 5, 10, 15};
        const std::uint32_t zero_indices[] = {3, 7, 11, 12, 13, 14};
        for (std::uint32_t idx : one_indices)
        {
            if (idx >= words) continue;
            push_key(read_word(idx) ^ expected_one);
        }
        for (std::uint32_t idx : zero_indices)
        {
            if (idx >= words) continue;
            push_key(read_word(idx) ^ expected_zero);
        }
    }
    else if (stride == 28)
    {
        push_key(read_word(3) ^ expected_one);
        push_key(read_word(4) ^ expected_zero);
        push_key(read_word(5) ^ expected_zero);
        push_key(read_word(6) ^ expected_zero);
    }
    else if (stride == 32)
    {
        push_key(read_word(3) ^ expected_one);
        for (int i = 4; i < 8; ++i)
            push_key(read_word(i) ^ expected_zero);
    }
    else if (stride == 40 || stride == 52)
    {
        for (int i = 0; i < 3; ++i)
            push_key(read_word(i) ^ expected_one);
        push_key(read_word(6) ^ expected_one);
        for (int i = 7; i < 10; ++i)
            push_key(read_word(i) ^ expected_zero);
    }
    else if (stride == 60)
    {
        for (int i = 0; i < 3; ++i)
            push_key(read_word(i) ^ expected_one);
        push_key(read_word(4) ^ expected_one);
        push_key(read_word(8) ^ expected_one);
        push_key(read_word(12) ^ expected_one);
        const std::uint32_t zero_indices_60[] = {5, 6, 7, 9, 10, 11, 13, 14};
        for (std::uint32_t idx : zero_indices_60)
        {
            if (idx >= words) continue;
            push_key(read_word(idx) ^ expected_zero);
        }
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
    struct format_entry_t
    {
        std::size_t stride;
        bone_format_t format;
    };
    const format_entry_t formats[] = {
        {64, bone_format_t::matrix4x4_64},
        {64, bone_format_t::matrix3x4_64_pad},
        {48, bone_format_t::matrix3x4_48},
        {60, bone_format_t::srt_mat3x3_60},
        {52, bone_format_t::srt_quat_52_pad},
        {40, bone_format_t::srt_quat_40},
        {32, bone_format_t::dual_quat_32},
        {28, bone_format_t::quat_pos_28},
    };
    for (std::size_t off = 0; off + 28 <= probe_end; off += 4)
    {
        for (const auto& fe : formats)
        {
            if (off + fe.stride > bytes.size())
                continue;
            for (std::uint32_t key : format_xor_key_candidates(bytes, off, fe.stride))
            {
                matrix_eval_t first;
                const std::uint32_t count = matrix_run_count_decoded(bytes, off, fe.stride, key,
                                                                       world_max, max_count, &first);
                if (count == 0)
                    continue;
                const bool better = count > best.count ||
                    (count == best.count && key == 0 && best.xor_key != 0) ||
                    (count == best.count && key == 0 && best.format == bone_format_t::unknown);
                if (!better)
                    continue;
                best.count = count;
                best.stride = fe.stride;
                best.offset = off;
                best.xor_key = key;
                best.decode = key == 0 ? "raw_float32" : "xor32_float32";
                best.first_eval = first;
                best.format = fe.format;
                best.entry_stride = fe.stride;
            }
        }
    }
    return best;
}

matrix_decode_result_t best_interleaved_decode_run(const std::vector<std::uint8_t>& bytes,
                                                    double world_max,
                                                    std::uint32_t max_count,
                                                    std::size_t max_probe_bytes)
{
    matrix_decode_result_t best;
    const std::size_t probe_end = std::min<std::size_t>(bytes.size(), max_probe_bytes);
    const std::size_t matrix_strides[] = {48, 64, 28, 32, 40, 52, 60};
    const std::size_t entry_strides[] = {64, 80, 96, 112, 128, 192, 256};
    for (std::size_t off = 0; off + 64 <= probe_end; off += 16)
    {
        for (std::size_t mstride : matrix_strides)
        {
            for (std::size_t estride : entry_strides)
            {
                if (estride <= mstride || off + estride > bytes.size())
                    continue;
                for (std::uint32_t key : format_xor_key_candidates(bytes, off, mstride))
                {
                    std::uint32_t count = 0;
                    for (std::size_t cursor = off; cursor + mstride <= bytes.size() && count < max_count; cursor += estride)
                    {
                        float raw[16];
                        if (!decode_words_generic(bytes, cursor, mstride, key, raw, 16))
                            break;
                        if (!plausible_bone_format(raw, mstride, world_max))
                            break;
                        ++count;
                    }
                    if (count == 0)
                        continue;
                    const bool better = count > best.count ||
                        (count == best.count && key == 0 && best.xor_key != 0);
                    if (!better)
                        continue;
                    best.count = count;
                    best.stride = mstride;
                    best.entry_stride = estride;
                    best.offset = off;
                    best.xor_key = key;
                    best.decode = key == 0 ? "raw_float32_interleaved" : "xor32_float32_interleaved";
                    best.format = bone_format_t::unknown;
                }
            }
        }
    }
    return best;
}

bool decode_matrix_rolling_xor(const std::vector<std::uint8_t>& bytes,
                               std::size_t off, std::size_t stride,
                               std::uint32_t seed, std::uint32_t multiplier,
                               std::uint32_t increment, float* out)
{
    if (off + stride > bytes.size() || (stride != 48 && stride != 64))
        return false;
    std::fill(out, out + 16, 0.0f);
    const std::size_t words = stride / sizeof(std::uint32_t);
    std::uint32_t key = seed;
    for (std::size_t i = 0; i < words; ++i)
    {
        std::uint32_t word = 0;
        std::memcpy(&word, bytes.data() + off + i * sizeof(std::uint32_t), sizeof(word));
        word ^= key;
        out[i] = float_from_u32(word);
        key = key * multiplier + increment;
    }
    if (stride == 48)
        out[15] = 1.0f;
    return true;
}

bool decode_matrix_multi_key_xor(const std::vector<std::uint8_t>& bytes,
                                  std::size_t off, std::size_t stride,
                                  const std::vector<std::uint32_t>& keys, float* out)
{
    if (off + stride > bytes.size() || (stride != 48 && stride != 64))
        return false;
    if (keys.empty())
        return false;
    std::fill(out, out + 16, 0.0f);
    const std::size_t words = stride / sizeof(std::uint32_t);
    for (std::size_t i = 0; i < words; ++i)
    {
        std::uint32_t word = 0;
        std::memcpy(&word, bytes.data() + off + i * sizeof(std::uint32_t), sizeof(word));
        word ^= keys[i % keys.size()];
        out[i] = float_from_u32(word);
    }
    if (stride == 48)
        out[15] = 1.0f;
    return true;
}

bool decode_matrix_additive(const std::vector<std::uint8_t>& bytes,
                             std::size_t off, std::size_t stride,
                             std::uint32_t add_key, bool word_mode, float* out)
{
    if (off + stride > bytes.size() || (stride != 48 && stride != 64))
        return false;
    std::fill(out, out + 16, 0.0f);
    if (word_mode)
    {
        const std::size_t words = stride / sizeof(std::uint32_t);
        for (std::size_t i = 0; i < words; ++i)
        {
            std::uint32_t word = 0;
            std::memcpy(&word, bytes.data() + off + i * sizeof(std::uint32_t), sizeof(word));
            word = word - add_key;
            out[i] = float_from_u32(word);
        }
    }
    else
    {
        for (std::size_t i = 0; i + sizeof(std::uint32_t) <= stride; i += sizeof(std::uint32_t))
        {
            std::uint32_t word = 0;
            std::memcpy(&word, bytes.data() + off + i, sizeof(word));
            const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(&word);
            std::uint32_t decoded = 0;
            for (int b = 0; b < 4; ++b)
                reinterpret_cast<std::uint8_t*>(&decoded)[b] =
                    static_cast<std::uint8_t>(p[b] - static_cast<std::uint8_t>(add_key >> (b * 8)));
            out[i / sizeof(std::uint32_t)] = float_from_u32(decoded);
        }
    }
    if (stride == 48)
        out[15] = 1.0f;
    return true;
}

multi_decode_result_t best_multi_decode_run(const std::vector<std::uint8_t>& bytes,
                                             double world_max,
                                             std::uint32_t max_count,
                                             std::size_t max_probe_bytes)
{
    multi_decode_result_t best;

    matrix_decode_result_t baseline = best_matrix_decode_run(bytes, world_max, max_count, max_probe_bytes);
    if (baseline.count > 0)
    {
        best.algorithm = baseline.xor_key == 0 ? decode_algorithm_t::raw_float32 : decode_algorithm_t::xor_uniform;
        best.algorithm_name = baseline.decode;
        best.count = baseline.count;
        best.stride = baseline.stride;
        best.offset = baseline.offset;
        best.uniform_key = baseline.xor_key;
        best.first_eval = baseline.first_eval;
        best.format = baseline.format;
        best.entry_stride = baseline.entry_stride;
    }

    const std::size_t probe_end = std::min<std::size_t>(bytes.size(), max_probe_bytes);

    auto try_rolling = [&](std::size_t off, std::size_t stride,
                           std::uint32_t seed, std::uint32_t mul, std::uint32_t inc) {
        std::uint32_t count = 0;
        matrix_eval_t first{};
        bool first_eval_set = false;
        for (std::size_t cursor = off; cursor + stride <= bytes.size() && count < max_count; cursor += stride)
        {
            float f[16] = {};
            if (!decode_matrix_rolling_xor(bytes, cursor, stride, seed, mul, inc, f))
                break;
            matrix_eval_t eval = evaluate_matrix4x4(f, world_max);
            if (!eval.plausible)
                break;
            if (count == 0) { first = eval; first_eval_set = true; }
            ++count;
        }
        if (count > 0 && (count > best.count ||
            (count == best.count && best.algorithm == decode_algorithm_t::raw_float32)))
        {
            best.algorithm = decode_algorithm_t::xor_rolling;
            best.algorithm_name = "xor_rolling";
            best.count = count;
            best.stride = stride;
            best.offset = off;
            best.rolling_seed = seed;
            best.rolling_multiplier = mul;
            best.rolling_increment = inc;
            best.uniform_key = 0;
            best.format = bone_format_t::unknown;
            best.entry_stride = stride;
            if (first_eval_set) best.first_eval = first;
        }
    };
    auto try_additive = [&](std::size_t off, std::size_t stride, std::uint32_t key, bool word_mode) {
        std::uint32_t count = 0;
        matrix_eval_t first{};
        bool first_eval_set = false;
        for (std::size_t cursor = off; cursor + stride <= bytes.size() && count < max_count; cursor += stride)
        {
            float f[16] = {};
            if (!decode_matrix_additive(bytes, cursor, stride, key, word_mode, f))
                break;
            matrix_eval_t eval = evaluate_matrix4x4(f, world_max);
            if (!eval.plausible)
                break;
            if (count == 0) { first = eval; first_eval_set = true; }
            ++count;
        }
        if (count > 0 && (count > best.count ||
            (count == best.count && best.algorithm == decode_algorithm_t::raw_float32)))
        {
            best.algorithm = word_mode ? decode_algorithm_t::additive_word : decode_algorithm_t::additive_byte;
            best.algorithm_name = word_mode ? "additive_word32" : "additive_byte";
            best.count = count;
            best.stride = stride;
            best.offset = off;
            best.additive_key = key;
            best.uniform_key = 0;
            best.format = bone_format_t::unknown;
            best.entry_stride = stride;
            if (first_eval_set) best.first_eval = first;
        }
    };

    for (std::size_t off = 0; off + 48 <= probe_end; off += 16)
    {
        for (std::size_t stride : {64ull, 48ull})
        {
            if (off + stride > bytes.size())
                continue;
            static const std::uint32_t common_seeds[] = {0x3F800000u, 0x40000000u, 0x00000001u, 0xDEADBEEFu, 0xCAFEBABEu};
            static const std::uint32_t common_muls[] = {0x00000001u, 0x00000101u, 0x01000193u};
            static const std::uint32_t common_incs[] = {0u, 0x3F800000u, 0x00000001u};
            for (std::uint32_t seed : common_seeds)
                for (std::uint32_t mul : common_muls)
                    for (std::uint32_t inc : common_incs)
                        try_rolling(off, stride, seed, mul, inc);
            for (std::uint32_t key : format_xor_key_candidates(bytes, off, stride))
            {
                try_additive(off, stride, key, true);
                try_additive(off, stride, key, false);
            }
        }
    }
    return best;
}

decryption_analysis_t derive_decryption_from_pair(const std::vector<std::uint8_t>& encrypted,
                                                   const std::vector<std::uint8_t>& decrypted,
                                                   std::size_t compare_size)
{
    decryption_analysis_t result;
    const std::size_t n = std::min(compare_size, std::min(encrypted.size(), decrypted.size()));
    if (n < 16)
    {
        result.verification_detail = "insufficient_data";
        return result;
    }
    result.total_bytes = n;

    bool uniform_xor_match = true;
    std::uint32_t xor_key_candidate = 0;
    std::memcpy(&xor_key_candidate, encrypted.data(), sizeof(xor_key_candidate));
    std::uint32_t first_decrypted_word = 0;
    std::memcpy(&first_decrypted_word, decrypted.data(), sizeof(first_decrypted_word));
    xor_key_candidate ^= first_decrypted_word;
    for (std::size_t i = 0; i + 3 < n; i += 4)
    {
        std::uint32_t enc_word = 0, dec_word = 0;
        std::memcpy(&enc_word, encrypted.data() + i, sizeof(enc_word));
        std::memcpy(&dec_word, decrypted.data() + i, sizeof(dec_word));
        if ((enc_word ^ xor_key_candidate) != dec_word)
        {
            uniform_xor_match = false;
            break;
        }
        ++result.match_bytes;
    }
    if (uniform_xor_match)
    {
        result.algorithm = decode_algorithm_t::xor_uniform;
        result.algorithm_name = "xor_uniform";
        result.uniform_key = xor_key_candidate;
        result.key_words.push_back(xor_key_candidate);
        result.derived_key_bytes.resize(4);
        std::memcpy(result.derived_key_bytes.data(), &xor_key_candidate, 4);
        result.key_length = 4;
        result.key_pattern = "uniform_32bit";
        result.verified = true;
        result.verification_detail = "verified_uniform_xor_all_words_match";
        return result;
    }

    result.match_bytes = 0;
    std::vector<std::uint32_t> per_word_keys;
    per_word_keys.reserve(n / 4);
    for (std::size_t i = 0; i + 3 < n; i += 4)
    {
        std::uint32_t enc_word = 0, dec_word = 0;
        std::memcpy(&enc_word, encrypted.data() + i, sizeof(enc_word));
        std::memcpy(&dec_word, decrypted.data() + i, sizeof(dec_word));
        per_word_keys.push_back(enc_word ^ dec_word);
    }
    bool all_same = per_word_keys.size() > 1 &&
        std::all_of(per_word_keys.begin(), per_word_keys.end(),
                     [&](std::uint32_t k) { return k == per_word_keys[0]; });
    if (!all_same && per_word_keys.size() >= 4)
    {
        bool is_multi_key = true;
        const std::size_t period = per_word_keys.size() / 4;
        for (std::size_t i = period; i < per_word_keys.size(); ++i)
        {
            if (per_word_keys[i] != per_word_keys[i % period])
            {
                is_multi_key = false;
                break;
            }
        }
        if (is_multi_key)
        {
            result.algorithm = decode_algorithm_t::xor_multi_key;
            result.algorithm_name = "xor_multi_key";
            result.key_words.assign(per_word_keys.begin(), per_word_keys.begin() + period);
            result.key_length = static_cast<std::uint32_t>(period * 4);
            result.derived_key_bytes.resize(period * 4);
            for (std::size_t i = 0; i < period; ++i)
                std::memcpy(result.derived_key_bytes.data() + i * 4, &per_word_keys[i], 4);
            result.key_pattern = "multi_key_period_" + std::to_string(period);
            result.verified = true;
            result.verification_detail = "verified_multi_key_xor_periodic_match";
            result.match_bytes = n;
            return result;
        }
        bool per_element_rolling = true;
        for (std::size_t i = 4; i < per_word_keys.size(); ++i)
        {
            const std::uint32_t expected = per_word_keys[i - 1] * 0x00000101u + 0x3F800000u;
            if (per_word_keys[i] != expected)
            {
                per_element_rolling = false;
                break;
            }
        }
        if (per_element_rolling && per_word_keys.size() >= 8)
        {
            result.algorithm = decode_algorithm_t::xor_rolling;
            result.algorithm_name = "xor_rolling";
            result.rolling_seed = per_word_keys[0];
            result.rolling_multiplier = 0x00000101u;
            result.rolling_increment = 0x3F800000u;
            result.key_words = {per_word_keys[0]};
            result.key_length = 4;
            result.derived_key_bytes.resize(4);
            std::memcpy(result.derived_key_bytes.data(), &result.rolling_seed, 4);
            result.key_pattern = "rolling_lcg";
            result.verified = true;
            result.verification_detail = "verified_rolling_xor_lcg_match";
            result.match_bytes = n;
            return result;
        }
        result.algorithm = decode_algorithm_t::custom;
        result.algorithm_name = "custom_per_word_xor";
        result.key_words = per_word_keys;
        result.key_length = static_cast<std::uint32_t>(per_word_keys.size() * 4);
        result.derived_key_bytes.resize(per_word_keys.size() * 4);
        for (std::size_t i = 0; i < per_word_keys.size(); ++i)
            std::memcpy(result.derived_key_bytes.data() + i * 4, &per_word_keys[i], 4);
        result.key_pattern = "per_word_key_stream";
        result.verified = true;
        result.verification_detail = "verified_per_word_xor_full_key_stream";
        result.match_bytes = n;
        return result;
    }

    result.match_bytes = 0;
    bool additive_word_match = true;
    std::uint32_t add_key_candidate = 0;
    std::memcpy(&add_key_candidate, encrypted.data(), sizeof(add_key_candidate));
    std::uint32_t first_dec = 0;
    std::memcpy(&first_dec, decrypted.data(), sizeof(first_dec));
    add_key_candidate = first_dec - add_key_candidate;
    for (std::size_t i = 0; i + 3 < n; i += 4)
    {
        std::uint32_t enc_word = 0, dec_word = 0;
        std::memcpy(&enc_word, encrypted.data() + i, sizeof(enc_word));
        std::memcpy(&dec_word, decrypted.data() + i, sizeof(dec_word));
        if ((enc_word + add_key_candidate) != dec_word)
        {
            additive_word_match = false;
            break;
        }
        ++result.match_bytes;
    }
    if (additive_word_match)
    {
        result.algorithm = decode_algorithm_t::additive_word;
        result.algorithm_name = "additive_word32";
        result.additive_key = add_key_candidate;
        result.key_words.push_back(add_key_candidate);
        result.derived_key_bytes.resize(4);
        std::memcpy(result.derived_key_bytes.data(), &add_key_candidate, 4);
        result.key_length = 4;
        result.key_pattern = "uniform_additive_32bit";
        result.verified = true;
        result.verification_detail = "verified_additive_word_all_words_match";
        return result;
    }

    result.algorithm = decode_algorithm_t::custom;
    result.algorithm_name = "unknown";
    result.verification_detail = "no_uniform_additive_xor_pattern_matched";
    return result;
}

bool verify_decryption(const std::vector<std::uint8_t>& encrypted,
                       const std::vector<std::uint8_t>& expected_decrypted,
                       const decryption_analysis_t& analysis,
                       std::size_t compare_size)
{
    if (!analysis.verified)
        return false;
    const std::size_t n = std::min(compare_size, std::min(encrypted.size(), expected_decrypted.size()));
    std::vector<std::uint8_t> redecrypted(n, 0);
    for (std::size_t i = 0; i + 4 <= n; i += 4)
    {
        std::uint32_t enc_word = 0;
        std::memcpy(&enc_word, encrypted.data() + i, sizeof(enc_word));
        std::uint32_t dec_word = 0;
        switch (analysis.algorithm)
        {
        case decode_algorithm_t::xor_uniform:
            dec_word = enc_word ^ analysis.uniform_key;
            break;
        case decode_algorithm_t::xor_multi_key:
            if (analysis.key_words.empty()) return false;
            dec_word = enc_word ^ analysis.key_words[(i / 4) % analysis.key_words.size()];
            break;
        case decode_algorithm_t::xor_rolling:
        {
            std::uint32_t key = analysis.rolling_seed;
            for (std::size_t j = 0; j < i / 4; ++j)
                key = key * analysis.rolling_multiplier + analysis.rolling_increment;
            dec_word = enc_word ^ key;
            break;
        }
        case decode_algorithm_t::additive_word:
            dec_word = enc_word + analysis.additive_key;
            break;
        case decode_algorithm_t::additive_byte:
        {
            for (int b = 0; b < 4; ++b)
                redecrypted[i + b] = static_cast<std::uint8_t>(
                    encrypted[i + b] + static_cast<std::uint8_t>(analysis.additive_key >> (b * 8)));
            continue;
        }
        default:
            return false;
        }
        std::memcpy(redecrypted.data() + i, &dec_word, sizeof(dec_word));
    }
    return std::equal(redecrypted.begin(), redecrypted.begin() + n, expected_decrypted.begin());
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
    matrix_decode_result_t decoded = best_matrix_decode_run(bytes, 1000000.0, 256, 512);
    const std::uint32_t matrix_count = decoded.count;
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
    row["matrix_size"] = decoded.stride;
    row["format"] = bone_format_name(decoded.format);
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
            matrix_decode_result_t decoded = best_matrix_decode_run(bytes, world_max, 256, static_cast<std::size_t>(bytes.size() - off));
            const std::uint32_t best_run = decoded.count;
            if (best_run == 0)
                continue;
            auto row = make_cbuffer_candidate(pid, -1, region.base + off + decoded.offset, 0, 0,
                                               "bounded_private_memory_matrix_scan", 0.35);
            if (!row)
                continue;
            (*row)["matrix_count"] = best_run;
            (*row)["matrix_size"] = decoded.stride;
            (*row)["format"] = bone_format_name(decoded.format);
            (*row)["confidence"] = std::min(0.95, 0.38 + static_cast<double>(best_run) * 0.04);
            append_unique_candidate(out, *row, seen, limit);
            off += decoded.stride * std::max<std::uint32_t>(best_run, 1);
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

std::string classify_mesh_type(std::uint32_t index_count, std::uint32_t vertex_count, const std::string& draw_kind)
{
    if (draw_kind.find("Indexed") != std::string::npos)
    {
        if (vertex_count >= 1000 && vertex_count <= 50000 && index_count >= 2000 && index_count <= 80000)
            return "character";
        if (vertex_count >= 100 && vertex_count <= 2000 && index_count <= 6000)
            return "weapon";
        if (vertex_count >= 10000)
            return "world_or_static";
    }
    else
    {
        if (vertex_count >= 1000 && vertex_count <= 50000)
            return "character";
        if (vertex_count >= 100 && vertex_count <= 2000)
            return "weapon";
        if (vertex_count >= 10000)
            return "world_or_static";
    }
    return "unknown";
}

std::uint32_t current_frame_index(std::uint32_t /*pid*/)
{
    return frame_tracking_state().current_frame.load(std::memory_order_acquire);
}

std::uint32_t current_draw_ordinal(std::uint32_t /*pid*/)
{
    return frame_tracking_state().current_draw_ordinal.load(std::memory_order_acquire);
}

struct per_frame_bind_state_t
{
    std::atomic<std::uint64_t> last_cbuffer_va{0};
    std::atomic<int> last_cbuffer_slot{-1};
    std::atomic<std::uint64_t> last_cbuffer_timestamp_ms{0};
};

per_frame_bind_state_t& per_frame_bind_state()
{
    static per_frame_bind_state_t state;
    return state;
}

std::string classification_to_string(store::cbuffer_class_t c)
{
    switch (c)
    {
    case store::cbuffer_class_t::persistent: return "persistent";
    case store::cbuffer_class_t::per_draw: return "per_draw";
    case store::cbuffer_class_t::static_bind: return "static";
    default: return "unknown";
    }
}

json draw_call_info_to_json(const store::draw_call_info_t& dc)
{
    json j;
    j["timestamp_ms"] = dc.timestamp_ms;
    j["index_count"] = dc.index_count;
    j["vertex_count"] = dc.vertex_count;
    j["start_index"] = dc.start_index;
    j["instance_count"] = dc.instance_count;
    j["start_vertex"] = dc.start_vertex;
    j["base_vertex"] = dc.base_vertex;
    j["draw_kind"] = dc.draw_kind;
    j["likely_mesh_type"] = dc.likely_mesh_type;
    j["preceding_cbuffer_va"] = dc.preceding_cbuffer_va ? json(sa_format_address(dc.preceding_cbuffer_va)) : json(nullptr);
    j["preceding_cbuffer_slot"] = dc.preceding_cbuffer_slot;
    j["preceding_cbuffer_timestamp_ms"] = dc.preceding_cbuffer_timestamp_ms;
    j["frame_index"] = dc.frame_index;
    j["draw_ordinal"] = dc.draw_ordinal;
    return j;
}

json frame_batch_to_json(const store::frame_batch_t& fb)
{
    json j;
    j["pid"] = fb.pid;
    j["frame_index"] = fb.frame_index;
    j["start_timestamp_ms"] = fb.start_timestamp_ms;
    j["end_timestamp_ms"] = fb.end_timestamp_ms;
    j["total_draw_count"] = fb.total_draw_count;
    j["character_draw_count"] = fb.character_draw_count;
    j["weapon_draw_count"] = fb.weapon_draw_count;
    j["world_draw_count"] = fb.world_draw_count;
    json draws = json::array();
    for (const auto& dc : fb.draw_calls)
        draws.push_back(draw_call_info_to_json(dc));
    j["draw_calls"] = std::move(draws);
    json binds = json::array();
    for (const auto& [va, slot] : fb.cbuffer_binds)
    {
        binds.push_back({
            {"va", sa_format_address(va)},
            {"slot", slot >= 0 ? json(slot) : json(nullptr)}
        });
    }
    j["cbuffer_binds"] = std::move(binds);
    json vbinds = json::array();
    for (const auto& [va, slot] : fb.vertex_buffer_binds)
    {
        vbinds.push_back({
            {"va", sa_format_address(va)},
            {"slot", slot >= 0 ? json(slot) : json(nullptr)}
        });
    }
    j["vertex_buffer_binds"] = std::move(vbinds);
    return j;
}

json cbuffer_classification_to_json(const store::cbuffer_classification_t& cc)
{
    json j;
    j["va"] = sa_format_address(cc.va);
    j["slot"] = cc.slot >= 0 ? json(cc.slot) : json(nullptr);
    j["classification"] = classification_to_string(cc.classification);
    j["frames_seen"] = cc.frames_seen;
    j["total_binds"] = cc.total_binds;
    j["distinct_draw_calls"] = cc.distinct_draw_calls;
    j["frequency_score"] = cc.frequency_score;
    j["recommended_for"] = cc.recommended_for;
    json frames = json::array();
    for (auto f : cc.frame_indices) frames.push_back(f);
    j["frame_indices"] = std::move(frames);
    json draws = json::array();
    for (const auto& dc : cc.associated_draw_calls)
        draws.push_back(draw_call_info_to_json(dc));
    j["associated_draw_calls"] = std::move(draws);
    return j;
}

json hot_va_to_json(const store::hot_va_entry_t& hv)
{
    json j;
    j["va"] = sa_format_address(hv.va);
    j["slot"] = hv.slot >= 0 ? json(hv.slot) : json(nullptr);
    j["pid"] = hv.pid;
    j["hit_count"] = hv.hit_count;
    j["frame_count"] = hv.frame_count;
    j["first_seen_ms"] = hv.first_seen_ms;
    j["last_seen_ms"] = hv.last_seen_ms;
    j["confidence_boost"] = hv.confidence_boost;
    return j;
}

store::draw_call_info_t extract_draw_call_info(std::uint32_t pid,
                                               const driver_bridge::thread_context_t& ctx,
                                               const store::dx_hook_record_t& record,
                                               std::uint32_t frame_index,
                                               std::uint32_t draw_ordinal)
{
    store::draw_call_info_t dc;
    dc.timestamp_ms = unix_time_ms();
    dc.frame_index = frame_index;
    dc.draw_ordinal = draw_ordinal;
    dc.draw_kind = record.action == "draw" ? record.api : "unknown";

    if (record.action == "draw")
    {
        if (record.target_name == "DrawIndexed")
        {
            dc.index_count = static_cast<std::uint32_t>(ctx.rdx);
            dc.start_index = static_cast<std::uint32_t>(ctx.r8);
            dc.base_vertex = static_cast<int>(ctx.r9);
            dc.vertex_count = 0;
            dc.draw_kind = "DrawIndexed";
        }
        else if (record.target_name == "DrawInstanced")
        {
            dc.vertex_count = static_cast<std::uint32_t>(ctx.rdx);
            dc.instance_count = static_cast<std::uint32_t>(ctx.r8);
            dc.start_vertex = static_cast<std::uint32_t>(ctx.r9);
            dc.draw_kind = "DrawInstanced";
        }
        else if (record.target_name == "Draw")
        {
            dc.vertex_count = static_cast<std::uint32_t>(ctx.rdx);
            dc.start_vertex = static_cast<std::uint32_t>(ctx.r8);
            dc.draw_kind = "Draw";
        }
        else if (record.target_name == "DrawIndexedInstanced")
        {
            dc.index_count = static_cast<std::uint32_t>(ctx.rdx);
            dc.instance_count = static_cast<std::uint32_t>(ctx.r8);
            dc.start_index = static_cast<std::uint32_t>(ctx.r9);
            dc.base_vertex = static_cast<int>(stack_arg64(pid, ctx.rsp, 0));
            dc.draw_kind = "DrawIndexedInstanced";
        }
        else
        {
            const std::string api = lower_ascii(record.api);
            if (api.find("d3d11") != std::string::npos || api.find("d3d12") != std::string::npos)
            {
                auto mod = find_module_for_address(pid, record.target_va);
                if (mod && mod->name.find("DrawIndexed") != std::string::npos)
                {
                    dc.index_count = static_cast<std::uint32_t>(ctx.rdx);
                    dc.start_index = static_cast<std::uint32_t>(ctx.r8);
                    dc.base_vertex = static_cast<int>(ctx.r9);
                    dc.vertex_count = 0;
                    dc.draw_kind = "DrawIndexed";
                }
                else if (mod && mod->name.find("DrawInstanced") != std::string::npos)
                {
                    dc.vertex_count = static_cast<std::uint32_t>(ctx.rdx);
                    dc.instance_count = static_cast<std::uint32_t>(ctx.r8);
                    dc.start_vertex = static_cast<std::uint32_t>(ctx.r9);
                    dc.draw_kind = "DrawInstanced";
                }
                else if (mod && mod->name.find("Draw") != std::string::npos)
                {
                    dc.vertex_count = static_cast<std::uint32_t>(ctx.rdx);
                    dc.start_vertex = static_cast<std::uint32_t>(ctx.r8);
                    dc.draw_kind = "Draw";
                }
            }
        }
    }

    auto& bs = per_frame_bind_state();
    dc.preceding_cbuffer_va = bs.last_cbuffer_va.load(std::memory_order_acquire);
    dc.preceding_cbuffer_slot = bs.last_cbuffer_slot.load(std::memory_order_acquire);
    dc.preceding_cbuffer_timestamp_ms = bs.last_cbuffer_timestamp_ms.load(std::memory_order_acquire);

    dc.likely_mesh_type = classify_mesh_type(dc.index_count, dc.vertex_count, dc.draw_kind);
    return dc;
}

void update_hot_vas_from_frame(std::uint32_t pid, const store::frame_batch_t& batch)
{
    auto existing = store::list_hot_vas(pid);
    for (const auto& [va, slot] : batch.cbuffer_binds)
    {
        auto it = std::find_if(existing.begin(), existing.end(), [&](const store::hot_va_entry_t& e) {
            return e.va == va && e.slot == slot;
        });
        if (it != existing.end())
        {
            store::hot_va_entry_t updated = *it;
            updated.hit_count++;
            updated.frame_count++;
            updated.last_seen_ms = batch.end_timestamp_ms;
            updated.confidence_boost = std::min(0.20, updated.hit_count * 0.02);
            store::update_hot_va(updated);
        }
        else
        {
            store::hot_va_entry_t entry;
            entry.va = va;
            entry.slot = slot;
            entry.pid = pid;
            entry.hit_count = 1;
            entry.frame_count = 1;
            entry.first_seen_ms = batch.end_timestamp_ms;
            entry.last_seen_ms = batch.end_timestamp_ms;
            entry.confidence_boost = 0.02;
            store::add_hot_va(entry);
        }
    }
}

void on_present_hit(std::uint32_t pid, std::uint32_t /*tid*/, const driver_bridge::thread_context_t& /*ctx*/)
{
    auto& state = frame_tracking_state();
    if (!state.enabled.load(std::memory_order_acquire))
        return;

    const std::uint32_t completed_frame = state.current_frame.load(std::memory_order_acquire);
    const std::uint64_t start_ms = state.frame_start_ms.load(std::memory_order_acquire);

    store::frame_batch_t batch;
    batch.pid = pid;
    batch.frame_index = completed_frame;
    batch.start_timestamp_ms = start_ms;
    batch.end_timestamp_ms = unix_time_ms();

    std::vector<store::draw_call_info_t> frame_draws;
    std::vector<std::pair<std::uint64_t, int>> frame_cbuffers;
    for (const auto& record : store::list_dx_hooks(pid))
    {
        for (const auto& cap : record.captures)
        {
            const std::uint32_t cap_frame = cap.value("frame_index", 0u);
            if (cap_frame != completed_frame)
                continue;
            if (cap.contains("draw_call_info") && cap["draw_call_info"].is_object())
            {
                store::draw_call_info_t dc;
                dc.timestamp_ms = cap["draw_call_info"].value("timestamp_ms", 0ull);
                dc.index_count = cap["draw_call_info"].value("index_count", 0u);
                dc.vertex_count = cap["draw_call_info"].value("vertex_count", 0u);
                dc.draw_kind = cap["draw_call_info"].value("draw_kind", std::string());
                dc.likely_mesh_type = cap["draw_call_info"].value("likely_mesh_type", std::string());
                dc.frame_index = completed_frame;
                if (cap["draw_call_info"].contains("preceding_cbuffer_va"))
                {
                    std::uint64_t pva = 0;
                    if (parse_u64_value(cap["draw_call_info"]["preceding_cbuffer_va"], pva))
                        dc.preceding_cbuffer_va = pva;
                }
                dc.preceding_cbuffer_slot = cap["draw_call_info"].value("preceding_cbuffer_slot", -1);
                frame_draws.push_back(dc);
            }
            if (cap.contains("cbuffers") && cap["cbuffers"].is_array())
            {
                for (const auto& cb : cap["cbuffers"])
                {
                    std::uint64_t va = 0;
                    if (cb.contains("va") && parse_u64_value(cb["va"], va) && va != 0)
                    {
                        int slot = -1;
                        if (cb.contains("slot") && cb["slot"].is_number_integer())
                            slot = cb["slot"].get<int>();
                        frame_cbuffers.push_back({va, slot});
                    }
                }
            }
        }
    }

    batch.draw_calls = std::move(frame_draws);
    batch.cbuffer_binds = std::move(frame_cbuffers);
    batch.total_draw_count = static_cast<std::uint32_t>(batch.draw_calls.size());
    for (const auto& dc : batch.draw_calls)
    {
        if (dc.likely_mesh_type == "character") ++batch.character_draw_count;
        else if (dc.likely_mesh_type == "weapon") ++batch.weapon_draw_count;
        else if (dc.likely_mesh_type == "world_or_static") ++batch.world_draw_count;
    }

    store::add_frame_batch(batch);
    update_hot_vas_from_frame(pid, batch);

    state.current_frame.store(completed_frame + 1, std::memory_order_release);
    state.current_draw_ordinal.store(0, std::memory_order_release);
    state.frame_start_ms.store(unix_time_ms(), std::memory_order_release);
}

std::vector<store::cbuffer_classification_t> classify_cbuffers(std::uint32_t pid, std::size_t min_frames = 2)
{
    auto batches = store::list_frame_batches(pid);
    if (batches.size() < min_frames)
        return {};

    struct va_accumulator_t
    {
        int slot = -1;
        std::set<std::uint32_t> frames;
        std::uint32_t total_binds = 0;
        std::set<std::uint32_t> draw_ordinals;
        std::vector<store::draw_call_info_t> associated_draws;
    };

    std::map<std::uint64_t, va_accumulator_t> accumulators;
    for (const auto& batch : batches)
    {
        for (const auto& [va, slot] : batch.cbuffer_binds)
        {
            auto& acc = accumulators[va];
            acc.slot = slot;
            acc.frames.insert(batch.frame_index);
            ++acc.total_binds;
        }
        for (const auto& dc : batch.draw_calls)
        {
            if (dc.preceding_cbuffer_va != 0)
            {
                auto& acc = accumulators[dc.preceding_cbuffer_va];
                acc.draw_ordinals.insert(dc.draw_ordinal);
                acc.associated_draws.push_back(dc);
            }
        }
    }

    std::vector<store::cbuffer_classification_t> results;
    const std::uint32_t total_frames = static_cast<std::uint32_t>(batches.size());
    for (auto& [va, acc] : accumulators)
    {
        store::cbuffer_classification_t cc;
        cc.va = va;
        cc.slot = acc.slot;
        cc.pid = pid;
        cc.frames_seen = static_cast<std::uint32_t>(acc.frames.size());
        cc.total_binds = acc.total_binds;
        cc.distinct_draw_calls = static_cast<std::uint32_t>(acc.draw_ordinals.size());
        cc.frame_indices = {acc.frames.begin(), acc.frames.end()};
        cc.associated_draw_calls = std::move(acc.associated_draws);

        const double frame_ratio = static_cast<double>(cc.frames_seen) / static_cast<double>(total_frames);
        cc.frequency_score = frame_ratio;

        if (frame_ratio >= 0.8 && cc.total_binds > total_frames)
        {
            cc.classification = store::cbuffer_class_t::persistent;
            cc.recommended_for = "view_matrix";
        }
        else if (cc.distinct_draw_calls > 0 && frame_ratio < 0.5)
        {
            cc.classification = store::cbuffer_class_t::per_draw;
            cc.recommended_for = "bone_buffer";
        }
        else if (cc.frames_seen <= 1 && cc.total_binds <= 2)
        {
            cc.classification = store::cbuffer_class_t::static_bind;
            cc.recommended_for = "material_or_texture_constants";
        }
        else
        {
            cc.classification = store::cbuffer_class_t::unknown;
            cc.recommended_for = "unknown";
        }

        results.push_back(std::move(cc));
    }

    std::sort(results.begin(), results.end(), [](const store::cbuffer_classification_t& a, const store::cbuffer_classification_t& b) {
        if (a.classification != b.classification)
            return static_cast<int>(a.classification) < static_cast<int>(b.classification);
        return a.frequency_score > b.frequency_score;
    });

    return results;
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
    const std::uint32_t fidx = current_frame_index(pid);
    cap["frame_index"] = fidx;
    if (record.action == "draw")
    {
        store::draw_call_info_t dc = extract_draw_call_info(pid, ctx, record, fidx, current_draw_ordinal(pid));
        cap["draw_call_info"] = draw_call_info_to_json(dc);
    }
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
        if (record.action == "present")
            on_present_hit(pid, tid, ctx);
        else if (record.action == "draw")
            frame_tracking_state().current_draw_ordinal.fetch_add(1, std::memory_order_acq_rel);
        else if (record.action == "cbuffer_bind")
        {
            const std::string api = lower_ascii(record.api);
            if (api.find("d3d11") != std::string::npos)
            {
                auto& bs = per_frame_bind_state();
                std::vector<std::uint8_t> ptrs;
                if (read_bytes(pid, ctx.r9, 8, ptrs) && ptrs.size() >= 8)
                {
                    std::uint64_t resource = 0;
                    std::memcpy(&resource, ptrs.data(), sizeof(resource));
                    if (resource != 0)
                    {
                        std::vector<std::uint8_t> obj_bytes;
                        if (read_bytes(pid, resource, 0x300, obj_bytes))
                        {
                            for (std::size_t off = 0; off + 8 <= obj_bytes.size(); off += 8)
                            {
                                std::uint64_t ptr = 0;
                                std::memcpy(&ptr, obj_bytes.data() + off, sizeof(ptr));
                                driver_bridge::memory_region_t region{};
                                if (query_region(pid, ptr, region) && is_readable(region) && !is_executable(region))
                                {
                                    bs.last_cbuffer_va.store(ptr, std::memory_order_release);
                                    bs.last_cbuffer_slot.store(static_cast<int>(ctx.rdx), std::memory_order_release);
                                    bs.last_cbuffer_timestamp_ms.store(unix_time_ms(), std::memory_order_release);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else if (api.find("d3d12") != std::string::npos)
            {
                auto& bs = per_frame_bind_state();
                bs.last_cbuffer_va.store(ctx.r8, std::memory_order_release);
                bs.last_cbuffer_slot.store(static_cast<int>(ctx.rdx), std::memory_order_release);
                bs.last_cbuffer_timestamp_ms.store(unix_time_ms(), std::memory_order_release);
            }
        }
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

using ::re::dx_hook::clear_dx_record_breakpoints;

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
        if ((poll_count++ % 40) == 0)
        {
            for (const auto& th : threads_for(pid))
                arm_dx_records_for_thread(pid, th.tid);
        }
        poll_dx_thread_contexts(pid);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
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
        if (mcp_standalone::current_call_cancelled())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    const DWORD gle = state.error.load(std::memory_order_acquire);
    error = "DirectX kernel context consumer failed or timed out, error=" + std::to_string(static_cast<unsigned long>(gle));
    return false;
}

struct staging_watch_t
{
    std::uint64_t staging_va = 0;
    std::uint64_t staging_size = 0;
    std::uint32_t pid = 0;
    int hw_slot = 0;
    std::vector<std::uint32_t> tids;
    std::vector<std::uint8_t> cleartext_snapshot;
    std::uint64_t frame_index = 0;
    std::uint32_t max_frames = 3;
    std::string trace_id;
    bool captured_write = false;
    std::uint64_t pointer_location_va = 0;
    bool track_reallocation = false;
};

struct staging_watch_state_t
{
    std::atomic<bool> active{false};
    std::atomic<bool> polling{false};
    std::atomic<std::uint32_t> pid{0};
    std::mutex watch_mutex;
    std::vector<staging_watch_t> watches;
};

staging_watch_state_t& staging_watch_state()
{
    static staging_watch_state_t state;
    return state;
}

std::vector<std::uint64_t> capture_callstack(std::uint32_t pid, std::uint64_t rsp, std::size_t max_depth)
{
    std::vector<std::uint64_t> arr;
    std::uint64_t cursor = rsp;
    for (std::size_t i = 0; i < max_depth; ++i)
    {
        std::uint64_t ret_addr = 0;
        if (!read_u64(pid, cursor, ret_addr) || ret_addr == 0)
            break;
        driver_bridge::memory_region_t region{};
        if (query_region(pid, ret_addr, region) && is_executable(region))
            arr.push_back(ret_addr);
        cursor += 8;
    }
    return arr;
}

std::uint64_t detect_encrypted_source_va(const driver_bridge::thread_context_t& ctx,
                                          std::uint32_t pid, std::uint64_t staging_va)
{
    auto try_register = [&](std::uint64_t reg_value) -> std::uint64_t {
        if (reg_value == 0 || reg_value == staging_va)
            return 0;
        driver_bridge::memory_region_t region{};
        if (query_region(pid, reg_value, region) && is_readable(region) && !is_executable(region))
            return reg_value;
        return 0;
    };
    std::uint64_t candidates[] = {ctx.rcx, ctx.rdx, ctx.r8, ctx.rsi, ctx.rdi, ctx.rbx, ctx.r9};
    for (std::uint64_t c : candidates)
    {
        std::uint64_t found = try_register(c);
        if (found)
            return found;
    }
    for (int i = 0; i < 8; ++i)
    {
        std::uint64_t stack_val = 0;
        if (read_u64(pid, ctx.rsp + static_cast<std::uint64_t>(0x28 + i * 8), stack_val) && stack_val != 0)
        {
            std::uint64_t found = try_register(stack_val);
            if (found)
                return found;
        }
    }
    return 0;
}

bool capture_staging_write_hit(std::uint32_t pid, std::uint32_t tid,
                                const driver_bridge::thread_context_t& ctx)
{
    auto& state = staging_watch_state();
    std::lock_guard<std::mutex> lock(state.watch_mutex);
    bool matched = false;
    for (auto& watch : state.watches)
    {
        if (watch.pid != pid || watch.captured_write)
            continue;
        const std::uint64_t slot_address = context_dr_address(ctx, watch.hw_slot);
        if (slot_address != watch.staging_va)
            continue;
        const bool dr6_hit = (ctx.dr6 & (1ull << static_cast<unsigned>(watch.hw_slot))) != 0;
        if (!dr6_hit)
            continue;

        watch.captured_write = true;
        matched = true;

        std::uint64_t encrypted_source_va = detect_encrypted_source_va(ctx, pid, watch.staging_va);
        const std::size_t read_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(watch.staging_size, 4096));
        std::vector<std::uint8_t> decrypted_bytes;
        if (read_size > 0)
            read_bytes(pid, watch.staging_va, read_size, decrypted_bytes);
        std::vector<std::uint8_t> encrypted_bytes;
        if (encrypted_source_va != 0)
            read_bytes(pid, encrypted_source_va, read_size, encrypted_bytes);

        decryption_analysis_t analysis;
        if (!encrypted_bytes.empty() && !decrypted_bytes.empty())
            analysis = derive_decryption_from_pair(encrypted_bytes, decrypted_bytes, read_size);
        else
            analysis.verification_detail = encrypted_bytes.empty() ? "encrypted_source_unreadable" : "decrypted_staging_unreadable";

        if (analysis.verified && !encrypted_bytes.empty() && !decrypted_bytes.empty())
        {
            const bool re_verified = verify_decryption(encrypted_bytes, decrypted_bytes, analysis, read_size);
            if (!re_verified)
            {
                analysis.verified = false;
                analysis.verification_detail = "re_decryption_mismatch_after_initial_match";
            }
        }

        store::decryption_trace_record_t record;
        record.id = watch.trace_id;
        record.pid = pid;
        record.staging_va = watch.staging_va;
        record.staging_size = watch.staging_size;
        record.decryption_func_va = ctx.rip;
        record.encrypted_source_va = encrypted_source_va;
        record.encrypted_source_size = encrypted_bytes.size();
        record.algorithm_name = analysis.algorithm_name;
        record.derived_key_bytes = analysis.derived_key_bytes;
        record.key_length = analysis.key_length;
        record.key_pattern = analysis.key_pattern;
        record.verified = analysis.verified;
        record.verification_detail = analysis.verification_detail;
        record.caller_rip = ctx.rip;
        record.callstack = capture_callstack(pid, ctx.rsp, 16);
        record.register_snapshot = register_snapshot(ctx);
        record.cleartext_sample.assign(decrypted_bytes.begin(),
            decrypted_bytes.begin() + std::min<std::size_t>(decrypted_bytes.size(), 256));
        record.encrypted_sample.assign(encrypted_bytes.begin(),
            encrypted_bytes.begin() + std::min<std::size_t>(encrypted_bytes.size(), 256));
        record.created_ms = unix_time_ms();
        record.frame_index = watch.frame_index;
        record.hw_slot = watch.hw_slot;
        record.status = analysis.verified ? "verified" : "captured_unverified";
        store::add_decryption_trace(record);

        diag::log_tagged_fmt("dx_hook",
            "staging_write_captured pid=%u tid=%u staging_va=%s rip=%s encrypted_source=%s algorithm=%s verified=%d key_len=%u elapsed_ms=%llu",
            pid, tid,
            sa_format_address(watch.staging_va).c_str(),
            sa_format_address(ctx.rip).c_str(),
            sa_format_address(encrypted_source_va).c_str(),
            analysis.algorithm_name.c_str(),
            analysis.verified ? 1 : 0,
            analysis.key_length,
            static_cast<unsigned long long>(GetTickCount64()));

        if (watch.frame_index + 1 < watch.max_frames)
        {
            watch.captured_write = false;
            watch.frame_index++;
            watch.trace_id = store::next_id("dec");
            for (auto t : watch.tids)
                driver_bridge::set_hardware_breakpoint(t, watch.hw_slot, watch.staging_va, 1, 3);
        }
    }
    if (matched)
    {
        driver_bridge::thread_context_t next = ctx;
        next.rflags |= 0x10000ull;
        next.dr6 = 0;
        driver_bridge::set_thread_context(tid, next, (1ull << 17) | (1ull << 22));
    }
    return matched;
}

void staging_watch_loop()
{
    auto& state = staging_watch_state();
    const std::uint32_t pid = state.pid.load(std::memory_order_acquire);
    if (pid == 0 || !driver_bridge::using_kernel_driver())
    {
        state.active.store(false, std::memory_order_release);
        state.polling.store(false, std::memory_order_release);
        return;
    }
    for (const auto& th : threads_for(pid))
    {
        std::lock_guard<std::mutex> lock(state.watch_mutex);
        for (auto& watch : state.watches)
        {
            if (watch.captured_write)
                continue;
            if (std::find(watch.tids.begin(), watch.tids.end(), th.tid) == watch.tids.end())
            {
                if (driver_bridge::set_hardware_breakpoint(th.tid, watch.hw_slot,
                                                            watch.staging_va, 1, 3))
                    watch.tids.push_back(th.tid);
            }
        }
    }
    std::uint64_t poll_count = 0;
    while (state.polling.load(std::memory_order_acquire))
    {
        if (!driver_bridge::using_kernel_driver())
            break;
        if ((poll_count++ % 20) == 0)
        {
            for (const auto& th : threads_for(pid))
            {
                std::lock_guard<std::mutex> lock(state.watch_mutex);
                for (auto& watch : state.watches)
                {
                    if (watch.captured_write)
                        continue;
                    if (std::find(watch.tids.begin(), watch.tids.end(), th.tid) == watch.tids.end())
                    {
                        if (driver_bridge::set_hardware_breakpoint(th.tid, watch.hw_slot,
                                                                    watch.staging_va, 1, 3))
                            watch.tids.push_back(th.tid);
                    }
                }
            }
        }
        if ((poll_count % 30) == 0)
        {
            std::lock_guard<std::mutex> lock(state.watch_mutex);
            for (auto& watch : state.watches)
            {
                if (watch.captured_write)
                    continue;
                if (watch.track_reallocation && watch.pointer_location_va != 0)
                {
                    std::uint64_t current_staging = 0;
                    if (read_u64(pid, watch.pointer_location_va, current_staging) &&
                        current_staging != 0 && current_staging != watch.staging_va)
                    {
                        for (auto t : watch.tids)
                            driver_bridge::clear_hardware_breakpoint(t, watch.hw_slot);
                        watch.staging_va = current_staging;
                        watch.tids.clear();
                        watch.captured_write = false;
                    }
                }
            }
        }
        for (const auto tid : [&]() -> std::vector<std::uint32_t> {
            std::lock_guard<std::mutex> lock(state.watch_mutex);
            std::vector<std::uint32_t> tids;
            for (const auto& w : state.watches)
                for (auto t : w.tids)
                    if (std::find(tids.begin(), tids.end(), t) == tids.end())
                        tids.push_back(t);
            return tids;
        }())
        {
            driver_bridge::thread_context_t ctx{};
            if (!driver_bridge::get_thread_context(tid, ctx))
                continue;
            capture_staging_write_hit(pid, tid, ctx);
        }
        {
            std::lock_guard<std::mutex> lock(state.watch_mutex);
            bool all_captured = !state.watches.empty();
            for (const auto& w : state.watches)
                if (!w.captured_write)
                    all_captured = false;
            if (all_captured)
                break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    {
        std::lock_guard<std::mutex> lock(state.watch_mutex);
        for (const auto& watch : state.watches)
            for (auto tid : watch.tids)
                driver_bridge::clear_hardware_breakpoint(tid, watch.hw_slot);
    }
    state.active.store(false, std::memory_order_release);
    state.polling.store(false, std::memory_order_release);
    state.pid.store(0, std::memory_order_release);
}

bool start_staging_watch(std::uint32_t pid, std::uint64_t staging_va,
                          std::uint64_t staging_size, int hw_slot,
                          std::uint32_t max_frames,
                          std::uint64_t pointer_location_va,
                          std::string& error)
{
    auto& state = staging_watch_state();
    if (state.active.load(std::memory_order_acquire))
    {
        error = "staging watch already active";
        return false;
    }
    if (!driver_bridge::using_kernel_driver())
    {
        error = "kernel driver required for write hardware breakpoints";
        return false;
    }
    store::decryption_trace_record_t trace;
    trace.id = store::next_id("dec");
    trace.pid = pid;
    trace.staging_va = staging_va;
    trace.staging_size = staging_size;
    trace.hw_slot = hw_slot;
    trace.created_ms = unix_time_ms();
    trace.status = "armed_waiting_for_write";
    store::add_decryption_trace(trace);

    staging_watch_t watch;
    watch.staging_va = staging_va;
    watch.staging_size = staging_size;
    watch.pid = pid;
    watch.hw_slot = hw_slot;
    watch.trace_id = trace.id;
    watch.frame_index = 0;
    watch.max_frames = max_frames;
    watch.pointer_location_va = pointer_location_va;
    watch.track_reallocation = pointer_location_va != 0;

    std::vector<std::uint8_t> cleartext;
    if (staging_size > 0)
        read_bytes(pid, staging_va, static_cast<std::size_t>(std::min<std::uint64_t>(staging_size, 4096)), cleartext);
    watch.cleartext_snapshot = std::move(cleartext);

    {
        std::lock_guard<std::mutex> lock(state.watch_mutex);
        state.watches.clear();
        state.watches.push_back(std::move(watch));
    }
    state.pid.store(pid, std::memory_order_release);
    state.polling.store(true, std::memory_order_release);
    state.active.store(true, std::memory_order_release);
    if (!work_queue::post_service([]() { staging_watch_loop(); }))
    {
        state.polling.store(false, std::memory_order_release);
        state.active.store(false, std::memory_order_release);
        error = "failed to schedule staging watch loop";
        return false;
    }
    for (int i = 0; i < 80; ++i)
    {
        if (state.active.load(std::memory_order_acquire) &&
            state.pid.load(std::memory_order_acquire) == pid)
            break;
        if (mcp_standalone::current_call_cancelled())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return true;
}

void stop_staging_watch(std::uint32_t pid)
{
    auto& state = staging_watch_state();
    if (state.pid.load(std::memory_order_acquire) != pid)
        return;
    state.polling.store(false, std::memory_order_release);
    for (int i = 0; i < 80 && state.active.load(std::memory_order_acquire); ++i)
    {
        if (mcp_standalone::current_call_cancelled())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
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

struct vec3_t
{
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
};

struct vec4_t
{
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    float w = 0.0f;
};

struct screen_point_t
{
    float x = 0.0f;
    float y = 0.0f;
    bool behind_camera = false;
    bool valid = false;
};

struct w2s_result_t
{
    screen_point_t screen;
    vec4_t clip;
    vec3_t view_space;
};

struct mat4x4_t
{
    float m[16] = {};

    void load_from_floats(const float* f)
    {
        std::memcpy(m, f, sizeof(m));
    }

    bool read_from_process(std::uint32_t pid, std::uint64_t va)
    {
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(pid, va, 64, bytes) || bytes.size() < 64)
            return false;
        std::memcpy(m, bytes.data(), sizeof(m));
        return true;
    }
};

bool orientation_is_row_major(const std::string& orientation)
{
    return orientation == "row_major" ||
           orientation == "row_vector_viewproj_or_projection_product";
}

bool orientation_is_column_major(const std::string& orientation)
{
    return orientation == "column_major" ||
           orientation == "column_vector_viewproj_or_projection_product";
}

vec4_t transform_point(const vec3_t& world, const mat4x4_t& mat, bool row_major)
{
    vec4_t clip;
    if (row_major)
    {
        clip.x = world.x * mat.m[0]  + world.y * mat.m[4]  + world.z * mat.m[8]  + mat.m[12];
        clip.y = world.x * mat.m[1]  + world.y * mat.m[5]  + world.z * mat.m[9]  + mat.m[13];
        clip.z = world.x * mat.m[2]  + world.y * mat.m[6]  + world.z * mat.m[10] + mat.m[14];
        clip.w = world.x * mat.m[3]  + world.y * mat.m[7]  + world.z * mat.m[11] + mat.m[15];
    }
    else
    {
        clip.x = mat.m[0] * world.x + mat.m[4] * world.y + mat.m[8]  * world.z + mat.m[12];
        clip.y = mat.m[1] * world.x + mat.m[5] * world.y + mat.m[9]  * world.z + mat.m[13];
        clip.z = mat.m[2] * world.x + mat.m[6] * world.y + mat.m[10] * world.z + mat.m[14];
        clip.w = mat.m[3] * world.x + mat.m[7] * world.y + mat.m[11] * world.z + mat.m[15];
    }
    return clip;
}

w2s_result_t world_to_screen_viewproj(const vec3_t& world_pos,
                                       const mat4x4_t& viewproj,
                                       bool row_major,
                                       std::uint32_t screen_w,
                                       std::uint32_t screen_h)
{
    w2s_result_t result;
    result.clip = transform_point(world_pos, viewproj, row_major);

    if (result.clip.w <= 0.0001f)
    {
        result.screen.behind_camera = true;
        result.screen.valid = false;
        return result;
    }

    const float inv_w = 1.0f / result.clip.w;
    const float ndc_x = result.clip.x * inv_w;
    const float ndc_y = result.clip.y * inv_w;
    const float ndc_z = result.clip.z * inv_w;

    result.view_space.x = ndc_x;
    result.view_space.y = ndc_y;
    result.view_space.z = ndc_z;

    result.screen.x = (ndc_x + 1.0f) * 0.5f * static_cast<float>(screen_w);
    result.screen.y = (1.0f - ndc_y) * 0.5f * static_cast<float>(screen_h);
    result.screen.behind_camera = false;
    result.screen.valid = (ndc_x >= -1.5f && ndc_x <= 1.5f &&
                            ndc_y >= -1.5f && ndc_y <= 1.5f &&
                            ndc_z >= -1.0f && ndc_z <= 1.0f);
    return result;
}

w2s_result_t world_to_screen(const vec3_t& world_pos,
                              const mat4x4_t& view,
                              const mat4x4_t& proj,
                              bool row_major,
                              std::uint32_t screen_w,
                              std::uint32_t screen_h)
{
    vec4_t view_space = transform_point(world_pos, view, row_major);

    if (view_space.w <= 0.0001f && view_space.w > -0.0001f)
        view_space.w = 0.0001f;

    vec3_t view_pos;
    view_pos.x = view_space.x;
    view_pos.y = view_space.y;
    view_pos.z = view_space.z;

    vec4_t clip = transform_point(view_pos, proj, row_major);

    w2s_result_t result;
    result.view_space = view_pos;
    result.clip = clip;

    if (clip.w <= 0.0001f)
    {
        result.screen.behind_camera = true;
        result.screen.valid = false;
        return result;
    }

    const float inv_w = 1.0f / clip.w;
    const float ndc_x = clip.x * inv_w;
    const float ndc_y = clip.y * inv_w;
    const float ndc_z = clip.z * inv_w;

    result.screen.x = (ndc_x + 1.0f) * 0.5f * static_cast<float>(screen_w);
    result.screen.y = (1.0f - ndc_y) * 0.5f * static_cast<float>(screen_h);
    result.screen.behind_camera = false;
    result.screen.valid = (ndc_x >= -1.5f && ndc_x <= 1.5f &&
                            ndc_y >= -1.5f && ndc_y <= 1.5f &&
                            ndc_z >= -1.0f && ndc_z <= 1.0f);
    return result;
}

mat4x4_t compose_viewproj(const mat4x4_t& view, const mat4x4_t& proj, bool row_major)
{
    mat4x4_t result;
    if (row_major)
    {
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                result.m[i * 4 + j] =
                    view.m[i * 4 + 0] * proj.m[0 * 4 + j] +
                    view.m[i * 4 + 1] * proj.m[1 * 4 + j] +
                    view.m[i * 4 + 2] * proj.m[2 * 4 + j] +
                    view.m[i * 4 + 3] * proj.m[3 * 4 + j];
            }
        }
    }
    else
    {
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                result.m[i * 4 + j] =
                    proj.m[i * 4 + 0] * view.m[0 * 4 + j] +
                    proj.m[i * 4 + 1] * view.m[1 * 4 + j] +
                    proj.m[i * 4 + 2] * view.m[2 * 4 + j] +
                    proj.m[i * 4 + 3] * view.m[3 * 4 + j];
            }
        }
    }
    return result;
}

vec3_t extract_translation(const mat4x4_t& mat, bool row_major)
{
    vec3_t t;
    if (row_major)
    {
        t.x = mat.m[12];
        t.y = mat.m[13];
        t.z = mat.m[14];
    }
    else
    {
        t.x = mat.m[3];
        t.y = mat.m[7];
        t.z = mat.m[11];
    }
    return t;
}

vec3_t extract_bone_position(const mat4x4_t& bone_matrix, bool row_major)
{
    return extract_translation(bone_matrix, row_major);
}

struct matrix_read_t
{
    bool ok = false;
    mat4x4_t matrix;
    matrix_eval_t eval;
    std::string orientation;
    std::uint64_t va = 0;
};

matrix_read_t read_and_evaluate_matrix(std::uint32_t pid, std::uint64_t va, double world_max)
{
    matrix_read_t result;
    result.va = va;
    if (va == 0)
        return result;
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, va, 64, bytes) || bytes.size() < 64)
        return result;
    float f[16] = {};
    std::memcpy(f, bytes.data(), 64);
    result.matrix.load_from_floats(f);
    result.eval = evaluate_matrix4x4(f, world_max);
    result.orientation = result.eval.orientation;
    result.ok = result.eval.plausible;
    return result;
}

struct screen_dimensions_t
{
    bool ok = false;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::string source;
    HWND hwnd = nullptr;
};

screen_dimensions_t discover_screen_dimensions(std::uint32_t pid,
                                                std::uint32_t override_w,
                                                std::uint32_t override_h)
{
    screen_dimensions_t dims;

    if (override_w > 0 && override_h > 0 &&
        override_w <= 16384 && override_h <= 16384)
    {
        dims.ok = true;
        dims.width = override_w;
        dims.height = override_h;
        dims.source = "parameter";
        return dims;
    }

    auto window = find_target_window(pid);
    if (window)
    {
        RECT client_rect{};
        if (GetClientRect(window->hwnd, &client_rect) &&
            client_rect.right > client_rect.left &&
            client_rect.bottom > client_rect.top)
        {
            dims.ok = true;
            dims.width = static_cast<std::uint32_t>(client_rect.right - client_rect.left);
            dims.height = static_cast<std::uint32_t>(client_rect.bottom - client_rect.top);
            dims.source = "GetClientRect";
            dims.hwnd = window->hwnd;
            return dims;
        }
        dims.ok = true;
        dims.width = static_cast<std::uint32_t>(window->rect.right - window->rect.left);
        dims.height = static_cast<std::uint32_t>(window->rect.bottom - window->rect.top);
        dims.source = "GetWindowRect";
        dims.hwnd = window->hwnd;
        return dims;
    }

    dims.ok = false;
    dims.source = "not_found";
    return dims;
}

struct remote_com_call_t
{
    std::uint32_t pid = 0;
    std::uint64_t deadline_ms = 0;
    std::string error;
    std::size_t call_count = 0;

    std::uint64_t read_vtable_method(std::uint64_t object_va, std::uint32_t slot)
    {
        if (object_va == 0)
        {
            error = "null object_va for vtable read";
            return 0;
        }
        std::uint64_t vtable_va = 0;
        if (!re::read_u64(pid, object_va, vtable_va) || vtable_va == 0)
        {
            error = "failed to read vtable pointer at " + sa_format_address(object_va);
            return 0;
        }
        std::uint64_t method_va = 0;
        const std::uint64_t slot_va = vtable_va + static_cast<std::uint64_t>(slot) * 8ull;
        if (!re::read_u64(pid, slot_va, method_va) || method_va == 0)
        {
            error = "failed to read vtable slot " + std::to_string(slot) + " at " + sa_format_address(slot_va);
            return 0;
        }
        return method_va;
    }

    std::uint64_t call_com_method(std::uint64_t method_va, std::uint64_t this_va,
                                  std::uint64_t arg2 = 0, std::uint64_t arg3 = 0, std::uint64_t arg4 = 0)
    {
        if (method_va == 0)
        {
            error = "null method_va for COM call";
            return 0;
        }
        if (!driver_bridge::attached_process_alive())
        {
            error = "target process not alive before COM call";
            return 0;
        }
        const std::uint64_t call_started = GetTickCount64();
        ++call_count;
        diag::log_tagged_fmt("dx_hook",
            "read_gpu_buffer com_call call=%zu method=0x%llX this=0x%llX arg2=0x%llX arg3=0x%llX arg4=0x%llX pid=%u",
            call_count,
            static_cast<unsigned long long>(method_va),
            static_cast<unsigned long long>(this_va),
            static_cast<unsigned long long>(arg2),
            static_cast<unsigned long long>(arg3),
            static_cast<unsigned long long>(arg4),
            pid);
        const std::uint64_t ret = driver_bridge::call_function(method_va, this_va, arg2, arg3, arg4);
        const std::uint64_t elapsed = GetTickCount64() - call_started;
        if (!driver_bridge::attached_process_alive())
        {
            error = "target process died during COM call (method=" + sa_format_address(method_va) + ")";
            diag::log_tagged_fmt("dx_hook",
                "read_gpu_buffer com_call_dead call=%zu method=0x%llX elapsed_ms=%llu pid=%u",
                call_count,
                static_cast<unsigned long long>(method_va),
                static_cast<unsigned long long>(elapsed),
                pid);
            return ret;
        }
        diag::log_tagged_fmt("dx_hook",
            "read_gpu_buffer com_call_done call=%zu method=0x%llX ret=0x%llX elapsed_ms=%llu pid=%u",
            call_count,
            static_cast<unsigned long long>(method_va),
            static_cast<unsigned long long>(ret),
            static_cast<unsigned long long>(elapsed),
            pid);
        return ret;
    }

    std::uint64_t call_com_method_6(std::uint64_t method_va, std::uint64_t this_va,
                                    std::uint64_t arg1, std::uint64_t arg2,
                                    std::uint64_t arg3, std::uint64_t arg4,
                                    std::uint64_t arg5)
    {
        if (method_va == 0)
        {
            error = "null method_va for COM call_6";
            return 0;
        }
        if (!driver_bridge::attached_process_alive())
        {
            error = "target process not alive before COM call_6";
            return 0;
        }
        std::vector<std::uint8_t> shellcode;
        shellcode.reserve(64);
        auto emit = [&](const void* p, std::size_t n) {
            const auto* b = static_cast<const std::uint8_t*>(p);
            shellcode.insert(shellcode.end(), b, b + n);
        };
        auto emit_byte = [&](std::uint8_t b) { shellcode.push_back(b); };
        auto emit_u64 = [&](std::uint64_t v) {
            for (int i = 0; i < 8; ++i)
                emit_byte(static_cast<std::uint8_t>(v >> (i * 8)));
        };
        const std::uint8_t sub_rsp_38[]   = { 0x48, 0x83, 0xEC, 0x38 };
        const std::uint8_t mov_rax_imm[]  = { 0x48, 0xB8 };
        const std::uint8_t mov_rsp20_rax[]= { 0x48, 0x89, 0x44, 0x24, 0x20 };
        const std::uint8_t mov_rsp28_rax[]= { 0x48, 0x89, 0x44, 0x24, 0x28 };
        const std::uint8_t call_rax[]     = { 0xFF, 0xD0 };
        const std::uint8_t add_rsp_38[]   = { 0x48, 0x83, 0xC4, 0x38 };
        const std::uint8_t ret_insn[]     = { 0xC3 };
        emit(sub_rsp_38, sizeof(sub_rsp_38));
        emit(mov_rax_imm, sizeof(mov_rax_imm)); emit_u64(arg4);
        emit(mov_rsp20_rax, sizeof(mov_rsp20_rax));
        emit(mov_rax_imm, sizeof(mov_rax_imm)); emit_u64(arg5);
        emit(mov_rsp28_rax, sizeof(mov_rsp28_rax));
        emit(mov_rax_imm, sizeof(mov_rax_imm)); emit_u64(method_va);
        emit(call_rax, sizeof(call_rax));
        emit(add_rsp_38, sizeof(add_rsp_38));
        emit(ret_insn, sizeof(ret_insn));
        const std::uint64_t stub_va = driver_bridge::allocate_memory_for(pid, 64);
        if (stub_va == 0)
        {
            error = "allocate_memory_for failed for call_6 trampoline";
            return 0;
        }
        if (!driver_bridge::write_memory_for(pid, stub_va, shellcode))
        {
            error = "write_memory_for failed for call_6 trampoline at " + sa_format_address(stub_va);
            driver_bridge::free_memory_for(pid, stub_va);
            return 0;
        }
        std::uint32_t old_protect = 0;
        driver_bridge::protect_memory_for(pid, stub_va, 64, 0x40, &old_protect);
        const std::uint64_t call_started = GetTickCount64();
        ++call_count;
        diag::log_tagged_fmt("dx_hook",
            "read_gpu_buffer com_call_6 call=%zu method=0x%llX this=0x%llX a1=0x%llX a2=0x%llX a3=0x%llX a4=0x%llX a5=0x%llX stub=0x%llX pid=%u",
            call_count,
            static_cast<unsigned long long>(method_va),
            static_cast<unsigned long long>(this_va),
            static_cast<unsigned long long>(arg1),
            static_cast<unsigned long long>(arg2),
            static_cast<unsigned long long>(arg3),
            static_cast<unsigned long long>(arg4),
            static_cast<unsigned long long>(arg5),
            static_cast<unsigned long long>(stub_va),
            pid);
        const std::uint64_t ret = driver_bridge::call_function(stub_va, this_va, arg1, arg2, arg3);
        const std::uint64_t elapsed = GetTickCount64() - call_started;
        driver_bridge::protect_memory_for(pid, stub_va, 64, 0x04, &old_protect);
        driver_bridge::free_memory_for(pid, stub_va);
        if (!driver_bridge::attached_process_alive())
        {
            error = "target process died during COM call_6 (method=" + sa_format_address(method_va) + ")";
            diag::log_tagged_fmt("dx_hook",
                "read_gpu_buffer com_call_6_dead call=%zu method=0x%llX elapsed_ms=%llu pid=%u",
                call_count,
                static_cast<unsigned long long>(method_va),
                static_cast<unsigned long long>(elapsed),
                pid);
            return ret;
        }
        diag::log_tagged_fmt("dx_hook",
            "read_gpu_buffer com_call_6_done call=%zu method=0x%llX ret=0x%llX elapsed_ms=%llu pid=%u",
            call_count,
            static_cast<unsigned long long>(method_va),
            static_cast<unsigned long long>(ret),
            static_cast<unsigned long long>(elapsed),
            pid);
        return ret;
    }

    std::uint64_t alloc(std::size_t size)
    {
        if (size == 0)
        {
            error = "alloc size is zero";
            return 0;
        }
        const std::uint64_t addr = driver_bridge::allocate_memory_for(pid, size);
        if (addr == 0)
            error = "allocate_memory_for failed for size " + std::to_string(size);
        return addr;
    }

    std::uint64_t alloc_and_write(const std::vector<std::uint8_t>& data)
    {
        const std::uint64_t addr = alloc(data.size());
        if (addr == 0)
            return 0;
        if (!driver_bridge::write_memory_for(pid, addr, data))
        {
            error = "write_memory_for failed at " + sa_format_address(addr);
            driver_bridge::free_memory_for(pid, addr);
            return 0;
        }
        return addr;
    }

    std::uint64_t read_u64_at(std::uint64_t address)
    {
        std::uint64_t value = 0;
        if (!re::read_u64(pid, address, value))
        {
            error = "read_u64 failed at " + sa_format_address(address);
            return 0;
        }
        return value;
    }

    bool read_bytes_at(std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out)
    {
        if (!re::read_bytes(pid, address, size, out) || out.size() != size)
        {
            error = "read_bytes failed at " + sa_format_address(address) + " size=" + std::to_string(size);
            return false;
        }
        return true;
    }

    bool target_alive() const
    {
        return driver_bridge::attached_process_alive();
    }

    bool deadline_exceeded() const
    {
        if (deadline_ms == 0)
            return false;
        return GetTickCount64() >= deadline_ms;
    }
};
}

frame_tracking_state_t& frame_tracking_state()
{
    static frame_tracking_state_t state;
    return state;
}

void clear_dx_record_breakpoints(std::uint32_t pid)
{
    for (const auto& record : store::list_dx_hooks(pid))
    {
        for (auto tid : record.tids)
            driver_bridge::clear_hardware_breakpoint(tid, record.hw_slot);
    }
}

void stop_dx_debug_loop(std::uint32_t pid)
{
    auto& state = dx_debug_state();
    if (state.pid.load(std::memory_order_acquire) != pid)
        return;
    state.polling.store(false, std::memory_order_release);
    frame_tracking_state().enabled.store(false, std::memory_order_release);
    for (int i = 0; i < 80 && state.running.load(std::memory_order_acquire); ++i)
    {
        if (mcp_standalone::current_call_cancelled())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
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
        bool auto_cancelled = false;
        auto push_cancelled_api = [&](const char* api_name) {
            json cancelled = slots_to_result(scope.pid(), api_name, {});
            cancelled["discovery_status"] = "cancelled";
            cancelled["cancelled"] = true;
            apis.push_back(std::move(cancelled));
        };
        auto push_auto_api = [&](const char* api_name, const char* module_name) {
            if (dx_call_cancelled("find_device_vtable_auto", scope.pid(), started_ms))
            {
                auto_cancelled = true;
                push_cancelled_api(api_name);
                return;
            }
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
            if (dx_call_cancelled("find_device_vtable_auto_after_api", scope.pid(), started_ms))
                auto_cancelled = true;
        };
        if (!dx_call_cancelled("find_device_vtable_auto_d3d11", scope.pid(), started_ms))
            push_auto_api("d3d11", "d3d11.dll");
        else
        {
            auto_cancelled = true;
            push_cancelled_api("d3d11");
        }
        if (!dx_call_cancelled("find_device_vtable_auto_d3d12", scope.pid(), started_ms))
            push_auto_api("d3d12", "d3d12.dll");
        else
        {
            auto_cancelled = true;
            push_cancelled_api("d3d12");
        }
        if (!dx_call_cancelled("find_device_vtable_auto_dxgi", scope.pid(), started_ms))
            push_auto_api("dxgi", "dxgi.dll");
        else
        {
            auto_cancelled = true;
            push_cancelled_api("dxgi");
        }
        if (!dx_call_cancelled("find_device_vtable_auto_vulkan", scope.pid(), started_ms))
            push_auto_api("vulkan", "vulkan-1.dll");
        else
        {
            auto_cancelled = true;
            push_cancelled_api("vulkan");
        }
        json result;
        result["process_id"] = scope.pid();
        result["api"] = "auto";
        result["apis"] = std::move(apis);
        result["cancelled"] = auto_cancelled;
        result["elapsed_ms"] = GetTickCount64() - started_ms;
        diag::log_tagged_fmt("dx_hook", "find_device_vtable exit pid=%u api=auto elapsed_ms=%llu",
                             scope.pid(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (auto_cancelled)
            return tool_result_t::error("DX vtable discovery cancelled.", result);
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
    json result = slots_to_result(scope.pid(), api, slots);
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    if (dx_call_cancelled("find_device_vtable_after_explicit", scope.pid(), started_ms))
    {
        result["cancelled"] = true;
        return tool_result_t::error("DX vtable discovery cancelled.", result);
    }
    return tool_result_t::ok(result);
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
        frame_tracking_state().enabled.store(false, std::memory_order_release);
        return tool_result_t::ok("DX hooks removed.", result);
    }

    if (action == "full_capture")
    {
        if (!unsafe_confirmed(p))
            return unsafe_required("dx_hook_manage full_capture");
        active_process_scope_t scope(p);
        if (!scope.ok())
            return tool_result_t::error(scope.error());
        const std::string api = api_param(p);
        if (!api_supported(api, true))
            return tool_result_t::error("Unsupported DX API value for full_capture.");

        if (!driver_bridge::using_kernel_driver())
        {
            json result;
            result["process_id"] = scope.pid();
            result["capability"] = {{"available", false}, {"reason", "kernel driver required for parallel multi-target HWBP"}};
            return tool_result_t::error("DX kernel-context hardware-breakpoint backend is unavailable.", result);
        }

        auto slots = discover_api(scope.pid(), api, true);
        std::optional<slot_entry_t> present_target, draw_target, cbuffer_target;
        for (const auto& s : slots)
        {
            if (s.target_va == 0 || !s.validated) continue;
            if (s.role == "present" && !present_target) present_target = s;
            if (s.role == "draw" && !draw_target)
            {
                if (s.name == "DrawIndexed" || s.name == "Draw" || s.name == "DrawInstanced" || s.name == "DrawIndexedInstanced")
                    draw_target = s;
            }
            if (s.role == "cbuffer_bind" && !cbuffer_target)
            {
                if (s.name == "VSSetConstantBuffers")
                    cbuffer_target = s;
            }
        }
        if (!draw_target)
        {
            for (const auto& s : slots)
            {
                if (s.target_va == 0 || !s.validated) continue;
                if (s.role == "draw" && !draw_target) draw_target = s;
            }
        }
        if (!cbuffer_target)
        {
            for (const auto& s : slots)
            {
                if (s.target_va == 0 || !s.validated) continue;
                if (s.role == "cbuffer_bind" && !cbuffer_target) cbuffer_target = s;
            }
        }
        if (!present_target)
        {
            auto present_slots = discover_dxgi_present(scope.pid(), true);
            if (!present_slots.empty())
                present_target = present_slots[0];
        }
        if (!present_target || !draw_target || !cbuffer_target)
        {
            json result;
            result["process_id"] = scope.pid();
            result["resolved_targets"] = {
                {"present", present_target ? json(sa_format_address(present_target->target_va)) : json(nullptr)},
                {"draw", draw_target ? json(sa_format_address(draw_target->target_va)) : json(nullptr)},
                {"cbuffer_bind", cbuffer_target ? json(sa_format_address(cbuffer_target->target_va)) : json(nullptr)}
            };
            result["failure_reason"] = "could_not_resolve_all_three_targets";
            return tool_result_t::error("Could not resolve Present, Draw, and CBufferBind targets simultaneously.", result);
        }

        auto make_record = [&](const slot_entry_t& target, const std::string& act, int hw_slot) {
            store::dx_hook_record_t rec;
            rec.id = store::next_id("dx");
            rec.pid = scope.pid();
            rec.api = api == "auto" ? target.module_name : api;
            rec.action = act;
            rec.target_va = target.target_va;
            rec.target_name = target.name;
            rec.hw_slot = hw_slot;
            rec.capture_cbuffers = (act == "cbuffer_bind");
            rec.capture_vertex_buffers = false;
            rec.max_captures = static_cast<std::uint32_t>(numeric_param(p, "max_captures", 32, 1, 1024));
            rec.created_ms = unix_time_ms();
            for (const auto& th : threads_for(scope.pid()))
                if (driver_bridge::set_hardware_breakpoint(th.tid, hw_slot, target.target_va, 0, 0))
                    rec.tids.push_back(th.tid);
            return rec;
        };

        auto present_rec = make_record(*present_target, "present", 0);
        auto draw_rec = make_record(*draw_target, "draw", 1);
        auto cbuffer_rec = make_record(*cbuffer_target, "cbuffer_bind", 2);

        if (present_rec.tids.empty() || draw_rec.tids.empty() || cbuffer_rec.tids.empty())
        {
            clear_dx_record_breakpoints({present_rec, draw_rec, cbuffer_rec});
            json result;
            result["process_id"] = scope.pid();
            result["capability"] = {{"available", false}, {"reason", "could not arm all 3 HWBPs on any thread"}};
            return tool_result_t::error("Parallel multi-target HWBP arming failed.", result);
        }

        std::vector<store::dx_hook_record_t> prepared_records = {present_rec, draw_rec, cbuffer_rec};
        for (const auto& prepared : prepared_records)
            store::add_dx_hook(prepared);

        frame_tracking_state().enabled.store(true, std::memory_order_release);
        frame_tracking_state().frame_start_ms.store(unix_time_ms(), std::memory_order_release);
        frame_tracking_state().current_frame.store(0, std::memory_order_release);
        frame_tracking_state().current_draw_ordinal.store(0, std::memory_order_release);

        std::string debug_error;
        bool debug_started = start_dx_debug_loop(scope.pid(), debug_error);
        if (!debug_started)
        {
            for (const auto& r : prepared_records) clear_dx_record_breakpoints(r);
            for (const auto& r : prepared_records) store::remove_dx_hook(r.id);
            json result;
            result["process_id"] = scope.pid();
            result["failure_reason"] = debug_error;
            return tool_result_t::error("DX debug loop failed to start for full_capture.", result);
        }

        json result;
        result["process_id"] = scope.pid();
        result["action"] = "full_capture";
        result["capture_backend"] = "hardware_breakpoint_kernel_context";
        result["parallel_hwbp_slots"] = {{"dr0_present", 0}, {"dr1_draw", 1}, {"dr2_cbuffer_bind", 2}};
        result["present_hook"] = dx_record_json(present_rec);
        result["draw_hook"] = dx_record_json(draw_rec);
        result["cbuffer_hook"] = dx_record_json(cbuffer_rec);
        result["frame_tracking_enabled"] = true;
        result["armed_threads"] = present_rec.tids.size();
        result["capture_cbuffers"] = true;
        result["kernel_context_consumer"] = true;
        return tool_result_t::ok("Parallel multi-target HWBP armed: Present + Draw + CBufferBind.", result);
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
    record.target_name = target->name;
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

    bool has_present_hook = false;
    for (const auto& prepared : prepared_records)
    {
        if (prepared.action == "present")
        {
            has_present_hook = true;
            break;
        }
    }
    if (has_present_hook && debug_started)
    {
        frame_tracking_state().enabled.store(true, std::memory_order_release);
        frame_tracking_state().frame_start_ms.store(unix_time_ms(), std::memory_order_release);
        frame_tracking_state().current_frame.store(0, std::memory_order_release);
        frame_tracking_state().current_draw_ordinal.store(0, std::memory_order_release);
    }

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

    auto classifications = classify_cbuffers(scope.pid());
    json class_json = json::array();
    for (const auto& cc : classifications)
        class_json.push_back(cbuffer_classification_to_json(cc));
    result["cbuffer_classifications"] = std::move(class_json);

    for (auto& row : result["cbuffers"])
    {
        std::uint64_t row_va = 0;
        if (row.contains("va") && parse_u64_value(row["va"], row_va) && row_va != 0)
        {
            for (const auto& cc : classifications)
            {
                if (cc.va == row_va)
                {
                    row["classification"] = classification_to_string(cc.classification);
                    row["recommended_for"] = cc.recommended_for;
                    row["frequency_score"] = cc.frequency_score;
                    row["frames_seen"] = cc.frames_seen;
                    break;
                }
            }
        }
    }

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
        if (size < 28ull * min_bones)
            return;
        std::vector<std::uint8_t> bytes;
        const std::size_t read_size = static_cast<std::size_t>(std::min<std::uint64_t>(size, std::max<std::uint64_t>(64ull * max_bones + 256ull, 8192ull)));
        if (!read_bytes(scope.pid(), va, read_size, bytes) || bytes.size() < 28ull * min_bones)
            return;
        multi_decode_result_t decoded = best_multi_decode_run(bytes, world_max, max_bones, 512);
        if (decoded.count < min_bones)
        {
            matrix_decode_result_t interleaved = best_interleaved_decode_run(bytes, world_max, max_bones, 512);
            if (interleaved.count > decoded.count)
            {
                decoded.algorithm = interleaved.xor_key == 0 ? decode_algorithm_t::raw_float32 : decode_algorithm_t::xor_uniform;
                decoded.algorithm_name = interleaved.decode;
                decoded.count = interleaved.count;
                decoded.stride = interleaved.stride;
                decoded.offset = interleaved.offset;
                decoded.uniform_key = interleaved.xor_key;
                decoded.first_eval = interleaved.first_eval;
                decoded.format = interleaved.format;
                decoded.entry_stride = interleaved.entry_stride;
            }
        }
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
        row["format"] = bone_format_name(decoded.format);
        row["format_stride"] = decoded.stride;
        if (decoded.entry_stride > decoded.stride)
        {
            row["entry_stride"] = decoded.entry_stride;
            row["interleaved"] = true;
            row["interleaved_gap"] = decoded.entry_stride - decoded.stride;
        }
        else
        {
            row["entry_stride"] = decoded.stride;
            row["interleaved"] = false;
            row["interleaved_gap"] = 0;
        }
        row["decode"] = decoded.algorithm_name;
        row["algorithm"] = decoded.algorithm_name;
        row["xor_key"] = decoded.uniform_key == 0 ? json(nullptr) : json(sa_format_address(decoded.uniform_key));
        if (decoded.algorithm == decode_algorithm_t::xor_rolling)
        {
            row["rolling_seed"] = sa_format_address(decoded.rolling_seed);
            row["rolling_multiplier"] = sa_format_address(decoded.rolling_multiplier);
            row["rolling_increment"] = sa_format_address(decoded.rolling_increment);
        }
        if (decoded.algorithm == decode_algorithm_t::additive_word ||
            decoded.algorithm == decode_algorithm_t::additive_byte)
        {
            row["additive_key"] = sa_format_address(decoded.additive_key);
        }
        if (!decoded.key_words.empty() && decoded.algorithm == decode_algorithm_t::xor_multi_key)
        {
            json kw = json::array();
            for (auto k : decoded.key_words)
                kw.push_back(sa_format_address(k));
            row["multi_key_words"] = std::move(kw);
        }
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
        if (decoded.algorithm == decode_algorithm_t::xor_uniform)
            confidence += 0.06;
        if (decoded.algorithm == decode_algorithm_t::xor_rolling ||
            decoded.algorithm == decode_algorithm_t::xor_multi_key ||
            decoded.algorithm == decode_algorithm_t::additive_word ||
            decoded.algorithm == decode_algorithm_t::additive_byte)
            confidence += 0.08;
        if (decoded.offset != 0)
            confidence -= 0.03;
        if (decoded.format != bone_format_t::matrix4x4_64 &&
            decoded.format != bone_format_t::matrix3x4_48 &&
            decoded.format != bone_format_t::unknown)
            confidence += 0.04;
        if (decoded.entry_stride > decoded.stride)
            confidence -= 0.02;

        auto hot_vas = store::list_hot_vas(scope.pid());
        auto hot_it = std::find_if(hot_vas.begin(), hot_vas.end(), [&](const store::hot_va_entry_t& e) {
            return e.va == va + decoded.offset;
        });
        if (hot_it != hot_vas.end())
        {
            confidence += hot_it->confidence_boost;
            row["hot_va_boost"] = hot_it->confidence_boost;
            row["hot_va_hit_count"] = hot_it->hit_count;
        }
        confidence = std::min(0.99, std::max(0.0, confidence));
        row["confidence"] = confidence;
        row["source"] = source_name;
        row["evidence"] = source;
        row["toolchain_hint"] = "Use this VA as bone_buffer_va for bone projection or cross-correlation with view matrix";
        row["next_action"] = "dx_project_bones";
        row["next_action_params"] = json::object({
            {"process_id", scope.pid()},
            {"bone_buffer_va", sa_format_address(va + decoded.offset)}
        });
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
        {"matrix_strides", {64, 48, 60, 52, 40, 32, 28}},
        {"formats", {"matrix4x4_64", "matrix3x4_48", "matrix3x4_64_padded",
                      "srt_mat3x3_60", "srt_quat_52_padded", "srt_quat_40",
                      "dual_quat_32", "quat_pos_28"}},
        {"interleaved_scan", true},
        {"decoders", {"raw_float32", "xor_uniform", "xor_rolling", "xor_multi_key", "additive_byte", "additive_word32"}},
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
    const std::uint64_t started_ms = GetTickCount64();
    auto deadline_remaining = []() -> std::uint64_t {
        const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
        if (deadline == 0)
            return 0;
        const std::uint64_t now = GetTickCount64();
        return deadline > now ? deadline - now : 0;
    };
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
    diag::log_tagged_fmt("dx_hook",
                         "map_resource_to_va enter pid=%u handle=%s max_candidates=%zu deadline_remaining_ms=%llu diag_id=%s",
                         scope.pid(),
                         sa_format_address(handle).c_str(),
                         max_candidates,
                         static_cast<unsigned long long>(deadline_remaining()),
                         mcp_standalone::current_call_diag_id());
    std::size_t query_count = 0;
    std::size_t query_failures = 0;
    std::size_t read_count = 0;
    std::size_t read_failures = 0;
    std::size_t preview_reads = 0;
    std::size_t pointer_slots = 0;
    std::size_t nested_slots = 0;
    std::size_t gpu_candidates = 0;
    std::size_t pointer_candidates = 0;
    std::vector<std::uint8_t> bytes;
    driver_bridge::memory_region_t handle_region{};
    ++query_count;
    const bool handle_region_ok = query_region(scope.pid(), handle, handle_region);
    if (!handle_region_ok)
        ++query_failures;
    const bool handle_readable = handle_region_ok && is_readable(handle_region) && !is_guarded(handle_region);
    diag::log_tagged_fmt("dx_hook",
                         "map_resource_to_va handle_region pid=%u ok=%d readable=%d guarded=%d base=%s size=%llu protect=%s elapsed_ms=%llu",
                         scope.pid(),
                         handle_region_ok ? 1 : 0,
                         handle_readable ? 1 : 0,
                         handle_region_ok && is_guarded(handle_region) ? 1 : 0,
                         handle_region_ok ? sa_format_address(handle_region.base).c_str() : "0x0",
                         static_cast<unsigned long long>(handle_region_ok ? handle_region.size : 0),
                         handle_region_ok ? sa_format_address(handle_region.protect).c_str() : "0x0",
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    ++read_count;
    if (!read_bytes(scope.pid(), handle, 0x400, bytes))
    {
        ++read_failures;
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
        result["query_count"] = query_count;
        result["query_failures"] = query_failures;
        result["read_count"] = read_count;
        result["read_failures"] = read_failures;
        result["preview_reads"] = preview_reads;
        result["pointer_slots"] = pointer_slots;
        result["nested_slots"] = nested_slots;
        result["pointer_candidates"] = pointer_candidates;
        result["gpu_candidates"] = gpu_candidates;
        result["phase"] = "initial_read";
        result["partial"] = false;
        result["found"] = false;
        result["deadline_hit"] = false;
        result["cancelled"] = false;
        result["elapsed_ms"] = GetTickCount64() - started_ms;
        diag::log_tagged_fmt("dx_hook",
                             "map_resource_to_va exit pid=%u ok=0 phase=initial_read handle=%s bytes=0 query_count=%zu query_failures=%zu read_count=%zu read_failures=%zu elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(handle).c_str(),
                             query_count,
                             query_failures,
                             read_count,
                             read_failures,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Failed to read resource object or descriptor as target-process memory.", result);
    }
    diag::log_tagged_fmt("dx_hook",
                         "map_resource_to_va initial_read pid=%u handle=%s ok=1 bytes=%zu elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(handle).c_str(),
                         bytes.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
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
        ++query_count;
        if (ptr == 0 || !query_region(scope.pid(), ptr, region))
        {
            ++query_failures;
            return std::nullopt;
        }
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
        ++preview_reads;
        ++read_count;
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
        else
        {
            ++read_failures;
        }
        ++pointer_candidates;
        return row;
    };
    auto append_gpu_candidate = [&](std::uint64_t gpu_va, std::uint64_t size, std::uint64_t owner, std::uint64_t offset, const std::string& source) {
        if (gpu_va == 0 || candidates.size() >= max_candidates)
            return;
        ++gpu_candidates;
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
        diag::log_tagged_fmt("dx_hook",
                             "map_resource_to_va direct_candidate pid=%u handle=%s candidates=%zu elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(handle).c_str(),
                             candidates.size(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
    }

    std::uint64_t vtable_va = 0;
    ++read_count;
    const bool vtable_ptr_ok = read_u64(scope.pid(), handle, vtable_va);
    if (!vtable_ptr_ok)
        ++read_failures;
    json vtable_evidence;
    vtable_evidence["vtable_va"] = vtable_va ? json(sa_format_address(vtable_va)) : json(nullptr);
    vtable_evidence["method_count_sampled"] = 0;
    vtable_evidence["executable_method_count"] = 0;
    if (vtable_va != 0)
    {
        std::vector<std::uint8_t> vtable_bytes;
        ++read_count;
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
                ++query_count;
                const bool executable = fn != 0 && query_region(scope.pid(), fn, fn_region) && is_executable(fn_region) && !is_guarded(fn_region);
                if (fn == 0 || !executable)
                    ++query_failures;
                if (executable)
                    ++executable_methods;
                methods.push_back({{"slot", i}, {"va", fn ? json(sa_format_address(fn)) : json(nullptr)}, {"executable", executable}, {"owner", fn ? module_owner_for_address(scope.pid(), fn) : json(nullptr)}});
            }
            vtable_evidence["method_count_sampled"] = entries;
            vtable_evidence["executable_method_count"] = executable_methods;
            vtable_evidence["methods"] = std::move(methods);
        }
        else
        {
            ++read_failures;
        }
    }
    diag::log_tagged_fmt("dx_hook",
                         "map_resource_to_va vtable pid=%u vtable=%s ptr_ok=%d method_count=%zu executable=%zu read_count=%zu read_failures=%zu query_count=%zu query_failures=%zu elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(vtable_va).c_str(),
                         vtable_ptr_ok ? 1 : 0,
                         vtable_evidence["method_count_sampled"].get<std::size_t>(),
                         vtable_evidence["executable_method_count"].get<std::size_t>(),
                         read_count,
                         read_failures,
                          query_count,
                          query_failures,
                          static_cast<unsigned long long>(GetTickCount64() - started_ms));

    auto sorted_candidate_copy = [&]() {
        json rows = candidates;
        std::sort(rows.begin(), rows.end(), [](const json& a, const json& b) {
            const double ca = a.contains("confidence") && a["confidence"].is_number() ? a["confidence"].get<double>() : 0.0;
            const double cb = b.contains("confidence") && b["confidence"].is_number() ? b["confidence"].get<double>() : 0.0;
            if (ca != cb)
                return ca > cb;
            const bool ae = a.contains("executable") && a["executable"].is_boolean() && a["executable"].get<bool>();
            const bool be = b.contains("executable") && b["executable"].is_boolean() && b["executable"].get<bool>();
            return !ae && be;
        });
        return rows;
    };
    auto build_result = [&](const char* phase, bool partial, bool deadline_hit, bool cancelled) {
        json rows = sorted_candidate_copy();
        json result;
        result["process_id"] = scope.pid();
        result["resource_handle"] = sa_format_address(handle);
        result["handle_region"] = handle_region_ok ? json(region_json(handle_region)) : json(nullptr);
        result["com_vtable_evidence"] = vtable_evidence;
        result["candidates"] = std::move(rows);
        result["count"] = result["candidates"].size();
        result["candidate_count"] = result["candidates"].size();
        result["found"] = !result["candidates"].empty();
        result["va"] = result["candidates"].empty() ? json(nullptr) : result["candidates"][0]["candidate_va"];
        result["phase"] = phase ? phase : "";
        result["partial"] = partial;
        result["deadline_hit"] = deadline_hit;
        result["cancelled"] = cancelled;
        result["deadline_remaining_ms"] = deadline_remaining();
        result["capability"] = {
            {"cpu_pointer_walk", true},
            {"max_candidates", max_candidates},
            {"gpu_virtual_address_mapping_proven", !result["candidates"].empty() && result["candidates"][0].contains("cpu_va_mapped") && result["candidates"][0]["cpu_va_mapped"].is_boolean() && result["candidates"][0]["cpu_va_mapped"].get<bool>()},
            {"descriptor_gpu_va_reported_as_cpu_va", false}
        };
        result["query_count"] = query_count;
        result["query_failures"] = query_failures;
        result["read_count"] = read_count;
        result["read_failures"] = read_failures;
        result["preview_reads"] = preview_reads;
        result["pointer_slots"] = pointer_slots;
        result["nested_slots"] = nested_slots;
        result["pointer_candidates"] = pointer_candidates;
        result["gpu_candidates"] = gpu_candidates;
        result["elapsed_ms"] = GetTickCount64() - started_ms;
        return result;
    };
    auto is_high_confidence_backing = [](const json& row) {
        const bool readable = row.contains("readable") && row["readable"].is_boolean() && row["readable"].get<bool>();
        const bool executable = row.contains("executable") && row["executable"].is_boolean() && row["executable"].get<bool>();
        const bool guarded = row.contains("guarded") && row["guarded"].is_boolean() && row["guarded"].get<bool>();
        const double confidence = row.contains("confidence") && row["confidence"].is_number() ? row["confidence"].get<double>() : 0.0;
        const std::string proof = row.value("mapping_proof", std::string());
        const std::string source = row.value("source", std::string());
        const std::uint64_t matrix_count = row.contains("matrix_count") && row["matrix_count"].is_number_unsigned() ? row["matrix_count"].get<std::uint64_t>() : 0;
        return readable && !executable && !guarded && proof == "cpu_readable_process_va" &&
            (confidence >= 0.72 || source == "d3d12_cbv_descriptor_buffer_location_cpu_mapped" || matrix_count != 0);
    };

    for (std::size_t off = 0; off + 8 <= bytes.size(); off += 8)
    {
        ++pointer_slots;
        if (dx_call_cancelled("map_resource_to_va_pointer_walk", scope.pid(), started_ms))
        {
            const bool cancelled = mcp_standalone::current_call_cancelled();
            return tool_result_t::error(cancelled ? "Resource VA mapping cancelled." : "Resource VA mapping deadline reached.", build_result("pointer_walk", true, !cancelled, cancelled));
        }
        std::uint64_t ptr = 0;
        std::memcpy(&ptr, bytes.data() + off, sizeof(ptr));
        if (auto row = make_pointer_row(ptr, handle, static_cast<std::uint64_t>(off), "resource_object_qword_pointer", "resource_handle+" + sa_format_address(off), 0.35))
        {
            append_candidate(*row);
            if (is_high_confidence_backing(*row))
                return tool_result_t::ok(build_result("pointer_walk_high_confidence", false, false, false));
        }
        if (off + 12 <= bytes.size())
        {
            std::uint32_t size32 = 0;
            std::memcpy(&size32, bytes.data() + off + 8, sizeof(size32));
            if (ptr != 0 && size32 != 0 && size32 <= 512u * 1024u * 1024u && (ptr & 0xFu) == 0)
            {
                driver_bridge::memory_region_t ptr_region{};
                ++query_count;
                if (query_region(scope.pid(), ptr, ptr_region) && is_readable(ptr_region) && !is_guarded(ptr_region))
                {
                    if (auto row = make_pointer_row(ptr, handle, static_cast<std::uint64_t>(off), "d3d12_cbv_descriptor_buffer_location_cpu_mapped", "descriptor.BufferLocation", 0.72))
                    {
                        (*row)["descriptor_size_bytes"] = size32;
                        (*row)["gpu_va"] = sa_format_address(ptr);
                        (*row)["cpu_va_mapped"] = true;
                        append_candidate(*row);
                        if (is_high_confidence_backing(*row))
                            return tool_result_t::ok(build_result("descriptor_high_confidence", false, false, false));
                    }
                }
                else
                {
                    ++query_failures;
                    append_gpu_candidate(ptr, size32, handle, static_cast<std::uint64_t>(off), "d3d12_cbv_descriptor_gpu_va");
                }
            }
        }
        if (candidates.size() >= max_candidates)
            break;
    }
    diag::log_tagged_fmt("dx_hook",
                         "map_resource_to_va pointer_walk pid=%u slots=%zu candidates=%zu pointer_candidates=%zu gpu_candidates=%zu query_count=%zu query_failures=%zu read_count=%zu read_failures=%zu elapsed_ms=%llu",
                         scope.pid(),
                         pointer_slots,
                         candidates.size(),
                         pointer_candidates,
                         gpu_candidates,
                         query_count,
                         query_failures,
                         read_count,
                         read_failures,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));

    json first_level = candidates;
    for (const auto& row : first_level)
    {
        if (candidates.size() >= max_candidates)
            break;
        if (dx_call_cancelled("map_resource_to_va_nested_walk", scope.pid(), started_ms))
        {
            const bool cancelled = mcp_standalone::current_call_cancelled();
            return tool_result_t::error(cancelled ? "Resource VA mapping cancelled." : "Resource VA mapping deadline reached.", build_result("nested_walk", true, !cancelled, cancelled));
        }
        std::uint64_t base = 0;
        if (!row.contains("candidate_va") || !parse_u64_value(row["candidate_va"], base) || base == 0)
            continue;
        if (row.contains("executable") && row["executable"].is_boolean() && row["executable"].get<bool>())
            continue;
        std::vector<std::uint8_t> nested;
        ++read_count;
        if (!read_bytes(scope.pid(), base, 0x180, nested) || nested.size() < sizeof(std::uint64_t))
        {
            ++read_failures;
            continue;
        }
        for (std::size_t off = 0; off + sizeof(std::uint64_t) <= nested.size() && candidates.size() < max_candidates; off += sizeof(std::uint64_t))
        {
            ++nested_slots;
            if (dx_call_cancelled("map_resource_to_va_nested_slots", scope.pid(), started_ms))
            {
                const bool cancelled = mcp_standalone::current_call_cancelled();
                return tool_result_t::error(cancelled ? "Resource VA mapping cancelled." : "Resource VA mapping deadline reached.", build_result("nested_slots", true, !cancelled, cancelled));
            }
            std::uint64_t ptr = 0;
            std::memcpy(&ptr, nested.data() + off, sizeof(ptr));
            if (auto nested_row = make_pointer_row(ptr, base, static_cast<std::uint64_t>(off), "resource_nested_qword_pointer", row.value("chain", std::string("resource")) + "->" + sa_format_address(off), 0.28))
            {
                append_candidate(*nested_row);
                if (is_high_confidence_backing(*nested_row))
                    return tool_result_t::ok(build_result("nested_high_confidence", false, false, false));
            }
        }
    }
    diag::log_tagged_fmt("dx_hook",
                         "map_resource_to_va nested_walk pid=%u nested_slots=%zu candidates=%zu pointer_candidates=%zu gpu_candidates=%zu query_count=%zu query_failures=%zu read_count=%zu read_failures=%zu preview_reads=%zu elapsed_ms=%llu",
                         scope.pid(),
                         nested_slots,
                         candidates.size(),
                         pointer_candidates,
                         gpu_candidates,
                         query_count,
                         query_failures,
                         read_count,
                         read_failures,
                         preview_reads,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    json result = build_result("complete", false, false, false);
    if (result["count"].get<std::size_t>() == 0)
    {
        diag::log_tagged_fmt("dx_hook",
                             "map_resource_to_va exit pid=%u ok=0 handle=%s count=0 query_count=%zu query_failures=%zu read_count=%zu read_failures=%zu pointer_slots=%zu nested_slots=%zu pointer_candidates=%zu gpu_candidates=%zu elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(handle).c_str(),
                             query_count,
                             query_failures,
                             read_count,
                             read_failures,
                             pointer_slots,
                             nested_slots,
                             pointer_candidates,
                             gpu_candidates,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        result["failure_reason"] = "no_cpu_readable_resource_backing_candidate";
        return tool_result_t::error("No CPU-readable resource backing candidate was recovered.", result);
    }
    diag::log_tagged_fmt("dx_hook",
                         "map_resource_to_va exit pid=%u ok=1 handle=%s count=%zu va=%s query_count=%zu query_failures=%zu read_count=%zu read_failures=%zu pointer_slots=%zu nested_slots=%zu pointer_candidates=%zu gpu_candidates=%zu elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(handle).c_str(),
                         result["count"].get<std::size_t>(),
                         result["va"].is_string() ? result["va"].get<std::string>().c_str() : "null",
                         query_count,
                         query_failures,
                         read_count,
                         read_failures,
                         pointer_slots,
                         nested_slots,
                         pointer_candidates,
                         gpu_candidates,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
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
    std::string output_path = string_param(params, "output_path");
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

    if (allow_window_fallback)
    {
        auto window = find_target_window(scope.pid());
        if (!window)
        {
            json result;
            result["process_id"] = scope.pid();
            result["format"] = format;
            result["captured"] = false;
            result["source"] = "window_capture_gdi";
            result["gpu_texture_memory"] = false;
            result["gpu_readback_capability"] = gpu_readback_capability;
            result["allow_window_fallback"] = true;
            result["window_fallback_available"] = false;
            result["window_capture_backend"] = "disabled_no_visible_window";
            result["output_path"] = nullptr;
            result["bytes_written"] = 0;
            result["evidence"] = {
                {"process_window_validated", false},
                {"bounded_file_write", false},
                {"render_target_readback", false},
                {"frame_capture_only", false},
                {"window_frame_is_gpu_memory", false}
            };
            return tool_result_t::error("No visible window found for target process.", result);
        }

        std::vector<std::uint8_t> rgba;
        int width = 0, height = 0;
        std::string method, capture_error;
        if (!capture_window_rgba(window->hwnd, rgba, width, height, method, capture_error))
        {
            json result;
            result["process_id"] = scope.pid();
            result["format"] = format;
            result["captured"] = false;
            result["source"] = "window_capture_gdi";
            result["gpu_texture_memory"] = false;
            result["gpu_readback_capability"] = gpu_readback_capability;
            result["allow_window_fallback"] = true;
            result["window_fallback_available"] = false;
            result["window_capture_backend"] = "disabled_capture_failure";
            result["output_path"] = nullptr;
            result["bytes_written"] = 0;
            result["window_title"] = wide_to_utf8(window->title);
            result["window_class"] = wide_to_utf8(window->cls);
            result["evidence"] = {
                {"process_window_validated", true},
                {"bounded_file_write", false},
                {"render_target_readback", false},
                {"frame_capture_only", false},
                {"window_frame_is_gpu_memory", false}
            };
            return tool_result_t::error("Window capture failed: " + capture_error, result);
        }

        std::filesystem::path output = output_path.empty()
            ? default_capture_path(scope.pid(), format)
            : std::filesystem::path(output_path);
        std::string write_error;
        bool write_ok = false;
        if (format == "png")
            write_ok = write_png_file(output, rgba, width, height, write_error);
        else
            write_ok = write_binary_file(output, rgba, write_error);
        if (!write_ok)
        {
            std::string label = format == "png" ? "PNG encode failed: " : "RGBA write failed: ";
            json result;
            result["process_id"] = scope.pid();
            result["format"] = format;
            result["captured"] = false;
            result["source"] = "window_capture_gdi";
            result["gpu_texture_memory"] = false;
            result["gpu_readback_capability"] = gpu_readback_capability;
            result["allow_window_fallback"] = true;
            result["window_fallback_available"] = true;
            result["window_capture_backend"] = method;
            result["output_path"] = nullptr;
            result["bytes_written"] = 0;
            result["width"] = width;
            result["height"] = height;
            result["window_title"] = wide_to_utf8(window->title);
            result["window_class"] = wide_to_utf8(window->cls);
            result["evidence"] = {
                {"process_window_validated", true},
                {"bounded_file_write", false},
                {"render_target_readback", false},
                {"frame_capture_only", false},
                {"window_frame_is_gpu_memory", false}
            };
            return tool_result_t::error(label + write_error, result);
        }

        json result;
        result["process_id"] = scope.pid();
        result["format"] = format;
        result["captured"] = true;
        result["source"] = "window_capture_gdi";
        result["method"] = method;
        result["width"] = width;
        result["height"] = height;
        result["output_path"] = output.string();
        result["bytes_written"] = rgba.size();
        result["gpu_texture_memory"] = false;
        result["gpu_readback_capability"] = gpu_readback_capability;
        result["allow_window_fallback"] = true;
        result["window_fallback_available"] = true;
        result["window_capture_backend"] = method;
        result["window_title"] = wide_to_utf8(window->title);
        result["window_class"] = wide_to_utf8(window->cls);
        result["evidence"] = {
            {"process_window_validated", true},
            {"bounded_file_write", true},
            {"render_target_readback", false},
            {"frame_capture_only", true},
            {"window_frame_is_gpu_memory", false}
        };
        return tool_result_t::ok("Window captured via " + method + ". This is a GDI screenshot, not GPU memory readback.", result);
    }

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

        auto hot_vas = store::list_hot_vas(scope.pid());
        auto hot_it = std::find_if(hot_vas.begin(), hot_vas.end(), [&](const store::hot_va_entry_t& e) {
            return e.va == va;
        });
        if (hot_it != hot_vas.end())
        {
            confidence += hot_it->confidence_boost;
            row["hot_va_boost"] = hot_it->confidence_boost;
            row["hot_va_hit_count"] = hot_it->hit_count;
            row["hot_va_frame_count"] = hot_it->frame_count;
        }
        else
        {
            for (const auto& hv : hot_vas)
            {
                if (std::abs(static_cast<std::int64_t>(hv.va) - static_cast<std::int64_t>(va)) < 4096)
                {
                    confidence += hv.confidence_boost * 0.5;
                    row["hot_va_proximity_boost"] = hv.confidence_boost * 0.5;
                    break;
                }
            }
        }

        if (hot_it == hot_vas.end() && temporal_hits.count(va) && temporal_hits[va] <= 1)
        {
            confidence -= 0.05;
            row["single_hit_penalty"] = -0.05;
        }

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
        row["toolchain_hint"] = "Use this VA as matrix_buffer_va input to dx_identify_bone_buffer or dx_project_bones for correlation";
        row["next_action"] = "dx_verify_view_matrix";
        row["next_action_params"] = json::object({
            {"process_id", scope.pid()},
            {"matrix_va", sa_format_address(va)}
        });
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

tool_result_t verify_view_matrix(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t matrix_va = 0;
    if (!parse_address_param(params, "matrix_va", matrix_va) &&
        !parse_address_param(params, "view_matrix_va", matrix_va) &&
        !parse_address_param(params, "candidate_va", matrix_va))
        return tool_result_t::error("'matrix_va' (or 'view_matrix_va'/'candidate_va') is required.");
    if (matrix_va == 0)
        return tool_result_t::error("'matrix_va' is required and must be non-zero.");

    const double world_max = number_param(params, "world_unit_max", 1000000.0, 1.0, 1000000000.0);
    const std::uint32_t screen_w = static_cast<std::uint32_t>(numeric_param(params, "screen_width", 0, 0, 16384));
    const std::uint32_t screen_h = static_cast<std::uint32_t>(numeric_param(params, "screen_height", 0, 0, 16384));

    screen_dimensions_t dims = discover_screen_dimensions(scope.pid(), screen_w, screen_h);
    if (!dims.ok)
        return tool_result_t::error("Could not determine screen dimensions. Provide 'screen_width' and 'screen_height' parameters.", json{
            {"process_id", scope.pid()},
            {"matrix_va", sa_format_address(matrix_va)},
            {"screen_dimension_source", dims.source}
        });

    matrix_read_t mat = read_and_evaluate_matrix(scope.pid(), matrix_va, world_max);
    if (!mat.ok)
        return tool_result_t::error("Matrix at given VA is not plausible or could not be read.", json{
            {"process_id", scope.pid()},
            {"matrix_va", sa_format_address(matrix_va)},
            {"eval_reason", mat.eval.reason},
            {"matrix_type", mat.eval.type},
            {"screen_width", dims.width},
            {"screen_height", dims.height}
        });

    const bool row_major = orientation_is_row_major(mat.orientation);
    const bool col_major = orientation_is_column_major(mat.orientation);
    const bool orientation_known = row_major || col_major;

    json result;
    result["process_id"] = scope.pid();
    result["matrix_va"] = sa_format_address(matrix_va);
    result["matrix_type"] = mat.eval.type;
    result["matrix_orientation"] = mat.orientation;
    result["determinant3x3"] = mat.eval.determinant;
    result["orthogonality_error"] = mat.eval.orthogonality_error;
    result["inverse_residual3x3"] = mat.eval.inverse_residual;
    result["screen_width"] = dims.width;
    result["screen_height"] = dims.height;
    result["screen_dimension_source"] = dims.source;
    json floats = json::array();
    for (int i = 0; i < 16; ++i)
        floats.push_back(mat.matrix.m[i]);
    result["preview_floats"] = floats;

    json projected_points = json::array();
    if (params.contains("test_world_points") && params["test_world_points"].is_array())
    {
        for (const auto& pt : params["test_world_points"])
        {
            vec3_t world;
            if (pt.is_array() && pt.size() >= 3)
            {
                world.x = pt[0].get<float>();
                world.y = pt[1].get<float>();
                world.z = pt[2].get<float>();
            }
            else if (pt.is_object() && pt.contains("x") && pt.contains("y") && pt.contains("z"))
            {
                world.x = pt["x"].get<float>();
                world.y = pt["y"].get<float>();
                world.z = pt["z"].get<float>();
            }
            else
                continue;

            if (!orientation_known)
            {
                w2s_result_t rm = world_to_screen_viewproj(world, mat.matrix, true, dims.width, dims.height);
                w2s_result_t cm = world_to_screen_viewproj(world, mat.matrix, false, dims.width, dims.height);
                projected_points.push_back({
                    {"world", {{"x", world.x}, {"y", world.y}, {"z", world.z}}},
                    {"row_major", {{"screen_x", rm.screen.x}, {"screen_y", rm.screen.y},
                                   {"behind_camera", rm.screen.behind_camera}, {"valid", rm.screen.valid},
                                   {"clip_w", rm.clip.w}}},
                    {"column_major", {{"screen_x", cm.screen.x}, {"screen_y", cm.screen.y},
                                      {"behind_camera", cm.screen.behind_camera}, {"valid", cm.screen.valid},
                                      {"clip_w", cm.clip.w}}}
                });
            }
            else
            {
                w2s_result_t w2s = world_to_screen_viewproj(world, mat.matrix, row_major, dims.width, dims.height);
                projected_points.push_back({
                    {"world", {{"x", world.x}, {"y", world.y}, {"z", world.z}}},
                    {"screen_x", w2s.screen.x},
                    {"screen_y", w2s.screen.y},
                    {"behind_camera", w2s.screen.behind_camera},
                    {"valid", w2s.screen.valid},
                    {"clip_w", w2s.clip.w},
                    {"ndc_x", w2s.clip.x / (w2s.clip.w != 0 ? w2s.clip.w : 1.0f)},
                    {"ndc_y", w2s.clip.y / (w2s.clip.w != 0 ? w2s.clip.w : 1.0f)}
                });
            }
        }
    }
    result["projected_points"] = projected_points;
    result["projected_point_count"] = projected_points.size();

    bool verified = false;
    double confidence_adjustment = 0.0;
    json heuristic = json::object();
    json notes = json::array();

    if (projected_points.empty())
    {
        const vec3_t cube_corners[8] = {
            {-1, -1, -1}, {1, -1, -1}, {1, 1, -1}, {-1, 1, -1},
            {-1, -1,  1}, {1, -1,  1}, {1, 1,  1}, {-1, 1,  1}
        };
        json cube_projections = json::array();
        int valid_count = 0;
        int behind_count = 0;
        float min_screen_x = FLT_MAX, max_screen_x = -FLT_MAX;
        float min_screen_y = FLT_MAX, max_screen_y = -FLT_MAX;

        for (int i = 0; i < 8; ++i)
        {
            w2s_result_t w2s;
            if (orientation_known)
                w2s = world_to_screen_viewproj(cube_corners[i], mat.matrix, row_major, dims.width, dims.height);
            else
                w2s = world_to_screen_viewproj(cube_corners[i], mat.matrix, true, dims.width, dims.height);

            if (w2s.screen.behind_camera)
                ++behind_count;
            else
            {
                if (w2s.screen.x < min_screen_x) min_screen_x = w2s.screen.x;
                if (w2s.screen.x > max_screen_x) max_screen_x = w2s.screen.x;
                if (w2s.screen.y < min_screen_y) min_screen_y = w2s.screen.y;
                if (w2s.screen.y > max_screen_y) max_screen_y = w2s.screen.y;
                if (w2s.screen.valid)
                    ++valid_count;
            }
            cube_projections.push_back({
                {"corner", i},
                {"world", {{"x", cube_corners[i].x}, {"y", cube_corners[i].y}, {"z", cube_corners[i].z}}},
                {"screen_x", w2s.screen.x},
                {"screen_y", w2s.screen.y},
                {"behind_camera", w2s.screen.behind_camera},
                {"clip_w", w2s.clip.w}
            });
        }

        heuristic["cube_corner_projections"] = cube_projections;
        heuristic["valid_count"] = valid_count;
        heuristic["behind_count"] = behind_count;

        const bool all_behind = behind_count == 8;
        const bool none_behind = behind_count == 0;
        const bool some_valid = valid_count > 0;

        if (all_behind)
        {
            notes.push_back("All 8 unit-cube corners are behind the camera. The matrix may be a view matrix with the camera at origin looking down -Z; try test world points in front of the camera.");
            confidence_adjustment = -0.10;
        }
        else if (none_behind && some_valid)
        {
            const float span_x = max_screen_x - min_screen_x;
            const float span_y = max_screen_y - min_screen_y;
            heuristic["screen_span_x"] = span_x;
            heuristic["screen_span_y"] = span_y;

            const bool reasonable_span = span_x > 1.0f && span_x < static_cast<float>(dims.width) * 4.0f &&
                                          span_y > 1.0f && span_y < static_cast<float>(dims.height) * 4.0f;
            if (reasonable_span)
            {
                verified = true;
                confidence_adjustment = 0.08;
                notes.push_back("Unit-cube corners project to a reasonable spread of screen coordinates.");
            }
            else
            {
                notes.push_back("Unit-cube corners project but screen spread is unusual (too small or too large).");
                confidence_adjustment = -0.05;
            }
        }
        else
        {
            notes.push_back("Mixed projection results: some corners behind camera, some in front. This is plausible for a view matrix near the origin.");
            confidence_adjustment = 0.0;
        }

        if (!orientation_known)
            notes.push_back("Matrix orientation is not definitively row_major or column_major. Projection results assume row_major. Provide test_world_points for dual-orientation comparison.");

        result["screen_bounds"] = {
            {"min_x", min_screen_x == FLT_MAX ? json(nullptr) : json(min_screen_x)},
            {"max_x", max_screen_x == -FLT_MAX ? json(nullptr) : json(max_screen_x)},
            {"min_y", min_screen_y == FLT_MAX ? json(nullptr) : json(min_screen_y)},
            {"max_y", max_screen_y == -FLT_MAX ? json(nullptr) : json(max_screen_y)}
        };
    }

    result["heuristic"] = heuristic;
    result["verified"] = verified;
    result["confidence_adjustment"] = confidence_adjustment;
    result["notes"] = notes;
    result["finding_semantics"] = "projection_verification_evidence_not_camera_object";
    result["elapsed_ms"] = GetTickCount64() - started_ms;

    diag::log_tagged_fmt("dx_hook",
                         "verify_view_matrix exit pid=%u matrix_va=%s type=%s orientation=%s verified=%d conf_adj=%f elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(matrix_va).c_str(),
                         mat.eval.type.c_str(),
                         mat.orientation.c_str(),
                         verified ? 1 : 0,
                         confidence_adjustment,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));

    return tool_result_t::ok("View matrix verification completed.", result);
}

tool_result_t project_bones(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t bone_buffer_va = 0;
    if (!parse_address_param(params, "bone_buffer_va", bone_buffer_va) &&
        !parse_address_param(params, "matrix_buffer_va", bone_buffer_va))
        return tool_result_t::error("'bone_buffer_va' is required.");
    if (bone_buffer_va == 0)
        return tool_result_t::error("'bone_buffer_va' is required and must be non-zero.");

    std::uint64_t view_matrix_va = 0;
    if (!parse_address_param(params, "view_matrix_va", view_matrix_va) &&
        !parse_address_param(params, "matrix_va", view_matrix_va))
        return tool_result_t::error("'view_matrix_va' is required.");
    if (view_matrix_va == 0)
        return tool_result_t::error("'view_matrix_va' is required and must be non-zero.");

    const double world_max = number_param(params, "world_unit_max", 1000000.0, 1.0, 1000000000.0);
    const std::uint32_t screen_w = static_cast<std::uint32_t>(numeric_param(params, "screen_width", 0, 0, 16384));
    const std::uint32_t screen_h = static_cast<std::uint32_t>(numeric_param(params, "screen_height", 0, 0, 16384));

    screen_dimensions_t dims = discover_screen_dimensions(scope.pid(), screen_w, screen_h);
    if (!dims.ok)
        return tool_result_t::error("Could not determine screen dimensions. Provide 'screen_width' and 'screen_height' parameters.", json{
            {"process_id", scope.pid()},
            {"bone_buffer_va", sa_format_address(bone_buffer_va)},
            {"view_matrix_va", sa_format_address(view_matrix_va)},
            {"screen_dimension_source", dims.source}
        });

    matrix_read_t view_mat = read_and_evaluate_matrix(scope.pid(), view_matrix_va, world_max);
    if (!view_mat.ok)
        return tool_result_t::error("View matrix at given VA is not plausible or could not be read.", json{
            {"process_id", scope.pid()},
            {"view_matrix_va", sa_format_address(view_matrix_va)},
            {"eval_reason", view_mat.eval.reason},
            {"matrix_type", view_mat.eval.type}
        });

    const bool row_major = orientation_is_row_major(view_mat.orientation);
    const bool col_major = orientation_is_column_major(view_mat.orientation);
    const bool orientation_known = row_major || col_major;
    const bool use_row_major = orientation_known ? row_major : true;

    const std::uint32_t max_bones = static_cast<std::uint32_t>(numeric_param(params, "max_bones", 256, 1, 4096));
    const std::size_t read_size = static_cast<std::size_t>(64ull * max_bones);
    std::vector<std::uint8_t> bone_bytes;
    if (!read_bytes(scope.pid(), bone_buffer_va, read_size, bone_bytes) || bone_bytes.size() < 48)
        return tool_result_t::error("Could not read bone buffer at given VA.", json{
            {"process_id", scope.pid()},
            {"bone_buffer_va", sa_format_address(bone_buffer_va)},
            {"requested_read_size", read_size},
            {"bytes_read", bone_bytes.size()}
        });

    matrix_decode_result_t decoded = best_matrix_decode_run(bone_bytes, world_max, max_bones, 512);
    if (decoded.count == 0)
        return tool_result_t::error("No plausible bone matrices found in bone buffer.", json{
            {"process_id", scope.pid()},
            {"bone_buffer_va", sa_format_address(bone_buffer_va)},
            {"view_matrix_va", sa_format_address(view_matrix_va)}
        });

    std::set<std::uint32_t> requested_indices;
    if (params.contains("bone_indices") && params["bone_indices"].is_array())
    {
        for (const auto& idx : params["bone_indices"])
        {
            if (idx.is_number_integer())
                requested_indices.insert(static_cast<std::uint32_t>(idx.get<int>()));
        }
    }

    json bone_results = json::array();
    std::uint32_t projected_count = 0;
    std::uint32_t behind_camera_count = 0;
    std::uint32_t valid_screen_count = 0;

    for (std::uint32_t i = 0; i < decoded.count; ++i)
    {
        if (!requested_indices.empty() && requested_indices.count(i) == 0)
            continue;

        const std::size_t bone_offset = decoded.offset + i * decoded.stride;
        float f[16] = {};
        if (!decode_matrix_words(bone_bytes, bone_offset, decoded.stride, decoded.xor_key, f))
            continue;

        mat4x4_t bone_matrix;
        bone_matrix.load_from_floats(f);

        matrix_eval_t bone_eval = evaluate_matrix4x4(f, world_max);
        const bool bone_row_major = orientation_is_row_major(bone_eval.orientation);
        const bool bone_col_major = orientation_is_column_major(bone_eval.orientation);
        const bool bone_use_row_major = bone_row_major ? true : (bone_col_major ? false : true);

        vec3_t bone_pos = extract_bone_position(bone_matrix, bone_use_row_major);

        w2s_result_t w2s = world_to_screen_viewproj(bone_pos, view_mat.matrix, use_row_major, dims.width, dims.height);

        double confidence = 0.50;
        if (bone_eval.plausible)
            confidence += bone_eval.score * 0.20;
        if (!w2s.screen.behind_camera)
            confidence += 0.10;
        if (w2s.screen.valid)
            confidence += 0.05;

        json bone_row;
        bone_row["bone_index"] = i;
        bone_row["world_pos"] = {{"x", bone_pos.x}, {"y", bone_pos.y}, {"z", bone_pos.z}};
        bone_row["screen_x"] = w2s.screen.x;
        bone_row["screen_y"] = w2s.screen.y;
        bone_row["behind_camera"] = w2s.screen.behind_camera;
        bone_row["valid"] = w2s.screen.valid;
        bone_row["clip_w"] = w2s.clip.w;
        bone_row["confidence"] = std::min(0.95, confidence);
        bone_row["bone_matrix_orientation"] = bone_eval.orientation;
        bone_row["decode"] = decoded.decode;

        bone_results.push_back(std::move(bone_row));
        ++projected_count;
        if (w2s.screen.behind_camera)
            ++behind_camera_count;
        else if (w2s.screen.valid)
            ++valid_screen_count;

        if (dx_call_cancelled("project_bones_iteration", scope.pid(), started_ms))
            break;
    }

    json result;
    result["process_id"] = scope.pid();
    result["bone_buffer_va"] = sa_format_address(bone_buffer_va);
    result["view_matrix_va"] = sa_format_address(view_matrix_va);
    result["view_matrix_type"] = view_mat.eval.type;
    result["view_matrix_orientation"] = view_mat.orientation;
    result["bone_count"] = decoded.count;
    result["projected_count"] = projected_count;
    result["projected"] = projected_count;
    result["behind_camera_count"] = behind_camera_count;
    result["valid_screen_count"] = valid_screen_count;
    result["screen_width"] = dims.width;
    result["screen_height"] = dims.height;
    result["screen_dimension_source"] = dims.source;
    result["matrix_stride"] = decoded.stride;
    result["decode"] = decoded.decode;
    result["xor_key"] = decoded.xor_key == 0 ? json(nullptr) : json(sa_format_address(decoded.xor_key));
    result["bones"] = std::move(bone_results);
    result["finding_semantics"] = "bone_screen_projection_evidence";
    result["usage_hint"] = "If projected bone screen positions form a recognizable human silhouette on screen, both the view matrix and bone buffer are confirmed correct. The AI agent can overlay these coordinates on a screen capture to visually verify.";
    result["elapsed_ms"] = GetTickCount64() - started_ms;

    diag::log_tagged_fmt("dx_hook",
                         "project_bones exit pid=%u bone_va=%s view_va=%s bones=%u projected=%u behind=%u valid=%u elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(bone_buffer_va).c_str(),
                         sa_format_address(view_matrix_va).c_str(),
                         decoded.count,
                         projected_count,
                         behind_camera_count,
                         valid_screen_count,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));

    return tool_result_t::ok("Bone positions projected to screen coordinates.", result);
}

tool_result_t trace_decryption(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);

    if (action == "list")
    {
        json arr = json::array();
        for (const auto& trace : store::list_decryption_traces(scope.pid()))
        {
            json row;
            row["id"] = trace.id;
            row["process_id"] = trace.pid;
            row["staging_va"] = sa_format_address(trace.staging_va);
            row["staging_size"] = trace.staging_size;
            row["decryption_func_va"] = trace.decryption_func_va ? json(sa_format_address(trace.decryption_func_va)) : json(nullptr);
            row["encrypted_source_va"] = trace.encrypted_source_va ? json(sa_format_address(trace.encrypted_source_va)) : json(nullptr);
            row["encrypted_source_size"] = trace.encrypted_source_size;
            row["algorithm"] = trace.algorithm_name;
            row["key_length"] = trace.key_length;
            row["key_pattern"] = trace.key_pattern;
            row["verified"] = trace.verified;
            row["verification_detail"] = trace.verification_detail;
            row["caller_rip"] = trace.caller_rip ? json(sa_format_address(trace.caller_rip)) : json(nullptr);
            row["status"] = trace.status;
            row["created_ms"] = trace.created_ms;
            row["frame_index"] = trace.frame_index;
            if (!trace.derived_key_bytes.empty())
                row["key_hex"] = bytes_to_hex(trace.derived_key_bytes, 64);
            arr.push_back(std::move(row));
        }
        json result;
        result["process_id"] = scope.pid();
        result["traces"] = std::move(arr);
        result["count"] = result["traces"].size();
        return tool_result_t::ok(result);
    }

    if (action == "stop")
    {
        if (!unsafe_confirmed(p))
            return unsafe_required("dx_trace_decryption stop");
        stop_staging_watch(scope.pid());
        json result;
        result["process_id"] = scope.pid();
        result["stopped"] = true;
        return tool_result_t::ok("Staging buffer watch stopped.", result);
    }

    if (action == "detail")
    {
        const std::string trace_id = string_param(p, "trace_id");
        if (trace_id.empty())
            return tool_result_t::error("'trace_id' is required for detail.");
        store::decryption_trace_record_t trace;
        if (!store::find_decryption_trace(trace_id, trace))
            return tool_result_t::error("Trace not found.");
        json result;
        result["id"] = trace.id;
        result["process_id"] = trace.pid;
        result["staging_va"] = sa_format_address(trace.staging_va);
        result["staging_size"] = trace.staging_size;
        result["decryption_func_va"] = trace.decryption_func_va ? json(sa_format_address(trace.decryption_func_va)) : json(nullptr);
        result["encrypted_source_va"] = trace.encrypted_source_va ? json(sa_format_address(trace.encrypted_source_va)) : json(nullptr);
        result["encrypted_source_size"] = trace.encrypted_source_size;
        result["algorithm"] = trace.algorithm_name;
        result["key_length"] = trace.key_length;
        result["key_pattern"] = trace.key_pattern;
        result["verified"] = trace.verified;
        result["verification_detail"] = trace.verification_detail;
        result["caller_rip"] = trace.caller_rip ? json(sa_format_address(trace.caller_rip)) : json(nullptr);
        result["register_snapshot"] = trace.register_snapshot;
        result["callstack"] = json::array();
        for (auto addr : trace.callstack)
        {
            json frame;
            frame["va"] = sa_format_address(addr);
            auto cmod = find_module_for_address(scope.pid(), addr);
            if (cmod)
            {
                frame["module"] = cmod->name;
                frame["rva"] = sa_format_address(addr - cmod->base);
            }
            result["callstack"].push_back(std::move(frame));
        }
        result["cleartext_hex"] = bytes_to_hex(trace.cleartext_sample, 256);
        result["encrypted_hex"] = bytes_to_hex(trace.encrypted_sample, 256);
        if (!trace.derived_key_bytes.empty())
            result["key_hex"] = bytes_to_hex(trace.derived_key_bytes, 128);
        result["status"] = trace.status;
        result["created_ms"] = trace.created_ms;
        result["frame_index"] = trace.frame_index;
        auto mod = find_module_for_address(scope.pid(), trace.decryption_func_va);
        if (mod)
        {
            result["decryption_func_module"] = mod->name;
            result["decryption_func_rva"] = sa_format_address(trace.decryption_func_va - mod->base);
        }
        return tool_result_t::ok(result);
    }

    if (action == "remove")
    {
        if (!unsafe_confirmed(p))
            return unsafe_required("dx_trace_decryption remove");
        const std::string trace_id = string_param(p, "trace_id");
        if (trace_id.empty())
            return tool_result_t::error("'trace_id' is required for remove.");
        store::decryption_trace_record_t removed;
        if (!store::remove_decryption_trace(trace_id, &removed))
            return tool_result_t::error("Trace not found.");
        json result;
        result["removed_id"] = trace_id;
        return tool_result_t::ok("Trace removed.", result);
    }

    if (action != "trace")
        return compat_unknown_action("dx_trace_decryption", action);

    if (!unsafe_confirmed(p))
        return unsafe_required("dx_trace_decryption trace");

    std::uint64_t staging_va = 0;
    if (!parse_address_param(p, "staging_va", staging_va) || staging_va == 0)
    {
        std::uint64_t cbuffer_va = 0;
        if (!parse_address_param(p, "cbuffer_va", cbuffer_va) || cbuffer_va == 0)
            return tool_result_t::error("'staging_va' (or 'cbuffer_va') is required for trace action.");
        staging_va = cbuffer_va;
    }

    driver_bridge::memory_region_t region{};
    if (!query_region(scope.pid(), staging_va, region) || !is_readable(region))
        return tool_result_t::error("staging_va is not readable in target process.");

    const std::uint64_t staging_size = [&]() -> std::uint64_t {
        std::uint64_t size = 0;
        if (parse_address_param(p, "staging_size", size) && size > 0)
            return size;
        const std::uint64_t region_end = region.base + region.size;
        return region_end > staging_va ? region_end - staging_va : 4096;
    }();

    const int hw_slot = static_cast<int>(numeric_param(p, "hw_slot", 0, 0, 3));
    const std::uint32_t max_frames = static_cast<std::uint32_t>(numeric_param(p, "max_frames", 3, 1, 16));
    const std::uint32_t timeout_ms = static_cast<std::uint32_t>(numeric_param(p, "timeout_ms", 30000, 1000, 120000));

    std::uint64_t pointer_location_va = 0;
    parse_address_param(p, "pointer_location_va", pointer_location_va);

    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error("Kernel driver is required for write hardware breakpoints.");

    diag::log_tagged_fmt("dx_hook",
        "trace_decryption enter pid=%u staging_va=%s staging_size=%llu hw_slot=%d max_frames=%u timeout_ms=%u",
        scope.pid(),
        sa_format_address(staging_va).c_str(),
        static_cast<unsigned long long>(staging_size),
        hw_slot,
        max_frames,
        timeout_ms);

    std::string watch_error;
    if (!start_staging_watch(scope.pid(), staging_va, staging_size, hw_slot,
                              max_frames, pointer_location_va, watch_error))
        return tool_result_t::error("Failed to start staging watch: " + watch_error);

    const std::uint64_t deadline = GetTickCount64() + timeout_ms;
    while (GetTickCount64() < deadline)
    {
        if (dx_call_cancelled("trace_decryption_wait", scope.pid(), started_ms))
        {
            stop_staging_watch(scope.pid());
            return tool_result_t::error("Trace decryption cancelled.");
        }
        bool all_captured = false;
        {
            auto& state = staging_watch_state();
            std::lock_guard<std::mutex> lock(state.watch_mutex);
            all_captured = !state.watches.empty();
            for (const auto& w : state.watches)
                if (!w.captured_write)
                    all_captured = false;
        }
        if (all_captured)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    stop_staging_watch(scope.pid());

    json traces = json::array();
    for (const auto& trace : store::list_decryption_traces(scope.pid()))
    {
        if (trace.staging_va != staging_va)
            continue;
        json row;
        row["id"] = trace.id;
        row["decryption_func_va"] = trace.decryption_func_va ? json(sa_format_address(trace.decryption_func_va)) : json(nullptr);
        row["encrypted_source_va"] = trace.encrypted_source_va ? json(sa_format_address(trace.encrypted_source_va)) : json(nullptr);
        row["algorithm"] = trace.algorithm_name;
        row["key_length"] = trace.key_length;
        row["key_pattern"] = trace.key_pattern;
        row["verified"] = trace.verified;
        row["verification_detail"] = trace.verification_detail;
        row["caller_rip"] = trace.caller_rip ? json(sa_format_address(trace.caller_rip)) : json(nullptr);
        row["status"] = trace.status;
        row["frame_index"] = trace.frame_index;
        if (!trace.derived_key_bytes.empty())
            row["key_hex"] = bytes_to_hex(trace.derived_key_bytes, 64);
        auto mod = find_module_for_address(scope.pid(), trace.decryption_func_va);
        if (mod)
        {
            row["decryption_func_module"] = mod->name;
            row["decryption_func_rva"] = sa_format_address(trace.decryption_func_va - mod->base);
        }
        traces.push_back(std::move(row));
    }

    json result;
    result["process_id"] = scope.pid();
    result["staging_va"] = sa_format_address(staging_va);
    result["staging_size"] = staging_size;
    result["traces"] = std::move(traces);
    result["trace_count"] = result["traces"].size();
    result["found"] = result["trace_count"].get<std::size_t>() != 0;
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    if (result["trace_count"].get<std::size_t>() == 0)
    {
        result["failure_reason"] = "no_write_hit_within_timeout";
        return tool_result_t::ok("No staging buffer write was captured within the timeout.", result);
    }
    result["best"] = result["traces"][0];
    return tool_result_t::ok("Staging buffer decryption trace captured.", result);
}

tool_result_t read_gpu_buffer(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    if (!unsafe_confirmed(params))
        return unsafe_required("dx_read_gpu_buffer");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error("Kernel driver is required for remote COM method invocation.");

    std::uint64_t buffer_va = 0;
    if (!parse_address_param(params, "buffer_va", buffer_va) || buffer_va == 0)
        return tool_result_t::error("'buffer_va' is required and must be non-zero.");

    std::uint64_t device_context_va = 0;
    parse_address_param(params, "device_context_va", device_context_va);

    const std::uint64_t max_size = numeric_param(params, "max_size", 65536, 1, 1048576);
    const bool detect_matrices = bool_param(params, "detect_matrices", true);

    if (device_context_va == 0)
    {
        for (const auto& record : store::list_dx_hooks(scope.pid()))
        {
            if (lower_ascii(record.api).find("d3d11") == std::string::npos)
                continue;
            if (record.action != "cbuffer_bind")
                continue;
            for (const auto& cap : record.captures)
            {
                if (!cap.contains("cbuffers") || !cap["cbuffers"].is_array())
                    continue;
                bool found_match = false;
                for (const auto& cb : cap["cbuffers"])
                {
                    std::uint64_t va = 0;
                    if (cb.contains("va") && parse_u64_value(cb["va"], va) && va == buffer_va)
                    {
                        found_match = true;
                        break;
                    }
                }
                if (!found_match)
                    continue;
                if (cap.contains("registers") && cap["registers"].contains("rcx"))
                {
                    std::uint64_t rcx = 0;
                    if (parse_u64_value(cap["registers"]["rcx"], rcx) && rcx != 0)
                    {
                        device_context_va = rcx;
                        break;
                    }
                }
            }
            if (device_context_va != 0)
                break;
        }
    }

    if (device_context_va == 0)
        return tool_result_t::error("'device_context_va' is required and could not be auto-detected from stored cbuffer captures. Provide the ID3D11DeviceContext* address explicitly.");

    remote_com_call_t com;
    com.pid = scope.pid();
    com.deadline_ms = mcp_standalone::current_call_deadline_ms();

    diag::log_tagged_fmt("dx_hook",
        "read_gpu_buffer enter pid=%u buffer_va=%s device_context_va=%s max_size=%llu detect_matrices=%d",
        scope.pid(),
        sa_format_address(buffer_va).c_str(),
        sa_format_address(device_context_va).c_str(),
        static_cast<unsigned long long>(max_size),
        detect_matrices ? 1 : 0);

    driver_bridge::memory_region_t buffer_region{};
    if (!query_region(scope.pid(), buffer_va, buffer_region) || !is_readable(buffer_region))
        return tool_result_t::error("buffer_va is not readable in target process (cannot read vtable).");

    const std::uint64_t buffer_get_desc_ptr = com.read_vtable_method(buffer_va, 10);
    if (buffer_get_desc_ptr == 0)
        return tool_result_t::error("Failed to read ID3D11Buffer::GetDesc vtable slot: " + com.error);

    const std::uint64_t buffer_get_device_ptr = com.read_vtable_method(buffer_va, 3);
    if (buffer_get_device_ptr == 0)
        return tool_result_t::error("Failed to read ID3D11Buffer::GetDevice vtable slot: " + com.error);

    constexpr std::size_t kBufferDescSize = 24;
    const std::uint64_t desc_va = com.alloc(kBufferDescSize);
    if (desc_va == 0)
        return tool_result_t::error("Failed to allocate target memory for D3D11_BUFFER_DESC: " + com.error);

    com.call_com_method(buffer_get_desc_ptr, buffer_va, desc_va);
    if (!com.error.empty())
    {
        driver_bridge::free_memory_for(scope.pid(), desc_va);
        return tool_result_t::error("ID3D11Buffer::GetDesc failed: " + com.error);
    }

    std::vector<std::uint8_t> desc_bytes;
    if (!com.read_bytes_at(desc_va, kBufferDescSize, desc_bytes))
    {
        driver_bridge::free_memory_for(scope.pid(), desc_va);
        return tool_result_t::error("Failed to read D3D11_BUFFER_DESC from target: " + com.error);
    }
    driver_bridge::free_memory_for(scope.pid(), desc_va);

    std::uint32_t byte_width = 0;
    std::uint32_t usage = 0;
    std::uint32_t bind_flags = 0;
    std::uint32_t cpu_access_flags = 0;
    std::uint32_t misc_flags = 0;
    std::uint32_t structure_byte_stride = 0;
    std::memcpy(&byte_width, desc_bytes.data() + 0, 4);
    std::memcpy(&usage, desc_bytes.data() + 4, 4);
    std::memcpy(&bind_flags, desc_bytes.data() + 8, 4);
    std::memcpy(&cpu_access_flags, desc_bytes.data() + 12, 4);
    std::memcpy(&misc_flags, desc_bytes.data() + 16, 4);
    std::memcpy(&structure_byte_stride, desc_bytes.data() + 20, 4);

    if (byte_width == 0)
        return tool_result_t::error("ID3D11Buffer::GetDesc returned ByteWidth=0.");

    std::uint64_t read_size = byte_width;
    if (read_size > max_size)
        read_size = max_size;

    diag::log_tagged_fmt("dx_hook",
        "read_gpu_buffer desc pid=%u byte_width=%u usage=%u bind_flags=0x%X cpu_access=0x%X misc=0x%X stride=%u read_size=%llu",
        scope.pid(),
        byte_width,
        usage,
        bind_flags,
        cpu_access_flags,
        misc_flags,
        structure_byte_stride,
        static_cast<unsigned long long>(read_size));

    const std::uint64_t context_get_device_ptr = com.read_vtable_method(device_context_va, 3);
    if (context_get_device_ptr == 0)
        return tool_result_t::error("Failed to read ID3D11DeviceContext::GetDevice vtable slot: " + com.error);

    const std::uint64_t device_out_va = com.alloc(8);
    if (device_out_va == 0)
        return tool_result_t::error("Failed to allocate target memory for device out-param: " + com.error);

    com.call_com_method(context_get_device_ptr, device_context_va, device_out_va);
    if (!com.error.empty())
    {
        driver_bridge::free_memory_for(scope.pid(), device_out_va);
        return tool_result_t::error("ID3D11DeviceContext::GetDevice failed: " + com.error);
    }

    const std::uint64_t device_va = com.read_u64_at(device_out_va);
    driver_bridge::free_memory_for(scope.pid(), device_out_va);
    if (device_va == 0)
        return tool_result_t::error("ID3D11DeviceContext::GetDevice returned null device pointer.");

    diag::log_tagged_fmt("dx_hook",
        "read_gpu_buffer device_resolved pid=%u device_va=%s",
        scope.pid(),
        sa_format_address(device_va).c_str());

    const std::uint64_t create_buffer_ptr = com.read_vtable_method(device_va, 3);
    if (create_buffer_ptr == 0)
        return tool_result_t::error("Failed to read ID3D11Device::CreateBuffer vtable slot: " + com.error);

    std::vector<std::uint8_t> staging_desc(kBufferDescSize, 0);
    {
        const std::uint32_t staging_byte_width = static_cast<std::uint32_t>(read_size);
        const std::uint32_t staging_usage = 3;
        const std::uint32_t staging_bind = 0;
        const std::uint32_t staging_cpu = 0x8000;
        const std::uint32_t staging_misc = 0;
        const std::uint32_t staging_stride = 0;
        std::memcpy(staging_desc.data() + 0, &staging_byte_width, 4);
        std::memcpy(staging_desc.data() + 4, &staging_usage, 4);
        std::memcpy(staging_desc.data() + 8, &staging_bind, 4);
        std::memcpy(staging_desc.data() + 12, &staging_cpu, 4);
        std::memcpy(staging_desc.data() + 16, &staging_misc, 4);
        std::memcpy(staging_desc.data() + 20, &staging_stride, 4);
    }

    const std::uint64_t staging_desc_va = com.alloc_and_write(staging_desc);
    if (staging_desc_va == 0)
        return tool_result_t::error("Failed to allocate/write staging D3D11_BUFFER_DESC: " + com.error);

    const std::uint64_t staging_out_va = com.alloc(8);
    if (staging_out_va == 0)
    {
        driver_bridge::free_memory_for(scope.pid(), staging_desc_va);
        return tool_result_t::error("Failed to allocate target memory for staging out-param: " + com.error);
    }

    const std::uint64_t create_hr = com.call_com_method(create_buffer_ptr, device_va, staging_desc_va, 0, staging_out_va);
    driver_bridge::free_memory_for(scope.pid(), staging_desc_va);

    std::uint64_t staging_buffer_va = 0;
    if (com.error.empty())
        staging_buffer_va = com.read_u64_at(staging_out_va);
    driver_bridge::free_memory_for(scope.pid(), staging_out_va);

    if (!com.error.empty())
        return tool_result_t::error("ID3D11Device::CreateBuffer failed: " + com.error);

    if (staging_buffer_va == 0)
    {
        std::ostringstream hs;
        hs << "0x" << std::hex << static_cast<std::uint32_t>(create_hr);
        return tool_result_t::error("ID3D11Device::CreateBuffer returned null staging buffer. HRESULT=" + hs.str());
    }

    diag::log_tagged_fmt("dx_hook",
        "read_gpu_buffer staging_created pid=%u staging_buffer_va=%s",
        scope.pid(),
        sa_format_address(staging_buffer_va).c_str());

    auto release_staging = [&]() {
        if (staging_buffer_va == 0 || !com.target_alive())
            return;
        const std::uint64_t r = com.read_vtable_method(staging_buffer_va, 2);
        com.error.clear();
        if (r != 0)
            com.call_com_method(r, staging_buffer_va);
        com.error.clear();
    };

    const std::uint64_t copy_resource_ptr = com.read_vtable_method(device_context_va, 44);
    if (copy_resource_ptr == 0)
    {
        release_staging();
        return tool_result_t::error("Failed to read ID3D11DeviceContext::CopyResource vtable slot: " + com.error);
    }

    com.call_com_method(copy_resource_ptr, device_context_va, staging_buffer_va, buffer_va);
    if (!com.error.empty())
    {
        release_staging();
        return tool_result_t::error("ID3D11DeviceContext::CopyResource failed: " + com.error);
    }

    const std::uint64_t map_ptr = com.read_vtable_method(device_context_va, 57);
    if (map_ptr == 0)
    {
        release_staging();
        return tool_result_t::error("Failed to read ID3D11DeviceContext::Map vtable slot: " + com.error);
    }

    constexpr std::size_t kMappedSubresourceSize = 16;
    const std::uint64_t mapped_va = com.alloc(kMappedSubresourceSize);
    if (mapped_va == 0)
    {
        release_staging();
        return tool_result_t::error("Failed to allocate target memory for D3D11_MAPPED_SUBRESOURCE: " + com.error);
    }

    const std::uint64_t map_hr = com.call_com_method_6(map_ptr, device_context_va, staging_buffer_va, 0, 1, 0, mapped_va);
    if (!com.error.empty())
    {
        driver_bridge::free_memory_for(scope.pid(), mapped_va);
        release_staging();
        return tool_result_t::error("ID3D11DeviceContext::Map failed: " + com.error);
    }

    const std::int32_t map_hr32 = static_cast<std::int32_t>(map_hr & 0xFFFFFFFFull);
    if (map_hr32 < 0)
    {
        driver_bridge::free_memory_for(scope.pid(), mapped_va);
        release_staging();
        std::ostringstream hs;
        hs << "0x" << std::hex << static_cast<std::uint32_t>(map_hr);
        return tool_result_t::error("ID3D11DeviceContext::Map returned failure HRESULT=" + hs.str());
    }

    std::vector<std::uint8_t> mapped_bytes;
    if (!com.read_bytes_at(mapped_va, kMappedSubresourceSize, mapped_bytes))
    {
        if (com.target_alive())
        {
            const std::uint64_t unmap_ptr = com.read_vtable_method(device_context_va, 58);
            com.error.clear();
            if (unmap_ptr != 0)
                com.call_com_method(unmap_ptr, device_context_va, staging_buffer_va, 0);
            com.error.clear();
        }
        driver_bridge::free_memory_for(scope.pid(), mapped_va);
        release_staging();
        return tool_result_t::error("Failed to read D3D11_MAPPED_SUBRESOURCE from target: " + com.error);
    }
    driver_bridge::free_memory_for(scope.pid(), mapped_va);

    std::uint64_t mapped_data_ptr = 0;
    std::uint32_t row_pitch = 0;
    std::uint32_t depth_pitch = 0;
    std::memcpy(&mapped_data_ptr, mapped_bytes.data() + 0, 8);
    std::memcpy(&row_pitch, mapped_bytes.data() + 8, 4);
    std::memcpy(&depth_pitch, mapped_bytes.data() + 12, 4);

    if (mapped_data_ptr == 0)
    {
        if (com.target_alive())
        {
            const std::uint64_t unmap_ptr = com.read_vtable_method(device_context_va, 58);
            com.error.clear();
            if (unmap_ptr != 0)
                com.call_com_method(unmap_ptr, device_context_va, staging_buffer_va, 0);
            com.error.clear();
        }
        release_staging();
        return tool_result_t::error("ID3D11DeviceContext::Map succeeded but pData is null.");
    }

    diag::log_tagged_fmt("dx_hook",
        "read_gpu_buffer mapped pid=%u pData=%s row_pitch=%u depth_pitch=%u",
        scope.pid(),
        sa_format_address(mapped_data_ptr).c_str(),
        row_pitch,
        depth_pitch);

    std::vector<std::uint8_t> buffer_data;
    if (!com.read_bytes_at(mapped_data_ptr, static_cast<std::size_t>(read_size), buffer_data))
    {
        if (com.target_alive())
        {
            const std::uint64_t unmap_ptr = com.read_vtable_method(device_context_va, 58);
            com.error.clear();
            if (unmap_ptr != 0)
                com.call_com_method(unmap_ptr, device_context_va, staging_buffer_va, 0);
            com.error.clear();
        }
        release_staging();
        return tool_result_t::error("Failed to read mapped buffer data from target: " + com.error);
    }

    if (com.target_alive())
    {
        const std::uint64_t unmap_ptr = com.read_vtable_method(device_context_va, 58);
        com.error.clear();
        if (unmap_ptr != 0)
            com.call_com_method(unmap_ptr, device_context_va, staging_buffer_va, 0);
        com.error.clear();
    }

    release_staging();

    json result;
    result["process_id"] = scope.pid();
    result["buffer_va"] = sa_format_address(buffer_va);
    result["device_context_va"] = sa_format_address(device_context_va);
    result["device_va"] = sa_format_address(device_va);
    result["staging_buffer_va"] = sa_format_address(staging_buffer_va);
    result["buffer_desc"] = {
        {"byte_width", byte_width},
        {"usage", usage},
        {"bind_flags", bind_flags},
        {"cpu_access_flags", cpu_access_flags},
        {"misc_flags", misc_flags},
        {"structure_byte_stride", structure_byte_stride}
    };
    result["mapped_subresource"] = {
        {"data_va", sa_format_address(mapped_data_ptr)},
        {"row_pitch", row_pitch},
        {"depth_pitch", depth_pitch}
    };
    result["bytes_read"] = buffer_data.size();
    result["read_size"] = read_size;
    result["truncated"] = read_size < static_cast<std::uint64_t>(byte_width);
    result["com_call_count"] = com.call_count;
    result["data_hex"] = bytes_to_hex(buffer_data, 4096);
    result["preview_floats"] = preview_floats(buffer_data);

    if (detect_matrices && !buffer_data.empty())
    {
        matrix_decode_result_t decoded = best_matrix_decode_run(buffer_data, 1000000.0, 256, buffer_data.size());
        result["matrix_detection"] = {
            {"count", decoded.count},
            {"stride", decoded.stride},
            {"offset", decoded.offset},
            {"xor_key", decoded.xor_key},
            {"decode", decoded.decode},
            {"format", bone_format_name(decoded.format)}
        };
    }

    result["elapsed_ms"] = GetTickCount64() - started_ms;
    result["target_alive_after_readback"] = com.target_alive();

    diag::log_tagged_fmt("dx_hook",
        "read_gpu_buffer done pid=%u bytes_read=%zu com_calls=%zu elapsed_ms=%llu target_alive=%d",
        scope.pid(),
        buffer_data.size(),
        com.call_count,
        static_cast<unsigned long long>(GetTickCount64() - started_ms),
        com.target_alive() ? 1 : 0);

    return tool_result_t::ok("GPU buffer readback completed via remote COM method invocation.", result);
}

tool_result_t correlate_results(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t view_matrix_va = 0;
    std::uint64_t bone_buffer_va = 0;
    parse_address_param(params, "view_matrix_va", view_matrix_va);
    parse_address_param(params, "bone_buffer_va", bone_buffer_va);

    if (view_matrix_va == 0 && bone_buffer_va == 0)
        return tool_result_t::error("At least one of view_matrix_va or bone_buffer_va is required.");

    json result;
    result["process_id"] = scope.pid();
    result["view_matrix_va"] = view_matrix_va ? json(sa_format_address(view_matrix_va)) : json(nullptr);
    result["bone_buffer_va"] = bone_buffer_va ? json(sa_format_address(bone_buffer_va)) : json(nullptr);

    auto batches = store::list_frame_batches(scope.pid());
    json frame_matches = json::array();

    for (const auto& batch : batches)
    {
        bool has_view = false, has_bone = false;
        for (const auto& [va, slot] : batch.cbuffer_binds)
        {
            if (va == view_matrix_va) has_view = true;
            if (va == bone_buffer_va) has_bone = true;
        }
        if ((view_matrix_va == 0 || has_view) && (bone_buffer_va == 0 || has_bone))
        {
            json match;
            match["frame_index"] = batch.frame_index;
            match["start_timestamp_ms"] = batch.start_timestamp_ms;
            match["end_timestamp_ms"] = batch.end_timestamp_ms;
            match["total_draw_count"] = batch.total_draw_count;
            match["character_draw_count"] = batch.character_draw_count;
            match["view_matrix_present"] = has_view;
            match["bone_buffer_present"] = has_bone;
            json draws = json::array();
            for (const auto& dc : batch.draw_calls)
            {
                json d;
                d["draw_kind"] = dc.draw_kind;
                d["index_count"] = dc.index_count;
                d["vertex_count"] = dc.vertex_count;
                d["likely_mesh_type"] = dc.likely_mesh_type;
                d["preceding_cbuffer_va"] = dc.preceding_cbuffer_va ? json(sa_format_address(dc.preceding_cbuffer_va)) : json(nullptr);
                d["preceding_cbuffer_slot"] = dc.preceding_cbuffer_slot;
                draws.push_back(std::move(d));
            }
            match["draw_calls"] = std::move(draws);
            frame_matches.push_back(std::move(match));
        }
    }

    result["matching_frames"] = std::move(frame_matches);
    result["matching_frame_count"] = result["matching_frames"].size();
    result["same_frame"] = result["matching_frame_count"].get<std::size_t>() > 0;
    result["correlation_strength"] = "none";
    if (result["matching_frame_count"].get<std::size_t>() > 0)
    {
        const auto count = result["matching_frame_count"].get<std::size_t>();
        if (count >= 3) result["correlation_strength"] = "strong";
        else if (count >= 1) result["correlation_strength"] = "moderate";
    }

    auto hot_vas = store::list_hot_vas(scope.pid());
    for (const auto& hv : hot_vas)
    {
        if (hv.va == view_matrix_va || hv.va == bone_buffer_va)
        {
            result["hot_va_evidence"] = hot_va_to_json(hv);
            break;
        }
    }

    return tool_result_t::ok("Cross-tool correlation complete.", result);
}

tool_result_t get_frame_summary(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    auto batches = store::list_frame_batches(scope.pid());
    if (batches.empty())
    {
        json result;
        result["process_id"] = scope.pid();
        result["frame_count"] = 0;
        result["failure_reason"] = "no_frame_batches_captured";
        result["hint"] = "Arm a Present HWBP plus draw/cbuffer HWBPs to capture frame batches";
        return tool_result_t::ok("No frame batches captured yet.", result);
    }

    const std::uint32_t requested_frame = static_cast<std::uint32_t>(numeric_param(params, "frame_index", 0, 0, batches.size()));
    const bool latest = bool_param(params, "latest", true);

    const auto& batch = latest ? batches.back() : batches[std::min<std::size_t>(requested_frame, batches.size() - 1)];

    json result = frame_batch_to_json(batch);
    result["process_id"] = scope.pid();
    result["frame_count"] = batches.size();
    result["latest"] = latest;

    auto classifications = classify_cbuffers(scope.pid());
    json class_json = json::array();
    for (const auto& cc : classifications)
        class_json.push_back(cbuffer_classification_to_json(cc));
    result["cbuffer_classifications"] = std::move(class_json);

    auto hot_vas = store::list_hot_vas(scope.pid());
    json hot_json = json::array();
    for (const auto& hv : hot_vas)
        hot_json.push_back(hot_va_to_json(hv));
    result["hot_vas"] = std::move(hot_json);

    return tool_result_t::ok("Frame summary retrieved.", result);
}

tool_result_t auto_narrow(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    const std::uint32_t capture_frames = static_cast<std::uint32_t>(numeric_param(params, "capture_frames", 3, 1, 10));
    const double world_max = number_param(params, "world_unit_max", 1000000.0, 1.0, 1000000000.0);
    const std::uint32_t min_bones = static_cast<std::uint32_t>(numeric_param(params, "min_bones", 4, 1, 1024));
    const std::uint32_t max_bones = static_cast<std::uint32_t>(numeric_param(params, "max_bones", 256, min_bones, 4096));
    const std::string api = api_param(params);

    if (!unsafe_confirmed(params))
        return unsafe_required("dx_auto_narrow");

    if (!driver_bridge::using_kernel_driver())
    {
        json result;
        result["process_id"] = scope.pid();
        result["capability"] = {{"available", false}, {"reason", "kernel driver required for auto_narrow"}};
        return tool_result_t::error("DX kernel-context backend is unavailable.", result);
    }

    for (const auto& record : store::list_dx_hooks(scope.pid()))
    {
        for (auto tid : record.tids)
            driver_bridge::clear_hardware_breakpoint(tid, record.hw_slot);
    }
    store::remove_dx_hooks(scope.pid());
    stop_dx_debug_loop(scope.pid());
    store::clear_frame_batches(scope.pid());
    store::clear_hot_vas(scope.pid());
    store::clear_cbuffer_classifications(scope.pid());

    auto slots = discover_api(scope.pid(), api, true);
    std::optional<slot_entry_t> present_target, draw_target, cbuffer_target;
    for (const auto& s : slots)
    {
        if (s.target_va == 0 || !s.validated) continue;
        if (s.role == "present" && !present_target) present_target = s;
        if (s.role == "draw" && !draw_target)
        {
            if (s.name == "DrawIndexed" || s.name == "Draw" || s.name == "DrawInstanced" || s.name == "DrawIndexedInstanced")
                draw_target = s;
        }
        if (s.role == "cbuffer_bind" && !cbuffer_target)
        {
            if (s.name == "VSSetConstantBuffers")
                cbuffer_target = s;
        }
    }
    if (!draw_target)
    {
        for (const auto& s : slots)
        {
            if (s.target_va == 0 || !s.validated) continue;
            if (s.role == "draw" && !draw_target) draw_target = s;
        }
    }
    if (!cbuffer_target)
    {
        for (const auto& s : slots)
        {
            if (s.target_va == 0 || !s.validated) continue;
            if (s.role == "cbuffer_bind" && !cbuffer_target) cbuffer_target = s;
        }
    }
    if (!present_target)
    {
        auto present_slots = discover_dxgi_present(scope.pid(), true);
        if (!present_slots.empty())
            present_target = present_slots[0];
    }

    if (!present_target || !draw_target || !cbuffer_target)
    {
        json result;
        result["process_id"] = scope.pid();
        result["resolved_targets"] = {
            {"present", present_target ? json(sa_format_address(present_target->target_va)) : json(nullptr)},
            {"draw", draw_target ? json(sa_format_address(draw_target->target_va)) : json(nullptr)},
            {"cbuffer_bind", cbuffer_target ? json(sa_format_address(cbuffer_target->target_va)) : json(nullptr)}
        };
        result["failure_reason"] = "could_not_resolve_all_three_targets";
        return tool_result_t::error("Auto-narrow requires Present, Draw, and CBufferBind targets.", result);
    }

    std::vector<store::dx_hook_record_t> prepared;
    auto arm = [&](const slot_entry_t& target, const std::string& act, int hw_slot) {
        store::dx_hook_record_t rec;
        rec.id = store::next_id("dx");
        rec.pid = scope.pid();
        rec.api = api == "auto" ? target.module_name : api;
        rec.action = act;
        rec.target_va = target.target_va;
        rec.target_name = target.name;
        rec.hw_slot = hw_slot;
        rec.capture_cbuffers = (act == "cbuffer_bind");
        rec.max_captures = 64;
        rec.created_ms = unix_time_ms();
        for (const auto& th : threads_for(scope.pid()))
            if (driver_bridge::set_hardware_breakpoint(th.tid, hw_slot, target.target_va, 0, 0))
                rec.tids.push_back(th.tid);
        return rec;
    };

    auto present_rec = arm(*present_target, "present", 0);
    auto draw_rec = arm(*draw_target, "draw", 1);
    auto cbuffer_rec = arm(*cbuffer_target, "cbuffer_bind", 2);

    if (present_rec.tids.empty() || draw_rec.tids.empty() || cbuffer_rec.tids.empty())
    {
        clear_dx_record_breakpoints({present_rec, draw_rec, cbuffer_rec});
        json result;
        result["process_id"] = scope.pid();
        result["failure_reason"] = "hwbp_arming_failed";
        return tool_result_t::error("Could not arm all 3 HWBPs.", result);
    }

    prepared = {present_rec, draw_rec, cbuffer_rec};
    for (const auto& r : prepared) store::add_dx_hook(r);

    frame_tracking_state().enabled.store(true, std::memory_order_release);
    frame_tracking_state().frame_start_ms.store(unix_time_ms(), std::memory_order_release);
    frame_tracking_state().current_frame.store(0, std::memory_order_release);
    frame_tracking_state().current_draw_ordinal.store(0, std::memory_order_release);

    std::string debug_error;
    if (!start_dx_debug_loop(scope.pid(), debug_error))
    {
        for (const auto& r : prepared) { clear_dx_record_breakpoints(r); store::remove_dx_hook(r.id); }
        json result;
        result["process_id"] = scope.pid();
        result["failure_reason"] = debug_error;
        return tool_result_t::error("Debug loop failed to start.", result);
    }

    if (dx_call_cancelled("auto_narrow_post_debug_start", scope.pid(), started_ms))
    {
        stop_dx_debug_loop(scope.pid());
        for (const auto& r : prepared) clear_dx_record_breakpoints(r);
        frame_tracking_state().enabled.store(false, std::memory_order_release);
        json result;
        result["process_id"] = scope.pid();
        result["cancelled"] = true;
        return tool_result_t::error("Auto-narrow cancelled after debug loop start.", result);
    }

    const std::uint64_t frame_deadline_ms = started_ms + capture_frames * 2000ull + 5000ull;
    bool auto_narrow_cancelled = false;
    while (store::list_frame_batches(scope.pid()).size() < capture_frames)
    {
        if (GetTickCount64() > frame_deadline_ms)
            break;
        if (dx_call_cancelled("auto_narrow_frame_capture", scope.pid(), started_ms))
        {
            auto_narrow_cancelled = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    stop_dx_debug_loop(scope.pid());
    for (const auto& r : prepared) clear_dx_record_breakpoints(r);
    frame_tracking_state().enabled.store(false, std::memory_order_release);

    if (auto_narrow_cancelled)
    {
        json result;
        result["process_id"] = scope.pid();
        result["captured_frames"] = store::list_frame_batches(scope.pid()).size();
        result["cancelled"] = true;
        return tool_result_t::error("Auto-narrow cancelled during frame capture.", result);
    }

    if (dx_call_cancelled("auto_narrow_post_capture", scope.pid(), started_ms))
    {
        json result;
        result["process_id"] = scope.pid();
        result["captured_frames"] = store::list_frame_batches(scope.pid()).size();
        result["cancelled"] = true;
        return tool_result_t::error("Auto-narrow cancelled after frame capture.", result);
    }

    auto batches = store::list_frame_batches(scope.pid());
    if (batches.empty())
    {
        json result;
        result["process_id"] = scope.pid();
        result["captured_frames"] = 0;
        result["failure_reason"] = "no_frames_captured_within_timeout";
        return tool_result_t::error("Auto-narrow captured no frames within timeout.", result);
    }

    auto classifications = classify_cbuffers(scope.pid());
    for (auto& cc : classifications)
    {
        cc.pid = scope.pid();
        store::add_cbuffer_classification(cc);
    }

    json view_matrix_candidates = json::array();
    std::size_t vm_eval_count = 0;
    for (const auto& cc : classifications)
    {
        if (cc.classification != store::cbuffer_class_t::persistent)
            continue;
        if ((++vm_eval_count & 0x7u) == 0 && dx_call_cancelled("auto_narrow_vm_eval", scope.pid(), started_ms))
        {
            json result;
            result["process_id"] = scope.pid();
            result["captured_frames"] = batches.size();
            result["cancelled"] = true;
            result["view_matrix_candidates"] = std::move(view_matrix_candidates);
            return tool_result_t::error("Auto-narrow cancelled during view matrix evaluation.", result);
        }

        std::vector<std::uint8_t> bytes;
        if (!read_bytes(scope.pid(), cc.va, 64, bytes) || bytes.size() < 64)
            continue;

        float f[16] = {};
        std::memcpy(f, bytes.data(), 64);
        matrix_eval_t eval = evaluate_matrix4x4(f, world_max);
        if (!eval.plausible || eval.static_null_view)
            continue;

        auto hot_vas = store::list_hot_vas(scope.pid());
        auto hot_it = std::find_if(hot_vas.begin(), hot_vas.end(), [&](const store::hot_va_entry_t& e) { return e.va == cc.va; });

        double confidence = 0.50 + eval.score * 0.35;
        confidence += 0.18;
        confidence += cc.frequency_score * 0.10;
        if (hot_it != hot_vas.end()) confidence += hot_it->confidence_boost;
        confidence = std::min(0.98, std::max(0.0, confidence));

        json row;
        row["va"] = sa_format_address(cc.va);
        row["confidence"] = confidence;
        row["matrix_type"] = eval.type;
        row["matrix_orientation"] = eval.orientation;
        row["determinant3x3"] = eval.determinant;
        row["orthogonality_error"] = eval.orthogonality_error;
        row["classification"] = "persistent";
        row["frequency_score"] = cc.frequency_score;
        row["frames_seen"] = cc.frames_seen;
        row["preview_floats"] = preview_floats(bytes);
        row["source"] = "auto_narrow_persistent_cbuffer";
        if (hot_it != hot_vas.end())
        {
            row["hot_va_hit_count"] = hot_it->hit_count;
            row["hot_va_frame_count"] = hot_it->frame_count;
        }
        view_matrix_candidates.push_back(std::move(row));
    }

    json bone_buffer_candidates = json::array();
    std::size_t bb_eval_count = 0;
    for (const auto& cc : classifications)
    {
        if (cc.classification != store::cbuffer_class_t::per_draw)
            continue;
        if ((++bb_eval_count & 0x7u) == 0 && dx_call_cancelled("auto_narrow_bb_eval", scope.pid(), started_ms))
        {
            json result;
            result["process_id"] = scope.pid();
            result["captured_frames"] = batches.size();
            result["cancelled"] = true;
            result["view_matrix_candidates"] = std::move(view_matrix_candidates);
            result["bone_buffer_candidates"] = std::move(bone_buffer_candidates);
            return tool_result_t::error("Auto-narrow cancelled during bone buffer evaluation.", result);
        }

        driver_bridge::memory_region_t region{};
        if (!query_region(scope.pid(), cc.va, region))
            continue;
        std::uint64_t size = region.base + region.size - cc.va;
        if (size < 64ull * min_bones)
            continue;

        std::vector<std::uint8_t> bytes;
        const std::size_t read_size = static_cast<std::size_t>(std::min<std::uint64_t>(size, std::max<std::uint64_t>(64ull * max_bones + 256ull, 8192ull)));
        if (!read_bytes(scope.pid(), cc.va, read_size, bytes) || bytes.size() < 48ull * min_bones)
            continue;

        matrix_decode_result_t decoded = best_matrix_decode_run(bytes, world_max, max_bones, 512);
        if (decoded.count < min_bones)
            continue;

        auto hot_vas = store::list_hot_vas(scope.pid());
        auto hot_it = std::find_if(hot_vas.begin(), hot_vas.end(), [&](const store::hot_va_entry_t& e) { return e.va == cc.va; });

        double confidence = 0.40 + static_cast<double>(decoded.count) / static_cast<double>(std::max<std::uint32_t>(max_bones, 1)) * 0.42;
        confidence += 0.18;
        confidence += cc.frequency_score * 0.05;
        if (hot_it != hot_vas.end()) confidence += hot_it->confidence_boost;
        if (decoded.decode == "xor32_float32") confidence += 0.06;
        confidence = std::min(0.99, std::max(0.0, confidence));

        json row;
        row["va"] = sa_format_address(cc.va + decoded.offset);
        row["base_va"] = sa_format_address(cc.va);
        row["confidence"] = confidence;
        row["bone_count"] = decoded.count;
        row["matrix_size"] = decoded.stride;
        row["decode"] = decoded.decode;
        row["classification"] = "per_draw";
        row["frequency_score"] = cc.frequency_score;
        row["frames_seen"] = cc.frames_seen;
        row["associated_draw_count"] = cc.associated_draw_calls.size();
        row["source"] = "auto_narrow_per_draw_cbuffer";
        if (!cc.associated_draw_calls.empty())
        {
            const auto& dc = cc.associated_draw_calls.front();
            row["sample_draw_call"] = {
                {"draw_kind", dc.draw_kind},
                {"index_count", dc.index_count},
                {"vertex_count", dc.vertex_count},
                {"likely_mesh_type", dc.likely_mesh_type}
            };
        }
        bone_buffer_candidates.push_back(std::move(row));
    }

    std::sort(view_matrix_candidates.begin(), view_matrix_candidates.end(), [](const json& a, const json& b) {
        return a["confidence"].get<double>() > b["confidence"].get<double>();
    });
    std::sort(bone_buffer_candidates.begin(), bone_buffer_candidates.end(), [](const json& a, const json& b) {
        return a["confidence"].get<double>() > b["confidence"].get<double>();
    });

    json result;
    result["process_id"] = scope.pid();
    result["captured_frames"] = batches.size();
    result["capture_elapsed_ms"] = static_cast<unsigned long long>(GetTickCount64() - started_ms);

    json frame_summaries = json::array();
    for (const auto& batch : batches)
    {
        json fs;
        fs["frame_index"] = batch.frame_index;
        fs["total_draws"] = batch.total_draw_count;
        fs["character_draws"] = batch.character_draw_count;
        fs["weapon_draws"] = batch.weapon_draw_count;
        fs["world_draws"] = batch.world_draw_count;
        fs["cbuffer_bind_count"] = batch.cbuffer_binds.size();
        frame_summaries.push_back(std::move(fs));
    }
    result["frame_summaries"] = std::move(frame_summaries);

    json class_json = json::array();
    for (const auto& cc : classifications)
        class_json.push_back(cbuffer_classification_to_json(cc));
    result["cbuffer_classifications"] = std::move(class_json);

    result["view_matrix_candidates"] = std::move(view_matrix_candidates);
    result["view_matrix_candidate_count"] = result["view_matrix_candidates"].size();
    result["best_view_matrix"] = result["view_matrix_candidates"].empty() ? json(nullptr) : result["view_matrix_candidates"][0];

    result["bone_buffer_candidates"] = std::move(bone_buffer_candidates);
    result["bone_buffer_candidate_count"] = result["bone_buffer_candidates"].size();
    result["best_bone_buffer"] = result["bone_buffer_candidates"].empty() ? json(nullptr) : result["bone_buffer_candidates"][0];

    if (!result["view_matrix_candidates"].empty())
    {
        result["view_matrix_candidates"][0]["next_action"] = "dx_correlate_results";
        result["view_matrix_candidates"][0]["next_action_params"] = json::object({
            {"process_id", scope.pid()},
            {"view_matrix_va", result["view_matrix_candidates"][0]["va"]}
        });
    }
    if (!result["bone_buffer_candidates"].empty())
    {
        result["bone_buffer_candidates"][0]["next_action"] = "dx_correlate_results";
        result["bone_buffer_candidates"][0]["next_action_params"] = json::object({
            {"process_id", scope.pid()},
            {"bone_buffer_va", result["bone_buffer_candidates"][0]["va"]}
        });
    }

    result["found"] = !result["view_matrix_candidates"].empty() || !result["bone_buffer_candidates"].empty();
    result["summary"] = "Auto-narrow complete: " + std::to_string(batches.size()) + " frames, " +
                        std::to_string(result["view_matrix_candidate_count"].get<std::size_t>()) + " view matrix candidates, " +
                        std::to_string(result["bone_buffer_candidate_count"].get<std::size_t>()) + " bone buffer candidates";

    diag::log_tagged_fmt("dx_hook", "auto_narrow exit pid=%u frames=%zu vm_candidates=%zu bb_candidates=%zu elapsed_ms=%llu",
                         scope.pid(), batches.size(),
                         result["view_matrix_candidate_count"].get<std::size_t>(),
                         result["bone_buffer_candidate_count"].get<std::size_t>(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));

    return tool_result_t::ok(result["summary"].get<std::string>(), result);
}
}
