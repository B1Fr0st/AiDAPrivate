#include "dx_hook.hpp"

#include "artifact_store.hpp"
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
    bool target_executable = false;
    bool validated = false;
};

using pfn_d3d11_create_device_t = HRESULT(WINAPI*)(IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT, UINT, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
using pfn_d3d11_create_device_and_swap_chain_t = HRESULT(WINAPI*)(IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT, UINT, const DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
using pfn_d3d12_create_device_t = HRESULT(WINAPI*)(IUnknown*, D3D_FEATURE_LEVEL, REFIID, void**);

std::string api_param(const json& params)
{
    std::string api = lower_ascii(string_param(params, "api", "auto"));
    if (api.empty())
        api = "auto";
    return api;
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
    entry.local_prologue = local_prologue_hint(entry.local_va);
    entry.hint = entry.local_prologue;
    if (entry.target_va == 0)
    {
        entry.validated = false;
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
    std::vector<std::uint8_t> bytes;
    diag::log_tagged_fmt("dx_hook", "finalize_slot read_begin pid=%u name=%s target_va=%s bytes=16",
                         pid,
                         entry.name.c_str(),
                         sa_format_address(entry.target_va).c_str());
    if (read_bytes(pid, entry.target_va, 16, bytes) && !bytes.empty())
    {
        entry.target_bytes = bytes_to_hex(bytes, 16);
        AsmInstr ins = zydis_decode_one(bytes.data(), static_cast<int>(std::min<std::size_t>(bytes.size(), 16)), entry.target_va);
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
    entry.validated = entry.target_executable && !entry.target_bytes.empty() && entry.target_prologue.find("unknown:") != 0;
    diag::log_tagged_fmt("dx_hook", "finalize_slot exit pid=%u name=%s slot=%u target_va=%s target_rva=%s executable=%d validated=%d elapsed_ms=%llu",
                         pid,
                         entry.name.c_str(),
                         entry.slot,
                         sa_format_address(entry.target_va).c_str(),
                         entry.target_rva ? sa_format_address(entry.target_rva).c_str() : "0x0",
                         entry.target_executable ? 1 : 0,
                         entry.validated ? 1 : 0,
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
    obj["evidence"] = {
        {"dummy_vtable_slot", slot.slot},
        {"local_va", slot.local_va ? json(sa_format_address(slot.local_va)) : json(nullptr)},
        {"target_va", slot.target_va ? json(sa_format_address(slot.target_va)) : json(nullptr)},
        {"target_module", slot.module_name},
        {"target_rva", slot.target_rva ? json(sa_format_address(slot.target_rva)) : json(nullptr)},
        {"target_executable_region", slot.target_executable},
        {"target_first_instruction", slot.target_prologue},
        {"target_first_16_bytes", slot.target_bytes}
    };
    map[slot.name] = std::move(obj);
}

std::map<std::string, std::uint32_t> d3d11_context_slots()
{
    return {
        {"VSSetConstantBuffers", 7},
        {"DrawIndexed", 12},
        {"DrawIndexedInstanced", 14},
        {"PSSetShaderResources", 25},
        {"IASetVertexBuffers", 54}
    };
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
            slot_entry_t entry;
            entry.name = name;
            entry.slot = index;
            entry.local_va = vtable[index];
            entry.module_name = "d3d11.dll";
            diag::log_tagged_fmt("dx_hook", "discover_d3d11_live slot_begin pid=%u name=%s index=%u local_va=%s",
                                 pid,
                                 entry.name.c_str(),
                                 entry.slot,
                                 sa_format_address(entry.local_va).c_str());
            entry.target_va = map_local_to_target(pid, "d3d11.dll", entry.local_va, false);
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
        slot_entry_t entry;
        entry.name = name;
        entry.slot = index;
        entry.local_va = vtable[index];
        diag::log_tagged_fmt("dx_hook", "discover_d3d11 dummy_slot_begin pid=%u name=%s index=%u local_va=%s",
                             pid,
                             entry.name.c_str(),
                             entry.slot,
                             sa_format_address(entry.local_va).c_str());
        entry.target_va = map_local_to_target(pid, "d3d11.dll", entry.local_va);
        entry.module_name = "d3d11.dll";
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

std::vector<slot_entry_t> discover_d3d12(std::uint32_t pid)
{
    std::vector<slot_entry_t> slots;
    HMODULE d3d12 = LoadLibraryA("d3d12.dll");
    if (!d3d12)
        return slots;
    auto create_device = reinterpret_cast<pfn_d3d12_create_device_t>(GetProcAddress(d3d12, "D3D12CreateDevice"));
    if (!create_device)
        return slots;
    ID3D12Device* device = nullptr;
    HRESULT hr = create_device(nullptr, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), reinterpret_cast<void**>(&device));
    if (FAILED(hr) || !device)
        return slots;
    ID3D12CommandAllocator* alloc = nullptr;
    ID3D12GraphicsCommandList* list = nullptr;
    hr = device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, __uuidof(ID3D12CommandAllocator), reinterpret_cast<void**>(&alloc));
    if (SUCCEEDED(hr) && alloc)
        hr = device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, alloc, nullptr, __uuidof(ID3D12GraphicsCommandList), reinterpret_cast<void**>(&list));
    if (SUCCEEDED(hr) && list)
    {
        auto vtable = *reinterpret_cast<std::uint64_t**>(list);
        std::map<std::string, std::uint32_t> wanted = {
            {"DrawInstanced", 12},
            {"DrawIndexedInstanced", 13},
            {"Dispatch", 14},
            {"SetGraphicsRootConstantBufferView", 27},
            {"SetGraphicsRoot32BitConstants", 29}
        };
        for (const auto& [name, index] : wanted)
        {
            slot_entry_t entry;
            entry.name = name;
            entry.slot = index;
            entry.local_va = vtable[index];
            entry.target_va = map_local_to_target(pid, "d3d12.dll", entry.local_va);
            entry.module_name = "d3d12.dll";
            finalize_slot(pid, entry);
            slots.push_back(std::move(entry));
        }
    }
    if (list) list->Release();
    if (alloc) alloc->Release();
    device->Release();
    return slots;
}

std::vector<slot_entry_t> discover_dxgi_present(std::uint32_t pid)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("dx_hook", "discover_dxgi_present enter pid=%u tid=%lu",
                         pid,
                         static_cast<unsigned long>(GetCurrentThreadId()));
    std::vector<slot_entry_t> slots;
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
                    entry.target_va = map_local_to_target(pid, "dxgi.dll", entry.local_va);
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

std::vector<slot_entry_t> discover_vulkan(std::uint32_t pid)
{
    std::vector<slot_entry_t> slots;
    HMODULE vulkan = LoadLibraryA("vulkan-1.dll");
    auto target = find_module_by_name(pid, "vulkan-1.dll");
    const char* names[] = {"vkQueuePresentKHR", "vkCmdDraw", "vkCmdDrawIndexed"};
    for (const char* name : names)
    {
        slot_entry_t entry;
        entry.name = name;
        entry.module_name = "vulkan-1.dll";
        entry.local_va = vulkan ? reinterpret_cast<std::uint64_t>(GetProcAddress(vulkan, name)) : 0;
        entry.target_va = entry.local_va != 0 ? map_local_to_target(pid, "vulkan-1.dll", entry.local_va) : 0;
        if (target)
            finalize_slot(pid, entry);
        else
            entry.hint = "vulkan_not_loaded_in_target";
        slots.push_back(std::move(entry));
    }
    return slots;
}

json slots_to_result(std::uint32_t pid, const std::string& api, const std::vector<slot_entry_t>& slots)
{
    json slot_map = json::object();
    for (const auto& slot : slots)
        push_slot(slot_map, slot);
    json result;
    result["process_id"] = pid;
    result["api"] = api;
    result["slot_map"] = std::move(slot_map);
    result["count"] = result["slot_map"].size();
    return result;
}

std::vector<slot_entry_t> discover_api(std::uint32_t pid, const std::string& api, bool allow_dummy_device = true)
{
    if (api == "d3d11") return discover_d3d11(pid, allow_dummy_device);
    if (api == "d3d12") return discover_d3d12(pid);
    if (api == "vulkan") return discover_vulkan(pid);
    std::vector<slot_entry_t> out;
    auto d3d11 = discover_d3d11(pid, allow_dummy_device);
    auto d3d12 = discover_d3d12(pid);
    auto vk = discover_vulkan(pid);
    out.insert(out.end(), d3d11.begin(), d3d11.end());
    out.insert(out.end(), d3d12.begin(), d3d12.end());
    out.insert(out.end(), vk.begin(), vk.end());
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
    const std::uint64_t target = driver_bridge::resolve_export(module->base, export_name.c_str());
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
    entry.name = "snapshot_marker::" + export_name;
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
    if (api == "vulkan")
        candidates.insert(candidates.begin(), {"vulkan-1.dll", "vkQueuePresentKHR"});
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
        auto present = discover_dxgi_present(pid);
        if (!present.empty() && present.front().target_va != 0)
        {
            diag::log_tagged_fmt("dx_hook", "choose_hook_target present_exact pid=%u api=%s target=%s elapsed_ms=%llu",
                                 pid,
                                 api.c_str(),
                                 sa_format_address(present.front().target_va).c_str(),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return present.front();
        }
    }
    auto slots = discover_api(pid, api);
    diag::log_tagged_fmt("dx_hook", "choose_hook_target slots pid=%u api=%s action=%s slots=%zu resolved=%zu elapsed_ms=%llu",
                         pid,
                         api.c_str(),
                         action.c_str(),
                         slots.size(),
                         resolved_slot_count(slots),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    for (const auto& slot : slots)
    {
        if (action == "draw" && (slot.name == "DrawIndexed" || slot.name == "DrawIndexedInstanced" || slot.name == "DrawIndexedInstanced"))
        {
            diag::log_tagged_fmt("dx_hook", "choose_hook_target draw_slot pid=%u name=%s target=%s elapsed_ms=%llu",
                                 pid,
                                 slot.name.c_str(),
                                 sa_format_address(slot.target_va).c_str(),
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return slot;
        }
        if (action == "present" && slot.name.find("Present") != std::string::npos)
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
    out["captures"] = record.captures;
    return out;
}

bool plausible_matrix4x4(const float* f, double world_max)
{
    if (!std::isfinite(f[0]) || !std::isfinite(f[5]) || !std::isfinite(f[10]) || !std::isfinite(f[15]))
        return false;
    const float r0 = std::sqrt(f[0] * f[0] + f[1] * f[1] + f[2] * f[2]);
    const float r1 = std::sqrt(f[4] * f[4] + f[5] * f[5] + f[6] * f[6]);
    const float r2 = std::sqrt(f[8] * f[8] + f[9] * f[9] + f[10] * f[10]);
    const bool rows = r0 > 0.5f && r0 < 2.0f && r1 > 0.5f && r1 < 2.0f && r2 > 0.5f && r2 < 2.0f;
    const bool translation = std::fabs(f[12]) <= world_max && std::fabs(f[13]) <= world_max && std::fabs(f[14]) <= world_max;
    return rows && translation;
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

json register_snapshot(const CONTEXT& ctx)
{
    return json{
        {"rip", sa_format_address(static_cast<std::uint64_t>(ctx.Rip))},
        {"rsp", sa_format_address(static_cast<std::uint64_t>(ctx.Rsp))},
        {"rbp", sa_format_address(static_cast<std::uint64_t>(ctx.Rbp))},
        {"rax", sa_format_address(static_cast<std::uint64_t>(ctx.Rax))},
        {"rbx", sa_format_address(static_cast<std::uint64_t>(ctx.Rbx))},
        {"rcx", sa_format_address(static_cast<std::uint64_t>(ctx.Rcx))},
        {"rdx", sa_format_address(static_cast<std::uint64_t>(ctx.Rdx))},
        {"rsi", sa_format_address(static_cast<std::uint64_t>(ctx.Rsi))},
        {"rdi", sa_format_address(static_cast<std::uint64_t>(ctx.Rdi))},
        {"r8", sa_format_address(static_cast<std::uint64_t>(ctx.R8))},
        {"r9", sa_format_address(static_cast<std::uint64_t>(ctx.R9))},
        {"r10", sa_format_address(static_cast<std::uint64_t>(ctx.R10))},
        {"r11", sa_format_address(static_cast<std::uint64_t>(ctx.R11))},
        {"r12", sa_format_address(static_cast<std::uint64_t>(ctx.R12))},
        {"r13", sa_format_address(static_cast<std::uint64_t>(ctx.R13))},
        {"r14", sa_format_address(static_cast<std::uint64_t>(ctx.R14))},
        {"r15", sa_format_address(static_cast<std::uint64_t>(ctx.R15))}
    };
}

std::uint64_t stack_arg64(std::uint32_t pid, std::uint64_t rsp, std::uint32_t index)
{
    std::uint64_t value = 0;
    read_u64(pid, rsp + 0x28ull + static_cast<std::uint64_t>(index) * 8ull, value);
    return value;
}

bool enable_debug_privilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const DWORD gle = GetLastError();
    CloseHandle(token);
    return ok && gle == ERROR_SUCCESS;
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
                                       std::size_t limit)
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
        collect_pointer_candidates(pid, resource, 0x300, "d3d_resource_object_pointer_snapshot", slot, out, seen, limit);
        if (out.size() < limit)
        {
            auto row = make_cbuffer_candidate(pid, slot, resource, resource, 0, "d3d_resource_object_bytes", 0.25);
            if (row)
                append_unique_candidate(out, *row, seen, limit);
        }
    }
}

json scan_memory_cbuffer_candidates(std::uint32_t pid, std::size_t limit, double world_max, std::size_t max_regions)
{
    json out = json::array();
    std::set<std::uint64_t> seen;
    std::size_t scanned_regions = 0;
    for (const auto& region : regions_for(pid, 4096))
    {
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
    return out;
}

json collect_cbuffer_candidates_from_context(std::uint32_t pid, const CONTEXT& ctx, const store::dx_hook_record_t& record)
{
    json out = json::array();
    std::set<std::uint64_t> seen;
    const std::string api = lower_ascii(record.api);
    const bool cbuffer_bind = record.action == "cbuffer_bind";
    if (cbuffer_bind && api.find("d3d11") != std::string::npos)
        collect_resource_array_candidates(pid, static_cast<std::uint64_t>(ctx.Rdx), static_cast<std::uint64_t>(ctx.R8), static_cast<std::uint64_t>(ctx.R9), out, seen, record.max_captures ? record.max_captures : 32);
    if (cbuffer_bind && api.find("d3d12") != std::string::npos)
    {
        auto row = make_cbuffer_candidate(pid, static_cast<int>(ctx.Rdx), static_cast<std::uint64_t>(ctx.R8), 0, 0, "d3d12_root_cbv_gpu_va_candidate", 0.40);
        if (row)
            append_unique_candidate(out, *row, seen, record.max_captures ? record.max_captures : 32);
    }
    collect_pointer_candidates(pid, static_cast<std::uint64_t>(ctx.Rcx), 0x1000, "d3d_context_object_pointer_snapshot", -1, out, seen, record.max_captures ? record.max_captures : 32);
    if (record.capture_cbuffers && out.size() < std::min<std::uint32_t>(record.max_captures ? record.max_captures : 32, 16))
    {
        json scanned = scan_memory_cbuffer_candidates(pid, 16, 1000000.0, 256);
        for (const auto& row : scanned)
            append_unique_candidate(out, row, seen, record.max_captures ? record.max_captures : 32);
    }
    return out;
}

json dx_args_json(std::uint32_t pid, const CONTEXT& ctx, const store::dx_hook_record_t& record)
{
    json args;
    args["this"] = sa_format_address(static_cast<std::uint64_t>(ctx.Rcx));
    args["arg0"] = static_cast<std::uint64_t>(ctx.Rdx);
    args["arg1"] = static_cast<std::uint64_t>(ctx.R8);
    args["arg2"] = static_cast<std::uint64_t>(ctx.R9);
    args["stack_arg0"] = stack_arg64(pid, static_cast<std::uint64_t>(ctx.Rsp), 0);
    args["stack_arg1"] = stack_arg64(pid, static_cast<std::uint64_t>(ctx.Rsp), 1);
    if (record.action == "present")
    {
        args["swap_chain"] = sa_format_address(static_cast<std::uint64_t>(ctx.Rcx));
        args["sync_interval"] = static_cast<std::uint64_t>(ctx.Rdx);
        args["flags"] = static_cast<std::uint64_t>(ctx.R8);
    }
    else if (record.action == "cbuffer_bind")
    {
        if (lower_ascii(record.api).find("d3d11") != std::string::npos)
        {
            args["start_slot"] = static_cast<std::uint64_t>(ctx.Rdx);
            args["buffer_count"] = static_cast<std::uint64_t>(ctx.R8);
            args["buffer_array"] = sa_format_address(static_cast<std::uint64_t>(ctx.R9));
        }
        else if (lower_ascii(record.api).find("d3d12") != std::string::npos)
        {
            args["root_parameter_index"] = static_cast<std::uint64_t>(ctx.Rdx);
            args["buffer_location"] = sa_format_address(static_cast<std::uint64_t>(ctx.R8));
        }
    }
    else if (record.action == "draw")
    {
        args["index_or_vertex_count"] = static_cast<std::uint64_t>(ctx.Rdx);
        args["instance_or_start_index"] = static_cast<std::uint64_t>(ctx.R8);
        args["start_index_or_vertex"] = static_cast<std::uint64_t>(ctx.R9);
        args["stack_draw_arg0"] = stack_arg64(pid, static_cast<std::uint64_t>(ctx.Rsp), 0);
        args["stack_draw_arg1"] = stack_arg64(pid, static_cast<std::uint64_t>(ctx.Rsp), 1);
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

json make_debug_capture(std::uint32_t pid,
                        std::uint32_t tid,
                        const CONTEXT& ctx,
                        const store::dx_hook_record_t& record,
                        std::uint64_t exception_address,
                        const std::string& backend)
{
    json cap;
    cap["event_type"] = backend == "hardware_breakpoint_debug_event" ? "breakpoint_hit" : "snapshot";
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
    cap["evidence"] = {
        {"source", backend},
        {"thread_context_captured", backend == "hardware_breakpoint_debug_event"},
        {"cbuffer_source", record.capture_cbuffers ? "d3d_bind_args_context_pointer_or_bounded_memory_snapshot" : "disabled"},
        {"gpu_texture_readback", false}
    };
    return cap;
}

json make_snapshot_capture(std::uint32_t pid, const store::dx_hook_record_t& record, const std::string& reason, const json* params = nullptr)
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
        cap["cbuffers"] = explicit_used ? std::move(explicit_rows) : scan_memory_cbuffer_candidates(pid, limit, 1000000.0, 512);
    cap["evidence"] = {
        {"source", "bounded_snapshot_fallback"},
        {"thread_context_captured", false},
        {"cbuffer_source", explicit_used ? "explicit_cbuffer_candidate" : "bounded_private_memory_matrix_scan"},
        {"gpu_texture_readback", false}
    };
    return cap;
}

void refresh_snapshot_records(std::uint32_t pid, const std::string& reason, const json* params = nullptr)
{
    for (auto record : store::list_dx_hooks(pid))
    {
        if (!record.captures.empty())
            continue;
        if (!record.capture_cbuffers && record.action != "cbuffer_bind")
            continue;
        append_capture(record, make_snapshot_capture(pid, record, reason, params));
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
            for (const auto& cb : cap["cbuffers"])
                out.push_back(cb);
        }
    }
    return out;
}

void close_debug_event_handles(const DEBUG_EVENT& evt)
{
    switch (evt.dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
        if (evt.u.CreateProcessInfo.hFile) CloseHandle(evt.u.CreateProcessInfo.hFile);
        if (evt.u.CreateProcessInfo.hThread) CloseHandle(evt.u.CreateProcessInfo.hThread);
        if (evt.u.CreateProcessInfo.hProcess) CloseHandle(evt.u.CreateProcessInfo.hProcess);
        break;
    case CREATE_THREAD_DEBUG_EVENT:
        if (evt.u.CreateThread.hThread) CloseHandle(evt.u.CreateThread.hThread);
        break;
    case LOAD_DLL_DEBUG_EVENT:
        if (evt.u.LoadDll.hFile) CloseHandle(evt.u.LoadDll.hFile);
        break;
    default:
        break;
    }
}

bool capture_dx_breakpoint_hit(std::uint32_t pid, const DEBUG_EVENT& evt)
{
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, evt.dwThreadId);
    if (!thread)
        return false;
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx))
    {
        CloseHandle(thread);
        return false;
    }
    const std::uint64_t exception_address = reinterpret_cast<std::uint64_t>(evt.u.Exception.ExceptionRecord.ExceptionAddress);
    bool matched = false;
    for (auto record : store::list_dx_hooks(pid))
    {
        if (record.target_va == 0)
            continue;
        if (record.target_va != static_cast<std::uint64_t>(ctx.Rip) && record.target_va != exception_address)
            continue;
        append_capture(record, make_debug_capture(pid, evt.dwThreadId, ctx, record, exception_address, "hardware_breakpoint_debug_event"));
        matched = true;
    }
    if (matched)
    {
        ctx.EFlags |= 0x10000;
        SetThreadContext(thread, &ctx);
    }
    CloseHandle(thread);
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
    enable_debug_privilege();
    if (pid == 0 || !DebugActiveProcess(pid))
    {
        state.error.store(GetLastError(), std::memory_order_release);
        state.attached.store(false, std::memory_order_release);
        state.polling.store(false, std::memory_order_release);
        state.running.store(false, std::memory_order_release);
        return;
    }
    DebugSetProcessKillOnExit(FALSE);
    state.error.store(0, std::memory_order_release);
    state.attached.store(true, std::memory_order_release);
    for (const auto& th : threads_for(pid))
        arm_dx_records_for_thread(pid, th.tid);
    bool initial_break_pending = true;
    while (state.polling.load(std::memory_order_acquire))
    {
        if (store::list_dx_hooks(pid).empty())
            break;
        DEBUG_EVENT evt{};
        if (!WaitForDebugEvent(&evt, 100))
            continue;
        DWORD continue_status = DBG_CONTINUE;
        if (evt.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            const DWORD code = evt.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_SINGLE_STEP)
            {
                if (!capture_dx_breakpoint_hit(pid, evt))
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
            else if (code == EXCEPTION_BREAKPOINT && evt.u.Exception.dwFirstChance != 0 && initial_break_pending)
            {
                initial_break_pending = false;
                continue_status = DBG_CONTINUE;
            }
            else
            {
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
        }
        else if (evt.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
        {
            arm_dx_records_for_thread(pid, evt.dwThreadId);
        }
        else if (evt.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT)
        {
            for (auto record : store::list_dx_hooks(pid))
            {
                auto& tids = record.tids;
                tids.erase(std::remove(tids.begin(), tids.end(), evt.dwThreadId), tids.end());
                store::update_dx_hook(record);
            }
        }
        else if (evt.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            state.polling.store(false, std::memory_order_release);
        }
        close_debug_event_handles(evt);
        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continue_status);
    }
    clear_dx_record_breakpoints(pid);
    if (state.attached.exchange(false, std::memory_order_acq_rel))
        DebugActiveProcessStop(pid);
    state.polling.store(false, std::memory_order_release);
    state.pid.store(0, std::memory_order_release);
    state.running.store(false, std::memory_order_release);
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
        error = "another DirectX debug-event consumer is already active";
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
        error = "failed to schedule DirectX debug-event consumer";
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
    error = "DebugActiveProcess failed or timed out, error=" + std::to_string(static_cast<unsigned long>(gle));
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
    auto slots = discover_api(pid, api);
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0 && slot.name == "VSSetConstantBuffers")
            return slot;
    }
    for (const auto& slot : slots)
    {
        if (slot.target_va != 0 && slot.name == "SetGraphicsRootConstantBufferView")
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
    if (api == "auto")
    {
        json apis = json::array();
        apis.push_back(slots_to_result(scope.pid(), "d3d11", discover_d3d11(scope.pid(), false)));
        apis.push_back(slots_to_result(scope.pid(), "d3d12", discover_d3d12(scope.pid())));
        apis.push_back(slots_to_result(scope.pid(), "dxgi", discover_dxgi_present(scope.pid())));
        apis.push_back(slots_to_result(scope.pid(), "vulkan", discover_vulkan(scope.pid())));
        json result;
        result["process_id"] = scope.pid();
        result["api"] = "auto";
        result["apis"] = std::move(apis);
        diag::log_tagged_fmt("dx_hook", "find_device_vtable exit pid=%u api=auto elapsed_ms=%llu",
                             scope.pid(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::ok(result);
    }
    auto slots = api == "dxgi" ? discover_dxgi_present(scope.pid()) : discover_api(scope.pid(), api, false);
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

    const int hw_slot = static_cast<int>(numeric_param(p, "hw_slot", action == "draw" ? 1 : 0, 0, 3));
    store::dx_hook_record_t record;
    record.id = store::next_id("dx");
    record.pid = scope.pid();
    record.api = api == "auto" ? target->module_name : api;
    record.action = action;
    record.target_va = target->target_va;
    record.hw_slot = hw_slot;
    record.capture_cbuffers = bool_param(p, "capture_cbuffers", true);
    record.capture_vertex_buffers = bool_param(p, "capture_vertex_buffers", false);
    record.max_captures = static_cast<std::uint32_t>(numeric_param(p, "max_captures", 16, 1, 1024));
    record.created_ms = unix_time_ms();
    std::size_t primary_threads_seen = 0;
    if (!snapshot_only)
    {
        for (const auto& th : threads_for(scope.pid()))
        {
            ++primary_threads_seen;
            if (driver_bridge::set_hardware_breakpoint(th.tid, hw_slot, target->target_va, 0, 0))
                record.tids.push_back(th.tid);
        }
    }
    diag::log_tagged_fmt("dx_hook", "hook_manage primary_record pid=%u action=%s target_va=%s snapshot_only=%d threads_seen=%zu armed=%zu",
                         scope.pid(),
                         action.c_str(),
                         sa_format_address(target->target_va).c_str(),
                         snapshot_only ? 1 : 0,
                         primary_threads_seen,
                         record.tids.size());
    store::add_dx_hook(record);

    json auxiliary = nullptr;
    if (action == "draw" && record.capture_cbuffers && !snapshot_only)
    {
        const std::uint64_t bind_start_ms = GetTickCount64();
        auto bind_target = choose_cbuffer_target(scope.pid(), api);
        diag::log_tagged_fmt("dx_hook", "hook_manage cbuffer_target pid=%u ok=%d name=%s target_va=%s elapsed_ms=%llu",
                             scope.pid(),
                             bind_target && bind_target->target_va != 0 ? 1 : 0,
                             bind_target ? bind_target->name.c_str() : "",
                             bind_target && bind_target->target_va != 0 ? sa_format_address(bind_target->target_va).c_str() : "0x0",
                             static_cast<unsigned long long>(GetTickCount64() - bind_start_ms));
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
            store::add_dx_hook(bind_record);
            auxiliary = dx_record_json(bind_record);
            auxiliary["target_name"] = bind_target->name;
            auxiliary["target_hint"] = bind_target->hint;
        }
    }

    std::string debug_error;
    bool debug_started = false;
    if (!snapshot_only)
        debug_started = start_dx_debug_loop(scope.pid(), debug_error);
    if (!debug_started)
        refresh_snapshot_records(scope.pid(), debug_error.empty() ? "snapshot mode requested" : debug_error, &p);
    for (const auto& updated : store::list_dx_hooks(scope.pid()))
    {
        if (updated.id == record.id)
        {
            record = updated;
            break;
        }
    }
    std::size_t total_armed_threads = 0;
    for (const auto& updated : store::list_dx_hooks(scope.pid()))
        total_armed_threads += updated.tids.size();
    if (debug_started && total_armed_threads == 0)
    {
        debug_error = "hardware breakpoints could not be armed on any target thread";
        stop_dx_debug_loop(scope.pid());
        debug_started = false;
        refresh_snapshot_records(scope.pid(), debug_error, &p);
        for (const auto& updated : store::list_dx_hooks(scope.pid()))
        {
            if (updated.id == record.id)
            {
                record = updated;
                break;
            }
        }
    }

    json result = dx_record_json(record);
    result["hook_id"] = record.id;
    result["target_name"] = target->name;
    result["target_hint"] = target->hint;
    result["callback_mode"] = callback_mode;
    result["capture_backend"] = debug_started ? "hardware_breakpoint_debug_events" : "bounded_snapshot_fallback";
    result["debug_event_consumer"] = debug_started;
    result["fallback_reason"] = debug_started ? json(nullptr) : json(debug_error.empty() ? "snapshot mode requested" : debug_error);
    result["armed_threads"] = total_armed_threads;
    result["auxiliary_cbuffer_hook"] = std::move(auxiliary);
    result["snapshot_capture_seeded"] = !debug_started;
    diag::log_tagged_fmt("dx_hook", "hook_manage exit pid=%u action=%s hook_id=%s debug_started=%d armed_threads=%zu elapsed_ms=%llu",
                         scope.pid(),
                         action.c_str(),
                         record.id.c_str(),
                         debug_started ? 1 : 0,
                         total_armed_threads,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(debug_started ? "DX hook armed with debug-event capture." : "DX hook recorded with bounded snapshot fallback.", result);
}

tool_result_t list_bound_cbuffers(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    refresh_snapshot_records(scope.pid(), "list_bound_cbuffers requested current bounded evidence", &params);
    json arr = json::array();
    std::set<std::uint64_t> seen;
    collect_explicit_cbuffer_candidates(scope.pid(), params, arr, seen, 128, "explicit_cbuffer_candidate");
    for (const auto& record : store::list_dx_hooks(scope.pid()))
    {
        for (const auto& cap : record.captures)
        {
            if (cap.contains("cbuffers") && cap["cbuffers"].is_array())
            {
                for (const auto& cb : cap["cbuffers"])
                    append_unique_candidate(arr, cb, seen, 128);
            }
        }
    }
    json result;
    result["process_id"] = scope.pid();
    result["api"] = api_param(params);
    result["cbuffers"] = std::move(arr);
    result["count"] = result["cbuffers"].size();
    result["capture_source"] = "dx_hook_captures_or_bounded_snapshot";
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
    refresh_snapshot_records(scope.pid(), "identify_bone_buffer requested current bounded evidence", &params);
    json candidates = json::array();
    auto evaluate_candidate = [&](const json& source, const std::string& source_name) {
        if (!source.contains("va"))
            return;
        std::uint64_t va = 0;
        if (!parse_u64_value(source["va"], va) || va == 0)
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
        const std::size_t read_size = static_cast<std::size_t>(std::min<std::uint64_t>(size, std::max<std::uint64_t>(64ull * max_bones, 4096ull)));
        if (!read_bytes(scope.pid(), va, read_size, bytes) || bytes.size() < 64ull * min_bones)
            return;
        const std::uint32_t count64 = matrix_run_count(bytes, 0, 64, world_max, max_bones);
        const std::uint32_t count48 = matrix_run_count(bytes, 0, 48, world_max, max_bones);
        const std::uint32_t best = std::max(count64, count48);
        if (best < min_bones)
            return;
        json row;
        row["cbuffer_slot"] = source.contains("slot") ? source["slot"] : json(nullptr);
        row["va"] = sa_format_address(va);
        row["bone_count"] = best;
        row["matrix_size"] = count64 >= count48 ? 64 : 48;
        double source_confidence = 0.40;
        if (source.contains("confidence") && source["confidence"].is_number())
            source_confidence = source["confidence"].get<double>();
        row["confidence"] = std::min(0.99, source_confidence + static_cast<double>(best) / static_cast<double>(std::max<std::uint32_t>(max_bones, 1)) * 0.45);
        row["source"] = source_name;
        row["evidence"] = source;
        candidates.push_back(std::move(row));
    };

    for (const auto& cb : explicit_cbuffer_candidates(scope.pid(), params, 64, "explicit_cbuffer_candidate"))
    {
        if (candidates.size() >= 64)
            break;
        evaluate_candidate(cb, "explicit_cbuffer_candidate");
    }

    for (const auto& cb : stored_cbuffer_rows(scope.pid()))
    {
        if (candidates.size() >= 64)
            break;
        evaluate_candidate(cb, "dx_hook_cbuffer_capture");
    }

    if (candidates.empty())
    {
        json scanned = scan_memory_cbuffer_candidates(scope.pid(), 64, world_max, 512);
        for (const auto& row : scanned)
            evaluate_candidate(row, "bounded_private_memory_matrix_scan");
    }
    json result;
    result["process_id"] = scope.pid();
    result["candidates"] = std::move(candidates);
    result["capture_source"] = "none";
    if (!result["candidates"].empty() && result["candidates"][0].contains("source") && result["candidates"][0]["source"].is_string())
        result["capture_source"] = result["candidates"][0]["source"].get<std::string>();
    if (!result["candidates"].empty())
    {
        result["best"] = result["candidates"][0];
        return tool_result_t::ok(result);
    }
    result["best"] = nullptr;
    return tool_result_t::ok("No bone-like buffer found.", result);
}

tool_result_t map_resource_to_va(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    std::uint64_t handle = 0;
    if (!parse_address_param(params, "resource_handle", handle) || handle == 0)
        return tool_result_t::error("'resource_handle' is required.");
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(scope.pid(), handle, 0x200, bytes))
        return tool_result_t::error("Failed to read resource object.");
    json candidates = json::array();
    for (std::size_t off = 0; off + 8 <= bytes.size(); off += 8)
    {
        std::uint64_t ptr = 0;
        std::memcpy(&ptr, bytes.data() + off, sizeof(ptr));
        driver_bridge::memory_region_t region{};
        if (ptr != 0 && query_region(scope.pid(), ptr, region) && is_readable(region))
        {
            json row;
            row["field_offset"] = off;
            row["candidate_va"] = sa_format_address(ptr);
            row["region"] = region_json(region);
            candidates.push_back(std::move(row));
            if (candidates.size() >= 32)
                break;
        }
    }
    json result;
    result["process_id"] = scope.pid();
    result["resource_handle"] = sa_format_address(handle);
    result["candidates"] = std::move(candidates);
    result["va"] = result["candidates"].empty() ? json(nullptr) : result["candidates"][0]["candidate_va"];
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
    const auto window = find_target_window(scope.pid());
    if (!window)
    {
        json result;
        result["process_id"] = scope.pid();
        result["captured"] = false;
        result["source"] = "target_window_frame_capture";
        result["gpu_texture_memory"] = false;
        result["reason"] = "no visible top-level window belongs to the target process";
        return tool_result_t::error("No target window is available for render validation capture.", result);
    }
    std::vector<std::uint8_t> rgba;
    int width = 0;
    int height = 0;
    std::string method;
    std::string error;
    if (!capture_window_rgba(window->hwnd, rgba, width, height, method, error))
    {
        json result;
        result["process_id"] = scope.pid();
        result["captured"] = false;
        result["source"] = "target_window_frame_capture";
        result["gpu_texture_memory"] = false;
        result["reason"] = error;
        return tool_result_t::error("Window-frame capture failed.", result);
    }
    std::filesystem::path output;
    const std::string requested = string_param(params, "output_path");
    if (!requested.empty())
        output = std::filesystem::path(requested);
    else
        output = default_capture_path(scope.pid(), format);
    bool wrote = false;
    if (format == "rgba")
        wrote = write_binary_file(output, rgba, error);
    else
        wrote = write_png_file(output, rgba, width, height, error);
    if (!wrote)
    {
        json result;
        result["process_id"] = scope.pid();
        result["captured"] = false;
        result["source"] = "target_window_frame_capture";
        result["gpu_texture_memory"] = false;
        result["reason"] = error;
        result["width"] = width;
        result["height"] = height;
        return tool_result_t::error("Render validation capture could not be written.", result);
    }
    json result;
    result["process_id"] = scope.pid();
    result["format"] = format;
    result["captured"] = true;
    result["source"] = "target_window_frame_capture";
    result["capture_method"] = method;
    result["gpu_texture_memory"] = false;
    result["output_path"] = output.string();
    result["width"] = width;
    result["height"] = height;
    result["bytes"] = rgba.size();
    result["window"] = {
        {"hwnd", sa_format_address(reinterpret_cast<std::uint64_t>(window->hwnd))},
        {"title", wide_to_utf8(window->title)},
        {"class", wide_to_utf8(window->cls)},
        {"left", window->rect.left},
        {"top", window->rect.top},
        {"right", window->rect.right},
        {"bottom", window->rect.bottom}
    };
    result["evidence"] = {
        {"process_window_validated", true},
        {"bounded_file_write", true},
        {"max_dimension", 8192},
        {"render_target_readback", false},
        {"frame_capture_only", true}
    };
    return tool_result_t::ok("Render validation frame captured from target window.", result);
}

tool_result_t find_view_matrix(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const bool cbuffers_only = bool_param(params, "scan_cbuffers_only", true);
    const double world_max = number_param(params, "world_unit_max", 1000000.0, 1.0, 1000000000.0);
    json out = json::array();
    bool used_cbuffer_capture = false;
    bool used_memory_fallback = false;
    refresh_snapshot_records(scope.pid(), "find_view_matrix requested current bounded evidence", &params);
    auto inspect_candidate = [&](const json& candidate, const std::string& source) {
        if (!candidate.contains("va") || out.size() >= 128)
            return;
        std::uint64_t va = 0;
        if (!parse_u64_value(candidate["va"], va) || va == 0)
            return;
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(scope.pid(), va, 64, bytes) || bytes.size() < 64)
            return;
        float f[16] = {};
        std::memcpy(f, bytes.data(), 64);
        if (!plausible_matrix4x4(f, world_max))
            return;
        json row;
        row["va"] = sa_format_address(va);
        double source_confidence = 0.50;
        if (candidate.contains("confidence") && candidate["confidence"].is_number())
            source_confidence = candidate["confidence"].get<double>();
        row["confidence"] = std::min(0.96, source_confidence + (source == "dx_hook_cbuffer_capture" ? 0.20 : 0.05));
        row["matrix_type"] = std::fabs(f[15] - 1.0f) < 0.01f ? "view" : "viewproj";
        row["preview_floats"] = preview_floats(bytes);
        row["source"] = source;
        row["evidence"] = candidate;
        out.push_back(std::move(row));
    };

    for (const auto& cb : explicit_cbuffer_candidates(scope.pid(), params, 128, "explicit_cbuffer_candidate"))
    {
        inspect_candidate(cb, "explicit_cbuffer_candidate");
        if (out.size() >= 128)
            break;
    }

    for (const auto& cb : stored_cbuffer_rows(scope.pid()))
    {
        inspect_candidate(cb, "dx_hook_cbuffer_capture");
        if (out.size() >= 128)
            break;
    }
    used_cbuffer_capture = !out.empty();

    if (!used_cbuffer_capture || !cbuffers_only)
    {
        json scanned = scan_memory_cbuffer_candidates(scope.pid(), 128 - static_cast<std::size_t>(out.size()), world_max, cbuffers_only ? 512 : 4096);
        for (const auto& row : scanned)
        {
            inspect_candidate(row, "bounded_private_memory_matrix_scan");
            if (out.size() >= 128)
                break;
        }
        used_memory_fallback = !scanned.empty();
    }
    json result;
    result["process_id"] = scope.pid();
    result["scan_cbuffers_only"] = cbuffers_only;
    result["used_cbuffer_capture"] = used_cbuffer_capture;
    result["used_memory_fallback"] = used_memory_fallback;
    result["results"] = std::move(out);
    result["count"] = result["results"].size();
    return tool_result_t::ok(result);
}
}
