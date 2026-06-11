#include "vmt.hpp"

#include "artifact_store.hpp"

#include <algorithm>
#include <cstring>

namespace re::vmt
{
namespace
{
bool read_vtable_pointer(std::uint32_t pid, std::uint64_t address, std::uint64_t& vtable)
{
    return read_u64(pid, address, vtable) && vtable != 0;
}

std::size_t bounded_slot_count(std::uint32_t pid, std::uint64_t vtable_va, std::size_t requested)
{
    requested = std::clamp<std::size_t>(requested, 1, 1024);
    std::size_t valid = 0;
    for (std::size_t i = 0; i < requested; ++i)
    {
        std::uint64_t fn = 0;
        if (!read_u64(pid, vtable_va + i * 8, fn) || fn == 0)
            break;
        driver_bridge::memory_region_t region{};
        if (!query_region(pid, fn, region) || !is_executable(region))
            break;
        ++valid;
    }
    return valid == 0 ? requested : valid;
}

json hook_record_json(const store::vmt_hook_record_t& record)
{
    json out;
    out["hook_id"] = record.id;
    out["process_id"] = record.pid;
    out["vtable_va"] = sa_format_address(record.vtable_va);
    out["object_va"] = sa_format_address(record.object_va);
    out["slot"] = record.slot;
    out["slot_va"] = sa_format_address(record.slot_va);
    out["callback_va"] = sa_format_address(record.callback_va);
    out["original_fn_va"] = sa_format_address(record.original_fn_va);
    out["trampoline_va"] = sa_format_address(record.trampoline_va);
    out["copied_vtable_va"] = sa_format_address(record.copied_vtable_va);
    out["method"] = record.method;
    out["created_ms"] = record.created_ms;
    return out;
}

bool write_pointer_patch(std::uint32_t pid, std::uint64_t slot_address, std::uint64_t value)
{
    driver_bridge::memory_region_t region{};
    std::uint32_t old_protect = 0;
    const bool got_region = query_region(pid, slot_address, region);
    if (got_region && !is_writable(region))
        protect_remote(pid, slot_address & ~0xFFFULL, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect);
    const bool ok = write_u64(pid, slot_address, value);
    if (got_region && old_protect != 0)
        protect_remote(pid, slot_address & ~0xFFFULL, 0x1000, old_protect, nullptr);
    return ok;
}

std::uint64_t make_trampoline(std::uint32_t pid, std::uint64_t original)
{
    std::vector<std::uint8_t> stub = {
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0
    };
    std::memcpy(stub.data() + 2, &original, sizeof(original));
    std::uint64_t remote = allocate_remote(pid, 0x1000);
    if (remote == 0)
        return 0;
    if (!write_bytes(pid, remote, stub))
    {
        free_remote(pid, remote);
        return 0;
    }
    protect_remote(pid, remote, 0x1000, PAGE_EXECUTE_READ, nullptr);
    return remote;
}

std::vector<std::uint8_t> make_u64_pattern(std::uint64_t value)
{
    std::vector<std::uint8_t> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    return bytes;
}

bool parse_required_slot(const json& params, std::uint64_t& slot)
{
    if (!params.contains("slot"))
        return false;
    if (!parse_u64_value(params["slot"], slot))
        return false;
    return slot <= 4095;
}

bool executable_pointer(std::uint32_t pid, std::uint64_t value)
{
    driver_bridge::memory_region_t region{};
    return value != 0 && query_region(pid, value, region) && is_executable(region);
}
}

tool_result_t read(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t address = 0;
    if (!parse_address_param(params, "address", address) || address == 0)
        return tool_result_t::error("'address' is required.");

    std::uint64_t vtable_va = 0;
    if (!read_vtable_pointer(scope.pid(), address, vtable_va))
        return tool_result_t::error("Failed to read vtable pointer at address.");

    const std::size_t max_slots = static_cast<std::size_t>(numeric_param(params, "max_slots", 128, 1, 1024));
    json slots = json::array();
    for (std::size_t i = 0; i < max_slots; ++i)
    {
        std::uint64_t fn = 0;
        if (!read_u64(scope.pid(), vtable_va + i * 8, fn) || fn == 0)
            break;
        driver_bridge::memory_region_t region{};
        const bool executable = query_region(scope.pid(), fn, region) && is_executable(region);
        json row;
        row["slot"] = i;
        row["address"] = sa_format_address(fn);
        row["hint"] = executable ? classify_function_hint(scope.pid(), fn) : "non_executable";
        if (executable)
            row["preview"] = disasm_preview(scope.pid(), fn, 2);
        slots.push_back(std::move(row));
        if (!executable)
            break;
    }

    json result;
    result["process_id"] = scope.pid();
    result["object_or_pointer_va"] = sa_format_address(address);
    result["vtable_va"] = sa_format_address(vtable_va);
    result["returned"] = slots.size();
    result["slots"] = std::move(slots);
    return tool_result_t::ok(result);
}

tool_result_t hook_manage(const json& params)
{
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);

    if (action == "list")
    {
        std::uint32_t pid = 0;
        parse_pid_param(p, pid);
        json arr = json::array();
        for (const auto& record : store::list_vmt_hooks(pid))
            arr.push_back(hook_record_json(record));
        json result;
        result["hooks"] = std::move(arr);
        result["count"] = result["hooks"].size();
        return tool_result_t::ok(result);
    }

    if (action == "remove")
    {
        if (!unsafe_confirmed(p))
            return unsafe_required("vmt_hook_manage remove");
        const std::string hook_id = string_param(p, "hook_id");
        if (hook_id.empty())
            return tool_result_t::error("'hook_id' is required for remove.");
        store::vmt_hook_record_t record;
        if (!store::find_vmt_hook(hook_id, record))
            return tool_result_t::error("Unknown VMT hook id.");
        active_process_scope_t scope(record.pid);
        if (!scope.ok())
            return tool_result_t::error(scope.error());
        json result = hook_record_json(record);
        bool restored = false;
        if (record.method == "patch_vtable")
            restored = record.slot_va != 0 && record.original_fn_va != 0 && write_pointer_patch(scope.pid(), record.slot_va, record.original_fn_va);
        else if (record.method == "patch_object" || record.method == "vmt_copy")
            restored = record.object_va != 0 && record.vtable_va != 0 && write_pointer_patch(scope.pid(), record.object_va, record.vtable_va);
        else
            restored = record.slot_va != 0 && record.original_fn_va != 0 && write_pointer_patch(scope.pid(), record.slot_va, record.original_fn_va);
        result["restored"] = restored;
        if (!restored)
            return tool_result_t::error("VMT hook restoration failed; record was retained.", result);
        const bool trampoline_freed = record.trampoline_va == 0 || free_remote(scope.pid(), record.trampoline_va);
        const bool copy_freed = record.copied_vtable_va == 0 || free_remote(scope.pid(), record.copied_vtable_va);
        result["trampoline_freed"] = trampoline_freed;
        result["copied_vtable_freed"] = copy_freed;
        if (!trampoline_freed || !copy_freed)
            return tool_result_t::error("VMT hook restored, but remote allocation cleanup failed; record was retained.", result);
        store::vmt_hook_record_t removed;
        if (!store::remove_vmt_hook(hook_id, &removed))
            return tool_result_t::error("VMT hook restored, but record removal failed.", result);
        return tool_result_t::ok(record.method == "vmt_copy" ? "VMT copy restored." : "VMT hook removed.", result);
    }

    if (action != "install")
        return compat_unknown_action("vmt_hook_manage", action);

    if (!unsafe_confirmed(p))
        return unsafe_required("vmt_hook_manage install");

    active_process_scope_t scope(p);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t vtable_va = 0;
    std::uint64_t callback_va = 0;
    if (!parse_address_param(p, "vtable_va", vtable_va) || vtable_va == 0)
        return tool_result_t::error("'vtable_va' is required for install.");
    if (!parse_address_param(p, "callback_va", callback_va) || callback_va == 0)
        return tool_result_t::error("'callback_va' is required for install.");
    std::uint64_t slot64 = 0;
    if (!parse_required_slot(p, slot64))
        return tool_result_t::error("'slot' is required for install and must be between 0 and 4095.");
    const auto slot = static_cast<std::uint32_t>(slot64);
    if (!executable_pointer(scope.pid(), callback_va))
        return tool_result_t::error("'callback_va' must point to executable target memory.");
    std::string method = lower_ascii(string_param(p, "method", "patch_vtable"));
    if (method.empty())
        method = "patch_vtable";

    std::uint64_t object_va = 0;
    std::uint64_t effective_vtable = vtable_va;
    std::uint64_t original_object_vtable = vtable_va;
    std::uint64_t copied_vtable = 0;
    if (method == "patch_object")
    {
        if (!parse_address_param(p, "object_va", object_va) || object_va == 0)
            return tool_result_t::error("'object_va' is required when method='patch_object'.");
        std::uint64_t object_vtable = 0;
        if (!read_u64(scope.pid(), object_va, object_vtable) || object_vtable == 0)
            return tool_result_t::error("Failed to read object's current vtable.");
        original_object_vtable = object_vtable;
        if (vtable_va != object_vtable)
            effective_vtable = object_vtable;
        const std::size_t slots_to_copy = bounded_slot_count(scope.pid(), effective_vtable, static_cast<std::size_t>(numeric_param(p, "copy_slots", 256, slot + 1, 1024)));
        std::vector<std::uint8_t> table_bytes;
        if (!read_bytes(scope.pid(), effective_vtable, slots_to_copy * 8, table_bytes) || table_bytes.size() < (slot + 1ull) * 8ull)
            return tool_result_t::error("Failed to read source vtable for object copy.");
        copied_vtable = allocate_remote(scope.pid(), std::max<std::size_t>(static_cast<std::size_t>(0x1000), table_bytes.size()));
        if (copied_vtable == 0)
            return tool_result_t::error("Failed to allocate copied vtable.");
        if (!write_bytes(scope.pid(), copied_vtable, table_bytes))
        {
            free_remote(scope.pid(), copied_vtable);
            return tool_result_t::error("Failed to write copied vtable.");
        }
        if (!write_pointer_patch(scope.pid(), object_va, copied_vtable))
        {
            free_remote(scope.pid(), copied_vtable);
            return tool_result_t::error("Failed to patch object vtable pointer.");
        }
        effective_vtable = copied_vtable;
    }
    else if (method != "patch_vtable")
    {
        return tool_result_t::error("method must be 'patch_vtable' or 'patch_object'.");
    }

    const std::uint64_t slot_va = effective_vtable + static_cast<std::uint64_t>(slot) * 8ull;
    std::uint64_t original = 0;
    if (!read_u64(scope.pid(), slot_va, original) || original == 0)
    {
        if (copied_vtable != 0 && object_va != 0)
            write_pointer_patch(scope.pid(), object_va, original_object_vtable);
        if (copied_vtable != 0)
            free_remote(scope.pid(), copied_vtable);
        return tool_result_t::error("Failed to read original vtable slot.");
    }
    if (!executable_pointer(scope.pid(), original))
    {
        if (copied_vtable != 0 && object_va != 0)
            write_pointer_patch(scope.pid(), object_va, original_object_vtable);
        if (copied_vtable != 0)
            free_remote(scope.pid(), copied_vtable);
        return tool_result_t::error("Requested VMT slot does not contain an executable function pointer.");
    }
    const std::uint64_t trampoline = make_trampoline(scope.pid(), original);
    if (trampoline == 0)
    {
        if (copied_vtable != 0 && object_va != 0)
            write_pointer_patch(scope.pid(), object_va, original_object_vtable);
        if (copied_vtable != 0)
            free_remote(scope.pid(), copied_vtable);
        return tool_result_t::error("Failed to allocate original-call trampoline.");
    }
    if (!write_pointer_patch(scope.pid(), slot_va, callback_va))
    {
        if (copied_vtable != 0 && object_va != 0)
            write_pointer_patch(scope.pid(), object_va, original_object_vtable);
        free_remote(scope.pid(), trampoline);
        if (copied_vtable != 0)
            free_remote(scope.pid(), copied_vtable);
        return tool_result_t::error("Failed to patch vtable slot.");
    }

    store::vmt_hook_record_t record;
    record.id = store::next_id("vmt");
    record.pid = scope.pid();
    record.vtable_va = method == "patch_object" ? original_object_vtable : effective_vtable;
    record.object_va = object_va;
    record.slot = slot;
    record.slot_va = slot_va;
    record.callback_va = callback_va;
    record.original_fn_va = original;
    record.trampoline_va = trampoline;
    record.copied_vtable_va = copied_vtable;
    record.method = method;
    record.created_ms = unix_time_ms();
    store::add_vmt_hook(record);
    return tool_result_t::ok("VMT hook installed.", hook_record_json(record));
}

tool_result_t copy(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("vmt_copy");

    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t object_va = 0;
    if (!parse_address_param(params, "object_va", object_va) || object_va == 0)
        return tool_result_t::error("'object_va' is required.");
    std::uint64_t original_vtable = 0;
    if (!read_u64(scope.pid(), object_va, original_vtable) || original_vtable == 0)
        return tool_result_t::error("Failed to read object vtable pointer.");

    const std::size_t slots = bounded_slot_count(scope.pid(), original_vtable, static_cast<std::size_t>(numeric_param(params, "max_slots", 256, 1, 1024)));
    std::vector<std::uint8_t> table;
    if (!read_bytes(scope.pid(), original_vtable, slots * 8, table) || table.empty())
        return tool_result_t::error("Failed to read vtable bytes.");
    const std::size_t alloc_size = std::max<std::size_t>(static_cast<std::size_t>(0x1000), static_cast<std::size_t>((table.size() + 0xFFF) & ~static_cast<std::size_t>(0xFFF)));
    const std::uint64_t copy_va = allocate_remote(scope.pid(), alloc_size);
    if (copy_va == 0)
        return tool_result_t::error("Failed to allocate vtable copy.");
    if (!write_bytes(scope.pid(), copy_va, table))
    {
        free_remote(scope.pid(), copy_va);
        return tool_result_t::error("Failed to write vtable copy.");
    }
    if (!write_pointer_patch(scope.pid(), object_va, copy_va))
    {
        free_remote(scope.pid(), copy_va);
        return tool_result_t::error("Failed to patch object vtable pointer.");
    }

    json result;
    result["process_id"] = scope.pid();
    result["object_va"] = sa_format_address(object_va);
    result["copy_va"] = sa_format_address(copy_va);
    result["original_va"] = sa_format_address(original_vtable);
    result["slots_copied"] = slots;
    store::vmt_hook_record_t record;
    record.id = store::next_id("vmtcopy");
    record.pid = scope.pid();
    record.vtable_va = original_vtable;
    record.object_va = object_va;
    record.copied_vtable_va = copy_va;
    record.method = "vmt_copy";
    record.created_ms = unix_time_ms();
    store::add_vmt_hook(record);
    result["hook_id"] = record.id;
    result["managed_restore"] = true;
    return tool_result_t::ok("VMT copied and object patched.", result);
}

tool_result_t find_slot_by_signature(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t vtable_va = 0;
    if (!parse_address_param(params, "vtable_va", vtable_va) || vtable_va == 0)
        return tool_result_t::error("'vtable_va' is required.");
    const std::string pattern_text = string_param(params, "pattern");
    std::vector<parsed_pattern_byte_t> pattern;
    std::string pattern_error;
    if (!parse_pattern(pattern_text, pattern, &pattern_error))
        return tool_result_t::error("Invalid pattern: " + pattern_error);
    const std::size_t max_slots = static_cast<std::size_t>(numeric_param(params, "max_slots", 256, 1, 1024));
    for (std::size_t i = 0; i < max_slots; ++i)
    {
        std::uint64_t fn = 0;
        if (!read_u64(scope.pid(), vtable_va + i * 8, fn) || fn == 0)
            break;
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(scope.pid(), fn, std::max<std::size_t>(pattern.size(), 16), bytes) || bytes.size() < pattern.size())
            continue;
        if (pattern_matches(bytes.data(), bytes.size(), pattern))
        {
            json result;
            result["slot"] = i;
            result["address"] = sa_format_address(fn);
            result["hint"] = classify_function_hint(scope.pid(), fn);
            return tool_result_t::ok(result);
        }
    }
    json result;
    result["slot"] = nullptr;
    result["address"] = nullptr;
    return tool_result_t::ok("No matching VMT slot found.", result);
}

tool_result_t scan_objects(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t vtable_va = 0;
    if (!parse_address_param(params, "vtable_va", vtable_va) || vtable_va == 0)
        return tool_result_t::error("'vtable_va' is required.");
    const std::size_t max_results = static_cast<std::size_t>(numeric_param(params, "max_results", 512, 1, 10000));
    const auto needle = make_u64_pattern(vtable_va);
    json arr = json::array();
    for (const auto& region : regions_for(scope.pid(), 8192))
    {
        if (arr.size() >= max_results)
            break;
        if (!is_readable(region) || !is_writable(region) || region.size < 8 || region.size > 64ull * 1024ull * 1024ull)
            continue;
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(scope.pid(), region.base, static_cast<std::size_t>(region.size), bytes) || bytes.size() < 8)
            continue;
        for (std::size_t i = 0; i + 8 <= bytes.size(); i += 8)
        {
            if (std::memcmp(bytes.data() + i, needle.data(), 8) != 0)
                continue;
            json obj;
            obj["object_va"] = sa_format_address(region.base + i);
            obj["region_info"] = region_json(region);
            arr.push_back(std::move(obj));
            if (arr.size() >= max_results)
                break;
        }
    }
    json result;
    result["process_id"] = scope.pid();
    result["vtable_va"] = sa_format_address(vtable_va);
    result["returned"] = arr.size();
    result["objects"] = std::move(arr);
    return tool_result_t::ok(result);
}
}
