#include "vmt.hpp"

#include "artifact_store.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace re::vmt
{
namespace
{
std::uint64_t deadline_remaining_ms()
{
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline == 0)
        return 0;
    const std::uint64_t now = GetTickCount64();
    return deadline > now ? deadline - now : 0;
}

bool vmt_call_cancelled(const char* phase, std::uint32_t pid, std::uint64_t started_ms)
{
    if (mcp_standalone::current_call_cancelled())
    {
        diag::log_tagged_fmt("vmt", "cancelled phase=%s pid=%u elapsed_ms=%llu diag_id=%s",
                             phase ? phase : "",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0 && GetTickCount64() >= deadline)
    {
        diag::log_tagged_fmt("vmt", "deadline_reached phase=%s pid=%u elapsed_ms=%llu diag_id=%s",
                             phase ? phase : "",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    return false;
}

json vmt_cancel_detail(const char* action, std::uint32_t pid, std::uint64_t started_ms)
{
    return json{
        {"action", action ? action : ""},
        {"process_id", pid},
        {"elapsed_ms", GetTickCount64() - started_ms},
        {"deadline_remaining_ms", deadline_remaining_ms()},
        {"cancelled", mcp_standalone::current_call_cancelled()},
        {"diag_id", mcp_standalone::current_call_diag_id()}
    };
}

bool read_vtable_pointer(std::uint32_t pid, std::uint64_t address, std::uint64_t& vtable)
{
    return read_u64(pid, address, vtable) && vtable != 0;
}

std::size_t bounded_slot_count(std::uint32_t pid,
                               std::uint64_t vtable_va,
                               std::size_t requested,
                               const char* phase = nullptr,
                               std::uint64_t started_ms = 0,
                               bool* cancelled = nullptr,
                               std::size_t* reads = nullptr,
                               std::size_t* queries = nullptr)
{
    requested = std::clamp<std::size_t>(requested, 1, 1024);
    std::size_t valid = 0;
    for (std::size_t i = 0; i < requested; ++i)
    {
        if (started_ms != 0 && (i & 0x0Fu) == 0 && vmt_call_cancelled(phase, pid, started_ms))
        {
            if (cancelled)
                *cancelled = true;
            break;
        }
        std::uint64_t fn = 0;
        if (reads)
            ++*reads;
        if (!read_u64(pid, vtable_va + i * 8, fn) || fn == 0)
            break;
        driver_bridge::memory_region_t region{};
        if (queries)
            ++*queries;
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

std::string normalize_disasm_match_text(std::string value)
{
    value = lower_ascii(std::move(value));
    std::string out;
    bool pending_space = false;
    for (char ch : value)
    {
        const unsigned char uch = static_cast<unsigned char>(ch);
        if (std::isspace(uch))
        {
            pending_space = true;
            continue;
        }
        if (ch == ',' || ch == '[' || ch == ']' || ch == '+' || ch == '-' || ch == ':' || ch == '(' || ch == ')')
        {
            if (!out.empty() && out.back() == ' ')
                out.pop_back();
            out.push_back(ch);
            pending_space = false;
            continue;
        }
        if (pending_space && !out.empty())
            out.push_back(' ');
        out.push_back(ch);
        pending_space = false;
    }
    if (!out.empty() && out.back() == ' ')
        out.pop_back();
    return out;
}

std::vector<std::string> parse_disasm_pattern(const std::string& text)
{
    std::vector<std::string> out;
    std::string current;
    auto flush = [&]() {
        std::string normalized = normalize_disasm_match_text(trim_ascii(current));
        if (!normalized.empty())
            out.push_back(std::move(normalized));
        current.clear();
    };
    for (char ch : text)
    {
        if (ch == ';' || ch == '\n' || ch == '\r')
            flush();
        else
            current.push_back(ch);
    }
    flush();
    return out;
}

bool glob_match_normalized(const std::string& pattern, const std::string& text)
{
    std::size_t p = 0;
    std::size_t t = 0;
    std::size_t star = std::string::npos;
    std::size_t star_text = 0;
    while (t < text.size())
    {
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == text[t]))
        {
            ++p;
            ++t;
            continue;
        }
        if (p < pattern.size() && pattern[p] == '*')
        {
            star = p++;
            star_text = t;
            continue;
        }
        if (star != std::string::npos)
        {
            p = star + 1;
            t = ++star_text;
            continue;
        }
        return false;
    }
    while (p < pattern.size() && pattern[p] == '*')
        ++p;
    return p == pattern.size();
}

bool disasm_instruction_matches(const std::string& pattern, const AsmInstr& ins, const std::string& normalized_text)
{
    const std::string mnemonic = normalize_disasm_match_text(ins.mnem);
    return (!mnemonic.empty() && glob_match_normalized(pattern, mnemonic)) ||
        glob_match_normalized(pattern, normalized_text);
}

bool disasm_pattern_matches(std::uint32_t pid,
                            std::uint64_t fn,
                            const std::vector<std::string>& pattern,
                            json* preview)
{
    std::uint64_t cursor = fn;
    json rows = json::array();
    for (std::size_t i = 0; i < pattern.size(); ++i)
    {
        AsmInstr ins = decode_one(pid, cursor);
        const std::string text = disasm_text(ins);
        const std::string normalized = normalize_disasm_match_text(text);
        const bool matched = disasm_instruction_matches(pattern[i], ins, normalized);
        json row;
        row["address"] = sa_format_address(cursor);
        row["text"] = text;
        row["mnemonic"] = normalize_disasm_match_text(ins.mnem);
        row["pattern"] = pattern[i];
        row["matched"] = matched;
        rows.push_back(std::move(row));
        if (ins.len <= 0 || ins.mnem[0] == '\0' || !matched)
        {
            if (preview)
                *preview = std::move(rows);
            return false;
        }
        cursor += static_cast<std::uint64_t>(std::max(ins.len, 1));
    }
    if (preview)
        *preview = std::move(rows);
    return true;
}

bool executable_pointer(std::uint32_t pid, std::uint64_t value)
{
    driver_bridge::memory_region_t region{};
    return value != 0 && query_region(pid, value, region) && is_executable(region);
}
}

tool_result_t read(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t address = 0;
    if (!parse_address_param(params, "address", address) || address == 0)
        return tool_result_t::error("'address' is required.");
    const std::size_t max_slots = static_cast<std::size_t>(numeric_param(params, "max_slots", 128, 1, 1024));
    diag::log_tagged_fmt("vmt",
                         "read enter pid=%u address=%s max_slots=%zu deadline_remaining_ms=%llu diag_id=%s",
                         scope.pid(),
                         sa_format_address(address).c_str(),
                         max_slots,
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());

    std::uint64_t vtable_va = 0;
    if (!read_vtable_pointer(scope.pid(), address, vtable_va))
    {
        diag::log_tagged_fmt("vmt",
                             "read exit pid=%u ok=0 phase=object_vtable_read address=%s elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(address).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Failed to read vtable pointer at address.");
    }

    json slots = json::array();
    std::size_t slot_reads = 0;
    std::size_t region_queries = 0;
    std::size_t executable_slots = 0;
    for (std::size_t i = 0; i < max_slots; ++i)
    {
        if ((i & 0x0Fu) == 0 && vmt_call_cancelled("read_slots", scope.pid(), started_ms))
            return tool_result_t::error("VMT read cancelled.", vmt_cancel_detail("read", scope.pid(), started_ms));
        std::uint64_t fn = 0;
        ++slot_reads;
        if (!read_u64(scope.pid(), vtable_va + i * 8, fn) || fn == 0)
            break;
        driver_bridge::memory_region_t region{};
        ++region_queries;
        const bool executable = query_region(scope.pid(), fn, region) && is_executable(region);
        if (executable)
            ++executable_slots;
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
    result["slot_reads"] = slot_reads;
    result["region_queries"] = region_queries;
    result["executable_slots"] = executable_slots;
    result["slots"] = std::move(slots);
    diag::log_tagged_fmt("vmt",
                         "read exit pid=%u ok=1 vtable=%s returned=%zu slot_reads=%zu region_queries=%zu executable=%zu elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(vtable_va).c_str(),
                         result["returned"].get<std::size_t>(),
                         slot_reads,
                         region_queries,
                         executable_slots,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}

tool_result_t hook_manage(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    diag::log_tagged_fmt("vmt",
                         "hook_manage enter action=%s deadline_remaining_ms=%llu diag_id=%s",
                         action.c_str(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());

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
        diag::log_tagged_fmt("vmt",
                             "hook_manage exit action=list pid=%u count=%zu elapsed_ms=%llu",
                             pid,
                             result["count"].get<std::size_t>(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
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
        diag::log_tagged_fmt("vmt",
                             "hook_manage remove_begin pid=%u hook_id=%s method=%s slot=%u object=%s slot_va=%s copied_vtable=%s trampoline=%s",
                             scope.pid(),
                             hook_id.c_str(),
                             record.method.c_str(),
                             record.slot,
                             sa_format_address(record.object_va).c_str(),
                             sa_format_address(record.slot_va).c_str(),
                             sa_format_address(record.copied_vtable_va).c_str(),
                             sa_format_address(record.trampoline_va).c_str());
        if (vmt_call_cancelled("hook_remove_before_restore", scope.pid(), started_ms))
            return tool_result_t::error("VMT hook removal cancelled.", vmt_cancel_detail("remove", scope.pid(), started_ms));
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
        diag::log_tagged_fmt("vmt",
                             "hook_manage remove_cleanup pid=%u hook_id=%s restored=%d trampoline_freed=%d copied_vtable_freed=%d elapsed_ms=%llu",
                             scope.pid(),
                             hook_id.c_str(),
                             restored ? 1 : 0,
                             trampoline_freed ? 1 : 0,
                             copy_freed ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
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
    diag::log_tagged_fmt("vmt",
                         "hook_manage install_begin pid=%u method=%s slot=%u vtable=%s callback=%s object=%s",
                         scope.pid(),
                         method.c_str(),
                         slot,
                         sa_format_address(vtable_va).c_str(),
                         sa_format_address(callback_va).c_str(),
                         sa_format_address(object_va).c_str());
    if (vmt_call_cancelled("hook_install_before_copy", scope.pid(), started_ms))
        return tool_result_t::error("VMT hook install cancelled.", vmt_cancel_detail("install", scope.pid(), started_ms));
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
        bool slot_count_cancelled = false;
        std::size_t count_reads = 0;
        std::size_t count_queries = 0;
        const std::size_t slots_to_copy = bounded_slot_count(scope.pid(),
                                                             effective_vtable,
                                                             static_cast<std::size_t>(numeric_param(p, "copy_slots", 256, slot + 1, 1024)),
                                                             "hook_install_bounded_slot_count",
                                                             started_ms,
                                                             &slot_count_cancelled,
                                                             &count_reads,
                                                             &count_queries);
        diag::log_tagged_fmt("vmt",
                             "hook_manage install_slot_count pid=%u effective_vtable=%s requested_slot=%u slots_to_copy=%zu reads=%zu queries=%zu cancelled=%d elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(effective_vtable).c_str(),
                             slot,
                             slots_to_copy,
                             count_reads,
                             count_queries,
                             slot_count_cancelled ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (slot_count_cancelled)
            return tool_result_t::error("VMT hook install cancelled.", vmt_cancel_detail("install", scope.pid(), started_ms));
        std::vector<std::uint8_t> table_bytes;
        if (!read_bytes(scope.pid(), effective_vtable, slots_to_copy * 8, table_bytes) || table_bytes.size() < (slot + 1ull) * 8ull)
            return tool_result_t::error("Failed to read source vtable for object copy.");
        copied_vtable = allocate_remote(scope.pid(), std::max<std::size_t>(static_cast<std::size_t>(0x1000), table_bytes.size()));
        diag::log_tagged_fmt("vmt",
                             "hook_manage install_copy_alloc pid=%u bytes=%zu copied_vtable=%s elapsed_ms=%llu",
                             scope.pid(),
                             table_bytes.size(),
                             sa_format_address(copied_vtable).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (copied_vtable == 0)
            return tool_result_t::error("Failed to allocate copied vtable.");
        if (!write_bytes(scope.pid(), copied_vtable, table_bytes))
        {
            const bool freed = free_remote(scope.pid(), copied_vtable);
            diag::log_tagged_fmt("vmt",
                                 "hook_manage install_copy_write_failed pid=%u copied_vtable=%s cleanup_freed=%d elapsed_ms=%llu",
                                 scope.pid(),
                                 sa_format_address(copied_vtable).c_str(),
                                 freed ? 1 : 0,
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return tool_result_t::error("Failed to write copied vtable.");
        }
        if (!write_pointer_patch(scope.pid(), object_va, copied_vtable))
        {
            const bool freed = free_remote(scope.pid(), copied_vtable);
            diag::log_tagged_fmt("vmt",
                                 "hook_manage install_object_patch_failed pid=%u object=%s copied_vtable=%s cleanup_freed=%d elapsed_ms=%llu",
                                 scope.pid(),
                                 sa_format_address(object_va).c_str(),
                                 sa_format_address(copied_vtable).c_str(),
                                 freed ? 1 : 0,
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
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
        const bool restored = copied_vtable != 0 && object_va != 0 ? write_pointer_patch(scope.pid(), object_va, original_object_vtable) : true;
        const bool freed = copied_vtable != 0 ? free_remote(scope.pid(), copied_vtable) : true;
        diag::log_tagged_fmt("vmt",
                             "hook_manage install_original_read_failed pid=%u slot_va=%s restored=%d copied_freed=%d elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(slot_va).c_str(),
                             restored ? 1 : 0,
                             freed ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Failed to read original vtable slot.");
    }
    if (!executable_pointer(scope.pid(), original))
    {
        const bool restored = copied_vtable != 0 && object_va != 0 ? write_pointer_patch(scope.pid(), object_va, original_object_vtable) : true;
        const bool freed = copied_vtable != 0 ? free_remote(scope.pid(), copied_vtable) : true;
        diag::log_tagged_fmt("vmt",
                             "hook_manage install_original_not_executable pid=%u original=%s restored=%d copied_freed=%d elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(original).c_str(),
                             restored ? 1 : 0,
                             freed ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Requested VMT slot does not contain an executable function pointer.");
    }
    const std::uint64_t trampoline = make_trampoline(scope.pid(), original);
    diag::log_tagged_fmt("vmt",
                         "hook_manage install_trampoline pid=%u original=%s trampoline=%s elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(original).c_str(),
                         sa_format_address(trampoline).c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (trampoline == 0)
    {
        const bool restored = copied_vtable != 0 && object_va != 0 ? write_pointer_patch(scope.pid(), object_va, original_object_vtable) : true;
        const bool freed = copied_vtable != 0 ? free_remote(scope.pid(), copied_vtable) : true;
        diag::log_tagged_fmt("vmt",
                             "hook_manage install_trampoline_failed pid=%u restored=%d copied_freed=%d elapsed_ms=%llu",
                             scope.pid(),
                             restored ? 1 : 0,
                             freed ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Failed to allocate original-call trampoline.");
    }
    if (!write_pointer_patch(scope.pid(), slot_va, callback_va))
    {
        const bool restored = copied_vtable != 0 && object_va != 0 ? write_pointer_patch(scope.pid(), object_va, original_object_vtable) : true;
        const bool trampoline_freed = free_remote(scope.pid(), trampoline);
        const bool copied_freed = copied_vtable != 0 ? free_remote(scope.pid(), copied_vtable) : true;
        diag::log_tagged_fmt("vmt",
                             "hook_manage install_slot_patch_failed pid=%u slot_va=%s restored=%d trampoline_freed=%d copied_freed=%d elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(slot_va).c_str(),
                             restored ? 1 : 0,
                             trampoline_freed ? 1 : 0,
                             copied_freed ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
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
    diag::log_tagged_fmt("vmt",
                         "hook_manage exit action=install pid=%u hook_id=%s method=%s slot=%u slot_va=%s copied_vtable=%s trampoline=%s elapsed_ms=%llu",
                         scope.pid(),
                         record.id.c_str(),
                         record.method.c_str(),
                         record.slot,
                         sa_format_address(record.slot_va).c_str(),
                         sa_format_address(record.copied_vtable_va).c_str(),
                         sa_format_address(record.trampoline_va).c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("VMT hook installed.", hook_record_json(record));
}

tool_result_t copy(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return unsafe_required("vmt_copy");

    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t object_va = 0;
    if (!parse_address_param(params, "object_va", object_va) || object_va == 0)
        return tool_result_t::error("'object_va' is required.");
    diag::log_tagged_fmt("vmt",
                         "copy enter pid=%u object=%s deadline_remaining_ms=%llu diag_id=%s",
                         scope.pid(),
                         sa_format_address(object_va).c_str(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    std::uint64_t original_vtable = 0;
    if (!read_u64(scope.pid(), object_va, original_vtable) || original_vtable == 0)
    {
        diag::log_tagged_fmt("vmt",
                             "copy exit pid=%u ok=0 phase=object_vtable_read object=%s elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(object_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Failed to read object vtable pointer.");
    }

    bool slot_count_cancelled = false;
    std::size_t count_reads = 0;
    std::size_t count_queries = 0;
    const std::size_t slots = bounded_slot_count(scope.pid(),
                                                 original_vtable,
                                                 static_cast<std::size_t>(numeric_param(params, "max_slots", 256, 1, 1024)),
                                                 "copy_bounded_slot_count",
                                                 started_ms,
                                                 &slot_count_cancelled,
                                                 &count_reads,
                                                 &count_queries);
    diag::log_tagged_fmt("vmt",
                         "copy slot_count pid=%u original_vtable=%s slots=%zu reads=%zu queries=%zu cancelled=%d elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(original_vtable).c_str(),
                         slots,
                         count_reads,
                         count_queries,
                         slot_count_cancelled ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (slot_count_cancelled)
        return tool_result_t::error("VMT copy cancelled.", vmt_cancel_detail("copy", scope.pid(), started_ms));
    std::vector<std::uint8_t> table;
    if (!read_bytes(scope.pid(), original_vtable, slots * 8, table) || table.empty())
        return tool_result_t::error("Failed to read vtable bytes.");
    const std::size_t alloc_size = std::max<std::size_t>(static_cast<std::size_t>(0x1000), static_cast<std::size_t>((table.size() + 0xFFF) & ~static_cast<std::size_t>(0xFFF)));
    const std::uint64_t copy_va = allocate_remote(scope.pid(), alloc_size);
    diag::log_tagged_fmt("vmt",
                         "copy alloc pid=%u original_vtable=%s table_bytes=%zu alloc_size=%zu copy_va=%s elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(original_vtable).c_str(),
                         table.size(),
                         alloc_size,
                         sa_format_address(copy_va).c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (copy_va == 0)
        return tool_result_t::error("Failed to allocate vtable copy.");
    if (!write_bytes(scope.pid(), copy_va, table))
    {
        const bool freed = free_remote(scope.pid(), copy_va);
        diag::log_tagged_fmt("vmt",
                             "copy write_failed pid=%u copy_va=%s cleanup_freed=%d elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(copy_va).c_str(),
                             freed ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Failed to write vtable copy.");
    }
    if (!write_pointer_patch(scope.pid(), object_va, copy_va))
    {
        const bool freed = free_remote(scope.pid(), copy_va);
        diag::log_tagged_fmt("vmt",
                             "copy patch_failed pid=%u object=%s copy_va=%s cleanup_freed=%d elapsed_ms=%llu",
                             scope.pid(),
                             sa_format_address(object_va).c_str(),
                             sa_format_address(copy_va).c_str(),
                             freed ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
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
    diag::log_tagged_fmt("vmt",
                         "copy exit pid=%u ok=1 object=%s original=%s copy=%s slots=%zu table_bytes=%zu hook_id=%s elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(object_va).c_str(),
                         sa_format_address(original_vtable).c_str(),
                         sa_format_address(copy_va).c_str(),
                         slots,
                         table.size(),
                         record.id.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("VMT copied and object patched.", result);
}

tool_result_t find_slot_by_signature(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t vtable_va = 0;
    if (!parse_address_param(params, "vtable_va", vtable_va) || vtable_va == 0)
        return tool_result_t::error("'vtable_va' is required.");
    const std::string pattern_text = string_param(params, "pattern");
    if (trim_ascii(pattern_text).empty())
        return tool_result_t::error("'pattern' is required.");
    const std::string pattern_kind = lower_ascii(trim_ascii(string_param(params, "pattern_kind", "auto")));
    std::vector<parsed_pattern_byte_t> byte_pattern;
    std::string pattern_error;
    const bool byte_mode = pattern_kind != "disasm" && parse_pattern(pattern_text, byte_pattern, &pattern_error);
    std::vector<std::string> disasm_pattern;
    if (!byte_mode)
    {
        if (pattern_kind == "bytes")
            return tool_result_t::error("Invalid byte pattern: " + pattern_error);
        disasm_pattern = parse_disasm_pattern(pattern_text);
        if (disasm_pattern.empty())
            return tool_result_t::error("Invalid disassembly pattern.");
    }
    if (pattern_kind != "auto" && pattern_kind != "bytes" && pattern_kind != "disasm")
        return tool_result_t::error("'pattern_kind' must be auto, bytes, or disasm.");
    if (byte_mode && byte_pattern.empty())
        return tool_result_t::error("Invalid pattern: " + pattern_error);
    const std::size_t max_slots = static_cast<std::size_t>(numeric_param(params, "max_slots", 256, 1, 1024));
    diag::log_tagged_fmt("vmt",
                         "find_slot enter pid=%u vtable=%s max_slots=%zu mode=%s deadline_remaining_ms=%llu diag_id=%s",
                         scope.pid(),
                         sa_format_address(vtable_va).c_str(),
                         max_slots,
                         byte_mode ? "bytes" : "disasm",
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    std::size_t slot_reads = 0;
    std::size_t pattern_reads = 0;
    std::size_t disasm_checks = 0;
    for (std::size_t i = 0; i < max_slots; ++i)
    {
        if ((i & 0x0Fu) == 0 && vmt_call_cancelled("find_slot_scan", scope.pid(), started_ms))
            return tool_result_t::error("VMT slot signature search cancelled.", vmt_cancel_detail("find_slot_by_signature", scope.pid(), started_ms));
        std::uint64_t fn = 0;
        ++slot_reads;
        if (!read_u64(scope.pid(), vtable_va + i * 8, fn) || fn == 0)
            break;
        json disasm_match_preview;
        bool matched = false;
        if (byte_mode)
        {
            std::vector<std::uint8_t> bytes;
            ++pattern_reads;
            if (!read_bytes(scope.pid(), fn, std::max<std::size_t>(byte_pattern.size(), 16), bytes) || bytes.size() < byte_pattern.size())
                continue;
            matched = pattern_matches(bytes.data(), bytes.size(), byte_pattern);
        }
        else
        {
            ++disasm_checks;
            matched = disasm_pattern_matches(scope.pid(), fn, disasm_pattern, &disasm_match_preview);
        }
        if (matched)
        {
            json result;
            result["slot"] = i;
            result["address"] = sa_format_address(fn);
            result["match_mode"] = byte_mode ? "bytes" : "disasm";
            result["hint"] = classify_function_hint(scope.pid(), fn);
            if (!byte_mode)
                result["disasm_match"] = std::move(disasm_match_preview);
            result["slot_reads"] = slot_reads;
            result["pattern_reads"] = pattern_reads;
            result["disasm_checks"] = disasm_checks;
            diag::log_tagged_fmt("vmt",
                                 "find_slot exit pid=%u matched=1 slot=%zu address=%s slot_reads=%zu pattern_reads=%zu disasm_checks=%zu elapsed_ms=%llu",
                                 scope.pid(),
                                 i,
                                 sa_format_address(fn).c_str(),
                                 slot_reads,
                                 pattern_reads,
                                 disasm_checks,
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return tool_result_t::ok(result);
        }
    }
    json result;
    result["slot"] = nullptr;
    result["address"] = nullptr;
    result["match_mode"] = byte_mode ? "bytes" : "disasm";
    result["slot_reads"] = slot_reads;
    result["pattern_reads"] = pattern_reads;
    result["disasm_checks"] = disasm_checks;
    diag::log_tagged_fmt("vmt",
                         "find_slot exit pid=%u matched=0 slot_reads=%zu pattern_reads=%zu disasm_checks=%zu elapsed_ms=%llu",
                         scope.pid(),
                         slot_reads,
                         pattern_reads,
                         disasm_checks,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("No matching VMT slot found.", result);
}

tool_result_t scan_objects(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t vtable_va = 0;
    if (!parse_address_param(params, "vtable_va", vtable_va) || vtable_va == 0)
        return tool_result_t::error("'vtable_va' is required.");
    const std::size_t max_results = static_cast<std::size_t>(numeric_param(params, "max_results", 512, 1, 10000));
    const auto needle = make_u64_pattern(vtable_va);
    json arr = json::array();
    std::size_t regions_considered = 0;
    std::size_t regions_read = 0;
    std::size_t read_failures = 0;
    std::size_t qwords_scanned = 0;
    diag::log_tagged_fmt("vmt",
                         "scan_objects enter pid=%u vtable=%s max_results=%zu deadline_remaining_ms=%llu diag_id=%s",
                         scope.pid(),
                         sa_format_address(vtable_va).c_str(),
                         max_results,
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    std::uint64_t object_va = 0;
    if (parse_address_param(params, "object_va", object_va) && object_va != 0)
    {
        std::uint64_t object_vtable = 0;
        if (read_u64(scope.pid(), object_va, object_vtable) && object_vtable == vtable_va)
        {
            driver_bridge::memory_region_t region{};
            json obj;
            obj["object_va"] = sa_format_address(object_va);
            if (query_region(scope.pid(), object_va, region))
                obj["region_info"] = region_json(region);
            arr.push_back(std::move(obj));
        }
    }
    std::vector<driver_bridge::memory_region_t> scan_regions;
    std::uint64_t range_base = 0;
    std::uint64_t range_size = 0;
    if (parse_address_param(params, "range_base", range_base) || parse_address_param(params, "scan_start_va", range_base))
    {
        if (!parse_address_param(params, "range_size", range_size) && !parse_address_param(params, "scan_size", range_size))
            range_size = 0x1000;
        driver_bridge::memory_region_t region{};
        if (query_region(scope.pid(), range_base, region) && is_readable(region))
        {
            const std::uint64_t region_end = region.base + region.size;
            if (region_end > range_base)
            {
                region.base = range_base;
                region.size = std::min<std::uint64_t>(range_size, region_end - range_base);
                scan_regions.push_back(region);
            }
        }
    }
    if (scan_regions.empty() && arr.empty())
        scan_regions = regions_for(scope.pid(), 8192);
    for (const auto& region : scan_regions)
    {
        if (arr.size() >= max_results)
            break;
        if (vmt_call_cancelled("scan_objects_regions", scope.pid(), started_ms))
            return tool_result_t::error("VMT object scan cancelled.", vmt_cancel_detail("scan_objects", scope.pid(), started_ms));
        ++regions_considered;
        if (!is_readable(region) || !is_writable(region) || region.size < 8 || region.size > 64ull * 1024ull * 1024ull)
            continue;
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(scope.pid(), region.base, static_cast<std::size_t>(region.size), bytes) || bytes.size() < 8)
        {
            ++read_failures;
            continue;
        }
        ++regions_read;
        for (std::size_t i = 0; i + 8 <= bytes.size(); i += 8)
        {
            ++qwords_scanned;
            if ((qwords_scanned & 0x3FFFu) == 0 && vmt_call_cancelled("scan_objects_qwords", scope.pid(), started_ms))
                return tool_result_t::error("VMT object scan cancelled.", vmt_cancel_detail("scan_objects", scope.pid(), started_ms));
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
    result["regions_considered"] = regions_considered;
    result["regions_read"] = regions_read;
    result["read_failures"] = read_failures;
    result["qwords_scanned"] = qwords_scanned;
    result["objects"] = std::move(arr);
    diag::log_tagged_fmt("vmt",
                         "scan_objects exit pid=%u returned=%zu regions_considered=%zu regions_read=%zu read_failures=%zu qwords=%zu elapsed_ms=%llu",
                         scope.pid(),
                         result["returned"].get<std::size_t>(),
                         regions_considered,
                         regions_read,
                         read_failures,
                         qwords_scanned,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}
}
