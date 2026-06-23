#include "artifact_store.hpp"

#include <atomic>

namespace re::store
{
namespace
{
std::atomic<std::uint64_t> g_id_counter{1};
std::mutex& store_mutex()
{
    static std::mutex m;
    return m;
}

std::map<std::string, dx_hook_record_t>& dx_hooks()
{
    static std::map<std::string, dx_hook_record_t> hooks;
    return hooks;
}

std::map<std::string, vmt_hook_record_t>& vmt_hooks()
{
    static std::map<std::string, vmt_hook_record_t> hooks;
    return hooks;
}

std::map<std::string, heap_session_t>& heap_sessions()
{
    static std::map<std::string, heap_session_t> sessions;
    return sessions;
}

std::map<std::string, memory_snapshot_t>& memory_snapshots()
{
    static std::map<std::string, memory_snapshot_t> snapshots;
    return snapshots;
}

std::filesystem::path offsets_path()
{
    return appdata_re_dir() / "offsets.json";
}

std::filesystem::path signatures_path()
{
    return appdata_re_dir() / "signatures.json";
}
}

std::string next_id(const char* prefix)
{
    const std::uint64_t value = g_id_counter.fetch_add(1, std::memory_order_relaxed);
    return std::string(prefix ? prefix : "re") + "_" + std::to_string(unix_time_ms()) + "_" + std::to_string(value);
}

json offset_to_json(const offset_record_t& record)
{
    json out;
    out["id"] = record.id;
    out["name"] = record.name;
    out["category"] = record.category;
    out["notes"] = record.notes;
    out["process_id"] = record.pid;
    out["va"] = sa_format_address(record.va);
    out["module_name"] = record.module_name;
    out["module_rva"] = sa_format_address(record.module_rva);
    out["aob_pattern"] = record.aob_pattern;
    out["rtti_path"] = record.rtti_path;
    out["xref_context"] = record.xref_context;
    if (!record.fingerprint.is_null() && !record.fingerprint.empty())
        out["fingerprint"] = record.fingerprint;
    out["status"] = record.status;
    out["last_found_va"] = sa_format_address(record.last_found_va);
    out["created_ms"] = record.created_ms;
    out["updated_ms"] = record.updated_ms;
    return out;
}

offset_record_t offset_from_json(const json& value)
{
    offset_record_t record;
    record.id = value.value("id", std::string());
    record.name = value.value("name", std::string());
    record.category = value.value("category", std::string());
    record.notes = value.value("notes", std::string());
    record.pid = value.value("process_id", 0u);
    if (value.contains("va")) parse_u64_value(value["va"], record.va);
    record.module_name = value.value("module_name", std::string());
    if (value.contains("module_rva")) parse_u64_value(value["module_rva"], record.module_rva);
    record.aob_pattern = value.value("aob_pattern", std::string());
    record.rtti_path = value.value("rtti_path", std::string());
    record.xref_context = value.value("xref_context", std::string());
    if (value.contains("fingerprint") && value["fingerprint"].is_object())
        record.fingerprint = value["fingerprint"];
    record.status = value.value("status", std::string());
    if (value.contains("last_found_va")) parse_u64_value(value["last_found_va"], record.last_found_va);
    record.created_ms = value.value("created_ms", 0ull);
    record.updated_ms = value.value("updated_ms", 0ull);
    return record;
}

std::vector<offset_record_t> load_offsets()
{
    json root;
    std::vector<offset_record_t> out;
    if (!read_json_file(offsets_path(), root))
        return out;
    const json* arr = nullptr;
    if (root.is_array())
        arr = &root;
    else if (root.contains("offsets") && root["offsets"].is_array())
        arr = &root["offsets"];
    if (!arr)
        return out;
    for (const auto& item : *arr)
        out.push_back(offset_from_json(item));
    return out;
}

bool save_offsets(const std::vector<offset_record_t>& records)
{
    json root;
    root["version"] = 1;
    root["updated_ms"] = unix_time_ms();
    root["offsets"] = json::array();
    for (const auto& record : records)
        root["offsets"].push_back(offset_to_json(record));
    return write_json_file_atomic(offsets_path(), root);
}

json signature_to_json(const signature_record_t& record)
{
    json out;
    out["id"] = record.id;
    out["name"] = record.name;
    out["pattern"] = record.pattern;
    out["module_hint"] = record.module_hint;
    out["category"] = record.category;
    out["notes"] = record.notes;
    out["offset_from_match"] = record.offset_from_match;
    out["last_status"] = record.last_status;
    out["last_va"] = sa_format_address(record.last_va);
    out["last_match_count"] = record.last_match_count;
    out["created_ms"] = record.created_ms;
    out["updated_ms"] = record.updated_ms;
    return out;
}

signature_record_t signature_from_json(const json& value)
{
    signature_record_t record;
    record.id = value.value("id", std::string());
    record.name = value.value("name", std::string());
    record.pattern = value.value("pattern", std::string());
    record.module_hint = value.value("module_hint", std::string());
    record.category = value.value("category", std::string());
    record.notes = value.value("notes", std::string());
    record.offset_from_match = value.value("offset_from_match", 0ll);
    record.last_status = value.value("last_status", std::string());
    if (value.contains("last_va")) parse_u64_value(value["last_va"], record.last_va);
    record.last_match_count = value.value("last_match_count", 0u);
    record.created_ms = value.value("created_ms", 0ull);
    record.updated_ms = value.value("updated_ms", 0ull);
    return record;
}

std::vector<signature_record_t> load_signatures()
{
    json root;
    std::vector<signature_record_t> out;
    if (!read_json_file(signatures_path(), root))
        return out;
    const json* arr = nullptr;
    if (root.is_array())
        arr = &root;
    else if (root.contains("signatures") && root["signatures"].is_array())
        arr = &root["signatures"];
    if (!arr)
        return out;
    for (const auto& item : *arr)
        out.push_back(signature_from_json(item));
    return out;
}

bool save_signatures(const std::vector<signature_record_t>& records)
{
    json root;
    root["version"] = 1;
    root["updated_ms"] = unix_time_ms();
    root["signatures"] = json::array();
    for (const auto& record : records)
        root["signatures"].push_back(signature_to_json(record));
    return write_json_file_atomic(signatures_path(), root);
}

void add_dx_hook(dx_hook_record_t record)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    dx_hooks()[record.id] = std::move(record);
}

std::vector<dx_hook_record_t> list_dx_hooks(std::uint32_t pid)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<dx_hook_record_t> out;
    for (const auto& [id, record] : dx_hooks())
    {
        (void)id;
        if (pid == 0 || record.pid == pid)
            out.push_back(record);
    }
    return out;
}

std::size_t remove_dx_hooks(std::uint32_t pid)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::size_t removed = 0;
    for (auto it = dx_hooks().begin(); it != dx_hooks().end();)
    {
        if (pid == 0 || it->second.pid == pid)
        {
            it = dx_hooks().erase(it);
            ++removed;
        }
        else
        {
            ++it;
        }
    }
    return removed;
}

bool remove_dx_hook(const std::string& id, dx_hook_record_t* removed)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    auto it = dx_hooks().find(id);
    if (it == dx_hooks().end())
        return false;
    if (removed)
        *removed = it->second;
    dx_hooks().erase(it);
    return true;
}

bool update_dx_hook(const dx_hook_record_t& record)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    auto it = dx_hooks().find(record.id);
    if (it == dx_hooks().end())
        return false;
    it->second = record;
    return true;
}

void add_vmt_hook(vmt_hook_record_t record)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    vmt_hooks()[record.id] = std::move(record);
}

std::vector<vmt_hook_record_t> list_vmt_hooks(std::uint32_t pid)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<vmt_hook_record_t> out;
    for (const auto& [id, record] : vmt_hooks())
    {
        (void)id;
        if (pid == 0 || record.pid == pid)
            out.push_back(record);
    }
    return out;
}

bool find_vmt_hook(const std::string& id, vmt_hook_record_t& out)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    auto it = vmt_hooks().find(id);
    if (it == vmt_hooks().end())
        return false;
    out = it->second;
    return true;
}

bool remove_vmt_hook(const std::string& id, vmt_hook_record_t* removed)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    auto it = vmt_hooks().find(id);
    if (it == vmt_hooks().end())
        return false;
    if (removed)
        *removed = it->second;
    vmt_hooks().erase(it);
    return true;
}

void add_heap_session(heap_session_t session)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    heap_sessions()[session.id] = std::move(session);
}

bool update_heap_session(const heap_session_t& session)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    auto it = heap_sessions().find(session.id);
    if (it == heap_sessions().end())
        return false;
    it->second = session;
    return true;
}

bool find_heap_session(const std::string& id, heap_session_t& out)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    auto it = heap_sessions().find(id);
    if (it == heap_sessions().end())
        return false;
    out = it->second;
    return true;
}

std::vector<heap_session_t> list_heap_sessions(std::uint32_t pid)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<heap_session_t> out;
    for (const auto& [id, session] : heap_sessions())
    {
        (void)id;
        if (pid == 0 || session.pid == pid)
            out.push_back(session);
    }
    return out;
}

bool remove_heap_session(const std::string& id, heap_session_t* removed)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    auto it = heap_sessions().find(id);
    if (it == heap_sessions().end())
        return false;
    if (removed)
        *removed = it->second;
    heap_sessions().erase(it);
    return true;
}

void add_memory_snapshot(memory_snapshot_t snapshot)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    memory_snapshots()[snapshot.id] = std::move(snapshot);
}

bool find_memory_snapshot(const std::string& id, memory_snapshot_t& out)
{
    std::lock_guard<std::mutex> lock(store_mutex());
    auto it = memory_snapshots().find(id);
    if (it == memory_snapshots().end())
        return false;
    out = it->second;
    return true;
}

std::vector<memory_snapshot_t> list_memory_snapshots()
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<memory_snapshot_t> out;
    for (const auto& [id, snapshot] : memory_snapshots())
    {
        (void)id;
        out.push_back(snapshot);
    }
    return out;
}
}
