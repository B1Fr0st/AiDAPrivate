#pragma once

#include "re_common.hpp"

#include <map>
#include <mutex>
#include <optional>

namespace re::store
{
struct dx_hook_record_t
{
    std::string id;
    std::uint32_t pid = 0;
    std::string api;
    std::string action;
    std::uint64_t target_va = 0;
    std::string target_name;
    std::vector<std::uint32_t> tids;
    int hw_slot = 0;
    bool capture_cbuffers = false;
    bool capture_vertex_buffers = false;
    std::uint32_t max_captures = 0;
    std::vector<json> captures;
    std::uint64_t created_ms = 0;
};

struct draw_call_info_t
{
    std::uint64_t timestamp_ms = 0;
    std::uint32_t index_count = 0;
    std::uint32_t vertex_count = 0;
    std::uint32_t start_index = 0;
    std::uint32_t instance_count = 0;
    std::uint32_t start_vertex = 0;
    int base_vertex = 0;
    std::string draw_kind;
    std::string likely_mesh_type;
    std::uint64_t preceding_cbuffer_va = 0;
    int preceding_cbuffer_slot = -1;
    std::uint64_t preceding_cbuffer_timestamp_ms = 0;
    std::uint32_t frame_index = 0;
    std::uint32_t draw_ordinal = 0;
};

struct frame_batch_t
{
    std::uint32_t pid = 0;
    std::uint32_t frame_index = 0;
    std::uint64_t start_timestamp_ms = 0;
    std::uint64_t end_timestamp_ms = 0;
    std::vector<draw_call_info_t> draw_calls;
    std::vector<std::pair<std::uint64_t, int>> cbuffer_binds;
    std::vector<std::pair<std::uint64_t, int>> vertex_buffer_binds;
    std::uint32_t total_draw_count = 0;
    std::uint32_t character_draw_count = 0;
    std::uint32_t weapon_draw_count = 0;
    std::uint32_t world_draw_count = 0;
};

enum class cbuffer_class_t : std::uint8_t
{
    unknown = 0,
    persistent,
    per_draw,
    static_bind
};

struct cbuffer_classification_t
{
    std::uint64_t va = 0;
    int slot = -1;
    std::uint32_t pid = 0;
    cbuffer_class_t classification = cbuffer_class_t::unknown;
    std::uint32_t frames_seen = 0;
    std::uint32_t total_binds = 0;
    std::uint32_t distinct_draw_calls = 0;
    double frequency_score = 0.0;
    std::string recommended_for;
    std::vector<std::uint32_t> frame_indices;
    std::vector<draw_call_info_t> associated_draw_calls;
};

struct hot_va_entry_t
{
    std::uint64_t va = 0;
    int slot = -1;
    std::uint32_t pid = 0;
    std::uint32_t hit_count = 0;
    std::uint32_t frame_count = 0;
    std::uint64_t first_seen_ms = 0;
    std::uint64_t last_seen_ms = 0;
    double confidence_boost = 0.0;
};

struct vmt_hook_record_t
{
    std::string id;
    std::uint32_t pid = 0;
    std::uint64_t vtable_va = 0;
    std::uint64_t object_va = 0;
    std::uint32_t slot = 0;
    std::uint64_t slot_va = 0;
    std::uint64_t callback_va = 0;
    std::uint64_t original_fn_va = 0;
    std::uint64_t trampoline_va = 0;
    std::uint64_t copied_vtable_va = 0;
    std::string method;
    std::uint64_t created_ms = 0;
};

struct heap_capture_t
{
    std::uint64_t va = 0;
    std::uint64_t size = 0;
    std::uint64_t alignment = 0;
    std::vector<std::uint64_t> callstack;
    std::uint64_t timestamp_ms = 0;
};

struct heap_session_t
{
    std::string id;
    std::uint32_t pid = 0;
    std::uint64_t min_size = 0;
    std::uint64_t max_size = 0;
    std::uint64_t alignment = 0;
    bool capture_callstack = true;
    std::uint32_t max_captures = 0;
    bool active = true;
    std::uint64_t started_ms = 0;
    std::uint64_t rtl_allocate_heap = 0;
    int hw_slot = 0;
    std::vector<std::uint32_t> tids;
    std::vector<heap_capture_t> baseline;
    std::vector<heap_capture_t> captures;
};

struct offset_record_t
{
    std::string id;
    std::string name;
    std::string category;
    std::string notes;
    std::uint32_t pid = 0;
    std::uint64_t va = 0;
    std::string module_name;
    std::uint64_t module_rva = 0;
    std::string aob_pattern;
    std::string rtti_path;
    std::string xref_context;
    json fingerprint;
    std::string status;
    std::uint64_t last_found_va = 0;
    std::uint64_t created_ms = 0;
    std::uint64_t updated_ms = 0;
};

struct signature_record_t
{
    std::string id;
    std::string name;
    std::string pattern;
    std::string module_hint;
    std::string category;
    std::string notes;
    std::int64_t offset_from_match = 0;
    std::string last_status;
    std::uint64_t last_va = 0;
    std::uint32_t last_match_count = 0;
    std::uint64_t created_ms = 0;
    std::uint64_t updated_ms = 0;
};

struct memory_snapshot_t
{
    std::string id;
    std::uint32_t pid = 0;
    std::uint64_t base_va = 0;
    std::uint64_t size = 0;
    std::vector<std::uint8_t> data;
    std::uint64_t created_ms = 0;
};

struct decryption_trace_record_t
{
    std::string id;
    std::uint32_t pid = 0;
    std::uint64_t staging_va = 0;
    std::uint64_t staging_size = 0;
    std::uint64_t decryption_func_va = 0;
    std::uint64_t encrypted_source_va = 0;
    std::uint64_t encrypted_source_size = 0;
    std::string algorithm_name;
    std::vector<std::uint8_t> derived_key_bytes;
    std::uint32_t key_length = 0;
    std::string key_pattern;
    bool verified = false;
    std::string verification_detail;
    std::uint64_t caller_rip = 0;
    std::vector<std::uint64_t> callstack;
    json register_snapshot;
    std::vector<std::uint8_t> cleartext_sample;
    std::vector<std::uint8_t> encrypted_sample;
    std::uint64_t created_ms = 0;
    std::uint64_t frame_index = 0;
    int hw_slot = 0;
    std::string status;
};

std::string next_id(const char* prefix);

std::vector<offset_record_t> load_offsets();
bool save_offsets(const std::vector<offset_record_t>& records);
json offset_to_json(const offset_record_t& record);
offset_record_t offset_from_json(const json& value);

std::vector<signature_record_t> load_signatures();
bool save_signatures(const std::vector<signature_record_t>& records);
json signature_to_json(const signature_record_t& record);
signature_record_t signature_from_json(const json& value);

void add_dx_hook(dx_hook_record_t record);
std::vector<dx_hook_record_t> list_dx_hooks(std::uint32_t pid = 0);
std::size_t remove_dx_hooks(std::uint32_t pid);
bool remove_dx_hook(const std::string& id, dx_hook_record_t* removed = nullptr);
bool update_dx_hook(const dx_hook_record_t& record);

void add_vmt_hook(vmt_hook_record_t record);
std::vector<vmt_hook_record_t> list_vmt_hooks(std::uint32_t pid = 0);
bool find_vmt_hook(const std::string& id, vmt_hook_record_t& out);
bool remove_vmt_hook(const std::string& id, vmt_hook_record_t* removed = nullptr);

void add_heap_session(heap_session_t session);
bool update_heap_session(const heap_session_t& session);
bool find_heap_session(const std::string& id, heap_session_t& out);
std::vector<heap_session_t> list_heap_sessions(std::uint32_t pid = 0);
bool remove_heap_session(const std::string& id, heap_session_t* removed = nullptr);

void add_memory_snapshot(memory_snapshot_t snapshot);
bool find_memory_snapshot(const std::string& id, memory_snapshot_t& out);
std::vector<memory_snapshot_t> list_memory_snapshots();

void add_decryption_trace(decryption_trace_record_t record);
bool find_decryption_trace(const std::string& id, decryption_trace_record_t& out);
std::vector<decryption_trace_record_t> list_decryption_traces(std::uint32_t pid = 0);
bool remove_decryption_trace(const std::string& id, decryption_trace_record_t* removed = nullptr);
std::size_t remove_decryption_traces(std::uint32_t pid);

void add_frame_batch(frame_batch_t batch);
std::vector<frame_batch_t> list_frame_batches(std::uint32_t pid);
void clear_frame_batches(std::uint32_t pid);
std::optional<frame_batch_t> latest_frame_batch(std::uint32_t pid);

void add_hot_va(hot_va_entry_t entry);
std::vector<hot_va_entry_t> list_hot_vas(std::uint32_t pid);
void clear_hot_vas(std::uint32_t pid);
void update_hot_va(const hot_va_entry_t& entry);

void add_cbuffer_classification(cbuffer_classification_t classification);
std::vector<cbuffer_classification_t> list_cbuffer_classifications(std::uint32_t pid);
void clear_cbuffer_classifications(std::uint32_t pid);
}
