#include "../settings/standalone_compat.hpp"
#include "../re/dx_hook.hpp"
#include "../re/vmt.hpp"
#include "../re/rtti.hpp"
#include "../re/encptr.hpp"
#include "../re/offsets.hpp"
#include "../re/heap_track.hpp"
#include "../re/sigs.hpp"
#include "../re/struct_adv.hpp"

namespace re_tools
{
void register_re_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {"dx_find_device_vtable", "re.dx_hook",
        "Discover D3D11, D3D12, DXGI, or Vulkan draw/present targets using local dummy devices and target module RVA mapping.",
        {{"api", "string", "auto|d3d11|d3d12|dxgi|vulkan", false},
         {"process_id", "number", "Target process id", false}},
        re::dx_hook::find_device_vtable, true});

    register_compat(srv, {"dx_hook_manage", "re.dx_hook",
        "Manage DirectX/DXGI draw or present hardware-breakpoint hooks. Actions: draw, present, remove.",
        {{"action", "string", "draw|present|remove", true},
         {"process_id", "number", "Target process id", true},
         {"api", "string", "auto|d3d11|d3d12|vulkan", false},
         {"capture_cbuffers", "boolean", "Capture constant-buffer metadata when callback support is available", false},
         {"capture_vertex_buffers", "boolean", "Capture vertex-buffer metadata when callback support is available", false},
         {"max_captures", "number", "Maximum captures to retain", false},
         {"callback_mode", "string", "hw_bp|vmt_patch", false},
         {"confirm_unsafe", "boolean", "Required for hook installation/removal", false},
         {"allow_unsafe", "boolean", "Alias of confirm_unsafe", false}},
        re::dx_hook::hook_manage, false});

    register_compat(srv, {"dx_list_bound_cbuffers", "re.dx_hook",
        "List constant buffers captured by active DX draw hooks.",
        {{"process_id", "number", "Target process id", true},
         {"api", "string", "Optional API filter", false}},
        re::dx_hook::list_bound_cbuffers, true});

    register_compat(srv, {"dx_identify_bone_buffer", "re.dx_hook",
        "Heuristically find matrix/bone buffers in readable writable process memory.",
        {{"process_id", "number", "Target process id", true},
         {"world_unit_max", "number", "Maximum plausible translation component", false},
         {"min_bones", "number", "Minimum matrix count", false},
         {"max_bones", "number", "Maximum matrix count", false}},
        re::dx_hook::identify_bone_buffer, true});

    register_compat(srv, {"dx_map_resource_to_va", "re.dx_hook",
        "Inspect a D3D resource or descriptor object for candidate CPU-side backing pointers.",
        {{"resource_handle", "string", "Resource object or descriptor address", true},
         {"process_id", "number", "Target process id", true}},
        re::dx_hook::map_resource_to_va, true});

    register_compat(srv, {"dx_dump_render_targets", "re.dx_hook",
        "Attempt render-target capture for the current DX hook context.",
        {{"process_id", "number", "Target process id", true},
         {"format", "string", "rgba|png", false},
         {"output_path", "string", "Optional output path", false},
         {"confirm_unsafe", "boolean", "Required when writing files or installing capture callbacks", false},
         {"allow_unsafe", "boolean", "Alias of confirm_unsafe", false}},
        re::dx_hook::dump_render_targets, false});

    register_compat(srv, {"dx_find_view_matrix", "re.dx_hook",
        "Find plausible view/projection matrices in captured buffers or process memory.",
        {{"process_id", "number", "Target process id", true},
         {"scan_cbuffers_only", "boolean", "Restrict to captured constant buffers", false}},
        re::dx_hook::find_view_matrix, true});

    register_compat(srv, {"vmt_read", "re.vmt",
        "Read and classify virtual method table slots from an object or vtable-pointer address.",
        {{"address", "string", "Address containing a vtable pointer", true},
         {"max_slots", "number", "Maximum slots to read", false},
         {"process_id", "number", "Target process id", false}},
        re::vmt::read, true});

    register_compat(srv, {"vmt_hook_manage", "re.vmt",
        "Install, remove, or list VMT slot hooks. Actions: install, remove, list.",
        {{"action", "string", "install|remove|list", true},
         {"hook_id", "string", "Hook id for remove", false},
         {"vtable_va", "string", "Vtable base for install", false},
         {"object_va", "string", "Object address for patch_object mode", false},
         {"slot", "number", "Vtable slot index", false},
         {"callback_va", "string", "Replacement callback address", false},
         {"method", "string", "patch_vtable|patch_object", false},
         {"process_id", "number", "Target process id", false},
         {"confirm_unsafe", "boolean", "Required for install/remove", false},
         {"allow_unsafe", "boolean", "Alias of confirm_unsafe", false}},
        re::vmt::hook_manage, false});

    register_compat(srv, {"vmt_copy", "re.vmt",
        "Copy an object's VMT into remote memory and patch only that object to the copy.",
        {{"object_va", "string", "Object address", true},
         {"process_id", "number", "Target process id", false},
         {"max_slots", "number", "Maximum slots to copy", false},
         {"confirm_unsafe", "boolean", "Required", false},
         {"allow_unsafe", "boolean", "Alias of confirm_unsafe", false}},
        re::vmt::copy, false});

    register_compat(srv, {"vmt_find_slot_by_signature", "re.vmt",
        "Find a VMT slot whose function prologue matches a hex pattern with wildcards.",
        {{"vtable_va", "string", "Vtable base", true},
         {"pattern", "string", "Hex pattern with ?? wildcards", true},
         {"max_slots", "number", "Maximum slots to scan", false},
         {"process_id", "number", "Target process id", false}},
        re::vmt::find_slot_by_signature, true});

    register_compat(srv, {"vmt_scan_objects", "re.vmt",
        "Scan readable writable memory for objects whose first pointer equals the given vtable.",
        {{"vtable_va", "string", "Vtable address", true},
         {"process_id", "number", "Target process id", false},
         {"max_results", "number", "Maximum objects to return", false}},
        re::vmt::scan_objects, true});

    register_compat(srv, {"rtti_scan", "re.rtti",
        "Scan live module RTTI TypeDescriptor and CompleteObjectLocator records.",
        {{"module_name", "string", "Optional module name", false},
         {"filter", "string", "Optional regex filter", false},
         {"process_id", "number", "Target process id", false},
         {"max_results", "number", "Maximum types to return", false}},
        re::rtti::scan, true});

    register_compat(srv, {"rtti_find_type", "re.rtti",
        "Find RTTI types matching a regex pattern.",
        {{"pattern", "string", "Name regex", true},
         {"process_id", "number", "Target process id", false}},
        re::rtti::find_type, true});

    register_compat(srv, {"rtti_list_hierarchy", "re.rtti",
        "List inheritance hierarchy for an RTTI type name or vtable/type descriptor VA.",
        {{"type_name_or_va", "string", "Type substring or address", true},
         {"process_id", "number", "Target process id", false}},
        re::rtti::list_hierarchy, true});

    register_compat(srv, {"rtti_find_constructor", "re.rtti",
        "Find constructor candidates that reference a given vtable.",
        {{"vtable_va", "string", "Vtable address", true},
         {"process_id", "number", "Target process id", false}},
        re::rtti::find_constructor, true});

    register_compat(srv, {"encptr_scan_chain", "re.encptr",
        "Scan for raw and transformed pointer chains connecting source_va to target_va.",
        {{"source_va", "string", "Source pointer slot or base address", true},
         {"target_va", "string", "Expected target address", true},
         {"max_hops", "number", "Maximum chain depth", false},
          {"max_offset", "number", "Maximum signed field offset per hop", false},
          {"max_results", "number", "Maximum paths to return", false},
          {"test_xor", "boolean", "Test XOR transforms", false},
          {"test_rol", "boolean", "Test rotate transforms", false},
          {"test_add", "boolean", "Test add/sub transforms", false},
          {"xor_key", "string", "Optional known XOR key", false},
          {"xor_keys", "array", "Optional known XOR keys", false},
          {"add_keys", "array", "Optional known add constants", false},
          {"sub_keys", "array", "Optional known sub constants", false},
          {"process_id", "number", "Target process id", false}},
        re::encptr::scan_chain, true});

    register_compat(srv, {"encptr_detect_transform", "re.encptr",
        "Detect a single-hop transform between raw_value and expected_next.",
        {{"raw_value", "string", "Raw value", true},
          {"expected_next", "string", "Expected transformed value", true},
          {"address_va", "string", "Optional source slot address for XOR-with-address detection", false}},
        re::encptr::detect_transform, true});

    register_compat(srv, {"encptr_emit_resolver", "re.encptr",
        "Emit C++ resolver code for an encoded pointer chain.",
        {{"chain", "object", "Chain object from encptr_scan_chain", true},
         {"function_name", "string", "Generated function name", false},
         {"base_symbol", "string", "Generated base symbol parameter", false}},
        re::encptr::emit_resolver, true});

    register_compat(srv, {"encptr_verify_stable", "re.encptr",
        "Sample a resolved encoded pointer chain repeatedly and classify stability.",
        {{"chain", "object", "Chain object", true},
         {"samples", "number", "Sample count", false},
         {"interval_ms", "number", "Interval between samples", false},
         {"process_id", "number", "Target process id", false}},
        re::encptr::verify_stable, true});

    register_compat(srv, {"offsets_manage", "re.offsets",
        "Manage persisted offsets. Actions: record, list, reverify, rebase, export.",
        {{"action", "string", "record|list|reverify|rebase|export", true},
          {"payload", "object", "Action-specific payload", false},
          {"name", "string", "Offset name for record/export identifier", false},
          {"va", "string", "Live offset VA for record", false},
          {"category", "string", "Category filter or record category", false},
          {"notes", "string", "Record notes", false},
          {"aob_pattern", "string", "AoB fingerprint for record/reverify", false},
          {"rtti_path", "string", "RTTI path evidence for record", false},
          {"xref_context", "string", "Xref context evidence for record", false},
          {"verified_only", "boolean", "List only valid offsets", false},
          {"offset_id", "string", "Single offset id for reverify/rebase", false},
          {"offset_ids", "array", "Offset ids for reverify/rebase", false},
          {"module_name", "string", "Module filter for reverify/rebase", false},
          {"output_path", "string", "Export output path", false},
          {"namespace_name", "string", "C++ namespace for export", false},
          {"use_rva", "boolean", "Export RVAs instead of VAs", false},
          {"process_id", "number", "Target process id", false},
          {"confirm_unsafe", "boolean", "Required for actions that write persistence or files", false},
          {"allow_unsafe", "boolean", "Alias of confirm_unsafe", false}},
        re::offsets::manage, false});

    register_compat(srv, {"heap_track_manage", "re.heap_track",
        "Manage heap allocation tracking sessions. Actions: start, results, stop.",
        {{"action", "string", "start|results|stop", true},
         {"payload", "object", "Action-specific payload", false},
         {"confirm_unsafe", "boolean", "Required for start and stop", false},
         {"allow_unsafe", "boolean", "Alias of confirm_unsafe", false}},
        re::heap_track::manage, false});

    register_compat(srv, {"sigs_manage", "re.sigs",
        "Manage persisted pattern signatures. Actions: save, list, scan_all, import, export.",
        {{"action", "string", "save|list|scan_all|import|export", true},
          {"payload", "object", "Action-specific payload", false},
          {"name", "string", "Signature name for save", false},
          {"pattern", "string", "AoB pattern for save", false},
          {"module_hint", "string", "Module scope hint or filter", false},
          {"category", "string", "Category filter or record category", false},
          {"notes", "string", "Record notes", false},
          {"offset_from_match", "number", "VA adjustment from pattern match", false},
          {"source", "string", "Import file path or inline content", false},
          {"format", "string", "json|ida|x64dbg|ce", false},
          {"output_path", "string", "Export output path", false},
          {"process_id", "number", "Target process id for scan_all", false},
          {"confirm_unsafe", "boolean", "Required for actions that write persistence or files", false},
          {"allow_unsafe", "boolean", "Alias of confirm_unsafe", false}},
        re::sigs::manage, false});

    register_compat(srv, {"struct_observe", "re.struct_adv",
        "Observe a struct region and infer fields using the existing struct reconstruction engine.",
        {{"base_va", "string", "Struct base address", true},
         {"size", "number", "Struct size", false},
         {"duration_sec", "number", "Observation duration", false},
         {"timeout_ms", "number", "Maximum observation wait time", false},
         {"process_id", "number", "Target process id", false},
         {"confirm_unsafe", "boolean", "Required to arm observation breakpoints", false},
         {"allow_unsafe", "boolean", "Alias of confirm_unsafe", false}},
        re::struct_adv::observe, false});

    register_compat(srv, {"struct_correlate", "re.struct_adv",
        "Correlate separately found field addresses into a probable struct base and offsets.",
        {{"field_addresses", "array", "Array of {name, va}", true},
         {"max_span", "number", "Maximum candidate struct span", false},
         {"process_id", "number", "Target process id for type previews", false}},
        re::struct_adv::correlate, true});

    register_compat(srv, {"struct_array_detect", "re.struct_adv",
        "Check whether base_va is the start of repeated struct-like elements.",
        {{"base_va", "string", "Array base address", true},
          {"suspected_size", "number", "Suspected element size", true},
          {"max_elements", "number", "Maximum elements to inspect", false},
          {"process_id", "number", "Target process id", false}},
        re::struct_adv::array_detect, true});

    register_compat(srv, {"struct_compare_snapshots", "re.struct_adv",
        "Compare two RE or scanner snapshots for a struct region.",
        {{"snapshot_a_id", "string", "First snapshot id or name", true},
         {"snapshot_b_id", "string", "Second snapshot id or name", true},
         {"base_va", "string", "Struct base address", true},
         {"struct_size", "number", "Struct size", false}},
        re::struct_adv::compare_snapshots, true});
}
}
