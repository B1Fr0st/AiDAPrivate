#include "standalone_compat.hpp"
#include "../protected_re/protected_re_core.hpp"

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace protected_re_tools {

void register_protected_re_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "vm_identify", "protected_re",
        "Detect virtual-machine protection indicators around a VM prologue and return dispatcher, handler-table, register, confidence, and evidence fields.",
        {{"address", "string", "VA inside the VM prologue", true},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::vm_identify, true});

    register_compat(srv, {
        "vm_trace_bytecode", "protected_re",
        "Snapshot a live thread and emulate a VM entry offline to record bounded dispatch steps, side effects, and opcode-map matches when evidence is supplied.",
        {{"entry_va", "string", "VM entry point", true},
         {"max_steps", "number", "Maximum emulated instructions", false},
         {"max_returned_steps", "number", "Maximum dispatch steps returned", false},
         {"handler_table_va", "string", "Optional VM handler table for opcode matching", false},
         {"handler_count", "number", "Optional handler table count", false},
         {"opcode_map", "object", "Optional vm_build_opcode_map output", false},
         {"tid", "number", "Thread id to snapshot", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::vm_trace_bytecode, true});

    register_compat(srv, {
        "vm_classify_handler", "protected_re",
        "Classify a VM handler using bounded static decoding and differential offline emulation where available.",
        {{"handler_va", "string", "VM handler address", true},
         {"handler_size", "number", "Handler byte range", false},
         {"num_test_inputs", "number", "Synthetic input count", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::vm_classify_handler, true});

    register_compat(srv, {
        "vm_build_opcode_map", "protected_re",
        "Classify every executable pointer in a VM handler table into a bounded opcode semantic map.",
        {{"handler_table_va", "string", "VM handler table address", true},
         {"handler_count", "number", "Number of handler pointers", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::vm_build_opcode_map, true});

    register_compat(srv, {
        "vm_lift_to_il", "protected_re",
        "Lift VM trace steps and an opcode map into a compact architecture-neutral IL.",
        {{"trace", "object", "vm_trace_bytecode output or steps array", true},
         {"opcode_map", "object", "vm_build_opcode_map output or opcode_map object", true},
         {"optimize", "boolean", "Apply local IL simplifications", false}},
        protected_re::vm_lift_to_il, true});

    register_compat(srv, {
        "vm_recover_cfg", "protected_re",
        "Recover a basic control-flow graph from optimized VM IL.",
        {{"optimized_il", "object", "vm_lift_to_il output", true}},
        protected_re::vm_recover_cfg, true});

    register_compat(srv, {
        "vm_emit_pseudocode", "protected_re",
        "Emit C-like or asm-comment pseudocode from a recovered VM CFG.",
        {{"cfg", "object", "vm_recover_cfg output", true},
         {"style", "string", "c or asm_comments", false}},
        protected_re::vm_emit_pseudocode, true});

    register_compat(srv, {
        "cff_detect", "protected_re",
        "Detect control-flow flattening indicators in a bounded function region.",
        {{"address", "string", "Function entry address", true},
         {"size", "number", "Bytes to analyze", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::cff_detect, true});

    register_compat(srv, {
        "cff_recover_cfg", "protected_re",
        "Recover a heuristic CFG from flattened control flow and emit DOT plus pseudocode.",
        {{"address", "string", "Function entry address", true},
         {"state_var_hint", "string", "Optional known state variable", false},
         {"size", "number", "Bytes to analyze", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::cff_recover_cfg, true});

    register_compat(srv, {
        "mba_simplify", "protected_re",
        "Simplify recognizable mixed boolean arithmetic instruction windows with proof/evidence metadata.",
        {{"address", "string", "Region start address", true},
         {"size", "number", "Region size", false},
         {"use_z3", "boolean", "Request Z3-backed proof where backend support exists", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::mba_simplify, true});

    register_compat(srv, {
        "opaque_predicate_detect", "protected_re",
        "Find syntactically provable opaque predicates in a bounded code region.",
        {{"address", "string", "Region start address", true},
         {"size", "number", "Region size", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::opaque_predicate_detect, true});

    register_compat(srv, {
        "opaque_predicate_patch", "protected_re",
        "Patch detected opaque predicates using NOPs or unconditional jumps after explicit unsafe confirmation.",
        {{"predicates", "array", "Predicates from opaque_predicate_detect", true},
         {"confirm_unsafe", "boolean", "Required to mutate target code", false},
         {"allow_unsafe", "boolean", "Alternative unsafe confirmation", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::opaque_predicate_patch, false});

    register_compat(srv, {
        "bogus_block_remove", "protected_re",
        "Identify unreachable and opaque-guarded bogus blocks without mutating the target.",
        {{"address", "string", "Function entry address", true},
         {"size", "number", "Region size", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::bogus_block_remove, true});

    register_compat(srv, {
        "drv_find_dispatch_table", "protected_re",
        "Locate DRIVER_OBJECT MajorFunction assignments in a selected kernel driver's DriverEntry.",
        {{"driver_name", "string", "Kernel driver name or path filter", false},
         {"module_base", "string", "Kernel module base", false},
         {"auto_select_wdm_driver", "boolean", "Select a loaded non-ntoskrnl WDM driver with accepted MajorFunction assignments", false},
         {"max_auto_modules", "number", "Maximum loaded kernel modules to scan during auto-selection", false},
         {"timeout_ms", "number", "Internal dispatch scan budget in milliseconds", false},
         {"max_candidates", "number", "Maximum MajorFunction assignment candidates to inspect", false},
         {"max_entry_bytes", "number", "Maximum DriverEntry bytes to read and disassemble", false},
         {"max_entry_instructions", "number", "Maximum DriverEntry instructions to decode", false},
         {"process_id", "number", "Reserved for compatibility", false}},
        protected_re::drv_find_dispatch_table, true});

    register_compat(srv, {
        "drv_decode_irp_handlers", "protected_re",
        "Decode IRP handlers found by drv_find_dispatch_table and return bounded previews.",
        {{"dispatch_table", "object", "drv_find_dispatch_table output", true}},
        protected_re::drv_decode_irp_handlers, true});

    register_compat(srv, {
        "drv_find_ioctl_dispatch", "protected_re",
        "Locate IOCTL comparison and dispatch patterns inside an IRP_MJ_DEVICE_CONTROL handler.",
        {{"device_control_handler_va", "string", "Device control handler address", true}},
        protected_re::drv_find_ioctl_dispatch, true});

    register_compat(srv, {
        "drv_enumerate_ioctls", "protected_re",
        "Decode IOCTL bitfields and surface buffer-method risk metadata.",
        {{"ioctl_handlers", "array", "Handlers from drv_find_ioctl_dispatch", true}},
        protected_re::drv_enumerate_ioctls, true});

    register_compat(srv, {
        "drv_find_device_names", "protected_re",
        "Find kernel driver device and symbolic-link strings in bounded loaded module scans.",
        {{"driver_name", "string", "Optional kernel driver name or path filter", false},
         {"module_base", "string", "Optional kernel module base", false},
         {"max_modules", "number", "Maximum modules scanned when no filter is supplied", false},
         {"process_id", "number", "Reserved for compatibility", false}},
        protected_re::drv_find_device_names, true});

    register_compat(srv, {
        "drv_check_buffer_safety", "protected_re",
        "Analyze IOCTL handlers for common buffer-safety risk indicators with confidence metadata.",
        {{"ioctl_handlers", "array", "Handlers from drv_find_ioctl_dispatch or drv_enumerate_ioctls", true}},
        protected_re::drv_check_buffer_safety, true});

    register_compat(srv, {
        "drv_hook_manage", "protected_re",
        "Manage kernel IRP hook state. Install fails closed unless a safe backend is exposed.",
        {{"action", "string", "install, start, stop, remove, status, or list", true},
         {"payload", "object", "Action-specific parameters", false},
         {"hook_id", "string", "Hook id for remove", false},
         {"driver_name", "string", "Driver object name for install", false},
         {"irp_code", "number", "IRP major code for install", false},
         {"callback_va", "string", "Callback address for install", false},
         {"confirm_unsafe", "boolean", "Recorded for install capability evidence", false},
         {"allow_unsafe", "boolean", "Alternative unsafe confirmation", false}},
        protected_re::drv_hook_manage, false});

    register_compat(srv, {
        "drv_send_ioctl", "protected_re",
        "Send a raw IOCTL to a device symlink after explicit unsafe confirmation.",
        {{"device_symlink", "string", "Win32 device path", true},
         {"ioctl_code", "number", "IOCTL code", true},
         {"input_buffer_hex", "string", "Optional input bytes", false},
         {"output_buffer_size", "number", "Output buffer size", false},
         {"confirm_unsafe", "boolean", "Required to send IOCTL", false},
         {"allow_unsafe", "boolean", "Alternative unsafe confirmation", false}},
        protected_re::drv_send_ioctl, false});

    register_compat(srv, {
        "smc_manage", "protected_re",
        "Manage self-modifying code PAGE_GUARD capture sessions. Actions: start, captures, stop.",
        {{"action", "string", "start, captures, or stop", true},
         {"payload", "object", "Action-specific parameters", false},
         {"session_id", "string", "Session id for captures or stop", false},
         {"watch_va", "string", "Region start for start", false},
         {"watch_size", "number", "Region size for start", false},
         {"capture_on_write", "boolean", "Capture write events", false},
         {"capture_on_execute", "boolean", "Capture execute events", false},
         {"confirm_unsafe", "boolean", "Required for start", false},
         {"allow_unsafe", "boolean", "Alternative unsafe confirmation", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::smc_manage, false});

    register_compat(srv, {
        "smc_scan_encrypted_regions", "protected_re",
        "Scan mapped PE sections for high-entropy or suspicious executable regions.",
        {{"process_id", "number", "Optional target process id", false},
         {"module_name", "string", "Optional module filter", false},
         {"module_base", "string", "Optional module base", false},
         {"module_size", "number", "Optional synthetic module image size", false},
         {"include_all", "boolean", "Return all scanned sections", false}},
        protected_re::smc_scan_encrypted_regions, true});

    register_compat(srv, {
        "smc_find_decryptor", "protected_re",
        "Find candidate decryptor/write instructions for a known decrypted target range.",
        {{"target_va", "string", "Known decrypted region address", true},
         {"target_size", "number", "Known decrypted region size", true},
         {"scan_base", "string", "Optional bounded private code scan start", false},
         {"scan_size", "number", "Optional bounded private code scan size", false},
         {"process_id", "number", "Optional target process id", false}},
        protected_re::smc_find_decryptor, true});

    register_compat(srv, {
        "pack_detect", "protected_re",
        "Detect generic packer indicators using mapped-section entropy and import-table shape.",
        {{"process_id", "number", "Optional target process id", false},
         {"module_name", "string", "Optional module filter", false},
         {"module_base", "string", "Optional module base", false},
         {"module_size", "number", "Optional synthetic module image size", false}},
        protected_re::pack_detect, true});

    register_compat(srv, {
        "pack_find_oep", "protected_re",
        "Find OEP candidates with generic behavioral strategies after explicit unsafe confirmation.",
        {{"process_id", "number", "Optional target process id", false},
         {"module_name", "string", "Optional module filter", false},
         {"module_base", "string", "Optional module base", false},
         {"module_size", "number", "Optional synthetic module image size", false},
         {"strategy", "string", "esp_trick, page_guard, tail_jump, or all", false},
         {"timeout_ms", "number", "Observation timeout", false},
         {"tid", "number", "Optional watched thread", false},
         {"confirm_unsafe", "boolean", "Required to observe target execution", false},
         {"allow_unsafe", "boolean", "Alternative unsafe confirmation", false}},
        protected_re::pack_find_oep, false});

    register_compat(srv, {
        "pack_iat_manage", "protected_re",
        "Monitor IAT reconstruction with GetProcAddress and LoadLibraryA/W/ExA/ExW hardware-breakpoint evidence, then reconstruct the current IAT. Actions: start, results, stop.",
        {{"action", "string", "start, results, or stop", true},
         {"payload", "object", "Action-specific parameters", false},
         {"session_id", "string", "Session id for results or stop", false},
         {"max_captures", "number", "Maximum reconstructed entries", false},
         {"process_id", "number", "Optional target process id", false},
         {"module_name", "string", "Optional module filter for results", false},
         {"module_base", "string", "Optional module base for results", false},
         {"confirm_unsafe", "boolean", "Required for start", false},
         {"allow_unsafe", "boolean", "Alternative unsafe confirmation", false}},
        protected_re::pack_iat_manage, false});

}

}
