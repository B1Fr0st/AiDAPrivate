from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "mcp": ROOT / "src" / "standalone" / "src" / "core" / "mcp" / "mcp_standalone.cpp",
    "dbg": ROOT / "src" / "standalone" / "src" / "core" / "debugger" / "debugger_tools_standalone.cpp",
    "thread": ROOT / "src" / "standalone" / "src" / "core" / "debugger" / "thread_intel_tools_standalone.cpp",
    "cmake": ROOT / "CMakeLists.txt",
}


errors = []


def rel(path):
    return str(path.relative_to(ROOT)).replace("\\", "/")


def read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        errors.append((rel(path), 0, str(path), "required Phase 5 source file is missing"))
        return ""


TEXT = {name: read(path) for name, path in FILES.items()}


def line_of(path_key, token):
    text = TEXT[path_key]
    idx = text.find(token)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def line_of_pos(path_key, pos):
    return TEXT[path_key].count("\n", 0, max(0, pos)) + 1


def fail(path_key, token, reason):
    errors.append((rel(FILES[path_key]), line_of(path_key, token), token, reason))


def fail_at(path_key, pos, token, reason):
    errors.append((rel(FILES[path_key]), line_of_pos(path_key, pos), token, reason))


def require(path_key, token, reason):
    if token not in TEXT[path_key]:
        fail(path_key, token, reason)


def require_regex(path_key, pattern, token, reason, flags=re.S):
    if not re.search(pattern, TEXT[path_key], flags):
        fail(path_key, token, reason)


def require_any(path_key, tokens, token_name, reason):
    if not any(token in TEXT[path_key] for token in tokens):
        fail(path_key, token_name, reason)


def balanced_block(path_key, token):
    text = TEXT[path_key]
    start = text.find(token)
    if start < 0:
        fail(path_key, token, "required Phase 5 source block is missing")
        return ""
    brace = text.find("{", start)
    if brace < 0:
        fail(path_key, token, "required Phase 5 source block has no body")
        return ""
    depth = 0
    for idx in range(brace, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    fail(path_key, token, "required Phase 5 source block is unterminated")
    return ""


def require_in(block, path_key, token, reason):
    if token not in block:
        fail(path_key, token, reason)


def require_any_in(block, path_key, tokens, token_name, reason):
    if not any(token in block for token in tokens):
        fail(path_key, token_name, reason)


def reject_in(block, path_key, token, reason):
    idx = block.find(token)
    if idx >= 0:
        block_pos = TEXT[path_key].find(block)
        fail_at(path_key, block_pos + idx if block_pos >= 0 else idx, token, reason)


def reject_regex_in(block, path_key, pattern, token, reason):
    match = re.search(pattern, block, re.S)
    if match:
        block_pos = TEXT[path_key].find(block)
        fail_at(path_key, block_pos + match.start() if block_pos >= 0 else match.start(), token, reason)


def require_order(path_key, first, second, reason):
    text = TEXT[path_key]
    first_pos = text.find(first)
    second_pos = text.find(second)
    if first_pos < 0 or second_pos < 0 or first_pos >= second_pos:
        fail(path_key, f"{first} -> {second}", reason)


def check_regression_pair():
    require("mcp", "thread_classify", "one-agent regression coverage must keep thread_classify visible to MCP classification diagnostics")
    require("mcp", "exclusive_mutating", "thread_classify must remain covered by the mutating lane classification model")
    require("mcp", "target_resolve", "regression model must retain target_resolve phase evidence for held active-session locks")
    require("dbg", "dbg_find_strings", "one-agent regression coverage must keep dbg_find_strings source-visible")
    require("thread", "thread_classify", "one-agent regression coverage must keep thread_classify registration source-visible")
    require_regex("dbg",
                  r"OBFSTR\(\"dbg_find_strings\"\).*?},\s*true\}\);",
                  "dbg_find_strings read_only=true",
                  "dbg_find_strings must remain read-only so it queues behind exclusive mutating owners instead of taking a mutating lane")
    require_regex("thread",
                  r"OBFSTR\(\"thread_classify\"\).*?handle_thread_classify,\s*false\}\);",
                  "thread_classify read_only=false",
                  "thread_classify must remain mutating for the exclusive_mutating regression model")
    require_regex("mcp",
                  r"if\s*\(\s*session_manager\s*\|\|\s*!tool\.read_only\s*\).*?exclusive_mutating",
                  "read_only=false exclusive_mutating mapping",
                  "MCP lane prediction must retain the read_only=false to exclusive_mutating mapping")


def check_no_blind_steal():
    lease = balanced_block("mcp", "class active_session_lease_lock_t")
    for signature in ["bool try_acquire_exclusive", "bool try_acquire_shared"]:
        body = balanced_block("mcp", signature)
        require_in(body, "mcp", "exclusive_owner_token_ == 0", "active-session lock acquisition must only succeed when no exclusive owner is present")
        for token in [
            "exclusive_owner_expired",
            "mcp_now_ms()",
            "exclusive_owner_token_ = 0",
            "exclusive_owner_deadline_ms_ = 0",
            "release_exclusive",
            "release_shared",
            "notify_all",
            ".erase(",
            ".clear(",
        ]:
            reject_in(body, "mcp", token, "active_session_lease_lock_t acquisition must not steal, clear, or notify away expired owners")
    expired_refs = [m.start() for m in re.finditer(r"\bexclusive_owner_expired\b", TEXT["mcp"])]
    if len(expired_refs) > 1:
        fail_at("mcp", expired_refs[1], "exclusive_owner_expired", "expired-owner observation must not be used to steal or bypass active-session owners")

    eviction = balanced_block("mcp", "static bool active_session_owner_request_eviction")
    require_in(eviction, "mcp", "mcp_lease_registry_signal_cancel", "overdue owner eviction must signal cooperative cancellation through the generation-aware lease registry")
    require_in(eviction, "mcp", "mcp_lease_registry_mark_stale", "overdue owner eviction must mark stale owners in the generation-aware lease registry")
    require_in(eviction, "mcp", "cancelled = true", "overdue owner eviction must mark owner records cancelled instead of unlocking them")
    require_in(eviction, "mcp", "tool_policy_lock_eviction_requested", "overdue owner eviction must emit source-visible evidence")
    for token in [
        "release_exclusive",
        "release_shared",
        "active_session_lease_lock().",
        "exclusive_owner_token_ = 0",
        "active_session_exclusive_owner() = {}",
        "shared_owners.erase",
        "shared_owners.clear",
        "try_acquire",
        "TerminateThread",
        "SuspendThread",
        "ResumeThread",
    ]:
        reject_in(eviction, "mcp", token, "active_session_owner_request_eviction must not blind-steal, force-unlock, or kill protected in-process work")


def check_registry_generation_model():
    for token in [
        "mcp_lease_registry_record_t",
        "mcp_lease_registry_acquire_t",
        "mcp_lease_registry_snapshot_t",
        "mcp_lease_registry_active",
        "mcp_lease_registry_tombstones",
        "mcp_lease_registry_acquire",
        "mcp_lease_registry_set_phase",
        "mcp_lease_registry_commit_eligible",
        "mcp_lease_registry_signal_cancel",
        "mcp_lease_registry_mark_stale",
        "mcp_lease_registry_fence",
        "mcp_lease_registry_release",
        "mcp_lease_registry_bounded_snapshot",
        "mcp_late_result_evidence_json",
        "mcp_log_late_result_discarded",
        "mcp_broker_delivery_fence_t",
        "mcp_operation_registry_scope_t",
        "mcp_late_result_error_result",
        "active_session_owner_record_t",
        "active_session_owner_snapshot_t",
        "active_session_owner_snapshot",
        "active_session_owner_guard_t",
        "active_session_owner_request_eviction",
    ]:
        require("mcp", token, "active-session lease registry API surface is missing")

    lease_record = balanced_block("mcp", "struct mcp_lease_registry_record_t")
    delivery_fence = balanced_block("mcp", "class mcp_broker_delivery_fence_t")
    registry_scope = balanced_block("mcp", "class mcp_operation_registry_scope_t")
    for token in [
        "lease_token",
        "registry_generation",
        "operation_generation",
        "session_id",
        "session_hash",
        "target_id",
        "target_pid",
        "phase",
        "external_process_kind",
        "external_process_pid",
        "external_process_identity",
        "external_process_session",
        "external_process_generation",
        "external_expected_executable_path",
        "external_process_creation_time_100ns",
        "external_sidecar_ownership_marker",
        "external_force_cleanup_eligible",
    ]:
        require_in(lease_record, "mcp", token, "mcp_lease_registry_record_t must bind lease ownership to token, generation, session, target, PID, phase, and external sidecar proof fields")
    for token in [
        "token_",
        "generation_",
        "snapshot_",
        "mark_timeout",
        "validate_handler_return",
        "claim_delivery",
        "release_locked",
        "mcp_late_result_evidence_json",
        "mcp_log_late_result_discarded",
        "mcp_lease_registry_signal_cancel",
        "mcp_lease_registry_mark_stale",
        "mcp_lease_registry_fence",
        "std::mutex",
    ]:
        require_in(delivery_fence, "mcp", token, "mcp_broker_delivery_fence_t must carry token/generation state and fence handler return, timeout, and delivery with thread-safe RAII release")
    for token in [
        "token_",
        "registry_generation_",
        "operation_generation_",
        "lease_snapshot_",
        "set_phase",
        "commit_eligible",
        "mcp_lease_registry_acquire",
        "mcp_lease_registry_release",
        "mcp_lease_registry_commit_eligible",
    ]:
        require_in(registry_scope, "mcp", token, "mcp_operation_registry_scope_t must wrap non-active-session operations in the same generation-aware registry")

    record = balanced_block("mcp", "struct active_session_owner_record_t")
    snapshot = balanced_block("mcp", "struct active_session_owner_snapshot_t")
    for block_name, block in [("active_session_owner_record_t", record), ("active_session_owner_snapshot_t", snapshot)]:
        for token in ["token", "deadline_ms", "pid", "tid", "phase"]:
            require_in(block, "mcp", token, f"{block_name} must retain Phase 5 owner identity evidence")
        for token in ["registry_generation", "operation_generation", "session_id", "target_id", "target_pid"]:
            require_in(block, "mcp", token, f"{block_name} must be generation-aware and bind owners to session, target, and PID")

    require_any("mcp",
                ["mcp_lease_registry_active", "mcp_lease_registry_generation_source", "mcp_lease_operation_generation_source"],
                "generation-aware active-session lease registry",
                "Phase 5 must expose a generation-aware registry API rather than split owner/lease state alone")


def check_wait_policy_bounded_busy():
    wait_body = balanced_block("mcp", "static policy_lock_wait_t wait_policy_lock")
    for token in [
        "tool_policy_lock_wait_begin",
        "tool_policy_lock_wait_acquired",
        "tool_policy_lock_wait_cancelled",
        "tool_policy_lock_wait_busy",
        "tool_policy_lock_wait_state",
        "active_session_owner_request_eviction",
        "owner_deadline_expired",
        "policy_lock_status_t::busy",
        "policy_lock_error_result",
        "MCP active-session policy lock is busy",
    ]:
        require("mcp", token, "Phase 5 bounded wait, busy, cancellation, and stale-owner evidence is missing")
    reject_in(wait_body, "mcp", "std::unique_lock", "policy wait must not hold a lock while polling owner state")
    reject_in(wait_body, "mcp", "TerminateThread", "policy wait must not use generic thread kill for stale owners")


def check_late_result_fencing():
    for token in [
        "late_result_disposition",
        "fenced_after_timeout",
        "discarded_after_timeout",
        "cancelled_before_delivery",
        "not_started",
        "tool_call_timeout_lock_owner",
        "browser_tool_late_result_disposition",
        "MCP-LATE-RESULT-DISCARDED",
    ]:
        require("mcp", token, "Phase 5 late-result log family is missing")

    for signature in ["tool_result_t server_t::call_registered_tool", "json server_t::handle_tools_call"]:
        body = balanced_block("mcp", signature)
        for token_name, tokens in [
            ("lease token", ["call_token", "lease_token", "owner_token"]),
            ("session id/hash", ["session_id", "session_hash", "current_mcp_session_hash"]),
            ("target id", ["target_id", "capacity_target_id_from_args"]),
            ("target PID", ["target_pid"]),
            ("generation", ["generation"]),
            ("phase", ["phase"]),
        ]:
            require_any_in(body, "mcp", tokens, token_name, f"{signature} must fence late results by {token_name}")
        require_any_in(body,
                       "mcp",
                       ["mcp_broker_delivery_fence_t", "delivery_fence"],
                       "late result fence API",
                       f"{signature} must create a source-visible late-result operation before handler dispatch")
        require_any_in(body,
                       "mcp",
                       ["claim_delivery", "validate_handler_return", "mcp_late_result_error_result"],
                       "late result delivery validation",
                       f"{signature} must validate handler return and claim delivery before publishing results")
        require_any_in(body,
                       "mcp",
                       ["mark_timeout", "mcp_log_late_result_discarded"],
                       "late result timeout fence",
                       f"{signature} must tombstone timed-out work in the late-result registry")
        if "promise.set_value" in body:
            require_any_in(body,
                           "mcp",
                           ["claim_delivery", "validate_handler_return", "mcp_late_result_error_result"],
                           "discarded late result evidence",
                           f"{signature} must discard or fence results that arrive after timeout")


def check_camoufox_cleanup_gate():
    text = TEXT["mcp"]
    for token in [
        "external_force_cleanup_eligible",
        "external_process_kind",
        "external_process_pid",
        "external_process_identity",
        "external_process_session",
        "external_process_generation",
        "external_expected_executable_path",
        "external_process_creation_time_100ns",
        "external_sidecar_ownership_marker",
        "mcp_camoufox_cleanup_stale_sidecar",
        "cleanup_stale_sidecar_if_owned",
        "stale_sidecar_cleanup_proof_t",
    ]:
        require("mcp", token, "Camoufox cleanup proof model must retain external ownership evidence fields")
    cleanup_block = balanced_block("mcp", "static json mcp_camoufox_cleanup_stale_sidecar")
    for token in [
        "stale_sidecar_cleanup_proof_t proof",
        "proof.bridge_session_id",
        "proof.mcp_session_id",
        "proof.mcp_session_hash",
        "proof.principal_bucket",
        "proof.expected_executable_path",
        "proof.expected_sidecar_pid",
        "proof.expected_bridge_generation",
        "proof.expected_process_creation_time_100ns",
        "proof.lease_token",
        "proof.registry_generation",
        "proof.operation_generation",
        "proof.sidecar_ownership_marker",
        "cleanup_stale_sidecar_if_owned",
        "MCP-CAMOUFOX-STALE-CLEANUP",
    ]:
        require_in(cleanup_block, "mcp", token, "Camoufox cleanup must be proof-gated by generation, PID, session, executable/sidecar ownership")
    for token in ["TerminateThread", "SuspendThread", "QueueUserAPC"]:
        if token in text:
            fail("mcp", token, "Phase 5 recovery must not use generic in-process thread kill or suspension")


def check_phase5_cmake_wiring():
    for token in [
        "AIDA_PHASE5_LEASE_REGISTRY_GUARD_SCRIPT",
        "AiDALeaseRegistryGuards",
        "verify_phase5_lease_registry.py",
    ]:
        require("cmake", token, "Phase 5 static guard must be wired into CMake")
    require_regex("cmake",
                  r"add_dependencies\s*\(\s*AiDALeaseRegistryGuards[^\)]*AiDAToolAdmissionGuards",
                  "add_dependencies(AiDALeaseRegistryGuards ... AiDAToolAdmissionGuards)",
                  "Phase 5 guard must run after Phase 4 tool admission guard")
    require_regex("cmake",
                  r"add_dependencies\s*\(\s*AiDAStandalone[^\)]*AiDALeaseRegistryGuards",
                  "add_dependencies(AiDAStandalone ... AiDALeaseRegistryGuards)",
                  "AiDAStandalone must depend on the Phase 5 lease registry guard")


def check_phase5_logs_and_health():
    for token in [
        "MCP-STALE-LEASE",
        "MCP-LOCK-CONFLICT",
        "mcp_lease_late_result_discard_count",
        "mcp_lease_camoufox_cleanup_attempt_count",
        "mcp_lease_camoufox_cleanup_rejected_count",
        "mcp_lease_lock_conflict_count",
        "mcp_lease_record_lock_conflict",
        "mcp_lease_conflict_counters_json",
    ]:
        require("mcp", token, f"Phase 5 log/counter API surface is missing: {token}")

    snapshot = balanced_block("mcp", "static json mcp_lease_registry_bounded_snapshot")
    for token in [
        "active_leases_by_lane",
        "active_leases_by_tool",
        "active_leases_by_session",
        "active_leases_by_target",
        "active_leases_by_principal",
        "stale_count",
        "fenced_count",
        "overdue_owners_count",
        "cancellation_signalled_count",
        "oldest_active_owner_age_ms",
        "stale_owners_present",
        "top_lock_owners_by_age",
        "conflict_counters_by_lane",
        "late_result_discard_count",
        "camoufox_cleanup_attempt_count",
        "camoufox_cleanup_rejected_count",
        "lock_conflict_count",
    ]:
        require_in(snapshot, "mcp", token, f"Phase 5 health lease registry snapshot must include {token}")

    require("mcp", "p0_p1_available_while_stale", "Phase 5 /health must cross-reference P0/P1 availability with stale owner presence")
    require("mcp", "p0_p1_availability", "Phase 5 /health must expose p0_p1_availability in lease registry snapshot")


def main():
    check_regression_pair()
    check_no_blind_steal()
    check_registry_generation_model()
    check_wait_policy_bounded_busy()
    check_late_result_fencing()
    check_camoufox_cleanup_gate()
    check_phase5_logs_and_health()
    check_phase5_cmake_wiring()
    if errors:
        for path, line, token, reason in errors:
            print(f"{path}:{line}: {token}: {reason}", file=sys.stderr)
        return 1
    print("Phase 5 lease registry guard passed: generation-aware leases, no blind stealing, late-result fencing, Camoufox cleanup proof gate, one-agent regression coverage, stale-lease/conflict logs, and bounded health snapshots are present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
