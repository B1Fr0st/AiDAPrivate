from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "mcp": ROOT / "src" / "standalone" / "src" / "core" / "mcp" / "mcp_standalone.cpp",
    "diag": ROOT / "src" / "standalone" / "src" / "core" / "mcp" / "mcp_capacity_governor_diag.hpp",
    "cmake": ROOT / "CMakeLists.txt",
}

errors = []


def rel(path):
    return str(path.relative_to(ROOT)).replace("\\", "/")


def read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        errors.append((rel(path), 0, str(path), "required Phase 4 source file is missing"))
        return ""


TEXT = {name: read(path) for name, path in FILES.items()}


def line_of(text, token):
    idx = text.find(token)
    if idx < 0:
        return 0
    return text.count("\n", 0, idx) + 1


def fail(path_key, token, reason):
    errors.append((rel(FILES[path_key]), line_of(TEXT[path_key], token), token, reason))


def require(path_key, token, reason):
    if token not in TEXT[path_key]:
        fail(path_key, token, reason)


def reject(path_key, token, reason):
    if token in TEXT[path_key]:
        fail(path_key, token, reason)


def require_regex(path_key, pattern, token, reason, flags=re.S):
    if not re.search(pattern, TEXT[path_key], flags):
        fail(path_key, token, reason)


def body_from(text, signature, anchor=None):
    start = text.find(signature) if anchor is None else text.find(signature, text.find(anchor))
    if start < 0:
        return ""
    brace = text.find("{", start)
    if brace < 0:
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
    return ""


def slice_from(text, start_token, end_token=None):
    start = text.find(start_token)
    if start < 0:
        return ""
    if end_token is None:
        return text[start:]
    end = text.find(end_token, start + len(start_token))
    return text[start:] if end < 0 else text[start:end]


def require_in(blob, path_key, token, reason):
    if token not in blob:
        fail(path_key, token, reason)


def reject_in(blob, path_key, token, reason):
    if token in blob:
        fail(path_key, token, reason)


def require_order(blob, path_key, first, second, reason):
    first_pos = blob.find(first)
    second_pos = blob.find(second)
    if first_pos < 0 or second_pos < 0 or first_pos >= second_pos:
        fail(path_key, f"{first} -> {second}", reason)


for token in [
    "struct mcp_tool_capacity_counts_t",
    "struct mcp_tool_capacity_record_t",
    "struct mcp_tool_capacity_snapshot_t",
    "class mcp_tool_capacity_lease_t",
    "static bool mcp_tool_try_acquire_capacity",
    "static void mcp_tool_release_all_capacity_leases",
    "static capacity_diag::activity_counters_t mcp_tool_capacity_activity_for_context",
    "static json mcp_tool_capacity_health_snapshot",
    "g_mcp_tool_active_leases",
    "g_mcp_tool_cleanup_released_leases",
    "g_mcp_tool_by_principal",
    "g_mcp_tool_by_session",
    "g_mcp_tool_by_target",
    "g_mcp_tool_by_domain",
    "g_mcp_tool_by_lane",
    "g_mcp_tool_by_priority",
    "g_mcp_tool_by_tool",
    "g_mcp_tool_by_class",
    "g_mcp_tool_rejected_by_principal",
    "g_mcp_tool_rejected_by_session",
    "g_mcp_tool_rejected_by_target",
    "g_mcp_tool_rejected_by_domain",
    "g_mcp_tool_rejected_by_lane",
    "g_mcp_tool_rejected_by_priority",
    "g_mcp_tool_rejected_by_tool",
    "g_mcp_tool_rejected_by_class",
    "MCP-TOOL-ADMIT",
    "MCP-TOOL-REJECT",
    "MCP-TOOL-LEASE-RELEASE",
    "MCP-TOOL-LEASE-SNAPSHOT",
    "MCP-TOOL-BYPASS-AUDIT",
    "release(\"scope_exit\")",
    "release(\"move_assign\")",
    "other.active_ = false",
    "tool_capacity_lease.release(\"enqueue_failure\")",
    "tool_capacity_lease.release(\"timeout\")",
    "tool_capacity_lease.release(\"cancellation\")",
    "tool_capacity_lease.release(\"client_disconnect_before_start\")",
    "api_tool_capacity_lease.release(\"client_disconnect_before_start\")",
    "mcp_tool_release_reason_from_result",
    "api_tool_capacity_lease.release(mcp_tool_release_reason_from_result(tr, false))",
    "mcp_tool_release_all_capacity_leases(\"stop_already_stopped\")",
    "mcp_tool_release_all_capacity_leases(\"stop_requested\")",
    "mcp_tool_release_all_capacity_leases(\"listen_after_bind_returned\")",
]:
    require("mcp", token, "shared Phase 4 tool admission broker evidence is missing")

for token in [
    "bool browser_tool = false",
    "bool scanner_tool = false",
    "bool decompiler_tool = false",
    "bool network_tool = false",
    "\"browser_tool\"",
    "\"scanner_tool\"",
    "\"decompiler_tool\"",
    "\"network_tool\"",
]:
    require("diag", token, "capacity diagnostics must preserve Phase 4 tool class fields")

try_acquire = body_from(TEXT["mcp"], "static bool mcp_tool_try_acquire_capacity")
if not try_acquire:
    fail("mcp", "static bool mcp_tool_try_acquire_capacity", "broker acquire helper body is missing")
else:
    for token in [
        "std::lock_guard<std::mutex> lk(g_mcp_tool_capacity_mtx)",
        "mcp_tool_evaluate_locked(prediction, record)",
        "mcp_tool_add_rejected_locked(record)",
        "mcp_tool_add_active_locked(record)",
        "out->activate(record)",
        "MCP-TOOL-REJECT",
        "MCP-TOOL-ADMIT",
    ]:
        require_in(try_acquire, "mcp", token, "broker acquire must atomically evaluate, charge, and log")
    reject_in(try_acquire, "mcp", "invoke_tool_with_concurrency_policy", "broker acquire must not run handlers while holding admission state")

lease_release = body_from(TEXT["mcp"], "void release(const char* reason) noexcept", "class mcp_tool_capacity_lease_t")
if not lease_release:
    fail("mcp", "void release(const char* reason) noexcept", "tool lease release body is missing")
else:
    for token in [
        "std::lock_guard<std::mutex> lk(g_mcp_tool_capacity_mtx)",
        "mcp_tool_remove_active_locked(record)",
        "g_mcp_tool_active_leases.erase(it)",
        "g_mcp_tool_cleanup_released_leases.find(record.lease_id)",
        "active_ = false",
        "g_mcp_tool_leases_released.fetch_add",
        "MCP-TOOL-LEASE-RELEASE",
    ]:
        require_in(lease_release, "mcp", token, "RAII lease release must be exact-once, charged, and logged")
    reject_in(lease_release, "mcp", "invoke_tool_with_concurrency_policy", "lease release must not run handlers while holding admission state")

cleanup_release = body_from(TEXT["mcp"], "static void mcp_tool_release_all_capacity_leases")
if not cleanup_release:
    fail("mcp", "static void mcp_tool_release_all_capacity_leases", "shutdown cleanup release helper body is missing")
else:
    for token in [
        "std::lock_guard<std::mutex> lk(g_mcp_tool_capacity_mtx)",
        "mcp_tool_remove_active_locked(kv.second)",
        "g_mcp_tool_cleanup_released_leases.insert(kv.first)",
        "g_mcp_tool_active_leases.clear()",
        "g_mcp_tool_leases_released.fetch_add",
        "mcp_tool_log_cleanup_release(record, reason)",
    ]:
        require_in(cleanup_release, "mcp", token, "shutdown cleanup must release active leases exactly once")
    reject_in(cleanup_release, "mcp", "invoke_tool_with_concurrency_policy", "shutdown cleanup must not run handlers while holding admission state")

for signature in [
    "tool_result_t server_t::call_registered_tool",
    "json server_t::handle_tools_call",
]:
    body = body_from(TEXT["mcp"], signature)
    if not body:
        fail("mcp", signature, "tool dispatch body is missing")
        continue
    require_in(body, "mcp", "mcp_tool_try_acquire_capacity", "external tool dispatch must use the shared broker")
    require_order(body, "mcp", "mcp_tool_try_acquire_capacity", "selected_executor.enqueue(std::move(task), meta)", "broker admission must precede enqueue")
    require_order(body, "mcp", "selected_executor.enqueue(std::move(task), meta)", "future.wait_for(std::chrono::milliseconds(timeout_ms))", "enqueue must precede caller wait")
    require_in(body, "mcp", "release(\"enqueue_failure\")", "enqueue failure must release the lease")
    require_in(body, "mcp", "release(\"timeout\")", "timeout path must release the lease")
    require_in(body, "mcp", "mcp_tool_release_reason_from_result", "success/failure path must release with structured reason")
    if signature == "json server_t::handle_tools_call":
        require_in(body, "mcp", "current_mcp_connection_closed()", "JSON-RPC tool dispatch must check client disconnect before enqueue")
        require_order(body, "mcp", "mcp_tool_try_acquire_capacity", "current_mcp_connection_closed()", "client-disconnect check must run after a real lease exists")
        require_order(body, "mcp", "current_mcp_connection_closed()", "selected_executor.enqueue(std::move(task), meta)", "client-disconnect rejection must happen before enqueue")

direct = body_from(TEXT["mcp"], "tool_result_t server_t::call_registered_tool")
if direct:
    require_in(direct, "mcp", "mcp_tool_bypass_audit(capacity_prediction, \"source_visible_internal_callsite_contract\")", "internal direct-call bypass must be explicit and audited")
    require_order(direct, "mcp", "if (!external_visible_only)", "mcp_tool_capacity_lease_t tool_capacity_lease", "internal bypass must be separated before external broker admission")
    internal = direct[direct.find("if (!external_visible_only)"):direct.find("mcp_tool_capacity_lease_t tool_capacity_lease")]
    for token in ["arguments.contains", "arguments.value", "arguments[", "params.value", "params["]:
        reject_in(internal, "mcp", token, "internal bypass must not be controlled by spoofable request arguments")

api_tools_call = slice_from(TEXT["mcp"], "svr.Post(\"/api/tools/call\"", "std::map<std::string, std::shared_ptr<sse_session_t>> sse_sessions")
if not api_tools_call:
    fail("mcp", "svr.Post(\"/api/tools/call\"", "REST tool call route body is missing")
else:
    require_in(api_tools_call, "mcp", "mcp_tool_try_acquire_capacity", "REST tool calls must use the shared broker")
    require_order(api_tools_call, "mcp", "mcp_tool_try_acquire_capacity", "invoke_tool_with_concurrency_policy", "REST admission must precede handler execution")
    require_order(api_tools_call, "mcp", "request_connection_closed(req)", "invoke_tool_with_concurrency_policy", "REST client-disconnect rejection must happen before handler execution")
    require_in(api_tools_call, "mcp", "api_tool_capacity_lease.release(\"client_disconnect_before_start\")", "REST client-disconnect path must release the lease before start")
    require_order(api_tools_call, "mcp", "invoke_tool_with_concurrency_policy", "api_tool_capacity_lease.release(mcp_tool_release_reason_from_result(tr, false))", "REST route must release after handler completion")

health = body_from(TEXT["mcp"], "static json mcp_tool_capacity_health_snapshot")
if not health:
    fail("mcp", "static json mcp_tool_capacity_health_snapshot", "tool admission health snapshot body is missing")
else:
    for token in [
        "\"by_principal\"",
        "\"by_session\"",
        "\"by_target\"",
        "\"by_domain\"",
        "\"by_lane\"",
        "\"by_priority\"",
        "\"by_tool\"",
        "\"by_class\"",
        "\"rejected_by_principal\"",
        "\"rejected_by_session\"",
        "\"rejected_by_target\"",
        "\"rejected_by_domain\"",
        "\"rejected_by_lane\"",
        "\"rejected_by_priority\"",
        "\"rejected_by_tool\"",
        "\"rejected_by_class\"",
        "\"domain_classes\"",
        "\"oldest_active_ms\"",
        "\"top_pressure_contributors\"",
        "\"availability\"",
        "\"p0\"",
        "\"p1\"",
        "\"p4_p5_active\"",
        "\"p0_p1_protected_from_p4_p5\"",
    ]:
        require_in(health, "mcp", token, "tool admission health must expose Phase 4 pressure dimensions")

capacity_health = body_from(TEXT["mcp"], "static json capacity_health_snapshot")
if capacity_health:
    require_in(capacity_health, "mcp", "mcp_tool_capacity_health_snapshot(quotas)", "global capacity health must include tool admission health")
    require_in(capacity_health, "mcp", "out[\"tool_admission\"]", "tool admission snapshot must be exposed in health")
else:
    fail("mcp", "static json capacity_health_snapshot", "global capacity health body is missing")

for token in [
    "AIDA_PHASE4_TOOL_ADMISSION_GUARD_SCRIPT",
    "AIDA_PHASE4_DIRECT_CALL_ADMISSION_GUARD_SCRIPT",
    "AiDAToolAdmissionGuards",
    "AiDADirectCallAdmissionGuards",
    "verify_phase4_tool_admission.py",
    "verify_phase4_direct_call_admission.py",
]:
    require("cmake", token, "Phase 4 tool admission static guard must be wired into CMake")

require_regex("cmake",
              r"add_dependencies\s*\(\s*AiDADirectCallAdmissionGuards[^\)]*AiDAIngressAdmissionGuards",
              "add_dependencies(AiDADirectCallAdmissionGuards ... AiDAIngressAdmissionGuards)",
              "Phase 4 direct-call guard must run after Phase 3 ingress admission guard")
require_regex("cmake",
              r"add_dependencies\s*\(\s*AiDAToolAdmissionGuards[^\)]*AiDADirectCallAdmissionGuards",
              "add_dependencies(AiDAToolAdmissionGuards ... AiDADirectCallAdmissionGuards)",
              "Phase 4 tool admission guard must run after direct-call admission guard")
require_regex("cmake",
              r"add_dependencies\s*\(\s*AiDAStandalone[^\)]*AiDAToolAdmissionGuards",
              "add_dependencies(AiDAStandalone ... AiDAToolAdmissionGuards)",
              "AiDAStandalone must depend on the Phase 4 tool admission guard")

if errors:
    for path, line, token, reason in errors:
        print(f"{path}:{line}: {token}: {reason}", file=sys.stderr)
    sys.exit(1)

print("Phase 4 tool admission guard passed: shared broker admission, exact-once leases, shutdown cleanup, health fields, logs, and CMake wiring are present.")
