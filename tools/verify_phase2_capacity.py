from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


FILES = {
    "mcp": ROOT / "src" / "standalone" / "src" / "core" / "mcp" / "mcp_standalone.cpp",
    "diag": ROOT / "src" / "standalone" / "src" / "core" / "mcp" / "mcp_capacity_governor_diag.hpp",
    "cmd": ROOT / "src" / "standalone" / "src" / "core" / "tools" / "command_sessions.hpp",
    "cmake": ROOT / "CMakeLists.txt",
}


errors = []


def rel(path):
    return str(path.relative_to(ROOT)).replace("\\", "/")


def read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        errors.append((rel(path), 0, str(path), "required Phase 2 source file is missing"))
        return ""


TEXT = {name: read(path) for name, path in FILES.items()}


def line_of(text, token):
    idx = text.find(token)
    if idx < 0:
        return 0
    return text.count("\n", 0, idx) + 1


def fail(path_key, token, reason, text=None):
    source = TEXT[path_key] if text is None else text
    errors.append((rel(FILES[path_key]), line_of(source, token), token, reason))


def require(path_key, token, reason):
    if token not in TEXT[path_key]:
        fail(path_key, token, reason)


def require_regex(path_key, pattern, token, reason, flags=0):
    if not re.search(pattern, TEXT[path_key], flags):
        fail(path_key, token, reason)


def forbid_regex(path_key, pattern, reason, flags=0):
    for match in re.finditer(pattern, TEXT[path_key], flags):
        source = TEXT[path_key]
        token = match.group(0).splitlines()[0][:160]
        errors.append((rel(FILES[path_key]), source.count("\n", 0, match.start()) + 1, token, reason))


def function_span(text, signature):
    start = text.find(signature)
    if start < 0:
        return None
    brace = text.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for idx in range(brace, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return (start, idx + 1)
    return None


def in_any_span(pos, spans):
    for span in spans:
        if span and span[0] <= pos < span[1]:
            return True
    return False


for token in [
    '#include "mcp_capacity_governor_diag.hpp"',
    '#include "../tools/command_sessions.hpp"',
    "struct mcp_route_identity_t",
    "thread_local mcp_route_identity_t tls_route_identity",
    "make_mcp_route_identity",
    "current_mcp_principal()",
    "current_mcp_session_hash()",
    "authorization_present",
    "mcp_identity_hash_text",
]:
    require("mcp", token, "MCP ingress identity extraction and propagation must remain present")

for token in [
    "enum class priority_t",
    "p0 = 0",
    "p1 = 1",
    "p2 = 2",
    "p3 = 3",
    "p4 = 4",
    "p5 = 5",
    "bool diagnostics_only = true",
    "bool enforcement_enabled = false",
    "inline quota_set_t make_quota_set",
    "q.global_external_active_tools = (std::max)(tool_workers, std::size_t{8})",
    "q.global_external_queued_tools = (std::max)(std::size_t{128}, tool_workers * std::size_t{32})",
    "per_principal_active_normal_tools = 4",
    "per_principal_active_long_running_tools = 1",
    "per_principal_queued_normal_tools = 32",
    "per_principal_queued_long_running_tools = 8",
    "per_session_active_mutations = 1",
    "per_session_active_read_only_tools = 4",
    "per_target_driver_debugger_active_tools = 2",
    "per_domain_mutating_active_tools = 1",
    "active_batch_children_per_principal = 16",
    "queued_batch_children_per_principal = 128",
    "active_background_command_sessions_per_principal = 2",
    "global_active_background_command_sessions = 8",
    "inline bool classify_long_running",
    "inline priority_t predict_priority",
    "inline std::uint32_t predict_cost_units",
    "inline prediction_t predict",
    "inline json pressure_json",
    "inline json prediction_json",
    "inline json activity_snapshot_json",
    "inline json recent_snapshot_json",
]:
    require("diag", token, "Phase 2 capacity model, quotas, priorities, or JSON diagnostics drifted")

for token in [
    "MCP-CAPACITY-DIAGNOSTIC",
    "MCP-CAPACITY-SNAPSHOT",
    "MCP-BATCH-FANOUT-DIAGNOSTIC",
    "MCP-DOWNSTREAM-PRESSURE",
    "phase2_enforced=%d",
    'prediction.enforcement_enabled ? 1 : 0',
    'out["phase2_diagnostics"]',
    '"phase2_diagnostics_only"',
    '{"enforcement_enabled", false}',
    'health["capacity"] = capacity_health_snapshot',
]:
    require("mcp", token, "required Phase 2 diagnostics-only logging or health surface is missing")

for token in [
    'diagnose_capacity("http_ingress_post_mcp"',
    'diagnose_capacity("http_ingress_get_mcp"',
    'diagnose_capacity("http_ingress_delete_mcp"',
    'diagnose_capacity("http_ingress_get_sse"',
    'diagnose_capacity("http_ingress_post_sse"',
    'diagnose_capacity("http_ingress_delete_sse"',
    'diagnose_capacity("http_ingress_post_message"',
    'diagnose_capacity("http_ingress_api_tools"',
    'diagnose_capacity("http_ingress_api_tools_call"',
    'diagnose_capacity("jsonrpc_route_pre_dispatch"',
    'diagnose_capacity("jsonrpc_batch_pre_expand"',
    'diagnose_capacity("jsonrpc_batch_child_pre_enqueue"',
    'diagnose_capacity("tools_call_pre_admission"',
    'diagnose_capacity("api_tools_call_pre_admission"',
    'diagnose_capacity("direct_registered_tool_pre_admission"',
]:
    require("mcp", token, "all current ingress, JSON-RPC, REST, batch, and direct tool paths need pre-admission diagnostics")

for token in [
    "JSON-RPC /mcp",
    "JSON-RPC /sse",
    "JSON-RPC /message",
    "REST /api/tools",
    "REST /api/tools/call",
    "direct external call_registered_tool",
    "internal/downstream producer",
]:
    require("mcp", token, "required Phase 2 transport identifier is missing")

for token in [
    "capacity_tool_context",
    "capacity_route_context",
    "capacity_pressure_snapshot",
    "capacity_health_snapshot",
    "capacity_diag::scoped_activity_t",
    "capacity_diag::remember_prediction",
    "capacity_diag::prediction_json",
    "mcp_capacity_snapshot_state_t",
    "mcp_capacity_counts_map_json",
    "mcp_capacity_contributors_json",
    "mcp_pressure_registry_json",
    "mcp_executor_health_snapshot(&capacity_state)",
]:
    require("mcp", token, "capacity diagnostics must remain source-enforced and health-visible")

for token in [
    "principal_id",
    "session_hash",
    "transport",
    "target_id",
    "target_pid",
    "batch_id",
    "batch_index",
    "batch_size",
    "external_tool",
    "read_only",
    "mutating",
    "long_running",
    "background_command",
    "driver_debugger",
]:
    require("mcp", token, "executor task metadata must retain Phase 2 pressure dimensions")

for token in [
    "record_pressure_enqueue",
    "record_pressure_start",
    "record_pressure_finish",
    "mcp_pressure_snapshot",
    "command_sessions::stats()",
    "work_queue::stats()",
    "work_queue::service_stats()",
    "critical_work_queue::stats()",
    "downstream_queues",
    "background_commands",
    "batch_fanout",
    "top_pressure_contributors",
    "overload_flags",
]:
    require("mcp", token, "queue, downstream, batch, long-running, and background pressure instrumentation must remain present")

for token in [
    "struct stats_t",
    "inline stats_t stats",
    "std::try_to_lock",
    "registry_lock_busy",
    "oldest_running_ms",
    "oldest_reader_active_ms",
    "active_summary",
]:
    require("cmd", token, "background command capacity snapshot must remain bounded and nonblocking")

for token in [
    "AIDA_PHASE2_CAPACITY_GUARD_SCRIPT",
    "AiDACapacityDiagnosticsGuards",
    "verify_phase2_capacity.py",
]:
    require("cmake", token, "Phase 2 static guard must be wired into the mandatory verification path")

require_regex("cmake",
              r"add_dependencies\s*\(\s*AiDAStandalone[^\)]*AiDACapacityDiagnosticsGuards",
              "add_dependencies(AiDAStandalone ... AiDACapacityDiagnosticsGuards)",
              "AiDAStandalone must depend on the Phase 2 capacity guard")

guarded_routes = {
    ("Post", "/mcp"): "http_ingress_post_mcp",
    ("Get", "/mcp"): "http_ingress_get_mcp",
    ("Delete", "/mcp"): "http_ingress_delete_mcp",
    ("Get", "/api/tools"): "http_ingress_api_tools",
    ("Post", "/api/tools/call"): "http_ingress_api_tools_call",
    ("Get", "/sse"): "http_ingress_get_sse",
    ("Post", "/sse"): "http_ingress_post_sse",
    ("Delete", "/sse"): "http_ingress_delete_sse",
    ("Post", "/message"): "http_ingress_post_message",
}
reviewed_route_exceptions = {
    ("Options", ".*"),
    ("Post", "/ida-plugin-auth"),
    ("Get", "/health"),
    ("Get", "/"),
}
for match in re.finditer(r"svr\.(Get|Post|Delete|Put|Patch|Options)\(\"([^\"]+)\"", TEXT["mcp"]):
    route = (match.group(1), match.group(2))
    line = TEXT["mcp"].count("\n", 0, match.start()) + 1
    if route in reviewed_route_exceptions:
        continue
    expected = guarded_routes.get(route)
    if not expected:
        errors.append((rel(FILES["mcp"]), line, f"svr.{route[0]}(\"{route[1]}\")", "new MCP HTTP route must be reviewed and given Phase 2 capacity diagnostics or an explicit guard exception"))
        continue
    window = TEXT["mcp"][match.start():match.start() + 2200]
    if expected not in window:
        errors.append((rel(FILES["mcp"]), line, f"svr.{route[0]}(\"{route[1]}\")", f"route is missing nearby diagnose_capacity marker {expected}"))

phase4_enforcement_spans = [
    function_span(TEXT["mcp"], "static bool mcp_tool_admission_try_acquire"),
]
for match in re.finditer(r"phase2_enforced\s*=\s*1|prediction\.enforcement_enabled\s*=\s*true", TEXT["mcp"]):
    if in_any_span(match.start(), phase4_enforcement_spans):
        continue
    token = match.group(0).splitlines()[0][:160]
    errors.append((rel(FILES["mcp"]), TEXT["mcp"].count("\n", 0, match.start()) + 1, token, "Phase 2 is diagnostics-only; only Phase 4 tool admission may enable enforcement"))

forbid_regex("diag",
             r"diagnostics_only\s*=\s*false|enforcement_enabled\s*=\s*true",
             "Phase 2 capacity model must not enable enforcement")

for raw_secret in [
    "Authorization').c_str()",
    'get_header_value("Authorization").c_str()',
    "Bearer ",
    "api_key",
    "private_key",
]:
    if raw_secret in TEXT["mcp"] or raw_secret in TEXT["diag"]:
        source_key = "mcp" if raw_secret in TEXT["mcp"] else "diag"
        fail(source_key, raw_secret, "capacity diagnostics must not log raw credentials or secret material")

if errors:
    for path, line, token, reason in errors:
        print(f"{path}:{line}: {token}: {reason}", file=sys.stderr)
    sys.exit(1)

print("Phase 2 capacity diagnostics guard passed: MCP ingress, prediction, pressure, health, and diagnostics-only invariants are present.")
