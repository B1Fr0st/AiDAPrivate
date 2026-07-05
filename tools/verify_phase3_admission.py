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
        errors.append((rel(path), 0, str(path), "required Phase 3 source file is missing"))
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


def require_regex(path_key, pattern, token, reason, flags=re.S):
    if not re.search(pattern, TEXT[path_key], flags):
        fail(path_key, token, reason)


def require_order(path_key, first, second, reason):
    text = TEXT[path_key]
    first_pos = text.find(first)
    second_pos = text.find(second)
    if first_pos < 0 or second_pos < 0 or first_pos >= second_pos:
        fail(path_key, f"{first} -> {second}", reason)


for token in [
    "MCP-CAPACITY-ADMIT",
    "MCP-CAPACITY-REJECT",
    "MCP-CAPACITY-RELEASE",
    "MCP-BATCH-ADMIT",
    "MCP-BATCH-REJECT",
    "MCP-STREAM-ADMIT",
    "MCP-STREAM-REJECT",
    "MCP-STREAM-RELEASE",
]:
    require("mcp", token, "required Phase 3 admission, batch, or stream event is missing")

for token in [
    "mcp_try_admit_http_ingress",
    "mcp_ingress_is_governed_route",
    "mcp_ingress_try_admit",
    "mcp_ingress_try_activate_locked",
    "g_mcp_ingress_by_route",
    "g_mcp_ingress_by_route_principal",
    "mcp_ingress_record_rejection",
    "tls_http_request_counted",
    "mcp_http_capacity_rejection_body",
    "MCP_CAPACITY_REJECT",
    '"disposition", "not_started"',
    'req.path == "/mcp"',
    'req.path == "/message"',
    'req.path == "/sse"',
    'req.path == "/api/tools/call"',
]:
    require("mcp", token, "HTTP ingress admission must remain enforced before governed route handlers")

require_order("mcp",
              "if (!mcp_try_admit_http_ingress(req, res))",
              "g_active_http_requests.fetch_add",
              "pre-routing admission must run before request active accounting and downstream handlers")

for token in [
    "mcp_reserved_lane_t",
    "mcp_try_acquire_reserved_lane",
    "mcp_reserved_lanes_health_snapshot",
    "mcp_reserved_lane_rejection_body",
    "jsonrpc_route_dispatch",
    "jsonrpc_batch_reserved_inline",
    "health_available",
    "cancellation_available",
    "p0_available",
    "reserved_lane_availability",
]:
    require("mcp", token, "health, cancellation, shutdown, and P0 reserved lanes must remain explicit")

for token in [
    "reserved_control_batch_items",
    "reservable_batch_items",
    "reserve_mcp_batch_children(batch_identity.principal_id, reservable_batch_items)",
    "item_reserved_control",
    "mcp_jsonrpc_item_uses_reserved_lane",
    "make_batch_not_started_error",
    "mcp_jsonrpc_batch_reservation",
    "g_mcp_batch_children_rejected",
    "g_mcp_batch_children_reserved",
    "batch_incomplete_reason",
    "connection_closed_now(connection_closed)",
]:
    require("mcp", token, "JSON-RPC batch admission must reserve non-control children before expansion and reject excess children individually")

require_regex("mcp",
              r"reserve_mcp_batch_children\(batch_identity\.principal_id,\s*reservable_batch_items\).*?auto& executor = mcp_batch_executor\(\).*?executor\.enqueue",
              "reserve_mcp_batch_children(...) ... executor.enqueue",
              "batch capacity must be reserved before any child is enqueued")
require_regex("mcp",
              r"if \(!reservation\).*?complete_item\(i,\s*make_batch_not_started_error.*?continue;\s*\}\s*log_batch_admit\(\"child_pre_enqueue\".*?executor\.enqueue",
              "if (!reservation) ... not_started ... executor.enqueue",
              "unreserved batch children must be rejected before executor enqueue")

for token in [
    "AIDA_MCP_MAX_STREAMS_PER_PRINCIPAL",
    "max_concurrent_streams_per_principal",
    "g_stream_principal_buckets",
    "set_stream_rejection_response",
    "release_stream_slot",
    "release_all_stream_slots",
    "stream_capacity_health_snapshot",
]:
    require("mcp", token, "per-principal SSE stream caps and cleanup must remain present")

for token in [
    'out["ingress_admission"]',
    'out["rejection_counters"]',
    'out["reserved_lane_availability"]',
    'out["batch_fanout"]',
    'out["streams"]',
    'health["reserved_lanes"]',
    'health["p0_available"]',
    'health["health_available"]',
    'health["cancellation_available"]',
]:
    require("mcp", token, "Phase 3 health snapshot fields are missing")

for token in [
    "global_ingress_active_requests",
    "global_ingress_queued_requests",
    "per_principal_ingress_active_requests",
    "per_principal_ingress_queued_requests",
    "global_ingress_streams",
    "per_principal_ingress_streams",
    "p0_reserved_liveness_slots",
]:
    require("diag", token, "Phase 3 ingress and reserved-lane quota data is missing")

for token in [
    "AIDA_PHASE3_INGRESS_ADMISSION_GUARD_SCRIPT",
    "AiDAIngressAdmissionGuards",
    "verify_phase3_admission.py",
]:
    require("cmake", token, "Phase 3 static guard must be wired into the mandatory verification path")

require_regex("cmake",
              r"add_dependencies\s*\(\s*AiDAIngressAdmissionGuards[^\)]*AiDACapacityDiagnosticsGuards",
              "add_dependencies(AiDAIngressAdmissionGuards ... AiDACapacityDiagnosticsGuards)",
              "Phase 3 guard must run after Phase 0/1/2 guards")
require_regex("cmake",
              r"add_dependencies\s*\(\s*AiDAStandalone[^\)]*AiDAIngressAdmissionGuards",
              "add_dependencies(AiDAStandalone ... AiDAIngressAdmissionGuards)",
              "AiDAStandalone must depend on the Phase 3 ingress admission guard")

for forbidden in [
    "cmake --build",
    "build-host.cmd",
    "msbuild",
    "ninja",
]:
    if forbidden in TEXT["mcp"]:
        fail("mcp", forbidden, "Phase 3 source guard found forbidden build-tool text in MCP source")

if errors:
    for path, line, token, reason in errors:
        print(f"{path}:{line}: {token}: {reason}", file=sys.stderr)
    sys.exit(1)

print("Phase 3 ingress admission guard passed: ingress caps, reserved lanes, batch reservation, stream caps, health, and rejection evidence are present.")
