from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "mcp": ROOT / "src" / "standalone" / "src" / "core" / "mcp" / "mcp_standalone.cpp",
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


def fail_path(path, text, pos, token, reason):
    errors.append((rel(path), text.count("\n", 0, pos) + 1, token, reason))


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


def function_body(text, signature):
    start = text.find(signature)
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


body = function_body(TEXT["mcp"], "tool_result_t server_t::call_registered_tool")
if not body:
    fail("mcp", "tool_result_t server_t::call_registered_tool", "direct call_registered_tool symbol body is missing")

for token in [
    "direct external call_registered_tool",
    "internal/downstream producer",
    "direct_registered_tool_pre_admission",
    "mcp_tool_try_acquire_capacity(capacity_prediction, call_begin, &tool_capacity_lease, &admission_rejection)",
    "selected_executor.enqueue(std::move(task), meta)",
    "MCP-TOOL-BROKER-ADMIT",
    "MCP_TOOL_ADMISSION_REJECTED",
    '"broker_admission"] = "rejected"',
    '"disposition"] = "not_started"',
    '"late_result_disposition"] = "not_started"',
    "tool_capacity_lease.release(\"enqueue_failure\")",
    "tool_result_t::error(\"MCP direct tool broker admission rejected; tool was not started.\"",
    "MCP_TOOL_CAPACITY_REJECT",
    "MCP-TOOL-BYPASS-AUDIT",
    "source_visible_internal_callsite_contract",
    '"user_input_consulted_for_bypass"] = false',
]:
    if token not in body and token not in TEXT["mcp"]:
        fail("mcp", token, "Phase 4 direct-call admission or bypass-audit evidence is missing")

require_regex("mcp",
              r"if\s*\(!external_visible_only\)\s*\{(?:(?!\n\s*\}\s*\n\s*mcp_tool_capacity_lease_t).)*mcp_tool_bypass_audit\(capacity_prediction,\s*\"source_visible_internal_callsite_contract\"\).*?invoke_tool_with_concurrency_policy\(found,\s*arguments,\s*handler_copy,\s*&metrics\).*?return tr;",
              "if (!external_visible_only) ... MCP-TOOL-BYPASS-AUDIT ... invoke_tool_with_concurrency_policy ... return tr;",
              "internal direct-call bypass must be explicit, audited, and source-visible before inline handler dispatch")

internal_start = body.find("if (!external_visible_only)")
internal_end = body.find("mcp_tool_capacity_lease_t tool_capacity_lease", internal_start)
if internal_start >= 0 and internal_end > internal_start:
    internal_slice = body[internal_start:internal_end]
    for forbidden in ["arguments.contains", "arguments.value", "arguments[", "payload.value", "params.value", "params["]:
        if forbidden in internal_slice:
            fail("mcp", forbidden, "internal bypass decision must not depend on spoofable caller arguments")

require_regex("mcp",
              r"mcp_tool_capacity_lease_t\s+tool_capacity_lease;.*?mcp_tool_try_acquire_capacity\(capacity_prediction,\s*call_begin,\s*&tool_capacity_lease,\s*&admission_rejection\).*?auto\s+task\s*=.*?invoke_tool_with_concurrency_policy\(found,\s*arguments,\s*handler_copy,\s*&task_metrics\).*?if\s*\(!selected_executor\.enqueue\(std::move\(task\),\s*meta\)\)",
              "mcp_tool_try_acquire_capacity ... auto task ... invoke_tool_with_concurrency_policy ... selected_executor.enqueue",
              "external direct calls must define handler work only inside an executor task and require broker admission")

require_order("mcp",
              "if (!selected_executor.enqueue(std::move(task), meta))",
              "future.wait_for(std::chrono::milliseconds(timeout_ms))",
              "external direct calls must test broker admission before waiting for execution")
require_order("mcp",
              "tool_capacity_lease.release(\"enqueue_failure\")",
              "tool_result_t::error(\"MCP direct tool broker admission rejected; tool was not started.\"",
              "enqueue rejection must release the tool lease before returning structured not-started error")

allowed_false_callers = {
    "src/standalone/src/core/ai/standalone_chat.cpp",
    "src/standalone/src/core/network/network_tool_aliases_standalone.cpp",
    "src/standalone/src/core/testlab/test_all_mcp.cpp",
}

call_re = re.compile(r"call_registered_tool\s*\((?P<body>.*?)\)\s*;", re.S)
for path in (ROOT / "src" / "standalone").rglob("*.cpp"):
    text = read(path)
    for match in call_re.finditer(text):
        prefix = text[max(0, match.start() - 80):match.start()]
        if "server_t::" in prefix or "tool_result_t" in prefix:
            continue
        call_body = match.group("body")
        path_rel = rel(path)
        compact = re.sub(r"\s+", " ", call_body)
        if "false" in call_body:
            if path_rel not in allowed_false_callers:
                fail_path(path, text, match.start(), compact[:180], "internal call_registered_tool bypass call site is not in the reviewed source-visible allowlist")
        elif "true" in call_body:
            continue
        else:
            fail_path(path, text, match.start(), compact[:180], "call_registered_tool callers must pass a literal external_visible_only value")

for token in [
    "AIDA_PHASE4_DIRECT_CALL_ADMISSION_GUARD_SCRIPT",
    "AiDADirectCallAdmissionGuards",
    "verify_phase4_direct_call_admission.py",
]:
    require("cmake", token, "Phase 4 direct-call static guard must be wired into CMake")

require_regex("cmake",
              r"add_dependencies\s*\(\s*AiDADirectCallAdmissionGuards[^\)]*AiDAIngressAdmissionGuards",
              "add_dependencies(AiDADirectCallAdmissionGuards ... AiDAIngressAdmissionGuards)",
              "Phase 4 guard must run after Phase 3 ingress admission guard")
require_regex("cmake",
              r"add_dependencies\s*\(\s*AiDAStandalone[^\)]*AiDADirectCallAdmissionGuards",
              "add_dependencies(AiDAStandalone ... AiDADirectCallAdmissionGuards)",
              "AiDAStandalone must depend on the Phase 4 direct-call admission guard")

if errors:
    for path, line, token, reason in errors:
        print(f"{path}:{line}: {token}: {reason}", file=sys.stderr)
    sys.exit(1)

print("Phase 4 direct call_registered_tool admission guard passed: external direct calls require broker admission, internal bypasses are audited, and not-started rejection details are structured.")
