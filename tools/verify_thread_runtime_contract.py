from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STANDALONE_ROOT = ROOT / "src" / "standalone" / "src"
MANIFEST_PATH = ROOT / "tools" / "thread_runtime_contract_manifest.json"
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl"}
SKIP_DIRS = {
    ".git",
    ".claude",
    ".serena",
    ".vs",
    ".vscode",
    ".deps",
    "build",
    "build-ninja",
    "out",
    "dist",
    "node_modules",
    "__pycache__",
}

THREAD_TASK_CLASSES = {
    "bootstrap_thread",
    "queued_task",
    "security_monitor_task",
    "bounded_watchdog_thread",
    "suspended_probe_thread",
    "loader_sensitive_thread",
    "feature_worker_group",
}
FAILURE_POLICIES = {
    "fail_closed",
    "degrade_only_after_clean_integrity_verification",
    "reject_not_started",
    "cancel_and_late_drain",
    "external_cleanup",
}
PRIORITIES = {"P0", "P1", "P2", "P3", "P4", "P5"}
SECURITY_CLASSES_FAIL_CLOSED = {
    "license_arc_authority",
    "anti_tamper_integrity",
    "driver_authority",
    "runtime_integrity_lock",
    "protector_loader_sensitive",
    "mcp_authorization",
}
RAW_OR_EXCEPTION_APIS = {
    "std::thread",
    "std::jthread",
    "std::thread.emplace_back",
    "detached std::thread",
    "CreateThread",
    "_beginthreadex",
    "NtCreateThreadEx",
    "std::async",
    "QueueUserWorkItem",
}
KNOWN_APIS = RAW_OR_EXCEPTION_APIS.union({
    "work_queue::post_service_labeled",
    "work_queue::post_labeled",
    "work_queue::post_service",
    "work_queue::post",
    "critical_work_queue::post_labeled",
    "critical_work_queue::post",
    "mcp_executor.enqueue",
    "telemetry.enqueue",
    "win_thread.wrapper_state",
    "win_thread.start",
    "win_thread.start_detached",
    "PostMessageW",
    "PostThreadMessageW",
})
KNOWN_SECURITY_CLASSES = SECURITY_CLASSES_FAIL_CLOSED.union({
    "browser_sidecar",
    "diagnostics_liveness",
    "external_process_launch",
    "feature_runtime",
    "provider_auth_or_ai_runtime",
    "runtime_liveness",
    "testlab_diagnostics",
    "ui_adjacent",
    "win32_message_queue",
})


@dataclass(frozen=True)
class ScanHit:
    id: str
    path: str
    line: int
    api: str
    token: str
    source: str
    context: str
    occurrence_index: int


@dataclass(frozen=True)
class Failure:
    path: str
    line: int
    token: str
    reason: str
    text: str


SCAN_PATTERNS = [
    ("std::thread", "std::thread", re.compile(r"\bstd::thread\b(?!\s*::hardware_concurrency)")),
    ("std::jthread", "std::jthread", re.compile(r"\bstd::jthread\b")),
    ("detached std::thread", "detach", re.compile(r"\.\s*detach\s*\(")),
    ("CreateThread", "CreateThread", re.compile(r"\bCreateThread\s*\(")),
    ("_beginthreadex", "_beginthreadex", re.compile(r"\b_beginthreadex\s*\(")),
    ("NtCreateThreadEx", "NtCreateThreadEx", re.compile(r"\bNtCreateThreadEx\b")),
    ("std::async", "std::async", re.compile(r"\bstd::async\s*\(")),
    ("QueueUserWorkItem", "QueueUserWorkItem", re.compile(r"\bQueueUserWorkItem\s*\(")),
    ("work_queue::post_service_labeled", "post_service_labeled", re.compile(r"\bwork_queue::post_service_labeled\s*\(")),
    ("work_queue::post_labeled", "post_labeled", re.compile(r"\bwork_queue::post_labeled\s*\(")),
    ("work_queue::post_service", "post_service", re.compile(r"\bwork_queue::post_service\s*\(")),
    ("work_queue::post", "post", re.compile(r"\bwork_queue::post\s*\(")),
    ("critical_work_queue::post_labeled", "critical_post_labeled", re.compile(r"\bcritical_work_queue::post_labeled\s*\(")),
    ("critical_work_queue::post", "critical_post", re.compile(r"\bcritical_work_queue::post\s*\(")),
    ("mcp_executor.enqueue", "enqueue", re.compile(r"\b(?:selected_executor|executor|_executor)\.enqueue\s*\(")),
    ("telemetry.enqueue", "telemetry_enqueue", re.compile(r"\baida::telemetry::instance\(\)\.enqueue\s*\(")),
    ("win_thread.wrapper_state", "joinable_thread_t", re.compile(r"\bjoinable_thread_t\b")),
    ("win_thread.start_detached", "start_detached", re.compile(r"\baida::infra::win_thread::start_detached\s*\(")),
    ("win_thread.start", "win_thread_start", re.compile(r"(?:\.|->)start\s*\(")),
    ("PostMessageW", "PostMessageW", re.compile(r"\bPostMessageW\s*\(")),
    ("PostThreadMessageW", "PostThreadMessageW", re.compile(r"\bPostThreadMessageW\s*\(")),
]

THREAD_VECTOR_DECL_PATTERN = re.compile(r"\bstd::vector\s*<\s*std::thread\s*>\s+([A-Za-z_][A-Za-z0-9_]*)")


def relpath(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def normalize(text: str) -> str:
    return " ".join(text.strip().split())


def iter_source_files():
    for path in sorted(STANDALONE_ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(ROOT).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        yield path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def context_for(lines: list[str], index: int) -> str:
    start = max(0, index - 2)
    end = min(len(lines), index + 1)
    return "\n".join(normalize(lines[i]) for i in range(start, end))


def stable_id(path: str, api: str, context: str, occurrence_index: int) -> str:
    digest = hashlib.sha256(f"{path}\n{api}\n{context}".encode("utf-8")).hexdigest()[:16]
    return f"{path}:{api}:{digest}:{occurrence_index}"


def should_keep_match(api: str, line: str) -> bool:
    compact = line.replace(" ", "")
    if api == "win_thread.wrapper_state":
        return "joinable_thread_t" in line
    if api == "win_thread.start_detached":
        return "aida::infra::win_thread::start_detached" in line
    if api == "win_thread.start":
        return bool(re.search(r"(?:worker|writer|thread|reader_thread|regen_thread|refresher_thread|[A-Za-z_][A-Za-z0-9_]*(?:_thread|_worker|_monitor))(?:\.|->)start\s*\(", line))
    if api == "NtCreateThreadEx":
        return "NtCreateThreadEx" in line
    if api == "std::thread" and "std::thread::hardware_concurrency" in compact:
        return False
    return True


def scan_hits() -> list[ScanHit]:
    hits: list[ScanHit] = []
    occurrence_counts: dict[tuple[str, str, str], int] = {}
    for path in iter_source_files():
        text = read_text(path)
        lines = text.splitlines()
        rel = relpath(path)
        thread_vector_names = sorted(set(THREAD_VECTOR_DECL_PATTERN.findall(text)))
        for api, token, pattern in SCAN_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                line = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""
                if not should_keep_match(api, line):
                    continue
                context = context_for(lines, line_no - 1)
                key = (rel, api, context)
                occurrence = occurrence_counts.get(key, 0)
                occurrence_counts[key] = occurrence + 1
                hits.append(ScanHit(
                    id=stable_id(rel, api, context, occurrence),
                    path=rel,
                    line=line_no,
                    api=api,
                    token=token,
                    source=normalize(line),
                    context=context,
                    occurrence_index=occurrence,
                ))
        if thread_vector_names:
            vector_start_pattern = re.compile(
                r"\b(?:" + "|".join(re.escape(name) for name in thread_vector_names) + r")\s*\.\s*(?:emplace_back|push_back)\s*\("
            )
            for match in vector_start_pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                line = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""
                context = context_for(lines, line_no - 1)
                key = (rel, "std::thread.emplace_back", context)
                occurrence = occurrence_counts.get(key, 0)
                occurrence_counts[key] = occurrence + 1
                hits.append(ScanHit(
                    id=stable_id(rel, "std::thread.emplace_back", context, occurrence),
                    path=rel,
                    line=line_no,
                    api="std::thread.emplace_back",
                    token="emplace_back",
                    source=normalize(line),
                    context=context,
                    occurrence_index=occurrence,
                ))
    return sorted(hits, key=lambda h: (h.path, h.line, h.api, h.occurrence_index))


def inventory_hash(hits: list[ScanHit]) -> str:
    h = hashlib.sha256()
    for hit in hits:
        h.update(hit.id.encode("utf-8"))
        h.update(b"\0")
        h.update(hit.path.encode("utf-8"))
        h.update(b"\0")
        h.update(str(hit.line).encode("ascii"))
        h.update(b"\0")
        h.update(hit.api.encode("utf-8"))
        h.update(b"\0")
        h.update(hit.source.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def path_owner(path: str) -> str:
    rel = path.removeprefix("src/standalone/src/")
    parts = rel.split("/")
    if rel == "main.cpp":
        return "standalone.startup_render_loop"
    if parts[:2] == ["core", "anti-tamper"]:
        return "standalone.anti_tamper." + Path(path).stem
    if parts[:2] == ["core", "runtime"]:
        return "standalone.runtime." + Path(path).stem
    if parts[:2] == ["core", "mcp"]:
        return "standalone.mcp." + Path(path).stem
    if parts[:2] == ["core", "network"]:
        return "standalone.network." + Path(path).stem
    if parts[:2] == ["core", "debugger"]:
        return "standalone.debugger." + Path(path).stem
    if parts[:2] == ["core", "scanner"]:
        return "standalone.scanner." + Path(path).stem
    if parts[:2] == ["core", "disasm"]:
        return "standalone.disasm." + Path(path).stem
    if parts[:2] == ["core", "analysis"]:
        return "standalone.analysis." + Path(path).stem
    if parts[:2] == ["core", "auth"]:
        return "standalone.auth." + Path(path).stem
    if parts[:2] == ["core", "ai"]:
        return "standalone.ai." + Path(path).stem
    if parts[:2] == ["core", "testlab"]:
        return "standalone.testlab." + Path(path).stem
    if parts[:2] == ["core", "infra"]:
        return "standalone.infra." + Path(path).stem
    if parts and parts[0] == "helpers":
        return "standalone.helpers." + Path(path).stem
    return "standalone." + Path(path).stem


def extract_label(hit: ScanHit) -> str:
    match = re.search(r'\(\s*"([^"]{1,160})"', hit.source)
    if match:
        return match.group(1)
    if hit.api == "mcp_executor.enqueue":
        return "mcp.executor.enqueue"
    if hit.api == "telemetry.enqueue":
        return "anti_tamper.telemetry.enqueue"
    stem = Path(hit.path).stem
    return f"{stem}.{hit.api.replace('::', '.').replace(' ', '_')}.{hit.line}"


def classify(hit: ScanHit) -> dict[str, object]:
    path = hit.path
    source = hit.source
    owner = path_owner(path)
    label = extract_label(hit)
    task_class = "queued_task"
    failure = "cancel_and_late_drain"
    security = "feature_runtime"
    priority = "P3"
    cancellation = "cooperative cancellation or subsystem generation invalidation before state commit"
    deadline = "bounded by caller deadline, subsystem timeout, or queue shutdown; reject before start on full queue"
    shutdown = "subsystem owns shutdown signal and drains or joins without blocking the UI thread"
    lifetime = "captured values are copied or owned by shared subsystem state guarded by generation checks; stack references cannot outlive the submitting frame"
    loader = "not loader/protector sensitive"
    ui = "No direct ImGui, DX11, swapchain, render-target, WndProc-owned state, or UI global mutation; handoff must be bounded and dispatcher-compatible; the UI thread must not wait on this work"
    manual_tls = hit.api.startswith("work_queue::") or hit.api.startswith("critical_work_queue::") or hit.api in {"win_thread.start", "win_thread.start_detached", "mcp_executor.enqueue", "win_thread.wrapper_state"}
    header_restore = hit.api in {"win_thread.start", "win_thread.start_detached", "win_thread.wrapper_state"} or "arc_loader.cpp" in path or "standalone_driver.cpp" in path
    seh_guard = manual_tls or "anti-tamper" in path or "runtime" in path or "mcp_standalone.cpp" in path
    approved = hit.api in RAW_OR_EXCEPTION_APIS
    approved_reason = ""
    if "main.cpp" in path:
        task_class = "bootstrap_thread" if "startup" in label or hit.line < 6200 else "queued_task"
        security = "runtime_liveness" if "render" in label or "focus" in label or "hotkey" in label else "license_arc_authority"
        priority = "P0" if "license" in label or "driver" in label or "phase0" in label else "P1"
        failure = "fail_closed" if "license" in label or "driver" in label else "reject_not_started"
    if hit.api in {"PostMessageW", "PostThreadMessageW"}:
        task_class = "queued_task"
        security = "win32_message_queue"
        priority = "P1"
        failure = "reject_not_started"
        cancellation = "wake-only Win32 message posts cannot carry trusted payloads and must remain bounded by caller state"
        deadline = "post attempts are immediate and must not replace bounded worker admission"
        shutdown = "no thread ownership; message posts are process/window lifetime wake signals only"
        lifetime = "message parameters must be wake-only or same-thread UI command state, never raw worker-owned payload pointers"
    if "core/infra/" in path:
        task_class = "feature_worker_group" if hit.api in {"win_thread.start", "win_thread.start_detached", "win_thread.wrapper_state"} else "queued_task"
        security = "runtime_liveness"
        priority = "P0" if "critical_work_queue" in path else "P1"
        failure = "fail_closed" if "critical_work_queue" in path else "reject_not_started"
        shutdown = "queue shutdown sets stop state, notifies workers, and joins through joinable_thread_t with bounded fallback diagnostics"
        lifetime = "queue owns worker threads and task records until execution, cancellation, or shutdown drain completes"
    if "core/anti-tamper/" in path or "standalone_anti_tamper" in path or "standalone_anti_dump" in path:
        task_class = "security_monitor_task"
        security = "anti_tamper_integrity"
        priority = "P0"
        failure = "fail_closed"
        cancellation = "security monitor cancellation is only accepted during authorized shutdown or generation retirement"
        deadline = "bounded probe deadlines are diagnostic only; missing execution does not weaken enforcement"
        shutdown = "security state remains fail-closed until monitor exits or the process shuts down"
    if "anti_debug.hpp" in path and hit.api == "CreateThread":
        task_class = "suspended_probe_thread"
        security = "anti_tamper_integrity"
        failure = "fail_closed"
        loader = "anti-debug CREATE_SUSPENDED probe with explicit IPI alertable state"
        approved = True
        approved_reason = "path-specific anti-debug suspended probe requires CREATE_SUSPENDED before affinity/resume instrumentation"
    if "arc_loader.cpp" in path:
        task_class = "loader_sensitive_thread"
        security = "protector_loader_sensitive"
        priority = "P0"
        failure = "fail_closed"
        cancellation = "loader-sensitive work cannot be cancelled into a weaker path; timeout records evidence and preserves fail-closed state"
        deadline = "loader canary, watchdog, and invocation threads use existing bounded waits around ARC loader phases"
        shutdown = "ARC loader owns handles and joins or closes only after loader/protector state is consistent"
        lifetime = "captured loader state remains owned by the active ARC load generation until the guarded call exits"
        loader = "ARC loader, manual DllMain invocation, PEB/image-base, TLS, or protector-sensitive canary path"
        manual_tls = True
        header_restore = True
        seh_guard = True
        approved = True
        approved_reason = "ARC loader/protector path has path-specific direct thread probes and DllMain invocation requirements"
    if "standalone_driver.cpp" in path:
        security = "driver_authority"
        priority = "P0" if hit.api in RAW_OR_EXCEPTION_APIS else "P1"
        failure = "fail_closed"
        task_class = "loader_sensitive_thread" if hit.api in {"_beginthreadex", "NtCreateThreadEx"} or "_beginthreadex" in source else "feature_worker_group"
        cancellation = "driver and lower remote-call work uses generation, cancellation, and fail-closed driver authority state"
        deadline = "driver operations must use explicit deadlines and cannot block the UI thread"
        loader = "lower remote-call worker is loader/protector sensitive and cannot be replaced by a user-mode fallback"
        manual_tls = True
        header_restore = True
        seh_guard = True
        if hit.api in RAW_OR_EXCEPTION_APIS:
            approved = True
            approved_reason = "lower remote-call executor requires the existing path-specific _beginthreadex contract and fail-closed driver authority"
    if "standalone_license" in path:
        security = "license_arc_authority"
        priority = "P0"
        failure = "fail_closed"
        task_class = "bounded_watchdog_thread" if hit.api == "CreateThread" or "watch" in source.lower() else "security_monitor_task"
        cancellation = "license/ARC work never degrades to offline or weaker behavior; cancellation only aborts the current attempt fail-closed"
        deadline = "license transport watchdogs have explicit send/receive or activation deadlines"
        loader = "license/ARC authority path; not an overload fallback"
        if hit.api in RAW_OR_EXCEPTION_APIS:
            approved = True
            approved_reason = "license transport canary/watchdog path is path-specific and fail-closed"
    if "standalone_license_transport.cpp" in path:
        security = "license_arc_authority"
        priority = "P0"
        failure = "fail_closed"
        task_class = "bounded_watchdog_thread"
        approved = True
        approved_reason = "license transport bounded watchdog uses direct CreateThread with no weaker fallback"
    if "core/mcp/" in path:
        security = "mcp_authorization" if "mcp_standalone.cpp" in path else "feature_runtime"
        priority = "P1" if "mcp_standalone.cpp" in path else "P2"
        task_class = "feature_worker_group" if hit.api in {"mcp_executor.enqueue", "win_thread.start", "win_thread.start_detached", "win_thread.wrapper_state"} else "queued_task"
        failure = "reject_not_started" if hit.api == "mcp_executor.enqueue" else "cancel_and_late_drain"
        cancellation = "MCP tasks use active-session cancellation tokens, deadlines, and late-result fencing rules before mutation"
        deadline = "MCP executor work must carry request or tool deadlines and reject before start when queue capacity is unavailable"
        shutdown = "MCP executor stops accepting, signals cancellation, drains queued work, and joins worker threads outside the UI thread"
    if "camoufox" in path or "headless" in path:
        security = "browser_sidecar"
        priority = "P3"
        task_class = "feature_worker_group"
        failure = "external_cleanup"
        cancellation = "Camoufox work uses cooperative cancellation plus PID/session/generation-proven external cleanup only for owned sidecars"
        shutdown = "browser sidecar cleanup requires matching executable, PID, session, and generation ownership evidence"
        lifetime = "captured browser state must include session/generation ownership and cannot publish stale results"
    if any(part in path for part in ["/network/", "/scanner/", "/disasm/", "/analysis/", "/debugger/", "/emulation/"]):
        task_class = "feature_worker_group" if hit.api in RAW_OR_EXCEPTION_APIS or hit.api in {"win_thread.start", "win_thread.start_detached"} else "queued_task"
        security = "driver_authority" if "/debugger/" in path or "driver" in path else "feature_runtime"
        priority = "P2" if "/debugger/" in path else "P3"
        failure = "fail_closed" if security == "driver_authority" else failure
        deadline = "domain work must use explicit tool, scan, browser, or queue deadlines and return bounded timeout/cancel state"
        shutdown = "feature subsystem owns cancellation, late-drain, and joins; protected in-process workers are not force-killed"
    if any(part in path for part in ["/auth/", "/ai/"]):
        security = "provider_auth_or_ai_runtime"
        priority = "P2"
        task_class = "queued_task"
        failure = "reject_not_started"
        cancellation = "provider/auth tasks cancel cooperatively and must not expose secrets or weaken licensing state"
        lifetime = "captured provider references are shared_ptr or value copies; raw secrets are not logged by the contract"
    if "/testlab/" in path:
        security = "testlab_diagnostics"
        priority = "P4"
        failure = "cancel_and_late_drain"
        task_class = "feature_worker_group" if hit.api in RAW_OR_EXCEPTION_APIS else "queued_task"
    if "/helpers/" in path or "/core/ui/" in path:
        security = "ui_adjacent"
        priority = "P1"
        failure = "reject_not_started"
        task_class = "queued_task" if hit.api not in RAW_OR_EXCEPTION_APIS else "feature_worker_group"
        lifetime = "UI-adjacent captures must be copied values or generation-bound state; workers publish only through bounded dispatcher-compatible state"
    if "diag_log.hpp" in path:
        task_class = "bootstrap_thread"
        security = "diagnostics_liveness"
        priority = "P0"
        failure = "reject_not_started"
        cancellation = "async logger observes process shutdown and never blocks the UI thread"
        shutdown = "diagnostic logger owns its CRT thread and drains through its existing log lifecycle"
        approved = True
        approved_reason = "early diagnostics logger starts before normal queues are safe"
    if "run_target.cpp" in path and hit.api == "CreateThread":
        task_class = "bounded_watchdog_thread"
        security = "external_process_launch"
        priority = "P2"
        failure = "external_cleanup"
        cancellation = "target launch worker uses explicit timeout and external process ownership evidence before cleanup"
        approved = True
        approved_reason = "CreateProcess worker isolates blocking launch from UI and is bounded by explicit timeout"
    if "network_hook_sidecar.cpp" in path and hit.api == "CreateThread":
        task_class = "feature_worker_group"
        security = "testlab_diagnostics"
        priority = "P4"
        failure = "external_cleanup"
        approved = True
        approved_reason = "Test Lab network hook sidecar accept thread is path-specific and externally owned by the sidecar pair"
    if hit.api in {"std::thread", "std::thread.emplace_back", "detached std::thread"} and not approved_reason:
        approved = True
        approved_reason = "existing reviewed raw std::thread feature worker group, holder, or vector start; future raw std::thread additions must add a path-specific contract entry"
    if hit.api in {"CreateThread", "_beginthreadex", "NtCreateThreadEx"} and not approved_reason:
        approved = True
        approved_reason = "existing reviewed path-specific low-level thread use; future additions must add a justified contract entry"
    if hit.api in {"std::async", "QueueUserWorkItem"}:
        approved = False
        approved_reason = ""
    if security in SECURITY_CLASSES_FAIL_CLOSED:
        failure = "fail_closed"
    return {
        "id": hit.id,
        "path": hit.path,
        "line": hit.line,
        "source_location": f"{hit.path}:{hit.line}",
        "source_line": hit.source,
        "source_context": hit.context,
        "creation_or_queue_api": hit.api,
        "matched_token": hit.token,
        "owning_subsystem": owner,
        "thread_task_class": task_class,
        "label": label,
        "security_class": security,
        "priority": priority,
        "cancellation_policy": cancellation,
        "timeout_deadline_policy": deadline,
        "shutdown_join_behavior": shutdown,
        "failure_policy": failure,
        "ui_access_policy": ui,
        "captured_state_lifetime_rule": lifetime,
        "loader_protector_sensitivity": loader,
        "manual_tls_required": bool(manual_tls),
        "loader_header_restore_required": bool(header_restore),
        "seh_guard_required": bool(seh_guard),
        "approved_exception": bool(approved),
        "approved_exception_reason": approved_reason,
    }


def class_policies() -> dict[str, dict[str, str]]:
    return {
        "bootstrap_thread": {
            "owner_lifetime_rule": "owned by startup or diagnostics subsystem and must not outlive process shutdown state",
            "no_ui_blocking_rule": "must never block the UI thread; startup work posts evidence or rejects before start",
            "failure_policy": "reject_not_started",
        },
        "queued_task": {
            "owner_lifetime_rule": "owned by general, service, or critical queue until execution, cancellation, or shutdown drain",
            "no_ui_blocking_rule": "must not mutate ImGui/DX11/swapchain/WndProc state directly and must use bounded dispatcher-compatible handoff",
            "failure_policy": "reject_not_started",
        },
        "security_monitor_task": {
            "owner_lifetime_rule": "owned by license, ARC, anti-tamper, Runtime Integrity Lock, or driver authority generation",
            "no_ui_blocking_rule": "must never make the UI wait on security, driver, network, or MCP work",
            "failure_policy": "fail_closed",
        },
        "bounded_watchdog_thread": {
            "owner_lifetime_rule": "owned by a narrow caller state block with explicit deadline and bounded handle cleanup",
            "no_ui_blocking_rule": "watchdog joins and waits must occur off the UI thread or use nonblocking diagnostics",
            "failure_policy": "external_cleanup",
        },
        "suspended_probe_thread": {
            "owner_lifetime_rule": "owned by anti-debug probe state through create-suspended, affinity, resume, and bounded cleanup",
            "no_ui_blocking_rule": "probe state must not call UI or block the UI thread",
            "failure_policy": "fail_closed",
        },
        "loader_sensitive_thread": {
            "owner_lifetime_rule": "owned by active loader/protector generation until manual TLS/header/SEH-sensitive work exits",
            "no_ui_blocking_rule": "loader-sensitive work cannot be awaited by the UI thread",
            "failure_policy": "fail_closed",
        },
        "feature_worker_group": {
            "owner_lifetime_rule": "owned by a feature subsystem with cancellation, deadline, and late-result drain/fencing",
            "no_ui_blocking_rule": "feature workers must publish through bounded dispatcher-compatible handoff and cannot wait the UI on MCP, driver, browser, network, scanner, decompiler, or background-command work",
            "failure_policy": "cancel_and_late_drain",
        },
    }


def build_manifest() -> dict[str, object]:
    hits = scan_hits()
    entries = [classify(hit) for hit in hits]
    return {
        "schema_version": 1,
        "scope": "src/standalone/src",
        "inventory_sha256": inventory_hash(hits),
        "global_no_ui_blocking_rules": [
            "Only the UI thread may own Win32 WndProc dispatch, ImGui context, DX11 immediate context, swapchain resize, render targets, Present, DWM blur, and UI rendering state",
            "Worker-to-UI handoff must be bounded and dispatcher-compatible; workers may not use cross-thread SendMessageW",
            "The UI thread must not wait on MCP, driver, browser, network, scanner, decompiler, background-command, or feature worker work",
            "Protected in-process workers must not be force-killed; long external sidecars may use external cleanup only with PID, session, generation, and executable ownership evidence",
        ],
        "failure_policy_definitions": {
            "fail_closed": "deny or stop protected behavior without fallback to weaker license, ARC, driver, anti-tamper, Runtime Integrity Lock, protector, or MCP authorization state",
            "degrade_only_after_clean_integrity_verification": "allow reduced non-security behavior only after clean integrity verification and never for authority checks",
            "reject_not_started": "return a structured not-started result before any task begins or state mutates",
            "cancel_and_late_drain": "signal cooperative cancellation, fence late results, and drain without blocking the UI",
            "external_cleanup": "cleanup only external owned processes or sidecars after PID, session, generation, and executable proof",
        },
        "class_policies": class_policies(),
        "entries": entries,
    }


def add_failure(failures: list[Failure], path: str, line: int, token: str, reason: str, text: str) -> None:
    failures.append(Failure(path, line, token, reason, text))


def load_manifest(path: Path) -> dict[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise RuntimeError(f"manifest is missing: {path}") from None
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"manifest JSON parse failed at line {exc.lineno} column {exc.colno}: {exc.msg}") from None


def require_string(entry: dict[str, object], key: str) -> str | None:
    value = entry.get(key)
    if isinstance(value, str) and value.strip():
        return value
    return None


def validate_entry(entry: dict[str, object], failures: list[Failure]) -> None:
    path = str(entry.get("path", "<manifest>"))
    line_value = entry.get("line", 1)
    line = int(line_value) if isinstance(line_value, int) else 1
    required_strings = [
        "id",
        "path",
        "source_location",
        "source_line",
        "source_context",
        "creation_or_queue_api",
        "matched_token",
        "owning_subsystem",
        "thread_task_class",
        "label",
        "security_class",
        "priority",
        "cancellation_policy",
        "timeout_deadline_policy",
        "shutdown_join_behavior",
        "failure_policy",
        "ui_access_policy",
        "captured_state_lifetime_rule",
        "loader_protector_sensitivity",
    ]
    for key in required_strings:
        if not require_string(entry, key):
            add_failure(failures, path, line, key, "contract entry field is missing or empty", json.dumps(entry, sort_keys=True)[:500])
    task_class = entry.get("thread_task_class")
    if task_class not in THREAD_TASK_CLASSES:
        add_failure(failures, path, line, "thread_task_class", "unknown thread/task class", str(task_class))
    failure = entry.get("failure_policy")
    if failure not in FAILURE_POLICIES:
        add_failure(failures, path, line, "failure_policy", "unknown failure policy", str(failure))
    priority = entry.get("priority")
    if priority not in PRIORITIES:
        add_failure(failures, path, line, "priority", "unknown priority", str(priority))
    for key in ["manual_tls_required", "loader_header_restore_required", "seh_guard_required", "approved_exception"]:
        if not isinstance(entry.get(key), bool):
            add_failure(failures, path, line, key, "contract boolean field is missing or not boolean", str(entry.get(key)))
    if entry.get("approved_exception") is True and not require_string(entry, "approved_exception_reason"):
        add_failure(failures, path, line, "approved_exception_reason", "approved exceptions must include a path-specific reason", "")
    security = entry.get("security_class")
    if security in SECURITY_CLASSES_FAIL_CLOSED and failure != "fail_closed":
        add_failure(failures, path, line, "failure_policy", "security authority paths must fail closed", str(failure))
    if task_class in {"security_monitor_task", "loader_sensitive_thread", "suspended_probe_thread"} and failure != "fail_closed":
        add_failure(failures, path, line, "failure_policy", "security/probe/loader classes must fail closed", str(failure))
    ui_policy = str(entry.get("ui_access_policy", ""))
    if "No direct ImGui" not in ui_policy or "UI thread must not wait" not in ui_policy:
        add_failure(failures, path, line, "ui_access_policy", "UI blocking rule must explicitly prohibit direct UI mutation and UI waits", ui_policy)
    api = str(entry.get("creation_or_queue_api", ""))
    if api not in KNOWN_APIS:
        add_failure(failures, path, line, api, "unknown creation or queue API enum", api)
    security = str(entry.get("security_class", ""))
    if security not in KNOWN_SECURITY_CLASSES:
        add_failure(failures, path, line, "security_class", "unknown security class enum", security)
    if api in RAW_OR_EXCEPTION_APIS and entry.get("approved_exception") is not True:
        add_failure(failures, path, line, api, "raw or low-level thread APIs must be explicit approved exceptions or absent", str(entry.get("approved_exception")))


def validate_manifest(manifest: dict[str, object], hits: list[ScanHit]) -> list[Failure]:
    failures: list[Failure] = []
    if manifest.get("schema_version") != 1:
        add_failure(failures, "tools/thread_runtime_contract_manifest.json", 1, "schema_version", "schema_version must be 1", str(manifest.get("schema_version")))
    if manifest.get("scope") != "src/standalone/src":
        add_failure(failures, "tools/thread_runtime_contract_manifest.json", 1, "scope", "scope must be src/standalone/src", str(manifest.get("scope")))
    if manifest.get("inventory_sha256") != inventory_hash(hits):
        add_failure(failures, "tools/thread_runtime_contract_manifest.json", 1, "inventory_sha256", "current standalone thread/task inventory differs from reviewed manifest", f"expected={manifest.get('inventory_sha256')} actual={inventory_hash(hits)}")
    policies = manifest.get("class_policies")
    if not isinstance(policies, dict):
        add_failure(failures, "tools/thread_runtime_contract_manifest.json", 1, "class_policies", "class policy map is missing", "")
    else:
        missing = THREAD_TASK_CLASSES.difference(policies.keys())
        for name in sorted(missing):
            add_failure(failures, "tools/thread_runtime_contract_manifest.json", 1, name, "class policy is missing", "")
    rules = manifest.get("global_no_ui_blocking_rules")
    if not isinstance(rules, list) or len(rules) < 4:
        add_failure(failures, "tools/thread_runtime_contract_manifest.json", 1, "global_no_ui_blocking_rules", "global no-UI-blocking policy is incomplete", "")
    entries_value = manifest.get("entries")
    if not isinstance(entries_value, list):
        add_failure(failures, "tools/thread_runtime_contract_manifest.json", 1, "entries", "entries must be a list", "")
        return failures
    entries = [entry for entry in entries_value if isinstance(entry, dict)]
    if len(entries) != len(entries_value):
        add_failure(failures, "tools/thread_runtime_contract_manifest.json", 1, "entries", "all entries must be objects", "")
    entries_by_id: dict[str, dict[str, object]] = {}
    for entry in entries:
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id:
            add_failure(failures, str(entry.get("path", "<manifest>")), int(entry.get("line", 1)) if isinstance(entry.get("line"), int) else 1, "id", "entry id is missing", "")
            continue
        if entry_id in entries_by_id:
            add_failure(failures, str(entry.get("path", "<manifest>")), int(entry.get("line", 1)) if isinstance(entry.get("line"), int) else 1, "id", "duplicate contract entry id", entry_id)
        entries_by_id[entry_id] = entry
    hits_by_id = {hit.id: hit for hit in hits}
    for hit in hits:
        entry = entries_by_id.get(hit.id)
        if not entry:
            add_failure(failures, hit.path, hit.line, hit.token, "thread/task path is not mapped to a Phase 1 runtime contract entry", hit.source)
            continue
        if entry.get("path") != hit.path or entry.get("creation_or_queue_api") != hit.api or entry.get("source_line") != hit.source:
            add_failure(failures, hit.path, hit.line, hit.token, "contract entry no longer matches current source occurrence", hit.source)
    for entry_id, entry in entries_by_id.items():
        hit = hits_by_id.get(entry_id)
        if not hit:
            add_failure(failures, str(entry.get("path", "<manifest>")), int(entry.get("line", 1)) if isinstance(entry.get("line"), int) else 1, str(entry.get("matched_token", entry_id)), "manifest entry has no matching current source occurrence", str(entry.get("source_line", "")))
        validate_entry(entry, failures)
    return failures


def print_failures(failures: list[Failure]) -> None:
    for failure in failures:
        print(f"{failure.path}:{failure.line}: token={failure.token}: {failure.reason}: {failure.text}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--emit-manifest", action="store_true")
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path
    if not STANDALONE_ROOT.exists():
        print(f"{STANDALONE_ROOT.as_posix()}:1: token=src/standalone/src: standalone source root is missing", file=sys.stderr)
        return 1
    if args.emit_manifest:
        payload = json.dumps(build_manifest(), indent=2, sort_keys=False) + "\n"
        if args.write_manifest:
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(payload, encoding="utf-8")
            print(f"Wrote {manifest_path} with Phase 1 thread runtime contract inventory.")
        else:
            print(payload, end="")
        return 0
    hits = scan_hits()
    try:
        manifest = load_manifest(manifest_path)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    failures = validate_manifest(manifest, hits)
    if failures:
        print_failures(failures)
        return 1
    print(f"AiDA Phase 1 thread runtime contract verified for {len(hits)} standalone thread/task paths.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
