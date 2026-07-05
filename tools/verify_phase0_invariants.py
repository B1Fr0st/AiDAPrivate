from __future__ import annotations

import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STANDALONE_ROOT = ROOT / "src" / "standalone" / "src"
MAIN_CPP = STANDALONE_ROOT / "main.cpp"
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


@dataclass(frozen=True)
class Failure:
    path: str
    line: int
    token: str
    reason: str
    text: str


THREAD_ALLOWLIST = {
    ("src/standalone/src/core/anti-tamper/anti_debug.hpp", "HANDLE remote_handle = CreateThread(nullptr, 0, &ipi_alertable_thread, &remote_signal, CREATE_SUSPENDED, nullptr);"): "approved suspended anti-debug IPI alertable probe",
    ("src/standalone/src/core/anti-tamper/anti_dump.hpp", "HANDLE thread = CreateThread(nullptr, 0, dacl_seal_worker_proc, state, 0, nullptr);"): "approved anti-dump DACL seal worker",
    ("src/standalone/src/core/anti-tamper/nanomites.hpp", "HANDLE worker = CreateThread(nullptr, 0, drx_apply_proc, &args, 0, nullptr);"): "approved nanomite DRx apply worker",
    ("src/standalone/src/core/anti-tamper/nanomites.hpp", "s.refresher_thread.detach();"): "approved nanomite refresher shutdown detach",
    ("src/standalone/src/core/infra/critical_work_queue.hpp", "w.detach();"): "approved critical work queue bounded shutdown fallback",
    ("src/standalone/src/core/infra/win_thread.hpp", "HANDLE h = CreateThread(nullptr, stack_bytes, &entry, state, flags, &tid);"): "approved low-level AiDA thread wrapper",
    ("src/standalone/src/core/infra/win_thread.hpp", "GetProcAddress(ntdll, \"NtCreateThreadEx\")) : nullptr;"): "approved low-level AiDA thread wrapper dynamic probe",
    ("src/standalone/src/core/infra/win_thread.hpp", "\"NtCreateThreadEx unavailable name=%s ntdll=%p gle=%lu\","): "approved low-level AiDA thread wrapper diagnostic token",
    ("src/standalone/src/core/infra/win_thread.hpp", "append_nt_attempt_error(errors, \"NtCreateThreadEx\", name, stack_bytes, static_cast<LONG>(0xC0000139L), gle, errno, 0);"): "approved low-level AiDA thread wrapper diagnostic token",
    ("src/standalone/src/core/infra/win_thread.hpp", "\"NtCreateThreadEx result name=%s stack_bytes=%u status=0x%08lX handle=%p tid=%lu elapsed_ms=%lu gle=%lu errno=%d caller_pid=%lu caller_tid=%lu state=%p entry=%p\","): "approved low-level AiDA thread wrapper diagnostic token",
    ("src/standalone/src/core/infra/win_thread.hpp", "append_nt_attempt_error(errors, \"NtCreateThreadEx\", name, stack_bytes, status, gle, crt, elapsed);"): "approved low-level AiDA thread wrapper diagnostic token",
    ("src/standalone/src/core/infra/win_thread.hpp", "uintptr_t raw = _beginthreadex(nullptr, stack_bytes, &crt_entry, state, 0, &tid);"): "approved low-level AiDA thread wrapper CRT path",
    ("src/standalone/src/core/infra/work_queue.hpp", "w.detach();"): "approved work queue bounded shutdown fallback",
    ("src/standalone/src/core/diagnostics/observer.hpp", "worker.detach();"): "approved diagnostics observer bounded lifecycle thread",
    ("src/standalone/src/core/mcp/mcp_standalone.cpp", "worker.detach();"): "approved MCP executor shutdown fallback",
    ("src/standalone/src/core/network/burp/collaborator.cpp", "std::thread(task).detach();"): "approved existing collaborator async task exception",
    ("src/standalone/src/core/network/burp/crawl_audit.cpp", "std::thread worker;"): "approved existing crawl audit worker holder pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/burp/crawl_audit.cpp", "entry->worker = std::thread([pipeline_id, crawl_id, cf, cfg_copy]() {"): "approved crawl audit owned worker",
    ("src/standalone/src/core/network/burp/intruder_engine.cpp", "std::vector<std::thread> workers;"): "approved existing intruder worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/burp/intruder_engine.cpp", "std::vector<std::thread> ws;"): "approved existing intruder batch worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/burp/offensive/business_logic_engine.cpp", "std::vector<std::thread> threads;"): "approved existing business logic worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/burp/param_miner.cpp", "std::vector<std::thread> threads;"): "approved existing param miner worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/flow_store.cpp", "std::vector<std::thread> workers;"): "approved existing flow store worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/mitm_proxy.cpp", "std::thread thread;"): "approved existing MITM proxy listener holder pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/mitm_proxy.cpp", "rt->thread = std::thread(extra_listener_loop, rt);"): "approved MITM proxy owned listener",
    ("src/standalone/src/core/network/quic_proxy.cpp", "std::thread worker;"): "approved existing QUIC proxy listener holder pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/quic_proxy.cpp", "rt->worker = std::thread(listener_loop, rt);"): "approved QUIC proxy owned listener",
    ("src/standalone/src/core/runtime/arc_loader.cpp", "HANDLE canary = CreateThread(nullptr, 0, &arc_diag_canary_thread_proc,"): "approved ARC loader canary probe",
    ("src/standalone/src/core/runtime/arc_loader.cpp", "GetProcAddress(GetModuleHandleW(L\"ntdll.dll\"), \"NtCreateThreadEx\"));"): "approved ARC loader direct thread canary probe",
    ("src/standalone/src/core/runtime/arc_loader.cpp", "HANDLE wd_thread = CreateThread(nullptr, 0, wd_proc, &wd_ctx, 0, &wd_tid);"): "approved ARC loader bounded watchdog",
    ("src/standalone/src/core/runtime/arc_loader.cpp", "HANDLE inv_thread = CreateThread(nullptr, 0, inv_thread_proc, inv_ctx, 0, &inv_tid);"): "approved ARC loader invocation thread",
    ("src/standalone/src/core/runtime/run_target.cpp", "HANDLE create_thread = CreateThread("): "approved target launch worker with explicit timeout",
    ("src/standalone/src/core/runtime/run_target.cpp", "out.error = format_error(\"CreateThread(CreateProcess worker)\", create_thread_gle);"): "approved target launch worker diagnostic token",
    ("src/standalone/src/core/runtime/standalone_anti_dump.hpp", "HANDLE thread = CreateThread(nullptr, 0, dacl_seal_worker_proc, state, 0, nullptr);"): "approved standalone anti-dump DACL seal worker",
    ("src/standalone/src/core/runtime/standalone_driver.cpp", "uintptr_t raw = _beginthreadex(nullptr,"): "approved lower remote-call executor thread",
    ("src/standalone/src/core/runtime/standalone_driver.cpp", "uintptr_t raw2 = _beginthreadex(nullptr,"): "approved lower remote-call secondary executor thread",
    ("src/standalone/src/core/runtime/standalone_license.cpp", "HANDLE h = CreateThread(nullptr, 0, &canary_proc, (LPVOID)&done, 0, &tid);"): "approved license transport canary probe",
    ("src/standalone/src/core/runtime/standalone_license.cpp", "HANDLE wd_send_thread = CreateThread(nullptr, 0, [](LPVOID arg) -> DWORD {"): "approved license WinHTTP send watchdog",
    ("src/standalone/src/core/runtime/standalone_license.cpp", "HANDLE wd_recv_thread = CreateThread(nullptr, 0, [](LPVOID arg) -> DWORD {"): "approved license WinHTTP receive watchdog",
    ("src/standalone/src/core/runtime/standalone_license.cpp", "std::thread([at_watch_done,"): "approved activation watchdog detach path",
    ("src/standalone/src/core/runtime/standalone_license.cpp", "}).detach();"): "approved activation watchdog detach path",
    ("src/standalone/src/core/runtime/standalone_license_transport.cpp", "return CreateThread(nullptr, 0, [](LPVOID arg) -> DWORD {"): "approved license transport bounded watchdog",
    ("src/standalone/src/core/scanner/memory_scanner.cpp", "std::vector<std::thread> workers;"): "approved existing memory scanner worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/scanner/memory_scanner.cpp", "std::vector<std::thread> ptr_workers;"): "approved existing pointer scanner worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/scanner/memory_scanner.cpp", "std::vector<std::thread> dfs_workers;"): "approved existing DFS scanner worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/testlab/network_hook_sidecar.cpp", "pair->accept_thread = CreateThread(nullptr, 0, accept_thread_proc, thread_state, 0, nullptr);"): "approved Test Lab sidecar accept thread",
    ("src/standalone/src/core/tools/driver_tools_standalone.cpp", "\"NtCreateThreadEx\", \"NtDeviceIoControlFile\", \"NtQuerySystemInformation\","): "approved driver tool detection signature token",
    ("src/standalone/src/helpers/diag_log.hpp", "uintptr_t th = _beginthreadex(nullptr, 0, async_log_thread_main, nullptr, 0, &tid);"): "approved async diagnostic logger thread",
    ("src/standalone/src/core/infra/taskflow_evaluation.hpp", "inline constexpr const char* kTaskflowRejectionReason = \"Taskflow v4.1.0 requires C++20; AiDAStandalone targets C++17; Taskflow owns internal std::thread workers that bypass AiDA win_thread wrappers; no C++20 migration is permitted for AiDAStandalone\";"): "approved Taskflow evaluation evidence string literal",
    ("src/standalone/src/core/infra/taskflow_evaluation.hpp", "inline constexpr const char* kTaskflowSourceEvidenceSpawn = \"executor.hpp:1295 '_workers[id]._thread = std::thread([&, id, wif] () {' -- Executor::_spawn creates std::thread directly\";"): "approved Taskflow evaluation evidence string literal",
    ("src/standalone/src/core/infra/taskflow_evaluation.hpp", "inline constexpr const char* kTaskflowSourceEvidenceWorkerThread = \"worker.hpp:97 'std::thread _thread;' -- Worker class stores std::thread as value member\";"): "approved Taskflow evaluation evidence string literal",
    ("src/standalone/src/core/infra/taskflow_evaluation.hpp", "inline constexpr const char* kAidaWinThreadEvidence = \"win_thread.hpp:237 CreateThread :274 NtCreateThreadEx :341 _beginthreadex with SEH guards TLS init stack reserve control diagnostic logging -- incompatible with Taskflow std::thread value members\";"): "approved Taskflow evaluation evidence string literal",
    ("src/standalone/src/core/infra/taskflow_evaluation.hpp", "static_assert(kTaskflowOwnsWorkerThreads == true, \"Taskflow Executor::_spawn creates std::thread directly (executor.hpp:1295)\");"): "approved Taskflow evaluation static_assert evidence string",
    ("src/standalone/src/core/infra/taskflow_evaluation.hpp", "static_assert(kTaskflowCanUseAidaWinThreadWrappers == false, \"Taskflow Worker stores std::thread value member (worker.hpp:97); no hook to inject win_thread wrappers\");"): "approved Taskflow evaluation static_assert evidence string",
}

SENDMESSAGE_ALLOWLIST = {
    ("src/standalone/src/main.cpp", "SendMessageW(hwnd, WM_SETICON, ICON_BIG,   (LPARAM)hIcon);"): "approved same-thread startup icon assignment",
    ("src/standalone/src/main.cpp", "SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);"): "approved same-thread startup icon assignment",
}

THREAD_ALLOWLIST_COUNTS = {
    ("src/standalone/src/core/mcp/mcp_standalone.cpp", "worker.detach();", "detached std::thread"): 2,
    ("src/standalone/src/core/infra/taskflow_evaluation.hpp", "inline constexpr const char* kTaskflowSourceEvidenceSpawn = \"executor.hpp:1295 '_workers[id]._thread = std::thread([&, id, wif] () {' -- Executor::_spawn creates std::thread directly\";", "std::thread"): 2,
    ("src/standalone/src/core/infra/taskflow_evaluation.hpp", "inline constexpr const char* kTaskflowSourceEvidenceWorkerThread = \"worker.hpp:97 'std::thread _thread;' -- Worker class stores std::thread as value member\";", "std::thread"): 2,
}

THREAD_VECTOR_START_ALLOWLIST = {
    ("src/standalone/src/core/network/burp/intruder_engine.cpp", "ws.emplace_back([job]() { worker_pooled_h1(job); });"): "approved existing intruder batch raw std::thread worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/burp/offensive/business_logic_engine.cpp", "threads.emplace_back([&, i]() {"): "approved existing business logic raw std::thread worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/burp/param_miner.cpp", "for (size_t i = 0; i < concurrency; ++i) threads.emplace_back(worker);"): "approved existing param miner raw std::thread worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/network/flow_store.cpp", "workers.emplace_back([&, i]() {"): "approved existing flow store raw std::thread worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/scanner/memory_scanner.cpp", "workers.emplace_back([&]() {"): "approved existing memory scanner raw std::thread worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/scanner/memory_scanner.cpp", "ptr_workers.emplace_back(scan_pointer_worker, w);"): "approved existing pointer scanner raw std::thread worker group pending Phase 1 runtime inventory",
    ("src/standalone/src/core/scanner/memory_scanner.cpp", "dfs_workers.emplace_back(dfs_worker);"): "approved existing DFS scanner raw std::thread worker group pending Phase 1 runtime inventory",
}

THREAD_PATTERNS = [
    (re.compile(r"\bstd::thread\b(?!\s*::hardware_concurrency)"), "std::thread"),
    (re.compile(r"\.\s*detach\s*\("), "detached std::thread"),
    (re.compile(r"\bCreateThread\s*\("), "CreateThread"),
    (re.compile(r"\b_beginthreadex\s*\("), "_beginthreadex"),
    (re.compile(r"\bNtCreateThreadEx\b"), "NtCreateThreadEx"),
    (re.compile(r"\bstd::async\s*\("), "std::async"),
    (re.compile(r"\bQueueUserWorkItem\s*\("), "QueueUserWorkItem"),
]

THREAD_VECTOR_DECL_PATTERN = re.compile(r"\bstd::vector\s*<\s*std::thread\s*>\s+([A-Za-z_][A-Za-z0-9_]*)")

DXGI_PATTERNS = [
    (re.compile(r"\bdxgi1_3(?:\.h)?\b", re.IGNORECASE), "dxgi1_3.h", "DXGI 1.3 waitable/flip latency path is forbidden"),
    (re.compile(r"\bDXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT\b"), "DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT", "DXGI frame-latency waitable swapchain flag is forbidden"),
    (re.compile(r"\bIDXGISwapChain2\b"), "IDXGISwapChain2", "DXGI 1.3 waitable swapchain interface is forbidden"),
    (re.compile(r"\bSetMaximumFrameLatency\b"), "SetMaximumFrameLatency", "waitable swapchain latency control is forbidden"),
    (re.compile(r"\bGetFrameLatencyWaitableObject\b"), "GetFrameLatencyWaitableObject", "waitable swapchain latency object is forbidden"),
    (re.compile(r"\bDXGI_SWAP_EFFECT_FLIP_DISCARD\b"), "DXGI_SWAP_EFFECT_FLIP_DISCARD", "standalone renderer must stay on classic discard swap effect"),
    (re.compile(r"\bDXGI_SWAP_EFFECT_FLIP_SEQUENTIAL\b"), "DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL", "standalone renderer must stay on classic discard swap effect"),
    (re.compile(r"\bdxgi_latency_interactive\b", re.IGNORECASE), "dxgi_latency_interactive", "removed DXGI latency diagnostics are forbidden"),
    (re.compile(r"\b(?:frame|swapchain)[_\-\s]*latency[_\-\s]*waitable\b", re.IGNORECASE), "frame latency waitable", "waitable frame latency object naming is forbidden"),
    (re.compile(r"\bwaitable[_\-\s]*(?:frame[_\-\s]*latency|swapchain|pre[_\-\s]*render)\b", re.IGNORECASE), "waitable swapchain", "waitable swapchain pre-render path is forbidden"),
    (re.compile(r"\b(?:pre[_\-\s]*render)[_\-\s]*waitable\b", re.IGNORECASE), "pre-render waitable", "waitable swapchain pre-render path is forbidden"),
]

DIRECT_EMPTY_QUEUE_FORBID = re.compile(
    r"GetQueueStatus\s*\(\s*QS_ALLINPUT\s*\)[^;\n]*(?:==|<=)\s*0[^;\n]*(?:break|return|continue)",
    re.IGNORECASE,
)


def relpath(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def normalize(line: str) -> str:
    return " ".join(line.strip().split())


def iter_source_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(ROOT).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        yield path


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def find_const_initializer(lines: list[str], name: str) -> tuple[int, str] | None:
    pattern = re.compile(rf"\b{name}\b\s*=\s*(.*?);")
    for index, line in enumerate(lines, 1):
        match = pattern.search(line)
        if match:
            return index, match.group(1).strip()
    return None


def token_set(expr: str) -> set[str]:
    return set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr))


def add_failure(failures: list[Failure], path: Path, line: int, token: str, reason: str, text: str) -> None:
    failures.append(Failure(relpath(path), line, token, reason, text.strip()))


def require_const_token(failures: list[Failure], lines: list[str], name: str, token: str, present: bool) -> None:
    found = find_const_initializer(lines, name)
    if not found:
        add_failure(failures, MAIN_CPP, 1, name, f"{name} declaration is missing", "")
        return
    line, expr = found
    has_token = token in token_set(expr)
    if has_token != present:
        expectation = "include" if present else "exclude"
        add_failure(failures, MAIN_CPP, line, token, f"{name} must {expectation} {token}", expr)


def check_message_pump(failures: list[Failure]) -> None:
    lines = read_lines(MAIN_CPP)
    text = "\n".join(lines)
    require_const_token(failures, lines, "kAidaQueuedPeekFlags", "PM_QS_SENDMESSAGE", True)
    require_const_token(failures, lines, "kAidaQueuedNoSendPeekFlags", "PM_QS_SENDMESSAGE", False)
    send_only = find_const_initializer(lines, "kAidaSendOnlyPeekFlags")
    if not send_only:
        add_failure(failures, MAIN_CPP, 1, "kAidaSendOnlyPeekFlags", "kAidaSendOnlyPeekFlags declaration is missing", "")
    else:
        line, expr = send_only
        tokens = token_set(expr)
        if tokens != {"PM_REMOVE", "PM_QS_SENDMESSAGE"}:
            add_failure(failures, MAIN_CPP, line, "kAidaSendOnlyPeekFlags", "kAidaSendOnlyPeekFlags must be exactly PM_REMOVE | PM_QS_SENDMESSAGE", expr)
    for index, line in enumerate(lines, 1):
        if DIRECT_EMPTY_QUEUE_FORBID.search(line):
            add_failure(failures, MAIN_CPP, index, "GetQueueStatus(QS_ALLINPUT)", "empty queue path must not break before a nonblocking PeekMessage probe", line)
    required_shapes = [
        (
            "budgeted pump queued peek",
            r"const\s+UINT\s+peek_flags\s*=\s*non_send_pending\s*\?\s*kAidaQueuedNoSendPeekFlags\s*:\s*kAidaQueuedPeekFlags\s*;\s*BOOL\s+has_message\s*=\s*::PeekMessage\s*\(\s*&msg\s*,\s*nullptr\s*,\s*0U\s*,\s*0U\s*,\s*peek_flags\s*\)",
        ),
        (
            "budgeted pump send-only drain",
            r"PeekMessage\s*\(\s*&sent_probe\s*,\s*nullptr\s*,\s*0U\s*,\s*0U\s*,\s*kAidaSendOnlyPeekFlags\s*\)",
        ),
        (
            "render loop empty queue probe marker",
            r"if\s*\(\s*queue_current\s*==\s*0\s*\)\s*\{\s*aida_tracer::set_peek_state\s*\(\s*queue_status_before\s*,\s*0\s*\)\s*;\s*aida_tracer::set_peek_call_shape\s*\(\s*kAidaQueuedPeekFlags\s*,\s*nullptr\s*\)\s*;\s*\}",
        ),
        (
            "render loop queued peek",
            r"const\s+UINT\s+peek_remove_flags\s*=\s*non_send_pending\s*\?\s*kAidaQueuedNoSendPeekFlags\s*:\s*kAidaQueuedPeekFlags\s*;\s*.*?PeekMessage\s*\(\s*&msg\s*,\s*peek_filter\s*,\s*0U\s*,\s*0U\s*,\s*peek_remove_flags\s*\)",
        ),
        (
            "render loop send-only drain",
            r"PeekMessage\s*\(\s*&sent_probe\s*,\s*nullptr\s*,\s*0U\s*,\s*0U\s*,\s*kAidaSendOnlyPeekFlags\s*\)",
        ),
    ]
    for token, pattern in required_shapes:
        if not re.search(pattern, text, re.DOTALL):
            add_failure(failures, MAIN_CPP, 1, token, "message-pump invariant shape is missing", token)
    if re.search(r"if\s*\(\s*queue_current\s*==\s*0\s*\)\s*\{[^{}]*(?:break|return|continue)\s*;", text, re.DOTALL):
        add_failure(failures, MAIN_CPP, 1, "queue_current == 0", "empty queue branch must fall through to PeekMessage instead of breaking", "queue_current == 0")


def collect_source_lines() -> list[tuple[Path, str, list[str]]]:
    sources = []
    for path in iter_source_files(STANDALONE_ROOT):
        text = path.read_text(encoding="utf-8", errors="replace")
        sources.append((path, text, text.splitlines()))
    return sources


def check_allowed_lines(
    failures: list[Failure],
    sources: list[tuple[Path, str, list[str]]],
    allowlist: dict[tuple[str, str], str],
    patterns,
    reason: str,
) -> None:
    normalized_allowlist = {(path, normalize(line)): why for (path, line), why in allowlist.items()}
    allowed_counts = Counter()
    for path, line in normalized_allowlist:
        for pattern, token in patterns:
            if pattern.search(line):
                allowed_counts[(path, line, token)] += 1
    for (path, line, token), count in THREAD_ALLOWLIST_COUNTS.items():
        allowed_counts[(path, normalize(line), token)] = count
    seen_counts = Counter()
    for path, text, lines in sources:
        rel = relpath(path)
        for pattern, token in patterns:
            for match in pattern.finditer(text):
                index = text.count("\n", 0, match.start()) + 1
                line = lines[index - 1] if 0 <= index - 1 < len(lines) else ""
                normalized = normalize(line)
                key = (rel, normalized, token)
                if (rel, normalized) not in normalized_allowlist or key not in allowed_counts:
                    add_failure(failures, path, index, token, reason, line)
                    continue
                if seen_counts[key] >= allowed_counts[key]:
                    add_failure(failures, path, index, token, f"{reason}; approved occurrence count exceeded", line)
                    continue
                seen_counts[key] += 1


def check_thread_vector_starts(failures: list[Failure], sources: list[tuple[Path, str, list[str]]]) -> None:
    normalized_allowlist = {(path, normalize(line)): why for (path, line), why in THREAD_VECTOR_START_ALLOWLIST.items()}
    for path, text, lines in sources:
        rel = relpath(path)
        thread_vector_names = sorted(set(THREAD_VECTOR_DECL_PATTERN.findall(text)))
        if not thread_vector_names:
            continue
        pattern = re.compile(
            r"\b(?:" + "|".join(re.escape(name) for name in thread_vector_names) + r")\s*\.\s*(?:emplace_back|push_back)\s*\("
        )
        for match in pattern.finditer(text):
            index = text.count("\n", 0, match.start()) + 1
            line = lines[index - 1] if 0 <= index - 1 < len(lines) else ""
            normalized = normalize(line)
            if (rel, normalized) not in normalized_allowlist:
                add_failure(
                    failures,
                    path,
                    index,
                    "std::thread vector start",
                    "unapproved raw std::thread vector start; use an AiDA-owned wrapper or add a narrow audited exception",
                    line,
                )


def check_dxgi(failures: list[Failure], sources: list[tuple[Path, str, list[str]]]) -> None:
    for path, _text, lines in sources:
        for index, line in enumerate(lines, 1):
            for pattern, token, reason in DXGI_PATTERNS:
                match = pattern.search(line)
                if match:
                    add_failure(failures, path, index, token, reason, line)


def check_wait_helper(failures: list[Failure]) -> None:
    lines = read_lines(MAIN_CPP)
    text = "\n".join(lines)
    match = re.search(
        r"static\s+frame_wait_result_t\s+wait_for_frame_latency_or_input\s*\(\s*DWORD\s+requested_ms\s*\)\s*\{(?P<body>.*?)^\}",
        text,
        re.DOTALL | re.MULTILINE,
    )
    if not match:
        add_failure(failures, MAIN_CPP, 1, "wait_for_frame_latency_or_input", "classic zero-handle message wait helper is missing", "")
        return
    body = match.group("body")
    if "MsgWaitForMultipleObjectsEx(0, nullptr, requested_ms, QS_ALLINPUT, MWMO_INPUTAVAILABLE)" not in body:
        add_failure(failures, MAIN_CPP, 1, "MsgWaitForMultipleObjectsEx", "frame wait helper must use zero handles and QS_ALLINPUT only", "wait_for_frame_latency_or_input")


def print_failures(failures: list[Failure]) -> None:
    for failure in failures:
        print(
            f"{failure.path}:{failure.line}: token={failure.token}: {failure.reason}: {failure.text}",
            file=sys.stderr,
        )


def main() -> int:
    failures: list[Failure] = []
    if not STANDALONE_ROOT.exists():
        add_failure(failures, STANDALONE_ROOT, 1, "src/standalone/src", "standalone source root is missing", "")
    if not MAIN_CPP.exists():
        add_failure(failures, MAIN_CPP, 1, "main.cpp", "standalone main.cpp is missing", "")
    if failures:
        print_failures(failures)
        return 1
    sources = collect_source_lines()
    check_message_pump(failures)
    check_allowed_lines(
        failures,
        sources,
        SENDMESSAGE_ALLOWLIST,
        [(re.compile(r"\bSendMessageW\s*\("), "SendMessageW")],
        "cross-thread SendMessageW is forbidden; only same-thread startup WM_SETICON calls are approved",
    )
    check_allowed_lines(
        failures,
        sources,
        THREAD_ALLOWLIST,
        THREAD_PATTERNS,
        "unapproved standalone thread start or token; use an AiDA-owned wrapper or add a narrow audited exception",
    )
    check_thread_vector_starts(failures, sources)
    check_dxgi(failures, sources)
    check_wait_helper(failures)
    if failures:
        print_failures(failures)
        return 1
    print("AiDA Phase 0 static invariants verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
