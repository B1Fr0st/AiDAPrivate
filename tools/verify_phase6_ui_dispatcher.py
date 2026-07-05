from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STANDALONE_ROOT = ROOT / "src" / "standalone" / "src"
MAIN_CPP = STANDALONE_ROOT / "main.cpp"
HELPERS_CPP = STANDALONE_ROOT / "helpers" / "helpers.cpp"
TESTLAB_UI_CPP = STANDALONE_ROOT / "core" / "testlab" / "test_all_ui.cpp"
CMAKE = ROOT / "CMakeLists.txt"

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

PHASE_GUARDS = [
    "tools/verify_phase0_invariants.py",
    "tools/verify_thread_runtime_contract.py",
    "tools/verify_phase2_capacity.py",
    "tools/verify_phase3_admission.py",
    "tools/verify_phase4_direct_call_admission.py",
    "tools/verify_phase4_tool_admission.py",
    "tools/verify_phase5_lease_registry.py",
]

PHASE_GUARD_CMAKE_TOKENS = [
    "AiDAPhase0StaticGuards",
    "AiDAThreadRuntimeContractGuards",
    "AiDACapacityDiagnosticsGuards",
    "AiDAIngressAdmissionGuards",
    "AiDADirectCallAdmissionGuards",
    "AiDAToolAdmissionGuards",
    "AiDALeaseRegistryGuards",
]

FORBIDDEN_SCRIPT_EXECUTION = [
    re.compile(r"\bsubprocess\s*\."),
    re.compile(r"\bos\s*\.\s*system\s*\("),
    re.compile(r"\bos\s*\.\s*popen\s*\("),
    re.compile(r"\bPopen\s*\("),
    re.compile(r"\bStart-Process\b", re.IGNORECASE),
]

FORBIDDEN_DXGI = [
    (re.compile(r"\bdxgi1_3(?:\.h)?\b", re.IGNORECASE), "dxgi1_3.h", "DXGI 1.3 waitable/flip latency path is forbidden"),
    (re.compile(r"\bDXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT\b"), "DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT", "DXGI waitable swapchain flag is forbidden"),
    (re.compile(r"\bIDXGISwapChain2\b"), "IDXGISwapChain2", "DXGI 1.3 waitable swapchain interface is forbidden"),
    (re.compile(r"\bSetMaximumFrameLatency\b"), "SetMaximumFrameLatency", "waitable swapchain latency control is forbidden"),
    (re.compile(r"\bGetFrameLatencyWaitableObject\b"), "GetFrameLatencyWaitableObject", "waitable swapchain latency object is forbidden"),
    (re.compile(r"\bDXGI_SWAP_EFFECT_FLIP_DISCARD\b"), "DXGI_SWAP_EFFECT_FLIP_DISCARD", "flip-model swap effect is forbidden"),
    (re.compile(r"\bDXGI_SWAP_EFFECT_FLIP_SEQUENTIAL\b"), "DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL", "flip-model swap effect is forbidden"),
]

UI_DISPATCHER_POST_TOKENS = [
    "ui_dispatcher_post",
    "post_ui_task",
    "post_to_ui_thread",
    "enqueue_ui_task",
    "aida::ui_dispatcher::enqueue",
    "aida::ui_thread::post",
    "bool post(",
    "enqueue_result_t enqueue",
]

UI_DISPATCHER_DRAIN_TOKENS = [
    "ui_dispatcher_drain",
    "drain_ui_dispatcher",
    "run_ui_dispatcher_tasks",
    "aida::ui_dispatcher::drain",
    "std::uint32_t drain",
    "drain_result_t drain",
]

UI_DISPATCHER_WAKE_TOKENS = [
    "ui_dispatcher_wake",
    "wake_ui_dispatcher",
    "request_wake",
    "post_wake_locked",
    "ui_dispatch_post_wake_locked",
    "bool wake(",
]

UI_AFFINITY_TOKENS = [
    "require_ui_thread",
    "assert_ui_thread",
    "ui_affinity_guard",
    "check_ui_thread",
    "is_ui_thread",
    "require_owner",
    "record_ui_owner",
    "capture_owner_tid",
    "UI-AFFINITY-VIOLATION",
]


@dataclass(frozen=True)
class Failure:
    path: str
    line: int
    token: str
    reason: str
    text: str


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


TEXT = {
    "main": read(MAIN_CPP),
    "helpers": read(HELPERS_CPP),
    "testlab_ui": read(TESTLAB_UI_CPP),
    "cmake": read(CMAKE),
}

FAILURES: list[Failure] = []


def add_failure(path: Path, line: int, token: str, reason: str, text: str = "") -> None:
    FAILURES.append(Failure(rel(path), line, token, reason, " ".join(text.strip().split())))


def line_of(text: str, token: str) -> int:
    index = text.find(token)
    if index < 0:
        return 1
    return text.count("\n", 0, index) + 1


def line_of_pos(text: str, pos: int) -> int:
    return text.count("\n", 0, max(0, pos)) + 1


def fail_key(key: str, token: str, reason: str) -> None:
    path = {"main": MAIN_CPP, "helpers": HELPERS_CPP, "testlab_ui": TESTLAB_UI_CPP, "cmake": CMAKE}[key]
    add_failure(path, line_of(TEXT[key], token), token, reason)


def require_key(key: str, token: str, reason: str) -> None:
    if token not in TEXT[key]:
        fail_key(key, token, reason)


def require_regex_key(key: str, pattern: str, token: str, reason: str, flags: int = re.S) -> None:
    if not re.search(pattern, TEXT[key], flags):
        fail_key(key, token, reason)


def has_any(text: str, tokens: list[str]) -> bool:
    return any(token in text for token in tokens)


def require_any_text(path: Path, text: str, tokens: list[str], token_name: str, reason: str) -> None:
    if not has_any(text, tokens):
        add_failure(path, 1, token_name, reason)


def iter_source_files(root: Path):
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(ROOT).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        yield path


def all_standalone_sources() -> list[tuple[Path, str, list[str]]]:
    result = []
    for path in iter_source_files(STANDALONE_ROOT):
        text = read(path)
        result.append((path, text, text.splitlines()))
    return result


SOURCES = all_standalone_sources()


def balanced_block(text: str, token: str) -> tuple[int, str]:
    start = text.find(token)
    if start < 0:
        return -1, ""
    brace = text.find("{", start)
    if brace < 0:
        return start, ""
    depth = 0
    for index in range(brace, len(text)):
        ch = text[index]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return start, text[start:index + 1]
    return start, ""


def first_balanced_block(text: str, tokens: list[str]) -> tuple[int, str, str]:
    for token in tokens:
        start, body = balanced_block(text, token)
        if start >= 0 and body:
            return start, body, token
    return -1, "", tokens[0]


def regex_balanced_block(text: str, pattern: str) -> tuple[int, str, str]:
    match = re.search(pattern, text, re.S)
    if not match:
        return -1, "", pattern
    token = match.group(0)
    brace = text.find("{", match.start())
    if brace < 0:
        return match.start(), "", token
    depth = 0
    for index in range(brace, len(text)):
        ch = text[index]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return match.start(), text[match.start():index + 1], token
    return match.start(), "", token


def function_block(text: str, name: str) -> tuple[int, str, str]:
    pattern = rf"(?:[\w:<>,~*&\s]+\s+)?{re.escape(name)}\s*\([^;{{)]*(?:\)[^;{{]*)?\)\s*\{{"
    return regex_balanced_block(text, pattern)


def function_block_regex(text: str, pattern: str) -> tuple[int, str, str]:
    return regex_balanced_block(text, pattern + r"\s*\{")


def check_required_files() -> None:
    for path in [MAIN_CPP, HELPERS_CPP, TESTLAB_UI_CPP, CMAKE]:
        if not path.exists():
            add_failure(path, 1, path.name, "required Phase 6 source file is missing")


def check_prior_guard_scripts_direct_source_only() -> None:
    for rel_script in PHASE_GUARDS:
        path = ROOT / rel_script
        text = read(path)
        if not path.exists():
            add_failure(path, 1, rel_script, "Phase 0-5 guard script is missing")
            continue
        if "sys.exit(" not in text and "raise SystemExit" not in text and "sys.exit(1)" not in text:
            add_failure(path, 1, "sys.exit", "guard script must return a process status directly")
        for pattern in FORBIDDEN_SCRIPT_EXECUTION:
            for match in pattern.finditer(text):
                add_failure(path, line_of_pos(text, match.start()), match.group(0), "guard script must remain source-only and must not invoke external commands", text.splitlines()[line_of_pos(text, match.start()) - 1])
    for token in PHASE_GUARD_CMAKE_TOKENS:
        require_key("cmake", token, "Phase 0-5 guard target must remain wired in CMake")


def check_phase0_guard_still_covers_invariants() -> None:
    path = ROOT / "tools" / "verify_phase0_invariants.py"
    text = read(path)
    for token in [
        "kAidaQueuedPeekFlags",
        "PM_QS_SENDMESSAGE",
        "kAidaQueuedNoSendPeekFlags",
        "kAidaSendOnlyPeekFlags",
        "SendMessageW",
        "DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT",
        "DXGI_SWAP_EFFECT_FLIP_DISCARD",
        "DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL",
        "QueueUserWorkItem",
    ]:
        if token not in text:
            add_failure(path, 1, token, "Phase 0 guard no longer protects required message-pump/thread/DXGI invariant")


def check_phase6_cmake_wiring() -> None:
    for token in [
        "AIDA_PHASE6_UI_DISPATCHER_GUARD_SCRIPT",
        "AiDAUiDispatcherGuards",
        "verify_phase6_ui_dispatcher.py",
    ]:
        require_key("cmake", token, "Phase 6 static guard must be wired into CMake")
    require_regex_key(
        "cmake",
        r"add_dependencies\s*\(\s*AiDAUiDispatcherGuards[^\)]*AiDALeaseRegistryGuards",
        "add_dependencies(AiDAUiDispatcherGuards ... AiDALeaseRegistryGuards)",
        "Phase 6 guard must run after the Phase 5 lease registry guard",
    )
    require_regex_key(
        "cmake",
        r"add_dependencies\s*\(\s*AiDAStandalone[^\)]*AiDAUiDispatcherGuards",
        "add_dependencies(AiDAStandalone ... AiDAUiDispatcherGuards)",
        "AiDAStandalone must depend on the Phase 6 UI dispatcher guard",
    )


def check_no_dxgi_waitable_or_flip_latency_path() -> None:
    for path, _text, lines in SOURCES:
        for index, line in enumerate(lines, 1):
            for pattern, token, reason in FORBIDDEN_DXGI:
                if pattern.search(line):
                    add_failure(path, index, token, reason, line)


def dispatcher_sources() -> list[tuple[Path, str]]:
    result = []
    marker = re.compile(r"\b(?:ui_dispatcher|UiDispatcher|UI_DISPATCHER|g_ui_owner_tid|kAidaUiDispatcher)\b")
    for path, text, _lines in SOURCES:
        if marker.search(text):
            result.append((path, text))
    return result


def dispatcher_implementation_sources() -> list[tuple[Path, str]]:
    result = []
    for path, text in dispatcher_sources():
        if "PostMessageW" in text and "kAidaUiDispatcherWakeMessage" in text and ("std::deque" in text or "task_t" in text):
            result.append((path, text))
    return result


def find_dispatcher_implementation_blocks() -> list[tuple[Path, int, str, str]]:
    blocks: list[tuple[Path, int, str, str]] = []
    patterns = [
        r"namespace\s+aida::ui_dispatcher\b",
        r"namespace\s+aida::ui_thread\b",
        r"\b(?:class|struct)\s+(?:ui_dispatcher_t|ui_dispatcher|UiDispatcher)\b",
    ]
    for path, text in dispatcher_implementation_sources():
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                start, body = balanced_block(text, match.group(0))
                if not body:
                    continue
                if "PostMessageW" in body and "kAidaUiDispatcherWakeMessage" in body and ("std::deque" in body or "task_t" in body):
                    blocks.append((path, start, match.group(0), body))
    return blocks


def check_dispatcher_core_contract() -> None:
    dispatchers = dispatcher_implementation_sources()
    if not dispatchers:
        add_failure(MAIN_CPP, 1, "ui_dispatcher", "Phase 6 requires one central wake-only UI dispatcher, but no dispatcher source marker was found")
        return
    blocks = find_dispatcher_implementation_blocks()
    if len(blocks) != 1:
        if not blocks:
            add_failure(dispatchers[0][0], 1, "ui_dispatcher implementation", "exactly one central UI dispatcher implementation is required")
        else:
            for path, start, token, _body in blocks:
                add_failure(path, line_of_pos(read(path), start), token, "exactly one central UI dispatcher implementation is required")
    combined = "\n".join(text for _path, text in dispatchers)
    for token, reason in [
        ("g_ui_owner_tid", "dispatcher must capture and expose the UI owner thread id"),
        ("kAidaUiDispatcherWakeMessage", "dispatcher must use a dedicated wake-only message constant"),
        ("wake_pending", "dispatcher must coalesce Win32 wake messages"),
        ("queue_depth", "dispatcher must log queue depth"),
        ("priority", "dispatcher tasks must carry priority"),
        ("cancel", "dispatcher tasks must carry cancellation state"),
        ("budget_ms", "dispatcher must enforce a drain time budget"),
        ("task_budget", "dispatcher must enforce a drain task budget"),
    ]:
        if token not in combined:
            add_failure(dispatchers[0][0], 1, token, reason)
    require_any_text(dispatchers[0][0], combined, UI_DISPATCHER_POST_TOKENS, "ui dispatcher post API", "worker-to-UI handoffs must use the central dispatcher post API")
    require_any_text(dispatchers[0][0], combined, UI_DISPATCHER_DRAIN_TOKENS, "ui dispatcher drain API", "render loop must drain the central dispatcher at known UI points")
    require_any_text(dispatchers[0][0], combined, UI_DISPATCHER_WAKE_TOKENS, "ui dispatcher wake API", "dispatcher must have one wake-only API")
    require_any_text(dispatchers[0][0], combined, UI_AFFINITY_TOKENS, "UI affinity guard", "dispatcher must provide or use UI-affinity checks")
    wake_candidates = [
        function_block_regex(combined, r"(?:static\s+)?bool\s+ui_dispatch_post_wake_locked\s*\([^)]*\)"),
        function_block_regex(combined, r"(?:static\s+)?bool\s+post_wake_locked\s*\([^)]*\)"),
        function_block_regex(combined, r"(?:static\s+)?void\s+request_wake\s*\([^)]*\)"),
        function_block_regex(combined, r"bool\s+wake\s*\([^)]*\)"),
    ]
    start, wake_body, wake_token = next(((s, b, t) for s, b, t in wake_candidates if s >= 0 and b), (-1, "", "dispatcher wake"))
    if not wake_body:
        add_failure(dispatchers[0][0], 1, wake_token, "dispatcher wake function body is missing")
    else:
        if "SendMessage" in wake_body:
            add_failure(dispatchers[0][0], 1, "SendMessage", "dispatcher wake must never use SendMessage")
        if "PostMessageW" not in wake_body and "PostThreadMessageW" not in wake_body:
            add_failure(dispatchers[0][0], 1, "PostMessageW/PostThreadMessageW", "dispatcher wake must use a posted wake signal")
        if "exchange" not in wake_body and "compare_exchange" not in wake_body:
            add_failure(dispatchers[0][0], 1, "wake_pending.exchange", "dispatcher wake must atomically coalesce wake messages")
        if not re.search(r"Post(?:Thread)?MessageW\s*\([^;]+kAidaUiDispatcherWakeMessage\s*,\s*0\s*,\s*0\s*\)", wake_body, re.S):
            add_failure(dispatchers[0][0], 1, "kAidaUiDispatcherWakeMessage", "dispatcher wake message must carry zero wParam and zero lParam")
    drain_candidates = [
        function_block_regex(combined, r"drain_result_t\s+drain\s*\([^)]*\)"),
        function_block_regex(combined, r"std::uint32_t\s+drain\s*\([^)]*\)"),
    ]
    start, drain_body, drain_token = next(((s, b, t) for s, b, t in drain_candidates if s >= 0 and b), (-1, "", "ui_dispatcher_drain"))
    if not drain_body:
        add_failure(dispatchers[0][0], 1, drain_token, "dispatcher drain function body is missing")
    else:
        drain_requirements = [
            (["wake_pending"], "wake_pending", "dispatcher drain must reset wake coalescing"),
            (["queue_depth", "depth_after_pop", "pending_count", "g_ui_dispatch_last_depth"], "queue_depth", "dispatcher drain must maintain queue-depth evidence"),
            (["budget_ms"], "budget_ms", "dispatcher drain must enforce a time budget"),
            (["task_budget", "max_tasks"], "task_budget", "dispatcher drain must enforce a task budget"),
            (["priority", "priority_rank", "best_rank"], "priority", "dispatcher drain must enforce dispatcher task priority"),
            (["cancel", "cancelled", "cancellation_requested"], "cancel", "dispatcher drain must enforce task cancellation"),
        ]
        for tokens, token_name, reason in drain_requirements:
            if not has_any(drain_body, tokens):
                add_failure(dispatchers[0][0], line_of(read(dispatchers[0][0]), "std::uint32_t drain"), token_name, reason)
        if "store(false" not in drain_body and ".exchange(false" not in drain_body:
            add_failure(dispatchers[0][0], 1, "wake_pending.store(false)", "dispatcher drain must clear the wake-pending flag after taking queued work")


def check_ui_owner_tid_contract() -> None:
    combined = "\n".join(text for _path, text, _lines in SOURCES)
    definitions = list(re.finditer(r"std::atomic\s*<\s*(?:DWORD|unsigned\s+long)\s*>\s+g_ui_owner_tid\s*\{", combined))
    if not definitions:
        add_failure(MAIN_CPP, 1, "g_ui_owner_tid", "Phase 6 requires a process-wide atomic UI owner thread id")
    elif len(definitions) != 1:
        add_failure(MAIN_CPP, 1, "g_ui_owner_tid", "Phase 6 requires exactly one process-wide UI owner thread id definition")
    owner_capture_patterns = [
        "g_ui_owner_tid.store",
        "g_ui_owner_tid.exchange",
        "g_ui_owner_tid.compare_exchange",
        "capture_owner_tid(::GetCurrentThreadId()",
        "capture_owner_tid(GetCurrentThreadId()",
    ]
    if not has_any(combined, owner_capture_patterns) or "GetCurrentThreadId()" not in combined:
        add_failure(MAIN_CPP, 1, "g_ui_owner_tid.store(GetCurrentThreadId())", "UI owner TID must be captured from the UI thread")
    if "g_ui_owner_tid.load" not in combined:
        add_failure(MAIN_CPP, 1, "g_ui_owner_tid.load", "UI owner TID must be used by affinity checks and diagnostics")
    if "ui_owner_tid" not in combined:
        add_failure(MAIN_CPP, 1, "ui_owner_tid", "UI owner TID must be source-visible in diagnostics")


def check_affinity_guards_around_ui_sensitive_blocks() -> None:
    checks = [
        ("main", MAIN_CPP, r"LRESULT\s+WINAPI\s+WndProc\s*\([^)]*\)", "WndProc must assert UI affinity before ImGui/Win32 UI state handling"),
        ("main", MAIN_CPP, r"bool\s+CreateDeviceD3D\s*\([^)]*\)", "CreateDeviceD3D must assert UI affinity before D3D/swapchain creation"),
        ("main", MAIN_CPP, r"void\s+CleanupDeviceD3D\s*\([^)]*\)", "CleanupDeviceD3D must assert UI affinity before D3D/swapchain teardown"),
        ("main", MAIN_CPP, r"void\s+CreateRenderTarget\s*\([^)]*\)", "CreateRenderTarget must assert UI affinity before render-target/blur mutation"),
        ("main", MAIN_CPP, r"void\s+CleanupRenderTarget\s*\([^)]*\)", "CleanupRenderTarget must assert UI affinity before render-target mutation"),
        ("main", MAIN_CPP, r"static\s+bool\s+resize_swapchain_and_target\s*\([^)]*\)", "swapchain resize must assert UI affinity"),
        ("main", MAIN_CPP, r"__declspec\s*\(\s*noinline\s*\)\s*static\s+DWORD\s+seh_swapchain_present\s*\([^)]*\)", "Present must assert UI affinity"),
        ("main", MAIN_CPP, r"__declspec\s*\(\s*noinline\s*\)\s*static\s+DWORD\s+seh_imgui_wndproc_handler\s*\([^)]*\)", "ImGui WndProc bridge must assert UI affinity"),
    ]
    for key, path, signature, reason in checks:
        start, body, token = function_block_regex(TEXT[key], signature)
        if not body:
            add_failure(path, 1, signature, "required UI-sensitive function body is missing")
            continue
        if not has_any(body, UI_AFFINITY_TOKENS) and "g_ui_owner_tid" not in body:
            add_failure(path, line_of_pos(TEXT[key], start), token, reason)
    wnd_start, wnd_body, _token = function_block_regex(TEXT["main"], r"LRESULT\s+WINAPI\s+WndProc\s*\([^)]*\)")
    if wnd_body:
        for token in ["globals::ui::", "DwmSetWindowAttribute", "rebuild_fonts", "aida::ui::apply_imgui_style"]:
            if token in wnd_body and not has_any(wnd_body, UI_AFFINITY_TOKENS):
                add_failure(MAIN_CPP, line_of_pos(TEXT["main"], wnd_start), token, "global UI mutation in WndProc must be covered by UI-affinity checks")


def check_testlab_uses_dispatcher() -> None:
    text = TEXT["testlab_ui"]
    if not has_any(text, UI_DISPATCHER_POST_TOKENS):
        fail_key("testlab_ui", "phase_ui_tests", "Test Lab UI-phase publication must use the central UI dispatcher")
    for token in ["PostMessageW(g_hwnd, WM_NULL", "::PostMessageW(g_hwnd, WM_NULL"]:
        if token in text:
            fail_key("testlab_ui", token, "Test Lab must not wake the render thread directly with WM_NULL; use dispatcher wake coalescing")
    if "g_ui_phase_jobs" in text and not has_any(text, UI_DISPATCHER_DRAIN_TOKENS):
        fail_key("testlab_ui", "g_ui_phase_jobs", "Test Lab-specific UI queue must be migrated into or drained by the central dispatcher")
    testlab_root = STANDALONE_ROOT / "core" / "testlab"
    for path in iter_source_files(testlab_root):
        file_text = read(path)
        exchange_start, exchange_body = balanced_block(file_text, "publish_exchange_observed_on_ui")
        exchange_end = exchange_start + len(exchange_body) if exchange_start >= 0 else -1
        exchange_body_proves_ui = bool(exchange_body) and has_any(exchange_body, UI_DISPATCHER_POST_TOKENS) and has_any(exchange_body, UI_AFFINITY_TOKENS) and "source_proven_ui_thread" in exchange_body
        for match in re.finditer(r"\baida::events::publish\s*\(", file_text):
            context = file_text[max(0, match.start() - 1200):match.end() + 1200]
            if exchange_body_proves_ui and exchange_start <= match.start() <= exchange_end:
                continue
            if not has_any(context, UI_DISPATCHER_POST_TOKENS) and "ui_thread_only" not in context and "source_proven_ui_thread" not in context:
                add_failure(path, line_of_pos(file_text, match.start()), "aida::events::publish", "Test Lab event publication must use the central dispatcher or carry source-visible UI-thread-only proof")


def check_file_dialog_uses_dispatcher() -> None:
    text = TEXT["helpers"]
    if "file_dialog" not in text:
        fail_key("helpers", "file_dialog", "deferred file-dialog publication path is missing")
        return
    publication_token = "static void store_result"
    start, store_body = balanced_block(text, publication_token)
    if not store_body:
        publication_token = "static void publish_result"
        start, store_body = balanced_block(text, publication_token)
    if not store_body:
        fail_key("helpers", publication_token, "file-dialog result publication function is missing")
        return
    if not has_any(store_body, UI_DISPATCHER_POST_TOKENS):
        add_failure(HELPERS_CPP, line_of_pos(text, start), publication_token, "file-dialog worker result publication must enqueue a UI dispatcher task")
    if "result_ready().store(true" in store_body:
        add_failure(HELPERS_CPP, line_of_pos(text, text.find("result_ready().store(true", start)), "result_ready().store(true)", "file-dialog publication must not rely on render polling state instead of the dispatcher")
    start, run_body = balanced_block(text, "static void run_pending")
    if run_body and "file_browser::open_path" in run_body and not has_any(run_body, UI_AFFINITY_TOKENS) and not has_any(run_body, UI_DISPATCHER_DRAIN_TOKENS):
        add_failure(HELPERS_CPP, line_of_pos(text, start), "file_browser::open_path", "file-dialog UI mutation must execute under dispatcher UI-affinity proof")


def extract_wm_dropfiles_block() -> tuple[int, str]:
    text = TEXT["main"]
    wnd_start, wnd_body, _token = function_block_regex(text, r"LRESULT\s+WINAPI\s+WndProc\s*\([^)]*\)")
    if wnd_start < 0 or not wnd_body:
        return -1, ""
    case_rel = wnd_body.find("case WM_DROPFILES:")
    if case_rel < 0:
        return -1, ""
    case_pos = wnd_start + case_rel
    if case_pos < 0:
        return -1, ""
    next_case_rel = wnd_body.find("\n    case ", case_rel + 1)
    switch_end_rel = wnd_body.find("\n    }\n    aida_tracer::set_wndproc_state(\"defwindowproc_enter\"", case_rel)
    rel_end = min([pos for pos in [next_case_rel, switch_end_rel] if pos >= 0], default=len(wnd_body))
    end = wnd_start + rel_end
    return case_pos, text[case_pos:end]


def check_dragdrop_is_deferred_out_of_wndproc() -> None:
    start, block = extract_wm_dropfiles_block()
    if not block:
        add_failure(MAIN_CPP, 1, "WM_DROPFILES", "WndProc must handle drag/drop payload capture explicitly")
        return
    for token in ["file_browser::open_path", "work_queue::post", "CreateProcess", "WaitFor", ".join(", "driver_", "network"]:
        if token in block:
            add_failure(MAIN_CPP, line_of_pos(TEXT["main"], start + block.find(token)), token, "WM_DROPFILES must stay fast and defer heavy work out of WndProc")
    if "DragFinish" not in block:
        add_failure(MAIN_CPP, line_of_pos(TEXT["main"], start), "DragFinish", "WM_DROPFILES must release the HDROP handle after bounded capture")
    if not has_any(block, UI_DISPATCHER_POST_TOKENS):
        add_failure(MAIN_CPP, line_of_pos(TEXT["main"], start), "WM_DROPFILES dispatcher post", "drag/drop publication must use the central dispatcher after bounded payload capture")


def check_worker_to_ui_handoffs_are_routed() -> None:
    for path, text, lines in SOURCES:
        rel_path = rel(path)
        if "ui_dispatcher" in rel_path:
            continue
        for index, line in enumerate(lines, 1):
            normalized = " ".join(line.strip().split())
            if "PostMessageW(g_hwnd, WM_NULL" in normalized or "::PostMessageW(g_hwnd, WM_NULL" in normalized:
                add_failure(path, index, "PostMessageW(g_hwnd, WM_NULL)", "worker-to-UI wake must be routed through dispatcher wake coalescing", line)
        for match in re.finditer(r"PostThreadMessageW\s*\([^;\n]+WM_NULL[^;\n]*\)", text):
            context = text[max(0, match.start() - 900):match.end() + 900]
            if "ui_dispatcher" in context or "peek_rescue" in context or "render_stall_recovery" in context:
                continue
            index = line_of_pos(text, match.start())
            line = lines[index - 1] if 0 <= index - 1 < len(lines) else ""
            add_failure(path, index, "PostThreadMessageW(... WM_NULL)", "worker-to-UI thread wake must be routed through dispatcher wake coalescing", line)


def check_dispatcher_budget_and_flood_contract() -> None:
    dispatchers = dispatcher_sources()
    if not dispatchers:
        return
    combined = "\n".join(text for _path, text in dispatchers)
    for tokens, token_name, reason in [
        (["max_queue", "MaxQueue", "kMaxQueueDepth", "kUiDispatchMaxDepth"], "max_queue", "dispatcher must bound queued UI tasks so worker floods cannot grow unbounded"),
        (["queue_full", "rejected_full", "reject_capacity"], "queue_full", "dispatcher must log or reject full queues explicitly"),
        (["UI-DISPATCHER-BACKLOG", "UI-DISPATCHER-REJECT", "ui_dispatcher"], "UI-DISPATCHER-BACKLOG", "dispatcher backlog diagnostics must be source-visible"),
        (["wake_pending"], "wake_pending", "dispatcher must coalesce posted Win32 wake messages"),
        (["compare_exchange", "exchange(true"], "compare_exchange", "dispatcher must use atomic compare/exchange wake coalescing"),
    ]:
        if not has_any(combined, tokens):
            add_failure(dispatchers[0][0], 1, token_name, reason)
    if "PostMessageW" in combined or "PostThreadMessageW" in combined:
        wake_count = len(re.findall(r"Post(?:Thread)?MessageW\s*\([^;]+kAidaUiDispatcherWakeMessage", combined, re.S))
        if len(find_dispatcher_implementation_blocks()) == 1 and wake_count > 2:
            add_failure(dispatchers[0][0], 1, "PostMessageW(kAidaUiDispatcherWakeMessage)", "one dispatcher wake function may use HWND and thread fallback posts, but no extra wake post sites are allowed")


def check_no_untrusted_window_message_payload_commands() -> None:
    wnd_start, wnd_body, _token = function_block_regex(TEXT["main"], r"LRESULT\s+WINAPI\s+WndProc\s*\([^)]*\)")
    if not wnd_body:
        add_failure(MAIN_CPP, 1, "WndProc", "WndProc body is missing")
        return
    for token in ["case WM_COPYDATA", "case WM_USER", "case WM_APP", "COPYDATASTRUCT", "RegisterWindowMessage"]:
        if token in wnd_body:
            add_failure(MAIN_CPP, line_of_pos(TEXT["main"], wnd_start + wnd_body.find(token)), token, "WndProc must not trust custom window-message payload commands")
    for path, text, _lines in SOURCES:
        for match in re.finditer(r"\bRegisterWindowMessage[AW]?\s*\(", text):
            add_failure(path, line_of_pos(text, match.start()), "RegisterWindowMessage", "custom window messages must be wake-only and must not carry trusted command payloads")
        for match in re.finditer(r"\bPost(?:Thread)?MessageW\s*\([^;\n]+,\s*(?:WM_APP|WM_USER|kAidaUiDispatcherWakeMessage)[^,\n]*,\s*([^,\n]+),\s*([^)]+)\)", text):
            wparam = " ".join(match.group(1).strip().split())
            lparam = " ".join(match.group(2).strip().rstrip(";").split())
            zero_values = {"0", "0U", "0UL", "NULL", "nullptr"}
            if wparam not in zero_values or lparam not in zero_values:
                add_failure(path, line_of_pos(text, match.start()), "PostMessageW custom payload", "custom window messages must be wake-only and carry zero payload fields", match.group(0))


def main() -> int:
    check_required_files()
    check_prior_guard_scripts_direct_source_only()
    check_phase0_guard_still_covers_invariants()
    check_phase6_cmake_wiring()
    check_no_dxgi_waitable_or_flip_latency_path()
    check_dispatcher_core_contract()
    check_ui_owner_tid_contract()
    check_affinity_guards_around_ui_sensitive_blocks()
    check_testlab_uses_dispatcher()
    check_file_dialog_uses_dispatcher()
    check_dragdrop_is_deferred_out_of_wndproc()
    check_worker_to_ui_handoffs_are_routed()
    check_dispatcher_budget_and_flood_contract()
    check_no_untrusted_window_message_payload_commands()
    if FAILURES:
        for failure in FAILURES:
            print(f"{failure.path}:{failure.line}: token={failure.token}: {failure.reason}: {failure.text}", file=sys.stderr)
        return 1
    print("Phase 6 UI dispatcher guard passed: central wake-only dispatcher, UI owner affinity, routed UI handoffs, WndProc drag/drop deferral, wake coalescing, Phase 0 invariants, and source-only Phase 0-5 guards are present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
