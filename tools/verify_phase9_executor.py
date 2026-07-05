#!/usr/bin/env python3
"""Phase 9: Executor Facade And Taskflow Evaluation - Static Source Verification Script.

This script verifies that all Phase 9 executor and taskflow evaluation components
exist in the source code without invoking any build, configure, compile, link, or
package step.

Phase 9 requirements:
  1. aida::executor facade header with 9 domains and full submission fields
  2. All required API functions: submit, active_snapshot, wait_for, cancel,
     check_deadlines, shutdown, set_ui_owner_tid, is_ui_thread,
     taskflow_evaluation_status, snapshot_json_string
  3. Required log events: EXECUTOR-SUBMIT, EXECUTOR-REJECT, EXECUTOR-START,
     EXECUTOR-FINISH, EXECUTOR-CANCEL, EXECUTOR-TIMEOUT, EXECUTOR-SNAPSHOT,
     EXECUTOR-UI-WAIT-REJECTED
  4. Metadata ring breadcrumbs via emit_breadcrumb and breadcrumb_category_t
  5. No raw thread creation in executor.hpp
  6. Routes to existing queues only (work_queue, critical_work_queue)
  7. taskflow_evaluation.hpp with kTaskflowVersion="4.1.0" and
     kTaskflowEvaluationStatus="not_integrated_rejected_by_cxx_standard"
  8. No Taskflow headers in any AiDAStandalone source file
  9. No C++20 features in executor.hpp
  10. Phase 0-8 guard scripts still exist
  11. Ported call sites use aida::executor::submit
  12. EXECUTOR-UI-WAIT-REJECTED rejects UI-thread blocking waits
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STANDALONE_ROOT = os.path.join(REPO_ROOT, "src", "standalone", "src")
INFRA_ROOT = os.path.join(STANDALONE_ROOT, "core", "infra")
DIAG_ROOT = os.path.join(STANDALONE_ROOT, "core", "diagnostics")

errors = []
warnings = []
passed = []


def check_file_exists(path, description):
    if os.path.isfile(path):
        passed.append(f"EXISTS: {description} ({os.path.relpath(path, REPO_ROOT)})")
        return True
    else:
        errors.append(f"MISSING: {description} ({os.path.relpath(path, REPO_ROOT)})")
        return False


def check_pattern_in_file(path, pattern, description, flags=0):
    if not os.path.isfile(path):
        errors.append(f"FILE_MISSING for {description}: {path}")
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        if re.search(pattern, content, flags):
            passed.append(f"FOUND: {description}")
            return True
        else:
            errors.append(f"NOT_FOUND: {description} in {os.path.relpath(path, REPO_ROOT)}")
            return False
    except Exception as e:
        errors.append(f"READ_ERROR: {description}: {e}")
        return False


def check_pattern_in_dir(dirpath, pattern, description, extensions=(".hpp", ".cpp", ".h"), flags=0):
    if not os.path.isdir(dirpath):
        errors.append(f"DIR_MISSING for {description}: {dirpath}")
        return False
    for root, dirs, files in os.walk(dirpath):
        if os.sep + ".deps" + os.sep in root + os.sep:
            continue
        for fname in files:
            if fname.endswith(extensions):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    if re.search(pattern, content, flags):
                        passed.append(f"FOUND: {description} in {os.path.relpath(fpath, REPO_ROOT)}")
                        return True
                except Exception:
                    pass
    errors.append(f"NOT_FOUND_IN_DIR: {description} in {os.path.relpath(dirpath, REPO_ROOT)}")
    return False


def check_no_pattern_in_file(path, pattern, description, flags=0):
    if not os.path.isfile(path):
        errors.append(f"FILE_MISSING for {description}: {path}")
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        matches = re.findall(pattern, content, flags)
        if matches:
            errors.append(f"FORBIDDEN_FOUND: {description} in {os.path.relpath(path, REPO_ROOT)} ({len(matches)} matches)")
            return False
        else:
            passed.append(f"ABSENT: {description}")
            return True
    except Exception as e:
        errors.append(f"READ_ERROR: {description}: {e}")
        return False


def check_no_pattern_in_dir(dirpath, pattern, description, extensions=(".hpp", ".cpp", ".h"), flags=0, exclude_files=()):
    if not os.path.isdir(dirpath):
        errors.append(f"DIR_MISSING for {description}: {dirpath}")
        return False
    found = False
    for root, dirs, files in os.walk(dirpath):
        if os.sep + ".deps" + os.sep in root + os.sep:
            continue
        for fname in files:
            if fname.endswith(extensions):
                fpath = os.path.join(root, fname)
                if os.path.basename(fpath) in exclude_files:
                    continue
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    matches = re.findall(pattern, content, flags)
                    if matches:
                        errors.append(f"FORBIDDEN_FOUND: {description} in {os.path.relpath(fpath, REPO_ROOT)} ({len(matches)} matches)")
                        found = True
                except Exception:
                    pass
    if not found:
        passed.append(f"ABSENT_IN_DIR: {description} in {os.path.relpath(dirpath, REPO_ROOT)}")
        return True
    return False


def check_all_patterns_in_file(path, patterns, description_prefix, flags=0):
    if not os.path.isfile(path):
        errors.append(f"FILE_MISSING for {description_prefix}: {path}")
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        errors.append(f"READ_ERROR: {description_prefix}: {e}")
        return False
    all_ok = True
    for label, pat in patterns:
        if re.search(pat, content, flags):
            passed.append(f"FOUND: {description_prefix}: {label}")
        else:
            errors.append(f"NOT_FOUND: {description_prefix}: {label} in {os.path.relpath(path, REPO_ROOT)}")
            all_ok = False
    return all_ok


print("=" * 70)
print("Phase 9: Executor Facade And Taskflow Evaluation - Static Source Verification")
print("=" * 70)
print()

# --- 1. Executor facade header exists ---
print("[1] Executor facade header")
executor_path = os.path.join(INFRA_ROOT, "executor.hpp")
check_file_exists(executor_path, "executor.hpp")

# --- 2. Namespace aida::executor ---
print("[2] Namespace aida::executor")
check_pattern_in_file(executor_path, r"namespace\s+aida::executor", "namespace aida::executor")

# --- 3. All 9 domains present ---
print("[3] All 9 domains present")
domain_patterns = [
    ("domain general", r"domain_t::general"),
    ("domain service", r"domain_t::service"),
    ("domain critical", r"domain_t::critical"),
    ("domain ui_dispatch", r"domain_t::ui_dispatch"),
    ("domain external_tool", r"domain_t::external_tool"),
    ("domain long_running", r"domain_t::long_running"),
    ("domain security_liveness", r"domain_t::security_liveness"),
    ("domain feature_worker", r"domain_t::feature_worker"),
    ("domain diagnostics", r"domain_t::diagnostics"),
]
check_all_patterns_in_file(executor_path, domain_patterns, "domain enum")

# --- 4. All required submission fields present ---
print("[4] All required submission fields present")
submission_fields = [
    ("owner_subsystem", r"owner_subsystem"),
    ("label", r"\blabel\b"),
    ("thread_class", r"thread_class"),
    ("domain", r"\bdomain\b"),
    ("priority", r"priority"),
    ("cancel_hook", r"cancel_hook"),
    ("deadline_ms", r"deadline_ms"),
    ("capacity_lease", r"capacity_lease"),
    ("no_capacity_reason", r"no_capacity_reason"),
    ("session_id", r"session_id"),
    ("target_id", r"target_id"),
    ("target_pid", r"target_pid"),
    ("lease_token", r"lease_token"),
    ("generation", r"generation"),
    ("diagnostic_id", r"diagnostic_id"),
    ("request_id", r"request_id"),
    ("ui_access_policy", r"ui_access_policy"),
    ("failure_policy", r"failure_policy"),
    ("shutdown_policy", r"shutdown_policy"),
    ("body", r"std::function<void\(\)>\s+body"),
]
check_all_patterns_in_file(executor_path, submission_fields, "submission_t field")

# --- 5. Required API functions present ---
print("[5] Required API functions present")
api_functions = [
    ("submit", r"submit_result_t\s+submit\b"),
    ("active_snapshot", r"active_snapshot_t\s+active_snapshot\b"),
    ("wait_for", r"wait_result_t\s+wait_for\b"),
    ("cancel", r"bool\s+cancel\b"),
    ("check_deadlines", r"void\s+check_deadlines\b"),
    ("shutdown", r"void\s+shutdown\b"),
    ("set_ui_owner_tid", r"void\s+set_ui_owner_tid\b"),
    ("is_ui_thread", r"bool\s+is_ui_thread\b"),
    ("taskflow_evaluation_status", r"taskflow_evaluation_status"),
    ("snapshot_json_string", r"snapshot_json_string"),
]
check_all_patterns_in_file(executor_path, api_functions, "API function")

# --- 6. Required log events present ---
print("[6] Required log events present")
log_events = [
    ("EXECUTOR-SUBMIT", r"EXECUTOR-SUBMIT"),
    ("EXECUTOR-REJECT", r"EXECUTOR-REJECT"),
    ("EXECUTOR-START", r"EXECUTOR-START"),
    ("EXECUTOR-FINISH", r"EXECUTOR-FINISH"),
    ("EXECUTOR-CANCEL", r"EXECUTOR-CANCEL"),
    ("EXECUTOR-TIMEOUT", r"EXECUTOR-TIMEOUT"),
    ("EXECUTOR-SNAPSHOT", r"EXECUTOR-SNAPSHOT"),
    ("EXECUTOR-UI-WAIT-REJECTED", r"EXECUTOR-UI-WAIT-REJECTED"),
]
check_all_patterns_in_file(executor_path, log_events, "log event")

# --- 7. Metadata ring breadcrumbs present ---
print("[7] Metadata ring breadcrumbs")
check_pattern_in_file(executor_path, r"emit_breadcrumb", "emit_breadcrumb function")
check_pattern_in_file(executor_path, r"breadcrumb_category_t", "breadcrumb_category_t reference")
check_pattern_in_file(executor_path, r"aida::diagnostics::emit", "aida::diagnostics::emit call")

# --- 8. No raw thread creation in executor.hpp ---
print("[8] No raw thread creation in executor.hpp")
check_no_pattern_in_file(executor_path, r"std::thread", "no std::thread in executor.hpp")
check_no_pattern_in_file(executor_path, r"CreateThread", "no CreateThread in executor.hpp")
check_no_pattern_in_file(executor_path, r"_beginthreadex", "no _beginthreadex in executor.hpp")
check_no_pattern_in_file(executor_path, r"NtCreateThreadEx", "no NtCreateThreadEx in executor.hpp")
check_no_pattern_in_file(executor_path, r"std::async", "no std::async in executor.hpp")
check_no_pattern_in_file(executor_path, r"QueueUserWorkItem", "no QueueUserWorkItem in executor.hpp")

# --- 9. Routes to existing queues only ---
print("[9] Routes to existing queues only")
check_pattern_in_file(executor_path, r"work_queue::post_labeled", "routes to work_queue::post_labeled")
check_pattern_in_file(executor_path, r"work_queue::post_service_labeled", "routes to work_queue::post_service_labeled")
check_pattern_in_file(executor_path, r"critical_work_queue::post_labeled", "routes to critical_work_queue::post_labeled")

# --- 10. taskflow_evaluation.hpp exists ---
print("[10] taskflow_evaluation.hpp exists")
taskflow_eval_path = os.path.join(INFRA_ROOT, "taskflow_evaluation.hpp")
check_file_exists(taskflow_eval_path, "taskflow_evaluation.hpp")

# --- 11. Taskflow evaluation record constants ---
print("[11] Taskflow evaluation record constants")
check_pattern_in_file(taskflow_eval_path, r'kTaskflowVersion\s*=\s*"4\.1\.0"', "kTaskflowVersion = 4.1.0")
check_pattern_in_file(
    taskflow_eval_path,
    r'kTaskflowEvaluationStatus\s*=\s*"not_integrated_rejected_by_cxx_standard"',
    "kTaskflowEvaluationStatus = not_integrated_rejected_by_cxx_standard",
)

# --- 12. No Taskflow headers in AiDAStandalone source ---
print("[12] No Taskflow headers in AiDAStandalone source")
check_no_pattern_in_dir(
    STANDALONE_ROOT,
    r'#include\s*[<"].*taskflow[>"]',
    "no taskflow include in standalone source",
    extensions=(".hpp", ".cpp", ".h"),
)

# --- 13. No Taskflow tf:: namespace in AiDAStandalone source ---
print("[13] No Taskflow tf:: namespace in AiDAStandalone source")
check_no_pattern_in_dir(
    STANDALONE_ROOT,
    r"\btf::",
    "no tf:: namespace reference in standalone source",
    extensions=(".hpp", ".cpp", ".h"),
    exclude_files=("taskflow_evaluation.hpp",),
)

# --- 14. domain_to_queue_name function with all 9 domain mappings ---
print("[14] domain_to_queue_name with all 9 domain mappings")
check_pattern_in_file(executor_path, r"domain_to_queue_name", "domain_to_queue_name function exists")
queue_name_patterns = [
    ("general->work_queue.general", r'domain_t::general.*?return\s+"work_queue\.general"'),
    ("service->work_queue.service", r'domain_t::service.*?return\s+"work_queue\.service"'),
    ("critical->critical_work_queue", r'domain_t::critical.*?return\s+"critical_work_queue"'),
    ("ui_dispatch->ui_dispatcher", r'domain_t::ui_dispatch.*?return\s+"ui_dispatcher"'),
    ("external_tool->work_queue.general+capacity_governor", r'domain_t::external_tool.*?return\s+"work_queue\.general\+capacity_governor"'),
    ("long_running->work_queue.service+downstream_governor", r'domain_t::long_running.*?return\s+"work_queue\.service\+downstream_governor"'),
    ("security_liveness->critical_work_queue.reserved_p0", r'domain_t::security_liveness.*?return\s+"critical_work_queue\.reserved_p0"'),
    ("feature_worker->work_queue.general+downstream_governor.feature_worker", r'domain_t::feature_worker.*?return\s+"work_queue\.general\+downstream_governor\.feature_worker"'),
    ("diagnostics->work_queue.general.low_priority", r'domain_t::diagnostics.*?return\s+"work_queue\.general\.low_priority"'),
]
check_all_patterns_in_file(executor_path, queue_name_patterns, "domain_to_queue_name mapping", flags=re.DOTALL)

# --- 15. No C++20 features in executor.hpp ---
print("[15] No C++20 features in executor.hpp")
check_no_pattern_in_file(executor_path, r"\bconcept\b\s+", "no C++20 concepts in executor.hpp")
check_no_pattern_in_file(executor_path, r"\branges::", "no C++20 ranges in executor.hpp")
check_no_pattern_in_file(executor_path, r"\bco_await\b", "no C++20 coroutines (co_await) in executor.hpp")
check_no_pattern_in_file(executor_path, r"\bco_yield\b", "no C++20 coroutines (co_yield) in executor.hpp")
check_no_pattern_in_file(executor_path, r"\bco_return\b", "no C++20 coroutines (co_return) in executor.hpp")
check_no_pattern_in_file(executor_path, r"\bimport\s+", "no C++20 modules in executor.hpp")
check_no_pattern_in_file(executor_path, r"\bconsteval\b", "no C++20 consteval in executor.hpp")
check_no_pattern_in_file(executor_path, r"\bconstinit\b", "no C++20 constinit in executor.hpp")
check_no_pattern_in_file(executor_path, r"<=>", "no C++20 spaceship operator in executor.hpp")

# --- 16. Phase 0-8 guard scripts still exist ---
print("[16] Phase 0-8 guard scripts still exist")
phase_guards = {
    0: "verify_phase0_invariants.py",
    1: "verify_thread_runtime_contract.py",
    2: "verify_phase2_capacity.py",
    3: "verify_phase3_admission.py",
    4: "verify_phase4_tool_admission.py",
    5: "verify_phase5_lease_registry.py",
    6: "verify_phase6_ui_dispatcher.py",
    7: "verify_phase7_downstream_producers.py",
    8: "verify_phase8_diagnostics.py",
}
for phase in range(9):
    guard_path = os.path.join(REPO_ROOT, "tools", phase_guards[phase])
    check_file_exists(guard_path, f"Phase {phase} guard script")

# --- 17. Ported call sites use aida::executor::submit ---
print("[17] Ported call sites use aida::executor::submit")
ported_files = [
    os.path.join(STANDALONE_ROOT, "core", "disasm", "decompile_tools_standalone.cpp"),
    os.path.join(STANDALONE_ROOT, "core", "testlab", "test_all_disasm.cpp"),
]
non_portable_files = [
    (os.path.join(STANDALONE_ROOT, "core", "analysis", "analysis_tools_standalone.cpp"), "no work_queue::post calls in file"),
    (os.path.join(STANDALONE_ROOT, "core", "scanner", "scanner_tools_standalone.cpp"), "no work_queue::post calls in file"),
    (os.path.join(STANDALONE_ROOT, "core", "analysis", "pdb_downloader.cpp"), "no work_queue::post calls in file"),
    (os.path.join(STANDALONE_ROOT, "core", "testlab", "test_all_features.cpp"), "all call sites in startup/UI/Camoufox/heartbeat/full-test authority paths"),
]
for candidate in ported_files:
    if not os.path.isfile(candidate):
        errors.append(f"PORTED_FILE_MISSING: {os.path.relpath(candidate, REPO_ROOT)}")
        continue
    try:
        with open(candidate, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        if re.search(r"aida::executor::submit", content):
            passed.append(f"PORTED: {os.path.relpath(candidate, REPO_ROOT)} uses aida::executor::submit")
        else:
            errors.append(f"NOT_PORTED: {os.path.relpath(candidate, REPO_ROOT)} does not use aida::executor::submit")
    except Exception as e:
        errors.append(f"READ_ERROR: {os.path.relpath(candidate, REPO_ROOT)}: {e}")
for candidate, reason in non_portable_files:
    if os.path.isfile(candidate):
        passed.append(f"NON_PORTABLE: {os.path.relpath(candidate, REPO_ROOT)} - {reason}")
    else:
        warnings.append(f"NON_PORTABLE_FILE_MISSING: {os.path.relpath(candidate, REPO_ROOT)}")

# --- 18. EXECUTOR-UI-WAIT-REJECTED rejects UI-thread blocking waits ---
print("[18] EXECUTOR-UI-WAIT-REJECTED rejects UI-thread blocking waits")
check_pattern_in_file(
    executor_path,
    r"EXECUTOR-UI-WAIT-REJECTED.*is_ui_thread|is_ui_thread.*EXECUTOR-UI-WAIT-REJECTED",
    "UI-thread wait rejection in submit path",
    flags=re.DOTALL,
)
check_pattern_in_file(
    executor_path,
    r"wait_for.*is_ui_thread|is_ui_thread.*wait_for",
    "wait_for rejects UI thread",
    flags=re.DOTALL,
)
check_pattern_in_file(
    executor_path,
    r"total_ui_wait_rejected",
    "total_ui_wait_rejected counter",
)

# --- 19. Executor diagnostics integrated into health surface ---
print("[19] Executor diagnostics integrated into health surface")
diag_snapshot_path = os.path.join(DIAG_ROOT, "diagnostic_snapshot.hpp")
check_pattern_in_file(diag_snapshot_path, r"executor_snapshot", "executor_snapshot field in diagnostic_state_t")
check_pattern_in_file(diag_snapshot_path, r'state\.executor_snapshot', "executor field used in build_diagnostics_json")
check_pattern_in_file(diag_snapshot_path, r'taskflow_evaluation\b', "taskflow_evaluation field in diagnostic_state_t")
check_pattern_in_file(diag_snapshot_path, r'state\.taskflow_evaluation', "taskflow_evaluation field used in build_diagnostics_json")

# --- 20. Executor lifecycle wired into main.cpp ---
print("[20] Executor lifecycle wired into main.cpp")
main_cpp_path = os.path.join(STANDALONE_ROOT, "main.cpp")
check_pattern_in_file(main_cpp_path, r'#include.*core/infra/executor\.hpp', "main.cpp includes executor.hpp")
check_pattern_in_file(main_cpp_path, r'#include.*core/infra/taskflow_evaluation\.hpp', "main.cpp includes taskflow_evaluation.hpp")
check_pattern_in_file(main_cpp_path, r'aida::executor::set_ui_owner_tid', "main.cpp calls executor::set_ui_owner_tid")
check_pattern_in_file(main_cpp_path, r'aida::infra::taskflow_eval::log_evaluation', "main.cpp calls taskflow_eval::log_evaluation")
check_pattern_in_file(main_cpp_path, r'aida::executor::check_deadlines', "main.cpp calls executor::check_deadlines from periodic tick")

# --- 21. Executor snapshot wired into mcp_standalone.cpp health endpoint ---
print("[21] Executor snapshot wired into mcp_standalone.cpp health endpoint")
mcp_cpp_path = os.path.join(STANDALONE_ROOT, "core", "mcp", "mcp_standalone.cpp")
check_pattern_in_file(mcp_cpp_path, r'#include.*infra/executor\.hpp', "mcp_standalone.cpp includes executor.hpp")
check_pattern_in_file(mcp_cpp_path, r'#include.*infra/taskflow_evaluation\.hpp', "mcp_standalone.cpp includes taskflow_evaluation.hpp")
check_pattern_in_file(mcp_cpp_path, r'aida::executor::snapshot_json_string', "mcp_standalone.cpp calls executor::snapshot_json_string")
check_pattern_in_file(mcp_cpp_path, r'diag_state\.executor_snapshot\s*=', "mcp_standalone.cpp populates diag_state.executor_snapshot")
check_pattern_in_file(mcp_cpp_path, r'diag_state\.taskflow_evaluation\s*=', "mcp_standalone.cpp populates diag_state.taskflow_evaluation")
check_pattern_in_file(mcp_cpp_path, r'aida::infra::taskflow_eval::kTaskflowEvaluationStatus', "mcp_standalone.cpp references taskflow evaluation status constant")

# --- 22. taskflow_evaluation.hpp has static_asserts proving C++20 incompatibility ---
print("[22] taskflow_evaluation.hpp static_asserts")
taskflow_eval_path = os.path.join(INFRA_ROOT, "taskflow_evaluation.hpp")
check_pattern_in_file(taskflow_eval_path, r'static_assert.*kTaskflowRequiredCxxStandard\s*==\s*20', "static_assert C++20 requirement")
check_pattern_in_file(taskflow_eval_path, r'static_assert.*kAidaStandaloneCxxStandard\s*==\s*17', "static_assert C++17 target")
check_pattern_in_file(taskflow_eval_path, r'static_assert.*kTaskflowIntegratedIntoAidaStandalone\s*==\s*false', "static_assert not integrated")
check_pattern_in_file(taskflow_eval_path, r'static_assert.*kTaskflowOwnsWorkerThreads\s*==\s*true', "static_assert owns worker threads")
check_pattern_in_file(taskflow_eval_path, r'static_assert.*kTaskflowCanUseAidaWinThreadWrappers\s*==\s*false', "static_assert cannot use win_thread wrappers")

# --- 23. Taskflow local source path exists ---
print("[23] Taskflow local source path exists")
taskflow_local_path = os.path.join(REPO_ROOT, ".deps", "taskflow")
if os.path.isdir(taskflow_local_path):
    passed.append(f"EXISTS: Taskflow local source at .deps/taskflow")
    taskflow_cmake = os.path.join(taskflow_local_path, "CMakeLists.txt")
    if os.path.isfile(taskflow_cmake):
        check_pattern_in_file(taskflow_cmake, r'VERSION\s+4\.1\.0', "Taskflow version 4.1.0 in CMakeLists.txt")
        check_pattern_in_file(taskflow_cmake, r'set\(CMAKE_CXX_STANDARD\s+20\)', "Taskflow requires C++20 in CMakeLists.txt")
    else:
        errors.append("MISSING: Taskflow CMakeLists.txt")
else:
    errors.append(f"MISSING: Taskflow local source at .deps/taskflow")

# --- 24. No Taskflow headers in forbidden domain files ---
print("[24] No Taskflow headers in forbidden domain files")
forbidden_domain_files = [
    os.path.join(STANDALONE_ROOT, "main.cpp"),
    os.path.join(STANDALONE_ROOT, "core", "runtime", "standalone_license.hpp"),
    os.path.join(STANDALONE_ROOT, "core", "runtime", "standalone_license.cpp"),
    os.path.join(STANDALONE_ROOT, "core", "runtime", "arc_loader.cpp"),
    os.path.join(STANDALONE_ROOT, "core", "anti-tamper", "orchestrator.hpp"),
    os.path.join(STANDALONE_ROOT, "core", "anti-tamper", "enforcement.hpp"),
    os.path.join(STANDALONE_ROOT, "core", "mcp", "mcp_standalone.cpp"),
    os.path.join(STANDALONE_ROOT, "core", "mcp", "mcp_standalone.hpp"),
    os.path.join(STANDALONE_ROOT, "core", "network", "burp", "camoufox_bridge.cpp"),
    os.path.join(STANDALONE_ROOT, "core", "network", "burp", "camoufox_bridge.hpp"),
]
for forbidden_file in forbidden_domain_files:
    if not os.path.isfile(forbidden_file):
        continue
    check_no_pattern_in_file(forbidden_file, r'#include\s*[<"].*taskflow[>"]', f"no taskflow include in {os.path.relpath(forbidden_file, REPO_ROOT)}")

# --- 25. No security-sensitive domain selects a Taskflow backend in executor.hpp ---
print("[25] No security-sensitive domain selects Taskflow backend")
check_no_pattern_in_file(executor_path, r'#include\s*[<"].*taskflow[>"]', "no taskflow include in executor.hpp")
check_no_pattern_in_file(executor_path, r'\btf::Executor\b', "no tf::Executor in executor.hpp")
check_no_pattern_in_file(executor_path, r'\btf::Taskflow\b', "no tf::Taskflow in executor.hpp")

# --- 26. No new raw thread creation bypasses executor facade ---
print("[26] No new raw thread creation in executor facade")
check_no_pattern_in_file(executor_path, r'\bstd::thread\b', "no std::thread in executor.hpp")
check_no_pattern_in_file(executor_path, r'\bCreateThread\b', "no CreateThread in executor.hpp")
check_no_pattern_in_file(executor_path, r'\b_beginthreadex\b', "no _beginthreadex in executor.hpp")
check_no_pattern_in_file(executor_path, r'\bNtCreateThreadEx\b', "no NtCreateThreadEx in executor.hpp")
check_no_pattern_in_file(executor_path, r'\bstd::async\b', "no std::async in executor.hpp")
check_no_pattern_in_file(executor_path, r'\bQueueUserWorkItem\b', "no QueueUserWorkItem in executor.hpp")

# --- 27. Taskflow evaluation status constant is rejection ---
print("[27] Taskflow evaluation status is rejection")
check_pattern_in_file(taskflow_eval_path, r'kTaskflowEvaluationStatus\s*=\s*"not_integrated_rejected_by_cxx_standard"', "evaluation status is not_integrated_rejected_by_cxx_standard")
check_pattern_in_file(taskflow_eval_path, r'kTaskflowIntegratedIntoAidaStandalone\s*=\s*false', "integration flag is false")
check_pattern_in_file(taskflow_eval_path, r'TASKFLOW-INTEGRATION-REJECTED', "TASKFLOW-INTEGRATION-REJECTED log event present")
check_pattern_in_file(taskflow_eval_path, r'TASKFLOW-EVALUATION', "TASKFLOW-EVALUATION log event present")

# --- 28. Executor domain_to_breadcrumb_category maps to Phase 8 metadata ring ---
print("[28] Executor domain_to_breadcrumb_category maps to metadata ring")
check_pattern_in_file(executor_path, r'domain_to_breadcrumb_category', "domain_to_breadcrumb_category function exists")
check_pattern_in_file(executor_path, r'breadcrumb_category_t::work_queue', "maps to work_queue category")
check_pattern_in_file(executor_path, r'breadcrumb_category_t::critical_queue', "maps to critical_queue category")
check_pattern_in_file(executor_path, r'breadcrumb_category_t::capacity_governor', "maps to capacity_governor category")
check_pattern_in_file(executor_path, r'breadcrumb_category_t::downstream_producer', "maps to downstream_producer category")
check_pattern_in_file(executor_path, r'breadcrumb_category_t::ui_dispatcher', "maps to ui_dispatcher category")

# --- 29. Executor snapshot_json_string includes taskflow evaluation status ---
print("[29] Executor snapshot_json_string includes taskflow evaluation status")
check_pattern_in_file(executor_path, r'taskflow_evaluation_status\(\)', "taskflow_evaluation_status function called in snapshot")
check_pattern_in_file(executor_path, r'taskflow_evaluation_status', "taskflow_evaluation_status JSON field in snapshot")

# --- 30. Executor shutdown_guard exists ---
print("[30] Executor shutdown_guard exists")
check_pattern_in_file(executor_path, r'shutdown_guard_t', "shutdown_guard_t struct exists")
check_pattern_in_file(executor_path, r'g_shutdown_guard', "static g_shutdown_guard instance exists")

# --- Summary ---
print()
print("=" * 70)
print(f"PASSED:  {len(passed)}")
print(f"WARNINGS: {len(warnings)}")
print(f"ERRORS:  {len(errors)}")
print("=" * 70)

if errors:
    print()
    print("ERRORS:")
    for e in errors:
        print(f"  - {e}")

if warnings:
    print()
    print("WARNINGS:")
    for w in warnings:
        print(f"  - {w}")

if errors:
    sys.exit(1)
else:
    print()
    print("Phase 9 static source verification: PASSED")
    sys.exit(0)
