#!/usr/bin/env python3

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STANDALONE_ROOT = os.path.join(REPO_ROOT, "src", "standalone", "src")
INFRA_ROOT = os.path.join(STANDALONE_ROOT, "core", "infra")
TASKFLOW_ROOT = os.path.join(REPO_ROOT, ".deps", "taskflow")

errors = []
passed = []
warnings = []


def rel(path):
    return os.path.relpath(path, REPO_ROOT)


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def check_file(path, label):
    if os.path.isfile(path):
        passed.append(f"EXISTS: {label} ({rel(path)})")
        return True
    errors.append(f"MISSING: {label} ({rel(path)})")
    return False


def require(path, pattern, label, flags=0):
    if not check_file(path, label):
        return False
    text = read(path)
    if re.search(pattern, text, flags):
        passed.append(f"FOUND: {label}")
        return True
    errors.append(f"NOT_FOUND: {label} in {rel(path)}")
    return False


def forbid(path, pattern, label, flags=0):
    if not check_file(path, label):
        return False
    text = read(path)
    matches = re.findall(pattern, text, flags)
    if matches:
        errors.append(f"FORBIDDEN_FOUND: {label} in {rel(path)} ({len(matches)} matches)")
        return False
    passed.append(f"ABSENT: {label}")
    return True


def source_files(root):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", "build", "build-ninja"}]
        for name in files:
            if name.endswith((".hpp", ".h", ".cpp", ".cc", ".cxx")):
                yield os.path.join(current, name)


def forbid_outside(root, pattern, label, allowed_relpaths, flags=0):
    found = False
    allowed = {os.path.normcase(os.path.normpath(p)) for p in allowed_relpaths}
    for path in source_files(root):
        r = os.path.normcase(os.path.normpath(rel(path)))
        if r in allowed:
            continue
        text = read(path)
        matches = re.findall(pattern, text, flags)
        if matches:
            found = True
            errors.append(f"FORBIDDEN_FOUND: {label} in {rel(path)} ({len(matches)} matches)")
    if not found:
        passed.append(f"ABSENT_OUTSIDE_ALLOWED: {label}")
    return not found


def require_all(path, checks, prefix, flags=0):
    ok = True
    for label, pattern in checks:
        if not require(path, pattern, f"{prefix}: {label}", flags):
            ok = False
    return ok


def main():
    print("=" * 76)
    print("Phase 9 Taskflow v3.11 Runtime/Executor Static Source Verification")
    print("=" * 76)

    runtime_path = os.path.join(INFRA_ROOT, "taskflow_runtime.hpp")
    executor_path = os.path.join(INFRA_ROOT, "executor.hpp")
    evaluation_path = os.path.join(INFRA_ROOT, "taskflow_evaluation.hpp")
    worker_path = os.path.join(TASKFLOW_ROOT, "taskflow", "core", "worker.hpp")
    tf_executor_path = os.path.join(TASKFLOW_ROOT, "taskflow", "core", "executor.hpp")
    taskflow_cmake = os.path.join(TASKFLOW_ROOT, "CMakeLists.txt")
    main_cpp = os.path.join(STANDALONE_ROOT, "main.cpp")

    check_file(runtime_path, "taskflow_runtime.hpp")
    check_file(executor_path, "executor.hpp")
    check_file(evaluation_path, "taskflow_evaluation.hpp")
    check_file(worker_path, "Taskflow worker.hpp")
    check_file(tf_executor_path, "Taskflow executor.hpp")
    check_file(taskflow_cmake, "Taskflow CMakeLists.txt")

    require(taskflow_cmake, r"project\(Taskflow\s+VERSION\s+3\.11\.0\s+LANGUAGES\s+CXX\)", "Taskflow version 3.11.0")
    forbid(taskflow_cmake, r"VERSION\s+4\.", "no Taskflow 4.x requirement")
    forbid(taskflow_cmake, r"set\s*\(\s*CMAKE_CXX_STANDARD\s+20\s*\)", "no Taskflow C++20 standard requirement")
    require(os.path.join(TASKFLOW_ROOT, "taskflow", "taskflow.hpp"), r"#define\s+TF_VERSION\s+301100", "TF_VERSION 301100")

    require(worker_path, r"#include\s+\"win_thread\.hpp\"", "Taskflow worker includes AiDA win_thread")
    require(worker_path, r"aida::infra::win_thread::joinable_thread_t\s+_thread", "Taskflow Worker stores joinable_thread_t")
    require(worker_path, r"aida::infra::win_thread::joinable_thread_t&\s+thread\(\)", "Taskflow Worker thread accessor returns joinable_thread_t")
    forbid(worker_path, r"\bstd::thread\s+_thread\b", "no raw std::thread worker storage")

    require(tf_executor_path, r"_thread\.start\s*\(", "Taskflow _spawn starts AiDA joinable thread")
    require(tf_executor_path, r"failed to start AiDA Taskflow worker", "Taskflow worker start failure is surfaced")
    require(tf_executor_path, r"std::unordered_map\s*<\s*unsigned\s*,\s*Worker\s*\*>", "Taskflow worker lookup uses Win32 TID key")
    require(tf_executor_path, r"GetCurrentThreadId\(\)", "Taskflow this_worker uses current Win32 TID")
    forbid(tf_executor_path, r"_thread\s*=\s*std::thread\s*\(", "no raw std::thread worker creation")
    forbid(tf_executor_path, r"std::unordered_map\s*<\s*std::thread::id\s*,\s*Worker\s*\*>", "no std::thread::id worker map")
    forbid(tf_executor_path, r"_thread\.get_id\s*\(", "no std::thread get_id dependency for workers")

    runtime_symbols = [
        ("task_descriptor_t", r"struct\s+task_descriptor_t\b"),
        ("graph_descriptor_t", r"struct\s+graph_descriptor_t\b"),
        ("job_handle_t", r"struct\s+job_handle_t\b"),
        ("executor_domain_t", r"enum\s+class\s+executor_domain_t\b"),
        ("job_state_t", r"enum\s+class\s+job_state_t\b"),
        ("queued", r"job_state_t[\s\S]*queued"),
        ("not_started", r"job_state_t[\s\S]*not_started"),
        ("running", r"job_state_t[\s\S]*running"),
        ("completed", r"job_state_t[\s\S]*completed"),
        ("cancelled", r"job_state_t[\s\S]*cancelled"),
        ("failed", r"job_state_t[\s\S]*failed"),
        ("timed_out", r"job_state_t[\s\S]*timed_out"),
        ("submit", r"submit_result_t\s+submit\s*\("),
        ("submit_graph", r"submit_result_t\s+submit_graph\s*\("),
        ("cancel", r"bool\s+cancel\s*\("),
        ("wait_for", r"wait_result_t\s+wait_for\s*\("),
        ("check_deadlines", r"void\s+check_deadlines\s*\("),
        ("active_snapshot", r"runtime_snapshot_t\s+active_snapshot\s*\("),
        ("snapshot_json_string", r"std::string\s+snapshot_json_string\s*\("),
        ("all_pools_quiescent", r"bool\s+all_pools_quiescent\s*\("),
        ("shutdown", r"(?:bool|void)\s+shutdown\s*\("),
        ("compat pool_t", r"struct\s+pool_t\b"),
        ("compat post_to", r"bool\s+post_to\s*\("),
        ("compat stats_for", r"stats_t\s+stats_for\s*\("),
        ("compat shutdown_pool", r"(?:bool|void)\s+shutdown_pool\s*\("),
        ("tf run future", r"p\.executor->run\s*\("),
        ("stored future", r"tf::Future<void>\s+future"),
        ("future cancel", r"future\.cancel\s*\("),
        ("cancellation token", r"cancellation_token_t"),
        ("deadline timeout", r"taskflow_deadline_timeout"),
        ("stuck workers", r"stuck_workers_for"),
    ]
    require_all(runtime_path, runtime_symbols, "runtime facade")
    forbid(runtime_path, r"silent_async\s*\(", "no silent_async in taskflow_runtime")
    forbid(runtime_path, r"executor->silent_async", "no executor->silent_async in taskflow_runtime")

    executor_symbols = [
        ("namespace", r"namespace\s+aida::infra::executor"),
        ("domain_t", r"enum\s+class\s+domain_t"),
        ("submit", r"submit_result_t\s+submit\s*\("),
        ("active_snapshot", r"active_snapshot_t\s+active_snapshot\s*\("),
        ("wait_for", r"wait_result_t\s+wait_for\s*\("),
        ("cancel", r"bool\s+cancel\s*\("),
        ("check_deadlines", r"void\s+check_deadlines\s*\("),
        ("shutdown", r"(?:bool|void)\s+shutdown\s*\("),
        ("snapshot_json_string", r"std::string\s+snapshot_json_string\s*\("),
        ("runtime submit", r"taskflow_runtime::submit\s*\("),
        ("runtime wait", r"taskflow_runtime::wait_for\s*\("),
        ("runtime cancel", r"taskflow_runtime::cancel\s*\("),
        ("runtime deadlines", r"taskflow_runtime::check_deadlines\s*\("),
        ("runtime shutdown", r"taskflow_runtime::shutdown\s*\("),
        ("runtime snapshot", r"taskflow_runtime::active_snapshot\s*\("),
        ("UI wait rejected", r"EXECUTOR-UI-WAIT-REJECTED"),
        ("submit log", r"EXECUTOR-SUBMIT"),
        ("start log", r"EXECUTOR-START"),
        ("finish log", r"EXECUTOR-FINISH"),
        ("cancel log", r"EXECUTOR-CANCEL"),
        ("timeout log", r"EXECUTOR-TIMEOUT"),
        ("snapshot log", r"EXECUTOR-SNAPSHOT"),
        ("reject reasons", r"reject_reasons"),
        ("capacity lease snapshot", r"capacity_lease_active"),
        ("downstream governor", r"downstream_governor"),
    ]
    require_all(executor_path, executor_symbols, "executor facade")
    forbid(executor_path, r"\bwork_queue::", "executor does not route through work_queue")
    forbid(executor_path, r"\bcritical_work_queue::", "executor does not route through critical_work_queue")
    forbid(executor_path, r"\btf::Executor\b", "no raw tf::Executor in executor facade")
    forbid(executor_path, r"\btf::Taskflow\b", "no raw tf::Taskflow in executor facade")
    forbid(executor_path, r"\bstd::thread\b|\bCreateThread\b|\b_beginthreadex\b|\bNtCreateThreadEx\b|\bstd::async\b|\bQueueUserWorkItem\b", "no raw thread creation in executor facade")

    evaluation_checks = [
        ("version 3.11.0", r'kTaskflowVersion\s*=\s*"3\.11\.0"'),
        ("C++17", r"kTaskflowRequiredCxxStandard\s*=\s*17"),
        ("no C++20", r"kTaskflowRequiresCxx20\s*=\s*false"),
        ("worker joinable", r"kTaskflowWorkerStorageUsesAidaJoinableThread\s*=\s*true"),
        ("win thread wrappers", r"kTaskflowCanUseAidaWinThreadWrappers\s*=\s*true"),
        ("runtime facade", r"kTaskflowRuntimeFacadeIntegrated\s*=\s*true"),
        ("executor facade", r"kTaskflowExecutorFacadeRoutesRuntime\s*=\s*true"),
        ("tracked futures", r"kTaskflowRuntimeUsesTrackedRunFutures\s*=\s*true"),
        ("silent async false", r"kTaskflowRuntimeUsesSilentAsyncForProtectedWork\s*=\s*false"),
        ("standalone-wide complete", r"kTaskflowStandaloneWideMigrationComplete\s*=\s*true"),
        ("integrated complete", r"kTaskflowIntegratedIntoAidaStandalone\s*=\s*true"),
        ("complete status", r'kTaskflowEvaluationStatus\s*=\s*"standalone_wide_taskflow_3_11_cxx17_integration_complete"'),
        ("complete log", r"TASKFLOW-INTEGRATION-COMPLETE"),
        ("static TF_VERSION", r"static_assert\s*\(\s*TF_VERSION\s*==\s*301100"),
    ]
    require_all(evaluation_path, evaluation_checks, "truthful evaluation")
    forbid(evaluation_path, r"4\.1\.0|not_integrated_rejected_by_cxx_standard", "no stale Taskflow 4.x rejection evaluation")
    forbid(evaluation_path, r"kTaskflowStandaloneWideMigrationComplete\s*=\s*false", "standalone-wide completion cannot be false")
    forbid(evaluation_path, r"kTaskflowIntegratedIntoAidaStandalone\s*=\s*false", "AiDAStandalone integration cannot be false")
    forbid(evaluation_path, r'kTaskflowEvaluationStatus\s*=\s*"[^"]*pend' r'ing[^"]*"', "no old incomplete evaluation status")
    forbid(evaluation_path, r"TASKFLOW-INTEGRATION-" r"PART" r"IAL", "no old incomplete integration log")

    allowed_taskflow_relpaths = {
        os.path.join("src", "standalone", "src", "core", "infra", "taskflow_runtime.hpp"),
        os.path.join("src", "standalone", "src", "core", "infra", "taskflow_evaluation.hpp"),
    }
    forbid_outside(STANDALONE_ROOT, r"#include\s*[<\"]taskflow/", "direct Taskflow includes outside runtime/evaluation", allowed_taskflow_relpaths)
    forbid_outside(STANDALONE_ROOT, r"\btf::Executor\b", "raw tf::Executor outside runtime/evaluation", allowed_taskflow_relpaths)
    forbid_outside(STANDALONE_ROOT, r"\btf::Taskflow\b", "raw tf::Taskflow outside runtime/evaluation", allowed_taskflow_relpaths)
    forbid_outside(STANDALONE_ROOT, r"\.silent_async\s*\(", "raw silent_async outside runtime/evaluation", allowed_taskflow_relpaths)

    require(main_cpp, r"kAidaQueuedPeekFlags[\s\S]*PM_QS_SENDMESSAGE", "message pump queued flags include PM_QS_SENDMESSAGE")
    require(main_cpp, r"kAidaSendOnlyPeekFlags\s*=\s*PM_REMOVE\s*\|\s*PM_QS_SENDMESSAGE", "message pump send-only flags drain send messages")
    require(main_cpp, r"GetQueueStatus\s*\(\s*QS_ALLINPUT\s*\)[\s\S]{0,1000}PeekMessage\s*\([^;]+kAidaSendOnlyPeekFlags", "send-only messages are drained")
    require(main_cpp, r"const\s+UINT\s+peek_flags\s*=\s*kAidaQueuedPeekFlags[\s\S]{0,400}PeekMessage\s*\(", "empty queue path still performs nonblocking PeekMessage probe")

    forbid(executor_path, r"\bconcept\b\s+|\branges::|\bco_await\b|\bco_yield\b|\bco_return\b|\bimport\s+|\bconsteval\b|\bconstinit\b|<=>", "no C++20 features in executor")
    forbid(runtime_path, r"\bconcept\b\s+|\branges::|\bco_await\b|\bco_yield\b|\bco_return\b|\bimport\s+|\bconsteval\b|\bconstinit\b|<=>", "no C++20 features in runtime")

    print()
    print("=" * 76)
    print(f"PASSED:   {len(passed)}")
    print(f"WARNINGS: {len(warnings)}")
    print(f"ERRORS:   {len(errors)}")
    print("=" * 76)
    if errors:
        print()
        print("ERRORS:")
        for item in errors:
            print(f"  - {item}")
    if warnings:
        print()
        print("WARNINGS:")
        for item in warnings:
            print(f"  - {item}")
    if errors:
        sys.exit(1)
    print()
    print("Phase 9 Taskflow v3.11 static source verification: PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
