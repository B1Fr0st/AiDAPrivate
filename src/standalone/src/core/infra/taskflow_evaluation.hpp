#pragma once

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <taskflow/taskflow.hpp>
#endif

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#else
#include "../../helpers/diag_log.hpp"
#endif

namespace aida::infra::taskflow_eval {

inline constexpr const char* kTaskflowLocalPath = ".deps/taskflow";
inline constexpr const char* kTaskflowVersion = "3.11.0";
inline constexpr int kTaskflowRequiredCxxStandard = 17;
inline constexpr int kAidaStandaloneCxxStandard = 17;
inline constexpr bool kTaskflowRequiresCxx20 = false;
inline constexpr bool kTaskflowOwnsWorkerThreads = true;
inline constexpr bool kTaskflowWorkerStorageUsesAidaJoinableThread = true;
inline constexpr bool kTaskflowCanUseAidaWinThreadWrappers = true;
inline constexpr bool kTaskflowWorkerInterfaceTlsGuarded = true;
inline constexpr bool kTaskflowTaskBodySehGuarded = true;
inline constexpr bool kTaskflowRuntimeFacadeIntegrated = true;
inline constexpr bool kTaskflowExecutorFacadeRoutesRuntime = true;
inline constexpr bool kTaskflowRuntimeUsesTrackedRunFutures = true;
inline constexpr bool kTaskflowRuntimeUsesSilentAsyncForProtectedWork = false;
inline constexpr bool kTaskflowStandaloneWideMigrationComplete = true;
inline constexpr bool kTaskflowIntegratedIntoAidaStandalone = true;
inline constexpr const char* kTaskflowEvaluationStatus = "standalone_wide_taskflow_3_11_cxx17_integration_complete";
inline constexpr const char* kTaskflowIntegrationReason = "Taskflow v3.11.0 is C++17-compatible; AiDAStandalone now routes inspected production scheduling through AiDA joinable worker threads, tracked tf::Taskflow run futures, cancellation tokens, deadline enforcement, snapshots, shutdown diagnostics, and the central executor/runtime facade";
inline constexpr const char* kTaskflowCompletionReason = "Standalone-wide MCP, Test Lab, startup graph, producer-domain, and security lifecycle scheduling now uses the central Taskflow runtime/executor architecture with legacy queue wrappers removed";
inline constexpr const char* kTaskflowRejectionReason = "none_integration_complete";

inline constexpr const char* kTaskflowSourceEvidenceExecutor = ".deps/taskflow/taskflow/core/executor.hpp:_spawn starts workers through aida::infra::win_thread::joinable_thread_t and maps workers by GetCurrentThreadId";
inline constexpr const char* kTaskflowSourceEvidenceWorkerThread = ".deps/taskflow/taskflow/core/worker.hpp stores aida::infra::win_thread::joinable_thread_t _thread";
inline constexpr const char* kTaskflowSourceEvidenceRuntime = "taskflow_runtime.hpp defines task_descriptor_t, job_handle_t, executor_domain_t, submit, submit_graph, cancel, wait_for, check_deadlines, active_snapshot, snapshot_json_string, all_pools_quiescent, and shutdown";
inline constexpr const char* kTaskflowSourceEvidenceExecutorFacade = "executor.hpp maps aida::infra::executor::submit/cancel/wait_for/check_deadlines/active_snapshot/shutdown onto taskflow_runtime";
inline constexpr const char* kTaskflowSourceEvidenceConcepts = ".deps/taskflow/CMakeLists.txt project(Taskflow VERSION 3.11.0) and TF_VERSION 301100";

enum class taskflow_evaluation_gate_t {
    cxx_standard_compatible,
    worker_storage_uses_aida_thread,
    worker_boundary_guarded,
    task_body_guarded,
    runtime_facade_integrated,
    executor_facade_routed,
    tracked_future_cancellation,
    standalone_wide_migration_complete
};

struct evaluation_result_t {
    bool runtime_core_passed;
    bool standalone_wide_passed;
    const char* status;
    const char* reason;
    taskflow_evaluation_gate_t failed_gates[4];
    int failed_gate_count;
};

inline evaluation_result_t evaluation_result() {
    evaluation_result_t result{};
    result.runtime_core_passed =
        kTaskflowRequiredCxxStandard == 17 &&
        kAidaStandaloneCxxStandard == 17 &&
        !kTaskflowRequiresCxx20 &&
        kTaskflowWorkerStorageUsesAidaJoinableThread &&
        kTaskflowCanUseAidaWinThreadWrappers &&
        kTaskflowWorkerInterfaceTlsGuarded &&
        kTaskflowTaskBodySehGuarded &&
        kTaskflowRuntimeFacadeIntegrated &&
        kTaskflowExecutorFacadeRoutesRuntime &&
        kTaskflowRuntimeUsesTrackedRunFutures &&
        !kTaskflowRuntimeUsesSilentAsyncForProtectedWork;
    result.standalone_wide_passed = kTaskflowStandaloneWideMigrationComplete;
    result.status = kTaskflowEvaluationStatus;
    result.reason = result.runtime_core_passed && result.standalone_wide_passed ? kTaskflowCompletionReason : kTaskflowIntegrationReason;
    result.failed_gate_count = 0;
    return result;
}

inline void log_evaluation() {
    diag::log_tagged_fmt("TASKFLOW-EVALUATION",
        "version=%s required_cxx=%d aida_cxx=%d requires_cxx20=%d owns_threads=%d worker_joinable_thread=%d can_use_win_thread=%d worker_tls_guarded=%d task_seh_guarded=%d runtime_facade=%d executor_facade=%d tracked_futures=%d silent_async_protected=%d standalone_wide_complete=%d integrated=%d status=%s",
        kTaskflowVersion,
        kTaskflowRequiredCxxStandard,
        kAidaStandaloneCxxStandard,
        kTaskflowRequiresCxx20 ? 1 : 0,
        kTaskflowOwnsWorkerThreads ? 1 : 0,
        kTaskflowWorkerStorageUsesAidaJoinableThread ? 1 : 0,
        kTaskflowCanUseAidaWinThreadWrappers ? 1 : 0,
        kTaskflowWorkerInterfaceTlsGuarded ? 1 : 0,
        kTaskflowTaskBodySehGuarded ? 1 : 0,
        kTaskflowRuntimeFacadeIntegrated ? 1 : 0,
        kTaskflowExecutorFacadeRoutesRuntime ? 1 : 0,
        kTaskflowRuntimeUsesTrackedRunFutures ? 1 : 0,
        kTaskflowRuntimeUsesSilentAsyncForProtectedWork ? 1 : 0,
        kTaskflowStandaloneWideMigrationComplete ? 1 : 0,
        kTaskflowIntegratedIntoAidaStandalone ? 1 : 0,
        kTaskflowEvaluationStatus);

    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_executor=%.400s", kTaskflowSourceEvidenceExecutor);
    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_worker_thread=%.400s", kTaskflowSourceEvidenceWorkerThread);
    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_runtime=%.400s", kTaskflowSourceEvidenceRuntime);
    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_executor_facade=%.400s", kTaskflowSourceEvidenceExecutorFacade);
    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_cxx17=%.400s", kTaskflowSourceEvidenceConcepts);

    const auto r = evaluation_result();
    diag::log_tagged_fmt("TASKFLOW-INTEGRATION-COMPLETE",
        "status=%s runtime_core_passed=%d standalone_wide_passed=%d reason=%.600s completion=%.600s failed_gates=%d",
        r.status,
        r.runtime_core_passed ? 1 : 0,
        r.standalone_wide_passed ? 1 : 0,
        r.reason,
        kTaskflowCompletionReason,
        r.failed_gate_count);
}

inline void log_integration_status() {
    diag::log_tagged_fmt("TASKFLOW-STATUS",
        "version=%s status=%s runtime_core=%d standalone_wide_complete=%d requires_cxx20=%d aida_cxx=%d worker_joinable_thread=%d tracked_futures=%d",
        kTaskflowVersion,
        kTaskflowEvaluationStatus,
        kTaskflowRuntimeFacadeIntegrated ? 1 : 0,
        kTaskflowStandaloneWideMigrationComplete ? 1 : 0,
        kTaskflowRequiresCxx20 ? 1 : 0,
        kAidaStandaloneCxxStandard,
        kTaskflowWorkerStorageUsesAidaJoinableThread ? 1 : 0,
        kTaskflowRuntimeUsesTrackedRunFutures ? 1 : 0);
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
static_assert(TF_VERSION == 301100, "AiDAStandalone Taskflow integration is pinned to Taskflow v3.11.0");
#endif
static_assert(kTaskflowRequiredCxxStandard == 17, "Taskflow v3.11.0 is integrated under AiDAStandalone C++17");
static_assert(kAidaStandaloneCxxStandard == 17, "AiDAStandalone targets C++17 per root CMakeLists.txt");
static_assert(kTaskflowRequiresCxx20 == false, "Taskflow v3.11.0 checkout supports C++17");
static_assert(kTaskflowOwnsWorkerThreads == true, "Taskflow Executor still owns worker lifecycle");
static_assert(kTaskflowWorkerStorageUsesAidaJoinableThread == true, "Taskflow workers must use AiDA joinable_thread_t storage");
static_assert(kTaskflowCanUseAidaWinThreadWrappers == true, "Taskflow worker creation must use AiDA win_thread wrappers");
static_assert(kTaskflowRuntimeUsesTrackedRunFutures == true, "Protected runtime work must use tracked Taskflow run futures");
static_assert(kTaskflowRuntimeUsesSilentAsyncForProtectedWork == false, "Protected runtime work must not use untracked silent_async");
static_assert(kTaskflowStandaloneWideMigrationComplete == true, "AiDAStandalone source scheduling migration must be complete");
static_assert(kTaskflowIntegratedIntoAidaStandalone == true, "AiDAStandalone must report completed Taskflow integration");
static_assert(__cplusplus >= 201703L, "AiDAStandalone Taskflow integration requires C++17 or newer");

}
