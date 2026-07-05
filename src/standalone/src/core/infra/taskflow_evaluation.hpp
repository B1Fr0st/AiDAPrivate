#pragma once

#include "../../helpers/diag_log.hpp"

namespace aida::infra::taskflow_eval {

inline constexpr const char* kTaskflowLocalPath = ".deps/taskflow";
inline constexpr const char* kTaskflowVersion = "4.1.0";
inline constexpr int kTaskflowRequiredCxxStandard = 20;
inline constexpr int kAidaStandaloneCxxStandard = 17;
inline constexpr bool kTaskflowRequiresCxx20 = true;
inline constexpr bool kTaskflowOwnsWorkerThreads = true;
inline constexpr bool kTaskflowCanUseAidaWinThreadWrappers = false;
inline constexpr bool kTaskflowIntegratedIntoAidaStandalone = false;
inline constexpr const char* kTaskflowEvaluationStatus = "not_integrated_rejected_by_cxx_standard";
inline constexpr const char* kTaskflowRejectionReason = "Taskflow v4.1.0 requires C++20; AiDAStandalone targets C++17; Taskflow owns internal std::thread workers that bypass AiDA win_thread wrappers; no C++20 migration is permitted for AiDAStandalone";

inline constexpr const char* kTaskflowSourceEvidenceExecutor = "executor.hpp:23 'An tf::Executor manages a set of worker threads to run tasks using an efficient work-stealing scheduling algorithm'";
inline constexpr const char* kTaskflowSourceEvidenceSpawn = "executor.hpp:1295 '_workers[id]._thread = std::thread([&, id, wif] () {' -- Executor::_spawn creates std::thread directly";
inline constexpr const char* kTaskflowSourceEvidenceWorkerThread = "worker.hpp:97 'std::thread _thread;' -- Worker class stores std::thread as value member";
inline constexpr const char* kTaskflowSourceEvidenceConcepts = "serializer.hpp:21 '#include <concepts>' plus 50+ C++20 requires-clauses across async.hpp runtime.hpp executor.hpp task_group.hpp flow_builder.hpp graph.hpp";
inline constexpr const char* kAidaWinThreadEvidence = "win_thread.hpp:237 CreateThread :274 NtCreateThreadEx :341 _beginthreadex with SEH guards TLS init stack reserve control diagnostic logging -- incompatible with Taskflow std::thread value members";

enum class taskflow_evaluation_gate_t {
    cxx_standard_compatible,
    thread_ownership_compatible,
    security_domain_isolated,
    capacity_cancellation_preserved,
    real_dag_use_case_exists,
    static_guards_present
};

struct evaluation_result_t {
    bool passed;
    const char* status;
    const char* reason;
    taskflow_evaluation_gate_t failed_gates[6];
    int failed_gate_count;
};

inline evaluation_result_t evaluation_result() {
    evaluation_result_t result{};
    result.passed = false;
    result.status = kTaskflowEvaluationStatus;
    result.reason = kTaskflowRejectionReason;
    result.failed_gates[0] = taskflow_evaluation_gate_t::cxx_standard_compatible;
    result.failed_gates[1] = taskflow_evaluation_gate_t::thread_ownership_compatible;
    result.failed_gates[2] = taskflow_evaluation_gate_t::security_domain_isolated;
    result.failed_gates[3] = taskflow_evaluation_gate_t::capacity_cancellation_preserved;
    result.failed_gates[4] = taskflow_evaluation_gate_t::real_dag_use_case_exists;
    result.failed_gates[5] = taskflow_evaluation_gate_t::static_guards_present;
    result.failed_gate_count = 6;
    return result;
}

inline void log_evaluation() {
    diag::log_tagged_fmt("TASKFLOW-EVALUATION",
        "version=%s required_cxx=%d aida_cxx=%d requires_cxx20=%d owns_threads=%d can_use_win_thread=%d integrated=%d",
        kTaskflowVersion,
        kTaskflowRequiredCxxStandard,
        kAidaStandaloneCxxStandard,
        kTaskflowRequiresCxx20 ? 1 : 0,
        kTaskflowOwnsWorkerThreads ? 1 : 0,
        kTaskflowCanUseAidaWinThreadWrappers ? 1 : 0,
        kTaskflowIntegratedIntoAidaStandalone ? 1 : 0);

    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_executor=%.400s", kTaskflowSourceEvidenceExecutor);
    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_spawn=%.400s", kTaskflowSourceEvidenceSpawn);
    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_worker_thread=%.400s", kTaskflowSourceEvidenceWorkerThread);
    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_concepts=%.400s", kTaskflowSourceEvidenceConcepts);
    diag::log_tagged_fmt("TASKFLOW-EVALUATION", "evidence_win_thread=%.400s", kAidaWinThreadEvidence);

    const auto r = evaluation_result();
    diag::log_tagged_fmt("TASKFLOW-INTEGRATION-REJECTED",
        "reason=%.600s failed_gates=%d",
        r.reason,
        r.failed_gate_count);

    diag::log_tagged_fmt("TASKFLOW-INTEGRATION-REJECTED",
        "gate_0=cxx_standard_compatible gate_1=thread_ownership_compatible gate_2=security_domain_isolated gate_3=capacity_cancellation_preserved gate_4=real_dag_use_case_exists gate_5=static_guards_present");
}

inline void log_integration_status() {
    diag::log_tagged_fmt("TASKFLOW-STATUS",
        "version=%s status=%s integrated=%d requires_cxx20=%d aida_cxx=%d owns_threads=%d can_use_win_thread=%d",
        kTaskflowVersion,
        kTaskflowEvaluationStatus,
        kTaskflowIntegratedIntoAidaStandalone ? 1 : 0,
        kTaskflowRequiresCxx20 ? 1 : 0,
        kAidaStandaloneCxxStandard,
        kTaskflowOwnsWorkerThreads ? 1 : 0,
        kTaskflowCanUseAidaWinThreadWrappers ? 1 : 0);
}

static_assert(kTaskflowRequiredCxxStandard == 20, "Taskflow v4.1.0 requires C++20 per CMakeLists.txt");
static_assert(kAidaStandaloneCxxStandard == 17, "AiDAStandalone targets C++17 per root CMakeLists.txt");
static_assert(kTaskflowRequiresCxx20 == true, "Taskflow v4.1.0 CMakeLists.txt sets CMAKE_CXX_STANDARD 20");
static_assert(kTaskflowOwnsWorkerThreads == true, "Taskflow Executor::_spawn creates std::thread directly (executor.hpp:1295)");
static_assert(kTaskflowCanUseAidaWinThreadWrappers == false, "Taskflow Worker stores std::thread value member (worker.hpp:97); no hook to inject win_thread wrappers");
static_assert(kTaskflowIntegratedIntoAidaStandalone == false, "Taskflow rejected: C++20 requirement incompatible with C++17 AiDAStandalone");

static_assert(!kTaskflowIntegratedIntoAidaStandalone || !kTaskflowRequiresCxx20 || kAidaStandaloneCxxStandard >= kTaskflowRequiredCxxStandard, "C++20 dependency cannot be integrated into C++17 target");

}
