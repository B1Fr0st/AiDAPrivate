#include "ghidra_native_provider.hpp"

#include <exception>
#include <new>
#include <utility>

int wmain(int argc, wchar_t** argv)
{
    using namespace aida::analysis;
    using namespace aida::analysis::native_worker;

    runtime::startup_t startup;
    if (!runtime::parse_startup(argc, argv, startup) || !runtime::receive_bootstrap(startup))
        return 2;
    const auto provider = runtime::provider_identity(startup);
    if (provider.provider_binary_hash.empty() || !runtime::send_hello(startup, provider, startup.manifest_hash))
        return 3;
    bool session_snapshot_verified = false;
    sha256_digest_t session_snapshot_hash{};
    bool first_job = true;
    for (;;) {
        const auto outcome = runtime::receive_job_or_shutdown(startup,
            std::chrono::milliseconds(first_job ? 30000 : 60000));
        if (outcome.result != runtime::job_receive_result_t::received || !outcome.job) {
            if (first_job)
                return 4;
            return 0;
        }
        first_job = false;
        const auto& job = *outcome.job;
        if (job.cache_key.provider.provider != startup.provider ||
            job.cache_key.provider.provider_name != provider.provider_name ||
            job.cache_key.provider.provider_version != provider.provider_version ||
            job.cache_key.provider.provider_binary_hash != provider.provider_binary_hash ||
            job.cache_key.provider.worker_build_id != provider.worker_build_id ||
            job.cache_key.provider.worker_build_hash != provider.worker_build_hash) {
            runtime::send_failure(startup, job.job_id,
                decompiler_diagnostic_code_t::worker_integrity_failure,
                "decompiler.isolated_worker.provider_identity");
            return 5;
        }
        if (!session_snapshot_verified || session_snapshot_hash != job.snapshot_hash) {
            if (!runtime::verify_snapshot(startup, job)) {
                runtime::send_failure(startup, job.job_id, decompiler_diagnostic_code_t::worker_integrity_failure,
                    "decompiler.native_worker.snapshot_integrity");
                return 6;
            }
            session_snapshot_verified = true;
            session_snapshot_hash = job.snapshot_hash;
        }
        runtime::cancel_pump_t pump;
        pump.start(startup);
        ghidra_native_provider::result_t result;
        try {
            result = ghidra_native_provider::produce(startup, job, pump.cancel_flag());
        } catch (const std::bad_alloc&) {
            pump.stop();
            runtime::send_failure(startup, job.job_id,
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.isolated_worker.provider_allocation_failed");
            return 7;
        } catch (const std::exception&) {
            pump.stop();
            runtime::send_failure(startup, job.job_id,
                decompiler_diagnostic_code_t::provider_failure,
                "decompiler.isolated_worker.provider_exception");
            return 7;
        } catch (...) {
            pump.stop();
            runtime::send_failure(startup, job.job_id,
                decompiler_diagnostic_code_t::provider_failure,
                "decompiler.isolated_worker.provider_unknown_exception");
            return 7;
        }
        pump.stop();
        if (pump.consumed_cancel()) {
            runtime::send_failure(startup, job.job_id,
                decompiler_diagnostic_code_t::cancelled,
                "decompiler.isolated_worker.job_cancelled");
            continue;
        }
        if (!result.document) {
            bool any_retryable = false;
            for (const auto& diagnostic : result.diagnostics) {
                if (diagnostic.retryable) {
                    any_retryable = true;
                    break;
                }
            }
            runtime::send_failures(startup, job.job_id, std::move(result.diagnostics));
            if (any_retryable)
                return 7;
            continue;
        }
        if (result.provider_artifacts.empty()) {
            runtime::send_failure(startup, job.job_id,
                decompiler_diagnostic_code_t::worker_protocol_failure,
                "decompiler.isolated_worker.provider_artifacts");
            return 8;
        }
        const auto send_status = runtime::send_document(startup, job.job_id,
            std::move(result.provider_artifacts), std::move(*result.document),
            std::move(result.printc_evidence));
        if (send_status == runtime::document_send_status_t::sent)
            continue;
        if (send_status == runtime::document_send_status_t::resource_limit)
            return runtime::send_failure(startup, job.job_id,
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.isolated_worker.result_frame_limit") ? 9 : 10;
        if (send_status == runtime::document_send_status_t::invalid_contract)
            return runtime::send_failure(startup, job.job_id,
                decompiler_diagnostic_code_t::worker_protocol_failure,
                "decompiler.isolated_worker.result_contract") ? 11 : 12;
        return 13;
    }
}
