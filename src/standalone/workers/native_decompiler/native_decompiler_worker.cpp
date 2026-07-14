#include "ghidra_native_provider.hpp"

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
    const auto job = runtime::receive_job(startup, std::chrono::seconds(30));
    if (!job)
        return 4;
    if (job->cache_key.provider.provider != startup.provider ||
        job->cache_key.provider.provider_name != provider.provider_name ||
        job->cache_key.provider.provider_version != provider.provider_version ||
        job->cache_key.provider.provider_binary_hash != provider.provider_binary_hash ||
        job->cache_key.provider.worker_build_id != provider.worker_build_id ||
        job->cache_key.provider.worker_build_hash != provider.worker_build_hash) {
        runtime::send_failure(startup, job->job_id,
            decompiler_diagnostic_code_t::worker_integrity_failure,
            "decompiler.isolated_worker.provider_identity");
        return 5;
    }
    if (!runtime::verify_snapshot(startup, *job)) {
        runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::worker_integrity_failure,
            "decompiler.native_worker.snapshot_integrity");
        return 6;
    }
    auto result = ghidra_native_provider::produce(startup, *job);
    if (!result.document) {
        runtime::send_failures(startup, job->job_id, std::move(result.diagnostics));
        return 7;
    }
    if (result.provider_artifacts.empty()) {
        runtime::send_failure(startup, job->job_id,
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.isolated_worker.provider_artifacts");
        return 8;
    }
    const auto send_status = runtime::send_document(startup, job->job_id,
        std::move(result.provider_artifacts), std::move(*result.document),
        std::move(result.printc_evidence));
    if (send_status == runtime::document_send_status_t::sent)
        return 0;
    if (send_status == runtime::document_send_status_t::resource_limit)
        return runtime::send_failure(startup, job->job_id,
            decompiler_diagnostic_code_t::resource_limit,
            "decompiler.isolated_worker.result_frame_limit") ? 9 : 10;
    if (send_status == runtime::document_send_status_t::invalid_contract)
        return runtime::send_failure(startup, job->job_id,
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.isolated_worker.result_contract") ? 11 : 12;
    return 13;
}
