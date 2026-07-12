#include "ghidra_native_provider.hpp"

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
    if (!runtime::verify_snapshot(startup, *job)) {
        runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::worker_integrity_failure,
            "decompiler.native_worker.snapshot_integrity");
        return 5;
    }
    auto result = ghidra_native_provider::produce(startup, *job);
    if (!result.document) {
        runtime::send_failures(startup, job->job_id, std::move(result.diagnostics));
        return 6;
    }
    return runtime::send_document(startup, job->job_id, *result.document) ? 0 : 7;
}
