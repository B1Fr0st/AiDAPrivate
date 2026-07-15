#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../core/workbench/adapters/pseudocode_document.hpp"

#include <map>
#include <memory>
#include <mutex>

namespace aida::analysis {
class analysis_workspace_t;
}

namespace aida::preview {

class synchronous_pseudocode_source_adapter_t final
    : public workbench::pseudocode_document::pseudocode_source_adapter_t {
public:
    explicit synchronous_pseudocode_source_adapter_t(
        std::shared_ptr<analysis::analysis_workspace_t> workspace);

    std::uint64_t current_generation() const noexcept override;
    bool generation_current(std::uint64_t generation) const noexcept override;
    workbench::workbench_error_t resolve_request(
        std::uint64_t function_address,
        analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms,
        workbench::pseudocode_document::pseudocode_request_t& output) const override;
    workbench::workbench_error_t request_decompilation(
        const workbench::pseudocode_document::pseudocode_request_t& request,
        std::uint64_t job_id) override;
    workbench::workbench_error_t cancel_decompilation(
        std::uint64_t job_id) override;
    bool poll_result(std::uint64_t job_id,
                     analysis::decompiler_document_t& output) override;
    bool poll_failure(
        std::uint64_t job_id,
        std::vector<analysis::decompiler_diagnostic_t>& output) override;
    bool job_active(std::uint64_t job_id) const noexcept override;
    analysis::decompiler_profile_budget_t profile_budget(
        analysis::decompiler_profile_id_t profile) const noexcept override;

private:
    std::shared_ptr<analysis::analysis_workspace_t> workspace_;
    mutable std::mutex mutex_;
    std::map<std::uint64_t, analysis::decompiler_document_t> completed_;
};

}

#endif
