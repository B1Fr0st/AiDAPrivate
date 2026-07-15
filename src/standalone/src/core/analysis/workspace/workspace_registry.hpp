#pragma once

#include "analysis_workspace.hpp"
#include "live_snapshot_provider.hpp"
#include "pe_baseline_analyzer.hpp"
#include "../readers/pe_coff_reader.hpp"
#include "../../infra/taskflow_runtime.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <functional>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida::analysis {

struct load_profile_t {
    target_kind_t target_kind = target_kind_t::static_file;
    std::vector<std::uint8_t> profile_bytes;
    std::uint64_t max_lease_size = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t read_chunk_size = 4ULL * 1024ULL * 1024ULL;
    pe_parser_profile_t parser_profile;
    pe_parser_profile_t analyzer_parser_profile;
    std::string analysis_settings_json;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    endian_t endian = endian_t::little;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    pe_artifact_kind_t artifact_kind = pe_artifact_kind_t::executable;
};

struct open_static_workspace_request_t {
    std::string source_path;
    std::string bin_name;
    std::optional<std::string> member_path;
    std::vector<std::uint8_t> load_profile;
    mapped_file_provider_options_t provider_options;
    pe_parse_limits_t pe_limits;
    baseline_analysis_settings_t analysis_settings;
};

struct open_provider_workspace_request_t {
    std::shared_ptr<const byte_provider_t> provider;
    std::string bin_name;
    std::optional<provider_member_metadata_t> member_metadata;
    std::vector<std::uint8_t> load_profile;
    mapped_file_provider_options_t provider_options;
    pe_parse_limits_t pe_limits;
    baseline_analysis_settings_t analysis_settings;
};

struct open_live_workspace_request_t {
    live_snapshot_request_t snapshot;
    std::string bin_name;
    std::vector<std::uint8_t> capture_profile;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    std::uint64_t image_base = 0;
};

struct open_live_function_request_t {
    live_function_snapshot_request_t snapshot;
    std::string bin_name;
};

struct target_resolution_options_t {
    bool allow_unique_substring = false;
    bool require_selector_when_multiple = true;
};

struct workspace_admission_handle_t {
    aida::infra::taskflow_runtime::job_handle_t job;
    std::shared_ptr<cancellation_source_t> cancellation;

    bool valid() const noexcept { return job.valid() && cancellation != nullptr; }
};

class workspace_registry_t final {
public:
    workspace_registry_t() = default;
    workspace_registry_t(const workspace_registry_t&) = delete;
    workspace_registry_t& operator=(const workspace_registry_t&) = delete;

    workspace_result_t<std::shared_ptr<analysis_workspace_t>>
        open_static(const open_static_workspace_request_t& request,
                    const cancellation_token_t& cancel = {});
    workspace_result_t<workspace_admission_handle_t> open_static_async(
        open_static_workspace_request_t request,
        std::function<void(workspace_result_t<std::shared_ptr<analysis_workspace_t>>)> completion,
        std::optional<std::chrono::steady_clock::time_point> deadline = {});
    workspace_result_t<std::shared_ptr<analysis_workspace_t>> admit_verified_provider(
        const open_provider_workspace_request_t& request,
        const cancellation_token_t& cancel = {});
    workspace_result_t<workspace_admission_handle_t> admit_verified_provider_async(
        open_provider_workspace_request_t request,
        std::function<void(workspace_result_t<std::shared_ptr<analysis_workspace_t>>)> completion,
        std::optional<std::chrono::steady_clock::time_point> deadline = {});
    static bool cancel_admission(workspace_admission_handle_t& handle) noexcept;
    workspace_result_t<std::shared_ptr<analysis_workspace_t>>
        open_live(const open_live_workspace_request_t& request,
                  const cancellation_token_t& cancel = {});
    workspace_result_t<std::shared_ptr<analysis_workspace_t>>
        open_live_function(const open_live_function_request_t& request,
                           const cancellation_token_t& cancel = {});

    workspace_result_t<void> close(const binary_id_t& id,
                                   std::chrono::steady_clock::time_point deadline);
    std::shared_ptr<analysis_workspace_t> find_by_binary_id(const binary_id_t& id) const;
    std::vector<std::shared_ptr<analysis_workspace_t>>
        find_by_exact_name_or_path(const std::string& name_or_path) const;
    std::shared_ptr<analysis_workspace_t>
        find_by_pid(std::uint32_t pid,
                    std::optional<std::uint64_t> creation_time_100ns = {}) const;
    std::shared_ptr<const pe_coff_metadata_result_t>
        find_pe_coff_metadata(const binary_id_t& id) const;
    workspace_result_t<std::shared_ptr<analysis_workspace_t>>
        resolve(const target_selector_t& selector,
                const target_resolution_options_t& options = {}) const;
    std::vector<std::shared_ptr<analysis_workspace_t>> list() const;

    workspace_result_t<void> select_for_ui(const binary_id_t& id);
    std::shared_ptr<analysis_workspace_t> selected_for_ui() const;
    std::optional<binary_id_t> selected_binary_id() const;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    void bind_preview_workspace(std::shared_ptr<analysis_workspace_t> workspace);
#endif

private:
    workspace_result_t<std::shared_ptr<analysis_workspace_t>>
        insert_or_get(std::shared_ptr<analysis_workspace_t> workspace,
                      std::shared_ptr<const pe_coff_metadata_result_t> pe_coff_metadata = {});
    workspace_result_t<std::shared_ptr<analysis_workspace_t>> admit_provider_impl(
        const open_provider_workspace_request_t& request,
        const cancellation_token_t& cancel,
        const std::function<workspace_result_t<void>()>& revalidate,
        std::shared_ptr<const workspace_image_t> pre_parsed_image = {});

    mutable std::shared_mutex mutex_;
    std::unordered_map<binary_id_t, std::shared_ptr<analysis_workspace_t>, binary_id_hash_t> workspaces_;
    std::unordered_map<binary_id_t, std::shared_ptr<const pe_coff_metadata_result_t>, binary_id_hash_t>
        pe_coff_metadata_;
    std::optional<binary_id_t> ui_selection_;
};

workspace_registry_t& workspace_registry();

}
