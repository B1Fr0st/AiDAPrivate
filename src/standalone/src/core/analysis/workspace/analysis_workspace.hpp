#pragma once

#include "byte_provider.hpp"
#include "compact_ir.hpp"
#include "pe_image.hpp"
#include "workspace_identity.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

class workspace_database_t;
class overlay_journal_t;
class decompiler_service_t;
class persistence_queue_t;
class search_index_t;
class analysis_workspace_t;
class workspace_registry_t;
struct workspace_publication_state_t;
struct projection_invalidation_set_t;
struct managed_artifact_publication_t;

class workspace_analysis_run_t final {
public:
    workspace_analysis_run_t() = default;
    ~workspace_analysis_run_t();
    workspace_analysis_run_t(workspace_analysis_run_t&& other) noexcept;
    workspace_analysis_run_t& operator=(workspace_analysis_run_t&& other) noexcept;
    workspace_analysis_run_t(const workspace_analysis_run_t&) = delete;
    workspace_analysis_run_t& operator=(const workspace_analysis_run_t&) = delete;

    explicit operator bool() const noexcept { return workspace_ != nullptr; }
    std::uint64_t generation() const noexcept { return generation_; }
    void release() noexcept;

private:
    workspace_analysis_run_t(std::shared_ptr<analysis_workspace_t> workspace,
                             std::uint64_t generation);

    std::shared_ptr<analysis_workspace_t> workspace_;
    std::uint64_t generation_ = 0;

    friend class analysis_workspace_t;
};

enum class workspace_readiness_t : std::uint8_t {
    created = 0,
    provider_ready = 1,
    parsed = 2,
    analyzing = 3,
    baseline_ready = 4,
    partial = 5,
    failed = 6,
    cancelling = 7,
    closing = 8,
    closed = 9
};

struct workspace_progress_t {
    workspace_readiness_t readiness = workspace_readiness_t::created;
    std::string phase;
    std::uint64_t completed_units = 0;
    std::uint64_t total_units = 0;
    std::uint64_t completed_bytes = 0;
    std::uint64_t total_bytes = 0;
    bool cancellation_requested = false;
    std::optional<workspace_error_t> error;
};

struct analysis_publication_t final {
    analysis_publication_t(std::shared_ptr<const analysis_snapshot_t> snapshot_value,
                           std::shared_ptr<const byte_provider_t> provider_value,
                           std::shared_ptr<search_index_t> search_index_value,
                           workspace_readiness_t readiness_value,
                           std::shared_ptr<const managed_artifact_publication_t>
                               managed_artifacts_value = {}) noexcept
        : snapshot(std::move(snapshot_value)),
          provider(std::move(provider_value)),
          search_index(std::move(search_index_value)),
          managed_artifacts(std::move(managed_artifacts_value)),
          binary_id(snapshot ? snapshot->binary_id : binary_id_t{}),
          load_profile_hash(snapshot ? snapshot->load_profile_hash : sha256_digest_t{}),
          generation(snapshot ? snapshot->generation : 0),
          analysis_revision(snapshot ? snapshot->analysis_revision : 0),
          overlay_revision(snapshot ? snapshot->overlay_revision : 0),
          readiness(readiness_value) {}

    bool coherent_with(const workspace_identity_t& identity) const noexcept;

    const std::shared_ptr<const analysis_snapshot_t> snapshot;
    const std::shared_ptr<const byte_provider_t> provider;
    const std::shared_ptr<search_index_t> search_index;
    const std::shared_ptr<const managed_artifact_publication_t> managed_artifacts;
    const binary_id_t binary_id;
    const sha256_digest_t load_profile_hash;
    const std::uint64_t generation;
    const std::uint64_t analysis_revision;
    const std::uint64_t overlay_revision;
    const workspace_readiness_t readiness;
};

struct workspace_provider_binding_t {
    workspace_provider_binding_t() = default;
    workspace_provider_binding_t(sha256_digest_t content_hash_value,
                                 std::string normalized_source_value,
                                 std::uint64_t provider_size_value)
        : content_hash(content_hash_value),
          normalized_source(std::move(normalized_source_value)),
          provider_size(provider_size_value) {}

    sha256_digest_t content_hash;
    std::string normalized_source;
    std::uint64_t provider_size = 0;

private:
    bool verified = false;
    const byte_provider_t* verified_provider = nullptr;
    byte_provider_identity_t verified_identity;
    sha256_digest_t verified_content_hash;
    std::optional<sha256_digest_t> live_module_generation_hash;

    friend class analysis_workspace_t;
    friend class workspace_registry_t;
};

struct workspace_view_state_t {
    std::optional<address_t> selection;
    std::vector<address_t> navigation_back;
    std::vector<address_t> navigation_forward;
    std::vector<address_t> bookmarks;
    std::uint64_t revision = 0;
};

class workspace_lifecycle_participant_t {
public:
    virtual ~workspace_lifecycle_participant_t() = default;
    virtual void request_cancel() noexcept = 0;
    virtual workspace_result_t<void>
        drain(std::chrono::steady_clock::time_point deadline) = 0;
};

class analysis_workspace_t final : public std::enable_shared_from_this<analysis_workspace_t> {
public:
    static workspace_result_t<std::shared_ptr<analysis_workspace_t>>
        create(std::shared_ptr<const workspace_identity_t> identity,
               std::shared_ptr<const byte_provider_t> provider,
               std::shared_ptr<const pe_image_t> image = {},
               std::optional<workspace_provider_binding_t> binding = {},
               const cancellation_token_t& cancel = {});
    static workspace_result_t<std::shared_ptr<analysis_workspace_t>>
        create_normalized(std::shared_ptr<const workspace_identity_t> identity,
                          std::shared_ptr<const byte_provider_t> provider,
                          std::shared_ptr<const workspace_image_t> image,
                          std::optional<workspace_provider_binding_t> binding = {},
                          const cancellation_token_t& cancel = {});
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static workspace_result_t<std::shared_ptr<analysis_workspace_t>>
        create_preview(std::shared_ptr<const workspace_identity_t> identity,
                       std::shared_ptr<const byte_provider_t> provider,
                       std::shared_ptr<const workspace_image_t> normalized_image,
                       std::shared_ptr<const pe_image_t> image,
                       std::shared_ptr<const analysis_snapshot_t> snapshot);
#endif

    ~analysis_workspace_t();
    analysis_workspace_t(const analysis_workspace_t&) = delete;
    analysis_workspace_t& operator=(const analysis_workspace_t&) = delete;

    const workspace_identity_t& identity() const noexcept { return *identity_; }
    const std::shared_ptr<const workspace_identity_t>& identity_handle() const noexcept { return identity_; }
    const byte_provider_t& provider() const noexcept { return *provider_router_; }
    std::shared_ptr<const byte_provider_t> provider_handle() const noexcept;
    const byte_provider_t& source_provider() const noexcept { return *source_provider_; }
    const std::shared_ptr<const byte_provider_t>& source_provider_handle() const noexcept {
        return source_provider_;
    }
    target_kind_t target_kind() const noexcept { return identity_->target_kind(); }

    workspace_result_t<void> verify_provider_binding() const;

    std::shared_ptr<const pe_image_t> image() const noexcept;
    std::shared_ptr<const workspace_image_t> normalized_image() const noexcept;
    std::shared_ptr<const analysis_publication_t> analysis_publication() const noexcept;
    std::shared_ptr<const analysis_snapshot_t> snapshot() const noexcept;
    workspace_result_t<void> publish_image(std::uint64_t expected_generation,
                                           std::shared_ptr<const pe_image_t> image);
    workspace_result_t<void> publish_normalized_image(
        std::uint64_t expected_generation, std::shared_ptr<const workspace_image_t> image,
        std::shared_ptr<const pe_image_t> pe_adapter = {});
    workspace_result_t<void> publish_snapshot(std::uint64_t expected_generation,
                                              std::shared_ptr<const analysis_snapshot_t> snapshot,
                                              bool require_complete_coverage);
    workspace_result_t<void> publish_analysis_bundle(
        std::uint64_t expected_generation,
        std::uint64_t expected_analysis_revision,
        std::shared_ptr<const analysis_snapshot_t> snapshot,
        std::shared_ptr<search_index_t> search_index,
        bool require_complete_coverage,
        std::function<workspace_result_t<void>()> finalizer = {});
    workspace_result_t<void> publish_managed_artifacts(
        std::uint64_t expected_generation,
        std::uint64_t expected_analysis_revision,
        std::shared_ptr<const managed_artifact_publication_t> managed_artifacts,
        bool advance_empty_analysis_revision);
    workspace_result_t<std::size_t> publish_projected_generation(
        std::uint64_t expected_generation,
        std::uint64_t expected_analysis_revision,
        std::uint64_t target_generation,
        std::uint64_t target_overlay_revision,
        std::shared_ptr<const byte_provider_t> projected_provider,
        const projection_invalidation_set_t& invalidation,
        std::function<workspace_result_t<void>(
            const std::shared_ptr<const analysis_snapshot_t>&,
            const std::shared_ptr<search_index_t>&)> finalizer);

    std::uint64_t generation() const noexcept;
    std::uint64_t analysis_revision() const noexcept;
    std::uint64_t overlay_revision() const noexcept;
    workspace_result_t<workspace_analysis_run_t>
        try_begin_analysis(std::uint64_t expected_generation);
    workspace_result_t<std::uint64_t> begin_new_generation();
    workspace_result_t<std::uint64_t> advance_overlay_revision(std::uint64_t expected_revision);
    workspace_result_t<std::uint64_t> restore_overlay_revision(
        std::uint64_t expected_current, std::uint64_t persisted_revision,
        std::uint64_t persisted_generation,
        std::shared_ptr<const byte_provider_t> projected_provider = {});
    workspace_result_t<void> restore_projected_provider(
        std::uint64_t expected_generation,
        std::uint64_t expected_analysis_revision,
        std::uint64_t expected_overlay_revision,
        std::shared_ptr<const byte_provider_t> projected_provider);

    cancellation_token_t cancellation_token() const;
    void request_cancel() noexcept;
    bool closing() const noexcept { return closing_.load(std::memory_order_acquire); }
    bool closed() const noexcept { return closed_.load(std::memory_order_acquire); }

    workspace_progress_t progress() const;
    workspace_result_t<void> update_progress(std::uint64_t expected_generation,
                                             workspace_progress_t progress);
    workspace_result_t<void> record_analysis_attempt_failure(
        std::uint64_t expected_generation,
        std::uint64_t expected_analysis_revision,
        workspace_error_t error);

    workspace_view_state_t view_state() const;
    workspace_result_t<void> update_view_state(
        const std::function<void(workspace_view_state_t&)>& mutation);

    workspace_result_t<void> register_lifecycle_participant(
        std::shared_ptr<workspace_lifecycle_participant_t> participant);
    workspace_result_t<void> close(std::chrono::steady_clock::time_point deadline);

    workspace_result_t<void> install_database(std::shared_ptr<workspace_database_t> database);
    workspace_result_t<void> install_overlay(std::shared_ptr<overlay_journal_t> overlay);
    workspace_result_t<void> install_decompiler(std::shared_ptr<decompiler_service_t> decompiler);
    workspace_result_t<void> install_persistence_queue(std::shared_ptr<persistence_queue_t> queue);
    workspace_result_t<void> install_search_index(std::shared_ptr<search_index_t> index);
    std::shared_ptr<workspace_database_t> database() const;
    std::shared_ptr<overlay_journal_t> overlay() const;
    std::shared_ptr<decompiler_service_t> decompiler() const;
    std::shared_ptr<persistence_queue_t> persistence_queue() const;
    std::shared_ptr<search_index_t> search_index() const;

    std::shared_mutex& mutation_mutex() noexcept { return mutation_mutex_; }

private:
    analysis_workspace_t(std::shared_ptr<const workspace_identity_t> identity,
                         std::shared_ptr<const byte_provider_t> provider,
                         std::shared_ptr<const workspace_image_t> image,
                         std::shared_ptr<const pe_image_t> pe_adapter);
    static workspace_result_t<std::shared_ptr<analysis_workspace_t>> create_impl(
        std::shared_ptr<const workspace_identity_t> identity,
        std::shared_ptr<const byte_provider_t> provider,
        std::shared_ptr<const workspace_image_t> image,
        std::shared_ptr<const pe_image_t> pe_adapter,
        std::optional<workspace_provider_binding_t> binding,
        const cancellation_token_t& cancel);
    static workspace_result_t<workspace_provider_binding_t> verify_provider_binding(
        const std::shared_ptr<const byte_provider_t>& provider,
        const cancellation_token_t& cancel);
    static workspace_result_t<std::shared_ptr<const workspace_image_t>> bind_normalized_image(
        std::shared_ptr<const workspace_image_t> image,
        const workspace_identity_t& identity,
        const workspace_provider_binding_t& binding);
    workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>
        canonicalize_snapshot(std::shared_ptr<const analysis_snapshot_t> snapshot,
                              const std::shared_ptr<const byte_provider_t>& provider) const;
    void release_analysis_run(std::uint64_t generation) noexcept;

    std::shared_ptr<const workspace_identity_t> identity_;
    std::shared_ptr<const byte_provider_t> source_provider_;
    std::shared_ptr<workspace_publication_state_t> publication_state_;
    std::shared_ptr<const byte_provider_t> provider_router_;
    workspace_provider_binding_t provider_binding_;
    std::atomic<std::uint64_t> active_analysis_generation_{0};
    std::atomic<bool> closing_{false};
    std::atomic<bool> closed_{false};
    std::atomic<bool> publication_finalizer_active_{false};
    mutable std::shared_mutex publication_mutex_;
    mutable std::mutex state_mutex_;
    workspace_progress_t progress_;
    workspace_view_state_t view_state_;
    cancellation_source_t cancellation_;
    std::vector<std::weak_ptr<workspace_lifecycle_participant_t>> lifecycle_participants_;
    std::shared_ptr<workspace_database_t> database_;
    std::shared_ptr<overlay_journal_t> overlay_;
    std::shared_ptr<decompiler_service_t> decompiler_;
    std::shared_ptr<persistence_queue_t> persistence_queue_;
    std::shared_mutex mutation_mutex_;
    std::mutex close_mutex_;
    std::mutex analysis_run_mutex_;
    std::condition_variable analysis_run_cv_;

    friend class workspace_analysis_run_t;
    friend class workspace_registry_t;
};

}
