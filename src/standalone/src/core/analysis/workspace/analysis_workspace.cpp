#include "analysis_workspace.hpp"

#include "../decompiler/managed_entity_binding.hpp"

#include "checked_range.hpp"
#include "live_snapshot_provider.hpp"
#include "search_index.hpp"
#include "../overlay_projection.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida::analysis {
namespace {

workspace_result_t<void> integrity_failure(std::string message) {
    return workspace_result_t<void>::failure(
        make_workspace_error(workspace_error_code_t::integrity_failure,
                             std::move(message), "snapshot_validate"));
}

workspace_error_t workspace_stop_error(const cancellation_token_t& token,
                                       const char* phase) {
    if (token.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "workspace deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "workspace operation was cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_error_t publication_finalizer_conflict(const char* phase) {
    return make_workspace_error(workspace_error_code_t::service_conflict,
                                "analysis publication finalizer is active", phase);
}

template <typename T>
workspace_result_t<void> install_workspace_service(
    std::shared_ptr<T>& destination, std::shared_ptr<T> value,
    bool unavailable, const char* service_name) {
    if (!value)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 std::string(service_name) + " service is null",
                                 "workspace_service"));
    if (unavailable)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_service"));
    if (destination) {
        if (destination.get() == value.get())
            return workspace_result_t<void>::success();
        if (destination.use_count() == 1) {
            destination = std::move(value);
            return workspace_result_t<void>::success();
        }
        auto error = make_workspace_error(workspace_error_code_t::service_conflict,
                                          std::string(service_name) +
                                              " service is already installed",
                                          "workspace_service");
        error.details.emplace_back("service", service_name);
        return workspace_result_t<void>::failure(std::move(error));
    }
    destination = std::move(value);
    return workspace_result_t<void>::success();
}

bool same_address_domain(const address_t& lhs, const address_t& rhs) noexcept {
    return lhs.space == rhs.space && lhs.architecture == rhs.architecture && lhs.mode == rhs.mode;
}

bool valid_address(const address_t& address) noexcept {
    if (address.space > address_space_id_t::live_virtual)
        return false;
    return workspace_architecture_mode_matches(address.architecture, address.mode);
}

bool valid_provenance(fact_provenance_t provenance) noexcept {
    return provenance <= fact_provenance_t::decompiler_feedback;
}

bool valid_workspace_address(const address_t& address,
                             const workspace_identity_t& identity) noexcept {
    if (!valid_address(address) || address.architecture != identity.architecture() ||
        address.mode != identity.architecture_mode())
        return false;
    if (identity.target_kind() == target_kind_t::live_snapshot)
        return address.space == address_space_id_t::live_virtual;
    return address.space == address_space_id_t::file_offset ||
           address.space == address_space_id_t::relative_virtual ||
           address.space == address_space_id_t::virtual_address;
}

bool same_provider_identity(const byte_provider_identity_t& lhs,
                            const byte_provider_identity_t& rhs) noexcept {
    return lhs.normalized_source == rhs.normalized_source &&
           lhs.size == rhs.size &&
           lhs.volume_serial == rhs.volume_serial &&
           lhs.file_id == rhs.file_id &&
           lhs.last_write_time_100ns == rhs.last_write_time_100ns &&
           lhs.immutable_snapshot == rhs.immutable_snapshot &&
           lhs.member == rhs.member;
}

bool same_live_module_source(const module_identity_t& lhs,
                             const module_identity_t& rhs) noexcept {
    return lhs.base == rhs.base && lhs.size == rhs.size &&
           lhs.normalized_name == rhs.normalized_name &&
           lhs.normalized_path == rhs.normalized_path;
}

workspace_result_t<void> validate_complete_coverage(const analysis_snapshot_t& snapshot,
                                                     const cancellation_token_t& cancel) {
    if (!snapshot.normalized_image)
        return integrity_failure("complete coverage requires a normalized image");
    std::uint64_t visited = 0;
    const auto poll = [&]() -> workspace_result_t<void> {
        if ((visited++ & 255U) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(
                workspace_stop_error(cancel, "snapshot_validate"));
        return workspace_result_t<void>::success();
    };
    const auto validate_regions = [&](const auto& regions) -> workspace_result_t<void> {
        for (const auto& region : regions) {
            auto stopped = poll();
            if (!stopped)
                return stopped;
            if ((region.permissions & image_permission_execute) == 0)
                continue;
            const std::uint64_t region_size =
                std::max<std::uint64_t>(region.virtual_size, region.file_size);
            if (region_size == 0)
                continue;
            const std::uint64_t region_start = region.virtual_address;
            std::uint64_t region_end = 0;
            if (!checked_add_u64(region_start, region_size, region_end))
                return integrity_failure("executable image range overflowed");
            std::uint64_t cursor = region_start;
            for (const auto& span : snapshot.coverage) {
                stopped = poll();
                if (!stopped)
                    return stopped;
                if (span.start.space != address_space_id_t::relative_virtual)
                    continue;
                std::uint64_t span_end = 0;
                if (!checked_add_u64(span.start.value, span.size, span_end))
                    return integrity_failure("coverage span overflowed");
                if (span_end <= region_start || span.start.value >= region_end)
                    continue;
                if (span.start.value != cursor || span_end > region_end)
                    return integrity_failure("executable coverage contains a gap or overlap");
                if (span.reason == coverage_reason_t::pending || span.size == 0)
                    return integrity_failure("executable coverage contains pending or empty data");
                cursor = span_end;
            }
            if (cursor != region_end)
                return integrity_failure("executable coverage does not account for the full image range");
        }
        return workspace_result_t<void>::success();
    };
    if (!snapshot.normalized_image->sections.empty())
        return validate_regions(snapshot.normalized_image->sections);
    return validate_regions(snapshot.normalized_image->segments);
}

workspace_result_t<std::shared_ptr<const workspace_image_t>> bind_publication_image(
    std::shared_ptr<const workspace_image_t> image,
    const workspace_identity_t& identity,
    const byte_provider_t& provider,
    const sha256_digest_t& provider_hash,
    const char* phase) {
    if (!image || provider_hash.empty())
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "publication image binding is incomplete", phase));
    auto validation = validate_workspace_image(*image);
    if (!validation)
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            validation.error());
    const auto& provider_identity = provider.identity();
    if (provider_identity.normalized_source.empty() ||
        provider_identity.size != provider.size() ||
        image->format != identity.format() ||
        image->architecture != identity.architecture() ||
        image->architecture_mode != identity.architecture_mode() ||
        image->abi != identity.abi() || image->endian != identity.endian() ||
        image->image_base != identity.image_base() ||
        image->provider_size != provider.size() ||
        image->member != provider_identity.member ||
        (provider_identity.content_sha256 &&
         *provider_identity.content_sha256 != provider_hash)) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "publication image conflicts with its byte provider", phase));
    }
    if (identity.target_kind() == target_kind_t::static_file &&
        ((identity.normalized_member_path().has_value() != image->member.has_value()) ||
         (image->member && image->member->normalized_member_path !=
             *identity.normalized_member_path()))) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "publication image member conflicts with workspace identity",
                                 phase));
    }
    try {
        auto bound = std::make_shared<workspace_image_t>(*image);
        bound->workspace_binary_id = identity.binary_id();
        bound->provider_content_hash = provider_hash;
        bound->provider_source = provider_identity.normalized_source;
        bound->provider_size = provider.size();
        bound->member = provider_identity.member;
        bound->provider_binding_verified = true;
        auto bound_validation = validate_workspace_image(*bound, {}, true);
        if (!bound_validation)
            return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                bound_validation.error());
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::success(
            std::static_pointer_cast<const workspace_image_t>(std::move(bound)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "publication image binding allocation failed", phase));
    }
}

bool snapshot_has_analysis_facts(const analysis_snapshot_t& snapshot) noexcept {
    return !snapshot.instructions.empty() ||
           !snapshot.delay_slot_counts.empty() ||
           !snapshot.operand_facts.empty() ||
           !snapshot.target_facts.empty() || !snapshot.blocks.empty() ||
           !snapshot.function_chunks.empty() ||
           !snapshot.function_block_memberships.empty() ||
           !snapshot.functions.empty() || !snapshot.edges.empty() ||
           !snapshot.call_graph.call_sites.empty() ||
           !snapshot.call_graph.candidates.empty() ||
           !snapshot.call_graph.edges.empty() ||
           !snapshot.call_graph.conflicts.empty() || !snapshot.xrefs.empty() ||
           !snapshot.strings.empty() || !snapshot.symbols.empty() ||
           !snapshot.rich_facts.data_candidates.empty() ||
           !snapshot.rich_facts.data_pointer_facts.empty() ||
           !snapshot.rich_facts.data_conflicts.empty() ||
           !snapshot.rich_facts.type_candidates.empty() ||
           !snapshot.rich_facts.type_references.empty() ||
           !snapshot.rich_facts.metadata_conflicts.empty() ||
           !snapshot.coverage.empty();
}

workspace_result_t<std::uint64_t> executable_byte_count(
    const analysis_snapshot_t& snapshot, const char* phase) {
    if (!snapshot.normalized_image)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "analysis snapshot has no normalized image", phase));
    std::uint64_t executable_bytes = 0;
    const auto count_regions = [&](const auto& regions) {
        for (const auto& region : regions) {
            if ((region.permissions & image_permission_execute) == 0)
                continue;
            const auto extent = std::max<std::uint64_t>(
                region.virtual_size, region.file_size);
            if (!checked_add_u64(executable_bytes, extent, executable_bytes))
                return false;
        }
        return true;
    };
    const bool valid = snapshot.normalized_image->sections.empty()
        ? count_regions(snapshot.normalized_image->segments)
        : count_regions(snapshot.normalized_image->sections);
    if (!valid)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "executable byte count overflowed", phase));
    return workspace_result_t<std::uint64_t>::success(executable_bytes);
}

workspace_readiness_t publication_readiness(
    const analysis_snapshot_t& snapshot) noexcept {
    if (snapshot.baseline_complete)
        return workspace_readiness_t::baseline_ready;
    if (snapshot.analysis_revision != 0)
        return workspace_readiness_t::partial;
    return snapshot.normalized_image
        ? workspace_readiness_t::parsed
        : workspace_readiness_t::provider_ready;
}

workspace_progress_t publication_progress(
    workspace_readiness_t readiness, std::uint64_t executable_bytes) {
    workspace_progress_t progress;
    progress.readiness = readiness;
    progress.phase = readiness == workspace_readiness_t::baseline_ready
        ? "baseline_ready"
        : readiness == workspace_readiness_t::partial
            ? "partial"
            : readiness == workspace_readiness_t::parsed
                ? "parsed"
                : "provider_ready";
    progress.completed_units = 1;
    progress.total_units = 1;
    progress.completed_bytes = executable_bytes;
    progress.total_bytes = executable_bytes;
    return progress;
}

}

struct workspace_publication_state_t final {
    std::shared_ptr<const analysis_publication_t> publication;
};

namespace {

class publication_router_provider_t final : public byte_provider_t {
public:
    publication_router_provider_t(
        std::shared_ptr<workspace_publication_state_t> state,
        std::shared_ptr<const byte_provider_t> source)
        : state_(std::move(state)), source_(std::move(source)),
          identity_(source_->identity()) {
        identity_.immutable_snapshot = false;
        identity_.content_sha256.reset();
    }

    const byte_provider_identity_t& identity() const noexcept override {
        return identity_;
    }

    std::uint64_t size() const noexcept override {
        return source_->size();
    }

    std::uint64_t maximum_contiguous_lease(
        std::uint64_t offset) const noexcept override {
        const auto provider = active_provider();
        return provider ? provider->maximum_contiguous_lease(offset) : 0;
    }

    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size_value,
        const cancellation_token_t& cancel) const override {
        const auto provider = active_provider();
        if (!provider)
            return workspace_result_t<byte_view_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "workspace byte publication is unavailable",
                                     "workspace_provider"));
        return provider->lease(offset, size_value, cancel);
    }

private:
    std::shared_ptr<const byte_provider_t> active_provider() const noexcept {
        const auto publication = std::atomic_load_explicit(
            &state_->publication, std::memory_order_acquire);
        return publication ? publication->provider : nullptr;
    }

    std::shared_ptr<workspace_publication_state_t> state_;
    std::shared_ptr<const byte_provider_t> source_;
    byte_provider_identity_t identity_;
};

}

bool analysis_publication_t::coherent_with(
    const workspace_identity_t& identity) const noexcept {
    if (!snapshot || !provider || binary_id != identity.binary_id() ||
        load_profile_hash != identity.load_profile_hash() ||
        snapshot->binary_id != binary_id ||
        snapshot->load_profile_hash != load_profile_hash ||
        snapshot->generation != generation ||
        snapshot->analysis_revision != analysis_revision ||
        snapshot->overlay_revision != overlay_revision || generation == 0)
        return false;
    const auto& provider_identity = provider->identity();
    if (provider_identity.normalized_source.empty() ||
        provider_identity.size != provider->size())
        return false;
    if (snapshot->normalized_image) {
        const auto& image = *snapshot->normalized_image;
        if (!image.provider_binding_verified ||
            image.workspace_binary_id != identity.binary_id() ||
            image.format != identity.format() ||
            image.architecture != identity.architecture() ||
            image.architecture_mode != identity.architecture_mode() ||
            image.abi != identity.abi() || image.endian != identity.endian() ||
            image.image_base != identity.image_base() ||
            image.provider_size != provider->size() ||
            image.provider_source != provider_identity.normalized_source ||
            image.member != provider_identity.member ||
            (provider_identity.content_sha256
                 ? image.provider_content_hash != *provider_identity.content_sha256
                 : image.provider_content_hash != identity.content_hash()))
            return false;
        if (identity.target_kind() == target_kind_t::static_file &&
            ((identity.normalized_member_path().has_value() != image.member.has_value()) ||
             (image.member && image.member->normalized_member_path !=
                 *identity.normalized_member_path())))
            return false;
        if (snapshot->image &&
            (snapshot->image->format() != image.format ||
             snapshot->image->architecture() != image.architecture ||
             snapshot->image->architecture_mode() != image.architecture_mode ||
             snapshot->image->abi() != image.abi ||
             snapshot->image->endian() != image.endian ||
             snapshot->image->image_base() != image.image_base))
            return false;
    } else if (snapshot->image) {
        return false;
    }
    if (search_index) {
        if (!search_index->matches(snapshot))
            return false;
        if (!search_index->matches(binary_id, load_profile_hash,
                                   generation, analysis_revision, overlay_revision))
            return false;
    }
    if (managed_artifacts &&
        !managed_artifacts->coherent_with(identity, *provider, generation,
                                           analysis_revision, overlay_revision))
        return false;
    if (readiness == workspace_readiness_t::baseline_ready)
        return snapshot->baseline_complete && search_index != nullptr;
    return !snapshot->baseline_complete;
}

namespace {

workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>
rebind_publication_managed_artifacts(
    const std::shared_ptr<const managed_artifact_publication_t>& source,
    const workspace_identity_t& identity,
    const std::shared_ptr<const byte_provider_t>& provider,
    const std::shared_ptr<const pe_image_t>& pe_image,
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision,
    const cancellation_token_t& cancel) {
    if (!source)
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::success(
            nullptr);
    if (!provider)
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                "managed publication provider is unavailable",
                "workspace_managed_rebind"));
    return rebind_managed_artifact_publication(
        *source, identity, *provider, pe_image, generation,
        analysis_revision, overlay_revision, cancel);
}

}

workspace_result_t<workspace_provider_binding_t>
analysis_workspace_t::verify_provider_binding(
    const std::shared_ptr<const byte_provider_t>& provider,
    const cancellation_token_t& cancel) {
    if (!provider)
        return workspace_result_t<workspace_provider_binding_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace provider is null", "workspace_create"));
    const auto identity_before = provider->identity();
    if (identity_before.normalized_source.empty() ||
        identity_before.size != provider->size())
        return workspace_result_t<workspace_provider_binding_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace provider identity is incomplete",
                                 "workspace_create"));
    const auto mapped = std::dynamic_pointer_cast<const mapped_file_provider_t>(provider);
    if (mapped) {
        auto current = mapped->revalidate();
        if (!current)
            return workspace_result_t<workspace_provider_binding_t>::failure(current.error());
    }
    auto content = sha256_provider(*provider, cancel);
    if (!content)
        return workspace_result_t<workspace_provider_binding_t>::failure(content.error());
    if (mapped) {
        auto current = mapped->revalidate();
        if (!current)
            return workspace_result_t<workspace_provider_binding_t>::failure(current.error());
    }
    const auto identity_after = provider->identity();
    if (!same_provider_identity(identity_before, identity_after) ||
        identity_after.size != provider->size())
        return workspace_result_t<workspace_provider_binding_t>::failure(
            make_workspace_error(workspace_error_code_t::file_changed,
                                 "workspace provider identity changed during verification",
                                 "workspace_create"));
    if (const auto live =
            std::dynamic_pointer_cast<const live_snapshot_provider_t>(provider)) {
        if (live->metadata().capture_hash != content.value() ||
            live->metadata().capture_size != provider->size())
            return workspace_result_t<workspace_provider_binding_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "live provider content proof is invalid",
                                     "workspace_create"));
    }
    workspace_provider_binding_t binding(content.value(),
        identity_after.normalized_source, provider->size());
    binding.verified = true;
    binding.verified_provider = provider.get();
    binding.verified_identity = identity_after;
    binding.verified_content_hash = content.value();
    if (const auto live =
            std::dynamic_pointer_cast<const live_snapshot_provider_t>(provider))
        binding.live_module_generation_hash = live->metadata().module.content_hash;
    return workspace_result_t<workspace_provider_binding_t>::success(std::move(binding));
}

workspace_result_t<void> analysis_workspace_t::verify_provider_binding() const {
    if (!provider_binding_.verified)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace provider binding was not verified at creation",
                                 "workspace_verify_binding"));
    const auto& current_identity = source_provider_->identity();
    if (!same_provider_identity(provider_binding_.verified_identity, current_identity))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::file_changed,
                                 "workspace provider identity changed since creation",
                                 "workspace_verify_binding"));
    if (provider_binding_.verified_identity.size != source_provider_->size() ||
        provider_binding_.provider_size != source_provider_->size())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::file_changed,
                                 "workspace provider size changed since creation",
                                 "workspace_verify_binding"));
    if (provider_binding_.normalized_source != current_identity.normalized_source)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::file_changed,
                                 "workspace provider source path changed since creation",
                                 "workspace_verify_binding"));
    if (const auto mapped =
            std::dynamic_pointer_cast<const mapped_file_provider_t>(source_provider_handle())) {
        auto revalidation = mapped->revalidate();
        if (!revalidation)
            return workspace_result_t<void>::failure(revalidation.error());
    }
    if (provider_binding_.content_hash != identity_->content_hash())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace provider content hash does not match its identity",
                                 "workspace_verify_binding"));
    const auto publication = analysis_publication();
    if (!publication || !publication->provider)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication provider is unavailable",
                                 "workspace_verify_binding"));
    if (const auto image = publication->snapshot->normalized_image) {
        const auto& published_identity = publication->provider->identity();
        const auto published_hash = published_identity.content_sha256
            ? *published_identity.content_sha256
            : provider_binding_.content_hash;
        if (!image->provider_binding_verified ||
            image->workspace_binary_id != identity_->binary_id() ||
            image->provider_content_hash != published_hash ||
            image->provider_source != published_identity.normalized_source ||
            image->provider_size != publication->provider->size() ||
            image->member != publication->provider->member_metadata()) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                     "normalized image provider binding is stale",
                                     "workspace_verify_binding"));
        }
    }
    return workspace_result_t<void>::success();
}

workspace_analysis_run_t::workspace_analysis_run_t(
    std::shared_ptr<analysis_workspace_t> workspace, std::uint64_t generation)
    : workspace_(std::move(workspace)), generation_(generation) {}

workspace_analysis_run_t::~workspace_analysis_run_t() {
    release();
}

workspace_analysis_run_t::workspace_analysis_run_t(
    workspace_analysis_run_t&& other) noexcept
    : workspace_(std::move(other.workspace_)), generation_(other.generation_) {
    other.generation_ = 0;
}

workspace_analysis_run_t& workspace_analysis_run_t::operator=(
    workspace_analysis_run_t&& other) noexcept {
    if (this != &other) {
        release();
        workspace_ = std::move(other.workspace_);
        generation_ = other.generation_;
        other.generation_ = 0;
    }
    return *this;
}

void workspace_analysis_run_t::release() noexcept {
    auto workspace = std::move(workspace_);
    const auto generation = generation_;
    generation_ = 0;
    if (workspace)
        workspace->release_analysis_run(generation);
}

workspace_result_t<void> validate_rich_fact_publication(
    const analysis_snapshot_t& snapshot,
    const analysis_rich_fact_publication_t& publication,
    const cancellation_token_t& cancel)
{
    std::uint64_t visits = 0;
    const auto poll = [&]() -> workspace_result_t<void> {
        if ((visits++ & 255U) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(
                workspace_stop_error(cancel, "rich_fact_validate"));
        return workspace_result_t<void>::success();
    };
    const auto address_in_snapshot = [&](const address_t& address,
                                         std::uint64_t size = 1) noexcept {
        if (!valid_address(address))
            return false;
        if (!snapshot.normalized_image)
            return true;
        if (address.space == address_space_id_t::file_offset)
            return workspace_image_span_within(address.value, size,
                snapshot.normalized_image->provider_size);
        return workspace_image_contains(*snapshot.normalized_image, address, size);
    };
    const auto expected_id = [](entity_id_t id, std::uint8_t domain,
                                std::size_t index) noexcept {
        return entity_domain(id) == domain &&
            entity_ordinal(id) == static_cast<std::uint64_t>(index + 1);
    };
    std::unordered_set<entity_id_t> type_ids;
    type_ids.reserve(publication.type_candidates.size());
    for (std::size_t index = 0; index < publication.data_candidates.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& candidate = publication.data_candidates[index];
        if (!expected_id(candidate.id, 8, index) || candidate.size == 0 ||
            candidate.kind > data_candidate_kind_t::in_image_pointer ||
            !address_in_snapshot(candidate.address, candidate.size) ||
            !valid_provenance(candidate.provenance) || candidate.confidence > 100 ||
            (candidate.target && (!address_in_snapshot(*candidate.target) ||
                candidate.target->architecture != candidate.address.architecture ||
                candidate.target->mode != candidate.address.mode)))
            return integrity_failure("published data candidate is invalid");
    }
    for (std::size_t index = 0; index < publication.data_pointer_facts.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& pointer = publication.data_pointer_facts[index];
        if (!expected_id(pointer.id, 12, index) ||
            pointer.candidate_kind > data_candidate_kind_t::in_image_pointer ||
            pointer.encoding > data_pointer_encoding_t::signed_relative_to_next ||
            (pointer.width_bytes != 1 && pointer.width_bytes != 2 &&
             pointer.width_bytes != 4 && pointer.width_bytes != 8) ||
            !address_in_snapshot(pointer.slot, pointer.width_bytes) ||
            !address_in_snapshot(pointer.target) ||
            pointer.slot.architecture != pointer.target.architecture ||
            pointer.slot.mode != pointer.target.mode ||
            !valid_provenance(pointer.provenance) || pointer.confidence > 100)
            return integrity_failure("published data pointer fact is invalid");
    }
    for (std::size_t index = 0; index < publication.data_conflicts.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& conflict = publication.data_conflicts[index];
        if (!expected_id(conflict.id, 13, index) ||
            conflict.kind > data_candidate_kind_t::in_image_pointer ||
            !address_in_snapshot(conflict.address) ||
            !valid_provenance(conflict.selected_provenance) ||
            !valid_provenance(conflict.rejected_provenance) ||
            conflict.selected_confidence > 100 || conflict.rejected_confidence > 100 ||
            conflict.selected_target == conflict.rejected_target ||
            (conflict.selected_target && !address_in_snapshot(*conflict.selected_target)) ||
            (conflict.rejected_target && !address_in_snapshot(*conflict.rejected_target)))
            return integrity_failure("published data conflict is invalid");
    }
    for (std::size_t index = 0; index < publication.type_candidates.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& candidate = publication.type_candidates[index];
        if (!expected_id(candidate.id, 10, index) ||
            candidate.kind > symbol_type_candidate_kind_t::metadata_region ||
            candidate.provenance > metadata_provenance_t::managed_metadata ||
            candidate.confidence > 100 || candidate.display_name.empty() ||
            candidate.source_key.empty() ||
            (!candidate.explicitly_unknown && candidate.canonical_type.empty()) ||
            (candidate.address && !address_in_snapshot(*candidate.address)) ||
            (candidate.related_address &&
                !address_in_snapshot(*candidate.related_address)) ||
            !type_ids.insert(candidate.id).second)
            return integrity_failure("published symbol type candidate is invalid");
    }
    for (std::size_t index = 0; index < publication.type_references.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& reference = publication.type_references[index];
        if (!expected_id(reference.id, 9, index) ||
            reference.kind > type_reference_kind_t::managed_reference ||
            reference.provenance > metadata_provenance_t::managed_metadata ||
            reference.confidence > 100 || reference.source_key.empty() ||
            (!reference.source && !reference.target && reference.source_entity == 0 &&
                reference.target_entity == 0) ||
            (reference.source && !address_in_snapshot(*reference.source)) ||
            (reference.target && !address_in_snapshot(*reference.target)) ||
            (reference.source_entity != 0 &&
                type_ids.find(reference.source_entity) == type_ids.end()) ||
            (reference.target_entity != 0 &&
                type_ids.find(reference.target_entity) == type_ids.end()))
            return integrity_failure("published type reference fact is invalid");
    }
    for (std::size_t index = 0; index < publication.metadata_conflicts.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& conflict = publication.metadata_conflicts[index];
        if (!expected_id(conflict.id, 14, index) ||
            conflict.kind > metadata_conflict_kind_t::related_address ||
            conflict.selected_provenance > metadata_provenance_t::managed_metadata ||
            conflict.rejected_provenance > metadata_provenance_t::managed_metadata ||
            conflict.selected_confidence > 100 || conflict.rejected_confidence > 100 ||
            conflict.identity.empty() ||
            conflict.selected_value == conflict.rejected_value ||
            (conflict.address && !address_in_snapshot(*conflict.address)))
            return integrity_failure("published metadata conflict is invalid");
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_call_graph_publication(
    const analysis_snapshot_t& snapshot,
    const call_graph_publication_t& publication,
    const cancellation_token_t& cancel)
{
    if (publication.nodes.empty() && publication.call_sites.empty() &&
        publication.candidates.empty() && publication.edges.empty() &&
        publication.conflicts.empty()) {
        if (publication.indirect_site_count != 0 ||
            publication.unresolved_site_count != 0 || publication.bounded)
            return integrity_failure("empty call graph publication has nonempty state");
        return workspace_result_t<void>::success();
    }
    std::uint64_t visits = 0;
    const auto poll = [&]() -> workspace_result_t<void> {
        if ((visits++ & 255U) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(
                workspace_stop_error(cancel, "call_graph_validate"));
        return workspace_result_t<void>::success();
    };
    const auto valid_quality = [](const call_graph_quality_t& quality) noexcept {
        return valid_provenance(quality.provenance) && quality.confidence <= 100 &&
            quality.contributor_count != 0;
    };
    const auto expected_id = [](entity_id_t id, std::uint8_t domain,
                                std::size_t index) noexcept {
        return entity_domain(id) == domain &&
            entity_ordinal(id) == static_cast<std::uint64_t>(index + 1);
    };
    std::unordered_map<entity_id_t, const function_record_t*> functions;
    std::unordered_map<entity_id_t, const basic_block_record_t*> blocks;
    std::unordered_map<entity_id_t, std::size_t> instructions;
    std::unordered_map<entity_id_t, std::unordered_set<entity_id_t>> block_functions;
    functions.reserve(snapshot.functions.size());
    blocks.reserve(snapshot.blocks.size());
    instructions.reserve(snapshot.instructions.size());
    block_functions.reserve(snapshot.blocks.size());
    for (const auto& function : snapshot.functions)
        functions.emplace(function.id, &function);
    for (const auto& block : snapshot.blocks) {
        blocks.emplace(block.id, &block);
        block_functions[block.id].insert(block.function_id);
    }
    for (const auto& membership : snapshot.function_block_memberships)
        block_functions[membership.block_id].insert(membership.function_id);
    for (std::size_t index = 0; index < snapshot.instructions.size(); ++index)
        instructions.emplace(snapshot.instructions[index].id, index);
    if (publication.nodes.size() != snapshot.functions.size())
        return integrity_failure("published call graph node catalog is incomplete");
    std::unordered_map<entity_id_t, std::size_t> node_indices;
    node_indices.reserve(publication.nodes.size());
    for (std::size_t index = 0; index < publication.nodes.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& node = publication.nodes[index];
        const auto function = functions.find(node.function_id);
        if (function == functions.end() || node.address != function->second->start ||
            !node_indices.emplace(node.function_id, index).second ||
            (index != 0 && !(publication.nodes[index - 1].address < node.address)))
            return integrity_failure("published call graph node is invalid");
    }
    std::unordered_map<entity_id_t, const recovered_call_site_t*> sites;
    sites.reserve(publication.call_sites.size());
    std::uint64_t expected_candidate = 0;
    std::uint64_t indirect_sites = 0;
    std::uint64_t unresolved_sites = 0;
    for (std::size_t index = 0; index < publication.call_sites.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& site = publication.call_sites[index];
        const auto instruction = instructions.find(site.instruction_id);
        const auto block = blocks.find(site.source_block_id);
        const auto membership = block_functions.find(site.source_block_id);
        std::uint64_t candidate_end = 0;
        if (!expected_id(site.id, 15, index) ||
            functions.find(site.source_function_id) == functions.end() ||
            block == blocks.end() || instruction == instructions.end() ||
            membership == block_functions.end() ||
            membership->second.find(site.source_function_id) == membership->second.end() ||
            snapshot.instructions[instruction->second].address != site.address ||
            instruction->second < block->second->first_instruction ||
            instruction->second >= static_cast<std::uint64_t>(
                block->second->first_instruction) + block->second->instruction_count ||
            site.first_candidate != expected_candidate ||
            !checked_add_u64(site.first_candidate, site.candidate_count, candidate_end) ||
            candidate_end > publication.candidates.size() ||
            site.unresolved != (site.candidate_count == 0) ||
            !sites.emplace(site.id, &site).second)
            return integrity_failure("published call site is invalid");
        expected_candidate = candidate_end;
        if (site.indirect)
            ++indirect_sites;
        if (site.unresolved)
            ++unresolved_sites;
    }
    if (expected_candidate != publication.candidates.size() ||
        indirect_sites != publication.indirect_site_count ||
        unresolved_sites != publication.unresolved_site_count)
        return integrity_failure("published call graph site counters are inconsistent");
    for (std::size_t index = 0; index < publication.candidates.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& candidate = publication.candidates[index];
        const auto site = sites.find(candidate.call_site_id);
        if (!expected_id(candidate.id, 16, index) || site == sites.end() ||
            candidate.kind > indirect_call_candidate_kind_t::decompiler ||
            !valid_address(candidate.target) || !valid_quality(candidate.quality) ||
            candidate.rank >= site->second->candidate_count ||
            index != static_cast<std::size_t>(site->second->first_candidate) +
                candidate.rank ||
            candidate.external_target != !candidate.target_function_id.has_value() ||
            (candidate.target_function_id &&
                (functions.find(*candidate.target_function_id) == functions.end() ||
                 functions[*candidate.target_function_id]->start != candidate.target)))
            return integrity_failure("published call candidate is invalid");
    }
    struct node_counts_t {
        std::uint64_t incoming = 0;
        std::uint64_t outgoing = 0;
        std::uint64_t indirect = 0;
        std::uint64_t unresolved = 0;
    };
    std::unordered_map<entity_id_t, node_counts_t> counts;
    counts.reserve(publication.nodes.size());
    std::unordered_map<entity_id_t, std::uint64_t> edge_counts;
    edge_counts.reserve(publication.call_sites.size());
    for (const auto& site : publication.call_sites) {
        counts[site.source_function_id].unresolved += site.unresolved ? 1 : 0;
        edge_counts.emplace(site.id, 0);
    }
    for (std::size_t index = 0; index < publication.edges.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& edge = publication.edges[index];
        const auto site = sites.find(edge.call_site_id);
        if (!expected_id(edge.id, 17, index) || site == sites.end() ||
            edge.source_function_id != site->second->source_function_id ||
            edge.source_block_id != site->second->source_block_id ||
            edge.call_site != site->second->address ||
            edge.resolution > call_graph_resolution_t::unresolved ||
            !valid_address(edge.call_site) || !valid_address(edge.target) ||
            !valid_quality(edge.quality) ||
            (site->second->unresolved !=
                (edge.resolution == call_graph_resolution_t::unresolved)))
            return integrity_failure("published call graph edge is invalid");
        if (site->second->unresolved) {
            if (edge.candidate_rank != 0 || edge.target.value != 0 ||
                edge.target_function_id || edge.external_target || edge.target_noreturn)
                return integrity_failure("published unresolved call edge is invalid");
        } else {
            std::uint64_t candidate_index = 0;
            if (edge.candidate_rank >= site->second->candidate_count ||
                !checked_add_u64(site->second->first_candidate,
                    edge.candidate_rank, candidate_index) ||
                candidate_index >= publication.candidates.size())
                return integrity_failure("published call edge candidate is invalid");
            const auto& candidate = publication.candidates[
                static_cast<std::size_t>(candidate_index)];
            const auto expected_resolution = site->second->tail_call
                ? call_graph_resolution_t::tail_call
                : (site->second->indirect
                    ? call_graph_resolution_t::indirect_candidate
                    : call_graph_resolution_t::direct);
            const bool quality_matches =
                edge.quality.provenance == candidate.quality.provenance &&
                edge.quality.confidence == candidate.quality.confidence &&
                edge.quality.contributor_count == candidate.quality.contributor_count &&
                edge.quality.conflicted == candidate.quality.conflicted;
            bool expected_noreturn = false;
            if (candidate.target_function_id) {
                const auto target = functions.find(*candidate.target_function_id);
                if (target == functions.end())
                    return integrity_failure("published call edge target is invalid");
                expected_noreturn = target->second->noreturn;
            }
            if (candidate.call_site_id != edge.call_site_id ||
                candidate.rank != edge.candidate_rank ||
                candidate.target != edge.target ||
                candidate.target_function_id != edge.target_function_id ||
                candidate.external_target != edge.external_target ||
                edge.external_target != !edge.target_function_id.has_value() ||
                edge.resolution != expected_resolution || !quality_matches ||
                edge.target_noreturn != expected_noreturn)
                return integrity_failure("published call edge does not match its candidate");
        }
        ++edge_counts[edge.call_site_id];
        auto& source = counts[edge.source_function_id];
        ++source.outgoing;
        if (site->second->indirect)
            ++source.indirect;
        if (edge.target_function_id)
            ++counts[*edge.target_function_id].incoming;
    }
    for (const auto& site : publication.call_sites) {
        const auto expected = site.unresolved ? 1ULL : site.candidate_count;
        if (edge_counts[site.id] != expected)
            return integrity_failure("published call graph edge ranges are inconsistent");
    }
    for (const auto& node : publication.nodes) {
        const auto& actual = counts[node.function_id];
        if (node.incoming_edges != actual.incoming ||
            node.outgoing_edges != actual.outgoing ||
            node.indirect_edges != actual.indirect ||
            node.unresolved_sites != actual.unresolved)
            return integrity_failure("published call graph node counters are inconsistent");
    }
    for (std::size_t index = 0; index < publication.conflicts.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& conflict = publication.conflicts[index];
        if (!expected_id(conflict.id, 18, index) ||
            conflict.kind > call_graph_conflict_kind_t::orphan_candidate ||
            (conflict.kind != call_graph_conflict_kind_t::orphan_candidate &&
                conflict.instruction_id != 0 &&
                instructions.find(conflict.instruction_id) == instructions.end()) ||
            (conflict.source_function_id != 0 &&
                functions.find(conflict.source_function_id) == functions.end()) ||
            (conflict.selected_target_function_id != 0 &&
                functions.find(conflict.selected_target_function_id) == functions.end()) ||
            (conflict.kind != call_graph_conflict_kind_t::orphan_candidate &&
                conflict.kind != call_graph_conflict_kind_t::candidate_identity_mismatch &&
                conflict.competing_target_function_id != 0 &&
                functions.find(conflict.competing_target_function_id) == functions.end()))
            return integrity_failure("published call graph conflict is invalid");
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_analysis_snapshot(const analysis_snapshot_t& snapshot,
                                                     bool require_complete_coverage,
                                                     const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(
            workspace_stop_error(cancel, "snapshot_validate"));
    std::uint64_t validation_visits = 0;
    const auto poll = [&]() -> workspace_result_t<void> {
        if ((validation_visits++ & 255U) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(
                workspace_stop_error(cancel, "snapshot_validate"));
        return workspace_result_t<void>::success();
    };
    const auto validate_sorted = [&](const auto& values, auto less)
        -> workspace_result_t<void> {
        for (std::size_t index = 1; index < values.size(); ++index) {
            auto stopped = poll();
            if (!stopped)
                return stopped;
            if (less(values[index], values[index - 1]))
                return integrity_failure("snapshot fact tables are not in deterministic order");
        }
        return workspace_result_t<void>::success();
    };
    if (snapshot.binary_id.empty() || snapshot.load_profile_hash.empty())
        return integrity_failure("snapshot workspace identity is missing");
    if (snapshot.generation == 0)
        return integrity_failure("snapshot generation is zero");
    if (!snapshot.normalized_image && !snapshot.image)
        return integrity_failure("snapshot image is missing");
    if (snapshot.normalized_image) {
        auto image_validation = validate_workspace_image(*snapshot.normalized_image, {}, false,
                                                         cancel);
        if (!image_validation)
            return image_validation;
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (snapshot.image &&
            (snapshot.image->format() != snapshot.normalized_image->format ||
             snapshot.image->architecture() != snapshot.normalized_image->architecture ||
             snapshot.image->architecture_mode() != snapshot.normalized_image->architecture_mode ||
             snapshot.image->abi() != snapshot.normalized_image->abi ||
             snapshot.image->endian() != snapshot.normalized_image->endian ||
             snapshot.image->image_base() != snapshot.normalized_image->image_base))
            return integrity_failure("snapshot PE adapter conflicts with the normalized image");
    }
    if (require_complete_coverage && !snapshot.baseline_complete)
        return integrity_failure("snapshot is not marked baseline complete");
    const auto address_in_image = [&snapshot](const address_t& address,
                                              std::uint64_t size = 1) noexcept {
        if (!snapshot.normalized_image)
            return true;
        if (address.space == address_space_id_t::file_offset)
            return workspace_image_span_within(address.value, size,
                                               snapshot.normalized_image->provider_size);
        if (address.space == address_space_id_t::relative_virtual ||
            address.space == address_space_id_t::virtual_address ||
            address.space == address_space_id_t::live_virtual)
            return workspace_image_contains(*snapshot.normalized_image, address, size);
        return true;
    };
    for (std::size_t index = 1; index < snapshot.instructions.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!(snapshot.instructions[index - 1].address < snapshot.instructions[index].address))
            return integrity_failure("instructions are not in deterministic unique order");
    }
    if (!snapshot.delay_slot_counts.empty()) {
        if (snapshot.delay_slot_counts.size() != snapshot.instructions.size())
            return integrity_failure("delay-slot column does not align with instructions");
        std::vector<std::uint8_t> claimed_delay_slots(snapshot.instructions.size(), 0);
        constexpr std::uint32_t transfer_mask = flow_branch | flow_call | flow_return |
            flow_interrupt | flow_terminal;
        for (std::size_t index = 0; index < snapshot.instructions.size(); ++index) {
            auto stopped = poll();
            if (!stopped)
                return stopped;
            const auto count = snapshot.delay_slot_counts[index];
            if (count == 0)
                continue;
            if (count > 2 || claimed_delay_slots[index] != 0 ||
                (snapshot.instructions[index].flow_flags & transfer_mask) == 0 ||
                index + count >= snapshot.instructions.size())
                return integrity_failure("delay-slot metadata is malformed");
            auto expected = snapshot.instructions[index].address.value;
            if (!checked_add_u64(expected, snapshot.instructions[index].length, expected))
                return integrity_failure("delay-slot instruction range overflowed");
            for (std::size_t offset = 1; offset <= count; ++offset) {
                const auto slot_index = index + offset;
                const auto& slot = snapshot.instructions[slot_index];
                if (claimed_delay_slots[slot_index] != 0 ||
                    slot.address.value != expected ||
                    !same_address_domain(snapshot.instructions[index].address, slot.address) ||
                    (slot.flow_flags & transfer_mask) != 0)
                    return integrity_failure("delay-slot instruction sequence is malformed");
                claimed_delay_slots[slot_index] = 1;
                if (!checked_add_u64(expected, slot.length, expected))
                    return integrity_failure("delay-slot instruction range overflowed");
            }
        }
    }
    std::uint64_t entity_count = snapshot.instructions.size();
    const std::array<std::uint64_t, 17> additional_counts{{
        snapshot.blocks.size(), snapshot.function_chunks.size(), snapshot.functions.size(), snapshot.edges.size(),
        snapshot.xrefs.size(), snapshot.strings.size(), snapshot.symbols.size(),
        snapshot.call_graph.call_sites.size(), snapshot.call_graph.candidates.size(),
        snapshot.call_graph.edges.size(), snapshot.call_graph.conflicts.size(),
        snapshot.rich_facts.data_candidates.size(),
        snapshot.rich_facts.data_pointer_facts.size(),
        snapshot.rich_facts.data_conflicts.size(), snapshot.rich_facts.type_candidates.size(),
        snapshot.rich_facts.type_references.size(),
        snapshot.rich_facts.metadata_conflicts.size()
    }};
    for (const auto count : additional_counts) {
        if (!checked_add_u64(entity_count, count, entity_count) ||
            entity_count > std::numeric_limits<std::size_t>::max())
            return integrity_failure("snapshot entity count overflowed");
    }
    std::vector<entity_id_t> entity_ids;
    entity_ids.reserve(static_cast<std::size_t>(entity_count));
    std::vector<entity_id_t> graph_entity_ids;
    const std::uint64_t graph_entity_count = snapshot.instructions.size() +
        snapshot.blocks.size() + snapshot.functions.size();
    graph_entity_ids.reserve(static_cast<std::size_t>(graph_entity_count));
    auto append_ids = [&](const auto& values, bool graph_entity) -> workspace_result_t<void> {
        for (const auto& value : values) {
            auto stopped = poll();
            if (!stopped)
                return stopped;
            if (value.id == 0)
                return integrity_failure("snapshot contains a zero or duplicate entity id");
            entity_ids.push_back(value.id);
            if (graph_entity)
                graph_entity_ids.push_back(value.id);
        }
        return workspace_result_t<void>::success();
    };
    auto appended = append_ids(snapshot.instructions, true);
    if (!appended) return appended;
    appended = append_ids(snapshot.blocks, true);
    if (!appended) return appended;
    appended = append_ids(snapshot.function_chunks, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.functions, true);
    if (!appended) return appended;
    appended = append_ids(snapshot.edges, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.xrefs, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.strings, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.symbols, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.call_graph.call_sites, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.call_graph.candidates, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.call_graph.edges, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.call_graph.conflicts, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.rich_facts.data_candidates, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.rich_facts.data_pointer_facts, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.rich_facts.data_conflicts, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.rich_facts.type_candidates, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.rich_facts.type_references, false);
    if (!appended) return appended;
    appended = append_ids(snapshot.rich_facts.metadata_conflicts, false);
    if (!appended) return appended;
    std::sort(entity_ids.begin(), entity_ids.end());
    for (std::size_t index = 1; index < entity_ids.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (entity_ids[index - 1] == entity_ids[index])
            return integrity_failure("snapshot contains a zero or duplicate entity id");
    }
    std::sort(graph_entity_ids.begin(), graph_entity_ids.end());
    std::uint64_t expected_operand_begin = 0;
    std::uint64_t expected_target_begin = 0;
    for (const auto& instruction : snapshot.instructions) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (instruction.length == 0 ||
            !valid_address(instruction.address) ||
            !address_in_image(instruction.address, instruction.length) ||
            instruction.coverage != coverage_reason_t::decoded ||
            !valid_provenance(instruction.provenance) ||
            (instruction.flow_flags & ~(flow_fallthrough | flow_direct |
                  flow_indirect | flow_call | flow_branch | flow_conditional |
                  flow_return | flow_interrupt | flow_terminal |
                  flow_privileged)) != 0 ||
            instruction.confidence > 100)
            return integrity_failure("compact instruction record is invalid");
        const std::uint64_t operand_end = static_cast<std::uint64_t>(instruction.operand_fact_begin) +
                                          instruction.operand_fact_count;
        const std::uint64_t target_end = static_cast<std::uint64_t>(instruction.target_fact_begin) +
                                         instruction.target_fact_count;
        if (instruction.operand_fact_begin != expected_operand_begin ||
            instruction.target_fact_begin != expected_target_begin ||
            operand_end > snapshot.operand_facts.size() ||
            target_end > snapshot.target_facts.size())
            return integrity_failure("instruction fact range exceeds its table");
        for (std::uint64_t index = instruction.operand_fact_begin; index < operand_end; ++index) {
            stopped = poll();
            if (!stopped)
                return stopped;
            const auto& operand = snapshot.operand_facts[static_cast<std::size_t>(index)];
            if (operand.instruction_id != instruction.id ||
                operand.operand_index != index - instruction.operand_fact_begin ||
                (operand.scale != 0 && operand.scale != 1 && operand.scale != 2 &&
                 operand.scale != 4 && operand.scale != 8) ||
                operand.kind > operand_kind_t::pointer)
                return integrity_failure("operand fact belongs to a different instruction");
            if (operand.kind != operand_kind_t::memory &&
                (operand.segment_reg != 0 || operand.base_reg != 0 ||
                 operand.index_reg != 0 || operand.scale != 0 ||
                 operand.displacement != 0))
                return integrity_failure("non-memory operand contains memory-only facts");
        }
        for (std::uint64_t index = instruction.target_fact_begin; index < target_end; ++index) {
            stopped = poll();
            if (!stopped)
                return stopped;
            const auto& target = snapshot.target_facts[static_cast<std::size_t>(index)];
            if (target.instruction_id != instruction.id || !valid_address(target.target) ||
                target.target.architecture != instruction.address.architecture ||
                target.target.mode != instruction.address.mode ||
                target.kind > target_kind_record_t::fallthrough)
                return integrity_failure("target fact belongs to a different instruction");
        }
        expected_operand_begin = operand_end;
        expected_target_begin = target_end;
    }
    if (expected_operand_begin != snapshot.operand_facts.size() ||
        expected_target_begin != snapshot.target_facts.size())
        return integrity_failure("snapshot contains orphan instruction facts");
    auto ordered = validate_sorted(snapshot.blocks, [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.start, lhs.end, lhs.id) < std::tie(rhs.start, rhs.end, rhs.id);
    });
    if (!ordered) return ordered;
    ordered = validate_sorted(snapshot.functions, [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.start, lhs.end, lhs.id) < std::tie(rhs.start, rhs.end, rhs.id);
    });
    if (!ordered) return ordered;
    ordered = validate_sorted(snapshot.edges, [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.source, lhs.target, lhs.kind, lhs.id) <
               std::tie(rhs.source, rhs.target, rhs.kind, rhs.id);
    });
    if (!ordered) return ordered;
    ordered = validate_sorted(snapshot.xrefs, [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.source, lhs.target, lhs.kind, lhs.id) <
               std::tie(rhs.source, rhs.target, rhs.kind, rhs.id);
    });
    if (!ordered) return ordered;
    ordered = validate_sorted(snapshot.strings, [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.address, lhs.id) < std::tie(rhs.address, rhs.id);
    });
    if (!ordered) return ordered;
    ordered = validate_sorted(snapshot.symbols, [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.address, lhs.name, lhs.id) < std::tie(rhs.address, rhs.name, rhs.id);
    });
    if (!ordered) return ordered;
    for (const auto& block : snapshot.blocks) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!same_address_domain(block.start, block.end) ||
            block.start.value >= block.end.value || !valid_address(block.start) ||
            !address_in_image(block.start, block.end.value - block.start.value) ||
            !valid_provenance(block.provenance) || block.confidence > 100 ||
            static_cast<std::uint64_t>(block.first_instruction) + block.instruction_count >
                snapshot.instructions.size())
            return integrity_failure("basic block record is invalid");
        if (block.instruction_count == 0)
            return integrity_failure("basic block has no instructions");
        const auto instruction_end = static_cast<std::uint64_t>(block.first_instruction) +
                                     block.instruction_count;
        std::uint64_t cursor = block.start.value;
        for (std::uint64_t index = block.first_instruction; index < instruction_end; ++index) {
            stopped = poll();
            if (!stopped)
                return stopped;
            const auto& instruction = snapshot.instructions[static_cast<std::size_t>(index)];
            if (!same_address_domain(block.start, instruction.address) ||
                instruction.address.value != cursor ||
                !checked_add_u64(cursor, instruction.length, cursor) ||
                cursor > block.end.value)
                return integrity_failure("basic block instruction range is inconsistent");
            if (!snapshot.delay_slot_counts.empty() &&
                index + snapshot.delay_slot_counts[static_cast<std::size_t>(index)] >=
                    instruction_end)
                return integrity_failure("basic block splits a delay-slot sequence");
        }
        if (cursor != block.end.value)
            return integrity_failure("basic block end does not match its instruction range");
    }
    for (std::size_t index = 1; index < snapshot.blocks.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        const auto& previous = snapshot.blocks[index - 1];
        const auto& current = snapshot.blocks[index];
        if (same_address_domain(previous.end, current.start) &&
            previous.end.value > current.start.value)
            return integrity_failure("basic block records overlap");
    }
    std::unordered_set<entity_id_t> function_ids;
    function_ids.reserve(snapshot.functions.size());
    for (const auto& function : snapshot.functions) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        function_ids.insert(function.id);
    }
    std::unordered_set<entity_id_t> symbol_ids;
    symbol_ids.reserve(snapshot.symbols.size());
    for (const auto& symbol : snapshot.symbols) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        symbol_ids.insert(symbol.id);
    }
    std::uint64_t expected_first_chunk = 0;
    std::uint64_t expected_first_membership = 0;
    for (const auto& function : snapshot.functions) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!same_address_domain(function.start, function.end) ||
            function.start.value >= function.end.value || !valid_address(function.start) ||
            !address_in_image(function.start, function.end.value - function.start.value) ||
            !valid_provenance(function.provenance) || function.confidence > 100 ||
            static_cast<std::uint64_t>(function.first_block) + function.block_count >
                snapshot.blocks.size())
            return integrity_failure("function record is invalid");
        if (function.symbol_id && symbol_ids.find(*function.symbol_id) == symbol_ids.end())
            return integrity_failure("function references an unknown symbol");
        const std::uint64_t block_end = static_cast<std::uint64_t>(function.first_block) +
                                        function.block_count;
        for (std::uint64_t index = function.first_block; index < block_end; ++index) {
            stopped = poll();
            if (!stopped)
                return stopped;
            const auto& block = snapshot.blocks[static_cast<std::size_t>(index)];
            if (block.function_id != function.id ||
                !same_address_domain(function.start, block.start) ||
                block.start.value < function.start.value ||
                block.end.value > function.end.value)
                return integrity_failure("function block range contains a foreign block");
        }
        if (function.chunk_count == 0) {
            if (function.first_chunk != 0 || function.block_membership_count != 0 ||
                function.first_block_membership != 0)
                return integrity_failure("function compact-IR ranges are inconsistent");
            continue;
        }
        const std::uint64_t chunk_end = static_cast<std::uint64_t>(function.first_chunk) +
                                        function.chunk_count;
        const std::uint64_t membership_end =
            static_cast<std::uint64_t>(function.first_block_membership) +
            function.block_membership_count;
        if (function.first_chunk != expected_first_chunk ||
            function.first_block_membership != expected_first_membership ||
            chunk_end > snapshot.function_chunks.size() ||
            membership_end > snapshot.function_block_memberships.size() ||
            function.chunks.size() != function.chunk_count)
            return integrity_failure("function compact-IR ranges are inconsistent");
        const auto& primary_chunk = snapshot.function_chunks[function.first_chunk];
        if (primary_chunk.start != function.start ||
            function.first_block != primary_chunk.first_block ||
            function.block_count != primary_chunk.block_count)
            return integrity_failure("function primary chunk is inconsistent");
        std::uint64_t membership_index = function.first_block_membership;
        const function_chunk_record_t* previous_chunk = nullptr;
        for (std::uint64_t chunk_index = function.first_chunk; chunk_index < chunk_end;
             ++chunk_index) {
            stopped = poll();
            if (!stopped)
                return stopped;
            const auto& chunk = snapshot.function_chunks[static_cast<std::size_t>(chunk_index)];
            if (chunk.id == 0 || chunk.function_id != function.id ||
                !same_address_domain(chunk.start, chunk.end) ||
                !same_address_domain(function.start, chunk.start) ||
                chunk.start.value >= chunk.end.value || !valid_address(chunk.start) ||
                !address_in_image(chunk.start, chunk.end.value - chunk.start.value) ||
                !valid_provenance(chunk.provenance) || chunk.confidence > 100 ||
                chunk.block_count == 0 ||
                static_cast<std::uint64_t>(chunk.first_block) + chunk.block_count >
                    snapshot.blocks.size())
                return integrity_failure("function chunk record is invalid");
            const auto& range = function.chunks[static_cast<std::size_t>(
                chunk_index - function.first_chunk)];
            const auto expected_kind = static_cast<std::uint8_t>(
                (chunk.shared ? function_chunk_shared : function_chunk_none) |
                (chunk.cold ? function_chunk_cold : function_chunk_none));
            if (range.rva_start != chunk.start.value ||
                range.rva_end != chunk.end.value || range.chunk_kind != expected_kind)
                return integrity_failure("function chunk compatibility range is inconsistent");
            if (previous_chunk && previous_chunk->end.value > chunk.start.value)
                return integrity_failure("function chunks are not in deterministic range order");
            std::uint64_t cursor = chunk.start.value;
            bool chunk_has_shared_block = false;
            const std::uint64_t chunk_block_end =
                static_cast<std::uint64_t>(chunk.first_block) + chunk.block_count;
            for (std::uint64_t block_index = chunk.first_block;
                 block_index < chunk_block_end; ++block_index) {
                stopped = poll();
                if (!stopped)
                    return stopped;
                if (membership_index >= membership_end)
                    return integrity_failure("function block membership range is inconsistent");
                const auto& block = snapshot.blocks[static_cast<std::size_t>(block_index)];
                const auto& membership = snapshot.function_block_memberships[
                    static_cast<std::size_t>(membership_index)];
                if (membership.function_id == 0 || membership.chunk_id == 0 ||
                    membership.block_id == 0 || membership.function_id != function.id ||
                    membership.chunk_id != chunk.id || membership.block_id != block.id ||
                    membership.block_index != block_index ||
                    membership.ordinal != membership_index - function.first_block_membership ||
                    membership.shared != (block.function_id != function.id))
                    return integrity_failure("function block membership references are inconsistent");
                if (!same_address_domain(chunk.start, block.start) ||
                    block.start.value != cursor || block.end.value > chunk.end.value ||
                    !checked_add_u64(cursor, block.end.value - block.start.value, cursor))
                    return integrity_failure("function chunk block range is inconsistent");
                chunk_has_shared_block = chunk_has_shared_block || membership.shared;
                ++membership_index;
            }
            if (cursor != chunk.end.value || chunk.shared != chunk_has_shared_block)
                return integrity_failure("function chunk membership state is inconsistent");
            previous_chunk = &chunk;
        }
        if (membership_index != membership_end ||
            snapshot.function_chunks[static_cast<std::size_t>(chunk_end - 1)].end != function.end)
            return integrity_failure("function compact-IR ranges are inconsistent");
        expected_first_chunk = chunk_end;
        expected_first_membership = membership_end;
    }
    if (expected_first_chunk != snapshot.function_chunks.size() ||
        expected_first_membership != snapshot.function_block_memberships.size())
        return integrity_failure("snapshot contains orphan function compact-IR records");
    for (const auto& block : snapshot.blocks) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (function_ids.find(block.function_id) == function_ids.end())
            return integrity_failure("basic block references an unknown function");
    }
    struct function_extent_t {
        address_t start;
        address_t end;
        bool explicit_membership = false;
    };
    std::vector<function_extent_t> function_extents;
    function_extents.reserve(snapshot.function_chunks.size() + snapshot.functions.size());
    for (const auto& function : snapshot.functions) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (function.chunk_count == 0) {
            function_extents.push_back({function.start, function.end, false});
            continue;
        }
        const auto end = static_cast<std::uint64_t>(function.first_chunk) +
            function.chunk_count;
        for (std::uint64_t index = function.first_chunk; index < end; ++index) {
            const auto& chunk = snapshot.function_chunks[static_cast<std::size_t>(index)];
            function_extents.push_back({chunk.start, chunk.end, true});
        }
    }
    std::sort(function_extents.begin(), function_extents.end(),
        [](const function_extent_t& lhs, const function_extent_t& rhs) {
            return std::tie(lhs.start, lhs.end, lhs.explicit_membership) <
                std::tie(rhs.start, rhs.end, rhs.explicit_membership);
        });
    address_t maximum_end;
    address_t maximum_legacy_end;
    bool have_extent = false;
    bool have_legacy_extent = false;
    for (const auto& current : function_extents) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!have_extent || !same_address_domain(maximum_end, current.start)) {
            maximum_end = current.end;
            have_extent = true;
            have_legacy_extent = !current.explicit_membership;
            if (have_legacy_extent)
                maximum_legacy_end = current.end;
            continue;
        }
        const bool overlaps_any = maximum_end.value > current.start.value;
        const bool overlaps_legacy = have_legacy_extent &&
            maximum_legacy_end.value > current.start.value;
        if ((!current.explicit_membership && overlaps_any) ||
            (current.explicit_membership && overlaps_legacy))
            return integrity_failure("function extents overlap without shared-tail ownership");
        if (current.end.value > maximum_end.value)
            maximum_end = current.end;
        if (!current.explicit_membership &&
            (!have_legacy_extent || current.end.value > maximum_legacy_end.value)) {
            maximum_legacy_end = current.end;
            have_legacy_extent = true;
        }
    }
    for (const auto& edge : snapshot.edges) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!valid_address(edge.source) || !valid_address(edge.target) ||
            !same_address_domain(edge.source, edge.target) ||
            edge.kind > edge_kind_t::indirect ||
            !valid_provenance(edge.provenance) || edge.confidence > 100)
            return integrity_failure("edge record is invalid");
        if (!std::binary_search(graph_entity_ids.begin(), graph_entity_ids.end(),
                                edge.source_entity))
            return integrity_failure("edge references an unknown source entity");
        if (edge.target_entity &&
            !std::binary_search(graph_entity_ids.begin(), graph_entity_ids.end(),
                                *edge.target_entity))
            return integrity_failure("edge references an unknown target entity");
    }
    for (const auto& xref : snapshot.xrefs) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!valid_address(xref.source) || !valid_address(xref.target) ||
            xref.kind > xref_kind_t::relocation ||
            !valid_provenance(xref.provenance) || xref.confidence > 100)
            return integrity_failure("xref record is invalid");
    }
    for (const auto& string : snapshot.strings) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!valid_address(string.address) || string.byte_length == 0 ||
            !address_in_image(string.address, string.byte_length) ||
            string.encoding > string_encoding_t::utf16_le ||
            !valid_provenance(string.provenance) || string.confidence > 100)
            return integrity_failure("string record is invalid");
    }
    for (const auto& symbol : snapshot.symbols) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!valid_address(symbol.address) || symbol.name.empty() ||
            !address_in_image(symbol.address) ||
            symbol.kind > symbol_kind_t::metadata ||
            !valid_provenance(symbol.provenance) || symbol.confidence > 100)
            return integrity_failure("symbol record is invalid");
    }
    auto rich_facts = validate_rich_fact_publication(snapshot, snapshot.rich_facts, cancel);
    if (!rich_facts)
        return rich_facts;
    auto call_graph = validate_call_graph_publication(snapshot, snapshot.call_graph, cancel);
    if (!call_graph)
        return call_graph;
    for (const auto& span : snapshot.coverage) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (span.size == 0 || span.reason > coverage_reason_t::pending ||
            !valid_provenance(span.provenance) || span.confidence > 100 ||
            !valid_address(span.start) || !address_in_image(span.start, span.size))
            return integrity_failure("coverage span is invalid");
    }
    ordered = validate_sorted(snapshot.coverage, [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.start, lhs.size, lhs.reason) <
               std::tie(rhs.start, rhs.size, rhs.reason);
    });
    if (!ordered)
        return ordered;
    for (std::size_t index = 1; index < snapshot.coverage.size(); ++index) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (!same_address_domain(snapshot.coverage[index - 1].start,
                                 snapshot.coverage[index].start))
            continue;
        std::uint64_t previous_end = 0;
        if (!checked_add_u64(snapshot.coverage[index - 1].start.value,
                             snapshot.coverage[index - 1].size, previous_end) ||
            previous_end > snapshot.coverage[index].start.value)
            return integrity_failure("coverage spans overlap or overflow");
    }
    if (require_complete_coverage) {
        auto result = validate_complete_coverage(snapshot, cancel);
        if (!result)
            return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> analysis_workspace_t::create(
    std::shared_ptr<const workspace_identity_t> identity,
    std::shared_ptr<const byte_provider_t> provider,
    std::shared_ptr<const pe_image_t> image,
    std::optional<workspace_provider_binding_t> binding,
    const cancellation_token_t& cancel) {
    std::shared_ptr<const workspace_image_t> normalized_image;
    if (image) {
        if (!provider)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "workspace provider is required for PE normalization",
                                     "workspace_create"));
        auto normalized = normalize_pe_image(*image, *provider, cancel);
        if (!normalized)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                normalized.error());
        normalized_image = normalized.take_value();
    }
    return create_impl(std::move(identity), std::move(provider), std::move(normalized_image),
                       std::move(image), std::move(binding), cancel);
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> analysis_workspace_t::create_normalized(
    std::shared_ptr<const workspace_identity_t> identity,
    std::shared_ptr<const byte_provider_t> provider,
    std::shared_ptr<const workspace_image_t> image,
    std::optional<workspace_provider_binding_t> binding,
    const cancellation_token_t& cancel) {
    return create_impl(std::move(identity), std::move(provider), std::move(image), {},
                       std::move(binding), cancel);
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
workspace_result_t<std::shared_ptr<analysis_workspace_t>>
analysis_workspace_t::create_preview(
    std::shared_ptr<const workspace_identity_t> identity,
    std::shared_ptr<const byte_provider_t> provider,
    std::shared_ptr<const workspace_image_t> normalized_image,
    std::shared_ptr<const pe_image_t> image,
    std::shared_ptr<const analysis_snapshot_t> snapshot_value) {
    if (!identity || !provider || !normalized_image || !image || !snapshot_value)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "preview workspace fixture is incomplete",
                                 "workspace_preview"));
    auto workspace = std::shared_ptr<analysis_workspace_t>(new analysis_workspace_t(
        std::move(identity), std::move(provider), std::move(normalized_image),
        std::move(image)));
    workspace->provider_binding_ = workspace_provider_binding_t(
        workspace->identity().content_hash(),
        workspace->source_provider().identity().normalized_source,
        workspace->source_provider().size());
    auto canonical = workspace->canonicalize_snapshot(
        std::move(snapshot_value), workspace->provider_handle());
    if (!canonical)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            canonical.error());
    auto validation = validate_analysis_snapshot(*canonical.value(), false);
    if (!validation)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            validation.error());
    const auto publication = std::make_shared<const analysis_publication_t>(
        canonical.take_value(), workspace->provider_handle(), nullptr,
        workspace_readiness_t::partial);
    std::atomic_store_explicit(&workspace->publication_state_->publication,
                               publication, std::memory_order_release);
    workspace->progress_.readiness = workspace_readiness_t::partial;
    workspace->progress_.phase = "analysis-ready";
    workspace->progress_.completed_units = 7;
    workspace->progress_.total_units = 7;
    workspace->progress_.completed_bytes = workspace->source_provider().size();
    workspace->progress_.total_bytes = workspace->source_provider().size();
    return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::success(
        std::move(workspace));
}
#endif

workspace_result_t<std::shared_ptr<analysis_workspace_t>> analysis_workspace_t::create_impl(
    std::shared_ptr<const workspace_identity_t> identity,
    std::shared_ptr<const byte_provider_t> provider,
    std::shared_ptr<const workspace_image_t> image,
    std::shared_ptr<const pe_image_t> pe_adapter,
    std::optional<workspace_provider_binding_t> binding,
    const cancellation_token_t& cancel) {
    if (!identity || !provider)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace identity and provider are required", "workspace_create"));
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            workspace_stop_error(cancel, "workspace_create"));
    if (identity->target_kind() == target_kind_t::static_file &&
        provider->identity().immutable_snapshot)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "static workspace cannot use a live snapshot provider",
                                 "workspace_create"));
    if (identity->target_kind() == target_kind_t::live_snapshot &&
        !provider->identity().immutable_snapshot)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live workspace requires an immutable snapshot provider",
                                 "workspace_create"));
    if (identity->target_kind() == target_kind_t::live_snapshot &&
        !std::dynamic_pointer_cast<const live_snapshot_provider_t>(provider))
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                  "live workspace provider type is invalid",
                                  "workspace_create"));
    const bool binding_proof_valid = binding && binding->verified &&
        binding->verified_provider == provider.get() &&
        same_provider_identity(binding->verified_identity, provider->identity()) &&
        binding->verified_content_hash == binding->content_hash &&
        binding->verified_identity.normalized_source == binding->normalized_source &&
        binding->verified_identity.size == binding->provider_size;
    if (!binding_proof_valid) {
        auto verified = verify_provider_binding(provider, cancel);
        if (!verified)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                verified.error());
        if (binding && (binding->content_hash != verified.value().content_hash ||
                        binding->provider_size != verified.value().provider_size ||
                        binding->normalized_source != verified.value().normalized_source))
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "supplied workspace provider proof is invalid",
                                     "workspace_create"));
        binding = verified.take_value();
    }
    if (binding->content_hash != identity->content_hash() ||
        binding->provider_size != provider->size() ||
        binding->normalized_source != provider->identity().normalized_source)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace provider binding does not match its identity",
                                 "workspace_create"));
    if (identity->target_kind() == target_kind_t::static_file) {
        const auto member_separator = binding->normalized_source.find("#member:");
        const std::string provider_source = member_separator == std::string::npos
            ? binding->normalized_source
            : binding->normalized_source.substr(0, member_separator);
        if (normalize_target_name(provider_source) !=
            normalize_target_name(identity->normalized_source_path())) {
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "workspace source path does not match its provider",
                                     "workspace_create"));
        }
        const auto& provider_member = provider->member_metadata();
        if ((identity->normalized_member_path().has_value() != provider_member.has_value()) ||
            (provider_member && provider_member->normalized_member_path !=
                *identity->normalized_member_path())) {
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                     "workspace member identity does not match its provider",
                                     "workspace_create"));
        }
    }
    if (identity->target_kind() == target_kind_t::live_snapshot) {
        const auto live = std::dynamic_pointer_cast<const live_snapshot_provider_t>(provider);
        const auto& metadata = live->metadata();
        const auto expected_provider_source = "live://" +
            std::to_string(metadata.process.pid) + "/" +
            metadata.module.normalized_name + "@" +
            std::to_string(metadata.capture_address);
        if (!identity->process() || !identity->module() ||
            !(*identity->process() == metadata.process) ||
            !same_live_module_source(*identity->module(), metadata.module) ||
            identity->content_hash() != metadata.capture_hash ||
            identity->image_base() != metadata.module.base ||
            binding->normalized_source != expected_provider_source ||
            !identity->module()->content_hash ||
            !binding->live_module_generation_hash ||
            *identity->module()->content_hash != *binding->live_module_generation_hash)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "live workspace provider and identity proofs disagree",
                                     "workspace_create"));
        if (metadata.module.content_hash &&
            *metadata.module.content_hash != *identity->module()->content_hash)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "live module content proof does not match the capture",
                                     "workspace_create"));
    }
    std::shared_ptr<const workspace_image_t> bound_image;
    if (image) {
        auto bound = bind_normalized_image(std::move(image), *identity, *binding);
        if (!bound)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                bound.error());
        bound_image = bound.take_value();
    }
    if (pe_adapter &&
        (!bound_image || pe_adapter->format() != bound_image->format ||
         pe_adapter->architecture() != bound_image->architecture ||
         pe_adapter->architecture_mode() != bound_image->architecture_mode ||
         pe_adapter->abi() != bound_image->abi || pe_adapter->endian() != bound_image->endian ||
         pe_adapter->image_base() != bound_image->image_base)) {
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace PE adapter conflicts with its normalized image",
                                 "workspace_create"));
    }
    auto workspace_ptr = std::shared_ptr<analysis_workspace_t>(new analysis_workspace_t(
        std::move(identity), std::move(provider), std::move(bound_image),
        std::move(pe_adapter)));
    workspace_ptr->provider_binding_ = std::move(binding.value());
    return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::success(
        std::move(workspace_ptr));
}

workspace_result_t<std::shared_ptr<const workspace_image_t>>
analysis_workspace_t::bind_normalized_image(
    std::shared_ptr<const workspace_image_t> image,
    const workspace_identity_t& identity,
    const workspace_provider_binding_t& binding) {
    if (!image)
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "normalized image is null", "workspace_image_bind"));
    auto validation = validate_workspace_image(*image);
    if (!validation)
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            validation.error());
    if (image->format != identity.format() ||
        image->architecture != identity.architecture() ||
        image->architecture_mode != identity.architecture_mode() ||
        image->abi != identity.abi() || image->endian != identity.endian() ||
        image->image_base != identity.image_base() ||
        image->provider_size != binding.provider_size) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "normalized image conflicts with workspace identity",
                                 "workspace_image_bind"));
    }
    if (identity.target_kind() == target_kind_t::static_file &&
        ((identity.normalized_member_path().has_value() != image->member.has_value()) ||
         (image->member && image->member->normalized_member_path !=
             *identity.normalized_member_path()))) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "normalized image member metadata conflicts with identity",
                                 "workspace_image_bind"));
    }
    if (image->member != binding.verified_identity.member)
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "normalized image member metadata conflicts with its provider",
                                 "workspace_image_bind"));
    if (image->provider_binding_verified &&
        (image->workspace_binary_id != identity.binary_id() ||
         image->provider_content_hash != binding.content_hash ||
         image->provider_source != binding.normalized_source)) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "normalized image has a conflicting provider binding",
                                 "workspace_image_bind"));
    }
    try {
        auto bound = std::make_shared<workspace_image_t>(*image);
        bound->workspace_binary_id = identity.binary_id();
        bound->provider_content_hash = binding.content_hash;
        bound->provider_source = binding.normalized_source;
        bound->provider_size = binding.provider_size;
        bound->provider_binding_verified = true;
        auto bound_validation = validate_workspace_image(*bound, {}, true);
        if (!bound_validation)
            return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                bound_validation.error());
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::success(
            std::static_pointer_cast<const workspace_image_t>(std::move(bound)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "normalized image binding allocation failed",
                                 "workspace_image_bind"));
    }
}

workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>
analysis_workspace_t::canonicalize_snapshot(
    std::shared_ptr<const analysis_snapshot_t> snapshot_value,
    const std::shared_ptr<const byte_provider_t>& provider) const {
    if (!snapshot_value || !provider)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "snapshot or publication provider is null",
                                 "workspace_snapshot_bind"));
    std::shared_ptr<const workspace_image_t> normalized = snapshot_value->normalized_image;
    const auto current = analysis_publication();
    if (current && current->snapshot && current->snapshot->normalized_image &&
        ((normalized && normalized == current->snapshot->normalized_image) ||
         (snapshot_value->image && snapshot_value->image == current->snapshot->image))) {
        if (snapshot_value->normalized_image != current->snapshot->normalized_image)
            snapshot_value->normalized_image = current->snapshot->normalized_image;
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success(
            std::move(snapshot_value));
    }
    if (!normalized && snapshot_value->image) {
        auto converted = normalize_pe_image(
            *snapshot_value->image, *provider, cancellation_.token());
        if (!converted)
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                converted.error());
        normalized = converted.take_value();
    }
    if (!normalized)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "snapshot has no normalized image", "workspace_snapshot_bind"));
    if (!current || !current->snapshot ||
        normalized != current->snapshot->normalized_image) {
        const auto& provider_identity = provider->identity();
        sha256_digest_t provider_hash;
        if (provider_identity.content_sha256) {
            provider_hash = *provider_identity.content_sha256;
        } else if (provider.get() == source_provider_.get()) {
            provider_hash = provider_binding_.content_hash;
        } else {
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                     "publication provider has no content identity",
                                     "workspace_snapshot_bind"));
        }
        auto bound = bind_publication_image(
            std::move(normalized), *identity_, *provider, provider_hash,
            "workspace_snapshot_bind");
        if (!bound)
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(bound.error());
        normalized = bound.take_value();
    }
    if (snapshot_value->normalized_image == normalized)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success(
            std::move(snapshot_value));
    try {
        auto canonical = std::make_shared<analysis_snapshot_t>(*snapshot_value);
        canonical->normalized_image = std::move(normalized);
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success(
            std::static_pointer_cast<const analysis_snapshot_t>(std::move(canonical)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "snapshot normalization allocation failed",
                                 "workspace_snapshot_bind"));
    }
}

analysis_workspace_t::analysis_workspace_t(
    std::shared_ptr<const workspace_identity_t> identity,
    std::shared_ptr<const byte_provider_t> provider,
    std::shared_ptr<const workspace_image_t> image,
    std::shared_ptr<const pe_image_t> pe_adapter)
    : identity_(std::move(identity)), source_provider_(std::move(provider)),
      publication_state_(std::make_shared<workspace_publication_state_t>()),
      provider_router_(std::make_shared<publication_router_provider_t>(
          publication_state_, source_provider_)) {
    auto initial = std::make_shared<analysis_snapshot_t>();
    initial->binary_id = identity_->binary_id();
    initial->load_profile_hash = identity_->load_profile_hash();
    initial->generation = 1;
    initial->analysis_revision = 0;
    initial->overlay_revision = 0;
    initial->baseline_complete = false;
    initial->normalized_image = std::move(image);
    initial->image = std::move(pe_adapter);
    const auto readiness = initial->normalized_image ? workspace_readiness_t::parsed
                                          : workspace_readiness_t::provider_ready;
    publication_state_->publication = std::make_shared<const analysis_publication_t>(
        std::static_pointer_cast<const analysis_snapshot_t>(initial),
        source_provider_, nullptr, readiness);
    progress_.readiness = readiness;
    progress_.phase = initial->normalized_image ? "parsed" : "provider_ready";
    progress_.total_bytes = source_provider_->size();
}

analysis_workspace_t::~analysis_workspace_t() {
    request_cancel();
}

std::shared_ptr<const pe_image_t> analysis_workspace_t::image() const noexcept {
    const auto publication = analysis_publication();
    return publication && publication->snapshot ? publication->snapshot->image : nullptr;
}

std::shared_ptr<const workspace_image_t> analysis_workspace_t::normalized_image() const noexcept {
    const auto publication = analysis_publication();
    return publication && publication->snapshot ? publication->snapshot->normalized_image : nullptr;
}

std::shared_ptr<const analysis_publication_t>
analysis_workspace_t::analysis_publication() const noexcept {
    auto publication = std::atomic_load_explicit(
        &publication_state_->publication, std::memory_order_acquire);
    if (publication && !publication->coherent_with(*identity_))
        return {};
    return publication;
}

std::shared_ptr<const byte_provider_t>
analysis_workspace_t::provider_handle() const noexcept {
    const auto publication = analysis_publication();
    return publication ? publication->provider : nullptr;
}

std::uint64_t analysis_workspace_t::generation() const noexcept {
    const auto publication = analysis_publication();
    return publication ? publication->generation : 0;
}

std::uint64_t analysis_workspace_t::analysis_revision() const noexcept {
    const auto publication = analysis_publication();
    return publication ? publication->analysis_revision : 0;
}

std::uint64_t analysis_workspace_t::overlay_revision() const noexcept {
    const auto publication = analysis_publication();
    return publication ? publication->overlay_revision : 0;
}

std::shared_ptr<const analysis_snapshot_t> analysis_workspace_t::snapshot() const noexcept {
    const auto publication = analysis_publication();
    return publication ? publication->snapshot : nullptr;
}

workspace_result_t<workspace_analysis_run_t>
analysis_workspace_t::try_begin_analysis(std::uint64_t expected_generation) {
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<workspace_analysis_run_t>::failure(
            publication_finalizer_conflict("workspace_analysis"));
    std::shared_lock publication_lock(publication_mutex_);
    if (closing() || closed())
        return workspace_result_t<workspace_analysis_run_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_analysis"));
    if (expected_generation == 0 || generation() != expected_generation)
        return workspace_result_t<workspace_analysis_run_t>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "analysis generation is stale", "workspace_analysis"));
    std::uint64_t inactive = 0;
    if (!active_analysis_generation_.compare_exchange_strong(
            inactive, expected_generation, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        auto error = make_workspace_error(workspace_error_code_t::analysis_in_progress,
                                          "workspace analysis is already in progress",
                                          "workspace_analysis");
        error.details.emplace_back("active_generation", std::to_string(inactive));
        return workspace_result_t<workspace_analysis_run_t>::failure(std::move(error));
    }
    return workspace_result_t<workspace_analysis_run_t>::success(
        workspace_analysis_run_t(shared_from_this(), expected_generation));
}

void analysis_workspace_t::release_analysis_run(std::uint64_t generation_value) noexcept {
    {
        std::lock_guard lock(analysis_run_mutex_);
        std::uint64_t active = generation_value;
        active_analysis_generation_.compare_exchange_strong(
            active, 0, std::memory_order_acq_rel, std::memory_order_acquire);
    }
    analysis_run_cv_.notify_all();
}

workspace_result_t<void> analysis_workspace_t::publish_image(
    std::uint64_t expected_generation, std::shared_ptr<const pe_image_t> image_value) {
    if (!image_value)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "published image is null", "workspace_publish"));
    if (closing() || closed())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_publish"));
    const auto workspace_cancel = cancellation_.token();
    if (workspace_cancel.stop_requested())
        return workspace_result_t<void>::failure(
            workspace_stop_error(workspace_cancel, "workspace_publish"));
    const auto publication_provider = provider_handle();
    if (!publication_provider)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication provider is unavailable",
                                 "workspace_publish"));
    auto normalized = normalize_pe_image(
        *image_value, *publication_provider, cancellation_.token());
    if (!normalized)
        return workspace_result_t<void>::failure(normalized.error());
    return publish_normalized_image(expected_generation, normalized.take_value(),
                                    std::move(image_value));
}

workspace_result_t<void> analysis_workspace_t::publish_normalized_image(
    std::uint64_t expected_generation, std::shared_ptr<const workspace_image_t> image_value,
    std::shared_ptr<const pe_image_t> pe_adapter) {
    if (!image_value)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "published normalized image is null", "workspace_publish"));
    if (closing() || closed())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_publish"));
    const auto workspace_cancel = cancellation_.token();
    if (workspace_cancel.stop_requested())
        return workspace_result_t<void>::failure(
            workspace_stop_error(workspace_cancel, "workspace_publish"));
    const auto publication_provider = provider_handle();
    if (!publication_provider)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication provider is unavailable",
                                 "workspace_publish"));
    const auto& provider_identity = publication_provider->identity();
    sha256_digest_t provider_hash;
    if (provider_identity.content_sha256) {
        provider_hash = *provider_identity.content_sha256;
    } else if (publication_provider.get() == source_provider_.get()) {
        provider_hash = provider_binding_.content_hash;
    } else {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "publication provider has no content identity",
                                 "workspace_publish"));
    }
    auto bound = bind_publication_image(
        std::move(image_value), *identity_, *publication_provider, provider_hash,
        "workspace_publish");
    if (!bound)
        return workspace_result_t<void>::failure(bound.error());
    auto normalized = bound.take_value();
    if (pe_adapter &&
        (pe_adapter->format() != normalized->format ||
         pe_adapter->architecture() != normalized->architecture ||
         pe_adapter->architecture_mode() != normalized->architecture_mode ||
         pe_adapter->abi() != normalized->abi || pe_adapter->endian() != normalized->endian ||
         pe_adapter->image_base() != normalized->image_base)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "published PE adapter conflicts with normalized image",
                                 "workspace_publish"));
    }
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_publish"));
    std::unique_lock lock(publication_mutex_);
    if (closing() || closed())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_publish"));
    if (generation() != expected_generation)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "image publication generation is stale", "workspace_publish"));
    const auto current_publication = analysis_publication();
    if (!current_publication || !current_publication->snapshot ||
        current_publication->provider != publication_provider)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication is missing",
                                 "workspace_publish"));
    const auto current_image = current_publication->snapshot->normalized_image;
    if (pe_adapter && current_publication->snapshot->image == pe_adapter && current_image)
        return workspace_result_t<void>::success();
    if (current_image) {
        if (current_image == normalized &&
            current_publication->snapshot->image == pe_adapter)
            return workspace_result_t<void>::success();
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::service_conflict,
                                 "workspace image is already published",
                                 "workspace_publish"));
    }
    if (analysis_revision() != 0 || current_publication->snapshot->analysis_revision != 0 ||
        current_publication->snapshot->baseline_complete ||
        !current_publication->snapshot->instructions.empty() ||
        current_publication->search_index)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "workspace image cannot change after analysis publication",
                                 "workspace_publish"));
    auto updated = std::make_shared<analysis_snapshot_t>(*current_publication->snapshot);
    updated->normalized_image = std::move(normalized);
    updated->image = std::move(pe_adapter);
    const auto replacement = std::make_shared<const analysis_publication_t>(
        std::static_pointer_cast<const analysis_snapshot_t>(updated),
        current_publication->provider, nullptr, workspace_readiness_t::parsed,
        current_publication->managed_artifacts);
    std::string parsed_phase = "parsed";
    {
        std::lock_guard state_lock(state_mutex_);
        progress_.readiness = workspace_readiness_t::parsed;
        progress_.phase = std::move(parsed_phase);
        std::atomic_store_explicit(&publication_state_->publication, replacement,
                                   std::memory_order_release);
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> analysis_workspace_t::publish_snapshot(
    std::uint64_t expected_generation,
    std::shared_ptr<const analysis_snapshot_t> snapshot_value,
    bool require_complete_coverage) {
    if (!snapshot_value)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "published snapshot is null", "workspace_publish"));
    if (closing() || closed())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_publish"));
    const auto workspace_cancel = cancellation_.token();
    if (workspace_cancel.stop_requested())
        return workspace_result_t<void>::failure(
            workspace_stop_error(workspace_cancel, "workspace_publish"));
    if (snapshot_value->binary_id != identity_->binary_id() ||
        snapshot_value->load_profile_hash != identity_->load_profile_hash())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::substitution_rejected,
                                 "published snapshot belongs to another workspace",
                                 "workspace_publish"));
    const auto publication_provider = provider_handle();
    if (!publication_provider)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication provider is unavailable",
                                 "workspace_publish"));
    auto canonical_snapshot = canonicalize_snapshot(
        snapshot_value, publication_provider);
    if (!canonical_snapshot)
        return workspace_result_t<void>::failure(canonical_snapshot.error());
    snapshot_value = canonical_snapshot.take_value();
    if (target_kind() == target_kind_t::live_snapshot &&
        (require_complete_coverage || snapshot_value->baseline_complete))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::live_target_bulk_analysis_unsupported,
                                 "live targets do not accept baseline analysis publication",
                                 "workspace_publish"));
    if (require_complete_coverage || snapshot_value->baseline_complete)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "baseline snapshots require atomic analysis-bundle publication",
                                 "workspace_publish"));
    auto validation = validate_analysis_snapshot(*snapshot_value, require_complete_coverage,
                                                 workspace_cancel);
    if (!validation)
        return validation;
    const auto source_publication = analysis_publication();
    if (!source_publication || !source_publication->snapshot)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication is unavailable",
                                 "workspace_publish"));
    auto rebound_managed = rebind_publication_managed_artifacts(
        source_publication->managed_artifacts, *identity_, publication_provider,
        snapshot_value->image, snapshot_value->generation,
        snapshot_value->analysis_revision, snapshot_value->overlay_revision,
        workspace_cancel);
    if (!rebound_managed)
        return workspace_result_t<void>::failure(rebound_managed.error());
    const auto replacement = std::make_shared<const analysis_publication_t>(
        snapshot_value, publication_provider, nullptr,
        workspace_readiness_t::partial, rebound_managed.take_value());
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_publish"));
    std::unique_lock lock(publication_mutex_);
    std::string partial_phase = "partial";
    {
        std::lock_guard state_lock(state_mutex_);
        if (closing() || closed())
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::workspace_closing,
                                     "workspace is closing", "workspace_publish"));
        const auto workspace_cancel = cancellation_.token();
        if (workspace_cancel.stop_requested())
            return workspace_result_t<void>::failure(
                workspace_stop_error(workspace_cancel, "workspace_publish"));
        if (generation() != expected_generation ||
            snapshot_value->generation != expected_generation)
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                                     "snapshot publication generation is stale",
                                     "workspace_publish"));
        const std::uint64_t current_revision = analysis_revision();
        if (current_revision == std::numeric_limits<std::uint64_t>::max() ||
            snapshot_value->analysis_revision != current_revision + 1 ||
            snapshot_value->overlay_revision != overlay_revision())
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::revision_conflict,
                                     "snapshot publication revision conflicts with workspace state",
                                     "workspace_publish"));
        const auto current_publication = analysis_publication();
        if (!current_publication || current_publication != source_publication ||
            !current_publication->snapshot ||
            current_publication->provider != publication_provider ||
            snapshot_value->normalized_image !=
                current_publication->snapshot->normalized_image)
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "snapshot image does not match the published image",
                                     "workspace_publish"));
        progress_.readiness = workspace_readiness_t::partial;
        progress_.phase = std::move(partial_phase);
        progress_.error.reset();
        std::atomic_store_explicit(&publication_state_->publication, replacement,
                                   std::memory_order_release);
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> analysis_workspace_t::publish_analysis_bundle(
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::shared_ptr<const analysis_snapshot_t> snapshot_value,
    std::shared_ptr<search_index_t> search_index_value,
    bool require_complete_coverage,
    std::function<workspace_result_t<void>()> finalizer) {
    if (!snapshot_value || !search_index_value)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "analysis bundle requires a snapshot and search index",
                                 "workspace_publish"));
    if (closing() || closed())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_publish"));
    const auto workspace_cancel = cancellation_.token();
    if (workspace_cancel.stop_requested())
        return workspace_result_t<void>::failure(
            workspace_stop_error(workspace_cancel, "workspace_publish"));
    if (snapshot_value->binary_id != identity_->binary_id() ||
        snapshot_value->load_profile_hash != identity_->load_profile_hash())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::substitution_rejected,
                                 "analysis bundle belongs to another workspace",
                                 "workspace_publish"));
    const auto publication_provider = provider_handle();
    if (!publication_provider)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication provider is unavailable",
                                 "workspace_publish"));
    auto canonical_snapshot = canonicalize_snapshot(
        snapshot_value, publication_provider);
    if (!canonical_snapshot)
        return workspace_result_t<void>::failure(canonical_snapshot.error());
    snapshot_value = canonical_snapshot.take_value();
    if (target_kind() == target_kind_t::live_snapshot &&
        (require_complete_coverage || snapshot_value->baseline_complete))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::live_target_bulk_analysis_unsupported,
                                 "live targets do not accept baseline analysis publication",
                                 "workspace_publish"));
    auto validation = validate_analysis_snapshot(*snapshot_value,
                                                 require_complete_coverage,
                                                 workspace_cancel);
    if (!validation)
        return validation;
    if (search_index_value &&
        (!search_index_value->matches(snapshot_value) ||
         !search_index_value->matches(identity_->binary_id(), identity_->load_profile_hash(),
                                      snapshot_value->generation,
                                      snapshot_value->analysis_revision,
                                      snapshot_value->overlay_revision)))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "search index does not match the analysis snapshot",
                                 "workspace_publish"));
    auto executable_bytes = executable_byte_count(
        *snapshot_value, "workspace_publish");
    if (!executable_bytes)
        return workspace_result_t<void>::failure(executable_bytes.error());
    const auto source_publication = analysis_publication();
    if (!source_publication || !source_publication->snapshot)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication is unavailable",
                                 "workspace_publish"));
    auto rebound_managed = rebind_publication_managed_artifacts(
        source_publication->managed_artifacts, *identity_, publication_provider,
        snapshot_value->image, snapshot_value->generation,
        snapshot_value->analysis_revision, snapshot_value->overlay_revision,
        workspace_cancel);
    if (!rebound_managed)
        return workspace_result_t<void>::failure(rebound_managed.error());
    const auto readiness = publication_readiness(*snapshot_value);
    const auto replacement = std::make_shared<const analysis_publication_t>(
        snapshot_value, publication_provider, search_index_value, readiness,
        rebound_managed.take_value());
    auto replacement_progress = publication_progress(
        readiness, executable_bytes.value());
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_publish"));
    std::unique_lock<std::shared_mutex> mutation_lock(mutation_mutex_, std::defer_lock);
    std::unique_lock<std::shared_mutex> publication_lock(publication_mutex_, std::defer_lock);
    std::lock(mutation_lock, publication_lock);
    {
        std::lock_guard state_lock(state_mutex_);
        if (closing() || closed())
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::workspace_closing,
                                     "workspace is closing", "workspace_publish"));
        const auto workspace_cancel = cancellation_.token();
        if (workspace_cancel.stop_requested())
            return workspace_result_t<void>::failure(
                workspace_stop_error(workspace_cancel, "workspace_publish"));
        if (generation() != expected_generation)
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                                     "analysis bundle generation is stale",
                                     "workspace_publish"));
        const auto current_publication = analysis_publication();
        if (!current_publication || current_publication != source_publication ||
            !current_publication->snapshot ||
            current_publication->provider != publication_provider ||
            snapshot_value->normalized_image !=
                current_publication->snapshot->normalized_image)
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "analysis bundle image does not match the workspace",
                                     "workspace_publish"));
        if (analysis_revision() != expected_analysis_revision ||
            expected_analysis_revision ==
                (std::numeric_limits<std::uint64_t>::max)() ||
            snapshot_value->generation != expected_generation ||
            snapshot_value->analysis_revision != expected_analysis_revision + 1 ||
            snapshot_value->overlay_revision != overlay_revision()) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::revision_conflict,
                                     "analysis bundle revision conflicts with workspace state",
                                     "workspace_publish"));
        }
    }
    if (finalizer) {
        publication_finalizer_active_.store(true, std::memory_order_release);
        workspace_result_t<void> finalized = workspace_result_t<void>::success();
        try {
            finalized = finalizer();
        } catch (...) {
            finalized = workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::persistence_failure,
                                     "analysis publication finalizer threw an exception",
                                     "workspace_publish"));
        }
        publication_finalizer_active_.store(false, std::memory_order_release);
        if (!finalized)
            return finalized;
    }
    {
        std::lock_guard state_lock(state_mutex_);
        replacement_progress.cancellation_requested =
            cancellation_.token().stop_requested();
        progress_ = std::move(replacement_progress);
        std::atomic_store_explicit(&publication_state_->publication, replacement,
                                   std::memory_order_release);
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> analysis_workspace_t::publish_managed_artifacts(
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::shared_ptr<const managed_artifact_publication_t> managed_artifacts,
    bool advance_empty_analysis_revision) {
    if (!managed_artifacts || target_kind() != target_kind_t::static_file)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "managed artifact publication requires a static workspace binding",
                "workspace_managed_publish"));
    if (closing() || closed() ||
        publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                "workspace cannot accept managed artifact publication",
                "workspace_managed_publish"));
    const auto source = analysis_publication();
    if (!source || !source->snapshot || !source->provider ||
        source->generation != expected_generation ||
        source->analysis_revision != expected_analysis_revision)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                "workspace changed before managed artifact publication",
                "workspace_managed_publish"));
    const bool advance = advance_empty_analysis_revision &&
        expected_analysis_revision == 0 && !source->search_index &&
        !source->snapshot->baseline_complete &&
        !snapshot_has_analysis_facts(*source->snapshot);
    const auto target_revision = advance ? 1ULL : expected_analysis_revision;
    if (!managed_artifacts->coherent_with(
            *identity_, *source->provider, expected_generation,
            target_revision, source->overlay_revision)) {
        if (!advance || !managed_artifacts->coherent_with(
                *identity_, *source->provider, expected_generation,
                expected_analysis_revision, source->overlay_revision))
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                    "managed artifact publication does not match the workspace",
                    "workspace_managed_publish"));
        auto rebound = rebind_managed_artifact_publication(
            *managed_artifacts, *identity_, *source->provider,
            source->snapshot->image, expected_generation, target_revision,
            source->overlay_revision, cancellation_token());
        if (!rebound)
            return workspace_result_t<void>::failure(rebound.error());
        managed_artifacts = rebound.take_value();
    }
    std::shared_ptr<const analysis_snapshot_t> snapshot_value = source->snapshot;
    workspace_readiness_t readiness = source->readiness;
    try {
        if (advance) {
            auto revised = std::make_shared<analysis_snapshot_t>(*source->snapshot);
            revised->analysis_revision = target_revision;
            revised->baseline_complete = false;
            snapshot_value = std::static_pointer_cast<const analysis_snapshot_t>(
                std::move(revised));
            readiness = workspace_readiness_t::partial;
        }
    } catch (const std::bad_alloc&) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "managed artifact publication allocation failed",
                "workspace_managed_publish"));
    }
    std::shared_ptr<const analysis_publication_t> replacement;
    try {
        replacement = std::make_shared<const analysis_publication_t>(
            snapshot_value, source->provider, source->search_index, readiness,
            std::move(managed_artifacts));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "managed artifact publication allocation failed",
                "workspace_managed_publish"));
    }
    if (!replacement->coherent_with(*identity_))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "managed artifact publication is incoherent",
                "workspace_managed_publish"));
    std::unique_lock<std::shared_mutex> mutation_lock(
        mutation_mutex_, std::defer_lock);
    std::unique_lock<std::shared_mutex> publication_lock(
        publication_mutex_, std::defer_lock);
    std::lock(mutation_lock, publication_lock);
    std::lock_guard state_lock(state_mutex_);
    if (closing() || closed() ||
        active_analysis_generation_.load(std::memory_order_acquire) != 0)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::analysis_in_progress,
                "managed artifact publication conflicts with workspace activity",
                "workspace_managed_publish"));
    if (analysis_publication() != source || generation() != expected_generation ||
        analysis_revision() != expected_analysis_revision)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                "workspace changed during managed artifact publication",
                "workspace_managed_publish"));
    progress_.readiness = readiness;
    progress_.phase = advance ? "managed_metadata_ready" : progress_.phase;
    progress_.error.reset();
    std::atomic_store_explicit(
        &publication_state_->publication, replacement, std::memory_order_release);
    return workspace_result_t<void>::success();
}

namespace {

std::optional<std::uint64_t> projected_rva(
    const workspace_image_t& image, const address_t& address) noexcept {
    if (address.space == address_space_id_t::relative_virtual)
        return address.value;
    if (address.space == address_space_id_t::virtual_address ||
        address.space == address_space_id_t::live_virtual) {
        if (address.value < image.image_base)
            return std::nullopt;
        return address.value - image.image_base;
    }
    if (address.space != address_space_id_t::file_offset)
        return std::nullopt;
    for (const auto& mapping : image.address_mappings) {
        if (mapping.source_space != address_space_id_t::file_offset ||
            mapping.target_space != address_space_id_t::relative_virtual ||
            address.value < mapping.source_start ||
            address.value >= mapping.source_start + mapping.size)
            continue;
        return mapping.target_start + address.value - mapping.source_start;
    }
    return std::nullopt;
}

bool projected_overlap(const workspace_image_t& image,
                       const address_t& address, std::uint64_t size,
                       const std::vector<projected_range_t>& ranges) noexcept {
    const auto start = projected_rva(image, address);
    if (!start || size == 0 ||
        size > (std::numeric_limits<std::uint64_t>::max)() - *start)
        return false;
    const projected_range_t fact_range{*start, size, false,
        overlay_operation_kind_v9_t::reanalysis};
    return std::any_of(ranges.begin(), ranges.end(),
        [&](const auto& range) { return fact_range.overlaps(range); });
}

bool projected_overlap(const workspace_image_t& image,
                       const address_t& begin, const address_t& end,
                       const std::vector<projected_range_t>& ranges) noexcept {
    if (begin.space != end.space || begin.architecture != end.architecture ||
        begin.mode != end.mode || end.value <= begin.value)
        return false;
    return projected_overlap(image, begin, end.value - begin.value, ranges);
}

struct projected_cancellation_t final {};

void poll_projected_cancellation(const cancellation_token_t& cancel,
                                 std::uint64_t& visits) {
    if ((visits++ & 255U) == 0 && cancel.stop_requested())
        throw projected_cancellation_t{};
}

template <typename T, typename Predicate>
std::vector<T> retain_records(const std::vector<T>& source, Predicate retain,
                              const cancellation_token_t& cancel) {
    std::vector<T> result;
    result.reserve(source.size());
    std::uint64_t visits = 0;
    for (const auto& record : source) {
        poll_projected_cancellation(cancel, visits);
        if (retain(record))
            result.push_back(record);
    }
    return result;
}

template <typename T>
void assign_projected_entity_ids(std::vector<T>& records,
                                 std::uint8_t domain,
                                 const cancellation_token_t& cancel) {
    const auto tag = static_cast<std::uint64_t>(domain) << 56U;
    std::uint64_t visits = 0;
    for (std::size_t index = 0; index < records.size(); ++index) {
        poll_projected_cancellation(cancel, visits);
        records[index].id = tag | static_cast<std::uint64_t>(index + 1U);
    }
}

std::vector<projected_range_t> merged_projected_ranges(
    std::vector<projected_range_t> ranges) {
    std::sort(ranges.begin(), ranges.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.offset, lhs.size) <
                std::tie(rhs.offset, rhs.size);
        });
    std::vector<projected_range_t> merged;
    merged.reserve(ranges.size());
    for (const auto& range : ranges) {
        if (range.size == 0)
            continue;
        if (merged.empty()) {
            merged.push_back(range);
            merged.back().is_byte_patch = false;
            merged.back().source_kind =
                overlay_operation_kind_v9_t::reanalysis;
            continue;
        }
        auto& previous = merged.back();
        const auto previous_end = previous.offset + previous.size;
        const auto range_end = range.offset + range.size;
        if (range.offset > previous_end) {
            merged.push_back(range);
            merged.back().is_byte_patch = false;
            merged.back().source_kind =
                overlay_operation_kind_v9_t::reanalysis;
            continue;
        }
        previous.size = (std::max)(previous_end, range_end) - previous.offset;
    }
    return merged;
}

call_graph_publication_t retain_projected_call_graph(
    const analysis_snapshot_t& source,
    const analysis_snapshot_t& projected,
    const workspace_image_t& image,
    const std::vector<projected_range_t>& ranges,
    bool code_changed,
    const cancellation_token_t& cancel) {
    if (!code_changed) {
        call_graph_publication_t result;
        const auto retain_all = [](const auto&) { return true; };
        result.nodes = retain_records(
            source.call_graph.nodes, retain_all, cancel);
        result.call_sites = retain_records(
            source.call_graph.call_sites, retain_all, cancel);
        result.candidates = retain_records(
            source.call_graph.candidates, retain_all, cancel);
        result.edges = retain_records(
            source.call_graph.edges, retain_all, cancel);
        result.conflicts = retain_records(
            source.call_graph.conflicts, retain_all, cancel);
        result.indirect_site_count = source.call_graph.indirect_site_count;
        result.unresolved_site_count = source.call_graph.unresolved_site_count;
        result.bounded = source.call_graph.bounded;
        return result;
    }
    if (source.call_graph.nodes.empty() && source.call_graph.call_sites.empty() &&
        source.call_graph.candidates.empty() && source.call_graph.edges.empty() &&
        source.call_graph.conflicts.empty())
        return {};

    std::unordered_set<entity_id_t> functions;
    std::unordered_set<entity_id_t> blocks;
    std::unordered_set<entity_id_t> instructions;
    functions.reserve(projected.functions.size());
    blocks.reserve(projected.blocks.size());
    instructions.reserve(projected.instructions.size());
    std::uint64_t visits = 0;
    for (const auto& record : projected.functions) {
        poll_projected_cancellation(cancel, visits);
        functions.insert(record.id);
    }
    for (const auto& record : projected.blocks) {
        poll_projected_cancellation(cancel, visits);
        blocks.insert(record.id);
    }
    for (const auto& record : projected.instructions) {
        poll_projected_cancellation(cancel, visits);
        instructions.insert(record.id);
    }

    std::unordered_map<entity_id_t,
                       std::vector<const call_graph_edge_record_t*>> edges_by_site;
    edges_by_site.reserve(source.call_graph.call_sites.size());
    for (const auto& edge : source.call_graph.edges) {
        poll_projected_cancellation(cancel, visits);
        edges_by_site[edge.call_site_id].push_back(&edge);
    }

    call_graph_publication_t result;
    std::unordered_set<entity_id_t> indirect_sites;
    result.call_sites.reserve(source.call_graph.call_sites.size());
    result.candidates.reserve(source.call_graph.candidates.size());
    result.edges.reserve(source.call_graph.edges.size());
    for (const auto& site : source.call_graph.call_sites) {
        poll_projected_cancellation(cancel, visits);
        if (functions.find(site.source_function_id) == functions.end() ||
            blocks.find(site.source_block_id) == blocks.end() ||
            instructions.find(site.instruction_id) == instructions.end() ||
            projected_overlap(image, site.address, 1, ranges))
            continue;
        const auto candidate_end = static_cast<std::uint64_t>(
            site.first_candidate) + site.candidate_count;
        if (candidate_end > source.call_graph.candidates.size())
            continue;
        bool retain_site = true;
        for (std::uint64_t index = site.first_candidate;
             index < candidate_end; ++index) {
            poll_projected_cancellation(cancel, visits);
            const auto& candidate = source.call_graph.candidates[
                static_cast<std::size_t>(index)];
            if ((candidate.target_function_id &&
                 functions.find(*candidate.target_function_id) == functions.end()) ||
                projected_overlap(image, candidate.target, 1, ranges)) {
                retain_site = false;
                break;
            }
        }
        const auto source_edges = edges_by_site.find(site.id);
        if (!retain_site || source_edges == edges_by_site.end())
            continue;
        const auto expected_edge_count = site.unresolved
            ? 1ULL : static_cast<std::uint64_t>(site.candidate_count);
        if (source_edges->second.size() != expected_edge_count)
            continue;

        auto retained_site = site;
        retained_site.id = call_site_entity_tag |
            static_cast<std::uint64_t>(result.call_sites.size() + 1U);
        retained_site.first_candidate = static_cast<std::uint32_t>(
            result.candidates.size());
        for (std::uint64_t index = site.first_candidate;
             index < candidate_end; ++index) {
            poll_projected_cancellation(cancel, visits);
            auto candidate = source.call_graph.candidates[
                static_cast<std::size_t>(index)];
            candidate.id = call_candidate_entity_tag |
                static_cast<std::uint64_t>(result.candidates.size() + 1U);
            candidate.call_site_id = retained_site.id;
            candidate.rank = static_cast<std::uint32_t>(
                result.candidates.size() - retained_site.first_candidate);
            result.candidates.push_back(std::move(candidate));
        }
        for (const auto* source_edge : source_edges->second) {
            poll_projected_cancellation(cancel, visits);
            auto edge = *source_edge;
            edge.id = call_edge_entity_tag |
                static_cast<std::uint64_t>(result.edges.size() + 1U);
            edge.call_site_id = retained_site.id;
            result.edges.push_back(std::move(edge));
        }
        result.indirect_site_count += retained_site.indirect ? 1U : 0U;
        result.unresolved_site_count += retained_site.unresolved ? 1U : 0U;
        if (retained_site.indirect)
            indirect_sites.insert(retained_site.id);
        result.call_sites.push_back(std::move(retained_site));
    }

    result.conflicts.reserve(source.call_graph.conflicts.size());
    for (const auto& source_conflict : source.call_graph.conflicts) {
        poll_projected_cancellation(cancel, visits);
        if ((source_conflict.source_function_id != 0 &&
             functions.find(source_conflict.source_function_id) == functions.end()) ||
            (source_conflict.selected_target_function_id != 0 &&
             functions.find(source_conflict.selected_target_function_id) ==
                 functions.end()) ||
            (source_conflict.competing_target_function_id != 0 &&
             functions.find(source_conflict.competing_target_function_id) ==
                 functions.end()) ||
            (source_conflict.instruction_id != 0 &&
             source_conflict.kind !=
                 call_graph_conflict_kind_t::orphan_candidate &&
             instructions.find(source_conflict.instruction_id) ==
                 instructions.end()))
            continue;
        auto conflict = source_conflict;
        conflict.id = call_conflict_entity_tag |
            static_cast<std::uint64_t>(result.conflicts.size() + 1U);
        result.conflicts.push_back(std::move(conflict));
    }

    result.nodes.reserve(projected.functions.size());
    std::unordered_map<entity_id_t, std::size_t> node_indices;
    node_indices.reserve(projected.functions.size());
    for (const auto& function : projected.functions) {
        poll_projected_cancellation(cancel, visits);
        call_graph_node_record_t node;
        node.function_id = function.id;
        node.address = function.start;
        node_indices.emplace(function.id, result.nodes.size());
        result.nodes.push_back(std::move(node));
    }
    for (const auto& site : result.call_sites) {
        poll_projected_cancellation(cancel, visits);
        result.nodes[node_indices[site.source_function_id]].unresolved_sites +=
            site.unresolved ? 1U : 0U;
    }
    for (const auto& edge : result.edges) {
        poll_projected_cancellation(cancel, visits);
        auto& source_node = result.nodes[node_indices[edge.source_function_id]];
        ++source_node.outgoing_edges;
        if (indirect_sites.find(edge.call_site_id) != indirect_sites.end())
            ++source_node.indirect_edges;
        if (edge.target_function_id)
            ++result.nodes[node_indices[*edge.target_function_id]].incoming_edges;
    }
    result.bounded = !result.nodes.empty() || !result.call_sites.empty() ||
            !result.candidates.empty() || !result.edges.empty() ||
            !result.conflicts.empty()
        ? source.call_graph.bounded : false;
    return result;
}

workspace_result_t<std::shared_ptr<analysis_snapshot_t>>
make_projected_analysis_candidate(
    const analysis_snapshot_t& source,
    std::shared_ptr<const workspace_image_t> projected_image,
    std::uint64_t target_generation,
    std::uint64_t target_overlay_revision,
    const projection_invalidation_set_t& invalidation,
    const cancellation_token_t& cancel,
    std::vector<projected_range_t>& dependency_ranges) {
    if (!projected_image)
        return workspace_result_t<std::shared_ptr<analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "projected image is unavailable",
                                 "workspace_overlay_candidate"));
    std::shared_ptr<analysis_snapshot_t> next;
    try {
        next = std::make_shared<analysis_snapshot_t>();
        next->binary_id = source.binary_id;
        next->load_profile_hash = source.load_profile_hash;
        next->generation = target_generation;
        next->analysis_revision = source.analysis_revision;
        next->overlay_revision = target_overlay_revision;
        next->baseline_complete = source.baseline_complete;
        next->normalized_image = std::move(projected_image);
        next->image = source.image;
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "projected candidate allocation failed",
                                 "workspace_overlay_candidate"));
    }
    const auto& image = *next->normalized_image;
    const auto& ranges = invalidation.affected_ranges;
    dependency_ranges = ranges;
    const bool code_changed =
        stage_test(invalidation.invalidated_stages,
                   projection_stage_flag_t::disassembler) ||
        stage_test(invalidation.invalidated_stages,
                   projection_stage_flag_t::basic_block_table) ||
        stage_test(invalidation.invalidated_stages,
                   projection_stage_flag_t::function_table);
    std::unordered_set<entity_id_t> removed_functions;
    std::uint64_t candidate_visits = 0;
    if (code_changed) {
        for (const auto& function : source.functions) {
            poll_projected_cancellation(cancel, candidate_visits);
            bool affected = projected_overlap(
                image, function.start, function.end, ranges);
            for (const auto& chunk : function.chunks)
                affected = affected || std::any_of(
                    ranges.begin(), ranges.end(), [&](const auto& range) {
                        return projected_range_t{
                            chunk.rva_start,
                            chunk.rva_end > chunk.rva_start
                                ? chunk.rva_end - chunk.rva_start : 0,
                            false, overlay_operation_kind_v9_t::reanalysis}
                            .overlaps(range);
                    });
            if (affected)
                removed_functions.insert(function.id);
        }
        for (const auto& block : source.blocks) {
            poll_projected_cancellation(cancel, candidate_visits);
            if (projected_overlap(image, block.start, block.end, ranges))
                removed_functions.insert(block.function_id);
        }
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto& membership : source.function_block_memberships) {
                poll_projected_cancellation(cancel, candidate_visits);
                if (membership.block_index >= source.blocks.size())
                    continue;
                const auto owner = source.blocks[membership.block_index].function_id;
                const bool member_removed =
                    removed_functions.find(membership.function_id) !=
                    removed_functions.end();
                const bool owner_removed =
                    removed_functions.find(owner) != removed_functions.end();
                if (!member_removed && !owner_removed)
                    continue;
                if (removed_functions.insert(membership.function_id).second)
                    changed = true;
                if (removed_functions.insert(owner).second)
                    changed = true;
            }
        }
    }
    if (code_changed) {
        for (const auto& function : source.functions) {
            poll_projected_cancellation(cancel, candidate_visits);
            if (removed_functions.find(function.id) == removed_functions.end())
                continue;
            if (!function.chunks.empty()) {
                for (const auto& chunk : function.chunks) {
                    poll_projected_cancellation(cancel, candidate_visits);
                    if (chunk.rva_end <= chunk.rva_start)
                        continue;
                    dependency_ranges.push_back({
                        chunk.rva_start, chunk.rva_end - chunk.rva_start,
                        false, overlay_operation_kind_v9_t::reanalysis});
                }
                continue;
            }
            const auto start = projected_rva(image, function.start);
            const auto end = projected_rva(image, function.end);
            if (start && end && *end > *start)
                dependency_ranges.push_back({
                    *start, *end - *start, false,
                    overlay_operation_kind_v9_t::reanalysis});
        }
    }
    dependency_ranges = merged_projected_ranges(
        std::move(dependency_ranges));

    std::vector<std::int64_t> instruction_map(source.instructions.size(), -1);
    std::vector<bool> remove_instruction(source.instructions.size(), false);
    if (code_changed) {
        for (std::size_t index = 0; index < source.instructions.size(); ++index) {
            poll_projected_cancellation(cancel, candidate_visits);
            remove_instruction[index] = projected_overlap(
                image, source.instructions[index].address,
                source.instructions[index].length, ranges);
        }
        for (const auto& block : source.blocks) {
            poll_projected_cancellation(cancel, candidate_visits);
            if (removed_functions.find(block.function_id) == removed_functions.end())
                continue;
            const auto end = static_cast<std::uint64_t>(block.first_instruction) +
                block.instruction_count;
            for (std::uint64_t index = block.first_instruction;
                 index < end && index < remove_instruction.size(); ++index)
                remove_instruction[static_cast<std::size_t>(index)] = true;
        }
        if (!source.delay_slot_counts.empty()) {
            for (std::size_t index = 0; index < source.instructions.size(); ++index) {
                poll_projected_cancellation(cancel, candidate_visits);
                const auto count = source.delay_slot_counts[index];
                if (count == 0 || index + count >= source.instructions.size())
                    continue;
                bool remove_group = false;
                for (std::size_t offset = 0; offset <= count; ++offset)
                    remove_group = remove_group || remove_instruction[index + offset];
                if (remove_group)
                    for (std::size_t offset = 0; offset <= count; ++offset)
                        remove_instruction[index + offset] = true;
            }
        }
    }
    next->instructions.reserve(source.instructions.size());
    next->operand_facts.reserve(source.operand_facts.size());
    next->target_facts.reserve(source.target_facts.size());
    if (!source.delay_slot_counts.empty())
        next->delay_slot_counts.reserve(source.delay_slot_counts.size());
    for (std::size_t index = 0; index < source.instructions.size(); ++index) {
        if ((index & 1023U) == 0 && cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<analysis_snapshot_t>>::failure(
                workspace_stop_error(cancel, "workspace_overlay_candidate"));
        if (remove_instruction[index])
            continue;
        auto instruction = source.instructions[index];
        instruction_map[index] = static_cast<std::int64_t>(next->instructions.size());
        const auto operand_begin = instruction.operand_fact_begin;
        const auto operand_end = static_cast<std::uint64_t>(operand_begin) +
            instruction.operand_fact_count;
        const auto target_begin = instruction.target_fact_begin;
        const auto target_end = static_cast<std::uint64_t>(target_begin) +
            instruction.target_fact_count;
        instruction.operand_fact_begin =
            static_cast<std::uint32_t>(next->operand_facts.size());
        instruction.target_fact_begin =
            static_cast<std::uint32_t>(next->target_facts.size());
        next->operand_facts.insert(next->operand_facts.end(),
            source.operand_facts.begin() + static_cast<std::ptrdiff_t>(operand_begin),
            source.operand_facts.begin() + static_cast<std::ptrdiff_t>(operand_end));
        next->target_facts.insert(next->target_facts.end(),
            source.target_facts.begin() + static_cast<std::ptrdiff_t>(target_begin),
            source.target_facts.begin() + static_cast<std::ptrdiff_t>(target_end));
        next->instructions.push_back(std::move(instruction));
        if (!source.delay_slot_counts.empty())
            next->delay_slot_counts.push_back(source.delay_slot_counts[index]);
    }

    std::vector<std::int64_t> block_map(source.blocks.size(), -1);
    next->blocks.reserve(source.blocks.size());
    for (std::size_t index = 0; index < source.blocks.size(); ++index) {
        poll_projected_cancellation(cancel, candidate_visits);
        const auto& source_block = source.blocks[index];
        if (removed_functions.find(source_block.function_id) !=
            removed_functions.end())
            continue;
        const auto first = source_block.first_instruction;
        const auto last = static_cast<std::uint64_t>(first) +
            source_block.instruction_count - 1U;
        if (last >= instruction_map.size() || instruction_map[first] < 0 ||
            instruction_map[static_cast<std::size_t>(last)] < 0 ||
            instruction_map[static_cast<std::size_t>(last)] -
                    instruction_map[first] + 1 != source_block.instruction_count)
            return workspace_result_t<std::shared_ptr<analysis_snapshot_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "retained block lost an instruction",
                                     "workspace_overlay_candidate"));
        auto block = source_block;
        block.first_instruction = static_cast<std::uint32_t>(instruction_map[first]);
        block_map[index] = static_cast<std::int64_t>(next->blocks.size());
        next->blocks.push_back(std::move(block));
    }

    next->functions.reserve(source.functions.size());
    next->function_chunks.reserve(source.function_chunks.size());
    next->function_block_memberships.reserve(
        source.function_block_memberships.size());
    for (const auto& source_function : source.functions) {
        poll_projected_cancellation(cancel, candidate_visits);
        if (removed_functions.find(source_function.id) != removed_functions.end())
            continue;
        auto function = source_function;
        if (function.block_count != 0) {
            if (function.first_block >= block_map.size() ||
                block_map[function.first_block] < 0)
                return workspace_result_t<std::shared_ptr<analysis_snapshot_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                                         "retained function lost its primary block",
                                         "workspace_overlay_candidate"));
            function.first_block = static_cast<std::uint32_t>(
                block_map[function.first_block]);
        }
        if (function.chunk_count != 0) {
            const auto source_chunk_begin = source_function.first_chunk;
            const auto source_chunk_end = static_cast<std::uint64_t>(source_chunk_begin) +
                source_function.chunk_count;
            const auto source_membership_begin = source_function.first_block_membership;
            const auto source_membership_end =
                static_cast<std::uint64_t>(source_membership_begin) +
                source_function.block_membership_count;
            function.first_chunk = static_cast<std::uint32_t>(
                next->function_chunks.size());
            function.first_block_membership = static_cast<std::uint32_t>(
                next->function_block_memberships.size());
            for (std::uint64_t index = source_chunk_begin;
                 index < source_chunk_end; ++index) {
                poll_projected_cancellation(cancel, candidate_visits);
                auto chunk = source.function_chunks[static_cast<std::size_t>(index)];
                if (chunk.first_block >= block_map.size() ||
                    block_map[chunk.first_block] < 0)
                    return workspace_result_t<std::shared_ptr<analysis_snapshot_t>>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                                             "retained chunk lost a block",
                                             "workspace_overlay_candidate"));
                chunk.first_block = static_cast<std::uint32_t>(
                    block_map[chunk.first_block]);
                next->function_chunks.push_back(std::move(chunk));
            }
            for (std::uint64_t index = source_membership_begin;
                 index < source_membership_end; ++index) {
                poll_projected_cancellation(cancel, candidate_visits);
                auto membership = source.function_block_memberships[
                    static_cast<std::size_t>(index)];
                if (membership.block_index >= block_map.size() ||
                    block_map[membership.block_index] < 0)
                    return workspace_result_t<std::shared_ptr<analysis_snapshot_t>>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                                             "retained membership lost a block",
                                             "workspace_overlay_candidate"));
                membership.block_index = static_cast<std::uint32_t>(
                    block_map[membership.block_index]);
                membership.ordinal = static_cast<std::uint32_t>(
                    next->function_block_memberships.size() -
                    function.first_block_membership);
                next->function_block_memberships.push_back(
                    std::move(membership));
            }
        }
        next->functions.push_back(std::move(function));
    }

    std::unordered_set<entity_id_t> graph_entities;
    for (const auto& record : next->instructions) {
        poll_projected_cancellation(cancel, candidate_visits);
        graph_entities.insert(record.id);
    }
    for (const auto& record : next->blocks) {
        poll_projected_cancellation(cancel, candidate_visits);
        graph_entities.insert(record.id);
    }
    for (const auto& record : next->functions) {
        poll_projected_cancellation(cancel, candidate_visits);
        graph_entities.insert(record.id);
    }
    next->edges = retain_records(source.edges, [&](const auto& edge) {
        return graph_entities.find(edge.source_entity) != graph_entities.end() &&
            (!edge.target_entity ||
             graph_entities.find(*edge.target_entity) != graph_entities.end()) &&
            (!code_changed ||
             (!projected_overlap(
                  image, edge.source, 1, dependency_ranges) &&
              !projected_overlap(
                  image, edge.target, 1, dependency_ranges)));
    }, cancel);
    next->call_graph = retain_projected_call_graph(
        source, *next, image, dependency_ranges, code_changed, cancel);

    next->xrefs = retain_records(source.xrefs, [&](const auto& xref) {
        return !stage_test(invalidation.invalidated_stages,
                           projection_stage_flag_t::xref_table) ||
            (!projected_overlap(
                 image, xref.source, 1, dependency_ranges) &&
             !projected_overlap(
                 image, xref.target, 1, dependency_ranges));
    }, cancel);
    next->strings = retain_records(source.strings, [&](const auto& string) {
        return !stage_test(invalidation.invalidated_stages,
                           projection_stage_flag_t::string_table) ||
            !projected_overlap(
                image, string.address, string.byte_length,
                dependency_ranges);
    }, cancel);
    next->symbols = retain_records(source.symbols, [&](const auto& symbol) {
        return !stage_test(invalidation.invalidated_stages,
                           projection_stage_flag_t::symbol_table) ||
            !projected_overlap(image, symbol.address, 1, ranges);
    }, cancel);
    std::unordered_set<entity_id_t> retained_symbols;
    retained_symbols.reserve(next->symbols.size());
    for (const auto& symbol : next->symbols) {
        poll_projected_cancellation(cancel, candidate_visits);
        retained_symbols.insert(symbol.id);
    }
    for (auto& function : next->functions) {
        poll_projected_cancellation(cancel, candidate_visits);
        if (function.symbol_id &&
            retained_symbols.find(*function.symbol_id) == retained_symbols.end())
            function.symbol_id.reset();
    }
    if (!stage_test(invalidation.invalidated_stages,
                    projection_stage_flag_t::type_table)) {
        const auto retain_all = [](const auto&) { return true; };
        next->rich_facts.data_candidates = retain_records(
            source.rich_facts.data_candidates, retain_all, cancel);
        next->rich_facts.data_pointer_facts = retain_records(
            source.rich_facts.data_pointer_facts, retain_all, cancel);
        next->rich_facts.data_conflicts = retain_records(
            source.rich_facts.data_conflicts, retain_all, cancel);
        next->rich_facts.type_candidates = retain_records(
            source.rich_facts.type_candidates, retain_all, cancel);
        next->rich_facts.type_references = retain_records(
            source.rich_facts.type_references, retain_all, cancel);
        next->rich_facts.metadata_conflicts = retain_records(
            source.rich_facts.metadata_conflicts, retain_all, cancel);
    } else {
        if (ranges.empty()) {
            const auto retain_all = [](const auto&) { return true; };
            next->rich_facts.data_candidates = retain_records(
                source.rich_facts.data_candidates, retain_all, cancel);
            next->rich_facts.data_pointer_facts = retain_records(
                source.rich_facts.data_pointer_facts, retain_all, cancel);
            next->rich_facts.data_conflicts = retain_records(
                source.rich_facts.data_conflicts, retain_all, cancel);
        } else {
            next->rich_facts.data_candidates = retain_records(
                source.rich_facts.data_candidates, [&](const auto& record) {
                    return !projected_overlap(
                               image, record.address,
                               (std::max)(record.size, std::uint64_t{1}),
                               dependency_ranges) &&
                        (!record.target ||
                         !projected_overlap(
                             image, *record.target, 1,
                             dependency_ranges));
                }, cancel);
            next->rich_facts.data_pointer_facts = retain_records(
                source.rich_facts.data_pointer_facts, [&](const auto& record) {
                    return !projected_overlap(
                               image, record.slot,
                               (std::max<std::uint64_t>)(
                                   record.width_bytes, std::uint64_t{1}),
                               dependency_ranges) &&
                        !projected_overlap(
                            image, record.target, 1, dependency_ranges);
                }, cancel);
            next->rich_facts.data_conflicts = retain_records(
                source.rich_facts.data_conflicts, [&](const auto& record) {
                    return !projected_overlap(
                               image, record.address, 1,
                               dependency_ranges) &&
                        (!record.selected_target ||
                         !projected_overlap(
                             image, *record.selected_target, 1,
                             dependency_ranges)) &&
                        (!record.rejected_target ||
                         !projected_overlap(
                             image, *record.rejected_target, 1,
                             dependency_ranges));
                }, cancel);
            next->rich_facts.type_candidates = retain_records(
                source.rich_facts.type_candidates, [&](const auto& record) {
                    return (!record.address ||
                            !projected_overlap(
                                image, *record.address, 1,
                                dependency_ranges)) &&
                        (!record.related_address ||
                         !projected_overlap(
                             image, *record.related_address, 1,
                             dependency_ranges));
                }, cancel);
        }
        std::unordered_set<entity_id_t> retained_type_entities;
        retained_type_entities.reserve(
            next->rich_facts.type_candidates.size());
        for (const auto& record : next->rich_facts.type_candidates) {
            poll_projected_cancellation(cancel, candidate_visits);
            retained_type_entities.insert(record.id);
        }
        if (!ranges.empty()) {
            next->rich_facts.type_references = retain_records(
                source.rich_facts.type_references, [&](const auto& record) {
                    return (!record.source ||
                            !projected_overlap(
                                image, *record.source, 1,
                                dependency_ranges)) &&
                        (!record.target ||
                         !projected_overlap(
                             image, *record.target, 1,
                             dependency_ranges)) &&
                        (record.source_entity == 0 ||
                         retained_type_entities.find(record.source_entity) !=
                             retained_type_entities.end()) &&
                        (record.target_entity == 0 ||
                         retained_type_entities.find(record.target_entity) !=
                             retained_type_entities.end());
                }, cancel);
            next->rich_facts.metadata_conflicts = retain_records(
                source.rich_facts.metadata_conflicts, [&](const auto& record) {
                    return !record.address ||
                        !projected_overlap(
                            image, *record.address, 1,
                            dependency_ranges);
                }, cancel);
        }
        assign_projected_entity_ids(
            next->rich_facts.data_candidates, 8, cancel);
        assign_projected_entity_ids(
            next->rich_facts.data_pointer_facts, 12, cancel);
        assign_projected_entity_ids(
            next->rich_facts.data_conflicts, 13, cancel);
        std::unordered_map<entity_id_t, entity_id_t> type_id_map;
        type_id_map.reserve(next->rich_facts.type_candidates.size());
        for (std::size_t index = 0;
             index < next->rich_facts.type_candidates.size(); ++index) {
            poll_projected_cancellation(cancel, candidate_visits);
            const auto old_id = next->rich_facts.type_candidates[index].id;
            const auto new_id = (10ULL << 56U) |
                static_cast<std::uint64_t>(index + 1U);
            type_id_map.emplace(old_id, new_id);
            next->rich_facts.type_candidates[index].id = new_id;
        }
        for (auto& reference : next->rich_facts.type_references) {
            poll_projected_cancellation(cancel, candidate_visits);
            if (reference.source_entity != 0)
                reference.source_entity =
                    type_id_map.at(reference.source_entity);
            if (reference.target_entity != 0)
                reference.target_entity =
                    type_id_map.at(reference.target_entity);
        }
        assign_projected_entity_ids(
            next->rich_facts.type_references, 9, cancel);
        assign_projected_entity_ids(
            next->rich_facts.metadata_conflicts, 14, cancel);
    }

    const auto& coverage_ranges = dependency_ranges;
    if (!stage_test(invalidation.invalidated_stages,
                    projection_stage_flag_t::coverage_table)) {
        next->coverage = retain_records(
            source.coverage, [](const auto&) { return true; }, cancel);
    } else {
        for (const auto& span : source.coverage) {
            poll_projected_cancellation(cancel, candidate_visits);
            const auto rva = projected_rva(image, span.start);
            if (!rva || span.size == 0)
                continue;
            std::vector<std::pair<std::uint64_t, std::uint64_t>> pieces{{
                *rva, *rva + span.size}};
            for (const auto& range : coverage_ranges) {
                poll_projected_cancellation(cancel, candidate_visits);
                std::vector<std::pair<std::uint64_t, std::uint64_t>> split;
                for (const auto& piece : pieces) {
                    const auto range_end = range.offset + range.size;
                    if (range_end <= piece.first || range.offset >= piece.second) {
                        split.push_back(piece);
                        continue;
                    }
                    if (piece.first < range.offset)
                        split.emplace_back(piece.first, range.offset);
                    if (range_end < piece.second)
                        split.emplace_back(range_end, piece.second);
                }
                pieces = std::move(split);
            }
            for (const auto& piece : pieces) {
                auto retained = span;
                retained.start.value += piece.first - *rva;
                retained.size = piece.second - piece.first;
                next->coverage.push_back(std::move(retained));
            }
        }
        for (const auto& range : coverage_ranges) {
            poll_projected_cancellation(cancel, candidate_visits);
            if (range.size == 0)
                continue;
            coverage_span_t pending;
            pending.start.space = address_space_id_t::relative_virtual;
            pending.start.value = range.offset;
            pending.start.architecture = image.architecture;
            pending.start.mode = image.architecture_mode;
            pending.size = range.size;
            pending.reason = coverage_reason_t::pending;
            next->coverage.push_back(std::move(pending));
        }
        std::sort(next->coverage.begin(), next->coverage.end(),
            [](const auto& lhs, const auto& rhs) {
                return std::tie(lhs.start, lhs.size, lhs.reason) <
                       std::tie(rhs.start, rhs.size, rhs.reason);
            });
    }
    if (invalidation.invalidated_stages != projection_stage_flag_t::none)
        next->baseline_complete = false;
    return workspace_result_t<std::shared_ptr<analysis_snapshot_t>>::success(
        std::move(next));
}

}

workspace_result_t<std::size_t>
analysis_workspace_t::publish_projected_generation(
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::uint64_t target_generation,
    std::uint64_t target_overlay_revision,
    std::shared_ptr<const byte_provider_t> projected_provider,
    const projection_invalidation_set_t& invalidation,
    std::function<workspace_result_t<void>(
        const std::shared_ptr<const analysis_snapshot_t>&,
        const std::shared_ptr<search_index_t>&)> finalizer) {
    if (!projected_provider || !finalizer ||
        expected_generation == (std::numeric_limits<std::uint64_t>::max)() ||
        target_generation != expected_generation + 1 ||
        target_overlay_revision == 0 ||
        target_kind() != target_kind_t::static_file) {
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "projected generation publication is invalid",
                                 "workspace_overlay_publish"));
    }
    const auto& projected_identity = projected_provider->identity();
    if (!projected_identity.immutable_snapshot ||
        !projected_identity.content_sha256 ||
        projected_identity.content_sha256->empty() ||
        projected_identity.normalized_source.empty() ||
        projected_identity.size != projected_provider->size() ||
        projected_provider->size() != source_provider_->size() ||
        projected_identity.member != source_provider_->member_metadata()) {
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "projected provider identity is invalid",
                                 "workspace_overlay_publish"));
    }
    if (closing() || closed())
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing",
                                 "workspace_overlay_publish"));
    const auto workspace_cancel = cancellation_token();
    if (workspace_cancel.stop_requested())
        return workspace_result_t<std::size_t>::failure(
            workspace_stop_error(workspace_cancel, "workspace_overlay_publish"));
    const auto source = analysis_publication();
    if (!source || !source->snapshot || !source->provider ||
        source->generation != expected_generation ||
        source->analysis_revision != expected_analysis_revision ||
        !source->snapshot->normalized_image) {
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "workspace publication changed before projected generation preparation",
                                 "workspace_overlay_publish"));
    }
    const auto image_size = source->snapshot->normalized_image->image_size;
    for (const auto& range : invalidation.affected_ranges) {
        if (range.size == 0 || range.offset >= image_size ||
            range.size > image_size - range.offset)
            return workspace_result_t<std::size_t>::failure(
                make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "projected invalidation range exceeds the normalized image",
                    "workspace_overlay_publish"));
    }

    std::shared_ptr<const analysis_snapshot_t> projected_snapshot;
    std::shared_ptr<search_index_t> projected_index;
    std::vector<projected_range_t> dependency_ranges;
    std::size_t retired_index_entries = source->search_index
        ? source->search_index->record_count()
        : 0;
    try {
        auto rebound = bind_publication_image(
            source->snapshot->normalized_image, *identity_, *projected_provider,
            *projected_identity.content_sha256, "workspace_overlay_publish");
        if (!rebound)
            return workspace_result_t<std::size_t>::failure(rebound.error());
        auto next = make_projected_analysis_candidate(
            *source->snapshot, rebound.take_value(), target_generation,
            target_overlay_revision, invalidation, workspace_cancel,
            dependency_ranges);
        if (!next)
            return workspace_result_t<std::size_t>::failure(next.error());
        projected_snapshot =
            std::static_pointer_cast<const analysis_snapshot_t>(next.take_value());
        if (source->search_index) {
            auto data_candidates = stage_test(
                    invalidation.invalidated_stages,
                    projection_stage_flag_t::type_table)
                ? retain_records(
                      projected_snapshot->rich_facts.data_candidates,
                      [](const auto&) { return true; }, workspace_cancel)
                : retain_records(
                      source->search_index->data_candidates(),
                      [](const auto&) { return true; }, workspace_cancel);
            std::unordered_set<entity_id_t> retained_functions;
            retained_functions.reserve(projected_snapshot->functions.size());
            std::uint64_t function_visits = 0;
            for (const auto& function : projected_snapshot->functions) {
                poll_projected_cancellation(
                    workspace_cancel, function_visits);
                retained_functions.insert(function.id);
            }
            auto switches = retain_records(
                source->search_index->switches(), [&](const auto& record) {
                    if (!stage_test(invalidation.invalidated_stages,
                                    projection_stage_flag_t::function_table))
                        return true;
                    if (retained_functions.find(record.function_id) ==
                        retained_functions.end())
                        return false;
                    const auto table_size = (std::max)(
                        static_cast<std::uint64_t>(record.entry_size) *
                            static_cast<std::uint64_t>(
                                record.case_targets.size()),
                        std::uint64_t{1});
                    if (projected_overlap(
                            *projected_snapshot->normalized_image,
                            record.dispatch, 1, dependency_ranges) ||
                        projected_overlap(
                            *projected_snapshot->normalized_image,
                            record.table, table_size, dependency_ranges) ||
                        (record.default_target &&
                         projected_overlap(
                             *projected_snapshot->normalized_image,
                             *record.default_target, 1,
                             dependency_ranges)))
                        return false;
                    return std::none_of(
                        record.case_targets.begin(),
                        record.case_targets.end(),
                        [&](const auto& target) {
                            return projected_overlap(
                                *projected_snapshot->normalized_image,
                                target, 1, dependency_ranges);
                        });
                }, workspace_cancel);
            auto types = retain_records(
                source->search_index->types(), [&](const auto& record) {
                    return !stage_test(invalidation.invalidated_stages,
                                       projection_stage_flag_t::type_table) ||
                        (!invalidation.affected_ranges.empty() &&
                         !projected_overlap(
                             *projected_snapshot->normalized_image,
                             record.address, 1,
                             dependency_ranges));
                }, workspace_cancel);
            auto metrics = std::make_shared<analysis_metrics_t>(target_generation);
            auto rebuilt = search_index_t::build(
                projected_snapshot,
                std::move(data_candidates), std::move(switches), std::move(types),
                std::move(metrics), source->search_index->limits(),
                workspace_cancel);
            if (!rebuilt)
                return workspace_result_t<std::size_t>::failure(rebuilt.error());
            projected_index = rebuilt.take_value();
            const auto projected_records = projected_index->record_count();
            retired_index_entries = retired_index_entries >= projected_records
                ? retired_index_entries - projected_records : 0;
        }
    } catch (const projected_cancellation_t&) {
        return workspace_result_t<std::size_t>::failure(
            workspace_stop_error(
                workspace_cancel, "workspace_overlay_publish"));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "projected generation allocation failed",
                                 "workspace_overlay_publish"));
    }

    auto validation = validate_analysis_snapshot(
        *projected_snapshot, projected_snapshot->baseline_complete,
        workspace_cancel);
    if (!validation)
        return workspace_result_t<std::size_t>::failure(validation.error());
    if (projected_index &&
        (!projected_index->matches(projected_snapshot) ||
         !projected_index->matches(
             identity_->binary_id(), identity_->load_profile_hash(),
             target_generation, projected_snapshot->analysis_revision,
             target_overlay_revision))) {
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "projected search index does not match its generation",
                                 "workspace_overlay_publish"));
    }
    const auto expected_projected_analysis_revision = expected_analysis_revision;
    if (projected_snapshot->analysis_revision !=
            expected_projected_analysis_revision ||
        (source->search_index && !projected_index) ||
        (!source->search_index && projected_index)) {
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "projected snapshot preservation policy is inconsistent",
                                 "workspace_overlay_publish"));
    }
    auto executable_bytes = executable_byte_count(
        *projected_snapshot, "workspace_overlay_publish");
    if (!executable_bytes)
        return workspace_result_t<std::size_t>::failure(executable_bytes.error());
    const auto readiness = publication_readiness(*projected_snapshot);
    auto projected_managed = rebind_publication_managed_artifacts(
        source->managed_artifacts, *identity_, projected_provider,
        projected_snapshot->image, target_generation,
        projected_snapshot->analysis_revision, target_overlay_revision,
        workspace_cancel);
    if (!projected_managed)
        return workspace_result_t<std::size_t>::failure(
            projected_managed.error());
    std::shared_ptr<const analysis_publication_t> replacement;
    workspace_progress_t replacement_progress;
    try {
        replacement = std::make_shared<const analysis_publication_t>(
            projected_snapshot, projected_provider, projected_index, readiness,
            projected_managed.take_value());
        replacement_progress = publication_progress(
            readiness, executable_bytes.value());
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "projected publication allocation failed",
                                 "workspace_overlay_publish"));
    }
    if (!replacement->coherent_with(*identity_))
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "projected publication is incoherent",
                                 "workspace_overlay_publish"));
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<std::size_t>::failure(
            publication_finalizer_conflict("workspace_overlay_publish"));

    std::unique_lock<std::shared_mutex> mutation_lock(
        mutation_mutex_, std::defer_lock);
    std::unique_lock<std::shared_mutex> publication_lock(
        publication_mutex_, std::defer_lock);
    std::lock(mutation_lock, publication_lock);
    {
        std::lock_guard state_lock(state_mutex_);
        if (closing() || closed())
            return workspace_result_t<std::size_t>::failure(
                make_workspace_error(workspace_error_code_t::workspace_closing,
                                     "workspace is closing",
                                     "workspace_overlay_publish"));
        const auto current = analysis_publication();
        if (!current || current != source ||
            current->generation != expected_generation)
            return workspace_result_t<std::size_t>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                                     "workspace generation changed before projected publication",
                                     "workspace_overlay_publish"));
        if (active_analysis_generation_.load(std::memory_order_acquire) != 0)
            return workspace_result_t<std::size_t>::failure(
                make_workspace_error(workspace_error_code_t::analysis_in_progress,
                                     "projected generation cannot publish during analysis",
                                     "workspace_overlay_publish"));
        if (current->analysis_revision != expected_analysis_revision ||
            current->overlay_revision ==
                (std::numeric_limits<std::uint64_t>::max)() ||
            target_overlay_revision != current->overlay_revision + 1 ||
            projected_snapshot->image != current->snapshot->image)
            return workspace_result_t<std::size_t>::failure(
                make_workspace_error(workspace_error_code_t::revision_conflict,
                                     "projected generation conflicts with workspace revisions",
                                     "workspace_overlay_publish"));
    }

    publication_finalizer_active_.store(true, std::memory_order_release);
    workspace_result_t<void> finalized = workspace_result_t<void>::success();
    try {
        finalized = finalizer(projected_snapshot, projected_index);
    } catch (...) {
        finalized = workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::persistence_failure,
                                 "projected publication finalizer threw an exception",
                                 "workspace_overlay_publish"));
    }
    publication_finalizer_active_.store(false, std::memory_order_release);
    if (!finalized)
        return workspace_result_t<std::size_t>::failure(finalized.error());

    {
        std::lock_guard state_lock(state_mutex_);
        cancellation_source_t replacement_cancellation;
        cancellation_.request_cancel();
        cancellation_ = std::move(replacement_cancellation);
        replacement_progress.cancellation_requested = false;
        progress_ = std::move(replacement_progress);
        std::atomic_store_explicit(
            &publication_state_->publication, replacement,
            std::memory_order_release);
    }
    return workspace_result_t<std::size_t>::success(retired_index_entries);
}

workspace_result_t<std::uint64_t> analysis_workspace_t::begin_new_generation() {
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<std::uint64_t>::failure(
            publication_finalizer_conflict("workspace_generation"));
    std::unique_lock publication_lock(publication_mutex_);
    std::lock_guard state_lock(state_mutex_);
    if (closing())
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_generation"));
    if (active_analysis_generation_.load(std::memory_order_acquire) != 0)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::analysis_in_progress,
                                 "workspace generation cannot change during analysis",
                                 "workspace_generation"));
    const auto current_publication = analysis_publication();
    if (!current_publication || !current_publication->snapshot)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication is missing",
                                 "workspace_generation"));
    const std::uint64_t current = current_publication->generation;
    if (current == std::numeric_limits<std::uint64_t>::max())
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "workspace generation overflowed", "workspace_generation"));
    const std::uint64_t next = current + 1;
    try {
    auto empty = std::make_shared<analysis_snapshot_t>();
    empty->binary_id = identity_->binary_id();
    empty->load_profile_hash = identity_->load_profile_hash();
    empty->generation = next;
    empty->overlay_revision = overlay_revision();
    empty->normalized_image = current_publication->snapshot->normalized_image;
    empty->image = current_publication->snapshot->image;
    const auto readiness = empty->normalized_image ? workspace_readiness_t::parsed
                                        : workspace_readiness_t::provider_ready;
    std::shared_ptr<const managed_artifact_publication_t> managed_artifacts;
    if (current_publication->managed_artifacts) {
        auto rebound = std::make_shared<managed_artifact_publication_t>(
            *current_publication->managed_artifacts);
        rebound->generation = next;
        rebound->analysis_revision = 0;
        rebound->overlay_revision = empty->overlay_revision;
        managed_artifacts = std::static_pointer_cast<
            const managed_artifact_publication_t>(std::move(rebound));
    }
    const auto replacement = std::make_shared<const analysis_publication_t>(
        std::static_pointer_cast<const analysis_snapshot_t>(empty),
        current_publication->provider, nullptr, readiness,
        std::move(managed_artifacts));
    if (!replacement->coherent_with(*identity_))
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "new workspace generation publication is incoherent",
                "workspace_generation"));
    cancellation_source_t replacement_cancellation;
    workspace_progress_t replacement_progress;
    replacement_progress.readiness = readiness;
    replacement_progress.phase = empty->normalized_image ? "parsed" : "provider_ready";
    replacement_progress.total_bytes = current_publication->provider->size();
    cancellation_.request_cancel();
    cancellation_ = std::move(replacement_cancellation);
    progress_ = std::move(replacement_progress);
    std::atomic_store_explicit(
        &publication_state_->publication, replacement, std::memory_order_release);
    return workspace_result_t<std::uint64_t>::success(next);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "new workspace generation allocation failed",
                "workspace_generation"));
    }
}

workspace_result_t<std::uint64_t> analysis_workspace_t::advance_overlay_revision(
    std::uint64_t expected_revision) {
    static_cast<void>(expected_revision);
    return workspace_result_t<std::uint64_t>::failure(
        make_workspace_error(workspace_error_code_t::service_conflict,
                             "isolated overlay revision publication is unsupported",
                             "workspace_overlay"));
}

workspace_result_t<std::uint64_t> analysis_workspace_t::restore_overlay_revision(
    std::uint64_t expected_current, std::uint64_t persisted_revision,
    std::uint64_t persisted_generation,
    std::shared_ptr<const byte_provider_t> projected_provider) {
    const auto source = analysis_publication();
    if (!source || !source->snapshot || !source->provider ||
        source->analysis_revision != 0) {
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "overlay revision can only be restored before analysis publication",
                                 "workspace_overlay_restore"));
    }
    if (persisted_revision == 0 || persisted_revision <= expected_current ||
        persisted_revision == (std::numeric_limits<std::uint64_t>::max)() ||
        persisted_generation <= source->generation ||
        persisted_generation == (std::numeric_limits<std::uint64_t>::max)())
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "persisted overlay generation or revision is not a valid monotonic restoration",
                                 "workspace_overlay_restore"));
    auto publication_provider = projected_provider
        ? std::move(projected_provider)
        : source->provider;
    if (!publication_provider)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "restored overlay provider is unavailable",
                                 "workspace_overlay_restore"));
    if (publication_provider != source->provider) {
        const auto& provider_identity = publication_provider->identity();
        if (!provider_identity.immutable_snapshot ||
            !provider_identity.content_sha256 ||
            provider_identity.content_sha256->empty() ||
            provider_identity.normalized_source.empty() ||
            provider_identity.size != publication_provider->size() ||
            publication_provider->size() != source_provider_->size() ||
            provider_identity.member != source_provider_->member_metadata())
            return workspace_result_t<std::uint64_t>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                     "restored overlay provider identity is invalid",
                                     "workspace_overlay_restore"));
    }
    std::shared_ptr<const analysis_snapshot_t> restored_snapshot;
    try {
        auto restored = std::make_shared<analysis_snapshot_t>(*source->snapshot);
        restored->generation = persisted_generation;
        restored->overlay_revision = persisted_revision;
        if (publication_provider != source->provider && restored->normalized_image) {
            auto rebound = bind_publication_image(
                restored->normalized_image, *identity_, *publication_provider,
                *publication_provider->identity().content_sha256,
                "workspace_overlay_restore");
            if (!rebound)
                return workspace_result_t<std::uint64_t>::failure(rebound.error());
            restored->normalized_image = rebound.take_value();
        }
        restored_snapshot =
            std::static_pointer_cast<const analysis_snapshot_t>(std::move(restored));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "overlay restoration allocation failed",
                                 "workspace_overlay_restore"));
    }
    auto restored_managed = rebind_publication_managed_artifacts(
        source->managed_artifacts, *identity_, publication_provider,
        restored_snapshot->image, persisted_generation,
        restored_snapshot->analysis_revision, persisted_revision,
        cancellation_token());
    if (!restored_managed)
        return workspace_result_t<std::uint64_t>::failure(
            restored_managed.error());
    const auto replacement = std::make_shared<const analysis_publication_t>(
        restored_snapshot, publication_provider, nullptr, source->readiness,
        restored_managed.take_value());
    if (!replacement->coherent_with(*identity_))
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "restored overlay publication is incoherent",
                                 "workspace_overlay_restore"));
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<std::uint64_t>::failure(
            publication_finalizer_conflict("workspace_overlay_restore"));
    std::unique_lock publication_lock(publication_mutex_);
    std::lock_guard state_lock(state_mutex_);
    if (closing())
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_overlay_restore"));
    const auto current_publication = analysis_publication();
    if (current_publication != source || analysis_revision() != 0 ||
        !current_publication->snapshot ||
        current_publication->snapshot->analysis_revision != 0 ||
        current_publication->snapshot->baseline_complete ||
        snapshot_has_analysis_facts(*current_publication->snapshot) ||
        current_publication->search_index ||
        progress_.readiness == workspace_readiness_t::analyzing ||
        progress_.readiness == workspace_readiness_t::baseline_ready ||
        progress_.readiness == workspace_readiness_t::partial ||
        progress_.readiness == workspace_readiness_t::failed)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "overlay revision can only be restored before analysis publication",
                                 "workspace_overlay_restore"));
    if (current_publication->overlay_revision != expected_current ||
        current_publication->generation != source->generation)
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "overlay revision changed during restoration",
                                 "workspace_overlay_restore"));
    std::atomic_store_explicit(
        &publication_state_->publication, replacement, std::memory_order_release);
    return workspace_result_t<std::uint64_t>::success(persisted_revision);
}

workspace_result_t<void> analysis_workspace_t::restore_projected_provider(
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::uint64_t expected_overlay_revision,
    std::shared_ptr<const byte_provider_t> projected_provider) {
    if (!projected_provider || target_kind() != target_kind_t::static_file)
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "projected provider restoration is invalid",
            "workspace_overlay_provider_restore"));
    const auto& provider_identity = projected_provider->identity();
    if (!provider_identity.immutable_snapshot ||
        !provider_identity.content_sha256 ||
        provider_identity.content_sha256->empty() ||
        provider_identity.normalized_source.empty() ||
        provider_identity.size != projected_provider->size() ||
        projected_provider->size() != source_provider_->size() ||
        provider_identity.member != source_provider_->member_metadata())
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::provider_binding_mismatch,
            "restored projected provider identity is invalid",
            "workspace_overlay_provider_restore"));
    const auto source = analysis_publication();
    if (!source || !source->snapshot || !source->snapshot->normalized_image ||
        source->generation != expected_generation ||
        source->analysis_revision != expected_analysis_revision ||
        source->overlay_revision != expected_overlay_revision)
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "workspace publication changed before projected provider restoration",
            "workspace_overlay_provider_restore"));
    const auto restore_cancel = cancellation_token();
    std::shared_ptr<const analysis_snapshot_t> restored_snapshot;
    std::shared_ptr<search_index_t> restored_index;
    try {
        auto rebound = bind_publication_image(
            source->snapshot->normalized_image, *identity_, *projected_provider,
            *provider_identity.content_sha256,
            "workspace_overlay_provider_restore");
        if (!rebound)
            return workspace_result_t<void>::failure(rebound.error());
        auto restored = std::make_shared<analysis_snapshot_t>(*source->snapshot);
        restored->normalized_image = rebound.take_value();
        restored_snapshot =
            std::static_pointer_cast<const analysis_snapshot_t>(std::move(restored));
        if (source->search_index) {
            auto metrics = std::make_shared<analysis_metrics_t>(expected_generation);
            auto rebuilt = search_index_t::build(
                restored_snapshot, source->search_index->data_candidates(),
                source->search_index->switches(), source->search_index->types(),
                std::move(metrics), source->search_index->limits(),
                restore_cancel);
            if (!rebuilt)
                return workspace_result_t<void>::failure(rebuilt.error());
            restored_index = rebuilt.take_value();
        }
    } catch (const std::bad_alloc&) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "projected provider restoration allocation failed",
            "workspace_overlay_provider_restore"));
    }
    auto validated = validate_analysis_snapshot(
        *restored_snapshot, restored_snapshot->baseline_complete,
        restore_cancel);
    if (!validated)
        return validated;
    auto restored_managed = rebind_publication_managed_artifacts(
        source->managed_artifacts, *identity_, projected_provider,
        restored_snapshot->image, expected_generation,
        expected_analysis_revision, expected_overlay_revision,
        restore_cancel);
    if (!restored_managed)
        return workspace_result_t<void>::failure(restored_managed.error());
    const auto replacement = std::make_shared<const analysis_publication_t>(
        restored_snapshot, projected_provider, restored_index, source->readiness,
        restored_managed.take_value());
    if (!replacement->coherent_with(*identity_))
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "restored projected publication is incoherent",
            "workspace_overlay_provider_restore"));
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_overlay_provider_restore"));
    std::unique_lock<std::shared_mutex> mutation_lock(
        mutation_mutex_, std::defer_lock);
    std::unique_lock<std::shared_mutex> publication_lock(
        publication_mutex_, std::defer_lock);
    std::lock(mutation_lock, publication_lock);
    std::lock_guard state_lock(state_mutex_);
    if (closing() || closed())
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "workspace is closing",
            "workspace_overlay_provider_restore"));
    if (active_analysis_generation_.load(std::memory_order_acquire) != 0)
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::analysis_in_progress,
            "projected provider cannot be restored during analysis",
            "workspace_overlay_provider_restore"));
    const auto current = analysis_publication();
    if (current != source || current->generation != expected_generation ||
        current->analysis_revision != expected_analysis_revision ||
        current->overlay_revision != expected_overlay_revision)
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "workspace revisions changed during projected provider restoration",
            "workspace_overlay_provider_restore"));
    std::atomic_store_explicit(
        &publication_state_->publication, replacement,
        std::memory_order_release);
    return workspace_result_t<void>::success();
}

cancellation_token_t analysis_workspace_t::cancellation_token() const {
    std::lock_guard lock(state_mutex_);
    return cancellation_.token();
}

void analysis_workspace_t::request_cancel() noexcept {
    std::lock_guard lock(state_mutex_);
    cancellation_.request_cancel();
    progress_.cancellation_requested = true;
    if (!closed() && progress_.readiness != workspace_readiness_t::closing)
        progress_.readiness = workspace_readiness_t::cancelling;
}

workspace_progress_t analysis_workspace_t::progress() const {
    std::lock_guard lock(state_mutex_);
    return progress_;
}

workspace_result_t<void> analysis_workspace_t::update_progress(
    std::uint64_t expected_generation, workspace_progress_t progress_value) {
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_progress"));
    std::shared_lock publication_lock(publication_mutex_);
    std::lock_guard lock(state_mutex_);
    if (generation() != expected_generation)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "progress update generation is stale", "workspace_progress"));
    if (closing())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_progress"));
    if (progress_value.completed_units > progress_value.total_units ||
        progress_value.completed_bytes > progress_value.total_bytes)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "progress counters exceed their totals", "workspace_progress"));
    if (progress_value.phase.empty() || progress_value.error ||
        (progress_value.readiness != workspace_readiness_t::provider_ready &&
         progress_value.readiness != workspace_readiness_t::parsed &&
         progress_value.readiness != workspace_readiness_t::analyzing &&
         progress_value.readiness != workspace_readiness_t::baseline_ready &&
         progress_value.readiness != workspace_readiness_t::partial))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "progress state is invalid", "workspace_progress"));
    const auto token = cancellation_.token();
    if (token.stop_requested())
        return workspace_result_t<void>::failure(
            workspace_stop_error(token, "workspace_progress"));
    if (progress_.readiness == workspace_readiness_t::baseline_ready &&
        progress_value.readiness != workspace_readiness_t::baseline_ready)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "baseline-ready progress requires a new generation before regression",
                                 "workspace_progress"));
    if (progress_value.readiness == workspace_readiness_t::baseline_ready) {
        if (target_kind() == target_kind_t::live_snapshot)
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::live_target_bulk_analysis_unsupported,
                                     "live targets cannot become baseline-ready",
                                     "workspace_progress"));
        const auto publication = analysis_publication();
        if (!publication || !publication->snapshot ||
            !publication->snapshot->baseline_complete)
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "baseline readiness requires a complete snapshot",
                                     "workspace_progress"));
    }
    progress_value.cancellation_requested = cancellation_.token().stop_requested();
    progress_ = std::move(progress_value);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> analysis_workspace_t::record_analysis_attempt_failure(
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    workspace_error_t error) {
    if (error.code == workspace_error_code_t::none || error.message.empty())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "analysis attempt failure requires a stable error",
                                 "workspace_progress"));
    if (error.phase.empty())
        error.phase = "analysis_attempt";
    std::string failure_phase = error.phase;
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_progress"));
    std::shared_lock publication_lock(publication_mutex_);
    std::lock_guard state_lock(state_mutex_);
    if (closing() || closed())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_progress"));
    const auto publication = analysis_publication();
    if (!publication || !publication->snapshot)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication is missing",
                                 "workspace_progress"));
    if (generation() != expected_generation ||
        publication->generation != expected_generation)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "analysis attempt failure generation is stale",
                                 "workspace_progress"));
    if (analysis_revision() != expected_analysis_revision ||
        publication->analysis_revision != expected_analysis_revision)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "analysis attempt failure revision conflicts with workspace state",
                                 "workspace_progress"));
    const bool valid_baseline = publication->readiness ==
                                    workspace_readiness_t::baseline_ready &&
                                publication->snapshot->baseline_complete &&
                                publication->search_index &&
                                publication->search_index->matches(publication->snapshot) &&
                                publication->search_index->matches(
                                    identity_->binary_id(), identity_->load_profile_hash(),
                                    publication->generation,
                                    publication->analysis_revision,
                                    publication->overlay_revision);
    if (!valid_baseline) {
        progress_.readiness = workspace_readiness_t::failed;
        progress_.phase = std::move(failure_phase);
    }
    progress_.error = std::move(error);
    return workspace_result_t<void>::success();
}

workspace_view_state_t analysis_workspace_t::view_state() const {
    std::lock_guard lock(state_mutex_);
    return view_state_;
}

workspace_result_t<void> analysis_workspace_t::update_view_state(
    const std::function<void(workspace_view_state_t&)>& mutation) {
    if (!mutation)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "view-state mutation is empty", "workspace_view"));
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_view"));
    std::lock_guard lock(state_mutex_);
    if (closing())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_view"));
    if (view_state_.revision == std::numeric_limits<std::uint64_t>::max())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "view-state revision overflowed", "workspace_view"));
    workspace_view_state_t next = view_state_;
    mutation(next);
    constexpr std::size_t maximum_bookmarks = 65536;
    if (next.bookmarks.size() > maximum_bookmarks)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "workspace view state exceeds its limits",
                                 "workspace_view"));
    if ((next.selection && !valid_workspace_address(*next.selection, *identity_)) ||
        !std::all_of(next.bookmarks.begin(), next.bookmarks.end(),
                     [&](const auto& address) {
                         return valid_workspace_address(address, *identity_);
                     }))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace view state contains an invalid address",
                                 "workspace_view"));
    next.revision = view_state_.revision + 1;
    view_state_ = std::move(next);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> analysis_workspace_t::register_lifecycle_participant(
    std::shared_ptr<workspace_lifecycle_participant_t> participant) {
    if (!participant)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "lifecycle participant is null", "workspace_lifecycle"));
    if (publication_finalizer_active_.load(std::memory_order_acquire)) {
        participant->request_cancel();
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_lifecycle"));
    }
    std::unique_lock lock(state_mutex_);
    if (closing() || closed()) {
        lock.unlock();
        participant->request_cancel();
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_lifecycle"));
    }
    lifecycle_participants_.erase(
        std::remove_if(lifecycle_participants_.begin(), lifecycle_participants_.end(),
                       [](const auto& weak) { return weak.expired(); }),
        lifecycle_participants_.end());
    for (const auto& weak : lifecycle_participants_) {
        if (auto existing = weak.lock(); existing == participant)
            return workspace_result_t<void>::success();
    }
    if (lifecycle_participants_.size() >= 64) {
        lock.unlock();
        participant->request_cancel();
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "lifecycle participant limit is reached",
                                 "workspace_lifecycle"));
    }
    lifecycle_participants_.push_back(std::move(participant));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> analysis_workspace_t::close(
    std::chrono::steady_clock::time_point deadline) {
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_close"));
    std::lock_guard close_lock(close_mutex_);
    {
        std::unique_lock publication_lock(publication_mutex_);
        bool expected = false;
        if (!closing_.compare_exchange_strong(expected, true, std::memory_order_acq_rel) &&
            closed())
            return workspace_result_t<void>::success();
    }
    std::vector<std::shared_ptr<workspace_lifecycle_participant_t>> participants;
    {
        std::lock_guard lock(state_mutex_);
        cancellation_.request_cancel();
        progress_.readiness = workspace_readiness_t::closing;
        progress_.phase = "closing";
        progress_.cancellation_requested = true;
        for (auto& weak : lifecycle_participants_) {
            if (auto participant = weak.lock())
                participants.push_back(std::move(participant));
        }
    }
    for (const auto& participant : participants)
        participant->request_cancel();
    for (const auto& participant : participants) {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                              "workspace close deadline exceeded",
                                              "workspace_close");
            error.deadline = true;
            return workspace_result_t<void>::failure(std::move(error));
        }
        auto result = participant->drain(deadline);
        if (!result)
            return result;
    }
    {
        std::unique_lock run_lock(analysis_run_mutex_);
        if (!analysis_run_cv_.wait_until(run_lock, deadline, [&] {
                return active_analysis_generation_.load(std::memory_order_acquire) == 0;
            })) {
            auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                              "workspace analysis did not drain before close",
                                              "workspace_close");
            error.deadline = true;
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
    {
        std::lock_guard lock(state_mutex_);
        progress_.readiness = workspace_readiness_t::closed;
        progress_.phase = "closed";
        lifecycle_participants_.clear();
        database_.reset();
        overlay_.reset();
        decompiler_.reset();
        persistence_queue_.reset();
    }
    closed_.store(true, std::memory_order_release);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> analysis_workspace_t::install_database(
    std::shared_ptr<workspace_database_t> database_value) {
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_service"));
    std::lock_guard lock(state_mutex_);
    return install_workspace_service(database_, std::move(database_value),
                                     closing() || closed(), "database");
}

workspace_result_t<void> analysis_workspace_t::install_overlay(
    std::shared_ptr<overlay_journal_t> overlay_value) {
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_service"));
    std::lock_guard lock(state_mutex_);
    return install_workspace_service(overlay_, std::move(overlay_value),
                                     closing() || closed(), "overlay");
}

workspace_result_t<void> analysis_workspace_t::install_decompiler(
    std::shared_ptr<decompiler_service_t> decompiler_value) {
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_service"));
    std::lock_guard lock(state_mutex_);
    return install_workspace_service(decompiler_, std::move(decompiler_value),
                                     closing() || closed(), "decompiler");
}

workspace_result_t<void> analysis_workspace_t::install_persistence_queue(
    std::shared_ptr<persistence_queue_t> queue_value) {
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_service"));
    std::lock_guard lock(state_mutex_);
    return install_workspace_service(persistence_queue_, std::move(queue_value),
                                     closing() || closed(), "persistence_queue");
}

workspace_result_t<void> analysis_workspace_t::install_search_index(
    std::shared_ptr<search_index_t> index_value) {
    if (!index_value)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "search index service is null",
                                 "workspace_service"));
    if (publication_finalizer_active_.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(
            publication_finalizer_conflict("workspace_service"));
    std::unique_lock publication_lock(publication_mutex_);
    std::lock_guard state_lock(state_mutex_);
    if (closing() || closed())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace is closing", "workspace_service"));
    const auto current = analysis_publication();
    if (!current || !current->snapshot)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "workspace publication is missing",
                                 "workspace_service"));
    if (current->search_index) {
        if (current->search_index.get() == index_value.get())
            return workspace_result_t<void>::success();
    }
    if (!index_value->matches(current->snapshot) ||
        !index_value->matches(identity_->binary_id(), identity_->load_profile_hash(),
                              current->generation, current->analysis_revision,
                              current->overlay_revision))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "search index does not match the current analysis publication",
                                 "workspace_service"));
    const auto replacement = std::make_shared<const analysis_publication_t>(
        current->snapshot, current->provider, std::move(index_value),
        current->readiness, current->managed_artifacts);
    std::atomic_store_explicit(&publication_state_->publication, replacement,
                               std::memory_order_release);
    return workspace_result_t<void>::success();
}

std::shared_ptr<workspace_database_t> analysis_workspace_t::database() const {
    std::lock_guard lock(state_mutex_);
    return database_;
}

std::shared_ptr<overlay_journal_t> analysis_workspace_t::overlay() const {
    std::lock_guard lock(state_mutex_);
    return overlay_;
}

std::shared_ptr<decompiler_service_t> analysis_workspace_t::decompiler() const {
    std::lock_guard lock(state_mutex_);
    return decompiler_;
}

std::shared_ptr<persistence_queue_t> analysis_workspace_t::persistence_queue() const {
    std::lock_guard lock(state_mutex_);
    return persistence_queue_;
}

std::shared_ptr<search_index_t> analysis_workspace_t::search_index() const {
    const auto publication = analysis_publication();
    return publication ? publication->search_index : nullptr;
}

}
