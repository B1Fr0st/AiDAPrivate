#include "decompiler_ui_integration.hpp"

#include "decompile_batch_orchestrator.hpp"
#include "generation_snapshot_store.hpp"
#include "legacy_document_adapter.hpp"
#include "native_worker_host.hpp"
#include "providers/cli_provider.hpp"
#include "providers/dalvik_ssa.hpp"
#include "providers/jvm_ssa.hpp"

#include "decompiler_contracts.hpp"
#include "pseudocode_renderer.hpp"
#include "typed_ast.hpp"

#include "../flirt/static_recognition_service.hpp"
#include "../workspace/decompiler_feedback.hpp"
#include "../workspace/decompiler_service.hpp"
#include "../../../helpers/diag_log.hpp"
#include "../../../../workers/native_decompiler/snapshot_sidecar.hpp"

#include "../../disasm/ghidra_adapters/aida_arch_map.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <thread>
#include <unordered_map>
#include <utility>
#include <variant>

namespace aida::analysis {
namespace {

using managed_capture_value_t = std::variant<
    std::shared_ptr<const managed_cli::request_t>,
    std::shared_ptr<const jvm_ssa::jvm_method_input_t>,
    std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>;

struct managed_capture_cache_entry_t final {
    managed_capture_value_t value;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    sha256_digest_t provider_hash;
    std::uint64_t byte_size = 0;
    std::uint64_t touch = 0;
};

struct managed_module_snapshot_cache_entry_t final {
    managed_cli::immutable_module_snapshot_t snapshot;
    sha256_digest_t artifact_hash;
    sha256_digest_t provider_hash;
    std::uint64_t provider_offset = 0;
    std::uint64_t provider_size = 0;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t touch = 0;
};

struct native_identity_cache_entry_t {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    std::vector<decompiler_chunk_fingerprint_t> fingerprints;
    sha256_digest_t function_bytes_hash{};
    decompiler_entity_key_t entity{};
    std::string canonical_symbol;
    std::uint64_t function_id = 0;
    std::uint64_t generation = 0, analysis_revision = 0, overlay_revision = 0;
    sha256_digest_t load_profile_hash{};
    sha256_digest_t worker_protocol_hash{};
    std::uint64_t touch = 0;
};

inline constexpr std::size_t k_native_identity_cache_max_entries = 256;

struct ui_state_t final {
    ui_state_t(std::shared_ptr<analysis_workspace_t> workspace_value,
               std::shared_ptr<decompiler_pipeline_service_t> service_value,
               decompiler_ui_integration_config_t config_value)
        : workspace(std::move(workspace_value)),
          service(std::move(service_value)),
          config(std::move(config_value))
    {
    }

    std::shared_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<decompiler_pipeline_service_t> service;
    std::shared_ptr<decompiler_isolated_provider_host_t> pooled_native_host;
    decompiler_ui_integration_config_t config;
    mutable std::mutex metrics_mutex;
    decompiler_ui_integration_metrics_t metrics;
    std::atomic<std::uint64_t> request_counter{0};
    std::optional<decompiler_provider_identity_t> native_provider;
    std::optional<decompiler_provider_identity_t> cli_provider;
    std::optional<decompiler_provider_identity_t> jvm_provider;
    std::optional<decompiler_provider_identity_t> dalvik_provider;
    sha256_digest_t native_worker_protocol_hash;
    sha256_digest_t native_manifest_hash;
    sha256_digest_t managed_manifest_hash;
    sha256_digest_t managed_runtime_manifest_hash;
    std::uint32_t native_worker_protocol_version = 0;
    mutable std::mutex managed_capture_mutex;
    std::unordered_map<std::string, managed_capture_cache_entry_t>
        managed_capture_cache;
    std::unordered_map<std::string, managed_module_snapshot_cache_entry_t>
        managed_module_snapshot_cache;
    std::unordered_map<std::string, std::uint64_t>
        managed_module_snapshot_inflight;
    std::condition_variable managed_capture_condition;
    std::uint64_t managed_capture_cache_bytes = 0;
    std::uint64_t managed_module_snapshot_cache_bytes = 0;
    std::uint64_t managed_module_snapshot_reserved_bytes = 0;
    std::uint64_t managed_capture_clock = 0;
    std::uint64_t managed_cache_epoch = 0;
    mutable std::mutex native_identity_mutex;
    std::unordered_map<std::uint64_t, native_identity_cache_entry_t>
        native_identity_cache;
    std::uint64_t native_identity_clock = 0;
};

struct production_cache_entry_t {
    std::shared_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<decompiler_ui_integration_t> integration;
    std::uint64_t touch = 0;
};

std::mutex production_cache_mutex;
std::unordered_map<const analysis_workspace_t*, production_cache_entry_t> production_cache;
std::uint64_t production_cache_clock = 0;
constexpr std::size_t maximum_cached_production_integrations = 32;

const decompiler_profile_budget_t& profile_budget(
    const decompiler_profile_policy_t& policy,
    decompiler_profile_id_t profile) noexcept {
    switch (profile) {
    case decompiler_profile_id_t::fast:
        return policy.fast;
    case decompiler_profile_id_t::thorough:
        return policy.thorough;
    case decompiler_profile_id_t::balanced:
    default:
        return policy.balanced;
    }
}

std::string managed_capture_key(
    const generation_bound_decompiler_entity_t& binding) {
    return binding.binary_id.to_hex() + "|" +
        binding.load_profile_hash.to_hex() + "|" +
        binding.provider_hash.to_hex() + "|" +
        binding.artifact_hash.to_hex() + "|" +
        std::to_string(binding.generation) + "|" +
        std::to_string(binding.analysis_revision) + "|" +
        std::to_string(binding.overlay_revision) + "|" +
        std::to_string(binding.type_graph_revision) + "|" +
        stable_serialization_hash(binding.entity).to_hex();
}

std::string managed_module_snapshot_key(
    const generation_bound_decompiler_entity_t& binding,
    const managed_artifact_binding_record_t& artifact) {
    return binding.binary_id.to_hex() + "|" +
        binding.provider_hash.to_hex() + "|" +
        artifact.artifact_hash.to_hex() + "|" +
        std::to_string(artifact.provider_offset) + "|" +
        std::to_string(artifact.provider_size) + "|" +
        std::to_string(binding.generation);
}

std::string managed_embedded_logical_identity(
    const analysis_publication_t& publication,
    const managed_artifact_binding_record_t& artifact) {
    std::string container = publication.provider->identity().normalized_source;
    const auto member_separator = container.find("!/");
    if (member_separator != std::string::npos)
        container.resize(member_separator);
    const auto embedded_separator = container.find("#member:");
    if (embedded_separator != std::string::npos)
        container.resize(embedded_separator);
    std::string member;
    if (publication.provider->member_metadata()) {
        member = publication.provider->member_metadata()->normalized_member_path;
    } else {
        member = "artifact/" + std::to_string(artifact.artifact_ordinal) +
            "/" + artifact.artifact_hash.to_hex() + ".managed-pe";
    }
    return container + "#member:" + member;
}

workspace_error_t ui_request_error(
    const workspace_error_code_t code,
    std::string message,
    std::string phase)
{
    return make_workspace_error(code, std::move(message), std::move(phase));
}

workspace_result_t<void> validate_managed_cli_preflight(
    const managed_cli::request_t& request,
    const cancellation_token_t& cancel) {
    if (request.module_source.kind ==
        managed_cli::module_source_kind_t::embedded_member) {
        const auto serialized = managed_cli::serialize_request(request);
        if (!serialized)
            return workspace_result_t<void>::failure(serialized.error());
        return workspace_result_t<void>::success();
    }
    if (request.module_source.kind !=
        managed_cli::module_source_kind_t::regular_file) {
        return workspace_result_t<void>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "managed CLI module source kind is invalid",
                "decompiler_ui.cli.preflight.source"));
    }
    if (request.module_snapshot || request.module_source.module_size != 0 ||
        request.module_source.filesystem_path.empty() ||
        request.module_source.logical_identity !=
            request.module_source.filesystem_path ||
        request.module_source.module_hash.empty() || request.entity_hash.empty() ||
        request.worker.runtime_manifest_hash.empty() || request.contract_hash.empty() ||
        !request.cache_identity.empty() ||
        !request.request_binding_hash.empty()) {
        return workspace_result_t<void>::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "managed CLI regular-file request is not an unbound canonical request",
                "decompiler_ui.cli.preflight.regular"));
    }
    auto canonical = managed_cli::make_request(
        request.sequence, request.request_id,
        request.module_source.filesystem_path, request.entity,
        request.workspace_generation, request.type_graph_revision,
        request.profile, request.worker, cancel);
    if (!canonical)
        return workspace_result_t<void>::failure(canonical.error());
    const auto& expected = canonical.value();
    if (expected.module_snapshot || expected.module_source.module_size != 0 ||
        expected.module_source.kind != request.module_source.kind ||
        expected.module_source.logical_identity !=
            request.module_source.logical_identity ||
        expected.module_source.filesystem_path !=
            request.module_source.filesystem_path ||
        expected.module_source.module_hash != request.module_source.module_hash ||
        expected.entity_hash != request.entity_hash ||
        expected.worker.runtime_manifest_hash !=
            request.worker.runtime_manifest_hash ||
        expected.contract_hash != request.contract_hash ||
        !expected.cache_identity.empty() ||
        !expected.request_binding_hash.empty()) {
        return workspace_result_t<void>::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "managed CLI regular-file request does not match its canonical contract",
                "decompiler_ui.cli.preflight.regular"));
    }
    return workspace_result_t<void>::success();
}

void erase_managed_captures_for_snapshot_locked(
    ui_state_t& state,
    const std::shared_ptr<const std::vector<std::uint8_t>>& bytes) {
    for (auto iterator = state.managed_capture_cache.begin();
         iterator != state.managed_capture_cache.end();) {
        const auto* request = std::get_if<
            std::shared_ptr<const managed_cli::request_t>>(
                &iterator->second.value);
        if (request && *request && (*request)->module_snapshot == bytes) {
            state.managed_capture_cache_bytes -= iterator->second.byte_size;
            iterator = state.managed_capture_cache.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

void erase_managed_module_snapshot_locked(
    ui_state_t& state,
    const std::string& key) {
    const auto found = state.managed_module_snapshot_cache.find(key);
    if (found == state.managed_module_snapshot_cache.end())
        return;
    erase_managed_captures_for_snapshot_locked(
        state, found->second.snapshot.bytes);
    state.managed_module_snapshot_cache_bytes -= found->second.provider_size;
    state.managed_module_snapshot_cache.erase(found);
}

bool erase_oldest_managed_capture_locked(ui_state_t& state) {
    if (state.managed_capture_cache.empty())
        return false;
    const auto oldest = std::min_element(
        state.managed_capture_cache.begin(),
        state.managed_capture_cache.end(),
        [](const auto& left, const auto& right) {
            return left.second.touch < right.second.touch;
        });
    state.managed_capture_cache_bytes -= oldest->second.byte_size;
    state.managed_capture_cache.erase(oldest);
    return true;
}

bool erase_oldest_managed_module_snapshot_locked(ui_state_t& state) {
    if (state.managed_module_snapshot_cache.empty())
        return false;
    const auto oldest = std::min_element(
        state.managed_module_snapshot_cache.begin(),
        state.managed_module_snapshot_cache.end(),
        [](const auto& left, const auto& right) {
            return left.second.touch < right.second.touch;
        });
    const auto key = oldest->first;
    erase_managed_module_snapshot_locked(state, key);
    return true;
}

workspace_result_t<managed_cli::immutable_module_snapshot_t>
acquire_managed_cli_snapshot(
    ui_state_t& state,
    const std::shared_ptr<const analysis_publication_t>& publication,
    const generation_bound_decompiler_entity_t& binding,
    const managed_artifact_binding_record_t& artifact,
    const cancellation_token_t& cancel) {
    const auto key = managed_module_snapshot_key(binding, artifact);
    std::uint64_t reservation_epoch = 0;
    for (;;) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
                ui_request_error(cancel.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "managed CLI snapshot acquisition was cancelled",
                    "decompiler_ui.entity.capture.cli.snapshot"));
        std::unique_lock lock(state.managed_capture_mutex);
        for (auto iterator = state.managed_module_snapshot_cache.begin();
             iterator != state.managed_module_snapshot_cache.end();) {
            const auto stale =
                iterator->second.generation != publication->generation ||
                iterator->second.analysis_revision != publication->analysis_revision ||
                iterator->second.overlay_revision != publication->overlay_revision ||
                iterator->second.provider_hash != binding.provider_hash;
            if (!stale) {
                ++iterator;
                continue;
            }
            const auto stale_key = iterator->first;
            ++iterator;
            erase_managed_module_snapshot_locked(state, stale_key);
        }
        const auto found = state.managed_module_snapshot_cache.find(key);
        if (found != state.managed_module_snapshot_cache.end()) {
            if (found->second.artifact_hash != artifact.artifact_hash ||
                found->second.provider_offset != artifact.provider_offset ||
                found->second.provider_size != artifact.provider_size)
                return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
                    ui_request_error(workspace_error_code_t::integrity_failure,
                        "managed CLI snapshot cache identity collided",
                        "decompiler_ui.entity.capture.cli.snapshot"));
            found->second.touch = ++state.managed_capture_clock;
            return workspace_result_t<managed_cli::immutable_module_snapshot_t>::success(
                found->second.snapshot);
        }
        if (state.managed_module_snapshot_inflight.find(key) !=
            state.managed_module_snapshot_inflight.end()) {
            state.managed_capture_condition.wait_for(
                lock, std::chrono::milliseconds(10));
            continue;
        }
        const auto maximum_bytes = state.config.max_managed_capture_bytes;
        const auto entry_limit = state.config.max_managed_capture_cache_entries;
        if (artifact.provider_size == 0 ||
            artifact.provider_size > maximum_bytes ||
            artifact.provider_size > managed_cli::k_managed_cli_maximum_module_bytes)
            return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
                ui_request_error(workspace_error_code_t::limit_exceeded,
                    "managed CLI artifact exceeds the immutable snapshot budget",
                    "decompiler_ui.entity.capture.cli.snapshot"));
        const auto has_capacity = [&]() {
            const auto entry_count = state.managed_module_snapshot_cache.size() +
                state.managed_module_snapshot_inflight.size();
            const auto used_bytes = state.managed_capture_cache_bytes +
                state.managed_module_snapshot_cache_bytes +
                state.managed_module_snapshot_reserved_bytes;
            return entry_count < entry_limit && used_bytes <= maximum_bytes &&
                artifact.provider_size <= maximum_bytes - used_bytes;
        };
        while (!has_capacity()) {
            bool evicted = false;
            if (state.managed_module_snapshot_cache.size() +
                    state.managed_module_snapshot_inflight.size() >= entry_limit)
                evicted = erase_oldest_managed_module_snapshot_locked(state);
            if (!evicted && state.managed_capture_cache_bytes != 0)
                evicted = erase_oldest_managed_capture_locked(state);
            if (!evicted)
                evicted = erase_oldest_managed_module_snapshot_locked(state);
            if (evicted)
                continue;
            if (!state.managed_module_snapshot_inflight.empty()) {
                state.managed_capture_condition.wait_for(
                    lock, std::chrono::milliseconds(10));
                if (cancel.stop_requested())
                    break;
                continue;
            }
            return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
                ui_request_error(workspace_error_code_t::limit_exceeded,
                    "managed CLI snapshot cache cannot satisfy its memory budget",
                    "decompiler_ui.entity.capture.cli.snapshot"));
        }
        if (cancel.stop_requested())
            continue;
        state.managed_module_snapshot_inflight.emplace(key, artifact.provider_size);
        state.managed_module_snapshot_reserved_bytes += artifact.provider_size;
        reservation_epoch = state.managed_cache_epoch;
        break;
    }

    const auto release_reservation = [&]() {
        std::lock_guard lock(state.managed_capture_mutex);
        const auto inflight = state.managed_module_snapshot_inflight.find(key);
        if (inflight != state.managed_module_snapshot_inflight.end()) {
            state.managed_module_snapshot_reserved_bytes -= inflight->second;
            state.managed_module_snapshot_inflight.erase(inflight);
        }
        state.managed_capture_condition.notify_all();
    };

    auto captured = capture_managed_artifact_snapshot(
        *publication, binding, artifact.provider_size, cancel);
    if (!captured) {
        release_reservation();
        return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
            captured.error());
    }
    workspace_result_t<managed_cli::immutable_module_snapshot_t> snapshot =
        workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "managed CLI snapshot allocation failed",
                "decompiler_ui.entity.capture.cli.snapshot"));
    try {
        auto captured_bytes = captured.take_value();
        std::vector<std::uint8_t> bytes(
            captured_bytes->begin(), captured_bytes->end());
        captured_bytes.reset();
        snapshot = managed_cli::make_immutable_module_snapshot(
            std::move(bytes), cancel);
    } catch (const std::bad_alloc&) {
        release_reservation();
        return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "managed CLI snapshot allocation failed",
                "decompiler_ui.entity.capture.cli.snapshot"));
    }
    if (!snapshot) {
        release_reservation();
        return snapshot;
    }
    if (snapshot.value().hash != artifact.artifact_hash) {
        release_reservation();
        return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "managed CLI snapshot hash changed during capture",
                "decompiler_ui.entity.capture.cli.snapshot"));
    }

    std::unique_lock lock(state.managed_capture_mutex);
    const auto inflight = state.managed_module_snapshot_inflight.find(key);
    if (inflight != state.managed_module_snapshot_inflight.end()) {
        state.managed_module_snapshot_reserved_bytes -= inflight->second;
        state.managed_module_snapshot_inflight.erase(inflight);
    }
    if (state.managed_cache_epoch != reservation_epoch ||
        state.workspace->analysis_publication() != publication) {
        lock.unlock();
        state.managed_capture_condition.notify_all();
        return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
            ui_request_error(workspace_error_code_t::target_stale,
                "workspace changed during managed CLI snapshot capture",
                "decompiler_ui.entity.capture.cli.snapshot"));
    }
    managed_module_snapshot_cache_entry_t entry;
    entry.snapshot = snapshot.value();
    entry.artifact_hash = artifact.artifact_hash;
    entry.provider_hash = binding.provider_hash;
    entry.provider_offset = artifact.provider_offset;
    entry.provider_size = artifact.provider_size;
    entry.generation = binding.generation;
    entry.analysis_revision = binding.analysis_revision;
    entry.overlay_revision = binding.overlay_revision;
    entry.touch = ++state.managed_capture_clock;
    try {
        const auto insertion = state.managed_module_snapshot_cache.emplace(
            key, std::move(entry));
        if (insertion.second) {
            state.managed_module_snapshot_cache_bytes += artifact.provider_size;
        } else {
            snapshot = workspace_result_t<managed_cli::immutable_module_snapshot_t>::success(
                insertion.first->second.snapshot);
        }
    } catch (const std::bad_alloc&) {
        lock.unlock();
        state.managed_capture_condition.notify_all();
        return workspace_result_t<managed_cli::immutable_module_snapshot_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "managed CLI snapshot cache allocation failed",
                "decompiler_ui.entity.capture.cli.snapshot"));
    }
    lock.unlock();
    state.managed_capture_condition.notify_all();
    return snapshot;
}

bool checked_add(const std::uint64_t left, const std::uint64_t right, std::uint64_t& output) noexcept
{
    if (right > (std::numeric_limits<std::uint64_t>::max)() - left)
        return false;
    output = left + right;
    return true;
}

bool address_matches(
    const address_t& address,
    const std::uint64_t requested,
    const std::uint64_t image_base) noexcept
{
    if (address.space != address_space_id_t::relative_virtual &&
        address.space != address_space_id_t::virtual_address &&
        address.space != address_space_id_t::live_virtual)
        return false;
    if (address.value == requested)
        return true;
    std::uint64_t runtime = 0;
    if (address.space == address_space_id_t::relative_virtual)
        return checked_add(image_base, address.value, runtime) && runtime == requested;
    return (address.space == address_space_id_t::virtual_address ||
            address.space == address_space_id_t::live_virtual) &&
           address.value >= image_base && address.value - image_base == requested;
}

std::optional<std::uint64_t> relative_value(
    const address_t& address,
    const std::uint64_t image_base) noexcept
{
    if (address.space == address_space_id_t::relative_virtual)
        return address.value;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) &&
        address.value >= image_base)
        return address.value - image_base;
    return std::nullopt;
}

std::optional<std::uint64_t> provider_offset_for_range(
    const workspace_image_t& image,
    const std::uint64_t relative_begin,
    const std::uint64_t size) noexcept
{
    std::uint64_t relative_end = 0;
    if (size == 0 || !checked_add(relative_begin, size, relative_end))
        return std::nullopt;
    for (const auto& mapping : image.address_mappings) {
        if (mapping.source_space != address_space_id_t::file_offset ||
            mapping.target_space != address_space_id_t::relative_virtual)
            continue;
        std::uint64_t mapping_end = 0;
        if (!checked_add(mapping.target_start, mapping.size, mapping_end) ||
            relative_begin < mapping.target_start || relative_end > mapping_end)
            continue;
        std::uint64_t provider_offset = 0;
        if (!checked_add(mapping.source_start,
                relative_begin - mapping.target_start, provider_offset))
            return std::nullopt;
        std::uint64_t provider_end = 0;
        if (!checked_add(provider_offset, size, provider_end) ||
            provider_end > image.provider_size)
            return std::nullopt;
        return provider_offset;
    }
    return std::nullopt;
}

const function_record_t* resolve_function(
    const analysis_snapshot_t& snapshot,
    const std::uint64_t requested,
    const std::uint64_t image_base) noexcept
{
    const auto found = std::find_if(snapshot.functions.begin(), snapshot.functions.end(),
        [requested, image_base](const function_record_t& function) {
            return address_matches(function.start, requested, image_base);
        });
    return found == snapshot.functions.end() ? nullptr : &*found;
}

std::string resolve_function_symbol(
    const analysis_snapshot_t& snapshot,
    const function_record_t& function)
{
    if (function.symbol_id) {
        const auto symbol = std::find_if(snapshot.symbols.begin(), snapshot.symbols.end(),
            [&function](const symbol_record_t& current) {
                return current.id == *function.symbol_id;
            });
        if (symbol != snapshot.symbols.end() && !symbol->name.empty())
            return symbol->name;
    }
    return "function_" + std::to_string(function.id);
}

decompiler_fact_provenance_t decompiler_provenance(
    const metadata_provenance_t value) noexcept
{
    switch (value) {
    case metadata_provenance_t::debug_metadata:
        return decompiler_fact_provenance_t::debug_metadata;
    case metadata_provenance_t::rtti:
    case metadata_provenance_t::vtable_validation:
        return decompiler_fact_provenance_t::rtti;
    case metadata_provenance_t::objective_c_metadata:
        return decompiler_fact_provenance_t::objc_metadata;
    case metadata_provenance_t::swift_metadata:
        return decompiler_fact_provenance_t::swift_metadata;
    case metadata_provenance_t::managed_metadata:
        return decompiler_fact_provenance_t::loader_metadata;
    case metadata_provenance_t::decoded:
    case metadata_provenance_t::relocation:
    case metadata_provenance_t::loader_symbol:
    case metadata_provenance_t::import_metadata:
    case metadata_provenance_t::export_metadata:
        return decompiler_fact_provenance_t::loader_metadata;
    case metadata_provenance_t::unknown:
        return decompiler_fact_provenance_t::unknown;
    }
    return decompiler_fact_provenance_t::unknown;
}

decompiler_type_kind_t decompiler_type_kind(
    const symbol_type_candidate_record_t& value) noexcept
{
    if (value.explicitly_unknown)
        return decompiler_type_kind_t::unknown;
    switch (value.kind) {
    case symbol_type_candidate_kind_t::function_prototype:
    case symbol_type_candidate_kind_t::import_prototype:
    case symbol_type_candidate_kind_t::managed_method:
        return decompiler_type_kind_t::function;
    case symbol_type_candidate_kind_t::pointer_object:
    case symbol_type_candidate_kind_t::virtual_table:
        return decompiler_type_kind_t::pointer;
    case symbol_type_candidate_kind_t::rtti_type:
    case symbol_type_candidate_kind_t::type_information:
    case symbol_type_candidate_kind_t::objective_c_class:
    case symbol_type_candidate_kind_t::swift_type:
    case symbol_type_candidate_kind_t::managed_type:
        return decompiler_type_kind_t::class_type;
    case symbol_type_candidate_kind_t::objective_c_protocol:
    case symbol_type_candidate_kind_t::swift_protocol:
        return decompiler_type_kind_t::interface_type;
    case symbol_type_candidate_kind_t::global_object:
    case symbol_type_candidate_kind_t::managed_field:
    case symbol_type_candidate_kind_t::debug_type:
    case symbol_type_candidate_kind_t::metadata_region:
    case symbol_type_candidate_kind_t::objective_c_selector:
        return decompiler_type_kind_t::unknown;
    }
    return decompiler_type_kind_t::unknown;
}

decompiler_type_edge_kind_t decompiler_edge_kind(
    const type_reference_kind_t value) noexcept
{
    switch (value) {
    case type_reference_kind_t::inheritance:
        return decompiler_type_edge_kind_t::base;
    case type_reference_kind_t::virtual_table_slot:
        return decompiler_type_edge_kind_t::member;
    case type_reference_kind_t::protocol_conformance:
        return decompiler_type_edge_kind_t::constraint;
    case type_reference_kind_t::definition:
    case type_reference_kind_t::metadata_reference:
    case type_reference_kind_t::managed_reference:
        return decompiler_type_edge_kind_t::alias;
    }
    return decompiler_type_edge_kind_t::alias;
}

std::optional<source_coordinate_t> type_coordinate(
    const std::optional<address_t>& address,
    const decompiler_entity_key_t& entity,
    const std::uint64_t generation)
{
    if (!address || address->value == (std::numeric_limits<std::uint64_t>::max)())
        return std::nullopt;
    source_coordinate_t coordinate;
    coordinate.layer = decompiler_coordinate_layer_t::provider_ir;
    coordinate.workspace_generation = generation;
    coordinate.entity = entity;
    auto end = *address;
    ++end.value;
    coordinate.address_range = decompiler_address_range_t{*address, end};
    return coordinate;
}

type_graph::type_seed_batch_t workspace_type_evidence(
    const analysis_snapshot_t& snapshot,
    const decompiler_entity_key_t& entity,
    const std::vector<std::pair<std::uint64_t, std::uint64_t>>& spans,
    const std::uint64_t image_base)
{
    constexpr std::size_t maximum_candidates = 4096;
    constexpr std::size_t maximum_references = 16384;
    const auto in_function = [&](const std::optional<address_t>& address) {
        if (!address)
            return false;
        const auto relative = relative_value(*address, image_base);
        if (!relative)
            return false;
        return std::any_of(spans.begin(), spans.end(), [&](const auto& span) {
            return *relative >= span.first && *relative < span.second;
        });
    };
    type_graph::type_seed_batch_t batch;
    batch.source = decompiler_fact_provenance_t::loader_metadata;
    batch.source_label = "workspace_rich_type_facts";
    std::unordered_map<entity_id_t, std::size_t> selected;
    selected.reserve((std::min)(snapshot.rich_facts.type_candidates.size(), maximum_candidates));
    for (const auto& source : snapshot.rich_facts.type_candidates) {
        if (!in_function(source.address) && !in_function(source.related_address))
            continue;
        if (batch.candidates.size() >= maximum_candidates)
            break;
        type_graph::type_candidate_t candidate;
        candidate.kind = decompiler_type_kind(source);
        candidate.canonical_name = source.canonical_type.empty()
            ? "unknown." + source.display_name + "." + std::to_string(source.id)
            : source.canonical_type;
        candidate.display_name = source.display_name;
        candidate.confidence = source.confidence;
        candidate.provenance = decompiler_provenance(source.provenance);
        candidate.source_detail = source.source_key;
        if (const auto coordinate = type_coordinate(
                source.address ? source.address : source.related_address,
                entity, snapshot.generation))
            candidate.coordinate = *coordinate;
        selected.emplace(source.id, batch.candidates.size());
        batch.candidates.push_back(std::move(candidate));
    }
    std::size_t reference_count = 0;
    for (const auto& reference : snapshot.rich_facts.type_references) {
        if (reference_count >= maximum_references)
            break;
        const auto source = selected.find(reference.source_entity);
        const auto target = selected.find(reference.target_entity);
        if (source == selected.end() || target == selected.end() || source == target)
            continue;
        type_graph::type_edge_candidate_t edge;
        edge.kind = decompiler_edge_kind(reference.kind);
        edge.target_canonical_name = batch.candidates[target->second].canonical_name;
        edge.stable_name = reference.source_key;
        edge.local_ordinal = static_cast<std::uint32_t>(
            batch.candidates[source->second].edges.size() + 1);
        edge.confidence = reference.confidence;
        edge.provenance = decompiler_provenance(reference.provenance);
        edge.source_detail = reference.source_key;
        batch.candidates[source->second].edges.push_back(std::move(edge));
        ++reference_count;
    }
    return batch;
}

workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>> function_spans(
    const analysis_snapshot_t& snapshot,
    const function_record_t& function,
    const std::uint64_t image_base,
    const std::size_t max_function_chunks)
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    if (function.chunk_count != 0) {
        const auto first = static_cast<std::uint64_t>(function.first_chunk);
        std::uint64_t end = 0;
        if (function.chunk_count > max_function_chunks) {
            return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                ui_request_error(workspace_error_code_t::limit_exceeded,
                    "decompiler UI function has too many chunks", "decompiler_ui.identity.chunks"));
        }
        if (!checked_add(first, function.chunk_count, end) ||
            end > snapshot.function_chunks.size()) {
            return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                ui_request_error(workspace_error_code_t::integrity_failure,
                    "decompiler UI function chunk range is invalid", "decompiler_ui.identity.chunks"));
        }
        spans.reserve(function.chunk_count);
        for (std::uint64_t index = first; index < end; ++index) {
            const auto& chunk = snapshot.function_chunks[static_cast<std::size_t>(index)];
            if (chunk.function_id != function.id) {
                return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                    ui_request_error(workspace_error_code_t::integrity_failure,
                        "decompiler UI function chunk ownership is invalid",
                        "decompiler_ui.identity.chunks"));
            }
            const auto begin = relative_value(chunk.start, image_base);
            const auto chunk_end = relative_value(chunk.end, image_base);
            if (!begin || !chunk_end) {
                return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                    ui_request_error(workspace_error_code_t::integrity_failure,
                        "decompiler UI function chunk is not image-relative",
                        "decompiler_ui.identity.chunks"));
            }
            spans.emplace_back(*begin, *chunk_end);
        }
    } else {
        const auto begin = relative_value(function.start, image_base);
        const auto end = relative_value(function.end, image_base);
        if (!begin || !end) {
            return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                ui_request_error(workspace_error_code_t::invalid_argument,
                    "decompiler UI function range is not image-relative",
                    "decompiler_ui.identity.range"));
        }
        spans.emplace_back(*begin, *end);
    }
    std::sort(spans.begin(), spans.end());
    std::vector<std::pair<std::uint64_t, std::uint64_t>> merged;
    merged.reserve(spans.size());
    for (const auto& span : spans) {
        if (span.first >= span.second) {
            return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                ui_request_error(workspace_error_code_t::invalid_argument,
                    "decompiler UI function chunk is empty or reversed",
                    "decompiler_ui.identity.chunks"));
        }
        if (!merged.empty() && span.first < merged.back().second) {
            return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                ui_request_error(workspace_error_code_t::integrity_failure,
                    "decompiler UI function chunks overlap",
                    "decompiler_ui.identity.chunks"));
        }
        if (!merged.empty() && span.first == merged.back().second) {
            merged.back().second = span.second;
        } else {
            merged.push_back(span);
        }
    }
    return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::success(
        std::move(merged));
}

bool valid_language_for_image(
    const decompiler_language_identity_t& language,
    const workspace_image_t& image) noexcept
{
    return !language.language_id.empty() && !language.language_version.empty() &&
           !language.compiler_spec_id.empty() && !language.language_spec_hash.empty() &&
           language.architecture == image.architecture &&
           language.mode == image.architecture_mode && language.endian == image.endian;
}

bool canonicalize_dependencies(std::vector<decompiler_dependency_version_t>& dependencies)
{
    std::sort(dependencies.begin(), dependencies.end(),
        [](const decompiler_dependency_version_t& left,
           const decompiler_dependency_version_t& right) {
            return left.name < right.name;
        });
    if (dependencies.empty())
        return false;
    std::string previous;
    for (const auto& dependency : dependencies) {
        if (dependency.name.empty() || dependency.version.empty() ||
            dependency.content_hash.empty() ||
            (!previous.empty() && dependency.name == previous))
            return false;
        previous = dependency.name;
    }
    return true;
}

workspace_result_t<std::vector<decompiler_dependency_version_t>>
native_dependency_identities(
    const ui_state_t& state,
    const decompiler_language_identity_t& language)
{
    if (!state.native_provider ||
        state.native_provider->provider_name.empty() ||
        state.native_provider->provider_version.empty() ||
        state.native_provider->provider_binary_hash.empty() ||
        state.native_provider->worker_build_id.empty() ||
        state.native_provider->worker_build_hash.empty() ||
        state.native_worker_protocol_hash.empty() ||
        state.native_manifest_hash.empty() ||
        state.native_worker_protocol_version != k_decompiler_worker_protocol_version ||
        language.language_version.empty() || language.compiler_spec_id.empty() ||
        language.language_spec_hash.empty()) {
        return workspace_result_t<std::vector<decompiler_dependency_version_t>>::failure(
            ui_request_error(workspace_error_code_t::provider_unavailable,
                "production native decompiler dependency identities are unavailable",
                "decompiler_ui.native.dependencies"));
    }
    std::vector<decompiler_dependency_version_t> dependencies{
        {"aida.native.provider",
            state.native_provider->provider_version + "|" +
                state.native_provider->worker_build_id,
            state.native_provider->provider_binary_hash},
        {"aida.native.worker.manifest",
            std::to_string(native_worker::k_native_worker_manifest_schema_version),
            state.native_manifest_hash},
        {"aida.native.worker.protocol",
            std::to_string(state.native_worker_protocol_version),
            state.native_worker_protocol_hash},
        {"ghidra.language",
            language.language_version + "|" + language.compiler_spec_id,
            language.language_spec_hash}};
    if (!canonicalize_dependencies(dependencies)) {
        return workspace_result_t<std::vector<decompiler_dependency_version_t>>::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "production native decompiler dependency identities are invalid",
                "decompiler_ui.native.dependencies"));
    }
    return workspace_result_t<std::vector<decompiler_dependency_version_t>>::success(
        std::move(dependencies));
}

bool equal_provider_identity(
    const decompiler_provider_identity_t& left,
    const decompiler_provider_identity_t& right) noexcept
{
    return left.provider == right.provider &&
           left.provider_name == right.provider_name &&
           left.provider_version == right.provider_version &&
           left.provider_binary_hash == right.provider_binary_hash &&
           left.worker_build_id == right.worker_build_id &&
           left.worker_build_hash == right.worker_build_hash;
}

bool equal_language_identity(
    const decompiler_language_identity_t& left,
    const decompiler_language_identity_t& right) noexcept
{
    return left.language_id == right.language_id &&
           left.language_version == right.language_version &&
           left.compiler_spec_id == right.compiler_spec_id &&
           left.language_spec_hash == right.language_spec_hash &&
           left.architecture == right.architecture &&
           left.mode == right.mode && left.endian == right.endian;
}

decompiler_language_identity_t native_language_identity(
    const ghidra_adapter::ghidra_language_spec_t& language,
    const workspace_image_t& image)
{
    decompiler_language_identity_t result;
    result.language_id = language.language_id;
    result.language_version = "ghidra-staged-v1";
    result.compiler_spec_id = language.compiler_spec_id;
    result.language_spec_hash = stable_serialization_hash(
        language.language_id + "|" + language.compiler_spec_id);
    result.architecture = image.architecture;
    result.mode = image.architecture_mode;
    result.endian = image.endian;
    return result;
}

bool publication_matches_request(
    const analysis_workspace_t& workspace,
    const decompiler_pipeline_request_t& request) noexcept
{
    const auto publication = workspace.analysis_publication();
    return !workspace.closing() && !workspace.closed() && publication &&
           publication->coherent_with(workspace.identity()) && publication->snapshot &&
           publication->generation == request.workspace_generation &&
           publication->analysis_revision == request.analysis_revision &&
           publication->overlay_revision == request.cache_identity.overlay_revision &&
           publication->load_profile_hash == request.cache_identity.loader_layout_hash;
}

std::uint64_t native_function_byte_size(
    const analysis_snapshot_t& snapshot,
    const function_record_t& function) noexcept
{
    std::uint64_t total = 0;
    for (const auto& chunk : function.chunks) {
        if (chunk.rva_end > chunk.rva_start)
            total += chunk.rva_end - chunk.rva_start;
    }
    if (total == 0 && function.chunk_count != 0 &&
        function.first_chunk <= snapshot.function_chunks.size() &&
        function.chunk_count <= snapshot.function_chunks.size() - function.first_chunk) {
        for (std::uint32_t index = 0; index < function.chunk_count; ++index) {
            const auto& chunk = snapshot.function_chunks[function.first_chunk + index];
            if (chunk.end.value >= chunk.start.value)
                total += chunk.end.value - chunk.start.value;
        }
    }
    if (total == 0 && function.end.value >= function.start.value)
        total = function.end.value - function.start.value;
    return total;
}

struct native_generation_context_entry_t {
    std::shared_ptr<const decompiler_provider_context_t> context;
    sha256_digest_t snapshot_hash;
    std::uint64_t touch = 0;
};

std::mutex native_generation_context_mutex;
std::unordered_map<std::string, native_generation_context_entry_t> native_generation_context_cache;
std::uint64_t native_generation_context_clock = 0;
constexpr std::size_t k_native_generation_context_cache_limit = 8;

const char* native_feedback_address_space_text(const address_space_id_t space) noexcept
{
    switch (space) {
    case address_space_id_t::virtual_address:
        return "virtual-address";
    case address_space_id_t::relative_virtual:
        return "relative-virtual";
    case address_space_id_t::file_offset:
        return "file-offset";
    case address_space_id_t::live_virtual:
        return "live-virtual";
    }
    return "unknown";
}

void feedback_digest_u64(std::string& output, const std::uint64_t value)
{
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffU));
}

void feedback_digest_text(std::string& output, const std::string& value)
{
    feedback_digest_u64(output, value.size());
    output.append(value);
}

sha256_digest_t compute_native_feedback_digest(
    analysis_workspace_t& workspace,
    const analysis_publication_t& publication)
{
    sha256_digest_t digest;
    auto ws_decompiler = workspace.decompiler();
    if (!ws_decompiler)
        return digest;
    const auto feedback = ws_decompiler->feedback_model();
    if (!feedback)
        return digest;
    decompiler_feedback_scope_key_t scope;
    scope.workspace_id = workspace.identity().binary_id().to_hex();
    scope.binary_id = scope.workspace_id;
    scope.address_space_id = native_feedback_address_space_text(
        address_space_id_t::relative_virtual);
    scope.architecture_id = "architecture-" + std::to_string(
        static_cast<unsigned int>(workspace.identity().architecture()));
    scope.generation = publication.generation;
    scope.overlay_revision = publication.overlay_revision;
    scope.type_revision = publication.analysis_revision;
    const auto snapshot = feedback->snapshot(scope);
    if (!snapshot.exists || snapshot.facts.empty())
        return digest;
    std::string canonical;
    canonical.reserve(4096);
    for (const auto& fact : snapshot.facts) {
        const auto kind = static_cast<std::uint64_t>(fact.kind);
        const auto* name = std::get_if<decompiler_feedback_name_t>(&fact.payload);
        const auto* comment = std::get_if<decompiler_feedback_comment_t>(&fact.payload);
        const auto* type_assignment = std::get_if<decompiler_feedback_type_assignment_t>(&fact.payload);
        const auto* prototype = std::get_if<decompiler_feedback_prototype_t>(&fact.payload);
        const auto* storage = std::get_if<decompiler_feedback_storage_t>(&fact.payload);
        if (!name && !comment && !type_assignment && !prototype && !storage)
            continue;
        feedback_digest_u64(canonical, kind);
        feedback_digest_text(canonical, fact.logical_key);
        feedback_digest_text(canonical, fact.fact_id);
        if (name) {
            feedback_digest_u64(canonical, name->address);
            feedback_digest_text(canonical, name->identifier);
        } else if (comment) {
            feedback_digest_u64(canonical, comment->address);
            feedback_digest_text(canonical, comment->text);
        } else if (type_assignment) {
            feedback_digest_u64(canonical, type_assignment->address);
            feedback_digest_text(canonical, type_assignment->type_name);
        } else if (prototype) {
            feedback_digest_u64(canonical, prototype->function);
            feedback_digest_text(canonical, prototype->declaration);
            feedback_digest_text(canonical, prototype->calling_convention);
        } else {
            feedback_digest_u64(canonical, storage->address);
            feedback_digest_u64(canonical, static_cast<std::uint64_t>(storage->stack_offset));
            feedback_digest_u64(canonical, storage->byte_size);
            feedback_digest_text(canonical, storage->identifier);
            feedback_digest_text(canonical, storage->type_name);
        }
    }
    if (canonical.empty())
        return digest;
    return stable_serialization_hash(canonical);
}

workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>
repack_context_with_feedback_digest(
    const std::shared_ptr<const decompiler_provider_context_t>& base_context,
    const sha256_digest_t& feedback_digest,
    const std::uint64_t generation,
    const bool is_64bit)
{
    using result_t = workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>;
    const auto* native = dynamic_cast<const ghidra_native_provider_context_t*>(
        base_context.get());
    if (!native || !native->snapshot() || native->snapshot()->empty()) {
        return result_t::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "native generation snapshot context is not digest-repackable",
                "decompiler_ui.native_capture.repack"));
    }
    native_worker::native_provider_snapshot_views_t views;
    std::vector<decompiler_diagnostic_t> parse_diagnostics;
    if (!native_worker::parse_native_provider_snapshot_views(
            std::string_view(reinterpret_cast<const char*>(native->snapshot()->data()),
                             native->snapshot()->size()),
            views, parse_diagnostics) ||
        views.format_version != native_worker::k_native_provider_snapshot_v3_version) {
        return result_t::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "native generation snapshot failed view parsing for digest repack",
                "decompiler_ui.native_capture.repack"));
    }
    namespace sidecar_ns = native_worker::snapshot_sidecar;
    sidecar_ns::sidecar_t sidecar;
    sidecar.is_64bit = is_64bit;
    if (!views.sidecar.empty()) {
        const auto decoded = sidecar_ns::decode(views.sidecar.data(), views.sidecar.size());
        if (!decoded) {
            return result_t::failure(
                ui_request_error(workspace_error_code_t::integrity_failure,
                    "native generation snapshot sidecar failed decoding for digest repack",
                    "decompiler_ui.native_capture.repack"));
        }
        sidecar = std::move(*decoded);
    }
    std::memcpy(sidecar.feedback_digest, feedback_digest.bytes.data(),
        sizeof(sidecar.feedback_digest));
    const auto sidecar_bytes = sidecar_ns::encode(sidecar);
    if (sidecar_bytes.empty()) {
        return result_t::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "native generation snapshot sidecar failed re-encoding for digest repack",
                "decompiler_ui.native_capture.repack"));
    }
    native_worker::native_provider_snapshot_t snapshot;
    snapshot.image_base = views.image_base;
    snapshot.image_size = views.image_size;
    snapshot.ranges.reserve(views.ranges.size());
    try {
        for (const auto& view : views.ranges) {
            native_worker::native_provider_snapshot_range_t range;
            range.relative_virtual_address = view.relative_virtual_address;
            range.bytes.assign(view.data, view.data + view.size);
            snapshot.ranges.push_back(std::move(range));
        }
    } catch (const std::bad_alloc&) {
        return result_t::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "native generation snapshot digest repack allocation failed",
                "decompiler_ui.native_capture.repack"));
    }
    const auto serialized = native_worker::serialize_native_provider_snapshot_v3(
        snapshot, sidecar_bytes);
    if (serialized.empty()) {
        return result_t::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "native generation snapshot digest repack serialization failed",
                "decompiler_ui.native_capture.repack"));
    }
    std::vector<std::uint8_t> serialized_bytes(serialized.begin(), serialized.end());
    auto shared_snapshot = std::make_shared<const std::vector<std::uint8_t>>(
        std::move(serialized_bytes));
    const auto snapshot_hash = stable_serialization_hash(serialized);
    const auto published = generation_snapshot_store_t::instance().publish(
        generation, snapshot_hash, shared_snapshot);
    ::diag::log_tagged_fmt("decompiler",
        "generation_snapshot_feedback_repack generation=%llu snapshot_bytes=%llu published=%d",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(shared_snapshot->size()),
        published ? 1 : 0);
    std::shared_ptr<const decompiler_provider_context_t> context =
        std::make_shared<ghidra_native_provider_context_t>(
            std::move(shared_snapshot), snapshot_hash);
    return result_t::success(std::move(context));
}

workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>
resolve_native_generation_context(
    analysis_workspace_t& workspace,
    const std::shared_ptr<const analysis_publication_t>& publication,
    const cancellation_token_t& cancel)
{
    using result_t = workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>;
    if (!publication || !publication->coherent_with(workspace.identity()) ||
        !publication->snapshot || !publication->snapshot->normalized_image) {
        return result_t::failure(
            ui_request_error(workspace_error_code_t::stale_generation,
                "native generation context publication is stale or incoherent",
                "decompiler_ui.native_capture.generation"));
    }
    if (cancel.stop_requested()) {
        return result_t::failure(
            ui_request_error(cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "native generation context resolution was cancelled",
                "decompiler_ui.native_capture.generation"));
    }
    std::string base_key;
    base_key.reserve(160);
    base_key.append(workspace.identity().binary_id().to_hex());
    base_key.push_back('|');
    base_key.append(std::to_string(publication->generation));
    base_key.push_back('|');
    base_key.append(std::to_string(publication->analysis_revision));
    base_key.push_back('|');
    base_key.append(std::to_string(publication->overlay_revision));
    base_key.push_back('|');
    base_key.append(publication->load_profile_hash.to_hex());
    {
        std::lock_guard lock(native_generation_context_mutex);
        const auto found = native_generation_context_cache.find(base_key);
        if (found != native_generation_context_cache.end() && found->second.context) {
            found->second.touch = ++native_generation_context_clock;
            return result_t::success(found->second.context);
        }
    }
    const auto feedback_digest = compute_native_feedback_digest(workspace, *publication);
    const auto cache_key = base_key + "|" + feedback_digest.to_hex();
    {
        std::lock_guard lock(native_generation_context_mutex);
        const auto found = native_generation_context_cache.find(cache_key);
        if (found != native_generation_context_cache.end() && found->second.context) {
            found->second.touch = ++native_generation_context_clock;
            native_generation_context_cache[base_key] = found->second;
            return result_t::success(found->second.context);
        }
    }
    const auto shared_workspace = workspace.shared_from_this();
    auto captured = decompile_batch_orchestrator_t::capture_generation_provider_context(
        shared_workspace, publication, cancel);
    if (!captured)
        return result_t::failure(captured.error());
    std::shared_ptr<const decompiler_provider_context_t> context =
        std::move(captured.value());
    if (!feedback_digest.empty()) {
        auto repacked = repack_context_with_feedback_digest(
            context, feedback_digest, publication->generation,
            publication->snapshot->normalized_image->address_width_bits >= 64);
        if (!repacked)
            return result_t::failure(repacked.error());
        context = std::move(repacked.value());
    }
    const auto* native = dynamic_cast<const ghidra_native_provider_context_t*>(context.get());
    if (!native) {
        return result_t::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "native generation context is not a ghidra provider context",
                "decompiler_ui.native_capture.generation"));
    }
    const auto snapshot_hash = native->snapshot_hash();
    {
        std::lock_guard lock(native_generation_context_mutex);
        const auto found = native_generation_context_cache.find(cache_key);
        if (found != native_generation_context_cache.end() && found->second.context &&
            found->second.snapshot_hash == snapshot_hash) {
            found->second.touch = ++native_generation_context_clock;
            native_generation_context_cache[base_key] = found->second;
            return result_t::success(found->second.context);
        }
        while (native_generation_context_cache.size() >= k_native_generation_context_cache_limit) {
            const auto oldest = std::min_element(
                native_generation_context_cache.begin(), native_generation_context_cache.end(),
                [](const auto& left, const auto& right) {
                    return left.second.touch < right.second.touch;
                });
            if (oldest == native_generation_context_cache.end())
                break;
            native_generation_context_cache.erase(oldest);
        }
        native_generation_context_entry_t entry;
        entry.context = context;
        entry.snapshot_hash = snapshot_hash;
        entry.touch = ++native_generation_context_clock;
        native_generation_context_cache.insert_or_assign(cache_key, entry);
        native_generation_context_cache.insert_or_assign(base_key, std::move(entry));
    }
    ::diag::log_tagged_fmt("decompiler",
        "generation_context_resolved generation=%llu feedback_digest=%s shared=1",
        static_cast<unsigned long long>(publication->generation),
        feedback_digest.empty() ? "none" : "present");
    return result_t::success(std::move(context));
}

workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>
capture_native_provider_context(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const decompiler_provider_request_t& request,
    const cancellation_token_t& cancel) try
{
    if (!workspace || cancel.stop_requested()) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "native decompiler snapshot capture was cancelled",
                "decompiler_ui.native_capture"));
    }
    const auto& key = request.cache_key;
    if (key.stage != decompiler_cache_stage_t::provider_ir ||
        key.workspace_id != workspace->identity().binary_id().to_hex() ||
        !validate_decompiler_pipeline_cache_key(key).valid()) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(workspace_error_code_t::provider_binding_mismatch,
                "native decompiler snapshot request is not bound to this workspace",
                "decompiler_ui.native_capture.binding"));
    }
    const auto publication = workspace->analysis_publication();
    if (!publication || !publication->coherent_with(workspace->identity()) ||
        !publication->snapshot || !publication->snapshot->normalized_image ||
        publication->generation != key.workspace_generation ||
        publication->analysis_revision != key.analysis_revision ||
        publication->overlay_revision != key.overlay_revision ||
        publication->load_profile_hash != key.loader_layout_hash) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(workspace_error_code_t::stale_generation,
                "native decompiler snapshot request revision is stale",
                "decompiler_ui.native_capture.revision"));
    }
    const auto image = publication->snapshot->normalized_image;
    auto language = ghidra_adapter::resolve_ghidra_language(*image, cancel);
    if (!language)
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            language.error());
    if (!equal_language_identity(native_language_identity(language.value(), *image), key.language)) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(workspace_error_code_t::provider_binding_mismatch,
                "native decompiler language identity changed before provider capture",
                "decompiler_ui.native_capture.language"));
    }
    const auto* native_identity = std::get_if<native_decompiler_entity_identity_t>(&key.entity.identity);
    const auto function = native_identity
        ? std::find_if(publication->snapshot->functions.begin(), publication->snapshot->functions.end(),
            [native_identity](const function_record_t& current) {
                return current.id == native_identity->function_id;
            })
        : publication->snapshot->functions.end();
    if (!native_identity || function == publication->snapshot->functions.end() ||
        function->start != native_identity->entry || function->end != native_identity->end) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(workspace_error_code_t::provider_binding_mismatch,
                "native decompiler function identity changed before snapshot capture",
                "decompiler_ui.native_capture.function"));
    }
    if (image->image_size == 0) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "native decompiler image has no addressable extent",
                "decompiler_ui.native_capture.image_limit"));
    }
    if (std::chrono::steady_clock::now() >= request.deadline) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(workspace_error_code_t::deadline_exceeded,
                "native decompiler snapshot capture exceeded its deadline",
                "decompiler_ui.native_capture.read"));
    }
    return resolve_native_generation_context(*workspace, publication, cancel);
} catch (const std::bad_alloc&) {
    return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
        ui_request_error(workspace_error_code_t::limit_exceeded,
            "native decompiler snapshot capture allocation failed",
            "decompiler_ui.native_capture"));
} catch (...) {
    return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
        ui_request_error(workspace_error_code_t::provider_unavailable,
            "native decompiler snapshot capture failed",
            "decompiler_ui.native_capture"));
}

decompiler_ui_diagnostic_t map_diagnostic(
    const decompiler_diagnostic_t& diag) {
    decompiler_ui_diagnostic_t ui_diag;
    ui_diag.severity = diag.severity;
    ui_diag.code = diag.code;
    ui_diag.localization_key = diag.localization_key;
    ui_diag.localization_arguments = diag.localization_arguments;
    ui_diag.coordinate = diag.coordinate;
    ui_diag.confidence = diag.confidence;
    ui_diag.retryable = diag.retryable;
    if (!diag.localization_key.empty())
        ui_diag.message = diag.localization_key;
    else
        ui_diag.message = "decompiler_diagnostic";
    for (const auto& arg : diag.localization_arguments) {
        ui_diag.message += " ";
        ui_diag.message += arg;
    }
    return ui_diag;
}

decompiler_ui_source_mapping_t map_source_mapping(
    const decompiler_document_source_map_t& source_map,
    const source_coordinate_t& coord) {
    decompiler_ui_source_mapping_t mapping;
    mapping.token_begin = source_map.document_range.begin;
    mapping.token_end = source_map.document_range.end;
    mapping.coordinate = coord;
    if (coord.address_range) {
        mapping.address = coord.address_range->begin.value;
        mapping.address_range = coord.address_range;
    }
    if (coord.instruction_range)
        mapping.instruction_id = coord.instruction_range->first_instruction_id;
    if (coord.source_origin) {
        mapping.source_path = coord.source_origin->source_path;
        mapping.source_line = coord.source_origin->first_line;
        mapping.source_column = coord.source_origin->first_column;
    }
    return mapping;
}

bool result_has_null_ast(const decompiler_pipeline_result_t& result) noexcept {
    if (!result.rendered_stage)
        return true;
    const auto& document = result.rendered_stage->document;
    return document.ast.root_node_id == 0 || document.ast.nodes.empty() ||
           document.rendered_text.empty();
}

bool document_has_partial_decompilation(const decompiler_document_t& document) noexcept {
    return std::any_of(document.ast.nodes.begin(), document.ast.nodes.end(),
        [](const typed_pseudocode_ast_node_t& node) {
            return node.kind == typed_pseudocode_ast_node_kind_t::goto_statement ||
                   node.kind == typed_pseudocode_ast_node_kind_t::label_statement;
        });
}

bool result_has_partial_decompilation(const decompiler_pipeline_result_t& result) noexcept {
    if (!result.rendered_stage)
        return false;
    return document_has_partial_decompilation(result.rendered_stage->document);
}

bool result_has_guessed_body(const decompiler_pipeline_result_t& result) noexcept {
    if (!result.rendered_stage)
        return true;
    return !typed_ast_has_proven_function_body(result.rendered_stage->document.ast);
}

bool result_has_complete_source_map(const decompiler_pipeline_result_t& result) noexcept
{
    if (!result.rendered_stage)
        return false;
    const auto& document = result.rendered_stage->document;
    if (document.tokens.size() != document.source_maps.size())
        return false;
    std::uint32_t expected = 0;
    for (std::size_t index = 0; index < document.tokens.size(); ++index) {
        const auto& token = document.tokens[index];
        const auto& source_map = document.source_maps[index];
        if (token.range.begin != expected ||
            source_map.document_range.begin != token.range.begin ||
            source_map.document_range.end != token.range.end)
            return false;
        expected = token.range.end;
    }
    return expected == document.rendered_text.size();
}

decompiler_ui_result_t map_workspace_decompiler_result(
    const decompiler_result_t& ws_result,
    const decompiler_pipeline_request_t& pipeline_request)
{
    decompiler_ui_result_t ui_result;
    ui_result.status = decompiler_pipeline_status_t::completed;
    ui_result.elapsed_ms = static_cast<std::uint64_t>(ws_result.elapsed_ms);
    ui_result.rendered_text = ws_result.pseudocode;
    ui_result.document = std::make_shared<const decompiler_document_t>(ws_result.document);
    ui_result.language_id = pipeline_request.language.language_id;
    ui_result.workspace_generation = pipeline_request.workspace_generation;
    ui_result.analysis_revision = pipeline_request.analysis_revision;
    ui_result.overlay_revision = pipeline_request.cache_identity.overlay_revision;
    ui_result.used_legacy_fallback = true;
    if (const auto* native = std::get_if<native_decompiler_entity_identity_t>(
            &ws_result.document.entity.identity))
        ui_result.function_symbol = native->canonical_symbol;
    for (const auto& source_map : ws_result.document.source_maps) {
        for (const auto& coordinate : source_map.coordinates) {
            ui_result.source_mappings.push_back(
                map_source_mapping(source_map, coordinate));
        }
    }
    return ui_result;
}

bool pipeline_result_is_failure(const decompiler_pipeline_result_t& result) noexcept
{
    if (result.status != decompiler_pipeline_status_t::completed)
        return true;
    if (!result.rendered_stage)
        return true;
    const auto& document = result.rendered_stage->document;
    return document.rendered_text.empty() || document.ast.nodes.empty();
}

workspace_result_t<decompiler_pipeline_request_t> build_managed_pipeline_request(
    const analysis_workspace_t& workspace,
    decompiler_entity_key_t entity,
    decompiler_language_identity_t language,
    std::shared_ptr<const decompiler_provider_context_t> context,
    std::string registration_id,
    const decompiler_ui_invocation_source_t source,
    const decompiler_profile_id_t profile,
    std::optional<decompiler_profile_budget_t> budget,
    const decompiler_pipeline_cache_mode_t cache_mode,
    const sha256_digest_t& worker_protocol_hash,
    const sha256_digest_t& artifact_hash,
    const std::uint64_t type_graph_revision,
    std::vector<decompiler_dependency_version_t> dependencies,
    const cancellation_token_t& cancel)
{
    if (source == decompiler_ui_invocation_source_t::baseline_hook || !context ||
        registration_id.empty() || worker_protocol_hash.empty() || artifact_hash.empty() ||
        type_graph_revision == 0 || dependencies.empty() ||
        !validate_decompiler_entity_key(entity).valid()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "managed decompiler request violates the explicit typed contract",
                "decompiler_ui.managed.identity"));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "managed decompiler request was cancelled before capture",
                "decompiler_ui.managed.cancel"));
    }
    const auto publication = workspace.analysis_publication();
    if (!publication || !publication->coherent_with(workspace.identity()) ||
        !publication->snapshot || publication->generation == 0 ||
        publication->analysis_revision == 0 || publication->load_profile_hash.empty()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::analysis_in_progress,
                "managed decompiler requires a coherent analyzed workspace revision",
                "decompiler_ui.managed.revision"));
    }
    std::sort(dependencies.begin(), dependencies.end(),
        [](const decompiler_dependency_version_t& left,
           const decompiler_dependency_version_t& right) {
            return left.name < right.name;
        });
    for (std::size_t index = 0; index < dependencies.size(); ++index) {
        if (dependencies[index].name.empty() || dependencies[index].version.empty() ||
            dependencies[index].content_hash.empty() ||
            (index != 0 && dependencies[index - 1].name == dependencies[index].name)) {
            return workspace_result_t<decompiler_pipeline_request_t>::failure(
                ui_request_error(workspace_error_code_t::invalid_argument,
                    "managed decompiler dependency identity is invalid",
                    "decompiler_ui.managed.dependencies"));
        }
    }

    decompiler_pipeline_request_t request;
    request.invocation = decompiler_ui_integration_t::map_invocation_source(source);
    request.cache_mode = cache_mode;
    request.workspace_id = workspace.identity().binary_id().to_hex();
    request.workspace_generation = publication->generation;
    request.analysis_revision = publication->analysis_revision;
    request.entity = std::move(entity);
    request.language = std::move(language);
    request.profile = profile;
    request.budget = std::move(budget);
    request.provider_registration_id = std::move(registration_id);
    request.provider_context = std::move(context);
    request.cache_identity.worker_protocol_hash = worker_protocol_hash;
    request.cache_identity.loader_layout_hash = publication->load_profile_hash;
    request.cache_identity.function_bytes_hash = artifact_hash;
    request.cache_identity.metadata_revision = publication->analysis_revision;
    request.cache_identity.type_graph_revision = type_graph_revision;
    request.cache_identity.overlay_revision = publication->snapshot->overlay_revision;
    request.cache_identity.dependencies = std::move(dependencies);
    request.deadline = cancel.deadline();
    return workspace_result_t<decompiler_pipeline_request_t>::success(std::move(request));
}

}

struct decompiler_ui_integration_t::impl_t {
    ui_state_t state;

    explicit impl_t(std::shared_ptr<analysis_workspace_t> ws,
                    std::shared_ptr<decompiler_pipeline_service_t> svc,
                    decompiler_ui_integration_config_t cfg)
        : state(std::move(ws), std::move(svc), std::move(cfg)) {}

    void increment_metric(
        std::uint64_t decompiler_ui_integration_metrics_t::*field) noexcept {
        std::lock_guard<std::mutex> lock(state.metrics_mutex);
        state.metrics.*field += 1;
    }
};

decompiler_ui_integration_t::decompiler_ui_integration_t(
    std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)) {}

decompiler_ui_integration_t::~decompiler_ui_integration_t() = default;

workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
decompiler_ui_integration_t::create(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<decompiler_pipeline_service_t> service,
    decompiler_ui_integration_config_t config) {
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompiler UI integration requires a workspace",
                "decompiler_ui_integration"));
    }
    if (!service) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                "decompiler UI integration requires a pipeline service",
                "decompiler_ui_integration"));
    }
    if (config.max_function_bytes == 0 || config.max_function_chunks == 0 ||
        config.max_managed_capture_cache_entries == 0 ||
        config.max_managed_capture_bytes == 0 ||
        config.max_managed_capture_bytes > (256ULL << 20) ||
        !config.managed_reader_limits.valid()) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompiler UI integration identity limits are invalid",
                "decompiler_ui_integration"));
    }
    auto impl = std::make_unique<impl_t>(workspace, service, config);
    return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::success(
        std::shared_ptr<decompiler_ui_integration_t>(
            new decompiler_ui_integration_t(std::move(impl))));
}

workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
decompiler_ui_integration_t::create_production(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::filesystem::path runtime_root,
    decompiler_ui_integration_config_t config)
{
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "production decompiler integration requires a workspace",
                "decompiler_ui.production"));
    }
    auto runtime = native_worker::create_packaged_native_worker_runtime(
        std::move(runtime_root));
    if (!runtime) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            runtime.error());
    }
    try {
        auto providers = std::make_shared<decompiler_provider_registry_t>();
        decompiler_builtin_provider_config_t builtin;
        builtin.native.identity = runtime.value().provider;
        builtin.native.isolated = true;
        builtin.cli.identity = runtime.value().cli_provider;
        builtin.cli.isolated = true;
        builtin.jvm.identity = runtime.value().jvm_provider;
        builtin.jvm.isolated = true;
        builtin.dalvik.identity = runtime.value().dalvik_provider;
        builtin.dalvik.isolated = true;
        auto registered = register_builtin_decompiler_providers(*providers, builtin);
        if (!registered) {
            return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
                registered.error());
        }
        auto cache = decompiler_cache_t::create();
        if (!cache) {
            return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
                cache.error());
        }
        native_worker::native_worker_session_pool_config_t pool_config;
        const unsigned int logical_cores = (std::max)(2u, std::thread::hardware_concurrency());
        pool_config.batch_slots = (std::min<std::size_t>)(
            native_worker::native_worker_session_pool_config_t{}.batch_slots,
            (std::max<std::size_t>)(2, logical_cores - 1));
        pool_config.interactive_reserved_slots = (std::min<std::size_t>)(
            native_worker::native_worker_session_pool_config_t{}.interactive_reserved_slots,
            static_cast<std::size_t>(logical_cores - 2));
        ::diag::log_tagged_fmt("decompiler",
            "pool_config batch_slots=%zu interactive_reserved=%zu logical_cores=%u source=hardware_formula",
            pool_config.batch_slots,
            pool_config.interactive_reserved_slots,
            logical_cores);
        auto pooled_native_host =
            native_worker::create_pooled_native_worker_provider_host(runtime.value(), pool_config);
        config.service_config.isolated_provider_host = pooled_native_host;
        config.service_config.max_parallel_requests =
            (std::min<std::size_t>)(64, static_cast<std::size_t>(logical_cores)) +
            pool_config.interactive_reserved_slots + 1;
        config.service_config.database = workspace->database();
        config.service_config.metrics_sink = workspace->background_metrics();
        auto service = decompiler_pipeline_service_t::create(
            std::move(providers), cache.take_value(), {}, config.service_config);
        if (!service) {
            return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
                service.error());
        }
        auto integration = create(workspace, service.take_value(), std::move(config));
        if (!integration)
            return integration;
        integration.value()->impl_->state.pooled_native_host = std::move(pooled_native_host);
        integration.value()->impl_->state.native_provider = runtime.value().provider;
        integration.value()->impl_->state.cli_provider = runtime.value().cli_provider;
        integration.value()->impl_->state.jvm_provider = runtime.value().jvm_provider;
        integration.value()->impl_->state.dalvik_provider = runtime.value().dalvik_provider;
        integration.value()->impl_->state.native_worker_protocol_hash =
            runtime.value().worker_protocol_hash;
        integration.value()->impl_->state.native_manifest_hash = runtime.value().manifest_hash;
        integration.value()->impl_->state.managed_manifest_hash =
            runtime.value().managed_manifest_hash;
        integration.value()->impl_->state.managed_runtime_manifest_hash =
            runtime.value().managed_runtime_manifest_hash;
        integration.value()->impl_->state.native_worker_protocol_version =
            runtime.value().worker_protocol_version;
        return integration;
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "production decompiler integration allocation failed",
                "decompiler_ui.production"));
    } catch (...) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            ui_request_error(workspace_error_code_t::provider_unavailable,
                "production decompiler integration initialization failed",
                "decompiler_ui.production"));
    }
}

workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
decompiler_ui_integration_t::production_for_workspace(
    std::shared_ptr<analysis_workspace_t> workspace)
{
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "production decompiler integration requires a workspace",
                "decompiler_ui.production_cache"));
    }
    const auto* key = workspace.get();
    {
        std::lock_guard lock(production_cache_mutex);
        const auto found = production_cache.find(key);
        if (found != production_cache.end() && found->second.workspace == workspace &&
            found->second.integration) {
            found->second.touch = ++production_cache_clock;
            return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::success(
                found->second.integration);
        }
    }
    auto created = create_production(workspace);
    if (!created)
        return created;
    std::shared_ptr<decompiler_ui_integration_t> evicted;
    {
        std::lock_guard lock(production_cache_mutex);
        const auto found = production_cache.find(key);
        if (found != production_cache.end() && found->second.workspace == workspace &&
            found->second.integration) {
            found->second.touch = ++production_cache_clock;
            return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::success(
                found->second.integration);
        }
        if (production_cache.size() >= maximum_cached_production_integrations) {
            const auto oldest = std::min_element(
                production_cache.begin(), production_cache.end(),
                [](const auto& left, const auto& right) {
                    return left.second.touch < right.second.touch;
                });
            if (oldest != production_cache.end()) {
                evicted = std::move(oldest->second.integration);
                production_cache.erase(oldest);
            }
        }
        production_cache_entry_t entry;
        entry.workspace = std::move(workspace);
        entry.integration = created.value();
        entry.touch = ++production_cache_clock;
        production_cache.insert_or_assign(key, std::move(entry));
    }
    evicted.reset();
    return created;
}

workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
decompiler_ui_integration_t::find_production_for_workspace(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "production decompiler integration requires a workspace",
                "decompiler_ui.production_cache"));
    }
    std::lock_guard lock(production_cache_mutex);
    const auto found = production_cache.find(workspace.get());
    if (found == production_cache.end() || found->second.workspace != workspace ||
        !found->second.integration) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            ui_request_error(workspace_error_code_t::provider_unavailable,
                "production decompiler integration is not installed for the workspace",
                "decompiler_ui.production_cache"));
    }
    found->second.touch = ++production_cache_clock;
    return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::success(
        found->second.integration);
}

decompiler_pipeline_invocation_t
decompiler_ui_integration_t::map_invocation_source(
    decompiler_ui_invocation_source_t source) noexcept {
    switch (source) {
    case decompiler_ui_invocation_source_t::keyboard_f5:
    case decompiler_ui_invocation_source_t::keyboard_shift_f5:
    case decompiler_ui_invocation_source_t::context_menu:
        return decompiler_pipeline_invocation_t::explicit_ui;
    case decompiler_ui_invocation_source_t::mcp_request:
        return decompiler_pipeline_invocation_t::explicit_mcp;
    case decompiler_ui_invocation_source_t::api_call:
        return decompiler_pipeline_invocation_t::explicit_api;
    case decompiler_ui_invocation_source_t::baseline_hook:
        return decompiler_pipeline_invocation_t::baseline_analysis;
    default:
        return decompiler_pipeline_invocation_t::unspecified;
    }
}

workspace_result_t<decompiler_pipeline_request_t>
decompiler_ui_integration_t::build_pipeline_request(
    const decompiler_ui_request_t& request,
    const analysis_workspace_t& workspace,
    const std::uint64_t max_function_bytes,
    const std::size_t max_function_chunks,
    const cancellation_token_t& cancel) try
{
    if (max_function_bytes == 0 || max_function_chunks == 0 ||
        request.worker_protocol_hash.empty() ||
        request.metadata_revision == 0 || request.type_graph_revision == 0) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler UI identity inputs are incomplete",
                "decompiler_ui.identity"));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "decompiler UI identity construction was cancelled",
                "decompiler_ui.identity"));
    }
    auto binding = workspace.verify_provider_binding();
    if (!binding)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(binding.error());
    const auto publication = workspace.analysis_publication();
    if (!publication || !publication->coherent_with(workspace.identity()) ||
        !publication->snapshot || !publication->snapshot->normalized_image) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::stale_generation,
                "decompiler UI workspace publication is stale or incoherent",
                "decompiler_ui.identity.workspace"));
    }
    const auto snapshot = publication->snapshot;
    const auto image = snapshot->normalized_image;
    if (!valid_language_for_image(request.language, *image)) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler UI language and compiler identity does not match the workspace image",
                "decompiler_ui.identity.language"));
    }
    auto dependencies = request.dependencies;
    if (!canonicalize_dependencies(dependencies)) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler UI dependency identity set is invalid",
                "decompiler_ui.identity.dependencies"));
    }
    const auto* function = resolve_function(*snapshot, request.function_address, image->image_base);
    if (!function || function->id == 0) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::target_not_found,
                "decompiler UI function is not present in the current workspace snapshot",
                "decompiler_ui.identity.function"));
    }
    if (request.function_end_address != 0 &&
        !address_matches(function->end, request.function_end_address, image->image_base)) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::target_stale,
                "decompiler UI function end does not match the current workspace snapshot",
                "decompiler_ui.identity.function"));
    }
    auto spans_result = function_spans(
        *snapshot, *function, image->image_base, max_function_chunks);
    if (!spans_result)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(spans_result.error());
    auto spans = std::move(spans_result.value());
    std::uint64_t total_bytes = 0;
    for (const auto& span : spans) {
        const auto span_size = span.second - span.first;
        if (!checked_add(total_bytes, span_size, total_bytes) || total_bytes > max_function_bytes) {
            return workspace_result_t<decompiler_pipeline_request_t>::failure(
                ui_request_error(workspace_error_code_t::limit_exceeded,
                    "decompiler UI function bytes exceed the configured limit",
                    "decompiler_ui.identity.bytes"));
        }
    }
    if (total_bytes == 0 || total_bytes > (std::numeric_limits<std::size_t>::max)()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler UI function has no readable bytes",
                "decompiler_ui.identity.bytes"));
    }
    std::vector<std::uint8_t> aggregate;
    std::vector<decompiler_chunk_fingerprint_t> fingerprints;
    try {
        aggregate.reserve(static_cast<std::size_t>(total_bytes));
        fingerprints.reserve(spans.size());
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "decompiler UI identity allocation failed",
                "decompiler_ui.identity.bytes"));
    }
    const auto pe = snapshot->image;
    for (const auto& span : spans) {
        if (cancel.stop_requested()) {
            return workspace_result_t<decompiler_pipeline_request_t>::failure(
                ui_request_error(cancel.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "decompiler UI identity construction was cancelled",
                    "decompiler_ui.identity.bytes"));
        }
        const auto size = span.second - span.first;
        auto provider_offset = provider_offset_for_range(*image, span.first, size);
        if (!provider_offset && pe) {
            const auto mapped = pe->rva_to_file_offset(span.first, size);
            if (mapped)
                provider_offset = mapped.value();
        }
        if (!provider_offset) {
            return workspace_result_t<decompiler_pipeline_request_t>::failure(
                ui_request_error(workspace_error_code_t::out_of_range,
                    "decompiler UI function chunk is not backed by provider bytes",
                    "decompiler_ui.identity.mapping"));
        }
        auto bytes = workspace.provider().read_vector(
            *provider_offset, size, max_function_bytes, cancel);
        if (!bytes)
            return workspace_result_t<decompiler_pipeline_request_t>::failure(bytes.error());
        auto digest = sha256_bytes(bytes.value().data(), bytes.value().size(), cancel);
        if (!digest)
            return workspace_result_t<decompiler_pipeline_request_t>::failure(digest.error());
        decompiler_chunk_fingerprint_t fingerprint;
        fingerprint.begin = address_t{address_space_id_t::relative_virtual,
            span.first, image->architecture, image->architecture_mode};
        fingerprint.end = address_t{address_space_id_t::relative_virtual,
            span.second, image->architecture, image->architecture_mode};
        fingerprint.bytes_hash = digest.value();
        fingerprints.push_back(std::move(fingerprint));
        aggregate.insert(aggregate.end(), bytes.value().begin(), bytes.value().end());
    }
    auto function_hash = sha256_bytes(aggregate.data(), aggregate.size(), cancel);
    if (!function_hash)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(function_hash.error());
    const auto entry = relative_value(function->start, image->image_base);
    const auto end = relative_value(function->end, image->image_base);
    if (!entry || !end || *entry >= *end) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler UI function identity range is invalid",
                "decompiler_ui.identity.function"));
    }

    const auto canonical_symbol = resolve_function_symbol(*snapshot, *function);
    if (!request.function_symbol.empty() && request.function_symbol != canonical_symbol) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::target_stale,
                "decompiler UI function symbol does not match the current workspace snapshot",
                "decompiler_ui.identity.function"));
    }

    native_decompiler_entity_identity_t native_identity;
    native_identity.function_id = function->id;
    native_identity.entry = address_t{address_space_id_t::relative_virtual,
        *entry, image->architecture, image->architecture_mode};
    native_identity.end = address_t{address_space_id_t::relative_virtual,
        *end, image->architecture, image->architecture_mode};
    native_identity.function_bytes_hash = function_hash.value();
    native_identity.canonical_symbol = canonical_symbol;
    decompiler_entity_key_t entity;
    entity.kind = decompiler_entity_kind_t::native_function;
    entity.format = image->format;
    entity.architecture = image->architecture;
    entity.mode = image->architecture_mode;
    entity.endian = image->endian;
    entity.identity = std::move(native_identity);
    if (!validate_decompiler_entity_key(entity).valid()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler UI function identity failed contract validation",
                "decompiler_ui.identity.function"));
    }

    if (auto integration = find_production_for_workspace(
            std::const_pointer_cast<analysis_workspace_t>(
                workspace.shared_from_this()))) {
        auto& identity_state = integration.value()->impl_->state;
        native_identity_cache_entry_t identity_entry;
        identity_entry.spans = spans;
        identity_entry.fingerprints = fingerprints;
        identity_entry.function_bytes_hash = function_hash.value();
        identity_entry.entity = entity;
        identity_entry.canonical_symbol = canonical_symbol;
        identity_entry.function_id = function->id;
        identity_entry.generation = snapshot->generation;
        identity_entry.analysis_revision = snapshot->analysis_revision;
        identity_entry.overlay_revision = snapshot->overlay_revision;
        identity_entry.load_profile_hash = publication->load_profile_hash;
        identity_entry.worker_protocol_hash = request.worker_protocol_hash;
        std::lock_guard<std::mutex> identity_lock(identity_state.native_identity_mutex);
        identity_entry.touch = ++identity_state.native_identity_clock;
        if (identity_state.native_identity_cache.size() >=
            k_native_identity_cache_max_entries) {
            const auto oldest = std::min_element(
                identity_state.native_identity_cache.begin(),
                identity_state.native_identity_cache.end(),
                [](const auto& left, const auto& right) {
                    return left.second.touch < right.second.touch;
                });
            if (oldest != identity_state.native_identity_cache.end())
                identity_state.native_identity_cache.erase(oldest);
        }
        identity_state.native_identity_cache.insert_or_assign(
            function->id, std::move(identity_entry));
    }

    decompiler_pipeline_request_t pipeline_request;
    pipeline_request.invocation = map_invocation_source(request.source);
    pipeline_request.cache_mode = request.cache_mode;
    pipeline_request.workspace_id = workspace.identity().binary_id().to_hex();
    pipeline_request.workspace_generation = snapshot->generation;
    pipeline_request.analysis_revision = snapshot->analysis_revision;
    pipeline_request.entity = std::move(entity);
    pipeline_request.language = request.language;
    pipeline_request.profile = request.profile;
    pipeline_request.budget = request.budget;
    pipeline_request.renderer = request.renderer;
    pipeline_request.provider_registration_id = request.provider_registration_id;
    pipeline_request.provider_context = request.provider_context;
    pipeline_request.provider_context_factory = request.provider_context_factory;
    pipeline_request.cache_identity.worker_protocol_hash = request.worker_protocol_hash;
    pipeline_request.cache_identity.loader_layout_hash = publication->load_profile_hash;
    pipeline_request.cache_identity.function_bytes_hash = function_hash.value();
    pipeline_request.cache_identity.chunk_fingerprints = std::move(fingerprints);
    pipeline_request.cache_identity.metadata_revision = request.metadata_revision;
    pipeline_request.cache_identity.type_graph_revision = request.type_graph_revision;
    pipeline_request.cache_identity.overlay_revision = snapshot->overlay_revision;
    pipeline_request.cache_identity.dependencies = std::move(dependencies);
    auto type_evidence = workspace_type_evidence(
        *snapshot, pipeline_request.entity, spans, image->image_base);
    if (!type_evidence.candidates.empty())
        pipeline_request.type_evidence.push_back(std::move(type_evidence));
    auto recognition_seed_batches = static_recognition::type_seed_batches_for(
        std::const_pointer_cast<analysis_workspace_t>(workspace.shared_from_this()),
        pipeline_request.entity,
        pipeline_request.workspace_generation, 70);
    for (auto& seed_batch : recognition_seed_batches)
        pipeline_request.type_evidence.push_back(std::move(seed_batch));
    pipeline_request.deadline = request.deadline;
    return workspace_result_t<decompiler_pipeline_request_t>::success(
        std::move(pipeline_request));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "decompiler UI identity allocation failed",
                "decompiler_ui.identity"));
    } catch (...) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "decompiler UI identity construction failed",
                "decompiler_ui.identity"));
    }

workspace_result_t<decompiler_pipeline_request_t> make_native_pipeline_request(
    analysis_workspace_t& workspace,
    const std::shared_ptr<const analysis_publication_t>& publication,
    const function_record_t& function,
    const decompiler_pipeline_invocation_t invocation,
    const decompiler_pipeline_cache_mode_t cache_mode,
    const decompiler_profile_id_t profile,
    const std::optional<decompiler_profile_budget_t>& budget,
    const std::optional<std::chrono::steady_clock::time_point>& deadline,
    const std::shared_ptr<const decompiler_provider_context_t>& provider_context,
    const cancellation_token_t& cancel) try
{
    constexpr std::uint64_t max_function_bytes = 64ULL << 20;
    constexpr std::size_t max_function_chunks = 65536;
    if (!publication || !publication->coherent_with(workspace.identity()) ||
        !publication->snapshot || !publication->snapshot->normalized_image ||
        publication->analysis_revision == 0) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::stale_generation,
                "decompiler pipeline workspace publication is stale or incoherent",
                "decompiler_ui.identity.workspace"));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "decompiler pipeline identity construction was cancelled",
                "decompiler_ui.identity"));
    }
    auto binding = workspace.verify_provider_binding();
    if (!binding)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(binding.error());
    const auto snapshot = publication->snapshot;
    const auto image = snapshot->normalized_image;
    if (function.id == 0) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::target_not_found,
                "decompiler pipeline function is not present in the current workspace snapshot",
                "decompiler_ui.identity.function"));
    }
    const auto entry = relative_value(function.start, image->image_base);
    const auto end = relative_value(function.end, image->image_base);
    if (!entry || !end || *entry >= *end || *end > image->image_size) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler pipeline function identity range is invalid",
                "decompiler_ui.identity.function"));
    }
    auto integration = decompiler_ui_integration_t::production_for_workspace(
        workspace.shared_from_this());
    if (!integration)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            integration.error());
    const auto& state = integration.value()->impl_->state;
    if (!state.native_provider || state.native_worker_protocol_hash.empty() ||
        state.native_manifest_hash.empty() ||
        state.native_worker_protocol_version != k_decompiler_worker_protocol_version) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::provider_unavailable,
                "production native decompiler runtime is unavailable",
                "decompiler_ui.native"));
    }
    auto language = ghidra_adapter::resolve_ghidra_language(*image, cancel);
    if (!language)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(language.error());
    const auto identity_language = native_language_identity(language.value(), *image);
    auto dependencies = native_dependency_identities(state, identity_language);
    if (!dependencies)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            dependencies.error());
    auto& identity_state = integration.value()->impl_->state;
    native_identity_cache_entry_t identity_hit_entry;
    bool identity_hit = false;
    {
        std::lock_guard<std::mutex> identity_lock(identity_state.native_identity_mutex);
        const auto found = identity_state.native_identity_cache.find(function.id);
        if (found != identity_state.native_identity_cache.end()) {
            if (found->second.generation != snapshot->generation ||
                found->second.analysis_revision != snapshot->analysis_revision ||
                found->second.overlay_revision != snapshot->overlay_revision) {
                identity_state.native_identity_cache.clear();
            } else if (found->second.load_profile_hash != publication->load_profile_hash ||
                       found->second.worker_protocol_hash !=
                           state.native_worker_protocol_hash) {
                identity_state.native_identity_cache.erase(found);
            } else {
                found->second.touch = ++identity_state.native_identity_clock;
                identity_hit_entry = found->second;
                identity_hit = true;
            }
        }
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    std::vector<decompiler_chunk_fingerprint_t> fingerprints;
    sha256_digest_t function_bytes_hash{};
    decompiler_entity_key_t entity;
    if (identity_hit) {
        spans = std::move(identity_hit_entry.spans);
        fingerprints = std::move(identity_hit_entry.fingerprints);
        function_bytes_hash = identity_hit_entry.function_bytes_hash;
        entity = std::move(identity_hit_entry.entity);
        integration.value()->impl_->increment_metric(
            &decompiler_ui_integration_metrics_t::native_identity_cache_hits);
        ::diag::log_tagged_fmt("decompiler",
            "native_identity_cache hit=1 function_id=%llu",
            static_cast<unsigned long long>(function.id));
    } else {
    auto spans_result = function_spans(
        *snapshot, function, image->image_base, max_function_chunks);
    if (!spans_result)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            spans_result.error());
    spans = std::move(spans_result.value());
    std::uint64_t total_bytes = 0;
    for (const auto& span : spans) {
        const auto span_size = span.second - span.first;
        if (!checked_add(total_bytes, span_size, total_bytes) ||
            total_bytes > max_function_bytes) {
            return workspace_result_t<decompiler_pipeline_request_t>::failure(
                ui_request_error(workspace_error_code_t::limit_exceeded,
                    "decompiler pipeline function bytes exceed the configured limit",
                    "decompiler_ui.identity.bytes"));
        }
    }
    if (total_bytes == 0 || total_bytes > (std::numeric_limits<std::size_t>::max)()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler pipeline function has no readable bytes",
                "decompiler_ui.identity.bytes"));
    }
    std::vector<std::uint8_t> aggregate;
    try {
        aggregate.reserve(static_cast<std::size_t>(total_bytes));
        fingerprints.reserve(spans.size());
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "decompiler pipeline identity allocation failed",
                "decompiler_ui.identity.bytes"));
    }
    const auto pe = snapshot->image;
    for (const auto& span : spans) {
        if (cancel.stop_requested()) {
            return workspace_result_t<decompiler_pipeline_request_t>::failure(
                ui_request_error(cancel.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "decompiler pipeline identity construction was cancelled",
                    "decompiler_ui.identity.bytes"));
        }
        const auto size = span.second - span.first;
        auto provider_offset = provider_offset_for_range(*image, span.first, size);
        if (!provider_offset && pe) {
            const auto mapped = pe->rva_to_file_offset(span.first, size);
            if (mapped)
                provider_offset = mapped.value();
        }
        if (!provider_offset) {
            return workspace_result_t<decompiler_pipeline_request_t>::failure(
                ui_request_error(workspace_error_code_t::out_of_range,
                    "decompiler pipeline function chunk is not backed by provider bytes",
                    "decompiler_ui.identity.mapping"));
        }
        auto bytes = workspace.provider().read_vector(
            *provider_offset, size, max_function_bytes, cancel);
        if (!bytes)
            return workspace_result_t<decompiler_pipeline_request_t>::failure(bytes.error());
        auto digest = sha256_bytes(bytes.value().data(), bytes.value().size(), cancel);
        if (!digest)
            return workspace_result_t<decompiler_pipeline_request_t>::failure(digest.error());
        decompiler_chunk_fingerprint_t fingerprint;
        fingerprint.begin = address_t{address_space_id_t::relative_virtual,
            span.first, image->architecture, image->architecture_mode};
        fingerprint.end = address_t{address_space_id_t::relative_virtual,
            span.second, image->architecture, image->architecture_mode};
        fingerprint.bytes_hash = digest.value();
        fingerprints.push_back(std::move(fingerprint));
        aggregate.insert(aggregate.end(), bytes.value().begin(), bytes.value().end());
    }
    auto function_hash = sha256_bytes(aggregate.data(), aggregate.size(), cancel);
    if (!function_hash)
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            function_hash.error());
    native_decompiler_entity_identity_t native_identity;
    native_identity.function_id = function.id;
    native_identity.entry = address_t{address_space_id_t::relative_virtual,
        *entry, image->architecture, image->architecture_mode};
    native_identity.end = address_t{address_space_id_t::relative_virtual,
        *end, image->architecture, image->architecture_mode};
    native_identity.function_bytes_hash = function_hash.value();
    const auto canonical_symbol = resolve_function_symbol(*snapshot, function);
    native_identity.canonical_symbol = canonical_symbol;
    entity.kind = decompiler_entity_kind_t::native_function;
    entity.format = image->format;
    entity.architecture = image->architecture;
    entity.mode = image->architecture_mode;
    entity.endian = image->endian;
    entity.identity = std::move(native_identity);
    if (!validate_decompiler_entity_key(entity).valid()) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "decompiler pipeline function identity failed contract validation",
                "decompiler_ui.identity.function"));
    }
    function_bytes_hash = function_hash.value();
    {
        native_identity_cache_entry_t identity_entry;
        identity_entry.spans = spans;
        identity_entry.fingerprints = fingerprints;
        identity_entry.function_bytes_hash = function_bytes_hash;
        identity_entry.entity = entity;
        identity_entry.canonical_symbol = canonical_symbol;
        identity_entry.function_id = function.id;
        identity_entry.generation = snapshot->generation;
        identity_entry.analysis_revision = snapshot->analysis_revision;
        identity_entry.overlay_revision = snapshot->overlay_revision;
        identity_entry.load_profile_hash = publication->load_profile_hash;
        identity_entry.worker_protocol_hash = state.native_worker_protocol_hash;
        std::lock_guard<std::mutex> identity_lock(identity_state.native_identity_mutex);
        identity_entry.touch = ++identity_state.native_identity_clock;
        if (identity_state.native_identity_cache.size() >=
            k_native_identity_cache_max_entries) {
            const auto oldest = std::min_element(
                identity_state.native_identity_cache.begin(),
                identity_state.native_identity_cache.end(),
                [](const auto& left, const auto& right) {
                    return left.second.touch < right.second.touch;
                });
            if (oldest != identity_state.native_identity_cache.end())
                identity_state.native_identity_cache.erase(oldest);
        }
        identity_state.native_identity_cache.insert_or_assign(
            function.id, std::move(identity_entry));
    }
    integration.value()->impl_->increment_metric(
        &decompiler_ui_integration_metrics_t::native_identity_cache_misses);
    ::diag::log_tagged_fmt("decompiler",
        "native_identity_cache hit=0 function_id=%llu",
        static_cast<unsigned long long>(function.id));
    }
    decompiler_pipeline_request_t pipeline_request;
    pipeline_request.invocation = invocation;
    pipeline_request.cache_mode = cache_mode;
    pipeline_request.workspace_id = workspace.identity().binary_id().to_hex();
    pipeline_request.workspace_generation = snapshot->generation;
    pipeline_request.analysis_revision = snapshot->analysis_revision;
    pipeline_request.entity = std::move(entity);
    pipeline_request.language = identity_language;
    pipeline_request.profile = profile;
    pipeline_request.budget = budget;
    pipeline_request.provider_registration_id = "aida.decompiler.native.ghidra";
    pipeline_request.provider_context = provider_context;
    if (!pipeline_request.provider_context) {
        std::shared_ptr<analysis_workspace_t> shared_workspace =
            workspace.shared_from_this();
        pipeline_request.provider_context_factory =
            [shared_workspace](const decompiler_provider_request_t& provider_request,
                               const cancellation_token_t& provider_cancel) {
                return capture_native_provider_context(
                    shared_workspace, provider_request, provider_cancel);
            };
    }
    pipeline_request.cache_identity.worker_protocol_hash =
        state.native_worker_protocol_hash;
    pipeline_request.cache_identity.loader_layout_hash = publication->load_profile_hash;
    pipeline_request.cache_identity.function_bytes_hash = function_bytes_hash;
    pipeline_request.cache_identity.chunk_fingerprints = std::move(fingerprints);
    pipeline_request.cache_identity.metadata_revision = publication->analysis_revision;
    pipeline_request.cache_identity.type_graph_revision = publication->analysis_revision;
    pipeline_request.cache_identity.overlay_revision = snapshot->overlay_revision;
    pipeline_request.cache_identity.dependencies = dependencies.take_value();
    auto type_evidence = workspace_type_evidence(
        *snapshot, pipeline_request.entity, spans, image->image_base);
    if (!type_evidence.candidates.empty())
        pipeline_request.type_evidence.push_back(std::move(type_evidence));
    auto recognition_seed_batches = static_recognition::type_seed_batches_for(
        workspace.shared_from_this(), pipeline_request.entity,
        pipeline_request.workspace_generation, 70);
    for (auto& seed_batch : recognition_seed_batches)
        pipeline_request.type_evidence.push_back(std::move(seed_batch));
    pipeline_request.deadline = deadline;
    return workspace_result_t<decompiler_pipeline_request_t>::success(
        std::move(pipeline_request));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "decompiler pipeline identity allocation failed",
                "decompiler_ui.identity"));
    } catch (...) {
        return workspace_result_t<decompiler_pipeline_request_t>::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "decompiler pipeline identity construction failed",
                "decompiler_ui.identity"));
    }

decompiler_ui_result_t
decompiler_ui_integration_t::map_pipeline_result(
    const decompiler_pipeline_result_t& result) {
    decompiler_ui_result_t ui_result;
    ui_result.status = result.status;
    ui_result.elapsed_ms = result.elapsed_wall_clock_ms;
    ui_result.cache_hit_stage = result.cache_hit_stage;
    ui_result.provider = result.provider;
    ui_result.readability = result.readability;
    ui_result.provider_stage = result.provider_stage;
    ui_result.normalized_stage = result.normalized_stage;
    if (result.rendered_stage) {
        const auto& document = result.rendered_stage->document;
        ui_result.document = std::shared_ptr<const decompiler_document_t>(
            result.rendered_stage, &result.rendered_stage->document);
        ui_result.rendered_text = document.rendered_text;
        if (const auto* native = std::get_if<native_decompiler_entity_identity_t>(
                &document.entity.identity))
            ui_result.function_symbol = native->canonical_symbol;
        if (document.ast.nodes.empty() && document.rendered_text.empty())
            ui_result.status = decompiler_pipeline_status_t::normalization_failed;
        for (const auto& source_map : document.source_maps) {
            for (const auto& coordinate : source_map.coordinates) {
                ui_result.source_mappings.push_back(
                    map_source_mapping(source_map, coordinate));
            }
        }
    }
    for (const auto& diag : result.diagnostics) {
        ui_result.diagnostics.push_back(map_diagnostic(diag));
    }
    return ui_result;
}

workspace_result_t<decompiler_ui_result_t>
decompiler_ui_integration_t::execute_pipeline(
    decompiler_pipeline_request_t pipeline_request,
    const decompiler_ui_invocation_source_t source,
    const bool require_complete_source_map,
    const cancellation_token_t& cancel)
{
    if (!impl_ || !impl_->state.workspace || !impl_->state.service) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompiler UI integration is not initialized",
                "decompiler_ui.execute"));
    }
    impl_->state.request_counter.fetch_add(1, std::memory_order_acq_rel);
    impl_->increment_metric(&decompiler_ui_integration_metrics_t::total_requests);
    switch (source) {
    case decompiler_ui_invocation_source_t::keyboard_f5:
    case decompiler_ui_invocation_source_t::keyboard_shift_f5:
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::f5_requests);
        break;
    case decompiler_ui_invocation_source_t::mcp_request:
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::mcp_requests);
        break;
    case decompiler_ui_invocation_source_t::api_call:
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::api_requests);
        break;
    default:
        break;
    }
    const bool interactive_native =
        pipeline_request.invocation == decompiler_pipeline_invocation_t::explicit_ui &&
        pipeline_request.entity.kind == decompiler_entity_kind_t::native_function;
    if (pipeline_request.entity.kind == decompiler_entity_kind_t::native_function &&
        !pipeline_request.provider_context) {
        const auto publication = impl_->state.workspace->analysis_publication();
        if (publication && publication_matches_request(*impl_->state.workspace, pipeline_request)) {
            auto generation_context = resolve_native_generation_context(
                *impl_->state.workspace, publication, cancel);
            if (generation_context) {
                pipeline_request.provider_context = std::move(generation_context.value());
            } else {
                ::diag::log_tagged_fmt("decompiler",
                    "interactive_generation_context_unavailable code=%s",
                    generation_context.error().stable_code().c_str());
            }
        }
    }
    decompiler_pipeline_result_t pipeline_result;
    bool probe_satisfied = false;
    if (interactive_native) {
        std::shared_ptr<decompile_batch_orchestrator_t> background;
        try {
            background = impl_->state.workspace->background_decompile();
        } catch (...) {
            background.reset();
        }
        bool interactive_admitted = false;
        if (background)
            interactive_admitted = background->admit_interactive_priority(pipeline_request.entity);
        const auto probe_started = std::chrono::steady_clock::now();
        const auto probe = impl_->state.service->probe_rendered_cache(pipeline_request);
        const auto probe_ms = static_cast<std::uint64_t>((std::max<std::int64_t>)(0,
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - probe_started).count()));
        if (probe.hit_stage != decompiler_rendered_probe_stage_t::none && probe.rendered) {
            pseudocode_readability_request_t readability_request;
            readability_request.limits =
                impl_->state.config.service_config.readability_limits;
            readability_request.require_complete_source_map =
                impl_->state.config.service_config.require_complete_source_map;
            auto analyzed = analyze_pseudocode_readability(
                probe.rendered->document.ast, probe.rendered->document,
                readability_request);
            if (analyzed.succeeded() && analyzed.report) {
                pipeline_result.status = decompiler_pipeline_status_t::completed;
                pipeline_result.rendered_stage = probe.rendered;
                pipeline_result.cache_hit_stage =
                    decompiler_cache_stage_t::rendered_document;
                pipeline_result.diagnostics = probe.rendered->diagnostics;
                pipeline_result.readability = std::move(*analyzed.report);
                probe_satisfied = true;
                ::diag::log_tagged_fmt("decompiler",
                    "interactive_dispatch wait_ms=%llu slot=CACHED deadline_ms=0 est_insns=0 batch_active=%d admitted=%d probe_hit=%s",
                    static_cast<unsigned long long>(probe_ms),
                    background && background->run_snapshot().active ? 1 : 0,
                    interactive_admitted ? 1 : 0,
                    probe.hit_stage == decompiler_rendered_probe_stage_t::persistent_rendered
                        ? "persistent" : "memory");
            }
        }
        if (!probe_satisfied) {
            const auto* native_identity =
                std::get_if<native_decompiler_entity_identity_t>(
                    &pipeline_request.entity.identity);
            std::uint64_t estimated_instructions = 0;
            std::uint64_t deadline_budget_ms = 0;
            if (native_identity &&
                native_identity->end.value > native_identity->entry.value) {
                const std::uint64_t byte_size =
                    native_identity->end.value - native_identity->entry.value;
                estimated_instructions = byte_size / 4 + ((byte_size % 4) != 0 ? 1 : 0);
            }
            if (pipeline_request.deadline) {
                const auto remaining =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        *pipeline_request.deadline -
                            std::chrono::steady_clock::now()).count();
                deadline_budget_ms =
                    static_cast<std::uint64_t>((std::max<std::int64_t>)(0, remaining));
            }
            const char* slot_class = "POOLED";
            if (impl_->state.pooled_native_host) {
                if (const auto* pooled =
                        dynamic_cast<const native_worker::pooled_native_worker_provider_host_t*>(
                            impl_->state.pooled_native_host.get())) {
                    if (const auto classification = pooled->classify_interactive_dispatch()) {
                        slot_class = *classification ==
                                native_worker::pooled_native_worker_provider_host_t::slot_class_t::reserved
                            ? "RESERVED"
                            : "BORROWED";
                    }
                }
            }
            ::diag::log_tagged_fmt("decompiler",
                "interactive_dispatch wait_ms=%llu slot=%s deadline_ms=%llu est_insns=%llu batch_active=%d admitted=%d",
                static_cast<unsigned long long>(probe_ms),
                slot_class,
                static_cast<unsigned long long>(deadline_budget_ms),
                static_cast<unsigned long long>(estimated_instructions),
                background && background->run_snapshot().active ? 1 : 0,
                interactive_admitted ? 1 : 0);
        }
    }
    if (!probe_satisfied)
        pipeline_result = impl_->state.service->decompile(pipeline_request, cancel);
    if (!publication_matches_request(*impl_->state.workspace, pipeline_request)) {
        ::diag::log_tagged_fmt("decompiler", "typed_pipeline path=primary status=stale_generation workspace_generation=%llu current_generation=%llu",
            static_cast<unsigned long long>(pipeline_request.workspace_generation),
            static_cast<unsigned long long>(impl_->state.workspace->generation()));
        decompiler_ui_result_t ui_result;
        ui_result.status = decompiler_pipeline_status_t::stale_generation;
        ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
        decompiler_ui_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::error;
        diagnostic.code = decompiler_diagnostic_code_t::cache_key_rejected;
        diagnostic.localization_key = "decompiler.ui.stale_result";
        diagnostic.localization_arguments = {
            std::to_string(pipeline_request.workspace_generation),
            std::to_string(impl_->state.workspace->generation())};
        diagnostic.message = diagnostic.localization_key + " " +
            diagnostic.localization_arguments.front() + " " +
            diagnostic.localization_arguments.back();
        diagnostic.retryable = true;
        ui_result.diagnostics.push_back(std::move(diagnostic));
        return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
    }
    if (pipeline_result.succeeded()) {
        ::diag::log_tagged_fmt("decompiler", "typed_pipeline path=primary status=completed elapsed_ms=%llu cache_hit=%d partial=%d used_legacy_fallback=0",
            static_cast<unsigned long long>(pipeline_result.elapsed_wall_clock_ms),
            pipeline_result.cache_hit_stage.has_value() ? 1 : 0,
            result_has_partial_decompilation(pipeline_result) ? 1 : 0);
        if (impl_->state.config.reject_null_ast && result_has_null_ast(pipeline_result)) {
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::rejected_null_ast);
            decompiler_ui_result_t ui_result;
            ui_result.status = decompiler_pipeline_status_t::normalization_failed;
            ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
            decompiler_ui_diagnostic_t diagnostic;
            diagnostic.severity = decompiler_diagnostic_severity_t::error;
            diagnostic.code = decompiler_diagnostic_code_t::malformed_ast;
            diagnostic.message = "decompiler returned a null AST: rejected by integration policy";
            diagnostic.retryable = true;
            ui_result.diagnostics.push_back(std::move(diagnostic));
            return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
        }
        if (impl_->state.config.reject_guessed_body && result_has_guessed_body(pipeline_result)) {
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::rejected_guessed_body);
            decompiler_ui_result_t ui_result;
            ui_result.status = decompiler_pipeline_status_t::normalization_failed;
            ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
            decompiler_ui_diagnostic_t diagnostic;
            diagnostic.severity = decompiler_diagnostic_severity_t::error;
            diagnostic.code = decompiler_diagnostic_code_t::malformed_ast;
            diagnostic.message = "decompiler returned a body without typed proof: rejected by integration policy";
            diagnostic.retryable = true;
            ui_result.diagnostics.push_back(std::move(diagnostic));
            return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
        }
        if (require_complete_source_map && !result_has_complete_source_map(pipeline_result)) {
            decompiler_ui_result_t ui_result;
            ui_result.status = decompiler_pipeline_status_t::rendering_failed;
            ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
            decompiler_ui_diagnostic_t diagnostic;
            diagnostic.severity = decompiler_diagnostic_severity_t::error;
            diagnostic.code = decompiler_diagnostic_code_t::source_map_rejected;
            diagnostic.message = "decompiler returned an incomplete source map: rejected by request policy";
            diagnostic.retryable = true;
            ui_result.diagnostics.push_back(std::move(diagnostic));
            return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
        }
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::completed);
        if (pipeline_result.cache_hit_stage)
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::cache_hits);
    } else {
        ::diag::log_tagged_fmt("decompiler", "typed_pipeline path=primary status=failed pipeline_status=%u partial=%d",
            static_cast<unsigned int>(pipeline_result.status),
            result_has_partial_decompilation(pipeline_result) ? 1 : 0);
        switch (pipeline_result.status) {
        case decompiler_pipeline_status_t::provider_failed:
        case decompiler_pipeline_status_t::provider_crashed:
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::provider_failures);
            break;
        case decompiler_pipeline_status_t::deadline_exceeded:
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::deadline_exceeded);
            break;
        case decompiler_pipeline_status_t::cancelled:
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::cancelled);
            break;
        default:
            break;
        }
    }
    auto ui_result = map_pipeline_result(pipeline_result);
    ui_result.language_id = pipeline_request.language.language_id;
    ui_result.workspace_generation = pipeline_request.workspace_generation;
    ui_result.analysis_revision = pipeline_request.analysis_revision;
    ui_result.overlay_revision = pipeline_request.cache_identity.overlay_revision;
    if (impl_->state.config.legacy_fallback_enabled &&
        pipeline_result_is_failure(pipeline_result) &&
        !cancel.stop_requested()) {
        const auto workspace = impl_->state.workspace;
        auto ws_decompiler = workspace ? workspace->decompiler() : nullptr;
        if (ws_decompiler) {
            const auto* native_identity = std::get_if<
                native_decompiler_entity_identity_t>(
                    &pipeline_request.entity.identity);
            if (native_identity) {
                ::diag::log_tagged_fmt("decompiler", "legacy_fallback reason=typed_pipeline_failed pipeline_status=%u",
                    static_cast<unsigned int>(pipeline_result.status));
                decompiler_request_t ws_request;
                ws_request.use_memory_cache = true;
                ws_request.use_persistent_cache = false;
                ws_request.publish_feedback = false;
                ws_request.deadline = pipeline_request.deadline;
                auto ws_result = ws_decompiler->decompile(
                    native_identity->entry, ws_request, cancel);
                if (ws_result && !ws_result.value().pseudocode.empty() &&
                    ws_result.value().document.rendered_text ==
                        ws_result.value().pseudocode) {
                    auto fallback_result = map_workspace_decompiler_result(
                        ws_result.value(), pipeline_request);
                    impl_->increment_metric(
                        &decompiler_ui_integration_metrics_t::completed);
                    ::diag::log_tagged_fmt("decompiler", "legacy_fallback path=workspace_service status=completed elapsed_ms=%llu used_legacy_fallback=1 partial=%d",
                        static_cast<unsigned long long>(ws_result.value().elapsed_ms),
                        document_has_partial_decompilation(ws_result.value().document) ? 1 : 0);
                    return workspace_result_t<decompiler_ui_result_t>::success(
                        std::move(fallback_result));
                }
                ::diag::log_tagged_fmt("decompiler", "legacy_fallback path=workspace_service status=failed");
            }
        }
    }
    return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
}

workspace_result_t<decompiler_ui_result_t>
decompiler_ui_integration_t::decompile(
    const decompiler_ui_request_t& request,
    const cancellation_token_t& cancel) {
    if (!impl_ || !impl_->state.workspace || !impl_->state.service) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompiler UI integration is not initialized",
                "decompile"));
    }
    if (request.provider_context && request.provider_context_factory) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompiler UI request cannot provide both a context and a context factory",
                "decompile"));
    }
    auto built_request = build_pipeline_request(request, *impl_->state.workspace,
        impl_->state.config.max_function_bytes,
        impl_->state.config.max_function_chunks, cancel);
    if (!built_request)
        return workspace_result_t<decompiler_ui_result_t>::failure(built_request.error());
    return execute_pipeline(std::move(built_request.value()), request.source,
        request.require_complete_source_map, cancel);
}

workspace_result_t<decompiler_ui_result_t>
decompiler_ui_integration_t::decompile_native(
    const std::uint64_t function_address,
    const decompiler_ui_invocation_source_t source,
    const decompiler_profile_id_t profile,
    const decompiler_pipeline_cache_mode_t cache_mode,
    const cancellation_token_t& cancel)
{
    if (!impl_ || !impl_->state.workspace || !impl_->state.native_provider ||
        impl_->state.native_worker_protocol_hash.empty() ||
        impl_->state.native_manifest_hash.empty() ||
        impl_->state.native_worker_protocol_version != k_decompiler_worker_protocol_version) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::provider_unavailable,
                "production native decompiler runtime is unavailable",
                "decompiler_ui.native"));
    }
    const auto workspace = impl_->state.workspace;
    const auto publication = workspace->analysis_publication();
    if (!publication ||
        !publication->coherent_with(workspace->identity()) || !publication->snapshot ||
        !publication->snapshot->normalized_image || publication->analysis_revision == 0) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::analysis_in_progress,
                "native decompiler requires a coherent analyzed workspace revision",
                "decompiler_ui.native.revision"));
    }
    auto language = ghidra_adapter::resolve_ghidra_language(
        *publication->snapshot->normalized_image, cancel);
    if (!language)
        return workspace_result_t<decompiler_ui_result_t>::failure(language.error());
    const auto* function = resolve_function(
        *publication->snapshot, function_address,
        publication->snapshot->normalized_image->image_base);
    if (!function || function->id == 0) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::target_not_found,
                "native decompiler function is not present in the current analysis revision",
                "decompiler_ui.native.function"));
    }

    const auto& image = *publication->snapshot->normalized_image;
    const std::uint64_t function_bytes =
        native_function_byte_size(*publication->snapshot, *function);
    const std::uint64_t deadline_ms =
        decompile_batch_orchestrator_t::compute_size_aware_deadline(
            function_bytes, image.architecture, decompile_deadline_lane_t::interactive);
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(deadline_ms);
    auto built = make_native_pipeline_request(*workspace, publication, *function,
        map_invocation_source(source), cache_mode, profile,
        std::nullopt, deadline, {}, cancel);
    if (!built)
        return workspace_result_t<decompiler_ui_result_t>::failure(built.error());
    return execute_pipeline(std::move(built.value()), source, true, cancel);
}

workspace_result_t<decompiler_ui_result_t>
decompiler_ui_integration_t::decompile_cli(
    std::shared_ptr<const managed_cli::request_t> request,
    const decompiler_ui_invocation_source_t source,
    const decompiler_pipeline_cache_mode_t cache_mode,
    const cancellation_token_t& cancel)
{
    if (!impl_ || !impl_->state.workspace || !impl_->state.cli_provider ||
        impl_->state.native_worker_protocol_hash.empty() ||
        impl_->state.managed_manifest_hash.empty() ||
        impl_->state.managed_runtime_manifest_hash.empty() ||
        impl_->state.native_worker_protocol_version != k_decompiler_worker_protocol_version ||
        !request || request->sequence != 1 || request->type_graph_revision == 0 ||
        request->worker.runtime_manifest_hash !=
            impl_->state.managed_runtime_manifest_hash ||
        !equal_provider_identity(*impl_->state.cli_provider,
            decompiler_provider_identity_t{
                decompiler_provider_id_t::ilspy_cli,
                "ICSharpCode.Decompiler",
                request->worker.provider_version,
                request->worker.decompiler_assembly_hash,
                request->worker.worker_build_id,
                request->worker.worker_build_hash})) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::provider_unavailable,
                "production CLI decompiler runtime or request identity is unavailable",
                "decompiler_ui.cli"));
    }
    const auto publication = impl_->state.workspace->analysis_publication();
    if (!publication || !publication->snapshot ||
        !publication->coherent_with(impl_->state.workspace->identity()) ||
        request->workspace_generation != publication->generation ||
        request->type_graph_revision != publication->analysis_revision) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::target_stale,
                "CLI decompiler request is not bound to the current workspace revision",
                "decompiler_ui.cli.revision"));
    }
    const auto preflight = validate_managed_cli_preflight(*request, cancel);
    if (!preflight)
        return workspace_result_t<decompiler_ui_result_t>::failure(preflight.error());
    const auto* identity = std::get_if<cli_decompiler_entity_identity_t>(
        &request->entity.identity);
    if (!identity || identity->module_hash.empty()) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "CLI decompiler entity has no immutable module identity",
                "decompiler_ui.cli.entity"));
    }
    decompiler_language_identity_t language;
    language.language_id = "cli-il";
    language.language_version = "ecma-335";
    language.compiler_spec_id = "managed-cli";
    language.language_spec_hash = stable_serialization_hash(
        std::string("cli-il|ecma-335|") + request->worker.provider_version);
    std::shared_ptr<const decompiler_provider_context_t> context;
    try {
        context = std::make_shared<managed_cli_provider_context_t>(request);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "CLI decompiler context allocation failed",
                "decompiler_ui.cli.context"));
    }
    std::vector<decompiler_dependency_version_t> dependencies{
        {"aida.managed.provider",
            impl_->state.cli_provider->provider_version + "|" +
                impl_->state.cli_provider->worker_build_id,
            impl_->state.cli_provider->provider_binary_hash},
        {"aida.managed.worker.manifest",
            std::to_string(native_worker::k_managed_worker_manifest_schema_version),
            impl_->state.managed_manifest_hash},
        {"aida.managed.worker.protocol",
            std::to_string(impl_->state.native_worker_protocol_version),
            impl_->state.native_worker_protocol_hash},
        {"aida.managed.runtime", "net10.0|Microsoft.NETCore.App|10.0.9|win-x64",
            request->worker.runtime_manifest_hash}};
    auto pipeline = build_managed_pipeline_request(
        *impl_->state.workspace, request->entity, std::move(language), std::move(context),
        "aida.decompiler.managed.cli", source, request->profile.profile,
        request->profile, cache_mode, impl_->state.native_worker_protocol_hash,
        identity->module_hash, request->type_graph_revision,
        std::move(dependencies), cancel);
    if (!pipeline)
        return workspace_result_t<decompiler_ui_result_t>::failure(pipeline.error());
    return execute_pipeline(std::move(pipeline.value()), source, true, cancel);
}

workspace_result_t<decompiler_ui_result_t>
decompiler_ui_integration_t::decompile_jvm(
    std::shared_ptr<const jvm_ssa::jvm_method_input_t> input,
    const decompiler_ui_invocation_source_t source,
    const decompiler_profile_id_t profile,
    const decompiler_pipeline_cache_mode_t cache_mode,
    const cancellation_token_t& cancel)
{
    if (!impl_ || !impl_->state.workspace || !impl_->state.jvm_provider ||
        impl_->state.native_worker_protocol_hash.empty() ||
        impl_->state.native_manifest_hash.empty() || !input ||
        !equal_provider_identity(input->provider, *impl_->state.jvm_provider)) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::provider_unavailable,
                "production JVM decompiler runtime or request identity is unavailable",
                "decompiler_ui.jvm"));
    }
    const auto publication = impl_->state.workspace->analysis_publication();
    const auto* identity = std::get_if<jvm_decompiler_entity_identity_t>(
        &input->entity.identity);
    if (!publication || !publication->snapshot ||
        !publication->coherent_with(impl_->state.workspace->identity()) ||
        input->workspace_generation != publication->generation ||
        input->type_graph_revision != publication->analysis_revision ||
        !identity || identity->class_artifact_hash.empty() ||
        input->language.architecture != architecture_id_t::jvm_bytecode ||
        input->language.mode != architecture_mode_t::jvm) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::target_stale,
                "JVM decompiler input is not bound to the current workspace revision",
                "decompiler_ui.jvm.revision"));
    }
    const auto serialized = jvm_ssa::serialize_jvm_method_input(*input);
    if (serialized.empty()) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "JVM decompiler input failed canonical serialization",
                "decompiler_ui.jvm.input"));
    }
    std::shared_ptr<const decompiler_provider_context_t> context;
    try {
        context = std::make_shared<jvm_ssa_provider_context_t>(input);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "JVM decompiler context allocation failed",
                "decompiler_ui.jvm.context"));
    }
    std::vector<decompiler_dependency_version_t> dependencies{
        {"aida.jvm.provider",
            impl_->state.jvm_provider->provider_version + "|" +
                impl_->state.jvm_provider->worker_build_id,
            impl_->state.jvm_provider->provider_binary_hash},
        {"aida.native.worker.manifest",
            std::to_string(native_worker::k_native_worker_manifest_schema_version),
            impl_->state.native_manifest_hash},
        {"aida.native.worker.protocol",
            std::to_string(impl_->state.native_worker_protocol_version),
            impl_->state.native_worker_protocol_hash},
        {"jvm.language",
            input->language.language_version + "|" + input->language.compiler_spec_id,
            input->language.language_spec_hash}};
    auto pipeline = build_managed_pipeline_request(
        *impl_->state.workspace, input->entity, input->language, std::move(context),
        "aida.decompiler.jvm.ssa", source, profile, {}, cache_mode,
        impl_->state.native_worker_protocol_hash, identity->class_artifact_hash,
        input->type_graph_revision, std::move(dependencies), cancel);
    if (!pipeline)
        return workspace_result_t<decompiler_ui_result_t>::failure(pipeline.error());
    return execute_pipeline(std::move(pipeline.value()), source, true, cancel);
}

workspace_result_t<decompiler_ui_result_t>
decompiler_ui_integration_t::decompile_dalvik(
    std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t> capture,
    const decompiler_ui_invocation_source_t source,
    const decompiler_profile_id_t profile,
    const decompiler_pipeline_cache_mode_t cache_mode,
    const cancellation_token_t& cancel)
{
    if (!impl_ || !impl_->state.workspace || !impl_->state.dalvik_provider ||
        impl_->state.native_worker_protocol_hash.empty() ||
        impl_->state.native_manifest_hash.empty() || !capture ||
        !equal_provider_identity(capture->request.provider,
            *impl_->state.dalvik_provider)) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::provider_unavailable,
                "production Dalvik decompiler runtime or request identity is unavailable",
                "decompiler_ui.dalvik"));
    }
    const auto publication = impl_->state.workspace->analysis_publication();
    const auto* identity = std::get_if<dalvik_decompiler_entity_identity_t>(
        &capture->request.entity.identity);
    if (!publication || !publication->snapshot ||
        !publication->coherent_with(impl_->state.workspace->identity()) ||
        capture->request.workspace_generation != publication->generation ||
        capture->request.type_graph_revision != publication->analysis_revision ||
        !identity || identity->dex_hash.empty() ||
        capture->request.language.architecture != architecture_id_t::dalvik_bytecode ||
        capture->request.language.mode != architecture_mode_t::dalvik) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::target_stale,
                "Dalvik decompiler capture is not bound to the current workspace revision",
                "decompiler_ui.dalvik.revision"));
    }
    const auto serialized = dalvik_ssa::serialize_capture(*capture);
    if (serialized.empty()) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::invalid_argument,
                "Dalvik decompiler capture failed canonical serialization",
                "decompiler_ui.dalvik.input"));
    }
    std::shared_ptr<const decompiler_provider_context_t> context;
    try {
        context = std::make_shared<dalvik_ssa_provider_context_t>(capture);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "Dalvik decompiler context allocation failed",
                "decompiler_ui.dalvik.context"));
    }
    std::vector<decompiler_dependency_version_t> dependencies{
        {"aida.dalvik.provider",
            impl_->state.dalvik_provider->provider_version + "|" +
                impl_->state.dalvik_provider->worker_build_id,
            impl_->state.dalvik_provider->provider_binary_hash},
        {"aida.native.worker.manifest",
            std::to_string(native_worker::k_native_worker_manifest_schema_version),
            impl_->state.native_manifest_hash},
        {"aida.native.worker.protocol",
            std::to_string(impl_->state.native_worker_protocol_version),
            impl_->state.native_worker_protocol_hash},
        {"dalvik.language",
            capture->request.language.language_version + "|" +
                capture->request.language.compiler_spec_id,
            capture->request.language.language_spec_hash}};
    auto pipeline = build_managed_pipeline_request(
        *impl_->state.workspace, capture->request.entity, capture->request.language,
        std::move(context), "aida.decompiler.dalvik.ssa", source, profile, {},
        cache_mode, impl_->state.native_worker_protocol_hash, identity->dex_hash,
        capture->request.type_graph_revision, std::move(dependencies), cancel);
    if (!pipeline)
        return workspace_result_t<decompiler_ui_result_t>::failure(pipeline.error());
    return execute_pipeline(std::move(pipeline.value()), source, true, cancel);
}

workspace_result_t<generation_bound_decompiler_entity_t>
decompiler_ui_integration_t::resolve_entity_at(
    const decompiler_entity_locator_t& locator,
    const cancellation_token_t& cancel) {
    if (!impl_ || !impl_->state.workspace)
        return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "decompiler entity producer is not initialized",
                "decompiler_ui.entity.resolve"));
    const auto workspace = impl_->state.workspace;
    if (workspace->target_kind() != target_kind_t::static_file &&
        (locator.token || (locator.expected_kind &&
            *locator.expected_kind !=
                decompiler_entity_kind_t::native_function)))
        return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
            ui_request_error(
                workspace_error_code_t::live_target_bulk_analysis_unsupported,
                "managed entity resolution is unavailable for live workspaces",
                "decompiler_ui.entity.resolve"));
    for (std::uint32_t attempt = 0; attempt != 2; ++attempt) {
        if (cancel.stop_requested())
            return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                ui_request_error(cancel.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "decompiler entity resolution was cancelled",
                    "decompiler_ui.entity.resolve"));
        auto publication = workspace->analysis_publication();
        if (!publication || !publication->snapshot || !publication->provider)
            return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                ui_request_error(workspace_error_code_t::target_stale,
                    "workspace publication is unavailable",
                    "decompiler_ui.entity.resolve"));
        const auto format = workspace->identity().format();
        const bool managed_candidate =
            format == format_id_t::pe32 || format == format_id_t::pe32_plus ||
            format == format_id_t::classfile || format == format_id_t::dex ||
            format == format_id_t::oat || format == format_id_t::vdex;
        if (!publication->managed_artifacts && managed_candidate &&
            workspace->target_kind() == target_kind_t::static_file) {
            const auto target_revision = publication->analysis_revision == 0
                ? 1ULL : publication->analysis_revision;
            auto admitted = build_managed_artifact_publication(
                workspace->identity(), *publication->provider,
                publication->snapshot->image, publication->generation,
                target_revision, publication->overlay_revision,
                impl_->state.config.managed_reader_limits, cancel);
            if (!admitted) {
                impl_->increment_metric(
                    &decompiler_ui_integration_metrics_t::entity_resolution_failures);
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    admitted.error());
            }
            if (admitted.value()) {
                auto published = workspace->publish_managed_artifacts(
                    publication->generation, publication->analysis_revision,
                    admitted.take_value(), true);
                if (!published) {
                    if (published.error().code == workspace_error_code_t::revision_conflict ||
                        published.error().code == workspace_error_code_t::stale_generation)
                        continue;
                    impl_->increment_metric(
                        &decompiler_ui_integration_metrics_t::entity_resolution_failures);
                    return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                        published.error());
                }
                publication = workspace->analysis_publication();
                if (!publication)
                    continue;
            }
        }
        auto resolved = resolve_generation_bound_entity(
            workspace->identity(), *publication, locator, cancel);
        if (!resolved) {
            impl_->increment_metric(
                &decompiler_ui_integration_metrics_t::entity_resolution_failures);
            return resolved;
        }
        auto binding = resolved.take_value();
        if (binding.entity.kind == decompiler_entity_kind_t::native_function) {
            if (!impl_->state.native_provider ||
                impl_->state.native_worker_protocol_hash.empty() ||
                !publication->snapshot->normalized_image)
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    ui_request_error(workspace_error_code_t::provider_unavailable,
                        "native entity identity runtime is unavailable",
                        "decompiler_ui.entity.resolve.native"));
            const auto* native = std::get_if<native_decompiler_entity_identity_t>(
                &binding.entity.identity);
            if (!native)
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    ui_request_error(workspace_error_code_t::integrity_failure,
                        "native entity identity is invalid",
                        "decompiler_ui.entity.resolve.native"));
            auto language = ghidra_adapter::resolve_ghidra_language(
                *publication->snapshot->normalized_image, cancel);
            if (!language)
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    language.error());
            std::uint64_t address = native->entry.value;
            if (native->entry.space == address_space_id_t::relative_virtual) {
                if (!checked_add(
                        publication->snapshot->normalized_image->image_base,
                        native->entry.value, address))
                    return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                        ui_request_error(workspace_error_code_t::range_overflow,
                            "native entity address overflowed",
                            "decompiler_ui.entity.resolve.native"));
            }
            decompiler_ui_request_t identity_request;
            identity_request.source = decompiler_ui_invocation_source_t::api_call;
            identity_request.function_address = address;
            identity_request.language = native_language_identity(
                language.value(), *publication->snapshot->normalized_image);
            identity_request.worker_protocol_hash =
                impl_->state.native_worker_protocol_hash;
            identity_request.metadata_revision = publication->analysis_revision;
            identity_request.type_graph_revision = publication->analysis_revision;
            auto dependencies = native_dependency_identities(
                impl_->state, identity_request.language);
            if (!dependencies)
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    dependencies.error());
            identity_request.dependencies = dependencies.take_value();
            auto identity = build_pipeline_request(
                identity_request, *workspace,
                impl_->state.config.max_function_bytes,
                impl_->state.config.max_function_chunks, cancel);
            if (!identity)
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    identity.error());
            binding.entity = identity.value().entity;
            const auto* complete_native =
                std::get_if<native_decompiler_entity_identity_t>(
                    &binding.entity.identity);
            if (!complete_native)
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    ui_request_error(workspace_error_code_t::integrity_failure,
                        "native entity identity construction failed",
                        "decompiler_ui.entity.resolve.native"));
            binding.artifact_hash = complete_native->function_bytes_hash;
        }
        auto current = workspace->analysis_publication();
        if (current != publication)
            continue;
        auto validated = validate_generation_bound_entity(
            workspace->identity(), *current, binding, cancel);
        if (!validated) {
            impl_->increment_metric(
                &decompiler_ui_integration_metrics_t::entity_resolution_failures);
            return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                validated.error());
        }
        impl_->increment_metric(
            &decompiler_ui_integration_metrics_t::entity_resolutions);
        return workspace_result_t<generation_bound_decompiler_entity_t>::success(
            std::move(binding));
    }
    impl_->increment_metric(
        &decompiler_ui_integration_metrics_t::entity_resolution_failures);
    return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
        ui_request_error(workspace_error_code_t::revision_conflict,
            "workspace changed repeatedly during entity resolution",
            "decompiler_ui.entity.resolve"));
}

workspace_result_t<decompiler_ui_result_t>
decompiler_ui_integration_t::decompile_entity(
    const generation_bound_decompiler_entity_t& binding,
    decompiler_ui_invocation_source_t source,
    decompiler_profile_id_t profile,
    decompiler_pipeline_cache_mode_t cache_mode,
    const cancellation_token_t& cancel) {
    try {
    if (!impl_ || !impl_->state.workspace)
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::integrity_failure,
                "decompiler entity producer is not initialized",
                "decompiler_ui.entity.decompile"));
    const auto workspace = impl_->state.workspace;
    auto publication = workspace->analysis_publication();
    if (!publication)
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::target_stale,
                "workspace publication is unavailable",
                "decompiler_ui.entity.decompile"));
    auto validation = validate_generation_bound_entity(
        workspace->identity(), *publication, binding, cancel);
    if (!validation)
        return workspace_result_t<decompiler_ui_result_t>::failure(
            validation.error());
    workspace_result_t<decompiler_ui_result_t> result =
        workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::unsupported_format,
                "decompiler entity kind is unsupported",
                "decompiler_ui.entity.decompile"));
    if (binding.entity.kind == decompiler_entity_kind_t::native_function) {
        const auto* native = std::get_if<native_decompiler_entity_identity_t>(
            &binding.entity.identity);
        if (!native || !publication->snapshot->normalized_image)
            return workspace_result_t<decompiler_ui_result_t>::failure(
                ui_request_error(workspace_error_code_t::integrity_failure,
                    "native entity binding is invalid",
                    "decompiler_ui.entity.decompile.native"));
        std::uint64_t address = native->entry.value;
        if (native->entry.space == address_space_id_t::relative_virtual &&
            !checked_add(publication->snapshot->normalized_image->image_base,
                native->entry.value, address))
            return workspace_result_t<decompiler_ui_result_t>::failure(
                ui_request_error(workspace_error_code_t::range_overflow,
                    "native entity address overflowed",
                    "decompiler_ui.entity.decompile.native"));
        result = decompile_native(address, source, profile, cache_mode, cancel);
    } else {
        if (!binding.artifact_index || !publication->managed_artifacts ||
            *binding.artifact_index >=
                publication->managed_artifacts->artifacts().size())
            return workspace_result_t<decompiler_ui_result_t>::failure(
                ui_request_error(workspace_error_code_t::target_stale,
                    "managed entity artifact is unavailable",
                    "decompiler_ui.entity.decompile.managed"));
        const auto& artifact = publication->managed_artifacts->artifacts()[
            *binding.artifact_index];
        if (artifact.provider_size > impl_->state.config.max_managed_capture_bytes)
            return workspace_result_t<decompiler_ui_result_t>::failure(
                ui_request_error(workspace_error_code_t::limit_exceeded,
                    "managed entity artifact exceeds the capture budget",
                    "decompiler_ui.entity.decompile.managed"));
        const auto key = managed_capture_key(binding) + "|" +
            std::to_string(static_cast<std::uint32_t>(profile));
        std::optional<managed_capture_value_t> captured;
        {
            std::lock_guard lock(impl_->state.managed_capture_mutex);
            for (auto iterator = impl_->state.managed_capture_cache.begin();
                 iterator != impl_->state.managed_capture_cache.end();) {
                if (iterator->second.generation != publication->generation ||
                    iterator->second.analysis_revision !=
                        publication->analysis_revision ||
                    iterator->second.overlay_revision !=
                        publication->overlay_revision ||
                    iterator->second.provider_hash != binding.provider_hash) {
                    impl_->state.managed_capture_cache_bytes -=
                        iterator->second.byte_size;
                    iterator = impl_->state.managed_capture_cache.erase(iterator);
                }
                else
                    ++iterator;
            }
            for (auto iterator =
                     impl_->state.managed_module_snapshot_cache.begin();
                 iterator != impl_->state.managed_module_snapshot_cache.end();) {
                const auto stale =
                    iterator->second.generation != publication->generation ||
                    iterator->second.analysis_revision !=
                        publication->analysis_revision ||
                    iterator->second.overlay_revision !=
                        publication->overlay_revision ||
                    iterator->second.provider_hash != binding.provider_hash;
                if (!stale) {
                    ++iterator;
                    continue;
                }
                const auto stale_key = iterator->first;
                ++iterator;
                erase_managed_module_snapshot_locked(
                    impl_->state, stale_key);
            }
            const auto found = impl_->state.managed_capture_cache.find(key);
            if (found != impl_->state.managed_capture_cache.end()) {
                found->second.touch = ++impl_->state.managed_capture_clock;
                captured = found->second.value;
            }
        }
        if (captured)
            impl_->increment_metric(
                &decompiler_ui_integration_metrics_t::managed_capture_cache_hits);
        if (!captured) {
            if (binding.entity.kind == decompiler_entity_kind_t::cli_method) {
                if (!impl_->state.cli_provider ||
                    impl_->state.managed_runtime_manifest_hash.empty())
                    return workspace_result_t<decompiler_ui_result_t>::failure(
                        ui_request_error(workspace_error_code_t::provider_unavailable,
                            "verified app-local CLI runtime identity is unavailable",
                            "decompiler_ui.entity.capture.cli"));
                managed_cli::worker_identity_t worker;
                worker.provider_version =
                    impl_->state.cli_provider->provider_version;
                worker.decompiler_assembly_hash =
                    impl_->state.cli_provider->provider_binary_hash;
                worker.worker_build_id =
                    impl_->state.cli_provider->worker_build_id;
                worker.worker_build_hash =
                    impl_->state.cli_provider->worker_build_hash;
                worker.runtime_manifest_hash =
                    impl_->state.managed_runtime_manifest_hash;
                const auto& budget = profile_budget(
                    impl_->state.config.service_config.profiles, profile);
                const auto request_id = "entity-" +
                    stable_serialization_hash(binding.entity).to_hex();
                const auto whole_mapped_file =
                    artifact.provider_offset == 0 &&
                    artifact.provider_size == publication->provider->size() &&
                    !publication->provider->member_metadata() &&
                    std::dynamic_pointer_cast<const mapped_file_provider_t>(
                        publication->provider) != nullptr;
                auto request = [&]() -> workspace_result_t<managed_cli::request_t> {
                    if (whole_mapped_file)
                        return managed_cli::make_request(
                            1, request_id,
                            publication->provider->identity().normalized_source,
                            binding.entity, binding.generation,
                            binding.type_graph_revision, budget, worker,
                            cancel);
                    auto snapshot = acquire_managed_cli_snapshot(
                        impl_->state, publication, binding, artifact, cancel);
                    if (!snapshot)
                        return workspace_result_t<managed_cli::request_t>::failure(
                            snapshot.error());
                    return managed_cli::make_embedded_request(
                        1, request_id,
                        managed_embedded_logical_identity(*publication, artifact),
                        snapshot.take_value(), binding.entity,
                        binding.generation, binding.type_graph_revision,
                        budget, worker, cancel);
                }();
                if (!request)
                    return workspace_result_t<decompiler_ui_result_t>::failure(
                        request.error());
                captured = managed_capture_value_t{
                    std::make_shared<const managed_cli::request_t>(
                        request.take_value())};
            } else if (binding.entity.kind ==
                       decompiler_entity_kind_t::jvm_method) {
                if (!impl_->state.jvm_provider)
                    return workspace_result_t<decompiler_ui_result_t>::failure(
                        ui_request_error(workspace_error_code_t::provider_unavailable,
                            "verified JVM provider identity is unavailable",
                            "decompiler_ui.entity.capture.jvm"));
                auto input = capture_jvm_entity_input(
                    *publication, binding, *impl_->state.jvm_provider, cancel);
                if (!input)
                    return workspace_result_t<decompiler_ui_result_t>::failure(
                        input.error());
                captured = managed_capture_value_t{input.take_value()};
            } else if (binding.entity.kind ==
                       decompiler_entity_kind_t::dalvik_method) {
                if (!impl_->state.dalvik_provider)
                    return workspace_result_t<decompiler_ui_result_t>::failure(
                        ui_request_error(workspace_error_code_t::provider_unavailable,
                            "verified Dalvik provider identity is unavailable",
                            "decompiler_ui.entity.capture.dalvik"));
                auto input = capture_dalvik_entity_input(
                    *publication, binding, *impl_->state.dalvik_provider, cancel);
                if (!input)
                    return workspace_result_t<decompiler_ui_result_t>::failure(
                        input.error());
                captured = managed_capture_value_t{input.take_value()};
            }
            if (!captured)
                return workspace_result_t<decompiler_ui_result_t>::failure(
                    ui_request_error(workspace_error_code_t::unsupported_format,
                        "managed entity kind has no capture provider",
                        "decompiler_ui.entity.capture"));
            if (workspace->analysis_publication() != publication)
                return workspace_result_t<decompiler_ui_result_t>::failure(
                    ui_request_error(workspace_error_code_t::target_stale,
                        "workspace changed during managed entity capture",
                        "decompiler_ui.entity.capture"));
            {
                std::lock_guard lock(impl_->state.managed_capture_mutex);
                const auto capture_byte_size =
                    binding.entity.kind == decompiler_entity_kind_t::cli_method
                        ? 0ULL
                        : artifact.provider_size;
                const auto existing =
                    impl_->state.managed_capture_cache.find(key);
                if (existing != impl_->state.managed_capture_cache.end()) {
                    impl_->state.managed_capture_cache_bytes -=
                        existing->second.byte_size;
                    impl_->state.managed_capture_cache.erase(existing);
                }
                const auto has_capacity = [&]() {
                    const auto used_bytes =
                        impl_->state.managed_capture_cache_bytes +
                        impl_->state.managed_module_snapshot_cache_bytes +
                        impl_->state.managed_module_snapshot_reserved_bytes;
                    return impl_->state.managed_capture_cache.size() <
                            impl_->state.config.max_managed_capture_cache_entries &&
                        used_bytes <= impl_->state.config.max_managed_capture_bytes &&
                        capture_byte_size <=
                            impl_->state.config.max_managed_capture_bytes - used_bytes;
                };
                while (!has_capacity()) {
                    if (erase_oldest_managed_capture_locked(impl_->state))
                        continue;
                    if (erase_oldest_managed_module_snapshot_locked(
                            impl_->state))
                        continue;
                    return workspace_result_t<decompiler_ui_result_t>::failure(
                        ui_request_error(workspace_error_code_t::limit_exceeded,
                            "managed capture cache cannot satisfy its memory budget",
                            "decompiler_ui.entity.capture.cache"));
                }
                managed_capture_cache_entry_t entry;
                entry.value = *captured;
                entry.generation = binding.generation;
                entry.analysis_revision = binding.analysis_revision;
                entry.overlay_revision = binding.overlay_revision;
                entry.provider_hash = binding.provider_hash;
                entry.byte_size = capture_byte_size;
                entry.touch = ++impl_->state.managed_capture_clock;
                impl_->state.managed_capture_cache.insert_or_assign(
                    key, std::move(entry));
                impl_->state.managed_capture_cache_bytes +=
                    capture_byte_size;
            }
        }
        if (const auto* request = std::get_if<
                std::shared_ptr<const managed_cli::request_t>>(&*captured))
            result = decompile_cli(*request, source, cache_mode, cancel);
        else if (const auto* input = std::get_if<
                     std::shared_ptr<const jvm_ssa::jvm_method_input_t>>(
                         &*captured))
            result = decompile_jvm(*input, source, profile, cache_mode, cancel);
        else if (const auto* input = std::get_if<
                     std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>(
                         &*captured))
            result = decompile_dalvik(*input, source, profile, cache_mode, cancel);
    }
    const auto after = workspace->analysis_publication();
    if (after != publication)
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::target_stale,
                "workspace changed during decompilation",
                "decompiler_ui.entity.decompile"));
    auto after_validation = validate_generation_bound_entity(
        workspace->identity(), *after, binding, cancel);
    if (!after_validation)
        return workspace_result_t<decompiler_ui_result_t>::failure(
            after_validation.error());
    return result;
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "decompiler entity capture allocation failed",
                "decompiler_ui.entity.decompile"));
    }
}

workspace_result_t<void>
decompiler_ui_integration_t::invalidate_workspace() {
    if (!impl_ || !impl_->state.workspace || !impl_->state.service) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompiler UI integration is not initialized",
                "invalidate_workspace"));
    }
    auto result = impl_->state.service->invalidate_workspace(
        impl_->state.workspace->identity().binary_id().to_hex(),
        impl_->state.workspace->generation());
    {
        std::lock_guard lock(impl_->state.managed_capture_mutex);
        ++impl_->state.managed_cache_epoch;
        impl_->state.managed_capture_cache.clear();
        impl_->state.managed_module_snapshot_cache.clear();
        impl_->state.managed_capture_cache_bytes = 0;
        impl_->state.managed_module_snapshot_cache_bytes = 0;
        impl_->state.managed_capture_clock = 0;
        impl_->state.managed_capture_condition.notify_all();
    }
    return result;
}

decompiler_ui_integration_metrics_t
decompiler_ui_integration_t::metrics() const noexcept {
    if (!impl_)
        return {};
    std::lock_guard<std::mutex> lock(impl_->state.metrics_mutex);
    return impl_->state.metrics;
}

std::shared_ptr<decompiler_pipeline_service_t>
decompiler_ui_integration_t::service() const noexcept {
    if (!impl_)
        return nullptr;
    return impl_->state.service;
}

std::shared_ptr<analysis_workspace_t>
decompiler_ui_integration_t::workspace() const noexcept {
    if (!impl_)
        return nullptr;
    return impl_->state.workspace;
}

}
