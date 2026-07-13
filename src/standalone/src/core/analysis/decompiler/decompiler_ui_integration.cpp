#include "decompiler_ui_integration.hpp"

#include "legacy_document_adapter.hpp"
#include "native_worker_host.hpp"

#include "decompiler_contracts.hpp"
#include "pseudocode_renderer_v2.hpp"
#include "typed_ast_v2.hpp"

#include "../../disasm/ghidra_adapters/aida_arch_map.hpp"
#include "../../disasm/ghidra_adapters/aida_load_image.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <mutex>
#include <new>
#include <utility>

namespace aida::analysis {
namespace {

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
    decompiler_ui_integration_config_t config;
    mutable std::mutex metrics_mutex;
    decompiler_ui_integration_metrics_t metrics;
    std::atomic<std::uint64_t> request_counter{0};
    std::optional<decompiler_provider_identity_t> native_provider;
    sha256_digest_t native_worker_protocol_hash;
    sha256_digest_t native_manifest_hash;
    std::uint32_t native_worker_protocol_version = 0;
    std::shared_ptr<std::mutex> native_capture_mutex;
};

workspace_error_t ui_request_error(
    const workspace_error_code_t code,
    std::string message,
    std::string phase)
{
    return make_workspace_error(code, std::move(message), std::move(phase));
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

decompiler_provider_identity_t packaged_provider_identity(
    const decompiler_provider_id_t provider,
    std::string provider_name,
    std::string worker_build_id)
{
    decompiler_provider_identity_t result;
    result.provider = provider;
    result.provider_name = std::move(provider_name);
    result.provider_version = "1";
    result.provider_binary_hash = stable_serialization_hash(
        result.provider_name + "|provider|" + result.provider_version);
    result.worker_build_id = std::move(worker_build_id);
    result.worker_build_hash = stable_serialization_hash(
        result.worker_build_id + "|build|" + result.provider_version);
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
    auto revision = ghidra_adapter::make_ghidra_adapter_revision(
        workspace->identity(), *publication->snapshot, cancel);
    if (!revision)
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            revision.error());
    auto load_image = ghidra_adapter::ghidra_load_image_t::create(
        workspace->provider_handle(), image, language.value(), revision.value(), {}, cancel);
    if (!load_image)
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            load_image.error());
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
    constexpr std::uint64_t maximum_virtual_image_bytes =
        256ULL * 1024ULL * 1024ULL - 64ULL;
    if (image->image_size == 0 || image->image_size > maximum_virtual_image_bytes ||
        image->image_size > (std::numeric_limits<std::size_t>::max)()) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "native decompiler virtual image exceeds the isolated worker snapshot limit",
                "decompiler_ui.native_capture.image_limit"));
    }
    native_worker::native_provider_snapshot_t snapshot;
    snapshot.image_base = image->image_base;
    snapshot.virtual_image.resize(static_cast<std::size_t>(image->image_size), 0);
    for (const auto& range : load_image.value()->mapped_ranges()) {
        if (cancel.stop_requested() || std::chrono::steady_clock::now() >= request.deadline) {
            return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
                ui_request_error(cancel.deadline_exceeded() ||
                        std::chrono::steady_clock::now() >= request.deadline
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "native decompiler snapshot capture was cancelled",
                    "decompiler_ui.native_capture.read"));
        }
        const auto rva = relative_value(range.start, image->image_base);
        if (!rva || *rva > image->image_size || range.size > image->image_size - *rva) {
            return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
                ui_request_error(workspace_error_code_t::integrity_failure,
                    "native decompiler mapped range is outside the normalized image",
                    "decompiler_ui.native_capture.mapping"));
        }
        auto read = load_image.value()->read(range.start, range.size, cancel);
        if (!read)
            return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
                read.error());
        if (read.value().bytes.size() != range.size) {
            return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
                ui_request_error(workspace_error_code_t::integrity_failure,
                    "native decompiler mapped range snapshot is truncated",
                    "decompiler_ui.native_capture.read"));
        }
        std::copy(read.value().bytes.begin(), read.value().bytes.end(),
            snapshot.virtual_image.begin() + static_cast<std::size_t>(*rva));
    }
    const auto serialized = native_worker::serialize_native_provider_snapshot(snapshot);
    if (serialized.empty()) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            ui_request_error(workspace_error_code_t::limit_exceeded,
                "native decompiler snapshot serialization failed",
                "decompiler_ui.native_capture.serialize"));
    }
    std::vector<std::uint8_t> serialized_bytes(serialized.begin(), serialized.end());
    auto shared_snapshot = std::make_shared<const std::vector<std::uint8_t>>(
        std::move(serialized_bytes));
    std::shared_ptr<const decompiler_provider_context_t> context =
        std::make_shared<ghidra_native_provider_context_t>(
            std::move(shared_snapshot), stable_serialization_hash(serialized));
    return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::success(
        std::move(context));
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
    if (config.max_function_bytes == 0 || config.max_function_chunks == 0) {
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
        builtin.cli.identity = packaged_provider_identity(
            decompiler_provider_id_t::ilspy_cli,
            "aida-managed-cli", "aida-managed-cli-offline-worker-v2");
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
        auto cache = decompiler_cache_v9_t::create();
        if (!cache) {
            return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
                cache.error());
        }
        config.service_config.isolated_provider_host = runtime.value().provider_host;
        auto service = decompiler_pipeline_service_t::create(
            std::move(providers), cache.take_value(), {}, config.service_config);
        if (!service) {
            return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
                service.error());
        }
        auto integration = create(workspace, service.take_value(), std::move(config));
        if (!integration)
            return integration;
        integration.value()->impl_->state.native_provider = runtime.value().provider;
        integration.value()->impl_->state.native_worker_protocol_hash =
            runtime.value().worker_protocol_hash;
        integration.value()->impl_->state.native_manifest_hash = runtime.value().manifest_hash;
        integration.value()->impl_->state.native_worker_protocol_version =
            runtime.value().worker_protocol_version;
        integration.value()->impl_->state.native_capture_mutex = std::make_shared<std::mutex>();
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
    if (request.function_address == 0 || max_function_bytes == 0 ||
        max_function_chunks == 0 || request.worker_protocol_hash.empty() ||
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

decompiler_ui_result_t
decompiler_ui_integration_t::map_pipeline_result(
    const decompiler_pipeline_result_t& result) {
    decompiler_ui_result_t ui_result;
    ui_result.status = result.status;
    ui_result.elapsed_ms = result.elapsed_wall_clock_ms;
    ui_result.cache_hit_stage = result.cache_hit_stage;
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
decompiler_ui_integration_t::decompile(
    const decompiler_ui_request_t& request,
    const cancellation_token_t& cancel) {
    if (!impl_ || !impl_->state.workspace || !impl_->state.service) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompiler UI integration is not initialized",
                "decompile"));
    }
    if (request.function_address == 0) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompiler UI request requires a non-zero function address",
                "decompile"));
    }
    impl_->state.request_counter.fetch_add(1, std::memory_order_acq_rel);
    impl_->increment_metric(&decompiler_ui_integration_metrics_t::total_requests);
    switch (request.source) {
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
    auto pipeline_request = std::move(built_request.value());
    auto pipeline_result = impl_->state.service->decompile(pipeline_request, cancel);
    if (!publication_matches_request(*impl_->state.workspace, pipeline_request)) {
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
        if (impl_->state.config.reject_null_ast && result_has_null_ast(pipeline_result)) {
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::rejected_null_ast);
            decompiler_ui_result_t ui_result;
            ui_result.status = decompiler_pipeline_status_t::normalization_failed;
            ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
            decompiler_ui_diagnostic_t diag;
            diag.severity = decompiler_diagnostic_severity_t::error;
            diag.code = decompiler_diagnostic_code_t::malformed_ast;
            diag.message = "decompiler returned a null AST: rejected by integration policy";
            diag.retryable = true;
            ui_result.diagnostics.push_back(std::move(diag));
            return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
        }
        if (impl_->state.config.reject_guessed_body && result_has_guessed_body(pipeline_result)) {
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::rejected_guessed_body);
            decompiler_ui_result_t ui_result;
            ui_result.status = decompiler_pipeline_status_t::normalization_failed;
            ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
            decompiler_ui_diagnostic_t diag;
            diag.severity = decompiler_diagnostic_severity_t::error;
            diag.code = decompiler_diagnostic_code_t::malformed_ast;
            diag.message = "decompiler returned a body without typed proof: rejected by integration policy";
            diag.retryable = true;
            ui_result.diagnostics.push_back(std::move(diag));
            return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
        }
        if (request.require_complete_source_map &&
            !result_has_complete_source_map(pipeline_result)) {
            decompiler_ui_result_t ui_result;
            ui_result.status = decompiler_pipeline_status_t::rendering_failed;
            ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
            decompiler_ui_diagnostic_t diag;
            diag.severity = decompiler_diagnostic_severity_t::error;
            diag.code = decompiler_diagnostic_code_t::source_map_rejected;
            diag.message = "decompiler returned an incomplete source map: rejected by request policy";
            diag.retryable = true;
            ui_result.diagnostics.push_back(std::move(diag));
            return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
        }
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::completed);
        if (pipeline_result.cache_hit_stage)
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::cache_hits);
    } else {
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
    return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
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
        !impl_->state.native_capture_mutex ||
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
    if (function_address == 0 || !publication ||
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

    decompiler_ui_request_t request;
    request.source = source;
    request.function_address = function_address;
    request.function_end_address = function->end.value;
    request.function_symbol = resolve_function_symbol(*publication->snapshot, *function);
    request.language = native_language_identity(
        language.value(), *publication->snapshot->normalized_image);
    request.worker_protocol_hash = impl_->state.native_worker_protocol_hash;
    request.metadata_revision = publication->analysis_revision;
    request.type_graph_revision = publication->analysis_revision;
    request.profile = profile;
    request.cache_mode = cache_mode;
    request.provider_registration_id = "aida.decompiler.native.ghidra";
    request.dependencies = {
        {"aida.native.provider",
            impl_->state.native_provider->provider_version + "|" +
                impl_->state.native_provider->worker_build_id,
            impl_->state.native_provider->provider_binary_hash},
        {"aida.native.worker.manifest",
            std::to_string(native_worker::k_native_worker_manifest_schema_version),
            impl_->state.native_manifest_hash},
        {"aida.native.worker.protocol",
            std::to_string(impl_->state.native_worker_protocol_version),
            impl_->state.native_worker_protocol_hash},
        {"ghidra.language",
            request.language.language_version + "|" + request.language.compiler_spec_id,
            request.language.language_spec_hash}};
    const auto capture_mutex = impl_->state.native_capture_mutex;
    request.provider_context_factory = [workspace, capture_mutex](
        const decompiler_provider_request_t& provider_request,
        const cancellation_token_t& provider_cancel) {
        std::lock_guard<std::mutex> lock(*capture_mutex);
        return capture_native_provider_context(workspace, provider_request, provider_cancel);
    };
    return decompile(request, cancel);
}

workspace_result_t<void>
decompiler_ui_integration_t::invalidate_workspace() {
    if (!impl_ || !impl_->state.workspace || !impl_->state.service) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompiler UI integration is not initialized",
                "invalidate_workspace"));
    }
    return impl_->state.service->invalidate_workspace(
        impl_->state.workspace->identity().binary_id().to_hex(),
        impl_->state.workspace->generation());
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
