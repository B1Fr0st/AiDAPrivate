#include "decompiler_service.hpp"

#include "advanced_cfg.hpp"
#include "calling_convention.hpp"
#include "pseudocode_readability.hpp"
#include "semantic_fusion.hpp"
#include "type_recovery.hpp"
#include "../../disasm/ghidra_adapters/aida_arch_map.hpp"
#include "../../disasm/ghidra_adapters/aida_function_db.hpp"
#include "../../disasm/ghidra_adapters/aida_load_image.hpp"
#include "../../disasm/ghidra_decompiler.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <functional>
#include <future>
#include <list>
#include <limits>
#include <mutex>
#include <new>
#include <stdexcept>
#include <tuple>
#include <unordered_map>

#include <nlohmann/json.hpp>

namespace aida::analysis {

namespace {

using json = nlohmann::json;

struct resolved_function_t {
    std::shared_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<const analysis_snapshot_t> snapshot;
    std::shared_ptr<const pe_image_t> image;
    function_record_t function;
    address_t normalized_address;
    std::uint64_t entry_va = 0;
    std::uint64_t end_va = 0;
    std::uint64_t function_rva = 0;
    std::uint64_t provider_offset = 0;
    std::uint64_t byte_size = 0;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
};

const char* address_space_text(address_space_id_t space) noexcept {
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

bool same_address(const address_t& left, const address_t& right) noexcept {
    return left.value == right.value && left.space == right.space &&
        left.architecture == right.architecture;
}

bool valid_workspace_id(const std::string& value, std::size_t max_bytes) noexcept {
    if (value.empty() || value.size() > max_bytes)
        return false;
    for (const unsigned char character : value) {
        if (!std::isalnum(character) && character != '-' &&
            character != '_' && character != '.')
            return false;
    }
    return true;
}

workspace_result_t<void> validate_request_context(
    const decompiler_request_context_t& context,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const decompiler_service_limits_t& limits,
    const char* phase) {
    if (!workspace || workspace->closing() || workspace->closed()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "workspace is closing", phase));
    }
    if (!valid_workspace_id(context.workspace_id, limits.max_workspace_id_bytes) ||
        context.function_id == 0 || !context.address_space ||
        !context.generation || !context.overlay_revision || !context.type_revision) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "decompiler request context is incomplete or exceeds its bounded identity format",
            phase));
    }
    if (context.function_address.space != *context.address_space) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "decompiler request address space does not match its explicit context",
            phase));
    }
    if (context.function_address.architecture != architecture_id_t::unknown &&
        context.function_address.architecture != workspace->identity().architecture()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "decompiler request architecture does not match the workspace",
            phase));
    }
    if (*context.generation != workspace->generation() ||
        *context.overlay_revision != workspace->overlay_revision()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "decompiler request context revisions are stale",
            phase));
    }
    return workspace_result_t<void>::success();
}

std::uint64_t utc_milliseconds() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

workspace_error_t cancellation_error(const cancellation_token_t& cancel,
                                     const char* phase) {
    auto error = make_workspace_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                   : workspace_error_code_t::cancelled,
        cancel.deadline_exceeded() ? "decompiler deadline exceeded"
                                   : "decompiler request cancelled",
        phase);
    error.cancellation = !cancel.deadline_exceeded();
    error.deadline = cancel.deadline_exceeded();
    return error;
}

std::uint64_t workspace_load_base(const workspace_identity_t& identity,
                                  const pe_image_t* image) noexcept {
    if (identity.target_kind() == target_kind_t::live_snapshot && identity.module())
        return identity.module()->base;
    return image ? image->image_base() : identity.image_base();
}

workspace_result_t<std::uint64_t> rva_to_workspace_va(
    std::uint64_t rva,
    const workspace_identity_t& identity,
    const pe_image_t* image,
    const char* phase) {
    const std::uint64_t base = workspace_load_base(identity, image);
    std::uint64_t address = 0;
    if (!checked_add_u64(base, rva, address)) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "workspace virtual address overflows",
            phase));
    }
    return workspace_result_t<std::uint64_t>::success(address);
}

workspace_result_t<std::uint64_t> address_to_va(
    const address_t& address,
    const workspace_identity_t& identity,
    const pe_image_t* image) {
    if (address.architecture != architecture_id_t::unknown &&
        address.architecture != identity.architecture()) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "address architecture does not match the workspace",
            "decompiler.resolve_address"));
    }
    if (identity.target_kind() == target_kind_t::live_snapshot &&
        address.space != address_space_id_t::live_virtual) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_address_space,
            "live decompilation requires a live-virtual address",
            "decompiler.resolve_address"));
    }
    switch (address.space) {
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        return workspace_result_t<std::uint64_t>::success(address.value);
    case address_space_id_t::relative_virtual:
        return rva_to_workspace_va(address.value, identity, image,
                                   "decompiler.resolve_address");
    case address_space_id_t::file_offset:
        if (image) {
            auto rva = image->file_offset_to_rva(address.value);
            if (!rva)
                return workspace_result_t<std::uint64_t>::failure(rva.error());
            return rva_to_workspace_va(rva.value(), identity, image,
                                       "decompiler.resolve_address");
        }
        break;
    }
    return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
        workspace_error_code_t::unsupported_address_space,
        "address cannot be translated for this workspace",
        "decompiler.resolve_address"));
}

workspace_result_t<std::uint64_t> address_to_provider_offset(
    const address_t& address,
    const workspace_identity_t& identity,
    const pe_image_t* image,
    std::uint64_t size) {
    if (image) {
        switch (address.space) {
        case address_space_id_t::file_offset:
            if (address.value > image->headers_size() &&
                !image->section_for_file_offset(address.value, size)) {
                return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
                    workspace_error_code_t::out_of_range,
                    "file range is outside the mapped image",
                    "decompiler.provider_offset"));
            }
            return workspace_result_t<std::uint64_t>::success(address.value);
        case address_space_id_t::relative_virtual:
            return image->rva_to_file_offset(address.value, size);
        case address_space_id_t::virtual_address:
        case address_space_id_t::live_virtual: {
            const std::uint64_t base = workspace_load_base(identity, image);
            if (address.value < base) {
                return workspace_result_t<std::uint64_t>::failure(
                    make_workspace_error(workspace_error_code_t::out_of_range,
                        "address precedes the workspace image base",
                        "decompiler.provider_offset"));
            }
            return image->rva_to_file_offset(address.value - base, size);
        }
        }
    }
    auto va = address_to_va(address, identity, image);
    if (!va)
        return workspace_result_t<std::uint64_t>::failure(va.error());
    const std::uint64_t base = identity.module()
        ? identity.module()->base : identity.image_base();
    if (va.value() < base)
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "address precedes the captured provider base",
            "decompiler.provider_offset"));
    return workspace_result_t<std::uint64_t>::success(va.value() - base);
}

workspace_result_t<resolved_function_t> resolve_function(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const address_t& requested,
    const decompiler_service_limits_t& limits) {
    if (!workspace || workspace->closing() || workspace->closed()) {
        return workspace_result_t<resolved_function_t>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "workspace is closing",
            "decompiler.resolve_function"));
    }
    auto snapshot = workspace->snapshot();
    if (!snapshot) {
        return workspace_result_t<resolved_function_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "no analysis snapshot is available for function-boundary validation",
            "decompiler.resolve_function"));
    }
    auto image = workspace->image();
    if (snapshot->generation != workspace->generation() ||
        snapshot->analysis_revision != workspace->analysis_revision()) {
        return workspace_result_t<resolved_function_t>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "analysis snapshot revisions are stale",
            "decompiler.resolve_function"));
    }
    auto requested_va = address_to_va(requested, workspace->identity(), image.get());
    if (!requested_va)
        return workspace_result_t<resolved_function_t>::failure(requested_va.error());

    const function_record_t* selected = nullptr;
    std::uint64_t selected_start = 0;
    std::uint64_t selected_end = 0;
    for (const auto& function : snapshot->functions) {
        auto start = address_to_va(function.start, workspace->identity(), image.get());
        auto end = address_to_va(function.end, workspace->identity(), image.get());
        if (!start || !end || end.value() <= start.value())
            continue;
        if (requested_va.value() >= start.value() && requested_va.value() < end.value()) {
            if (!selected || end.value() - start.value() < selected_end - selected_start) {
                selected = &function;
                selected_start = start.value();
                selected_end = end.value();
            }
        }
    }
    if (!selected) {
        return workspace_result_t<resolved_function_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "the requested address is not inside a proven function boundary",
            "decompiler.resolve_function"));
    }

    const std::uint64_t byte_size = selected_end - selected_start;
    if (byte_size == 0 || byte_size > limits.max_function_bytes) {
        return workspace_result_t<resolved_function_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "function byte range exceeds the decompiler budget",
            "decompiler.resolve_function"));
    }
    auto provider_offset = address_to_provider_offset(
        selected->start, workspace->identity(), image.get(), byte_size);
    if (!provider_offset)
        return workspace_result_t<resolved_function_t>::failure(provider_offset.error());
    if (provider_offset.value() > workspace->provider().size() ||
        byte_size > workspace->provider().size() - provider_offset.value()) {
        return workspace_result_t<resolved_function_t>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "function range is outside the workspace byte provider",
            "decompiler.resolve_function"));
    }

    resolved_function_t result;
    result.workspace = workspace;
    result.snapshot = std::move(snapshot);
    result.image = std::move(image);
    result.function = *selected;
    result.normalized_address = selected->start;
    result.entry_va = selected_start;
    result.end_va = selected_end;
    result.byte_size = byte_size;
    result.provider_offset = provider_offset.value();
    result.generation = result.snapshot->generation;
    result.analysis_revision = result.snapshot->analysis_revision;
    if (result.image) {
        const std::uint64_t base = workspace_load_base(workspace->identity(),
                                                       result.image.get());
        if (selected_start < base) {
            return workspace_result_t<resolved_function_t>::failure(
                make_workspace_error(workspace_error_code_t::out_of_range,
                    "function address precedes the workspace image base",
                    "decompiler.resolve_function"));
        }
        result.function_rva = selected_start - base;
    } else {
        const std::uint64_t base = workspace->identity().module()
            ? workspace->identity().module()->base : workspace->identity().image_base();
        result.function_rva = selected_start - base;
    }
    return workspace_result_t<resolved_function_t>::success(std::move(result));
}

workspace_result_t<void> validate_resolved_context(
    const decompiler_request_context_t& context,
    const resolved_function_t& function,
    const char* phase) {
    if (context.function_id != function.function.id ||
        *context.generation != function.generation ||
        *context.overlay_revision != function.overlay_revision) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "decompiler request context no longer identifies the resolved function revision",
            phase));
    }
    auto requested_va = address_to_va(context.function_address,
        function.workspace->identity(), function.image.get());
    if (!requested_va)
        return workspace_result_t<void>::failure(requested_va.error());
    if (requested_va.value() != function.entry_va) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "decompiler request function address is not the validated function entry",
            phase));
    }
    return workspace_result_t<void>::success();
}

bool result_address_in_range(const resolved_function_t& function,
                             std::uint64_t address) noexcept {
    if (address == 0 ||
        (address >= function.entry_va && address < function.end_va))
        return true;
    const auto& identity = function.workspace->identity();
    const std::uint64_t image_base = workspace_load_base(identity, function.image.get());
    std::uint64_t image_end = image_base;
    if (identity.target_kind() == target_kind_t::live_snapshot && identity.module()) {
        checked_add_u64(identity.module()->base, identity.module()->size, image_end);
    } else if (function.image) {
        checked_add_u64(function.image->image_base(), function.image->image_size(), image_end);
    }
    return address >= image_base && address < image_end;
}

struct decompiler_adapter_inputs_t {
    std::shared_ptr<const workspace_image_t> image;
    ghidra_adapter::ghidra_language_catalog_t language_catalog;
    ghidra_adapter::ghidra_language_spec_t language;
    ghidra_adapter::ghidra_adapter_revision_t revision;
    ghidra_adapter::ghidra_adapter_cache_key_t cache_key;
    std::shared_ptr<const ghidra_adapter::ghidra_load_image_t> load_image;
    std::shared_ptr<const ghidra_adapter::ghidra_function_database_t> function_database;
    ghidra_adapter::ghidra_entity_address_key_t function;
};

workspace_result_t<decompiler_adapter_inputs_t> prepare_adapter_inputs(
    const resolved_function_t& function,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(
            cancellation_error(cancel, "decompiler.adapter"));
    }
    auto image = function.workspace->normalized_image();
    if (!image) {
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "decompiler requires a normalized workspace image",
            "decompiler.adapter"));
    }
    auto language = ghidra_adapter::resolve_ghidra_language(*image, cancel);
    if (!language)
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(language.error());
    auto revision = ghidra_adapter::make_ghidra_adapter_revision(
        function.workspace->identity(), *function.snapshot, cancel);
    if (!revision)
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(revision.error());
    if (revision.value().generation != function.generation ||
        revision.value().analysis_revision != function.analysis_revision ||
        revision.value().overlay_revision != function.overlay_revision) {
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "Ghidra adapter revision does not match the validated workspace revision",
            "decompiler.adapter"));
    }
    auto load_image = ghidra_adapter::ghidra_load_image_t::create(
        function.workspace->provider_handle(), image, language.value(), revision.value(), {}, cancel);
    if (!load_image)
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(load_image.error());
    auto provider_offset = load_image.value()->provider_offset_for_address(
        function.normalized_address, cancel);
    if (!provider_offset)
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(provider_offset.error());
    if (provider_offset.value() != function.provider_offset) {
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "Ghidra load image does not preserve the validated function provider offset",
            "decompiler.adapter"));
    }
    auto function_database = ghidra_adapter::ghidra_function_database_t::create(
        function.workspace->identity(), *image, *function.snapshot, language.value(),
        revision.value(), {}, {}, {}, cancel);
    if (!function_database)
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(
            function_database.error());
    const auto* adapter_function = function_database.value()->find_function(function.function.id);
    if (!adapter_function ||
        !same_address(adapter_function->key.address, function.normalized_address) ||
        !same_address(adapter_function->end, function.function.end)) {
        return workspace_result_t<decompiler_adapter_inputs_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "Ghidra function database does not preserve the validated function range",
            "decompiler.adapter"));
    }
    decompiler_adapter_inputs_t inputs;
    inputs.image = std::move(image);
    inputs.language_catalog.staging_root = language.value().language_root;
    inputs.language_catalog.languages.push_back({
        language.value().language_id, {language.value().compiler_spec_id}});
    inputs.language = language.take_value();
    inputs.revision = revision.take_value();
    inputs.cache_key = load_image.value()->cache_key();
    inputs.load_image = load_image.take_value();
    inputs.function_database = function_database.take_value();
    inputs.function = adapter_function->key;
    return workspace_result_t<decompiler_adapter_inputs_t>::success(std::move(inputs));
}

workspace_result_t<sha256_digest_t> hash_function(
    const resolved_function_t& function,
    const cancellation_token_t& cancel) {
    auto subrange = subrange_provider_t::create(
        function.workspace->provider_handle(), function.provider_offset,
        function.byte_size, "decompiler-function");
    if (!subrange)
        return workspace_result_t<sha256_digest_t>::failure(subrange.error());
    return sha256_provider(*subrange.value(), cancel, 1ULL << 20);
}

workspace_result_t<decompiler_cache_key_t> make_cache_key(
    const resolved_function_t& function,
    const workspace_database_versions_t& versions,
    const sha256_digest_t& content_hash,
    const std::optional<decompiler_request_context_t>& context,
    const ghidra_decompiler::ghidra_adapter_decompile_cache_key_t& adapter_cache_key,
    const decompiler_service_limits_t& limits) {
    const auto& identity = function.workspace->identity();
    decompiler_cache_key_t key;
    key.binary_id = identity.binary_id();
    key.format = identity.format();
    key.architecture = identity.architecture();
    key.architecture_mode = identity.architecture_mode();
    key.abi = identity.abi();
    key.endian = identity.endian();
    key.engine_version = versions.engine_version;
    key.specification_version = versions.specification_version;
    key.analysis_settings_hash = versions.analysis_settings_hash;
    std::string scope = "|ghidra-adapter-decompile=" + adapter_cache_key.digest.to_hex();
    if (context) {
        scope += std::string{"|decompiler-context:v1|workspace="} +
            context->workspace_id + "|space=" + address_space_text(*context->address_space) +
            "|type-revision=" + std::to_string(*context->type_revision);
    }
    if (scope.size() > limits.max_cache_key_bytes ||
        key.analysis_settings_hash.size() > limits.max_cache_key_bytes - scope.size()) {
        return workspace_result_t<decompiler_cache_key_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "decompiler cache context exceeds the bounded cache-key budget",
            "decompiler.cache.key"));
    }
    key.analysis_settings_hash += scope;
    key.function_id = function.function.id;
    key.function_rva = function.function_rva;
    key.function_content_hash = content_hash;
    key.analysis_revision = function.analysis_revision;
    key.overlay_revision = function.overlay_revision;
    key.generation = function.generation;
    const std::string canonical = key.canonical();
    if (canonical.empty() || canonical.size() > limits.max_cache_key_bytes) {
        return workspace_result_t<decompiler_cache_key_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "decompiler cache key exceeds the configured bound",
            "decompiler.cache.key"));
    }
    return workspace_result_t<decompiler_cache_key_t>::success(std::move(key));
}

json serialize_result(const decompiler_result_t& result) {
    json annotations = json::array();
    for (const auto& item : result.annotations) {
        annotations.push_back({{"kind", item.kind}, {"start", item.start},
            {"end", item.end}, {"address", item.address}, {"name", item.name}});
    }
    json lines = json::array();
    for (const auto& item : result.line_to_address)
        lines.push_back({item.first, item.second});
    json callees = json::array();
    for (const auto& item : result.callees)
        callees.push_back({item.first, item.second});
    return json{{"function_name", result.function_name},
        {"pseudocode", result.pseudocode}, {"annotations", std::move(annotations)},
        {"line_to_address", std::move(lines)}, {"callees", std::move(callees)},
        {"sleigh_id", result.sleigh_id}, {"elapsed_ms", result.elapsed_ms}};
}

workspace_result_t<void> validate_result_size(
    const decompiler_result_t& result,
    const decompiler_service_limits_t& limits,
    const char* phase);

workspace_result_t<decompiler_result_t> deserialize_result(
    const std::string& text,
    const resolved_function_t& function,
    const std::optional<decompiler_request_context_t>& context,
    const decompiler_service_limits_t& limits) {
    json value = json::parse(text, nullptr, false);
    if (value.is_discarded() || !value.is_object()) {
        return workspace_result_t<decompiler_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "persistent decompiler cache contains invalid JSON",
            "decompiler.cache.read"));
    }
    try {
        decompiler_result_t result;
        result.binary_id = function.workspace->identity().binary_id();
        result.context = context;
        result.function_id = function.function.id;
        result.function_address = function.function.start;
        result.function_name = value.at("function_name").get<std::string>();
        result.pseudocode = value.at("pseudocode").get<std::string>();
        result.sleigh_id = value.at("sleigh_id").get<std::string>();
        result.elapsed_ms = value.value("elapsed_ms", 0.0);
        result.generation = function.generation;
        result.analysis_revision = function.analysis_revision;
        result.overlay_revision = function.overlay_revision;
        if (result.pseudocode.empty() ||
            result.pseudocode.size() > limits.max_pseudocode_bytes)
            throw std::length_error("pseudocode exceeds limit");
        const auto& annotations = value.at("annotations");
        if (!annotations.is_array() || annotations.size() > limits.max_annotations)
            throw std::length_error("annotation count exceeds limit");
        result.annotations.reserve(annotations.size());
        for (const auto& item : annotations) {
            decompiler_annotation_t annotation;
            annotation.kind = item.at("kind").get<std::uint8_t>();
            annotation.start = item.at("start").get<std::size_t>();
            annotation.end = item.at("end").get<std::size_t>();
            annotation.address = item.at("address").get<std::uint64_t>();
            annotation.name = item.at("name").get<std::string>();
            if (annotation.start > annotation.end ||
                annotation.end > result.pseudocode.size() ||
                !result_address_in_range(function, annotation.address))
                throw std::out_of_range("annotation range is invalid");
            result.annotations.push_back(std::move(annotation));
        }
        const auto& lines = value.at("line_to_address");
        const auto& callees = value.at("callees");
        if (!lines.is_array() || !callees.is_array() ||
            lines.size() > limits.max_annotations ||
            callees.size() > limits.max_annotations)
            throw std::length_error("mapping count exceeds limit");
        result.line_to_address.reserve(lines.size());
        for (const auto& item : lines) {
            if (!item.is_array() || item.size() != 2)
                throw std::invalid_argument("invalid line mapping");
            const std::uint64_t address = item[1].get<std::uint64_t>();
            if (!result_address_in_range(function, address))
                throw std::out_of_range("line mapping address is invalid");
            result.line_to_address.emplace_back(item[0].get<int>(), address);
        }
        result.callees.reserve(callees.size());
        for (const auto& item : callees) {
            if (!item.is_array() || item.size() != 2)
                throw std::invalid_argument("invalid callee mapping");
            const std::uint64_t address = item[1].get<std::uint64_t>();
            if (!result_address_in_range(function, address))
                throw std::out_of_range("callee mapping address is invalid");
            result.callees.emplace_back(item[0].get<std::string>(), address);
        }
        auto size = validate_result_size(result, limits, "decompiler.cache.read");
        if (!size)
            return workspace_result_t<decompiler_result_t>::failure(size.error());
        return workspace_result_t<decompiler_result_t>::success(std::move(result));
    } catch (const std::exception& error) {
        auto failure = make_workspace_error(workspace_error_code_t::integrity_failure,
            "persistent decompiler cache record failed validation",
            "decompiler.cache.read");
        failure.details.emplace_back("reason", error.what());
        return workspace_result_t<decompiler_result_t>::failure(std::move(failure));
    }
}

std::uint64_t result_size(const decompiler_result_t& result) {
    std::uint64_t size = result.pseudocode.size() + result.function_name.size() +
        result.sleigh_id.size();
    if (result.context)
        size += result.context->workspace_id.size();
    for (const auto& item : result.annotations)
        size += sizeof(item) + item.name.size();
    for (const auto& item : result.callees)
        size += sizeof(item) + item.first.size();
    size += result.line_to_address.size() *
        sizeof(std::pair<int, std::uint64_t>);
    return size;
}

workspace_result_t<void> validate_result_size(
    const decompiler_result_t& result,
    const decompiler_service_limits_t& limits,
    const char* phase) {
    std::uint64_t size = 0;
    const auto add = [&size](std::uint64_t value) {
        std::uint64_t next = 0;
        if (!checked_add_u64(size, value, next))
            return false;
        size = next;
        return true;
    };
    if (!add(result.pseudocode.size()) || !add(result.function_name.size()) ||
        !add(result.sleigh_id.size()) ||
        (result.context && !add(result.context->workspace_id.size()))) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "decompiler result size overflows its bounded accounting",
            phase));
    }
    for (const auto& item : result.annotations) {
        if (!add(sizeof(item)) || !add(item.name.size()))
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "decompiler annotation size overflows its bounded accounting",
                phase));
    }
    for (const auto& item : result.callees) {
        if (!add(sizeof(item)) || !add(item.first.size()))
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "decompiler callee size overflows its bounded accounting",
                phase));
    }
    if (result.line_to_address.size() >
        std::numeric_limits<std::uint64_t>::max() /
            sizeof(std::pair<int, std::uint64_t>) ||
        !add(result.line_to_address.size() *
             sizeof(std::pair<int, std::uint64_t>)) ||
        size > limits.max_result_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "decompiler result exceeds the configured output budget",
            phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> wait_ticket(
    const persistence_ticket_t& ticket,
    const cancellation_token_t& cancel,
    const cancellation_token_t* deadline,
    const char* phase) {
    if (!ticket.accepted || !ticket.completion.valid()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "persistence queue rejected the decompiler operation", phase));
    }
    while (ticket.completion.wait_for(std::chrono::milliseconds(10)) !=
           std::future_status::ready) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(cancellation_error(cancel, phase));
        if (deadline && deadline->stop_requested()) {
            return workspace_result_t<void>::failure(cancellation_error(*deadline, phase));
        }
    }
    return ticket.completion.get();
}

workspace_result_t<void> wait_ticket(
    const persistence_ticket_t& ticket,
    const cancellation_token_t& cancel,
    const char* phase) {
    return wait_ticket(ticket, cancel, nullptr, phase);
}

ghidra_decompiler::ghidra_decompile_result_limits_t make_adapter_result_limits(
    const decompiler_service_limits_t& limits) {
    ghidra_decompiler::ghidra_decompile_result_limits_t result;
    result.max_pseudocode_bytes = limits.max_pseudocode_bytes;
    result.max_annotations = limits.max_annotations;
    result.max_line_mappings = limits.max_annotations;
    result.max_callees = limits.max_annotations;
    result.max_result_bytes = limits.max_result_bytes;
    return result;
}

workspace_result_t<ghidra_decompiler::ghidra_adapter_decompile_request_t>
make_adapter_decompile_request(
    const resolved_function_t& function,
    const std::optional<decompiler_request_context_t>& context,
    const decompiler_adapter_inputs_t& adapter,
    const decompiler_service_limits_t& limits,
    const cancellation_token_t& cancel,
    std::atomic<bool>* engine_cancel,
    std::function<bool()> cancel_check,
    std::optional<std::chrono::steady_clock::time_point> deadline) {
    ghidra_decompiler::ghidra_adapter_decompile_request_t request;
    request.workspace_identity = &function.workspace->identity();
    request.workspace_id = context ? context->workspace_id
                                   : function.workspace->identity().binary_id().to_hex();
    request.normalized_image = adapter.image;
    request.analysis_snapshot = function.snapshot;
    request.language_catalog = adapter.language_catalog;
    request.language = adapter.language;
    request.revision = adapter.revision;
    request.adapter_cache_key = adapter.cache_key;
    request.load_image = adapter.load_image;
    request.function_database = adapter.function_database;
    request.function = adapter.function;
    request.type_revision = context ? *context->type_revision : function.analysis_revision;
    request.cancellation = cancel;
    request.engine_cancel = engine_cancel;
    request.cancel_check = std::move(cancel_check);
    request.deadline = deadline;
    request.result_limits = make_adapter_result_limits(limits);
    return workspace_result_t<ghidra_decompiler::ghidra_adapter_decompile_request_t>::success(
        std::move(request));
}

const char* adapter_error_code_text(
    ghidra_decompiler::ghidra_adapter_error_code_t code) noexcept {
    switch (code) {
    case ghidra_decompiler::ghidra_adapter_error_code_t::cancelled:
        return "cancelled";
    case ghidra_decompiler::ghidra_adapter_error_code_t::deadline_exceeded:
        return "deadline_exceeded";
    case ghidra_decompiler::ghidra_adapter_error_code_t::result_limit_exceeded:
        return "result_limit_exceeded";
    case ghidra_decompiler::ghidra_adapter_error_code_t::invalid_request:
        return "invalid_request";
    case ghidra_decompiler::ghidra_adapter_error_code_t::unsupported_language_family:
        return "unsupported_language_family";
    case ghidra_decompiler::ghidra_adapter_error_code_t::language_family_not_staged:
        return "language_family_not_staged";
    case ghidra_decompiler::ghidra_adapter_error_code_t::adapter_revision_mismatch:
        return "adapter_revision_mismatch";
    case ghidra_decompiler::ghidra_adapter_error_code_t::adapter_cache_key_mismatch:
        return "adapter_cache_key_mismatch";
    case ghidra_decompiler::ghidra_adapter_error_code_t::function_not_found:
        return "function_not_found";
    case ghidra_decompiler::ghidra_adapter_error_code_t::decompiler_unavailable:
        return "decompiler_unavailable";
    case ghidra_decompiler::ghidra_adapter_error_code_t::decompilation_failed:
        return "decompilation_failed";
    case ghidra_decompiler::ghidra_adapter_error_code_t::none:
        return "none";
    }
    return "unknown";
}

workspace_error_t map_adapter_error(
    const ghidra_decompiler::ghidra_adapter_error_t& adapter_error,
    const address_t& address) {
    workspace_error_code_t code = workspace_error_code_t::decode_failure;
    switch (adapter_error.code) {
    case ghidra_decompiler::ghidra_adapter_error_code_t::cancelled:
        code = workspace_error_code_t::cancelled;
        break;
    case ghidra_decompiler::ghidra_adapter_error_code_t::deadline_exceeded:
        code = workspace_error_code_t::deadline_exceeded;
        break;
    case ghidra_decompiler::ghidra_adapter_error_code_t::result_limit_exceeded:
        code = workspace_error_code_t::limit_exceeded;
        break;
    case ghidra_decompiler::ghidra_adapter_error_code_t::invalid_request:
        code = workspace_error_code_t::invalid_argument;
        break;
    case ghidra_decompiler::ghidra_adapter_error_code_t::unsupported_language_family:
    case ghidra_decompiler::ghidra_adapter_error_code_t::language_family_not_staged:
        code = workspace_error_code_t::unsupported_format;
        break;
    case ghidra_decompiler::ghidra_adapter_error_code_t::adapter_revision_mismatch:
    case ghidra_decompiler::ghidra_adapter_error_code_t::adapter_cache_key_mismatch:
        code = workspace_error_code_t::revision_conflict;
        break;
    case ghidra_decompiler::ghidra_adapter_error_code_t::function_not_found:
        code = workspace_error_code_t::target_not_found;
        break;
    case ghidra_decompiler::ghidra_adapter_error_code_t::decompiler_unavailable:
        code = workspace_error_code_t::provider_unavailable;
        break;
    case ghidra_decompiler::ghidra_adapter_error_code_t::decompilation_failed:
    case ghidra_decompiler::ghidra_adapter_error_code_t::none:
        break;
    }
    auto error = make_workspace_error(code,
        adapter_error.message.empty() ? "Ghidra adapter decompilation failed"
                                      : adapter_error.message,
        adapter_error.phase.empty() ? "decompiler.ghidra.adapter" : adapter_error.phase);
    error.address = address;
    error.cancellation = adapter_error.code ==
        ghidra_decompiler::ghidra_adapter_error_code_t::cancelled;
    error.deadline = adapter_error.code ==
        ghidra_decompiler::ghidra_adapter_error_code_t::deadline_exceeded;
    error.details.emplace_back("adapter_code", adapter_error_code_text(adapter_error.code));
    if (adapter_error.language_family) {
        error.details.emplace_back("adapter_language_family",
            std::to_string(static_cast<unsigned int>(*adapter_error.language_family)));
    }
    return error;
}

}

struct decompiler_service_t::state_t {
    struct cache_item_t {
        decompiler_cache_key_t key;
        decompiler_result_t result;
        std::uint64_t bytes = 0;
        std::list<std::string>::iterator lru;
    };

    std::weak_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<workspace_database_t> database;
    std::shared_ptr<decompiler_feedback_model_t> feedback;
    workspace_database_versions_t versions;
    decompiler_service_limits_t limits;
    cancellation_source_t cancellation;
    mutable std::mutex mutex;
    std::condition_variable condition;
    bool accepting = true;
    std::size_t active_contexts = 0;
    std::string workspace_id;
    std::unordered_map<std::string, cache_item_t> cache;
    std::list<std::string> lru;
    std::uint64_t cache_bytes = 0;
    std::vector<decompiler_history_entry_t> history;
    std::uint64_t requests = 0;
    std::uint64_t completed = 0;
    std::uint64_t failed = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t memory_cache_hits = 0;
    std::uint64_t persistent_cache_hits = 0;
    std::uint64_t cache_misses = 0;
    std::uint64_t evictions = 0;
    std::uint64_t feedback_publications = 0;
    std::uint64_t feedback_rejections = 0;
    std::uint64_t feedback_no_change = 0;
};

namespace {

void append_history_locked(decompiler_service_t::state_t& state,
                           const decompiler_result_t& result) {
    decompiler_history_entry_t entry;
    entry.function_id = result.function_id;
    entry.function_address = result.function_address;
    entry.function_name = result.function_name;
    entry.generation = result.generation;
    entry.overlay_revision = result.overlay_revision;
    entry.completed_utc_ms = utc_milliseconds();
    if (!state.history.empty()) {
        const auto& prior = state.history.back();
        if (prior.function_id == entry.function_id &&
            prior.generation == entry.generation &&
            prior.overlay_revision == entry.overlay_revision)
            state.history.pop_back();
    }
    state.history.push_back(std::move(entry));
    if (state.history.size() > state.limits.max_history_entries)
        state.history.erase(state.history.begin(),
            state.history.begin() +
                static_cast<std::ptrdiff_t>(state.history.size() -
                                            state.limits.max_history_entries));
}

void touch_cache_locked(decompiler_service_t::state_t& state,
                        decompiler_service_t::state_t::cache_item_t& item,
                        const std::string& key) {
    state.lru.erase(item.lru);
    state.lru.push_back(key);
    item.lru = std::prev(state.lru.end());
}

void insert_cache_locked(decompiler_service_t::state_t& state,
                         const decompiler_cache_key_t& cache_key,
                         decompiler_result_t result) {
    const std::string key = cache_key.canonical();
    auto existing = state.cache.find(key);
    if (existing != state.cache.end()) {
        state.cache_bytes -= existing->second.bytes;
        state.lru.erase(existing->second.lru);
        state.cache.erase(existing);
    }
    state.lru.push_back(key);
    decompiler_service_t::state_t::cache_item_t item;
    item.key = cache_key;
    item.bytes = result_size(result) + key.size();
    item.result = std::move(result);
    item.lru = std::prev(state.lru.end());
    state.cache_bytes += item.bytes;
    state.cache.emplace(key, std::move(item));
    while (!state.lru.empty() &&
           (state.cache.size() > state.limits.max_memory_cache_entries ||
            state.cache_bytes > state.limits.max_memory_cache_bytes)) {
        const std::string victim = state.lru.front();
        state.lru.pop_front();
        auto found = state.cache.find(victim);
        if (found != state.cache.end()) {
            state.cache_bytes -= found->second.bytes;
            state.cache.erase(found);
            ++state.evictions;
        }
    }
}

class context_guard_t {
public:
    explicit context_guard_t(std::shared_ptr<decompiler_service_t::state_t> state)
        : state_(std::move(state)) {}
    ~context_guard_t() {
        if (!state_)
            return;
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->active_contexts > 0)
            --state_->active_contexts;
        state_->condition.notify_all();
    }
    context_guard_t(const context_guard_t&) = delete;
    context_guard_t& operator=(const context_guard_t&) = delete;
private:
    std::shared_ptr<decompiler_service_t::state_t> state_;
};

workspace_result_t<void> acquire_context(
    const std::shared_ptr<decompiler_service_t::state_t>& state,
    const cancellation_token_t& caller,
    const cancellation_token_t& workspace_cancel,
    const cancellation_token_t& deadline) {
    std::unique_lock<std::mutex> lock(state->mutex);
    for (;;) {
        if (!state->accepting || state->cancellation.token().stop_requested()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::workspace_closing,
                "decompiler service is closing",
                "decompiler.acquire_context"));
        }
        if (caller.stop_requested())
            return workspace_result_t<void>::failure(
                cancellation_error(caller, "decompiler.acquire_context"));
        if (workspace_cancel.stop_requested())
            return workspace_result_t<void>::failure(
                cancellation_error(workspace_cancel, "decompiler.acquire_context"));
        if (deadline.stop_requested())
            return workspace_result_t<void>::failure(
                cancellation_error(deadline, "decompiler.acquire_context"));
        if (state->active_contexts < state->limits.max_parallel_contexts) {
            ++state->active_contexts;
            return workspace_result_t<void>::success();
        }
        state->condition.wait_for(lock, std::chrono::milliseconds(10));
    }
}

workspace_result_t<void> bind_workspace_context(
    const std::shared_ptr<decompiler_service_t::state_t>& state,
    const decompiler_request_context_t& context) {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (!state->accepting || state->cancellation.token().stop_requested()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "decompiler service is closing",
            "decompiler.context"));
    }
    if (state->workspace_id.empty()) {
        state->workspace_id = context.workspace_id;
        return workspace_result_t<void>::success();
    }
    if (state->workspace_id != context.workspace_id) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "decompiler request workspace does not match the service workspace binding",
            "decompiler.context"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> ensure_request_current(
    const std::shared_ptr<decompiler_service_t::state_t>& state,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const resolved_function_t& function,
    const std::optional<decompiler_request_context_t>& context,
    const cancellation_token_t& caller,
    const cancellation_token_t& workspace_cancel,
    const cancellation_token_t& deadline,
    const char* phase) {
    if (caller.stop_requested())
        return workspace_result_t<void>::failure(cancellation_error(caller, phase));
    if (deadline.stop_requested())
        return workspace_result_t<void>::failure(cancellation_error(deadline, phase));
    if (workspace_cancel.stop_requested())
        return workspace_result_t<void>::failure(cancellation_error(workspace_cancel, phase));
    if (!workspace || workspace->closing() || workspace->closed()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "workspace is closing", phase));
    }
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (!state->accepting || state->cancellation.token().stop_requested()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::workspace_closing,
                "decompiler service is closing", phase));
        }
    }
    if (workspace->generation() != function.generation ||
        workspace->analysis_revision() != function.analysis_revision ||
        workspace->overlay_revision() != function.overlay_revision) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "decompiler request became stale before result publication", phase));
    }
    if (context && (*context->generation != function.generation ||
                    *context->overlay_revision != function.overlay_revision)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "decompiler request context no longer matches the active workspace revision",
            phase));
    }
    return workspace_result_t<void>::success();
}

struct decompiler_quality_result_t {
    std::optional<semantic_fusion_result_t> semantic;
    std::optional<cfg_analysis_result_t> cfg;
    std::optional<cc_analysis_result_t> calling_convention;
    std::optional<type_recovery_result_t> types;
    std::vector<decompiler_feedback_fact_t> feedback_facts;
};

bool quality_error_requires_abort(const workspace_error_t& error) noexcept {
    if (error.cancellation || error.deadline)
        return true;
    switch (error.code) {
    case workspace_error_code_t::cancelled:
    case workspace_error_code_t::deadline_exceeded:
    case workspace_error_code_t::stale_generation:
    case workspace_error_code_t::target_stale:
    case workspace_error_code_t::revision_conflict:
    case workspace_error_code_t::workspace_closing:
        return true;
    default:
        return false;
    }
}

std::string bounded_quality_detail(std::string detail) {
    constexpr std::size_t max_detail_bytes = 512;
    if (detail.empty())
        return "quality module did not provide a diagnostic";
    if (detail.size() > max_detail_bytes)
        detail.resize(max_detail_bytes);
    return detail;
}

std::uint64_t feedback_type_revision(const decompiler_request_t& request,
                                     const resolved_function_t& function) noexcept {
    return request.context ? *request.context->type_revision : function.analysis_revision;
}

decompiler_feedback_range_t feedback_function_range(const resolved_function_t& function) {
    return {function.entry_va, function.byte_size};
}

std::string quality_fact_suffix(const resolved_function_t& function,
                                std::uint64_t type_revision) {
    return std::to_string(function.function.id) + ":" +
        std::to_string(function.entry_va) + ":" +
        std::to_string(function.generation) + ":" +
        std::to_string(function.analysis_revision) + ":" +
        std::to_string(function.overlay_revision) + ":" +
        std::to_string(type_revision);
}

void append_quality_abstention(decompiler_quality_result_t& quality,
                               const resolved_function_t& function,
                               std::uint64_t type_revision,
                               const std::string& category,
                               decompiler_feedback_abstention_reason_t reason,
                               std::string detail) {
    const std::string suffix = quality_fact_suffix(function, type_revision);
    decompiler_feedback_fact_t fact;
    fact.fact_id = "decompiler-quality-abstention:" + category + ":" + suffix;
    fact.logical_key = "decompiler-quality:" + category + ":" +
        std::to_string(function.entry_va);
    fact.publisher_id = "workspace-decompiler-quality";
    fact.kind = decompiler_feedback_fact_kind_t::abstention;
    fact.authority = decompiler_feedback_authority_t::decompiler;
    fact.validation.grade = decompiler_feedback_validation_grade_t::validated;
    fact.validation.validator_id = "workspace-quality-integration";
    fact.validation.evidence_id = function.workspace->identity().binary_id().to_hex();
    fact.validation.evidence_revision = function.analysis_revision;
    fact.source_revision = function.analysis_revision;
    fact.affected_range = feedback_function_range(function);
    fact.payload = decompiler_feedback_abstention_t{reason, bounded_quality_detail(std::move(detail))};
    quality.feedback_facts.push_back(std::move(fact));
}

void append_quality_error(decompiler_quality_result_t& quality,
                          const resolved_function_t& function,
                          std::uint64_t type_revision,
                          const std::string& category,
                          decompiler_feedback_error_class_t error_class,
                          std::string detail) {
    const std::string suffix = quality_fact_suffix(function, type_revision);
    decompiler_feedback_fact_t fact;
    fact.fact_id = "decompiler-quality-error:" + category + ":" + suffix;
    fact.logical_key = "decompiler-quality:" + category + ":" +
        std::to_string(function.entry_va);
    fact.publisher_id = "workspace-decompiler-quality";
    fact.kind = decompiler_feedback_fact_kind_t::error;
    fact.authority = decompiler_feedback_authority_t::decompiler;
    fact.validation.grade = decompiler_feedback_validation_grade_t::validated;
    fact.validation.validator_id = "workspace-quality-integration";
    fact.validation.evidence_id = function.workspace->identity().binary_id().to_hex();
    fact.validation.evidence_revision = function.analysis_revision;
    fact.source_revision = function.analysis_revision;
    fact.affected_range = feedback_function_range(function);
    fact.payload = decompiler_feedback_error_t{error_class, bounded_quality_detail(std::move(detail)), false};
    quality.feedback_facts.push_back(std::move(fact));
}

bool feedback_address_in_function(const resolved_function_t& function,
                                  const address_t& address,
                                  std::uint64_t& value) {
    auto translated = address_to_va(address, function.workspace->identity(), function.image.get());
    if (!translated)
        return false;
    if (!feedback_function_range(function).contains(translated.value()))
        return false;
    value = translated.value();
    return true;
}

bool feedback_range_end_in_function(const resolved_function_t& function,
                                    const address_t& address,
                                    std::uint64_t& value) {
    auto translated = address_to_va(address, function.workspace->identity(), function.image.get());
    if (!translated || translated.value() <= function.entry_va ||
        translated.value() > function.end_va) {
        return false;
    }
    value = translated.value();
    return true;
}

bool quality_stop_requested(const cancellation_token_t& caller,
                            const cancellation_token_t& workspace_cancel,
                            const cancellation_token_t& deadline) noexcept {
    return caller.stop_requested() || workspace_cancel.stop_requested() ||
        deadline.stop_requested();
}

std::optional<decompiler_feedback_fact_t> make_validated_cfg_fact(
    const resolved_function_t& function,
    std::uint64_t type_revision,
    const cfg_analysis_result_t& cfg,
    const cancellation_token_t& caller,
    const cancellation_token_t& workspace_cancel,
    const cancellation_token_t& deadline) {
    if (cfg.bounded || !cfg.conflicts.empty() || cfg.basic_blocks.empty())
        return std::nullopt;
    decompiler_feedback_cfg_t payload;
    payload.blocks.reserve(cfg.basic_blocks.size());
    for (std::size_t index = 0; index < cfg.basic_blocks.size(); ++index) {
        if ((index & 63U) == 0 && quality_stop_requested(caller, workspace_cancel, deadline))
            return std::nullopt;
        const auto& block = cfg.basic_blocks[index];
        if (block.function_id != function.function.id || block.quality.conflicted ||
            block.quality.confidence != 100) {
            return std::nullopt;
        }
        std::uint64_t begin = 0;
        std::uint64_t end = 0;
        if (!feedback_address_in_function(function, block.start, begin) ||
            !feedback_range_end_in_function(function, block.end, end) || end <= begin) {
            return std::nullopt;
        }
        payload.blocks.push_back({{begin, end - begin}, block.terminal});
    }
    std::sort(payload.blocks.begin(), payload.blocks.end(), [](const auto& left, const auto& right) {
        return left.range < right.range;
    });
    for (std::size_t index = 1; index < payload.blocks.size(); ++index) {
        if (payload.blocks[index - 1].range.overlaps(payload.blocks[index].range))
            return std::nullopt;
    }
    payload.edges.reserve(cfg.cfg_edges.size());
    for (std::size_t index = 0; index < cfg.cfg_edges.size(); ++index) {
        if ((index & 63U) == 0 && quality_stop_requested(caller, workspace_cancel, deadline))
            return std::nullopt;
        const auto& edge = cfg.cfg_edges[index];
        if (edge.derived || edge.external_target || edge.quality.conflicted ||
            edge.quality.confidence != 100) {
            return std::nullopt;
        }
        std::uint64_t source = 0;
        std::uint64_t target = 0;
        if (!feedback_address_in_function(function, edge.source, source) ||
            !feedback_address_in_function(function, edge.target, target)) {
            return std::nullopt;
        }
        payload.edges.push_back({source, target});
    }
    std::sort(payload.edges.begin(), payload.edges.end(), [](const auto& left, const auto& right) {
        return std::tie(left.source, left.target) < std::tie(right.source, right.target);
    });
    payload.edges.erase(std::unique(payload.edges.begin(), payload.edges.end(), [](const auto& left,
                                                                                   const auto& right) {
        return left.source == right.source && left.target == right.target;
    }), payload.edges.end());
    const std::string suffix = quality_fact_suffix(function, type_revision);
    decompiler_feedback_fact_t fact;
    fact.fact_id = "decompiler-quality-cfg:" + suffix;
    fact.logical_key = "decompiler-cfg:" + std::to_string(function.entry_va);
    fact.publisher_id = "workspace-decompiler-quality";
    fact.kind = decompiler_feedback_fact_kind_t::cfg;
    fact.authority = decompiler_feedback_authority_t::baseline_graph;
    fact.validation.grade = decompiler_feedback_validation_grade_t::proven;
    fact.validation.validator_id = "advanced-cfg-range-validator";
    fact.validation.evidence_id = function.workspace->identity().binary_id().to_hex();
    fact.validation.evidence_revision = function.analysis_revision;
    fact.source_revision = function.analysis_revision;
    fact.affected_range = feedback_function_range(function);
    fact.payload = std::move(payload);
    return fact;
}

bool has_authoritative_type_evidence(
    const recovered_type_t& type,
    const std::unordered_map<std::uint64_t, const type_recovery_evidence_t*>& evidence_by_id) {
    if (type.state != type_resolution_state_t::resolved ||
        type.confidence != 100 || type.descriptor.declared_name.empty()) {
        return false;
    }
    for (const auto evidence_id : type.supporting_evidence_ids) {
        const auto found = evidence_by_id.find(evidence_id);
        if (found == evidence_by_id.end() || found->second->propagated ||
            !found->second->hard_constraint || found->second->confidence != 100 ||
            (found->second->provenance != type_evidence_provenance_t::debug_info &&
             found->second->provenance != type_evidence_provenance_t::user_definition) ||
            found->second->candidate.declared_name != type.descriptor.declared_name) {
            continue;
        }
        return true;
    }
    return false;
}

void append_validated_type_facts(decompiler_quality_result_t& quality,
                                 const resolved_function_t& function,
                                 std::uint64_t type_revision,
                                 const type_recovery_result_t& recovery,
                                 const cancellation_token_t& caller,
                                 const cancellation_token_t& workspace_cancel,
                                 const cancellation_token_t& deadline) {
    std::unordered_map<std::uint64_t, const type_recovery_evidence_t*> evidence_by_id;
    evidence_by_id.reserve(recovery.evidence.size());
    for (std::size_t index = 0; index < recovery.evidence.size(); ++index) {
        if ((index & 63U) == 0 && quality_stop_requested(caller, workspace_cancel, deadline))
            return;
        const auto& evidence = recovery.evidence[index];
        if (evidence.evidence_id != 0)
            evidence_by_id.emplace(evidence.evidence_id, &evidence);
    }
    std::size_t appended = 0;
    constexpr std::size_t max_type_facts = 16;
    for (std::size_t index = 0; index < recovery.types.size(); ++index) {
        if ((index & 63U) == 0 && quality_stop_requested(caller, workspace_cancel, deadline))
            return;
        if (appended == max_type_facts)
            break;
        const auto& type = recovery.types[index];
        if (!has_authoritative_type_evidence(type, evidence_by_id))
            continue;
        std::uint64_t address = 0;
        if (!feedback_address_in_function(function, type.subject.address, address))
            continue;
        const std::string suffix = quality_fact_suffix(function, type_revision);
        decompiler_feedback_fact_t fact;
        fact.fact_id = "decompiler-quality-type:" + suffix + ":" +
            std::to_string(type.subject.entity_id) + ":" + std::to_string(address);
        fact.logical_key = "decompiler-type:" + std::to_string(address) + ":" +
            type.descriptor.declared_name;
        fact.publisher_id = "workspace-decompiler-quality";
        fact.kind = decompiler_feedback_fact_kind_t::type_assignment;
        fact.authority = decompiler_feedback_authority_t::trusted_recovery;
        fact.validation.grade = decompiler_feedback_validation_grade_t::proven;
        fact.validation.validator_id = "type-recovery-authoritative-evidence";
        fact.validation.evidence_id = function.workspace->identity().binary_id().to_hex();
        fact.validation.evidence_revision = function.analysis_revision;
        fact.source_revision = function.analysis_revision;
        fact.affected_range = feedback_function_range(function);
        fact.payload = decompiler_feedback_type_assignment_t{address, type.descriptor.declared_name};
        quality.feedback_facts.push_back(std::move(fact));
        ++appended;
    }
}

workspace_result_t<decompiler_quality_result_t> run_decompiler_quality(
    const std::shared_ptr<decompiler_service_t::state_t>& state,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const resolved_function_t& function,
    const decompiler_request_t& request,
    const cancellation_token_t& caller,
    const cancellation_token_t& workspace_cancel,
    const cancellation_token_t& deadline) {
    decompiler_quality_result_t quality;
    const std::uint64_t type_revision = feedback_type_revision(request, function);
    const cancellation_token_t& quality_cancel = request.deadline ? deadline : caller;
    const auto current = [&](const char* phase) {
        return ensure_request_current(state, workspace, function, request.context,
            caller, workspace_cancel, deadline, phase);
    };
    auto gate = current("decompiler.quality.semantic.preflight");
    if (!gate)
        return workspace_result_t<decompiler_quality_result_t>::failure(gate.error());

    semantic_fusion_request_t semantic_request;
    semantic_request.function_rva = function.function_rva;
    semantic_request.function_address = function.function.start;
    auto semantic = fuse_semantic_evidence(*workspace, semantic_request, quality_cancel);
    if (!semantic) {
        if (quality_error_requires_abort(semantic.error()))
            return workspace_result_t<decompiler_quality_result_t>::failure(semantic.error());
        append_quality_error(quality, function, type_revision, "semantic",
            decompiler_feedback_error_class_t::ir_lift, semantic.error().message);
    } else {
        quality.semantic = semantic.take_value();
        append_quality_abstention(quality, function, type_revision, "semantic",
            decompiler_feedback_abstention_reason_t::unsupported_encoding,
            "semantic fusion facts were consumed by type recovery; the feedback model has no value, alias, or use-def payload");
    }
    gate = current("decompiler.quality.semantic.complete");
    if (!gate)
        return workspace_result_t<decompiler_quality_result_t>::failure(gate.error());

    auto cfg = analyze_advanced_cfg(*workspace, function.function.start.value, quality_cancel);
    if (!cfg) {
        if (quality_error_requires_abort(cfg.error()))
            return workspace_result_t<decompiler_quality_result_t>::failure(cfg.error());
        append_quality_error(quality, function, type_revision, "cfg",
            decompiler_feedback_error_class_t::cfg_reconstruction, cfg.error().message);
    } else {
        quality.cfg = cfg.take_value();
        auto fact = make_validated_cfg_fact(function, type_revision, *quality.cfg,
            caller, workspace_cancel, deadline);
        if (fact) {
            quality.feedback_facts.push_back(std::move(*fact));
        } else {
            append_quality_abstention(quality, function, type_revision, "cfg",
                decompiler_feedback_abstention_reason_t::contradictory_evidence,
                "advanced CFG did not produce a complete conflict-free range-proven graph for feedback publication");
        }
    }
    gate = current("decompiler.quality.cfg.complete");
    if (!gate)
        return workspace_result_t<decompiler_quality_result_t>::failure(gate.error());

    calling_convention_request_t calling_convention_request;
    calling_convention_request.function = function.function.start;
    calling_convention_request.expected_generation = function.generation;
    calling_convention_request.expected_analysis_revision = function.analysis_revision;
    calling_convention_request.expected_overlay_revision = function.overlay_revision;
    auto calling_convention = infer_calling_convention(*workspace, calling_convention_request,
                                                       quality_cancel);
    if (!calling_convention) {
        if (quality_error_requires_abort(calling_convention.error())) {
            return workspace_result_t<decompiler_quality_result_t>::failure(
                calling_convention.error());
        }
        append_quality_error(quality, function, type_revision, "calling-convention",
            decompiler_feedback_error_class_t::integration, calling_convention.error().message);
    } else {
        quality.calling_convention = calling_convention.take_value();
        append_quality_abstention(quality, function, type_revision, "calling-convention",
            decompiler_feedback_abstention_reason_t::unsupported_encoding,
            "calling-convention inference was consumed by type recovery; no source-proven C declaration is available for prototype publication");
    }
    gate = current("decompiler.quality.calling_convention.complete");
    if (!gate)
        return workspace_result_t<decompiler_quality_result_t>::failure(gate.error());

    type_recovery_request_t type_request;
    type_request.function_rva = function.function.start.value;
    type_request.address_space = function.function.start.space;
    type_request.semantic_result = quality.semantic ? &*quality.semantic : nullptr;
    type_request.cfg_result = quality.cfg ? &*quality.cfg : nullptr;
    type_request.calling_convention_result = quality.calling_convention
        ? &*quality.calling_convention : nullptr;
    auto types = recover_types(*workspace, type_request, quality_cancel);
    if (!types) {
        if (quality_error_requires_abort(types.error()))
            return workspace_result_t<decompiler_quality_result_t>::failure(types.error());
        append_quality_error(quality, function, type_revision, "type-recovery",
            decompiler_feedback_error_class_t::type_recovery, types.error().message);
    } else {
        quality.types = types.take_value();
        const std::size_t facts_before = quality.feedback_facts.size();
        append_validated_type_facts(quality, function, type_revision, *quality.types,
            caller, workspace_cancel, deadline);
        if (quality.feedback_facts.size() == facts_before) {
            append_quality_abstention(quality, function, type_revision, "type-recovery",
                decompiler_feedback_abstention_reason_t::unsupported_encoding,
                "type recovery produced no direct non-propagated confidence-100 debug or user declaration for feedback publication");
        }
    }
    gate = current("decompiler.quality.type_recovery.complete");
    if (!gate)
        return workspace_result_t<decompiler_quality_result_t>::failure(gate.error());

    const typed_pseudocode_ast_t* typed_ast = nullptr;
    const auto readability = render_typed_pseudocode(typed_ast, {});
    if (readability.succeeded() || readability.errors.size() != 1 ||
        readability.errors.front().code != pseudocode_render_error_code_t::invalid_ast) {
        return workspace_result_t<decompiler_quality_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "typed pseudocode renderer did not report the expected missing-AST state",
            "decompiler.quality.readability"));
    }
    append_quality_error(quality, function, type_revision, "readability",
        decompiler_feedback_error_class_t::integration,
        "ghidra_adapter_decompile_result_t supplies text, annotations, mappings, and callees but no typed_pseudocode_ast_t; " +
            readability.errors.front().detail);
    gate = current("decompiler.quality.readability.complete");
    if (!gate)
        return workspace_result_t<decompiler_quality_result_t>::failure(gate.error());
    return workspace_result_t<decompiler_quality_result_t>::success(std::move(quality));
}

workspace_error_t feedback_error(
    workspace_error_code_t code,
    const decompiler_feedback_publication_result_t& result) {
    auto error = make_workspace_error(code,
        result.message.empty() ? "decompiler feedback publication failed" : result.message,
        "decompiler.feedback.publish");
    if (!result.code.empty())
        error.details.emplace_back("feedback_code", result.code);
    return error;
}

workspace_result_t<void> publish_feedback(
    const std::shared_ptr<decompiler_service_t::state_t>& state,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const resolved_function_t& function,
    const decompiler_request_t& request,
    const cancellation_token_t& caller,
    const cancellation_token_t& workspace_cancel,
    const cancellation_token_t& deadline,
    const decompiler_quality_result_t* quality,
    decompiler_result_t& result) {
    if (!request.publish_feedback)
        return workspace_result_t<void>::success();
    auto current = ensure_request_current(state, workspace, function, request.context,
        caller, workspace_cancel, deadline, "decompiler.feedback.preflight");
    if (!current)
        return current;
    std::shared_ptr<decompiler_feedback_model_t> feedback;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        feedback = state->feedback;
    }
    if (!feedback) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "decompiler feedback hook is not installed",
            "decompiler.feedback.publish"));
    }

    decompiler_feedback_scope_key_t scope;
    scope.workspace_id = request.context ? request.context->workspace_id
                                         : workspace->identity().binary_id().to_hex();
    scope.binary_id = workspace->identity().binary_id().to_hex();
    scope.address_space_id = request.context
        ? address_space_text(*request.context->address_space)
        : address_space_text(function.function.start.space);
    scope.architecture_id = "architecture-" + std::to_string(
        static_cast<unsigned int>(workspace->identity().architecture()));
    scope.generation = function.generation;
    scope.overlay_revision = function.overlay_revision;
    scope.type_revision = feedback_type_revision(request, function);

    auto scope_validation = decompiler_feedback_model_t::validate_scope(
        scope, feedback->limits());
    if (!scope_validation.valid) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
            scope_validation.message.empty() ? "decompiler feedback scope is invalid"
                                             : scope_validation.message,
            "decompiler.feedback.scope");
        error.details.emplace_back("feedback_code", scope_validation.code);
        return workspace_result_t<void>::failure(std::move(error));
    }

    decompiler_feedback_range_t function_range;
    function_range.begin = function.entry_va;
    function_range.size = function.byte_size;
    if (!function_range.valid() || !function_range.contains(function.entry_va) ||
        !function_range.contains(function.end_va - 1)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "validated function range cannot be represented for decompiler feedback",
            "decompiler.feedback.scope"));
    }

    const std::string fact_suffix = std::to_string(function.function.id) + ":" +
        std::to_string(function.entry_va) + ":" + std::to_string(function.generation) +
        ":" + std::to_string(function.overlay_revision) + ":" +
        std::to_string(feedback_type_revision(request, function));
    decompiler_feedback_fact_t boundary;
    boundary.fact_id = "decompiler-boundary:" + fact_suffix;
    boundary.logical_key = "function-boundary:" + std::to_string(function.entry_va);
    boundary.publisher_id = "workspace-decompiler-service";
    boundary.kind = decompiler_feedback_fact_kind_t::function_boundary;
    boundary.authority = decompiler_feedback_authority_t::decompiler;
    boundary.validation.grade = decompiler_feedback_validation_grade_t::proven;
    boundary.validation.validator_id = "workspace-function-range";
    boundary.validation.evidence_id = workspace->identity().binary_id().to_hex();
    boundary.validation.evidence_revision = function.analysis_revision;
    boundary.source_revision = function.analysis_revision;
    boundary.affected_range = function_range;
    boundary.payload = decompiler_feedback_function_boundary_t{
        function.entry_va, function.end_va};

    std::vector<decompiler_feedback_fact_t> facts;
    facts.reserve(1U + (quality ? quality->feedback_facts.size() : 0U));
    auto boundary_validation = decompiler_feedback_model_t::validate_fact(
        boundary, feedback->limits());
    if (!boundary_validation.valid) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
            boundary_validation.message.empty() ? "validated decompiler boundary fact is invalid"
                                                : boundary_validation.message,
            "decompiler.feedback.fact");
        error.details.emplace_back("feedback_code", boundary_validation.code);
        return workspace_result_t<void>::failure(std::move(error));
    }
    facts.push_back(std::move(boundary));

    if (quality) {
        for (const auto& candidate : quality->feedback_facts) {
            if (facts.size() >= feedback->limits().max_facts_per_publication)
                break;
            if (!function_range.contains(candidate.affected_range))
                continue;
            auto validation = decompiler_feedback_model_t::validate_fact(
                candidate, feedback->limits());
            if (validation.valid)
                facts.push_back(candidate);
        }
    }

    decompiler_feedback_publication_request_t publication;
    publication.scope = std::move(scope);
    publication.facts = std::move(facts);
    publication.deadline = request.deadline;
    publication.is_cancelled = [state, workspace, function, context = request.context,
                                caller, workspace_cancel, deadline]() {
        return !ensure_request_current(state, workspace, function, context, caller,
            workspace_cancel, deadline, "decompiler.feedback.cancel_check");
    };
    auto publication_result = feedback->publish(publication);
    current = ensure_request_current(state, workspace, function, request.context,
        caller, workspace_cancel, deadline, "decompiler.feedback.complete");
    if (!current)
        return current;
    result.feedback = publication_result;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->feedback_rejections += publication_result.rejections.size();
        if (publication_result.status == decompiler_feedback_publication_status_t::published)
            ++state->feedback_publications;
        else if (publication_result.status == decompiler_feedback_publication_status_t::no_change ||
                 publication_result.status == decompiler_feedback_publication_status_t::fixed_point_closed)
            ++state->feedback_no_change;
    }
    switch (publication_result.status) {
    case decompiler_feedback_publication_status_t::published:
    case decompiler_feedback_publication_status_t::no_change:
    case decompiler_feedback_publication_status_t::fixed_point_closed:
        return workspace_result_t<void>::success();
    case decompiler_feedback_publication_status_t::cancelled:
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::cancelled,
            "decompiler feedback publication was cancelled",
            "decompiler.feedback.publish"));
    case decompiler_feedback_publication_status_t::deadline_exceeded:
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::deadline_exceeded,
            "decompiler feedback publication exceeded its deadline",
            "decompiler.feedback.publish"));
    case decompiler_feedback_publication_status_t::invalid_scope:
        return workspace_result_t<void>::failure(feedback_error(
            workspace_error_code_t::invalid_argument, publication_result));
    case decompiler_feedback_publication_status_t::internal_failure:
        return workspace_result_t<void>::failure(feedback_error(
            workspace_error_code_t::integrity_failure, publication_result));
    }
    return workspace_result_t<void>::failure(feedback_error(
        workspace_error_code_t::integrity_failure, publication_result));
}

}

decompiler_service_t::decompiler_service_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

decompiler_service_t::~decompiler_service_t() {
    request_cancel();
    drain(std::chrono::steady_clock::now() + std::chrono::seconds(2));
}

workspace_result_t<std::shared_ptr<decompiler_service_t>>
decompiler_service_t::create(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<workspace_database_t> database,
    workspace_database_versions_t versions,
    decompiler_service_limits_t limits) {
    try {
        return create(std::move(workspace), std::move(database), std::move(versions),
            std::make_shared<decompiler_feedback_model_t>(), limits);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<decompiler_service_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "decompiler feedback model allocation failed", "decompiler.create"));
    }
}

workspace_result_t<std::shared_ptr<decompiler_service_t>>
decompiler_service_t::create(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<workspace_database_t> database,
    workspace_database_versions_t versions,
    std::shared_ptr<decompiler_feedback_model_t> feedback,
    decompiler_service_limits_t limits) {
    if (!workspace || !database || versions.engine_version.empty() ||
        versions.specification_version.empty() ||
        versions.analysis_settings_hash.empty() ||
        !feedback ||
        limits.max_parallel_contexts == 0 ||
        limits.max_memory_cache_entries == 0 ||
        limits.max_memory_cache_bytes == 0 ||
        limits.max_function_bytes == 0 ||
        limits.max_pseudocode_bytes == 0 ||
        limits.max_result_bytes < limits.max_pseudocode_bytes ||
        limits.max_cache_key_bytes == 0 ||
        limits.max_workspace_id_bytes == 0 ||
        limits.max_annotations == 0 || limits.max_history_entries == 0 ||
        versions.engine_version.size() > limits.max_cache_key_bytes ||
        versions.specification_version.size() > limits.max_cache_key_bytes ||
        versions.analysis_settings_hash.size() > limits.max_cache_key_bytes) {
        return workspace_result_t<std::shared_ptr<decompiler_service_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompiler service requires a workspace, database, versions, and nonzero limits",
                "decompiler.create"));
    }
    const auto& database_options = database->options();
    if (!database_options.identity ||
        database_options.identity->binary_id() != workspace->identity().binary_id() ||
        database_options.versions.engine_version != versions.engine_version ||
        database_options.versions.specification_version != versions.specification_version ||
        database_options.versions.analysis_settings_hash != versions.analysis_settings_hash) {
        return workspace_result_t<std::shared_ptr<decompiler_service_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                "decompiler database identity or versions do not match the workspace",
                "decompiler.create"));
    }
    auto state = std::make_shared<state_t>();
    state->workspace = workspace;
    state->database = std::move(database);
    state->feedback = std::move(feedback);
    state->versions = std::move(versions);
    state->limits = limits;
    auto service = std::shared_ptr<decompiler_service_t>(
        new decompiler_service_t(std::move(state)));
    auto attach_failure = [&service](workspace_error_t error) {
        service->request_cancel();
        auto drained = service->drain(
            std::chrono::steady_clock::now() + std::chrono::seconds(2));
        if (!drained) {
            error.details.emplace_back("attach_cleanup_code",
                                       drained.error().stable_code());
            error.details.emplace_back("attach_cleanup_message",
                                       drained.error().message);
        }
        return workspace_result_t<std::shared_ptr<decompiler_service_t>>::failure(
            std::move(error));
    };
    auto registered = workspace->register_lifecycle_participant(service);
    if (!registered)
        return attach_failure(registered.error());
    auto installed = workspace->install_decompiler(service);
    if (!installed)
        return attach_failure(installed.error());
    return workspace_result_t<std::shared_ptr<decompiler_service_t>>::success(
        std::move(service));
}

workspace_result_t<decompiler_result_t> decompiler_service_t::decompile(
    const address_t& address,
    decompiler_request_t request,
    const cancellation_token_t& cancel) {
    std::shared_ptr<analysis_workspace_t> workspace = state_->workspace.lock();
    if (!workspace) {
        return workspace_result_t<decompiler_result_t>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "workspace no longer exists",
            "decompiler.decompile"));
    }
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        ++state_->requests;
    }
    cancellation_source_t deadline_cancel(request.deadline);
    const auto deadline_token = deadline_cancel.token();
    auto workspace_cancel = workspace->cancellation_token();
    auto fail = [this](workspace_error_t error) {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (error.cancellation || error.deadline ||
            error.code == workspace_error_code_t::cancelled ||
            error.code == workspace_error_code_t::deadline_exceeded)
            ++state_->cancelled;
        else
            ++state_->failed;
        return workspace_result_t<decompiler_result_t>::failure(std::move(error));
    };
    if (cancel.stop_requested())
        return fail(cancellation_error(cancel, "decompiler.decompile"));
    if (deadline_token.stop_requested())
        return fail(cancellation_error(deadline_token, "decompiler.decompile"));
    if (request.context) {
        auto context = validate_request_context(*request.context, workspace,
            state_->limits, "decompiler.context");
        if (!context)
            return fail(context.error());
        if (!same_address(address, request.context->function_address)) {
            return fail(make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompiler address and explicit request function address differ",
                "decompiler.context"));
        }
    }

    std::shared_lock<std::shared_mutex> revision_lock(workspace->mutation_mutex());
    auto function = resolve_function(workspace, address, state_->limits);
    if (!function)
        return fail(function.error());
    function.value().overlay_revision = workspace->overlay_revision();
    if (request.context) {
        auto context = validate_resolved_context(*request.context, function.value(),
            "decompiler.context");
        if (!context)
            return fail(context.error());
        auto bound = bind_workspace_context(state_, *request.context);
        if (!bound)
            return fail(bound.error());
    }
    revision_lock.unlock();
    auto current = ensure_request_current(state_, workspace, function.value(), request.context,
        cancel, workspace_cancel, deadline_token, "decompiler.preflight");
    if (!current)
        return fail(current.error());
    auto adapter = prepare_adapter_inputs(function.value(), cancel);
    if (!adapter)
        return fail(adapter.error());
    current = ensure_request_current(state_, workspace, function.value(), request.context,
        cancel, workspace_cancel, deadline_token, "decompiler.adapter");
    if (!current)
        return fail(current.error());
    std::atomic<bool> engine_cancel{false};
    auto service_cancel = state_->cancellation.token();
    const auto function_value = function.value();
    const auto context_value = request.context;
    auto cancel_check = [state = state_, workspace, function_value, context_value,
                         cancel, workspace_cancel, deadline_token, service_cancel,
                         &engine_cancel]() {
        return engine_cancel.load(std::memory_order_acquire) ||
            cancel.stop_requested() || workspace_cancel.stop_requested() ||
            service_cancel.stop_requested() || deadline_token.stop_requested() ||
            !ensure_request_current(state, workspace, function_value, context_value,
                cancel, workspace_cancel, deadline_token, "decompiler.ghidra.cancel_check");
    };
    auto adapter_request = make_adapter_decompile_request(function.value(), request.context,
        adapter.value(), state_->limits, cancel, &engine_cancel, cancel_check, request.deadline);
    if (!adapter_request)
        return fail(adapter_request.error());
    auto adapter_decompile_cache_key =
        ghidra_decompiler::make_ghidra_adapter_decompile_cache_key(
            adapter_request.value(), cancel);
    if (!adapter_decompile_cache_key) {
        current = ensure_request_current(state_, workspace, function.value(), request.context,
            cancel, workspace_cancel, deadline_token, "decompiler.adapter.cache_key");
        if (!current)
            return fail(current.error());
        return fail(adapter_decompile_cache_key.error());
    }
    auto content_hash = hash_function(function.value(), cancel);
    if (!content_hash)
        return fail(content_hash.error());
    current = ensure_request_current(state_, workspace, function.value(), request.context,
        cancel, workspace_cancel, deadline_token, "decompiler.cache.key");
    if (!current)
        return fail(current.error());
    auto cache_key = make_cache_key(function.value(), state_->versions,
        content_hash.value(), request.context, adapter_decompile_cache_key.value(), state_->limits);
    if (!cache_key)
        return fail(cache_key.error());
    const std::string canonical_key = cache_key.value().canonical();

    if (request.use_memory_cache) {
        std::optional<decompiler_result_t> cached;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            auto found = state_->cache.find(canonical_key);
            if (found != state_->cache.end()) {
                touch_cache_locked(*state_, found->second, canonical_key);
                cached = found->second.result;
            }
        }
        if (cached) {
            current = ensure_request_current(state_, workspace, function.value(), request.context,
                cancel, workspace_cancel, deadline_token, "decompiler.cache.memory");
            if (!current)
                return fail(current.error());
            cached->context = request.context;
            cached->cache_hit = true;
            cached->persistent_cache_hit = false;
            cached->feedback.reset();
            std::optional<decompiler_quality_result_t> quality;
            if (request.publish_feedback) {
                auto generated = run_decompiler_quality(state_, workspace, function.value(), request,
                    cancel, workspace_cancel, deadline_token);
                if (!generated)
                    return fail(generated.error());
                quality = generated.take_value();
            }
            auto published = publish_feedback(state_, workspace, function.value(), request,
                cancel, workspace_cancel, deadline_token,
                quality ? &*quality : nullptr, *cached);
            if (!published)
                return fail(published.error());
            current = ensure_request_current(state_, workspace, function.value(), request.context,
                cancel, workspace_cancel, deadline_token, "decompiler.cache.memory.complete");
            if (!current)
                return fail(current.error());
            std::lock_guard<std::mutex> lock(state_->mutex);
            ++state_->memory_cache_hits;
            ++state_->completed;
            append_history_locked(*state_, *cached);
            return workspace_result_t<decompiler_result_t>::success(std::move(*cached));
        }
    }

    if (request.use_persistent_cache) {
        auto record = state_->database->load_decompiler_cache(cache_key.value(), cancel);
        if (!record) {
            return fail(record.error());
        } else if (record.value()) {
            auto decoded = deserialize_result(record.value()->result_json,
                function.value(), request.context, state_->limits);
            if (decoded) {
                current = ensure_request_current(state_, workspace, function.value(), request.context,
                    cancel, workspace_cancel, deadline_token, "decompiler.cache.persistent");
                if (!current)
                    return fail(current.error());
                auto cached = decoded.take_value();
                cached.cache_hit = true;
                cached.persistent_cache_hit = true;
                cached.feedback.reset();
                std::optional<decompiler_quality_result_t> quality;
                if (request.publish_feedback) {
                    auto generated = run_decompiler_quality(state_, workspace, function.value(), request,
                        cancel, workspace_cancel, deadline_token);
                    if (!generated)
                        return fail(generated.error());
                    quality = generated.take_value();
                }
                auto published = publish_feedback(state_, workspace, function.value(), request,
                    cancel, workspace_cancel, deadline_token,
                    quality ? &*quality : nullptr, cached);
                if (!published)
                    return fail(published.error());
                current = ensure_request_current(state_, workspace, function.value(), request.context,
                    cancel, workspace_cancel, deadline_token, "decompiler.cache.persistent.complete");
                if (!current)
                    return fail(current.error());
                std::lock_guard<std::mutex> lock(state_->mutex);
                ++state_->persistent_cache_hits;
                ++state_->completed;
                if (request.use_memory_cache) {
                    auto cache_result = cached;
                    cache_result.feedback.reset();
                    insert_cache_locked(*state_, cache_key.value(), std::move(cache_result));
                }
                append_history_locked(*state_, cached);
                return workspace_result_t<decompiler_result_t>::success(std::move(cached));
            }
            auto invalidation = state_->database->invalidate_decompiler_cache(
                cache_key.value().function_rva, cache_key.value().overlay_revision, cancel);
            auto invalidated = wait_ticket(
                invalidation, cancel, &deadline_token, "decompiler.cache.invalidate_corrupt");
            if (!invalidated)
                return fail(invalidated.error());
            current = ensure_request_current(state_, workspace, function.value(), request.context,
                cancel, workspace_cancel, deadline_token, "decompiler.cache.invalidate_corrupt");
            if (!current)
                return fail(current.error());
        }
    }
    current = ensure_request_current(state_, workspace, function.value(), request.context,
        cancel, workspace_cancel, deadline_token, "decompiler.acquire_context");
    if (!current)
        return fail(current.error());
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        ++state_->cache_misses;
    }

    auto acquired = acquire_context(state_, cancel, workspace_cancel, deadline_token);
    if (!acquired) {
        return fail(acquired.error());
    }
    context_guard_t context_guard(state_);

    auto adapter_result = ghidra_decompiler::decompile_adapter(adapter_request.value());
    if (!adapter_result) {
        current = ensure_request_current(state_, workspace, function.value(), request.context,
            cancel, workspace_cancel, deadline_token, "decompiler.ghidra.complete");
        if (!current)
            return fail(current.error());
        return fail(adapter_result.error());
    }
    auto adapter_output = adapter_result.take_value();
    current = ensure_request_current(state_, workspace, function.value(), request.context,
        cancel, workspace_cancel, deadline_token, "decompiler.ghidra.complete");
    if (!current)
        return fail(current.error());
    if (adapter_output.cache_key.digest.to_hex() !=
        adapter_decompile_cache_key.value().digest.to_hex()) {
        return fail(make_workspace_error(workspace_error_code_t::integrity_failure,
            "Ghidra adapter returned a decompile cache key that does not match the validated request",
            "decompiler.ghidra.adapter"));
    }
    auto native = std::move(adapter_output.result);

    if (native.is_error || !native.complete || native.pseudocode.empty()) {
        auto adapter_error = native.adapter_error;
        if (adapter_error.message.empty()) {
            adapter_error.message = native.error_text.empty()
                ? "native decompiler returned no structured result" : native.error_text;
        }
        return fail(map_adapter_error(adapter_error, function.value().function.start));
    }
    if (native.pseudocode.size() > state_->limits.max_pseudocode_bytes ||
        native.annotations.size() > state_->limits.max_annotations ||
        native.line_to_address.size() > state_->limits.max_annotations ||
        native.callees.size() > state_->limits.max_annotations) {
        return fail(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "native decompiler output exceeds the workspace result budget",
            "decompiler.ghidra"));
    }

    const std::size_t mapping_budget = state_->limits.max_annotations;

    decompiler_result_t result;
    result.binary_id = workspace->identity().binary_id();
    result.context = request.context;
    result.function_id = function.value().function.id;
    result.function_address = function.value().function.start;
    result.function_name = std::move(native.function_name);
    result.pseudocode = std::move(native.pseudocode);
    result.sleigh_id = std::move(native.sleigh_id);
    result.generation = function.value().generation;
    result.analysis_revision = function.value().analysis_revision;
    result.overlay_revision = function.value().overlay_revision;
    result.elapsed_ms = native.elapsed_ms;

    result.line_to_address.reserve(
        std::min(native.line_to_address.size(), mapping_budget));
    for (const auto& entry : native.line_to_address) {
        if (result.line_to_address.size() >= mapping_budget)
            break;
        if (result_address_in_range(function.value(), entry.second))
            result.line_to_address.push_back(entry);
    }

    result.callees.reserve(
        std::min(native.callees.size(), mapping_budget));
    for (const auto& entry : native.callees) {
        if (result.callees.size() >= mapping_budget)
            break;
        if (result_address_in_range(function.value(), entry.second))
            result.callees.push_back(entry);
    }

    result.annotations.reserve(
        std::min(native.annotations.size(), mapping_budget));
    for (auto& item : native.annotations) {
        if (result.annotations.size() >= mapping_budget)
            break;
        if (item.start > item.end || item.end > result.pseudocode.size()) {
            return fail(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "native decompiler produced an invalid annotation range",
                "decompiler.ghidra"));
        }
        decompiler_annotation_t annotation;
        annotation.kind = static_cast<std::uint8_t>(item.kind);
        annotation.start = item.start;
        annotation.end = item.end;
        annotation.address = item.offset;
        annotation.name = std::move(item.name);
        if (!result_address_in_range(function.value(), annotation.address))
            continue;
        result.annotations.push_back(std::move(annotation));
    }

    auto size = validate_result_size(result, state_->limits, "decompiler.output");
    if (!size)
        return fail(size.error());

    std::optional<decompiler_quality_result_t> quality;
    if (request.publish_feedback) {
        auto generated = run_decompiler_quality(state_, workspace, function.value(), request,
            cancel, workspace_cancel, deadline_token);
        if (!generated)
            return fail(generated.error());
        quality = generated.take_value();
    }

    std::string result_json;
    try {
        result_json = serialize_result(result).dump();
    } catch (const std::exception& error) {
        auto failure = make_workspace_error(workspace_error_code_t::integrity_failure,
            "native decompiler result is not valid bounded UTF-8 JSON",
            "decompiler.serialize");
        failure.details.emplace_back("reason", error.what());
        return fail(std::move(failure));
    }
    if (result_json.size() > workspace_decompiler_cache_record_limit ||
        result_json.size() > state_->limits.max_result_bytes) {
        return fail(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "serialized decompiler result exceeds the output budget",
            "decompiler.serialize"));
    }
    if (request.use_persistent_cache) {
        current = ensure_request_current(state_, workspace, function.value(), request.context,
            cancel, workspace_cancel, deadline_token, "decompiler.cache.store");
        if (!current)
            return fail(current.error());
        decompiler_cache_record_t record;
        record.key = cache_key.value();
        record.function_name = result.function_name;
        record.result_json = result_json;
        record.created_utc_ms = utc_milliseconds();
        record.last_access_utc_ms = record.created_utc_ms;
        record.result_bytes = result_json.size();
        auto ticket = state_->database->store_decompiler_cache(std::move(record), cancel);
        auto persisted = wait_ticket(ticket, cancel, &deadline_token,
            "decompiler.cache.store");
        if (!persisted)
            return fail(persisted.error());
        current = ensure_request_current(state_, workspace, function.value(), request.context,
            cancel, workspace_cancel, deadline_token, "decompiler.cache.store.complete");
        if (!current)
            return fail(current.error());
    }
    auto published = publish_feedback(state_, workspace, function.value(), request,
        cancel, workspace_cancel, deadline_token,
        quality ? &*quality : nullptr, result);
    if (!published)
        return fail(published.error());
    current = ensure_request_current(state_, workspace, function.value(), request.context,
        cancel, workspace_cancel, deadline_token, "decompiler.publish");
    if (!current)
        return fail(current.error());
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (request.use_memory_cache) {
            auto cache_result = result;
            cache_result.feedback.reset();
            insert_cache_locked(*state_, cache_key.value(), std::move(cache_result));
        }
        append_history_locked(*state_, result);
        ++state_->completed;
    }
    return workspace_result_t<decompiler_result_t>::success(std::move(result));
}

workspace_result_t<decompiler_result_t> decompiler_service_t::decompile(
    const decompiler_request_t& request,
    const cancellation_token_t& cancel) {
    if (!request.context) {
        return workspace_result_t<decompiler_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "explicit decompiler request context is required by this overload",
            "decompiler.decompile"));
    }
    return decompile(request.context->function_address, request, cancel);
}

workspace_result_t<void> decompiler_service_t::invalidate(
    std::optional<address_t> function,
    const cancellation_token_t& cancel) {
    auto workspace = state_->workspace.lock();
    if (!workspace) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "workspace no longer exists",
            "decompiler.invalidate"));
    }
    std::optional<std::uint64_t> function_rva;
    std::optional<entity_id_t> function_id;
    if (function) {
        auto resolved = resolve_function(workspace, *function, state_->limits);
        if (!resolved)
            return workspace_result_t<void>::failure(resolved.error());
        function_rva = resolved.value().function_rva;
        function_id = resolved.value().function.id;
    }
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        for (auto it = state_->cache.begin(); it != state_->cache.end();) {
            if (!function_id || it->second.key.function_id == *function_id) {
                state_->cache_bytes -= it->second.bytes;
                state_->lru.erase(it->second.lru);
                it = state_->cache.erase(it);
            } else {
                ++it;
            }
        }
    }
    auto ticket = state_->database->invalidate_decompiler_cache(
        function_rva, std::nullopt, cancel);
    return wait_ticket(ticket, cancel, "decompiler.invalidate");
}

decompiler_service_snapshot_t decompiler_service_t::snapshot() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    decompiler_service_snapshot_t result;
    result.requests = state_->requests;
    result.completed = state_->completed;
    result.failed = state_->failed;
    result.cancelled = state_->cancelled;
    result.memory_cache_hits = state_->memory_cache_hits;
    result.persistent_cache_hits = state_->persistent_cache_hits;
    result.cache_misses = state_->cache_misses;
    result.evictions = state_->evictions;
    result.feedback_publications = state_->feedback_publications;
    result.feedback_rejections = state_->feedback_rejections;
    result.feedback_no_change = state_->feedback_no_change;
    result.memory_cache_bytes = state_->cache_bytes;
    result.memory_cache_entries = state_->cache.size();
    result.active_contexts = state_->active_contexts;
    result.accepting = state_->accepting;
    return result;
}

std::vector<decompiler_history_entry_t> decompiler_service_t::history() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->history;
}

std::shared_ptr<decompiler_feedback_model_t> decompiler_service_t::feedback_model() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->feedback;
}

void decompiler_service_t::request_cancel() noexcept {
    state_->cancellation.request_cancel();
    std::lock_guard<std::mutex> lock(state_->mutex);
    state_->accepting = false;
    state_->condition.notify_all();
}

workspace_result_t<void> decompiler_service_t::drain(
    std::chrono::steady_clock::time_point deadline) {
    std::unique_lock<std::mutex> lock(state_->mutex);
    state_->accepting = false;
    state_->cancellation.request_cancel();
    while (state_->active_contexts != 0) {
        if (state_->condition.wait_until(lock, deadline) == std::cv_status::timeout &&
            state_->active_contexts != 0) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::deadline_exceeded,
                "decompiler contexts did not drain before the deadline",
                "decompiler.drain"));
        }
    }
    return workspace_result_t<void>::success();
}

}
