#include "pseudocode_document.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <limits>
#include <utility>

namespace aida {
namespace workbench {
namespace pseudocode_document {
namespace {

std::uint64_t now_ms() noexcept
{
    const auto time = std::chrono::steady_clock::now();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            time.time_since_epoch()).count());
}

bool token_range_valid(std::uint32_t begin,
                       std::uint32_t end,
                       std::size_t text_size) noexcept
{
    return begin < end && end <= text_size;
}

bool address_extent_valid(std::uint64_t address, std::uint64_t extent) noexcept
{
    return extent != 0 &&
           extent - 1 <= (std::numeric_limits<std::uint64_t>::max)() - address;
}

bool source_origin_valid(
    const aida::analysis::decompiler_source_origin_t& origin) noexcept
{
    return !origin.source_artifact_hash.empty() && !origin.source_path.empty() &&
           origin.first_line != 0 &&
           origin.last_line >= origin.first_line &&
           (origin.last_line != origin.first_line ||
            origin.last_column >= origin.first_column);
}

bool diagnostic_valid(
    const aida::analysis::decompiler_diagnostic_t& diagnostic) noexcept
{
    return diagnostic.severity >= aida::analysis::decompiler_diagnostic_severity_t::note &&
           diagnostic.severity <= aida::analysis::decompiler_diagnostic_severity_t::error &&
           diagnostic.code >= aida::analysis::decompiler_diagnostic_code_t::invalid_contract &&
           diagnostic.code <= aida::analysis::decompiler_diagnostic_code_t::source_map_rejected &&
           !diagnostic.localization_key.empty() && diagnostic.confidence <= 100 &&
           (!diagnostic.coordinate || !diagnostic.coordinate->source_origin ||
            source_origin_valid(*diagnostic.coordinate->source_origin));
}

bool diagnostics_valid(
    const std::vector<aida::analysis::decompiler_diagnostic_t>& diagnostics) noexcept
{
    std::uint32_t previous_ordinal = 0;
    for (const auto& diagnostic : diagnostics) {
        if (!diagnostic_valid(diagnostic) || diagnostic.ordinal <= previous_ordinal)
            return false;
        previous_ordinal = diagnostic.ordinal;
    }
    return true;
}

bool profile_valid(aida::analysis::decompiler_profile_id_t profile) noexcept
{
    return profile >= aida::analysis::decompiler_profile_id_t::fast &&
           profile <= aida::analysis::decompiler_profile_id_t::thorough;
}

bool same_binding(
    const std::optional<aida::analysis::generation_bound_decompiler_entity_t>& lhs,
    const std::optional<aida::analysis::generation_bound_decompiler_entity_t>& rhs)
    noexcept
{
    if (lhs.has_value() != rhs.has_value()) return false;
    if (!lhs) return true;
    return lhs->schema_version == rhs->schema_version &&
           lhs->binary_id == rhs->binary_id &&
           lhs->load_profile_hash == rhs->load_profile_hash &&
           lhs->provider_hash == rhs->provider_hash &&
           lhs->artifact_hash == rhs->artifact_hash &&
           lhs->provider_size == rhs->provider_size &&
           lhs->generation == rhs->generation &&
           lhs->analysis_revision == rhs->analysis_revision &&
           lhs->overlay_revision == rhs->overlay_revision &&
           lhs->type_graph_revision == rhs->type_graph_revision &&
           lhs->reader_schema_version == rhs->reader_schema_version &&
           lhs->artifact_index == rhs->artifact_index &&
           lhs->method_index == rhs->method_index &&
           lhs->entity == rhs->entity;
}

std::string diagnostic_message(
    const aida::analysis::decompiler_diagnostic_t& diagnostic)
{
    std::string message = diagnostic.localization_key.empty()
        ? "decompiler_diagnostic" : diagnostic.localization_key;
    for (const auto& argument : diagnostic.localization_arguments) {
        message.push_back(' ');
        message += argument;
    }
    return message;
}

pseudocode_diagnostic_view_t diagnostic_view(
    const aida::analysis::decompiler_diagnostic_t& diagnostic)
{
    pseudocode_diagnostic_view_t view;
    view.severity = diagnostic.severity;
    view.code = diagnostic.code;
    view.localization_key = diagnostic.localization_key;
    view.message = diagnostic_message(diagnostic);
    view.coordinate = diagnostic.coordinate;
    view.confidence = diagnostic.confidence;
    view.retryable = diagnostic.retryable;
    view.ordinal = diagnostic.ordinal;
    if (diagnostic.coordinate && diagnostic.coordinate->source_origin) {
        view.has_line = true;
        view.line = diagnostic.coordinate->source_origin->first_line;
    }
    return view;
}

pseudocode_source_map_view_t source_map_view(
    const aida::analysis::decompiler_document_source_map_t& source_map,
    const aida::analysis::source_coordinate_t& coordinate)
{
    pseudocode_source_map_view_t view;
    view.token_begin = source_map.document_range.begin;
    view.token_end = source_map.document_range.end;
    view.coordinate = coordinate;
    if (coordinate.address_range) {
        view.has_address = true;
        view.address = coordinate.address_range->begin.value;
        view.address_extent = coordinate.address_range->end.value -
                              coordinate.address_range->begin.value;
        view.address_range = coordinate.address_range;
    }
    if (coordinate.source_origin) {
        view.has_source = true;
        view.source_line = coordinate.source_origin->first_line;
        view.source_column = coordinate.source_origin->first_column;
        view.source_last_line = coordinate.source_origin->last_line;
        view.source_last_column = coordinate.source_origin->last_column;
        view.source_path = coordinate.source_origin->source_path;
    }
    return view;
}

aida::analysis::decompiler_diagnostic_t terminal_diagnostic(
    aida::analysis::decompiler_diagnostic_code_t code,
    const char* localization_key,
    std::uint64_t job_id)
{
    aida::analysis::decompiler_diagnostic_t diagnostic;
    diagnostic.severity = aida::analysis::decompiler_diagnostic_severity_t::error;
    diagnostic.code = code;
    diagnostic.localization_key = localization_key;
    diagnostic.localization_arguments.push_back(std::to_string(job_id));
    diagnostic.ordinal = 1;
    return diagnostic;
}

aida::analysis::decompiler_diagnostic_t stale_result_diagnostic(
    std::uint64_t job_id,
    std::uint64_t result_generation,
    std::uint64_t current_generation)
{
    auto diagnostic = terminal_diagnostic(
        aida::analysis::decompiler_diagnostic_code_t::cache_key_rejected,
        "decompiler.worker.stale_result", job_id);
    diagnostic.localization_arguments.push_back(std::to_string(result_generation));
    diagnostic.localization_arguments.push_back(std::to_string(current_generation));
    diagnostic.retryable = true;
    return diagnostic;
}

bool coordinate_bound_to(
    const aida::analysis::source_coordinate_t& coordinate,
    const pseudocode_cached_document_t& cache_entry) noexcept
{
    return coordinate.workspace_generation == cache_entry.workspace_generation &&
           coordinate.entity == cache_entry.entity;
}

bool diagnostics_bound_to(
    const std::vector<aida::analysis::decompiler_diagnostic_t>& diagnostics,
    const pseudocode_cached_document_t& cache_entry) noexcept
{
    return std::all_of(diagnostics.begin(), diagnostics.end(),
        [&cache_entry](const aida::analysis::decompiler_diagnostic_t& diagnostic) {
            return !diagnostic.coordinate ||
                   coordinate_bound_to(*diagnostic.coordinate, cache_entry);
        });
}

bool unknowns_bound_to(
    const std::vector<aida::analysis::decompiler_unknown_t>& unknowns,
    const pseudocode_cached_document_t& cache_entry) noexcept
{
    return std::all_of(unknowns.begin(), unknowns.end(),
        [&cache_entry](const aida::analysis::decompiler_unknown_t& unknown) {
            return coordinate_bound_to(unknown.coordinate, cache_entry);
        });
}

bool document_bound_to_generation(
    const aida::analysis::decompiler_document_t& document,
    const pseudocode_cached_document_t& cache_entry) noexcept
{
    if (document.entity != cache_entry.entity || document.ast.entity != cache_entry.entity ||
        !unknowns_bound_to(document.unknowns, cache_entry) ||
        !diagnostics_bound_to(document.diagnostics, cache_entry) ||
        !unknowns_bound_to(document.ast.unknowns, cache_entry) ||
        !diagnostics_bound_to(document.ast.diagnostics, cache_entry))
        return false;
    for (const auto& node : document.ast.nodes) {
        if (!coordinate_bound_to(node.coordinate, cache_entry))
            return false;
    }
    for (const auto& coordinate : document.ast.source_coordinates) {
        if (!coordinate_bound_to(coordinate, cache_entry))
            return false;
    }
    for (const auto& source_map : document.source_maps) {
        for (const auto& coordinate : source_map.coordinates) {
            if (!coordinate_bound_to(coordinate, cache_entry))
                return false;
        }
    }
    return true;
}

}

bool pseudocode_page_request_valid(const pseudocode_page_request_t& request) noexcept
{
    return request.line_count != 0 &&
           request.line_count <= k_pseudocode_document_max_page_lines;
}

bool pseudocode_selection_valid(const pseudocode_selection_t& selection) noexcept
{
    switch (selection.kind) {
    case selection_kind_t::none:
        return !selection.has_address && selection.address == 0 &&
               selection.token_begin == 0 && selection.token_end == 0 &&
               selection.line_number == 0;
    case selection_kind_t::address:
        return selection.has_address &&
               ((selection.token_begin == 0 && selection.token_end == 0) ||
                selection.token_begin < selection.token_end);
    case selection_kind_t::range:
        return (selection.has_address || selection.address == 0) &&
               selection.token_begin < selection.token_end;
    case selection_kind_t::source:
        return !selection.has_address && selection.address == 0 &&
               selection.token_begin < selection.token_end &&
               selection.line_number != 0;
    case selection_kind_t::entity:
        return false;
    }
    return false;
}

bool pseudocode_request_valid(const pseudocode_request_t& request)
{
    if (request.timeout_ms == 0 || request.workspace_generation == 0 ||
        !profile_valid(request.profile) ||
        !aida::analysis::validate_decompiler_entity_key(request.entity).valid())
        return false;
    if (!request.binding)
        return true;
    const auto& binding = *request.binding;
    return binding.schema_version ==
               aida::analysis::managed_entity_binding_schema_version &&
           binding.generation == request.workspace_generation &&
           binding.entity == request.entity &&
           binding.analysis_revision != 0 && binding.provider_size != 0 &&
           !binding.binary_id.empty() && !binding.provider_hash.empty() &&
           !binding.artifact_hash.empty();
}

std::optional<aida::analysis::decompiler_entity_locator_t>
parse_pseudocode_entity_locator(std::string_view value) noexcept
{
    const auto colon = value.find(':');
    const auto at = value.find('@', colon == std::string_view::npos
        ? 0 : colon + 1U);
    if (colon == std::string_view::npos || at == std::string_view::npos ||
        colon == 0 || at <= colon + 1U || at + 1U >= value.size() ||
        value.find(':', colon + 1U) != std::string_view::npos ||
        value.find('@', at + 1U) != std::string_view::npos)
        return std::nullopt;
    aida::analysis::decompiler_entity_kind_t kind;
    const auto prefix = value.substr(0, colon);
    if (prefix == "cli")
        kind = aida::analysis::decompiler_entity_kind_t::cli_method;
    else if (prefix == "jvm")
        kind = aida::analysis::decompiler_entity_kind_t::jvm_method;
    else if (prefix == "dalvik")
        kind = aida::analysis::decompiler_entity_kind_t::dalvik_method;
    else
        return std::nullopt;
    std::uint32_t token = 0;
    std::uint32_t artifact = 0;
    const auto token_text = value.substr(colon + 1U, at - colon - 1U);
    const auto artifact_text = value.substr(at + 1U);
    if ((token_text.size() > 1U && token_text.front() == '0') ||
        (artifact_text.size() > 1U && artifact_text.front() == '0'))
        return std::nullopt;
    const auto token_result = std::from_chars(
        token_text.data(), token_text.data() + token_text.size(), token, 10);
    const auto artifact_result = std::from_chars(
        artifact_text.data(), artifact_text.data() + artifact_text.size(),
        artifact, 10);
    if (token_result.ec != std::errc{} ||
        token_result.ptr != token_text.data() + token_text.size() ||
        artifact_result.ec != std::errc{} ||
        artifact_result.ptr != artifact_text.data() + artifact_text.size())
        return std::nullopt;
    aida::analysis::decompiler_entity_locator_t locator;
    locator.token = token;
    locator.artifact_ordinal = artifact;
    locator.expected_kind = kind;
    return locator;
}

std::optional<std::string> canonical_pseudocode_entity_locator(
    const aida::analysis::decompiler_entity_locator_t& locator)
{
    if (locator.address || !locator.token || !locator.artifact_ordinal ||
        !locator.expected_kind)
        return std::nullopt;
    std::string prefix;
    switch (*locator.expected_kind) {
    case aida::analysis::decompiler_entity_kind_t::cli_method:
        prefix = "cli";
        break;
    case aida::analysis::decompiler_entity_kind_t::jvm_method:
        prefix = "jvm";
        break;
    case aida::analysis::decompiler_entity_kind_t::dalvik_method:
        prefix = "dalvik";
        break;
    default:
        return std::nullopt;
    }
    return prefix + ":" + std::to_string(*locator.token) + "@" +
        std::to_string(*locator.artifact_ordinal);
}

pseudocode_error_t pseudocode_document_model_t::fail(
    pseudocode_error_code_t code, std::uint64_t subject) const noexcept
{
    return {code, subject};
}

pseudocode_error_t pseudocode_document_model_t::stale() const noexcept
{
    return {pseudocode_error_code_t::stale_generation, bound_generation_};
}

pseudocode_document_model_t::pseudocode_document_model_t(
    pseudocode_source_adapter_t& source,
    const pseudocode_navigation_adapter_t* navigation) noexcept
    : source_(&source)
    , navigation_(navigation)
    , bound_generation_(source.current_generation())
    , next_job_id_(1)
    , active_(nullptr)
{
}

bool pseudocode_document_model_t::lease_current(
    std::uint64_t generation) const noexcept
{
    return generation == bound_generation_ &&
           source_->generation_current(bound_generation_);
}

bool pseudocode_document_model_t::entry_current(
    const pseudocode_cached_document_t& entry) const noexcept
{
    return entry.workspace_generation == bound_generation_ &&
           source_->generation_current(entry.workspace_generation) &&
           source_->binding_current(entry.binding);
}

pseudocode_error_t pseudocode_document_model_t::validate_document(
    const aida::analysis::decompiler_document_t& document,
    const pseudocode_cached_document_t& cache_entry) const
{
    if (document.schema_version != aida::analysis::k_decompiler_document_schema_version ||
        document.entity != cache_entry.entity ||
        document.profile != cache_entry.profile_info.profile ||
        document.rendered_text.empty() || document.tokens.empty() ||
        document.source_maps.empty())
        return fail(pseudocode_error_code_t::worker_failure, cache_entry.job_id);
    if (document.rendered_text.size() > k_pseudocode_document_max_rendered_bytes ||
        document.tokens.size() > k_pseudocode_document_max_tokens ||
        document.source_maps.size() > k_pseudocode_document_max_source_maps ||
        document.ast.nodes.size() > k_pseudocode_document_max_ast_nodes ||
        document.diagnostics.size() > k_pseudocode_document_max_diagnostics) {
        return fail(pseudocode_error_code_t::resource_exhausted, cache_entry.job_id);
    }
    if (!document_bound_to_generation(document, cache_entry))
        return fail(pseudocode_error_code_t::stale_result, cache_entry.job_id);

    std::size_t line_length = 0;
    std::uint32_t line_count = 1;
    for (std::size_t index = 0; index < document.rendered_text.size(); ++index) {
        const auto character = document.rendered_text[index];
        if (character == '\n') {
            line_length = 0;
            if (index + 1U < document.rendered_text.size() &&
                ++line_count > k_pseudocode_document_max_lines) {
                return fail(pseudocode_error_code_t::resource_exhausted, cache_entry.job_id);
            }
        } else if (++line_length > k_pseudocode_document_max_line_length) {
            return fail(pseudocode_error_code_t::resource_exhausted, cache_entry.job_id);
        }
    }

    std::size_t coordinate_count = 0;
    for (const auto& source_map : document.source_maps) {
        if (source_map.coordinates.size() >
            static_cast<std::size_t>(k_pseudocode_document_max_source_maps) - coordinate_count) {
            return fail(pseudocode_error_code_t::resource_exhausted, cache_entry.job_id);
        }
        coordinate_count += source_map.coordinates.size();
    }
    if (!aida::analysis::validate_decompiler_document(document).valid())
        return fail(pseudocode_error_code_t::worker_failure, cache_entry.job_id);
    return {};
}

pseudocode_cached_document_t* pseudocode_document_model_t::find_cached(
    const aida::analysis::decompiler_entity_key_t& entity)
{
    for (auto iterator = cache_.rbegin(); iterator != cache_.rend(); ++iterator) {
        if (iterator->entity == entity && entry_current(*iterator))
            return &(*iterator);
    }
    for (auto iterator = cache_.rbegin(); iterator != cache_.rend(); ++iterator) {
        if (iterator->entity == entity)
            return &(*iterator);
    }
    return nullptr;
}

pseudocode_cached_document_t* pseudocode_document_model_t::find_cached(
    const pseudocode_request_t& request)
{
    for (auto& entry : cache_) {
        if (entry.entity == request.entity &&
            entry.workspace_generation == request.workspace_generation &&
            entry.profile_info.profile == request.profile &&
            same_binding(entry.binding, request.binding))
            return &entry;
    }
    return nullptr;
}

const pseudocode_cached_document_t* pseudocode_document_model_t::find_cached(
    const aida::analysis::decompiler_entity_key_t& entity) const
{
    for (auto iterator = cache_.rbegin(); iterator != cache_.rend(); ++iterator) {
        if (iterator->entity == entity && entry_current(*iterator))
            return &(*iterator);
    }
    for (auto iterator = cache_.rbegin(); iterator != cache_.rend(); ++iterator) {
        if (iterator->entity == entity)
            return &(*iterator);
    }
    return nullptr;
}

const pseudocode_cached_document_t* pseudocode_document_model_t::find_cached(
    const pseudocode_request_t& request) const
{
    for (const auto& entry : cache_) {
        if (entry.entity == request.entity &&
            entry.workspace_generation == request.workspace_generation &&
            entry.profile_info.profile == request.profile &&
            same_binding(entry.binding, request.binding))
            return &entry;
    }
    return nullptr;
}

bool pseudocode_document_model_t::evict_oldest()
{
    if (cache_.size() < k_pseudocode_document_max_cached_documents)
        return true;
    auto oldest = cache_.end();
    for (auto iterator = cache_.begin(); iterator != cache_.end(); ++iterator) {
        if (iterator->state == pseudocode_cache_state_t::requesting)
            continue;
        if (oldest == cache_.end() || iterator->cached_at_ms < oldest->cached_at_ms)
            oldest = iterator;
    }
    if (oldest == cache_.end())
        return false;
    if (active_ == &(*oldest)) {
        active_ = nullptr;
        line_views_.clear();
        selection_ = {};
    }
    cache_.erase(oldest);
    return true;
}

void pseudocode_document_model_t::split_lines()
{
    line_views_.clear();
    if (!active_ || !active_->document || active_->document->rendered_text.empty())
        return;

    const auto& text = active_->document->rendered_text;
    std::size_t position = 0;
    std::uint32_t line_number = 1;
    while (position < text.size() &&
           line_views_.size() < k_pseudocode_document_max_lines) {
        auto end = text.find('\n', position);
        if (end == std::string::npos)
            end = text.size();
        pseudocode_line_view_t line;
        line.line_number = line_number++;
        line.text_begin = static_cast<std::uint32_t>(position);
        line.text_end = static_cast<std::uint32_t>(end);
        line.text = text.substr(position, end - position);
        line_views_.push_back(std::move(line));
        if (end == text.size())
            break;
        position = end + 1;
    }

    for (std::uint32_t token_index = 0;
         token_index < active_->document->tokens.size(); ++token_index) {
        const auto& token = active_->document->tokens[token_index];
        const auto line = std::upper_bound(
            line_views_.begin(), line_views_.end(), token.range.begin,
            [](std::uint32_t offset, const pseudocode_line_view_t& candidate) {
                return offset < candidate.text_begin;
            });
        if (line == line_views_.begin())
            continue;
        auto& target = *(line - 1);
        if (target.token_count == 0)
            target.first_token = token_index;
        ++target.token_count;
    }
}

void pseudocode_document_model_t::rebuild_address_map()
{
    if (!active_ || !active_->document)
        return;
    active_->address_map.clear();
    for (const auto& source_map : active_->document->source_maps) {
        for (const auto& coordinate : source_map.coordinates) {
            if (!coordinate.address_range)
                continue;
            pseudocode_address_map_entry_t entry;
            entry.address = coordinate.address_range->begin.value;
            entry.extent = coordinate.address_range->end.value -
                           coordinate.address_range->begin.value;
            entry.token_begin = source_map.document_range.begin;
            entry.token_end = source_map.document_range.end;
            const auto line = std::upper_bound(
                line_views_.begin(), line_views_.end(), entry.token_begin,
                [](std::uint32_t offset, const pseudocode_line_view_t& candidate) {
                    return offset < candidate.text_begin;
                });
            if (line != line_views_.begin())
                entry.line_number = (line - 1)->line_number;
            active_->address_map.push_back(entry);
        }
    }
    std::sort(active_->address_map.begin(), active_->address_map.end(),
        [](const pseudocode_address_map_entry_t& lhs,
           const pseudocode_address_map_entry_t& rhs) {
            if (lhs.address != rhs.address)
                return lhs.address < rhs.address;
            if (lhs.extent != rhs.extent)
                return lhs.extent > rhs.extent;
            if (lhs.token_begin != rhs.token_begin)
                return lhs.token_begin < rhs.token_begin;
            return lhs.token_end < rhs.token_end;
        });
    active_->address_map.erase(
        std::unique(active_->address_map.begin(), active_->address_map.end(),
            [](const pseudocode_address_map_entry_t& lhs,
               const pseudocode_address_map_entry_t& rhs) {
                return lhs.address == rhs.address && lhs.extent == rhs.extent &&
                       lhs.token_begin == rhs.token_begin && lhs.token_end == rhs.token_end;
            }),
        active_->address_map.end());
}

pseudocode_error_t pseudocode_document_model_t::resolve_request(
    std::uint64_t function_address,
    aida::analysis::decompiler_profile_id_t profile,
    std::uint64_t timeout_ms,
    pseudocode_request_t& output) const
{
    output = {};
    if (function_address == 0 || timeout_ms == 0)
        return fail(pseudocode_error_code_t::invalid_argument, function_address);
    const auto resolved = source_->resolve_request(
        function_address, profile, timeout_ms, output);
    if (!resolved)
        return fail(pseudocode_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(resolved.code));
    if (!pseudocode_request_valid(output)) {
        output = {};
        return fail(pseudocode_error_code_t::invalid_argument, function_address);
    }
    return {};
}

pseudocode_error_t pseudocode_document_model_t::resolve_request(
    const aida::analysis::decompiler_entity_locator_t& locator,
    aida::analysis::decompiler_profile_id_t profile,
    std::uint64_t timeout_ms,
    pseudocode_request_t& output) const
{
    output = {};
    if (timeout_ms == 0 || (locator.address.has_value() == locator.token.has_value()))
        return fail(pseudocode_error_code_t::invalid_argument);
    const auto resolved = source_->resolve_request(
        locator, profile, timeout_ms, output);
    if (!resolved)
        return fail(pseudocode_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(resolved.code));
    if (!pseudocode_request_valid(output)) {
        output = {};
        return fail(pseudocode_error_code_t::invalid_argument);
    }
    return {};
}

pseudocode_error_t pseudocode_document_model_t::request(
    const pseudocode_request_t& request)
{
    return request(request, false);
}

pseudocode_error_t pseudocode_document_model_t::request(
    const pseudocode_request_t& request,
    bool force_refresh)
{
    if (!pseudocode_request_valid(request))
        return fail(pseudocode_error_code_t::invalid_argument);
    if (!lease_current(request.workspace_generation))
        return stale();
    if (!source_->binding_current(request.binding))
        return fail(pseudocode_error_code_t::stale_result,
                    request.workspace_generation);

    for (auto& entry : cache_) {
        if (entry.state != pseudocode_cache_state_t::requesting ||
            entry_current(entry))
            continue;
        static_cast<void>(source_->cancel_decompilation(entry.job_id));
        entry.state = pseudocode_cache_state_t::stale;
        entry.document.reset();
    }
    auto* existing = find_cached(request);
    if (existing && existing->state == pseudocode_cache_state_t::requesting) {
        active_ = existing;
        line_views_.clear();
        selection_ = {};
        if (!force_refresh && entry_current(*existing) &&
            same_binding(existing->binding, request.binding))
            return fail(pseudocode_error_code_t::request_in_progress, existing->job_id);
        const auto cancel_error = source_->cancel_decompilation(existing->job_id);
        if (!cancel_error)
            return fail(pseudocode_error_code_t::adapter_rejected,
                        static_cast<std::uint64_t>(cancel_error.code));
        existing->state = pseudocode_cache_state_t::stale;
    }
    if (!force_refresh && existing &&
        existing->state == pseudocode_cache_state_t::cached &&
        entry_current(*existing) &&
        existing->profile_info.profile == request.profile &&
        same_binding(existing->binding, request.binding)) {
        active_ = existing;
        split_lines();
        rebuild_address_map();
        if (!source_->generation_current(bound_generation_))
            return stale();
        return {};
    }

    if (!existing && !evict_oldest())
        return fail(pseudocode_error_code_t::cache_full, cache_.size());
    if (next_job_id_ == 0)
        return fail(pseudocode_error_code_t::resource_exhausted);

    const auto budget = source_->profile_budget(request.profile);
    if (!lease_current(request.workspace_generation))
        return stale();
    if (!aida::analysis::validate_decompiler_profile(budget).valid() ||
        budget.profile != request.profile ||
        request.timeout_ms > budget.max_wall_clock_ms) {
        return fail(pseudocode_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(request.profile));
    }
    const auto job_id = next_job_id_++;
    const auto adapter_error = source_->request_decompilation(request, job_id);
    if (!source_->generation_current(bound_generation_) ||
        !source_->binding_current(request.binding)) {
        if (adapter_error) {
            const auto cancel_error = source_->cancel_decompilation(job_id);
            if (!cancel_error)
                return fail(pseudocode_error_code_t::adapter_rejected,
                            static_cast<std::uint64_t>(cancel_error.code));
        }
        return stale();
    }
    if (!adapter_error)
        return fail(pseudocode_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(adapter_error.code));

    pseudocode_cached_document_t entry;
    entry.entity = request.entity;
    entry.binding = request.binding;
    entry.workspace_generation = bound_generation_;
    entry.state = pseudocode_cache_state_t::requesting;
    entry.job_id = job_id;
    entry.cached_at_ms = now_ms();
    entry.profile_info.profile = request.profile;
    entry.profile_info.max_wall_clock_ms = budget.max_wall_clock_ms;
    entry.profile_info.max_cpu_ms = budget.max_cpu_ms;
    entry.profile_info.max_memory_bytes = budget.max_memory_bytes;

    if (existing) {
        *existing = std::move(entry);
        active_ = existing;
    } else {
        cache_.push_back(std::move(entry));
        active_ = &cache_.back();
    }
    line_views_.clear();
    selection_ = {};
    return {};
}

pseudocode_error_t pseudocode_document_model_t::activate(
    const aida::analysis::decompiler_entity_key_t& entity)
{
    if (!aida::analysis::validate_decompiler_entity_key(entity).valid())
        return fail(pseudocode_error_code_t::invalid_argument);
    auto* existing = find_cached(entity);
    if (!existing)
        return fail(pseudocode_error_code_t::cache_miss);
    const bool changed = active_ != existing;
    active_ = existing;
    if (changed)
        selection_ = {};
    if (!entry_current(*existing)) {
        line_views_.clear();
        return stale();
    }
    if (existing->state == pseudocode_cache_state_t::cached) {
        split_lines();
        rebuild_address_map();
    } else {
        line_views_.clear();
    }
    return {};
}

pseudocode_error_t pseudocode_document_model_t::activate(
    const pseudocode_request_t& request)
{
    if (!pseudocode_request_valid(request))
        return fail(pseudocode_error_code_t::invalid_argument);
    auto* existing = find_cached(request);
    if (!existing)
        return fail(pseudocode_error_code_t::cache_miss);
    const bool changed = active_ != existing;
    active_ = existing;
    if (changed)
        selection_ = {};
    if (!entry_current(*existing)) {
        line_views_.clear();
        return stale();
    }
    if (existing->state == pseudocode_cache_state_t::cached) {
        split_lines();
        rebuild_address_map();
    } else {
        line_views_.clear();
    }
    return {};
}

pseudocode_error_t pseudocode_document_model_t::cancel(std::uint64_t job_id)
{
    for (auto& entry : cache_) {
        if (entry.job_id != job_id)
            continue;
        if (entry.state != pseudocode_cache_state_t::requesting)
            return fail(pseudocode_error_code_t::no_active_request, job_id);
        const auto adapter_error = source_->cancel_decompilation(job_id);
        if (!adapter_error)
            return fail(pseudocode_error_code_t::adapter_rejected,
                        static_cast<std::uint64_t>(adapter_error.code));
        entry.state = pseudocode_cache_state_t::cancelled;
        if (active_ == &entry) {
            line_views_.clear();
            selection_ = {};
        }
        return {};
    }
    return fail(pseudocode_error_code_t::no_active_request, job_id);
}

pseudocode_error_t pseudocode_document_model_t::poll(std::uint64_t job_id)
{
    for (auto& entry : cache_) {
        if (entry.job_id != job_id)
            continue;
        if (entry.state != pseudocode_cache_state_t::requesting)
            return fail(pseudocode_error_code_t::no_active_request, job_id);
        const bool entry_active = active_ == &entry;
        const auto reject_stale_result = [&]() {
            entry.state = pseudocode_cache_state_t::stale;
            entry.document.reset();
            entry.failure_diagnostics.clear();
            entry.failure_diagnostics.push_back(stale_result_diagnostic(
                job_id, entry.workspace_generation, source_->current_generation()));
            entry.profile_info.elapsed_ms = now_ms() - entry.cached_at_ms;
            if (entry_active) {
                line_views_.clear();
                selection_ = {};
            }
            return fail(pseudocode_error_code_t::stale_result, job_id);
        };
        if (source_->job_active(job_id)) {
            if (!entry_current(entry)) {
                source_->cancel_decompilation(job_id);
                return reject_stale_result();
            }
            return {};
        }

        aida::analysis::decompiler_document_t document;
        const auto has_result = source_->poll_result(job_id, document);
        std::vector<aida::analysis::decompiler_diagnostic_t> diagnostics;
        const auto has_failure = !has_result && source_->poll_failure(job_id, diagnostics);
        if (!entry_current(entry)) {
            return reject_stale_result();
        }

        if (has_result) {
            auto error = validate_document(document, entry);
            if (!error) {
                if (error.code == pseudocode_error_code_t::stale_result)
                    return reject_stale_result();
                entry.state = pseudocode_cache_state_t::failed;
                entry.document.reset();
                entry.failure_diagnostics.clear();
                entry.failure_diagnostics.push_back(terminal_diagnostic(
                    error.code == pseudocode_error_code_t::resource_exhausted
                        ? aida::analysis::decompiler_diagnostic_code_t::resource_limit
                        : aida::analysis::decompiler_diagnostic_code_t::malformed_document,
                    error.code == pseudocode_error_code_t::resource_exhausted
                        ? "decompiler.document.resource_limit"
                        : "decompiler.document.rejected",
                    job_id));
                entry.profile_info.elapsed_ms = now_ms() - entry.cached_at_ms;
                if (entry_active) {
                    line_views_.clear();
                    selection_ = {};
                }
                return error;
            }
            if (!entry_current(entry)) {
                return reject_stale_result();
            }
            entry.document = std::make_shared<aida::analysis::decompiler_document_t>(
                std::move(document));
            entry.failure_diagnostics.clear();
            entry.state = pseudocode_cache_state_t::cached;
            entry.profile_info.elapsed_ms = now_ms() - entry.cached_at_ms;
            if (entry_active) {
                split_lines();
                rebuild_address_map();
            }
            if (!entry_current(entry))
                return reject_stale_result();
            return {};
        }

        if (!has_failure || diagnostics.empty())
            diagnostics.push_back(terminal_diagnostic(
                has_failure
                    ? aida::analysis::decompiler_diagnostic_code_t::provider_failure
                    : aida::analysis::decompiler_diagnostic_code_t::worker_protocol_failure,
                has_failure
                    ? "decompiler.worker.empty_failure"
                    : "decompiler.worker.missing_terminal_result",
                job_id));
        if (diagnostics.size() > k_pseudocode_document_max_diagnostics)
            diagnostics.resize(k_pseudocode_document_max_diagnostics);
        if (!diagnostics_valid(diagnostics)) {
            diagnostics.clear();
            diagnostics.push_back(terminal_diagnostic(
                aida::analysis::decompiler_diagnostic_code_t::worker_protocol_failure,
                "decompiler.worker.invalid_failure",
                job_id));
        }
        if (!entry_current(entry))
            return reject_stale_result();
        entry.failure_diagnostics = std::move(diagnostics);
        entry.document.reset();
        entry.state = pseudocode_cache_state_t::failed;
        entry.profile_info.elapsed_ms = now_ms() - entry.cached_at_ms;
        if (entry_active) {
            line_views_.clear();
            selection_ = {};
        }
        return fail(pseudocode_error_code_t::worker_failure, job_id);
    }
    return fail(pseudocode_error_code_t::no_active_request, job_id);
}

pseudocode_error_t pseudocode_document_model_t::page(
    const pseudocode_page_request_t& request,
    pseudocode_page_t& output) const
{
    output = {};
    if (!pseudocode_page_request_valid(request))
        return fail(pseudocode_error_code_t::invalid_argument, request.line_count);
    if (!active_)
        return source_->generation_current(bound_generation_)
            ? fail(pseudocode_error_code_t::cache_miss) : stale();
    const bool retained_stale_result = active_->state == pseudocode_cache_state_t::stale &&
        !active_->failure_diagnostics.empty() &&
        active_->failure_diagnostics.front().localization_key ==
            "decompiler.worker.stale_result";
    if (!entry_current(*active_) && !retained_stale_result)
        return stale();

    output.workspace_generation = active_->workspace_generation;
    output.cache_state = active_->state;
    if (active_->state == pseudocode_cache_state_t::requesting) {
        if (!entry_current(*active_)) {
            output = {};
            return stale();
        }
        return {};
    }
    if (active_->state == pseudocode_cache_state_t::stale) {
        output.diagnostics = diagnostics();
        return fail(retained_stale_result
                ? pseudocode_error_code_t::stale_result
                : pseudocode_error_code_t::stale_generation,
            retained_stale_result ? active_->job_id : active_->workspace_generation);
    }
    if (active_->state == pseudocode_cache_state_t::failed) {
        output.diagnostics = diagnostics();
        return fail(pseudocode_error_code_t::worker_failure, active_->job_id);
    }
    if (active_->state == pseudocode_cache_state_t::cancelled)
        return fail(pseudocode_error_code_t::request_cancelled, active_->job_id);
    if (!active_->document)
        return fail(pseudocode_error_code_t::cache_miss);

    output.total_lines = static_cast<std::uint32_t>(line_views_.size());
    output.first_line = request.first_line;
    if (request.first_line >= line_views_.size()) {
        output.diagnostics = diagnostics();
        if (!entry_current(*active_)) {
            output = {};
            return stale();
        }
        return {};
    }

    const auto remaining = static_cast<std::uint32_t>(line_views_.size()) - request.first_line;
    const auto to_read = (std::min)(request.line_count, remaining);
    output.lines.reserve(to_read);
    std::uint32_t page_text_begin = line_views_[request.first_line].text_begin;
    std::uint32_t page_text_end = page_text_begin;
    for (std::uint32_t index = 0; index < to_read; ++index) {
        const auto& line = line_views_[request.first_line + index];
        output.lines.push_back(line);
        page_text_end = line.text_end;
        if (page_text_end < active_->document->rendered_text.size() &&
            active_->document->rendered_text[page_text_end] == '\n') {
            ++page_text_end;
        }
    }

    for (std::size_t token_index = 0;
         token_index < active_->document->tokens.size(); ++token_index) {
        const auto& token = active_->document->tokens[token_index];
        if (token.range.end <= page_text_begin)
            continue;
        if (token.range.begin >= page_text_end)
            break;
        pseudocode_token_view_t view;
        view.kind = token.kind;
        view.token_index = static_cast<std::uint32_t>(token_index);
        view.range = token.range;
        view.ast_node_id = token.ast_node_id;
        view.text = active_->document->rendered_text.substr(
            token.range.begin, token.range.end - token.range.begin);
        output.tokens.push_back(std::move(view));
    }

    for (const auto& source_map : active_->document->source_maps) {
        if (source_map.document_range.end <= page_text_begin)
            continue;
        if (source_map.document_range.begin >= page_text_end)
            break;
        for (const auto& coordinate : source_map.coordinates)
            output.source_maps.push_back(source_map_view(source_map, coordinate));
    }
    output.diagnostics = diagnostics();
    if (!entry_current(*active_)) {
        output = {};
        return stale();
    }
    return {};
}

pseudocode_error_t pseudocode_document_model_t::select(
    const pseudocode_selection_t& selection)
{
    if (!pseudocode_selection_valid(selection))
        return fail(pseudocode_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(selection.kind));
    if (!lease_current(bound_generation_))
        return stale();
    if (selection.kind == selection_kind_t::none) {
        selection_ = {};
        return {};
    }
    if (!active_ || active_->state != pseudocode_cache_state_t::cached || !active_->document)
        return fail(pseudocode_error_code_t::cache_miss);
    if (!entry_current(*active_))
        return stale();

    pseudocode_selection_t canonical = selection;
    if (selection.kind == selection_kind_t::address) {
        pseudocode_address_map_entry_t mapping;
        auto error = resolve_address(selection.address, mapping);
        if (!error)
            return error;
        if ((selection.token_begin != 0 || selection.token_end != 0) &&
            (selection.token_begin != mapping.token_begin ||
             selection.token_end != mapping.token_end)) {
            return fail(pseudocode_error_code_t::token_not_mapped, selection.token_begin);
        }
        canonical.token_begin = mapping.token_begin;
        canonical.token_end = mapping.token_end;
        canonical.line_number = mapping.line_number;
    } else {
        if (selection.token_end > active_->document->rendered_text.size())
            return fail(pseudocode_error_code_t::token_not_mapped, selection.token_end);
        pseudocode_address_map_entry_t mapping;
        const auto error = resolve_token(selection.token_begin, mapping);
        if (selection.has_address) {
            if (!error || selection.address < mapping.address ||
                selection.address - mapping.address >= mapping.extent) {
                return fail(pseudocode_error_code_t::address_not_mapped, selection.address);
            }
        }
        if (error && canonical.line_number == 0)
            canonical.line_number = mapping.line_number;
    }
    if (!entry_current(*active_))
        return stale();
    selection_ = canonical;
    return {};
}

void pseudocode_document_model_t::clear_selection() noexcept
{
    selection_ = {};
}

pseudocode_error_t pseudocode_document_model_t::resolve_address(
    std::uint64_t address,
    pseudocode_address_map_entry_t& output) const
{
    output = {};
    if (!lease_current(bound_generation_))
        return stale();
    if (!active_ || active_->state != pseudocode_cache_state_t::cached || !active_->document)
        return fail(pseudocode_error_code_t::cache_miss);
    if (!entry_current(*active_))
        return stale();
    if (navigation_) {
        pseudocode_address_map_entry_t candidate;
        const auto adapter_error = navigation_->resolve_address_to_token(
            address, *active_->document, candidate);
        if (!entry_current(*active_))
            return stale();
        if (adapter_error && candidate.extent != 0 && address >= candidate.address &&
            address - candidate.address < candidate.extent &&
            address_extent_valid(candidate.address, candidate.extent) &&
            token_range_valid(candidate.token_begin, candidate.token_end,
                              active_->document->rendered_text.size())) {
            output = candidate;
            return {};
        }
    }

    const pseudocode_address_map_entry_t* best = nullptr;
    for (const auto& entry : active_->address_map) {
        if (entry.address > address)
            break;
        if (entry.extent == 0 || address - entry.address >= entry.extent)
            continue;
        if (!best || entry.address > best->address ||
            (entry.address == best->address && entry.extent < best->extent))
            best = &entry;
    }
    if (!entry_current(*active_))
        return stale();
    if (!best)
        return fail(pseudocode_error_code_t::address_not_mapped, address);
    output = *best;
    return {};
}

pseudocode_error_t pseudocode_document_model_t::resolve_token(
    std::uint32_t token_begin,
    pseudocode_address_map_entry_t& output) const
{
    output = {};
    if (!lease_current(bound_generation_))
        return stale();
    if (!active_ || active_->state != pseudocode_cache_state_t::cached || !active_->document)
        return fail(pseudocode_error_code_t::cache_miss);
    if (!entry_current(*active_))
        return stale();
    if (token_begin >= active_->document->rendered_text.size())
        return fail(pseudocode_error_code_t::token_not_mapped, token_begin);
    if (navigation_) {
        pseudocode_address_map_entry_t candidate;
        const auto adapter_error = navigation_->resolve_token_to_address(
            token_begin, *active_->document, candidate);
        if (!entry_current(*active_))
            return stale();
        if (adapter_error && address_extent_valid(candidate.address, candidate.extent) &&
            token_range_valid(candidate.token_begin, candidate.token_end,
                              active_->document->rendered_text.size()) &&
            token_begin >= candidate.token_begin && token_begin < candidate.token_end) {
            output = candidate;
            return {};
        }
    }
    for (const auto& entry : active_->address_map) {
        if (token_begin >= entry.token_begin && token_begin < entry.token_end) {
            if (!entry_current(*active_))
                return stale();
            output = entry;
            return {};
        }
    }
    if (!entry_current(*active_))
        return stale();
    return fail(pseudocode_error_code_t::token_not_mapped, token_begin);
}

void pseudocode_document_model_t::refresh() noexcept
{
    const auto generation = source_->current_generation();
    if (generation != bound_generation_)
        bound_generation_ = generation;
    for (auto& entry : cache_) {
        if (!entry_current(entry) &&
            entry.state != pseudocode_cache_state_t::requesting)
            entry.state = pseudocode_cache_state_t::stale;
    }
    if (active_ && !entry_current(*active_)) {
        line_views_.clear();
        selection_ = {};
    }
}

pseudocode_command_result_t pseudocode_document_model_t::execute(
    const pseudocode_command_t& command)
{
    pseudocode_command_result_t result;
    const auto require_lease = [&]() {
        if (lease_current(command.expected_generation))
            return true;
        result.error = stale();
        return false;
    };

    switch (command.kind) {
    case pseudocode_command_kind_t::request:
        if (require_lease()) {
            const auto previous_job = active_ ? active_->job_id : 0;
            result.error = request(command.request);
            if (active_)
                result.job_id = active_->job_id;
            result.changed = result.error.ok() && result.job_id != previous_job;
        }
        break;
    case pseudocode_command_kind_t::cancel:
        result.error = cancel(command.job_id);
        result.changed = result.error.ok();
        break;
    case pseudocode_command_kind_t::poll: {
        const auto previous_state = cache_state();
        result.error = poll(command.job_id);
        result.changed = cache_state() != previous_state;
        break;
    }
    case pseudocode_command_kind_t::page:
        if (require_lease()) {
            result.error = page(command.page_request, result.page);
            result.changed = result.error.ok() && !result.page.lines.empty();
        }
        break;
    case pseudocode_command_kind_t::select:
        if (require_lease()) {
            result.error = select(command.selection);
            result.selection = selection_;
            result.changed = result.error.ok();
        }
        break;
    case pseudocode_command_kind_t::clear_selection:
        if (require_lease()) {
            result.changed = selection_.kind != selection_kind_t::none;
            clear_selection();
        }
        break;
    case pseudocode_command_kind_t::refresh: {
        const auto previous_generation = bound_generation_;
        refresh();
        result.changed = previous_generation != bound_generation_;
        break;
    }
    case pseudocode_command_kind_t::resolve_address:
        if (require_lease()) {
            result.error = resolve_address(command.resolve_address, result.address_map_entry);
            result.changed = result.error.ok();
        }
        break;
    case pseudocode_command_kind_t::resolve_token:
        if (require_lease()) {
            result.error = resolve_token(command.resolve_token, result.address_map_entry);
            result.changed = result.error.ok();
        }
        break;
    default:
        result.error = fail(pseudocode_error_code_t::invalid_argument,
                            static_cast<std::uint64_t>(command.kind));
        break;
    }
    result.cache_state = cache_state();
    return result;
}

pseudocode_cache_state_t pseudocode_document_model_t::cache_state() const noexcept
{
    return active_ ? active_->state : pseudocode_cache_state_t::empty;
}

const pseudocode_cached_document_t*
pseudocode_document_model_t::cached_document() const noexcept
{
    return active_;
}

const pseudocode_cached_document_t*
pseudocode_document_model_t::cached_document(
    const aida::analysis::decompiler_entity_key_t& entity) const noexcept
{
    return find_cached(entity);
}

const pseudocode_cached_document_t*
pseudocode_document_model_t::cached_document(
    const pseudocode_request_t& request) const noexcept
{
    return find_cached(request);
}

std::uint64_t pseudocode_document_model_t::current_generation() const noexcept
{
    return source_->current_generation();
}

bool pseudocode_document_model_t::generation_current(
    std::uint64_t generation) const noexcept
{
    return lease_current(generation);
}

bool pseudocode_document_model_t::is_stale() const noexcept
{
    return !source_->generation_current(bound_generation_) ||
           (active_ && active_->state == pseudocode_cache_state_t::stale) ||
           (active_ && !entry_current(*active_));
}

bool pseudocode_document_model_t::has_pending_requests() const noexcept
{
    return std::any_of(cache_.begin(), cache_.end(),
        [](const pseudocode_cached_document_t& entry) {
            return entry.state == pseudocode_cache_state_t::requesting;
        });
}

std::uint32_t pseudocode_document_model_t::cached_document_count() const noexcept
{
    return static_cast<std::uint32_t>(cache_.size());
}

const pseudocode_selection_t& pseudocode_document_model_t::selection() const noexcept
{
    return selection_;
}

const pseudocode_profile_info_t&
pseudocode_document_model_t::profile_info() const noexcept
{
    static const pseudocode_profile_info_t empty;
    return active_ ? active_->profile_info : empty;
}

std::vector<pseudocode_diagnostic_view_t>
pseudocode_document_model_t::diagnostics() const
{
    std::vector<pseudocode_diagnostic_view_t> result;
    if (!active_)
        return result;
    const bool retained_stale_result = active_->state == pseudocode_cache_state_t::stale &&
        !active_->failure_diagnostics.empty() &&
        active_->failure_diagnostics.front().localization_key ==
            "decompiler.worker.stale_result";
    if (!entry_current(*active_) && !retained_stale_result)
        return result;
    const auto* source = &active_->failure_diagnostics;
    if (active_->state != pseudocode_cache_state_t::failed && active_->document)
        source = &active_->document->diagnostics;
    const auto count = (std::min)(source->size(),
                                  static_cast<std::size_t>(k_pseudocode_document_max_diagnostics));
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index)
        result.push_back(diagnostic_view((*source)[index]));
    if (!entry_current(*active_) && !retained_stale_result)
        result.clear();
    return result;
}

std::vector<pseudocode_source_map_view_t>
pseudocode_document_model_t::source_maps() const
{
    std::vector<pseudocode_source_map_view_t> result;
    if (!active_ || !active_->document ||
        !entry_current(*active_) ||
        active_->state != pseudocode_cache_state_t::cached)
        return result;
    result.reserve((std::min)(active_->document->source_maps.size(),
                              static_cast<std::size_t>(k_pseudocode_document_max_source_maps)));
    for (const auto& source_map : active_->document->source_maps) {
        for (const auto& coordinate : source_map.coordinates) {
            result.push_back(source_map_view(source_map, coordinate));
            if (result.size() >= k_pseudocode_document_max_source_maps) {
                if (!entry_current(*active_))
                    result.clear();
                return result;
            }
        }
    }
    if (!entry_current(*active_))
        result.clear();
    return result;
}

}
}
}
