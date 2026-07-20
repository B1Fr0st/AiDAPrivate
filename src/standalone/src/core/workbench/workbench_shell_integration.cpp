#include "workbench_shell_integration.hpp"

#include "workbench_persistence.hpp"
#include "../analysis/decompiler/decompiler_service.hpp"
#include "../analysis/decompiler/decompiler_ui_integration.hpp"
#include "../analysis/workspace/analysis_workspace.hpp"
#include "../analysis/workspace/overlay_journal.hpp"
#include "../infra/executor.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#include "../../preview/workbench_preview_adapter.hpp"
#else
#include "../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace aida {
namespace workbench {
namespace {

constexpr std::uint64_t k_shell_fnv_offset = 14695981039346656037ULL;
constexpr std::uint64_t k_shell_fnv_prime = 1099511628211ULL;

workbench_error_t shell_error(workbench_error_code_t code,
                              std::uint64_t subject = 0) noexcept
{
    return {code, subject};
}

workbench_error_t inspector_shell_error(
    const inspector::inspector_error_t& error) noexcept
{
    using inspector_code_t = inspector::inspector_error_code_t;
    switch (error.code) {
    case inspector_code_t::none:
        return {};
    case inspector_code_t::workspace_mismatch:
        return shell_error(workbench_error_code_t::workspace_mismatch, error.subject);
    case inspector_code_t::stale_generation:
    case inspector_code_t::selection_changed:
        return shell_error(workbench_error_code_t::revision_mismatch, error.subject);
    case inspector_code_t::invalid_panel:
        return shell_error(workbench_error_code_t::invalid_panel, error.subject);
    case inspector_code_t::invalid_layout:
    case inspector_code_t::layout_growth:
        return shell_error(workbench_error_code_t::invalid_layout, error.subject);
    case inspector_code_t::identifier_overflow:
        return shell_error(workbench_error_code_t::revision_overflow, error.subject);
    case inspector_code_t::invalid_context:
        return shell_error(workbench_error_code_t::invalid_view, error.subject);
    case inspector_code_t::invalid_query:
    case inspector_code_t::query_capacity:
    case inspector_code_t::duplicate_query:
    case inspector_code_t::query_not_found:
    case inspector_code_t::invalid_result:
    case inspector_code_t::result_limit_exceeded:
    case inspector_code_t::payload_mismatch:
        return shell_error(workbench_error_code_t::adapter_rejected, error.subject);
    }
    return shell_error(workbench_error_code_t::adapter_rejected, error.subject);
}

bool checked_add(std::uint64_t lhs, std::uint64_t rhs,
                 std::uint64_t& output) noexcept
{
    if (rhs > (std::numeric_limits<std::uint64_t>::max)() - lhs)
        return false;
    output = lhs + rhs;
    return true;
}

template <typename T, typename Compare, typename Cancellation>
bool bounded_stable_sort(std::vector<T>& values, Compare compare,
                         const Cancellation* cancellation)
{
    if (values.size() < 2)
        return !(cancellation && cancellation->cancelled());
    std::vector<T> scratch(values.size());
    for (std::size_t width = 1; width < values.size();) {
        for (std::size_t first = 0; first < values.size();) {
            if (cancellation && cancellation->cancelled())
                return false;
            const auto middle = (std::min)(values.size(), first + width);
            const auto last = (std::min)(values.size(), middle + width);
            auto left = first;
            auto right = middle;
            auto output = first;
            while (left < middle || right < last) {
                if ((output & 0xFFU) == 0U && cancellation &&
                    cancellation->cancelled())
                    return false;
                if (left < middle &&
                    (right == last || !compare(values[right], values[left]))) {
                    scratch[output++] = std::move(values[left++]);
                } else {
                    scratch[output++] = std::move(values[right++]);
                }
            }
            first = last;
        }
        values.swap(scratch);
        if (width > values.size() / 2U)
            break;
        width *= 2U;
    }
    return !(cancellation && cancellation->cancelled());
}

std::uint64_t stable_hash(std::string_view value) noexcept
{
    std::uint64_t hash = k_shell_fnv_offset;
    for (const auto character : value) {
        hash ^= static_cast<std::uint8_t>(character);
        hash *= k_shell_fnv_prime;
    }
    return hash == 0 ? 1 : hash;
}

std::string hexadecimal(std::uint64_t value)
{
    std::ostringstream output;
    output << "0x" << std::uppercase << std::hex << value;
    return output.str();
}

std::string hexadecimal_bytes(const std::vector<std::uint8_t>& bytes)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string output;
    if (bytes.empty())
        return output;
    output.reserve(bytes.size() * 3U - 1U);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0)
            output.push_back(' ');
        output.push_back(digits[bytes[index] >> 4U]);
        output.push_back(digits[bytes[index] & 0x0FU]);
    }
    return output;
}

std::string bounded_diff_value(const std::string& value)
{
    if (value.size() <= diff_document::k_diff_document_max_value_bytes)
        return value;
    const auto suffix = std::string("#") + hexadecimal(stable_hash(value));
    const auto prefix_size =
        diff_document::k_diff_document_max_value_bytes - suffix.size();
    return value.substr(0, prefix_size) + suffix;
}

struct retained_overlay_t final {
    std::uint64_t generation = 0;
    analysis::overlay_snapshot_t snapshot;
};

class workbench_analysis_source_t;

class workbench_analysis_source_catalog_t final {
public:
    bool publish(workspace_id_t workspace,
                 const analysis::binary_id_t& binary_id,
                 const std::shared_ptr<workbench_analysis_source_t>& source)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = sources_.find(workspace.value);
        if (found != sources_.end()) {
            const auto active = found->second.source.lock();
            if (active && found->second.binary_id != binary_id)
                return false;
        }
        source_entry_t entry;
        entry.binary_id = binary_id;
        entry.source = source;
        sources_[workspace.value] = std::move(entry);
        return true;
    }

    std::shared_ptr<workbench_analysis_source_t> find(
        std::uint64_t workspace) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = sources_.find(workspace);
        if (found == sources_.end())
            return {};
        auto source = found->second.source.lock();
        if (!source)
            sources_.erase(found);
        return source;
    }

private:
    struct source_entry_t final {
        analysis::binary_id_t binary_id;
        std::weak_ptr<workbench_analysis_source_t> source;
    };

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::uint64_t, source_entry_t> sources_;
};

std::shared_ptr<workbench_analysis_source_catalog_t> production_source_catalog()
{
    static const auto catalog =
        std::make_shared<workbench_analysis_source_catalog_t>();
    return catalog;
}

const char* analysis_document_title(document_kind_t kind) noexcept
{
    switch (kind) {
        case document_kind_t::disassembly:
            return "Disassembly";
        case document_kind_t::hex:
            return "Hex";
        case document_kind_t::pseudocode:
            return "Pseudocode";
        case document_kind_t::graph:
            return "Graph";
        case document_kind_t::diff:
            return "Diff";
        default:
            return nullptr;
    }
}

bool analysis_document_descriptor(const document_identity_t& identity,
                                  document_descriptor_t& output)
{
    output = {};
    const auto* title = analysis_document_title(identity.kind);
    const auto managed_locator =
        identity.kind == document_kind_t::pseudocode &&
        !identity.has_address
            ? pseudocode_document::parse_pseudocode_entity_locator(
                identity.provider_key)
            : std::nullopt;
    const auto canonical_managed_locator = managed_locator
        ? pseudocode_document::canonical_pseudocode_entity_locator(
            *managed_locator)
        : std::nullopt;
    const bool managed_identity = canonical_managed_locator &&
        *canonical_managed_locator == identity.provider_key;
    if (!title || !identity.workspace.valid() || identity.object_id != 1 ||
        identity.variant_id != 0 ||
        (identity.provider_key != "analysis" && !managed_identity) ||
        (identity.has_address && identity.address == 0))
        return false;
    output.identity = identity;
    output.title = title;
    if (identity.has_address) {
        std::ostringstream stream;
        stream << title << " 0x" << std::uppercase << std::hex
               << identity.address;
        output.title = stream.str();
    } else if (managed_identity) {
        output.title = std::string(title) + " " + identity.provider_key;
    }
    output.can_open = true;
    return true;
}

class workbench_analysis_source_t final
    : public std::enable_shared_from_this<workbench_analysis_source_t>,
      public navigator::navigator_packed_store_adapter_t {
public:
    workbench_analysis_source_t(
        workspace_id_t workspace,
        std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace,
        std::uint32_t generation_limit,
        std::uint32_t overlay_limit)
        : workspace_(workspace),
          analysis_workspace_(std::move(analysis_workspace)),
          generation_limit_(generation_limit),
          overlay_limit_(overlay_limit)
    {
    }

    bool capture_current() const
    {
        if (!analysis_workspace_ || analysis_workspace_->closing() ||
            analysis_workspace_->closed())
            return false;
        std::shared_ptr<const analysis::analysis_publication_t> publication;
        analysis::overlay_snapshot_t overlay_snapshot;
        bool captured = false;
        for (std::uint32_t attempt = 0; attempt < 2U; ++attempt) {
            publication = analysis_workspace_->analysis_publication();
            if (!publication || !publication->snapshot ||
                publication->generation == 0)
                return false;
            auto overlay = analysis_workspace_->overlay();
            if (overlay) {
                try {
                    overlay_snapshot = overlay->snapshot();
                } catch (...) {
                    return false;
                }
            } else {
                overlay_snapshot = {};
                overlay_snapshot.revision =
                    analysis_workspace_->overlay_revision();
            }
            const auto confirmed =
                analysis_workspace_->analysis_publication();
            if (same_publication(publication, confirmed)) {
                captured = true;
                break;
            }
        }
        if (!captured)
            return false;
        const auto generation = publication->generation;

        std::lock_guard<std::mutex> lock(mutex_);
        const auto publication_match = std::find_if(
            publications_.begin(), publications_.end(),
            [&publication](const auto& candidate) {
                return candidate->generation == publication->generation;
            });
        if (publication_match == publications_.end()) {
            publications_.push_back(std::move(publication));
        } else if (!same_publication(*publication_match, publication)) {
            *publication_match = std::move(publication);
        }
        while (publications_.size() > generation_limit_)
            publications_.pop_front();

        const auto overlay_match = std::find_if(
            overlays_.begin(), overlays_.end(),
            [&overlay_snapshot, generation](const retained_overlay_t& candidate) {
                return candidate.generation == generation &&
                       candidate.snapshot.revision == overlay_snapshot.revision;
            });
        if (overlay_match == overlays_.end()) {
            retained_overlay_t retained;
            retained.generation = generation;
            retained.snapshot = std::move(overlay_snapshot);
            overlays_.push_back(std::move(retained));
        } else {
            overlay_match->snapshot = std::move(overlay_snapshot);
        }
        while (overlays_.size() > overlay_limit_)
            overlays_.pop_front();
        return true;
    }

    std::shared_ptr<const analysis::analysis_publication_t>
        current_publication() const
    {
        if (!capture_current())
            return {};
        std::lock_guard<std::mutex> lock(mutex_);
        if (publications_.empty())
            return {};
        const auto generation = current_generation_locked();
        const auto found = std::find_if(
            publications_.begin(), publications_.end(),
            [generation](const auto& publication) {
                return publication->generation == generation;
            });
        if (found == publications_.end())
            return {};
        return *found;
    }

    std::shared_ptr<const analysis::analysis_publication_t> publication(
        std::uint64_t generation) const
    {
        capture_current();
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = std::find_if(
            publications_.begin(), publications_.end(),
            [generation](const auto& publication) {
                return publication->generation == generation;
            });
        if (found == publications_.end())
            return {};
        return *found;
    }

    bool publication_current(
        const std::shared_ptr<const analysis::analysis_publication_t>& bound) const
    {
        if (!bound || !analysis_workspace_ || analysis_workspace_->closing() ||
            analysis_workspace_->closed())
            return false;
        const auto current = analysis_workspace_->analysis_publication();
        return same_publication(bound, current);
    }

    std::uint64_t current_generation() const noexcept override
    {
        if (!analysis_workspace_)
            return 0;
        const auto publication = analysis_workspace_->analysis_publication();
        return publication ? publication->generation : 0;
    }

    bool generation_available(std::uint64_t generation) const
    {
        return publication(generation) != nullptr;
    }

    bool generation_current(std::uint64_t generation) const noexcept override
    {
        try {
            const auto current = analysis_workspace_
                ? analysis_workspace_->analysis_publication() : nullptr;
            return current && current->generation == generation &&
                   current->snapshot && !analysis_workspace_->closing() &&
                   !analysis_workspace_->closed();
        } catch (...) {
            return false;
        }
    }

    std::uint64_t record_count(
        navigator::navigator_domain_t domain,
        std::uint64_t generation) const noexcept override
    {
        try {
            const auto retained = publication(generation);
            if (!retained || !retained->snapshot)
                return 0;
            const auto& snapshot = *retained->snapshot;
            const auto image = snapshot.normalized_image;
            switch (domain) {
            case navigator::navigator_domain_t::binaries:
                return 1;
            case navigator::navigator_domain_t::sections:
                return image ? (image->sections.empty()
                    ? image->segments.size() : image->sections.size()) : 0;
            case navigator::navigator_domain_t::functions:
                return snapshot.functions.size();
            case navigator::navigator_domain_t::imports:
                return image ? image->imports.size() : 0;
            case navigator::navigator_domain_t::exports:
                return image ? image->exports.size() : 0;
            case navigator::navigator_domain_t::strings:
                return snapshot.strings.size();
            case navigator::navigator_domain_t::symbols:
                return snapshot.symbols.size();
            case navigator::navigator_domain_t::types:
                return snapshot.rich_facts.type_candidates.size();
            case navigator::navigator_domain_t::diagnostics:
                return snapshot.rich_facts.metadata_conflicts.size();
            case navigator::navigator_domain_t::bookmarks:
                return analysis_workspace_->view_state().bookmarks.size();
            case navigator::navigator_domain_t::progress:
                return 1;
            case navigator::navigator_domain_t::invalid:
                return 0;
            }
        } catch (...) {
        }
        return 0;
    }

    bool record_at(navigator::navigator_domain_t domain,
                   std::uint64_t generation, std::uint64_t ordinal,
                   navigator::navigator_item_view_t& output) const noexcept override
    {
        output = {};
        try {
            const auto retained = publication(generation);
            if (!retained || !retained->snapshot)
                return false;
            const auto& snapshot = *retained->snapshot;
            const auto image = snapshot.normalized_image;
            output.domain = domain;
            output.selectable = true;
            output.expandable = false;
            switch (domain) {
            case navigator::navigator_domain_t::binaries:
                if (ordinal != 0)
                    return false;
                output.id = navigator_row_identity(domain, 1);
                output.label = analysis_workspace_->identity().bin_name();
                output.secondary = image
                    ? std::string_view(image->format_name) : std::string_view{};
                output.detail = "Static binary";
                output.has_address = image && image->image_size != 0;
                output.address = image ? image->image_base : 0;
                output.metric = analysis_workspace_->provider().size();
                break;
            case navigator::navigator_domain_t::sections:
                if (!image)
                    return false;
                if (!image->sections.empty()) {
                    if (ordinal >= image->sections.size())
                        return false;
                    const auto& section = image->sections[
                        static_cast<std::size_t>(ordinal)];
                    output.id = navigator_row_identity(
                        domain, section.index + 1ULL);
                    output.label = section.name.empty()
                        ? std::string_view("Unnamed section") : section.name;
                    output.secondary = "Section";
                    output.has_address = section.virtual_size != 0;
                    output.address = section.virtual_address;
                    output.metric = section.virtual_size;
                } else {
                    if (ordinal >= image->segments.size())
                        return false;
                    const auto& segment = image->segments[
                        static_cast<std::size_t>(ordinal)];
                    output.id = navigator_row_identity(
                        domain, segment.index + 1ULL);
                    output.label = segment.name.empty()
                        ? std::string_view("Unnamed segment") : segment.name;
                    output.secondary = "Segment";
                    output.has_address = segment.virtual_size != 0;
                    output.address = segment.virtual_address;
                    output.metric = segment.virtual_size;
                }
                break;
            case navigator::navigator_domain_t::functions: {
                if (ordinal >= snapshot.functions.size())
                    return false;
                const auto& function = snapshot.functions[
                    static_cast<std::size_t>(ordinal)];
                output.id = navigator_row_identity(
                    domain, function.id != 0 ? function.id : function.start.value);
                const auto symbol = std::lower_bound(
                    snapshot.symbols.begin(), snapshot.symbols.end(),
                    function.start,
                    [](const analysis::symbol_record_t& candidate,
                       const analysis::address_t& address) {
                        return candidate.address < address;
                    });
                output.label = symbol == snapshot.symbols.end() ||
                               symbol->address != function.start ||
                               symbol->name.empty()
                    ? std::string_view("Function") : symbol->name;
                output.secondary = function.thunk ? "Thunk" : "Function";
                output.has_address = true;
                output.address = function.start.value;
                output.metric = function.block_count;
                break;
            }
            case navigator::navigator_domain_t::imports: {
                if (!image || ordinal >= image->imports.size())
                    return false;
                const auto& import = image->imports[
                    static_cast<std::size_t>(ordinal)];
                output.id = navigator_row_identity(
                    domain, import.address.value != 0
                        ? import.address.value : ordinal + 1U);
                output.label = import.name && !import.name->empty()
                    ? std::string_view(*import.name)
                    : std::string_view("Ordinal import");
                output.secondary = import.library;
                output.detail = import.delayed ? "Delay import" : "Import";
                output.has_address = import.address.value != 0;
                output.address = import.address.value;
                break;
            }
            case navigator::navigator_domain_t::exports: {
                if (!image || ordinal >= image->exports.size())
                    return false;
                const auto& exported = image->exports[
                    static_cast<std::size_t>(ordinal)];
                output.id = navigator_row_identity(
                    domain, exported.address.value != 0
                        ? exported.address.value : exported.ordinal + 1U);
                output.label = exported.name && !exported.name->empty()
                    ? std::string_view(*exported.name)
                    : std::string_view("Ordinal export");
                output.secondary = exported.forwarder
                    ? std::string_view(*exported.forwarder)
                    : std::string_view("Export");
                output.has_address = exported.address.value != 0;
                output.address = exported.address.value;
                output.metric = exported.ordinal;
                break;
            }
            case navigator::navigator_domain_t::strings: {
                if (ordinal >= snapshot.strings.size())
                    return false;
                const auto& value = snapshot.strings[
                    static_cast<std::size_t>(ordinal)];
                output.id = navigator_row_identity(
                    domain, value.id != 0 ? value.id : value.address.value);
                output.label = value.value.empty()
                    ? std::string_view("Empty string") : value.value;
                output.secondary = "String";
                output.has_address = true;
                output.address = value.address.value;
                output.metric = value.byte_length;
                break;
            }
            case navigator::navigator_domain_t::symbols: {
                if (ordinal >= snapshot.symbols.size())
                    return false;
                const auto& symbol = snapshot.symbols[
                    static_cast<std::size_t>(ordinal)];
                output.id = navigator_row_identity(
                    domain, symbol.id != 0 ? symbol.id : symbol.address.value);
                output.label = symbol.name.empty()
                    ? std::string_view("Unnamed symbol") : symbol.name;
                output.secondary = "Symbol";
                output.has_address = true;
                output.address = symbol.address.value;
                output.metric = symbol.confidence;
                break;
            }
            case navigator::navigator_domain_t::types: {
                if (ordinal >= snapshot.rich_facts.type_candidates.size())
                    return false;
                const auto& type = snapshot.rich_facts.type_candidates[
                    static_cast<std::size_t>(ordinal)];
                output.id = navigator_row_identity(
                    domain, type.id != 0 ? type.id : ordinal + 1U);
                output.label = type.display_name.empty()
                    ? std::string_view("Unnamed type") : type.display_name;
                output.secondary = type.canonical_type;
                output.detail = type.source_key;
                output.has_address = type.address.has_value();
                output.address = type.address ? type.address->value : 0;
                output.metric = type.confidence;
                break;
            }
            case navigator::navigator_domain_t::diagnostics: {
                if (ordinal >= snapshot.rich_facts.metadata_conflicts.size())
                    return false;
                const auto& conflict = snapshot.rich_facts.metadata_conflicts[
                    static_cast<std::size_t>(ordinal)];
                output.id = navigator_row_identity(
                    domain, conflict.id != 0 ? conflict.id : ordinal + 1U);
                output.label = conflict.identity.empty()
                    ? std::string_view("Metadata conflict") : conflict.identity;
                output.secondary = conflict.selected_value;
                output.detail = conflict.rejected_value;
                output.has_address = conflict.address.has_value();
                output.address = conflict.address ? conflict.address->value : 0;
                output.metric = conflict.selected_confidence;
                output.severity = navigator::navigator_severity_t::warning;
                break;
            }
            case navigator::navigator_domain_t::bookmarks: {
                const auto bookmarks = analysis_workspace_->view_state().bookmarks;
                if (ordinal >= bookmarks.size())
                    return false;
                const auto address = bookmarks[static_cast<std::size_t>(ordinal)];
                output.id = navigator_row_identity(domain, address.value);
                output.label = "Bookmark";
                output.secondary = "Workspace bookmark";
                output.has_address = true;
                output.address = address.value;
                break;
            }
            case navigator::navigator_domain_t::progress: {
                if (ordinal != 0)
                    return false;
                const auto progress = analysis_workspace_->progress();
                output.id = navigator_row_identity(domain, generation);
                output.label = "Analysis progress";
                output.secondary = "Workspace analysis state";
                output.metric = progress.completed_units;
                output.selectable = false;
                output.severity = progress.error
                    ? navigator::navigator_severity_t::error
                    : navigator::navigator_severity_t::information;
                break;
            }
            case navigator::navigator_domain_t::invalid:
                return false;
            }
            return output.id.valid() && !output.label.empty() &&
                   generation_current(generation);
        } catch (...) {
            output = {};
            return false;
        }
    }

    std::uint64_t tree_child_count(
        navigator::navigator_domain_t domain, std::uint64_t generation,
        navigator::navigator_row_id_t parent) const noexcept override
    {
        return parent.valid() ? 0 : record_count(domain, generation);
    }

    bool tree_child_at(navigator::navigator_domain_t domain,
                       std::uint64_t generation,
                       navigator::navigator_row_id_t parent,
                       std::uint64_t ordinal,
                       navigator::navigator_item_view_t& output) const noexcept override
    {
        if (parent.valid()) {
            output = {};
            return false;
        }
        return record_at(domain, generation, ordinal, output);
    }

    bool navigation_document(
        navigator::navigator_domain_t domain, std::uint64_t generation,
        navigator::navigator_row_id_t id, std::uint64_t address,
        document_identity_t& output) const override
    {
        output = {};
        if (!generation_current(generation) || !id.valid() || address == 0 ||
            domain == navigator::navigator_domain_t::binaries ||
            domain == navigator::navigator_domain_t::progress ||
            domain == navigator::navigator_domain_t::invalid)
            return false;
        output.workspace = workspace_;
        output.kind = document_kind_t::disassembly;
        output.object_id = 1;
        output.provider_key = "analysis";
        output.has_address = true;
        output.address = address;
        return true;
    }

    bool overlay_snapshot(std::uint64_t generation,
                          std::uint64_t revision,
                          analysis::overlay_snapshot_t& output) const
    {
        capture_current();
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = std::find_if(
            overlays_.begin(), overlays_.end(),
            [generation, revision](const retained_overlay_t& retained) {
                return retained.generation == generation &&
                       retained.snapshot.revision == revision;
            });
        if (found == overlays_.end())
            return false;
        output = found->snapshot;
        return true;
    }

    bool current_overlay_snapshot(std::uint64_t generation,
                                  analysis::overlay_snapshot_t& output) const
    {
        if (!capture_current())
            return false;
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto iterator = overlays_.rbegin(); iterator != overlays_.rend();
             ++iterator) {
            if (iterator->generation == generation) {
                output = iterator->snapshot;
                return true;
            }
        }
        return false;
    }

    std::uint64_t current_overlay_revision(std::uint64_t generation) const noexcept
    {
        try {
            analysis::overlay_snapshot_t snapshot;
            return current_overlay_snapshot(generation, snapshot)
                ? snapshot.revision : 0;
        } catch (...) {
            return 0;
        }
    }

    workbench_error_t transact_overlay(
        std::uint64_t generation,
        analysis::overlay_operation_t operation)
    {
        const auto current = current_publication();
        if (!current || current->generation != generation ||
            !publication_current(current))
            return shell_error(workbench_error_code_t::revision_mismatch,
                               generation);
        auto overlay = analysis_workspace_->overlay();
        if (!overlay)
            return shell_error(workbench_error_code_t::adapter_rejected,
                               generation);
        analysis::overlay_snapshot_t snapshot;
        if (!current_overlay_snapshot(generation, snapshot))
            return shell_error(workbench_error_code_t::adapter_rejected,
                               generation);
        analysis::overlay_transaction_request_t request;
        request.operations.push_back(std::move(operation));
        request.expected_revision = snapshot.revision;
        const auto result = overlay->transact(
            request, analysis_workspace_->cancellation_token());
        if (!result || !result.value().committed)
            return shell_error(workbench_error_code_t::adapter_rejected,
                               snapshot.revision);
        if (!capture_current())
            return shell_error(workbench_error_code_t::adapter_rejected,
                               result.value().revision);
        return {};
    }

    bool map_to_provider_offset(
        const analysis::analysis_publication_t& publication,
        const analysis::address_t& address,
        std::uint64_t size,
        std::uint64_t& output) const noexcept
    {
        output = 0;
        if (!analysis_workspace_ || size == 0)
            return false;
        const auto provider_size = analysis_workspace_->provider().size();
        if (address.space == analysis::address_space_id_t::file_offset) {
            if (address.value > provider_size || size > provider_size - address.value)
                return false;
            output = address.value;
            return true;
        }

        const auto image = publication.snapshot->normalized_image;
        if (!image)
            return false;
        analysis::address_t normalized = address;
        if (normalized.space == analysis::address_space_id_t::virtual_address ||
            normalized.space == analysis::address_space_id_t::live_virtual) {
            if (normalized.value < image->image_base)
                return false;
            normalized.value -= image->image_base;
            normalized.space = analysis::address_space_id_t::relative_virtual;
        }
        for (const auto& mapping : image->address_mappings) {
            if (mapping.source_space != analysis::address_space_id_t::file_offset ||
                mapping.target_space != normalized.space ||
                normalized.value < mapping.target_start)
                continue;
            const auto delta = normalized.value - mapping.target_start;
            if (delta > mapping.size || size > mapping.size - delta)
                continue;
            std::uint64_t offset = 0;
            if (!checked_add(mapping.source_start, delta, offset) ||
                offset > provider_size || size > provider_size - offset)
                continue;
            output = offset;
            return true;
        }
        return false;
    }

    bool read_bytes(const analysis::analysis_publication_t& publication,
                    const analysis::address_t& address,
                    std::uint64_t size,
                    std::uint64_t hard_limit,
                    std::vector<std::uint8_t>& output) const
    {
        output.clear();
        if (size == 0 || size > hard_limit)
            return false;
        std::uint64_t offset = 0;
        if (!map_to_provider_offset(publication, address, size, offset))
            return false;
        const auto result = analysis_workspace_->provider().read_vector(
            offset, size, hard_limit, analysis_workspace_->cancellation_token());
        if (!result)
            return false;
        output = result.value();
        return output.size() == size;
    }

    workspace_id_t workspace() const noexcept { return workspace_; }

    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace() const noexcept
    {
        return analysis_workspace_;
    }

private:
    static navigator::navigator_row_id_t navigator_row_identity(
        navigator::navigator_domain_t domain, std::uint64_t value) noexcept
    {
        std::uint64_t hash = k_shell_fnv_offset;
        hash ^= static_cast<std::uint8_t>(domain);
        hash *= k_shell_fnv_prime;
        for (std::uint32_t shift = 0; shift != 64U; shift += 8U) {
            hash ^= static_cast<std::uint8_t>(value >> shift);
            hash *= k_shell_fnv_prime;
        }
        return {hash == 0 ? 1 : hash};
    }

    static bool same_publication(
        const std::shared_ptr<const analysis::analysis_publication_t>& lhs,
        const std::shared_ptr<const analysis::analysis_publication_t>& rhs)
    {
        return lhs && rhs && lhs == rhs;
    }

    std::uint64_t current_generation_locked() const noexcept
    {
        if (!analysis_workspace_)
            return 0;
        const auto publication = analysis_workspace_->analysis_publication();
        return publication ? publication->generation : 0;
    }

    workspace_id_t workspace_;
    std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace_;
    std::size_t generation_limit_;
    std::size_t overlay_limit_;
    mutable std::mutex mutex_;
    mutable std::deque<std::shared_ptr<const analysis::analysis_publication_t>>
        publications_;
    mutable std::deque<retained_overlay_t> overlays_;
};

struct analysis_document_lease_t final {
    std::shared_ptr<workbench_analysis_source_t> source;
    std::shared_ptr<const analysis::analysis_publication_t> publication;

    bool valid() const noexcept
    {
        return source && publication && publication->snapshot &&
               publication->generation != 0;
    }

    bool current(std::uint64_t generation) const
    {
        return valid() && generation == publication->generation &&
               source->publication_current(publication);
    }
};

std::string render_operand(const analysis::operand_fact_t& operand)
{
    switch (operand.kind) {
    case analysis::operand_kind_t::reg:
        return "r" + std::to_string(operand.reg);
    case analysis::operand_kind_t::immediate:
        return hexadecimal(operand.immediate);
    case analysis::operand_kind_t::pointer:
        return hexadecimal(operand.has_resolved_expression_value
            ? operand.resolved_expression_value : operand.immediate);
    case analysis::operand_kind_t::memory: {
        std::string value = "[";
        if (operand.base_reg != 0)
            value += "r" + std::to_string(operand.base_reg);
        if (operand.index_reg != 0) {
            if (value.size() != 1)
                value.push_back('+');
            value += "r" + std::to_string(operand.index_reg);
            if (operand.scale > 1)
                value += "*" + std::to_string(operand.scale);
        }
        if (operand.has_displacement) {
            if (operand.displacement >= 0 && value.size() != 1)
                value.push_back('+');
            value += std::to_string(operand.displacement);
        }
        value.push_back(']');
        return value;
    }
    case analysis::operand_kind_t::none:
        return {};
    }
    return {};
}

class production_disasm_source_t final
    : public disasm_document::disasm_source_adapter_t {
public:
    explicit production_disasm_source_t(analysis_document_lease_t lease)
        : lease_(std::move(lease))
    {
    }

    std::uint64_t current_generation() const noexcept override
    {
        return lease_.publication ? lease_.publication->generation : 0;
    }

    bool generation_current(std::uint64_t generation) const noexcept override
    {
        try {
            return lease_.current(generation);
        } catch (...) {
            return false;
        }
    }

    std::uint64_t total_rows(std::uint64_t generation) const noexcept override
    {
        if (!generation_current(generation))
            return 0;
        return lease_.publication->snapshot->instructions.size();
    }

    bool row_at(std::uint64_t generation, std::uint64_t ordinal,
                disasm_document::disasm_instruction_view_t& output) const override
    {
        output = {};
        try {
            if (!generation_current(generation) ||
                ordinal >= lease_.publication->snapshot->instructions.size())
                return false;
            const auto& snapshot = *lease_.publication->snapshot;
            const auto& instruction =
                snapshot.instructions[static_cast<std::size_t>(ordinal)];
            if (instruction.length == 0)
                return false;
            output.id = {ordinal + 1U};
            output.address = instruction.address.value;
            output.byte_size = instruction.length;
            output.mnemonic = "mnemonic_" +
                              std::to_string(instruction.mnemonic_id);

            const auto operand_begin = instruction.operand_fact_begin;
            const auto operand_count = instruction.operand_fact_count;
            if (operand_begin > snapshot.operand_facts.size() ||
                operand_count > snapshot.operand_facts.size() - operand_begin)
                return false;
            for (std::uint32_t index = 0; index < operand_count; ++index) {
                const auto text = render_operand(
                    snapshot.operand_facts[operand_begin + index]);
                if (text.empty())
                    continue;
                if (!output.operands.empty())
                    output.operands += ", ";
                output.operands += text;
            }

            const auto target_begin = instruction.target_fact_begin;
            const auto target_count = instruction.target_fact_count;
            if (target_begin > snapshot.target_facts.size() ||
                target_count > snapshot.target_facts.size() - target_begin)
                return false;
            for (std::uint32_t index = 0; index < target_count; ++index) {
                const auto& target = snapshot.target_facts[target_begin + index];
                if (target.kind == analysis::target_kind_record_t::call &&
                    !output.has_call_target) {
                    output.has_call_target = true;
                    output.call_target = target.target.value;
                } else if (target.kind == analysis::target_kind_record_t::branch &&
                           !output.has_branch_target) {
                    output.has_branch_target = true;
                    output.branch_target = target.target.value;
                }
            }

            std::vector<std::uint8_t> bytes;
            if (lease_.source->read_bytes(*lease_.publication,
                                          instruction.address,
                                          instruction.length,
                                          disasm_document::k_disasm_document_max_raw_bytes,
                                          bytes))
                output.raw_hex = hexadecimal_bytes(bytes);
            return generation_current(generation);
        } catch (...) {
            output = {};
            return false;
        }
    }

    bool row_by_address(std::uint64_t generation, std::uint64_t address,
                        disasm_document::disasm_instruction_view_t& output,
                        std::uint64_t& ordinal) const override
    {
        output = {};
        ordinal = 0;
        try {
            if (!generation_current(generation))
                return false;
            const auto& instructions =
                lease_.publication->snapshot->instructions;
            const auto upper = std::upper_bound(
                instructions.begin(), instructions.end(), address,
                [](std::uint64_t value,
                   const analysis::instruction_record_t& instruction) {
                    return value < instruction.address.value;
                });
            if (upper == instructions.begin())
                return false;
            const auto candidate = upper - 1;
            if (candidate->length == 0 || address < candidate->address.value ||
                address - candidate->address.value >= candidate->length)
                return false;
            ordinal = static_cast<std::uint64_t>(
                candidate - instructions.begin());
            return row_at(generation, ordinal, output);
        } catch (...) {
            output = {};
            ordinal = 0;
            return false;
        }
    }

    std::uint64_t overlay_revision(std::uint64_t generation) const noexcept override
    {
        return generation_current(generation)
            ? lease_.source->current_overlay_revision(generation) : 0;
    }

    bool typed_address(std::uint64_t generation,
                       std::uint64_t address,
                       analysis::address_t& output) const
    {
        disasm_document::disasm_instruction_view_t row;
        std::uint64_t ordinal = 0;
        if (!row_by_address(generation, address, row, ordinal))
            return false;
        output = lease_.publication->snapshot->instructions[
            static_cast<std::size_t>(ordinal)].address;
        output.value = address;
        return true;
    }

    const analysis_document_lease_t& lease() const noexcept { return lease_; }

private:
    analysis_document_lease_t lease_;
};

bool project_disasm_overlay(
    const analysis::overlay_operation_t& operation,
    std::uint64_t revision,
    disasm_document::disasm_overlay_entry_t& output)
{
    output = {};
    output.revision = revision;
    output.address = operation.address.value;
    output.active = !operation.remove;
    switch (operation.kind) {
    case analysis::overlay_operation_kind_t::comment:
    case analysis::overlay_operation_kind_t::comment_update:
        output.kind = disasm_document::disasm_overlay_kind_t::comment;
        output.text = operation.text;
        break;
    case analysis::overlay_operation_kind_t::name:
        output.kind = disasm_document::disasm_overlay_kind_t::function_name;
        output.text = operation.name;
        break;
    case analysis::overlay_operation_kind_t::bookmark:
        output.kind = disasm_document::disasm_overlay_kind_t::label;
        output.text = operation.name;
        break;
    case analysis::overlay_operation_kind_t::type_application:
    case analysis::overlay_operation_kind_t::type_update:
    case analysis::overlay_operation_kind_t::type_declaration:
        output.kind = disasm_document::disasm_overlay_kind_t::type_override;
        output.text = operation.type.empty() ? operation.name : operation.type;
        break;
    case analysis::overlay_operation_kind_t::byte_patch:
    case analysis::overlay_operation_kind_t::assembly_patch:
    case analysis::overlay_operation_kind_t::integer_patch:
        output.kind = disasm_document::disasm_overlay_kind_t::patch;
        output.text = !operation.bytes.empty()
            ? hexadecimal_bytes(operation.bytes)
            : (!operation.assembly.empty() ? operation.assembly
                                           : operation.integer_value);
        break;
    default:
        return false;
    }
    return disasm_document::disasm_overlay_entry_valid(output);
}

class production_disasm_overlay_t final
    : public disasm_document::disasm_overlay_adapter_t {
public:
    production_disasm_overlay_t(
        std::shared_ptr<workbench_analysis_source_t> source,
        production_disasm_source_t& rows)
        : source_(std::move(source)), rows_(&rows)
    {
    }

    std::uint32_t overlay_count(std::uint64_t generation) const noexcept override
    {
        try {
            return static_cast<std::uint32_t>((std::min)(
                entries(generation).size(),
                static_cast<std::size_t>(
                        (std::numeric_limits<std::uint32_t>::max)())));
        } catch (...) {
            return disasm_document::k_disasm_document_max_overlays + 1U;
        }
    }

    bool overlay_at(std::uint64_t generation, std::uint32_t ordinal,
                    disasm_document::disasm_overlay_entry_t& output) const override
    {
        output = {};
        const auto projected = entries(generation);
        if (ordinal >= projected.size())
            return false;
        output = projected[static_cast<std::size_t>(ordinal)];
        return true;
    }

    bool overlay_by_address(
        std::uint64_t generation,
        std::uint64_t address,
        disasm_document::disasm_overlay_entry_t& output) const override
    {
        output = {};
        const auto projected = entries(generation);
        const auto found = std::find_if(
            projected.rbegin(), projected.rend(),
            [address](const auto& entry) {
                return entry.address == address && entry.active;
            });
        if (found == projected.rend())
            return false;
        output = *found;
        return true;
    }

    workbench_error_t apply_overlay(
        std::uint64_t generation,
        const disasm_document::disasm_overlay_entry_t& entry) const override
    {
        if (!rows_->generation_current(generation))
            return shell_error(workbench_error_code_t::revision_mismatch,
                               generation);
        if (!entry.active)
            return remove_overlay(generation, entry.address);
        analysis::overlay_operation_t operation;
        if (!rows_->typed_address(generation, entry.address, operation.address))
            return shell_error(workbench_error_code_t::invalid_navigation,
                               entry.address);
        switch (entry.kind) {
        case disasm_document::disasm_overlay_kind_t::user_annotation:
        case disasm_document::disasm_overlay_kind_t::comment:
            operation.kind = analysis::overlay_operation_kind_t::comment_update;
            operation.text = entry.text;
            break;
        case disasm_document::disasm_overlay_kind_t::function_name:
            operation.kind = analysis::overlay_operation_kind_t::name;
            operation.name = entry.text;
            break;
        case disasm_document::disasm_overlay_kind_t::label:
            operation.kind = analysis::overlay_operation_kind_t::bookmark;
            operation.name = entry.text;
            break;
        case disasm_document::disasm_overlay_kind_t::type_override:
            operation.kind = analysis::overlay_operation_kind_t::type_application;
            operation.type = entry.text;
            operation.variable = "address";
            break;
        case disasm_document::disasm_overlay_kind_t::patch:
            return shell_error(workbench_error_code_t::invalid_document_state,
                               entry.address);
        }
        return source_->transact_overlay(generation, std::move(operation));
    }

    workbench_error_t remove_overlay(std::uint64_t generation,
                                     std::uint64_t address) const override
    {
        analysis::overlay_snapshot_t snapshot;
        if (!source_->current_overlay_snapshot(generation, snapshot))
            return shell_error(workbench_error_code_t::adapter_rejected,
                               generation);
        for (auto iterator = snapshot.items.rbegin();
             iterator != snapshot.items.rend(); ++iterator) {
            disasm_document::disasm_overlay_entry_t projected;
            if (!project_disasm_overlay(iterator->second, snapshot.revision,
                                        projected) ||
                projected.address != address || !projected.active)
                continue;
            auto operation = iterator->second;
            operation.remove = true;
            return source_->transact_overlay(generation,
                                             std::move(operation));
        }
        return shell_error(workbench_error_code_t::invalid_document, address);
    }

private:
    std::vector<disasm_document::disasm_overlay_entry_t> entries(
        std::uint64_t generation) const
    {
        std::vector<disasm_document::disasm_overlay_entry_t> output;
        if (!rows_->generation_current(generation))
            return output;
        analysis::overlay_snapshot_t snapshot;
        if (!source_->current_overlay_snapshot(generation, snapshot))
            return output;
        output.reserve((std::min)(snapshot.items.size(),
            static_cast<std::size_t>(
                disasm_document::k_disasm_document_max_overlays + 1U)));
        for (const auto& item : snapshot.items) {
            disasm_document::disasm_overlay_entry_t projected;
            if (project_disasm_overlay(item.second, snapshot.revision,
                                       projected)) {
                output.push_back(std::move(projected));
                if (output.size() >
                    disasm_document::k_disasm_document_max_overlays)
                    break;
            }
        }
        return output;
    }

    std::shared_ptr<workbench_analysis_source_t> source_;
    production_disasm_source_t* rows_;
};

struct hex_span_t final {
    analysis::address_space_id_t address_space =
        analysis::address_space_id_t::relative_virtual;
    std::uint64_t address = 0;
    std::uint64_t provider_offset = 0;
    std::uint64_t size = 0;
    std::uint64_t row_begin = 0;
    std::uint64_t row_count = 0;
};

class production_hex_source_t final
    : public hex_document::hex_source_adapter_t {
public:
    explicit production_hex_source_t(analysis_document_lease_t lease)
        : lease_(std::move(lease))
    {
        rebuild_spans();
    }

    std::uint64_t current_generation() const noexcept override
    {
        return lease_.publication ? lease_.publication->generation : 0;
    }

    bool generation_current(std::uint64_t generation) const noexcept override
    {
        try {
            return lease_.current(generation);
        } catch (...) {
            return false;
        }
    }

    std::uint64_t total_rows(std::uint64_t generation) const noexcept override
    {
        if (!generation_current(generation))
            return 0;
        return valid_ ? total_rows_
                      : hex_document::k_hex_document_max_total_rows + 1U;
    }

    bool row_at(std::uint64_t generation, std::uint64_t ordinal,
                hex_document::hex_row_view_t& output) const override
    {
        output = {};
        try {
            if (!valid_ || !generation_current(generation) ||
                ordinal >= total_rows_)
                return false;
            const auto span = std::find_if(
                spans_.begin(), spans_.end(),
                [ordinal](const hex_span_t& candidate) {
                    return ordinal >= candidate.row_begin &&
                           ordinal - candidate.row_begin < candidate.row_count;
                });
            if (span == spans_.end())
                return false;
            const auto local_row = ordinal - span->row_begin;
            const auto local_offset =
                local_row * hex_document::k_hex_document_bytes_per_row;
            const auto byte_count = static_cast<std::uint32_t>((std::min)(
                span->size - local_offset,
                static_cast<std::uint64_t>(
                    hex_document::k_hex_document_bytes_per_row)));
            analysis::address_t address;
            address.space = span->address_space;
            address.value = span->address + local_offset;
            const auto image = lease_.publication->snapshot->normalized_image;
            if (image) {
                address.architecture = image->architecture;
                address.mode = image->architecture_mode;
            }
            if (!lease_.source->read_bytes(*lease_.publication, address,
                                           byte_count,
                                           hex_document::k_hex_document_bytes_per_row,
                                           output.bytes))
                return false;
            output.id = {ordinal + 1U};
            output.address = address.value;
            output.byte_count = byte_count;
            output.hex_text = hexadecimal_bytes(output.bytes);
            output.ascii_text.reserve(output.bytes.size());
            for (const auto byte : output.bytes)
                output.ascii_text.push_back(byte >= 0x20U && byte <= 0x7EU
                    ? static_cast<char>(byte) : '.');
            return generation_current(generation);
        } catch (...) {
            output = {};
            return false;
        }
    }

    bool row_by_address(std::uint64_t generation, std::uint64_t address,
                        hex_document::hex_row_view_t& output,
                        std::uint64_t& ordinal) const override
    {
        output = {};
        ordinal = 0;
        if (!valid_ || !generation_current(generation))
            return false;
        const auto span = std::find_if(
            spans_.begin(), spans_.end(),
            [address](const hex_span_t& candidate) {
                return address >= candidate.address &&
                       address - candidate.address < candidate.size;
            });
        if (span == spans_.end())
            return false;
        const auto local_row = (address - span->address) /
            hex_document::k_hex_document_bytes_per_row;
        ordinal = span->row_begin + local_row;
        return row_at(generation, ordinal, output);
    }

    std::uint64_t overlay_revision(std::uint64_t generation) const noexcept override
    {
        return generation_current(generation)
            ? lease_.source->current_overlay_revision(generation) : 0;
    }

    bool typed_address(std::uint64_t generation,
                       std::uint64_t address,
                       analysis::address_t& output) const noexcept
    {
        if (!generation_current(generation))
            return false;
        const auto span = std::find_if(
            spans_.begin(), spans_.end(),
            [address](const hex_span_t& candidate) {
                return address >= candidate.address &&
                       address - candidate.address < candidate.size;
            });
        if (span == spans_.end())
            return false;
        output = {};
        output.space = span->address_space;
        output.value = address;
        const auto image = lease_.publication->snapshot->normalized_image;
        if (image) {
            output.architecture = image->architecture;
            output.mode = image->architecture_mode;
        }
        return true;
    }

private:
    void rebuild_spans()
    {
        valid_ = lease_.valid();
        if (!valid_)
            return;
        const auto provider_size =
            lease_.source->analysis_workspace()->provider().size();
        const auto image = lease_.publication->snapshot->normalized_image;
        if (image) {
            for (const auto& mapping : image->address_mappings) {
                if (mapping.source_space !=
                        analysis::address_space_id_t::file_offset ||
                    mapping.target_space !=
                        analysis::address_space_id_t::relative_virtual ||
                    mapping.size == 0 || mapping.source_start > provider_size ||
                    mapping.size > provider_size - mapping.source_start)
                    continue;
                hex_span_t span;
                span.address_space = mapping.target_space;
                span.address = mapping.target_start;
                span.provider_offset = mapping.source_start;
                span.size = mapping.size;
                spans_.push_back(span);
            }
        }
        if (spans_.empty() && provider_size != 0) {
            hex_span_t span;
            span.address_space = analysis::address_space_id_t::file_offset;
            span.size = provider_size;
            spans_.push_back(span);
        }
        std::sort(spans_.begin(), spans_.end(),
            [](const hex_span_t& lhs, const hex_span_t& rhs) {
                return std::tie(lhs.address, lhs.provider_offset, lhs.size) <
                       std::tie(rhs.address, rhs.provider_offset, rhs.size);
            });
        std::vector<hex_span_t> normalized;
        normalized.reserve(spans_.size());
        for (const auto& span : spans_) {
            if (!normalized.empty()) {
                auto& previous = normalized.back();
                std::uint64_t previous_address_end = 0;
                std::uint64_t previous_provider_end = 0;
                if (!checked_add(previous.address, previous.size,
                                 previous_address_end) ||
                    !checked_add(previous.provider_offset, previous.size,
                                 previous_provider_end)) {
                    valid_ = false;
                    return;
                }
                if (span.address < previous_address_end) {
                    valid_ = false;
                    return;
                }
                if (span.address == previous_address_end &&
                    span.provider_offset == previous_provider_end &&
                    span.address_space == previous.address_space) {
                    if (!checked_add(previous.size, span.size, previous.size)) {
                        valid_ = false;
                        return;
                    }
                    continue;
                }
            }
            normalized.push_back(span);
        }
        spans_ = std::move(normalized);
        for (auto& span : spans_) {
            span.row_begin = total_rows_;
            span.row_count = span.size /
                hex_document::k_hex_document_bytes_per_row;
            if (span.size % hex_document::k_hex_document_bytes_per_row != 0)
                ++span.row_count;
            if (!checked_add(total_rows_, span.row_count, total_rows_)) {
                valid_ = false;
                return;
            }
        }
    }

    analysis_document_lease_t lease_;
    std::vector<hex_span_t> spans_;
    std::uint64_t total_rows_ = 0;
    bool valid_ = false;
};

bool project_hex_overlay(const analysis::overlay_operation_t& operation,
                         std::uint64_t revision,
                         hex_document::hex_overlay_entry_t& output)
{
    output = {};
    output.revision = revision;
    output.address = operation.address.value;
    output.active = !operation.remove;
    switch (operation.kind) {
    case analysis::overlay_operation_kind_t::byte_patch:
    case analysis::overlay_operation_kind_t::assembly_patch:
    case analysis::overlay_operation_kind_t::integer_patch:
        if (operation.bytes.empty())
            return false;
        output.kind = hex_document::hex_overlay_kind_t::patch;
        output.patch_bytes = operation.bytes;
        output.extent = operation.bytes.size();
        break;
    case analysis::overlay_operation_kind_t::comment:
    case analysis::overlay_operation_kind_t::comment_update:
        output.kind = hex_document::hex_overlay_kind_t::annotation;
        output.text = operation.text;
        output.extent = operation.end
            ? operation.end->value - operation.address.value : 1U;
        break;
    case analysis::overlay_operation_kind_t::bookmark:
        output.kind = hex_document::hex_overlay_kind_t::highlight;
        output.text = operation.name;
        output.extent = operation.end
            ? operation.end->value - operation.address.value : 1U;
        break;
    default:
        return false;
    }
    return hex_document::hex_overlay_entry_valid(output);
}

class production_hex_overlay_t final
    : public hex_document::hex_overlay_adapter_t {
public:
    production_hex_overlay_t(
        std::shared_ptr<workbench_analysis_source_t> source,
        production_hex_source_t& rows)
        : source_(std::move(source)), rows_(&rows)
    {
    }

    std::uint32_t overlay_count(std::uint64_t generation) const noexcept override
    {
        try {
            return static_cast<std::uint32_t>((std::min)(
                entries(generation).size(),
                static_cast<std::size_t>(
                        (std::numeric_limits<std::uint32_t>::max)())));
        } catch (...) {
            return hex_document::k_hex_document_max_overlays + 1U;
        }
    }

    bool overlay_at(std::uint64_t generation, std::uint32_t ordinal,
                    hex_document::hex_overlay_entry_t& output) const override
    {
        output = {};
        const auto projected = entries(generation);
        if (ordinal >= projected.size())
            return false;
        output = projected[static_cast<std::size_t>(ordinal)];
        return true;
    }

    bool overlay_by_address(std::uint64_t generation, std::uint64_t address,
                            hex_document::hex_overlay_entry_t& output) const override
    {
        output = {};
        const auto projected = entries(generation);
        const auto found = std::find_if(
            projected.rbegin(), projected.rend(),
            [address](const auto& entry) {
                return entry.address == address && entry.active;
            });
        if (found == projected.rend())
            return false;
        output = *found;
        return true;
    }

    workbench_error_t apply_overlay(
        std::uint64_t generation,
        const hex_document::hex_overlay_entry_t& entry) const override
    {
        if (!rows_->generation_current(generation))
            return shell_error(workbench_error_code_t::revision_mismatch,
                               generation);
        if (!entry.active)
            return remove_overlay(generation, entry.address);
        analysis::overlay_operation_t operation;
        if (!rows_->typed_address(generation, entry.address, operation.address))
            return shell_error(workbench_error_code_t::invalid_navigation,
                               entry.address);
        analysis::address_t end = operation.address;
        if (!checked_add(end.value, entry.extent, end.value))
            return shell_error(workbench_error_code_t::invalid_document_state,
                               entry.address);
        operation.end = end;
        switch (entry.kind) {
        case hex_document::hex_overlay_kind_t::patch:
            operation.kind = analysis::overlay_operation_kind_t::byte_patch;
            operation.bytes = entry.patch_bytes;
            break;
        case hex_document::hex_overlay_kind_t::annotation:
            operation.kind = analysis::overlay_operation_kind_t::comment_update;
            operation.text = entry.text;
            break;
        case hex_document::hex_overlay_kind_t::highlight:
            operation.kind = analysis::overlay_operation_kind_t::bookmark;
            operation.name = entry.text;
            break;
        }
        return source_->transact_overlay(generation, std::move(operation));
    }

    workbench_error_t remove_overlay(std::uint64_t generation,
                                     std::uint64_t address) const override
    {
        analysis::overlay_snapshot_t snapshot;
        if (!source_->current_overlay_snapshot(generation, snapshot))
            return shell_error(workbench_error_code_t::adapter_rejected,
                               generation);
        for (auto iterator = snapshot.items.rbegin();
             iterator != snapshot.items.rend(); ++iterator) {
            hex_document::hex_overlay_entry_t projected;
            if (!project_hex_overlay(iterator->second, snapshot.revision,
                                     projected) ||
                projected.address != address || !projected.active)
                continue;
            auto operation = iterator->second;
            operation.remove = true;
            return source_->transact_overlay(generation,
                                             std::move(operation));
        }
        return shell_error(workbench_error_code_t::invalid_document, address);
    }

private:
    std::vector<hex_document::hex_overlay_entry_t> entries(
        std::uint64_t generation) const
    {
        std::vector<hex_document::hex_overlay_entry_t> output;
        if (!rows_->generation_current(generation))
            return output;
        analysis::overlay_snapshot_t snapshot;
        if (!source_->current_overlay_snapshot(generation, snapshot))
            return output;
        output.reserve((std::min)(snapshot.items.size(),
            static_cast<std::size_t>(
                hex_document::k_hex_document_max_overlays + 1U)));
        for (const auto& item : snapshot.items) {
            hex_document::hex_overlay_entry_t projected;
            if (project_hex_overlay(item.second, snapshot.revision, projected)) {
                output.push_back(std::move(projected));
                if (output.size() >
                    hex_document::k_hex_document_max_overlays)
                    break;
            }
        }
        return output;
    }

    std::shared_ptr<workbench_analysis_source_t> source_;
    production_hex_source_t* rows_;
};

class production_disasm_navigation_t final
    : public disasm_document::disasm_navigation_adapter_t {
public:
    explicit production_disasm_navigation_t(
        std::shared_ptr<workbench_document_bridge_t> bridge)
        : bridge_(std::move(bridge))
    {
    }

    workbench_error_t resolve_cross_document(
        const disasm_document::disasm_cross_document_request_t& request,
        disasm_document::disasm_cross_document_result_t& output) const override
    {
        output = {};
        document_kind_t kind = document_kind_t::unknown;
        switch (request.target) {
        case disasm_document::disasm_cross_document_target_t::hex:
            kind = document_kind_t::hex;
            break;
        case disasm_document::disasm_cross_document_target_t::pseudocode:
            kind = document_kind_t::pseudocode;
            break;
        case disasm_document::disasm_cross_document_target_t::graph:
            kind = document_kind_t::graph;
            break;
        }
        navigation_resolution_t resolution;
        const auto error = bridge_->resolve_target(
            request.source_document, kind, request.address, resolution);
        if (!error)
            return error;
        output.resolved = true;
        output.target_document = std::move(resolution.document);
        output.target_selection = std::move(resolution.selection);
        output.target_cursor = resolution.cursor;
        return {};
    }

private:
    std::shared_ptr<workbench_document_bridge_t> bridge_;
};

class production_hex_navigation_t final
    : public hex_document::hex_navigation_adapter_t {
public:
    explicit production_hex_navigation_t(
        std::shared_ptr<workbench_document_bridge_t> bridge)
        : bridge_(std::move(bridge))
    {
    }

    workbench_error_t resolve_cross_document(
        const hex_document::hex_cross_document_request_t& request,
        hex_document::hex_cross_document_result_t& output) const override
    {
        output = {};
        document_kind_t kind = document_kind_t::unknown;
        switch (request.target) {
        case hex_document::hex_cross_document_target_t::disassembly:
            kind = document_kind_t::disassembly;
            break;
        case hex_document::hex_cross_document_target_t::pseudocode:
            kind = document_kind_t::pseudocode;
            break;
        case hex_document::hex_cross_document_target_t::graph:
            kind = document_kind_t::graph;
            break;
        }
        navigation_resolution_t resolution;
        const auto error = bridge_->resolve_target(
            request.source_document, kind, request.address, resolution);
        if (!error)
            return error;
        output.resolved = true;
        output.target_document = std::move(resolution.document);
        output.target_selection = std::move(resolution.selection);
        output.target_cursor = resolution.cursor;
        return {};
    }

private:
    std::shared_ptr<workbench_document_bridge_t> bridge_;
};

graph_document::graph_edge_kind_t graph_edge_kind(
    analysis::edge_kind_t kind) noexcept
{
    switch (kind) {
    case analysis::edge_kind_t::fallthrough:
        return graph_document::graph_edge_kind_t::unconditional;
    case analysis::edge_kind_t::conditional_taken:
        return graph_document::graph_edge_kind_t::conditional_true;
    case analysis::edge_kind_t::unconditional:
        return graph_document::graph_edge_kind_t::unconditional;
    case analysis::edge_kind_t::call:
    case analysis::edge_kind_t::tail_call:
        return graph_document::graph_edge_kind_t::call;
    case analysis::edge_kind_t::return_edge:
        return graph_document::graph_edge_kind_t::return_edge;
    case analysis::edge_kind_t::exception_edge:
        return graph_document::graph_edge_kind_t::switch_case;
    case analysis::edge_kind_t::indirect:
        return graph_document::graph_edge_kind_t::indirect_call;
    }
    return graph_document::graph_edge_kind_t::unconditional;
}

struct graph_node_range_t final {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    graph_document::graph_node_id_t node;
};

std::uint64_t graph_range_end(std::uint64_t begin,
                              std::uint64_t candidate) noexcept
{
    if (candidate > begin)
        return candidate;
    return begin == (std::numeric_limits<std::uint64_t>::max)()
        ? begin : begin + 1U;
}

struct graph_edge_candidate_t final {
    graph_document::graph_node_id_t source;
    graph_document::graph_node_id_t target;
    graph_document::graph_edge_kind_t kind =
        graph_document::graph_edge_kind_t::unconditional;
    std::uint64_t site_address = 0;
    std::uint64_t stable_source_id = 0;
    std::string label;
};

struct graph_materialization_t final {
    std::uint64_t generation = 0;
    graph_document::graph_kind_t kind = graph_document::graph_kind_t::cfg;
    std::uint64_t function_address = 0;
    std::uint64_t total_nodes = 0;
    std::uint64_t total_edges = 0;
    std::vector<graph_document::graph_node_view_t> nodes;
    std::vector<graph_document::graph_edge_view_t> edges;
    std::vector<graph_node_range_t> ranges;
};

bool sort_graph_ranges(
    std::vector<graph_node_range_t>& ranges,
    const graph_document::graph_cancellation_t* cancellation)
{
    return bounded_stable_sort(ranges,
        [](const graph_node_range_t& lhs, const graph_node_range_t& rhs) {
            return std::tie(lhs.begin, lhs.end, lhs.node.value) <
                   std::tie(rhs.begin, rhs.end, rhs.node.value);
        }, cancellation);
}

graph_document::graph_node_id_t graph_node_for_address(
    const std::vector<graph_node_range_t>& ranges,
    std::uint64_t address) noexcept
{
    auto range = std::upper_bound(
        ranges.begin(), ranges.end(), address,
        [](std::uint64_t candidate, const graph_node_range_t& item) {
            return candidate < item.begin;
        });
    if (range == ranges.begin())
        return {};
    --range;
    if (address < range->begin)
        return {};
    if (range->end > range->begin)
        return address < range->end ? range->node
                                    : graph_document::graph_node_id_t{};
    return address == range->begin ? range->node
                                   : graph_document::graph_node_id_t{};
}

graph_document::graph_node_id_t graph_node_identity(
    std::uint64_t entity_id,
    std::uint64_t address,
    std::string_view domain) noexcept
{
    std::uint64_t hash = k_shell_fnv_offset;
    const auto append = [&hash](std::uint8_t byte) {
        hash ^= byte;
        hash *= k_shell_fnv_prime;
    };
    for (const auto character : domain)
        append(static_cast<std::uint8_t>(character));
    append(static_cast<std::uint8_t>(0xFFU));
    append(static_cast<std::uint8_t>(entity_id != 0 ? 1U : 0U));
    auto identity = entity_id != 0 ? entity_id : address;
    for (std::size_t index = 0; index < sizeof(identity); ++index) {
        append(static_cast<std::uint8_t>(identity & 0xFFU));
        identity >>= 8U;
    }
    return {hash == 0 ? 1 : hash};
}

using graph_function_index_t =
    std::unordered_map<analysis::entity_id_t,
                       const analysis::function_record_t*>;
using graph_symbol_index_t =
    std::unordered_map<analysis::entity_id_t,
                       const analysis::symbol_record_t*>;

std::string function_label(const graph_function_index_t& functions,
                           const graph_symbol_index_t& symbols,
                           analysis::entity_id_t function_id,
                           std::uint64_t address)
{
    const auto function = functions.find(function_id);
    if (function != functions.end() && function->second->symbol_id) {
        const auto symbol = symbols.find(*function->second->symbol_id);
        if (symbol != symbols.end() && !symbol->second->name.empty())
            return symbol->second->name;
    }
    return "sub_" + hexadecimal(address);
}

graph_document::graph_source_result_t finalize_graph_edges(
    graph_materialization_t& output,
    std::vector<graph_edge_candidate_t> candidates,
    const graph_document::graph_source_limits_t& limits,
    const graph_document::graph_cancellation_t* cancellation)
{
    if (candidates.size() > limits.max_edges)
        return graph_document::graph_source_result_t::limit_exceeded;
    if (!bounded_stable_sort(candidates,
        [](const graph_edge_candidate_t& lhs,
           const graph_edge_candidate_t& rhs) {
            return std::tie(lhs.source.value, lhs.target.value, lhs.kind,
                            lhs.site_address, lhs.stable_source_id,
                            lhs.label) <
                   std::tie(rhs.source.value, rhs.target.value, rhs.kind,
                            rhs.site_address, rhs.stable_source_id,
                            rhs.label);
        }, cancellation))
        return graph_document::graph_source_result_t::cancelled;
    output.total_edges = candidates.size();
    if (output.total_edges > limits.max_edges)
        return graph_document::graph_source_result_t::limit_exceeded;

    std::map<std::uint64_t, std::size_t> node_indices;
    for (std::size_t index = 0; index < output.nodes.size(); ++index) {
        if (!output.nodes[index].id.valid() ||
            !node_indices.emplace(output.nodes[index].id.value, index).second) {
            output.total_edges =
                graph_document::k_graph_document_max_edges + 1U;
            output.edges.clear();
            return graph_document::graph_source_result_t::rejected;
        }
    }

    output.edges.reserve(candidates.size());
    std::unordered_set<std::uint64_t> edge_ids;
    edge_ids.reserve(candidates.size());
    std::tuple<std::uint64_t, std::uint64_t,
               graph_document::graph_edge_kind_t, std::uint64_t> previous{};
    bool have_previous = false;
    std::uint64_t parallel_ordinal = 0;
    for (auto& candidate : candidates) {
        if ((output.edges.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled()) {
            output.edges.clear();
            return graph_document::graph_source_result_t::cancelled;
        }
        const auto identity = std::make_tuple(
            candidate.source.value, candidate.target.value,
            candidate.kind, candidate.site_address);
        if (!have_previous || identity != previous) {
            parallel_ordinal = 0;
            previous = identity;
            have_previous = true;
        } else {
            ++parallel_ordinal;
        }
        graph_document::graph_edge_view_t edge;
        edge.source = candidate.source;
        edge.target = candidate.target;
        edge.kind = candidate.kind;
        edge.site_address = candidate.site_address;
        edge.parallel_ordinal = parallel_ordinal;
        edge.label = std::move(candidate.label);
        edge.id = graph_document::compute_deterministic_edge_id(
            {edge.source, edge.target, edge.kind, edge.site_address,
             edge.parallel_ordinal});
        if (!edge.id.valid() || !edge_ids.insert(edge.id.value).second) {
            for (auto& node : output.nodes) {
                node.in_degree = 0;
                node.out_degree = 0;
            }
            output.edges.clear();
            output.total_edges =
                graph_document::k_graph_document_max_edges + 1U;
            return graph_document::graph_source_result_t::rejected;
        }
        const auto source = node_indices.find(edge.source.value);
        const auto target = node_indices.find(edge.target.value);
        if (source == node_indices.end() || target == node_indices.end())
            continue;
        auto& out_degree = output.nodes[source->second].out_degree;
        auto& in_degree = output.nodes[target->second].in_degree;
        if (out_degree != (std::numeric_limits<std::uint32_t>::max)())
            ++out_degree;
        if (in_degree != (std::numeric_limits<std::uint32_t>::max)())
            ++in_degree;
        output.edges.push_back(std::move(edge));
    }
    output.total_edges = output.edges.size();
    return graph_document::graph_source_result_t::success;
}

graph_document::graph_source_result_t build_cfg_graph(
    const std::shared_ptr<const analysis::analysis_publication_t>& publication,
    std::uint64_t function_address,
    const graph_document::graph_source_limits_t& limits,
    const graph_document::graph_cancellation_t* cancellation,
    std::shared_ptr<graph_materialization_t>& output)
{
    output = std::make_shared<graph_materialization_t>();
    output->generation = publication->generation;
    output->kind = graph_document::graph_kind_t::cfg;
    output->function_address = function_address;
    const auto& snapshot = *publication->snapshot;

    std::vector<std::size_t> block_indices;
    if (function_address != 0) {
        const analysis::function_record_t* function = nullptr;
        std::size_t traversed_functions = 0;
        for (const auto& candidate : snapshot.functions) {
            if ((traversed_functions & 0xFFU) == 0U && cancellation &&
                cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            if (traversed_functions >= limits.max_nodes)
                return graph_document::graph_source_result_t::limit_exceeded;
            ++traversed_functions;
            if (function_address >= candidate.start.value &&
                function_address < candidate.end.value) {
                function = &candidate;
                break;
            }
        }
        if (!function) {
            return graph_document::graph_source_result_t::not_found;
        }
        if (function->block_membership_count != 0) {
            const auto first = static_cast<std::size_t>(
                function->first_block_membership);
            const auto count = static_cast<std::size_t>(
                function->block_membership_count);
            if (count > limits.max_nodes ||
                first > snapshot.function_block_memberships.size() ||
                count > snapshot.function_block_memberships.size() - first) {
                return count > limits.max_nodes
                    ? graph_document::graph_source_result_t::limit_exceeded
                    : graph_document::graph_source_result_t::rejected;
            }
            block_indices.reserve(count);
            std::unordered_set<analysis::entity_id_t> membership_ids;
            membership_ids.reserve(count);
            for (std::size_t offset = 0; offset < count; ++offset) {
                if ((offset & 0xFFU) == 0U && cancellation &&
                    cancellation->cancelled())
                    return graph_document::graph_source_result_t::cancelled;
                const auto& membership =
                    snapshot.function_block_memberships[first + offset];
                const auto block_index =
                    static_cast<std::size_t>(membership.block_index);
                if (membership.function_id != function->id ||
                    membership.ordinal != static_cast<std::uint32_t>(offset) ||
                    block_index >= snapshot.blocks.size() ||
                    snapshot.blocks[block_index].id != membership.block_id ||
                    !membership_ids.insert(membership.block_id).second) {
                    return graph_document::graph_source_result_t::rejected;
                }
                block_indices.push_back(block_index);
            }
        } else {
            const auto first = static_cast<std::size_t>(function->first_block);
            const auto count = static_cast<std::size_t>(function->block_count);
            if (count > limits.max_nodes ||
                first > snapshot.blocks.size() ||
                count > snapshot.blocks.size() - first) {
                return count > limits.max_nodes
                    ? graph_document::graph_source_result_t::limit_exceeded
                    : graph_document::graph_source_result_t::rejected;
            }
            block_indices.reserve(count);
            for (std::size_t offset = 0; offset < count; ++offset)
                block_indices.push_back(first + offset);
        }
    } else {
        if (snapshot.blocks.size() > limits.max_nodes) {
            output->total_nodes = snapshot.blocks.size();
            output->total_edges = snapshot.edges.size();
            return graph_document::graph_source_result_t::limit_exceeded;
        }
        block_indices.reserve(snapshot.blocks.size());
        for (std::size_t index = 0; index < snapshot.blocks.size(); ++index)
            block_indices.push_back(index);
    }

    if (!bounded_stable_sort(block_indices,
        [&snapshot](std::size_t lhs, std::size_t rhs) {
            const auto& left = snapshot.blocks[lhs];
            const auto& right = snapshot.blocks[rhs];
            return std::tie(left.start.value, left.end.value, left.id, lhs) <
                   std::tie(right.start.value, right.end.value, right.id, rhs);
        }, cancellation))
        return graph_document::graph_source_result_t::cancelled;

    std::unordered_map<analysis::entity_id_t,
                       graph_document::graph_node_id_t> block_nodes;
    std::unordered_set<std::uint64_t> stable_node_ids;
    stable_node_ids.reserve(block_indices.size());
    output->total_nodes = block_indices.size();
    for (const auto block_index : block_indices) {
        if ((output->nodes.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        const auto& block = snapshot.blocks[block_index];
        graph_document::graph_node_view_t node;
        node.id = graph_node_identity(block.id, block.start.value, "cfg");
        node.kind = graph_document::graph_node_kind_t::basic_block;
        node.address = block.start.value;
        node.label = "loc_" + hexadecimal(block.start.value);
        node.instruction_count = block.instruction_count;
        if (!stable_node_ids.insert(node.id.value).second) {
            output->total_nodes =
                graph_document::k_graph_document_max_nodes + 1U;
            output->nodes.clear();
            output->ranges.clear();
            output->total_edges = snapshot.edges.size();
            return graph_document::graph_source_result_t::rejected;
        }
        if (block.id != 0)
            block_nodes.emplace(block.id, node.id);
        output->nodes.push_back(std::move(node));
        graph_node_range_t range;
        range.begin = block.start.value;
        range.end = graph_range_end(block.start.value, block.end.value);
        range.node = output->nodes.back().id;
        output->ranges.push_back(range);
    }
    if (!sort_graph_ranges(output->ranges, cancellation))
        return graph_document::graph_source_result_t::cancelled;

    std::vector<graph_edge_candidate_t> edges;
    edges.reserve((std::min)(snapshot.edges.size(),
        static_cast<std::size_t>(limits.max_edges + 1U)));
    std::uint64_t traversed_edges = 0;
    for (const auto& source_edge : snapshot.edges) {
        ++traversed_edges;
        if ((traversed_edges & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        if (traversed_edges > limits.max_edges)
            return graph_document::graph_source_result_t::limit_exceeded;
        auto source = block_nodes.find(source_edge.source_entity);
        auto source_node = source != block_nodes.end()
            ? source->second
            : graph_node_for_address(output->ranges,
                                     source_edge.source.value);
        graph_document::graph_node_id_t target_node;
        if (source_edge.target_entity) {
            const auto target = block_nodes.find(*source_edge.target_entity);
            if (target != block_nodes.end())
                target_node = target->second;
        }
        if (!target_node.valid())
            target_node = graph_node_for_address(output->ranges,
                                                 source_edge.target.value);
        if (!source_node.valid() || !target_node.valid())
            continue;
        graph_edge_candidate_t edge;
        edge.source = source_node;
        edge.target = target_node;
        edge.kind = graph_edge_kind(source_edge.kind);
        edge.site_address = source_edge.source.value;
        edge.stable_source_id = source_edge.id;
        edges.push_back(std::move(edge));
        if (edges.size() > limits.max_edges)
            break;
    }
    return finalize_graph_edges(*output, std::move(edges), limits,
                                cancellation);
}

graph_document::graph_source_result_t build_call_graph(
    const std::shared_ptr<const analysis::analysis_publication_t>& publication,
    std::uint64_t function_address,
    const graph_document::graph_source_limits_t& limits,
    const graph_document::graph_cancellation_t* cancellation,
    std::shared_ptr<graph_materialization_t>& output)
{
    output = std::make_shared<graph_materialization_t>();
    output->generation = publication->generation;
    output->kind = graph_document::graph_kind_t::call_graph;
    output->function_address = function_address;
    const auto& snapshot = *publication->snapshot;

    if (snapshot.call_graph.nodes.size() > limits.max_nodes ||
        snapshot.call_graph.edges.size() > limits.max_edges) {
        output->total_nodes = snapshot.call_graph.nodes.size();
        output->total_edges = snapshot.call_graph.edges.size();
        return graph_document::graph_source_result_t::limit_exceeded;
    }

    std::unordered_set<analysis::entity_id_t> required_functions;
    required_functions.reserve(snapshot.call_graph.nodes.size());
    for (const auto& node : snapshot.call_graph.nodes) {
        if ((required_functions.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        required_functions.insert(node.function_id);
    }

    graph_function_index_t functions;
    functions.reserve(required_functions.size());
    std::size_t traversed_functions = 0;
    for (const auto& function : snapshot.functions) {
        if ((traversed_functions & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        if (traversed_functions >= limits.max_nodes)
            return graph_document::graph_source_result_t::limit_exceeded;
        ++traversed_functions;
        if (required_functions.find(function.id) != required_functions.end())
            functions.emplace(function.id, &function);
        if (functions.size() == required_functions.size())
            break;
    }

    std::unordered_set<analysis::entity_id_t> required_symbols;
    required_symbols.reserve(functions.size());
    for (const auto& [function_id, function] : functions) {
        static_cast<void>(function_id);
        if (function->symbol_id)
            required_symbols.insert(*function->symbol_id);
    }
    graph_symbol_index_t symbols;
    symbols.reserve(required_symbols.size());
    std::size_t traversed_symbols = 0;
    for (const auto& symbol : snapshot.symbols) {
        if ((traversed_symbols & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        if (traversed_symbols >= limits.max_nodes ||
            symbols.size() == required_symbols.size())
            break;
        ++traversed_symbols;
        if (required_symbols.find(symbol.id) != required_symbols.end())
            symbols.emplace(symbol.id, &symbol);
    }

    std::optional<analysis::entity_id_t> focus_function;
    std::unordered_set<analysis::entity_id_t> included_functions;
    if (function_address != 0) {
        const auto focus = std::find_if(
            snapshot.call_graph.nodes.begin(), snapshot.call_graph.nodes.end(),
            [function_address](const auto& node) {
                return node.address.value == function_address;
            });
        if (focus == snapshot.call_graph.nodes.end())
            return graph_document::graph_source_result_t::not_found;
        focus_function = focus->function_id;
        included_functions.insert(focus->function_id);
        std::uint64_t traversed_edges = 0;
        for (const auto& edge : snapshot.call_graph.edges) {
            ++traversed_edges;
            if ((traversed_edges & 0xFFU) == 0U && cancellation &&
                cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            if (traversed_edges > limits.max_edges)
                return graph_document::graph_source_result_t::limit_exceeded;
            if (edge.source_function_id == *focus_function) {
                if (edge.target_function_id)
                    included_functions.insert(*edge.target_function_id);
            } else if (edge.target_function_id &&
                       *edge.target_function_id == *focus_function) {
                included_functions.insert(edge.source_function_id);
            }
        }
    }

    std::unordered_map<analysis::entity_id_t,
                        graph_document::graph_node_id_t> function_nodes;
    std::unordered_set<std::uint64_t> stable_node_ids;
    stable_node_ids.reserve(snapshot.call_graph.nodes.size());
    for (const auto& source_node : snapshot.call_graph.nodes) {
        if ((output->total_nodes & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        if (focus_function &&
            included_functions.find(source_node.function_id) ==
                included_functions.end())
            continue;
        ++output->total_nodes;
        if (output->total_nodes > limits.max_nodes)
            break;
        graph_document::graph_node_view_t node;
        node.id = graph_node_identity(source_node.function_id,
                                      source_node.address.value,
                                      "call");
        node.kind = graph_document::graph_node_kind_t::function;
        node.address = source_node.address.value;
        node.label = function_label(functions, symbols, source_node.function_id,
                                    source_node.address.value);
        node.in_degree = static_cast<std::uint32_t>((std::min)(
            source_node.incoming_edges,
            static_cast<std::uint64_t>(
                (std::numeric_limits<std::uint32_t>::max)())));
        node.out_degree = static_cast<std::uint32_t>((std::min)(
            source_node.outgoing_edges,
            static_cast<std::uint64_t>(
                (std::numeric_limits<std::uint32_t>::max)())));
        if (!stable_node_ids.insert(node.id.value).second) {
            output->total_nodes =
                graph_document::k_graph_document_max_nodes + 1U;
            break;
        }
        if (source_node.function_id != 0)
            function_nodes.emplace(source_node.function_id, node.id);
        output->nodes.push_back(std::move(node));
        const auto function = functions.find(source_node.function_id);
        graph_node_range_t range;
        range.begin = source_node.address.value;
        range.end = graph_range_end(
            source_node.address.value,
            function != functions.end()
                ? function->second->end.value : source_node.address.value);
        range.node = output->nodes.back().id;
        output->ranges.push_back(range);
    }
    if (output->total_nodes > limits.max_nodes) {
        output->nodes.clear();
        output->ranges.clear();
        output->total_edges = snapshot.call_graph.edges.size();
        return graph_document::graph_source_result_t::limit_exceeded;
    }
    if (!sort_graph_ranges(output->ranges, cancellation))
        return graph_document::graph_source_result_t::cancelled;

    std::vector<graph_edge_candidate_t> edges;
    edges.reserve((std::min)(snapshot.call_graph.edges.size(),
        static_cast<std::size_t>(
            limits.max_edges + 1U)));
    for (const auto& source_edge : snapshot.call_graph.edges) {
        if ((edges.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        const auto source = function_nodes.find(source_edge.source_function_id);
        if (source == function_nodes.end() || !source_edge.target_function_id)
            continue;
        const auto target = function_nodes.find(*source_edge.target_function_id);
        if (target == function_nodes.end())
            continue;
        graph_edge_candidate_t edge;
        edge.source = source->second;
        edge.target = target->second;
        edge.kind = source_edge.resolution ==
                analysis::call_graph_resolution_t::indirect_candidate
            ? graph_document::graph_edge_kind_t::indirect_call
            : graph_document::graph_edge_kind_t::call;
        edge.site_address = source_edge.call_site.value;
        edge.stable_source_id = source_edge.id;
        edges.push_back(std::move(edge));
        if (edges.size() > limits.max_edges)
            break;
    }
    for (auto& node : output->nodes) {
        node.in_degree = 0;
        node.out_degree = 0;
    }
    return finalize_graph_edges(*output, std::move(edges), limits,
                                cancellation);
}

class production_graph_source_t final
    : public graph_document::graph_source_adapter_t {
public:
    production_graph_source_t(analysis_document_lease_t lease,
                              std::uint32_t cache_limit)
        : lease_(std::move(lease)), cache_limit_(cache_limit)
    {
    }

    std::uint64_t current_generation() const noexcept override
    {
        return lease_.publication ? lease_.publication->generation : 0;
    }

    bool generation_current(std::uint64_t generation) const noexcept override
    {
        try {
            return lease_.current(generation);
        } catch (...) {
            return false;
        }
    }

    bool generation_available(std::uint64_t generation) const noexcept override
    {
        try {
            return lease_.source &&
                   lease_.source->generation_available(generation);
        } catch (...) {
            return false;
        }
    }

    bool supports_kind(graph_document::graph_kind_t kind) const noexcept override
    {
        return kind == graph_document::graph_kind_t::cfg ||
               kind == graph_document::graph_kind_t::call_graph;
    }

    graph_document::graph_source_result_t counts(
        std::uint64_t generation, graph_document::graph_kind_t kind,
        std::uint64_t function_address,
        const graph_document::graph_source_limits_t& limits,
        const graph_document::graph_cancellation_t* cancellation,
        graph_document::graph_source_counts_t& output) const noexcept override
    {
        output = {};
        std::shared_ptr<const graph_materialization_t> graph;
        const auto result = materialize(generation, kind, function_address,
                                        limits, cancellation, graph);
        if (result != graph_document::graph_source_result_t::success)
            return result;
        output.nodes = graph->total_nodes;
        output.edges = graph->total_edges;
        return graph_document::graph_source_result_t::success;
    }

    graph_document::graph_source_result_t node_at(
        std::uint64_t generation, graph_document::graph_kind_t kind,
        std::uint64_t function_address, std::uint64_t ordinal,
        const graph_document::graph_source_limits_t& limits,
        const graph_document::graph_cancellation_t* cancellation,
        graph_document::graph_node_view_t& output) const noexcept override
    {
        output = {};
        std::shared_ptr<const graph_materialization_t> graph;
        const auto result = materialize(generation, kind, function_address,
                                        limits, cancellation, graph);
        if (result != graph_document::graph_source_result_t::success)
            return result;
        if (cancellation && cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        if (ordinal >= graph->nodes.size())
            return graph_document::graph_source_result_t::not_found;
        output = graph->nodes[static_cast<std::size_t>(ordinal)];
        return graph_document::graph_source_result_t::success;
    }

    graph_document::graph_source_result_t edge_at(
        std::uint64_t generation, graph_document::graph_kind_t kind,
        std::uint64_t function_address, std::uint64_t ordinal,
        const graph_document::graph_source_limits_t& limits,
        const graph_document::graph_cancellation_t* cancellation,
        graph_document::graph_edge_view_t& output) const noexcept override
    {
        output = {};
        std::shared_ptr<const graph_materialization_t> graph;
        const auto result = materialize(generation, kind, function_address,
                                        limits, cancellation, graph);
        if (result != graph_document::graph_source_result_t::success)
            return result;
        if (cancellation && cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        if (ordinal >= graph->edges.size())
            return graph_document::graph_source_result_t::not_found;
        output = graph->edges[static_cast<std::size_t>(ordinal)];
        return graph_document::graph_source_result_t::success;
    }

    graph_document::graph_source_result_t node_by_address(
        std::uint64_t generation, graph_document::graph_kind_t kind,
        std::uint64_t function_address, std::uint64_t address,
        const graph_document::graph_source_limits_t& limits,
        const graph_document::graph_cancellation_t* cancellation,
        graph_document::graph_node_view_t& output,
        std::uint64_t& ordinal) const noexcept override
    {
        output = {};
        ordinal = 0;
        std::shared_ptr<const graph_materialization_t> graph;
        const auto result = materialize(generation, kind, function_address,
                                        limits, cancellation, graph);
        if (result != graph_document::graph_source_result_t::success)
            return result;
        const auto id = graph_node_for_address(graph->ranges, address);
        if (!id.valid())
            return graph_document::graph_source_result_t::not_found;
        return find_node(*graph, id, cancellation, output, ordinal);
    }

    graph_document::graph_source_result_t node_by_id(
        std::uint64_t generation, graph_document::graph_kind_t kind,
        std::uint64_t function_address, graph_document::graph_node_id_t id,
        const graph_document::graph_source_limits_t& limits,
        const graph_document::graph_cancellation_t* cancellation,
        graph_document::graph_node_view_t& output,
        std::uint64_t& ordinal) const noexcept override
    {
        output = {};
        ordinal = 0;
        std::shared_ptr<const graph_materialization_t> graph;
        const auto result = materialize(generation, kind, function_address,
                                        limits, cancellation, graph);
        if (result != graph_document::graph_source_result_t::success)
            return result;
        return find_node(*graph, id, cancellation, output, ordinal);
    }

    graph_document::graph_source_result_t edge_by_id(
        std::uint64_t generation, graph_document::graph_kind_t kind,
        std::uint64_t function_address, graph_document::graph_edge_id_t id,
        const graph_document::graph_source_limits_t& limits,
        const graph_document::graph_cancellation_t* cancellation,
        graph_document::graph_edge_view_t& output,
        std::uint64_t& ordinal) const noexcept override
    {
        output = {};
        ordinal = 0;
        std::shared_ptr<const graph_materialization_t> graph;
        const auto result = materialize(generation, kind, function_address,
                                        limits, cancellation, graph);
        if (result != graph_document::graph_source_result_t::success)
            return result;
        for (std::size_t index = 0; index < graph->edges.size(); ++index) {
            if ((index & 0xFFU) == 0U && cancellation &&
                cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            if (graph->edges[index].id != id)
                continue;
            ordinal = index;
            output = graph->edges[index];
            return graph_document::graph_source_result_t::success;
        }
        return graph_document::graph_source_result_t::not_found;
    }

    graph_document::graph_source_result_t address_for_node(
        std::uint64_t generation, graph_document::graph_node_id_t node,
        const graph_document::graph_cancellation_t* cancellation,
        std::uint64_t& address) const noexcept
    {
        address = 0;
        try {
            if (cancellation && cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            const auto publication = lease_.source->publication(generation);
            if (!publication || !publication->snapshot)
                return graph_document::graph_source_result_t::not_found;
            const auto total = publication->snapshot->blocks.size() +
                               publication->snapshot->call_graph.nodes.size();
            if (publication->snapshot->blocks.size() >
                    graph_document::k_graph_document_max_nodes ||
                publication->snapshot->call_graph.nodes.size() >
                    graph_document::k_graph_document_max_nodes ||
                total > 2U * graph_document::k_graph_document_max_nodes)
                return graph_document::graph_source_result_t::limit_exceeded;

            std::unordered_map<std::uint64_t, std::uint64_t> addresses;
            {
                std::lock_guard<std::mutex> lock(node_address_mutex_);
                if (node_address_generation_ == generation &&
                    node_address_index_valid_) {
                    const auto found = node_addresses_.find(node.value);
                    if (found == node_addresses_.end())
                        return graph_document::graph_source_result_t::not_found;
                    address = found->second;
                    return graph_document::graph_source_result_t::success;
                }
            }
            addresses.reserve(total);
            std::size_t inspected = 0;
            for (const auto& block : publication->snapshot->blocks) {
                if ((inspected++ & 0xFFU) == 0U && cancellation &&
                    cancellation->cancelled())
                    return graph_document::graph_source_result_t::cancelled;
                const auto id = graph_node_identity(
                    block.id, block.start.value, "cfg");
                if (!id.valid() ||
                    !addresses.emplace(id.value, block.start.value).second)
                    return graph_document::graph_source_result_t::rejected;
            }
            for (const auto& source_node :
                 publication->snapshot->call_graph.nodes) {
                if ((inspected++ & 0xFFU) == 0U && cancellation &&
                    cancellation->cancelled())
                    return graph_document::graph_source_result_t::cancelled;
                const auto id = graph_node_identity(
                    source_node.function_id, source_node.address.value,
                    "call");
                if (!id.valid() ||
                    !addresses.emplace(id.value,
                                       source_node.address.value).second)
                    return graph_document::graph_source_result_t::rejected;
            }
            if (!generation_current(generation) ||
                (cancellation && cancellation->cancelled()))
                return cancellation && cancellation->cancelled()
                    ? graph_document::graph_source_result_t::cancelled
                    : graph_document::graph_source_result_t::rejected;
            {
                std::lock_guard<std::mutex> lock(node_address_mutex_);
                node_addresses_ = std::move(addresses);
                node_address_generation_ = generation;
                node_address_index_valid_ = true;
                const auto found = node_addresses_.find(node.value);
                if (found == node_addresses_.end())
                    return graph_document::graph_source_result_t::not_found;
                address = found->second;
            }
            return graph_document::graph_source_result_t::success;
        } catch (...) {
            address = 0;
            return graph_document::graph_source_result_t::rejected;
        }
    }

private:
    struct cache_entry_t final {
        std::uint64_t generation = 0;
        graph_document::graph_kind_t kind = graph_document::graph_kind_t::cfg;
        std::uint64_t function_address = 0;
        std::shared_ptr<const graph_materialization_t> graph;
    };

    graph_document::graph_source_result_t materialize(
        std::uint64_t generation,
        graph_document::graph_kind_t kind,
        std::uint64_t function_address,
        const graph_document::graph_source_limits_t& limits,
        const graph_document::graph_cancellation_t* cancellation,
        std::shared_ptr<const graph_materialization_t>& output) const noexcept
    {
        output.reset();
        try {
            if (!graph_document::graph_source_limits_valid(limits) ||
                !supports_kind(kind))
                return graph_document::graph_source_result_t::rejected;
            if (cancellation && cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            if (!generation_available(generation))
                return graph_document::graph_source_result_t::not_found;
            {
                std::lock_guard<std::mutex> lock(cache_mutex_);
                const auto found = std::find_if(
                    cache_.begin(), cache_.end(),
                    [generation, kind, function_address](const cache_entry_t& entry) {
                        return entry.generation == generation &&
                               entry.kind == kind &&
                               entry.function_address == function_address;
                    });
                if (found != cache_.end()) {
                    if (found->graph->total_nodes > limits.max_nodes ||
                        found->graph->total_edges > limits.max_edges)
                        return graph_document::graph_source_result_t::limit_exceeded;
                    output = found->graph;
                    return graph_document::graph_source_result_t::success;
                }
            }
            const auto publication = lease_.source->publication(generation);
            if (!publication || !publication->snapshot)
                return graph_document::graph_source_result_t::not_found;
            std::shared_ptr<graph_materialization_t> built;
            graph_document::graph_source_result_t result;
            if (kind == graph_document::graph_kind_t::cfg)
                result = build_cfg_graph(publication, function_address,
                                         limits, cancellation, built);
            else
                result = build_call_graph(publication, function_address,
                                          limits, cancellation, built);
            if (result != graph_document::graph_source_result_t::success ||
                !built)
                return result;
            if (cancellation && cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            if (!generation_current(generation))
                return graph_document::graph_source_result_t::rejected;
            std::lock_guard<std::mutex> lock(cache_mutex_);
            const auto existing = std::find_if(
                cache_.begin(), cache_.end(),
                [generation, kind, function_address](const cache_entry_t& entry) {
                    return entry.generation == generation &&
                           entry.kind == kind &&
                           entry.function_address == function_address;
                });
            if (existing != cache_.end()) {
                output = existing->graph;
                return graph_document::graph_source_result_t::success;
            }
            cache_entry_t entry;
            entry.generation = generation;
            entry.kind = kind;
            entry.function_address = function_address;
            entry.graph = built;
            cache_.push_back(std::move(entry));
            while (cache_.size() > (std::max<std::size_t>)(1U, cache_limit_))
                cache_.pop_front();
            output = std::move(built);
            return graph_document::graph_source_result_t::success;
        } catch (...) {
            output.reset();
            return graph_document::graph_source_result_t::rejected;
        }
    }

    static graph_document::graph_source_result_t find_node(
        const graph_materialization_t& graph,
        graph_document::graph_node_id_t id,
        const graph_document::graph_cancellation_t* cancellation,
        graph_document::graph_node_view_t& output,
        std::uint64_t& ordinal) noexcept
    {
        for (std::size_t index = 0; index < graph.nodes.size(); ++index) {
            if ((index & 0xFFU) == 0U && cancellation &&
                cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            if (graph.nodes[index].id != id)
                continue;
            ordinal = index;
            output = graph.nodes[index];
            return graph_document::graph_source_result_t::success;
        }
        return graph_document::graph_source_result_t::not_found;
    }

    analysis_document_lease_t lease_;
    std::size_t cache_limit_;
    mutable std::mutex cache_mutex_;
    mutable std::deque<cache_entry_t> cache_;
    mutable std::mutex node_address_mutex_;
    mutable std::unordered_map<std::uint64_t, std::uint64_t> node_addresses_;
    mutable std::uint64_t node_address_generation_ = 0;
    mutable bool node_address_index_valid_ = false;
};

class production_graph_overlay_t final
    : public graph_document::graph_overlay_adapter_t {
public:
    production_graph_overlay_t(
        std::shared_ptr<workbench_analysis_source_t> source,
        production_graph_source_t& graph)
        : source_(std::move(source)), graph_(&graph)
    {
    }

    graph_document::graph_source_result_t overlay_count(
        std::uint64_t generation, std::uint32_t limit,
        const graph_document::graph_cancellation_t* cancellation,
        std::uint32_t& output) const noexcept override
    {
        output = 0;
        try {
            if (limit == 0 || limit > graph_document::k_graph_document_max_overlays)
                return graph_document::graph_source_result_t::rejected;
            std::shared_ptr<const projection_t> projection;
            const auto result = refresh_projection(
                generation, limit, cancellation, projection);
            if (result != graph_document::graph_source_result_t::success)
                return result;
            output = projection->count;
            return graph_document::graph_source_result_t::success;
        } catch (...) {
            output = 0;
            return graph_document::graph_source_result_t::rejected;
        }
    }

    graph_document::graph_source_result_t overlay_node(
        std::uint64_t generation, graph_document::graph_node_id_t node,
        std::uint32_t max_label_bytes,
        const graph_document::graph_cancellation_t* cancellation,
        std::string& text) const noexcept override
    {
        text.clear();
        try {
            if (max_label_bytes == 0 ||
                max_label_bytes > graph_document::k_graph_document_max_label_bytes)
                return graph_document::graph_source_result_t::rejected;
            auto projection = cached_projection(generation);
            if (!projection) {
                const auto refreshed = refresh_projection(
                    generation, graph_document::k_graph_document_max_overlays,
                    cancellation, projection);
                if (refreshed != graph_document::graph_source_result_t::success)
                    return refreshed;
            }
            std::uint64_t address = 0;
            const auto resolved = graph_->address_for_node(
                generation, node, cancellation, address);
            if (resolved != graph_document::graph_source_result_t::success)
                return resolved;
            const auto found = projection->labels.find(address);
            if (found == projection->labels.end())
                return graph_document::graph_source_result_t::not_found;
            if (found->second.size() > max_label_bytes)
                return graph_document::graph_source_result_t::limit_exceeded;
            text = found->second;
            return graph_document::graph_source_result_t::success;
        } catch (...) {
            text.clear();
            return graph_document::graph_source_result_t::rejected;
        }
    }

private:
    struct projection_t final {
        std::uint64_t generation = 0;
        std::uint64_t revision = 0;
        std::uint32_t count = 0;
        std::unordered_map<std::uint64_t, std::string> labels;
    };

    std::shared_ptr<const projection_t> cached_projection(
        std::uint64_t generation) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = std::find_if(
            projections_.begin(), projections_.end(),
            [generation](const auto& projection) {
                return projection->generation == generation;
            });
        if (found == projections_.end())
            return {};
        return *found;
    }

    graph_document::graph_source_result_t refresh_projection(
        std::uint64_t generation,
        std::uint32_t limit,
        const graph_document::graph_cancellation_t* cancellation,
        std::shared_ptr<const projection_t>& output) const
    {
        output.reset();
        if (cancellation && cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;
        analysis::overlay_snapshot_t snapshot;
        if (!source_->current_overlay_snapshot(generation, snapshot))
            return graph_document::graph_source_result_t::not_found;
        const auto publication = source_->publication(generation);
        if (!publication || !publication->snapshot ||
            publication->snapshot->blocks.size() >
                graph_document::k_graph_document_max_nodes ||
            publication->snapshot->call_graph.nodes.size() >
                graph_document::k_graph_document_max_nodes)
            return graph_document::graph_source_result_t::limit_exceeded;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto found = std::find_if(
                projections_.begin(), projections_.end(),
                [generation, &snapshot](const auto& projection) {
                    return projection->generation == generation &&
                           projection->revision == snapshot.revision;
                });
            if (found != projections_.end()) {
                if ((*found)->count > limit)
                    return graph_document::graph_source_result_t::limit_exceeded;
                output = *found;
                return graph_document::graph_source_result_t::success;
            }
        }

        auto projection = std::make_shared<projection_t>();
        projection->generation = generation;
        projection->revision = snapshot.revision;
        std::unordered_set<std::uint64_t> graph_addresses;
        graph_addresses.reserve(publication->snapshot->blocks.size() +
                                publication->snapshot->call_graph.nodes.size());
        std::size_t inspected = 0;
        for (const auto& block : publication->snapshot->blocks) {
            if ((inspected++ & 0xFFU) == 0U && cancellation &&
                cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            graph_addresses.insert(block.start.value);
        }
        for (const auto& source_node :
             publication->snapshot->call_graph.nodes) {
            if ((inspected++ & 0xFFU) == 0U && cancellation &&
                cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            graph_addresses.insert(source_node.address.value);
        }

        std::unordered_map<std::uint64_t, std::string> names;
        std::size_t count = 0;
        for (auto iterator = snapshot.items.rbegin();
             iterator != snapshot.items.rend(); ++iterator) {
            if ((count & 0xFFU) == 0U && cancellation &&
                cancellation->cancelled())
                return graph_document::graph_source_result_t::cancelled;
            const auto& operation = iterator->second;
            if (operation.remove ||
                graph_addresses.find(operation.address.value) ==
                    graph_addresses.end())
                continue;
            const auto is_name =
                operation.kind == analysis::overlay_operation_kind_t::name;
            const auto is_comment =
                operation.kind == analysis::overlay_operation_kind_t::comment ||
                operation.kind ==
                    analysis::overlay_operation_kind_t::comment_update;
            if (!is_name && !is_comment)
                continue;
            ++count;
            if (count > limit ||
                count > graph_document::k_graph_document_max_overlays)
                return graph_document::graph_source_result_t::limit_exceeded;
            if ((is_name && operation.name.size() >
                    graph_document::k_graph_document_max_label_bytes) ||
                (is_comment && operation.text.size() >
                    graph_document::k_graph_document_max_label_bytes)) {
                return graph_document::graph_source_result_t::limit_exceeded;
            }
            if (is_name && !operation.name.empty())
                names.emplace(operation.address.value, operation.name);
            if (is_comment && !operation.text.empty())
                projection->labels.emplace(operation.address.value,
                                           operation.text);
        }
        projection->count = static_cast<std::uint32_t>(count);
        for (auto& [address, name] : names)
            projection->labels.insert_or_assign(address, std::move(name));
        if (cancellation && cancellation->cancelled())
            return graph_document::graph_source_result_t::cancelled;

        std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = std::find_if(
            projections_.begin(), projections_.end(),
            [generation](const auto& candidate) {
                return candidate->generation == generation;
            });
        if (existing != projections_.end()) {
            if ((*existing)->revision > projection->revision)
                projection = std::const_pointer_cast<projection_t>(*existing);
            projections_.erase(existing);
        }
        projections_.push_back(projection);
        while (projections_.size() > 2U)
            projections_.pop_front();
        output = std::move(projection);
        return graph_document::graph_source_result_t::success;
    }

    std::shared_ptr<workbench_analysis_source_t> source_;
    production_graph_source_t* graph_;
    mutable std::mutex mutex_;
    mutable std::deque<std::shared_ptr<const projection_t>> projections_;
};

struct diff_entity_value_t final {
    diff_document::diff_domain_t domain =
        diff_document::diff_domain_t::instruction;
    std::uint64_t address = 0;
    std::string value;
};

struct diff_materialization_t final {
    diff_document::diff_scope_t scope;
    std::vector<diff_document::diff_entry_t> entries;
    diff_document::diff_summary_t summary;
};

using diff_entity_map_t = std::map<std::string, diff_entity_value_t>;

std::string diff_key(std::string_view domain, std::uint64_t identity)
{
    return std::string(domain) + ":" + std::to_string(identity);
}

bool append_diff_entity(diff_entity_map_t& output,
                        std::size_t limit,
                        std::string key,
                        diff_document::diff_domain_t domain,
                        std::uint64_t address,
                        std::string value)
{
    if (key.empty() ||
        key.size() > diff_document::k_diff_document_max_entity_key_bytes)
        return false;
    if (output.find(key) != output.end() || output.size() >= limit)
        return false;
    diff_entity_value_t record;
    record.domain = domain;
    record.address = address;
    record.value = bounded_diff_value(value);
    return output.emplace(std::move(key), std::move(record)).second;
}

diff_document::diff_source_result_t append_snapshot_diff_entities(
    const analysis::analysis_snapshot_t& snapshot,
    std::size_t limit,
    const diff_document::diff_cancellation_t* cancellation,
    diff_entity_map_t& output)
{
    output.clear();
    for (const auto& instruction : snapshot.instructions) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        const auto identity = instruction.id != 0
            ? instruction.id : instruction.address.value;
        std::ostringstream value;
        value << "length=" << static_cast<std::uint32_t>(instruction.length)
              << ";mnemonic=" << instruction.mnemonic_id
              << ";opcode=" << instruction.opcode_id
              << ";flow=" << instruction.flow_flags
              << ";confidence=" << static_cast<std::uint32_t>(instruction.confidence);
        if (!append_diff_entity(output, limit,
                diff_key("instruction", identity),
                diff_document::diff_domain_t::instruction,
                instruction.address.value, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }
    for (const auto& function : snapshot.functions) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        const auto identity = function.id != 0
            ? function.id : function.start.value;
        std::ostringstream value;
        value << "end=" << hexadecimal(function.end.value)
              << ";blocks=" << function.block_count
              << ";chunks=" << function.chunk_count
              << ";thunk=" << function.thunk
              << ";noreturn=" << function.noreturn
              << ";confidence=" << static_cast<std::uint32_t>(function.confidence);
        if (!append_diff_entity(output, limit,
                diff_key("function", identity),
                diff_document::diff_domain_t::function,
                function.start.value, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }
    for (const auto& string_record : snapshot.strings) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        const auto identity = string_record.id != 0
            ? string_record.id : string_record.address.value;
        std::ostringstream value;
        value << "encoding=" << static_cast<std::uint32_t>(string_record.encoding)
              << ";length=" << string_record.byte_length
              << ";confidence=" << static_cast<std::uint32_t>(string_record.confidence)
              << ";value=" << string_record.value;
        if (!append_diff_entity(output, limit,
                diff_key("string", identity),
                diff_document::diff_domain_t::string,
                string_record.address.value, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }
    for (const auto& symbol : snapshot.symbols) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        auto domain = diff_document::diff_domain_t::symbol;
        if (symbol.kind == analysis::symbol_kind_t::import_symbol)
            domain = diff_document::diff_domain_t::import;
        else if (symbol.kind == analysis::symbol_kind_t::export_symbol)
            domain = diff_document::diff_domain_t::export_entry;
        else if (symbol.kind == analysis::symbol_kind_t::type_symbol)
            domain = diff_document::diff_domain_t::type;
        const auto identity = symbol.id != 0 ? symbol.id : symbol.address.value;
        std::ostringstream value;
        value << "kind=" << static_cast<std::uint32_t>(symbol.kind)
              << ";confidence=" << static_cast<std::uint32_t>(symbol.confidence)
              << ";name=" << symbol.name;
        if (!append_diff_entity(output, limit,
                diff_key("symbol", identity), domain,
                symbol.address.value, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }
    for (const auto& type : snapshot.rich_facts.type_candidates) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        const auto fallback_identity =
            std::to_string(type.source_key.size()) + ":" + type.source_key +
            ":" + std::to_string(type.display_name.size()) + ":" +
            type.display_name;
        const auto identity = type.id != 0
            ? type.id : stable_hash(fallback_identity);
        std::ostringstream value;
        value << "kind=" << static_cast<std::uint32_t>(type.kind)
              << ";confidence=" << static_cast<std::uint32_t>(type.confidence)
              << ";unknown=" << type.explicitly_unknown
              << ";name=" << type.display_name
              << ";type=" << type.canonical_type
              << ";source=" << type.source_key;
        if (!append_diff_entity(output, limit,
                diff_key("type", identity),
                diff_document::diff_domain_t::type,
                type.address ? type.address->value : 0, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }

    const auto image = snapshot.normalized_image;
    if (!image)
        return diff_document::diff_source_result_t::success;
    for (const auto& section : image->sections) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        std::ostringstream value;
        value << "name=" << section.name
              << ";virtual_size=" << section.virtual_size
              << ";file_offset=" << section.file_offset
              << ";file_size=" << section.file_size
              << ";flags=" << section.flags
              << ";permissions=" << section.permissions;
        if (!append_diff_entity(output, limit,
                diff_key("section", section.index),
                diff_document::diff_domain_t::section,
                section.virtual_address, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }
    std::unordered_map<std::string, std::uint64_t> import_occurrences;
    import_occurrences.reserve((std::min)(image->imports.size(), limit));
    for (const auto& imported : image->imports) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        const auto imported_name =
            imported.name ? *imported.name : std::string{};
        std::ostringstream logical_identity;
        logical_identity << imported.library.size() << ':'
                         << imported.library << ':'
                         << imported.name.has_value() << ':'
                         << imported_name.size() << ':' << imported_name << ':'
                         << imported.ordinal.has_value() << ':'
                         << (imported.ordinal ? *imported.ordinal : 0) << ':'
                         << imported.delayed;
        const auto logical_key = logical_identity.str();
        const auto occurrence = import_occurrences[logical_key]++;
        const auto identity = logical_key + ':' + std::to_string(occurrence);
        std::ostringstream value;
        value << "library=" << imported.library
              << ";name=" << imported_name
              << ";ordinal=" << (imported.ordinal ? *imported.ordinal : 0)
              << ";lookup=" << hexadecimal(imported.lookup_address.value)
              << ";delayed=" << imported.delayed;
        if (!append_diff_entity(output, limit,
                diff_key("import", stable_hash(identity)),
                diff_document::diff_domain_t::import,
                imported.address.value, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }
    for (const auto& exported : image->exports) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        std::ostringstream value;
        value << "name=" << (exported.name ? *exported.name : std::string{})
              << ";ordinal=" << exported.ordinal
              << ";forwarder="
              << (exported.forwarder ? *exported.forwarder : std::string{});
        if (!append_diff_entity(output, limit,
                diff_key("export", exported.ordinal),
                diff_document::diff_domain_t::export_entry,
                exported.address.value, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }
    return diff_document::diff_source_result_t::success;
}

std::uint64_t hash_overlay_bytes(const std::vector<std::uint8_t>& bytes) noexcept
{
    std::uint64_t hash = k_shell_fnv_offset;
    for (const auto byte : bytes) {
        hash ^= byte;
        hash *= k_shell_fnv_prime;
    }
    return hash == 0 ? 1 : hash;
}

diff_document::diff_source_result_t append_overlay_diff_entities(
    const analysis::overlay_snapshot_t& snapshot,
    std::size_t limit,
    const diff_document::diff_cancellation_t* cancellation,
    diff_entity_map_t& output)
{
    output.clear();
    for (const auto& [entity_key, operation] : snapshot.items) {
        if ((output.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        std::string key = "overlay:" + entity_key;
        if (key.size() > diff_document::k_diff_document_max_entity_key_bytes)
            key = diff_key("overlay", stable_hash(entity_key));
        std::ostringstream value;
        value << "kind=" << static_cast<std::uint32_t>(operation.kind)
              << ";end=" << (operation.end ? operation.end->value : 0)
              << ";remove=" << operation.remove
              << ";name=" << operation.name
              << ";text=" << operation.text
              << ";type=" << operation.type
              << ";variable=" << operation.variable
              << ";signature=" << operation.signature
              << ";bytes=" << operation.bytes.size()
              << ";bytes_hash=" << hexadecimal(hash_overlay_bytes(operation.bytes))
              << ";assembly=" << operation.assembly
              << ";integer_type=" << operation.integer_type
              << ";integer_value=" << operation.integer_value
              << ";stack_offset=" << operation.stack_offset
              << ";reanalysis_flags=" << operation.reanalysis_flags;
        if (!append_diff_entity(output, limit, std::move(key),
                diff_document::diff_domain_t::overlay,
                operation.address.value, value.str()))
            return diff_document::diff_source_result_t::limit_exceeded;
    }
    return diff_document::diff_source_result_t::success;
}

diff_document::diff_source_result_t build_diff_materialization(
    std::uint64_t generation,
    const diff_document::diff_scope_t& scope,
    std::size_t limit,
    const std::shared_ptr<const analysis::analysis_publication_t>& before_publication,
    const std::shared_ptr<const analysis::analysis_publication_t>& after_publication,
    const std::optional<analysis::overlay_snapshot_t>& before_overlay,
    const std::optional<analysis::overlay_snapshot_t>& after_overlay,
    const diff_document::diff_cancellation_t* cancellation,
    std::shared_ptr<diff_materialization_t>& result)
{
    result = std::make_shared<diff_materialization_t>();
    result->scope = scope;
    result->summary.snapshot_generation = generation;
    result->summary.scope = scope;
    diff_entity_map_t before;
    diff_entity_map_t after;
    diff_document::diff_source_result_t before_result;
    diff_document::diff_source_result_t after_result;
    if (scope.kind == diff_document::diff_kind_t::overlay) {
        if (!before_overlay || !after_overlay)
            return diff_document::diff_source_result_t::not_found;
        before_result = append_overlay_diff_entities(
            *before_overlay, limit, cancellation, before);
        if (before_result != diff_document::diff_source_result_t::success)
            return before_result;
        after_result = append_overlay_diff_entities(
            *after_overlay, limit, cancellation, after);
    } else {
        if (!before_publication || !before_publication->snapshot ||
            !after_publication || !after_publication->snapshot)
            return diff_document::diff_source_result_t::not_found;
        before_result = append_snapshot_diff_entities(
            *before_publication->snapshot, limit, cancellation, before);
        if (before_result != diff_document::diff_source_result_t::success)
            return before_result;
        after_result = append_snapshot_diff_entities(
            *after_publication->snapshot, limit, cancellation, after);
    }
    if (after_result != diff_document::diff_source_result_t::success)
        return after_result;

    auto before_it = before.begin();
    auto after_it = after.begin();
    while (before_it != before.end() || after_it != after.end()) {
        if ((result->entries.size() & 0xFFU) == 0U && cancellation &&
            cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        diff_document::diff_entry_t entry;
        if (after_it == after.end() ||
            (before_it != before.end() && before_it->first < after_it->first)) {
            entry.kind = diff_document::diff_entry_kind_t::removed;
            entry.domain = before_it->second.domain;
            entry.entity_key = before_it->first;
            entry.address = before_it->second.address;
            entry.old_address = before_it->second.address;
            entry.old_value = before_it->second.value;
            ++before_it;
        } else if (before_it == before.end() || after_it->first < before_it->first) {
            entry.kind = diff_document::diff_entry_kind_t::added;
            entry.domain = after_it->second.domain;
            entry.entity_key = after_it->first;
            entry.address = after_it->second.address;
            entry.new_address = after_it->second.address;
            entry.new_value = after_it->second.value;
            ++after_it;
        } else {
            const auto& old_record = before_it->second;
            const auto& new_record = after_it->second;
            const auto key = before_it->first;
            ++before_it;
            ++after_it;
            if (old_record.address == new_record.address &&
                old_record.value == new_record.value)
                continue;
            entry.kind = old_record.address != 0 && new_record.address != 0 &&
                         old_record.address != new_record.address
                ? diff_document::diff_entry_kind_t::moved
                : diff_document::diff_entry_kind_t::modified;
            entry.domain = new_record.domain;
            entry.entity_key = key;
            entry.address = new_record.address;
            entry.old_address = old_record.address;
            entry.new_address = new_record.address;
            entry.old_value = old_record.value;
            entry.new_value = new_record.value;
        }
        if (result->entries.size() >= limit) {
            result->entries.clear();
            return diff_document::diff_source_result_t::limit_exceeded;
        }
        switch (entry.kind) {
            case diff_document::diff_entry_kind_t::added:
                ++result->summary.added_count;
                break;
            case diff_document::diff_entry_kind_t::removed:
                ++result->summary.removed_count;
                break;
            case diff_document::diff_entry_kind_t::modified:
                ++result->summary.modified_count;
                break;
            case diff_document::diff_entry_kind_t::moved:
                ++result->summary.moved_count;
                break;
        }
        result->entries.push_back(std::move(entry));
    }
    result->summary.total_entries = result->entries.size();
    return cancellation && cancellation->cancelled()
        ? diff_document::diff_source_result_t::cancelled
        : diff_document::diff_source_result_t::success;
}

class production_diff_source_t final
    : public diff_document::diff_source_adapter_t {
public:
    production_diff_source_t(
        analysis_document_lease_t lease,
        std::shared_ptr<workbench_analysis_source_catalog_t> catalog,
        std::size_t cache_limit,
        std::size_t entry_limit)
        : lease_(std::move(lease)),
          catalog_(std::move(catalog)),
          cache_limit_(cache_limit),
          entry_limit_(entry_limit)
    {
    }

    std::uint64_t current_generation() const noexcept override
    {
        return lease_.publication ? lease_.publication->generation : 0;
    }

    bool generation_current(std::uint64_t generation) const noexcept override
    {
        try {
            return lease_.current(generation);
        } catch (...) {
            return false;
        }
    }

    bool supports_kind(diff_document::diff_kind_t kind) const noexcept override
    {
        return kind == diff_document::diff_kind_t::generation ||
               kind == diff_document::diff_kind_t::overlay ||
               kind == diff_document::diff_kind_t::workspace;
    }

    diff_document::diff_source_result_t scope_available(
        std::uint64_t generation,
        const diff_document::diff_scope_t& scope,
        const diff_document::diff_source_limits_t& limits,
        const diff_document::diff_cancellation_t* cancellation) const noexcept override
    {
        try {
            if (!diff_document::diff_source_limits_valid(limits))
                return diff_document::diff_source_result_t::rejected;
            if (cancellation && cancellation->cancelled())
                return diff_document::diff_source_result_t::cancelled;
            endpoint_material_t before;
            endpoint_material_t after;
            return resolve_scope(generation, scope, cancellation,
                                 before, after);
        } catch (...) {
            return diff_document::diff_source_result_t::rejected;
        }
    }

    diff_document::diff_source_result_t entry_count(
        std::uint64_t generation,
        const diff_document::diff_scope_t& scope,
        const diff_document::diff_source_limits_t& limits,
        const diff_document::diff_cancellation_t* cancellation,
        std::uint64_t& output) const noexcept override
    {
        output = 0;
        try {
            std::shared_ptr<const diff_materialization_t> materialization;
            const auto result = materialize(generation, scope, limits,
                                            cancellation, materialization);
            if (result != diff_document::diff_source_result_t::success)
                return result;
            output = materialization->entries.size();
            return diff_document::diff_source_result_t::success;
        } catch (...) {
            output = 0;
            return diff_document::diff_source_result_t::rejected;
        }
    }

    diff_document::diff_source_result_t entry_at(
        std::uint64_t generation,
        const diff_document::diff_scope_t& scope,
        std::uint64_t ordinal,
        const diff_document::diff_source_limits_t& limits,
        const diff_document::diff_cancellation_t* cancellation,
        diff_document::diff_entry_t& output) const noexcept override
    {
        output = {};
        try {
            std::shared_ptr<const diff_materialization_t> materialization;
            const auto result = materialize(generation, scope, limits,
                                            cancellation, materialization);
            if (result != diff_document::diff_source_result_t::success)
                return result;
            if (cancellation && cancellation->cancelled())
                return diff_document::diff_source_result_t::cancelled;
            if (ordinal >= materialization->entries.size())
                return diff_document::diff_source_result_t::not_found;
            output = materialization->entries[static_cast<std::size_t>(ordinal)];
            return generation_current(generation)
                ? diff_document::diff_source_result_t::success
                : diff_document::diff_source_result_t::rejected;
        } catch (...) {
            output = {};
            return diff_document::diff_source_result_t::rejected;
        }
    }

    diff_document::diff_source_result_t summary(
        std::uint64_t generation,
        const diff_document::diff_scope_t& scope,
        const diff_document::diff_source_limits_t& limits,
        const diff_document::diff_cancellation_t* cancellation,
        diff_document::diff_summary_t& output) const noexcept override
    {
        output = {};
        try {
            std::shared_ptr<const diff_materialization_t> materialization;
            const auto result = materialize(generation, scope, limits,
                                            cancellation, materialization);
            if (result != diff_document::diff_source_result_t::success)
                return result;
            output = materialization->summary;
            return generation_current(generation)
                ? diff_document::diff_source_result_t::success
                : diff_document::diff_source_result_t::rejected;
        } catch (...) {
            output = {};
            return diff_document::diff_source_result_t::rejected;
        }
    }

private:
    struct endpoint_material_t final {
        std::shared_ptr<workbench_analysis_source_t> source;
        std::shared_ptr<const analysis::analysis_publication_t> publication;
        std::optional<analysis::overlay_snapshot_t> overlay;
    };

    bool resolve_endpoint(const diff_document::diff_endpoint_t& endpoint,
                          bool require_overlay,
                          const diff_document::diff_cancellation_t* cancellation,
                          endpoint_material_t& output) const
    {
        output = {};
        if (cancellation && cancellation->cancelled())
            return false;
        output.source = catalog_ ? catalog_->find(endpoint.workspace_id) : nullptr;
        if (!output.source)
            return false;
        output.publication = output.source->publication(endpoint.generation);
        if (!output.publication || !output.publication->snapshot)
            return false;
        if (require_overlay) {
            if (cancellation && cancellation->cancelled())
                return false;
            analysis::overlay_snapshot_t snapshot;
            if (!output.source->overlay_snapshot(
                    endpoint.generation, endpoint.overlay_revision, snapshot))
                return false;
            output.overlay = std::move(snapshot);
        }
        return true;
    }

    diff_document::diff_source_result_t resolve_scope(
        std::uint64_t generation,
        const diff_document::diff_scope_t& scope,
        const diff_document::diff_cancellation_t* cancellation,
        endpoint_material_t& before,
        endpoint_material_t& after) const
    {
        if (cancellation && cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        if (!generation_current(generation) ||
            !diff_document::diff_scope_valid(scope) ||
            !supports_kind(scope.kind))
            return diff_document::diff_source_result_t::rejected;
        const auto local_workspace = lease_.source->workspace().value;
        const bool local_before = scope.before.workspace_id == local_workspace &&
                                  scope.before.generation == generation;
        const bool local_after = scope.after.workspace_id == local_workspace &&
                                 scope.after.generation == generation;
        if (!local_before && !local_after)
            return diff_document::diff_source_result_t::rejected;
        if (scope.kind == diff_document::diff_kind_t::generation &&
            (scope.before.workspace_id != local_workspace ||
             scope.after.workspace_id != local_workspace || !local_after))
            return diff_document::diff_source_result_t::rejected;
        if (scope.kind == diff_document::diff_kind_t::overlay &&
            (scope.before.workspace_id != local_workspace ||
             scope.after.workspace_id != local_workspace ||
             scope.before.generation != generation || !local_after))
            return diff_document::diff_source_result_t::rejected;
        const bool require_overlay =
            scope.kind == diff_document::diff_kind_t::overlay;
        if (!resolve_endpoint(scope.before, require_overlay, cancellation, before) ||
            !resolve_endpoint(scope.after, require_overlay, cancellation, after))
            return cancellation && cancellation->cancelled()
                ? diff_document::diff_source_result_t::cancelled
                : diff_document::diff_source_result_t::not_found;
        return generation_current(generation)
            ? diff_document::diff_source_result_t::success
            : diff_document::diff_source_result_t::rejected;
    }

    diff_document::diff_source_result_t materialize(
        std::uint64_t generation,
        const diff_document::diff_scope_t& scope,
        const diff_document::diff_source_limits_t& limits,
        const diff_document::diff_cancellation_t* cancellation,
        std::shared_ptr<const diff_materialization_t>& output) const
    {
        output.reset();
        if (!diff_document::diff_source_limits_valid(limits))
            return diff_document::diff_source_result_t::rejected;
        if (cancellation && cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            const auto found = std::find_if(
                cache_.begin(), cache_.end(),
                [&scope](const auto& item) { return item.first == scope; });
            if (found != cache_.end()) {
                if (found->second->entries.size() > limits.max_entries)
                    return diff_document::diff_source_result_t::limit_exceeded;
                output = found->second;
                return diff_document::diff_source_result_t::success;
            }
        }
        endpoint_material_t before;
        endpoint_material_t after;
        const auto scope_result = resolve_scope(
            generation, scope, cancellation, before, after);
        if (scope_result != diff_document::diff_source_result_t::success)
            return scope_result;
        const auto effective_limit = static_cast<std::size_t>((std::min)(
            static_cast<std::uint64_t>(entry_limit_), limits.max_entries));
        if (effective_limit == 0)
            return diff_document::diff_source_result_t::limit_exceeded;
        std::shared_ptr<diff_materialization_t> built;
        const auto build_result = build_diff_materialization(
            generation, scope, effective_limit, before.publication,
            after.publication, before.overlay, after.overlay, cancellation,
            built);
        if (build_result != diff_document::diff_source_result_t::success ||
            !built)
            return build_result;
        if (cancellation && cancellation->cancelled())
            return diff_document::diff_source_result_t::cancelled;
        if (!generation_current(generation))
            return diff_document::diff_source_result_t::rejected;
        std::lock_guard<std::mutex> lock(cache_mutex_);
        const auto existing = std::find_if(
            cache_.begin(), cache_.end(),
            [&scope](const auto& item) { return item.first == scope; });
        if (existing != cache_.end()) {
            output = existing->second;
            return diff_document::diff_source_result_t::success;
        }
        cache_.emplace_back(scope, built);
        while (cache_.size() > (std::max<std::size_t>)(1U, cache_limit_))
            cache_.pop_front();
        output = std::move(built);
        return diff_document::diff_source_result_t::success;
    }

    analysis_document_lease_t lease_;
    std::shared_ptr<workbench_analysis_source_catalog_t> catalog_;
    std::size_t cache_limit_;
    std::size_t entry_limit_;
    mutable std::mutex cache_mutex_;
    mutable std::deque<std::pair<diff_document::diff_scope_t,
                                 std::shared_ptr<diff_materialization_t>>> cache_;
};

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
struct pseudocode_job_payload_t final {
    bool succeeded = false;
    analysis::decompiler_document_t document;
    std::vector<analysis::decompiler_diagnostic_t> diagnostics;
};

constexpr std::size_t k_workbench_pseudocode_max_inflight = 8;
constexpr std::uint32_t k_workbench_pseudocode_teardown_budget_ms = 250;

analysis::decompiler_diagnostic_t pseudocode_terminal_diagnostic(
    analysis::decompiler_diagnostic_code_t code,
    std::string localization_key,
    bool retryable)
{
    analysis::decompiler_diagnostic_t diagnostic;
    diagnostic.severity = analysis::decompiler_diagnostic_severity_t::error;
    diagnostic.code = code;
    diagnostic.localization_key = std::move(localization_key);
    diagnostic.retryable = retryable;
    diagnostic.ordinal = 1;
    return diagnostic;
}

std::vector<analysis::decompiler_diagnostic_t> pseudocode_diagnostics(
    const analysis::decompiler_ui_result_t& result)
{
    std::vector<analysis::decompiler_diagnostic_t> diagnostics;
    diagnostics.reserve(result.diagnostics.size());
    std::uint32_t ordinal = 0;
    for (const auto& source : result.diagnostics) {
        analysis::decompiler_diagnostic_t diagnostic;
        diagnostic.severity = source.severity;
        diagnostic.code = source.code;
        diagnostic.localization_key = source.localization_key.empty()
            ? "workbench.pseudocode.decompiler_failure"
            : source.localization_key;
        diagnostic.localization_arguments = source.localization_arguments;
        diagnostic.coordinate = source.coordinate;
        diagnostic.confidence = source.confidence;
        diagnostic.retryable = source.retryable;
        diagnostic.ordinal = ++ordinal;
        diagnostics.push_back(std::move(diagnostic));
    }
    if (diagnostics.empty())
        diagnostics.push_back(pseudocode_terminal_diagnostic(
            analysis::decompiler_diagnostic_code_t::provider_failure,
            "workbench.pseudocode.decompiler_failure", true));
    return diagnostics;
}

class production_pseudocode_source_t final
    : public pseudocode_document::pseudocode_source_adapter_t {
public:
    explicit production_pseudocode_source_t(analysis_document_lease_t lease)
        : lease_(std::move(lease)),
          policy_(analysis::default_decompiler_profile_policy()),
          jobs_(std::make_shared<job_registry_t>())
    {
        const auto workspace = lease_.source
            ? lease_.source->analysis_workspace() : nullptr;
        if (workspace) {
            auto production = analysis::decompiler_ui_integration_t::
                production_for_workspace(workspace);
            if (production)
                decompiler_ = production.take_value();
        }
    }

    ~production_pseudocode_source_t() override
    {
        std::vector<std::uint64_t> task_ids;
        {
            std::lock_guard<std::mutex> lock(jobs_->mutex);
            jobs_->shutting_down = true;
            task_ids.reserve(jobs_->jobs.size());
            for (auto& [job_id, job] : jobs_->jobs) {
                static_cast<void>(job_id);
                job.cancellation->request_cancel();
                job.cancelled = true;
                if (job.task_id != 0)
                    task_ids.push_back(job.task_id);
            }
        }
        for (const auto task_id : task_ids)
            static_cast<void>(aida::infra::executor::cancel(task_id));
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(k_workbench_pseudocode_teardown_budget_ms);
        for (const auto task_id : task_ids) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline)
                break;
            const auto remaining = std::chrono::duration_cast<
                std::chrono::milliseconds>(deadline - now).count();
            static_cast<void>(aida::infra::executor::wait_for(
                task_id, static_cast<std::uint32_t>((std::max<std::int64_t>)(
                    1, remaining))));
        }
        std::lock_guard<std::mutex> lock(jobs_->mutex);
        jobs_->jobs.clear();
    }

    std::uint64_t current_generation() const noexcept override
    {
        return lease_.source ? lease_.source->current_generation() : 0;
    }

    bool generation_current(std::uint64_t generation) const noexcept override
    {
        try {
            return lease_.source && lease_.source->generation_current(generation);
        } catch (...) {
            return false;
        }
    }

    bool binding_current(
        const std::optional<analysis::generation_bound_decompiler_entity_t>&
            binding) const noexcept override
    {
        if (!binding)
            return generation_current(current_generation());
        try {
            const auto workspace = lease_.source
                ? lease_.source->analysis_workspace() : nullptr;
            const auto publication = workspace
                ? workspace->analysis_publication() : nullptr;
            if (!workspace || !publication ||
                workspace->overlay_revision() != binding->overlay_revision)
                return false;
            analysis::cancellation_source_t cancellation;
            return analysis::validate_generation_bound_entity(
                workspace->identity(), *publication, *binding,
                cancellation.token()).has_value();
        } catch (...) {
            return false;
        }
    }

    workbench_error_t resolve_request(
        std::uint64_t function_address,
        analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms,
        pseudocode_document::pseudocode_request_t& output) const override
    {
        analysis::decompiler_entity_locator_t locator;
        locator.address = function_address;
        return resolve_request(locator, profile, timeout_ms, output);
    }

    workbench_error_t resolve_request(
        const analysis::decompiler_entity_locator_t& locator,
        analysis::decompiler_profile_id_t profile,
        std::uint64_t timeout_ms,
        pseudocode_document::pseudocode_request_t& output) const override
    {
        output = {};
        const auto budget = profile_budget(profile);
        const auto effective_timeout = (std::min)(
            timeout_ms, budget.max_wall_clock_ms);
        const auto workspace = lease_.source
            ? lease_.source->analysis_workspace()
            : nullptr;
        const auto subject = locator.address.value_or(locator.token.value_or(0));
        if (timeout_ms == 0 || effective_timeout == 0 || !workspace ||
            !decompiler_ || (locator.address.has_value() == locator.token.has_value()) ||
            effective_timeout > static_cast<std::uint64_t>(
                (std::chrono::milliseconds::max)().count()))
            return shell_error(workbench_error_code_t::adapter_rejected, subject);

        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(
                static_cast<std::chrono::milliseconds::rep>(effective_timeout));
        analysis::cancellation_source_t cancellation(deadline);
        auto resolved = decompiler_->resolve_entity_at(locator, cancellation.token());
        if (!resolved)
            return shell_error(
                resolved.error().code == analysis::workspace_error_code_t::target_ambiguous
                    ? workbench_error_code_t::duplicate_identifier
                    : workbench_error_code_t::invalid_document,
                subject);
        auto binding = resolved.take_value();
        const auto publication = workspace->analysis_publication();
        if (!publication ||
            !lease_.source->generation_current(publication->generation) ||
            publication->generation != binding.generation ||
            publication->analysis_revision != binding.analysis_revision ||
            publication->overlay_revision != binding.overlay_revision ||
            workspace->overlay_revision() != binding.overlay_revision)
            return shell_error(workbench_error_code_t::revision_mismatch,
                               binding.generation);
        auto validated = analysis::validate_generation_bound_entity(
            workspace->identity(), *publication, binding, cancellation.token());
        if (!validated)
            return shell_error(workbench_error_code_t::revision_mismatch,
                               binding.generation);

        output.entity = binding.entity;
        output.binding = std::move(binding);
        output.profile = profile;
        output.workspace_generation = publication->generation;
        output.timeout_ms = effective_timeout;
        return {};
    }

    workbench_error_t request_decompilation(
        const pseudocode_document::pseudocode_request_t& request,
        std::uint64_t job_id) override
    {
        if (job_id == 0 || request.workspace_generation != current_generation() ||
            !generation_current(request.workspace_generation) ||
            request.timeout_ms == 0 ||
            request.timeout_ms > static_cast<std::uint64_t>(
                (std::chrono::milliseconds::max)().count()))
            return shell_error(workbench_error_code_t::revision_mismatch,
                               request.workspace_generation);
        if (!request.binding || request.binding->entity != request.entity ||
            request.binding->generation != request.workspace_generation ||
            !analysis::validate_decompiler_entity_key(request.entity).valid())
            return shell_error(workbench_error_code_t::invalid_document, job_id);
        const auto decompiler = decompiler_;
        if (!decompiler)
            return shell_error(workbench_error_code_t::adapter_rejected, job_id);
        const auto source = lease_.source;
        const auto workspace = source ? source->analysis_workspace() : nullptr;
        const auto publication = workspace ? workspace->analysis_publication() : nullptr;
        if (!workspace || !publication || !source->publication_current(publication) ||
            publication->generation != request.binding->generation ||
            publication->analysis_revision != request.binding->analysis_revision ||
            publication->overlay_revision != request.binding->overlay_revision ||
            workspace->overlay_revision() != request.binding->overlay_revision)
            return shell_error(workbench_error_code_t::revision_mismatch,
                               request.binding->generation);
        analysis::cancellation_source_t validation_cancellation;
        auto validated = analysis::validate_generation_bound_entity(
            workspace->identity(), *publication, *request.binding,
            validation_cancellation.token());
        if (!validated)
            return shell_error(workbench_error_code_t::revision_mismatch,
                               request.binding->generation);

        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(request.timeout_ms);
        auto cancellation = std::make_shared<analysis::cancellation_source_t>(deadline);
        try {
            std::lock_guard<std::mutex> lock(jobs_->mutex);
            reap_cancelled_locked(*jobs_);
            if (jobs_->shutting_down)
                return shell_error(workbench_error_code_t::adapter_rejected,
                                   job_id);
            if (jobs_->jobs.find(job_id) != jobs_->jobs.end())
                return shell_error(workbench_error_code_t::duplicate_identifier,
                                   job_id);
            if (jobs_->jobs.size() >= k_workbench_pseudocode_max_inflight) {
                return shell_error(workbench_error_code_t::adapter_rejected,
                                   static_cast<std::uint64_t>(jobs_->jobs.size()));
            }
            const auto inserted = jobs_->jobs.try_emplace(job_id);
            if (!inserted.second)
                return shell_error(workbench_error_code_t::duplicate_identifier,
                                   job_id);
            inserted.first->second.cancellation = cancellation;
        } catch (...) {
            return shell_error(workbench_error_code_t::adapter_rejected, job_id);
        }
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "workbench_pseudocode";
        submission.label = "workbench.pseudocode.decompile";
        submission.thread_class = "bounded_decompiler";
        submission.domain = aida::infra::executor::domain_t::feature_worker;
        submission.priority = request.profile ==
                analysis::decompiler_profile_id_t::fast ? 4 : 3;
        const auto now_ms = static_cast<std::uint64_t>(::GetTickCount64());
        submission.deadline_ms = request.timeout_ms >
                (std::numeric_limits<std::uint64_t>::max)() - now_ms
            ? (std::numeric_limits<std::uint64_t>::max)()
            : now_ms + request.timeout_ms;
        submission.generation = request.workspace_generation;
        submission.ui_access_policy = "forbidden";
        submission.failure_policy = "typed_diagnostic";
        submission.shutdown_policy = "cancel_replaceable";
        submission.cancel_hook = [cancellation, registry = jobs_, job_id] {
            cancellation->request_cancel();
            std::lock_guard<std::mutex> lock(registry->mutex);
            const auto found = registry->jobs.find(job_id);
            if (found == registry->jobs.end() || found->second.payload)
                return;
            pseudocode_job_payload_t payload;
            const bool deadline = cancellation->token().deadline_exceeded();
            payload.diagnostics.push_back(pseudocode_terminal_diagnostic(
                deadline
                    ? analysis::decompiler_diagnostic_code_t::deadline_exceeded
                    : analysis::decompiler_diagnostic_code_t::cancelled,
                deadline
                    ? "workbench.pseudocode.deadline_exceeded"
                    : "workbench.pseudocode.cancelled",
                !deadline));
            found->second.payload = std::move(payload);
        };
        const auto registry = jobs_;
        submission.body = [decompiler, source, publication, request,
                           workspace, cancellation, registry, job_id]() mutable {
            pseudocode_job_payload_t payload;
            try {
                if (cancellation->token().stop_requested()) {
                    payload.diagnostics.push_back(pseudocode_terminal_diagnostic(
                        analysis::decompiler_diagnostic_code_t::cancelled,
                        "workbench.pseudocode.cancelled", true));
                } else if (!source->publication_current(publication) ||
                           workspace->overlay_revision() !=
                               request.binding->overlay_revision) {
                    payload.diagnostics.push_back(pseudocode_terminal_diagnostic(
                        analysis::decompiler_diagnostic_code_t::cache_key_rejected,
                        "workbench.pseudocode.stale_generation", true));
                } else {
                    const auto result = decompiler->decompile_entity(
                        *request.binding,
                        analysis::decompiler_ui_invocation_source_t::keyboard_f5,
                        request.profile,
                        analysis::decompiler_pipeline_cache_mode_t::read_write,
                        cancellation->token());
                    if (!result || !result.value().succeeded()) {
                        const auto deadline =
                            cancellation->token().deadline_exceeded();
                        const auto cancelled =
                            cancellation->token().cancellation_requested();
                        if (deadline || cancelled) {
                            payload.diagnostics.push_back(
                                pseudocode_terminal_diagnostic(
                                    deadline
                                        ? analysis::decompiler_diagnostic_code_t::deadline_exceeded
                                        : analysis::decompiler_diagnostic_code_t::cancelled,
                                    deadline
                                        ? "workbench.pseudocode.deadline_exceeded"
                                        : "workbench.pseudocode.cancelled",
                                    !deadline));
                        } else if (result) {
                            payload.diagnostics = pseudocode_diagnostics(result.value());
                        } else {
                            const auto error_code = result.error().code;
                            const bool result_deadline = error_code ==
                                analysis::workspace_error_code_t::deadline_exceeded;
                            const bool result_cancelled = error_code ==
                                analysis::workspace_error_code_t::cancelled;
                            payload.diagnostics.push_back(
                                pseudocode_terminal_diagnostic(
                                    result_deadline
                                        ? analysis::decompiler_diagnostic_code_t::deadline_exceeded
                                        : result_cancelled
                                            ? analysis::decompiler_diagnostic_code_t::cancelled
                                            : analysis::decompiler_diagnostic_code_t::provider_failure,
                                    result.error().stable_code(),
                                    result_cancelled || result.error().code !=
                                        analysis::workspace_error_code_t::integrity_failure));
                        }
                    } else if (!source->publication_current(publication) ||
                               result.value().workspace_generation !=
                                   request.binding->generation ||
                               result.value().analysis_revision !=
                                   request.binding->analysis_revision ||
                               result.value().overlay_revision !=
                                   request.binding->overlay_revision ||
                               workspace->overlay_revision() !=
                                   request.binding->overlay_revision ||
                               result.value().document->entity != request.entity) {
                        payload.diagnostics.push_back(pseudocode_terminal_diagnostic(
                            analysis::decompiler_diagnostic_code_t::cache_key_rejected,
                            "workbench.pseudocode.stale_generation", true));
                    } else {
                        payload.document = *result.value().document;
                        payload.succeeded = true;
                    }
                }
            } catch (...) {
                payload = {};
                payload.diagnostics.push_back(pseudocode_terminal_diagnostic(
                    analysis::decompiler_diagnostic_code_t::provider_failure,
                    "workbench.pseudocode.worker_exception", true));
            }
            std::lock_guard<std::mutex> lock(registry->mutex);
            const auto found = registry->jobs.find(job_id);
            if (found == registry->jobs.end())
                return;
            if (found->second.payload)
                return;
            if (found->second.cancelled && payload.succeeded) {
                payload = {};
                payload.diagnostics.push_back(pseudocode_terminal_diagnostic(
                    analysis::decompiler_diagnostic_code_t::cancelled,
                    "workbench.pseudocode.cancelled", true));
            }
            found->second.payload = std::move(payload);
        };
        const auto submitted = aida::infra::executor::submit(
            std::move(submission));
        if (!submitted.submitted) {
            std::lock_guard<std::mutex> lock(jobs_->mutex);
            jobs_->jobs.erase(job_id);
            return shell_error(workbench_error_code_t::adapter_rejected,
                               job_id);
        }
        {
            std::lock_guard<std::mutex> lock(jobs_->mutex);
            const auto found = jobs_->jobs.find(job_id);
            if (found != jobs_->jobs.end())
                found->second.task_id = submitted.task_id;
        }
        return {};
    }

    workbench_error_t cancel_decompilation(std::uint64_t job_id) override
    {
        std::uint64_t task_id = 0;
        {
            std::lock_guard<std::mutex> lock(jobs_->mutex);
            const auto found = jobs_->jobs.find(job_id);
            if (found == jobs_->jobs.end())
                return shell_error(workbench_error_code_t::adapter_rejected, job_id);
            found->second.cancelled = true;
            found->second.cancellation->request_cancel();
            task_id = found->second.task_id;
        }
        if (task_id != 0)
            static_cast<void>(aida::infra::executor::cancel(task_id));
        return {};
    }

    bool poll_result(std::uint64_t job_id,
                     analysis::decompiler_document_t& output) override
    {
        output = {};
        std::lock_guard<std::mutex> lock(jobs_->mutex);
        auto found = jobs_->jobs.find(job_id);
        if (found == jobs_->jobs.end() || !found->second.payload ||
            !found->second.payload->succeeded)
            return false;
        output = std::move(found->second.payload->document);
        jobs_->jobs.erase(found);
        return true;
    }

    bool poll_failure(
        std::uint64_t job_id,
        std::vector<analysis::decompiler_diagnostic_t>& output) override
    {
        output.clear();
        std::lock_guard<std::mutex> lock(jobs_->mutex);
        auto found = jobs_->jobs.find(job_id);
        if (found == jobs_->jobs.end() || !found->second.payload ||
            found->second.payload->succeeded)
            return false;
        output = std::move(found->second.payload->diagnostics);
        jobs_->jobs.erase(found);
        return true;
    }

    bool job_active(std::uint64_t job_id) const noexcept override
    {
        try {
            std::lock_guard<std::mutex> lock(jobs_->mutex);
            auto found = jobs_->jobs.find(job_id);
            if (found == jobs_->jobs.end() || found->second.payload)
                return false;
            if (found->second.cancellation &&
                found->second.cancellation->token().stop_requested()) {
                pseudocode_job_payload_t payload;
                const bool deadline = found->second.cancellation->token().deadline_exceeded();
                payload.diagnostics.push_back(pseudocode_terminal_diagnostic(
                    deadline
                        ? analysis::decompiler_diagnostic_code_t::deadline_exceeded
                        : analysis::decompiler_diagnostic_code_t::cancelled,
                    deadline
                        ? "workbench.pseudocode.deadline_exceeded"
                        : "workbench.pseudocode.cancelled",
                    !deadline));
                found->second.payload = std::move(payload);
                return false;
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    analysis::decompiler_profile_budget_t profile_budget(
        analysis::decompiler_profile_id_t profile) const noexcept override
    {
        switch (profile) {
            case analysis::decompiler_profile_id_t::fast:
                return policy_.fast;
            case analysis::decompiler_profile_id_t::balanced:
                return policy_.balanced;
            case analysis::decompiler_profile_id_t::thorough:
                return policy_.thorough;
        }
        return {};
    }

private:
    struct job_state_t final {
        std::shared_ptr<analysis::cancellation_source_t> cancellation;
        std::uint64_t task_id = 0;
        std::optional<pseudocode_job_payload_t> payload;
        bool cancelled = false;
    };

    struct job_registry_t final {
        std::mutex mutex;
        std::map<std::uint64_t, job_state_t> jobs;
        bool shutting_down = false;
    };

    static void reap_cancelled_locked(job_registry_t& registry)
    {
        for (auto iterator = registry.jobs.begin();
             iterator != registry.jobs.end();) {
            if (!iterator->second.cancelled || !iterator->second.payload) {
                ++iterator;
                continue;
            }
            iterator = registry.jobs.erase(iterator);
        }
    }

    analysis_document_lease_t lease_;
    analysis::decompiler_profile_policy_t policy_;
    std::shared_ptr<analysis::decompiler_ui_integration_t> decompiler_;
    std::shared_ptr<job_registry_t> jobs_;
};
#endif

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
using workbench_pseudocode_source_t =
    aida::preview::synchronous_pseudocode_source_adapter_t;
#else
using workbench_pseudocode_source_t = production_pseudocode_source_t;
#endif

class production_pseudocode_navigation_t final
    : public pseudocode_document::pseudocode_navigation_adapter_t {
public:
    workbench_error_t resolve_address_to_token(
        std::uint64_t address,
        const analysis::decompiler_document_t& document,
        pseudocode_document::pseudocode_address_map_entry_t& output) const override
    {
        output = {};
        for (const auto& source_map : document.source_maps) {
            for (const auto& coordinate : source_map.coordinates) {
                if (!coordinate.address_range ||
                    coordinate.address_range->end.value <=
                        coordinate.address_range->begin.value ||
                    address < coordinate.address_range->begin.value ||
                    address >= coordinate.address_range->end.value)
                    continue;
                output.address = coordinate.address_range->begin.value;
                output.extent = coordinate.address_range->end.value -
                                coordinate.address_range->begin.value;
                output.token_begin = source_map.document_range.begin;
                output.token_end = source_map.document_range.end;
                if (output.token_begin >= output.token_end ||
                    output.token_end > document.rendered_text.size())
                    return shell_error(workbench_error_code_t::invalid_navigation,
                                       address);
                output.line_number = 1U + static_cast<std::uint32_t>(std::count(
                    document.rendered_text.begin(),
                    document.rendered_text.begin() +
                        static_cast<std::string::difference_type>(output.token_begin),
                    '\n'));
                return {};
            }
        }
        return shell_error(workbench_error_code_t::invalid_navigation, address);
    }

    workbench_error_t resolve_token_to_address(
        std::uint32_t token_begin,
        const analysis::decompiler_document_t& document,
        pseudocode_document::pseudocode_address_map_entry_t& output) const override
    {
        output = {};
        for (const auto& source_map : document.source_maps) {
            if (token_begin < source_map.document_range.begin ||
                token_begin >= source_map.document_range.end)
                continue;
            for (const auto& coordinate : source_map.coordinates) {
                if (!coordinate.address_range ||
                    coordinate.address_range->end.value <=
                        coordinate.address_range->begin.value)
                    continue;
                output.address = coordinate.address_range->begin.value;
                output.extent = coordinate.address_range->end.value -
                                coordinate.address_range->begin.value;
                output.token_begin = source_map.document_range.begin;
                output.token_end = source_map.document_range.end;
                if (output.token_begin >= output.token_end ||
                    output.token_end > document.rendered_text.size())
                    return shell_error(workbench_error_code_t::invalid_navigation,
                                       token_begin);
                output.line_number = 1U + static_cast<std::uint32_t>(std::count(
                    document.rendered_text.begin(),
                    document.rendered_text.begin() +
                        static_cast<std::string::difference_type>(output.token_begin),
                    '\n'));
                return {};
            }
        }
        return shell_error(workbench_error_code_t::invalid_navigation, token_begin);
    }
};

class production_document_bundle_t final {
public:
    production_document_bundle_t(
        analysis_document_lease_t lease,
        std::shared_ptr<workbench_document_bridge_t> bridge,
        std::shared_ptr<workbench_analysis_source_catalog_t> catalog,
        const workbench_shell_integration_config_t& config)
        : source_(lease.source),
          bridge_(std::move(bridge)),
          disasm_source_(lease),
          disasm_overlay_(source_, disasm_source_),
          disasm_navigation_(bridge_),
          disasm_model_(disasm_source_, &disasm_overlay_, &disasm_navigation_),
          hex_source_(lease),
          hex_overlay_(source_, hex_source_),
          hex_navigation_(bridge_),
          hex_model_(hex_source_, &hex_overlay_, &hex_navigation_),
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
          pseudocode_source_(lease.source
              ? lease.source->analysis_workspace() : nullptr),
#else
          pseudocode_source_(lease),
#endif
          pseudocode_navigation_(),
          pseudocode_model_(pseudocode_source_, &pseudocode_navigation_),
          graph_source_(lease, config.cached_graph_scope_limit),
          graph_overlay_(source_, graph_source_),
          graph_model_(graph_source_, &graph_overlay_),
          diff_source_(lease, std::move(catalog),
                       config.cached_diff_scope_limit,
                       config.materialized_diff_entry_limit),
          diff_model_(diff_source_),
          generation_(lease.publication->generation),
          analysis_revision_(lease.publication->analysis_revision)
    {
    }

    static std::vector<document_descriptor_t> descriptors(workspace_id_t workspace)
    {
        std::vector<document_descriptor_t> result;
        result.reserve(5);
        const auto append = [&result, workspace](document_kind_t kind,
                                                 const char* title) {
            document_descriptor_t descriptor;
            descriptor.identity.workspace = workspace;
            descriptor.identity.kind = kind;
            descriptor.identity.object_id = 1;
            descriptor.identity.provider_key = "analysis";
            descriptor.title = title;
            descriptor.can_open = true;
            result.push_back(std::move(descriptor));
        };
        append(document_kind_t::disassembly, "Disassembly");
        append(document_kind_t::hex, "Hex");
        append(document_kind_t::pseudocode, "Pseudocode");
        append(document_kind_t::graph, "Graph");
        append(document_kind_t::diff, "Diff");
        return result;
    }

    std::uint64_t generation() const noexcept { return generation_; }
    std::uint64_t analysis_revision() const noexcept { return analysis_revision_; }
    std::uint64_t overlay_revision() const noexcept
    {
        return source_->current_overlay_revision(generation_);
    }

    disasm_document::disasm_document_model_t* disassembly() noexcept
    {
        return &disasm_model_;
    }

    hex_document::hex_document_model_t* hex() noexcept { return &hex_model_; }

    pseudocode_document::pseudocode_document_model_t* pseudocode() noexcept
    {
        return &pseudocode_model_;
    }

    graph_document::graph_document_model_t* graph() noexcept
    {
        return &graph_model_;
    }

    diff_document::diff_document_model_t* diff() noexcept
    {
        return &diff_model_;
    }

private:
    std::shared_ptr<workbench_analysis_source_t> source_;
    std::shared_ptr<workbench_document_bridge_t> bridge_;
    production_disasm_source_t disasm_source_;
    production_disasm_overlay_t disasm_overlay_;
    production_disasm_navigation_t disasm_navigation_;
    disasm_document::disasm_document_model_t disasm_model_;
    production_hex_source_t hex_source_;
    production_hex_overlay_t hex_overlay_;
    production_hex_navigation_t hex_navigation_;
    hex_document::hex_document_model_t hex_model_;
    workbench_pseudocode_source_t pseudocode_source_;
    production_pseudocode_navigation_t pseudocode_navigation_;
    pseudocode_document::pseudocode_document_model_t pseudocode_model_;
    production_graph_source_t graph_source_;
    production_graph_overlay_t graph_overlay_;
    graph_document::graph_document_model_t graph_model_;
    production_diff_source_t diff_source_;
    diff_document::diff_document_model_t diff_model_;
    std::uint64_t generation_;
    std::uint64_t analysis_revision_;
};

struct workspace_integration_state_t final {
    mutable std::mutex mutex;
    workspace_id_t workspace;
    workbench_shell_center_view_t center_view;
    workbench_persistence_dto_t persistence;
    std::shared_ptr<navigator::navigator_tree_model_t> navigator_tree;
    std::shared_ptr<navigator::navigator_query_model_t> navigator_query;
    std::shared_ptr<navigator::navigator_navigation_model_t> navigator_nav;
    std::shared_ptr<inspector::inspector_query_session_t> inspector_session;
    std::shared_ptr<document_registry_t> document_registry;
    std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace;
    std::shared_ptr<workbench_analysis_source_t> analysis_source;
    std::shared_ptr<production_document_bundle_t> documents;
    std::shared_ptr<workbench_document_bridge_t> bridge;
    std::shared_ptr<workbench_persistence_adapter_t> persistence_adapter;
    const navigator::navigator_packed_store_adapter_t* navigator_adapter = nullptr;
    std::optional<inspector::inspector_context_t> inspector_context;
};

struct workspace_context_lifetime_t final {
    std::shared_ptr<workspace_integration_state_t> state;
    std::shared_ptr<navigator::navigator_tree_model_t> navigator_tree;
    std::shared_ptr<navigator::navigator_query_model_t> navigator_query;
    std::shared_ptr<navigator::navigator_navigation_model_t> navigator_nav;
    std::shared_ptr<inspector::inspector_query_session_t> inspector_session;
    std::shared_ptr<document_registry_t> document_registry;
    std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace;
    std::shared_ptr<production_document_bundle_t> documents;
    std::shared_ptr<workbench_document_bridge_t> bridge;
};

struct integration_state_t final {
    workbench_model_t* model = nullptr;
    workbench_shell_integration_config_t config;
    std::shared_ptr<workbench_analysis_source_catalog_t> source_catalog;
    mutable std::mutex metrics_mutex;
    workbench_shell_metrics_t metrics;
    mutable std::mutex workspaces_mutex;
    std::unordered_map<std::uint64_t,
                       std::shared_ptr<workspace_integration_state_t>> workspace_states;

    explicit integration_state_t(workbench_model_t& mdl,
                                 workbench_shell_integration_config_t cfg)
        : model(&mdl),
          config(std::move(cfg)),
          source_catalog(production_source_catalog())
    {
    }
};

workbench_persistence_dto_t build_default_persistence(
    workspace_id_t workspace,
    std::uint32_t history_capacity) {
    workbench_persistence_dto_t dto;
    dto.schema_version = k_workbench_contract_schema_version;
    dto.workspace = workspace;
    dto.revision = workspace_revision_t{1};
    dto.active_document = document_id_t{1};
    dto.history.workspace = workspace;
    dto.history.capacity = std::min(history_capacity, k_max_history_capacity);
    document_persistence_dto_t default_doc;
    default_doc.id = document_id_t{1};
    default_doc.identity.workspace = workspace;
    default_doc.identity.kind = document_kind_t::disassembly;
    default_doc.identity.object_id = 1;
    default_doc.identity.provider_key = "analysis";
    default_doc.title = "Disassembly";
    default_doc.closeable = true;
    dto.documents.push_back(std::move(default_doc));
    view_persistence_dto_t default_view;
    default_view.id = view_id_t{1};
    default_view.workspace = workspace;
    default_view.document = document_id_t{1};
    default_view.role = view_role_t::primary;
    default_view.focused = true;
    dto.views.push_back(std::move(default_view));
    panel_state_dto_t navigator_panel;
    navigator_panel.id = panel_instance_id_t{1};
    navigator_panel.workspace = workspace;
    navigator_panel.kind = panel_kind_t::navigator;
    navigator_panel.visible = true;
    navigator_panel.revision = workspace_revision_t{1};
    dto.panels.push_back(std::move(navigator_panel));
    panel_state_dto_t inspector_panel;
    inspector_panel.id = panel_instance_id_t{2};
    inspector_panel.workspace = workspace;
    inspector_panel.kind = panel_kind_t::inspector;
    inspector_panel.visible = true;
    inspector_panel.revision = workspace_revision_t{1};
    dto.panels.push_back(std::move(inspector_panel));
    return dto;
}

}

struct workbench_shell_integration_t::impl_t {
    integration_state_t state;

    explicit impl_t(workbench_model_t& mdl,
                    workbench_shell_integration_config_t cfg)
        : state(mdl, std::move(cfg)) {}

    void increment_metric(
        std::uint64_t workbench_shell_metrics_t::*field,
        std::uint64_t delta = 1) noexcept {
        std::lock_guard<std::mutex> lock(state.metrics_mutex);
        state.metrics.*field += delta;
    }

    std::shared_ptr<workspace_integration_state_t> get_state(
        workspace_id_t workspace) {
        std::lock_guard<std::mutex> lock(state.workspaces_mutex);
        auto it = state.workspace_states.find(workspace.value);
        return it != state.workspace_states.end() ? it->second : nullptr;
    }

    std::shared_ptr<workspace_integration_state_t> ensure_state(
        workspace_id_t workspace) {
        std::lock_guard<std::mutex> lock(state.workspaces_mutex);
        auto it = state.workspace_states.find(workspace.value);
        if (it != state.workspace_states.end())
            return it->second;
        auto inserted = std::make_shared<workspace_integration_state_t>();
        inserted->workspace = workspace;
        inserted->center_view.workspace = workspace;
        inserted->center_view.default_document_kind = document_kind_t::disassembly;
        inserted->center_view.is_default = false;
        inserted->center_view.navigator_visible = true;
        inserted->center_view.inspector_visible = true;
        inserted->center_view.bottom_panel_visible = false;
        inserted->bridge = std::make_shared<workbench_document_bridge_t>(workspace);
        inserted->document_registry = std::make_shared<document_registry_t>(workspace);
        inserted->persistence = build_default_persistence(
            workspace, state.config.default_history_capacity);
        state.workspace_states.emplace(workspace.value, inserted);
        return inserted;
    }

    void fill_context(
        const std::shared_ptr<workspace_integration_state_t>& workspace_state,
        workbench_shell_workspace_context_t& output) const {
        output = {};
        if (!workspace_state)
            return;
        auto lifetime = std::make_shared<workspace_context_lifetime_t>();
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        lifetime->state = workspace_state;
        lifetime->navigator_tree = workspace_state->navigator_tree;
        lifetime->navigator_query = workspace_state->navigator_query;
        lifetime->navigator_nav = workspace_state->navigator_nav;
        lifetime->inspector_session = workspace_state->inspector_session;
        lifetime->document_registry = workspace_state->document_registry;
        lifetime->analysis_workspace = workspace_state->analysis_workspace;
        lifetime->documents = workspace_state->documents;
        lifetime->bridge = workspace_state->bridge;

        output.workspace = workspace_state->workspace;
        output.persistence = workspace_state->persistence;
        output.analysis_workspace = lifetime->analysis_workspace;
        output.center_view = workspace_state->center_view;
        if (state.config.integrate_navigator) {
            output.navigator_tree = lifetime->navigator_tree.get();
            output.navigator_query = lifetime->navigator_query.get();
            output.navigator_nav = lifetime->navigator_nav.get();
        }
        if (state.config.integrate_inspector)
            output.inspector_session = lifetime->inspector_session.get();
        output.document_registry = lifetime->document_registry.get();
        output.document_bridge = lifetime->bridge.get();
        if (lifetime->documents) {
            output.disassembly_document = lifetime->documents->disassembly();
            output.hex_document = lifetime->documents->hex();
            output.pseudocode_document = lifetime->documents->pseudocode();
            output.graph_document = lifetime->documents->graph();
            output.diff_document = lifetime->documents->diff();
            output.analysis_generation = lifetime->documents->generation();
            output.analysis_revision = lifetime->documents->analysis_revision();
            output.overlay_revision = lifetime->documents->overlay_revision();
        }
        output.lifetime = std::static_pointer_cast<const void>(lifetime);
    }

    workbench_error_t remember_snapshot(
        const std::shared_ptr<workspace_integration_state_t>& workspace_state,
        const workbench_snapshot_ptr_t& snapshot) const {
        if (!workspace_state || !snapshot)
            return shell_error(workbench_error_code_t::invalid_workspace);
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        if (!workspace_state->document_registry)
            workspace_state->document_registry =
                std::make_shared<document_registry_t>(workspace_state->workspace);
        const auto registry_error = workspace_state->document_registry->restore(
            snapshot->persistence().documents);
        if (!registry_error)
            return registry_error;
        workspace_state->persistence = snapshot->persistence();
        return {};
    }

    workbench_error_t rebuild_documents(
        const std::shared_ptr<workspace_integration_state_t>& workspace_state,
        const std::shared_ptr<workbench_analysis_source_t>& source) const {
        if (!workspace_state || !source || !source->capture_current())
            return shell_error(workbench_error_code_t::adapter_rejected);
        const auto publication = source->current_publication();
        if (!publication || !publication->snapshot ||
            publication->generation == 0)
            return shell_error(workbench_error_code_t::adapter_rejected);
        std::shared_ptr<workbench_document_bridge_t> bridge;
        {
            std::lock_guard<std::mutex> lock(workspace_state->mutex);
            bridge = workspace_state->bridge;
        }
        if (!bridge)
            return shell_error(workbench_error_code_t::adapter_rejected);

        analysis_document_lease_t lease;
        lease.source = source;
        lease.publication = publication;
        std::shared_ptr<production_document_bundle_t> documents;
        try {
            documents = std::make_shared<production_document_bundle_t>(
                std::move(lease), bridge, state.source_catalog, state.config);
        } catch (...) {
            return shell_error(workbench_error_code_t::adapter_rejected,
                               publication->generation);
        }
        const auto bridge_error = bridge->replace(
            production_document_bundle_t::descriptors(workspace_state->workspace));
        if (!bridge_error)
            return bridge_error;
        if (!source->publication_current(publication))
            return shell_error(workbench_error_code_t::revision_mismatch,
                               publication->generation);
        {
            std::lock_guard<std::mutex> lock(workspace_state->mutex);
            workspace_state->analysis_source = source;
            workspace_state->analysis_workspace = source->analysis_workspace();
            workspace_state->documents = std::move(documents);
        }
        return {};
    }
};

workbench_shell_integration_t::workbench_shell_integration_t(
    std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)),
      config_(impl_ ? impl_->state.config : workbench_shell_integration_config_t{}) {}

workbench_shell_integration_t::~workbench_shell_integration_t() = default;

std::shared_ptr<workbench_shell_integration_t>
workbench_shell_integration_t::create(
    workbench_model_t& model,
    workbench_shell_integration_config_t config) {
    if (config.default_history_capacity == 0 ||
        config.default_history_capacity > k_max_history_capacity ||
        config.retained_generation_limit == 0 ||
        config.retained_overlay_revision_limit == 0 ||
        config.cached_graph_scope_limit == 0 ||
        config.cached_diff_scope_limit == 0 ||
        config.materialized_diff_entry_limit == 0 ||
        config.materialized_diff_entry_limit >
            diff_document::k_diff_document_max_entries)
        return {};
    try {
        auto impl = std::make_unique<impl_t>(model, std::move(config));
        return std::shared_ptr<workbench_shell_integration_t>(
            new workbench_shell_integration_t(std::move(impl)));
    } catch (...) {
        return {};
    }
}

workbench_error_t
workbench_shell_integration_t::append_center_view(
    workspace_id_t workspace,
    const workbench_shell_center_view_t& center_view,
    workbench_snapshot_ptr_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    auto ws_state = impl_->ensure_state(workspace);
    {
        std::lock_guard<std::mutex> lock(ws_state->mutex);
        ws_state->center_view = center_view;
        ws_state->center_view.workspace = workspace;
    }
    impl_->increment_metric(&workbench_shell_metrics_t::center_views_appended);
    auto snapshot_result = impl_->state.model->snapshot(workspace, output);
    if (!snapshot_result.ok())
        return snapshot_result;
    return impl_->remember_snapshot(ws_state, output);
}

workbench_error_t
workbench_shell_integration_t::make_default_for_analysis(
    workspace_id_t workspace,
    workbench_snapshot_ptr_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.make_default_for_analysis_workspaces)
        return workbench_error_t{};
    auto ws_state = impl_->ensure_state(workspace);
    {
        std::lock_guard<std::mutex> lock(ws_state->mutex);
        ws_state->center_view.is_default = true;
        ws_state->center_view.default_document_kind = document_kind_t::disassembly;
        ws_state->center_view.navigator_visible = true;
        ws_state->center_view.inspector_visible = true;
    }
    impl_->increment_metric(&workbench_shell_metrics_t::workspaces_created);
    auto snapshot_result = impl_->state.model->snapshot(workspace, output);
    if (!snapshot_result.ok())
        return snapshot_result;
    return impl_->remember_snapshot(ws_state, output);
}

workbench_error_t
workbench_shell_integration_t::restore_workspace_context(
    workspace_id_t workspace,
    workspace_revision_t expected_revision,
    const workbench_persistence_dto_t& persisted,
    const document_catalog_adapter_t& catalog,
    missing_document_policy_t policy,
    workbench_shell_workspace_context_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.restore_per_workspace_context)
        return workbench_error_t{};
    auto restore_result = impl_->state.model->restore_workspace(
        workspace, expected_revision, persisted, catalog, policy);
    if (!restore_result.error.ok()) {
        impl_->increment_metric(&workbench_shell_metrics_t::context_restore_failures);
        return restore_result.error;
    }
    auto ws_state = impl_->ensure_state(workspace);
    const auto remember_error = impl_->remember_snapshot(
        ws_state, restore_result.snapshot);
    if (!remember_error) {
        impl_->increment_metric(&workbench_shell_metrics_t::context_restore_failures);
        return remember_error;
    }
    impl_->fill_context(ws_state, output);
    impl_->increment_metric(&workbench_shell_metrics_t::workspaces_restored);
    impl_->increment_metric(&workbench_shell_metrics_t::context_restores);
    if (impl_->state.config.preserve_commands)
        impl_->increment_metric(&workbench_shell_metrics_t::commands_preserved);
    if (impl_->state.config.preserve_shortcuts)
        impl_->increment_metric(&workbench_shell_metrics_t::shortcuts_preserved);
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::integrate_navigator(
    workspace_id_t workspace,
    const navigator::navigator_packed_store_adapter_t& adapter) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.integrate_navigator)
        return workbench_error_t{};
    auto ws_state = impl_->ensure_state(workspace);
    auto tree = std::make_shared<navigator::navigator_tree_model_t>(adapter);
    auto query = std::make_shared<navigator::navigator_query_model_t>(adapter);
    auto navigation = std::make_shared<navigator::navigator_navigation_model_t>(
        adapter, workspace, navigation_event_id_t{1}, 1, true, nullptr);
    {
        std::lock_guard<std::mutex> lock(ws_state->mutex);
        ws_state->navigator_adapter = &adapter;
        ws_state->navigator_tree = std::move(tree);
        ws_state->navigator_query = std::move(query);
        ws_state->navigator_nav = std::move(navigation);
    }
    impl_->increment_metric(&workbench_shell_metrics_t::navigator_integrations);
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::integrate_inspector(
    workspace_id_t workspace,
    const inspector::inspector_context_t& context) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.integrate_inspector)
        return workbench_error_t{};
    auto ws_state = impl_->ensure_state(workspace);
    std::shared_ptr<inspector::inspector_query_session_t> session;
    {
        std::lock_guard<std::mutex> lock(ws_state->mutex);
        session = ws_state->inspector_session;
    }
    if (!session)
        session = std::make_shared<inspector::inspector_query_session_t>();
    auto activate = session->activate(context);
    if (!activate.ok())
        return inspector_shell_error(activate);
    {
        std::lock_guard<std::mutex> lock(ws_state->mutex);
        ws_state->inspector_context = context;
        ws_state->inspector_session = std::move(session);
    }
    impl_->increment_metric(&workbench_shell_metrics_t::inspector_integrations);
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::integrate_analysis_workspace(
    workspace_id_t workspace,
    std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace) {
    if (!impl_ || !workspace.valid())
        return shell_error(workbench_error_code_t::invalid_workspace);
    if (!analysis_workspace || analysis_workspace->closing() ||
        analysis_workspace->closed())
        return shell_error(workbench_error_code_t::adapter_rejected,
                           workspace.value);
    std::shared_ptr<workbench_persistence_adapter_t> persistence;
    if (impl_->state.config.integrate_persistence) {
        const auto database = analysis_workspace->database();
        if (!database)
            return shell_error(workbench_error_code_t::adapter_rejected,
                               workspace.value);
        try {
            persistence = std::make_shared<
                workspace_database_workbench_persistence_adapter_t>(
                    database, workspace);
        } catch (...) {
            return shell_error(workbench_error_code_t::adapter_rejected,
                               workspace.value);
        }
    }
    auto workspace_state = impl_->ensure_state(workspace);
    if (!impl_->state.config.integrate_analysis_documents) {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        workspace_state->analysis_workspace = std::move(analysis_workspace);
        workspace_state->persistence_adapter = std::move(persistence);
        return {};
    }
    std::shared_ptr<workbench_analysis_source_t> source;
    {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        if (workspace_state->analysis_source &&
            workspace_state->analysis_workspace == analysis_workspace)
            source = workspace_state->analysis_source;
    }
    if (!source) {
        try {
            source = std::make_shared<workbench_analysis_source_t>(
                workspace, analysis_workspace,
                impl_->state.config.retained_generation_limit,
                impl_->state.config.retained_overlay_revision_limit);
        } catch (...) {
            return shell_error(workbench_error_code_t::adapter_rejected,
                               workspace.value);
        }
    }
    if (!impl_->state.source_catalog->publish(
            workspace, analysis_workspace->identity().binary_id(), source))
        return shell_error(workbench_error_code_t::duplicate_identifier,
                           workspace.value);
    const auto rebuild_error = impl_->rebuild_documents(workspace_state, source);
    if (!rebuild_error)
        return rebuild_error;
    if (impl_->state.config.integrate_navigator) {
        const auto navigator_error = integrate_navigator(workspace, *source);
        if (!navigator_error)
            return navigator_error;
    }
    if (impl_->state.config.integrate_inspector) {
        const auto publication = source->current_publication();
        if (!publication)
            return shell_error(workbench_error_code_t::adapter_rejected,
                               workspace.value);
        const auto context_revision = (std::max<std::uint64_t>)(
            1U, publication->analysis_revision);
        inspector::inspector_context_t context;
        context.workspace = workspace;
        context.workspace_generation = workspace_revision_t{context_revision};
        context.document.workspace = workspace;
        context.document.kind = document_kind_t::disassembly;
        context.document.object_id = 1;
        context.document.provider_key = "analysis";
        context.selection_generation = context_revision;
        const auto inspector_error = integrate_inspector(workspace, context);
        if (!inspector_error)
            return inspector_error;
    }
    {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        workspace_state->persistence_adapter = std::move(persistence);
    }
    impl_->increment_metric(
        &workbench_shell_metrics_t::analysis_document_integrations);
    return {};
}

workbench_error_t
workbench_shell_integration_t::refresh_analysis_documents(
    workspace_id_t workspace) {
    if (!impl_ || !workspace.valid())
        return shell_error(workbench_error_code_t::invalid_workspace);
    auto workspace_state = impl_->get_state(workspace);
    if (!workspace_state)
        return shell_error(workbench_error_code_t::invalid_workspace,
                           workspace.value);
    std::shared_ptr<workbench_analysis_source_t> source;
    std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace;
    {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        source = workspace_state->analysis_source;
        analysis_workspace = workspace_state->analysis_workspace;
    }
    if (!analysis_workspace)
        return shell_error(workbench_error_code_t::adapter_rejected,
                           workspace.value);
    std::shared_ptr<workbench_persistence_adapter_t> persistence;
    if (impl_->state.config.integrate_persistence) {
        const auto database = analysis_workspace->database();
        if (!database)
            return shell_error(workbench_error_code_t::adapter_rejected,
                               workspace.value);
        try {
            persistence = std::make_shared<
                workspace_database_workbench_persistence_adapter_t>(
                    database, workspace);
        } catch (...) {
            return shell_error(workbench_error_code_t::adapter_rejected,
                               workspace.value);
        }
    }
    if (!impl_->state.config.integrate_analysis_documents) {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        workspace_state->persistence_adapter = std::move(persistence);
        return {};
    }
    if (!source)
        return shell_error(workbench_error_code_t::adapter_rejected,
                           workspace.value);
    const auto rebuild_error = impl_->rebuild_documents(workspace_state, source);
    if (!rebuild_error)
        return rebuild_error;
    {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        workspace_state->persistence_adapter = std::move(persistence);
    }
    impl_->increment_metric(
        &workbench_shell_metrics_t::analysis_document_refreshes);
    return {};
}

workbench_error_t
workbench_shell_integration_t::restore_persisted_workspace_context(
    workspace_id_t workspace,
    workspace_revision_t expected_revision,
    missing_document_policy_t policy,
    workbench_shell_workspace_context_t& output) {
    output = {};
    if (!impl_ || !workspace.valid())
        return shell_error(workbench_error_code_t::invalid_workspace);
    if (!impl_->state.config.integrate_persistence)
        return shell_error(workbench_error_code_t::adapter_rejected,
                           workspace.value);
    auto workspace_state = impl_->get_state(workspace);
    if (!workspace_state)
        return shell_error(workbench_error_code_t::invalid_workspace,
                           workspace.value);
    std::shared_ptr<workbench_persistence_adapter_t> persistence;
    std::shared_ptr<workbench_document_bridge_t> bridge;
    {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        persistence = workspace_state->persistence_adapter;
        bridge = workspace_state->bridge;
    }
    if (!persistence || !bridge)
        return shell_error(workbench_error_code_t::adapter_rejected,
                           workspace.value);
    workbench_persistence_dto_t persisted;
    const auto load_error = persistence->load(workspace, persisted);
    if (!load_error) {
        impl_->increment_metric(&workbench_shell_metrics_t::persistence_failures);
        return load_error;
    }
    for (const auto& document : persisted.documents) {
        document_descriptor_t descriptor;
        if (analysis_document_descriptor(document.identity, descriptor)) {
            const auto publish_error = bridge->publish(std::move(descriptor));
            if (!publish_error) {
                impl_->increment_metric(
                    &workbench_shell_metrics_t::persistence_failures);
                return publish_error;
            }
        }
    }
    impl_->increment_metric(&workbench_shell_metrics_t::persistence_loads);
    return restore_workspace_context(workspace, expected_revision, persisted,
                                     *bridge, policy, output);
}

workbench_error_t
workbench_shell_integration_t::store_workspace_context(
    workspace_id_t workspace,
    workspace_revision_t expected_revision) {
    if (!impl_ || !workspace.valid())
        return shell_error(workbench_error_code_t::invalid_workspace);
    if (!impl_->state.config.integrate_persistence)
        return shell_error(workbench_error_code_t::adapter_rejected,
                           workspace.value);
    auto workspace_state = impl_->get_state(workspace);
    if (!workspace_state)
        return shell_error(workbench_error_code_t::invalid_workspace,
                           workspace.value);
    std::shared_ptr<workbench_persistence_adapter_t> persistence;
    {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        persistence = workspace_state->persistence_adapter;
    }
    if (!persistence)
        return shell_error(workbench_error_code_t::adapter_rejected,
                           workspace.value);
    workbench_snapshot_ptr_t snapshot;
    const auto snapshot_error = impl_->state.model->snapshot(workspace, snapshot);
    if (!snapshot_error)
        return snapshot_error;
    if (snapshot->revision() != expected_revision)
        return shell_error(workbench_error_code_t::revision_mismatch,
                           snapshot->revision().value);
    const auto store_error = persistence->store(snapshot->persistence());
    if (!store_error) {
        impl_->increment_metric(&workbench_shell_metrics_t::persistence_failures);
        return store_error;
    }
    const auto remember_error = impl_->remember_snapshot(workspace_state, snapshot);
    if (!remember_error)
        return remember_error;
    impl_->increment_metric(&workbench_shell_metrics_t::persistence_stores);
    return {};
}

workbench_error_t
workbench_shell_integration_t::dispatch_command(
    const workbench_command_t& command,
    const workbench_services_t& services,
    workbench_command_result_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    auto effective_services = services;
    const auto workspace_state = impl_->get_state(command.workspace);
    if (workspace_state) {
        std::lock_guard<std::mutex> lock(workspace_state->mutex);
        if (!effective_services.documents)
            effective_services.documents = workspace_state->bridge.get();
        if (!effective_services.navigation)
            effective_services.navigation = workspace_state->bridge.get();
    }
    output = impl_->state.model->execute(command, effective_services);
    if (!output.error || !workspace_state || !output.snapshot)
        return output.error;
    const auto remember_error = impl_->remember_snapshot(
        workspace_state, output.snapshot);
    if (!remember_error) {
        output.error = remember_error;
        return remember_error;
    }
    if (command.kind == workbench_command_kind_t::navigate)
        impl_->increment_metric(&workbench_shell_metrics_t::navigation_dispatches);
    return output.error;
}

workbench_error_t
workbench_shell_integration_t::dispatch_navigation(
    workspace_id_t workspace,
    workspace_revision_t expected_revision,
    const navigation_event_t& navigation,
    workbench_command_result_t& output) {
    if (!impl_ || !workspace.valid() || navigation.workspace != workspace)
        return shell_error(workbench_error_code_t::invalid_navigation,
                           navigation.id.value);
    workbench_command_t command;
    command.kind = workbench_command_kind_t::navigate;
    command.workspace = workspace;
    command.expected_revision = expected_revision;
    command.navigation = navigation;
    command.request_focus = navigation.request_focus;
    const auto dispatched = dispatch_command(command, {}, output);
    if (!dispatched || !output.snapshot ||
        !impl_->state.config.integrate_inspector)
        return dispatched;
    inspector::inspector_context_t context;
    context.workspace = workspace;
    context.workspace_generation = output.snapshot->revision();
    context.document = navigation.target.document;
    context.selection = navigation.target.selection;
    context.selection_generation = output.snapshot->revision().value;
    const auto inspector_error = integrate_inspector(workspace, context);
    if (!inspector_error) {
        output.error = inspector_error;
        return inspector_error;
    }
    return dispatched;
}

std::vector<workspace_id_t>
workbench_shell_integration_t::managed_workspaces() const {
    if (!impl_)
        return {};
    std::lock_guard<std::mutex> lock(impl_->state.workspaces_mutex);
    std::vector<workspace_id_t> result;
    result.reserve(impl_->state.workspace_states.size());
    for (const auto& [id, state] : impl_->state.workspace_states) {
        static_cast<void>(id);
        result.push_back(state->workspace);
    }
    std::sort(result.begin(), result.end(),
        [](workspace_id_t lhs, workspace_id_t rhs) {
            return lhs.value < rhs.value;
        });
    return result;
}

bool
workbench_shell_integration_t::has_workspace_context(
    workspace_id_t workspace) const noexcept {
    if (!impl_)
        return false;
    std::lock_guard<std::mutex> lock(impl_->state.workspaces_mutex);
    return impl_->state.workspace_states.find(workspace.value) !=
        impl_->state.workspace_states.end();
}

const workbench_shell_workspace_context_t*
workbench_shell_integration_t::workspace_context(
    workspace_id_t workspace) const {
    if (!impl_)
        return nullptr;
    auto workspace_state = impl_->get_state(workspace);
    if (!workspace_state)
        return nullptr;
    static thread_local workbench_shell_workspace_context_t context;
    impl_->fill_context(workspace_state, context);
    return &context;
}

workbench_shell_metrics_t
workbench_shell_integration_t::metrics() const noexcept {
    if (!impl_)
        return {};
    std::lock_guard<std::mutex> lock(impl_->state.metrics_mutex);
    return impl_->state.metrics;
}

workbench_persistence_dto_t
workbench_shell_integration_t::create_default_persistence(
    workspace_id_t workspace,
    std::uint32_t history_capacity) {
    return build_default_persistence(workspace, history_capacity);
}

namespace {

struct workbench_runtime_binding_t final {
    std::mutex lifecycle_mutex;
    std::mutex persistence_mutex;
    analysis::binary_id_t binary_id;
    workspace_id_t workspace;
    std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace;
    std::unique_ptr<workbench_model_t> model;
    std::shared_ptr<workbench_shell_integration_t> shell;
    bool integrated = false;
    bool restored = false;
    bool closing = false;
    std::atomic<std::uint64_t> dirty_revision{0};
    std::atomic<std::uint64_t> persisted_revision{0};
    std::atomic<bool> persistence_scheduled{false};
    std::atomic<std::uint64_t> next_navigation_id{1};
};

workspace_id_t runtime_workspace_id(const analysis::binary_id_t& binary_id) noexcept
{
    std::uint64_t value = k_shell_fnv_offset;
    for (const auto byte : binary_id.bytes) {
        value ^= byte;
        value *= k_shell_fnv_prime;
    }
    if (value == 0)
        value = 1;
    return workspace_id_t{value};
}

const document_persistence_dto_t* active_document(
    const workbench_persistence_dto_t& persistence) noexcept
{
    const auto found = std::find_if(
        persistence.documents.begin(), persistence.documents.end(),
        [&persistence](const document_persistence_dto_t& document) {
            return document.id == persistence.active_document;
        });
    return found != persistence.documents.end() ? &*found : nullptr;
}

void raise_dirty_revision(
    const std::shared_ptr<workbench_runtime_binding_t>& binding,
    std::uint64_t revision) noexcept
{
    auto observed = binding->dirty_revision.load(std::memory_order_acquire);
    while (observed < revision &&
           !binding->dirty_revision.compare_exchange_weak(
               observed, revision, std::memory_order_acq_rel,
               std::memory_order_acquire)) {
    }
}

void schedule_runtime_persistence(
    const std::shared_ptr<workbench_runtime_binding_t>& binding);

void persist_runtime_binding(
    const std::shared_ptr<workbench_runtime_binding_t>& binding)
{
    const auto attempted_dirty_revision =
        binding->dirty_revision.load(std::memory_order_acquire);
    std::unique_lock<std::mutex> persistence_lock(binding->persistence_mutex);
    bool allow_reschedule = true;
    for (std::uint32_t attempt = 0; attempt != 16U; ++attempt) {
        workbench_shell_workspace_context_t context;
        {
            std::lock_guard<std::mutex> lifecycle_lock(binding->lifecycle_mutex);
            if (!binding->integrated || !binding->shell) {
                allow_reschedule = false;
                break;
            }
            const auto* current =
                binding->shell->workspace_context(binding->workspace);
            if (!current) {
                allow_reschedule = false;
                break;
            }
            context = *current;
        }
        const auto revision = context.persistence.revision.value;
        if (revision == 0) {
            allow_reschedule = false;
            break;
        }
        if (revision <= binding->persisted_revision.load(
                std::memory_order_acquire))
            break;
        const auto stored = binding->shell->store_workspace_context(
            binding->workspace, context.persistence.revision);
        if (!stored) {
            if (stored.code == workbench_error_code_t::revision_mismatch)
                continue;
            diag::log_tagged_fmt(
                "workbench_shell",
                "persistence_store_failed workspace=%llu revision=%llu code=%u subject=%llu",
                static_cast<unsigned long long>(binding->workspace.value),
                static_cast<unsigned long long>(revision),
                static_cast<unsigned>(stored.code),
                static_cast<unsigned long long>(stored.subject));
            allow_reschedule = false;
            break;
        }
        binding->persisted_revision.store(revision, std::memory_order_release);
        if (binding->dirty_revision.load(std::memory_order_acquire) <= revision)
            break;
    }
    persistence_lock.unlock();
    binding->persistence_scheduled.store(false, std::memory_order_release);
    bool closing = false;
    {
        std::lock_guard<std::mutex> lifecycle_lock(binding->lifecycle_mutex);
        closing = binding->closing;
    }
    const auto current_dirty_revision =
        binding->dirty_revision.load(std::memory_order_acquire);
    if (!closing &&
        (allow_reschedule ||
         current_dirty_revision > attempted_dirty_revision) &&
        current_dirty_revision >
            binding->persisted_revision.load(std::memory_order_acquire))
        schedule_runtime_persistence(binding);
}

void schedule_runtime_persistence(
    const std::shared_ptr<workbench_runtime_binding_t>& binding)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    binding->persisted_revision.store(
        binding->dirty_revision.load(std::memory_order_acquire),
        std::memory_order_release);
    binding->persistence_scheduled.store(false, std::memory_order_release);
#else
    bool expected = false;
    if (!binding->persistence_scheduled.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel,
            std::memory_order_acquire))
        return;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "workbench_shell";
    submission.label = "workbench.persist";
    submission.thread_class = "bounded_io";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.generation = binding->dirty_revision.load(
        std::memory_order_acquire);
    submission.ui_access_policy = "forbidden";
    submission.failure_policy = "retain_dirty_state";
    submission.shutdown_policy = "drain";
    submission.body = [binding] { persist_runtime_binding(binding); };
    const auto submitted =
        aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        binding->persistence_scheduled.store(false, std::memory_order_release);
        diag::log_tagged_fmt(
            "workbench_shell",
            "persistence_submit_failed workspace=%llu reason=%s",
            static_cast<unsigned long long>(binding->workspace.value),
            submitted.reject_reason.c_str());
    }
#endif
}

void mark_runtime_dirty(
    const std::shared_ptr<workbench_runtime_binding_t>& binding,
    std::uint64_t revision)
{
    raise_dirty_revision(binding, revision);
    schedule_runtime_persistence(binding);
}

workbench_error_t synchronize_runtime_documents(
    const std::shared_ptr<workbench_runtime_binding_t>& binding,
    workbench_shell_workspace_context_t& output)
{
    const auto publication =
        binding->analysis_workspace->analysis_publication();
    if (!publication || !publication->snapshot ||
        !publication->coherent_with(binding->analysis_workspace->identity()))
        return shell_error(workbench_error_code_t::adapter_rejected,
                           binding->workspace.value);
    const auto overlay_revision =
        binding->analysis_workspace->overlay_revision();
    if (output.analysis_generation == publication->generation &&
        output.analysis_revision == publication->analysis_revision &&
        output.overlay_revision == overlay_revision)
        return {};
    if (output.pseudocode_document &&
        output.pseudocode_document->has_pending_requests())
        return {};
    const auto refreshed =
        binding->shell->refresh_analysis_documents(binding->workspace);
    if (!refreshed)
        return refreshed;
    const auto* current = binding->shell->workspace_context(binding->workspace);
    if (!current)
        return shell_error(workbench_error_code_t::invalid_workspace,
                           binding->workspace.value);
    output = *current;
    return {};
}

workbench_error_t publish_runtime_document(
    workbench_shell_workspace_context_t& context,
    const document_identity_t& identity)
{
    if (!context.document_bridge)
        return shell_error(workbench_error_code_t::adapter_rejected,
                           identity.object_id);
    document_descriptor_t descriptor;
    if (!analysis_document_descriptor(identity, descriptor))
        return shell_error(workbench_error_code_t::invalid_document,
                           identity.object_id);
    return context.document_bridge->publish(std::move(descriptor));
}

document_identity_t runtime_document_identity(
    workspace_id_t workspace,
    document_kind_t kind,
    std::optional<std::uint64_t> address)
{
    document_identity_t identity;
    identity.workspace = workspace;
    identity.kind = kind;
    identity.object_id = 1;
    identity.provider_key = "analysis";
    if (address) {
        identity.has_address = true;
        identity.address = *address;
    }
    return identity;
}

std::optional<document_identity_t> runtime_entity_document_identity(
    workspace_id_t workspace,
    document_kind_t kind,
    std::string_view canonical_provider_key)
{
    if (kind != document_kind_t::pseudocode)
        return std::nullopt;
    const auto locator =
        pseudocode_document::parse_pseudocode_entity_locator(
            canonical_provider_key);
    const auto canonical = locator
        ? pseudocode_document::canonical_pseudocode_entity_locator(*locator)
        : std::nullopt;
    if (!canonical || *canonical != canonical_provider_key)
        return std::nullopt;
    auto identity = runtime_document_identity(workspace, kind, std::nullopt);
    identity.provider_key = *canonical;
    return identity;
}

}

struct workbench_shell_runtime_t::impl_t {
    mutable std::mutex mutex;
    std::map<analysis::binary_id_t,
             std::shared_ptr<workbench_runtime_binding_t>> bindings;

    workbench_error_t binding_for(
        const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
        std::shared_ptr<workbench_runtime_binding_t>& output)
    {
        output.reset();
        if (!analysis_workspace || analysis_workspace->closing() ||
            analysis_workspace->closed() ||
            analysis_workspace->identity().binary_id().empty())
            return shell_error(workbench_error_code_t::invalid_workspace);
        const auto binary_id = analysis_workspace->identity().binary_id();
        std::lock_guard<std::mutex> lock(mutex);
        auto found = bindings.find(binary_id);
        if (found != bindings.end()) {
            std::lock_guard<std::mutex> lifecycle_lock(
                found->second->lifecycle_mutex);
            if (!found->second->closing &&
                found->second->analysis_workspace == analysis_workspace) {
                output = found->second;
                return {};
            }
            if (!found->second->closing &&
                found->second->analysis_workspace &&
                !found->second->analysis_workspace->closed())
                return shell_error(workbench_error_code_t::duplicate_identifier,
                                   found->second->workspace.value);
            bindings.erase(found);
        }

        auto binding = std::make_shared<workbench_runtime_binding_t>();
        binding->binary_id = binary_id;
        binding->workspace = runtime_workspace_id(binary_id);
        binding->analysis_workspace = analysis_workspace;
        binding->model = std::make_unique<workbench_model_t>();
        const auto initial =
            workbench_shell_integration_t::create_default_persistence(
                binding->workspace, k_default_history_capacity);
        workbench_snapshot_ptr_t initial_snapshot;
        const auto created =
            binding->model->create_workspace(initial, initial_snapshot);
        if (!created)
            return created;
        workbench_shell_integration_config_t config;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        config.integrate_persistence = false;
#endif
        binding->shell =
            workbench_shell_integration_t::create(*binding->model, config);
        if (!binding->shell)
            return shell_error(workbench_error_code_t::adapter_rejected,
                               binding->workspace.value);
        binding->dirty_revision.store(initial.revision.value,
                                      std::memory_order_release);
        bindings.emplace(binary_id, binding);
        output = std::move(binding);
        return {};
    }
};

workbench_shell_runtime_t& workbench_shell_runtime_t::instance()
{
    static workbench_shell_runtime_t runtime;
    return runtime;
}

workbench_shell_runtime_t::workbench_shell_runtime_t()
    : impl_(std::make_unique<impl_t>())
{
}

workbench_shell_runtime_t::~workbench_shell_runtime_t()
{
    if (!impl_)
        return;
    std::vector<std::shared_ptr<workbench_runtime_binding_t>> bindings;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        for (auto& [binary_id, binding] : impl_->bindings) {
            static_cast<void>(binary_id);
            bindings.push_back(binding);
        }
        impl_->bindings.clear();
    }
    for (const auto& binding : bindings) {
        {
            std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
            binding->closing = true;
        }
        persist_runtime_binding(binding);
    }
}

workbench_error_t workbench_shell_runtime_t::attach_analysis_workspace(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    workbench_shell_workspace_context_t& output)
{
    output = {};
    if (!impl_)
        return shell_error(workbench_error_code_t::invalid_workspace);
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;

    bool persist_default = false;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        if (binding->closing)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        if (!binding->integrated) {
            const auto integrated = binding->shell->integrate_analysis_workspace(
                binding->workspace, analysis_workspace);
            if (!integrated)
                return integrated;
            workbench_snapshot_ptr_t snapshot;
            const auto made_default =
                binding->shell->make_default_for_analysis(
                    binding->workspace, snapshot);
            if (!made_default)
                return made_default;
            binding->integrated = true;
        }
        if (!binding->restored) {
            const auto* current =
                binding->shell->workspace_context(binding->workspace);
            if (!current)
                return shell_error(workbench_error_code_t::invalid_workspace,
                                   binding->workspace.value);
            const auto restored =
                binding->shell->restore_persisted_workspace_context(
                    binding->workspace, current->persistence.revision,
                    missing_document_policy_t::omit, output);
            if (!restored) {
                const auto* fallback =
                    binding->shell->workspace_context(binding->workspace);
                if (!fallback)
                    return restored;
                output = *fallback;
                persist_default = true;
                diag::log_tagged_fmt(
                    "workbench_shell",
                    "persistence_restore_default workspace=%llu code=%u subject=%llu",
                    static_cast<unsigned long long>(binding->workspace.value),
                    static_cast<unsigned>(restored.code),
                    static_cast<unsigned long long>(restored.subject));
            } else {
                binding->persisted_revision.store(
                    output.persistence.revision.value,
                    std::memory_order_release);
                binding->dirty_revision.store(
                    output.persistence.revision.value,
                    std::memory_order_release);
            }
            binding->restored = true;
        } else {
            const auto* current =
                binding->shell->workspace_context(binding->workspace);
            if (!current)
                return shell_error(workbench_error_code_t::invalid_workspace,
                                   binding->workspace.value);
            output = *current;
        }
        const auto synchronized =
            synchronize_runtime_documents(binding, output);
        if (!synchronized)
            return synchronized;
    }
    if (persist_default)
        mark_runtime_dirty(binding, output.persistence.revision.value);
    return {};
}

workbench_error_t workbench_shell_runtime_t::workspace_context(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    return {};
}

workbench_error_t workbench_shell_runtime_t::activate_document(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    document_kind_t kind,
    std::optional<std::uint64_t> address,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        const auto identity =
            runtime_document_identity(binding->workspace, kind, address);
        const auto descriptor_error = publish_runtime_document(output, identity);
        if (!descriptor_error)
            return descriptor_error;
        if (const auto* active = active_document(output.persistence)) {
            if (document_identity_equal(active->identity, identity) ||
                (!address && active->identity.kind == kind))
                return {};
        }
        workbench_command_t command;
        command.kind = workbench_command_kind_t::open_document;
        command.workspace = binding->workspace;
        command.expected_revision = output.persistence.revision;
        command.document_identity = identity;
        command.request_focus = true;
        workbench_command_result_t result;
        const auto dispatched =
            binding->shell->dispatch_command(command, {}, result);
        if (!dispatched)
            return dispatched;
        const auto* current =
            binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

workbench_error_t workbench_shell_runtime_t::activate_entity_document(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    document_kind_t kind,
    std::string_view canonical_provider_key,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    const auto identity = runtime_entity_document_identity(
        binding->workspace, kind, canonical_provider_key);
    if (!identity)
        return shell_error(workbench_error_code_t::invalid_document,
                           binding->workspace.value);
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        const auto descriptor_error = publish_runtime_document(output, *identity);
        if (!descriptor_error)
            return descriptor_error;
        if (const auto* active = active_document(output.persistence)) {
            if (document_identity_equal(active->identity, *identity))
                return {};
        }
        workbench_command_t command;
        command.kind = workbench_command_kind_t::open_document;
        command.workspace = binding->workspace;
        command.expected_revision = output.persistence.revision;
        command.document_identity = *identity;
        command.request_focus = true;
        workbench_command_result_t result;
        const auto dispatched =
            binding->shell->dispatch_command(command, {}, result);
        if (!dispatched)
            return dispatched;
        const auto* current =
            binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

workbench_error_t workbench_shell_runtime_t::close_document(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    document_kind_t kind,
    std::optional<std::uint64_t> address,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        const auto identity =
            runtime_document_identity(binding->workspace, kind, address);
        const auto found = std::find_if(
            output.persistence.documents.begin(),
            output.persistence.documents.end(),
            [&identity](const document_persistence_dto_t& document) {
                return document_identity_equal(document.identity, identity);
            });
        if (found == output.persistence.documents.end())
            return {};
        workbench_command_t command;
        command.kind = workbench_command_kind_t::close_document;
        command.workspace = binding->workspace;
        command.expected_revision = output.persistence.revision;
        command.document = found->id;
        workbench_command_result_t result;
        const auto dispatched =
            binding->shell->dispatch_command(command, {}, result);
        if (!dispatched)
            return dispatched;
        const auto* current =
            binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

workbench_error_t workbench_shell_runtime_t::close_entity_document(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    document_kind_t kind,
    std::string_view canonical_provider_key,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    const auto identity = runtime_entity_document_identity(
        binding->workspace, kind, canonical_provider_key);
    if (!identity)
        return shell_error(workbench_error_code_t::invalid_document,
                           binding->workspace.value);
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        const auto found = std::find_if(
            output.persistence.documents.begin(),
            output.persistence.documents.end(),
            [&identity](const document_persistence_dto_t& document) {
                return document_identity_equal(document.identity, *identity);
            });
        if (found == output.persistence.documents.end())
            return {};
        workbench_command_t command;
        command.kind = workbench_command_kind_t::close_document;
        command.workspace = binding->workspace;
        command.expected_revision = output.persistence.revision;
        command.document = found->id;
        workbench_command_result_t result;
        const auto dispatched =
            binding->shell->dispatch_command(command, {}, result);
        if (!dispatched)
            return dispatched;
        const auto* current =
            binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

workbench_error_t workbench_shell_runtime_t::navigate_document(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    document_kind_t kind,
    std::optional<std::uint64_t> document_address,
    const selection_context_t& selection,
    const document_local_cursor_t& cursor,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        const auto target = runtime_document_identity(
            binding->workspace, kind, document_address);
        const auto descriptor_error = publish_runtime_document(output, target);
        if (!descriptor_error)
            return descriptor_error;
        const auto focused_view = std::find_if(
            output.persistence.views.begin(), output.persistence.views.end(),
            [](const view_persistence_dto_t& view) { return view.focused; });
        if (focused_view == output.persistence.views.end())
            return shell_error(workbench_error_code_t::invalid_view,
                               binding->workspace.value);
        const auto source_document = std::find_if(
            output.persistence.documents.begin(),
            output.persistence.documents.end(),
            [&focused_view](const document_persistence_dto_t& document) {
                return document.id == focused_view->document;
            });
        if (source_document == output.persistence.documents.end())
            return shell_error(workbench_error_code_t::invalid_document,
                               focused_view->document.value);
        document_navigation_bridge_request_t bridge_request;
        auto event_id = binding->next_navigation_id.fetch_add(
            1, std::memory_order_acq_rel);
        if (event_id == 0)
            event_id = binding->next_navigation_id.fetch_add(
                1, std::memory_order_acq_rel);
        bridge_request.id = navigation_event_id_t{event_id};
        bridge_request.sequence = event_id;
        bridge_request.origin = navigation_origin_t::user;
        bridge_request.source.workspace = binding->workspace;
        bridge_request.source.document = source_document->id;
        bridge_request.source.view = focused_view->id;
        bridge_request.source.selection =
            source_document->local_state.selection;
        bridge_request.source.cursor = source_document->local_state.cursor;
        bridge_request.source.synchronization_group =
            focused_view->synchronization_group;
        bridge_request.source.synchronization_policy =
            focused_view->synchronization_policy;
        bridge_request.target.document = target;
        bridge_request.target.selection = selection;
        bridge_request.target.cursor = cursor;
        bridge_request.request_focus = true;
        navigation_event_t event;
        const auto emitted =
            output.document_bridge->emit(bridge_request, event);
        if (!emitted)
            return emitted;
        workbench_command_result_t result;
        const auto dispatched = binding->shell->dispatch_navigation(
            binding->workspace, output.persistence.revision, event, result);
        if (!dispatched)
            return dispatched;
        const auto* current =
            binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

workbench_error_t workbench_shell_runtime_t::navigate_entity_document(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    document_kind_t kind,
    std::string_view canonical_provider_key,
    const selection_context_t& selection,
    const document_local_cursor_t& cursor,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    const auto target = runtime_entity_document_identity(
        binding->workspace, kind, canonical_provider_key);
    if (!target)
        return shell_error(workbench_error_code_t::invalid_document,
                           binding->workspace.value);
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        const auto descriptor_error = publish_runtime_document(output, *target);
        if (!descriptor_error)
            return descriptor_error;
        const auto focused_view = std::find_if(
            output.persistence.views.begin(), output.persistence.views.end(),
            [](const view_persistence_dto_t& view) { return view.focused; });
        if (focused_view == output.persistence.views.end())
            return shell_error(workbench_error_code_t::invalid_view,
                               binding->workspace.value);
        const auto source_document = std::find_if(
            output.persistence.documents.begin(),
            output.persistence.documents.end(),
            [&focused_view](const document_persistence_dto_t& document) {
                return document.id == focused_view->document;
            });
        if (source_document == output.persistence.documents.end())
            return shell_error(workbench_error_code_t::invalid_document,
                               focused_view->document.value);
        document_navigation_bridge_request_t bridge_request;
        auto event_id = binding->next_navigation_id.fetch_add(
            1, std::memory_order_acq_rel);
        if (event_id == 0)
            event_id = binding->next_navigation_id.fetch_add(
                1, std::memory_order_acq_rel);
        bridge_request.id = navigation_event_id_t{event_id};
        bridge_request.sequence = event_id;
        bridge_request.origin = navigation_origin_t::user;
        bridge_request.source.workspace = binding->workspace;
        bridge_request.source.document = source_document->id;
        bridge_request.source.view = focused_view->id;
        bridge_request.source.selection =
            source_document->local_state.selection;
        bridge_request.source.cursor = source_document->local_state.cursor;
        bridge_request.source.synchronization_group =
            focused_view->synchronization_group;
        bridge_request.source.synchronization_policy =
            focused_view->synchronization_policy;
        bridge_request.target.document = *target;
        bridge_request.target.selection = selection;
        bridge_request.target.cursor = cursor;
        bridge_request.request_focus = true;
        navigation_event_t event;
        const auto emitted = output.document_bridge->emit(
            bridge_request, event);
        if (!emitted)
            return emitted;
        workbench_command_result_t result;
        const auto dispatched = binding->shell->dispatch_navigation(
            binding->workspace, output.persistence.revision, event, result);
        if (!dispatched)
            return dispatched;
        const auto* current =
            binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

workbench_error_t workbench_shell_runtime_t::publish_selection(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    const selection_context_t& selection,
    const document_local_cursor_t& cursor,
    navigation_origin_t origin,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    if (!validate_selection_context(selection) ||
        !validate_document_local_cursor(cursor))
        return shell_error(workbench_error_code_t::invalid_navigation);
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        const auto focused_view = std::find_if(
            output.persistence.views.begin(), output.persistence.views.end(),
            [](const view_persistence_dto_t& view) { return view.focused; });
        if (focused_view == output.persistence.views.end())
            return shell_error(workbench_error_code_t::invalid_view,
                               binding->workspace.value);
        const auto source_document = std::find_if(
            output.persistence.documents.begin(), output.persistence.documents.end(),
            [&focused_view](const document_persistence_dto_t& document) {
                return document.id == focused_view->document;
            });
        if (source_document == output.persistence.documents.end())
            return shell_error(workbench_error_code_t::invalid_document,
                               focused_view->document.value);
        document_navigation_bridge_request_t request;
        auto event_id = binding->next_navigation_id.fetch_add(
            1, std::memory_order_acq_rel);
        if (event_id == 0)
            event_id = binding->next_navigation_id.fetch_add(
                1, std::memory_order_acq_rel);
        request.id = navigation_event_id_t{event_id};
        request.sequence = event_id;
        request.origin = origin;
        request.source.workspace = binding->workspace;
        request.source.document = source_document->id;
        request.source.view = focused_view->id;
        request.source.selection = source_document->local_state.selection;
        request.source.cursor = source_document->local_state.cursor;
        request.source.synchronization_group = focused_view->synchronization_group;
        request.source.synchronization_policy = focused_view->synchronization_policy;
        request.target.document = source_document->identity;
        request.target.selection = selection;
        request.target.cursor = cursor;
        request.request_focus = false;
        navigation_event_t event;
        const auto emitted = output.document_bridge->emit(request, event);
        if (!emitted)
            return emitted;
        workbench_command_result_t result;
        const auto dispatched = binding->shell->dispatch_navigation(
            binding->workspace, output.persistence.revision, event, result);
        if (!dispatched)
            return dispatched;
        const auto* current = binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

workbench_error_t workbench_shell_runtime_t::publish_document_selection(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    document_id_t document,
    const selection_context_t& selection,
    const document_local_cursor_t& cursor,
    navigation_origin_t origin,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    if (document.value == 0 || !validate_selection_context(selection) ||
        !validate_document_local_cursor(cursor))
        return shell_error(workbench_error_code_t::invalid_navigation, document.value);
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        const auto source_document = std::find_if(
            output.persistence.documents.begin(), output.persistence.documents.end(),
            [document](const document_persistence_dto_t& candidate) {
                return candidate.id == document;
            });
        if (source_document == output.persistence.documents.end())
            return shell_error(workbench_error_code_t::invalid_document, document.value);
        const auto source_view = std::find_if(
            output.persistence.views.begin(), output.persistence.views.end(),
            [document](const view_persistence_dto_t& candidate) {
                return candidate.document == document;
            });
        if (source_view == output.persistence.views.end())
            return shell_error(workbench_error_code_t::invalid_view, document.value);
        document_navigation_bridge_request_t request;
        auto event_id = binding->next_navigation_id.fetch_add(
            1, std::memory_order_acq_rel);
        if (event_id == 0)
            event_id = binding->next_navigation_id.fetch_add(
                1, std::memory_order_acq_rel);
        request.id = navigation_event_id_t{event_id};
        request.sequence = event_id;
        request.origin = origin;
        request.source.workspace = binding->workspace;
        request.source.document = source_document->id;
        request.source.view = source_view->id;
        request.source.selection = source_document->local_state.selection;
        request.source.cursor = source_document->local_state.cursor;
        request.source.synchronization_group = source_view->synchronization_group;
        request.source.synchronization_policy = source_view->synchronization_policy;
        request.target.document = source_document->identity;
        request.target.selection = selection;
        request.target.cursor = cursor;
        request.request_focus = false;
        navigation_event_t event;
        const auto emitted = output.document_bridge->emit(request, event);
        if (!emitted)
            return emitted;
        workbench_command_result_t result;
        const auto dispatched = binding->shell->dispatch_navigation(
            binding->workspace, output.persistence.revision, event, result);
        if (!dispatched)
            return dispatched;
        const auto* current = binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

workbench_error_t workbench_shell_runtime_t::navigate_history(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace,
    bool forward,
    workbench_shell_workspace_context_t& output)
{
    const auto attached = attach_analysis_workspace(analysis_workspace, output);
    if (!attached)
        return attached;
    std::shared_ptr<workbench_runtime_binding_t> binding;
    const auto binding_error = impl_->binding_for(analysis_workspace, binding);
    if (!binding_error)
        return binding_error;
    std::uint64_t changed_revision = 0;
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        workbench_command_t command;
        command.kind = forward ? workbench_command_kind_t::history_forward
                               : workbench_command_kind_t::history_back;
        command.workspace = binding->workspace;
        command.expected_revision = output.persistence.revision;
        workbench_command_result_t result;
        const auto dispatched = binding->shell->dispatch_command(command, {}, result);
        if (!dispatched)
            return dispatched;
        const auto* current = binding->shell->workspace_context(binding->workspace);
        if (!current)
            return shell_error(workbench_error_code_t::invalid_workspace,
                               binding->workspace.value);
        output = *current;
        const auto active = std::find_if(
            output.persistence.documents.begin(), output.persistence.documents.end(),
            [&output](const document_persistence_dto_t& document) {
                return document.id == output.persistence.active_document;
            });
        if (active != output.persistence.documents.end()) {
            inspector::inspector_context_t context;
            context.workspace = binding->workspace;
            context.workspace_generation = output.persistence.revision;
            context.document = active->identity;
            context.selection = active->local_state.selection;
            context.selection_generation = output.persistence.revision.value;
            const auto inspector_error = binding->shell->integrate_inspector(
                binding->workspace, context);
            if (!inspector_error)
                return inspector_error;
        }
        if (result.changed)
            changed_revision = output.persistence.revision.value;
    }
    if (changed_revision != 0)
        mark_runtime_dirty(binding, changed_revision);
    return {};
}

std::vector<std::shared_ptr<analysis::analysis_workspace_t>>
workbench_shell_runtime_t::analysis_workspaces() const
{
    if (!impl_)
        return {};
    std::vector<std::shared_ptr<analysis::analysis_workspace_t>> output;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    output.reserve(impl_->bindings.size());
    for (const auto& [binary_id, binding] : impl_->bindings) {
        static_cast<void>(binary_id);
        if (!binding || !binding->analysis_workspace ||
            binding->analysis_workspace->closing() ||
            binding->analysis_workspace->closed())
            continue;
        output.push_back(binding->analysis_workspace);
    }
    std::sort(output.begin(), output.end(), [](const auto& lhs, const auto& rhs) {
        return lhs->identity().binary_id() < rhs->identity().binary_id();
    });
    return output;
}

workbench_error_t workbench_shell_runtime_t::close_analysis_workspace(
    const std::shared_ptr<analysis::analysis_workspace_t>& analysis_workspace)
{
    if (!impl_ || !analysis_workspace)
        return shell_error(workbench_error_code_t::invalid_workspace);
    std::shared_ptr<workbench_runtime_binding_t> binding;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        const auto found = impl_->bindings.find(
            analysis_workspace->identity().binary_id());
        if (found == impl_->bindings.end() ||
            found->second->analysis_workspace != analysis_workspace)
            return {};
        binding = found->second;
    }
    {
        std::lock_guard<std::mutex> lock(binding->lifecycle_mutex);
        binding->closing = true;
        if (binding->shell) {
            const auto* current =
                binding->shell->workspace_context(binding->workspace);
            if (current)
                raise_dirty_revision(binding,
                    current->persistence.revision.value);
        }
    }
    persist_runtime_binding(binding);
    const auto persisted =
        binding->persisted_revision.load(std::memory_order_acquire);
    const auto dirty = binding->dirty_revision.load(std::memory_order_acquire);
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        const auto found = impl_->bindings.find(binding->binary_id);
        if (found != impl_->bindings.end() && found->second == binding)
            impl_->bindings.erase(found);
    }
    return persisted >= dirty
        ? workbench_error_t{}
        : shell_error(workbench_error_code_t::adapter_rejected, dirty);
}

}
}
