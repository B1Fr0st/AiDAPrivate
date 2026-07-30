#include "symbol_type_candidates.hpp"

#include "../readers/elf_reader.hpp"
#include "../readers/macho_reader.hpp"
#include "../readers/managed/managed_reader_contracts.hpp"
#include "../readers/pe_coff_reader.hpp"
#include "checked_range.hpp"
#include "parallel_pass.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cctype>
#include <iterator>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <utility>

namespace aida::analysis {

namespace {

constexpr std::uint64_t kSymbolEntityTag = 7ULL << 56;
constexpr std::uint64_t kTypeXrefEntityTag = 9ULL << 56;
constexpr std::uint64_t kTypeEntityTag = 10ULL << 56;
constexpr std::uint64_t kMetadataConflictEntityTag = 14ULL << 56;

struct pending_relation_t {
    std::string source_key;
    std::string target_name;
    std::optional<address_t> source;
    std::optional<address_t> target;
    type_reference_kind_t kind = type_reference_kind_t::metadata_reference;
    metadata_provenance_t provenance = metadata_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "symbol and type candidate discovery deadline exceeded",
            "symbol_type_candidates");
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "symbol and type candidate discovery cancelled", "symbol_type_candidates");
    error.cancellation = true;
    return error;
}

address_t rva_address(const workspace_image_t& image, std::uint64_t rva) noexcept {
    return {address_space_id_t::relative_virtual, rva, image.architecture,
        image.architecture_mode};
}

std::optional<std::uint64_t> to_rva(const workspace_image_t& image,
                                    const address_t& address) noexcept {
    if (address.architecture != image.architecture || address.mode != image.architecture_mode)
        return std::nullopt;
    if (address.space == address_space_id_t::relative_virtual)
        return address.value < image.image_size ? std::optional<std::uint64_t>(address.value)
                                                : std::nullopt;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) &&
        address.value >= image.image_base) {
        const auto rva = address.value - image.image_base;
        return rva < image.image_size ? std::optional<std::uint64_t>(rva) : std::nullopt;
    }
    return std::nullopt;
}

std::optional<address_t> canonical_address(const workspace_image_t& image,
                                           const address_t& address) noexcept {
    const auto rva = to_rva(image, address);
    if (!rva)
        return std::nullopt;
    const auto canonical = rva_address(image, *rva);
    return workspace_image_contains(image, canonical) ? std::optional<address_t>(canonical)
                                                       : std::nullopt;
}

std::optional<address_t> canonical_value(const workspace_image_t& image,
                                         std::uint64_t value) noexcept {
    if (value >= image.image_base) {
        const auto rva = value - image.image_base;
        if (rva < image.image_size) {
            const auto address = rva_address(image, rva);
            if (workspace_image_contains(image, address))
                return address;
        }
    }
    if (value < image.image_size) {
        const auto address = rva_address(image, value);
        if (workspace_image_contains(image, address))
            return address;
    }
    return std::nullopt;
}

std::optional<address_t> file_offset_address(const workspace_image_t& image,
                                             std::uint64_t file_offset) noexcept {
    for (const auto& mapping : image.address_mappings) {
        if (mapping.source_space == address_space_id_t::file_offset &&
            mapping.target_space == address_space_id_t::relative_virtual &&
            file_offset >= mapping.source_start &&
            file_offset - mapping.source_start < mapping.size) {
            std::uint64_t rva = 0;
            if (checked_add_u64(mapping.target_start,
                    file_offset - mapping.source_start, rva))
                return canonical_value(image, rva);
        }
    }
    const auto find = [&](const auto& regions) -> std::optional<address_t> {
        for (const auto& region : regions) {
            if (file_offset < region.file_offset ||
                file_offset - region.file_offset >= region.file_size)
                continue;
            std::uint64_t rva = 0;
            if (!checked_add_u64(region.virtual_address,
                    file_offset - region.file_offset, rva))
                return std::nullopt;
            return canonical_value(image, rva);
        }
        return std::nullopt;
    };
    auto section = find(image.sections);
    return section ? section : find(image.segments);
}

bool executable(const workspace_image_t& image, const address_t& address) noexcept {
    const auto rva = to_rva(image, address);
    if (!rva)
        return false;
    const auto find = [rva](const auto& regions) noexcept {
        for (const auto& region : regions) {
            const auto extent = (std::max)(region.virtual_size, region.file_size);
            if (*rva >= region.virtual_address && *rva - region.virtual_address < extent)
                return (region.permissions & image_permission_execute) != 0;
        }
        return false;
    };
    return find(image.sections) || find(image.segments);
}

std::string lower_ascii(std::string value) {
    for (auto& character : value)
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    return value;
}

bool starts_with(const std::string& value, const char* prefix) noexcept {
    const std::string_view expected(prefix);
    return value.size() >= expected.size() &&
           std::equal(expected.begin(), expected.end(), value.begin());
}

bool contains(const std::string& value, const char* token) noexcept {
    return value.find(token) != std::string::npos;
}

std::string hex_value(std::uint64_t value) {
    char buffer[16];
    const auto converted = std::to_chars(buffer, buffer + sizeof(buffer), value, 16);
    return converted.ec == std::errc{} ? std::string(buffer, converted.ptr) : std::string("0");
}

metadata_provenance_t metadata_from_fact(fact_provenance_t provenance) noexcept {
    switch (provenance) {
        case fact_provenance_t::relocation: return metadata_provenance_t::relocation;
        case fact_provenance_t::export_entry: return metadata_provenance_t::export_metadata;
        case fact_provenance_t::debug_symbol: return metadata_provenance_t::debug_metadata;
        case fact_provenance_t::recursive_decode:
        case fact_provenance_t::gap_recovery:
        case fact_provenance_t::call_target: return metadata_provenance_t::decoded;
        default: return metadata_provenance_t::loader_symbol;
    }
}

std::optional<std::pair<symbol_type_candidate_kind_t, metadata_provenance_t>>
classify_name(const std::string& name) {
    const auto lower = lower_ascii(name);
    if (starts_with(lower, "??_7") || starts_with(lower, "_ztv") ||
        contains(lower, "vftable") || contains(lower, "vtable for ")) {
        return std::make_pair(symbol_type_candidate_kind_t::virtual_table,
            metadata_provenance_t::vtable_validation);
    }
    if (starts_with(lower, "??_r") || starts_with(lower, "_zti") ||
        starts_with(lower, "_zts") || contains(lower, "typeinfo for ") ||
        contains(lower, "type_info")) {
        return std::make_pair(symbol_type_candidate_kind_t::rtti_type,
            metadata_provenance_t::rtti);
    }
    if (contains(name, "OBJC_CLASS_$_") || contains(name, "OBJC_METACLASS_$_") ||
        contains(lower, "objc_class")) {
        return std::make_pair(symbol_type_candidate_kind_t::objective_c_class,
            metadata_provenance_t::objective_c_metadata);
    }
    if (contains(name, "OBJC_PROTOCOL_$_") || contains(lower, "objc_protocol")) {
        return std::make_pair(symbol_type_candidate_kind_t::objective_c_protocol,
            metadata_provenance_t::objective_c_metadata);
    }
    if (starts_with(name, "$s") || starts_with(name, "_$s") ||
        starts_with(name, "_Tt") || contains(lower, "swift")) {
        return std::make_pair(symbol_type_candidate_kind_t::swift_type,
            metadata_provenance_t::swift_metadata);
    }
    return std::nullopt;
}

const char* canonical_type_for(symbol_type_candidate_kind_t kind) noexcept {
    switch (kind) {
        case symbol_type_candidate_kind_t::function_prototype: return "unknown_function";
        case symbol_type_candidate_kind_t::import_prototype: return "unknown_import";
        case symbol_type_candidate_kind_t::global_object: return "unknown_data";
        case symbol_type_candidate_kind_t::pointer_object: return "unknown_pointer";
        case symbol_type_candidate_kind_t::rtti_type: return "cpp_rtti_type";
        case symbol_type_candidate_kind_t::virtual_table: return "cpp_virtual_table";
        case symbol_type_candidate_kind_t::type_information: return "type_information";
        case symbol_type_candidate_kind_t::objective_c_class: return "objective_c_class";
        case symbol_type_candidate_kind_t::objective_c_protocol: return "objective_c_protocol";
        case symbol_type_candidate_kind_t::objective_c_selector: return "objective_c_selector";
        case symbol_type_candidate_kind_t::swift_type: return "swift_type";
        case symbol_type_candidate_kind_t::swift_protocol: return "swift_protocol";
        case symbol_type_candidate_kind_t::managed_type: return "managed_type";
        case symbol_type_candidate_kind_t::managed_method: return "managed_method";
        case symbol_type_candidate_kind_t::managed_field: return "managed_field";
        case symbol_type_candidate_kind_t::debug_type: return "debug_type";
        case symbol_type_candidate_kind_t::metadata_region: return "metadata_region";
    }
    return "unknown";
}

bool stronger(const symbol_record_t& lhs, const symbol_record_t& rhs) noexcept {
    if (provenance_rank(lhs.provenance) != provenance_rank(rhs.provenance))
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    return lhs.kind < rhs.kind;
}

bool stronger(const symbol_type_candidate_record_t& lhs,
              const symbol_type_candidate_record_t& rhs) noexcept {
    if (metadata_provenance_rank(lhs.provenance) !=
        metadata_provenance_rank(rhs.provenance))
        return metadata_provenance_rank(lhs.provenance) >
               metadata_provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    if (lhs.explicitly_unknown != rhs.explicitly_unknown)
        return !lhs.explicitly_unknown;
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.canonical_type != rhs.canonical_type)
        return lhs.canonical_type < rhs.canonical_type;
    return lhs.source_key < rhs.source_key;
}

bool stronger(const type_reference_fact_t& lhs,
              const type_reference_fact_t& rhs) noexcept {
    if (metadata_provenance_rank(lhs.provenance) !=
        metadata_provenance_rank(rhs.provenance))
        return metadata_provenance_rank(lhs.provenance) >
               metadata_provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    return lhs.source_key < rhs.source_key;
}

bool same_type_identity(const symbol_type_candidate_record_t& lhs,
                        const symbol_type_candidate_record_t& rhs) noexcept {
    if (lhs.address || rhs.address)
        return lhs.address == rhs.address && lhs.display_name == rhs.display_name;
    return lhs.display_name == rhs.display_name && lhs.source_key == rhs.source_key;
}

struct collect_sink_t {
    collect_sink_t(const symbol_type_candidate_limits_t& limits_,
        const cancellation_token_t& cancel_) : limits(&limits_), cancel(&cancel_) {}

    const symbol_type_candidate_limits_t* limits;
    const cancellation_token_t* cancel;
    std::vector<symbol_record_t> symbols;
    std::vector<symbol_type_candidate_record_t> types;
    std::vector<pending_relation_t> pending;
    std::vector<metadata_conflict_record_t> conflicts;
    std::vector<type_reference_fact_t> references;
    std::uint64_t duplicate_symbols = 0;
    std::uint64_t duplicate_type_candidates = 0;
    std::uint64_t string_bytes = 0;
    std::uint64_t result_bytes = 0;
    std::uint64_t checks = 0;

    workspace_result_t<void> poll() {
        if (++checks < limits->cancellation_check_interval)
            return workspace_result_t<void>::success();
        checks = 0;
        return cancel->stop_requested()
            ? workspace_result_t<void>::failure(stop_error(*cancel))
            : workspace_result_t<void>::success();
    }

    workspace_result_t<void> charge(std::uint64_t fixed, std::uint64_t strings) {
        if (!checked_add_u64(string_bytes, strings, string_bytes) ||
            string_bytes > limits->max_string_bytes ||
            !checked_add_u64(fixed, strings, fixed) ||
            !checked_add_u64(result_bytes, fixed, result_bytes) ||
            result_bytes > limits->max_result_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "symbol and type candidate storage exceeds its bound",
                "symbol_type_candidates"));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> append_symbol(address_t address, std::string name,
        symbol_kind_t kind, fact_provenance_t provenance, std::uint8_t confidence) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (name.empty() || confidence > 100 || symbols.size() >= limits->max_symbols) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "symbol candidate is invalid or exceeds its count bound",
                "symbol_type_candidates"));
        }
        auto charged = charge(sizeof(symbol_record_t), name.size());
        if (!charged)
            return charged;
        symbol_record_t symbol;
        symbol.address = address;
        symbol.name = std::move(name);
        symbol.kind = kind;
        symbol.provenance = provenance;
        symbol.confidence = confidence;
        symbols.push_back(std::move(symbol));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> append_type(symbol_type_candidate_record_t candidate) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (candidate.display_name.empty() || candidate.confidence > 100 ||
            types.size() >= limits->max_type_candidates) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "type candidate is invalid or exceeds its count bound",
                "symbol_type_candidates"));
        }
        std::uint64_t strings = 0;
        if (!checked_add_u64(candidate.display_name.size(),
                candidate.canonical_type.size(), strings) ||
            !checked_add_u64(strings, candidate.source_key.size(), strings)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "type candidate string accounting overflows",
                "symbol_type_candidates"));
        }
        auto charged = charge(sizeof(symbol_type_candidate_record_t), strings);
        if (!charged)
            return charged;
        types.push_back(std::move(candidate));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> append_pending(pending_relation_t relation) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (pending.size() >= limits->max_type_references) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "type reference count exceeds its bound", "symbol_type_candidates"));
        }
        std::uint64_t strings = 0;
        if (!checked_add_u64(relation.source_key.size(), relation.target_name.size(), strings)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "type reference string accounting overflows",
                "symbol_type_candidates"));
        }
        auto charged = charge(sizeof(pending_relation_t), strings);
        if (!charged)
            return charged;
        pending.push_back(std::move(relation));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> append_conflict(metadata_conflict_record_t conflict) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (conflicts.size() >= limits->max_conflicts) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "metadata conflict count exceeds its bound",
                "symbol_type_candidates"));
        }
        std::uint64_t strings = 0;
        if (!checked_add_u64(conflict.identity.size(), conflict.selected_value.size(), strings) ||
            !checked_add_u64(strings, conflict.rejected_value.size(), strings)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "metadata conflict string accounting overflows",
                "symbol_type_candidates"));
        }
        auto charged = charge(sizeof(metadata_conflict_record_t), strings);
        if (!charged)
            return charged;
        conflicts.push_back(std::move(conflict));
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> append_reference(type_reference_fact_t reference) {
        auto stopped = poll();
        if (!stopped)
            return stopped;
        if (references.size() >= limits->max_type_references) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "type reference count exceeds its bound", "symbol_type_candidates"));
        }
        auto charged = charge(sizeof(type_reference_fact_t), reference.source_key.size());
        if (!charged)
            return charged;
        references.push_back(std::move(reference));
        return workspace_result_t<void>::success();
    }
};

struct collect_task_t {
    std::uint32_t loop = 0;
    std::uint32_t outer = 0;
    std::uint32_t substream = 0;
    std::size_t begin = 0;
    std::size_t end = 0;
};

struct collect_context_t {
    const workspace_image_t& image;
    const std::vector<function_record_t>& functions;
    const std::vector<data_candidate_record_t>& data_candidates;
    const symbol_type_metadata_sources_t& metadata;
    const symbol_type_candidate_limits_t& limits;
    const cancellation_token_t& cancel;
    const std::vector<std::uint64_t>* named_functions = nullptr;
};

struct collect_totals_t {
    std::uint64_t symbols = 0;
    std::uint64_t types = 0;
    std::uint64_t pending = 0;
    std::uint64_t conflicts = 0;
    std::uint64_t references = 0;
    std::uint64_t string_bytes = 0;
    std::uint64_t result_bytes = 0;
};

std::uint64_t collect_ordinal(std::uint32_t loop, std::uint32_t outer,
    std::uint32_t substream, std::size_t item) noexcept {
    return (static_cast<std::uint64_t>(loop & 0x3FFU) << 54) |
           (static_cast<std::uint64_t>(outer & 0xFFFU) << 42) |
           (static_cast<std::uint64_t>(substream & 0x3U) << 40) |
           (static_cast<std::uint64_t>(item) & 0xFFFFFFFFFFULL);
}

workspace_result_t<void> reduce_ordered_failures(std::vector<ordered_error_t>& failures) {
    std::size_t best = failures.size();
    for (std::size_t index = 0; index < failures.size(); ++index) {
        if (failures[index].ordinal != (std::numeric_limits<std::uint64_t>::max)() &&
            (best == failures.size() || failures[index].ordinal < failures[best].ordinal))
            best = index;
    }
    if (best != failures.size())
        return workspace_result_t<void>::failure(std::move(failures[best].error));
    return workspace_result_t<void>::success();
}

template <typename Fn>
workspace_result_t<void> run_ordered_tasks(std::size_t task_count, Fn&& task_fn,
    std::vector<ordered_error_t>& failures, const cancellation_token_t& cancel) {
    failures.assign(task_count, ordered_error_t{});
    if (task_count == 0)
        return workspace_result_t<void>::success();
    const auto worker_total = (std::min<std::size_t>)(task_count, parallel_worker_count());
    std::atomic<std::size_t> next{0};
    const auto shards = parallel_shards(worker_total,
        static_cast<std::uint32_t>(worker_total));
    const auto run = parallel_run_shards(shards,
        [&](std::size_t, parallel_shard_t) -> workspace_result_t<void> {
            for (;;) {
                if (cancel.stop_requested())
                    break;
                const auto index = next.fetch_add(1, std::memory_order_relaxed);
                if (index >= task_count)
                    break;
                task_fn(index);
            }
            return workspace_result_t<void>::success();
        }, cancel);
    if (!run)
        return workspace_result_t<void>::failure(run.error());
    return reduce_ordered_failures(failures);
}

workspace_result_t<void> accumulate_budgets(collect_totals_t& totals,
    const std::vector<collect_sink_t>& sinks,
    const symbol_type_candidate_limits_t& limits, bool count_output_vectors) {
    for (const auto& sink : sinks) {
        bool overflow = false;
        if (count_output_vectors) {
            overflow = !checked_add_u64(totals.symbols, sink.symbols.size(), totals.symbols) ||
                       !checked_add_u64(totals.types, sink.types.size(), totals.types) ||
                       !checked_add_u64(totals.pending, sink.pending.size(), totals.pending);
        }
        if (overflow ||
            !checked_add_u64(totals.conflicts, sink.conflicts.size(), totals.conflicts) ||
            !checked_add_u64(totals.references, sink.references.size(), totals.references) ||
            !checked_add_u64(totals.string_bytes, sink.string_bytes, totals.string_bytes) ||
            !checked_add_u64(totals.result_bytes, sink.result_bytes, totals.result_bytes)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "symbol and type candidate storage exceeds its bound",
                "symbol_type_candidates"));
        }
    }
    if (totals.symbols > limits.max_symbols) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "symbol candidate is invalid or exceeds its count bound",
            "symbol_type_candidates"));
    }
    if (totals.types > limits.max_type_candidates) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "type candidate is invalid or exceeds its count bound",
            "symbol_type_candidates"));
    }
    if (totals.pending > limits.max_type_references ||
        totals.references > limits.max_type_references) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "type reference count exceeds its bound", "symbol_type_candidates"));
    }
    if (totals.conflicts > limits.max_conflicts) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "metadata conflict count exceeds its bound",
            "symbol_type_candidates"));
    }
    if (totals.string_bytes > limits.max_string_bytes ||
        totals.result_bytes > limits.max_result_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "symbol and type candidate storage exceeds its bound",
            "symbol_type_candidates"));
    }
    return workspace_result_t<void>::success();
}

template <typename T>
void append_sink_vectors(std::vector<T>& out, std::vector<collect_sink_t>& sinks,
    std::vector<T> collect_sink_t::* member) {
    std::size_t total = 0;
    for (const auto& sink : sinks)
        total += (sink.*member).size();
    out.reserve(out.size() + total);
    for (auto& sink : sinks) {
        auto& source = sink.*member;
        std::move(source.begin(), source.end(), std::back_inserter(out));
    }
}

template <typename T, typename SameRun>
std::vector<parallel_shard_t> aligned_shards(const std::vector<T>& items,
    SameRun&& same_run, std::uint32_t workers) {
    auto shards = parallel_shards(items.size(), workers);
    for (std::size_t index = 1; index < shards.size(); ++index) {
        auto begin = shards[index].begin;
        while (begin < items.size() && same_run(items[begin - 1], items[begin]))
            ++begin;
        shards[index].begin = begin;
        shards[index - 1].end = begin;
    }
    return shards;
}

template <typename T, typename Equal>
std::uint64_t unique_aligned(std::vector<T>& items, Equal&& equal,
    const cancellation_token_t& cancel) {
    if (items.size() < 2)
        return 0;
    const auto shards = aligned_shards(items, equal, parallel_worker_count());
    std::vector<std::vector<T>> kept(shards.size());
    std::vector<std::uint64_t> removed(shards.size(), 0);
    parallel_run_shards(shards,
        [&](std::size_t slot, parallel_shard_t shard) -> workspace_result_t<void> {
            auto& out = kept[slot];
            out.reserve(shard.end - shard.begin);
            for (std::size_t index = shard.begin; index != shard.end; ++index) {
                if (index == shard.begin || !equal(items[index - 1], items[index]))
                    out.push_back(std::move(items[index]));
                else
                    ++removed[slot];
            }
            return workspace_result_t<void>::success();
        }, cancel);
    std::uint64_t total_removed = 0;
    std::size_t total_kept = 0;
    for (std::size_t index = 0; index < shards.size(); ++index) {
        total_removed += removed[index];
        total_kept += kept[index].size();
    }
    std::vector<T> compacted;
    compacted.reserve(total_kept);
    for (auto& shard_kept : kept)
        std::move(shard_kept.begin(), shard_kept.end(), std::back_inserter(compacted));
    items = std::move(compacted);
    return total_removed;
}

void collect_imports(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& imported = image.imports[index];
        const auto address = canonical_address(image, imported.address);
        if (!address)
            continue;
        std::string name = imported.library;
        name.push_back('!');
        name += imported.name.value_or("#" + std::to_string(imported.ordinal.value_or(0)));
        auto appended = sink.append_symbol(*address, name, symbol_kind_t::import_symbol,
            fact_provenance_t::relocation, 100);
        if (!appended) {
            failure = {collect_ordinal(1, 0, 0, index), appended.error()};
            return;
        }
        symbol_type_candidate_record_t type;
        type.address = *address;
        type.kind = symbol_type_candidate_kind_t::import_prototype;
        type.display_name = std::move(name);
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "import:" + type.display_name;
        type.provenance = metadata_provenance_t::import_metadata;
        type.confidence = 100;
        auto typed = sink.append_type(std::move(type));
        if (!typed) {
            failure = {collect_ordinal(1, 0, 0, index), typed.error()};
            return;
        }
    }
}

void collect_exports(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& exported = image.exports[index];
        const auto address = canonical_address(image, exported.address);
        if (!address)
            continue;
        const auto name = exported.name.value_or("ordinal_" + std::to_string(exported.ordinal));
        const auto kind = executable(image, *address) && !exported.forwarder
            ? symbol_kind_t::function : symbol_kind_t::export_symbol;
        auto appended = sink.append_symbol(*address, name, kind,
            fact_provenance_t::export_entry, 100);
        if (!appended) {
            failure = {collect_ordinal(2, 0, 0, index), appended.error()};
            return;
        }
    }
}

void collect_image_symbols(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& source = image.symbols[index];
        if (!source.defined || source.name.empty())
            continue;
        const auto address = canonical_address(image, source.address);
        if (!address)
            continue;
        const auto kind = source.kind == image_symbol_kind_t::function
            ? symbol_kind_t::function :
            source.kind == image_symbol_kind_t::import_symbol
                ? symbol_kind_t::import_symbol :
            source.kind == image_symbol_kind_t::export_symbol
                ? symbol_kind_t::export_symbol :
            source.kind == image_symbol_kind_t::debug_symbol
                ? symbol_kind_t::debug_symbol :
            source.kind == image_symbol_kind_t::type_symbol
                ? symbol_kind_t::type_symbol : symbol_kind_t::data;
        const auto provenance = kind == symbol_kind_t::debug_symbol ||
            kind == symbol_kind_t::type_symbol ? fact_provenance_t::debug_symbol :
            kind == symbol_kind_t::export_symbol || kind == symbol_kind_t::function
                ? fact_provenance_t::export_entry : fact_provenance_t::relocation;
        auto appended = sink.append_symbol(*address, source.name, kind, provenance,
            source.binding == image_symbol_binding_t::local ? 85 : 92);
        if (!appended) {
            failure = {collect_ordinal(3, 0, 0, index), appended.error()};
            return;
        }
    }
}

void collect_elf_symbols(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& source = ctx.metadata.elf->symbol_seeds[index];
        if (!source.address || source.name.empty())
            continue;
        const auto address = canonical_address(image, *source.address);
        if (!address)
            continue;
        const auto kind = source.imported ? symbol_kind_t::import_symbol :
            source.exported ? symbol_kind_t::export_symbol :
            source.kind == elf_symbol_kind_t::function ? symbol_kind_t::function :
            source.kind == elf_symbol_kind_t::data ? symbol_kind_t::data :
            symbol_kind_t::metadata;
        const auto provenance = source.source == elf_symbol_seed_source_t::symbol_table
            ? fact_provenance_t::debug_symbol :
            source.imported ? fact_provenance_t::relocation :
            source.exported ? fact_provenance_t::export_entry :
            fact_provenance_t::linear_validation;
        auto appended = sink.append_symbol(*address, source.name, kind, provenance,
            source.weak ? 78 : 90);
        if (!appended) {
            failure = {collect_ordinal(4, 0, 0, index), appended.error()};
            return;
        }
    }
}

void collect_elf_types(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& seed = ctx.metadata.elf->type_seeds[index];
        symbol_type_candidate_record_t type;
        if (seed.region.address)
            type.address = canonical_address(image, *seed.region.address);
        type.kind = symbol_type_candidate_kind_t::debug_type;
        type.display_name = seed.region.name.empty()
            ? "elf_debug_" + std::to_string(static_cast<unsigned>(seed.kind))
            : seed.region.name;
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "elf:type:" + std::to_string(seed.region.section_index) + ":" +
            std::to_string(static_cast<unsigned>(seed.kind));
        type.provenance = metadata_provenance_t::debug_metadata;
        type.confidence = seed.region.compressed ? 88 : 92;
        auto appended = sink.append_type(std::move(type));
        if (!appended) {
            failure = {collect_ordinal(5, 0, 0, index), appended.error()};
            return;
        }
    }
}

void collect_pe_coff_types(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& seed = ctx.metadata.pe_coff->type_seeds[index];
        symbol_type_candidate_record_t type;
        if (seed.rva)
            type.address = canonical_value(image, *seed.rva);
        type.kind = seed.kind == pe_coff_type_seed_kind_t::rtti
            ? symbol_type_candidate_kind_t::rtti_type :
            seed.kind == pe_coff_type_seed_kind_t::vtable
                ? symbol_type_candidate_kind_t::virtual_table :
                symbol_type_candidate_kind_t::type_information;
        type.display_name = seed.name.empty()
            ? std::string(canonical_type_for(type.kind)) : seed.name;
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "pe_coff:type:" +
            std::to_string(static_cast<unsigned>(seed.origin)) + ":" + type.display_name;
        type.provenance = type.kind == symbol_type_candidate_kind_t::virtual_table
            ? metadata_provenance_t::vtable_validation : metadata_provenance_t::rtti;
        type.confidence = seed.origin == pe_coff_type_seed_origin_t::coff_symbol ? 88 : 94;
        auto appended = sink.append_type(std::move(type));
        if (!appended) {
            failure = {collect_ordinal(6, 0, 0, index), appended.error()};
            return;
        }
    }
}

void collect_macho(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    const auto& slice = ctx.metadata.macho->slices[task.outer];
    if (task.substream == 0) {
        for (std::size_t index = task.begin; index != task.end; ++index) {
            const auto& source = slice.symbols[index];
            const auto address = canonical_value(image, source.value);
            if (!address || source.name.empty())
                continue;
            const auto kind = executable(image, *address)
                ? symbol_kind_t::function : symbol_kind_t::data;
            auto appended = sink.append_symbol(*address, source.name, kind,
                fact_provenance_t::linear_validation, 88);
            if (!appended) {
                failure = {collect_ordinal(7, task.outer, 0, index), appended.error()};
                return;
            }
        }
        return;
    }
    if (task.substream == 1) {
        for (std::size_t index = task.begin; index != task.end; ++index) {
            const auto& binding = slice.bindings[index];
            const auto address = canonical_value(image, binding.address);
            if (!address || binding.symbol.empty())
                continue;
            auto appended = sink.append_symbol(*address, binding.symbol,
                symbol_kind_t::import_symbol, fact_provenance_t::relocation, 96);
            if (!appended) {
                failure = {collect_ordinal(7, task.outer, 1, index), appended.error()};
                return;
            }
        }
        return;
    }
    if (task.substream == 2) {
        for (std::size_t index = task.begin; index != task.end; ++index) {
            const auto& exported = slice.exports[index];
            const auto address = canonical_value(image, exported.address);
            if (!address || exported.name.empty())
                continue;
            auto appended = sink.append_symbol(*address, exported.name,
                executable(image, *address) ? symbol_kind_t::function
                                            : symbol_kind_t::export_symbol,
                fact_provenance_t::export_entry, 98);
            if (!appended) {
                failure = {collect_ordinal(7, task.outer, 2, index), appended.error()};
                return;
            }
        }
        return;
    }
    const auto slice_key = slice.identity.stable_key();
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& seed = slice.metadata_seeds[index];
        symbol_type_candidate_record_t type;
        type.address = canonical_value(image, seed.address);
        const auto section = lower_ascii(seed.section_name);
        if (seed.kind == "objc") {
            type.kind = contains(section, "protocol")
                ? symbol_type_candidate_kind_t::objective_c_protocol :
                contains(section, "sel")
                    ? symbol_type_candidate_kind_t::objective_c_selector :
                    symbol_type_candidate_kind_t::objective_c_class;
            type.provenance = metadata_provenance_t::objective_c_metadata;
        } else {
            type.kind = contains(section, "proto")
                ? symbol_type_candidate_kind_t::swift_protocol
                : symbol_type_candidate_kind_t::swift_type;
            type.provenance = metadata_provenance_t::swift_metadata;
        }
        type.display_name = seed.section_name.empty()
            ? seed.kind + "_metadata" : seed.section_name;
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "macho:" + slice_key + ":" + seed.segment_name + ":" +
            seed.section_name + ":" + std::to_string(seed.file_offset);
        type.confidence = 96;
        auto appended = sink.append_type(std::move(type));
        if (!appended) {
            failure = {collect_ordinal(7, task.outer, 3, index), appended.error()};
            return;
        }
    }
}

void collect_managed(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    const auto* artifact = ctx.metadata.managed_artifacts[task.outer];
    if (!artifact || !artifact->valid())
        return;
    const auto module = artifact->module_identity.assembly_name + ":" +
        artifact->module_identity.module_name;
    std::map<std::uint32_t, std::string> method_keys;
    const auto& types = artifact->types;
    for (std::size_t index = 0; index < types.size(); ++index) {
        const auto& source = types[index];
        symbol_type_candidate_record_t type;
        type.kind = symbol_type_candidate_kind_t::managed_type;
        type.display_name = source.fully_qualified_name.empty()
            ? source.type_name : source.fully_qualified_name;
        type.canonical_type = source.signature.empty()
            ? type.display_name : source.signature;
        type.source_key = "managed:" + module + ":type:" +
            std::to_string(source.metadata_token);
        type.provenance = metadata_provenance_t::managed_metadata;
        type.confidence = 100;
        type.explicitly_unknown = false;
        auto appended = sink.append_type(type);
        if (!appended) {
            failure = {collect_ordinal(8, task.outer, 0, index), appended.error()};
            return;
        }
        if (source.base_type_name && !source.base_type_name->empty()) {
            pending_relation_t relation;
            relation.source_key = type.source_key;
            relation.target_name = *source.base_type_name;
            relation.kind = type_reference_kind_t::inheritance;
            relation.provenance = metadata_provenance_t::managed_metadata;
            relation.confidence = 100;
            auto related = sink.append_pending(std::move(relation));
            if (!related) {
                failure = {collect_ordinal(8, task.outer, 0, index), related.error()};
                return;
            }
        }
    }
    const auto& methods = artifact->methods;
    for (std::size_t index = 0; index < methods.size(); ++index) {
        const auto& source = methods[index];
        symbol_type_candidate_record_t type;
        type.address = source.has_body ? file_offset_address(image, source.code_offset)
                                       : std::nullopt;
        type.kind = symbol_type_candidate_kind_t::managed_method;
        type.display_name = source.declaring_type_name.empty()
            ? source.method_name : source.declaring_type_name + "::" + source.method_name;
        type.canonical_type = source.method_signature.empty()
            ? std::string(canonical_type_for(type.kind)) : source.method_signature;
        type.source_key = "managed:" + module + ":method:" +
            std::to_string(source.metadata_token) + ":" +
            std::to_string(source.method_index);
        type.provenance = metadata_provenance_t::managed_metadata;
        type.confidence = source.has_body ? 100 : 96;
        type.explicitly_unknown = source.method_signature.empty();
        method_keys.emplace(source.method_index, type.source_key);
        if (type.address) {
            auto symbol = sink.append_symbol(*type.address, type.display_name,
                symbol_kind_t::function, fact_provenance_t::debug_symbol, 100);
            if (!symbol) {
                failure = {collect_ordinal(8, task.outer, 1, index), symbol.error()};
                return;
            }
        }
        auto appended = sink.append_type(std::move(type));
        if (!appended) {
            failure = {collect_ordinal(8, task.outer, 1, index), appended.error()};
            return;
        }
    }
    const auto& fields = artifact->fields;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        const auto& source = fields[index];
        symbol_type_candidate_record_t type;
        type.kind = symbol_type_candidate_kind_t::managed_field;
        type.display_name = source.declaring_type_name.empty()
            ? source.field_name : source.declaring_type_name + "::" + source.field_name;
        type.canonical_type = source.field_signature.empty()
            ? std::string(canonical_type_for(type.kind)) : source.field_signature;
        type.source_key = "managed:" + module + ":field:" +
            std::to_string(source.metadata_token) + ":" +
            std::to_string(source.field_index);
        type.provenance = metadata_provenance_t::managed_metadata;
        type.confidence = 100;
        type.explicitly_unknown = source.field_signature.empty();
        auto appended = sink.append_type(std::move(type));
        if (!appended) {
            failure = {collect_ordinal(8, task.outer, 2, index), appended.error()};
            return;
        }
    }
    const auto& references = artifact->member_references;
    for (std::size_t index = 0; index < references.size(); ++index) {
        const auto& reference = references[index];
        const auto source = method_keys.find(reference.source_method_index);
        if (source == method_keys.end())
            continue;
        pending_relation_t relation;
        relation.source_key = source->second;
        relation.target_name = reference.declaring_type_name;
        if (!reference.member_name.empty()) {
            if (!relation.target_name.empty())
                relation.target_name += "::";
            relation.target_name += reference.member_name;
        }
        relation.kind = type_reference_kind_t::managed_reference;
        relation.provenance = metadata_provenance_t::managed_metadata;
        relation.confidence = 98;
        auto appended = sink.append_pending(std::move(relation));
        if (!appended) {
            failure = {collect_ordinal(8, task.outer, 3, index), appended.error()};
            return;
        }
    }
}

void collect_functions(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    const auto& named = *ctx.named_functions;
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& function = ctx.functions[index];
        const auto address = canonical_address(image, function.start);
        if (!address)
            continue;
        const auto name = "sub_" + hex_value(address->value);
        if (!std::binary_search(named.begin(), named.end(), address->value)) {
            auto appended = sink.append_symbol(*address, name, symbol_kind_t::function,
                function.provenance, function.confidence);
            if (!appended) {
                failure = {collect_ordinal(9, 0, 0, index), appended.error()};
                return;
            }
        }
        symbol_type_candidate_record_t type;
        type.address = *address;
        type.kind = symbol_type_candidate_kind_t::function_prototype;
        type.display_name = name;
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "function:" + hex_value(address->value);
        type.provenance = metadata_from_fact(function.provenance);
        type.confidence = function.confidence;
        auto appended = sink.append_type(std::move(type));
        if (!appended) {
            failure = {collect_ordinal(9, 0, 0, index), appended.error()};
            return;
        }
    }
}

void collect_data_candidates(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    const auto& image = ctx.image;
    for (std::size_t index = task.begin; index != task.end; ++index) {
        const auto& data = ctx.data_candidates[index];
        const auto address = canonical_address(image, data.address);
        if (!address)
            continue;
        symbol_type_candidate_record_t type;
        type.address = *address;
        type.related_address = data.target ? canonical_address(image, *data.target) : std::nullopt;
        type.kind = data.target ? symbol_type_candidate_kind_t::pointer_object
                                : symbol_type_candidate_kind_t::global_object;
        type.display_name = "data_" + hex_value(address->value);
        type.canonical_type = canonical_type_for(type.kind);
        type.source_key = "data:" + std::to_string(static_cast<unsigned>(data.kind)) + ":" +
            hex_value(address->value);
        type.provenance = metadata_from_fact(data.provenance);
        type.confidence = data.confidence;
        auto appended = sink.append_type(std::move(type));
        if (!appended) {
            failure = {collect_ordinal(10, 0, 0, index), appended.error()};
            return;
        }
    }
}

void execute_collect_task(const collect_context_t& ctx, const collect_task_t& task,
    collect_sink_t& sink, ordered_error_t& failure) {
    switch (task.loop) {
        case 1: collect_imports(ctx, task, sink, failure); break;
        case 2: collect_exports(ctx, task, sink, failure); break;
        case 3: collect_image_symbols(ctx, task, sink, failure); break;
        case 4: collect_elf_symbols(ctx, task, sink, failure); break;
        case 5: collect_elf_types(ctx, task, sink, failure); break;
        case 6: collect_pe_coff_types(ctx, task, sink, failure); break;
        case 7: collect_macho(ctx, task, sink, failure); break;
        case 8: collect_managed(ctx, task, sink, failure); break;
        case 9: collect_functions(ctx, task, sink, failure); break;
        case 10: collect_data_candidates(ctx, task, sink, failure); break;
        default: break;
    }
}

void append_collect_tasks(std::vector<collect_task_t>& tasks, std::uint32_t loop,
    std::size_t count, std::uint32_t workers) {
    for (const auto& shard : parallel_shards(count, workers))
        tasks.push_back(collect_task_t{loop, 0, 0, shard.begin, shard.end});
}

void append_macho_tasks(std::vector<collect_task_t>& tasks, std::uint32_t slice_index,
    const readers::macho_metadata_document_t& macho, std::uint32_t workers) {
    const auto& slice = macho.slices[slice_index];
    for (const auto& shard : parallel_shards(slice.symbols.size(), workers))
        tasks.push_back(collect_task_t{7, slice_index, 0, shard.begin, shard.end});
    for (const auto& shard : parallel_shards(slice.bindings.size(), workers))
        tasks.push_back(collect_task_t{7, slice_index, 1, shard.begin, shard.end});
    for (const auto& shard : parallel_shards(slice.exports.size(), workers))
        tasks.push_back(collect_task_t{7, slice_index, 2, shard.begin, shard.end});
    for (const auto& shard : parallel_shards(slice.metadata_seeds.size(), workers))
        tasks.push_back(collect_task_t{7, slice_index, 3, shard.begin, shard.end});
}

workspace_result_t<void> run_collect_wave(const collect_context_t& ctx,
    const std::vector<collect_task_t>& tasks, std::vector<collect_sink_t>& sinks) {
    sinks.clear();
    sinks.reserve(tasks.size());
    for (std::size_t index = 0; index < tasks.size(); ++index)
        sinks.emplace_back(ctx.limits, ctx.cancel);
    std::vector<ordered_error_t> failures;
    return run_ordered_tasks(tasks.size(), [&](std::size_t index) {
        execute_collect_task(ctx, tasks[index], sinks[index], failures[index]);
    }, failures, ctx.cancel);
}

void dedup_symbols_shard(const std::vector<symbol_record_t>& sorted,
    const parallel_shard_t& shard, collect_sink_t& sink, ordered_error_t& failure) {
    for (std::size_t index = shard.begin; index != shard.end; ++index) {
        const auto& symbol = sorted[index];
        if (sink.symbols.empty() || sink.symbols.back().address != symbol.address ||
            sink.symbols.back().name != symbol.name) {
            sink.symbols.push_back(symbol);
            continue;
        }
        ++sink.duplicate_symbols;
        const auto& selected = sink.symbols.back();
        if (selected.kind == symbol.kind)
            continue;
        metadata_conflict_record_t conflict;
        conflict.address = selected.address;
        conflict.identity = selected.name;
        conflict.kind = metadata_conflict_kind_t::symbol_kind;
        conflict.selected_value = std::to_string(static_cast<unsigned>(selected.kind));
        conflict.rejected_value = std::to_string(static_cast<unsigned>(symbol.kind));
        conflict.selected_provenance = metadata_from_fact(selected.provenance);
        conflict.rejected_provenance = metadata_from_fact(symbol.provenance);
        conflict.selected_confidence = selected.confidence;
        conflict.rejected_confidence = symbol.confidence;
        auto appended = sink.append_conflict(std::move(conflict));
        if (!appended) {
            failure = {collect_ordinal(11, 0, 0, index), appended.error()};
            return;
        }
    }
}

void dedup_types_shard(const std::vector<symbol_type_candidate_record_t>& sorted,
    const parallel_shard_t& shard, collect_sink_t& sink, ordered_error_t& failure) {
    for (std::size_t index = shard.begin; index != shard.end; ++index) {
        const auto& type = sorted[index];
        if (sink.types.empty() || !same_type_identity(sink.types.back(), type)) {
            sink.types.push_back(type);
            continue;
        }
        ++sink.duplicate_type_candidates;
        const auto& selected = sink.types.back();
        const auto record_conflict = [&](metadata_conflict_kind_t kind,
            std::string selected_value, std::string rejected_value)
            -> workspace_result_t<void> {
            metadata_conflict_record_t conflict;
            conflict.address = selected.address;
            conflict.identity = selected.display_name;
            conflict.kind = kind;
            conflict.selected_value = std::move(selected_value);
            conflict.rejected_value = std::move(rejected_value);
            conflict.selected_provenance = selected.provenance;
            conflict.rejected_provenance = type.provenance;
            conflict.selected_confidence = selected.confidence;
            conflict.rejected_confidence = type.confidence;
            return sink.append_conflict(std::move(conflict));
        };
        workspace_result_t<void> conflict = workspace_result_t<void>::success();
        if (selected.kind != type.kind) {
            conflict = record_conflict(metadata_conflict_kind_t::type_kind,
                std::to_string(static_cast<unsigned>(selected.kind)),
                std::to_string(static_cast<unsigned>(type.kind)));
        } else if (selected.canonical_type != type.canonical_type) {
            conflict = record_conflict(metadata_conflict_kind_t::canonical_type,
                selected.canonical_type, type.canonical_type);
        } else if (selected.related_address != type.related_address) {
            conflict = record_conflict(metadata_conflict_kind_t::related_address,
                selected.related_address ? hex_value(selected.related_address->value) : "none",
                type.related_address ? hex_value(type.related_address->value) : "none");
        }
        if (!conflict) {
            failure = {collect_ordinal(14, 0, 0, index), conflict.error()};
            return;
        }
    }
}

const symbol_type_candidate_record_t* flat_map_find(
    const std::vector<std::uint32_t>& map,
    const std::vector<symbol_type_candidate_record_t>& types,
    const std::string& key, bool source_key) noexcept {
    std::size_t begin = 0;
    std::size_t end = map.size();
    while (begin < end) {
        const auto middle = begin + (end - begin) / 2;
        const auto& probe = source_key ? types[map[middle]].source_key
                                       : types[map[middle]].display_name;
        if (probe < key)
            begin = middle + 1;
        else
            end = middle;
    }
    if (begin < map.size()) {
        const auto& probe = source_key ? types[map[begin]].source_key
                                       : types[map[begin]].display_name;
        if (probe == key)
            return &types[map[begin]];
    }
    return nullptr;
}

std::vector<std::uint32_t> build_flat_type_map(
    const std::vector<symbol_type_candidate_record_t>& types, bool source_key,
    const cancellation_token_t& cancel) {
    std::vector<std::uint32_t> indices(types.size());
    for (std::size_t index = 0; index < indices.size(); ++index)
        indices[index] = static_cast<std::uint32_t>(index);
    const auto key_of = [&](std::uint32_t index) -> const std::string& {
        return source_key ? types[index].source_key : types[index].display_name;
    };
    parallel_sort(indices.begin(), indices.end(), [&](std::uint32_t lhs, std::uint32_t rhs) {
        const auto& left = key_of(lhs);
        const auto& right = key_of(rhs);
        if (left != right)
            return left < right;
        return lhs < rhs;
    });
    unique_aligned(indices, [&](std::uint32_t lhs, std::uint32_t rhs) {
        return key_of(lhs) == key_of(rhs);
    }, cancel);
    return indices;
}

struct vtable_run_t {
    std::size_t begin = 0;
    std::size_t accepted = 0;
    address_t address;
};

workspace_result_t<symbol_type_candidate_result_t> build_impl(
    const workspace_image_t& image, const std::vector<function_record_t>& functions,
    const std::vector<data_candidate_record_t>& data_candidates,
    const symbol_type_metadata_sources_t& metadata,
    const symbol_type_candidate_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (limits.max_symbols == 0 || limits.max_type_candidates == 0 ||
        limits.max_type_references == 0 || limits.max_conflicts == 0 ||
        limits.max_string_bytes == 0 || limits.max_result_bytes == 0 ||
        limits.minimum_vtable_entries < 2 ||
        limits.maximum_vtable_entries < limits.minimum_vtable_entries ||
        limits.cancellation_check_interval == 0) {
        return workspace_result_t<symbol_type_candidate_result_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "symbol and type candidate limits are invalid",
                "symbol_type_candidates"));
    }
    const auto workers = parallel_worker_count();
    collect_context_t ctx{image, functions, data_candidates, metadata, limits, cancel, nullptr};
    collect_totals_t totals;
    symbol_type_candidate_result_t result;

    std::vector<collect_task_t> wave_one_tasks;
    append_collect_tasks(wave_one_tasks, 1, image.imports.size(), workers);
    append_collect_tasks(wave_one_tasks, 2, image.exports.size(), workers);
    append_collect_tasks(wave_one_tasks, 3, image.symbols.size(), workers);
    if (metadata.elf) {
        append_collect_tasks(wave_one_tasks, 4, metadata.elf->symbol_seeds.size(), workers);
        append_collect_tasks(wave_one_tasks, 5, metadata.elf->type_seeds.size(), workers);
    }
    if (metadata.pe_coff)
        append_collect_tasks(wave_one_tasks, 6, metadata.pe_coff->type_seeds.size(), workers);
    if (metadata.macho) {
        for (std::size_t slice = 0; slice < metadata.macho->slices.size(); ++slice) {
            if (metadata.macho->slices[slice].identity.architecture != image.architecture)
                continue;
            append_macho_tasks(wave_one_tasks, static_cast<std::uint32_t>(slice),
                *metadata.macho, workers);
        }
    }
    for (std::size_t artifact = 0; artifact < metadata.managed_artifacts.size(); ++artifact)
        wave_one_tasks.push_back(
            collect_task_t{8, static_cast<std::uint32_t>(artifact), 0, 0, 0});

    std::vector<collect_sink_t> wave_one_sinks;
    auto collected = run_collect_wave(ctx, wave_one_tasks, wave_one_sinks);
    if (!collected)
        return workspace_result_t<symbol_type_candidate_result_t>::failure(collected.error());
    auto budgeted = accumulate_budgets(totals, wave_one_sinks, limits, true);
    if (!budgeted)
        return workspace_result_t<symbol_type_candidate_result_t>::failure(budgeted.error());

    std::vector<symbol_record_t> symbols;
    std::vector<symbol_type_candidate_record_t> types;
    std::vector<pending_relation_t> pending_relations;
    std::vector<metadata_conflict_record_t> conflicts;
    append_sink_vectors(symbols, wave_one_sinks, &collect_sink_t::symbols);
    append_sink_vectors(types, wave_one_sinks, &collect_sink_t::types);
    append_sink_vectors(pending_relations, wave_one_sinks, &collect_sink_t::pending);
    wave_one_sinks.clear();
    wave_one_sinks.shrink_to_fit();

    std::vector<std::uint64_t> named_functions;
    {
        const auto shards = parallel_shards(symbols.size(), workers);
        std::vector<std::vector<std::uint64_t>> per_shard(shards.size());
        std::vector<ordered_error_t> failures;
        auto named = run_ordered_tasks(shards.size(), [&](std::size_t slot) {
            const auto& shard = shards[slot];
            auto& local = per_shard[slot];
            for (std::size_t index = shard.begin; index != shard.end; ++index) {
                if (symbols[index].kind == symbol_kind_t::function)
                    local.push_back(symbols[index].address.value);
            }
        }, failures, cancel);
        if (!named)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(named.error());
        std::size_t total = 0;
        for (const auto& local : per_shard)
            total += local.size();
        named_functions.reserve(total);
        for (auto& local : per_shard)
            std::move(local.begin(), local.end(), std::back_inserter(named_functions));
        parallel_sort(named_functions.begin(), named_functions.end(),
            [](std::uint64_t lhs, std::uint64_t rhs) { return lhs < rhs; });
        unique_aligned(named_functions,
            [](std::uint64_t lhs, std::uint64_t rhs) { return lhs == rhs; }, cancel);
    }
    ctx.named_functions = &named_functions;

    std::vector<collect_task_t> wave_two_tasks;
    append_collect_tasks(wave_two_tasks, 9, functions.size(), workers);
    append_collect_tasks(wave_two_tasks, 10, data_candidates.size(), workers);
    std::vector<collect_sink_t> wave_two_sinks;
    collected = run_collect_wave(ctx, wave_two_tasks, wave_two_sinks);
    if (!collected)
        return workspace_result_t<symbol_type_candidate_result_t>::failure(collected.error());
    budgeted = accumulate_budgets(totals, wave_two_sinks, limits, true);
    if (!budgeted)
        return workspace_result_t<symbol_type_candidate_result_t>::failure(budgeted.error());
    append_sink_vectors(symbols, wave_two_sinks, &collect_sink_t::symbols);
    append_sink_vectors(types, wave_two_sinks, &collect_sink_t::types);
    append_sink_vectors(pending_relations, wave_two_sinks, &collect_sink_t::pending);
    wave_two_sinks.clear();
    wave_two_sinks.shrink_to_fit();

    parallel_sort(symbols.begin(), symbols.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.name != rhs.name)
            return lhs.name < rhs.name;
        if (stronger(lhs, rhs))
            return true;
        if (stronger(rhs, lhs))
            return false;
        return lhs.kind < rhs.kind;
    });
    {
        const auto shards = aligned_shards(symbols,
            [](const symbol_record_t& lhs, const symbol_record_t& rhs) {
                return lhs.address == rhs.address && lhs.name == rhs.name;
            }, workers);
        std::vector<collect_sink_t> sinks;
        sinks.reserve(shards.size());
        for (std::size_t index = 0; index < shards.size(); ++index)
            sinks.emplace_back(limits, cancel);
        std::vector<ordered_error_t> failures;
        auto deduped = run_ordered_tasks(shards.size(), [&](std::size_t slot) {
            dedup_symbols_shard(symbols, shards[slot], sinks[slot], failures[slot]);
        }, failures, cancel);
        if (!deduped)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(deduped.error());
        budgeted = accumulate_budgets(totals, sinks, limits, false);
        if (!budgeted)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(budgeted.error());
        std::vector<symbol_record_t> kept;
        append_sink_vectors(kept, sinks, &collect_sink_t::symbols);
        append_sink_vectors(conflicts, sinks, &collect_sink_t::conflicts);
        for (const auto& sink : sinks)
            result.duplicate_symbols += sink.duplicate_symbols;
        symbols = std::move(kept);
    }
    for (std::size_t index = 0; index < symbols.size(); ++index)
        symbols[index].id = kSymbolEntityTag | static_cast<std::uint64_t>(index + 1);

    {
        const auto shards = parallel_shards(symbols.size(), workers);
        std::vector<collect_sink_t> sinks;
        sinks.reserve(shards.size());
        for (std::size_t index = 0; index < shards.size(); ++index)
            sinks.emplace_back(limits, cancel);
        std::vector<ordered_error_t> failures;
        auto classified = run_ordered_tasks(shards.size(), [&](std::size_t slot) {
            const auto& shard = shards[slot];
            auto& sink = sinks[slot];
            for (std::size_t index = shard.begin; index != shard.end; ++index) {
                const auto& symbol = symbols[index];
                const auto classified_name = classify_name(symbol.name);
                if (!classified_name && symbol.kind != symbol_kind_t::type_symbol)
                    continue;
                symbol_type_candidate_record_t type;
                type.address = symbol.address;
                type.kind = classified_name ? classified_name->first
                    : symbol_type_candidate_kind_t::debug_type;
                type.display_name = symbol.name;
                type.canonical_type = canonical_type_for(type.kind);
                type.source_key = "symbol:" + symbol.name + ":" + hex_value(symbol.address.value);
                type.provenance = classified_name ? classified_name->second
                    : metadata_provenance_t::debug_metadata;
                type.confidence = (std::max)(symbol.confidence, static_cast<std::uint8_t>(88));
                type.explicitly_unknown = false;
                auto appended = sink.append_type(std::move(type));
                if (!appended) {
                    failures[slot] = {collect_ordinal(12, 0, 0, index), appended.error()};
                    return;
                }
            }
        }, failures, cancel);
        if (!classified)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(classified.error());
        budgeted = accumulate_budgets(totals, sinks, limits, true);
        if (!budgeted)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(budgeted.error());
        append_sink_vectors(types, sinks, &collect_sink_t::types);
    }

    const auto pointer_width = static_cast<std::uint64_t>(image.address_width_bits / 8U);
    if (pointer_width == 4 || pointer_width == 8) {
        std::vector<const data_candidate_record_t*> pointers;
        {
            const auto shards = parallel_shards(data_candidates.size(), workers);
            std::vector<std::vector<const data_candidate_record_t*>> per_shard(shards.size());
            std::vector<ordered_error_t> failures;
            auto filtered = run_ordered_tasks(shards.size(), [&](std::size_t slot) {
                const auto& shard = shards[slot];
                auto& local = per_shard[slot];
                for (std::size_t index = shard.begin; index != shard.end; ++index) {
                    const auto& data = data_candidates[index];
                    if (!data.target || !executable(image, *data.target))
                        continue;
                    const auto address = canonical_address(image, data.address);
                    const auto target = canonical_address(image, *data.target);
                    if (address && target && data.size == pointer_width)
                        local.push_back(&data);
                }
            }, failures, cancel);
            if (!filtered)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(
                    filtered.error());
            std::size_t total = 0;
            for (const auto& local : per_shard)
                total += local.size();
            pointers.reserve(total);
            for (auto& local : per_shard)
                std::move(local.begin(), local.end(), std::back_inserter(pointers));
        }
        parallel_sort(pointers.begin(), pointers.end(), [&](const auto* lhs, const auto* rhs) {
            const auto left = to_rva(image, lhs->address).value_or(image.image_size);
            const auto right = to_rva(image, rhs->address).value_or(image.image_size);
            if (left != right)
                return left < right;
            return lhs->target < rhs->target;
        });
        std::vector<vtable_run_t> runs;
        std::size_t begin = 0;
        while (begin < pointers.size()) {
            std::size_t end = begin + 1;
            auto previous = to_rva(image, pointers[begin]->address).value_or(image.image_size);
            while (end < pointers.size()) {
                const auto current = to_rva(image, pointers[end]->address).value_or(
                    image.image_size);
                if (current != previous + pointer_width)
                    break;
                previous = current;
                ++end;
            }
            const auto count = static_cast<std::uint64_t>(end - begin);
            if (count >= limits.minimum_vtable_entries) {
                const auto accepted = static_cast<std::size_t>((std::min<std::uint64_t>)(
                    count, limits.maximum_vtable_entries));
                const auto address = canonical_address(image, pointers[begin]->address);
                if (address)
                    runs.push_back(vtable_run_t{begin, accepted, *address});
            }
            begin = end;
        }
        if (!runs.empty()) {
            std::vector<collect_sink_t> sinks;
            sinks.reserve(runs.size());
            for (std::size_t index = 0; index < runs.size(); ++index)
                sinks.emplace_back(limits, cancel);
            std::vector<ordered_error_t> failures;
            auto detected = run_ordered_tasks(runs.size(), [&](std::size_t slot) {
                const auto& run = runs[slot];
                auto& sink = sinks[slot];
                std::string name = "vtable_" + hex_value(run.address.value);
                for (const auto& symbol : symbols) {
                    if (symbol.address == run.address && classify_name(symbol.name)) {
                        name = symbol.name;
                        break;
                    }
                }
                symbol_type_candidate_record_t type;
                type.address = run.address;
                type.kind = symbol_type_candidate_kind_t::virtual_table;
                type.display_name = name;
                type.canonical_type = canonical_type_for(type.kind);
                type.source_key = "vtable:" + hex_value(run.address.value);
                type.provenance = metadata_provenance_t::vtable_validation;
                type.confidence = 90;
                type.explicitly_unknown = false;
                const auto source_key = type.source_key;
                auto appended = sink.append_type(std::move(type));
                if (!appended) {
                    failures[slot] = {collect_ordinal(13, 0, 0, slot), appended.error()};
                    return;
                }
                for (std::size_t index = 0; index < run.accepted; ++index) {
                    pending_relation_t relation;
                    relation.source_key = source_key;
                    relation.source = canonical_address(image,
                        pointers[run.begin + index]->address);
                    relation.target = canonical_address(image,
                        *pointers[run.begin + index]->target);
                    relation.kind = type_reference_kind_t::virtual_table_slot;
                    relation.provenance = metadata_provenance_t::vtable_validation;
                    relation.confidence = pointers[run.begin + index]->confidence;
                    auto related = sink.append_pending(std::move(relation));
                    if (!related) {
                        failures[slot] = {collect_ordinal(13, 0, 0, slot), related.error()};
                        return;
                    }
                }
            }, failures, cancel);
            if (!detected)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(
                    detected.error());
            budgeted = accumulate_budgets(totals, sinks, limits, true);
            if (!budgeted)
                return workspace_result_t<symbol_type_candidate_result_t>::failure(
                    budgeted.error());
            append_sink_vectors(types, sinks, &collect_sink_t::types);
            append_sink_vectors(pending_relations, sinks, &collect_sink_t::pending);
        }
    }

    parallel_sort(types.begin(), types.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.display_name != rhs.display_name)
            return lhs.display_name < rhs.display_name;
        if (!lhs.address && lhs.source_key != rhs.source_key)
            return lhs.source_key < rhs.source_key;
        if (stronger(lhs, rhs))
            return true;
        if (stronger(rhs, lhs))
            return false;
        return std::tie(lhs.kind, lhs.canonical_type, lhs.related_address) <
               std::tie(rhs.kind, rhs.canonical_type, rhs.related_address);
    });
    {
        const auto shards = aligned_shards(types,
            [](const symbol_type_candidate_record_t& lhs,
               const symbol_type_candidate_record_t& rhs) {
                return same_type_identity(lhs, rhs);
            }, workers);
        std::vector<collect_sink_t> sinks;
        sinks.reserve(shards.size());
        for (std::size_t index = 0; index < shards.size(); ++index)
            sinks.emplace_back(limits, cancel);
        std::vector<ordered_error_t> failures;
        auto deduped = run_ordered_tasks(shards.size(), [&](std::size_t slot) {
            dedup_types_shard(types, shards[slot], sinks[slot], failures[slot]);
        }, failures, cancel);
        if (!deduped)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(deduped.error());
        budgeted = accumulate_budgets(totals, sinks, limits, false);
        if (!budgeted)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(budgeted.error());
        std::vector<symbol_type_candidate_record_t> kept;
        append_sink_vectors(kept, sinks, &collect_sink_t::types);
        append_sink_vectors(conflicts, sinks, &collect_sink_t::conflicts);
        for (const auto& sink : sinks)
            result.duplicate_type_candidates += sink.duplicate_type_candidates;
        types = std::move(kept);
    }
    for (std::size_t index = 0; index < types.size(); ++index)
        types[index].id = kTypeEntityTag | static_cast<std::uint64_t>(index + 1);

    const auto key_to_entity = build_flat_type_map(types, true, cancel);
    const auto name_to_entity = build_flat_type_map(types, false, cancel);
    {
        std::vector<collect_task_t> reference_tasks;
        for (const auto& shard : parallel_shards(types.size(), workers))
            reference_tasks.push_back(collect_task_t{15, 0, 0, shard.begin, shard.end});
        for (const auto& shard : parallel_shards(pending_relations.size(), workers))
            reference_tasks.push_back(collect_task_t{15, 0, 1, shard.begin, shard.end});
        std::vector<collect_sink_t> sinks;
        sinks.reserve(reference_tasks.size());
        for (std::size_t index = 0; index < reference_tasks.size(); ++index)
            sinks.emplace_back(limits, cancel);
        std::vector<ordered_error_t> failures;
        auto resolved = run_ordered_tasks(reference_tasks.size(), [&](std::size_t slot) {
            const auto& task = reference_tasks[slot];
            auto& sink = sinks[slot];
            if (task.substream == 0) {
                for (std::size_t index = task.begin; index != task.end; ++index) {
                    const auto& type = types[index];
                    if (!type.address)
                        continue;
                    type_reference_fact_t reference;
                    reference.source = type.address;
                    reference.source_entity = type.id;
                    reference.kind = type_reference_kind_t::definition;
                    reference.provenance = type.provenance;
                    reference.confidence = type.confidence;
                    reference.source_key = type.source_key;
                    auto appended = sink.append_reference(std::move(reference));
                    if (!appended) {
                        failures[slot] = {collect_ordinal(15, 0, 0, index), appended.error()};
                        return;
                    }
                }
                return;
            }
            for (std::size_t index = task.begin; index != task.end; ++index) {
                const auto& pending = pending_relations[index];
                type_reference_fact_t reference;
                reference.source = pending.source;
                reference.target = pending.target;
                const auto* source = flat_map_find(key_to_entity, types, pending.source_key, true);
                if (source)
                    reference.source_entity = source->id;
                const auto* target = flat_map_find(name_to_entity, types, pending.target_name,
                    false);
                if (target)
                    reference.target_entity = target->id;
                reference.kind = pending.kind;
                reference.provenance = pending.provenance;
                reference.confidence = pending.confidence;
                reference.source_key = pending.source_key;
                if (!pending.target_name.empty())
                    reference.source_key += "->" + pending.target_name;
                auto appended = sink.append_reference(std::move(reference));
                if (!appended) {
                    failures[slot] = {collect_ordinal(15, 0, 1, index), appended.error()};
                    return;
                }
            }
        }, failures, cancel);
        if (!resolved)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(resolved.error());
        budgeted = accumulate_budgets(totals, sinks, limits, true);
        if (!budgeted)
            return workspace_result_t<symbol_type_candidate_result_t>::failure(budgeted.error());
        append_sink_vectors(result.type_references, sinks, &collect_sink_t::references);
    }
    parallel_sort(result.type_references.begin(), result.type_references.end(),
        [](const auto& lhs, const auto& rhs) {
            if (lhs.source != rhs.source)
                return lhs.source < rhs.source;
            if (lhs.target != rhs.target)
                return lhs.target < rhs.target;
            if (lhs.source_entity != rhs.source_entity)
                return lhs.source_entity < rhs.source_entity;
            if (lhs.target_entity != rhs.target_entity)
                return lhs.target_entity < rhs.target_entity;
            if (lhs.kind != rhs.kind)
                return lhs.kind < rhs.kind;
            if (stronger(lhs, rhs))
                return true;
            if (stronger(rhs, lhs))
                return false;
            return lhs.source_key < rhs.source_key;
        });
    result.duplicate_type_references = unique_aligned(result.type_references,
        [](const type_reference_fact_t& lhs, const type_reference_fact_t& rhs) {
            return lhs.source == rhs.source && lhs.target == rhs.target &&
                   lhs.source_entity == rhs.source_entity &&
                   lhs.target_entity == rhs.target_entity && lhs.kind == rhs.kind;
        }, cancel);
    for (std::size_t index = 0; index < result.type_references.size(); ++index)
        result.type_references[index].id = kTypeXrefEntityTag |
            static_cast<std::uint64_t>(index + 1);

    parallel_sort(conflicts.begin(), conflicts.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.address, lhs.identity, lhs.kind, lhs.selected_value,
                   lhs.rejected_value, lhs.selected_provenance,
                   lhs.rejected_provenance, lhs.selected_confidence,
                   lhs.rejected_confidence) <
               std::tie(rhs.address, rhs.identity, rhs.kind, rhs.selected_value,
                   rhs.rejected_value, rhs.selected_provenance,
                   rhs.rejected_provenance, rhs.selected_confidence,
                   rhs.rejected_confidence);
    });
    unique_aligned(conflicts,
        [](const metadata_conflict_record_t& lhs, const metadata_conflict_record_t& rhs) {
            return lhs.address == rhs.address && lhs.identity == rhs.identity &&
                   lhs.kind == rhs.kind && lhs.selected_value == rhs.selected_value &&
                   lhs.rejected_value == rhs.rejected_value &&
                   lhs.selected_provenance == rhs.selected_provenance &&
                   lhs.rejected_provenance == rhs.rejected_provenance &&
                   lhs.selected_confidence == rhs.selected_confidence &&
                   lhs.rejected_confidence == rhs.rejected_confidence;
        }, cancel);
    for (std::size_t index = 0; index < conflicts.size(); ++index)
        conflicts[index].id = kMetadataConflictEntityTag | static_cast<std::uint64_t>(index + 1);

    result.symbols = std::move(symbols);
    result.type_candidates = std::move(types);
    result.conflicts = std::move(conflicts);
    if (cancel.stop_requested())
        return workspace_result_t<symbol_type_candidate_result_t>::failure(stop_error(cancel));
    return workspace_result_t<symbol_type_candidate_result_t>::success(std::move(result));
}

}

workspace_result_t<symbol_type_candidate_result_t> symbol_type_candidate_builder_t::build(
    const workspace_image_t& image, const std::vector<function_record_t>& functions,
    const std::vector<data_candidate_record_t>& data_candidates,
    const symbol_type_metadata_sources_t& metadata,
    const symbol_type_candidate_limits_t& limits, const cancellation_token_t& cancel) {
    try {
        return build_impl(image, functions, data_candidates, metadata, limits, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<symbol_type_candidate_result_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "symbol and type candidate allocation failed",
                "symbol_type_candidates"));
    } catch (const std::length_error&) {
        return workspace_result_t<symbol_type_candidate_result_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "symbol and type candidate allocation length is unsupported",
                "symbol_type_candidates"));
    }
}

}
